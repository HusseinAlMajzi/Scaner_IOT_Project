"""
Advanced Service Discovery using mDNS (Bonjour/Avahi) and SSDP (UPnP)
Discovers IoT devices advertising services on the network
"""

import asyncio
import logging
import socket
import struct
from zeroconf import ServiceBrowser, ServiceListener, Zeroconf
from typing import List, Dict
import xml.etree.ElementTree as ET
import aiohttp
from datetime import datetime

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class MDNSDiscovery(ServiceListener):
    """mDNS/Bonjour service discovery for IoT devices"""
    
    # Common IoT service types
    IOT_SERVICES = [
        '_http._tcp.local.',
        '_https._tcp.local.',
        '_mqtt._tcp.local.',
        '_coap._udp.local.',
        '_ipp._tcp.local.',        # Printers
        '_airplay._tcp.local.',    # Apple AirPlay
        '_googlecast._tcp.local.', # Google Cast
        '_hap._tcp.local.',        # HomeKit
        '_homekit._tcp.local.',
        '_matter._tcp.local.',     # Matter protocol
        '_thread._udp.local.',     # Thread protocol
        '_zigbee._tcp.local.',
        '_device-info._tcp.local.',
        '_workstation._tcp.local.',
        '_sftp-ssh._tcp.local.',
        '_smb._tcp.local.',
    ]
    
    def __init__(self):
        self.discovered_services = []
        self.zeroconf = None
        self.browsers = []
    
    def add_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        """Called when a service is discovered"""
        try:
            info = zc.get_service_info(type_, name)
            if info:
                service_data = {
                    'name': name,
                    'type': type_,
                    'addresses': [socket.inet_ntoa(addr) for addr in info.addresses],
                    'port': info.port,
                    'server': info.server,
                    'properties': {k.decode('utf-8'): v.decode('utf-8') 
                                 for k, v in info.properties.items()},
                    'discovered_at': datetime.now().isoformat(),
                    'discovery_method': 'mDNS'
                }
                self.discovered_services.append(service_data)
                logger.info(f"mDNS: Found {name} at {service_data['addresses']}")
        except Exception as e:
            logger.error(f"Error processing mDNS service {name}: {e}")
    
    def update_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        """Called when a service is updated"""
        logger.debug(f"mDNS: Service updated {name}")
    
    def remove_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        """Called when a service is removed"""
        logger.debug(f"mDNS: Service removed {name}")
    
    async def discover_services(self, timeout=10):
        """
        Discover services using mDNS
        
        Args:
            timeout: Discovery timeout in seconds
        """
        logger.info("Starting mDNS service discovery...")
        
        try:
            self.zeroconf = Zeroconf()
            
            # Browse for each service type
            for service_type in self.IOT_SERVICES:
                browser = ServiceBrowser(self.zeroconf, service_type, self)
                self.browsers.append(browser)
            
            # Wait for discovery
            await asyncio.sleep(timeout)
            
            logger.info(f"mDNS: Discovered {len(self.discovered_services)} services")
            
        except Exception as e:
            logger.error(f"mDNS discovery error: {e}")
        finally:
            if self.zeroconf:
                self.zeroconf.close()
        
        return self.discovered_services
    
    def get_discovered_devices(self):
        """Convert discovered services to device format"""
        devices = {}
        
        for service in self.discovered_services:
            for addr in service['addresses']:
                if addr not in devices:
                    devices[addr] = {
                        'ip_address': addr,
                        'hostname': service['server'],
                        'services': [],
                        'ports': set(),
                        'discovery_method': 'mDNS'
                    }
                
                devices[addr]['services'].append({
                    'name': service['name'],
                    'type': service['type'],
                    'port': service['port'],
                    'properties': service['properties']
                })
                devices[addr]['ports'].add(service['port'])
        
        # Convert to list format
        result = []
        for ip, data in devices.items():
            data['open_ports'] = sorted(list(data['ports']))
            del data['ports']
            result.append(data)
        
        return result


class SSDPDiscovery:
    """SSDP (UPnP) device discovery"""
    
    SSDP_ADDR = "239.255.255.250"
    SSDP_PORT = 1900
    SSDP_MX = 3
    SSDP_ST = "ssdp:all"
    
    def __init__(self):
        self.discovered_devices = []
    
    def _create_ssdp_request(self):
        """Create SSDP M-SEARCH request"""
        return (
            'M-SEARCH * HTTP/1.1\r\n'
            f'HOST: {self.SSDP_ADDR}:{self.SSDP_PORT}\r\n'
            'MAN: "ssdp:discover"\r\n'
            f'MX: {self.SSDP_MX}\r\n'
            f'ST: {self.SSDP_ST}\r\n'
            '\r\n'
        ).encode('utf-8')
    
    def _parse_ssdp_response(self, response):
        """Parse SSDP response"""
        try:
            lines = response.decode('utf-8', errors='ignore').split('\r\n')
            headers = {}
            
            for line in lines[1:]:  # Skip first line (HTTP status)
                if ':' in line:
                    key, value = line.split(':', 1)
                    headers[key.strip().upper()] = value.strip()
            
            return headers
        except Exception as e:
            logger.error(f"Error parsing SSDP response: {e}")
            return {}
    
    async def _fetch_device_description(self, location):
        """Fetch and parse device description XML"""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(location, timeout=5) as response:
                    if response.status == 200:
                        xml_data = await response.text()
                        root = ET.fromstring(xml_data)
                        
                        # Extract device info from XML
                        ns = {'upnp': 'urn:schemas-upnp-org:device-1-0'}
                        device = root.find('.//upnp:device', ns)
                        
                        if device is not None:
                            return {
                                'device_type': device.findtext('upnp:deviceType', '', ns),
                                'friendly_name': device.findtext('upnp:friendlyName', '', ns),
                                'manufacturer': device.findtext('upnp:manufacturer', '', ns),
                                'model_name': device.findtext('upnp:modelName', '', ns),
                                'model_number': device.findtext('upnp:modelNumber', '', ns),
                                'serial_number': device.findtext('upnp:serialNumber', '', ns),
                                'udn': device.findtext('upnp:UDN', '', ns)
                            }
        except Exception as e:
            logger.error(f"Error fetching device description from {location}: {e}")
        
        return {}
    
    async def discover_devices(self, timeout=10):
        """
        Discover UPnP devices using SSDP
        
        Args:
            timeout: Discovery timeout in seconds
        """
        logger.info("Starting SSDP device discovery...")
        
        try:
            # Create UDP socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
            sock.settimeout(timeout)
            
            # Send M-SEARCH request
            request = self._create_ssdp_request()
            sock.sendto(request, (self.SSDP_ADDR, self.SSDP_PORT))
            
            # Collect responses
            responses = []
            try:
                while True:
                    data, addr = sock.recvfrom(2048)
                    responses.append((addr[0], self._parse_ssdp_response(data)))
            except socket.timeout:
                pass
            
            sock.close()
            
            # Process responses
            devices = {}
            for ip, headers in responses:
                if ip not in devices:
                    devices[ip] = {
                        'ip_address': ip,
                        'discovery_method': 'SSDP',
                        'upnp_devices': [],
                        'discovered_at': datetime.now().isoformat()
                    }
                
                device_info = {
                    'server': headers.get('SERVER', ''),
                    'location': headers.get('LOCATION', ''),
                    'usn': headers.get('USN', ''),
                    'st': headers.get('ST', '')
                }
                
                # Fetch detailed info if location available
                if device_info['location']:
                    details = await self._fetch_device_description(device_info['location'])
                    device_info.update(details)
                
                devices[ip]['upnp_devices'].append(device_info)
            
            self.discovered_devices = list(devices.values())
            logger.info(f"SSDP: Discovered {len(self.discovered_devices)} devices")
            
        except Exception as e:
            logger.error(f"SSDP discovery error: {e}")
        
        return self.discovered_devices


class ServiceDiscoveryManager:
    """Unified service discovery manager combining mDNS and SSDP"""
    
    def __init__(self):
        self.mdns = MDNSDiscovery()
        self.ssdp = SSDPDiscovery()
    
    async def discover_all(self, timeout=15):
        """
        Run both mDNS and SSDP discovery concurrently
        
        Args:
            timeout: Discovery timeout in seconds
        """
        logger.info("Starting comprehensive service discovery...")
        
        # Run discoveries concurrently
        mdns_task = asyncio.create_task(self.mdns.discover_services(timeout))
        ssdp_task = asyncio.create_task(self.ssdp.discover_devices(timeout))
        
        await asyncio.gather(mdns_task, ssdp_task, return_exceptions=True)
        
        # Combine results
        devices = self._merge_discoveries()
        
        logger.info(f"Total devices discovered: {len(devices)}")
        return devices
    
    def _merge_discoveries(self):
        """Merge mDNS and SSDP discoveries"""
        devices_map = {}
        
        # Add mDNS devices
        for device in self.mdns.get_discovered_devices():
            ip = device['ip_address']
            devices_map[ip] = device
            devices_map[ip]['discovery_methods'] = ['mDNS']
        
        # Merge SSDP devices
        for device in self.ssdp.discovered_devices:
            ip = device['ip_address']
            if ip in devices_map:
                # Merge with existing device
                devices_map[ip]['upnp_devices'] = device.get('upnp_devices', [])
                devices_map[ip]['discovery_methods'].append('SSDP')
            else:
                # Add new device
                devices_map[ip] = device
                devices_map[ip]['discovery_methods'] = ['SSDP']
        
        return list(devices_map.values())
    
    def get_statistics(self):
        """Get discovery statistics"""
        return {
            'mdns_services': len(self.mdns.discovered_services),
            'ssdp_devices': len(self.ssdp.discovered_devices),
            'total_unique_ips': len(self._merge_discoveries())
        }


# Example usage
async def main():
    """Test service discovery"""
    manager = ServiceDiscoveryManager()
    
    print("Starting service discovery...")
    devices = await manager.discover_all(timeout=15)
    stats = manager.get_statistics()
    
    print(f"\n=== Discovery Statistics ===")
    print(f"mDNS services: {stats['mdns_services']}")
    print(f"SSDP devices: {stats['ssdp_devices']}")
    print(f"Total unique devices: {stats['total_unique_ips']}")
    
    print(f"\n=== Discovered Devices ===")
    for device in devices:
        print(f"\nIP: {device['ip_address']}")
        print(f"  Methods: {', '.join(device.get('discovery_methods', []))}")
        if 'hostname' in device:
            print(f"  Hostname: {device['hostname']}")
        if 'services' in device:
            print(f"  Services: {len(device['services'])}")
        if 'upnp_devices' in device:
            print(f"  UPnP Devices: {len(device['upnp_devices'])}")


if __name__ == '__main__':
    asyncio.run(main())
