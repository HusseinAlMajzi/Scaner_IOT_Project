"""
Passive Device Discovery Service
Discovers devices through passive network traffic analysis without active scanning
"""

import asyncio
import logging
from scapy.all import sniff, ARP, IP, TCP, UDP, ICMP, Ether
from collections import defaultdict
from datetime import datetime, timedelta
import netifaces
import threading
import socket

try:
    import netifaces
    HAS_NETIFACES = True
except ImportError:
    HAS_NETIFACES = False
    logger.warning("netifaces not available, using fallback method for interface detection")

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class PassiveDiscovery:
    """Passive network traffic analyzer for device discovery"""
    
    def __init__(self, interface=None, timeout=60):
        """
        Initialize passive discovery
        
        Args:
            interface: Network interface to monitor (None for auto-detect)
            timeout: How long to capture traffic in seconds
        """
        self.interface = interface or self._get_default_interface()
        self.timeout = timeout
        self.devices = {}
        self.traffic_stats = defaultdict(lambda: {
            'packets': 0,
            'bytes': 0,
            'protocols': set(),
            'ports': set(),
            'first_seen': None,
            'last_seen': None
        })
        self.is_running = False
        self._stop_event = threading.Event()
    
    def _get_default_interface(self):
        """Get the default network interface"""
        if HAS_NETIFACES:
            try:
                gateways = netifaces.gateways()
                default_gateway = gateways['default'][netifaces.AF_INET]
                return default_gateway[1]
            except Exception as e:
                logger.warning(f"Could not determine default interface with netifaces: {e}")
        
        # Fallback method
        try:
            # Try common interface names
            import subprocess
            result = subprocess.check_output(['ip', 'route', 'show', 'default'], text=True)
            interface = result.split()[4] if len(result.split()) >= 5 else None
            if interface:
                return interface
        except Exception as e:
            logger.warning(f"Fallback interface detection failed: {e}")
        
        # Last resort - return None and let user specify
        logger.warning("Could not auto-detect interface. Please specify manually.")
        return None
    
    def _packet_handler(self, packet):
        """Process captured packets"""
        try:
            timestamp = datetime.now()
            
            # Extract source information
            if IP in packet:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                
                # Track device
                if src_ip not in ['0.0.0.0', '255.255.255.255']:
                    self._update_device_info(src_ip, packet, timestamp)
                
                if dst_ip not in ['0.0.0.0', '255.255.255.255']:
                    self._update_device_info(dst_ip, packet, timestamp, is_destination=True)
            
            # Extract MAC address from ARP
            if ARP in packet:
                src_ip = packet[ARP].psrc
                src_mac = packet[ARP].hwsrc
                
                if src_ip not in ['0.0.0.0']:
                    if src_ip not in self.devices:
                        self.devices[src_ip] = {
                            'ip_address': src_ip,
                            'mac_address': src_mac,
                            'hostname': None,
                            'protocols': set(),
                            'ports': set(),
                            'first_seen': timestamp,
                            'last_seen': timestamp,
                            'packet_count': 0,
                            'byte_count': 0
                        }
                    else:
                        self.devices[src_ip]['mac_address'] = src_mac
                        self.devices[src_ip]['last_seen'] = timestamp
        
        except Exception as e:
            logger.error(f"Error processing packet: {e}")
    
    def _update_device_info(self, ip, packet, timestamp, is_destination=False):
        """Update device information from packet"""
        if ip not in self.devices:
            self.devices[ip] = {
                'ip_address': ip,
                'mac_address': None,
                'hostname': None,
                'protocols': set(),
                'ports': set(),
                'first_seen': timestamp,
                'last_seen': timestamp,
                'packet_count': 0,
                'byte_count': 0
            }
        
        device = self.devices[ip]
        device['last_seen'] = timestamp
        device['packet_count'] += 1
        device['byte_count'] += len(packet)
        
        # Extract MAC address from Ethernet layer
        if Ether in packet and not is_destination:
            device['mac_address'] = packet[Ether].src
        
        # Detect protocols
        if TCP in packet:
            device['protocols'].add('TCP')
            if not is_destination:
                device['ports'].add(packet[TCP].sport)
            else:
                device['ports'].add(packet[TCP].dport)
        
        if UDP in packet:
            device['protocols'].add('UDP')
            if not is_destination:
                device['ports'].add(packet[UDP].sport)
            else:
                device['ports'].add(packet[UDP].dport)
        
        if ICMP in packet:
            device['protocols'].add('ICMP')
        
        if ARP in packet:
            device['protocols'].add('ARP')
    
    def start_capture(self):
        """Start passive packet capture"""
        logger.info(f"Starting passive discovery on interface: {self.interface}")
        self.is_running = True
        self._stop_event.clear()
        
        try:
            # Capture packets with a filter
            sniff(
                iface=self.interface,
                prn=self._packet_handler,
                timeout=self.timeout,
                store=False,
                stop_filter=lambda x: self._stop_event.is_set()
            )
        except Exception as e:
            logger.error(f"Error during packet capture: {e}")
        finally:
            self.is_running = False
        
        logger.info(f"Passive discovery completed. Found {len(self.devices)} devices")
    
    def stop_capture(self):
        """Stop passive packet capture"""
        logger.info("Stopping passive discovery...")
        self._stop_event.set()
        self.is_running = False
    
    def get_discovered_devices(self):
        """Get list of discovered devices"""
        devices_list = []
        
        for ip, info in self.devices.items():
            # Convert sets to lists for JSON serialization
            device_info = {
                'ip_address': ip,
                'mac_address': info['mac_address'],
                'hostname': info['hostname'],
                'protocols': list(info['protocols']),
                'open_ports': sorted(list(info['ports'])),
                'first_seen': info['first_seen'].isoformat() if info['first_seen'] else None,
                'last_seen': info['last_seen'].isoformat() if info['last_seen'] else None,
                'packet_count': info['packet_count'],
                'byte_count': info['byte_count'],
                'discovery_method': 'passive'
            }
            devices_list.append(device_info)
        
        return devices_list
    
    def get_statistics(self):
        """Get capture statistics"""
        total_packets = sum(d['packet_count'] for d in self.devices.values())
        total_bytes = sum(d['byte_count'] for d in self.devices.values())
        
        return {
            'devices_found': len(self.devices),
            'total_packets': total_packets,
            'total_bytes': total_bytes,
            'capture_duration': self.timeout,
            'interface': self.interface
        }


class PassiveDiscoveryAsync:
    """Async version of passive discovery for concurrent operations"""
    
    def __init__(self, interface=None, timeout=60):
        self.passive = PassiveDiscovery(interface, timeout)
        self.thread = None
    
    async def start_discovery(self):
        """Start discovery in background thread"""
        loop = asyncio.get_event_loop()
        
        # Run blocking capture in thread pool
        self.thread = threading.Thread(target=self.passive.start_capture)
        self.thread.daemon = True
        self.thread.start()
        
        # Wait for completion or timeout
        await asyncio.sleep(self.passive.timeout + 5)
        
        return self.passive.get_discovered_devices()
    
    def stop_discovery(self):
        """Stop discovery"""
        self.passive.stop_capture()
        if self.thread:
            self.thread.join(timeout=5)
    
    def get_devices(self):
        """Get discovered devices"""
        return self.passive.get_discovered_devices()
    
    def get_stats(self):
        """Get statistics"""
        return self.passive.get_statistics()


# Example usage
if __name__ == '__main__':
    # Test passive discovery
    discovery = PassiveDiscovery(timeout=30)
    
    print("Starting passive device discovery...")
    print("Monitoring network traffic for 30 seconds...")
    
    discovery.start_capture()
    
    devices = discovery.get_discovered_devices()
    stats = discovery.get_statistics()
    
    print(f"\n=== Discovery Results ===")
    print(f"Devices found: {stats['devices_found']}")
    print(f"Total packets: {stats['total_packets']}")
    print(f"Total bytes: {stats['total_bytes']}")
    
    print("\n=== Discovered Devices ===")
    for device in devices:
        print(f"\nIP: {device['ip_address']}")
        print(f"  MAC: {device['mac_address']}")
        print(f"  Protocols: {', '.join(device['protocols'])}")
        print(f"  Ports: {device['open_ports']}")
        print(f"  Packets: {device['packet_count']}")
