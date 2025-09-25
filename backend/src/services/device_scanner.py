import nmap
import socket
import subprocess
import re
from netaddr import IPNetwork
from scapy.all import ARP, Ether, srp
import requests
from datetime import datetime
import json

class DeviceScanner:
    def __init__(self):
        self.nm = nmap.PortScanner()
        self.iot_signatures = {
            # Common IoT device signatures based on banners, services, etc.
            'camera': ['axis', 'hikvision', 'dahua', 'foscam', 'webcam', 'ipcam'],
            'router': ['router', 'gateway', 'linksys', 'netgear', 'tp-link', 'asus'],
            'smart_tv': ['samsung', 'lg', 'sony', 'smart tv', 'android tv'],
            'printer': ['printer', 'canon', 'hp', 'epson', 'brother'],
            'nas': ['synology', 'qnap', 'drobo', 'nas'],
            'smart_home': ['nest', 'alexa', 'google home', 'philips hue', 'smart'],
            'industrial': ['siemens', 'schneider', 'rockwell', 'modbus', 'scada'],
            'medical': ['ge healthcare', 'philips medical', 'medical device']
        }
    
    def get_network_range(self):
        """Get the local network range automatically"""
        try:
            # Get default gateway
            result = subprocess.run(['ip', 'route', 'show', 'default'], 
                                  capture_output=True, text=True)
            if result.returncode == 0:
                # Extract interface from default route
                lines = result.stdout.strip().split('\n')
                for line in lines:
                    if 'default via' in line:
                        parts = line.split()
                        if 'dev' in parts:
                            interface = parts[parts.index('dev') + 1]
                            break
                
                # Get IP and netmask for the interface
                result = subprocess.run(['ip', 'addr', 'show', interface], 
                                      capture_output=True, text=True)
                if result.returncode == 0:
                    # Extract IP/CIDR
                    match = re.search(r'inet (\d+\.\d+\.\d+\.\d+/\d+)', result.stdout)
                    if match:
                        return match.group(1)
            
            # Fallback to common private networks
            return "192.168.1.0/24"
        except Exception as e:
            print(f"Error getting network range: {e}")
            return "192.168.1.0/24"
    
    def scan_network(self, network_range=None):
        """Scan network for active devices"""
        if not network_range:
            network_range = self.get_network_range()
        
        print(f"Scanning network: {network_range}")
        devices = []
        
        try:
            # Use nmap for comprehensive scanning
            self.nm.scan(hosts=network_range, arguments='-sn -T4')
            
            for host in self.nm.all_hosts():
                if self.nm[host].state() == 'up':
                    device_info = self.get_device_details(host)
                    if device_info:
                        devices.append(device_info)
        
        except Exception as e:
            print(f"Error during network scan: {e}")
            # Fallback to ARP scan using scapy
            devices = self.arp_scan(network_range)
        
        return devices
    
    def arp_scan(self, network_range):
        """Fallback ARP scan using scapy"""
        devices = []
        try:
            # Create ARP request
            arp_request = ARP(pdst=network_range)
            broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
            arp_request_broadcast = broadcast / arp_request
            
            # Send request and receive response
            answered_list = srp(arp_request_broadcast, timeout=2, verbose=False)[0]
            
            for element in answered_list:
                device_info = {
                    'ip_address': element[1].psrc,
                    'mac_address': element[1].hwsrc,
                    'hostname': self.get_hostname(element[1].psrc),
                    'manufacturer': self.get_mac_vendor(element[1].hwsrc),
                    'device_type': 'Unknown',
                    'os_info': None,
                    'firmware_version': None,
                    'open_ports': [],
                    'last_scanned_at': datetime.utcnow()
                }
                devices.append(device_info)
        
        except Exception as e:
            print(f"Error during ARP scan: {e}")
        
        return devices
    
    def get_device_details(self, ip):
        """Get detailed information about a device"""
        device_info = {
            'ip_address': ip,
            'mac_address': None,
            'hostname': None,
            'manufacturer': None,
            'device_type': 'Unknown',
            'os_info': None,
            'firmware_version': None,
            'open_ports': [],
            'last_scanned_at': datetime.utcnow()
        }
        
        try:
            # Get hostname
            device_info['hostname'] = self.get_hostname(ip)
            
            # Get MAC address (if on same subnet)
            device_info['mac_address'] = self.get_mac_address(ip)
            
            # Get manufacturer from MAC
            if device_info['mac_address']:
                device_info['manufacturer'] = self.get_mac_vendor(device_info['mac_address'])
            
            # Port scan for common IoT ports
            device_info['open_ports'] = self.scan_common_ports(ip)
            
            # Try to identify device type and OS
            device_info['device_type'], device_info['os_info'] = self.identify_device(ip, device_info['open_ports'])
            
            # Try to get firmware version
            device_info['firmware_version'] = self.get_firmware_version(ip, device_info['open_ports'])
            
        except Exception as e:
            print(f"Error getting device details for {ip}: {e}")
        
        return device_info
    
    def get_hostname(self, ip):
        """Get hostname for IP address"""
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            return hostname
        except:
            return None
    
    def get_mac_address(self, ip):
        """Get MAC address for IP (works only on same subnet)"""
        try:
            # Try ARP table first
            result = subprocess.run(['arp', '-n', ip], capture_output=True, text=True)
            if result.returncode == 0:
                match = re.search(r'([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}', result.stdout)
                if match:
                    return match.group(0)
        except:
            pass
        return None
    
    def get_mac_vendor(self, mac_address):
        """Get vendor information from MAC address"""
        if not mac_address:
            return None
        
        try:
            # Use online MAC vendor lookup (you might want to use a local database)
            oui = mac_address.replace(':', '').replace('-', '')[:6].upper()
            
            # Simple vendor mapping (you can expand this)
            vendor_map = {
                '001B63': 'Apple',
                '00E04C': 'Realtek',
                '001E58': 'Cisco',
                '00A0C9': 'Intel',
                '001CF0': 'D-Link',
                '00E092': 'Netgear',
                '001DD8': 'TP-Link'
            }
            
            return vendor_map.get(oui, 'Unknown')
        except:
            return 'Unknown'
    
    def scan_common_ports(self, ip):
        """Scan common IoT ports"""
        common_ports = [
            21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995,  # Standard ports
            1883, 8883,  # MQTT
            5683, 5684,  # CoAP
            8080, 8443, 8888, 9000,  # Common web ports
            502, 503,  # Modbus
            2404,  # IEC 61850
            47808,  # BACnet
            1900,  # UPnP
            5000, 5001, 5555,  # Common IoT ports
        ]
        
        open_ports = []
        
        try:
            # Quick scan of common ports
            self.nm.scan(ip, ','.join(map(str, common_ports)), arguments='-T4 -sV')
            
            if ip in self.nm.all_hosts():
                for port in self.nm[ip]['tcp']:
                    port_info = self.nm[ip]['tcp'][port]
                    if port_info['state'] == 'open':
                        open_ports.append({
                            'port': port,
                            'service': port_info.get('name', 'unknown'),
                            'version': port_info.get('version', ''),
                            'product': port_info.get('product', ''),
                            'banner': port_info.get('extrainfo', '')
                        })
        
        except Exception as e:
            print(f"Error scanning ports for {ip}: {e}")
        
        return open_ports
    
    def identify_device(self, ip, open_ports):
        """Identify device type based on open ports and services"""
        device_type = 'Unknown'
        os_info = None
        
        # Analyze open ports and services
        services = [port['service'].lower() for port in open_ports]
        products = [port['product'].lower() for port in open_ports]
        banners = [port['banner'].lower() for port in open_ports]
        
        all_info = ' '.join(services + products + banners)
        
        # Check against IoT signatures
        for dev_type, signatures in self.iot_signatures.items():
            for signature in signatures:
                if signature.lower() in all_info:
                    device_type = dev_type.replace('_', ' ').title()
                    break
            if device_type != 'Unknown':
                break
        
        # Additional heuristics
        if any(port['port'] in [1883, 8883] for port in open_ports):
            device_type = 'IoT Device (MQTT)'
        elif any(port['port'] in [5683, 5684] for port in open_ports):
            device_type = 'IoT Device (CoAP)'
        elif any(port['port'] == 502 for port in open_ports):
            device_type = 'Industrial Device (Modbus)'
        elif any(port['port'] == 1900 for port in open_ports):
            device_type = 'UPnP Device'
        
        # Try to get OS information
        try:
            self.nm.scan(ip, arguments='-O')
            if ip in self.nm.all_hosts() and 'osmatch' in self.nm[ip]:
                os_matches = self.nm[ip]['osmatch']
                if os_matches:
                    os_info = os_matches[0]['name']
        except:
            pass 
        
        return device_type, os_info
    
    def get_firmware_version(self, ip, open_ports):
        """Try to get firmware version from device"""
        firmware_version = None
        
        # Check web interfaces for version information
        for port in open_ports:
            if port['service'] in ['http', 'https']:
                try:
                    protocol = 'https' if port['service'] == 'https' else 'http'
                    url = f"{protocol}://{ip}:{port['port']}"
                    
                    response = requests.get(url, timeout=5, verify=False)
                    
                    # Look for version in headers
                    server_header = response.headers.get('Server', '')
                    if server_header:
                        version_match = re.search(r'(\d+\.\d+(?:\.\d+)?)', server_header)
                        if version_match:
                            firmware_version = version_match.group(1)
                            break
                    
                    # Look for version in HTML content
                    content = response.text.lower()
                    version_patterns = [
                        r'firmware[:\s]+v?(\d+\.\d+(?:\.\d+)?)',
                        r'version[:\s]+v?(\d+\.\d+(?:\.\d+)?)',
                        r'v(\d+\.\d+(?:\.\d+)?)'
                    ]
                    
                    for pattern in version_patterns:
                        match = re.search(pattern, content)
                        if match:
                            firmware_version = match.group(1)
                            break
                    
                    if firmware_version:
                        break
                
                except:
                    continue
        
        return firmware_version

