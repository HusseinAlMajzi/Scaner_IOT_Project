import socket
import struct
import time
import threading
from typing import Dict, List, Optional, Tuple
import requests
import json
from datetime import datetime
import ssl
import subprocess
import re

class ProtocolScanner:
    def __init__(self):
        self.timeout = 5
        self.max_threads = 10
        
        # Protocol signatures and patterns
        self.protocol_signatures = {
            'mqtt': {
                'ports': [1883, 8883],
                'patterns': [b'\x10', b'MQTT', b'MQIsdp'],
                'description': 'MQTT (Message Queuing Telemetry Transport)'
            },
            'coap': {
                'ports': [5683, 5684],
                'patterns': [b'\x40', b'\x41', b'\x42', b'\x43'],
                'description': 'CoAP (Constrained Application Protocol)'
            },
            'modbus': {
                'ports': [502, 503],
                'patterns': [b'\x00\x00\x00\x00\x00\x06'],
                'description': 'Modbus TCP/IP'
            },
            'bacnet': {
                'ports': [47808],
                'patterns': [b'\x81', b'\x82', b'\x83'],
                'description': 'BACnet (Building Automation and Control Networks)'
            },
            'dnp3': {
                'ports': [20000],
                'patterns': [b'\x05\x64'],
                'description': 'DNP3 (Distributed Network Protocol)'
            },
            'upnp': {
                'ports': [1900],
                'patterns': [b'M-SEARCH', b'NOTIFY', b'HTTP/1.1'],
                'description': 'UPnP (Universal Plug and Play)'
            },
            'snmp': {
                'ports': [161, 162],
                'patterns': [b'\x30', b'\x02\x01'],
                'description': 'SNMP (Simple Network Management Protocol)'
            },
            'zigbee': {
                'ports': [17754, 17755],
                'patterns': [b'\x00\x00\x00\x00'],
                'description': 'Zigbee Protocol'
            },
            'lora': {
                'ports': [1700, 1680],
                'patterns': [b'\x01', b'\x02'],
                'description': 'LoRaWAN Protocol'
            }
        }
    
    def scan_device_protocols(self, ip_address: str, open_ports: List[Dict]) -> List[Dict]:
        """Scan a device for IoT protocols"""
        detected_protocols = []
        
        # Check known IoT protocol ports
        for protocol_name, protocol_info in self.protocol_signatures.items():
            for port_info in open_ports:
                port = port_info.get('port')
                if port in protocol_info['ports']:
                    protocol_details = self._analyze_protocol(ip_address, port, protocol_name)
                    if protocol_details:
                        detected_protocols.append(protocol_details)
        
        # Deep scan for additional protocols
        additional_protocols = self._deep_protocol_scan(ip_address, open_ports)
        detected_protocols.extend(additional_protocols)
        
        return detected_protocols
    
    def _analyze_protocol(self, ip_address: str, port: int, protocol_name: str) -> Optional[Dict]:
        """Analyze a specific protocol on a given port"""
        protocol_info = self.protocol_signatures.get(protocol_name)
        if not protocol_info:
            return None
        
        try:
            if protocol_name == 'mqtt':
                return self._analyze_mqtt(ip_address, port)
            elif protocol_name == 'coap':
                return self._analyze_coap(ip_address, port)
            elif protocol_name == 'modbus':
                return self._analyze_modbus(ip_address, port)
            elif protocol_name == 'bacnet':
                return self._analyze_bacnet(ip_address, port)
            elif protocol_name == 'upnp':
                return self._analyze_upnp(ip_address, port)
            elif protocol_name == 'snmp':
                return self._analyze_snmp(ip_address, port)
            else:
                return self._generic_protocol_check(ip_address, port, protocol_name)
        
        except Exception as e:
            print(f"Error analyzing {protocol_name} on {ip_address}:{port}: {e}")
            return None
    
    def _analyze_mqtt(self, ip_address: str, port: int) -> Optional[Dict]:
        """Analyze MQTT protocol"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            # Try to connect
            result = sock.connect_ex((ip_address, port))
            if result != 0:
                sock.close()
                return None
            
            # Send MQTT CONNECT packet
            connect_packet = bytearray([
                0x10,  # CONNECT packet type
                0x0C,  # Remaining length
                0x00, 0x04, 0x4D, 0x51, 0x54, 0x54,  # Protocol name "MQTT"
                0x04,  # Protocol level
                0x00,  # Connect flags
                0x00, 0x3C,  # Keep alive (60 seconds)
            ])
            
            sock.send(connect_packet)
            response = sock.recv(1024)
            sock.close()
            
            if response and len(response) >= 4:
                # Check for CONNACK packet
                if response[0] == 0x20:
                    return_code = response[3] if len(response) > 3 else 0
                    
                    vulnerabilities = []
                    
                    # Check for authentication
                    if return_code == 0:  # Connection accepted
                        vulnerabilities.append({
                            'type': 'No Authentication',
                            'severity': 'High',
                            'description': 'MQTT broker accepts connections without authentication'
                        })
                    
                    # Check for SSL/TLS
                    if port == 1883:  # Unencrypted MQTT
                        vulnerabilities.append({
                            'type': 'Unencrypted Communication',
                            'severity': 'Medium',
                            'description': 'MQTT communication is not encrypted'
                        })
                    
                    return {
                        'protocol': 'MQTT',
                        'port': port,
                        'version': '3.1.1',
                        'description': 'MQTT Message Broker',
                        'vulnerabilities': vulnerabilities,
                        'details': {
                            'return_code': return_code,
                            'encrypted': port == 8883
                        }
                    }
        
        except Exception as e:
            print(f"MQTT analysis error: {e}")
        
        return None
    
    def _analyze_coap(self, ip_address: str, port: int) -> Optional[Dict]:
        """Analyze CoAP protocol"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)
            
            # CoAP GET request to /.well-known/core
            coap_packet = bytearray([
                0x40,  # Version (2 bits) + Type (2 bits) + Token Length (4 bits)
                0x01,  # Code (GET)
                0x00, 0x01,  # Message ID
                0xBB, 0x2E, 0x77, 0x65, 0x6C, 0x6C, 0x2D, 0x6B, 0x6E, 0x6F, 0x77, 0x6E,  # .well-known
                0x04, 0x63, 0x6F, 0x72, 0x65  # core
            ])
            
            sock.sendto(coap_packet, (ip_address, port))
            response, addr = sock.recvfrom(1024)
            sock.close()
            
            if response and len(response) >= 4:
                vulnerabilities = []
                
                # Check for DTLS encryption
                if port == 5683:  # Unencrypted CoAP
                    vulnerabilities.append({
                        'type': 'Unencrypted Communication',
                        'severity': 'Medium',
                        'description': 'CoAP communication is not encrypted (no DTLS)'
                    })
                
                # Parse response for available resources
                resources = []
                if len(response) > 4:
                    payload = response[4:].decode('utf-8', errors='ignore')
                    # Simple parsing of CoAP link format
                    resource_matches = re.findall(r'<([^>]+)>', payload)
                    resources = resource_matches[:10]  # Limit to first 10 resources
                
                return {
                    'protocol': 'CoAP',
                    'port': port,
                    'version': '1.0',
                    'description': 'Constrained Application Protocol',
                    'vulnerabilities': vulnerabilities,
                    'details': {
                        'encrypted': port == 5684,
                        'resources': resources
                    }
                }
        
        except Exception as e:
            print(f"CoAP analysis error: {e}")
        
        return None
    
    def _analyze_modbus(self, ip_address: str, port: int) -> Optional[Dict]:
        """Analyze Modbus TCP protocol"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            result = sock.connect_ex((ip_address, port))
            if result != 0:
                sock.close()
                return None
            
            # Modbus TCP read holding registers request
            modbus_packet = bytearray([
                0x00, 0x01,  # Transaction ID
                0x00, 0x00,  # Protocol ID
                0x00, 0x06,  # Length
                0x01,        # Unit ID
                0x03,        # Function code (Read Holding Registers)
                0x00, 0x00,  # Starting address
                0x00, 0x01   # Quantity of registers
            ])
            
            sock.send(modbus_packet)
            response = sock.recv(1024)
            sock.close()
            
            if response and len(response) >= 8:
                vulnerabilities = []
                
                # Modbus has no built-in security
                vulnerabilities.append({
                    'type': 'No Authentication',
                    'severity': 'Critical',
                    'description': 'Modbus protocol has no built-in authentication or encryption'
                })
                
                vulnerabilities.append({
                    'type': 'Industrial Protocol Exposure',
                    'severity': 'High',
                    'description': 'Industrial control protocol exposed to network'
                })
                
                return {
                    'protocol': 'Modbus TCP',
                    'port': port,
                    'version': 'TCP/IP',
                    'description': 'Modbus Industrial Protocol',
                    'vulnerabilities': vulnerabilities,
                    'details': {
                        'function_codes_supported': ['Read Holding Registers'],
                        'unit_id': 1
                    }
                }
        
        except Exception as e:
            print(f"Modbus analysis error: {e}")
        
        return None
    
    def _analyze_bacnet(self, ip_address: str, port: int) -> Optional[Dict]:
        """Analyze BACnet protocol"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)
            
            # BACnet Who-Is request
            bacnet_packet = bytearray([
                0x81,        # BACnet Virtual Link Control
                0x0A,        # Function
                0x00, 0x0C,  # Length
                0x01, 0x20,  # Destination network and address
                0xFF,        # Destination MAC
                0x10, 0x08,  # NPDU control and hop count
                0x00, 0x1E,  # APDU type and service
                0xFF, 0xFF   # Device instance range
            ])
            
            sock.sendto(bacnet_packet, (ip_address, port))
            response, addr = sock.recvfrom(1024)
            sock.close()
            
            if response and len(response) >= 4:
                vulnerabilities = []
                
                # BACnet security issues
                vulnerabilities.append({
                    'type': 'No Authentication',
                    'severity': 'High',
                    'description': 'BACnet protocol typically lacks authentication mechanisms'
                })
                
                vulnerabilities.append({
                    'type': 'Building Automation Exposure',
                    'severity': 'Medium',
                    'description': 'Building automation protocol exposed to network'
                })
                
                return {
                    'protocol': 'BACnet',
                    'port': port,
                    'version': 'IP',
                    'description': 'Building Automation and Control Networks',
                    'vulnerabilities': vulnerabilities,
                    'details': {
                        'transport': 'UDP',
                        'responds_to_whois': True
                    }
                }
        
        except Exception as e:
            print(f"BACnet analysis error: {e}")
        
        return None
    
    def _analyze_upnp(self, ip_address: str, port: int) -> Optional[Dict]:
        """Analyze UPnP protocol"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)
            
            # UPnP M-SEARCH request
            msearch_request = (
                "M-SEARCH * HTTP/1.1\r\n"
                "HOST: 239.255.255.250:1900\r\n"
                "MAN: \"ssdp:discover\"\r\n"
                "ST: upnp:rootdevice\r\n"
                "MX: 3\r\n\r\n"
            ).encode()
            
            sock.sendto(msearch_request, (ip_address, port))
            response, addr = sock.recvfrom(1024)
            sock.close()
            
            if response:
                response_str = response.decode('utf-8', errors='ignore')
                
                vulnerabilities = []
                
                # UPnP security vulnerabilities
                vulnerabilities.append({
                    'type': 'UPnP Exposure',
                    'severity': 'Medium',
                    'description': 'UPnP service can be exploited for DDoS amplification attacks'
                })
                
                if 'SERVER:' in response_str:
                    vulnerabilities.append({
                        'type': 'Information Disclosure',
                        'severity': 'Low',
                        'description': 'UPnP service reveals device information'
                    })
                
                # Extract server information
                server_info = None
                for line in response_str.split('\r\n'):
                    if line.startswith('SERVER:'):
                        server_info = line.split(':', 1)[1].strip()
                        break
                
                return {
                    'protocol': 'UPnP',
                    'port': port,
                    'version': '1.0',
                    'description': 'Universal Plug and Play',
                    'vulnerabilities': vulnerabilities,
                    'details': {
                        'server_info': server_info,
                        'responds_to_msearch': True
                    }
                }
        
        except Exception as e:
            print(f"UPnP analysis error: {e}")
        
        return None
    
    def _analyze_snmp(self, ip_address: str, port: int) -> Optional[Dict]:
        """Analyze SNMP protocol"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)
            
            # SNMP GET request for system description (1.3.6.1.2.1.1.1.0)
            snmp_packet = bytearray([
                0x30, 0x26,  # SEQUENCE, length
                0x02, 0x01, 0x00,  # INTEGER version (0 = v1)
                0x04, 0x06, 0x70, 0x75, 0x62, 0x6C, 0x69, 0x63,  # OCTET STRING "public"
                0xA0, 0x19,  # GET REQUEST
                0x02, 0x01, 0x01,  # INTEGER request-id
                0x02, 0x01, 0x00,  # INTEGER error-status
                0x02, 0x01, 0x00,  # INTEGER error-index
                0x30, 0x0E,  # SEQUENCE varbind list
                0x30, 0x0C,  # SEQUENCE varbind
                0x06, 0x08, 0x2B, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00,  # OID 1.3.6.1.2.1.1.1.0
                0x05, 0x00   # NULL
            ])
            
            sock.sendto(snmp_packet, (ip_address, port))
            response, addr = sock.recvfrom(1024)
            sock.close()
            
            if response and len(response) > 10:
                vulnerabilities = []
                
                # Check for default community string
                if b'public' in snmp_packet:
                    vulnerabilities.append({
                        'type': 'Default Community String',
                        'severity': 'High',
                        'description': 'SNMP uses default community string "public"'
                    })
                
                # SNMP v1/v2c security issues
                vulnerabilities.append({
                    'type': 'Weak Authentication',
                    'severity': 'Medium',
                    'description': 'SNMP v1/v2c uses weak community-based authentication'
                })
                
                return {
                    'protocol': 'SNMP',
                    'port': port,
                    'version': 'v1/v2c',
                    'description': 'Simple Network Management Protocol',
                    'vulnerabilities': vulnerabilities,
                    'details': {
                        'community_string': 'public',
                        'responds_to_get': True
                    }
                }
        
        except Exception as e:
            print(f"SNMP analysis error: {e}")
        
        return None
    
    def _generic_protocol_check(self, ip_address: str, port: int, protocol_name: str) -> Optional[Dict]:
        """Generic protocol check for other IoT protocols"""
        try:
            protocol_info = self.protocol_signatures.get(protocol_name)
            if not protocol_info:
                return None
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            result = sock.connect_ex((ip_address, port))
            if result != 0:
                sock.close()
                return None
            
            # Send a simple probe
            sock.send(b'\x00\x01\x02\x03')
            response = sock.recv(1024)
            sock.close()
            
            # Check for protocol patterns
            for pattern in protocol_info['patterns']:
                if pattern in response:
                    return {
                        'protocol': protocol_name.upper(),
                        'port': port,
                        'version': 'Unknown',
                        'description': protocol_info['description'],
                        'vulnerabilities': [{
                            'type': 'Protocol Detection',
                            'severity': 'Info',
                            'description': f'{protocol_name.upper()} protocol detected'
                        }],
                        'details': {
                            'pattern_matched': pattern.hex()
                        }
                    }
        
        except Exception as e:
            print(f"Generic protocol check error for {protocol_name}: {e}")
        
        return None
    
    def _deep_protocol_scan(self, ip_address: str, open_ports: List[Dict]) -> List[Dict]:
        """Perform deep scanning for additional protocols"""
        additional_protocols = []
        
        # Check for web-based IoT interfaces
        web_protocols = self._scan_web_interfaces(ip_address, open_ports)
        additional_protocols.extend(web_protocols)
        
        # Check for custom IoT protocols
        custom_protocols = self._scan_custom_protocols(ip_address, open_ports)
        additional_protocols.extend(custom_protocols)
        
        return additional_protocols
    
    def _scan_web_interfaces(self, ip_address: str, open_ports: List[Dict]) -> List[Dict]:
        """Scan for web-based IoT interfaces"""
        web_protocols = []
        
        for port_info in open_ports:
            port = port_info.get('port')
            service = port_info.get('service', '').lower()
            
            if service in ['http', 'https'] or port in [80, 443, 8080, 8443, 8888]:
                try:
                    protocol = 'https' if port == 443 or service == 'https' else 'http'
                    url = f"{protocol}://{ip_address}:{port}"
                    
                    response = requests.get(url, timeout=self.timeout, verify=False)
                    
                    vulnerabilities = []
                    iot_indicators = []
                    
                    # Check for IoT-specific headers and content
                    headers = response.headers
                    content = response.text.lower()
                    
                    # Common IoT web interface indicators
                    iot_keywords = [
                        'iot', 'smart', 'sensor', 'device', 'gateway', 'router',
                        'camera', 'nvr', 'dvr', 'automation', 'control'
                    ]
                    
                    for keyword in iot_keywords:
                        if keyword in content:
                            iot_indicators.append(keyword)
                    
                    # Security checks
                    if protocol == 'http':
                        vulnerabilities.append({
                            'type': 'Unencrypted Web Interface',
                            'severity': 'Medium',
                            'description': 'Web interface is not encrypted (HTTP instead of HTTPS)'
                        })
                    
                    # Check for default credentials page
                    if any(term in content for term in ['login', 'password', 'admin']):
                        vulnerabilities.append({
                            'type': 'Web Authentication Interface',
                            'severity': 'Info',
                            'description': 'Device has a web-based authentication interface'
                        })
                    
                    # Check server header for IoT device info
                    server_header = headers.get('Server', '')
                    if server_header:
                        for keyword in iot_keywords:
                            if keyword in server_header.lower():
                                iot_indicators.append(f"server:{keyword}")
                    
                    if iot_indicators:
                        web_protocols.append({
                            'protocol': 'HTTP/HTTPS Web Interface',
                            'port': port,
                            'version': protocol.upper(),
                            'description': 'IoT Device Web Interface',
                            'vulnerabilities': vulnerabilities,
                            'details': {
                                'iot_indicators': iot_indicators,
                                'server_header': server_header,
                                'title': self._extract_title(content)
                            }
                        })
                
                except Exception as e:
                    print(f"Web interface scan error for {ip_address}:{port}: {e}")
        
        return web_protocols
    
    def _scan_custom_protocols(self, ip_address: str, open_ports: List[Dict]) -> List[Dict]:
        """Scan for custom IoT protocols on unusual ports"""
        custom_protocols = []
        
        # Common custom IoT ports
        custom_iot_ports = [
            4840,  # OPC UA
            5000, 5001, 5555,  # Common IoT application ports
            6653,  # OpenFlow
            8000, 8001, 8888, 9000, 9001,  # Custom web services
            10000, 10001,  # Custom protocols
        ]
        
        for port_info in open_ports:
            port = port_info.get('port')
            
            if port in custom_iot_ports:
                try:
                    # Try different connection types
                    protocol_info = self._probe_custom_port(ip_address, port)
                    if protocol_info:
                        custom_protocols.append(protocol_info)
                
                except Exception as e:
                    print(f"Custom protocol scan error for {ip_address}:{port}: {e}")
        
        return custom_protocols
    
    def _probe_custom_port(self, ip_address: str, port: int) -> Optional[Dict]:
        """Probe a custom port for protocol information"""
        try:
            # Try TCP first
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            result = sock.connect_ex((ip_address, port))
            if result == 0:
                # Send various probes
                probes = [
                    b'GET / HTTP/1.1\r\nHost: ' + ip_address.encode() + b'\r\n\r\n',
                    b'\x00\x01\x02\x03\x04\x05',
                    b'HELLO\r\n',
                    b'\x16\x03\x01',  # TLS handshake
                ]
                
                for probe in probes:
                    try:
                        sock.send(probe)
                        response = sock.recv(1024)
                        
                        if response:
                            protocol_type = self._identify_protocol_from_response(response, port)
                            if protocol_type:
                                sock.close()
                                return {
                                    'protocol': protocol_type,
                                    'port': port,
                                    'version': 'Unknown',
                                    'description': f'Custom IoT Protocol on port {port}',
                                    'vulnerabilities': [{
                                        'type': 'Custom Protocol',
                                        'severity': 'Info',
                                        'description': f'Custom or proprietary protocol detected on port {port}'
                                    }],
                                    'details': {
                                        'response_sample': response[:50].hex()
                                    }
                                }
                    except:
                        continue
            
            sock.close()
        
        except Exception as e:
            print(f"Custom port probe error: {e}")
        
        return None
    
    def _identify_protocol_from_response(self, response: bytes, port: int) -> Optional[str]:
        """Identify protocol from response data"""
        response_str = response.decode('utf-8', errors='ignore').lower()
        
        # HTTP-like responses
        if b'http/' in response or b'html' in response:
            return 'HTTP-based Service'
        
        # JSON responses (REST APIs)
        if response_str.startswith('{') or 'json' in response_str:
            return 'JSON API'
        
        # XML responses
        if b'<?xml' in response or b'<xml' in response:
            return 'XML-based Service'
        
        # Binary protocols
        if len(response) > 0 and all(b < 32 or b > 126 for b in response[:10]):
            return 'Binary Protocol'
        
        # OPC UA (port 4840)
        if port == 4840:
            return 'OPC UA'
        
        return 'Unknown Protocol'
    
    def _extract_title(self, html_content: str) -> str:
        """Extract title from HTML content"""
        try:
            title_match = re.search(r'<title[^>]*>([^<]+)</title>', html_content, re.IGNORECASE)
            if title_match:
                return title_match.group(1).strip()
        except:
            pass
        return 'Unknown'
    
    def generate_protocol_report(self, protocols: List[Dict]) -> Dict:
        """Generate a comprehensive protocol analysis report"""
        if not protocols:
            return {
                'summary': 'No IoT protocols detected',
                'total_protocols': 0,
                'security_score': 100,
                'recommendations': []
            }
        
        total_protocols = len(protocols)
        total_vulnerabilities = sum(len(p.get('vulnerabilities', [])) for p in protocols)
        
        # Calculate security score
        critical_vulns = sum(1 for p in protocols for v in p.get('vulnerabilities', []) if v.get('severity') == 'Critical')
        high_vulns = sum(1 for p in protocols for v in p.get('vulnerabilities', []) if v.get('severity') == 'High')
        medium_vulns = sum(1 for p in protocols for v in p.get('vulnerabilities', []) if v.get('severity') == 'Medium')
        
        security_score = max(0, 100 - (critical_vulns * 30) - (high_vulns * 20) - (medium_vulns * 10))
        
        # Generate recommendations
        recommendations = []
        
        if any('No Authentication' in str(v) for p in protocols for v in p.get('vulnerabilities', [])):
            recommendations.append('تفعيل المصادقة لجميع البروتوكولات المكتشفة')
        
        if any('Unencrypted' in str(v) for p in protocols for v in p.get('vulnerabilities', [])):
            recommendations.append('تفعيل التشفير لجميع الاتصالات')
        
        if any(p.get('protocol') in ['Modbus TCP', 'BACnet'] for p in protocols):
            recommendations.append('عزل البروتوكولات الصناعية في شبكة منفصلة')
        
        if any(p.get('protocol') == 'UPnP' for p in protocols):
            recommendations.append('تعطيل UPnP إذا لم يكن ضرورياً')
        
        recommendations.append('تحديث البرامج الثابتة لجميع الأجهزة')
        recommendations.append('مراقبة حركة البيانات للبروتوكولات المكتشفة')
        
        return {
            'summary': f'تم اكتشاف {total_protocols} بروتوكول IoT مع {total_vulnerabilities} ثغرة أمنية',
            'total_protocols': total_protocols,
            'total_vulnerabilities': total_vulnerabilities,
            'security_score': security_score,
            'protocol_breakdown': {
                'industrial': len([p for p in protocols if p.get('protocol') in ['Modbus TCP', 'BACnet', 'DNP3']]),
                'iot_messaging': len([p for p in protocols if p.get('protocol') in ['MQTT', 'CoAP']]),
                'network_services': len([p for p in protocols if p.get('protocol') in ['UPnP', 'SNMP']]),
                'web_interfaces': len([p for p in protocols if 'Web Interface' in p.get('protocol', '')]),
                'custom': len([p for p in protocols if 'Custom' in p.get('protocol', '') or 'Unknown' in p.get('protocol', '')])
            },
            'recommendations': recommendations
        }

