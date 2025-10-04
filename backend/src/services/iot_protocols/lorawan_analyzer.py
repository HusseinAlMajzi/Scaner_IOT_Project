"""
LoRaWAN Protocol Analysis
Detects and analyzes LoRaWAN devices and gateways
"""

import logging
from typing import Dict, List, Optional
from datetime import datetime
import struct

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class LoRaWANAnalyzer:
    """
    LoRaWAN protocol analyzer and security scanner
    Analyzes LoRa gateways and network servers
    """
    
    # LoRaWAN frequency bands
    FREQUENCY_BANDS = {
        'EU868': '863-870 MHz (Europe)',
        'US915': '902-928 MHz (North America)',
        'CN779': '779-787 MHz (China)',
        'EU433': '433-434 MHz (Europe)',
        'AU915': '915-928 MHz (Australia)',
        'AS923': '920-925 MHz (Asia)',
        'KR920': '920-923 MHz (South Korea)',
        'IN865': '865-867 MHz (India)'
    }
    
    # LoRaWAN message types
    MESSAGE_TYPES = {
        0x00: 'Join Request',
        0x01: 'Join Accept',
        0x02: 'Unconfirmed Data Up',
        0x03: 'Unconfirmed Data Down',
        0x04: 'Confirmed Data Up',
        0x05: 'Confirmed Data Down',
        0x06: 'Rejoin Request',
        0x07: 'Proprietary'
    }
    
    # Common LoRaWAN ports
    LORAWAN_PORTS = {
        1700: 'Semtech UDP Protocol',
        1701: 'Semtech UDP Protocol (alternate)',
        8080: 'LoRa Network Server HTTP',
        8883: 'LoRa Network Server MQTT',
        3001: 'ChirpStack Gateway Bridge'
    }
    
    def __init__(self):
        """Initialize LoRaWAN analyzer"""
        self.discovered_gateways = []
        self.discovered_devices = []
        self.vulnerabilities = []
    
    def detect_lorawan_presence(self, scan_results: List[Dict]) -> List[Dict]:
        """
        Detect LoRaWAN gateways and devices
        
        Args:
            scan_results: Results from network scanning
            
        Returns:
            List of potential LoRaWAN components
        """
        potential_lorawan = []
        
        for device in scan_results:
            indicators = []
            
            # Check manufacturer
            manufacturer = (device.get('manufacturer', '') or '').lower()
            lorawan_manufacturers = [
                'semtech', 'chirpstack', 'ttn', 'things network',
                'loriot', 'actility', 'kerlink', 'multitech',
                'rak wireless', 'laird', 'lora', 'lorawan'
            ]
            
            for mfr in lorawan_manufacturers:
                if mfr in manufacturer:
                    indicators.append(f'LoRaWAN manufacturer: {mfr}')
                    break
            
            # Check hostname
            hostname = (device.get('hostname', '') or '').lower()
            if any(term in hostname for term in ['lora', 'lorawan', 'chirpstack', 'ttn', 'gateway']):
                indicators.append('LoRaWAN keyword in hostname')
            
            # Check for LoRaWAN ports
            open_ports = device.get('open_ports', [])
            lorawan_port_found = False
            for port, desc in self.LORAWAN_PORTS.items():
                if port in open_ports:
                    indicators.append(f'LoRaWAN port detected: {port} ({desc})')
                    lorawan_port_found = True
            
            # Check services
            services = device.get('services', [])
            for service in services:
                service_name = service if isinstance(service, str) else service.get('name', '')
                if any(term in service_name.lower() for term in ['lora', 'chirpstack']):
                    indicators.append('LoRaWAN service detected')
            
            if indicators:
                device_info = device.copy()
                device_info['lorawan_indicators'] = indicators
                device_info['protocol'] = 'LoRaWAN'
                device_info['confidence'] = min(len(indicators) * 0.3, 1.0)
                device_info['component_type'] = 'Gateway' if lorawan_port_found else 'Unknown'
                potential_lorawan.append(device_info)
        
        self.discovered_gateways = potential_lorawan
        return potential_lorawan
    
    def analyze_gateway(self, ip: str, port: int = 1700) -> Dict:
        """
        Analyze LoRaWAN gateway
        
        Args:
            ip: Gateway IP address
            port: Gateway port
            
        Returns:
            Analysis results
        """
        analysis = {
            'device_type': 'LoRaWAN Gateway',
            'ip': ip,
            'port': port,
            'vulnerabilities': [],
            'security_score': 100,
            'timestamp': datetime.now().isoformat()
        }
        
        # Check if gateway is exposed to internet
        import socket
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(5)
            
            # Try to send PULL_DATA packet
            pull_data = bytearray([
                0x02,  # Protocol version
                0x00, 0x00,  # Random token
                0x02  # PULL_DATA identifier
            ])
            # Add gateway EUI (8 bytes of zeros for test)
            pull_data.extend([0x00] * 8)
            
            sock.sendto(pull_data, (ip, port))
            
            # If we can send data, gateway is accessible
            vuln = {
                'type': 'Exposed LoRaWAN Gateway',
                'severity': 'High',
                'description': f'LoRaWAN gateway accessible on {ip}:{port}',
                'recommendation': 'Restrict gateway access to VPN or specific IPs only'
            }
            analysis['vulnerabilities'].append(vuln)
            analysis['security_score'] -= 35
            self.vulnerabilities.append(vuln)
            
            sock.close()
        except Exception as e:
            logger.debug(f"Error checking gateway: {e}")
        
        return analysis
    
    def check_lorawan_security(self, network_info: Dict) -> Dict:
        """
        Check LoRaWAN network security configuration
        
        Args:
            network_info: LoRaWAN network information
            
        Returns:
            Security assessment
        """
        assessment = {
            'activation_method': network_info.get('activation', 'Unknown'),
            'encryption': 'Unknown',
            'vulnerabilities': [],
            'security_score': 100
        }
        
        # Check activation method (OTAA vs ABP)
        if network_info.get('activation') == 'ABP':
            vuln = {
                'type': 'ABP Activation Used',
                'severity': 'Medium',
                'description': 'Network uses ABP instead of OTAA activation',
                'recommendation': 'Use OTAA activation for better security'
            }
            assessment['vulnerabilities'].append(vuln)
            assessment['security_score'] -= 20
            self.vulnerabilities.append(vuln)
        
        # Check for default keys
        if network_info.get('using_default_appkey'):
            vuln = {
                'type': 'Default Application Key',
                'severity': 'Critical',
                'description': 'Device using default or weak application key',
                'recommendation': 'Generate unique, strong application keys'
            }
            assessment['vulnerabilities'].append(vuln)
            assessment['security_score'] -= 50
            self.vulnerabilities.append(vuln)
        
        # Check frame counter
        if not network_info.get('frame_counter_check'):
            vuln = {
                'type': 'Frame Counter Check Disabled',
                'severity': 'High',
                'description': 'Frame counter validation disabled (replay attack risk)',
                'recommendation': 'Enable frame counter checking'
            }
            assessment['vulnerabilities'].append(vuln)
            assessment['security_score'] -= 30
            self.vulnerabilities.append(vuln)
        
        # Check for public network
        if network_info.get('is_public_network'):
            vuln = {
                'type': 'Public Network Usage',
                'severity': 'Low',
                'description': 'Using public LoRaWAN network (less control)',
                'recommendation': 'Consider private network for sensitive applications'
            }
            assessment['vulnerabilities'].append(vuln)
            assessment['security_score'] -= 10
        
        return assessment
    
    def analyze_device_security(self, device_info: Dict) -> Dict:
        """
        Analyze individual LoRaWAN end-device security
        
        Args:
            device_info: Device information
            
        Returns:
            Device security analysis
        """
        analysis = {
            'device_eui': device_info.get('dev_eui', 'Unknown'),
            'device_type': device_info.get('device_type', 'Unknown'),
            'vulnerabilities': [],
            'security_score': 100
        }
        
        # Check activation method
        if device_info.get('activation_method') == 'ABP':
            vuln = {
                'type': 'ABP Activation',
                'severity': 'Medium',
                'description': 'Device uses ABP instead of OTAA',
                'recommendation': 'Re-provision device with OTAA'
            }
            analysis['vulnerabilities'].append(vuln)
            analysis['security_score'] -= 20
        
        # Check LoRaWAN version
        lorawan_version = device_info.get('lorawan_version', '1.0')
        if lorawan_version == '1.0':
            vuln = {
                'type': 'Outdated LoRaWAN Version',
                'severity': 'Medium',
                'description': 'Device using LoRaWAN 1.0 (consider upgrading)',
                'recommendation': 'Upgrade to LoRaWAN 1.1 for improved security'
            }
            analysis['vulnerabilities'].append(vuln)
            analysis['security_score'] -= 15
        
        # Check for weak data rate
        data_rate = device_info.get('data_rate')
        if data_rate and data_rate < 2:
            vuln = {
                'type': 'Low Data Rate',
                'severity': 'Low',
                'description': 'Device using low data rate (longer air time)',
                'recommendation': 'Optimize data rate to reduce exposure'
            }
            analysis['vulnerabilities'].append(vuln)
            analysis['security_score'] -= 10
        
        return analysis
    
    def detect_lorawan_attacks(self) -> List[Dict]:
        """
        Detect potential LoRaWAN attacks
        
        Returns:
            List of known attack vectors
        """
        attacks = [
            {
                'name': 'Replay Attack',
                'description': 'Replaying captured LoRaWAN frames',
                'mitigation': 'Enable frame counter validation',
                'severity': 'High'
            },
            {
                'name': 'Bit-Flipping Attack',
                'description': 'Modifying encrypted payloads',
                'mitigation': 'Use LoRaWAN 1.1 with improved MIC',
                'severity': 'Medium'
            },
            {
                'name': 'ACK Spoofing',
                'description': 'Sending fake acknowledgments',
                'mitigation': 'Validate all downlink messages',
                'severity': 'Medium'
            },
            {
                'name': 'Jamming',
                'description': 'RF jamming on LoRa frequencies',
                'mitigation': 'Monitor RF spectrum, use multiple channels',
                'severity': 'High'
            },
            {
                'name': 'Gateway Impersonation',
                'description': 'Rogue gateway capturing join requests',
                'mitigation': 'Use private networks with authenticated gateways',
                'severity': 'High'
            }
        ]
        
        return attacks
    
    def generate_report(self) -> Dict:
        """Generate comprehensive LoRaWAN analysis report"""
        report = {
            'protocol': 'LoRaWAN',
            'timestamp': datetime.now().isoformat(),
            'discovered_gateways': len(self.discovered_gateways),
            'discovered_devices': len(self.discovered_devices),
            'gateways': self.discovered_gateways,
            'devices': self.discovered_devices,
            'total_vulnerabilities': len(self.vulnerabilities),
            'vulnerabilities': self.vulnerabilities,
            'recommendations': [],
            'security_notes': []
        }
        
        # Generate recommendations
        if any(v['type'] == 'Default Application Key' for v in self.vulnerabilities):
            report['recommendations'].append(
                'CRITICAL: Replace all default application keys with unique keys'
            )
        
        if any(v['type'] == 'Frame Counter Check Disabled' for v in self.vulnerabilities):
            report['recommendations'].append(
                'Enable frame counter validation to prevent replay attacks'
            )
        
        if any(v['type'] == 'ABP Activation Used' for v in self.vulnerabilities):
            report['recommendations'].append(
                'Migrate devices from ABP to OTAA activation'
            )
        
        if any(v['type'] == 'Exposed LoRaWAN Gateway' for v in self.vulnerabilities):
            report['recommendations'].append(
                'Restrict gateway access to VPN or whitelist specific IPs'
            )
        
        # Add security notes
        report['security_notes'] = [
            'LoRaWAN uses AES-128 encryption with two session keys',
            'OTAA provides better security than ABP activation',
            'LoRaWAN 1.1 fixes several security issues from 1.0',
            'Always validate frame counters to prevent replays',
            'Monitor gateway connectivity for anomalies',
            'Use private networks for critical applications'
        ]
        
        return report


# Known LoRaWAN device types
LORAWAN_DEVICE_TYPES = {
    'environmental_sensor': ['Temperature', 'Humidity', 'Air Quality'],
    'tracking': ['GPS Tracker', 'Asset Tracker'],
    'utility': ['Water Meter', 'Gas Meter', 'Electricity Meter'],
    'industrial': ['Pressure Sensor', 'Flow Meter', 'Level Sensor'],
    'agriculture': ['Soil Moisture', 'Weather Station'],
    'smart_city': ['Parking Sensor', 'Waste Management', 'Street Light']
}


# Example usage
def main():
    """Test LoRaWAN analyzer"""
    print("="*70)
    print("LoRaWAN Protocol Analyzer - Phase 5")
    print("="*70)
    
    analyzer = LoRaWANAnalyzer()
    
    # Test with sample scan results
    sample_devices = [
        {
            'ip_address': '192.168.1.70',
            'manufacturer': 'Semtech',
            'hostname': 'lora-gateway-01',
            'open_ports': [1700, 22, 80]
        },
        {
            'ip_address': '192.168.1.71',
            'hostname': 'chirpstack-server',
            'open_ports': [8080, 8883, 3001]
        }
    ]
    
    print("\nDetecting LoRaWAN components...")
    lorawan_components = analyzer.detect_lorawan_presence(sample_devices)
    
    print(f"\nFound {len(lorawan_components)} potential LoRaWAN components:")
    for device in lorawan_components:
        print(f"\n  IP: {device['ip_address']}")
        print(f"  Type: {device.get('component_type', 'Unknown')}")
        print(f"  Confidence: {device['confidence']:.0%}")
        print(f"  Indicators:")
        for indicator in device['lorawan_indicators']:
            print(f"    - {indicator}")
    
    # Show known attacks
    attacks = analyzer.detect_lorawan_attacks()
    print(f"\n{'='*70}")
    print(f"Known LoRaWAN Attack Vectors: {len(attacks)}")
    print(f"{'='*70}")
    for attack in attacks[:3]:
        print(f"\n  [{attack['severity']}] {attack['name']}")
        print(f"  Description: {attack['description']}")
        print(f"  Mitigation: {attack['mitigation']}")
    
    # Generate report
    report = analyzer.generate_report()
    
    print(f"\n{'='*70}")
    print("Analysis Summary")
    print(f"{'='*70}")
    print(f"Gateways Found: {report['discovered_gateways']}")
    print(f"Devices Found: {report['discovered_devices']}")
    print(f"Vulnerabilities: {report['total_vulnerabilities']}")
    
    if report['security_notes']:
        print(f"\nSecurity Notes:")
        for note in report['security_notes'][:3]:
            print(f"  • {note}")


if __name__ == '__main__':
    main()
