"""
Zigbee Protocol Analysis
Detects and analyzes Zigbee devices and networks
"""

import logging
from typing import Dict, List, Optional
from datetime import datetime
import struct
import socket

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ZigbeeAnalyzer:
    """
    Zigbee protocol analyzer and security scanner
    Note: Requires Zigbee coordinator/sniffer hardware for full functionality
    """
    
    # Zigbee channels (IEEE 802.15.4)
    ZIGBEE_CHANNELS = list(range(11, 27))  # Channels 11-26 (2.4 GHz)
    
    # Common Zigbee device types
    DEVICE_TYPES = {
        0x0000: 'Coordinator',
        0x0001: 'Router',
        0x0002: 'End Device',
        0x0003: 'Unknown Device'
    }
    
    # Zigbee cluster IDs (common)
    CLUSTER_IDS = {
        0x0000: 'Basic',
        0x0001: 'Power Configuration',
        0x0003: 'Identify',
        0x0004: 'Groups',
        0x0005: 'Scenes',
        0x0006: 'On/Off',
        0x0008: 'Level Control',
        0x0009: 'Alarms',
        0x0300: 'Color Control',
        0x0400: 'Illuminance Measurement',
        0x0402: 'Temperature Measurement',
        0x0403: 'Pressure Measurement',
        0x0405: 'Humidity Measurement',
        0x0406: 'Occupancy Sensing',
        0x0500: 'IAS Zone',
        0x0B04: 'Electrical Measurement'
    }
    
    def __init__(self):
        """Initialize Zigbee analyzer"""
        self.discovered_devices = []
        self.vulnerabilities = []
        self.network_info = {}
    
    def detect_zigbee_presence(self, scan_results: List[Dict]) -> List[Dict]:
        """
        Detect Zigbee devices from general network scan
        
        Args:
            scan_results: Results from network scanning
            
        Returns:
            List of potential Zigbee devices
        """
        potential_zigbee = []
        
        for device in scan_results:
            # Check for Zigbee indicators
            indicators = []
            
            # Check manufacturer
            manufacturer = (device.get('manufacturer', '') or '').lower()
            zigbee_manufacturers = [
                'philips', 'hue', 'xiaomi', 'aqara', 'ikea', 
                'osram', 'samsung', 'smartthings', 'sengled',
                'tuya', 'sonoff', 'zigbee'
            ]
            
            for mfr in zigbee_manufacturers:
                if mfr in manufacturer:
                    indicators.append(f'Zigbee manufacturer: {mfr}')
                    break
            
            # Check device name/hostname
            hostname = (device.get('hostname', '') or '').lower()
            if any(term in hostname for term in ['zigbee', 'zha', 'z2m', 'zigbee2mqtt']):
                indicators.append('Zigbee keyword in hostname')
            
            # Check for Zigbee coordinator ports
            open_ports = device.get('open_ports', [])
            if 8888 in open_ports or 9999 in open_ports:
                indicators.append('Zigbee coordinator port detected')
            
            # Check services
            services = device.get('services', [])
            for service in services:
                service_name = service if isinstance(service, str) else service.get('name', '')
                if 'zigbee' in service_name.lower():
                    indicators.append('Zigbee service detected')
            
            if indicators:
                device_info = device.copy()
                device_info['zigbee_indicators'] = indicators
                device_info['protocol'] = 'Zigbee'
                device_info['confidence'] = len(indicators) * 0.3
                potential_zigbee.append(device_info)
        
        self.discovered_devices = potential_zigbee
        return potential_zigbee
    
    def analyze_zigbee_coordinator(self, ip: str, port: int = 8888) -> Dict:
        """
        Analyze Zigbee coordinator/gateway
        
        Args:
            ip: Coordinator IP address
            port: Coordinator port
            
        Returns:
            Analysis results
        """
        analysis = {
            'device_type': 'Zigbee Coordinator',
            'ip': ip,
            'port': port,
            'vulnerabilities': [],
            'security_score': 100,
            'timestamp': datetime.now().isoformat()
        }
        
        # Check if coordinator is exposed
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            result = sock.connect_ex((ip, port))
            sock.close()
            
            if result == 0:
                vuln = {
                    'type': 'Exposed Zigbee Coordinator',
                    'severity': 'High',
                    'description': f'Zigbee coordinator accessible on {ip}:{port}',
                    'recommendation': 'Restrict coordinator access to local network only'
                }
                analysis['vulnerabilities'].append(vuln)
                analysis['security_score'] -= 30
                self.vulnerabilities.append(vuln)
        except Exception as e:
            logger.debug(f"Error checking coordinator: {e}")
        
        return analysis
    
    def check_zigbee_security(self, network_info: Dict) -> Dict:
        """
        Check Zigbee network security configuration
        
        Args:
            network_info: Zigbee network information
            
        Returns:
            Security assessment
        """
        assessment = {
            'network_key_status': 'Unknown',
            'install_code': 'Unknown',
            'trust_center': 'Unknown',
            'vulnerabilities': [],
            'security_score': 100
        }
        
        # Check for default network keys
        if network_info.get('using_default_key'):
            vuln = {
                'type': 'Default Network Key',
                'severity': 'Critical',
                'description': 'Zigbee network using default or well-known key',
                'recommendation': 'Generate and configure unique network key'
            }
            assessment['vulnerabilities'].append(vuln)
            assessment['security_score'] -= 50
            self.vulnerabilities.append(vuln)
        
        # Check for open joining
        if network_info.get('permit_join', False):
            vuln = {
                'type': 'Open Network Joining',
                'severity': 'High',
                'description': 'Zigbee network allows device joining without restrictions',
                'recommendation': 'Disable permit join when not adding devices'
            }
            assessment['vulnerabilities'].append(vuln)
            assessment['security_score'] -= 30
            self.vulnerabilities.append(vuln)
        
        # Check for missing install codes
        if not network_info.get('requires_install_code'):
            vuln = {
                'type': 'No Install Code Requirement',
                'severity': 'Medium',
                'description': 'Network does not require install codes for joining',
                'recommendation': 'Enable install code requirement for Zigbee 3.0'
            }
            assessment['vulnerabilities'].append(vuln)
            assessment['security_score'] -= 20
            self.vulnerabilities.append(vuln)
        
        return assessment
    
    def analyze_device_security(self, device_info: Dict) -> Dict:
        """
        Analyze individual Zigbee device security
        
        Args:
            device_info: Device information
            
        Returns:
            Device security analysis
        """
        analysis = {
            'device_id': device_info.get('ieee_address', 'Unknown'),
            'device_type': device_info.get('device_type', 'Unknown'),
            'vulnerabilities': [],
            'security_score': 100
        }
        
        # Check firmware version
        fw_version = device_info.get('firmware_version')
        if fw_version and self._is_outdated_firmware(fw_version):
            vuln = {
                'type': 'Outdated Firmware',
                'severity': 'Medium',
                'description': f'Device running outdated firmware: {fw_version}',
                'recommendation': 'Update device firmware to latest version'
            }
            analysis['vulnerabilities'].append(vuln)
            analysis['security_score'] -= 20
        
        # Check for insecure clusters
        clusters = device_info.get('clusters', [])
        insecure_clusters = [0x0000, 0x0001, 0x0003]  # Basic, Power, Identify
        
        exposed_insecure = [c for c in clusters if c in insecure_clusters]
        if exposed_insecure:
            vuln = {
                'type': 'Exposed Management Clusters',
                'severity': 'Low',
                'description': f'Device exposes management clusters: {exposed_insecure}',
                'recommendation': 'Restrict access to management clusters'
            }
            analysis['vulnerabilities'].append(vuln)
            analysis['security_score'] -= 10
        
        return analysis
    
    def _is_outdated_firmware(self, version: str) -> bool:
        """Check if firmware version is outdated"""
        # Simple heuristic - versions < 1.0 or very old dates
        try:
            if version.startswith('0.'):
                return True
            # Check for old year patterns
            if any(year in version for year in ['2018', '2019', '2020']):
                return True
        except:
            pass
        return False
    
    def detect_zigbee_attacks(self, network_traffic: List[bytes]) -> List[Dict]:
        """
        Detect potential Zigbee attacks from network traffic
        
        Args:
            network_traffic: Captured Zigbee packets
            
        Returns:
            List of detected attacks
        """
        attacks = []
        
        # This would require actual packet analysis
        # Placeholder for attack detection patterns
        attack_patterns = {
            'replay_attack': b'\x08\x00',  # Simplified pattern
            'jamming': None,  # Would detect repeated interference
            'key_extraction': None  # Would detect key negotiation anomalies
        }
        
        logger.info("Zigbee attack detection requires hardware sniffer")
        
        return attacks
    
    def generate_report(self) -> Dict:
        """Generate comprehensive Zigbee analysis report"""
        report = {
            'protocol': 'Zigbee',
            'timestamp': datetime.now().isoformat(),
            'discovered_devices': len(self.discovered_devices),
            'devices': self.discovered_devices,
            'total_vulnerabilities': len(self.vulnerabilities),
            'vulnerabilities': self.vulnerabilities,
            'recommendations': []
        }
        
        # Generate recommendations
        if any(v['type'] == 'Default Network Key' for v in self.vulnerabilities):
            report['recommendations'].append(
                'CRITICAL: Change default Zigbee network key immediately'
            )
        
        if any(v['type'] == 'Open Network Joining' for v in self.vulnerabilities):
            report['recommendations'].append(
                'Disable permit join on Zigbee coordinator when not adding devices'
            )
        
        if any(v['type'] == 'Exposed Zigbee Coordinator' for v in self.vulnerabilities):
            report['recommendations'].append(
                'Restrict Zigbee coordinator access to local network only'
            )
        
        return report


# Known Zigbee device fingerprints
ZIGBEE_FINGERPRINTS = {
    'philips_hue': {
        'manufacturer': 'Philips',
        'model_patterns': ['hue', 'LWB', 'LCT'],
        'device_types': ['Light', 'Bridge']
    },
    'xiaomi_aqara': {
        'manufacturer': 'LUMI',
        'model_patterns': ['lumi.', 'aqara'],
        'device_types': ['Sensor', 'Switch', 'Plug']
    },
    'ikea_tradfri': {
        'manufacturer': 'IKEA',
        'model_patterns': ['TRADFRI'],
        'device_types': ['Light', 'Remote', 'Plug']
    },
    'samsung_smartthings': {
        'manufacturer': 'Samsung',
        'model_patterns': ['SmartThings'],
        'device_types': ['Hub', 'Sensor', 'Plug']
    }
}


# Example usage
def main():
    """Test Zigbee analyzer"""
    print("="*70)
    print("Zigbee Protocol Analyzer - Phase 5")
    print("="*70)
    
    analyzer = ZigbeeAnalyzer()
    
    # Test with sample scan results
    sample_devices = [
        {
            'ip_address': '192.168.1.50',
            'manufacturer': 'Philips',
            'hostname': 'Philips-hue-bridge',
            'open_ports': [80, 443, 8888]
        },
        {
            'ip_address': '192.168.1.51',
            'manufacturer': 'LUMI',
            'hostname': 'xiaomi-gateway',
            'services': [{'name': 'Zigbee Gateway'}]
        }
    ]
    
    print("\nDetecting Zigbee devices...")
    zigbee_devices = analyzer.detect_zigbee_presence(sample_devices)
    
    print(f"\nFound {len(zigbee_devices)} potential Zigbee devices:")
    for device in zigbee_devices:
        print(f"\n  IP: {device['ip_address']}")
        print(f"  Manufacturer: {device.get('manufacturer', 'Unknown')}")
        print(f"  Confidence: {device['confidence']:.0%}")
        print(f"  Indicators:")
        for indicator in device['zigbee_indicators']:
            print(f"    - {indicator}")
    
    # Generate report
    report = analyzer.generate_report()
    
    print(f"\n{'='*70}")
    print("Analysis Summary")
    print(f"{'='*70}")
    print(f"Devices Found: {report['discovered_devices']}")
    print(f"Vulnerabilities: {report['total_vulnerabilities']}")
    
    if report['recommendations']:
        print(f"\nRecommendations:")
        for rec in report['recommendations']:
            print(f"  • {rec}")


if __name__ == '__main__':
    main()
