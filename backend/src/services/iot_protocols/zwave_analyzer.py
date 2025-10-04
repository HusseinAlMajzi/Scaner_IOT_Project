"""
Z-Wave Protocol Analysis
Detects and analyzes Z-Wave devices and networks
"""

import logging
from typing import Dict, List, Optional
from datetime import datetime

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ZWaveAnalyzer:
    """
    Z-Wave protocol analyzer and security scanner
    Note: Requires Z-Wave controller for full functionality
    """
    
    # Z-Wave frequency bands
    FREQUENCY_BANDS = {
        'EU': '868.42 MHz',
        'US': '908.42 MHz',
        'ANZ': '921.42 MHz',
        'HK': '919.82 MHz',
        'IN': '865.22 MHz',
        'RU': '869.00 MHz'
    }
    
    # Z-Wave device classes
    DEVICE_CLASSES = {
        0x01: 'Remote Controller',
        0x02: 'Static Controller',
        0x03: 'AV Control Point',
        0x04: 'Display',
        0x05: 'Network Extender',
        0x06: 'Appliance',
        0x07: 'Sensor Notification',
        0x08: 'Thermostat',
        0x09: 'Window Covering',
        0x10: 'Binary Switch',
        0x11: 'Multilevel Switch',
        0x20: 'Binary Sensor',
        0x21: 'Multilevel Sensor',
        0x30: 'Pulse Meter',
        0x31: 'Meter',
        0x40: 'Entry Control',
        0xA1: 'Alarm Sensor'
    }
    
    # Common Z-Wave manufacturers
    MANUFACTURERS = {
        0x0086: 'Aeotec',
        0x010F: 'Fibaro',
        0x0063: 'GE/Jasco',
        0x0258: 'Neo Coolcam',
        0x0109: 'Vision Security',
        0x0175: 'Remotec',
        0x0060: 'Everspring',
        0x0184: 'Philio Tech',
        0x0099: 'Widom',
        0x0208: 'Wenzhou MTLC'
    }
    
    def __init__(self):
        """Initialize Z-Wave analyzer"""
        self.discovered_devices = []
        self.vulnerabilities = []
        self.network_info = {}
    
    def detect_zwave_presence(self, scan_results: List[Dict]) -> List[Dict]:
        """
        Detect Z-Wave devices from general network scan
        
        Args:
            scan_results: Results from network scanning
            
        Returns:
            List of potential Z-Wave devices
        """
        potential_zwave = []
        
        for device in scan_results:
            indicators = []
            
            # Check manufacturer
            manufacturer = (device.get('manufacturer', '') or '').lower()
            zwave_manufacturers = [
                'aeotec', 'fibaro', 'ge', 'jasco', 'kwikset',
                'schlage', 'yale', 'vision', 'remotec', 'zwave', 'z-wave'
            ]
            
            for mfr in zwave_manufacturers:
                if mfr in manufacturer:
                    indicators.append(f'Z-Wave manufacturer: {mfr}')
                    break
            
            # Check device name/hostname
            hostname = (device.get('hostname', '') or '').lower()
            if any(term in hostname for term in ['zwave', 'z-wave', 'zwavejs', 'openzwave']):
                indicators.append('Z-Wave keyword in hostname')
            
            # Check for Z-Wave controller ports
            open_ports = device.get('open_ports', [])
            if 3000 in open_ports or 8091 in open_ports:  # Common Z-Wave UI ports
                indicators.append('Z-Wave controller port detected')
            
            # Check device type
            device_type = (device.get('device_type', '') or '').lower()
            if any(term in device_type for term in ['smart_lock', 'door_lock', 'thermostat']):
                # These are commonly Z-Wave devices
                indicators.append(f'Common Z-Wave device type: {device_type}')
            
            if indicators:
                device_info = device.copy()
                device_info['zwave_indicators'] = indicators
                device_info['protocol'] = 'Z-Wave'
                device_info['confidence'] = min(len(indicators) * 0.35, 1.0)
                potential_zwave.append(device_info)
        
        self.discovered_devices = potential_zwave
        return potential_zwave
    
    def analyze_zwave_controller(self, ip: str, port: int = 8091) -> Dict:
        """
        Analyze Z-Wave controller/gateway
        
        Args:
            ip: Controller IP address
            port: Controller port
            
        Returns:
            Analysis results
        """
        analysis = {
            'device_type': 'Z-Wave Controller',
            'ip': ip,
            'port': port,
            'vulnerabilities': [],
            'security_score': 100,
            'timestamp': datetime.now().isoformat()
        }
        
        # Check if controller UI is exposed
        import socket
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            result = sock.connect_ex((ip, port))
            sock.close()
            
            if result == 0:
                vuln = {
                    'type': 'Exposed Z-Wave Controller',
                    'severity': 'High',
                    'description': f'Z-Wave controller UI accessible on {ip}:{port}',
                    'recommendation': 'Restrict controller access with authentication and firewall'
                }
                analysis['vulnerabilities'].append(vuln)
                analysis['security_score'] -= 35
                self.vulnerabilities.append(vuln)
        except Exception as e:
            logger.debug(f"Error checking controller: {e}")
        
        return analysis
    
    def check_zwave_security(self, network_info: Dict) -> Dict:
        """
        Check Z-Wave network security configuration
        
        Args:
            network_info: Z-Wave network information
            
        Returns:
            Security assessment
        """
        assessment = {
            's0_security': 'Unknown',
            's2_security': 'Unknown',
            'network_key': 'Unknown',
            'vulnerabilities': [],
            'security_score': 100
        }
        
        # Check for S2 security (Z-Wave Plus)
        if not network_info.get('s2_enabled'):
            vuln = {
                'type': 'S2 Security Not Enabled',
                'severity': 'High',
                'description': 'Z-Wave network not using S2 security framework',
                'recommendation': 'Upgrade to Z-Wave Plus with S2 security'
            }
            assessment['vulnerabilities'].append(vuln)
            assessment['security_score'] -= 30
            self.vulnerabilities.append(vuln)
        
        # Check for default network key
        if network_info.get('using_default_key'):
            vuln = {
                'type': 'Default Network Key',
                'severity': 'Critical',
                'description': 'Z-Wave network using default or factory network key',
                'recommendation': 'Generate and configure unique network key'
            }
            assessment['vulnerabilities'].append(vuln)
            assessment['security_score'] -= 50
            self.vulnerabilities.append(vuln)
        
        # Check for insecure inclusion mode
        if network_info.get('insecure_inclusion_enabled'):
            vuln = {
                'type': 'Insecure Device Inclusion',
                'severity': 'Medium',
                'description': 'Network allows insecure device inclusion',
                'recommendation': 'Use secure inclusion with DSK verification'
            }
            assessment['vulnerabilities'].append(vuln)
            assessment['security_score'] -= 20
            self.vulnerabilities.append(vuln)
        
        return assessment
    
    def analyze_device_security(self, device_info: Dict) -> Dict:
        """
        Analyze individual Z-Wave device security
        
        Args:
            device_info: Device information
            
        Returns:
            Device security analysis
        """
        analysis = {
            'device_id': device_info.get('node_id', 'Unknown'),
            'device_type': device_info.get('device_class', 'Unknown'),
            'vulnerabilities': [],
            'security_score': 100
        }
        
        # Check security level
        security_level = device_info.get('security_level', 'None')
        if security_level == 'None':
            vuln = {
                'type': 'No Security',
                'severity': 'High',
                'description': 'Device not using any Z-Wave security',
                'recommendation': 'Re-include device with S0 or S2 security'
            }
            analysis['vulnerabilities'].append(vuln)
            analysis['security_score'] -= 40
        elif security_level == 'S0':
            vuln = {
                'type': 'Outdated Security (S0)',
                'severity': 'Medium',
                'description': 'Device using legacy S0 security',
                'recommendation': 'Upgrade to Z-Wave Plus device with S2'
            }
            analysis['vulnerabilities'].append(vuln)
            analysis['security_score'] -= 20
        
        # Check firmware version
        fw_version = device_info.get('firmware_version')
        if fw_version and self._is_outdated_firmware(fw_version):
            vuln = {
                'type': 'Outdated Firmware',
                'severity': 'Medium',
                'description': f'Device running outdated firmware: {fw_version}',
                'recommendation': 'Update device firmware via OTA if supported'
            }
            analysis['vulnerabilities'].append(vuln)
            analysis['security_score'] -= 15
        
        # Check for critical devices (locks, alarms)
        if device_info.get('is_critical_device'):
            if security_level != 'S2':
                vuln = {
                    'type': 'Critical Device Without S2',
                    'severity': 'Critical',
                    'description': 'Security-critical device not using S2 security',
                    'recommendation': 'Replace with S2-certified device'
                }
                analysis['vulnerabilities'].append(vuln)
                analysis['security_score'] -= 50
        
        return analysis
    
    def _is_outdated_firmware(self, version: str) -> bool:
        """Check if firmware version is outdated"""
        try:
            # Simple heuristic
            if version.startswith('1.') or version.startswith('2.'):
                return True
            if any(year in version for year in ['2018', '2019', '2020']):
                return True
        except:
            pass
        return False
    
    def detect_zwave_attacks(self) -> List[Dict]:
        """
        Detect potential Z-Wave attacks
        
        Returns:
            List of detected attack indicators
        """
        attacks = []
        
        # Known Z-Wave vulnerabilities
        known_vulns = [
            {
                'name': 'Z-Shave Attack',
                'description': 'Downgrade attack forcing S2 to S0 security',
                'mitigation': 'Ensure all devices use S2 Authenticated or higher'
            },
            {
                'name': 'Key Sniffing',
                'description': 'Network key interception during inclusion',
                'mitigation': 'Use out-of-band DSK verification'
            },
            {
                'name': 'Replay Attack',
                'description': 'Replay of captured Z-Wave commands',
                'mitigation': 'Ensure nonce-based encryption is working'
            }
        ]
        
        logger.info("Z-Wave attack detection requires specialized hardware")
        
        return attacks
    
    def generate_report(self) -> Dict:
        """Generate comprehensive Z-Wave analysis report"""
        report = {
            'protocol': 'Z-Wave',
            'timestamp': datetime.now().isoformat(),
            'discovered_devices': len(self.discovered_devices),
            'devices': self.discovered_devices,
            'total_vulnerabilities': len(self.vulnerabilities),
            'vulnerabilities': self.vulnerabilities,
            'recommendations': [],
            'security_notes': []
        }
        
        # Generate recommendations
        if any(v['type'] == 'Default Network Key' for v in self.vulnerabilities):
            report['recommendations'].append(
                'CRITICAL: Change default Z-Wave network key immediately'
            )
        
        if any(v['type'] == 'S2 Security Not Enabled' for v in self.vulnerabilities):
            report['recommendations'].append(
                'Upgrade to Z-Wave Plus controller and devices with S2 security'
            )
        
        if any(v['type'] == 'Critical Device Without S2' for v in self.vulnerabilities):
            report['recommendations'].append(
                'Replace security-critical devices (locks, alarms) with S2-certified models'
            )
        
        # Add security notes
        report['security_notes'] = [
            'Z-Wave operates on sub-GHz frequencies (868/908 MHz)',
            'S2 security provides authenticated encryption',
            'Always verify DSK during device inclusion',
            'Keep controller firmware updated',
            'Monitor for unusual device behavior'
        ]
        
        return report


# Known Z-Wave device fingerprints
ZWAVE_FINGERPRINTS = {
    'aeotec': {
        'manufacturer_id': 0x0086,
        'common_devices': ['Multisensor', 'Smart Switch', 'Range Extender']
    },
    'fibaro': {
        'manufacturer_id': 0x010F,
        'common_devices': ['Motion Sensor', 'Door Sensor', 'Smart Implant']
    },
    'yale_locks': {
        'manufacturer_id': 0x0129,
        'common_devices': ['Smart Lock', 'Deadbolt']
    },
    'kwikset': {
        'manufacturer_id': 0x0090,
        'common_devices': ['Smart Lock', 'Deadbolt']
    }
}


# Example usage
def main():
    """Test Z-Wave analyzer"""
    print("="*70)
    print("Z-Wave Protocol Analyzer - Phase 5")
    print("="*70)
    
    analyzer = ZWaveAnalyzer()
    
    # Test with sample scan results
    sample_devices = [
        {
            'ip_address': '192.168.1.60',
            'manufacturer': 'Aeotec',
            'hostname': 'zwave-controller',
            'open_ports': [80, 8091]
        },
        {
            'ip_address': '192.168.1.61',
            'device_type': 'smart_lock',
            'manufacturer': 'Yale'
        }
    ]
    
    print("\nDetecting Z-Wave devices...")
    zwave_devices = analyzer.detect_zwave_presence(sample_devices)
    
    print(f"\nFound {len(zwave_devices)} potential Z-Wave devices:")
    for device in zwave_devices:
        print(f"\n  IP: {device.get('ip_address', 'N/A')}")
        print(f"  Manufacturer: {device.get('manufacturer', 'Unknown')}")
        print(f"  Confidence: {device['confidence']:.0%}")
        print(f"  Indicators:")
        for indicator in device['zwave_indicators']:
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
    
    if report['security_notes']:
        print(f"\nSecurity Notes:")
        for note in report['security_notes'][:3]:
            print(f"  • {note}")


if __name__ == '__main__':
    main()
