"""
Wireless Protocol Fingerprinting
Advanced fingerprinting for wireless IoT devices
"""

import logging
from typing import Dict, List, Optional
import re

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class WirelessFingerprinter:
    """Fingerprint wireless IoT devices based on various characteristics"""
    
    # Device patterns based on SSID, manufacturer, and characteristics
    DEVICE_FINGERPRINTS = {
        'smart_tv': {
            'ssid_patterns': ['samsung', 'lg webos', 'sony', 'vizio', '[tv]'],
            'services': ['miracast', 'airplay', 'chromecast'],
            'ports': [8008, 8009, 9080],
            'characteristics': ['media_streaming', 'screen_mirroring']
        },
        'smart_speaker': {
            'ssid_patterns': ['echo-', 'google home', 'homepod', 'alexa'],
            'ble_services': ['audio', 'media'],
            'characteristics': ['voice_control', 'music_streaming']
        },
        'smart_bulb': {
            'ssid_patterns': ['philips hue', 'lifx', 'yeelight', 'wiz'],
            'ble_names': ['hue', 'lifx', 'yeelight'],
            'characteristics': ['lighting_control']
        },
        'smart_camera': {
            'ssid_patterns': ['cam-', 'camera', 'ipcam', 'nest cam', 'ring'],
            'ports': [554, 8000, 8080],  # RTSP, common camera ports
            'characteristics': ['video_streaming', 'motion_detection']
        },
        'smart_lock': {
            'ble_names': ['august', 'yale', 'schlage', 'lock'],
            'characteristics': ['access_control', 'keyless_entry']
        },
        'smart_thermostat': {
            'ssid_patterns': ['nest', 'ecobee', 'honeywell', 'thermostat'],
            'characteristics': ['temperature_control', 'hvac']
        },
        'smart_plug': {
            'ssid_patterns': ['plug', 'tp-link', 'wemo', 'socket'],
            'ble_names': ['plug', 'outlet'],
            'characteristics': ['power_control', 'energy_monitoring']
        },
        'fitness_tracker': {
            'ble_names': ['fitbit', 'garmin', 'mi band', 'amazfit'],
            'ble_services': ['heart_rate', 'battery', 'device_info'],
            'characteristics': ['health_monitoring', 'activity_tracking']
        },
        'smart_watch': {
            'ble_names': ['watch', 'gear', 'apple watch', 'galaxy watch'],
            'ble_services': ['heart_rate', 'notifications'],
            'characteristics': ['wearable', 'notifications']
        },
        'drone': {
            'ssid_patterns': ['mavic', 'phantom', 'dji', 'parrot', 'drone'],
            'wifi_direct': True,
            'characteristics': ['aerial_photography', 'flight_control']
        },
        'robot_vacuum': {
            'ssid_patterns': ['roomba', 'roborock', 'xiaomi vacuum', 'vacuum'],
            'characteristics': ['autonomous_navigation', 'cleaning']
        },
        'wireless_printer': {
            'ssid_patterns': ['hp-', 'canon-', 'epson-', 'brother-', 'print'],
            'services': ['ipp', 'airprint'],
            'ports': [631, 9100],
            'characteristics': ['printing', 'scanning']
        },
        'gaming_console': {
            'ssid_patterns': ['playstation', 'xbox', 'nintendo', 'switch'],
            'characteristics': ['gaming', 'entertainment']
        },
        'smart_hub': {
            'ssid_patterns': ['hub-', 'smartthings', 'homekit', 'alexa'],
            'characteristics': ['home_automation', 'device_control']
        }
    }
    
    # Manufacturer detection patterns (MAC OUI and other indicators)
    MANUFACTURER_PATTERNS = {
        'apple': ['apple', 'iphone', 'ipad', 'macbook', 'airpods', 'homepod'],
        'google': ['google', 'nest', 'chromecast', 'pixel'],
        'amazon': ['amazon', 'echo', 'alexa', 'fire tv', 'ring'],
        'samsung': ['samsung', 'galaxy', 'smartthings'],
        'xiaomi': ['xiaomi', 'mi ', 'redmi', 'roborock'],
        'philips': ['philips', 'hue'],
        'tp-link': ['tp-link', 'kasa'],
        'sonos': ['sonos'],
        'bose': ['bose'],
        'fitbit': ['fitbit'],
        'garmin': ['garmin']
    }
    
    def __init__(self):
        """Initialize wireless fingerprinter"""
        pass
    
    def fingerprint_device(self, device_data: Dict) -> Dict:
        """
        Fingerprint a wireless device
        
        Args:
            device_data: Device information (SSID, BLE name, services, etc.)
            
        Returns:
            Enhanced device data with fingerprint information
        """
        result = device_data.copy()
        
        # Extract relevant fields
        ssid = (device_data.get('ssid', '') or device_data.get('name', '')).lower()
        services = device_data.get('services', [])
        ports = device_data.get('open_ports', [])
        protocol = device_data.get('protocol', '').lower()
        
        # Detect device type
        device_type, confidence = self._classify_device_type(
            ssid, services, ports, protocol
        )
        result['device_type'] = device_type
        result['confidence'] = confidence
        
        # Detect manufacturer
        manufacturer = self._detect_manufacturer(ssid, device_data)
        if manufacturer:
            result['manufacturer'] = manufacturer
        
        # Add characteristics
        if device_type in self.DEVICE_FINGERPRINTS:
            result['characteristics'] = self.DEVICE_FINGERPRINTS[device_type].get(
                'characteristics', []
            )
        
        # Security posture
        result['security_posture'] = self._assess_security_posture(device_data)
        
        # Add metadata
        result['fingerprinted'] = True
        result['fingerprint_method'] = 'wireless_analysis'
        
        return result
    
    def _classify_device_type(self, name: str, services: List, 
                             ports: List, protocol: str) -> tuple:
        """
        Classify device type based on various indicators
        
        Returns:
            (device_type, confidence_score)
        """
        scores = {}
        
        for device_type, fingerprint in self.DEVICE_FINGERPRINTS.items():
            score = 0
            
            # Check name/SSID patterns
            if name:
                for pattern in fingerprint.get('ssid_patterns', []):
                    if pattern.lower() in name:
                        score += 40
                        break
                
                for pattern in fingerprint.get('ble_names', []):
                    if pattern.lower() in name:
                        score += 40
                        break
            
            # Check services
            if services:
                fingerprint_services = [
                    s.lower() for s in fingerprint.get('services', [])
                ] + [
                    s.lower() for s in fingerprint.get('ble_services', [])
                ]
                
                for service in services:
                    service_name = service if isinstance(service, str) else service.get('name', '')
                    service_name = service_name.lower()
                    
                    for fp_service in fingerprint_services:
                        if fp_service in service_name:
                            score += 20
            
            # Check ports
            if ports and fingerprint.get('ports'):
                matching_ports = set(ports) & set(fingerprint['ports'])
                if matching_ports:
                    score += len(matching_ports) * 15
            
            # Check Wi-Fi Direct
            if fingerprint.get('wifi_direct') and name.startswith('direct-'):
                score += 30
            
            if score > 0:
                scores[device_type] = score
        
        # Return best match
        if scores:
            best_type = max(scores, key=scores.get)
            max_score = scores[best_type]
            confidence = min(max_score / 100, 1.0)  # Normalize to 0-1
            return best_type, confidence
        
        return 'unknown_wireless', 0.0
    
    def _detect_manufacturer(self, name: str, device_data: Dict) -> Optional[str]:
        """Detect device manufacturer"""
        name_lower = name.lower()
        
        # Check name patterns
        for manufacturer, patterns in self.MANUFACTURER_PATTERNS.items():
            for pattern in patterns:
                if pattern in name_lower:
                    return manufacturer.capitalize()
        
        # Check existing manufacturer data
        if device_data.get('manufacturer'):
            return device_data['manufacturer']
        
        return None
    
    def _assess_security_posture(self, device_data: Dict) -> Dict:
        """Assess overall security posture of the device"""
        posture = {
            'risk_level': 'Unknown',
            'concerns': [],
            'strengths': []
        }
        
        risk_score = 0
        
        # Check encryption
        if device_data.get('protocol') == 'Bluetooth LE':
            # BLE devices
            if not device_data.get('encrypted', True):
                posture['concerns'].append('Unencrypted BLE communication')
                risk_score += 30
            
            if device_data.get('pairing_vulnerable'):
                posture['concerns'].append('Weak pairing mechanism')
                risk_score += 20
        
        elif 'Wi-Fi' in device_data.get('protocol', ''):
            # Wi-Fi devices
            security = device_data.get('primary_security', 'UNKNOWN')
            
            if security == 'OPEN':
                posture['concerns'].append('Open Wi-Fi network')
                risk_score += 40
            elif security == 'WEP':
                posture['concerns'].append('WEP encryption (obsolete)')
                risk_score += 35
            elif security == 'WPA':
                posture['concerns'].append('WPA encryption (outdated)')
                risk_score += 20
            elif security == 'WPA2':
                posture['strengths'].append('WPA2 encryption')
            elif security == 'WPA3':
                posture['strengths'].append('WPA3 encryption (strong)')
                risk_score -= 10
            
            if device_data.get('wps_enabled'):
                posture['concerns'].append('WPS enabled')
                risk_score += 15
        
        # Check for default credentials (if applicable)
        if device_data.get('default_credentials'):
            posture['concerns'].append('Using default credentials')
            risk_score += 25
        
        # Check for firmware updates
        if device_data.get('outdated_firmware'):
            posture['concerns'].append('Outdated firmware')
            risk_score += 15
        
        # Determine risk level
        if risk_score >= 50:
            posture['risk_level'] = 'High'
        elif risk_score >= 25:
            posture['risk_level'] = 'Medium'
        else:
            posture['risk_level'] = 'Low'
        
        posture['risk_score'] = min(risk_score, 100)
        
        return posture
    
    def generate_report(self, devices: List[Dict]) -> Dict:
        """
        Generate comprehensive wireless security report
        
        Args:
            devices: List of fingerprinted devices
            
        Returns:
            Security report with statistics and recommendations
        """
        report = {
            'total_devices': len(devices),
            'device_types': {},
            'manufacturers': {},
            'risk_distribution': {
                'High': 0,
                'Medium': 0,
                'Low': 0,
                'Unknown': 0
            },
            'protocols': {
                'BLE': 0,
                'Classic Bluetooth': 0,
                'Wi-Fi': 0,
                'Wi-Fi Direct': 0
            },
            'security_concerns': [],
            'recommendations': []
        }
        
        for device in devices:
            # Count device types
            device_type = device.get('device_type', 'unknown')
            report['device_types'][device_type] = report['device_types'].get(device_type, 0) + 1
            
            # Count manufacturers
            manufacturer = device.get('manufacturer', 'Unknown')
            report['manufacturers'][manufacturer] = report['manufacturers'].get(manufacturer, 0) + 1
            
            # Count risk levels
            risk_level = device.get('security_posture', {}).get('risk_level', 'Unknown')
            report['risk_distribution'][risk_level] += 1
            
            # Count protocols
            protocol = device.get('protocol', 'Unknown')
            if 'BLE' in protocol or 'Bluetooth LE' in protocol:
                report['protocols']['BLE'] += 1
            elif 'Bluetooth' in protocol:
                report['protocols']['Classic Bluetooth'] += 1
            elif 'Wi-Fi Direct' in protocol:
                report['protocols']['Wi-Fi Direct'] += 1
            elif 'Wi-Fi' in protocol:
                report['protocols']['Wi-Fi'] += 1
            
            # Collect security concerns
            concerns = device.get('security_posture', {}).get('concerns', [])
            for concern in concerns:
                if concern not in report['security_concerns']:
                    report['security_concerns'].append(concern)
        
        # Generate recommendations
        if report['risk_distribution']['High'] > 0:
            report['recommendations'].append(
                f"{report['risk_distribution']['High']} high-risk devices found. "
                "Immediate action required."
            )
        
        if 'Open Wi-Fi network' in report['security_concerns']:
            report['recommendations'].append(
                "Enable WPA2/WPA3 encryption on all open networks."
            )
        
        if 'WPS enabled' in report['security_concerns']:
            report['recommendations'].append(
                "Disable WPS on routers to prevent brute force attacks."
            )
        
        if 'Unencrypted BLE communication' in report['security_concerns']:
            report['recommendations'].append(
                "Enable BLE pairing and encryption on all devices."
            )
        
        return report


# Example usage
if __name__ == '__main__':
    fingerprinter = WirelessFingerprinter()
    
    # Test devices
    test_devices = [
        {
            'ssid': 'Philips-hue-12345',
            'protocol': 'Wi-Fi',
            'primary_security': 'WPA2'
        },
        {
            'name': 'Fitbit Charge 5',
            'protocol': 'Bluetooth LE',
            'services': [{'name': 'Heart Rate'}, {'name': 'Battery'}]
        },
        {
            'ssid': 'DIRECT-roku-123',
            'protocol': 'Wi-Fi Direct'
        }
    ]
    
    print("="*60)
    print("Wireless Fingerprinting Test")
    print("="*60)
    
    fingerprinted = []
    for device in test_devices:
        result = fingerprinter.fingerprint_device(device)
        fingerprinted.append(result)
        
        print(f"\nDevice: {device.get('ssid') or device.get('name')}")
        print(f"Type: {result['device_type']}")
        print(f"Confidence: {result['confidence']:.2%}")
        print(f"Manufacturer: {result.get('manufacturer', 'Unknown')}")
        print(f"Risk Level: {result['security_posture']['risk_level']}")
    
    # Generate report
    report = fingerprinter.generate_report(fingerprinted)
    
    print(f"\n{'='*60}")
    print("Security Report")
    print(f"{'='*60}")
    print(f"Total Devices: {report['total_devices']}")
    print(f"\nRisk Distribution:")
    for level, count in report['risk_distribution'].items():
        print(f"  {level}: {count}")
    
    print(f"\nRecommendations:")
    for rec in report['recommendations']:
        print(f"  - {rec}")
