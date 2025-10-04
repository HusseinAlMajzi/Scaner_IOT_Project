"""
Threat Intelligence Integration
Improved zero-day detection and threat correlation
"""

import asyncio
import logging
from typing import Dict, List, Optional
from datetime import datetime, timedelta
import hashlib
import re

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ThreatIntelligence:
    """
    Advanced threat intelligence and zero-day detection
    """
    
    # Known CVE patterns and indicators
    CVE_PATTERNS = {
        'iot': [
            r'iot', r'smart', r'connected', r'embedded',
            r'camera', r'router', r'gateway', r'sensor'
        ],
        'protocol': [
            r'mqtt', r'coap', r'modbus', r'bacnet', r'dnp3',
            r'zigbee', r'zwave', r'lorawan'
        ],
        'vulnerability_types': [
            r'authentication bypass', r'command injection',
            r'buffer overflow', r'default credentials',
            r'information disclosure', r'denial of service'
        ]
    }
    
    # Zero-day indicators (behavioral patterns)
    ZERO_DAY_INDICATORS = {
        'anomalous_behavior': [
            'unexpected_port_open',
            'unusual_protocol_usage',
            'abnormal_traffic_pattern',
            'unauthorized_service'
        ],
        'configuration_issues': [
            'development_mode_enabled',
            'debug_endpoints_exposed',
            'admin_panel_accessible',
            'default_settings_active'
        ],
        'code_patterns': [
            'eval_function_exposed',
            'command_execution_possible',
            'path_traversal_vulnerable',
            'sql_injection_possible'
        ]
    }
    
    # Threat actor TTPs (Tactics, Techniques, Procedures)
    THREAT_ACTOR_TTPS = {
        'mirai_botnet': {
            'indicators': ['port 23 open', 'telnet', 'default credentials'],
            'target_devices': ['camera', 'router', 'dvr'],
            'severity': 'Critical'
        },
        'reaper_botnet': {
            'indicators': ['multiple vulnerabilities', 'weak credentials'],
            'target_devices': ['iot', 'camera', 'router'],
            'severity': 'Critical'
        },
        'vpnfilter': {
            'indicators': ['port 80', 'router', 'outdated firmware'],
            'target_devices': ['router', 'nas'],
            'severity': 'Critical'
        }
    }
    
    def __init__(self):
        """Initialize threat intelligence"""
        self.threat_database = []
        self.zero_day_candidates = []
        self.matched_threats = []
    
    def analyze_for_zero_day(self, device_info: Dict, 
                            vulnerability_info: Dict) -> Dict:
        """
        Improved zero-day detection using multiple indicators
        
        Args:
            device_info: Device information
            vulnerability_info: Vulnerability details
            
        Returns:
            Zero-day assessment
        """
        assessment = {
            'is_potential_zero_day': False,
            'confidence': 0.0,
            'indicators': [],
            'risk_score': 0,
            'recommendation': ''
        }
        
        confidence_score = 0
        
        # Indicator 1: Unknown vulnerability pattern
        if not vulnerability_info.get('cve_id'):
            confidence_score += 20
            assessment['indicators'].append('No CVE ID assigned')
        
        # Indicator 2: Recent discovery
        discovered_date = vulnerability_info.get('discovered_at')
        if discovered_date:
            try:
                discovered = datetime.fromisoformat(discovered_date.replace('Z', '+00:00'))
                days_old = (datetime.now() - discovered.replace(tzinfo=None)).days
                
                if days_old < 7:
                    confidence_score += 30
                    assessment['indicators'].append(f'Recently discovered ({days_old} days ago)')
            except:
                pass
        
        # Indicator 3: Novel attack vector
        vuln_desc = vulnerability_info.get('description', '').lower()
        novel_patterns = [
            'zero-day', 'unknown', 'undisclosed', 'newly discovered',
            'previously unknown', 'novel'
        ]
        
        if any(pattern in vuln_desc for pattern in novel_patterns):
            confidence_score += 25
            assessment['indicators'].append('Novel attack vector mentioned')
        
        # Indicator 4: Multiple services affected
        affected_services = vulnerability_info.get('affected_services', [])
        if len(affected_services) > 3:
            confidence_score += 15
            assessment['indicators'].append(f'{len(affected_services)} services affected')
        
        # Indicator 5: Critical device type
        device_type = device_info.get('device_type', '').lower()
        critical_types = ['camera', 'lock', 'gateway', 'router', 'plc', 'scada']
        
        if any(ctype in device_type for ctype in critical_types):
            confidence_score += 10
            assessment['indicators'].append(f'Critical device type: {device_type}')
        
        # Indicator 6: Unusual port/protocol combination
        open_ports = device_info.get('open_ports', [])
        unusual_ports = [p for p in open_ports if p > 10000 or p in [31337, 4444, 5555]]
        
        if unusual_ports:
            confidence_score += 15
            assessment['indicators'].append(f'Unusual ports detected: {unusual_ports}')
        
        # Indicator 7: No public exploit available yet
        if not vulnerability_info.get('exploit_available'):
            confidence_score += 10
            assessment['indicators'].append('No public exploit available')
        
        # Calculate final confidence
        assessment['confidence'] = min(confidence_score / 100, 1.0)
        assessment['risk_score'] = confidence_score
        
        # Determine if potential zero-day
        if assessment['confidence'] >= 0.5:
            assessment['is_potential_zero_day'] = True
            assessment['recommendation'] = 'Isolate device and monitor closely for suspicious activity'
            
            self.zero_day_candidates.append({
                'device': device_info.get('ip_address'),
                'vulnerability': vulnerability_info.get('description', 'Unknown'),
                'confidence': assessment['confidence'],
                'timestamp': datetime.now().isoformat()
            })
        
        return assessment
    
    def correlate_with_threats(self, device_info: Dict) -> List[Dict]:
        """
        Correlate device with known threat actor TTPs
        
        Args:
            device_info: Device information
            
        Returns:
            List of matched threats
        """
        matches = []
        
        device_type = device_info.get('device_type', '').lower()
        open_ports = device_info.get('open_ports', [])
        
        for threat_name, ttp in self.THREAT_ACTOR_TTPS.items():
            match_score = 0
            matched_indicators = []
            
            # Check target devices
            for target in ttp['target_devices']:
                if target in device_type:
                    match_score += 30
                    matched_indicators.append(f'Target device type: {target}')
            
            # Check indicators
            for indicator in ttp['indicators']:
                # Check ports
                if 'port' in indicator:
                    try:
                        port_num = int(re.search(r'\d+', indicator).group())
                        if port_num in open_ports:
                            match_score += 20
                            matched_indicators.append(f'Port indicator: {indicator}')
                    except:
                        pass
                
                # Check other indicators
                if indicator.lower() in str(device_info).lower():
                    match_score += 15
                    matched_indicators.append(f'Indicator found: {indicator}')
            
            # If significant match
            if match_score >= 30:
                match = {
                    'threat_actor': threat_name,
                    'severity': ttp['severity'],
                    'match_score': match_score,
                    'indicators': matched_indicators,
                    'description': f'Device matches {threat_name} target profile',
                    'recommendation': f'Monitor for {threat_name} activity patterns'
                }
                matches.append(match)
                self.matched_threats.append(match)
        
        return matches
    
    def check_known_exploits(self, device_info: Dict) -> List[Dict]:
        """
        Check device against known exploit database
        
        Args:
            device_info: Device information
            
        Returns:
            List of applicable exploits
        """
        exploits = []
        
        # Check for Metasploit-like exploit patterns
        device_type = device_info.get('device_type', '').lower()
        manufacturer = (device_info.get('manufacturer', '') or '').lower()
        firmware = device_info.get('firmware_version', '')
        
        # Example exploit patterns (simplified)
        exploit_patterns = {
            'camera_rce': {
                'devices': ['camera', 'ipcam', 'dvr', 'nvr'],
                'manufacturers': ['hikvision', 'dahua', 'foscam'],
                'severity': 'Critical',
                'description': 'Known RCE vulnerability in IP cameras'
            },
            'router_backdoor': {
                'devices': ['router', 'gateway'],
                'manufacturers': ['dlink', 'netgear', 'linksys'],
                'severity': 'Critical',
                'description': 'Known backdoor in router firmware'
            },
            'telnet_botnet': {
                'ports': [23],
                'severity': 'Critical',
                'description': 'Telnet exposed - potential botnet target'
            }
        }
        
        for exploit_name, pattern in exploit_patterns.items():
            match = False
            
            # Check device type
            if pattern.get('devices'):
                if any(dev in device_type for dev in pattern['devices']):
                    match = True
            
            # Check manufacturer
            if pattern.get('manufacturers'):
                if any(mfr in manufacturer for mfr in pattern['manufacturers']):
                    match = True
            
            # Check ports
            if pattern.get('ports'):
                open_ports = device_info.get('open_ports', [])
                if any(port in open_ports for port in pattern['ports']):
                    match = True
            
            if match:
                exploit = {
                    'name': exploit_name,
                    'severity': pattern['severity'],
                    'description': pattern['description'],
                    'recommendation': 'Update firmware and apply security patches'
                }
                exploits.append(exploit)
        
        return exploits
    
    def generate_threat_report(self, devices: List[Dict]) -> Dict:
        """
        Generate comprehensive threat intelligence report
        
        Args:
            devices: List of analyzed devices
            
        Returns:
            Threat intelligence report
        """
        report = {
            'timestamp': datetime.now().isoformat(),
            'total_devices_analyzed': len(devices),
            'zero_day_candidates': len(self.zero_day_candidates),
            'threat_actor_matches': len(self.matched_threats),
            'total_threats': len(self.zero_day_candidates) + len(self.matched_threats),
            'high_risk_devices': [],
            'recommendations': []
        }
        
        # Identify high-risk devices
        for device in devices:
            risk_indicators = []
            
            # Check for multiple vulnerabilities
            vulns = device.get('vulnerabilities', [])
            if len(vulns) > 5:
                risk_indicators.append(f'{len(vulns)} vulnerabilities found')
            
            # Check for critical vulnerabilities
            critical_vulns = [v for v in vulns if v.get('severity') == 'Critical']
            if critical_vulns:
                risk_indicators.append(f'{len(critical_vulns)} critical vulnerabilities')
            
            # Check for threat matches
            threat_matches = [t for t in self.matched_threats if device.get('ip_address') in str(t)]
            if threat_matches:
                risk_indicators.append('Matches known threat actor TTPs')
            
            if len(risk_indicators) >= 2:
                report['high_risk_devices'].append({
                    'ip': device.get('ip_address'),
                    'device_type': device.get('device_type'),
                    'risk_indicators': risk_indicators
                })
        
        # Generate recommendations
        if report['zero_day_candidates'] > 0:
            report['recommendations'].append(
                f'Monitor {report["zero_day_candidates"]} potential zero-day candidates closely'
            )
        
        if report['threat_actor_matches'] > 0:
            report['recommendations'].append(
                f'Investigate {report["threat_actor_matches"]} devices matching threat actor profiles'
            )
        
        if report['high_risk_devices']:
            report['recommendations'].append(
                f'Isolate {len(report["high_risk_devices"])} high-risk devices for further analysis'
            )
        
        return report


# Example usage
def main():
    """Test threat intelligence"""
    print("="*70)
    print("Threat Intelligence System - Phase 6")
    print("="*70)
    
    ti = ThreatIntelligence()
    
    # Test device
    test_device = {
        'ip_address': '192.168.1.100',
        'device_type': 'camera',
        'manufacturer': 'Hikvision',
        'open_ports': [23, 80, 554]
    }
    
    # Test vulnerability
    test_vuln = {
        'description': 'Newly discovered authentication bypass',
        'discovered_at': datetime.now().isoformat(),
        'affected_services': ['http', 'rtsp', 'telnet', 'ftp']
    }
    
    print("\nAnalyzing for zero-day potential...")
    zd_assessment = ti.analyze_for_zero_day(test_device, test_vuln)
    
    print(f"\nZero-Day Assessment:")
    print(f"  Potential Zero-Day: {'Yes' if zd_assessment['is_potential_zero_day'] else 'No'}")
    print(f"  Confidence: {zd_assessment['confidence']:.0%}")
    print(f"  Risk Score: {zd_assessment['risk_score']}/100")
    
    if zd_assessment['indicators']:
        print(f"  Indicators:")
        for indicator in zd_assessment['indicators']:
            print(f"    - {indicator}")
    
    print("\nChecking threat actor correlation...")
    threat_matches = ti.correlate_with_threats(test_device)
    
    if threat_matches:
        print(f"\n⚠️  Threat Actor Matches Found: {len(threat_matches)}")
        for match in threat_matches:
            print(f"\n  [{match['severity']}] {match['threat_actor']}")
            print(f"  Match Score: {match['match_score']}/100")
            print(f"  Description: {match['description']}")
    
    print("\nChecking known exploits...")
    exploits = ti.check_known_exploits(test_device)
    
    if exploits:
        print(f"\n⚠️  Known Exploits Found: {len(exploits)}")
        for exploit in exploits:
            print(f"\n  [{exploit['severity']}] {exploit['name']}")
            print(f"  {exploit['description']}")


if __name__ == '__main__':
    main()
