"""
Custom Vulnerability Rule Engine - Phase 10.3
Allows custom security rules and policies
"""

import logging
import re
from typing import Dict, List, Callable
from datetime import datetime

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class VulnerabilityRule:
    """Individual vulnerability detection rule"""
    
    def __init__(self, rule_id: str, name: str, description: str,
                 condition: Callable, severity: str = 'Medium'):
        """
        Initialize vulnerability rule
        
        Args:
            rule_id: Unique rule identifier
            name: Rule name
            description: Rule description
            condition: Function that returns True if vulnerable
            severity: Vulnerability severity
        """
        self.rule_id = rule_id
        self.name = name
        self.description = description
        self.condition = condition
        self.severity = severity
        self.created_at = datetime.now().isoformat()
        self.matches = 0
    
    def evaluate(self, target: Dict) -> bool:
        """
        Evaluate rule against target
        
        Args:
            target: Device or scan data
            
        Returns:
            True if rule matches (vulnerability found)
        """
        try:
            if self.condition(target):
                self.matches += 1
                return True
        except Exception as e:
            logger.error(f"Rule evaluation error ({self.rule_id}): {e}")
        
        return False


class CustomRuleEngine:
    """Custom vulnerability rule engine"""
    
    def __init__(self):
        """Initialize rule engine"""
        self.rules = {}
        self.load_default_rules()
    
    def load_default_rules(self):
        """Load default security rules"""
        
        # Rule: Telnet exposed
        self.add_rule(VulnerabilityRule(
            rule_id='telnet_exposed',
            name='Telnet Service Exposed',
            description='Device has Telnet port (23) open',
            condition=lambda d: 23 in d.get('open_ports', []),
            severity='High'
        ))
        
        # Rule: Default HTTP port on camera
        self.add_rule(VulnerabilityRule(
            rule_id='camera_http_exposed',
            name='Camera HTTP Interface Exposed',
            description='IP camera with HTTP interface exposed',
            condition=lambda d: (
                'camera' in d.get('device_type', '').lower() and
                80 in d.get('open_ports', [])
            ),
            severity='Medium'
        ))
        
        # Rule: Multiple critical vulnerabilities
        self.add_rule(VulnerabilityRule(
            rule_id='multiple_critical',
            name='Multiple Critical Vulnerabilities',
            description='Device has 3+ critical vulnerabilities',
            condition=lambda d: len([
                v for v in d.get('vulnerabilities', [])
                if v.get('severity') == 'Critical'
            ]) >= 3,
            severity='Critical'
        ))
        
        # Rule: Unencrypted IoT protocol
        self.add_rule(VulnerabilityRule(
            rule_id='unencrypted_iot_protocol',
            name='Unencrypted IoT Protocol',
            description='Using unencrypted MQTT or CoAP',
            condition=lambda d: (
                1883 in d.get('open_ports', []) or  # MQTT
                5683 in d.get('open_ports', [])     # CoAP
            ),
            severity='High'
        ))
        
        # Rule: Industrial device exposed
        self.add_rule(VulnerabilityRule(
            rule_id='industrial_exposed',
            name='Industrial Device Exposed',
            description='PLC/SCADA device accessible',
            condition=lambda d: (
                d.get('device_type') in ['plc', 'scada', 'rtu'] or
                502 in d.get('open_ports', [])  # Modbus
            ),
            severity='Critical'
        ))
        
        logger.info(f"Loaded {len(self.rules)} default rules")
    
    def add_rule(self, rule: VulnerabilityRule) -> bool:
        """
        Add custom rule
        
        Args:
            rule: Vulnerability rule
            
        Returns:
            Success status
        """
        self.rules[rule.rule_id] = rule
        logger.info(f"Added rule: {rule.name}")
        return True
    
    def remove_rule(self, rule_id: str) -> bool:
        """Remove rule"""
        if rule_id in self.rules:
            del self.rules[rule_id]
            logger.info(f"Removed rule: {rule_id}")
            return True
        return False
    
    def evaluate_all_rules(self, target: Dict) -> List[Dict]:
        """
        Evaluate all rules against target
        
        Args:
            target: Device or scan data
            
        Returns:
            List of matched rules (vulnerabilities found)
        """
        matches = []
        
        for rule in self.rules.values():
            if rule.evaluate(target):
                match = {
                    'rule_id': rule.rule_id,
                    'rule_name': rule.name,
                    'description': rule.description,
                    'severity': rule.severity,
                    'detected_at': datetime.now().isoformat()
                }
                matches.append(match)
                
                logger.info(f"Rule matched: {rule.name} on {target.get('ip_address', 'unknown')}")
        
        return matches
    
    def scan_with_rules(self, devices: List[Dict]) -> Dict:
        """
        Scan devices with all custom rules
        
        Args:
            devices: List of devices to scan
            
        Returns:
            Scan results with custom rule matches
        """
        logger.info(f"Scanning {len(devices)} devices with {len(self.rules)} rules")
        
        results = {
            'total_devices': len(devices),
            'total_rules': len(self.rules),
            'matches': [],
            'devices_with_issues': 0,
            'timestamp': datetime.now().isoformat()
        }
        
        devices_with_issues = set()
        
        for device in devices:
            device_matches = self.evaluate_all_rules(device)
            
            if device_matches:
                devices_with_issues.add(device.get('id') or device.get('ip_address'))
                
                results['matches'].extend([
                    {**match, 'device_id': device.get('id'), 'device_ip': device.get('ip_address')}
                    for match in device_matches
                ])
        
        results['devices_with_issues'] = len(devices_with_issues)
        
        logger.info(f"Custom rule scan complete: {len(results['matches'])} matches on {results['devices_with_issues']} devices")
        
        return results
    
    def get_rule_statistics(self) -> Dict:
        """Get rule engine statistics"""
        return {
            'total_rules': len(self.rules),
            'rules': [
                {
                    'id': rule.rule_id,
                    'name': rule.name,
                    'severity': rule.severity,
                    'matches': rule.matches
                }
                for rule in self.rules.values()
            ]
        }
    
    def create_rule_from_template(self, template: str, params: Dict) -> VulnerabilityRule:
        """
        Create rule from template
        
        Args:
            template: Template type
            params: Template parameters
            
        Returns:
            Created rule
        """
        templates = {
            'port_check': lambda p: VulnerabilityRule(
                rule_id=f"port_{p['port']}",
                name=f"Port {p['port']} Exposed",
                description=f"Device has port {p['port']} open",
                condition=lambda d: p['port'] in d.get('open_ports', []),
                severity=p.get('severity', 'Medium')
            ),
            'device_type_check': lambda p: VulnerabilityRule(
                rule_id=f"type_{p['type']}",
                name=f"{p['type'].title()} Security Check",
                description=f"Security check for {p['type']} devices",
                condition=lambda d: p['type'] in d.get('device_type', '').lower(),
                severity=p.get('severity', 'Medium')
            )
        }
        
        template_func = templates.get(template)
        if template_func:
            return template_func(params)
        
        raise ValueError(f"Unknown template: {template}")


# Global rule engine
rule_engine = CustomRuleEngine()


# Example usage
if __name__ == '__main__':
    print("="*70)
    print("Custom Vulnerability Rule Engine - Phase 10.3")
    print("="*70)
    
    engine = CustomRuleEngine()
    
    print(f"\nDefault Rules Loaded: {len(engine.rules)}")
    for rule_id, rule in engine.rules.items():
        print(f"  - {rule.name} ({rule.severity})")
    
    # Test devices
    test_devices = [
        {'id': 1, 'ip_address': '192.168.1.100', 'device_type': 'camera', 'open_ports': [23, 80, 554]},
        {'id': 2, 'ip_address': '192.168.1.101', 'device_type': 'plc', 'open_ports': [502]},
        {'id': 3, 'ip_address': '192.168.1.102', 'device_type': 'router', 'open_ports': [80, 443]}
    ]
    
    # Scan with rules
    print("\nScanning devices with custom rules...")
    results = engine.scan_with_rules(test_devices)
    
    print(f"\nResults:")
    print(f"  Devices Scanned: {results['total_devices']}")
    print(f"  Rules Applied: {results['total_rules']}")
    print(f"  Matches Found: {len(results['matches'])}")
    print(f"  Devices with Issues: {results['devices_with_issues']}")
    
    if results['matches']:
        print(f"\n  Matched Rules:")
        for match in results['matches']:
            print(f"    [{match['severity']}] {match['rule_name']} on {match['device_ip']}")
