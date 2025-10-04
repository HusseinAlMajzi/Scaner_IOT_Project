"""
Threat Scoring System - Phase 8.1
Advanced threat scoring and risk prioritization
"""

import logging
from typing import Dict, List
from datetime import datetime

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ThreatScoringEngine:
    """Advanced threat scoring with multiple factors"""
    
    # Severity weights
    SEVERITY_WEIGHTS = {
        'Critical': 10.0,
        'High': 7.5,
        'Medium': 5.0,
        'Low': 2.5,
        'Info': 1.0
    }
    
    # Device criticality multipliers
    DEVICE_CRITICALITY = {
        'smart_lock': 2.0,
        'ip_camera': 1.8,
        'router': 1.9,
        'gateway': 1.9,
        'plc': 2.0,
        'scada': 2.0,
        'medical_device': 2.0,
        'smart_hub': 1.7,
        'thermostat': 1.3,
        'smart_plug': 1.2,
        'smart_light': 1.1
    }
    
    # Exploit availability impact
    EXPLOIT_AVAILABILITY = {
        'public': 2.0,
        'weaponized': 1.8,
        'poc': 1.5,
        'theoretical': 1.0,
        'unknown': 1.2
    }
    
    def calculate_cvss_score(self, cvss_vector: str = None, cvss_score: float = None) -> float:
        """Calculate or use existing CVSS score"""
        if cvss_score:
            return cvss_score
        
        # If vector provided, parse it (simplified)
        if cvss_vector:
            # Basic CVSS parsing
            if 'AV:N' in cvss_vector:  # Network vector
                return 7.5
            elif 'AV:A' in cvss_vector:  # Adjacent
                return 6.0
            elif 'AV:L' in cvss_vector:  # Local
                return 4.0
        
        return 5.0  # Default medium score
    
    def calculate_threat_score(self, vulnerability: Dict, device: Dict) -> Dict:
        """
        Calculate comprehensive threat score
        
        Args:
            vulnerability: Vulnerability information
            device: Device information
            
        Returns:
            Threat score breakdown
        """
        score_breakdown = {
            'base_score': 0,
            'severity_score': 0,
            'device_criticality': 0,
            'exploit_score': 0,
            'exposure_score': 0,
            'final_score': 0,
            'priority': 'Medium'
        }
        
        # 1. Base CVSS score (0-10)
        cvss = self.calculate_cvss_score(
            vulnerability.get('cvss_vector'),
            vulnerability.get('cvss_score')
        )
        score_breakdown['base_score'] = cvss
        
        # 2. Severity weight (0-10)
        severity = vulnerability.get('severity', 'Medium')
        severity_weight = self.SEVERITY_WEIGHTS.get(severity, 5.0)
        score_breakdown['severity_score'] = severity_weight
        
        # 3. Device criticality (multiplier 1.0-2.0)
        device_type = device.get('device_type', 'unknown').lower()
        criticality = self.DEVICE_CRITICALITY.get(device_type, 1.0)
        score_breakdown['device_criticality'] = criticality
        
        # 4. Exploit availability (multiplier 1.0-2.0)
        exploit_status = vulnerability.get('exploit_availability', 'unknown')
        exploit_mult = self.EXPLOIT_AVAILABILITY.get(exploit_status, 1.2)
        score_breakdown['exploit_score'] = exploit_mult
        
        # 5. Network exposure (0-10)
        open_ports = len(device.get('open_ports', []))
        exposure = min(open_ports / 5 * 10, 10)  # More ports = more exposure
        score_breakdown['exposure_score'] = exposure
        
        # Calculate final threat score (0-100)
        final = (
            (cvss * 0.4) +  # 40% weight to CVSS
            (severity_weight * 0.3) +  # 30% weight to severity
            (exposure * 0.1)  # 10% weight to exposure
        ) * criticality * (exploit_mult * 0.5 + 0.5)  # Apply multipliers
        
        score_breakdown['final_score'] = min(final * 10, 100)  # Scale to 100
        
        # Determine priority
        if score_breakdown['final_score'] >= 80:
            score_breakdown['priority'] = 'Critical'
        elif score_breakdown['final_score'] >= 60:
            score_breakdown['priority'] = 'High'
        elif score_breakdown['final_score'] >= 40:
            score_breakdown['priority'] = 'Medium'
        else:
            score_breakdown['priority'] = 'Low'
        
        return score_breakdown
    
    def prioritize_vulnerabilities(self, vulnerabilities: List[Dict], 
                                  devices: List[Dict]) -> List[Dict]:
        """
        Prioritize vulnerabilities by threat score
        
        Args:
            vulnerabilities: List of vulnerabilities
            devices: List of devices
            
        Returns:
            Prioritized vulnerability list with scores
        """
        device_map = {d.get('id'): d for d in devices}
        scored_vulns = []
        
        for vuln in vulnerabilities:
            device_id = vuln.get('device_id')
            device = device_map.get(device_id, {})
            
            score_info = self.calculate_threat_score(vuln, device)
            
            vuln_with_score = vuln.copy()
            vuln_with_score['threat_score'] = score_info['final_score']
            vuln_with_score['priority'] = score_info['priority']
            vuln_with_score['score_breakdown'] = score_info
            
            scored_vulns.append(vuln_with_score)
        
        # Sort by threat score (highest first)
        scored_vulns.sort(key=lambda v: v['threat_score'], reverse=True)
        
        return scored_vulns


# Example usage
if __name__ == '__main__':
    print("="*70)
    print("Threat Scoring Engine - Phase 8.1")
    print("="*70)
    
    engine = ThreatScoringEngine()
    
    # Test vulnerability
    test_vuln = {
        'description': 'Default credentials',
        'severity': 'Critical',
        'cvss_score': 9.8,
        'exploit_availability': 'public'
    }
    
    test_device = {
        'id': 1,
        'device_type': 'smart_lock',
        'open_ports': [80, 443, 22]
    }
    
    score = engine.calculate_threat_score(test_vuln, test_device)
    
    print(f"\nThreat Score Calculation:")
    print(f"  Base CVSS: {score['base_score']:.1f}/10")
    print(f"  Severity: {score['severity_score']:.1f}/10")
    print(f"  Device Criticality: {score['device_criticality']:.1f}x")
    print(f"  Exploit Score: {score['exploit_score']:.1f}x")
    print(f"  Exposure: {score['exposure_score']:.1f}/10")
    print(f"\n  FINAL THREAT SCORE: {score['final_score']:.1f}/100")
    print(f"  PRIORITY: {score['priority']}")
