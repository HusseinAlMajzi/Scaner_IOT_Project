"""
Executive Summary Generator - Phase 8.4
Generates high-level executive summaries for business stakeholders
"""

import logging
from typing import Dict, List
from datetime import datetime

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ExecutiveSummaryGenerator:
    """Generates executive-level security summaries"""
    
    def __init__(self):
        """Initialize executive summary generator"""
        pass
    
    def generate_summary(self, scan_data: Dict) -> Dict:
        """
        Generate executive summary
        
        Args:
            scan_data: Complete scan data with devices and vulnerabilities
            
        Returns:
            Executive summary
        """
        summary = {
            'generated_at': datetime.now().isoformat(),
            'scan_date': scan_data.get('timestamp'),
            'overview': {},
            'key_findings': [],
            'risk_assessment': {},
            'business_impact': {},
            'recommendations': [],
            'metrics': {}
        }
        
        devices = scan_data.get('devices', [])
        vulnerabilities = scan_data.get('vulnerabilities', [])
        
        # Overview
        summary['overview'] = {
            'total_devices_scanned': len(devices),
            'total_vulnerabilities_found': len(vulnerabilities),
            'scan_coverage': self._calculate_coverage(scan_data),
            'security_posture': self._assess_security_posture(vulnerabilities)
        }
        
        # Key findings (top 5 critical issues)
        summary['key_findings'] = self._extract_key_findings(vulnerabilities, devices)
        
        # Risk assessment
        summary['risk_assessment'] = self._assess_risk(vulnerabilities, devices)
        
        # Business impact
        summary['business_impact'] = self._assess_business_impact(vulnerabilities, devices)
        
        # Top recommendations
        summary['recommendations'] = self._generate_top_recommendations(vulnerabilities, devices)
        
        # Key metrics
        summary['metrics'] = self._calculate_key_metrics(devices, vulnerabilities)
        
        return summary
    
    def _calculate_coverage(self, scan_data: Dict) -> str:
        """Calculate scan coverage"""
        # Simple coverage based on number of devices and depth
        devices = scan_data.get('devices', [])
        
        if not devices:
            return '0%'
        
        # Check if deep analysis was performed
        has_deep_analysis = any(
            'protocols_analyzed' in d or 'fingerprinted' in d
            for d in devices
        )
        
        if has_deep_analysis:
            return '90%+'
        else:
            return '70%'
    
    def _assess_security_posture(self, vulnerabilities: List[Dict]) -> str:
        """Assess overall security posture"""
        if not vulnerabilities:
            return 'Good'
        
        critical = len([v for v in vulnerabilities if v.get('severity') == 'Critical'])
        high = len([v for v in vulnerabilities if v.get('severity') == 'High'])
        
        if critical >= 5 or high >= 10:
            return 'Poor'
        elif critical >= 2 or high >= 5:
            return 'Fair'
        elif critical >= 1 or high >= 2:
            return 'Moderate'
        else:
            return 'Good'
    
    def _extract_key_findings(self, vulnerabilities: List[Dict], 
                             devices: List[Dict]) -> List[str]:
        """Extract top 5 key findings"""
        findings = []
        
        # Count by severity
        critical = [v for v in vulnerabilities if v.get('severity') == 'Critical']
        high = [v for v in vulnerabilities if v.get('severity') == 'High']
        
        if critical:
            findings.append(
                f"{len(critical)} CRITICAL vulnerabilities require immediate attention"
            )
        
        if high:
            findings.append(
                f"{len(high)} HIGH-severity vulnerabilities found"
            )
        
        # Check for default credentials
        default_cred_vulns = [v for v in vulnerabilities 
                             if 'default' in v.get('description', '').lower() 
                             and 'credential' in v.get('description', '').lower()]
        if default_cred_vulns:
            findings.append(
                f"{len(default_cred_vulns)} devices using default credentials"
            )
        
        # Check for unencrypted communications
        encryption_vulns = [v for v in vulnerabilities 
                           if 'unencrypted' in v.get('description', '').lower() 
                           or 'encryption' in v.get('description', '').lower()]
        if encryption_vulns:
            findings.append(
                f"{len(encryption_vulns)} devices with encryption issues"
            )
        
        # Check for exposed services
        exposed_services = [v for v in vulnerabilities 
                          if 'exposed' in v.get('description', '').lower()]
        if exposed_services:
            findings.append(
                f"{len(exposed_services)} exposed services detected"
            )
        
        return findings[:5]  # Top 5
    
    def _assess_risk(self, vulnerabilities: List[Dict], 
                    devices: List[Dict]) -> Dict:
        """Comprehensive risk assessment"""
        risk = {
            'overall_risk_level': 'Low',
            'risk_score': 0,
            'critical_devices_at_risk': 0,
            'attack_surface': 'Small',
            'likelihood_of_compromise': 'Low'
        }
        
        # Calculate risk score (0-100)
        score = 0
        
        # Severity-based scoring
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'Low')
            if severity == 'Critical':
                score += 20
            elif severity == 'High':
                score += 10
            elif severity == 'Medium':
                score += 5
            else:
                score += 2
        
        risk['risk_score'] = min(score, 100)
        
        # Determine overall risk level
        if risk['risk_score'] >= 70:
            risk['overall_risk_level'] = 'Critical'
            risk['likelihood_of_compromise'] = 'High'
        elif risk['risk_score'] >= 50:
            risk['overall_risk_level'] = 'High'
            risk['likelihood_of_compromise'] = 'Medium'
        elif risk['risk_score'] >= 30:
            risk['overall_risk_level'] = 'Medium'
            risk['likelihood_of_compromise'] = 'Low'
        else:
            risk['overall_risk_level'] = 'Low'
            risk['likelihood_of_compromise'] = 'Very Low'
        
        # Count critical devices
        critical_types = ['smart_lock', 'camera', 'router', 'gateway', 'plc']
        risk['critical_devices_at_risk'] = len([
            d for d in devices 
            if any(ct in d.get('device_type', '').lower() for ct in critical_types)
        ])
        
        # Assess attack surface
        total_ports = sum(len(d.get('open_ports', [])) for d in devices)
        if total_ports > 50:
            risk['attack_surface'] = 'Large'
        elif total_ports > 20:
            risk['attack_surface'] = 'Medium'
        else:
            risk['attack_surface'] = 'Small'
        
        return risk
    
    def _assess_business_impact(self, vulnerabilities: List[Dict], 
                               devices: List[Dict]) -> Dict:
        """Assess business impact of vulnerabilities"""
        impact = {
            'potential_losses': [],
            'compliance_risks': [],
            'operational_risks': [],
            'reputational_risks': []
        }
        
        # Check for data breach risks
        data_vulns = [v for v in vulnerabilities 
                     if any(term in v.get('description', '').lower() 
                           for term in ['disclosure', 'exposure', 'leak', 'unencrypted'])]
        if data_vulns:
            impact['potential_losses'].append(
                'Data breach could result in regulatory fines and legal costs'
            )
            impact['compliance_risks'].append(
                'GDPR/CCPA compliance violations possible'
            )
        
        # Check for availability risks
        dos_vulns = [v for v in vulnerabilities 
                    if 'denial' in v.get('description', '').lower()]
        if dos_vulns:
            impact['operational_risks'].append(
                'Service disruption could impact business operations'
            )
        
        # Check for critical device compromise
        critical_devices = [d for d in devices 
                          if d.get('device_type') in ['smart_lock', 'camera', 'plc']]
        if critical_devices:
            impact['operational_risks'].append(
                f'{len(critical_devices)} critical devices could be compromised'
            )
            impact['reputational_risks'].append(
                'Security breach could damage company reputation'
            )
        
        return impact
    
    def _generate_top_recommendations(self, vulnerabilities: List[Dict], 
                                     devices: List[Dict]) -> List[Dict]:
        """Generate prioritized recommendations"""
        recommendations = []
        
        # Priority 1: Critical vulnerabilities
        critical = [v for v in vulnerabilities if v.get('severity') == 'Critical']
        if critical:
            recommendations.append({
                'priority': 1,
                'action': f'Address {len(critical)} critical vulnerabilities immediately',
                'timeline': 'Within 24-48 hours',
                'impact': 'Prevents immediate exploitation'
            })
        
        # Priority 2: Default credentials
        default_creds = [v for v in vulnerabilities 
                        if 'default' in v.get('description', '').lower()]
        if default_creds:
            recommendations.append({
                'priority': 2,
                'action': f'Change default credentials on {len(default_creds)} devices',
                'timeline': 'Within 1 week',
                'impact': 'Significantly reduces attack surface'
            })
        
        # Priority 3: Encryption issues
        encryption = [v for v in vulnerabilities 
                     if 'encryption' in v.get('description', '').lower() 
                     or 'unencrypted' in v.get('description', '').lower()]
        if encryption:
            recommendations.append({
                'priority': 3,
                'action': f'Enable encryption on {len(encryption)} devices/services',
                'timeline': 'Within 2 weeks',
                'impact': 'Protects data in transit'
            })
        
        # Priority 4: Update outdated firmware
        outdated = [d for d in devices 
                   if 'outdated' in str(d.get('firmware_version', '')).lower()]
        if outdated:
            recommendations.append({
                'priority': 4,
                'action': f'Update firmware on {len(outdated)} devices',
                'timeline': 'Within 1 month',
                'impact': 'Patches known vulnerabilities'
            })
        
        # Priority 5: Network segmentation
        total_devices = len(devices)
        if total_devices > 5:
            recommendations.append({
                'priority': 5,
                'action': 'Implement network segmentation for IoT devices',
                'timeline': 'Within 2 months',
                'impact': 'Limits lateral movement'
            })
        
        return recommendations[:5]  # Top 5
    
    def _calculate_key_metrics(self, devices: List[Dict], 
                               vulnerabilities: List[Dict]) -> Dict:
        """Calculate key security metrics"""
        metrics = {
            'vulnerability_density': 0,  # Vulns per device
            'critical_exposure': 0,  # % of devices with critical vulns
            'remediation_effort': 'Low',
            'mean_time_to_remediate': 'Unknown'
        }
        
        if devices:
            metrics['vulnerability_density'] = len(vulnerabilities) / len(devices)
            
            # Calculate critical exposure
            devices_with_critical = len(set(
                v.get('device_id') for v in vulnerabilities 
                if v.get('severity') == 'Critical'
            ))
            metrics['critical_exposure'] = (devices_with_critical / len(devices)) * 100
        
        # Estimate remediation effort
        total_vulns = len(vulnerabilities)
        if total_vulns > 50:
            metrics['remediation_effort'] = 'High'
            metrics['mean_time_to_remediate'] = '3-6 months'
        elif total_vulns > 20:
            metrics['remediation_effort'] = 'Medium'
            metrics['mean_time_to_remediate'] = '1-3 months'
        else:
            metrics['remediation_effort'] = 'Low'
            metrics['mean_time_to_remediate'] = '2-4 weeks'
        
        return metrics
    
    def format_for_presentation(self, summary: Dict) -> str:
        """Format summary for executive presentation"""
        output = []
        output.append("="*70)
        output.append("EXECUTIVE SECURITY SUMMARY")
        output.append("="*70)
        output.append("")
        
        # Overview
        output.append("OVERVIEW")
        output.append("-" * 70)
        overview = summary['overview']
        output.append(f"Devices Scanned: {overview['total_devices_scanned']}")
        output.append(f"Vulnerabilities Found: {overview['total_vulnerabilities_found']}")
        output.append(f"Security Posture: {overview['security_posture']}")
        output.append("")
        
        # Risk Assessment
        output.append("RISK ASSESSMENT")
        output.append("-" * 70)
        risk = summary['risk_assessment']
        output.append(f"Overall Risk Level: {risk['overall_risk_level']}")
        output.append(f"Risk Score: {risk['risk_score']}/100")
        output.append(f"Likelihood of Compromise: {risk['likelihood_of_compromise']}")
        output.append("")
        
        # Key Findings
        output.append("KEY FINDINGS")
        output.append("-" * 70)
        for i, finding in enumerate(summary['key_findings'], 1):
            output.append(f"{i}. {finding}")
        output.append("")
        
        # Top Recommendations
        output.append("TOP RECOMMENDATIONS")
        output.append("-" * 70)
        for rec in summary['recommendations'][:3]:
            output.append(f"[Priority {rec['priority']}] {rec['action']}")
            output.append(f"  Timeline: {rec['timeline']}")
            output.append(f"  Impact: {rec['impact']}")
            output.append("")
        
        return "\n".join(output)


# Example usage
if __name__ == '__main__':
    print("="*70)
    print("Executive Summary Generator - Phase 8.4")
    print("="*70)
    
    generator = ExecutiveSummaryGenerator()
    
    # Test data
    test_scan = {
        'timestamp': datetime.now().isoformat(),
        'devices': [
            {'id': i, 'device_type': 'camera', 'open_ports': [80, 554]} 
            for i in range(10)
        ],
        'vulnerabilities': [
            {'device_id': 1, 'description': 'Default credentials', 'severity': 'Critical'},
            {'device_id': 2, 'description': 'Unencrypted communication', 'severity': 'High'},
            {'device_id': 3, 'description': 'Weak encryption', 'severity': 'Medium'},
        ]
    }
    
    summary = generator.generate_summary(test_scan)
    
    print("\n" + generator.format_for_presentation(summary))
