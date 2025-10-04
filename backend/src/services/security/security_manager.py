"""
Security Analysis Manager - Phase 6
Unified manager for all advanced security features
"""

import asyncio
import logging
from typing import Dict, List, Optional
from datetime import datetime

from .default_credentials import DefaultCredentialTester
from .ssl_tls_analyzer import SSLTLSAnalyzer
from .encryption_analyzer import EncryptionAnalyzer
from .threat_intelligence import ThreatIntelligence

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class SecurityAnalysisManager:
    """
    Comprehensive security analysis manager
    Coordinates all Phase 6 security features
    """
    
    def __init__(self):
        """Initialize security analysis manager"""
        self.credential_tester = DefaultCredentialTester()
        self.ssl_analyzer = SSLTLSAnalyzer()
        self.encryption_analyzer = EncryptionAnalyzer()
        self.threat_intel = ThreatIntelligence()
        
        self.all_vulnerabilities = []
    
    async def comprehensive_security_analysis(self, device_info: Dict) -> Dict:
        """
        Run comprehensive security analysis on a device
        
        Args:
            device_info: Device information
            
        Returns:
            Complete security analysis report
        """
        ip = device_info.get('ip_address')
        logger.info(f"Starting comprehensive security analysis for {ip}")
        
        report = {
            'ip': ip,
            'timestamp': datetime.now().isoformat(),
            'analyses_performed': [],
            'vulnerabilities': [],
            'overall_security_score': 100,
            'risk_level': 'Low'
        }
        
        # 1. Test for default credentials
        logger.info(f"Testing default credentials on {ip}")
        cred_result = await self.credential_tester.test_device_credentials(device_info)
        
        if cred_result['successful']:
            report['analyses_performed'].append({
                'test': 'Default Credentials',
                'result': 'Vulnerable',
                'details': f"Found {len(cred_result['successful'])} default credentials"
            })
            report['vulnerabilities'].extend(cred_result['vulnerabilities'])
            report['overall_security_score'] -= 40
        else:
            report['analyses_performed'].append({
                'test': 'Default Credentials',
                'result': 'Passed',
                'details': f"Tested {cred_result['tested']} credentials - none successful"
            })
        
        # 2. SSL/TLS analysis (if HTTPS port is open)
        https_ports = [p for p in device_info.get('open_ports', []) if p in [443, 8443]]
        
        if https_ports:
            logger.info(f"Analyzing SSL/TLS on {ip}")
            for port in https_ports[:1]:  # Analyze first HTTPS port
                try:
                    ssl_result = await self.ssl_analyzer.comprehensive_analysis(ip, port)
                    
                    report['analyses_performed'].append({
                        'test': 'SSL/TLS Security',
                        'result': f"Score: {ssl_result['security_score']}/100",
                        'details': f"Found {len(ssl_result['vulnerabilities'])} SSL/TLS issues"
                    })
                    
                    report['vulnerabilities'].extend(ssl_result['vulnerabilities'])
                    
                    # Update score
                    ssl_impact = (100 - ssl_result['security_score']) / 2
                    report['overall_security_score'] -= ssl_impact
                    
                except Exception as e:
                    logger.error(f"SSL/TLS analysis failed: {e}")
        
        # 3. Encryption quality assessment
        logger.info(f"Assessing encryption quality for {ip}")
        encryption_result = self.encryption_analyzer.assess_encryption_quality(device_info)
        
        report['analyses_performed'].append({
            'test': 'Encryption Quality',
            'result': f"Score: {encryption_result['overall_score']}/100",
            'details': f"Strengths: {len(encryption_result['strengths'])}, Weaknesses: {len(encryption_result['weaknesses'])}"
        })
        
        encryption_impact = (100 - encryption_result['overall_score']) / 3
        report['overall_security_score'] -= encryption_impact
        
        # 4. Threat intelligence correlation
        logger.info(f"Correlating with threat intelligence for {ip}")
        threat_matches = self.threat_intel.correlate_with_threats(device_info)
        
        if threat_matches:
            report['analyses_performed'].append({
                'test': 'Threat Intelligence',
                'result': 'Matches Found',
                'details': f"Matched {len(threat_matches)} threat actor profiles"
            })
            
            for match in threat_matches:
                vuln = {
                    'type': 'Threat Actor Match',
                    'severity': match['severity'],
                    'description': match['description'],
                    'threat_actor': match['threat_actor'],
                    'recommendation': match['recommendation']
                }
                report['vulnerabilities'].append(vuln)
            
            report['overall_security_score'] -= len(threat_matches) * 10
        
        # 5. Zero-day detection (if vulnerabilities exist)
        existing_vulns = device_info.get('vulnerabilities', [])
        for vuln in existing_vulns[:3]:  # Check first 3
            zd_assessment = self.threat_intel.analyze_for_zero_day(device_info, vuln)
            
            if zd_assessment['is_potential_zero_day']:
                report['analyses_performed'].append({
                    'test': 'Zero-Day Detection',
                    'result': 'Potential Zero-Day',
                    'details': f"Confidence: {zd_assessment['confidence']:.0%}"
                })
                
                vuln_info = {
                    'type': 'Potential Zero-Day Vulnerability',
                    'severity': 'Critical',
                    'description': f"Newly discovered vulnerability with {zd_assessment['confidence']:.0%} zero-day confidence",
                    'indicators': zd_assessment['indicators'],
                    'recommendation': zd_assessment['recommendation']
                }
                report['vulnerabilities'].append(vuln_info)
                
                report['overall_security_score'] -= 30
        
        # Calculate final scores
        report['overall_security_score'] = max(0, report['overall_security_score'])
        
        # Determine risk level
        if report['overall_security_score'] < 40:
            report['risk_level'] = 'Critical'
        elif report['overall_security_score'] < 60:
            report['risk_level'] = 'High'
        elif report['overall_security_score'] < 80:
            report['risk_level'] = 'Medium'
        else:
            report['risk_level'] = 'Low'
        
        self.all_vulnerabilities.extend(report['vulnerabilities'])
        
        logger.info(f"Security analysis complete for {ip}. Risk: {report['risk_level']}, Score: {report['overall_security_score']:.0f}/100")
        
        return report
    
    async def batch_security_analysis(self, devices: List[Dict]) -> List[Dict]:
        """
        Analyze multiple devices concurrently
        
        Args:
            devices: List of device dictionaries
            
        Returns:
            List of analysis reports
        """
        logger.info(f"Starting batch security analysis for {len(devices)} devices")
        
        tasks = [self.comprehensive_security_analysis(device) for device in devices]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Filter valid results
        valid_results = []
        for result in results:
            if isinstance(result, dict):
                valid_results.append(result)
            else:
                logger.error(f"Analysis error: {result}")
        
        logger.info(f"Batch analysis complete. {len(valid_results)} devices analyzed")
        
        return valid_results
    
    def generate_executive_summary(self, results: List[Dict]) -> Dict:
        """
        Generate executive summary of security analysis
        
        Args:
            results: List of analysis results
            
        Returns:
            Executive summary
        """
        summary = {
            'total_devices': len(results),
            'risk_distribution': {
                'Critical': 0,
                'High': 0,
                'Medium': 0,
                'Low': 0
            },
            'total_vulnerabilities': sum(len(r['vulnerabilities']) for r in results),
            'critical_vulnerabilities': 0,
            'high_vulnerabilities': 0,
            'devices_with_defaults': 0,
            'ssl_issues_found': 0,
            'zero_day_candidates': len(self.threat_intel.zero_day_candidates),
            'threat_matches': len(self.threat_intel.matched_threats),
            'average_security_score': 0,
            'top_recommendations': []
        }
        
        total_score = 0
        
        for result in results:
            # Count risk levels
            risk = result.get('risk_level', 'Low')
            summary['risk_distribution'][risk] += 1
            
            # Count vulnerabilities by severity
            for vuln in result.get('vulnerabilities', []):
                severity = vuln.get('severity', '')
                if severity == 'Critical':
                    summary['critical_vulnerabilities'] += 1
                elif severity == 'High':
                    summary['high_vulnerabilities'] += 1
            
            # Count specific issues
            for analysis in result.get('analyses_performed', []):
                if 'Default Credentials' in analysis['test'] and 'Vulnerable' in analysis['result']:
                    summary['devices_with_defaults'] += 1
                elif 'SSL/TLS' in analysis['test']:
                    if 'Score: ' in analysis['result']:
                        score = int(analysis['result'].split('Score: ')[1].split('/')[0])
                        if score < 70:
                            summary['ssl_issues_found'] += 1
            
            total_score += result.get('overall_security_score', 0)
        
        if results:
            summary['average_security_score'] = total_score / len(results)
        
        # Generate top recommendations
        if summary['critical_vulnerabilities'] > 0:
            summary['top_recommendations'].append(
                f"URGENT: Address {summary['critical_vulnerabilities']} critical vulnerabilities immediately"
            )
        
        if summary['devices_with_defaults'] > 0:
            summary['top_recommendations'].append(
                f"Change default credentials on {summary['devices_with_defaults']} devices"
            )
        
        if summary['zero_day_candidates'] > 0:
            summary['top_recommendations'].append(
                f"Monitor {summary['zero_day_candidates']} potential zero-day vulnerabilities"
            )
        
        if summary['ssl_issues_found'] > 0:
            summary['top_recommendations'].append(
                f"Fix SSL/TLS issues on {summary['ssl_issues_found']} devices"
            )
        
        return summary


# Example usage
async def main():
    """Test security analysis manager"""
    print("="*70)
    print("Security Analysis Manager - Phase 6")
    print("="*70)
    
    manager = SecurityAnalysisManager()
    
    # Test devices
    test_devices = [
        {
            'ip_address': '192.168.1.100',
            'device_type': 'camera',
            'manufacturer': 'Hikvision',
            'open_ports': [80, 443, 23, 554],
            'vulnerabilities': []
        },
        {
            'ip_address': '192.168.1.101',
            'device_type': 'router',
            'manufacturer': 'TP-Link',
            'open_ports': [80, 443],
            'vulnerabilities': []
        }
    ]
    
    print(f"\nAnalyzing {len(test_devices)} devices...")
    results = await manager.batch_security_analysis(test_devices)
    
    summary = manager.generate_executive_summary(results)
    
    print(f"\n{'='*70}")
    print("Executive Summary")
    print(f"{'='*70}")
    
    print(f"\nDevices Analyzed: {summary['total_devices']}")
    print(f"Average Security Score: {summary['average_security_score']:.1f}/100")
    
    print(f"\nRisk Distribution:")
    for level, count in summary['risk_distribution'].items():
        print(f"  {level}: {count}")
    
    print(f"\nVulnerability Summary:")
    print(f"  Total: {summary['total_vulnerabilities']}")
    print(f"  Critical: {summary['critical_vulnerabilities']}")
    print(f"  High: {summary['high_vulnerabilities']}")
    
    print(f"\nSpecific Findings:")
    print(f"  Devices with Defaults: {summary['devices_with_defaults']}")
    print(f"  SSL/TLS Issues: {summary['ssl_issues_found']}")
    print(f"  Zero-Day Candidates: {summary['zero_day_candidates']}")
    print(f"  Threat Matches: {summary['threat_matches']}")
    
    if summary['top_recommendations']:
        print(f"\nTop Recommendations:")
        for rec in summary['top_recommendations']:
            print(f"  • {rec}")
    
    # Show detailed results
    print(f"\n{'='*70}")
    print("Detailed Device Analysis")
    print(f"{'='*70}")
    
    for i, result in enumerate(results, 1):
        print(f"\n{i}. {result['ip']} - Risk: {result['risk_level']}")
        print(f"   Security Score: {result['overall_security_score']:.0f}/100")
        print(f"   Analyses: {len(result['analyses_performed'])}")
        print(f"   Vulnerabilities: {len(result['vulnerabilities'])}")
        
        if result['vulnerabilities']:
            print(f"   Top Issues:")
            for vuln in result['vulnerabilities'][:2]:
                print(f"     - [{vuln['severity']}] {vuln['type']}")


if __name__ == '__main__':
    asyncio.run(main())
