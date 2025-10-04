"""
Firmware Analysis Manager - Phase 7
Unified manager for all firmware analysis capabilities
"""

import asyncio
import logging
import os
import shutil
from typing import Dict, List, Optional
from datetime import datetime

from .firmware_upload import FirmwareUploadManager
from .firmware_analyzer import FirmwareAnalyzer
from .firmware_vuln_scanner import FirmwareVulnerabilityScanner

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class FirmwareAnalysisManager:
    """
    Comprehensive firmware analysis manager
    Handles upload, extraction, analysis, and vulnerability detection
    """
    
    def __init__(self, upload_dir: str = 'uploads/firmware'):
        """
        Initialize firmware analysis manager
        
        Args:
            upload_dir: Directory for firmware uploads
        """
        self.upload_manager = FirmwareUploadManager(upload_dir)
        self.analyzer = FirmwareAnalyzer()
        self.vuln_scanner = FirmwareVulnerabilityScanner()
        
        self.analysis_reports = {}
    
    async def upload_and_analyze(self, file_obj, metadata: Dict) -> Dict:
        """
        Upload firmware and perform comprehensive analysis
        
        Args:
            file_obj: Uploaded file object
            metadata: Firmware metadata (manufacturer, model, version)
            
        Returns:
            Complete analysis report
        """
        logger.info(f"Starting firmware analysis for {file_obj.filename}")
        
        report = {
            'timestamp': datetime.now().isoformat(),
            'firmware_info': {},
            'upload_status': {},
            'extraction': {},
            'vulnerabilities': [],
            'credentials': [],
            'certificates': [],
            'components': [],
            'security_features': {},
            'overall_risk_level': 'Unknown',
            'recommendations': []
        }
        
        # Step 1: Upload firmware
        logger.info("Step 1: Uploading firmware...")
        upload_result = self.upload_manager.save_firmware(file_obj, metadata)
        report['upload_status'] = upload_result
        
        if not upload_result['success']:
            report['overall_risk_level'] = 'Unknown'
            return report
        
        firmware_info = upload_result['firmware']
        report['firmware_info'] = firmware_info
        firmware_path = firmware_info['file_path']
        
        # Step 2: Extract firmware
        logger.info("Step 2: Extracting firmware...")
        extraction = self.analyzer.extract_firmware(firmware_path)
        report['extraction'] = {
            'success': extraction['success'],
            'filesystems_found': extraction.get('filesystems_found', []),
            'files_extracted': len(extraction.get('extracted_files', []))
        }
        
        extracted_dir = extraction.get('output_dir') if extraction['success'] else None
        
        # Step 3: Search for hardcoded credentials
        logger.info("Step 3: Searching for hardcoded credentials...")
        credentials = self.analyzer.find_hardcoded_credentials(
            firmware_path,
            extracted_dir
        )
        report['credentials'] = credentials
        
        if credentials:
            for cred in credentials:
                vuln = {
                    'type': 'Hardcoded Credentials',
                    'severity': 'Critical',
                    'description': f'Hardcoded {cred["type"]}: {cred["value"]}',
                    'file': cred['file'],
                    'recommendation': 'Remove hardcoded credentials, use secure key storage'
                }
                report['vulnerabilities'].append(vuln)
        
        # Step 4: Extract certificates and keys
        if extracted_dir:
            logger.info("Step 4: Extracting certificates...")
            certificates = self.analyzer.extract_certificates(extracted_dir)
            report['certificates'] = certificates
            
            for cert in certificates:
                vuln = {
                    'type': f'Embedded {cert["type"]}',
                    'severity': cert['severity'],
                    'description': f'Embedded {cert["type"]} found in firmware',
                    'file': cert['file'],
                    'recommendation': 'Validate certificate security and usage'
                }
                report['vulnerabilities'].append(vuln)
        
        # Step 5: Detect components and versions
        if extracted_dir:
            logger.info("Step 5: Detecting components...")
            components = self.vuln_scanner.detect_components(extracted_dir)
            report['components'] = components
            
            # Check for known vulnerabilities
            logger.info("Step 6: Checking component vulnerabilities...")
            component_vulns = self.vuln_scanner.check_component_vulnerabilities(components)
            report['vulnerabilities'].extend(component_vulns)
        
        # Step 7: Scan for dangerous functions
        if extracted_dir:
            logger.info("Step 7: Scanning for dangerous functions...")
            dangerous_funcs = self.vuln_scanner.scan_for_dangerous_functions(extracted_dir)
            
            for func in dangerous_funcs[:20]:  # Limit to top 20
                vuln = {
                    'type': f'Dangerous Function: {func["category"]}',
                    'severity': func['severity'],
                    'description': f'{func["occurrences"]} occurrences in {func["file"]}',
                    'recommendation': 'Review code for security issues'
                }
                report['vulnerabilities'].append(vuln)
        
        # Step 8: Check security features
        logger.info("Step 8: Checking security features...")
        security_features = self.vuln_scanner.check_security_features(firmware_path)
        report['security_features'] = security_features
        
        for finding in security_features.get('findings', []):
            vuln = {
                'type': finding['issue'],
                'severity': finding['severity'],
                'description': finding['description'],
                'recommendation': 'Recompile with security features enabled'
            }
            report['vulnerabilities'].append(vuln)
        
        # Step 9: Calculate overall risk
        logger.info("Step 9: Calculating risk level...")
        risk_score = self._calculate_risk_score(report)
        
        if risk_score >= 80:
            report['overall_risk_level'] = 'Critical'
        elif risk_score >= 60:
            report['overall_risk_level'] = 'High'
        elif risk_score >= 40:
            report['overall_risk_level'] = 'Medium'
        else:
            report['overall_risk_level'] = 'Low'
        
        report['risk_score'] = risk_score
        
        # Step 10: Generate recommendations
        report['recommendations'] = self._generate_recommendations(report)
        
        # Cleanup extracted files
        if extracted_dir and os.path.exists(extracted_dir):
            try:
                shutil.rmtree(extracted_dir)
                logger.info(f"Cleaned up extraction directory: {extracted_dir}")
            except Exception as e:
                logger.warning(f"Could not clean up extraction directory: {e}")
        
        # Save report
        firmware_id = firmware_info['id']
        self.analysis_reports[firmware_id] = report
        
        logger.info(f"Firmware analysis complete. Risk: {report['overall_risk_level']}, Score: {risk_score}/100")
        
        return report
    
    def _calculate_risk_score(self, report: Dict) -> int:
        """Calculate overall risk score"""
        score = 0
        
        # Hardcoded credentials (very bad)
        score += len(report.get('credentials', [])) * 20
        
        # Embedded private keys (very bad)
        private_keys = [c for c in report.get('certificates', []) if 'private' in c['type'].lower()]
        score += len(private_keys) * 15
        
        # Known CVEs
        cve_vulns = [v for v in report.get('vulnerabilities', []) if 'CVE-' in str(v)]
        score += len(cve_vulns) * 10
        
        # Dangerous functions
        dangerous = [v for v in report.get('vulnerabilities', []) if 'Dangerous Function' in v.get('type', '')]
        score += len(dangerous) * 5
        
        # Missing security features
        security_findings = report.get('security_features', {}).get('findings', [])
        score += len(security_findings) * 8
        
        return min(score, 100)
    
    def _generate_recommendations(self, report: Dict) -> List[str]:
        """Generate actionable recommendations"""
        recommendations = []
        
        # Critical issues first
        if report.get('credentials'):
            recommendations.append(
                f"CRITICAL: Remove {len(report['credentials'])} hardcoded credentials from firmware"
            )
        
        private_keys = [c for c in report.get('certificates', []) if 'private' in c['type'].lower()]
        if private_keys:
            recommendations.append(
                f"CRITICAL: Remove {len(private_keys)} embedded private keys"
            )
        
        # Component vulnerabilities
        cve_vulns = [v for v in report.get('vulnerabilities', []) if 'CVE-' in str(v)]
        if cve_vulns:
            recommendations.append(
                f"Update {len(cve_vulns)} vulnerable components to latest versions"
            )
        
        # Security features
        if not report.get('security_features', {}).get('stack_canary'):
            recommendations.append(
                "Enable stack canary protection during compilation"
            )
        
        if not report.get('security_features', {}).get('nx_bit'):
            recommendations.append(
                "Enable NX bit to prevent code execution on stack"
            )
        
        # Dangerous functions
        dangerous = [v for v in report.get('vulnerabilities', []) if 'Dangerous Function' in v.get('type', '')]
        if len(dangerous) > 10:
            recommendations.append(
                f"Review and secure {len(dangerous)} dangerous function usages"
            )
        
        return recommendations
    
    def get_analysis_report(self, firmware_id: str) -> Optional[Dict]:
        """Get analysis report for firmware"""
        return self.analysis_reports.get(firmware_id)
    
    def list_analyzed_firmware(self) -> List[Dict]:
        """List all analyzed firmware"""
        return [
            {
                'firmware_id': fw_id,
                'risk_level': report['overall_risk_level'],
                'vulnerabilities': len(report['vulnerabilities']),
                'timestamp': report['timestamp']
            }
            for fw_id, report in self.analysis_reports.items()
        ]


# Example usage
async def main():
    """Test firmware analysis manager"""
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python firmware_manager.py <firmware_file>")
        sys.exit(1)
    
    firmware_file = sys.argv[1]
    
    print("="*70)
    print("Firmware Analysis Manager - Phase 7")
    print("="*70)
    
    manager = FirmwareAnalysisManager()
    
    # Simulate file upload
    print(f"\nAnalyzing: {firmware_file}")
    
    with open(firmware_file, 'rb') as f:
        # Create mock file object
        class MockFile:
            def __init__(self, file_obj, filename):
                self.file_obj = file_obj
                self.filename = filename
            
            def save(self, path):
                with open(path, 'wb') as out:
                    shutil.copyfileobj(self.file_obj, out)
        
        mock_file = MockFile(f, os.path.basename(firmware_file))
        
        metadata = {
            'manufacturer': 'Unknown',
            'model': 'Unknown',
            'version': '1.0'
        }
        
        report = await manager.upload_and_analyze(mock_file, metadata)
    
    print(f"\n{'='*70}")
    print("Analysis Report")
    print(f"{'='*70}")
    
    print(f"\nRisk Level: {report['overall_risk_level']}")
    print(f"Risk Score: {report.get('risk_score', 0)}/100")
    
    print(f"\nVulnerabilities: {len(report['vulnerabilities'])}")
    print(f"Hardcoded Credentials: {len(report.get('credentials', []))}")
    print(f"Embedded Certificates: {len(report.get('certificates', []))}")
    print(f"Components Found: {len(report.get('components', []))}")
    
    if report['recommendations']:
        print(f"\nRecommendations:")
        for rec in report['recommendations']:
            print(f"  • {rec}")


if __name__ == '__main__':
    asyncio.run(main())
