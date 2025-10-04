"""
Reporting Manager - Phase 8
Unified manager for all advanced reporting features
"""

import logging
from typing import Dict, List
from datetime import datetime
import os

from .threat_scoring import ThreatScoringEngine
from .vulnerability_correlation import VulnerabilityCorrelation
from .scan_comparison import ScanComparison
from .executive_summary import ExecutiveSummaryGenerator
from .visualization import ReportVisualization
from .report_templates import ReportTemplates

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class AdvancedReportingManager:
    """
    Comprehensive reporting manager
    Coordinates all Phase 8 features
    """
    
    def __init__(self):
        """Initialize reporting manager"""
        self.threat_scorer = ThreatScoringEngine()
        self.correlator = VulnerabilityCorrelation()
        self.comparator = ScanComparison()
        self.summary_gen = ExecutiveSummaryGenerator()
        self.visualizer = ReportVisualization()
        self.templates = ReportTemplates()
        
        self.generated_reports = []
    
    def generate_comprehensive_report(self, scan_data: Dict, 
                                     industry: str = 'general',
                                     include_charts: bool = True,
                                     previous_scans: List[Dict] = None) -> Dict:
        """
        Generate comprehensive security report
        
        Args:
            scan_data: Current scan data
            industry: Industry type for template
            include_charts: Include visualizations
            previous_scans: Previous scans for comparison
            
        Returns:
            Complete report package
        """
        logger.info(f"Generating comprehensive report for {industry} industry")
        
        report_package = {
            'report_id': datetime.now().strftime('%Y%m%d_%H%M%S'),
            'generated_at': datetime.now().isoformat(),
            'industry': industry,
            'scan_data': scan_data,
            'threat_analysis': {},
            'correlation_analysis': {},
            'executive_summary': {},
            'visualizations': {},
            'comparison': {},
            'html_report': '',
            'pdf_report_path': None
        }
        
        devices = scan_data.get('devices', [])
        vulnerabilities = scan_data.get('vulnerabilities', [])
        
        # Step 1: Threat Scoring
        logger.info("Step 1: Calculating threat scores...")
        scored_vulns = self.threat_scorer.prioritize_vulnerabilities(
            vulnerabilities, devices
        )
        report_package['threat_analysis'] = {
            'prioritized_vulnerabilities': scored_vulns[:20],  # Top 20
            'average_threat_score': sum(v['threat_score'] for v in scored_vulns) / len(scored_vulns) if scored_vulns else 0
        }
        
        # Step 2: Vulnerability Correlation
        logger.info("Step 2: Correlating vulnerabilities...")
        correlations = self.correlator.find_related_vulnerabilities(vulnerabilities)
        attack_chains = self.correlator.detect_attack_chains(vulnerabilities, devices)
        
        report_package['correlation_analysis'] = {
            'correlated_groups': correlations,
            'attack_chains': attack_chains,
            'total_attack_chains': len(attack_chains)
        }
        
        # Step 3: Executive Summary
        logger.info("Step 3: Generating executive summary...")
        exec_summary = self.summary_gen.generate_summary(scan_data)
        report_package['executive_summary'] = exec_summary
        
        # Step 4: Visualizations
        if include_charts:
            logger.info("Step 4: Creating visualizations...")
            charts = self.visualizer.create_complete_dashboard(scan_data)
            report_package['visualizations'] = charts
        
        # Step 5: Scan Comparison (if previous scans provided)
        if previous_scans and len(previous_scans) > 0:
            logger.info("Step 5: Comparing with previous scans...")
            comparison = self.comparator.compare_scans(previous_scans[-1], scan_data)
            report_package['comparison'] = comparison
            
            # Trend analysis
            all_scans = previous_scans + [scan_data]
            trends = self.comparator.analyze_trends(all_scans)
            report_package['trends'] = trends
        
        # Step 6: Generate HTML Report
        logger.info("Step 6: Generating HTML report...")
        html_report = self.templates.generate_industry_report(
            industry, scan_data, exec_summary
        )
        report_package['html_report'] = html_report
        
        # Save HTML report
        reports_dir = 'reports/generated'
        os.makedirs(reports_dir, exist_ok=True)
        
        report_filename = f"iot_security_report_{report_package['report_id']}_{industry}.html"
        report_path = os.path.join(reports_dir, report_filename)
        
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(html_report)
        
        report_package['report_path'] = report_path
        
        logger.info(f"Report generated: {report_path}")
        
        self.generated_reports.append(report_package)
        
        return report_package
    
    def generate_comparison_report(self, scan1: Dict, scan2: Dict) -> Dict:
        """
        Generate scan comparison report
        
        Args:
            scan1: Earlier scan
            scan2: Later scan
            
        Returns:
            Comparison report
        """
        comparison = self.comparator.compare_scans(scan1, scan2)
        
        # Create HTML report for comparison
        html = self._format_comparison_html(comparison)
        
        return {
            'comparison': comparison,
            'html': html
        }
    
    def _format_comparison_html(self, comparison: Dict) -> str:
        """Format comparison as HTML"""
        html = '<div class="section">'
        html += '<h2>📈 Scan Comparison</h2>'
        
        html += f'<p><strong>Overall Change:</strong> {comparison["overall_change"]}</p>'
        
        html += '<h3>Devices</h3>'
        html += f'<p>Previous: {comparison["devices"]["previous"]}</p>'
        html += f'<p>Current: {comparison["devices"]["current"]}</p>'
        html += f'<p>Change: {comparison["devices"]["change"]:+d}</p>'
        
        html += '<h3>Vulnerabilities</h3>'
        html += f'<p>Previous: {comparison["vulnerabilities"]["previous"]}</p>'
        html += f'<p>Current: {comparison["vulnerabilities"]["current"]}</p>'
        html += f'<p>Change: {comparison["vulnerabilities"]["change"]:+d}</p>'
        
        if comparison.get('improvements'):
            html += '<h3>✅ Improvements</h3><ul>'
            for imp in comparison['improvements']:
                html += f'<li>{imp}</li>'
            html += '</ul>'
        
        if comparison.get('deteriorations'):
            html += '<h3>⚠️ Deteriorations</h3><ul>'
            for det in comparison['deteriorations']:
                html += f'<li>{det}</li>'
            html += '</ul>'
        
        html += '</div>'
        return html
    
    def get_report_statistics(self) -> Dict:
        """Get statistics about generated reports"""
        return {
            'total_reports': len(self.generated_reports),
            'industries_covered': list(set(r['industry'] for r in self.generated_reports)),
            'latest_report': self.generated_reports[-1] if self.generated_reports else None
        }


# Example usage
if __name__ == '__main__':
    print("="*70)
    print("Advanced Reporting Manager - Phase 8")
    print("="*70)
    
    manager = AdvancedReportingManager()
    
    # Test scan data
    test_scan = {
        'timestamp': datetime.now().isoformat(),
        'devices': [
            {'id': 1, 'ip_address': '192.168.1.100', 'device_type': 'camera', 'open_ports': [80, 554]},
            {'id': 2, 'ip_address': '192.168.1.101', 'device_type': 'smart_lock', 'open_ports': [443]}
        ],
        'vulnerabilities': [
            {'id': 1, 'device_id': 1, 'description': 'Default credentials', 'severity': 'Critical'},
            {'id': 2, 'device_id': 1, 'description': 'Unencrypted stream', 'severity': 'High'},
            {'id': 3, 'device_id': 2, 'description': 'Weak encryption', 'severity': 'Medium'}
        ]
    }
    
    print("\nGenerating comprehensive report...")
    report = manager.generate_comprehensive_report(
        test_scan,
        industry='smart_home',
        include_charts=True
    )
    
    print(f"\n✓ Report generated: {report['report_id']}")
    print(f"  Industry: {report['industry']}")
    print(f"  Threat Analysis: {len(report['threat_analysis']['prioritized_vulnerabilities'])} vulnerabilities scored")
    print(f"  Attack Chains: {report['correlation_analysis']['total_attack_chains']}")
    print(f"  Visualizations: {len(report['visualizations'])} charts")
    print(f"  Report Path: {report['report_path']}")
    
    stats = manager.get_report_statistics()
    print(f"\nReporting Statistics:")
    print(f"  Total Reports: {stats['total_reports']}")
