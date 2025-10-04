"""
Scan Comparison & Trending - Phase 8.3
Compares scans over time and identifies trends
"""

import logging
from typing import Dict, List
from datetime import datetime, timedelta
from collections import defaultdict

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ScanComparison:
    """Compare and trend multiple scans"""
    
    def __init__(self):
        """Initialize scan comparison"""
        self.comparisons = []
    
    def compare_scans(self, scan1: Dict, scan2: Dict) -> Dict:
        """
        Compare two scans
        
        Args:
            scan1: Earlier scan data
            scan2: Later scan data
            
        Returns:
            Comparison results
        """
        comparison = {
            'scan1_date': scan1.get('timestamp'),
            'scan2_date': scan2.get('timestamp'),
            'devices': {},
            'vulnerabilities': {},
            'overall_change': 'unchanged',
            'improvements': [],
            'deteriorations': []
        }
        
        # Compare device counts
        devices1 = scan1.get('devices', [])
        devices2 = scan2.get('devices', [])
        
        comparison['devices'] = {
            'previous': len(devices1),
            'current': len(devices2),
            'change': len(devices2) - len(devices1),
            'new_devices': self._find_new_items(devices1, devices2, 'ip_address'),
            'removed_devices': self._find_removed_items(devices1, devices2, 'ip_address')
        }
        
        # Compare vulnerabilities
        vulns1 = scan1.get('vulnerabilities', [])
        vulns2 = scan2.get('vulnerabilities', [])
        
        comparison['vulnerabilities'] = {
            'previous': len(vulns1),
            'current': len(vulns2),
            'change': len(vulns2) - len(vulns1),
            'new_vulnerabilities': self._find_new_vulnerabilities(vulns1, vulns2),
            'fixed_vulnerabilities': self._find_fixed_vulnerabilities(vulns1, vulns2)
        }
        
        # Determine overall change
        vuln_change = comparison['vulnerabilities']['change']
        
        if vuln_change > 0:
            comparison['overall_change'] = 'worse'
            comparison['deteriorations'].append(
                f"{vuln_change} new vulnerabilities discovered"
            )
        elif vuln_change < 0:
            comparison['overall_change'] = 'better'
            comparison['improvements'].append(
                f"{abs(vuln_change)} vulnerabilities fixed"
            )
        
        # Check severity changes
        severity_change = self._compare_severity_distribution(vulns1, vulns2)
        comparison['severity_change'] = severity_change
        
        if severity_change.get('critical_change', 0) > 0:
            comparison['deteriorations'].append(
                f"{severity_change['critical_change']} new critical vulnerabilities"
            )
        elif severity_change.get('critical_change', 0) < 0:
            comparison['improvements'].append(
                f"{abs(severity_change['critical_change'])} critical vulnerabilities fixed"
            )
        
        self.comparisons.append(comparison)
        return comparison
    
    def _find_new_items(self, old_list: List[Dict], new_list: List[Dict], 
                       key: str) -> List[Dict]:
        """Find items in new_list that aren't in old_list"""
        old_keys = {item.get(key) for item in old_list}
        return [item for item in new_list if item.get(key) not in old_keys]
    
    def _find_removed_items(self, old_list: List[Dict], new_list: List[Dict], 
                           key: str) -> List[Dict]:
        """Find items in old_list that aren't in new_list"""
        new_keys = {item.get(key) for item in new_list}
        return [item for item in old_list if item.get(key) not in new_keys]
    
    def _find_new_vulnerabilities(self, old_vulns: List[Dict], 
                                 new_vulns: List[Dict]) -> List[Dict]:
        """Find vulnerabilities that are new"""
        # Create signature for each vulnerability
        old_sigs = {self._vuln_signature(v) for v in old_vulns}
        return [v for v in new_vulns if self._vuln_signature(v) not in old_sigs]
    
    def _find_fixed_vulnerabilities(self, old_vulns: List[Dict], 
                                   new_vulns: List[Dict]) -> List[Dict]:
        """Find vulnerabilities that were fixed"""
        new_sigs = {self._vuln_signature(v) for v in new_vulns}
        return [v for v in old_vulns if self._vuln_signature(v) not in new_sigs]
    
    def _vuln_signature(self, vuln: Dict) -> str:
        """Create unique signature for vulnerability"""
        device_id = vuln.get('device_id', 'unknown')
        description = vuln.get('description', '')
        cve_id = vuln.get('cve_id', '')
        
        return f"{device_id}:{cve_id}:{description[:50]}"
    
    def _compare_severity_distribution(self, old_vulns: List[Dict], 
                                      new_vulns: List[Dict]) -> Dict:
        """Compare severity distribution between scans"""
        def count_by_severity(vulns):
            counts = defaultdict(int)
            for v in vulns:
                counts[v.get('severity', 'Low')] += 1
            return dict(counts)
        
        old_dist = count_by_severity(old_vulns)
        new_dist = count_by_severity(new_vulns)
        
        return {
            'critical_change': new_dist.get('Critical', 0) - old_dist.get('Critical', 0),
            'high_change': new_dist.get('High', 0) - old_dist.get('High', 0),
            'medium_change': new_dist.get('Medium', 0) - old_dist.get('Medium', 0),
            'low_change': new_dist.get('Low', 0) - old_dist.get('Low', 0)
        }
    
    def analyze_trends(self, scans: List[Dict]) -> Dict:
        """
        Analyze trends across multiple scans
        
        Args:
            scans: List of scans ordered by date
            
        Returns:
            Trend analysis
        """
        if len(scans) < 2:
            return {'error': 'Need at least 2 scans for trend analysis'}
        
        trends = {
            'time_period': f"{scans[0].get('timestamp')} to {scans[-1].get('timestamp')}",
            'total_scans': len(scans),
            'device_trend': [],
            'vulnerability_trend': [],
            'severity_trend': {},
            'overall_trend': 'stable'
        }
        
        # Track device counts over time
        for scan in scans:
            trends['device_trend'].append({
                'date': scan.get('timestamp'),
                'count': len(scan.get('devices', []))
            })
        
        # Track vulnerability counts over time
        for scan in scans:
            vulns = scan.get('vulnerabilities', [])
            trends['vulnerability_trend'].append({
                'date': scan.get('timestamp'),
                'total': len(vulns),
                'critical': len([v for v in vulns if v.get('severity') == 'Critical']),
                'high': len([v for v in vulns if v.get('severity') == 'High']),
                'medium': len([v for v in vulns if v.get('severity') == 'Medium']),
                'low': len([v for v in vulns if v.get('severity') == 'Low'])
            })
        
        # Determine overall trend
        first_vuln_count = len(scans[0].get('vulnerabilities', []))
        last_vuln_count = len(scans[-1].get('vulnerabilities', []))
        
        change_pct = ((last_vuln_count - first_vuln_count) / max(first_vuln_count, 1)) * 100
        
        if change_pct > 20:
            trends['overall_trend'] = 'deteriorating'
            trends['trend_description'] = f'Security posture worsening ({change_pct:.1f}% more vulnerabilities)'
        elif change_pct < -20:
            trends['overall_trend'] = 'improving'
            trends['trend_description'] = f'Security posture improving ({abs(change_pct):.1f}% fewer vulnerabilities)'
        else:
            trends['overall_trend'] = 'stable'
            trends['trend_description'] = 'Security posture relatively stable'
        
        return trends


# Example usage
if __name__ == '__main__':
    print("="*70)
    print("Scan Comparison & Trending - Phase 8.3")
    print("="*70)
    
    comparator = ScanComparison()
    
    # Test scans
    scan1 = {
        'timestamp': '2024-01-01T10:00:00',
        'devices': [
            {'id': 1, 'ip_address': '192.168.1.100'},
            {'id': 2, 'ip_address': '192.168.1.101'}
        ],
        'vulnerabilities': [
            {'device_id': 1, 'description': 'Default credentials', 'severity': 'Critical'},
            {'device_id': 2, 'description': 'Weak encryption', 'severity': 'High'}
        ]
    }
    
    scan2 = {
        'timestamp': '2024-01-15T10:00:00',
        'devices': [
            {'id': 1, 'ip_address': '192.168.1.100'},
            {'id': 2, 'ip_address': '192.168.1.101'},
            {'id': 3, 'ip_address': '192.168.1.102'}
        ],
        'vulnerabilities': [
            {'device_id': 1, 'description': 'Default credentials', 'severity': 'Critical'},
            {'device_id': 2, 'description': 'Weak encryption', 'severity': 'High'},
            {'device_id': 3, 'description': 'Open port 23', 'severity': 'High'}
        ]
    }
    
    # Compare scans
    print("\nComparing scans...")
    comparison = comparator.compare_scans(scan1, scan2)
    
    print(f"\nDevices: {comparison['devices']['previous']} → {comparison['devices']['current']}")
    print(f"  Change: {comparison['devices']['change']:+d}")
    print(f"  New: {len(comparison['devices']['new_devices'])}")
    
    print(f"\nVulnerabilities: {comparison['vulnerabilities']['previous']} → {comparison['vulnerabilities']['current']}")
    print(f"  Change: {comparison['vulnerabilities']['change']:+d}")
    print(f"  Overall: {comparison['overall_change']}")
    
    if comparison['deteriorations']:
        print(f"\n⚠️  Deteriorations:")
        for d in comparison['deteriorations']:
            print(f"    - {d}")
