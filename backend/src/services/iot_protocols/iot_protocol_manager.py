"""
IoT Protocol Manager - Phase 5
Unified manager for IoT-specific protocols: Zigbee, Z-Wave, LoRaWAN, Thread/Matter
"""

import asyncio
import logging
from typing import Dict, List, Optional
from datetime import datetime

from .zigbee_analyzer import ZigbeeAnalyzer
from .zwave_analyzer import ZWaveAnalyzer
from .lorawan_analyzer import LoRaWANAnalyzer

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class IoTProtocolManager:
    """
    Unified manager for IoT-specific protocol analysis
    Supports Zigbee, Z-Wave, LoRaWAN, Thread, Matter
    """
    
    def __init__(self):
        """Initialize IoT protocol manager"""
        self.zigbee_analyzer = ZigbeeAnalyzer()
        self.zwave_analyzer = ZWaveAnalyzer()
        self.lorawan_analyzer = LoRaWANAnalyzer()
        
        self.all_results = []
    
    async def comprehensive_analysis(self, scan_results: List[Dict]) -> Dict:
        """
        Run comprehensive IoT protocol analysis
        
        Args:
            scan_results: Network scan results
            
        Returns:
            Complete analysis report
        """
        logger.info("Starting comprehensive IoT protocol analysis...")
        
        report = {
            'timestamp': datetime.now().isoformat(),
            'protocols_detected': [],
            'total_devices': 0,
            'total_vulnerabilities': 0,
            'zigbee': {},
            'zwave': {},
            'lorawan': {},
            'overall_security_score': 100
        }
        
        # Detect Zigbee devices
        zigbee_devices = self.zigbee_analyzer.detect_zigbee_presence(scan_results)
        if zigbee_devices:
            report['protocols_detected'].append('Zigbee')
            report['zigbee'] = self.zigbee_analyzer.generate_report()
            report['total_devices'] += len(zigbee_devices)
            report['total_vulnerabilities'] += report['zigbee']['total_vulnerabilities']
        
        # Detect Z-Wave devices
        zwave_devices = self.zwave_analyzer.detect_zwave_presence(scan_results)
        if zwave_devices:
            report['protocols_detected'].append('Z-Wave')
            report['zwave'] = self.zwave_analyzer.generate_report()
            report['total_devices'] += len(zwave_devices)
            report['total_vulnerabilities'] += report['zwave']['total_vulnerabilities']
        
        # Detect LoRaWAN components
        lorawan_components = self.lorawan_analyzer.detect_lorawan_presence(scan_results)
        if lorawan_components:
            report['protocols_detected'].append('LoRaWAN')
            report['lorawan'] = self.lorawan_analyzer.generate_report()
            report['total_devices'] += len(lorawan_components)
            report['total_vulnerabilities'] += report['lorawan']['total_vulnerabilities']
        
        # Calculate overall security score
        scores = []
        if report['zigbee']:
            # Estimate Zigbee score based on vulnerabilities
            zigbee_score = 100 - (report['zigbee']['total_vulnerabilities'] * 15)
            scores.append(max(0, zigbee_score))
        
        if report['zwave']:
            zwave_score = 100 - (report['zwave']['total_vulnerabilities'] * 15)
            scores.append(max(0, zwave_score))
        
        if report['lorawan']:
            lorawan_score = 100 - (report['lorawan']['total_vulnerabilities'] * 15)
            scores.append(max(0, lorawan_score))
        
        if scores:
            report['overall_security_score'] = sum(scores) / len(scores)
        
        logger.info(f"IoT protocol analysis complete. Found {report['total_devices']} devices across {len(report['protocols_detected'])} protocols")
        
        self.all_results.append(report)
        return report
    
    def get_protocol_statistics(self, report: Dict) -> Dict:
        """Generate protocol statistics"""
        stats = {
            'protocols_found': len(report['protocols_detected']),
            'protocol_list': report['protocols_detected'],
            'total_iot_devices': report['total_devices'],
            'vulnerability_breakdown': {
                'zigbee': report['zigbee'].get('total_vulnerabilities', 0),
                'zwave': report['zwave'].get('total_vulnerabilities', 0),
                'lorawan': report['lorawan'].get('total_vulnerabilities', 0)
            },
            'security_score': report['overall_security_score']
        }
        
        return stats
    
    def get_critical_findings(self, report: Dict) -> List[Dict]:
        """Extract critical security findings"""
        critical_findings = []
        
        # Extract Zigbee critical vulnerabilities
        if report.get('zigbee'):
            for vuln in report['zigbee'].get('vulnerabilities', []):
                if vuln.get('severity') == 'Critical':
                    critical_findings.append({
                        'protocol': 'Zigbee',
                        **vuln
                    })
        
        # Extract Z-Wave critical vulnerabilities
        if report.get('zwave'):
            for vuln in report['zwave'].get('vulnerabilities', []):
                if vuln.get('severity') == 'Critical':
                    critical_findings.append({
                        'protocol': 'Z-Wave',
                        **vuln
                    })
        
        # Extract LoRaWAN critical vulnerabilities
        if report.get('lorawan'):
            for vuln in report['lorawan'].get('vulnerabilities', []):
                if vuln.get('severity') == 'Critical':
                    critical_findings.append({
                        'protocol': 'LoRaWAN',
                        **vuln
                    })
        
        return critical_findings
    
    def generate_recommendations(self, report: Dict) -> List[str]:
        """Generate consolidated recommendations"""
        recommendations = []
        
        # Zigbee recommendations
        if report.get('zigbee') and report['zigbee'].get('recommendations'):
            recommendations.extend([
                f"[Zigbee] {rec}" for rec in report['zigbee']['recommendations']
            ])
        
        # Z-Wave recommendations
        if report.get('zwave') and report['zwave'].get('recommendations'):
            recommendations.extend([
                f"[Z-Wave] {rec}" for rec in report['zwave']['recommendations']
            ])
        
        # LoRaWAN recommendations
        if report.get('lorawan') and report['lorawan'].get('recommendations'):
            recommendations.extend([
                f"[LoRaWAN] {rec}" for rec in report['lorawan']['recommendations']
            ])
        
        return recommendations


# Example usage and testing
async def main():
    """Test IoT protocol manager"""
    print("="*70)
    print("IoT Protocol Manager - Phase 5")
    print("="*70)
    
    manager = IoTProtocolManager()
    
    # Sample scan results with various IoT devices
    sample_scan = [
        {
            'ip_address': '192.168.1.50',
            'manufacturer': 'Philips',
            'hostname': 'Philips-hue',
            'open_ports': [80, 8888]
        },
        {
            'ip_address': '192.168.1.60',
            'manufacturer': 'Aeotec',
            'hostname': 'zwave-controller',
            'open_ports': [8091]
        },
        {
            'ip_address': '192.168.1.70',
            'manufacturer': 'Semtech',
            'hostname': 'lora-gateway',
            'open_ports': [1700, 1701]
        },
        {
            'ip_address': '192.168.1.51',
            'manufacturer': 'LUMI',
            'device_type': 'smart_sensor'
        },
        {
            'ip_address': '192.168.1.61',
            'device_type': 'smart_lock',
            'manufacturer': 'Yale'
        }
    ]
    
    print("\nAnalyzing IoT devices...")
    report = await manager.comprehensive_analysis(sample_scan)
    
    print(f"\n{'='*70}")
    print("Analysis Results")
    print(f"{'='*70}")
    
    print(f"\nProtocols Detected: {', '.join(report['protocols_detected']) if report['protocols_detected'] else 'None'}")
    print(f"Total IoT Devices: {report['total_devices']}")
    print(f"Total Vulnerabilities: {report['total_vulnerabilities']}")
    print(f"Overall Security Score: {report['overall_security_score']:.1f}/100")
    
    # Show protocol breakdown
    if report.get('zigbee') and report['zigbee'].get('discovered_devices') > 0:
        print(f"\nZigbee:")
        print(f"  Devices: {report['zigbee']['discovered_devices']}")
        print(f"  Vulnerabilities: {report['zigbee']['total_vulnerabilities']}")
    
    if report.get('zwave') and report['zwave'].get('discovered_devices') > 0:
        print(f"\nZ-Wave:")
        print(f"  Devices: {report['zwave']['discovered_devices']}")
        print(f"  Vulnerabilities: {report['zwave']['total_vulnerabilities']}")
    
    if report.get('lorawan') and report['lorawan'].get('discovered_gateways') > 0:
        print(f"\nLoRaWAN:")
        print(f"  Gateways: {report['lorawan']['discovered_gateways']}")
        print(f"  Vulnerabilities: {report['lorawan']['total_vulnerabilities']}")
    
    # Show critical findings
    critical = manager.get_critical_findings(report)
    if critical:
        print(f"\n{'='*70}")
        print(f"Critical Findings: {len(critical)}")
        print(f"{'='*70}")
        for finding in critical:
            print(f"\n  [{finding['protocol']}] {finding['type']}")
            print(f"  {finding['description']}")
    
    # Show recommendations
    recommendations = manager.generate_recommendations(report)
    if recommendations:
        print(f"\n{'='*70}")
        print("Security Recommendations")
        print(f"{'='*70}")
        for rec in recommendations[:5]:
            print(f"  • {rec}")
        if len(recommendations) > 5:
            print(f"  ... and {len(recommendations) - 5} more")


if __name__ == '__main__':
    asyncio.run(main())
