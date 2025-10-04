"""
Protocol Analysis Manager - Phase 4
Unified manager for all protocol-specific deep analysis
"""

import asyncio
import logging
from typing import Dict, List, Optional
from datetime import datetime

# Import protocol analyzers
try:
    from .mqtt_analyzer import MQTTAnalyzer, HAS_MQTT
except ImportError:
    HAS_MQTT = False

try:
    from .coap_analyzer import CoAPAnalyzer, HAS_COAP
except ImportError:
    HAS_COAP = False

try:
    from .modbus_analyzer import ModbusAnalyzer, HAS_MODBUS
except ImportError:
    HAS_MODBUS = False

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ProtocolAnalysisManager:
    """
    Unified manager for protocol-specific security analysis
    Supports MQTT, CoAP, Modbus, BACnet, DNP3
    """
    
    # Protocol to port mapping
    PROTOCOL_PORTS = {
        'mqtt': [1883, 8883],
        'coap': [5683, 5684],
        'modbus': [502],
        'bacnet': [47808],
        'dnp3': [20000],
        'http': [80, 8080, 8000],
        'https': [443, 8443]
    }
    
    def __init__(self):
        """Initialize protocol analysis manager"""
        self.results = {}
        self.available_analyzers = {
            'mqtt': HAS_MQTT,
            'coap': HAS_COAP,
            'modbus': HAS_MODBUS
        }
    
    def detect_protocol(self, port: int) -> Optional[str]:
        """
        Detect protocol based on port number
        
        Args:
            port: Port number
            
        Returns:
            Protocol name or None
        """
        for protocol, ports in self.PROTOCOL_PORTS.items():
            if port in ports:
                return protocol
        return None
    
    async def analyze_device(self, ip: str, ports: List[int]) -> Dict:
        """
        Analyze device for protocol-specific vulnerabilities
        
        Args:
            ip: Device IP address
            ports: List of open ports
            
        Returns:
            Analysis results for all detected protocols
        """
        logger.info(f"Starting protocol analysis for {ip}")
        
        device_analysis = {
            'ip': ip,
            'timestamp': datetime.now().isoformat(),
            'protocols_analyzed': [],
            'vulnerabilities': [],
            'overall_security_score': 100
        }
        
        # Analyze each port
        for port in ports:
            protocol = self.detect_protocol(port)
            
            if not protocol:
                continue
            
            if protocol not in self.available_analyzers:
                logger.warning(f"No analyzer available for {protocol}")
                continue
            
            if not self.available_analyzers[protocol]:
                logger.warning(f"{protocol.upper()} analyzer not installed")
                continue
            
            # Run protocol-specific analysis
            try:
                if protocol == 'mqtt':
                    result = await self._analyze_mqtt(ip, port)
                elif protocol == 'coap':
                    result = await self._analyze_coap(ip, port)
                elif protocol == 'modbus':
                    result = await self._analyze_modbus(ip, port)
                else:
                    continue
                
                device_analysis['protocols_analyzed'].append(result)
                device_analysis['vulnerabilities'].extend(result.get('vulnerabilities', []))
                
                # Update overall score (take minimum)
                protocol_score = result.get('security_score', 100)
                device_analysis['overall_security_score'] = min(
                    device_analysis['overall_security_score'],
                    protocol_score
                )
                
            except Exception as e:
                logger.error(f"Error analyzing {protocol} on {ip}:{port}: {e}")
        
        logger.info(f"Protocol analysis complete for {ip}. Score: {device_analysis['overall_security_score']}/100")
        
        return device_analysis
    
    async def _analyze_mqtt(self, ip: str, port: int) -> Dict:
        """Analyze MQTT broker"""
        logger.info(f"Analyzing MQTT at {ip}:{port}")
        
        analyzer = MQTTAnalyzer(ip, port)
        return await analyzer.comprehensive_analysis()
    
    async def _analyze_coap(self, ip: str, port: int) -> Dict:
        """Analyze CoAP server"""
        logger.info(f"Analyzing CoAP at {ip}:{port}")
        
        analyzer = CoAPAnalyzer(ip, port)
        return await analyzer.comprehensive_analysis()
    
    async def _analyze_modbus(self, ip: str, port: int) -> Dict:
        """Analyze Modbus server"""
        logger.info(f"Analyzing Modbus at {ip}:{port}")
        
        analyzer = ModbusAnalyzer(ip, port)
        return await analyzer.comprehensive_analysis()
    
    async def batch_analysis(self, devices: List[Dict]) -> List[Dict]:
        """
        Analyze multiple devices concurrently
        
        Args:
            devices: List of device dictionaries with 'ip' and 'open_ports'
            
        Returns:
            List of analysis results
        """
        logger.info(f"Starting batch protocol analysis for {len(devices)} devices")
        
        tasks = []
        for device in devices:
            ip = device.get('ip_address') or device.get('ip')
            ports = device.get('open_ports', [])
            
            if ip and ports:
                tasks.append(self.analyze_device(ip, ports))
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Filter out exceptions
        valid_results = []
        for result in results:
            if isinstance(result, dict):
                valid_results.append(result)
            else:
                logger.error(f"Analysis error: {result}")
        
        logger.info(f"Batch analysis complete. {len(valid_results)} devices analyzed")
        
        return valid_results
    
    def get_statistics(self, results: List[Dict]) -> Dict:
        """Generate statistics from analysis results"""
        stats = {
            'total_devices': len(results),
            'protocols_found': {},
            'total_vulnerabilities': 0,
            'critical_vulnerabilities': 0,
            'high_vulnerabilities': 0,
            'medium_vulnerabilities': 0,
            'low_vulnerabilities': 0,
            'average_security_score': 0
        }
        
        total_score = 0
        
        for result in results:
            # Count protocols
            for protocol_result in result.get('protocols_analyzed', []):
                protocol = protocol_result.get('protocol', 'Unknown')
                stats['protocols_found'][protocol] = stats['protocols_found'].get(protocol, 0) + 1
            
            # Count vulnerabilities
            for vuln in result.get('vulnerabilities', []):
                stats['total_vulnerabilities'] += 1
                severity = vuln.get('severity', '').lower()
                
                if severity == 'critical':
                    stats['critical_vulnerabilities'] += 1
                elif severity == 'high':
                    stats['high_vulnerabilities'] += 1
                elif severity == 'medium':
                    stats['medium_vulnerabilities'] += 1
                elif severity == 'low':
                    stats['low_vulnerabilities'] += 1
            
            # Sum scores
            total_score += result.get('overall_security_score', 0)
        
        if results:
            stats['average_security_score'] = total_score / len(results)
        
        return stats


# Example usage
async def main():
    """Test protocol analysis manager"""
    manager = ProtocolAnalysisManager()
    
    print("="*70)
    print("Protocol Analysis Manager - Phase 4")
    print("="*70)
    
    print(f"\nAvailable Analyzers:")
    for protocol, available in manager.available_analyzers.items():
        status = "✓ Available" if available else "✗ Not Installed"
        print(f"  {protocol.upper()}: {status}")
    
    # Test with sample devices
    test_devices = [
        {'ip': '192.168.1.100', 'open_ports': [1883, 80]},
        {'ip': '192.168.1.101', 'open_ports': [5683]},
        {'ip': '192.168.1.102', 'open_ports': [502]}
    ]
    
    print(f"\nAnalyzing {len(test_devices)} test devices...")
    results = await manager.batch_analysis(test_devices)
    
    stats = manager.get_statistics(results)
    
    print(f"\n{'='*70}")
    print("Analysis Results")
    print(f"{'='*70}")
    
    print(f"\nDevices Analyzed: {stats['total_devices']}")
    print(f"Protocols Found: {dict(stats['protocols_found'])}")
    print(f"Total Vulnerabilities: {stats['total_vulnerabilities']}")
    print(f"  Critical: {stats['critical_vulnerabilities']}")
    print(f"  High: {stats['high_vulnerabilities']}")
    print(f"  Medium: {stats['medium_vulnerabilities']}")
    print(f"  Low: {stats['low_vulnerabilities']}")
    print(f"Average Security Score: {stats['average_security_score']:.1f}/100")


if __name__ == '__main__':
    asyncio.run(main())
