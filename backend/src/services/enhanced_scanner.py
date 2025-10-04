"""
Enhanced Device Scanner - Phase 2
Combines passive discovery, mDNS/SSDP, and advanced fingerprinting
"""

import asyncio
import logging
from concurrent.futures import ThreadPoolExecutor
from typing import List, Dict
from datetime import datetime
import threading

from .passive_discovery import PassiveDiscoveryAsync
from .service_discovery import ServiceDiscoveryManager
from .device_fingerprinting import DeviceFingerprinter, ProtocolRecognizer
from .device_scanner import DeviceScanner  # Original scanner

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class EnhancedScanner:
    """
    Enhanced IoT device scanner with multiple discovery methods
    Optimized for performance using async/await and thread pools
    """
    
    def __init__(self, network_range: str = None):
        """
        Initialize enhanced scanner
        
        Args:
            network_range: Network range to scan (e.g., "192.168.1.0/24")
        """
        self.network_range = network_range
        self.passive_scanner = PassiveDiscoveryAsync(timeout=30)
        self.service_discovery = ServiceDiscoveryManager()
        self.fingerprinter = DeviceFingerprinter()
        self.protocol_recognizer = ProtocolRecognizer()
        self.active_scanner = DeviceScanner()  # Fallback to original
        
        self.executor = ThreadPoolExecutor(max_workers=10)
        self.discovered_devices = {}
        
    async def passive_scan(self) -> List[Dict]:
        """Run passive network traffic analysis"""
        logger.info("Starting passive discovery...")
        try:
            devices = await self.passive_scanner.start_discovery()
            logger.info(f"Passive discovery found {len(devices)} devices")
            return devices
        except Exception as e:
            logger.error(f"Passive scan error: {e}")
            return []
    
    async def service_scan(self) -> List[Dict]:
        """Run mDNS and SSDP service discovery"""
        logger.info("Starting service discovery (mDNS/SSDP)...")
        try:
            devices = await self.service_discovery.discover_all(timeout=15)
            logger.info(f"Service discovery found {len(devices)} devices")
            return devices
        except Exception as e:
            logger.error(f"Service scan error: {e}")
            return []
    
    async def active_scan(self) -> List[Dict]:
        """Run active nmap-based scanning (fallback)"""
        logger.info("Starting active scan...")
        try:
            loop = asyncio.get_event_loop()
            # Run blocking nmap scan in thread pool
            devices = await loop.run_in_executor(
                self.executor,
                self.active_scanner.scan_network,
                self.network_range
            )
            logger.info(f"Active scan found {len(devices)} devices")
            return devices
        except Exception as e:
            logger.error(f"Active scan error: {e}")
            return []
    
    def _merge_device_info(self, devices_list: List[List[Dict]]) -> Dict[str, Dict]:
        """
        Merge device information from multiple sources
        
        Args:
            devices_list: List of device lists from different scanners
            
        Returns:
            Dictionary mapping IP to merged device info
        """
        merged = {}
        
        for devices in devices_list:
            for device in devices:
                ip = device.get('ip_address')
                if not ip:
                    continue
                
                if ip not in merged:
                    merged[ip] = {
                        'ip_address': ip,
                        'mac_address': None,
                        'hostname': None,
                        'manufacturer': None,
                        'device_type': 'unknown',
                        'open_ports': [],
                        'services': [],
                        'protocols': [],
                        'discovery_methods': [],
                        'confidence': 0.0,
                        'first_discovered': datetime.now().isoformat(),
                        'last_seen': datetime.now().isoformat()
                    }
                
                # Merge data
                existing = merged[ip]
                
                # Update basic info (prefer non-None values)
                if device.get('mac_address') and not existing['mac_address']:
                    existing['mac_address'] = device['mac_address']
                
                if device.get('hostname') and not existing['hostname']:
                    existing['hostname'] = device['hostname']
                
                if device.get('manufacturer') and not existing['manufacturer']:
                    existing['manufacturer'] = device['manufacturer']
                
                # Merge ports (union)
                if device.get('open_ports'):
                    existing['open_ports'] = list(set(
                        existing['open_ports'] + device['open_ports']
                    ))
                
                # Merge services
                if device.get('services'):
                    existing['services'].extend(device['services'])
                
                # Merge protocols
                if device.get('protocols'):
                    protocols = device['protocols']
                    if isinstance(protocols, (list, set)):
                        existing['protocols'] = list(set(
                            existing['protocols'] + list(protocols)
                        ))
                
                # Track discovery method
                method = device.get('discovery_method', 'unknown')
                if method not in existing['discovery_methods']:
                    existing['discovery_methods'].append(method)
                
                # Update last seen
                existing['last_seen'] = datetime.now().isoformat()
        
        return merged
    
    async def _enrich_with_protocols(self, devices: Dict[str, Dict]):
        """Recognize protocols on open ports"""
        logger.info("Recognizing protocols on open ports...")
        
        tasks = []
        for ip, device in devices.items():
            for port in device.get('open_ports', [])[:10]:  # Limit to first 10 ports
                tasks.append(self._recognize_port_protocol(ip, port, device))
        
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
    
    async def _recognize_port_protocol(self, ip: str, port: int, device: Dict):
        """Recognize protocol for a specific port"""
        try:
            protocol = await self.protocol_recognizer.recognize_protocol(ip, port)
            if protocol:
                if protocol not in device['protocols']:
                    device['protocols'].append(protocol)
                    logger.debug(f"{ip}:{port} -> {protocol}")
        except Exception as e:
            logger.debug(f"Protocol recognition failed for {ip}:{port}: {e}")
    
    async def comprehensive_scan(self, use_passive=True, use_service=True, 
                                use_active=True, fingerprint=True) -> List[Dict]:
        """
        Run comprehensive scan with all methods
        
        Args:
            use_passive: Enable passive traffic analysis
            use_service: Enable mDNS/SSDP discovery
            use_active: Enable active nmap scanning
            fingerprint: Enable device fingerprinting
            
        Returns:
            List of discovered and enriched devices
        """
        logger.info("="*60)
        logger.info("Starting Enhanced Comprehensive Scan")
        logger.info("="*60)
        
        start_time = datetime.now()
        
        # Run discovery methods concurrently
        scan_tasks = []
        
        if use_passive:
            scan_tasks.append(('passive', self.passive_scan()))
        
        if use_service:
            scan_tasks.append(('service', self.service_scan()))
        
        if use_active and self.network_range:
            scan_tasks.append(('active', self.active_scan()))
        
        # Execute all scans concurrently
        scan_results = []
        if scan_tasks:
            task_names, tasks = zip(*scan_tasks)
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for name, result in zip(task_names, results):
                if isinstance(result, list):
                    scan_results.append(result)
                    logger.info(f"{name.capitalize()} scan completed")
                else:
                    logger.error(f"{name.capitalize()} scan failed: {result}")
        
        # Merge all discovered devices
        logger.info("Merging discovery results...")
        merged_devices = self._merge_device_info(scan_results)
        
        # Enrich with protocol recognition
        if merged_devices:
            await self._enrich_with_protocols(merged_devices)
        
        # Fingerprint devices
        if fingerprint and merged_devices:
            logger.info("Fingerprinting devices...")
            devices_list = list(merged_devices.values())
            fingerprinted = await self.fingerprinter.fingerprint_devices_batch(devices_list)
            
            # Update merged devices with fingerprint data
            for device in fingerprinted:
                ip = device['ip_address']
                if ip in merged_devices:
                    merged_devices[ip].update(device)
        
        # Convert to list
        final_devices = list(merged_devices.values())
        
        # Sort by IP address
        final_devices.sort(key=lambda d: d['ip_address'])
        
        # Calculate statistics
        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()
        
        logger.info("="*60)
        logger.info(f"Scan completed in {duration:.2f} seconds")
        logger.info(f"Total devices discovered: {len(final_devices)}")
        logger.info("="*60)
        
        self.discovered_devices = merged_devices
        return final_devices
    
    def get_statistics(self) -> Dict:
        """Get scan statistics"""
        if not self.discovered_devices:
            return {}
        
        devices = list(self.discovered_devices.values())
        
        # Count by device type
        device_types = {}
        for device in devices:
            dtype = device.get('device_type', 'unknown')
            device_types[dtype] = device_types.get(dtype, 0) + 1
        
        # Count by discovery method
        discovery_methods = {}
        for device in devices:
            for method in device.get('discovery_methods', []):
                discovery_methods[method] = discovery_methods.get(method, 0) + 1
        
        # Calculate average confidence
        confidences = [d.get('confidence', 0) for d in devices]
        avg_confidence = sum(confidences) / len(confidences) if confidences else 0
        
        return {
            'total_devices': len(devices),
            'device_types': device_types,
            'discovery_methods': discovery_methods,
            'average_confidence': avg_confidence,
            'unique_manufacturers': len(set(d.get('manufacturer', 'unknown') 
                                           for d in devices)),
            'total_ports': sum(len(d.get('open_ports', [])) for d in devices),
            'total_services': sum(len(d.get('services', [])) for d in devices)
        }
    
    def cleanup(self):
        """Cleanup resources"""
        logger.info("Cleaning up enhanced scanner resources...")
        self.passive_scanner.stop_discovery()
        self.executor.shutdown(wait=False)


# Example usage and testing
async def main():
    """Test enhanced scanner"""
    scanner = EnhancedScanner(network_range="192.168.1.0/24")
    
    print("Starting enhanced comprehensive scan...")
    print("This will use passive, mDNS/SSDP, and active methods")
    print("-" * 60)
    
    devices = await scanner.comprehensive_scan(
        use_passive=True,
        use_service=True,
        use_active=True,
        fingerprint=True
    )
    
    stats = scanner.get_statistics()
    
    print("\n" + "="*60)
    print("SCAN RESULTS")
    print("="*60)
    
    print(f"\nStatistics:")
    print(f"  Total Devices: {stats['total_devices']}")
    print(f"  Unique Manufacturers: {stats['unique_manufacturers']}")
    print(f"  Total Open Ports: {stats['total_ports']}")
    print(f"  Total Services: {stats['total_services']}")
    print(f"  Average Confidence: {stats['average_confidence']:.2%}")
    
    print(f"\nDevice Types:")
    for dtype, count in stats['device_types'].items():
        print(f"  {dtype}: {count}")
    
    print(f"\nDiscovery Methods:")
    for method, count in stats['discovery_methods'].items():
        print(f"  {method}: {count}")
    
    print(f"\n\nDiscovered Devices:")
    print("-" * 60)
    
    for device in devices[:10]:  # Show first 10
        print(f"\n{device['ip_address']}")
        print(f"  MAC: {device.get('mac_address', 'Unknown')}")
        print(f"  Hostname: {device.get('hostname', 'Unknown')}")
        print(f"  Type: {device.get('device_type', 'Unknown')}")
        print(f"  Manufacturer: {device.get('manufacturer', 'Unknown')}")
        print(f"  Confidence: {device.get('confidence', 0):.2%}")
        print(f"  Methods: {', '.join(device.get('discovery_methods', []))}")
        print(f"  Ports: {device.get('open_ports', [])[:10]}")
        print(f"  Protocols: {device.get('protocols', [])}")
    
    if len(devices) > 10:
        print(f"\n... and {len(devices) - 10} more devices")
    
    scanner.cleanup()


if __name__ == '__main__':
    asyncio.run(main())
