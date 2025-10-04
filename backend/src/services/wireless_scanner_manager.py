"""
Wireless Scanner Manager - Phase 3
Unified manager for all wireless scanning capabilities:
- Bluetooth Low Energy (BLE)
- Classic Bluetooth
- Wi-Fi Networks
- Wi-Fi Direct
- Wireless fingerprinting
"""

import asyncio
import logging
from typing import List, Dict
from datetime import datetime

from .bluetooth_scanner import BluetoothScannerManager, HAS_BLEAK, HAS_PYBLUEZ
from .wifi_scanner import WiFiScanner
from .wireless_fingerprinting import WirelessFingerprinter

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class WirelessScannerManager:
    """
    Comprehensive wireless scanner for IoT devices
    Combines BLE, Bluetooth Classic, Wi-Fi, and fingerprinting
    """
    
    def __init__(self, scan_duration: int = 10):
        """
        Initialize wireless scanner manager
        
        Args:
            scan_duration: How long to scan in seconds
        """
        self.scan_duration = scan_duration
        
        # Initialize scanners
        self.bluetooth_scanner = None
        self.wifi_scanner = None
        self.fingerprinter = WirelessFingerprinter()
        
        # Initialize available scanners
        if HAS_BLEAK or HAS_PYBLUEZ:
            self.bluetooth_scanner = BluetoothScannerManager(scan_duration)
        
        self.wifi_scanner = WiFiScanner()
        
        self.all_devices = []
    
    async def scan_bluetooth(self) -> List[Dict]:
        """
        Scan for Bluetooth devices (BLE + Classic)
        
        Returns:
            List of discovered Bluetooth devices
        """
        if not self.bluetooth_scanner:
            logger.warning("Bluetooth scanning not available")
            return []
        
        logger.info("Starting Bluetooth scan...")
        try:
            devices = await self.bluetooth_scanner.scan_all()
            logger.info(f"Bluetooth scan found {len(devices)} devices")
            return devices
        except Exception as e:
            logger.error(f"Bluetooth scan error: {e}")
            return []
    
    async def scan_wifi(self) -> List[Dict]:
        """
        Scan for Wi-Fi networks
        
        Returns:
            List of discovered Wi-Fi networks
        """
        if not self.wifi_scanner:
            logger.warning("Wi-Fi scanning not available")
            return []
        
        logger.info("Starting Wi-Fi scan...")
        try:
            networks = await self.wifi_scanner.scan_networks()
            logger.info(f"Wi-Fi scan found {len(networks)} networks")
            return networks
        except Exception as e:
            logger.error(f"Wi-Fi scan error: {e}")
            return []
    
    def detect_wifi_direct(self) -> List[Dict]:
        """
        Detect Wi-Fi Direct devices
        
        Returns:
            List of Wi-Fi Direct devices
        """
        if not self.wifi_scanner or not self.wifi_scanner.discovered_networks:
            return []
        
        return self.wifi_scanner.detect_wifi_direct()
    
    async def comprehensive_scan(self, 
                                scan_bluetooth: bool = True,
                                scan_wifi: bool = True,
                                fingerprint: bool = True) -> List[Dict]:
        """
        Run comprehensive wireless scan
        
        Args:
            scan_bluetooth: Enable Bluetooth scanning
            scan_wifi: Enable Wi-Fi scanning
            fingerprint: Enable device fingerprinting
            
        Returns:
            Combined list of all discovered wireless devices
        """
        logger.info("="*60)
        logger.info("Starting Comprehensive Wireless Scan")
        logger.info("="*60)
        
        start_time = datetime.now()
        
        all_devices = []
        
        # Scan Bluetooth devices
        if scan_bluetooth:
            bluetooth_devices = await self.scan_bluetooth()
            all_devices.extend(bluetooth_devices)
        
        # Scan Wi-Fi networks
        if scan_wifi:
            wifi_networks = await self.scan_wifi()
            all_devices.extend(wifi_networks)
            
            # Detect Wi-Fi Direct
            wifi_direct_devices = self.detect_wifi_direct()
            all_devices.extend(wifi_direct_devices)
        
        # Fingerprint devices
        if fingerprint and all_devices:
            logger.info("Fingerprinting wireless devices...")
            fingerprinted_devices = []
            
            for device in all_devices:
                try:
                    fingerprinted = self.fingerprinter.fingerprint_device(device)
                    fingerprinted_devices.append(fingerprinted)
                except Exception as e:
                    logger.error(f"Fingerprinting error: {e}")
                    fingerprinted_devices.append(device)
            
            all_devices = fingerprinted_devices
        
        self.all_devices = all_devices
        
        # Calculate duration
        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()
        
        logger.info("="*60)
        logger.info(f"Wireless scan completed in {duration:.2f} seconds")
        logger.info(f"Total devices discovered: {len(all_devices)}")
        logger.info("="*60)
        
        return all_devices
    
    def get_statistics(self) -> Dict:
        """Get comprehensive wireless scanning statistics"""
        if not self.all_devices:
            return {}
        
        stats = {
            'total_devices': len(self.all_devices),
            'bluetooth_devices': 0,
            'ble_devices': 0,
            'classic_bluetooth_devices': 0,
            'wifi_networks': 0,
            'wifi_direct_devices': 0,
            'device_types': {},
            'manufacturers': {},
            'security_stats': {
                'high_risk': 0,
                'medium_risk': 0,
                'low_risk': 0,
                'unknown_risk': 0
            }
        }
        
        for device in self.all_devices:
            protocol = device.get('protocol', '').lower()
            
            # Count by protocol
            if 'bluetooth le' in protocol or 'ble' in protocol:
                stats['ble_devices'] += 1
                stats['bluetooth_devices'] += 1
            elif 'bluetooth' in protocol:
                stats['classic_bluetooth_devices'] += 1
                stats['bluetooth_devices'] += 1
            elif 'wi-fi direct' in protocol:
                stats['wifi_direct_devices'] += 1
            elif 'wi-fi' in protocol:
                stats['wifi_networks'] += 1
            
            # Count device types
            device_type = device.get('device_type', 'unknown')
            stats['device_types'][device_type] = stats['device_types'].get(device_type, 0) + 1
            
            # Count manufacturers
            manufacturer = device.get('manufacturer', 'Unknown')
            stats['manufacturers'][manufacturer] = stats['manufacturers'].get(manufacturer, 0) + 1
            
            # Security stats
            risk_level = device.get('security_posture', {}).get('risk_level', 'unknown')
            if risk_level.lower() == 'high':
                stats['security_stats']['high_risk'] += 1
            elif risk_level.lower() == 'medium':
                stats['security_stats']['medium_risk'] += 1
            elif risk_level.lower() == 'low':
                stats['security_stats']['low_risk'] += 1
            else:
                stats['security_stats']['unknown_risk'] += 1
        
        # Add Bluetooth statistics if available
        if self.bluetooth_scanner:
            bt_stats = self.bluetooth_scanner.get_statistics()
            stats['bluetooth_scanner_stats'] = bt_stats
        
        # Add Wi-Fi statistics if available
        if self.wifi_scanner:
            wifi_stats = self.wifi_scanner.get_statistics()
            stats['wifi_scanner_stats'] = wifi_stats
        
        return stats
    
    def generate_security_report(self) -> Dict:
        """Generate comprehensive security report"""
        if not self.all_devices:
            return {}
        
        return self.fingerprinter.generate_report(self.all_devices)
    
    def get_high_risk_devices(self) -> List[Dict]:
        """Get list of high-risk devices"""
        high_risk = []
        
        for device in self.all_devices:
            risk_level = device.get('security_posture', {}).get('risk_level', '')
            if risk_level.lower() == 'high':
                high_risk.append(device)
        
        return high_risk
    
    def get_devices_by_type(self, device_type: str) -> List[Dict]:
        """Get devices filtered by type"""
        return [
            device for device in self.all_devices
            if device.get('device_type', '').lower() == device_type.lower()
        ]
    
    def get_devices_by_manufacturer(self, manufacturer: str) -> List[Dict]:
        """Get devices filtered by manufacturer"""
        return [
            device for device in self.all_devices
            if device.get('manufacturer', '').lower() == manufacturer.lower()
        ]


# Example usage and testing
async def main():
    """Test comprehensive wireless scanning"""
    print("="*70)
    print("Comprehensive Wireless Scanner - Phase 3")
    print("="*70)
    
    scanner = WirelessScannerManager(scan_duration=10)
    
    print("\nStarting comprehensive wireless scan...")
    print("This will scan for:")
    print("  - Bluetooth Low Energy (BLE) devices")
    print("  - Classic Bluetooth devices")
    print("  - Wi-Fi networks")
    print("  - Wi-Fi Direct devices")
    print("  - Device fingerprinting and security analysis")
    print("\n" + "-"*70)
    
    devices = await scanner.comprehensive_scan(
        scan_bluetooth=True,
        scan_wifi=True,
        fingerprint=True
    )
    
    stats = scanner.get_statistics()
    
    print(f"\n{'='*70}")
    print("SCAN RESULTS")
    print(f"{'='*70}")
    
    print(f"\n📊 Statistics:")
    print(f"  Total Devices: {stats['total_devices']}")
    print(f"  Bluetooth Devices: {stats['bluetooth_devices']}")
    print(f"    - BLE: {stats['ble_devices']}")
    print(f"    - Classic: {stats['classic_bluetooth_devices']}")
    print(f"  Wi-Fi Networks: {stats['wifi_networks']}")
    print(f"  Wi-Fi Direct: {stats['wifi_direct_devices']}")
    
    print(f"\n🔐 Security Assessment:")
    print(f"  High Risk: {stats['security_stats']['high_risk']}")
    print(f"  Medium Risk: {stats['security_stats']['medium_risk']}")
    print(f"  Low Risk: {stats['security_stats']['low_risk']}")
    
    print(f"\n📱 Device Types:")
    for dtype, count in sorted(stats['device_types'].items(), 
                               key=lambda x: x[1], reverse=True)[:10]:
        print(f"  {dtype}: {count}")
    
    print(f"\n🏢 Manufacturers:")
    for mfr, count in sorted(stats['manufacturers'].items(), 
                            key=lambda x: x[1], reverse=True)[:10]:
        print(f"  {mfr}: {count}")
    
    # Show sample devices
    print(f"\n{'='*70}")
    print("Sample Discovered Devices")
    print(f"{'='*70}")
    
    for i, device in enumerate(devices[:10], 1):
        name = device.get('name') or device.get('ssid') or 'Unknown'
        print(f"\n{i}. {name}")
        print(f"   Type: {device.get('device_type', 'Unknown')}")
        print(f"   Protocol: {device.get('protocol', 'Unknown')}")
        print(f"   Manufacturer: {device.get('manufacturer', 'Unknown')}")
        
        if device.get('address'):
            print(f"   Address: {device['address']}")
        if device.get('bssid'):
            print(f"   BSSID: {device['bssid']}")
        
        if device.get('security_posture'):
            posture = device['security_posture']
            print(f"   Risk Level: {posture.get('risk_level', 'Unknown')}")
            if posture.get('concerns'):
                print(f"   Concerns: {', '.join(posture['concerns'][:2])}")
    
    if len(devices) > 10:
        print(f"\n... and {len(devices) - 10} more devices")
    
    # Security report
    security_report = scanner.generate_security_report()
    
    if security_report.get('recommendations'):
        print(f"\n{'='*70}")
        print("🛡️  Security Recommendations")
        print(f"{'='*70}")
        for rec in security_report['recommendations']:
            print(f"  • {rec}")
    
    # High-risk devices
    high_risk_devices = scanner.get_high_risk_devices()
    if high_risk_devices:
        print(f"\n{'='*70}")
        print(f"⚠️  High-Risk Devices ({len(high_risk_devices)})")
        print(f"{'='*70}")
        for device in high_risk_devices[:5]:
            name = device.get('name') or device.get('ssid') or 'Unknown'
            print(f"  • {name}")
            concerns = device.get('security_posture', {}).get('concerns', [])
            if concerns:
                print(f"    Issues: {', '.join(concerns[:2])}")


if __name__ == '__main__':
    asyncio.run(main())
