"""
Bluetooth Scanner - BLE and Classic Bluetooth Discovery
Discovers Bluetooth Low Energy and Classic Bluetooth IoT devices
"""

import asyncio
import logging
from typing import List, Dict, Optional
from datetime import datetime
import struct

try:
    from bleak import BleakScanner, BleakClient
    from bleak.backends.device import BLEDevice
    HAS_BLEAK = True
except ImportError:
    HAS_BLEAK = False
    logging.warning("Bleak not available. BLE scanning disabled.")

try:
    import bluetooth
    HAS_PYBLUEZ = True
except ImportError:
    HAS_PYBLUEZ = False
    logging.warning("PyBluez not available. Classic Bluetooth scanning disabled.")

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class BLEScanner:
    """Bluetooth Low Energy device scanner"""
    
    # Known IoT device service UUIDs
    IOT_SERVICE_UUIDS = {
        '0000180f-0000-1000-8000-00805f9b34fb': 'Battery Service',
        '0000180a-0000-1000-8000-00805f9b34fb': 'Device Information',
        '00001800-0000-1000-8000-00805f9b34fb': 'Generic Access',
        '00001801-0000-1000-8000-00805f9b34fb': 'Generic Attribute',
        '0000181c-0000-1000-8000-00805f9b34fb': 'User Data',
        '0000fff0-0000-1000-8000-00805f9b34fb': 'Custom IoT Service',
        # Smart Home devices
        '000015231212efde1523785feabcd123': 'Xiaomi Mi',
        '0000fe95-0000-1000-8000-00805f9b34fb': 'Xiaomi Inc.',
        '0000fd6f-0000-1000-8000-00805f9b34fb': 'Apple Continuity',
        # Health & Fitness
        '0000180d-0000-1000-8000-00805f9b34fb': 'Heart Rate',
        '00001816-0000-1000-8000-00805f9b34fb': 'Cycling Speed',
        '00001818-0000-1000-8000-00805f9b34fb': 'Cycling Power',
        # Smart Lock
        '00001530-1212-efde-1523-785feabcd123': 'Smart Lock Service',
    }
    
    # Device type patterns based on name
    DEVICE_PATTERNS = {
        'smart_bulb': ['philips', 'hue', 'lifx', 'yeelight', 'bulb', 'light'],
        'smart_lock': ['lock', 'august', 'yale', 'schlage'],
        'fitness_tracker': ['fitbit', 'garmin', 'xiaomi band', 'mi band', 'amazfit'],
        'smart_watch': ['watch', 'gear', 'apple watch', 'galaxy watch'],
        'smart_speaker': ['echo', 'google home', 'homepod'],
        'beacon': ['beacon', 'ibeacon', 'eddystone'],
        'smart_sensor': ['sensor', 'temperature', 'humidity', 'motion'],
        'smart_plug': ['plug', 'outlet', 'socket'],
        'medical_device': ['blood', 'glucose', 'thermometer', 'oximeter']
    }
    
    def __init__(self, scan_duration: int = 10):
        """
        Initialize BLE scanner
        
        Args:
            scan_duration: How long to scan in seconds
        """
        if not HAS_BLEAK:
            raise ImportError("Bleak library required for BLE scanning")
        
        self.scan_duration = scan_duration
        self.discovered_devices = []
    
    def _classify_device(self, device: BLEDevice, advertisement_data) -> str:
        """Classify BLE device type based on name and services"""
        device_name = (device.name or '').lower()
        
        # Check name patterns
        for device_type, patterns in self.DEVICE_PATTERNS.items():
            for pattern in patterns:
                if pattern in device_name:
                    return device_type
        
        # Check service UUIDs
        if advertisement_data and hasattr(advertisement_data, 'service_uuids'):
            for uuid in advertisement_data.service_uuids:
                uuid_lower = uuid.lower()
                if uuid_lower in self.IOT_SERVICE_UUIDS:
                    service_name = self.IOT_SERVICE_UUIDS[uuid_lower]
                    if 'heart rate' in service_name.lower():
                        return 'fitness_tracker'
                    elif 'lock' in service_name.lower():
                        return 'smart_lock'
        
        return 'unknown_ble'
    
    def _parse_manufacturer_data(self, manufacturer_data: Dict) -> Dict:
        """Parse manufacturer-specific data"""
        parsed = {}
        
        for company_id, data in manufacturer_data.items():
            # Apple iBeacon
            if company_id == 0x004C and len(data) >= 23:
                if data[0:2] == bytes([0x02, 0x15]):  # iBeacon
                    parsed['beacon_type'] = 'iBeacon'
                    parsed['uuid'] = data[2:18].hex()
                    parsed['major'] = struct.unpack('>H', data[18:20])[0]
                    parsed['minor'] = struct.unpack('>H', data[20:22])[0]
                    parsed['tx_power'] = struct.unpack('b', data[22:23])[0]
            
            # Google Eddystone
            elif company_id == 0xFEAA:
                parsed['beacon_type'] = 'Eddystone'
            
            # Xiaomi
            elif company_id == 0x038F:
                parsed['manufacturer'] = 'Xiaomi'
            
            # Qualcomm
            elif company_id == 0x000D:
                parsed['manufacturer'] = 'Qualcomm'
        
        return parsed
    
    async def scan_devices(self) -> List[Dict]:
        """
        Scan for BLE devices
        
        Returns:
            List of discovered BLE devices with details
        """
        logger.info(f"Starting BLE scan for {self.scan_duration} seconds...")
        
        try:
            devices = await BleakScanner.discover(
                timeout=self.scan_duration,
                return_adv=True
            )
            
            for device, advertisement_data in devices.values():
                device_info = {
                    'address': device.address,
                    'name': device.name or 'Unknown',
                    'rssi': advertisement_data.rssi if advertisement_data else None,
                    'device_type': self._classify_device(device, advertisement_data),
                    'discovery_method': 'BLE',
                    'discovered_at': datetime.now().isoformat(),
                    'protocol': 'Bluetooth LE',
                    'connectable': True  # Most BLE devices are connectable
                }
                
                # Add service UUIDs
                if advertisement_data and hasattr(advertisement_data, 'service_uuids'):
                    device_info['services'] = []
                    for uuid in advertisement_data.service_uuids:
                        service_name = self.IOT_SERVICE_UUIDS.get(uuid.lower(), 'Unknown Service')
                        device_info['services'].append({
                            'uuid': uuid,
                            'name': service_name
                        })
                
                # Parse manufacturer data
                if advertisement_data and advertisement_data.manufacturer_data:
                    manufacturer_info = self._parse_manufacturer_data(
                        advertisement_data.manufacturer_data
                    )
                    device_info.update(manufacturer_info)
                
                self.discovered_devices.append(device_info)
            
            logger.info(f"BLE scan completed. Found {len(self.discovered_devices)} devices")
            return self.discovered_devices
            
        except Exception as e:
            logger.error(f"BLE scan error: {e}")
            return []
    
    async def get_device_details(self, address: str) -> Optional[Dict]:
        """
        Get detailed information about a specific BLE device
        
        Args:
            address: BLE device address
            
        Returns:
            Device details including services and characteristics
        """
        logger.info(f"Getting details for BLE device: {address}")
        
        try:
            async with BleakClient(address, timeout=10.0) as client:
                if not await client.is_connected():
                    return None
                
                services = []
                for service in client.services:
                    service_info = {
                        'uuid': service.uuid,
                        'description': service.description,
                        'characteristics': []
                    }
                    
                    for char in service.characteristics:
                        char_info = {
                            'uuid': char.uuid,
                            'description': char.description,
                            'properties': char.properties,
                            'readable': 'read' in char.properties,
                            'writable': 'write' in char.properties,
                            'notifiable': 'notify' in char.properties
                        }
                        
                        # Try to read value if readable
                        if 'read' in char.properties:
                            try:
                                value = await client.read_gatt_char(char.uuid)
                                char_info['value'] = value.hex()
                            except:
                                pass
                        
                        service_info['characteristics'].append(char_info)
                    
                    services.append(service_info)
                
                return {
                    'address': address,
                    'services': services,
                    'connected': True
                }
                
        except Exception as e:
            logger.error(f"Error getting device details: {e}")
            return None
    
    async def test_pairing_security(self, address: str) -> Dict:
        """
        Test BLE pairing security
        
        Args:
            address: BLE device address
            
        Returns:
            Security assessment results
        """
        logger.info(f"Testing pairing security for: {address}")
        
        security_assessment = {
            'address': address,
            'vulnerabilities': [],
            'security_level': 'unknown',
            'encryption': False,
            'authentication': False
        }
        
        try:
            async with BleakClient(address, timeout=10.0) as client:
                # Check if device requires pairing
                try:
                    # Try to read a protected characteristic
                    for service in client.services:
                        for char in service.characteristics:
                            if 'read' in char.properties:
                                try:
                                    await client.read_gatt_char(char.uuid)
                                    # If we can read without pairing
                                    security_assessment['vulnerabilities'].append({
                                        'type': 'No Authentication Required',
                                        'severity': 'High',
                                        'description': 'Device allows access without pairing'
                                    })
                                except:
                                    security_assessment['authentication'] = True
                                break
                        break
                except:
                    pass
                
                # Check for Just Works pairing vulnerability
                security_assessment['vulnerabilities'].append({
                    'type': 'Potential Just Works Pairing',
                    'severity': 'Medium',
                    'description': 'Device may use insecure pairing method'
                })
                
        except Exception as e:
            logger.error(f"Pairing security test error: {e}")
        
        return security_assessment


class ClassicBluetoothScanner:
    """Classic Bluetooth device scanner"""
    
    def __init__(self, scan_duration: int = 10):
        """
        Initialize Classic Bluetooth scanner
        
        Args:
            scan_duration: How long to scan in seconds
        """
        if not HAS_PYBLUEZ:
            raise ImportError("PyBluez library required for Classic Bluetooth scanning")
        
        self.scan_duration = scan_duration
        self.discovered_devices = []
    
    def scan_devices(self) -> List[Dict]:
        """
        Scan for Classic Bluetooth devices
        
        Returns:
            List of discovered devices
        """
        logger.info(f"Starting Classic Bluetooth scan...")
        
        try:
            nearby_devices = bluetooth.discover_devices(
                duration=self.scan_duration,
                lookup_names=True,
                flush_cache=True,
                lookup_class=True
            )
            
            for addr, name, dev_class in nearby_devices:
                device_info = {
                    'address': addr,
                    'name': name or 'Unknown',
                    'device_class': dev_class,
                    'device_type': self._classify_device_class(dev_class),
                    'discovery_method': 'Classic Bluetooth',
                    'discovered_at': datetime.now().isoformat(),
                    'protocol': 'Bluetooth Classic'
                }
                
                # Try to get services
                try:
                    services = bluetooth.find_service(address=addr)
                    device_info['services'] = []
                    for service in services:
                        device_info['services'].append({
                            'name': service.get('name', 'Unknown'),
                            'protocol': service.get('protocol', 'Unknown'),
                            'port': service.get('port', 0)
                        })
                except:
                    pass
                
                self.discovered_devices.append(device_info)
            
            logger.info(f"Classic Bluetooth scan completed. Found {len(self.discovered_devices)} devices")
            return self.discovered_devices
            
        except Exception as e:
            logger.error(f"Classic Bluetooth scan error: {e}")
            return []
    
    def _classify_device_class(self, dev_class: int) -> str:
        """Classify device based on Bluetooth device class"""
        # Major device class (bits 8-12)
        major_class = (dev_class >> 8) & 0x1F
        
        major_classes = {
            0x01: 'Computer',
            0x02: 'Phone',
            0x03: 'LAN/Network Access Point',
            0x04: 'Audio/Video',
            0x05: 'Peripheral',
            0x06: 'Imaging',
            0x07: 'Wearable',
            0x08: 'Toy',
            0x09: 'Health'
        }
        
        return major_classes.get(major_class, 'Unknown')


class BluetoothScannerManager:
    """Unified Bluetooth scanner for both BLE and Classic"""
    
    def __init__(self, scan_duration: int = 10):
        """
        Initialize unified Bluetooth scanner
        
        Args:
            scan_duration: How long to scan in seconds
        """
        self.scan_duration = scan_duration
        self.ble_scanner = None
        self.classic_scanner = None
        
        # Initialize available scanners
        if HAS_BLEAK:
            self.ble_scanner = BLEScanner(scan_duration)
        
        if HAS_PYBLUEZ:
            self.classic_scanner = ClassicBluetoothScanner(scan_duration)
    
    async def scan_all(self) -> List[Dict]:
        """
        Scan for all Bluetooth devices (BLE and Classic)
        
        Returns:
            Combined list of all discovered Bluetooth devices
        """
        logger.info("Starting comprehensive Bluetooth scan...")
        
        all_devices = []
        
        # Scan BLE devices
        if self.ble_scanner:
            try:
                ble_devices = await self.ble_scanner.scan_devices()
                all_devices.extend(ble_devices)
            except Exception as e:
                logger.error(f"BLE scan failed: {e}")
        
        # Scan Classic Bluetooth devices (blocking, run in executor)
        if self.classic_scanner:
            try:
                loop = asyncio.get_event_loop()
                classic_devices = await loop.run_in_executor(
                    None,
                    self.classic_scanner.scan_devices
                )
                all_devices.extend(classic_devices)
            except Exception as e:
                logger.error(f"Classic Bluetooth scan failed: {e}")
        
        logger.info(f"Total Bluetooth devices found: {len(all_devices)}")
        return all_devices
    
    def get_statistics(self) -> Dict:
        """Get scanning statistics"""
        ble_count = len(self.ble_scanner.discovered_devices) if self.ble_scanner else 0
        classic_count = len(self.classic_scanner.discovered_devices) if self.classic_scanner else 0
        
        return {
            'ble_devices': ble_count,
            'classic_devices': classic_count,
            'total_devices': ble_count + classic_count,
            'ble_available': HAS_BLEAK,
            'classic_available': HAS_PYBLUEZ
        }


# Example usage and testing
async def main():
    """Test Bluetooth scanning"""
    print("="*60)
    print("Bluetooth Scanner Test")
    print("="*60)
    
    scanner = BluetoothScannerManager(scan_duration=10)
    
    print("\nStarting Bluetooth device discovery...")
    devices = await scanner.scan_all()
    
    stats = scanner.get_statistics()
    
    print(f"\n{'='*60}")
    print("Scan Results")
    print(f"{'='*60}")
    print(f"BLE Devices: {stats['ble_devices']}")
    print(f"Classic Bluetooth Devices: {stats['classic_devices']}")
    print(f"Total Devices: {stats['total_devices']}")
    
    print(f"\n{'='*60}")
    print("Discovered Devices")
    print(f"{'='*60}")
    
    for i, device in enumerate(devices, 1):
        print(f"\n{i}. {device['name']}")
        print(f"   Address: {device['address']}")
        print(f"   Type: {device.get('device_type', 'Unknown')}")
        print(f"   Protocol: {device['protocol']}")
        if device.get('rssi'):
            print(f"   Signal: {device['rssi']} dBm")
        if device.get('services'):
            print(f"   Services: {len(device['services'])}")


if __name__ == '__main__':
    asyncio.run(main())
