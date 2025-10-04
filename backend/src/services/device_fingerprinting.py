"""
Advanced Device Fingerprinting Service
Uses multiple techniques to accurately identify IoT devices
"""

import asyncio
import logging
import re
from mac_vendor_lookup import MacLookup
import aiohttp
from typing import Dict, List, Optional
import socket
import struct

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class DeviceFingerprinter:
    """Advanced device fingerprinting using multiple techniques"""
    
    # Device patterns based on various indicators
    DEVICE_PATTERNS = {
        'smart_tv': {
            'ports': [8008, 8009, 9080],  # Google Cast, Smart TV ports
            'services': ['_googlecast._tcp', '_airplay._tcp'],
            'manufacturers': ['samsung', 'lg', 'sony', 'vizio'],
            'keywords': ['tv', 'television', 'cast', 'roku']
        },
        'smart_speaker': {
            'ports': [8008, 8009, 55443],
            'services': ['_googlecast._tcp', '_spotify-connect._tcp'],
            'manufacturers': ['amazon', 'google'],
            'keywords': ['echo', 'alexa', 'home', 'mini', 'nest']
        },
        'ip_camera': {
            'ports': [80, 443, 554, 8000, 8080],  # HTTP, RTSP, common camera ports
            'services': ['_axis-video._tcp', '_rtsp._tcp'],
            'manufacturers': ['axis', 'hikvision', 'dahua', 'nest'],
            'keywords': ['camera', 'ipcam', 'webcam', 'surveillance']
        },
        'smart_light': {
            'ports': [80, 443, 38899],  # Philips Hue bridge
            'services': ['_hue._tcp'],
            'manufacturers': ['philips', 'lifx', 'tp-link'],
            'keywords': ['hue', 'light', 'bulb', 'lifx']
        },
        'smart_plug': {
            'ports': [9999, 80],
            'manufacturers': ['tp-link', 'wemo', 'belkin'],
            'keywords': ['plug', 'switch', 'outlet', 'wemo']
        },
        'thermostat': {
            'ports': [80, 443],
            'manufacturers': ['nest', 'honeywell', 'ecobee'],
            'keywords': ['thermostat', 'nest', 'ecobee']
        },
        'router': {
            'ports': [80, 443, 8080, 22, 23],
            'services': ['_router._tcp'],
            'manufacturers': ['cisco', 'netgear', 'asus', 'tp-link', 'linksys'],
            'keywords': ['router', 'gateway', 'ap', 'access point']
        },
        'printer': {
            'ports': [515, 631, 9100],  # LPD, IPP, HP JetDirect
            'services': ['_ipp._tcp', '_printer._tcp', '_pdl-datastream._tcp'],
            'manufacturers': ['hp', 'canon', 'epson', 'brother'],
            'keywords': ['printer', 'print', 'scanner']
        },
        'nas': {
            'ports': [139, 445, 548, 5000, 5001],  # SMB, AFP, Synology
            'services': ['_smb._tcp', '_afpovertcp._tcp'],
            'manufacturers': ['synology', 'qnap', 'netgear', 'western digital'],
            'keywords': ['nas', 'storage', 'diskstation']
        },
        'iot_hub': {
            'ports': [80, 443, 1883, 8883],  # HTTP, MQTT
            'services': ['_mqtt._tcp', '_homekit._tcp', '_matter._tcp'],
            'manufacturers': ['samsung', 'amazon', 'google', 'apple'],
            'keywords': ['hub', 'bridge', 'gateway', 'smartthings', 'homekit']
        }
    }
    
    def __init__(self):
        self.mac_lookup = MacLookup()
        self.mac_lookup.update_vendors()  # Update vendor database
    
    def _get_manufacturer_from_mac(self, mac_address: str) -> Optional[str]:
        """Look up manufacturer from MAC address"""
        if not mac_address:
            return None
        
        try:
            manufacturer = self.mac_lookup.lookup(mac_address)
            return manufacturer.lower() if manufacturer else None
        except Exception as e:
            logger.debug(f"MAC lookup failed for {mac_address}: {e}")
            return None
    
    def _match_device_type(self, device_data: Dict) -> tuple:
        """
        Match device type based on various indicators
        
        Returns:
            (device_type, confidence_score)
        """
        scores = {}
        
        ports = set(device_data.get('open_ports', []))
        services = [s.get('type', '') for s in device_data.get('services', [])]
        manufacturer = device_data.get('manufacturer', '').lower() if device_data.get('manufacturer') else ''
        hostname = device_data.get('hostname', '').lower() if device_data.get('hostname') else ''
        
        # Score each device type
        for device_type, patterns in self.DEVICE_PATTERNS.items():
            score = 0
            
            # Check port matches
            if ports:
                pattern_ports = set(patterns.get('ports', []))
                port_matches = len(ports & pattern_ports)
                if port_matches > 0:
                    score += port_matches * 20
            
            # Check service matches
            if services:
                for service in services:
                    for pattern_service in patterns.get('services', []):
                        if pattern_service in service:
                            score += 30
            
            # Check manufacturer matches
            if manufacturer:
                for mfr in patterns.get('manufacturers', []):
                    if mfr in manufacturer:
                        score += 40
            
            # Check hostname keywords
            if hostname:
                for keyword in patterns.get('keywords', []):
                    if keyword in hostname:
                        score += 25
            
            if score > 0:
                scores[device_type] = score
        
        # Return best match
        if scores:
            best_type = max(scores, key=scores.get)
            max_score = scores[best_type]
            confidence = min(max_score / 100, 1.0)  # Normalize to 0-1
            return best_type, confidence
        
        return 'unknown', 0.0
    
    def _analyze_http_banner(self, banner: str) -> Dict:
        """Analyze HTTP banner for device information"""
        info = {}
        
        if not banner:
            return info
        
        banner_lower = banner.lower()
        
        # Extract Server header
        server_match = re.search(r'Server:\s*([^\r\n]+)', banner, re.IGNORECASE)
        if server_match:
            info['server'] = server_match.group(1).strip()
        
        # Detect embedded devices
        embedded_indicators = {
            'embedded': ['embedded', 'iot', 'lighttpd', 'busybox'],
            'camera': ['ipcamera', 'webcam', 'camera', 'dvr', 'nvr'],
            'router': ['router', 'gateway', 'openwrt', 'dd-wrt'],
            'nas': ['nas', 'storage', 'synology', 'qnap']
        }
        
        for device_type, indicators in embedded_indicators.items():
            for indicator in indicators:
                if indicator in banner_lower:
                    info['likely_type'] = device_type
                    break
        
        return info
    
    async def _probe_http_service(self, ip: str, port: int = 80) -> Dict:
        """Probe HTTP service for fingerprinting"""
        try:
            url = f"http://{ip}:{port}/"
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=5)) as response:
                    headers = dict(response.headers)
                    body = await response.text()
                    
                    return {
                        'status_code': response.status,
                        'headers': headers,
                        'server': headers.get('Server', ''),
                        'content_type': headers.get('Content-Type', ''),
                        'body_snippet': body[:500] if body else ''
                    }
        except Exception as e:
            logger.debug(f"HTTP probe failed for {ip}:{port}: {e}")
            return {}
    
    def _detect_os_from_ttl(self, ttl: int) -> Optional[str]:
        """Detect OS based on TTL value"""
        if not ttl:
            return None
        
        # Common TTL values
        if ttl <= 64:
            return 'Linux/Unix'
        elif ttl <= 128:
            return 'Windows'
        elif ttl <= 255:
            return 'Cisco/Network Device'
        
        return None
    
    async def fingerprint_device(self, device_data: Dict) -> Dict:
        """
        Comprehensive device fingerprinting
        
        Args:
            device_data: Dictionary with device information
            
        Returns:
            Enhanced device data with fingerprint information
        """
        logger.info(f"Fingerprinting device: {device_data.get('ip_address')}")
        
        result = device_data.copy()
        
        # Get manufacturer from MAC
        if device_data.get('mac_address'):
            manufacturer = self._get_manufacturer_from_mac(device_data['mac_address'])
            if manufacturer:
                result['manufacturer'] = manufacturer
        
        # Match device type
        device_type, confidence = self._match_device_type(device_data)
        result['device_type'] = device_type
        result['confidence'] = confidence
        
        # HTTP probing if port 80 is open
        if 80 in device_data.get('open_ports', []):
            http_info = await self._probe_http_service(device_data['ip_address'])
            if http_info:
                result['http_info'] = http_info
                banner_analysis = self._analyze_http_banner(
                    f"Server: {http_info.get('server', '')}"
                )
                result.update(banner_analysis)
        
        # Add fingerprinting metadata
        result['fingerprinted'] = True
        result['fingerprint_timestamp'] = asyncio.get_event_loop().time()
        
        return result
    
    async def fingerprint_devices_batch(self, devices: List[Dict]) -> List[Dict]:
        """
        Fingerprint multiple devices concurrently
        
        Args:
            devices: List of device dictionaries
            
        Returns:
            List of fingerprinted devices
        """
        logger.info(f"Batch fingerprinting {len(devices)} devices...")
        
        tasks = [self.fingerprint_device(device) for device in devices]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Filter out exceptions
        fingerprinted = []
        for result in results:
            if isinstance(result, dict):
                fingerprinted.append(result)
            else:
                logger.error(f"Fingerprinting error: {result}")
        
        logger.info(f"Successfully fingerprinted {len(fingerprinted)} devices")
        return fingerprinted


class ProtocolRecognizer:
    """Application-layer protocol recognition"""
    
    # Protocol signatures
    PROTOCOL_SIGNATURES = {
        'http': {
            'ports': [80, 8080, 8000, 8888],
            'pattern': rb'HTTP/\d\.\d'
        },
        'https': {
            'ports': [443, 8443],
            'pattern': rb'\x16\x03[\x00-\x03]'  # TLS handshake
        },
        'mqtt': {
            'ports': [1883, 8883],
            'pattern': rb'\x10[\x00-\xff]'  # MQTT CONNECT
        },
        'coap': {
            'ports': [5683, 5684],
            'pattern': rb'[\x40-\x7f][\x00-\x04]'  # CoAP header
        },
        'modbus': {
            'ports': [502],
            'pattern': rb'\x00[\x00-\xff]\x00\x00'
        },
        'ssh': {
            'ports': [22],
            'pattern': rb'SSH-'
        },
        'telnet': {
            'ports': [23],
            'pattern': rb'\xff[\xfb-\xfe]'  # Telnet IAC
        },
        'ftp': {
            'ports': [21],
            'pattern': rb'220[- ]'
        },
        'rtsp': {
            'ports': [554],
            'pattern': rb'RTSP/'
        },
        'snmp': {
            'ports': [161, 162],
            'pattern': rb'\x30'  # ASN.1 SEQUENCE
        }
    }
    
    async def recognize_protocol(self, ip: str, port: int, timeout: int = 3) -> Optional[str]:
        """
        Recognize protocol on given port
        
        Args:
            ip: IP address
            port: Port number
            timeout: Connection timeout
            
        Returns:
            Protocol name or None
        """
        try:
            # Try to connect and read banner
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port),
                timeout=timeout
            )
            
            # Read first bytes
            data = await asyncio.wait_for(reader.read(100), timeout=1)
            
            writer.close()
            await writer.wait_closed()
            
            # Match against signatures
            for protocol, signature in self.PROTOCOL_SIGNATURES.items():
                if port in signature['ports']:
                    if re.search(signature['pattern'], data):
                        return protocol
            
            return None
            
        except Exception as e:
            logger.debug(f"Protocol recognition failed for {ip}:{port}: {e}")
            return None


# Example usage
async def main():
    """Test device fingerprinting"""
    fingerprinter = DeviceFingerprinter()
    
    # Test device
    test_device = {
        'ip_address': '192.168.1.100',
        'mac_address': '00:17:88:12:34:56',  # Philips MAC
        'hostname': 'Philips-hue',
        'open_ports': [80, 443, 38899],
        'services': [{'type': '_hue._tcp'}]
    }
    
    result = await fingerprinter.fingerprint_device(test_device)
    
    print("\n=== Fingerprinting Result ===")
    print(f"IP: {result['ip_address']}")
    print(f"Manufacturer: {result.get('manufacturer', 'Unknown')}")
    print(f"Device Type: {result.get('device_type', 'Unknown')}")
    print(f"Confidence: {result.get('confidence', 0):.2%}")
    

if __name__ == '__main__':
    asyncio.run(main())
