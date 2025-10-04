"""
Wi-Fi Security Scanner
Analyzes Wi-Fi networks, security protocols, and vulnerabilities
"""

import asyncio
import logging
import subprocess
import re
from typing import List, Dict, Optional
from datetime import datetime
import struct

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class WiFiScanner:
    """Wi-Fi network scanner and security analyzer"""
    
    # Security protocol strengths
    SECURITY_STRENGTH = {
        'OPEN': 0,
        'WEP': 1,
        'WPA': 2,
        'WPA2': 3,
        'WPA3': 4,
        'WPA2/WPA3': 4
    }
    
    # Known vulnerable configurations
    VULNERABILITIES = {
        'OPEN': {
            'severity': 'Critical',
            'description': 'Network is open without encryption',
            'recommendation': 'Enable WPA2 or WPA3 encryption'
        },
        'WEP': {
            'severity': 'Critical',
            'description': 'WEP encryption is severely outdated and easily crackable',
            'recommendation': 'Upgrade to WPA2 or WPA3 immediately'
        },
        'WPA': {
            'severity': 'High',
            'description': 'WPA is vulnerable to various attacks',
            'recommendation': 'Upgrade to WPA2 or WPA3'
        },
        'WPS': {
            'severity': 'High',
            'description': 'WPS (Wi-Fi Protected Setup) is vulnerable to brute force attacks',
            'recommendation': 'Disable WPS on the router'
        },
        'WEAK_PASSWORD': {
            'severity': 'High',
            'description': 'Network may be using a weak or default password',
            'recommendation': 'Use a strong, unique password (16+ characters)'
        }
    }
    
    def __init__(self, interface: Optional[str] = None):
        """
        Initialize Wi-Fi scanner
        
        Args:
            interface: Wi-Fi interface to use (None for auto-detect)
        """
        self.interface = interface or self._get_wireless_interface()
        self.discovered_networks = []
    
    def _get_wireless_interface(self) -> Optional[str]:
        """Detect wireless network interface"""
        try:
            # Try to find wireless interface
            result = subprocess.check_output(
                ['iw', 'dev'],
                stderr=subprocess.STDOUT,
                text=True
            )
            
            # Parse output to find interface name
            for line in result.split('\n'):
                if 'Interface' in line:
                    interface = line.split()[1]
                    logger.info(f"Found wireless interface: {interface}")
                    return interface
                    
        except subprocess.CalledProcessError:
            pass
        except FileNotFoundError:
            logger.warning("'iw' command not found. Install wireless-tools package.")
        
        # Fallback: try common interface names
        for name in ['wlan0', 'wlp2s0', 'wlp3s0', 'wlo1']:
            try:
                result = subprocess.check_output(
                    ['ifconfig', name],
                    stderr=subprocess.DEVNULL,
                    text=True
                )
                logger.info(f"Using interface: {name}")
                return name
            except:
                continue
        
        logger.warning("No wireless interface found")
        return None
    
    def _parse_iwlist_output(self, output: str) -> List[Dict]:
        """Parse iwlist scan output"""
        networks = []
        current_network = None
        
        for line in output.split('\n'):
            line = line.strip()
            
            # New cell (network)
            if line.startswith('Cell'):
                if current_network:
                    networks.append(current_network)
                current_network = {
                    'discovered_at': datetime.now().isoformat(),
                    'discovery_method': 'Wi-Fi Scan'
                }
                
                # Extract MAC address
                mac_match = re.search(r'Address: ([\w:]+)', line)
                if mac_match:
                    current_network['bssid'] = mac_match.group(1)
            
            elif current_network:
                # ESSID (network name)
                if 'ESSID:' in line:
                    essid_match = re.search(r'ESSID:"([^"]*)"', line)
                    if essid_match:
                        current_network['ssid'] = essid_match.group(1)
                
                # Channel
                elif 'Channel:' in line or 'Frequency:' in line:
                    channel_match = re.search(r'Channel:?(\d+)', line)
                    if channel_match:
                        current_network['channel'] = int(channel_match.group(1))
                
                # Signal strength
                elif 'Signal level' in line:
                    signal_match = re.search(r'Signal level[=:](-?\d+)', line)
                    if signal_match:
                        current_network['signal'] = int(signal_match.group(1))
                
                # Encryption
                elif 'Encryption key:' in line:
                    current_network['encrypted'] = 'on' in line.lower()
                
                # Security protocols
                elif 'WPA' in line or 'WPA2' in line or 'WPA3' in line:
                    if 'security' not in current_network:
                        current_network['security'] = []
                    
                    if 'WPA3' in line:
                        current_network['security'].append('WPA3')
                    elif 'WPA2' in line:
                        current_network['security'].append('WPA2')
                    elif 'WPA' in line:
                        current_network['security'].append('WPA')
                
                # WPS
                elif 'WPS' in line:
                    current_network['wps_enabled'] = True
        
        # Add last network
        if current_network:
            networks.append(current_network)
        
        return networks
    
    def _parse_nmcli_output(self, output: str) -> List[Dict]:
        """Parse nmcli output (alternative method)"""
        networks = []
        
        lines = output.strip().split('\n')[1:]  # Skip header
        
        for line in lines:
            parts = line.split(':')
            if len(parts) >= 8:
                network = {
                    'ssid': parts[1].strip(),
                    'bssid': parts[0].strip(),
                    'signal': int(parts[5].strip()) if parts[5].strip().isdigit() else 0,
                    'channel': parts[4].strip(),
                    'security': [],
                    'discovered_at': datetime.now().isoformat(),
                    'discovery_method': 'Wi-Fi Scan'
                }
                
                # Parse security
                security_str = parts[7].strip()
                if 'WPA3' in security_str:
                    network['security'].append('WPA3')
                if 'WPA2' in security_str:
                    network['security'].append('WPA2')
                if 'WPA' in security_str and 'WPA2' not in security_str:
                    network['security'].append('WPA')
                if 'WEP' in security_str:
                    network['security'].append('WEP')
                if not network['security']:
                    network['security'].append('OPEN')
                
                networks.append(network)
        
        return networks
    
    async def scan_networks(self) -> List[Dict]:
        """
        Scan for Wi-Fi networks
        
        Returns:
            List of discovered networks with security information
        """
        if not self.interface:
            logger.error("No wireless interface available")
            return []
        
        logger.info(f"Scanning Wi-Fi networks on {self.interface}...")
        
        try:
            # Try nmcli first (more reliable on modern systems)
            try:
                result = subprocess.check_output(
                    ['nmcli', '-f', 'BSSID,SSID,MODE,CHAN,FREQ,RATE,SIGNAL,SECURITY', 
                     'dev', 'wifi', 'list'],
                    stderr=subprocess.STDOUT,
                    text=True,
                    timeout=30
                )
                networks = self._parse_nmcli_output(result)
            except:
                # Fallback to iwlist
                result = subprocess.check_output(
                    ['sudo', 'iwlist', self.interface, 'scan'],
                    stderr=subprocess.STDOUT,
                    text=True,
                    timeout=30
                )
                networks = self._parse_iwlist_output(result)
            
            # Analyze security for each network
            for network in networks:
                network.update(self._analyze_security(network))
            
            self.discovered_networks = networks
            logger.info(f"Found {len(networks)} Wi-Fi networks")
            
            return networks
            
        except subprocess.TimeoutExpired:
            logger.error("Wi-Fi scan timed out")
            return []
        except subprocess.CalledProcessError as e:
            logger.error(f"Wi-Fi scan error: {e}")
            return []
        except Exception as e:
            logger.error(f"Unexpected error during Wi-Fi scan: {e}")
            return []
    
    def _analyze_security(self, network: Dict) -> Dict:
        """
        Analyze network security and identify vulnerabilities
        
        Args:
            network: Network information dictionary
            
        Returns:
            Security analysis results
        """
        analysis = {
            'vulnerabilities': [],
            'security_score': 0,
            'recommendations': []
        }
        
        security_protocols = network.get('security', [])
        
        # Determine primary security protocol
        if not security_protocols or 'OPEN' in security_protocols:
            primary_security = 'OPEN'
        elif 'WPA3' in security_protocols:
            primary_security = 'WPA3'
        elif 'WPA2' in security_protocols:
            primary_security = 'WPA2'
        elif 'WPA' in security_protocols:
            primary_security = 'WPA'
        elif 'WEP' in security_protocols:
            primary_security = 'WEP'
        else:
            primary_security = 'UNKNOWN'
        
        network['primary_security'] = primary_security
        
        # Calculate security score (0-100)
        base_score = self.SECURITY_STRENGTH.get(primary_security, 0) * 20
        
        # Add vulnerability information
        if primary_security in self.VULNERABILITIES:
            vuln_info = self.VULNERABILITIES[primary_security]
            analysis['vulnerabilities'].append({
                'type': f'Weak Encryption: {primary_security}',
                'severity': vuln_info['severity'],
                'description': vuln_info['description'],
                'recommendation': vuln_info['recommendation']
            })
        
        # Check for WPS
        if network.get('wps_enabled'):
            analysis['vulnerabilities'].append({
                'type': 'WPS Enabled',
                'severity': self.VULNERABILITIES['WPS']['severity'],
                'description': self.VULNERABILITIES['WPS']['description'],
                'recommendation': self.VULNERABILITIES['WPS']['recommendation']
            })
            base_score -= 15
        
        # Check signal strength (potential for eavesdropping)
        signal = network.get('signal', -100)
        if signal > -50:
            analysis['vulnerabilities'].append({
                'type': 'Strong Signal Outside Premises',
                'severity': 'Low',
                'description': 'Network signal is strong and may extend beyond intended area',
                'recommendation': 'Reduce router power or reposition for better coverage control'
            })
        
        # Check for hidden SSID (security through obscurity)
        if not network.get('ssid') or network.get('ssid') == '':
            analysis['notes'] = ['Hidden SSID (not a security feature)']
        
        analysis['security_score'] = max(0, min(100, base_score))
        
        return analysis
    
    def detect_wifi_direct(self) -> List[Dict]:
        """
        Detect Wi-Fi Direct devices
        
        Returns:
            List of Wi-Fi Direct devices
        """
        logger.info("Scanning for Wi-Fi Direct devices...")
        
        wifi_direct_devices = []
        
        for network in self.discovered_networks:
            ssid = network.get('ssid', '')
            
            # Wi-Fi Direct networks typically start with "DIRECT-"
            if ssid.startswith('DIRECT-'):
                wifi_direct_device = network.copy()
                wifi_direct_device['device_type'] = 'Wi-Fi Direct'
                wifi_direct_device['protocol'] = 'Wi-Fi Direct (P2P)'
                
                # Extract device name if available
                if len(ssid) > 8:
                    wifi_direct_device['device_name'] = ssid[8:]
                
                wifi_direct_devices.append(wifi_direct_device)
        
        logger.info(f"Found {len(wifi_direct_devices)} Wi-Fi Direct devices")
        return wifi_direct_devices
    
    def get_statistics(self) -> Dict:
        """Get scanning statistics"""
        if not self.discovered_networks:
            return {}
        
        stats = {
            'total_networks': len(self.discovered_networks),
            'open_networks': 0,
            'wep_networks': 0,
            'wpa_networks': 0,
            'wpa2_networks': 0,
            'wpa3_networks': 0,
            'wps_enabled': 0,
            'avg_security_score': 0
        }
        
        total_score = 0
        
        for network in self.discovered_networks:
            primary_security = network.get('primary_security', 'UNKNOWN')
            
            if primary_security == 'OPEN':
                stats['open_networks'] += 1
            elif primary_security == 'WEP':
                stats['wep_networks'] += 1
            elif primary_security == 'WPA':
                stats['wpa_networks'] += 1
            elif primary_security == 'WPA2':
                stats['wpa2_networks'] += 1
            elif primary_security == 'WPA3':
                stats['wpa3_networks'] += 1
            
            if network.get('wps_enabled'):
                stats['wps_enabled'] += 1
            
            total_score += network.get('security_score', 0)
        
        if stats['total_networks'] > 0:
            stats['avg_security_score'] = total_score / stats['total_networks']
        
        return stats


# Example usage and testing
async def main():
    """Test Wi-Fi scanning"""
    print("="*60)
    print("Wi-Fi Security Scanner Test")
    print("="*60)
    
    scanner = WiFiScanner()
    
    print(f"\nUsing interface: {scanner.interface}")
    print("\nScanning for Wi-Fi networks...")
    
    networks = await scanner.scan_networks()
    
    stats = scanner.get_statistics()
    
    print(f"\n{'='*60}")
    print("Scan Results")
    print(f"{'='*60}")
    print(f"Total Networks: {stats.get('total_networks', 0)}")
    print(f"Open Networks: {stats.get('open_networks', 0)}")
    print(f"WEP Networks: {stats.get('wep_networks', 0)}")
    print(f"WPA Networks: {stats.get('wpa_networks', 0)}")
    print(f"WPA2 Networks: {stats.get('wpa2_networks', 0)}")
    print(f"WPA3 Networks: {stats.get('wpa3_networks', 0)}")
    print(f"WPS Enabled: {stats.get('wps_enabled', 0)}")
    print(f"Average Security Score: {stats.get('avg_security_score', 0):.1f}/100")
    
    print(f"\n{'='*60}")
    print("Discovered Networks")
    print(f"{'='*60}")
    
    for i, network in enumerate(networks[:10], 1):  # Show first 10
        print(f"\n{i}. {network.get('ssid', 'Hidden Network')}")
        print(f"   BSSID: {network.get('bssid', 'Unknown')}")
        print(f"   Security: {network.get('primary_security', 'Unknown')}")
        print(f"   Signal: {network.get('signal', 'Unknown')} dBm")
        print(f"   Channel: {network.get('channel', 'Unknown')}")
        print(f"   Security Score: {network.get('security_score', 0)}/100")
        
        if network.get('vulnerabilities'):
            print(f"   Vulnerabilities: {len(network['vulnerabilities'])}")
            for vuln in network['vulnerabilities']:
                print(f"     - {vuln['type']} ({vuln['severity']})")
    
    if len(networks) > 10:
        print(f"\n... and {len(networks) - 10} more networks")
    
    # Check for Wi-Fi Direct
    wifi_direct = scanner.detect_wifi_direct()
    if wifi_direct:
        print(f"\n{'='*60}")
        print(f"Wi-Fi Direct Devices: {len(wifi_direct)}")
        print(f"{'='*60}")
        for device in wifi_direct:
            print(f"  - {device.get('device_name', 'Unknown')}")


if __name__ == '__main__':
    asyncio.run(main())
