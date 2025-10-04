"""
Default Credential Database and Testing
Tests devices against known default username/password combinations
"""

import asyncio
import logging
from typing import Dict, List, Optional, Tuple
import aiohttp
import socket
from datetime import datetime

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# Comprehensive default credential database
DEFAULT_CREDENTIALS = {
    # Generic/Common
    'generic': [
        ('admin', 'admin'),
        ('admin', 'password'),
        ('admin', ''),
        ('root', 'root'),
        ('root', 'password'),
        ('root', ''),
        ('user', 'user'),
        ('administrator', 'administrator'),
        ('guest', 'guest'),
        ('', ''),
    ],
    
    # IoT Devices
    'iot': [
        ('admin', '1234'),
        ('admin', '12345'),
        ('admin', '123456'),
        ('root', '1234'),
        ('pi', 'raspberry'),
        ('admin', 'admin1234'),
        ('admin', 'pass'),
    ],
    
    # IP Cameras
    'camera': [
        ('admin', ''),
        ('admin', '12345'),
        ('admin', '888888'),
        ('admin', '666666'),
        ('root', '12345'),
        ('supervisor', 'supervisor'),
        ('admin', '4321'),
        ('default', 'default'),
        ('viewer', 'viewer'),
    ],
    
    # Routers
    'router': [
        ('admin', 'admin'),
        ('admin', 'password'),
        ('admin', ''),
        ('root', 'admin'),
        ('user', 'user'),
        ('admin', '1234'),
        ('admin', 'smcadmin'),
        ('cusadmin', 'password'),
    ],
    
    # Smart Home Hubs
    'smart_hub': [
        ('admin', 'admin'),
        ('admin', ''),
        ('admin', 'password'),
        ('admin', '1234'),
    ],
    
    # Industrial/SCADA
    'industrial': [
        ('admin', 'admin'),
        ('administrator', 'administrator'),
        ('root', 'root'),
        ('operator', 'operator'),
        ('admin', '1234'),
        ('admin', 'password'),
    ],
    
    # Network Devices
    'network': [
        ('admin', 'admin'),
        ('admin', ''),
        ('cisco', 'cisco'),
        ('ubnt', 'ubnt'),
        ('root', 'default'),
    ],
    
    # Database Systems
    'database': [
        ('admin', 'admin'),
        ('root', ''),
        ('postgres', 'postgres'),
        ('mysql', 'mysql'),
        ('sa', 'sa'),
    ],
}

# Vendor-specific credentials
VENDOR_CREDENTIALS = {
    'cisco': [('admin', 'admin'), ('cisco', 'cisco')],
    'netgear': [('admin', 'password'), ('admin', '1234')],
    'linksys': [('admin', 'admin'), ('admin', '')],
    'dlink': [('admin', ''), ('admin', 'admin')],
    'tplink': [('admin', 'admin'), ('admin', '')],
    'asus': [('admin', 'admin'), ('admin', '')],
    'ubiquiti': [('ubnt', 'ubnt'), ('root', 'ubnt')],
    'hikvision': [('admin', '12345'), ('admin', '')],
    'dahua': [('admin', 'admin'), ('admin', '888888')],
    'axis': [('root', 'pass'), ('root', '')],
    'samsung': [('admin', ''), ('admin', '1111')],
    'lg': [('admin', ''), ('admin', '1234')],
    'philips': [('admin', ''), ('admin', '1234')],
    'xiaomi': [('admin', ''), ('admin', '1234')],
}


class DefaultCredentialTester:
    """Test devices for default credentials"""
    
    def __init__(self):
        """Initialize credential tester"""
        self.tested_credentials = []
        self.successful_logins = []
        self.vulnerabilities = []
    
    def get_credentials_for_device(self, device_info: Dict) -> List[Tuple[str, str]]:
        """
        Get relevant credential list based on device type and manufacturer
        
        Args:
            device_info: Device information dictionary
            
        Returns:
            List of (username, password) tuples to test
        """
        credentials = set()
        
        # Add generic credentials
        credentials.update(DEFAULT_CREDENTIALS['generic'])
        
        # Add device type specific credentials
        device_type = (device_info.get('device_type', '') or '').lower()
        
        if 'camera' in device_type or 'ipcam' in device_type:
            credentials.update(DEFAULT_CREDENTIALS['camera'])
        elif 'router' in device_type or 'gateway' in device_type:
            credentials.update(DEFAULT_CREDENTIALS['router'])
        elif 'hub' in device_type or 'bridge' in device_type:
            credentials.update(DEFAULT_CREDENTIALS['smart_hub'])
        elif 'plc' in device_type or 'scada' in device_type:
            credentials.update(DEFAULT_CREDENTIALS['industrial'])
        else:
            credentials.update(DEFAULT_CREDENTIALS['iot'])
        
        # Add vendor-specific credentials
        manufacturer = (device_info.get('manufacturer', '') or '').lower()
        for vendor, vendor_creds in VENDOR_CREDENTIALS.items():
            if vendor in manufacturer:
                credentials.update(vendor_creds)
                logger.info(f"Added {len(vendor_creds)} vendor-specific credentials for {vendor}")
        
        return list(credentials)
    
    async def test_http_auth(self, ip: str, port: int, username: str, 
                            password: str, timeout: int = 5) -> bool:
        """
        Test HTTP basic authentication
        
        Args:
            ip: Device IP
            port: HTTP port
            username: Username to test
            password: Password to test
            timeout: Connection timeout
            
        Returns:
            True if authentication successful
        """
        try:
            auth = aiohttp.BasicAuth(username, password)
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=timeout)) as session:
                url = f"http://{ip}:{port}"
                
                async with session.get(url, auth=auth, allow_redirects=False) as response:
                    # Success codes indicate authentication worked
                    if response.status in [200, 301, 302]:
                        return True
                    # 401 means auth failed
                    elif response.status == 401:
                        return False
        except Exception as e:
            logger.debug(f"HTTP auth test failed for {ip}:{port} - {e}")
        
        return False
    
    async def test_ssh_auth(self, ip: str, port: int, username: str, 
                           password: str, timeout: int = 5) -> bool:
        """
        Test SSH authentication
        
        Args:
            ip: Device IP
            port: SSH port
            username: Username to test
            password: Password to test
            timeout: Connection timeout
            
        Returns:
            True if authentication successful
        """
        try:
            import paramiko
            
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            try:
                client.connect(
                    ip, 
                    port=port, 
                    username=username, 
                    password=password,
                    timeout=timeout,
                    allow_agent=False,
                    look_for_keys=False
                )
                client.close()
                return True
            except paramiko.AuthenticationException:
                return False
            except Exception as e:
                logger.debug(f"SSH connection failed: {e}")
                return False
        except ImportError:
            logger.warning("paramiko not available for SSH testing")
            return False
    
    async def test_telnet_auth(self, ip: str, port: int, username: str, 
                              password: str, timeout: int = 5) -> bool:
        """
        Test Telnet authentication
        
        Args:
            ip: Device IP
            port: Telnet port
            username: Username to test
            password: Password to test
            timeout: Connection timeout
            
        Returns:
            True if authentication successful
        """
        try:
            import telnetlib
            
            tn = telnetlib.Telnet(ip, port, timeout=timeout)
            
            # Wait for login prompt
            tn.read_until(b"login: ", timeout=2)
            tn.write(username.encode('ascii') + b"\n")
            
            # Wait for password prompt
            tn.read_until(b"Password: ", timeout=2)
            tn.write(password.encode('ascii') + b"\n")
            
            # Check if login successful
            response = tn.read_some()
            
            tn.close()
            
            # If we see success indicators, auth worked
            if b"$" in response or b"#" in response or b">" in response:
                return True
            
        except Exception as e:
            logger.debug(f"Telnet test failed: {e}")
        
        return False
    
    async def test_device_credentials(self, device_info: Dict) -> Dict:
        """
        Test device for default credentials
        
        Args:
            device_info: Device information
            
        Returns:
            Test results with successful credentials
        """
        ip = device_info.get('ip_address')
        ports = device_info.get('open_ports', [])
        
        result = {
            'ip': ip,
            'tested': 0,
            'successful': [],
            'vulnerabilities': [],
            'timestamp': datetime.now().isoformat()
        }
        
        if not ip or not ports:
            return result
        
        # Get credentials to test
        credentials_to_test = self.get_credentials_for_device(device_info)
        logger.info(f"Testing {len(credentials_to_test)} credentials for {ip}")
        
        # Test each service
        for port in ports:
            if port == 80 or port == 8080:
                # Test HTTP
                for username, password in credentials_to_test[:10]:  # Limit to avoid lockouts
                    result['tested'] += 1
                    if await self.test_http_auth(ip, port, username, password):
                        success = {
                            'service': 'HTTP',
                            'port': port,
                            'username': username,
                            'password': password
                        }
                        result['successful'].append(success)
                        logger.warning(f"Default credentials found on {ip}:{port} - {username}:{password}")
            
            elif port == 22:
                # Test SSH
                for username, password in credentials_to_test[:5]:  # SSH lockout risk
                    result['tested'] += 1
                    if await self.test_ssh_auth(ip, port, username, password):
                        success = {
                            'service': 'SSH',
                            'port': port,
                            'username': username,
                            'password': password
                        }
                        result['successful'].append(success)
                        logger.warning(f"Default SSH credentials found on {ip}:{port}")
            
            elif port == 23:
                # Test Telnet
                for username, password in credentials_to_test[:5]:
                    result['tested'] += 1
                    if await self.test_telnet_auth(ip, port, username, password):
                        success = {
                            'service': 'Telnet',
                            'port': port,
                            'username': username,
                            'password': password
                        }
                        result['successful'].append(success)
                        logger.warning(f"Default Telnet credentials found on {ip}:{port}")
        
        # Generate vulnerabilities
        if result['successful']:
            for success in result['successful']:
                vuln = {
                    'type': 'Default Credentials',
                    'severity': 'Critical',
                    'description': f"Device accepts default credentials on {success['service']} (port {success['port']})",
                    'username': success['username'],
                    'password': success['password'],
                    'recommendation': 'Change default credentials immediately',
                    'cvss_score': 9.8
                }
                result['vulnerabilities'].append(vuln)
                self.vulnerabilities.append(vuln)
        
        return result
    
    async def batch_test(self, devices: List[Dict]) -> List[Dict]:
        """
        Test multiple devices concurrently
        
        Args:
            devices: List of device dictionaries
            
        Returns:
            List of test results
        """
        logger.info(f"Batch testing {len(devices)} devices for default credentials")
        
        tasks = [self.test_device_credentials(device) for device in devices]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Filter out exceptions
        valid_results = []
        for result in results:
            if isinstance(result, dict):
                valid_results.append(result)
            else:
                logger.error(f"Testing error: {result}")
        
        # Count successful finds
        total_found = sum(len(r['successful']) for r in valid_results)
        logger.info(f"Default credential testing complete. Found credentials on {total_found} services")
        
        return valid_results
    
    def generate_report(self, results: List[Dict]) -> Dict:
        """Generate comprehensive report"""
        report = {
            'total_devices_tested': len(results),
            'total_credentials_tested': sum(r['tested'] for r in results),
            'devices_with_defaults': sum(1 for r in results if r['successful']),
            'total_vulnerabilities': sum(len(r['vulnerabilities']) for r in results),
            'successful_logins': [],
            'recommendations': []
        }
        
        # Collect all successful logins
        for result in results:
            if result['successful']:
                report['successful_logins'].append({
                    'ip': result['ip'],
                    'credentials': result['successful']
                })
        
        # Generate recommendations
        if report['devices_with_defaults'] > 0:
            report['recommendations'].append(
                f"CRITICAL: {report['devices_with_defaults']} devices found with default credentials"
            )
            report['recommendations'].append(
                "Change all default credentials immediately"
            )
            report['recommendations'].append(
                "Implement password policies requiring strong, unique passwords"
            )
            report['recommendations'].append(
                "Enable multi-factor authentication where possible"
            )
        
        return report


# Example usage
async def main():
    """Test default credential tester"""
    print("="*70)
    print("Default Credential Tester - Phase 6")
    print("="*70)
    
    tester = DefaultCredentialTester()
    
    # Test devices
    test_devices = [
        {
            'ip_address': '192.168.1.100',
            'open_ports': [80, 22],
            'device_type': 'camera',
            'manufacturer': 'Hikvision'
        },
        {
            'ip_address': '192.168.1.101',
            'open_ports': [80, 23],
            'device_type': 'router',
            'manufacturer': 'TP-Link'
        }
    ]
    
    print(f"\nTesting {len(test_devices)} devices...")
    results = await tester.batch_test(test_devices)
    
    report = tester.generate_report(results)
    
    print(f"\n{'='*70}")
    print("Test Results")
    print(f"{'='*70}")
    print(f"Devices Tested: {report['total_devices_tested']}")
    print(f"Credentials Tested: {report['total_credentials_tested']}")
    print(f"Devices with Defaults: {report['devices_with_defaults']}")
    print(f"Total Vulnerabilities: {report['total_vulnerabilities']}")
    
    if report['successful_logins']:
        print(f"\n⚠️  Default Credentials Found:")
        for login in report['successful_logins']:
            print(f"\n  {login['ip']}:")
            for cred in login['credentials']:
                print(f"    [{cred['service']}:{cred['port']}] {cred['username']}:{cred['password']}")
    
    if report['recommendations']:
        print(f"\nRecommendations:")
        for rec in report['recommendations']:
            print(f"  • {rec}")


if __name__ == '__main__':
    asyncio.run(main())
