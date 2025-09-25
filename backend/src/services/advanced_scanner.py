import asyncio
import aiohttp
import ssl
import socket
import struct
import hashlib
import base64
from typing import Dict, List, Optional, Tuple
from datetime import datetime, timedelta
import json
import re
import subprocess
from concurrent.futures import ThreadPoolExecutor
import threading

class AdvancedScanner:
    def __init__(self):
        self.timeout = 10
        self.max_concurrent = 20
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
        ]
        
        # Advanced vulnerability patterns
        self.vulnerability_patterns = {
            'default_credentials': [
                ('admin', 'admin'), ('admin', 'password'), ('admin', ''),
                ('root', 'root'), ('root', 'password'), ('root', ''),
                ('user', 'user'), ('guest', 'guest'), ('admin', '123456'),
                ('admin', 'admin123'), ('administrator', 'administrator')
            ],
            'weak_ssl_ciphers': [
                'RC4', 'DES', '3DES', 'MD5', 'SHA1', 'NULL'
            ],
            'information_disclosure': [
                'server:', 'x-powered-by:', 'x-aspnet-version:',
                'x-generator:', 'x-drupal-cache:', 'x-varnish:'
            ],
            'directory_traversal': [
                '../../../etc/passwd', '..\\..\\..\\windows\\system32\\drivers\\etc\\hosts',
                '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd'
            ],
            'command_injection': [
                '; cat /etc/passwd', '| whoami', '`id`',
                '$(whoami)', '; ls -la', '& dir'
            ]
        }
    
    async def advanced_device_scan(self, device_info: Dict) -> Dict:
        """Perform advanced security scanning on a device"""
        ip_address = device_info.get('ip_address')
        open_ports = device_info.get('open_ports', [])
        
        scan_results = {
            'device_ip': ip_address,
            'scan_timestamp': datetime.utcnow(),
            'vulnerabilities': [],
            'security_score': 100,
            'risk_level': 'Low',
            'recommendations': []
        }
        
        # Parallel scanning tasks
        tasks = []
        
        # SSL/TLS analysis for HTTPS services
        https_ports = [port for port in open_ports if port.get('service') in ['https', 'ssl'] or port.get('port') in [443, 8443]]
        if https_ports:
            tasks.append(self._analyze_ssl_security(ip_address, https_ports))
        
        # Web application security testing
        web_ports = [port for port in open_ports if port.get('service') in ['http', 'https'] or port.get('port') in [80, 443, 8080, 8443, 8888]]
        if web_ports:
            tasks.append(self._analyze_web_security(ip_address, web_ports))
        
        # Authentication testing
        tasks.append(self._test_authentication_security(ip_address, open_ports))
        
        # Network service analysis
        tasks.append(self._analyze_network_services(ip_address, open_ports))
        
        # Firmware analysis (if accessible)
        tasks.append(self._analyze_firmware_security(ip_address, open_ports))
        
        # Execute all tasks concurrently
        if tasks:
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Combine results
            for result in results:
                if isinstance(result, dict) and 'vulnerabilities' in result:
                    scan_results['vulnerabilities'].extend(result['vulnerabilities'])
        
        # Calculate overall security score and risk level
        scan_results['security_score'] = self._calculate_security_score(scan_results['vulnerabilities'])
        scan_results['risk_level'] = self._determine_risk_level(scan_results['security_score'])
        scan_results['recommendations'] = self._generate_recommendations(scan_results['vulnerabilities'])
        
        return scan_results
    
    async def _analyze_ssl_security(self, ip_address: str, https_ports: List[Dict]) -> Dict:
        """Analyze SSL/TLS security configuration"""
        vulnerabilities = []
        
        for port_info in https_ports:
            port = port_info.get('port')
            
            try:
                # Create SSL context for analysis
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                
                # Connect and get certificate info
                with socket.create_connection((ip_address, port), timeout=self.timeout) as sock:
                    with context.wrap_socket(sock, server_hostname=ip_address) as ssock:
                        cert = ssock.getpeercert()
                        cipher = ssock.cipher()
                        
                        # Check certificate validity
                        if cert:
                            not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                            not_before = datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')
                            
                            # Certificate expiration check
                            days_until_expiry = (not_after - datetime.utcnow()).days
                            if days_until_expiry < 30:
                                vulnerabilities.append({
                                    'type': 'SSL Certificate Expiring Soon',
                                    'severity': 'Medium' if days_until_expiry > 7 else 'High',
                                    'description': f'SSL certificate expires in {days_until_expiry} days',
                                    'port': port,
                                    'details': {'expiry_date': not_after.isoformat()}
                                })
                            
                            # Self-signed certificate check
                            if cert.get('issuer') == cert.get('subject'):
                                vulnerabilities.append({
                                    'type': 'Self-Signed Certificate',
                                    'severity': 'Medium',
                                    'description': 'Device uses a self-signed SSL certificate',
                                    'port': port,
                                    'details': {'subject': str(cert.get('subject'))}
                                })
                        
                        # Cipher suite analysis
                        if cipher:
                            cipher_name = cipher[0]
                            protocol_version = cipher[1]
                            
                            # Check for weak ciphers
                            for weak_cipher in self.vulnerability_patterns['weak_ssl_ciphers']:
                                if weak_cipher.lower() in cipher_name.lower():
                                    vulnerabilities.append({
                                        'type': 'Weak SSL Cipher',
                                        'severity': 'High',
                                        'description': f'Weak cipher suite detected: {cipher_name}',
                                        'port': port,
                                        'details': {'cipher': cipher_name, 'protocol': protocol_version}
                                    })
                            
                            # Check for old SSL/TLS versions
                            if protocol_version in ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1']:
                                vulnerabilities.append({
                                    'type': 'Outdated SSL/TLS Version',
                                    'severity': 'High',
                                    'description': f'Outdated SSL/TLS version: {protocol_version}',
                                    'port': port,
                                    'details': {'protocol': protocol_version}
                                })
            
            except Exception as e:
                print(f"SSL analysis error for {ip_address}:{port}: {e}")
        
        return {'vulnerabilities': vulnerabilities}
    
    async def _analyze_web_security(self, ip_address: str, web_ports: List[Dict]) -> Dict:
        """Analyze web application security"""
        vulnerabilities = []
        
        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=self.timeout),
            connector=aiohttp.TCPConnector(ssl=False)
        ) as session:
            
            for port_info in web_ports:
                port = port_info.get('port')
                service = port_info.get('service', '')
                
                protocol = 'https' if service == 'https' or port == 443 else 'http'
                base_url = f"{protocol}://{ip_address}:{port}"
                
                try:
                    # Basic HTTP response analysis
                    async with session.get(base_url) as response:
                        headers = response.headers
                        content = await response.text()
                        
                        # Security headers analysis
                        security_headers = {
                            'X-Frame-Options': 'Missing clickjacking protection',
                            'X-Content-Type-Options': 'Missing MIME type sniffing protection',
                            'X-XSS-Protection': 'Missing XSS protection',
                            'Strict-Transport-Security': 'Missing HSTS header',
                            'Content-Security-Policy': 'Missing CSP header'
                        }
                        
                        for header, description in security_headers.items():
                            if header not in headers:
                                vulnerabilities.append({
                                    'type': 'Missing Security Header',
                                    'severity': 'Medium',
                                    'description': description,
                                    'port': port,
                                    'details': {'missing_header': header}
                                })
                        
                        # Information disclosure in headers
                        for header_name, header_value in headers.items():
                            for disclosure_pattern in self.vulnerability_patterns['information_disclosure']:
                                if disclosure_pattern.lower() in header_name.lower():
                                    vulnerabilities.append({
                                        'type': 'Information Disclosure',
                                        'severity': 'Low',
                                        'description': f'Server information disclosed in {header_name} header',
                                        'port': port,
                                        'details': {'header': header_name, 'value': header_value}
                                    })
                        
                        # Default page detection
                        default_indicators = [
                            'default page', 'welcome to', 'it works', 'apache2',
                            'nginx', 'iis', 'test page', 'under construction'
                        ]
                        
                        content_lower = content.lower()
                        for indicator in default_indicators:
                            if indicator in content_lower:
                                vulnerabilities.append({
                                    'type': 'Default Web Page',
                                    'severity': 'Low',
                                    'description': 'Device appears to be using default web page',
                                    'port': port,
                                    'details': {'indicator': indicator}
                                })
                                break
                    
                    # Directory traversal testing
                    for traversal_payload in self.vulnerability_patterns['directory_traversal'][:3]:  # Test first 3
                        try:
                            test_url = f"{base_url}/{traversal_payload}"
                            async with session.get(test_url) as response:
                                if response.status == 200:
                                    content = await response.text()
                                    if 'root:' in content or 'Administrator' in content:
                                        vulnerabilities.append({
                                            'type': 'Directory Traversal',
                                            'severity': 'Critical',
                                            'description': 'Directory traversal vulnerability detected',
                                            'port': port,
                                            'details': {'payload': traversal_payload}
                                        })
                        except:
                            continue
                    
                    # Common vulnerable paths
                    vulnerable_paths = [
                        '/admin', '/administrator', '/login', '/config',
                        '/backup', '/test', '/debug', '/phpinfo.php',
                        '/.env', '/config.php', '/wp-config.php'
                    ]
                    
                    for path in vulnerable_paths:
                        try:
                            test_url = f"{base_url}{path}"
                            async with session.get(test_url) as response:
                                if response.status == 200:
                                    vulnerabilities.append({
                                        'type': 'Sensitive Path Accessible',
                                        'severity': 'Medium',
                                        'description': f'Sensitive path accessible: {path}',
                                        'port': port,
                                        'details': {'path': path, 'status': response.status}
                                    })
                        except:
                            continue
                
                except Exception as e:
                    print(f"Web security analysis error for {ip_address}:{port}: {e}")
        
        return {'vulnerabilities': vulnerabilities}
    
    async def _test_authentication_security(self, ip_address: str, open_ports: List[Dict]) -> Dict:
        """Test authentication security"""
        vulnerabilities = []
        
        # Test default credentials on various services
        for port_info in open_ports:
            port = port_info.get('port')
            service = port_info.get('service', '').lower()
            
            # Web-based authentication testing
            if service in ['http', 'https'] or port in [80, 443, 8080, 8443]:
                web_auth_vulns = await self._test_web_authentication(ip_address, port, service)
                vulnerabilities.extend(web_auth_vulns)
            
            # SSH authentication testing
            elif service == 'ssh' or port == 22:
                ssh_auth_vulns = await self._test_ssh_authentication(ip_address, port)
                vulnerabilities.extend(ssh_auth_vulns)
            
            # Telnet authentication testing
            elif service == 'telnet' or port == 23:
                telnet_auth_vulns = await self._test_telnet_authentication(ip_address, port)
                vulnerabilities.extend(telnet_auth_vulns)
            
            # FTP authentication testing
            elif service == 'ftp' or port == 21:
                ftp_auth_vulns = await self._test_ftp_authentication(ip_address, port)
                vulnerabilities.extend(ftp_auth_vulns)
        
        return {'vulnerabilities': vulnerabilities}
    
    async def _test_web_authentication(self, ip_address: str, port: int, service: str) -> List[Dict]:
        """Test web-based authentication"""
        vulnerabilities = []
        
        protocol = 'https' if service == 'https' or port == 443 else 'http'
        base_url = f"{protocol}://{ip_address}:{port}"
        
        # Common login paths
        login_paths = ['/login', '/admin', '/administrator', '/auth', '/signin', '/']
        
        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=self.timeout),
            connector=aiohttp.TCPConnector(ssl=False)
        ) as session:
            
            for login_path in login_paths:
                try:
                    login_url = f"{base_url}{login_path}"
                    
                    # Check if login page exists
                    async with session.get(login_url) as response:
                        if response.status != 200:
                            continue
                        
                        content = await response.text()
                        
                        # Look for login forms
                        if any(term in content.lower() for term in ['password', 'login', 'username', 'signin']):
                            
                            # Test default credentials
                            for username, password in self.vulnerability_patterns['default_credentials'][:5]:  # Test first 5
                                try:
                                    # Try form-based authentication
                                    login_data = {
                                        'username': username, 'password': password,
                                        'user': username, 'pass': password,
                                        'login': username, 'pwd': password
                                    }
                                    
                                    async with session.post(login_url, data=login_data) as auth_response:
                                        auth_content = await auth_response.text()
                                        
                                        # Check for successful login indicators
                                        success_indicators = ['dashboard', 'welcome', 'logout', 'admin panel']
                                        failure_indicators = ['invalid', 'incorrect', 'failed', 'error']
                                        
                                        auth_content_lower = auth_content.lower()
                                        
                                        has_success = any(indicator in auth_content_lower for indicator in success_indicators)
                                        has_failure = any(indicator in auth_content_lower for indicator in failure_indicators)
                                        
                                        if has_success and not has_failure:
                                            vulnerabilities.append({
                                                'type': 'Default Credentials',
                                                'severity': 'Critical',
                                                'description': f'Default credentials work: {username}/{password}',
                                                'port': port,
                                                'details': {
                                                    'username': username,
                                                    'password': password,
                                                    'login_url': login_url
                                                }
                                            })
                                            break  # Stop testing once we find working credentials
                                
                                except:
                                    continue
                            
                            # Check for basic auth
                            try:
                                auth_header = f"Basic {base64.b64encode(f'{username}:{password}'.encode()).decode()}"
                                headers = {'Authorization': auth_header}
                                
                                async with session.get(login_url, headers=headers) as auth_response:
                                    if auth_response.status == 200:
                                        vulnerabilities.append({
                                            'type': 'Default HTTP Basic Auth',
                                            'severity': 'Critical',
                                            'description': f'Default HTTP Basic Auth credentials: {username}/{password}',
                                            'port': port,
                                            'details': {'username': username, 'password': password}
                                        })
                            except:
                                pass
                
                except Exception as e:
                    print(f"Web auth testing error for {login_url}: {e}")
        
        return vulnerabilities
    
    async def _test_ssh_authentication(self, ip_address: str, port: int) -> List[Dict]:
        """Test SSH authentication (basic check)"""
        vulnerabilities = []
        
        try:
            # Simple SSH banner grab and basic checks
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            result = sock.connect_ex((ip_address, port))
            if result == 0:
                banner = sock.recv(1024).decode('utf-8', errors='ignore')
                sock.close()
                
                # Check SSH version
                if 'SSH-1.' in banner:
                    vulnerabilities.append({
                        'type': 'Outdated SSH Version',
                        'severity': 'High',
                        'description': 'SSH version 1.x detected (deprecated)',
                        'port': port,
                        'details': {'banner': banner.strip()}
                    })
                
                # Note: Actual credential testing would require paramiko or similar
                # For now, we just flag SSH as potentially vulnerable
                vulnerabilities.append({
                    'type': 'SSH Service Detected',
                    'severity': 'Info',
                    'description': 'SSH service detected - ensure strong authentication',
                    'port': port,
                    'details': {'banner': banner.strip()}
                })
        
        except Exception as e:
            print(f"SSH testing error: {e}")
        
        return vulnerabilities
    
    async def _test_telnet_authentication(self, ip_address: str, port: int) -> List[Dict]:
        """Test Telnet authentication"""
        vulnerabilities = []
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            result = sock.connect_ex((ip_address, port))
            if result == 0:
                # Telnet is inherently insecure
                vulnerabilities.append({
                    'type': 'Insecure Telnet Service',
                    'severity': 'Critical',
                    'description': 'Telnet service detected - unencrypted remote access',
                    'port': port,
                    'details': {'protocol': 'telnet'}
                })
                
                sock.close()
        
        except Exception as e:
            print(f"Telnet testing error: {e}")
        
        return vulnerabilities
    
    async def _test_ftp_authentication(self, ip_address: str, port: int) -> List[Dict]:
        """Test FTP authentication"""
        vulnerabilities = []
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            result = sock.connect_ex((ip_address, port))
            if result == 0:
                response = sock.recv(1024).decode('utf-8', errors='ignore')
                
                # Test anonymous FTP
                sock.send(b'USER anonymous\r\n')
                user_response = sock.recv(1024).decode('utf-8', errors='ignore')
                
                if '331' in user_response:  # User name okay, need password
                    sock.send(b'PASS anonymous@example.com\r\n')
                    pass_response = sock.recv(1024).decode('utf-8', errors='ignore')
                    
                    if '230' in pass_response:  # User logged in
                        vulnerabilities.append({
                            'type': 'Anonymous FTP Access',
                            'severity': 'Medium',
                            'description': 'Anonymous FTP access is enabled',
                            'port': port,
                            'details': {'access_type': 'anonymous'}
                        })
                
                sock.close()
        
        except Exception as e:
            print(f"FTP testing error: {e}")
        
        return vulnerabilities
    
    async def _analyze_network_services(self, ip_address: str, open_ports: List[Dict]) -> Dict:
        """Analyze network services for vulnerabilities"""
        vulnerabilities = []
        
        for port_info in open_ports:
            port = port_info.get('port')
            service = port_info.get('service', '').lower()
            
            # Check for dangerous services
            dangerous_services = {
                'telnet': 'Critical',
                'rsh': 'Critical',
                'rlogin': 'Critical',
                'ftp': 'Medium',
                'tftp': 'High',
                'finger': 'Medium',
                'echo': 'Low',
                'chargen': 'Low'
            }
            
            if service in dangerous_services:
                vulnerabilities.append({
                    'type': 'Dangerous Network Service',
                    'severity': dangerous_services[service],
                    'description': f'Potentially dangerous service detected: {service}',
                    'port': port,
                    'details': {'service': service}
                })
            
            # Check for services on unusual ports
            standard_ports = {
                21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp',
                53: 'dns', 80: 'http', 110: 'pop3', 143: 'imap',
                443: 'https', 993: 'imaps', 995: 'pop3s'
            }
            
            if port not in standard_ports and port < 1024:
                vulnerabilities.append({
                    'type': 'Service on Unusual Port',
                    'severity': 'Low',
                    'description': f'Service running on unusual privileged port: {port}',
                    'port': port,
                    'details': {'service': service}
                })
        
        return {'vulnerabilities': vulnerabilities}
    
    async def _analyze_firmware_security(self, ip_address: str, open_ports: List[Dict]) -> Dict:
        """Analyze firmware-related security issues"""
        vulnerabilities = []
        
        # Check for firmware update mechanisms
        web_ports = [port for port in open_ports if port.get('service') in ['http', 'https'] or port.get('port') in [80, 443, 8080, 8443]]
        
        if web_ports:
            async with aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=self.timeout),
                connector=aiohttp.TCPConnector(ssl=False)
            ) as session:
                
                for port_info in web_ports:
                    port = port_info.get('port')
                    service = port_info.get('service', '')
                    
                    protocol = 'https' if service == 'https' or port == 443 else 'http'
                    base_url = f"{protocol}://{ip_address}:{port}"
                    
                    # Check for firmware-related paths
                    firmware_paths = [
                        '/firmware', '/update', '/upgrade', '/flash',
                        '/admin/firmware', '/system/update', '/config/firmware'
                    ]
                    
                    for path in firmware_paths:
                        try:
                            test_url = f"{base_url}{path}"
                            async with session.get(test_url) as response:
                                if response.status == 200:
                                    content = await response.text()
                                    
                                    if any(term in content.lower() for term in ['firmware', 'update', 'upgrade', 'flash']):
                                        vulnerabilities.append({
                                            'type': 'Firmware Update Interface',
                                            'severity': 'Medium',
                                            'description': f'Firmware update interface accessible at {path}',
                                            'port': port,
                                            'details': {'path': path}
                                        })
                        except:
                            continue
        
        return {'vulnerabilities': vulnerabilities}
    
    def _calculate_security_score(self, vulnerabilities: List[Dict]) -> int:
        """Calculate overall security score based on vulnerabilities"""
        if not vulnerabilities:
            return 100
        
        score = 100
        
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'Low').lower()
            
            if severity == 'critical':
                score -= 25
            elif severity == 'high':
                score -= 15
            elif severity == 'medium':
                score -= 8
            elif severity == 'low':
                score -= 3
        
        return max(0, score)
    
    def _determine_risk_level(self, security_score: int) -> str:
        """Determine risk level based on security score"""
        if security_score >= 80:
            return 'Low'
        elif security_score >= 60:
            return 'Medium'
        elif security_score >= 40:
            return 'High'
        else:
            return 'Critical'
    
    def _generate_recommendations(self, vulnerabilities: List[Dict]) -> List[str]:
        """Generate security recommendations based on vulnerabilities"""
        recommendations = []
        
        vuln_types = [vuln.get('type', '') for vuln in vulnerabilities]
        
        if any('Default Credentials' in vtype for vtype in vuln_types):
            recommendations.append('تغيير جميع كلمات المرور الافتراضية فوراً')
        
        if any('SSL' in vtype or 'TLS' in vtype for vtype in vuln_types):
            recommendations.append('تحديث إعدادات SSL/TLS وإزالة البروتوكولات الضعيفة')
        
        if any('Security Header' in vtype for vtype in vuln_types):
            recommendations.append('إضافة رؤوس الأمان المفقودة للواجهات الويب')
        
        if any('Telnet' in vtype or 'FTP' in vtype for vtype in vuln_types):
            recommendations.append('تعطيل الخدمات غير الآمنة واستخدام بدائل مشفرة')
        
        if any('Directory Traversal' in vtype for vtype in vuln_types):
            recommendations.append('تطبيق تصحيحات أمنية للثغرات الحرجة فوراً')
        
        # General recommendations
        recommendations.extend([
            'تحديث البرامج الثابتة إلى أحدث الإصدارات',
            'تفعيل جدار الحماية وتقييد الوصول للشبكة',
            'مراقبة سجلات النظام بانتظام',
            'إجراء فحوصات أمنية دورية'
        ])
        
        return list(set(recommendations))  # Remove duplicates

