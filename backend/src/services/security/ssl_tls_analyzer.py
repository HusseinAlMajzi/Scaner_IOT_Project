"""
Advanced SSL/TLS Security Analyzer
Performs comprehensive SSL/TLS vulnerability assessment and certificate validation
"""

import asyncio
import logging
import ssl
import socket
from typing import Dict, List, Optional
from datetime import datetime, timedelta
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes

try:
    import OpenSSL
    HAS_OPENSSL = True
except ImportError:
    HAS_OPENSSL = False
    logging.warning("pyOpenSSL not available")

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class SSLTLSAnalyzer:
    """
    Advanced SSL/TLS security analyzer
    Tests for vulnerabilities, weak ciphers, certificate issues
    """
    
    # Weak/deprecated cipher suites
    WEAK_CIPHERS = [
        'NULL', 'EXPORT', 'DES', 'RC4', 'RC2', 'MD5',
        'anon', 'ADH', 'AECDH', 'PSK'
    ]
    
    # Known SSL/TLS vulnerabilities
    KNOWN_VULNERABILITIES = {
        'POODLE': {
            'affects': ['SSLv3'],
            'severity': 'High',
            'description': 'SSLv3 vulnerable to POODLE attack'
        },
        'BEAST': {
            'affects': ['TLSv1.0'],
            'severity': 'Medium',
            'description': 'TLS 1.0 vulnerable to BEAST attack'
        },
        'CRIME': {
            'affects': ['compression'],
            'severity': 'Medium',
            'description': 'TLS compression vulnerable to CRIME attack'
        },
        'HEARTBLEED': {
            'affects': ['heartbeat'],
            'severity': 'Critical',
            'description': 'OpenSSL Heartbleed vulnerability'
        },
        'FREAK': {
            'affects': ['EXPORT'],
            'severity': 'High',
            'description': 'Export-grade cipher vulnerability'
        },
        'LOGJAM': {
            'affects': ['DHE_EXPORT'],
            'severity': 'High',
            'description': 'Weak Diffie-Hellman parameters'
        },
        'DROWN': {
            'affects': ['SSLv2'],
            'severity': 'Critical',
            'description': 'SSLv2 vulnerable to DROWN attack'
        }
    }
    
    def __init__(self):
        """Initialize SSL/TLS analyzer"""
        self.vulnerabilities = []
    
    def get_ssl_context(self, protocol_version=None):
        """Create SSL context for testing"""
        if protocol_version:
            context = ssl.SSLContext(protocol_version)
        else:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        return context
    
    async def test_ssl_version(self, host: str, port: int, 
                               protocol_version, timeout: int = 5) -> bool:
        """
        Test if specific SSL/TLS version is supported
        
        Args:
            host: Target host
            port: Target port
            protocol_version: SSL/TLS protocol version to test
            timeout: Connection timeout
            
        Returns:
            True if protocol is supported
        """
        try:
            context = self.get_ssl_context(protocol_version)
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            
            ssl_sock = context.wrap_socket(sock)
            ssl_sock.connect((host, port))
            ssl_sock.close()
            
            return True
        except Exception as e:
            logger.debug(f"Protocol {protocol_version} not supported: {e}")
            return False
    
    async def test_supported_protocols(self, host: str, port: int) -> Dict:
        """
        Test which SSL/TLS protocols are supported
        
        Args:
            host: Target host
            port: Target port
            
        Returns:
            Dictionary of protocol support results
        """
        result = {
            'supported_protocols': [],
            'deprecated_protocols': [],
            'vulnerabilities': []
        }
        
        protocols_to_test = {
            'SSLv2': getattr(ssl, 'PROTOCOL_SSLv2', None),
            'SSLv3': getattr(ssl, 'PROTOCOL_SSLv3', None),
            'TLSv1.0': getattr(ssl, 'PROTOCOL_TLSv1', None),
            'TLSv1.1': getattr(ssl, 'PROTOCOL_TLSv1_1', None),
            'TLSv1.2': getattr(ssl, 'PROTOCOL_TLSv1_2', None),
            'TLSv1.3': getattr(ssl, 'PROTOCOL_TLS', None),
        }
        
        for protocol_name, protocol_version in protocols_to_test.items():
            if protocol_version is None:
                continue
            
            try:
                supported = await self.test_ssl_version(host, port, protocol_version)
                
                if supported:
                    result['supported_protocols'].append(protocol_name)
                    
                    # Check for deprecated protocols
                    if protocol_name in ['SSLv2', 'SSLv3', 'TLSv1.0']:
                        result['deprecated_protocols'].append(protocol_name)
                        
                        # Add vulnerability
                        if protocol_name == 'SSLv2':
                            vuln = {
                                'type': 'DROWN Attack',
                                'severity': 'Critical',
                                'description': 'SSLv2 is enabled (DROWN vulnerability)',
                                'protocol': protocol_name,
                                'recommendation': 'Disable SSLv2 immediately'
                            }
                            result['vulnerabilities'].append(vuln)
                            self.vulnerabilities.append(vuln)
                        
                        elif protocol_name == 'SSLv3':
                            vuln = {
                                'type': 'POODLE Attack',
                                'severity': 'High',
                                'description': 'SSLv3 is enabled (POODLE vulnerability)',
                                'protocol': protocol_name,
                                'recommendation': 'Disable SSLv3'
                            }
                            result['vulnerabilities'].append(vuln)
                            self.vulnerabilities.append(vuln)
            
            except Exception as e:
                logger.debug(f"Error testing {protocol_name}: {e}")
        
        return result
    
    def get_certificate(self, host: str, port: int, timeout: int = 5) -> Optional[Dict]:
        """
        Retrieve SSL certificate
        
        Args:
            host: Target host
            port: Target port
            timeout: Connection timeout
            
        Returns:
            Certificate information dictionary
        """
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((host, port), timeout=timeout) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssl_sock:
                    cert_der = ssl_sock.getpeercert(binary_form=True)
                    cert_pem = ssl.DER_cert_to_PEM_cert(cert_der)
                    
                    # Parse certificate
                    cert = x509.load_pem_x509_certificate(
                        cert_pem.encode(),
                        default_backend()
                    )
                    
                    return {
                        'subject': cert.subject.rfc4514_string(),
                        'issuer': cert.issuer.rfc4514_string(),
                        'version': cert.version.value,
                        'serial_number': cert.serial_number,
                        'not_valid_before': cert.not_valid_before_utc,
                        'not_valid_after': cert.not_valid_after_utc,
                        'signature_algorithm': cert.signature_algorithm_oid._name,
                        'raw_cert': cert
                    }
        
        except Exception as e:
            logger.error(f"Error retrieving certificate: {e}")
            return None
    
    def validate_certificate(self, cert_info: Dict) -> Dict:
        """
        Validate certificate for security issues
        
        Args:
            cert_info: Certificate information
            
        Returns:
            Validation results
        """
        result = {
            'valid': True,
            'issues': [],
            'vulnerabilities': []
        }
        
        if not cert_info:
            return result
        
        # Check expiration
        now = datetime.now(cert_info['not_valid_after'].tzinfo)
        days_until_expiry = (cert_info['not_valid_after'] - now).days
        
        if days_until_expiry < 0:
            result['valid'] = False
            issue = {
                'type': 'Expired Certificate',
                'severity': 'Critical',
                'description': f'Certificate expired {abs(days_until_expiry)} days ago',
                'recommendation': 'Renew certificate immediately'
            }
            result['issues'].append(issue)
            result['vulnerabilities'].append(issue)
            self.vulnerabilities.append(issue)
        
        elif days_until_expiry < 30:
            issue = {
                'type': 'Certificate Expiring Soon',
                'severity': 'Medium',
                'description': f'Certificate expires in {days_until_expiry} days',
                'recommendation': 'Renew certificate soon'
            }
            result['issues'].append(issue)
        
        # Check signature algorithm
        weak_algorithms = ['md5', 'sha1']
        sig_algo = cert_info['signature_algorithm'].lower()
        
        if any(weak in sig_algo for weak in weak_algorithms):
            issue = {
                'type': 'Weak Signature Algorithm',
                'severity': 'High',
                'description': f'Certificate uses weak signature: {sig_algo}',
                'recommendation': 'Use SHA-256 or stronger'
            }
            result['issues'].append(issue)
            result['vulnerabilities'].append(issue)
            self.vulnerabilities.append(issue)
        
        # Check certificate validity period
        cert_lifetime = (cert_info['not_valid_after'] - cert_info['not_valid_before']).days
        if cert_lifetime > 825:  # Apple/Google limit
            issue = {
                'type': 'Long Certificate Validity',
                'severity': 'Low',
                'description': f'Certificate valid for {cert_lifetime} days (exceeds 825-day limit)',
                'recommendation': 'Use certificates with shorter validity periods'
            }
            result['issues'].append(issue)
        
        # Check self-signed
        if cert_info['subject'] == cert_info['issuer']:
            issue = {
                'type': 'Self-Signed Certificate',
                'severity': 'Medium',
                'description': 'Certificate is self-signed',
                'recommendation': 'Use certificate from trusted CA'
            }
            result['issues'].append(issue)
        
        return result
    
    def analyze_cipher_suites(self, host: str, port: int) -> Dict:
        """
        Analyze supported cipher suites
        
        Args:
            host: Target host
            port: Target port
            
        Returns:
            Cipher suite analysis
        """
        result = {
            'weak_ciphers': [],
            'strong_ciphers': [],
            'vulnerabilities': []
        }
        
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((host, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssl_sock:
                    cipher = ssl_sock.cipher()
                    
                    if cipher:
                        cipher_name = cipher[0]
                        protocol = cipher[1]
                        bits = cipher[2]
                        
                        # Check for weak ciphers
                        is_weak = any(weak in cipher_name.upper() for weak in self.WEAK_CIPHERS)
                        
                        if is_weak or bits < 128:
                            result['weak_ciphers'].append(cipher_name)
                            
                            vuln = {
                                'type': 'Weak Cipher Suite',
                                'severity': 'High',
                                'description': f'Weak cipher in use: {cipher_name} ({bits} bits)',
                                'recommendation': 'Disable weak ciphers, use AES-256-GCM or ChaCha20-Poly1305'
                            }
                            result['vulnerabilities'].append(vuln)
                            self.vulnerabilities.append(vuln)
                        else:
                            result['strong_ciphers'].append(cipher_name)
        
        except Exception as e:
            logger.error(f"Error analyzing ciphers: {e}")
        
        return result
    
    async def comprehensive_analysis(self, host: str, port: int = 443) -> Dict:
        """
        Run comprehensive SSL/TLS security analysis
        
        Args:
            host: Target host
            port: Target port (default 443)
            
        Returns:
            Complete analysis report
        """
        logger.info(f"Starting SSL/TLS analysis for {host}:{port}")
        
        report = {
            'host': host,
            'port': port,
            'timestamp': datetime.now().isoformat(),
            'protocol_support': {},
            'certificate': {},
            'cipher_analysis': {},
            'vulnerabilities': [],
            'security_score': 100
        }
        
        # Test protocol support
        protocol_result = await self.test_supported_protocols(host, port)
        report['protocol_support'] = protocol_result
        
        if protocol_result['deprecated_protocols']:
            report['security_score'] -= len(protocol_result['deprecated_protocols']) * 20
        
        # Get and validate certificate
        cert_info = self.get_certificate(host, port)
        if cert_info:
            report['certificate'] = {
                'subject': cert_info['subject'],
                'issuer': cert_info['issuer'],
                'valid_from': cert_info['not_valid_before'].isoformat(),
                'valid_until': cert_info['not_valid_after'].isoformat(),
                'signature_algorithm': cert_info['signature_algorithm']
            }
            
            cert_validation = self.validate_certificate(cert_info)
            report['certificate']['validation'] = cert_validation
            
            if not cert_validation['valid']:
                report['security_score'] -= 30
            if cert_validation['issues']:
                report['security_score'] -= len(cert_validation['issues']) * 10
        
        # Analyze cipher suites
        cipher_result = self.analyze_cipher_suites(host, port)
        report['cipher_analysis'] = cipher_result
        
        if cipher_result['weak_ciphers']:
            report['security_score'] -= len(cipher_result['weak_ciphers']) * 15
        
        # Compile all vulnerabilities
        report['vulnerabilities'] = self.vulnerabilities
        report['security_score'] = max(0, report['security_score'])
        
        logger.info(f"SSL/TLS analysis complete. Security score: {report['security_score']}/100")
        
        return report


# Example usage
async def main():
    """Test SSL/TLS analyzer"""
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python ssl_tls_analyzer.py <host> [port]")
        print("Example: python ssl_tls_analyzer.py google.com 443")
        sys.exit(1)
    
    host = sys.argv[1]
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 443
    
    print("="*70)
    print(f"SSL/TLS Security Analysis: {host}:{port}")
    print("="*70)
    
    analyzer = SSLTLSAnalyzer()
    report = await analyzer.comprehensive_analysis(host, port)
    
    print(f"\n{'='*70}")
    print("Analysis Results")
    print(f"{'='*70}")
    
    print(f"\nSecurity Score: {report['security_score']}/100")
    
    print(f"\nSupported Protocols:")
    for protocol in report['protocol_support']['supported_protocols']:
        deprecated = " (DEPRECATED)" if protocol in report['protocol_support']['deprecated_protocols'] else ""
        print(f"  ✓ {protocol}{deprecated}")
    
    if report.get('certificate'):
        print(f"\nCertificate:")
        print(f"  Subject: {report['certificate']['subject']}")
        print(f"  Issuer: {report['certificate']['issuer']}")
        print(f"  Valid Until: {report['certificate']['valid_until']}")
        print(f"  Signature: {report['certificate']['signature_algorithm']}")
    
    print(f"\nVulnerabilities Found: {len(report['vulnerabilities'])}")
    for vuln in report['vulnerabilities']:
        print(f"\n  [{vuln['severity']}] {vuln['type']}")
        print(f"  {vuln['description']}")
        if vuln.get('recommendation'):
            print(f"  → {vuln['recommendation']}")


if __name__ == '__main__':
    asyncio.run(main())
