"""
Advanced Encryption Quality Analyzer
Evaluates encryption strength and cryptographic algorithm quality
"""

import logging
from typing import Dict, List, Optional
from datetime import datetime
import hashlib

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class EncryptionAnalyzer:
    """
    Advanced encryption quality assessment
    Evaluates cryptographic algorithms and implementations
    """
    
    # Algorithm strength ratings (0-100)
    ALGORITHM_STRENGTH = {
        # Symmetric encryption
        'AES-256-GCM': 100,
        'AES-256-CBC': 95,
        'AES-128-GCM': 90,
        'AES-128-CBC': 85,
        'ChaCha20-Poly1305': 100,
        '3DES': 40,
        'DES': 10,
        'RC4': 5,
        'RC2': 5,
        
        # Hash algorithms
        'SHA-512': 100,
        'SHA-384': 95,
        'SHA-256': 90,
        'SHA-224': 85,
        'SHA-1': 30,
        'MD5': 10,
        'MD4': 5,
        
        # Key exchange
        'ECDHE': 100,
        'DHE': 85,
        'RSA': 70,
        'DH': 60,
        'EXPORT': 5,
        'ANON': 0,
    }
    
    # Known weak/broken algorithms
    BROKEN_ALGORITHMS = [
        'DES', 'RC2', 'RC4', 'MD4', 'MD5', 'SHA-1 (for signatures)',
        'EXPORT', 'NULL', 'ANON'
    ]
    
    # Minimum key lengths (bits)
    MINIMUM_KEY_LENGTHS = {
        'RSA': 2048,
        'DSA': 2048,
        'DH': 2048,
        'ECC': 256,
        'AES': 128
    }
    
    def __init__(self):
        """Initialize encryption analyzer"""
        self.findings = []
        self.vulnerabilities = []
    
    def evaluate_algorithm(self, algorithm: str, key_length: Optional[int] = None) -> Dict:
        """
        Evaluate cryptographic algorithm strength
        
        Args:
            algorithm: Algorithm name
            key_length: Key length in bits (if applicable)
            
        Returns:
            Evaluation results
        """
        result = {
            'algorithm': algorithm,
            'key_length': key_length,
            'strength_score': 0,
            'rating': 'Unknown',
            'issues': []
        }
        
        # Get strength score
        algo_upper = algorithm.upper()
        for known_algo, score in self.ALGORITHM_STRENGTH.items():
            if known_algo.upper() in algo_upper:
                result['strength_score'] = score
                break
        
        # Rate the algorithm
        if result['strength_score'] >= 90:
            result['rating'] = 'Strong'
        elif result['strength_score'] >= 70:
            result['rating'] = 'Acceptable'
        elif result['strength_score'] >= 50:
            result['rating'] = 'Weak'
        else:
            result['rating'] = 'Broken'
        
        # Check if algorithm is broken
        if any(broken in algo_upper for broken in self.BROKEN_ALGORITHMS):
            result['issues'].append({
                'type': 'Broken Algorithm',
                'severity': 'Critical',
                'description': f'{algorithm} is cryptographically broken',
                'recommendation': 'Replace with modern algorithm (AES-256-GCM, ChaCha20-Poly1305)'
            })
            self.vulnerabilities.append(result['issues'][-1])
        
        # Check key length
        if key_length:
            for algo_type, min_length in self.MINIMUM_KEY_LENGTHS.items():
                if algo_type in algo_upper and key_length < min_length:
                    result['issues'].append({
                        'type': 'Insufficient Key Length',
                        'severity': 'High',
                        'description': f'{algorithm} key length ({key_length} bits) below minimum ({min_length} bits)',
                        'recommendation': f'Use minimum {min_length}-bit keys'
                    })
                    self.vulnerabilities.append(result['issues'][-1])
        
        return result
    
    def evaluate_cipher_suite(self, cipher_suite: str) -> Dict:
        """
        Evaluate complete cipher suite
        
        Args:
            cipher_suite: Full cipher suite name
            
        Returns:
            Evaluation results
        """
        result = {
            'cipher_suite': cipher_suite,
            'components': {},
            'overall_strength': 0,
            'issues': []
        }
        
        # Parse cipher suite components
        # Example: TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
        parts = cipher_suite.split('_')
        
        # Extract key exchange
        if 'ECDHE' in cipher_suite:
            result['components']['key_exchange'] = 'ECDHE'
        elif 'DHE' in cipher_suite:
            result['components']['key_exchange'] = 'DHE'
        elif 'RSA' in cipher_suite and 'ECDHE' not in cipher_suite:
            result['components']['key_exchange'] = 'RSA'
        
        # Extract encryption
        if 'AES_256_GCM' in cipher_suite:
            result['components']['encryption'] = 'AES-256-GCM'
        elif 'AES_128_GCM' in cipher_suite:
            result['components']['encryption'] = 'AES-128-GCM'
        elif 'AES_256_CBC' in cipher_suite:
            result['components']['encryption'] = 'AES-256-CBC'
        elif 'AES_128_CBC' in cipher_suite:
            result['components']['encryption'] = 'AES-128-CBC'
        elif 'CHACHA20' in cipher_suite:
            result['components']['encryption'] = 'ChaCha20-Poly1305'
        
        # Extract MAC/AEAD
        if 'SHA384' in cipher_suite:
            result['components']['mac'] = 'SHA-384'
        elif 'SHA256' in cipher_suite:
            result['components']['mac'] = 'SHA-256'
        elif 'SHA' in cipher_suite:
            result['components']['mac'] = 'SHA-1'
        elif 'GCM' in cipher_suite or 'POLY1305' in cipher_suite:
            result['components']['mac'] = 'AEAD (Authenticated Encryption)'
        
        # Calculate overall strength
        strengths = []
        for component_type, component_name in result['components'].items():
            eval_result = self.evaluate_algorithm(component_name)
            strengths.append(eval_result['strength_score'])
            
            if eval_result['issues']:
                result['issues'].extend(eval_result['issues'])
        
        if strengths:
            result['overall_strength'] = sum(strengths) / len(strengths)
        
        # Check for forward secrecy
        if result['components'].get('key_exchange') in ['ECDHE', 'DHE']:
            result['forward_secrecy'] = True
        else:
            result['forward_secrecy'] = False
            result['issues'].append({
                'type': 'No Forward Secrecy',
                'severity': 'Medium',
                'description': 'Cipher suite does not provide forward secrecy',
                'recommendation': 'Use ECDHE or DHE key exchange'
            })
        
        return result
    
    def check_protocol_downgrade(self, supported_protocols: List[str]) -> Dict:
        """
        Check for protocol downgrade vulnerabilities
        
        Args:
            supported_protocols: List of supported protocol versions
            
        Returns:
            Downgrade attack assessment
        """
        result = {
            'vulnerable': False,
            'severity': 'High',
            'details': []
        }
        
        # If both old and new protocols are supported
        old_protocols = [p for p in supported_protocols if p in ['SSLv2', 'SSLv3', 'TLSv1.0']]
        new_protocols = [p for p in supported_protocols if p in ['TLSv1.2', 'TLSv1.3']]
        
        if old_protocols and new_protocols:
            result['vulnerable'] = True
            result['details'].append(
                f'Server supports both old ({", ".join(old_protocols)}) and '
                f'new ({", ".join(new_protocols)}) protocols'
            )
            result['recommendation'] = 'Disable deprecated protocols to prevent downgrade attacks'
            
            vuln = {
                'type': 'Protocol Downgrade Risk',
                'severity': 'High',
                'description': result['details'][0],
                'recommendation': result['recommendation']
            }
            self.vulnerabilities.append(vuln)
        
        return result
    
    def assess_encryption_quality(self, device_info: Dict) -> Dict:
        """
        Assess overall encryption quality for a device
        
        Args:
            device_info: Device information including protocols and ciphers
            
        Returns:
            Quality assessment
        """
        assessment = {
            'overall_score': 100,
            'strengths': [],
            'weaknesses': [],
            'recommendations': []
        }
        
        # Check if any encryption is used
        has_encryption = False
        
        # Check for HTTPS
        if 443 in device_info.get('open_ports', []) or 8443 in device_info.get('open_ports', []):
            has_encryption = True
            assessment['strengths'].append('HTTPS enabled')
        
        # Check for secure protocol ports
        secure_ports = [8883, 5684, 8000]  # MQTTS, CoAPS, etc.
        if any(port in device_info.get('open_ports', []) for port in secure_ports):
            has_encryption = True
            assessment['strengths'].append('Secure protocol ports detected')
        
        # Check for insecure ports
        insecure_ports = [80, 23, 21, 1883, 5683]  # HTTP, Telnet, FTP, MQTT, CoAP
        exposed_insecure = [p for p in device_info.get('open_ports', []) if p in insecure_ports]
        
        if exposed_insecure:
            assessment['weaknesses'].append(f'Insecure ports exposed: {exposed_insecure}')
            assessment['overall_score'] -= len(exposed_insecure) * 10
        
        if not has_encryption:
            assessment['weaknesses'].append('No encryption detected')
            assessment['overall_score'] -= 50
            assessment['recommendations'].append('Enable encryption (HTTPS, TLS, DTLS)')
        
        return assessment


# Example usage
async def main():
    """Test encryption analyzer"""
    print("="*70)
    print("Encryption Quality Analyzer - Phase 6")
    print("="*70)
    
    analyzer = EncryptionAnalyzer()
    
    # Test cipher suite evaluation
    test_suites = [
        'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
        'TLS_RSA_WITH_AES_128_CBC_SHA',
        'TLS_RSA_WITH_RC4_128_SHA',
        'TLS_RSA_WITH_3DES_EDE_CBC_SHA'
    ]
    
    print("\nEvaluating Cipher Suites:")
    print("-" * 70)
    
    for suite in test_suites:
        result = analyzer.evaluate_cipher_suite(suite)
        print(f"\n{suite}")
        print(f"  Strength: {result['overall_strength']:.0f}/100")
        print(f"  Forward Secrecy: {'Yes' if result['forward_secrecy'] else 'No'}")
        
        if result['issues']:
            print(f"  Issues:")
            for issue in result['issues']:
                print(f"    - [{issue['severity']}] {issue['type']}")


if __name__ == '__main__':
    asyncio.run(main())
