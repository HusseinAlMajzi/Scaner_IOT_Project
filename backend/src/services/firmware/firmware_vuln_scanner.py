"""
Firmware Vulnerability Scanner
Scans firmware for known vulnerabilities and security issues
"""

import os
import re
import logging
from typing import Dict, List, Optional
from datetime import datetime
import subprocess

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class FirmwareVulnerabilityScanner:
    """
    Scans firmware for security vulnerabilities
    """
    
    # Known vulnerable libraries/components
    VULNERABLE_COMPONENTS = {
        'busybox': {
            'vulnerable_versions': ['<1.30.0'],
            'cves': ['CVE-2021-28831', 'CVE-2022-30065']
        },
        'openssl': {
            'vulnerable_versions': ['<1.0.2', '<1.1.1'],
            'cves': ['CVE-2014-0160', 'CVE-2016-2107']  # Heartbleed, Padding Oracle
        },
        'dropbear': {
            'vulnerable_versions': ['<2020.80'],
            'cves': ['CVE-2021-36369']
        },
        'dnsmasq': {
            'vulnerable_versions': ['<2.86'],
            'cves': ['CVE-2020-25681', 'CVE-2020-25682']
        },
        'lighttpd': {
            'vulnerable_versions': ['<1.4.60'],
            'cves': ['CVE-2022-22707']
        },
        'upnp': {
            'vulnerable_versions': ['*'],
            'cves': ['CVE-2020-12695']  # CallStranger
        }
    }
    
    # Dangerous function patterns
    DANGEROUS_FUNCTIONS = {
        'command_injection': [
            r'system\s*\(',
            r'exec\s*\(',
            r'popen\s*\(',
            r'shell_exec\s*\(',
            r'passthru\s*\(',
        ],
        'buffer_overflow': [
            r'strcpy\s*\(',
            r'strcat\s*\(',
            r'sprintf\s*\(',
            r'gets\s*\(',
        ],
        'format_string': [
            r'printf\s*\([^,]*\)',
            r'fprintf\s*\([^,]*,[^,]*\)',
        ],
        'path_traversal': [
            r'\.\./\.\./',
            r'\.\.\\\.\.\\',
        ]
    }
    
    def __init__(self):
        """Initialize firmware vulnerability scanner"""
        self.vulnerabilities = []
        self.components_found = []
    
    def detect_components(self, extracted_dir: str) -> List[Dict]:
        """
        Detect software components and their versions
        
        Args:
            extracted_dir: Directory with extracted firmware
            
        Returns:
            List of detected components
        """
        components = []
        
        try:
            # Search for version strings
            for root, dirs, files in os.walk(extracted_dir):
                for file in files:
                    if file in ['busybox', 'dropbear', 'lighttpd', 'dnsmasq']:
                        file_path = os.path.join(root, file)
                        
                        # Try to get version
                        try:
                            result = subprocess.run(
                                [file_path, '--version'],
                                capture_output=True,
                                text=True,
                                timeout=2
                            )
                            version_output = result.stdout + result.stderr
                            
                            # Extract version number
                            version_match = re.search(r'v?(\d+\.\d+\.?\d*)', version_output)
                            version = version_match.group(1) if version_match else 'Unknown'
                            
                            component = {
                                'name': file,
                                'version': version,
                                'path': file_path
                            }
                            components.append(component)
                            logger.info(f"Found {file} version {version}")
                        
                        except:
                            pass
        
        except Exception as e:
            logger.error(f"Error detecting components: {e}")
        
        self.components_found = components
        return components
    
    def check_component_vulnerabilities(self, components: List[Dict]) -> List[Dict]:
        """
        Check components against known vulnerabilities
        
        Args:
            components: List of detected components
            
        Returns:
            List of vulnerabilities
        """
        vulnerabilities = []
        
        for component in components:
            comp_name = component['name'].lower()
            comp_version = component['version']
            
            if comp_name in self.VULNERABLE_COMPONENTS:
                vuln_info = self.VULNERABLE_COMPONENTS[comp_name]
                
                # Check if version is vulnerable
                is_vulnerable = False
                for vuln_version in vuln_info['vulnerable_versions']:
                    if '<' in vuln_version:
                        # Simple version comparison
                        max_version = vuln_version.replace('<', '')
                        if comp_version < max_version:
                            is_vulnerable = True
                    elif vuln_version == '*':
                        is_vulnerable = True
                
                if is_vulnerable:
                    for cve in vuln_info['cves']:
                        vuln = {
                            'component': comp_name,
                            'version': comp_version,
                            'cve_id': cve,
                            'severity': 'High',
                            'description': f'Vulnerable {comp_name} version {comp_version} ({cve})',
                            'recommendation': f'Update {comp_name} to latest version'
                        }
                        vulnerabilities.append(vuln)
                        logger.warning(f"Vulnerability found: {cve} in {comp_name}")
        
        self.vulnerabilities.extend(vulnerabilities)
        return vulnerabilities
    
    def scan_for_dangerous_functions(self, extracted_dir: str) -> List[Dict]:
        """
        Scan for dangerous function usage
        
        Args:
            extracted_dir: Directory with extracted firmware
            
        Returns:
            List of dangerous function findings
        """
        findings = []
        
        try:
            # Search in binary and script files
            for root, dirs, files in os.walk(extracted_dir):
                for file in files[:100]:  # Limit to first 100 files
                    file_path = os.path.join(root, file)
                    
                    # Skip very large files
                    if os.path.getsize(file_path) > 10 * 1024 * 1024:  # 10MB
                        continue
                    
                    try:
                        with open(file_path, 'r', errors='ignore') as f:
                            content = f.read()
                        
                        # Search for dangerous patterns
                        for func_category, patterns in self.DANGEROUS_FUNCTIONS.items():
                            for pattern in patterns:
                                matches = re.findall(pattern, content)
                                
                                if matches:
                                    finding = {
                                        'category': func_category,
                                        'pattern': pattern,
                                        'file': os.path.basename(file_path),
                                        'occurrences': len(matches),
                                        'severity': 'High' if func_category in ['command_injection', 'buffer_overflow'] else 'Medium',
                                        'description': f'Dangerous function usage: {func_category}'
                                    }
                                    findings.append(finding)
                    
                    except:
                        continue
        
        except Exception as e:
            logger.error(f"Error scanning for dangerous functions: {e}")
        
        return findings
    
    def check_security_features(self, firmware_path: str) -> Dict:
        """
        Check for security features in firmware binary
        
        Args:
            firmware_path: Path to firmware file
            
        Returns:
            Security features analysis
        """
        features = {
            'stack_canary': False,
            'nx_bit': False,
            'pie': False,
            'relro': False,
            'fortify': False,
            'findings': []
        }
        
        try:
            # Use checksec if available
            try:
                result = subprocess.run(
                    ['checksec', '--file', firmware_path],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                
                output = result.stdout.lower()
                
                features['stack_canary'] = 'canary found' in output
                features['nx_bit'] = 'nx enabled' in output
                features['pie'] = 'pie enabled' in output
                features['relro'] = 'full relro' in output or 'partial relro' in output
                features['fortify'] = 'fortify' in output
                
            except FileNotFoundError:
                logger.warning("checksec not available, using alternative method")
                
                # Alternative: use readelf
                result = subprocess.run(
                    ['readelf', '-h', firmware_path],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                
                output = result.stdout
                
                # Check for security features
                if 'DYN' in output:
                    features['pie'] = True
                if 'GNU_RELRO' in output:
                    features['relro'] = True
            
            # Generate findings
            if not features['stack_canary']:
                features['findings'].append({
                    'issue': 'No Stack Canary',
                    'severity': 'Medium',
                    'description': 'Binary compiled without stack protection'
                })
            
            if not features['nx_bit']:
                features['findings'].append({
                    'issue': 'No NX Bit',
                    'severity': 'High',
                    'description': 'Executable stack - buffer overflow risk'
                })
            
            if not features['pie']:
                features['findings'].append({
                    'issue': 'No PIE',
                    'severity': 'Medium',
                    'description': 'Binary not position independent'
                })
        
        except Exception as e:
            logger.error(f"Error checking security features: {e}")
        
        return features
    
    def generate_vulnerability_report(self) -> Dict:
        """Generate comprehensive vulnerability report"""
        report = {
            'timestamp': datetime.now().isoformat(),
            'total_vulnerabilities': len(self.vulnerabilities),
            'vulnerabilities': self.vulnerabilities,
            'components_analyzed': len(self.components_found),
            'components': self.components_found,
            'severity_distribution': {
                'Critical': 0,
                'High': 0,
                'Medium': 0,
                'Low': 0
            },
            'recommendations': []
        }
        
        # Count by severity
        for vuln in self.vulnerabilities:
            severity = vuln.get('severity', 'Medium')
            report['severity_distribution'][severity] += 1
        
        # Generate recommendations
        if report['severity_distribution']['Critical'] > 0:
            report['recommendations'].append(
                'URGENT: Address critical vulnerabilities immediately'
            )
        
        if any(v.get('cve_id', '').startswith('CVE-2014') for v in self.vulnerabilities):
            report['recommendations'].append(
                'Update extremely outdated components (vulnerabilities from 2014)'
            )
        
        return report


# Example usage
if __name__ == '__main__':
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python firmware_vuln_scanner.py <firmware_file>")
        sys.exit(1)
    
    firmware_file = sys.argv[1]
    
    print("="*70)
    print(f"Firmware Vulnerability Scanner: {os.path.basename(firmware_file)}")
    print("="*70)
    
    scanner = FirmwareVulnerabilityScanner()
    
    # Analyze structure first
    from firmware_analyzer import FirmwareAnalyzer
    analyzer = FirmwareAnalyzer()
    
    print("\nExtracting firmware...")
    extraction = analyzer.extract_firmware(firmware_file)
    
    if extraction['success']:
        print(f"Extracted to: {extraction['output_dir']}")
        print(f"Files extracted: {len(extraction['extracted_files'])}")
        
        # Detect components
        print("\nDetecting components...")
        components = scanner.detect_components(extraction['output_dir'])
        print(f"Components found: {len(components)}")
        
        # Check vulnerabilities
        print("\nChecking for vulnerabilities...")
        vulns = scanner.check_component_vulnerabilities(components)
        
        print(f"\nVulnerabilities: {len(vulns)}")
        for vuln in vulns:
            print(f"  [{vuln['severity']}] {vuln['cve_id']}: {vuln['description']}")
        
        # Search for credentials
        print("\nSearching for hardcoded credentials...")
        creds = analyzer.find_hardcoded_credentials(firmware_file, extraction['output_dir'])
        print(f"Credentials found: {len(creds)}")
        
        # Cleanup
        import shutil
        shutil.rmtree(extraction['output_dir'])
    else:
        print(f"Extraction failed: {extraction.get('error', 'Unknown error')}")
