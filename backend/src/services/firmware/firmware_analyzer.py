"""
Firmware Analysis Engine
Extracts and analyzes firmware images for security vulnerabilities
"""

import os
import re
import subprocess
import logging
from typing import Dict, List, Optional
from datetime import datetime
import tempfile
import shutil

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class FirmwareAnalyzer:
    """
    Comprehensive firmware analysis engine
    Uses binwalk and other tools for firmware extraction and analysis
    """
    
    def __init__(self):
        """Initialize firmware analyzer"""
        self.analysis_results = {}
        self.extracted_files = []
        self.vulnerabilities = []
    
    def extract_firmware(self, firmware_path: str, output_dir: Optional[str] = None) -> Dict:
        """
        Extract firmware using binwalk
        
        Args:
            firmware_path: Path to firmware file
            output_dir: Output directory for extraction
            
        Returns:
            Extraction results
        """
        if output_dir is None:
            output_dir = tempfile.mkdtemp(prefix='firmware_extract_')
        
        result = {
            'firmware_path': firmware_path,
            'output_dir': output_dir,
            'extracted_files': [],
            'filesystems_found': [],
            'success': False
        }
        
        try:
            # Run binwalk extraction
            logger.info(f"Extracting firmware: {firmware_path}")
            
            cmd = ['binwalk', '-e', '-M', firmware_path, '-C', output_dir]
            process = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300  # 5 minute timeout
            )
            
            if process.returncode == 0:
                result['success'] = True
                
                # Parse binwalk output
                for line in process.stdout.split('\n'):
                    if 'filesystem' in line.lower():
                        result['filesystems_found'].append(line.strip())
                
                # List extracted files
                if os.path.exists(output_dir):
                    for root, dirs, files in os.walk(output_dir):
                        for file in files:
                            file_path = os.path.join(root, file)
                            result['extracted_files'].append(file_path)
                
                self.extracted_files = result['extracted_files']
                logger.info(f"Extracted {len(result['extracted_files'])} files")
            else:
                result['error'] = process.stderr
                logger.error(f"Binwalk extraction failed: {process.stderr}")
            
        except subprocess.TimeoutExpired:
            result['error'] = 'Extraction timed out'
            logger.error("Firmware extraction timed out")
        except Exception as e:
            result['error'] = str(e)
            logger.error(f"Extraction error: {e}")
        
        return result
    
    def find_hardcoded_credentials(self, firmware_path: str, 
                                   extracted_dir: Optional[str] = None) -> List[Dict]:
        """
        Search for hardcoded credentials in firmware
        
        Args:
            firmware_path: Path to firmware file
            extracted_dir: Directory with extracted files
            
        Returns:
            List of found credentials
        """
        credentials = []
        
        # Common credential patterns
        patterns = {
            'password': [
                r'password\s*=\s*["\']([^"\']+)["\']',
                r'passwd\s*=\s*["\']([^"\']+)["\']',
                r'pwd\s*=\s*["\']([^"\']+)["\']',
            ],
            'api_key': [
                r'api[_-]?key\s*=\s*["\']([^"\']+)["\']',
                r'api[_-]?secret\s*=\s*["\']([^"\']+)["\']',
            ],
            'token': [
                r'token\s*=\s*["\']([^"\']+)["\']',
                r'auth[_-]?token\s*=\s*["\']([^"\']+)["\']',
            ],
            'username': [
                r'username\s*=\s*["\']([^"\']+)["\']',
                r'user\s*=\s*["\']([^"\']+)["\']',
            ]
        }
        
        try:
            # Search in extracted files if available
            search_paths = []
            
            if extracted_dir and os.path.exists(extracted_dir):
                # Search in extracted files
                for root, dirs, files in os.walk(extracted_dir):
                    for file in files:
                        # Focus on text-like files
                        if any(file.endswith(ext) for ext in ['.txt', '.conf', '.cfg', '.ini', '.xml', '.json', '.sh', '.py']):
                            search_paths.append(os.path.join(root, file))
            else:
                # Search in firmware file directly
                search_paths.append(firmware_path)
            
            for search_path in search_paths[:100]:  # Limit to first 100 files
                try:
                    with open(search_path, 'r', errors='ignore') as f:
                        content = f.read()
                    
                    # Search for patterns
                    for cred_type, pattern_list in patterns.items():
                        for pattern in pattern_list:
                            matches = re.findall(pattern, content, re.IGNORECASE)
                            
                            for match in matches:
                                credential = {
                                    'type': cred_type,
                                    'value': match,
                                    'file': os.path.basename(search_path),
                                    'pattern': pattern,
                                    'severity': 'Critical'
                                }
                                credentials.append(credential)
                                logger.warning(f"Found hardcoded {cred_type} in {search_path}")
                
                except:
                    continue
        
        except Exception as e:
            logger.error(f"Error searching for credentials: {e}")
        
        # Remove duplicates
        unique_creds = []
        seen = set()
        for cred in credentials:
            key = (cred['type'], cred['value'])
            if key not in seen:
                seen.add(key)
                unique_creds.append(cred)
        
        logger.info(f"Found {len(unique_creds)} unique hardcoded credentials")
        return unique_creds
    
    def extract_certificates(self, extracted_dir: str) -> List[Dict]:
        """
        Extract embedded SSL/TLS certificates and keys
        
        Args:
            extracted_dir: Directory with extracted firmware
            
        Returns:
            List of found certificates/keys
        """
        certificates = []
        
        # Certificate patterns
        cert_patterns = {
            'certificate': r'-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----',
            'private_key': r'-----BEGIN (?:RSA )?PRIVATE KEY-----(.*?)-----END (?:RSA )?PRIVATE KEY-----',
            'public_key': r'-----BEGIN PUBLIC KEY-----(.*?)-----END PUBLIC KEY-----',
        }
        
        try:
            for root, dirs, files in os.walk(extracted_dir):
                for file in files:
                    file_path = os.path.join(root, file)
                    
                    try:
                        with open(file_path, 'r', errors='ignore') as f:
                            content = f.read()
                        
                        for cert_type, pattern in cert_patterns.items():
                            matches = re.findall(pattern, content, re.DOTALL)
                            
                            for match in matches:
                                cert_info = {
                                    'type': cert_type,
                                    'file': os.path.basename(file_path),
                                    'size': len(match),
                                    'severity': 'High' if 'private' in cert_type.lower() else 'Medium'
                                }
                                certificates.append(cert_info)
                                logger.warning(f"Found {cert_type} in {file_path}")
                    
                    except:
                        continue
        
        except Exception as e:
            logger.error(f"Error extracting certificates: {e}")
        
        logger.info(f"Found {len(certificates)} certificates/keys")
        return certificates
    
    def find_sensitive_strings(self, extracted_dir: str) -> List[Dict]:
        """
        Find sensitive information in firmware
        
        Args:
            extracted_dir: Directory with extracted firmware
            
        Returns:
            List of sensitive findings
        """
        findings = []
        
        # Sensitive patterns
        sensitive_patterns = {
            'ip_address': r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
            'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            'url': r'https?://[^\s<>"{}|\\^`\[\]]+',
            'aws_key': r'AKIA[0-9A-Z]{16}',
            'private_key_marker': r'-----BEGIN .*PRIVATE KEY-----',
            'api_endpoint': r'/api/[a-zA-Z0-9_/]+',
        }
        
        try:
            for root, dirs, files in os.walk(extracted_dir):
                for file in files[:50]:  # Limit to first 50 files
                    file_path = os.path.join(root, file)
                    
                    try:
                        with open(file_path, 'r', errors='ignore') as f:
                            content = f.read(1024 * 100)  # Read first 100KB
                        
                        for info_type, pattern in sensitive_patterns.items():
                            matches = re.findall(pattern, content)
                            
                            for match in matches[:10]:  # Limit matches per file
                                finding = {
                                    'type': info_type,
                                    'value': match,
                                    'file': os.path.basename(file_path),
                                    'severity': 'High' if 'key' in info_type else 'Medium'
                                }
                                findings.append(finding)
                    
                    except:
                        continue
        
        except Exception as e:
            logger.error(f"Error finding sensitive strings: {e}")
        
        return findings
    
    def analyze_file_structure(self, firmware_path: str) -> Dict:
        """
        Analyze firmware file structure
        
        Args:
            firmware_path: Path to firmware file
            
        Returns:
            Structure analysis
        """
        analysis = {
            'firmware_path': firmware_path,
            'file_signatures': [],
            'embedded_files': [],
            'compression': []
        }
        
        try:
            # Run binwalk without extraction for analysis
            cmd = ['binwalk', firmware_path]
            process = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60
            )
            
            if process.returncode == 0:
                lines = process.stdout.split('\n')
                
                for line in lines:
                    if line.strip() and not line.startswith('DECIMAL'):
                        # Parse binwalk output
                        parts = line.split(maxsplit=2)
                        if len(parts) >= 3:
                            offset = parts[0]
                            sig_type = parts[2] if len(parts) > 2 else 'Unknown'
                            
                            analysis['file_signatures'].append({
                                'offset': offset,
                                'type': sig_type
                            })
                            
                            # Categorize
                            if any(term in sig_type.lower() for term in ['filesystem', 'squashfs', 'cramfs', 'jffs2']):
                                analysis['embedded_files'].append(sig_type)
                            elif any(term in sig_type.lower() for term in ['compressed', 'gzip', 'lzma', 'zip']):
                                analysis['compression'].append(sig_type)
        
        except Exception as e:
            logger.error(f"Error analyzing file structure: {e}")
        
        return analysis
    
    def get_firmware_metadata(self, firmware_path: str) -> Dict:
        """
        Extract metadata from firmware
        
        Args:
            firmware_path: Path to firmware file
            
        Returns:
            Firmware metadata
        """
        metadata = {
            'file_name': os.path.basename(firmware_path),
            'file_size': os.path.getsize(firmware_path),
            'file_type': self._detect_file_type(firmware_path),
            'hashes': self._calculate_file_hash(firmware_path),
            'timestamp': datetime.now().isoformat()
        }
        
        return metadata


# Example usage
if __name__ == '__main__':
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python firmware_analyzer.py <firmware_file>")
        sys.exit(1)
    
    firmware_file = sys.argv[1]
    
    print("="*70)
    print(f"Firmware Analysis: {os.path.basename(firmware_file)}")
    print("="*70)
    
    analyzer = FirmwareAnalyzer()
    
    # Analyze structure
    print("\nAnalyzing firmware structure...")
    structure = analyzer.analyze_file_structure(firmware_file)
    
    print(f"\nFile Signatures Found: {len(structure['file_signatures'])}")
    for sig in structure['file_signatures'][:10]:
        print(f"  {sig['offset']}: {sig['type']}")
    
    if structure['file_signatures'] and len(structure['file_signatures']) > 10:
        print(f"  ... and {len(structure['file_signatures']) - 10} more")
    
    print(f"\nFilesystems: {len(structure['embedded_files'])}")
    for fs in set(structure['embedded_files']):
        print(f"  - {fs}")
    
    print(f"\nCompression: {len(structure['compression'])}")
    for comp in set(structure['compression']):
        print(f"  - {comp}")
