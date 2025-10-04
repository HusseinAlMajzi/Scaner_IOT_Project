"""
Firmware Upload and Management
Handles firmware file uploads and basic validation
"""

import os
import hashlib
import logging
import magic
from datetime import datetime
from typing import Dict, Optional
from werkzeug.utils import secure_filename

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class FirmwareUploadManager:
    """Manages firmware file uploads and storage"""
    
    # Allowed firmware file extensions
    ALLOWED_EXTENSIONS = {
        '.bin', '.img', '.fw', '.rom', '.hex', '.elf',
        '.zip', '.tar', '.tar.gz', '.tgz', '.rar', '.7z'
    }
    
    # Maximum file size (500MB)
    MAX_FILE_SIZE = 500 * 1024 * 1024
    
    def __init__(self, upload_dir: str = 'uploads/firmware'):
        """
        Initialize firmware upload manager
        
        Args:
            upload_dir: Directory to store uploaded firmware
        """
        self.upload_dir = upload_dir
        os.makedirs(upload_dir, exist_ok=True)
        self.uploaded_files = []
    
    def _calculate_file_hash(self, file_path: str) -> Dict[str, str]:
        """
        Calculate multiple hashes for file integrity
        
        Args:
            file_path: Path to firmware file
            
        Returns:
            Dictionary of hash values
        """
        hashes = {
            'md5': hashlib.md5(),
            'sha1': hashlib.sha1(),
            'sha256': hashlib.sha256()
        }
        
        with open(file_path, 'rb') as f:
            while chunk := f.read(8192):
                for hash_obj in hashes.values():
                    hash_obj.update(chunk)
        
        return {
            name: hash_obj.hexdigest()
            for name, hash_obj in hashes.items()
        }
    
    def _detect_file_type(self, file_path: str) -> str:
        """
        Detect file type using magic bytes
        
        Args:
            file_path: Path to firmware file
            
        Returns:
            File type description
        """
        try:
            file_type = magic.from_file(file_path)
            return file_type
        except Exception as e:
            logger.error(f"Error detecting file type: {e}")
            return "Unknown"
    
    def validate_firmware_file(self, file_path: str, original_filename: str) -> Dict:
        """
        Validate uploaded firmware file
        
        Args:
            file_path: Path to uploaded file
            original_filename: Original filename
            
        Returns:
            Validation results
        """
        validation = {
            'valid': True,
            'errors': [],
            'warnings': [],
            'info': {}
        }
        
        # Check file exists
        if not os.path.exists(file_path):
            validation['valid'] = False
            validation['errors'].append('File does not exist')
            return validation
        
        # Check file size
        file_size = os.path.getsize(file_path)
        validation['info']['file_size'] = file_size
        
        if file_size == 0:
            validation['valid'] = False
            validation['errors'].append('File is empty')
        elif file_size > self.MAX_FILE_SIZE:
            validation['valid'] = False
            validation['errors'].append(f'File too large ({file_size} bytes)')
        
        # Check extension
        _, ext = os.path.splitext(original_filename.lower())
        if ext not in self.ALLOWED_EXTENSIONS:
            validation['warnings'].append(f'Uncommon file extension: {ext}')
        
        # Detect file type
        file_type = self._detect_file_type(file_path)
        validation['info']['file_type'] = file_type
        
        # Calculate hashes
        hashes = self._calculate_file_hash(file_path)
        validation['info']['hashes'] = hashes
        
        return validation
    
    def save_firmware(self, file_obj, metadata: Dict) -> Dict:
        """
        Save uploaded firmware file
        
        Args:
            file_obj: File object from request
            metadata: Firmware metadata (manufacturer, model, version)
            
        Returns:
            Saved firmware information
        """
        try:
            # Secure filename
            original_filename = secure_filename(file_obj.filename)
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"{timestamp}_{original_filename}"
            file_path = os.path.join(self.upload_dir, filename)
            
            # Save file
            file_obj.save(file_path)
            logger.info(f"Firmware saved: {file_path}")
            
            # Validate
            validation = self.validate_firmware_file(file_path, original_filename)
            
            if not validation['valid']:
                # Delete invalid file
                os.remove(file_path)
                return {
                    'success': False,
                    'errors': validation['errors']
                }
            
            # Create firmware record
            firmware_info = {
                'id': hashlib.sha256(filename.encode()).hexdigest()[:16],
                'filename': filename,
                'original_filename': original_filename,
                'file_path': file_path,
                'file_size': validation['info']['file_size'],
                'file_type': validation['info']['file_type'],
                'hashes': validation['info']['hashes'],
                'manufacturer': metadata.get('manufacturer'),
                'model': metadata.get('model'),
                'version': metadata.get('version'),
                'upload_timestamp': datetime.now().isoformat(),
                'analyzed': False,
                'warnings': validation.get('warnings', [])
            }
            
            self.uploaded_files.append(firmware_info)
            
            return {
                'success': True,
                'firmware': firmware_info
            }
            
        except Exception as e:
            logger.error(f"Error saving firmware: {e}")
            return {
                'success': False,
                'errors': [str(e)]
            }
    
    def get_firmware_info(self, firmware_id: str) -> Optional[Dict]:
        """Get firmware information by ID"""
        for firmware in self.uploaded_files:
            if firmware['id'] == firmware_id:
                return firmware
        return None
    
    def delete_firmware(self, firmware_id: str) -> bool:
        """Delete firmware file"""
        firmware = self.get_firmware_info(firmware_id)
        
        if firmware:
            try:
                if os.path.exists(firmware['file_path']):
                    os.remove(firmware['file_path'])
                
                self.uploaded_files.remove(firmware)
                logger.info(f"Deleted firmware: {firmware_id}")
                return True
            except Exception as e:
                logger.error(f"Error deleting firmware: {e}")
        
        return False


# Example usage
if __name__ == '__main__':
    manager = FirmwareUploadManager()
    
    print("="*70)
    print("Firmware Upload Manager - Phase 7")
    print("="*70)
    
    print("\nAllowed Extensions:")
    for ext in manager.ALLOWED_EXTENSIONS:
        print(f"  {ext}")
    
    print(f"\nMax File Size: {manager.MAX_FILE_SIZE / (1024*1024):.0f} MB")
    print(f"Upload Directory: {manager.upload_dir}")
