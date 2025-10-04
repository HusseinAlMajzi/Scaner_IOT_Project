"""
Real-Time Progress Tracking - Phase 9.4
WebSocket-based real-time progress updates
"""

import logging
from typing import Dict, List, Callable
from datetime import datetime
import threading

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ProgressTracker:
    """Real-time progress tracking for scans"""
    
    def __init__(self):
        """Initialize progress tracker"""
        self.active_scans = {}
        self.callbacks = []
        self._lock = threading.Lock()
    
    def start_scan(self, scan_id: str, total_steps: int = 100) -> None:
        """
        Start tracking a new scan
        
        Args:
            scan_id: Unique scan identifier
            total_steps: Total steps in scan
        """
        with self._lock:
            self.active_scans[scan_id] = {
                'scan_id': scan_id,
                'status': 'running',
                'progress': 0,
                'total_steps': total_steps,
                'current_step': 'Starting scan...',
                'devices_found': 0,
                'vulnerabilities_found': 0,
                'started_at': datetime.now().isoformat(),
                'estimated_completion': None,
                'errors': []
            }
        
        logger.info(f"Started tracking scan: {scan_id}")
        self._notify_callbacks(scan_id)
    
    def update_progress(self, scan_id: str, progress: int = None, 
                       step: str = None, **kwargs) -> None:
        """
        Update scan progress
        
        Args:
            scan_id: Scan identifier
            progress: Progress percentage (0-100)
            step: Current step description
            **kwargs: Additional updates
        """
        with self._lock:
            if scan_id not in self.active_scans:
                logger.warning(f"Unknown scan ID: {scan_id}")
                return
            
            scan = self.active_scans[scan_id]
            
            if progress is not None:
                scan['progress'] = min(progress, 100)
            
            if step is not None:
                scan['current_step'] = step
            
            # Update additional fields
            for key, value in kwargs.items():
                scan[key] = value
            
            # Estimate completion time
            if scan['progress'] > 0:
                started = datetime.fromisoformat(scan['started_at'])
                elapsed = (datetime.now() - started).total_seconds()
                
                if scan['progress'] < 100:
                    remaining_pct = 100 - scan['progress']
                    time_per_pct = elapsed / scan['progress']
                    estimated_remaining = remaining_pct * time_per_pct
                    
                    scan['estimated_completion'] = f"{int(estimated_remaining)} seconds"
        
        self._notify_callbacks(scan_id)
    
    def complete_scan(self, scan_id: str, success: bool = True) -> None:
        """
        Mark scan as complete
        
        Args:
            scan_id: Scan identifier
            success: Whether scan completed successfully
        """
        with self._lock:
            if scan_id not in self.active_scans:
                return
            
            scan = self.active_scans[scan_id]
            scan['status'] = 'completed' if success else 'failed'
            scan['progress'] = 100 if success else scan['progress']
            scan['completed_at'] = datetime.now().isoformat()
            
            started = datetime.fromisoformat(scan['started_at'])
            duration = (datetime.now() - started).total_seconds()
            scan['duration_seconds'] = duration
        
        logger.info(f"Scan {scan_id} completed in {duration:.1f}s")
        self._notify_callbacks(scan_id)
    
    def fail_scan(self, scan_id: str, error: str) -> None:
        """
        Mark scan as failed
        
        Args:
            scan_id: Scan identifier
            error: Error message
        """
        with self._lock:
            if scan_id not in self.active_scans:
                return
            
            scan = self.active_scans[scan_id]
            scan['status'] = 'failed'
            scan['errors'].append(error)
            scan['failed_at'] = datetime.now().isoformat()
        
        logger.error(f"Scan {scan_id} failed: {error}")
        self._notify_callbacks(scan_id)
    
    def get_status(self, scan_id: str) -> Dict:
        """Get current scan status"""
        with self._lock:
            return self.active_scans.get(scan_id, {})
    
    def get_all_active_scans(self) -> List[Dict]:
        """Get all active scans"""
        with self._lock:
            return [
                scan for scan in self.active_scans.values()
                if scan['status'] == 'running'
            ]
    
    def register_callback(self, callback: Callable) -> None:
        """
        Register callback for progress updates
        
        Args:
            callback: Function to call on updates
        """
        self.callbacks.append(callback)
    
    def _notify_callbacks(self, scan_id: str) -> None:
        """Notify all registered callbacks"""
        scan_data = self.active_scans.get(scan_id)
        
        for callback in self.callbacks:
            try:
                callback(scan_data)
            except Exception as e:
                logger.error(f"Callback error: {e}")
    
    def cleanup_old_scans(self, hours: int = 24) -> int:
        """
        Remove old scan data
        
        Args:
            hours: Remove scans older than this many hours
            
        Returns:
            Number of scans removed
        """
        with self._lock:
            to_remove = []
            cutoff = datetime.now().timestamp() - (hours * 3600)
            
            for scan_id, scan in self.active_scans.items():
                started = datetime.fromisoformat(scan['started_at'])
                if started.timestamp() < cutoff:
                    to_remove.append(scan_id)
            
            for scan_id in to_remove:
                del self.active_scans[scan_id]
            
            logger.info(f"Cleaned up {len(to_remove)} old scans")
            return len(to_remove)


# Global progress tracker
progress_tracker = ProgressTracker()


# Example usage
if __name__ == '__main__':
    import time
    
    print("="*70)
    print("Real-Time Progress Tracker - Phase 9.4")
    print("="*70)
    
    tracker = ProgressTracker()
    
    # Register callback
    def print_progress(scan_data):
        if scan_data:
            print(f"\rProgress: {scan_data['progress']}% - {scan_data['current_step']}", end='')
    
    tracker.register_callback(print_progress)
    
    # Simulate scan
    scan_id = "test_scan_001"
    tracker.start_scan(scan_id, total_steps=5)
    
    for i in range(1, 6):
        time.sleep(1)
        tracker.update_progress(
            scan_id, 
            progress=i * 20,
            step=f"Step {i}/5",
            devices_found=i * 2
        )
    
    tracker.complete_scan(scan_id)
    
    print("\n\nFinal Status:")
    final_status = tracker.get_status(scan_id)
    print(f"  Duration: {final_status['duration_seconds']:.1f}s")
    print(f"  Devices: {final_status['devices_found']}")
    print(f"  Status: {final_status['status']}")
