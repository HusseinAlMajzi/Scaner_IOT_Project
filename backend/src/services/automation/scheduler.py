"""
Scheduled Scanning Automation - Phase 10.1
Automated recurring scans with cron-like scheduling
"""

import logging
from typing import Dict, List, Optional, Callable
from datetime import datetime, timedelta
import threading
import time
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.interval import IntervalTrigger

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ScanScheduler:
    """Automated scan scheduling system"""
    
    def __init__(self):
        """Initialize scan scheduler"""
        self.scheduler = BackgroundScheduler()
        self.scheduled_scans = {}
        self.scheduler.start()
        
        logger.info("Scan scheduler initialized")
    
    def schedule_scan(self, schedule_id: str, scan_config: Dict, 
                     schedule_type: str, schedule_params: Dict,
                     callback: Callable) -> bool:
        """
        Schedule a recurring scan
        
        Args:
            schedule_id: Unique schedule identifier
            scan_config: Scan configuration
            schedule_type: 'interval', 'cron', or 'daily'
            schedule_params: Schedule parameters
            callback: Function to execute
            
        Returns:
            Success status
        """
        try:
            # Create trigger based on schedule type
            if schedule_type == 'interval':
                # Interval-based (every X hours/minutes)
                hours = schedule_params.get('hours', 0)
                minutes = schedule_params.get('minutes', 0)
                
                trigger = IntervalTrigger(
                    hours=hours,
                    minutes=minutes
                )
            
            elif schedule_type == 'cron':
                # Cron expression
                trigger = CronTrigger.from_crontab(schedule_params.get('expression', '0 0 * * *'))
            
            elif schedule_type == 'daily':
                # Daily at specific time
                hour = schedule_params.get('hour', 0)
                minute = schedule_params.get('minute', 0)
                
                trigger = CronTrigger(
                    hour=hour,
                    minute=minute
                )
            
            else:
                logger.error(f"Invalid schedule type: {schedule_type}")
                return False
            
            # Add job to scheduler
            job = self.scheduler.add_job(
                func=callback,
                trigger=trigger,
                args=[scan_config],
                id=schedule_id,
                replace_existing=True
            )
            
            self.scheduled_scans[schedule_id] = {
                'schedule_id': schedule_id,
                'scan_config': scan_config,
                'schedule_type': schedule_type,
                'schedule_params': schedule_params,
                'job_id': job.id,
                'created_at': datetime.now().isoformat(),
                'next_run': job.next_run_time.isoformat() if job.next_run_time else None,
                'status': 'active'
            }
            
            logger.info(f"Scheduled scan {schedule_id}: {schedule_type} - Next run: {job.next_run_time}")
            
            return True
        
        except Exception as e:
            logger.error(f"Error scheduling scan: {e}")
            return False
    
    def remove_schedule(self, schedule_id: str) -> bool:
        """
        Remove scheduled scan
        
        Args:
            schedule_id: Schedule identifier
            
        Returns:
            Success status
        """
        try:
            if schedule_id in self.scheduled_scans:
                self.scheduler.remove_job(schedule_id)
                del self.scheduled_scans[schedule_id]
                
                logger.info(f"Removed schedule: {schedule_id}")
                return True
            else:
                logger.warning(f"Schedule not found: {schedule_id}")
                return False
        
        except Exception as e:
            logger.error(f"Error removing schedule: {e}")
            return False
    
    def pause_schedule(self, schedule_id: str) -> bool:
        """Pause scheduled scan"""
        try:
            self.scheduler.pause_job(schedule_id)
            self.scheduled_scans[schedule_id]['status'] = 'paused'
            
            logger.info(f"Paused schedule: {schedule_id}")
            return True
        
        except Exception as e:
            logger.error(f"Error pausing schedule: {e}")
            return False
    
    def resume_schedule(self, schedule_id: str) -> bool:
        """Resume scheduled scan"""
        try:
            self.scheduler.resume_job(schedule_id)
            self.scheduled_scans[schedule_id]['status'] = 'active'
            
            logger.info(f"Resumed schedule: {schedule_id}")
            return True
        
        except Exception as e:
            logger.error(f"Error resuming schedule: {e}")
            return False
    
    def get_schedule(self, schedule_id: str) -> Optional[Dict]:
        """Get schedule information"""
        return self.scheduled_scans.get(schedule_id)
    
    def list_schedules(self) -> List[Dict]:
        """List all scheduled scans"""
        return list(self.scheduled_scans.values())
    
    def shutdown(self):
        """Shutdown scheduler"""
        logger.info("Shutting down scan scheduler...")
        self.scheduler.shutdown()


# Global scheduler instance
scan_scheduler = ScanScheduler()


# Example usage
if __name__ == '__main__':
    import time
    
    print("="*70)
    print("Scan Scheduler - Phase 10.1")
    print("="*70)
    
    scheduler = ScanScheduler()
    
    # Test callback
    def test_scan(config):
        print(f"\n[{datetime.now()}] Executing scheduled scan: {config}")
    
    # Schedule daily scan
    scheduler.schedule_scan(
        schedule_id='daily_scan_001',
        scan_config={'network': '192.168.1.0/24'},
        schedule_type='interval',
        schedule_params={'minutes': 1},  # Every minute for testing
        callback=test_scan
    )
    
    print("\nScheduled scans:")
    for schedule in scheduler.list_schedules():
        print(f"  {schedule['schedule_id']}: {schedule['schedule_type']} - Next run: {schedule['next_run']}")
    
    print("\nWaiting for scheduled execution (2 minutes)...")
    time.sleep(120)
    
    scheduler.shutdown()
