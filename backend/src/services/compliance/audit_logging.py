"""
Audit Logging & Compliance - Phase 10.5
Comprehensive audit trail for compliance requirements
"""

import logging
from typing import Dict, Optional
from datetime import datetime
from functools import wraps
from flask import request
from flask_login import current_user

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class AuditLogger:
    """Comprehensive audit logging system"""
    
    # Event categories
    CATEGORY_AUTH = 'authentication'
    CATEGORY_SCAN = 'scanning'
    CATEGORY_DEVICE = 'device_management'
    CATEGORY_REPORT = 'reporting'
    CATEGORY_ADMIN = 'administration'
    CATEGORY_SECURITY = 'security_event'
    
    # Event types
    EVENT_LOGIN = 'login'
    EVENT_LOGOUT = 'logout'
    EVENT_SCAN_START = 'scan_started'
    EVENT_SCAN_COMPLETE = 'scan_completed'
    EVENT_DEVICE_ADDED = 'device_added'
    EVENT_DEVICE_MODIFIED = 'device_modified'
    EVENT_DEVICE_DELETED = 'device_deleted'
    EVENT_REPORT_GENERATED = 'report_generated'
    EVENT_USER_CREATED = 'user_created'
    EVENT_USER_MODIFIED = 'user_modified'
    EVENT_ROLE_CHANGED = 'role_changed'
    EVENT_VULN_DETECTED = 'vulnerability_detected'
    
    def __init__(self, db_session=None):
        """
        Initialize audit logger
        
        Args:
            db_session: Database session for persistent logging
        """
        self.db = db_session
        self.audit_log = []  # In-memory log
        self.log_file = 'logs/audit.log'
        
        # Ensure log directory exists
        import os
        os.makedirs('logs', exist_ok=True)
    
    def log_event(self, category: str, event_type: str, 
                  details: Dict, user_id: Optional[int] = None,
                  ip_address: Optional[str] = None) -> None:
        """
        Log audit event
        
        Args:
            category: Event category
            event_type: Event type
            details: Event details
            user_id: User ID (if applicable)
            ip_address: IP address
        """
        event = {
            'timestamp': datetime.now().isoformat(),
            'category': category,
            'event_type': event_type,
            'user_id': user_id,
            'ip_address': ip_address,
            'details': details
        }
        
        # Add to in-memory log
        self.audit_log.append(event)
        
        # Write to file
        self._write_to_file(event)
        
        # Write to database if available
        if self.db:
            self._write_to_database(event)
        
        logger.info(f"Audit: {category}.{event_type} by user {user_id}")
    
    def _write_to_file(self, event: Dict) -> None:
        """Write event to log file"""
        try:
            import json
            
            with open(self.log_file, 'a', encoding='utf-8') as f:
                f.write(json.dumps(event, ensure_ascii=False) + '\n')
        
        except Exception as e:
            logger.error(f"Error writing to audit log: {e}")
    
    def _write_to_database(self, event: Dict) -> None:
        """Write event to database"""
        try:
            # Would create AuditLog model and insert
            # For now, just placeholder
            pass
        except Exception as e:
            logger.error(f"Error writing to database: {e}")
    
    def query_events(self, category: Optional[str] = None,
                    event_type: Optional[str] = None,
                    user_id: Optional[int] = None,
                    start_date: Optional[datetime] = None,
                    end_date: Optional[datetime] = None,
                    limit: int = 100) -> List[Dict]:
        """
        Query audit events
        
        Args:
            category: Filter by category
            event_type: Filter by event type
            user_id: Filter by user
            start_date: Start date filter
            end_date: End date filter
            limit: Maximum results
            
        Returns:
            Matching audit events
        """
        results = self.audit_log.copy()
        
        # Apply filters
        if category:
            results = [e for e in results if e['category'] == category]
        
        if event_type:
            results = [e for e in results if e['event_type'] == event_type]
        
        if user_id:
            results = [e for e in results if e['user_id'] == user_id]
        
        if start_date:
            results = [e for e in results 
                      if datetime.fromisoformat(e['timestamp']) >= start_date]
        
        if end_date:
            results = [e for e in results 
                      if datetime.fromisoformat(e['timestamp']) <= end_date]
        
        # Sort by timestamp (newest first)
        results.sort(key=lambda e: e['timestamp'], reverse=True)
        
        return results[:limit]
    
    def generate_compliance_report(self, start_date: datetime, 
                                  end_date: datetime) -> Dict:
        """
        Generate compliance report
        
        Args:
            start_date: Report start date
            end_date: Report end date
            
        Returns:
            Compliance report
        """
        events = self.query_events(start_date=start_date, end_date=end_date, limit=10000)
        
        report = {
            'period': f"{start_date.date()} to {end_date.date()}",
            'total_events': len(events),
            'events_by_category': {},
            'events_by_user': {},
            'security_events': [],
            'failed_operations': []
        }
        
        # Categorize events
        for event in events:
            category = event['category']
            report['events_by_category'][category] = report['events_by_category'].get(category, 0) + 1
            
            user_id = event.get('user_id', 'system')
            report['events_by_user'][user_id] = report['events_by_user'].get(user_id, 0) + 1
            
            # Track security events
            if event['category'] == self.CATEGORY_SECURITY:
                report['security_events'].append(event)
            
            # Track failures
            if event['details'].get('status') == 'failed':
                report['failed_operations'].append(event)
        
        report['security_event_count'] = len(report['security_events'])
        report['failed_operation_count'] = len(report['failed_operations'])
        
        return report


# Global audit logger
audit_logger = AuditLogger()


def audit_log(category: str, event_type: str, get_details: callable = None):
    """
    Decorator for audit logging
    
    Args:
        category: Event category
        event_type: Event type
        get_details: Function to extract details from result
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Execute function
            result = func(*args, **kwargs)
            
            # Extract details
            if get_details:
                details = get_details(result)
            else:
                details = {'function': func.__name__}
            
            # Get user and IP
            user_id = current_user.id if current_user.is_authenticated else None
            ip_address = request.remote_addr if request else None
            
            # Log event
            audit_logger.log_event(
                category=category,
                event_type=event_type,
                details=details,
                user_id=user_id,
                ip_address=ip_address
            )
            
            return result
        
        return wrapper
    return decorator


# Example usage
if __name__ == '__main__':
    from datetime import timedelta
    
    print("="*70)
    print("Audit Logging & Compliance - Phase 10.5")
    print("="*70)
    
    auditor = AuditLogger()
    
    # Simulate events
    print("\nSimulating audit events...")
    
    auditor.log_event(
        category=AuditLogger.CATEGORY_AUTH,
        event_type=AuditLogger.EVENT_LOGIN,
        details={'username': 'admin', 'status': 'success'},
        user_id=1,
        ip_address='192.168.1.50'
    )
    
    auditor.log_event(
        category=AuditLogger.CATEGORY_SCAN,
        event_type=AuditLogger.EVENT_SCAN_START,
        details={'network': '192.168.1.0/24', 'scan_type': 'comprehensive'},
        user_id=1,
        ip_address='192.168.1.50'
    )
    
    auditor.log_event(
        category=AuditLogger.CATEGORY_SECURITY,
        event_type=AuditLogger.EVENT_VULN_DETECTED,
        details={'severity': 'Critical', 'device': '192.168.1.100'},
        user_id=1
    )
    
    print(f"\nTotal Events Logged: {len(auditor.audit_log)}")
    
    # Query events
    print("\nQuerying authentication events...")
    auth_events = auditor.query_events(category=AuditLogger.CATEGORY_AUTH)
    print(f"  Found: {len(auth_events)}")
    
    # Generate compliance report
    print("\nGenerating compliance report...")
    start = datetime.now() - timedelta(days=30)
    end = datetime.now()
    
    compliance = auditor.generate_compliance_report(start, end)
    print(f"  Events: {compliance['total_events']}")
    print(f"  Security Events: {compliance['security_event_count']}")
    print(f"  Failed Operations: {compliance['failed_operation_count']}")
    
    print(f"\n  Events by Category:")
    for cat, count in compliance['events_by_category'].items():
        print(f"    {cat}: {count}")
