"""
Role-Based Access Control (RBAC) - Phase 10.4
Advanced user roles and permissions system
"""

import logging
from typing import List, Dict, Set
from functools import wraps
from flask import jsonify
from flask_login import current_user

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class Permission:
    """Permission definitions"""
    
    # Device permissions
    VIEW_DEVICES = 'view_devices'
    SCAN_DEVICES = 'scan_devices'
    MODIFY_DEVICES = 'modify_devices'
    DELETE_DEVICES = 'delete_devices'
    
    # Scan permissions
    VIEW_SCANS = 'view_scans'
    START_SCAN = 'start_scan'
    STOP_SCAN = 'stop_scan'
    SCHEDULE_SCAN = 'schedule_scan'
    
    # Report permissions
    VIEW_REPORTS = 'view_reports'
    GENERATE_REPORTS = 'generate_reports'
    EXPORT_REPORTS = 'export_reports'
    DELETE_REPORTS = 'delete_reports'
    
    # Admin permissions
    MANAGE_USERS = 'manage_users'
    MANAGE_ROLES = 'manage_roles'
    VIEW_AUDIT_LOG = 'view_audit_log'
    SYSTEM_SETTINGS = 'system_settings'
    
    # Advanced features
    UPLOAD_FIRMWARE = 'upload_firmware'
    ANALYZE_FIRMWARE = 'analyze_firmware'
    CREATE_CUSTOM_RULES = 'create_custom_rules'
    MANAGE_INTEGRATIONS = 'manage_integrations'


class Role:
    """Role definitions with permissions"""
    
    def __init__(self, name: str, permissions: Set[str], description: str = ''):
        """
        Initialize role
        
        Args:
            name: Role name
            permissions: Set of permission strings
            description: Role description
        """
        self.name = name
        self.permissions = permissions
        self.description = description


# Define standard roles
ROLES = {
    'admin': Role(
        name='Admin',
        description='Full system access',
        permissions={
            # All permissions
            Permission.VIEW_DEVICES, Permission.SCAN_DEVICES,
            Permission.MODIFY_DEVICES, Permission.DELETE_DEVICES,
            Permission.VIEW_SCANS, Permission.START_SCAN,
            Permission.STOP_SCAN, Permission.SCHEDULE_SCAN,
            Permission.VIEW_REPORTS, Permission.GENERATE_REPORTS,
            Permission.EXPORT_REPORTS, Permission.DELETE_REPORTS,
            Permission.MANAGE_USERS, Permission.MANAGE_ROLES,
            Permission.VIEW_AUDIT_LOG, Permission.SYSTEM_SETTINGS,
            Permission.UPLOAD_FIRMWARE, Permission.ANALYZE_FIRMWARE,
            Permission.CREATE_CUSTOM_RULES, Permission.MANAGE_INTEGRATIONS
        }
    ),
    
    'security_analyst': Role(
        name='Security Analyst',
        description='Can perform scans and generate reports',
        permissions={
            Permission.VIEW_DEVICES, Permission.SCAN_DEVICES,
            Permission.VIEW_SCANS, Permission.START_SCAN, Permission.STOP_SCAN,
            Permission.VIEW_REPORTS, Permission.GENERATE_REPORTS, Permission.EXPORT_REPORTS,
            Permission.UPLOAD_FIRMWARE, Permission.ANALYZE_FIRMWARE,
            Permission.CREATE_CUSTOM_RULES
        }
    ),
    
    'operator': Role(
        name='Operator',
        description='Can view and run basic scans',
        permissions={
            Permission.VIEW_DEVICES, Permission.SCAN_DEVICES,
            Permission.VIEW_SCANS, Permission.START_SCAN,
            Permission.VIEW_REPORTS
        }
    ),
    
    'viewer': Role(
        name='Viewer',
        description='Read-only access',
        permissions={
            Permission.VIEW_DEVICES,
            Permission.VIEW_SCANS,
            Permission.VIEW_REPORTS
        }
    )
}


class RBACManager:
    """Role-Based Access Control Manager"""
    
    def __init__(self):
        """Initialize RBAC manager"""
        self.roles = ROLES
    
    def has_permission(self, user: any, permission: str) -> bool:
        """
        Check if user has permission
        
        Args:
            user: User object
            permission: Permission to check
            
        Returns:
            True if user has permission
        """
        if not user or not hasattr(user, 'role'):
            return False
        
        user_role = self.roles.get(user.role, ROLES['viewer'])
        return permission in user_role.permissions
    
    def has_any_permission(self, user: any, permissions: List[str]) -> bool:
        """Check if user has any of the permissions"""
        return any(self.has_permission(user, perm) for perm in permissions)
    
    def has_all_permissions(self, user: any, permissions: List[str]) -> bool:
        """Check if user has all permissions"""
        return all(self.has_permission(user, perm) for perm in permissions)
    
    def get_user_permissions(self, user: any) -> Set[str]:
        """Get all permissions for user"""
        if not user or not hasattr(user, 'role'):
            return set()
        
        user_role = self.roles.get(user.role, ROLES['viewer'])
        return user_role.permissions
    
    def assign_role(self, user: any, role_name: str) -> bool:
        """Assign role to user"""
        if role_name not in self.roles:
            logger.error(f"Unknown role: {role_name}")
            return False
        
        user.role = role_name
        logger.info(f"Assigned role {role_name} to user {user.id}")
        return True


# Global RBAC manager
rbac_manager = RBACManager()


def require_permission(permission: str):
    """
    Decorator to require specific permission
    
    Args:
        permission: Required permission
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            if not current_user.is_authenticated:
                return jsonify({
                    'success': False,
                    'message': 'Authentication required'
                }), 401
            
            if not rbac_manager.has_permission(current_user, permission):
                logger.warning(f"Permission denied: {current_user.username} lacks {permission}")
                
                return jsonify({
                    'success': False,
                    'message': 'غير مصرح لك بهذا الإجراء',
                    'error': 'insufficient_permissions'
                }), 403
            
            return func(*args, **kwargs)
        
        return wrapper
    return decorator


def require_role(role_name: str):
    """Decorator to require specific role"""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            if not current_user.is_authenticated:
                return jsonify({'success': False, 'message': 'Authentication required'}), 401
            
            user_role = getattr(current_user, 'role', 'viewer')
            
            if user_role != role_name and user_role != 'admin':
                return jsonify({
                    'success': False,
                    'message': 'غير مصرح لك بهذا الإجراء'
                }), 403
            
            return func(*args, **kwargs)
        
        return wrapper
    return decorator


# Example usage
if __name__ == '__main__':
    print("="*70)
    print("Role-Based Access Control - Phase 10.4")
    print("="*70)
    
    rbac = RBACManager()
    
    print("\nAvailable Roles:")
    for role_name, role in rbac.roles.items():
        print(f"\n  {role.name}:")
        print(f"    Description: {role.description}")
        print(f"    Permissions: {len(role.permissions)}")
    
    # Test permission check
    class MockUser:
        def __init__(self, role):
            self.id = 1
            self.username = 'test'
            self.role = role
    
    admin_user = MockUser('admin')
    viewer_user = MockUser('viewer')
    
    print(f"\nPermission Tests:")
    print(f"  Admin can start scan: {rbac.has_permission(admin_user, Permission.START_SCAN)}")
    print(f"  Viewer can start scan: {rbac.has_permission(viewer_user, Permission.START_SCAN)}")
    print(f"  Viewer can view devices: {rbac.has_permission(viewer_user, Permission.VIEW_DEVICES)}")
