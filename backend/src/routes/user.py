from flask import Blueprint, jsonify, request
from flask_login import login_required, current_user
from datetime import datetime
from src.models import db, User, Device, Report

user_bp = Blueprint('user', __name__)

@user_bp.route('/users/dashboard', methods=['GET'])
@login_required
def get_user_dashboard():
    """Get dashboard statistics for current user"""
    try:
        # Get user's device count
        device_count = Device.query.filter_by(user_id=current_user.id).count()
        
        # Get user's report count
        report_count = Report.query.filter_by(user_id=current_user.id).count()
        
        # Get recent devices
        recent_devices = Device.query.filter_by(user_id=current_user.id)\
            .order_by(Device.created_at.desc())\
            .limit(5)\
            .all()
        
        return jsonify({
            'success': True,
            'dashboard': {
                'user': current_user.to_dict(),
                'device_count': device_count,
                'report_count': report_count,
                'recent_devices': [device.to_dict() for device in recent_devices]
            }
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'خطأ في جلب لوحة التحكم: {str(e)}'
        }), 500

@user_bp.route('/users/stats', methods=['GET'])
@login_required
def get_user_stats():
    """Get detailed statistics for current user"""
    try:
        # Get all user's devices
        devices = Device.query.filter_by(user_id=current_user.id).all()
        
        # Get all user's reports
        reports = Report.query.filter_by(user_id=current_user.id).all()
        
        # Calculate statistics
        total_scans = len(devices)
        total_reports = len(reports)
        
        # Get device types distribution
        device_types = {}
        for device in devices:
            dtype = device.device_type or 'Unknown'
            device_types[dtype] = device_types.get(dtype, 0) + 1
        
        # Get scan activity (last 30 days)
        thirty_days_ago = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
        recent_scans = Device.query.filter(
            Device.user_id == current_user.id,
            Device.created_at >= thirty_days_ago
        ).count()
        
        return jsonify({
            'success': True,
            'stats': {
                'total_scans': total_scans,
                'total_reports': total_reports,
                'recent_scans': recent_scans,
                'device_types': device_types,
                'last_scan': devices[0].created_at.isoformat() if devices else None
            }
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'خطأ في جلب الإحصائيات: {str(e)}'
        }), 500

@user_bp.route('/users/profile', methods=['GET'])
@login_required
def get_profile():
    """Get current user profile"""
    try:
        return jsonify({
            'success': True,
            'profile': current_user.to_dict()
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'خطأ في جلب الملف الشخصي: {str(e)}'
        }), 500

@user_bp.route('/users/activity', methods=['GET'])
@login_required
def get_user_activity():
    """Get user's recent activity"""
    try:
        # Get recent devices (last 10)
        recent_devices = Device.query.filter_by(user_id=current_user.id)\
            .order_by(Device.created_at.desc())\
            .limit(10)\
            .all()
        
        # Get recent reports (last 10)
        recent_reports = Report.query.filter_by(user_id=current_user.id)\
            .order_by(Report.generated_at.desc())\
            .limit(10)\
            .all()
        
        return jsonify({
            'success': True,
            'activity': {
                'recent_devices': [device.to_dict() for device in recent_devices],
                'recent_reports': [report.to_dict() for report in recent_reports]
            }
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'خطأ في جلب النشاط: {str(e)}'
        }), 500
