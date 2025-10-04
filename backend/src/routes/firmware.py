"""
Firmware Analysis Routes - Phase 7
API endpoints for firmware upload and analysis
"""

from flask import Blueprint, request, jsonify, send_file
from flask_login import login_required, current_user
from werkzeug.utils import secure_filename
import os
import asyncio
from datetime import datetime

from src.models import db, Device, Vulnerability
from src.services.firmware.firmware_manager import FirmwareAnalysisManager

firmware_bp = Blueprint('firmware', __name__)

# Initialize firmware manager
firmware_manager = FirmwareAnalysisManager()

# Track firmware analysis jobs
firmware_jobs = {}


@firmware_bp.route('/firmware/upload', methods=['POST'])
@login_required
def upload_firmware():
    """
    Upload firmware file for analysis
    
    Expects multipart/form-data with:
    - file: Firmware file
    - manufacturer: Device manufacturer (optional)
    - model: Device model (optional)
    - version: Firmware version (optional)
    - device_id: Associated device ID (optional)
    """
    try:
        # Check if file is present
        if 'file' not in request.files:
            return jsonify({
                'success': False,
                'message': 'لم يتم إرفاق ملف'
            }), 400
        
        file = request.files['file']
        
        if file.filename == '':
            return jsonify({
                'success': False,
                'message': 'لم يتم اختيار ملف'
            }), 400
        
        # Get metadata
        metadata = {
            'manufacturer': request.form.get('manufacturer', 'Unknown'),
            'model': request.form.get('model', 'Unknown'),
            'version': request.form.get('version', 'Unknown'),
            'device_id': request.form.get('device_id'),
            'user_id': current_user.id
        }
        
        # Save firmware
        upload_result = firmware_manager.upload_manager.save_firmware(file, metadata)
        
        if not upload_result['success']:
            return jsonify({
                'success': False,
                'message': 'فشل رفع الملف',
                'errors': upload_result.get('errors', [])
            }), 400
        
        firmware_info = upload_result['firmware']
        
        # Start analysis in background
        firmware_id = firmware_info['id']
        firmware_jobs[firmware_id] = {
            'status': 'queued',
            'progress': 0,
            'firmware_info': firmware_info
        }
        
        return jsonify({
            'success': True,
            'message': 'تم رفع الملف بنجاح',
            'firmware_id': firmware_id,
            'firmware': firmware_info
        })
    
    except Exception as e:
        logger.error(f"Upload error: {e}")
        return jsonify({
            'success': False,
            'message': f'خطأ في رفع الملف: {str(e)}'
        }), 500


@firmware_bp.route('/firmware/<firmware_id>/analyze', methods=['POST'])
@login_required
def analyze_firmware(firmware_id):
    """
    Start firmware analysis
    
    Args:
        firmware_id: ID of uploaded firmware
    """
    try:
        # Check if firmware exists
        firmware_info = firmware_manager.upload_manager.get_firmware_info(firmware_id)
        
        if not firmware_info:
            return jsonify({
                'success': False,
                'message': 'الملف غير موجود'
            }), 404
        
        # Check if already analyzing
        if firmware_id in firmware_jobs and firmware_jobs[firmware_id]['status'] == 'analyzing':
            return jsonify({
                'success': False,
                'message': 'التحليل قيد التشغيل بالفعل'
            }), 400
        
        # Update status
        firmware_jobs[firmware_id] = {
            'status': 'analyzing',
            'progress': 0,
            'firmware_info': firmware_info,
            'started_at': datetime.now().isoformat()
        }
        
        # Start analysis in background thread
        import threading
        thread = threading.Thread(
            target=perform_firmware_analysis,
            args=(firmware_id, firmware_info)
        )
        thread.daemon = True
        thread.start()
        
        return jsonify({
            'success': True,
            'message': 'بدأ تحليل البرنامج الثابت',
            'firmware_id': firmware_id
        })
    
    except Exception as e:
        logger.error(f"Analysis start error: {e}")
        return jsonify({
            'success': False,
            'message': f'خطأ في بدء التحليل: {str(e)}'
        }), 500


@firmware_bp.route('/firmware/<firmware_id>/status', methods=['GET'])
@login_required
def get_firmware_analysis_status(firmware_id):
    """Get firmware analysis status"""
    try:
        if firmware_id not in firmware_jobs:
            return jsonify({
                'success': False,
                'message': 'التحليل غير موجود'
            }), 404
        
        status = firmware_jobs[firmware_id]
        
        return jsonify({
            'success': True,
            'status': status
        })
    
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'خطأ: {str(e)}'
        }), 500


@firmware_bp.route('/firmware/<firmware_id>/report', methods=['GET'])
@login_required
def get_firmware_report(firmware_id):
    """Get firmware analysis report"""
    try:
        report = firmware_manager.get_analysis_report(firmware_id)
        
        if not report:
            return jsonify({
                'success': False,
                'message': 'التقرير غير موجود'
            }), 404
        
        return jsonify({
            'success': True,
            'report': report
        })
    
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'خطأ: {str(e)}'
        }), 500


@firmware_bp.route('/firmware/list', methods=['GET'])
@login_required
def list_firmware():
    """List all analyzed firmware"""
    try:
        firmware_list = firmware_manager.list_analyzed_firmware()
        
        return jsonify({
            'success': True,
            'firmware': firmware_list
        })
    
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'خطأ: {str(e)}'
        }), 500


@firmware_bp.route('/firmware/<firmware_id>/delete', methods=['DELETE'])
@login_required
def delete_firmware(firmware_id):
    """Delete firmware file and analysis"""
    try:
        success = firmware_manager.upload_manager.delete_firmware(firmware_id)
        
        if success:
            # Remove from jobs
            if firmware_id in firmware_jobs:
                del firmware_jobs[firmware_id]
            
            # Remove analysis report
            if firmware_id in firmware_manager.analysis_reports:
                del firmware_manager.analysis_reports[firmware_id]
            
            return jsonify({
                'success': True,
                'message': 'تم حذف الملف بنجاح'
            })
        else:
            return jsonify({
                'success': False,
                'message': 'فشل حذف الملف'
            }), 404
    
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'خطأ: {str(e)}'
        }), 500


def perform_firmware_analysis(firmware_id, firmware_info):
    """
    Perform firmware analysis in background
    
    Args:
        firmware_id: Firmware ID
        firmware_info: Firmware information
    """
    try:
        # Update progress
        firmware_jobs[firmware_id]['progress'] = 10
        firmware_jobs[firmware_id]['current_step'] = 'استخراج البرنامج الثابت...'
        
        # Create mock file object for analysis
        class MockFile:
            def __init__(self, path, filename):
                self.path = path
                self.filename = filename
            
            def save(self, dest_path):
                import shutil
                shutil.copy2(self.path, dest_path)
        
        mock_file = MockFile(firmware_info['file_path'], firmware_info['original_filename'])
        
        metadata = {
            'manufacturer': firmware_info.get('manufacturer'),
            'model': firmware_info.get('model'),
            'version': firmware_info.get('version')
        }
        
        # Run analysis
        firmware_jobs[firmware_id]['progress'] = 30
        firmware_jobs[firmware_id]['current_step'] = 'تحليل البرنامج الثابت...'
        
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        report = loop.run_until_complete(
            firmware_manager.upload_and_analyze(mock_file, metadata)
        )
        loop.close()
        
        # Update job status
        firmware_jobs[firmware_id]['status'] = 'completed'
        firmware_jobs[firmware_id]['progress'] = 100
        firmware_jobs[firmware_id]['current_step'] = 'اكتمل التحليل'
        firmware_jobs[firmware_id]['report'] = report
        firmware_jobs[firmware_id]['completed_at'] = datetime.now().isoformat()
        
        logger.info(f"Firmware analysis completed for {firmware_id}")
    
    except Exception as e:
        logger.error(f"Firmware analysis error: {e}")
        import traceback
        traceback.print_exc()
        
        firmware_jobs[firmware_id]['status'] = 'failed'
        firmware_jobs[firmware_id]['error'] = str(e)
