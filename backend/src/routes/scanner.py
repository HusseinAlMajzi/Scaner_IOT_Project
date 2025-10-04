
from flask import Blueprint, request, jsonify, send_file
from flask import current_app
from flask_login import login_required, current_user
from datetime import datetime
import threading
import uuid
import os
from src.models import db, Device, Vulnerability, ScanResult, Report, ScanSession
from src.services.device_scanner import DeviceScanner
from src.services.vulnerability_scanner import VulnerabilityScanner
from src.services.report_generator import ReportGenerator
import asyncio
import sys

scanner_bp = Blueprint('scanner', __name__)

# Global variables to track scan status
scan_status = {
    'is_scanning': False,
    'progress': 0,
    'current_step': '',
    'scan_id': None,
    'devices_found': 0,
    'vulnerabilities_found': 0
}

device_scanner = DeviceScanner()
vuln_scanner = VulnerabilityScanner()
report_generator = ReportGenerator()

@scanner_bp.route('/scan/start', methods=['POST'])
@login_required
def start_scan():
    """Start a new network scan"""
    global scan_status
    
    if scan_status['is_scanning']:
        return jsonify({
            'success': False,
            'message': 'فحص آخر قيد التشغيل بالفعل'
        }), 400
    
    data = request.get_json() or {}
    network_range = data.get('network_range')
    scan_mode = data.get('scan_mode', 'standard')
    scan_name = data.get('scan_name', f'فحص {datetime.now().strftime("%Y-%m-%d %H:%M")}')
    
    # Create new scan session
    scan_id = str(uuid.uuid4())
    scan_session = ScanSession(
        id=scan_id,
        user_id=current_user.id,
        name=scan_name,
        scan_mode=scan_mode,
        status='running',
        started_at=datetime.now()
    )
    db.session.add(scan_session)
    db.session.commit()
    
    # Start scan in background thread
    scan_status = {
        'is_scanning': True,
        'progress': 0,
        'current_step': 'بدء الفحص...',
        'scan_id': scan_id,
        'devices_found': 0,
        'vulnerabilities_found': 0,
        'scan_mode': scan_mode
    }
    
   # تمرير current_app والمستخدم إلى الدالة
    if scan_mode == 'comprehensive':
        # Use ALL services comprehensively
        thread = threading.Thread(
            target=perform_ultra_comprehensive_scan, 
            args=(network_range, scan_id, current_app._get_current_object(), current_user.id)
        )
    elif scan_mode == 'enhanced':
        thread = threading.Thread(
            target=perform_enhanced_scan, 
            args=(network_range, scan_id, current_app._get_current_object(), current_user.id)
        )
    else:
        thread = threading.Thread(
            target=perform_comprehensive_scan, 
            args=(network_range, scan_id, current_app._get_current_object(), current_user.id)
        )
    
    thread.daemon = True
    thread.start()
    
    return jsonify({
        'success': True,
        'message': 'تم بدء الفحص بنجاح',
        'scan_id': scan_id,
        'scan_mode': scan_mode
    })

@scanner_bp.route('/scan/status', methods=['GET'])
@login_required
def get_scan_status():
    """Get current scan status"""
    return jsonify(scan_status)

@scanner_bp.route('/scan/stop', methods=['POST'])
@login_required
def stop_scan():
    """Stop current scan"""
    global scan_status
    
    # Always allow stopping, even if no scan is running (to fix stuck states)
    scan_status['is_scanning'] = False
    scan_status['current_step'] = 'تم إيقاف الفحص'
    scan_status['progress'] = 0
    
    return jsonify({
        'success': True,
        'message': 'تم إيقاف الفحص'
    })

@scanner_bp.route('/devices', methods=['GET'])
@login_required
def get_devices():
    """Get devices for current user, optionally filtered by scan session"""
    try:
        scan_session_id = request.args.get('scan_session_id')
        
        if scan_session_id:
            # Get devices for specific scan session
            devices = Device.query.filter_by(
                user_id=current_user.id,
                scan_session_id=scan_session_id
            ).all()
        else:
            # Get all devices (for backward compatibility)
            devices = Device.query.filter_by(user_id=current_user.id).all()
        
        return jsonify({
            'success': True,
            'devices': [device.to_dict() for device in devices]
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'خطأ في جلب الأجهزة: {str(e)}'
        }), 500

@scanner_bp.route('/devices/<device_id>', methods=['GET'])
@login_required
def get_device_details(device_id):
    """Get detailed information about a specific device"""
    try:
        device = Device.query.filter_by(id=device_id, user_id=current_user.id).first()
        if not device:
            return jsonify({
                'success': False,
                'message': 'الجهاز غير موجود أو لا تملك صلاحية للوصول إليه'
            }), 404
        
        # Get vulnerabilities for this device
        scan_results = ScanResult.query.filter_by(device_id=device_id).all()
        vulnerabilities = []
        
        for result in scan_results:
            vuln = Vulnerability.query.get(result.vulnerability_id)
            if vuln:
                vuln_dict = vuln.to_dict()
                vuln_dict['scan_result'] = result.to_dict()
                vulnerabilities.append(vuln_dict)
        
        device_dict = device.to_dict()
        device_dict['vulnerabilities'] = vulnerabilities
        
        return jsonify({
            'success': True,
            'device': device_dict
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'خطأ في جلب تفاصيل الجهاز: {str(e)}'
        }), 500

@scanner_bp.route('/vulnerabilities', methods=['GET'])
@login_required
def get_vulnerabilities():
    """Get vulnerabilities, optionally filtered by scan session"""
    try:
        scan_session_id = request.args.get('scan_session_id')
        
        # Get devices for this session or all user devices
        if scan_session_id:
            user_device_ids = [d.id for d in Device.query.filter_by(
                user_id=current_user.id,
                scan_session_id=scan_session_id
            ).all()]
        else:
            user_device_ids = [d.id for d in Device.query.filter_by(user_id=current_user.id).all()]
        
        if not user_device_ids:
            return jsonify({
                'success': True,
                'vulnerabilities': []
            })
        
        scan_results = ScanResult.query.filter(ScanResult.device_id.in_(user_device_ids)).all()
        vuln_ids = [sr.vulnerability_id for sr in scan_results]
        vulnerabilities = Vulnerability.query.filter(Vulnerability.id.in_(vuln_ids)).all() if vuln_ids else []
        
        return jsonify({
            'success': True,
            'vulnerabilities': [vuln.to_dict() for vuln in vulnerabilities]
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'خطأ في جلب الثغرات: {str(e)}'
        }), 500

@scanner_bp.route('/vulnerabilities/stats', methods=['GET'])
@login_required
def get_vulnerability_stats():
    """Get vulnerability statistics, optionally filtered by scan session"""
    try:
        scan_session_id = request.args.get('scan_session_id')
        
        # Get devices for this session or all user devices
        if scan_session_id:
            user_device_ids = [d.id for d in Device.query.filter_by(
                user_id=current_user.id,
                scan_session_id=scan_session_id
            ).all()]
        else:
            user_device_ids = [d.id for d in Device.query.filter_by(user_id=current_user.id).all()]
        
        if not user_device_ids:
            return jsonify({
                'success': True,
                'stats': {'total': 0, 'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
            })
        
        scan_results = ScanResult.query.filter(ScanResult.device_id.in_(user_device_ids)).all()
        vuln_ids = [sr.vulnerability_id for sr in scan_results]
        
        if not vuln_ids:
            return jsonify({
                'success': True,
                'stats': {'total': 0, 'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
            })
        
        total_vulns = Vulnerability.query.filter(Vulnerability.id.in_(vuln_ids)).count()
        critical_count = Vulnerability.query.filter(Vulnerability.id.in_(vuln_ids), Vulnerability.severity=='Critical').count()
        high_count = Vulnerability.query.filter(Vulnerability.id.in_(vuln_ids), Vulnerability.severity=='High').count()
        medium_count = Vulnerability.query.filter(Vulnerability.id.in_(vuln_ids), Vulnerability.severity=='Medium').count()
        low_count = Vulnerability.query.filter(Vulnerability.id.in_(vuln_ids), Vulnerability.severity=='Low').count()
        
        return jsonify({
            'success': True,
            'stats': {
                'total': total_vulns,
                'critical': critical_count,
                'high': high_count,
                'medium': medium_count,
                'low': low_count
            }
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'خطأ في جلب إحصائيات الثغرات: {str(e)}'
        }), 500

@scanner_bp.route('/reports/generate', methods=['POST'])
@login_required
def generate_report():
    """Generate a security report for active scan session"""
    try:
        data = request.get_json() or {}
        report_title = data.get('title', f'تقرير أمان IoT - {datetime.now().strftime("%Y-%m-%d")}')
        scan_session_id = data.get('scan_session_id')  # Get scan session filter
        
        # Get devices for this scan session or all user devices
        if scan_session_id:
            devices = Device.query.filter_by(
                user_id=current_user.id,
                scan_session_id=scan_session_id
            ).all()
            
            # Add scan name to report title
            scan_session = ScanSession.query.get(scan_session_id)
            if scan_session:
                report_title = f'تقرير: {scan_session.name}'
        else:
            devices = Device.query.filter_by(user_id=current_user.id).all()
        user_device_ids = [d.id for d in devices]
        scan_results = ScanResult.query.filter(ScanResult.device_id.in_(user_device_ids)).all()
        vuln_ids = [sr.vulnerability_id for sr in scan_results]
        vulnerabilities = Vulnerability.query.filter(Vulnerability.id.in_(vuln_ids)).all()
        
        # Convert to dictionaries
        devices_data = [device.to_dict() for device in devices]
        vulns_data = [vuln.to_dict() for vuln in vulnerabilities]
        results_data = [result.to_dict() for result in scan_results]
        
        # Generate report
        report_info = report_generator.generate_report(
            devices_data, vulns_data, results_data, report_title
        )
        
        # Save report to database - use PDF if available, otherwise HTML
        report_file = report_info.get('pdf_file') or report_info['html_file']
        report = Report(
            user_id=current_user.id,
            title=report_info['title'],
            file_path=report_file,
            scan_ids=report_info['scan_ids'],
            summary=report_info['summary'],
            total_devices=report_info['total_devices'],
            total_vulnerabilities=report_info['total_vulnerabilities'],
            critical_count=report_info['critical_count'],
            high_count=report_info['high_count'],
            medium_count=report_info['medium_count'],
            low_count=report_info['low_count']
        )
        
        db.session.add(report)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'تم إنشاء التقرير بنجاح',
            'report': report.to_dict()
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'خطأ في إنشاء التقرير: {str(e)}'
        }), 500

@scanner_bp.route('/reports', methods=['GET'])
@login_required
def get_reports():
    """Get list of generated reports for current user"""
    try:
        reports = Report.query.filter_by(user_id=current_user.id).order_by(Report.generated_at.desc()).all()
        return jsonify({
            'success': True,
            'reports': [report.to_dict() for report in reports]
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'خطأ في جلب التقارير: {str(e)}'
        }), 500

@scanner_bp.route('/scan/wireless', methods=['POST'])
@login_required
def start_wireless_scan():
    """Start wireless scanning (BLE, Bluetooth, Wi-Fi)"""
    global scan_status
    
    if scan_status['is_scanning']:
        return jsonify({
            'success': False,
            'message': 'فحص آخر قيد التشغيل بالفعل'
        }), 400
    
    data = request.get_json() or {}
    scan_bluetooth = data.get('scan_bluetooth', True)
    scan_wifi = data.get('scan_wifi', True)
    
    # Start wireless scan in background thread
    scan_id = str(uuid.uuid4())
    scan_status = {
        'is_scanning': True,
        'progress': 0,
        'current_step': 'بدء فحص الأجهزة اللاسلكية...',
        'scan_id': scan_id,
        'devices_found': 0,
        'vulnerabilities_found': 0,
        'scan_mode': 'wireless'
    }
    
    thread = threading.Thread(
        target=perform_wireless_scan,
        args=(scan_id, current_app._get_current_object(), current_user.id, 
              scan_bluetooth, scan_wifi)
    )
    thread.daemon = True
    thread.start()
    
    return jsonify({
        'success': True,
        'message': 'تم بدء فحص الأجهزة اللاسلكية بنجاح',
        'scan_id': scan_id
    })

@scanner_bp.route('/scan/iot-protocols', methods=['POST'])
@login_required
def start_iot_protocol_scan():
    """Start IoT protocol scanning (Zigbee, Z-Wave, LoRaWAN)"""
    global scan_status
    
    if scan_status['is_scanning']:
        return jsonify({
            'success': False,
            'message': 'فحص آخر قيد التشغيل بالفعل'
        }), 400
    
    # Start IoT protocol scan in background thread
    scan_id = str(uuid.uuid4())
    scan_status = {
        'is_scanning': True,
        'progress': 0,
        'current_step': 'بدء فحص بروتوكولات IoT...',
        'scan_id': scan_id,
        'devices_found': 0,
        'vulnerabilities_found': 0,
        'scan_mode': 'iot_protocols'
    }
    
    thread = threading.Thread(
        target=perform_iot_protocol_scan,
        args=(scan_id, current_app._get_current_object(), current_user.id)
    )
    thread.daemon = True
    thread.start()
    
    return jsonify({
        'success': True,
        'message': 'تم بدء فحص بروتوكولات IoT بنجاح',
        'scan_id': scan_id
    })

@scanner_bp.route('/scan/advanced-security', methods=['POST'])
@login_required
def start_advanced_security_scan():
    """Start advanced security scanning (Phase 6)"""
    global scan_status
    
    if scan_status['is_scanning']:
        return jsonify({
            'success': False,
            'message': 'فحص آخر قيد التشغيل بالفعل'
        }), 400
    
    # Start advanced security scan
    scan_id = str(uuid.uuid4())
    scan_status = {
        'is_scanning': True,
        'progress': 0,
        'current_step': 'بدء الفحص الأمني المتقدم...',
        'scan_id': scan_id,
        'devices_found': 0,
        'vulnerabilities_found': 0,
        'scan_mode': 'advanced_security'
    }
    
    thread = threading.Thread(
        target=perform_advanced_security_scan,
        args=(scan_id, current_app._get_current_object(), current_user.id)
    )
    thread.daemon = True
    thread.start()
    
    return jsonify({
        'success': True,
        'message': 'تم بدء الفحص الأمني المتقدم بنجاح',
        'scan_id': scan_id
    })

@scanner_bp.route('/reports/<report_id>/download', methods=['GET'])
@login_required
def download_report(report_id):
    """Download a specific report as PDF"""
    try:
        
        report = Report.query.filter_by(id=report_id, user_id=current_user.id).first()
        if not report:
            return jsonify({
                'success': False,
                'message': 'التقرير غير موجود'
            }), 404
        
        if not os.path.exists(report.file_path):
            return jsonify({
                'success': False,
                'message': 'ملف التقرير غير موجود'
            }), 404
        
        # Determine file extension
        file_ext = '.pdf' if report.file_path.endswith('.pdf') else '.html'
        download_name = f"{report.title}{file_ext}"
        
        # Send file for download
        return send_file(
            report.file_path,
            as_attachment=True,
            download_name=download_name,
            mimetype='application/pdf' if file_ext == '.pdf' else 'text/html'
        )
        
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'خطأ في تحميل التقرير: {str(e)}'
        }), 500


@scanner_bp.route('/reports/<report_id>/preview', methods=['GET'])
@login_required
def preview_report(report_id):
    """Preview a report in browser"""
    try:
        
        report = Report.query.filter_by(id=report_id, user_id=current_user.id).first()
        if not report:
            return jsonify({
                'success': False,
                'message': 'التقرير غير موجود'
            }), 404
        
        # For preview, always use HTML version if available
        html_path = report.file_path.replace('.pdf', '.html') if report.file_path.endswith('.pdf') else report.file_path
        
        if not os.path.exists(html_path):
            return jsonify({
                'success': False,
                'message': 'ملف المعاينة غير موجود'
            }), 404
        
        # Send HTML file for preview (not as attachment)
        return send_file(
            html_path,
            mimetype='text/html'
        )
        
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'خطأ في معاينة التقرير: {str(e)}'
        }), 500

def perform_comprehensive_scan(network_range, scan_id, app, user_id):
    """Perform COMPREHENSIVE scanning using ALL available services"""
    global scan_status

    with app.app_context(): 
    
        try:
            
    
            # Step 1: Network Discovery
            scan_status['current_step'] = 'اكتشاف الأجهزة في الشبكة...'
            scan_status['progress'] = 5
            
            discovered_devices = device_scanner.scan_network(network_range)
            scan_status['devices_found'] = len(discovered_devices)
            scan_status['progress'] = 30
            
            # Step 2: Save devices to database
            scan_status['current_step'] = 'حفظ معلومات الأجهزة...'
            
            saved_devices = []
            for device_info in discovered_devices:
                # Always create NEW device for each scan (don't reuse old devices)
                # This ensures each scan has its own isolated data
                device_info['user_id'] = user_id
                device_info['scan_session_id'] = scan_id
                device = Device(**device_info)
                db.session.add(device)
                saved_devices.append(device)
            
            db.session.commit()
            scan_status['progress'] = 50
            
            # Step 3: Vulnerability Scanning
            scan_status['current_step'] = 'فحص الثغرات الأمنية...'
            
            total_vulnerabilities = 0
            
            for i, device in enumerate(saved_devices):
                if not scan_status['is_scanning']:
                    break
                    
                scan_status['current_step'] = f'فحص الجهاز {device.ip_address}...'
                
                # Get device info as dict
                device_info = device.to_dict()
                
                # Scan for vulnerabilities
                vulnerabilities = vuln_scanner.scan_device_vulnerabilities(device_info)
                
                # Save vulnerabilities and scan results
                for vuln_data in vulnerabilities:
                    # Check if vulnerability already exists
                    existing_vuln = None
                    if vuln_data.get('cve_id'):
                        existing_vuln = Vulnerability.query.filter_by(cve_id=vuln_data['cve_id']).first()
                    
                    if existing_vuln:
                        vulnerability = existing_vuln
                    else:
                        # Create new vulnerability
                        vulnerability = Vulnerability(
                            cve_id=vuln_data.get('cve_id'),
                            description=vuln_data['description'],
                            severity=vuln_data['severity'],
                            recommendation=vuln_data.get('recommendation'),
                            source=vuln_data['source'],
                            cvss_score=vuln_data.get('cvss_score'),
                            affected_products=vuln_data.get('affected_products'),
                            references=vuln_data.get('references'),
                            published_date=vuln_data.get('published_date'),
                            updated_date=vuln_data.get('updated_date')
                        )
                        db.session.add(vulnerability)
                        db.session.flush()  # Get the ID
                    
                    # Create scan result
                    scan_result = ScanResult(
                        device_id=device.id,
                        vulnerability_id=vulnerability.id,
                        status='Detected',
                        confidence_level='Medium'
                    )
                    db.session.add(scan_result)
                    total_vulnerabilities += 1
                
                # Update progress
                progress = 50 + (i + 1) / len(saved_devices) * 40
                scan_status['progress'] = int(progress)
            
            db.session.commit()
            scan_status['vulnerabilities_found'] = total_vulnerabilities
            
            # Update scan session status
            session = ScanSession.query.get(scan_id)
            if session:
                session.status = 'completed'
                session.completed_at = datetime.now()
                session.devices_found = scan_status['devices_found']
                session.vulnerabilities_found = total_vulnerabilities
                db.session.commit()
            
            # Step 4: Complete
            scan_status['current_step'] = 'اكتمل الفحص'
            scan_status['progress'] = 100
            scan_status['is_scanning'] = False
            
        except Exception as e:
            print(f"Error during scan: {e}")
            scan_status['current_step'] = f'خطأ في الفحص: {str(e)}'
            scan_status['is_scanning'] = False


def perform_enhanced_scan(network_range, scan_id, app, user_id):
    """
    Perform enhanced scanning with Phase 2 features:
    - Passive discovery
    - mDNS/SSDP service discovery
    - Advanced fingerprinting
    - Protocol recognition
    """
    global scan_status
    
    with app.app_context():
        try:
            from src.services.enhanced_scanner import EnhancedScanner
            
            # Step 1: Initialize enhanced scanner
            scan_status['current_step'] = 'بدء الفحص المتقدم...'
            scan_status['progress'] = 5
            
            scanner = EnhancedScanner(network_range=network_range)
            
            # Step 2: Run comprehensive scan
            scan_status['current_step'] = 'تشغيل الفحص الشامل (سلبي + mDNS/SSDP + نشط)...'
            scan_status['progress'] = 10
            
            # Run async scan in sync context
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            discovered_devices = loop.run_until_complete(
                scanner.comprehensive_scan(
                    use_passive=True,
                    use_service=True,
                    use_active=True if network_range else False,
                    fingerprint=True
                )
            )
            loop.close()
            
            scan_status['devices_found'] = len(discovered_devices)
            scan_status['progress'] = 40
            
            # Step 3: Save devices to database
            scan_status['current_step'] = 'حفظ معلومات الأجهزة المكتشفة...'
            
            saved_devices = []
            for device_info in discovered_devices:
                # Always create NEW device for this scan session
                device_data = {
                    'user_id': user_id,
                    'scan_session_id': scan_id,
                    'ip_address': device_info['ip_address'],
                    'mac_address': device_info.get('mac_address'),
                    'hostname': device_info.get('hostname'),
                    'manufacturer': device_info.get('manufacturer'),
                    'device_type': device_info.get('device_type', 'unknown'),
                    'open_ports': device_info.get('open_ports', []),
                    'last_scanned_at': datetime.now()
                }
                
                device = Device(**device_data)
                db.session.add(device)
                saved_devices.append(device)
            
            db.session.commit()
            scan_status['progress'] = 60
            
            # Step 4: Vulnerability Scanning
            scan_status['current_step'] = 'فحص الثغرات الأمنية...'
            
            total_vulnerabilities = 0
            
            for i, device in enumerate(saved_devices):
                if not scan_status['is_scanning']:
                    break
                
                scan_status['current_step'] = f'فحص الجهاز {device.ip_address}...'
                
                # Get device info as dict
                device_dict = device.to_dict()
                
                # Scan for vulnerabilities
                vulnerabilities = vuln_scanner.scan_device_vulnerabilities(device_dict)
                
                # Save vulnerabilities and scan results
                for vuln_data in vulnerabilities:
                    # Check if vulnerability already exists
                    existing_vuln = None
                    if vuln_data.get('cve_id'):
                        existing_vuln = Vulnerability.query.filter_by(cve_id=vuln_data['cve_id']).first()
                    
                    if existing_vuln:
                        vulnerability = existing_vuln
                    else:
                        # Create new vulnerability
                        vulnerability = Vulnerability(
                            cve_id=vuln_data.get('cve_id'),
                            description=vuln_data['description'],
                            severity=vuln_data['severity'],
                            recommendation=vuln_data.get('recommendation'),
                            source=vuln_data['source'],
                            cvss_score=vuln_data.get('cvss_score'),
                            affected_products=vuln_data.get('affected_products'),
                            references=vuln_data.get('references'),
                            published_date=vuln_data.get('published_date'),
                            updated_date=vuln_data.get('updated_date')
                        )
                        db.session.add(vulnerability)
                        db.session.flush()
                    
                    # Create scan result
                    scan_result = ScanResult(
                        device_id=device.id,
                        vulnerability_id=vulnerability.id,
                        status='Detected',
                        confidence_level=device_dict.get('confidence', 'Medium')
                    )
                    db.session.add(scan_result)
                    total_vulnerabilities += 1
                
                # Update progress
                progress = 60 + (i + 1) / len(saved_devices) * 35
                scan_status['progress'] = int(progress)
            
            db.session.commit()
            scan_status['vulnerabilities_found'] = total_vulnerabilities
            
            # Cleanup
            scanner.cleanup()
            
            # Update scan session status
            session = ScanSession.query.get(scan_id)
            if session:
                session.status = 'completed'
                session.completed_at = datetime.now()
                session.devices_found = len(saved_devices)
                session.vulnerabilities_found = total_vulnerabilities
                db.session.commit()
            
            # Step 5: Complete
            scan_status['current_step'] = 'اكتمل الفحص المتقدم'
            scan_status['progress'] = 100
            scan_status['is_scanning'] = False
            
        except Exception as e:
            print(f"Error during enhanced scan: {e}")
            import traceback
            traceback.print_exc()
            scan_status['current_step'] = f'خطأ في الفحص المتقدم: {str(e)}'
            scan_status['is_scanning'] = False


def perform_wireless_scan(scan_id, app, user_id, scan_bluetooth=True, scan_wifi=True):
    """
    Perform wireless scanning (Phase 3):
    - Bluetooth Low Energy (BLE)
    - Classic Bluetooth
    - Wi-Fi networks
    - Wi-Fi Direct
    - Wireless fingerprinting
    """
    global scan_status
    
    with app.app_context():
        try:
            from src.services.wireless_scanner_manager import WirelessScannerManager
            
            # Step 1: Initialize wireless scanner
            scan_status['current_step'] = 'بدء فحص الأجهزة اللاسلكية...'
            scan_status['progress'] = 5
            
            scanner = WirelessScannerManager(scan_duration=15)
            
            # Step 2: Run comprehensive wireless scan
            scan_status['current_step'] = 'فحص Bluetooth و Wi-Fi...'
            scan_status['progress'] = 10
            
            # Run async scan in sync context
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            discovered_devices = loop.run_until_complete(
                scanner.comprehensive_scan(
                    scan_bluetooth=scan_bluetooth,
                    scan_wifi=scan_wifi,
                    fingerprint=True
                )
            )
            loop.close()
            
            scan_status['devices_found'] = len(discovered_devices)
            scan_status['progress'] = 50
            
            # Step 3: Save devices to database
            scan_status['current_step'] = 'حفظ معلومات الأجهزة اللاسلكية...'
            
            saved_devices = []
            for device_info in discovered_devices:
                # For wireless devices, use address or BSSID as identifier
                identifier = device_info.get('address') or device_info.get('bssid')
                if not identifier:
                    continue
                
                # Check if device already exists
                existing_device = Device.query.filter_by(
                    mac_address=identifier,
                    user_id=user_id
                ).first()
                
                # Prepare device data
                device_data = {
                    'user_id': user_id,
                    'ip_address': device_info.get('ip_address', identifier),  # Use identifier if no IP
                    'mac_address': identifier,
                    'hostname': device_info.get('name') or device_info.get('ssid'),
                    'manufacturer': device_info.get('manufacturer'),
                    'device_type': device_info.get('device_type', 'unknown_wireless'),
                    'open_ports': device_info.get('open_ports', []),
                    'last_scanned_at': datetime.now()
                }
                
                if existing_device:
                    # Update existing device
                    for key, value in device_data.items():
                        if hasattr(existing_device, key) and value is not None:
                            setattr(existing_device, key, value)
                    device = existing_device
                else:
                    # Create new device
                    device = Device(**device_data)
                    db.session.add(device)
                
                saved_devices.append(device)
            
            db.session.commit()
            scan_status['progress'] = 70
            
            # Step 4: Analyze security (create vulnerabilities for wireless issues)
            scan_status['current_step'] = 'تحليل الثغرات الأمنية...'
            
            total_vulnerabilities = 0
            
            for i, (device, device_info) in enumerate(zip(saved_devices, discovered_devices)):
                if not scan_status['is_scanning']:
                    break
                
                # Check for security vulnerabilities
                vulnerabilities_data = []
                
                # Check security posture
                security_posture = device_info.get('security_posture', {})
                concerns = security_posture.get('concerns', [])
                
                for concern in concerns:
                    vuln_data = {
                        'description': concern,
                        'severity': 'High' if 'unencrypted' in concern.lower() or 'open' in concern.lower() else 'Medium',
                        'recommendation': 'Enable encryption and secure configuration',
                        'source': 'Wireless Security Analysis'
                    }
                    vulnerabilities_data.append(vuln_data)
                
                # Check for open Wi-Fi
                if device_info.get('primary_security') == 'OPEN':
                    vulnerabilities_data.append({
                        'description': 'Open Wi-Fi network without encryption',
                        'severity': 'Critical',
                        'recommendation': 'Enable WPA2/WPA3 encryption immediately',
                        'source': 'Wi-Fi Security Analysis'
                    })
                
                # Save vulnerabilities
                for vuln_data in vulnerabilities_data:
                    # Create vulnerability
                    vulnerability = Vulnerability(
                        description=vuln_data['description'],
                        severity=vuln_data['severity'],
                        recommendation=vuln_data['recommendation'],
                        source=vuln_data['source']
                    )
                    db.session.add(vulnerability)
                    db.session.flush()
                    
                    # Create scan result
                    scan_result = ScanResult(
                        device_id=device.id,
                        vulnerability_id=vulnerability.id,
                        status='Detected',
                        confidence_level='High'
                    )
                    db.session.add(scan_result)
                    total_vulnerabilities += 1
                
                # Update progress
                progress = 70 + (i + 1) / len(saved_devices) * 25
                scan_status['progress'] = int(progress)
            
            db.session.commit()
            scan_status['vulnerabilities_found'] = total_vulnerabilities
            
            # Step 5: Complete
            scan_status['current_step'] = 'اكتمل فحص الأجهزة اللاسلكية'
            scan_status['progress'] = 100
            scan_status['is_scanning'] = False
            
        except Exception as e:
            print(f"Error during wireless scan: {e}")
            import traceback
            traceback.print_exc()
            scan_status['current_step'] = f'خطأ في فحص الأجهزة اللاسلكية: {str(e)}'
            scan_status['is_scanning'] = False


def perform_iot_protocol_scan(scan_id, app, user_id):
    """
    Perform IoT protocol scanning (Phase 5):
    - Zigbee device detection
    - Z-Wave device detection
    - LoRaWAN gateway detection
    - Thread/Matter protocol analysis
    """
    global scan_status
    
    with app.app_context():
        try:
            from src.services.iot_protocols.iot_protocol_manager import IoTProtocolManager
            
            # Step 1: Initialize IoT protocol manager
            scan_status['current_step'] = 'بدء فحص بروتوكولات IoT...'
            scan_status['progress'] = 5
            
            manager = IoTProtocolManager()
            
            # Step 2: Get existing devices from database for analysis
            scan_status['current_step'] = 'جلب بيانات الأجهزة...'
            scan_status['progress'] = 10
            
            # Get user's devices
            existing_devices = Device.query.filter_by(user_id=user_id).all()
            scan_results = [device.to_dict() for device in existing_devices]
            
            # Step 3: Run comprehensive IoT protocol analysis
            scan_status['current_step'] = 'تحليل بروتوكولات Zigbee, Z-Wave, LoRaWAN...'
            scan_status['progress'] = 20
            
            # Run async analysis in sync context
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            report = loop.run_until_complete(
                manager.comprehensive_analysis(scan_results)
            )
            loop.close()
            
            scan_status['devices_found'] = report['total_devices']
            scan_status['progress'] = 60
            
            # Step 4: Save IoT protocol findings
            scan_status['current_step'] = 'حفظ نتائج بروتوكولات IoT...'
            
            total_vulnerabilities = 0
            
            # Process Zigbee findings
            if report.get('zigbee') and report['zigbee'].get('vulnerabilities'):
                for vuln in report['zigbee']['vulnerabilities']:
                    vulnerability = Vulnerability(
                        description=f"[Zigbee] {vuln['description']}",
                        severity=vuln['severity'],
                        recommendation=vuln.get('recommendation', 'Review Zigbee security configuration'),
                        source='Zigbee Protocol Analysis'
                    )
                    db.session.add(vulnerability)
                    total_vulnerabilities += 1
            
            # Process Z-Wave findings
            if report.get('zwave') and report['zwave'].get('vulnerabilities'):
                for vuln in report['zwave']['vulnerabilities']:
                    vulnerability = Vulnerability(
                        description=f"[Z-Wave] {vuln['description']}",
                        severity=vuln['severity'],
                        recommendation=vuln.get('recommendation', 'Review Z-Wave security configuration'),
                        source='Z-Wave Protocol Analysis'
                    )
                    db.session.add(vulnerability)
                    total_vulnerabilities += 1
            
            # Process LoRaWAN findings
            if report.get('lorawan') and report['lorawan'].get('vulnerabilities'):
                for vuln in report['lorawan']['vulnerabilities']:
                    vulnerability = Vulnerability(
                        description=f"[LoRaWAN] {vuln['description']}",
                        severity=vuln['severity'],
                        recommendation=vuln.get('recommendation', 'Review LoRaWAN security configuration'),
                        source='LoRaWAN Protocol Analysis'
                    )
                    db.session.add(vulnerability)
                    total_vulnerabilities += 1
            
            db.session.commit()
            scan_status['vulnerabilities_found'] = total_vulnerabilities
            scan_status['progress'] = 90
            
            # Step 5: Complete
            scan_status['current_step'] = f'اكتمل فحص IoT - اكتشف {len(report["protocols_detected"])} بروتوكول'
            scan_status['progress'] = 100
            scan_status['is_scanning'] = False
            
        except Exception as e:
            print(f"Error during IoT protocol scan: {e}")
            import traceback
            traceback.print_exc()
            scan_status['current_step'] = f'خطأ في فحص بروتوكولات IoT: {str(e)}'
            scan_status['is_scanning'] = False


def perform_advanced_security_scan(scan_id, app, user_id):
    """
    Perform advanced security scanning (Phase 6):
    - Default credential testing
    - SSL/TLS vulnerability assessment
    - Encryption quality analysis
    - Threat intelligence correlation
    - Zero-day detection
    """
    global scan_status
    
    with app.app_context():
        try:
            from src.services.security.security_manager import SecurityAnalysisManager
            
            # Step 1: Initialize security manager
            scan_status['current_step'] = 'بدء الفحص الأمني المتقدم...'
            scan_status['progress'] = 5
            
            manager = SecurityAnalysisManager()
            
            # Step 2: Get existing devices for analysis
            scan_status['current_step'] = 'جلب بيانات الأجهزة للتحليل...'
            scan_status['progress'] = 10
            
            existing_devices = Device.query.filter_by(user_id=user_id).all()
            devices_to_analyze = [device.to_dict() for device in existing_devices]
            
            if not devices_to_analyze:
                scan_status['current_step'] = 'لا توجد أجهزة للفحص'
                scan_status['is_scanning'] = False
                return
            
            # Step 3: Run comprehensive security analysis
            scan_status['current_step'] = 'تحليل الأمان الشامل (اختبار الاعتمادات + SSL/TLS + التشفير)...'
            scan_status['progress'] = 20
            
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            analysis_results = loop.run_until_complete(
                manager.batch_security_analysis(devices_to_analyze)
            )
            loop.close()
            
            scan_status['progress'] = 60
            
            # Step 4: Save security findings
            scan_status['current_step'] = 'حفظ نتائج التحليل الأمني...'
            
            total_vulnerabilities = 0
            
            for i, (device, analysis) in enumerate(zip(existing_devices, analysis_results)):
                if not scan_status['is_scanning']:
                    break
                
                # Save vulnerabilities found by advanced security analysis
                for vuln_info in analysis.get('vulnerabilities', []):
                    vulnerability = Vulnerability(
                        description=vuln_info.get('description', ''),
                        severity=vuln_info.get('severity', 'Medium'),
                        recommendation=vuln_info.get('recommendation', 'Review security configuration'),
                        source='Advanced Security Analysis'
                    )
                    db.session.add(vulnerability)
                    db.session.flush()
                    
                    # Create scan result
                    scan_result = ScanResult(
                        device_id=device.id,
                        vulnerability_id=vulnerability.id,
                        status='Detected',
                        confidence_level='High'
                    )
                    db.session.add(scan_result)
                    total_vulnerabilities += 1
                
                progress = 60 + (i + 1) / len(existing_devices) * 35
                scan_status['progress'] = int(progress)
            
            db.session.commit()
            scan_status['vulnerabilities_found'] = total_vulnerabilities
            
            # Step 5: Complete
            scan_status['current_step'] = 'اكتمل الفحص الأمني المتقدم'
            scan_status['progress'] = 100
            scan_status['is_scanning'] = False
            
        except Exception as e:
            print(f"Error during advanced security scan: {e}")
            import traceback
            traceback.print_exc()
            scan_status['current_step'] = f'خطأ في الفحص الأمني المتقدم: {str(e)}'
            scan_status['is_scanning'] = False


def perform_ultra_comprehensive_scan(network_range, scan_id, app, user_id):
    """
    ULTRA COMPREHENSIVE SCAN - Uses ALL available services
    
    This function orchestrates a complete security assessment using:
    1. Basic network discovery (device_scanner)
    2. Enhanced discovery (enhanced_scanner) 
    3. Wireless scanning (bluetooth + wifi)
    4. IoT protocol analysis (Zigbee, Z-Wave, LoRaWAN)
    5. Deep protocol analysis (MQTT, CoAP, Modbus)
    6. Advanced security testing (credentials, SSL/TLS, encryption)
    7. Threat intelligence correlation
    8. Firmware analysis (if available)
    """
    global scan_status
    
    with app.app_context():
        try:
            print("=" * 80)
            print("STARTING ULTRA COMPREHENSIVE SCAN")
            print(f"User ID: {user_id}")
            print(f"Scan ID: {scan_id}")
            print(f"Network Range: {network_range or 'Auto-detect'}")
            print("=" * 80)
            
            all_discovered_devices = []
            all_vulnerabilities_count = 0
            
            # PHASE 1: Basic Network Discovery (10%)
            scan_status['current_step'] = '📡 Phase 1/8: Network Discovery'
            scan_status['progress'] = 5
            print("\n[Phase 1] Starting basic network discovery...")
            
            from src.services.device_scanner import DeviceScanner
            device_scanner = DeviceScanner()
            basic_devices = device_scanner.scan_network(network_range)
            print(f"[Phase 1] Found {len(basic_devices)} devices via basic scan")
            all_discovered_devices.extend(basic_devices)
            scan_status['devices_found'] = len(all_discovered_devices)
            scan_status['progress'] = 10
            
            # PHASE 2: Enhanced Discovery (20%)
            scan_status['current_step'] = '🔍 Phase 2/8: Enhanced Discovery (Passive + mDNS/SSDP)'
            scan_status['progress'] = 15
            print("\n[Phase 2] Starting enhanced discovery...")
            
            try:
                from src.services.enhanced_scanner import EnhancedScanner
                enhanced_scanner = EnhancedScanner(network_range=network_range)
                
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                enhanced_devices = loop.run_until_complete(
                    enhanced_scanner.comprehensive_scan(
                        use_passive=True,
                        use_service=True,
                        use_active=True,
                        fingerprint=True
                    )
                )
                loop.close()
                enhanced_scanner.cleanup()
                
                print(f"[Phase 2] Found {len(enhanced_devices)} devices via enhanced scan")
                # Merge devices (avoid duplicates by IP)
                existing_ips = {d['ip_address'] for d in all_discovered_devices}
                for device in enhanced_devices:
                    if device['ip_address'] not in existing_ips:
                        all_discovered_devices.append(device)
                        existing_ips.add(device['ip_address'])
                
                scan_status['devices_found'] = len(all_discovered_devices)
            except Exception as e:
                print(f"[Phase 2] Error: {e}")
            
            scan_status['progress'] = 20
            
            # PHASE 3: Wireless Scanning (30%)
            scan_status['current_step'] = '📶 Phase 3/8: Wireless Scanning (BLE + WiFi)'
            scan_status['progress'] = 25
            print("\n[Phase 3] Starting wireless scanning...")
            
            try:
                from src.services.wireless_scanner_manager import WirelessScannerManager
                wireless_scanner = WirelessScannerManager(scan_duration=10)
                
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                wireless_devices = loop.run_until_complete(
                    wireless_scanner.comprehensive_scan(
                        scan_bluetooth=True,
                        scan_wifi=True,
                        fingerprint=True
                    )
                )
                loop.close()
                
                print(f"[Phase 3] Found {len(wireless_devices)} wireless devices")
                # Add wireless devices (they have MAC addresses as identifiers)
                for device in wireless_devices:
                    identifier = device.get('address') or device.get('bssid')
                    if identifier:
                        all_discovered_devices.append({
                            'ip_address': device.get('ip_address', identifier),
                            'mac_address': identifier,
                            'hostname': device.get('name') or device.get('ssid'),
                            'manufacturer': device.get('manufacturer'),
                            'device_type': device.get('device_type', 'wireless'),
                            'open_ports': [],
                            'last_scanned_at': datetime.now()
                        })
                
                scan_status['devices_found'] = len(all_discovered_devices)
            except Exception as e:
                print(f"[Phase 3] Error: {e}")
            
            scan_status['progress'] = 30
            
            # PHASE 4: Save All Devices (35%)
            scan_status['current_step'] = '💾 Phase 4/8: Saving Discovered Devices'
            scan_status['progress'] = 35
            print(f"\n[Phase 4] Saving {len(all_discovered_devices)} devices to database...")
            
            saved_devices = []
            for device_info in all_discovered_devices:
                try:
                    # Always create NEW device for this scan session
                    device_data = {
                        'user_id': user_id,
                        'scan_session_id': scan_id,
                        'ip_address': device_info['ip_address'],
                        'mac_address': device_info.get('mac_address'),
                        'hostname': device_info.get('hostname'),
                        'manufacturer': device_info.get('manufacturer'),
                        'device_type': device_info.get('device_type', 'unknown'),
                        'open_ports': device_info.get('open_ports', []),
                        'last_scanned_at': datetime.now()
                    }
                    
                    device = Device(**device_data)
                    db.session.add(device)
                    saved_devices.append(device)
                except Exception as e:
                    print(f"[Phase 4] Error saving device {device_info.get('ip_address')}: {e}")
            
            db.session.commit()
            print(f"[Phase 4] Saved {len(saved_devices)} devices")
            scan_status['progress'] = 40
            
            # PHASE 5: Basic Vulnerability Scanning (50%)
            scan_status['current_step'] = '🔒 Phase 5/8: Vulnerability Scanning'
            scan_status['progress'] = 45
            print("\n[Phase 5] Starting vulnerability scanning...")
            
            from src.services.vulnerability_scanner import VulnerabilityScanner
            vuln_scanner = VulnerabilityScanner()
            
            for i, device in enumerate(saved_devices):
                if not scan_status['is_scanning']:
                    break
                
                try:
                    device_dict = device.to_dict()
                    vulnerabilities = vuln_scanner.scan_device_vulnerabilities(device_dict)
                    
                    for vuln_data in vulnerabilities:
                        existing_vuln = None
                        if vuln_data.get('cve_id'):
                            existing_vuln = Vulnerability.query.filter_by(cve_id=vuln_data['cve_id']).first()
                        
                        if existing_vuln:
                            vulnerability = existing_vuln
                        else:
                            vulnerability = Vulnerability(
                                cve_id=vuln_data.get('cve_id'),
                                description=vuln_data['description'],
                                severity=vuln_data['severity'],
                                recommendation=vuln_data.get('recommendation'),
                                source=vuln_data['source'],
                                cvss_score=vuln_data.get('cvss_score'),
                                affected_products=vuln_data.get('affected_products'),
                                references=vuln_data.get('references'),
                                published_date=vuln_data.get('published_date'),
                                updated_date=vuln_data.get('updated_date')
                            )
                            db.session.add(vulnerability)
                            db.session.flush()
                        
                        scan_result = ScanResult(
                            device_id=device.id,
                            vulnerability_id=vulnerability.id,
                            status='Detected',
                            confidence_level='Medium'
                        )
                        db.session.add(scan_result)
                        all_vulnerabilities_count += 1
                except Exception as e:
                    print(f"[Phase 5] Error scanning device {device.ip_address}: {e}")
                
                progress = 45 + (i + 1) / len(saved_devices) * 10
                scan_status['progress'] = int(progress)
            
            db.session.commit()
            scan_status['vulnerabilities_found'] = all_vulnerabilities_count
            print(f"[Phase 5] Found {all_vulnerabilities_count} vulnerabilities")
            scan_status['progress'] = 55
            
            # PHASE 6: IoT Protocol Analysis (65%)
            scan_status['current_step'] = '🌐 Phase 6/8: IoT Protocol Analysis (Zigbee/Z-Wave/LoRaWAN)'
            scan_status['progress'] = 60
            print("\n[Phase 6] Starting IoT protocol analysis...")
            
            try:
                from src.services.iot_protocols.iot_protocol_manager import IoTProtocolManager
                iot_manager = IoTProtocolManager()
                
                devices_data = [d.to_dict() for d in saved_devices]
                
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                protocol_report = loop.run_until_complete(
                    iot_manager.comprehensive_analysis(devices_data)
                )
                loop.close()
                
                print(f"[Phase 6] Found {len(protocol_report.get('protocols_detected', []))} IoT protocols")
                
                # Save IoT protocol vulnerabilities
                for protocol_name in ['zigbee', 'zwave', 'lorawan']:
                    if protocol_report.get(protocol_name) and protocol_report[protocol_name].get('vulnerabilities'):
                        for vuln in protocol_report[protocol_name]['vulnerabilities']:
                            vulnerability = Vulnerability(
                                description=f"[{protocol_name.upper()}] {vuln['description']}",
                                severity=vuln['severity'],
                                recommendation=vuln.get('recommendation', f'Review {protocol_name} configuration'),
                                source=f'{protocol_name.capitalize()} Protocol Analysis'
                            )
                            db.session.add(vulnerability)
                            all_vulnerabilities_count += 1
                
                db.session.commit()
                scan_status['vulnerabilities_found'] = all_vulnerabilities_count
            except Exception as e:
                print(f"[Phase 6] Error: {e}")
            
            scan_status['progress'] = 65
            
            # PHASE 7: Advanced Security Analysis (80%)
            scan_status['current_step'] = '🛡️ Phase 7/8: Advanced Security (Credentials/SSL/Encryption)'
            scan_status['progress'] = 70
            print("\n[Phase 7] Starting advanced security analysis...")
            
            try:
                from src.services.security.security_manager import SecurityAnalysisManager
                security_manager = SecurityAnalysisManager()
                
                devices_to_analyze = [d.to_dict() for d in saved_devices[:10]]  # Limit to first 10 for speed
                
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                security_results = loop.run_until_complete(
                    security_manager.batch_security_analysis(devices_to_analyze)
                )
                loop.close()
                
                print(f"[Phase 7] Analyzed {len(security_results)} devices for security issues")
                
                # Save advanced security findings
                for device, analysis in zip(saved_devices[:10], security_results):
                    for vuln_info in analysis.get('vulnerabilities', []):
                        vulnerability = Vulnerability(
                            description=vuln_info.get('description', ''),
                            severity=vuln_info.get('severity', 'Medium'),
                            recommendation=vuln_info.get('recommendation', 'Review security configuration'),
                            source='Advanced Security Analysis'
                        )
                        db.session.add(vulnerability)
                        db.session.flush()
                        
                        scan_result = ScanResult(
                            device_id=device.id,
                            vulnerability_id=vulnerability.id,
                            status='Detected',
                            confidence_level='High'
                        )
                        db.session.add(scan_result)
                        all_vulnerabilities_count += 1
                
                db.session.commit()
                scan_status['vulnerabilities_found'] = all_vulnerabilities_count
            except Exception as e:
                print(f"[Phase 7] Error: {e}")
            
            scan_status['progress'] = 80
            
            # PHASE 8: Final Commit & Summary (100%)
            scan_status['current_step'] = '✅ Phase 8/8: Finalizing Results'
            scan_status['progress'] = 90
            print("\n[Phase 8] Finalizing scan results...")
            
            try:
                db.session.commit()
                print("[Phase 8] All results committed to database")
            except Exception as e:
                print(f"[Phase 8] Commit error: {e}")
                db.session.rollback()
            
            # Update scan session
            session = ScanSession.query.get(scan_id)
            if session:
                session.status = 'completed'
                session.completed_at = datetime.now()
                session.devices_found = len(saved_devices)
                session.vulnerabilities_found = all_vulnerabilities_count
                db.session.commit()
            
            # Final summary
            scan_status['progress'] = 100
            scan_status['current_step'] = '🎉 Scan Complete!'
            scan_status['is_scanning'] = False
            
            print("\n" + "=" * 80)
            print("ULTRA COMPREHENSIVE SCAN COMPLETE")
            print(f"Total Devices Discovered: {len(saved_devices)}")
            print(f"Total Vulnerabilities Found: {all_vulnerabilities_count}")
            print(f"Scan ID: {scan_id}")
            print(f"User ID: {user_id}")
            print("=" * 80)
            
        except Exception as e:
            print(f"\n❌ SCAN ERROR: {e}")
            import traceback
            traceback.print_exc()
            scan_status['current_step'] = f'خطأ في الفحص: {str(e)}'
            scan_status['is_scanning'] = False



# ============================================================================
# SCAN SESSION MANAGEMENT ENDPOINTS
# ============================================================================

@scanner_bp.route('/scan-sessions', methods=['GET'])
@login_required
def get_scan_sessions():
    """
    Get all scan sessions for current user
    """
    try:
        sessions = ScanSession.query.filter_by(
            user_id=current_user.id
        ).order_by(ScanSession.created_at.desc()).all()
        
        return jsonify({
            'success': True,
            'sessions': [session.to_dict() for session in sessions]
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'خطأ في جلب الفحوصات: {str(e)}'
        }), 500


@scanner_bp.route('/scan-sessions/<session_id>', methods=['GET'])
@login_required
def get_scan_session(session_id):
    """
    Get specific scan session with its data
    """
    try:
        session = ScanSession.query.filter_by(
            id=session_id,
            user_id=current_user.id
        ).first()
        
        if not session:
            return jsonify({
                'success': False,
                'message': 'الفحص غير موجود'
            }), 404
        
        # Get devices for this session
        devices = Device.query.filter_by(scan_session_id=session_id).all()
        device_ids = [d.id for d in devices]
        
        # Get vulnerabilities for these devices
        scan_results = ScanResult.query.filter(
            ScanResult.device_id.in_(device_ids)
        ).all() if device_ids else []
        vuln_ids = [sr.vulnerability_id for sr in scan_results]
        vulnerabilities = Vulnerability.query.filter(
            Vulnerability.id.in_(vuln_ids)
        ).all() if vuln_ids else []
        
        session_data = session.to_dict()
        session_data['devices'] = [d.to_dict() for d in devices]
        session_data['vulnerabilities'] = [v.to_dict() for v in vulnerabilities]
        session_data['total_devices'] = len(devices)
        session_data['total_vulnerabilities'] = len(vulnerabilities)
        
        return jsonify({
            'success': True,
            'session': session_data
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'خطأ في جلب بيانات الفحص: {str(e)}'
        }), 500


@scanner_bp.route('/scan-sessions/<session_id>', methods=['DELETE'])
@login_required
def delete_scan_session(session_id):
    """
    Delete a scan session and all its associated data
    """
    try:
        session = ScanSession.query.filter_by(
            id=session_id,
            user_id=current_user.id
        ).first()
        
        if not session:
            return jsonify({
                'success': False,
                'message': 'الفحص غير موجود'
            }), 404
        
        # Delete will cascade to devices and scan_results
        db.session.delete(session)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'تم حذف الفحص بنجاح'
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({
            'success': False,
            'message': f'خطأ في حذف الفحص: {str(e)}'
        }), 500
