
from flask import Blueprint, request, jsonify
from flask import current_app
from datetime import datetime
import threading
import uuid
from src.models import db, Device, Vulnerability, ScanResult, Report
from src.services.device_scanner import DeviceScanner
from src.services.vulnerability_scanner import VulnerabilityScanner
from src.services.report_generator import ReportGenerator

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
    
    # Start scan in background thread
    scan_id = str(uuid.uuid4())
    scan_status = {
        'is_scanning': True,
        'progress': 0,
        'current_step': 'بدء الفحص...',
        'scan_id': scan_id,
        'devices_found': 0,
        'vulnerabilities_found': 0
    }
    
   # تمرير current_app إلى الدالة
    thread = threading.Thread(
        target=perform_scan, 
        args=(network_range, scan_id, current_app._get_current_object())
    )
    thread.daemon = True
    thread.start()
    
    return jsonify({
        'success': True,
        'message': 'تم بدء الفحص بنجاح',
        'scan_id': scan_id
    })

@scanner_bp.route('/scan/status', methods=['GET'])
def get_scan_status():
    """Get current scan status"""
    return jsonify(scan_status)

@scanner_bp.route('/scan/stop', methods=['POST'])
def stop_scan():
    """Stop current scan"""
    global scan_status
    
    if not scan_status['is_scanning']:
        return jsonify({
            'success': False,
            'message': 'لا يوجد فحص قيد التشغيل'
        }), 400
    
    scan_status['is_scanning'] = False
    scan_status['current_step'] = 'تم إيقاف الفحص'
    
    return jsonify({
        'success': True,
        'message': 'تم إيقاف الفحص'
    })

@scanner_bp.route('/devices', methods=['GET'])
def get_devices():
    """Get all discovered devices"""
    try:
        devices = Device.query.all()
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
def get_device_details(device_id):
    """Get detailed information about a specific device"""
    try:
        device = Device.query.get_or_404(device_id)
        
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
def get_vulnerabilities():
    """Get all discovered vulnerabilities"""
    try:
        vulnerabilities = Vulnerability.query.all()
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
def get_vulnerability_stats():
    """Get vulnerability statistics"""
    try:
        total_vulns = Vulnerability.query.count()
        critical_count = Vulnerability.query.filter_by(severity='Critical').count()
        high_count = Vulnerability.query.filter_by(severity='High').count()
        medium_count = Vulnerability.query.filter_by(severity='Medium').count()
        low_count = Vulnerability.query.filter_by(severity='Low').count()
        
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
def generate_report():
    """Generate a security report"""
    try:
        data = request.get_json() or {}
        report_title = data.get('title', f'تقرير أمان IoT - {datetime.now().strftime("%Y-%m-%d")}')
        
        # Get all devices and their vulnerabilities
        devices = Device.query.all()
        vulnerabilities = Vulnerability.query.all()
        scan_results = ScanResult.query.all()
        
        # Convert to dictionaries
        devices_data = [device.to_dict() for device in devices]
        vulns_data = [vuln.to_dict() for vuln in vulnerabilities]
        results_data = [result.to_dict() for result in scan_results]
        
        # Generate report
        report_info = report_generator.generate_report(
            devices_data, vulns_data, results_data, report_title
        )
        
        # Save report to database
        report = Report(
            title=report_info['title'],
            file_path=report_info['html_file'],
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
def get_reports():
    """Get list of generated reports"""
    try:
        reports = Report.query.order_by(Report.generated_at.desc()).all()
        return jsonify({
            'success': True,
            'reports': [report.to_dict() for report in reports]
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'خطأ في جلب التقارير: {str(e)}'
        }), 500

@scanner_bp.route('/reports/<report_id>/download', methods=['GET'])
def download_report(report_id):
    """Download a specific report"""
    try:
        report = Report.query.get_or_404(report_id)
        
        # Return file path for frontend to handle download
        return jsonify({
            'success': True,
            'file_path': report.file_path,
            'filename': f"{report.title}.html"
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'خطأ في تحميل التقرير: {str(e)}'
        }), 500

def perform_scan(network_range, scan_id, app):
    """Perform the actual scanning in background"""
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
                # Check if device already exists
                existing_device = Device.query.filter_by(ip_address=device_info['ip_address']).first()
                
                if existing_device:
                    # Update existing device
                    for key, value in device_info.items():
                        if hasattr(existing_device, key):
                            setattr(existing_device, key, value)
                    device = existing_device
                else:
                    # Create new device
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
            
            # Step 4: Complete
            scan_status['current_step'] = 'اكتمل الفحص'
            scan_status['progress'] = 100
            scan_status['is_scanning'] = False
            
        except Exception as e:
            print(f"Error during scan: {e}")
            scan_status['current_step'] = f'خطأ في الفحص: {str(e)}'
            scan_status['is_scanning'] = False

