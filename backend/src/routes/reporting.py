"""
Advanced Reporting Routes - Phase 8
API endpoints for advanced reporting features
"""

from flask import Blueprint, request, jsonify, send_file
from flask_login import login_required, current_user
from datetime import datetime

from src.models import db, Device, Vulnerability, ScanResult, Report
from src.services.reporting.reporting_manager import AdvancedReportingManager

reporting_bp = Blueprint('reporting', __name__)

# Initialize reporting manager
reporting_manager = AdvancedReportingManager()


@reporting_bp.route('/reports/advanced/generate', methods=['POST'])
@login_required
def generate_advanced_report():
    """
    Generate advanced security report with all Phase 8 features
    
    Request body:
    {
        "title": "Report title",
        "industry": "healthcare|industrial|smart_home|enterprise",
        "include_charts": true,
        "include_comparison": true
    }
    """
    try:
        data = request.get_json() or {}
        
        title = data.get('title', f'IoT Security Report - {datetime.now().strftime("%Y-%m-%d")}')
        industry = data.get('industry', 'general')
        include_charts = data.get('include_charts', True)
        include_comparison = data.get('include_comparison', False)
        
        # Get user's devices and vulnerabilities
        devices = Device.query.filter_by(user_id=current_user.id).all()
        user_device_ids = [d.id for d in devices]
        
        scan_results = ScanResult.query.filter(
            ScanResult.device_id.in_(user_device_ids)
        ).all()
        
        vuln_ids = [sr.vulnerability_id for sr in scan_results]
        vulnerabilities = Vulnerability.query.filter(
            Vulnerability.id.in_(vuln_ids)
        ).all()
        
        # Prepare scan data
        scan_data = {
            'timestamp': datetime.now().isoformat(),
            'devices': [d.to_dict() for d in devices],
            'vulnerabilities': [v.to_dict() for v in vulnerabilities]
        }
        
        # Get previous scans for comparison (if requested)
        previous_scans = []
        if include_comparison:
            previous_reports = Report.query.filter_by(
                user_id=current_user.id
            ).order_by(Report.generated_at.desc()).limit(5).all()
            
            # Note: Would need to store full scan data in reports for real comparison
            # For now, just placeholder
        
        # Generate comprehensive report
        report_package = reporting_manager.generate_comprehensive_report(
            scan_data,
            industry=industry,
            include_charts=include_charts,
            previous_scans=previous_scans
        )
        
        # Save to database
        report = Report(
            user_id=current_user.id,
            title=title,
            file_path=report_package['report_path'],
            scan_ids=[],
            summary=str(report_package['executive_summary'].get('overview', {})),
            total_devices=len(devices),
            total_vulnerabilities=len(vulnerabilities),
            critical_count=len([v for v in vulnerabilities if v.severity == 'Critical']),
            high_count=len([v for v in vulnerabilities if v.severity == 'High']),
            medium_count=len([v for v in vulnerabilities if v.severity == 'Medium']),
            low_count=len([v for v in vulnerabilities if v.severity == 'Low'])
        )
        
        db.session.add(report)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'تم إنشاء التقرير المتقدم بنجاح',
            'report': {
                'id': report.id,
                'report_id': report_package['report_id'],
                'path': report_package['report_path'],
                'threat_analysis': {
                    'total_scored': len(report_package['threat_analysis']['prioritized_vulnerabilities']),
                    'average_score': report_package['threat_analysis']['average_threat_score']
                },
                'attack_chains_found': report_package['correlation_analysis']['total_attack_chains'],
                'visualizations_count': len(report_package.get('visualizations', {}))
            }
        })
    
    except Exception as e:
        logger.error(f"Report generation error: {e}")
        import traceback
        traceback.print_exc()
        
        return jsonify({
            'success': False,
            'message': f'خطأ في إنشاء التقرير: {str(e)}'
        }), 500


@reporting_bp.route('/reports/executive-summary', methods=['GET'])
@login_required
def get_executive_summary():
    """Get executive summary of current security posture"""
    try:
        # Get user's devices and vulnerabilities
        devices = Device.query.filter_by(user_id=current_user.id).all()
        user_device_ids = [d.id for d in devices]
        
        scan_results = ScanResult.query.filter(
            ScanResult.device_id.in_(user_device_ids)
        ).all()
        
        vuln_ids = [sr.vulnerability_id for sr in scan_results]
        vulnerabilities = Vulnerability.query.filter(
            Vulnerability.id.in_(vuln_ids)
        ).all()
        
        scan_data = {
            'timestamp': datetime.now().isoformat(),
            'devices': [d.to_dict() for d in devices],
            'vulnerabilities': [v.to_dict() for v in vulnerabilities]
        }
        
        # Generate executive summary
        summary = reporting_manager.summary_gen.generate_summary(scan_data)
        
        return jsonify({
            'success': True,
            'summary': summary
        })
    
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'خطأ: {str(e)}'
        }), 500


@reporting_bp.route('/reports/threat-scores', methods=['GET'])
@login_required
def get_threat_scores():
    """Get threat scores for all vulnerabilities"""
    try:
        devices = Device.query.filter_by(user_id=current_user.id).all()
        user_device_ids = [d.id for d in devices]
        
        scan_results = ScanResult.query.filter(
            ScanResult.device_id.in_(user_device_ids)
        ).all()
        
        vuln_ids = [sr.vulnerability_id for sr in scan_results]
        vulnerabilities = Vulnerability.query.filter(
            Vulnerability.id.in_(vuln_ids)
        ).all()
        
        devices_dict = [d.to_dict() for d in devices]
        vulns_dict = [v.to_dict() for v in vulnerabilities]
        
        # Calculate threat scores
        scored = reporting_manager.threat_scorer.prioritize_vulnerabilities(
            vulns_dict, devices_dict
        )
        
        return jsonify({
            'success': True,
            'scored_vulnerabilities': scored
        })
    
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'خطأ: {str(e)}'
        }), 500


@reporting_bp.route('/reports/attack-chains', methods=['GET'])
@login_required
def get_attack_chains():
    """Detect and return attack chains"""
    try:
        devices = Device.query.filter_by(user_id=current_user.id).all()
        user_device_ids = [d.id for d in devices]
        
        scan_results = ScanResult.query.filter(
            ScanResult.device_id.in_(user_device_ids)
        ).all()
        
        vuln_ids = [sr.vulnerability_id for sr in scan_results]
        vulnerabilities = Vulnerability.query.filter(
            Vulnerability.id.in_(vuln_ids)
        ).all()
        
        devices_dict = [d.to_dict() for d in devices]
        vulns_dict = [v.to_dict() for v in vulnerabilities]
        
        # Detect attack chains
        chains = reporting_manager.correlator.detect_attack_chains(
            vulns_dict, devices_dict
        )
        
        return jsonify({
            'success': True,
            'attack_chains': chains,
            'total': len(chains)
        })
    
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'خطأ: {str(e)}'
        }), 500


@reporting_bp.route('/reports/visualizations', methods=['GET'])
@login_required
def get_visualizations():
    """Get visualization charts"""
    try:
        devices = Device.query.filter_by(user_id=current_user.id).all()
        user_device_ids = [d.id for d in devices]
        
        scan_results = ScanResult.query.filter(
            ScanResult.device_id.in_(user_device_ids)
        ).all()
        
        vuln_ids = [sr.vulnerability_id for sr in scan_results]
        vulnerabilities = Vulnerability.query.filter(
            Vulnerability.id.in_(vuln_ids)
        ).all()
        
        scan_data = {
            'devices': [d.to_dict() for d in devices],
            'vulnerabilities': [v.to_dict() for v in vulnerabilities]
        }
        
        # Generate all charts
        charts = reporting_manager.visualizer.create_complete_dashboard(scan_data)
        
        return jsonify({
            'success': True,
            'charts': charts
        })
    
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'خطأ: {str(e)}'
        }), 500


@reporting_bp.route('/reports/statistics', methods=['GET'])
@login_required
def get_reporting_statistics():
    """Get reporting statistics"""
    try:
        stats = reporting_manager.get_report_statistics()
        
        return jsonify({
            'success': True,
            'statistics': stats
        })
    
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'خطأ: {str(e)}'
        }), 500
