"""
Custom Report Templates - Phase 8.6
Industry-specific report templates
"""

import logging
from typing import Dict
from jinja2 import Template

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ReportTemplates:
    """Manages industry-specific report templates"""
    
    # Base HTML template
    BASE_TEMPLATE = """
<!DOCTYPE html>
<html dir="rtl" lang="ar">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{ title }}</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 40px; background: #f5f5f5; }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; border-radius: 10px; }
        .section { background: white; margin: 20px 0; padding: 25px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .critical { color: #dc2626; font-weight: bold; }
        .high { color: #ea580c; font-weight: bold; }
        .medium { color: #eab308; }
        .low { color: #3b82f6; }
        table { width: 100%; border-collapse: collapse; margin: 15px 0; }
        th, td { padding: 12px; text-align: right; border-bottom: 1px solid #e5e7eb; }
        th { background: #f3f4f6; font-weight: 600; }
        .metric { font-size: 2em; font-weight: bold; color: #667eea; }
        .chart-container { margin: 20px 0; }
    </style>
</head>
<body>
    <div class="header">
        <h1>{{ title }}</h1>
        <p>تاريخ التقرير: {{ report_date }}</p>
        <p>{{ industry_note }}</p>
    </div>
    
    {{ content }}
</body>
</html>
"""
    
    HEALTHCARE_TEMPLATE = """
    <div class="section">
        <h2>🏥 Healthcare Compliance Summary</h2>
        <p><strong>HIPAA Compliance Status:</strong> {{ hipaa_status }}</p>
        <p><strong>Protected Health Information (PHI) at Risk:</strong> {{ phi_risk }}</p>
        <ul>
            <li>Medical devices scanned: {{ medical_devices }}</li>
            <li>Critical vulnerabilities affecting patient safety: {{ patient_safety_vulns }}</li>
            <li>Data encryption compliance: {{ encryption_compliance }}</li>
        </ul>
    </div>
"""
    
    INDUSTRIAL_TEMPLATE = """
    <div class="section">
        <h2>🏭 Industrial Control Systems (ICS) Security</h2>
        <p><strong>ICS/SCADA Devices:</strong> {{ ics_devices }}</p>
        <p><strong>Operational Technology (OT) Risk Level:</strong> {{ ot_risk_level }}</p>
        <ul>
            <li>PLCs/RTUs scanned: {{ plc_count }}</li>
            <li>Safety system vulnerabilities: {{ safety_vulns }}</li>
            <li>Network segmentation status: {{ segmentation_status }}</li>
            <li>Industrial protocol security: {{ protocol_security }}</li>
        </ul>
    </div>
"""
    
    SMART_HOME_TEMPLATE = """
    <div class="section">
        <h2>🏠 Smart Home Security Assessment</h2>
        <p><strong>Privacy Risk Level:</strong> {{ privacy_risk }}</p>
        <ul>
            <li>Smart devices in home: {{ smart_device_count }}</li>
            <li>Cameras/microphones with vulnerabilities: {{ surveillance_devices }}</li>
            <li>Smart locks security status: {{ lock_security }}</li>
            <li>Voice assistant security: {{ voice_assistant_security }}</li>
        </ul>
    </div>
"""
    
    ENTERPRISE_TEMPLATE = """
    <div class="section">
        <h2>🏢 Enterprise IoT Security Summary</h2>
        <p><strong>Corporate Network Risk:</strong> {{ corporate_risk }}</p>
        <ul>
            <li>IoT devices on corporate network: {{ iot_count }}</li>
            <li>Shadow IT devices discovered: {{ shadow_it_count }}</li>
            <li>Compliance status (ISO 27001): {{ iso_compliance }}</li>
            <li>Zero-trust readiness: {{ zero_trust_status }}</li>
        </ul>
    </div>
"""
    
    def __init__(self):
        """Initialize report templates"""
        self.templates = {
            'healthcare': self.HEALTHCARE_TEMPLATE,
            'industrial': self.INDUSTRIAL_TEMPLATE,
            'smart_home': self.SMART_HOME_TEMPLATE,
            'enterprise': self.ENTERPRISE_TEMPLATE
        }
    
    def generate_industry_report(self, industry: str, scan_data: Dict, 
                                 executive_summary: Dict) -> str:
        """
        Generate industry-specific report
        
        Args:
            industry: Industry type (healthcare, industrial, smart_home, enterprise)
            scan_data: Scan data
            executive_summary: Executive summary data
            
        Returns:
            HTML report
        """
        # Prepare template data
        template_data = {
            'title': f'تقرير أمان IoT - {industry.title()}',
            'report_date': datetime.now().strftime('%Y-%m-%d %H:%M'),
            'industry_note': self._get_industry_note(industry)
        }
        
        # Generate industry-specific content
        industry_content = self._generate_industry_content(industry, scan_data)
        
        # Combine with executive summary
        content_parts = []
        
        # Add executive summary section
        content_parts.append(self._format_executive_section(executive_summary))
        
        # Add industry-specific section
        content_parts.append(industry_content)
        
        # Add vulnerability details
        content_parts.append(self._format_vulnerability_section(scan_data))
        
        # Add device inventory
        content_parts.append(self._format_device_section(scan_data))
        
        template_data['content'] = '\n'.join(content_parts)
        
        # Render template
        template = Template(self.BASE_TEMPLATE)
        html = template.render(**template_data)
        
        return html
    
    def _get_industry_note(self, industry: str) -> str:
        """Get industry-specific note"""
        notes = {
            'healthcare': 'تقييم أمان الأجهزة الطبية ومتطلبات HIPAA',
            'industrial': 'تحليل أمان أنظمة التحكم الصناعي (ICS/SCADA)',
            'smart_home': 'تقييم أمان المنزل الذكي والخصوصية',
            'enterprise': 'تحليل أمان أجهزة IoT في الشبكة المؤسسية'
        }
        return notes.get(industry, 'تقرير أمان شامل لأجهزة IoT')
    
    def _generate_industry_content(self, industry: str, scan_data: Dict) -> str:
        """Generate industry-specific content section"""
        devices = scan_data.get('devices', [])
        vulnerabilities = scan_data.get('vulnerabilities', [])
        
        if industry == 'healthcare':
            medical_devices = [d for d in devices if 'medical' in d.get('device_type', '').lower()]
            patient_safety_vulns = [v for v in vulnerabilities 
                                  if v.get('severity') in ['Critical', 'High']]
            
            template = Template(self.HEALTHCARE_TEMPLATE)
            return template.render(
                hipaa_status='Needs Review' if vulnerabilities else 'Compliant',
                phi_risk='High' if patient_safety_vulns else 'Low',
                medical_devices=len(medical_devices),
                patient_safety_vulns=len(patient_safety_vulns),
                encryption_compliance='Pass' if not any('unencrypted' in v.get('description', '').lower() for v in vulnerabilities) else 'Fail'
            )
        
        elif industry == 'industrial':
            ics_devices = [d for d in devices if d.get('device_type') in ['plc', 'scada', 'rtu']]
            safety_vulns = [v for v in vulnerabilities if v.get('severity') == 'Critical']
            
            template = Template(self.INDUSTRIAL_TEMPLATE)
            return template.render(
                ics_devices=len(ics_devices),
                ot_risk_level='High' if safety_vulns else 'Medium',
                plc_count=len(ics_devices),
                safety_vulns=len(safety_vulns),
                segmentation_status='Not Implemented' if len(devices) > 5 else 'Partial',
                protocol_security='Needs Review'
            )
        
        elif industry == 'smart_home':
            cameras = [d for d in devices if 'camera' in d.get('device_type', '').lower()]
            locks = [d for d in devices if 'lock' in d.get('device_type', '').lower()]
            
            template = Template(self.SMART_HOME_TEMPLATE)
            return template.render(
                privacy_risk='High' if len(cameras) > 2 else 'Medium',
                smart_device_count=len(devices),
                surveillance_devices=len(cameras),
                lock_security='Secure' if not vulnerabilities else 'At Risk',
                voice_assistant_security='Not Scanned'
            )
        
        elif industry == 'enterprise':
            template = Template(self.ENTERPRISE_TEMPLATE)
            return template.render(
                corporate_risk='High' if vulnerabilities else 'Low',
                iot_count=len(devices),
                shadow_it_count=len([d for d in devices if d.get('discovery_method') == 'passive']),
                iso_compliance='Partial',
                zero_trust_status='Not Implemented'
            )
        
        return ""
    
    def _format_executive_section(self, summary: Dict) -> str:
        """Format executive summary section"""
        html = '<div class="section">'
        html += '<h2>📊 Executive Summary</h2>'
        
        overview = summary.get('overview', {})
        html += f'<p class="metric">{overview.get("total_devices_scanned", 0)}</p>'
        html += '<p>أجهزة تم فحصها</p>'
        
        html += f'<p class="metric">{overview.get("total_vulnerabilities_found", 0)}</p>'
        html += '<p>ثغرة أمنية</p>'
        
        risk = summary.get('risk_assessment', {})
        risk_class = risk.get('overall_risk_level', 'Low').lower()
        html += f'<p><strong>مستوى المخاطر:</strong> <span class="{risk_class}">{risk.get("overall_risk_level", "Unknown")}</span></p>'
        
        html += '</div>'
        return html
    
    def _format_vulnerability_section(self, scan_data: Dict) -> str:
        """Format vulnerability details section"""
        html = '<div class="section">'
        html += '<h2>🔍 Vulnerability Details</h2>'
        html += '<table>'
        html += '<tr><th>الجهاز</th><th>الثغرة</th><th>الخطورة</th><th>التوصية</th></tr>'
        
        for vuln in scan_data.get('vulnerabilities', [])[:20]:
            severity = vuln.get('severity', 'Low')
            severity_class = severity.lower()
            
            html += '<tr>'
            html += f'<td>{vuln.get("device_id", "N/A")}</td>'
            html += f'<td>{vuln.get("description", "")[:100]}</td>'
            html += f'<td class="{severity_class}">{severity}</td>'
            html += f'<td>{vuln.get("recommendation", "")[:100]}</td>'
            html += '</tr>'
        
        html += '</table>'
        html += '</div>'
        return html
    
    def _format_device_section(self, scan_data: Dict) -> str:
        """Format device inventory section"""
        html = '<div class="section">'
        html += '<h2>📱 Device Inventory</h2>'
        html += '<table>'
        html += '<tr><th>عنوان IP</th><th>النوع</th><th>الشركة المصنعة</th><th>المنافذ المفتوحة</th></tr>'
        
        for device in scan_data.get('devices', [])[:20]:
            html += '<tr>'
            html += f'<td>{device.get("ip_address", "N/A")}</td>'
            html += f'<td>{device.get("device_type", "Unknown")}</td>'
            html += f'<td>{device.get("manufacturer", "Unknown")}</td>'
            html += f'<td>{len(device.get("open_ports", []))}</td>'
            html += '</tr>'
        
        html += '</table>'
        html += '</div>'
        return html


# Example usage
if __name__ == '__main__':
    print("="*70)
    print("Custom Report Templates - Phase 8.6")
    print("="*70)
    
    templates = ReportTemplates()
    
    print("\nAvailable Templates:")
    for industry in templates.templates.keys():
        print(f"  - {industry.title()}")
    
    print("\n✓ Templates ready for report generation")
