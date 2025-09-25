import os
import json
from datetime import datetime
from typing import List, Dict
import markdown
from jinja2 import Template

class ReportGenerator:
    def __init__(self, reports_dir='reports'):
        self.reports_dir = reports_dir
        os.makedirs(reports_dir, exist_ok=True)
        
        # HTML template for reports
        self.html_template = """
<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{ report_title }}</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
            direction: rtl;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 0 20px rgba(0,0,0,0.1);
        }
        .header {
            text-align: center;
            border-bottom: 3px solid #2c3e50;
            padding-bottom: 20px;
            margin-bottom: 30px;
        }
        .header h1 {
            color: #2c3e50;
            margin: 0;
            font-size: 2.5em;
        }
        .header .subtitle {
            color: #7f8c8d;
            font-size: 1.2em;
            margin-top: 10px;
        }
        .summary {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px;
            border-radius: 10px;
            margin-bottom: 30px;
        }
        .summary h2 {
            margin-top: 0;
            color: white;
        }
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        .stat-card {
            background: white;
            padding: 20px;
            border-radius: 10px;
            text-align: center;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            border-left: 5px solid #3498db;
        }
        .stat-card.critical { border-left-color: #e74c3c; }
        .stat-card.high { border-left-color: #f39c12; }
        .stat-card.medium { border-left-color: #f1c40f; }
        .stat-card.low { border-left-color: #27ae60; }
        .stat-number {
            font-size: 2.5em;
            font-weight: bold;
            color: #2c3e50;
        }
        .stat-label {
            color: #7f8c8d;
            font-size: 1.1em;
        }
        .section {
            margin-bottom: 40px;
        }
        .section h2 {
            color: #2c3e50;
            border-bottom: 2px solid #ecf0f1;
            padding-bottom: 10px;
        }
        .device-card {
            background: #f8f9fa;
            border: 1px solid #dee2e6;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 20px;
        }
        .device-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
        }
        .device-ip {
            font-size: 1.3em;
            font-weight: bold;
            color: #2c3e50;
        }
        .device-type {
            background: #3498db;
            color: white;
            padding: 5px 15px;
            border-radius: 20px;
            font-size: 0.9em;
        }
        .vulnerability-list {
            margin-top: 15px;
        }
        .vulnerability-item {
            background: white;
            border: 1px solid #dee2e6;
            border-radius: 5px;
            padding: 15px;
            margin-bottom: 10px;
            border-right: 5px solid #3498db;
        }
        .vulnerability-item.critical { border-right-color: #e74c3c; }
        .vulnerability-item.high { border-right-color: #f39c12; }
        .vulnerability-item.medium { border-right-color: #f1c40f; }
        .vulnerability-item.low { border-right-color: #27ae60; }
        .vuln-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 10px;
        }
        .vuln-cve {
            font-weight: bold;
            color: #2c3e50;
        }
        .severity-badge {
            padding: 3px 10px;
            border-radius: 15px;
            font-size: 0.8em;
            font-weight: bold;
            color: white;
        }
        .severity-badge.critical { background: #e74c3c; }
        .severity-badge.high { background: #f39c12; }
        .severity-badge.medium { background: #f1c40f; color: #2c3e50; }
        .severity-badge.low { background: #27ae60; }
        .vuln-description {
            color: #555;
            margin-bottom: 10px;
        }
        .vuln-recommendation {
            background: #e8f5e8;
            border: 1px solid #c3e6c3;
            border-radius: 5px;
            padding: 10px;
            color: #2d5a2d;
        }
        .recommendations {
            background: #f0f8ff;
            border: 1px solid #b6d7ff;
            border-radius: 10px;
            padding: 20px;
            margin-top: 30px;
        }
        .recommendations h3 {
            color: #2c3e50;
            margin-top: 0;
        }
        .recommendation-list {
            list-style-type: none;
            padding: 0;
        }
        .recommendation-list li {
            background: white;
            margin: 10px 0;
            padding: 15px;
            border-radius: 5px;
            border-right: 4px solid #3498db;
        }
        .footer {
            text-align: center;
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid #ecf0f1;
            color: #7f8c8d;
        }
        @media print {
            body { background: white; }
            .container { box-shadow: none; }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>{{ report_title }}</h1>
            <div class="subtitle">تقرير أمان أجهزة إنترنت الأشياء</div>
            <div class="subtitle">{{ generation_date }}</div>
        </div>

        <div class="summary">
            <h2>ملخص التقرير</h2>
            <p>{{ summary }}</p>
        </div>

        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-number">{{ total_devices }}</div>
                <div class="stat-label">إجمالي الأجهزة</div>
            </div>
            <div class="stat-card critical">
                <div class="stat-number">{{ critical_count }}</div>
                <div class="stat-label">ثغرات حرجة</div>
            </div>
            <div class="stat-card high">
                <div class="stat-number">{{ high_count }}</div>
                <div class="stat-label">ثغرات عالية</div>
            </div>
            <div class="stat-card medium">
                <div class="stat-number">{{ medium_count }}</div>
                <div class="stat-label">ثغرات متوسطة</div>
            </div>
            <div class="stat-card low">
                <div class="stat-number">{{ low_count }}</div>
                <div class="stat-label">ثغرات منخفضة</div>
            </div>
        </div>

        <div class="section">
            <h2>تفاصيل الأجهزة والثغرات</h2>
            {% for device in devices %}
            <div class="device-card">
                <div class="device-header">
                    <div class="device-ip">{{ device.ip_address }}</div>
                    <div class="device-type">{{ device.device_type or 'جهاز غير معروف' }}</div>
                </div>
                <div>
                    <strong>الشركة المصنعة:</strong> {{ device.manufacturer or 'غير معروف' }}<br>
                    <strong>اسم المضيف:</strong> {{ device.hostname or 'غير متوفر' }}<br>
                    <strong>نظام التشغيل:</strong> {{ device.os_info or 'غير معروف' }}<br>
                    <strong>إصدار البرنامج الثابت:</strong> {{ device.firmware_version or 'غير معروف' }}
                </div>
                
                {% if device.vulnerabilities %}
                <div class="vulnerability-list">
                    <h4>الثغرات المكتشفة ({{ device.vulnerabilities|length }}):</h4>
                    {% for vuln in device.vulnerabilities %}
                    <div class="vulnerability-item {{ vuln.severity.lower() }}">
                        <div class="vuln-header">
                            <div class="vuln-cve">{{ vuln.cve_id or 'ثغرة مخصصة' }}</div>
                            <div class="severity-badge {{ vuln.severity.lower() }}">{{ vuln.severity }}</div>
                        </div>
                        <div class="vuln-description">{{ vuln.description }}</div>
                        {% if vuln.recommendation %}
                        <div class="vuln-recommendation">
                            <strong>التوصية:</strong> {{ vuln.recommendation }}
                        </div>
                        {% endif %}
                    </div>
                    {% endfor %}
                </div>
                {% else %}
                <div style="color: #27ae60; font-weight: bold; margin-top: 15px;">
                    ✓ لم يتم اكتشاف ثغرات أمنية في هذا الجهاز
                </div>
                {% endif %}
            </div>
            {% endfor %}
        </div>

        <div class="recommendations">
            <h3>التوصيات العامة لتحسين الأمان</h3>
            <ul class="recommendation-list">
                <li>قم بتحديث البرامج الثابتة لجميع الأجهزة إلى أحدث الإصدارات</li>
                <li>غيّر كلمات المرور الافتراضية واستخدم كلمات مرور قوية وفريدة</li>
                <li>فعّل التشفير لجميع الاتصالات (HTTPS, SSL/TLS)</li>
                <li>أغلق المنافذ والخدمات غير الضرورية</li>
                <li>راقب حركة الشبكة بانتظام للكشف عن الأنشطة المشبوهة</li>
                <li>قم بإجراء فحوصات أمنية دورية</li>
                <li>استخدم شبكة منفصلة لأجهزة IoT (Network Segmentation)</li>
                <li>فعّل المصادقة الثنائية حيثما أمكن</li>
            </ul>
        </div>

        <div class="footer">
            <p>تم إنشاء هذا التقرير بواسطة أداة فحص أمان أجهزة إنترنت الأشياء</p>
            <p>{{ generation_date }}</p>
        </div>
    </div>
</body>
</html>
        """
    
    def generate_report(self, devices: List[Dict], vulnerabilities: List[Dict], 
                       scan_results: List[Dict], report_title: str = None) -> Dict:
        """Generate a comprehensive security report"""
        
        if not report_title:
            report_title = f"تقرير أمان IoT - {datetime.now().strftime('%Y-%m-%d %H:%M')}"
        
        # Prepare data for report
        report_data = self._prepare_report_data(devices, vulnerabilities, scan_results)
        
        # Generate HTML report
        html_content = self._generate_html_report(report_data, report_title)
        
        # Generate Markdown report
        markdown_content = self._generate_markdown_report(report_data, report_title)
        
        # Save reports to files
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        html_filename = f"iot_security_report_{timestamp}.html"
        md_filename = f"iot_security_report_{timestamp}.md"
        
        html_path = os.path.join(self.reports_dir, html_filename)
        md_path = os.path.join(self.reports_dir, md_filename)
        
        with open(html_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        with open(md_path, 'w', encoding='utf-8') as f:
            f.write(markdown_content)
        
        # Create report metadata
        report_info = {
            'id': f"report_{timestamp}",
            'title': report_title,
            'generated_at': datetime.now(),
            'html_file': html_path,
            'markdown_file': md_path,
            'summary': report_data['summary'],
            'total_devices': report_data['total_devices'],
            'total_vulnerabilities': report_data['total_vulnerabilities'],
            'critical_count': report_data['critical_count'],
            'high_count': report_data['high_count'],
            'medium_count': report_data['medium_count'],
            'low_count': report_data['low_count'],
            'scan_ids': [result['id'] for result in scan_results]
        }
        
        return report_info
    
    def _prepare_report_data(self, devices: List[Dict], vulnerabilities: List[Dict], 
                           scan_results: List[Dict]) -> Dict:
        """Prepare and organize data for report generation"""
        
        # Create vulnerability lookup
        vuln_lookup = {vuln['id']: vuln for vuln in vulnerabilities}
        
        # Group scan results by device
        device_vulns = {}
        for result in scan_results:
            device_id = result['device_id']
            vuln_id = result['vulnerability_id']
            
            if device_id not in device_vulns:
                device_vulns[device_id] = []
            
            if vuln_id in vuln_lookup:
                device_vulns[device_id].append(vuln_lookup[vuln_id])
        
        # Add vulnerabilities to devices
        devices_with_vulns = []
        for device in devices:
            device_copy = device.copy()
            device_copy['vulnerabilities'] = device_vulns.get(device['id'], [])
            devices_with_vulns.append(device_copy)
        
        # Calculate statistics
        total_devices = len(devices)
        total_vulnerabilities = len(vulnerabilities)
        
        severity_counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'Unknown')
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        # Generate summary
        summary = self._generate_summary(total_devices, total_vulnerabilities, severity_counts)
        
        return {
            'devices': devices_with_vulns,
            'vulnerabilities': vulnerabilities,
            'scan_results': scan_results,
            'total_devices': total_devices,
            'total_vulnerabilities': total_vulnerabilities,
            'critical_count': severity_counts['Critical'],
            'high_count': severity_counts['High'],
            'medium_count': severity_counts['Medium'],
            'low_count': severity_counts['Low'],
            'summary': summary
        }
    
    def _generate_summary(self, total_devices: int, total_vulns: int, severity_counts: Dict) -> str:
        """Generate a summary of the scan results"""
        
        if total_vulns == 0:
            return f"تم فحص {total_devices} جهاز ولم يتم اكتشاف أي ثغرات أمنية. جميع الأجهزة تبدو آمنة."
        
        critical_high = severity_counts['Critical'] + severity_counts['High']
        
        if critical_high > 0:
            risk_level = "عالي"
            action = "يتطلب اتخاذ إجراءات فورية"
        elif severity_counts['Medium'] > 0:
            risk_level = "متوسط"
            action = "يُنصح بمعالجة الثغرات في أقرب وقت ممكن"
        else:
            risk_level = "منخفض"
            action = "يُنصح بمراقبة الأجهزة ومعالجة الثغرات عند الإمكان"
        
        return (f"تم فحص {total_devices} جهاز واكتشاف {total_vulns} ثغرة أمنية. "
                f"مستوى المخاطر: {risk_level}. {action}.")
    
    def _generate_html_report(self, report_data: Dict, report_title: str) -> str:
        """Generate HTML report using Jinja2 template"""
        
        template = Template(self.html_template)
        
        return template.render(
            report_title=report_title,
            generation_date=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            **report_data
        )
    
    def _generate_markdown_report(self, report_data: Dict, report_title: str) -> str:
        """Generate Markdown report"""
        
        md_content = f"""# {report_title}

**تاريخ الإنشاء:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

## ملخص التقرير

{report_data['summary']}

## الإحصائيات

| المؤشر | العدد |
|---------|-------|
| إجمالي الأجهزة | {report_data['total_devices']} |
| إجمالي الثغرات | {report_data['total_vulnerabilities']} |
| ثغرات حرجة | {report_data['critical_count']} |
| ثغرات عالية | {report_data['high_count']} |
| ثغرات متوسطة | {report_data['medium_count']} |
| ثغرات منخفضة | {report_data['low_count']} |

## تفاصيل الأجهزة والثغرات

"""
        
        for device in report_data['devices']:
            md_content += f"""### الجهاز: {device['ip_address']}

- **نوع الجهاز:** {device.get('device_type', 'غير معروف')}
- **الشركة المصنعة:** {device.get('manufacturer', 'غير معروف')}
- **اسم المضيف:** {device.get('hostname', 'غير متوفر')}
- **نظام التشغيل:** {device.get('os_info', 'غير معروف')}
- **إصدار البرنامج الثابت:** {device.get('firmware_version', 'غير معروف')}

"""
            
            if device['vulnerabilities']:
                md_content += f"#### الثغرات المكتشفة ({len(device['vulnerabilities'])}):\n\n"
                
                for vuln in device['vulnerabilities']:
                    md_content += f"""**{vuln.get('cve_id', 'ثغرة مخصصة')}** - {vuln['severity']}

{vuln['description']}

"""
                    if vuln.get('recommendation'):
                        md_content += f"**التوصية:** {vuln['recommendation']}\n\n"
                    
                    md_content += "---\n\n"
            else:
                md_content += "✅ **لم يتم اكتشاف ثغرات أمنية في هذا الجهاز**\n\n"
        
        md_content += """## التوصيات العامة

1. قم بتحديث البرامج الثابتة لجميع الأجهزة إلى أحدث الإصدارات
2. غيّر كلمات المرور الافتراضية واستخدم كلمات مرور قوية وفريدة
3. فعّل التشفير لجميع الاتصالات (HTTPS, SSL/TLS)
4. أغلق المنافذ والخدمات غير الضرورية
5. راقب حركة الشبكة بانتظام للكشف عن الأنشطة المشبوهة
6. قم بإجراء فحوصات أمنية دورية
7. استخدم شبكة منفصلة لأجهزة IoT (Network Segmentation)
8. فعّل المصادقة الثنائية حيثما أمكن

---

*تم إنشاء هذا التقرير بواسطة أداة فحص أمان أجهزة إنترنت الأشياء*
"""
        
        return md_content
    
    def get_report_list(self) -> List[Dict]:
        """Get list of generated reports"""
        reports = []
        
        try:
            for filename in os.listdir(self.reports_dir):
                if filename.endswith('.html'):
                    file_path = os.path.join(self.reports_dir, filename)
                    stat = os.stat(file_path)
                    
                    reports.append({
                        'filename': filename,
                        'path': file_path,
                        'size': stat.st_size,
                        'created_at': datetime.fromtimestamp(stat.st_ctime),
                        'modified_at': datetime.fromtimestamp(stat.st_mtime)
                    })
        
        except Exception as e:
            print(f"Error getting report list: {e}")
        
        return sorted(reports, key=lambda x: x['created_at'], reverse=True)

