"""
Advanced Visualization - Phase 8.5
Creates charts, graphs, and visual reports using Plotly
"""

import logging
from typing import Dict, List
import plotly.graph_objects as go
import plotly.express as px
from collections import Counter

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ReportVisualization:
    """Creates visual charts for security reports"""
    
    def __init__(self):
        """Initialize visualization module"""
        self.charts = {}
    
    def create_severity_pie_chart(self, vulnerabilities: List[Dict]) -> str:
        """Create pie chart of vulnerability severities"""
        severities = [v.get('severity', 'Low') for v in vulnerabilities]
        severity_counts = Counter(severities)
        
        fig = go.Figure(data=[go.Pie(
            labels=list(severity_counts.keys()),
            values=list(severity_counts.values()),
            marker=dict(colors=['#dc2626', '#ea580c', '#eab308', '#3b82f6'])
        )])
        
        fig.update_layout(
            title='Vulnerabilities by Severity',
            showlegend=True
        )
        
        return fig.to_html(full_html=False, include_plotlyjs='cdn')
    
    def create_device_type_bar_chart(self, devices: List[Dict]) -> str:
        """Create bar chart of device types"""
        device_types = [d.get('device_type', 'unknown') for d in devices]
        type_counts = Counter(device_types)
        
        fig = go.Figure(data=[go.Bar(
            x=list(type_counts.keys()),
            y=list(type_counts.values()),
            marker_color='#3b82f6'
        )])
        
        fig.update_layout(
            title='Devices by Type',
            xaxis_title='Device Type',
            yaxis_title='Count'
        )
        
        return fig.to_html(full_html=False, include_plotlyjs='cdn')
    
    def create_risk_heatmap(self, devices: List[Dict], 
                           vulnerabilities: List[Dict]) -> str:
        """Create risk heatmap"""
        # Group vulnerabilities by device
        device_risk = {}
        for device in devices:
            device_id = device.get('id')
            device_vulns = [v for v in vulnerabilities if v.get('device_id') == device_id]
            
            # Calculate risk score
            risk_score = sum(
                10 if v.get('severity') == 'Critical' else
                7 if v.get('severity') == 'High' else
                4 if v.get('severity') == 'Medium' else 2
                for v in device_vulns
            )
            
            device_risk[device.get('ip_address', str(device_id))] = risk_score
        
        # Create heatmap data
        ips = list(device_risk.keys())
        scores = list(device_risk.values())
        
        fig = go.Figure(data=go.Heatmap(
            z=[scores],
            x=ips,
            colorscale='Reds'
        ))
        
        fig.update_layout(
            title='Device Risk Heatmap',
            xaxis_title='Device',
            yaxis_title='Risk Score'
        )
        
        return fig.to_html(full_html=False, include_plotlyjs='cdn')
    
    def create_trend_chart(self, scan_history: List[Dict]) -> str:
        """Create vulnerability trend chart over time"""
        dates = [scan.get('timestamp', '')[:10] for scan in scan_history]
        vuln_counts = [len(scan.get('vulnerabilities', [])) for scan in scan_history]
        
        fig = go.Figure(data=go.Scatter(
            x=dates,
            y=vuln_counts,
            mode='lines+markers',
            line=dict(color='#ef4444', width=3),
            marker=dict(size=10)
        ))
        
        fig.update_layout(
            title='Vulnerability Trend Over Time',
            xaxis_title='Date',
            yaxis_title='Vulnerability Count'
        )
        
        return fig.to_html(full_html=False, include_plotlyjs='cdn')
    
    def create_protocol_distribution(self, devices: List[Dict]) -> str:
        """Create protocol distribution chart"""
        protocols = []
        for device in devices:
            device_protocols = device.get('protocols', [])
            protocols.extend(device_protocols)
        
        protocol_counts = Counter(protocols)
        
        fig = go.Figure(data=[go.Bar(
            x=list(protocol_counts.keys()),
            y=list(protocol_counts.values()),
            marker_color='#8b5cf6'
        )])
        
        fig.update_layout(
            title='Protocol Distribution',
            xaxis_title='Protocol',
            yaxis_title='Count'
        )
        
        return fig.to_html(full_html=False, include_plotlyjs='cdn')
    
    def create_complete_dashboard(self, scan_data: Dict) -> Dict[str, str]:
        """Create complete visualization dashboard"""
        charts = {}
        
        devices = scan_data.get('devices', [])
        vulnerabilities = scan_data.get('vulnerabilities', [])
        
        if vulnerabilities:
            charts['severity_pie'] = self.create_severity_pie_chart(vulnerabilities)
        
        if devices:
            charts['device_types'] = self.create_device_type_bar_chart(devices)
        
        if devices and vulnerabilities:
            charts['risk_heatmap'] = self.create_risk_heatmap(devices, vulnerabilities)
        
        if devices:
            charts['protocols'] = self.create_protocol_distribution(devices)
        
        self.charts = charts
        return charts


# Example usage
if __name__ == '__main__':
    print("="*70)
    print("Advanced Visualization - Phase 8.5")
    print("="*70)
    
    viz = ReportVisualization()
    
    # Test data
    test_vulns = [
        {'severity': 'Critical'}, {'severity': 'Critical'},
        {'severity': 'High'}, {'severity': 'High'}, {'severity': 'High'},
        {'severity': 'Medium'}, {'severity': 'Medium'},
        {'severity': 'Low'}
    ]
    
    print("\nGenerating visualizations...")
    html = viz.create_severity_pie_chart(test_vulns)
    print(f"Severity pie chart: {len(html)} bytes")
    
    print("✓ Visualizations ready for reports")
