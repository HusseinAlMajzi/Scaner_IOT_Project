"""
Integration APIs - Phase 10.2
APIs for external tool integration (SIEM, ticketing, etc.)
"""

import logging
import requests
import json
from typing import Dict, List, Optional
from datetime import datetime

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class IntegrationManager:
    """Manages external tool integrations"""
    
    def __init__(self):
        """Initialize integration manager"""
        self.integrations = {}
    
    def register_integration(self, integration_name: str, config: Dict) -> bool:
        """
        Register external integration
        
        Args:
            integration_name: Name of integration
            config: Integration configuration
            
        Returns:
            Success status
        """
        self.integrations[integration_name] = {
            'name': integration_name,
            'type': config.get('type'),
            'endpoint': config.get('endpoint'),
            'api_key': config.get('api_key'),
            'enabled': config.get('enabled', True),
            'registered_at': datetime.now().isoformat()
        }
        
        logger.info(f"Registered integration: {integration_name}")
        return True
    
    def send_to_siem(self, event_data: Dict, siem_config: Dict) -> bool:
        """
        Send security event to SIEM system
        
        Args:
            event_data: Event data to send
            siem_config: SIEM configuration
            
        Returns:
            Success status
        """
        try:
            endpoint = siem_config.get('endpoint')
            api_key = siem_config.get('api_key')
            
            # Format event for SIEM
            siem_event = {
                'timestamp': datetime.now().isoformat(),
                'source': 'IoT Security Scanner',
                'event_type': event_data.get('type', 'vulnerability_detected'),
                'severity': event_data.get('severity', 'medium'),
                'device': event_data.get('device'),
                'description': event_data.get('description'),
                'raw_data': event_data
            }
            
            # Send to SIEM
            headers = {
                'Authorization': f'Bearer {api_key}',
                'Content-Type': 'application/json'
            }
            
            response = requests.post(
                endpoint,
                json=siem_event,
                headers=headers,
                timeout=10
            )
            
            if response.status_code in [200, 201, 202]:
                logger.info(f"Event sent to SIEM: {event_data.get('type')}")
                return True
            else:
                logger.error(f"SIEM rejected event: {response.status_code}")
                return False
        
        except Exception as e:
            logger.error(f"SIEM integration error: {e}")
            return False
    
    def create_jira_ticket(self, vulnerability: Dict, jira_config: Dict) -> Optional[str]:
        """
        Create Jira ticket for vulnerability
        
        Args:
            vulnerability: Vulnerability data
            jira_config: Jira configuration
            
        Returns:
            Ticket ID if created
        """
        try:
            endpoint = f"{jira_config['url']}/rest/api/2/issue"
            
            ticket_data = {
                'fields': {
                    'project': {'key': jira_config['project_key']},
                    'summary': f"[IoT Security] {vulnerability.get('description', '')[:100]}",
                    'description': self._format_jira_description(vulnerability),
                    'issuetype': {'name': 'Security'},
                    'priority': {'name': self._map_severity_to_priority(vulnerability.get('severity'))},
                    'labels': ['iot', 'security', 'vulnerability']
                }
            }
            
            headers = {
                'Authorization': f"Bearer {jira_config['api_token']}",
                'Content-Type': 'application/json'
            }
            
            response = requests.post(
                endpoint,
                json=ticket_data,
                headers=headers,
                timeout=10
            )
            
            if response.status_code in [200, 201]:
                ticket_key = response.json().get('key')
                logger.info(f"Created Jira ticket: {ticket_key}")
                return ticket_key
            else:
                logger.error(f"Jira ticket creation failed: {response.status_code}")
                return None
        
        except Exception as e:
            logger.error(f"Jira integration error: {e}")
            return None
    
    def send_slack_alert(self, alert_data: Dict, slack_config: Dict) -> bool:
        """
        Send alert to Slack
        
        Args:
            alert_data: Alert data
            slack_config: Slack webhook configuration
            
        Returns:
            Success status
        """
        try:
            webhook_url = slack_config.get('webhook_url')
            
            # Format Slack message
            severity_emoji = {
                'Critical': '🔴',
                'High': '🟠',
                'Medium': '🟡',
                'Low': '🟢'
            }
            
            emoji = severity_emoji.get(alert_data.get('severity', 'Medium'), '⚪')
            
            message = {
                'text': f"{emoji} IoT Security Alert",
                'blocks': [
                    {
                        'type': 'header',
                        'text': {
                            'type': 'plain_text',
                            'text': f"{emoji} {alert_data.get('title', 'Security Alert')}"
                        }
                    },
                    {
                        'type': 'section',
                        'fields': [
                            {'type': 'mrkdwn', 'text': f"*Severity:* {alert_data.get('severity')}"},
                            {'type': 'mrkdwn', 'text': f"*Device:* {alert_data.get('device')}"},
                            {'type': 'mrkdwn', 'text': f"*Time:* {datetime.now().strftime('%Y-%m-%d %H:%M')}"},
                        ]
                    },
                    {
                        'type': 'section',
                        'text': {
                            'type': 'mrkdwn',
                            'text': alert_data.get('description', '')
                        }
                    }
                ]
            }
            
            response = requests.post(
                webhook_url,
                json=message,
                timeout=10
            )
            
            if response.status_code == 200:
                logger.info("Slack alert sent successfully")
                return True
            else:
                logger.error(f"Slack alert failed: {response.status_code}")
                return False
        
        except Exception as e:
            logger.error(f"Slack integration error: {e}")
            return False
    
    def _format_jira_description(self, vulnerability: Dict) -> str:
        """Format vulnerability for Jira description"""
        desc = f"""
h3. Vulnerability Details

*Description:* {vulnerability.get('description', 'N/A')}
*Severity:* {vulnerability.get('severity', 'Unknown')}
*CVE ID:* {vulnerability.get('cve_id', 'N/A')}
*CVSS Score:* {vulnerability.get('cvss_score', 'N/A')}

h3. Affected Device

*Device ID:* {vulnerability.get('device_id', 'N/A')}
*IP Address:* {vulnerability.get('device_ip', 'N/A')}

h3. Recommendation

{vulnerability.get('recommendation', 'Review and remediate this vulnerability')}

h3. References

{vulnerability.get('references', 'N/A')}
"""
        return desc
    
    def _map_severity_to_priority(self, severity: str) -> str:
        """Map vulnerability severity to Jira priority"""
        mapping = {
            'Critical': 'Highest',
            'High': 'High',
            'Medium': 'Medium',
            'Low': 'Low'
        }
        return mapping.get(severity, 'Medium')
    
    def export_to_csv(self, scan_results: Dict, filepath: str) -> bool:
        """Export scan results to CSV"""
        try:
            import csv
            
            with open(filepath, 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.writer(csvfile)
                
                # Write devices
                writer.writerow(['Devices'])
                writer.writerow(['IP', 'Type', 'Manufacturer', 'Open Ports'])
                
                for device in scan_results.get('devices', []):
                    writer.writerow([
                        device.get('ip_address'),
                        device.get('device_type'),
                        device.get('manufacturer'),
                        len(device.get('open_ports', []))
                    ])
                
                writer.writerow([])
                
                # Write vulnerabilities
                writer.writerow(['Vulnerabilities'])
                writer.writerow(['Device', 'Description', 'Severity', 'CVE'])
                
                for vuln in scan_results.get('vulnerabilities', []):
                    writer.writerow([
                        vuln.get('device_id'),
                        vuln.get('description', '')[:100],
                        vuln.get('severity'),
                        vuln.get('cve_id', 'N/A')
                    ])
            
            logger.info(f"Exported to CSV: {filepath}")
            return True
        
        except Exception as e:
            logger.error(f"CSV export error: {e}")
            return False
    
    def export_to_json(self, scan_results: Dict, filepath: str) -> bool:
        """Export scan results to JSON"""
        try:
            with open(filepath, 'w', encoding='utf-8') as jsonfile:
                json.dump(scan_results, jsonfile, indent=2, ensure_ascii=False)
            
            logger.info(f"Exported to JSON: {filepath}")
            return True
        
        except Exception as e:
            logger.error(f"JSON export error: {e}")
            return False


# Example usage
if __name__ == '__main__':
    print("="*70)
    print("Integration APIs - Phase 10.2")
    print("="*70)
    
    manager = IntegrationManager()
    
    # Register integrations
    print("\nRegistering integrations...")
    
    manager.register_integration('splunk', {
        'type': 'siem',
        'endpoint': 'https://splunk.example.com/api',
        'api_key': 'test_key',
        'enabled': True
    })
    
    manager.register_integration('jira', {
        'type': 'ticketing',
        'url': 'https://jira.example.com',
        'api_token': 'test_token',
        'project_key': 'SEC'
    })
    
    print(f"\nRegistered integrations: {len(manager.integrations)}")
    for name in manager.integrations:
        print(f"  - {name}")
    
    print("\n✓ Integration APIs ready")
