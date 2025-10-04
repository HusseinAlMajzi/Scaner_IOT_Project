"""
MQTT Protocol Deep Analysis
Tests MQTT broker security, authentication, and exposure
"""

import asyncio
import logging
from typing import Dict, List, Optional
from datetime import datetime
import socket

try:
    import paho.mqtt.client as mqtt
    HAS_MQTT = True
except ImportError:
    HAS_MQTT = False
    logging.warning("paho-mqtt not available. MQTT analysis disabled.")

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class MQTTAnalyzer:
    """Deep analysis of MQTT broker security"""
    
    # Common MQTT ports
    MQTT_PORTS = [1883, 8883, 1884, 8884]
    
    # Common default credentials
    DEFAULT_CREDENTIALS = [
        ('admin', 'admin'),
        ('mqtt', 'mqtt'),
        ('user', 'user'),
        ('test', 'test'),
        ('guest', 'guest'),
        ('', ''),  # Anonymous
    ]
    
    # Sensitive topics to check
    SENSITIVE_TOPICS = [
        '#',  # All topics
        '$SYS/#',  # System topics
        'device/#',
        'sensor/#',
        'home/#',
        'iot/#',
        'control/#',
        'config/#',
        'admin/#'
    ]
    
    def __init__(self, host: str, port: int = 1883, timeout: int = 10):
        """
        Initialize MQTT analyzer
        
        Args:
            host: MQTT broker host
            port: MQTT broker port
            timeout: Connection timeout
        """
        if not HAS_MQTT:
            raise ImportError("paho-mqtt library required for MQTT analysis")
        
        self.host = host
        self.port = port
        self.timeout = timeout
        self.vulnerabilities = []
        self.discovered_topics = []
        self.broker_info = {}
    
    def _on_connect(self, client, userdata, flags, rc):
        """MQTT connection callback"""
        userdata['connected'] = True
        userdata['connect_result'] = rc
        
        if rc == 0:
            logger.info(f"Connected to MQTT broker at {self.host}:{self.port}")
        else:
            logger.warning(f"Connection failed with code {rc}")
    
    def _on_message(self, client, userdata, message):
        """MQTT message callback"""
        topic = message.topic
        payload = message.payload.decode('utf-8', errors='ignore')
        
        if topic not in userdata['topics']:
            userdata['topics'].append(topic)
            logger.debug(f"Discovered topic: {topic}")
    
    def test_anonymous_access(self) -> Dict:
        """Test if broker allows anonymous access"""
        result = {
            'test': 'Anonymous Access',
            'vulnerable': False,
            'severity': 'Critical',
            'details': ''
        }
        
        try:
            client = mqtt.Client(client_id="iot_scanner_anon")
            userdata = {'connected': False, 'connect_result': None, 'topics': []}
            client.user_data_set(userdata)
            client.on_connect = self._on_connect
            
            client.connect(self.host, self.port, self.timeout)
            client.loop_start()
            
            # Wait for connection
            for _ in range(self.timeout * 10):
                if userdata['connected']:
                    break
                asyncio.sleep(0.1)
            
            client.loop_stop()
            client.disconnect()
            
            if userdata['connect_result'] == 0:
                result['vulnerable'] = True
                result['details'] = 'Broker allows anonymous connections without authentication'
                self.vulnerabilities.append(result)
            else:
                result['details'] = 'Broker requires authentication'
            
        except Exception as e:
            result['details'] = f'Error testing anonymous access: {str(e)}'
            logger.error(result['details'])
        
        return result
    
    def test_default_credentials(self) -> List[Dict]:
        """Test common default credentials"""
        results = []
        
        for username, password in self.DEFAULT_CREDENTIALS:
            result = {
                'test': f'Default Credentials: {username or "anonymous"}',
                'vulnerable': False,
                'severity': 'High',
                'details': ''
            }
            
            try:
                client = mqtt.Client(client_id=f"iot_scanner_{username}")
                userdata = {'connected': False, 'connect_result': None}
                client.user_data_set(userdata)
                client.on_connect = self._on_connect
                
                if username or password:
                    client.username_pw_set(username, password)
                
                client.connect(self.host, self.port, self.timeout)
                client.loop_start()
                
                # Wait for connection
                for _ in range(self.timeout * 10):
                    if userdata['connected']:
                        break
                    asyncio.sleep(0.1)
                
                client.loop_stop()
                client.disconnect()
                
                if userdata['connect_result'] == 0:
                    result['vulnerable'] = True
                    result['details'] = f'Successfully connected with credentials: {username}:{password}'
                    self.vulnerabilities.append(result)
                    results.append(result)
                    logger.warning(f"Default credentials working: {username}:{password}")
                
            except Exception as e:
                logger.debug(f"Credentials {username}:{password} failed: {e}")
        
        return results
    
    def discover_topics(self, username: str = None, password: str = None) -> List[str]:
        """
        Discover published topics
        
        Args:
            username: Username for authentication
            password: Password for authentication
            
        Returns:
            List of discovered topics
        """
        discovered = []
        
        try:
            client = mqtt.Client(client_id="iot_scanner_discover")
            userdata = {'connected': False, 'topics': []}
            client.user_data_set(userdata)
            client.on_connect = self._on_connect
            client.on_message = self._on_message
            
            if username or password:
                client.username_pw_set(username, password)
            
            client.connect(self.host, self.port, self.timeout)
            client.loop_start()
            
            # Wait for connection
            for _ in range(self.timeout * 10):
                if userdata['connected']:
                    break
                asyncio.sleep(0.1)
            
            if userdata['connected']:
                # Subscribe to common topics
                for topic in self.SENSITIVE_TOPICS:
                    try:
                        client.subscribe(topic)
                        logger.debug(f"Subscribed to: {topic}")
                    except:
                        pass
                
                # Wait for messages
                asyncio.sleep(5)
                
                discovered = userdata['topics']
                self.discovered_topics = discovered
            
            client.loop_stop()
            client.disconnect()
            
        except Exception as e:
            logger.error(f"Error discovering topics: {e}")
        
        return discovered
    
    def test_topic_authorization(self) -> Dict:
        """Test if topics are properly protected"""
        result = {
            'test': 'Topic Authorization',
            'vulnerable': False,
            'severity': 'High',
            'details': ''
        }
        
        # Try to access sensitive topics without credentials
        topics = self.discover_topics()
        
        if topics:
            result['vulnerable'] = True
            result['details'] = f'Discovered {len(topics)} topics without proper authorization'
            self.vulnerabilities.append(result)
        else:
            result['details'] = 'Topics appear to be properly protected'
        
        return result
    
    def get_broker_info(self) -> Dict:
        """Get broker information from $SYS topics"""
        info = {}
        
        try:
            client = mqtt.Client(client_id="iot_scanner_info")
            userdata = {'connected': False, 'sys_info': {}}
            
            def on_sys_message(client, userdata, message):
                topic = message.topic
                payload = message.payload.decode('utf-8', errors='ignore')
                userdata['sys_info'][topic] = payload
            
            client.user_data_set(userdata)
            client.on_connect = self._on_connect
            client.on_message = on_sys_message
            
            client.connect(self.host, self.port, self.timeout)
            client.loop_start()
            
            # Wait for connection
            for _ in range(self.timeout * 10):
                if userdata['connected']:
                    break
                asyncio.sleep(0.1)
            
            if userdata['connected']:
                client.subscribe('$SYS/#')
                asyncio.sleep(3)
                info = userdata['sys_info']
            
            client.loop_stop()
            client.disconnect()
            
        except Exception as e:
            logger.error(f"Error getting broker info: {e}")
        
        self.broker_info = info
        return info
    
    def check_ssl_tls(self) -> Dict:
        """Check if SSL/TLS is enabled"""
        result = {
            'test': 'SSL/TLS Encryption',
            'vulnerable': False,
            'severity': 'High',
            'details': ''
        }
        
        # Check if running on SSL port
        if self.port in [8883, 8884]:
            result['details'] = f'Broker running on SSL port {self.port}'
        else:
            result['vulnerable'] = True
            result['details'] = f'Broker running on unencrypted port {self.port}'
            result['recommendation'] = 'Enable SSL/TLS encryption'
            self.vulnerabilities.append(result)
        
        return result
    
    async def comprehensive_analysis(self) -> Dict:
        """
        Run comprehensive MQTT security analysis
        
        Returns:
            Complete analysis report
        """
        logger.info(f"Starting MQTT analysis for {self.host}:{self.port}")
        
        report = {
            'host': self.host,
            'port': self.port,
            'protocol': 'MQTT',
            'timestamp': datetime.now().isoformat(),
            'tests_performed': [],
            'vulnerabilities': [],
            'broker_info': {},
            'discovered_topics': [],
            'security_score': 100
        }
        
        # Test anonymous access
        anon_result = self.test_anonymous_access()
        report['tests_performed'].append(anon_result)
        if anon_result['vulnerable']:
            report['security_score'] -= 40
        
        # Test default credentials
        cred_results = self.test_default_credentials()
        report['tests_performed'].extend(cred_results)
        if cred_results:
            report['security_score'] -= 30
        
        # Test SSL/TLS
        ssl_result = self.check_ssl_tls()
        report['tests_performed'].append(ssl_result)
        if ssl_result['vulnerable']:
            report['security_score'] -= 20
        
        # Discover topics (if we have access)
        topics = self.discover_topics()
        report['discovered_topics'] = topics
        if len(topics) > 10:
            report['security_score'] -= 10
        
        # Test topic authorization
        auth_result = self.test_topic_authorization()
        report['tests_performed'].append(auth_result)
        
        # Get broker info
        broker_info = self.get_broker_info()
        report['broker_info'] = broker_info
        
        # Compile vulnerabilities
        report['vulnerabilities'] = self.vulnerabilities
        report['security_score'] = max(0, report['security_score'])
        
        logger.info(f"MQTT analysis complete. Security score: {report['security_score']}/100")
        
        return report


# Example usage and testing
async def main():
    """Test MQTT analyzer"""
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python mqtt_analyzer.py <host> [port]")
        print("Example: python mqtt_analyzer.py 192.168.1.100 1883")
        sys.exit(1)
    
    host = sys.argv[1]
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 1883
    
    print("="*70)
    print(f"MQTT Security Analysis: {host}:{port}")
    print("="*70)
    
    analyzer = MQTTAnalyzer(host, port)
    report = await analyzer.comprehensive_analysis()
    
    print(f"\n{'='*70}")
    print("Analysis Results")
    print(f"{'='*70}")
    
    print(f"\nSecurity Score: {report['security_score']}/100")
    
    print(f"\nVulnerabilities Found: {len(report['vulnerabilities'])}")
    for vuln in report['vulnerabilities']:
        print(f"\n  [{vuln['severity']}] {vuln['test']}")
        print(f"  Details: {vuln['details']}")
        if vuln.get('recommendation'):
            print(f"  Recommendation: {vuln['recommendation']}")
    
    if report['discovered_topics']:
        print(f"\nDiscovered Topics ({len(report['discovered_topics'])}):")
        for topic in report['discovered_topics'][:10]:
            print(f"  - {topic}")
        if len(report['discovered_topics']) > 10:
            print(f"  ... and {len(report['discovered_topics']) - 10} more")
    
    if report['broker_info']:
        print(f"\nBroker Information:")
        for key, value in list(report['broker_info'].items())[:5]:
            print(f"  {key}: {value}")


if __name__ == '__main__':
    asyncio.run(main())
