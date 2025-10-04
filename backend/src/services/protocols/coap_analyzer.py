"""
CoAP Protocol Deep Analysis
Tests CoAP server security and resource discovery
"""

import asyncio
import logging
from typing import Dict, List, Optional
from datetime import datetime

try:
    from aiocoap import Context, Message, Code
    from aiocoap.numbers.codes import Code as CoAPCode
    HAS_COAP = True
except ImportError:
    HAS_COAP = False
    logging.warning("aiocoap not available. CoAP analysis disabled.")

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class CoAPAnalyzer:
    """Deep analysis of CoAP server security"""
    
    # Common CoAP ports
    COAP_PORTS = [5683, 5684]
    
    # Common resource paths to probe
    COMMON_RESOURCES = [
        '/.well-known/core',  # Resource discovery
        '/temperature',
        '/humidity',
        '/light',
        '/sensor',
        '/actuator',
        '/config',
        '/status',
        '/info',
        '/admin',
        '/api',
        '/data'
    ]
    
    def __init__(self, host: str, port: int = 5683):
        """
        Initialize CoAP analyzer
        
        Args:
            host: CoAP server host
            port: CoAP server port
        """
        if not HAS_COAP:
            raise ImportError("aiocoap library required for CoAP analysis")
        
        self.host = host
        self.port = port
        self.vulnerabilities = []
        self.discovered_resources = []
    
    async def discover_resources(self) -> List[Dict]:
        """
        Discover available CoAP resources
        
        Returns:
            List of discovered resources
        """
        resources = []
        
        try:
            context = await Context.create_client_context()
            
            # Query well-known core for resource discovery
            uri = f'coap://{self.host}:{self.port}/.well-known/core'
            request = Message(code=Code.GET, uri=uri)
            
            try:
                response = await asyncio.wait_for(
                    context.request(request).response,
                    timeout=10
                )
                
                if response.code.is_successful():
                    payload = response.payload.decode('utf-8', errors='ignore')
                    
                    # Parse link format
                    for link in payload.split(','):
                        if '<' in link and '>' in link:
                            path = link[link.find('<')+1:link.find('>')]
                            resource_info = {
                                'path': path,
                                'discovered_by': 'well-known-core'
                            }
                            
                            # Extract resource type if available
                            if 'rt=' in link:
                                rt_start = link.find('rt="') + 4
                                rt_end = link.find('"', rt_start)
                                resource_info['type'] = link[rt_start:rt_end]
                            
                            resources.append(resource_info)
                            logger.info(f"Discovered resource: {path}")
                
            except asyncio.TimeoutError:
                logger.warning("Resource discovery timed out")
            except Exception as e:
                logger.error(f"Error during resource discovery: {e}")
            
            await context.shutdown()
            
        except Exception as e:
            logger.error(f"Failed to create CoAP context: {e}")
        
        self.discovered_resources = resources
        return resources
    
    async def probe_common_resources(self) -> List[Dict]:
        """Probe common resource paths"""
        found_resources = []
        
        try:
            context = await Context.create_client_context()
            
            for path in self.COMMON_RESOURCES:
                uri = f'coap://{self.host}:{self.port}{path}'
                request = Message(code=Code.GET, uri=uri)
                
                try:
                    response = await asyncio.wait_for(
                        context.request(request).response,
                        timeout=5
                    )
                    
                    if response.code.is_successful():
                        resource_info = {
                            'path': path,
                            'code': str(response.code),
                            'accessible': True,
                            'payload_size': len(response.payload),
                            'discovered_by': 'probing'
                        }
                        found_resources.append(resource_info)
                        logger.info(f"Accessible resource: {path}")
                
                except asyncio.TimeoutError:
                    pass
                except Exception as e:
                    logger.debug(f"Resource {path} not accessible: {e}")
            
            await context.shutdown()
            
        except Exception as e:
            logger.error(f"Error probing resources: {e}")
        
        return found_resources
    
    async def test_authentication(self) -> Dict:
        """Test if CoAP server requires authentication"""
        result = {
            'test': 'Authentication Check',
            'vulnerable': False,
            'severity': 'High',
            'details': ''
        }
        
        # CoAP typically doesn't have built-in auth (relies on DTLS)
        # Check if resources are accessible without DTLS
        accessible_count = len([r for r in self.discovered_resources if r.get('accessible')])
        
        if accessible_count > 0:
            result['vulnerable'] = True
            result['details'] = f'{accessible_count} resources accessible without authentication'
            result['recommendation'] = 'Enable DTLS for secure CoAP (CoAPS)'
            self.vulnerabilities.append(result)
        else:
            result['details'] = 'No resources accessible without authentication'
        
        return result
    
    async def test_write_operations(self) -> Dict:
        """Test if PUT/POST operations are allowed"""
        result = {
            'test': 'Write Operations',
            'vulnerable': False,
            'severity': 'Critical',
            'details': ''
        }
        
        writable_resources = []
        
        try:
            context = await Context.create_client_context()
            
            for resource in self.discovered_resources[:5]:  # Test first 5 resources
                path = resource.get('path', '')
                uri = f'coap://{self.host}:{self.port}{path}'
                
                # Try PUT
                request = Message(code=Code.PUT, uri=uri, payload=b'test')
                
                try:
                    response = await asyncio.wait_for(
                        context.request(request).response,
                        timeout=5
                    )
                    
                    if response.code.is_successful():
                        writable_resources.append(path)
                        logger.warning(f"Writable resource found: {path}")
                
                except:
                    pass
            
            await context.shutdown()
            
        except Exception as e:
            logger.error(f"Error testing write operations: {e}")
        
        if writable_resources:
            result['vulnerable'] = True
            result['details'] = f'Writable resources found: {", ".join(writable_resources)}'
            result['recommendation'] = 'Restrict write permissions to authorized clients only'
            self.vulnerabilities.append(result)
        else:
            result['details'] = 'No writable resources found'
        
        return result
    
    async def test_observation(self) -> Dict:
        """Test if observe functionality is exposed"""
        result = {
            'test': 'Resource Observation',
            'vulnerable': False,
            'severity': 'Medium',
            'details': ''
        }
        
        try:
            context = await Context.create_client_context()
            
            # Try to observe a resource
            if self.discovered_resources:
                path = self.discovered_resources[0].get('path', '')
                uri = f'coap://{self.host}:{self.port}{path}'
                request = Message(code=Code.GET, uri=uri, observe=0)
                
                try:
                    response = await asyncio.wait_for(
                        context.request(request).response,
                        timeout=5
                    )
                    
                    if response.code.is_successful() and response.opt.observe is not None:
                        result['vulnerable'] = True
                        result['details'] = 'Resource observation enabled without restrictions'
                        result['recommendation'] = 'Restrict observation to authorized clients'
                        self.vulnerabilities.append(result)
                    else:
                        result['details'] = 'Observation appears to be restricted'
                
                except:
                    result['details'] = 'Unable to test observation'
            
            await context.shutdown()
            
        except Exception as e:
            logger.error(f"Error testing observation: {e}")
        
        return result
    
    async def check_dtls(self) -> Dict:
        """Check if DTLS is enabled"""
        result = {
            'test': 'DTLS Encryption',
            'vulnerable': False,
            'severity': 'High',
            'details': ''
        }
        
        if self.port == 5684:
            result['details'] = 'Server running on CoAPS port (5684) - DTLS likely enabled'
        else:
            result['vulnerable'] = True
            result['details'] = 'Server running on unencrypted CoAP port (5683)'
            result['recommendation'] = 'Enable DTLS encryption (CoAPS on port 5684)'
            self.vulnerabilities.append(result)
        
        return result
    
    async def comprehensive_analysis(self) -> Dict:
        """
        Run comprehensive CoAP security analysis
        
        Returns:
            Complete analysis report
        """
        logger.info(f"Starting CoAP analysis for {self.host}:{self.port}")
        
        report = {
            'host': self.host,
            'port': self.port,
            'protocol': 'CoAP',
            'timestamp': datetime.now().isoformat(),
            'tests_performed': [],
            'vulnerabilities': [],
            'discovered_resources': [],
            'security_score': 100
        }
        
        # Discover resources
        resources = await self.discover_resources()
        
        # Probe common resources
        probed = await self.probe_common_resources()
        resources.extend(probed)
        
        report['discovered_resources'] = resources
        self.discovered_resources = resources
        
        if len(resources) > 5:
            report['security_score'] -= 10
        
        # Test authentication
        auth_result = await self.test_authentication()
        report['tests_performed'].append(auth_result)
        if auth_result['vulnerable']:
            report['security_score'] -= 30
        
        # Test write operations
        write_result = await self.test_write_operations()
        report['tests_performed'].append(write_result)
        if write_result['vulnerable']:
            report['security_score'] -= 40
        
        # Test observation
        obs_result = await self.test_observation()
        report['tests_performed'].append(obs_result)
        if obs_result['vulnerable']:
            report['security_score'] -= 15
        
        # Check DTLS
        dtls_result = await self.check_dtls()
        report['tests_performed'].append(dtls_result)
        if dtls_result['vulnerable']:
            report['security_score'] -= 20
        
        # Compile vulnerabilities
        report['vulnerabilities'] = self.vulnerabilities
        report['security_score'] = max(0, report['security_score'])
        
        logger.info(f"CoAP analysis complete. Security score: {report['security_score']}/100")
        
        return report


# Example usage and testing
async def main():
    """Test CoAP analyzer"""
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python coap_analyzer.py <host> [port]")
        print("Example: python coap_analyzer.py 192.168.1.100 5683")
        sys.exit(1)
    
    host = sys.argv[1]
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 5683
    
    print("="*70)
    print(f"CoAP Security Analysis: {host}:{port}")
    print("="*70)
    
    analyzer = CoAPAnalyzer(host, port)
    report = await analyzer.comprehensive_analysis()
    
    print(f"\n{'='*70}")
    print("Analysis Results")
    print(f"{'='*70}")
    
    print(f"\nSecurity Score: {report['security_score']}/100")
    
    print(f"\nDiscovered Resources: {len(report['discovered_resources'])}")
    for resource in report['discovered_resources'][:10]:
        print(f"  - {resource['path']}")
        if resource.get('type'):
            print(f"    Type: {resource['type']}")
    
    print(f"\nVulnerabilities Found: {len(report['vulnerabilities'])}")
    for vuln in report['vulnerabilities']:
        print(f"\n  [{vuln['severity']}] {vuln['test']}")
        print(f"  Details: {vuln['details']}")
        if vuln.get('recommendation'):
            print(f"  Recommendation: {vuln['recommendation']}")


if __name__ == '__main__':
    asyncio.run(main())
