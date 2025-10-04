"""
Modbus Protocol Deep Analysis
Tests Modbus TCP security, register/coil enumeration
"""

import asyncio
import logging
from typing import Dict, List, Optional
from datetime import datetime

try:
    from pymodbus.client import ModbusTcpClient
    from pymodbus.exceptions import ModbusException
    HAS_MODBUS = True
except ImportError:
    HAS_MODBUS = False
    logging.warning("pymodbus not available. Modbus analysis disabled.")

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ModbusAnalyzer:
    """Deep analysis of Modbus TCP security"""
    
    # Default Modbus port
    MODBUS_PORT = 502
    
    # Register/coil ranges to probe
    PROBE_RANGES = {
        'coils': [(0, 100), (1000, 1100), (10000, 10100)],
        'discrete_inputs': [(0, 100), (1000, 1100), (10000, 10100)],
        'holding_registers': [(0, 100), (1000, 1100), (10000, 10100), (40000, 40100)],
        'input_registers': [(0, 100), (1000, 1100), (10000, 10100), (30000, 30100)]
    }
    
    def __init__(self, host: str, port: int = 502):
        """
        Initialize Modbus analyzer
        
        Args:
            host: Modbus server host
            port: Modbus server port
        """
        if not HAS_MODBUS:
            raise ImportError("pymodbus library required for Modbus analysis")
        
        self.host = host
        self.port = port
        self.vulnerabilities = []
        self.discovered_registers = {
            'coils': [],
            'discrete_inputs': [],
            'holding_registers': [],
            'input_registers': []
        }
    
    def test_connection(self) -> Dict:
        """Test basic Modbus connection"""
        result = {
            'test': 'Connection Test',
            'vulnerable': False,
            'severity': 'Info',
            'details': ''
        }
        
        try:
            client = ModbusTcpClient(self.host, port=self.port, timeout=5)
            
            if client.connect():
                result['details'] = 'Successfully connected to Modbus server'
                logger.info(f"Connected to Modbus at {self.host}:{self.port}")
                client.close()
                return result
            else:
                result['details'] = 'Failed to connect to Modbus server'
                return result
                
        except Exception as e:
            result['details'] = f'Connection error: {str(e)}'
            return result
    
    def test_authentication(self) -> Dict:
        """Test if Modbus requires authentication"""
        result = {
            'test': 'Authentication Check',
            'vulnerable': False,
            'severity': 'Critical',
            'details': ''
        }
        
        # Modbus TCP typically has no authentication
        try:
            client = ModbusTcpClient(self.host, port=self.port, timeout=5)
            
            if client.connect():
                # Try to read a register
                response = client.read_holding_registers(0, 1, slave=1)
                
                if not response.isError():
                    result['vulnerable'] = True
                    result['details'] = 'Modbus server allows unauthenticated access'
                    result['recommendation'] = 'Implement firewall rules or use Modbus security extensions'
                    self.vulnerabilities.append(result)
                else:
                    result['details'] = 'Access appears to be restricted'
                
                client.close()
            
        except Exception as e:
            result['details'] = f'Error testing authentication: {str(e)}'
        
        return result
    
    def enumerate_coils(self) -> List[Dict]:
        """Enumerate accessible coils"""
        coils = []
        
        try:
            client = ModbusTcpClient(self.host, port=self.port, timeout=5)
            
            if client.connect():
                for start, end in self.PROBE_RANGES['coils']:
                    try:
                        count = min(end - start, 100)  # Read max 100 at a time
                        response = client.read_coils(start, count, slave=1)
                        
                        if not response.isError():
                            coil_info = {
                                'type': 'coil',
                                'address': start,
                                'count': count,
                                'values': response.bits[:count]
                            }
                            coils.append(coil_info)
                            logger.info(f"Found {count} coils at address {start}")
                    
                    except Exception as e:
                        logger.debug(f"No coils at {start}: {e}")
                
                client.close()
        
        except Exception as e:
            logger.error(f"Error enumerating coils: {e}")
        
        self.discovered_registers['coils'] = coils
        return coils
    
    def enumerate_holding_registers(self) -> List[Dict]:
        """Enumerate accessible holding registers"""
        registers = []
        
        try:
            client = ModbusTcpClient(self.host, port=self.port, timeout=5)
            
            if client.connect():
                for start, end in self.PROBE_RANGES['holding_registers']:
                    try:
                        count = min(end - start, 100)
                        response = client.read_holding_registers(start, count, slave=1)
                        
                        if not response.isError():
                            reg_info = {
                                'type': 'holding_register',
                                'address': start,
                                'count': count,
                                'values': response.registers[:count]
                            }
                            registers.append(reg_info)
                            logger.info(f"Found {count} holding registers at address {start}")
                    
                    except Exception as e:
                        logger.debug(f"No holding registers at {start}: {e}")
                
                client.close()
        
        except Exception as e:
            logger.error(f"Error enumerating holding registers: {e}")
        
        self.discovered_registers['holding_registers'] = registers
        return registers
    
    def enumerate_input_registers(self) -> List[Dict]:
        """Enumerate accessible input registers"""
        registers = []
        
        try:
            client = ModbusTcpClient(self.host, port=self.port, timeout=5)
            
            if client.connect():
                for start, end in self.PROBE_RANGES['input_registers']:
                    try:
                        count = min(end - start, 100)
                        response = client.read_input_registers(start, count, slave=1)
                        
                        if not response.isError():
                            reg_info = {
                                'type': 'input_register',
                                'address': start,
                                'count': count,
                                'values': response.registers[:count]
                            }
                            registers.append(reg_info)
                            logger.info(f"Found {count} input registers at address {start}")
                    
                    except Exception as e:
                        logger.debug(f"No input registers at {start}: {e}")
                
                client.close()
        
        except Exception as e:
            logger.error(f"Error enumerating input registers: {e}")
        
        self.discovered_registers['input_registers'] = registers
        return registers
    
    def test_write_operations(self) -> Dict:
        """Test if write operations are allowed"""
        result = {
            'test': 'Write Operations',
            'vulnerable': False,
            'severity': 'Critical',
            'details': ''
        }
        
        writable_addresses = []
        
        try:
            client = ModbusTcpClient(self.host, port=self.port, timeout=5)
            
            if client.connect():
                # Try to write to holding registers
                for start, _ in self.PROBE_RANGES['holding_registers'][:2]:
                    try:
                        # Read current value first
                        read_response = client.read_holding_registers(start, 1, slave=1)
                        
                        if not read_response.isError():
                            original_value = read_response.registers[0]
                            
                            # Try to write the same value back
                            write_response = client.write_register(start, original_value, slave=1)
                            
                            if not write_response.isError():
                                writable_addresses.append(start)
                                logger.warning(f"Writable register found at address {start}")
                    
                    except Exception as e:
                        logger.debug(f"Register {start} not writable: {e}")
                
                client.close()
        
        except Exception as e:
            logger.error(f"Error testing write operations: {e}")
        
        if writable_addresses:
            result['vulnerable'] = True
            result['details'] = f'Writable registers found: {writable_addresses}'
            result['recommendation'] = 'Restrict write permissions to authorized devices only'
            self.vulnerabilities.append(result)
        else:
            result['details'] = 'No writable registers found or write operations blocked'
        
        return result
    
    def test_unit_id_enumeration(self) -> Dict:
        """Test for multiple Modbus slave IDs"""
        result = {
            'test': 'Unit ID Enumeration',
            'vulnerable': False,
            'severity': 'Medium',
            'details': ''
        }
        
        active_units = []
        
        try:
            client = ModbusTcpClient(self.host, port=self.port, timeout=3)
            
            if client.connect():
                # Test common slave IDs
                for slave_id in range(1, 11):
                    try:
                        response = client.read_holding_registers(0, 1, slave=slave_id)
                        
                        if not response.isError():
                            active_units.append(slave_id)
                            logger.info(f"Active Modbus unit ID: {slave_id}")
                    
                    except:
                        pass
                
                client.close()
        
        except Exception as e:
            logger.error(f"Error enumerating unit IDs: {e}")
        
        if len(active_units) > 1:
            result['vulnerable'] = True
            result['details'] = f'Multiple active unit IDs found: {active_units}'
            result['recommendation'] = 'Ensure only necessary unit IDs are exposed'
            self.vulnerabilities.append(result)
        elif len(active_units) == 1:
            result['details'] = f'Single unit ID active: {active_units[0]}'
        else:
            result['details'] = 'No active unit IDs found'
        
        return result
    
    async def comprehensive_analysis(self) -> Dict:
        """
        Run comprehensive Modbus security analysis
        
        Returns:
            Complete analysis report
        """
        logger.info(f"Starting Modbus analysis for {self.host}:{self.port}")
        
        report = {
            'host': self.host,
            'port': self.port,
            'protocol': 'Modbus TCP',
            'timestamp': datetime.now().isoformat(),
            'tests_performed': [],
            'vulnerabilities': [],
            'discovered_registers': {},
            'security_score': 100
        }
        
        # Test connection
        conn_result = self.test_connection()
        report['tests_performed'].append(conn_result)
        
        if 'Failed' in conn_result['details']:
            report['security_score'] = 0
            report['note'] = 'Unable to connect to Modbus server'
            return report
        
        # Test authentication
        auth_result = self.test_authentication()
        report['tests_performed'].append(auth_result)
        if auth_result['vulnerable']:
            report['security_score'] -= 40
        
        # Enumerate coils
        coils = self.enumerate_coils()
        if coils:
            report['security_score'] -= 10
        
        # Enumerate holding registers
        holding = self.enumerate_holding_registers()
        if holding:
            report['security_score'] -= 15
        
        # Enumerate input registers
        input_regs = self.enumerate_input_registers()
        if input_regs:
            report['security_score'] -= 10
        
        report['discovered_registers'] = self.discovered_registers
        
        # Test write operations
        write_result = self.test_write_operations()
        report['tests_performed'].append(write_result)
        if write_result['vulnerable']:
            report['security_score'] -= 35
        
        # Test unit ID enumeration
        unit_result = self.test_unit_id_enumeration()
        report['tests_performed'].append(unit_result)
        if unit_result['vulnerable']:
            report['security_score'] -= 10
        
        # Compile vulnerabilities
        report['vulnerabilities'] = self.vulnerabilities
        report['security_score'] = max(0, report['security_score'])
        
        logger.info(f"Modbus analysis complete. Security score: {report['security_score']}/100")
        
        return report


# Example usage and testing
async def main():
    """Test Modbus analyzer"""
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python modbus_analyzer.py <host> [port]")
        print("Example: python modbus_analyzer.py 192.168.1.100 502")
        sys.exit(1)
    
    host = sys.argv[1]
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 502
    
    print("="*70)
    print(f"Modbus Security Analysis: {host}:{port}")
    print("="*70)
    
    analyzer = ModbusAnalyzer(host, port)
    report = await analyzer.comprehensive_analysis()
    
    print(f"\n{'='*70}")
    print("Analysis Results")
    print(f"{'='*70}")
    
    print(f"\nSecurity Score: {report['security_score']}/100")
    
    print(f"\nDiscovered Registers:")
    for reg_type, registers in report['discovered_registers'].items():
        if registers:
            print(f"  {reg_type}: {len(registers)} ranges found")
            for reg in registers[:3]:
                print(f"    - Address {reg['address']}: {reg['count']} registers")
    
    print(f"\nVulnerabilities Found: {len(report['vulnerabilities'])}")
    for vuln in report['vulnerabilities']:
        print(f"\n  [{vuln['severity']}] {vuln['test']}")
        print(f"  Details: {vuln['details']}")
        if vuln.get('recommendation'):
            print(f"  Recommendation: {vuln['recommendation']}")


if __name__ == '__main__':
    asyncio.run(main())
