"""
Distributed Scanning System - Phase 9.2
Enables parallel and distributed scanning for large networks
"""

import asyncio
import logging
from typing import List, Dict
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor
from multiprocessing import cpu_count
import queue
import threading

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class DistributedScanner:
    """Distributed scanning with worker pools"""
    
    def __init__(self, max_workers: int = None):
        """
        Initialize distributed scanner
        
        Args:
            max_workers: Maximum worker threads (default: CPU count * 2)
        """
        self.max_workers = max_workers or (cpu_count() * 2)
        self.thread_pool = ThreadPoolExecutor(max_workers=self.max_workers)
        self.process_pool = ProcessPoolExecutor(max_workers=cpu_count())
        
        self.task_queue = queue.Queue()
        self.results = []
        
        logger.info(f"Distributed scanner initialized with {self.max_workers} workers")
    
    async def scan_network_distributed(self, network_range: str, 
                                       chunk_size: int = 50) -> List[Dict]:
        """
        Scan network using distributed workers
        
        Args:
            network_range: Network range (e.g., "192.168.1.0/24")
            chunk_size: Devices per chunk
            
        Returns:
            Aggregated scan results
        """
        import ipaddress
        
        logger.info(f"Starting distributed scan of {network_range}")
        
        # Generate IP addresses
        try:
            network = ipaddress.IPv4Network(network_range, strict=False)
            all_ips = [str(ip) for ip in network.hosts()]
        except Exception as e:
            logger.error(f"Invalid network range: {e}")
            return []
        
        # Split into chunks
        chunks = [all_ips[i:i+chunk_size] for i in range(0, len(all_ips), chunk_size)]
        
        logger.info(f"Scanning {len(all_ips)} IPs in {len(chunks)} chunks")
        
        # Scan chunks in parallel
        tasks = [self._scan_chunk(chunk, i) for i, chunk in enumerate(chunks)]
        chunk_results = await asyncio.gather(*tasks)
        
        # Aggregate results
        all_devices = []
        for chunk_result in chunk_results:
            all_devices.extend(chunk_result)
        
        logger.info(f"Distributed scan complete. Found {len(all_devices)} devices")
        
        return all_devices
    
    async def _scan_chunk(self, ip_list: List[str], chunk_id: int) -> List[Dict]:
        """Scan a chunk of IPs"""
        logger.debug(f"Chunk {chunk_id}: Scanning {len(ip_list)} IPs")
        
        devices = []
        
        for ip in ip_list:
            # Quick ping check first
            if await self._quick_ping(ip):
                # Detailed scan
                device_info = await self._scan_single_ip(ip)
                if device_info:
                    devices.append(device_info)
        
        logger.debug(f"Chunk {chunk_id}: Found {len(devices)} devices")
        return devices
    
    async def _quick_ping(self, ip: str, timeout: float = 0.5) -> bool:
        """Quick ping check"""
        import subprocess
        
        try:
            result = await asyncio.wait_for(
                asyncio.create_subprocess_exec(
                    'ping', '-c', '1', '-W', str(int(timeout)), ip,
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.DEVNULL
                ),
                timeout=timeout + 0.5
            )
            process = await result.wait()
            return process.returncode == 0
        except:
            return False
    
    async def _scan_single_ip(self, ip: str) -> Optional[Dict]:
        """Scan single IP address"""
        import socket
        
        # Quick port scan
        common_ports = [21, 22, 23, 80, 443, 445, 3389, 8080, 8883, 1883]
        open_ports = []
        
        for port in common_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.3)
                result = sock.connect_ex((ip, port))
                sock.close()
                
                if result == 0:
                    open_ports.append(port)
            except:
                pass
        
        if open_ports:
            return {
                'ip_address': ip,
                'open_ports': open_ports,
                'discovery_method': 'distributed_scan'
            }
        
        return None
    
    def scan_ports_parallel(self, ip: str, ports: List[int]) -> List[int]:
        """
        Scan ports in parallel
        
        Args:
            ip: IP address
            ports: List of ports to scan
            
        Returns:
            List of open ports
        """
        import socket
        
        def check_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((ip, port))
                sock.close()
                return port if result == 0 else None
            except:
                return None
        
        # Scan ports in parallel
        with ThreadPoolExecutor(max_workers=50) as executor:
            results = executor.map(check_port, ports)
        
        open_ports = [p for p in results if p is not None]
        return open_ports
    
    def shutdown(self):
        """Shutdown worker pools"""
        logger.info("Shutting down distributed scanner...")
        self.thread_pool.shutdown(wait=True)
        self.process_pool.shutdown(wait=True)


# Example usage
async def main():
    """Test distributed scanner"""
    print("="*70)
    print("Distributed Scanner - Phase 9.2")
    print("="*70)
    
    scanner = DistributedScanner()
    
    print(f"\nWorkers: {scanner.max_workers}")
    print(f"CPU Cores: {cpu_count()}")
    
    # Test with small network
    print("\nTesting distributed scan on 192.168.1.0/29...")
    devices = await scanner.scan_network_distributed('192.168.1.0/29', chunk_size=4)
    
    print(f"\nDevices Found: {len(devices)}")
    for device in devices:
        print(f"  {device['ip_address']}: {len(device['open_ports'])} ports open")
    
    scanner.shutdown()


if __name__ == '__main__':
    asyncio.run(main())
