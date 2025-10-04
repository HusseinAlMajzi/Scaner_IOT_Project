"""
Batch Scanning Operations - Phase 9.5
Efficient batch operations for large-scale scanning
"""

import asyncio
import logging
from typing import List, Dict, Callable
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class BatchScanner:
    """Efficient batch scanning operations"""
    
    def __init__(self, batch_size: int = 50, max_workers: int = 10):
        """
        Initialize batch scanner
        
        Args:
            batch_size: Items per batch
            max_workers: Maximum concurrent workers
        """
        self.batch_size = batch_size
        self.max_workers = max_workers
        self.executor = ThreadPoolExecutor(max_workers=max_workers)
    
    async def batch_scan_devices(self, ip_list: List[str], 
                                scan_func: Callable) -> List[Dict]:
        """
        Scan devices in batches
        
        Args:
            ip_list: List of IP addresses
            scan_func: Function to scan single device
            
        Returns:
            Aggregated scan results
        """
        logger.info(f"Batch scanning {len(ip_list)} devices")
        
        # Split into batches
        batches = [
            ip_list[i:i+self.batch_size] 
            for i in range(0, len(ip_list), self.batch_size)
        ]
        
        logger.info(f"Created {len(batches)} batches")
        
        all_results = []
        
        for batch_num, batch in enumerate(batches, 1):
            logger.info(f"Processing batch {batch_num}/{len(batches)}")
            
            # Scan batch concurrently
            tasks = [scan_func(ip) for ip in batch]
            batch_results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Filter valid results
            for result in batch_results:
                if isinstance(result, dict):
                    all_results.append(result)
                elif isinstance(result, Exception):
                    logger.error(f"Scan error: {result}")
        
        logger.info(f"Batch scan complete: {len(all_results)} devices scanned")
        
        return all_results
    
    async def batch_vulnerability_scan(self, devices: List[Dict], 
                                      vuln_scanner: Callable) -> List[Dict]:
        """
        Scan vulnerabilities in batches
        
        Args:
            devices: List of devices to scan
            vuln_scanner: Vulnerability scanning function
            
        Returns:
            Aggregated vulnerability results
        """
        logger.info(f"Batch vulnerability scanning {len(devices)} devices")
        
        batches = [
            devices[i:i+self.batch_size] 
            for i in range(0, len(devices), self.batch_size)
        ]
        
        all_vulnerabilities = []
        
        for batch_num, batch in enumerate(batches, 1):
            logger.info(f"Scanning vulnerability batch {batch_num}/{len(batches)}")
            
            tasks = [vuln_scanner(device) for device in batch]
            batch_results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for result in batch_results:
                if isinstance(result, list):
                    all_vulnerabilities.extend(result)
                elif isinstance(result, Exception):
                    logger.error(f"Vulnerability scan error: {result}")
        
        logger.info(f"Found {len(all_vulnerabilities)} total vulnerabilities")
        
        return all_vulnerabilities
    
    def batch_database_insert(self, items: List[Dict], 
                             model_class, db_session) -> int:
        """
        Batch insert items into database
        
        Args:
            items: List of items to insert
            model_class: SQLAlchemy model class
            db_session: Database session
            
        Returns:
            Number of items inserted
        """
        logger.info(f"Batch inserting {len(items)} items")
        
        try:
            # Create model instances
            instances = [model_class(**item) for item in items]
            
            # Bulk insert
            db_session.bulk_save_objects(instances)
            db_session.commit()
            
            logger.info(f"Batch insert complete: {len(instances)} items")
            return len(instances)
        
        except Exception as e:
            logger.error(f"Batch insert error: {e}")
            db_session.rollback()
            return 0
    
    def batch_database_update(self, updates: List[Dict], 
                             model_class, db_session, 
                             key_field: str = 'id') -> int:
        """
        Batch update items in database
        
        Args:
            updates: List of update dictionaries
            model_class: SQLAlchemy model class
            db_session: Database session
            key_field: Field to match records
            
        Returns:
            Number of items updated
        """
        logger.info(f"Batch updating {len(updates)} items")
        
        try:
            # Use bulk_update_mappings for efficiency
            db_session.bulk_update_mappings(model_class, updates)
            db_session.commit()
            
            logger.info(f"Batch update complete: {len(updates)} items")
            return len(updates)
        
        except Exception as e:
            logger.error(f"Batch update error: {e}")
            db_session.rollback()
            return 0
    
    def shutdown(self):
        """Shutdown batch scanner"""
        logger.info("Shutting down batch scanner...")
        self.executor.shutdown(wait=True)


class ScanQueue:
    """Queue manager for scan operations"""
    
    def __init__(self):
        """Initialize scan queue"""
        self.queues = {
            'high_priority': asyncio.PriorityQueue(),
            'normal': asyncio.Queue(),
            'low_priority': asyncio.Queue()
        }
        self.workers = []
        self.running = False
    
    async def add_scan(self, scan_task: Dict, priority: str = 'normal') -> None:
        """
        Add scan to queue
        
        Args:
            scan_task: Scan task details
            priority: Priority level (high_priority, normal, low_priority)
        """
        if priority == 'high_priority':
            await self.queues['high_priority'].put((0, scan_task))
        elif priority == 'low_priority':
            await self.queues['low_priority'].put(scan_task)
        else:
            await self.queues['normal'].put(scan_task)
        
        logger.info(f"Added scan to {priority} queue")
    
    async def process_queue(self, num_workers: int = 3):
        """
        Process scan queue with workers
        
        Args:
            num_workers: Number of worker tasks
        """
        self.running = True
        
        # Start workers
        self.workers = [
            asyncio.create_task(self._worker(i))
            for i in range(num_workers)
        ]
        
        logger.info(f"Started {num_workers} queue workers")
    
    async def _worker(self, worker_id: int):
        """Queue worker task"""
        logger.info(f"Worker {worker_id} started")
        
        while self.running:
            scan_task = None
            
            # Check high priority first
            try:
                _, scan_task = await asyncio.wait_for(
                    self.queues['high_priority'].get(),
                    timeout=0.1
                )
            except asyncio.TimeoutError:
                pass
            
            # Then normal priority
            if not scan_task:
                try:
                    scan_task = await asyncio.wait_for(
                        self.queues['normal'].get(),
                        timeout=0.1
                    )
                except asyncio.TimeoutError:
                    pass
            
            # Finally low priority
            if not scan_task:
                try:
                    scan_task = await asyncio.wait_for(
                        self.queues['low_priority'].get(),
                        timeout=0.1
                    )
                except asyncio.TimeoutError:
                    await asyncio.sleep(1)
                    continue
            
            if scan_task:
                # Process scan
                logger.info(f"Worker {worker_id} processing: {scan_task.get('scan_id')}")
                
                try:
                    # Execute scan function
                    scan_func = scan_task.get('function')
                    if scan_func:
                        await scan_func()
                except Exception as e:
                    logger.error(f"Worker {worker_id} error: {e}")
    
    async def stop(self):
        """Stop queue processing"""
        self.running = False
        
        # Cancel workers
        for worker in self.workers:
            worker.cancel()
        
        logger.info("Queue processing stopped")


# Example usage
async def main():
    """Test batch operations"""
    print("="*70)
    print("Batch Operations - Phase 9.5")
    print("="*70)
    
    batch_scanner = BatchScanner(batch_size=10, max_workers=5)
    
    print(f"\nBatch Size: {batch_scanner.batch_size}")
    print(f"Max Workers: {batch_scanner.max_workers}")
    
    # Test progress tracker
    print("\nTesting progress tracker...")
    tracker = ProgressTracker()
    
    scan_id = "batch_test_001"
    tracker.start_scan(scan_id, total_steps=5)
    
    for i in range(1, 6):
        await asyncio.sleep(0.5)
        tracker.update_progress(
            scan_id,
            progress=i * 20,
            step=f"Processing step {i}",
            devices_found=i * 3
        )
    
    tracker.complete_scan(scan_id)
    
    final_status = tracker.get_status(scan_id)
    print(f"\n  Scan completed in {final_status.get('duration_seconds', 0):.1f}s")
    print(f"  Devices found: {final_status.get('devices_found', 0)}")
    
    batch_scanner.shutdown()


if __name__ == '__main__':
    asyncio.run(main())
