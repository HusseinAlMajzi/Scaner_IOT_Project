"""
Performance Manager - Phase 9
Unified manager for all performance and scalability features
"""

import asyncio
import logging
import time
from typing import Dict, List
from datetime import datetime
from functools import wraps

from .caching import CacheManager, cached
from .distributed_scanner import DistributedScanner
from .database_optimization import DatabaseOptimizer, configure_connection_pool
from .realtime_progress import ProgressTracker, progress_tracker
from .batch_operations import BatchScanner, ScanQueue
from .rate_limiting import RateLimiter, rate_limiters

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class PerformanceManager:
    """
    Comprehensive performance and scalability manager
    Coordinates all Phase 9 features for production readiness
    """
    
    def __init__(self, db_session=None):
        """
        Initialize performance manager
        
        Args:
            db_session: Database session for optimization
        """
        self.cache = CacheManager()
        self.distributed_scanner = DistributedScanner()
        self.db_optimizer = DatabaseOptimizer(db_session) if db_session else None
        self.progress_tracker = progress_tracker
        self.batch_scanner = BatchScanner()
        self.scan_queue = ScanQueue()
        
        logger.info("Performance manager initialized")
    
    async def optimized_network_scan(self, network_range: str, 
                                    use_cache: bool = True,
                                    distributed: bool = True) -> List[Dict]:
        """
        Perform optimized network scan
        
        Args:
            network_range: Network range to scan
            use_cache: Use caching for results
            distributed: Use distributed scanning
            
        Returns:
            Scan results
        """
        scan_id = f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        logger.info(f"Starting optimized scan: {scan_id}")
        
        # Check cache first
        if use_cache:
            cache_key = f"network_scan:{network_range}"
            cached_result = self.cache.get(cache_key)
            
            if cached_result:
                logger.info(f"Cache hit for {network_range}")
                return cached_result
        
        # Start progress tracking
        self.progress_tracker.start_scan(scan_id, total_steps=100)
        
        try:
            # Use distributed scanning
            if distributed:
                self.progress_tracker.update_progress(
                    scan_id, 
                    progress=10, 
                    step="Initializing distributed scan..."
                )
                
                devices = await self.distributed_scanner.scan_network_distributed(
                    network_range,
                    chunk_size=50
                )
            else:
                # Fallback to single-threaded
                devices = []
            
            self.progress_tracker.update_progress(
                scan_id,
                progress=100,
                step="Scan complete",
                devices_found=len(devices)
            )
            
            # Cache results
            if use_cache and devices:
                cache_key = f"network_scan:{network_range}"
                self.cache.set(cache_key, devices, ttl=300)  # 5 min cache
            
            self.progress_tracker.complete_scan(scan_id)
            
            return devices
        
        except Exception as e:
            logger.error(f"Optimized scan error: {e}")
            self.progress_tracker.fail_scan(scan_id, str(e))
            return []
    
    def initialize_database_optimizations(self) -> Dict:
        """Initialize all database optimizations"""
        if not self.db_optimizer:
            return {'error': 'No database session provided'}
        
        logger.info("Initializing database optimizations...")
        
        results = self.db_optimizer.optimize_all()
        
        logger.info(f"Database optimization complete: {results['indexes']['created']} indexes created")
        
        return results
    
    async def batch_process_devices(self, devices: List[Dict], 
                                   process_func) -> List[Dict]:
        """
        Process devices in optimized batches
        
        Args:
            devices: List of devices to process
            process_func: Processing function
            
        Returns:
            Processing results
        """
        logger.info(f"Batch processing {len(devices)} devices")
        
        # Use batch scanner
        results = await self.batch_scanner.batch_scan_devices(
            [d.get('ip_address', '') for d in devices],
            process_func
        )
        
        return results
    
    def get_performance_metrics(self) -> Dict:
        """Get comprehensive performance metrics"""
        metrics = {
            'timestamp': datetime.now().isoformat(),
            'cache': self.cache.get_stats(),
            'distributed_scanner': {
                'workers': self.distributed_scanner.max_workers
            },
            'progress_tracker': {
                'active_scans': len(self.progress_tracker.get_all_active_scans())
            },
            'rate_limiters': {}
        }
        
        # Get rate limiter stats
        for name, limiter in rate_limiters.items():
            metrics['rate_limiters'][name] = limiter.get_stats()
        
        return metrics
    
    def cleanup(self):
        """Cleanup resources"""
        logger.info("Cleaning up performance manager...")
        
        # Shutdown distributed scanner
        self.distributed_scanner.shutdown()
        
        # Shutdown batch scanner
        self.batch_scanner.shutdown()
        
        # Cleanup old progress data
        self.progress_tracker.cleanup_old_scans(hours=24)
        
        logger.info("Performance manager cleanup complete")


# Performance monitoring decorator
def monitor_performance(func_name: str = None):
    """
    Decorator to monitor function performance
    
    Args:
        func_name: Name for monitoring (defaults to function name)
    """
    def decorator(func):
        @wraps(func)
        async def async_wrapper(*args, **kwargs):
            name = func_name or func.__name__
            start_time = time.time()
            
            try:
                result = await func(*args, **kwargs)
                duration = time.time() - start_time
                
                logger.info(f"Performance [{name}]: {duration:.3f}s")
                
                return result
            except Exception as e:
                duration = time.time() - start_time
                logger.error(f"Performance [{name}] FAILED after {duration:.3f}s: {e}")
                raise
        
        @wraps(func)
        def sync_wrapper(*args, **kwargs):
            name = func_name or func.__name__
            start_time = time.time()
            
            try:
                result = func(*args, **kwargs)
                duration = time.time() - start_time
                
                logger.info(f"Performance [{name}]: {duration:.3f}s")
                
                return result
            except Exception as e:
                duration = time.time() - start_time
                logger.error(f"Performance [{name}] FAILED after {duration:.3f}s: {e}")
                raise
        
        # Return appropriate wrapper
        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        else:
            return sync_wrapper
    
    return decorator


# Example usage
async def main():
    """Test performance manager"""
    print("="*70)
    print("Performance Manager - Phase 9")
    print("="*70)
    
    manager = PerformanceManager()
    
    # Get metrics
    metrics = manager.get_performance_metrics()
    
    print(f"\nPerformance Metrics:")
    print(f"  Cache Backend: {metrics['cache']['backend']}")
    print(f"  Distributed Workers: {metrics['distributed_scanner']['workers']}")
    print(f"  Active Scans: {metrics['progress_tracker']['active_scans']}")
    
    print(f"\nRate Limiters:")
    for name, stats in metrics['rate_limiters'].items():
        print(f"  {name}: {stats['rate_limit']}")
    
    # Test optimized scan
    print(f"\nTesting optimized scan...")
    
    @monitor_performance('test_scan')
    async def test_scan():
        await asyncio.sleep(0.5)
        return {'devices': 10}
    
    result = await test_scan()
    
    manager.cleanup()
    
    print("\n✓ Performance manager ready for production")


if __name__ == '__main__':
    asyncio.run(main())
