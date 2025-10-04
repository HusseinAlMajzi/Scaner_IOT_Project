"""
Advanced Caching System - Phase 9.1
Implements Redis-based caching for improved performance
"""

import logging
import json
import hashlib
from typing import Any, Optional
from datetime import timedelta
from functools import wraps

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Try to import Redis, fallback to in-memory cache
try:
    import redis
    HAS_REDIS = True
except ImportError:
    HAS_REDIS = False
    logger.warning("Redis not available, using in-memory cache")


class CacheManager:
    """Advanced caching with Redis backend"""
    
    def __init__(self, redis_host: str = 'localhost', redis_port: int = 6379):
        """
        Initialize cache manager
        
        Args:
            redis_host: Redis server host
            redis_port: Redis server port
        """
        self.redis_client = None
        self.memory_cache = {}  # Fallback in-memory cache
        
        if HAS_REDIS:
            try:
                self.redis_client = redis.Redis(
                    host=redis_host,
                    port=redis_port,
                    decode_responses=True,
                    socket_connect_timeout=5
                )
                # Test connection
                self.redis_client.ping()
                logger.info("Redis cache initialized")
            except Exception as e:
                logger.warning(f"Redis connection failed: {e}, using memory cache")
                self.redis_client = None
    
    def _generate_key(self, prefix: str, *args, **kwargs) -> str:
        """Generate cache key from arguments"""
        key_parts = [prefix]
        key_parts.extend(str(arg) for arg in args)
        key_parts.extend(f"{k}:{v}" for k, v in sorted(kwargs.items()))
        
        key_str = ":".join(key_parts)
        
        # Hash long keys
        if len(key_str) > 200:
            key_hash = hashlib.md5(key_str.encode()).hexdigest()
            return f"{prefix}:{key_hash}"
        
        return key_str
    
    def get(self, key: str) -> Optional[Any]:
        """Get value from cache"""
        try:
            if self.redis_client:
                value = self.redis_client.get(key)
                if value:
                    return json.loads(value)
            else:
                return self.memory_cache.get(key)
        except Exception as e:
            logger.error(f"Cache get error: {e}")
        
        return None
    
    def set(self, key: str, value: Any, ttl: int = 3600) -> bool:
        """
        Set value in cache
        
        Args:
            key: Cache key
            value: Value to cache
            ttl: Time to live in seconds
            
        Returns:
            Success status
        """
        try:
            serialized = json.dumps(value)
            
            if self.redis_client:
                self.redis_client.setex(key, ttl, serialized)
            else:
                self.memory_cache[key] = serialized
            
            return True
        except Exception as e:
            logger.error(f"Cache set error: {e}")
            return False
    
    def delete(self, key: str) -> bool:
        """Delete key from cache"""
        try:
            if self.redis_client:
                self.redis_client.delete(key)
            else:
                self.memory_cache.pop(key, None)
            
            return True
        except Exception as e:
            logger.error(f"Cache delete error: {e}")
            return False
    
    def clear_pattern(self, pattern: str) -> int:
        """Clear all keys matching pattern"""
        count = 0
        
        try:
            if self.redis_client:
                keys = self.redis_client.keys(pattern)
                if keys:
                    count = self.redis_client.delete(*keys)
            else:
                # Clear matching keys from memory cache
                keys_to_delete = [k for k in self.memory_cache.keys() if pattern in k]
                for key in keys_to_delete:
                    del self.memory_cache[key]
                count = len(keys_to_delete)
            
            logger.info(f"Cleared {count} cache keys matching '{pattern}'")
        except Exception as e:
            logger.error(f"Cache clear error: {e}")
        
        return count
    
    def get_stats(self) -> Dict:
        """Get cache statistics"""
        stats = {
            'backend': 'redis' if self.redis_client else 'memory',
            'connected': self.redis_client is not None
        }
        
        try:
            if self.redis_client:
                info = self.redis_client.info()
                stats['keys'] = info.get('db0', {}).get('keys', 0)
                stats['memory_used'] = info.get('used_memory_human', 'N/A')
                stats['hits'] = info.get('keyspace_hits', 0)
                stats['misses'] = info.get('keyspace_misses', 0)
            else:
                stats['keys'] = len(self.memory_cache)
        except Exception as e:
            logger.error(f"Error getting cache stats: {e}")
        
        return stats


# Global cache instance
cache_manager = CacheManager()


def cached(ttl: int = 3600, key_prefix: str = 'cache'):
    """
    Decorator for caching function results
    
    Args:
        ttl: Time to live in seconds
        key_prefix: Prefix for cache keys
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Generate cache key
            cache_key = cache_manager._generate_key(key_prefix, func.__name__, *args, **kwargs)
            
            # Try to get from cache
            cached_value = cache_manager.get(cache_key)
            if cached_value is not None:
                logger.debug(f"Cache hit: {cache_key}")
                return cached_value
            
            # Execute function
            result = func(*args, **kwargs)
            
            # Cache result
            cache_manager.set(cache_key, result, ttl)
            logger.debug(f"Cache set: {cache_key}")
            
            return result
        
        return wrapper
    return decorator


# Example usage
if __name__ == '__main__':
    print("="*70)
    print("Cache Manager - Phase 9.1")
    print("="*70)
    
    cache = CacheManager()
    
    print(f"\nCache Backend: {cache.get_stats()['backend']}")
    
    # Test cache operations
    print("\nTesting cache operations...")
    
    cache.set('test:key1', {'data': 'value1'}, ttl=60)
    result = cache.get('test:key1')
    print(f"  Set/Get: {result}")
    
    cache.delete('test:key1')
    result = cache.get('test:key1')
    print(f"  After delete: {result}")
    
    # Test decorator
    @cached(ttl=30, key_prefix='scan')
    def expensive_function(param):
        print("    Executing expensive function...")
        return {'result': param * 2}
    
    print("\nTesting cache decorator...")
    result1 = expensive_function(5)  # Will execute
    result2 = expensive_function(5)  # Will use cache
    
    stats = cache.get_stats()
    print(f"\nCache Statistics: {stats}")
