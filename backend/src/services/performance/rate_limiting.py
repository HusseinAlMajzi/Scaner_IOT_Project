"""
API Rate Limiting - Phase 9.6
Implements rate limiting and throttling for API endpoints
"""

import logging
import time
from typing import Dict, Optional
from functools import wraps
from flask import request, jsonify

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class RateLimiter:
    """Token bucket rate limiter"""
    
    def __init__(self, rate: int = 100, per: int = 60):
        """
        Initialize rate limiter
        
        Args:
            rate: Number of requests allowed
            per: Time period in seconds
        """
        self.rate = rate
        self.per = per
        self.allowance = rate
        self.last_check = time.time()
        self.buckets = {}  # Per-user buckets
    
    def _get_bucket(self, identifier: str) -> Dict:
        """Get or create rate limit bucket for identifier"""
        if identifier not in self.buckets:
            self.buckets[identifier] = {
                'allowance': self.rate,
                'last_check': time.time()
            }
        
        return self.buckets[identifier]
    
    def is_allowed(self, identifier: str) -> bool:
        """
        Check if request is allowed
        
        Args:
            identifier: User/IP identifier
            
        Returns:
            True if request is allowed
        """
        bucket = self._get_bucket(identifier)
        
        current = time.time()
        time_passed = current - bucket['last_check']
        bucket['last_check'] = current
        
        # Add tokens based on time passed
        bucket['allowance'] += time_passed * (self.rate / self.per)
        
        if bucket['allowance'] > self.rate:
            bucket['allowance'] = self.rate
        
        # Check if request can be made
        if bucket['allowance'] < 1.0:
            return False
        else:
            bucket['allowance'] -= 1.0
            return True
    
    def get_remaining(self, identifier: str) -> int:
        """Get remaining requests for identifier"""
        bucket = self._get_bucket(identifier)
        return int(bucket['allowance'])
    
    def reset(self, identifier: str) -> None:
        """Reset rate limit for identifier"""
        if identifier in self.buckets:
            self.buckets[identifier]['allowance'] = self.rate
    
    def get_stats(self) -> Dict:
        """Get rate limiter statistics"""
        return {
            'rate_limit': f"{self.rate} per {self.per}s",
            'active_buckets': len(self.buckets),
            'total_requests_tracked': sum(
                self.rate - bucket['allowance'] 
                for bucket in self.buckets.values()
            )
        }


# Global rate limiters for different endpoint types
rate_limiters = {
    'scan': RateLimiter(rate=10, per=60),      # 10 scans per minute
    'api': RateLimiter(rate=100, per=60),      # 100 API calls per minute
    'report': RateLimiter(rate=20, per=60),    # 20 reports per minute
    'upload': RateLimiter(rate=5, per=60),     # 5 uploads per minute
}


def rate_limit(limiter_name: str = 'api'):
    """
    Decorator for rate limiting endpoints
    
    Args:
        limiter_name: Name of rate limiter to use
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            limiter = rate_limiters.get(limiter_name)
            
            if not limiter:
                return func(*args, **kwargs)
            
            # Get identifier (user ID or IP)
            from flask_login import current_user
            
            if current_user.is_authenticated:
                identifier = f"user:{current_user.id}"
            else:
                identifier = f"ip:{request.remote_addr}"
            
            # Check rate limit
            if not limiter.is_allowed(identifier):
                logger.warning(f"Rate limit exceeded for {identifier}")
                
                return jsonify({
                    'success': False,
                    'message': 'معدل الطلبات مرتفع جداً. يرجى المحاولة لاحقاً',
                    'error': 'rate_limit_exceeded',
                    'retry_after': limiter.per
                }), 429
            
            # Execute function
            return func(*args, **kwargs)
        
        return wrapper
    return decorator


class RequestThrottler:
    """Advanced request throttling with burst support"""
    
    def __init__(self, sustained_rate: int = 10, burst_rate: int = 20):
        """
        Initialize throttler
        
        Args:
            sustained_rate: Sustained requests per minute
            burst_rate: Burst requests allowed
        """
        self.sustained_rate = sustained_rate
        self.burst_rate = burst_rate
        self.request_times = {}  # Per-user request timestamps
    
    def is_allowed(self, identifier: str) -> tuple:
        """
        Check if request is allowed
        
        Args:
            identifier: User/IP identifier
            
        Returns:
            (allowed: bool, reason: str)
        """
        current_time = time.time()
        
        if identifier not in self.request_times:
            self.request_times[identifier] = []
        
        # Clean old timestamps (older than 60 seconds)
        self.request_times[identifier] = [
            t for t in self.request_times[identifier]
            if current_time - t < 60
        ]
        
        request_count = len(self.request_times[identifier])
        
        # Check burst limit
        recent_requests = [
            t for t in self.request_times[identifier]
            if current_time - t < 10  # Last 10 seconds
        ]
        
        if len(recent_requests) >= self.burst_rate:
            return False, 'burst_limit_exceeded'
        
        # Check sustained rate
        if request_count >= self.sustained_rate:
            return False, 'sustained_limit_exceeded'
        
        # Allow request
        self.request_times[identifier].append(current_time)
        return True, 'allowed'
    
    def get_stats(self, identifier: str) -> Dict:
        """Get throttling stats for identifier"""
        if identifier not in self.request_times:
            return {
                'requests_in_window': 0,
                'sustained_limit': self.sustained_rate,
                'burst_limit': self.burst_rate
            }
        
        current_time = time.time()
        recent = len([t for t in self.request_times[identifier] if current_time - t < 60])
        
        return {
            'requests_in_window': recent,
            'sustained_limit': self.sustained_rate,
            'burst_limit': self.burst_rate,
            'remaining': max(0, self.sustained_rate - recent)
        }


# Global throttler
request_throttler = RequestThrottler(sustained_rate=50, burst_rate=100)


# Example usage
if __name__ == '__main__':
    print("="*70)
    print("Rate Limiting & Throttling - Phase 9.6")
    print("="*70)
    
    limiter = RateLimiter(rate=10, per=60)
    
    print(f"\nRate Limit: {limiter.rate} requests per {limiter.per} seconds")
    
    # Test rate limiting
    user_id = "test_user_001"
    
    print(f"\nTesting rate limiter for {user_id}...")
    allowed_count = 0
    denied_count = 0
    
    for i in range(15):
        if limiter.is_allowed(user_id):
            allowed_count += 1
        else:
            denied_count += 1
    
    print(f"  Allowed: {allowed_count}")
    print(f"  Denied: {denied_count}")
    print(f"  Remaining: {limiter.get_remaining(user_id)}")
    
    # Test throttler
    print(f"\nTesting request throttler...")
    throttler = RequestThrottler(sustained_rate=10, burst_rate=15)
    
    stats = throttler.get_stats(user_id)
    print(f"  Sustained Rate: {stats['sustained_limit']}/min")
    print(f"  Burst Rate: {stats['burst_limit']}")
    
    print("\n✓ Rate limiting ready for production")
