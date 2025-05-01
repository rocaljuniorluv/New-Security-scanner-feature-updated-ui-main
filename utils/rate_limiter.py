import time
from typing import Dict, List
from datetime import datetime, timedelta

class RateLimiter:
    def __init__(self, window: int = 60, max_requests: int = 100):
        """
        Initialize rate limiter
        
        Args:
            window: Time window in seconds
            max_requests: Maximum number of requests allowed in the window
        """
        self.window = window
        self.max_requests = max_requests
        self.requests: Dict[str, List[datetime]] = {}
        
    def can_proceed(self, key: str) -> bool:
        """
        Check if a request can proceed
        
        Args:
            key: Identifier for the rate limit (e.g., API endpoint)
            
        Returns:
            bool: True if request can proceed, False otherwise
        """
        now = datetime.now()
        
        # Initialize request list for key if not exists
        if key not in self.requests:
            self.requests[key] = []
            
        # Remove old requests outside the window
        self.requests[key] = [
            req_time for req_time in self.requests[key]
            if now - req_time < timedelta(seconds=self.window)
        ]
        
        # Check if we're within limits
        if len(self.requests[key]) >= self.max_requests:
            return False
            
        # Add current request
        self.requests[key].append(now)
        return True
        
    def wait_if_needed(self, key: str) -> None:
        """
        Wait if necessary to respect rate limits
        
        Args:
            key: Identifier for the rate limit
        """
        while not self.can_proceed(key):
            time.sleep(1)
            
    def get_wait_time(self, key: str) -> float:
        """
        Calculate wait time needed to respect rate limits
        
        Args:
            key: Identifier for the rate limit
            
        Returns:
            float: Wait time in seconds
        """
        if key not in self.requests or not self.requests[key]:
            return 0
            
        now = datetime.now()
        oldest_request = min(self.requests[key])
        wait_time = (oldest_request + timedelta(seconds=self.window) - now).total_seconds()
        
        return max(0, wait_time) 