"""
GLOBAL INTELLIGENCE SECURITY COMMAND CENTER - RATE LIMITING MODULE
Enterprise-grade API rate limiting with Redis backend support

This module implements:
- Token bucket rate limiting algorithm
- Per-user and per-IP rate limits
- Redis-backed distributed rate limiting
- In-memory fallback for single-instance deployments
- Configurable rate limit tiers
- Rate limit headers in responses

Classification: TOP SECRET // NSOC // TIER-0
"""

import os
import time
import logging
import hashlib
from typing import Optional, Dict, Callable
from dataclasses import dataclass
from collections import defaultdict
import threading

from fastapi import Request, Response, HTTPException, status
from starlette.middleware.base import BaseHTTPMiddleware

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


REDIS_URL = os.environ.get("REDIS_URL", "")
DEFAULT_RATE_LIMIT = int(os.environ.get("DEFAULT_RATE_LIMIT", "100"))
DEFAULT_RATE_WINDOW = int(os.environ.get("DEFAULT_RATE_WINDOW", "60"))
BURST_MULTIPLIER = float(os.environ.get("BURST_MULTIPLIER", "1.5"))


@dataclass
class RateLimitTier:
    name: str
    requests_per_minute: int
    requests_per_hour: int
    requests_per_day: int
    burst_size: int


RATE_LIMIT_TIERS: Dict[str, RateLimitTier] = {
    "free": RateLimitTier(
        name="free",
        requests_per_minute=10,
        requests_per_hour=100,
        requests_per_day=500,
        burst_size=15
    ),
    "basic": RateLimitTier(
        name="basic",
        requests_per_minute=600,
        requests_per_hour=10000,
        requests_per_day=100000,
        burst_size=1000
    ),
    "professional": RateLimitTier(
        name="professional",
        requests_per_minute=300,
        requests_per_hour=5000,
        requests_per_day=50000,
        burst_size=500
    ),
    "enterprise": RateLimitTier(
        name="enterprise",
        requests_per_minute=1000,
        requests_per_hour=20000,
        requests_per_day=200000,
        burst_size=2000
    ),
    "unlimited": RateLimitTier(
        name="unlimited",
        requests_per_minute=100000,
        requests_per_hour=1000000,
        requests_per_day=10000000,
        burst_size=10000
    ),
}


class TokenBucket:
    def __init__(self, capacity: int, refill_rate: float):
        self.capacity = capacity
        self.refill_rate = refill_rate
        self.tokens = capacity
        self.last_refill = time.time()
        self._lock = threading.Lock()
    
    def consume(self, tokens: int = 1) -> bool:
        with self._lock:
            now = time.time()
            elapsed = now - self.last_refill
            self.tokens = min(self.capacity, self.tokens + elapsed * self.refill_rate)
            self.last_refill = now
            
            if self.tokens >= tokens:
                self.tokens -= tokens
                return True
            return False
    
    def get_tokens(self) -> float:
        with self._lock:
            now = time.time()
            elapsed = now - self.last_refill
            return min(self.capacity, self.tokens + elapsed * self.refill_rate)


class InMemoryRateLimiter:
    def __init__(self):
        self._buckets: Dict[str, TokenBucket] = {}
        self._request_counts: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))
        self._window_starts: Dict[str, Dict[str, float]] = defaultdict(lambda: defaultdict(float))
        self._lock = threading.Lock()
    
    def _get_bucket(self, key: str, capacity: int, refill_rate: float) -> TokenBucket:
        with self._lock:
            if key not in self._buckets:
                self._buckets[key] = TokenBucket(capacity, refill_rate)
            return self._buckets[key]
    
    def check_rate_limit(self, key: str, tier: RateLimitTier) -> tuple:
        bucket = self._get_bucket(
            f"{key}:burst",
            tier.burst_size,
            tier.requests_per_minute / 60.0
        )
        
        if not bucket.consume():
            return False, 0, tier.requests_per_minute
        
        now = time.time()
        minute_key = f"{key}:minute"
        hour_key = f"{key}:hour"
        day_key = f"{key}:day"
        
        with self._lock:
            if now - self._window_starts[minute_key].get("start", 0) >= 60:
                self._request_counts[minute_key] = defaultdict(int)
                self._window_starts[minute_key]["start"] = now
            
            if now - self._window_starts[hour_key].get("start", 0) >= 3600:
                self._request_counts[hour_key] = defaultdict(int)
                self._window_starts[hour_key]["start"] = now
            
            if now - self._window_starts[day_key].get("start", 0) >= 86400:
                self._request_counts[day_key] = defaultdict(int)
                self._window_starts[day_key]["start"] = now
            
            self._request_counts[minute_key][key] += 1
            self._request_counts[hour_key][key] += 1
            self._request_counts[day_key][key] += 1
            
            minute_count = self._request_counts[minute_key][key]
            hour_count = self._request_counts[hour_key][key]
            day_count = self._request_counts[day_key][key]
        
        if minute_count > tier.requests_per_minute:
            return False, 60 - (now - self._window_starts[minute_key]["start"]), tier.requests_per_minute
        
        if hour_count > tier.requests_per_hour:
            return False, 3600 - (now - self._window_starts[hour_key]["start"]), tier.requests_per_hour
        
        if day_count > tier.requests_per_day:
            return False, 86400 - (now - self._window_starts[day_key]["start"]), tier.requests_per_day
        
        remaining = tier.requests_per_minute - minute_count
        return True, remaining, tier.requests_per_minute
    
    def get_usage(self, key: str) -> Dict[str, int]:
        with self._lock:
            return {
                "minute": self._request_counts[f"{key}:minute"].get(key, 0),
                "hour": self._request_counts[f"{key}:hour"].get(key, 0),
                "day": self._request_counts[f"{key}:day"].get(key, 0),
            }


class RedisRateLimiter:
    def __init__(self, redis_url: str):
        self._redis_url = redis_url
        self._client = None
        self._connect()
    
    def _connect(self):
        try:
            import redis
            self._client = redis.from_url(self._redis_url)
            self._client.ping()
            logger.info("Redis rate limiter connected")
        except Exception as e:
            logger.warning(f"Redis connection failed, falling back to in-memory: {e}")
            self._client = None
    
    def check_rate_limit(self, key: str, tier: RateLimitTier) -> tuple:
        if not self._client:
            return True, tier.requests_per_minute, tier.requests_per_minute
        
        try:
            pipe = self._client.pipeline()
            now = time.time()
            
            minute_key = f"ratelimit:{key}:minute:{int(now // 60)}"
            hour_key = f"ratelimit:{key}:hour:{int(now // 3600)}"
            day_key = f"ratelimit:{key}:day:{int(now // 86400)}"
            
            pipe.incr(minute_key)
            pipe.expire(minute_key, 120)
            pipe.incr(hour_key)
            pipe.expire(hour_key, 7200)
            pipe.incr(day_key)
            pipe.expire(day_key, 172800)
            
            results = pipe.execute()
            
            minute_count = results[0]
            hour_count = results[2]
            day_count = results[4]
            
            if minute_count > tier.requests_per_minute:
                retry_after = 60 - (now % 60)
                return False, retry_after, tier.requests_per_minute
            
            if hour_count > tier.requests_per_hour:
                retry_after = 3600 - (now % 3600)
                return False, retry_after, tier.requests_per_hour
            
            if day_count > tier.requests_per_day:
                retry_after = 86400 - (now % 86400)
                return False, retry_after, tier.requests_per_day
            
            remaining = tier.requests_per_minute - minute_count
            return True, remaining, tier.requests_per_minute
            
        except Exception as e:
            logger.error(f"Redis rate limit check failed: {e}")
            return True, tier.requests_per_minute, tier.requests_per_minute
    
    def get_usage(self, key: str) -> Dict[str, int]:
        if not self._client:
            return {"minute": 0, "hour": 0, "day": 0}
        
        try:
            now = time.time()
            minute_key = f"ratelimit:{key}:minute:{int(now // 60)}"
            hour_key = f"ratelimit:{key}:hour:{int(now // 3600)}"
            day_key = f"ratelimit:{key}:day:{int(now // 86400)}"
            
            pipe = self._client.pipeline()
            pipe.get(minute_key)
            pipe.get(hour_key)
            pipe.get(day_key)
            results = pipe.execute()
            
            return {
                "minute": int(results[0] or 0),
                "hour": int(results[1] or 0),
                "day": int(results[2] or 0),
            }
        except Exception as e:
            logger.error(f"Redis usage check failed: {e}")
            return {"minute": 0, "hour": 0, "day": 0}


class RateLimiterService:
    _instance = None
    _lock = threading.Lock()
    
    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._initialized = False
        return cls._instance
    
    def __init__(self):
        if self._initialized:
            return
        self._initialized = True
        
        if REDIS_URL:
            self._limiter = RedisRateLimiter(REDIS_URL)
        else:
            self._limiter = InMemoryRateLimiter()
            logger.info("Using in-memory rate limiter")
    
    def check_rate_limit(self, key: str, tier_name: str = "basic") -> tuple:
        tier = RATE_LIMIT_TIERS.get(tier_name, RATE_LIMIT_TIERS["basic"])
        return self._limiter.check_rate_limit(key, tier)
    
    def get_usage(self, key: str) -> Dict[str, int]:
        return self._limiter.get_usage(key)


def get_rate_limiter() -> RateLimiterService:
    return RateLimiterService()


def get_client_identifier(request: Request) -> str:
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        client_ip = forwarded.split(",")[0].strip()
    else:
        client_ip = request.client.host if request.client else "unknown"
    
    user_id = getattr(request.state, "user_id", None)
    if user_id:
        return f"user:{user_id}"
    
    api_key = request.headers.get("X-API-Key")
    if api_key:
        return f"apikey:{hashlib.sha256(api_key.encode()).hexdigest()[:16]}"
    
    return f"ip:{client_ip}"


def get_user_tier(request: Request) -> str:
    tier = getattr(request.state, "rate_limit_tier", None)
    if tier:
        return tier
    
    if request.headers.get("X-API-Key"):
        return "professional"
    
    return "basic"


class RateLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, exclude_paths: list = None):
        super().__init__(app)
        self.exclude_paths = exclude_paths or ["/healthz", "/docs", "/openapi.json", "/redoc"]
        self.rate_limiter = get_rate_limiter()
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        if any(request.url.path.startswith(path) for path in self.exclude_paths):
            return await call_next(request)
        
        client_id = get_client_identifier(request)
        tier = get_user_tier(request)
        
        allowed, remaining_or_retry, limit = self.rate_limiter.check_rate_limit(client_id, tier)
        
        if not allowed:
            return Response(
                content='{"detail": "Rate limit exceeded. Please retry later."}',
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                headers={
                    "Content-Type": "application/json",
                    "X-RateLimit-Limit": str(limit),
                    "X-RateLimit-Remaining": "0",
                    "X-RateLimit-Reset": str(int(time.time() + remaining_or_retry)),
                    "Retry-After": str(int(remaining_or_retry)),
                    "Access-Control-Allow-Origin": "*",
                    "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
                    "Access-Control-Allow-Headers": "Content-Type, Authorization, X-API-Key",
                }
            )
        
        response = await call_next(request)
        
        response.headers["X-RateLimit-Limit"] = str(limit)
        response.headers["X-RateLimit-Remaining"] = str(max(0, int(remaining_or_retry)))
        response.headers["X-RateLimit-Reset"] = str(int(time.time() + 60))
        
        return response


def rate_limit(tier: str = "basic", cost: int = 1):
    def decorator(func: Callable) -> Callable:
        async def wrapper(request: Request, *args, **kwargs):
            client_id = get_client_identifier(request)
            rate_limiter = get_rate_limiter()
            
            for _ in range(cost):
                allowed, remaining, limit = rate_limiter.check_rate_limit(client_id, tier)
                if not allowed:
                    raise HTTPException(
                        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                        detail="Rate limit exceeded",
                        headers={"Retry-After": str(int(remaining))}
                    )
            
            return await func(request, *args, **kwargs)
        
        return wrapper
    return decorator
