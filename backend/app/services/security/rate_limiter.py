import time
from collections import defaultdict, deque
from threading import Lock
from fastapi import HTTPException, Request, status


class SlidingWindowRateLimiter:
    """Thread-safe in-memory sliding window rate limiter."""

    def __init__(self):
        self._requests = defaultdict(deque)
        self._lock = Lock()

    def check(self, key: str, max_calls: int, window_seconds: int) -> bool:
        now = time.monotonic()
        with self._lock:
            queue = self._requests[key]
            while queue and now - queue[0] >= window_seconds:
                queue.popleft()

            if len(queue) >= max_calls:
                return False

            queue.append(now)
            return True


# Global rate limiter instance
limiter = SlidingWindowRateLimiter()


def rate_limit(max_calls: int, window_seconds: int = 60):
    """FastAPI route dependency enforcing rate limiting per client IP."""
    def dependency(request: Request):
        client_ip = request.client.host if request.client else "127.0.0.1"
        endpoint = request.url.path
        key = f"{client_ip}:{endpoint}"

        allowed = limiter.check(key, max_calls, window_seconds)
        if not allowed:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Rate limit exceeded. Maximum {max_calls} requests per {window_seconds}s.",
                headers={"Retry-After": str(window_seconds)},
            )

    return dependency
