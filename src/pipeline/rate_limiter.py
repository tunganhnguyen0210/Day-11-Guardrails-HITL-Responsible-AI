"""
Assignment 11 — Layer 1: Rate Limiter

What: limits how many requests a single user can send in a sliding time
window (default: 10 requests / 60 seconds).

Why: none of the other layers (injection detection, topic filter, output
filter, judge) protect against simple abuse — a user (or bot) hammering the
endpoint with thousands of requests per minute. The rate limiter is the
*first* layer because it is the cheapest check (no LLM call, no regex over
the message body) and stops abusive traffic before it can even reach the
more expensive layers.
"""
import time
from collections import defaultdict, deque
from dataclasses import dataclass


@dataclass
class RateLimitResult:
    """Outcome of a rate limit check for a single request."""
    allowed: bool
    requests_in_window: int
    wait_seconds: float


class RateLimiter:
    """Sliding-window, per-user rate limiter.

    Each user gets their own deque of request timestamps. On every check we
    drop timestamps older than `window_seconds`, then compare the remaining
    count against `max_requests`.
    """

    def __init__(self, max_requests: int = 10, window_seconds: int = 60):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.user_windows: dict[str, deque] = defaultdict(deque)

    def check(self, user_id: str) -> RateLimitResult:
        """Check (and record, if allowed) a request for `user_id`.

        Returns a RateLimitResult telling the caller whether the request is
        allowed, how many requests are currently in the window, and — if
        blocked — how many seconds until the oldest request expires.
        """
        now = time.time()
        window = self.user_windows[user_id]

        # Drop timestamps that have aged out of the window.
        while window and window[0] <= now - self.window_seconds:
            window.popleft()

        if len(window) >= self.max_requests:
            wait_seconds = self.window_seconds - (now - window[0])
            return RateLimitResult(
                allowed=False,
                requests_in_window=len(window),
                wait_seconds=max(wait_seconds, 0.0),
            )

        window.append(now)
        return RateLimitResult(
            allowed=True,
            requests_in_window=len(window),
            wait_seconds=0.0,
        )

    def reset(self, user_id: str | None = None):
        """Clear rate-limit history for one user, or everyone (testing helper)."""
        if user_id is None:
            self.user_windows.clear()
        else:
            self.user_windows.pop(user_id, None)
