"""
Rate Limiter — sliding-window rate limiter per source IP.

Protects against packet floods by tracking packet counts per source
in a 1-second sliding window.  When a source exceeds the threshold,
all its packets are dropped before rule evaluation even begins.
"""

import time
import threading
import logging
from collections import defaultdict, deque
from typing import Dict

logger = logging.getLogger("pyrowall.ratelimit")


class RateLimiter:
    """
    Sliding-window rate limiter.

    Usage:
        rl = RateLimiter(max_pps=100)
        if not rl.is_allowed("1.2.3.4"):
            drop(packet)

    The limiter tracks per-source-IP packet timestamps in a deque.
    Old entries (> 1 second) are pruned on each call.
    A background thread periodically cleans up stale source entries
    to prevent memory leaks from disappeared sources.
    """

    def __init__(self, max_pps: int = 100, cleanup_interval: int = 30):
        """
        Args:
            max_pps:  Maximum packets per second per source IP.
            cleanup_interval:  Seconds between stale-entry cleanup sweeps.
        """
        self.max_pps = max_pps
        self._windows: Dict[str, deque] = defaultdict(deque)
        self._lock = threading.Lock()
        self._blocked: Dict[str, float] = {}  # src_ip -> first-blocked timestamp
        self._stop_event = threading.Event()

        self._cleanup_thread = threading.Thread(
            target=self._cleanup_loop,
            args=(cleanup_interval,),
            daemon=True,
            name="rate-limiter-cleanup",
        )
        self._cleanup_thread.start()

    # ------------------------------------------------------------------ #
    # Public API                                                           #
    # ------------------------------------------------------------------ #

    def is_allowed(self, src_ip: str) -> bool:
        """
        Return True if the source IP is within its rate limit.

        Prunes timestamps older than 1 second, then checks the count.
        """
        now = time.time()
        with self._lock:
            window = self._windows[src_ip]

            # Prune entries older than 1 second
            while window and window[0] < now - 1.0:
                window.popleft()

            if len(window) >= self.max_pps:
                # Record first-blocked time for reporting
                if src_ip not in self._blocked:
                    self._blocked[src_ip] = now
                    logger.warning(
                        "Rate limit exceeded for %s (%d pps > %d max)",
                        src_ip, len(window), self.max_pps,
                    )
                return False

            window.append(now)
            # Clear blocked status if previously blocked
            self._blocked.pop(src_ip, None)
            return True

    def get_blocked_sources(self) -> dict:
        """Return dict of currently blocked IPs and when they were first blocked."""
        with self._lock:
            return dict(self._blocked)

    def reset(self, src_ip: str = None):
        """Reset rate limit state.  If src_ip given, reset only that source."""
        with self._lock:
            if src_ip:
                self._windows.pop(src_ip, None)
                self._blocked.pop(src_ip, None)
            else:
                self._windows.clear()
                self._blocked.clear()

    def stop(self):
        """Stop the background cleanup thread."""
        self._stop_event.set()

    # ------------------------------------------------------------------ #
    # Internal                                                             #
    # ------------------------------------------------------------------ #

    def _cleanup_loop(self, interval: int):
        """Remove source entries that have been idle for > 10 seconds."""
        while not self._stop_event.wait(timeout=interval):
            self._cleanup()

    def _cleanup(self):
        now = time.time()
        with self._lock:
            stale = [
                ip for ip, window in self._windows.items()
                if not window or window[-1] < now - 10.0
            ]
            for ip in stale:
                del self._windows[ip]
                self._blocked.pop(ip, None)
            if stale:
                logger.debug("Cleaned up %d stale rate-limit entries", len(stale))
