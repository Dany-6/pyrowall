"""
PyroWall - Stateful Firewall Engine
Core packet processing and state tracking module.
"""

import logging
import os
import time
import threading
from dataclasses import dataclass, field
from typing import Optional, Tuple, Callable
from collections import defaultdict

from .packet import Packet
from .state_table import StateTable, ConnectionState
from .rate_limiter import RateLimiter
from rules.rule_engine import RuleEngine, Rule, Action

logger = logging.getLogger("pyrowall.firewall")


@dataclass
class FirewallStats:
    packets_seen: int = 0
    packets_allowed: int = 0
    packets_denied: int = 0
    packets_logged: int = 0
    packets_rate_limited: int = 0
    bytes_seen: int = 0
    start_time: float = field(default_factory=time.time)

    def uptime(self) -> float:
        return time.time() - self.start_time

    def summary(self) -> dict:
        return {
            "uptime_seconds": round(self.uptime(), 2),
            "packets_seen": self.packets_seen,
            "packets_allowed": self.packets_allowed,
            "packets_denied": self.packets_denied,
            "packets_logged": self.packets_logged,
            "packets_rate_limited": self.packets_rate_limited,
            "bytes_seen": self.bytes_seen,
            "allow_rate": round(
                self.packets_allowed / max(1, self.packets_seen) * 100, 1
            ),
        }


class Firewall:
    """
    Main stateful firewall class.

    Usage:
        fw = Firewall()
        fw.load_rules("rules/default.rules")
        fw.start()

        action, rule = fw.process(packet)
    """

    def __init__(
        self,
        default_policy: Action = Action.DENY,
        rate_limit: int = 0,
    ):
        """
        Args:
            default_policy:  Action when no rule matches.
            rate_limit:      Max packets per second per source IP.
                             0 = disabled.
        """
        self.default_policy = default_policy
        self.rule_engine = RuleEngine(default_policy=default_policy)
        self.state_table = StateTable()
        self.stats = FirewallStats()
        self._running = False
        self._lock = threading.Lock()
        self._event_hooks = defaultdict(list)  # e.g. "deny" -> [callbacks]

        # Rate limiter (disabled if rate_limit <= 0)
        self.rate_limiter: Optional[RateLimiter] = None
        if rate_limit > 0:
            self.rate_limiter = RateLimiter(max_pps=rate_limit)

        # Hot-reload state
        self._watch_thread: Optional[threading.Thread] = None
        self._watch_stop = threading.Event()
        self._rules_path: Optional[str] = None
        self._rules_mtime: float = 0

    # ------------------------------------------------------------------ #
    # Rule management                                                      #
    # ------------------------------------------------------------------ #

    def load_rules(self, path: str):
        """Load rules from a .rules file."""
        self.rule_engine.load_from_file(path)
        self._rules_path = path
        try:
            self._rules_mtime = os.path.getmtime(path)
        except OSError:
            self._rules_mtime = 0
        logger.info("Loaded rules from %s", path)

    def add_rule(self, **kwargs):
        """Add a single rule programmatically."""
        self.rule_engine.add_rule(**kwargs)

    def watch_rules(self, interval: int = 5):
        """Start watching the rules file for changes and auto-reload."""
        if not self._rules_path:
            logger.warning("No rules file loaded; cannot watch")
            return

        def loop():
            while not self._watch_stop.wait(timeout=interval):
                try:
                    mtime = os.path.getmtime(self._rules_path)
                    if mtime != self._rules_mtime:
                        logger.info(
                            "Rules file changed, reloading: %s", self._rules_path
                        )
                        self.rule_engine.clear_rules()
                        self.rule_engine.load_from_file(self._rules_path)
                        self._rules_mtime = mtime
                except Exception as exc:
                    logger.error("Error reloading rules: %s", exc)

        self._watch_thread = threading.Thread(
            target=loop, daemon=True, name="rule-watcher"
        )
        self._watch_thread.start()
        logger.info("Watching rules file for changes: %s", self._rules_path)

    # ------------------------------------------------------------------ #
    # Packet processing                                                    #
    # ------------------------------------------------------------------ #

    def process(self, packet: Packet) -> Tuple[Action, Optional[Rule]]:
        """
        Process one packet and return (action, matched_rule).

        Steps:
          1. Update stats
          2. Rate limit check
          3. Check state table (existing connection -> fast-path allow)
          4. Evaluate rules
          5. Update state table on ALLOW or LOG
          6. Fire event hooks
        """
        with self._lock:
            self.stats.packets_seen += 1
            self.stats.bytes_seen += packet.size

            # Rate limit check
            if self.rate_limiter and not self.rate_limiter.is_allowed(packet.src_ip):
                self.stats.packets_denied += 1
                self.stats.packets_rate_limited += 1
                logger.warning("RATE-LIMITED  %s", packet)
                self._fire("deny", packet, None)
                return Action.DENY, None

            # Fast-path: established connection
            if self.state_table.is_established(packet):
                self.stats.packets_allowed += 1
                logger.debug("ESTABLISHED %s", packet)
                self._fire("allow", packet, None)
                return Action.ALLOW, None

            # Rule evaluation
            action, matched_rule = self.rule_engine.evaluate(packet)

            if action == Action.ALLOW:
                self.state_table.track(packet)
                self.stats.packets_allowed += 1
                logger.info("ALLOW  %s  (rule: %s)", packet, matched_rule)
                self._fire("allow", packet, matched_rule)

            elif action == Action.DENY:
                self.stats.packets_denied += 1
                logger.warning("DENY   %s  (rule: %s)", packet, matched_rule)
                self._fire("deny", packet, matched_rule)

            elif action == Action.LOG:
                # LOG = allow the packet through + log it
                self.state_table.track(packet)
                self.stats.packets_logged += 1
                self.stats.packets_allowed += 1
                logger.info("LOG    %s  (rule: %s)", packet, matched_rule)
                self._fire("log", packet, matched_rule)

            return action, matched_rule

    # ------------------------------------------------------------------ #
    # Event hooks                                                          #
    # ------------------------------------------------------------------ #

    def on(self, event: str, callback: Callable):
        """Register a callback for firewall events: 'deny', 'allow', 'log'."""
        self._event_hooks[event].append(callback)

    def _fire(self, event: str, *args):
        for cb in self._event_hooks.get(event, []):
            try:
                cb(*args)
            except Exception as exc:
                logger.error("Hook error (%s): %s", event, exc)

    # ------------------------------------------------------------------ #
    # Lifecycle                                                            #
    # ------------------------------------------------------------------ #

    def start(self):
        self._running = True
        logger.info("PyroWall started (default policy: %s)", self.default_policy.name)

    def stop(self):
        self._running = False

        # Stop rule watcher
        self._watch_stop.set()
        if self._watch_thread and self._watch_thread.is_alive():
            self._watch_thread.join(timeout=2)

        # Stop state table cleanup
        self.state_table.stop()

        # Stop rate limiter cleanup
        if self.rate_limiter:
            self.rate_limiter.stop()

        logger.info("PyroWall stopped. Stats: %s", self.stats.summary())

    @property
    def running(self):
        return self._running
