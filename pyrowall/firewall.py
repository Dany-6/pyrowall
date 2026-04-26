"""
PyroWall - Stateful Firewall Engine
Core packet processing and state tracking module.
"""

import logging
import time
import threading
from dataclasses import dataclass, field
from typing import Optional
from collections import defaultdict

from .packet import Packet
from .state_table import StateTable, ConnectionState
from rules.rule_engine import RuleEngine, Action

logger = logging.getLogger("pyrowall.firewall")


@dataclass
class FirewallStats:
    packets_seen: int = 0
    packets_allowed: int = 0
    packets_denied: int = 0
    packets_logged: int = 0
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
            "bytes_seen": self.bytes_seen,
            "allow_rate": round(self.packets_allowed / max(1, self.packets_seen) * 100, 1),
        }


class Firewall:
    """
    Main stateful firewall class.

    Usage:
        fw = Firewall()
        fw.load_rules("rules/default.rules")
        fw.start()
    """

    def __init__(self, default_policy: Action = Action.DENY):
        self.default_policy = default_policy
        self.rule_engine = RuleEngine(default_policy=default_policy)
        self.state_table = StateTable()
        self.stats = FirewallStats()
        self._running = False
        self._lock = threading.Lock()
        self._event_hooks = defaultdict(list)  # e.g. "deny" -> [callbacks]

    # ------------------------------------------------------------------ #
    # Rule management                                                      #
    # ------------------------------------------------------------------ #

    def load_rules(self, path: str):
        """Load rules from a .rules file."""
        self.rule_engine.load_from_file(path)
        logger.info("Loaded rules from %s", path)

    def add_rule(self, **kwargs):
        """Add a single rule programmatically."""
        self.rule_engine.add_rule(**kwargs)

    # ------------------------------------------------------------------ #
    # Packet processing                                                    #
    # ------------------------------------------------------------------ #

    def process(self, packet: Packet) -> Action:
        """
        Process one packet and return the action to take.

        Steps:
          1. Update stats
          2. Check state table (existing connection → fast-path allow)
          3. Evaluate rules
          4. Update state table on ALLOW
          5. Fire event hooks
        """
        with self._lock:
            self.stats.packets_seen += 1
            self.stats.bytes_seen += packet.size

            # Fast-path: established connection
            if self.state_table.is_established(packet):
                self.stats.packets_allowed += 1
                logger.debug("ESTABLISHED %s", packet)
                return Action.ALLOW

            # Rule evaluation
            action, matched_rule = self.rule_engine.evaluate(packet)

            if action == Action.ALLOW:
                self.state_table.track(packet)
                self.stats.packets_allowed += 1
                logger.info("ALLOW  %s  (rule: %s)", packet, matched_rule)

            elif action == Action.DENY:
                self.stats.packets_denied += 1
                logger.warning("DENY   %s  (rule: %s)", packet, matched_rule)
                self._fire("deny", packet, matched_rule)

            elif action == Action.LOG:
                self.stats.packets_logged += 1
                logger.info("LOG    %s  (rule: %s)", packet, matched_rule)

            return action

    # ------------------------------------------------------------------ #
    # Event hooks                                                          #
    # ------------------------------------------------------------------ #

    def on(self, event: str, callback):
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
        logger.info("PyroWall stopped. Stats: %s", self.stats.summary())

    @property
    def running(self):
        return self._running
