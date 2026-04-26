"""
Rule Engine — loads, stores, and evaluates firewall rules.

Rule file format (.rules):
  # Comments start with #
  ALLOW TCP 0.0.0.0/0 ANY -> 0.0.0.0/0 80   # allow HTTP
  ALLOW TCP 0.0.0.0/0 ANY -> 0.0.0.0/0 443  # allow HTTPS
  DENY  TCP 0.0.0.0/0 ANY -> 0.0.0.0/0 22   # block SSH
  LOG   UDP 0.0.0.0/0 ANY -> 0.0.0.0/0 53   # log DNS
  DENY  ANY 0.0.0.0/0 ANY -> 0.0.0.0/0 ANY  # default deny

Direction arrow "->" separates source (src_ip src_port) from dest (dst_ip dst_port).
ANY means "match everything" for that field.
CIDR notation supported for IPs.
"""

import ipaddress
import logging
import re
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Optional, Tuple

logger = logging.getLogger("pyrowall.rules")


class Action(Enum):
    ALLOW = "ALLOW"
    DENY  = "DENY"
    LOG   = "LOG"


@dataclass
class Rule:
    action: Action
    protocol: str             # "TCP", "UDP", "ICMP", "ANY"
    src_network: str          # "0.0.0.0/0" or specific CIDR or IP
    src_port: Optional[int]   # None means ANY
    dst_network: str
    dst_port: Optional[int]
    comment: str = ""
    priority: int = 100       # lower = higher priority

    def matches(self, packet) -> bool:
        """Return True if this rule matches the given packet."""
        # Protocol check
        if self.protocol != "ANY" and self.protocol.upper() != packet.protocol.upper():
            return False

        # Source IP
        if not self._ip_matches(packet.src_ip, self.src_network):
            return False

        # Destination IP
        if not self._ip_matches(packet.dst_ip, self.dst_network):
            return False

        # Source port
        if self.src_port is not None and self.src_port != packet.src_port:
            return False

        # Destination port
        if self.dst_port is not None and self.dst_port != packet.dst_port:
            return False

        return True

    @staticmethod
    def _ip_matches(ip_str: str, network_str: str) -> bool:
        if network_str in ("ANY", "0.0.0.0/0", "::/0"):
            return True
        try:
            return ipaddress.ip_address(ip_str) in ipaddress.ip_network(network_str, strict=False)
        except ValueError:
            return ip_str == network_str

    def __str__(self):
        sp = str(self.src_port) if self.src_port is not None else "ANY"
        dp = str(self.dst_port) if self.dst_port is not None else "ANY"
        return (
            f"{self.action.value:5s} {self.protocol:4s} "
            f"{self.src_network}:{sp} -> {self.dst_network}:{dp}"
            + (f"  # {self.comment}" if self.comment else "")
        )


class RuleEngine:
    """
    Stores an ordered list of rules and evaluates packets against them.
    First matching rule wins.
    """

    def __init__(self, default_policy: Action = Action.DENY):
        self.rules: list[Rule] = []
        self.default_policy = default_policy

    # ------------------------------------------------------------------ #
    # Rule management                                                      #
    # ------------------------------------------------------------------ #

    def add_rule(
        self,
        action: Action,
        protocol: str = "ANY",
        src_network: str = "0.0.0.0/0",
        src_port: Optional[int] = None,
        dst_network: str = "0.0.0.0/0",
        dst_port: Optional[int] = None,
        comment: str = "",
        priority: int = 100,
    ):
        rule = Rule(
            action=action,
            protocol=protocol,
            src_network=src_network,
            src_port=src_port,
            dst_network=dst_network,
            dst_port=dst_port,
            comment=comment,
            priority=priority,
        )
        self.rules.append(rule)
        self.rules.sort(key=lambda r: r.priority)
        logger.debug("Rule added: %s", rule)

    def load_from_file(self, path: str):
        """Parse a .rules file and add rules to the engine."""
        parsed = 0
        skipped = 0
        with open(path) as f:
            for lineno, raw in enumerate(f, 1):
                line = raw.strip()
                if not line or line.startswith("#"):
                    continue
                try:
                    rule = self._parse_line(line)
                    self.rules.append(rule)
                    parsed += 1
                except ValueError as exc:
                    logger.warning("Line %d skipped: %s — %s", lineno, line, exc)
                    skipped += 1

        self.rules.sort(key=lambda r: r.priority)
        logger.info("Loaded %d rules (%d skipped) from %s", parsed, skipped, path)

    # ------------------------------------------------------------------ #
    # Evaluation                                                           #
    # ------------------------------------------------------------------ #

    def evaluate(self, packet) -> Tuple[Action, Optional[Rule]]:
        """
        Evaluate packet against rules in priority order.
        Returns (Action, matching_rule_or_None).
        """
        for rule in self.rules:
            if rule.matches(packet):
                return rule.action, rule

        return self.default_policy, None

    # ------------------------------------------------------------------ #
    # Parser                                                               #
    # ------------------------------------------------------------------ #

    def _parse_line(self, line: str) -> Rule:
        """
        Parse a single rule line.

        Format:
          ACTION PROTO SRC_IP SRC_PORT -> DST_IP DST_PORT [# comment]
        Example:
          ALLOW TCP 192.168.0.0/16 ANY -> 0.0.0.0/0 443  # HTTPS
        """
        # Strip inline comment
        comment = ""
        if "#" in line:
            line, _, comment = line.partition("#")
            comment = comment.strip()
            line = line.strip()

        parts = line.split()
        if len(parts) < 7 or parts[4] != "->":
            raise ValueError(
                f"Expected: ACTION PROTO SRC_IP SRC_PORT -> DST_IP DST_PORT, got: {line!r}"
            )

        action_str, proto, src_ip, src_port_str, _, dst_ip, dst_port_str = parts[:7]

        try:
            action = Action[action_str.upper()]
        except KeyError:
            raise ValueError(f"Unknown action: {action_str!r}")

        src_port = None if src_port_str.upper() == "ANY" else int(src_port_str)
        dst_port = None if dst_port_str.upper() == "ANY" else int(dst_port_str)

        return Rule(
            action=action,
            protocol=proto.upper(),
            src_network=src_ip,
            src_port=src_port,
            dst_network=dst_ip,
            dst_port=dst_port,
            comment=comment,
        )

    def list_rules(self):
        """Print all rules in a formatted table."""
        if not self.rules:
            print("No rules loaded.")
            return
        print(f"{'#':<4} {'ACTION':<7} {'PROTO':<5} {'SRC':<22} {'DST':<22} COMMENT")
        print("-" * 80)
        for i, rule in enumerate(self.rules):
            sp = str(rule.src_port) if rule.src_port else "ANY"
            dp = str(rule.dst_port) if rule.dst_port else "ANY"
            src = f"{rule.src_network}:{sp}"
            dst = f"{rule.dst_network}:{dp}"
            print(f"{i:<4} {rule.action.value:<7} {rule.protocol:<5} {src:<22} {dst:<22} {rule.comment}")
