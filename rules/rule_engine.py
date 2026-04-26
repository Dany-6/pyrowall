"""
Rule Engine — loads, stores, and evaluates firewall rules.

Rule file format (.rules):
  # Comments start with #
  ALLOW TCP 0.0.0.0/0 ANY -> 0.0.0.0/0 80         # allow HTTP
  ALLOW TCP 0.0.0.0/0 ANY -> 0.0.0.0/0 443        # allow HTTPS
  DENY  TCP 0.0.0.0/0 ANY -> 0.0.0.0/0 22         # block SSH
  LOG   UDP 0.0.0.0/0 ANY -> 0.0.0.0/0 53         # log DNS
  DENY  ANY 0.0.0.0/0 ANY -> 0.0.0.0/0 ANY        # default deny

Direction arrow "->" separates source (src_ip src_port) from dest (dst_ip dst_port).
ANY means "match everything" for that field.
CIDR notation supported for IPs (IPv4 and IPv6).
Port ranges supported: 1024-65535
Time-based schedules: schedule:HH:MM-HH:MM (24-hour format)
"""

import ipaddress
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum, auto
from typing import Optional, Tuple, List

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
    src_port: Optional[int]   # None means ANY (single port)
    dst_network: str
    dst_port: Optional[int]   # None means ANY (single port)
    comment: str = ""
    priority: int = 100       # lower = higher priority

    # Port range support (None means use single src_port/dst_port)
    src_port_end: Optional[int] = None   # end of source port range
    dst_port_end: Optional[int] = None   # end of dest port range

    # Time-based schedule (None means always active)
    schedule_start: Optional[str] = None  # "HH:MM"
    schedule_end: Optional[str] = None    # "HH:MM"

    # Hit counter
    hit_count: int = field(default=0, repr=False)

    def matches(self, packet) -> bool:
        """Return True if this rule matches the given packet."""
        # Time-based schedule check
        if not self._is_active_now():
            return False

        # Protocol check
        if self.protocol != "ANY" and self.protocol.upper() != packet.protocol.upper():
            return False

        # Source IP
        if not self._ip_matches(packet.src_ip, self.src_network):
            return False

        # Destination IP
        if not self._ip_matches(packet.dst_ip, self.dst_network):
            return False

        # Source port (range or single)
        if not self._port_matches(packet.src_port, self.src_port, self.src_port_end):
            return False

        # Destination port (range or single)
        if not self._port_matches(packet.dst_port, self.dst_port, self.dst_port_end):
            return False

        # Match found — increment hit counter
        self.hit_count += 1
        return True

    def _is_active_now(self) -> bool:
        """Check if the rule is active based on its time schedule."""
        if self.schedule_start is None or self.schedule_end is None:
            return True

        now = datetime.now().strftime("%H:%M")
        start = self.schedule_start
        end = self.schedule_end

        if start <= end:
            # Normal range (e.g. 08:00-17:00)
            return start <= now <= end
        else:
            # Overnight range (e.g. 22:00-06:00)
            return now >= start or now <= end

    @staticmethod
    def _ip_matches(ip_str: str, network_str: str) -> bool:
        """Match an IP address against a network/CIDR specification."""
        if network_str.upper() == "ANY" or network_str in ("0.0.0.0/0", "::/0"):
            return True
        try:
            return ipaddress.ip_address(ip_str) in ipaddress.ip_network(
                network_str, strict=False
            )
        except ValueError:
            return ip_str == network_str

    @staticmethod
    def _port_matches(
        packet_port: int,
        rule_port: Optional[int],
        rule_port_end: Optional[int],
    ) -> bool:
        """Match a port against a single port or range."""
        if rule_port is None:
            return True  # ANY
        if rule_port_end is not None:
            # Range match
            return rule_port <= packet_port <= rule_port_end
        # Exact match
        return rule_port == packet_port

    def __str__(self):
        sp = self._port_str(self.src_port, self.src_port_end)
        dp = self._port_str(self.dst_port, self.dst_port_end)
        s = (
            f"{self.action.value:5s} {self.protocol:4s} "
            f"{self.src_network}:{sp} -> {self.dst_network}:{dp}"
        )
        if self.schedule_start:
            s += f"  schedule:{self.schedule_start}-{self.schedule_end}"
        if self.comment:
            s += f"  # {self.comment}"
        return s

    @staticmethod
    def _port_str(port: Optional[int], port_end: Optional[int]) -> str:
        if port is None:
            return "ANY"
        if port_end is not None:
            return f"{port}-{port_end}"
        return str(port)


class RuleEngine:
    """
    Stores an ordered list of rules and evaluates packets against them.
    First matching rule wins.
    """

    def __init__(self, default_policy: Action = Action.DENY):
        self.rules: List[Rule] = []
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
        src_port_end: Optional[int] = None,
        dst_port_end: Optional[int] = None,
        schedule_start: Optional[str] = None,
        schedule_end: Optional[str] = None,
    ):
        """Add a rule programmatically with full validation."""
        # Validate
        self._validate_network(src_network, "src_network")
        self._validate_network(dst_network, "dst_network")
        self._validate_port(src_port, "src_port")
        self._validate_port(dst_port, "dst_port")
        self._validate_port(src_port_end, "src_port_end")
        self._validate_port(dst_port_end, "dst_port_end")
        self._validate_protocol(protocol)

        if src_port_end is not None and src_port is not None and src_port_end < src_port:
            raise ValueError(f"src_port_end ({src_port_end}) < src_port ({src_port})")
        if dst_port_end is not None and dst_port is not None and dst_port_end < dst_port:
            raise ValueError(f"dst_port_end ({dst_port_end}) < dst_port ({dst_port})")

        if schedule_start:
            self._validate_time(schedule_start, "schedule_start")
        if schedule_end:
            self._validate_time(schedule_end, "schedule_end")

        rule = Rule(
            action=action,
            protocol=protocol.upper(),
            src_network=src_network,
            src_port=src_port,
            dst_network=dst_network,
            dst_port=dst_port,
            comment=comment,
            priority=priority,
            src_port_end=src_port_end,
            dst_port_end=dst_port_end,
            schedule_start=schedule_start,
            schedule_end=schedule_end,
        )
        self.rules.append(rule)
        self.rules.sort(key=lambda r: r.priority)
        logger.debug("Rule added: %s", rule)

    def load_from_file(self, path: str):
        """Parse a .rules file and add rules to the engine."""
        parsed = 0
        skipped = 0
        try:
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
                        logger.warning("Line %d skipped: %s -- %s", lineno, line, exc)
                        skipped += 1
        except FileNotFoundError:
            logger.error("Rules file not found: %s", path)
            raise
        except PermissionError:
            logger.error("Permission denied reading rules file: %s", path)
            raise

        self.rules.sort(key=lambda r: r.priority)
        logger.info("Loaded %d rules (%d skipped) from %s", parsed, skipped, path)

    def clear_rules(self):
        """Remove all rules (used for hot-reloading)."""
        self.rules.clear()
        logger.info("All rules cleared")

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
    # Statistics                                                           #
    # ------------------------------------------------------------------ #

    def rule_stats(self) -> list:
        """Return hit-count statistics for all rules."""
        return [
            {
                "index": i,
                "rule": str(rule),
                "hit_count": rule.hit_count,
                "action": rule.action.value,
            }
            for i, rule in enumerate(self.rules)
        ]

    def reset_hit_counts(self):
        """Reset all rule hit counters."""
        for rule in self.rules:
            rule.hit_count = 0

    # ------------------------------------------------------------------ #
    # Parser                                                               #
    # ------------------------------------------------------------------ #

    def _parse_line(self, line: str) -> Rule:
        """
        Parse a single rule line.

        Format:
          ACTION PROTO SRC_IP SRC_PORT -> DST_IP DST_PORT [schedule:HH:MM-HH:MM] [# comment]
        Examples:
          ALLOW TCP 192.168.0.0/16 ANY -> 0.0.0.0/0 443  # HTTPS
          DENY  TCP 0.0.0.0/0 ANY -> 0.0.0.0/0 1024-65535  # ephemeral
          DENY  TCP 0.0.0.0/0 ANY -> 0.0.0.0/0 80 schedule:22:00-06:00  # no HTTP at night
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

        # Parse optional schedule (after port fields)
        schedule_start = None
        schedule_end = None
        for extra in parts[7:]:
            if extra.startswith("schedule:"):
                sched = extra[len("schedule:"):]
                if "-" in sched:
                    schedule_start, schedule_end = sched.split("-", 1)
                    self._validate_time(schedule_start, "schedule_start")
                    self._validate_time(schedule_end, "schedule_end")
                else:
                    raise ValueError(f"Invalid schedule format: {extra!r}")

        try:
            action = Action[action_str.upper()]
        except KeyError:
            raise ValueError(f"Unknown action: {action_str!r}")

        # Validate protocol
        self._validate_protocol(proto)

        # Validate IPs
        self._validate_network(src_ip, "src_ip")
        self._validate_network(dst_ip, "dst_ip")

        # Parse ports (support ranges like 1024-65535)
        src_port, src_port_end = self._parse_port(src_port_str, "src_port")
        dst_port, dst_port_end = self._parse_port(dst_port_str, "dst_port")

        return Rule(
            action=action,
            protocol=proto.upper(),
            src_network=src_ip,
            src_port=src_port,
            dst_network=dst_ip,
            dst_port=dst_port,
            comment=comment,
            src_port_end=src_port_end,
            dst_port_end=dst_port_end,
            schedule_start=schedule_start,
            schedule_end=schedule_end,
        )

    # ------------------------------------------------------------------ #
    # Validation helpers                                                   #
    # ------------------------------------------------------------------ #

    @staticmethod
    def _parse_port(port_str: str, field_name: str) -> Tuple[Optional[int], Optional[int]]:
        """
        Parse a port specification.  Returns (port, port_end).

        Examples:
          "ANY"        -> (None, None)
          "80"         -> (80, None)
          "1024-65535" -> (1024, 65535)
        """
        if port_str.upper() == "ANY":
            return None, None

        if "-" in port_str:
            parts = port_str.split("-", 1)
            try:
                start = int(parts[0])
                end = int(parts[1])
            except ValueError:
                raise ValueError(f"Invalid port range for {field_name}: {port_str!r}")
            if start < 0 or end < 0:
                raise ValueError(f"Negative port in {field_name}: {port_str!r}")
            if start > 65535 or end > 65535:
                raise ValueError(f"Port out of range in {field_name}: {port_str!r}")
            if end < start:
                raise ValueError(
                    f"Port range end < start in {field_name}: {port_str!r}"
                )
            return start, end

        try:
            port = int(port_str)
        except ValueError:
            raise ValueError(f"Invalid port for {field_name}: {port_str!r}")
        if port < 0:
            raise ValueError(f"Negative port for {field_name}: {port}")
        if port > 65535:
            raise ValueError(f"Port out of range for {field_name}: {port}")
        return port, None

    @staticmethod
    def _validate_network(network: str, field_name: str):
        """Validate an IP/CIDR network specification."""
        if network.upper() == "ANY":
            return
        if network in ("0.0.0.0/0", "::/0"):
            return
        try:
            ipaddress.ip_network(network, strict=False)
        except ValueError as e:
            raise ValueError(f"Invalid network for {field_name}: {network!r} ({e})")

    @staticmethod
    def _validate_protocol(proto: str):
        """Validate protocol string."""
        valid = {"TCP", "UDP", "ICMP", "ANY"}
        if proto.upper() not in valid:
            raise ValueError(
                f"Invalid protocol: {proto!r} (must be one of {valid})"
            )

    @staticmethod
    def _validate_port(port: Optional[int], field_name: str):
        """Validate a single port number."""
        if port is None:
            return
        if not isinstance(port, int):
            raise ValueError(f"{field_name} must be int or None, got {type(port)}")
        if port < 0:
            raise ValueError(f"Negative port for {field_name}: {port}")
        if port > 65535:
            raise ValueError(f"Port out of range for {field_name}: {port}")

    @staticmethod
    def _validate_time(time_str: str, field_name: str):
        """Validate a HH:MM time string."""
        if not re.match(r"^\d{2}:\d{2}$", time_str):
            raise ValueError(
                f"Invalid time for {field_name}: {time_str!r} (expected HH:MM)"
            )
        h, m = time_str.split(":")
        if not (0 <= int(h) <= 23 and 0 <= int(m) <= 59):
            raise ValueError(
                f"Time out of range for {field_name}: {time_str!r}"
            )

    # ------------------------------------------------------------------ #
    # Display                                                              #
    # ------------------------------------------------------------------ #

    def list_rules(self):
        """Print all rules in a formatted table."""
        if not self.rules:
            print("No rules loaded.")
            return
        print(
            f"{'#':<4} {'ACTION':<7} {'PROTO':<5} {'SRC':<22} {'DST':<22} "
            f"{'HITS':<6} COMMENT"
        )
        print("-" * 90)
        for i, rule in enumerate(self.rules):
            sp = Rule._port_str(rule.src_port, rule.src_port_end)
            dp = Rule._port_str(rule.dst_port, rule.dst_port_end)
            src = f"{rule.src_network}:{sp}"
            dst = f"{rule.dst_network}:{dp}"
            sched = ""
            if rule.schedule_start:
                sched = f" [{rule.schedule_start}-{rule.schedule_end}]"
            print(
                f"{i:<4} {rule.action.value:<7} {rule.protocol:<5} "
                f"{src:<22} {dst:<22} {rule.hit_count:<6} "
                f"{rule.comment}{sched}"
            )
