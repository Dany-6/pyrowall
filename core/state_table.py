"""
State Table — tracks active connections for stateful inspection.
"""

import time
import threading
import logging
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Dict, Optional, List

logger = logging.getLogger("pyrowall.state")


class ConnectionState(Enum):
    SYN_SENT      = auto()
    ESTABLISHED   = auto()
    FIN_WAIT      = auto()
    CLOSED        = auto()
    UDP_ACTIVE    = auto()
    ICMP_ACTIVE   = auto()


@dataclass
class Connection:
    key: tuple
    state: ConnectionState
    created_at: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    packet_count: int = 0
    byte_count: int = 0

    def touch(self, size: int = 0):
        self.last_seen = time.time()
        self.packet_count += 1
        self.byte_count += size

    def age(self) -> float:
        return time.time() - self.created_at

    def idle(self) -> float:
        return time.time() - self.last_seen


class StateTable:
    """
    Tracks connection state for stateful packet inspection.

    Timeouts (seconds):
      TCP established : 3600
      TCP SYN         :   60
      UDP             :  120
      ICMP            :   30
    """

    TIMEOUTS = {
        ConnectionState.ESTABLISHED: 3600,
        ConnectionState.SYN_SENT:      60,
        ConnectionState.UDP_ACTIVE:    120,
        ConnectionState.ICMP_ACTIVE:    30,
        ConnectionState.FIN_WAIT:       30,
        ConnectionState.CLOSED:          0,
    }

    def __init__(self, cleanup_interval: int = 60):
        self._table: Dict[tuple, Connection] = {}
        self._lock = threading.RLock()
        self._cleanup_interval = cleanup_interval
        self._stop_event = threading.Event()
        self._cleanup_thread: Optional[threading.Thread] = None

        if cleanup_interval > 0:
            self._start_cleanup_thread()

    # ------------------------------------------------------------------ #
    # Public API                                                           #
    # ------------------------------------------------------------------ #

    def track(self, packet) -> Connection:
        """Add or update a connection entry for an allowed packet."""
        with self._lock:
            key = packet.connection_key
            proto = packet.protocol.upper()

            if proto == "TCP":
                conn = self._handle_tcp(packet, key)
            elif proto == "UDP":
                conn = self._upsert(key, ConnectionState.UDP_ACTIVE, packet.size)
            else:  # ICMP and others
                conn = self._upsert(key, ConnectionState.ICMP_ACTIVE, packet.size)

            return conn

    def is_established(self, packet) -> bool:
        """Return True if this packet belongs to a tracked connection."""
        with self._lock:
            # Check forward direction
            conn = self._table.get(packet.connection_key)
            if conn and conn.state in (
                ConnectionState.ESTABLISHED,
                ConnectionState.UDP_ACTIVE,
                ConnectionState.ICMP_ACTIVE,
                ConnectionState.FIN_WAIT,
            ):
                conn.touch(packet.size)
                return True

            # Check reverse direction (reply packets)
            conn = self._table.get(packet.reverse_key)
            if conn and conn.state in (
                ConnectionState.ESTABLISHED,
                ConnectionState.SYN_SENT,    # Allow SYN-ACK replies
                ConnectionState.UDP_ACTIVE,  # Allow UDP replies
                ConnectionState.ICMP_ACTIVE, # Allow ICMP replies
            ):
                conn.touch(packet.size)
                # Upgrade SYN_SENT to ESTABLISHED on reverse traffic
                if conn.state == ConnectionState.SYN_SENT:
                    conn.state = ConnectionState.ESTABLISHED
                return True

        return False

    def remove(self, key: tuple):
        with self._lock:
            self._table.pop(key, None)

    def snapshot(self) -> list:
        """Return a list of active connections as dicts."""
        with self._lock:
            return [
                {
                    "key": c.key,
                    "state": c.state.name,
                    "age": round(c.age(), 1),
                    "idle": round(c.idle(), 1),
                    "packets": c.packet_count,
                    "bytes": c.byte_count,
                }
                for c in self._table.values()
                if c.state != ConnectionState.CLOSED
            ]

    def count(self) -> int:
        with self._lock:
            return sum(1 for c in self._table.values() if c.state != ConnectionState.CLOSED)

    def top_talkers(self, n: int = 10) -> List[dict]:
        """Return top N connections by byte count."""
        with self._lock:
            active = [
                c for c in self._table.values()
                if c.state != ConnectionState.CLOSED
            ]
            active.sort(key=lambda c: c.byte_count, reverse=True)
            return [
                {
                    "src": f"{c.key[0]}:{c.key[1]}",
                    "dst": f"{c.key[2]}:{c.key[3]}",
                    "proto": c.key[4],
                    "bytes": c.byte_count,
                    "packets": c.packet_count,
                    "state": c.state.name,
                    "age": round(c.age(), 1),
                }
                for c in active[:n]
            ]

    # ------------------------------------------------------------------ #
    # Lifecycle                                                            #
    # ------------------------------------------------------------------ #

    def stop(self):
        """Stop the background cleanup thread gracefully."""
        self._stop_event.set()
        if self._cleanup_thread and self._cleanup_thread.is_alive():
            self._cleanup_thread.join(timeout=2)
            logger.debug("State table cleanup thread stopped")

    # ------------------------------------------------------------------ #
    # Internal helpers                                                     #
    # ------------------------------------------------------------------ #

    def _handle_tcp(self, packet, key) -> Connection:
        existing = self._table.get(key)

        if packet.is_syn():
            conn = Connection(key=key, state=ConnectionState.SYN_SENT)
            self._table[key] = conn
            return conn

        if existing:
            if "ACK" in packet.flags.upper():
                if existing.state == ConnectionState.SYN_SENT:
                    existing.state = ConnectionState.ESTABLISHED
            if packet.is_fin():
                existing.state = ConnectionState.FIN_WAIT
            if packet.is_rst():
                existing.state = ConnectionState.CLOSED
            existing.touch(packet.size)
            return existing

        # Unknown TCP packet without existing state -- create ESTABLISHED
        conn = Connection(key=key, state=ConnectionState.ESTABLISHED)
        conn.touch(packet.size)
        self._table[key] = conn
        return conn

    def _upsert(self, key, state, size) -> Connection:
        if key not in self._table:
            conn = Connection(key=key, state=state)
            self._table[key] = conn
        else:
            conn = self._table[key]
            conn.touch(size)
        return conn

    # ------------------------------------------------------------------ #
    # Cleanup                                                              #
    # ------------------------------------------------------------------ #

    def _cleanup(self) -> int:
        """Remove expired connections. Returns count of removed entries."""
        with self._lock:
            expired = []
            for key, conn in self._table.items():
                timeout = self.TIMEOUTS.get(conn.state, 60)
                if conn.idle() > timeout:
                    expired.append(key)
            for key in expired:
                del self._table[key]
            if expired:
                logger.debug("Cleaned up %d expired connections", len(expired))
            return len(expired)

    def _start_cleanup_thread(self):
        def loop():
            while not self._stop_event.wait(timeout=self._cleanup_interval):
                self._cleanup()

        self._cleanup_thread = threading.Thread(
            target=loop, daemon=True, name="state-cleanup"
        )
        self._cleanup_thread.start()
