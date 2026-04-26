"""
Packet model — represents a single network packet.
"""

from dataclasses import dataclass, field
from typing import Optional
import time


@dataclass
class Packet:
    """
    Represents a parsed network packet.

    Attributes:
        src_ip      Source IP address (string, e.g. "192.168.1.1")
        dst_ip      Destination IP address
        src_port    Source port (0 for ICMP/non-TCP/UDP)
        dst_port    Destination port
        protocol    "TCP", "UDP", "ICMP", or other string
        flags       TCP flags string, e.g. "SYN", "ACK", "FIN", "RST"
        size        Packet size in bytes
        payload     Raw payload bytes (optional)
        timestamp   Unix timestamp of capture
    """

    src_ip: str
    dst_ip: str
    protocol: str
    src_port: int = 0
    dst_port: int = 0
    flags: str = ""
    size: int = 64
    payload: bytes = field(default=b"", repr=False)
    timestamp: float = field(default_factory=time.time)

    # ------------------------------------------------------------------ #
    # Helpers                                                              #
    # ------------------------------------------------------------------ #

    @property
    def connection_key(self) -> tuple:
        """5-tuple that identifies a connection."""
        return (self.src_ip, self.src_port, self.dst_ip, self.dst_port, self.protocol)

    @property
    def reverse_key(self) -> tuple:
        """Reverse direction — for matching reply packets."""
        return (self.dst_ip, self.dst_port, self.src_ip, self.src_port, self.protocol)

    def is_syn(self) -> bool:
        return "SYN" in self.flags.upper() and "ACK" not in self.flags.upper()

    def is_fin(self) -> bool:
        return "FIN" in self.flags.upper()

    def is_rst(self) -> bool:
        return "RST" in self.flags.upper()

    def __str__(self):
        return (
            f"{self.protocol} {self.src_ip}:{self.src_port} -> "
            f"{self.dst_ip}:{self.dst_port} [{self.flags}] {self.size}B"
        )

    # ------------------------------------------------------------------ #
    # Factory helpers                                                      #
    # ------------------------------------------------------------------ #

    @classmethod
    def tcp(cls, src_ip, dst_ip, src_port, dst_port, flags="SYN", size=64):
        return cls(src_ip=src_ip, dst_ip=dst_ip, src_port=src_port,
                   dst_port=dst_port, protocol="TCP", flags=flags, size=size)

    @classmethod
    def udp(cls, src_ip, dst_ip, src_port, dst_port, size=64):
        return cls(src_ip=src_ip, dst_ip=dst_ip, src_port=src_port,
                   dst_port=dst_port, protocol="UDP", size=size)

    @classmethod
    def icmp(cls, src_ip, dst_ip, size=64):
        return cls(src_ip=src_ip, dst_ip=dst_ip, protocol="ICMP", size=size)
