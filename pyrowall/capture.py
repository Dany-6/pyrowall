"""
Packet Capture — intercept real network packets.

Two backends:
  1. scapy  (preferred, auto-detected)
  2. Raw sockets (fallback, Linux only, requires root)

Run as root / sudo to capture live traffic.
"""

import logging
import threading
import socket
import struct
from typing import Callable, Optional

from .packet import Packet

logger = logging.getLogger("pyrowall.capture")

# Try importing scapy
try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    logger.warning("scapy not installed — falling back to raw socket capture")


class PacketCapture:
    """
    Captures live packets from a network interface and calls a handler function.

    Usage:
        def handler(pkt: Packet):
            action = firewall.process(pkt)

        cap = PacketCapture(interface="eth0", handler=handler)
        cap.start()
        ...
        cap.stop()
    """

    def __init__(
        self,
        interface: str = "eth0",
        handler: Optional[Callable[[Packet], None]] = None,
        bpf_filter: str = "ip",
    ):
        self.interface = interface
        self.handler = handler
        self.bpf_filter = bpf_filter
        self._running = False
        self._thread: Optional[threading.Thread] = None

    def start(self):
        self._running = True
        if SCAPY_AVAILABLE:
            self._thread = threading.Thread(
                target=self._capture_scapy, daemon=True, name="packet-capture"
            )
        else:
            self._thread = threading.Thread(
                target=self._capture_raw, daemon=True, name="packet-capture"
            )
        self._thread.start()
        logger.info("Capture started on %s (scapy=%s)", self.interface, SCAPY_AVAILABLE)

    def stop(self):
        self._running = False
        logger.info("Capture stopped")

    # ------------------------------------------------------------------ #
    # Scapy backend                                                        #
    # ------------------------------------------------------------------ #

    def _capture_scapy(self):
        def _process(scapy_pkt):
            if not self._running:
                return
            pkt = self._scapy_to_packet(scapy_pkt)
            if pkt and self.handler:
                self.handler(pkt)

        sniff(
            iface=self.interface,
            filter=self.bpf_filter,
            prn=_process,
            store=False,
            stop_filter=lambda _: not self._running,
        )

    @staticmethod
    def _scapy_to_packet(sp) -> Optional[Packet]:
        if not sp.haslayer(IP):
            return None

        ip = sp[IP]
        proto = ip.proto

        if sp.haslayer(TCP):
            tcp = sp[TCP]
            flags = _tcp_flags(tcp.flags)
            size = len(sp)
            payload = bytes(sp[Raw]) if sp.haslayer(Raw) else b""
            return Packet(
                src_ip=str(ip.src), dst_ip=str(ip.dst),
                protocol="TCP", src_port=tcp.sport, dst_port=tcp.dport,
                flags=flags, size=size, payload=payload,
            )

        if sp.haslayer(UDP):
            udp = sp[UDP]
            size = len(sp)
            payload = bytes(sp[Raw]) if sp.haslayer(Raw) else b""
            return Packet(
                src_ip=str(ip.src), dst_ip=str(ip.dst),
                protocol="UDP", src_port=udp.sport, dst_port=udp.dport,
                size=size, payload=payload,
            )

        if sp.haslayer(ICMP):
            return Packet(
                src_ip=str(ip.src), dst_ip=str(ip.dst),
                protocol="ICMP", size=len(sp),
            )

        return Packet(
            src_ip=str(ip.src), dst_ip=str(ip.dst),
            protocol=str(proto), size=len(sp),
        )

    # ------------------------------------------------------------------ #
    # Raw socket backend (Linux only)                                      #
    # ------------------------------------------------------------------ #

    def _capture_raw(self):
        try:
            s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
            s.bind((self.interface, 0))
            s.settimeout(1.0)
        except PermissionError:
            logger.error("Raw socket requires root privileges. Run with sudo.")
            return
        except OSError as e:
            logger.error("Cannot open socket on %s: %s", self.interface, e)
            return

        logger.info("Raw socket capture active on %s", self.interface)

        while self._running:
            try:
                raw, _ = s.recvfrom(65535)
                pkt = self._parse_raw(raw)
                if pkt and self.handler:
                    self.handler(pkt)
            except socket.timeout:
                continue
            except Exception as exc:
                logger.debug("Raw capture error: %s", exc)

        s.close()

    @staticmethod
    def _parse_raw(raw: bytes) -> Optional[Packet]:
        """Parse Ethernet frame → IP header → TCP/UDP."""
        if len(raw) < 34:
            return None

        # Skip Ethernet header (14 bytes)
        ip_start = 14
        ip_header = raw[ip_start:ip_start + 20]

        ihl = (ip_header[0] & 0x0F) * 4
        proto = ip_header[9]
        src_ip = socket.inet_ntoa(ip_header[12:16])
        dst_ip = socket.inet_ntoa(ip_header[16:20])
        total_len = struct.unpack("!H", ip_header[2:4])[0]

        transport_start = ip_start + ihl

        if proto == 6:  # TCP
            if len(raw) < transport_start + 20:
                return None
            tcp_hdr = raw[transport_start:transport_start + 20]
            src_port, dst_port = struct.unpack("!HH", tcp_hdr[:4])
            flags_byte = tcp_hdr[13]
            flags = _raw_tcp_flags(flags_byte)
            return Packet(src_ip=src_ip, dst_ip=dst_ip, protocol="TCP",
                          src_port=src_port, dst_port=dst_port, flags=flags, size=total_len)

        if proto == 17:  # UDP
            if len(raw) < transport_start + 8:
                return None
            src_port, dst_port = struct.unpack("!HH", raw[transport_start:transport_start + 4])
            return Packet(src_ip=src_ip, dst_ip=dst_ip, protocol="UDP",
                          src_port=src_port, dst_port=dst_port, size=total_len)

        if proto == 1:  # ICMP
            return Packet(src_ip=src_ip, dst_ip=dst_ip, protocol="ICMP", size=total_len)

        return None


# ------------------------------------------------------------------ #
# Helpers                                                              #
# ------------------------------------------------------------------ #

def _tcp_flags(flags) -> str:
    """Convert scapy TCP flags to string."""
    names = []
    flag_map = {"F": "FIN", "S": "SYN", "R": "RST", "P": "PSH", "A": "ACK"}
    for char, name in flag_map.items():
        if char in str(flags):
            names.append(name)
    return "|".join(names)


def _raw_tcp_flags(byte: int) -> str:
    names = []
    if byte & 0x01: names.append("FIN")
    if byte & 0x02: names.append("SYN")
    if byte & 0x04: names.append("RST")
    if byte & 0x08: names.append("PSH")
    if byte & 0x10: names.append("ACK")
    if byte & 0x20: names.append("URG")
    return "|".join(names)
