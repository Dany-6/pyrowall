"""
Firewall Event Logger — writes structured log entries to file and/or console.
"""

import json
import logging
import os
import time
from typing import Optional


class FirewallLogger:
    """
    Structured event logger.

    Logs JSON lines to a file for easy parsing + alerts to console.

    Usage:
        fwlog = FirewallLogger(log_file="logs/firewall.log")
        fwlog.log_event("DENY", packet, rule)
    """

    def __init__(
        self,
        log_file: Optional[str] = "logs/firewall.log",
        log_level: int = logging.INFO,
    ):
        os.makedirs(os.path.dirname(log_file) if log_file and os.path.dirname(log_file) else ".", exist_ok=True)

        self.log_file = log_file
        self._file_handle = open(log_file, "a") if log_file else None

        # Console logger
        self.logger = logging.getLogger("pyrowall.events")
        if not self.logger.handlers:
            handler = logging.StreamHandler()
            handler.setFormatter(
                logging.Formatter("%(asctime)s  %(levelname)-8s  %(message)s", datefmt="%H:%M:%S")
            )
            self.logger.addHandler(handler)
        self.logger.setLevel(log_level)

    def log_event(self, action: str, packet, rule=None):
        """Write one structured event."""
        entry = {
            "ts": round(time.time(), 3),
            "action": action,
            "proto": packet.protocol,
            "src": f"{packet.src_ip}:{packet.src_port}",
            "dst": f"{packet.dst_ip}:{packet.dst_port}",
            "flags": packet.flags,
            "size": packet.size,
            "rule": str(rule) if rule else "default",
        }

        # JSON line to file
        if self._file_handle:
            self._file_handle.write(json.dumps(entry) + "\n")
            self._file_handle.flush()

        # Human-readable console
        msg = (
            f"{action:<6} {packet.protocol:<4} "
            f"{packet.src_ip}:{packet.src_port} → "
            f"{packet.dst_ip}:{packet.dst_port}"
            + (f" [{packet.flags}]" if packet.flags else "")
        )

        if action == "DENY":
            self.logger.warning(msg)
        elif action == "LOG":
            self.logger.info(msg)
        else:
            self.logger.debug(msg)

    def close(self):
        if self._file_handle:
            self._file_handle.close()
