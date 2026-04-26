#!/usr/bin/env python3
"""
PyroWall CLI — run, monitor, and test the firewall from the command line.

Usage examples:
  python main.py --simulate          # simulate with test packets (no root needed)
  python main.py --live eth0         # capture live traffic on eth0 (needs sudo)
  python main.py --rules my.rules    # use custom rules file
  python main.py --stats             # run then print stats
  python main.py --list-rules        # print loaded rules
"""

import argparse
import logging
import signal
import sys
import time

# Make sure imports resolve correctly when run from project root
sys.path.insert(0, __file__.rsplit("/", 1)[0] if "/" in __file__ else ".")

from core.firewall import Firewall
from core.packet import Packet
from rules.rule_engine import Action
from logs.event_logger import FirewallLogger


# ------------------------------------------------------------------ #
# Logging setup                                                        #
# ------------------------------------------------------------------ #

def setup_logging(verbose: bool = False):
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s  %(name)-22s  %(levelname)-8s  %(message)s",
        datefmt="%H:%M:%S",
    )


# ------------------------------------------------------------------ #
# Simulation mode                                                      #
# ------------------------------------------------------------------ #

SIMULATION_PACKETS = [
    Packet.tcp("8.8.8.8",       "192.168.1.10", 53,   1024, flags="SYN"),
    Packet.tcp("192.168.1.10",  "1.1.1.1",       1025, 443,  flags="SYN"),
    Packet.tcp("203.0.113.5",   "192.168.1.10",  6543, 22,   flags="SYN"),
    Packet.udp("192.168.1.10",  "8.8.8.8",       5353, 53),
    Packet.icmp("10.0.0.1",     "192.168.1.10"),
    Packet.tcp("192.168.1.20",  "192.168.1.10",  4321, 80,   flags="SYN"),
    Packet.tcp("185.100.87.3",  "192.168.1.10",  9999, 23,   flags="SYN"),  # Telnet
    Packet.tcp("192.168.1.30",  "192.168.1.10",  3333, 445,  flags="SYN"),  # SMB
    Packet.tcp("10.0.0.5",      "192.168.1.10",  4444, 22,   flags="SYN"),  # SSH from LAN → OK
    Packet.udp("192.168.1.10",  "8.8.8.8",       1234, 443),
]


def run_simulation(fw: Firewall, fwlog: FirewallLogger):
    print("\n" + "=" * 65)
    print("  PyroWall — Simulation Mode")
    print("=" * 65)
    print(f"  {'#':<4} {'ACTION':<7} {'PACKET'}")
    print("-" * 65)

    for i, pkt in enumerate(SIMULATION_PACKETS, 1):
        action = fw.process(pkt)
        fwlog.log_event(action.value, pkt)
        symbol = {"ALLOW": "✓", "DENY": "✗", "LOG": "◎"}.get(action.value, "?")
        print(f"  {i:<4} {symbol} {action.value:<6} {pkt}")

    print("=" * 65)
    print("\n  Stats:", fw.stats.summary())
    print(f"  Active connections: {fw.state_table.count()}")


# ------------------------------------------------------------------ #
# Live capture mode                                                    #
# ------------------------------------------------------------------ #

def run_live(fw: Firewall, fwlog: FirewallLogger, interface: str):
    try:
        from core.capture import PacketCapture
    except ImportError:
        print("ERROR: capture module not available.")
        sys.exit(1)

    def handle(pkt: Packet):
        action = fw.process(pkt)
        fwlog.log_event(action.value, pkt)

    cap = PacketCapture(interface=interface, handler=handle)

    def shutdown(sig, frame):
        print("\n\nShutting down...")
        cap.stop()
        fw.stop()
        print("Stats:", fw.stats.summary())
        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    fw.start()
    cap.start()
    print(f"\nPyroWall listening on {interface}  (Ctrl+C to stop)\n")

    while True:
        time.sleep(5)
        s = fw.stats
        print(
            f"\r  seen={s.packets_seen}  allow={s.packets_allowed}  "
            f"deny={s.packets_denied}  conns={fw.state_table.count()}",
            end="",
            flush=True,
        )


# ------------------------------------------------------------------ #
# Main                                                                 #
# ------------------------------------------------------------------ #

def main():
    parser = argparse.ArgumentParser(
        prog="pyrowall",
        description="PyroWall — Python Stateful Firewall",
    )
    parser.add_argument("--simulate",   action="store_true",  help="Run simulation with test packets")
    parser.add_argument("--live",       metavar="IFACE",       help="Live capture on network interface")
    parser.add_argument("--rules",      default="rules/default.rules", help="Rules file path")
    parser.add_argument("--list-rules", action="store_true",  help="Print loaded rules and exit")
    parser.add_argument("--log-file",   default="logs/firewall.log",   help="Event log output file")
    parser.add_argument("--policy",     choices=["allow", "deny"], default="deny",
                        help="Default policy when no rule matches")
    parser.add_argument("--verbose",    action="store_true",  help="Enable debug logging")
    args = parser.parse_args()

    setup_logging(args.verbose)

    default_policy = Action.ALLOW if args.policy == "allow" else Action.DENY
    fw = Firewall(default_policy=default_policy)
    fw.load_rules(args.rules)

    if args.list_rules:
        fw.rule_engine.list_rules()
        return

    fwlog = FirewallLogger(log_file=args.log_file)

    if args.simulate:
        fw.start()
        run_simulation(fw, fwlog)
        fw.stop()
    elif args.live:
        run_live(fw, fwlog, args.live)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
