# 🔥 PyroWall — Python Stateful Firewall

A fully functional stateful packet-filtering firewall built in pure Python, written as a cybersecurity learning project.

---

## Features

- **Stateful inspection** — tracks TCP connections (SYN -> ESTABLISHED -> FIN), UDP, and ICMP sessions
- **Rule engine** — human-readable `.rules` file format with ALLOW / DENY / LOG actions
- **Advanced rules** — supports port ranges (e.g. `1024-65535`) and time-based schedules (e.g. `schedule:22:00-06:00`)
- **CIDR matching** — match source/destination IPs against network ranges (e.g. `192.168.0.0/16` and IPv6 `::/0`)
- **Rate limiting** — sliding-window anti-flood protection per source IP
- **Hot-reloading** — auto-reloads rules without restarting the firewall
- **Live capture** — intercept real traffic via `scapy` or raw sockets (root required)
- **Simulation mode** — test rules against synthetic packets without any network access
- **Event hooks** — register Python callbacks on firewall events (`deny`, `allow`, `log`)
- **Structured logging** — JSON-line log file with matched rule attribution for easy parsing
- **Full test suite** — 70+ pytest unit and integration tests

---

## Project Structure

```
pyrowall/
├── core/
│   ├── firewall.py        # Main Firewall class — orchestrates everything
│   ├── packet.py          # Packet dataclass + factory methods
│   ├── rate_limiter.py    # Sliding-window rate limiter
│   ├── state_table.py     # Stateful connection tracking + top talkers
│   └── capture.py         # Live packet capture (scapy / raw socket)
├── rules/
│   ├── rule_engine.py     # Rule parser, matcher, evaluator
│   └── default.rules      # Default ruleset
├── logs/
│   └── event_logger.py    # JSON + console structured logging
├── tests/
│   └── test_firewall.py   # Full pytest test suite
├── main.py                # CLI entry point
└── requirements.txt
```

---

## Quick Start

### 1. Clone & install

```bash
git clone https://github.com/Dany-6/pyrowall.git
cd pyrowall
pip install pytest          # required for tests
pip install scapy           # optional — only for live capture
```

### 2. Run simulation (no root needed)

```bash
python main.py --simulate
```

Output:
```
===========================================================================
  PyroWall -- Simulation Mode
===========================================================================
  #    ACTION  RULE                           PACKET
---------------------------------------------------------------------------
  1    [+] ALLOW  ephemeral ports                TCP 8.8.8.8:53 -> 192.168.1.10:1024 [SYN] 64B
  2    [+] ALLOW  HTTPS                          TCP 192.168.1.10:1025 -> 1.1.1.1:443 [SYN] 64B
  3    [X] DENY   block public SSH               TCP 203.0.113.5:6543 -> 192.168.1.10:22 [SYN] 64B
  ...
```

### 3. Run the test suite

```bash
python -m pytest tests/ -v
```

### 4. List loaded rules

```bash
python main.py --list-rules
```

### 5. Live capture (needs root / sudo)

```bash
sudo python main.py --live eth0
```

Replace `eth0` with your network interface (check with `ip a` or `ifconfig`).

### 6. Use a custom rules file

```bash
python main.py --simulate --rules rules/default.rules
```

---

## Rules File Format

```
# ACTION  PROTO  SRC_IP      SRC_PORT  ->  DST_IP      DST_PORT  [schedule:HH:MM-HH:MM] # comment
ALLOW     TCP    0.0.0.0/0   ANY       ->  0.0.0.0/0   443                              # HTTPS
DENY      TCP    0.0.0.0/0   ANY       ->  0.0.0.0/0   23                               # Telnet
LOG       ICMP   0.0.0.0/0   ANY       ->  0.0.0.0/0   ANY                              # ping
ALLOW     TCP    0.0.0.0/0   ANY       ->  0.0.0.0/0   1024-65535                       # port ranges
DENY      TCP    0.0.0.0/0   ANY       ->  0.0.0.0/0   80        schedule:22:00-06:00   # time-based
DENY      ANY    0.0.0.0/0   ANY       ->  0.0.0.0/0   ANY                              # default deny
```

| Field    | Values                              |
|----------|-------------------------------------|
| ACTION   | `ALLOW`, `DENY`, `LOG`              |
| PROTO    | `TCP`, `UDP`, `ICMP`, `ANY`         |
| IP       | `x.x.x.x`, `x.x.x.x/CIDR`, `::/0`, `ANY` |
| PORT     | integer (e.g. `443`), range (e.g. `1024-65535`), or `ANY` |
| SCHEDULE | optional, `schedule:HH:MM-HH:MM`    |

Rules are evaluated **top-to-bottom**. First match wins.

---

## Programmatic Usage

```python
from core.firewall import Firewall
from core.packet import Packet
from rules.rule_engine import Action

fw = Firewall(default_policy=Action.DENY)
fw.load_rules("rules/default.rules")
fw.start()

# Process a synthetic packet
packet = Packet.tcp("1.2.3.4", "5.6.7.8", 12345, 443, flags="SYN")
action, rule = fw.process(packet)
print(action)  # Action.ALLOW

# Register a hook on denied packets
fw.on("deny", lambda pkt, rule: print(f"Blocked: {pkt}"))
```

---

## How It Works

```
Incoming Packet
      │
      ▼
  State Table ──── Already established? ──→ ALLOW (fast path)
      │ No
      ▼
  Rule Engine ──── Match rules top-down ──→ ALLOW / DENY / LOG
      │
      ▼
  Update state (if ALLOW) + Log event
```

1. **Packet arrives** → parsed into a `Packet` object (src/dst IP, port, protocol, TCP flags)
2. **State check** → if this 5-tuple matches an established connection, allow immediately
3. **Rule evaluation** → walk rules in priority order; first match returns the action
4. **State update** → allowed TCP SYN packets are added to the state table
5. **Logging** → every event written to JSON log file

---

## CLI Reference

| Flag | Description |
|------|-------------|
| `--simulate` | Run test packets through the firewall (no root) |
| `--live IFACE` | Capture live traffic on interface (needs sudo) |
| `--rules FILE` | Path to custom rules file |
| `--list-rules` | Print all loaded rules and exit |
| `--policy allow\|deny` | Default policy when no rule matches |
| `--log-file FILE` | Output log file path |
| `--rate-limit N` | Max packets/sec per source IP (0=disabled) |
| `--watch` | Watch rules file for changes and auto-reload |
| `--verbose` | Enable debug logging |

---

## Requirements

- Python 3.10+
- `pytest` for running tests
- `scapy` (optional) for live packet capture

---

## Disclaimer

This is an educational project. Do not use as your only line of network defence. For production environments, use established tools like `iptables`, `nftables`, `pf`, or commercial firewalls.

---

## License

MIT License — free to use, modify, and distribute.
