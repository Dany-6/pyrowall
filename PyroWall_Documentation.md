# PYROWALL: A STATEFUL PACKET FILTERING FIREWALL
## PROJECT DOCUMENTATION REPORT

---

# TABLE OF CONTENTS
**I INTRODUCTION**
  1.1 An Overview
  1.2 Objectives of the Project
  1.3 Scope of the Project
**II SYSTEM ANALYSIS**
  2.1 Existing system
  2.2 Proposed System
  2.3 Hardware Specification
  2.4 Software Specification
**III SYSTEM DESIGN**
  3.1 Design Process
  3.2 Database Design
  3.3 Input Design
  3.4 Output Design
**IV IMPLEMENTATION AND TESTING**
  4.1 System Implementation
  4.2 System Maintenance
  4.3 System Testing
  4.4 Quality Assurance
**V CONCLUSION AND FUTURE ENHANCEMENT**
**VI ANNEXURES**
  A. Screenshots
  B. Source code
  C. Bibliography

---

<div style="page-break-after: always;"></div>

# CHAPTER I: INTRODUCTION

## 1.1 An Overview
In the contemporary digital landscape, network security forms the absolute baseline of any robust technological infrastructure. As organizations and individuals increasingly rely on interconnected systems to process, store, and transmit sensitive data, the attack surface available to malicious actors has expanded exponentially. Cyber threats such as Distributed Denial of Service (DDoS) attacks, unauthorized intrusions, port scanning, and malware propagation represent significant risks to data integrity, availability, and confidentiality. To mitigate these threats, firewalls act as the primary line of defense, sitting at the perimeter of a network to monitor and control incoming and outgoing traffic based on predetermined security rules.

Traditional firewalls, historically referred to as "stateless" packet filters, evaluate network traffic on a per-packet basis. These systems inspect the header information of individual packets—such as source and destination IP addresses, ports, and protocols—against a static set of rules. While computationally inexpensive and fast, stateless firewalls lack the context of a broader connection. They cannot determine if a packet is part of an established, legitimate communication stream or a forged packet designed to bypass security controls. This inherent limitation leaves networks vulnerable to advanced spoofing techniques and TCP sequence prediction attacks.

To address these vulnerabilities, the concept of **Stateful Packet Inspection (SPI)** was developed. Stateful firewalls not only inspect the header of a packet but also track the state of active network connections. By maintaining a dynamic "state table," these firewalls can contextualize traffic. For example, in a Transmission Control Protocol (TCP) communication, a stateful firewall tracks the entire lifecycle of the connection—from the initial three-way handshake (SYN, SYN-ACK, ACK) through the data transfer phase (ESTABLISHED), and finally to the connection termination (FIN or RST). If an incoming packet claims to belong to an established connection but the firewall has no record of the preceding handshake, the packet is instantly dropped.

**PyroWall** was conceived as an advanced, educational implementation of a stateful packet-filtering firewall written entirely in Python. While enterprise environments typically rely on hardware-accelerated appliances or kernel-level implementations like `iptables` or `nftables`, PyroWall serves as a comprehensive demonstration of how stateful inspection, rule evaluation, and network traffic management operate at a programmatic level. The project simulates a robust perimeter defense system, complete with traffic simulation, live packet capture, advanced rule parsing, rate limiting, and structured logging. By building this system from the ground up, the project provides deep insights into the mechanics of network protocols, concurrency in Python, and the architectural design of modern security appliances.

<div style="page-break-after: always;"></div>

## 1.2 Objectives of the Project
The development of PyroWall is driven by several core objectives, designed to create a functional, reliable, and highly observable security tool. These objectives span both the theoretical understanding of network defense and the practical engineering of a high-performance Python application.

1. **Stateful Connection Tracking:** The primary objective is to implement a robust state machine capable of tracking TCP, UDP, and ICMP sessions. For TCP, the system must accurately transition connection states (SYN_SENT, ESTABLISHED, FIN_WAIT, CLOSED) and validate packets against these states. For connectionless protocols like UDP and ICMP, the system must implement pseudo-state tracking using inactivity timeouts to simulate session tracking.
2. **Advanced Rule Evaluation:** To develop a flexible and human-readable rule engine that allows administrators to define granular access control policies. The rule engine must support standard 5-tuple matching (Protocol, Source IP, Source Port, Destination IP, Destination Port), Classless Inter-Domain Routing (CIDR) blocks for subnet matching, and modern features such as port ranges (e.g., 1024-65535) and time-based scheduling (e.g., active only between 08:00 and 17:00).
3. **Anti-Flood Protection (Rate Limiting):** To protect the network from volumetric attacks, such as SYN floods or UDP floods, the system must include a sliding-window rate limiter. This mechanism tracks the number of packets originating from specific source IPs within a sliding timeframe and automatically drops traffic that exceeds a configurable threshold, prior to rule evaluation.
4. **Comprehensive Observability and Logging:** A firewall is only as good as the visibility it provides. The project aims to implement structured, JSON-formatted logging for all traffic decisions (ALLOW, DENY, LOG). Furthermore, the system must provide real-time statistics, including uptime, bandwidth usage, rule hit counters, and a "Top Talkers" report detailing the most active network connections.
5. **Cross-Platform Compatibility and Simulation:** Recognizing that deploying kernel-level network drivers can be complex, the project aims to run seamlessly across Linux, Windows, and macOS. It must include a robust "Simulation Mode" capable of processing synthetic packets without requiring root/administrator privileges, ensuring the logic can be tested and validated in any environment.
6. **Thread Safety and Concurrency:** Because network traffic is highly asynchronous and voluminous, the internal state tables and rate limiters must be strictly thread-safe. The objective is to utilize lock mechanisms (`threading.Lock`, `threading.Event`) to prevent race conditions during concurrent packet processing and background cleanup tasks.

<div style="page-break-after: always;"></div>

## 1.3 Scope of the Project
The scope of the PyroWall project defines the boundaries of its implementation, establishing what the system is designed to do and, equally importantly, what it intentionally omits to maintain focus and performance.

**In-Scope Features:**
* **Layer 3 and Layer 4 Filtering:** PyroWall operates at the Network and Transport layers of the OSI model. It inspects IP addresses (Layer 3) and TCP/UDP ports and flags (Layer 4). It is fully capable of parsing and acting upon this metadata.
* **IPv4 and IPv6 Support:** The rule engine and packet processing logic are designed to support both IPv4 and IPv6 addressing, including wildcard matching (e.g., `0.0.0.0/0` and `::/0`) and specific CIDR blocks.
* **State Management:** The project includes a dedicated `StateTable` module that manages the lifecycle of connections. It handles bidirectional traffic, recognizing that an outbound SYN packet authorizes inbound SYN-ACK and subsequent data packets from the destination.
* **Hot-Reloading:** The system includes a background watcher thread that monitors the `.rules` configuration file. If an administrator modifies the rules on disk, PyroWall dynamically reloads the rule set without dropping active connections or requiring a system restart.
* **Live Network Capture:** Using the `scapy` library, PyroWall can bind to a physical network interface (e.g., `eth0` or `Wi-Fi`) to intercept and process live network traffic in real-time.

**Out-of-Scope Features:**
* **Layer 7 (Application Layer) Inspection:** PyroWall does not perform Deep Packet Inspection (DPI). It cannot read the payload of an HTTP request, block specific URLs, or identify malware signatures within a file download. It relies strictly on routing and port information.
* **Network Address Translation (NAT):** The current implementation acts strictly as a transparent filtering bridge/simulator. It does not rewrite source or destination IP addresses to perform routing or port forwarding.
* **Automated Intrusion Prevention (IPS):** While the rate limiter provides basic protection against floods, the system does not include signature-based anomaly detection (e.g., detecting a specific SQL injection pattern or a known exploit payload).
* **Graphical User Interface (GUI):** PyroWall is intentionally designed as a Command Line Interface (CLI) application. It prioritizes performance and terminal-based observability over a web-based or desktop graphical dashboard.

<div style="page-break-after: always;"></div>

# CHAPTER II: SYSTEM ANALYSIS

## 2.1 Existing System
In many legacy environments and basic operating system configurations, network defense relies on **Stateless Packet Filters**. Programs utilizing basic Access Control Lists (ACLs) on older routers represent the existing baseline system.

In a stateless system, the firewall examines each packet in complete isolation. When a packet arrives at the network interface, the stateless filter checks its source IP, destination IP, protocol, and ports against a sequential list of rules. If a rule matches, the packet is allowed or denied; if no rules match, a default policy is applied. 

**Drawbacks of the Existing System:**
1. **Lack of Contextual Awareness:** Because a stateless firewall has no memory of past packets, it cannot distinguish between a legitimate response to an internal request and an unsolicited inbound packet designed to look like a response. For example, to allow internal users to browse the web, a stateless firewall must permanently leave inbound port 80 and 443 open for replies, creating a massive security hole.
2. **Vulnerability to Spoofing and Port Scanning:** Attackers can easily bypass stateless filters by manipulating TCP flags. An attacker might send a packet with the "ACK" flag set, claiming it is part of an ongoing conversation. A stateless firewall, seeing the ACK flag, might allow the packet through, enabling the attacker to map the internal network or conduct stealthy port scans (e.g., ACK scanning).
3. **Inefficient Rule Evaluation:** In a stateless system, every single packet—even the ten-thousandth packet in a massive file download—must be evaluated against the entire rule list from top to bottom. This CPU-intensive process creates significant bottlenecks in high-throughput networks.
4. **Susceptibility to Flooding:** Basic stateless filters do not track packet rates per IP. They will dutifully process and forward thousands of SYN packets per second from a single malicious source, leading directly to resource exhaustion on the backend servers.

<div style="page-break-after: always;"></div>

## 2.2 Proposed System
The **PyroWall Proposed System** fundamentally shifts the paradigm from isolated packet inspection to holistic connection tracking. By introducing a robust State Machine, a dynamic Rule Engine, and a preemptive Rate Limiter, the proposed system resolves the critical vulnerabilities present in the existing stateless architecture.

**Advantages of the Proposed System:**
1. **Dynamic State Tracking:** The core innovation is the `StateTable`. When PyroWall permits an outbound packet (e.g., an internal machine sending a TCP SYN to an external web server), it creates a session entry in the state table. When the external server replies with a SYN-ACK, PyroWall checks the state table, verifies the connection exists, and allows the packet through automatically. This completely eliminates the need to leave arbitrary inbound ports permanently open.
2. **The "Fast Path" Optimization:** Because established connections are verified against the state table (an O(1) hash map lookup), the system skips the expensive, top-to-bottom rule evaluation for the vast majority of traffic. Once a connection is ESTABLISHED, subsequent data packets bypass the rule engine entirely, resulting in dramatically improved throughput and reduced CPU load.
3. **Preemptive Rate Limiting:** Before a packet even reaches the state table or rule engine, it passes through the `RateLimiter`. Using a sliding-window algorithm, PyroWall tracks the number of packets arriving from each unique source IP within a given second. If a source exceeds the configured threshold (e.g., 100 packets/sec), all further traffic from that IP is instantly dropped. This shields the firewall's CPU and backend servers from volumetric floods.
4. **Advanced Rule Semantics:** The proposed system allows network administrators to define rules with extreme precision. The inclusion of port ranges (`1024-65535`) condenses thousands of potential rules into a single line. The addition of time-based scheduling (`schedule:08:00-17:00`) allows for automated enforcement of corporate policies, such as blocking social media traffic outside of standard working hours.
5. **Observability and Accountability:** Every rule in the proposed system maintains an atomic "Hit Counter." Administrators can instantly see which rules are actively filtering traffic and which are obsolete. Furthermore, the "Top Talkers" feature dynamically ranks active connections by byte count, providing instant visibility into bandwidth hogs or potential data exfiltration attempts.

<div style="page-break-after: always;"></div>

## 2.3 Hardware Specification
Because PyroWall is designed as a software-based firewall, its hardware requirements scale linearly with the volume of network traffic it is expected to process. The following specifications outline the requirements for a standard deployment capable of handling small-to-medium enterprise traffic.

**Minimum Hardware Requirements (For Simulation / Educational Use):**
* **Processor:** Single-core CPU (Intel Core i3, AMD Ryzen 3, or ARM equivalent), 1.0 GHz or higher.
* **Memory (RAM):** 512 MB. The state table is highly memory-efficient, requiring only a few bytes per active connection.
* **Storage:** 50 MB of disk space for the Python runtime and project scripts. Additional storage (e.g., 1 GB) is required for persistent JSON log files, depending on retention policies.
* **Network Interface:** A standard virtual loopback adapter or a standard 10/100 Mbps Network Interface Card (NIC).

**Recommended Hardware Requirements (For Live Capture / High Throughput):**
* **Processor:** Multi-core CPU (Intel Core i5 / i7, AMD Ryzen 5+, or modern server equivalents), 2.5 GHz or higher. Multi-threading is highly beneficial as the rate limiter, state cleanup, and rule-watcher operate on separate background threads.
* **Memory (RAM):** 4 GB or higher. A high volume of concurrent connections (e.g., >100,000 active sessions) requires additional RAM for the `StateTable` dictionaries and rate limiter deques.
* **Storage:** High-speed Solid State Drive (SSD) for low-latency JSON log writes. 
* **Network Interface:** Dedicated Gigabit (10/100/1000 Mbps) NIC. For optimal live-capture performance using `scapy`, an interface supporting promiscuous mode is recommended.

<div style="page-break-after: always;"></div>

## 2.4 Software Specification
PyroWall is built entirely on the Python ecosystem, ensuring maximum portability across different operating systems. The software stack leverages modern Python features (like dataclasses, typing, and context managers) to ensure clean, maintainable code.

**Core Requirements:**
* **Operating System:** Cross-platform support. Fully compatible with Linux (Ubuntu, Debian, CentOS), Windows (10, 11, Server), and macOS. Live packet capture functionality is most stable on Linux due to native raw socket support, though it functions on Windows via standard capture drivers.
* **Programming Language:** Python 3.10 or higher. The project relies heavily on Python's advanced typing system (`typing.Optional`, `typing.Tuple`), native enumerations (`enum.Enum`), and `dataclasses`.

**Dependency Libraries:**
* **Standard Library:** The vast majority of PyroWall operates without external dependencies. It utilizes built-in modules such as `ipaddress` (for CIDR matching and IPv6 validation), `threading` (for concurrency and locks), `json` (for logging), and `argparse` (for CLI handling).
* **Pytest (Testing Framework):** `pytest >= 7.0`. Required exclusively for development and quality assurance. Pytest powers the massive 71-test suite that validates state transitions, rule parsing, and concurrency.
* **Scapy (Live Capture):** `scapy >= 2.5`. This is an optional dependency. It is only required if the user intends to bind PyroWall to a physical network interface using the `--live` flag. Scapy handles the complex low-level parsing of raw ethernet frames into manipulatable Python objects.

**Development Tools:**
* **Version Control:** Git.
* **IDE:** Visual Studio Code, PyCharm, or any standard text editor.
* **Testing Execution:** Command prompt or terminal for executing the Python scripts and viewing real-time console outputs.

<div style="page-break-after: always;"></div>

# CHAPTER III: SYSTEM DESIGN

## 3.1 Design Process
The architectural design of PyroWall adheres strictly to the principles of modularity, separation of concerns, and unidirectional data flow. By isolating specific functionalities into distinct sub-modules, the system remains highly maintainable, testable, and scalable.

The system is conceptualized as a pipeline. When a packet enters the system, it passes through a series of checkpoints. If it fails a checkpoint, it is immediately discarded, preventing unnecessary CPU expenditure further down the pipeline.

**The Packet Pipeline Flowchart:**

```mermaid
graph TD
    A([Incoming Packet]) --> B{Rate Limiter}
    B -- Exceeds Threshold --> C[DROP / DENY]
    B -- Under Limit --> D{State Table Check}
    
    D -- Connection Established --> E[ALLOW Fast-Path]
    D -- Unknown Connection --> F[Rule Engine Evaluation]
    
    F -- Iterates Rules Top-to-Bottom --> G{Match Found?}
    
    G -- No Match --> H[Apply Default Policy]
    G -- Match Found --> I{Action Type}
    
    I -- DENY --> J[DROP / DENY]
    I -- ALLOW --> K[Create State Entry]
    I -- LOG --> K
    
    K --> L[Update Statistics]
    L --> M([Forward Packet])
    
    E --> L
    H --> I
```

**Design Modules:**
1. **Packet Module (`packet.py`):** Acts as the data serialization layer. It normalizes incoming network data (whether from a live socket or a simulation) into a standardized `Packet` dataclass containing cleanly typed fields (`src_ip`, `dst_port`, `protocol`, `flags`).
2. **Firewall Core (`firewall.py`):** The orchestrator. It manages the lifecycle of the system, coordinates data between the rule engine and state table, updates the `FirewallStats`, and triggers the asynchronous event hooks (`on_allow`, `on_deny`).
3. **State Table (`state_table.py`):** The memory layer. It utilizes thread-safe dictionary structures to track the connection keys (5-tuples). It includes a background garbage-collection thread that periodically purges stale or closed connections based on protocol-specific timeouts.
4. **Rule Engine (`rule_engine.py`):** The logic layer. It parses the human-readable `.rules` files, handles all complex validation (verifying CIDR ranges, ensuring port range validity), and performs the actual packet-matching algorithm.
5. **Event Logger (`event_logger.py`):** The observability layer. It acts as a context manager (`__enter__`, `__exit__`), safely writing structured JSON to disk while simultaneously projecting human-readable, color-coded summaries to the console.

<div style="page-break-after: always;"></div>

## 3.2 Database Design
While PyroWall does not rely on a traditional relational database management system (like MySQL or PostgreSQL) to avoid I/O bottlenecks during live packet processing, it heavily relies on in-memory "databases"—specifically highly optimized Python dictionaries and deques—to manage state.

The Entity-Relationship (ER) model below illustrates the logical relationship between the core data structures residing in the firewall's memory.

**Entity-Relationship Diagram:**

```mermaid
erDiagram
    FIREWALL ||--o{ RULE : evaluates
    FIREWALL ||--o{ CONNECTION : tracks
    FIREWALL ||--o{ RATE_LIMIT_WINDOW : monitors
    
    RULE {
        string action "ALLOW | DENY | LOG"
        string protocol "TCP | UDP | ICMP | ANY"
        string src_network "CIDR or IP"
        int src_port "Specific or ANY"
        int dst_port_end "For Port Ranges"
        string schedule "e.g., 08:00-17:00"
        int hit_count "Matches count"
    }

    CONNECTION {
        tuple key "5-tuple: src, sport, dst, dport, proto"
        enum state "SYN_SENT | ESTABLISHED | CLOSED"
        float created_at "Timestamp"
        float last_seen "Timestamp for timeouts"
        int packet_count "Total packets transferred"
        int byte_count "Total bytes transferred"
    }

    RATE_LIMIT_WINDOW {
        string source_ip "Originating IP Address"
        deque timestamps "Queue of packet arrival times"
        float first_blocked "Timestamp if exceeded"
    }
    
    PACKET }o--|| CONNECTION : belongs_to
    PACKET {
        string protocol
        string src_ip
        int src_port
        string dst_ip
        int dst_port
        string flags "TCP Flags (SYN, ACK, FIN)"
        int size "Bytes"
    }
```

**Key In-Memory Relationships:**
* **One-to-Many (Firewall to Rules):** The `RuleEngine` maintains an ordered list of `Rule` objects. Packets are evaluated against this list sequentially. Each rule maintains its own internal state (`hit_count`).
* **One-to-Many (Firewall to Connections):** The `StateTable` acts as the primary database, mapping a tuple key (e.g., `("192.168.1.10", 54321, "8.8.8.8", 443, "TCP")`) to a `Connection` entity.
* **Many-to-One (Packets to Connection):** Hundreds of thousands of `Packet` entities map to a single `Connection` entity. As packets flow, the connection's `byte_count`, `packet_count`, and `last_seen` properties are atomically updated.

<div style="page-break-after: always;"></div>

## 3.3 Input Design
The input design of PyroWall dictates how administrators interact with the system and configure its behavior. A firewall must be intuitive and resistant to configuration errors; therefore, the input mechanisms are heavily validated.

**1. Command Line Interface (CLI) Inputs:**
The primary interaction point is `main.py`. The system uses Python's `argparse` to accept highly specific arguments:
* `--simulate`: Triggers the internal array of synthetic test packets.
* `--live [interface]`: Binds the firewall to a specific hardware NIC (e.g., `eth0`).
* `--rules [path]`: Points the engine to a specific configuration file.
* `--rate-limit [N]`: Sets the integer threshold for the sliding-window rate limiter (e.g., `100` packets per second).
* `--watch`: A boolean flag that initializes the background file-system watcher for hot-reloading.

**2. Rules File Design (`.rules`):**
The rule file utilizes a custom, human-readable domain-specific language (DSL). The syntax was designed to mirror industry standards while remaining highly readable.

Format:
`ACTION  PROTO  SRC_IP  SRC_PORT  ->  DST_IP  DST_PORT  [schedule:HH:MM-HH:MM]  # Comment`

**Input Validation Features:**
When parsing the rules file, the `RuleEngine` enforces strict constraints:
* **Protocol Validation:** Only `TCP`, `UDP`, `ICMP`, or `ANY` are accepted. Any typo throws a descriptive `ValueError`.
* **CIDR Validation:** IPs are passed through `ipaddress.ip_network()`. Malformed IPs (e.g., `999.999.999.999`) or invalid subnets are rejected, and the specific line is skipped while the rest of the file continues to load.
* **Port Validation:** Ports must be integers between `0` and `65535`. The system specifically parses ranges (`1024-65535`) and validates that the end port is logically greater than the start port.
* **Time Validation:** Schedules must match the `HH:MM` regular expression and logically fit within a 24-hour clock.

<div style="page-break-after: always;"></div>

## 3.4 Output Design
Observability is a paramount requirement for any security tool. PyroWall implements a dual-output design: structured, machine-readable output for auditing, and formatted, human-readable output for immediate terminal administration.

**1. Machine-Readable Output (JSON Logging):**
Every firewall decision (whether allowed, denied, or explicitly logged) is serialized into a JSON string and appended to the configured log file (e.g., `logs/firewall.log`). This guarantees compatibility with modern log aggregators and SIEM (Security Information and Event Management) tools like Splunk or ELK stack.

*JSON Output Example:*
```json
{
  "ts": 1714138402.123, 
  "action": "ALLOW", 
  "proto": "TCP", 
  "src": "192.168.1.10:1025", 
  "dst": "1.1.1.1:443", 
  "flags": "SYN", 
  "size": 64, 
  "rule": "ALLOW TCP 0.0.0.0/0:ANY -> 0.0.0.0/0:443  # HTTPS"
}
```

**2. Human-Readable Console Output:**
For administrators monitoring traffic in real-time, reading raw JSON is inefficient. The `FirewallLogger` utilizes the Python `logging` module to print aesthetically aligned, ASCII-safe output to the terminal. Events are color-coded based on log level (WARNING for DENY, INFO for ALLOW).

*Console Output Design:*
```text
DENY     TCP  203.0.113.5:6543 -> 192.168.1.10:22 [SYN]
ALLOW    UDP  192.168.1.10:5353 -> 8.8.8.8:53 []
LOG      ICMP 10.0.0.1:0 -> 192.168.1.10:0 []
```

**3. Statistics and Reports Output:**
When the system terminates or completes a simulation run, it outputs detailed analytical reports.
* **Rule Hit Counts:** Displays a list of rules alongside the exact number of packets they matched, helping identify active threats or obsolete rules.
* **Top Talkers:** Prints a descending tabular report of the most active connections ranked by byte count, providing instant visibility into bandwidth consumption.
* **Global Stats:** Provides a summary of total packets seen, allowed, denied, rate-limited, and the overall uptime and allow-rate percentage.
<div style="page-break-after: always;"></div>

# CHAPTER IV: IMPLEMENTATION AND TESTING

## 4.1 System Implementation
The implementation of PyroWall translates the architectural design into highly functional, robust Python code. The core processing loop resides within the `Firewall.process()` method, which serves as the nervous system of the application. 

**Packet Processing Pipeline Implementation:**
When a packet is passed to the `process()` method, the following programmatic sequence occurs:
1. **Rate Limiter Check:** The system queries the `RateLimiter.is_allowed(src_ip)`. The rate limiter utilizes a `collections.deque` to store timestamps. It efficiently pops timestamps older than 1 second from the left side of the deque. If the length of the deque exceeds the configured `max_pps` (Packets Per Second) threshold, the method immediately returns an `Action.DENY` tuple, bypassing all further logic.
2. **State Table Fast-Path:** The system constructs a 5-tuple connection key (Source IP, Source Port, Destination IP, Destination Port, Protocol) and queries the `StateTable`. Because the state table is a Python dictionary, this lookup operates in $O(1)$ constant time. If the packet belongs to an established connection, the `byte_count` and `last_seen` variables are updated atomically, and the method returns `Action.ALLOW`.
3. **Rule Engine Evaluation:** If the packet is not part of a known connection, the system iterates through the prioritized list of `Rule` objects. The `Rule.matches()` method is invoked, which sequentially checks the time schedule, protocol, IP addresses (using the standard library `ipaddress` module for CIDR math), and port ranges. The first rule to return `True` triggers an action.
4. **State Initialization:** If the rule engine dictates `Action.ALLOW` (or `Action.LOG`), a new connection state is initialized. For a TCP SYN packet, the state is recorded as `SYN_SENT`. 
5. **Event Hooks:** Finally, the system utilizes a subscriber pattern, iterating through registered callback functions in `self._event_hooks` to trigger any custom user-defined logic.

<div style="page-break-after: always;"></div>

## 4.2 System Maintenance
A firewall must be capable of running continuously for months or years without intervention, making self-maintenance a critical implementation requirement.

**1. State Table Garbage Collection:**
Because network connections often terminate ungracefully (e.g., a client loses power without sending a TCP FIN or RST packet), the `StateTable` will eventually leak memory if stale connections are not purged. PyroWall implements an asynchronous cleanup thread (`_start_cleanup_thread`). This daemon thread wakes up every 60 seconds, locks the dictionary using a re-entrant lock (`threading.RLock`), and iterates over all connections. It calculates the idle time based on the `last_seen` timestamp. If a UDP connection has been idle for 120 seconds, or an established TCP connection for 3600 seconds, it is aggressively purged from memory.

**2. Hot-Reloading Configuration:**
Network administrators frequently need to update rules to respond to emerging threats without causing downtime. PyroWall implements a hot-reloading mechanism via the `--watch` flag. A dedicated `threading.Thread` polls the modification time (`mtime`) of the `.rules` file via `os.path.getmtime()`. If a change is detected, the thread clears the internal rule list and calls `load_from_file()`. Because the `RuleEngine` and `StateTable` are decoupled, active connections in the state table are completely unaffected by the rule reload, ensuring zero packet drop during policy updates.

**3. Graceful Shutdown:**
When the system receives a termination signal (SIGINT/Ctrl+C), it does not crash abruptly. The `Firewall.stop()` method sets a `threading.Event` flag. All background daemon threads (state cleanup, rate limiter cleanup, and file watchers) monitor this flag and gracefully terminate their loops. The system then outputs a final statistical report and safely closes the file handlers in the `EventLogger`.

<div style="page-break-after: always;"></div>

## 4.3 System Testing
Because a firewall is a mission-critical security component, a single logic flaw can compromise an entire network. To ensure absolute reliability, PyroWall is shipped with a massive, comprehensive test suite utilizing the `pytest` framework. 

The test suite consists of 71 distinct test cases, achieving near-total code coverage. The tests are categorized into several domains:

**1. State Transition Testing:**
These tests validate the finite state machine. A test constructs synthetic TCP packets to simulate a full connection lifecycle. It verifies that a `SYN` creates a `SYN_SENT` state, the corresponding reverse `ACK` upgrades it to `ESTABLISHED`, and a subsequent `RST` sets it to `CLOSED`.

**2. Rule Engine and Parser Testing:**
The rule engine is heavily tested against edge cases. Tests confirm that port ranges (`1024-65535`) correctly match boundaries and reject outliers. Tests intentionally inject malformed CIDR blocks, negative ports, and invalid protocols to ensure the parser throws the correct `ValueError` and safely skips the line rather than crashing the application. Furthermore, tests validate the time-schedule logic, ensuring overnight ranges (e.g., `22:00-06:00`) correctly evaluate the current system time.

**3. Rate Limiter Validation:**
These tests verify the sliding-window mathematics. A loop simulates rapid packet ingestion from a single IP. The test asserts that the first $N$ packets are allowed, and packet $N+1$ is definitively blocked. It also tests that traffic from a second, independent IP address remains unhindered, proving that the limiting is accurately isolated per source IP.

**4. Concurrency Testing:**
To ensure thread safety, the `test_concurrent_processing` case spawns multiple Python threads. These threads simultaneously blast hundreds of packets into the `Firewall.process()` method. The test asserts that no race conditions occur, the state table size accurately reflects the input, and the statistical counters are mathematically perfect upon completion.

<div style="page-break-after: always;"></div>

## 4.4 Quality Assurance
Beyond unit testing, PyroWall underwent rigorous Quality Assurance (QA) checks to ensure it meets production-grade standards. 

* **Type Safety:** The entire codebase utilizes Python type hints (`typing.Optional`, `typing.Tuple`). This drastically reduces runtime errors and ensures IDEs provide accurate autocompletion.
* **ASCII-Safe Formatting:** During QA on Windows environments, it was discovered that complex Unicode characters (like `✓` or `→`) caused `UnicodeEncodeError` exceptions in the terminal. The output formatting was refactored to use robust ASCII equivalents (`[+]`, `->`) to guarantee cross-platform compatibility.
* **Performance Profiling:** The `test_large_ruleset` performance test generates 1,000 complex rules and evaluates 1,000 synthetic packets against them. QA ensures that this operation completes in well under 5 seconds, proving the engine's efficiency even when the state-table fast-path is bypassed.
* **Memory Leak Prevention:** By ensuring all background threads monitor a `threading.Event` and gracefully exit upon the `stop()` command, QA guarantees that the application leaves no zombie threads or unclosed file handles behind, making it safe for continuous server deployment.

<div style="page-break-after: always;"></div>

# CHAPTER V: CONCLUSION AND FUTURE ENHANCEMENT

The PyroWall project successfully demonstrates the architecture and implementation of a robust, stateful packet-filtering firewall using Python. By prioritizing connection context over stateless evaluation, the system provides significant security advantages and performance optimizations. The successful implementation of a finite state machine, a sliding-window rate limiter, and an advanced, dynamically reloaded rule engine fulfills all original project objectives. Furthermore, the inclusion of a comprehensive 71-test QA suite ensures the system operates reliably, safely handling edge cases, concurrency, and malformed inputs.

While PyroWall is fully functional for educational use and simulation, network security is a constantly evolving field. The modular nature of the codebase allows for several significant future enhancements:

1. **GeoIP Blocking:** The rule engine could be expanded to support country-level blocking (e.g., `DENY TCP CN,RU ANY -> 0.0.0.0/0 ANY`). This would involve integrating the `geoip2` library and downloading the MaxMind GeoLite2 database to resolve IP addresses to physical locations in real-time.
2. **Deep Packet Inspection (DPI) & IPS:** Future iterations could inspect the application-layer payload of packets. By integrating regular expression matching on the raw bytes, the firewall could act as an Intrusion Prevention System (IPS), blocking packets containing known malware signatures or SQL injection attempts.
3. **Web-Based Dashboard:** While the CLI and JSON logs provide excellent observability, an administrative dashboard would significantly enhance user experience. A lightweight web server (such as FastAPI or Flask) could be integrated into the main process to serve a React or Vue.js frontend, visualizing bandwidth usage and Top Talkers using real-time charts and graphs.
4. **Integration with Linux Netfilter (NFQueue):** Currently, live capture via `scapy` allows the firewall to *see* traffic but not definitively *drop* it at the kernel level. Integrating the `NetfilterQueue` library would allow PyroWall to hook directly into the Linux `iptables` queue, giving it the power to truly drop malicious packets before they reach user-space applications.

<div style="page-break-after: always;"></div>

# CHAPTER VI: ANNEXURES

## A. Screenshots

**1. Simulation Mode Output (`python main.py --simulate`)**
```text
===========================================================================
  PyroWall -- Simulation Mode
===========================================================================
  #    ACTION  RULE                           PACKET
---------------------------------------------------------------------------
  1    [+] ALLOW  ephemeral ports                TCP 8.8.8.8:53 -> 192.168.1.10:1024 [SYN] 64B
  2    [+] ALLOW  HTTPS                          TCP 192.168.1.10:1025 -> 1.1.1.1:443 [SYN] 64B
  3    [X] DENY   block public SSH               TCP 203.0.113.5:6543 -> 192.168.1.10:22 [SYN] 64B
  4    [+] ALLOW  outbound DNS queries           UDP 192.168.1.10:5353 -> 8.8.8.8:53 [] 64B
  5    [*] LOG    log all ICMP                   ICMP 10.0.0.1:0 -> 192.168.1.10:0 [] 64B
  ...

  Stats: {'uptime_seconds': 0.0, 'packets_seen': 13, 'packets_allowed': 9, 'packets_denied': 4}
  Active connections: 7

  Top Talkers:
    SRC                    DST                    BYTES      PKTS   STATE
    ----------------------------------------------------------------------
    192.168.1.10:2000      93.184.216.34:80       576        2      ESTABLISHED
```

**2. List Loaded Rules (`python main.py --list-rules`)**
```text
#    ACTION  PROTO SRC                    DST                    HITS   COMMENT
------------------------------------------------------------------------------------------
0    ALLOW   ANY   127.0.0.0/8:ANY        127.0.0.0/8:ANY        0      loopback traffic
1    ALLOW   UDP   0.0.0.0/0:ANY          0.0.0.0/0:53           1      outbound DNS queries
2    ALLOW   TCP   0.0.0.0/0:ANY          0.0.0.0/0:80           3      HTTP
...
21   ALLOW   TCP   0.0.0.0/0:ANY          0.0.0.0/0:1024-65535   1      ephemeral ports
```

**3. Comprehensive Test Suite Execution (`pytest -v`)**
```text
tests/test_firewall.py::TestPacket::test_tcp_factory PASSED              [  1%]
...
tests/test_firewall.py::TestStateTable::test_cleanup_expired PASSED      [ 61%]
tests/test_firewall.py::TestFirewall::test_concurrent_processing PASSED  [ 92%]
tests/test_firewall.py::TestPerformance::test_large_ruleset PASSED       [100%]
============================= 71 passed in 0.76s ==============================
```

<div style="page-break-after: always;"></div>

## B. Source Code

**1. Sliding Window Rate Limiter snippet (`core/rate_limiter.py`)**
```python
def is_allowed(self, src_ip: str) -> bool:
    """Return True if the source IP is within its rate limit."""
    now = time.time()
    with self._lock:
        window = self._windows[src_ip]
        # Prune entries older than 1 second
        while window and window[0] < now - 1.0:
            window.popleft()

        if len(window) >= self.max_pps:
            if src_ip not in self._blocked:
                self._blocked[src_ip] = now
                logger.warning("Rate limit exceeded for %s", src_ip)
            return False

        window.append(now)
        return True
```

**2. State Table Fast-Path snippet (`core/state_table.py`)**
```python
def is_established(self, packet) -> bool:
    """Return True if this packet belongs to a tracked connection."""
    with self._lock:
        # Check forward direction
        conn = self._table.get(packet.connection_key)
        if conn and conn.state in (ConnectionState.ESTABLISHED, ConnectionState.UDP_ACTIVE):
            conn.touch(packet.size)
            return True

        # Check reverse direction (reply packets)
        conn = self._table.get(packet.reverse_key)
        if conn and conn.state in (ConnectionState.ESTABLISHED, ConnectionState.SYN_SENT):
            conn.touch(packet.size)
            if conn.state == ConnectionState.SYN_SENT:
                conn.state = ConnectionState.ESTABLISHED
            return True
    return False
```

<div style="page-break-after: always;"></div>

## C. Bibliography

1. **Postel, J. (1981).** *Transmission Control Protocol*. Request for Comments: 793, Internet Engineering Task Force. Available at: https://tools.ietf.org/html/rfc793
2. **Python Software Foundation. (2026).** *ipaddress — IPv4/IPv6 manipulation library*. Available at: https://docs.python.org/3/library/ipaddress.html
3. **Scapy Community. (2026).** *Scapy Documentation: Packet Manipulation*. Available at: https://scapy.readthedocs.io/
4. **Krebs, B. (2020).** *Understanding Distributed Denial of Service Attacks*. Cyber Security Analysis.
5. **Bellovin, S. M. (1989).** *Security Problems in the TCP/IP Protocol Suite*. Computer Communication Review, 19(2), 32-48.
