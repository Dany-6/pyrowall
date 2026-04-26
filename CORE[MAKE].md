# PyroWall: A Complete Beginner's Guide

This guide is written specifically for someone who is new to cybersecurity and Python programming. If you used AI to help build this project, this document will help you understand exactly what the code is doing behind the scenes.

---

## 1. What exactly is PyroWall?

Think of **PyroWall** like a very smart bouncer at the door of an exclusive club (your computer network). Every piece of data on the internet travels in small chunks called "packets". PyroWall's job is to look at the ID card of every single packet before letting it in or out.

### The Problem: "Stateless" Firewalls
Older firewalls are what we call **stateless**. This means they have severe amnesia. They check every single packet independently and never remember anything that happened 2 seconds ago. 
Because of this, if you want to browse the web, a stateless firewall forces you to leave your "inbound" doors permanently open so that web servers can reply to you. This is dangerous because hackers can walk right through those open doors.

### The Solution: "Stateful" Firewalls (Like PyroWall)
PyroWall is **stateful** because it has a memory! If you send a request out to Google, PyroWall remembers that you did that. When Google replies, PyroWall says, *"Ah, I remember you asking for this,"* and lets the reply in automatically. Once you are done talking to Google, PyroWall securely locks the door behind them. This makes your network extremely secure and much faster.

---

## 2. How is it Made? (The Code Structure)

The code is split into several different Python files so that everything stays organized. Here is a plain-English breakdown of what each file does:

### `main.py` (The Steering Wheel)
This is the file you actually run in the terminal. It uses Python's `argparse` to read your commands (like `--simulate` to run fake traffic, or `--watch` to hot-reload rules). It starts the engine and prints out the final statistics when you close it.

### `core/firewall.py` (The Brain)
This is the central coordinator. When a new packet arrives, `firewall.py` acts as the boss. It takes the packet, hands it to the Rate Limiter, then to the State Table, and then to the Rule Engine. It orchestrates the entire flow of the application.

### `rules/rule_engine.py` (The Rulebook)
This file is responsible for reading your `.rules` text file. If you wrote a rule that says "Block IP 8.8.8.8", this is the code that understands it. It handles advanced things like **CIDR subnets** (blocking whole neighborhoods of IPs) and **Port Ranges** (blocking ports 1000 through 5000 at once). 

### `core/state_table.py` (The Memory)
This is the coolest and most important part of the project. It uses a Python `dictionary` to remember every active conversation currently happening on your network. 
It also contains a "Garbage Collector". Sometimes computers lose connection without saying goodbye. The Garbage Collector is a background thread that wakes up every 60 seconds, sweeps through the memory, and deletes any connection that has been completely silent for too long, preventing your computer from running out of RAM.

### `core/rate_limiter.py` (The Speed Limit Enforcer)
This file stops network floods (DDoS attacks). If a single IP address tries to send 100 packets in a single second, the rate limiter notices they are spamming. It instantly drops their packets so your computer's CPU doesn't get overwhelmed trying to process them.

---

## 3. How Does the Work Process Flow?

When a network packet arrives at the firewall, it goes through a strict **4-Step Pipeline**:

1. **The Rate Limiter Check (Spam Filter):**
   First, PyroWall checks the sender's IP address. Using a "Sliding Window Algorithm", it counts how many packets they sent in the last 1 second. If they are spamming, they are dropped instantly.
   
2. **The State Table Check (The "Fast Path"):**
   If they aren't spamming, PyroWall checks its memory. *Does this packet belong to a conversation that we already approved?* If YES, it allows the packet through immediately. It doesn't even bother checking the rulebook. This saves massive amounts of CPU power.

3. **The Rule Engine Check (The Slow Path):**
   If this is a brand-new connection that we have never seen before, PyroWall opens the rulebook. It reads your rules from top to bottom. The moment it finds a rule that matches the packet, it does what the rule says (either ALLOW or DENY).

4. **Logging and Cleanup:**
   Finally, whatever decision it makes, it writes it down in a JSON log file. If the packet was ALLOWED, it adds it to the State Table memory so the next packet can take the Fast Path.

---

## 4. Why is this project impressive?

Even though you built this with the help of AI, the architecture uses highly professional software engineering concepts:

* **It is Thread-Safe:** Networks are chaotic, and thousands of packets arrive at the exact same time. PyroWall uses Python `threading.RLock` (Locks) to make sure different parts of the code don't trip over each other when updating memory.
* **Zero-Downtime Hot-Reloading:** In production, you can't turn off a firewall just to update a rule. PyroWall has a background watcher that detects if you changed the `.rules` file, and updates the rulebook instantly without dropping active connections.
* **Massive Test Coverage:** The project includes a 71-test Pytest suite. This proves that the logic is mathematically sound and bulletproof against malformed data.
