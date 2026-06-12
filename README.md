# Network Packet Analyzer

A Python tool that captures and parses **real** network packets using Scapy.
Built as part of my cybersecurity learning — replacing an earlier simulation-based
version that used random data instead of actual traffic.

> ⚠️ **Legal notice:** Only run this on networks you own or have written permission
> to monitor. Capturing traffic on unauthorized networks is illegal under the
> Information Technology Act, 2000 (India) and equivalent laws globally.
> This tool is for lab environments and authorized testing only.

---

## What it actually does

- Captures live packets from a real network interface using Scapy's `sniff()`
- Parses IP headers: source/destination IP, TTL, protocol
- Parses TCP headers: ports, flags (SYN, ACK, RST, FIN), sequence numbers
- Parses UDP and ICMP packets
- Detects and parses DNS queries and responses (query name, record type, answers)
- Detects HTTP requests and responses (method, path, status code)
- Identifies common services by port number (SSH, HTTP, DNS, RDP, SMB, etc.)
- Tracks live statistics: protocol breakdown, top talkers by IP
- Flags basic port scan indicators (one source hitting many destination ports)
- Supports BPF filter strings — same syntax as Wireshark/tcpdump
- Exports everything to CSV for offline analysis
- CLI mode works without a display (headless servers, SSH sessions)

---

## Why I rewrote this

The original version (`Packetsniffer.py`) used `random.choice()` to generate
fake IP addresses and `random.randint()` for packet lengths. It looked like a
packet sniffer but captured nothing. Any technical interviewer or security
engineer would see through it immediately.

The rewrite uses Scapy's actual packet capture engine. The parsed fields come
from real packet headers — not strings I made up.

---

## What I learned building this

**Scapy's packet model:** Each protocol is a layer. `pkt[IP].src` gives the
real source IP. `pkt[TCP].flags` gives the actual TCP flags as a bitmask.
`pkt.haslayer(DNS)` tells you if DNS was decoded on top of UDP.

**Threading with Tkinter:** Tkinter is not thread-safe. You can't call any
`widget.insert()` from a background thread or the GUI crashes. The fix is a
`queue.Queue` — the Scapy capture thread puts parsed packets in, and the main
thread drains it every 100ms with `root.after()`. This pattern is important in
any event-driven GUI application.

**BPF filters:** Berkeley Packet Filter syntax is what Wireshark, tcpdump, and
Scapy all use. `"tcp port 80"` means TCP traffic on port 80. `"host 10.0.0.1"`
means traffic to or from that IP. `"not arp"` excludes ARP broadcast noise.
Learning BPF makes Wireshark significantly more useful in a real SOC context.

**TCP flags and what they tell you:**
- `SYN` only → connection initiation, or SYN scan (Nmap default)
- `RST` → port closed, or firewall/IDS resetting a connection
- `SYN-ACK` → server accepting a connection
- `FIN-ACK` → graceful close
- Seeing a flood of SYN packets from one source → SYN flood indicator

**DNS without encryption:** All DNS queries in this tool's output are readable
in plaintext. Every domain a machine looks up is visible to anyone on the
network segment. This is why DNS over HTTPS (DoH) exists.

**Port scan detection:** If one source IP hits 15+ different destination ports
in a short window, that is a heuristic indicator of a port scan. The tool
flags these in the statistics panel. This is a simplified version of what
SIEMs do with correlation rules.

---

## Requirements

```
Python 3.8+
scapy
```

```bash
pip install scapy
```

On Linux/macOS: requires root privileges for raw socket access.
On Windows: requires WinPcap or Npcap installed.

---

## Usage

### GUI mode (default)
```bash
sudo python3 packet_analyzer.py
sudo python3 packet_analyzer.py -i eth0
sudo python3 packet_analyzer.py -i eth0 -f "tcp port 443"
```

### CLI mode (headless / no display)
```bash
sudo python3 packet_analyzer.py --no-gui -i eth0
sudo python3 packet_analyzer.py --no-gui -i eth0 -f "dns"
sudo python3 packet_analyzer.py --no-gui -i eth0 -f "tcp" -c 200 -o capture.csv
```

### BPF filter examples
```
tcp                          → TCP traffic only
udp port 53                  → DNS queries and responses
host 192.168.1.100           → traffic to/from a specific IP
tcp and port 80              → HTTP traffic
not arp                      → exclude ARP broadcasts
tcp[tcpflags] & tcp-syn != 0 → SYN packets only (advanced)
```

---

## Lab setup

I tested this in an isolated local network VM:
- **OS:** Kali Linux (VirtualBox VM)
- **Interface used:** eth0 (host-only adapter)
- **No internet traffic captured** — all test traffic was generated locally

Recommended way to generate test traffic while learning:
```bash
# Terminal 1 — run the analyzer
sudo python3 packet_analyzer.py -i eth0

# Terminal 2 — generate traffic to observe
ping 8.8.8.8                 # generates ICMP
nslookup google.com          # generates DNS
curl http://example.com      # generates HTTP
```

---

## What this does NOT do

- No deep packet inspection (DPI) beyond what Scapy's built-in layers handle
- No packet reassembly (fragmented packets are shown as fragments)
- No pcap file import (planned improvement — use `rdpcap()`)
- No alerting or automated response (that is a SIEM's job)

---

## Planned improvements

- [ ] Import existing `.pcap` files for offline analysis
- [ ] Detect SYN flood patterns with time-windowed counting
- [ ] Filter by IP or port directly in the GUI without restarting capture
- [ ] Show geolocation of external IPs (using ip-api.com or MaxMind GeoLite2)
- [ ] Export to pcap format for Wireshark

---

## Tools and libraries

- [Scapy](https://scapy.net/) — packet capture and parsing
- Python 3 standard library: `tkinter`, `threading`, `queue`, `csv`, `argparse`

---

## Part of

Prodigy InfoTech Cybersecurity Internship — Task 05 (rewritten post-internship
to replace the simulation-based original with real packet capture)
