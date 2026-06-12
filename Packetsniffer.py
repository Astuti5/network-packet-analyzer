"""
Network Packet Analyzer
-----------------------
Author: Astuti (github.com/Astuti5)
Built for: Educational purposes — understanding live network traffic at the packet level.

Captures real packets from a network interface using Scapy.
Run in a VM or lab environment only. Requires root/admin privileges.

Usage:
    sudo python3 packet_analyzer.py                     # auto-selects interface
    sudo python3 packet_analyzer.py -i eth0             # specify interface
    sudo python3 packet_analyzer.py -i eth0 -f "tcp"   # BPF filter
    sudo python3 packet_analyzer.py --no-gui            # CLI-only mode

Dependencies:
    pip install scapy
"""

import argparse
import sys
import threading
import queue
import os
import csv
from datetime import datetime
from collections import defaultdict

# ---------------------------------------------------------------------------
# Guard: Scapy import with a clear error if not installed
# ---------------------------------------------------------------------------
try:
    from scapy.all import (
        sniff, get_if_list, conf,
        IP, IPv6, TCP, UDP, ICMP, DNS, Raw,
        ARP, Ether
    )
    from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

# ---------------------------------------------------------------------------
# Guard: Tkinter import — fall back to CLI mode if not available
# ---------------------------------------------------------------------------
try:
    import tkinter as tk
    from tkinter import ttk, scrolledtext, messagebox, filedialog
    TK_AVAILABLE = True
except ImportError:
    TK_AVAILABLE = False


# ===========================================================================
# Core packet parsing logic — completely separated from the UI layer
# This is the part that does real security-relevant work
# ===========================================================================

class PacketParser:
    """
    Parses a raw Scapy packet into a flat dictionary of fields.

    Why a separate class: the old code mixed parsing with UI rendering.
    This makes it impossible to test the logic or reuse it in a CLI context.
    Now the parser is UI-agnostic — same logic feeds both the GUI and CLI mode.
    """

    PROTOCOL_MAP = {
        1:   "ICMP",
        6:   "TCP",
        17:  "UDP",
        41:  "IPv6",
        58:  "ICMPv6",
        89:  "OSPF",
    }

    # Well-known port → service name (subset — enough for lab work)
    PORT_SERVICES = {
        20:   "FTP-data",
        21:   "FTP",
        22:   "SSH",
        23:   "Telnet",
        25:   "SMTP",
        53:   "DNS",
        67:   "DHCP",
        68:   "DHCP",
        80:   "HTTP",
        110:  "POP3",
        143:  "IMAP",
        161:  "SNMP",
        443:  "HTTPS",
        445:  "SMB",
        3306: "MySQL",
        3389: "RDP",
        5432: "PostgreSQL",
        6379: "Redis",
        8080: "HTTP-alt",
        8443: "HTTPS-alt",
    }

    @classmethod
    def parse(cls, pkt) -> dict:
        """
        Takes a Scapy packet object, returns a structured dict with all
        fields we care about. Returns None if the packet has no IP layer
        (e.g. raw ARP or non-IP Ethernet frames we don't want to show).
        """
        # We only care about IP traffic for this tool
        if not pkt.haslayer(IP) and not pkt.haslayer(IPv6):
            # Still capture ARP — useful for lab/recon awareness
            if pkt.haslayer(ARP):
                return cls._parse_arp(pkt)
            return None

        result = {
            "timestamp":   datetime.now().strftime("%H:%M:%S.%f")[:-3],
            "src_ip":      "",
            "dst_ip":      "",
            "src_port":    "-",
            "dst_port":    "-",
            "protocol":    "Unknown",
            "service":     "",
            "length":      len(pkt),
            "ttl":         "",
            "flags":       "",
            "info":        "",
            "raw_summary": pkt.summary(),
        }

        # --- IP layer ---
        if pkt.haslayer(IP):
            ip = pkt[IP]
            result["src_ip"]   = ip.src
            result["dst_ip"]   = ip.dst
            result["ttl"]      = ip.ttl
            result["protocol"] = cls.PROTOCOL_MAP.get(ip.proto, f"Proto-{ip.proto}")

        elif pkt.haslayer(IPv6):
            ip6 = pkt[IPv6]
            result["src_ip"]   = ip6.src
            result["dst_ip"]   = ip6.dst
            result["protocol"] = "IPv6"

        # --- Transport layer ---
        if pkt.haslayer(TCP):
            tcp = pkt[TCP]
            result["src_port"] = tcp.sport
            result["dst_port"] = tcp.dport
            result["protocol"] = "TCP"
            result["flags"]    = cls._tcp_flags(tcp.flags)
            result["service"]  = cls._service_name(tcp.sport, tcp.dport)
            result["info"]     = cls._tcp_info(pkt, tcp)

        elif pkt.haslayer(UDP):
            udp = pkt[UDP]
            result["src_port"] = udp.sport
            result["dst_port"] = udp.dport
            result["protocol"] = "UDP"
            result["service"]  = cls._service_name(udp.sport, udp.dport)
            result["info"]     = cls._udp_info(pkt, udp)

        elif pkt.haslayer(ICMP):
            icmp = pkt[ICMP]
            result["protocol"] = "ICMP"
            result["info"]     = cls._icmp_info(icmp)

        # --- Application layer hints ---
        if pkt.haslayer(DNS):
            result["protocol"] = "DNS"
            result["info"]     = cls._dns_info(pkt[DNS])

        if pkt.haslayer(HTTPRequest):
            result["protocol"] = "HTTP"
            result["info"]     = cls._http_request_info(pkt[HTTPRequest])

        if pkt.haslayer(HTTPResponse):
            result["protocol"] = "HTTP"
            result["info"]     = cls._http_response_info(pkt[HTTPResponse])

        return result

    @classmethod
    def _parse_arp(cls, pkt) -> dict:
        arp = pkt[ARP]
        op = "Request" if arp.op == 1 else "Reply"
        return {
            "timestamp":   datetime.now().strftime("%H:%M:%S.%f")[:-3],
            "src_ip":      arp.psrc,
            "dst_ip":      arp.pdst,
            "src_port":    "-",
            "dst_port":    "-",
            "protocol":    "ARP",
            "service":     "",
            "length":      len(pkt),
            "ttl":         "-",
            "flags":       "",
            "info":        f"ARP {op}: who has {arp.pdst}? tell {arp.psrc}",
            "raw_summary": pkt.summary(),
        }

    @classmethod
    def _tcp_flags(cls, flags) -> str:
        """
        Converts Scapy TCP flags integer/object to readable string.
        e.g. 0x02 → SYN, 0x12 → SYN-ACK, 0x10 → ACK, 0x04 → RST
        """
        flag_map = {
            "F": "FIN",
            "S": "SYN",
            "R": "RST",
            "P": "PSH",
            "A": "ACK",
            "U": "URG",
            "E": "ECE",
            "C": "CWR",
        }
        flags_str = str(flags)
        active = [flag_map[c] for c in flags_str if c in flag_map]
        return "-".join(active) if active else str(flags)

    @classmethod
    def _service_name(cls, sport, dport) -> str:
        """
        Tries to identify the service by checking well-known ports.
        Checks destination first (server port), then source (response direction).
        """
        return (cls.PORT_SERVICES.get(dport)
                or cls.PORT_SERVICES.get(sport)
                or "")

    @classmethod
    def _tcp_info(cls, pkt, tcp) -> str:
        """Build a Wireshark-style info string for TCP packets."""
        flags = cls._tcp_flags(tcp.flags)
        info = f"{tcp.sport} → {tcp.dport} [{flags}] Seq={tcp.seq}"
        if "ACK" in flags:
            info += f" Ack={tcp.ack}"
        info += f" Win={tcp.window}"
        payload_len = len(pkt[Raw].load) if pkt.haslayer(Raw) else 0
        if payload_len:
            info += f" Len={payload_len}"
        return info

    @classmethod
    def _udp_info(cls, pkt, udp) -> str:
        payload_len = len(pkt[Raw].load) if pkt.haslayer(Raw) else 0
        return f"{udp.sport} → {udp.dport} Len={payload_len}"

    @classmethod
    def _icmp_info(cls, icmp) -> str:
        type_map = {
            0:  "Echo Reply",
            3:  "Destination Unreachable",
            5:  "Redirect",
            8:  "Echo Request (ping)",
            11: "Time Exceeded (TTL expired)",
            30: "Traceroute",
        }
        return type_map.get(icmp.type, f"Type={icmp.type} Code={icmp.code}")

    @classmethod
    def _dns_info(cls, dns) -> str:
        """Extract DNS query name and type from the DNS layer."""
        try:
            if dns.qr == 0:  # Query
                qname = dns.qd.qname.decode(errors="replace").rstrip(".")
                qtype_map = {1: "A", 2: "NS", 5: "CNAME", 15: "MX",
                             16: "TXT", 28: "AAAA", 33: "SRV"}
                qtype = qtype_map.get(dns.qd.qtype, str(dns.qd.qtype))
                return f"DNS Query: {qname} ({qtype})"
            else:  # Response
                answers = []
                an = dns.an
                while an:
                    try:
                        rdata = an.rdata
                        if isinstance(rdata, bytes):
                            rdata = rdata.decode(errors="replace")
                        answers.append(str(rdata))
                    except Exception:
                        pass
                    an = an.payload if hasattr(an, "payload") else None
                    if not hasattr(an, "rdata"):
                        break
                return f"DNS Response: {', '.join(answers[:3])}"
        except Exception:
            return "DNS"

    @classmethod
    def _http_request_info(cls, http) -> str:
        try:
            method = http.Method.decode(errors="replace") if http.Method else "?"
            path   = http.Path.decode(errors="replace") if http.Path else "/"
            host   = http.Host.decode(errors="replace") if http.Host else ""
            return f"HTTP {method} {host}{path}"
        except Exception:
            return "HTTP Request"

    @classmethod
    def _http_response_info(cls, http) -> str:
        try:
            status = http.Status_Code.decode(errors="replace") if http.Status_Code else "?"
            reason = http.Reason_Phrase.decode(errors="replace") if http.Reason_Phrase else ""
            return f"HTTP {status} {reason}"
        except Exception:
            return "HTTP Response"


# ===========================================================================
# Statistics tracker — counts by protocol, IP, port
# Used for the stats panel in GUI mode and the summary in CLI mode
# ===========================================================================

class PacketStats:
    def __init__(self):
        self.total       = 0
        self.by_protocol = defaultdict(int)
        self.by_src_ip   = defaultdict(int)
        self.by_dst_ip   = defaultdict(int)
        self.by_service  = defaultdict(int)
        self.total_bytes = 0
        # For detecting basic port scan pattern (many dports from one src)
        self.src_to_dports = defaultdict(set)

    def update(self, parsed: dict):
        self.total       += 1
        self.total_bytes += parsed.get("length", 0)
        self.by_protocol[parsed["protocol"]] += 1
        self.by_src_ip[parsed["src_ip"]]     += 1
        self.by_dst_ip[parsed["dst_ip"]]     += 1

        svc = parsed.get("service")
        if svc:
            self.by_service[svc] += 1

        # Port scan heuristic: same src hitting many different dst ports
        dport = parsed.get("dst_port")
        if dport != "-" and parsed.get("src_ip"):
            self.src_to_dports[parsed["src_ip"]].add(dport)

    def potential_scanners(self, threshold=15) -> list:
        """
        Returns source IPs that have hit more than `threshold` distinct
        destination ports — a basic indicator of a port scan.
        Not reliable in isolation; for learning purposes only.
        """
        return [
            (ip, len(ports))
            for ip, ports in self.src_to_dports.items()
            if len(ports) >= threshold
        ]

    def summary_text(self) -> str:
        lines = [
            f"Total packets : {self.total}",
            f"Total bytes   : {self.total_bytes:,}",
            "",
            "--- Protocol breakdown ---",
        ]
        for proto, count in sorted(self.by_protocol.items(),
                                   key=lambda x: x[1], reverse=True):
            pct = (count / self.total * 100) if self.total else 0
            lines.append(f"  {proto:<12} {count:>6}  ({pct:.1f}%)")

        lines += ["", "--- Top 5 source IPs ---"]
        for ip, count in sorted(self.by_src_ip.items(),
                                key=lambda x: x[1], reverse=True)[:5]:
            lines.append(f"  {ip:<20} {count:>6} packets")

        scanners = self.potential_scanners()
        if scanners:
            lines += ["", "--- Possible port scan activity ---"]
            for ip, port_count in sorted(scanners, key=lambda x: x[1], reverse=True):
                lines.append(f"  ⚠  {ip} — {port_count} distinct destination ports")

        return "\n".join(lines)


# ===========================================================================
# CLI mode — for use without a display / headless environments
# ===========================================================================

def run_cli(interface: str, bpf_filter: str, count: int, output_file: str):
    """
    Pure terminal packet capture. Useful on headless servers or inside tmux.
    Prints one line per packet in a Wireshark-style format.
    """
    if not SCAPY_AVAILABLE:
        print("[ERROR] Scapy is not installed. Run: pip install scapy")
        sys.exit(1)

    stats  = PacketStats()
    writer = None
    csvfile = None

    if output_file:
        csvfile = open(output_file, "w", newline="")
        fieldnames = ["no", "timestamp", "src_ip", "src_port",
                      "dst_ip", "dst_port", "protocol", "service",
                      "length", "ttl", "flags", "info"]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames,
                                extrasaction="ignore")
        writer.writeheader()
        print(f"[*] Logging to {output_file}")

    pkt_num = [0]

    def handle(pkt):
        parsed = PacketParser.parse(pkt)
        if not parsed:
            return
        pkt_num[0] += 1
        stats.update(parsed)

        # Terminal output
        line = (
            f"{pkt_num[0]:>5}  "
            f"{parsed['timestamp']}  "
            f"{parsed['src_ip']:<20}"
            f"{str(parsed['src_port']):<8}"
            f"→  "
            f"{parsed['dst_ip']:<20}"
            f"{str(parsed['dst_port']):<8}"
            f"{parsed['protocol']:<8}"
            f"{parsed['info']}"
        )
        print(line)

        if writer:
            row = dict(parsed)
            row["no"] = pkt_num[0]
            writer.writerow(row)

    iface_display = interface if interface else "default"
    filter_display = f" filter='{bpf_filter}'" if bpf_filter else ""
    count_display  = f" count={count}" if count else " (Ctrl+C to stop)"

    print(f"\n[*] Starting capture on {iface_display}{filter_display}{count_display}")
    print(f"[*] {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("-" * 100)
    print(f"{'No':>5}  {'Time':<15}{'Src IP':<20}{'SPort':<8}   "
          f"{'Dst IP':<20}{'DPort':<8}{'Proto':<8}Info")
    print("-" * 100)

    try:
        sniff(
            iface=interface or None,
            filter=bpf_filter or None,
            count=count or 0,
            prn=handle,
            store=False,
        )
    except KeyboardInterrupt:
        pass
    except PermissionError:
        print("\n[ERROR] Permission denied. Run with sudo.")
        sys.exit(1)
    finally:
        print("\n" + "=" * 60)
        print(stats.summary_text())
        if csvfile:
            csvfile.close()
            print(f"\n[*] Saved to {output_file}")


# ===========================================================================
# GUI mode
# ===========================================================================

class PacketAnalyzerGUI:
    """
    Tkinter GUI for real-time packet capture and display.

    Key differences from the original version:
    - Uses Scapy sniff() in a background thread (non-blocking)
    - Parses real packet fields — IP headers, TCP flags, DNS queries, etc.
    - Stats panel shows live protocol breakdown
    - Export to CSV of everything captured
    - BPF filter support (e.g. "tcp port 80", "icmp", "host 192.168.1.1")
    - Interface selector dropdown
    """

    # Colour codes for different protocols in the packet list
    PROTO_COLORS = {
        "TCP":   "#e8f4f8",
        "UDP":   "#e8f8e8",
        "DNS":   "#f8f4e8",
        "HTTP":  "#ffe8e8",
        "ICMP":  "#f0e8ff",
        "ARP":   "#fff0e8",
        "IPv6":  "#e8e8ff",
    }

    def __init__(self, root: tk.Tk, interface: str = None, bpf_filter: str = ""):
        self.root       = root
        self.interface  = interface
        self.bpf_filter = bpf_filter

        self.root.title("Network Packet Analyzer")
        self.root.geometry("1200x750")
        self.root.minsize(900, 600)

        self.packet_count  = 0
        self.is_capturing  = False
        self.capture_thread = None
        self.packet_queue  = queue.Queue()  # thread-safe bridge from Scapy → Tkinter
        self.captured_rows = []             # for CSV export
        self.stats         = PacketStats()

        self._build_ui()
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)
        # Start polling the queue for packets from the capture thread
        self._poll_queue()

    # -----------------------------------------------------------------------
    # UI construction
    # -----------------------------------------------------------------------

    def _build_ui(self):
        self._build_toolbar()
        self._build_packet_tree()
        self._build_detail_and_stats()
        self._build_statusbar()
        self._apply_protocol_tags()

    def _build_toolbar(self):
        bar = ttk.Frame(self.root, padding="5 5 5 0")
        bar.pack(fill=tk.X)

        # Interface selector
        ttk.Label(bar, text="Interface:").pack(side=tk.LEFT, padx=(0, 3))
        self.iface_var = tk.StringVar(value=self.interface or "")
        iface_combo = ttk.Combobox(bar, textvariable=self.iface_var, width=12)
        iface_combo["values"] = self._get_interfaces()
        iface_combo.pack(side=tk.LEFT, padx=(0, 10))

        # BPF filter
        ttk.Label(bar, text="Filter (BPF):").pack(side=tk.LEFT, padx=(0, 3))
        self.filter_var = tk.StringVar(value=self.bpf_filter)
        filter_entry = ttk.Entry(bar, textvariable=self.filter_var, width=25)
        filter_entry.pack(side=tk.LEFT, padx=(0, 10))
        ttk.Label(bar, text="e.g. tcp, udp port 53, host 192.168.1.1",
                  foreground="gray").pack(side=tk.LEFT, padx=(0, 15))

        # Buttons
        self.start_btn = ttk.Button(bar, text="▶  Start Capture",
                                    command=self._start_capture)
        self.start_btn.pack(side=tk.LEFT, padx=3)

        self.stop_btn = ttk.Button(bar, text="■  Stop",
                                   command=self._stop_capture, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, padx=3)

        ttk.Button(bar, text="Clear", command=self._clear).pack(side=tk.LEFT, padx=3)
        ttk.Button(bar, text="Export CSV", command=self._export_csv).pack(side=tk.LEFT, padx=3)

    def _build_packet_tree(self):
        frame = ttk.Frame(self.root)
        frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        columns = ("no", "time", "src_ip", "src_port",
                   "dst_ip", "dst_port", "proto", "service",
                   "length", "flags", "info")
        col_widths = {
            "no":       45,  "time":     105, "src_ip":   130,
            "src_port": 60,  "dst_ip":   130, "dst_port": 60,
            "proto":    65,  "service":  80,  "length":   60,
            "flags":    90,  "info":     280,
        }
        col_labels = {
            "no": "No.", "time": "Time", "src_ip": "Source IP",
            "src_port": "SPort", "dst_ip": "Dest IP", "dst_port": "DPort",
            "proto": "Protocol", "service": "Service", "length": "Len",
            "flags": "Flags", "info": "Info",
        }

        self.tree = ttk.Treeview(frame, columns=columns,
                                  show="headings", selectmode="browse")
        for col in columns:
            self.tree.heading(col, text=col_labels[col])
            self.tree.column(col, width=col_widths[col], anchor=tk.W, stretch=False)

        # Make the Info column stretch to fill remaining space
        self.tree.column("info", stretch=True)

        vsb = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=self.tree.yview)
        hsb = ttk.Scrollbar(frame, orient=tk.HORIZONTAL, command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        frame.rowconfigure(0, weight=1)
        frame.columnconfigure(0, weight=1)

        self.tree.bind("<<TreeviewSelect>>", self._show_detail)

    def _build_detail_and_stats(self):
        pane = ttk.PanedWindow(self.root, orient=tk.HORIZONTAL)
        pane.pack(fill=tk.BOTH, expand=False, padx=5, pady=(0, 5))

        # --- Packet detail (left) ---
        detail_frame = ttk.LabelFrame(pane, text="Packet Detail", padding=5)
        self.detail_text = scrolledtext.ScrolledText(
            detail_frame, height=10, wrap=tk.WORD,
            font=("Consolas", 10), state=tk.DISABLED
        )
        self.detail_text.pack(fill=tk.BOTH, expand=True)
        pane.add(detail_frame, weight=3)

        # --- Stats (right) ---
        stats_frame = ttk.LabelFrame(pane, text="Live Statistics", padding=5)
        self.stats_text = scrolledtext.ScrolledText(
            stats_frame, height=10, wrap=tk.WORD,
            font=("Consolas", 10), state=tk.DISABLED
        )
        self.stats_text.pack(fill=tk.BOTH, expand=True)
        pane.add(stats_frame, weight=1)

    def _build_statusbar(self):
        self.status_var = tk.StringVar(value="Ready — select an interface and press Start Capture")
        bar = ttk.Label(self.root, textvariable=self.status_var,
                        relief=tk.SUNKEN, anchor=tk.W, padding="3 2")
        bar.pack(fill=tk.X, side=tk.BOTTOM)

    def _apply_protocol_tags(self):
        for proto, color in self.PROTO_COLORS.items():
            self.tree.tag_configure(proto, background=color)

    # -----------------------------------------------------------------------
    # Interface helpers
    # -----------------------------------------------------------------------

    @staticmethod
    def _get_interfaces() -> list:
        if not SCAPY_AVAILABLE:
            return ["eth0", "wlan0", "lo"]
        try:
            return get_if_list()
        except Exception:
            return ["eth0", "wlan0", "lo"]

    # -----------------------------------------------------------------------
    # Capture lifecycle
    # -----------------------------------------------------------------------

    def _start_capture(self):
        if not SCAPY_AVAILABLE:
            messagebox.showerror(
                "Scapy not installed",
                "Scapy is required for real packet capture.\n\n"
                "Install it with:\n  pip install scapy\n\n"
                "Then re-run this script with sudo/root."
            )
            return

        iface      = self.iface_var.get().strip() or None
        bpf_filter = self.filter_var.get().strip() or None

        self.is_capturing   = True
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self.status_var.set(
            f"Capturing on {iface or 'default interface'}"
            + (f"  |  filter: {bpf_filter}" if bpf_filter else "")
        )

        self.capture_thread = threading.Thread(
            target=self._capture_worker,
            args=(iface, bpf_filter),
            daemon=True,
        )
        self.capture_thread.start()

    def _capture_worker(self, iface, bpf_filter):
        """
        Runs in a background thread.
        Scapy's sniff() blocks — this keeps the GUI responsive.
        Parsed packets go into a queue; the main thread reads them.
        """
        def on_packet(pkt):
            if not self.is_capturing:
                return
            parsed = PacketParser.parse(pkt)
            if parsed:
                self.packet_queue.put(parsed)

        try:
            sniff(
                iface=iface,
                filter=bpf_filter,
                prn=on_packet,
                store=False,
                stop_filter=lambda _: not self.is_capturing,
            )
        except PermissionError:
            self.packet_queue.put({"_error": "Permission denied. Run with sudo."})
        except Exception as e:
            self.packet_queue.put({"_error": str(e)})

    def _stop_capture(self):
        self.is_capturing = False
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.status_var.set(
            f"Capture stopped — {self.packet_count} packets"
        )

    def _clear(self):
        if self.is_capturing:
            self._stop_capture()
        self.tree.delete(*self.tree.get_children())
        self.packet_count  = 0
        self.captured_rows = []
        self.stats         = PacketStats()
        self._set_detail("")
        self._set_stats("")
        self.status_var.set("Cleared")

    # -----------------------------------------------------------------------
    # Queue polling — bridges capture thread → GUI thread safely
    # -----------------------------------------------------------------------

    def _poll_queue(self):
        """
        Called every 100ms by Tkinter's event loop.
        Drains up to 50 packets per tick to avoid freezing the UI under
        high packet rates.
        """
        processed = 0
        while processed < 50:
            try:
                item = self.packet_queue.get_nowait()
            except queue.Empty:
                break

            if "_error" in item:
                messagebox.showerror("Capture error", item["_error"])
                self._stop_capture()
                break

            self._add_row(item)
            self.stats.update(item)
            processed += 1

        if processed:
            self._refresh_stats()

        self.root.after(100, self._poll_queue)

    # -----------------------------------------------------------------------
    # Tree row insertion
    # -----------------------------------------------------------------------

    def _add_row(self, p: dict):
        self.packet_count += 1
        values = (
            self.packet_count,
            p["timestamp"],
            p["src_ip"],
            p["src_port"],
            p["dst_ip"],
            p["dst_port"],
            p["protocol"],
            p.get("service", ""),
            p["length"],
            p.get("flags", ""),
            p.get("info", ""),
        )
        tag = p["protocol"] if p["protocol"] in self.PROTO_COLORS else ""
        self.tree.insert("", tk.END, values=values, tags=(tag,))
        self.tree.yview_moveto(1)  # auto-scroll

        # Store for CSV export
        row = dict(zip(
            ["no", "timestamp", "src_ip", "src_port", "dst_ip", "dst_port",
             "protocol", "service", "length", "flags", "info"],
            values
        ))
        self.captured_rows.append(row)

        self.status_var.set(f"Packets captured: {self.packet_count}")

    # -----------------------------------------------------------------------
    # Detail panel
    # -----------------------------------------------------------------------

    def _show_detail(self, _event=None):
        sel = self.tree.selection()
        if not sel:
            return
        vals = self.tree.item(sel[0])["values"]
        no, ts, src_ip, src_port, dst_ip, dst_port, proto, svc, length, flags, info = vals

        detail = f"Packet #{no}\n"
        detail += "=" * 50 + "\n"
        detail += f"Time:        {ts}\n"
        detail += f"Source:      {src_ip}:{src_port}\n"
        detail += f"Destination: {dst_ip}:{dst_port}\n"
        detail += f"Protocol:    {proto}\n"
        if svc:
            detail += f"Service:     {svc}\n"
        detail += f"Length:      {length} bytes\n"
        if flags:
            detail += f"TCP Flags:   {flags}\n"
        detail += "\n"
        detail += f"Info:\n  {info}\n"

        # Provide educational context per protocol
        detail += "\n--- What this means ---\n"
        detail += self._educational_context(proto, flags, src_port, dst_port, info)

        self._set_detail(detail)

    def _educational_context(self, proto, flags, sport, dport, info) -> str:
        """
        Adds a one-paragraph educational note per packet type.
        This is the kind of thing you'd explain in a security interview.
        """
        ctx = {
            "TCP": (
                "TCP is a connection-oriented protocol. Look at the Flags field — "
                "SYN starts a connection, SYN-ACK is the server's response, ACK completes "
                "the 3-way handshake. RST tears down a connection abruptly (common in port scans). "
                "FIN is a graceful close."
            ),
            "UDP": (
                "UDP is connectionless — no handshake, no guaranteed delivery. "
                "Commonly used for DNS (port 53), DHCP, and streaming. "
                "UDP floods are a common DDoS vector because they require no handshake."
            ),
            "DNS": (
                "DNS translates domain names to IPs. Unencrypted DNS traffic (port 53) "
                "can be intercepted and modified (DNS spoofing / cache poisoning). "
                "DNS over HTTPS (DoH) or DNS over TLS (DoT) addresses this."
            ),
            "HTTP": (
                "HTTP traffic is unencrypted. Everything in this packet — including any "
                "cookies, credentials, or form data — is readable in plaintext. "
                "This is why HTTPS (TLS) is mandatory for anything sensitive."
            ),
            "ICMP": (
                "ICMP is used for ping (type 8 = echo request, type 0 = echo reply) and "
                "network diagnostics. Type 3 = destination unreachable. "
                "ICMP tunneling is a known covert channel technique used by malware."
            ),
            "ARP": (
                "ARP maps IP addresses to MAC addresses on a local network. "
                "ARP has no authentication — ARP spoofing (gratuitous ARP replies) is the "
                "basis for man-in-the-middle attacks on LAN segments."
            ),
        }
        # TCP flag-specific notes
        if proto == "TCP" and flags:
            if "SYN" in flags and "ACK" not in flags:
                return (
                    "SYN packet — this is the first step of the TCP 3-way handshake, or "
                    "part of a SYN scan. Nmap's default (-sS) sends SYN packets and never "
                    "completes the handshake, making it harder to detect in application logs."
                )
            if "RST" in flags:
                return (
                    "RST packet — connection reset. Can mean: the port is closed (scanner "
                    "response), a firewall is sending resets, or an IDS is tearing down "
                    "a detected malicious connection."
                )
        return ctx.get(proto, f"Protocol: {proto}. Inspect the Info field for layer-7 details.")

    # -----------------------------------------------------------------------
    # Stats panel
    # -----------------------------------------------------------------------

    def _refresh_stats(self):
        self._set_stats(self.stats.summary_text())

    def _set_detail(self, text: str):
        self.detail_text.config(state=tk.NORMAL)
        self.detail_text.delete(1.0, tk.END)
        self.detail_text.insert(tk.END, text)
        self.detail_text.config(state=tk.DISABLED)

    def _set_stats(self, text: str):
        self.stats_text.config(state=tk.NORMAL)
        self.stats_text.delete(1.0, tk.END)
        self.stats_text.insert(tk.END, text)
        self.stats_text.config(state=tk.DISABLED)

    # -----------------------------------------------------------------------
    # Export
    # -----------------------------------------------------------------------

    def _export_csv(self):
        if not self.captured_rows:
            messagebox.showinfo("Nothing to export", "No packets captured yet.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
            initialfile=f"capture_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        )
        if not path:
            return
        with open(path, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=self.captured_rows[0].keys())
            writer.writeheader()
            writer.writerows(self.captured_rows)
        self.status_var.set(f"Exported {len(self.captured_rows)} rows → {path}")

    # -----------------------------------------------------------------------
    # Lifecycle
    # -----------------------------------------------------------------------

    def _on_close(self):
        self.is_capturing = False
        self.root.destroy()


# ===========================================================================
# Entry point
# ===========================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Network Packet Analyzer — real capture using Scapy",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sudo python3 packet_analyzer.py
  sudo python3 packet_analyzer.py -i eth0 -f "tcp port 80"
  sudo python3 packet_analyzer.py --no-gui -i eth0 -f "dns" -o dns_capture.csv
  sudo python3 packet_analyzer.py --no-gui -i eth0 -c 100
        """,
    )
    parser.add_argument("-i", "--interface", default=None,
                        help="Network interface to capture on (e.g. eth0, wlan0)")
    parser.add_argument("-f", "--filter", default="",
                        help="BPF filter string (e.g. 'tcp', 'udp port 53', 'host 10.0.0.1')")
    parser.add_argument("-c", "--count", type=int, default=0,
                        help="Stop after capturing N packets (0 = unlimited, CLI mode only)")
    parser.add_argument("-o", "--output", default=None,
                        help="CSV file to write captured packets to (CLI mode only)")
    parser.add_argument("--no-gui", action="store_true",
                        help="Run in CLI mode (no Tkinter required)")
    args = parser.parse_args()

    if args.no_gui or not TK_AVAILABLE:
        run_cli(
            interface=args.interface,
            bpf_filter=args.filter,
            count=args.count,
            output_file=args.output,
        )
    else:
        if not SCAPY_AVAILABLE:
            print("[WARNING] Scapy not found — GUI will launch but capture won't work.")
            print("Install with: pip install scapy\n")

        root = tk.Tk()
        PacketAnalyzerGUI(root, interface=args.interface, bpf_filter=args.filter)
        root.mainloop()


if __name__ == "__main__":
    main()
