#!/usr/bin/env python3
"""
generate_syn_mdst_pcaps_eth.py
Creates 5 PCAPs (with Ethernet frames) to test a Suricata rule:
  track by_src, count 100, seconds 5  (SYN multi-destination burst)

Usage:
  python3 generate_syn_mdst_pcaps_eth.py /path/to/outdir
If no outdir is given, ./pcaps_mdst_eth is used.

Requires:
  - Python 3
  - scapy (pip install scapy)  OR  apt-get install python3-scapy
"""

import sys, time, random
from pathlib import Path

try:
    from scapy.all import Ether, IP, TCP, wrpcap
except Exception as e:
    print("ERROR: scapy not found. Install with: pip3 install scapy  (or: sudo apt install python3-scapy)")
    raise

OUT_DIR = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("./pcaps_mdst_eth")
OUT_DIR.mkdir(parents=True, exist_ok=True)

# ---------- helpers ----------
def mac_for_ip(ip: str) -> str:
    """Deterministic demo MAC from IPv4 (for Ethernet link-layer in PCAP)."""
    a,b,c,d = (int(x) for x in ip.split("."))
    return f"02:00:{a:02x}:{b:02x}:{c:02x}:{d:02x}"

def syn_pkt(src_ip, dst_ip, sport, dport, ts):
    e = Ether(src=mac_for_ip(src_ip), dst=mac_for_ip(dst_ip))
    ip = IP(src=src_ip, dst=dst_ip)
    # flags='S' implies ACK=0; Suricata rule also checks ack:0, OK.
    tcp = TCP(sport=sport, dport=dport, flags="S", seq=1000)
    p = e/ip/tcp
    p.time = ts
    return p

def writepcap(name, pkts):
    path = OUT_DIR / name
    wrpcap(str(path), pkts)
    print(f"Wrote {path}  ({len(pkts)} pkts)")
    return path

base = time.time()

# Common targets within 192.168.100.0/24
def dst_ip(i):
    # avoid .0 and .255
    return f"192.168.100.{(i % 254) + 1}"

pcaps = []

# 1) TRIGGER: single source 111.111.111.111 -> many destinations, 120 SYNs in ~4.8s
#    120 pkts, spacing 0.04s => 120*0.04 = 4.8s (within 5s window)
pkts = []
t0 = base
src = "111.111.111.111"
for i in range(120):
    pkts.append(syn_pkt(src, dst_ip(i), sport=40000+i, dport=80, ts=t0 + i*0.04))
pcaps.append(writepcap("mdst_burst_trigger_eth.pcap", pkts))

# 2) NO TRIGGER: single source, 99 SYNs in ~4.95s (below threshold 100/5s)
pkts = []
t0 = base + 200
src = "111.111.111.111"
for i in range(99):
    pkts.append(syn_pkt(src, dst_ip(i), sport=41000+i, dport=80, ts=t0 + i*0.05))
pcaps.append(writepcap("mdst_borderline99_no_trigger_eth.pcap", pkts))

# 3) NO TRIGGER (rate too slow): single source 150 SYNs over ~15s
#    spacing 0.1s => any 5s window ~50 pkts (well below 100)
pkts = []
t0 = base + 400
src = "111.111.111.111"
for i in range(150):
    pkts.append(syn_pkt(src, dst_ip(i), sport=42000+i, dport=80, ts=t0 + i*0.10))
pcaps.append(writepcap("mdst_slow150_no_trigger_eth.pcap", pkts))

# 4) TRIGGER with noise: many random sources (noise) + one malicious source burst 110 in ~4.4s
pkts = []
t0 = base + 700
# noise: 300 SYNs from random sources over ~6s (won't trigger per-src)
for i in range(300):
    rsrc = f"{random.randint(10,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
    pkts.append(syn_pkt(rsrc, dst_ip(i), sport=random.randint(20000,60000), dport=80, ts=t0 + i*0.02))
# malicious burst from 111.111.111.111: 110 pkts, spacing 0.04s => 4.4s
start_ts = t0 + 300*0.02 + 0.1
mal = "111.111.111.111"
for i in range(110):
    pkts.append(syn_pkt(mal, dst_ip(i), sport=43000+i, dport=80, ts=start_ts + i*0.04))
pcaps.append(writepcap("mdst_noise_plus_trigger_eth.pcap", pkts))

# 5) NO TRIGGER: distributed sources (per-src <= 30) all within ~5s
#    10 sources * 30 pkts = 300 total, but each src <100 in 5s
pkts = []
t0 = base + 1000
for s in range(10):
    src = f"10.10.{s}.{s+10}"
    for i in range(30):
        # keep within ~4.5s
        pkts.append(syn_pkt(src, dst_ip(i), sport=44000 + s*100 + i, dport=80, ts=t0 + i*0.15 + s*0.002))
pcaps.append(writepcap("mdst_distributed_no_trigger_eth.pcap", pkts))

print("\nDONE. Generated files:")
for p in pcaps:
    print(" -", p)

