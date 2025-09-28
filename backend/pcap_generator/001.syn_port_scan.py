#!/usr/bin/env python3
"""
generate_syn_pcaps_eth.py
Creates 5 PCAPs with Ethernet frames so tcpreplay / tcpdump on real NIC can see them.

Usage:
  python3 generate_syn_pcaps_eth.py /path/to/outdir
If you want to transmit live (send packets out an interface), run as root and set SEND_INTERFACE to e.g. "eth0" and set DO_SEND=True.
"""

import sys, time, random
from pathlib import Path

try:
    from scapy.all import Ether, IP, TCP, wrpcap, sendp
except Exception as e:
    print("ERROR: scapy not found. Install with: pip3 install scapy")
    raise

OUT_DIR = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("./pcaps_eth")
OUT_DIR.mkdir(parents=True, exist_ok=True)

# If you want to actually send packets live, set DO_SEND=True and SEND_INTERFACE to your interface (requires root)
DO_SEND = False
SEND_INTERFACE = "eth0"

def make_syn_eth(src_ip, dst_ip, src_mac, dst_mac, sport, dport, ts):
    e = Ether(src=src_mac, dst=dst_mac)
    ip = IP(src=src_ip, dst=dst_ip)
    tcp = TCP(sport=sport, dport=dport, flags="S", seq=1000)
    pkt = e / ip / tcp
    pkt.time = ts
    return pkt

def mac_for_ip(ip):
    # simple deterministic pseudo-mac generator for readability (not for real networks)
    parts = ip.split('.')
    return "02:00:%02x:%02x:%02x:%02x" % (int(parts[0]) & 0xff, int(parts[1]) & 0xff, int(parts[2]) & 0xff, int(parts[3]) & 0xff)

base = time.time()
pcap_list = []

# 1) syn_scan_single_src_eth.pcap -> should trigger
pkts = []
t = base
src = "111.111.111.111"
dst = "192.168.100.80"
src_mac = mac_for_ip(src)
dst_mac = mac_for_ip(dst)
for i, port in enumerate(range(1, 101)):
    if i >= 60: break
    pkts.append(make_syn_eth(src, dst, src_mac, dst_mac, sport=40000+i, dport=port, ts=t + i*0.08))
pfn = OUT_DIR / "syn_scan_single_src_eth.pcap"
wrpcap(str(pfn), pkts)
pcap_list.append(pfn)

# 2) syn_multi_dest_eth.pcap -> should trigger (single src, many dst)
pkts = []
t = base + 200
src = "111.111.111.111"
src_mac = mac_for_ip(src)
for i in range(70):
    dst_ip = f"192.168.100.{(i % 240) + 1}"
    dst_mac = mac_for_ip(dst_ip)
    pkts.append(make_syn_eth(src, dst_ip, src_mac, dst_mac, sport=41000+i, dport=80, ts=t + i*0.1))
pfn = OUT_DIR / "syn_multi_dest_eth.pcap"
wrpcap(str(pfn), pkts)
pcap_list.append(pfn)

# 3) syn_distributed_no_trigger_eth.pcap -> should NOT trigger (per-src below threshold)
pkts = []
t = base + 400
dst = "192.168.100.80"
dst_mac = mac_for_ip(dst)
for s_idx in range(10):
    src_ip = f"10.10.{s_idx}.{s_idx+10}"
    src_mac = mac_for_ip(src_ip)
    for j in range(10):
        pkts.append(make_syn_eth(src_ip, dst, src_mac, dst_mac, sport=42000 + s_idx*100 + j, dport=1000 + j, ts=t + j*0.9 + s_idx*0.01))
pfn = OUT_DIR / "syn_distributed_no_trigger_eth.pcap"
wrpcap(str(pfn), pkts)
pcap_list.append(pfn)

# 4) syn_random_with_trigger_eth.pcap -> should trigger (malicious src burst among noise)
pkts = []
t = base + 800
# background noise
for i in range(200):
    src_ip = f"{random.randint(50,200)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
    src_mac = mac_for_ip(src_ip)
    pkts.append(make_syn_eth(src_ip, "192.168.100.80", src_mac, mac_for_ip("192.168.100.80"), sport=random.randint(20000,60000), dport=random.randint(20,1024), ts=t + i*0.02))
# malicious burst
mal_src = "111.111.111.111"
mal_src_mac = mac_for_ip(mal_src)
start_ts = t + 200*0.02 + 0.1
for i in range(60):
    pkts.append(make_syn_eth(mal_src, "192.168.100.80", mal_src_mac, mac_for_ip("192.168.100.80"), sport=43000+i, dport=1000+i, ts=start_ts + i*0.05))
pfn = OUT_DIR / "syn_random_with_trigger_eth.pcap"
wrpcap(str(pfn), pkts)
pcap_list.append(pfn)

# 5) syn_lowrate_no_trigger_eth.pcap -> should NOT trigger (spread out over ~125s)
pkts = []
t = base + 1300
src = "111.111.111.111"
src_mac = mac_for_ip(src)
dst = "192.168.100.80"
dst_mac = mac_for_ip(dst)
for i in range(50):
    pkts.append(make_syn_eth(src, dst, src_mac, dst_mac, sport=44000+i, dport=2000+i, ts=t + i*2.5))
pfn = OUT_DIR / "syn_lowrate_no_trigger_eth.pcap"
wrpcap(str(pfn), pkts)
pcap_list.append(pfn)

print("Wrote PCAPs (Ethernet) to:", OUT_DIR)
for p in pcap_list:
    print(" -", p)

# Optional: send live (uncomment if you want to transmit immediately - requires root and correct interface!)
if DO_SEND:
    print("Sending pcap 1 live on interface", SEND_INTERFACE)
    # sendp will use the packets list we created for the first pcap; you can also read from wrpcap files and send
    sendp(pkts, iface=SEND_INTERFACE, verbose=True)

