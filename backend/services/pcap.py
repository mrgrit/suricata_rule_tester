import subprocess, os, shlex
from ..settings import SETTINGS

def list_pcaps():
    root = SETTINGS.pcap_root
    tree = []
    for dirpath, dirnames, filenames in os.walk(root):
        rel = os.path.relpath(dirpath, root)
        files = [f for f in filenames if f.lower().endswith((".pcap",".pcapng"))]
        if files:
            tree.append({"dir": rel, "files": sorted(files)})
    return sorted(tree, key=lambda x: x["dir"])

def extract_ips(pcap_path: str):
    cmd = f'tshark -r {shlex.quote(pcap_path)} -T fields -e ip.src -e ip.dst'
    out = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if out.returncode != 0:
        raise RuntimeError(out.stderr)
    srcs, dsts = set(), set()
    for line in out.stdout.splitlines():
        parts = line.strip().split("\t")
        if len(parts) >= 1 and parts[0]:
            srcs.add(parts[0])
        if len(parts) >= 2 and parts[1]:
            dsts.add(parts[1])
    return sorted(srcs), sorted(dsts)
