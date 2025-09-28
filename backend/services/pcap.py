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

def preview_rows(pcap_path: str, dfilter: str | None = None, count: int = 100):
    """
    tshark로 가벼운 컬럼만 추출해서 테이블 형태로 반환
    - 구분자: 파이프(|) → 파싱 확실
    """
    import subprocess
    fields = [
        "frame.number",
        "frame.time_relative",
        "ip.src",
        "ip.dst",
        "_ws.col.Protocol",
        "frame.len",
    ]
    sep = "|"  # ← 핵심: 파이프를 구분자로 사용
    cmd = [
        "tshark", "-r", pcap_path, "-n",
        "-T", "fields",
        "-E", f"separator={sep}",
        "-E", "occurrence=f",
    ]
    for f in fields:
        cmd += ["-e", f]
    if dfilter:
        cmd += ["-Y", dfilter]
    if count:
        cmd += ["-c", str(count)]

    p = subprocess.run(cmd, capture_output=True, text=True)
    if p.returncode != 0:
        raise RuntimeError(p.stderr or "tshark failed")

    rows = []
    for line in p.stdout.splitlines():
        cols = line.split(sep)
        cols += [""] * (len(fields) - len(cols))  # 칼럼 수 보정
        rows.append({
            "no": cols[0],
            "time": cols[1],
            "src": cols[2],
            "dst": cols[3],
            "proto": cols[4],
            "len": cols[5],
        })
    return rows

