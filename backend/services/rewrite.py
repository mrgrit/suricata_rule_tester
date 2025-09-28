import pathlib, subprocess, tempfile, os
from ..settings import SETTINGS

def ensure_rewritten_dir(original_path: str):
    root = pathlib.Path(SETTINGS.pcap_root).resolve()
    p = pathlib.Path(original_path).resolve()
    rel = p.relative_to(root)
    target_dir = root / "_rewritten" / rel.parent
    target_dir.mkdir(parents=True, exist_ok=True)
    target_path = target_dir / p.name
    return str(target_path)

def _supports(opt: str) -> bool:
    try:
        out = subprocess.run(["tcprewrite", "--help"], capture_output=True, text=True)
        return opt in out.stdout
    except Exception:
        return False

def tcprewrite(infile: str, outfile: str, src_map: dict=None, dst_map: dict=None):
    src_map = src_map or {}
    dst_map = dst_map or {}

    has_srcipmap = _supports("--srcipmap")
    has_dstipmap = _supports("--dstipmap")
    has_pnat = _supports("--pnat")

    if (src_map and has_srcipmap) or (dst_map and has_dstipmap):
        args = ["tcprewrite", "--infile", infile, "--outfile", outfile]
        if src_map and has_srcipmap:
            src_pairs = [f"{old}/32:{new}/32" for old, new in src_map.items()]
            args += ["--srcipmap", ",".join(src_pairs)]
        if dst_map and has_dstipmap:
            dst_pairs = [f"{old}/32:{new}/32" for old, new in dst_map.items()]
            args += ["--dstipmap", ",".join(dst_pairs)]
        proc = subprocess.run(args, capture_output=True, text=True)
        return proc.returncode, proc.stdout, proc.stderr

    if has_pnat:
        current_in = infile
        pairs = list(src_map.items()) + list(dst_map.items())
        if not pairs:
            proc = subprocess.run(["tcprewrite", "--infile", infile, "--outfile", outfile], capture_output=True, text=True)
            return proc.returncode, proc.stdout, proc.stderr
        for i, (old, new) in enumerate(pairs):
            is_last = (i == len(pairs) - 1)
            out_path = outfile if is_last else tempfile.mkstemp(suffix=".pcap", dir=str(pathlib.Path(outfile).parent))[1]
            cmd = ["tcprewrite", "--infile", current_in, "--outfile", out_path, "--pnat", f"{old}/32:{new}/32"]
            proc = subprocess.run(cmd, capture_output=True, text=True)
            if proc.returncode != 0:
                return proc.returncode, proc.stdout, proc.stderr
            current_in = out_path
        return 0, "pnat chain applied", ""

    return 1, "", "tcprewrite lacks srcipmap/dstipmap and pnat on this system"
