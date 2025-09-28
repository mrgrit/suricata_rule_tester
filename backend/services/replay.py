import subprocess
from ..settings import SETTINGS

def tcpreplay(pcap_path: str, iface: str=None, rate: str=None, loop: int=1):
    iface = iface or SETTINGS.nic_iface
    args = ["tcpreplay", "--intf1", iface, "--loop", str(loop), pcap_path]
    if rate:
        args.insert(1, f"--mbps={rate}")
    if SETTINGS.use_sudo_replay:
        args = ["sudo", "-n"] + args
    proc = subprocess.run(args, capture_output=True, text=True)
    return proc.returncode, proc.stdout, proc.stderr
