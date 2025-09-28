# backend/services/suricata.py
import shlex
from .ssh import run, sftp_write
from ..settings import SETTINGS

def remote_tail(file_path: str, grep: str=None, lines: int=100):
    cmd = f"tail -n {int(lines)} -F {shlex.quote(file_path)} | head -n {int(lines)}"
    if grep:
        cmd = f"grep -i {shlex.quote(grep)} {shlex.quote(file_path)} | tail -n {int(lines)}"
    return run(SETTINGS.suri_host, SETTINGS.suri_user, SETTINGS.suri_key, cmd)

def test_rules():
    return run(SETTINGS.suri_host, SETTINGS.suri_user, SETTINGS.suri_key, SETTINGS.suri_test_cmd)

def reload_suricata():
    return run(SETTINGS.suri_host, SETTINGS.suri_user, SETTINGS.suri_key, SETTINGS.suri_reload_cmd)

# ★ 변경: SFTP로 규칙 파일을 직접 씀 (따옴표/이스케이프 문제 종결)
def write_rule_file(content: str):
    remote_path = f"{SETTINGS.suri_rule_dir}/{SETTINGS.suri_local_rule}"
    # Suricata 규칙은 ASCII/UTF-8 텍스트. bytes로 전송.
    data = content.encode("utf-8")
    return sftp_write(SETTINGS.suri_host, SETTINGS.suri_user, SETTINGS.suri_key, remote_path, data)

def tcpdump_capture(iface: str, host: str, count: int=20, duration: int=5):
    cmd = f"sudo timeout {int(duration)} tcpdump -ni {shlex.quote(iface)} host {shlex.quote(host)} -c {int(count)} -vv"
    return run(SETTINGS.suri_host, SETTINGS.suri_user, SETTINGS.suri_key, cmd, timeout=duration+10)

