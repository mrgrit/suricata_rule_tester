from pydantic import BaseModel
from dotenv import load_dotenv
import os

load_dotenv()

class Settings(BaseModel):
    pcap_root: str = os.getenv("PCAP_ROOT", "/home/llm/pcaps")
    nic_iface: str = os.getenv("NIC_IFACE", "eth0")
    use_sudo_replay: bool = os.getenv("USE_SUDO_REPLAY", "0") == "1"

    api_key: str = os.getenv("API_KEY", "devkey")

    suri_host: str = os.getenv("SURICATA_HOST", "127.0.0.1")
    suri_user: str = os.getenv("SURICATA_USER", "root")
    suri_key: str = os.getenv("SURICATA_SSH_KEY", "~/.ssh/id_ed25519")
    suri_passphrase: str = os.getenv("SURICATA_SSH_PASSPHRASE", "")
    suri_password: str = os.getenv("SURICATA_PASSWORD", "")

    suri_eve: str = os.getenv("SURICATA_EVE", "/var/log/suricata/eve.json")
    suri_fast: str = os.getenv("SURICATA_FAST", "/var/log/suricata/fast.log")
    suri_rule_dir: str = os.getenv("SURICATA_RULE_DIR", "/etc/suricata/rules")
    suri_local_rule: str = os.getenv("SURICATA_LOCAL_RULE", "local.rules")
    suri_test_cmd: str = os.getenv("SURICATA_TEST_CMD", "suricata -T -S /etc/suricata/rules/local.rules")
    suri_reload_cmd: str = os.getenv("SURICATA_RELOAD_CMD", "systemctl reload suricata")

    git_token: str = os.getenv("GIT_WEBHOOK_TOKEN", "")

SETTINGS = Settings()
