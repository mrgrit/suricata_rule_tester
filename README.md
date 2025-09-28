# Suri Replay Web API — Final (FastAPI + HTMX)

모든 이슈를 반영한 **웹 UI + 풀 REST API** 버전입니다.

## 핵심 수정 요약
- **Pydantic v2**: 모든 settings 필드 타입 지정
- **SQLite 안정화**: 절대경로 DB, 모델 강제 import, 서버 기동 시 자동 생성
- **tcprewrite 호환**: `--srcipmap/--dstipmap`은 옵션 1회 + 콤마 다중값, 미지원이면 `--pnat` 체인
- **tcpreplay 권한**: `.env USE_SUDO_REPLAY=1` 시 `sudo -n` 사용 (권장: `setcap`)
- **SSH 인증 강화**: ed25519/RSA/ECDSA + passphrase/password 지원
- **NIC 목록 API** (`/api/nics`)
- **원격 tcpdump 캡처 API/UI** (`/api/suricata/capture`)
- **모든 기능 REST API**로 노출(`/api/*`), API Key 필요

## 설치
```bash
sudo apt update
sudo apt install -y python3-pip python3-venv tshark tcpreplay libcap2-bin

python3 -m venv .venv && source .venv/bin/activate
pip install -r backend/requirements.txt

cp .env.example .env && nano .env

# (선택) DB 수동 초기화 — 서버 시작 시 자동으로도 생성됨
python -m backend.init_db

# 권한(권장): sudo 없이 tcpreplay 가능하게
sudo setcap cap_net_raw,cap_net_admin+ep $(which tcpreplay)
getcap $(which tcpreplay)
# 예: /usr/bin/tcpreplay = cap_net_admin,cap_net_raw+ep

# 실행
uvicorn backend.app:app --host 0.0.0.0 --port 8080 --reload
```

### .env
```ini
PCAP_ROOT=/home/llm/pcaps
NIC_IFACE=eth0
USE_SUDO_REPLAY=0               # 1이면 sudo -n 사용(Visudo 필요)

SURICATA_HOST=10.20.50.100
SURICATA_USER=suricata
SURICATA_SSH_KEY=~/.ssh/id_ed25519
SURICATA_SSH_PASSPHRASE=
SURICATA_PASSWORD=             # 키 없을 때만(테스트 용)

SURICATA_EVE=/var/log/suricata/eve.json
SURICATA_FAST=/var/log/suricata/fast.log
SURICATA_RULE_DIR=/etc/suricata/rules
SURICATA_LOCAL_RULE=local.rules
SURICATA_TEST_CMD=suricata -T -S /etc/suricata/rules/local.rules
SURICATA_RELOAD_CMD=systemctl reload suricata

API_KEY=devkey
GIT_WEBHOOK_TOKEN=changeme
```

## REST API 요약
- `GET /api/health`
- `GET /api/actions?limit=50`
- `GET /api/nics`
- `GET /api/pcaps`
- `GET /api/pcaps/ips?path=/full/path.pcap`
- `POST /api/pcaps/rewrite` `{path, src_map, dst_map}`
- `POST /api/pcaps/replay` `{path, loop, rate}`
- `GET /api/suricata/logs?file=fast|eve&grep=&lines=200`
- `POST /api/suricata/rules` `{content}`
- `POST /api/suricata/validate`
- `POST /api/suricata/reload`
- `POST /api/suricata/capture` `{iface, host, count, duration}`
- `POST /api/git/pull`
- `POST /hooks/git?token=...`

모든 `/api/*`는 헤더 `x-api-key: <API_KEY>` 필요.

## 아키텍처
```
[Web (HTMX)] ⇄ [FastAPI] ─ subprocess → tcprewrite/tcpreplay/tshark
                    │
                    ├─ SSH(Paramiko) → Suricata host: tail/test/reload/rule/tcpdump
                    │
                    └─ SQLite(ActionLog)
```
