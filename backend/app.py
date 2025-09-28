import os, subprocess
from fastapi import FastAPI, Request, Form, Query, HTTPException, Header, Body
from fastapi.responses import HTMLResponse, PlainTextResponse
from fastapi.templating import Jinja2Templates
from sqlmodel import select
from .settings import SETTINGS
from .db import get_session, init_db
from .models import ActionLog
from .services.pcap import list_pcaps, extract_ips
from .services.rewrite import ensure_rewritten_dir, tcprewrite
from .services.replay import tcpreplay
from .services.suricata import remote_tail, test_rules, reload_suricata, write_rule_file, tcpdump_capture

app = FastAPI()
templates = Jinja2Templates(directory="backend/templates")

@app.on_event("startup")
def _startup_create_tables():
    init_db()

def require_key(x_api_key: str = Header(None)):
    if x_api_key != SETTINGS.api_key:
        raise HTTPException(status_code=401, detail="Bad API key")

def _log(action: str, detail: str, rc: int=0, so: str|None=None, se: str|None=None):
    with get_session() as s:
        row = ActionLog(action=action, detail=detail, exit_code=rc, stdout=so, stderr=se)
        s.add(row); s.commit()

# HTML
@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@app.get("/logs", response_class=HTMLResponse)
def logs(request: Request):
    with get_session() as s:
        rows = s.exec(select(ActionLog).order_by(ActionLog.id.desc()).limit(30)).all()
    return templates.TemplateResponse("logs.html", {"request": request, "rows": rows})

@app.get("/pcaps", response_class=HTMLResponse)
def pcaps_page(request: Request):
    tree = list_pcaps()
    return templates.TemplateResponse("pcaps.html", {"request": request, "tree": tree, "api_key": SETTINGS.api_key})

@app.get("/pcaps/ips", response_class=HTMLResponse)
def pcaps_ips(request: Request, dir: str = Query(...), file: str = Query(...)):
    base = os.path.join(SETTINGS.pcap_root, "" if dir == "." else dir)
    full = os.path.join(base, file)
    srcs, dsts = extract_ips(full)
    return templates.TemplateResponse("ips.html", {"request": request, "dir": dir, "file": file, "srcs": srcs, "dsts": dsts})

@app.post("/pcaps/rewrite", response_class=HTMLResponse)
async def pcaps_rewrite(request: Request, dir: str = Form(...), file: str = Form(...)):
    base = os.path.join(SETTINGS.pcap_root, "" if dir == "." else dir)
    full = os.path.join(base, file)
    data = dict(await request.form())
    src_map = {k[4:]:v for k,v in data.items() if k.startswith("src_") and v}
    dst_map = {k[4:]:v for k,v in data.items() if k.startswith("dst_") and v}
    outpcap = ensure_rewritten_dir(full)
    rc, so, se = tcprewrite(full, outpcap, src_map, dst_map)
    _log("tcprewrite", f"{file} -> {outpcap} | rc={rc}", rc, so, se)
    return templates.TemplateResponse("simple_result.html", {"request": request, "data": (so or se or f'rc={rc} out={outpcap}').strip()})

@app.post("/pcaps/replay", response_class=HTMLResponse)
def pcaps_replay(request: Request, dir: str = Form(...), file: str = Form(...), loop: int = Form(1), rate: str = Form(None)):
    base = os.path.join(SETTINGS.pcap_root, "" if dir == "." else dir)
    full = os.path.join(base, file)
    rc, so, se = tcpreplay(full, iface=SETTINGS.nic_iface, rate=rate, loop=loop)
    _log("tcpreplay", full, rc, so, se)
    return templates.TemplateResponse("replay_result.html", {"request": request, "stdout": so, "stderr": se})

@app.get("/suricata", response_class=HTMLResponse)
def suri_page(request: Request):
    return templates.TemplateResponse("suricata.html", {"request": request})

@app.get("/suricata/logs", response_class=PlainTextResponse)
def suri_logs(file: str = Query("fast"), grep: str | None = None):
    fpath = SETTINGS.suri_fast if file == "fast" else SETTINGS.suri_eve
    rc, out, err = remote_tail(fpath, grep=grep)
    _log("tail", f"{file} grep={grep}", rc, None, err)
    return out or err or ""

@app.post("/suricata/capture", response_class=PlainTextResponse)
def suri_capture(iface: str = Form(...), host: str = Form(...), count: int = Form(20), duration: int = Form(5)):
    rc, out, err = tcpdump_capture(iface, host, count=count, duration=duration)
    _log("tcpdump", f"{iface} host {host}", rc, out[:200] if out else "", err[:200] if err else "")
    return out or err or ""

# API
@app.get("/api/health")
def api_health(x_api_key: str = Header(None)):
    require_key(x_api_key); return {"ok": True}

@app.get("/api/actions")
def api_actions(limit: int = 50, x_api_key: str = Header(None)):
    require_key(x_api_key)
    with get_session() as s:
        rows = s.exec(select(ActionLog).order_by(ActionLog.id.desc()).limit(limit)).all()
    return [{"id": r.id, "action": r.action, "detail": r.detail, "rc": r.exit_code, "created_at": r.created_at.isoformat()} for r in rows]

@app.get("/api/nics")
def api_nics(x_api_key: str = Header(None)):
    require_key(x_api_key)
    out = subprocess.run(["bash","-lc","ip -br addr || ip link || ls /sys/class/net"], capture_output=True, text=True)
    return {"rc": out.returncode, "stdout": out.stdout, "stderr": out.stderr}

@app.get("/api/pcaps")
def api_pcaps(x_api_key: str = Header(None)):
    require_key(x_api_key); return list_pcaps()

@app.get("/api/pcaps/ips")
def api_pcaps_ips(path: str = Query(...), x_api_key: str = Header(None)):
    require_key(x_api_key)
    srcs, dsts = extract_ips(path)
    return {"srcs": srcs, "dsts": dsts}

@app.post("/api/pcaps/rewrite")
def api_pcaps_rewrite(payload: dict = Body(...), x_api_key: str = Header(None)):
    require_key(x_api_key)
    path = payload.get("path")
    src_map = payload.get("src_map") or {}
    dst_map = payload.get("dst_map") or {}
    outpcap = ensure_rewritten_dir(path)
    rc, so, se = tcprewrite(path, outpcap, src_map, dst_map)
    _log("tcprewrite", f"{path} -> {outpcap} | rc={rc}", rc, so, se)
    return {"infile": path, "outfile": outpcap, "rc": rc, "stdout": so, "stderr": se}

@app.post("/api/pcaps/replay")
def api_pcaps_replay(payload: dict = Body(...), x_api_key: str = Header(None)):
    require_key(x_api_key)
    path = payload.get("path"); loop = int(payload.get("loop") or 1); rate = payload.get("rate")
    rc, so, se = tcpreplay(path, iface=SETTINGS.nic_iface, rate=rate, loop=loop)
    _log("tcpreplay", path, rc, so, se)
    return {"rc": rc, "stdout": so, "stderr": se}

@app.get("/api/suricata/logs")
def api_suri_logs(file: str = Query("fast"), grep: str | None = None, lines: int = 200, x_api_key: str = Header(None)):
    require_key(x_api_key)
    fpath = SETTINGS.suri_fast if file == "fast" else SETTINGS.suri_eve
    rc, out, err = remote_tail(fpath, grep=grep, lines=lines)
    _log("tail", f"{file} grep={grep}", rc, None, err)
    return {"rc": rc, "out": out, "err": err}

@app.post("/api/suricata/rules")
def api_suri_rules(payload: dict = Body(...), x_api_key: str = Header(None)):
    require_key(x_api_key)
    content = payload.get("content","")
    rc, out, err = write_rule_file(content)
    _log("write_rule", f"bytes={len(content)}", rc, out, err)
    return {"rc": rc, "out": out, "err": err}

@app.post("/api/suricata/validate")
def api_suri_validate(x_api_key: str = Header(None)):
    require_key(x_api_key)
    rc, out, err = test_rules()
    _log("validate", out[:200] if out else "", rc, out, err)
    return {"rc": rc, "out": out, "err": err}

@app.post("/api/suricata/reload")
def api_suri_reload(x_api_key: str = Header(None)):
    require_key(x_api_key)
    rc, out, err = reload_suricata()
    _log("reload", out[:200] if out else "", rc, out, err)
    return {"rc": rc, "out": out, "err": err}

@app.post("/api/git/pull")
def api_git_pull(x_api_key: str = Header(None)):
    require_key(x_api_key)
    proc = subprocess.run("git pull --ff-only", shell=True, capture_output=True, text=True)
    _log("git_pull", proc.stdout.strip(), proc.returncode, proc.stdout, proc.stderr)
    return {"rc": proc.returncode, "stdout": proc.stdout, "stderr": proc.stderr}

@app.post("/hooks/git", response_class=PlainTextResponse)
def git_hook(request: Request, token: str = Query("")):
    if not SETTINGS.git_token or token != SETTINGS.git_token:
        raise HTTPException(403, "bad token")
    proc = subprocess.run("git pull --ff-only", shell=True, capture_output=True, text=True)
    _log("git_pull", proc.stdout.strip(), proc.returncode, proc.stdout, proc.stderr)
    return proc.stdout or proc.stderr or f"rc={proc.returncode}"
