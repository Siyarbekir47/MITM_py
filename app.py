# PacketScope – Windows 11 (Python 3.11)
# HTTPS Interceptor + Fake Responses (stable)
# Architektur: FastAPI + mitmdump (Subprozess) + Addon, das in die API postet
# Getestet mit mitmproxy 10.x.

from __future__ import annotations

import os
import json
import base64
import shutil
import subprocess
import time
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
import uvicorn

# ---------------- Paths ----------------
ROOT = Path(__file__).parent
STATIC = ROOT / "ui"
DATA = ROOT / "data"; DATA.mkdir(exist_ok=True)
ADDONS_DIR = ROOT / "addons"; ADDONS_DIR.mkdir(exist_ok=True)
FORWARDER_PATH = ADDONS_DIR / "_forwarder_runtime.py"

# ---------------- Store ----------------
class FlowItem(BaseModel):
    id: str
    ts_start: float
    ts_end: Optional[float] = None
    client_ip: str
    client_port: int
    server_ip: Optional[str] = None
    server_port: Optional[int] = None
    method: str
    scheme: str
    host: str
    path: str
    http_version: str
    status_code: Optional[int] = None
    request_headers: dict
    response_headers: Optional[dict] = None
    request_size: int = 0
    response_size: Optional[int] = None
    pid: Optional[int] = None
    exe: Optional[str] = None

class Store:
    def __init__(self):
        self.flows: dict[str, FlowItem] = {}
        self.raw_req: dict[str, bytes] = {}
        self.raw_resp: dict[str, bytes] = {}
        self.req_text: dict[str, str] = {}
        self.resp_text: dict[str, str] = {}

    @staticmethod
    def _decode_text(blob: bytes | None) -> str:
        if not blob:
            return ""
        for enc in ("utf-8", "latin-1"):
            try:
                return blob.decode(enc)
            except Exception:
                pass
        return blob.decode("utf-8", errors="replace")

    @staticmethod
    def _b64_to_bytes(val) -> bytes:
        if not val:
            return b""
        try:
            if isinstance(val, (bytes, bytearray)):
                return base64.b64decode(val)
            if isinstance(val, str):
                return base64.b64decode(val)
        except Exception:
            return b""
        return b""

    def upsert_request(self, payload: dict):
        fid = payload["id"]
        item = FlowItem(**{k: payload[k] for k in FlowItem.model_fields.keys() if k in payload})
        self.flows[fid] = item
        # raw request bytes (start line + headers + blank line + body)
        line = f"{payload['method']} {payload['path']} HTTP/{payload['http_version']}\r\n".encode()
        headers = b"".join([f"{k}: {v}\r\n".encode() for k, v in (payload.get('request_headers') or {}).items()])
        body = self._b64_to_bytes(payload.get('request_body_b64'))
        self.raw_req[fid] = line + headers + b"\r\n" + body
        self.req_text[fid] = self._decode_text(body)

    def upsert_response(self, payload: dict):
        fid = payload["id"]
        it = self.flows.get(fid)
        if not it:
            # Minimaler Platzhalter, falls Request verpasst wurde
            it = FlowItem(**{k: payload.get(k) for k in FlowItem.model_fields.keys() if k in payload})
            self.flows[fid] = it
        it.ts_end = payload.get("ts_end", it.ts_end)
        it.status_code = payload.get("status_code")
        it.response_headers = payload.get("response_headers", {})
        it.response_size = payload.get("response_size")
        # raw response bytes (status line + headers + blank line + body)
        line = f"HTTP/{payload['http_version']} {payload.get('status_code', 0)} {payload.get('reason','')}\r\n".encode()
        headers = b"".join([f"{k}: {v}\r\n".encode() for k, v in (payload.get('response_headers') or {}).items()])
        body = self._b64_to_bytes(payload.get('response_body_b64'))
        self.raw_resp[fid] = line + headers + b"\r\n" + body
        self.resp_text[fid] = self._decode_text(body)

    def query(self, q=None, method=None, host=None, ip=None, port=None, pid=None, exe=None, limit=500):
        res = list(self.flows.values())
        if q:
            ql = str(q).lower()
            res = [x for x in res if ql in x.host.lower() or ql in x.path.lower()]
        if method:
            res = [x for x in res if x.method.upper() == str(method).upper()]
        if host:
            res = [x for x in res if str(host).lower() in x.host.lower()]
        if ip:
            res = [x for x in res if x.client_ip == ip or x.server_ip == ip]
        if port:
            res = [x for x in res if x.client_port == port or x.server_port == port]
        if pid is not None:
            res = [x for x in res if x.pid == pid]
        if exe:
            ex = str(exe).lower()
            res = [x for x in res if (x.exe or '').lower().endswith(ex) or (x.exe or '').lower() == ex]
        res.sort(key=lambda x: x.ts_start, reverse=True)
        return [x.model_dump() for x in res[:limit]]

    def get(self, fid: str):
        it = self.flows.get(fid)
        if not it:
            return None
        d = it.model_dump()
        d["request_body_text"] = self.req_text.get(fid, "")
        d["response_body_text"] = self.resp_text.get(fid, "")
        return d

    def get_raw_request(self, fid: str) -> Optional[bytes]:
        return self.raw_req.get(fid)

    def get_raw_response(self, fid: str) -> Optional[bytes]:
        return self.raw_resp.get(fid)

    def export_har(self, path: Path):
        entries = []
        for x in self.flows.values():
            entries.append({
                "startedDateTime": time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(x.ts_start)),
                "time": int(((x.ts_end or x.ts_start) - x.ts_start) * 1000),
                "request": {
                    "method": x.method,
                    "url": f"{x.scheme}://{x.host}{x.path}",
                    "httpVersion": x.http_version,
                    "headers": [{"name": k, "value": v} for k, v in (x.request_headers or {}).items()],
                    "bodySize": len(self.req_text.get(x.id, '').encode('utf-8'))
                },
                "response": {
                    "status": x.status_code or 0,
                    "httpVersion": x.http_version,
                    "headers": [{"name": k, "value": v} for k, v in (x.response_headers or {}).items()],
                    "bodySize": len(self.resp_text.get(x.id, '').encode('utf-8'))
                },
                "serverIPAddress": x.server_ip,
            })
        har = {"log": {"version": "1.2", "creator": {"name": "PacketScope", "version": "0.3"}, "entries": entries}}
        path.write_text(json.dumps(har, indent=2), encoding="utf-8")

store = Store()

# ---------------- FastAPI ----------------
app = FastAPI(title="PacketScope API")
app.mount("/static", StaticFiles(directory=str(STATIC), html=True), name="static")

@app.get("/", response_class=HTMLResponse)
async def index():
    with open(STATIC / "index.html", "r", encoding="utf-8") as f:
        return HTMLResponse(f.read())

class RuleModel(BaseModel):
    name: str
    host_re: Optional[str] = None
    path_re: Optional[str] = None
    method: Optional[str] = None
    delay_ms: int = 0
    status_code: int = 200
    headers: Optional[dict[str, str]] = None
    body: Optional[str] = None

@app.post("/api/ingest")
async def ingest(req: Request):
    payload = await req.json()
    kind = payload.get("kind")
    if kind == "request":
        store.upsert_request(payload)
    elif kind == "response":
        store.upsert_response(payload)
    return {"ok": True}

@app.get("/api/flows")
async def list_flows(q: str | None = None, method: str | None = None, host: str | None = None,
                     ip: str | None = None, port: int | None = None, pid: int | None = None,
                     exe: str | None = None, limit: int = 500):
    return JSONResponse(store.query(q, method, host, ip, port, pid, exe, limit))

@app.get("/api/flows/{flow_id}")
async def get_flow(flow_id: str):
    item = store.get(flow_id)
    if not item:
        raise HTTPException(404)
    return JSONResponse(item)

@app.get("/api/flows/{flow_id}/raw/request")
async def get_flow_req_raw(flow_id: str):
    raw = store.get_raw_request(flow_id)
    if raw is None:
        raise HTTPException(404)
    path = DATA / f"{flow_id}_request.txt"; path.write_bytes(raw)
    return FileResponse(str(path), filename=path.name, media_type="text/plain")

@app.get("/api/flows/{flow_id}/raw/response")
async def get_flow_resp_raw(flow_id: str):
    raw = store.get_raw_response(flow_id)
    if raw is None:
        raise HTTPException(404)
    path = DATA / f"{flow_id}_response.txt"; path.write_bytes(raw)
    return FileResponse(str(path), filename=path.name, media_type="text/plain")

@app.post("/api/rules", status_code=201)
async def add_rule(rule: RuleModel):
    rules_path = DATA / "rules.json"
    rules = []
    if rules_path.exists():
        try:
            rules = json.loads(rules_path.read_text("utf-8"))
        except Exception:
            rules = []
    # upsert
    rules = [r for r in rules if r.get("name") != rule.name] + [rule.model_dump()]
    rules_path.write_text(json.dumps(rules, indent=2), encoding="utf-8")
    return {"ok": True}

@app.get("/api/rules")
async def list_rules():
    p = DATA / "rules.json"
    if not p.exists():
        return []
    try:
        return json.loads(p.read_text("utf-8"))
    except Exception:
        return []

@app.delete("/api/rules/{name}")
async def delete_rule(name: str):
    p = DATA / "rules.json"
    if not p.exists():
        raise HTTPException(404)
    rules = [r for r in json.loads(p.read_text("utf-8")) if r.get("name") != name]
    p.write_text(json.dumps(rules, indent=2), encoding="utf-8")
    return {"ok": True}

@app.get("/api/export/har")
async def export_har():
    path = DATA / "export.har"; store.export_har(path)
    return FileResponse(str(path), filename=path.name, media_type="application/json")

# ---------------- mitmdump forwarder (addon script) ----------------
FORWARDER_CODE = r"""
from mitmproxy import http
import json, time, re, base64, threading
import urllib.request
import os, pathlib

INGEST = os.environ.get("PACKETSCOPE_INGEST", "http://127.0.0.1:5173/api/ingest")
RULES_PATH = os.environ.get("PACKETSCOPE_RULES", str(pathlib.Path(__file__).parent.parent / 'data' / 'rules.json'))

class Forwarder:
    def __init__(self):
        self.rules = []
        self._load_rules()
        self._start_rules_watcher()

    def _load_rules(self):
        try:
            p = pathlib.Path(RULES_PATH)
            if p.exists():
                self.rules = json.loads(p.read_text('utf-8'))
            else:
                self.rules = []
        except Exception:
            self.rules = []

    def _start_rules_watcher(self):
        def loop():
            mtime = 0
            p = pathlib.Path(RULES_PATH)
            while True:
                try:
                    if p.exists():
                        mt = p.stat().st_mtime
                        if mt != mtime:
                            mtime = mt
                            self._load_rules()
                except Exception:
                    pass
                time.sleep(1)
        import threading
        threading.Thread(target=loop, daemon=True).start()

    def _post(self, payload: dict):
        data = json.dumps(payload).encode('utf-8')
        req = urllib.request.Request(INGEST, data=data, headers={'Content-Type':'application/json'})
        # Proxy explizit BYPASSEN, um Loop zu verhindern
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        try:
            opener.open(req, timeout=2)
        except Exception:
            pass

    def request(self, flow: http.HTTPFlow):
        p = flow.request
        fid = f"{p.method}|{p.host}|{p.path}|{p.timestamp_start:.6f}"
        rid = base64.urlsafe_b64encode(fid.encode()).decode()[:16]
        payload = {
            'kind':'request',
            'id': rid,
            'ts_start': p.timestamp_start,
            'client_ip': flow.client_conn.address[0],
            'client_port': flow.client_conn.address[1],
            'server_ip': flow.server_conn.ip_address[0] if flow.server_conn.ip_address else None,
            'server_port': flow.server_conn.ip_address[1] if flow.server_conn.ip_address else None,
            'method': p.method,
            'scheme': p.scheme,
            'host': p.host,
            'path': p.path,
            'http_version': p.http_version,
            'request_headers': dict(p.headers.items()),
            'request_size': len(p.raw_content or b'') + len(str(p.headers)),
            'request_body_b64': base64.b64encode(p.raw_content or b'').decode(),
        }
        # Fake-Regeln
        for r in self.rules:
            if r.get('method') and r['method'].upper() != p.method.upper():
                continue
            if r.get('host_re') and not re.search(r['host_re'], p.host):
                continue
            if r.get('path_re') and not re.search(r['path_re'], p.path):
                continue
            time.sleep(max(0, int(r.get('delay_ms',0)))/1000.0)
            flow.response = http.Response.make(
                int(r.get('status_code',200)),
                (r.get('body') or '').encode('utf-8'),
                r.get('headers') or {}
            )
            break
        self._post(payload)

    def response(self, flow: http.HTTPFlow):
        r = flow.response
        p = flow.request
        fid = f"{p.method}|{p.host}|{p.path}|{p.timestamp_start:.6f}"
        rid = base64.urlsafe_b64encode(fid.encode()).decode()[:16]
        payload = {
            'kind':'response',
            'id': rid,
            'ts_end': getattr(r, 'timestamp_end', time.time()),
            'http_version': r.http_version,
            'status_code': r.status_code,
            'reason': r.reason,
            'response_headers': dict(r.headers.items()),
            'response_size': len(r.raw_content or b'') + len(str(r.headers)),
            'response_body_b64': base64.b64encode(r.raw_content or b'').decode(),
        }
        self._post(payload)

addons = [Forwarder()]
"""

proc: Optional[subprocess.Popen] = None

@app.on_event("startup")
def on_startup():
    # Schreibe Addon
    FORWARDER_PATH.write_text(FORWARDER_CODE, encoding="utf-8")
    # finde mitmdump
    exe = shutil.which("mitmdump")
    if not exe:
        raise RuntimeError("mitmdump nicht gefunden (venv aktiv?).")
    env = dict(**os.environ)
    env.update({
        "PACKETSCOPE_INGEST": "http://127.0.0.1:5173/api/ingest",
        "PACKETSCOPE_RULES": str(DATA/"rules.json"),
        # Proxy-Bypass für lokale Calls
        "NO_PROXY": "127.0.0.1,localhost",
        "no_proxy": "127.0.0.1,localhost",
    })
    args = [exe, "-p", "8080", "-s", str(FORWARDER_PATH)]
    global proc
    proc = subprocess.Popen(args, env=env, cwd=str(ROOT))

@app.on_event("shutdown")
def on_shutdown():
    global proc
    try:
        if proc and proc.poll() is None:
            proc.terminate()
    except Exception:
        pass

# ---------------- Main ----------------
if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=5173, log_level="info")
