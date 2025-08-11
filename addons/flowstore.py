# ----------
# File: addons/flowstore.py
# ----------
from __future__ import annotations
import base64
import hashlib
import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from mitmproxy import http

@dataclass
class FlowItem:
    id: str
    ts_start: float
    ts_end: float | None
    client_ip: str
    client_port: int
    server_ip: str | None
    server_port: int | None
    method: str
    scheme: str
    host: str
    path: str
    http_version: str
    status_code: int | None
    request_headers: dict[str, str]
    response_headers: dict[str, str] | None
    request_size: int
    response_size: int | None
    pid: int | None
    exe: str | None

class FlowStore:
    def __init__(self, procmap):
        self.procmap = procmap
        self._flows: dict[str, FlowItem] = {}
        self._raw_req: dict[str, bytes] = {}
        self._raw_resp: dict[str, bytes] = {}

    # mitmproxy hooks
    def request(self, flow: http.HTTPFlow):
        fid = self._id_for_flow(flow)
        pid, exe = self.procmap.lookup(flow.client_conn.address[0], flow.client_conn.address[1])
        item = FlowItem(
            id=fid,
            ts_start=flow.request.timestamp_start,
            ts_end=None,
            client_ip=flow.client_conn.address[0],
            client_port=flow.client_conn.address[1],
            server_ip=flow.server_conn.ip_address[0] if flow.server_conn.ip_address else None,
            server_port=flow.server_conn.ip_address[1] if flow.server_conn.ip_address else None,
            method=flow.request.method,
            scheme=flow.request.scheme,
            host=flow.request.host,
            path=flow.request.path,
            http_version=flow.request.http_version,
            status_code=None,
            request_headers={k: v for k, v in flow.request.headers.items()},
            response_headers=None,
            request_size=len(flow.request.raw_content or b"") + len(str(flow.request.headers)),
            response_size=None,
            pid=pid,
            exe=exe,
        )
        self._flows[fid] = item
        self._raw_req[fid] = self._build_raw_request(flow)

    def response(self, flow: http.HTTPFlow):
        fid = self._id_for_flow(flow)
        item = self._flows.get(fid)
        if item:
            item.ts_end = flow.response.timestamp_end
            item.status_code = flow.response.status_code
            item.response_headers = {k: v for k, v in flow.response.headers.items()}
            item.response_size = len(flow.response.raw_content or b"") + len(str(flow.response.headers))
        self._raw_resp[fid] = self._build_raw_response(flow)

    # helpers
    def _id_for_flow(self, flow: http.HTTPFlow) -> str:
        h = hashlib.sha1()
        key = f"{flow.request.method}|{flow.request.host}|{flow.request.path}|{flow.request.timestamp_start}"
        h.update(key.encode("utf-8"))
        return h.hexdigest()[:16]

    def _build_raw_request(self, flow: http.HTTPFlow) -> bytes:
        line = f"{flow.request.method} {flow.request.path} HTTP/{flow.request.http_version}\r\n".encode()
        headers = b"".join([f"{k}: {v}\r\n".encode() for k, v in flow.request.headers.items()])
        body = flow.request.raw_content or b""
        return line + headers + b"\r\n" + body

    def _build_raw_response(self, flow: http.HTTPFlow) -> bytes:
        if not flow.response:
            return b""
        line = f"HTTP/{flow.response.http_version} {flow.response.status_code} {flow.response.reason}\r\n".encode()
        headers = b"".join([f"{k}: {v}\r\n".encode() for k, v in flow.response.headers.items()])
        body = flow.response.raw_content or b""
        return line + headers + b"\r\n" + body

    # query/export API
    def query(self, q=None, method=None, host=None, ip=None, port=None, pid=None, exe=None, limit=500):
        res = list(self._flows.values())
        if q:
            ql = q.lower()
            res = [x for x in res if ql in x.host.lower() or ql in x.path.lower()]
        if method:
            res = [x for x in res if x.method.upper() == method.upper()]
        if host:
            res = [x for x in res if host.lower() in x.host.lower()]
        if ip:
            res = [x for x in res if x.client_ip == ip or x.server_ip == ip]
        if port:
            res = [x for x in res if x.client_port == port or x.server_port == port]
        if pid is not None:
            res = [x for x in res if x.pid == pid]
        if exe:
            res = [x for x in res if (x.exe or '').lower().endswith(exe.lower()) or (x.exe or '').lower() == exe.lower()]
        res.sort(key=lambda x: x.ts_start, reverse=True)
        # serialize
        out = []
        for x in res[:limit]:
            out.append({
                **x.__dict__,
                "ts_start": x.ts_start,
                "ts_end": x.ts_end,
            })
        return out

    def get(self, fid: str):
        x = self._flows.get(fid)
        return x.__dict__ if x else None

    def get_raw_request(self, fid: str) -> bytes | None:
        return self._raw_req.get(fid)

    def get_raw_response(self, fid: str) -> bytes | None:
        return self._raw_resp.get(fid)

    def export_har(self, path: Path):
        # Minimal HAR export
        entries = []
        for x in self._flows.values():
            entries.append({
                "startedDateTime": datetime.utcfromtimestamp(x.ts_start).isoformat()+"Z",
                "time": int(((x.ts_end or x.ts_start) - x.ts_start) * 1000),
                "request": {
                    "method": x.method,
                    "url": f"{x.scheme}://{x.host}{x.path}",
                    "httpVersion": x.http_version,
                    "headers": [{"name": k, "value": v} for k, v in (x.request_headers or {}).items()],
                },
                "response": {
                    "status": x.status_code or 0,
                    "httpVersion": x.http_version,
                    "headers": [{"name": k, "value": v} for k, v in (x.response_headers or {}).items()],
                },
                "_proc": {"pid": x.pid, "exe": x.exe},
                "serverIPAddress": x.server_ip,
            })
        har = {"log": {"version": "1.2", "creator": {"name": "PacketScope", "version": "0.1"}, "entries": entries}}
        path.write_text(json.dumps(har, indent=2), encoding="utf-8")
