
# ----------
# File: addons/faker.py
# ----------
from __future__ import annotations
import asyncio
import re
from dataclasses import dataclass
from typing import Optional
from mitmproxy import http

@dataclass
class Rule:
    name: str
    host_re: Optional[str] = None
    path_re: Optional[str] = None
    method: Optional[str] = None
    delay_ms: int = 0
    status_code: int = 200
    headers: dict[str, str] = None
    body: bytes = b""

class FakeResponder:
    def __init__(self):
        self.rules: list[Rule] = []

    def add_rule(self, r: Rule):
        # replace if name exists
        self.rules = [x for x in self.rules if x.name != r.name] + [r]

    def remove_rule(self, name: str) -> bool:
        n = len(self.rules)
        self.rules = [x for x in self.rules if x.name != name]
        return len(self.rules) != n

    async def request(self, flow: http.HTTPFlow):
        # apply first matching rule
        for r in self.rules:
            if r.method and flow.request.method.upper() != r.method.upper():
                continue
            if r.host_re and not re.search(r.host_re, flow.request.host):
                continue
            if r.path_re and not re.search(r.path_re, flow.request.path):
                continue
            if r.delay_ms:
                await asyncio.sleep(r.delay_ms/1000)
            flow.response = http.Response.make(
                r.status_code,
                r.body or b"",
                r.headers or {},
            )
            flow.metadata["faked_by"] = r.name
            return
