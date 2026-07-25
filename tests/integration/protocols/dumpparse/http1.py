"""Reconstruct HTTP/1.x messages from the proxy's raw decrypted dump bytes.

The proxy is a byte pipe: `<conn>.c2s` is the exact client->server plaintext,
`<conn>.s2c` the server->client plaintext. We re-parse those blobs with h11 (a
sans-IO HTTP/1.1 state machine) to prove the dump is *parseable*: every request
and response across a keep-alive/pipelined connection is recovered with framing
decoded (dechunked / Content-Length / EOF body).

Response framing depends on the request method (HEAD/204/304 -> no body). The
two streams are dumped independently, so we parse requests first, then drive an
h11 CLIENT with synthetic requests carrying the real methods.
"""
from dataclasses import dataclass, field
from typing import List, Tuple
import h11


@dataclass
class Message:
    kind: str
    method: str = ""
    target: str = ""
    status: int = 0
    reason: str = ""
    http_version: str = ""
    headers: List[Tuple[str, str]] = field(default_factory=list)
    body: bytes = b""
    informational: List[int] = field(default_factory=list)

    def header(self, name: str):
        name = name.lower()
        for k, v in self.headers:
            if k.lower() == name:
                return v
        return None


@dataclass
class Parsed:
    requests: List[Message] = field(default_factory=list)
    responses: List[Message] = field(default_factory=list)
    level: int = 0
    error: str = ""


def _hdrs(headers):
    return [(k.decode("latin-1"), v.decode("latin-1")) for (k, v) in headers]


def _parse_requests(c2s: bytes) -> List[Message]:
    conn = h11.Connection(h11.SERVER)
    conn.receive_data(c2s)
    conn.receive_data(b"")
    out, cur = [], None
    while True:
        try:
            ev = conn.next_event()
        except h11.RemoteProtocolError:
            break
        if ev is h11.NEED_DATA or ev is h11.PAUSED:
            break
        if isinstance(ev, h11.Request):
            cur = Message("request", method=ev.method.decode("ascii"),
                          target=ev.target.decode("latin-1"),
                          http_version=ev.http_version.decode("ascii"),
                          headers=_hdrs(ev.headers))
        elif isinstance(ev, h11.Data):
            if cur is not None:
                cur.body += bytes(ev.data)
        elif isinstance(ev, h11.EndOfMessage):
            if cur is not None:
                out.append(cur); cur = None
            # Advance our (server) state with a synthetic response so h11 will
            # permit the next cycle and we can parse further pipelined requests.
            try:
                conn.send(h11.Response(status_code=200, headers=[("Content-Length", "0")]))
                conn.send(h11.EndOfMessage())
                conn.start_next_cycle()
            except h11.LocalProtocolError:
                break
        elif isinstance(ev, h11.ConnectionClosed):
            break
    return out


def _parse_responses(s2c: bytes, methods: List[str]) -> List[Message]:
    conn = h11.Connection(h11.CLIENT)
    conn.receive_data(s2c)
    conn.receive_data(b"")
    out, cur, pending = [], None, []
    idx = 0

    def send_request(method):
        conn.send(h11.Request(method=method, target="/",
                              headers=[("Host", "x"), ("Content-Length", "0")]))
        conn.send(h11.EndOfMessage())

    if methods:
        send_request(methods[0]); idx = 1
    while True:
        try:
            ev = conn.next_event()
        except h11.RemoteProtocolError:
            break
        if ev is h11.NEED_DATA or ev is h11.PAUSED:
            break
        if isinstance(ev, h11.InformationalResponse):
            pending.append(ev.status_code)
        elif isinstance(ev, h11.Response):
            cur = Message("response", status=ev.status_code,
                          reason=(ev.reason or b"").decode("latin-1"),
                          http_version=ev.http_version.decode("ascii"),
                          headers=_hdrs(ev.headers), informational=list(pending))
            pending = []
        elif isinstance(ev, h11.Data):
            if cur is not None:
                cur.body += bytes(ev.data)
        elif isinstance(ev, h11.EndOfMessage):
            if cur is not None:
                out.append(cur); cur = None
            try:
                conn.start_next_cycle()
            except h11.LocalProtocolError:
                break
            if idx < len(methods):
                send_request(methods[idx]); idx += 1
        elif isinstance(ev, h11.ConnectionClosed):
            break
    return out


def parse_exchange(c2s: bytes, s2c: bytes) -> Parsed:
    p = Parsed()
    try:
        p.requests = _parse_requests(c2s)
        methods = [m.method for m in p.requests] or ["GET"]
        p.responses = _parse_responses(s2c, methods)
    except Exception as e:
        p.error = f"{type(e).__name__}: {e}"
        return p
    if p.requests or p.responses:
        p.level = 2 if any(m.body for m in p.requests + p.responses) else 1
    return p
