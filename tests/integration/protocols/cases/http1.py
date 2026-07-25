#!/usr/bin/env python3
"""HTTP/1.1 baseline: GET (small+large) + HEAD + POST over one keep-alive conn."""
import hashlib, http.client, os, sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import _util
from dumpparse.http1 import parse_exchange

LARGE_N = 100_000
SMALL_BODY = b"hello-http1"


def run_server(a):
    peerfile = a.peerfile

    class H(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def _record(self):
            with open(peerfile, "a") as fh:
                fh.write(self.client_address[0] + "\n")

        def _send(self, body, head_only=False):
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            if not head_only:
                self.wfile.write(body)

        def do_GET(self):
            self._record()
            self._send(b"X" * LARGE_N if self.path.startswith("/large") else SMALL_BODY)

        def do_HEAD(self):
            self._record(); self._send(SMALL_BODY, head_only=True)

        def do_POST(self):
            self._record()
            n = int(self.headers.get("Content-Length", "0"))
            data = self.rfile.read(n) if n else b""
            self._send(b"posted:" + hashlib.sha256(data).hexdigest().encode())

        def log_message(self, *a_):
            pass

    httpd = ThreadingHTTPServer((a.bind, a.port), H)
    httpd.socket = _util.server_ctx(a.cert, a.key).wrap_socket(httpd.socket, server_side=True)
    with open(a.ready, "w") as fh:
        fh.write("ready\n")
    httpd.serve_forever()


def run_client(a):
    ctx = _util.client_ctx(a.cafile)
    tls = _util.connect_tls(ctx, a.host, a.port, a.server_name, a.bind_addr)
    conn = http.client.HTTPSConnection(a.server_name, a.port, context=ctx, timeout=15)
    conn.sock = tls  # dial by IP with SNI=server_name, but keep Host: server_name
    out = []
    conn.request("GET", "/small");  r = conn.getresponse(); out.append((r.status, r.read()))
    conn.request("GET", "/large");  r = conn.getresponse(); out.append((r.status, len(r.read())))
    conn.request("HEAD", "/small"); r = conn.getresponse(); out.append((r.status, len(r.read())))
    payload = b"the-body-to-post"
    conn.request("POST", "/echo", body=payload, headers={"Content-Length": str(len(payload))})
    r = conn.getresponse(); out.append((r.status, r.read()))
    conn.close()

    want_post = b"posted:" + hashlib.sha256(payload).hexdigest().encode()
    ok = (out[0] == (200, SMALL_BODY) and out[1] == (200, LARGE_N)
          and out[2] == (200, 0) and out[3] == (200, want_post))
    if ok:
        print("FORWARD_OK http1 get/large/head/post keep-alive"); return 0
    print(f"FORWARD_FAIL out={out}"); return 1


def run_parse(a):
    _, c2s, s2c, _ = _util.read_conn(a.dump_dir)
    p = parse_exchange(c2s, s2c)
    if p.error:
        print(f"DUMP_FAIL {p.error}"); return
    methods = [r.method for r in p.requests]
    statuses = [r.status for r in p.responses]
    if len(p.requests) >= 4 and statuses[:4] == [200, 200, 200, 200]:
        print(f"DUMP_OK level={p.level} reqs={methods} statuses={statuses}")
    else:
        print(f"DUMP_PARTIAL level={p.level} reqs={methods} statuses={statuses}")


if __name__ == "__main__":
    _util.case_main(run_server, run_client, run_parse)
