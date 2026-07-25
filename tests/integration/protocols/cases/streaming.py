#!/usr/bin/env python3
"""Chunked, long-lived response streamed with gaps; client must see it arrive
incrementally (proves the byte pipe does not buffer-before-forward)."""
import http.client, os, sys, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import _util
from dumpparse.http1 import parse_exchange

CHUNKS = [b"chunk-%02d\n" % i for i in range(10)]
FULL = b"".join(CHUNKS)
GAP = 0.05


def run_server(a):
    peerfile = a.peerfile

    class H(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_GET(self):
            with open(peerfile, "a") as fh:
                fh.write(self.client_address[0] + "\n")
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            for c in CHUNKS:
                self.wfile.write(b"%X\r\n%b\r\n" % (len(c), c))
                self.wfile.flush()
                time.sleep(GAP)
            self.wfile.write(b"0\r\n\r\n"); self.wfile.flush()

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
    conn = http.client.HTTPSConnection(a.server_name, a.port, context=ctx, timeout=20)
    conn.sock = tls
    conn.request("GET", "/stream")
    r = conn.getresponse()
    buf = b""; times = []; t0 = time.monotonic()
    while True:
        d = r.read(16)
        if not d:
            break
        buf += d; times.append(time.monotonic() - t0)
    conn.close()
    spread = (times[-1] - times[0]) if len(times) > 1 else 0.0
    if r.status == 200 and buf == FULL and spread > 0.1:
        print(f"FORWARD_OK streaming incremental spread={spread:.2f}s"); return 0
    print(f"FORWARD_FAIL status={r.status} len={len(buf)}/{len(FULL)} spread={spread:.2f}"); return 1


def run_parse(a):
    _, c2s, s2c, _ = _util.read_conn(a.dump_dir)
    p = parse_exchange(c2s, s2c)
    if p.error:
        print(f"DUMP_FAIL {p.error}"); return
    if p.responses and p.responses[0].body == FULL:
        print(f"DUMP_OK level={p.level} dechunked {len(FULL)} bytes")
    else:
        print(f"DUMP_PARTIAL level={p.level} body={len(p.responses[0].body) if p.responses else 0}/{len(FULL)}")


if __name__ == "__main__":
    _util.case_main(run_server, run_client, run_parse)
