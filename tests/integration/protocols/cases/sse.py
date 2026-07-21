#!/usr/bin/env python3
"""Server-Sent Events over HTTP/1.1: incremental text/event-stream delivery,
then parse the dumped body back into events. Passing is a differentiator vs
mitmproxy (which buffers + warns on SSE)."""
import http.client, os, sys, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import _util
from dumpparse.http1 import parse_exchange
from dumpparse.eventstream import parse_events

N_EVENTS = 10
GAP = 0.03


def run_server(a):
    peerfile = a.peerfile

    class H(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_GET(self):
            with open(peerfile, "a") as fh:
                fh.write(self.client_address[0] + "\n")
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()

            def w(b):
                self.wfile.write(b"%X\r\n%b\r\n" % (len(b), b)); self.wfile.flush()

            w(b": stream open\n\n")
            for i in range(N_EVENTS):
                w(b"event: tick\ndata: %d\nid: %d\n\n" % (i, i))
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
    tls = _util.connect_tls(ctx, a.host, a.port, a.server_name, a.bind_addr, timeout=20)
    conn = http.client.HTTPSConnection(a.server_name, a.port, context=ctx, timeout=20)
    conn.sock = tls
    conn.request("GET", "/events")
    r = conn.getresponse()
    buf = b""; times = []; t0 = time.monotonic()
    while True:
        d = r.read(32)
        if not d:
            break
        buf += d; times.append(time.monotonic() - t0)
    conn.close()
    ticks = [e for e in parse_events(buf) if e["event"] == "tick"]
    spread = (times[-1] - times[0]) if len(times) > 1 else 0.0
    if r.status == 200 and len(ticks) >= N_EVENTS and spread > 0.1:
        print(f"FORWARD_OK sse {len(ticks)} events spread={spread:.2f}s"); return 0
    print(f"FORWARD_FAIL status={r.status} ticks={len(ticks)}/{N_EVENTS} spread={spread:.2f}"); return 1


def run_parse(a):
    _, c2s, s2c, _ = _util.read_conn(a.dump_dir)
    p = parse_exchange(c2s, s2c)
    if p.error:
        print(f"DUMP_FAIL {p.error}"); return
    if not p.responses or "event-stream" not in (p.responses[0].header("content-type") or ""):
        print(f"DUMP_PARTIAL level={p.level} not-event-stream"); return
    ticks = [e for e in parse_events(p.responses[0].body) if e["event"] == "tick"]
    if len(ticks) >= N_EVENTS:
        print(f"DUMP_OK level={p.level} parsed {len(ticks)} SSE events")
    else:
        print(f"DUMP_PARTIAL level={p.level} ticks={len(ticks)}/{N_EVENTS}")


if __name__ == "__main__":
    _util.case_main(run_server, run_client, run_parse)
