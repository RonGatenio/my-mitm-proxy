#!/usr/bin/env python3
"""Keep-alive: >=5 requests on ONE connection; the dump parser must walk all."""
import http.client, os, sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import _util
from dumpparse.http1 import parse_exchange

N_REQ = 5


def run_server(a):
    peerfile = a.peerfile

    class H(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_GET(self):
            with open(peerfile, "a") as fh:
                fh.write(self.client_address[0] + "\n")
            body = ("resp" + self.path).encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

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
    conn.sock = tls
    statuses = []
    for i in range(N_REQ):
        conn.request("GET", f"/{i}")
        r = conn.getresponse()
        body = r.read()
        statuses.append((r.status, body == f"resp/{i}".encode()))
    conn.close()
    if len(statuses) == N_REQ and all(s == 200 and okbody for s, okbody in statuses):
        print(f"FORWARD_OK keepalive {N_REQ} requests one connection"); return 0
    print(f"FORWARD_FAIL statuses={statuses}"); return 1


def run_parse(a):
    _, c2s, s2c, _ = _util.read_conn(a.dump_dir)
    p = parse_exchange(c2s, s2c)
    if p.error:
        print(f"DUMP_FAIL {p.error}"); return
    if len(p.requests) >= N_REQ and len([r for r in p.responses if r.status == 200]) >= N_REQ:
        print(f"DUMP_OK level={p.level} walked {len(p.requests)} reqs / {len(p.responses)} resps")
    else:
        print(f"DUMP_PARTIAL level={p.level} reqs={len(p.requests)} resps={len(p.responses)}")


if __name__ == "__main__":
    _util.case_main(run_server, run_client, run_parse)
