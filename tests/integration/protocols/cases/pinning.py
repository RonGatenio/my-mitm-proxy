#!/usr/bin/env python3
"""Cert-pinning / HSTS win: the proxy presents the GENUINE leaf, so a whole-cert
pin matches (a forging MITM's cert would not). HSTS header forwarded verbatim."""
import http.client, os, ssl, sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import _util
from dumpparse.http1 import parse_exchange

HSTS = "max-age=31536000; includeSubDomains"
BODY = b"pinned-ok"


def run_server(a):
    peerfile = a.peerfile

    class H(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_GET(self):
            with open(peerfile, "a") as fh:
                fh.write(self.client_address[0] + "\n")
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Strict-Transport-Security", HSTS)
            self.send_header("Content-Length", str(len(BODY)))
            self.end_headers(); self.wfile.write(BODY)

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
    presented = tls.getpeercert(binary_form=True)
    with open(a.cafile) as fh:
        expected = ssl.PEM_cert_to_DER_cert(fh.read())
    pin_ok = presented == expected
    conn = http.client.HTTPSConnection(a.server_name, a.port, context=ctx, timeout=15)
    conn.sock = tls
    conn.request("GET", "/")
    r = conn.getresponse(); body = r.read()
    hsts = r.getheader("Strict-Transport-Security")
    conn.close()
    if pin_ok and r.status == 200 and body == BODY and hsts == HSTS:
        print("FORWARD_OK pinning genuine-leaf pin matched + HSTS present"); return 0
    print(f"FORWARD_FAIL pin_ok={pin_ok} status={r.status} hsts={hsts!r}"); return 1


def run_parse(a):
    _, c2s, s2c, _ = _util.read_conn(a.dump_dir)
    p = parse_exchange(c2s, s2c)
    if p.error:
        print(f"DUMP_FAIL {p.error}"); return
    if (p.responses and p.responses[0].status == 200
            and p.responses[0].header("strict-transport-security") == HSTS):
        print(f"DUMP_OK level={p.level} HSTS header recovered from dump")
    else:
        print(f"DUMP_PARTIAL level={p.level}")


if __name__ == "__main__":
    _util.case_main(run_server, run_client, run_parse)
