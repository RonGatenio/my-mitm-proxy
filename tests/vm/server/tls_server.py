#!/usr/bin/env python3
"""Minimal HTTPS server for the VM harness.

Serves 200/MITM-OK for any GET and records the peer IP + path so the harness
can assert source-IP preservation. Stdlib only (present in Ubuntu cloud images).
"""
import argparse
import http.server
import ssl
import sys


def make_handler(logfile):
    class Handler(http.server.BaseHTTPRequestHandler):
        def _record(self):
            peer = self.client_address[0]
            line = "%s %s\n" % (peer, self.path)
            sys.stderr.write("PEER " + line)
            sys.stderr.flush()
            if logfile:
                with open(logfile, "a") as fh:
                    fh.write(line)
            return peer

        def do_GET(self):
            peer = self._record()
            body = ("MITM-OK path=%s peer=%s\n" % (self.path, peer)).encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass  # silence default stderr access log; we log our own line

    return Handler


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cert", required=True)
    ap.add_argument("--key", required=True)
    ap.add_argument("--bind", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=443)
    ap.add_argument("--logfile")
    args = ap.parse_args()

    httpd = http.server.HTTPServer((args.bind, args.port), make_handler(args.logfile))
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(args.cert, args.key)
    httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
    sys.stderr.write("LISTENING %s:%d\n" % (args.bind, args.port))
    sys.stderr.flush()
    httpd.serve_forever()


if __name__ == "__main__":
    main()
