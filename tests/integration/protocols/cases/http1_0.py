#!/usr/bin/env python3
"""HTTP/1.0: response body delimited by connection close (no Content-Length)."""
import os, socket, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import _util
from dumpparse.http1 import parse_exchange

BODY = b"http10-eof-delimited-body-payload"


def run_server(a):
    ctx = _util.server_ctx(a.cert, a.key)
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((a.bind, a.port)); srv.listen(8)
    with open(a.ready, "w") as fh:
        fh.write("ready\n")
    while True:
        raw, peer = srv.accept()
        with open(a.peerfile, "a") as fh:
            fh.write(peer[0] + "\n")
        try:
            tls = ctx.wrap_socket(raw, server_side=True)
        except OSError:
            raw.close(); continue
        try:
            tls.recv(4096)  # consume request line/headers
            # HTTP/1.0, no Content-Length: body ends when we close the socket.
            tls.sendall(b"HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\n\r\n" + BODY)
        except OSError:
            pass
        finally:
            try:
                tls.close()  # close == EOF that delimits the body
            except OSError:
                pass


def run_client(a):
    ctx = _util.client_ctx(a.cafile)
    tls = _util.connect_tls(ctx, a.host, a.port, a.server_name, a.bind_addr)
    tls.sendall(b"GET / HTTP/1.0\r\nHost: " + a.server_name.encode() + b"\r\n\r\n")
    chunks = []
    while True:
        d = tls.recv(4096)
        if not d:
            break
        chunks.append(d)
    tls.close()
    resp = b"".join(chunks)
    if resp.startswith(b"HTTP/1.0 200") and resp.endswith(BODY):
        print("FORWARD_OK http1.0 eof-delimited body"); return 0
    print(f"FORWARD_FAIL got={resp[:80]!r}"); return 1


def run_parse(a):
    _, c2s, s2c, _ = _util.read_conn(a.dump_dir)
    p = parse_exchange(c2s, s2c)
    if p.error:
        print(f"DUMP_FAIL {p.error}"); return
    if p.responses and p.responses[0].status == 200 and p.responses[0].body == BODY:
        print(f"DUMP_OK level={p.level}")
    else:
        print(f"DUMP_PARTIAL level={p.level} resp={[(r.status, len(r.body)) for r in p.responses]}")


if __name__ == "__main__":
    _util.case_main(run_server, run_client, run_parse)
