#!/usr/bin/env python3
"""Fake upstream TLS server for the mymitm netns e2e test.

Runs inside netns "srv" bound to 192.168.1.50:443. For each accepted
connection it RECORDS the peer source IP it observes (this is the core
source-IP-preservation proof) and serves a fixed response body.

Every accepted connection's peer IP is APPENDED (one per line) to --peerfile
so the driver can assert that both expected client IPs appear (e.g. 10.8.0.5
and 10.8.0.9) and that the box IP (192.168.1.10) does NOT appear.
"""
import argparse
import socket
import ssl
import sys

EXPECTED_REQUEST = b"PING-FROM-CLIENT"
RESPONSE_BODY = b"PONG-FROM-SERVER"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cert", required=True)
    ap.add_argument("--key", required=True)
    ap.add_argument("--bind", default="192.168.1.50")
    ap.add_argument("--port", type=int, default=443)
    ap.add_argument("--peerfile", required=True)
    ap.add_argument("--readyfile", required=True)
    args = ap.parse_args()

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=args.cert, keyfile=args.key)

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((args.bind, args.port))
    srv.listen(8)

    # Signal readiness only after we are actually listening.
    with open(args.readyfile, "w") as f:
        f.write("ready\n")
    print(f"[fake_server] listening on {args.bind}:{args.port}", flush=True)

    while True:
        raw, peer = srv.accept()
        peer_ip = peer[0]
        print(f"[fake_server] connection from peer={peer_ip}", flush=True)
        # Append the peer IP (one per line) so the driver can assert all
        # expected client IPs appear across multi-client runs.
        with open(args.peerfile, "a") as f:
            f.write(peer_ip + "\n")
        try:
            tls = ctx.wrap_socket(raw, server_side=True)
        except ssl.SSLError as e:
            print(f"[fake_server] TLS error: {e}", flush=True)
            raw.close()
            continue
        try:
            data = tls.recv(4096)
            print(f"[fake_server] recv {data!r}", flush=True)
            tls.sendall(RESPONSE_BODY)
        except OSError as e:
            print(f"[fake_server] io error: {e}", flush=True)
        finally:
            try:
                tls.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            tls.close()
        # Keep serving — the multi-client test sends two connections.


if __name__ == "__main__":
    sys.exit(main())
