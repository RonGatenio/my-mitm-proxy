#!/usr/bin/env python3
"""TLS client for the mymitm netns e2e test.

Runs inside netns "cli" (source IP 10.8.0.5). Connects to 192.168.1.50:443.
Because the eBPF cls_tun program DNATs the flow to the proxy's local listener,
the TLS the client actually terminates is the proxy's REAL leaf cert. The
client PINS/TRUSTS that genuine cert (loaded as the CA file) so assertion 1 is
a real cryptographic trust check, not verification-disabled.

Sends EXPECTED_REQUEST, reads the response, prints it, and exits 0 on success.
"""
import argparse
import socket
import ssl
import sys

REQUEST = b"PING-FROM-CLIENT"
EXPECTED_RESPONSE = b"PONG-FROM-SERVER"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cafile", required=True, help="genuine leaf cert, trusted as CA")
    ap.add_argument("--host", default="192.168.1.50")
    ap.add_argument("--port", type=int, default=443)
    ap.add_argument("--server-name", default="server.test", help="SNI / cert CN to verify")
    args = ap.parse_args()

    # Real cert verification: trust ONLY the genuine leaf cert.
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.load_verify_locations(cafile=args.cafile)
    ctx.verify_mode = ssl.CERT_REQUIRED
    # The cert CN/SAN is server.test; we connect by IP, so check the hostname
    # against the SNI name we send (server_hostname), which the cert matches.
    ctx.check_hostname = True

    raw = socket.create_connection((args.host, args.port), timeout=10)
    try:
        tls = ctx.wrap_socket(raw, server_hostname=args.server_name)
    except ssl.SSLError as e:
        print(f"HANDSHAKE_FAILED: {e}", flush=True)
        return 2

    peer_cert = tls.getpeercert()
    print(f"HANDSHAKE_OK peer_cert_subject={peer_cert.get('subject')}", flush=True)

    tls.sendall(REQUEST)
    resp = tls.recv(4096)
    print(f"RESPONSE={resp!r}", flush=True)
    tls.close()

    if resp != EXPECTED_RESPONSE:
        print(f"BAD_RESPONSE expected={EXPECTED_RESPONSE!r} got={resp!r}", flush=True)
        return 3
    print("CLIENT_OK", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
