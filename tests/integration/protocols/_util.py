"""Shared helpers for protocol case modules. Dependency-free (stdlib + argparse)."""
import argparse, json, os, socket, ssl, sys


def server_ctx(cert, key):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=cert, keyfile=key)
    return ctx


def client_ctx(cafile):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.load_verify_locations(cafile=cafile)
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.check_hostname = True
    return ctx


def connect_tls(ctx, host, port, server_name, bind_addr=None, timeout=15):
    raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    raw.settimeout(timeout)
    if bind_addr:
        raw.bind((bind_addr, 0))
    raw.connect((host, port))
    return ctx.wrap_socket(raw, server_hostname=server_name)


def _read(path):
    try:
        with open(path, "rb") as fh:
            return fh.read()
    except FileNotFoundError:
        return b""


def read_conn(dump_dir):
    """(conn_id, c2s, s2c, record) for the FIRST connection in index.jsonl."""
    idx = os.path.join(dump_dir, "index.jsonl")
    rec = None
    with open(idx, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                rec = json.loads(line); break
    if rec is None:
        raise ValueError("empty index.jsonl")
    cid = rec.get("conn_id") or rec.get("id")
    return cid, _read(os.path.join(dump_dir, f"{cid}.c2s")), _read(os.path.join(dump_dir, f"{cid}.s2c")), rec


def records(dump_dir):
    """All index.jsonl records (multi-connection cases)."""
    idx = os.path.join(dump_dir, "index.jsonl")
    out = []
    if os.path.exists(idx):
        with open(idx, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    out.append(json.loads(line))
    return out


def case_main(server, client, parse):
    """Standard server/client/parse CLI shared by every simple case module."""
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="role", required=True)
    s = sub.add_parser("server")
    for f in ("--cert", "--key", "--bind", "--ready", "--peerfile"):
        s.add_argument(f, required=True)
    s.add_argument("--port", type=int, required=True)
    c = sub.add_parser("client")
    for f in ("--cafile", "--host", "--server-name"):
        c.add_argument(f, required=True)
    c.add_argument("--port", type=int, required=True)
    c.add_argument("--bind-addr", default=None)
    p = sub.add_parser("parse")
    p.add_argument("--dump-dir", required=True)
    a = ap.parse_args()
    if a.role == "server":
        server(a)
    elif a.role == "client":
        sys.exit(client(a) or 0)
    else:
        parse(a)
