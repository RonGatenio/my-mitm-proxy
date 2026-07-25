#!/usr/bin/env python3
"""Controllable TLS client for the bash-orchestrated lifecycle scenarios."""
import argparse, os, sys, time
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import _util


def _get(tls, path, server_name):
    try:
        tls.sendall(b"GET " + path.encode() + b" HTTP/1.1\r\nHost: "
                    + server_name.encode() + b"\r\nConnection: keep-alive\r\n\r\n")
        tls.settimeout(5)
        data = b""
        while b"\r\n\r\n" not in data:
            d = tls.recv(4096)
            if not d:
                break
            data += d
        return data
    except OSError:
        return None


def cmd_once(a):
    ctx = _util.client_ctx(a.cafile)
    try:
        tls = _util.connect_tls(ctx, a.host, a.port, a.server_name, a.bind_addr)
    except OSError as e:
        print(f"FORWARD_FAIL connect: {e}"); return 1
    resp = _get(tls, "/once", a.server_name)
    try:
        tls.close()
    except OSError:
        pass
    if resp and b" 200 " in resp:
        print("FORWARD_OK newconn intercepted"); return 0
    print(f"FORWARD_FAIL resp={resp!r}"); return 1


def cmd_hold(a):
    ctx = _util.client_ctx(a.cafile)
    try:
        tls = _util.connect_tls(ctx, a.host, a.port, a.server_name, a.bind_addr)
    except OSError as e:
        print(f"HOLD_CONNECT_FAIL {e}"); return 1
    first = _get(tls, "/first", a.server_name)
    if not (first and b" 200 " in first):
        print(f"HOLD_INITIAL_FAIL resp={first!r}")
        try:
            tls.close()
        except OSError:
            pass
        return 1
    with open(a.connected, "w") as fh:
        fh.write("ok\n")
    for _ in range(200):
        if os.path.exists(a.go):
            break
        time.sleep(0.1)
    second = _get(tls, "/second", a.server_name)
    try:
        tls.close()
    except OSError:
        pass
    if second and b" 200 " in second:
        print("SECOND_OK"); return 0
    print("SECOND_RESET"); return 2


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("once", "hold"):
        s = sub.add_parser(name)
        for f in ("--cafile", "--host", "--server-name"):
            s.add_argument(f, required=True)
        s.add_argument("--port", type=int, required=True)
        s.add_argument("--bind-addr", default=None)
        if name == "hold":
            s.add_argument("--connected", required=True)
            s.add_argument("--go", required=True)
    a = ap.parse_args()
    sys.exit(cmd_once(a) if a.cmd == "once" else cmd_hold(a))


if __name__ == "__main__":
    main()
