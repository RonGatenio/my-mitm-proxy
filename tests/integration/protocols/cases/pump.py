#!/usr/bin/env python3
"""Byte-pipe correctness: concurrent full-duplex transfer, a mid-stream idle
gap, and 200 KiB each way (crosses the proxy's 16 KiB pump chunk). End-of-upload
is signaled at the application layer (SENTINEL) so no TLS half-close is needed."""
import os, socket, sys, threading, time
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import _util

C2S_BODY = (b"C2S-" * 50000)[:200000]
SENTINEL = b"<<C2S-END>>"
C2S = C2S_BODY + SENTINEL
S2C = (b"S2C-" * 50000)[:200000]
TRAILER = b"<<S2C-DONE>>"


def _serve_conn(tls):
    recv = bytearray()

    def reader():
        while True:
            try:
                d = tls.recv(65536)
            except OSError:
                break
            if not d:
                break
            recv.extend(d)
            if recv.endswith(SENTINEL):
                break

    rt = threading.Thread(target=reader); rt.start()
    try:
        half = len(S2C) // 2
        tls.sendall(S2C[:half])
        time.sleep(0.5)                 # idle mid-stream; must not time out
        tls.sendall(S2C[half:])
        rt.join(timeout=15)
        tls.sendall(TRAILER if bytes(recv) == C2S else b"<<S2C-BADUP>>")
    except OSError:
        pass
    finally:
        try:
            tls.close()
        except OSError:
            pass


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
        threading.Thread(target=_serve_conn, args=(tls,), daemon=True).start()


def run_client(a):
    ctx = _util.client_ctx(a.cafile)
    tls = _util.connect_tls(ctx, a.host, a.port, a.server_name, a.bind_addr, timeout=30)
    err = []

    def writer():
        try:
            tls.sendall(C2S)            # upload while the reader below downloads
        except OSError as e:
            err.append(str(e))

    wt = threading.Thread(target=writer); wt.start()
    recv = bytearray()
    while True:
        try:
            d = tls.recv(65536)
        except OSError:
            break
        if not d:
            break
        recv.extend(d)
        if recv.endswith(TRAILER):
            break
    wt.join(timeout=15)
    try:
        tls.close()
    except OSError:
        pass
    data = bytes(recv)
    if data == S2C + TRAILER:
        print(f"FORWARD_OK pump full-duplex+idle+large ({len(data)} B down, {len(C2S)} B up)"); return 0
    print(f"FORWARD_FAIL down={len(data)}/{len(S2C) + len(TRAILER)} err={err} tail={data[-16:]!r}"); return 1


def run_parse(a):
    _, c2s, s2c, _ = _util.read_conn(a.dump_dir)
    if c2s == C2S and s2c == S2C + TRAILER:
        print("DUMP_OK level=1 raw byte-exact both directions")
    else:
        print(f"DUMP_PARTIAL level=1 c2s={len(c2s)}/{len(C2S)} s2c={len(s2c)}/{len(S2C) + len(TRAILER)}")


if __name__ == "__main__":
    _util.case_main(run_server, run_client, run_parse)
