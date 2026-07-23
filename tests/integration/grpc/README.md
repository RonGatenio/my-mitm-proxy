# gRPC end-to-end conformance (netns)

Proves the byte-relay + ALPN-mirror MITM (`mymitm`) carries a **real grpcio**
conversation end-to-end for all four RPC shapes — unary, server-streaming,
client-streaming, and **bidirectional (full-duplex)** — with ALPN negotiated as
`h2` on both TLS legs and the decrypted HTTP/2 bytes teed to the dump.

This is the fast counterpart to the qemu VM `h2` target: it runs the **real
static musl release binary** against the eBPF data plane inside network
namespaces (~15s), so it's the primary gRPC regression gate.

## Run

```sh
# build the binary once
cargo build -p mymitm --release --target x86_64-unknown-linux-musl
# run the test (root: it creates netns/veths and attaches eBPF)
sudo bash tests/integration/grpc/run_grpc_netns.sh
```

The driver is self-bootstrapping: on first run it creates `.venv/` with
`grpcio` + `grpcio-tools` (needs `python3-venv` and network) and regenerates the
`echo_pb2*.py` stubs from `echo.proto`. Both `.venv/` and the generated stubs
are gitignored.

## What is asserted

1. All four RPC shapes succeed; server-stream and bidi arrive **incrementally**
   (inter-arrival spread > 0.1s), proving the relay never buffers a whole
   direction. gRPC status `OK` is implicit — grpcio raises on any non-OK trailer.
2. The proxy logs `upstream=h2 downstream=h2` (ALPN mirrored on both legs).
3. The decrypted dump contains the HTTP/2 client preface (`PRI * HTTP/2.0`),
   confirming genuine h2 bytes were relayed and teed.

## Files

- `echo.proto` — the four-shape Echo service.
- `grpc_server.py` / `grpc_client.py` — grpcio server/client (server pins the
  leaf cert; client trusts it with the authority overridden to `server.test`).
- `run_grpc_netns.sh` — topology + proxy launch + assertions (mirrors
  `../run_e2e.sh`'s eBPF single-client setup).
