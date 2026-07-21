#!/usr/bin/env python3
"""gRPC (grpcio) conformance client for the mymitm netns prototype.

Connects to <host:port> (the MITM-intercepted server address), trusting the
pinned leaf cert with the authority overridden to server.test. Exercises all
four RPC shapes and prints a structured <SHAPE>_OK line per success so the
shell driver can assert on them. Exits nonzero on any failure.

Timing checks:
  - ServerStream / BiDi assert incremental delivery (replies arrive spread out,
    not all buffered to the end) — a proxy that buffered the whole response
    would collapse the inter-arrival gaps.
"""
import argparse
import sys
import time

import grpc
import echo_pb2
import echo_pb2_grpc

STREAM_COUNT = 8
BIDI_MSGS = 5


def make_channel(args):
    with open(args.cafile, "rb") as f:
        ca = f.read()
    creds = grpc.ssl_channel_credentials(root_certificates=ca)
    options = (("grpc.ssl_target_name_override", args.server_name),)
    return grpc.secure_channel("%s:%d" % (args.host, args.port), creds, options=options)


def check_unary(stub):
    reply = stub.Unary(echo_pb2.EchoRequest(message="hello", seq=42), timeout=15)
    assert reply.message == "echo:hello", reply.message
    assert reply.seq == 42, reply.seq
    print("UNARY_OK", flush=True)


def check_server_stream(stub):
    t0 = time.monotonic()
    times = []
    replies = []
    for r in stub.ServerStream(echo_pb2.EchoRequest(message="x", seq=0), timeout=15):
        times.append(time.monotonic() - t0)
        replies.append(r)
    assert len(replies) == STREAM_COUNT, "got %d replies" % len(replies)
    assert [r.seq for r in replies] == list(range(STREAM_COUNT)), [r.seq for r in replies]
    # incremental: last arrival meaningfully after the first (server sleeps 50ms/msg)
    assert times[-1] - times[0] > 0.1, "server-stream not incremental: %r" % times
    print("SERVERSTREAM_OK spread=%.3fs" % (times[-1] - times[0]), flush=True)


def check_client_stream(stub):
    def gen():
        for i in range(4):
            yield echo_pb2.EchoRequest(message="c%d" % i, seq=i)
    reply = stub.ClientStream(gen(), timeout=15)
    assert reply.message == "agg:4:c3", reply.message
    assert reply.seq == 4, reply.seq
    print("CLIENTSTREAM_OK", flush=True)


def check_bidi(stub):
    # Full-duplex: feed requests one at a time with gaps, read replies as they
    # come back. Proves the single h2 stream carries both directions live.
    sent = []

    def gen():
        for i in range(BIDI_MSGS):
            sent.append("m%d" % i)
            yield echo_pb2.EchoRequest(message="m%d" % i, seq=i)
            time.sleep(0.05)

    t0 = time.monotonic()
    times = []
    got = []
    for r in stub.BiDi(gen(), timeout=15):
        times.append(time.monotonic() - t0)
        got.append(r)
    assert len(got) == BIDI_MSGS, "got %d bidi replies" % len(got)
    assert [r.message for r in got] == ["bidi:m%d" % i for i in range(BIDI_MSGS)], [r.message for r in got]
    assert [r.seq for r in got] == list(range(BIDI_MSGS)), [r.seq for r in got]
    assert times[-1] - times[0] > 0.1, "bidi not incremental: %r" % times
    print("BIDI_OK spread=%.3fs" % (times[-1] - times[0]), flush=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cafile", required=True)
    ap.add_argument("--host", required=True)
    ap.add_argument("--port", type=int, default=443)
    ap.add_argument("--server-name", default="server.test")
    args = ap.parse_args()

    ch = make_channel(args)
    # Fail fast if the channel never becomes ready.
    try:
        grpc.channel_ready_future(ch).result(timeout=15)
    except grpc.FutureTimeoutError:
        print("CHANNEL_NOT_READY", flush=True)
        return 2
    stub = echo_pb2_grpc.EchoStub(ch)

    try:
        check_unary(stub)
        check_server_stream(stub)
        check_client_stream(stub)
        check_bidi(stub)
    except AssertionError as e:
        print("ASSERT_FAILED: %s" % e, flush=True)
        return 1
    except grpc.RpcError as e:
        print("RPC_ERROR: %s %s" % (e.code(), e.details()), flush=True)
        return 1
    print("ALL_GRPC_OK", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
