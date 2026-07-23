#!/usr/bin/env python3
"""Real gRPC (grpcio) echo server for the mymitm netns conformance prototype.

Serves the four RPC shapes over TLS with ALPN=h2 (grpc-core negotiates h2
itself). Runs in netns "srv" bound to 192.168.1.50:443 behind the MITM. The
proxy relays the decrypted HTTP/2 bytes verbatim; this server proves the far
end sees a well-formed gRPC conversation for every shape.
"""
import argparse
import sys
import time
from concurrent import futures

import grpc
import echo_pb2
import echo_pb2_grpc

STREAM_COUNT = 8  # server-stream / bidi reply count


class EchoServicer(echo_pb2_grpc.EchoServicer):
    def Unary(self, request, context):
        return echo_pb2.EchoReply(message="echo:" + request.message, seq=request.seq)

    def ServerStream(self, request, context):
        # Incremental delivery: small gaps so a buffering proxy would be visible.
        for i in range(STREAM_COUNT):
            yield echo_pb2.EchoReply(message="stream:" + request.message, seq=i)
            time.sleep(0.05)

    def ClientStream(self, request_iterator, context):
        count = 0
        last = ""
        for req in request_iterator:
            count += 1
            last = req.message
        return echo_pb2.EchoReply(message="agg:%d:%s" % (count, last), seq=count)

    def BiDi(self, request_iterator, context):
        # Full-duplex: echo each request as it arrives, interleaved.
        for req in request_iterator:
            yield echo_pb2.EchoReply(message="bidi:" + req.message, seq=req.seq)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cert", required=True)
    ap.add_argument("--key", required=True)
    ap.add_argument("--bind", default="192.168.1.50")
    ap.add_argument("--port", type=int, default=443)
    ap.add_argument("--readyfile", required=True)
    args = ap.parse_args()

    with open(args.key, "rb") as f:
        key = f.read()
    with open(args.cert, "rb") as f:
        crt = f.read()
    creds = grpc.ssl_server_credentials([(key, crt)])

    server = grpc.server(futures.ThreadPoolExecutor(max_workers=8))
    echo_pb2_grpc.add_EchoServicer_to_server(EchoServicer(), server)
    server.add_secure_port("%s:%d" % (args.bind, args.port), creds)
    server.start()
    with open(args.readyfile, "w") as f:
        f.write("ready\n")
    print("[grpc_server] listening on %s:%d" % (args.bind, args.port), flush=True)
    server.wait_for_termination()


if __name__ == "__main__":
    sys.exit(main())
