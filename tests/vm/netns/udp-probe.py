#!/usr/bin/env python3
"""One-datagram UDP reachability probe for tests/vm/validate-netns.sh.

The routing rule that steers the client's traffic into the namespace must be
narrowed to TCP <server_port>. Anything else addressed to the same server that
enters the namespace dies there -- ip_forward is 0 inside it, and the classifiers
only rewrite TCP -- which is what silently blackholed an RD Gateway's UDP 3391
transport before the steer was scoped. This probe is how the harness proves that
traffic still reaches the server.

Python because it is the one interpreter both A and C are guaranteed to have
(C already runs the test TLS server on it); nc/socat are not installed.

    udp-probe.py listen <port> <outfile>   write the first datagram's payload
                                           to <outfile>, then exit
    udp-probe.py send <ip> <port> <text>   send <text> as a datagram
"""
import socket
import sys

LISTEN_TIMEOUT = 120  # generous: the caller polls <outfile> and gives up first


def main(argv):
    if len(argv) == 4 and argv[1] == "listen":
        port, out = int(argv[2]), argv[3]
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("0.0.0.0", port))
        s.settimeout(LISTEN_TIMEOUT)
        try:
            data, _ = s.recvfrom(4096)
        except socket.timeout:
            return 1
        with open(out, "wb") as f:
            f.write(data)
        return 0

    if len(argv) == 5 and argv[1] == "send":
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        payload = argv[4].encode()
        # Three copies. UDP is unreliable by design, and a single dropped
        # datagram would read here as "the steer blackholed it" -- the exact
        # false negative this probe must not manufacture.
        for _ in range(3):
            s.sendto(payload, (argv[2], int(argv[3])))
        return 0

    sys.stderr.write(__doc__)
    return 2


sys.exit(main(sys.argv))
