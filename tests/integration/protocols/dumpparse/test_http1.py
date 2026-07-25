from dumpparse.http1 import parse_exchange


def test_single_get():
    c2s = b"GET /hello HTTP/1.1\r\nHost: server.test\r\n\r\n"
    s2c = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Type: text/plain\r\n\r\nhello"
    p = parse_exchange(c2s, s2c)
    assert p.error == ""
    assert len(p.requests) == 1 and p.requests[0].method == "GET" and p.requests[0].target == "/hello"
    assert len(p.responses) == 1 and p.responses[0].status == 200 and p.responses[0].body == b"hello"
    assert p.level == 2


def test_keepalive_three():
    req = b"GET /a HTTP/1.1\r\nHost: h\r\n\r\n"
    c2s = req.replace(b"/a", b"/1") + req.replace(b"/a", b"/2") + req.replace(b"/a", b"/3")
    s2c = b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nX" * 3
    p = parse_exchange(c2s, s2c)
    assert [r.target for r in p.requests] == ["/1", "/2", "/3"]
    assert len(p.responses) == 3 and all(r.status == 200 for r in p.responses)


def test_chunked_response_dechunked():
    c2s = b"GET / HTTP/1.1\r\nHost: h\r\n\r\n"
    s2c = (b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
           b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n")
    p = parse_exchange(c2s, s2c)
    assert p.responses[0].body == b"hello world"   # dechunked -> L2
    assert p.level == 2


def test_http10_eof_body():
    c2s = b"GET / HTTP/1.0\r\n\r\n"
    s2c = b"HTTP/1.0 200 OK\r\n\r\nbody-until-eof"   # no CL; EOF-delimited
    p = parse_exchange(c2s, s2c)
    assert p.responses[0].status == 200 and p.responses[0].body == b"body-until-eof"


def test_head_no_body():
    c2s = b"HEAD / HTTP/1.1\r\nHost: h\r\n\r\n"
    s2c = b"HTTP/1.1 200 OK\r\nContent-Length: 99\r\n\r\n"   # HEAD: no body despite CL
    p = parse_exchange(c2s, s2c)
    assert p.requests[0].method == "HEAD" and p.responses[0].body == b""


def test_garbage_is_error_not_crash():
    p = parse_exchange(b"\x00\x01not http", b"\xff\xfe")
    assert p.error != "" or (not p.requests and not p.responses)
