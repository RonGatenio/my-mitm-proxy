from dumpparse.eventstream import parse_events


def test_basic_events():
    body = (b": stream open\n\n"
            b"event: greeting\ndata: hello\nid: 1\n\n"
            b"data: line-a\ndata: line-b\n\n"
            b"retry: 3000\ndata: last\n\n")
    ev = parse_events(body)
    assert len(ev) == 3
    assert ev[0]["event"] == "greeting" and ev[0]["data"] == "hello" and ev[0]["id"] == "1"
    assert ev[0]["comments"] == []
    assert ev[1]["data"] == "line-a\nline-b"     # multi-line data joined by \n
    assert ev[2]["retry"] == "3000" and ev[2]["data"] == "last"


def test_leading_comment_only_block_is_not_an_event():
    ev = parse_events(b": just a comment\n\ndata: x\n\n")
    assert len(ev) == 1 and ev[0]["data"] == "x"


def test_count_matches_expected():
    body = b"".join(b"data: %d\n\n" % i for i in range(10))
    assert len(parse_events(body)) == 10
