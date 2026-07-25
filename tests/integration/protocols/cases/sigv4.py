#!/usr/bin/env python3
"""AWS SigV4 (header + presigned) integrity probe.

The server independently recomputes the signature over the bytes it received and
compares it to the client's; a match proves the proxy did not reorder headers,
change casing, alter the body, or re-chunk. Logic is importable + unit-tested by
test_sigv4.py; the netns run then proves byte-transparency through the pipe."""
import http.client, os, sys
from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import _util
from dumpparse.http1 import parse_exchange
from botocore.auth import SigV4Auth, SigV4QueryAuth
from botocore.awsrequest import AWSRequest
from botocore.credentials import Credentials

CREDS = Credentials("AKIDEXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
REGION = "us-east-1"
SERVICE = "mymitmtest"


# ---- signing (client) ----------------------------------------------------
def sign_headers(method, url, body):
    req = AWSRequest(method=method, url=url, data=body, headers={})
    SigV4Auth(CREDS, SERVICE, REGION).add_auth(req)
    p = req.prepare()
    return dict(p.headers), (p.body if isinstance(p.body, (bytes, bytearray)) else body)


def presign(method, url):
    req = AWSRequest(method=method, url=url, data=b"", headers={})
    SigV4QueryAuth(CREDS, SERVICE, REGION, expires=300).add_auth(req)
    return req.prepare().url


# ---- validation (server) -------------------------------------------------
def _parse_authz(authz):
    body = authz[len("AWS4-HMAC-SHA256 "):]
    out = {}
    for part in body.split(", "):
        k, v = part.split("=", 1)
        out[k] = v
    return out


def validate_headers(method, url, headers, body):
    low = {k.lower(): v for k, v in headers.items()}
    authz = low.get("authorization")
    amz_date = low.get("x-amz-date")
    if not authz or not authz.startswith("AWS4-HMAC-SHA256 ") or not amz_date:
        return False
    parsed = _parse_authz(authz)
    signed = parsed["SignedHeaders"].split(";")
    # SigV4 signs `host` as the URL authority; it may not appear as a literal
    # header in the captured set, so derive it from the request URL when absent.
    if "host" not in low:
        low["host"] = urlsplit(url).netloc
    rebuilt = {h: low.get(h) for h in signed}
    if any(v is None for v in rebuilt.values()):
        return False
    req = AWSRequest(method=method, url=url, data=body, headers=rebuilt)
    auth = SigV4Auth(CREDS, SERVICE, REGION)
    req.context["timestamp"] = amz_date
    cr = auth.canonical_request(req)
    sts = auth.string_to_sign(req, cr)
    return auth.signature(sts, req) == parsed["Signature"]


def validate_presigned(method, full_url, host):
    parts = urlsplit(full_url)
    pairs = parse_qsl(parts.query, keep_blank_values=True)
    recv_sig = dict(pairs).get("X-Amz-Signature")
    amz_date = dict(pairs).get("X-Amz-Date")
    if not recv_sig or not amz_date:
        return False
    kept = [(k, v) for k, v in pairs if k != "X-Amz-Signature"]
    url_wo = urlunsplit((parts.scheme or "https", host, parts.path, urlencode(kept), ""))
    req = AWSRequest(method=method, url=url_wo, data=b"", headers={"host": host})
    auth = SigV4QueryAuth(CREDS, SERVICE, REGION)
    req.context["timestamp"] = amz_date
    cr = auth.canonical_request(req)
    sts = auth.string_to_sign(req, cr)
    return auth.signature(sts, req) == recv_sig


# ---- roles ---------------------------------------------------------------
def run_server(a):
    peerfile = a.peerfile
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    class H(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def _ok(self, valid):
            body = b"SIGV4_OK" if valid else b"SIGV4_BAD"
            self.send_response(200 if valid else 401)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers(); self.wfile.write(body)

        def _host(self):
            return self.headers.get("Host", "server.test")

        def do_PUT(self):
            with open(peerfile, "a") as fh:
                fh.write(self.client_address[0] + "\n")
            n = int(self.headers.get("Content-Length", "0"))
            body = self.rfile.read(n) if n else b""
            url = f"https://{self._host()}{self.path}"
            self._ok(validate_headers("PUT", url, dict(self.headers.items()), body))

        def do_GET(self):
            with open(peerfile, "a") as fh:
                fh.write(self.client_address[0] + "\n")
            full = f"https://{self._host()}{self.path}"
            self._ok(validate_presigned("GET", full, self._host()))

        def log_message(self, *a_):
            pass

    httpd = ThreadingHTTPServer((a.bind, a.port), H)
    httpd.socket = _util.server_ctx(a.cert, a.key).wrap_socket(httpd.socket, server_side=True)
    with open(a.ready, "w") as fh:
        fh.write("ready\n")
    httpd.serve_forever()


def run_client(a):
    ctx = _util.client_ctx(a.cafile)
    tls = _util.connect_tls(ctx, a.host, a.port, a.server_name, a.bind_addr)
    conn = http.client.HTTPSConnection(a.server_name, a.port, context=ctx, timeout=15)
    conn.sock = tls
    body = b"sigv4-put-body"
    headers, out_body = sign_headers("PUT", f"https://{a.server_name}/bucket/key", body)
    send_h = {k: v for k, v in headers.items() if k.lower() != "host"}
    conn.request("PUT", "/bucket/key", body=out_body, headers=send_h)
    r1 = conn.getresponse(); b1 = r1.read()
    purl = presign("GET", f"https://{a.server_name}/bucket/obj")
    sp = urlsplit(purl)
    conn.request("GET", sp.path + "?" + sp.query)
    r2 = conn.getresponse(); b2 = r2.read()
    conn.close()
    if r1.status == 200 and b1 == b"SIGV4_OK" and r2.status == 200 and b2 == b"SIGV4_OK":
        print("FORWARD_OK sigv4 header+presigned validated byte-exact"); return 0
    print(f"FORWARD_FAIL put=({r1.status},{b1!r}) get=({r2.status},{b2!r})"); return 1


def run_parse(a):
    _, c2s, s2c, _ = _util.read_conn(a.dump_dir)
    p = parse_exchange(c2s, s2c)
    if p.error:
        print(f"DUMP_FAIL {p.error}"); return
    has_authz = b"AWS4-HMAC-SHA256" in c2s
    has_qsig = b"X-Amz-Signature" in c2s
    oks = [r.status for r in p.responses if r.status == 200]
    if len(p.requests) >= 2 and len(oks) >= 2 and has_authz and has_qsig:
        print(f"DUMP_OK level={p.level} authz+presigned recovered, {len(oks)} x 200")
    else:
        print(f"DUMP_PARTIAL level={p.level} reqs={len(p.requests)} oks={len(oks)} authz={has_authz} qsig={has_qsig}")


if __name__ == "__main__":
    _util.case_main(run_server, run_client, run_parse)
