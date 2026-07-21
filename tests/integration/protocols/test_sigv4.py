from cases.sigv4 import sign_headers, validate_headers, presign, validate_presigned

HOST = "server.test"


def test_header_auth_roundtrip_and_tamper():
    body = b"PUT-body-bytes"
    headers, out_body = sign_headers("PUT", f"https://{HOST}/bucket/key", body)
    url = f"https://{HOST}/bucket/key"
    assert validate_headers("PUT", url, headers, out_body) is True
    # Any byte change to the signed request must break validation:
    assert validate_headers("PUT", url, headers, out_body + b"x") is False
    assert validate_headers("POST", url, headers, out_body) is False


def test_presigned_roundtrip_and_tamper():
    purl = presign("GET", f"https://{HOST}/bucket/obj")
    assert validate_presigned("GET", purl, HOST) is True
    assert validate_presigned("GET", purl.replace("bucket", "bukket"), HOST) is False
