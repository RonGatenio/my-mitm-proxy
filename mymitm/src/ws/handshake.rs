//! Minimal, hand-rolled HTTP/1.1 WebSocket-upgrade detection. v1 assumes the
//! upgrade is the FIRST request on the connection: we scan a single request
//! header block (client) and a single response header block (server). Anything
//! else -> NotWebSocket (tap goes dormant, raw dump continues).

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Negotiation {
    pub permessage_deflate: bool,
    pub client_no_context_takeover: bool,
    pub server_no_context_takeover: bool,
    /// True if the server selected any extension other than permessage-deflate.
    pub unsupported_extension: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub enum RequestScan {
    NeedMore,
    NotWebSocket,
    Upgrade { consumed: usize },
}

#[derive(Debug, PartialEq, Eq)]
pub enum ResponseScan {
    NeedMore,
    NotWebSocket,
    Accepted { consumed: usize, neg: Negotiation },
}

/// Index just past the CRLFCRLF that ends the header block, or None.
fn end_of_headers(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4)
}

/// Split a header block (excluding the request/status line) into (name_lower, value)
/// pairs. `block` is the bytes up to and including the final CRLFCRLF.
fn header_lines(block: &[u8]) -> Vec<(String, String)> {
    let text = String::from_utf8_lossy(block);
    let mut out = Vec::new();
    for line in text.split("\r\n").skip(1) {
        if line.is_empty() {
            break;
        }
        if let Some((k, v)) = line.split_once(':') {
            out.push((k.trim().to_ascii_lowercase(), v.trim().to_string()));
        }
    }
    out
}

fn header_contains(headers: &[(String, String)], name: &str, needle: &str) -> bool {
    headers
        .iter()
        .filter(|(k, _)| k == name)
        .any(|(_, v)| v.to_ascii_lowercase().contains(needle))
}

pub fn scan_request(buf: &[u8]) -> RequestScan {
    let Some(consumed) = end_of_headers(buf) else {
        return RequestScan::NeedMore;
    };
    let block = &buf[..consumed];
    let text = String::from_utf8_lossy(block);
    let first = text.lines().next().unwrap_or("");
    let is_get = first.starts_with("GET ");
    let headers = header_lines(block);
    if is_get
        && header_contains(&headers, "upgrade", "websocket")
        && header_contains(&headers, "connection", "upgrade")
    {
        RequestScan::Upgrade { consumed }
    } else {
        RequestScan::NotWebSocket
    }
}

pub fn scan_response(buf: &[u8]) -> ResponseScan {
    let Some(consumed) = end_of_headers(buf) else {
        return ResponseScan::NeedMore;
    };
    let block = &buf[..consumed];
    let text = String::from_utf8_lossy(block);
    let first = text.lines().next().unwrap_or("");
    // Status line: "HTTP/1.1 101 ..."
    let is_101 = first.split_whitespace().nth(1) == Some("101");
    let headers = header_lines(block);
    if !is_101 || !header_contains(&headers, "upgrade", "websocket") {
        return ResponseScan::NotWebSocket;
    }

    let mut neg = Negotiation::default();
    for (k, v) in headers.iter().filter(|(k, _)| k == "sec-websocket-extensions") {
        let _ = k;
        for ext in v.split(',') {
            let mut params = ext.split(';').map(|p| p.trim().to_ascii_lowercase());
            let token = params.next().unwrap_or_default();
            if token == "permessage-deflate" {
                neg.permessage_deflate = true;
                for p in params {
                    match p.as_str() {
                        "client_no_context_takeover" => neg.client_no_context_takeover = true,
                        "server_no_context_takeover" => neg.server_no_context_takeover = true,
                        _ => {} // window-bits params ignored (see spec)
                    }
                }
            } else if !token.is_empty() {
                neg.unsupported_extension = true;
            }
        }
    }
    ResponseScan::Accepted { consumed, neg }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_needs_full_headers() {
        assert!(matches!(scan_request(b"GET /ws HTTP/1.1\r\nUpgrade: web"), RequestScan::NeedMore));
    }

    #[test]
    fn detects_upgrade_request() {
        let req = b"GET /ws HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n";
        match scan_request(req) {
            RequestScan::Upgrade { consumed } => assert_eq!(consumed, req.len()),
            other => panic!("expected Upgrade, got {other:?}"),
        }
    }

    #[test]
    fn plain_get_is_not_websocket() {
        let req = b"GET /index.html HTTP/1.1\r\nHost: x\r\n\r\n";
        assert!(matches!(scan_request(req), RequestScan::NotWebSocket));
    }

    #[test]
    fn detects_101_response_without_deflate() {
        let resp = b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n";
        match scan_response(resp) {
            ResponseScan::Accepted { consumed, neg } => {
                assert_eq!(consumed, resp.len());
                assert!(!neg.permessage_deflate);
                assert!(!neg.unsupported_extension);
            }
            other => panic!("expected Accepted, got {other:?}"),
        }
    }

    #[test]
    fn parses_permessage_deflate_params() {
        let resp = b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\
                     Sec-WebSocket-Extensions: permessage-deflate; server_no_context_takeover\r\n\r\n";
        match scan_response(resp) {
            ResponseScan::Accepted { neg, .. } => {
                assert!(neg.permessage_deflate);
                assert!(neg.server_no_context_takeover);
                assert!(!neg.client_no_context_takeover);
                assert!(!neg.unsupported_extension);
            }
            other => panic!("expected Accepted, got {other:?}"),
        }
    }

    #[test]
    fn flags_unknown_extension() {
        let resp = b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\
                     Sec-WebSocket-Extensions: x-custom-ext\r\n\r\n";
        match scan_response(resp) {
            ResponseScan::Accepted { neg, .. } => assert!(neg.unsupported_extension),
            other => panic!("expected Accepted, got {other:?}"),
        }
    }

    #[test]
    fn non_101_response_is_not_websocket() {
        let resp = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
        assert!(matches!(scan_response(resp), ResponseScan::NotWebSocket));
    }
}
