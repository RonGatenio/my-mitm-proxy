use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use crate::ntlm::{detect_challenge, NtlmChallenge};
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

pub struct ConnDump {
    pub id: String,
    client: SocketAddr,
    server: SocketAddr,
    c2s: Option<File>,
    s2c: Option<File>,
    ws: Option<File>,
    ws_tried: bool,
    ws_path: PathBuf,
    start: String,
    // NTLM CHALLENGE capture (independent of the raw streams).
    ntlm_dump: bool,
    server_name: Option<String>,
    ntlm_path: PathBuf,
    ntlm_buf: Vec<u8>,
    ntlm_scan_done: bool,
}

impl Dumper {
    pub fn new(dir: &Path, opts: DumpOptions) -> std::io::Result<Dumper> {
        fs::create_dir_all(dir)?;
        Ok(Dumper { dir: dir.to_path_buf(), opts })
    }

    pub fn open_conn(&self, client: SocketAddr, server: SocketAddr) -> ConnDump {
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let id = format!("conn-{n:08}");
        let mk = |suffix: &str| OpenOptions::new().create(true).write(true).truncate(true)
            .open(self.dir.join(format!("{id}.{suffix}")))
            .map_err(|e| tracing::warn!("dump open {suffix} failed: {e}")).ok();
        // Raw stream files are created only when raw_dump is on; NTLM-only mode
        // leaves them unopened so a real RDP session writes no per-connection bulk.
        let (c2s, s2c) = if self.opts.raw_dump { (mk("c2s"), mk("s2c")) } else { (None, None) };
        ConnDump {
            id: id.clone(),
            client, server,
            c2s,
            s2c,
            ws: None,
            ws_tried: false,
            ws_path: self.dir.join(format!("{id}.ws.jsonl")),
            start: now_iso(),
            ntlm_dump: self.opts.ntlm_dump,
            server_name: self.opts.server_name.clone(),
            ntlm_path: self.dir.join("ntlm.jsonl"),
            ntlm_buf: Vec::new(),
            ntlm_scan_done: false,
        }
    }
}

impl ConnDump {
    pub fn write_c2s(&mut self, b: &[u8]) { write_some(&mut self.c2s, b); }
    pub fn write_s2c(&mut self, b: &[u8]) {
        write_some(&mut self.s2c, b);
        self.ntlm_scan(b);
    }

    /// Feed server→client plaintext to the NTLM CHALLENGE detector. The auth
    /// handshake is tiny and lands before the tunnel goes opaque, so we buffer a
    /// bounded prefix; on the first hit, append one record to `ntlm.jsonl` and
    /// stop scanning this connection.
    fn ntlm_scan(&mut self, b: &[u8]) {
        const CAP: usize = 64 * 1024;
        if !self.ntlm_dump || self.ntlm_scan_done {
            return;
        }
        let room = CAP.saturating_sub(self.ntlm_buf.len());
        if room > 0 {
            self.ntlm_buf.extend_from_slice(&b[..room.min(b.len())]);
        }
        if let Some(ch) = detect_challenge(&self.ntlm_buf) {
            self.write_ntlm_record(&ch);
            self.ntlm_scan_done = true;
            self.ntlm_buf = Vec::new();
        } else if self.ntlm_buf.len() >= CAP {
            // Bounded: the challenge was not in the first CAP bytes; stop scanning.
            self.ntlm_scan_done = true;
            self.ntlm_buf = Vec::new();
        }
    }

    /// Append one NTLM CHALLENGE record (nonce + gateway computer/domain names +
    /// which target it connected to) as a JSON line to `ntlm.jsonl`.
    fn write_ntlm_record(&self, ch: &NtlmChallenge) {
        let rec = serde_json::json!({
            "conn_id": self.id,
            "ts": now_iso(),
            "client": self.client.to_string(),
            "server": self.server.to_string(),
            "server_name": self.server_name,
            "server_challenge": hex(&ch.server_challenge),
            "target_name": ch.target_name,
            "nb_computer_name": ch.nb_computer_name,
            "nb_domain_name": ch.nb_domain_name,
            "dns_computer_name": ch.dns_computer_name,
            "dns_domain_name": ch.dns_domain_name,
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
            computer = ch.nb_computer_name.as_deref().or(ch.dns_computer_name.as_deref()).unwrap_or("?"),
            "NTLM challenge captured"
        );
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

    pub fn finish(self, dir: &Path, ws: &WsStatus) {
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

fn write_some(f: &mut Option<File>, b: &[u8]) {
    if let Some(file) = f.as_mut() {
        if let Err(e) = file.write_all(b) { tracing::warn!("dump write failed: {e}"); }
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;
    use crate::ws::{Opcode, WsKind, WsMessage, WsStatus};

    #[test]
    fn writes_streams_and_index() {
        let dir = tempfile::tempdir().unwrap();
        let d = Dumper::new(dir.path(), DumpOptions::default()).unwrap();
        let mut c = d.open_conn(
            "10.8.0.5:43012".parse::<SocketAddr>().unwrap(),
            "192.168.1.50:443".parse::<SocketAddr>().unwrap());
        c.write_c2s(b"GET / HTTP/1.1\r\n");
        c.write_s2c(b"HTTP/1.1 200 OK\r\n");
        let id = c.id.clone();
        c.finish(dir.path(), &crate::ws::WsStatus::none());

        let c2s = std::fs::read(dir.path().join(format!("{id}.c2s"))).unwrap();
        assert_eq!(c2s, b"GET / HTTP/1.1\r\n");
        let s2c = std::fs::read(dir.path().join(format!("{id}.s2c"))).unwrap();
        assert_eq!(s2c, b"HTTP/1.1 200 OK\r\n");
        let idx = std::fs::read_to_string(dir.path().join("index.jsonl")).unwrap();
        assert!(idx.contains("10.8.0.5:43012"));
        assert!(idx.contains("192.168.1.50:443"));
    }

    #[test]
    fn writes_ws_messages_text_and_binary() {
        let dir = tempfile::tempdir().unwrap();
        let d = Dumper::new(dir.path(), DumpOptions::default()).unwrap();
        let mut c = d.open_conn(
            "10.0.0.1:1".parse().unwrap(),
            "10.0.0.2:443".parse().unwrap(),
        );
        c.write_ws_message(&WsMessage { from_client: true, opcode: Opcode::Text, payload: b"{\"a\":1}".to_vec() });
        c.write_ws_message(&WsMessage { from_client: false, opcode: Opcode::Binary, payload: vec![0, 159, 146, 150] });
        let id = c.id.clone();
        let ws = WsStatus { kind: WsKind::Decoded, permessage_deflate: true, message_count: 2, close_code: Some(1000), close_reason: Some("bye".into()), undecodable_reason: None };
        c.finish(dir.path(), &ws);

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
        let mut c = d.open_conn("10.0.0.1:1".parse().unwrap(), "10.0.0.2:443".parse().unwrap());
        c.write_ws_message(&WsMessage { from_client: true, opcode: Opcode::Text, payload: vec![0xff, 0xfe] });
        let id = c.id.clone();
        c.finish(dir.path(), &WsStatus::none());
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
        let mut c = d.open_conn(
            "10.20.1.5:51616".parse().unwrap(),
            "10.20.2.10:443".parse().unwrap());
        let id = c.id.clone();
        // A 401 carrying the MS-NLMP example CHALLENGE_MESSAGE in a WWW-Authenticate: NTLM header.
        let b64 = B64.encode(crate::ntlm::CHALLENGE_MESSAGE_EXAMPLE);
        let s2c = format!("HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: NTLM {b64}\r\n\r\n");
        c.write_s2c(s2c.as_bytes());
        c.finish(dir.path(), &crate::ws::WsStatus::none());

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
        // index.jsonl still written even with raw_dump = false
        assert!(dir.path().join("index.jsonl").exists());
    }

    #[test]
    fn ntlm_dump_records_first_challenge_only() {
        let dir = tempfile::tempdir().unwrap();
        let d = Dumper::new(dir.path(), DumpOptions {
            raw_dump: false, ntlm_dump: true, server_name: None,
        }).unwrap();
        let mut c = d.open_conn("10.0.0.1:1".parse().unwrap(), "10.0.0.2:443".parse().unwrap());
        let b64 = B64.encode(crate::ntlm::CHALLENGE_MESSAGE_EXAMPLE);
        c.write_s2c(format!("HTTP/1.1 401\r\nWWW-Authenticate: NTLM {b64}\r\n\r\n").as_bytes());
        c.write_s2c(format!("HTTP/1.1 401\r\nWWW-Authenticate: NTLM {b64}\r\n\r\n").as_bytes());
        c.finish(dir.path(), &crate::ws::WsStatus::none());
        let n = std::fs::read_to_string(dir.path().join("ntlm.jsonl")).unwrap().lines().count();
        assert_eq!(n, 1, "only the first challenge per connection is recorded");
    }

    #[test]
    fn both_dumps_off_writes_no_stream_or_ntlm_files() {
        let dir = tempfile::tempdir().unwrap();
        let d = Dumper::new(dir.path(), DumpOptions {
            raw_dump: false, ntlm_dump: false, server_name: None,
        }).unwrap();
        let mut c = d.open_conn("10.0.0.1:1".parse().unwrap(), "10.0.0.2:443".parse().unwrap());
        let id = c.id.clone();
        let b64 = B64.encode(crate::ntlm::CHALLENGE_MESSAGE_EXAMPLE);
        c.write_c2s(b"GET / HTTP/1.1\r\n\r\n");
        c.write_s2c(format!("HTTP/1.1 401\r\nWWW-Authenticate: NTLM {b64}\r\n\r\n").as_bytes());
        c.finish(dir.path(), &crate::ws::WsStatus::none());
        assert!(!dir.path().join(format!("{id}.c2s")).exists());
        assert!(!dir.path().join(format!("{id}.s2c")).exists());
        assert!(!dir.path().join("ntlm.jsonl").exists());
    }
}
