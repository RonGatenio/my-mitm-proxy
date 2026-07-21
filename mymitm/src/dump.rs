use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use crate::ws::{Opcode, WsMessage, WsStatus};

static COUNTER: AtomicU64 = AtomicU64::new(0);

pub struct Dumper { dir: PathBuf }

pub struct ConnDump {
    pub id: String,
    client: SocketAddr,
    server: SocketAddr,
    c2s: Option<File>,
    s2c: Option<File>,
    ws: Option<File>,
    ws_path: PathBuf,
    start: String,
}

impl Dumper {
    pub fn new(dir: &Path) -> std::io::Result<Dumper> {
        fs::create_dir_all(dir)?;
        Ok(Dumper { dir: dir.to_path_buf() })
    }

    pub fn open_conn(&self, client: SocketAddr, server: SocketAddr) -> ConnDump {
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let id = format!("conn-{n:08}");
        let mk = |suffix: &str| OpenOptions::new().create(true).write(true).truncate(true)
            .open(self.dir.join(format!("{id}.{suffix}")))
            .map_err(|e| tracing::warn!("dump open {suffix} failed: {e}")).ok();
        ConnDump {
            id: id.clone(),
            client, server,
            c2s: mk("c2s"),
            s2c: mk("s2c"),
            ws: None,
            ws_path: self.dir.join(format!("{id}.ws.jsonl")),
            start: now_iso(),
        }
    }
}

impl ConnDump {
    pub fn write_c2s(&mut self, b: &[u8]) { write_some(&mut self.c2s, b); }
    pub fn write_s2c(&mut self, b: &[u8]) { write_some(&mut self.s2c, b); }

    /// Append one decoded WebSocket message as a JSON line to `{id}.ws.jsonl`
    /// (created lazily on first message). Text with valid UTF-8 goes in `data`;
    /// binary and invalid-UTF-8 text go in `b64`.
    pub fn write_ws_message(&mut self, msg: &WsMessage) {
        if self.ws.is_none() {
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
        match (msg.opcode, std::str::from_utf8(&msg.payload)) {
            (Opcode::Text, Ok(s)) => {
                rec["data"] = serde_json::Value::String(s.to_string());
            }
            (Opcode::Text, Err(_)) => {
                rec["b64"] = serde_json::Value::String(B64.encode(&msg.payload));
                rec["invalid_utf8"] = serde_json::Value::Bool(true);
            }
            (Opcode::Binary, _) => {
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;
    use crate::ws::{Opcode, WsKind, WsMessage, WsStatus};

    #[test]
    fn writes_streams_and_index() {
        let dir = tempfile::tempdir().unwrap();
        let d = Dumper::new(dir.path()).unwrap();
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
        let d = Dumper::new(dir.path()).unwrap();
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
        let d = Dumper::new(dir.path()).unwrap();
        let mut c = d.open_conn("10.0.0.1:1".parse().unwrap(), "10.0.0.2:443".parse().unwrap());
        c.write_ws_message(&WsMessage { from_client: true, opcode: Opcode::Text, payload: vec![0xff, 0xfe] });
        let id = c.id.clone();
        c.finish(dir.path(), &WsStatus::none());
        let jsonl = std::fs::read_to_string(dir.path().join(format!("{id}.ws.jsonl"))).unwrap();
        let rec: serde_json::Value = serde_json::from_str(jsonl.lines().next().unwrap()).unwrap();
        assert!(rec["b64"].is_string());
        assert_eq!(rec["invalid_utf8"], true);
    }
}
