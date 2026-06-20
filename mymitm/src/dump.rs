use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static COUNTER: AtomicU64 = AtomicU64::new(0);

pub struct Dumper { dir: PathBuf }

pub struct ConnDump {
    pub id: String,
    client: SocketAddr,
    server: SocketAddr,
    c2s: Option<File>,
    s2c: Option<File>,
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
            start: now_iso(),
        }
    }
}

impl ConnDump {
    pub fn write_c2s(&mut self, b: &[u8]) { write_some(&mut self.c2s, b); }
    pub fn write_s2c(&mut self, b: &[u8]) { write_some(&mut self.s2c, b); }

    pub fn finish(self, dir: &Path) {
        let rec = serde_json::json!({
            "conn_id": self.id, "client": self.client.to_string(),
            "server": self.server.to_string(), "start_ts": self.start, "end_ts": now_iso(),
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
        c.finish(dir.path());

        let c2s = std::fs::read(dir.path().join(format!("{id}.c2s"))).unwrap();
        assert_eq!(c2s, b"GET / HTTP/1.1\r\n");
        let s2c = std::fs::read(dir.path().join(format!("{id}.s2c"))).unwrap();
        assert_eq!(s2c, b"HTTP/1.1 200 OK\r\n");
        let idx = std::fs::read_to_string(dir.path().join("index.jsonl")).unwrap();
        assert!(idx.contains("10.8.0.5:43012"));
        assert!(idx.contains("192.168.1.50:443"));
    }
}
