//! Proxy core: accept the locally-delivered (eBPF-DNAT'd) client connection,
//! terminate TLS presenting the REAL leaf cert+key, dial the real server over a
//! `SO_MARK`-tagged kernel socket, pump bytes both ways, and dump the decrypted
//! plaintext. Pure tokio + rustls(ring); no eBPF here.
//!
//! ## Upstream verification — why a custom pin verifier
//! We connect to the real server BY IP (no DNS in this environment), but its
//! certificate is issued for a HOSTNAME. Normal rustls validation against an
//! `IpAddress` `ServerName` therefore rejects the (otherwise valid) cert. Since
//! a MITM that already holds the real leaf cert has the strongest possible
//! check available — exact DER equality of the presented end-entity cert
//! against the cert we serve — we pin on that and skip hostname/path building
//! entirely. Signature checks are still performed via the ring provider so a
//! replayed-but-keyless cert cannot complete the handshake.

use std::net::{SocketAddr, SocketAddrV4};
use std::path::Path;
use std::sync::Arc;
use std::sync::Once;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::rustls::client::danger::{
    HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
};
use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use tokio_rustls::rustls::{self, DigitallySignedStruct, SignatureScheme};
use tokio_rustls::{TlsAcceptor, TlsConnector};

use crate::config::Settings;
use crate::dataplane::DataPlane;
use crate::dump::Dumper;
use crate::ws::{WsMessage, WsStatus, WsTap};

/// Install the ring `CryptoProvider` as the process default exactly once.
///
/// rustls 0.23 + ring requires a `CryptoProvider` to be installed before
/// `ServerConfig/ClientConfig::builder()` is called, otherwise the builder
/// panics at runtime ("no process-level CryptoProvider available"). We call
/// this from every public entry point so cert loading, the connector builder,
/// and tests are all safe regardless of call order.
pub fn ensure_crypto_provider() {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        // `install_default` returns Err if one is already installed; that is
        // fine — some other component may have installed it first.
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

/// Load the REAL leaf cert chain + private key and build a server-side TLS
/// config that presents them to the locally-delivered client.
pub fn load_server_tls(cert: &Path, key: &Path) -> anyhow::Result<Arc<rustls::ServerConfig>> {
    ensure_crypto_provider();
    let certs = rustls_pemfile::certs(&mut std::io::BufReader::new(std::fs::File::open(cert)?))
        .collect::<Result<Vec<_>, _>>()?;
    if certs.is_empty() {
        anyhow::bail!("no certificates found in {cert:?}");
    }
    let key = rustls_pemfile::private_key(&mut std::io::BufReader::new(std::fs::File::open(key)?))?
        .ok_or_else(|| anyhow::anyhow!("no private key in {key:?}"))?;
    let cfg = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    Ok(Arc::new(cfg))
}

/// Read the leaf (first) certificate's DER from a PEM file. This is the cert we
/// pin upstream against.
fn load_leaf_der(cert: &Path) -> anyhow::Result<CertificateDer<'static>> {
    let certs = rustls_pemfile::certs(&mut std::io::BufReader::new(std::fs::File::open(cert)?))
        .collect::<Result<Vec<_>, _>>()?;
    certs
        .into_iter()
        .next()
        .ok_or_else(|| anyhow::anyhow!("no certificates found in {cert:?}"))
}

/// A `ServerCertVerifier` that accepts the upstream server only if its presented
/// end-entity certificate's DER bytes are byte-for-byte equal to the configured
/// real leaf cert. Signature verification is delegated to the ring provider so
/// the handshake still proves the peer holds the matching private key.
#[derive(Debug)]
struct PinnedCertVerifier {
    pinned_leaf: CertificateDer<'static>,
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl PinnedCertVerifier {
    fn new(pinned_leaf: CertificateDer<'static>) -> Self {
        Self {
            pinned_leaf,
            provider: Arc::new(rustls::crypto::ring::default_provider()),
        }
    }
}

impl ServerCertVerifier for PinnedCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if end_entity.as_ref() == self.pinned_leaf.as_ref() {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General(
                "upstream leaf certificate does not match the pinned real cert".into(),
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Build the upstream `TlsConnector` that pins on the real leaf cert.
fn build_upstream_connector(s: &Settings) -> anyhow::Result<TlsConnector> {
    ensure_crypto_provider();
    let leaf = load_leaf_der(&s.cert_path)?;
    let verifier = Arc::new(PinnedCertVerifier::new(leaf));
    let cfg = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    Ok(TlsConnector::from(Arc::new(cfg)))
}

/// Compute the upstream SNI: the configured `server_name` if present, otherwise
/// the server IP (sent as SNI only — verification is by the pin verifier, so a
/// server that ignores an IP SNI still works).
fn upstream_server_name(s: &Settings) -> anyhow::Result<ServerName<'static>> {
    match &s.server_name {
        Some(name) => Ok(ServerName::try_from(name.clone())
            .map_err(|e| anyhow::anyhow!("invalid server_name {name:?}: {e}"))?),
        None => Ok(ServerName::IpAddress(s.server_ip.into())),
    }
}

/// Bind `local_ip:local_port`, accept the DNAT'd client connections, and serve
/// each one (terminate client TLS, dial upstream, pump, dump) forever.
pub async fn run(s: Arc<Settings>, dumper: Arc<Dumper>, plane: Arc<dyn DataPlane>) -> anyhow::Result<()> {
    ensure_crypto_provider();
    let server_cfg = load_server_tls(&s.cert_path, &s.key_path)?;
    let acceptor = TlsAcceptor::from(server_cfg);
    let connector = build_upstream_connector(&s)?;

    let listener = TcpListener::bind((s.local_ip, s.local_port)).await?;
    tracing::info!("proxy listening on {}:{}", s.local_ip, s.local_port);

    loop {
        // A single transient accept() error (e.g. EMFILE, a reset between
        // accept and return) must not tear down the whole proxy: log and retry.
        let (inbound, peer) = match listener.accept().await {
            Ok(pair) => pair,
            Err(e) => {
                tracing::warn!("accept error (continuing): {e}");
                continue;
            }
        };
        let acceptor = acceptor.clone();
        let connector = connector.clone();
        let s = s.clone();
        let dumper = dumper.clone();
        let plane = plane.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_conn(inbound, peer, acceptor, connector, s, dumper, plane).await {
                tracing::warn!("conn {peer} ended: {e}");
            }
        });
    }
}

/// Relay one direction: read from `src`, tee each chunk to its dump `sink`, and
/// write it to `dst`. On clean EOF, shut down `dst`'s write half (propagating
/// FIN) and return `Ok`, ending only this direction. A read/write error returns
/// `Err` so the caller can tear the whole connection down.
/// Shared WebSocket-tap state: both pump directions feed it (it must see both to
/// decode), and it holds the `ConnMeta` that decoded messages are dumped into
/// until the pump finishes and the caller reclaims it for `finish`.
struct WsShared {
    tap: Option<WsTap>,
    meta: crate::dump::ConnMeta,
    ws_out: Vec<WsMessage>,
}

impl WsShared {
    fn feed(&mut self, from_client: bool, bytes: &[u8]) {
        // NTLM capture is independent of the WebSocket tap: it must run even in
        // NTLM-only mode, where the tap is disabled (raw_dump = false).
        if from_client {
            self.meta.feed_c2s(bytes);
        } else {
            self.meta.feed_s2c(bytes);
        }
        let Some(t) = self.tap.as_mut() else { return };
        if from_client {
            t.on_client_bytes(bytes, &mut self.ws_out);
        } else {
            t.on_server_bytes(bytes, &mut self.ws_out);
        }
        for m in self.ws_out.drain(..) { self.meta.write_ws_message(&m); }
    }
}

async fn pump_dir<R, W>(
    mut src: R,
    mut dst: W,
    mut sink: crate::dump::DirSink,
    shared: Arc<std::sync::Mutex<WsShared>>,
    from_client: bool,
) -> std::io::Result<()>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    let mut buf = [0u8; 16384];
    loop {
        let n = src.read(&mut buf).await?;
        if n == 0 {
            dst.shutdown().await.ok();
            return Ok(());
        }
        sink.write(&buf[..n]);
        dst.write_all(&buf[..n]).await?;
        // Feed the WebSocket tap after relaying, so the lock stays off the hot path.
        {
            let mut g = shared.lock().unwrap_or_else(|e| e.into_inner());
            g.feed(from_client, &buf[..n]);
        }
    }
}

async fn handle_conn(
    inbound: TcpStream,
    peer: SocketAddr,
    acceptor: TlsAcceptor,
    connector: TlsConnector,
    s: Arc<Settings>,
    dumper: Arc<Dumper>,
    plane: Arc<dyn DataPlane>,
) -> anyhow::Result<()> {
    // 1. Terminate the client's TLS, presenting the REAL leaf cert.
    let client_tls = acceptor.accept(inbound).await?;

    // 2. Dial the real server via the data plane, then TLS upstream.
    //
    // The accepted socket's peer IS the real client (DNAT rewrote only the dst),
    // so its IP is what the upstream leg must carry for source-IP preservation.
    let client_ip = match peer.ip() {
        std::net::IpAddr::V4(v4) => v4,
        std::net::IpAddr::V6(_) => anyhow::bail!("ipv6 client unsupported in v1"),
    };
    let server_addr = SocketAddrV4::new(s.server_ip, s.server_port);
    let std_up = plane.upstream_socket(client_ip, server_addr)?;
    let up = TcpStream::from_std(std_up)?;
    let server_name = upstream_server_name(&s)?;
    let server_tls = connector.connect(server_name, up).await?;

    // 3. Pump bytes both ways, dumping decrypted plaintext per direction.
    let server_sa = SocketAddr::from((s.server_ip, s.server_port));
    let (meta, c2s_sink, s2c_sink) = dumper.open_conn(peer, server_sa);
    let (cr, cw) = tokio::io::split(client_tls);
    let (sr, sw) = tokio::io::split(server_tls);

    // Two independent directions, each owning its reader, peer-writer, and dump
    // sink — no shared borrow, so neither can head-of-line-block the other (the
    // old single `select!` loop stalled one side while `write_all` awaited on the
    // other). `try_join!` waits for both to finish; a hard error on either cancels
    // the sibling and tears the connection down.
    //
    // The WebSocket tap must observe BOTH directions, so it — and the `ConnMeta`
    // it dumps decoded messages into — live behind a shared mutex. Each direction
    // feeds the tap AFTER relaying its bytes, so the lock never sits on the relay
    // path and the two directions stay independent.
    // The WS tap feeds .ws.jsonl, a raw-dump artifact — skip it in NTLM-only mode.
    let tap = if s.raw_dump && s.ws_decode { Some(WsTap::new()) } else { None };
    let shared = Arc::new(std::sync::Mutex::new(WsShared { tap, meta, ws_out: Vec::new() }));

    let c2s = pump_dir(cr, sw, c2s_sink, shared.clone(), true);
    let s2c = pump_dir(sr, cw, s2c_sink, shared.clone(), false);
    let outcome = tokio::try_join!(c2s, s2c);

    // Both directions have joined, so `shared` is the sole remaining owner:
    // reclaim the tap + meta, finalize the WebSocket status, write the index.
    let WsShared { tap, meta, .. } = Arc::into_inner(shared)
        .expect("both pump tasks have joined; no other Arc refs remain")
        .into_inner()
        .unwrap_or_else(|e| e.into_inner());
    let ws_status = match tap {
        Some(t) => t.finalize(),
        None => WsStatus::none(),
    };
    meta.finish(&s.dump_path, &ws_status);
    outcome?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use std::path::PathBuf;

    /// Generate a throwaway self-signed cert for `names`, returning (cert_pem, key_pem).
    fn gen_cert(names: Vec<String>) -> (String, String) {
        let cert = rcgen::generate_simple_self_signed(names).unwrap();
        (cert.cert.pem(), cert.key_pair.serialize_pem())
    }

    fn write_cert(dir: &Path, names: Vec<String>) -> (PathBuf, PathBuf) {
        let (cert_pem, key_pem) = gen_cert(names);
        let c = dir.join("c.pem");
        let k = dir.join("k.pem");
        std::fs::write(&c, cert_pem).unwrap();
        std::fs::write(&k, key_pem).unwrap();
        (c, k)
    }

    #[test]
    fn loads_cert_and_key() {
        let dir = tempfile::tempdir().unwrap();
        let (c, k) = write_cert(dir.path(), vec!["test".into()]);

        // valid cert+key loads and is usable as an acceptor
        let cfg = load_server_tls(&c, &k).unwrap();
        let _acceptor = TlsAcceptor::from(cfg);

        // missing key file is an error
        assert!(load_server_tls(&c, &dir.path().join("missing.pem")).is_err());
    }

    fn settings_for(cert: &Path, key: &Path, server_ip: Ipv4Addr) -> Settings {
        let mut s = Settings::test_default();
        s.server_ip = server_ip;
        s.server_port = 0; // overridden per-test to the fake server's port
        s.local_port = 0; // unused by the loopback test (binds its own listener)
        s.fwmark = 0; // DirectPlane ignores it; no CAP_NET_ADMIN needed
        s.cert_path = cert.to_path_buf();
        s.key_path = key.to_path_buf();
        s
    }

    /// Full loopback round-trip with NO eBPF:
    /// fake upstream TLS server (rcgen self-signed) <-> proxy <-> TLS client.
    /// Proves terminate + dial + pump + dump + the DER-pin verifier, and asserts
    /// the dump files contain the decrypted plaintext.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn loopback_roundtrip_with_dump() {
        ensure_crypto_provider();
        let dir = tempfile::tempdir().unwrap();
        // The SAME cert is used as: the fake server's identity, the proxy's
        // "real leaf" served to the client, AND the proxy's upstream pin.
        let (cert, key) = write_cert(dir.path(), vec!["localhost".into()]);

        // ---- fake upstream TLS server on 127.0.0.1 ----
        let server_cfg = load_server_tls(&cert, &key).unwrap();
        let server_acceptor = TlsAcceptor::from(server_cfg);
        let server_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let server_addr = server_listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (sock, _) = server_listener.accept().await.unwrap();
            let mut tls = server_acceptor.accept(sock).await.unwrap();
            let mut buf = [0u8; 1024];
            let n = tls.read(&mut buf).await.unwrap();
            assert_eq!(&buf[..n], b"PING-FROM-CLIENT");
            tls.write_all(b"PONG-FROM-SERVER").await.unwrap();
            tls.shutdown().await.ok();
        });

        // ---- proxy ----
        let dump_dir = dir.path().join("dumps");
        let dumper = Arc::new(Dumper::new(&dump_dir, crate::dump::DumpOptions::default()).unwrap());
        let server_v4 = match server_addr.ip() {
            std::net::IpAddr::V4(v4) => v4,
            _ => unreachable!(),
        };
        let mut settings = settings_for(&cert, &key, server_v4);
        settings.server_port = server_addr.port();
        settings.dump_path = dump_dir.clone();
        // server's cert is for "localhost" but we connect by IP; the pin
        // verifier makes that fine. Send no SNI override -> IP SNI.
        let settings = Arc::new(settings);

        // bind the proxy on an ephemeral local port
        let proxy_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let proxy_addr = proxy_listener.local_addr().unwrap();
        let acceptor = TlsAcceptor::from(load_server_tls(&cert, &key).unwrap());
        let connector = build_upstream_connector(&settings).unwrap();
        {
            let settings = settings.clone();
            let dumper = dumper.clone();
            let plane: Arc<dyn crate::dataplane::DataPlane> =
                Arc::new(crate::dataplane::DirectPlane);
            tokio::spawn(async move {
                let (inbound, peer) = proxy_listener.accept().await.unwrap();
                handle_conn(inbound, peer, acceptor, connector, settings, dumper, plane)
                    .await
                    .unwrap();
            });
        }

        // ---- TLS client -> proxy ----
        // The client also pins on the same leaf (DER equality), exercising the
        // exact-cert trust path from the client side too.
        let client_connector = build_upstream_connector(&settings).unwrap();
        let client_sock = TcpStream::connect(proxy_addr).await.unwrap();
        let client_name = ServerName::try_from("localhost").unwrap();
        let mut client_tls = client_connector
            .connect(client_name, client_sock)
            .await
            .unwrap();

        client_tls.write_all(b"PING-FROM-CLIENT").await.unwrap();
        let mut buf = [0u8; 1024];
        let n = client_tls.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"PONG-FROM-SERVER");
        client_tls.shutdown().await.ok();

        // ---- assert the dump captured decrypted plaintext both ways ----
        // Give the proxy task a moment to finish writing + index.
        for _ in 0..50 {
            if std::fs::read_to_string(dump_dir.join("index.jsonl")).is_ok() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        let idx = std::fs::read_to_string(dump_dir.join("index.jsonl")).unwrap();
        let conn_id = idx
            .lines()
            .find_map(|l| {
                serde_json::from_str::<serde_json::Value>(l)
                    .ok()
                    .and_then(|v| v.get("conn_id").and_then(|c| c.as_str().map(String::from)))
            })
            .expect("index.jsonl has a conn_id");
        let c2s = std::fs::read(dump_dir.join(format!("{conn_id}.c2s"))).unwrap();
        let s2c = std::fs::read(dump_dir.join(format!("{conn_id}.s2c"))).unwrap();
        assert_eq!(c2s, b"PING-FROM-CLIENT");
        assert_eq!(s2c, b"PONG-FROM-SERVER");
    }

    /// Full-duplex + half-close: the client streams a large blob then closes its
    /// write half; the server, after the client's EOF, streams its own large blob
    /// back. The client (write side closed) must still receive all of it. Exercises
    /// both pump directions, multi-chunk streaming, and the per-direction dumps.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn pump_full_duplex_and_half_close() {
        ensure_crypto_provider();
        let dir = tempfile::tempdir().unwrap();
        let (cert, key) = write_cert(dir.path(), vec!["localhost".into()]);
        const N: usize = 200_000; // > pump buffer (16 KiB) -> many chunks
        let up_blob = vec![0xABu8; N];
        let down_blob = vec![0xCDu8; N];

        // fake upstream server
        let server_acceptor = TlsAcceptor::from(load_server_tls(&cert, &key).unwrap());
        let server_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let server_addr = server_listener.local_addr().unwrap();
        let up_expect = up_blob.clone();
        let down_send = down_blob.clone();
        tokio::spawn(async move {
            let (sock, _) = server_listener.accept().await.unwrap();
            let tls = server_acceptor.accept(sock).await.unwrap();
            let (mut r, mut w) = tokio::io::split(tls);
            let mut got = Vec::new();
            r.read_to_end(&mut got).await.unwrap();
            assert_eq!(got, up_expect);
            w.write_all(&down_send).await.unwrap();
            w.shutdown().await.ok();
        });

        // proxy
        let dump_dir = dir.path().join("dumps");
        let dumper = Arc::new(Dumper::new(&dump_dir, crate::dump::DumpOptions::default()).unwrap());
        let server_v4 = match server_addr.ip() { std::net::IpAddr::V4(v4) => v4, _ => unreachable!() };
        let mut settings = settings_for(&cert, &key, server_v4);
        settings.server_port = server_addr.port();
        settings.dump_path = dump_dir.clone();
        let settings = Arc::new(settings);
        let proxy_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let proxy_addr = proxy_listener.local_addr().unwrap();
        let acceptor = TlsAcceptor::from(load_server_tls(&cert, &key).unwrap());
        let connector = build_upstream_connector(&settings).unwrap();
        {
            let settings = settings.clone();
            let dumper = dumper.clone();
            let plane: Arc<dyn crate::dataplane::DataPlane> = Arc::new(crate::dataplane::DirectPlane);
            tokio::spawn(async move {
                let (inbound, peer) = proxy_listener.accept().await.unwrap();
                handle_conn(inbound, peer, acceptor, connector, settings, dumper, plane).await.unwrap();
            });
        }

        // client: send blob, half-close write, then read the server's blob in full
        let client_connector = build_upstream_connector(&settings).unwrap();
        let client_sock = TcpStream::connect(proxy_addr).await.unwrap();
        let client_name = ServerName::try_from("localhost").unwrap();
        let client_tls = client_connector.connect(client_name, client_sock).await.unwrap();
        let (mut cr, mut cw) = tokio::io::split(client_tls);
        cw.write_all(&up_blob).await.unwrap();
        cw.shutdown().await.ok();
        let mut got = Vec::new();
        cr.read_to_end(&mut got).await.unwrap();
        assert_eq!(got, down_blob);
    }

    /// The pin verifier must REJECT a different leaf cert.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn pin_verifier_rejects_wrong_cert() {
        ensure_crypto_provider();
        let dir = tempfile::tempdir().unwrap();
        let dir_a = dir.path().join("a");
        let dir_b = dir.path().join("b");
        std::fs::create_dir_all(&dir_a).unwrap();
        std::fs::create_dir_all(&dir_b).unwrap();
        // server presents cert A
        let (server_cert, server_key) = write_cert(&dir_a, vec!["localhost".into()]);
        // proxy pins cert B (different key/DER)
        let (pin_cert, _pin_key) = write_cert(&dir_b, vec!["localhost".into()]);

        let server_cfg = load_server_tls(&server_cert, &server_key).unwrap();
        let server_acceptor = TlsAcceptor::from(server_cfg);
        let server_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let server_addr = server_listener.local_addr().unwrap();
        tokio::spawn(async move {
            if let Ok((sock, _)) = server_listener.accept().await {
                // handshake will fail when client (proxy) rejects the cert
                let _ = server_acceptor.accept(sock).await;
            }
        });

        let mut settings = settings_for(&pin_cert, &pin_cert, Ipv4Addr::LOCALHOST);
        settings.server_port = server_addr.port();
        let settings = Arc::new(settings);

        let connector = build_upstream_connector(&settings).unwrap();
        let up = TcpStream::connect(server_addr).await.unwrap();
        let name = ServerName::IpAddress(Ipv4Addr::LOCALHOST.into());
        let res = connector.connect(name, up).await;
        assert!(res.is_err(), "handshake must fail when leaf cert != pinned cert");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn websocket_loopback_decodes_message() {
        ensure_crypto_provider();
        let dir = tempfile::tempdir().unwrap();
        let (cert, key) = write_cert(dir.path(), vec!["localhost".into()]);

        // fake upstream: complete the WS handshake, then send one unmasked text frame.
        let server_cfg = load_server_tls(&cert, &key).unwrap();
        let server_acceptor = TlsAcceptor::from(server_cfg);
        let server_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let server_addr = server_listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (sock, _) = server_listener.accept().await.unwrap();
            let mut tls = server_acceptor.accept(sock).await.unwrap();
            let mut buf = [0u8; 1024];
            let _ = tls.read(&mut buf).await.unwrap(); // read client's upgrade request
            tls.write_all(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n").await.unwrap();
            // one server->client text frame "pong" (unmasked)
            tls.write_all(&[0x81, 0x04, b'p', b'o', b'n', b'g']).await.unwrap();
            let mut sink = [0u8; 64];
            let _ = tls.read(&mut sink).await; // wait for client frame then close
            tls.shutdown().await.ok();
        });

        let dump_dir = dir.path().join("dumps");
        let dumper = Arc::new(Dumper::new(&dump_dir, crate::dump::DumpOptions::default()).unwrap());
        let server_v4 = match server_addr.ip() { std::net::IpAddr::V4(v4) => v4, _ => unreachable!() };
        let mut settings = settings_for(&cert, &key, server_v4);
        settings.server_port = server_addr.port();
        settings.dump_path = dump_dir.clone();
        let settings = Arc::new(settings);

        let proxy_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let proxy_addr = proxy_listener.local_addr().unwrap();
        let acceptor = TlsAcceptor::from(load_server_tls(&cert, &key).unwrap());
        let connector = build_upstream_connector(&settings).unwrap();
        {
            let settings = settings.clone();
            let dumper = dumper.clone();
            let plane: Arc<dyn crate::dataplane::DataPlane> = Arc::new(crate::dataplane::DirectPlane);
            tokio::spawn(async move {
                let (inbound, peer) = proxy_listener.accept().await.unwrap();
                handle_conn(inbound, peer, acceptor, connector, settings, dumper, plane).await.unwrap();
            });
        }

        // client: send upgrade request, send one masked text frame, read the pong.
        let client_connector = build_upstream_connector(&settings).unwrap();
        let client_sock = TcpStream::connect(proxy_addr).await.unwrap();
        let mut client_tls = client_connector
            .connect(ServerName::try_from("localhost").unwrap(), client_sock)
            .await
            .unwrap();
        client_tls.write_all(b"GET /ws HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n").await.unwrap();
        let mut buf = [0u8; 128];
        let _ = client_tls.read(&mut buf).await.unwrap(); // 101 (+ maybe pong)
        // masked client text frame "ping"
        client_tls.write_all(&[0x81, 0x84, 0x00, 0x00, 0x00, 0x00, b'p', b'i', b'n', b'g']).await.unwrap();
        client_tls.shutdown().await.ok();

        // assert the ws.jsonl captured both directions.
        for _ in 0..50 {
            if std::fs::read_to_string(dump_dir.join("index.jsonl")).is_ok() { break; }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        let idx = std::fs::read_to_string(dump_dir.join("index.jsonl")).unwrap();
        let conn_id = idx.lines().find_map(|l| {
            serde_json::from_str::<serde_json::Value>(l).ok()
                .and_then(|v| v.get("conn_id").and_then(|c| c.as_str().map(String::from)))
        }).expect("conn_id");
        let ws = std::fs::read_to_string(dump_dir.join(format!("{conn_id}.ws.jsonl"))).unwrap();
        assert!(ws.contains("\"pong\""), "server->client text decoded: {ws}");
        assert!(ws.contains("\"ping\""), "client->server text decoded: {ws}");
    }
}
