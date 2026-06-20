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

use std::net::SocketAddr;
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
use crate::dump::Dumper;

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

/// Create a TCP socket to `server` tagged with `SO_MARK` = `fwmark` (so the
/// eBPF eth0 classifier SNATs its source to the client IP), connect, and return
/// a non-blocking `std::net::TcpStream` ready to wrap with tokio.
///
/// SO_MARK MUST be set BEFORE connect so the very first SYN carries the mark.
pub fn upstream_socket(server: SocketAddr, fwmark: u32) -> std::io::Result<std::net::TcpStream> {
    let domain = match server {
        SocketAddr::V4(_) => socket2::Domain::IPV4,
        SocketAddr::V6(_) => socket2::Domain::IPV6,
    };
    let sock = socket2::Socket::new(domain, socket2::Type::STREAM, Some(socket2::Protocol::TCP))?;
    // SO_MARK must precede connect so the very first SYN carries the mark.
    // A mark of 0 means "do not tag" — skip the setsockopt entirely, which also
    // lets the proxy/loopback tests run without CAP_NET_ADMIN.
    if fwmark != 0 {
        sock.set_mark(fwmark)?;
    }
    // Blocking connect keeps EINPROGRESS handling simple; flip to non-blocking
    // only after the connection is established so the tokio runtime drives
    // reads/writes afterwards.
    sock.connect(&server.into())?;
    sock.set_nonblocking(true)?;
    Ok(sock.into())
}

/// Bind `local_ip:local_port`, accept the DNAT'd client connections, and serve
/// each one (terminate client TLS, dial upstream, pump, dump) forever.
pub async fn run(s: Arc<Settings>, dumper: Arc<Dumper>) -> anyhow::Result<()> {
    ensure_crypto_provider();
    let server_cfg = load_server_tls(&s.cert_path, &s.key_path)?;
    let acceptor = TlsAcceptor::from(server_cfg);
    let connector = build_upstream_connector(&s)?;

    let listener = TcpListener::bind((s.local_ip, s.local_port)).await?;
    tracing::info!("proxy listening on {}:{}", s.local_ip, s.local_port);

    loop {
        let (inbound, peer) = listener.accept().await?;
        let acceptor = acceptor.clone();
        let connector = connector.clone();
        let s = s.clone();
        let dumper = dumper.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_conn(inbound, peer, acceptor, connector, s, dumper).await {
                tracing::warn!("conn {peer} ended: {e}");
            }
        });
    }
}

async fn handle_conn(
    inbound: TcpStream,
    peer: SocketAddr,
    acceptor: TlsAcceptor,
    connector: TlsConnector,
    s: Arc<Settings>,
    dumper: Arc<Dumper>,
) -> anyhow::Result<()> {
    // 1. Terminate the client's TLS, presenting the REAL leaf cert.
    let client_tls = acceptor.accept(inbound).await?;

    // 2. Dial the real server over a SO_MARK-tagged socket, then TLS upstream.
    let server_addr = SocketAddr::from((s.server_ip, s.server_port));
    let std_up = upstream_socket(server_addr, s.fwmark)?;
    let up = TcpStream::from_std(std_up)?;
    let server_name = upstream_server_name(&s)?;
    let server_tls = connector.connect(server_name, up).await?;

    // 3. Pump bytes both ways, dumping decrypted plaintext per direction.
    //
    // Both directions write into the single `ConnDump`, so we drive them from
    // one `select!` loop (rather than two concurrently-borrowing tasks) — the
    // dump writes are non-blocking file appends, so this does not stall the
    // network path in practice.
    let mut conn = dumper.open_conn(peer, server_addr);
    let (mut cr, mut cw) = tokio::io::split(client_tls);
    let (mut sr, mut sw) = tokio::io::split(server_tls);

    let mut c2s_buf = [0u8; 16384];
    let mut s2c_buf = [0u8; 16384];
    let mut c2s_open = true;
    let mut s2c_open = true;

    while c2s_open || s2c_open {
        tokio::select! {
            r = cr.read(&mut c2s_buf), if c2s_open => {
                match r {
                    Ok(0) | Err(_) => { c2s_open = false; sw.shutdown().await.ok(); }
                    Ok(n) => {
                        conn.write_c2s(&c2s_buf[..n]);
                        if sw.write_all(&c2s_buf[..n]).await.is_err() { c2s_open = false; }
                    }
                }
            }
            r = sr.read(&mut s2c_buf), if s2c_open => {
                match r {
                    Ok(0) | Err(_) => { s2c_open = false; cw.shutdown().await.ok(); }
                    Ok(n) => {
                        conn.write_s2c(&s2c_buf[..n]);
                        if cw.write_all(&s2c_buf[..n]).await.is_err() { s2c_open = false; }
                    }
                }
            }
        }
    }

    conn.finish(&s.dump_path);
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
        Settings {
            client_ip: Ipv4Addr::new(10, 8, 0, 5),
            server_ip,
            server_port: 0,
            tun_iface: "tun0".into(),
            egress_iface: "eth0".into(),
            local_ip: Ipv4Addr::LOCALHOST,
            local_port: 0,
            fwmark: 0,
            cert_path: cert.to_path_buf(),
            key_path: key.to_path_buf(),
            dump_path: PathBuf::from("/tmp"),
            bpf_obj_name: "mymitm".into(),
            box_ip: Ipv4Addr::new(192, 168, 1, 10),
            log_level: "info".into(),
            server_name: None,
        }
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
        let dumper = Arc::new(Dumper::new(&dump_dir).unwrap());
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
            tokio::spawn(async move {
                let (inbound, peer) = proxy_listener.accept().await.unwrap();
                handle_conn(inbound, peer, acceptor, connector, settings, dumper)
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
}
