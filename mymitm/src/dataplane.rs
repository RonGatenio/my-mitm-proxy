//! Data-plane abstraction. Both the eBPF and iproute planes implement
//! `DataPlane::upstream_socket`, which opens the per-connection upstream socket
//! carrying the client's source IP by that plane's mechanism. Each concrete
//! plane reverses all kernel state it installs in its own `Drop`.

use std::io;
use std::net::{Ipv4Addr, SocketAddrV4, TcpStream};

pub trait DataPlane: Send + Sync {
    fn upstream_socket(&self, client_ip: Ipv4Addr, server: SocketAddrV4) -> io::Result<TcpStream>;
}

/// Plain `connect()` with no source-IP preservation — a test-only `DataPlane`
/// for the loopback proxy tests, which exercise terminate/dial/pump/dump with no
/// kernel plumbing. It is not wired to any `DataPlaneKind` variant, so it is
/// compiled only under `cfg(test)`; add a `DataPlaneKind` variant in `config.rs`
/// if a runtime debug plane is ever wanted.
#[cfg(test)]
pub struct DirectPlane;

#[cfg(test)]
impl DataPlane for DirectPlane {
    fn upstream_socket(&self, _client_ip: Ipv4Addr, server: SocketAddrV4) -> io::Result<TcpStream> {
        let s = TcpStream::connect(server)?;
        s.set_nonblocking(true)?;
        Ok(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;

    #[test]
    fn direct_plane_connects_and_roundtrips() {
        let l = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let addr = match l.local_addr().unwrap() { std::net::SocketAddr::V4(a) => a, _ => unreachable!() };
        let h = std::thread::spawn(move || {
            let (mut c, _) = l.accept().unwrap();
            let mut b = [0u8; 4]; c.read_exact(&mut b).unwrap();
            c.write_all(&b).unwrap();
        });
        let s = DirectPlane.upstream_socket(Ipv4Addr::new(10, 8, 0, 5), addr).unwrap();
        s.set_nonblocking(false).unwrap();
        let mut s = s;
        s.write_all(b"ping").unwrap();
        let mut b = [0u8; 4]; s.read_exact(&mut b).unwrap();
        assert_eq!(&b, b"ping");
        h.join().unwrap();
    }
}
