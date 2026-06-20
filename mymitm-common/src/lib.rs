#![no_std]

pub const VERSION: u32 = 1;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Config {
    pub client_ip: u32,
    pub server_ip: u32,
    pub box_ip: u32,
    pub local_ip: u32,
    pub server_port: u16,
    pub local_port: u16,
    pub fwmark: u32,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct UpstreamKey {
    pub server_ip: u32,
    pub client_ip: u32,
    pub server_port: u16,
    pub client_port: u16,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct UpstreamVal {
    pub box_ip: u32,
    pub box_port: u16,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Rewrite { None, DnatToLocal, UnDnatFromLocal, SnatToClient, UnSnatToBox }

#[derive(Clone, Copy)]
pub struct PktMeta {
    pub src_ip: u32,
    pub dst_ip: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub mark: u32,
}

pub fn classify_tun(m: &PktMeta, cfg: &Config, egress: bool) -> Rewrite {
    if !egress {
        if m.src_ip == cfg.client_ip && m.dst_ip == cfg.server_ip && m.dst_port == cfg.server_port {
            return Rewrite::DnatToLocal;
        }
    } else if m.src_ip == cfg.local_ip && m.src_port == cfg.local_port && m.dst_ip == cfg.client_ip {
        return Rewrite::UnDnatFromLocal;
    }
    Rewrite::None
}

/// v1 single-client invariant: the ingress un-SNAT branch matches purely on
/// `(src == server:port, dst == client_ip)` with no per-flow conntrack. This is
/// correct in v1 because the only traffic that can match that shape is our own
/// upstream's replies — there is a single target client, and the box does not
/// otherwise originate connections to `server:port` on behalf of `client_ip`.
/// (Multi-client / general conntrack is an accepted post-v1 follow-up.)
pub fn classify_eth(m: &PktMeta, cfg: &Config, egress: bool) -> Rewrite {
    if egress {
        if m.mark == cfg.fwmark && m.dst_ip == cfg.server_ip && m.dst_port == cfg.server_port {
            return Rewrite::SnatToClient;
        }
    } else if m.src_ip == cfg.server_ip && m.src_port == cfg.server_port && m.dst_ip == cfg.client_ip {
        return Rewrite::UnSnatToBox;
    }
    Rewrite::None
}

#[cfg(feature = "user")]
mod pod {
    use super::*;
    unsafe impl aya::Pod for Config {}
    unsafe impl aya::Pod for UpstreamKey {}
    unsafe impl aya::Pod for UpstreamVal {}
}

#[cfg(test)]
mod tests {
    use super::*;
    // helper: build a Config in network byte order
    fn cfg() -> Config {
        Config {
            client_ip: u32::from(core::net::Ipv4Addr::new(10,8,0,5)).to_be(),
            server_ip: u32::from(core::net::Ipv4Addr::new(192,168,1,50)).to_be(),
            box_ip:    u32::from(core::net::Ipv4Addr::new(192,168,1,10)).to_be(),
            local_ip:  u32::from(core::net::Ipv4Addr::new(127,0,0,1)).to_be(),
            server_port: 443u16.to_be(),
            local_port:  8443u16.to_be(),
            fwmark: 0x1337,
        }
    }
    fn meta(s: (&str,u16), d: (&str,u16), mark: u32) -> PktMeta {
        PktMeta {
            src_ip: u32::from(s.0.parse::<core::net::Ipv4Addr>().unwrap()).to_be(),
            dst_ip: u32::from(d.0.parse::<core::net::Ipv4Addr>().unwrap()).to_be(),
            src_port: s.1.to_be(), dst_port: d.1.to_be(), mark,
        }
    }

    #[test]
    fn tun_ingress_target_is_dnatted() {
        let r = classify_tun(&meta(("10.8.0.5",43012),("192.168.1.50",443),0), &cfg(), false);
        assert_eq!(r, Rewrite::DnatToLocal);
    }
    #[test]
    fn tun_ingress_other_client_untouched() {
        let r = classify_tun(&meta(("10.8.0.9",43012),("192.168.1.50",443),0), &cfg(), false);
        assert_eq!(r, Rewrite::None);
    }
    #[test]
    fn tun_egress_reply_is_undnatted() {
        let r = classify_tun(&meta(("127.0.0.1",8443),("10.8.0.5",43012),0), &cfg(), true);
        assert_eq!(r, Rewrite::UnDnatFromLocal);
    }
    #[test]
    fn eth_egress_marked_is_snatted() {
        let r = classify_eth(&meta(("192.168.1.10",51000),("192.168.1.50",443),0x1337), &cfg(), true);
        assert_eq!(r, Rewrite::SnatToClient);
    }
    #[test]
    fn eth_egress_unmarked_untouched() {
        let r = classify_eth(&meta(("192.168.1.10",51000),("192.168.1.50",443),0), &cfg(), true);
        assert_eq!(r, Rewrite::None);
    }
    #[test]
    fn eth_ingress_reply_to_client_is_unsnatted() {
        let r = classify_eth(&meta(("192.168.1.50",443),("10.8.0.5",51000),0), &cfg(), false);
        assert_eq!(r, Rewrite::UnSnatToBox);
    }
}
