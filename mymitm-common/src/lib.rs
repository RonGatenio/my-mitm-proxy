#![no_std]

pub const VERSION: u32 = 1;

/// Default firewall mark stamped on the proxy's upstream sockets (and matched by
/// the eBPF egress classifier / iproute fwmark rule). Must be non-zero.
pub const DEFAULT_FWMARK: u32 = 0x1337;

/// Capacity of the self-evicting LRU maps. `UPSTREAM` holds reverse SNAT
/// mappings; `EGRESS` holds box-ephemeral-port -> client-IP. LRU so a missed
/// userspace cleanup can never permanently wedge either map.
pub const UPSTREAM_MAP_CAPACITY: u32 = 1024;
pub const EGRESS_MAP_CAPACITY: u32 = 1024;

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
    /// Explicit padding to ensure all bytes are initialised before passing this
    /// struct as a map value pointer. Without this, the compiler emits 2 bytes
    /// of uninitialised tail-padding (box_ip:4 + box_port:2 + implicit pad:2 =
    /// 8) which the 4.x BPF verifier rejects as "invalid indirect read from
    /// stack" when the stack-local value is passed to bpf_map_update_elem.
    pub _pad: u16,
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
        // Ingress: any client (or the restricted one) -> target server gets DNAT'd.
        let client_ok = cfg.client_ip == 0 || m.src_ip == cfg.client_ip;
        if client_ok && m.dst_ip == cfg.server_ip && m.dst_port == cfg.server_port {
            return Rewrite::DnatToLocal;
        }
    } else if m.src_ip == cfg.local_ip && m.src_port == cfg.local_port {
        // Egress: any reply from our listener is ours -> un-DNAT back to server.
        return Rewrite::UnDnatFromLocal;
    }
    Rewrite::None
}

/// v2: client IP is dynamic. The egress branch signals SnatToClient; the SNAT
/// target IP is resolved by the eBPF program from the EGRESS map (box ephemeral
/// port -> client IP). The ingress branch matches purely on (src==server:port);
/// the UPSTREAM map lookup (keyed on the packet's own dst==client) decides whether
/// the reply is one of ours, so no client_ip condition is needed here.
pub fn classify_eth(m: &PktMeta, cfg: &Config, egress: bool) -> Rewrite {
    if egress {
        if m.mark == cfg.fwmark && m.dst_ip == cfg.server_ip && m.dst_port == cfg.server_port {
            return Rewrite::SnatToClient;
        }
    } else if m.src_ip == cfg.server_ip && m.src_port == cfg.server_port {
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

    // client_ip == 0 means "any client" -> wildcard DNAT on tun ingress.
    fn cfg_wild() -> Config {
        let mut c = cfg();
        c.client_ip = 0; // 0.0.0.0 wildcard
        c
    }

    #[test]
    fn tun_ingress_wildcard_dnats_any_client() {
        let c = cfg_wild();
        // two different clients, both hitting the target server -> both DNAT
        assert_eq!(classify_tun(&meta(("10.8.0.5",40000),("192.168.1.50",443),0), &c, false), Rewrite::DnatToLocal);
        assert_eq!(classify_tun(&meta(("10.8.0.99",40001),("192.168.1.50",443),0), &c, false), Rewrite::DnatToLocal);
    }

    #[test]
    fn tun_ingress_wildcard_ignores_other_server() {
        let c = cfg_wild();
        assert_eq!(classify_tun(&meta(("10.8.0.5",40000),("192.168.1.77",443),0), &c, false), Rewrite::None);
    }

    #[test]
    fn tun_ingress_restrict_mode_still_filters_client() {
        // client_ip set -> only that client is intercepted
        assert_eq!(classify_tun(&meta(("10.8.0.9",40000),("192.168.1.50",443),0), &cfg(), false), Rewrite::None);
        assert_eq!(classify_tun(&meta(("10.8.0.5",40000),("192.168.1.50",443),0), &cfg(), false), Rewrite::DnatToLocal);
    }

    #[test]
    fn tun_egress_undnats_reply_to_any_client() {
        // reply from our listener to ANY client dst -> un-DNAT (no dst==client check)
        let c = cfg_wild();
        assert_eq!(classify_tun(&meta(("127.0.0.1",8443),("10.8.0.99",40001),0), &c, true), Rewrite::UnDnatFromLocal);
    }

    #[test]
    fn eth_ingress_unsnats_reply_to_any_client() {
        // server reply to ANY client -> un-SNAT (no dst==client check)
        let c = cfg_wild();
        assert_eq!(classify_eth(&meta(("192.168.1.50",443),("10.8.0.99",51000),0), &c, false), Rewrite::UnSnatToBox);
    }
}
