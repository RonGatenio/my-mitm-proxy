#![no_std]
#![no_main]

//! eBPF data plane for mymitmproxy.
//!
//! Task 6 implements the `tun0` (L3) classifiers `cls_tun_ingress` /
//! `cls_tun_egress`: DNAT the target client->server flow to the local listener
//! on ingress, and un-DNAT the listener's replies back to look like they came
//! from the real server on egress. The actual rewrite decision is delegated to
//! the host-unit-tested `mymitm_common::classify_tun`; this crate is only the
//! thin kernel glue that reads the skb, asks the classifier, and applies the
//! rewrite + checksum fixups via BPF helpers.
//!
//! API note (versions pinned: aya-ebpf 0.1.1, network-types 0.2.0):
//! - `TcContext::{load, store, l3_csum_replace, l4_csum_replace, data, data_end}`.
//!   `load`/`store` are helper-based (`bpf_skb_load_bytes`/`store_bytes`), so they
//!   are bounds-checked by the kernel; we still add an explicit `data_end` guard.
//! - The skb `mark` has no public getter; it is read via the public raw field
//!   `ctx.skb.skb` (a `*mut __sk_buff`).
//! - network-types header fields are raw byte arrays (e.g. `Ipv4Hdr.src_addr:
//!   [u8;4]`). We work with fixed byte offsets and load/store `u32`/`u16` so the
//!   values stay in network byte order end-to-end.

use aya_ebpf::{
    bindings::{BPF_F_PSEUDO_HDR, TC_ACT_OK},
    macros::{classifier, map},
    maps::Array,
    programs::TcContext,
};
use mymitm_common::{classify_tun, Config, PktMeta, Rewrite};
use network_types::{eth::EthHdr, ip::Ipv4Hdr, tcp::TcpHdr};

/// Single-entry config map (index 0 -> Config), populated by userspace.
#[map]
static CONFIG: Array<Config> = Array::with_max_entries(1, 0);

const ETH_LEN: usize = EthHdr::LEN; // 14
const IP_MIN_LEN: usize = Ipv4Hdr::LEN; // 20
const TCP_MIN_LEN: usize = TcpHdr::LEN; // 20

// Byte offsets within the IPv4 header (network-types 0.2.0 layout, repr(C)).
const IP_OFF_PROTO: usize = 9;
const IP_OFF_CHECK: usize = 10;
const IP_OFF_SRC: usize = 12;
const IP_OFF_DST: usize = 16;
const IPPROTO_TCP: u8 = 6;

// Byte offsets within the TCP header.
const TCP_OFF_SRC: usize = 0;
const TCP_OFF_DST: usize = 2;
const TCP_OFF_CHECK: usize = 16;

/// Read the single Config entry. Returns None if userspace hasn't populated it.
#[inline(always)]
fn cfg() -> Option<Config> {
    CONFIG.get(0).copied()
}

/// Parse L2 (if any) + IPv4 + TCP headers into a PktMeta and report the L3/L4
/// byte offsets so the rewrite helpers can target the right fields.
///
/// Auto-detects L2: a `tun` is L3 (raw IPv4, offset 0). If the first nibble is
/// not 4 we assume an Ethernet frame (so the same helper is reusable on `eth0`
/// in Task 7). Returns `(meta, l3_off, l4_off)`.
#[inline(always)]
fn meta(ctx: &TcContext) -> Option<(PktMeta, usize, usize)> {
    // Detect L2 by the IP-version nibble of the first byte.
    let first: u8 = ctx.load(0).ok()?;
    let l3 = if (first >> 4) == 4 {
        0
    } else {
        // Ethernet: confirm it carries IPv4 before trusting the offset.
        let eth_proto: u16 = ctx.load(ETH_LEN - 2).ok()?; // ether_type, NBO
        // network-types EtherType::Ipv4 == 0x0800u16.to_be(); compare in NBO.
        if eth_proto != 0x0800u16.to_be() {
            return None;
        }
        ETH_LEN
    };

    // Explicit bounds guard (belt-and-suspenders; load helpers also bound-check).
    if ctx.data() + l3 + IP_MIN_LEN + TCP_MIN_LEN > ctx.data_end() {
        return None;
    }

    // IPv4: verify version again at l3 and require TCP.
    let vihl: u8 = ctx.load(l3).ok()?;
    if (vihl >> 4) != 4 {
        return None;
    }
    let proto: u8 = ctx.load(l3 + IP_OFF_PROTO).ok()?;
    if proto != IPPROTO_TCP {
        return None;
    }
    let ihl = ((vihl & 0x0f) as usize) * 4;
    if ihl < IP_MIN_LEN {
        return None;
    }
    let l4 = l3 + ihl;

    // Addresses/ports loaded as raw u32/u16 -> stay in network byte order.
    let src_ip: u32 = ctx.load(l3 + IP_OFF_SRC).ok()?;
    let dst_ip: u32 = ctx.load(l3 + IP_OFF_DST).ok()?;
    let src_port: u16 = ctx.load(l4 + TCP_OFF_SRC).ok()?;
    let dst_port: u16 = ctx.load(l4 + TCP_OFF_DST).ok()?;

    let m = PktMeta {
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        // skb mark: no public getter in aya-ebpf 0.1.1, read the raw field.
        mark: unsafe { (*ctx.skb.skb).mark },
    };
    Some((m, l3, l4))
}

/// DNAT: rewrite the destination IP:port and fix the IPv4 + TCP checksums.
/// `new_ip`/`new_port` are in network byte order.
#[inline(always)]
fn set_dst(
    ctx: &mut TcContext,
    l3: usize,
    l4: usize,
    new_ip: u32,
    new_port: u16,
) -> Result<(), i64> {
    let old_ip: u32 = ctx.load(l3 + IP_OFF_DST)?;
    let old_port: u16 = ctx.load(l4 + TCP_OFF_DST)?;

    // L3 checksum: IP address change only affects the IPv4 header checksum.
    ctx.l3_csum_replace(l3 + IP_OFF_CHECK, old_ip as u64, new_ip as u64, 4)?;
    // L4 checksum: the destination IP is part of the TCP pseudo-header.
    ctx.l4_csum_replace(
        l4 + TCP_OFF_CHECK,
        old_ip as u64,
        new_ip as u64,
        (BPF_F_PSEUDO_HDR | 4) as u64,
    )?;
    // L4 checksum: the destination port lives in the TCP header itself.
    ctx.l4_csum_replace(l4 + TCP_OFF_CHECK, old_port as u64, new_port as u64, 2)?;

    // Write the new values (no flags; csum already adjusted above).
    ctx.store(l3 + IP_OFF_DST, &new_ip, 0)?;
    ctx.store(l4 + TCP_OFF_DST, &new_port, 0)?;
    Ok(())
}

/// Un-DNAT / SNAT: rewrite the source IP:port and fix the checksums.
/// `new_ip`/`new_port` are in network byte order.
#[inline(always)]
fn set_src(
    ctx: &mut TcContext,
    l3: usize,
    l4: usize,
    new_ip: u32,
    new_port: u16,
) -> Result<(), i64> {
    let old_ip: u32 = ctx.load(l3 + IP_OFF_SRC)?;
    let old_port: u16 = ctx.load(l4 + TCP_OFF_SRC)?;

    ctx.l3_csum_replace(l3 + IP_OFF_CHECK, old_ip as u64, new_ip as u64, 4)?;
    ctx.l4_csum_replace(
        l4 + TCP_OFF_CHECK,
        old_ip as u64,
        new_ip as u64,
        (BPF_F_PSEUDO_HDR | 4) as u64,
    )?;
    ctx.l4_csum_replace(l4 + TCP_OFF_CHECK, old_port as u64, new_port as u64, 2)?;

    ctx.store(l3 + IP_OFF_SRC, &new_ip, 0)?;
    ctx.store(l4 + TCP_OFF_SRC, &new_port, 0)?;
    Ok(())
}

#[classifier]
pub fn cls_tun_ingress(mut ctx: TcContext) -> i32 {
    run_tun(&mut ctx, false)
}

#[classifier]
pub fn cls_tun_egress(mut ctx: TcContext) -> i32 {
    run_tun(&mut ctx, true)
}

#[inline(always)]
fn run_tun(ctx: &mut TcContext, egress: bool) -> i32 {
    let (Some((m, l3, l4)), Some(c)) = (meta(ctx), cfg()) else {
        return TC_ACT_OK;
    };
    match classify_tun(&m, &c, egress) {
        // Ingress: target client->server gets its dst rewritten to the listener.
        Rewrite::DnatToLocal => {
            let _ = set_dst(ctx, l3, l4, c.local_ip, c.local_port);
        }
        // Egress: listener's reply gets its src rewritten back to the real server.
        Rewrite::UnDnatFromLocal => {
            let _ = set_src(ctx, l3, l4, c.server_ip, c.server_port);
        }
        _ => {}
    }
    TC_ACT_OK
}

// Placeholder eth classifiers (real DNAT/SNAT logic lands in Task 7). Kept so
// the object exports all four program names the userspace loader expects.
#[classifier]
pub fn cls_eth_ingress(_ctx: TcContext) -> i32 {
    TC_ACT_OK
}

#[classifier]
pub fn cls_eth_egress(_ctx: TcContext) -> i32 {
    TC_ACT_OK
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
