//! Namespace mode: run the data plane inside a network namespace so the host
//! firewall never sees a locally-terminated flow.
//!
//! ## The problem
//!
//! Interception turns ONE forwarded flow into TWO locally-terminated ones. The
//! client's SYN is rewritten to `local_addr:local_port` and delivered via
//! **INPUT**; the proxy dials the server itself, so that leg is locally
//! generated and leaves via **OUTPUT**. A box whose firewall permits only
//! `FORWARD -> server` drops both legs — in *either* data plane, because this is
//! chain traversal and not anything plane-specific.
//!
//! ## The mechanism
//!
//! Both legs become *forwarded* traffic again from the host's point of view:
//!
//! ```text
//!   client --[tun_iface]--FORWARD--> vc_h |netns| vc_n --> rewrite --> listener
//!   server <-[egress_iface]-FORWARD- vu_h |netns| vu_n <-- upstream socket
//! ```
//!
//! The destination address is still the real server for the whole time the
//! packet is in the host's stack — the rewrite to `local_addr:local_port`
//! happens INSIDE the namespace, where the chains are empty. So the host's
//! existing `FORWARD -d <server> --dport <port> -j ACCEPT` rule matches BOTH
//! legs (measured: its counter shows exactly two accepted SYNs per session) and
//! nothing in the firewall has to change.
//!
//! Because `net.ipv4.conf.*` is namespaced, the `route_localnet` / `rp_filter`
//! changes made by [`crate::sysctl`] land inside the namespace and never touch
//! the box — which also retires the box-wide `conf.all.rp_filter=0` caveat.
//!
//! ## Why TWO veth pairs
//!
//! One pair (`tun_iface == egress_iface`) is tempting and fails subtly: all four
//! classifiers then share two hooks, and tc runs them in `pref` order under
//! `direct-action`, where the FIRST program to return `TC_ACT_OK` ends the
//! chain. On ingress `cls_eth_ingress` takes the lower pref, accepts every
//! client packet (it only matches replies *from* the server), and
//! `cls_tun_ingress` never runs — so nothing is rewritten. Measured on 4.15:
//! the flow was routed straight through the namespace to the server,
//! un-intercepted, while the client still saw a healthy HTTP 200. Two pairs give
//! each hook exactly one program, which is the arrangement the product already
//! validates on real interfaces.
//!
//! The namespace also runs with `ip_forward=0`: if interception ever misses, the
//! packet is DROPPED rather than quietly forwarded to the server in the clear.
//! Fail closed, not fail open.
//!
//! ## Requirements on the host firewall
//!
//! - `FORWARD` accepts NEW to `<server>:<port>` **without** an `-i`/`-o` match —
//!   a rule pinned to `-i tun0 -o eth0` will not match `-o vc_h` / `-i vu_h`.
//! - `FORWARD` accepts `ESTABLISHED,RELATED` (both return paths).
//! - `net.ipv4.ip_forward=1` on the host.
//!
//! [`preflight`] checks these and fails fast with the exact diagnosis rather
//! than letting the proxy start into a silent blackhole.

use std::net::Ipv4Addr;
use std::process::Command;

use crate::config::Settings;

// ---------------------------------------------------------------------------
// Naming and addressing
// ---------------------------------------------------------------------------

/// Host- and namespace-side interface names.
///
/// Fixed rather than derived: the two policy-routing tables are already keyed on
/// `fwmark` so two instances cannot fight over routes, and running two proxies
/// on one box is not a supported configuration today. Keeping the names stable
/// keeps `--cleanup` and the operator-facing docs unambiguous.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Names {
    pub ns: String,
    /// Client-leg veth: host side.
    pub vc_h: String,
    /// Client-leg veth: namespace side. Becomes the child's `tun_iface`.
    pub vc_n: String,
    /// Upstream-leg veth: host side.
    pub vu_h: String,
    /// Upstream-leg veth: namespace side. Becomes the child's `egress_iface`.
    pub vu_n: String,
}

impl Default for Names {
    fn default() -> Self {
        Names {
            ns: "mitm".into(),
            vc_h: "mmc0".into(),
            vc_n: "mmc1".into(),
            vu_h: "mmu0".into(),
            vu_n: "mmu1".into(),
        }
    }
}

/// RFC 3927 link-local /30s, so the plumbing cannot collide with any routable
/// address the box actually uses.
pub const CH_ADDR: Ipv4Addr = Ipv4Addr::new(169, 254, 7, 1);
pub const CN_ADDR: Ipv4Addr = Ipv4Addr::new(169, 254, 7, 2);
pub const UH_ADDR: Ipv4Addr = Ipv4Addr::new(169, 254, 8, 1);
pub const UN_ADDR: Ipv4Addr = Ipv4Addr::new(169, 254, 8, 2);
const PFX: u8 = 30;

/// Bases for the derived policy-routing tables and rule priorities. Chosen to
/// stay clear of the iproute plane's own table (`100 + (fwmark & 0xff)`) and its
/// `30000 + table` rule priority.
const T_IN_BASE: u32 = 300;
const T_BACK_BASE: u32 = 400;
const P_IN_BASE: u32 = 31_000;
const P_BACK_BASE: u32 = 32_000;
/// Priority for the throwaway rule [`probe_l4_rule_support`] adds and deletes.
/// Below both bases so it cannot collide with a live steer.
const P_PROBE: u32 = 30_999;

/// The settings the child process must run with: the namespace-side interfaces
/// and the box IP the upstream socket binds inside the namespace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InnerCfg {
    pub tun_iface: String,
    pub egress_iface: String,
    pub box_ip: Ipv4Addr,
}

// ---------------------------------------------------------------------------
// Pure plumbing spec (no side effects, unit-tested without root)
// ---------------------------------------------------------------------------

/// One plumbing step: a command to run, and how to undo it (when undoing it
/// individually is meaningful — deleting the namespace or a veth already removes
/// everything configured *inside* or *on* it, so most steps have no separate
/// inverse).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Step {
    pub prog: &'static str,
    pub args: Vec<String>,
    pub undo: Option<Vec<String>>,
}

fn step(prog: &'static str, args: &[&str], undo: Option<&[&str]>) -> Step {
    Step {
        prog,
        args: args.iter().map(|s| s.to_string()).collect(),
        undo: undo.map(|u| u.iter().map(|s| s.to_string()).collect()),
    }
}

/// The full namespace plumbing for `cfg`, as data.
#[derive(Debug, Clone)]
pub struct Plumbing {
    pub names: Names,
    pub inner: InnerCfg,
    pub t_in: u32,
    pub t_back: u32,
    pub p_in: u32,
    pub p_back: u32,
    pub steps: Vec<Step>,
    /// Sysctls written on the HOST. Not saved/restored: they apply to interfaces
    /// this module creates and destroys, so there is no prior value to preserve.
    pub host_sysctls: Vec<(String, &'static str)>,
}

/// Build the plumbing spec without executing anything.
///
/// `l4_steer` selects whether the two steer rules carry `ipproto tcp` +
/// `dport`/`sport` selectors. They are what keeps non-TCP and other-port traffic
/// to the same server OUT of the namespace — which matters because the namespace
/// runs with `ip_forward=0`, so anything steered in that the classifiers do not
/// rewrite is dropped. An RD Gateway is the motivating case: it serves the tunnel
/// on TCP 443 and an optional UDP transport on 3391, and an unscoped steer would
/// blackhole the latter. FIB-rule L4 selectors need kernel ≥ 4.17 (and an
/// iproute2 that speaks the syntax), so callers pass the result of
/// [`probe_l4_rule_support`]; on an older kernel the unscoped form is used and
/// only TCP `server_port` survives.
pub fn build_plumbing(cfg: &Settings, l4_steer: bool) -> Plumbing {
    let n = Names::default();
    let mask = cfg.fwmark & 0xff;
    let (t_in, t_back) = (T_IN_BASE + mask, T_BACK_BASE + mask);
    let (p_in, p_back) = (P_IN_BASE + mask, P_BACK_BASE + mask);

    let server = cfg.server_ip.to_string();
    let port = cfg.server_port.to_string();
    let server32 = format!("{}/32", cfg.server_ip);
    let ch = CH_ADDR.to_string();
    let cn = CN_ADDR.to_string();
    let uh = UH_ADDR.to_string();
    let un = UN_ADDR.to_string();
    let ch_pfx = format!("{CH_ADDR}/{PFX}");
    let uh_pfx = format!("{UH_ADDR}/{PFX}");
    let cn_pfx = format!("{CN_ADDR}/{PFX}");
    let un_pfx = format!("{UN_ADDR}/{PFX}");
    let t_in_s = t_in.to_string();
    let t_back_s = t_back.to_string();
    let p_in_s = p_in.to_string();
    let p_back_s = p_back.to_string();

    let mut steps = Vec::new();

    // --- namespace + the two veth pairs ---------------------------------
    // `ip netns del` destroys the namespace-side veths, and destroying either
    // end of a veth pair destroys its peer, so the host-side deletes below are
    // belt-and-braces for a partially applied setup.
    steps.push(step("ip", &["netns", "add", &n.ns], Some(&["netns", "del", &n.ns])));
    steps.push(step(
        "ip",
        &["link", "add", &n.vc_h, "type", "veth", "peer", "name", &n.vc_n],
        Some(&["link", "del", &n.vc_h]),
    ));
    steps.push(step(
        "ip",
        &["link", "add", &n.vu_h, "type", "veth", "peer", "name", &n.vu_n],
        Some(&["link", "del", &n.vu_h]),
    ));
    steps.push(step("ip", &["link", "set", &n.vc_n, "netns", &n.ns], None));
    steps.push(step("ip", &["link", "set", &n.vu_n, "netns", &n.ns], None));

    // --- host side of the veths ------------------------------------------
    steps.push(step("ip", &["addr", "add", &ch_pfx, "dev", &n.vc_h], None));
    steps.push(step("ip", &["link", "set", &n.vc_h, "up"], None));
    steps.push(step("ip", &["addr", "add", &uh_pfx, "dev", &n.vu_h], None));
    steps.push(step("ip", &["link", "set", &n.vu_h, "up"], None));

    // --- inside the namespace --------------------------------------------
    steps.push(step("ip", &["netns", "exec", &n.ns, "ip", "link", "set", "lo", "up"], None));
    steps.push(step("ip", &["netns", "exec", &n.ns, "ip", "addr", "add", &cn_pfx, "dev", &n.vc_n], None));
    steps.push(step("ip", &["netns", "exec", &n.ns, "ip", "addr", "add", &un_pfx, "dev", &n.vu_n], None));
    steps.push(step("ip", &["netns", "exec", &n.ns, "ip", "link", "set", &n.vc_n, "up"], None));
    steps.push(step("ip", &["netns", "exec", &n.ns, "ip", "link", "set", &n.vu_n, "up"], None));
    // The upstream leg is the only traffic addressed to the server, so a /32
    // sends it out the upstream veth; everything else (the listener's replies,
    // whatever the client's address happens to be) takes the default out the
    // client veth. No policy routing inside, and no need to know the client
    // prefix in advance.
    steps.push(step(
        "ip",
        &["netns", "exec", &n.ns, "ip", "route", "add", &server32, "via", &uh, "dev", &n.vu_n],
        None,
    ));
    steps.push(step(
        "ip",
        &["netns", "exec", &n.ns, "ip", "route", "add", "default", "via", &ch, "dev", &n.vc_n],
        None,
    ));
    // Fail closed: a packet that was NOT rewritten to the listener dies here
    // instead of being forwarded on to the server unintercepted.
    steps.push(step(
        "ip",
        &["netns", "exec", &n.ns, "sysctl", "-wq", "net.ipv4.ip_forward=0"],
        None,
    ));

    // --- steer the client's flow into the namespace -----------------------
    // Scoped by INGRESS interface on purpose. A plain `<server>/32 via <netns>`
    // in the main table would also make the server's own replies arriving on the
    // egress interface look like they came the wrong way, forcing rp_filter off
    // on a real interface. Keeping the steer in a policy table leaves the MAIN
    // route to the server untouched, so the egress interface's reverse path
    // stays symmetric and needs no sysctl change at all.
    steps.push(step(
        "ip",
        &["route", "add", &server32, "via", &cn, "dev", &n.vc_h, "table", &t_in_s],
        Some(&["route", "flush", "table", &t_in_s]),
    ));
    // Scoped to TCP <server_port> when the kernel can: everything else addressed
    // to the server (the RD Gateway's UDP 3391 transport, ICMP) then stays on the
    // main table and is forwarded normally, instead of entering a namespace that
    // will not rewrite it and cannot forward it.
    let mut r_in: Vec<&str> =
        vec!["rule", "add", "priority", &p_in_s, "iif", &cfg.tun_iface, "to", &server];
    if l4_steer {
        r_in.extend_from_slice(&["ipproto", "tcp", "dport", &port]);
    }
    r_in.extend_from_slice(&["lookup", &t_in_s]);
    let mut r_in_del = r_in.clone();
    r_in_del[1] = "del";
    steps.push(step("ip", &r_in, Some(&r_in_del)));

    // --- steer the server's replies into the namespace --------------------
    // With source-IP preservation the reply's destination is the CLIENT's IP, so
    // the main table would send it back out to the real client. Match on
    // (arrived on the egress interface, came from the server) and hand it to the
    // namespace's upstream leg, where `cls_eth_ingress` un-SNATs it.
    steps.push(step(
        "ip",
        &["route", "add", "default", "via", &un, "dev", &n.vu_h, "table", &t_back_s],
        Some(&["route", "flush", "table", &t_back_s]),
    ));
    // The reply direction of the same flow, so the port selector is the SOURCE
    // port here. Not steering the server's ICMP costs nothing: the classifiers
    // only rewrite TCP, so ICMP steered into the namespace was dropped anyway.
    let mut r_back: Vec<&str> =
        vec!["rule", "add", "priority", &p_back_s, "iif", &cfg.egress_iface, "from", &server];
    if l4_steer {
        r_back.extend_from_slice(&["ipproto", "tcp", "sport", &port]);
    }
    r_back.extend_from_slice(&["lookup", &t_back_s]);
    let mut r_back_del = r_back.clone();
    r_back_del[1] = "del";
    steps.push(step("ip", &r_back, Some(&r_back_del)));

    // Each host-side veth receives traffic whose source the main table
    // associates with a different interface: the client-leg veth sees the
    // listener's replies (src = server, main says the egress iface) and the
    // upstream-leg veth sees the upstream leg (src = preserved client, main says
    // the tun iface). Loose mode accepts both. Note 2 > 1: the kernel takes
    // MAX(conf.all, conf.<iface>), so 2 LOOSENS even on a hardened box with
    // conf.all.rp_filter=1 — no box-wide change required.
    let host_sysctls = vec![
        (format!("net.ipv4.conf.{}.rp_filter", n.vc_h), "2"),
        (format!("net.ipv4.conf.{}.rp_filter", n.vu_h), "2"),
    ];

    Plumbing {
        inner: InnerCfg {
            tun_iface: n.vc_n.clone(),
            egress_iface: n.vu_n.clone(),
            box_ip: UN_ADDR,
        },
        names: n,
        t_in,
        t_back,
        p_in,
        p_back,
        steps,
        host_sysctls,
    }
}

// ---------------------------------------------------------------------------
// Preflight
// ---------------------------------------------------------------------------

/// Why namespace mode cannot work on this box, if it cannot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Blocker {
    NoForwarding,
    ForwardPinnedToIfaces(String),
    /// The permission is scoped to a source subnet, and source-IP preservation is
    /// off — so the upstream leg leaves with the namespace's own address and
    /// cannot match it. The client leg still would, which makes this a half-open
    /// failure that looks like a firewall bug.
    SourceScopedNeedsPreservation(String),
}

/// What the preflight concluded. A box can be fine in two distinguishable ways:
/// with a permission we positively identified, or with nothing to identify (no
/// firewall / permissive policy). Saying which is the difference between an
/// operator trusting the startup log and having to go read the ruleset.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Diagnosis {
    pub blocker: Option<Blocker>,
    /// The rule carrying the permission both legs will match, when found.
    pub confirmed_by: Option<String>,
    /// Set when nothing was confirmed AND the ruleset looks restrictive, i.e. the
    /// case where we cannot prove it will work and have reason to doubt it.
    pub unconfirmed_but_restrictive: bool,
}

/// A candidate ACCEPT: forward-reachable, and addressed to the server.
struct Candidate {
    rule: String,
    pins_iface: bool,
    src: Option<(Ipv4Addr, u8)>,
}

/// `true` if `ip` falls inside `net/len`.
fn cidr_contains(net: Ipv4Addr, len: u8, ip: Ipv4Addr) -> bool {
    if len == 0 {
        return true;
    }
    if len > 32 {
        return false;
    }
    let mask = u32::MAX << (32 - len as u32);
    (u32::from(net) & mask) == (u32::from(ip) & mask)
}

/// Does this rule's protocol/port narrowing still admit TCP `port`?
///
/// Load-bearing on the motivating box, whose ruleset carries TWO accepts for the
/// same server address — `--dport 443 -p tcp` and `--dport 3391 -p udp`. Crediting
/// the UDP one as the permission for our TCP flow would let the preflight confirm
/// a box that is about to blackhole.
///
/// An absent `-p` or `--dport` means "any", so absence admits everything.
fn permits_tcp_port(toks: &[&str], port: u16) -> bool {
    for w in toks.windows(2) {
        match w[0] {
            "-p" | "--protocol" => {
                if !matches!(w[1].to_ascii_lowercase().as_str(), "tcp" | "6") {
                    return false;
                }
            }
            // `--dport 443`, a `443:445` range, or multiport's comma list of both.
            "--dport" | "--dports" | "--destination-port" | "--destination-ports" => {
                let hit = w[1].split(',').any(|spec| match spec.split_once(':') {
                    Some((lo, hi)) => {
                        let lo = lo.parse::<u16>().unwrap_or(0);
                        let hi = hi.parse::<u16>().unwrap_or(u16::MAX);
                        (lo..=hi).contains(&port)
                    }
                    None => spec.parse::<u16>().map(|p| p == port).unwrap_or(false),
                });
                if !hit {
                    return false;
                }
            }
            _ => {}
        }
    }
    true
}

/// Parse an iptables address operand: `10.8.0.0/24`, `10.8.0.5`, `10.8.0.5/32`.
fn parse_cidr(s: &str) -> Option<(Ipv4Addr, u8)> {
    let (ip, len) = match s.split_once('/') {
        Some((i, l)) => (i, l.parse::<u8>().ok()?),
        None => (s, 32),
    };
    Some((ip.parse::<Ipv4Addr>().ok()?, len))
}

/// The chains a packet traversing FORWARD can actually reach, following `-j`/`-g`
/// jumps transitively. Without this the check is blind on any box using a
/// frontend: ufw's FORWARD chain holds nothing but jumps, and the real rules live
/// in `ufw-user-forward`.
///
/// A `-j TARGET` is a chain jump exactly when the dump also appends to `TARGET`,
/// which needs no list of built-in verdicts to stay correct. A jumped-to chain
/// with no rules of its own can hold no ACCEPT, so missing it is harmless.
fn forward_reachable_chains(rules: &str) -> std::collections::BTreeSet<String> {
    let mut appended: std::collections::BTreeSet<&str> = Default::default();
    for line in rules.lines() {
        if let Some(rest) = line.trim().strip_prefix("-A ") {
            if let Some(c) = rest.split_whitespace().next() {
                appended.insert(c);
            }
        }
    }
    let mut reach: std::collections::BTreeSet<String> = Default::default();
    reach.insert("FORWARD".to_string());
    loop {
        let mut grew = false;
        for line in rules.lines() {
            let Some(rest) = line.trim().strip_prefix("-A ") else { continue };
            let toks: Vec<&str> = rest.split_whitespace().collect();
            let Some(chain) = toks.first() else { continue };
            if !reach.contains(*chain) {
                continue;
            }
            for w in toks.windows(2) {
                if (w[0] == "-j" || w[0] == "-g")
                    && appended.contains(w[1])
                    && reach.insert(w[1].to_string())
                {
                    grew = true;
                }
            }
        }
        if !grew {
            break;
        }
    }
    reach
}

/// Does this ruleset look like it would drop what it does not explicitly permit?
/// Only used to decide whether an unconfirmed verdict deserves a warning, so a
/// heuristic is appropriate: a restrictive FORWARD policy, or a reachable
/// catch-all DROP/REJECT (which is how ufw closes the chain while leaving the
/// policy at ACCEPT).
fn forward_looks_restrictive(rules: &str, reach: &std::collections::BTreeSet<String>) -> bool {
    for line in rules.lines() {
        let l = line.trim();
        if l == "-P FORWARD DROP" || l == "-P FORWARD REJECT" {
            return true;
        }
        let Some(rest) = l.strip_prefix("-A ") else { continue };
        let toks: Vec<&str> = rest.split_whitespace().collect();
        let Some(chain) = toks.first() else { continue };
        if !reach.contains(*chain) {
            continue;
        }
        let terminal = toks
            .windows(2)
            .any(|w| w[0] == "-j" && (w[1] == "DROP" || w[1] == "REJECT"));
        // A catch-all: no address or port narrowing it to some other flow.
        let narrowed = toks
            .iter()
            .any(|t| matches!(*t, "-d" | "-s" | "--dport" | "--sport" | "--dports" | "--sports"));
        if terminal && !narrowed {
            return true;
        }
    }
    false
}

/// Decide whether namespace mode can work, from the facts that matter: whether
/// the host forwards at all, and whether its filter table's forward path carries
/// a permission that BOTH namespace legs will still match.
///
/// Pure so it can be unit-tested without root or a firewall. `filter_rules` is
/// the whole filter table (`iptables -S`), not just the FORWARD chain — see
/// [`forward_reachable_chains`].
///
/// Two ways an existing permission stops matching once the legs move into the
/// namespace:
///   - **interface pinning.** `-i tun0 -o eth0 -d <server> -j ACCEPT` permits the
///     flow today but cannot match `-o mmc0` (client leg) or `-i mmu0` (upstream
///     leg).
///   - **source scoping without preservation.** `-s <vpn_subnet> -d <server>
///     -j ACCEPT` matches the client leg either way, but the upstream leg only
///     carries a source in that subnet while `preserve_src_ip` is on.
pub fn diagnose(
    ip_forward: bool,
    filter_rules: &str,
    server: Ipv4Addr,
    server_port: u16,
    client: Option<Ipv4Addr>,
    preserve_src_ip: bool,
) -> Diagnosis {
    let none = |blocker| Diagnosis { blocker, confirmed_by: None, unconfirmed_but_restrictive: false };
    if !ip_forward {
        return none(Some(Blocker::NoForwarding));
    }

    let reach = forward_reachable_chains(filter_rules);
    let mut candidates: Vec<Candidate> = Vec::new();
    for line in filter_rules.lines() {
        let l = line.trim();
        let Some(rest) = l.strip_prefix("-A ") else { continue };
        let toks: Vec<&str> = rest.split_whitespace().collect();
        let Some(chain) = toks.first() else { continue };
        if !reach.contains(*chain) {
            continue;
        }
        if !toks.windows(2).any(|w| w[0] == "-j" && w[1] == "ACCEPT") {
            continue;
        }
        // Must be addressed TO the server: a `-s <server>` accept is the reply
        // direction, not the permission the client leg needs. Negated matches
        // (`! -d`) are not permissions for this destination either.
        let dst_is_server = toks.windows(2).any(|w| {
            w[0] == "-d" && parse_cidr(w[1]).map(|(ip, len)| ip == server && len == 32).unwrap_or(false)
        });
        if !dst_is_server || toks.contains(&"!") || !permits_tcp_port(&toks, server_port) {
            continue;
        }
        let src = toks
            .windows(2)
            .find(|w| w[0] == "-s")
            .and_then(|w| parse_cidr(w[1]));
        candidates.push(Candidate {
            rule: l.to_string(),
            pins_iface: toks.iter().any(|t| *t == "-i" || *t == "-o"),
            src,
        });
    }

    let mut pinned: Option<String> = None;
    let mut needs_pres: Option<String> = None;
    for c in candidates {
        if c.pins_iface {
            pinned.get_or_insert(c.rule);
            continue;
        }
        match c.src {
            // Destination-only: matches both legs regardless of what they carry.
            None => {
                return Diagnosis {
                    blocker: None,
                    confirmed_by: Some(c.rule),
                    unconfirmed_but_restrictive: false,
                }
            }
            Some((net, len)) => {
                // The upstream leg's source is the preserved client, or else the
                // namespace's own address.
                let upstream_ok = if preserve_src_ip {
                    // Unknown client (we intercept whichever one connects): we
                    // cannot check containment, so take the rule at its word.
                    client.map(|c| cidr_contains(net, len, c)).unwrap_or(true)
                } else {
                    cidr_contains(net, len, UN_ADDR)
                };
                if upstream_ok {
                    return Diagnosis {
                        blocker: None,
                        confirmed_by: Some(c.rule),
                        unconfirmed_but_restrictive: false,
                    };
                }
                // Scoped to a subnet our upstream leg will not be in. If that is
                // only because preservation is off, say so — it is fixable.
                if !preserve_src_ip && client.map(|c| cidr_contains(net, len, c)).unwrap_or(true) {
                    needs_pres.get_or_insert(c.rule);
                }
            }
        }
    }

    if let Some(rule) = needs_pres {
        return none(Some(Blocker::SourceScopedNeedsPreservation(rule)));
    }
    if let Some(rule) = pinned {
        return none(Some(Blocker::ForwardPinnedToIfaces(rule)));
    }
    // Nothing server-specific to confirm. Fine on a box with a permissive
    // forward path (the common case, and every box with no firewall) — but worth
    // saying out loud when the ruleset looks like it drops the unpermitted.
    Diagnosis {
        blocker: None,
        confirmed_by: None,
        unconfirmed_but_restrictive: forward_looks_restrictive(filter_rules, &reach),
    }
}

/// Human-facing explanation + remedy for a [`Blocker`].
pub fn blocker_message(b: &Blocker, names: &Names) -> String {
    match b {
        Blocker::NoForwarding => "netns mode needs net.ipv4.ip_forward=1 on the host: the client and \
             upstream legs are both FORWARDed through the namespace. Fix by ONE of:\n  \
             (a) enable forwarding: sysctl -w net.ipv4.ip_forward=1, or\n  \
             (b) pass --netns=false to run the data plane directly on the host interfaces."
            .to_string(),
        Blocker::ForwardPinnedToIfaces(rule) => format!(
            "netns mode cannot use this box's FORWARD permission because it is pinned to specific \
             interfaces:\n  {rule}\nIn netns mode the two legs traverse FORWARD as \
             `-o {vc_h}` (client leg) and `-i {vu_h}` (upstream leg), which that rule will not \
             match — the proxy would start and then silently blackhole. Fix by ONE of:\n  \
             (a) drop the -i/-o match from that rule so it matches on destination alone \
             (under ufw: replace `ufw route allow in on X out on Y to <server> …` with \
             `ufw route allow to <server> port <port> proto tcp`), or\n  \
             (b) add `-o {vc_h}` / `-i {vu_h}` companions to it, or\n  \
             (c) pass --netns=false and instead permit the two locally-terminated legs \
             (INPUT to the listener, OUTPUT to the server).",
            rule = rule,
            vc_h = names.vc_h,
            vu_h = names.vu_h,
        ),
        Blocker::SourceScopedNeedsPreservation(rule) => format!(
            "this box's forward permission for the server is scoped to a source subnet:\n  \
             {rule}\nbut source-IP preservation is OFF, so the upstream leg dials the server \
             from the namespace's own address ({un}) instead of the client's and will not match \
             it. The client leg still matches, so the proxy would accept the connection and then \
             hang on the upstream dial. Fix by ONE of:\n  \
             (a) drop --preserve-src-ip=false / set preserve_src_ip = true (the default), or\n  \
             (b) widen that rule to permit the box's own source as well, or\n  \
             (c) pass --netns=false.",
            rule = rule,
            un = UN_ADDR,
        ),
    }
}

/// Whether this kernel's FIB rules accept L4 selectors (`ipproto`, `dport`), so
/// the steer can be narrowed to TCP `server_port`. Added in 4.17.
///
/// Probed rather than derived from `uname`, because iproute2 has to speak the
/// syntax too and both failures look identical from here: `ip rule add` exits
/// non-zero. The probe rule matches nothing real and is deleted immediately.
pub fn probe_l4_rule_support() -> bool {
    let p = P_PROBE.to_string();
    let add: Vec<String> = ["rule", "add", "priority", &p, "iif", "lo", "to", "127.0.0.1",
                            "ipproto", "tcp", "dport", "1", "lookup", "253"]
        .iter().map(|s| s.to_string()).collect();
    if run("ip", &add).is_err() {
        return false;
    }
    let mut del = add.clone();
    del[1] = "del".to_string();
    let _ = run("ip", &del);
    true
}

/// Run the preflight against the live host. Fails fast rather than starting into
/// a silent blackhole.
pub fn preflight(cfg: &Settings) -> anyhow::Result<()> {
    let names = Names::default();
    let ip_forward = crate::sysctl::read_sysctl("net.ipv4.ip_forward")
        .map(|v| v.trim() == "1")
        .unwrap_or(false);
    // The WHOLE filter table, not just FORWARD: on any box with a firewall
    // frontend the forward permission lives in a jumped-to chain (ufw keeps it in
    // `ufw-user-forward`, and FORWARD itself holds only jumps).
    // A box with no iptables at all is fine — treat an unreadable ruleset as empty.
    let rules = Command::new("iptables")
        .arg("-S")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .unwrap_or_default();

    let d = diagnose(
        ip_forward,
        &rules,
        cfg.server_ip,
        cfg.server_port,
        cfg.client_ip,
        cfg.preserve_src_ip,
    );
    if let Some(b) = d.blocker {
        anyhow::bail!("{}", blocker_message(&b, &names));
    }
    match d.confirmed_by {
        Some(rule) => tracing::info!(
            %rule,
            "netns preflight: both legs will match this forward permission"
        ),
        None if d.unconfirmed_but_restrictive => tracing::warn!(
            "netns preflight: found no forward permission for {}:{} but this box's forward path \
             looks restrictive. If the proxy accepts connections and then hangs, that ruleset is \
             the first place to look — both legs must be permitted to/from the REAL server \
             address (they traverse FORWARD as -o {} and -i {}).",
            cfg.server_ip, cfg.server_port, names.vc_h, names.vu_h
        ),
        None => tracing::debug!("netns preflight: no server-specific forward rule to check"),
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Execution
// ---------------------------------------------------------------------------

fn run(prog: &str, args: &[String]) -> std::io::Result<()> {
    tracing::debug!("netns: {prog} {}", args.join(" "));
    let out = Command::new(prog).args(args).output()?;
    if !out.status.success() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!(
                "{prog} {} exited {}: {}",
                args.join(" "),
                out.status,
                String::from_utf8_lossy(&out.stderr).trim()
            ),
        ));
    }
    Ok(())
}

/// Owns the host-side namespace plumbing; `Drop` reverses it.
///
/// Held by the SUPERVISOR process, which stays in the host namespace — that is
/// the whole reason namespace mode re-execs a child instead of calling `setns`
/// in-process. A process that has moved into the namespace can no longer delete
/// the host's veths, rules or routing tables.
pub struct NetnsGuard {
    plumbing: Plumbing,
    /// How many steps were applied, so a mid-apply failure unwinds exactly.
    applied: usize,
}

impl NetnsGuard {
    /// Apply the plumbing. On any failure, reverses everything already applied
    /// before returning `Err` — never leaves a half-built namespace.
    pub fn setup(cfg: &Settings) -> anyhow::Result<(NetnsGuard, InnerCfg)> {
        // A previous unclean exit leaves the namespace and veths behind, and
        // `ip netns add` would then fail on the very first step. Clear first.
        cleanup(cfg);

        let l4_steer = probe_l4_rule_support();
        if !l4_steer {
            tracing::warn!(
                "this kernel's routing rules do not support L4 selectors (needs >= 4.17), so the \
                 steer cannot be narrowed to TCP {}. ALL traffic from {} to {} enters the \
                 namespace, and anything the classifiers do not rewrite (e.g. an RD Gateway's UDP \
                 3391 transport) is dropped there rather than forwarded.",
                cfg.server_port, cfg.tun_iface, cfg.server_ip
            );
        }
        let plumbing = build_plumbing(cfg, l4_steer);
        let inner = plumbing.inner.clone();
        let mut guard = NetnsGuard { plumbing, applied: 0 };

        for i in 0..guard.plumbing.steps.len() {
            let s = &guard.plumbing.steps[i];
            if let Err(e) = run(s.prog, &s.args) {
                let failed = format!("{} {}", s.prog, s.args.join(" "));
                guard.revert();
                return Err(anyhow::anyhow!("netns setup failed at `{failed}`: {e}"));
            }
            guard.applied = i + 1;
        }

        // Cloned so the loop does not hold a borrow of `guard` across `revert()`.
        let host_sysctls = guard.plumbing.host_sysctls.clone();
        for (key, want) in &host_sysctls {
            if let Err(e) = crate::sysctl::write_sysctl(key, want) {
                guard.revert();
                return Err(anyhow::anyhow!("netns setup failed setting {key}={want}: {e}"));
            }
        }

        tracing::info!(
            ns = %guard.plumbing.names.ns,
            client_leg = %format!("{}<->{}", guard.plumbing.names.vc_h, guard.plumbing.names.vc_n),
            upstream_leg = %format!("{}<->{}", guard.plumbing.names.vu_h, guard.plumbing.names.vu_n),
            // Logged so an operator can find exactly our state with
            // `ip rule show` / `ip route show table <n>`.
            table_in = guard.plumbing.t_in,
            table_back = guard.plumbing.t_back,
            prio_in = guard.plumbing.p_in,
            prio_back = guard.plumbing.p_back,
            "netns plumbing up; both legs now traverse the host's FORWARD chain"
        );
        Ok((guard, inner))
    }

    /// The namespace the supervised child must be executed in.
    pub fn ns(&self) -> &str {
        &self.plumbing.names.ns
    }

    /// Undo the applied steps in reverse order. Best-effort: every failure is
    /// ignored so one stuck step cannot strand the rest.
    fn revert(&mut self) {
        for i in (0..self.applied).rev() {
            if let Some(undo) = self.plumbing.steps[i].undo.clone() {
                let _ = run(self.plumbing.steps[i].prog, &undo);
            }
        }
        self.applied = 0;
    }
}

impl Drop for NetnsGuard {
    fn drop(&mut self) {
        self.revert();
        tracing::debug!("netns plumbing torn down");
    }
}

/// Best-effort reverse of leftovers from an unclean exit. Safe to call when
/// nothing is installed — every failure is ignored.
pub fn cleanup(cfg: &Settings) {
    // Both steer forms: whichever this kernel supports today, a leftover rule
    // could have been added in either shape (a kernel upgrade between runs, or a
    // `--cleanup` invoked on a different box). `ip rule del` must match the rule
    // exactly, so try both rather than probe and guess.
    for l4_steer in [true, false] {
        let p = build_plumbing(cfg, l4_steer);
        for s in p.steps.iter().rev() {
            if let Some(undo) = &s.undo {
                let _ = run(s.prog, undo);
            }
        }
    }
    // The probe's throwaway rule, in case a previous run died between add and del.
    let p = P_PROBE.to_string();
    let del: Vec<String> = ["rule", "del", "priority", &p, "iif", "lo", "to", "127.0.0.1",
                            "ipproto", "tcp", "dport", "1", "lookup", "253"]
        .iter().map(|s| s.to_string()).collect();
    let _ = run("ip", &del);
}

/// The argv for the supervised child: our own argv with namespace mode turned
/// off and the namespace-side interfaces appended.
///
/// Appending rather than rebuilding is deliberate — it preserves every override
/// the operator passed (`--data-plane`, `--alpn`, `--config`, …) without this
/// module having to know about any of them. clap takes the LAST occurrence of a
/// single-value argument, so the appended values win over anything earlier.
pub fn child_argv(argv: &[String], inner: &InnerCfg) -> Vec<String> {
    let mut out = argv.to_vec();
    out.push("--netns=false".into());
    out.push("--tun".into());
    out.push(inner.tun_iface.clone());
    out.push("--egress".into());
    out.push(inner.egress_iface.clone());
    out.push("--box-ip".into());
    out.push(inner.box_ip.to_string());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings() -> Settings {
        let mut s = Settings::test_default();
        s.server_ip = Ipv4Addr::new(10, 10, 2, 10);
        s.server_port = 443;
        s.tun_iface = "left0".into();
        s.egress_iface = "right0".into();
        s
    }

    #[test]
    fn inner_cfg_points_at_the_namespace_side_of_each_veth() {
        let p = build_plumbing(&settings(), true);
        // tun and egress MUST differ: one program per tc hook. A shared
        // interface lets the lower-pref classifier end the chain first.
        assert_eq!(p.inner.tun_iface, "mmc1");
        assert_eq!(p.inner.egress_iface, "mmu1");
        assert_ne!(p.inner.tun_iface, p.inner.egress_iface);
        assert_eq!(p.inner.box_ip, UN_ADDR);
    }

    #[test]
    fn tables_and_priorities_derive_from_fwmark() {
        let p = build_plumbing(&settings(), true);
        // 0x1337 & 0xff = 0x37 = 55
        assert_eq!(p.t_in, 300 + 55);
        assert_eq!(p.t_back, 400 + 55);
        assert_eq!(p.p_in, 31_000 + 55);
        assert_eq!(p.p_back, 32_000 + 55);
        // Must not collide with the iproute plane's table (100 + mask) or its
        // 30000 + table rule priority.
        assert_ne!(p.t_in, 100 + 55);
        assert_ne!(p.t_back, 100 + 55);
        assert!(p.p_in > 30_000 + (100 + 55));
    }

    #[test]
    fn namespace_is_created_first_and_removed_last() {
        let p = build_plumbing(&settings(), true);
        let first = &p.steps[0];
        assert_eq!(first.prog, "ip");
        assert_eq!(first.args[..3], ["netns", "add", "mitm"]);
        assert_eq!(first.undo.as_ref().unwrap()[..3], ["netns", "del", "mitm"]);
    }

    #[test]
    fn namespace_fails_closed_on_forwarding() {
        let p = build_plumbing(&settings(), true);
        // An un-rewritten packet must be dropped inside the namespace, not
        // forwarded on to the server in the clear.
        assert!(
            p.steps.iter().any(|s| s.args.iter().any(|a| a == "net.ipv4.ip_forward=0")),
            "namespace must set ip_forward=0"
        );
    }

    #[test]
    fn steer_rules_are_scoped_by_ingress_interface() {
        let p = build_plumbing(&settings(), true);
        let rules: Vec<&Step> = p.steps.iter().filter(|s| s.args.first().map(|a| a == "rule").unwrap_or(false)).collect();
        assert_eq!(rules.len(), 2, "one steer in, one steer back");
        // Inbound: from the tun iface, to the server.
        let a = &rules[0].args;
        assert!(a.contains(&"iif".to_string()) && a.contains(&"left0".to_string()));
        assert!(a.contains(&"to".to_string()) && a.contains(&"10.10.2.10".to_string()));
        // Return: from the server, arriving on the egress iface.
        let b = &rules[1].args;
        assert!(b.contains(&"iif".to_string()) && b.contains(&"right0".to_string()));
        assert!(b.contains(&"from".to_string()) && b.contains(&"10.10.2.10".to_string()));
    }

    #[test]
    fn steer_rules_are_scoped_to_tcp_server_port_when_supported() {
        let p = build_plumbing(&settings(), true);
        let rules: Vec<&Step> =
            p.steps.iter().filter(|s| s.args.first().map(|a| a == "rule").unwrap_or(false)).collect();
        let joined = |s: &Step| s.args.join(" ");
        // Client leg: the server is the DESTINATION, so dport.
        assert!(joined(rules[0]).contains("ipproto tcp dport 443"), "{}", joined(rules[0]));
        // Reply leg: the server is the SOURCE, so sport.
        assert!(joined(rules[1]).contains("ipproto tcp sport 443"), "{}", joined(rules[1]));
        // Undo must match the rule exactly or `ip rule del` will not find it.
        for r in &rules {
            let undo = r.undo.as_ref().unwrap();
            assert_eq!(undo[1], "del");
            assert_eq!(undo[2..], r.args[2..], "undo must differ only in add/del");
        }
    }

    #[test]
    fn steer_rules_fall_back_to_unscoped_without_l4_selectors() {
        // Pre-4.17 kernels reject `ipproto`/`dport` in a routing rule; the steer
        // then catches everything to the server, which is what the operator is
        // warned about at startup.
        let p = build_plumbing(&settings(), false);
        let rules: Vec<&Step> =
            p.steps.iter().filter(|s| s.args.first().map(|a| a == "rule").unwrap_or(false)).collect();
        assert_eq!(rules.len(), 2);
        for r in &rules {
            let j = r.args.join(" ");
            assert!(!j.contains("ipproto"), "must not emit an L4 selector: {j}");
            let undo = r.undo.as_ref().unwrap();
            assert_eq!(undo[2..], r.args[2..]);
        }
    }

    #[test]
    fn steer_port_follows_the_configured_server_port() {
        let mut s = settings();
        s.server_port = 3389;
        let p = build_plumbing(&s, true);
        let rules: Vec<&Step> =
            p.steps.iter().filter(|st| st.args.first().map(|a| a == "rule").unwrap_or(false)).collect();
        assert!(rules[0].args.join(" ").contains("dport 3389"));
        assert!(rules[1].args.join(" ").contains("sport 3389"));
    }

    #[test]
    fn every_rule_and_table_step_has_an_exact_inverse() {
        let p = build_plumbing(&settings(), true);
        for s in &p.steps {
            let is_rule = s.args.first().map(|a| a == "rule").unwrap_or(false);
            let is_table_route = s.args.iter().any(|a| a == "table");
            if is_rule || is_table_route {
                let undo = s.undo.as_ref().unwrap_or_else(|| panic!("no undo for {:?}", s.args));
                assert!(
                    undo.iter().any(|a| a == "del" || a == "flush"),
                    "undo must delete or flush: {undo:?}"
                );
            }
        }
    }

    #[test]
    fn host_sysctls_loosen_rp_filter_on_our_veths_only() {
        let p = build_plumbing(&settings(), true);
        assert_eq!(p.host_sysctls.len(), 2);
        for (key, want) in &p.host_sysctls {
            // 2 (loose), not 0: MAX(conf.all, conf.<iface>) means 2 wins over a
            // hardened conf.all=1 without touching anything box-wide.
            assert_eq!(*want, "2");
            assert!(key.contains("mmc0") || key.contains("mmu0"), "unexpected sysctl {key}");
            assert!(!key.contains(".all."), "must not touch a box-wide sysctl: {key}");
            assert!(!key.contains("left0") && !key.contains("right0"), "must not touch a real iface: {key}");
        }
    }

    #[test]
    fn child_argv_disables_netns_and_appends_inner_ifaces() {
        let argv = vec![
            "mymitm".to_string(),
            "--config".to_string(),
            "/etc/mymitm/mymitm.toml".to_string(),
            "--data-plane".to_string(),
            "iproute".to_string(),
        ];
        let inner = InnerCfg { tun_iface: "mmc1".into(), egress_iface: "mmu1".into(), box_ip: UN_ADDR };
        let out = child_argv(&argv, &inner);
        // Original arguments survive untouched, in order.
        assert_eq!(out[..5], argv[..]);
        assert!(out.contains(&"--netns=false".to_string()), "child must not re-plumb");
        // The appended overrides come last so clap's last-wins picks them.
        let tun_at = out.iter().position(|a| a == "--tun").unwrap();
        assert_eq!(out[tun_at + 1], "mmc1");
        let eg_at = out.iter().position(|a| a == "--egress").unwrap();
        assert_eq!(out[eg_at + 1], "mmu1");
        let box_at = out.iter().position(|a| a == "--box-ip").unwrap();
        assert_eq!(out[box_at + 1], "169.254.8.2");
    }

    #[test]
    fn child_argv_overrides_win_over_earlier_user_values() {
        // An operator who pinned --tun/--egress on the command line must still
        // end up with the namespace interfaces inside the namespace.
        let argv = vec![
            "mymitm".to_string(),
            "--tun".to_string(), "left0".to_string(),
            "--egress".to_string(), "right0".to_string(),
        ];
        let inner = InnerCfg { tun_iface: "mmc1".into(), egress_iface: "mmu1".into(), box_ip: UN_ADDR };
        let out = child_argv(&argv, &inner);
        // Last occurrence of each flag is ours.
        let last_tun = out.iter().rposition(|a| a == "--tun").unwrap();
        assert_eq!(out[last_tun + 1], "mmc1");
        let last_eg = out.iter().rposition(|a| a == "--egress").unwrap();
        assert_eq!(out[last_eg + 1], "mmu1");
    }

    // --- preflight ------------------------------------------------------

    const SERVER: Ipv4Addr = Ipv4Addr::new(10, 10, 2, 10);
    const CLIENT: Ipv4Addr = Ipv4Addr::new(10, 8, 0, 5);

    /// `diagnose` with the defaults that matter: client known, preservation on.
    fn dx(ip_forward: bool, rules: &str) -> Diagnosis {
        diagnose(ip_forward, rules, SERVER, 443, Some(CLIENT), true)
    }

    /// A ufw box: the FORWARD chain holds only jumps and the real permission
    /// lives in `ufw-user-forward`. Modelled on a tester box running
    ///   ufw allow in on eth1 to <if> port 22 proto tcp
    ///   ufw allow in on eth1 to <if> port 1194 proto udp
    ///   ufw deny from 10.8.0.0/24
    ///   ufw route allow from 10.8.0.0/24 to 10.10.2.10 port 443 proto tcp
    ///   ufw route allow from 10.8.0.0/24 to 10.10.2.10 port 3391 proto udp
    const UFW: &str = "\
-P INPUT DROP
-P FORWARD DROP
-P OUTPUT ACCEPT
-A INPUT -j ufw-before-logging-input
-A INPUT -j ufw-before-input
-A INPUT -j ufw-after-input
-A FORWARD -j ufw-before-logging-forward
-A FORWARD -j ufw-before-forward
-A FORWARD -j ufw-after-forward
-A FORWARD -j ufw-reject-forward
-A ufw-before-forward -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A ufw-before-forward -j ufw-user-forward
-A ufw-before-input -i lo -j ACCEPT
-A ufw-before-input -j ufw-user-input
-A ufw-user-input -i eth1 -p tcp -d 192.168.7.4 --dport 22 -j ACCEPT
-A ufw-user-input -i eth1 -p udp -d 192.168.7.4 --dport 1194 -j ACCEPT
-A ufw-user-input -s 10.8.0.0/24 -j DROP
-A ufw-user-forward -s 10.8.0.0/24 -d 10.10.2.10/32 -p tcp --dport 443 -j ACCEPT
-A ufw-user-forward -s 10.8.0.0/24 -d 10.10.2.10/32 -p udp --dport 3391 -j ACCEPT
-A ufw-reject-forward -j REJECT --reject-with icmp-port-unreachable
";

    #[test]
    fn preflight_requires_host_forwarding() {
        assert_eq!(dx(false, "").blocker, Some(Blocker::NoForwarding));
    }

    #[test]
    fn preflight_accepts_a_destination_only_forward_rule() {
        let rules = "-P FORWARD DROP\n\
                     -A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT\n\
                     -A FORWARD -d 10.10.2.10/32 -p tcp -m tcp --dport 443 -j ACCEPT\n";
        let d = dx(true, rules);
        assert_eq!(d.blocker, None);
        assert!(d.confirmed_by.unwrap().contains("-d 10.10.2.10/32"));
    }

    #[test]
    fn preflight_rejects_an_interface_pinned_forward_rule() {
        // This permits the flow today but will not match -o mmc0 / -i mmu0.
        let rules = "-A FORWARD -i tun0 -o eth0 -d 10.10.2.10/32 -p tcp --dport 443 -j ACCEPT\n";
        match dx(true, rules).blocker {
            Some(Blocker::ForwardPinnedToIfaces(r)) => assert!(r.contains("-i tun0")),
            other => panic!("expected an interface-pinning blocker, got {other:?}"),
        }
    }

    #[test]
    fn preflight_ignores_pinned_rules_for_other_servers() {
        let rules = "-A FORWARD -i tun0 -o eth0 -d 192.168.99.99/32 -j ACCEPT\n\
                     -A FORWARD -d 10.10.2.10/32 -p tcp --dport 443 -j ACCEPT\n";
        assert_eq!(dx(true, rules).blocker, None);
    }

    #[test]
    fn preflight_allows_a_box_with_no_forward_rules_at_all() {
        // Permissive FORWARD policy / no firewall: the common case today.
        let d = dx(true, "-P FORWARD ACCEPT\n");
        assert_eq!(d.blocker, None);
        assert_eq!(d.confirmed_by, None);
        assert!(!d.unconfirmed_but_restrictive, "nothing to warn about here");
    }

    // --- the ufw shape: rules live in a chain FORWARD only jumps to ---------

    #[test]
    fn preflight_finds_the_permission_inside_a_ufw_chain() {
        // The whole point of following jumps: scanning `-A FORWARD` alone finds
        // nothing here, and "found nothing" would be indistinguishable from a box
        // that genuinely has no permission.
        let d = dx(true, UFW);
        assert_eq!(d.blocker, None);
        let rule = d.confirmed_by.expect("must confirm the ufw-user-forward rule");
        assert!(rule.contains("ufw-user-forward"), "{rule}");
        assert!(rule.contains("--dport 443"), "must pick the TCP 443 rule, not UDP 3391: {rule}");
    }

    #[test]
    fn preflight_does_not_credit_a_rule_in_an_unreachable_chain() {
        // Same permission, but only INPUT jumps to the chain holding it, so it
        // cannot permit a forwarded leg.
        let rules = "-P FORWARD DROP\n\
                     -A INPUT -j my-input\n\
                     -A my-input -d 10.10.2.10/32 -p tcp --dport 443 -j ACCEPT\n\
                     -A FORWARD -j DROP\n";
        let d = dx(true, rules);
        assert_eq!(d.confirmed_by, None, "an INPUT-only accept is not a forward permission");
        assert!(d.unconfirmed_but_restrictive);
    }

    #[test]
    fn preflight_rejects_a_pinned_ufw_route_rule() {
        // `ufw route allow in on tun0 out on eth0 to <server> port 443 proto tcp`
        let rules = UFW.replace(
            "-A ufw-user-forward -s 10.8.0.0/24 -d 10.10.2.10/32 -p tcp --dport 443 -j ACCEPT",
            "-A ufw-user-forward -i tun0 -o eth0 -s 10.8.0.0/24 -d 10.10.2.10/32 -p tcp --dport 443 -j ACCEPT",
        );
        match dx(true, &rules).blocker {
            Some(Blocker::ForwardPinnedToIfaces(r)) => assert!(r.contains("-i tun0 -o eth0"), "{r}"),
            other => panic!("expected an interface-pinning blocker, got {other:?}"),
        }
    }

    // --- source-scoped permissions vs source-IP preservation ---------------

    #[test]
    fn preflight_rejects_a_source_scoped_rule_when_preservation_is_off() {
        // The client leg still matches (real client source), but the upstream leg
        // leaves as 169.254.8.2 and does not — a half-open failure.
        match diagnose(true, UFW, SERVER, 443, Some(CLIENT),false).blocker {
            Some(Blocker::SourceScopedNeedsPreservation(r)) => assert!(r.contains("-s 10.8.0.0/24")),
            other => panic!("expected a preservation blocker, got {other:?}"),
        }
        // ...and is fine with preservation on, which is the default.
        assert_eq!(diagnose(true, UFW, SERVER, 443, Some(CLIENT),true).blocker, None);
    }

    #[test]
    fn preflight_accepts_a_source_scope_that_covers_the_namespace_itself() {
        // Preservation off is only a problem when the rule excludes our source.
        let rules = "-P FORWARD DROP\n\
                     -A FORWARD -s 0.0.0.0/0 -d 10.10.2.10/32 -p tcp --dport 443 -j ACCEPT\n";
        assert_eq!(diagnose(true, rules, SERVER, 443, Some(CLIENT), false).blocker, None);
    }

    #[test]
    fn preflight_skips_a_source_scope_that_excludes_the_client() {
        // A permission for some other subnet is not ours; with nothing else to
        // confirm, this is the restrictive-and-unconfirmed case.
        let rules = "-P FORWARD DROP\n\
                     -A FORWARD -s 172.16.0.0/16 -d 10.10.2.10/32 -p tcp --dport 443 -j ACCEPT\n";
        let d = dx(true, rules);
        assert_eq!(d.blocker, None);
        assert_eq!(d.confirmed_by, None);
        assert!(d.unconfirmed_but_restrictive);
    }

    #[test]
    fn preflight_takes_a_source_scoped_rule_on_trust_when_the_client_is_unknown() {
        // client_ip is optional: we intercept whichever client connects, so there
        // is no containment to check and refusing to start would be wrong.
        let d = diagnose(true, UFW, SERVER, 443, None, true);
        assert_eq!(d.blocker, None);
        assert!(d.confirmed_by.is_some());
    }

    #[test]
    fn preflight_does_not_credit_a_permission_for_a_different_port_or_proto() {
        // The tester box permits UDP 3391 to the SAME address as TCP 443. Only
        // the rule matching our flow counts — the other one confirms nothing.
        let only_udp = "-P FORWARD DROP\n\
                        -A FORWARD -s 10.8.0.0/24 -d 10.10.2.10/32 -p udp --dport 3391 -j ACCEPT\n";
        let d = dx(true, only_udp);
        assert_eq!(d.confirmed_by, None, "a UDP permission is not a TCP 443 permission");
        assert!(d.unconfirmed_but_restrictive);

        // Conversely, our port inside a range or a multiport list does count.
        for rule in [
            "-A FORWARD -d 10.10.2.10/32 -p tcp --dport 440:450 -j ACCEPT",
            "-A FORWARD -d 10.10.2.10/32 -p tcp -m multiport --dports 80,443,8443 -j ACCEPT",
            "-A FORWARD -d 10.10.2.10/32 -j ACCEPT",
        ] {
            let rules = format!("-P FORWARD DROP\n{rule}\n");
            assert!(dx(true, &rules).confirmed_by.is_some(), "should confirm: {rule}");
        }
    }

    #[test]
    fn preflight_port_matching_follows_the_configured_port() {
        // Same ruleset, different target port: the 443 rule must stop counting.
        let d = diagnose(true, UFW, SERVER, 8443, Some(CLIENT), true);
        assert_eq!(d.confirmed_by, None);
    }

    // --- reply-direction and negated rules are not permissions -------------

    #[test]
    fn preflight_ignores_accepts_that_are_not_addressed_to_the_server() {
        // `-s <server>` is the reply direction; `! -d <server>` is not a
        // permission for the server at all.
        let rules = "-P FORWARD DROP\n\
                     -A FORWARD -s 10.10.2.10/32 -j ACCEPT\n\
                     -A FORWARD ! -d 10.10.2.10/32 -j ACCEPT\n";
        assert_eq!(dx(true, rules).confirmed_by, None);
    }

    #[test]
    fn cidr_containment_handles_the_edges() {
        assert!(cidr_contains(Ipv4Addr::new(0, 0, 0, 0), 0, CLIENT), "/0 covers everything");
        assert!(cidr_contains(Ipv4Addr::new(10, 8, 0, 0), 24, CLIENT));
        assert!(!cidr_contains(Ipv4Addr::new(10, 8, 1, 0), 24, CLIENT));
        assert!(cidr_contains(CLIENT, 32, CLIENT));
        assert!(!cidr_contains(Ipv4Addr::new(10, 8, 0, 0), 24, UN_ADDR));
    }

    #[test]
    fn blocker_messages_name_the_remedy_and_the_veths() {
        let names = Names::default();
        let m = blocker_message(&Blocker::NoForwarding, &names);
        assert!(m.contains("ip_forward=1"));
        assert!(m.contains("--netns=false"));

        let m = blocker_message(
            &Blocker::ForwardPinnedToIfaces("-A FORWARD -i tun0 -o eth0 -j ACCEPT".into()),
            &names,
        );
        assert!(m.contains("mmc0") && m.contains("mmu0"), "must name the veths the rule needs to match");
        assert!(m.contains("--netns=false"));
        assert!(m.contains("ufw route allow"), "ufw boxes need the ufw-native remedy");

        let m = blocker_message(
            &Blocker::SourceScopedNeedsPreservation("-A ufw-user-forward -s 10.8.0.0/24 -j ACCEPT".into()),
            &names,
        );
        assert!(m.contains("169.254.8.2"), "must name the address that will not match");
        assert!(m.contains("preserve_src_ip"));
    }
}
