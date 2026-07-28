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
//! Fail closed, not fail open — **on the eBPF plane**. The `iproute` plane sets
//! `net.ipv4.ip_forward=1` for itself during setup ([`crate::iproute`]), and inside
//! the namespace that overwrites the 0 set here, so that plane does not get this
//! guarantee. `tests/vm/validate-netns.sh` asserts each plane's actual behaviour
//! rather than the more flattering one.
//!
//! ## Requirements on the host firewall
//!
//! - `net.ipv4.ip_forward=1` on the host.
//! - The forward path accepts NEW to `<server>:<port>` **without** an `-i`/`-o`
//!   match — a rule pinned to `-i tun0 -o eth0` will not match `-o vc_h` /
//!   `-i vu_h`. The pin can also be inherited: a rule reachable only through
//!   `-A FORWARD -i tun0 -o eth0 -j <chain>` is just as unusable, even though the
//!   rule itself carries no interface match.
//! - If that accept is scoped to a source subnet, `preserve_src_ip` left on.
//! - The forward path accepts `ESTABLISHED,RELATED` (both return paths).
//!
//! [`preflight`] **fails fast** on the first three: no forwarding, an
//! interface-pinned permission, or a source-scoped permission with preservation
//! off. The `ESTABLISHED,RELATED` requirement is **not** checked — it holds on
//! every box that forwards anything at all, and a conntrack-state parser would
//! add a false-positive surface for no gain. When it finds no permission at all
//! and the forward path looks restrictive it warns rather than refusing, because
//! "I could not find one" is not "there is none".

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

/// WARN text for the pre-4.17 fallback, on both steer rules.
const L4_FALLBACK_WHY: &str = "this kernel's routing rules do not support L4 selectors (needs >= 4.17), \
     so the steer could not be narrowed to the server's TCP port. ALL traffic to the server now \
     enters the namespace, and anything the classifiers do not rewrite (e.g. an RD Gateway's UDP \
     3391 transport) is dropped there rather than forwarded.";

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
///
/// `alt` is a second spelling to try if the primary one fails, with its own
/// inverse. Used for the steer rules, whose L4 selectors need kernel ≥ 4.17: the
/// scoped form is attempted and the unscoped form is the fallback. Attempting the
/// real rule is deliberate — mymitm must not add and delete a throwaway rule just
/// to interrogate the kernel, and the failure that matters is the failure of the
/// rule we actually want, not of a stand-in for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Step {
    pub prog: &'static str,
    pub args: Vec<String>,
    pub undo: Option<Vec<String>>,
    pub alt: Option<AltStep>,
}

/// The fallback spelling of a [`Step`], with the inverse that matches *it*.
/// `ip rule del` must match the added rule exactly, so the undo cannot be shared.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AltStep {
    pub args: Vec<String>,
    pub undo: Option<Vec<String>>,
    /// Logged at WARN when the fallback is taken, naming the consequence.
    pub why: &'static str,
}

fn owned(args: &[&str]) -> Vec<String> {
    args.iter().map(|s| s.to_string()).collect()
}

fn step(prog: &'static str, args: &[&str], undo: Option<&[&str]>) -> Step {
    Step { prog, args: owned(args), undo: undo.map(owned), alt: None }
}

/// One steer rule: `base` + L4 `selectors` + `lookup <table>`, with the same rule
/// minus the selectors as its fallback. Each spelling gets the matching `del`,
/// built from its own argv so the two can never drift apart.
fn steer_step(base: &[&str], selectors: &[&str], table: &str) -> Step {
    let add = |extra: &[&str]| -> Vec<String> {
        let mut v: Vec<&str> = base.to_vec();
        v.extend_from_slice(extra);
        v.extend_from_slice(&["lookup", table]);
        owned(&v)
    };
    let del = |add: &[String]| -> Vec<String> {
        let mut v = add.to_vec();
        v[1] = "del".to_string();
        v
    };
    let scoped = add(selectors);
    let unscoped = add(&[]);
    Step {
        prog: "ip",
        undo: Some(del(&scoped)),
        args: scoped,
        alt: Some(AltStep { undo: Some(del(&unscoped)), args: unscoped, why: L4_FALLBACK_WHY }),
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
/// The two steer rules carry `ipproto tcp` + `dport`/`sport` selectors, with the
/// unscoped spelling as each one's [`AltStep`]. Those selectors are what keeps
/// non-TCP and other-port traffic to the same server OUT of the namespace — which
/// matters because the namespace runs with `ip_forward=0`, so anything steered in
/// that the classifiers do not rewrite is dropped. An RD Gateway is the motivating
/// case: it serves the tunnel on TCP 443 and an optional UDP transport on 3391,
/// and an unscoped steer would blackhole the latter.
///
/// FIB-rule L4 selectors need kernel ≥ 4.17 and an iproute2 that speaks the
/// syntax. Rather than probe for that — which would mean adding and deleting a
/// throwaway rule on the host, i.e. mutating state that is none of our business —
/// the scoped rule is simply attempted and the unscoped one used if it is
/// rejected. Both failure modes surface identically as a non-zero `ip rule add`,
/// which is exactly what the fallback keys on.
pub fn build_plumbing(cfg: &Settings) -> Plumbing {
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
    // Scoped to TCP <server_port>: everything else addressed to the server (the RD
    // Gateway's UDP 3391 transport, ICMP) then stays on the main table and is
    // forwarded normally, instead of entering a namespace that will not rewrite it
    // and cannot forward it. Pre-4.17 falls back to the unscoped spelling.
    let base_in: Vec<&str> =
        vec!["rule", "add", "priority", &p_in_s, "iif", &cfg.tun_iface, "to", &server];
    steps.push(steer_step(&base_in, &["ipproto", "tcp", "dport", &port], &t_in_s));

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
    let base_back: Vec<&str> =
        vec!["rule", "add", "priority", &p_back_s, "iif", &cfg.egress_iface, "from", &server];
    steps.push(steer_step(&base_back, &["ipproto", "tcp", "sport", &port], &t_back_s));

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
    /// The rule whose `-i`/`-o` stops this permission matching our veths — the
    /// candidate itself, or the jump that is the only way into its chain. `None`
    /// when nothing on the path pins an interface.
    pin_rule: Option<String>,
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
fn forward_reachable_chains(rules: &str) -> ForwardReach {
    let mut appended: std::collections::BTreeSet<&str> = Default::default();
    for line in rules.lines() {
        if let Some(rest) = line.trim().strip_prefix("-A ") {
            if let Some(c) = rest.split_whitespace().next() {
                appended.insert(c);
            }
        }
    }

    // Two closures over the same graph. `unpinned` follows only jumps whose own
    // rule carries no -i/-o, so it answers the question that actually matters:
    // which chains can a packet on OUR veths reach? `pinned_via` records, for a
    // chain reachable only through a pinned jump, one such jump — so an accept
    // found there can be reported with the rule that needs changing.
    let mut unpinned: std::collections::BTreeSet<String> = Default::default();
    let mut pinned_via: std::collections::BTreeMap<String, String> = Default::default();
    unpinned.insert("FORWARD".to_string());
    loop {
        let mut grew = false;
        for line in rules.lines() {
            let l = line.trim();
            let Some(rest) = l.strip_prefix("-A ") else { continue };
            let toks: Vec<&str> = rest.split_whitespace().collect();
            let Some(chain) = toks.first() else { continue };
            // Where a packet in this chain could have come from.
            let from_unpinned = unpinned.contains(*chain);
            let inherited = pinned_via.get(*chain).cloned();
            if !from_unpinned && inherited.is_none() {
                continue;
            }
            let jump_pins = pins_iface(&toks);
            for w in toks.windows(2) {
                if !(w[0] == "-j" || w[0] == "-g") || !appended.contains(w[1]) {
                    continue;
                }
                if from_unpinned && !jump_pins {
                    if unpinned.insert(w[1].to_string()) {
                        grew = true;
                    }
                } else {
                    // Either this jump pins interfaces, or we only got here
                    // through one that did. Record the pin as inherited.
                    let witness = if jump_pins { l.to_string() } else { inherited.clone().unwrap() };
                    if !unpinned.contains(w[1]) && !pinned_via.contains_key(w[1]) {
                        pinned_via.insert(w[1].to_string(), witness);
                        grew = true;
                    }
                }
            }
        }
        if !grew {
            break;
        }
    }
    // A chain that turned out to be unpinned-reachable is not pin-limited, even if
    // some other path to it was pinned.
    pinned_via.retain(|c, _| !unpinned.contains(c));
    ForwardReach { unpinned, pinned_via }
}

/// The forward path's chain closure, split by whether a packet on the namespace's
/// veths can actually get there.
#[derive(Debug, Default)]
struct ForwardReach {
    /// Reachable from `FORWARD` without crossing any `-i`/`-o` match.
    unpinned: std::collections::BTreeSet<String>,
    /// Reachable only through a jump that pins interfaces -> the jump rule.
    pinned_via: std::collections::BTreeMap<String, String>,
}

impl ForwardReach {
    /// Reachable at all, by either kind of path.
    fn any(&self, chain: &str) -> bool {
        self.unpinned.contains(chain) || self.pinned_via.contains_key(chain)
    }
}

/// Does this rule restrict which interfaces it matches? In namespace mode the legs
/// traverse FORWARD as `-o <vc_h>` / `-i <vu_h>`, so any `-i`/`-o` naming something
/// else cannot match. Both the short and long option spellings count.
fn pins_iface(toks: &[&str]) -> bool {
    toks.iter()
        .any(|t| matches!(*t, "-i" | "-o" | "--in-interface" | "--out-interface"))
}

/// Does this ruleset look like it would drop what it does not explicitly permit?
/// Only used to decide whether an unconfirmed verdict deserves a warning, so a
/// heuristic is appropriate: a restrictive FORWARD policy, or a reachable
/// catch-all DROP/REJECT (which is how ufw closes the chain while leaving the
/// policy at ACCEPT).
fn forward_looks_restrictive(rules: &str, reach: &ForwardReach) -> bool {
    for line in rules.lines() {
        let l = line.trim();
        if l == "-P FORWARD DROP" || l == "-P FORWARD REJECT" {
            return true;
        }
        let Some(rest) = l.strip_prefix("-A ") else { continue };
        let toks: Vec<&str> = rest.split_whitespace().collect();
        let Some(chain) = toks.first() else { continue };
        if !reach.any(chain) {
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
        if !reach.any(chain) {
            continue;
        }
        if !toks.windows(2).any(|w| w[0] == "-j" && w[1] == "ACCEPT") {
            continue;
        }
        // Must be addressed TO the server: a `-s <server>` accept is the reply
        // direction, not the permission the client leg needs. A `-d` covering the
        // server counts whatever its prefix length — a `-d 10.0.0.0/8` accept does
        // permit our flow, and (more importantly) an interface-pinned one must
        // still be recognised so it can be reported as a blocker. Negated matches
        // (`! -d`) are not permissions for this destination either.
        let dst_is_server = toks.windows(2).any(|w| {
            w[0] == "-d"
                && parse_cidr(w[1]).map(|(net, len)| cidr_contains(net, len, server)).unwrap_or(false)
        });
        if !dst_is_server || toks.contains(&"!") || !permits_tcp_port(&toks, server_port) {
            continue;
        }
        let src = toks
            .windows(2)
            .find(|w| w[0] == "-s")
            .and_then(|w| parse_cidr(w[1]));
        // Pinned by its own -i/-o, or by the only jump that leads to its chain.
        // The inherited case is invisible in the rule text, which is exactly why
        // it has to come from the closure and not from the tokens.
        let inherited_pin = reach.pinned_via.get(*chain);
        candidates.push(Candidate {
            rule: l.to_string(),
            pin_rule: if pins_iface(&toks) {
                Some(l.to_string())
            } else {
                inherited_pin.cloned()
            },
            src,
        });
    }

    let mut pinned: Option<String> = None;
    let mut needs_pres: Option<String> = None;
    for c in candidates {
        if let Some(pin) = c.pin_rule {
            pinned.get_or_insert(pin);
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
             match — the proxy would start and then silently blackhole. (If the rule above is a \
             `-j <chain>` jump, the permission itself is inside that chain and is unusable because \
             the only way into it is pinned.) Fix by ONE of:\n  \
             (a) drop the -i/-o match from that rule so it matches on destination alone \
             (under ufw: replace `ufw route allow in on X out on Y to <server> …` with \
             `ufw route allow to <server> port <port> proto tcp`), or\n  \
             (b) add a second, unpinned copy of the permission — one matching on destination \
             alone. Adding `-o {vc_h}` / `-i {vu_h}` variants of the pinned rule works too, but \
             note that BOTH legs need one: the client leg is `-o {vc_h}` and the upstream leg is \
             `-i {vu_h}`, so a single companion is not enough, or\n  \
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
    //
    // A box with genuinely no iptables is fine — there is no ruleset to conflict
    // with. But "could not read the ruleset" is NOT the same fact as "the ruleset
    // is empty", and conflating them turns the one check whose job is to fail
    // closed into a silent fail-open (a lost xtables lock, a missing binary, an
    // nft-only box). Say so out loud instead.
    let rules = match Command::new("iptables").arg("-S").output() {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).into_owned(),
        Ok(o) => {
            tracing::warn!(
                status = %o.status,
                stderr = %String::from_utf8_lossy(&o.stderr).trim(),
                "netns preflight: `iptables -S` failed, so this box's forward permissions could NOT \
                 be checked. Namespace mode needs the forward path to permit both legs to/from the \
                 real server address; if the proxy accepts connections and then hangs, that ruleset \
                 is the first place to look."
            );
            String::new()
        }
        Err(e) => {
            // ENOENT here is the ordinary "no iptables installed" case.
            if e.kind() == std::io::ErrorKind::NotFound {
                tracing::debug!("netns preflight: no iptables binary; no ruleset to check");
            } else {
                tracing::warn!(
                    error = %e,
                    "netns preflight: could not run `iptables -S`, so forward permissions were NOT \
                     checked"
                );
            }
            String::new()
        }
    };

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
    /// Per step, whether its [`AltStep`] spelling is the one that took — so the
    /// undo matches the argv that was actually run. `ip rule del` is exact.
    used_alt: Vec<bool>,
}

impl NetnsGuard {
    /// Apply the plumbing. On any failure, reverses everything already applied
    /// before returning `Err` — never leaves a half-built namespace.
    pub fn setup(cfg: &Settings) -> anyhow::Result<(NetnsGuard, InnerCfg)> {
        // The names are fixed, so two instances cannot coexist — and `cleanup`
        // below would delete a live one's namespace and veths out from under it.
        // Refuse instead of clobbering.
        if let Some(pids) = namespace_in_use() {
            anyhow::bail!(
                "network namespace `{ns}` already has processes in it (pids: {pids}). Another mymitm \
                 is probably running — namespace mode uses fixed names, so two instances cannot \
                 share a box. Stop that one first, or run with --cleanup if it is a leftover.",
                ns = Names::default().ns,
            );
        }
        // A previous unclean exit leaves the namespace and veths behind, and
        // `ip netns add` would then fail on the very first step. Clear first.
        cleanup(cfg);

        let plumbing = build_plumbing(cfg);
        let inner = plumbing.inner.clone();
        let n_steps = plumbing.steps.len();
        let mut guard = NetnsGuard { plumbing, applied: 0, used_alt: vec![false; n_steps] };

        for i in 0..n_steps {
            let s = &guard.plumbing.steps[i];
            if let Err(e) = run(s.prog, &s.args) {
                // A fallback spelling exists: the primary failing is expected on
                // some kernels, so try it before treating this as fatal.
                match &s.alt {
                    Some(alt) => {
                        let prog = s.prog;
                        let alt_args = alt.args.clone();
                        let why = alt.why;
                        if let Err(e2) = run(prog, &alt_args) {
                            let failed = format!("{prog} {}", alt_args.join(" "));
                            guard.revert();
                            return Err(anyhow::anyhow!(
                                "netns setup failed at `{failed}`: {e2} (the preferred spelling also \
                                 failed: {e})"
                            ));
                        }
                        tracing::warn!("{why}");
                        guard.used_alt[i] = true;
                    }
                    None => {
                        let failed = format!("{} {}", s.prog, s.args.join(" "));
                        guard.revert();
                        return Err(anyhow::anyhow!("netns setup failed at `{failed}`: {e}"));
                    }
                }
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
            let s = &self.plumbing.steps[i];
            // Undo the spelling that actually took: `ip rule del` matches exactly,
            // so the primary's inverse would silently fail on a fallback rule.
            let undo = if self.used_alt[i] {
                s.alt.as_ref().and_then(|a| a.undo.clone())
            } else {
                s.undo.clone()
            };
            if let Some(undo) = undo {
                let _ = run(s.prog, &undo);
            }
        }
        self.applied = 0;
    }
}

/// PIDs inside the namespace, if it exists and is not empty. `ip netns pids` lists
/// them; an absent namespace or an empty one both mean "free to use".
fn namespace_in_use() -> Option<String> {
    let out = Command::new("ip")
        .args(["netns", "pids", &Names::default().ns])
        .output()
        .ok()?;
    if !out.status.success() {
        return None; // no such namespace
    }
    let stdout = String::from_utf8_lossy(&out.stdout);
    let pids: Vec<&str> = stdout.split_whitespace().collect();
    if pids.is_empty() {
        None
    } else {
        Some(pids.join(", "))
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
    let p = build_plumbing(cfg);
    for s in p.steps.iter().rev() {
        // BOTH spellings of every step that has two: a leftover rule could have
        // been added in either shape (a kernel upgrade between runs, or a
        // `--cleanup` invoked on a different box than the one that plumbed it).
        // `ip rule del` must match exactly, so try each rather than guess.
        if let Some(undo) = &s.undo {
            let _ = run(s.prog, undo);
        }
        if let Some(undo) = s.alt.as_ref().and_then(|a| a.undo.as_ref()) {
            let _ = run(s.prog, undo);
        }
    }
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
        let p = build_plumbing(&settings());
        // tun and egress MUST differ: one program per tc hook. A shared
        // interface lets the lower-pref classifier end the chain first.
        assert_eq!(p.inner.tun_iface, "mmc1");
        assert_eq!(p.inner.egress_iface, "mmu1");
        assert_ne!(p.inner.tun_iface, p.inner.egress_iface);
        assert_eq!(p.inner.box_ip, UN_ADDR);
    }

    #[test]
    fn tables_and_priorities_derive_from_fwmark() {
        let p = build_plumbing(&settings());
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
        let p = build_plumbing(&settings());
        let first = &p.steps[0];
        assert_eq!(first.prog, "ip");
        assert_eq!(first.args[..3], ["netns", "add", "mitm"]);
        assert_eq!(first.undo.as_ref().unwrap()[..3], ["netns", "del", "mitm"]);
    }

    #[test]
    fn namespace_fails_closed_on_forwarding() {
        let p = build_plumbing(&settings());
        // An un-rewritten packet must be dropped inside the namespace, not
        // forwarded on to the server in the clear.
        assert!(
            p.steps.iter().any(|s| s.args.iter().any(|a| a == "net.ipv4.ip_forward=0")),
            "namespace must set ip_forward=0"
        );
    }

    #[test]
    fn steer_rules_are_scoped_by_ingress_interface() {
        let p = build_plumbing(&settings());
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

    /// The two steer rules, in plumbing order (client leg, then reply leg).
    fn steer_rules(p: &Plumbing) -> Vec<&Step> {
        p.steps
            .iter()
            .filter(|s| s.args.first().map(|a| a == "rule").unwrap_or(false))
            .collect()
    }

    #[test]
    fn steer_rules_are_scoped_to_tcp_server_port() {
        let p = build_plumbing(&settings());
        let rules = steer_rules(&p);
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
    fn steer_rules_carry_an_unscoped_fallback_with_its_own_exact_inverse() {
        // Pre-4.17 kernels reject `ipproto`/`dport` in a routing rule. There is no
        // probe: the scoped rule is attempted and this is what gets used if it
        // fails, so it must be a complete, self-consistent rule — including an undo
        // that matches ITS argv, since `ip rule del` is exact and the primary's
        // undo would silently fail to remove a fallback rule.
        let p = build_plumbing(&settings());
        let rules = steer_rules(&p);
        assert_eq!(rules.len(), 2);
        for r in &rules {
            let alt = r.alt.as_ref().expect("every steer rule needs a fallback");
            let j = alt.args.join(" ");
            assert!(!j.contains("ipproto"), "the fallback must carry no L4 selector: {j}");
            assert!(!j.contains("dport") && !j.contains("sport"), "{j}");
            // Still a complete rule: same selectors otherwise, same table.
            assert_eq!(alt.args[0], "rule");
            assert_eq!(alt.args[1], "add");
            assert!(alt.args.contains(&"lookup".to_string()), "{j}");
            let undo = alt.undo.as_ref().expect("the fallback needs its own inverse");
            assert_eq!(undo[1], "del");
            assert_eq!(undo[2..], alt.args[2..], "the fallback's undo must match the fallback");
            // And it must NOT be interchangeable with the primary's undo.
            assert_ne!(
                r.undo.as_ref().unwrap(),
                undo,
                "the two spellings need distinct inverses or one of them leaks"
            );
        }
    }

    #[test]
    fn only_the_steer_rules_have_a_fallback() {
        // A fallback means "failing is expected here". Anywhere else, a failure is
        // a real failure and must abort the setup, not be silently retried.
        let p = build_plumbing(&settings());
        for s in &p.steps {
            if s.alt.is_some() {
                assert_eq!(s.args.first().map(String::as_str), Some("rule"), "{:?}", s.args);
            }
        }
    }

    #[test]
    fn steer_port_follows_the_configured_server_port() {
        let mut s = settings();
        s.server_port = 3389;
        let p = build_plumbing(&s);
        let rules: Vec<&Step> =
            p.steps.iter().filter(|st| st.args.first().map(|a| a == "rule").unwrap_or(false)).collect();
        assert!(rules[0].args.join(" ").contains("dport 3389"));
        assert!(rules[1].args.join(" ").contains("sport 3389"));
    }

    #[test]
    fn every_rule_and_table_step_has_an_exact_inverse() {
        let p = build_plumbing(&settings());
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
        let p = build_plumbing(&settings());
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
    /// Inside the `UFW` fixture's `-s 10.10.1.0/24` scope, as the real client was.
    const CLIENT: Ipv4Addr = Ipv4Addr::new(10, 10, 1, 10);

    /// `diagnose` with the defaults that matter: client known, preservation on.
    fn dx(ip_forward: bool, rules: &str) -> Diagnosis {
        diagnose(ip_forward, rules, SERVER, 443, Some(CLIENT), true)
    }

    /// A ufw box: the FORWARD chain holds only jumps and the real permission
    /// lives in `ufw-user-forward`.
    ///
    /// This is the **entire `iptables -S` output of a live, enabled ufw 0.36**,
    /// verbatim, captured by `tests/vm/validate-netns.sh` with `FW_PROFILE=ufw`
    /// on Debian 11 (kernel 5.10) after applying the tester box's rules:
    ///   ufw allow in on <mgmt> to <mgmt_ip> port 22 proto tcp
    ///   ufw allow in on <mgmt> to <mgmt_ip> port 1194 proto udp
    ///   ufw deny from 10.10.1.0/24
    ///   ufw route allow from 10.10.1.0/24 to 10.10.2.10 port 443 proto tcp
    ///   ufw route allow from 10.10.1.0/24 to 10.10.2.10 port 3391 proto udp
    /// plus the harness's own unpinned `ufw allow 22/tcp`, which keeps the ssh
    /// session that applies the profile alive — hence two port-22 rules here.
    ///
    /// It is deliberately the *live table* and not `ufw --dry-run`: `preflight`
    /// reads `iptables -S`, whose canonical token order (`-s -d -i -o -p -m`)
    /// differs from what ufw writes into its own rules files. Two other shapes
    /// only the live table shows: the `-N` declarations, and `ufw-track-forward`
    /// — a chain FORWARD jumps to that has no rules at all, so the jump closure
    /// must not assume every `-j` target has appends.
    ///
    /// Keeping it whole matters: a trimmed fixture is a fixture whose author
    /// chose what the parser would see.
    const UFW: &str = "\
-P INPUT DROP
-P FORWARD DROP
-P OUTPUT ACCEPT
-N ufw-after-forward
-N ufw-after-input
-N ufw-after-logging-forward
-N ufw-after-logging-input
-N ufw-after-logging-output
-N ufw-after-output
-N ufw-before-forward
-N ufw-before-input
-N ufw-before-logging-forward
-N ufw-before-logging-input
-N ufw-before-logging-output
-N ufw-before-output
-N ufw-logging-allow
-N ufw-logging-deny
-N ufw-not-local
-N ufw-reject-forward
-N ufw-reject-input
-N ufw-reject-output
-N ufw-skip-to-policy-forward
-N ufw-skip-to-policy-input
-N ufw-skip-to-policy-output
-N ufw-track-forward
-N ufw-track-input
-N ufw-track-output
-N ufw-user-forward
-N ufw-user-input
-N ufw-user-limit
-N ufw-user-limit-accept
-N ufw-user-logging-forward
-N ufw-user-logging-input
-N ufw-user-logging-output
-N ufw-user-output
-A INPUT -j ufw-before-logging-input
-A INPUT -j ufw-before-input
-A INPUT -j ufw-after-input
-A INPUT -j ufw-after-logging-input
-A INPUT -j ufw-reject-input
-A INPUT -j ufw-track-input
-A FORWARD -j ufw-before-logging-forward
-A FORWARD -j ufw-before-forward
-A FORWARD -j ufw-after-forward
-A FORWARD -j ufw-after-logging-forward
-A FORWARD -j ufw-reject-forward
-A FORWARD -j ufw-track-forward
-A OUTPUT -j ufw-before-logging-output
-A OUTPUT -j ufw-before-output
-A OUTPUT -j ufw-after-output
-A OUTPUT -j ufw-after-logging-output
-A OUTPUT -j ufw-reject-output
-A OUTPUT -j ufw-track-output
-A ufw-after-input -p udp -m udp --dport 137 -j ufw-skip-to-policy-input
-A ufw-after-input -p udp -m udp --dport 138 -j ufw-skip-to-policy-input
-A ufw-after-input -p tcp -m tcp --dport 139 -j ufw-skip-to-policy-input
-A ufw-after-input -p tcp -m tcp --dport 445 -j ufw-skip-to-policy-input
-A ufw-after-input -p udp -m udp --dport 67 -j ufw-skip-to-policy-input
-A ufw-after-input -p udp -m udp --dport 68 -j ufw-skip-to-policy-input
-A ufw-after-input -m addrtype --dst-type BROADCAST -j ufw-skip-to-policy-input
-A ufw-after-logging-forward -m limit --limit 3/min --limit-burst 10 -j LOG --log-prefix \"[UFW BLOCK] \"
-A ufw-after-logging-input -m limit --limit 3/min --limit-burst 10 -j LOG --log-prefix \"[UFW BLOCK] \"
-A ufw-before-forward -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A ufw-before-forward -p icmp -m icmp --icmp-type 3 -j ACCEPT
-A ufw-before-forward -p icmp -m icmp --icmp-type 11 -j ACCEPT
-A ufw-before-forward -p icmp -m icmp --icmp-type 12 -j ACCEPT
-A ufw-before-forward -p icmp -m icmp --icmp-type 8 -j ACCEPT
-A ufw-before-forward -j ufw-user-forward
-A ufw-before-input -i lo -j ACCEPT
-A ufw-before-input -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A ufw-before-input -m conntrack --ctstate INVALID -j ufw-logging-deny
-A ufw-before-input -m conntrack --ctstate INVALID -j DROP
-A ufw-before-input -p icmp -m icmp --icmp-type 3 -j ACCEPT
-A ufw-before-input -p icmp -m icmp --icmp-type 11 -j ACCEPT
-A ufw-before-input -p icmp -m icmp --icmp-type 12 -j ACCEPT
-A ufw-before-input -p icmp -m icmp --icmp-type 8 -j ACCEPT
-A ufw-before-input -p udp -m udp --sport 67 --dport 68 -j ACCEPT
-A ufw-before-input -j ufw-not-local
-A ufw-before-input -d 224.0.0.251/32 -p udp -m udp --dport 5353 -j ACCEPT
-A ufw-before-input -d 239.255.255.250/32 -p udp -m udp --dport 1900 -j ACCEPT
-A ufw-before-input -j ufw-user-input
-A ufw-before-output -o lo -j ACCEPT
-A ufw-before-output -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A ufw-before-output -j ufw-user-output
-A ufw-logging-allow -m limit --limit 3/min --limit-burst 10 -j LOG --log-prefix \"[UFW ALLOW] \"
-A ufw-logging-deny -m conntrack --ctstate INVALID -m limit --limit 3/min --limit-burst 10 -j RETURN
-A ufw-logging-deny -m limit --limit 3/min --limit-burst 10 -j LOG --log-prefix \"[UFW BLOCK] \"
-A ufw-not-local -m addrtype --dst-type LOCAL -j RETURN
-A ufw-not-local -m addrtype --dst-type MULTICAST -j RETURN
-A ufw-not-local -m addrtype --dst-type BROADCAST -j RETURN
-A ufw-not-local -m limit --limit 3/min --limit-burst 10 -j ufw-logging-deny
-A ufw-not-local -j DROP
-A ufw-skip-to-policy-forward -j DROP
-A ufw-skip-to-policy-input -j DROP
-A ufw-skip-to-policy-output -j ACCEPT
-A ufw-track-output -p tcp -m conntrack --ctstate NEW -j ACCEPT
-A ufw-track-output -p udp -m conntrack --ctstate NEW -j ACCEPT
-A ufw-user-forward -s 10.10.1.0/24 -d 10.10.2.10/32 -p tcp -m tcp --dport 443 -j ACCEPT
-A ufw-user-forward -s 10.10.1.0/24 -d 10.10.2.10/32 -p udp -m udp --dport 3391 -j ACCEPT
-A ufw-user-input -p tcp -m tcp --dport 22 -j ACCEPT
-A ufw-user-input -d 10.0.2.15/32 -i ctrl0 -p tcp -m tcp --dport 22 -j ACCEPT
-A ufw-user-input -d 10.0.2.15/32 -i ctrl0 -p udp -m udp --dport 1194 -j ACCEPT
-A ufw-user-input -s 10.10.1.0/24 -j DROP
-A ufw-user-limit -m limit --limit 3/min -j LOG --log-prefix \"[UFW LIMIT BLOCK] \"
-A ufw-user-limit -j REJECT --reject-with icmp-port-unreachable
-A ufw-user-limit-accept -j ACCEPT
";

    /// The same box with the forward permission pinned to interfaces, i.e.
    /// `ufw route allow in on left0 out on right0 from ... port 443 proto tcp`.
    /// Also a verbatim live capture (`iptables -S ufw-user-forward`), because the
    /// pin's token position is exactly what the rejection test turns on.
    const UFW_PINNED_443: &str =
        "-A ufw-user-forward -s 10.10.1.0/24 -d 10.10.2.10/32 -i left0 -o right0 -p tcp -m tcp --dport 443 -j ACCEPT";
    /// The unpinned line it replaces.
    const UFW_OPEN_443: &str =
        "-A ufw-user-forward -s 10.10.1.0/24 -d 10.10.2.10/32 -p tcp -m tcp --dport 443 -j ACCEPT";

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
    fn preflight_rejects_a_permission_whose_chain_is_reached_only_by_a_pinned_jump() {
        // The pin is on the JUMP, not on the accept. Zone-based frontends
        // (firewalld, shorewall) are built this way, and the accept inside the zone
        // chain looks destination-only when read on its own — so crediting it
        // means logging "both legs will match" and then blackholing completely.
        let rules = "-P FORWARD DROP\n\
                     -A FORWARD -i tun0 -o eth0 -j zone_vpn_fwd\n\
                     -A zone_vpn_fwd -d 10.10.2.10/32 -p tcp -m tcp --dport 443 -j ACCEPT\n";
        match dx(true, rules).blocker {
            Some(Blocker::ForwardPinnedToIfaces(r)) => {
                assert!(r.contains("-i tun0 -o eth0"), "must name the pinned jump: {r}");
            }
            other => panic!("expected an inherited-pin blocker, got {other:?}"),
        }
    }

    #[test]
    fn preflight_credits_a_permission_reached_through_an_unpinned_jump_chain() {
        // The mirror image, and the case that must keep working: ufw's own shape,
        // where FORWARD jumps carry no interface match. Two hops deep, to exercise
        // the closure's fixed point rather than a single pass.
        let rules = "-P FORWARD DROP\n\
                     -A FORWARD -j ufw-before-forward\n\
                     -A ufw-before-forward -j ufw-user-forward\n\
                     -A ufw-user-forward -j deep-zone\n\
                     -A deep-zone -d 10.10.2.10/32 -p tcp -m tcp --dport 443 -j ACCEPT\n";
        let d = dx(true, rules);
        assert_eq!(d.blocker, None);
        assert!(
            d.confirmed_by.as_deref().unwrap_or("").contains("deep-zone"),
            "must follow three jumps to find it: {:?}",
            d.confirmed_by
        );
    }

    #[test]
    fn preflight_prefers_an_unpinned_path_when_a_chain_has_both() {
        // Reached via a pinned jump AND an unpinned one: a packet on our veths can
        // still get there, so this box is fine and must not be refused.
        let rules = "-P FORWARD DROP\n\
                     -A FORWARD -i tun0 -o eth0 -j shared_fwd\n\
                     -A FORWARD -j shared_fwd\n\
                     -A shared_fwd -d 10.10.2.10/32 -p tcp -m tcp --dport 443 -j ACCEPT\n";
        let d = dx(true, rules);
        assert_eq!(d.blocker, None, "an unpinned path exists; do not refuse");
        assert!(d.confirmed_by.is_some());
    }

    #[test]
    fn preflight_rejects_a_pinned_permission_addressed_to_a_subnet() {
        // `-d <subnet>` covering the server is a real permission for our flow, so a
        // pinned one has to be caught. Requiring /32 here used to let this through
        // as neither confirmed nor blocked — i.e. a warning, then a blackhole.
        let rules = "-P FORWARD DROP\n\
                     -A FORWARD -i tun0 -o eth0 -d 10.10.2.0/24 -p tcp -m tcp --dport 443 -j ACCEPT\n";
        match dx(true, rules).blocker {
            Some(Blocker::ForwardPinnedToIfaces(r)) => assert!(r.contains("10.10.2.0/24"), "{r}"),
            other => panic!("expected a pinning blocker, got {other:?}"),
        }
    }

    #[test]
    fn preflight_credits_a_permission_addressed_to_a_covering_subnet() {
        for spelling in ["-d 10.10.2.0/24", "-d 10.0.0.0/8", "-d 0.0.0.0/0"] {
            let rules = format!("-P FORWARD DROP\n-A FORWARD {spelling} -p tcp --dport 443 -j ACCEPT\n");
            assert!(
                dx(true, &rules).confirmed_by.is_some(),
                "a -d covering the server permits our flow: {spelling}"
            );
        }
        // ...but a subnet that excludes the server still confirms nothing.
        let elsewhere = "-P FORWARD DROP\n-A FORWARD -d 192.168.0.0/16 -p tcp --dport 443 -j ACCEPT\n";
        assert_eq!(dx(true, elsewhere).confirmed_by, None);
    }

    #[test]
    fn preflight_recognises_the_long_interface_option_spellings() {
        // iptables-save emits -i/-o, but a hand-written rule or a restore file may
        // use the long forms, and missing them means missing the blocker.
        for pin in ["--in-interface tun0", "--out-interface eth0"] {
            let rules =
                format!("-P FORWARD DROP\n-A FORWARD {pin} -d 10.10.2.10/32 -p tcp --dport 443 -j ACCEPT\n");
            assert!(
                matches!(dx(true, &rules).blocker, Some(Blocker::ForwardPinnedToIfaces(_))),
                "must treat `{pin}` as a pin"
            );
        }
    }

    #[test]
    fn preflight_only_credits_an_accept() {
        // A DROP or REJECT to the server is emphatically not a permission. Without
        // the -j ACCEPT check this would be logged as "both legs will match".
        for verdict in ["DROP", "REJECT", "LOG", "RETURN"] {
            let rules =
                format!("-P FORWARD DROP\n-A FORWARD -d 10.10.2.10/32 -p tcp --dport 443 -j {verdict}\n");
            assert_eq!(dx(true, &rules).confirmed_by, None, "-j {verdict} is not a permission");
        }
    }

    #[test]
    fn preflight_warns_on_a_catch_all_drop_even_when_the_policy_is_accept() {
        // ufw's shape: policy left at ACCEPT, the chain closed with a terminal
        // DROP. Warning here is the whole reason the restrictive heuristic looks at
        // reachable rules and not just at `-P`.
        let rules = "-P FORWARD ACCEPT\n\
                     -A FORWARD -j my-fwd\n\
                     -A my-fwd -d 10.9.9.9/32 -j ACCEPT\n\
                     -A my-fwd -j DROP\n";
        let d = dx(true, rules);
        assert_eq!(d.confirmed_by, None);
        assert!(d.unconfirmed_but_restrictive, "a reachable catch-all DROP is restrictive");

        // A DROP narrowed to some other flow is not a catch-all, so no warning.
        let narrowed = "-P FORWARD ACCEPT\n\
                        -A FORWARD -j my-fwd\n\
                        -A my-fwd -d 10.9.9.9/32 -j DROP\n";
        assert!(!dx(true, narrowed).unconfirmed_but_restrictive);

        // And a catch-all DROP in a chain nothing forwards into says nothing.
        let unreachable = "-P FORWARD ACCEPT\n-A INPUT -j in-only\n-A in-only -j DROP\n";
        assert!(!dx(true, unreachable).unconfirmed_but_restrictive);
    }

    #[test]
    fn preflight_rejects_a_pinned_ufw_route_rule() {
        let rules = UFW.replace(UFW_OPEN_443, UFW_PINNED_443);
        assert!(rules != UFW, "the fixture line to pin must exist verbatim");
        match dx(true, &rules).blocker {
            Some(Blocker::ForwardPinnedToIfaces(r)) => {
                assert!(r.contains("-i left0 -o right0"), "{r}")
            }
            other => panic!("expected an interface-pinning blocker, got {other:?}"),
        }
    }

    // --- source-scoped permissions vs source-IP preservation ---------------

    #[test]
    fn preflight_rejects_a_source_scoped_rule_when_preservation_is_off() {
        // The client leg still matches (real client source), but the upstream leg
        // leaves as 169.254.8.2 and does not — a half-open failure.
        match diagnose(true, UFW, SERVER, 443, Some(CLIENT),false).blocker {
            Some(Blocker::SourceScopedNeedsPreservation(r)) => assert!(r.contains("-s 10.10.1.0/24")),
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
    fn preflight_matches_addresses_with_and_without_a_prefix_length() {
        // ufw writes `-d 10.10.2.10`; a live `iptables -S` prints the same rule
        // back as `-d 10.10.2.10/32`. Both must be recognised.
        //
        // A wider `-d` that CONTAINS the server counts too — see
        // preflight_credits_a_permission_addressed_to_a_covering_subnet. This
        // deliberately reversed an earlier "a /24 is not a rule for this host":
        // `-d 10.10.2.0/24 --dport 443 -j ACCEPT` plainly does permit our flow, and
        // treating it as no rule at all meant an interface-pinned one produced
        // neither a confirmation nor a blocker — just a warning, then a blackhole.
        for spelling in ["-d 10.10.2.10", "-d 10.10.2.10/32"] {
            let rules = format!("-P FORWARD DROP\n-A FORWARD {spelling} -p tcp --dport 443 -j ACCEPT\n");
            assert!(dx(true, &rules).confirmed_by.is_some(), "should confirm: {spelling}");
        }
        // A prefix that excludes the server is still not our rule.
        let elsewhere = "-P FORWARD DROP\n-A FORWARD -d 10.10.3.0/24 -p tcp --dport 443 -j ACCEPT\n";
        assert_eq!(dx(true, elsewhere).confirmed_by, None, "a /24 without the server is not our rule");
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
        assert!(cidr_contains(Ipv4Addr::new(10, 10, 1, 0), 24, CLIENT));
        assert!(!cidr_contains(Ipv4Addr::new(10, 10, 2, 0), 24, CLIENT));
        assert!(cidr_contains(CLIENT, 32, CLIENT));
        assert!(!cidr_contains(Ipv4Addr::new(10, 10, 1, 0), 24, UN_ADDR));
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
