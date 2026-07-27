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
pub fn build_plumbing(cfg: &Settings) -> Plumbing {
    let n = Names::default();
    let mask = cfg.fwmark & 0xff;
    let (t_in, t_back) = (T_IN_BASE + mask, T_BACK_BASE + mask);
    let (p_in, p_back) = (P_IN_BASE + mask, P_BACK_BASE + mask);

    let server = cfg.server_ip.to_string();
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
    steps.push(step(
        "ip",
        &["rule", "add", "priority", &p_in_s, "iif", &cfg.tun_iface, "to", &server, "lookup", &t_in_s],
        Some(&["rule", "del", "priority", &p_in_s, "iif", &cfg.tun_iface, "to", &server, "lookup", &t_in_s]),
    ));

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
    steps.push(step(
        "ip",
        &["rule", "add", "priority", &p_back_s, "iif", &cfg.egress_iface, "from", &server, "lookup", &t_back_s],
        Some(&["rule", "del", "priority", &p_back_s, "iif", &cfg.egress_iface, "from", &server, "lookup", &t_back_s]),
    ));

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
}

/// Decide whether namespace mode can work, from the two facts that matter:
/// whether the host forwards at all, and the host's FORWARD ruleset.
///
/// Pure so it can be unit-tested without root or a firewall. `forward_rules` is
/// the output of `iptables -S FORWARD`.
///
/// The interface-pinning check is the important one: a rule such as
/// `-A FORWARD -i tun0 -o eth0 -d 10.0.0.5 -j ACCEPT` permits the flow today but
/// will NOT match once the legs become `-o mmc0` / `-i mmu0`, so namespace mode
/// would break a working box. We only flag rules that both pin an interface AND
/// mention the server, since those are the ones carrying the permission.
pub fn diagnose(ip_forward: bool, forward_rules: &str, server: Ipv4Addr) -> Option<Blocker> {
    if !ip_forward {
        return Some(Blocker::NoForwarding);
    }
    let server_s = server.to_string();
    for line in forward_rules.lines() {
        let l = line.trim();
        if !l.starts_with("-A FORWARD") || !l.contains("ACCEPT") {
            continue;
        }
        if !l.contains(&server_s) {
            continue;
        }
        let pins_iface = l.split_whitespace().any(|t| t == "-i" || t == "-o");
        if pins_iface {
            return Some(Blocker::ForwardPinnedToIfaces(l.to_string()));
        }
        // An un-pinned accept for the server: exactly what namespace mode needs.
        return None;
    }
    // No server-specific FORWARD accept at all. That is not a blocker: a box
    // with a permissive FORWARD policy (the common case, and every box with no
    // firewall) works fine. Only an interface-pinned permission is fatal.
    None
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
             (a) drop the -i/-o match from that rule so it matches on destination alone, or\n  \
             (b) add `-o {vc_h}` / `-i {vu_h}` companions to it, or\n  \
             (c) pass --netns=false and instead permit the two locally-terminated legs \
             (INPUT to the listener, OUTPUT to the server).",
            rule = rule,
            vc_h = names.vc_h,
            vu_h = names.vu_h,
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
    // A box with no iptables at all is fine — treat an unreadable ruleset as empty.
    let rules = Command::new("iptables")
        .args(["-S", "FORWARD"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .unwrap_or_default();

    if let Some(b) = diagnose(ip_forward, &rules, cfg.server_ip) {
        anyhow::bail!("{}", blocker_message(&b, &names));
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

        let plumbing = build_plumbing(cfg);
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
    let p = build_plumbing(cfg);
    for s in p.steps.iter().rev() {
        if let Some(undo) = &s.undo {
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

    #[test]
    fn preflight_requires_host_forwarding() {
        assert_eq!(diagnose(false, "", SERVER), Some(Blocker::NoForwarding));
    }

    #[test]
    fn preflight_accepts_a_destination_only_forward_rule() {
        let rules = "-P FORWARD DROP\n\
                     -A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT\n\
                     -A FORWARD -d 10.10.2.10/32 -p tcp -m tcp --dport 443 -j ACCEPT\n";
        assert_eq!(diagnose(true, rules, SERVER), None);
    }

    #[test]
    fn preflight_rejects_an_interface_pinned_forward_rule() {
        // This permits the flow today but will not match -o mmc0 / -i mmu0.
        let rules = "-A FORWARD -i tun0 -o eth0 -d 10.10.2.10/32 -p tcp --dport 443 -j ACCEPT\n";
        match diagnose(true, rules, SERVER) {
            Some(Blocker::ForwardPinnedToIfaces(r)) => assert!(r.contains("-i tun0")),
            other => panic!("expected an interface-pinning blocker, got {other:?}"),
        }
    }

    #[test]
    fn preflight_ignores_pinned_rules_for_other_servers() {
        let rules = "-A FORWARD -i tun0 -o eth0 -d 192.168.99.99/32 -j ACCEPT\n\
                     -A FORWARD -d 10.10.2.10/32 -p tcp --dport 443 -j ACCEPT\n";
        assert_eq!(diagnose(true, rules, SERVER), None);
    }

    #[test]
    fn preflight_allows_a_box_with_no_forward_rules_at_all() {
        // Permissive FORWARD policy / no firewall: the common case today.
        assert_eq!(diagnose(true, "-P FORWARD ACCEPT\n", SERVER), None);
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
    }
}
