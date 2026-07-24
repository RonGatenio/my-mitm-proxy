//! Shared kernel-sysctl helpers, plus the eBPF data plane's startup sysctl
//! preflight (added in a later task).
//!
//! Both data planes touch `/proc/sys`: the `iproute` plane as part of its visible
//! setup, and the `ebpf` plane to fix the two settings that otherwise make it
//! silently blackhole diverted client traffic. The low-level read/write primitives
//! live here so both share exactly one implementation.

/// A sysctl we changed and must restore. `key` is dotted (`net.ipv4.ip_forward`).
pub(crate) struct SavedSysctl {
    pub(crate) key: String,
    pub(crate) original: String,
}

/// Read a sysctl by dotted key. `None` if the path is unreadable (e.g. the
/// interface does not exist).
pub(crate) fn read_sysctl(key: &str) -> Option<String> {
    let p = format!("/proc/sys/{}", key.replace('.', "/"));
    std::fs::read_to_string(p).ok().map(|s| s.trim().to_string())
}

/// Write a sysctl by dotted key.
pub(crate) fn write_sysctl(key: &str, val: &str) -> std::io::Result<()> {
    let p = format!("/proc/sys/{}", key.replace('.', "/"));
    std::fs::write(p, val)
}

use std::net::Ipv4Addr;

/// One sysctl the eBPF plane needs changed, with the reason (for the WARN / error).
#[derive(Debug, Clone, PartialEq, Eq)]
struct Change {
    key: String,
    current: String,
    want: &'static str,
    reason: String,
}

/// PURE: given the plane's `local_ip` + `tun_iface` and a reader for current
/// sysctl values, list the changes the eBPF data plane needs. Empty when nothing
/// is wrong. Does not decide whether to apply them — see `plan`.
///
/// * `route_localnet` — only when `local_ip` is loopback. Effective value is
///   `conf.all.route_localnet OR conf.<iface>.route_localnet`; if neither is on
///   we set the iface knob to `1` (packets DNAT'd to the loopback listener are
///   martian-dropped otherwise).
/// * `rp_filter` — effective value is `MAX(conf.all, conf.<iface>)`, so BOTH must
///   be `0`; any non-zero one is flagged (the client's original source arrives on
///   the tun iface and would be reverse-path dropped).
fn needed_changes(
    local_ip: Ipv4Addr,
    tun_iface: &str,
    read: impl Fn(&str) -> Option<String>,
) -> Vec<Change> {
    let mut out = Vec::new();

    if local_ip.is_loopback() {
        let all_on = read("net.ipv4.conf.all.route_localnet").as_deref() == Some("1");
        let key = format!("net.ipv4.conf.{tun_iface}.route_localnet");
        if let Some(cur) = read(&key) {
            if !all_on && cur != "1" {
                out.push(Change {
                    key,
                    current: cur,
                    want: "1",
                    reason: format!(
                        "local_addr {local_ip} is a loopback address; client packets DNAT'd to \
                         it on {tun_iface} are martian-dropped without route_localnet"
                    ),
                });
            }
        }
    }

    for key in [
        "net.ipv4.conf.all.rp_filter".to_string(),
        format!("net.ipv4.conf.{tun_iface}.rp_filter"),
    ] {
        if let Some(cur) = read(&key) {
            if cur != "0" {
                out.push(Change {
                    key,
                    current: cur,
                    want: "0",
                    reason: format!(
                        "reverse-path filtering on {tun_iface} drops the client's preserved \
                         source address"
                    ),
                });
            }
        }
    }

    out
}

/// PURE: the actionable error shown when `manage_sysctls=false` and changes are
/// needed. Lists each problem and the three ways to fix it.
fn fail_message(changes: &[Change]) -> String {
    use std::fmt::Write;
    let mut m = String::from(
        "eBPF data plane needs kernel sysctls that are not set, and --manage-sysctls=false:\n",
    );
    for c in changes {
        let _ = writeln!(m, "  - {} is {}, needs {} ({})", c.key, c.current, c.want, c.reason);
    }
    let sets: Vec<String> =
        changes.iter().map(|c| format!("sysctl -w {}={}", c.key, c.want)).collect();
    let _ = write!(
        m,
        "Fix by ONE of:\n  \
         (a) drop --manage-sysctls=false to let mymitm set and restore them (default), or\n  \
         (b) set them yourself: {}, or\n  \
         (c) set local_addr to a non-loopback IP (removes the route_localnet requirement).",
        sets.join("; ")
    );
    m
}

/// PURE decision: apply the changes (manage=true, or nothing to do) vs fail
/// (manage=false with outstanding changes).
enum Plan {
    Apply(Vec<Change>),
    Fail(String),
}

fn plan(changes: Vec<Change>, manage: bool) -> Plan {
    if !manage && !changes.is_empty() {
        Plan::Fail(fail_message(&changes))
    } else {
        Plan::Apply(changes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn reader(pairs: &[(&'static str, &'static str)]) -> impl Fn(&str) -> Option<String> {
        let m: HashMap<String, String> =
            pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        move |k: &str| m.get(k).cloned()
    }

    const LOOPBACK: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 1);
    const REAL: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 10);
    const OK: &[(&str, &str)] = &[
        ("net.ipv4.conf.all.route_localnet", "0"),
        ("net.ipv4.conf.tun0.route_localnet", "1"),
        ("net.ipv4.conf.all.rp_filter", "0"),
        ("net.ipv4.conf.tun0.rp_filter", "0"),
    ];

    #[test]
    fn all_good_needs_nothing() {
        assert!(needed_changes(LOOPBACK, "tun0", reader(OK)).is_empty());
    }

    #[test]
    fn loopback_route_localnet_off_is_flagged() {
        let r = reader(&[
            ("net.ipv4.conf.all.route_localnet", "0"),
            ("net.ipv4.conf.tun0.route_localnet", "0"),
            ("net.ipv4.conf.all.rp_filter", "0"),
            ("net.ipv4.conf.tun0.rp_filter", "0"),
        ]);
        let c = needed_changes(LOOPBACK, "tun0", r);
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].key, "net.ipv4.conf.tun0.route_localnet");
        assert_eq!(c[0].want, "1");
    }

    #[test]
    fn all_route_localnet_on_satisfies_iface() {
        let r = reader(&[
            ("net.ipv4.conf.all.route_localnet", "1"),
            ("net.ipv4.conf.tun0.route_localnet", "0"),
            ("net.ipv4.conf.all.rp_filter", "0"),
            ("net.ipv4.conf.tun0.rp_filter", "0"),
        ]);
        assert!(needed_changes(LOOPBACK, "tun0", r).is_empty());
    }

    #[test]
    fn non_loopback_skips_route_localnet() {
        let r = reader(&[
            ("net.ipv4.conf.all.route_localnet", "0"),
            ("net.ipv4.conf.tun0.route_localnet", "0"),
            ("net.ipv4.conf.all.rp_filter", "0"),
            ("net.ipv4.conf.tun0.rp_filter", "0"),
        ]);
        assert!(needed_changes(REAL, "tun0", r).is_empty());
    }

    #[test]
    fn rp_filter_nonzero_on_all_or_iface_is_flagged() {
        let r = reader(&[
            ("net.ipv4.conf.all.route_localnet", "1"),
            ("net.ipv4.conf.tun0.route_localnet", "1"),
            ("net.ipv4.conf.all.rp_filter", "1"),
            ("net.ipv4.conf.tun0.rp_filter", "2"),
        ]);
        let c = needed_changes(LOOPBACK, "tun0", r);
        assert_eq!(c.len(), 2);
        assert!(c.iter().all(|x| x.want == "0"));
        assert_eq!(c[0].key, "net.ipv4.conf.all.rp_filter");
        assert_eq!(c[1].key, "net.ipv4.conf.tun0.rp_filter");
    }

    #[test]
    fn unreadable_iface_knob_is_skipped() {
        // Only `all` present; iface knobs absent (iface not up) -> nothing to do.
        let r = reader(&[
            ("net.ipv4.conf.all.route_localnet", "0"),
            ("net.ipv4.conf.all.rp_filter", "0"),
        ]);
        assert!(needed_changes(LOOPBACK, "tun0", r).is_empty());
    }

    #[test]
    fn plan_fails_only_when_unmanaged_and_dirty() {
        let dirty = vec![Change {
            key: "net.ipv4.conf.tun0.route_localnet".into(),
            current: "0".into(),
            want: "1",
            reason: "x".into(),
        }];
        assert!(matches!(plan(dirty.clone(), true), Plan::Apply(_)));
        assert!(matches!(plan(vec![], false), Plan::Apply(_)));
        assert!(matches!(plan(dirty, false), Plan::Fail(_)));
    }

    #[test]
    fn fail_message_lists_problems_and_remedies() {
        let dirty = vec![Change {
            key: "net.ipv4.conf.tun0.route_localnet".into(),
            current: "0".into(),
            want: "1",
            reason: "loopback".into(),
        }];
        let m = fail_message(&dirty);
        assert!(m.contains("net.ipv4.conf.tun0.route_localnet is 0, needs 1"));
        assert!(m.contains("sysctl -w net.ipv4.conf.tun0.route_localnet=1"));
        assert!(m.contains("--manage-sysctls"));
        assert!(m.contains("non-loopback"));
    }
}
