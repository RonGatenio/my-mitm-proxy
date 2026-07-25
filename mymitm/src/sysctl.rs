//! Shared kernel-sysctl helpers, plus the eBPF data plane's startup sysctl
//! preflight (SysctlGuard).
//!
//! Both data planes touch `/proc/sys`: the `iproute` plane as part of its visible
//! setup, and the `ebpf` plane to fix the two settings that otherwise make it
//! silently blackhole diverted client traffic. The low-level read/write primitives
//! live here so both share exactly one implementation.

/// A sysctl we changed and must restore. `key` is dotted (`net.ipv4.ip_forward`).
#[derive(Debug)]
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
         (a) pass --manage-sysctls=true to let mymitm set and restore them, or\n  \
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

use crate::config::Settings;

/// RAII guard: enforces the eBPF plane's sysctl requirements on `acquire`, and
/// restores whatever it changed on drop.
pub(crate) struct SysctlGuard {
    saved: Vec<SavedSysctl>,
}

impl SysctlGuard {
    /// Per `s.manage_sysctls`:
    /// * true  → set any wrong value (saving originals), WARN per change; restore on drop.
    /// * false → change nothing; `Err` with an actionable message if anything is wrong.
    pub(crate) fn acquire(s: &Settings) -> anyhow::Result<SysctlGuard> {
        let saved = compute_and_apply(
            s.local_ip,
            &s.tun_iface,
            s.manage_sysctls,
            read_sysctl,
            |k, v| write_sysctl(k, v),
        )?;
        Ok(SysctlGuard { saved })
    }
}

/// Core of `acquire`, parameterised over the read/write side effects so it is
/// unit-testable without root. Returns the originals to restore later; on
/// `manage=false` with outstanding changes it returns `Err` and writes nothing.
fn compute_and_apply(
    local_ip: std::net::Ipv4Addr,
    tun_iface: &str,
    manage: bool,
    read: impl Fn(&str) -> Option<String>,
    mut write: impl FnMut(&str, &str) -> std::io::Result<()>,
) -> anyhow::Result<Vec<SavedSysctl>> {
    let changes = match plan(needed_changes(local_ip, tun_iface, read), manage) {
        Plan::Fail(msg) => anyhow::bail!("{msg}"),
        Plan::Apply(c) => c,
    };
    let mut saved: Vec<SavedSysctl> = Vec::new();
    for c in &changes {
        if let Err(e) = write(&c.key, c.want) {
            // Roll back what we already changed, then fail.
            for sv in saved.iter().rev() {
                let _ = write(&sv.key, &sv.original);
            }
            anyhow::bail!("set {}={}: {e}", c.key, c.want);
        }
        tracing::warn!(
            "manage-sysctls: set {} {} -> {} ({}); will restore on exit",
            c.key, c.current, c.want, c.reason
        );
        saved.push(SavedSysctl { key: c.key.clone(), original: c.current.clone() });
    }
    Ok(saved)
}

impl Drop for SysctlGuard {
    fn drop(&mut self) {
        for sv in self.saved.iter().rev() {
            let _ = write_sysctl(&sv.key, &sv.original);
        }
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
        assert!(m.contains("--manage-sysctls=true"));
        assert!(m.contains("non-loopback"));
    }

    #[test]
    fn apply_sets_and_records_when_managed() {
        use std::cell::RefCell;
        let writes = RefCell::new(Vec::<(String, String)>::new());
        let saved = compute_and_apply(LOOPBACK, "tun0", true, reader(&[
            ("net.ipv4.conf.all.route_localnet", "0"),
            ("net.ipv4.conf.tun0.route_localnet", "0"),
            ("net.ipv4.conf.all.rp_filter", "0"),
            ("net.ipv4.conf.tun0.rp_filter", "0"),
        ]), |k, v| { writes.borrow_mut().push((k.to_string(), v.to_string())); Ok(()) }).unwrap();
        assert_eq!(
            writes.borrow().as_slice(),
            &[("net.ipv4.conf.tun0.route_localnet".to_string(), "1".to_string())]
        );
        assert_eq!(saved.len(), 1);
        assert_eq!(saved[0].key, "net.ipv4.conf.tun0.route_localnet");
        assert_eq!(saved[0].original, "0");
    }

    #[test]
    fn apply_fails_fast_when_unmanaged_and_dirty() {
        let res = compute_and_apply(LOOPBACK, "tun0", false, reader(&[
            ("net.ipv4.conf.all.route_localnet", "0"),
            ("net.ipv4.conf.tun0.route_localnet", "0"),
            ("net.ipv4.conf.all.rp_filter", "0"),
            ("net.ipv4.conf.tun0.rp_filter", "0"),
        ]), |_, _| panic!("must not write when unmanaged"));
        assert!(res.is_err());
        assert!(res.unwrap_err().to_string().contains("route_localnet"));
    }

    #[test]
    fn apply_noop_when_clean_even_if_unmanaged() {
        let saved =
            compute_and_apply(LOOPBACK, "tun0", false, reader(OK), |_, _| panic!("no writes"))
                .unwrap();
        assert!(saved.is_empty());
    }

    // Rollback: when a LATER write fails after an EARLIER one succeeded,
    // compute_and_apply restores the already-applied change(s) in reverse and
    // surfaces the original write error. Uses a counter closure that fails on the
    // 2nd write. The reader yields 3 changes (route_localnet + both rp_filter).
    #[test]
    fn apply_rolls_back_earlier_writes_on_later_failure() {
        use std::cell::RefCell;
        let calls = RefCell::new(Vec::<(String, String)>::new());
        let n = RefCell::new(0u32);
        let res = compute_and_apply(LOOPBACK, "tun0", true, reader(&[
            ("net.ipv4.conf.all.route_localnet", "0"),
            ("net.ipv4.conf.tun0.route_localnet", "0"),
            ("net.ipv4.conf.all.rp_filter", "1"),
            ("net.ipv4.conf.tun0.rp_filter", "1"),
        ]), |k, v| {
            calls.borrow_mut().push((k.to_string(), v.to_string()));
            let mut c = n.borrow_mut();
            *c += 1;
            if *c >= 2 {
                Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied, "boom"))
            } else {
                Ok(())
            }
        });
        assert!(res.is_err());
        let calls = calls.borrow();
        // 1st write applied tun0.route_localnet=1; 2nd write (all.rp_filter=0) failed;
        // rollback then restored tun0.route_localnet back to its original "0".
        assert_eq!(
            calls[0],
            ("net.ipv4.conf.tun0.route_localnet".to_string(), "1".to_string())
        );
        assert_eq!(
            calls[1],
            ("net.ipv4.conf.all.rp_filter".to_string(), "0".to_string())
        );
        assert_eq!(
            calls.last().unwrap(),
            &("net.ipv4.conf.tun0.route_localnet".to_string(), "0".to_string())
        );
    }

    // rp_filter is checked independently of the loopback gate: even for a
    // non-loopback local_ip (route_localnet skipped), a non-zero rp_filter is flagged.
    #[test]
    fn rp_filter_flagged_even_for_non_loopback_local_ip() {
        let r = reader(&[
            ("net.ipv4.conf.all.route_localnet", "0"),
            ("net.ipv4.conf.tun0.route_localnet", "0"),
            ("net.ipv4.conf.all.rp_filter", "1"),
            ("net.ipv4.conf.tun0.rp_filter", "0"),
        ]);
        let c = needed_changes(REAL, "tun0", r);
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].key, "net.ipv4.conf.all.rp_filter");
        assert_eq!(c[0].want, "0");
    }
}
