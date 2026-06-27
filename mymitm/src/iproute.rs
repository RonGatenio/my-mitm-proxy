//! Non-eBPF data plane: visible iproute2/iptables/sysctl plumbing achieving the
//! same DNAT-to-local + client-source-IP preservation. NOT stealthy by design.
//! Every action is reversed in Drop (and by `cleanup`).
//!
//! ## Mechanism
//! One fixed routing table id derived from fwmark (`table = 100 + (fwmark & 0xff)`).
//!
//! `setup()` installs in order:
//! 1. **iptables DNAT** — intercept client→server traffic arriving on the tun iface
//!    to the local listener (`local_ip:local_port`).
//! 2. **`ip rule fwmark → table`** — marked packets look up the custom table.
//! 3. **`ip route local 0.0.0.0/0 dev lo table N`** — so marked replies to spoofed
//!    client IPs are delivered locally (not dropped).
//!
//! `upstream_socket()` opens a TCP connection with `IP_TRANSPARENT` + `SO_MARK` +
//! bind-to-client-IP so packets egress with the client's source address.

use std::net::{Ipv4Addr, SocketAddrV4, TcpStream};
use std::process::Command;

use crate::config::Settings;
use crate::dataplane::DataPlane;

// ---------------------------------------------------------------------------
// Pure rule-spec builder (no side effects, unit-tested without root)
// ---------------------------------------------------------------------------

/// The exact CLI invocations this plane installs, in apply order.
///
/// Each entry is `(program, add-args, delete-args)` so teardown is the precise
/// inverse. The struct is pure / has no side effects — unit tested without root.
pub struct RuleSet {
    pub table: u32,
    pub items: Vec<(&'static str, Vec<String>, Vec<String>)>,
}

fn s(v: &str) -> String {
    v.to_string()
}

/// Build the full rule specification for `cfg` without executing anything.
pub fn build_ruleset(cfg: &Settings) -> RuleSet {
    let table = 100 + (cfg.fwmark & 0xff);
    let server = cfg.server_ip.to_string();
    let port = cfg.server_port.to_string();
    let local = format!("{}:{}", cfg.local_ip, cfg.local_port);
    let mark = cfg.fwmark.to_string();
    let tbl = table.to_string();
    let items = vec![
        // 1. Intercept: DNAT client→server to the local listener on the tun iface.
        (
            "iptables",
            vec![
                s("-t"),
                s("nat"),
                s("-A"),
                s("PREROUTING"),
                s("-i"),
                cfg.tun_iface.clone(),
                s("-p"),
                s("tcp"),
                s("-d"),
                server.clone(),
                s("--dport"),
                port.clone(),
                s("-j"),
                s("DNAT"),
                s("--to-destination"),
                local.clone(),
            ],
            vec![
                s("-t"),
                s("nat"),
                s("-D"),
                s("PREROUTING"),
                s("-i"),
                cfg.tun_iface.clone(),
                s("-p"),
                s("tcp"),
                s("-d"),
                server.clone(),
                s("--dport"),
                port.clone(),
                s("-j"),
                s("DNAT"),
                s("--to-destination"),
                local.clone(),
            ],
        ),
        // 2. Reply capture: fwmark → custom routing table.
        (
            "ip",
            vec![
                s("rule"),
                s("add"),
                s("fwmark"),
                mark.clone(),
                s("lookup"),
                tbl.clone(),
            ],
            vec![
                s("rule"),
                s("del"),
                s("fwmark"),
                mark.clone(),
                s("lookup"),
                tbl.clone(),
            ],
        ),
        // 3. Local delivery: marked replies to spoofed client IPs go to loopback.
        (
            "ip",
            vec![
                s("route"),
                s("add"),
                s("local"),
                s("0.0.0.0/0"),
                s("dev"),
                s("lo"),
                s("table"),
                tbl.clone(),
            ],
            vec![
                s("route"),
                s("del"),
                s("local"),
                s("0.0.0.0/0"),
                s("dev"),
                s("lo"),
                s("table"),
                tbl.clone(),
            ],
        ),
    ];
    RuleSet { table, items }
}

// ---------------------------------------------------------------------------
// Execution helpers
// ---------------------------------------------------------------------------

fn run(prog: &str, args: &[String]) -> std::io::Result<()> {
    tracing::debug!("iproute: {prog} {}", args.join(" "));
    let st = Command::new(prog).args(args).status()?;
    if !st.success() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("{prog} {:?} exited {st}", args),
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Sysctl helpers
// ---------------------------------------------------------------------------

/// A sysctl we set and must restore. `key` is in dotted form (`net.ipv4.ip_forward`).
struct SavedSysctl {
    key: String,
    original: String,
}

fn read_sysctl(key: &str) -> Option<String> {
    let p = format!("/proc/sys/{}", key.replace('.', "/"));
    std::fs::read_to_string(p).ok().map(|s| s.trim().to_string())
}

fn write_sysctl(key: &str, val: &str) -> std::io::Result<()> {
    let p = format!("/proc/sys/{}", key.replace('.', "/"));
    std::fs::write(p, val)
}

// ---------------------------------------------------------------------------
// IpRoutePlane
// ---------------------------------------------------------------------------

pub struct IpRoutePlane {
    rules: RuleSet,
    fwmark: u32,
    saved: Vec<SavedSysctl>,
}

impl IpRoutePlane {
    /// Install iptables DNAT, policy-routing rule + local route, and required
    /// sysctls. On any failure, reverses everything already applied before
    /// returning `Err` — never leaves a half-applied state.
    pub fn setup(s: &Settings) -> anyhow::Result<IpRoutePlane> {
        let mut saved = Vec::new();

        // Required sysctls.
        let sysctl_wants: Vec<(String, &str)> = vec![
            ("net.ipv4.ip_forward".to_string(), "1"),
            (
                format!("net.ipv4.conf.{}.rp_filter", s.tun_iface),
                "0",
            ),
            (
                format!("net.ipv4.conf.{}.route_localnet", s.tun_iface),
                "1",
            ),
        ];

        for (key, want) in &sysctl_wants {
            if let Some(orig) = read_sysctl(key) {
                if orig != *want {
                    write_sysctl(key, want)
                        .map_err(|e| anyhow::anyhow!("set {key}={want}: {e}"))?;
                    saved.push(SavedSysctl {
                        key: key.clone(),
                        original: orig,
                    });
                }
            }
        }

        let rules = build_ruleset(s);

        // Apply rules in order; on any failure, reverse what we've applied.
        let mut applied = 0usize;
        for (prog, add, _del) in &rules.items {
            if let Err(e) = run(prog, add) {
                // Roll back applied rules in reverse order.
                for (p2, _a2, d2) in rules.items[..applied].iter().rev() {
                    let _ = run(p2, d2);
                }
                // Restore sysctls in reverse order.
                for sv in saved.iter().rev() {
                    let _ = write_sysctl(&sv.key, &sv.original);
                }
                return Err(anyhow::anyhow!("apply {prog} failed: {e}"));
            }
            applied += 1;
        }

        tracing::info!("iproute data plane installed (table {})", rules.table);
        Ok(IpRoutePlane {
            rules,
            fwmark: s.fwmark,
            saved,
        })
    }
}

impl DataPlane for IpRoutePlane {
    /// Open a TCP connection to `server` bound to `client_ip:0` with
    /// `IP_TRANSPARENT` (allows binding a non-local address) and `SO_MARK`
    /// (routes replies via the custom table back to us). Returns a nonblocking
    /// `TcpStream` consistent with the eBPF plane.
    ///
    /// Note: socket2 0.6.4 names this `set_ip_transparent_v4` (not
    /// `set_ip_transparent`). We use the v4-specific variant since this plane is
    /// IPv4-only.
    fn upstream_socket(&self, client_ip: Ipv4Addr, server: SocketAddrV4) -> std::io::Result<TcpStream> {
        let sock = socket2::Socket::new(
            socket2::Domain::IPV4,
            socket2::Type::STREAM,
            Some(socket2::Protocol::TCP),
        )?;
        // IP_TRANSPARENT: allows binding to a non-local (client) source address.
        sock.set_ip_transparent_v4(true)?;
        sock.set_reuse_address(true)?;
        if self.fwmark != 0 {
            sock.set_mark(self.fwmark)?;
        }
        // Bind to dynamic client IP (ephemeral port 0) so packets egress with
        // src = client_ip; the fwmark rule routes replies back to us.
        sock.bind(&SocketAddrV4::new(client_ip, 0).into())?;
        sock.connect(&server.into())?;
        sock.set_nonblocking(true)?;
        Ok(sock.into())
    }
}

impl Drop for IpRoutePlane {
    fn drop(&mut self) {
        // Reverse rules in reverse apply order.
        for (prog, _add, del) in self.rules.items.iter().rev() {
            let _ = run(prog, del);
        }
        // Restore sysctls in reverse order.
        for sv in self.saved.iter().rev() {
            let _ = write_sysctl(&sv.key, &sv.original);
        }
        tracing::debug!("iproute data plane torn down");
    }
}

/// Best-effort reverse of leftovers from an unclean exit (matches what `setup`
/// adds). Safe to call when nothing is installed — failures are ignored.
pub fn cleanup(s: &Settings) {
    let rules = build_ruleset(s);
    for (prog, _add, del) in rules.items.iter().rev() {
        let _ = run(prog, del);
    }
}

// ---------------------------------------------------------------------------
// Tests (pure builder — no root required)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn settings() -> Settings {
        Settings {
            client_ip: None,
            server_ip: Ipv4Addr::new(192, 168, 1, 50),
            server_port: 443,
            tun_iface: "tun0".into(),
            egress_iface: "eth0".into(),
            local_ip: Ipv4Addr::LOCALHOST,
            local_port: 8443,
            fwmark: 0x1337,
            cert_path: PathBuf::from("/x"),
            key_path: PathBuf::from("/y"),
            dump_path: PathBuf::from("/tmp"),
            bpf_obj_name: "mymitm".into(),
            box_ip: Ipv4Addr::new(192, 168, 1, 10),
            log_level: "info".into(),
            server_name: None,
            data_plane: crate::config::DataPlaneKind::IpRoute,
            attach_mode: crate::config::AttachMode::Auto,
            cleanup: false,
        }
    }

    #[test]
    fn ruleset_table_from_fwmark_and_inverse_pairs() {
        let rs = build_ruleset(&settings());
        // table = 100 + (0x1337 & 0xff) = 100 + 0x37 = 100 + 55 = 155
        assert_eq!(rs.table, 100 + 0x37);
        // Every add has a matching delete with the same arg count.
        for (_p, add, del) in &rs.items {
            assert!(add.iter().any(|a| a == "-A" || a == "add"));
            assert!(del.iter().any(|d| d == "-D" || d == "del"));
            assert_eq!(add.len(), del.len());
        }
    }

    #[test]
    fn ruleset_dnat_targets_local_listener() {
        let rs = build_ruleset(&settings());
        let (_p, add, _del) = &rs.items[0];
        // The DNAT target must be the local listener address.
        assert!(add.contains(&"127.0.0.1:8443".to_string()));
        // The intercept must be scoped to the tun interface.
        assert!(add.contains(&"tun0".to_string()));
    }

    #[test]
    fn ruleset_has_exactly_three_items() {
        let rs = build_ruleset(&settings());
        // 1 iptables DNAT + 1 ip rule + 1 ip route
        assert_eq!(rs.items.len(), 3);
    }

    #[test]
    fn ruleset_table_id_in_rule_and_route() {
        let rs = build_ruleset(&settings());
        let tbl = rs.table.to_string();
        // ip rule add must reference the table id.
        let (_p, add_rule, _) = &rs.items[1];
        assert!(add_rule.contains(&tbl));
        // ip route add must also reference the same table id.
        let (_p, add_route, _) = &rs.items[2];
        assert!(add_route.contains(&tbl));
    }

    #[test]
    fn ruleset_fwmark_in_ip_rule() {
        let rs = build_ruleset(&settings());
        let mark = format!("{:#x}", 0x1337u32);
        let mark_dec = 0x1337u32.to_string();
        let (_p, add_rule, _) = &rs.items[1];
        // fwmark appears in decimal form (to_string on u32).
        assert!(
            add_rule.contains(&mark) || add_rule.contains(&mark_dec),
            "fwmark not found in ip rule: {add_rule:?}"
        );
    }

    /// Smoke-test: the `programs` field of each item is the right binary.
    #[test]
    fn ruleset_program_names() {
        let rs = build_ruleset(&settings());
        assert_eq!(rs.items[0].0, "iptables");
        assert_eq!(rs.items[1].0, "ip");
        assert_eq!(rs.items[2].0, "ip");
    }

    /// Privileged smoke test: setup() applies, drop reverses. Run with sudo.
    /// `cargo test -p mymitm --target x86_64-unknown-linux-gnu iproute_setup_and_drop -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn iproute_setup_and_drop() {
        use std::process::Command as C;

        // Create a throwaway tun interface.
        let _ = C::new("ip").args(["link", "del", "mmtun0"]).status();
        C::new("ip")
            .args(["tuntap", "add", "dev", "mmtun0", "mode", "tun"])
            .status()
            .expect("create mmtun0");
        C::new("ip")
            .args(["link", "set", "mmtun0", "up"])
            .status()
            .expect("up mmtun0");

        let s = Settings::from_toml_str(
            r#"
            target_server_ip = "192.168.1.50"
            cert_path = "/x"
            key_path = "/y"
            box_ip = "192.168.1.10"
            tun_iface = "mmtun0"
            egress_iface = "eth0"
            data_plane = "iproute"
        "#,
        )
        .expect("settings");

        let rs = build_ruleset(&s);
        let table_str = rs.table.to_string();

        {
            let _plane = IpRoutePlane::setup(&s).expect("setup");

            // Verify iptables rule exists.
            let out = C::new("iptables")
                .args(["-t", "nat", "-S", "PREROUTING"])
                .output()
                .expect("iptables -S");
            let rules = String::from_utf8_lossy(&out.stdout);
            assert!(
                rules.contains("DNAT") && rules.contains("mmtun0"),
                "DNAT rule missing while plane is active:\n{rules}"
            );
            println!("IPTABLES_OK: DNAT rule present");

            // Verify ip rule exists.
            let out = C::new("ip").args(["rule"]).output().expect("ip rule");
            let rules = String::from_utf8_lossy(&out.stdout);
            assert!(
                rules.contains("fwmark") && rules.contains(&table_str),
                "ip rule missing while plane is active:\n{rules}"
            );
            println!("IPRULE_OK: fwmark rule present");

            // Verify ip route exists.
            let out = C::new("ip")
                .args(["route", "show", "table", &table_str])
                .output()
                .expect("ip route show");
            let routes = String::from_utf8_lossy(&out.stdout);
            assert!(
                routes.contains("local") && routes.contains("lo"),
                "local route missing while plane is active:\n{routes}"
            );
            println!("IPROUTE_OK: local route present");
        } // _plane dropped -> rules/routes reversed

        // After drop, DNAT rule must be gone.
        let out = C::new("iptables")
            .args(["-t", "nat", "-S", "PREROUTING"])
            .output()
            .expect("iptables -S after drop");
        let rules = String::from_utf8_lossy(&out.stdout);
        assert!(
            !rules.contains("mmtun0"),
            "DNAT rule still present after drop:\n{rules}"
        );
        println!("IPTABLES_GONE_OK");

        // After drop, ip rule must be gone.
        let out = C::new("ip").args(["rule"]).output().expect("ip rule after drop");
        let rules_after = String::from_utf8_lossy(&out.stdout);
        assert!(
            !rules_after.contains(&table_str) || !rules_after.contains("fwmark"),
            "ip rule still present after drop:\n{rules_after}"
        );
        println!("IPRULE_GONE_OK");

        // After drop, ip route must be gone.
        let out = C::new("ip")
            .args(["route", "show", "table", &table_str])
            .output()
            .expect("ip route show after drop");
        let routes_after = String::from_utf8_lossy(&out.stdout);
        assert!(
            routes_after.trim().is_empty(),
            "local route still present after drop:\n{routes_after}"
        );
        println!("IPROUTE_GONE_OK");

        // Tear down mmtun0.
        let _ = C::new("ip").args(["link", "del", "mmtun0"]).status();
        println!("SMOKE_TEST_PASSED");
    }
}
