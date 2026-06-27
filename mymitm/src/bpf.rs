//! eBPF lifecycle (userspace side).
//!
//! `BpfPlane::load_and_attach` loads the embedded eBPF object with CO-RE
//! (`EbpfLoader` default → relocates against `/sys/kernel/btf/vmlinux`),
//! populates the single-entry `CONFIG` map, and attaches all four classifiers.
//!
//! ## TCX, not clsact (kernel 6.6)
//! This kernel is >= 6.6, where aya 0.13's `SchedClassifier::attach()` uses the
//! modern **TCX link** interface, NOT the legacy clsact-filter path (proven in
//! the Task 1 spike). Consequences for this module:
//!
//! * We do **not** create a clsact qdisc and do **not** shell out to `tc`.
//! * `prog.attach(iface, dir)` returns a `SchedClassifierLinkId`; the live link
//!   is owned by the `Ebpf` object. We hold the `Ebpf` inside `BpfPlane` for the
//!   process lifetime so the links — and therefore the attachments — stay alive.
//! * **Fail-open is automatic:** TCX links are owned by the process's fds. When
//!   `BpfPlane` drops (normal exit, SIGTERM, even SIGKILL) the kernel releases
//!   the links and the programs detach; traffic reverts to normal forwarding.
//!   So `Drop` needs no explicit teardown — dropping the `Ebpf` is sufficient.
//! * Attachment is verified via `SchedClassifier::query_tcx(iface, dir)`, NOT
//!   `tc filter show` / `bpftool` (both show nothing for TCX on this kernel).

use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::Mutex;

use aya::maps::{Array, HashMap as AyaHashMap, MapData};
use aya::programs::{SchedClassifier, TcAttachType};
use aya::{Ebpf, EbpfLoader};
use mymitm_common::Config;

use crate::config::Settings;
use crate::dataplane::DataPlane;

/// The four classifier program names, in (program, iface-selector, direction)
/// form. The iface selector picks `tun_iface` vs `egress_iface` from `Settings`
/// at attach time.
enum Side {
    Tun,
    Eth,
}

const PROGRAMS: [(&str, Side, TcAttachType); 4] = [
    ("cls_tun_ingress", Side::Tun, TcAttachType::Ingress),
    ("cls_tun_egress", Side::Tun, TcAttachType::Egress),
    ("cls_eth_ingress", Side::Eth, TcAttachType::Ingress),
    ("cls_eth_egress", Side::Eth, TcAttachType::Egress),
];

/// Owns the loaded eBPF object (and thus the live TCX links). Dropping it
/// detaches every program automatically.
pub struct BpfPlane {
    // Held for the process lifetime purely as an RAII guard: dropping it releases
    // the TCX links and auto-detaches the programs (see Drop). Not read directly.
    #[allow(dead_code)]
    ebpf: Ebpf,
    #[allow(dead_code)]
    tun: String,
    #[allow(dead_code)]
    egress_iface: String,
    box_ip: Ipv4Addr,
    fwmark: u32,
    /// EGRESS map: box ephemeral src port (NBO) -> client IP (NBO). Written per
    /// connection just before connect() so cls_eth_egress can SNAT correctly.
    egress_map: Mutex<AyaHashMap<MapData, u16, u32>>,
}

impl BpfPlane {
    /// Load the embedded object with CO-RE, populate `CONFIG`, init aya-log
    /// (best-effort), and attach all four classifiers via TCX.
    pub fn load_and_attach(s: &Settings) -> anyhow::Result<BpfPlane> {
        // EbpfLoader default does CO-RE BTF relocation against the running kernel.
        let mut ebpf = EbpfLoader::new().load(aya::include_bytes_aligned!(concat!(
            env!("OUT_DIR"),
            "/mymitm"
        )))?;

        // aya-log is best-effort: if the eBPF side emits no log map, init returns
        // an error we deliberately ignore so it never fails startup.
        let _ = aya_log::EbpfLogger::init(&mut ebpf);

        // Populate the single-entry CONFIG map (index 0) with the NBO config.
        {
            let map = ebpf
                .map_mut("CONFIG")
                .ok_or_else(|| anyhow::anyhow!("CONFIG map not found in eBPF object"))?;
            let mut cfgmap: Array<&mut MapData, Config> = Array::try_from(map)?;
            cfgmap.set(0, s.to_bpf_config(), 0)?;
        }

        // Take ownership of the EGRESS map so userspace can write it per-conn.
        let egress_map: AyaHashMap<MapData, u16, u32> = AyaHashMap::try_from(
            ebpf.take_map("EGRESS")
                .ok_or_else(|| anyhow::anyhow!("EGRESS map not found in eBPF object"))?,
        )?;

        // Load + attach the four classifiers. On 6.6 aya uses TCX automatically;
        // the returned link id is retained by the owning `SchedClassifier`, which
        // lives inside `ebpf`, so the attachment persists as long as we hold it.
        for (name, side, dir) in PROGRAMS {
            let iface = match side {
                Side::Tun => &s.tun_iface,
                Side::Eth => &s.egress_iface,
            };
            let prog: &mut SchedClassifier = ebpf
                .program_mut(name)
                .ok_or_else(|| anyhow::anyhow!("program {name} not found in eBPF object"))?
                .try_into()?;
            prog.load()
                .map_err(|e| anyhow::anyhow!("load {name}: {e}"))?;
            prog.attach(iface, dir)
                .map_err(|e| anyhow::anyhow!("attach {name} to {iface} {dir:?}: {e}"))?;
        }

        Ok(BpfPlane {
            ebpf,
            tun: s.tun_iface.clone(),
            egress_iface: s.egress_iface.clone(),
            box_ip: s.box_ip,
            fwmark: s.fwmark,
            egress_map: Mutex::new(egress_map),
        })
    }
}

impl Drop for BpfPlane {
    fn drop(&mut self) {
        // Nothing to do: dropping `self.ebpf` releases the TCX links, which the
        // kernel uses to detach the programs (fail-open). We do NOT touch `tc`.
        tracing::debug!(
            tun = %self.tun,
            egress = %self.egress_iface,
            "BpfPlane dropping; TCX links released, programs auto-detach"
        );
    }
}

impl DataPlane for BpfPlane {
    fn upstream_socket(
        &self,
        client_ip: Ipv4Addr,
        server: SocketAddrV4,
    ) -> std::io::Result<std::net::TcpStream> {
        let sock = socket2::Socket::new(
            socket2::Domain::IPV4,
            socket2::Type::STREAM,
            Some(socket2::Protocol::TCP),
        )?;
        if self.fwmark != 0 {
            sock.set_mark(self.fwmark)?;
        }
        // Bind box_ip:0 so the kernel assigns the ephemeral port NOW; we must
        // know it (and publish EGRESS) BEFORE connect() so the very first SYN is
        // SNAT'd. (port 0 -> kernel picks one; getsockname reads it back.)
        sock.bind(&SocketAddrV4::new(self.box_ip, 0).into())?;
        let local = sock.local_addr()?;
        let box_port = local
            .as_socket_ipv4()
            .map(|a| a.port())
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::Other, "no ipv4 local addr"))?;

        // Publish EGRESS[box_port] = client_ip (both NBO) before connect().
        {
            let mut map = self
                .egress_map
                .lock()
                .map_err(|_| std::io::Error::new(std::io::ErrorKind::Other, "egress map poisoned"))?;
            if let Err(e) = map.insert(box_port.to_be(), u32::from(client_ip).to_be(), 0) {
                // Log and proceed: the flow just won't be SNAT'd (visible failure).
                tracing::warn!("EGRESS insert failed for box_port={box_port}: {e}");
            }
        }

        sock.connect(&server.into())?;
        sock.set_nonblocking(true)?;
        Ok(sock.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Settings;
    use std::process::Command;

    /// Names of our four classifiers as the kernel reports them via TCX.
    const OUR_PROGS: [&str; 4] = [
        "cls_tun_ingress",
        "cls_tun_egress",
        "cls_eth_ingress",
        "cls_eth_egress",
    ];

    fn run_ip(args: &[&str]) {
        let _ = Command::new("ip").args(args).status();
    }

    /// Count how many of OUR programs the kernel reports attached to a given
    /// (iface, direction) via the TCX query path. Returns the program names.
    fn our_tcx_progs(iface: &str, dir: TcAttachType) -> Vec<String> {
        let (_revision, infos) = SchedClassifier::query_tcx(iface, dir)
            .unwrap_or_else(|e| panic!("query_tcx({iface}, {dir:?}): {e}"));
        infos
            .iter()
            .filter_map(|p| p.name_as_str().map(|s| s.to_string()))
            .filter(|n| OUR_PROGS.contains(&n.as_str()))
            .collect()
    }

    // Privileged: needs root to create the tun/dummy and load+attach eBPF.
    // Run: sudo -E env "PATH=$PATH" cargo test -p mymitm bpf -- --ignored
    #[test]
    #[ignore]
    fn loads_attaches_and_cleans_up() {
        // Clean any leftovers from a prior aborted run, then create temp ifaces.
        run_ip(&["link", "del", "mmtun0"]);
        run_ip(&["link", "del", "mmeth0"]);
        run_ip(&["tuntap", "add", "dev", "mmtun0", "mode", "tun"]);
        run_ip(&["link", "set", "mmtun0", "up"]);
        run_ip(&["link", "add", "mmeth0", "type", "dummy"]);
        run_ip(&["link", "set", "mmeth0", "up"]);

        let s = Settings::from_toml_str(
            r#"
                target_client_ip = "10.8.0.5"
                target_server_ip = "192.168.1.50"
                cert_path = "/x"
                key_path = "/y"
                box_ip = "192.168.1.10"
                tun_iface = "mmtun0"
                egress_iface = "mmeth0"
            "#,
        )
        .expect("settings parse");

        // The four (iface, direction) hooks our programs should occupy.
        let hooks = [
            ("mmtun0", TcAttachType::Ingress, "cls_tun_ingress"),
            ("mmtun0", TcAttachType::Egress, "cls_tun_egress"),
            ("mmeth0", TcAttachType::Ingress, "cls_eth_ingress"),
            ("mmeth0", TcAttachType::Egress, "cls_eth_egress"),
        ];

        {
            let _plane = BpfPlane::load_and_attach(&s).expect("load_and_attach");

            // Assert each hook has exactly our expected program attached (TCX).
            let mut total = 0;
            for (iface, dir, expected) in hooks {
                let progs = our_tcx_progs(iface, dir);
                assert!(
                    progs.iter().any(|n| n == expected),
                    "expected {expected} attached on {iface} {dir:?}, got {progs:?}"
                );
                total += progs.len();
                println!("ATTACH_OK {iface} {dir:?} -> {progs:?}");
            }
            assert_eq!(total, 4, "expected exactly 4 of our programs attached");
            println!("TCX_ATTACH_VERIFIED total={total}");
        } // _plane dropped here -> Ebpf dropped -> TCX links released

        // After drop, none of our programs may remain on any hook.
        let mut remaining = 0;
        for (iface, dir, _expected) in hooks {
            let progs = our_tcx_progs(iface, dir);
            assert!(
                progs.is_empty(),
                "after drop, {iface} {dir:?} still has {progs:?}"
            );
            remaining += progs.len();
            println!("DETACH_OK {iface} {dir:?} -> {progs:?}");
        }
        assert_eq!(remaining, 0, "expected 0 of our programs after drop");
        println!("TCX_DETACH_VERIFIED remaining={remaining}");

        // Teardown temp ifaces.
        run_ip(&["link", "del", "mmtun0"]);
        run_ip(&["link", "del", "mmeth0"]);
    }
}
