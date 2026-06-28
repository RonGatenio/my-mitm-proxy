//! eBPF lifecycle (userspace side).
//!
//! `BpfPlane::load_and_attach` loads the embedded eBPF object with CO-RE
//! (`EbpfLoader` default → relocates against `/sys/kernel/btf/vmlinux`),
//! populates the single-entry `CONFIG` map, and attaches all four classifiers.
//!
//! ## Attach mode: TCX vs legacy clsact+tc (`Settings.attach_mode`)
//! Attachment honors `attach_mode` so the same binary works from kernel 4.15
//! (no TCX) through 6.6+ (TCX):
//!
//! * `Tcx` — force the modern **TCX link** interface
//!   (`attach_with_options(.., TcxOrder(..))`). Requires kernel >= 6.6.
//! * `Tc` — force the legacy **clsact + tc-bpf** path: ensure a `clsact` qdisc
//!   exists on the iface (`tc::qdisc_add_clsact`), then attach the filter via
//!   `attach_with_options(.., Netlink(..))`. Works on 4.x..6.x.
//! * `Auto` (default) — try TCX first; on any error fall back to clsact+tc and
//!   log the fallback.
//!
//! ### Teardown / fail-open semantics — differ by path
//! * **TCX:** links are owned by the process's fds. When `BpfPlane` drops
//!   (normal exit, SIGTERM, even SIGKILL) the kernel releases the links and the
//!   programs detach; traffic reverts to normal forwarding. `Drop` needs no
//!   explicit teardown — dropping the `Ebpf` is sufficient.
//! * **Legacy tc:** netlink/tc filters do **not** auto-detach when the process
//!   dies, and the `clsact` qdisc we added stays behind. So when the tc path was
//!   used (`used_tc`), `Drop` must (a) detach our four filters by name via
//!   `tc::qdisc_detach_program`, and (b) remove the `clsact` qdisc entirely so
//!   traffic reverts to normal. aya 0.13 exposes no clsact-*removal* helper
//!   (only `qdisc_add_clsact` and per-name `qdisc_detach_program`), so qdisc
//!   removal shells out to `tc qdisc del dev <iface> clsact`. This is the
//!   tc-mode teardown path only; the TCX path still never touches `tc`.
//!
//! Attachment is verified differently per path: TCX via
//! `SchedClassifier::query_tcx(iface, dir)`; legacy tc via `tc filter show` /
//! presence of the `clsact` qdisc.

use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::Mutex;

use aya::maps::{Array, HashMap as AyaHashMap, MapData};
use aya::programs::tc::{self, NlOptions, TcAttachOptions};
use aya::programs::{SchedClassifier, TcAttachType};
use aya::{Ebpf, EbpfLoader, VerifierLogLevel};
use mymitm_common::Config;

use crate::config::{AttachMode, Settings};
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

/// Owns the loaded eBPF object (and thus the live links). On the TCX path,
/// dropping it detaches every program automatically. On the legacy tc path,
/// `Drop` additionally removes the clsact qdisc/filters (see `used_tc`).
pub struct BpfPlane {
    // Held for the process lifetime purely as an RAII guard: dropping it releases
    // the TCX links and auto-detaches the programs (see Drop). Not read directly.
    #[allow(dead_code)]
    ebpf: Ebpf,
    tun: String,
    egress_iface: String,
    /// True iff at least one classifier was attached via the legacy clsact+tc
    /// path (forced `Tc`, or `Auto` falling back). Drives tc teardown in `Drop`.
    used_tc: bool,
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
        // Detect whether the running kernel supports BTF function annotations
        // (btf_func, added in kernel 4.18). On kernels 4.14–4.17, `is_btf_supported()`
        // returns true (basic BTF works) but `btf_func` is false. Aya then:
        //   (a) sanitises the object's BTF (FUNC→TYPEDEF, FUNC_PROTO→ENUM),
        //   (b) uploads that sanitised BTF to the kernel (succeeds),
        //   (c) sets prog_btf_fd + func_info in BPF_PROG_LOAD.
        // The kernel rejects BPF_PROG_LOAD because func_info type_ids now resolve to
        // TYPEDEF (not FUNC), returning EINVAL with an empty verifier log.
        //
        // Fix: when btf_func is not supported, zero out the .BTF and .BTF.ext sections
        // from the in-memory ELF bytes before handing them to EbpfLoader. This prevents
        // aya from ever finding func_info. Our object has NO CO-RE relocations, so
        // stripping BTF is safe — the programs load and run identically without it.
        let btf_func_ok = aya::features().btf().map(|f| f.btf_func()).unwrap_or(false);

        const EBPF_OBJ: &[u8] = aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/mymitm"));
        let obj_bytes: std::borrow::Cow<'static, [u8]> = if !btf_func_ok {
            tracing::info!(
                "kernel does not support btf_func; stripping .BTF/.BTF.ext from eBPF object \
                 (safe: no CO-RE in our object)"
            );
            std::borrow::Cow::Owned(strip_btf_sections(EBPF_OBJ))
        } else {
            std::borrow::Cow::Borrowed(EBPF_OBJ)
        };

        // VerifierLogLevel::VERBOSE gives us the full verifier log on load failures
        // (important for old kernels where the error message may otherwise be empty).
        let mut ebpf = EbpfLoader::new()
            .verifier_log_level(VerifierLogLevel::VERBOSE)
            .load(&obj_bytes)?;

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

        // Load + attach the four classifiers honoring `attach_mode`. Track
        // whether any attach used the legacy tc path so Drop knows to tear down
        // the clsact qdisc (the TCX path auto-detaches and needs no teardown).
        let mut used_tc = false;
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
            used_tc |= attach_one(prog, iface, dir, s.attach_mode)
                .map_err(|e| anyhow::anyhow!("attach {name}: {e}"))?;
        }

        Ok(BpfPlane {
            ebpf,
            tun: s.tun_iface.clone(),
            egress_iface: s.egress_iface.clone(),
            used_tc,
            box_ip: s.box_ip,
            fwmark: s.fwmark,
            egress_map: Mutex::new(egress_map),
        })
    }
}

/// Attach one classifier honoring the requested mode. Returns `true` if it was
/// attached via the legacy clsact/tc path (so `Drop` knows to remove the qdisc).
///
/// * `Tcx` — force the TCX link interface (kernel >= 6.6). Fails on old kernels,
///   which is intended.
/// * `Tc` — ensure the clsact qdisc exists, then attach via legacy netlink/tc.
/// * `Auto` — try TCX first; on error fall back to clsact+tc (logged).
fn attach_one(
    prog: &mut SchedClassifier,
    iface: &str,
    dir: TcAttachType,
    mode: AttachMode,
) -> anyhow::Result<bool> {
    match mode {
        AttachMode::Tcx => {
            prog.attach_with_options(iface, dir, TcAttachOptions::TcxOrder(Default::default()))
                .map_err(|e| anyhow::anyhow!("tcx attach {iface} {dir:?}: {e}"))?;
            Ok(false)
        }
        AttachMode::Tc => {
            attach_tc(prog, iface, dir)?;
            Ok(true)
        }
        AttachMode::Auto => {
            match prog.attach_with_options(iface, dir, TcAttachOptions::TcxOrder(Default::default()))
            {
                Ok(_) => Ok(false),
                Err(e) => {
                    tracing::warn!(
                        "TCX attach failed ({e}); falling back to clsact+tc on {iface} {dir:?}"
                    );
                    attach_tc(prog, iface, dir)?;
                    Ok(true)
                }
            }
        }
    }
}

/// Ensure a clsact qdisc exists on `iface`, then attach `prog` via legacy
/// netlink/tc. The `qdisc_add_clsact` is idempotent in effect — an existing
/// clsact yields `EEXIST`, which we deliberately ignore.
fn attach_tc(prog: &mut SchedClassifier, iface: &str, dir: TcAttachType) -> anyhow::Result<()> {
    // Best-effort: ignore "exists". A real failure surfaces at attach time.
    let _ = tc::qdisc_add_clsact(iface);
    prog.attach_with_options(iface, dir, TcAttachOptions::Netlink(NlOptions::default()))
        .map_err(|e| anyhow::anyhow!("tc attach {iface} {dir:?}: {e}"))?;
    Ok(())
}

/// Names of our four classifiers, used for by-name tc filter detach.
const PROGRAM_NAMES: [&str; 4] = [
    "cls_tun_ingress",
    "cls_tun_egress",
    "cls_eth_ingress",
    "cls_eth_egress",
];

const _: () = assert!(PROGRAM_NAMES.len() == PROGRAMS.len());

/// Remove the clsact qdisc (and thus all its filters) from `iface` on the legacy
/// tc path. First detaches our four filters by name via aya (best-effort), then
/// removes the clsact qdisc entirely. aya 0.13 has no clsact-removal helper, so
/// the qdisc deletion shells out to `tc qdisc del dev <iface> clsact`. Errors are
/// logged, not propagated: teardown is always best-effort (fail-open).
fn teardown_tc(iface: &str) {
    use std::process::Command;

    // Safe to call even for an interface attached via TCX (no tc filters ever added):
    // all NotFound errors and the "No such file" tc qdisc del failure are swallowed silently.
    // Detach our filters by name on both directions (best-effort). NotFound just
    // means it was never attached / already gone.
    for dir in [TcAttachType::Ingress, TcAttachType::Egress] {
        for name in PROGRAM_NAMES {
            match tc::qdisc_detach_program(iface, dir, name) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => tracing::warn!("detach {name} on {iface} {dir:?} failed: {e}"),
            }
        }
    }

    // Remove the clsact qdisc entirely so traffic reverts to normal forwarding.
    // No aya API exists for this; shell out for the removal only.
    match Command::new("tc")
        .args(["qdisc", "del", "dev", iface, "clsact"])
        .output()
    {
        Ok(out) if out.status.success() => {}
        Ok(out) => {
            // "RTNETLINK answers: No such file or directory" => no clsact to
            // remove, which is the desired end state; log others at debug.
            tracing::debug!(
                "tc qdisc del clsact on {iface}: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }
        Err(e) => tracing::warn!("failed to run `tc qdisc del dev {iface} clsact`: {e}"),
    }
}

/// Best-effort removal of any clsact qdisc/filters this tool may have left on the
/// given interfaces after an unclean exit. Safe to call when nothing is attached
/// (used by the `--cleanup` flow). The TCX path leaves nothing behind, so this is
/// a no-op there; it only matters on hosts that used the legacy tc path.
pub fn cleanup_tc(tun: &str, egress: &str) {
    for iface in [tun, egress] {
        teardown_tc(iface);
    }
}

impl Drop for BpfPlane {
    fn drop(&mut self) {
        if self.used_tc {
            // Legacy tc path: filters do NOT auto-detach and the clsact qdisc we
            // added stays behind. Remove the clsact qdisc (and its filters) on
            // each iface so traffic reverts to normal forwarding (fail-open).
            teardown_tc(&self.tun);
            teardown_tc(&self.egress_iface);
            tracing::debug!(
                tun = %self.tun,
                egress = %self.egress_iface,
                "BpfPlane (tc) dropped; clsact qdisc removed"
            );
        } else {
            // TCX path: dropping `self.ebpf` releases the links, which the kernel
            // uses to detach the programs (fail-open). We do NOT touch `tc`.
            tracing::debug!(
                tun = %self.tun,
                egress = %self.egress_iface,
                "BpfPlane (TCX) dropped; links released, programs auto-detach"
            );
        }
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
        //
        // Lifecycle note: we INSERT here and do NOT delete on connection close.
        // Correctness relies on:
        //   (1) this insert happening before connect(), so cls_eth_egress sees the
        //       correct client IP for the very first SYN on this ephemeral port;
        //   (2) port-reuse: when the OS reuses a port for a new connection, this
        //       insert overwrites the stale entry before the new SYN is sent;
        //   (3) the 1024-entry LRU bounding the map (self-eviction on insert).
        //
        // Caveat: if this insert FAILS (logged warn below), a stale entry for a
        // reused box_port could cause that new flow to be SNATted to the previous
        // client's IP. Delete-on-close would convert that from "wrong SNAT IP" to
        // "no SNAT" instead — recorded as a known follow-up (see spec).
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

/// Return a copy of the ELF bytes with the `.BTF` and `.BTF.ext` sections
/// zeroed out. Used on kernels where basic BTF is available but `btf_func` is
/// not (e.g. 4.14–4.17): aya normally sanitises the object BTF and then passes
/// `prog_btf_fd + func_info` to BPF_PROG_LOAD, which the kernel rejects because
/// after sanitisation `func_info` type_ids resolve to TYPEDEF (not FUNC).
/// Zeroing these sections hides them from aya's ELF parser; aya then skips the
/// entire BTF upload and BPF_PROG_LOAD succeeds. Since our object has no CO-RE
/// relocations this is a no-op for correctness.
fn strip_btf_sections(elf: &[u8]) -> Vec<u8> {
    use object::{File, Object, ObjectSection};
    let mut out = elf.to_vec();
    // Best-effort: if we can't parse the ELF (shouldn't happen), return a copy
    // and let aya error with its own message.
    if let Ok(obj) = File::parse(elf as &[u8]) {
        for section in obj.sections() {
            if let Ok(name) = section.name() {
                if name == ".BTF" || name == ".BTF.ext" {
                    let (off, size) = (section.file_range().unwrap_or((0, 0)));
                    let start = off as usize;
                    let end = start + size as usize;
                    if end <= out.len() {
                        out[start..end].fill(0);
                    }
                }
            }
        }
    }
    out
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

    // Privileged: forces the legacy clsact+tc attach path and proves the qdisc is
    // added while attached and REMOVED on drop (tc-mode teardown / fail-open).
    // Run: sudo -E env "PATH=$PATH" cargo test -p mymitm tc_mode -- --ignored --nocapture
    #[test]
    #[ignore]
    fn tc_mode_attaches_and_removes_clsact() {
        // Clean any leftovers, then create temp ifaces.
        run_ip(&["link", "del", "mmtun0"]);
        run_ip(&["link", "del", "mmeth0"]);
        run_ip(&["tuntap", "add", "dev", "mmtun0", "mode", "tun"]);
        run_ip(&["link", "set", "mmtun0", "up"]);
        run_ip(&["link", "add", "mmeth0", "type", "dummy"]);
        run_ip(&["link", "set", "mmeth0", "up"]);

        let s = Settings::from_toml_str(
            r#"
                target_server_ip = "192.168.1.50"
                cert_path = "/x"
                key_path = "/y"
                box_ip = "192.168.1.10"
                tun_iface = "mmtun0"
                egress_iface = "mmeth0"
                attach_mode = "tc"
            "#,
        )
        .expect("settings parse");

        let ifaces = ["mmtun0", "mmeth0"];
        {
            let _plane = BpfPlane::load_and_attach(&s).expect("tc attach");
            // clsact qdisc must be present on both ifaces while attached.
            for iface in ifaces {
                let out = Command::new("tc")
                    .args(["qdisc", "show", "dev", iface])
                    .output()
                    .unwrap();
                assert!(
                    String::from_utf8_lossy(&out.stdout).contains("clsact"),
                    "clsact qdisc expected on {iface} while attached"
                );
            }
            println!("TC_ATTACH_OK");
        } // _plane dropped -> tc teardown removes clsact

        // After drop, the clsact qdisc must be gone on both ifaces.
        for iface in ifaces {
            let out = Command::new("tc")
                .args(["qdisc", "show", "dev", iface])
                .output()
                .unwrap();
            assert!(
                !String::from_utf8_lossy(&out.stdout).contains("clsact"),
                "clsact must be removed on drop for {iface}"
            );
        }
        println!("TC_DETACH_OK");

        run_ip(&["link", "del", "mmtun0"]);
        run_ip(&["link", "del", "mmeth0"]);
    }
}
