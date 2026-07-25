//! eBPF lifecycle (userspace side).
//!
//! `BpfPlane::load_and_attach` loads the embedded eBPF object, populates the
//! single-entry `CONFIG` map, and attaches all four classifiers.
//!
//! ## No CO-RE / kernel BTF required
//! The object carries **no CO-RE relocations**: all packet access uses fixed
//! byte offsets, and the one kernel-struct read (`__sk_buff.mark`) is against a
//! UAPI-stable ABI struct whose field offsets never move. So no kernel (vmlinux)
//! BTF is needed. `EbpfLoader`'s default still probes `/sys/kernel/btf/vmlinux`,
//! but a missing file is harmless — nothing consumes it, so no relocation step
//! ever runs. The only BTF that can affect the load is the object's *own*
//! `.BTF`/`.BTF.ext`, which is stripped on kernels lacking `btf_func` (see
//! `load_and_attach`).
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
#[derive(Copy, Clone)]
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
    /// When false, do NOT publish the EGRESS entry, so cls_eth_egress finds no
    /// SNAT target and leaves the source IP as box_ip (see `upstream_socket`).
    preserve_src_ip: bool,
    /// EGRESS map: box ephemeral src port (NBO) -> client IP (NBO). Written per
    /// connection just before connect() so cls_eth_egress can SNAT correctly.
    egress_map: Mutex<AyaHashMap<MapData, u16, u32>>,
    /// Restores any kernel sysctls we changed for this plane (route_localnet /
    /// rp_filter) when the plane drops. Held purely as an RAII guard.
    #[allow(dead_code)]
    _sysctls: crate::sysctl::SysctlGuard,
}

/// Load the embedded eBPF object into the kernel: raise `RLIMIT_MEMLOCK`, detect
/// `btf_func` support and strip `.BTF`/`.BTF.ext` when absent, then load with a
/// VERBOSE verifier log. Shared head of `load_and_attach` and `probe_ebpf_support`
/// so the two cannot drift. Returns the loaded (not-yet-attached) object; maps are
/// created here and freed when the returned `Ebpf` drops.
fn load_object() -> anyhow::Result<Ebpf> {
    // Kernels < 5.11 charge BPF map/program memory against RLIMIT_MEMLOCK
    // (5.11+ switched to memcg accounting). Raise it before creating any map,
    // or map creation fails with EPERM on 4.15/5.10 — see raise_memlock_rlimit.
    raise_memlock_rlimit();

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
    let ebpf = EbpfLoader::new()
        .verifier_log_level(VerifierLogLevel::VERBOSE)
        .load(&obj_bytes)?;
    Ok(ebpf)
}

impl BpfPlane {
    /// Load the embedded object, populate `CONFIG`, init aya-log (best-effort),
    /// and attach all four classifiers (TCX or clsact+tc per `attach_mode`).
    pub fn load_and_attach(s: &Settings) -> anyhow::Result<BpfPlane> {
        // Preflight the kernel sysctls the eBPF plane depends on (route_localnet /
        // rp_filter). With manage_sysctls=true this sets+saves them (restored on
        // drop); with =false it fails fast here if they are misconfigured — before
        // we load or attach anything. If a later step errors, this guard drops and
        // restores them automatically.
        let sysctls = crate::sysctl::SysctlGuard::acquire(s)?;

        let mut ebpf = load_object()?;

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

        // One clear line about which attach path was used, instead of a per-hook
        // warning. On kernels < 6.6 the clsact+tc path is expected, not a fault.
        if used_tc {
            tracing::info!("eBPF classifiers attached via clsact+tc (legacy tc path; TCX needs kernel >= 6.6)");
        } else {
            tracing::info!("eBPF classifiers attached via TCX");
        }

        if !s.preserve_src_ip {
            tracing::warn!(
                "source-IP preservation DISABLED (preserve_src_ip=false): upstream flows keep \
                 box_ip {} as their source; the server will see the box IP, not the client IP",
                s.box_ip
            );
        }

        Ok(BpfPlane {
            ebpf,
            tun: s.tun_iface.clone(),
            egress_iface: s.egress_iface.clone(),
            used_tc,
            box_ip: s.box_ip,
            fwmark: s.fwmark,
            preserve_src_ip: s.preserve_src_ip,
            egress_map: Mutex::new(egress_map),
            _sysctls: sysctls,
        })
    }
}

/// Preflight check: confirm the running kernel can load, verify, AND attach our
/// tc-classifiers, before we touch the real interfaces. Runs a full dry-run of the
/// load+attach path against `lo` and tears it down. Returns a stage-tagged error
/// (`[load]` / `[verifier]` / `[attach]`) with an actionable hint if eBPF is
/// unusable on this kernel.
///
/// Safety on `lo`: `CONFIG` is intentionally left unpopulated, so it reads back
/// all-zero; with `server_ip`/`server_port` == 0 the classifiers match no real
/// loopback packet, and every classifier returns `TC_ACT_OK` on all paths — so the
/// momentary attach can neither drop nor rewrite loopback traffic.
pub fn probe_ebpf_support(s: &Settings) -> anyhow::Result<()> {
    let krel = kernel_release();

    // Stage 1: load — memlock, (maybe) BTF strip, EbpfLoader::load, map creation.
    let mut ebpf = load_object().map_err(|e| {
        anyhow::anyhow!(
            "eBPF unusable [load]: {e}. Kernel may lack CONFIG_BPF_SYSCALL or BTF support."
        )
    })?;

    // Stage 2: verifier — load ALL four classifiers so this kernel's verifier is
    // exercised against every program (attach below only exercises one).
    for (name, _, _) in PROGRAMS {
        let prog: &mut SchedClassifier = ebpf
            .program_mut(name)
            .ok_or_else(|| anyhow::anyhow!("program {name} not found in eBPF object"))?
            .try_into()?;
        prog.load().map_err(|e| {
            anyhow::anyhow!(
                "eBPF unusable [verifier]: program {name} rejected on kernel {krel}: {e}"
            )
        })?;
    }

    // Stage 3: attach — one classifier to `lo`, honoring attach_mode (Auto tries
    // TCX then falls back to clsact+tc, reproducing the real path). This is where a
    // missing cls_bpf / clsact surfaces.
    let prog: &mut SchedClassifier = ebpf
        .program_mut("cls_tun_ingress")
        .ok_or_else(|| anyhow::anyhow!("program cls_tun_ingress not found in eBPF object"))?
        .try_into()?;
    let used_tc = attach_one(prog, "lo", TcAttachType::Ingress, s.attach_mode).map_err(|e| {
        anyhow::anyhow!(
            "eBPF unusable [attach]: tc/clsact attach on lo failed: {e}. {}",
            diagnose_attach_failure(&krel)
        )
    })?;

    // Stage 4: teardown. Dropping `ebpf` releases TCX links (auto-detach) and frees
    // the maps; the legacy tc path additionally needs its clsact qdisc removed.
    drop(ebpf);
    if used_tc {
        teardown_tc("lo");
    }

    tracing::info!(
        "eBPF support confirmed (kernel {krel}, attach path: {})",
        if used_tc { "tc" } else { "tcx" }
    );
    Ok(())
}

/// What we could determine about a tc feature's kernel module for the *running*
/// kernel — used to explain an `[attach]` failure accurately instead of asserting
/// one cause. The probe only observes "attach failed"; these signals let it say
/// *why*: compiled out vs module-not-installed vs present-but-not-loaded.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum FeatState {
    Loaded,          // in /proc/modules
    BuiltIn,         // modules.builtin, or CONFIG=y
    ModuleInstalled, // a .ko is installed for this kernel (modules.dep) but not loaded
    NotInstalled,    // CONFIG=m but no .ko installed for this kernel
    NotBuilt,        // CONFIG=n
    Absent,          // not loaded/built-in/installed and CONFIG unreadable
    Unknown,         // nothing inspectable (e.g. /lib/modules/<rel> missing)
}

/// Pure classification from gathered signals (no I/O, so it is unit-tested).
fn classify_feature(
    loaded: bool,
    builtin: bool,
    ko_installed: bool,
    cfg: Option<char>,
    moddir_present: bool,
) -> FeatState {
    if loaded {
        return FeatState::Loaded;
    }
    if builtin || cfg == Some('y') {
        return FeatState::BuiltIn;
    }
    if cfg == Some('n') {
        return FeatState::NotBuilt;
    }
    if ko_installed {
        return FeatState::ModuleInstalled;
    }
    if cfg == Some('m') {
        return FeatState::NotInstalled;
    }
    if !moddir_present {
        return FeatState::Unknown;
    }
    FeatState::Absent
}

/// Build the actionable remedy sentence from the two features' states, keyed on
/// the more informative (worst) of the two. Pure, so it is unit-tested.
fn attach_remedy(krel: &str, cls: FeatState, sch: FeatState) -> String {
    use FeatState::*;
    fn rank(s: FeatState) -> u8 {
        match s {
            NotBuilt => 5,
            NotInstalled => 4,
            Absent => 3,
            ModuleInstalled => 2,
            Unknown => 1,
            Loaded | BuiltIn => 0,
        }
    }
    let (worst, which) = if rank(cls) >= rank(sch) {
        (cls, "cls_bpf (CONFIG_NET_CLS_BPF)")
    } else {
        (sch, "clsact/sch_ingress (CONFIG_NET_SCH_INGRESS)")
    };
    match worst {
        NotBuilt => format!(
            "{which} is not built into kernel {krel} (=n). eBPF tc mode is unavailable here — \
             rerun with --data-plane iproute."
        ),
        NotInstalled => format!(
            "{which} is a module (=m) but no matching .ko is installed for kernel {krel}. \
             Install the kernel modules (e.g. linux-modules-extra-{krel}) and retry, or rerun \
             with --data-plane iproute."
        ),
        Absent => format!(
            "{which} is unavailable for kernel {krel} (not built-in, no module .ko found, and \
             CONFIG unreadable). Install this kernel's modules, or rerun with --data-plane iproute."
        ),
        ModuleInstalled => format!(
            "{which} module exists under /lib/modules/{krel} but did not load (blacklisted or \
             signature-rejected?). Try 'modprobe cls_bpf sch_ingress', or rerun with \
             --data-plane iproute."
        ),
        Unknown => format!(
            "could not inspect kernel modules for {krel} (is /lib/modules/{krel} present?). If \
             tc-BPF is unavailable, rerun with --data-plane iproute."
        ),
        Loaded | BuiltIn => format!(
            "cls_bpf and clsact appear available on kernel {krel}, yet the tc attach was rejected \
             — possibly a different kernel limitation. Rerun with --data-plane iproute."
        ),
    }
}

fn module_loaded(name: &str) -> bool {
    std::fs::read_to_string("/proc/modules")
        .map(|s| s.lines().any(|l| l.split_whitespace().next() == Some(name)))
        .unwrap_or(false)
}

fn module_builtin(krel: &str, name: &str) -> bool {
    std::fs::read_to_string(format!("/lib/modules/{krel}/modules.builtin"))
        .map(|s| s.lines().any(|l| l.contains(&format!("/{name}.ko"))))
        .unwrap_or(false)
}

fn module_ko_installed(krel: &str, name: &str) -> bool {
    // modules.dep lines look like `kernel/net/sched/cls_bpf.ko: <deps>` (the .ko
    // may carry a compression suffix, e.g. `.ko.xz`). Match the basename.
    std::fs::read_to_string(format!("/lib/modules/{krel}/modules.dep"))
        .map(|s| {
            s.lines().any(|l| {
                l.split(':')
                    .next()
                    .unwrap_or("")
                    .rsplit('/')
                    .next()
                    .and_then(|f| f.strip_prefix(name))
                    .is_some_and(|r| r.starts_with(".ko"))
            })
        })
        .unwrap_or(false)
}

/// CONFIG_* value ('y'/'m'/'n') from `/boot/config-<krel>` when present, else None.
/// (`/proc/config.gz` would need a gzip decoder; a distro kernel usually ships
/// `/boot/config-*`, and when neither exists the module-file signals still apply.)
fn config_value(krel: &str, symbol: &str) -> Option<char> {
    let text = std::fs::read_to_string(format!("/boot/config-{krel}")).ok()?;
    for line in text.lines() {
        if let Some(v) = line.strip_prefix(&format!("{symbol}=")) {
            return v.chars().next();
        }
        if line == format!("# {symbol} is not set") {
            return Some('n');
        }
    }
    None
}

fn feature_state(krel: &str, module: &str, symbol: &str) -> FeatState {
    let moddir_present = std::path::Path::new(&format!("/lib/modules/{krel}")).is_dir();
    classify_feature(
        module_loaded(module),
        module_builtin(krel, module),
        module_ko_installed(krel, module),
        config_value(krel, symbol),
        moddir_present,
    )
}

/// Best-effort inspection of the running kernel to explain WHY the tc attach
/// failed, returning a remedy sentence. Never fails (all reads are best-effort);
/// distinguishes compiled-out (=n) from module-not-installed from
/// present-but-not-loaded so the hint points at the right fix.
fn diagnose_attach_failure(krel: &str) -> String {
    let cls = feature_state(krel, "cls_bpf", "CONFIG_NET_CLS_BPF");
    let sch = feature_state(krel, "sch_ingress", "CONFIG_NET_SCH_INGRESS");
    attach_remedy(krel, cls, sch)
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
                    // Expected on kernels < 6.6 (no TCX): quietly fall back. Logged
                    // at DEBUG per-hook — otherwise this warns once per (iface,dir),
                    // i.e. 4x, which reads as a failure when it is the normal path.
                    // load_and_attach emits a single INFO summary of the path used.
                    tracing::debug!(
                        "TCX attach unavailable ({e}); using clsact+tc on {iface} {dir:?}"
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
        for (name, _, _) in PROGRAMS {
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
        //
        // When preserve_src_ip is false we deliberately DO NOT publish the entry:
        // cls_eth_egress then finds no EGRESS[box_port] and returns TC_ACT_OK,
        // leaving the source as box_ip. The socket is already bound to box_ip, so
        // the upstream flow simply egresses with the box's own IP — standard
        // proxy behavior, and the negative control for source-IP preservation.
        if self.preserve_src_ip {
            let mut map = self
                .egress_map
                .lock()
                .map_err(|_| std::io::Error::new(std::io::ErrorKind::Other, "egress map poisoned"))?;
            if let Err(e) = map.insert(box_port.to_be(), u32::from(client_ip).to_be(), 0) {
                // Log and proceed: the flow just won't be SNAT'd (visible failure).
                tracing::warn!("EGRESS insert failed for box_port={box_port}: {e}");
            }
        } else {
            tracing::debug!(
                "preserve_src_ip=false: not publishing EGRESS[{box_port}] -> client {client_ip}; \
                 flow keeps box_ip {} as source",
                self.box_ip
            );
        }

        sock.connect(&server.into())?;
        sock.set_nonblocking(true)?;
        Ok(sock.into())
    }
}

/// Raise `RLIMIT_MEMLOCK` to infinity for this process.
///
/// On kernels **< 5.11**, BPF map and program memory is charged against
/// `RLIMIT_MEMLOCK`; 5.11+ switched to memory-cgroup accounting. The default
/// limit is small (a systemd unit inherits ~64 KiB, a login shell ~8 MiB), so on
/// e.g. kernel 4.15 / 5.10 creating our maps fails with EPERM — the exact symptom
/// `failed to create map ... Operation not permitted (os error 1)`. libbpf and
/// older aya bumped this automatically; aya 0.13 leaves it to the caller.
///
/// Best-effort by design: we run as root (`CAP_SYS_RESOURCE`), so this succeeds
/// even under a restrictive systemd `LimitMEMLOCK`; on 5.11+ it is simply a
/// harmless no-op. A failure is logged, not fatal, since the load can still
/// succeed on memcg-accounted kernels.
fn raise_memlock_rlimit() {
    let lim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    // SAFETY: `lim` is a fully-initialised rlimit and RLIMIT_MEMLOCK is a valid
    // resource id; setrlimit reads the struct and does not retain the pointer.
    if unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &lim) } != 0 {
        tracing::warn!(
            "could not raise RLIMIT_MEMLOCK ({}); BPF map creation may fail on kernels < 5.11",
            std::io::Error::last_os_error()
        );
    } else {
        tracing::debug!("RLIMIT_MEMLOCK raised to infinity (needed for BPF on kernels < 5.11)");
    }
}

/// Best-effort kernel release string (e.g. "5.10.0-21-amd64") via `uname(2)`, for
/// diagnostics. Returns "unknown" if the syscall fails. `libc` is already a dep.
fn kernel_release() -> String {
    // SAFETY: `uts` is a POD struct that `uname` fully fills on success; we read
    // the NUL-terminated `release` field only after checking the return code.
    unsafe {
        let mut uts: libc::utsname = std::mem::zeroed();
        if libc::uname(&mut uts) != 0 {
            return "unknown".to_string();
        }
        std::ffi::CStr::from_ptr(uts.release.as_ptr())
            .to_string_lossy()
            .into_owned()
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
                    let (off, size) = section.file_range().unwrap_or((0, 0));
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

    /// Names of our four classifiers as the kernel reports them via TCX, derived
    /// from the single `PROGRAMS` source of truth (no duplicate list).
    fn our_prog_names() -> [&'static str; 4] {
        PROGRAMS.map(|(name, _, _)| name)
    }

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
            .filter(|n| our_prog_names().contains(&n.as_str()))
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

    // Privileged: the preflight probe must succeed on a kernel that supports our
    // data plane, and must leave NO clsact qdisc behind on `lo` (teardown check).
    // Run: sudo -E env "PATH=$PATH" cargo test -p mymitm probe -- --ignored --nocapture
    #[test]
    #[ignore]
    fn probe_reports_support_and_leaves_lo_clean() {
        let s = Settings::test_default();
        probe_ebpf_support(&s).expect("probe_ebpf_support should succeed on this kernel");
        // The probe must not leave a clsact qdisc on lo (TCX leaves nothing; the
        // tc path must have torn its qdisc down).
        let out = Command::new("tc")
            .args(["qdisc", "show", "dev", "lo"])
            .output()
            .unwrap();
        assert!(
            !String::from_utf8_lossy(&out.stdout).contains("clsact"),
            "probe must leave no clsact qdisc on lo"
        );
        println!("PROBE_OK");
    }

    #[test]
    fn classify_feature_maps_signals() {
        use FeatState::*;
        assert_eq!(classify_feature(true, false, false, None, true), Loaded);
        assert_eq!(classify_feature(false, true, false, None, true), BuiltIn);
        assert_eq!(classify_feature(false, false, false, Some('y'), true), BuiltIn);
        assert_eq!(classify_feature(false, false, false, Some('n'), true), NotBuilt);
        assert_eq!(classify_feature(false, false, true, Some('m'), true), ModuleInstalled);
        assert_eq!(classify_feature(false, false, true, None, true), ModuleInstalled);
        assert_eq!(classify_feature(false, false, false, Some('m'), true), NotInstalled);
        assert_eq!(classify_feature(false, false, false, None, false), Unknown);
        assert_eq!(classify_feature(false, false, false, None, true), Absent);
    }

    #[test]
    fn attach_remedy_picks_actionable_cause() {
        use FeatState::*;
        // Compiled out -> point at iproute, and do NOT suggest modprobe.
        let m = attach_remedy("5.10.0", NotBuilt, ModuleInstalled);
        assert!(m.contains("not built into kernel 5.10.0"), "{m}");
        assert!(m.contains("--data-plane iproute"), "{m}");
        assert!(!m.contains("modprobe"), "compiled-out must not suggest modprobe: {m}");
        // Present but not loaded (our repro / a blacklist) -> suggest modprobe.
        let m = attach_remedy("5.10.260", ModuleInstalled, ModuleInstalled);
        assert!(m.contains("did not load"), "{m}");
        assert!(m.contains("modprobe"), "{m}");
        // =m but no .ko for this kernel -> suggest installing the modules package.
        let m = attach_remedy("5.15.0", NotInstalled, BuiltIn);
        assert!(m.contains("linux-modules-extra-5.15.0"), "{m}");
        assert!(m.contains("no matching .ko"), "{m}");
    }
}
