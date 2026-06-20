use std::process::Command;

use anyhow::Context as _;
use aya::programs::{tc, SchedClassifier, TcAttachType};

const IFACE: &str = "spike0";

fn sh(cmd: &str) -> anyhow::Result<()> {
    let status = Command::new("sh").arg("-c").arg(cmd).status()?;
    if !status.success() {
        anyhow::bail!("command failed ({status}): {cmd}");
    }
    Ok(())
}

fn sh_ok(cmd: &str) {
    let _ = Command::new("sh").arg("-c").arg(cmd).status();
}

fn main() -> anyhow::Result<()> {
    env_logger::init();

    // 1. Create and bring up a temp tun device.
    sh_ok(&format!("ip link del {IFACE}"));
    sh(&format!("ip tuntap add dev {IFACE} mode tun"))
        .context("create tun")?;
    sh(&format!("ip link set {IFACE} up")).context("set tun up")?;

    // 2. Attach a clsact qdisc (ignore "exists").
    let _ = tc::qdisc_add_clsact(IFACE);

    // 3. Load the embedded eBPF object.
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/spike"
    )))
    .context("load ebpf object")?;

    // 4. Load + attach the SCHED_CLS program to ingress.
    let program: &mut SchedClassifier = ebpf
        .program_mut("spike")
        .context("program 'spike' not found")?
        .try_into()
        .context("program is not a SchedClassifier")?;
    program.load().context("prog.load()")?;
    program
        .attach(IFACE, TcAttachType::Ingress)
        .context("prog.attach()")?;

    println!("ATTACHED_OK");

    // 5. Programmatic proof: on kernel >= 6.6 aya attaches via the TCX link
    //    interface, so the program does NOT appear in `tc filter show`. Query
    //    the kernel's TCX program list for the iface to prove the attach.
    let (revision, prog_infos) = SchedClassifier::query_tcx(IFACE, TcAttachType::Ingress)
        .context("query_tcx")?;
    let summary: Vec<String> = prog_infos
        .iter()
        .map(|p| {
            format!(
                "id={} name={:?} type={:?}",
                p.id(),
                p.name_as_str(),
                p.program_type()
            )
        })
        .collect();
    println!(
        "TCX_QUERY_OK iface={IFACE} ingress revision={revision} attached={} {summary:?}",
        prog_infos.len()
    );
    assert!(
        !prog_infos.is_empty(),
        "no TCX programs attached to {IFACE} ingress"
    );

    // 6. Best-effort host-tool proof (TCX won't show in `tc filter show`;
    //    bpftool may be unavailable for the WSL kernel — non-fatal).
    let bpftool = if std::path::Path::new("/usr/sbin/bpftool").exists() {
        "/usr/sbin/bpftool"
    } else {
        "bpftool"
    };
    println!("--- tc filter show dev {IFACE} ingress (TCX not shown here) ---");
    sh_ok(&format!("tc filter show dev {IFACE} ingress"));
    println!("--- bpftool net show dev {IFACE} (best-effort) ---");
    sh_ok(&format!("{bpftool} net show dev {IFACE} 2>&1 | head -20"));

    Ok(())
}
