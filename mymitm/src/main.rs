mod alpn;
mod bpf;
mod config;
mod dataplane;
mod dump;
mod iproute;
mod netns;
mod ntlm;
mod proxy;
mod sysctl;
mod ws;

use std::sync::Arc;

/// Build the layered tracing subscriber from the configured levels. Returns the
/// file-appender worker guard, which must be held for the process lifetime so
/// buffered file-log lines are flushed on exit; it is `None` when file logging is
/// off. Both stdout and file levels default to `off`, so the proxy is silent
/// unless explicitly asked to log (on either sink, independently).
fn init_logging(s: &config::Settings) -> anyhow::Result<Option<tracing_appender::non_blocking::WorkerGuard>> {
    use tracing_subscriber::{fmt, prelude::*, EnvFilter};

    // A level string is "on" unless it is empty or exactly "off".
    fn is_on(level: &str) -> bool {
        !matches!(level.trim().to_ascii_lowercase().as_str(), "" | "off")
    }
    // Parse a level/directive; fall back to "off" (never crash on a typo).
    fn filter(level: &str) -> EnvFilter {
        EnvFilter::try_new(level).unwrap_or_else(|_| EnvFilter::new("off"))
    }

    let stdout_layer = fmt::layer()
        .with_writer(std::io::stdout)
        .with_filter(filter(&s.stdout_log_level));

    let (file_layer, guard) = if is_on(&s.file_log_level) {
        if let Some(dir) = s.log_file.parent() {
            if !dir.as_os_str().is_empty() {
                std::fs::create_dir_all(dir).ok();
            }
        }
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&s.log_file)
            .map_err(|e| anyhow::anyhow!("open log file {:?}: {e}", s.log_file))?;
        let (nb, guard) = tracing_appender::non_blocking(file);
        let layer = fmt::layer()
            .with_ansi(false)
            .with_writer(nb)
            .with_filter(filter(&s.file_log_level));
        (Some(layer), Some(guard))
    } else {
        (None, None)
    };

    tracing_subscriber::registry()
        .with(stdout_layer)
        .with(file_layer)
        .init();

    Ok(guard)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let settings = config::Settings::load()?;

    // Held to end of main so the file-log worker flushes on exit (None if off).
    let _log_guard = init_logging(&settings)?;

    tracing::info!(version = mymitm_common::VERSION, "mymitm starting");

    if settings.cleanup {
        tracing::info!("--cleanup: reversing any leftover data-plane state");
        bpf::cleanup_tc(&settings.tun_iface, &settings.egress_iface);
        iproute::cleanup(&settings);
        netns::cleanup(&settings);
    }

    // Namespace mode: plumb the host side, then re-exec ourselves INSIDE the
    // namespace and supervise that child. Everything below this point runs in
    // the child (which is invoked with --netns=false). Must come before any
    // data-plane work, since the child is the one that owns the data plane.
    if settings.netns {
        return run_netns_supervisor(&settings).await;
    }

    // Ensure the ring CryptoProvider is installed before any TLS use.
    // proxy::ensure_crypto_provider uses a Once guard, so calling it here and
    // inside proxy::run is safe — the second call is a no-op.
    proxy::ensure_crypto_provider();

    let dumper = Arc::new(dump::Dumper::new(
        &settings.dump_path,
        dump::DumpOptions {
            raw_dump: settings.raw_dump,
            ntlm_dump: settings.ntlm_dump,
            server_name: settings.server_name.clone(),
        },
    )?);

    // Build the chosen data plane. The concrete plane holds all kernel state
    // (TCX/tc links, policy routes, rules) and reverses it in its Drop impl.
    //
    // We store it as `Arc<dyn DataPlane>` directly. The single Arc is cloned
    // into `proxy::run`; when `main` returns after the select!, both the local
    // `plane` and any clones inside the proxy have dropped, running the concrete
    // Drop exactly once (the last Arc to drop). No Box<dyn Any> guard is needed:
    // holding the local `plane` Arc to end-of-main is sufficient because there
    // is no separate concrete Arc that could drop early.
    use crate::dataplane::DataPlane;
    let plane: Arc<dyn DataPlane> = match settings.data_plane {
        config::DataPlaneKind::Ebpf => {
            // Preflight: confirm eBPF is usable on this kernel and fail fast with a
            // stage-tagged diagnostic if not (skipped by --verify-bpf-support=false).
            if settings.verify_bpf_support {
                bpf::probe_ebpf_support(&settings)?;
            }
            Arc::new(bpf::BpfPlane::load_and_attach(&settings)?)
        }
        config::DataPlaneKind::IpRoute => {
            Arc::new(iproute::IpRoutePlane::setup(&settings)?)
        }
    };

    tracing::info!(?settings.data_plane, "data plane active; entering proxy loop");

    let settings = Arc::new(settings);
    tokio::select! {
        r = proxy::run(settings.clone(), dumper.clone(), plane.clone()) => { r?; }
        _ = shutdown_signal() => { tracing::info!("shutdown signal; detaching"); }
    }

    // `plane` (and the clone inside proxy::run, which exits at select! end)
    // both drop here → concrete plane Drop tears down all kernel state.
    drop(plane);
    Ok(())
}

/// Namespace mode's parent half: build the host-side plumbing, run a copy of
/// ourselves inside the namespace, and tear the plumbing down when it exits.
///
/// The parent deliberately stays in the host namespace. `setns` in-process is
/// perfectly viable — done from a plain single-threaded `main` before the runtime
/// starts, there is only one thread to move — so the reason is not thread safety
/// but **teardown ownership**: the plumbing (veths, policy rules, routing tables)
/// lives in the HOST namespace, and a process that has moved into the namespace
/// addresses the namespace's tables instead. Keeping a process out here means
/// "whoever owns the host state never left the host namespace", which survives
/// the child panicking, crashing, or being SIGKILLed; only killing this parent
/// leaks. An in-process variant is possible (spawn a cleanup thread before
/// `setns`, since threads created earlier stay in the host namespace) and would
/// buy a single PID — better systemd MAINPID/Restart semantics — at the cost of
/// more exit paths that can leak.
///
/// The child is `ip netns exec <ns> <self> <our argv> --netns=false --tun … `, so
/// the code inside the namespace is the same, already-validated path that runs
/// when namespace mode is off — only the interface names differ.
/// How long the supervised child gets to exit on SIGTERM before it is SIGKILLed.
/// Comfortably inside systemd's default `TimeoutStopSec=90s`, so the escalation is
/// ours and the guard's teardown always runs.
const CHILD_STOP_GRACE: std::time::Duration = std::time::Duration::from_secs(10);

async fn run_netns_supervisor(settings: &config::Settings) -> anyhow::Result<()> {
    // Fail fast if this box's FORWARD permission is pinned to interfaces that the
    // namespace's veths cannot match; starting anyway would blackhole silently.
    netns::preflight(settings)?;

    let (guard, inner) = netns::NetnsGuard::setup(settings)?;

    let exe = std::env::current_exe()?;
    let argv: Vec<String> = std::env::args().collect();
    let child_args = netns::child_argv(&argv, &inner);

    let mut cmd = tokio::process::Command::new("ip");
    cmd.args(["netns", "exec", guard.ns()]);
    cmd.arg(&exe);
    cmd.args(&child_args[1..]); // argv[0] is replaced by the resolved exe path
    // If this supervisor dies unexpectedly, don't leave the child running with
    // plumbing that is about to disappear underneath it.
    cmd.kill_on_drop(true);

    tracing::info!(
        ns = guard.ns(),
        tun = %inner.tun_iface,
        egress = %inner.egress_iface,
        box_ip = %inner.box_ip,
        "netns mode: starting the data plane inside the namespace"
    );

    let mut child = cmd
        .spawn()
        .map_err(|e| anyhow::anyhow!("failed to run `ip netns exec {}`: {e}", guard.ns()))?;

    let status = tokio::select! {
        r = child.wait() => r?,
        _ = shutdown_signal() => {
            tracing::info!("shutdown signal; stopping the namespaced data plane");
            // SIGTERM, not kill: the child's Drop impls must run so the
            // classifiers detach and the in-namespace sysctls are restored.
            if let Some(pid) = child.id() {
                unsafe { libc::kill(pid as libc::pid_t, libc::SIGTERM) };
            }
            // Bounded. An unbounded wait here is a trap: a child that ignores
            // SIGTERM or wedges on shutdown keeps this parent alive until the
            // service manager's own timeout SIGKILLs *us*, and then the guard's
            // Drop never runs — leaving the steer rules installed and the box
            // blackholed until someone runs --cleanup. Escalating ourselves keeps
            // teardown in the hands of the process that owns the host state.
            match tokio::time::timeout(CHILD_STOP_GRACE, child.wait()).await {
                Ok(r) => r?,
                Err(_) => {
                    tracing::warn!(
                        secs = CHILD_STOP_GRACE.as_secs(),
                        "the namespaced data plane did not exit after SIGTERM; sending SIGKILL so \
                         the host plumbing is still torn down (in-namespace state goes with the \
                         namespace)"
                    );
                    child.start_kill()?;
                    child.wait().await?
                }
            }
        }
    };

    // Drop order matters: the child is gone, so nothing is using the veths when
    // the guard reverses the plumbing.
    drop(guard);

    if !status.success() {
        anyhow::bail!("namespaced data plane exited with {status}");
    }
    Ok(())
}

async fn shutdown_signal() {
    use tokio::signal::unix::{signal, SignalKind};
    let mut term = signal(SignalKind::terminate()).expect("SIGTERM handler");
    let mut intr = signal(SignalKind::interrupt()).expect("SIGINT handler");
    tokio::select! {
        _ = term.recv() => {}
        _ = intr.recv() => {}
    }
}
