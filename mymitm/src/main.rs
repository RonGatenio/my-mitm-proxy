mod bpf;
mod config;
mod dataplane;
mod dump;
mod iproute;
mod proxy;
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
    }

    // Ensure the ring CryptoProvider is installed before any TLS use.
    // proxy::ensure_crypto_provider uses a Once guard, so calling it here and
    // inside proxy::run is safe — the second call is a no-op.
    proxy::ensure_crypto_provider();

    let dumper = Arc::new(dump::Dumper::new(&settings.dump_path)?);

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

async fn shutdown_signal() {
    use tokio::signal::unix::{signal, SignalKind};
    let mut term = signal(SignalKind::terminate()).expect("SIGTERM handler");
    let mut intr = signal(SignalKind::interrupt()).expect("SIGINT handler");
    tokio::select! {
        _ = term.recv() => {}
        _ = intr.recv() => {}
    }
}
