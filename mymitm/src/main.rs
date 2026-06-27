mod bpf;
mod config;
mod dataplane;
mod dump;
mod iproute;
mod proxy;

use std::sync::Arc;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let settings = config::Settings::load()?;

    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new(&settings.log_level))
        .init();

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
