mod bpf;
mod config;
mod dataplane;
mod dump;
mod proxy;

use std::sync::Arc;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let settings = config::Settings::load()?;

    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new(&settings.log_level))
        .init();

    tracing::info!(version = mymitm_common::VERSION, "mymitm starting");

    // Ensure the ring CryptoProvider is installed before any TLS use.
    // proxy::ensure_crypto_provider uses a Once guard, so calling it here and
    // inside proxy::run is safe — the second call is a no-op.
    proxy::ensure_crypto_provider();

    let dumper = Arc::new(dump::Dumper::new(&settings.dump_path)?);

    // Load BPF plane (keeps TCX links alive via Drop).
    // Takes &Settings so we can wrap settings in Arc afterwards.
    let _plane = bpf::BpfPlane::load_and_attach(&settings)?;

    tracing::info!("data plane attached; entering proxy loop");

    let settings = Arc::new(settings);
    tokio::select! {
        r = proxy::run(settings.clone(), dumper.clone()) => { r?; }
        _ = shutdown_signal() => { tracing::info!("shutdown signal; detaching"); }
    }

    // _plane drops here → TCX links released → programs auto-detach (fail-open)
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
