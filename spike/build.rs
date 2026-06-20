use aya_build::{Package, Toolchain};

fn main() -> anyhow::Result<()> {
    aya_build::build_ebpf(
        [Package {
            name: "spike-ebpf",
            root_dir: "spike-ebpf",
            no_default_features: false,
            features: &[],
        }],
        Toolchain::Nightly,
    )
}
