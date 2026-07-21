//! Build script: compile the out-of-tree `mymitm-ebpf` crate to BPF bytecode and
//! embed the resulting object so the userspace loader can `include_bytes_aligned!`
//! it at `concat!(env!("OUT_DIR"), "/mymitm")`.
//!
//! ## Why not `aya_build::build_ebpf` directly
//! The Task 1 spike used `aya_build::build_ebpf`, but it kept the eBPF crate as a
//! *workspace member*. Here `mymitm-ebpf` is deliberately out-of-tree (it has its
//! own `[workspace]` and a `bpfel-unknown-none` default target), so it is NOT a
//! member of the root workspace. `aya_build` shells out to
//! `rustup run nightly cargo build --package mymitm-ebpf ...`, and `--package`
//! resolves only against the *current* workspace — which cannot see
//! `mymitm-ebpf`, so it fails with "package ID specification did not match".
//!
//! This build.rs reproduces aya-build 0.1.3's exact invocation but drives the
//! eBPF crate by its own `--manifest-path` instead of `--package`, then copies
//! the emitted binary artifact into `$OUT_DIR/mymitm` (the eBPF `[[bin]]` name).
//! The compile flags (`-Z build-std=core`, `--cfg=bpf_target_arch`, `--btf`,
//! nightly via `rustup run`) match aya-build verbatim so CO-RE BTF is emitted.

use std::{
    env,
    ffi::OsString,
    fs,
    io::{BufRead as _, BufReader},
    path::PathBuf,
    process::{Child, Command, Stdio},
};

use anyhow::{anyhow, Context as _};

const EBPF_BIN: &str = "mymitm"; // [[bin]] name in mymitm-ebpf/Cargo.toml
const EBPF_MANIFEST: &str = "../mymitm-ebpf/Cargo.toml";

fn main() -> anyhow::Result<()> {
    // Rebuild if the eBPF sources or manifest change.
    println!("cargo:rerun-if-changed=../mymitm-ebpf/src");
    println!("cargo:rerun-if-changed=../mymitm-ebpf/Cargo.toml");
    println!("cargo:rerun-if-changed=../mymitm-common/src");

    let out_dir = PathBuf::from(env::var_os("OUT_DIR").ok_or(anyhow!("OUT_DIR not set"))?);

    // Host endianness selects the BPF target (matches aya-build).
    let endian =
        env::var_os("CARGO_CFG_TARGET_ENDIAN").ok_or(anyhow!("CARGO_CFG_TARGET_ENDIAN not set"))?;
    let target = if endian == "little" {
        "bpfel-unknown-none"
    } else if endian == "big" {
        "bpfeb-unknown-none"
    } else {
        return Err(anyhow!("unsupported endian={endian:?}"));
    };

    // BPF target arch for `--cfg=bpf_target_arch="..."` (aya-ebpf needs it).
    let bpf_target_arch = env::var("CARGO_CFG_TARGET_ARCH")
        .context("CARGO_CFG_TARGET_ARCH not set")?;
    let bpf_target_arch = if bpf_target_arch.starts_with("riscv64") {
        "riscv64".to_string()
    } else {
        bpf_target_arch
    };

    // Give the eBPF build its own target-dir under OUT_DIR to avoid cargo flock
    // contention with the outer build (aya-build does the same).
    let ebpf_target_dir = out_dir.join("ebpf-build");

    let mut cmd = Command::new("rustup");
    cmd.args([
        "run",
        "nightly",
        "cargo",
        "build",
        "--manifest-path",
        EBPF_MANIFEST,
        "-Z",
        "build-std=core",
        "--bins",
        "--message-format=json",
        "--release",
        "--target",
        target,
    ]);
    cmd.arg("--target-dir").arg(&ebpf_target_dir);

    // Replicate aya-build's CARGO_ENCODED_RUSTFLAGS (0x1f-separated).
    {
        const SEP: &str = "\x1f";
        let mut rustflags = OsString::new();
        for s in [
            "--cfg=bpf_target_arch=\"",
            &bpf_target_arch,
            "\"",
            SEP,
            "-Cdebuginfo=2",
            SEP,
            "-Clink-arg=--btf",
        ] {
            rustflags.push(s);
        }
        cmd.env("CARGO_ENCODED_RUSTFLAGS", rustflags);
    }

    // Ensure the outer crate's wrapper/rustc don't leak into the eBPF build.
    for key in ["RUSTC", "RUSTC_WORKSPACE_WRAPPER", "CARGO_BUILD_TARGET"] {
        cmd.env_remove(key);
    }

    let mut child = cmd
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("failed to spawn {cmd:?}"))?;
    let Child { stdout, stderr, .. } = &mut child;

    // Trampoline eBPF-build stderr to cargo warnings so it's visible.
    let stderr = stderr.take().expect("stderr");
    let stderr = BufReader::new(stderr);
    let stderr_thread = std::thread::spawn(move || {
        for line in stderr.lines() {
            let line = line.expect("read line");
            println!("cargo:warning={line}");
        }
    });

    // Parse JSON build messages to find the emitted binary artifact.
    let stdout = stdout.take().expect("stdout");
    let stdout = BufReader::new(stdout);
    let mut executable: Option<PathBuf> = None;
    for message in cargo_metadata::Message::parse_stream(stdout) {
        match message.expect("valid JSON") {
            cargo_metadata::Message::CompilerArtifact(artifact) => {
                if artifact.target.name == EBPF_BIN {
                    if let Some(exe) = artifact.executable {
                        executable = Some(exe.into_std_path_buf());
                    }
                }
            }
            cargo_metadata::Message::CompilerMessage(msg) => {
                for line in msg.message.rendered.unwrap_or_default().split('\n') {
                    println!("cargo:warning={line}");
                }
            }
            cargo_metadata::Message::TextLine(line) => {
                println!("cargo:warning={line}");
            }
            _ => {}
        }
    }

    let status = child
        .wait()
        .with_context(|| format!("failed to wait for {cmd:?}"))?;
    stderr_thread.join().expect("stderr thread");
    if !status.success() {
        return Err(anyhow!("eBPF build failed: {status:?}"));
    }

    let exe = executable.ok_or_else(|| {
        anyhow!("eBPF build produced no binary artifact named {EBPF_BIN:?}")
    })?;
    let dst = out_dir.join(EBPF_BIN);
    fs::copy(&exe, &dst)
        .with_context(|| format!("failed to copy {exe:?} to {dst:?}"))?;

    Ok(())
}
