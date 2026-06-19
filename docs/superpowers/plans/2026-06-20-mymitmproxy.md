# mymitmproxy Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A single static Rust binary that transparently MITMs TLS between one target client and one target server on an OpenVPN gateway, preserving the client's exact source IP, while leaving zero footprint in `ip route`/`iptables`/`nft`/`ip rule`.

**Architecture:** A tc-eBPF data plane (loaded via aya, CO-RE) does NAT in the kernel: it DNATs the target client→server flow on `tun0` to a local listener, and on `eth0` it SNATs our upstream socket's source to the client IP and un-SNATs the replies before routing. Userspace (tokio + rustls) terminates TLS with the real leaf cert, dumps decrypted bytes, and re-originates TLS upstream over an ordinary kernel socket tagged with `SO_MARK`. The hard packet-rewrite decision logic lives in a `no_std` shared crate so it is unit-testable on the host.

**Tech Stack:** Rust (workspace), aya + aya-ebpf (eBPF, CO-RE), tokio, tokio-rustls + rustls (`ring` provider), clap, serde + toml, anyhow/thiserror. Target `x86_64-unknown-linux-musl`, fully static.

## Global Constraints

- **Language/target:** Rust; build target `x86_64-unknown-linux-musl` with `-C target-feature=+crt-static`. Final binary must be fully static (`ldd` → "not a dynamic executable").
- **rustls crypto provider:** `ring` (not `aws-lc-rs`) — static-musl friendly.
- **No hostname resolution anywhere** — operate on IPs only (musl static-NSS limitation).
- **Config-clean (threat model A):** nothing in `ip route`, `iptables`/`nft`, or `ip rule`; no new visible interface. tc-eBPF footprint (visible to `bpftool`/`tc`) is acceptable.
- **eBPF must use CO-RE** (BTF at `/sys/kernel/btf/vmlinux`).
- **v1 scope:** exactly one target client IP + one target server IP:port. All other traffic untouched by the kernel.
- **Source-IP preservation is mandatory:** the upstream connection to the server must carry the client's exact source IP.
- **Shared map structs are `#[repr(C)]`** in `mymitm-common` and used verbatim by both the eBPF and userspace sides.
- **Map/program names** derive from a configurable `bpf_obj_name` prefix.
- **Dump I/O must never block or crash the proxy path.**

### Environment & command conventions

- The host is Windows; **all build/run/test commands execute inside the WSL2 Ubuntu-24.04 shell** (kernel 6.6, BTF present, `NET_CLS_BPF`/`NET_ACT_BPF` modules available).
- For build speed, clone/work in the **WSL filesystem** (e.g. `~/mymitmproxy`), not `/mnt/c`. The git repo of record is at `C:\projects\mymitmproxy`; mirror commits back (or develop directly in WSL and push).
- Commands below assume the current directory is the repo root inside WSL unless stated.
- Commands that load eBPF, create netns, or set `SO_MARK` need privileges — they are prefixed with `sudo`. Pure unit tests need no privileges.
- One-time toolchain setup (run once, not a task step):
  ```bash
  rustup target add x86_64-unknown-linux-musl
  rustup component add rust-src           # needed to build eBPF crate
  cargo install bpf-linker                  # aya eBPF linker
  sudo apt-get install -y musl-tools iproute2 libpcap-dev
  ```

---

## File structure

```
mymitmproxy/
├── Cargo.toml                      # workspace
├── rust-toolchain.toml             # pin toolchain + components
├── .cargo/config.toml              # musl target default, bpf-linker for ebpf
├── mymitm-common/                  # no_std shared types + rewrite-decision logic
│   ├── Cargo.toml
│   └── src/lib.rs
├── mymitm-ebpf/                    # eBPF programs (compiled to BPF)
│   ├── Cargo.toml
│   └── src/main.rs
├── mymitm/                         # userspace binary
│   ├── Cargo.toml
│   ├── build.rs                    # builds + embeds the eBPF object
│   └── src/
│       ├── main.rs                 # wiring, signals, Drop-guard lifecycle
│       ├── config.rs               # TOML + CLI
│       ├── bpf.rs                  # load/attach/maps/cleanup
│       ├── proxy.rs                # accept→terminate→dial→pump
│       └── dump.rs                 # JSONL index + c2s/s2c streams
└── tests/
    └── integration/
        ├── harness.sh              # netns setup/teardown
        └── e2e.rs                  # end-to-end assertions
```

Responsibilities:
- `mymitm-common` — the only place packet-classification/rewrite decisions and map layouts are defined; `no_std`, unit-tested on host.
- `mymitm-ebpf` — thin kernel glue: read skb, call common decision fn, apply rewrite via BPF helpers.
- `mymitm/bpf.rs` — aya lifecycle only.
- `mymitm/proxy.rs` — TLS + byte pumping only.
- `mymitm/dump.rs` — disk I/O only.
- `mymitm/config.rs` — configuration only.

---

## Task 1: Gating spike — prove tc-eBPF attaches to a `tun` in WSL2

**Goal:** De-risk the entire architecture before writing it. Confirm an aya `SCHED_CLS` program loads with CO-RE and attaches to a `tun` device's clsact qdisc in this WSL2 kernel. **If this fails, stop and provision a Hyper-V/EC2 VM; the rest of the plan runs identically there.**

**Files:**
- Create: `spike/Cargo.toml`, `spike/src/main.rs`, `spike/ebpf/Cargo.toml`, `spike/ebpf/src/main.rs` (throwaway; deleted in Task 2).

- [ ] **Step 1: Create a throwaway tun and confirm tc works at all (no eBPF yet)**

Run:
```bash
sudo ip tuntap add dev spike0 mode tun
sudo ip link set spike0 up
sudo tc qdisc add dev spike0 clsact
sudo tc qdisc show dev spike0
```
Expected: output includes `qdisc clsact`. If `tc qdisc add … clsact` errors with "Unknown qdisc", the `sch_clsact`/`NET_*_BPF` modules aren't loadable here → **VM fallback**.

- [ ] **Step 2: Write a no-op SCHED_CLS eBPF program**

`spike/ebpf/src/main.rs`:
```rust
#![no_std]
#![no_main]

use aya_ebpf::{macros::classifier, programs::TcContext, bindings::TC_ACT_OK};

#[classifier]
pub fn spike(_ctx: TcContext) -> i32 {
    TC_ACT_OK
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
```

- [ ] **Step 3: Write a loader that attaches it to `spike0`**

`spike/src/main.rs`:
```rust
use aya::programs::{tc, SchedClassifier, TcAttachType};

fn main() -> anyhow::Result<()> {
    let mut bpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"), "/spike"
    )))?;
    let _ = tc::qdisc_add_clsact("spike0"); // ignore "exists"
    let prog: &mut SchedClassifier = bpf.program_mut("spike").unwrap().try_into()?;
    prog.load()?;
    prog.attach("spike0", TcAttachType::Ingress)?;
    println!("attached OK; press ctrl-c");
    std::thread::sleep(std::time::Duration::from_secs(3600));
    Ok(())
}
```
(Use the aya project template's `build.rs`/xtask pattern to compile the ebpf crate into `OUT_DIR`. The aya book's "Development environment" + "Hello XDP/classifier" pages are the reference; adapt for `SchedClassifier`.)

- [ ] **Step 4: Build and run the spike**

Run:
```bash
sudo -E $(which cargo) run --manifest-path spike/Cargo.toml
```
Expected: prints `attached OK`. In another shell:
```bash
sudo bpftool prog show | grep -i sched_cls
sudo tc filter show dev spike0 ingress
```
Expected: the program is listed and the filter is attached.

- [ ] **Step 5: Record the result and decide environment**

If attach succeeded → WSL2 is the dev environment; continue. If it failed at Step 1 or Step 4 → document the error in `docs/superpowers/plans/2026-06-20-mymitmproxy.md` under a new "Environment decision" note and provision a VM before Task 2. Either way, tear down:
```bash
sudo tc qdisc del dev spike0 clsact 2>/dev/null; sudo ip link del spike0
```

- [ ] **Step 6: Commit the spike result note (not the throwaway code yet)**

```bash
git add docs/ && git commit -m "chore: tc-eBPF-on-tun spike result (WSL2 vs VM decision)"
```

---

## Task 2: Workspace scaffolding + static-musl build proof

**Goal:** Establish the cargo workspace and prove the userspace binary builds fully static under musl, before any real logic exists.

**Files:**
- Create: `Cargo.toml`, `rust-toolchain.toml`, `.cargo/config.toml`, `mymitm/Cargo.toml`, `mymitm/src/main.rs`, `mymitm-common/Cargo.toml`, `mymitm-common/src/lib.rs`, `mymitm-ebpf/Cargo.toml`, `mymitm-ebpf/src/main.rs`.
- Delete: `spike/` (no longer needed).

**Interfaces:**
- Produces: a buildable workspace with three member crates; `cargo build -p mymitm --target x86_64-unknown-linux-musl` yields a static binary.

- [ ] **Step 1: Write the workspace manifest**

`Cargo.toml`:
```toml
[workspace]
resolver = "2"
members = ["mymitm", "mymitm-common"]
# mymitm-ebpf is built out-of-tree by mymitm/build.rs (different target), not a workspace member.

[workspace.package]
edition = "2021"
license = "proprietary"
```

`rust-toolchain.toml`:
```toml
[toolchain]
channel = "stable"
components = ["rust-src"]
targets = ["x86_64-unknown-linux-musl"]
```

`.cargo/config.toml`:
```toml
[build]
target = "x86_64-unknown-linux-musl"

[target.x86_64-unknown-linux-musl]
rustflags = ["-C", "target-feature=+crt-static"]
```

- [ ] **Step 2: Write minimal crate skeletons**

`mymitm-common/Cargo.toml`:
```toml
[package]
name = "mymitm-common"
version = "0.1.0"
edition = "2021"

[features]
user = []          # gates aya::Pod impls (added in Task 3)

[dependencies]
```

`mymitm-common/src/lib.rs`:
```rust
#![no_std]

pub const VERSION: u32 = 1;
```

`mymitm/Cargo.toml`:
```toml
[package]
name = "mymitm"
version = "0.1.0"
edition = "2021"

[dependencies]
anyhow = "1"
```

`mymitm/src/main.rs`:
```rust
fn main() -> anyhow::Result<()> {
    println!("mymitm v{}", mymitm_common::VERSION);
    Ok(())
}
```
Add `mymitm-common = { path = "../mymitm-common" }` to `mymitm/Cargo.toml` `[dependencies]`.

`mymitm-ebpf/Cargo.toml` and `mymitm-ebpf/src/main.rs`: copy the no-op classifier skeleton from Task 1 Step 2 (kept minimal; real programs come in Tasks 6–7). `mymitm-ebpf` has its own `.cargo/config.toml` setting `target = "bpfel-unknown-none"` and `rustflags` for `bpf-linker` per the aya template.

- [ ] **Step 3: Build and verify static linkage**

Run:
```bash
cargo build -p mymitm
file target/x86_64-unknown-linux-musl/debug/mymitm
ldd target/x86_64-unknown-linux-musl/debug/mymitm
```
Expected: `file` reports `ELF 64-bit ... statically linked`; `ldd` prints `not a dynamic executable`.

- [ ] **Step 4: Run it**

Run: `./target/x86_64-unknown-linux-musl/debug/mymitm`
Expected: prints `mymitm v1`.

- [ ] **Step 5: Remove the spike and commit**

```bash
rm -rf spike
git add -A && git commit -m "chore: cargo workspace + static-musl build proof"
```

---

## Task 3: Shared types and rewrite-decision logic (`mymitm-common`)

**Goal:** Define the `#[repr(C)]` map structs and the pure, `no_std`, unit-tested logic that decides how to rewrite each packet. This is where correctness is locked in and tested without a kernel.

**Files:**
- Modify: `mymitm-common/src/lib.rs`
- Modify: `mymitm-common/Cargo.toml`
- Test: inline `#[cfg(test)]` module in `mymitm-common/src/lib.rs`

**Interfaces:**
- Produces:
  - `struct Config { client_ip: u32, server_ip: u32, box_ip: u32, local_ip: u32, server_port: u16, local_port: u16, fwmark: u32 }` (all IPs/ports in **network byte order**).
  - `struct UpstreamKey { server_ip: u32, client_ip: u32, server_port: u16, client_port: u16 }`
  - `struct UpstreamVal { box_ip: u32, box_port: u16 }`
  - `enum Rewrite { None, DnatToLocal, UnDnatFromLocal, SnatToClient, UnSnatToBox }`
  - `struct PktMeta { src_ip: u32, dst_ip: u32, src_port: u16, dst_port: u16, mark: u32 }`
  - `fn classify_tun(m: &PktMeta, cfg: &Config, egress: bool) -> Rewrite`
  - `fn classify_eth(m: &PktMeta, cfg: &Config, egress: bool) -> Rewrite`
  - All structs are `#[repr(C)]`, `Clone`, `Copy`; under feature `user`, also `unsafe impl aya::Pod`.

- [ ] **Step 1: Write failing tests for the classifiers**

Add to `mymitm-common/src/lib.rs`:
```rust
#[cfg(test)]
mod tests {
    use super::*;
    // helper: build a Config in network byte order
    fn cfg() -> Config {
        Config {
            client_ip: u32::from(core::net::Ipv4Addr::new(10,8,0,5)).to_be(),
            server_ip: u32::from(core::net::Ipv4Addr::new(192,168,1,50)).to_be(),
            box_ip:    u32::from(core::net::Ipv4Addr::new(192,168,1,10)).to_be(),
            local_ip:  u32::from(core::net::Ipv4Addr::new(127,0,0,1)).to_be(),
            server_port: 443u16.to_be(),
            local_port:  8443u16.to_be(),
            fwmark: 0x1337,
        }
    }
    fn meta(s: (&str,u16), d: (&str,u16), mark: u32) -> PktMeta {
        PktMeta {
            src_ip: u32::from(s.0.parse::<core::net::Ipv4Addr>().unwrap()).to_be(),
            dst_ip: u32::from(d.0.parse::<core::net::Ipv4Addr>().unwrap()).to_be(),
            src_port: s.1.to_be(), dst_port: d.1.to_be(), mark,
        }
    }

    #[test]
    fn tun_ingress_target_is_dnatted() {
        let r = classify_tun(&meta(("10.8.0.5",43012),("192.168.1.50",443),0), &cfg(), false);
        assert_eq!(r, Rewrite::DnatToLocal);
    }
    #[test]
    fn tun_ingress_other_client_untouched() {
        let r = classify_tun(&meta(("10.8.0.9",43012),("192.168.1.50",443),0), &cfg(), false);
        assert_eq!(r, Rewrite::None);
    }
    #[test]
    fn tun_egress_reply_is_undnatted() {
        let r = classify_tun(&meta(("127.0.0.1",8443),("10.8.0.5",43012),0), &cfg(), true);
        assert_eq!(r, Rewrite::UnDnatFromLocal);
    }
    #[test]
    fn eth_egress_marked_is_snatted() {
        let r = classify_eth(&meta(("192.168.1.10",51000),("192.168.1.50",443),0x1337), &cfg(), true);
        assert_eq!(r, Rewrite::SnatToClient);
    }
    #[test]
    fn eth_egress_unmarked_untouched() {
        let r = classify_eth(&meta(("192.168.1.10",51000),("192.168.1.50",443),0), &cfg(), true);
        assert_eq!(r, Rewrite::None);
    }
    #[test]
    fn eth_ingress_reply_to_client_is_unsnatted() {
        let r = classify_eth(&meta(("192.168.1.50",443),("10.8.0.5",51000),0), &cfg(), false);
        assert_eq!(r, Rewrite::UnSnatToBox);
    }
}
```

- [ ] **Step 2: Run tests, verify they fail to compile (types missing)**

Run: `cargo test -p mymitm-common`
Expected: FAIL — `cannot find type Config` / `function classify_tun not found`.

- [ ] **Step 3: Implement the types and classifiers**

Replace `mymitm-common/src/lib.rs` body (keep `#![no_std]`, add `extern crate core`):
```rust
#![no_std]

pub const VERSION: u32 = 1;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Config {
    pub client_ip: u32,
    pub server_ip: u32,
    pub box_ip: u32,
    pub local_ip: u32,
    pub server_port: u16,
    pub local_port: u16,
    pub fwmark: u32,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct UpstreamKey {
    pub server_ip: u32,
    pub client_ip: u32,
    pub server_port: u16,
    pub client_port: u16,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct UpstreamVal {
    pub box_ip: u32,
    pub box_port: u16,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Rewrite { None, DnatToLocal, UnDnatFromLocal, SnatToClient, UnSnatToBox }

#[derive(Clone, Copy)]
pub struct PktMeta {
    pub src_ip: u32,
    pub dst_ip: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub mark: u32,
}

pub fn classify_tun(m: &PktMeta, cfg: &Config, egress: bool) -> Rewrite {
    if !egress {
        if m.src_ip == cfg.client_ip && m.dst_ip == cfg.server_ip && m.dst_port == cfg.server_port {
            return Rewrite::DnatToLocal;
        }
    } else if m.src_ip == cfg.local_ip && m.src_port == cfg.local_port && m.dst_ip == cfg.client_ip {
        return Rewrite::UnDnatFromLocal;
    }
    Rewrite::None
}

pub fn classify_eth(m: &PktMeta, cfg: &Config, egress: bool) -> Rewrite {
    if egress {
        if m.mark == cfg.fwmark && m.dst_ip == cfg.server_ip && m.dst_port == cfg.server_port {
            return Rewrite::SnatToClient;
        }
    } else if m.src_ip == cfg.server_ip && m.src_port == cfg.server_port && m.dst_ip == cfg.client_ip {
        return Rewrite::UnSnatToBox;
    }
    Rewrite::None
}
```

- [ ] **Step 4: Run tests, verify pass**

Run: `cargo test -p mymitm-common`
Expected: PASS (6 tests). Note: `cargo test` runs on the host target; add `--target x86_64-unknown-linux-gnu` is unnecessary since tests build for host automatically (the `.cargo/config.toml` default target applies to builds, but `cargo test` of a `no_std`+`std`-test crate works because the `#[cfg(test)]` block links std on host). If the musl default target breaks `cargo test`, run `cargo test -p mymitm-common --target x86_64-unknown-linux-gnu`.

- [ ] **Step 5: Add aya::Pod impls under the `user` feature**

Append to `lib.rs`:
```rust
#[cfg(feature = "user")]
mod pod {
    use super::*;
    unsafe impl aya::Pod for Config {}
    unsafe impl aya::Pod for UpstreamKey {}
    unsafe impl aya::Pod for UpstreamVal {}
}
```
Add to `mymitm-common/Cargo.toml`:
```toml
[dependencies]
aya = { version = "0.13", optional = true }

[features]
user = ["dep:aya"]
```

- [ ] **Step 6: Verify both feature modes build**

Run:
```bash
cargo build -p mymitm-common
cargo build -p mymitm-common --features user --target x86_64-unknown-linux-musl
```
Expected: both succeed.

- [ ] **Step 7: Commit**

```bash
git add -A && git commit -m "feat(common): map structs + unit-tested rewrite classifiers"
```

---

## Task 4: Configuration (`mymitm/config.rs`)

**Goal:** TOML file + CLI overrides, with validation, producing the runtime config and a `mymitm_common::Config` (network byte order) for the eBPF map.

**Files:**
- Create: `mymitm/src/config.rs`
- Modify: `mymitm/src/main.rs` (declare module), `mymitm/Cargo.toml`
- Test: inline `#[cfg(test)]` in `config.rs`

**Interfaces:**
- Consumes: `mymitm_common::Config`.
- Produces:
  - `struct Settings { client_ip: Ipv4Addr, server_ip: Ipv4Addr, server_port: u16, tun_iface: String, egress_iface: String, local_ip: Ipv4Addr, local_port: u16, fwmark: u32, cert_path: PathBuf, key_path: PathBuf, dump_path: PathBuf, bpf_obj_name: String, box_ip: Ipv4Addr, log_level: String }`
  - `impl Settings { fn load() -> anyhow::Result<Settings>; fn to_bpf_config(&self) -> mymitm_common::Config }`

- [ ] **Step 1: Add dependencies**

`mymitm/Cargo.toml` `[dependencies]`:
```toml
clap = { version = "4", features = ["derive"] }
serde = { version = "1", features = ["derive"] }
toml = "0.8"
mymitm-common = { path = "../mymitm-common", features = ["user"] }
```

- [ ] **Step 2: Write failing tests**

`mymitm/src/config.rs` (test module):
```rust
#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn toml_parses_with_defaults() {
        let toml = r#"
            target_client_ip = "10.8.0.5"
            target_server_ip = "192.168.1.50"
            cert_path = "/x/leaf.pem"
            key_path = "/x/leaf.key"
            box_ip = "192.168.1.10"
        "#;
        let s = Settings::from_toml_str(toml).unwrap();
        assert_eq!(s.server_port, 443);          // default
        assert_eq!(s.tun_iface, "tun0");         // default
        assert_eq!(s.fwmark, 0x1337);            // default
        assert_eq!(s.local_port, 8443);          // default
    }

    #[test]
    fn to_bpf_config_is_network_order() {
        let toml = r#"
            target_client_ip = "10.8.0.5"
            target_server_ip = "192.168.1.50"
            cert_path = "/x" key_path = "/y" box_ip = "192.168.1.10"
        "#;
        let s = Settings::from_toml_str(toml).unwrap();
        let c = s.to_bpf_config();
        assert_eq!(c.server_port, 443u16.to_be());
        assert_eq!(c.client_ip, u32::from(Ipv4Addr::new(10,8,0,5)).to_be());
    }

    #[test]
    fn missing_required_field_errors() {
        let toml = r#"target_client_ip = "10.8.0.5""#;
        assert!(Settings::from_toml_str(toml).is_err());
    }
}
```

- [ ] **Step 3: Run tests, verify fail**

Run: `cargo test -p mymitm config --target x86_64-unknown-linux-gnu`
Expected: FAIL — `Settings` / `from_toml_str` not found.

- [ ] **Step 4: Implement config**

`mymitm/src/config.rs` (above the test module):
```rust
use std::net::Ipv4Addr;
use std::path::PathBuf;
use serde::Deserialize;
use clap::Parser;

#[derive(Debug, Clone, Deserialize)]
struct FileCfg {
    target_client_ip: Ipv4Addr,
    target_server_ip: Ipv4Addr,
    cert_path: PathBuf,
    key_path: PathBuf,
    box_ip: Ipv4Addr,
    #[serde(default = "d_port")] target_server_port: u16,
    #[serde(default = "d_tun")] tun_iface: String,
    #[serde(default = "d_eth")] egress_iface: String,
    #[serde(default = "d_local_ip")] local_addr: Ipv4Addr,
    #[serde(default = "d_local_port")] local_port: u16,
    #[serde(default = "d_mark")] fwmark: u32,
    #[serde(default = "d_dump")] dump_path: PathBuf,
    #[serde(default = "d_obj")] bpf_obj_name: String,
    #[serde(default = "d_log")] log_level: String,
}
fn d_port() -> u16 { 443 }
fn d_tun() -> String { "tun0".into() }
fn d_eth() -> String { "eth0".into() }
fn d_local_ip() -> Ipv4Addr { Ipv4Addr::new(127,0,0,1) }
fn d_local_port() -> u16 { 8443 }
fn d_mark() -> u32 { 0x1337 }
fn d_dump() -> PathBuf { "/var/tmp/mitm-dumps/".into() }
fn d_obj() -> String { "mymitm".into() }
fn d_log() -> String { "info".into() }

#[derive(Parser, Debug)]
#[command(version, about = "transparent TLS MITM with source-IP preservation")]
struct Cli {
    /// Path to TOML config
    #[arg(short, long, default_value = "mymitm.toml")]
    config: PathBuf,
    /// Override target client IP
    #[arg(long)] client: Option<Ipv4Addr>,
    /// Override target server IP
    #[arg(long)] server: Option<Ipv4Addr>,
    /// Override tun interface
    #[arg(long)] tun: Option<String>,
    /// Override egress interface
    #[arg(long)] egress: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Settings {
    pub client_ip: Ipv4Addr,
    pub server_ip: Ipv4Addr,
    pub server_port: u16,
    pub tun_iface: String,
    pub egress_iface: String,
    pub local_ip: Ipv4Addr,
    pub local_port: u16,
    pub fwmark: u32,
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
    pub dump_path: PathBuf,
    pub bpf_obj_name: String,
    pub box_ip: Ipv4Addr,
    pub log_level: String,
}

impl Settings {
    pub fn from_toml_str(s: &str) -> anyhow::Result<Settings> {
        let f: FileCfg = toml::from_str(s)?;
        Ok(Settings {
            client_ip: f.target_client_ip,
            server_ip: f.target_server_ip,
            server_port: f.target_server_port,
            tun_iface: f.tun_iface,
            egress_iface: f.egress_iface,
            local_ip: f.local_addr,
            local_port: f.local_port,
            fwmark: f.fwmark,
            cert_path: f.cert_path,
            key_path: f.key_path,
            dump_path: f.dump_path,
            bpf_obj_name: f.bpf_obj_name,
            box_ip: f.box_ip,
            log_level: f.log_level,
        })
    }

    pub fn load() -> anyhow::Result<Settings> {
        let cli = Cli::parse();
        let text = std::fs::read_to_string(&cli.config)?;
        let mut s = Settings::from_toml_str(&text)?;
        if let Some(v) = cli.client { s.client_ip = v; }
        if let Some(v) = cli.server { s.server_ip = v; }
        if let Some(v) = cli.tun { s.tun_iface = v; }
        if let Some(v) = cli.egress { s.egress_iface = v; }
        Ok(s)
    }

    pub fn to_bpf_config(&self) -> mymitm_common::Config {
        mymitm_common::Config {
            client_ip: u32::from(self.client_ip).to_be(),
            server_ip: u32::from(self.server_ip).to_be(),
            box_ip: u32::from(self.box_ip).to_be(),
            local_ip: u32::from(self.local_ip).to_be(),
            server_port: self.server_port.to_be(),
            local_port: self.local_port.to_be(),
            fwmark: self.fwmark,
        }
    }
}
```
Add `mod config;` to `mymitm/src/main.rs`.

- [ ] **Step 5: Run tests, verify pass**

Run: `cargo test -p mymitm config --target x86_64-unknown-linux-gnu`
Expected: PASS (3 tests).

- [ ] **Step 6: Commit**

```bash
git add -A && git commit -m "feat(config): TOML + CLI settings with NBO bpf config"
```

---

## Task 5: Dump writer (`mymitm/dump.rs`)

**Goal:** Per-connection decrypted-byte dump (JSONL index + `c2s`/`s2c` streams) that never blocks/crashes the proxy.

**Files:**
- Create: `mymitm/src/dump.rs`
- Modify: `mymitm/src/main.rs`, `mymitm/Cargo.toml`
- Test: inline `#[cfg(test)]` in `dump.rs`

**Interfaces:**
- Produces:
  - `struct Dumper { dir: PathBuf }`
  - `impl Dumper { fn new(dir: &Path) -> io::Result<Dumper>; fn open_conn(&self, client: SocketAddr, server: SocketAddr) -> ConnDump }`
  - `struct ConnDump { id: String, c2s: Option<File>, s2c: Option<File> }`
  - `impl ConnDump { fn write_c2s(&mut self, b: &[u8]); fn write_s2c(&mut self, b: &[u8]); fn finish(self, dir: &Path) }`
  - Errors are logged and swallowed (methods return `()`), satisfying "never crash the proxy".

- [ ] **Step 1: Add deps**

`mymitm/Cargo.toml`: add `serde_json = "1"`, `time = { version = "0.3", features = ["formatting"] }`, `tracing = "0.1"`. (`tracing` subscriber added in Task 10.)

- [ ] **Step 2: Write failing test**

`mymitm/src/dump.rs` (test module):
```rust
#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;

    #[test]
    fn writes_streams_and_index() {
        let dir = tempfile::tempdir().unwrap();
        let d = Dumper::new(dir.path()).unwrap();
        let mut c = d.open_conn(
            "10.8.0.5:43012".parse::<SocketAddr>().unwrap(),
            "192.168.1.50:443".parse::<SocketAddr>().unwrap());
        c.write_c2s(b"GET / HTTP/1.1\r\n");
        c.write_s2c(b"HTTP/1.1 200 OK\r\n");
        let id = c.id.clone();
        c.finish(dir.path());

        let c2s = std::fs::read(dir.path().join(format!("{id}.c2s"))).unwrap();
        assert_eq!(c2s, b"GET / HTTP/1.1\r\n");
        let idx = std::fs::read_to_string(dir.path().join("index.jsonl")).unwrap();
        assert!(idx.contains("10.8.0.5:43012"));
        assert!(idx.contains("192.168.1.50:443"));
    }
}
```
Add `tempfile = "3"` to `mymitm/Cargo.toml` `[dev-dependencies]`.

- [ ] **Step 3: Run test, verify fail**

Run: `cargo test -p mymitm dump --target x86_64-unknown-linux-gnu`
Expected: FAIL — `Dumper` not found.

- [ ] **Step 4: Implement dump**

`mymitm/src/dump.rs`:
```rust
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static COUNTER: AtomicU64 = AtomicU64::new(0);

pub struct Dumper { dir: PathBuf }

pub struct ConnDump {
    pub id: String,
    client: SocketAddr,
    server: SocketAddr,
    c2s: Option<File>,
    s2c: Option<File>,
    start: String,
}

impl Dumper {
    pub fn new(dir: &Path) -> std::io::Result<Dumper> {
        fs::create_dir_all(dir)?;
        Ok(Dumper { dir: dir.to_path_buf() })
    }

    pub fn open_conn(&self, client: SocketAddr, server: SocketAddr) -> ConnDump {
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let id = format!("conn-{n:08}");
        let mk = |suffix: &str| OpenOptions::new().create(true).write(true).truncate(true)
            .open(self.dir.join(format!("{id}.{suffix}")))
            .map_err(|e| tracing::warn!("dump open {suffix} failed: {e}")).ok();
        ConnDump {
            id: id.clone(),
            client, server,
            c2s: mk("c2s"),
            s2c: mk("s2c"),
            start: now_iso(),
        }
    }
}

impl ConnDump {
    pub fn write_c2s(&mut self, b: &[u8]) { write_some(&mut self.c2s, b); }
    pub fn write_s2c(&mut self, b: &[u8]) { write_some(&mut self.s2c, b); }

    pub fn finish(self, dir: &Path) {
        let rec = serde_json::json!({
            "conn_id": self.id, "client": self.client.to_string(),
            "server": self.server.to_string(), "start_ts": self.start, "end_ts": now_iso(),
        });
        if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(dir.join("index.jsonl")) {
            let _ = writeln!(f, "{rec}");
        }
    }
}

fn write_some(f: &mut Option<File>, b: &[u8]) {
    if let Some(file) = f.as_mut() {
        if let Err(e) = file.write_all(b) { tracing::warn!("dump write failed: {e}"); }
    }
}

fn now_iso() -> String {
    time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default()
}
```
Add `mod dump;` to `mymitm/src/main.rs`.

- [ ] **Step 5: Run test, verify pass**

Run: `cargo test -p mymitm dump --target x86_64-unknown-linux-gnu`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add -A && git commit -m "feat(dump): per-conn JSONL index + c2s/s2c streams"
```

---

## Task 6: eBPF program `cls_tun` (client-side DNAT)

**Goal:** The `tun0` classifier: DNAT target ingress to the local listener, un-DNAT egress replies. Uses the Task 3 classifiers for decisions and BPF helpers for the actual rewrite + checksum fixup.

**Files:**
- Modify: `mymitm-ebpf/src/main.rs`, `mymitm-ebpf/Cargo.toml`
- Verification: compile + a `BPF_PROG_TEST_RUN` smoke test in Task 8's loader (rewrite correctness is authoritatively proven by the Task 11 netns e2e). At this task we verify it **compiles to BPF and the verifier accepts it** when loaded.

**Interfaces:**
- Consumes: `mymitm_common::{Config, classify_tun, PktMeta, Rewrite}`, `config_map` (array, index 0 → `Config`).
- Produces: a `SchedClassifier` named `<prefix>_cls_tun` reading `direction` from a per-attach constant. We attach the same function twice (ingress/egress); direction is conveyed via two distinct programs `cls_tun_ingress` and `cls_tun_egress` to keep the verifier simple.

- [ ] **Step 1: Add ebpf deps**

`mymitm-ebpf/Cargo.toml`:
```toml
[dependencies]
aya-ebpf = "0.1"
mymitm-common = { path = "../mymitm-common", default-features = false }
network-types = "0.0.7"   # ethhdr/iphdr/tcphdr definitions

[[bin]]
name = "mymitm"
path = "src/main.rs"
```

- [ ] **Step 2: Implement parsing + cls_tun programs**

`mymitm-ebpf/src/main.rs`:
```rust
#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::{TC_ACT_OK, BPF_F_RECOMPUTE_CSUM},
    helpers::bpf_skb_store_bytes,
    macros::{classifier, map},
    maps::Array,
    programs::TcContext,
};
use core::mem;
use mymitm_common::{classify_tun, classify_eth, Config, PktMeta, Rewrite};
use network_types::{eth::{EthHdr, EtherType}, ip::Ipv4Hdr, tcp::TcpHdr};

#[map] static CONFIG: Array<Config> = Array::with_max_entries(1, 0);

const ETH_LEN: usize = EthHdr::LEN;
const IP_LEN: usize = Ipv4Hdr::LEN;

#[inline(always)]
fn meta(ctx: &TcContext) -> Option<(PktMeta, usize, usize)> {
    // tun is L3 (no ethernet). Detect: if first nibble is 4, it's raw IPv4.
    let first: u8 = ctx.load(0).ok()?;
    let l2 = if (first >> 4) == 4 { 0 } else { ETH_LEN };
    if l2 == ETH_LEN {
        let eth: EthHdr = ctx.load(0).ok()?;
        if eth.ether_type != EtherType::Ipv4 { return None; }
    }
    let ip: Ipv4Hdr = ctx.load(l2).ok()?;
    if ip.proto != network_types::ip::IpProto::Tcp { return None; }
    let ihl = ((ip.vihl & 0x0f) as usize) * 4;
    let tcp: TcpHdr = ctx.load(l2 + ihl).ok()?;
    let m = PktMeta {
        src_ip: ip.src_addr, dst_ip: ip.dst_addr,
        src_port: tcp.source, dst_port: tcp.dest,
        mark: unsafe { (*ctx.skb.skb).mark },
    };
    Some((m, l2, l2 + ihl))
}

#[inline(always)]
fn cfg() -> Option<Config> { CONFIG.get(0).copied() }

// Rewrite dst ip:port (DNAT). new_ip/new_port in network byte order.
#[inline(always)]
fn set_dst(ctx: &mut TcContext, l3: usize, l4: usize, new_ip: u32, new_port: u16) -> Result<(), i64> {
    let old_ip: u32 = ctx.load(l3 + offset_of_dst_ip())?;
    let old_port: u16 = ctx.load(l4 + 2)?; // tcp dest at +2
    let ip_csum = l3 + Ipv4Hdr::CSUM_OFFSET;     // see note below
    let tcp_csum = l4 + 16;                        // tcp checksum offset
    ctx.l3_csum_replace(ip_csum, old_ip as u64, new_ip as u64, 4)?;
    ctx.l4_csum_replace(tcp_csum, old_ip as u64, new_ip as u64, BPF_F_PSEUDO_HDR | 4)?;
    ctx.l4_csum_replace(tcp_csum, old_port as u64, new_port as u64, 2)?;
    ctx.store(l3 + offset_of_dst_ip(), &new_ip, 0)?;
    ctx.store(l4 + 2, &new_port, 0)?;
    Ok(())
}
// (set_src is symmetric, editing src ip at l3 + offset_of_src_ip() and tcp source at l4 + 0)
```
> Implementation note for the engineer: aya-ebpf exposes `TcContext::l3_csum_replace`, `l4_csum_replace`, `store`, and `load`. The exact constant names (`BPF_F_PSEUDO_HDR`, `Ipv4Hdr::CSUM_OFFSET`, field names `vihl`/`src_addr`) must be verified against the pinned `aya-ebpf`/`network-types` versions — pin them in Step 1 and `cargo doc --open` to confirm. Helper `offset_of_dst_ip()`/`offset_of_src_ip()` return the byte offsets of the IPv4 addr fields within the IP header (16 and 12 respectively).

```rust
#[classifier]
pub fn cls_tun_ingress(mut ctx: TcContext) -> i32 { run_tun(&mut ctx, false) }
#[classifier]
pub fn cls_tun_egress(mut ctx: TcContext) -> i32 { run_tun(&mut ctx, true) }

#[inline(always)]
fn run_tun(ctx: &mut TcContext, egress: bool) -> i32 {
    let (Some((m, l3, l4)), Some(c)) = (meta(ctx), cfg()) else { return TC_ACT_OK; };
    match classify_tun(&m, &c, egress) {
        Rewrite::DnatToLocal => { let _ = set_dst(ctx, l3, l4, c.local_ip, c.local_port); }
        Rewrite::UnDnatFromLocal => { let _ = set_src(ctx, l3, l4, c.server_ip, c.server_port); }
        _ => {}
    }
    TC_ACT_OK
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! { loop {} }
```

- [ ] **Step 3: Build the eBPF crate to BPF bytecode**

Run:
```bash
cargo build -p mymitm-ebpf --target bpfel-unknown-none -Z build-std=core --release
```
Expected: produces `target/bpfel-unknown-none/release/mymitm`. (Wrap this in `mymitm/build.rs` in Task 8; for now run manually.)

- [ ] **Step 4: Verify the verifier accepts cls_tun (quick load check)**

Use the spike-style loader (or a throwaway `examples/loadcheck.rs`) to `load()` the object and `prog.load()` both `cls_tun_ingress`/`cls_tun_egress` against a temp tun. Expected: no verifier error. If the verifier rejects (e.g. bounds checks), add explicit `ctx.data_end()` bounds guards in `meta()` per the aya book.

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "feat(ebpf): cls_tun DNAT/un-DNAT programs"
```

---

## Task 7: eBPF program `cls_eth` (server-side SNAT + un-SNAT)

**Goal:** The `eth0` classifier: on egress, SNAT our marked upstream packets' source to the client IP and record the flow; on ingress, un-SNAT replies' destination back to the box before routing.

**Files:**
- Modify: `mymitm-ebpf/src/main.rs`
- Verification: compile + verifier-accept (as Task 6); rewrite correctness proven in Task 11.

**Interfaces:**
- Consumes: `classify_eth`, `CONFIG`, and a new `UPSTREAM` map (`HashMap<UpstreamKey, UpstreamVal>`) shared with userspace.
- Produces: `cls_eth_ingress`, `cls_eth_egress` classifiers; `<prefix>_upstream` map.

- [ ] **Step 1: Add the upstream map and eth programs**

Append to `mymitm-ebpf/src/main.rs`:
```rust
use aya_ebpf::maps::HashMap as BpfHashMap;
use mymitm_common::{UpstreamKey, UpstreamVal};

#[map] static UPSTREAM: BpfHashMap<UpstreamKey, UpstreamVal> =
    BpfHashMap::with_max_entries(1024, 0);

#[classifier]
pub fn cls_eth_egress(mut ctx: TcContext) -> i32 {
    let (Some((m, l3, l4)), Some(c)) = (meta(&ctx), cfg()) else { return TC_ACT_OK; };
    if classify_eth(&m, &c, true) == Rewrite::SnatToClient {
        // record reverse mapping BEFORE rewrite (m.src_port is our box local port)
        let key = UpstreamKey { server_ip: c.server_ip, client_ip: c.client_ip,
                                server_port: c.server_port, client_port: m.src_port };
        let val = UpstreamVal { box_ip: c.box_ip, box_port: m.src_port };
        let _ = UPSTREAM.insert(&key, &val, 0);
        let _ = set_src(&mut ctx, l3, l4, c.client_ip, m.src_port); // ip→client, port unchanged
    }
    TC_ACT_OK
}

#[classifier]
pub fn cls_eth_ingress(mut ctx: TcContext) -> i32 {
    let (Some((m, l3, l4)), Some(c)) = (meta(&ctx), cfg()) else { return TC_ACT_OK; };
    if classify_eth(&m, &c, false) == Rewrite::UnSnatToBox {
        let key = UpstreamKey { server_ip: c.server_ip, client_ip: c.client_ip,
                                server_port: c.server_port, client_port: m.dst_port };
        if let Some(v) = unsafe { UPSTREAM.get(&key) } {
            let _ = set_dst(&mut ctx, l3, l4, v.box_ip, v.box_port);
        }
    }
    TC_ACT_OK
}
```
> Note: `set_src` keeps the source port unchanged (we spoof only the IP); the box's chosen ephemeral port is reused as the client-side port, which is also what `UpstreamKey.client_port` records, so ingress lookup matches.

- [ ] **Step 2: Build to BPF**

Run: `cargo build -p mymitm-ebpf --target bpfel-unknown-none -Z build-std=core --release`
Expected: builds.

- [ ] **Step 3: Verifier-accept check**

Load all four programs against temp `tun`/`dummy` interfaces (as Task 6 Step 4). Expected: accepted. Add bounds guards if rejected.

- [ ] **Step 4: Commit**

```bash
git add -A && git commit -m "feat(ebpf): cls_eth SNAT/un-SNAT with upstream map"
```

---

## Task 8: BPF lifecycle in userspace (`mymitm/bpf.rs` + `build.rs`)

**Goal:** Compile+embed the eBPF object, load it with CO-RE, populate `config_map`, create the clsact qdiscs, attach all four programs, expose the upstream map handle, and clean up idempotently.

**Files:**
- Create: `mymitm/build.rs`, `mymitm/src/bpf.rs`
- Modify: `mymitm/Cargo.toml`, `mymitm/src/main.rs`

**Interfaces:**
- Consumes: `Settings`, `mymitm_common::Config`.
- Produces:
  - `struct BpfPlane { ebpf: aya::Ebpf, tun: String, egress: String }`
  - `impl BpfPlane { fn load_and_attach(s: &Settings) -> anyhow::Result<BpfPlane>; fn upstream_map(&mut self) -> aya::maps::HashMap<_, UpstreamKey, UpstreamVal> }`
  - `impl Drop for BpfPlane` — detaches filters + removes qdiscs we added.

- [ ] **Step 1: Add deps and build.rs**

`mymitm/Cargo.toml`: add `aya = "0.13"`, `aya-log = "0.2"`. `[build-dependencies]`: `aya-build = "0.1"` (or a manual `Command` invoking the ebpf build).

`mymitm/build.rs`:
```rust
fn main() {
    // Build the eBPF crate to BPF and expose its path via OUT_DIR for include_bytes_aligned!.
    aya_build::build_ebpf("mymitm-ebpf").expect("build ebpf");
    println!("cargo:rerun-if-changed=../mymitm-ebpf/src");
}
```
> If `aya-build`'s API differs in the pinned version, fall back to a `std::process::Command` that runs the Task 6 Step 3 cargo line and copies the artifact into `OUT_DIR`.

- [ ] **Step 2: Write a load+attach integration test (privileged)**

`mymitm/src/bpf.rs` test module:
```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Settings;

    // Requires root + a temp tun/dummy. Run: sudo -E cargo test bpf_attach -- --ignored
    #[test] #[ignore]
    fn loads_attaches_and_cleans_up() {
        std::process::Command::new("ip").args(["tuntap","add","dev","mmtun0","mode","tun"]).status().unwrap();
        std::process::Command::new("ip").args(["link","set","mmtun0","up"]).status().unwrap();
        std::process::Command::new("ip").args(["link","add","mmeth0","type","dummy"]).status().unwrap();
        std::process::Command::new("ip").args(["link","set","mmeth0","up"]).status().unwrap();

        let s = Settings::from_toml_str(r#"
            target_client_ip="10.8.0.5" target_server_ip="192.168.1.50"
            cert_path="/x" key_path="/y" box_ip="192.168.1.10"
            tun_iface="mmtun0" egress_iface="mmeth0""#).unwrap();
        {
            let plane = BpfPlane::load_and_attach(&s).expect("attach");
            // filters present
            let out = std::process::Command::new("tc").args(["filter","show","dev","mmtun0","ingress"]).output().unwrap();
            assert!(String::from_utf8_lossy(&out.stdout).contains("bpf"));
            drop(plane);
        }
        // after drop, qdisc removed
        let out = std::process::Command::new("tc").args(["qdisc","show","dev","mmtun0"]).output().unwrap();
        assert!(!String::from_utf8_lossy(&out.stdout).contains("clsact"));

        for i in ["mmtun0","mmeth0"] {
            let _ = std::process::Command::new("ip").args(["link","del",i]).status();
        }
    }
}
```

- [ ] **Step 3: Run test, verify fail**

Run: `sudo -E $(which cargo) test -p mymitm bpf_attach --target x86_64-unknown-linux-musl -- --ignored`
Expected: FAIL — `BpfPlane` not found.

- [ ] **Step 4: Implement bpf.rs**

`mymitm/src/bpf.rs`:
```rust
use aya::programs::{tc, SchedClassifier, TcAttachType};
use aya::maps::{Array, HashMap};
use aya::{Ebpf, EbpfLoader};
use mymitm_common::{Config, UpstreamKey, UpstreamVal};
use crate::config::Settings;

pub struct BpfPlane { pub ebpf: Ebpf, tun: String, egress: String, owns_tun_qdisc: bool, owns_eth_qdisc: bool }

impl BpfPlane {
    pub fn load_and_attach(s: &Settings) -> anyhow::Result<BpfPlane> {
        let mut ebpf = EbpfLoader::new().load(aya::include_bytes_aligned!(
            concat!(env!("OUT_DIR"), "/mymitm")))?;
        let _ = aya_log::EbpfLogger::init(&mut ebpf);

        // populate config map (index 0)
        {
            let mut cfgmap: Array<_, Config> = Array::try_from(ebpf.map_mut("CONFIG").unwrap())?;
            cfgmap.set(0, s.to_bpf_config(), 0)?;
        }

        // idempotent qdisc creation; remember whether we created it
        let owns_tun_qdisc = tc::qdisc_add_clsact(&s.tun_iface).is_ok();
        let owns_eth_qdisc = tc::qdisc_add_clsact(&s.egress_iface).is_ok();

        for (name, iface, dir) in [
            ("cls_tun_ingress", &s.tun_iface, TcAttachType::Ingress),
            ("cls_tun_egress",  &s.tun_iface, TcAttachType::Egress),
            ("cls_eth_ingress", &s.egress_iface, TcAttachType::Ingress),
            ("cls_eth_egress",  &s.egress_iface, TcAttachType::Egress),
        ] {
            let p: &mut SchedClassifier = ebpf.program_mut(name).unwrap().try_into()?;
            p.load()?;
            p.attach(iface, dir)?;
        }
        Ok(BpfPlane { ebpf, tun: s.tun_iface.clone(), egress: s.egress_iface.clone(),
                      owns_tun_qdisc, owns_eth_qdisc })
    }

    pub fn upstream_map(&mut self) -> anyhow::Result<HashMap<&mut aya::maps::MapData, UpstreamKey, UpstreamVal>> {
        Ok(HashMap::try_from(self.ebpf.map_mut("UPSTREAM").unwrap())?)
    }
}

impl Drop for BpfPlane {
    fn drop(&mut self) {
        // detaching happens automatically when programs drop; remove qdiscs we created
        if self.owns_tun_qdisc { let _ = tc::qdisc_detach_program(&self.tun, TcAttachType::Ingress, "cls_tun_ingress"); }
        let _ = std::process::Command::new("tc").args(["qdisc","del","dev",&self.tun,"clsact"]).status();
        let _ = std::process::Command::new("tc").args(["qdisc","del","dev",&self.egress,"clsact"]).status();
    }
}
```
> Note: aya program names come from the `#[classifier]` fn names. If aya mangles or namespaces them, confirm via `ebpf.programs()` iteration and adjust the string literals. `qdisc_detach_program` is best-effort; the `tc qdisc del … clsact` removes all our filters in one shot, which is the reliable cleanup.

Add `mod bpf;` to `main.rs`.

- [ ] **Step 5: Run test, verify pass**

Run: `sudo -E $(which cargo) test -p mymitm bpf_attach --target x86_64-unknown-linux-musl -- --ignored`
Expected: PASS — filters present while alive, qdisc gone after drop.

- [ ] **Step 6: Add idempotent stale cleanup on startup**

Add a `fn pre_clean(s: &Settings)` that runs `tc qdisc del dev <iface> clsact` (ignoring errors) for both ifaces, and call it at the top of `load_and_attach`. This makes restart-after-crash safe. Add a test asserting two sequential `load_and_attach`+drop cycles both succeed.

- [ ] **Step 7: Commit**

```bash
git add -A && git commit -m "feat(bpf): CO-RE load, attach 4 progs, config map, idempotent cleanup"
```

---

## Task 9: Proxy core (`mymitm/proxy.rs`)

**Goal:** Accept the locally-delivered (DNAT'd) client connection, terminate TLS with the real cert, dial the server over a `SO_MARK`-tagged socket, pump bytes both ways, and dump.

**Files:**
- Create: `mymitm/src/proxy.rs`
- Modify: `mymitm/Cargo.toml`, `mymitm/src/main.rs`
- Test: inline test for cert loading + a localhost TLS round-trip (no eBPF).

**Interfaces:**
- Consumes: `Settings`, `Dumper`.
- Produces:
  - `async fn run(settings: Arc<Settings>, dumper: Arc<Dumper>) -> anyhow::Result<()>` — binds `local_ip:local_port`, serves forever.
  - `fn load_server_tls(cert: &Path, key: &Path) -> anyhow::Result<Arc<rustls::ServerConfig>>`
  - `fn upstream_socket(server: SocketAddr, fwmark: u32) -> io::Result<TcpStream>` (sets `SO_MARK`).

- [ ] **Step 1: Add deps (rustls with ring)**

`mymitm/Cargo.toml`:
```toml
tokio = { version = "1", features = ["rt-multi-thread","net","io-util","macros","signal"] }
tokio-rustls = { version = "0.26", default-features = false, features = ["ring","tls12"] }
rustls = { version = "0.23", default-features = false, features = ["ring","std"] }
rustls-pemfile = "2"
socket2 = "0.5"
```

- [ ] **Step 2: Write failing tests (cert load + TLS echo round-trip)**

`mymitm/src/proxy.rs` test module:
```rust
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn loads_cert_and_key() {
        // generate a throwaway cert+key with rcgen in the test
        let cert = rcgen::generate_simple_self_signed(vec!["test".into()]).unwrap();
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("c.pem"), cert.serialize_pem().unwrap()).unwrap();
        std::fs::write(dir.path().join("k.pem"), cert.serialize_private_key_pem()).unwrap();
        let cfg = load_server_tls(&dir.path().join("c.pem"), &dir.path().join("k.pem")).unwrap();
        assert!(cfg.cert_resolver.is_some() || true); // smoke: it built
    }
}
```
Add `[dev-dependencies] rcgen = "0.13"`.

- [ ] **Step 3: Run test, verify fail**

Run: `cargo test -p mymitm proxy --target x86_64-unknown-linux-gnu`
Expected: FAIL — `load_server_tls` not found.

- [ ] **Step 4: Implement proxy**

`mymitm/src/proxy.rs`:
```rust
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{TlsAcceptor, TlsConnector, rustls};
use crate::{config::Settings, dump::Dumper};

pub fn load_server_tls(cert: &Path, key: &Path) -> anyhow::Result<Arc<rustls::ServerConfig>> {
    let certs = rustls_pemfile::certs(&mut std::io::BufReader::new(std::fs::File::open(cert)?))
        .collect::<Result<Vec<_>,_>>()?;
    let key = rustls_pemfile::private_key(&mut std::io::BufReader::new(std::fs::File::open(key)?))?
        .ok_or_else(|| anyhow::anyhow!("no private key in {key:?}"))?;
    let cfg = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    Ok(Arc::new(cfg))
}

pub fn upstream_socket(server: SocketAddr, fwmark: u32) -> std::io::Result<std::net::TcpStream> {
    let sock = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::STREAM, None)?;
    sock.set_mark(fwmark)?;           // SO_MARK
    sock.set_nonblocking(true)?;
    let _ = sock.connect(&server.into()); // EINPROGRESS expected under nonblocking
    Ok(sock.into())
}

pub async fn run(s: Arc<Settings>, dumper: Arc<Dumper>) -> anyhow::Result<()> {
    let server_cfg = load_server_tls(&s.cert_path, &s.key_path)?;
    let acceptor = TlsAcceptor::from(server_cfg);
    let listener = TcpListener::bind((s.local_ip, s.local_port)).await?;
    tracing::info!("listening on {}:{}", s.local_ip, s.local_port);

    // upstream TLS client config: we hold the real cert, verify normally against a root we trust.
    // For v1 we pin the provided cert as the only trusted anchor.
    let connector = build_upstream_connector(&s)?;

    loop {
        let (inbound, peer) = listener.accept().await?;
        let (acceptor, connector, s, dumper) =
            (acceptor.clone(), connector.clone(), s.clone(), dumper.clone());
        tokio::spawn(async move {
            if let Err(e) = handle_conn(inbound, peer, acceptor, connector, s, dumper).await {
                tracing::warn!("conn {peer} ended: {e}");
            }
        });
    }
}

async fn handle_conn(
    inbound: TcpStream, peer: SocketAddr,
    acceptor: TlsAcceptor, connector: TlsConnector,
    s: Arc<Settings>, dumper: Arc<Dumper>,
) -> anyhow::Result<()> {
    let client_tls = acceptor.accept(inbound).await?;          // present real cert to client
    let server_addr = SocketAddr::from((s.server_ip, s.server_port));
    let std_up = upstream_socket(server_addr, s.fwmark)?;
    let up = TcpStream::from_std(std_up)?;
    up.writable().await?;                                       // wait connect completion
    let server_name = rustls::pki_types::ServerName::IpAddress(s.server_ip.into());
    let server_tls = connector.connect(server_name, up).await?;

    let mut conn = dumper.open_conn(peer, server_addr);
    let (mut cr, mut cw) = tokio::io::split(client_tls);
    let (mut sr, mut sw) = tokio::io::split(server_tls);

    let c2s = async {
        let mut buf = [0u8; 16384];
        loop {
            let n = cr.read(&mut buf).await?; if n == 0 { break; }
            conn.write_c2s(&buf[..n]);
            sw.write_all(&buf[..n]).await?;
        }
        Ok::<(), std::io::Error>(())
    };
    let s2c = async {
        let mut buf = [0u8; 16384];
        loop {
            let n = sr.read(&mut buf).await?; if n == 0 { break; }
            conn.write_s2c(&buf[..n]);
            cw.write_all(&buf[..n]).await?;
        }
        Ok::<(), std::io::Error>(())
    };
    let _ = tokio::try_join!(c2s, s2c);
    conn.finish(&s.dump_path);
    Ok(())
}
```
> `build_upstream_connector(&s)` builds a `TlsConnector` whose root store contains exactly the provided leaf/its issuer (pin), so we validate the real server. Implement it reading `s.cert_path` chain into a `rustls::RootCertStore`. If the server uses a private CA we don't have, fall back to a documented "danger: no-verify" connector flag (off by default).

Add `mod proxy;` to `main.rs`.

- [ ] **Step 5: Run test, verify pass**

Run: `cargo test -p mymitm proxy --target x86_64-unknown-linux-gnu`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add -A && git commit -m "feat(proxy): TLS terminate + SO_MARK upstream + pump + dump"
```

---

## Task 10: Wiring, signals, and Drop-guard lifecycle (`mymitm/main.rs`)

**Goal:** Tie config → bpf plane → proxy together, install tracing, and guarantee eBPF cleanup on SIGTERM/SIGINT and on panic.

**Files:**
- Modify: `mymitm/src/main.rs`, `mymitm/Cargo.toml`

**Interfaces:**
- Consumes: `Settings::load`, `BpfPlane::load_and_attach`, `proxy::run`, `Dumper::new`.

- [ ] **Step 1: Add tracing-subscriber**

`mymitm/Cargo.toml`: `tracing-subscriber = { version = "0.3", features = ["env-filter"] }`.

- [ ] **Step 2: Implement main**

`mymitm/src/main.rs`:
```rust
mod config; mod bpf; mod proxy; mod dump;
use std::sync::Arc;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let settings = config::Settings::load()?;
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new(&settings.log_level))
        .init();

    let dumper = Arc::new(dump::Dumper::new(&settings.dump_path)?);
    let _plane = bpf::BpfPlane::load_and_attach(&settings)?; // Drop cleans up
    tracing::info!("data plane attached; entering proxy loop");

    let settings = Arc::new(settings);
    tokio::select! {
        r = proxy::run(settings.clone(), dumper.clone()) => { r?; }
        _ = shutdown_signal() => { tracing::info!("shutdown signal; detaching"); }
    }
    // _plane dropped here → tc qdiscs removed
    Ok(())
}

async fn shutdown_signal() {
    use tokio::signal::unix::{signal, SignalKind};
    let mut term = signal(SignalKind::terminate()).unwrap();
    let mut intr = signal(SignalKind::interrupt()).unwrap();
    tokio::select! { _ = term.recv() => {}, _ = intr.recv() => {} }
}
```

- [ ] **Step 3: Build the full static binary**

Run:
```bash
cargo build -p mymitm --release
ldd target/x86_64-unknown-linux-musl/release/mymitm
```
Expected: `not a dynamic executable`; binary builds with embedded eBPF.

- [ ] **Step 4: Smoke-run against a sample config (no real traffic)**

Create `mymitm.toml` (sample), run under a temp tun/dummy as in Task 8, confirm it attaches, logs "entering proxy loop", and on Ctrl-C the qdiscs are gone (`tc qdisc show`).

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "feat: main wiring, signals, Drop-guard cleanup; static release build"
```

---

## Task 11: End-to-end integration in a netns harness

**Goal:** Prove the whole thing in a controlled namespace: a fake client, fake server, a `tun` standing in for `tun0`, and assertions that (a) the client gets the genuine cert, (b) bytes round-trip, (c) dumps are correct, and (d) **the upstream connection to the server carries the client's source IP**.

**Files:**
- Create: `tests/integration/harness.sh`, `tests/integration/e2e.rs` (or a `bash` test driver).
- Modify: `mymitm/Cargo.toml` (if using a Rust integration test) — likely simpler as a shell-driven test.

**Interfaces:**
- Consumes: the release binary + a generated cert/key.

- [ ] **Step 1: Write the netns harness script**

`tests/integration/harness.sh` (concept — fill exact addrs):
```bash
#!/usr/bin/env bash
set -euo pipefail
# netns "srv" holds the fake server on 192.168.1.50:443.
# root ns holds: a tun (tun0-stand-in) with the client subnet, and a veth to srv as "eth0".
sudo ip netns add srv
sudo ip link add veth0 type veth peer name veth1
sudo ip link set veth1 netns srv
sudo ip addr add 192.168.1.10/24 dev veth0           # box "eth0"
sudo ip link set veth0 up
sudo ip netns exec srv ip addr add 192.168.1.50/24 dev veth1
sudo ip netns exec srv ip link set veth1 up
sudo ip tuntap add dev tun0 mode tun
sudo ip addr add 10.8.0.1/24 dev tun0
sudo ip link set tun0 up
# a userspace "client" writes a SYN to tun0 with src 10.8.0.5 (use a tiny scapy/python or a
# raw-socket client run with that source via the tun). See e2e.rs notes.
```
> The exact client injection: run a small Python (scapy) or a Rust raw-socket client that emits the client→192.168.1.50:443 TLS flow sourced from 10.8.0.5 into tun0. Document the chosen method in the file.

- [ ] **Step 2: Write the fake TLS server**

A tiny TLS server in netns `srv` using the SAME cert we feed mymitm as the "real" cert; it echoes/serves a known body and **records the source IP of the inbound connection**.

- [ ] **Step 3: Write the e2e assertions**

Drive: start `mymitm` (config pointing tun_iface=tun0, egress_iface=veth0, server=192.168.1.50, client=10.8.0.5, box_ip=192.168.1.10), run the client, then assert:
1. Client TLS handshake succeeds and the presented cert == our leaf (pin check client-side).
2. The known request/response bytes match end-to-end.
3. `index.jsonl` + `<id>.c2s`/`.s2c` contain the expected plaintext.
4. **The fake server logged the inbound source IP == `10.8.0.5`** (the core source-IP-preservation proof), captured also via `ip netns exec srv tcpdump -ni veth1 'tcp port 443'`.

- [ ] **Step 4: Run the e2e (verify it fails first if binary missing, then passes)**

Run:
```bash
sudo bash tests/integration/harness.sh up
sudo ./target/x86_64-unknown-linux-musl/release/mymitm --config tests/integration/e2e.toml &
sudo bash tests/integration/run_client_and_assert.sh
sudo bash tests/integration/harness.sh down
```
Expected: all four assertions pass; teardown leaves no `tun0`/`veth0`/netns and no `clsact` qdiscs.

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "test(e2e): netns harness proving MITM + source-IP preservation"
```

---

## Self-review notes (for the implementer)

- **Spec coverage:** every spec section maps to a task — interception/diversion (T6), source-IP SNAT + return un-SNAT (T7), TLS terminate with real cert (T9), dump (T5), config surface (T4), static musl + ring (T2/T9), fail-open/idempotent cleanup (T8/T10), WSL-spike-then-VM (T1), e2e incl. source-IP proof (T11), CO-RE (T6–T8).
- **Biggest real risks** (verify early, don't trust the plan blindly): (1) tc-eBPF on `tun` in WSL2 (T1 gates it); (2) exact aya-ebpf/network-types helper & field names — pin versions and `cargo doc`; (3) the un-SNAT-before-routing behavior at tc-ingress on `eth0` actually preventing kernel forward-to-client — this is the load-bearing trick; if a stray packet still reaches the client, confirm tc ingress runs before the routing decision on this kernel and add a guard. T11 assertion (4) is what catches this.
- **Out of scope (don't build):** multi-target, HTTP parsing, pcap output, BPF-aware-inspection evasion.
