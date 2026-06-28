# mymitmproxy v2 Data Plane Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the MITM data plane learn the client IP dynamically per connection, run on kernel 4.15 through 6.6+, and offer a non-eBPF (iproute2/iptables) fallback — all behind one config switch, with the proxy core unchanged.

**Architecture:** Two data planes (`ebpf`, `iproute`) implement a common `DataPlane` trait whose one per-connection method opens the upstream socket carrying the client's source IP (eBPF: bind box IP + `SO_MARK` + populate an `EGRESS` BPF map for the kernel SNAT; iproute: `IP_TRANSPARENT` bind to the client IP + policy routing). eBPF attach auto-detects TCX (≥6.6) with a `clsact`+tc-bpf fallback. The client IP is no longer configured; the proxy learns it from the accepted listener socket's peer address and the kernel SNAT is keyed on the box's ephemeral upstream port.

**Tech Stack:** Rust, aya 0.13.1 / aya-ebpf 0.1.1, network-types 0.2.0, tokio, tokio-rustls 0.23 (ring), socket2, musl static target `x86_64-unknown-linux-musl`.

## Global Constraints

- Fully static `x86_64-unknown-linux-musl` binary; no runtime/libc deps. Verify with `ldd` showing "not a dynamic executable" / "statically linked".
- eBPF reads packets by **raw byte offset** and accesses `__sk_buff->mark` as a context field only — **no kernel-struct CO-RE relocations** (must remain BTF-free so it loads on kernel 4.15, which ships no BTF).
- All address/port values crossing the userspace↔eBPF boundary are **network byte order** (`.to_be()`); `Config.client_ip == 0` (0.0.0.0) is the "any client" sentinel.
- eBPF mode keeps the zero-`ip`/`iptables`/`ip rule` footprint (tc-eBPF footprint OK). **iproute mode deliberately installs visible rules** and must reverse every one in `Drop`/`--cleanup`.
- Host-side unit tests run with `--target x86_64-unknown-linux-gnu`. The release/static build is `cargo build -p mymitm --release` (workspace default target is musl).
- Single configured **target server IP:port**; multi-**client** is in scope, multi-server is not.

## Execution environment

- **Builds (eBPF + musl + privileged tests) must run in the WSL repo** at `~/projects/mymitmproxy` (native ext4 — required; do not build the eBPF/musl artifacts off `/mnt/c`).
- **File edits:** UNC root `\\wsl.localhost\Ubuntu-24.04\home\ron\projects\mymitmproxy\<path>`.
- **Shell:** `wsl.exe -e bash -lc 'export PATH=$HOME/.cargo/bin:$PATH; cd ~/projects/mymitmproxy && <cmd>'`. Passwordless sudo is available for privileged tests.
- **Branch sync (do once before Task 1):** this plan + the v2 spec were committed in the Windows clone (`C:\projects\mymitmproxy`). Push that branch to `origin`, then in the WSL repo create the work branch from it:
  - In `C:\projects\mymitmproxy`: `git push -u origin HEAD`
  - In WSL: `git fetch origin && git checkout -b feat/v2-dataplane origin/ci-gitlab-build-test` (or whatever ref carries commit `78a549b`). Confirm `docs/superpowers/plans/2026-06-27-mymitm-v2-dataplane.md` is present in WSL before starting.
- When the plan says "read the aya source", it means the crate under `~/.cargo/registry/src/*/aya-0.13.1/` — the exact API names below were written against that version but **verify them against the source** as you implement (this codebase has hit aya API drift before).

---

## File structure

- `mymitm-common/src/lib.rs` — classifier match logic (`classify_tun`, `classify_eth`); host-unit-tested. (Task 1)
- `mymitm-ebpf/src/main.rs` — kernel programs; add `EGRESS` map + dynamic SNAT lookup. (Task 2)
- `mymitm/src/config.rs` — `Settings`, TOML/CLI, defaults; add `data_plane`, `attach_mode`, optional `target_client_ip`, `--cleanup`; inline defaults. (Task 3)
- `mymitm/src/dataplane.rs` — **new**: `DataPlane` trait + `DirectPlane` (test/debug). (Task 4)
- `mymitm/src/bpf.rs` — `BpfPlane`: implement `DataPlane`, take `EGRESS` map handle, per-conn insert; attach-mode (TCX/tc) + tc Drop teardown. (Tasks 4, 5)
- `mymitm/src/iproute.rs` — **new**: `IpRoutePlane` setup/upstream_socket/Drop. (Task 6)
- `mymitm/src/proxy.rs` — `run`/`handle_conn` take `Arc<dyn DataPlane>`; drop the free `upstream_socket`. (Task 7)
- `mymitm/src/main.rs` — build the selected plane, `--cleanup`, wire into `proxy::run`. (Task 7)
- `tests/integration/` — multi-client + iproute-mode e2e. (Task 8)
- 4.15 verifier validation via `lvh`. (Task 9)

---

## Task 1: Dynamic / wildcard classifier logic (`mymitm-common`)

**Files:**
- Modify: `mymitm-common/src/lib.rs:45-71` (`classify_tun`, `classify_eth`)
- Test: `mymitm-common/src/lib.rs` (`#[cfg(test)] mod tests`, currently `:81-134`)

**Interfaces:**
- Consumes: existing `Config`, `PktMeta`, `Rewrite` (unchanged shapes).
- Produces: same function signatures `classify_tun(&PktMeta,&Config,bool)->Rewrite` and `classify_eth(&PktMeta,&Config,bool)->Rewrite`, with new semantics:
  - `classify_tun` ingress matches when `dst==server:port` **and** (`cfg.client_ip==0` **or** `src==cfg.client_ip`); egress matches when `src==local:local_port` (no dst check).
  - `classify_eth` ingress matches when `src==server:port` (no dst check); egress unchanged (`mark==fwmark && dst==server:port`). The egress branch still only *signals* `SnatToClient`; the SNAT **target IP** is resolved in the eBPF program from the `EGRESS` map (Task 2), not here.

- [ ] **Step 1: Write the failing tests**

Add these tests inside the existing `mod tests` in `mymitm-common/src/lib.rs` (keep the existing `cfg()`/`meta()` helpers):

```rust
    // client_ip == 0 means "any client" -> wildcard DNAT on tun ingress.
    fn cfg_wild() -> Config {
        let mut c = cfg();
        c.client_ip = 0; // 0.0.0.0 wildcard
        c
    }

    #[test]
    fn tun_ingress_wildcard_dnats_any_client() {
        let c = cfg_wild();
        // two different clients, both hitting the target server -> both DNAT
        assert_eq!(classify_tun(&meta(("10.8.0.5",40000),("192.168.1.50",443),0), &c, false), Rewrite::DnatToLocal);
        assert_eq!(classify_tun(&meta(("10.8.0.99",40001),("192.168.1.50",443),0), &c, false), Rewrite::DnatToLocal);
    }

    #[test]
    fn tun_ingress_wildcard_ignores_other_server() {
        let c = cfg_wild();
        assert_eq!(classify_tun(&meta(("10.8.0.5",40000),("192.168.1.77",443),0), &c, false), Rewrite::None);
    }

    #[test]
    fn tun_ingress_restrict_mode_still_filters_client() {
        // client_ip set -> only that client is intercepted
        assert_eq!(classify_tun(&meta(("10.8.0.9",40000),("192.168.1.50",443),0), &cfg(), false), Rewrite::None);
        assert_eq!(classify_tun(&meta(("10.8.0.5",40000),("192.168.1.50",443),0), &cfg(), false), Rewrite::DnatToLocal);
    }

    #[test]
    fn tun_egress_undnats_reply_to_any_client() {
        // reply from our listener to ANY client dst -> un-DNAT (no dst==client check)
        let c = cfg_wild();
        assert_eq!(classify_tun(&meta(("127.0.0.1",8443),("10.8.0.99",40001),0), &c, true), Rewrite::UnDnatFromLocal);
    }

    #[test]
    fn eth_ingress_unsnats_reply_to_any_client() {
        // server reply to ANY client -> un-SNAT (no dst==client check)
        let c = cfg_wild();
        assert_eq!(classify_eth(&meta(("192.168.1.50",443),("10.8.0.99",51000),0), &c, false), Rewrite::UnSnatToBox);
    }
```

- [ ] **Step 2: Run tests, verify they fail**

Run: `wsl.exe -e bash -lc 'export PATH=$HOME/.cargo/bin:$PATH; cd ~/projects/mymitmproxy && cargo test -p mymitm-common --target x86_64-unknown-linux-gnu'`
Expected: the new tests FAIL (current code requires `src==client_ip` and `dst==client_ip`).

- [ ] **Step 3: Implement the new logic**

Replace `classify_tun` and `classify_eth` (`mymitm-common/src/lib.rs:45-71`) with:

```rust
pub fn classify_tun(m: &PktMeta, cfg: &Config, egress: bool) -> Rewrite {
    if !egress {
        // Ingress: any client (or the restricted one) -> target server gets DNAT'd.
        let client_ok = cfg.client_ip == 0 || m.src_ip == cfg.client_ip;
        if client_ok && m.dst_ip == cfg.server_ip && m.dst_port == cfg.server_port {
            return Rewrite::DnatToLocal;
        }
    } else if m.src_ip == cfg.local_ip && m.src_port == cfg.local_port {
        // Egress: any reply from our listener is ours -> un-DNAT back to server.
        return Rewrite::UnDnatFromLocal;
    }
    Rewrite::None
}

/// v2: client IP is dynamic. The egress branch signals SnatToClient; the SNAT
/// target IP is resolved by the eBPF program from the EGRESS map (box ephemeral
/// port -> client IP). The ingress branch matches purely on (src==server:port);
/// the UPSTREAM map lookup (keyed on the packet's own dst==client) decides whether
/// the reply is one of ours, so no client_ip condition is needed here.
pub fn classify_eth(m: &PktMeta, cfg: &Config, egress: bool) -> Rewrite {
    if egress {
        if m.mark == cfg.fwmark && m.dst_ip == cfg.server_ip && m.dst_port == cfg.server_port {
            return Rewrite::SnatToClient;
        }
    } else if m.src_ip == cfg.server_ip && m.src_port == cfg.server_port {
        return Rewrite::UnSnatToBox;
    }
    Rewrite::None
}
```

- [ ] **Step 4: Run tests, verify all pass**

Run: `wsl.exe -e bash -lc 'export PATH=$HOME/.cargo/bin:$PATH; cd ~/projects/mymitmproxy && cargo test -p mymitm-common --target x86_64-unknown-linux-gnu'`
Expected: PASS (the old `tun_ingress_other_client_untouched`, `tun_egress_reply_is_undnatted`, `eth_*` tests still pass; new ones pass).

- [ ] **Step 5: Commit**

```bash
git add mymitm-common/src/lib.rs
git commit -m "feat(common): wildcard/dynamic client matching in classifiers"
```

---

## Task 2: `EGRESS` map + dynamic SNAT lookup (`mymitm-ebpf`)

**Files:**
- Modify: `mymitm-ebpf/src/main.rs` (add `EGRESS` map near `:47`; rewrite `cls_eth_egress` `:225-250`)

**Interfaces:**
- Consumes: Task 1 classifier semantics; existing `set_src`, `meta`, `cfg`, `UPSTREAM`.
- Produces: a BPF map named **`EGRESS`** of type `LruHashMap<u16, u32>` (key = box ephemeral source port NBO, value = client IP NBO) that userspace (Task 4) writes. `cls_eth_egress` resolves the SNAT target from it.

- [ ] **Step 1: Add the `EGRESS` map**

In `mymitm-ebpf/src/main.rs`, after the `UPSTREAM` map declaration (`:47`), add:

```rust
/// Dynamic per-connection SNAT target, populated by userspace BEFORE it issues
/// the upstream connect(): key = the box's ephemeral source port (NBO), value =
/// the client IP (NBO) to SNAT that flow's source to. Read by `cls_eth_egress`.
/// LRU so a missed userspace delete can never wedge the map.
#[map]
static EGRESS: LruHashMap<u16, u32> = LruHashMap::with_max_entries(1024, 0);
```

- [ ] **Step 2: Rewrite `cls_eth_egress` to use the dynamic lookup**

Replace `cls_eth_egress` (`mymitm-ebpf/src/main.rs:225-250`) with:

```rust
#[classifier]
pub fn cls_eth_egress(mut ctx: TcContext) -> i32 {
    let (Some((m, l3, l4)), Some(c)) = (meta(&ctx), cfg()) else {
        return TC_ACT_OK;
    };
    if classify_eth(&m, &c, true) == Rewrite::SnatToClient {
        // Resolve the SNAT target client IP from the EGRESS map, keyed by our
        // own ephemeral source port (userspace inserted it before connect()).
        // If absent, leave the packet untouched (visible failure, never wrong IP).
        let client_ip = match unsafe { EGRESS.get(&m.src_port) } {
            Some(ip) => *ip,
            None => return TC_ACT_OK,
        };
        // Record the reverse mapping BEFORE rewriting so ingress replies un-SNAT.
        let key = UpstreamKey {
            server_ip: c.server_ip,
            client_ip,
            server_port: c.server_port,
            client_port: m.src_port,
        };
        let val = UpstreamVal { box_ip: c.box_ip, box_port: m.src_port };
        let _ = UPSTREAM.insert(&key, &val, 0);
        let _ = set_src(&mut ctx, l3, l4, client_ip, m.src_port);
    }
    TC_ACT_OK
}
```

(`cls_eth_ingress`, `cls_tun_ingress`, `cls_tun_egress` need no edits — their behavior changed via Task 1's `classify_*`.)

- [ ] **Step 3: Build the eBPF object + full workspace, verify it compiles**

Run: `wsl.exe -e bash -lc 'export PATH=$HOME/.cargo/bin:$PATH; cd ~/projects/mymitmproxy && cargo build -p mymitm --release 2>&1 | tail -30'`
Expected: builds successfully (build.rs compiles the eBPF crate and embeds the object). No host unit test exists for kernel code; verification is the compile here + the e2e in Task 8 + the verifier check in Task 9.

- [ ] **Step 4: Sanity-check it stayed BTF-free**

Run: `wsl.exe -e bash -lc 'cd ~/projects/mymitmproxy && f=$(find target -name mymitm -path "*OUT_DIR*" -o -path "*build*" -name "mymitm" 2>/dev/null | head -1); llvm-objdump -h "$(find target -name "*.o" -path "*mymitm-ebpf*" | head -1)" 2>/dev/null | grep -i btf || echo "checked"'`
Expected: confirm there is no `.BTF.ext` relocation section requiring kernel BTF (a `.BTF` section describing map types is fine and expected; what must NOT appear is CO-RE relocations against kernel structs). If CO-RE relocations appear, stop and investigate which field access introduced them. (Definitive validation is the 4.15 `lvh` load in Task 9.)

- [ ] **Step 5: Commit**

```bash
git add mymitm-ebpf/src/main.rs
git commit -m "feat(ebpf): EGRESS map + dynamic per-connection SNAT target"
```

---

## Task 3: Config — modes, optional client IP, inline defaults (`mymitm/src/config.rs`)

**Files:**
- Modify: `mymitm/src/config.rs` (whole file)

**Interfaces:**
- Produces:
  - `pub enum DataPlaneKind { Ebpf, IpRoute }` (serde: lowercase `"ebpf"`/`"iproute"`).
  - `pub enum AttachMode { Auto, Tcx, Tc }` (serde: lowercase).
  - `Settings` gains `pub data_plane: DataPlaneKind`, `pub attach_mode: AttachMode`, `pub cleanup: bool`; `client_ip` becomes `pub client_ip: Option<Ipv4Addr>`.
  - `to_bpf_config()` maps `client_ip: None` → `0` and `Some(ip)` → `u32::from(ip).to_be()`.
- Consumes: nothing new.

> **Note on the `client_ip` type change:** `bpf.rs` and `proxy.rs` tests currently set `client_ip: Ipv4Addr::...` in a literal `Settings { .. }`. Those callers are updated in Tasks 4/7. Within this task only `config.rs` must compile and its own tests pass.

- [ ] **Step 1: Write the failing tests**

Replace the `#[cfg(test)] mod tests` block in `config.rs` with (keeps existing cases, adds new):

```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> &'static str {
        r#"
            target_server_ip = "192.168.1.50"
            cert_path = "/x/leaf.pem"
            key_path = "/x/leaf.key"
            box_ip = "192.168.1.10"
        "#
    }

    #[test]
    fn defaults_and_optional_client_ip() {
        let s = Settings::from_toml_str(base()).unwrap();
        assert_eq!(s.client_ip, None);                 // omitted -> dynamic
        assert_eq!(s.server_port, 443);
        assert_eq!(s.tun_iface, "tun0");
        assert_eq!(s.fwmark, 0x1337);
        assert!(matches!(s.data_plane, DataPlaneKind::Ebpf));
        assert!(matches!(s.attach_mode, AttachMode::Auto));
    }

    #[test]
    fn client_ip_restrict_mode_parses() {
        let toml = format!("{}\ntarget_client_ip = \"10.8.0.5\"", base());
        let s = Settings::from_toml_str(&toml).unwrap();
        assert_eq!(s.client_ip, Some(Ipv4Addr::new(10,8,0,5)));
    }

    #[test]
    fn data_plane_and_attach_mode_parse() {
        let toml = format!("{}\ndata_plane = \"iproute\"\nattach_mode = \"tc\"", base());
        let s = Settings::from_toml_str(&toml).unwrap();
        assert!(matches!(s.data_plane, DataPlaneKind::IpRoute));
        assert!(matches!(s.attach_mode, AttachMode::Tc));
    }

    #[test]
    fn to_bpf_config_client_ip_zero_when_dynamic() {
        let s = Settings::from_toml_str(base()).unwrap();
        assert_eq!(s.to_bpf_config().client_ip, 0);
    }

    #[test]
    fn to_bpf_config_client_ip_set_is_nbo() {
        let toml = format!("{}\ntarget_client_ip = \"10.8.0.5\"", base());
        let s = Settings::from_toml_str(&toml).unwrap();
        assert_eq!(s.to_bpf_config().client_ip, u32::from(Ipv4Addr::new(10,8,0,5)).to_be());
        assert_eq!(s.to_bpf_config().server_port, 443u16.to_be());
    }

    #[test]
    fn missing_required_field_errors() {
        assert!(Settings::from_toml_str(r#"target_server_ip = "10.0.0.1""#).is_err());
    }
}
```

- [ ] **Step 2: Run tests, verify they fail**

Run: `wsl.exe -e bash -lc 'export PATH=$HOME/.cargo/bin:$PATH; cd ~/projects/mymitmproxy && cargo test -p mymitm --target x86_64-unknown-linux-gnu config 2>&1 | tail -30'`
Expected: compile error / FAIL (new fields/enums don't exist).

- [ ] **Step 3: Rewrite `config.rs`**

Replace the top of `config.rs` (the `FileCfg`, `d_*` fns, `Cli`, `Settings`, `from_toml_str`, `to_bpf_config`) with:

```rust
use std::net::Ipv4Addr;
use std::path::PathBuf;
use serde::Deserialize;
use clap::{Parser, ValueEnum};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum DataPlaneKind { Ebpf, IpRoute }
impl Default for DataPlaneKind { fn default() -> Self { DataPlaneKind::Ebpf } }

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum AttachMode { Auto, Tcx, Tc }
impl Default for AttachMode { fn default() -> Self { AttachMode::Auto } }

#[derive(Debug, Clone, Deserialize)]
struct FileCfg {
    target_server_ip: Ipv4Addr,
    cert_path: PathBuf,
    key_path: PathBuf,
    box_ip: Ipv4Addr,
    #[serde(default)] target_client_ip: Option<Ipv4Addr>,
    #[serde(default = "d_port")] target_server_port: u16,
    #[serde(default = "d_tun")] tun_iface: String,
    #[serde(default = "d_eth")] egress_iface: String,
    #[serde(default = "d_local_ip")] local_addr: Ipv4Addr,
    #[serde(default = "d_local_port")] local_port: u16,
    #[serde(default = "d_mark")] fwmark: u32,
    #[serde(default = "d_dump")] dump_path: PathBuf,
    #[serde(default = "d_obj")] bpf_obj_name: String,
    #[serde(default = "d_log")] log_level: String,
    #[serde(default)] data_plane: DataPlaneKind,
    #[serde(default)] attach_mode: AttachMode,
    #[serde(default)] server_name: Option<String>,
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
    /// Override target client IP (restrict to one client; omit for dynamic)
    #[arg(long)] client: Option<Ipv4Addr>,
    /// Override target server IP
    #[arg(long)] server: Option<Ipv4Addr>,
    /// Override tun interface
    #[arg(long)] tun: Option<String>,
    /// Override egress interface
    #[arg(long)] egress: Option<String>,
    /// Override data plane
    #[arg(long, value_enum)] data_plane: Option<DataPlaneKind>,
    /// Override attach mode (eBPF only)
    #[arg(long, value_enum)] attach_mode: Option<AttachMode>,
    /// Override upstream SNI hostname
    #[arg(long = "server-name")] server_name: Option<String>,
    /// Reverse any leftover state (stale clsact qdisc / iproute rules) from a
    /// previous unclean exit, then continue startup.
    #[arg(long, default_value_t = false)] cleanup: bool,
}

#[derive(Debug, Clone)]
pub struct Settings {
    pub client_ip: Option<Ipv4Addr>,
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
    pub server_name: Option<String>,
    pub data_plane: DataPlaneKind,
    pub attach_mode: AttachMode,
    pub cleanup: bool,
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
            server_name: f.server_name,
            data_plane: f.data_plane,
            attach_mode: f.attach_mode,
            cleanup: false,
        })
    }

    pub fn load() -> anyhow::Result<Settings> {
        let cli = Cli::parse();
        let text = std::fs::read_to_string(&cli.config)?;
        let mut s = Settings::from_toml_str(&text)?;
        if let Some(v) = cli.client { s.client_ip = Some(v); }
        if let Some(v) = cli.server { s.server_ip = v; }
        if let Some(v) = cli.tun { s.tun_iface = v; }
        if let Some(v) = cli.egress { s.egress_iface = v; }
        if let Some(v) = cli.data_plane { s.data_plane = v; }
        if let Some(v) = cli.attach_mode { s.attach_mode = v; }
        if let Some(v) = cli.server_name { s.server_name = Some(v); }
        s.cleanup = cli.cleanup;
        Ok(s)
    }

    pub fn to_bpf_config(&self) -> mymitm_common::Config {
        mymitm_common::Config {
            client_ip: self.client_ip.map(|ip| u32::from(ip).to_be()).unwrap_or(0),
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

> The "inline defaults (#3)" requirement: the CLI now uses inline `#[arg(default_value = ...)]` / `#[arg(default_value_t = ...)]` (see `config`, `cleanup`). TOML defaults stay as `#[serde(default = "...")]` because serde does not accept literal default values inline; the `d_*` fns are the idiomatic serde equivalent and are kept deliberately.

- [ ] **Step 4: Run tests, verify pass**

Run: `wsl.exe -e bash -lc 'export PATH=$HOME/.cargo/bin:$PATH; cd ~/projects/mymitmproxy && cargo test -p mymitm --target x86_64-unknown-linux-gnu config 2>&1 | tail -30'`
Expected: PASS. (Other crates may not yet compile if they reference `client_ip`; this command runs only `config` tests in the `mymitm` crate. If the crate fails to build because `bpf.rs`/`proxy.rs` reference the old `client_ip: Ipv4Addr`, temporarily run `cargo test -p mymitm config` after Task 4/7 — but config.rs itself must be correct now. To keep this task independently green, also do Step 5.)

- [ ] **Step 5: Add a clap CLI smoke test (proves clap derive is valid)**

Add to `config.rs` tests:

```rust
    #[test]
    fn cli_parses_value_enums() {
        use clap::Parser;
        let c = Cli::try_parse_from(["mymitm","--data-plane","iproute","--attach-mode","tcx","--cleanup"]).unwrap();
        assert!(matches!(c.data_plane, Some(DataPlaneKind::IpRoute)));
        assert!(matches!(c.attach_mode, Some(AttachMode::Tcx)));
        assert!(c.cleanup);
    }
```

Run the same test command; expected PASS.

- [ ] **Step 6: Commit**

```bash
git add mymitm/src/config.rs
git commit -m "feat(config): data_plane/attach_mode modes, optional client IP, --cleanup"
```

---

## Task 4: `DataPlane` trait + eBPF `upstream_socket` with `EGRESS` insert

**Files:**
- Create: `mymitm/src/dataplane.rs`
- Modify: `mymitm/src/bpf.rs` (struct fields, `load_and_attach`, impl `DataPlane`; take `EGRESS` map; update the privileged test's `Settings` literal + TOML)
- Modify: `mymitm/src/main.rs:1-4` (add `mod dataplane;`)

**Interfaces:**
- Produces:
  ```rust
  // dataplane.rs
  pub trait DataPlane: Send + Sync {
      /// Open the upstream socket for one intercepted connection, carrying the
      /// client's source IP by the mode's mechanism.
      fn upstream_socket(&self, client_ip: std::net::Ipv4Addr, server: std::net::SocketAddrV4)
          -> std::io::Result<std::net::TcpStream>;
  }
  pub struct DirectPlane; // test/debug: plain connect, ignores client_ip
  ```
- Consumes: Task 3 `Settings` (`client_ip: Option`, `attach_mode`), Task 2 `EGRESS` map name.
- `BpfPlane` now implements `DataPlane`; its `upstream_socket` binds `box_ip:0`, sets `SO_MARK`, inserts `EGRESS[box_port]=client_ip` (NBO), then connects.

- [ ] **Step 1: Create `dataplane.rs` with the trait + `DirectPlane` and a test**

Create `mymitm/src/dataplane.rs`:

```rust
//! Data-plane abstraction. Both the eBPF and iproute planes implement
//! `DataPlane::upstream_socket`, which opens the per-connection upstream socket
//! carrying the client's source IP by that plane's mechanism. Each concrete
//! plane reverses all kernel state it installs in its own `Drop`.

use std::io;
use std::net::{Ipv4Addr, SocketAddrV4, TcpStream};

pub trait DataPlane: Send + Sync {
    fn upstream_socket(&self, client_ip: Ipv4Addr, server: SocketAddrV4) -> io::Result<TcpStream>;
}

/// Plain `connect()` with no source-IP preservation. Used by the loopback proxy
/// unit test (no kernel plumbing) and as a `--data-plane`-less debug path.
pub struct DirectPlane;

impl DataPlane for DirectPlane {
    fn upstream_socket(&self, _client_ip: Ipv4Addr, server: SocketAddrV4) -> io::Result<TcpStream> {
        let s = TcpStream::connect(server)?;
        s.set_nonblocking(true)?;
        Ok(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;

    #[test]
    fn direct_plane_connects_and_roundtrips() {
        let l = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let addr = match l.local_addr().unwrap() { std::net::SocketAddr::V4(a) => a, _ => unreachable!() };
        let h = std::thread::spawn(move || {
            let (mut c, _) = l.accept().unwrap();
            let mut b = [0u8; 4]; c.read_exact(&mut b).unwrap();
            c.write_all(&b).unwrap();
        });
        let s = DirectPlane.upstream_socket(Ipv4Addr::new(10,8,0,5), addr).unwrap();
        s.set_nonblocking(false).unwrap();
        let mut s = s;
        s.write_all(b"ping").unwrap();
        let mut b = [0u8; 4]; s.read_exact(&mut b).unwrap();
        assert_eq!(&b, b"ping");
        h.join().unwrap();
    }
}
```

Add `mod dataplane;` to `mymitm/src/main.rs` (with the other `mod` lines at `:1-4`).

- [ ] **Step 2: Run the DirectPlane test, verify it passes**

Run: `wsl.exe -e bash -lc 'export PATH=$HOME/.cargo/bin:$PATH; cd ~/projects/mymitmproxy && cargo test -p mymitm --target x86_64-unknown-linux-gnu dataplane 2>&1 | tail -20'`
Expected: PASS. (If the `mymitm` crate fails to compile due to `bpf.rs` still using old `client_ip`, proceed to Step 3 which fixes `bpf.rs`, then re-run.)

- [ ] **Step 3: Make `BpfPlane` implement `DataPlane` and hold the `EGRESS` map**

In `mymitm/src/bpf.rs`:

a) Update imports (top of file):

```rust
use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::Mutex;

use aya::maps::{Array, HashMap as AyaHashMap, MapData};
use aya::programs::{SchedClassifier, TcAttachType};
use aya::{Ebpf, EbpfLoader};
use mymitm_common::Config;

use crate::config::Settings;
use crate::dataplane::DataPlane;
```

b) Replace the `BpfPlane` struct with one that also owns the `EGRESS` map and the box IP/fwmark needed per connection:

```rust
pub struct BpfPlane {
    #[allow(dead_code)]
    ebpf: Ebpf,
    #[allow(dead_code)]
    tun: String,
    #[allow(dead_code)]
    egress_iface: String,
    box_ip: Ipv4Addr,
    fwmark: u32,
    /// EGRESS map: box ephemeral src port (NBO) -> client IP (NBO). Written per
    /// connection just before connect() so cls_eth_egress can SNAT correctly.
    egress_map: Mutex<AyaHashMap<MapData, u16, u32>>,
}
```

c) In `load_and_attach`, after populating `CONFIG` and before attaching programs, take the `EGRESS` map out of the `Ebpf`:

```rust
        // Take ownership of the EGRESS map so userspace can write it per-conn.
        let egress_map: AyaHashMap<MapData, u16, u32> = AyaHashMap::try_from(
            ebpf.take_map("EGRESS")
                .ok_or_else(|| anyhow::anyhow!("EGRESS map not found in eBPF object"))?,
        )?;
```

   Then build the returned struct:

```rust
        Ok(BpfPlane {
            ebpf,
            tun: s.tun_iface.clone(),
            egress_iface: s.egress_iface.clone(),
            box_ip: s.box_ip,
            fwmark: s.fwmark,
            egress_map: Mutex::new(egress_map),
        })
```

   (The `Drop` impl can keep its current debug log for now; Task 5 adds tc teardown.)

d) Add the `DataPlane` impl at the end of `bpf.rs` (this absorbs the logic of the old `proxy::upstream_socket`, now binding the box IP and writing `EGRESS`):

```rust
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
```

e) Update the **privileged test** in `bpf.rs` (`:162-172`): the TOML there sets `target_client_ip = "10.8.0.5"` — keep it (restrict mode is still valid). No type change needed since it uses `from_toml_str`. Leave the test otherwise as-is.

- [ ] **Step 4: Add `socket2` to `mymitm` deps if not already present**

Check: `wsl.exe -e bash -lc 'cd ~/projects/mymitmproxy && grep -n socket2 mymitm/Cargo.toml'`
Expected: it is already a dependency (used by the old `upstream_socket`). If missing, add `socket2 = { version = "0.5", features = ["all"] }`.

- [ ] **Step 5: Build the crate (host target), verify it compiles**

Run: `wsl.exe -e bash -lc 'export PATH=$HOME/.cargo/bin:$PATH; cd ~/projects/mymitmproxy && cargo build -p mymitm --target x86_64-unknown-linux-gnu 2>&1 | tail -30'`
Expected: compile FAILS only in `proxy.rs`/`main.rs` (they still call the removed free `upstream_socket` / old `run` signature) — that is expected and fixed in Task 7. `bpf.rs` and `dataplane.rs` themselves must compile clean. If errors are confined to `proxy.rs`/`main.rs`, proceed.

> If you prefer a fully-green checkpoint here, do Task 7 immediately after this task before running the full build/tests. Tasks 4 and 7 are the matched pair that swap the proxy onto the trait.

- [ ] **Step 6: Commit**

```bash
git add mymitm/src/dataplane.rs mymitm/src/bpf.rs mymitm/src/main.rs
git commit -m "feat(dataplane): DataPlane trait + eBPF upstream_socket with EGRESS insert"
```

---

## Task 5: Attach mode — TCX / tc(clsact) with auto-fallback + tc teardown (`mymitm/src/bpf.rs`)

**Files:**
- Modify: `mymitm/src/bpf.rs` (`load_and_attach` attach loop; `Drop`; add an `attached_tc: bool` + iface list for teardown)

**Interfaces:**
- Consumes: Task 3 `Settings.attach_mode` (`Auto|Tcx|Tc`).
- Produces: attachment that works on kernel 4.15 (clsact+tc-bpf) through 6.6+ (TCX). In `tc` mode, `Drop` removes the clsact qdisc.

> **Read first:** `~/.cargo/registry/src/*/aya-0.13.1/src/programs/tc.rs`. Confirm the exact items: `SchedClassifier::attach`, `SchedClassifier::attach_with_options`, the `TcAttachOptions` enum (expected variants `Netlink(..)` and a TCX variant taking a `LinkOrder`), and the qdisc helper (expected `aya::programs::tc::qdisc_add_clsact(iface)` and `qdisc_detach_program` / a clsact removal helper). Adjust the code below to the real names. The semantics to achieve are fixed even if names differ.

- [ ] **Step 1: Implement mode-aware attach**

Replace the attach loop in `load_and_attach` (`mymitm/src/bpf.rs:84-97`) with a helper call, and add the helper. Pass `s.attach_mode` in. Expected shape:

```rust
use crate::config::AttachMode;
use aya::programs::tc::{self, TcAttachOptions};

/// Attach one classifier honoring the requested mode. Returns true if it was
/// attached via the legacy clsact/tc path (so Drop knows to remove the qdisc).
fn attach_one(
    prog: &mut SchedClassifier,
    iface: &str,
    dir: TcAttachType,
    mode: AttachMode,
) -> anyhow::Result<bool> {
    match mode {
        // TCX only (kernel >= 6.6). Fails on old kernels — that's intended.
        AttachMode::Tcx => {
            prog.attach(iface, dir)
                .map_err(|e| anyhow::anyhow!("tcx attach {iface} {dir:?}: {e}"))?;
            Ok(false)
        }
        // Legacy clsact + tc-bpf (works on 4.x..6.x). Ensure the qdisc exists.
        AttachMode::Tc => {
            let _ = tc::qdisc_add_clsact(iface); // idempotent; ignore "exists"
            prog.attach_with_options(iface, dir, TcAttachOptions::Netlink(Default::default()))
                .map_err(|e| anyhow::anyhow!("tc attach {iface} {dir:?}: {e}"))?;
            Ok(true)
        }
        // Auto: try TCX, fall back to clsact+tc on failure (old kernel).
        AttachMode::Auto => match prog.attach(iface, dir) {
            Ok(_) => Ok(false),
            Err(e) => {
                tracing::warn!("TCX attach failed ({e}); falling back to clsact+tc on {iface} {dir:?}");
                let _ = tc::qdisc_add_clsact(iface);
                prog.attach_with_options(iface, dir, TcAttachOptions::Netlink(Default::default()))
                    .map_err(|e| anyhow::anyhow!("tc fallback attach {iface} {dir:?}: {e}"))?;
                Ok(true)
            }
        },
    }
}
```

In `load_and_attach`, track whether any attach used the tc path and which ifaces, so `Drop` can clean up:

```rust
        let mut used_tc = false;
        for (name, side, dir) in PROGRAMS {
            let iface = match side { Side::Tun => &s.tun_iface, Side::Eth => &s.egress_iface };
            let prog: &mut SchedClassifier = ebpf
                .program_mut(name)
                .ok_or_else(|| anyhow::anyhow!("program {name} not found"))?
                .try_into()?;
            prog.load().map_err(|e| anyhow::anyhow!("load {name}: {e}"))?;
            used_tc |= attach_one(prog, iface, dir, s.attach_mode)?;
        }
```

Add `used_tc: bool` to the `BpfPlane` struct and set it in the returned value.

- [ ] **Step 2: tc-mode teardown in `Drop`**

Replace `impl Drop for BpfPlane` so it removes the clsact qdisc on both ifaces when the tc path was used (TCX path still needs nothing):

```rust
impl Drop for BpfPlane {
    fn drop(&mut self) {
        if self.used_tc {
            // Legacy tc path: links do NOT auto-detach. Remove the clsact qdisc
            // (which drops both ingress+egress filters) on each iface.
            for iface in [self.tun.as_str(), self.egress_iface.as_str()] {
                if let Err(e) = aya::programs::tc::qdisc_detach_program_all_or_remove(iface) {
                    tracing::warn!("clsact teardown on {iface} failed: {e}");
                }
            }
            tracing::debug!("BpfPlane (tc) dropped; clsact qdisc removed");
        } else {
            tracing::debug!("BpfPlane (TCX) dropped; links released, auto-detach");
        }
    }
}
```

> The exact clsact-removal call may differ in aya 0.13 (it might be `tc::qdisc_detach_program` per (iface,attach_type,name), or you may need the `netlink`/`tc` helper to delete the clsact qdisc). Use whatever the source provides to **remove the clsact qdisc entirely** on the iface; if only per-program detach exists, detach all four. Verify against the aya source you read in the preamble.

- [ ] **Step 3: Add a static `--cleanup`-style helper for stale tc state**

Add a free function (used by Task 7's `--cleanup`):

```rust
/// Best-effort removal of any clsact qdisc this tool may have left on the given
/// interfaces after an unclean exit. Safe to call when nothing is attached.
pub fn cleanup_tc(tun: &str, egress: &str) {
    for iface in [tun, egress] {
        let _ = aya::programs::tc::qdisc_detach_program_all_or_remove(iface);
    }
}
```

(Match the real aya helper name as in Step 2.)

- [ ] **Step 4: Build, verify it compiles**

Run: `wsl.exe -e bash -lc 'export PATH=$HOME/.cargo/bin:$PATH; cd ~/projects/mymitmproxy && cargo build -p mymitm --target x86_64-unknown-linux-gnu 2>&1 | tail -30'`
Expected: `bpf.rs` compiles (errors still only in `proxy.rs`/`main.rs` until Task 7).

- [ ] **Step 5: Extend the privileged attach test to also cover tc mode**

In the `bpf.rs` test module, add an `#[ignore]` test that forces `attach_mode = Tc`, attaches on the temp `mmtun0`/`mmeth0`, asserts attachment via the legacy query (`tc filter show dev mmtun0 ingress` via `Command`, grep for the prog), drops the plane, and asserts the clsact qdisc is gone (`tc qdisc show dev mmtun0` no longer lists `clsact`). Mirror the structure of `loads_attaches_and_cleans_up`. Build it (it only runs under `--ignored` + sudo; it will actually be exercised in Task 9 on the 4.15 box and optionally on WSL):

```rust
    #[test]
    #[ignore]
    fn tc_mode_attaches_and_removes_clsact() {
        use std::process::Command;
        run_ip(&["link","del","mmtun0"]); run_ip(&["link","del","mmeth0"]);
        run_ip(&["tuntap","add","dev","mmtun0","mode","tun"]); run_ip(&["link","set","mmtun0","up"]);
        run_ip(&["link","add","mmeth0","type","dummy"]); run_ip(&["link","set","mmeth0","up"]);
        let s = Settings::from_toml_str(r#"
            target_server_ip = "192.168.1.50"
            cert_path = "/x"
            key_path = "/y"
            box_ip = "192.168.1.10"
            tun_iface = "mmtun0"
            egress_iface = "mmeth0"
            attach_mode = "tc"
        "#).unwrap();
        {
            let _plane = BpfPlane::load_and_attach(&s).expect("tc attach");
            let out = Command::new("tc").args(["qdisc","show","dev","mmtun0"]).output().unwrap();
            assert!(String::from_utf8_lossy(&out.stdout).contains("clsact"), "clsact qdisc expected");
            println!("TC_ATTACH_OK");
        }
        let out = Command::new("tc").args(["qdisc","show","dev","mmtun0"]).output().unwrap();
        assert!(!String::from_utf8_lossy(&out.stdout).contains("clsact"), "clsact must be removed on drop");
        println!("TC_DETACH_OK");
        run_ip(&["link","del","mmtun0"]); run_ip(&["link","del","mmeth0"]);
    }
```

- [ ] **Step 6: Commit**

```bash
git add mymitm/src/bpf.rs
git commit -m "feat(bpf): attach_mode auto/tcx/tc with clsact fallback + teardown"
```

---

## Task 6: iproute (non-eBPF) data plane (`mymitm/src/iproute.rs`)

**Files:**
- Create: `mymitm/src/iproute.rs`
- Modify: `mymitm/src/main.rs` (add `mod iproute;`)

**Interfaces:**
- Consumes: Task 3 `Settings`, Task 4 `DataPlane` trait.
- Produces: `pub struct IpRoutePlane` with `pub fn setup(s: &Settings) -> anyhow::Result<IpRoutePlane>`, `impl DataPlane` (IP_TRANSPARENT bind-to-client + SO_MARK + connect), `impl Drop` (reverse every rule/route/sysctl), and `pub fn cleanup(s: &Settings)` (best-effort reverse of leftovers).

> **Mechanism (from spec §"ip-route mode"):** one fixed routing table id derived from fwmark (e.g. `table = 100 + (fwmark & 0xff)`), used for both the `ip rule` and the local route. All shell-outs go through a small `run(cmd,args) -> Result` helper that logs the command; teardown ignores errors. The intercept rule is tagged implicitly by its exact match (tun iface + server + port), so cleanup deletes that exact rule.

- [ ] **Step 1: Write the `IpRoutePlane` skeleton + a unit test for the rule-spec builder**

Create `mymitm/src/iproute.rs`. Split the *rule specification* (pure, testable) from *execution* (shell-out). Test the spec builder without root:

```rust
//! Non-eBPF data plane: visible iproute2/iptables/sysctl plumbing achieving the
//! same DNAT-to-local + client-source-IP preservation. NOT stealthy by design.
//! Every action is reversed in Drop (and by `cleanup`).

use std::net::{Ipv4Addr, SocketAddrV4, TcpStream};
use std::process::Command;

use crate::config::Settings;
use crate::dataplane::DataPlane;

/// The exact CLI invocations this plane installs, in apply order. Each entry is
/// (program, add-args, delete-args) so teardown is the precise inverse. Pure /
/// no side effects — unit tested.
pub struct RuleSet {
    pub table: u32,
    pub items: Vec<(&'static str, Vec<String>, Vec<String>)>,
}

fn s(v: &str) -> String { v.to_string() }

pub fn build_ruleset(cfg: &Settings) -> RuleSet {
    let table = 100 + (cfg.fwmark & 0xff);
    let server = cfg.server_ip.to_string();
    let port = cfg.server_port.to_string();
    let local = format!("{}:{}", cfg.local_ip, cfg.local_port);
    let mark = cfg.fwmark.to_string();
    let tbl = table.to_string();
    let items = vec![
        // intercept: DNAT client->server to the local listener on the tun iface
        ("iptables", vec![s("-t"),s("nat"),s("-A"),s("PREROUTING"),s("-i"),cfg.tun_iface.clone(),
            s("-p"),s("tcp"),s("-d"),server.clone(),s("--dport"),port.clone(),
            s("-j"),s("DNAT"),s("--to-destination"),local.clone()],
         vec![s("-t"),s("nat"),s("-D"),s("PREROUTING"),s("-i"),cfg.tun_iface.clone(),
            s("-p"),s("tcp"),s("-d"),server.clone(),s("--dport"),port.clone(),
            s("-j"),s("DNAT"),s("--to-destination"),local.clone()]),
        // reply capture: marked replies to (spoofed) client IPs delivered locally
        ("ip", vec![s("rule"),s("add"),s("fwmark"),mark.clone(),s("lookup"),tbl.clone()],
               vec![s("rule"),s("del"),s("fwmark"),mark.clone(),s("lookup"),tbl.clone()]),
        ("ip", vec![s("route"),s("add"),s("local"),s("0.0.0.0/0"),s("dev"),s("lo"),s("table"),tbl.clone()],
               vec![s("route"),s("del"),s("local"),s("0.0.0.0/0"),s("dev"),s("lo"),s("table"),tbl.clone()]),
    ];
    RuleSet { table, items }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    fn settings() -> Settings {
        Settings {
            client_ip: None,
            server_ip: Ipv4Addr::new(192,168,1,50), server_port: 443,
            tun_iface: "tun0".into(), egress_iface: "eth0".into(),
            local_ip: Ipv4Addr::LOCALHOST, local_port: 8443, fwmark: 0x1337,
            cert_path: PathBuf::from("/x"), key_path: PathBuf::from("/y"),
            dump_path: PathBuf::from("/tmp"), bpf_obj_name: "mymitm".into(),
            box_ip: Ipv4Addr::new(192,168,1,10), log_level: "info".into(), server_name: None,
            data_plane: crate::config::DataPlaneKind::IpRoute,
            attach_mode: crate::config::AttachMode::Auto, cleanup: false,
        }
    }
    #[test]
    fn ruleset_table_from_fwmark_and_inverse_pairs() {
        let rs = build_ruleset(&settings());
        assert_eq!(rs.table, 100 + 0x37);
        // every add has a matching delete that differs only by the add/del verb
        for (_p, add, del) in &rs.items {
            assert!(add.iter().any(|a| a=="-A" || a=="add") );
            assert!(del.iter().any(|d| d=="-D" || d=="del") );
            assert_eq!(add.len(), del.len());
        }
    }
    #[test]
    fn ruleset_dnat_targets_local_listener() {
        let rs = build_ruleset(&settings());
        let (_p, add, _del) = &rs.items[0];
        assert!(add.contains(&"127.0.0.1:8443".to_string()));
        assert!(add.contains(&"tun0".to_string()));
    }
}
```

- [ ] **Step 2: Run the spec-builder tests, verify pass**

Run: `wsl.exe -e bash -lc 'export PATH=$HOME/.cargo/bin:$PATH; cd ~/projects/mymitmproxy && cargo test -p mymitm --target x86_64-unknown-linux-gnu iproute 2>&1 | tail -20'`
Expected: PASS (after adding `mod iproute;` to `main.rs`). Build errors confined to `proxy.rs`/`main.rs` are still acceptable until Task 7 — run with `--lib` if needed to isolate.

- [ ] **Step 3: Implement setup / DataPlane / Drop / cleanup**

Append to `iproute.rs`:

```rust
fn run(prog: &str, args: &[String]) -> std::io::Result<()> {
    tracing::debug!("iproute: {prog} {}", args.join(" "));
    let st = Command::new(prog).args(args).status()?;
    if !st.success() {
        return Err(std::io::Error::new(std::io::ErrorKind::Other,
            format!("{prog} {:?} exited {st}", args)));
    }
    Ok(())
}

/// A sysctl we set and must restore. `path` is the /proc/sys key in dotted form.
struct SavedSysctl { key: String, original: String }

pub struct IpRoutePlane {
    rules: RuleSet,
    fwmark: u32,
    saved: Vec<SavedSysctl>,
}

fn read_sysctl(key: &str) -> Option<String> {
    let p = format!("/proc/sys/{}", key.replace('.', "/"));
    std::fs::read_to_string(p).ok().map(|s| s.trim().to_string())
}
fn write_sysctl(key: &str, val: &str) -> std::io::Result<()> {
    let p = format!("/proc/sys/{}", key.replace('.', "/"));
    std::fs::write(p, val)
}

impl IpRoutePlane {
    pub fn setup(s: &Settings) -> anyhow::Result<IpRoutePlane> {
        let mut saved = Vec::new();
        // sysctls: ip_forward=1, rp_filter=0 on tun, route_localnet=1 on tun.
        for (key, want) in [
            ("net.ipv4.ip_forward".to_string(), "1"),
            (format!("net.ipv4.conf.{}.rp_filter", s.tun_iface), "0"),
            (format!("net.ipv4.conf.{}.route_localnet", s.tun_iface), "1"),
        ] {
            if let Some(orig) = read_sysctl(&key) {
                if orig != want {
                    write_sysctl(&key, want)
                        .map_err(|e| anyhow::anyhow!("set {key}={want}: {e}"))?;
                    saved.push(SavedSysctl { key, original: orig });
                }
            }
        }
        let rules = build_ruleset(s);
        // Apply rules in order; on any failure, reverse what we've applied.
        let mut applied = 0usize;
        for (prog, add, _del) in &rules.items {
            if let Err(e) = run(prog, add) {
                // roll back
                for (p2, _a2, d2) in rules.items[..applied].iter().rev() { let _ = run(p2, d2); }
                for sv in saved.iter().rev() { let _ = write_sysctl(&sv.key, &sv.original); }
                return Err(anyhow::anyhow!("apply {prog} failed: {e}"));
            }
            applied += 1;
        }
        tracing::info!("iproute data plane installed (table {})", rules.table);
        Ok(IpRoutePlane { rules, fwmark: s.fwmark, saved })
    }
}

impl DataPlane for IpRoutePlane {
    fn upstream_socket(&self, client_ip: Ipv4Addr, server: SocketAddrV4) -> std::io::Result<TcpStream> {
        let sock = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::STREAM, Some(socket2::Protocol::TCP))?;
        // IP_TRANSPARENT lets us bind a non-local (client) source address.
        sock.set_ip_transparent(true)?;
        sock.set_reuse_address(true)?;
        if self.fwmark != 0 { sock.set_mark(self.fwmark)?; }
        // Bind to the dynamic client IP (ephemeral port) -> packets egress with
        // src = client_ip; the fwmark rule routes the replies back to us.
        sock.bind(&SocketAddrV4::new(client_ip, 0).into())?;
        sock.connect(&server.into())?;
        sock.set_nonblocking(true)?;
        Ok(sock.into())
    }
}

impl Drop for IpRoutePlane {
    fn drop(&mut self) {
        for (prog, _add, del) in self.rules.items.iter().rev() { let _ = run(prog, del); }
        for sv in self.saved.iter().rev() { let _ = write_sysctl(&sv.key, &sv.original); }
        tracing::debug!("iproute data plane torn down");
    }
}

/// Best-effort reverse of leftovers from an unclean exit (matches what setup adds).
pub fn cleanup(s: &Settings) {
    let rules = build_ruleset(s);
    for (prog, _add, del) in rules.items.iter().rev() { let _ = run(prog, del); }
}
```

> `socket2::Socket::set_ip_transparent` exists in socket2 0.5 (Linux). Verify; if named differently, set `IP_TRANSPARENT` via `setsockopt`. `set_mark` is already used elsewhere.

- [ ] **Step 4: Build, verify `iproute.rs` compiles**

Run: `wsl.exe -e bash -lc 'export PATH=$HOME/.cargo/bin:$PATH; cd ~/projects/mymitmproxy && cargo build -p mymitm --target x86_64-unknown-linux-gnu 2>&1 | tail -30'`
Expected: `iproute.rs` compiles (remaining errors only in `proxy.rs`/`main.rs`).

- [ ] **Step 5: Commit**

```bash
git add mymitm/src/iproute.rs mymitm/src/main.rs
git commit -m "feat(iproute): IP_TRANSPARENT + policy-routing data plane with teardown"
```

---

## Task 7: Wire the proxy + main onto `DataPlane` (`proxy.rs`, `main.rs`)

**Files:**
- Modify: `mymitm/src/proxy.rs` (remove free `upstream_socket` `:177-195`; `run`/`handle_conn` take `Arc<dyn DataPlane>`; loopback test uses `DirectPlane`; `settings_for` updates `client_ip` to `Option`)
- Modify: `mymitm/src/main.rs` (build the selected plane, `--cleanup`, pass plane to `run`)

**Interfaces:**
- Consumes: Task 4 `DataPlane`/`DirectPlane`, `BpfPlane: DataPlane`; Task 6 `IpRoutePlane`; Task 3 `Settings.{data_plane,attach_mode,cleanup,client_ip:Option}`.
- Produces: `pub async fn run(s: Arc<Settings>, dumper: Arc<Dumper>, plane: Arc<dyn DataPlane>) -> anyhow::Result<()>`.

- [ ] **Step 1: Update `proxy.rs`**

a) Remove the free `pub fn upstream_socket(...)` (`:177-195`) entirely (its logic now lives in `BpfPlane`/`IpRoutePlane`).

b) Add `use crate::dataplane::DataPlane;` and `use std::net::SocketAddrV4;`.

c) Change `run`'s signature and the spawn to thread the plane through:

```rust
pub async fn run(
    s: Arc<Settings>,
    dumper: Arc<Dumper>,
    plane: Arc<dyn DataPlane>,
) -> anyhow::Result<()> {
    ensure_crypto_provider();
    let server_cfg = load_server_tls(&s.cert_path, &s.key_path)?;
    let acceptor = TlsAcceptor::from(server_cfg);
    let connector = build_upstream_connector(&s)?;

    let listener = TcpListener::bind((s.local_ip, s.local_port)).await?;
    tracing::info!("proxy listening on {}:{}", s.local_ip, s.local_port);

    loop {
        let (inbound, peer) = match listener.accept().await {
            Ok(pair) => pair,
            Err(e) => { tracing::warn!("accept error (continuing): {e}"); continue; }
        };
        let acceptor = acceptor.clone();
        let connector = connector.clone();
        let s = s.clone();
        let dumper = dumper.clone();
        let plane = plane.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_conn(inbound, peer, acceptor, connector, s, dumper, plane).await {
                tracing::warn!("conn {peer} ended: {e}");
            }
        });
    }
}
```

d) Update `handle_conn` to take the plane and use it (the client IP is the accepted peer's IP):

```rust
async fn handle_conn(
    inbound: TcpStream,
    peer: SocketAddr,
    acceptor: TlsAcceptor,
    connector: TlsConnector,
    s: Arc<Settings>,
    dumper: Arc<Dumper>,
    plane: Arc<dyn DataPlane>,
) -> anyhow::Result<()> {
    let client_tls = acceptor.accept(inbound).await?;

    // The accepted socket's peer IS the real client (DNAT rewrote only the dst),
    // so its IP is what the upstream leg must carry.
    let client_ip = match peer.ip() {
        std::net::IpAddr::V4(v4) => v4,
        std::net::IpAddr::V6(_) => anyhow::bail!("ipv6 client unsupported in v1"),
    };
    let server_addr = SocketAddrV4::new(s.server_ip, s.server_port);
    let std_up = plane.upstream_socket(client_ip, server_addr)?;
    let up = TcpStream::from_std(std_up)?;
    let server_name = upstream_server_name(&s)?;
    let server_tls = connector.connect(server_name, up).await?;

    let server_sa = SocketAddr::from((s.server_ip, s.server_port));
    let mut conn = dumper.open_conn(peer, server_sa);
    // ... (unchanged split/pump/finish body from current handle_conn) ...
```

Keep the rest of `handle_conn` (the `tokio::io::split` pump loop + `conn.finish`) exactly as-is.

e) In the test module: update `settings_for` so `client_ip: None` (it is unused by `DirectPlane`), and change the two `handle_conn(...)` test call sites to pass a plane:

```rust
    // in settings_for: client_ip: None,
    // in loopback_roundtrip_with_dump, replace the handle_conn spawn body:
    use crate::dataplane::DirectPlane;
    let plane: std::sync::Arc<dyn crate::dataplane::DataPlane> = std::sync::Arc::new(DirectPlane);
    // ...
    handle_conn(inbound, peer, acceptor, connector, settings, dumper, plane).await.unwrap();
```

The `pin_verifier_rejects_wrong_cert` test calls `connector.connect` directly (not `handle_conn`) and needs no plane; just fix its `settings_for` via the `client_ip: None` change.

- [ ] **Step 2: Update `main.rs` to build the selected plane + handle `--cleanup`**

Replace the body of `main()` (`mymitm/src/main.rs:8-39`) so it selects the plane:

```rust
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

    proxy::ensure_crypto_provider();
    let dumper = Arc::new(dump::Dumper::new(&settings.dump_path)?);

    // Build the chosen data plane. Each concrete plane holds its kernel state and
    // reverses it on Drop, so we keep it alive (`_plane`) for the whole run.
    use crate::dataplane::DataPlane;
    let (plane, _guard): (Arc<dyn DataPlane>, Box<dyn std::any::Any>) = match settings.data_plane {
        config::DataPlaneKind::Ebpf => {
            let p = Arc::new(bpf::BpfPlane::load_and_attach(&settings)?);
            (p.clone() as Arc<dyn DataPlane>, Box::new(p))
        }
        config::DataPlaneKind::IpRoute => {
            let p = Arc::new(iproute::IpRoutePlane::setup(&settings)?);
            (p.clone() as Arc<dyn DataPlane>, Box::new(p))
        }
    };

    tracing::info!(?settings.data_plane, "data plane active; entering proxy loop");

    let settings = Arc::new(settings);
    tokio::select! {
        r = proxy::run(settings.clone(), dumper.clone(), plane.clone()) => { r?; }
        _ = shutdown_signal() => { tracing::info!("shutdown signal; detaching"); }
    }
    // `_guard` (the Arc holding the concrete plane) drops here -> Drop tears down.
    Ok(())
}
```

> Why the `_guard` Box: `Arc<dyn DataPlane>` would also run `Drop`, but we want the concrete type's `Drop` to run while we still hold the only strong refs. Holding both the trait-object `Arc` and the concrete `Arc` and dropping at end of `main` is sufficient; the `Box<dyn Any>` simply keeps the concrete `Arc` named/alive. (If simpler, store `let plane = Arc::new(...)` once and `plane.clone() as Arc<dyn DataPlane>` for `run`; ensure the last drop happens at end of `main`.)

- [ ] **Step 3: Full host test suite**

Run: `wsl.exe -e bash -lc 'export PATH=$HOME/.cargo/bin:$PATH; cd ~/projects/mymitmproxy && cargo test -p mymitm-common -p mymitm --target x86_64-unknown-linux-gnu 2>&1 | tail -40'`
Expected: ALL non-ignored tests PASS (common classifiers, config, dataplane DirectPlane, iproute ruleset, proxy loopback round-trip + pin reject).

- [ ] **Step 4: Static release build + ldd**

Run: `wsl.exe -e bash -lc 'export PATH=$HOME/.cargo/bin:$PATH; cd ~/projects/mymitmproxy && cargo build -p mymitm --release 2>&1 | tail -15 && ldd target/x86_64-unknown-linux-musl/release/mymitm; file target/x86_64-unknown-linux-musl/release/mymitm'`
Expected: builds; `ldd` prints "not a dynamic executable" (or "statically linked"); `file` shows "statically linked".

- [ ] **Step 5: Commit**

```bash
git add mymitm/src/proxy.rs mymitm/src/main.rs
git commit -m "feat(proxy): drive upstream via DataPlane; main selects ebpf/iproute + --cleanup"
```

---

## Task 8: End-to-end — multi-client + iproute mode (`tests/integration/`)

**Files:**
- Modify: `tests/integration/run_e2e.sh`, `tests/integration/fake_server.py`, `tests/integration/client.py` (extend; keep the existing single-client eBPF assertions working)
- Create: `tests/integration/run_e2e_iproute.sh` (or a `MODE` env switch in `run_e2e.sh`)

**Interfaces:** none (shell/python harness). Asserts the four invariants per the spec, now for two clients and for both data planes.

- [ ] **Step 1: Add a second client netns and a multi-client assertion (eBPF mode)**

Extend `run_e2e.sh` to create a second client netns `cli2` with `vcli2 = 10.8.0.9/24` on the same root-side bridge/veth path to `tun_iface`, run the existing client from BOTH `cli` (10.8.0.5) and `cli2` (10.8.0.9), and assert the fake server recorded **two distinct peer IPs, each equal to its originating client** (10.8.0.5 and 10.8.0.9) — proving dynamic per-connection source-IP preservation. (Config now omits `target_client_ip` → wildcard.)

The fake server (`fake_server.py`) must append every accepted connection's peer IP to a results file; the driver greps that file for both expected IPs and fails if either is missing or if the box IP (192.168.1.10) appears.

- [ ] **Step 2: Run the eBPF multi-client e2e**

Run: `wsl.exe -e bash -lc 'cd ~/projects/mymitmproxy && sudo bash tests/integration/run_e2e.sh 2>&1 | tail -40'`
Expected: prints the 4 invariants passing AND `PEER_IPS: 10.8.0.5 10.8.0.9` (both preserved). Exit 0.

> If WSL's kernel/netns/eBPF combination can't run this (e.g. TCX/clsact limits), capture the failure and defer the authoritative run to the 4.15 VM in Task 9 — but attempt it here first.

- [ ] **Step 3: Add the iproute-mode run**

Add a second driver (or `MODE=iproute bash run_e2e.sh`) that writes a config with `data_plane = "iproute"` and repeats the SAME four assertions (handshake on real cert, byte round-trip, dump plaintext, server-observed src IP == client). The topology is identical; only the plane differs. The proxy must run with `CAP_NET_ADMIN`/root (IP_TRANSPARENT, ip rule). After the run, assert the box is clean: no leftover `iptables -t nat -S` PREROUTING DNAT to the listener, no `ip rule` for the fwmark, and the saved sysctls restored.

- [ ] **Step 4: Run the iproute-mode e2e**

Run: `wsl.exe -e bash -lc 'cd ~/projects/mymitmproxy && sudo MODE=iproute bash tests/integration/run_e2e.sh 2>&1 | tail -40'`
Expected: 4 invariants pass; post-run cleanliness checks pass. Exit 0. (If IP_TRANSPARENT/policy routing is unavailable under WSL, defer the authoritative run to Task 9 and note it.)

- [ ] **Step 5: Commit**

```bash
git add tests/integration/
git commit -m "test(e2e): multi-client source-IP preservation + iproute-mode run"
```

---

## Task 9: Kernel 4.15 verifier + attach validation (`lvh`)

**Files:**
- Create: `docs/superpowers/notes/2026-06-27-kernel-4.15-validation.md` (record results)
- Possibly modify: `mymitm-ebpf/src/main.rs` (only if the 4.15 verifier rejects something — tighten `meta()` bounds)

**Interfaces:** none. Validation gate for the Global Constraint "loads on 4.15, BTF-free".

> **Read first:** the `lvh` skill referenced in task.txt ("in sweetd in WSL there is the lvh skill"). Locate it under the sweetd repo and follow it to boot a 4.15 kernel VM with the project's eBPF object available.

- [ ] **Step 1: Build the artifacts to test on 4.15**

Run: `wsl.exe -e bash -lc 'export PATH=$HOME/.cargo/bin:$PATH; cd ~/projects/mymitmproxy && cargo build -p mymitm --release && ls -la target/x86_64-unknown-linux-musl/release/mymitm'`
Expected: static binary present (embeds the eBPF object).

- [ ] **Step 2: Boot a 4.15 VM via `lvh` and load the eBPF programs**

Using the `lvh` skill, boot kernel 4.15 and attempt to load+attach all four classifiers in **tc mode** (`attach_mode = "tc"`, since TCX doesn't exist on 4.15). The cleanest probe is the `#[ignore]` `tc_mode_attaches_and_removes_clsact` test from Task 5, or run the release binary against a `tun`/`dummy` pair inside the VM with a minimal config.

Run (inside the 4.15 VM, adapt to lvh's invocation):
`sudo -E env "PATH=$PATH" cargo test -p mymitm --target x86_64-unknown-linux-gnu bpf -- --ignored --nocapture`
Expected: the verifier ACCEPTS all four programs; `TC_ATTACH_OK` then `TC_DETACH_OK` print. Capture the full verifier log.

- [ ] **Step 3: If the verifier rejects a program — fix bounds, not features**

If load fails with a verifier error (e.g. "invalid access to packet", "min value is outside of the allowed memory range"), the fix is additional explicit bounds checks in `meta()` (`mymitm-ebpf/src/main.rs:78-131`) — never a CO-RE/BTF dependency. Re-build and re-test until it loads. Record the exact error and the fix in the notes file.

- [ ] **Step 4: Run the full e2e inside the 4.15 VM (authoritative)**

If the VM supports the netns topology, run the Task 8 harness (both modes) inside the 4.15 VM. This is the authoritative pass for the 4.15 target.
Run: `sudo bash tests/integration/run_e2e.sh && sudo MODE=iproute bash tests/integration/run_e2e.sh`
Expected: all invariants pass on 4.15.

- [ ] **Step 5: Record results + commit**

Write `docs/superpowers/notes/2026-06-27-kernel-4.15-validation.md` with: kernel version proof (`uname -r` == 4.15.x), the verifier acceptance log, attach/detach evidence, e2e results, and any `meta()` bounds fix applied.

```bash
git add docs/superpowers/notes/2026-06-27-kernel-4.15-validation.md mymitm-ebpf/src/main.rs
git commit -m "test(4.15): verifier + tc-attach + e2e validation on kernel 4.15 (lvh)"
```

---

## Out of scope (next, per chosen sequencing)

- Finalize `.gitlab-ci.yml` (#6) — already drafted on this branch; extend to optionally exercise the 4.15 verifier and publish the static binary as an artifact.
- The full 3-VM A/B/C router test (#5) — its own spec/plan after this lands.

---

## Self-review

- **Spec coverage:** dynamic client IP (Tasks 1,2,4,7); kernel 4.15 attach (Tasks 5,9); ip-route mode (Task 6); optional client IP + inline defaults + modes (Task 3); `EGRESS` map mechanism (Tasks 2,4); error handling / `--cleanup` / Drop teardown (Tasks 5,6,7); testing incl. multi-client + iproute + 4.15 (Tasks 1,3,8,9). All spec sections map to a task.
- **Type consistency:** `client_ip: Option<Ipv4Addr>` (Task 3) is consumed as `Option` in `to_bpf_config` (Task 3) and `Settings` literals (Tasks 4,6,7). `DataPlane::upstream_socket(Ipv4Addr, SocketAddrV4) -> io::Result<TcpStream>` is defined in Task 4 and implemented identically in Tasks 4 (Bpf/Direct) and 6 (IpRoute) and called in Task 7. `EGRESS` is `LruHashMap<u16,u32>` in eBPF (Task 2) and `AyaHashMap<MapData,u16,u32>` in userspace (Task 4) — keys/values NBO. `run`'s new 3-arg signature (Task 7) matches its caller in `main` (Task 7).
- **Placeholder scan:** the two "verify against aya source" notes (Tasks 5) and "verify socket2 API" (Task 6) are deliberate version-drift guards with concrete expected code, not TBDs — consistent with how this codebase handled aya/rustls drift before.
