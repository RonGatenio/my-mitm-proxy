# Build & release

`mymitm` ships as a **single, fully static** `x86_64` / `aarch64` musl binary — no
shared-object dependencies, so it runs on any Linux of the right arch regardless
of libc.

## Build profiles

| Profile | Cargo invocation | Symbols | Size (x86_64) | Use |
|---------|------------------|---------|---------------|-----|
| `release` | `cargo build -p mymitm --release` | kept (`not stripped`) | ~6.9 MB | normal, debuggable build |
| `release-stripped` | see below | **removed** (`stripped`) | ~2.3 MB | hardened / minimal build |

Both are static: `file` reports `static-pie linked`, `ldd` reports `statically
linked`, and `readelf -d` shows **no `NEEDED`** entries. CI fails the build if a
`NEEDED` dependency ever appears.

### Regular

```bash
cargo build -p mymitm --release
# -> target/x86_64-unknown-linux-musl/release/mymitm
```

### Stripped (no symbols / no strings)

The `[profile.release-stripped]` (in the root `Cargo.toml`) sets
`opt-level = "z"`, `lto = true`, `codegen-units = 1`, `panic = "abort"`,
`strip = "symbols"`. To also drop std **panic-message** strings, build it with
`build-std` + `panic_immediate_abort` (nightly; the repo already pins nightly):

```bash
cargo build -p mymitm \
  --profile release-stripped \
  -Z build-std=std,panic_abort \
  -Z build-std-features=panic_immediate_abort \
  --target x86_64-unknown-linux-musl
# -> target/x86_64-unknown-linux-musl/release-stripped/mymitm
```

**What the stripped build removes** (measured, x86_64):

| | regular | stripped |
|---|---|---|
| `file` | `not stripped` | `stripped` |
| `nm` symbol lines | 14,530 | *no symbols* |
| total `strings` | 66,931 | 28,435 (−57%) |
| panic `unwrap` strings | 58 | 0 |
| size | 6.9 MB | 2.3 MB |

**What it does *not* remove:** the symbol table, debug info, and std panic
strings are gone, but application-level string literals (our own log/format
messages, and error strings in dependencies) remain in `.rodata` — removing those
would require compiling the code paths out, not just stripping. So "no strings"
means *no symbol/debug/panic strings*, not a literally string-free binary.

## Verifying static linking

```bash
file    target/x86_64-unknown-linux-musl/release/mymitm   # ... static-pie linked ...
ldd     target/x86_64-unknown-linux-musl/release/mymitm   # statically linked
readelf -d target/x86_64-unknown-linux-musl/release/mymitm | grep NEEDED   # (no output)
```

`static-pie` is a *position-independent* static executable: the `readelf -d`
dynamic section holds only self-relocation entries (INIT/FINI/RELA…), never a
`NEEDED` (shared-library) entry.

## CI / release (GitHub Actions)

GitHub Actions is the authoritative CI.

- **`.github/workflows/ci.yml`** — runs on every push (any branch except
  `release`) and on PRs: installs the eBPF + musl toolchain, runs the unit tests,
  builds the static `x86_64` release, and asserts zero `NEEDED` deps. This is the
  pipeline that must stay green on the default branch.

- **`.github/workflows/release.yml`** — runs on push to the **`release` branch**
  (or manual dispatch). For each arch it builds **both** the regular and the
  stripped binary, then publishes a GitHub Release:
  - **tag / name:** `1.0.YYYYMMDD` (the UTC date the pipeline runs).
  - **assets:** `mymitm-<version>-<target>` and `mymitm-<version>-<target>-stripped`
    (+ a `.sha256` each), for:
    - `x86_64-unknown-linux-musl` on `ubuntu-latest` (native, required)
    - `aarch64-unknown-linux-musl` on `ubuntu-24.04-arm` (native, **best-effort**:
      `continue-on-error`, so if the account can't schedule an arm runner the
      x86_64 release still ships).

### Cutting a release

```bash
git switch release        # first time: git switch -c release
git merge --ff-only master
git push origin release   # -> builds + publishes 1.0.$(date -u +%Y%m%d)
```

Re-running on the same UTC day updates that day's release/tag in place.
