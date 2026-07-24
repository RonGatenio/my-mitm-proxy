//! Shared kernel-sysctl helpers, plus the eBPF data plane's startup sysctl
//! preflight (added in a later task).
//!
//! Both data planes touch `/proc/sys`: the `iproute` plane as part of its visible
//! setup, and the `ebpf` plane to fix the two settings that otherwise make it
//! silently blackhole diverted client traffic. The low-level read/write primitives
//! live here so both share exactly one implementation.

/// A sysctl we changed and must restore. `key` is dotted (`net.ipv4.ip_forward`).
pub(crate) struct SavedSysctl {
    pub(crate) key: String,
    pub(crate) original: String,
}

/// Read a sysctl by dotted key. `None` if the path is unreadable (e.g. the
/// interface does not exist).
pub(crate) fn read_sysctl(key: &str) -> Option<String> {
    let p = format!("/proc/sys/{}", key.replace('.', "/"));
    std::fs::read_to_string(p).ok().map(|s| s.trim().to_string())
}

/// Write a sysctl by dotted key.
pub(crate) fn write_sysctl(key: &str, val: &str) -> std::io::Result<()> {
    let p = format!("/proc/sys/{}", key.replace('.', "/"));
    std::fs::write(p, val)
}
