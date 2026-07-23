use std::net::Ipv4Addr;
use std::path::PathBuf;
use serde::Deserialize;
use clap::{ArgAction, Parser, ValueEnum};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum DataPlaneKind {
    Ebpf,
    #[clap(name = "iproute")]
    IpRoute,
}
impl Default for DataPlaneKind { fn default() -> Self { DataPlaneKind::Ebpf } }

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum AttachMode { Auto, Tcx, Tc }
impl Default for AttachMode { fn default() -> Self { AttachMode::Auto } }

#[derive(Debug, Clone, Deserialize)]
struct FileCfg {
    target_server_ip: Ipv4Addr,
    #[serde(default = "d_cert")] cert_path: PathBuf,
    #[serde(default = "d_key")] key_path: PathBuf,
    box_ip: Ipv4Addr,
    #[serde(default)] target_client_ip: Option<Ipv4Addr>,
    #[serde(default = "d_port")] target_server_port: u16,
    #[serde(default = "d_tun")] tun_iface: String,
    #[serde(default = "d_eth")] egress_iface: String,
    #[serde(default = "d_local_ip")] local_addr: Ipv4Addr,
    #[serde(default = "d_local_port")] local_port: u16,
    #[serde(default = "d_mark")] fwmark: u32,
    #[serde(default = "d_dump")] dump_path: PathBuf,
    /// Log level for stdout and for the log file, independently. Both default to
    /// "off" (the proxy is silent unless asked to log). RUST_LOG/tracing syntax:
    /// off|error|warn|info|debug|trace, or targeted e.g. "mymitm=debug".
    #[serde(default = "d_log_off")] stdout_log_level: String,
    #[serde(default = "d_log_off")] file_log_level: String,
    /// Where the file log is written (only when file_log_level != "off").
    #[serde(default = "d_log_file")] log_file: PathBuf,
    #[serde(default)] data_plane: DataPlaneKind,
    #[serde(default)] attach_mode: AttachMode,
    #[serde(default)] server_name: Option<String>,
    /// Preserve the client's source IP on the upstream leg (default true). Set
    /// false to dial upstream with the box's own IP instead (standard proxy
    /// behavior); the `--preserve-src-ip=false` CLI flag also forces this off.
    #[serde(default = "d_preserve")] preserve_src_ip: bool,
    #[serde(default = "d_ws_decode")] ws_decode: bool,
    /// Write the raw per-connection decrypted streams (.c2s/.s2c/.ws.jsonl).
    #[serde(default = "d_raw_dump")] raw_dump: bool,
    /// Scan the decrypted .s2c stream for the NTLM CHALLENGE -> ntlm.jsonl.
    #[serde(default = "d_ntlm_dump")] ntlm_dump: bool,
    /// Preflight-probe eBPF support at startup before committing to the real
    /// interfaces (default true). `--verify-bpf-support=false` skips the probe and
    /// goes straight to load+attach. Only consulted for the eBPF data plane.
    #[serde(default = "d_verify_bpf")] verify_bpf_support: bool,
    /// ALPN protocols the proxy is willing to negotiate, as an allowlist. The
    /// proxy offers upstream the intersection of this list and what the client
    /// offered, then presents the server's choice back to the client. Default
    /// ["h2","http/1.1"]. Set to ["http/1.1"] to force HTTP/1.1; [] disables ALPN.
    #[serde(default = "d_alpn")] alpn_protocols: Vec<String>,
}
fn d_port() -> u16 { 443 }
fn d_tun() -> String { "tun0".into() }
fn d_eth() -> String { "eth0".into() }
fn d_local_ip() -> Ipv4Addr { Ipv4Addr::new(127,0,0,1) }
fn d_local_port() -> u16 { 8443 }
fn d_mark() -> u32 { mymitm_common::DEFAULT_FWMARK }
fn d_dump() -> PathBuf { "/var/tmp/mitm-dumps/".into() }
fn d_log_off() -> String { "off".into() }
fn d_log_file() -> PathBuf { "/var/tmp/mymitm.log".into() }
fn d_cert() -> PathBuf { "/etc/mymitm/leaf.pem".into() }
fn d_key() -> PathBuf { "/etc/mymitm/leaf.key".into() }
fn d_preserve() -> bool { true }
fn d_ws_decode() -> bool { true }
fn d_raw_dump() -> bool { true }
fn d_ntlm_dump() -> bool { true }
fn d_verify_bpf() -> bool { true }
fn d_alpn() -> Vec<String> { vec!["h2".into(), "http/1.1".into()] }

#[derive(Parser, Debug)]
#[command(version, about = "transparent TLS MITM with source-IP preservation")]
struct Cli {
    /// Path to TOML config
    #[arg(short, long, env = "MYMITM_CONFIG", default_value = "mymitm.toml")]
    config: PathBuf,
    /// Override target client IP (restrict to one client; omit for dynamic)
    #[arg(long, env = "MYMITM_CLIENT")] client: Option<Ipv4Addr>,
    /// Override target server IP
    #[arg(long, env = "MYMITM_SERVER")] server: Option<Ipv4Addr>,
    /// Override path to the real leaf certificate (PEM)
    #[arg(long, env = "MYMITM_CERT")] cert: Option<PathBuf>,
    /// Override path to the real leaf private key (PEM)
    #[arg(long, env = "MYMITM_KEY")] key: Option<PathBuf>,
    /// Override the decrypted-traffic dump directory
    #[arg(long = "dump-path", env = "MYMITM_DUMP")] dump_path: Option<PathBuf>,
    /// Override tun interface
    #[arg(long, env = "MYMITM_TUN")] tun: Option<String>,
    /// Override egress interface
    #[arg(long, env = "MYMITM_EGRESS")] egress: Option<String>,
    /// Override data plane
    #[arg(long, value_enum, env = "MYMITM_DATA_PLANE")] data_plane: Option<DataPlaneKind>,
    /// Override attach mode (eBPF only)
    #[arg(long, value_enum, env = "MYMITM_ATTACH_MODE")] attach_mode: Option<AttachMode>,
    /// Override upstream SNI hostname
    #[arg(long = "server-name", env = "MYMITM_SERVER_NAME")] server_name: Option<String>,
    /// Log level for stdout (off|error|warn|info|debug|trace or e.g. "mymitm=debug").
    /// Default off — the proxy is silent unless this is set.
    #[arg(long = "stdout-log-level", env = "MYMITM_STDOUT_LOG")] stdout_log_level: Option<String>,
    /// Log level for the log file (same syntax). Default off.
    #[arg(long = "file-log-level", env = "MYMITM_FILE_LOG")] file_log_level: Option<String>,
    /// Path to the log file (used only when the file log level is not off).
    #[arg(long = "log-file", env = "MYMITM_LOG_FILE")] log_file: Option<PathBuf>,
    /// Source-IP preservation on the upstream leg (`--preserve-src-ip=true|false`).
    /// True (the default in the config file) dials the upstream with the client's
    /// IP; false dials with the box's own IP — standard (non-transparent) proxy
    /// behavior, so the server sees the box IP, not the client IP. Useful as a
    /// negative control. When given, overrides `preserve_src_ip` in the config
    /// file; when omitted, the config-file value stands.
    #[arg(long = "preserve-src-ip", env = "MYMITM_PRESERVE_SRC_IP", action = ArgAction::Set)]
    preserve_src_ip: Option<bool>,
    /// ALPN allowlist as a comma-separated list (e.g. "h2,http/1.1"). Overrides
    /// the config file. Use "http/1.1" to force HTTP/1.1 downgrade.
    #[arg(long = "alpn", env = "MYMITM_ALPN", value_delimiter = ',')]
    alpn: Option<Vec<String>>,
    /// Reverse any leftover state (stale clsact qdisc / iproute rules) from a
    /// previous unclean exit, then continue startup.
    #[arg(long, default_value_t = false)] cleanup: bool,
    /// WebSocket decoding (`--ws-decode=true|false`); raw dump is unaffected.
    /// When given, overrides `ws_decode` in the config file (default true); when
    /// omitted, the config-file value stands.
    #[arg(long = "ws-decode", action = ArgAction::Set)] ws_decode: Option<bool>,
    /// Write the raw per-connection decrypted streams — .c2s/.s2c/.ws.jsonl
    /// (`--raw-dump=true|false`). Default true; set false to keep only the NTLM
    /// summary (ntlm.jsonl) and skip the large per-connection files. Overrides
    /// `raw_dump` in the config file when given.
    #[arg(long = "raw-dump", action = ArgAction::Set)] raw_dump: Option<bool>,
    /// Extract the NTLM CHALLENGE_MESSAGE from the decrypted .s2c stream into
    /// ntlm.jsonl (`--ntlm-dump=true|false`). Default true; overrides `ntlm_dump`
    /// in the config file when given.
    #[arg(long = "ntlm-dump", action = ArgAction::Set)] ntlm_dump: Option<bool>,
    /// Preflight-check that eBPF is usable on this kernel before startup
    /// (`--verify-bpf-support=true|false`, default true). False skips the probe.
    /// eBPF data plane only; ignored for `--data-plane iproute`.
    #[arg(long = "verify-bpf-support", env = "MYMITM_VERIFY_BPF_SUPPORT", action = ArgAction::Set)]
    verify_bpf_support: Option<bool>,
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
    pub box_ip: Ipv4Addr,
    pub stdout_log_level: String,
    pub file_log_level: String,
    pub log_file: PathBuf,
    pub server_name: Option<String>,
    pub data_plane: DataPlaneKind,
    pub attach_mode: AttachMode,
    pub preserve_src_ip: bool,
    pub alpn_protocols: Vec<String>,
    pub cleanup: bool,
    pub ws_decode: bool,
    pub raw_dump: bool,
    pub ntlm_dump: bool,
    pub verify_bpf_support: bool,
}

impl Settings {
    pub fn from_toml_str(s: &str) -> anyhow::Result<Settings> {
        let f: FileCfg = toml::from_str(s)?;
        if f.fwmark == 0 {
            anyhow::bail!(
                "fwmark must be non-zero: 0 collapses the eBPF egress match \
                 (`mark == fwmark` would be true for all traffic) and is invalid \
                 for the iproute fwmark rule"
            );
        }
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
            box_ip: f.box_ip,
            stdout_log_level: f.stdout_log_level,
            file_log_level: f.file_log_level,
            log_file: f.log_file,
            server_name: f.server_name,
            data_plane: f.data_plane,
            attach_mode: f.attach_mode,
            preserve_src_ip: f.preserve_src_ip,
            alpn_protocols: f.alpn_protocols,
            cleanup: false,
            ws_decode: f.ws_decode,
            raw_dump: f.raw_dump,
            ntlm_dump: f.ntlm_dump,
            verify_bpf_support: f.verify_bpf_support,
        })
    }

    pub fn load() -> anyhow::Result<Settings> {
        let cli = Cli::parse();
        let text = std::fs::read_to_string(&cli.config)?;
        let mut s = Settings::from_toml_str(&text)?;
        if let Some(v) = cli.client { s.client_ip = Some(v); }
        if let Some(v) = cli.server { s.server_ip = v; }
        if let Some(v) = cli.cert { s.cert_path = v; }
        if let Some(v) = cli.key { s.key_path = v; }
        if let Some(v) = cli.dump_path { s.dump_path = v; }
        if let Some(v) = cli.tun { s.tun_iface = v; }
        if let Some(v) = cli.egress { s.egress_iface = v; }
        if let Some(v) = cli.data_plane { s.data_plane = v; }
        if let Some(v) = cli.attach_mode { s.attach_mode = v; }
        if let Some(v) = cli.server_name { s.server_name = Some(v); }
        if let Some(v) = cli.stdout_log_level { s.stdout_log_level = v; }
        if let Some(v) = cli.file_log_level { s.file_log_level = v; }
        if let Some(v) = cli.log_file { s.log_file = v; }
        // Boolean overrides take an explicit true/false; `None` (flag omitted)
        // leaves the config-file value untouched.
        if let Some(v) = cli.preserve_src_ip { s.preserve_src_ip = v; }
        if let Some(v) = cli.alpn { s.alpn_protocols = v; }
        s.cleanup = cli.cleanup;
        if let Some(v) = cli.ws_decode { s.ws_decode = v; }
        if let Some(v) = cli.raw_dump { s.raw_dump = v; }
        if let Some(v) = cli.ntlm_dump { s.ntlm_dump = v; }
        if let Some(v) = cli.verify_bpf_support { s.verify_bpf_support = v; }
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

#[cfg(test)]
impl Settings {
    /// Fully-populated `Settings` for tests; callers mutate only the fields they
    /// care about. Centralised so adding a `Settings` field doesn't require
    /// touching every test module's hand-built struct.
    pub fn test_default() -> Settings {
        Settings {
            client_ip: None,
            server_ip: Ipv4Addr::new(192, 168, 1, 50),
            server_port: 443,
            tun_iface: "tun0".into(),
            egress_iface: "eth0".into(),
            local_ip: Ipv4Addr::LOCALHOST,
            local_port: 8443,
            fwmark: mymitm_common::DEFAULT_FWMARK,
            cert_path: PathBuf::from("/x/leaf.pem"),
            key_path: PathBuf::from("/x/leaf.key"),
            dump_path: PathBuf::from("/tmp"),
            box_ip: Ipv4Addr::new(192, 168, 1, 10),
            stdout_log_level: "off".into(),
            file_log_level: "off".into(),
            log_file: PathBuf::from("/var/tmp/mymitm.log"),
            server_name: None,
            data_plane: DataPlaneKind::Ebpf,
            attach_mode: AttachMode::Auto,
            preserve_src_ip: true,
            alpn_protocols: vec!["h2".into(), "http/1.1".into()],
            cleanup: false,
            ws_decode: true,
            raw_dump: true,
            ntlm_dump: true,
            verify_bpf_support: true,
        }
    }
}

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
    fn preserve_src_ip_defaults_true_and_toml_can_disable() {
        // Omitted -> preservation on (the product's whole point).
        assert!(Settings::from_toml_str(base()).unwrap().preserve_src_ip);
        // Explicit opt-out via the config file.
        let toml = format!("{}\npreserve_src_ip = false", base());
        assert!(!Settings::from_toml_str(&toml).unwrap().preserve_src_ip);
    }

    #[test]
    fn cli_preserve_src_ip_flag_parses() {
        use clap::Parser;
        let default = Cli::try_parse_from(["mymitm"]).unwrap();
        assert_eq!(default.preserve_src_ip, None, "omitted -> leave config value");
        let off = Cli::try_parse_from(["mymitm", "--preserve-src-ip=false"]).unwrap();
        assert_eq!(off.preserve_src_ip, Some(false), "explicit false overrides");
        let on = Cli::try_parse_from(["mymitm", "--preserve-src-ip", "true"]).unwrap();
        assert_eq!(on.preserve_src_ip, Some(true), "explicit true overrides");
        // A bare flag with no value is rejected (explicit value required).
        assert!(Cli::try_parse_from(["mymitm", "--preserve-src-ip"]).is_err());
    }

    #[test]
    fn logging_defaults_off_and_overridable() {
        // Both levels default to off; the log-file path has a sensible default.
        let s = Settings::from_toml_str(base()).unwrap();
        assert_eq!(s.stdout_log_level, "off");
        assert_eq!(s.file_log_level, "off");
        assert_eq!(s.log_file, PathBuf::from("/var/tmp/mymitm.log"));
        // The config file can raise either level and set the path.
        let toml = format!(
            "{}\nstdout_log_level = \"info\"\nfile_log_level = \"debug\"\nlog_file = \"/tmp/x.log\"",
            base()
        );
        let s = Settings::from_toml_str(&toml).unwrap();
        assert_eq!(s.stdout_log_level, "info");
        assert_eq!(s.file_log_level, "debug");
        assert_eq!(s.log_file, PathBuf::from("/tmp/x.log"));
    }

    #[test]
    fn cli_log_args_parse() {
        use clap::Parser;
        let c = Cli::try_parse_from([
            "mymitm",
            "--stdout-log-level", "trace",
            "--file-log-level", "info",
            "--log-file", "/tmp/y.log",
        ]).unwrap();
        assert_eq!(c.stdout_log_level.as_deref(), Some("trace"));
        assert_eq!(c.file_log_level.as_deref(), Some("info"));
        assert_eq!(c.log_file.as_deref(), Some(std::path::Path::new("/tmp/y.log")));
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
    fn paths_default_when_omitted() {
        // cert/key/dump are now optional config fields with default values.
        let toml = r#"
            target_server_ip = "192.168.1.50"
            box_ip = "192.168.1.10"
        "#;
        let s = Settings::from_toml_str(toml).unwrap();
        assert_eq!(s.cert_path, PathBuf::from("/etc/mymitm/leaf.pem"));
        assert_eq!(s.key_path, PathBuf::from("/etc/mymitm/leaf.key"));
        assert_eq!(s.dump_path, PathBuf::from("/var/tmp/mitm-dumps/"));
    }

    #[test]
    fn missing_required_field_errors() {
        // box_ip is still required, so target_server_ip alone errors.
        assert!(Settings::from_toml_str(r#"target_server_ip = "10.0.0.1""#).is_err());
    }

    #[test]
    fn fwmark_zero_is_rejected() {
        let toml = format!("{}\nfwmark = 0", base());
        assert!(Settings::from_toml_str(&toml).is_err());
        // a non-zero fwmark is fine
        let ok = format!("{}\nfwmark = 4919", base());
        assert_eq!(Settings::from_toml_str(&ok).unwrap().fwmark, 4919);
    }

    #[test]
    fn cli_parses_path_overrides() {
        use clap::Parser;
        let c = Cli::try_parse_from([
            "mymitm",
            "--cert", "/tmp/c.pem",
            "--key", "/tmp/k.pem",
            "--dump-path", "/tmp/dumps",
        ]).unwrap();
        assert_eq!(c.cert.as_deref(), Some(std::path::Path::new("/tmp/c.pem")));
        assert_eq!(c.key.as_deref(), Some(std::path::Path::new("/tmp/k.pem")));
        assert_eq!(c.dump_path.as_deref(), Some(std::path::Path::new("/tmp/dumps")));
    }

    #[test]
    fn cli_parses_value_enums() {
        use clap::Parser;
        let c = Cli::try_parse_from(["mymitm","--data-plane","iproute","--attach-mode","tcx","--cleanup"]).unwrap();
        assert!(matches!(c.data_plane, Some(DataPlaneKind::IpRoute)));
        assert!(matches!(c.attach_mode, Some(AttachMode::Tcx)));
        assert!(c.cleanup);
    }

    #[test]
    fn ws_decode_defaults_true() {
        let s = Settings::from_toml_str(base()).unwrap();
        assert!(s.ws_decode);
    }

    #[test]
    fn ws_decode_can_be_disabled_in_file() {
        let toml = format!("{}\nws_decode = false", base());
        let s = Settings::from_toml_str(&toml).unwrap();
        assert!(!s.ws_decode);
    }

    #[test]
    fn cli_ws_decode_flag_parses() {
        use clap::Parser;
        let default = Cli::try_parse_from(["mymitm"]).unwrap();
        assert_eq!(default.ws_decode, None, "omitted -> leave config value");
        let off = Cli::try_parse_from(["mymitm", "--ws-decode=false"]).unwrap();
        assert_eq!(off.ws_decode, Some(false), "explicit false overrides");
        let on = Cli::try_parse_from(["mymitm", "--ws-decode", "true"]).unwrap();
        assert_eq!(on.ws_decode, Some(true), "explicit true overrides");
        // A bare flag with no value is rejected (explicit value required).
        assert!(Cli::try_parse_from(["mymitm", "--ws-decode"]).is_err());
    }

    #[test]
    fn raw_dump_and_ntlm_dump_default_true() {
        let s = Settings::from_toml_str(base()).unwrap();
        assert!(s.raw_dump);
        assert!(s.ntlm_dump);
    }

    #[test]
    fn raw_dump_and_ntlm_dump_can_be_disabled_in_file() {
        let toml = format!("{}\nraw_dump = false\nntlm_dump = false", base());
        let s = Settings::from_toml_str(&toml).unwrap();
        assert!(!s.raw_dump);
        assert!(!s.ntlm_dump);
    }

    #[test]
    fn cli_raw_dump_and_ntlm_dump_flags_parse() {
        use clap::Parser;
        let default = Cli::try_parse_from(["mymitm"]).unwrap();
        assert_eq!(default.raw_dump, None, "omitted -> leave config value");
        assert_eq!(default.ntlm_dump, None, "omitted -> leave config value");
        let off = Cli::try_parse_from(["mymitm", "--raw-dump=false", "--ntlm-dump=false"]).unwrap();
        assert_eq!(off.raw_dump, Some(false));
        assert_eq!(off.ntlm_dump, Some(false));
        let on = Cli::try_parse_from(["mymitm", "--raw-dump", "true", "--ntlm-dump", "true"]).unwrap();
        assert_eq!(on.raw_dump, Some(true));
        assert_eq!(on.ntlm_dump, Some(true));
        // A bare flag with no value is rejected (explicit value required).
        assert!(Cli::try_parse_from(["mymitm", "--raw-dump"]).is_err());
    }

    #[test]
    fn verify_bpf_support_defaults_true() {
        let s = Settings::from_toml_str(base()).unwrap();
        assert!(s.verify_bpf_support);
    }

    #[test]
    fn verify_bpf_support_can_be_disabled_in_file() {
        let toml = format!("{}\nverify_bpf_support = false", base());
        let s = Settings::from_toml_str(&toml).unwrap();
        assert!(!s.verify_bpf_support);
    }

    #[test]
    fn cli_verify_bpf_support_flag_parses() {
        use clap::Parser;
        let default = Cli::try_parse_from(["mymitm"]).unwrap();
        assert_eq!(default.verify_bpf_support, None, "omitted -> leave config value");
        let off = Cli::try_parse_from(["mymitm", "--verify-bpf-support=false"]).unwrap();
        assert_eq!(off.verify_bpf_support, Some(false), "explicit false overrides");
        let on = Cli::try_parse_from(["mymitm", "--verify-bpf-support", "true"]).unwrap();
        assert_eq!(on.verify_bpf_support, Some(true), "explicit true overrides");
        // A bare flag with no value is rejected (explicit value required).
        assert!(Cli::try_parse_from(["mymitm", "--verify-bpf-support"]).is_err());
    }

    #[test]
    fn alpn_defaults_and_toml_override() {
        // omitted -> [h2, http/1.1]
        let s = Settings::from_toml_str(base()).unwrap();
        assert_eq!(s.alpn_protocols, vec!["h2".to_string(), "http/1.1".to_string()]);
        // explicit single protocol (used to force HTTP/1.1)
        let toml = format!("{}\nalpn_protocols = [\"http/1.1\"]", base());
        let s = Settings::from_toml_str(&toml).unwrap();
        assert_eq!(s.alpn_protocols, vec!["http/1.1".to_string()]);
        // empty list -> ALPN disabled
        let toml = format!("{}\nalpn_protocols = []", base());
        let s = Settings::from_toml_str(&toml).unwrap();
        assert!(s.alpn_protocols.is_empty());
    }

    #[test]
    fn cli_alpn_parses_comma_list() {
        use clap::Parser;
        let c = Cli::try_parse_from(["mymitm", "--alpn", "h2,http/1.1"]).unwrap();
        assert_eq!(c.alpn, Some(vec!["h2".to_string(), "http/1.1".to_string()]));
        // absent -> None (leaves the config/default untouched)
        let d = Cli::try_parse_from(["mymitm"]).unwrap();
        assert_eq!(d.alpn, None);
    }
}
