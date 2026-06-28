use std::net::Ipv4Addr;
use std::path::PathBuf;
use serde::Deserialize;
use clap::{Parser, ValueEnum};

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
fn d_cert() -> PathBuf { "/etc/mymitm/leaf.pem".into() }
fn d_key() -> PathBuf { "/etc/mymitm/leaf.key".into() }

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
        if let Some(v) = cli.cert { s.cert_path = v; }
        if let Some(v) = cli.key { s.key_path = v; }
        if let Some(v) = cli.dump_path { s.dump_path = v; }
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
}
