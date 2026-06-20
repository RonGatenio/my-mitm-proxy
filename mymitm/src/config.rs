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
    /// Optional SNI hostname to send in the upstream ClientHello. Userspace-only;
    /// not part of `to_bpf_config`. If absent, the server IP is used as the SNI.
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
    /// Override target client IP
    #[arg(long)] client: Option<Ipv4Addr>,
    /// Override target server IP
    #[arg(long)] server: Option<Ipv4Addr>,
    /// Override tun interface
    #[arg(long)] tun: Option<String>,
    /// Override egress interface
    #[arg(long)] egress: Option<String>,
    /// Override upstream SNI hostname
    #[arg(long = "server-name")] server_name: Option<String>,
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
    pub server_name: Option<String>,
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
        if let Some(v) = cli.server_name { s.server_name = Some(v); }
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
            cert_path = "/x"
            key_path = "/y"
            box_ip = "192.168.1.10"
        "#;
        let s = Settings::from_toml_str(toml).unwrap();
        let c = s.to_bpf_config();
        assert_eq!(c.server_port, 443u16.to_be());
        assert_eq!(c.client_ip, u32::from(Ipv4Addr::new(10,8,0,5)).to_be());
    }

    #[test]
    fn server_name_optional_defaults_none_and_parses() {
        let none = r#"
            target_client_ip = "10.8.0.5"
            target_server_ip = "192.168.1.50"
            cert_path = "/x"
            key_path = "/y"
            box_ip = "192.168.1.10"
        "#;
        assert_eq!(Settings::from_toml_str(none).unwrap().server_name, None);

        let some = r#"
            target_client_ip = "10.8.0.5"
            target_server_ip = "192.168.1.50"
            cert_path = "/x"
            key_path = "/y"
            box_ip = "192.168.1.10"
            server_name = "real.example.com"
        "#;
        assert_eq!(
            Settings::from_toml_str(some).unwrap().server_name.as_deref(),
            Some("real.example.com")
        );
    }

    #[test]
    fn missing_required_field_errors() {
        let toml = r#"target_client_ip = "10.8.0.5""#;
        assert!(Settings::from_toml_str(toml).is_err());
    }
}
