use std::net::{Ipv4Addr, Ipv6Addr};
use std::num::NonZeroU64;
use std::path::PathBuf;

use serde::{Deserialize, Deserializer};

#[derive(Deserialize, Debug)]
pub struct Config {
    #[serde(default)]
    pub runtime: RuntimeConfig,
    pub tunnel: TunnelConfig,
    pub aftr: AftrConfig,
    #[serde(default)]
    pub discovery: DiscoveryConfig,
    pub health: HealthConfig,
}

#[derive(Deserialize, Debug)]
pub struct TunnelConfig {
    #[serde(default = "default_tunnel_name")]
    pub name: String,
    pub local_v6: Option<Ipv6Addr>,
    #[serde(
        default = "default_tunnel_local_v4",
        deserialize_with = "deserialize_b4_v4"
    )]
    pub local_v4: Ipv4Addr,
}

fn deserialize_b4_v4<'de, D>(d: D) -> Result<Ipv4Addr, D::Error>
where
    D: Deserializer<'de>,
{
    let addr = Ipv4Addr::deserialize(d)?;
    let o = addr.octets();
    // RFC 6333 5.7: reserved subnet 192.0.0.0/29
    // - .0 (subnet address)
    // - .1 (AFTR element)
    // - .7 (broadcast)
    if o[..3] != [192, 0, 0] || !(2..=6).contains(&o[3]) {
        return Err(serde::de::Error::custom(format!(
            "according to RFC 6333 tunnel.local_v4 must be in 192.0.0.0/29 host range (192.0.0.2..192.0.0.6), got {}",
            addr
        )));
    }
    Ok(addr)
}

#[derive(Deserialize, Debug, Clone)]
#[serde(from = "String")]
pub enum AftrAddress {
    Ip(Ipv6Addr),
    Fqdn(String),
}

impl From<String> for AftrAddress {
    fn from(value: String) -> Self {
        if let Ok(addr) = value.parse::<Ipv6Addr>() {
            Self::Ip(addr)
        } else {
            Self::Fqdn(value)
        }
    }
}

#[derive(Deserialize, Debug)]
pub struct AftrConfig {
    pub address: Option<AftrAddress>,
}

#[derive(Deserialize, Debug, Clone, Default)]
#[serde(rename_all = "lowercase")]
pub enum DiscoveryMethod {
    #[default]
    None,
    Hb46pp,
}

#[derive(Deserialize, Debug)]
pub struct DiscoveryConfig {
    #[serde(default)]
    pub method: DiscoveryMethod,
    #[serde(default = "default_discovery_vendorid")]
    pub vendor_id: String,
    #[serde(default = "default_discovery_product")]
    pub product: String,
}

impl Default for DiscoveryConfig {
    fn default() -> Self {
        Self {
            method: DiscoveryMethod::None,
            vendor_id: default_discovery_vendorid(),
            product: default_discovery_product(),
        }
    }
}

#[derive(Deserialize, Debug)]
pub struct HealthConfig {
    #[serde(default = "default_health_interval")]
    pub interval_secs: NonZeroU64,
    #[serde(default = "default_aftr_missing_grace_secs")]
    pub aftr_missing_grace_secs: u64,
}

#[derive(Deserialize, Debug)]
pub struct RuntimeConfig {
    #[serde(default = "default_runtime_state_dir")]
    pub state_dir: PathBuf,
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            state_dir: default_runtime_state_dir(),
        }
    }
}

fn default_tunnel_name() -> String {
    "dslite0".into()
}

fn default_health_interval() -> NonZeroU64 {
    NonZeroU64::new(30).unwrap()
}

fn default_tunnel_local_v4() -> Ipv4Addr {
    Ipv4Addr::new(192, 0, 0, 2)
}

fn default_runtime_state_dir() -> PathBuf {
    PathBuf::from("/var/run/dslite-b4")
}

fn default_aftr_missing_grace_secs() -> u64 {
    600
}

fn default_discovery_vendorid() -> String {
    "000000".into()
}

fn default_discovery_product() -> String {
    "dslite-b4".into()
}
