use std::net::{Ipv4Addr, Ipv6Addr};

use serde::{Deserialize, Deserializer};

#[derive(Deserialize, Debug)]
pub struct Config {
    pub tunnel: TunnelConfig,
    pub aftr: AftrConfig,
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

#[derive(Deserialize, Debug)]
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
    pub address: AftrAddress,
}

#[derive(Deserialize, Debug)]
pub struct HealthConfig {
    #[serde(default = "default_health_interval")]
    pub interval_secs: u64,
}

fn default_tunnel_name() -> String {
    "dslite0".into()
}

fn default_health_interval() -> u64 {
    30
}

fn default_tunnel_local_v4() -> Ipv4Addr {
    Ipv4Addr::new(192, 0, 0, 2)
}
