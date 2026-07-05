use std::net::{IpAddr, Ipv6Addr};
use thiserror::Error;
use tokio::net;

use crate::config::AftrAddress;

#[derive(Debug, Error)]
pub enum DnsError {
    #[error("resolving AFTR address: {0}")]
    LookupFailed(#[from] std::io::Error),
    #[error("no IPv6 address found for {0}")]
    NoIpv6(String),
}

pub async fn resolve_aftr_addresses(address: &AftrAddress) -> Result<Vec<Ipv6Addr>, DnsError> {
    match address {
        AftrAddress::Ip(ip) => Ok(vec![*ip]),
        AftrAddress::Fqdn(name) => {
            let addrs = net::lookup_host(format!("{}:0", name)).await?;

            let mut v6s = Vec::new();

            for addr in addrs {
                if let IpAddr::V6(v6) = addr.ip() {
                    v6s.push(v6);
                }
            }

            if v6s.is_empty() {
                Err(DnsError::NoIpv6(name.to_string()))
            } else {
                Ok(v6s)
            }
        }
    }
}
