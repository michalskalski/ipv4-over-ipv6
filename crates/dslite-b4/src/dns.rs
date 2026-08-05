//! IPv6-only resolution of configured AFTR endpoints.

use std::net::{IpAddr, Ipv6Addr};
use thiserror::Error;
use tokio::net;

use crate::config::AftrAddress;

#[derive(Debug, Error)]
/// Errors resolving an AFTR endpoint.
pub enum DnsError {
    #[error("resolving AFTR address: {0}")]
    /// The operating system resolver failed.
    LookupFailed(#[from] std::io::Error),
    #[error("no IPv6 address found for {0}")]
    /// Resolution succeeded without producing an IPv6 address.
    NoIpv6(String),
}

/// Resolves an AFTR literal or DNS name into IPv6 candidates.
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
