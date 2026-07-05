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

pub async fn resolve_aftr(
    address: &AftrAddress,
    preferred: Option<Ipv6Addr>,
) -> Result<Ipv6Addr, DnsError> {
    match address {
        AftrAddress::Ip(ip) => Ok(*ip),
        AftrAddress::Fqdn(name) => {
            let addrs = net::lookup_host(format!("{}:0", name)).await?;
            let selected = choose_aftr_ip(addrs.map(|addr| addr.ip()), preferred);
            match selected {
                Some(AftrSelection::Preferred(ip)) => {
                    tracing::debug!(aftr = %name, remote_v6 = %ip, "AFTR resolved using preferred address");
                    Ok(ip)
                }
                Some(AftrSelection::Fallback(ip)) => {
                    if let Some(preferred) = preferred {
                        tracing::debug!(
                            aftr = %name,
                            preferred_remote_v6 = %preferred,
                            selected_remote_v6 = %ip,
                            "AFTR preferred address not present in DNS results"
                        );
                    }
                    Ok(ip)
                }
                None => Err(DnsError::NoIpv6(name.to_string())),
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AftrSelection {
    Preferred(Ipv6Addr),
    Fallback(Ipv6Addr),
}

fn choose_aftr_ip(
    addrs: impl IntoIterator<Item = IpAddr>,
    preferred: Option<Ipv6Addr>,
) -> Option<AftrSelection> {
    let mut first_v6 = None;
    for addr in addrs {
        let IpAddr::V6(v6) = addr else {
            continue;
        };

        if first_v6.is_none() {
            first_v6 = Some(v6);
        }

        if Some(v6) == preferred {
            return Some(AftrSelection::Preferred(v6));
        }
    }
    first_v6.map(AftrSelection::Fallback)
}

#[cfg(test)]
mod tests {

    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn use_found_preferred_over_first_discovered() {
        let addrs = vec![
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2)),
        ];
        let preferred = Some(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2));

        let ip = choose_aftr_ip(addrs, preferred);

        assert_eq!(ip, preferred.map(AftrSelection::Preferred))
    }

    #[test]
    fn use_first_if_preferred_not_found() {
        let addrs = vec![
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 3)),
        ];
        let preferred = Some(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2));

        let ip = choose_aftr_ip(addrs, preferred);

        assert_eq!(
            ip,
            Some(AftrSelection::Fallback(Ipv6Addr::new(
                0x2001, 0xdb8, 0, 0, 0, 0, 0, 1
            )))
        )
    }

    #[test]
    fn use_first_if_preferred_not_defined() {
        let addrs = vec![
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 3)),
        ];
        let preferred = None;

        let ip = choose_aftr_ip(addrs, preferred);

        assert_eq!(
            ip,
            Some(AftrSelection::Fallback(Ipv6Addr::new(
                0x2001, 0xdb8, 0, 0, 0, 0, 0, 1
            )))
        )
    }

    #[test]
    fn none_if_no_v6_addresses() {
        let addrs = vec![IpAddr::V4(Ipv4Addr::new(192, 168, 0, 10))];
        let preferred = Some(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2));

        let ip = choose_aftr_ip(addrs, preferred);

        assert_eq!(ip, None)
    }
}
