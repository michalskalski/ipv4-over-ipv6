use std::net::Ipv6Addr;

use crate::discovery::DiscoveryError;
use futures_util::stream::TryStreamExt;
use libc;
use rtnetlink::{
    Error::NetlinkError,
    RouteMessageBuilder, new_connection,
    packet_route::route::{RouteAddress, RouteAttribute, RouteType},
};

pub async fn discover_local_v6(remote: Ipv6Addr) -> Result<Ipv6Addr, DiscoveryError> {
    let (connection, handle, _) = new_connection().map_err(|e| DiscoveryError::OpenNetlink(e))?;
    tokio::spawn(connection);

    let msg = RouteMessageBuilder::<Ipv6Addr>::new()
        .destination_prefix(remote, 128)
        .build();

    let mut stream = handle.route().get(msg).execute();

    match stream.try_next().await {
        Ok(Some(msg)) => {
            if matches!(
                msg.header.kind,
                RouteType::Unreachable | RouteType::BlackHole | RouteType::Prohibit
            ) {
                return Err(DiscoveryError::NoV6Connectivity);
            }

            let found = msg.attributes.iter().find_map(|attr| match attr {
                RouteAttribute::PrefSource(RouteAddress::Inet6(a)) => Some(Ok(*a)),
                RouteAttribute::PrefSource(_) => {
                    Some(Err(DiscoveryError::UnsupportedAddressFamily))
                }
                _ => None,
            });

            match found {
                Some(Ok(addr)) => {
                    if addr.is_unicast_link_local() {
                        return Err(DiscoveryError::LinkLocalOnly(addr));
                    }
                    let oif = msg.attributes.iter().find_map(|attr| {
                        if let RouteAttribute::Oif(idx) = attr {
                            Some(*idx)
                        } else {
                            None
                        }
                    });
                    tracing::debug!(%addr, oif, "local_v6 discovered");
                    Ok(addr)
                }
                Some(Err(e)) => Err(e),
                None => Err(DiscoveryError::NoPrefSrc),
            }
        }
        Ok(None) => Err(DiscoveryError::EmptyResponse),
        Err(e) => Err(classify_netlink_err(e)),
    }
}

fn classify_netlink_err(e: rtnetlink::Error) -> DiscoveryError {
    match e {
        NetlinkError(ref e_msg) => {
            if let Some(raw_err) = e_msg.to_io().raw_os_error() {
                if raw_err == libc::ENETUNREACH
                    || raw_err == libc::EHOSTUNREACH
                    || raw_err == libc::ENETDOWN
                {
                    return DiscoveryError::NoV6Connectivity;
                }
            }
            return DiscoveryError::Netlink(e);
        }
        _ => DiscoveryError::Netlink(e),
    }
}
