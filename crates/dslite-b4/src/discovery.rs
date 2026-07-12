use std::net::{IpAddr, Ipv6Addr, SocketAddr, UdpSocket};

use std::io;
use std::io::ErrorKind;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum DiscoveryError {
    #[error("no default IPv6 route available")]
    NoV6Connectivity,
    #[error("only link local addr available: {0}")]
    LinkLocalOnly(Ipv6Addr),
    #[error("unexpected route address family")]
    UnsupportedAddressFamily,
    #[error("ipv6 socket error: {0}")]
    Socket(io::Error),
}

impl DiscoveryError {
    pub fn is_transient(&self) -> bool {
        match self {
            DiscoveryError::NoV6Connectivity | DiscoveryError::LinkLocalOnly(_) => true,
            DiscoveryError::UnsupportedAddressFamily | DiscoveryError::Socket(_) => false,
        }
    }
}

/// Destination port for the discovery connect. No packet is ever
/// sent, so any nonzero value works. 9 is the discard service, chosen
/// to signal that no traffic is intended.
const DISCOVERY_PORT: u16 = 9;

/// Discover the local IPv6 address the kernel would use as source
/// for traffic to `remote`.
///
/// Connecting a UDP socket fixes the local half of the flow without
/// sending a packet. The kernel runs source address selection
/// (RFC 6724) for the destination and `getsockname` reports the
/// result.
///
/// Single-shot. The caller owns retry policy, branching on
/// [`DiscoveryError::is_transient`].
pub fn discover_local_v6(remote: Ipv6Addr) -> Result<Ipv6Addr, DiscoveryError> {
    let socket = UdpSocket::bind((Ipv6Addr::UNSPECIFIED, 0)).map_err(DiscoveryError::Socket)?;
    socket
        .connect(SocketAddr::from((remote, DISCOVERY_PORT)))
        .map_err(classify_socket_err)?;

    let ip = socket.local_addr().map_err(DiscoveryError::Socket)?.ip();

    match ip {
        IpAddr::V6(ipv6) => {
            if ipv6.is_unicast_link_local() {
                return Err(DiscoveryError::LinkLocalOnly(ipv6));
            }
            Ok(ipv6)
        }
        _ => Err(DiscoveryError::UnsupportedAddressFamily),
    }
}

fn classify_socket_err(e: io::Error) -> DiscoveryError {
    match e.kind() {
        ErrorKind::NetworkUnreachable | ErrorKind::HostUnreachable | ErrorKind::NetworkDown => {
            DiscoveryError::NoV6Connectivity
        }
        _ => DiscoveryError::Socket(e),
    }
}
