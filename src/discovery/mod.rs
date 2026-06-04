use std::net::Ipv6Addr;

use std::io;
use thiserror::Error;

#[cfg(target_os = "linux")]
pub mod linux;

#[cfg(target_os = "illumos")]
pub mod illumos;

#[cfg(target_os = "illumos")]
pub use illumos::discover_local_v6;
#[cfg(target_os = "linux")]
pub use linux::discover_local_v6;

#[derive(Error, Debug)]
pub enum DiscoveryError {
    #[error("no default IPv6 route available")]
    NoV6Connectivity,
    #[error("no IPv6 route which can be used")]
    UnreachableRoute,
    #[error("default IPv6 route present but no source")]
    NoPrefSrc,
    #[error("only link local addr available: {0}")]
    LinkLocalOnly(Ipv6Addr),
    #[error("empty response from netlink stream")]
    EmptyResponse,
    #[error("unable to open netlink socket: {0}")]
    #[cfg(target_os = "linux")]
    OpenNetlink(io::Error),
    #[error("unhandled netlink error: {0}")]
    #[cfg(target_os = "linux")]
    Netlink(rtnetlink::Error),
    #[error("unexpected route address family")]
    UnsupportedAddressFamily,
}

impl DiscoveryError {
    pub fn is_transient(&self) -> bool {
        match self {
            DiscoveryError::NoV6Connectivity
            | DiscoveryError::UnreachableRoute
            | DiscoveryError::NoPrefSrc
            | DiscoveryError::LinkLocalOnly(_)
            | DiscoveryError::EmptyResponse => true,
            #[cfg(target_os = "linux")]
            DiscoveryError::OpenNetlink(_) | DiscoveryError::Netlink(_) => false,
            DiscoveryError::UnsupportedAddressFamily => false,
        }
    }
}
