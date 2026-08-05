//! Tunnel state and backend interface shared by each platform.

use std::{
    net::{Ipv4Addr, Ipv6Addr},
    num::NonZeroU8,
};
use thiserror::Error;

// RFC 6333 5.7: AFTR element reserved address
const AFTR_V4_ELEMENT: Ipv4Addr = Ipv4Addr::new(192, 0, 0, 1);
// RFC 6333 5.7: B4 elements live in 192.0.0.0/29 (B4 hosts at .2..=.6,
// AFTR at .1, .0 subnet, .7 broadcast).
const B4_V4_PREFIX_LEN: u8 = 29;

#[cfg(target_os = "linux")]
/// Linux IP6 tunnel backend.
pub mod linux;

#[cfg(target_os = "illumos")]
/// illumos backend using `dladm`, `ipadm`, and a routing socket.
pub mod illumos;

/// Tunnel state observed from the operating system.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Observed {
    /// The managed tunnel does not exist.
    Absent,
    /// The managed tunnel exists with the reported properties.
    Present {
        /// Local IPv6 tunnel endpoint.
        local_v6: Ipv6Addr,
        /// Remote IPv6 tunnel endpoint.
        remote_v6: Ipv6Addr,
        /// Effective interface MTU.
        mtu: u32,
        /// Effective IPv6 encapsulation limit, or disabled.
        encapsulation_limit: Option<u8>,
        /// Whether the interface is administratively up.
        admin_up: bool,
    },
}

/// Complete state required to create or rebuild a tunnel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DesiredState {
    /// Local IPv6 tunnel endpoint.
    pub local_v6: Ipv6Addr,
    /// Remote IPv6 tunnel endpoint.
    pub remote_v6: Ipv6Addr,
    /// Reserved local B4 IPv4 address.
    pub local_v4: Ipv4Addr,
    /// Requested interface MTU, or the platform default.
    pub mtu: Option<u32>,
    /// Requested IPv6 encapsulation limit behavior, or the platform default.
    pub encapsulation_limit: Option<EncapsulationLimit>,
}

/// Mutable properties to update without rebuilding a tunnel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TunnelUpdate {
    /// New MTU, if it differs.
    pub mtu: Option<u32>,
    /// New encapsulation limit policy, if it differs.
    pub encapsulation_limit: Option<EncapsulationLimit>,
    /// Whether to bring an administratively down interface up.
    pub bring_up: bool,
}

impl TunnelUpdate {
    pub(crate) fn is_empty(&self) -> bool {
        self.mtu.is_none() && self.encapsulation_limit.is_none() && !self.bring_up
    }
}

/// Platform backend failures grouped by tunnel operation.
#[derive(Debug, Error)]
pub enum TunnelError {
    #[error("creating tunnel: {0}")]
    /// Tunnel creation failed.
    CreationFailed(String),
    #[error("destroying tunnel: {0}")]
    /// Tunnel removal failed.
    DestroyFailed(String),
    #[error("assigning address: {0}")]
    /// IPv4 endpoint assignment failed.
    AddressFailed(String),
    #[error("setting route: {0}")]
    /// Default route configuration failed.
    RouteFailed(String),
    #[error("checking tunnel status: {0}")]
    /// Observing existing tunnel state failed.
    StatusCheckFailed(String),
    #[error("updating tunnel: {0}")]
    /// Updating mutable tunnel state failed.
    UpdateFailed(String),
}

/// Desired IPv6 tunnel encapsulation limit behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncapsulationLimit {
    /// Disable encapsulation limit insertion.
    Disabled,
    /// Insert the specified encapsulation limit, which must not be zero.
    Value(NonZeroU8),
}

/// Operating system adapter used by reconciliation.
pub trait TunnelBackend: Send + Sync {
    /// Creates the tunnel and its required network state.
    ///
    /// If setup fails after creating platform state, the backend makes a best
    /// effort to remove state created by that call. The original setup error is
    /// returned. Cleanup errors are logged separately.
    fn setup(&self, desired: DesiredState) -> impl Future<Output = Result<(), TunnelError>> + Send;
    /// Updates mutable properties of an existing tunnel.
    fn update(
        &self,
        desired: DesiredState,
        update: TunnelUpdate,
    ) -> impl Future<Output = Result<(), TunnelError>> + Send;
    /// Observes whether the tunnel exists and reports its effective state.
    fn observe(&self) -> impl Future<Output = Result<Observed, TunnelError>> + Send;
    /// Removes the tunnel and associated IPv4 route state.
    fn teardown(&self) -> impl Future<Output = Result<(), TunnelError>> + Send;
}
