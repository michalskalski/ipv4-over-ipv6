use crate::tunnel::{
    AFTR_V4_ELEMENT, B4_V4_PREFIX_LEN, DesiredState, Observed, TunnelBackend, TunnelError,
};
use futures_util::stream::TryStreamExt;
use rtnetlink::{
    Handle, LinkMessageBuilder, LinkUnspec, RouteMessageBuilder, new_connection,
    packet_route::{
        IpProtocol,
        link::{
            InfoData, InfoIpTunnel, InfoKind, Ip6TunnelFlags, LinkAttribute, LinkFlags, LinkInfo,
            LinkMessage,
        },
    },
};
use std::net::{IpAddr, Ipv4Addr};

fn observed_from_link(link: &LinkMessage) -> Result<Observed, TunnelError> {
    let admin_up = link.header.flags.contains(LinkFlags::Up);
    let mut local_v6 = None;
    let mut remote_v6 = None;
    let mut mtu = None;

    for attribute in &link.attributes {
        if let LinkAttribute::Mtu(size) = attribute {
            mtu = Some(*size);
        }
        let LinkAttribute::LinkInfo(link_info) = attribute else {
            continue;
        };

        for info in link_info {
            let LinkInfo::Data(InfoData::IpTunnel(tunnel_info)) = info else {
                continue;
            };

            for info in tunnel_info {
                match info {
                    InfoIpTunnel::Local(IpAddr::V6(addr)) => local_v6 = Some(*addr),
                    InfoIpTunnel::Remote(IpAddr::V6(addr)) => remote_v6 = Some(*addr),
                    InfoIpTunnel::Local(addr) => {
                        return Err(TunnelError::StatusCheckFailed(format!(
                            "expected local IPv6 addr, got: {addr}"
                        )));
                    }
                    InfoIpTunnel::Remote(addr) => {
                        return Err(TunnelError::StatusCheckFailed(format!(
                            "expected remote IPv6 addr, got: {addr}"
                        )));
                    }
                    _ => {}
                }
            }
        }
    }

    match (local_v6, remote_v6, mtu) {
        (Some(local_v6), Some(remote_v6), Some(mtu)) => Ok(Observed::Present {
            local_v6,
            remote_v6,
            admin_up,
            mtu,
        }),
        _ => Err(TunnelError::StatusCheckFailed(format!(
            "tunnel state incomplete, local={local_v6:?}, remote={remote_v6:?}, mtu={mtu:?}"
        ))),
    }
}

pub struct LinuxBackend {
    name: String,
}

impl LinuxBackend {
    pub fn new(name: String) -> Self {
        Self { name }
    }

    fn open_handle() -> std::io::Result<Handle> {
        let (connection, handle, _) = new_connection()?;
        tokio::spawn(connection);
        Ok(handle)
    }

    async fn get_link_index(&self, handle: &Handle) -> Result<Option<u32>, rtnetlink::Error> {
        let mut links = handle.link().get().match_name(self.name.clone()).execute();
        match links.try_next().await? {
            Some(link) => Ok(Some(link.header.index)),
            None => Ok(None),
        }
    }

    async fn create_tunnel(
        &self,
        handle: &Handle,
        desired: &DesiredState,
    ) -> Result<u32, TunnelError> {
        let message = build_tunnel_message(&self.name, desired);

        handle
            .link()
            .add(message)
            .execute()
            .await
            .map_err(|e| TunnelError::CreationFailed(e.to_string()))?;

        self.get_link_index(handle)
            .await
            .map_err(|e| TunnelError::CreationFailed(e.to_string()))?
            .ok_or_else(|| {
                TunnelError::CreationFailed(format!(
                    "interface {} not found after creation",
                    self.name
                ))
            })
            .inspect(|u| tracing::debug!(name = %self.name, index = %u, "created interface"))
    }

    async fn add_address(
        &self,
        handle: &Handle,
        index: u32,
        local_v4: Ipv4Addr,
    ) -> Result<(), TunnelError> {
        handle
            .address()
            .add(index, std::net::IpAddr::V4(local_v4), B4_V4_PREFIX_LEN)
            .execute()
            .await
            .map_err(|e| TunnelError::AddressFailed(e.to_string()))
            .inspect(|_| tracing::debug!(address = %local_v4, "assigned local address"))
    }

    async fn add_default_route(&self, handle: &Handle, index: u32) -> Result<(), TunnelError> {
        let route = RouteMessageBuilder::<Ipv4Addr>::new()
            .output_interface(index)
            .gateway(AFTR_V4_ELEMENT)
            .build();

        handle
            .route()
            .add(route)
            .execute()
            .await
            .map_err(|e| TunnelError::RouteFailed(e.to_string()))
            .inspect(|_| tracing::debug!("default route added"))
    }
}

impl TunnelBackend for LinuxBackend {
    async fn setup(&self, desired: DesiredState) -> Result<(), TunnelError> {
        let handle = Self::open_handle()
            .map_err(|e| TunnelError::CreationFailed(format!("opening netlink connection: {e}")))?;

        let index = self.create_tunnel(&handle, &desired).await?;
        self.add_address(&handle, index, desired.local_v4).await?;
        self.add_default_route(&handle, index).await?;

        tracing::info!(
            name = %self.name,
            local_v6 = %desired.local_v6,
            remote_v6 = %desired.remote_v6,
            local_v4 = %desired.local_v4,
            "tunnel established"
        );

        Ok(())
    }

    async fn bring_up(&self) -> Result<(), TunnelError> {
        let handle = Self::open_handle()
            .map_err(|e| TunnelError::BringUpFailed(format!("opening netlink connection: {e}")))?;

        let index = self
            .get_link_index(&handle)
            .await
            .map_err(|e| TunnelError::BringUpFailed(e.to_string()))?
            .ok_or_else(|| {
                TunnelError::BringUpFailed(format!("interface {} not found", self.name))
            })?;

        let message = LinkMessageBuilder::<LinkUnspec>::default()
            .index(index)
            .up()
            .build();

        handle
            .link()
            .change(message)
            .execute()
            .await
            .map_err(|e| TunnelError::BringUpFailed(e.to_string()))
            .inspect(|_| tracing::info!(name = %self.name, "interface brought up"))
    }

    async fn observe(&self) -> Result<Observed, TunnelError> {
        let handle = Self::open_handle().map_err(|e| {
            TunnelError::StatusCheckFailed(format!("opening netlink connection: {e}"))
        })?;

        let mut links = handle.link().get().match_name(self.name.clone()).execute();
        match links.try_next().await {
            Ok(Some(link)) => observed_from_link(&link),
            Ok(None) => Ok(Observed::Absent),
            Err(rtnetlink::Error::NetlinkError(message))
                if message.to_io().raw_os_error() == Some(libc::ENODEV) =>
            {
                Ok(Observed::Absent)
            }
            Err(e) => Err(TunnelError::StatusCheckFailed(e.to_string())),
        }
    }

    async fn teardown(&self) -> Result<(), TunnelError> {
        let handle = Self::open_handle()
            .map_err(|e| TunnelError::DestroyFailed(format!("opening netlink connection: {e}")))?;

        let index = self
            .get_link_index(&handle)
            .await
            .map_err(|e| TunnelError::DestroyFailed(e.to_string()))?
            .ok_or_else(|| {
                TunnelError::DestroyFailed(format!("interface {} not found", self.name))
            })?;

        handle
            .link()
            .del(index)
            .execute()
            .await
            .map_err(|e| TunnelError::DestroyFailed(e.to_string()))
            .inspect(|_| tracing::info!(name=%self.name, "interface removed"))
    }
}

fn build_tunnel_message(name: &str, desired: &DesiredState) -> LinkMessage {
    let mut builder = LinkMessageBuilder::<LinkUnspec>::new_with_info_kind(InfoKind::Ip6Tnl)
        .set_info_data(InfoData::IpTunnel(vec![
            InfoIpTunnel::Local(std::net::IpAddr::V6(desired.local_v6)),
            InfoIpTunnel::Remote(std::net::IpAddr::V6(desired.remote_v6)),
            InfoIpTunnel::Protocol(IpProtocol::Ipip),
            InfoIpTunnel::Ipv6Flags(Ip6TunnelFlags::IgnEncapLimit), // TODO: make configurable
        ]))
        .name(name.to_string())
        .up();

    if let Some(mtu) = desired.mtu {
        builder = builder.mtu(mtu);
    }
    builder.build()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv6Addr;

    fn tunnel_link(local: IpAddr, remote: IpAddr, mtu: u32, admin_up: bool) -> LinkMessage {
        let mut link = LinkMessage::default();
        if admin_up {
            link.header.flags.insert(LinkFlags::Up);
        }
        link.attributes = vec![
            LinkAttribute::LinkInfo(vec![
                LinkInfo::Kind(InfoKind::Ip6Tnl),
                LinkInfo::Data(InfoData::IpTunnel(vec![
                    InfoIpTunnel::Local(local),
                    InfoIpTunnel::Remote(remote),
                ])),
            ]),
            LinkAttribute::Mtu(mtu),
        ];
        link
    }

    #[test]
    fn extracts_endpoints_and_admin_state_from_link() {
        let local_v6 = "2001:db8:1::1".parse().unwrap();
        let remote_v6 = "2001:db8:1::2".parse().unwrap();
        let mtu: u32 = 1460;
        let link = tunnel_link(IpAddr::V6(local_v6), IpAddr::V6(remote_v6), mtu, true);

        let observed = observed_from_link(&link).unwrap();

        assert_eq!(
            observed,
            Observed::Present {
                local_v6,
                remote_v6,
                mtu,
                admin_up: true,
            }
        );
    }

    #[test]
    fn reports_missing_remote_endpoint() {
        let local_v6 = "2001:db8:1::1".parse().unwrap();
        let mut link = tunnel_link(
            IpAddr::V6(local_v6),
            IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            1460,
            false,
        );
        let LinkAttribute::LinkInfo(link_info) = &mut link.attributes[0] else {
            unreachable!();
        };
        let LinkInfo::Data(InfoData::IpTunnel(tunnel_info)) = &mut link_info[1] else {
            unreachable!();
        };
        tunnel_info.retain(|info| !matches!(info, InfoIpTunnel::Remote(_)));

        let error = observed_from_link(&link).unwrap_err();

        assert_eq!(
            error.to_string(),
            format!(
                "checking tunnel status: tunnel state incomplete, local=Some({local_v6}), remote=None, mtu=Some(1460)"
            )
        );
    }

    #[test]
    fn rejects_ipv4_endpoint() {
        let link = tunnel_link(
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            IpAddr::V6("2001:db8:1::2".parse().unwrap()),
            1460,
            true,
        );

        let error = observed_from_link(&link).unwrap_err();

        assert_eq!(
            error.to_string(),
            "checking tunnel status: expected local IPv6 addr, got: 192.0.2.1"
        );
    }

    #[test]
    fn omits_mtu_when_not_configured() {
        let local_v6 = "2001:db8:1::1".parse().unwrap();
        let remote_v6 = "2001:db8:1::2".parse().unwrap();
        let local_v4 = "192.0.0.2".parse().unwrap();

        let desired = DesiredState {
            local_v6,
            remote_v6,
            local_v4,
            mtu: None,
        };
        let msg = build_tunnel_message("tunnel", &desired);

        assert!(
            !msg.attributes
                .iter()
                .any(|attribute| matches!(attribute, LinkAttribute::Mtu(_)))
        );
    }

    #[test]
    fn includes_configured_mtu() {
        let local_v6 = "2001:db8:1::1".parse().unwrap();
        let remote_v6 = "2001:db8:1::2".parse().unwrap();
        let local_v4 = "192.0.0.2".parse().unwrap();

        let desired = DesiredState {
            local_v6,
            remote_v6,
            local_v4,
            mtu: Some(1360),
        };
        let msg = build_tunnel_message("tunnel", &desired);

        assert!(msg.attributes.contains(&LinkAttribute::Mtu(1360)));
    }
}
