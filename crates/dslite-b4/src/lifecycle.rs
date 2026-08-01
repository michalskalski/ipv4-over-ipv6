use crate::tunnel::{
    DesiredState, EncapsulationLimit, Observed, TunnelBackend, TunnelError, TunnelUpdate,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Desired {
    Resolved(DesiredState),
    Absent,
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Plan {
    Create(DesiredState),
    Update {
        desired: DesiredState,
        changes: TunnelUpdate,
    },
    Rebuild(DesiredState),
    Teardown,
    Keep,
    Noop,
}

/// Computes the action needed to make observed tunnel state match desired state.
///
/// This function only compares state. It does not modify the tunnel.
pub fn plan(observed: &Observed, desired: &Desired) -> Plan {
    let desired = match desired {
        Desired::Resolved(desired) => desired,
        Desired::Absent => {
            return match observed {
                Observed::Present { .. } => Plan::Teardown,
                Observed::Absent => Plan::Noop,
            };
        }
        Desired::Unavailable => return Plan::Keep,
    };

    // tunnel absent - create
    let Observed::Present {
        local_v6,
        remote_v6,
        mtu,
        encapsulation_limit,
        admin_up,
    } = observed
    else {
        return Plan::Create(*desired);
    };

    // endpoints different - rebuild
    if local_v6 != &desired.local_v6 || remote_v6 != &desired.remote_v6 {
        return Plan::Rebuild(*desired);
    }

    let encapsulation_limit_update = match desired.encapsulation_limit {
        None => None,
        Some(EncapsulationLimit::Disabled) if encapsulation_limit.is_none() => None,
        Some(EncapsulationLimit::Value(limit)) if *encapsulation_limit == Some(limit.get()) => None,
        Some(limit) => Some(limit),
    };

    let update = TunnelUpdate {
        mtu: desired.mtu.filter(|desired_mtu| desired_mtu != mtu),
        encapsulation_limit: encapsulation_limit_update,
        bring_up: !admin_up,
    };

    // mutable properties different - update
    if update.is_empty() {
        Plan::Noop
    } else {
        Plan::Update {
            desired: *desired,
            changes: update,
        }
    }
}

pub async fn reconcile_once<B: TunnelBackend>(
    backend: &B,
    observed: &Observed,
    desired: &Desired,
) -> Result<Plan, TunnelError> {
    let action = plan(observed, desired);

    match action {
        Plan::Create(state) => backend.setup(state).await?,
        Plan::Update { desired, changes } => backend.update(desired, changes).await?,
        Plan::Rebuild(state) => {
            backend.teardown().await?;
            backend.setup(state).await?;
        }
        Plan::Teardown => backend.teardown().await?,
        Plan::Keep | Plan::Noop => {}
    }

    Ok(action)
}

#[cfg(test)]
mod tests {
    use std::{num::NonZeroU8, sync::Mutex};

    use super::*;
    use crate::tunnel::EncapsulationLimit;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Call {
        Observe,
        Setup,
        Update(TunnelUpdate),
        Teardown,
    }

    struct FakeBackend {
        observed: Observed,
        calls: Mutex<Vec<Call>>,
    }

    fn fake(observed: Observed) -> FakeBackend {
        FakeBackend {
            observed,
            calls: Mutex::new(Vec::new()),
        }
    }

    impl TunnelBackend for FakeBackend {
        async fn setup(&self, _desired: DesiredState) -> Result<(), TunnelError> {
            self.calls.lock().unwrap().push(Call::Setup);
            Ok(())
        }

        async fn update(
            &self,
            _desired: DesiredState,
            update: TunnelUpdate,
        ) -> Result<(), TunnelError> {
            self.calls.lock().unwrap().push(Call::Update(update));
            Ok(())
        }

        async fn observe(&self) -> Result<Observed, TunnelError> {
            self.calls.lock().unwrap().push(Call::Observe);
            Ok(self.observed)
        }

        async fn teardown(&self) -> Result<(), TunnelError> {
            self.calls.lock().unwrap().push(Call::Teardown);
            Ok(())
        }
    }

    fn calls(backend: &FakeBackend) -> Vec<Call> {
        backend.calls.lock().unwrap().clone()
    }

    fn desired(local_v6: Ipv6Addr, remote_v6: Ipv6Addr) -> Desired {
        Desired::Resolved(DesiredState {
            local_v6,
            remote_v6,
            local_v4: Ipv4Addr::new(192, 0, 0, 2),
            mtu: None,
            encapsulation_limit: None,
        })
    }

    fn resolved_state(desired: Desired) -> DesiredState {
        let Desired::Resolved(state) = desired else {
            unreachable!();
        };
        state
    }

    #[tokio::test]
    async fn reconcile_creates_absent_tunnel() {
        let backend = fake(Observed::Absent);
        let observed = backend.observe().await.unwrap();
        let desired = desired(Ipv6Addr::LOCALHOST, Ipv6Addr::UNSPECIFIED);

        let action = reconcile_once(&backend, &observed, &desired).await.unwrap();

        assert!(matches!(action, Plan::Create(_)));
        assert_eq!(calls(&backend), [Call::Observe, Call::Setup]);
    }

    #[tokio::test]
    async fn reconcile_brings_up_matching_down_tunnel() {
        let local_v6 = Ipv6Addr::LOCALHOST;
        let remote_v6 = Ipv6Addr::UNSPECIFIED;
        let backend = fake(Observed::Present {
            local_v6,
            remote_v6,
            mtu: 1460,
            encapsulation_limit: None,
            admin_up: false,
        });
        let observed = backend.observe().await.unwrap();
        let desired = desired(local_v6, remote_v6);

        let action = reconcile_once(&backend, &observed, &desired).await.unwrap();

        let update = TunnelUpdate {
            mtu: None,
            encapsulation_limit: None,
            bring_up: true,
        };
        assert_eq!(
            action,
            Plan::Update {
                desired: resolved_state(desired),
                changes: update,
            }
        );
        assert_eq!(calls(&backend), [Call::Observe, Call::Update(update)]);
    }

    #[tokio::test]
    async fn reconcile_updates_different_configured_mtu() {
        let local_v6 = Ipv6Addr::LOCALHOST;
        let remote_v6 = Ipv6Addr::UNSPECIFIED;
        let backend = fake(Observed::Present {
            local_v6,
            remote_v6,
            mtu: 1460,
            encapsulation_limit: None,
            admin_up: true,
        });
        let observed = backend.observe().await.unwrap();
        let desired = Desired::Resolved(DesiredState {
            local_v6,
            remote_v6,
            local_v4: Ipv4Addr::new(192, 0, 0, 2),
            mtu: Some(1360),
            encapsulation_limit: None,
        });

        let action = reconcile_once(&backend, &observed, &desired).await.unwrap();

        let update = TunnelUpdate {
            mtu: Some(1360),
            encapsulation_limit: None,
            bring_up: false,
        };
        assert_eq!(
            action,
            Plan::Update {
                desired: resolved_state(desired),
                changes: update,
            }
        );
        assert_eq!(calls(&backend), [Call::Observe, Call::Update(update)]);
    }

    #[tokio::test]
    async fn reconcile_rebuilds_tunnel_with_different_endpoint() {
        let backend = fake(Observed::Present {
            local_v6: Ipv6Addr::LOCALHOST,
            remote_v6: Ipv6Addr::UNSPECIFIED,
            mtu: 1460,
            encapsulation_limit: None,
            admin_up: true,
        });
        let desired = desired(
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
            Ipv6Addr::UNSPECIFIED,
        );
        let observed = backend.observe().await.unwrap();

        let action = reconcile_once(&backend, &observed, &desired).await.unwrap();

        assert!(matches!(action, Plan::Rebuild(_)));
        assert_eq!(
            calls(&backend),
            [Call::Observe, Call::Teardown, Call::Setup]
        );
    }

    #[tokio::test]
    async fn reconcile_does_nothing_when_tunnel_matches() {
        let local_v6 = Ipv6Addr::LOCALHOST;
        let remote_v6 = Ipv6Addr::UNSPECIFIED;
        let backend = fake(Observed::Present {
            local_v6,
            remote_v6,
            mtu: 1460,
            encapsulation_limit: None,
            admin_up: true,
        });
        let desired = desired(local_v6, remote_v6);
        let observed = backend.observe().await.unwrap();

        let action = reconcile_once(&backend, &observed, &desired).await.unwrap();

        assert_eq!(action, Plan::Noop);
        assert_eq!(calls(&backend), [Call::Observe]);
    }

    #[tokio::test]
    async fn reconcile_keeps_tunnel_when_desired_is_unavailable() {
        let backend = fake(Observed::Present {
            local_v6: Ipv6Addr::LOCALHOST,
            remote_v6: Ipv6Addr::UNSPECIFIED,
            mtu: 1460,
            encapsulation_limit: None,
            admin_up: true,
        });
        let observed = backend.observe().await.unwrap();

        let action = reconcile_once(&backend, &observed, &Desired::Unavailable)
            .await
            .unwrap();

        assert_eq!(action, Plan::Keep);
        assert_eq!(calls(&backend), [Call::Observe]);
    }

    #[tokio::test]
    async fn reconcile_tears_down_tunnel_when_desired_is_absent() {
        let backend = fake(Observed::Present {
            local_v6: Ipv6Addr::LOCALHOST,
            remote_v6: Ipv6Addr::UNSPECIFIED,
            mtu: 1460,
            encapsulation_limit: None,
            admin_up: true,
        });
        let observed = backend.observe().await.unwrap();

        let action = reconcile_once(&backend, &observed, &Desired::Absent)
            .await
            .unwrap();

        assert_eq!(action, Plan::Teardown);
        assert_eq!(calls(&backend), [Call::Observe, Call::Teardown]);
    }

    #[test]
    fn noop_when_observed_and_desired_are_absent() {
        let action = plan(&Observed::Absent, &Desired::Absent);

        assert_eq!(action, Plan::Noop);
    }

    #[test]
    fn keep_when_observed_absent_and_desired_unavailable() {
        let action = plan(&Observed::Absent, &Desired::Unavailable);
        assert_eq!(action, Plan::Keep)
    }

    #[test]
    fn keep_when_observed_present_and_desired_unavailable() {
        let addr = Ipv6Addr::LOCALHOST;
        let observed = Observed::Present {
            local_v6: addr,
            remote_v6: addr,
            mtu: 1460,
            encapsulation_limit: None,
            admin_up: true,
        };
        let action = plan(&observed, &Desired::Unavailable);
        assert_eq!(action, Plan::Keep)
    }

    #[test]
    fn create_when_observed_absent_and_desired_resolved() {
        let desired = desired(Ipv6Addr::LOCALHOST, Ipv6Addr::UNSPECIFIED);

        let action = plan(&Observed::Absent, &desired);

        let Desired::Resolved(state) = desired else {
            unreachable!();
        };
        assert_eq!(action, Plan::Create(state))
    }

    #[test]
    fn noop_when_endpoints_match_and_tunnel_is_up() {
        let local_v6 = Ipv6Addr::LOCALHOST;
        let remote_v6 = Ipv6Addr::UNSPECIFIED;
        let observed = Observed::Present {
            local_v6,
            remote_v6,
            mtu: 1460,
            encapsulation_limit: None,
            admin_up: true,
        };
        let desired = desired(local_v6, remote_v6);

        let action = plan(&observed, &desired);

        assert_eq!(action, Plan::Noop)
    }

    #[test]
    fn noop_when_configured_mtu_matches() {
        let local_v6 = Ipv6Addr::LOCALHOST;
        let remote_v6 = Ipv6Addr::UNSPECIFIED;
        let observed = Observed::Present {
            local_v6,
            remote_v6,
            mtu: 1460,
            encapsulation_limit: None,
            admin_up: true,
        };
        let desired = Desired::Resolved(DesiredState {
            local_v6,
            remote_v6,
            local_v4: Ipv4Addr::new(192, 0, 0, 2),
            mtu: Some(1460),
            encapsulation_limit: None,
        });

        let action = plan(&observed, &desired);

        assert_eq!(action, Plan::Noop)
    }

    #[test]
    fn update_when_configured_mtu_differs() {
        let local_v6 = Ipv6Addr::LOCALHOST;
        let remote_v6 = Ipv6Addr::UNSPECIFIED;
        let observed = Observed::Present {
            local_v6,
            remote_v6,
            mtu: 1460,
            encapsulation_limit: None,
            admin_up: true,
        };
        let desired = Desired::Resolved(DesiredState {
            local_v6,
            remote_v6,
            local_v4: Ipv4Addr::new(192, 0, 0, 2),
            mtu: Some(1360),
            encapsulation_limit: None,
        });

        let action = plan(&observed, &desired);

        let update = TunnelUpdate {
            mtu: Some(1360),
            encapsulation_limit: None,
            bring_up: false,
        };
        assert_eq!(
            action,
            Plan::Update {
                desired: resolved_state(desired),
                changes: update,
            }
        )
    }

    #[test]
    fn update_when_endpoints_match_and_tunnel_is_down() {
        let local_v6 = Ipv6Addr::LOCALHOST;
        let remote_v6 = Ipv6Addr::UNSPECIFIED;
        let observed = Observed::Present {
            local_v6,
            remote_v6,
            mtu: 1460,
            encapsulation_limit: None,
            admin_up: false,
        };
        let desired = desired(local_v6, remote_v6);

        let action = plan(&observed, &desired);

        assert_eq!(
            action,
            Plan::Update {
                desired: resolved_state(desired),
                changes: TunnelUpdate {
                    mtu: None,
                    encapsulation_limit: None,
                    bring_up: true,
                },
            }
        )
    }

    #[test]
    fn plans_encapsulation_limit_updates() {
        let value = EncapsulationLimit::Value(NonZeroU8::new(4).unwrap());
        let cases = [
            ("omitted", None, Some(4), None),
            (
                "disabled and absent",
                Some(EncapsulationLimit::Disabled),
                None,
                None,
            ),
            (
                "disabled but present",
                Some(EncapsulationLimit::Disabled),
                Some(4),
                Some(EncapsulationLimit::Disabled),
            ),
            ("matching value", Some(value), Some(4), None),
            ("value but absent", Some(value), None, Some(value)),
            ("different value", Some(value), Some(5), Some(value)),
            ("zero-valued option", Some(value), Some(0), Some(value)),
        ];

        for (name, desired_limit, observed_limit, expected_update) in cases {
            let local_v6 = Ipv6Addr::LOCALHOST;
            let remote_v6 = Ipv6Addr::UNSPECIFIED;
            let observed = Observed::Present {
                local_v6,
                remote_v6,
                mtu: 1460,
                encapsulation_limit: observed_limit,
                admin_up: true,
            };
            let desired = Desired::Resolved(DesiredState {
                local_v6,
                remote_v6,
                local_v4: Ipv4Addr::new(192, 0, 0, 2),
                mtu: None,
                encapsulation_limit: desired_limit,
            });

            let action = plan(&observed, &desired);
            let expected = match expected_update {
                Some(encapsulation_limit) => Plan::Update {
                    desired: resolved_state(desired),
                    changes: TunnelUpdate {
                        mtu: None,
                        encapsulation_limit: Some(encapsulation_limit),
                        bring_up: false,
                    },
                },
                None => Plan::Noop,
            };

            assert_eq!(action, expected, "{name}");
        }
    }

    #[test]
    fn rebuild_when_local_endpoint_differs() {
        let remote_v6 = Ipv6Addr::UNSPECIFIED;
        let observed = Observed::Present {
            local_v6: Ipv6Addr::LOCALHOST,
            remote_v6,
            mtu: 1460,
            encapsulation_limit: None,
            admin_up: true,
        };
        let desired = desired(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1), remote_v6);

        let action = plan(&observed, &desired);

        let Desired::Resolved(state) = desired else {
            unreachable!();
        };
        assert_eq!(action, Plan::Rebuild(state))
    }

    #[test]
    fn rebuild_when_remote_endpoint_differs() {
        let local_v6 = Ipv6Addr::LOCALHOST;
        let observed = Observed::Present {
            local_v6,
            remote_v6: Ipv6Addr::UNSPECIFIED,
            mtu: 1460,
            encapsulation_limit: None,
            admin_up: true,
        };
        let desired = desired(local_v6, Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));

        let action = plan(&observed, &desired);

        let Desired::Resolved(state) = desired else {
            unreachable!();
        };
        assert_eq!(action, Plan::Rebuild(state))
    }
}
