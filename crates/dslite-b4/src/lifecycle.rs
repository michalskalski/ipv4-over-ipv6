use crate::tunnel::{DesiredState, Observed, TunnelBackend, TunnelError};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Desired {
    Resolved(DesiredState),
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Create(DesiredState),
    BringUp,
    Rebuild(DesiredState),
    Keep,
    Noop,
}

fn decide(observed: &Observed, desired: &Desired) -> Action {
    match (observed, desired) {
        (Observed::Absent, Desired::Unavailable) => Action::Keep,
        (Observed::Present { .. }, Desired::Unavailable) => Action::Keep,
        (Observed::Absent, Desired::Resolved(ds)) => Action::Create(*ds),
        (
            Observed::Present {
                local_v6,
                remote_v6,
                mtu,
                admin_up,
            },
            Desired::Resolved(endpoints),
        ) if local_v6 == &endpoints.local_v6
            && remote_v6 == &endpoints.remote_v6
            && endpoints.mtu.is_none_or(|desired_mtu| desired_mtu == *mtu) =>
        {
            if *admin_up {
                Action::Noop
            } else {
                Action::BringUp
            }
        }
        // At least one endpoint or the configured MTU differs.
        (Observed::Present { .. }, Desired::Resolved(ds)) => Action::Rebuild(*ds),
    }
}

pub async fn reconcile_once<B: TunnelBackend>(
    backend: &B,
    observed: &Observed,
    desired: &Desired,
) -> Result<Action, TunnelError> {
    let action = decide(observed, desired);

    match action {
        Action::Create(state) => backend.setup(state).await?,
        Action::BringUp => backend.bring_up().await?,
        Action::Rebuild(state) => {
            backend.teardown().await?;
            backend.setup(state).await?;
        }
        Action::Keep | Action::Noop => {}
    }

    Ok(action)
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Call {
        Observe,
        Setup,
        BringUp,
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

        async fn bring_up(&self) -> Result<(), TunnelError> {
            self.calls.lock().unwrap().push(Call::BringUp);
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
        })
    }

    #[tokio::test]
    async fn reconcile_creates_absent_tunnel() {
        let backend = fake(Observed::Absent);
        let observed = backend.observe().await.unwrap();
        let desired = desired(Ipv6Addr::LOCALHOST, Ipv6Addr::UNSPECIFIED);

        let action = reconcile_once(&backend, &observed, &desired).await.unwrap();

        assert!(matches!(action, Action::Create(_)));
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
            admin_up: false,
        });
        let observed = backend.observe().await.unwrap();
        let desired = desired(local_v6, remote_v6);

        let action = reconcile_once(&backend, &observed, &desired).await.unwrap();

        assert_eq!(action, Action::BringUp);
        assert_eq!(calls(&backend), [Call::Observe, Call::BringUp]);
    }

    #[tokio::test]
    async fn reconcile_rebuilds_tunnel_with_different_endpoint() {
        let backend = fake(Observed::Present {
            local_v6: Ipv6Addr::LOCALHOST,
            remote_v6: Ipv6Addr::UNSPECIFIED,
            mtu: 1460,
            admin_up: true,
        });
        let desired = desired(
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
            Ipv6Addr::UNSPECIFIED,
        );
        let observed = backend.observe().await.unwrap();

        let action = reconcile_once(&backend, &observed, &desired).await.unwrap();

        assert!(matches!(action, Action::Rebuild(_)));
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
            admin_up: true,
        });
        let desired = desired(local_v6, remote_v6);
        let observed = backend.observe().await.unwrap();

        let action = reconcile_once(&backend, &observed, &desired).await.unwrap();

        assert_eq!(action, Action::Noop);
        assert_eq!(calls(&backend), [Call::Observe]);
    }

    #[tokio::test]
    async fn reconcile_keeps_tunnel_when_desired_is_unavailable() {
        let backend = fake(Observed::Present {
            local_v6: Ipv6Addr::LOCALHOST,
            remote_v6: Ipv6Addr::UNSPECIFIED,
            mtu: 1460,
            admin_up: true,
        });
        let observed = backend.observe().await.unwrap();

        let action = reconcile_once(&backend, &observed, &Desired::Unavailable)
            .await
            .unwrap();

        assert_eq!(action, Action::Keep);
        assert_eq!(calls(&backend), [Call::Observe]);
    }

    #[test]
    fn keep_when_observed_absent_and_desired_unavailable() {
        let action = decide(&Observed::Absent, &Desired::Unavailable);
        assert_eq!(action, Action::Keep)
    }

    #[test]
    fn keep_when_observed_present_and_desired_unavailable() {
        let addr = Ipv6Addr::LOCALHOST;
        let observed = Observed::Present {
            local_v6: addr,
            remote_v6: addr,
            mtu: 1460,
            admin_up: true,
        };
        let action = decide(&observed, &Desired::Unavailable);
        assert_eq!(action, Action::Keep)
    }

    #[test]
    fn create_when_observed_absent_and_desired_resolved() {
        let desired = desired(Ipv6Addr::LOCALHOST, Ipv6Addr::UNSPECIFIED);

        let action = decide(&Observed::Absent, &desired);

        let Desired::Resolved(state) = desired else {
            unreachable!();
        };
        assert_eq!(action, Action::Create(state))
    }

    #[test]
    fn noop_when_endpoints_match_and_tunnel_is_up() {
        let local_v6 = Ipv6Addr::LOCALHOST;
        let remote_v6 = Ipv6Addr::UNSPECIFIED;
        let observed = Observed::Present {
            local_v6,
            remote_v6,
            mtu: 1460,
            admin_up: true,
        };
        let desired = desired(local_v6, remote_v6);

        let action = decide(&observed, &desired);

        assert_eq!(action, Action::Noop)
    }

    #[test]
    fn noop_when_configured_mtu_matches() {
        let local_v6 = Ipv6Addr::LOCALHOST;
        let remote_v6 = Ipv6Addr::UNSPECIFIED;
        let observed = Observed::Present {
            local_v6,
            remote_v6,
            mtu: 1460,
            admin_up: true,
        };
        let desired = Desired::Resolved(DesiredState {
            local_v6,
            remote_v6,
            local_v4: Ipv4Addr::new(192, 0, 0, 2),
            mtu: Some(1460),
        });

        let action = decide(&observed, &desired);

        assert_eq!(action, Action::Noop)
    }

    #[test]
    fn rebuild_when_configured_mtu_differs() {
        let local_v6 = Ipv6Addr::LOCALHOST;
        let remote_v6 = Ipv6Addr::UNSPECIFIED;
        let observed = Observed::Present {
            local_v6,
            remote_v6,
            mtu: 1460,
            admin_up: true,
        };
        let desired = Desired::Resolved(DesiredState {
            local_v6,
            remote_v6,
            local_v4: Ipv4Addr::new(192, 0, 0, 2),
            mtu: Some(1360),
        });

        let action = decide(&observed, &desired);

        let Desired::Resolved(state) = desired else {
            unreachable!();
        };
        assert_eq!(action, Action::Rebuild(state))
    }

    #[test]
    fn bring_up_when_endpoints_match_and_tunnel_is_down() {
        let local_v6 = Ipv6Addr::LOCALHOST;
        let remote_v6 = Ipv6Addr::UNSPECIFIED;
        let observed = Observed::Present {
            local_v6,
            remote_v6,
            mtu: 1460,
            admin_up: false,
        };
        let desired = desired(local_v6, remote_v6);

        let action = decide(&observed, &desired);

        assert_eq!(action, Action::BringUp)
    }

    #[test]
    fn rebuild_when_local_endpoint_differs() {
        let remote_v6 = Ipv6Addr::UNSPECIFIED;
        let observed = Observed::Present {
            local_v6: Ipv6Addr::LOCALHOST,
            remote_v6,
            mtu: 1460,
            admin_up: true,
        };
        let desired = desired(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1), remote_v6);

        let action = decide(&observed, &desired);

        let Desired::Resolved(state) = desired else {
            unreachable!();
        };
        assert_eq!(action, Action::Rebuild(state))
    }

    #[test]
    fn rebuild_when_remote_endpoint_differs() {
        let local_v6 = Ipv6Addr::LOCALHOST;
        let observed = Observed::Present {
            local_v6,
            remote_v6: Ipv6Addr::UNSPECIFIED,
            mtu: 1460,
            admin_up: true,
        };
        let desired = desired(local_v6, Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));

        let action = decide(&observed, &desired);

        let Desired::Resolved(state) = desired else {
            unreachable!();
        };
        assert_eq!(action, Action::Rebuild(state))
    }
}
