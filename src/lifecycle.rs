use std::net::Ipv6Addr;

struct DesiredEndpoints {
    local_v6: Ipv6Addr,
    remote_v6: Ipv6Addr,
}

enum Observed {
    Absent,
    Present {
        local_v6: Ipv6Addr,
        remote_v6: Ipv6Addr,
        admin_up: bool,
    },
}

enum Desired {
    Resolved(DesiredEndpoints),
    Unavailable,
}

#[derive(PartialEq, Debug)]
enum Action {
    Create,
    BringUp,
    Rebuild,
    Keep,
    Noop,
}

fn decide(observed: &Observed, desired: &Desired) -> Action {
    match (observed, desired) {
        (Observed::Absent, Desired::Unavailable) => Action::Keep,
        (Observed::Present { .. }, Desired::Unavailable) => Action::Keep,
        (Observed::Absent, Desired::Resolved(_)) => Action::Create,
        (
            Observed::Present {
                local_v6,
                remote_v6,
                admin_up,
            },
            Desired::Resolved(endpoints),
        ) if local_v6 == &endpoints.local_v6 && remote_v6 == &endpoints.remote_v6 => {
            if *admin_up {
                Action::Noop
            } else {
                Action::BringUp
            }
        }
        // At least one endpoint differs.
        (Observed::Present { .. }, Desired::Resolved(_)) => Action::Rebuild,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
            admin_up: true,
        };
        let action = decide(&observed, &Desired::Unavailable);
        assert_eq!(action, Action::Keep)
    }

    #[test]
    fn create_when_observed_absent_and_desired_resolved() {
        let desired = Desired::Resolved(DesiredEndpoints {
            local_v6: Ipv6Addr::LOCALHOST,
            remote_v6: Ipv6Addr::UNSPECIFIED,
        });

        let action = decide(&Observed::Absent, &desired);

        assert_eq!(action, Action::Create)
    }

    #[test]
    fn noop_when_endpoints_match_and_tunnel_is_up() {
        let local_v6 = Ipv6Addr::LOCALHOST;
        let remote_v6 = Ipv6Addr::UNSPECIFIED;
        let observed = Observed::Present {
            local_v6,
            remote_v6,
            admin_up: true,
        };
        let desired = Desired::Resolved(DesiredEndpoints {
            local_v6,
            remote_v6,
        });

        let action = decide(&observed, &desired);

        assert_eq!(action, Action::Noop)
    }

    #[test]
    fn bring_up_when_endpoints_match_and_tunnel_is_down() {
        let local_v6 = Ipv6Addr::LOCALHOST;
        let remote_v6 = Ipv6Addr::UNSPECIFIED;
        let observed = Observed::Present {
            local_v6,
            remote_v6,
            admin_up: false,
        };
        let desired = Desired::Resolved(DesiredEndpoints {
            local_v6,
            remote_v6,
        });

        let action = decide(&observed, &desired);

        assert_eq!(action, Action::BringUp)
    }

    #[test]
    fn rebuild_when_local_endpoint_differs() {
        let remote_v6 = Ipv6Addr::UNSPECIFIED;
        let observed = Observed::Present {
            local_v6: Ipv6Addr::LOCALHOST,
            remote_v6,
            admin_up: true,
        };
        let desired = Desired::Resolved(DesiredEndpoints {
            local_v6: Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
            remote_v6,
        });

        let action = decide(&observed, &desired);

        assert_eq!(action, Action::Rebuild)
    }

    #[test]
    fn rebuild_when_remote_endpoint_differs() {
        let local_v6 = Ipv6Addr::LOCALHOST;
        let observed = Observed::Present {
            local_v6,
            remote_v6: Ipv6Addr::UNSPECIFIED,
            admin_up: true,
        };
        let desired = Desired::Resolved(DesiredEndpoints {
            local_v6,
            remote_v6: Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
        });

        let action = decide(&observed, &desired);

        assert_eq!(action, Action::Rebuild)
    }
}
