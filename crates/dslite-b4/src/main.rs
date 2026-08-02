use anyhow::Context;
use clap::{Parser, Subcommand};
#[cfg(target_os = "illumos")]
use dslite_b4::tunnel::illumos::IllumosBackend;
#[cfg(target_os = "linux")]
use dslite_b4::tunnel::linux::LinuxBackend;
use dslite_b4::{
    aftr::AftrSelector,
    aftr_discovery::{DiscoveryRuntime, DiscoveryState},
    config::{AftrAddress, Config},
    discovery::discover_local_v6,
    dns::resolve_aftr_addresses,
    lifecycle::{self, Desired, reconcile_once},
    network_changes::NetworkChanges,
    runtime_state::{
        self, PidFile, clear_provided_aftr, signal_daemon_refresh, write_provided_aftr,
    },
    tunnel::{DesiredState, Observed, TunnelBackend},
};
use std::{
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
use tokio::signal;

mod wake;
use wake::{WakeHint, schedule_next_wake};

#[derive(Parser)]
#[command(name = "dslite-b4", about = "DS-Lite B4 client")]
struct Cli {
    #[arg(short, long, default_value = "/etc/dslite-b4.toml", global = true)]
    config: PathBuf,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    Run,
    CheckConfig,
    SetAftr { addr: String },
    ClearAftr,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "dslite_b4=info".parse().unwrap()),
        )
        .init();
    let cli = Cli::parse();
    let config = load_config(&cli.config)?;
    match cli.command.unwrap_or(Commands::Run) {
        Commands::CheckConfig => {
            DiscoveryRuntime::validate_config(&config.discovery)?;

            tracing::info!(?config);
        }
        Commands::Run => {
            let discovery = DiscoveryRuntime::from_config(&config.discovery)?;
            let _pid = PidFile::create(&config.runtime.state_dir)?;

            #[cfg(target_os = "linux")]
            let backend = LinuxBackend::new(config.tunnel.name.clone());
            #[cfg(target_os = "illumos")]
            let backend = IllumosBackend::new(config.tunnel.name.clone())?;

            run(backend, &config, discovery).await?
        }
        Commands::SetAftr { addr } => {
            write_provided_aftr(&config.runtime.state_dir, &addr)?;
            signal_daemon_refresh(&config.runtime.state_dir)?;
        }
        Commands::ClearAftr => {
            clear_provided_aftr(&config.runtime.state_dir)?;
            signal_daemon_refresh(&config.runtime.state_dir)?;
        }
    }
    Ok(())
}

/// Desired tunnel state together with its scheduling constraint.
struct DesiredComputation {
    desired: Desired,
    wake_hint: WakeHint,
}

impl DesiredComputation {
    fn resolved(state: DesiredState, next_attempt_at: Option<Instant>) -> Self {
        Self {
            desired: Desired::Resolved(state),
            wake_hint: wake_hint_for_deadline(next_attempt_at, WakeHint::None),
        }
    }

    fn unavailable(next_attempt_at: Option<Instant>) -> Self {
        Self {
            desired: Desired::Unavailable,
            wake_hint: wake_hint_for_deadline(next_attempt_at, WakeHint::GenericRetry),
        }
    }

    fn absent(next_attempt_at: Option<Instant>) -> Self {
        Self {
            desired: Desired::Absent,
            wake_hint: wake_hint_for_deadline(next_attempt_at, WakeHint::None),
        }
    }
}

/// Converts a protocol deadline into a scheduling constraint.
///
/// An expired deadline uses the health interval. This prevents a result with
/// a zero TTL from causing an immediate reconciliation loop.
fn wake_hint_for_deadline(next_attempt_at: Option<Instant>, no_deadline: WakeHint) -> WakeHint {
    match next_attempt_at {
        Some(at) if at > Instant::now() => WakeHint::Deadline(at),
        Some(_) => WakeHint::None,
        None => no_deadline,
    }
}

async fn run<B: TunnelBackend>(
    backend: B,
    config: &Config,
    mut discovery: DiscoveryRuntime,
) -> anyhow::Result<()> {
    let mut sigterm = signal::unix::signal(signal::unix::SignalKind::terminate())?;
    let mut sigusr1 = signal::unix::signal(signal::unix::SignalKind::user_defined1())?;
    let mut network_changes = NetworkChanges::new()?;
    let mut aftr_selector = AftrSelector::new();
    let mut attempt: u64 = 0;
    'reconcile: loop {
        let observed = backend.observe().await?;
        let current_aftr = current_aftr(&observed);
        let computation =
            compute_desired(config, &mut discovery, &mut aftr_selector, current_aftr).await?;
        let action = reconcile_once(&backend, &observed, &computation.desired).await?;
        tracing::info!(?action, "reconciliation completed");

        let wake_hint = computation.wake_hint;

        if !matches!(wake_hint, WakeHint::GenericRetry) {
            attempt = 0;
        }

        let scheduled = schedule_next_wake(
            Instant::now(),
            Duration::from_secs(config.health.interval_secs.get()),
            wake_hint,
            attempt,
        );

        if matches!(wake_hint, WakeHint::GenericRetry) {
            attempt += 1;
        }

        tracing::debug!(
            reason = ?scheduled.reason,
            wait_secs = scheduled
                .at
                .saturating_duration_since(Instant::now())
                .as_secs(),
            "waiting for next reconciliation"
        );

        // Keep waiting for the original absolute deadline after an irrelevant
        // batch so event noise cannot postpone scheduled reconciliation.
        loop {
            tokio::select! {
                _ = tokio::time::sleep_until(scheduled.at.into()) => break,
                result = network_changes.next_batch() => {
                    result?;

                    match network_change_action(
                        &backend,
                        &computation.desired,
                        config.tunnel.local_v6.is_none(),
                    )
                    .await?
                    {
                        NetworkChangeAction::Ignore => {
                            tracing::trace!("network change does not require reconciliation");
                        }
                        NetworkChangeAction::Reconcile => {
                            tracing::debug!("network change requires reconciliation");
                            break;
                        }
                        NetworkChangeAction::RefreshDiscovery => {
                            tracing::debug!("network change requires discovery refresh");
                            discovery.invalidate();
                            break;
                        }
                    }
                }
                _ = sigusr1.recv() => {
                    tracing::debug!("runtime state refresh requested");
                    attempt = 0;
                    break;
                },
                _ = signal::ctrl_c() => break 'reconcile,
                _ = sigterm.recv() => break 'reconcile,
            }
        }
    }

    backend.teardown().await?;
    Ok(())
}

fn current_aftr(observed: &Observed) -> Option<std::net::Ipv6Addr> {
    match observed {
        Observed::Present { remote_v6, .. } => Some(*remote_v6),
        Observed::Absent => None,
    }
}

async fn compute_desired(
    config: &Config,
    discovery: &mut DiscoveryRuntime,
    aftr_selector: &mut AftrSelector,
    current_aftr: Option<std::net::Ipv6Addr>,
) -> anyhow::Result<DesiredComputation> {
    let (aftr, next_attempt_at) = match effective_aftr(config)? {
        Some(aftr) => (aftr, None),

        None => {
            tracing::debug!("no static or externally provided AFTR, trying automatic discovery");

            match discovery.discover_aftr().await {
                Ok(output) => {
                    let (state, next_attempt) = output.into_parts();
                    match state {
                        DiscoveryState::Available(aftr) => (aftr, next_attempt),
                        DiscoveryState::Unavailable => {
                            return Ok(DesiredComputation::unavailable(next_attempt));
                        }
                        DiscoveryState::NoService => {
                            tracing::debug!("automatic AFTR discovery reported no service");
                            return Ok(DesiredComputation::absent(next_attempt));
                        }
                    }
                }
                Err(error) => {
                    tracing::warn!(
                        error = %error, "automatic AFTR discovery unavailable"
                    );

                    return Ok(DesiredComputation::unavailable(None));
                }
            }
        }
    };
    let aftr_candidates = match resolve_aftr_addresses(&aftr).await {
        Ok(addrs) => {
            tracing::debug!(aftr = ?aftr, candidates = ?addrs, "AFTR addresses resolved");
            addrs
        }
        Err(e) => {
            tracing::warn!(error = %e, "AFTR resolution unavailable");
            return Ok(DesiredComputation::unavailable(None));
        }
    };
    let grace = Duration::from_secs(config.health.aftr_missing_grace_secs);
    let Some(aftr_ip) = aftr_selector.select(&aftr_candidates, current_aftr, grace, Instant::now())
    else {
        tracing::debug!("no AFTR address selected from resolved candidates");
        return Ok(DesiredComputation::unavailable(None));
    };
    tracing::debug!(remote_v6 = %aftr_ip, "AFTR address selected");
    let local_v6 = match config.tunnel.local_v6 {
        Some(addr) => {
            tracing::debug!(local_v6 = %addr, source = "config", "local IPv6 address selected");
            addr
        }
        None => match dslite_b4::discovery::discover_local_v6(aftr_ip) {
            Ok(addr) => {
                tracing::debug!(
                    local_v6 = %addr,
                    source = "kernel-route",
                    "local IPv6 address selected"
                );
                addr
            }
            Err(e) if e.is_transient() => {
                tracing::warn!(error = %e, "discover local IPv6 addr failed");
                return Ok(DesiredComputation::unavailable(None));
            }
            Err(e) => return Err(anyhow::anyhow!(e)),
        },
    };

    Ok(DesiredComputation::resolved(
        DesiredState {
            local_v6,
            remote_v6: aftr_ip,
            local_v4: config.tunnel.local_v4,
            mtu: config.tunnel.mtu,
            encapsulation_limit: config.tunnel.encapsulation_limit,
        },
        next_attempt_at,
    ))
}

fn effective_aftr(config: &Config) -> anyhow::Result<Option<AftrAddress>> {
    if let Some(address) = &config.aftr.address {
        tracing::debug!(source = "config", aftr = ?address, "AFTR source selected");
        return Ok(Some(address.clone()));
    }

    let provided = runtime_state::read_provided_aftr(&config.runtime.state_dir)?;
    if let Some(address) = &provided {
        tracing::debug!(
            source = "provided",
            aftr = ?address,
            state_dir = %config.runtime.state_dir.display(),
            "AFTR source selected"
        );
    }

    Ok(provided)
}

fn load_config(path: &Path) -> anyhow::Result<Config> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("reading config {}", path.display()))?;
    toml::from_str(&text).with_context(|| format!("parsing config {}", path.display()))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NetworkChangeAction {
    Ignore,
    Reconcile,
    RefreshDiscovery,
}

/// Classifies the action required after network notifications.
///
/// Tunnel drift always requires reconciliation. When the local IPv6 address
/// is selected automatically, a changed kernel source address requires a
/// discovery refresh. A source selection failure requires reconciliation.
async fn network_change_action<B: TunnelBackend>(
    backend: &B,
    desired: &Desired,
    local_v6_is_automatic: bool,
) -> anyhow::Result<NetworkChangeAction> {
    let observed = backend.observe().await?;

    let tunnel_matches_desired =
        matches!(lifecycle::plan(&observed, desired), lifecycle::Plan::Noop);

    let desired_state = match desired {
        Desired::Resolved(state) => state,
        Desired::Absent if tunnel_matches_desired => {
            return Ok(NetworkChangeAction::Ignore);
        }
        Desired::Absent | Desired::Unavailable => {
            return Ok(NetworkChangeAction::Reconcile);
        }
    };

    if local_v6_is_automatic {
        match discover_local_v6(desired_state.remote_v6) {
            Ok(local_v6) if local_v6 != desired_state.local_v6 => {
                return Ok(NetworkChangeAction::RefreshDiscovery);
            }
            Ok(_) => {}
            Err(error) => {
                tracing::debug!(
                    error = %error,
                    "local IPv6 selection unavailable after network change"
                );
                return Ok(NetworkChangeAction::Reconcile);
            }
        }
    }
    if tunnel_matches_desired {
        Ok(NetworkChangeAction::Ignore)
    } else {
        Ok(NetworkChangeAction::Reconcile)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dslite_b4::tunnel::{TunnelError, TunnelUpdate};
    use std::net::{Ipv4Addr, Ipv6Addr};

    struct FakeBackend {
        observed: Observed,
    }

    impl TunnelBackend for FakeBackend {
        async fn setup(&self, _desired: DesiredState) -> Result<(), TunnelError> {
            unreachable!()
        }

        async fn update(
            &self,
            _desired: DesiredState,
            _update: TunnelUpdate,
        ) -> Result<(), TunnelError> {
            unreachable!()
        }

        async fn observe(&self) -> Result<Observed, TunnelError> {
            Ok(self.observed)
        }

        async fn teardown(&self) -> Result<(), TunnelError> {
            unreachable!()
        }
    }

    fn test_desired_state() -> DesiredState {
        DesiredState {
            local_v6: Ipv6Addr::LOCALHOST,
            remote_v6: Ipv6Addr::LOCALHOST,
            local_v4: Ipv4Addr::new(192, 0, 0, 2),
            mtu: None,
            encapsulation_limit: None,
        }
    }

    #[test]
    fn desired_computation_selects_wake_policy() {
        let deadline = Instant::now() + Duration::from_secs(60);
        let expired_deadline = Instant::now() - Duration::from_secs(1);

        let cases = [
            (
                "resolved static state",
                DesiredComputation::resolved(test_desired_state(), None),
                WakeHint::None,
            ),
            (
                "resolved provisioned state",
                DesiredComputation::resolved(test_desired_state(), Some(deadline)),
                WakeHint::Deadline(deadline),
            ),
            (
                "resolved state with expired deadline",
                DesiredComputation::resolved(test_desired_state(), Some(expired_deadline)),
                WakeHint::None,
            ),
            (
                "absent without protocol deadline",
                DesiredComputation::absent(None),
                WakeHint::None,
            ),
            (
                "absent with protocol deadline",
                DesiredComputation::absent(Some(deadline)),
                WakeHint::Deadline(deadline),
            ),
            (
                "unavailable without protocol deadline",
                DesiredComputation::unavailable(None),
                WakeHint::GenericRetry,
            ),
            (
                "unavailable with protocol deadline",
                DesiredComputation::unavailable(Some(deadline)),
                WakeHint::Deadline(deadline),
            ),
            (
                "unavailable with expired deadline",
                DesiredComputation::unavailable(Some(expired_deadline)),
                WakeHint::None,
            ),
        ];

        for (name, computation, expected) in cases {
            assert_eq!(computation.wake_hint, expected, "{name}");
        }
    }

    #[tokio::test]
    async fn network_change_reconciles_when_desired_is_unavailable() {
        let backend = FakeBackend {
            observed: Observed::Absent,
        };

        assert_eq!(
            network_change_action(&backend, &Desired::Unavailable, false)
                .await
                .unwrap(),
            NetworkChangeAction::Reconcile
        );
    }

    #[tokio::test]
    async fn network_change_is_ignored_when_desired_is_absent() {
        let backend = FakeBackend {
            observed: Observed::Absent,
        };

        assert_eq!(
            network_change_action(&backend, &Desired::Absent, false)
                .await
                .unwrap(),
            NetworkChangeAction::Ignore
        );
    }

    #[tokio::test]
    async fn network_change_reconciles_tunnel_when_desired_is_absent() {
        let backend = FakeBackend {
            observed: Observed::Present {
                local_v6: Ipv6Addr::LOCALHOST,
                remote_v6: Ipv6Addr::LOCALHOST,
                mtu: 1452,
                encapsulation_limit: None,
                admin_up: true,
            },
        };

        assert_eq!(
            network_change_action(&backend, &Desired::Absent, false)
                .await
                .unwrap(),
            NetworkChangeAction::Reconcile
        );
    }

    #[tokio::test]
    async fn network_change_reconciles_tunnel_drift() {
        let backend = FakeBackend {
            observed: Observed::Absent,
        };
        let desired = Desired::Resolved(test_desired_state());

        assert_eq!(
            network_change_action(&backend, &desired, false)
                .await
                .unwrap(),
            NetworkChangeAction::Reconcile
        );
    }

    #[tokio::test]
    async fn network_change_ignores_matching_tunnel_with_explicit_local_v6() {
        let desired_state = test_desired_state();
        let backend = FakeBackend {
            observed: Observed::Present {
                local_v6: desired_state.local_v6,
                remote_v6: desired_state.remote_v6,
                mtu: 1452,
                encapsulation_limit: None,
                admin_up: true,
            },
        };
        let desired = Desired::Resolved(desired_state);

        assert_eq!(
            network_change_action(&backend, &desired, false)
                .await
                .unwrap(),
            NetworkChangeAction::Ignore
        );
    }
}
