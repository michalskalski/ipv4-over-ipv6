use anyhow::Context;
use clap::{Parser, Subcommand};
#[cfg(target_os = "illumos")]
use dslite_b4::tunnel::illumos::IllumosBackend;
#[cfg(target_os = "linux")]
use dslite_b4::tunnel::linux::LinuxBackend;
use dslite_b4::{
    aftr::AftrSelector,
    aftr_discovery::{DiscoveryRuntime, DiscoveryState},
    config::{AftrAddress, Config, DiscoveryMethod},
    discovery::discover_local_v6,
    dns::resolve_aftr_addresses,
    lifecycle::{self, Desired, reconcile_once},
    network_changes::NetworkChanges,
    runtime_state::{
        self, PidFile, clear_provided_aftr, signal_daemon_refresh, write_provided_aftr,
    },
    status::{
        self, AftrSource, ReconcileReason, SCHEMA_VERSION, StatusAction, StatusDesired,
        StatusSnapshot,
    },
    supervisor,
    tunnel::{DesiredState, Observed, TunnelBackend},
};
use std::{
    io::{self, Write},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
use tokio::signal;

mod logging;
mod wake;
use wake::{ScheduledWake, WakeHint, WakeReason, schedule_next_wake};

#[derive(Parser)]
#[command(name = "dslite-b4", about = "DS-Lite B4 tunnel manager")]
struct Cli {
    #[arg(short, long, default_value = "/etc/dslite-b4.toml", global = true)]
    config: PathBuf,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    Run,
    CheckConfig {
        /// Include the original TOML diagnostic. It may expose sensitive configuration values.
        #[arg(long)]
        show_source: bool,
    },
    SetAftr {
        addr: String,
    },
    ClearAftr,
    Status {
        #[arg(long)]
        json: bool,
        #[arg(long, value_name = "PATH")]
        state_dir: Option<PathBuf>,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command.unwrap_or(Commands::Run) {
        Commands::CheckConfig { show_source } => {
            let config = if show_source {
                load_config_with_source(&cli.config)?
            } else {
                load_config(&cli.config)?
            };
            logging::init(config.logging.level);
            DiscoveryRuntime::validate_config(&config.discovery)?;
            write_command_output("configuration is valid")?;
        }
        Commands::Run => {
            // SAFETY: `geteuid` has no preconditions and does not modify memory.
            anyhow::ensure!(unsafe { libc::geteuid() } == 0, "daemon must run as UID 0");
            let config = load_config(&cli.config)?;
            logging::init(config.logging.level);
            let pid = PidFile::create(&config.runtime.state_dir)?;
            status::remove(&config.runtime.state_dir)?;
            let discovery = DiscoveryRuntime::from_config(&config.discovery)?;

            #[cfg(target_os = "linux")]
            let backend = LinuxBackend::new(config.tunnel.name.clone());
            #[cfg(target_os = "illumos")]
            let backend = IllumosBackend::new(config.tunnel.name.clone())?;

            run(backend, &config, discovery, pid).await?
        }
        Commands::SetAftr { addr } => {
            let config = load_config(&cli.config)?;
            logging::init(config.logging.level);
            write_provided_aftr(&config.runtime.state_dir, &addr)?;
            signal_daemon_refresh(&config.runtime.state_dir)?;
        }
        Commands::ClearAftr => {
            let config = load_config(&cli.config)?;
            logging::init(config.logging.level);
            clear_provided_aftr(&config.runtime.state_dir)?;
            signal_daemon_refresh(&config.runtime.state_dir)?;
        }
        Commands::Status { json, state_dir } => {
            let state_dir = state_dir.unwrap_or_else(status::default_state_dir);
            let snapshot = StatusSnapshot::read(&state_dir)?;
            if json {
                write_command_output(&snapshot.pretty_json()?)?;
            } else {
                write_command_output(&snapshot.human(std::time::SystemTime::now()))?;
            }
        }
    }
    Ok(())
}

fn write_command_output(output: &str) -> anyhow::Result<()> {
    match writeln!(io::stdout().lock(), "{output}") {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::BrokenPipe => Ok(()),
        Err(error) => Err(error).context("writing command output"),
    }
}

/// Desired tunnel state together with its scheduling constraint.
struct DesiredComputation {
    desired: Desired,
    wake_hint: WakeHint,
    aftr_source: AftrSource,
    aftr: Option<String>,
    local_ipv6: Option<std::net::Ipv6Addr>,
    remote_ipv6: Option<std::net::Ipv6Addr>,
}

impl DesiredComputation {
    fn resolved(
        state: DesiredState,
        next_attempt_at: Option<Instant>,
        aftr_source: AftrSource,
        aftr: String,
    ) -> Self {
        Self {
            desired: Desired::Resolved(state),
            wake_hint: wake_hint_for_deadline(next_attempt_at, WakeHint::None),
            aftr_source,
            aftr: Some(aftr),
            local_ipv6: Some(state.local_v6),
            remote_ipv6: Some(state.remote_v6),
        }
    }

    fn unavailable(next_attempt_at: Option<Instant>, aftr_source: AftrSource) -> Self {
        let no_deadline = if aftr_source == AftrSource::None {
            WakeHint::None
        } else {
            WakeHint::GenericRetry
        };
        Self {
            desired: Desired::Unavailable,
            wake_hint: wake_hint_for_deadline(next_attempt_at, no_deadline),
            aftr_source,
            aftr: None,
            local_ipv6: None,
            remote_ipv6: None,
        }
    }

    fn absent(next_attempt_at: Option<Instant>, aftr_source: AftrSource) -> Self {
        Self {
            desired: Desired::Absent,
            wake_hint: wake_hint_for_deadline(next_attempt_at, WakeHint::None),
            aftr_source,
            aftr: None,
            local_ipv6: None,
            remote_ipv6: None,
        }
    }

    fn with_aftr(mut self, aftr: &AftrAddress) -> Self {
        self.aftr = Some(aftr_text(aftr));
        self
    }

    fn with_remote(mut self, remote: std::net::Ipv6Addr) -> Self {
        self.remote_ipv6 = Some(remote);
        self
    }

    fn with_local(mut self, local: Option<std::net::Ipv6Addr>) -> Self {
        self.local_ipv6 = local;
        self
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

#[derive(Debug)]
enum ShutdownReason {
    Sigint,
    Sigterm,
}

struct ShutdownSignals {
    sigint: signal::unix::Signal,
    sigterm: signal::unix::Signal,
}

impl ShutdownSignals {
    async fn recv(&mut self) -> ShutdownReason {
        tokio::select! {
            _ = self.sigint.recv() => ShutdownReason::Sigint,
            _ = self.sigterm.recv() => ShutdownReason::Sigterm,
        }
    }
}

async fn run<B: TunnelBackend>(
    backend: B,
    config: &Config,
    mut discovery: DiscoveryRuntime,
    mut pidfile: PidFile,
) -> anyhow::Result<()> {
    let mut shutdown = ShutdownSignals {
        sigint: signal::unix::signal(signal::unix::SignalKind::interrupt())?,
        sigterm: signal::unix::signal(signal::unix::SignalKind::terminate())?,
    };
    let mut sigusr1 = signal::unix::signal(signal::unix::SignalKind::user_defined1())?;
    let mut network_changes = NetworkChanges::new()?;
    pidfile.mark_ready()?;
    supervisor::ready().context("notifying systemd that initialization completed")?;
    let mut aftr_selector = AftrSelector::new();
    let mut attempt: u64 = 0;
    'reconcile: loop {
        let observed = backend.observe().await?;
        let current_aftr = current_aftr(&observed);

        // Desired state computation is safe to cancel while waiting on
        // discovery, unlike the state changing reconciliation below.
        let computation = tokio::select! {
            biased;

            reason = shutdown.recv() => {
                tracing::info!(?reason, "shutdown requested");
                break 'reconcile;
            }
            result = compute_desired(
                config,
                &mut discovery,
                &mut aftr_selector,
                current_aftr,
            ) => result?,
        };

        // Let a started tunnel mutation reach a consistent stopping point.
        let action = reconcile_once(&backend, &observed, &computation.desired).await?;
        match action {
            lifecycle::Plan::Keep | lifecycle::Plan::Noop => {
                tracing::debug!(?action, "reconciliation completed");
            }
            _ => tracing::info!(?action, "reconciliation completed"),
        }

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

        let snapshot = make_snapshot(config, &computation, action, scheduled)?;
        snapshot.write_atomic(&config.runtime.state_dir)?;
        if let Err(error) = supervisor::update(&snapshot) {
            tracing::warn!(error = %error, "updating systemd status failed");
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
                biased;

                reason = shutdown.recv() => {
                    tracing::info!(?reason, "shutdown requested");
                    break 'reconcile;
                }
                _ = sigusr1.recv() => {
                    tracing::debug!("runtime state refresh requested");
                    attempt = 0;
                    break;
                },
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
            }
        }
    }

    if let Err(error) = supervisor::stopping() {
        tracing::warn!(error = %error, "notifying systemd of shutdown failed");
    }
    if matches!(backend.observe().await?, Observed::Absent) {
        tracing::debug!("tunnel already absent during shutdown");
    } else {
        backend.teardown().await?;
    }
    status::remove(&config.runtime.state_dir)?;
    Ok(())
}

fn current_aftr(observed: &Observed) -> Option<std::net::Ipv6Addr> {
    match observed {
        Observed::Present { remote_v6, .. } => Some(*remote_v6),
        Observed::Absent => None,
    }
}

fn make_snapshot(
    config: &Config,
    computation: &DesiredComputation,
    action: lifecycle::Plan,
    scheduled: ScheduledWake,
) -> anyhow::Result<StatusSnapshot> {
    let desired = status_desired(&computation.desired);
    let last_action = status_action(action);
    let next_reconcile_reason = status_reason(scheduled.reason);
    let delay = scheduled.at.saturating_duration_since(Instant::now());

    Ok(StatusSnapshot {
        schema_version: SCHEMA_VERSION,
        generated_at: status::timestamp_now(),
        pid: std::process::id(),
        version: env!("CARGO_PKG_VERSION").to_owned(),
        tunnel_name: config.tunnel.name.clone(),
        desired,
        aftr_source: computation.aftr_source,
        aftr: computation.aftr.clone(),
        local_ipv6: computation.local_ipv6,
        remote_ipv6: computation.remote_ipv6,
        last_action,
        next_reconcile_at: status::timestamp_after(delay)?,
        next_reconcile_reason,
    })
}

fn status_desired(desired: &Desired) -> StatusDesired {
    match desired {
        Desired::Resolved(_) => StatusDesired::Resolved,
        Desired::Absent => StatusDesired::Absent,
        Desired::Unavailable => StatusDesired::Unavailable,
    }
}

fn status_action(action: lifecycle::Plan) -> StatusAction {
    match action {
        lifecycle::Plan::Create(_) => StatusAction::Create,
        lifecycle::Plan::Update { .. } => StatusAction::Update,
        lifecycle::Plan::Rebuild(_) => StatusAction::Rebuild,
        lifecycle::Plan::Teardown => StatusAction::Teardown,
        lifecycle::Plan::Keep => StatusAction::Keep,
        lifecycle::Plan::Noop => StatusAction::Noop,
    }
}

fn status_reason(reason: WakeReason) -> ReconcileReason {
    match reason {
        WakeReason::Health => ReconcileReason::Health,
        WakeReason::Discovery => ReconcileReason::Discovery,
        WakeReason::GenericRetry => ReconcileReason::Retry,
    }
}

async fn compute_desired(
    config: &Config,
    discovery: &mut DiscoveryRuntime,
    aftr_selector: &mut AftrSelector,
    current_aftr: Option<std::net::Ipv6Addr>,
) -> anyhow::Result<DesiredComputation> {
    let automatic_source = match config.discovery.method {
        DiscoveryMethod::Hb46pp => AftrSource::Hb46pp,
        DiscoveryMethod::None => AftrSource::None,
    };
    let (aftr, next_attempt_at, aftr_source) = match effective_aftr(config)? {
        Some((aftr, source)) => (aftr, None, source),

        None => {
            tracing::debug!("no static or externally provided AFTR, trying automatic discovery");

            match discovery.discover_aftr().await {
                Ok(output) => {
                    let (state, next_attempt) = output.into_parts();
                    match state {
                        DiscoveryState::Available(aftr) => (aftr, next_attempt, automatic_source),
                        DiscoveryState::Unavailable => {
                            return Ok(DesiredComputation::unavailable(
                                next_attempt,
                                automatic_source,
                            )
                            .with_local(config.tunnel.local_v6));
                        }
                        DiscoveryState::NoService => {
                            tracing::debug!("automatic AFTR discovery reported no service");
                            return Ok(DesiredComputation::absent(next_attempt, automatic_source));
                        }
                    }
                }
                Err(error) => {
                    tracing::warn!(
                        error = %error, "automatic AFTR discovery unavailable"
                    );

                    return Ok(DesiredComputation::unavailable(None, automatic_source)
                        .with_local(config.tunnel.local_v6));
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
            return Ok(DesiredComputation::unavailable(None, aftr_source)
                .with_aftr(&aftr)
                .with_local(config.tunnel.local_v6));
        }
    };
    let grace = Duration::from_secs(config.health.aftr_missing_grace_secs);
    let Some(aftr_ip) = aftr_selector.select(&aftr_candidates, current_aftr, grace, Instant::now())
    else {
        tracing::debug!("no AFTR address selected from resolved candidates");
        return Ok(DesiredComputation::unavailable(None, aftr_source)
            .with_aftr(&aftr)
            .with_local(config.tunnel.local_v6));
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
                return Ok(DesiredComputation::unavailable(None, aftr_source)
                    .with_aftr(&aftr)
                    .with_remote(aftr_ip));
            }
            Err(e) => return Err(anyhow::anyhow!(e)),
        },
    };

    let aftr_text = aftr_text(&aftr);
    Ok(DesiredComputation::resolved(
        DesiredState {
            local_v6,
            remote_v6: aftr_ip,
            local_v4: config.tunnel.local_v4,
            mtu: config.tunnel.mtu,
            encapsulation_limit: config.tunnel.encapsulation_limit,
        },
        next_attempt_at,
        aftr_source,
        aftr_text,
    ))
}

fn effective_aftr(config: &Config) -> anyhow::Result<Option<(AftrAddress, AftrSource)>> {
    if let Some(address) = &config.aftr.address {
        tracing::debug!(source = "config", aftr = ?address, "AFTR source selected");
        return Ok(Some((address.clone(), AftrSource::Config)));
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

    Ok(provided.map(|address| (address, AftrSource::Provided)))
}

fn aftr_text(address: &AftrAddress) -> String {
    match address {
        AftrAddress::Ip(address) => address.to_string(),
        AftrAddress::Fqdn(name) => name.clone(),
    }
}

fn load_config(path: &Path) -> anyhow::Result<Config> {
    let safe_path = safe_path(path);
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading config {safe_path}"))?;
    dslite_b4::config::parse(&text).with_context(|| format!("parsing config {safe_path}"))
}

fn load_config_with_source(path: &Path) -> anyhow::Result<Config> {
    let safe_path = safe_path(path);
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading config {safe_path}"))?;
    dslite_b4::config::parse_with_source(&text)
        .with_context(|| format!("parsing config {safe_path}"))
}

fn safe_path(path: &Path) -> String {
    path.to_string_lossy()
        .chars()
        .flat_map(char::escape_default)
        .collect()
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

    fn resolved_computation(next_attempt_at: Option<Instant>) -> DesiredComputation {
        DesiredComputation::resolved(
            test_desired_state(),
            next_attempt_at,
            AftrSource::Config,
            "2001:db8::1".to_owned(),
        )
    }

    #[test]
    fn desired_computation_selects_wake_policy() {
        let deadline = Instant::now() + Duration::from_secs(60);
        let expired_deadline = Instant::now() - Duration::from_secs(1);

        let cases = [
            (
                "resolved static state",
                resolved_computation(None),
                WakeHint::None,
            ),
            (
                "resolved provisioned state",
                resolved_computation(Some(deadline)),
                WakeHint::Deadline(deadline),
            ),
            (
                "resolved state with expired deadline",
                resolved_computation(Some(expired_deadline)),
                WakeHint::None,
            ),
            (
                "absent without protocol deadline",
                DesiredComputation::absent(None, AftrSource::Hb46pp),
                WakeHint::None,
            ),
            (
                "absent with protocol deadline",
                DesiredComputation::absent(Some(deadline), AftrSource::Hb46pp),
                WakeHint::Deadline(deadline),
            ),
            (
                "unavailable with discovery disabled",
                DesiredComputation::unavailable(None, AftrSource::None),
                WakeHint::None,
            ),
            (
                "unavailable without protocol deadline",
                DesiredComputation::unavailable(None, AftrSource::Hb46pp),
                WakeHint::GenericRetry,
            ),
            (
                "unavailable with protocol deadline",
                DesiredComputation::unavailable(Some(deadline), AftrSource::Hb46pp),
                WakeHint::Deadline(deadline),
            ),
            (
                "unavailable with expired deadline",
                DesiredComputation::unavailable(Some(expired_deadline), AftrSource::Hb46pp),
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
