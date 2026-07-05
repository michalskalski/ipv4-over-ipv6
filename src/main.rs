use anyhow::Context;
use clap::{Parser, Subcommand};
#[cfg(target_os = "illumos")]
use dslite_b4::tunnel::illumos::IllumosBackend;
#[cfg(target_os = "linux")]
use dslite_b4::tunnel::linux::LinuxBackend;
use dslite_b4::{
    config::{AftrAddress, Config},
    dns::resolve_aftr,
    lifecycle::{Desired, reconcile_once},
    network_changes::NetworkChanges,
    runtime_state::{
        self, PidFile, clear_provided_aftr, signal_daemon_refresh, write_provided_aftr,
    },
    tunnel::{DesiredState, Observed, TunnelBackend},
};
use std::{
    path::{Path, PathBuf},
    time::Duration,
};
use tokio::signal;

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
            tracing::info!(?config);
        }
        Commands::Run => {
            let _pid = PidFile::create(&config.runtime.state_dir)?;

            #[cfg(target_os = "linux")]
            let backend = LinuxBackend::new(config.tunnel.name.clone());
            #[cfg(target_os = "illumos")]
            let backend = IllumosBackend::new(config.tunnel.name.clone())?;

            run(backend, &config).await?
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

async fn run<B: TunnelBackend>(backend: B, config: &Config) -> anyhow::Result<()> {
    let mut sigterm = signal::unix::signal(signal::unix::SignalKind::terminate())?;
    let mut sigusr1 = signal::unix::signal(signal::unix::SignalKind::user_defined1())?;
    let mut network_changes = NetworkChanges::new()?;
    let mut attempt: u64 = 0;
    loop {
        let observed = backend.observe().await?;
        let preferred_aftr = preferred_aftr(&observed);
        let desired = compute_desired(config, preferred_aftr).await?;
        let action = reconcile_once(&backend, &observed, &desired).await?;
        tracing::info!(?action, "reconciliation completed");

        let delay = match desired {
            Desired::Resolved(_) => {
                attempt = 0;
                Duration::from_secs(config.health.interval_secs.get())
            }
            Desired::Unavailable => {
                let secs = (1u64 << attempt.min(5)).min(30);
                attempt += 1;
                tracing::debug!(wait_secs = %secs, "wait before retry");
                Duration::from_secs(secs)
            }
        };
        tokio::select! {
            _ = tokio::time::sleep(delay) => {},
            result = network_changes.changed() => { result?; attempt = 0; }
            _ = sigusr1.recv() => {
                tracing::debug!("runtime state refresh requested");
                attempt = 0;
            },
            _ = signal::ctrl_c() => break,
            _ = sigterm.recv() => break,
        }
    }

    backend.teardown().await?;
    Ok(())
}

fn preferred_aftr(observed: &Observed) -> Option<std::net::Ipv6Addr> {
    match observed {
        Observed::Present { remote_v6, .. } => Some(*remote_v6),
        Observed::Absent => None,
    }
}

async fn compute_desired(
    config: &Config,
    preferred_aftr: Option<std::net::Ipv6Addr>,
) -> anyhow::Result<Desired> {
    let Some(aftr) = effective_aftr(config)? else {
        tracing::debug!("no AFTR source available");
        return Ok(Desired::Unavailable);
    };
    let aftr_ip = match resolve_aftr(&aftr, preferred_aftr).await {
        Ok(addr) => addr,
        Err(e) => {
            tracing::warn!(error = %e, "AFTR resolution unavailable");
            return Ok(Desired::Unavailable);
        }
    };
    let local_v6 = match config.tunnel.local_v6 {
        Some(addr) => addr,
        None => match dslite_b4::discovery::discover_local_v6(aftr_ip) {
            Ok(addr) => addr,
            Err(e) if e.is_transient() => {
                tracing::warn!(error = %e, "discover local IPv6 addr failed");
                return Ok(Desired::Unavailable);
            }
            Err(e) => return Err(anyhow::anyhow!(e)),
        },
    };
    Ok(Desired::Resolved(DesiredState {
        local_v6,
        remote_v6: aftr_ip,
        local_v4: config.tunnel.local_v4,
    }))
}

fn effective_aftr(config: &Config) -> anyhow::Result<Option<AftrAddress>> {
    if let Some(address) = &config.aftr.address {
        return Ok(Some(address.clone()));
    }
    runtime_state::read_provided_aftr(&config.runtime.state_dir)
}

fn load_config(path: &Path) -> anyhow::Result<Config> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("reading config {}", path.display()))?;
    toml::from_str(&text).with_context(|| format!("parsing config {}", path.display()))
}
