#[cfg(target_os = "illumos")]
use dslite_b4::tunnel::illumos::IllumosBackend;
#[cfg(target_os = "linux")]
use dslite_b4::tunnel::linux::LinuxBackend;
use dslite_b4::{
    config::Config,
    dns::resolve,
    lifecycle::{Desired, reconcile_once},
    tunnel::{DesiredState, TunnelBackend},
};
use std::{path::PathBuf, time::Duration};
use tokio::signal;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "dslite-b4", about = "DS-Lite B4 client")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Run {
        #[arg(short, long)]
        config: PathBuf,
    },
    CheckConfig {
        #[arg(short, long)]
        config: PathBuf,
    },
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
    match cli.command {
        Commands::CheckConfig { config } => {
            let config = toml::from_str::<Config>(&std::fs::read_to_string(config)?)?;
            tracing::info!(?config);
        }
        Commands::Run { config } => {
            let config = toml::from_str::<Config>(&std::fs::read_to_string(config)?)?;

            #[cfg(target_os = "linux")]
            let backend = LinuxBackend::new(config.tunnel.name.clone());
            #[cfg(target_os = "illumos")]
            let backend = IllumosBackend::new(config.tunnel.name.clone())?;

            run(backend, &config).await?
        }
    }
    Ok(())
}

async fn run<B: TunnelBackend>(backend: B, config: &Config) -> anyhow::Result<()> {
    let mut sigterm = signal::unix::signal(signal::unix::SignalKind::terminate())?;
    let mut attempt: u64 = 0;
    loop {
        let desired = compute_desired(config).await?;
        let action = reconcile_once(&backend, &desired).await?;
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
            _ = signal::ctrl_c() => break,
            _ = sigterm.recv() => break,
        }
    }

    backend.teardown().await?;
    Ok(())
}

async fn compute_desired(config: &Config) -> anyhow::Result<Desired> {
    let aftr_ip = match resolve(&config.aftr.address).await {
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
