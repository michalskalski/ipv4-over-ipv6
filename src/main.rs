#[cfg(target_os = "illumos")]
use dslite_b4::tunnel::illumos::IllumosBackend;
#[cfg(target_os = "linux")]
use dslite_b4::tunnel::linux::LinuxBackend;
use dslite_b4::{config::Config, dns::resolve, tunnel::TunnelBackend};
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
            let aftr_ip = resolve(&config.aftr.address).await?;
            let local_v6 = match config.tunnel.local_v6 {
                Some(addr) => addr,
                None => {
                    let mut attempt: u64 = 0;
                    loop {
                        match dslite_b4::discovery::discover_local_v6(aftr_ip).await {
                            Ok(addr) => {
                                if attempt > 0 {
                                    tracing::info!(%addr, attempt, "local_v6 discovered after {attempt} attempts");
                                } else {
                                    tracing::info!(%addr, "local_v6 discovered");
                                }
                                break addr;
                            }
                            Err(e) if e.is_transient() => {
                                attempt += 1;
                                let secs = (1u64 << attempt.min(5)).min(30);
                                if attempt == 1 {
                                    tracing::warn!("{}, retrying...", e);
                                } else {
                                    tracing::debug!("{e}, retry #{attempt} in {secs}s")
                                }

                                tokio::time::sleep(Duration::from_secs(secs)).await;
                                continue;
                            }
                            Err(e) => return Err(anyhow::anyhow!(e)),
                        }
                    }
                }
            };
            #[cfg(target_os = "linux")]
            let backend = LinuxBackend::new(
                config.tunnel.name,
                local_v6,
                aftr_ip,
                config.tunnel.local_v4,
            );
            #[cfg(target_os = "illumos")]
            let backend = IllumosBackend::new(
                config.tunnel.name,
                local_v6,
                aftr_ip,
                config.tunnel.local_v4,
            )?;

            run(backend).await?
        }
    }
    Ok(())
}

async fn run<B: TunnelBackend>(backend: B) -> anyhow::Result<()> {
    backend.setup().await?;

    let mut sigterm = signal::unix::signal(signal::unix::SignalKind::terminate())?;
    tokio::select! {
        _ = signal::ctrl_c() => {},
        _ = sigterm.recv() => {},
    };

    backend.teardown().await?;
    Ok(())
}
