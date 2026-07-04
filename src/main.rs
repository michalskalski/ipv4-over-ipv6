use anyhow::Context;
use clap::{Parser, Subcommand};
#[cfg(target_os = "illumos")]
use dslite_b4::tunnel::illumos::IllumosBackend;
#[cfg(target_os = "linux")]
use dslite_b4::tunnel::linux::LinuxBackend;
use dslite_b4::{
    config::{AftrAddress, Config},
    dns::resolve,
    lifecycle::{Desired, reconcile_once},
    network_changes::NetworkChanges,
    tunnel::{DesiredState, TunnelBackend},
};
use std::{
    fs::{File, OpenOptions, TryLockError},
    io::Write,
    os::unix::fs::MetadataExt,
    path::PathBuf,
    time::Duration,
};
use tokio::signal;

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

const PROVIDED_AFTR_FILENAME: &str = "aftr";
const PID_FILENAME: &str = "dslite-b4.pid";

struct PidFile {
    path: PathBuf,
    _lock: File,
    dev: u64,
    ino: u64,
}

impl PidFile {
    fn create(path: PathBuf) -> anyhow::Result<Self> {
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(&path)
            .with_context(|| format!("opening pidfile {}", path.display()))?;

        match file.try_lock() {
            Ok(_) => (),
            Err(TryLockError::WouldBlock) => {
                anyhow::bail!("another dslite-b4 daemon is already running");
            }
            Err(TryLockError::Error(err)) => {
                return Err(err).with_context(|| format!("locking pidfile {}", path.display()));
            }
        }
        let metadata = file
            .metadata()
            .with_context(|| format!("reading pidfile metadata {}", path.display()))?;
        file.set_len(0)
            .with_context(|| format!("truncating pidfile {}", path.display()))?;
        file.seek(SeekFrom::Start(0))
            .with_context(|| format!("seeking pidfile {}", path.display()))?;
        write!(file, "{}\n", std::process::id())
            .with_context(|| format!("writing pidfile {}", path.display()))?;

        Ok(Self {
            path,
            _lock: file,
            dev: metadata.dev(),
            ino: metadata.ino(),
        })
    }
}

impl Drop for PidFile {
    fn drop(&mut self) {
        let Ok(metadata) = std::fs::metadata(&self.path) else {
            return;
        };
        if metadata.dev() == self.dev && metadata.ino() == self.ino {
            let _ = std::fs::remove_file(&self.path);
        }
    }
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

            std::fs::create_dir_all(&config.runtime.state_dir).with_context(|| {
                format!(
                    "creating runtime state directory {}",
                    config.runtime.state_dir.display()
                )
            })?;

            let _pid = PidFile::create(config.runtime.state_dir.join(PID_FILENAME))?;

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
    let mut sigusr1 = signal::unix::signal(signal::unix::SignalKind::user_defined1())?;
    let mut network_changes = NetworkChanges::new()?;
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

async fn compute_desired(config: &Config) -> anyhow::Result<Desired> {
    let Some(aftr) = effective_aftr(config)? else {
        tracing::debug!("no AFTR source available");
        return Ok(Desired::Unavailable);
    };
    let aftr_ip = match resolve(&aftr).await {
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

    let path = config.runtime.state_dir.join(PROVIDED_AFTR_FILENAME);

    match std::fs::read_to_string(&path) {
        Ok(value) => {
            let value = value.trim();
            if value.is_empty() {
                return Ok(None);
            }
            Ok(Some(AftrAddress::from(value.to_owned())))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e).with_context(|| format!("reading AFTR state file {}", path.display())),
    }
}
