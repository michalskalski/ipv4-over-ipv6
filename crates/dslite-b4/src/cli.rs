use clap::{Parser, Subcommand};
use std::path::PathBuf;

/// Commands for the DS Lite B4 daemon and its administration tools.
#[derive(Parser)]
#[command(
    name = "dslite-b4",
    version,
    about = "Manage a DS Lite B4 tunnel on Linux or illumos"
)]
pub(crate) struct Cli {
    /// Read configuration from this path.
    #[arg(short, long, default_value = "/etc/dslite-b4.toml", global = true)]
    pub(crate) config: PathBuf,

    #[command(subcommand)]
    pub(crate) command: Option<Commands>,
}

#[derive(Subcommand)]
pub(crate) enum Commands {
    /// Run the daemon and continue to reconcile tunnel state.
    Run,
    /// Validate configuration without changing network state.
    CheckConfig {
        /// Include the original TOML diagnostic. It may expose sensitive configuration values.
        #[arg(long)]
        show_source: bool,
    },
    /// Set the runtime AFTR override and ask the daemon to reconcile.
    SetAftr {
        /// AFTR IPv6 address or DNS name.
        #[arg(value_name = "ADDRESS")]
        addr: String,
    },
    /// Clear the runtime AFTR override and ask the daemon to reconcile.
    ClearAftr,
    /// Show the last status snapshot written by the daemon.
    Status {
        /// Print the complete status snapshot as JSON.
        #[arg(long)]
        json: bool,
        /// Read status from this runtime state directory.
        #[arg(long, value_name = "PATH")]
        state_dir: Option<PathBuf>,
    },
}
