#[path = "../src/cli.rs"]
mod cli;

use clap::CommandFactory;
use cli::Cli;
use std::{io, path::PathBuf};

const MAIN_DESCRIPTION: &str = "dslite-b4 is a foreground daemon that provides the B4 function described by RFC 6333. It creates an IPv4 in IPv6 tunnel to an AFTR and continues to reconcile the tunnel interface, reserved B4 address, and IPv4 default route with configuration and operating system state. Packet forwarding and encapsulation remain in the operating system network stack.";

const MAIN_SECTIONS: &str = r#".SH OPERATION
Running
.B dslite\-b4
without a subcommand is equivalent to
.BR "dslite\-b4 run" .
The daemon runs in the foreground and requires effective user ID 0.
It creates and manages the configured tunnel interface, assigns the reserved B4 IPv4 endpoint, and installs an IPv4 default route through the tunnel.
On shutdown it removes the managed tunnel and its status snapshot.
.SH AFTR SELECTION
A static AFTR in the configuration takes precedence over an AFTR supplied at run time.
The run time value takes precedence over automatic discovery.
The selected DNS name is resolved to IPv6 addresses before reconciliation.
.SH PRIVILEGES
The
.B run
command requires effective user ID 0.
On Linux, the supplied systemd service runs as root and limits its capability bounding set to
.BR CAP_NET_ADMIN .
On illumos, the supplied SMF service runs as root with the
.BR basic ,
.BR net_rawaccess ,
.BR sys_ip_config ,
.BR sys_dl_config ,
and
.B sys_iptun_config
privileges.
.PP
The
.B check\-config
command needs no special privileges.
The
.B status
command needs read access to the status snapshot.
The
.B set\-aftr
and
.B clear\-aftr
commands need permission to modify the state directory and signal the daemon.
With the supplied service configuration, this normally requires root.
.SH SIGNALS
.TP
.B SIGINT, SIGTERM
Stop the daemon, remove the managed tunnel, and remove the status snapshot.
.TP
.B SIGUSR1
Read the run time AFTR state again and start a reconciliation pass.
The
.B set\-aftr
and
.B clear\-aftr
commands send this signal to a running daemon.
The configuration file is not read again.
.SH FILES
.TP
.B /etc/dslite\-b4.toml
Default configuration file.
.TP
.B /run/dslite\-b4
Default Linux state directory.
.TP
.B /var/run/dslite\-b4
Default illumos state directory.
.PP
The state directory contains the locked PID file, the optional run time AFTR value, and the JSON status snapshot.
Its location can be changed with
.BR runtime.state_dir .
.SH SEE ALSO
.BR dslite\-b4.toml (5),
.BR dslite\-b4\-run (8),
.BR dslite\-b4\-check\-config (8),
.BR dslite\-b4\-set\-aftr (8),
.BR dslite\-b4\-clear\-aftr (8),
.BR dslite\-b4\-status (8)
"#;

fn generate(command: clap::Command, output: &std::path::Path) -> io::Result<()> {
    for subcommand in command.get_subcommands().filter(|item| !item.is_hide_set()) {
        generate(subcommand.clone(), output)?;
    }

    let is_main = command.get_name() == "dslite-b4";
    let command = if is_main {
        command.long_about(MAIN_DESCRIPTION)
    } else {
        command
    };
    let man = clap_mangen::Man::new(command).section("8");

    let path = if is_main {
        let mut rendered = Vec::new();
        man.render(&mut rendered)?;
        let rendered = String::from_utf8(rendered).map_err(io::Error::other)?;
        let marker = ".SH VERSION\n";
        let (before_version, version) = rendered
            .split_once(marker)
            .ok_or_else(|| io::Error::other("generated main page has no version section"))?;
        let page = format!("{before_version}{MAIN_SECTIONS}{marker}{version}");
        let path = output.join(man.get_filename());
        std::fs::write(&path, page)?;
        path
    } else {
        man.generate_to(output)?
    };
    normalize(&path)?;
    Ok(())
}

fn normalize(path: &std::path::Path) -> io::Result<()> {
    let page = std::fs::read_to_string(path)?;
    let mut normalized = page
        .lines()
        .map(str::trim_end)
        .collect::<Vec<_>>()
        .join("\n");
    normalized.push('\n');
    std::fs::write(path, normalized)
}

fn main() -> io::Result<()> {
    let output = std::env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("packaging/man/generated"));
    std::fs::create_dir_all(&output)?;
    let mut command = Cli::command().disable_help_subcommand(true);
    command.build();
    generate(command, &output)
}
