pub mod config;
pub mod discovery;
pub mod dns;
pub mod lifecycle;
pub mod network_changes;
pub mod runtime_state;
pub mod tunnel;

#[cfg(not(any(target_os = "linux", target_os = "illumos")))]
compile_error!("dslite-b4 only supports Linux and illumos");
