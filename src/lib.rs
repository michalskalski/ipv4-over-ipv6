pub mod config;
pub mod dhcpv6;
pub mod discovery;
pub mod dns;
pub mod lifecycle;
pub mod tunnel;

#[cfg(not(any(target_os = "linux", target_os = "illumos")))]
compile_error!("dslite-b4 only supports Linux and illumos");
