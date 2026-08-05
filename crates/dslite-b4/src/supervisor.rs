//! Notifications for platform service managers.

use crate::status::StatusSnapshot;

#[cfg(target_os = "linux")]
/// Notifies the service manager that initialization is complete.
pub fn ready() -> std::io::Result<()> {
    sd_notify::notify(&[
        sd_notify::NotifyState::Ready,
        sd_notify::NotifyState::Status("initial reconciliation in progress"),
    ])
}

#[cfg(target_os = "illumos")]
/// Completes the readiness operation without an action on illumos.
pub fn ready() -> std::io::Result<()> {
    Ok(())
}

#[cfg(target_os = "linux")]
/// Sends a concise operational status update to systemd.
pub fn update(snapshot: &StatusSnapshot) -> std::io::Result<()> {
    let summary = snapshot.supervisor_summary();
    sd_notify::notify(&[sd_notify::NotifyState::Status(&summary)])
}

#[cfg(target_os = "illumos")]
/// Completes the status operation without an action on illumos.
pub fn update(_snapshot: &StatusSnapshot) -> std::io::Result<()> {
    Ok(())
}

#[cfg(target_os = "linux")]
/// Notifies systemd that shutdown has begun.
pub fn stopping() -> std::io::Result<()> {
    sd_notify::notify(&[sd_notify::NotifyState::Stopping])
}

#[cfg(target_os = "illumos")]
/// Completes the stopping operation without an action on illumos.
pub fn stopping() -> std::io::Result<()> {
    Ok(())
}
