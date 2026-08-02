//! Platform service-manager notifications.

use crate::status::StatusSnapshot;

#[cfg(target_os = "linux")]
pub fn ready() -> std::io::Result<()> {
    sd_notify::notify(&[
        sd_notify::NotifyState::Ready,
        sd_notify::NotifyState::Status("initial reconciliation in progress"),
    ])
}

#[cfg(target_os = "illumos")]
pub fn ready() -> std::io::Result<()> {
    Ok(())
}

#[cfg(target_os = "linux")]
pub fn update(snapshot: &StatusSnapshot) -> std::io::Result<()> {
    let summary = snapshot.supervisor_summary();
    sd_notify::notify(&[sd_notify::NotifyState::Status(&summary)])
}

#[cfg(target_os = "illumos")]
pub fn update(_snapshot: &StatusSnapshot) -> std::io::Result<()> {
    Ok(())
}

#[cfg(target_os = "linux")]
pub fn stopping() -> std::io::Result<()> {
    sd_notify::notify(&[sd_notify::NotifyState::Stopping])
}

#[cfg(target_os = "illumos")]
pub fn stopping() -> std::io::Result<()> {
    Ok(())
}
