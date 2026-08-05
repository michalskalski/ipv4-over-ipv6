//! Versioned operational status stored in a file on each supported platform.

use std::{
    net::Ipv6Addr,
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::Context;
use serde::{Deserialize, Deserializer, Serialize};

use crate::atomic_file::atomic_replace;

/// Current JSON status schema version.
pub const SCHEMA_VERSION: u32 = 1;
/// Filename used for the status snapshot inside the runtime directory.
pub const STATUS_FILENAME: &str = "status.json";

/// Versioned snapshot of the daemon's last reconciliation result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StatusSnapshot {
    #[serde(deserialize_with = "deserialize_schema_version")]
    /// Status schema version.
    pub schema_version: u32,
    /// Time at which the snapshot was generated.
    pub generated_at: jiff::Timestamp,
    /// Daemon process identifier.
    pub pid: u32,
    /// Daemon package version.
    pub version: String,
    /// Managed tunnel interface name.
    pub tunnel_name: String,
    /// Availability of desired tunnel state.
    pub desired: StatusDesired,
    /// Source that supplied the current AFTR.
    pub aftr_source: AftrSource,
    #[serde(deserialize_with = "deserialize_required_option")]
    /// Configured or discovered AFTR name or literal.
    pub aftr: Option<String>,
    #[serde(deserialize_with = "deserialize_required_option")]
    /// Selected local IPv6 tunnel endpoint.
    pub local_ipv6: Option<Ipv6Addr>,
    #[serde(deserialize_with = "deserialize_required_option")]
    /// Resolved remote IPv6 tunnel endpoint.
    pub remote_ipv6: Option<Ipv6Addr>,
    /// Action taken by the last reconciliation pass.
    pub last_action: StatusAction,
    /// Scheduled time of the next reconciliation pass.
    pub next_reconcile_at: jiff::Timestamp,
    /// Constraint that selected the next reconciliation time.
    pub next_reconcile_reason: ReconcileReason,
}

/// Whether complete desired tunnel state was available.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StatusDesired {
    /// Complete tunnel state was resolved.
    Resolved,
    /// Configuration requests no tunnel.
    Absent,
    /// Desired state could not be resolved temporarily.
    Unavailable,
}

/// Source of the AFTR used to compute desired state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AftrSource {
    /// Static configuration.
    Config,
    /// Runtime override provided by the operator.
    Provided,
    /// HB46PP automatic discovery.
    Hb46pp,
    /// No AFTR source is active.
    None,
}

/// Reconciliation action reported in a status snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StatusAction {
    /// A tunnel was created.
    Create,
    /// Mutable tunnel properties were updated.
    Update,
    /// A tunnel was replaced.
    Rebuild,
    /// A tunnel was removed.
    Teardown,
    /// Existing state was retained because desired state was unavailable.
    Keep,
    /// No change was required.
    Noop,
}

/// Reason that determines the next reconciliation deadline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReconcileReason {
    /// Periodic health interval.
    Health,
    /// Discovery refresh directed by the protocol.
    Discovery,
    /// Retry backoff after a transient failure.
    Retry,
}

impl StatusSnapshot {
    /// Reads and validates a snapshot from `state_dir`.
    pub fn read(state_dir: &Path) -> anyhow::Result<Self> {
        let path = state_dir.join(STATUS_FILENAME);
        let bytes = std::fs::read(&path)
            .with_context(|| format!("reading status snapshot {}", path.display()))?;
        serde_json::from_slice(&bytes)
            .with_context(|| format!("parsing status snapshot {}", path.display()))
    }

    /// Atomically writes the snapshot with mode `0644`.
    pub fn write_atomic(&self, state_dir: &Path) -> anyhow::Result<()> {
        let path = state_dir.join(STATUS_FILENAME);
        let mut contents =
            serde_json::to_vec_pretty(self).context("serializing status snapshot")?;
        contents.push(b'\n');
        atomic_replace(&path, Some(0o644), &contents)
    }

    /// Serializes the snapshot as indented JSON.
    pub fn pretty_json(&self) -> anyhow::Result<String> {
        serde_json::to_string_pretty(self).context("serializing status snapshot")
    }

    /// Formats the snapshot for interactive status output relative to `now`.
    pub fn human(&self, now: SystemTime) -> String {
        let generated: SystemTime = self.generated_at.into();
        let next: SystemTime = self.next_reconcile_at.into();
        let age = relative_duration(now, generated, "old", "in the future");
        let next = {
            let at = next;
            if at <= now {
                format!(
                    "overdue by {}",
                    duration_text(now.duration_since(at).unwrap_or_default())
                )
            } else {
                format!(
                    "in {}",
                    duration_text(at.duration_since(now).unwrap_or_default())
                )
            }
        };
        let endpoint = |value: Option<Ipv6Addr>| {
            value.map_or_else(|| "unavailable".to_owned(), |addr| addr.to_string())
        };

        format!(
            "Snapshot: {} ({age})\nDesired: {}\nAFTR: {} ({})\nLocal IPv6: {}\nRemote IPv6: {}\nLast action: {}\nNext reconciliation: {} ({next})",
            self.generated_at,
            display_json_name(&self.desired),
            self.aftr.as_deref().unwrap_or("unavailable"),
            display_json_name(&self.aftr_source),
            endpoint(self.local_ipv6),
            endpoint(self.remote_ipv6),
            display_json_name(&self.last_action),
            display_json_name(&self.next_reconcile_reason),
        )
    }

    /// Formats the concise status sent to the service manager.
    pub fn supervisor_summary(&self) -> String {
        format!(
            "desired={}, action={}, next={} at {}",
            display_json_name(&self.desired),
            display_json_name(&self.last_action),
            display_json_name(&self.next_reconcile_reason),
            self.next_reconcile_at
        )
    }
}

/// Returns the current time as a status timestamp.
pub fn timestamp_now() -> jiff::Timestamp {
    jiff::Timestamp::now()
}

/// Returns a status timestamp `duration` after the current time.
pub fn timestamp_after(duration: Duration) -> anyhow::Result<jiff::Timestamp> {
    let value = SystemTime::now()
        .checked_add(duration)
        .context("next reconciliation time exceeds system clock range")?;
    let since_epoch = value
        .duration_since(UNIX_EPOCH)
        .context("system clock is before Unix epoch")?;
    let timestamp = jiff::Timestamp::new(
        i64::try_from(since_epoch.as_secs()).context("timestamp exceeds supported range")?,
        since_epoch.subsec_nanos() as i32,
    )?;
    Ok(timestamp)
}

/// Removes a stale snapshot, treating an absent file as success.
pub fn remove(state_dir: &Path) -> anyhow::Result<()> {
    let path = state_dir.join(STATUS_FILENAME);
    match std::fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => {
            Err(error).with_context(|| format!("removing status file {}", path.display()))
        }
    }
}

/// Returns the platform default runtime state directory.
pub fn default_state_dir() -> PathBuf {
    #[cfg(target_os = "linux")]
    return PathBuf::from("/run/dslite-b4");
    #[cfg(target_os = "illumos")]
    return PathBuf::from("/var/run/dslite-b4");
}

fn deserialize_schema_version<'de, D>(deserializer: D) -> Result<u32, D::Error>
where
    D: Deserializer<'de>,
{
    let version = u32::deserialize(deserializer)?;
    if version != SCHEMA_VERSION {
        return Err(serde::de::Error::custom(format!(
            "unsupported schema version {version}; expected {SCHEMA_VERSION}"
        )));
    }
    Ok(version)
}

fn deserialize_required_option<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    // Using `deserialize_with` without `default` makes the field required while
    // still allowing an explicit JSON null to deserialize as `None`.
    Option::<T>::deserialize(deserializer)
}

fn display_json_name<T: Serialize>(value: &T) -> String {
    serde_json::to_string(value)
        .unwrap_or_else(|_| "unknown".to_owned())
        .trim_matches('"')
        .to_owned()
}

fn relative_duration(now: SystemTime, at: SystemTime, past: &str, future: &str) -> String {
    match now.duration_since(at) {
        Ok(duration) => format!("{} {past}", duration_text(duration)),
        Err(error) => format!("{} {future}", duration_text(error.duration())),
    }
}

fn duration_text(duration: Duration) -> String {
    let seconds = duration.as_secs();
    if seconds >= 86_400 {
        format!("{}d", seconds / 86_400)
    } else if seconds >= 3_600 {
        format!("{}h", seconds / 3_600)
    } else if seconds >= 60 {
        format!("{}m", seconds / 60)
    } else {
        format!("{seconds}s")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn snapshot() -> StatusSnapshot {
        StatusSnapshot {
            schema_version: SCHEMA_VERSION,
            generated_at: "2026-08-02T12:34:56Z".parse().unwrap(),
            pid: 1234,
            version: "0.1.0".to_owned(),
            tunnel_name: "dslite0".to_owned(),
            desired: StatusDesired::Resolved,
            aftr_source: AftrSource::Hb46pp,
            aftr: Some("dslite.example.net".to_owned()),
            local_ipv6: Some("2001:db8::1".parse().unwrap()),
            remote_ipv6: Some("2001:db8::2".parse().unwrap()),
            last_action: StatusAction::Noop,
            next_reconcile_at: "2026-08-02T12:35:26Z".parse().unwrap(),
            next_reconcile_reason: ReconcileReason::Health,
        }
    }

    #[test]
    fn rejects_unsupported_schema_version() {
        let text = serde_json::to_string(&snapshot())
            .unwrap()
            .replace("\"schema_version\":1", "\"schema_version\":2");
        assert!(serde_json::from_str::<StatusSnapshot>(&text).is_err());

        let invalid_time = serde_json::to_string(&snapshot())
            .unwrap()
            .replace("2026-08-02T12:34:56Z", "not-a-timestamp");
        assert!(serde_json::from_str::<StatusSnapshot>(&invalid_time).is_err());
    }

    #[test]
    fn nullable_fields_are_always_present() {
        let mut value = snapshot();
        value.aftr = None;
        value.local_ipv6 = None;
        value.remote_ipv6 = None;
        let json = serde_json::to_value(value).unwrap();
        assert!(json.get("aftr").unwrap().is_null());
        assert!(json.get("local_ipv6").unwrap().is_null());
        assert!(json.get("remote_ipv6").unwrap().is_null());

        let mut object = json.as_object().unwrap().clone();
        object.remove("aftr");
        assert!(serde_json::from_value::<StatusSnapshot>(object.into()).is_err());
    }

    #[test]
    fn serializes_all_stable_enum_values() {
        assert_eq!(
            [
                StatusDesired::Resolved,
                StatusDesired::Absent,
                StatusDesired::Unavailable
            ]
            .map(|value| serde_json::to_value(value).unwrap()),
            ["resolved", "absent", "unavailable"]
                .map(|value| serde_json::Value::String(value.to_owned()))
        );
        assert_eq!(
            [
                AftrSource::Config,
                AftrSource::Provided,
                AftrSource::Hb46pp,
                AftrSource::None
            ]
            .map(|value| serde_json::to_value(value).unwrap()),
            ["config", "provided", "hb46pp", "none"]
                .map(|value| serde_json::Value::String(value.to_owned()))
        );
        assert_eq!(
            [
                StatusAction::Create,
                StatusAction::Update,
                StatusAction::Rebuild,
                StatusAction::Teardown,
                StatusAction::Keep,
                StatusAction::Noop,
            ]
            .map(|value| serde_json::to_value(value).unwrap()),
            ["create", "update", "rebuild", "teardown", "keep", "noop"]
                .map(|value| serde_json::Value::String(value.to_owned()))
        );
        assert_eq!(
            [
                ReconcileReason::Health,
                ReconcileReason::Discovery,
                ReconcileReason::Retry
            ]
            .map(|value| serde_json::to_value(value).unwrap()),
            ["health", "discovery", "retry"]
                .map(|value| serde_json::Value::String(value.to_owned()))
        );
    }

    #[test]
    fn writes_and_reads_mode_0644() {
        let directory = tempfile_dir();
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
        snapshot().write_atomic(&directory).unwrap();
        assert_eq!(StatusSnapshot::read(&directory).unwrap(), snapshot());
        let mode = std::fs::metadata(directory.join(STATUS_FILENAME))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o644);
        let directory_mode = std::fs::metadata(&directory).unwrap().permissions().mode();
        assert_eq!(directory_mode & 0o777, 0o700);
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn repeated_readers_only_see_complete_replacements() {
        let directory = tempfile_dir();
        snapshot().write_atomic(&directory).unwrap();
        let reader_directory = directory.clone();
        let reader = std::thread::spawn(move || {
            for _ in 0..500 {
                let value = StatusSnapshot::read(&reader_directory).unwrap();
                assert!(value.pid == 1234 || value.pid == 5678);
            }
        });
        for index in 0..40 {
            let mut value = snapshot();
            value.pid = if index % 2 == 0 { 1234 } else { 5678 };
            value.write_atomic(&directory).unwrap();
        }
        reader.join().unwrap();
        std::fs::remove_dir_all(directory).unwrap();
    }

    fn tempfile_dir() -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "dslite-b4-status-test-{}-{}",
            std::process::id(),
            timestamp_now()
        ));
        std::fs::create_dir(&path).unwrap();
        path
    }
}
