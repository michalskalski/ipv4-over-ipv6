use std::{path::PathBuf, process::Command};

#[cfg(target_os = "linux")]
use dslite_b4::status::{AftrSource, ReconcileReason, StatusAction, StatusDesired, StatusSnapshot};

fn temp_dir(name: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "dslite-b4-{name}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&path).unwrap();
    path
}

fn snapshot() -> &'static str {
    r#"{
  "schema_version": 1,
  "generated_at": "2026-08-02T12:34:56Z",
  "pid": 1234,
  "version": "0.1.0",
  "tunnel_name": "dslite0",
  "desired": "resolved",
  "aftr_source": "hb46pp",
  "aftr": "dslite.example.net",
  "local_ipv6": "2001:db8::1",
  "remote_ipv6": "2001:db8::2",
  "last_action": "noop",
  "next_reconcile_at": "2026-08-02T12:35:26Z",
  "next_reconcile_reason": "health"
}"#
}

fn status_command(state_dir: &PathBuf) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_dslite-b4"));
    command.arg("status").arg("--state-dir").arg(state_dir);
    command
}

#[test]
fn json_status_is_validated_json_only() {
    let directory = temp_dir("json-status");
    std::fs::write(directory.join("status.json"), snapshot()).unwrap();
    let output = status_command(&directory).arg("--json").output().unwrap();

    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["schema_version"], 1);
    assert_eq!(value["aftr_source"], "hb46pp");
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn human_status_reports_overdue_snapshot() {
    let directory = temp_dir("human-status");
    let old_snapshot = snapshot()
        .replace("2026-08-02T12:34:56Z", "2000-01-01T00:00:00Z")
        .replace("2026-08-02T12:35:26Z", "2000-01-01T00:00:30Z");
    std::fs::write(directory.join("status.json"), old_snapshot).unwrap();
    let output = status_command(&directory).output().unwrap();

    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("Desired: resolved"));
    assert!(stdout.contains("AFTR: dslite.example.net (hb46pp)"));
    assert!(stdout.contains("overdue by"));
    assert!(!stdout.contains("running"));
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn closed_stdout_pipe_exits_without_an_error() {
    use std::{os::fd::OwnedFd, os::unix::net::UnixStream, process::Stdio};

    let directory = temp_dir("closed-stdout");
    std::fs::write(directory.join("status.json"), snapshot()).unwrap();
    let (reader, writer) = UnixStream::pair().unwrap();
    drop(reader);

    let output = status_command(&directory)
        .arg("--json")
        .stdout(Stdio::from(OwnedFd::from(writer)))
        .output()
        .unwrap();

    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn missing_and_malformed_status_fail_without_stdout() {
    for (name, contents) in [("missing", None), ("malformed", Some(b"{".as_slice()))] {
        let directory = temp_dir(name);
        if let Some(contents) = contents {
            std::fs::write(directory.join("status.json"), contents).unwrap();
        }
        let output = status_command(&directory).output().unwrap();
        assert!(!output.status.success(), "{name}");
        assert!(output.stdout.is_empty(), "{name}");
        assert!(!output.stderr.is_empty(), "{name}");
        std::fs::remove_dir_all(directory).unwrap();
    }
}

#[test]
fn check_config_prints_success_without_debug_dump() {
    let config = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("example-config.toml");
    let output = Command::new(env!("CARGO_BIN_EXE_dslite-b4"))
        .arg("--config")
        .arg(config)
        .arg("check-config")
        .output()
        .unwrap();

    assert!(output.status.success());
    assert_eq!(output.stdout, b"configuration is valid\n");
    assert!(output.stderr.is_empty());
}

#[test]
fn check_config_diagnostics_are_safe_unless_source_is_requested() {
    let directory = temp_dir("invalid-config");
    let marker = "THIS_MUST_NOT_APPEAR";
    let cases = [
        (
            "unknown.toml",
            format!(
                r#"[tunnel]
local_v4 = "192.0.0.2"
[aftr]
address = "2001:db8::2"
[health]
interval_secs = 30
password = "{marker}"
"#,
            ),
        ),
        (
            "wrong-type.toml",
            format!(
                r#"[tunnel]
local_v4 = "192.0.0.2"
[aftr]
address = "2001:db8::2"
[health]
interval_secs = "{marker}"
"#,
            ),
        ),
        (
            "syntax.toml",
            format!("[tunnel]\nlocal_v4 = \"192.0.0.2\"\n[aftr]\naddress = \"\u{1b}[31m{marker}\n"),
        ),
    ];

    for (filename, contents) in cases {
        let path = directory.join(filename);
        std::fs::write(&path, contents).unwrap();
        let output = Command::new(env!("CARGO_BIN_EXE_dslite-b4"))
            .arg("--config")
            .arg(&path)
            .arg("check-config")
            .output()
            .unwrap();
        let stderr = String::from_utf8(output.stderr).unwrap();

        assert!(!output.status.success(), "{filename}");
        assert!(output.stdout.is_empty(), "{filename}");
        assert!(
            stderr.contains("invalid configuration at line "),
            "{filename}: {stderr}"
        );
        assert!(stderr.contains("line "), "{filename}: {stderr}");
        assert!(!stderr.contains(marker), "{filename}: {stderr}");
        assert!(!stderr.contains('\u{1b}'), "{filename}: {stderr}");
    }

    let path = directory.join("show-source.toml");
    std::fs::write(
        &path,
        format!(
            "[tunnel]\nlocal_v4 = \"192.0.0.2\"\n[aftr]\naddress = \"2001:db8::2\"\n[health]\ninterval_secs = \"{marker}\"\n"
        ),
    )
    .unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_dslite-b4"))
        .arg("--config")
        .arg(&path)
        .arg("check-config")
        .arg("--show-source")
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8(output.stderr).unwrap().contains(marker));

    std::fs::remove_dir_all(directory).unwrap();
}

#[cfg(target_os = "linux")]
fn notification_snapshot() -> StatusSnapshot {
    StatusSnapshot {
        schema_version: 1,
        generated_at: "2026-08-02T12:34:56Z".parse().unwrap(),
        pid: 1234,
        version: "0.1.0".to_owned(),
        tunnel_name: "dslite0".to_owned(),
        desired: StatusDesired::Resolved,
        aftr_source: AftrSource::Config,
        aftr: Some("2001:db8::2".to_owned()),
        local_ipv6: Some("2001:db8::1".parse().unwrap()),
        remote_ipv6: Some("2001:db8::2".parse().unwrap()),
        last_action: StatusAction::Noop,
        next_reconcile_at: "2026-08-02T12:35:26Z".parse().unwrap(),
        next_reconcile_reason: ReconcileReason::Health,
    }
}

#[cfg(target_os = "linux")]
#[test]
#[ignore]
fn notification_helper() {
    dslite_b4::supervisor::ready().unwrap();
    dslite_b4::supervisor::update(&notification_snapshot()).unwrap();
    dslite_b4::supervisor::stopping().unwrap();
}

#[cfg(target_os = "linux")]
#[test]
fn captures_systemd_readiness_status_and_shutdown() {
    use std::{os::unix::net::UnixDatagram, time::Duration};

    let directory = temp_dir("notify");
    let socket_path = directory.join("notify.sock");
    let socket = UnixDatagram::bind(&socket_path).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let output = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "notification_helper", "--ignored", "--nocapture"])
        .env("NOTIFY_SOCKET", &socket_path)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let mut messages = Vec::new();
    for _ in 0..3 {
        let mut buffer = [0_u8; 512];
        let length = socket.recv(&mut buffer).unwrap();
        messages.push(String::from_utf8(buffer[..length].to_vec()).unwrap());
    }
    assert!(messages[0].contains("READY=1"));
    assert!(messages[0].contains("STATUS=initial reconciliation in progress"));
    assert!(messages[1].contains("STATUS=desired=resolved, action=noop, next=health"));
    assert_eq!(messages[2], "STOPPING=1\n");
    std::fs::remove_dir_all(directory).unwrap();
}
