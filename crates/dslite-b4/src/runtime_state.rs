use anyhow::Context;
use std::{
    fs::{File, OpenOptions, TryLockError},
    io::{Seek, SeekFrom, Write},
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
};

use crate::config::AftrAddress;

const PROVIDED_AFTR_FILENAME: &str = "aftr";
const PID_FILENAME: &str = "dslite-b4.pid";

pub struct PidFile {
    path: PathBuf,
    _lock: File,
    dev: u64,
    ino: u64,
}

impl PidFile {
    pub fn create(runtime_dir: &Path) -> anyhow::Result<Self> {
        ensure_runtime_dir(runtime_dir)?;
        let path = runtime_dir.join(PID_FILENAME);
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
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
        writeln!(file, "{}", std::process::id())
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

pub fn read_provided_aftr(runtime_dir: &Path) -> anyhow::Result<Option<AftrAddress>> {
    let path = runtime_dir.join(PROVIDED_AFTR_FILENAME);

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

pub fn write_provided_aftr(runtime_dir: &Path, addr: &str) -> anyhow::Result<()> {
    let addr = addr.trim();
    anyhow::ensure!(!addr.is_empty(), "AFTR address must not be empty");
    anyhow::ensure!(
        !addr.chars().any(char::is_whitespace),
        "AFTR address must not contain whitespace"
    );

    ensure_runtime_dir(runtime_dir)?;
    let path = runtime_dir.join(PROVIDED_AFTR_FILENAME);

    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .context("system clock is before Unix epoch")?
        .as_nanos();
    let tmp_path = runtime_dir.join(format!(
        ".{PROVIDED_AFTR_FILENAME}.{}.{}.tmp",
        std::process::id(),
        nanos
    ));

    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&tmp_path)
        .with_context(|| format!("opening temporary AFTR state file {}", tmp_path.display()))?;

    writeln!(file, "{addr}")
        .with_context(|| format!("writing temporary AFTR state file {}", tmp_path.display()))?;
    file.sync_all()
        .with_context(|| format!("syncing temporary AFTR state file {}", tmp_path.display()))?;
    drop(file);

    std::fs::rename(&tmp_path, &path).with_context(|| {
        format!(
            "renaming AFTR state file {} to {}",
            tmp_path.display(),
            path.display()
        )
    })?;

    Ok(())
}

pub fn clear_provided_aftr(runtime_dir: &Path) -> anyhow::Result<()> {
    let path = runtime_dir.join(PROVIDED_AFTR_FILENAME);

    match std::fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e).with_context(|| format!("removing AFTR state file {}", path.display())),
    }
}

pub fn signal_daemon_refresh(runtime_dir: &Path) -> anyhow::Result<()> {
    let path = runtime_dir.join(PID_FILENAME);
    let pid = match std::fs::read_to_string(&path) {
        Ok(pid) => pid,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => {
            return Err(e).with_context(|| format!("reading pidfile {}", path.display()));
        }
    };

    let pid: libc::pid_t = pid
        .trim()
        .parse()
        .with_context(|| format!("parsing pidfile {}", path.display()))?;

    // SAFETY: FFI call with no outstanding preconditions.
    let rc = unsafe { libc::kill(pid, libc::SIGUSR1) };

    if rc == -1 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("signaling daemon pid {pid}"));
    }

    Ok(())
}

fn ensure_runtime_dir(runtime_dir: &Path) -> anyhow::Result<()> {
    std::fs::create_dir_all(runtime_dir)
        .with_context(|| format!("creating runtime state directory {}", runtime_dir.display()))
}
