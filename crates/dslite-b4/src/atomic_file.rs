//! Atomic replacement of small, file-backed runtime state.

use std::{
    fs::OpenOptions,
    io::Write,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::Context;

/// Replaces `path` with complete `contents` using a same-directory rename.
///
/// The destination remains unchanged until all contents have been written and
/// synchronized. If `mode` is present, it is applied exactly rather than being
/// reduced by the process umask. An unsuccessful operation cleans up its
/// temporary file when possible.
pub(crate) fn atomic_replace(
    path: &Path,
    mode: Option<u32>,
    contents: &[u8],
) -> anyhow::Result<()> {
    path.parent()
        .with_context(|| format!("atomic replacement path has no parent: {}", path.display()))?;
    let tmp_path = temporary_path(path);

    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode.unwrap_or(0o666))
            .open(&tmp_path)
            .with_context(|| format!("opening temporary state file {}", tmp_path.display()))?;
        if let Some(mode) = mode {
            file.set_permissions(std::fs::Permissions::from_mode(mode))
                .with_context(|| format!("setting state file mode {}", tmp_path.display()))?;
        }
        file.write_all(contents)
            .with_context(|| format!("writing temporary state file {}", tmp_path.display()))?;
        file.sync_all()
            .with_context(|| format!("syncing temporary state file {}", tmp_path.display()))?;
        drop(file);

        std::fs::rename(&tmp_path, path).with_context(|| {
            format!(
                "replacing state file {} with {}",
                path.display(),
                tmp_path.display()
            )
        })?;
        Ok(())
    })();

    if result.is_err() {
        let _ = std::fs::remove_file(&tmp_path);
    }
    result
}

fn temporary_path(path: &Path) -> PathBuf {
    let filename = path
        .file_name()
        .map(|name| name.to_string_lossy())
        .unwrap_or_default();
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    path.with_file_name(format!(".{filename}.{}.{nonce}.tmp", std::process::id()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn replaces_complete_contents_and_applies_exact_mode() {
        let directory = test_directory();
        let path = directory.join("state");
        std::fs::write(&path, b"old\n").unwrap();

        atomic_replace(&path, Some(0o640), b"new\n").unwrap();

        assert_eq!(std::fs::read(&path).unwrap(), b"new\n");
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o640);
        assert_eq!(temporary_files(&directory), 0);
        std::fs::remove_dir_all(directory).unwrap();
    }

    fn temporary_files(directory: &Path) -> usize {
        std::fs::read_dir(directory)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| entry.file_name().to_string_lossy().ends_with(".tmp"))
            .count()
    }

    fn test_directory() -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "dslite-b4-atomic-test-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&path).unwrap();
        path
    }
}
