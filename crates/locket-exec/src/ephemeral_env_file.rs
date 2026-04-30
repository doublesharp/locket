//! Ephemeral env-file fallback for children that cannot accept an env map.
//!
//! Writes the Locket env layer to a 0600 file inside a per-invocation 0700
//! parent directory created under the system temp dir (i.e. outside the
//! project tree). The returned guard deletes the file and its parent dir
//! when dropped. The file is formatted as `KEY=VALUE\n` lines so it can be
//! consumed by `docker run --env-file <path>` and equivalents.

use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use locket_core::EnvMap;
use thiserror::Error;

/// Mode bits used for the parent directory holding an ephemeral env file.
#[cfg(unix)]
const PARENT_DIR_MODE: u32 = 0o700;
/// Mode bits used for the env file itself.
#[cfg(unix)]
const FILE_MODE: u32 = 0o600;

/// Error returned when writing or cleaning up an ephemeral env file.
#[derive(Debug, Error)]
pub enum EphemeralEnvFileError {
    /// An env name contained an `=` or NUL byte.
    #[error("ephemeral env-file env name {name:?} is invalid")]
    InvalidEnvName {
        /// The invalid env variable name.
        name: String,
    },
    /// An env value contained a NUL byte or newline that would break parsing.
    #[error("ephemeral env-file value for {name:?} contains an unsupported byte")]
    InvalidEnvValue {
        /// The env variable whose value was invalid.
        name: String,
    },
    /// Filesystem operation failed.
    #[error("ephemeral env-file I/O failure: {0}")]
    Io(#[from] io::Error),
}

/// Whether a best-effort secure-erase of the file contents is supported on
/// this build.
///
/// Even on supported platforms the OS may keep cached pages or journal
/// blocks, so callers should treat this only as a best-effort hint.
#[must_use]
pub const fn secure_erase_supported() -> bool {
    cfg!(unix)
}

/// RAII handle to a written ephemeral env file.
///
/// Drop deletes the file and its parent directory. Drop is best-effort —
/// errors during deletion are silently ignored because there is no caller
/// to surface them to. Callers that want to detect cleanup failures should
/// call [`EphemeralEnvFile::cleanup`] explicitly before drop.
#[derive(Debug)]
pub struct EphemeralEnvFile {
    parent: PathBuf,
    path: PathBuf,
    cleaned: bool,
}

impl EphemeralEnvFile {
    /// Returns the absolute path that should be passed to `--env-file`.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Returns the parent directory holding the env file.
    #[must_use]
    pub fn parent_dir(&self) -> &Path {
        &self.parent
    }

    /// Best-effort overwrite + delete + parent-dir-remove.
    ///
    /// On supported platforms the file body is overwritten with zeros before
    /// being unlinked. On unsupported platforms the body is left as-is and
    /// only the file is unlinked.
    ///
    /// # Errors
    ///
    /// Returns the first I/O error from overwrite, unlink, or parent-dir
    /// removal. Callers can ignore the error and rely on Drop, but should
    /// prefer explicit cleanup so failures surface.
    pub fn cleanup(&mut self) -> Result<(), EphemeralEnvFileError> {
        if self.cleaned {
            return Ok(());
        }
        self.cleaned = true;
        if secure_erase_supported() && self.path.exists() {
            zero_fill_then_remove(&self.path)?;
        } else if self.path.exists() {
            fs::remove_file(&self.path)?;
        }
        if self.parent.exists() {
            fs::remove_dir(&self.parent)?;
        }
        Ok(())
    }
}

impl Drop for EphemeralEnvFile {
    fn drop(&mut self) {
        let _ = self.cleanup();
    }
}

/// Writes the supplied env map to a fresh ephemeral env file.
///
/// `parent_root` selects the parent directory under which the per-invocation
/// 0700 dir is created. Pass [`std::env::temp_dir`] in production; tests can
/// pass a controlled path. The path must already exist.
///
/// # Errors
///
/// Returns [`EphemeralEnvFileError`] when the env contains unsupported bytes
/// or when the filesystem rejects creation/permission updates.
pub fn write_ephemeral_env_file(
    env: &EnvMap,
    parent_root: &Path,
) -> Result<EphemeralEnvFile, EphemeralEnvFileError> {
    validate_env(env)?;

    let parent = create_parent_dir(parent_root)?;
    let path = parent.join("env");
    write_env_file(&path, env)?;

    Ok(EphemeralEnvFile { parent, path, cleaned: false })
}

fn validate_env(env: &EnvMap) -> Result<(), EphemeralEnvFileError> {
    for (name, value) in env {
        if name.is_empty() || name.contains('=') || name.as_bytes().contains(&0) {
            return Err(EphemeralEnvFileError::InvalidEnvName { name: name.clone() });
        }
        let value_bytes = value.as_str().as_bytes();
        if value_bytes.contains(&0) || value_bytes.contains(&b'\n') {
            return Err(EphemeralEnvFileError::InvalidEnvValue { name: name.clone() });
        }
    }
    Ok(())
}

fn create_parent_dir(root: &Path) -> Result<PathBuf, EphemeralEnvFileError> {
    let parent = unique_parent_path(root);
    fs::create_dir(&parent)?;
    set_parent_mode(&parent)?;
    Ok(parent)
}

#[cfg(unix)]
fn set_parent_mode(parent: &Path) -> Result<(), EphemeralEnvFileError> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(parent, fs::Permissions::from_mode(PARENT_DIR_MODE))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_parent_mode(_parent: &Path) -> Result<(), EphemeralEnvFileError> {
    Ok(())
}

fn unique_parent_path(root: &Path) -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let count = COUNTER.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    root.join(format!("locket-env-{pid}-{nanos}-{count}"))
}

#[cfg(unix)]
fn write_env_file(path: &Path, env: &EnvMap) -> Result<(), EphemeralEnvFileError> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut file =
        fs::OpenOptions::new().create_new(true).write(true).mode(FILE_MODE).open(path)?;
    for (name, value) in env {
        writeln!(file, "{name}={}", value.as_str())?;
    }
    file.flush()?;
    Ok(())
}

#[cfg(not(unix))]
fn write_env_file(path: &Path, env: &EnvMap) -> Result<(), EphemeralEnvFileError> {
    let mut file = fs::OpenOptions::new().create_new(true).write(true).open(path)?;
    for (name, value) in env {
        writeln!(file, "{name}={}", value.as_str())?;
    }
    file.flush()?;
    Ok(())
}

#[cfg(unix)]
fn zero_fill_then_remove(path: &Path) -> Result<(), EphemeralEnvFileError> {
    let len = match fs::metadata(path) {
        Ok(metadata) => metadata.len(),
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    if len > 0 {
        let mut file = fs::OpenOptions::new().write(true).open(path)?;
        let zeros = vec![0_u8; usize::try_from(len).unwrap_or(usize::MAX)];
        file.write_all(&zeros)?;
        file.flush()?;
    }
    fs::remove_file(path)?;
    Ok(())
}

#[cfg(not(unix))]
fn zero_fill_then_remove(path: &Path) -> Result<(), EphemeralEnvFileError> {
    fs::remove_file(path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use locket_core::EnvValue;

    fn temp_root() -> Result<PathBuf, EphemeralEnvFileError> {
        let mut root = std::env::temp_dir();
        root.push(format!("locket-env-test-root-{}", std::process::id()));
        fs::create_dir_all(&root)?;
        Ok(root)
    }

    fn make_env(pairs: &[(&str, &str)]) -> EnvMap {
        pairs
            .iter()
            .map(|(name, value)| ((*name).to_owned(), EnvValue::from((*value).to_owned())))
            .collect()
    }

    #[test]
    fn writes_env_file_in_docker_format() -> Result<(), EphemeralEnvFileError> {
        let env = make_env(&[("DATABASE_URL", "postgres://example"), ("API_TOKEN", "abc123")]);
        let mut handle = write_ephemeral_env_file(&env, &temp_root()?)?;

        let contents = fs::read_to_string(handle.path())?;
        assert!(contents.contains("DATABASE_URL=postgres://example\n"));
        assert!(contents.contains("API_TOKEN=abc123\n"));

        handle.cleanup()?;
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn parent_dir_is_0700_and_file_is_0600() -> Result<(), EphemeralEnvFileError> {
        use std::os::unix::fs::PermissionsExt;
        let env = make_env(&[("KEY", "value")]);
        let mut handle = write_ephemeral_env_file(&env, &temp_root()?)?;

        let parent_mode = fs::metadata(handle.parent_dir())?.permissions().mode() & 0o777;
        let file_mode = fs::metadata(handle.path())?.permissions().mode() & 0o777;
        assert_eq!(parent_mode, PARENT_DIR_MODE);
        assert_eq!(file_mode, FILE_MODE);

        handle.cleanup()?;
        Ok(())
    }

    #[test]
    fn cleanup_removes_file_and_parent() -> Result<(), EphemeralEnvFileError> {
        let env = make_env(&[("KEY", "value")]);
        let mut handle = write_ephemeral_env_file(&env, &temp_root()?)?;
        let path = handle.path().to_path_buf();
        let parent = handle.parent_dir().to_path_buf();

        handle.cleanup()?;

        assert!(!path.exists(), "env file should be deleted");
        assert!(!parent.exists(), "parent dir should be deleted");
        Ok(())
    }

    #[test]
    fn drop_cleans_up_file_and_parent() -> Result<(), EphemeralEnvFileError> {
        let env = make_env(&[("KEY", "value")]);
        let (path, parent) = {
            let handle = write_ephemeral_env_file(&env, &temp_root()?)?;
            (handle.path().to_path_buf(), handle.parent_dir().to_path_buf())
        };
        assert!(!path.exists(), "env file should be deleted on drop");
        assert!(!parent.exists(), "parent dir should be deleted on drop");
        Ok(())
    }

    #[test]
    fn rejects_env_name_containing_equals() -> Result<(), EphemeralEnvFileError> {
        let env = make_env(&[("BAD=NAME", "value")]);
        assert!(matches!(
            write_ephemeral_env_file(&env, &temp_root()?),
            Err(EphemeralEnvFileError::InvalidEnvName { .. })
        ));
        Ok(())
    }

    #[test]
    fn rejects_env_value_containing_newline() -> Result<(), EphemeralEnvFileError> {
        let env = make_env(&[("KEY", "line-1\nline-2")]);
        assert!(matches!(
            write_ephemeral_env_file(&env, &temp_root()?),
            Err(EphemeralEnvFileError::InvalidEnvValue { .. })
        ));
        Ok(())
    }

    #[test]
    fn rejects_empty_env_name() -> Result<(), EphemeralEnvFileError> {
        let env = make_env(&[("", "value")]);
        assert!(matches!(
            write_ephemeral_env_file(&env, &temp_root()?),
            Err(EphemeralEnvFileError::InvalidEnvName { .. })
        ));
        Ok(())
    }

    #[test]
    fn parent_path_is_outside_an_arbitrary_project_tree() -> Result<(), EphemeralEnvFileError> {
        let env = make_env(&[("KEY", "value")]);
        let mut handle = write_ephemeral_env_file(&env, &temp_root()?)?;
        let project = std::path::Path::new("/path/to/some/project");
        assert!(!handle.path().starts_with(project));
        handle.cleanup()?;
        Ok(())
    }

    #[test]
    fn cleanup_is_idempotent() -> Result<(), EphemeralEnvFileError> {
        let env = make_env(&[("KEY", "value")]);
        let mut handle = write_ephemeral_env_file(&env, &temp_root()?)?;
        handle.cleanup()?;
        handle.cleanup()?;
        Ok(())
    }

    #[test]
    fn secure_erase_capability_matches_target() {
        assert_eq!(secure_erase_supported(), cfg!(unix));
    }
}
