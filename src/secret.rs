//! Owner-only secret files and environment fallbacks.
//!
//! File contents are never included in errors.

use std::fs::File;
use std::io::Read;
use std::path::Path;

use anyhow::{Context, Result, bail};

/// Read one secret line from an owner-only file.
///
/// # Parameters
///
/// * `path` - Secret file path.
///
/// # Returns
///
/// Returns the secret with one trailing newline removed.
///
/// # Errors
///
/// Returns an error when the file cannot be opened, is group- or
/// world-readable on Unix, is empty, or contains more than one line.
///
/// # Examples
///
/// ```ignore
/// let password = read_owner_file(Path::new("proxlet.auth"))?;
/// ```
pub(crate) fn read_owner_file(path: &Path) -> Result<String> {
    let mut file =
        File::open(path).with_context(|| format!("could not open {}", path.display()))?;
    ensure_owner_only(path, &file)?;
    let mut text = String::new();
    file.read_to_string(&mut text)
        .with_context(|| format!("could not read {}", path.display()))?;
    if text.ends_with('\n') {
        text.pop();
        if text.ends_with('\r') {
            text.pop();
        }
    }
    if text.is_empty() || text.contains('\n') || text.contains('\r') {
        bail!("{} must contain one secret line", path.display());
    }
    Ok(text)
}

/// Resolve one secret from a flag, a file, or an environment variable.
///
/// # Parameters
///
/// * `flag_value` - Value from the command-line flag, if present.
/// * `file` - Secret file path, if present.
/// * `flag` - Flag name used in errors.
/// * `file_flag` - File flag name used in errors.
/// * `env_key` - Environment variable name.
///
/// # Returns
///
/// Returns the selected secret, or `None` when no source is set.
///
/// # Errors
///
/// Returns an error when more than one source is set, the file is unsafe,
/// or the environment value is empty or multi-line.
///
/// # Examples
///
/// ```ignore
/// let password = resolve(
///     cli.password.clone(),
///     cli.auth_file.as_deref(),
///     "--auth",
///     "--auth-file",
///     "PROXLET_AUTH",
/// )?;
/// ```
pub(crate) fn resolve(
    flag_value: Option<String>,
    file: Option<&Path>,
    flag: &str,
    file_flag: &str,
    env_key: &str,
) -> Result<Option<String>> {
    let from_env = env_value(env_key)?;
    match (flag_value, file, from_env) {
        (Some(value), None, None) => Ok(Some(value)),
        (None, Some(path), None) => read_owner_file(path).map(Some),
        (None, None, Some(value)) => Ok(Some(value)),
        (None, None, None) => Ok(None),
        (flag_value, file, from_env) => {
            let mut sources = Vec::new();
            if flag_value.is_some() {
                sources.push(flag);
            }
            if file.is_some() {
                sources.push(file_flag);
            }
            if from_env.is_some() {
                sources.push(env_key);
            }
            bail!("{} are mutually exclusive", sources.join(" and "))
        }
    }
}

/// Read a secret environment variable without treating it as absent when empty.
///
/// # Parameters
///
/// * `key` - Environment variable name.
///
/// # Returns
///
/// Returns the value, or `None` when the variable is unset.
///
/// # Errors
///
/// Returns an error when the value is not Unicode, empty, or multi-line.
///
/// # Examples
///
/// ```ignore
/// let password = env_value("PROXLET_AUTH")?;
/// ```
pub(crate) fn env_value(key: &str) -> Result<Option<String>> {
    match std::env::var(key) {
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(error) => bail!("{key} is not valid unicode: {error}"),
        Ok(value) if value.is_empty() || value.contains('\n') || value.contains('\r') => {
            bail!("{key} must contain one secret line")
        }
        Ok(value) => Ok(Some(value)),
    }
}

/// Reject a group- or world-readable secret file on Unix.
///
/// # Parameters
///
/// * `path` - Path used in the error.
/// * `file` - Opened file whose metadata is checked.
///
/// # Returns
///
/// Returns `Ok(())` when other users cannot read the file.
///
/// # Errors
///
/// Returns an error when metadata cannot be read or group/other permission
/// bits are set. Non-Unix platforms do not check an ACL.
///
/// # Examples
///
/// ```ignore
/// ensure_owner_only(path, &file)?;
/// ```
#[cfg(unix)]
fn ensure_owner_only(path: &Path, file: &File) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    let mode = file
        .metadata()
        .with_context(|| format!("could not stat {}", path.display()))?
        .mode();
    if mode & 0o077 != 0 {
        bail!("{} is readable by other users", path.display());
    }
    Ok(())
}

#[cfg(not(unix))]
fn ensure_owner_only(_path: &Path, _file: &File) -> Result<()> {
    Ok(())
}

/// Warn that secret flags are still visible in process arguments.
///
/// # Parameters
///
/// * `flags` - Flag names whose values appear in argv.
///
/// # Returns
///
/// This function does not return a value.
///
/// # Errors
///
/// This function does not return errors.
///
/// # Examples
///
/// ```ignore
/// warn_argv_secrets(&["--auth"]);
/// ```
pub(crate) fn warn_argv_secrets(flags: &[&str]) {
    for flag in flags {
        eprintln!("proxlet: {flag} remains visible in process arguments; prefer a mode 0600 file");
    }
}

#[cfg(all(test, unix))]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use super::*;

    #[test]
    fn rejects_group_readable_secret_file_without_echoing_it() {
        let path = std::env::temp_dir().join(format!("proxlet-secret-{}", std::process::id()));
        std::fs::write(&path, "s3cret-value\n").expect("write");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).expect("mode");
        let error = read_owner_file(&path).expect_err("group readable");
        let text = error.to_string();
        let _ = std::fs::remove_file(&path);
        assert!(text.contains("other users"), "{text}");
        assert!(!text.contains("s3cret-value"), "{text}");
    }
}
