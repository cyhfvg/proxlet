//! Owner-only secret files and environment fallbacks.
//!
//! File contents are never included in errors.

use url::Url;

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

/// Reject an AES secret or listener password used with the wrong proxy type.
///
/// # Parameters
///
/// * `fakehttp` - Whether the listener type is fakehttp.
/// * `has_listener_auth` - Whether a username or password source is set.
/// * `has_aes_secret` - Whether an AES secret source is set.
///
/// # Returns
///
/// Returns `Ok(())` when the secret sources match the listener type.
///
/// # Errors
///
/// Returns an error when an AES secret is set on a non-fakehttp listener, or
/// when listener authentication is set on a fakehttp listener. The error names
/// the flags and does not include secret values.
///
/// # Examples
///
/// ```ignore
/// reject_wrong_mode(false, false, true)?;
/// ```
pub(crate) fn reject_wrong_mode(
    fakehttp: bool,
    has_listener_auth: bool,
    has_aes_secret: bool,
) -> Result<()> {
    if has_aes_secret && !fakehttp {
        bail!("--aes-secret requires --type fakehttp");
    }
    if fakehttp && has_listener_auth {
        bail!("--type fakehttp does not accept --user or --auth; use --aes-secret");
    }
    Ok(())
}

/// Startup warning for a fakehttp listener that has no AES secret.
pub(crate) const PLAINTEXT_LISTENER: &str =
    "proxlet: fakehttp listener has no AES secret; tunnel payload is plaintext";

/// Startup warning for a fakehttp upstream that has no AES secret.
pub(crate) const PLAINTEXT_UPSTREAM: &str =
    "proxlet: fakehttp upstream has no AES secret; tunnel payload is plaintext";

/// Warn on stderr that a fakehttp role will carry plaintext.
///
/// # Parameters
///
/// * `listener_plain` - Whether the listener is fakehttp without a secret.
/// * `upstream_plain` - Whether the upstream URL is fakehttp without a secret.
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
/// warn_plaintext_fakehttp(true, false);
/// ```
pub(crate) fn warn_plaintext_fakehttp(listener_plain: bool, upstream_plain: bool) {
    if listener_plain {
        eprintln!("{PLAINTEXT_LISTENER}");
    }
    if upstream_plain {
        eprintln!("{PLAINTEXT_UPSTREAM}");
    }
}

/// Report whether a URL carries userinfo that would be visible in argv.
///
/// # Parameters
///
/// * `url` - Upstream URL.
///
/// # Returns
///
/// Returns true when the URL has a username or password.
///
/// # Errors
///
/// This function does not return errors.
///
/// # Examples
///
/// ```ignore
/// let leaks = url_has_userinfo(&url);
/// ```
pub(crate) fn url_has_userinfo(url: &Url) -> bool {
    !url.username().is_empty() || url.password().is_some()
}

/// Report whether an upstream URL is an unencrypted fakehttp proxy.
///
/// # Parameters
///
/// * `url` - Upstream URL.
///
/// # Returns
///
/// Returns true when the scheme is fakehttp and no secret userinfo is present.
///
/// # Errors
///
/// This function does not return errors.
///
/// # Examples
///
/// ```ignore
/// let plain = url_is_plaintext_fakehttp(&url);
/// ```
pub(crate) fn url_is_plaintext_fakehttp(url: &Url) -> bool {
    url.scheme() == "fakehttp" && !url_has_userinfo(url)
}

/// Compare two secrets without returning at the first mismatched byte.
///
/// # Parameters
///
/// * `left` - Provided secret bytes.
/// * `right` - Expected secret bytes.
///
/// # Returns
///
/// Returns `true` only when both slices have the same length and the same
/// bytes. Different lengths return `false` immediately.
///
/// # Errors
///
/// This function does not return errors.
///
/// # Examples
///
/// ```text
/// constant_time_eq(b"secret", b"secret") -> true
/// constant_time_eq(b"secreX", b"secret") -> false
/// ```
pub(crate) fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    left.ct_eq(right).into()
}

/// Match an HTTP Basic credential without leaking a password prefix.
///
/// # Parameters
///
/// * `header` - `Proxy-Authorization` header value.
/// * `username` - Expected username.
/// * `password` - Expected password.
///
/// # Returns
///
/// Returns `true` when the scheme is `Basic` in any ASCII case, one or more
/// spaces follow it, and the token matches `username:password` in standard
/// Base64.
///
/// # Errors
///
/// This function does not return errors.
///
/// # Examples
///
/// ```text
/// basic dTpw matches user u and password p
/// Basic dTpw matches the same credentials
/// ```
pub(crate) fn basic_authorization_matches(header: &str, username: &str, password: &str) -> bool {
    use base64::Engine;
    use subtle::ConstantTimeEq;

    let Some(token) = basic_token(header) else {
        return false;
    };
    let expected =
        base64::engine::general_purpose::STANDARD.encode(format!("{username}:{password}"));
    token.as_bytes().ct_eq(expected.as_bytes()).into()
}

/// Accept a Basic scheme and return its token.
///
/// # Parameters
///
/// * `header` - Raw authorization header value.
///
/// # Returns
///
/// Returns the token when the scheme is `basic` in any ASCII case and at least
/// one space separates it from a token that contains no whitespace.
///
/// # Errors
///
/// This function does not return errors.
///
/// # Examples
///
/// ```text
/// "BASIC dTpw" -> Some("dTpw")
/// "Bearer dTpw" -> None
/// ```
fn basic_token(header: &str) -> Option<&str> {
    let (scheme, rest) = header.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("basic") {
        return None;
    }
    let token = rest.trim_start_matches(' ');
    if token.is_empty() || token.bytes().any(|byte| byte.is_ascii_whitespace()) {
        return None;
    }
    Some(token)
}

#[cfg(test)]
mod mode_tests {
    use super::*;

    #[test]
    fn rejects_aes_secret_outside_fakehttp() {
        let error = reject_wrong_mode(false, false, true).expect_err("http secret");
        let text = error.to_string();
        assert!(text.contains("--aes-secret"), "{text}");
        assert!(text.contains("fakehttp"), "{text}");
    }

    #[test]
    fn rejects_listener_auth_on_fakehttp() {
        let error = reject_wrong_mode(true, true, false).expect_err("fakehttp auth");
        let text = error.to_string();
        assert!(text.contains("--user"), "{text}");
        assert!(text.contains("--aes-secret"), "{text}");
    }

    #[test]
    fn basic_scheme_is_case_insensitive_and_rejects_a_prefix() {
        assert!(basic_authorization_matches("basic dTpw", "u", "p"));
        assert!(basic_authorization_matches("BASIC dTpw", "u", "p"));
        assert!(basic_authorization_matches("Basic  dTpw", "u", "p"));
        assert!(!basic_authorization_matches("Basic dTpw", "u", "secret"));
        assert!(!basic_authorization_matches("Bearer dTpw", "u", "p"));
        assert!(constant_time_eq(b"secret", b"secret"));
        assert!(!constant_time_eq(b"secreX", b"secret"));
        assert!(!constant_time_eq(b"secret-extra", b"secret"));
    }

    #[test]
    fn plaintext_fakehttp_url_has_no_userinfo() {
        let plain = Url::parse("fakehttp://127.0.0.1:8080").expect("url");
        let secret = Url::parse("fakehttp://secret@127.0.0.1:8080").expect("url");
        assert!(url_is_plaintext_fakehttp(&plain));
        assert!(!url_is_plaintext_fakehttp(&secret));
        assert!(url_has_userinfo(&secret));
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
