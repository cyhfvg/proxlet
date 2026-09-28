//! Child argument reconstruction for daemon mode.
//!
//! Arguments come from the parsed [`Cli`], not from the raw argv tokens, so
//! clustered short options cannot make the child daemonize again.

use std::ffi::{OsStr, OsString};

use crate::cli::{AllowedIp, Cli};

/// Rebuild child arguments from parsed options, never from raw argv.
///
/// # Parameters
///
/// * `cli` - Parsed command-line options.
///
/// # Returns
///
/// Returns arguments that parse back to the same listener settings with
/// `daemon` forced off. `--log-file` and `--pid-file` stay with the parent.
///
/// # Errors
///
/// This function does not return errors.
///
/// # Examples
///
/// ```ignore
/// let args = background_args(&cli);
/// ```
pub(super) fn background_args(cli: &Cli) -> Vec<OsString> {
    let mut args = Vec::new();
    push_arg(&mut args, "--lhost", &cli.lhost);
    push_arg(&mut args, "--lport", cli.lport.to_string());
    push_arg(&mut args, "--type", cli.proxy_type.to_string());
    push_arg(
        &mut args,
        "--max-frame-size",
        cli.max_frame_size.to_string(),
    );
    push_arg(
        &mut args,
        "--connect-timeout",
        cli.connect_timeout.to_string(),
    );
    for entry in &cli.allow_ip {
        push_arg(&mut args, "--allow-ip", format_allowed(entry));
    }
    if let Some(username) = &cli.username {
        push_arg(&mut args, "--user", username);
    }
    if let Some(password) = &cli.password {
        push_arg(&mut args, "--auth", password);
    }
    if let Some(proxy) = &cli.proxy {
        push_arg(&mut args, "--proxy", proxy.as_str());
    }
    if let Some(secret) = &cli.aes_secret {
        push_arg(&mut args, "--aes-secret", secret);
    }
    for (flag, path) in [
        ("--proxy-ca", &cli.proxy_ca),
        ("--tls-cert", &cli.tls_cert),
        ("--tls-key", &cli.tls_key),
    ] {
        if let Some(path) = path {
            push_arg(&mut args, flag, path);
        }
    }
    args
}

/// Append one flag and its value.
///
/// # Parameters
///
/// * `args` - Argument vector being built.
/// * `flag` - Long option name.
/// * `value` - Option value. It is one argv element, not a shell word.
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
/// push_arg(&mut args, "--lport", "1080");
/// ```
fn push_arg(args: &mut Vec<OsString>, flag: &str, value: impl AsRef<OsStr>) {
    args.push(flag.into());
    args.push(value.as_ref().to_owned());
}

/// Format an allow-list entry as a CLI value.
///
/// # Parameters
///
/// * `entry` - Parsed allow-list entry.
///
/// # Returns
///
/// Returns an IP address or CIDR string that `AllowedIp` can parse again.
///
/// # Errors
///
/// This function does not return errors.
///
/// # Examples
///
/// ```ignore
/// let text = format_allowed(&cli.allow_ip[0]);
/// ```
fn format_allowed(entry: &AllowedIp) -> String {
    match entry {
        AllowedIp::Address(ip) => ip.to_string(),
        AllowedIp::Network(network) => network.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn rebuilds_child_arguments_without_daemon_flags() {
        let cli = Cli::try_parse_from([
            "proxlet",
            "--daemon",
            "--type",
            "mixed",
            "--lhost",
            "0.0.0.0",
            "--lport",
            "3000",
            "--allow-ip",
            "127.0.0.1/8",
            "--user",
            "alice",
            "--auth",
            "secret",
            "--log-file",
            "proxlet.log",
            "--pid-file",
            "proxlet.pid",
        ])
        .expect("valid daemon command");

        let args = background_args(&cli);
        let rendered = args
            .iter()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        assert!(
            !rendered.iter().any(|arg| arg == "--daemon" || arg == "-d"),
            "{rendered:?}"
        );
        assert!(!rendered.iter().any(|arg| arg.contains("log-file")));
        assert!(!rendered.iter().any(|arg| arg.contains("pid-file")));

        let mut child_argv = vec![OsString::from("proxlet")];
        child_argv.extend(args);
        let child = Cli::try_parse_from(child_argv).expect("rebuilt arguments");
        assert!(!child.daemon);
        assert_eq!(child.lhost, "0.0.0.0");
        assert_eq!(child.lport, 3000);
        assert_eq!(child.proxy_type, crate::ProxyType::Mixed);
        assert_eq!(child.username.as_deref(), Some("alice"));
        assert_eq!(child.password.as_deref(), Some("secret"));
        assert_eq!(child.allow_ip.len(), 1);
        assert!(child.log_file.is_none());
        assert!(child.pid_file.is_none());
    }

    #[test]
    fn clustered_short_options_do_not_survive_into_the_child() {
        let cli = Cli::try_parse_from(["proxlet", "-dl", "0.0.0.0"]).expect("clustered shorts");
        assert!(cli.daemon);
        assert_eq!(cli.lhost, "0.0.0.0");

        let mut child_argv = vec![OsString::from("proxlet")];
        child_argv.extend(background_args(&cli));
        let child = Cli::try_parse_from(child_argv).expect("rebuilt arguments");
        assert!(!child.daemon);
        assert_eq!(child.lhost, "0.0.0.0");
    }
}
