//! Background process launcher for daemon mode.
//!
//! This module starts a detached child process with the same executable and
//! command-line options, excluding daemon flags so the child runs in the normal
//! foreground server path.

use std::env;
use std::ffi::OsString;
use std::process::{Command, Stdio};

use anyhow::{Context, Result};

#[cfg(unix)]
use std::io;

/// Start a detached copy of the current executable and return its process ID.
///
/// # Parameters
///
/// This function takes no parameters.
///
/// # Returns
///
/// Returns the process ID of the spawned child.
///
/// # Errors
///
/// Returns an error when the current executable path cannot be determined or
/// the detached child process cannot be spawned.
pub fn spawn() -> Result<u32> {
    let executable = env::current_exe().context("could not determine current executable path")?;
    let mut command = Command::new(executable);
    command
        .args(background_args(env::args_os().skip(1)))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    configure_detached_process(&mut command);
    let child = command
        .spawn()
        .context("could not start detached proxlet process")?;
    Ok(child.id())
}

/// Remove daemon flags from arguments passed to the detached child process.
///
/// # Parameters
///
/// * `arguments` - Original command-line arguments excluding argv[0].
///
/// # Returns
///
/// Returns filtered arguments without `--daemon` or `-d`.
///
/// # Errors
///
/// This function does not return errors.
fn background_args(arguments: impl IntoIterator<Item = OsString>) -> Vec<OsString> {
    arguments
        .into_iter()
        .filter(|argument| argument != "--daemon" && argument != "-d")
        .collect()
}

#[cfg(unix)]
/// Configure Unix child process detachment.
///
/// # Parameters
///
/// * `command` - Command that will spawn the detached child.
///
/// # Returns
///
/// This function returns `()`.
///
/// # Errors
///
/// Any `setsid` failure is returned later by `Command::spawn`.
fn configure_detached_process(command: &mut Command) {
    use std::os::unix::process::CommandExt;

    // `setsid` disconnects the child from the launching terminal session.
    unsafe {
        command.pre_exec(|| {
            if libc::setsid() == -1 {
                Err(io::Error::last_os_error())
            } else {
                Ok(())
            }
        });
    }
}

#[cfg(windows)]
/// Configure Windows child process detachment.
///
/// # Parameters
///
/// * `command` - Command that will spawn the detached child.
///
/// # Returns
///
/// This function returns `()`.
///
/// # Errors
///
/// Detachment setup itself does not return errors; spawn failures are reported
/// by `Command::spawn`.
fn configure_detached_process(command: &mut Command) {
    use std::os::windows::process::CommandExt;

    const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
    const DETACHED_PROCESS: u32 = 0x0000_0008;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;

    command.creation_flags(DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW);
}

#[cfg(not(any(unix, windows)))]
/// Leave child process configuration unchanged on unsupported platforms.
///
/// # Parameters
///
/// * `_command` - Command that will spawn the child.
///
/// # Returns
///
/// This function returns `()`.
///
/// # Errors
///
/// This function does not return errors.
fn configure_detached_process(_command: &mut Command) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_daemon_flag_from_child_arguments() {
        let arguments =
            ["--daemon", "--type", "mixed", "-d", "--lport", "3000"].map(OsString::from);

        assert_eq!(
            background_args(arguments),
            ["--type", "mixed", "--lport", "3000"].map(OsString::from)
        );
    }
}
