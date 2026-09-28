//! Background process launcher for daemon mode.
//!
//! The parent validates local configuration, starts a detached child, and waits
//! until that child reports a successful bind. Child arguments are rebuilt from
//! the parsed [`Cli`] with daemon mode forced off.

use std::env;
use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, BufReader, Write};
use std::net::SocketAddr;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use anyhow::{Context, Result, bail};

use crate::cli::Cli;
use crate::connector::Connector;

mod args;
use args::background_args;

const READY_PREFIX: &str = "ready ";
const ERROR_PREFIX: &str = "error ";
const CHILD_MARKER: &str = "PROXLET_DAEMON_CHILD";
const STARTUP_TIMEOUT: Duration = Duration::from_secs(30);
static CHILD_REPORTED: AtomicBool = AtomicBool::new(false);

/// Start a detached child and return only after it is listening.
///
/// # Parameters
///
/// * `cli` - Parsed command-line options, including `--daemon`.
///
/// # Returns
///
/// Returns when the child has bound its listener. The child's PID is printed
/// to stdout.
///
/// # Errors
///
/// Returns an error when configuration, file checks, process spawn, the
/// readiness pipe, or binding fails. A failed start does not leave the child
/// running.
///
/// # Examples
///
/// ```ignore
/// daemon::spawn(&cli)?;
/// ```
pub fn spawn(cli: &Cli) -> Result<()> {
    crate::secret::warn_argv_secrets(&cli.visible_secret_flags());
    validate(cli)?;
    let mut command = Command::new(current_executable()?);
    command
        .args(background_args(cli))
        .env(CHILD_MARKER, "1")
        .stdin(Stdio::null())
        .stdout(log_stdio(cli)?)
        .stderr(Stdio::piped());
    configure_detached_process(&mut command);
    let mut child = command
        .spawn()
        .context("could not start detached proxlet process")?;
    let addr = match wait_until_ready(&mut child) {
        Ok(addr) => addr,
        Err(error) => {
            stop_child(&mut child);
            return Err(error);
        }
    };
    if let Some(path) = &cli.pid_file {
        if let Err(error) = write_pid_file(path, child.id()) {
            stop_child(&mut child);
            return Err(error.context("could not write pid file; stopped the background process"));
        }
    }
    println!(
        "proxlet listening on {addr} in background with PID {}",
        child.id()
    );
    Ok(())
}

/// Tell the parent that the listener is bound.
///
/// # Parameters
///
/// * `addr` - Address returned by the bound listener.
///
/// # Returns
///
/// Returns `Ok(())` in foreground mode and after the parent has been notified.
///
/// # Errors
///
/// Returns an error when the daemon status line cannot be written. Foreground
/// runs do not use the status pipe.
///
/// # Examples
///
/// ```ignore
/// report_ready(listener.local_addr()?)?;
/// ```
pub fn report_ready(addr: SocketAddr) -> Result<()> {
    if !is_daemon_child() {
        return Ok(());
    }
    let mut stderr = io::stderr();
    writeln!(stderr, "{READY_PREFIX}{addr}")?;
    stderr.flush()?;
    // 父进程读到这一行就会关掉管道读端. 先把 stderr 挪走, 避免后续写触发 SIGPIPE.
    discard_stderr();
    CHILD_REPORTED.store(true, Ordering::Relaxed);
    Ok(())
}

/// Report a startup failure to the daemon parent.
///
/// # Parameters
///
/// * `error` - Startup error to flatten into one status line.
///
/// # Returns
///
/// This function does not return a value. Foreground runs ignore it so the
/// process error hook remains the only printer.
///
/// # Errors
///
/// Write failures are ignored. The parent then observes a closed pipe.
///
/// # Examples
///
/// ```ignore
/// if let Err(error) = &result {
///     report_failure(error);
/// }
/// ```
pub fn report_failure(error: &anyhow::Error) {
    if !is_daemon_child() {
        return;
    }
    let message = format!("{error:#}").replace(['\n', '\r'], "; ");
    println!("proxlet: {message}");
    let _ = io::stdout().flush();
    let mut stderr = io::stderr();
    let _ = writeln!(stderr, "{ERROR_PREFIX}{message}");
    let _ = stderr.flush();
}

/// Check files and the upstream URL before detaching.
///
/// # Parameters
///
/// * `cli` - Parsed command-line options.
///
/// # Returns
///
/// Returns `Ok(())` when the parent can start a child.
///
/// # Errors
///
/// Returns an error when HTTPS listener files are missing, a referenced file
/// cannot be opened, or the upstream URL is invalid.
///
/// # Examples
///
/// ```ignore
/// validate(&cli)?;
/// ```
fn validate(cli: &Cli) -> Result<()> {
    if cli.proxy_type == crate::ProxyType::Https && cli.tls_cert.is_none() {
        bail!("--type https requires --tls-cert and --tls-key");
    }
    for path in [&cli.tls_cert, &cli.tls_key, &cli.proxy_ca]
        .into_iter()
        .flatten()
    {
        ensure_readable(path)?;
    }
    if let Some(path) = &cli.pid_file {
        ensure_parent_dir(path)?;
    }
    cli.check_secret_sources()?;
    let upstream = cli.resolved_upstream()?;
    Connector::with_fakehttp_max_frame_size(
        upstream,
        cli.proxy_ca.as_deref(),
        cli.max_frame_size * 1024,
    )?;
    Ok(())
}

/// Open the daemon log, or discard output when `--log-file` is absent.
///
/// # Parameters
///
/// * `cli` - Parsed command-line options.
///
/// # Returns
///
/// Returns the child stdout handle.
///
/// # Errors
///
/// Returns an error when the log file cannot be created or opened.
///
/// # Examples
///
/// ```ignore
/// command.stdout(log_stdio(&cli)?);
/// ```
fn log_stdio(cli: &Cli) -> Result<Stdio> {
    let Some(path) = &cli.log_file else {
        return Ok(Stdio::null());
    };
    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .with_context(|| format!("could not open {}", path.display()))?;
    Ok(Stdio::from(file))
}

/// Read the one-line child status.
///
/// # Parameters
///
/// * `child` - Spawned child whose stderr is the status pipe.
///
/// # Returns
///
/// Returns the bound listen address.
///
/// # Errors
///
/// Returns an error when the child fails, exits early, or does not report
/// within [`STARTUP_TIMEOUT`]. The caller stops the child.
///
/// # Examples
///
/// ```ignore
/// let addr = wait_until_ready(&mut child)?;
/// ```
fn wait_until_ready(child: &mut Child) -> Result<SocketAddr> {
    let stderr = child
        .stderr
        .take()
        .context("daemon status pipe was not created")?;
    let (sender, receiver) = mpsc::channel();
    thread::spawn(move || {
        let mut line = String::new();
        let result = BufReader::new(stderr).read_line(&mut line);
        let _ = sender.send((result, line));
    });
    let (result, line) = receiver
        .recv_timeout(STARTUP_TIMEOUT)
        .context("background proxlet did not start within 30s")?;
    let read = result.context("could not read daemon status")?;
    if read == 0 {
        bail!("background proxlet exited before listening");
    }
    parse_status(&line)
}

/// Parse a ready or error status line.
///
/// # Parameters
///
/// * `line` - One status line, including its trailing newline.
///
/// # Returns
///
/// Returns the bound listen address when the line is a ready report.
///
/// # Errors
///
/// Returns the child error text, or an invalid-status error.
///
/// # Examples
///
/// ```ignore
/// let addr = parse_status("ready 127.0.0.1:1080\n")?;
/// ```
fn parse_status(line: &str) -> Result<SocketAddr> {
    let line = line.trim_end_matches(['\r', '\n']);
    if let Some(addr) = line.strip_prefix(READY_PREFIX) {
        return addr.parse().context("daemon status address was invalid");
    }
    if let Some(message) = line.strip_prefix(ERROR_PREFIX) {
        bail!("{message}");
    }
    bail!("background proxlet sent an invalid status: {line}")
}

/// Write the child PID for process supervisors.
///
/// # Parameters
///
/// * `path` - Destination pid file. An existing file is replaced.
/// * `pid` - Child process id.
///
/// # Returns
///
/// Returns `Ok(())` after the pid line is written.
///
/// # Errors
///
/// Returns an error when the file cannot be created or written.
///
/// # Examples
///
/// ```ignore
/// write_pid_file(Path::new("/tmp/proxlet.pid"), child.id())?;
/// ```
fn write_pid_file(path: &Path, pid: u32) -> Result<()> {
    let mut file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(path)
        .with_context(|| format!("could not open {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(0o644))?;
    }
    writeln!(file, "{pid}").with_context(|| format!("could not write {}", path.display()))?;
    Ok(())
}

/// Stop a child that failed after spawn.
///
/// # Parameters
///
/// * `child` - Child process to kill.
///
/// # Returns
///
/// This function does not return a value.
///
/// # Errors
///
/// Kill and wait failures are ignored.
///
/// # Examples
///
/// ```ignore
/// stop_child(&mut child);
/// ```
fn stop_child(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

/// Return whether this process was spawned by [`spawn`].
///
/// # Parameters
///
/// This function takes no parameters.
///
/// # Returns
///
/// Returns `true` when the parent set the child marker.
///
/// # Errors
///
/// This function does not return errors.
///
/// # Examples
///
/// ```ignore
/// if is_daemon_child() {
///     writeln!(io::stderr(), "ready {addr}")?;
/// }
/// ```
fn is_daemon_child() -> bool {
    env::var_os(CHILD_MARKER).is_some() && !CHILD_REPORTED.load(Ordering::Relaxed)
}

/// Open a referenced file so missing paths fail before detach.
///
/// # Parameters
///
/// * `path` - File that must be readable.
///
/// # Returns
///
/// Returns `Ok(())` when the file can be opened.
///
/// # Errors
///
/// Returns an error when the path is missing or not readable.
///
/// # Examples
///
/// ```ignore
/// ensure_readable(Path::new("cert.pem"))?;
/// ```
fn ensure_readable(path: &Path) -> Result<()> {
    File::open(path).with_context(|| format!("could not open {}", path.display()))?;
    Ok(())
}

/// Reject a pid file whose parent directory is missing.
///
/// # Parameters
///
/// * `path` - Requested pid file path.
///
/// # Returns
///
/// Returns `Ok(())` when the file can be created in an existing directory.
///
/// # Errors
///
/// Returns an error when the parent directory does not exist.
///
/// # Examples
///
/// ```ignore
/// ensure_parent_dir(Path::new("/tmp/proxlet.pid"))?;
/// ```
fn ensure_parent_dir(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() && !parent.is_dir() {
            bail!("could not open {}", path.display());
        }
    }
    Ok(())
}

/// Locate the current executable for the detached child.
///
/// # Parameters
///
/// This function takes no parameters.
///
/// # Returns
///
/// Returns the current executable path.
///
/// # Errors
///
/// Returns an error when the path cannot be determined.
///
/// # Examples
///
/// ```ignore
/// let executable = current_executable()?;
/// ```
fn current_executable() -> Result<std::path::PathBuf> {
    env::current_exe().context("could not determine current executable path")
}

#[cfg(unix)]
/// Point stderr at `/dev/null` so a closed status pipe cannot raise SIGPIPE.
///
/// # Parameters
///
/// This function takes no parameters.
///
/// # Returns
///
/// This function does not return a value. Failure leaves stderr unchanged.
///
/// # Errors
///
/// This function does not return errors.
///
/// # Examples
///
/// ```ignore
/// discard_stderr();
/// ```
fn discard_stderr() {
    use std::os::unix::io::AsRawFd;

    let Ok(null) = File::open("/dev/null") else {
        return;
    };
    let _ = unsafe { libc::dup2(null.as_raw_fd(), libc::STDERR_FILENO) };
}

#[cfg(not(unix))]
/// Leave stderr in place on platforms without SIGPIPE.
///
/// # Parameters
///
/// This function takes no parameters.
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
/// discard_stderr();
/// ```
fn discard_stderr() {}

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
///
/// # Examples
///
/// ```ignore
/// configure_detached_process(&mut command);
/// ```
fn configure_detached_process(command: &mut Command) {
    use std::os::unix::process::CommandExt;

    // setsid 让子进程离开启动它的终端会话, 父进程退出不会带走它.
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
///
/// # Examples
///
/// ```ignore
/// configure_detached_process(&mut command);
/// ```
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
///
/// # Examples
///
/// ```ignore
/// configure_detached_process(&mut command);
/// ```
fn configure_detached_process(_command: &mut Command) {}
