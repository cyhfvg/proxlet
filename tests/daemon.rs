//! Daemon startup waits until the child is listening, then returns.

use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::process::Command;
use std::thread;
use std::time::Duration;

struct Daemon {
    pid: u32,
}

impl Drop for Daemon {
    fn drop(&mut self) {
        kill_pid(self.pid);
    }
}

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_proxlet")
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .expect("bind")
        .local_addr()
        .expect("addr")
        .port()
}

fn kill_pid(pid: u32) {
    #[cfg(unix)]
    let _ = Command::new("kill")
        .args(["-KILL", &pid.to_string()])
        .status();
    #[cfg(windows)]
    let _ = Command::new("taskkill")
        .args(["/F", "/PID", &pid.to_string()])
        .status();
}

fn pid_from(stdout: &str) -> u32 {
    stdout
        .rsplit_once("PID ")
        .and_then(|(_, pid)| pid.trim().parse().ok())
        .unwrap_or_else(|| panic!("missing pid in {stdout:?}"))
}

fn start(port: u16, extra: &[&str]) -> Daemon {
    let mut args = vec![
        "--daemon".to_owned(),
        "--lhost".to_owned(),
        "127.0.0.1".to_owned(),
        "--lport".to_owned(),
        port.to_string(),
    ];
    args.extend(extra.iter().map(|arg| (*arg).to_owned()));
    let output = Command::new(bin())
        .args(&args)
        .output()
        .expect("spawn parent");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "stdout={stdout:?} stderr={stderr:?}"
    );
    let pid = pid_from(&stdout);
    assert!(stdout.contains(&format!("127.0.0.1:{port}")), "{stdout:?}");
    Daemon { pid }
}

fn run_failing(args: &[&str]) -> (String, String) {
    let output = Command::new(bin()).args(args).output().expect("spawn");
    assert!(!output.status.success(), "unexpected success");
    (
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

fn wait_connect(port: u16) {
    let addr = format!("127.0.0.1:{port}");
    for _ in 0..50 {
        if TcpStream::connect(&addr).is_ok() {
            return;
        }
        thread::sleep(Duration::from_millis(20));
    }
    panic!("not listening on {addr}");
}

fn assert_not_listening(port: u16) {
    thread::sleep(Duration::from_millis(50));
    assert!(
        TcpStream::connect(("127.0.0.1", port)).is_err(),
        "port {port} is listening"
    );
}

#[test]
fn daemon_returns_after_listen_and_writes_log_and_pid() {
    let port = free_port();
    let dir = tempfile::tempdir().expect("tempdir");
    let log_path = dir.path().join("proxlet.log");
    let pid_path = dir.path().join("proxlet.pid");
    let daemon = start(
        port,
        &[
            "--log-file",
            log_path.to_str().expect("utf8"),
            "--pid-file",
            pid_path.to_str().expect("utf8"),
        ],
    );

    wait_connect(port);
    let log = std::fs::read_to_string(&log_path).expect("log");
    assert!(log.contains("proxlet listening on"), "{log:?}");
    let pid_text = std::fs::read_to_string(&pid_path).expect("pid file");
    assert_eq!(pid_text.trim(), daemon.pid.to_string());
}

#[test]
fn second_daemon_on_the_same_port_fails_without_a_pid_file() {
    let port = free_port();
    let _first = start(port, &[]);
    wait_connect(port);

    let dir = tempfile::tempdir().expect("tempdir");
    let pid_path = dir.path().join("second.pid");
    let port_text = port.to_string();
    let (_, stderr) = run_failing(&[
        "--daemon",
        "--lport",
        &port_text,
        "--pid-file",
        pid_path.to_str().expect("utf8"),
    ]);
    assert!(stderr.contains("could not bind"), "{stderr:?}");
    assert!(!pid_path.exists(), "failed start wrote a pid file");
    wait_connect(port);
}

#[test]
fn https_without_certificates_fails_before_listen() {
    let port = free_port();
    let port_text = port.to_string();
    let (_, stderr) = run_failing(&["--daemon", "--type", "https", "--lport", &port_text]);
    assert!(stderr.contains("tls-cert"), "{stderr:?}");
    assert_not_listening(port);
}

#[test]
fn invalid_upstream_fails_before_listen() {
    let port = free_port();
    let port_text = port.to_string();
    let (_, stderr) = run_failing(&[
        "--daemon",
        "--lport",
        &port_text,
        "--proxy",
        "ftp://127.0.0.1:9",
    ]);
    assert!(stderr.contains("unsupported"), "{stderr:?}");
    assert_not_listening(port);
}

#[test]
fn log_file_requires_daemon() {
    let (_, stderr) = run_failing(&["--log-file", "proxlet.log"]);
    assert!(stderr.to_ascii_lowercase().contains("daemon"), "{stderr:?}");
    assert!(!Path::new("proxlet.log").exists());
}
