//! Secrets from files and environment variables stay out of process arguments.

#![cfg(unix)]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::Duration;

struct Daemon {
    pid: u32,
    files: Vec<PathBuf>,
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = Command::new("kill")
            .args(["-KILL", &self.pid.to_string()])
            .status();
        for path in &self.files {
            let _ = std::fs::remove_file(path);
        }
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

fn write_secret(path: &std::path::Path, secret: &str, mode: u32) {
    std::fs::write(path, format!("{secret}\n")).expect("write secret");
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).expect("mode");
}

fn cmdline(pid: u32) -> String {
    let raw = std::fs::read(format!("/proc/{pid}/cmdline")).expect("cmdline");
    String::from_utf8_lossy(&raw).replace('\0', " ")
}

fn expect_407(port: u16) {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("timeout");
    stream
        .write_all(b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n")
        .expect("write");
    let mut buf = [0; 64];
    let n = stream.read(&mut buf).expect("read");
    let text = String::from_utf8_lossy(&buf[..n]);
    assert!(text.starts_with("HTTP/1.1 407"), "{text}");
}

fn start(port: u16, extra: &[&str], env: &[(&str, &str)], files: Vec<PathBuf>) -> Daemon {
    let log_file = std::env::temp_dir().join(format!("proxlet-secret-{port}.log"));
    let pid_file = std::env::temp_dir().join(format!("proxlet-secret-{port}.pid"));
    let _ = std::fs::remove_file(&log_file);
    let port_text = port.to_string();
    let mut args = vec![
        "--daemon",
        "--lhost",
        "127.0.0.1",
        "--lport",
        port_text.as_str(),
        "--log-file",
        log_file.to_str().expect("log path"),
        "--pid-file",
        pid_file.to_str().expect("pid path"),
    ];
    args.extend(extra.iter().copied());
    let mut command = Command::new(bin());
    command
        .args(&args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (key, value) in env {
        command.env(key, value);
    }
    let output = command.output().expect("spawn parent");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "stdout={stdout:?} stderr={stderr:?}"
    );
    let pid = stdout
        .rsplit_once("PID ")
        .and_then(|(_, pid)| pid.trim().parse().ok())
        .unwrap_or_else(|| panic!("missing pid in {stdout:?}"));
    let mut files = files;
    files.push(log_file);
    files.push(pid_file);
    Daemon { pid, files }
}

#[test]
fn auth_file_stays_out_of_process_arguments() {
    let port = free_port();
    let path = std::env::temp_dir().join(format!("proxlet-auth-{port}"));
    let password = "s3cret-file-value";
    write_secret(&path, password, 0o600);
    let daemon = start(
        port,
        &[
            "--user",
            "alice",
            "--auth-file",
            path.to_str().expect("path"),
        ],
        &[],
        vec![path.clone()],
    );
    let args = cmdline(daemon.pid);
    assert!(!args.contains(password), "{args}");
    expect_407(port);
}

#[test]
fn auth_flag_warns_without_printing_the_password() {
    let port = free_port();
    let password = "s3cret-flag-value";
    let log_file = std::env::temp_dir().join(format!("proxlet-warn-{port}.log"));
    let pid_file = std::env::temp_dir().join(format!("proxlet-warn-{port}.pid"));
    let port_text = port.to_string();
    let output = Command::new(bin())
        .args([
            "--daemon",
            "--lhost",
            "127.0.0.1",
            "--lport",
            port_text.as_str(),
            "--log-file",
            log_file.to_str().expect("log path"),
            "--pid-file",
            pid_file.to_str().expect("pid path"),
            "--user",
            "alice",
            "--auth",
            password,
        ])
        .output()
        .expect("spawn");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let pid = stdout
        .rsplit_once("PID ")
        .and_then(|(_, pid)| pid.trim().parse().ok())
        .unwrap_or_else(|| panic!("stdout={stdout:?} stderr={stderr:?}"));
    let _daemon = Daemon {
        pid,
        files: vec![log_file, pid_file],
    };
    assert!(
        output.status.success(),
        "stdout={stdout:?} stderr={stderr:?}"
    );
    assert!(stderr.contains("remains visible"), "{stderr}");
    assert!(!stderr.contains(password), "{stderr}");
    assert!(!stdout.contains(password), "{stdout}");
}
#[test]
fn group_readable_auth_file_fails_before_listen() {
    let port = free_port();
    let path = std::env::temp_dir().join(format!("proxlet-open-auth-{port}"));
    let password = "s3cret-open-value";
    write_secret(&path, password, 0o644);
    let port_text = port.to_string();
    let output = Command::new(bin())
        .args([
            "--lhost",
            "127.0.0.1",
            "--lport",
            port_text.as_str(),
            "--user",
            "alice",
            "--auth-file",
            path.to_str().expect("path"),
        ])
        .output()
        .expect("spawn");
    let _ = std::fs::remove_file(&path);
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!output.status.success(), "{text}");
    assert!(text.contains("other users"), "{text}");
    assert!(!text.contains(password), "{text}");
    assert!(TcpListener::bind(("127.0.0.1", port)).is_ok());
}

#[test]
fn auth_env_stays_out_of_process_arguments() {
    let port = free_port();
    let password = "s3cret-env-value";
    let daemon = start(
        port,
        &["--user", "alice"],
        &[("PROXLET_AUTH", password)],
        vec![],
    );
    let args = cmdline(daemon.pid);
    assert!(!args.contains(password), "{args}");
    assert!(!args.contains("PROXLET_AUTH"), "{args}");
    expect_407(port);
}

#[test]
fn auth_flag_and_env_fail_without_echoing_either() {
    let output = Command::new(bin())
        .env("PROXLET_AUTH", "from-env-value")
        .args(["--user", "alice", "--auth", "from-flag-value"])
        .output()
        .expect("spawn");
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!output.status.success(), "{text}");
    assert!(text.contains("PROXLET_AUTH"), "{text}");
    assert!(!text.contains("from-env-value"), "{text}");
    assert!(!text.contains("from-flag-value"), "{text}");
}
