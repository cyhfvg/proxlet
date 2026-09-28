//! Half authentication fails closed, and startup says whether auth is on.

use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

struct Daemon {
    pid: u32,
    log_file: PathBuf,
    pid_file: PathBuf,
}

impl Drop for Daemon {
    fn drop(&mut self) {
        #[cfg(unix)]
        let _ = Command::new("kill")
            .args(["-KILL", &self.pid.to_string()])
            .status();
        #[cfg(windows)]
        let _ = Command::new("taskkill")
            .args(["/F", "/PID", &self.pid.to_string()])
            .status();
        let _ = std::fs::remove_file(&self.log_file);
        let _ = std::fs::remove_file(&self.pid_file);
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

fn start(port: u16, extra: &[&str]) -> Daemon {
    let log_file = std::env::temp_dir().join(format!("proxlet-auth-{port}.log"));
    let pid_file = std::env::temp_dir().join(format!("proxlet-auth-{port}.pid"));
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
    let output = Command::new(bin())
        .args(&args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("spawn parent");
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
    Daemon {
        pid,
        log_file,
        pid_file,
    }
}

fn wait_log(path: &std::path::Path, needle: &str) -> String {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        if let Ok(text) = std::fs::read_to_string(path) {
            if text.contains(needle) {
                return text;
            }
        }
        if Instant::now() >= deadline {
            let text = std::fs::read_to_string(path).unwrap_or_default();
            panic!("log missing {needle:?}: {text:?}");
        }
        thread::sleep(Duration::from_millis(20));
    }
}

fn failed_output(args: &[&str]) -> String {
    let output = Command::new(bin())
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("spawn");
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!output.status.success(), "{text}");
    text
}

#[test]
fn half_auth_exits_and_does_not_listen() {
    let port = free_port();
    let user_only = failed_output(&[
        "--lhost",
        "127.0.0.1",
        "--lport",
        &port.to_string(),
        "--user",
        "alice",
    ]);
    assert!(user_only.contains("--auth"), "{user_only}");
    assert!(
        std::net::TcpStream::connect(format!("127.0.0.1:{port}")).is_err(),
        "half auth left a listener"
    );

    let auth_only = failed_output(&[
        "--daemon",
        "--lhost",
        "127.0.0.1",
        "--lport",
        &port.to_string(),
        "--auth",
        "secret",
    ]);
    assert!(auth_only.contains("--user"), "{auth_only}");
    assert!(
        std::net::TcpStream::connect(format!("127.0.0.1:{port}")).is_err(),
        "half auth left a listener"
    );
}

#[test]
fn startup_reports_whether_authentication_is_enabled() {
    let open_port = free_port();
    let open = start(open_port, &[]);
    let open_log = wait_log(&open.log_file, "authentication disabled");
    assert!(
        open_log.contains("proxlet: authentication disabled"),
        "{open_log}"
    );

    let locked_port = free_port();
    let locked = start(
        locked_port,
        &["--user", "proxy-user", "--auth", "s3cret-value"],
    );
    let locked_log = wait_log(&locked.log_file, "authentication enabled");
    assert!(
        locked_log.contains("proxlet: authentication enabled"),
        "{locked_log}"
    );
    assert!(!locked_log.contains("s3cret-value"), "{locked_log}");
}
