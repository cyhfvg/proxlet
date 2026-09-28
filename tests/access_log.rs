//! Access lines reach the daemon log file and never include the password.

use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::thread;
use std::time::{Duration, Instant};

const USER: &str = "proxy-user";
const PASSWORD: &str = "s3cret-value";

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

fn start(port: u16) -> Daemon {
    let log_file = std::env::temp_dir().join(format!("proxlet-access-{port}.log"));
    let pid_file = std::env::temp_dir().join(format!("proxlet-access-{port}.pid"));
    let _ = std::fs::remove_file(&log_file);
    let output = Command::new(bin())
        .args([
            "--daemon",
            "--lhost",
            "127.0.0.1",
            "--lport",
            &port.to_string(),
            "--type",
            "http",
            "--user",
            USER,
            "--auth",
            PASSWORD,
            "--log-file",
            log_file.to_str().expect("log path"),
            "--pid-file",
            pid_file.to_str().expect("pid path"),
        ])
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

fn basic_token(user: &str, password: &str) -> String {
    const TABLE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let raw = format!("{user}:{password}");
    let bytes = raw.as_bytes();
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = chunk.get(1).copied().unwrap_or(0) as u32;
        let b2 = chunk.get(2).copied().unwrap_or(0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(TABLE[((n >> 18) & 63) as usize] as char);
        out.push(TABLE[((n >> 12) & 63) as usize] as char);
        if chunk.len() > 1 {
            out.push(TABLE[((n >> 6) & 63) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(TABLE[(n & 63) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

fn exchange(port: u16, request: &str) -> String {
    let mut stream = TcpStream::connect(format!("127.0.0.1:{port}")).expect("connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("timeout");
    stream.write_all(request.as_bytes()).expect("write");
    let _ = stream.shutdown(Shutdown::Write);
    let mut buf = String::new();
    let _ = stream.read_to_string(&mut buf);
    buf
}

fn wait_log(path: &Path, needle: &str) -> String {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        if let Ok(text) = std::fs::read_to_string(path)
            && text.contains(needle)
        {
            return text;
        }
        if Instant::now() >= deadline {
            let text = std::fs::read_to_string(path).unwrap_or_default();
            panic!("log missing {needle:?}: {text:?}");
        }
        thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn auth_failure_is_logged_without_password() {
    let port = free_port();
    let daemon = start(port);
    let response = exchange(
        port,
        "GET http://proxy-user:s3cret-value@example.com/secret HTTP/1.1\r\nHost: example.com\r\n\r\n",
    );
    assert!(response.starts_with("HTTP/1.1 407"), "{response:?}");
    let log = wait_log(&daemon.log_file, "auth-failed");
    assert!(
        log.contains("127.0.0.1 http example.com:80 auth-failed"),
        "{log}"
    );
    assert!(!log.contains(PASSWORD), "{log}");
    assert!(!log.contains(USER), "{log}");
    assert!(!log.contains(&basic_token(USER, PASSWORD)), "{log}");
}

#[test]
fn successful_connect_logs_target_and_ok() {
    let origin = TcpListener::bind("127.0.0.1:0").expect("origin");
    let origin_addr = origin.local_addr().expect("origin addr");
    let port = free_port();
    let daemon = start(port);
    let token = basic_token(USER, PASSWORD);
    let request = format!(
        "CONNECT {origin_addr} HTTP/1.1\r\nHost: {origin_addr}\r\nProxy-Authorization: Basic {token}\r\n\r\n"
    );
    let client = thread::spawn(move || exchange(port, &request));
    let (mut accepted, _) = origin.accept().expect("accept");
    let mut ignored = [0_u8; 8];
    let _ = accepted.read(&mut ignored);
    drop(accepted);
    let response = client.join().expect("client");
    assert!(response.starts_with("HTTP/1.1 200"), "{response:?}");
    let log = wait_log(&daemon.log_file, " ok");
    assert!(
        log.contains(&format!("127.0.0.1 http {origin_addr} ok")),
        "{log}"
    );
    assert!(!log.contains(PASSWORD), "{log}");
    assert!(!log.contains(&token), "{log}");
}
