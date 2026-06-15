use std::path::PathBuf;

use clap::{CommandFactory, Parser};
use proxlet::{Cli, ProxyType};

#[test]
fn parses_requested_command_line_options() {
    let cli = Cli::try_parse_from([
        "proxlet",
        "-l",
        "0.0.0.0",
        "--daemon",
        "-p",
        "3128",
        "-t",
        "mixed",
        "--allow-ip",
        "127.0.0.1,127.0.0.2",
        "127.0.0.1/8",
        "--proxy",
        "socks5h://user:pass@127.0.0.1:1080",
        "--aes-secret",
        "fake-secret",
        "--max-frame-size",
        "32",
        "--proxy-ca",
        "certs/proxlet-ca.pem",
    ])
    .expect("valid command line");

    assert_eq!(cli.lport, 3128);
    assert!(cli.daemon);
    assert_eq!(cli.proxy_type, ProxyType::Mixed);
    assert_eq!(cli.allow_ip.len(), 3);
    assert!(
        cli.allow_ip
            .iter()
            .any(|allowed| allowed.contains(&"127.0.0.2".parse().expect("IP")))
    );
    assert_eq!(cli.proxy.expect("upstream").scheme(), "socks5h");
    assert_eq!(cli.aes_secret.as_deref(), Some("fake-secret"));
    assert_eq!(cli.max_frame_size, 32);
    assert_eq!(
        cli.proxy_ca.expect("proxy CA"),
        PathBuf::from("certs/proxlet-ca.pem")
    );
}

#[test]
fn parses_each_allow_ip_input_form() {
    let single =
        Cli::try_parse_from(["proxlet", "--allow-ip", "127.0.0.1"]).expect("single address");
    let comma_separated = Cli::try_parse_from(["proxlet", "--allow-ip", "127.0.0.1,127.0.0.2"])
        .expect("comma-separated addresses");
    let cidr = Cli::try_parse_from(["proxlet", "--allow-ip", "127.0.0.1/8"]).expect("CIDR network");

    assert_eq!(single.allow_ip.len(), 1);
    assert_eq!(comma_separated.allow_ip.len(), 2);
    assert_eq!(cidr.allow_ip.len(), 1);
    assert!(cidr.allow_ip[0].contains(&"127.10.20.30".parse().expect("IP")));
}

#[test]
fn parses_fakehttp_proxy_type() {
    let cli = Cli::try_parse_from(["proxlet", "-t", "fakehttp"]).expect("fakehttp type");

    assert_eq!(cli.proxy_type, ProxyType::FakeHttp);
}

#[test]
fn validates_max_frame_size_values() {
    let cli =
        Cli::try_parse_from(["proxlet", "--max-frame-size", "64"]).expect("valid max frame size");

    assert_eq!(cli.max_frame_size, 64);
    assert!(Cli::try_parse_from(["proxlet", "--max-frame-size", "12"]).is_err());
}

#[test]
fn proxy_help_includes_uri_examples() {
    let mut help = Vec::new();
    Cli::command().write_help(&mut help).expect("help renders");
    let help = String::from_utf8(help).expect("help is UTF-8");

    assert!(help.contains("http://user:pass@host:8080"));
    assert!(help.contains("https://user:pass@host:8443"));
    assert!(help.contains("socks5://user:pass@host:1080"));
    assert!(help.contains("fakehttp://secret@host:8080"));
    assert!(help.contains("ssh://user:pass@host:22"));
    assert!(help.contains("ssh://user@host:22?key=/path/to/id_rsa"));
}
