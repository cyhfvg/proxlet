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
fn ipv4_mapped_client_matches_ipv4_allow_list() {
    let cli = Cli::try_parse_from([
        "proxlet",
        "--allow-ip",
        "192.0.2.10,192.0.2.0/24,::ffff:198.51.100.10",
    ])
    .expect("allow-list");
    let mapped: std::net::IpAddr = "::ffff:192.0.2.10".parse().expect("mapped");
    let other: std::net::IpAddr = "::ffff:192.0.3.10".parse().expect("other");
    let v4: std::net::IpAddr = "198.51.100.10".parse().expect("v4");
    let v6: std::net::IpAddr = "2001:db8::1".parse().expect("v6");

    assert!(cli.allow_ip.iter().any(|allowed| allowed.contains(&mapped)));
    assert!(!cli.allow_ip.iter().any(|allowed| allowed.contains(&other)));
    assert!(cli.allow_ip.iter().any(|allowed| allowed.contains(&v4)));
    assert!(!cli.allow_ip.iter().any(|allowed| allowed.contains(&v6)));
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
fn connect_timeout_defaults_to_ten_seconds_and_rejects_zero() {
    let cli = Cli::try_parse_from(["proxlet"]).expect("defaults");
    assert_eq!(cli.connect_timeout, 10);

    let cli = Cli::try_parse_from(["proxlet", "--connect-timeout", "3"]).expect("custom timeout");
    assert_eq!(cli.connect_timeout, 3);
    assert!(Cli::try_parse_from(["proxlet", "--connect-timeout", "0"]).is_err());
    assert!(Cli::try_parse_from(["proxlet", "--connect-timeout", "-1"]).is_err());
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
    assert!(help.contains("Allowed values: 8, 16, 32, 64"));
}

#[test]
fn half_auth_flags_are_rejected() {
    let user_only =
        Cli::try_parse_from(["proxlet", "--user", "alice"]).expect("user may use a file");
    assert!(user_only.password.is_none());
    assert!(user_only.auth_file.is_none());

    let auth_only = Cli::try_parse_from(["proxlet", "--auth", "secret"]).expect_err("auth only");
    let auth_err = auth_only.to_string();
    assert!(
        auth_err.contains("--user"),
        "missing username flag not named: {auth_err}"
    );
    let conflict = Cli::try_parse_from([
        "proxlet",
        "--user",
        "alice",
        "--auth",
        "secret",
        "--auth-file",
        "proxlet.auth",
    ])
    .expect_err("flag and file");
    let conflict_err = conflict.to_string();
    assert!(
        conflict_err.contains("--auth"),
        "conflicting password source not named: {conflict_err}"
    );
}

#[tokio::test]
async fn into_config_rejects_half_auth_without_opening_a_proxy() {
    let mut user_only =
        Cli::try_parse_from(["proxlet", "--user", "alice", "--auth", "secret"]).expect("pair");
    user_only.password = None;
    let error = user_only.into_config().await.expect_err("user only");
    assert!(error.to_string().contains("--auth"), "{error:#}");

    let mut auth_only =
        Cli::try_parse_from(["proxlet", "--user", "alice", "--auth", "secret"]).expect("pair");
    auth_only.username = None;
    let error = auth_only.into_config().await.expect_err("auth only");
    assert!(error.to_string().contains("--user"), "{error:#}");
}

#[tokio::test]
async fn into_config_rejects_secret_on_the_wrong_listener_mode() {
    let http_secret =
        Cli::try_parse_from(["proxlet", "--type", "http", "--aes-secret", "s3cret-http"])
            .expect("parse");
    let error = http_secret.into_config().await.expect_err("http secret");
    let text = error.to_string();
    assert!(text.contains("--aes-secret"), "{text}");
    assert!(text.contains("fakehttp"), "{text}");
    assert!(!text.contains("s3cret-http"), "{text}");

    let fakehttp_auth = Cli::try_parse_from([
        "proxlet",
        "--type",
        "fakehttp",
        "--user",
        "alice",
        "--auth",
        "s3cret-auth",
    ])
    .expect("parse");
    let error = fakehttp_auth
        .into_config()
        .await
        .expect_err("fakehttp auth");
    let text = error.to_string();
    assert!(text.contains("--user"), "{text}");
    assert!(text.contains("--aes-secret"), "{text}");
    assert!(!text.contains("s3cret-auth"), "{text}");

    let user_only =
        Cli::try_parse_from(["proxlet", "--type", "fakehttp", "--user", "alice"]).expect("parse");
    let error = user_only.into_config().await.expect_err("user only");
    let text = error.to_string();
    assert!(text.contains("does not accept"), "{text}");
    assert!(!text.contains("--user requires --auth"), "{text}");
}
