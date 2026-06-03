# proxlet

[English](README.md) | [简体中文](README.zh-CN.md)

`proxlet` is a lightweight command-line proxy server for quickly creating a
proxy endpoint and optionally routing traffic through an upstream proxy.

## Features

- Supports HTTP, HTTPS, SOCKS5, and SOCKS5h proxy clients.
- Provides mixed mode for HTTP and SOCKS5 clients on the same port.
- Supports upstream proxy chaining with HTTP, HTTPS, SOCKS5, SOCKS5h, and SSH.
- Provides username/password authentication and source IP allowlists.
- Runs in the background with a built-in daemon option.
- Ships as a single executable for easy deployment.

## Installation

### Download a release

Download a prebuilt archive from the
[Releases](https://github.com/cyhfvg/proxlet/releases/latest) page.

### Build from source

Install the stable Rust toolchain, then run:

```bash
git clone https://github.com/cyhfvg/proxlet.git
cd proxlet
cargo build --release
```

The executable will be available at `target/release/proxlet`.

## Quick Start

Start an HTTP proxy using the default address `127.0.0.1:1080`:

```bash
proxlet
```

Accept HTTP and SOCKS5 clients on the same port:

```bash
proxlet --type mixed --lhost 0.0.0.0 --lport 1080
```

## Usage

### Choose a proxy type

```bash
proxlet --type http
proxlet --type socks5
proxlet --type socks5h
proxlet --type mixed
```

Available types are `http`, `https`, `socks5`, `socks5h`, and `mixed`.
The default is `http`.

### Create certificate files for HTTPS mode

Generate certificate files for local use, then start an HTTPS proxy:

```bash
./create_cert_key.sh
proxlet --type https --tls-cert certs/proxlet-cert.pem --tls-key certs/proxlet-key.pem
```

Trust `certs/proxlet-ca.pem` on clients that connect to this HTTPS proxy. Add
the proxy's hostname or IP address when generating files for another host:

```bash
./create_cert_key.sh --san DNS:proxy.example.com --san IP:192.0.2.10
```

### Chain through an upstream proxy

```bash
proxlet --proxy 'socks5h://username:password@127.0.0.1:1080'
proxlet --proxy 'ssh://username:password@127.0.0.1:22'
proxlet --proxy 'ssh://username@127.0.0.1:22?key=/home/username/.ssh/id_ed25519'
```

For SSH upstreams, use `ssh://username:password@host:port` for password
authentication or add `?key=/path/to/private_key` for public-key
authentication. When both a password and `key` are present, the password is
used as the private key passphrase.

To chain two `proxlet` instances through an HTTPS proxy, start the upstream
instance with its certificate, then provide its CA certificate to the
downstream instance:

```bash
# On the upstream host
./create_cert_key.sh --san IP:192.0.2.10
proxlet --type https --lhost 0.0.0.0 --lport 1080 \
  --tls-cert certs/proxlet-cert.pem --tls-key certs/proxlet-key.pem \
  --user relay --auth 'strong-password'

# On the downstream host, after receiving certs/proxlet-ca.pem securely
proxlet --proxy 'https://relay:strong-password@192.0.2.10:1080' \
  --proxy-ca certs/proxlet-ca.pem
```

### Restrict access

Enable authentication by specifying both a username and password:

```bash
proxlet --type mixed --user alice --auth 'strong-password'
```

Allow specific client addresses or networks:

```bash
proxlet --allow-ip '127.0.0.1'
proxlet --allow-ip '127.0.0.1,127.0.0.2'
proxlet --allow-ip '127.0.0.1/8'
```

### Run in the background

Use `--daemon` to start `proxlet` without keeping the current terminal
occupied. The command prints the PID of the background process. Daemon mode
does not create a PID file and does not write logs to the launching terminal.

```bash
proxlet --daemon --type mixed --lport 1080
```

On Linux, query the process using the PID printed at startup:

```bash
ps -p <PID> -f
```

If the PID is no longer available, find running instances by command line:

```bash
pgrep -af proxlet
```

Stop an instance on Linux:

```bash
kill <PID>
```

If it remains running after a reasonable wait, force it to exit:

```bash
kill -KILL <PID>
```

On Windows Command Prompt, query running instances or a known PID:

```bat
tasklist /FI "IMAGENAME eq proxlet.exe"
tasklist /FI "PID eq <PID>"
```

Stop an instance on Windows Command Prompt:

```bat
taskkill /PID <PID>
```

If necessary, force it to exit:

```bat
taskkill /F /PID <PID>
```

Equivalent PowerShell commands are:

```powershell
Get-Process proxlet
Get-Process -Id <PID>
Stop-Process -Id <PID>
Stop-Process -Id <PID> -Force
```

## Options

| Option | Description |
| --- | --- |
| `-d, --daemon` | Run in the background without terminal input or output |
| `--allow-ip <allow-src-ip>...` | Allow client IP addresses or CIDR networks |
| `-l, --lhost <lhost>` | Listening host, default: `127.0.0.1` |
| `-p, --lport <lport>` | Listening port, default: `1080` |
| `-u, --user <username>` | Authentication username |
| `-a, --auth <password>` | Authentication password |
| `-t, --type <type>` | Proxy type, default: `http` |
| `--proxy <SCHEMA_URL>` | Upstream proxy URL |
| `--proxy-ca <FILE>` | CA certificate bundle for an HTTPS upstream proxy |
| `--tls-cert <FILE>` | Certificate file for HTTPS mode |
| `--tls-key <FILE>` | Private key file for HTTPS mode |

Run `proxlet --help` for the complete command-line reference.

## Security

Use `proxlet` only in environments you own or are explicitly authorized to
operate. You are responsible for complying with applicable policies and laws.

An exposed proxy can be abused by unauthorized users. Bind public interfaces
only when needed, and configure authentication and/or an IP allowlist before
making a listener reachable outside your own machine. Monitor and remove
access when it is no longer required.

## Contributing

Issues and pull requests are welcome. Please keep changes focused and include
tests for behavior changes where possible.

## License

This project is licensed under the [BSD 3-Clause License](LICENSE).
