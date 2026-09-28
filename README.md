# proxlet

[English](README.md) | [简体中文](README.zh-CN.md)

`proxlet` is a lightweight command-line proxy server for quickly creating a
proxy endpoint and optionally routing traffic through an upstream proxy.

## Features

- Supports HTTP, HTTPS, SOCKS5, SOCKS5h, and fakehttp proxy clients.
- Provides mixed mode. Without TLS files, mixed accepts only HTTP and SOCKS5.
- Supports upstream proxy chaining with HTTP, HTTPS, SOCKS5, SOCKS5h, fakehttp,
  and SSH.
- Provides username/password authentication and source IP allowlists.
- Runs in the background with a built-in daemon option.
- Keeps accepting after transient listener errors instead of exiting.
- Bounds DNS, TCP dials, and handshakes with `--connect-timeout` (default 10 seconds). Established tunnels are not idle-timed out.
- Enables `TCP_NODELAY` on accepted client sockets and outbound TCP connections.
- Relays tunnel bytes with tokio's default 8 KiB buffers. A 256 KiB bidirectional loopback benchmark did not show a clear gain from larger buffers.
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

`mixed` accepts HTTP, SOCKS5 (`0x05`), and TLS (`0x16`) when TLS files are set.
Without TLS files, mixed accepts only HTTP and SOCKS5. It does not accept SOCKS4.

## Usage

### Choose a proxy type

```bash
proxlet --type http
proxlet --type socks5
proxlet --type socks5h
proxlet --type mixed
proxlet --type fakehttp
```

Available types are `http`, `https`, `socks5`, `socks5h`, `mixed`, and
`fakehttp`. The default is `http`. `socks5` and `socks5h` listeners behave the
same. Remote DNS follows the upstream URL, not `--type`. `--lhost` binds the
first resolved address and prints any unused results. An IPv6 authority must
be bracketed; an unbracketed address is rejected instead of using the default
port.
HTTP forward-proxy requests are forwarded once and then closed. Path and query
are copied unchanged. A header name or value containing CR, LF, or NUL is
rejected with 400 and the connection is closed. It is not rewritten or
forwarded. `Host` is rewritten to the target authority and hop-by-hop
headers are not forwarded. `CONNECT` tunnels are unchanged. A target host
containing a control character is rejected and is not spliced into an upstream
`CONNECT` request. A non-CONNECT `https://` absolute-form request is rejected
with HTTP 400 before dialing. A proxy request with an unusable target also
returns 400. Upstream connection
failure returns `502 Bad Gateway`. Origin-form probes still get a generic 404.
Authentication failure on a proxy request returns `407` with
`Proxy-Authenticate`; nmap classifies that reply as `http-proxy`.

### Create certificate files for HTTPS mode

Generate certificate files for local use, then start an HTTPS proxy:

```bash
./create_cert_key.sh
proxlet --type https --tls-cert certs/proxlet-cert.pem --tls-key certs/proxlet-key.pem
```

Trust `certs/proxlet-ca.pem` on clients that connect to this HTTPS proxy. Do
not distribute `certs/proxlet-ca-key.pem` or the whole `certs/` directory.
Add the proxy's hostname or IP address when generating files for another host:

```bash
./create_cert_key.sh --san DNS:proxy.example.com --san IP:192.0.2.10
```

### Chain through an upstream proxy

```bash
proxlet --proxy 'socks5h://username:password@127.0.0.1:1080'
proxlet --proxy 'fakehttp://strong-password@127.0.0.1:8080'
proxlet --proxy 'ssh://username:password@127.0.0.1:22'
proxlet --proxy 'ssh://username@127.0.0.1:22?key=/home/username/.ssh/id_ed25519'
```

A `socks5h` upstream sends hostnames to the upstream proxy. A `socks5` upstream
resolves locally and tries the next address when CONNECT is rejected. Proxy
dial and authentication failures are not retried. An IP literal is still sent
as a SOCKS5 IPv4 or IPv6 address, not as a domain name. A SOCKS
upstream URL with a username and password offers only method `0x02`. A SOCKS5
listener compares usernames and passwords as bytes. A non-UTF-8 password or
domain gets a failure reply instead of a dropped handshake. Connection refused
is reply `0x05`.

For SSH upstreams, use `ssh://username:password@host:port` for password
authentication or add `?key=/path/to/private_key` for public-key
authentication. When both a password and `key` are present, the password is
used as the private key passphrase. `?key=` is percent-decoded once and a
literal `+` is kept; write a space as `%20`.

Omitted ports default to 22 for `ssh`, 1080 for `socks5` and `socks5h`, 80 for
`http`, and 443 for `https`. fakehttp has no default port. A password without
a username is rejected, except a fakehttp secret written as
`fakehttp://:secret@host:port`.

An SSH upstream reuses one authenticated session and opens one `direct-tcpip`
channel per target. A dropped session is dialed again, and the private key is
loaded once. An HTTPS upstream still opens one `CONNECT` tunnel per target;
TLS sessions are reused by the shared rustls client config. A non-CONNECT
request through an HTTP upstream is forwarded as absolute-form and then closed.
It is not wrapped in `CONNECT`. The upstream response, including `407`, is
forwarded. A dial failure is still `502`. An HTTP upstream CONNECT succeeds
only when the status code is 200 and the response has no body.

For fakehttp chaining, run one upstream `proxlet` in fakehttp mode and point a
downstream `proxlet` at it. The downstream listener still exposes a normal
local proxy protocol, such as HTTP, for browsers and applications:

```bash
# On the upstream host
proxlet --lhost 10.10.50.20 --lport 8080 --type fakehttp \
  --aes-secret 'strong-password123'

# On the downstream host
proxlet --lhost 127.0.0.1 --lport 9090 --type http \
  --proxy 'fakehttp://strong-password123@10.10.50.20:8080'
```

fakehttp is designed to make the traffic between the two `proxlet` endpoints
look like plain HTTP traffic. It is not a browser-configurable HTTP proxy
protocol by itself; browsers and applications should connect to the downstream
`proxlet`, which translates their local HTTP or SOCKS proxy traffic into the
fakehttp tunnel.

After the handshake, fakehttp carries tunnel payloads inside HTTP/1.1 chunked
bodies. The URL path is fixed; the tunnel target travels inside the first
body chunk. When `--aes-secret` is set, that hello frame is encrypted and
authenticated with AES-256-GCM over the handshake fields, the client
contributes a random nonce and the server a random salt, and replayed
handshakes are rejected. Both upstream and downstream `proxlet` instances
must run the same fakehttp implementation version.

With `--aes-secret`, fakehttp tunnel payloads are framed and encrypted with
AES-256-GCM. Key material is derived from the secret plus the per-connection
client nonce and server salt, so the downstream URL only needs the same secret
value. Use `--max-frame-size <KB>` to choose the encrypted frame payload size.
Allowed values are `8`, `16`, `32`, and `64`; the default is `16`. When two
proxlet instances use different values, fakehttp negotiates the smaller value
for that connection.

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

Enable authentication with a username plus one password source. Providing only
the username, or only a password source, is an error. `--auth` still works,
but the password remains visible in process arguments and startup warns about
that. The HTTP `Basic` scheme is ASCII case-insensitive. Listener usernames
and passwords are compared in constant time. Prefer a mode 0600 file or `PROXLET_AUTH`:

```bash
install -m 600 /dev/null proxlet.auth
printf '%s\n' 'strong-password' > proxlet.auth
proxlet --type mixed --user alice --auth-file proxlet.auth
```

`--aes-secret`, `--aes-secret-file`, and `PROXLET_AES_SECRET` require
`--type fakehttp`. `--user` and `--auth` are rejected in that mode. A fakehttp
listener or `fakehttp://` upstream with no secret still starts, and warns that
the tunnel payload is plaintext. `--proxy-file` and `PROXLET_PROXY` keep an
upstream URL that contains a password out of process arguments. On Unix the
file must not be group- or world-readable. Non-Unix builds do not check an ACL.

Allow specific client addresses or networks:

```bash
proxlet --allow-ip '127.0.0.1'
proxlet --allow-ip '127.0.0.1,127.0.0.2'
proxlet --allow-ip '127.0.0.1/8'
```

An IPv4-mapped IPv6 client address such as `::ffff:192.0.2.10` matches the
IPv4 address or CIDR. A different IPv6 address still does not.

### Run in the background

Use `--daemon` to start `proxlet` without keeping the current terminal
occupied. The parent returns only after the child is listening, then prints
the listen address and PID. A failed start exits non-zero, prints the reason,
and does not leave a listening process behind.

`--log-file` and `--pid-file` both require `--daemon`. Without `--log-file`,
child logs are discarded. The pid file is written only after the listener is
bound.

Each listener attempt also writes one access line to stdout, which
`--log-file` captures:

```text
access <UTC time> <client-ip> <protocol> <target> <result>
```

`result` is `ok`, `auth-failed`, `rejected`, `bad-request`, `not-proxy`, or
`error`. The line has the client IP and target. It never includes the
username, password, or `Proxy-Authorization` value. A missing target is `-`.

```bash
proxlet --daemon --type mixed --lport 1080 --log-file proxlet.log --pid-file proxlet.pid
```

On Linux, query the process without printing its arguments:

```bash
ps -p <PID> -o pid,user,lstart
ss -ltnp 'sport = :1080'
```

Do not use `ps -f` or `pgrep -af`. Those print process arguments, including a
password passed with `--auth`, `--aes-secret`, or `--proxy`.

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
| `-d, --daemon` | Run in the background without terminal input or output. The parent returns after the child is listening |
| `--log-file <FILE>` | Append daemon stdout to this file. Requires `--daemon`. Without it, child logs are discarded |
| `--pid-file <FILE>` | Write the background PID after the listener is bound. Requires `--daemon` |
| `--allow-ip <allow-src-ip>...` | Allow client IP addresses or CIDR networks |
| `-l, --lhost <lhost>` | Listening host, default: `127.0.0.1` |
| `-p, --lport <lport>` | Listening port, default: `1080` |
| `-u, --user <username>` | Authentication username. Requires `--auth`, `--auth-file`, or `PROXLET_AUTH`. Rejected by `--type fakehttp` |
| `-a, --auth <password>` | Authentication password. Requires `--user`. Visible in process arguments; prefer `--auth-file` |
| `--auth-file <FILE>` | Password file, mode 0600. Requires `--user`. Mutually exclusive with `--auth` and `PROXLET_AUTH` |
| `-t, --type <type>` | Proxy type, default: `http` |
| `--proxy <SCHEMA_URL>` | Upstream proxy URL. Prefer `--proxy-file` when the URL contains a secret |
| `--proxy-file <FILE>` | Upstream proxy URL file, mode 0600. Mutually exclusive with `--proxy` and `PROXLET_PROXY` |
| `--connect-timeout <SECS>` | DNS, TCP dial, and handshake timeout in seconds. Must be greater than zero. Default: `10`. Established tunnels are not idle-timed out |
| `--aes-secret <SECRET>` | AES secret for `--type fakehttp`. Rejected on other listener types. Visible in process arguments; prefer `--aes-secret-file` |
| `--aes-secret-file <FILE>` | AES secret file, mode 0600. Requires `--type fakehttp`. Mutually exclusive with `--aes-secret` and `PROXLET_AES_SECRET` |
| `--max-frame-size <KB>` | fakehttp encrypted frame payload size in KiB: `8`, `16`, `32`, or `64`; default: `16` |
| `--proxy-ca <FILE>` | CA certificate bundle for an HTTPS upstream proxy. Requires `--proxy`, `--proxy-file`, or `PROXLET_PROXY` |
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
