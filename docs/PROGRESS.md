# proxlet Implementation Progress

Last updated: 2026-09-28

## Implemented

- Added an English command-line interface with `--allow-ip`, `--lhost`,
  `--lport`, `--user`, `--auth`, `--type`, `--proxy`, `--proxy-ca`, and
  `--daemon`.
- Added `--type` values `http`, `https`, `socks5`, `socks5h`, `mixed`, and
  `fakehttp`; the default is `http`.
- Implemented HTTP forward proxy requests and HTTP `CONNECT` tunnels.
- Implemented TLS-wrapped HTTPS proxy listener mode through
  `--tls-cert <FILE> --tls-key <FILE>`.
- Added `create_cert_key.sh` to generate a local CA and HTTPS proxy
  certificate/key files for quick setup.
- Implemented SOCKS5 CONNECT handling for IPv4, IPv6, and domain targets.
  Incoming SOCKS5 and SOCKS5h clients use the same standard SOCKS5 wire
  protocol; hostname targets remain available for remote DNS paths.
- Implemented mixed listener dispatch: HTTP and SOCKS5 are accepted on one
  port, and HTTPS proxy connections are also accepted on that port when TLS
  certificate files are configured.
- Implemented optional client access controls: source IP allowlisting with
  single IP, comma-separated IP, and CIDR forms; HTTP Basic proxy
  authentication; and SOCKS5 username/password authentication.
- Implemented upstream chaining for `http://`, `https://`, `socks5://`,
  `socks5h://`, and `fakehttp://` URLs.
- Added `--proxy-ca <FILE>` so a proxlet instance can trust a private CA when
  chaining through another proxlet HTTPS proxy.
- Added `--daemon` background mode. The parent returns only after the child is
  listening, then prints the listen address and PID. `--log-file` and
  `--pid-file` require `--daemon`; without `--log-file`, child logs are
  discarded. A failed start exits non-zero and does not leave a listener.
- Listener attempts write one access line to stdout:
  `access <time> <client-ip> <protocol> <target> <result>`. Authentication
  failures are included. Usernames, passwords, and authorization headers are
  not. Daemon `--log-file` captures these lines.
- Implemented SSH transport chaining for URLs such as
  `ssh://username:password@127.0.0.1:22`, using SSH `direct-tcpip`
  forwarding and direct trust of upstream SSH host keys.
- Added SSH upstream private-key authentication with
  `ssh://username@host:port?key=/path/to/private_key`; URL passwords are used
  as private key passphrases when a key is provided.
- Added `fakehttp` listener and upstream chaining mode, with optional
  AES-256-GCM framing through `--aes-secret` and `fakehttp://secret@host:port`.
- fakehttp now carries tunneled payload bytes inside HTTP/1.1 chunked bodies
  after the initial request/response headers.
- Added `--max-frame-size <KB>` for fakehttp encrypted frame sizing, with
  connection-level negotiation to the smaller endpoint value.
- Selected Rust-native networking APIs (`rustls` and `russh`) so distributed
  binaries do not depend on OpenSSL or a system `libssl` shared library.
- Added unit and asynchronous relay-path tests for command parsing, HTTP
  forwarding, SOCKS5 traffic, HTTP rewriting, and upstream URL parsing.
- Added end-to-end integration tests for the TLS listener using generated test
  certificates, plus live upstream HTTP, SOCKS5h, and SSH proxy fixtures with
  authentication failure coverage.
- Added live SSH upstream integration coverage for private-key authentication
  success and failure.
- Added live encrypted fakehttp upstream integration coverage.
- HTTP and fakehttp listeners now answer origin-form scanner probes such as
  nmap `GET /` with a generic nginx 404, and replace `502 Bad Gateway` with a
  503 page so version detection does not classify the port as `http-proxy`.
- HTTP forward-proxy requests are forwarded once and then closed. `Host` is
  rewritten to the target authority, hop-by-hop headers are not forwarded, and
  a later request on the same client connection is not copied to the first
  origin. `CONNECT` tunnels are unchanged.
- Transient accept errors no longer stop the process. `EMFILE`, `ENFILE`,
  `ECONNABORTED`, and `ENOBUFS` are logged and retried after a short backoff.
  The listener exits only when the listening socket is closed.
- DNS lookups, TCP dials, and protocol handshakes now fail after
  `--connect-timeout` seconds (default 10). Each resolved address gets a fresh
  deadline, and handshake header reads use the same deadline. Established
  tunnels and body copies are not idle-timed out.

## Operation Notes

- `http` mode supports HTTPS destination traffic through the standard
  `CONNECT` method; it does not encrypt the client-to-proxy hop.
- `https` mode encrypts the client-to-proxy hop and therefore requires a
  certificate and private key.
- `mixed` mode enables its TLS/HTTPS branch only when `--tls-cert` and
  `--tls-key` are supplied; otherwise HTTP and SOCKS5 remain available.
- Providing only `--user` or only `--auth` is a startup error that names the
  missing flag. Startup logs `authentication enabled` or `authentication disabled`.
- `--auth`, `--aes-secret`, and an upstream URL can be read from mode 0600
  files (`--auth-file`, `--aes-secret-file`, `--proxy-file`) or from
  `PROXLET_AUTH`, `PROXLET_AES_SECRET`, and `PROXLET_PROXY`. A flag that still
  puts a secret in process arguments warns at startup and does not print it.
- An AES secret on a non-fakehttp listener, or `--user`/`--auth` on a fakehttp
  listener, is a startup error. A fakehttp listener or upstream with no secret
  still starts, and warns that the tunnel payload is plaintext. An encryption
  mismatch names whether the listener or the client lacks the secret.
- A target host containing CR, LF, NUL, or another control character is
  rejected before it can be spliced into an HTTP `CONNECT` request. The error
  does not include the host.
- An SSH upstream reuses one authenticated session and opens one
  `direct-tcpip` channel per target. A dropped session is dialed again. The
  private key is loaded once with `spawn_blocking` and cached. An HTTPS
  upstream still opens one `CONNECT` tunnel per target; TLS sessions are
  reused by the shared rustls `ClientConfig`.
- A `socks5h` upstream sends an IP literal as SOCKS5 address type 1 or 4.
  Only a hostname is sent as address type 3.
- Accepted client sockets and successfully dialed TCP sockets enable
  `TCP_NODELAY`. Relay buffer sizes are unchanged.
- `benches/proxy.rs` measures a 256 KiB copy in each direction through the
  production relay. A short loopback run did not show a clear gain from 64 KiB
  buffers over tokio's default 8 KiB buffers, so `relay` still uses
  `copy_bidirectional`.
- A SOCKS upstream URL with credentials offers only username/password method
  `0x02`. A different selected method fails and includes the method number.
- A non-CONNECT `https://` absolute-form request is rejected with HTTP 400
  before dialing. It is not written as plaintext HTTP to port 443.
- An HTTP upstream CONNECT succeeds only when the status code field is 200 and
  the response does not declare a body.
- A SOCKS5 listener compares usernames and passwords as bytes. A non-UTF-8
  password or domain gets a failure reply. Connection refused is reply `0x05`.
- `scripts/local_build.sh --help` names proxlet. Its Windows target comment is
  `x86_64-pc-windows-msvc`.
- SSH upstream mode accepts server host keys directly and does not read or
  write `known_hosts`.
- fakehttp mode uses an HTTP/1.1-looking handshake followed by a proxlet-specific
  bidirectional tunnel on the same TCP connection.
- fakehttp v2 handshake (2026-09): the URL path is fixed and the tunnel target
  travels inside the first body chunk, AES-256-GCM encrypted and bound to the
  handshake transcript (Host, frame size, encoding) when a secret is
  configured. The client contributes a random nonce and the server a random
  salt; both feed key derivation, replayed handshakes are rejected by nonce,
  the frame-size header is mandatory on both sides, and an authenticated
  empty frame signals clean EOF so chunk-boundary truncation cannot look like
  a normal close. Both endpoints must run the same fakehttp version.
- Relay flushes both ends before copying so buffered writes are not left in
  user space. fakehttp chunked and crypto writers report accepted bytes only
  after the queued frame has been drained, including short writes.
