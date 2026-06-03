# proxlet Implementation Progress

Last updated: 2026-06-03

## Implemented

- Added an English command-line interface with `--allow-ip`, `--lhost`,
  `--lport`, `--user`, `--auth`, `--type`, `--proxy`, `--proxy-ca`, and
  `--daemon`.
- Added `--type` values `http`, `https`, `socks5`, `socks5h`, and `mixed`;
  the default is `http`.
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
- Implemented upstream chaining for `http://`, `https://`, `socks5://`, and
  `socks5h://` URLs.
- Added `--proxy-ca <FILE>` so a proxlet instance can trust a private CA when
  chaining through another proxlet HTTPS proxy.
- Added `--daemon` background mode with detached standard streams and printed
  process IDs for shell-based process management.
- Implemented SSH transport chaining for URLs such as
  `ssh://username:password@127.0.0.1:22`, using SSH `direct-tcpip`
  forwarding and direct trust of upstream SSH host keys.
- Selected Rust-native networking APIs (`rustls` and `russh`) so distributed
  binaries do not depend on OpenSSL or a system `libssl` shared library.
- Added unit and asynchronous relay-path tests for command parsing, HTTP
  forwarding, SOCKS5 traffic, HTTP rewriting, and upstream URL parsing.
- Added end-to-end integration tests for the TLS listener using generated test
  certificates, plus live upstream HTTP, SOCKS5h, and SSH proxy fixtures with
  authentication failure coverage.

## Operation Notes

- `http` mode supports HTTPS destination traffic through the standard
  `CONNECT` method; it does not encrypt the client-to-proxy hop.
- `https` mode encrypts the client-to-proxy hop and therefore requires a
  certificate and private key.
- `mixed` mode enables its TLS/HTTPS branch only when `--tls-cert` and
  `--tls-key` are supplied; otherwise HTTP and SOCKS5 remain available.
- Authentication is enabled only when both `--user` and `--auth` are present,
  matching the requested CLI behavior.
- SSH upstream mode accepts server host keys directly and does not read or
  write `known_hosts`.
