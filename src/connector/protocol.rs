//! Upstream HTTP CONNECT and SOCKS5 handshake helpers.

use std::net::IpAddr;
use std::time::Duration;

use anyhow::{bail, Result};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::upstream::Credentials;
use super::{BoxStream, Target};

/// Establish an HTTP CONNECT tunnel through an upstream proxy.
///
/// # Parameters
///
/// * `stream` - Connected upstream proxy stream.
/// * `target` - Final destination authority.
/// * `credentials` - Optional upstream Basic authentication credentials.
/// * `timeout` - Deadline for the CONNECT write and the response header read.
///
/// # Returns
///
/// Returns `Ok(())` once the upstream proxy reports tunnel establishment.
///
/// # Errors
///
/// Returns an error when the target host contains a control character, or when
/// writing the request, reading the response, parsing the response status, or
/// receiving a non-200 status fails. A 200 response that includes a body is
/// rejected. Control-character errors do not include the host.
pub(super) async fn establish_http_tunnel(
    stream: &mut BoxStream,
    target: &Target,
    credentials: Option<&Credentials>,
    timeout: Duration,
) -> Result<()> {
    super::with_timeout(timeout, "HTTP CONNECT handshake", async {
        Target::reject_control_chars(&target.host)?;
        let mut request = format!(
            "CONNECT {} HTTP/1.1\r\nHost: {}\r\n",
            target.authority(),
            target.authority()
        );
        if let Some(auth) = credentials {
            let token = BASE64.encode(format!("{}:{}", auth.username, auth.password));
            request.push_str(&format!("Proxy-Authorization: Basic {token}\r\n"));
        }
        request.push_str("\r\n");
        stream.write_all(request.as_bytes()).await?;
        stream.flush().await?;
        let header = read_header(stream, 16 * 1024).await?;
        let header_text = std::str::from_utf8(&header)?;
        let status = header_text.lines().next().unwrap_or_default();
        if http_status_code(status)? != 200 {
            bail!("upstream HTTP proxy rejected CONNECT: {status}");
        }
        if connect_response_has_body(header_text) {
            bail!("upstream HTTP proxy CONNECT response included a body");
        }
        Ok::<(), anyhow::Error>(())
    })
    .await
}

/// Establish a SOCKS5 CONNECT tunnel through an upstream proxy.
///
/// # Parameters
///
/// * `stream` - Connected upstream SOCKS5 proxy stream.
/// * `target` - Final destination.
/// * `credentials` - Optional username/password credentials.
/// * `remote_dns` - Whether to send the hostname to the upstream proxy.
/// * `timeout` - Deadline for DNS, authentication, and the CONNECT handshake.
///
/// # Returns
///
/// Returns `Ok(())` once the SOCKS5 proxy has connected to the target.
///
/// # Errors
/// Returns an error when authentication, DNS resolution, request writing, or
/// proxy response parsing fails. A selected method other than the one offered
/// is an error and includes the method number.
pub(crate) async fn socks_connect(
    stream: &mut BoxStream,
    target: &Target,
    credentials: Option<&Credentials>,
    remote_dns: bool,
    timeout: Duration,
) -> Result<()> {
    super::with_timeout(timeout, "SOCKS handshake", async {
        let expected = if credentials.is_some() { 0x02 } else { 0x00 };
        let methods: &[u8] = if credentials.is_some() {
            &[0x02]
        } else {
            &[0x00]
        };
        stream.write_all(&[0x05, methods.len() as u8]).await?;
        stream.write_all(methods).await?;
        let mut selected = [0_u8; 2];
        stream.read_exact(&mut selected).await?;
        if selected[0] != 0x05 || selected[1] != expected {
            bail!(
                "upstream SOCKS5 proxy selected method {:#04x}, expected {expected:#04x}",
                selected[1]
            );
        }
        if let Some(auth) = credentials {
            let username = sized_bytes(&auth.username, "SOCKS username")?;
            let password = sized_bytes(&auth.password, "SOCKS password")?;
            stream.write_all(&[0x01, username.len() as u8]).await?;
            stream.write_all(username).await?;
            stream.write_all(&[password.len() as u8]).await?;
            stream.write_all(password).await?;
            stream.read_exact(&mut selected).await?;
            if selected != [0x01, 0x00] {
                bail!("upstream SOCKS5 authentication failed");
            }
        }
        let mut request = vec![0x05, 0x01, 0x00];
        if remote_dns {
            append_remote_socks_host(&mut request, &target.host)?;
        } else {
            let mut addresses =
                tokio::net::lookup_host((target.host.as_str(), target.port)).await?;
            let address = addresses
                .next()
                .ok_or_else(|| anyhow::anyhow!("could not resolve {}", target.host))?;
            append_socks_ip(&mut request, address.ip());
        }
        request.extend_from_slice(&target.port.to_be_bytes());
        stream.write_all(&request).await?;
        let mut response = [0_u8; 4];
        stream.read_exact(&mut response).await?;
        if response[0] != 0x05 || response[1] != 0x00 {
            bail!(
                "upstream SOCKS5 connection failed with status {}",
                response[1]
            )
        }
        discard_socks_address(stream, response[3]).await?;
        Ok::<(), anyhow::Error>(())
    })
    .await
}

/// Append a socks5h destination, using an IP address type for literals.
///
/// # Parameters
///
/// * `request` - SOCKS5 CONNECT request being built.
/// * `host` - Destination host or IP literal.
///
/// # Returns
///
/// Returns `Ok(())` after the address type and address bytes are appended.
///
/// # Errors
///
/// Returns an error when a non-IP host is longer than 255 bytes.
///
/// # Examples
///
/// ```text
/// append_remote_socks_host(&mut request, "127.0.0.1")?;
/// append_remote_socks_host(&mut request, "example.com")?;
/// ```
fn append_remote_socks_host(request: &mut Vec<u8>, host: &str) -> Result<()> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        append_socks_ip(request, ip);
        return Ok(());
    }
    let host = sized_bytes(host, "target host")?;
    request.push(0x03);
    request.push(host.len() as u8);
    request.extend_from_slice(host);
    Ok(())
}

/// Append a SOCKS5 IPv4 or IPv6 address.
///
/// # Parameters
///
/// * `request` - SOCKS5 CONNECT request being built.
/// * `ip` - Parsed destination address.
///
/// # Returns
///
/// Returns after the address type and address bytes are appended. This function
/// does not fail.
///
/// # Examples
///
/// ```text
/// append_socks_ip(&mut request, "127.0.0.1".parse().expect("ip"));
/// ```
fn append_socks_ip(request: &mut Vec<u8>, ip: IpAddr) {
    match ip {
        IpAddr::V4(ip) => {
            request.push(0x01);
            request.extend_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            request.push(0x04);
            request.extend_from_slice(&ip.octets());
        }
    }
}

/// Borrow a string as SOCKS-sized bytes.
///
/// # Parameters
///
/// * `value` - String value to encode.
/// * `label` - Human-readable field name for error messages.
///
/// # Returns
///
/// Returns the borrowed byte slice when it fits in a one-byte length field.
///
/// # Errors
///
/// Returns an error when `value` is longer than 255 bytes.
fn sized_bytes<'a>(value: &'a str, label: &str) -> Result<&'a [u8]> {
    let bytes = value.as_bytes();
    if bytes.len() > u8::MAX as usize {
        bail!("{label} is too long")
    }
    Ok(bytes)
}

/// Read and discard the bound address from a SOCKS5 response.
///
/// # Parameters
///
/// * `stream` - Upstream SOCKS5 stream.
/// * `address_type` - SOCKS5 address type byte from the response header.
///
/// # Returns
///
/// Returns `Ok(())` after the address and port are consumed.
///
/// # Errors
///
/// Returns an error when the address type is invalid or the response ends early.
async fn discard_socks_address(stream: &mut BoxStream, address_type: u8) -> Result<()> {
    let size = match address_type {
        0x01 => 4,
        0x03 => {
            let mut length = [0_u8; 1];
            stream.read_exact(&mut length).await?;
            length[0] as usize
        }
        0x04 => 16,
        _ => bail!("upstream SOCKS5 proxy returned an invalid address type"),
    };
    let mut address_and_port = vec![0_u8; size + 2];
    stream.read_exact(&mut address_and_port).await?;
    Ok(())
}

/// Parse the numeric status code from an HTTP status line.
///
/// # Parameters
///
/// * `status` - First line of an upstream HTTP response.
///
/// # Returns
///
/// Returns the status code field.
///
/// # Errors
///
/// Returns an error when the line is not an HTTP status line or the code is
/// not a number.
///
/// # Examples
///
/// ```text
/// let code = http_status_code("HTTP/1.1 200 Connection Established")?;
/// ```
fn http_status_code(status: &str) -> Result<u16> {
    let mut parts = status.split_whitespace();
    let version = parts.next().unwrap_or_default();
    if !version.starts_with("HTTP/") {
        bail!("upstream HTTP proxy returned a malformed status line");
    }
    parts
        .next()
        .unwrap_or_default()
        .parse()
        .map_err(|_| anyhow::anyhow!("upstream HTTP proxy returned a malformed status line"))
}

/// Return whether a CONNECT response header declares a body.
///
/// # Parameters
///
/// * `header` - Complete upstream response header, including the status line.
///
/// # Returns
///
/// Returns `true` when `Content-Length` is present and not zero, or when
/// `Transfer-Encoding` is present.
///
/// # Errors
///
/// This function does not return errors.
///
/// # Examples
///
/// ```text
/// assert!(!connect_response_has_body("HTTP/1.1 200 OK\r\n\r\n"));
/// ```
fn connect_response_has_body(header: &str) -> bool {
    header.lines().skip(1).any(|line| {
        let Some((name, value)) = line.split_once(':') else {
            return false;
        };
        if name.eq_ignore_ascii_case("Transfer-Encoding") {
            return true;
        }
        name.eq_ignore_ascii_case("Content-Length") && value.trim().parse::<u64>().ok() != Some(0)
    })
}

/// Read an HTTP-style header until CRLFCRLF or a size limit.
///
/// # Parameters
///
/// * `stream` - Stream to read from.
/// * `limit` - Maximum accepted header size in bytes.
///
/// # Returns
///
/// Returns the complete header bytes including the terminating CRLFCRLF.
///
/// # Errors
///
/// Returns an error when the header exceeds `limit`, the stream ends early, or
/// I/O fails.
async fn read_header(stream: &mut BoxStream, limit: usize) -> Result<Vec<u8>> {
    crate::bufio::read_until(stream, &[], b"\r\n\r\n", limit, "proxy response header").await
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn connect_rejects_control_characters_before_writing() {
        let (client, mut upstream) = tokio::io::duplex(256);
        let mut client: BoxStream = Box::new(client);
        let target = Target::new("example.com\r\nProxy-Authorization: Basic eA==", 80);
        let error = establish_http_tunnel(&mut client, &target, None, Duration::from_secs(1))
            .await
            .expect_err("control host");
        let text = error.to_string();
        assert!(text.contains("control character"), "{text}");
        assert!(!text.contains("Proxy-Authorization"), "{text}");
        drop(client);
        let mut buf = [0_u8; 32];
        let n = upstream.read(&mut buf).await.expect("read");
        assert_eq!(n, 0, "rejected host must not be written");
    }

    #[tokio::test]
    async fn socks5h_sends_ip_literals_as_addresses() {
        let cases = [
            ("127.0.0.1", 80, vec![0x01, 127, 0, 0, 1, 0, 80]),
            ("::1", 443, {
                let mut bytes = vec![0x04];
                bytes.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
                bytes.extend_from_slice(&443u16.to_be_bytes());
                bytes
            }),
            ("localhost", 9, {
                let mut bytes = vec![0x03, b"localhost".len() as u8];
                bytes.extend_from_slice(b"localhost");
                bytes.extend_from_slice(&9u16.to_be_bytes());
                bytes
            }),
        ];
        for (host, port, expected) in cases {
            let (client, upstream) = tokio::io::duplex(256);
            let mut client: BoxStream = Box::new(client);
            let captured = tokio::spawn(async move {
                let mut upstream = upstream;
                let mut greeting = [0_u8; 2];
                upstream.read_exact(&mut greeting).await.expect("greeting");
                let mut methods = vec![0_u8; greeting[1] as usize];
                upstream.read_exact(&mut methods).await.expect("methods");
                upstream.write_all(&[0x05, 0x00]).await.expect("method");
                let mut head = [0_u8; 4];
                upstream.read_exact(&mut head).await.expect("request");
                let mut address = match head[3] {
                    0x01 => vec![0_u8; 4],
                    0x04 => vec![0_u8; 16],
                    0x03 => {
                        let mut length = [0_u8; 1];
                        upstream.read_exact(&mut length).await.expect("length");
                        let mut domain = vec![0_u8; length[0] as usize];
                        upstream.read_exact(&mut domain).await.expect("domain");
                        let mut encoded = vec![length[0]];
                        encoded.extend(domain);
                        encoded
                    }
                    other => panic!("unexpected address type {other}"),
                };
                if head[3] != 0x03 {
                    upstream.read_exact(&mut address).await.expect("address");
                }
                let mut port_bytes = [0_u8; 2];
                upstream.read_exact(&mut port_bytes).await.expect("port");
                upstream
                    .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                    .await
                    .expect("reply");
                let mut wire = vec![head[3]];
                wire.extend(address);
                wire.extend(port_bytes);
                wire
            });
            socks_connect(
                &mut client,
                &Target::new(host, port),
                None,
                true,
                Duration::from_secs(1),
            )
            .await
            .unwrap_or_else(|error| panic!("{host}: {error}"));
            let wire = captured.await.expect("capture");
            assert_eq!(wire, expected, "{host}");
        }
    }

    #[tokio::test]
    async fn socks_with_credentials_rejects_no_auth_selection() {
        let (client, mut upstream) = tokio::io::duplex(256);
        let mut client: BoxStream = Box::new(client);
        let auth = Credentials {
            username: "alice".to_string(),
            password: "secret".to_string(),
        };
        let task = tokio::spawn(async move {
            socks_connect(
                &mut client,
                &Target::new("example.com", 80),
                Some(&auth),
                true,
                Duration::from_secs(1),
            )
            .await
        });
        let mut greeting = [0_u8; 2];
        upstream.read_exact(&mut greeting).await.expect("greeting");
        assert_eq!(greeting, [0x05, 0x01]);
        let mut methods = [0_u8; 1];
        upstream.read_exact(&mut methods).await.expect("methods");
        assert_eq!(methods, [0x02]);
        upstream
            .write_all(&[0x05, 0x00])
            .await
            .expect("select no-auth");
        let error = task.await.expect("join").expect_err("no-auth selection");
        let text = error.to_string();
        assert!(text.contains("0x00"), "{text}");
        assert!(text.contains("0x02"), "{text}");
        let mut buf = [0_u8; 8];
        let n = upstream.read(&mut buf).await.expect("read");
        assert_eq!(n, 0, "rejected method must not send CONNECT");
    }

    #[tokio::test]
    async fn http_connect_parses_status_code_and_rejects_body() {
        let cases: &[(&[u8], bool, &str)] = &[
            (b"HTTP/1.1 200\r\n\r\n", true, ""),
            (
                b"HTTP/1.1 500 Error 200 inside\r\n\r\n",
                false,
                "rejected CONNECT",
            ),
            (
                b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\n",
                false,
                "included a body",
            ),
            (
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n",
                false,
                "included a body",
            ),
        ];
        for (response, ok, needle) in cases {
            let (client, mut upstream) = tokio::io::duplex(512);
            let mut client: BoxStream = Box::new(client);
            let response = *response;
            let upstream_task = tokio::spawn(async move {
                let mut buf = [0_u8; 256];
                let n = upstream.read(&mut buf).await.expect("request");
                assert!(buf[..n].starts_with(b"CONNECT "));
                upstream.write_all(response).await.expect("response");
            });
            let result = establish_http_tunnel(
                &mut client,
                &Target::new("example.com", 443),
                None,
                Duration::from_secs(1),
            )
            .await;
            upstream_task.await.expect("join");
            if *ok {
                result.unwrap_or_else(|error| panic!("{error}"));
            } else {
                let text = result.expect_err("status").to_string();
                assert!(text.contains(needle), "{text}");
            }
        }
    }
}
