//! Upstream HTTP CONNECT and SOCKS5 handshake helpers.

use anyhow::{Result, bail};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
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
///
/// # Returns
///
/// Returns `Ok(())` once the upstream proxy reports tunnel establishment.
///
/// # Errors
///
/// Returns an error when writing the request, reading the response, parsing the
/// response status, or receiving a non-200 status fails.
pub(super) async fn establish_http_tunnel(
    stream: &mut BoxStream,
    target: &Target,
    credentials: Option<&Credentials>,
) -> Result<()> {
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
    let status = std::str::from_utf8(&header)?
        .lines()
        .next()
        .unwrap_or_default();
    if !status.contains(" 200 ") {
        bail!("upstream HTTP proxy rejected CONNECT: {status}")
    }
    Ok(())
}

/// Establish a SOCKS5 CONNECT tunnel through an upstream proxy.
///
/// # Parameters
///
/// * `stream` - Connected upstream SOCKS5 proxy stream.
/// * `target` - Final destination.
/// * `credentials` - Optional username/password credentials.
/// * `remote_dns` - Whether to send the hostname to the upstream proxy.
///
/// # Returns
///
/// Returns `Ok(())` once the SOCKS5 proxy has connected to the target.
///
/// # Errors
///
/// Returns an error when authentication, DNS resolution, request writing, or
/// proxy response parsing fails.
pub(super) async fn socks_connect(
    stream: &mut BoxStream,
    target: &Target,
    credentials: Option<&Credentials>,
    remote_dns: bool,
) -> Result<()> {
    let methods = if credentials.is_some() {
        &[0x00, 0x02][..]
    } else {
        &[0x00][..]
    };
    stream.write_all(&[0x05, methods.len() as u8]).await?;
    stream.write_all(methods).await?;
    let mut selected = [0_u8; 2];
    stream.read_exact(&mut selected).await?;
    if selected[0] != 0x05 || selected[1] == 0xff {
        bail!("upstream SOCKS5 proxy rejected authentication methods")
    }
    if selected[1] == 0x02 {
        let auth = credentials
            .ok_or_else(|| anyhow::anyhow!("upstream SOCKS5 proxy requested credentials"))?;
        let username = sized_bytes(&auth.username, "SOCKS username")?;
        let password = sized_bytes(&auth.password, "SOCKS password")?;
        stream.write_all(&[0x01, username.len() as u8]).await?;
        stream.write_all(username).await?;
        stream.write_all(&[password.len() as u8]).await?;
        stream.write_all(password).await?;
        stream.read_exact(&mut selected).await?;
        if selected != [0x01, 0x00] {
            bail!("upstream SOCKS5 authentication failed")
        }
    }
    let mut request = vec![0x05, 0x01, 0x00];
    if remote_dns {
        let host = sized_bytes(&target.host, "target host")?;
        request.push(0x03);
        request.push(host.len() as u8);
        request.extend_from_slice(host);
    } else {
        let mut addresses = tokio::net::lookup_host((target.host.as_str(), target.port)).await?;
        let address = addresses
            .next()
            .ok_or_else(|| anyhow::anyhow!("could not resolve {}", target.host))?;
        match address.ip() {
            std::net::IpAddr::V4(ip) => {
                request.push(0x01);
                request.extend_from_slice(&ip.octets());
            }
            std::net::IpAddr::V6(ip) => {
                request.push(0x04);
                request.extend_from_slice(&ip.octets());
            }
        }
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
    Ok(())
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
    let mut header = Vec::with_capacity(256);
    while !header.ends_with(b"\r\n\r\n") {
        if header.len() >= limit {
            bail!("proxy response header exceeds {limit} bytes")
        }
        let mut byte = [0_u8; 1];
        stream.read_exact(&mut byte).await?;
        header.push(byte[0]);
    }
    Ok(header)
}
