//! SOCKS5 listener implementation.
//!
//! This module handles SOCKS5 CONNECT requests, optional username/password
//! authentication, target address parsing, and bidirectional relaying.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

use anyhow::{bail, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::cli::Auth;
use crate::connector::{relay, with_timeout, BoxStream, Connector, Target};

/// Serve one SOCKS5 client connection.
///
/// # Parameters
///
/// * `client` - Accepted client stream.
/// * `first_byte` - Optional first byte already read by mixed-mode detection.
/// * `connector` - Connector used to reach the requested target.
/// * `auth` - Optional listener username/password credentials.
/// * `peer` - Client IP recorded in the access log. The password is never logged.
/// * `protocol` - Access-log protocol token, usually `socks5`.
///
/// # Returns
///
/// Returns `Ok(())` after the connection finishes.
///
/// # Errors
///
/// Returns an error when the SOCKS version is unsupported, authentication
/// fails, the request is unsupported, target connection fails, or relay fails.
pub async fn serve(
    mut client: BoxStream,
    first_byte: Option<u8>,
    connector: Arc<Connector>,
    auth: Option<&Auth>,
    peer: IpAddr,
    protocol: &str,
) -> Result<()> {
    let timeout = connector.connect_timeout();
    let target = match with_timeout(timeout, "SOCKS handshake", async {
        let version = match first_byte {
            Some(byte) => byte,
            None => read_u8(&mut client).await?,
        };
        if version != 0x05 {
            bail!("unsupported SOCKS version");
        }
        authenticate(&mut client, auth).await?;
        read_request(&mut client).await
    })
    .await
    {
        Ok(target) => target,
        Err(error) => {
            let result = if error.to_string().contains("authentication") {
                "auth-failed"
            } else {
                "bad-request"
            };
            crate::access::record(peer, protocol, None, result);
            return Err(error);
        }
    };
    let logged = target.authority();
    let remote = match connector.connect(&target).await {
        Ok(remote) => remote,
        Err(error) => {
            let status = socks_connect_reply(&error);
            let _ = with_timeout(timeout, "SOCKS reply", write_reply(&mut client, status)).await;
            crate::access::record(peer, protocol, Some(&logged), "error");
            return Err(error);
        }
    };
    with_timeout(timeout, "SOCKS reply", write_reply(&mut client, 0x00)).await?;
    if let Err(error) = relay(client, remote).await {
        crate::access::record(peer, protocol, Some(&logged), "error");
        return Err(error.into());
    }
    crate::access::record(peer, protocol, Some(&logged), "ok");
    Ok(())
}

/// Negotiate SOCKS5 authentication with the client.
///
/// # Parameters
///
/// * `client` - SOCKS5 client stream.
/// * `auth` - Optional expected username/password credentials.
///
/// # Returns
///
/// Returns `Ok(())` after an acceptable method is selected and credentials
/// validate when required.
///
/// # Errors
///
/// Returns an error when the client omits required methods, sends invalid auth
/// framing, provides wrong credentials, or I/O fails.
async fn authenticate(client: &mut BoxStream, auth: Option<&Auth>) -> Result<()> {
    let method_count = read_u8(client).await? as usize;
    let mut methods = vec![0_u8; method_count];
    client.read_exact(&mut methods).await?;
    let selected = if auth.is_some() { 0x02 } else { 0x00 };
    if !methods.contains(&selected) {
        client.write_all(&[0x05, 0xff]).await?;
        bail!("SOCKS5 client did not offer required authentication method")
    }
    client.write_all(&[0x05, selected]).await?;
    if let Some(auth) = auth {
        if read_u8(client).await? != 0x01 {
            client.write_all(&[0x01, 0x01]).await?;
            bail!("invalid SOCKS5 username/password authentication version");
        }
        let username = read_counted_bytes(client).await?;
        let password = read_counted_bytes(client).await?;
        let user_ok =
            crate::secret::constant_time_eq(username.as_slice(), auth.username.as_bytes());
        let pass_ok =
            crate::secret::constant_time_eq(password.as_slice(), auth.password.as_bytes());
        if !user_ok || !pass_ok {
            client.write_all(&[0x01, 0x01]).await?;
            bail!("SOCKS5 authentication failed");
        }
        client.write_all(&[0x01, 0x00]).await?;
    }
    Ok(())
}

/// Read a SOCKS5 CONNECT request target.
///
/// # Parameters
///
/// * `client` - SOCKS5 client stream.
///
/// # Returns
///
/// Returns the requested target endpoint.
///
/// # Errors
///
/// Returns an error when the command is not CONNECT, the address type is
/// unsupported, the domain contains a control character, address data is
/// invalid, or I/O fails. Control-character errors do not include the domain.
async fn read_request(client: &mut BoxStream) -> Result<Target> {
    let mut prefix = [0_u8; 3];
    client.read_exact(&mut prefix).await?;
    if prefix != [0x05, 0x01, 0x00] {
        write_reply(client, 0x07).await?;
        bail!("only SOCKS5 CONNECT is supported")
    }
    let host = match read_u8(client).await? {
        0x01 => {
            let mut octets = [0_u8; 4];
            client.read_exact(&mut octets).await?;
            Ipv4Addr::from(octets).to_string()
        }
        0x03 => {
            let bytes = read_counted_bytes(client).await?;
            match String::from_utf8(bytes) {
                Ok(host) => host,
                Err(_) => {
                    write_reply(client, 0x01).await?;
                    bail!("SOCKS5 domain is not UTF-8");
                }
            }
        }
        0x04 => {
            let mut octets = [0_u8; 16];
            client.read_exact(&mut octets).await?;
            Ipv6Addr::from(octets).to_string()
        }
        _ => {
            write_reply(client, 0x08).await?;
            bail!("unsupported SOCKS5 target address type")
        }
    };
    let mut port = [0_u8; 2];
    client.read_exact(&mut port).await?;
    if let Err(error) = Target::reject_control_chars(&host) {
        write_reply(client, 0x01).await?;
        return Err(error);
    }
    Ok(Target::new(host, u16::from_be_bytes(port)))
}

/// Write a SOCKS5 CONNECT reply.
///
/// # Parameters
///
/// * `client` - SOCKS5 client stream.
/// * `status` - SOCKS5 reply status code.
///
/// # Returns
///
/// Returns `Ok(())` after the reply is written.
///
/// # Errors
///
/// Returns an error when writing to the client fails.
async fn write_reply(client: &mut BoxStream, status: u8) -> Result<()> {
    client
        .write_all(&[0x05, status, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await?;
    Ok(())
}

/// Read a SOCKS length-prefixed byte string.
///
/// # Parameters
///
/// * `client` - SOCKS5 client stream.
///
/// # Returns
///
/// Returns the raw bytes. Username, password, and domain values are not
/// required to be UTF-8 at this layer.
///
/// # Errors
///
/// Returns an error when reading fails.
///
/// # Examples
///
/// ```text
/// let bytes = read_counted_bytes(client).await?;
/// ```
async fn read_counted_bytes(client: &mut BoxStream) -> Result<Vec<u8>> {
    let length = read_u8(client).await? as usize;
    let mut bytes = vec![0_u8; length];
    client.read_exact(&mut bytes).await?;
    Ok(bytes)
}

/// Map a failed target dial to a SOCKS5 reply code.
///
/// # Parameters
///
/// * `error` - Error returned by the connector.
///
/// # Returns
///
/// Returns `0x05` when the error chain contains connection refused, otherwise
/// `0x04`.
///
/// # Errors
///
/// This function does not return errors.
///
/// # Examples
///
/// ```text
/// let status = socks_connect_reply(&error);
/// ```
fn socks_connect_reply(error: &anyhow::Error) -> u8 {
    let refused = error.chain().any(|cause| {
        cause
            .downcast_ref::<std::io::Error>()
            .is_some_and(|io_error| io_error.kind() == std::io::ErrorKind::ConnectionRefused)
    });
    if refused {
        0x05
    } else {
        0x04
    }
}

/// Read one byte from a SOCKS stream.
///
/// # Parameters
///
/// * `client` - SOCKS5 client stream.
///
/// # Returns
///
/// Returns the byte read from the stream.
///
/// # Errors
///
/// Returns an error when the stream closes early or I/O fails.
async fn read_u8(client: &mut BoxStream) -> Result<u8> {
    let mut byte = [0_u8; 1];
    client.read_exact(&mut byte).await?;
    Ok(byte[0])
}
