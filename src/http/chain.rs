//! Forward one non-CONNECT request to a plain HTTP upstream.

use std::net::IpAddr;

use anyhow::{bail, Result};
use tokio::io::AsyncWriteExt;

use crate::connector::{BoxStream, Connector, Target};

use super::forward;
use super::Request;

/// Forward absolute-form when the upstream is plain HTTP.
///
/// # Parameters
///
/// * `client` - Proxy client. Bytes after this request are left unread.
/// * `request` - Parsed non-CONNECT proxy request.
/// * `target` - Destination used for `Host` and the access log.
/// * `connector` - Connector that may hold an HTTP upstream.
/// * `peer` - Client address recorded in the access log.
/// * `protocol` - Access-log protocol name.
///
/// # Returns
///
/// Returns `Ok(true)` after one upstream response is written and both sides
/// are shut down. Returns `Ok(false)` when the upstream is not plain HTTP.
///
/// # Errors
///
/// Returns an error when the upstream dial, header splice, or exchange fails.
/// A dial failure writes `502 Bad Gateway` before returning.
///
/// # Examples
///
/// ```text
/// if chain::try_forward(&mut client, &request, &target, &connector, peer, "http").await? {
///     return Ok(());
/// }
/// ```
pub(super) async fn try_forward(
    client: &mut BoxStream,
    request: &Request,
    target: &Target,
    connector: &Connector,
    peer: IpAddr,
    protocol: &str,
) -> Result<bool> {
    let logged = target.authority();
    let opened = match connector.open_plain_http_upstream().await {
        Ok(opened) => opened,
        Err(error) => {
            crate::camouflage::write_proxy_status(client, "502 Bad Gateway").await?;
            crate::access::record(peer, protocol, Some(&logged), "error");
            return Err(error);
        }
    };
    let Some((mut remote, authorization)) = opened else {
        return Ok(false);
    };
    if authorization.as_deref().is_some_and(has_control_char) {
        let _ = remote.shutdown().await;
        crate::camouflage::write_proxy_status(client, "502 Bad Gateway").await?;
        crate::access::record(peer, protocol, Some(&logged), "error");
        bail!("upstream proxy authorization contains a control character");
    }
    let header = absolute_form_header(request, &logged, authorization.as_deref());
    if let Err(error) = forward::exchange(
        client,
        &mut remote,
        &request.method,
        &request.headers,
        &header,
        connector.connect_timeout(),
    )
    .await
    {
        crate::access::record(peer, protocol, Some(&logged), "error");
        return Err(error);
    }
    // 只交换这一次. 客户端后续请求留在原连接上, 不能进这条上游连接.
    client.shutdown().await?;
    remote.shutdown().await?;
    crate::access::record(peer, protocol, Some(&logged), "ok");
    Ok(true)
}

/// Build an absolute-form request header for an HTTP upstream.
///
/// # Parameters
///
/// * `request` - Client request. The request-target is copied unchanged.
/// * `authority` - Destination authority written as `Host`.
/// * `authorization` - Optional `Basic` value. It must not contain CR, LF, or NUL.
///
/// # Returns
///
/// Returns header bytes ending in a blank line.
///
/// # Errors
///
/// This function does not return errors.
///
/// # Examples
///
/// ```text
/// let header = absolute_form_header(&request, "example.com:80", Some("Basic eA=="));
/// ```
fn absolute_form_header(
    request: &Request,
    authority: &str,
    authorization: Option<&str>,
) -> Vec<u8> {
    let mut rewritten = format!("{} {} {}\r\n", request.method, request.uri, request.version);
    forward::append_forwarded_headers(&mut rewritten, &request.headers, Some(authority));
    if let Some(value) = authorization {
        // append_forwarded_headers 以空行结束. 认证头必须插在空行前.
        rewritten.truncate(rewritten.len() - 2);
        rewritten.push_str("Proxy-Authorization: ");
        rewritten.push_str(value);
        rewritten.push_str("\r\n\r\n");
    }
    rewritten.into_bytes()
}

/// Report whether a header value contains CR, LF, or NUL.
///
/// # Parameters
///
/// * `value` - Header value that would be spliced into an upstream request.
///
/// # Returns
///
/// Returns `true` when the value must not be written.
///
/// # Errors
///
/// This function does not return errors.
///
/// # Examples
///
/// ```text
/// has_control_char("Basic eA==")
/// ```
fn has_control_char(value: &str) -> bool {
    value
        .bytes()
        .any(|byte| byte == b'\r' || byte == b'\n' || byte == 0)
}

/// Report whether a request header name or value contains CR, LF, or NUL.
///
/// # Parameters
///
/// * `headers` - Parsed header pairs.
///
/// # Returns
///
/// Returns `true` when a name or value must be rejected instead of forwarded.
///
/// # Errors
///
/// This function does not return errors.
///
/// # Examples
///
/// ```text
/// request_has_control_header(&[("Host".to_owned(), "example.com\nX-Evil: 1".to_owned())])
/// ```
pub(super) fn request_has_control_header(headers: &[(String, String)]) -> bool {
    headers
        .iter()
        .any(|(name, value)| has_control_char(name) || has_control_char(value))
}
