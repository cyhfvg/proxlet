//! SOCKS5 upstream dialing with local-DNS address fallback.

use std::future::Future;
use std::net::IpAddr;
use std::time::Duration;

use anyhow::{bail, Context, Result};

use super::protocol::socks_connect;
use super::upstream::Endpoint;
use super::{BoxStream, Target};

/// Open a SOCKS5 upstream tunnel, trying each locally resolved address.
///
/// # Parameters
///
/// * `endpoint` - Upstream SOCKS5 proxy.
/// * `remote_dns` - Whether the upstream proxy should resolve the hostname.
/// * `target` - Final destination.
/// * `timeout` - Deadline for each proxy dial and handshake.
///
/// # Returns
///
/// Returns the connected proxy stream after a SOCKS5 CONNECT succeeds.
///
/// # Errors
///
/// Returns an error when the proxy cannot be reached, authentication fails, or
/// every resolved address is rejected. A local-DNS failure names the host and
/// each rejected address. `socks5h` still sends the hostname once.
///
/// # Examples
///
/// ```text
/// socks5://proxy example.test -> try 2001:db8::1, then 192.0.2.10
/// socks5h://proxy example.test -> send example.test once
/// ```
pub(super) async fn open_socks5(
    endpoint: &Endpoint,
    remote_dns: bool,
    target: &Target,
    timeout: Duration,
) -> Result<BoxStream> {
    if remote_dns || target.host.parse::<IpAddr>().is_ok() {
        return dial_socks(endpoint, target, remote_dns, timeout).await;
    }
    let addresses: Vec<IpAddr> = tokio::net::lookup_host((target.host.as_str(), target.port))
        .await
        .with_context(|| format!("could not resolve {}", target.host))?
        .map(|address| address.ip())
        .collect();
    let endpoint = endpoint.clone();
    let port = target.port;
    first_accepted_socks_address(&target.host, &addresses, move |ip| {
        let endpoint = endpoint.clone();
        let destination = Target::new(ip.to_string(), port);
        async move { dial_socks(&endpoint, &destination, false, timeout).await }
    })
    .await
}

/// Dial the upstream proxy and send one SOCKS5 CONNECT.
///
/// # Parameters
///
/// * `endpoint` - Upstream SOCKS5 proxy.
/// * `target` - Destination encoded into the CONNECT request.
/// * `remote_dns` - Whether to send a hostname instead of an address.
/// * `timeout` - Deadline for the dial and handshake.
///
/// # Returns
///
/// Returns the connected proxy stream.
///
/// # Errors
///
/// Returns an error when the proxy dial or SOCKS5 handshake fails.
///
/// # Examples
///
/// ```text
/// dial_socks(proxy, 192.0.2.10:80, false, 10s)
/// ```
async fn dial_socks(
    endpoint: &Endpoint,
    target: &Target,
    remote_dns: bool,
    timeout: Duration,
) -> Result<BoxStream> {
    let mut stream: BoxStream = Box::new(super::connect_tcp(&endpoint.target, timeout).await?);
    socks_connect(
        &mut stream,
        target,
        endpoint.credentials.as_ref(),
        remote_dns,
        timeout,
    )
    .await?;
    Ok(stream)
}

/// Try SOCKS5 destinations until one CONNECT is accepted.
///
/// # Parameters
///
/// * `host` - Original destination hostname, used in the failure message.
/// * `addresses` - Locally resolved addresses, in lookup order.
/// * `connect_one` - Opens a new proxy connection and requests one address.
///
/// # Returns
///
/// Returns the first successful connection.
///
/// # Errors
///
/// Returns the original error when the proxy dial or authentication fails.
/// Returns an error naming `host` and every rejected address when each CONNECT
/// is rejected. An empty address list is a resolution error.
///
/// # Examples
///
/// ```text
/// 2001:db8::1 rejected, 192.0.2.10 accepted -> use 192.0.2.10
/// ```
async fn first_accepted_socks_address<T, F, Fut>(
    host: &str,
    addresses: &[IpAddr],
    mut connect_one: F,
) -> Result<T>
where
    F: FnMut(IpAddr) -> Fut,
    Fut: Future<Output = Result<T>>,
{
    if addresses.is_empty() {
        bail!("could not resolve {host}");
    }
    let mut failures = Vec::new();
    for address in addresses {
        match connect_one(*address).await {
            Ok(value) => return Ok(value),
            Err(error) if socks_target_rejected(&error) => {
                failures.push(format!("{address}: {error}"));
            }
            Err(error) => return Err(error),
        }
    }
    bail!(
        "upstream SOCKS5 connection to {host} failed after trying {}",
        failures.join("; ")
    )
}

/// Report whether a SOCKS5 CONNECT was rejected by the upstream proxy.
///
/// # Parameters
///
/// * `error` - Error returned by one CONNECT attempt.
///
/// # Returns
///
/// Returns `true` when the proxy answered the CONNECT and rejected the target.
/// Proxy dial and authentication failures return `false`.
///
/// # Errors
///
/// This function does not return errors.
///
/// # Examples
///
/// ```text
/// upstream SOCKS5 connection failed with status 4 -> true
/// could not connect to proxy -> false
/// ```
fn socks_target_rejected(error: &anyhow::Error) -> bool {
    error
        .to_string()
        .starts_with("upstream SOCKS5 connection failed")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn tries_the_next_address_after_connect_rejection() {
        let first: IpAddr = "2001:db8::1".parse().expect("v6");
        let second: IpAddr = "192.0.2.10".parse().expect("v4");
        let mut seen = Vec::new();
        let result = first_accepted_socks_address("example.test", &[first, second], |ip| {
            seen.push(ip);
            async move {
                if ip == first {
                    Err(anyhow::anyhow!(
                        "upstream SOCKS5 connection failed with status 4"
                    ))
                } else {
                    Ok(ip)
                }
            }
        })
        .await
        .expect("second address");

        assert_eq!(result, second);
        assert_eq!(seen, vec![first, second]);
    }

    #[tokio::test]
    async fn names_the_host_and_every_rejected_address() {
        let first: IpAddr = "2001:db8::1".parse().expect("v6");
        let second: IpAddr = "192.0.2.10".parse().expect("v4");
        let error = first_accepted_socks_address("example.test", &[first, second], |_| async {
            Err::<IpAddr, _>(anyhow::anyhow!(
                "upstream SOCKS5 connection failed with status 4"
            ))
        })
        .await
        .expect_err("both rejected");
        let text = error.to_string();

        assert!(text.contains("example.test"), "{text}");
        assert!(text.contains("2001:db8::1"), "{text}");
        assert!(text.contains("192.0.2.10"), "{text}");
    }

    #[tokio::test]
    async fn does_not_retry_when_the_proxy_itself_fails() {
        let first: IpAddr = "2001:db8::1".parse().expect("v6");
        let second: IpAddr = "192.0.2.10".parse().expect("v4");
        let mut seen = Vec::new();
        let error = first_accepted_socks_address("example.test", &[first, second], |ip| {
            seen.push(ip);
            async move { Err::<IpAddr, _>(anyhow::anyhow!("could not connect to proxy")) }
        })
        .await
        .expect_err("proxy down");

        assert!(error.to_string().contains("could not connect to proxy"));
        assert_eq!(seen, vec![first]);
    }
}
