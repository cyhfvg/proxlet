//! SSH upstream direct-tcpip connector support.

use std::net::Shutdown;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use russh::client;
use russh::keys::{Algorithm, HashAlg, PrivateKeyWithHashAlg};
use tokio::net::TcpStream;

use super::upstream::{SshAuthenticationMethod, SshEndpoint};
use super::{BoxStream, Target, with_timeout};

#[derive(Clone)]
/// SSH client handler used for upstream sessions.
struct SshHandler;

impl client::Handler for SshHandler {
    type Error = anyhow::Error;

    /// Accept any SSH server host key.
    ///
    /// # Parameters
    ///
    /// * `self` - Mutable SSH handler state.
    /// * `_key` - Server public key presented during SSH handshake.
    ///
    /// # Returns
    ///
    /// Returns `true` to allow the connection.
    ///
    /// # Errors
    ///
    /// This handler does not return validation errors.
    async fn check_server_key(
        &mut self,
        _key: &russh::keys::ssh_key::PublicKey,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

/// Establish an SSH direct-tcpip channel to a target.
///
/// # Parameters
///
/// * `tcp` - Already connected SSH server stream. Dialing is the caller's job
///   so each address can use its own timeout.
/// * `endpoint` - SSH upstream endpoint and credentials.
/// * `target` - Final destination for the direct-tcpip channel.
/// * `timeout` - Deadline applied separately to key exchange, authentication,
///   and channel open. It is not an idle timeout for the opened channel.
///
/// # Returns
///
/// Returns a boxed SSH channel stream.
///
/// # Errors
///
/// Returns an error when SSH connection, authentication, key loading, or channel
/// opening fails.
///
/// # Examples
///
/// ```ignore
/// let stream = ssh_connect(tcp, endpoint, target, timeout).await?;
/// ```
pub(super) async fn ssh_connect(
    tcp: TcpStream,
    endpoint: &SshEndpoint,
    target: &Target,
    timeout: Duration,
) -> Result<BoxStream> {
    // 不用 client::connect, 否则会再拨一次号, 而且没有按地址超时.
    let _ = tcp.set_nodelay(true);
    let (stream, watchdog) = split_watchdog(tcp)?;
    let handshake = ssh_handshake(stream, endpoint, target, timeout).await;
    if handshake.is_err() {
        // connect_stream 在 kex 完成前就 spawn 了 session.run. drop 外层 timeout
        // 不会中止这个 task, kex 期间它也不看 handle 断开. 关掉这个克隆才能让残留
        // 读失败. 成功时只 drop 克隆, shutdown 会拆掉已建立隧道. 不要改用
        // inactivity_timeout, 那会给已建立会话加 idle-timeout.
        let _ = watchdog.shutdown(Shutdown::Both);
    }
    handshake
}

/// Run SSH key exchange, authentication, and direct-tcpip open.
///
/// # Parameters
///
/// * `stream` - Connected SSH server stream.
/// * `endpoint` - SSH upstream endpoint and credentials.
/// * `target` - Final destination for the direct-tcpip channel.
/// * `timeout` - Per-phase deadline.
///
/// # Returns
///
/// Returns a boxed SSH channel stream.
///
/// # Errors
///
/// Returns an error when key exchange, authentication, key loading, or channel
/// opening fails.
///
/// # Examples
///
/// ```ignore
/// let stream = ssh_handshake(tcp, endpoint, target, timeout).await?;
/// ```
async fn ssh_handshake(
    stream: TcpStream,
    endpoint: &SshEndpoint,
    target: &Target,
    timeout: Duration,
) -> Result<BoxStream> {
    let config = Arc::new(client::Config {
        nodelay: true,
        ..Default::default()
    });
    let mut session = with_timeout(
        timeout,
        "SSH handshake",
        client::connect_stream(config, stream, SshHandler),
    )
    .await
    .context("could not establish SSH upstream session")?;
    let authenticated = match &endpoint.auth.method {
        SshAuthenticationMethod::Password(password) => with_timeout(
            timeout,
            "SSH authentication",
            session.authenticate_password(endpoint.auth.username.clone(), password.clone()),
        )
        .await?
        .success(),
        SshAuthenticationMethod::PrivateKey { path, passphrase } => {
            // 读盘和 KDF 是同步的. 放在超时 future 外面, 避免把截止时间当成能打断它.
            let key = Arc::new(
                russh::keys::load_secret_key(path, passphrase.as_deref()).with_context(|| {
                    format!("could not load SSH private key {}", path.display())
                })?,
            );
            with_timeout(
                timeout,
                "SSH authentication",
                authenticate_private_key(&mut session, endpoint.auth.username.clone(), key),
            )
            .await?
        }
    };
    if !authenticated {
        bail!("SSH upstream authentication failed");
    }
    let channel = with_timeout(
        timeout,
        "SSH direct-tcpip",
        session.channel_open_direct_tcpip(target.host.clone(), target.port.into(), "127.0.0.1", 0),
    )
    .await
    .with_context(|| format!("SSH server could not forward to {}", target.authority()))?;
    Ok(Box::new(channel.into_stream()))
}

/// Duplicate a socket so a failed handshake can close russh's leftover task.
///
/// # Parameters
///
/// * `stream` - Connected TCP stream that will be given to russh.
///
/// # Returns
///
/// Returns the tokio stream for russh and a std clone used only as a watchdog.
///
/// # Errors
///
/// Returns an error when the socket cannot be converted or cloned.
///
/// # Examples
///
/// ```ignore
/// let (stream, watchdog) = split_watchdog(tcp)?;
/// ```
fn split_watchdog(stream: TcpStream) -> Result<(TcpStream, std::net::TcpStream)> {
    let std_stream = stream.into_std()?;
    std_stream.set_nonblocking(true)?;
    let watchdog = std_stream.try_clone()?;
    let stream = TcpStream::from_std(std_stream)?;
    Ok((stream, watchdog))
}

/// Try public-key authentication with compatible hash algorithms.
///
/// # Parameters
///
/// * `session` - Connected SSH client session.
/// * `username` - SSH username.
/// * `key` - Private key used for authentication.
///
/// # Returns
///
/// Returns `true` when one authentication attempt succeeds.
///
/// # Errors
///
/// Returns an error when querying server algorithms or an authentication attempt
/// fails at the protocol level.
async fn authenticate_private_key(
    session: &mut client::Handle<SshHandler>,
    username: String,
    key: Arc<russh::keys::PrivateKey>,
) -> Result<bool> {
    let key_algorithm = key.algorithm();
    let server_rsa_hash = if matches!(key_algorithm, Algorithm::Rsa { .. }) {
        session.best_supported_rsa_hash().await?
    } else {
        None
    };
    for hash_alg in publickey_hash_algorithms(key_algorithm, server_rsa_hash) {
        let result = session
            .authenticate_publickey(
                username.clone(),
                PrivateKeyWithHashAlg::new(key.clone(), hash_alg),
            )
            .await?;
        if result.success() {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Choose SSH public-key hash algorithms for an authentication attempt.
///
/// # Parameters
///
/// * `key_algorithm` - Algorithm of the loaded private key.
/// * `server_rsa_hash` - RSA signature algorithm advertised by the SSH server.
///
/// # Returns
///
/// Returns ordered hash algorithm candidates to try.
///
/// # Errors
///
/// This function does not return errors.
fn publickey_hash_algorithms(
    key_algorithm: Algorithm,
    server_rsa_hash: Option<Option<HashAlg>>,
) -> Vec<Option<HashAlg>> {
    if !matches!(key_algorithm, Algorithm::Rsa { .. }) {
        return vec![None];
    }

    match server_rsa_hash {
        Some(hash_alg) => vec![hash_alg],
        None => vec![Some(HashAlg::Sha512), Some(HashAlg::Sha256), None],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tries_rsa_sha2_when_server_does_not_advertise_signature_algorithms() {
        assert_eq!(
            publickey_hash_algorithms(Algorithm::Rsa { hash: None }, None),
            vec![Some(HashAlg::Sha512), Some(HashAlg::Sha256), None,]
        );
    }

    #[test]
    fn uses_server_advertised_rsa_signature_algorithm() {
        assert_eq!(
            publickey_hash_algorithms(Algorithm::Rsa { hash: None }, Some(Some(HashAlg::Sha256))),
            vec![Some(HashAlg::Sha256)]
        );
        assert_eq!(
            publickey_hash_algorithms(Algorithm::Rsa { hash: None }, Some(None)),
            vec![None]
        );
    }

    #[test]
    fn ignores_hash_algorithm_for_non_rsa_keys() {
        assert_eq!(
            publickey_hash_algorithms(Algorithm::Ed25519, Some(Some(HashAlg::Sha512))),
            vec![None]
        );
    }
}
