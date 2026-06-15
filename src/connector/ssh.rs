//! SSH upstream direct-tcpip connector support.

use std::sync::Arc;

use anyhow::{Context, Result, bail};
use russh::client;
use russh::keys::{Algorithm, HashAlg, PrivateKeyWithHashAlg};

use super::upstream::{SshAuthenticationMethod, SshEndpoint};
use super::{BoxStream, Target};

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
/// * `endpoint` - SSH upstream endpoint and credentials.
/// * `target` - Final destination for the direct-tcpip channel.
///
/// # Returns
///
/// Returns a boxed SSH channel stream.
///
/// # Errors
///
/// Returns an error when SSH connection, authentication, key loading, or channel
/// opening fails.
pub(super) async fn ssh_connect(endpoint: &SshEndpoint, target: &Target) -> Result<BoxStream> {
    let config = Arc::new(client::Config {
        nodelay: true,
        ..Default::default()
    });
    let mut session = client::connect(
        config,
        (endpoint.target.host.as_str(), endpoint.target.port),
        SshHandler,
    )
    .await
    .context("could not establish SSH upstream session")?;
    let authenticated = match &endpoint.auth.method {
        SshAuthenticationMethod::Password(password) => session
            .authenticate_password(endpoint.auth.username.clone(), password.clone())
            .await?
            .success(),
        SshAuthenticationMethod::PrivateKey { path, passphrase } => {
            let key = Arc::new(
                russh::keys::load_secret_key(path, passphrase.as_deref()).with_context(|| {
                    format!("could not load SSH private key {}", path.display())
                })?,
            );
            authenticate_private_key(&mut session, endpoint.auth.username.clone(), key).await?
        }
    };
    if !authenticated {
        bail!("SSH upstream authentication failed")
    }
    let channel = session
        .channel_open_direct_tcpip(target.host.clone(), target.port.into(), "127.0.0.1", 0)
        .await
        .with_context(|| format!("SSH server could not forward to {}", target.authority()))?;
    Ok(Box::new(channel.into_stream()))
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
