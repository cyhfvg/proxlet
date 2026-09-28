//! SSH upstream direct-tcpip connector support.

use std::net::Shutdown;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use russh::client;
use russh::keys::{Algorithm, HashAlg, PrivateKeyWithHashAlg};
use tokio::net::TcpStream;
use tokio::sync::Mutex;

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
/// Shared SSH session and private-key cache for one connector.
///
/// One connector has one SSH upstream. Channel opens share the authenticated
/// session. A dropped session is replaced on the next connect.
pub(super) struct SshSessions {
    pub(super) inner: Mutex<SshState>,
}

pub(super) struct SshState {
    handle: Option<client::Handle<SshHandler>>,
    key: Option<CachedPrivateKey>,
}

struct CachedPrivateKey {
    path: PathBuf,
    key: Arc<russh::keys::PrivateKey>,
}

impl SshSessions {
    /// Create an empty session cache.
    ///
    /// # Returns
    ///
    /// Returns a cache with no session and no loaded key.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let sessions = SshSessions::new();
    /// ```
    pub(super) fn new() -> Self {
        Self {
            inner: Mutex::new(SshState {
                handle: None,
                key: None,
            }),
        }
    }
}

/// Open an SSH direct-tcpip channel, reusing the authenticated session.
///
/// # Parameters
///
/// * `sessions` - Session and private-key cache shared by this connector.
/// * `endpoint` - SSH upstream endpoint and credentials.
/// * `target` - Final destination for the direct-tcpip channel.
/// * `timeout` - Deadline applied separately to dial, key exchange,
///   authentication, and channel open. It is not an idle timeout.
///
/// # Returns
///
/// Returns a stream for the opened channel.
///
/// # Errors
///
/// Returns an error when dialing, authentication, or channel open fails.
/// A dead cached session is dropped and replaced once. A target rejection
/// keeps the session.
///
/// # Examples
///
/// ```ignore
/// let stream = open_ssh_channel(&sessions, endpoint, target, timeout).await?;
/// ```
pub(super) async fn open_ssh_channel(
    sessions: &SshSessions,
    endpoint: &SshEndpoint,
    target: &Target,
    timeout: Duration,
) -> Result<BoxStream> {
    let mut state = sessions.inner.lock().await;
    if let Some(handle) = state.handle.as_ref().filter(|handle| !handle.is_closed()) {
        match open_direct_tcpip(handle, target, timeout).await {
            Ok(stream) => return Ok(stream),
            Err(error) if !session_lost(&error) => return Err(error),
            Err(_) => {}
        }
    }
    state.handle = None;

    let tcp = super::connect_tcp(&endpoint.target, timeout).await?;
    let handle = dial_authenticated(tcp, endpoint, &mut state, timeout).await?;
    let opened = open_direct_tcpip(&handle, target, timeout).await;
    if opened
        .as_ref()
        .err()
        .is_none_or(|error| !session_lost(error))
    {
        state.handle = Some(handle);
    }
    opened
}

fn session_lost(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        cause
            .downcast_ref::<russh::Error>()
            .is_some_and(|ssh_error| {
                matches!(
                    ssh_error,
                    russh::Error::Disconnect | russh::Error::SendError
                )
            })
    })
}

async fn dial_authenticated(
    tcp: TcpStream,
    endpoint: &SshEndpoint,
    state: &mut SshState,
    timeout: Duration,
) -> Result<client::Handle<SshHandler>> {
    // 不用 client::connect, 否则会再拨一次号, 而且没有按地址超时.
    let _ = tcp.set_nodelay(true);
    let (stream, watchdog) = split_watchdog(tcp)?;
    let result = authenticate(stream, endpoint, state, timeout).await;
    if result.is_err() {
        // connect_stream 在 kex 完成前就 spawn 了 session.run. drop 外层 timeout
        // 不会中止这个 task, kex 期间它也不看 handle 断开. 关掉这个克隆才能让残留
        // 读失败. 成功时只 drop 克隆, shutdown 会拆掉已建立隧道. 不要改用
        // inactivity_timeout, 那会给已建立会话加 idle-timeout.
        let _ = watchdog.shutdown(Shutdown::Both);
    }
    result
}

async fn authenticate<S>(
    stream: S,
    endpoint: &SshEndpoint,
    state: &mut SshState,
    timeout: Duration,
) -> Result<client::Handle<SshHandler>>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
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
            let key = cached_private_key(state, path, passphrase.as_deref()).await?;
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
    Ok(session)
}

pub(super) async fn cached_private_key(
    state: &mut SshState,
    path: &Path,
    passphrase: Option<&str>,
) -> Result<Arc<russh::keys::PrivateKey>> {
    if let Some(cached) = state.key.as_ref().filter(|cached| cached.path == path) {
        return Ok(cached.key.clone());
    }
    let owned_path = path.to_path_buf();
    let owned_passphrase = passphrase.map(str::to_owned);
    let loaded = tokio::task::spawn_blocking(move || {
        russh::keys::load_secret_key(&owned_path, owned_passphrase.as_deref())
    })
    .await
    .context("SSH private key loader task failed")?
    .with_context(|| format!("could not load SSH private key {}", path.display()))?;
    let key = Arc::new(loaded);
    state.key = Some(CachedPrivateKey {
        path: path.to_path_buf(),
        key: key.clone(),
    });
    Ok(key)
}

async fn open_direct_tcpip(
    session: &client::Handle<SshHandler>,
    target: &Target,
    timeout: Duration,
) -> Result<BoxStream> {
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

    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    use russh::server::{Auth, Handler, Server};
    use tokio::net::TcpListener;

    use super::super::upstream::{SshAuthentication, SshAuthenticationMethod, SshEndpoint};

    #[derive(Clone)]
    struct TestSshServer {
        accepts: Arc<AtomicUsize>,
        disconnect_once: Arc<AtomicBool>,
    }

    impl Server for TestSshServer {
        type Handler = Self;

        fn new_client(&mut self, _: Option<std::net::SocketAddr>) -> Self {
            self.accepts.fetch_add(1, Ordering::SeqCst);
            self.clone()
        }
    }

    impl Handler for TestSshServer {
        type Error = russh::Error;

        async fn auth_password(&mut self, _: &str, _: &str) -> Result<Auth, Self::Error> {
            Ok(Auth::Accept)
        }

        async fn auth_publickey(
            &mut self,
            _: &str,
            _: &russh::keys::ssh_key::PublicKey,
        ) -> Result<Auth, Self::Error> {
            Ok(Auth::Accept)
        }

        async fn channel_open_direct_tcpip(
            &mut self,
            _channel: russh::Channel<russh::server::Msg>,
            host_to_connect: &str,
            _port_to_connect: u32,
            _originator_address: &str,
            _originator_port: u32,
            _session: &mut russh::server::Session,
        ) -> Result<bool, Self::Error> {
            if host_to_connect == "reject.example" {
                return Ok(false);
            }
            if self.disconnect_once.swap(false, Ordering::SeqCst) {
                return Err(russh::Error::Disconnect);
            }
            Ok(true)
        }
    }

    fn test_host_key() -> russh::keys::PrivateKey {
        let keypair = russh::keys::ssh_key::private::Ed25519Keypair::from_seed(&[7; 32]);
        russh::keys::PrivateKey::new(
            russh::keys::ssh_key::private::KeypairData::Ed25519(keypair),
            "proxlet-test",
        )
        .expect("test host key")
    }

    struct RunningSsh {
        port: u16,
        accepts: Arc<AtomicUsize>,
        disconnect_once: Arc<AtomicBool>,
    }

    async fn start_ssh_server() -> RunningSsh {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind ssh");
        let port = listener.local_addr().expect("local addr").port();
        let accepts = Arc::new(AtomicUsize::new(0));
        let disconnect_once = Arc::new(AtomicBool::new(false));
        let mut server = TestSshServer {
            accepts: accepts.clone(),
            disconnect_once: disconnect_once.clone(),
        };
        let config = Arc::new(russh::server::Config {
            keys: vec![test_host_key()],
            auth_rejection_time: Duration::ZERO,
            auth_rejection_time_initial: Some(Duration::ZERO),
            ..Default::default()
        });
        tokio::spawn(async move {
            let _ = server.run_on_socket(config, &listener).await;
        });
        RunningSsh {
            port,
            accepts,
            disconnect_once,
        }
    }

    fn endpoint(port: u16, method: SshAuthenticationMethod) -> SshEndpoint {
        SshEndpoint {
            target: Target {
                host: "127.0.0.1".into(),
                port,
            },
            auth: SshAuthentication {
                username: "user".into(),
                method,
            },
        }
    }

    fn destination(host: &str, port: u16) -> Target {
        Target {
            host: host.into(),
            port,
        }
    }

    #[tokio::test]
    async fn reuses_one_ssh_session_until_the_server_drops_it() {
        let server = start_ssh_server().await;
        let sessions = SshSessions::new();
        let endpoint = endpoint(
            server.port,
            SshAuthenticationMethod::Password("password".into()),
        );
        let timeout = Duration::from_secs(5);

        open_ssh_channel(
            &sessions,
            &endpoint,
            &destination("one.example", 80),
            timeout,
        )
        .await
        .expect("first channel");
        open_ssh_channel(
            &sessions,
            &endpoint,
            &destination("two.example", 443),
            timeout,
        )
        .await
        .expect("second channel");
        let rejected = open_ssh_channel(
            &sessions,
            &endpoint,
            &destination("reject.example", 9),
            timeout,
        )
        .await;
        assert!(rejected.is_err(), "rejected target must fail");
        open_ssh_channel(
            &sessions,
            &endpoint,
            &destination("three.example", 22),
            timeout,
        )
        .await
        .expect("session survives target rejection");
        assert_eq!(server.accepts.load(Ordering::SeqCst), 1);

        server.disconnect_once.store(true, Ordering::SeqCst);
        open_ssh_channel(
            &sessions,
            &endpoint,
            &destination("four.example", 22),
            timeout,
        )
        .await
        .expect("reconnect after disconnect");
        assert_eq!(server.accepts.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn loads_ssh_private_key_once() {
        let server = start_ssh_server().await;
        let key = test_host_key();
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("id_ed25519");
        key.write_openssh_file(&path, russh::keys::ssh_key::LineEnding::LF)
            .expect("write key");
        let sessions = SshSessions::new();
        let endpoint = endpoint(
            server.port,
            SshAuthenticationMethod::PrivateKey {
                path: path.clone(),
                passphrase: None,
            },
        );
        let timeout = Duration::from_secs(5);
        open_ssh_channel(
            &sessions,
            &endpoint,
            &destination("one.example", 80),
            timeout,
        )
        .await
        .expect("key auth");
        std::fs::remove_file(&path).expect("remove key");
        open_ssh_channel(
            &sessions,
            &endpoint,
            &destination("two.example", 443),
            timeout,
        )
        .await
        .expect("cached key");
        assert_eq!(server.accepts.load(Ordering::SeqCst), 1);
    }
}
