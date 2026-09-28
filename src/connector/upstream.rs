//! Upstream URL parsing and TLS root loading for connector setup.

use std::fs::File;
use std::io::{self, BufReader};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use percent_encoding::percent_decode_str;
use tokio_rustls::rustls::RootCertStore;
use url::Url;

use super::Target;

#[derive(Clone, Debug)]
/// Username/password pair decoded from an upstream URL.
pub(super) struct Credentials {
    pub(super) username: String,
    pub(super) password: String,
}

#[derive(Clone, Debug)]
/// Upstream proxy endpoint plus optional credentials.
pub(super) struct Endpoint {
    pub(super) target: Target,
    pub(super) credentials: Option<Credentials>,
}

#[derive(Clone, Debug)]
/// SSH upstream endpoint plus its authentication configuration.
pub(super) struct SshEndpoint {
    pub(super) target: Target,
    pub(super) auth: SshAuthentication,
}

#[derive(Clone, Debug)]
/// SSH username and authentication method.
pub(super) struct SshAuthentication {
    pub(super) username: String,
    pub(super) method: SshAuthenticationMethod,
}

#[derive(Clone, Debug)]
/// Authentication methods supported for SSH upstream proxying.
pub(super) enum SshAuthenticationMethod {
    /// Password authentication.
    Password(String),
    /// Public-key authentication with optional key passphrase.
    PrivateKey {
        path: PathBuf,
        passphrase: Option<String>,
    },
}

#[derive(Clone, Debug)]
/// Parsed upstream proxy configuration.
pub(super) enum Upstream {
    /// Plain HTTP CONNECT upstream proxy.
    Http(Endpoint),
    /// HTTPS CONNECT upstream proxy.
    Https(Endpoint),
    /// SOCKS5 upstream proxy.
    Socks5 {
        endpoint: Endpoint,
        remote_dns: bool,
    },
    /// fakehttp proxlet-to-proxlet upstream.
    FakeHttp {
        endpoint: Endpoint,
        aes_secret: Option<String>,
    },
    /// SSH direct-tcpip upstream proxy.
    Ssh(SshEndpoint),
}

/// Add PEM CA certificates to a rustls root store.
///
/// # Parameters
///
/// * `roots` - Root certificate store to extend.
/// * `path` - PEM file containing one or more CA certificates.
///
/// # Returns
///
/// Returns `Ok(())` after all certificates are added.
///
/// # Errors
///
/// Returns an error when the file cannot be opened, contains no certificates,
/// contains invalid PEM, or a certificate cannot be accepted by rustls.
pub(super) fn add_ca_certificates(roots: &mut RootCertStore, path: &Path) -> Result<()> {
    let mut reader = BufReader::new(
        File::open(path)
            .with_context(|| format!("could not open upstream proxy CA {}", path.display()))?,
    );
    let certs = rustls_pemfile::certs(&mut reader).collect::<io::Result<Vec<_>>>()?;
    if certs.is_empty() {
        bail!(
            "upstream proxy CA file contains no certificates: {}",
            path.display()
        )
    }
    for certificate in certs {
        roots.add(certificate).with_context(|| {
            format!(
                "invalid certificate in upstream proxy CA file {}",
                path.display()
            )
        })?;
    }
    Ok(())
}

/// Parse an upstream proxy URL into an internal upstream configuration.
///
/// # Parameters
///
/// * `url` - User-provided upstream proxy URL.
///
/// # Returns
///
/// Returns a parsed [`Upstream`] variant.
///
/// # Errors
///
/// Returns an error when the URL is missing host or port information, uses an
/// unsupported scheme, has malformed credentials, or has invalid SSH options.
pub(super) fn parse_upstream(url: Url) -> Result<Upstream> {
    let target = Target::new(
        url.host_str()
            .ok_or_else(|| anyhow::anyhow!("upstream proxy URL has no host"))?,
        upstream_port(&url)?,
    );
    let endpoint = Endpoint {
        target: target.clone(),
        credentials: credentials(&url, url.scheme() == "fakehttp")?,
    };
    match url.scheme() {
        "http" => Ok(Upstream::Http(endpoint)),
        "https" => Ok(Upstream::Https(endpoint)),
        "socks5" => Ok(Upstream::Socks5 {
            endpoint,
            remote_dns: false,
        }),
        "socks5h" => Ok(Upstream::Socks5 {
            endpoint,
            remote_dns: true,
        }),
        "fakehttp" => Ok(Upstream::FakeHttp {
            endpoint,
            aes_secret: fakehttp_secret(&url)?,
        }),
        "ssh" => Ok(Upstream::Ssh(parse_ssh_upstream(target, &url)?)),
        schema => bail!("unsupported upstream proxy scheme: {schema}"),
    }
}

/// Resolve an upstream port, including scheme defaults.
///
/// # Parameters
///
/// * `url` - Upstream proxy URL.
///
/// # Returns
///
/// Returns an explicit port, or 80, 443, 22, and 1080 for `http`, `https`,
/// `ssh`, and `socks5`/`socks5h`.
///
/// # Errors
///
/// Returns an error when the scheme has no default and the URL omits the port.
///
/// # Examples
///
/// ```text
/// ssh://user@example.com -> 22
/// socks5://127.0.0.1 -> 1080
/// fakehttp://secret@example.com -> error
/// ```
fn upstream_port(url: &Url) -> Result<u16> {
    if let Some(port) = url.port() {
        return Ok(port);
    }
    match url.scheme() {
        "http" => Ok(80),
        "https" => Ok(443),
        "ssh" => Ok(22),
        "socks5" | "socks5h" => Ok(1080),
        scheme => bail!("upstream proxy URL has no port for scheme {scheme}"),
    }
}

/// Decode username/password credentials from a URL.
///
/// # Parameters
///
/// * `url` - Upstream URL containing optional userinfo.
/// * `allow_password_without_username` - When true, a password with an empty
///   username is treated as absent credentials. fakehttp uses that form for
///   its secret.
///
/// # Returns
///
/// Returns decoded credentials, or `None` when no username was supplied.
/// `username()` and `password()` are still percent-encoded, so this decodes
/// them once.
///
/// # Errors
///
/// Returns an error when a non-fakehttp URL has a password without a username,
/// or when percent-decoding or UTF-8 decoding fails.
///
/// # Examples
///
/// ```text
/// http://user:a%2Bb@127.0.0.1:8080 -> password a+b
/// http://:secret@127.0.0.1:8080 -> error
/// ```
fn credentials(url: &Url, allow_password_without_username: bool) -> Result<Option<Credentials>> {
    let username = url.username();
    let password = url.password();
    if username.is_empty() {
        if password.is_some() && !allow_password_without_username {
            bail!("upstream proxy URL has a password but no username");
        }
        return Ok(None);
    }
    Ok(Some(Credentials {
        username: decode_url_component(username)?,
        password: decode_url_component(password.unwrap_or_default())?,
    }))
}

/// Parse SSH-specific upstream authentication settings.
///
/// # Parameters
///
/// * `target` - SSH server endpoint.
/// * `url` - SSH upstream URL.
///
/// # Returns
///
/// Returns an [`SshEndpoint`] with a selected authentication method.
///
/// # Errors
///
/// Returns an error when required username/password/key data is missing or
/// malformed.
fn parse_ssh_upstream(target: Target, url: &Url) -> Result<SshEndpoint> {
    let credentials = credentials(url, false)?;
    let identity = ssh_identity_path(url)?;
    let auth = match (credentials, identity) {
        (Some(credentials), Some(path)) => SshAuthentication {
            username: credentials.username,
            method: SshAuthenticationMethod::PrivateKey {
                path,
                passphrase: non_empty(credentials.password),
            },
        },
        (Some(credentials), None) if !credentials.password.is_empty() => SshAuthentication {
            username: credentials.username,
            method: SshAuthenticationMethod::Password(credentials.password),
        },
        (Some(_), None) => bail!("ssh password authentication requires a password"),
        (None, Some(_)) => bail!("ssh private-key authentication requires a username"),
        (None, None) => bail!("ssh upstream URL requires username and password or ?key=<file>"),
    };
    Ok(SshEndpoint { target, auth })
}

/// Extract an SSH identity file path from URL query parameters.
///
/// # Parameters
///
/// * `url` - SSH upstream URL.
///
/// # Returns
///
/// Returns an optional private key path. The query is percent-decoded once.
/// A literal `+` is preserved; a space must be written as `%20`.
///
/// # Errors
///
/// Returns an error when a recognized key parameter is present but empty, or
/// when percent-decoding fails.
///
/// # Examples
///
/// ```text
/// ssh://user@host?key=/tmp/my+key -> /tmp/my+key
/// ssh://user@host?key=/tmp/my%20key -> /tmp/my key
/// ```
fn ssh_identity_path(url: &Url) -> Result<Option<PathBuf>> {
    let Some(query) = url.query() else {
        return Ok(None);
    };
    for pair in query.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
        if matches!(
            decode_url_component(name)?.as_str(),
            "key" | "identity" | "identity_file"
        ) {
            let value = decode_url_component(value)?;
            if value.is_empty() {
                bail!("ssh private key path is empty");
            }
            return Ok(Some(PathBuf::from(value)));
        }
    }
    Ok(None)
}

/// Convert an empty string into `None`.
///
/// # Parameters
///
/// * `value` - Owned string to inspect.
///
/// # Returns
///
/// Returns `Some(value)` when non-empty, otherwise `None`.
///
/// # Errors
///
/// This function does not return errors.
fn non_empty(value: String) -> Option<String> {
    if value.is_empty() { None } else { Some(value) }
}

/// Percent-decode a URL component into UTF-8 text.
///
/// # Parameters
///
/// * `value` - Percent-encoded URL component.
///
/// # Returns
///
/// Returns a decoded string.
///
/// # Errors
///
/// Returns an error when the decoded bytes are not valid UTF-8.
fn decode_url_component(value: &str) -> Result<String> {
    Ok(percent_decode_str(value).decode_utf8()?.into_owned())
}

/// Extract the fakehttp AES secret from an upstream URL.
///
/// # Parameters
///
/// * `url` - fakehttp upstream URL.
///
/// # Returns
///
/// Returns the decoded secret from password or username userinfo, or `None`.
///
/// # Errors
///
/// Returns an error when secret percent-decoding fails.
fn fakehttp_secret(url: &Url) -> Result<Option<String>> {
    let username = url.username();
    let password = url.password();
    match (username.is_empty(), password) {
        (_, Some(password)) => Ok(Some(decode_url_component(password)?)),
        (false, None) => Ok(Some(decode_url_component(username)?)),
        (true, None) => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_ssh_upstream_url() {
        let url = Url::parse("ssh://user:password@localhost:22").expect("URL");
        assert!(matches!(parse_upstream(url), Ok(Upstream::Ssh(_))));
    }

    #[test]
    fn accepts_fakehttp_upstream_url_with_aes_secret() {
        let url = Url::parse("fakehttp://secret@localhost:8080").expect("URL");
        let upstream = parse_upstream(url).expect("upstream");

        match upstream {
            Upstream::FakeHttp { aes_secret, .. } => {
                assert_eq!(aes_secret.as_deref(), Some("secret"));
            }
            _ => panic!("expected fakehttp upstream"),
        }
    }

    #[test]
    fn accepts_ssh_upstream_private_key_url() {
        let url =
            Url::parse("ssh://user@localhost:22?key=/home/user/.ssh/id_ed25519").expect("URL");
        let upstream = parse_upstream(url).expect("upstream");

        match upstream {
            Upstream::Ssh(endpoint) => {
                assert_eq!(endpoint.auth.username, "user");
                assert!(matches!(
                    endpoint.auth.method,
                    SshAuthenticationMethod::PrivateKey { .. }
                ));
            }
            _ => panic!("expected SSH upstream"),
        }
    }

    #[test]
    fn ssh_key_query_keeps_plus_and_defaults_port() {
        let url = Url::parse("ssh://user@localhost?key=/tmp/my+key").expect("URL");
        let upstream = parse_upstream(url).expect("upstream");
        match upstream {
            Upstream::Ssh(endpoint) => {
                assert_eq!(endpoint.target.port, 22);
                match endpoint.auth.method {
                    SshAuthenticationMethod::PrivateKey { path, passphrase } => {
                        assert_eq!(path, PathBuf::from("/tmp/my+key"));
                        assert!(passphrase.is_none());
                    }
                    _ => panic!("expected private key"),
                }
            }
            _ => panic!("expected SSH upstream"),
        }
    }

    #[test]
    fn socks_urls_default_to_port_1080() {
        let socks5 =
            parse_upstream(Url::parse("socks5://127.0.0.1").expect("URL")).expect("socks5");
        let socks5h =
            parse_upstream(Url::parse("socks5h://127.0.0.1").expect("URL")).expect("socks5h");
        match (socks5, socks5h) {
            (
                Upstream::Socks5 {
                    endpoint,
                    remote_dns,
                },
                Upstream::Socks5 {
                    endpoint: endpoint_h,
                    remote_dns: remote_h,
                },
            ) => {
                assert_eq!(endpoint.target.port, 1080);
                assert!(!remote_dns);
                assert_eq!(endpoint_h.target.port, 1080);
                assert!(remote_h);
            }
            _ => panic!("expected SOCKS upstreams"),
        }
    }

    #[test]
    fn password_without_username_is_rejected_except_fakehttp_secret() {
        let error = parse_upstream(Url::parse("http://:secret@127.0.0.1:8080").expect("URL"))
            .expect_err("password without username");
        assert!(error.to_string().contains("password but no username"));

        let upstream =
            parse_upstream(Url::parse("fakehttp://:secret@127.0.0.1:8080").expect("URL"))
                .expect("fakehttp secret");
        match upstream {
            Upstream::FakeHttp {
                aes_secret,
                endpoint,
            } => {
                assert_eq!(aes_secret.as_deref(), Some("secret"));
                assert!(endpoint.credentials.is_none());
            }
            _ => panic!("expected fakehttp upstream"),
        }
    }

    #[test]
    fn userinfo_is_percent_decoded_once() {
        let encoded = parse_upstream(Url::parse("http://user:a%252Bb@127.0.0.1:9").expect("URL"))
            .expect("encoded");
        let decoded = parse_upstream(Url::parse("http://user:a%2Bb@127.0.0.1:9").expect("URL"))
            .expect("decoded");
        match (encoded, decoded) {
            (Upstream::Http(encoded), Upstream::Http(decoded)) => {
                assert_eq!(encoded.credentials.expect("credentials").password, "a%2Bb");
                assert_eq!(decoded.credentials.expect("credentials").password, "a+b");
            }
            _ => panic!("expected HTTP upstreams"),
        }
    }
}
