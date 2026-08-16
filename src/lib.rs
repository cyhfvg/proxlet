//! proxlet library crate.
//!
//! The crate exposes CLI parsing, listener protocols, upstream connection
//! management, daemon spawning, and the top-level server runner used by the
//! binary.

/// Web-looking replies that hide nmap HTTP-proxy fingerprints.
pub mod camouflage;
/// Command-line parsing and runtime configuration.
pub mod cli;

/// Upstream connection management and bidirectional relay helpers.
pub mod connector;
/// Background process launching support.
pub mod daemon;
/// fakehttp proxlet-to-proxlet transport.
pub mod fakehttp;
/// HTTP forward proxy listener.
pub mod http;
/// Server runtime and protocol dispatch.
pub mod server;
/// SOCKS5 listener.
pub mod socks;

pub use cli::{Cli, ProxyType};
pub use server::run;
