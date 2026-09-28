//! Directional AES-GCM cipher state for fakehttp frames.
//!
//! v2 handshake derivation: the client picks a random 16-byte nonce, the
//! server answers with a random 16-byte salt, and every cipher key/nonce is
//! derived from `(secret, client_nonce, server_salt, direction, purpose)`.
//! The handshake frame uses a client-nonce-only cipher so the client can
//! transmit the encrypted target before the server salt exists.

use std::io;

use aes_gcm::aead::AeadInPlace;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce, Tag};
use anyhow::{Context as _, Result};
use sha2::{Digest, Sha256};

use crate::fakehttp::SALT_SIZE;

const NONCE_SIZE: usize = 12;
const KEY_SIZE: usize = 32;
const LABEL_HANDSHAKE: &[u8] = b"proxlet fakehttp v2 handshake\0";
const LABEL_TRAFFIC: &[u8] = b"proxlet fakehttp v2 traffic\0";
const LABEL_KEY: &[u8] = b"\0key";
const LABEL_NONCE: &[u8] = b"\0nonce";

/// AES-GCM cipher state for one tunnel direction.
pub(super) struct CipherDirection {
    cipher: Aes256Gcm,
    base_nonce: [u8; NONCE_SIZE],
    counter: u64,
}

impl CipherDirection {
    /// Create cipher state used for the encrypted hello frame.
    ///
    /// # Parameters
    ///
    /// * `secret` - Shared AES secret.
    /// * `client_nonce` - Random nonce chosen by the downstream client.
    ///
    /// # Returns
    ///
    /// Returns initialized handshake cipher state.
    ///
    /// # Errors
    ///
    /// Returns an error when AES-256-GCM cannot be initialized from the derived
    /// key.
    pub(super) fn handshake(secret: &str, client_nonce: &[u8; SALT_SIZE]) -> Result<Self> {
        Self::new(secret, &[LABEL_HANDSHAKE, client_nonce])
    }

    /// Create cipher state for one post-handshake traffic direction.
    ///
    /// # Parameters
    ///
    /// * `secret` - Shared AES secret.
    /// * `client_nonce` - Random nonce chosen by the downstream client.
    /// * `server_salt` - Random salt chosen by the upstream server.
    /// * `direction` - Direction label, `client-to-server` or
    ///   `server-to-client`.
    ///
    /// # Returns
    ///
    /// Returns initialized traffic cipher state.
    ///
    /// # Errors
    ///
    /// Returns an error when AES-256-GCM cannot be initialized from the derived
    /// key.
    pub(super) fn traffic(
        secret: &str,
        client_nonce: &[u8; SALT_SIZE],
        server_salt: &[u8; SALT_SIZE],
        direction: &[u8],
    ) -> Result<Self> {
        Self::new(
            secret,
            &[LABEL_TRAFFIC, client_nonce, server_salt, direction],
        )
    }

    /// Derive cipher state from a shared secret and derivation parts.
    ///
    /// # Parameters
    ///
    /// * `secret` - Shared AES secret.
    /// * `parts` - Ordered derivation inputs identifying the cipher purpose.
    ///
    /// # Returns
    /// Returns initialized cipher state.
    ///
    /// # Errors
    /// Returns an error when AES-256-GCM cannot be initialized from the derived
    /// key.
    fn new(secret: &str, parts: &[&[u8]]) -> Result<Self> {
        let key = derive_key(secret, parts);
        let base_nonce = derive_nonce(secret, parts);
        Ok(Self {
            cipher: Aes256Gcm::new_from_slice(&key)
                .context("could not initialize AES-256-GCM cipher")?,
            base_nonce,
            counter: 0,
        })
    }

    /// Encrypt plaintext in place with additional authenticated data.
    ///
    /// # Parameters
    ///
    /// * `self` - Directional cipher state.
    /// * `plaintext` - Mutable plaintext buffer to encrypt in place.
    /// * `aad` - Additional authenticated data bound to this frame.
    ///
    /// # Returns
    /// Returns the AES-GCM authentication tag.
    ///
    /// # Errors
    /// Returns an I/O error when nonce generation or encryption fails.
    pub(super) fn encrypt_in_place(&mut self, plaintext: &mut [u8], aad: &[u8]) -> io::Result<Tag> {
        let nonce = self.next_nonce()?;
        self.cipher
            .encrypt_in_place_detached(Nonce::from_slice(&nonce), aad, plaintext)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "fakehttp encryption failed"))
    }

    /// Decrypt ciphertext in place and authenticate the tag.
    ///
    /// # Parameters
    ///
    /// * `self` - Directional cipher state.
    /// * `ciphertext` - Mutable ciphertext buffer to decrypt in place.
    /// * `tag` - AES-GCM authentication tag.
    /// * `aad` - Additional authenticated data bound to this frame.
    ///
    /// # Returns
    /// Returns `Ok(())` after successful decryption.
    ///
    /// # Errors
    /// Returns an I/O error when nonce generation fails or authentication fails.
    pub(super) fn decrypt_in_place(
        &mut self,
        ciphertext: &mut [u8],
        tag: &Tag,
        aad: &[u8],
    ) -> io::Result<()> {
        let nonce = self.next_nonce()?;
        self.cipher
            .decrypt_in_place_detached(Nonce::from_slice(&nonce), aad, ciphertext, tag)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "fakehttp decryption failed"))
    }

    /// Derive the next per-frame nonce.
    ///
    /// # Parameters
    ///
    /// * `self` - Directional cipher state.
    ///
    /// # Returns
    /// Returns a 96-bit AES-GCM nonce.
    ///
    /// # Errors
    /// Returns an I/O error if the frame counter overflows.
    fn next_nonce(&mut self) -> io::Result<[u8; NONCE_SIZE]> {
        let counter = self.counter;
        self.counter = self.counter.checked_add(1).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "fakehttp frame counter overflowed",
            )
        })?;
        let mut nonce = self.base_nonce;
        for (nonce_byte, counter_byte) in nonce[4..].iter_mut().zip(counter.to_be_bytes()) {
            *nonce_byte ^= counter_byte;
        }
        Ok(nonce)
    }
}

/// Derive a 256-bit AES key from the secret and derivation parts.
///
/// # Parameters
///
/// * `secret` - Shared AES secret.
/// * `parts` - Ordered derivation inputs identifying the cipher purpose.
///
/// # Returns
/// Returns a 256-bit AES-GCM key.
///
/// # Errors
/// This function does not return errors.
fn derive_key(secret: &str, parts: &[&[u8]]) -> [u8; KEY_SIZE] {
    let digest = derive_digest(secret, parts, LABEL_KEY);
    let mut key = [0_u8; KEY_SIZE];
    key.copy_from_slice(&digest);
    key
}

/// Derive the 96-bit base nonce from the secret and derivation parts.
///
/// # Parameters
///
/// * `secret` - Shared AES secret.
/// * `parts` - Ordered derivation inputs identifying the cipher purpose.
///
/// # Returns
/// Returns a 96-bit base nonce.
///
/// # Errors
/// This function does not return errors.
fn derive_nonce(secret: &str, parts: &[&[u8]]) -> [u8; NONCE_SIZE] {
    let digest = derive_digest(secret, parts, LABEL_NONCE);
    let mut nonce = [0_u8; NONCE_SIZE];
    nonce.copy_from_slice(&digest[..NONCE_SIZE]);
    nonce
}

/// Hash derivation parts, a purpose suffix, and the secret together.
///
/// # Parameters
///
/// * `secret` - Shared AES secret.
/// * `parts` - Ordered derivation inputs.
/// * `suffix` - Purpose label separating key and nonce derivation.
///
/// # Returns
/// Returns the SHA-256 digest of the concatenated inputs.
///
/// # Errors
/// This function does not return errors.
fn derive_digest(secret: &str, parts: &[&[u8]], suffix: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part);
    }
    hasher.update(suffix);
    hasher.update(secret.as_bytes());
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn traffic_ciphers_differ_per_direction() {
        let secret = "secret";
        let nonce = [7_u8; SALT_SIZE];
        let salt = [9_u8; SALT_SIZE];

        let client_to_server =
            CipherDirection::traffic(secret, &nonce, &salt, b"client-to-server").expect("c2s");
        let server_to_client =
            CipherDirection::traffic(secret, &nonce, &salt, b"server-to-client").expect("s2c");

        assert_ne!(client_to_server.base_nonce, server_to_client.base_nonce);
    }

    #[test]
    fn handshake_cipher_differs_from_traffic_cipher() {
        let secret = "secret";
        let nonce = [7_u8; SALT_SIZE];
        let salt = [9_u8; SALT_SIZE];

        let handshake = CipherDirection::handshake(secret, &nonce).expect("handshake");
        let traffic =
            CipherDirection::traffic(secret, &nonce, &salt, b"client-to-server").expect("c2s");

        assert_ne!(handshake.base_nonce, traffic.base_nonce);
    }

    #[test]
    fn decrypt_rejects_mismatched_aad() {
        let secret = "secret";
        let nonce = [3_u8; SALT_SIZE];
        let mut cipher = CipherDirection::handshake(secret, &nonce).expect("handshake");
        let mut plaintext = b"target".to_vec();
        let tag = cipher
            .encrypt_in_place(&mut plaintext, b"aad-1")
            .expect("seal");

        let mut opener = CipherDirection::handshake(secret, &nonce).expect("handshake");
        assert!(
            opener
                .decrypt_in_place(&mut plaintext, &tag, b"aad-2")
                .is_err()
        );
    }
}
