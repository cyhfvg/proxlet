//! Directional AES-GCM cipher state for fakehttp frames.

use std::io;

use aes_gcm::aead::AeadInPlace;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce, Tag};
use anyhow::{Context as _, Result};
use sha2::{Digest, Sha256};

use crate::fakehttp::SALT_SIZE;

const NONCE_SIZE: usize = 12;

/// AES-GCM cipher state for one tunnel direction.
pub(super) struct CipherDirection {
    cipher: Aes256Gcm,
    base_nonce: [u8; NONCE_SIZE],
    counter: u64,
}

impl CipherDirection {
    /// Create cipher state for a direction label.
    ///
    /// # Parameters
    ///
    /// * `secret` - Shared AES secret.
    /// * `session` - Per-tunnel session token.
    /// * `direction` - Direction label used for nonce derivation.
    ///
    /// # Returns
    ///
    /// Returns initialized cipher state.
    ///
    /// # Errors
    ///
    /// Returns an error when AES-256-GCM cannot be initialized from the derived
    /// key.
    pub(super) fn new(secret: &str, session: &str, direction: &[u8]) -> Result<Self> {
        let salt = derive_salt(secret, session);
        let key = derive_key(secret, &salt);
        let base_nonce = derive_nonce(secret, session, &salt, direction);
        Ok(Self {
            cipher: Aes256Gcm::new_from_slice(&key)
                .context("could not initialize AES-256-GCM cipher")?,
            base_nonce,
            counter: 0,
        })
    }

    /// Encrypt plaintext in place and return its authentication tag.
    ///
    /// # Parameters
    ///
    /// * `self` - Directional cipher state.
    /// * `plaintext` - Mutable plaintext buffer to encrypt in place.
    ///
    /// # Returns
    ///
    /// Returns the AES-GCM authentication tag.
    ///
    /// # Errors
    ///
    /// Returns an I/O error when nonce generation or encryption fails.
    pub(super) fn encrypt_in_place(&mut self, plaintext: &mut [u8]) -> io::Result<Tag> {
        let nonce = self.next_nonce()?;
        self.cipher
            .encrypt_in_place_detached(Nonce::from_slice(&nonce), b"", plaintext)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "fakehttp encryption failed"))
    }

    /// Decrypt ciphertext in place and authenticate the tag.
    ///
    /// # Parameters
    ///
    /// * `self` - Directional cipher state.
    /// * `ciphertext` - Mutable ciphertext buffer to decrypt in place.
    /// * `tag` - AES-GCM authentication tag.
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` after successful decryption.
    ///
    /// # Errors
    ///
    /// Returns an I/O error when nonce generation fails or authentication fails.
    pub(super) fn decrypt_in_place(&mut self, ciphertext: &mut [u8], tag: &Tag) -> io::Result<()> {
        let nonce = self.next_nonce()?;
        self.cipher
            .decrypt_in_place_detached(Nonce::from_slice(&nonce), b"", ciphertext, tag)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "fakehttp decryption failed"))
    }

    /// Derive the next per-frame nonce.
    ///
    /// # Parameters
    ///
    /// * `self` - Directional cipher state.
    ///
    /// # Returns
    ///
    /// Returns a 96-bit AES-GCM nonce.
    ///
    /// # Errors
    ///
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

/// Derive a deterministic salt from the shared secret and session token.
///
/// # Parameters
///
/// * `secret` - Shared AES secret.
/// * `session` - Per-tunnel session token.
///
/// # Returns
///
/// Returns a 128-bit salt.
///
/// # Errors
///
/// This function does not return errors.
fn derive_salt(secret: &str, session: &str) -> [u8; SALT_SIZE] {
    let digest = Sha256::digest(
        [
            b"proxlet fakehttp salt\0".as_slice(),
            session.as_bytes(),
            secret.as_bytes(),
        ]
        .concat(),
    );
    let mut salt = [0_u8; SALT_SIZE];
    salt.copy_from_slice(&digest[..SALT_SIZE]);
    salt
}

/// Derive a 256-bit AES key from the shared secret and salt.
///
/// # Parameters
///
/// * `secret` - Shared AES secret.
/// * `salt` - Salt derived for the session.
///
/// # Returns
///
/// Returns a 256-bit AES-GCM key.
///
/// # Errors
///
/// This function does not return errors.
fn derive_key(secret: &str, salt: &[u8; SALT_SIZE]) -> [u8; 32] {
    let digest = Sha256::digest(
        [
            b"proxlet fakehttp key\0".as_slice(),
            salt,
            secret.as_bytes(),
        ]
        .concat(),
    );
    let mut key = [0_u8; 32];
    key.copy_from_slice(&digest);
    key
}

/// Derive the base nonce for one fakehttp traffic direction.
///
/// # Parameters
///
/// * `secret` - Shared AES secret.
/// * `session` - Per-tunnel session token.
/// * `salt` - Salt derived for the session.
/// * `direction` - Direction label.
///
/// # Returns
///
/// Returns a 96-bit base nonce.
///
/// # Errors
///
/// This function does not return errors.
fn derive_nonce(
    secret: &str,
    session: &str,
    salt: &[u8; SALT_SIZE],
    direction: &[u8],
) -> [u8; NONCE_SIZE] {
    let digest = Sha256::digest(
        [
            b"proxlet fakehttp nonce\0".as_slice(),
            salt,
            session.as_bytes(),
            direction,
            secret.as_bytes(),
        ]
        .concat(),
    );
    let mut nonce = [0_u8; NONCE_SIZE];
    nonce.copy_from_slice(&digest[..NONCE_SIZE]);
    nonce
}
