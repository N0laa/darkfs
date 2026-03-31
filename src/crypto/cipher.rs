//! XChaCha20-Poly1305 block encryption and decryption.
//!
//! Each block on disk is 4096 bytes laid out as:
//! `[24-byte random nonce | ciphertext | 16-byte Poly1305 auth tag]`
//!
//! A fresh random nonce is generated on every write, eliminating nonce reuse
//! even when the same file path is overwritten with the same passphrase.

use chacha20poly1305::aead::Aead;
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use rand::RngCore;
use zeroize::Zeroize;

use crate::util::constants::{BLOCK_SIZE, NONCE_SIZE, PAYLOAD_SIZE};
use crate::util::errors::DarkError;

/// Encrypt a plaintext payload into a full disk block.
///
/// Generates a fresh random 24-byte nonce and prepends it to the block.
/// Input: 4056-byte plaintext. Output: 4096-byte block `[nonce | ciphertext | tag]`.
pub fn encrypt_block(
    key: &[u8; 32],
    plaintext: &[u8; PAYLOAD_SIZE],
) -> Result<[u8; BLOCK_SIZE], DarkError> {
    let mut nonce_bytes = [0u8; NONCE_SIZE];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let xnonce = XNonce::from_slice(&nonce_bytes);

    let cipher = XChaCha20Poly1305::new(key.into());
    let ciphertext = cipher
        .encrypt(xnonce, plaintext.as_ref())
        .map_err(|_| DarkError::Encrypt)?;

    let mut block = [0u8; BLOCK_SIZE];
    block[..NONCE_SIZE].copy_from_slice(&nonce_bytes);
    block[NONCE_SIZE..].copy_from_slice(&ciphertext);
    Ok(block)
}

/// Decrypt a disk block back into a plaintext payload.
///
/// Extracts the 24-byte nonce from the block prefix, then decrypts.
/// Input: 4096-byte block. Output: 4056-byte plaintext.
/// Returns [`DarkError::Decrypt`] if authentication fails (wrong key, tampered data).
pub fn decrypt_block(
    key: &[u8; 32],
    block: &[u8; BLOCK_SIZE],
) -> Result<[u8; PAYLOAD_SIZE], DarkError> {
    let nonce_bytes: [u8; NONCE_SIZE] = block[..NONCE_SIZE]
        .try_into()
        .expect("slice is NONCE_SIZE");
    let xnonce = XNonce::from_slice(&nonce_bytes);

    let cipher = XChaCha20Poly1305::new(key.into());
    let mut plaintext = cipher
        .decrypt(xnonce, &block[NONCE_SIZE..])
        .map_err(|_| DarkError::Decrypt)?;

    let mut payload = [0u8; PAYLOAD_SIZE];
    payload.copy_from_slice(&plaintext);
    plaintext.zeroize(); // wipe intermediate heap buffer
    Ok(payload)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::RngCore;

    fn random_payload() -> [u8; PAYLOAD_SIZE] {
        let mut buf = [0u8; PAYLOAD_SIZE];
        rand::thread_rng().fill_bytes(&mut buf);
        buf
    }

    #[test]
    fn roundtrip() {
        let key = [42u8; 32];
        let plaintext = random_payload();

        let encrypted = encrypt_block(&key, &plaintext).unwrap();
        assert_eq!(encrypted.len(), BLOCK_SIZE);
        // Ciphertext portion (after nonce) should differ from plaintext
        assert_ne!(&encrypted[NONCE_SIZE..NONCE_SIZE + PAYLOAD_SIZE], &plaintext[..]);

        let decrypted = decrypt_block(&key, &encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn wrong_key_fails() {
        let key = [42u8; 32];
        let plaintext = random_payload();

        let encrypted = encrypt_block(&key, &plaintext).unwrap();

        let wrong_key = [99u8; 32];
        let result = decrypt_block(&wrong_key, &encrypted);
        assert!(matches!(result, Err(DarkError::Decrypt)));
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let key = [42u8; 32];
        let plaintext = random_payload();

        let mut encrypted = encrypt_block(&key, &plaintext).unwrap();
        encrypted[NONCE_SIZE] ^= 0xFF; // flip a byte in the ciphertext

        let result = decrypt_block(&key, &encrypted);
        assert!(matches!(result, Err(DarkError::Decrypt)));
    }

    #[test]
    fn random_data_fails_decrypt() {
        let key = [42u8; 32];
        let mut random_block = [0u8; BLOCK_SIZE];
        rand::thread_rng().fill_bytes(&mut random_block);

        let result = decrypt_block(&key, &random_block);
        assert!(matches!(result, Err(DarkError::Decrypt)));
    }

    #[test]
    fn different_nonce_each_write() {
        let key = [42u8; 32];
        let plaintext = random_payload();

        let block1 = encrypt_block(&key, &plaintext).unwrap();
        let block2 = encrypt_block(&key, &plaintext).unwrap();

        // Same plaintext, same key — but nonces (and thus ciphertext) must differ
        assert_ne!(block1[..NONCE_SIZE], block2[..NONCE_SIZE]);
        assert_ne!(block1, block2);

        // Both should decrypt to the same plaintext
        assert_eq!(decrypt_block(&key, &block1).unwrap(), plaintext);
        assert_eq!(decrypt_block(&key, &block2).unwrap(), plaintext);
    }
}
