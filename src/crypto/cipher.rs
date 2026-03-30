//! XChaCha20-Poly1305 block encryption and decryption.
//!
//! Each 4080-byte plaintext payload is encrypted into a 4096-byte block
//! (4080 bytes ciphertext + 16 bytes Poly1305 authentication tag).

use chacha20poly1305::aead::Aead;
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use zeroize::Zeroize;

use crate::util::constants::{BLOCK_SIZE, NONCE_SIZE, PAYLOAD_SIZE};
use crate::util::errors::VoidError;

/// Encrypt a plaintext payload into a full disk block.
///
/// Input: 4080-byte plaintext. Output: 4096-byte block (ciphertext + auth tag).
pub fn encrypt_block(
    key: &[u8; 32],
    nonce: &[u8; NONCE_SIZE],
    plaintext: &[u8; PAYLOAD_SIZE],
) -> Result<[u8; BLOCK_SIZE], VoidError> {
    let cipher = XChaCha20Poly1305::new(key.into());
    let xnonce = XNonce::from_slice(nonce);

    let ciphertext = cipher
        .encrypt(xnonce, plaintext.as_ref())
        .map_err(|_| VoidError::Encrypt)?;

    let mut block = [0u8; BLOCK_SIZE];
    block.copy_from_slice(&ciphertext);
    Ok(block)
}

/// Decrypt a disk block back into a plaintext payload.
///
/// Input: 4096-byte block. Output: 4080-byte plaintext.
/// Returns [`VoidError::Decrypt`] if authentication fails (wrong key, tampered data).
pub fn decrypt_block(
    key: &[u8; 32],
    nonce: &[u8; NONCE_SIZE],
    ciphertext: &[u8; BLOCK_SIZE],
) -> Result<[u8; PAYLOAD_SIZE], VoidError> {
    let cipher = XChaCha20Poly1305::new(key.into());
    let xnonce = XNonce::from_slice(nonce);

    let mut plaintext = cipher
        .decrypt(xnonce, ciphertext.as_ref())
        .map_err(|_| VoidError::Decrypt)?;

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
        let nonce = [7u8; NONCE_SIZE];
        let plaintext = random_payload();

        let encrypted = encrypt_block(&key, &nonce, &plaintext).unwrap();
        assert_eq!(encrypted.len(), BLOCK_SIZE);
        assert_ne!(&encrypted[..PAYLOAD_SIZE], &plaintext[..]);

        let decrypted = decrypt_block(&key, &nonce, &encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn wrong_key_fails() {
        let key = [42u8; 32];
        let nonce = [7u8; NONCE_SIZE];
        let plaintext = random_payload();

        let encrypted = encrypt_block(&key, &nonce, &plaintext).unwrap();

        let wrong_key = [99u8; 32];
        let result = decrypt_block(&wrong_key, &nonce, &encrypted);
        assert!(matches!(result, Err(VoidError::Decrypt)));
    }

    #[test]
    fn wrong_nonce_fails() {
        let key = [42u8; 32];
        let nonce = [7u8; NONCE_SIZE];
        let plaintext = random_payload();

        let encrypted = encrypt_block(&key, &nonce, &plaintext).unwrap();

        let wrong_nonce = [99u8; NONCE_SIZE];
        let result = decrypt_block(&key, &wrong_nonce, &encrypted);
        assert!(matches!(result, Err(VoidError::Decrypt)));
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let key = [42u8; 32];
        let nonce = [7u8; NONCE_SIZE];
        let plaintext = random_payload();

        let mut encrypted = encrypt_block(&key, &nonce, &plaintext).unwrap();
        encrypted[0] ^= 0xFF; // flip a byte

        let result = decrypt_block(&key, &nonce, &encrypted);
        assert!(matches!(result, Err(VoidError::Decrypt)));
    }

    #[test]
    fn random_data_fails_decrypt() {
        let key = [42u8; 32];
        let nonce = [7u8; NONCE_SIZE];
        let mut random_block = [0u8; BLOCK_SIZE];
        rand::thread_rng().fill_bytes(&mut random_block);

        let result = decrypt_block(&key, &nonce, &random_block);
        assert!(matches!(result, Err(VoidError::Decrypt)));
    }
}
