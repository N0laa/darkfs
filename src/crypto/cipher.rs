//! XChaCha20-Poly1305 block encryption with QSMM void masking.
//!
//! Each block on disk is 4096 bytes laid out as:
//! `[24-byte random nonce | ciphertext | 16-byte Poly1305 auth tag]`
//!
//! After AEAD encryption, the entire block is XOR-masked with a QSMM void
//! stream derived from `(master_secret, block_offset)`. This makes the block
//! indistinguishable from random noise — no nonce structure, no auth tag
//! position, nothing an observer can identify.
//!
//! On read, the mask is removed before AEAD decryption.

use chacha20poly1305::aead::Aead;
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use rand::RngCore;
use zeroize::Zeroize;

use qsmm::types::{BlockId, SecretKey};
use qsmm::void::mask;

use crate::util::constants::{BLOCK_SIZE, NONCE_SIZE, PAYLOAD_SIZE};
use crate::util::errors::DarkError;

/// Domain string used as hw_entropy for void masking.
/// Fixed per-filesystem to preserve deniability (no stored per-image entropy).
const VOID_HW_ENTROPY: &[u8] = b"darkfs-void-mask-v1";

/// Encrypt a plaintext payload into a full disk block, then void-mask it.
///
/// 1. Generates a fresh random 24-byte nonce.
/// 2. Encrypts with XChaCha20-Poly1305: `[nonce | ciphertext | tag]`.
/// 3. XOR-masks the entire block with QSMM void stream.
///
/// The `master_secret` is used for void masking. The `block_offset` determines
/// which mask stream is applied (each block gets a unique mask).
pub fn encrypt_block_masked(
    key: &[u8; 32],
    plaintext: &[u8; PAYLOAD_SIZE],
    master_secret: &[u8; 32],
    block_offset: u64,
) -> Result<[u8; BLOCK_SIZE], DarkError> {
    let block = encrypt_block(key, plaintext)?;

    // Void-mask the encrypted block.
    let qsmm_key = SecretKey::from_bytes(*master_secret);
    let masked = mask::mask_block(&block, &qsmm_key, BlockId(block_offset), VOID_HW_ENTROPY)
        .map_err(|_| DarkError::Encrypt)?;

    let mut result = [0u8; BLOCK_SIZE];
    result.copy_from_slice(&masked);
    Ok(result)
}

/// Unmask a void-masked block, then decrypt it.
///
/// 1. XOR-unmask the block with QSMM void stream.
/// 2. Extract the 24-byte nonce.
/// 3. Decrypt with XChaCha20-Poly1305.
pub fn decrypt_block_masked(
    key: &[u8; 32],
    masked_block: &[u8; BLOCK_SIZE],
    master_secret: &[u8; 32],
    block_offset: u64,
) -> Result<[u8; PAYLOAD_SIZE], DarkError> {
    // Void-unmask.
    let qsmm_key = SecretKey::from_bytes(*master_secret);
    let unmasked =
        mask::unmask_block(masked_block, &qsmm_key, BlockId(block_offset), VOID_HW_ENTROPY)
            .map_err(|_| DarkError::Decrypt)?;

    let mut block = [0u8; BLOCK_SIZE];
    block.copy_from_slice(&unmasked);

    decrypt_block(key, &block)
}

/// Encrypt a plaintext payload into a full disk block (no void masking).
///
/// Used internally and for backward compatibility.
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

/// Decrypt a disk block back into a plaintext payload (no void masking).
///
/// Used internally and for backward compatibility.
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
    plaintext.zeroize();
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

    // --- Unmasked (backward compat) ---

    #[test]
    fn roundtrip() {
        let key = [42u8; 32];
        let plaintext = random_payload();

        let encrypted = encrypt_block(&key, &plaintext).unwrap();
        assert_eq!(encrypted.len(), BLOCK_SIZE);
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
        assert!(matches!(decrypt_block(&wrong_key, &encrypted), Err(DarkError::Decrypt)));
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let key = [42u8; 32];
        let plaintext = random_payload();
        let mut encrypted = encrypt_block(&key, &plaintext).unwrap();
        encrypted[NONCE_SIZE] ^= 0xFF;
        assert!(matches!(decrypt_block(&key, &encrypted), Err(DarkError::Decrypt)));
    }

    #[test]
    fn random_data_fails_decrypt() {
        let key = [42u8; 32];
        let mut random_block = [0u8; BLOCK_SIZE];
        rand::thread_rng().fill_bytes(&mut random_block);
        assert!(matches!(decrypt_block(&key, &random_block), Err(DarkError::Decrypt)));
    }

    #[test]
    fn different_nonce_each_write() {
        let key = [42u8; 32];
        let plaintext = random_payload();
        let block1 = encrypt_block(&key, &plaintext).unwrap();
        let block2 = encrypt_block(&key, &plaintext).unwrap();
        assert_ne!(block1[..NONCE_SIZE], block2[..NONCE_SIZE]);
        assert_ne!(block1, block2);
        assert_eq!(decrypt_block(&key, &block1).unwrap(), plaintext);
        assert_eq!(decrypt_block(&key, &block2).unwrap(), plaintext);
    }

    // --- Void-masked ---

    #[test]
    fn masked_roundtrip() {
        let key = [42u8; 32];
        let master = [0xAA; 32];
        let plaintext = random_payload();

        let masked = encrypt_block_masked(&key, &plaintext, &master, 100).unwrap();
        let decrypted = decrypt_block_masked(&key, &masked, &master, 100).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn masked_wrong_master_fails() {
        let key = [42u8; 32];
        let master = [0xAA; 32];
        let wrong_master = [0xBB; 32];
        let plaintext = random_payload();

        let masked = encrypt_block_masked(&key, &plaintext, &master, 100).unwrap();
        // Wrong master_secret produces wrong unmask → AEAD auth fails.
        assert!(decrypt_block_masked(&key, &masked, &wrong_master, 100).is_err());
    }

    #[test]
    fn masked_wrong_offset_fails() {
        let key = [42u8; 32];
        let master = [0xAA; 32];
        let plaintext = random_payload();

        let masked = encrypt_block_masked(&key, &plaintext, &master, 100).unwrap();
        // Wrong block_offset produces wrong unmask → AEAD auth fails.
        assert!(decrypt_block_masked(&key, &masked, &master, 999).is_err());
    }

    #[test]
    fn masked_differs_from_unmasked() {
        let key = [42u8; 32];
        let master = [0xAA; 32];
        let plaintext = random_payload();

        let unmasked = encrypt_block(&key, &plaintext).unwrap();
        let masked = encrypt_block_masked(&key, &plaintext, &master, 0).unwrap();

        // Masked block should differ from unmasked (XOR with non-zero stream).
        assert_ne!(unmasked, masked);
    }

    #[test]
    fn masked_block_looks_random() {
        let key = [42u8; 32];
        let master = [0xAA; 32];

        // Mask many blocks and check byte distribution.
        let mut all_bytes = Vec::new();
        for offset in 0..50u64 {
            let plaintext = random_payload();
            let masked = encrypt_block_masked(&key, &plaintext, &master, offset).unwrap();
            all_bytes.extend_from_slice(&masked);
        }

        let mut counts = [0u64; 256];
        for &b in &all_bytes {
            counts[b as usize] += 1;
        }

        let expected = all_bytes.len() as f64 / 256.0;
        let chi_sq: f64 = counts
            .iter()
            .map(|&c| {
                let diff = c as f64 - expected;
                diff * diff / expected
            })
            .sum();

        assert!(
            chi_sq < 350.0,
            "masked blocks failed chi-squared test: {chi_sq}"
        );
    }
}
