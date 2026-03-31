//! HKDF-SHA256 per-block key derivation.
//!
//! Each `(file_path, block_num)` pair gets a unique encryption key,
//! derived deterministically from the master secret via HKDF.
//! Nonces are generated randomly per write (see `cipher.rs`).

use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::util::constants::KEY_SIZE;
use crate::util::errors::VoidError;

/// Derive a unique encryption key for a specific block of a file.
///
/// Uses HKDF-SHA256 with the master secret as both salt and IKM (safe because
/// the master secret has already been through Argon2id and has high entropy).
///
/// The `epoch` parameter (default 0) is mixed into the HKDF info string as an
/// anti-replay measure. Incrementing the epoch changes all derived keys, making
/// old blocks undecryptable. The epoch is NOT stored on disk — the user must
/// remember it alongside the passphrase. This preserves deniability.
pub fn derive_block_key(
    master_secret: &[u8; 32],
    canonical_path: &str,
    block_num: u64,
) -> Result<Zeroizing<[u8; KEY_SIZE]>, VoidError> {
    derive_block_key_with_epoch(master_secret, canonical_path, block_num, 0)
}

/// Like [`derive_block_key`] but with an explicit epoch for anti-replay.
pub fn derive_block_key_with_epoch(
    master_secret: &[u8; 32],
    canonical_path: &str,
    block_num: u64,
    epoch: u64,
) -> Result<Zeroizing<[u8; KEY_SIZE]>, VoidError> {
    let hkdf = Hkdf::<Sha256>::new(Some(master_secret), master_secret);

    let mut key = Zeroizing::new([0u8; KEY_SIZE]);
    let mut key_info = Vec::with_capacity(16 + 4 + canonical_path.len() + 8 + 5 + 8);
    key_info.extend_from_slice(b"voidfs-block-key");
    key_info.extend_from_slice(&(canonical_path.len() as u32).to_le_bytes());
    key_info.extend_from_slice(canonical_path.as_bytes());
    key_info.extend_from_slice(&block_num.to_le_bytes());
    key_info.extend_from_slice(b"epoch");
    key_info.extend_from_slice(&epoch.to_le_bytes());
    hkdf.expand(&key_info, key.as_mut())
        .map_err(|e| VoidError::Kdf(format!("HKDF expand (key): {e}")))?;

    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic() {
        let secret = [7u8; 32];
        let a = derive_block_key(&secret, "/foo", 0).unwrap();
        let b = derive_block_key(&secret, "/foo", 0).unwrap();
        assert_eq!(a.as_ref(), b.as_ref());
    }

    #[test]
    fn different_paths_produce_different_keys() {
        let secret = [7u8; 32];
        let a = derive_block_key(&secret, "/foo", 0).unwrap();
        let b = derive_block_key(&secret, "/bar", 0).unwrap();
        assert_ne!(a.as_ref(), b.as_ref());
    }

    #[test]
    fn different_block_nums_produce_different_keys() {
        let secret = [7u8; 32];
        let a = derive_block_key(&secret, "/foo", 0).unwrap();
        let b = derive_block_key(&secret, "/foo", 1).unwrap();
        assert_ne!(a.as_ref(), b.as_ref());
    }

    #[test]
    fn different_secrets_produce_different_keys() {
        let a = derive_block_key(&[1u8; 32], "/foo", 0).unwrap();
        let b = derive_block_key(&[2u8; 32], "/foo", 0).unwrap();
        assert_ne!(a.as_ref(), b.as_ref());
    }

    #[test]
    fn default_uses_epoch_zero() {
        let secret = [7u8; 32];
        let default_key = derive_block_key(&secret, "/foo", 0).unwrap();
        let epoch0_key = derive_block_key_with_epoch(&secret, "/foo", 0, 0).unwrap();
        assert_eq!(default_key.as_ref(), epoch0_key.as_ref());
    }

    #[test]
    fn different_epochs_produce_different_keys() {
        let secret = [7u8; 32];
        let e0 = derive_block_key_with_epoch(&secret, "/foo", 0, 0).unwrap();
        let e1 = derive_block_key_with_epoch(&secret, "/foo", 0, 1).unwrap();
        let e2 = derive_block_key_with_epoch(&secret, "/foo", 0, 2).unwrap();
        assert_ne!(e0.as_ref(), e1.as_ref());
        assert_ne!(e1.as_ref(), e2.as_ref());
        assert_ne!(e0.as_ref(), e2.as_ref());
    }
}
