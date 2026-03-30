//! HKDF-SHA256 per-block key and nonce derivation.
//!
//! Each `(file_path, block_num)` pair gets a unique encryption key and nonce,
//! derived deterministically from the master secret via HKDF.

use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::util::constants::{KEY_SIZE, NONCE_SIZE};
use crate::util::errors::VoidError;

/// A per-block encryption key and nonce, both zeroized on drop.
pub struct BlockKeys {
    /// 32-byte XChaCha20-Poly1305 key.
    pub key: Zeroizing<[u8; KEY_SIZE]>,
    /// 24-byte XChaCha20 nonce.
    pub nonce: Zeroizing<[u8; NONCE_SIZE]>,
}

/// Derive a unique key and nonce for a specific block of a file.
///
/// Uses HKDF-SHA256 with the master secret as both salt and IKM (safe because
/// the master secret has already been through Argon2id and has high entropy).
pub fn derive_block_keys(
    master_secret: &[u8; 32],
    canonical_path: &str,
    block_num: u64,
) -> Result<BlockKeys, VoidError> {
    let hkdf = Hkdf::<Sha256>::new(Some(master_secret), master_secret);

    // Derive the 32-byte block key
    let mut key = Zeroizing::new([0u8; KEY_SIZE]);
    let mut key_info = Vec::with_capacity(16 + canonical_path.len() + 8);
    key_info.extend_from_slice(b"voidfs-block-key");
    key_info.extend_from_slice(canonical_path.as_bytes());
    key_info.extend_from_slice(&block_num.to_le_bytes());
    hkdf.expand(&key_info, key.as_mut())
        .map_err(|e| VoidError::Kdf(format!("HKDF expand (key): {e}")))?;

    // Derive the 24-byte block nonce
    let mut nonce = Zeroizing::new([0u8; NONCE_SIZE]);
    let mut nonce_info = Vec::with_capacity(18 + canonical_path.len() + 8);
    nonce_info.extend_from_slice(b"voidfs-block-nonce");
    nonce_info.extend_from_slice(canonical_path.as_bytes());
    nonce_info.extend_from_slice(&block_num.to_le_bytes());
    hkdf.expand(&nonce_info, nonce.as_mut())
        .map_err(|e| VoidError::Kdf(format!("HKDF expand (nonce): {e}")))?;

    Ok(BlockKeys { key, nonce })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic() {
        let secret = [7u8; 32];
        let a = derive_block_keys(&secret, "/foo", 0).unwrap();
        let b = derive_block_keys(&secret, "/foo", 0).unwrap();
        assert_eq!(a.key.as_ref(), b.key.as_ref());
        assert_eq!(a.nonce.as_ref(), b.nonce.as_ref());
    }

    #[test]
    fn different_paths_produce_different_keys() {
        let secret = [7u8; 32];
        let a = derive_block_keys(&secret, "/foo", 0).unwrap();
        let b = derive_block_keys(&secret, "/bar", 0).unwrap();
        assert_ne!(a.key.as_ref(), b.key.as_ref());
        assert_ne!(a.nonce.as_ref(), b.nonce.as_ref());
    }

    #[test]
    fn different_block_nums_produce_different_keys() {
        let secret = [7u8; 32];
        let a = derive_block_keys(&secret, "/foo", 0).unwrap();
        let b = derive_block_keys(&secret, "/foo", 1).unwrap();
        assert_ne!(a.key.as_ref(), b.key.as_ref());
    }

    #[test]
    fn different_secrets_produce_different_keys() {
        let a = derive_block_keys(&[1u8; 32], "/foo", 0).unwrap();
        let b = derive_block_keys(&[2u8; 32], "/foo", 0).unwrap();
        assert_ne!(a.key.as_ref(), b.key.as_ref());
    }

    #[test]
    fn key_and_nonce_differ() {
        let secret = [7u8; 32];
        let keys = derive_block_keys(&secret, "/foo", 0).unwrap();
        // Key is 32 bytes, nonce is 24 — compare the overlap
        assert_ne!(&keys.key[..24], keys.nonce.as_ref());
    }
}
