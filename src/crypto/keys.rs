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
pub fn derive_block_key(
    master_secret: &[u8; 32],
    canonical_path: &str,
    block_num: u64,
) -> Result<Zeroizing<[u8; KEY_SIZE]>, VoidError> {
    let hkdf = Hkdf::<Sha256>::new(Some(master_secret), master_secret);

    let mut key = Zeroizing::new([0u8; KEY_SIZE]);
    let mut key_info = Vec::with_capacity(16 + 4 + canonical_path.len() + 8);
    key_info.extend_from_slice(b"voidfs-block-key");
    key_info.extend_from_slice(&(canonical_path.len() as u32).to_le_bytes());
    key_info.extend_from_slice(canonical_path.as_bytes());
    key_info.extend_from_slice(&block_num.to_le_bytes());
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
}
