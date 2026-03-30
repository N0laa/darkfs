//! Argon2id key derivation: passphrase → master secret.
//!
//! The salt is derived from the image size (not stored on disk) to preserve
//! deniability. Two images of identical size with the same passphrase produce
//! the same master secret — this is acceptable because the passphrase provides
//! the primary entropy.

use argon2::{Algorithm, Argon2, Params, Version};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::util::errors::VoidError;

/// Controls the cost parameters for Argon2id.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KdfPreset {
    /// Fast parameters for development and testing (t=1, m=8 MiB).
    Dev,
    /// Production parameters (t=4, m=256 MiB).
    Prod,
}

/// Derive a 32-byte master secret from a passphrase and image size using Argon2id.
///
/// The salt is `SHA-256("voidfs-v1-{image_size}")`, so no per-image salt needs
/// to be stored on disk.
pub fn derive_master_secret(
    passphrase: &[u8],
    image_size: u64,
    preset: KdfPreset,
) -> Result<Zeroizing<[u8; 32]>, VoidError> {
    let salt = Sha256::digest(format!("voidfs-v1-{image_size}").as_bytes());

    let (m_cost, t_cost) = match preset {
        KdfPreset::Dev => (8 * 1024, 1),    // 8 MiB, 1 iteration
        KdfPreset::Prod => (256 * 1024, 4), // 256 MiB, 4 iterations
    };

    let params =
        Params::new(m_cost, t_cost, 1, Some(32)).map_err(|e| VoidError::Kdf(e.to_string()))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut output = Zeroizing::new([0u8; 32]);
    argon2
        .hash_password_into(passphrase, &salt, output.as_mut())
        .map_err(|e| VoidError::Kdf(e.to_string()))?;

    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_output() {
        let a = derive_master_secret(b"test-passphrase", 64 * 1024 * 1024, KdfPreset::Dev)
            .expect("kdf failed");
        let b = derive_master_secret(b"test-passphrase", 64 * 1024 * 1024, KdfPreset::Dev)
            .expect("kdf failed");
        assert_eq!(a.as_ref(), b.as_ref());
    }

    #[test]
    fn different_passphrases_differ() {
        let a = derive_master_secret(b"passphrase-a", 64 * 1024 * 1024, KdfPreset::Dev)
            .expect("kdf failed");
        let b = derive_master_secret(b"passphrase-b", 64 * 1024 * 1024, KdfPreset::Dev)
            .expect("kdf failed");
        assert_ne!(a.as_ref(), b.as_ref());
    }

    #[test]
    fn different_image_sizes_differ() {
        let a = derive_master_secret(b"same-pass", 64 * 1024 * 1024, KdfPreset::Dev).expect("kdf");
        let b = derive_master_secret(b"same-pass", 128 * 1024 * 1024, KdfPreset::Dev).expect("kdf");
        assert_ne!(a.as_ref(), b.as_ref());
    }

    #[test]
    fn output_is_32_bytes() {
        let secret = derive_master_secret(b"test", 4096, KdfPreset::Dev).expect("kdf");
        assert_eq!(secret.len(), 32);
    }
}
