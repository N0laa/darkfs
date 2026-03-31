//! Argon2id key derivation: passphrase → master secret.
//!
//! The salt is `SHA-256("voidfs-v1-{image_size}")`, derived from the image
//! file size (not stored on disk) to preserve deniability. Two images of
//! identical size with the same passphrase produce the same master secret.
//!
//! # Known limitation (deterministic salt)
//!
//! Since the salt is derived from image size, an attacker could precompute
//! rainbow tables indexed by common image sizes. Argon2id's memory-hard cost
//! (256 MiB × 4 iterations in production mode) makes this expensive but not
//! impossible for well-funded adversaries. Mitigations:
//!
//! - **Use strong, unique passphrases.** The passphrase provides the actual
//!   entropy; the salt's role is only to prevent cross-image precomputation.
//! - **Use non-standard image sizes.** Appending a few random kilobytes to
//!   the image makes the size (and thus salt) unique.
//! - Storing a per-image random salt on disk would eliminate this issue but
//!   would break deniability (the salt would be a recognizable structure).

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

/// Derive a session secret by mixing the master secret with a per-image random salt.
///
/// `session_secret = HKDF-Expand(PRK from master_secret, info="voidfs-session" || random_salt)`
///
/// This ensures two images with the same passphrase and size have different
/// file encryption keys (because they have different `random_salt` values).
/// The `random_salt` is stored in the encrypted superblock and is generated
/// once per image on first use.
pub fn derive_session_secret(
    master_secret: &[u8; 32],
    random_salt: &[u8; 32],
) -> Result<Zeroizing<[u8; 32]>, VoidError> {
    use hkdf::Hkdf;
    use sha2::Sha256;

    let hkdf = Hkdf::<Sha256>::new(Some(master_secret), master_secret);
    let mut session = Zeroizing::new([0u8; 32]);
    let mut info = [0u8; 14 + 32];
    info[..14].copy_from_slice(b"voidfs-session");
    info[14..].copy_from_slice(random_salt);
    hkdf.expand(&info, session.as_mut())
        .map_err(|e| VoidError::Kdf(format!("HKDF expand (session): {e}")))?;
    Ok(session)
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

    #[test]
    fn session_secret_differs_with_salt() {
        let master = [42u8; 32];
        let salt_a = [1u8; 32];
        let salt_b = [2u8; 32];
        let a = derive_session_secret(&master, &salt_a).unwrap();
        let b = derive_session_secret(&master, &salt_b).unwrap();
        assert_ne!(a.as_ref(), b.as_ref());
    }

    #[test]
    fn session_secret_differs_from_master() {
        let master = [42u8; 32];
        let salt = [0u8; 32];
        let session = derive_session_secret(&master, &salt).unwrap();
        assert_ne!(session.as_ref(), &master);
    }

    #[test]
    fn session_secret_deterministic() {
        let master = [42u8; 32];
        let salt = [7u8; 32];
        let a = derive_session_secret(&master, &salt).unwrap();
        let b = derive_session_secret(&master, &salt).unwrap();
        assert_eq!(a.as_ref(), b.as_ref());
    }
}
