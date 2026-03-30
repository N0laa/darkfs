//! Multi-slot collision resolution for block placement.
//!
//! Each `(path, block_num)` has up to [`MAX_SLOTS`] possible disk locations.
//! When writing, we try each slot in order: if it already belongs to us
//! (decrypts successfully), we overwrite it; otherwise we pick the first
//! "available" slot (one that fails to decrypt with our key).

use crate::crypto::cipher::{decrypt_block, encrypt_block};
use crate::crypto::keys::derive_block_keys;
use crate::crypto::locator::block_offset;
use crate::store::image::ImageFile;
use crate::util::constants::{MAX_SLOTS, PAYLOAD_SIZE};
use crate::util::errors::{VoidError, VoidResult};

/// Write an encrypted block, resolving collisions across slots.
///
/// Tries each slot 0..MAX_SLOTS. Prefers overwriting our own slot (decrypt
/// succeeds). Falls back to the first slot where decrypt fails (random data
/// or another filesystem's block).
pub fn write_slot(
    image: &mut ImageFile,
    master_secret: &[u8; 32],
    canonical_path: &str,
    block_num: u64,
    plaintext: &[u8; PAYLOAD_SIZE],
) -> VoidResult<()> {
    let keys = derive_block_keys(master_secret, canonical_path, block_num)?;
    let encrypted = encrypt_block(&keys.key, &keys.nonce, plaintext)?;

    let total_blocks = image.total_blocks();
    let mut first_available: Option<u64> = None;

    for slot in 0..MAX_SLOTS {
        let offset = block_offset(master_secret, canonical_path, block_num, slot, total_blocks);
        let existing = image.read_block(offset)?;

        // Try decrypting with our key — if it works, this slot is ours
        if decrypt_block(&keys.key, &keys.nonce, &existing).is_ok() {
            image.write_block(offset, &encrypted)?;
            return Ok(());
        }

        // This slot doesn't belong to us — remember it as a candidate
        if first_available.is_none() {
            first_available = Some(offset);
        }
    }

    // No existing slot found — use first available
    if let Some(offset) = first_available {
        image.write_block(offset, &encrypted)?;
        Ok(())
    } else {
        Err(VoidError::NoSlotAvailable {
            path: canonical_path.to_string(),
            block_num,
        })
    }
}

/// Read and decrypt a block, trying all slot candidates.
///
/// Returns `Ok(Some(plaintext))` if found, `Ok(None)` if no slot decrypts
/// successfully (file doesn't exist or wrong passphrase).
pub fn read_slot(
    image: &mut ImageFile,
    master_secret: &[u8; 32],
    canonical_path: &str,
    block_num: u64,
) -> VoidResult<Option<[u8; PAYLOAD_SIZE]>> {
    let keys = derive_block_keys(master_secret, canonical_path, block_num)?;
    let total_blocks = image.total_blocks();

    for slot in 0..MAX_SLOTS {
        let offset = block_offset(master_secret, canonical_path, block_num, slot, total_blocks);
        let raw = image.read_block(offset)?;

        if let Ok(plaintext) = decrypt_block(&keys.key, &keys.nonce, &raw) {
            return Ok(Some(plaintext));
        }
    }

    Ok(None)
}

/// Erase a block by overwriting its slot with random data.
///
/// Finds which slot contains our data and overwrites it with random bytes.
/// Returns `true` if a block was erased, `false` if no matching slot was found.
pub fn erase_slot(
    image: &mut ImageFile,
    master_secret: &[u8; 32],
    canonical_path: &str,
    block_num: u64,
) -> VoidResult<bool> {
    let keys = derive_block_keys(master_secret, canonical_path, block_num)?;
    let total_blocks = image.total_blocks();

    for slot in 0..MAX_SLOTS {
        let offset = block_offset(master_secret, canonical_path, block_num, slot, total_blocks);
        let raw = image.read_block(offset)?;

        if decrypt_block(&keys.key, &keys.nonce, &raw).is_ok() {
            let mut random_data = [0u8; crate::util::constants::BLOCK_SIZE];
            rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut random_data);
            image.write_block(offset, &random_data)?;
            return Ok(true);
        }
    }

    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::constants::BLOCK_SIZE;
    use rand::RngCore;
    use tempfile::NamedTempFile;

    fn create_random_image(num_blocks: u64) -> (NamedTempFile, ImageFile) {
        let tmp = NamedTempFile::new().expect("create tempfile");
        let size = num_blocks * BLOCK_SIZE as u64;
        // Fill with random data (simulating mkvoid)
        let mut buf = vec![0u8; size as usize];
        rand::thread_rng().fill_bytes(&mut buf);
        std::io::Write::write_all(&mut tmp.as_file(), &buf).unwrap();
        let img = ImageFile::open(tmp.path()).unwrap();
        (tmp, img)
    }

    #[test]
    fn write_then_read() {
        let (_tmp, mut img) = create_random_image(64);
        let secret = [42u8; 32];
        let mut payload = [0u8; PAYLOAD_SIZE];
        payload[..5].copy_from_slice(b"hello");

        write_slot(&mut img, &secret, "/test", 0, &payload).unwrap();
        let result = read_slot(&mut img, &secret, "/test", 0).unwrap();
        assert_eq!(result, Some(payload));
    }

    #[test]
    fn nonexistent_returns_none() {
        let (_tmp, mut img) = create_random_image(64);
        let secret = [42u8; 32];
        let result = read_slot(&mut img, &secret, "/nonexistent", 0).unwrap();
        assert_eq!(result, None);
    }

    #[test]
    fn wrong_secret_returns_none() {
        let (_tmp, mut img) = create_random_image(64);
        let secret_a = [42u8; 32];
        let secret_b = [99u8; 32];
        let payload = [1u8; PAYLOAD_SIZE];

        write_slot(&mut img, &secret_a, "/test", 0, &payload).unwrap();
        let result = read_slot(&mut img, &secret_b, "/test", 0).unwrap();
        assert_eq!(result, None);
    }

    #[test]
    fn overwrite_own_block() {
        let (_tmp, mut img) = create_random_image(64);
        let secret = [42u8; 32];

        let payload1 = [1u8; PAYLOAD_SIZE];
        let payload2 = [2u8; PAYLOAD_SIZE];

        write_slot(&mut img, &secret, "/test", 0, &payload1).unwrap();
        write_slot(&mut img, &secret, "/test", 0, &payload2).unwrap();

        let result = read_slot(&mut img, &secret, "/test", 0).unwrap();
        assert_eq!(result, Some(payload2));
    }

    #[test]
    fn erase_block() {
        let (_tmp, mut img) = create_random_image(64);
        let secret = [42u8; 32];
        let payload = [1u8; PAYLOAD_SIZE];

        write_slot(&mut img, &secret, "/test", 0, &payload).unwrap();
        assert!(erase_slot(&mut img, &secret, "/test", 0).unwrap());

        let result = read_slot(&mut img, &secret, "/test", 0).unwrap();
        assert_eq!(result, None);
    }

    #[test]
    fn erase_nonexistent_returns_false() {
        let (_tmp, mut img) = create_random_image(64);
        let secret = [42u8; 32];
        assert!(!erase_slot(&mut img, &secret, "/nope", 0).unwrap());
    }

    #[test]
    fn two_files_same_image() {
        let (_tmp, mut img) = create_random_image(256);
        let secret = [42u8; 32];

        let payload_a = [0xAAu8; PAYLOAD_SIZE];
        let payload_b = [0xBBu8; PAYLOAD_SIZE];

        write_slot(&mut img, &secret, "/file_a", 0, &payload_a).unwrap();
        write_slot(&mut img, &secret, "/file_b", 0, &payload_b).unwrap();

        assert_eq!(
            read_slot(&mut img, &secret, "/file_a", 0).unwrap(),
            Some(payload_a)
        );
        assert_eq!(
            read_slot(&mut img, &secret, "/file_b", 0).unwrap(),
            Some(payload_b)
        );
    }
}
