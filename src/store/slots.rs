//! Multi-slot collision resolution for block placement.
//!
//! Each `(path, block_num)` has up to [`MAX_SLOTS`] possible disk locations.
//! When writing, we try each slot in order: if it already belongs to us
//! (decrypts successfully), we overwrite it; otherwise we pick the first
//! "available" slot (one that fails to decrypt with our key AND is not
//! claimed by another block in this session).

use crate::crypto::cipher::{decrypt_block, encrypt_block};
use crate::crypto::keys::derive_block_key;
use crate::crypto::locator::block_offset;
use crate::store::image::ImageFile;
use crate::util::constants::{BLOCK_SIZE, MAX_SLOTS, PAYLOAD_SIZE};
use crate::util::errors::{DarkError, DarkResult};

/// Perform a dummy encryption to equalize timing with a successful decryption.
///
/// When `decrypt_block` fails (wrong key / random data), the crypto library
/// short-circuits after Poly1305 tag verification WITHOUT running the ChaCha20
/// keystream to decrypt the ciphertext. A successful decrypt does that extra work.
///
/// This function runs `encrypt_block` on dummy data to compensate, ensuring both
/// the success and failure paths do roughly the same amount of ChaCha20 computation.
#[inline(never)]
fn timing_equalize(key: &[u8; 32], dummy: &mut [u8; PAYLOAD_SIZE]) {
    let _ = std::hint::black_box(encrypt_block(key, dummy));
}

/// Write an encrypted block, resolving collisions across slots.
///
/// Tries each slot 0..MAX_SLOTS. Prefers overwriting our own slot (decrypt
/// succeeds). Falls back to the first slot where decrypt fails and the offset
/// is not claimed by another block in this session.
///
/// Always iterates ALL slots to avoid leaking which slot is used via timing.
pub fn write_slot(
    image: &mut ImageFile,
    master_secret: &[u8; 32],
    canonical_path: &str,
    block_num: u64,
    plaintext: &[u8; PAYLOAD_SIZE],
) -> DarkResult<()> {
    let key = derive_block_key(master_secret, canonical_path, block_num)?;
    let encrypted = encrypt_block(&key, plaintext)?;

    let total_blocks = image.total_blocks();
    let mut own_slot: Option<u64> = None;
    let mut first_available: Option<u64> = None;

    // Dummy buffer to equalize work across success/failure decrypt paths (timing fix)
    let mut dummy = [0u8; PAYLOAD_SIZE];

    // Always iterate ALL slots (constant-time iteration count for side-channel resistance)
    for slot in 0..MAX_SLOTS {
        let offset = block_offset(master_secret, canonical_path, block_num, slot, total_blocks);
        let existing = image.read_block(offset)?;

        match decrypt_block(&key, &existing) {
            Ok(plaintext_buf) => {
                dummy.copy_from_slice(&plaintext_buf);
                if own_slot.is_none() {
                    own_slot = Some(offset);
                }
            }
            Err(_) => {
                // Equalize crypto work: run a dummy encrypt (same ChaCha20 cost as decrypt)
                timing_equalize(&key, &mut dummy);
                if first_available.is_none() && !image.is_offset_claimed(offset) {
                    first_available = Some(offset);
                }
            }
        }
    }

    // Prefer our own slot, then first available
    if let Some(offset) = own_slot.or(first_available) {
        image.write_block(offset, &encrypted)?;
        image.claim_offset(offset);
        Ok(())
    } else {
        Err(DarkError::NoSlotAvailable {
            path: canonical_path.to_string(),
            block_num,
        })
    }
}

/// Write an encrypted block using copy-on-write semantics.
///
/// Unlike [`write_slot`], this prefers writing to a *different* slot than the
/// one currently holding our data, leaving the old block intact until the caller
/// explicitly erases it. This enables atomic multi-block overwrites: data blocks
/// are written to new slots first, then block 0 commits the update, then old
/// slots are cleaned up.
///
/// Falls back to in-place overwrite if no other slot is available.
///
/// Returns `Ok(Some(old_offset))` if the block already existed (the old slot
/// that should be erased after commit), or `Ok(None)` for a fresh write.
pub fn write_slot_cow(
    image: &mut ImageFile,
    master_secret: &[u8; 32],
    canonical_path: &str,
    block_num: u64,
    plaintext: &[u8; PAYLOAD_SIZE],
) -> DarkResult<Option<u64>> {
    let key = derive_block_key(master_secret, canonical_path, block_num)?;
    let encrypted = encrypt_block(&key, plaintext)?;

    let total_blocks = image.total_blocks();
    let mut own_slot: Option<u64> = None;
    let mut first_available: Option<u64> = None;

    let mut dummy = [0u8; PAYLOAD_SIZE];

    for slot in 0..MAX_SLOTS {
        let offset = block_offset(master_secret, canonical_path, block_num, slot, total_blocks);
        let existing = image.read_block(offset)?;

        match decrypt_block(&key, &existing) {
            Ok(plaintext_buf) => {
                dummy.copy_from_slice(&plaintext_buf);
                if own_slot.is_none() {
                    own_slot = Some(offset);
                }
            }
            Err(_) => {
                timing_equalize(&key, &mut dummy);
                if first_available.is_none() && !image.is_offset_claimed(offset) {
                    first_available = Some(offset);
                }
            }
        }
    }

    match (own_slot, first_available) {
        // COW: we already own a slot AND there's a free slot — write to the new one
        (Some(old_offset), Some(new_offset)) => {
            image.write_block(new_offset, &encrypted)?;
            image.claim_offset(new_offset);
            Ok(Some(old_offset))
        }
        // No free slot but we own one — in-place overwrite (best effort)
        (Some(old_offset), None) => {
            image.write_block(old_offset, &encrypted)?;
            image.claim_offset(old_offset);
            Ok(None) // no old slot to erase since we overwrote in-place
        }
        // Fresh write — no old data
        (None, Some(new_offset)) => {
            image.write_block(new_offset, &encrypted)?;
            image.claim_offset(new_offset);
            Ok(None)
        }
        // No slot at all
        (None, None) => Err(DarkError::NoSlotAvailable {
            path: canonical_path.to_string(),
            block_num,
        }),
    }
}

/// Read and decrypt a block, trying all slot candidates.
///
/// Returns `Ok(Some(plaintext))` if found, `Ok(None)` if no slot decrypts
/// successfully (file doesn't exist or wrong passphrase).
///
/// Always iterates ALL slots to avoid leaking data existence via timing.
/// A wrong passphrase takes the same time as a correct one.
pub fn read_slot(
    image: &mut ImageFile,
    master_secret: &[u8; 32],
    canonical_path: &str,
    block_num: u64,
) -> DarkResult<Option<[u8; PAYLOAD_SIZE]>> {
    let key = derive_block_key(master_secret, canonical_path, block_num)?;
    let total_blocks = image.total_blocks();
    let mut found: Option<[u8; PAYLOAD_SIZE]> = None;

    // Dummy buffer to equalize work across success/failure decrypt paths (timing fix)
    let mut dummy = [0u8; PAYLOAD_SIZE];

    // Always iterate ALL slots (constant-time iteration count for side-channel resistance)
    for slot in 0..MAX_SLOTS {
        let offset = block_offset(master_secret, canonical_path, block_num, slot, total_blocks);
        let raw = image.read_block(offset)?;

        match decrypt_block(&key, &raw) {
            Ok(plaintext) => {
                dummy.copy_from_slice(&plaintext);
                if found.is_none() {
                    found = Some(plaintext);
                    image.claim_offset(offset);
                }
            }
            Err(_) => {
                // Equalize crypto work: run a dummy encrypt (same ChaCha20 cost as decrypt)
                timing_equalize(&key, &mut dummy);
            }
        }
    }

    Ok(found)
}

/// Erase a specific block offset by overwriting with random data.
///
/// Used by COW write to clean up old slots after a successful commit.
pub fn erase_slot_at(image: &mut ImageFile, offset: u64) -> DarkResult<()> {
    let mut random_data = [0u8; BLOCK_SIZE];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut random_data);
    image.write_block(offset, &random_data)?;
    image.release_offset(offset);
    Ok(())
}

/// Erase a block by overwriting its slot with random data.
///
/// Finds which slot contains our data and overwrites it with random bytes.
/// Returns `true` if a block was erased, `false` if no matching slot was found.
///
/// Always iterates ALL slots to avoid timing leaks.
pub fn erase_slot(
    image: &mut ImageFile,
    master_secret: &[u8; 32],
    canonical_path: &str,
    block_num: u64,
) -> DarkResult<bool> {
    let key = derive_block_key(master_secret, canonical_path, block_num)?;
    let total_blocks = image.total_blocks();
    let mut erased = false;

    // Dummy buffer for timing equalization
    let mut dummy = [0u8; PAYLOAD_SIZE];

    // Always iterate ALL slots
    for slot in 0..MAX_SLOTS {
        let offset = block_offset(master_secret, canonical_path, block_num, slot, total_blocks);
        let raw = image.read_block(offset)?;

        match decrypt_block(&key, &raw) {
            Ok(plaintext) => {
                dummy.copy_from_slice(&plaintext);
                if !erased {
                    let mut random_data = [0u8; BLOCK_SIZE];
                    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut random_data);
                    image.write_block(offset, &random_data)?;
                    image.release_offset(offset);
                    erased = true;
                }
            }
            Err(_) => {
                timing_equalize(&key, &mut dummy);
            }
        }
    }

    Ok(erased)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::RngCore;
    use tempfile::NamedTempFile;

    fn create_random_image(num_blocks: u64) -> (NamedTempFile, ImageFile) {
        let tmp = NamedTempFile::new().expect("create tempfile");
        let size = num_blocks * BLOCK_SIZE as u64;
        // Fill with random data (simulating mkdark)
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

    #[test]
    fn collision_tracking_prevents_overwrite() {
        // With a tiny image, writes should fail rather than silently destroy data
        let (_tmp, mut img) = create_random_image(8);
        let secret = [42u8; 32];

        let mut successes = 0;
        let mut failures = 0;
        for i in 0..50 {
            let path = format!("/file_{}", i);
            let payload = [i as u8; PAYLOAD_SIZE];
            match write_slot(&mut img, &secret, &path, 0, &payload) {
                Ok(()) => successes += 1,
                Err(DarkError::NoSlotAvailable { .. }) => failures += 1,
                Err(e) => panic!("unexpected error: {}", e),
            }
        }
        assert!(failures > 0, "should have some failures on tiny image");

        // All successful writes should be readable
        for i in 0..successes.min(50) {
            let path = format!("/file_{}", i);
            let payload = [i as u8; PAYLOAD_SIZE];
            if let Some(data) = read_slot(&mut img, &secret, &path, 0).unwrap() {
                assert_eq!(data, payload, "file {} corrupted", i);
            }
        }
    }
}
