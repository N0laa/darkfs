//! Encrypted superblock: per-image salt, generation counter, and slot map.
//!
//! The superblock is a single encrypted block at an HMAC-derived offset,
//! indistinguishable from random data without the passphrase. It stores:
//!
//! - **`random_salt`**: 32-byte per-image nonce, generated once on first use.
//!   Mixed into session key derivation to prevent cross-image key reuse.
//! - **`generation`**: Monotonic counter incremented on each write session.
//!   Enables replay detection (a rolled-back image has a lower generation).
//! - **`slot_map`**: Maps file path hashes to their slot indices, enabling
//!   O(1) slot lookup instead of O(MAX_SLOTS) scanning on reads.
//!
//! The superblock is encrypted with a key derived from `master_secret` (not
//! `session_secret`), since the superblock must be readable before the
//! session secret can be derived.

use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::Zeroizing;
use hkdf::Hkdf;

use crate::crypto::cipher::{decrypt_block, encrypt_block};
use crate::store::image::ImageFile;
use crate::util::constants::PAYLOAD_SIZE;
use crate::util::errors::{VoidError, VoidResult};

type HmacSha256 = Hmac<Sha256>;

/// Magic bytes for superblock identification after decryption: "VFS0".
const SB_MAGIC: [u8; 4] = [0x56, 0x46, 0x53, 0x30];

/// Current superblock format version.
const SB_VERSION: u8 = 1;

/// Fixed header size inside the superblock payload.
/// [4 magic] [1 version] [3 reserved] [32 salt] [8 generation] [4 file_count] = 52 bytes
const SB_HEADER_SIZE: usize = 52;

/// Size of the HMAC integrity tag appended to the serialized slot map.
const INTEGRITY_SIZE: usize = 32;

/// The superblock contents (decrypted and validated).
#[derive(Debug, Clone)]
pub struct Superblock {
    /// Per-image random salt (32 bytes), set once on first write.
    pub random_salt: [u8; 32],
    /// Monotonic generation counter, incremented on each write session.
    pub generation: u64,
    /// Number of tracked files.
    pub file_count: u32,
    /// Maps path_hash (u64) to slot index (u8) for O(1) lookups.
    pub slot_map: Vec<SlotEntry>,
}

/// A single entry in the superblock slot map.
#[derive(Debug, Clone)]
pub struct SlotEntry {
    /// First 8 bytes of HMAC(session_secret, canonical_path), as u64.
    pub path_hash: u64,
    /// Block number within the file.
    pub block_num: u32,
    /// Which slot (0..MAX_SLOTS) this block occupies.
    pub slot: u8,
}

/// Encoded size of one SlotEntry: 8 + 4 + 1 = 13 bytes.
const SLOT_ENTRY_SIZE: usize = 13;

/// Maximum entries that fit: (PAYLOAD_SIZE - SB_HEADER_SIZE - INTEGRITY_SIZE - 4 for count) / SLOT_ENTRY_SIZE
const MAX_SLOT_ENTRIES: usize = (PAYLOAD_SIZE - SB_HEADER_SIZE - INTEGRITY_SIZE - 4) / SLOT_ENTRY_SIZE;

impl Superblock {
    /// Create a new superblock with a fresh random salt.
    pub fn new() -> Self {
        let mut random_salt = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut random_salt);
        Self {
            random_salt,
            generation: 1,
            file_count: 0,
            slot_map: Vec::new(),
        }
    }

    /// Record a slot assignment for a file block.
    pub fn record_slot(&mut self, path_hash: u64, block_num: u32, slot: u8) {
        // Update existing entry or add new one
        if let Some(entry) = self.slot_map.iter_mut().find(
            |e| e.path_hash == path_hash && e.block_num == block_num,
        ) {
            entry.slot = slot;
        } else {
            self.slot_map.push(SlotEntry { path_hash, block_num, slot });
        }
    }

    /// Remove all slot entries for a given path hash.
    pub fn remove_path(&mut self, path_hash: u64) {
        self.slot_map.retain(|e| e.path_hash != path_hash);
    }

    /// Look up the slot index for a specific (path_hash, block_num).
    pub fn lookup_slot(&self, path_hash: u64, block_num: u32) -> Option<u8> {
        self.slot_map
            .iter()
            .find(|e| e.path_hash == path_hash && e.block_num == block_num)
            .map(|e| e.slot)
    }

    /// Check if the slot map has room for more entries.
    pub fn has_capacity(&self) -> bool {
        self.slot_map.len() < MAX_SLOT_ENTRIES
    }
}

/// Compute the disk offset where the superblock is stored.
pub fn superblock_offset(master_secret: &[u8; 32], total_blocks: u64) -> u64 {
    let mut mac = HmacSha256::new_from_slice(master_secret)
        .expect("HMAC accepts any key length");
    mac.update(b"voidfs-superblock");
    let result = mac.finalize().into_bytes();
    let hash_bytes: [u8; 8] = result[..8].try_into().expect("8 bytes");
    u64::from_le_bytes(hash_bytes) % total_blocks
}

/// Derive the encryption key used for the superblock (distinct from file keys).
fn derive_superblock_key(master_secret: &[u8; 32]) -> Result<Zeroizing<[u8; 32]>, VoidError> {
    let hkdf = Hkdf::<Sha256>::new(Some(master_secret), master_secret);
    let mut key = Zeroizing::new([0u8; 32]);
    hkdf.expand(b"voidfs-superblock-key", key.as_mut())
        .map_err(|e| VoidError::Kdf(format!("HKDF expand (superblock): {e}")))?;
    Ok(key)
}

/// Compute HMAC integrity over the superblock fields.
fn compute_integrity(master_secret: &[u8; 32], data: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(master_secret)
        .expect("HMAC accepts any key length");
    mac.update(b"voidfs-superblock-integrity");
    mac.update(data);
    let result = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

/// Serialize the superblock into a PAYLOAD_SIZE buffer.
fn serialize_superblock(
    master_secret: &[u8; 32],
    sb: &Superblock,
) -> Result<[u8; PAYLOAD_SIZE], VoidError> {
    if sb.slot_map.len() > MAX_SLOT_ENTRIES {
        return Err(VoidError::SuperblockFull {
            max_entries: MAX_SLOT_ENTRIES,
        });
    }

    let mut buf = [0u8; PAYLOAD_SIZE];
    let mut pos = 0;

    // Header: magic + version + reserved
    buf[pos..pos + 4].copy_from_slice(&SB_MAGIC);
    pos += 4;
    buf[pos] = SB_VERSION;
    pos += 1;
    pos += 3; // reserved

    // Salt, generation, file_count
    buf[pos..pos + 32].copy_from_slice(&sb.random_salt);
    pos += 32;
    buf[pos..pos + 8].copy_from_slice(&sb.generation.to_le_bytes());
    pos += 8;
    buf[pos..pos + 4].copy_from_slice(&sb.file_count.to_le_bytes());
    pos += 4;

    // Slot map: count + entries
    let entry_count = sb.slot_map.len() as u32;
    buf[pos..pos + 4].copy_from_slice(&entry_count.to_le_bytes());
    pos += 4;

    for entry in &sb.slot_map {
        buf[pos..pos + 8].copy_from_slice(&entry.path_hash.to_le_bytes());
        pos += 8;
        buf[pos..pos + 4].copy_from_slice(&entry.block_num.to_le_bytes());
        pos += 4;
        buf[pos] = entry.slot;
        pos += 1;
    }

    // Integrity HMAC over everything before it
    let integrity = compute_integrity(master_secret, &buf[..pos]);
    buf[pos..pos + 32].copy_from_slice(&integrity);

    Ok(buf)
}

/// Deserialize and validate a superblock from a PAYLOAD_SIZE buffer.
fn deserialize_superblock(
    master_secret: &[u8; 32],
    buf: &[u8; PAYLOAD_SIZE],
) -> Result<Superblock, VoidError> {
    let mut pos = 0;

    // Check magic
    if buf[pos..pos + 4] != SB_MAGIC {
        return Err(VoidError::InvalidMagic);
    }
    pos += 4;

    // Version
    let _version = buf[pos];
    pos += 1;
    pos += 3; // reserved

    // Salt
    let mut random_salt = [0u8; 32];
    random_salt.copy_from_slice(&buf[pos..pos + 32]);
    pos += 32;

    // Generation
    let generation = u64::from_le_bytes(buf[pos..pos + 8].try_into().unwrap());
    pos += 8;

    // File count
    let file_count = u32::from_le_bytes(buf[pos..pos + 4].try_into().unwrap());
    pos += 4;

    // Slot map
    let entry_count = u32::from_le_bytes(buf[pos..pos + 4].try_into().unwrap()) as usize;
    pos += 4;

    if entry_count > MAX_SLOT_ENTRIES {
        return Err(VoidError::SuperblockCorrupt);
    }

    let mut slot_map = Vec::with_capacity(entry_count);
    for _ in 0..entry_count {
        if pos + SLOT_ENTRY_SIZE > PAYLOAD_SIZE - INTEGRITY_SIZE {
            return Err(VoidError::SuperblockCorrupt);
        }
        let path_hash = u64::from_le_bytes(buf[pos..pos + 8].try_into().unwrap());
        pos += 8;
        let block_num = u32::from_le_bytes(buf[pos..pos + 4].try_into().unwrap());
        pos += 4;
        let slot = buf[pos];
        pos += 1;
        slot_map.push(SlotEntry { path_hash, block_num, slot });
    }

    // Verify integrity
    let expected = compute_integrity(master_secret, &buf[..pos]);
    let actual = &buf[pos..pos + 32];
    if expected != actual {
        return Err(VoidError::SuperblockCorrupt);
    }

    Ok(Superblock {
        random_salt,
        generation,
        file_count,
        slot_map,
    })
}

/// Read and decrypt the superblock from the image.
///
/// Returns `Ok(None)` if no superblock exists (fresh image or wrong passphrase).
pub fn read_superblock(
    image: &mut ImageFile,
    master_secret: &[u8; 32],
) -> VoidResult<Option<Superblock>> {
    let offset = superblock_offset(master_secret, image.total_blocks());
    let raw = image.read_block(offset)?;

    let key = derive_superblock_key(master_secret)?;
    let payload = match decrypt_block(&key, &raw) {
        Ok(p) => p,
        Err(VoidError::Decrypt) => return Ok(None), // no superblock yet
        Err(e) => return Err(e),
    };

    match deserialize_superblock(master_secret, &payload) {
        Ok(sb) => {
            // Claim the superblock offset to prevent file writes from overwriting it
            image.claim_offset(offset);
            Ok(Some(sb))
        }
        Err(VoidError::InvalidMagic) => Ok(None),
        Err(e) => Err(e),
    }
}

/// Number of deterministic decoy blocks written alongside each superblock update.
const DECOY_WRITE_COUNT: usize = 7;

/// Compute deterministic decoy offsets derived from master_secret.
///
/// These are fixed per-image so that the SAME set of blocks changes on every
/// superblock write. An adversary diffing snapshots sees `1 + DECOY_WRITE_COUNT`
/// blocks that change every time — they cannot distinguish the superblock from
/// the decoys without the passphrase.
fn decoy_offsets(master_secret: &[u8; 32], total_blocks: u64) -> Vec<u64> {
    let sb_off = superblock_offset(master_secret, total_blocks);
    let mut offsets = Vec::with_capacity(DECOY_WRITE_COUNT);
    for i in 0u32..DECOY_WRITE_COUNT as u32 * 4 {
        if offsets.len() >= DECOY_WRITE_COUNT {
            break;
        }
        let mut mac = HmacSha256::new_from_slice(master_secret)
            .expect("HMAC accepts any key length");
        mac.update(b"voidfs-decoy");
        mac.update(&i.to_le_bytes());
        let result = mac.finalize().into_bytes();
        let hash_bytes: [u8; 8] = result[..8].try_into().expect("8 bytes");
        let off = u64::from_le_bytes(hash_bytes) % total_blocks;
        if off != sb_off && !offsets.contains(&off) {
            offsets.push(off);
        }
    }
    offsets
}

/// Encrypt and write the superblock to the image, plus deterministic decoy blocks.
///
/// Writes `DECOY_WRITE_COUNT` random-data blocks to deterministic offsets
/// derived from `master_secret`, so that snapshot diffs see multiple blocks
/// changing every time and cannot identify which one is the superblock.
pub fn write_superblock(
    image: &mut ImageFile,
    master_secret: &[u8; 32],
    sb: &Superblock,
) -> VoidResult<()> {
    let offset = superblock_offset(master_secret, image.total_blocks());
    let key = derive_superblock_key(master_secret)?;
    let payload = serialize_superblock(master_secret, sb)?;
    let encrypted = encrypt_block(&key, &payload)?;
    image.write_block(offset, &encrypted)?;
    image.claim_offset(offset);

    // Write decoy blocks at deterministic (but secret) offsets.
    let total = image.total_blocks();
    let decoys = decoy_offsets(master_secret, total);
    let mut rng = rand::thread_rng();
    for idx in decoys {
        if !image.is_offset_claimed(idx) {
            let mut noise = [0u8; crate::util::constants::BLOCK_SIZE];
            rand::RngCore::fill_bytes(&mut rng, &mut noise);
            let _ = image.write_block(idx, &noise);
        }
    }

    Ok(())
}

/// Compute a path hash for the slot map.
///
/// Returns the first 8 bytes of HMAC-SHA256(secret, canonical_path) as u64.
pub fn path_hash(secret: &[u8; 32], canonical_path: &str) -> u64 {
    let mut mac = HmacSha256::new_from_slice(secret)
        .expect("HMAC accepts any key length");
    mac.update(b"voidfs-path-hash");
    mac.update(canonical_path.as_bytes());
    let result = mac.finalize().into_bytes();
    u64::from_le_bytes(result[..8].try_into().unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::constants::BLOCK_SIZE;
    use rand::RngCore;
    use tempfile::NamedTempFile;

    fn create_test_image(num_blocks: u64) -> (NamedTempFile, ImageFile) {
        let tmp = NamedTempFile::new().expect("create tempfile");
        let size = num_blocks * BLOCK_SIZE as u64;
        let mut buf = vec![0u8; size as usize];
        rand::thread_rng().fill_bytes(&mut buf);
        std::io::Write::write_all(&mut tmp.as_file(), &buf).unwrap();
        let img = ImageFile::open(tmp.path()).unwrap();
        (tmp, img)
    }

    #[test]
    fn superblock_roundtrip() {
        let (_tmp, mut img) = create_test_image(256);
        let master = [42u8; 32];

        let mut sb = Superblock::new();
        sb.generation = 5;
        sb.file_count = 3;
        sb.record_slot(12345, 0, 2);
        sb.record_slot(67890, 0, 1);
        sb.record_slot(67890, 1, 4);

        write_superblock(&mut img, &master, &sb).unwrap();
        let read_back = read_superblock(&mut img, &master).unwrap().unwrap();

        assert_eq!(read_back.random_salt, sb.random_salt);
        assert_eq!(read_back.generation, 5);
        assert_eq!(read_back.file_count, 3);
        assert_eq!(read_back.slot_map.len(), 3);
        assert_eq!(read_back.lookup_slot(12345, 0), Some(2));
        assert_eq!(read_back.lookup_slot(67890, 1), Some(4));
    }

    #[test]
    fn no_superblock_returns_none() {
        let (_tmp, mut img) = create_test_image(256);
        let master = [42u8; 32];
        assert!(read_superblock(&mut img, &master).unwrap().is_none());
    }

    #[test]
    fn wrong_key_returns_none() {
        let (_tmp, mut img) = create_test_image(256);
        let master = [42u8; 32];
        let wrong = [99u8; 32];

        let sb = Superblock::new();
        write_superblock(&mut img, &master, &sb).unwrap();

        assert!(read_superblock(&mut img, &wrong).unwrap().is_none());
    }

    #[test]
    fn integrity_detects_tampering() {
        let master = [42u8; 32];
        let sb = Superblock::new();
        let mut payload = serialize_superblock(&master, &sb).unwrap();

        // Tamper with the generation field (offset 44 = 4+1+3+32+8 minus 4 = byte 44)
        payload[44] ^= 0xFF;

        let result = deserialize_superblock(&master, &payload);
        assert!(matches!(result, Err(VoidError::SuperblockCorrupt)));
    }

    #[test]
    fn superblock_offset_claims_block() {
        let (_tmp, mut img) = create_test_image(256);
        let master = [42u8; 32];

        let sb = Superblock::new();
        write_superblock(&mut img, &master, &sb).unwrap();

        let offset = superblock_offset(&master, img.total_blocks());
        assert!(img.is_offset_claimed(offset));
    }

    #[test]
    fn slot_map_operations() {
        let mut sb = Superblock::new();

        sb.record_slot(111, 0, 3);
        sb.record_slot(222, 0, 1);
        sb.record_slot(111, 1, 0);

        assert_eq!(sb.lookup_slot(111, 0), Some(3));
        assert_eq!(sb.lookup_slot(111, 1), Some(0));
        assert_eq!(sb.lookup_slot(222, 0), Some(1));
        assert_eq!(sb.lookup_slot(999, 0), None);

        // Update existing
        sb.record_slot(111, 0, 4);
        assert_eq!(sb.lookup_slot(111, 0), Some(4));

        // Remove
        sb.remove_path(111);
        assert_eq!(sb.lookup_slot(111, 0), None);
        assert_eq!(sb.lookup_slot(111, 1), None);
        assert_eq!(sb.lookup_slot(222, 0), Some(1));
    }

    #[test]
    fn path_hash_deterministic() {
        let secret = [42u8; 32];
        let h1 = path_hash(&secret, "/foo");
        let h2 = path_hash(&secret, "/foo");
        assert_eq!(h1, h2);
    }

    #[test]
    fn path_hash_differs_for_different_paths() {
        let secret = [42u8; 32];
        let h1 = path_hash(&secret, "/foo");
        let h2 = path_hash(&secret, "/bar");
        assert_ne!(h1, h2);
    }
}
