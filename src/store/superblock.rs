//! Sharded metadata mesh: per-image salt, generation counter, and slot map.
//!
//! Instead of a single encrypted superblock, metadata is split into
//! threshold-recoverable shards via QSMM's shatter module. The shards
//! are scattered across the image at HMAC-derived positions, invisible
//! without the passphrase.
//!
//! - **Fault tolerant**: Need only 5 of 9 shards to reconstruct.
//! - **No decoys needed**: Every shard looks like random noise.
//! - **No single point of failure**: Losing up to 4 shards is safe.

use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::Zeroizing;

use qsmm::shatter::mesh::{MeshConfig, MetadataMesh, RetrievedShard};
use qsmm::shatter::sss;
use qsmm::types::{SecretKey, Threshold};

use crate::crypto::cipher::{decrypt_block_masked, encrypt_block_masked};
use crate::store::image::ImageFile;
use crate::util::constants::PAYLOAD_SIZE;
use crate::util::errors::{DarkError, DarkResult};

type HmacSha256 = Hmac<Sha256>;

/// Shard threshold: need K of N shards to reconstruct.
const SHARD_K: usize = 5;
/// Total shards written.
const SHARD_N: usize = 9;

/// Magic bytes for superblock identification after decryption: "DFS1".
const SB_MAGIC: [u8; 4] = [0x44, 0x46, 0x53, 0x31];

/// Current superblock format version.
const SB_VERSION: u8 = 2;

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
const MAX_SLOT_ENTRIES: usize =
    (PAYLOAD_SIZE - SB_HEADER_SIZE - INTEGRITY_SIZE - 4) / SLOT_ENTRY_SIZE;

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
        if let Some(entry) = self
            .slot_map
            .iter_mut()
            .find(|e| e.path_hash == path_hash && e.block_num == block_num)
        {
            entry.slot = slot;
        } else {
            self.slot_map.push(SlotEntry {
                path_hash,
                block_num,
                slot,
            });
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

/// Derive the encryption key used for superblock shard encryption.
fn derive_superblock_key(master_secret: &[u8; 32]) -> Result<Zeroizing<[u8; 32]>, DarkError> {
    let hkdf = hkdf::Hkdf::<Sha256>::new(Some(master_secret), master_secret);
    let mut key = Zeroizing::new([0u8; 32]);
    hkdf.expand(b"darkfs-superblock-key", key.as_mut())
        .map_err(|e| DarkError::Kdf(format!("HKDF expand (superblock): {e}")))?;
    Ok(key)
}

/// Compute HMAC integrity over the superblock fields.
fn compute_integrity(master_secret: &[u8; 32], data: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(master_secret).expect("HMAC accepts any key length");
    mac.update(b"darkfs-superblock-integrity");
    mac.update(data);
    let result = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

/// Serialize the superblock into bytes.
fn serialize_superblock(master_secret: &[u8; 32], sb: &Superblock) -> Result<Vec<u8>, DarkError> {
    if sb.slot_map.len() > MAX_SLOT_ENTRIES {
        return Err(DarkError::SuperblockFull {
            max_entries: MAX_SLOT_ENTRIES,
        });
    }

    let mut buf =
        vec![0u8; SB_HEADER_SIZE + 4 + sb.slot_map.len() * SLOT_ENTRY_SIZE + INTEGRITY_SIZE];
    let mut pos = 0;

    // Header
    buf[pos..pos + 4].copy_from_slice(&SB_MAGIC);
    pos += 4;
    buf[pos] = SB_VERSION;
    pos += 1;
    pos += 3; // reserved

    buf[pos..pos + 32].copy_from_slice(&sb.random_salt);
    pos += 32;
    buf[pos..pos + 8].copy_from_slice(&sb.generation.to_le_bytes());
    pos += 8;
    buf[pos..pos + 4].copy_from_slice(&sb.file_count.to_le_bytes());
    pos += 4;

    // Slot map
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

    // Integrity HMAC
    let integrity = compute_integrity(master_secret, &buf[..pos]);
    buf[pos..pos + 32].copy_from_slice(&integrity);

    Ok(buf)
}

/// Deserialize and validate a superblock from bytes.
fn deserialize_superblock(master_secret: &[u8; 32], buf: &[u8]) -> Result<Superblock, DarkError> {
    if buf.len() < SB_HEADER_SIZE + 4 + INTEGRITY_SIZE {
        return Err(DarkError::SuperblockCorrupt);
    }

    let mut pos = 0;

    if buf[pos..pos + 4] != SB_MAGIC {
        return Err(DarkError::InvalidMagic);
    }
    pos += 4;

    let _version = buf[pos];
    pos += 1;
    pos += 3; // reserved

    let mut random_salt = [0u8; 32];
    random_salt.copy_from_slice(&buf[pos..pos + 32]);
    pos += 32;

    let generation = u64::from_le_bytes(buf[pos..pos + 8].try_into().unwrap());
    pos += 8;

    let file_count = u32::from_le_bytes(buf[pos..pos + 4].try_into().unwrap());
    pos += 4;

    let entry_count = u32::from_le_bytes(buf[pos..pos + 4].try_into().unwrap()) as usize;
    pos += 4;

    if entry_count > MAX_SLOT_ENTRIES {
        return Err(DarkError::SuperblockCorrupt);
    }

    let mut slot_map = Vec::with_capacity(entry_count);
    for _ in 0..entry_count {
        if pos + SLOT_ENTRY_SIZE > buf.len() - INTEGRITY_SIZE {
            return Err(DarkError::SuperblockCorrupt);
        }
        let path_hash = u64::from_le_bytes(buf[pos..pos + 8].try_into().unwrap());
        pos += 8;
        let block_num = u32::from_le_bytes(buf[pos..pos + 4].try_into().unwrap());
        pos += 4;
        let slot = buf[pos];
        pos += 1;
        slot_map.push(SlotEntry {
            path_hash,
            block_num,
            slot,
        });
    }

    // Verify integrity
    let expected = compute_integrity(master_secret, &buf[..pos]);
    let actual = &buf[pos..pos + 32];
    use subtle::ConstantTimeEq;
    if expected.ct_eq(actual).unwrap_u8() == 0 {
        return Err(DarkError::SuperblockCorrupt);
    }

    Ok(Superblock {
        random_salt,
        generation,
        file_count,
        slot_map,
    })
}

/// Create the QSMM metadata mesh for this image.
fn create_mesh(total_blocks: u64) -> MetadataMesh {
    MetadataMesh::new(MeshConfig {
        threshold: Threshold::new(SHARD_K, SHARD_N),
        total_blocks,
    })
}

/// Convert master_secret to a QSMM SecretKey.
fn to_qsmm_key(master_secret: &[u8; 32]) -> SecretKey {
    SecretKey::from_bytes(*master_secret)
}

/// Read and reconstruct the superblock from sharded mesh.
///
/// Scans 9 HMAC-derived shard positions, decrypts each, and reconstructs
/// the superblock from 5+ valid shards. Returns `Ok(None)` if fewer than
/// 5 shards are recoverable (fresh image or wrong passphrase).
pub fn read_superblock(
    image: &mut ImageFile,
    master_secret: &[u8; 32],
) -> DarkResult<Option<Superblock>> {
    // Minimum image size: need at least SHARD_N blocks for shards
    // plus some blocks for file data.
    const MIN_BLOCKS: u64 = (SHARD_N as u64) + 16; // 9 shards + 16 blocks minimum
    if image.total_blocks() < MIN_BLOCKS {
        return Err(DarkError::InvalidImageSize {
            size: image.total_blocks() * crate::util::constants::BLOCK_SIZE as u64,
            block_size: crate::util::constants::BLOCK_SIZE,
        });
    }

    let mesh = create_mesh(image.total_blocks());
    let key = derive_superblock_key(master_secret)?;
    let qsmm_key = to_qsmm_key(master_secret);
    let hw_entropy = b"darkfs-mesh-entropy";

    let shard_locations = mesh.shard_locations(&qsmm_key, hw_entropy);

    // Try to read and decrypt each shard.
    let mut retrieved_shards: Vec<RetrievedShard> = Vec::new();

    for &block_id in shard_locations.iter() {
        let offset = block_id.0;

        let raw = match image.read_block(offset) {
            Ok(r) => r,
            Err(_) => continue,
        };

        // Try to void-unmask and decrypt the shard block.
        let payload = match decrypt_block_masked(&key, &raw, master_secret, offset) {
            Ok(p) => p,
            Err(_) => continue, // Not a valid shard — skip.
        };

        // Extract the sss::Share from the payload.
        // Format: [4-byte share_len | share_data | zero padding]
        if payload.len() < 4 {
            continue;
        }
        let share_len = u32::from_le_bytes(payload[..4].try_into().unwrap()) as usize;
        if share_len == 0 || 4 + share_len > payload.len() {
            continue;
        }
        let share_data = payload[4..4 + share_len].to_vec();

        retrieved_shards.push(RetrievedShard {
            share: sss::Share::from_bytes(share_data),
            source_block: block_id,
        });

        // Claim offset so file writes don't overwrite our shard.
        image.claim_offset(offset);
    }

    // Need at least SHARD_K shards to reconstruct.
    if retrieved_shards.len() < SHARD_K {
        return Ok(None);
    }

    // Reconstruct the serialized superblock from shards.
    let serialized = match mesh.reconstruct_metadata(&retrieved_shards) {
        Ok(data) => data,
        Err(_) => return Ok(None),
    };

    // Deserialize.
    match deserialize_superblock(master_secret, &serialized) {
        Ok(sb) => Ok(Some(sb)),
        Err(DarkError::InvalidMagic) => Ok(None),
        Err(e) => Err(e),
    }
}

/// Shard, encrypt, and write the superblock to the image.
///
/// Serializes the superblock, splits it into 9 shards (needing 5 to
/// reconstruct), encrypts each shard, and writes them to HMAC-derived
/// positions across the image.
pub fn write_superblock(
    image: &mut ImageFile,
    master_secret: &[u8; 32],
    sb: &Superblock,
) -> DarkResult<()> {
    // Minimum image size: need at least SHARD_N blocks for shards
    // plus some blocks for file data.
    const MIN_BLOCKS: u64 = (SHARD_N as u64) + 16; // 9 shards + 16 blocks minimum
    if image.total_blocks() < MIN_BLOCKS {
        return Err(DarkError::InvalidImageSize {
            size: image.total_blocks() * crate::util::constants::BLOCK_SIZE as u64,
            block_size: crate::util::constants::BLOCK_SIZE,
        });
    }

    let mesh = create_mesh(image.total_blocks());
    let key = derive_superblock_key(master_secret)?;
    let qsmm_key = to_qsmm_key(master_secret);
    let hw_entropy = b"darkfs-mesh-entropy";

    // Serialize the superblock.
    let serialized = serialize_superblock(master_secret, sb)?;

    // Shard it via QSMM.
    let placements = mesh
        .shard_metadata(&serialized, &qsmm_key, hw_entropy)
        .map_err(|e| {
            DarkError::Io(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("mesh shard failed: {e}"),
            ))
        })?;

    // Encrypt and write each shard.
    for placement in &placements {
        let offset = placement.target_block.0;
        let share_bytes = placement.share.to_bytes();

        // Pack share into a PAYLOAD_SIZE buffer: [4-byte len | share_data | zero padding]
        let mut payload = [0u8; PAYLOAD_SIZE];
        let share_len = share_bytes.len() as u32;
        payload[..4].copy_from_slice(&share_len.to_le_bytes());
        payload[4..4 + share_bytes.len()].copy_from_slice(share_bytes);

        let encrypted = encrypt_block_masked(&key, &payload, master_secret, offset)?;
        image.write_block(offset, &encrypted)?;
        image.claim_offset(offset);
    }

    // DA-7: Write decoy blocks to mask shard positions in multi-snapshot analysis.
    // Without decoys, an adversary can identify the 9 shard positions by observing
    // which blocks change on every superblock update.
    let total = image.total_blocks();
    let decoy_count = 7u64;
    let mut rng = rand::thread_rng();
    for _ in 0..decoy_count {
        let idx = rand::Rng::gen_range(&mut rng, 0..total);
        if !image.is_offset_claimed(idx) {
            let mut noise = [0u8; crate::util::constants::BLOCK_SIZE];
            rand::RngCore::fill_bytes(&mut rng, &mut noise);
            let _ = image.write_block(idx, &noise);
        }
    }

    Ok(())
}

/// Compute a path hash for the slot map.
pub fn path_hash(secret: &[u8; 32], canonical_path: &str) -> u64 {
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(b"darkfs-path-hash");
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
        let mut serialized = serialize_superblock(&master, &sb).unwrap();

        // Tamper with a byte in the salt region.
        serialized[10] ^= 0xFF;

        let result = deserialize_superblock(&master, &serialized);
        assert!(matches!(result, Err(DarkError::SuperblockCorrupt)));
    }

    #[test]
    fn shards_claim_offsets() {
        let (_tmp, mut img) = create_test_image(256);
        let master = [42u8; 32];

        let sb = Superblock::new();
        write_superblock(&mut img, &master, &sb).unwrap();

        // All 9 shard positions should be claimed.
        let mesh = create_mesh(img.total_blocks());
        let locations = mesh.shard_locations(&to_qsmm_key(&master), b"darkfs-mesh-entropy");
        for loc in &locations {
            assert!(
                img.is_offset_claimed(loc.0),
                "shard at offset {} should be claimed",
                loc.0
            );
        }
    }

    #[test]
    fn survives_corrupted_shards() {
        let (_tmp, mut img) = create_test_image(256);
        let master = [42u8; 32];

        let mut sb = Superblock::new();
        sb.generation = 42;
        sb.file_count = 7;
        write_superblock(&mut img, &master, &sb).unwrap();

        // Corrupt 4 of 9 shards (should still reconstruct from remaining 5).
        let mesh = create_mesh(img.total_blocks());
        let locations = mesh.shard_locations(&to_qsmm_key(&master), b"darkfs-mesh-entropy");
        let mut noise = [0u8; BLOCK_SIZE];
        for loc in locations.iter().take(4) {
            rand::thread_rng().fill_bytes(&mut noise);
            img.write_block(loc.0, &noise).unwrap();
        }

        let read_back = read_superblock(&mut img, &master).unwrap().unwrap();
        assert_eq!(read_back.generation, 42);
        assert_eq!(read_back.file_count, 7);
    }

    #[test]
    fn five_corrupted_shards_returns_none() {
        let (_tmp, mut img) = create_test_image(256);
        let master = [42u8; 32];

        let sb = Superblock::new();
        write_superblock(&mut img, &master, &sb).unwrap();

        // Corrupt 5 of 9 shards — only 4 remain, below threshold.
        let mesh = create_mesh(img.total_blocks());
        let locations = mesh.shard_locations(&to_qsmm_key(&master), b"darkfs-mesh-entropy");
        let mut noise = [0u8; BLOCK_SIZE];
        for loc in locations.iter().take(5) {
            rand::thread_rng().fill_bytes(&mut noise);
            img.write_block(loc.0, &noise).unwrap();
        }

        assert!(read_superblock(&mut img, &master).unwrap().is_none());
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

        sb.record_slot(111, 0, 4);
        assert_eq!(sb.lookup_slot(111, 0), Some(4));

        sb.remove_path(111);
        assert_eq!(sb.lookup_slot(111, 0), None);
        assert_eq!(sb.lookup_slot(111, 1), None);
        assert_eq!(sb.lookup_slot(222, 0), Some(1));
    }

    #[test]
    fn path_hash_deterministic() {
        let secret = [42u8; 32];
        assert_eq!(path_hash(&secret, "/foo"), path_hash(&secret, "/foo"));
    }

    #[test]
    fn path_hash_differs_for_different_paths() {
        let secret = [42u8; 32];
        assert_ne!(path_hash(&secret, "/foo"), path_hash(&secret, "/bar"));
    }
}
