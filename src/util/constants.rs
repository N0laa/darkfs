//! Global constants for the voidfs filesystem.

/// Size of a single block on disk, in bytes.
pub const BLOCK_SIZE: usize = 4096;

/// Size of the Poly1305 authentication tag, in bytes.
pub const TAG_SIZE: usize = 16;

/// Size of the plaintext payload within a single block (BLOCK_SIZE - TAG_SIZE - NONCE_SIZE).
/// Each block stores: [24-byte random nonce | ciphertext | 16-byte auth tag].
pub const PAYLOAD_SIZE: usize = BLOCK_SIZE - TAG_SIZE - NONCE_SIZE;

/// Maximum number of slot candidates for cuckoo-style collision resolution.
///
/// Higher values allow more files on the image (higher fill rate) at the cost
/// of slightly slower writes (more slots to scan). With 16 slots, practical
/// fill rate is ~50-60% before slot exhaustion becomes likely.
pub const MAX_SLOTS: u32 = 16;

/// Magic bytes in the file header that confirm successful decryption.
/// ASCII "VO1DF5" followed by two null bytes.
pub const MAGIC: [u8; 8] = [0x56, 0x4F, 0x31, 0x44, 0x46, 0x35, 0x00, 0x00];

/// Size of the [`FileHeader`] struct when serialized, in bytes.
pub const HEADER_SIZE: usize = 64;

/// Usable data bytes in block 0 of a file (payload minus header).
pub const DATA_IN_BLOCK0: usize = PAYLOAD_SIZE - HEADER_SIZE;

/// Usable data bytes in blocks 1..N of a file (full payload).
pub const DATA_IN_BLOCKN: usize = PAYLOAD_SIZE;

/// Size of an encryption key, in bytes.
pub const KEY_SIZE: usize = 32;

/// Size of an XChaCha20 nonce, in bytes.
pub const NONCE_SIZE: usize = 24;

/// Read padding tiers: each `read_file` is padded to the next tier's block
/// count with dummy reads, preventing timing attacks from revealing exact file
/// size. An observer learns only which tier (1 of 4) a file falls into.
pub const READ_TIERS: [u64; 4] = [1, 16, 256, 4096];

/// Return the padded block count for timing-safe reads.
///
/// Rounds `actual_blocks` up to the next tier boundary. Files larger than the
/// largest tier are capped (their timing already reveals "very large file").
pub fn tier_block_count(actual_blocks: u32) -> u64 {
    let n = actual_blocks as u64;
    for &tier in &READ_TIERS {
        if n <= tier {
            return tier;
        }
    }
    // Larger than the biggest tier — just use actual count (no meaningful padding)
    n
}

/// Maximum number of entries in a single-block superblock slot map.
///
/// Each entry is 13 bytes (8-byte path hash + 4-byte block_num + 1-byte slot index).
/// Payload budget: PAYLOAD_SIZE - 52 (header) - 4 (entry_count) - 32 (integrity)
///   = 4056 - 88 = 3968 bytes → 3968 / 13 = 305 entries.
pub const SUPERBLOCK_MAX_ENTRIES: usize = 305;
