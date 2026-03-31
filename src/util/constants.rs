//! Global constants for the voidfs filesystem.

/// Size of a single block on disk, in bytes.
pub const BLOCK_SIZE: usize = 4096;

/// Size of the Poly1305 authentication tag, in bytes.
pub const TAG_SIZE: usize = 16;

/// Size of the plaintext payload within a single block (BLOCK_SIZE - TAG_SIZE - NONCE_SIZE).
/// Each block stores: [24-byte random nonce | ciphertext | 16-byte auth tag].
pub const PAYLOAD_SIZE: usize = BLOCK_SIZE - TAG_SIZE - NONCE_SIZE;

/// Maximum number of slot candidates for cuckoo-style collision resolution.
pub const MAX_SLOTS: u32 = 5;

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
