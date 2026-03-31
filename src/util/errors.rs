//! Error types for darkfs.

/// The primary error type for all darkfs operations.
///
/// Display messages are intentionally redacted to avoid leaking internal state
/// (file paths, block offsets, image size). Use `Debug` formatting for diagnostics.
#[derive(Debug, thiserror::Error)]
pub enum DarkError {
    /// An I/O error occurred while reading or writing the image file.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Block index is beyond the image boundary.
    #[error("block index out of range")]
    BlockOutOfRange {
        /// The requested block index.
        index: u64,
        /// The total number of blocks in the image.
        total: u64,
    },

    /// Encryption failed.
    #[error("encryption failed")]
    Encrypt,

    /// Decryption failed (wrong key or corrupted data).
    #[error("decryption failed")]
    Decrypt,

    /// All slot candidates are occupied; the disk is effectively full.
    #[error("no available slot")]
    NoSlotAvailable {
        /// The file path that could not be written.
        path: String,
        /// The block number that could not be placed.
        block_num: u64,
    },

    /// The decrypted header did not contain the expected magic bytes.
    #[error("invalid header magic")]
    InvalidMagic,

    /// The requested file was not found (no block decrypted successfully).
    #[error("file not found")]
    FileNotFound,

    /// Key derivation failed.
    #[error("KDF error: {0}")]
    Kdf(String),

    /// A file's blocks are partially missing (likely overwritten by a collision).
    #[error("corrupt file: block missing")]
    CorruptFile {
        /// The file path.
        path: String,
        /// The missing block number.
        block_num: u64,
    },

    /// The image file size is not valid (zero or not a multiple of [`BLOCK_SIZE`]).
    #[error("invalid image size")]
    InvalidImageSize {
        /// The actual file size.
        size: u64,
        /// The expected block size.
        block_size: usize,
    },

    /// A file or directory already exists at the given path.
    #[error("already exists")]
    AlreadyExists {
        /// The path that already exists.
        path: String,
    },

    /// The directory is not empty and cannot be removed.
    #[error("directory not empty")]
    DirectoryNotEmpty {
        /// The non-empty directory.
        path: String,
    },

    /// An invalid or unsupported operation was requested.
    #[error("invalid operation: {reason}")]
    InvalidOperation {
        /// Why the operation is invalid.
        reason: String,
    },

    /// A reserved filename was used (e.g., `.dirindex`).
    #[error("reserved filename")]
    ReservedName {
        /// The reserved filename.
        name: String,
    },

    /// The file is too large to store.
    #[error("file too large")]
    FileTooLarge {
        /// The requested file size.
        size: u64,
        /// The maximum supported size.
        max: u64,
    },

    /// The image file is locked by another process.
    #[error("image is locked by another process")]
    ImageLocked,

    /// An invalid filename was provided.
    #[error("invalid filename")]
    InvalidName {
        /// Why the name is invalid.
        reason: String,
    },

    /// The superblock integrity check failed (corrupted or tampered).
    #[error("superblock integrity check failed")]
    SuperblockCorrupt,

    /// The superblock slot map is full.
    #[error("superblock full")]
    SuperblockFull {
        /// Maximum number of entries the superblock can hold.
        max_entries: usize,
    },

    /// The generation counter decreased, indicating a possible replay attack.
    #[error("generation mismatch")]
    GenerationMismatch {
        /// The expected minimum generation.
        expected: u64,
        /// The actual generation found.
        actual: u64,
    },
}

/// A convenience type alias for Results with [`DarkError`].
pub type DarkResult<T> = std::result::Result<T, DarkError>;
