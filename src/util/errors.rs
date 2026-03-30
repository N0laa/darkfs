//! Error types for voidfs.

/// The primary error type for all voidfs operations.
#[derive(Debug, thiserror::Error)]
pub enum VoidError {
    /// An I/O error occurred while reading or writing the image file.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Block index is beyond the image boundary.
    #[error("block index {index} out of range (total: {total})")]
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
    #[error("no available slot for path {path:?} block {block_num}")]
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
    #[error("corrupt file: block {block_num} missing for path {path:?}")]
    CorruptFile {
        /// The file path.
        path: String,
        /// The missing block number.
        block_num: u64,
    },

    /// The image file size is not a multiple of [`BLOCK_SIZE`].
    #[error("image size {size} is not a multiple of block size {block_size}")]
    InvalidImageSize {
        /// The actual file size.
        size: u64,
        /// The expected block size.
        block_size: usize,
    },

    /// A file or directory already exists at the given path.
    #[error("already exists: {path}")]
    AlreadyExists {
        /// The path that already exists.
        path: String,
    },

    /// The directory is not empty and cannot be removed.
    #[error("directory not empty: {path}")]
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
}

/// A convenience type alias for Results with [`VoidError`].
pub type VoidResult<T> = std::result::Result<T, VoidError>;
