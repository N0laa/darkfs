//! File header (inode metadata) embedded in block 0 of every file.
//!
//! The header is exactly [`HEADER_SIZE`] (64) bytes and is placed at the start
//! of block 0's plaintext. The remaining bytes in block 0 carry file data.

use std::io::{Cursor, Write};

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};

use crate::util::constants::{HEADER_SIZE, MAGIC};
use crate::util::errors::DarkError;

/// Metadata for a single file, stored inline in block 0.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileHeader {
    /// Format version (currently 1).
    pub version: u8,
    /// Total file size in bytes.
    pub file_size: u64,
    /// Number of blocks (including block 0).
    pub block_count: u32,
    /// POSIX file permissions.
    pub mode: u32,
    /// Creation time (Unix timestamp, seconds).
    pub created_at: i64,
    /// Modification time (Unix timestamp, seconds).
    pub modified_at: i64,
    /// Access time (Unix timestamp, seconds).
    pub accessed_at: i64,
}

impl FileHeader {
    /// Serialize the header into exactly [`HEADER_SIZE`] bytes.
    ///
    /// Layout (little-endian):
    /// ```text
    /// [magic: 8] [version: 1] [reserved: 3] [file_size: 8] [block_count: 4]
    /// [mode: 4] [created_at: 8] [modified_at: 8] [accessed_at: 8] [padding: 12]
    /// = 64 bytes
    /// ```
    pub fn to_bytes(&self) -> [u8; HEADER_SIZE] {
        let mut buf = [0u8; HEADER_SIZE];
        let mut cursor = Cursor::new(&mut buf[..]);

        cursor.write_all(&MAGIC).unwrap();
        cursor.write_u8(self.version).unwrap();
        cursor.write_all(&[0u8; 3]).unwrap(); // reserved
        cursor.write_u64::<LittleEndian>(self.file_size).unwrap();
        cursor.write_u32::<LittleEndian>(self.block_count).unwrap();
        cursor.write_u32::<LittleEndian>(self.mode).unwrap();
        cursor.write_i64::<LittleEndian>(self.created_at).unwrap();
        cursor.write_i64::<LittleEndian>(self.modified_at).unwrap();
        cursor.write_i64::<LittleEndian>(self.accessed_at).unwrap();
        // 12 bytes padding (already zero)

        buf
    }

    /// Deserialize a header from exactly [`HEADER_SIZE`] bytes.
    ///
    /// Returns [`DarkError::InvalidMagic`] if the magic bytes don't match,
    /// which indicates a failed decryption (wrong passphrase) or corrupt data.
    pub fn from_bytes(data: &[u8; HEADER_SIZE]) -> Result<Self, DarkError> {
        let mut cursor = Cursor::new(data);

        let mut magic = [0u8; 8];
        std::io::Read::read_exact(&mut cursor, &mut magic).unwrap();
        if magic != MAGIC {
            return Err(DarkError::InvalidMagic);
        }

        let version = cursor.read_u8().unwrap();
        let mut _reserved = [0u8; 3];
        std::io::Read::read_exact(&mut cursor, &mut _reserved).unwrap();
        let file_size = cursor.read_u64::<LittleEndian>().unwrap();
        let block_count = cursor.read_u32::<LittleEndian>().unwrap();
        let mode = cursor.read_u32::<LittleEndian>().unwrap();
        let created_at = cursor.read_i64::<LittleEndian>().unwrap();
        let modified_at = cursor.read_i64::<LittleEndian>().unwrap();
        let accessed_at = cursor.read_i64::<LittleEndian>().unwrap();

        Ok(Self {
            version,
            file_size,
            block_count,
            mode,
            created_at,
            modified_at,
            accessed_at,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_header() -> FileHeader {
        FileHeader {
            version: 1,
            file_size: 12345,
            block_count: 4,
            mode: 0o644,
            created_at: 1700000000,
            modified_at: 1700000100,
            accessed_at: 1700000200,
        }
    }

    #[test]
    fn roundtrip() {
        let header = sample_header();
        let bytes = header.to_bytes();
        assert_eq!(bytes.len(), HEADER_SIZE);
        let parsed = FileHeader::from_bytes(&bytes).unwrap();
        assert_eq!(header, parsed);
    }

    #[test]
    fn magic_is_first_8_bytes() {
        let header = sample_header();
        let bytes = header.to_bytes();
        assert_eq!(&bytes[..8], &MAGIC);
    }

    #[test]
    fn invalid_magic_rejected() {
        let mut bytes = [0u8; HEADER_SIZE];
        bytes[0] = 0xFF; // corrupt magic
        let result = FileHeader::from_bytes(&bytes);
        assert!(matches!(result, Err(DarkError::InvalidMagic)));
    }

    #[test]
    fn zero_size_file() {
        let header = FileHeader {
            version: 1,
            file_size: 0,
            block_count: 1,
            mode: 0o644,
            created_at: 0,
            modified_at: 0,
            accessed_at: 0,
        };
        let bytes = header.to_bytes();
        let parsed = FileHeader::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.file_size, 0);
    }
}
