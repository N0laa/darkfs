//! Raw block read/write on image files.
//!
//! An [`ImageFile`] provides direct access to fixed-size blocks on the
//! underlying void image. All I/O is block-aligned.
//!
//! The `used_offsets` set tracks which block offsets are known to contain
//! data for the current session, preventing silent data loss from collisions.

use std::collections::HashSet;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

use fs2::FileExt;

use crate::util::constants::BLOCK_SIZE;
use crate::util::errors::{DarkError, DarkResult};

/// Handle to an open void image file for block-level I/O.
pub struct ImageFile {
    file: File,
    total_blocks: u64,
    /// Block offsets known to contain data for the current session.
    /// Prevents new writes from silently overwriting existing file blocks.
    used_offsets: HashSet<u64>,
}

impl ImageFile {
    /// Open an existing image file for reading and writing.
    ///
    /// Returns an error if the file size is not a multiple of [`BLOCK_SIZE`].
    pub fn open(path: &Path) -> DarkResult<Self> {
        let file = OpenOptions::new().read(true).write(true).open(path)?;
        let size = file.metadata()?.len();

        if size == 0 || size % BLOCK_SIZE as u64 != 0 {
            return Err(DarkError::InvalidImageSize {
                size,
                block_size: BLOCK_SIZE,
            });
        }

        // Acquire an exclusive advisory lock to prevent concurrent access.
        // The lock is released automatically when the File is dropped.
        file.try_lock_exclusive().map_err(|_| DarkError::ImageLocked)?;

        Ok(Self {
            file,
            total_blocks: size / BLOCK_SIZE as u64,
            used_offsets: HashSet::new(),
        })
    }

    /// The total number of blocks in this image.
    pub fn total_blocks(&self) -> u64 {
        self.total_blocks
    }

    /// Read a single block from the image.
    pub fn read_block(&mut self, index: u64) -> DarkResult<[u8; BLOCK_SIZE]> {
        if index >= self.total_blocks {
            return Err(DarkError::BlockOutOfRange {
                index,
                total: self.total_blocks,
            });
        }

        self.file.seek(SeekFrom::Start(index * BLOCK_SIZE as u64))?;
        let mut buf = [0u8; BLOCK_SIZE];
        self.file.read_exact(&mut buf)?;
        Ok(buf)
    }

    /// Write a single block to the image.
    pub fn write_block(&mut self, index: u64, data: &[u8; BLOCK_SIZE]) -> DarkResult<()> {
        if index >= self.total_blocks {
            return Err(DarkError::BlockOutOfRange {
                index,
                total: self.total_blocks,
            });
        }

        self.file.seek(SeekFrom::Start(index * BLOCK_SIZE as u64))?;
        self.file.write_all(data)?;
        self.file.flush()?;
        Ok(())
    }

    /// Mark a block offset as claimed by the current session.
    ///
    /// Prevents other writes from silently overwriting this block.
    pub fn claim_offset(&mut self, offset: u64) {
        self.used_offsets.insert(offset);
    }

    /// Check whether a block offset is already claimed.
    pub fn is_offset_claimed(&self, offset: u64) -> bool {
        self.used_offsets.contains(&offset)
    }

    /// Release a claimed block offset (e.g., after erasing).
    pub fn release_offset(&mut self, offset: u64) {
        self.used_offsets.remove(&offset);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::RngCore;
    use tempfile::NamedTempFile;

    fn create_test_image(num_blocks: u64) -> NamedTempFile {
        let tmp = NamedTempFile::new().expect("create tempfile");
        let size = num_blocks * BLOCK_SIZE as u64;
        tmp.as_file().set_len(size).expect("set file length");
        tmp
    }

    #[test]
    fn open_and_total_blocks() {
        let tmp = create_test_image(16);
        let img = ImageFile::open(tmp.path()).unwrap();
        assert_eq!(img.total_blocks(), 16);
    }

    #[test]
    fn reject_non_aligned_size() {
        let tmp = NamedTempFile::new().unwrap();
        tmp.as_file().set_len(4097).unwrap();
        let result = ImageFile::open(tmp.path());
        assert!(matches!(result, Err(DarkError::InvalidImageSize { .. })));
    }

    #[test]
    fn write_then_read() {
        let tmp = create_test_image(4);
        let mut img = ImageFile::open(tmp.path()).unwrap();

        let mut data = [0u8; BLOCK_SIZE];
        rand::thread_rng().fill_bytes(&mut data);

        img.write_block(2, &data).unwrap();
        let read_back = img.read_block(2).unwrap();
        assert_eq!(data, read_back);
    }

    #[test]
    fn out_of_range_read() {
        let tmp = create_test_image(4);
        let mut img = ImageFile::open(tmp.path()).unwrap();
        let result = img.read_block(4);
        assert!(matches!(result, Err(DarkError::BlockOutOfRange { .. })));
    }

    #[test]
    fn out_of_range_write() {
        let tmp = create_test_image(4);
        let mut img = ImageFile::open(tmp.path()).unwrap();
        let result = img.write_block(4, &[0u8; BLOCK_SIZE]);
        assert!(matches!(result, Err(DarkError::BlockOutOfRange { .. })));
    }

    #[test]
    fn claim_and_check_offset() {
        let tmp = create_test_image(4);
        let mut img = ImageFile::open(tmp.path()).unwrap();

        assert!(!img.is_offset_claimed(0));
        img.claim_offset(0);
        assert!(img.is_offset_claimed(0));
        img.release_offset(0);
        assert!(!img.is_offset_claimed(0));
    }
}
