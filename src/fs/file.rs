//! Multi-block file read and write operations.
//!
//! Files are split across multiple blocks. Block 0 contains a [`FileHeader`]
//! followed by up to [`DATA_IN_BLOCK0`] bytes of file data. Subsequent blocks
//! carry [`DATA_IN_BLOCKN`] bytes each.

use std::time::{SystemTime, UNIX_EPOCH};

use crate::crypto::locator::canonical_path;
use crate::fs::inode::FileHeader;
use crate::store::image::ImageFile;
use crate::store::slots::{read_slot, write_slot};
use crate::util::constants::{DATA_IN_BLOCK0, DATA_IN_BLOCKN, HEADER_SIZE, PAYLOAD_SIZE};
use crate::util::errors::{VoidError, VoidResult};

/// Maximum file size: limited by u32 block_count in the header.
/// 1 header block + (u32::MAX - 1) data blocks * 4080 bytes each.
const MAX_FILE_SIZE: u64 = DATA_IN_BLOCK0 as u64 + (u32::MAX as u64 - 1) * DATA_IN_BLOCKN as u64;

/// Compute the number of blocks needed to store `data_len` bytes.
fn compute_block_count(data_len: usize) -> VoidResult<u32> {
    if data_len as u64 > MAX_FILE_SIZE {
        return Err(VoidError::FileTooLarge {
            size: data_len as u64,
            max: MAX_FILE_SIZE,
        });
    }
    if data_len <= DATA_IN_BLOCK0 {
        Ok(1)
    } else {
        let remaining = data_len - DATA_IN_BLOCK0;
        Ok(1 + remaining.div_ceil(DATA_IN_BLOCKN) as u32)
    }
}

/// Write a file to the image at the given virtual path.
///
/// Writes data blocks 1..N first, then block 0 (with the header) last.
/// This ordering ensures that if the process crashes mid-write, the old
/// block 0 header remains intact, pointing to the old file's data. The
/// orphaned new blocks are harmless noise.
pub fn write_file(
    image: &mut ImageFile,
    master_secret: &[u8; 32],
    path: &str,
    data: &[u8],
) -> VoidResult<()> {
    let canon = canonical_path(path);
    let block_count = compute_block_count(data.len())?;

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    let header = FileHeader {
        version: 1,
        file_size: data.len() as u64,
        block_count,
        mode: 0o644,
        created_at: now,
        modified_at: now,
        accessed_at: now,
    };

    // Blocks 1..N first (pure data) — crash-safe ordering
    let data_in_b0 = data.len().min(DATA_IN_BLOCK0);
    let mut offset = data_in_b0;
    for block_num in 1..block_count as u64 {
        let mut payload = [0u8; PAYLOAD_SIZE];
        let chunk_end = (offset + DATA_IN_BLOCKN).min(data.len());
        let chunk_len = chunk_end - offset;
        payload[..chunk_len].copy_from_slice(&data[offset..offset + chunk_len]);

        write_slot(image, master_secret, &canon, block_num, &payload)?;
        offset += chunk_len;
    }

    // Block 0 last (header + first data chunk) — acts as commit marker
    let header_bytes = header.to_bytes();
    let mut payload0 = [0u8; PAYLOAD_SIZE];
    payload0[..HEADER_SIZE].copy_from_slice(&header_bytes);
    payload0[HEADER_SIZE..HEADER_SIZE + data_in_b0].copy_from_slice(&data[..data_in_b0]);

    write_slot(image, master_secret, &canon, 0, &payload0)?;

    Ok(())
}

/// Read a file from the image at the given virtual path.
///
/// Returns `Ok(None)` if the file does not exist (or the passphrase is wrong —
/// these are indistinguishable by design).
pub fn read_file(
    image: &mut ImageFile,
    master_secret: &[u8; 32],
    path: &str,
) -> VoidResult<Option<Vec<u8>>> {
    let canon = canonical_path(path);

    // Read block 0
    let payload0 = match read_slot(image, master_secret, &canon, 0)? {
        Some(p) => p,
        None => return Ok(None),
    };

    // Parse header
    let header_bytes: [u8; HEADER_SIZE] = payload0[..HEADER_SIZE]
        .try_into()
        .expect("slice is HEADER_SIZE");
    let header = match FileHeader::from_bytes(&header_bytes) {
        Ok(h) => h,
        Err(VoidError::InvalidMagic) => return Ok(None),
        Err(e) => return Err(e),
    };

    let file_size = header.file_size as usize;
    // Sanity check: file_size should not exceed what block_count can hold
    let max_for_blocks = if header.block_count <= 1 {
        DATA_IN_BLOCK0
    } else {
        DATA_IN_BLOCK0 + (header.block_count as usize - 1) * DATA_IN_BLOCKN
    };
    if file_size > max_for_blocks {
        return Ok(None); // corrupted header — treat as nonexistent
    }
    let mut result = Vec::with_capacity(file_size);

    // Data from block 0
    let data_in_b0 = file_size.min(DATA_IN_BLOCK0);
    result.extend_from_slice(&payload0[HEADER_SIZE..HEADER_SIZE + data_in_b0]);

    // Data from blocks 1..N
    for block_num in 1..header.block_count as u64 {
        let payload =
            read_slot(image, master_secret, &canon, block_num)?.ok_or(VoidError::CorruptFile {
                path: canon.clone(),
                block_num,
            })?;

        let remaining = file_size - result.len();
        let chunk_len = remaining.min(DATA_IN_BLOCKN);
        result.extend_from_slice(&payload[..chunk_len]);
    }

    Ok(Some(result))
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
        let mut buf = vec![0u8; size as usize];
        rand::thread_rng().fill_bytes(&mut buf);
        std::io::Write::write_all(&mut tmp.as_file(), &buf).unwrap();
        let img = ImageFile::open(tmp.path()).unwrap();
        (tmp, img)
    }

    #[test]
    fn block_count_small_file() {
        assert_eq!(compute_block_count(0).unwrap(), 1);
        assert_eq!(compute_block_count(1).unwrap(), 1);
        assert_eq!(compute_block_count(DATA_IN_BLOCK0).unwrap(), 1);
    }

    #[test]
    fn block_count_needs_two() {
        assert_eq!(compute_block_count(DATA_IN_BLOCK0 + 1).unwrap(), 2);
        assert_eq!(
            compute_block_count(DATA_IN_BLOCK0 + DATA_IN_BLOCKN).unwrap(),
            2
        );
    }

    #[test]
    fn block_count_needs_three() {
        assert_eq!(
            compute_block_count(DATA_IN_BLOCK0 + DATA_IN_BLOCKN + 1).unwrap(),
            3
        );
    }

    #[test]
    fn roundtrip_empty() {
        let (_tmp, mut img) = create_random_image(64);
        let secret = [42u8; 32];

        write_file(&mut img, &secret, "/empty", b"").unwrap();
        let data = read_file(&mut img, &secret, "/empty").unwrap();
        assert_eq!(data, Some(vec![]));
    }

    #[test]
    fn roundtrip_small() {
        let (_tmp, mut img) = create_random_image(64);
        let secret = [42u8; 32];
        let content = b"hello, voidfs!";

        write_file(&mut img, &secret, "/hello.txt", content).unwrap();
        let data = read_file(&mut img, &secret, "/hello.txt").unwrap();
        assert_eq!(data.as_deref(), Some(content.as_slice()));
    }

    #[test]
    fn roundtrip_exactly_block0() {
        let (_tmp, mut img) = create_random_image(64);
        let secret = [42u8; 32];
        let content = vec![0xAB; DATA_IN_BLOCK0];

        write_file(&mut img, &secret, "/exact", &content).unwrap();
        let data = read_file(&mut img, &secret, "/exact").unwrap();
        assert_eq!(data, Some(content));
    }

    #[test]
    fn roundtrip_two_blocks() {
        let (_tmp, mut img) = create_random_image(128);
        let secret = [42u8; 32];
        let content = vec![0xCD; DATA_IN_BLOCK0 + 1];

        write_file(&mut img, &secret, "/two", &content).unwrap();
        let data = read_file(&mut img, &secret, "/two").unwrap();
        assert_eq!(data, Some(content));
    }

    #[test]
    fn roundtrip_multi_block() {
        let (_tmp, mut img) = create_random_image(256);
        let secret = [42u8; 32];
        // ~20 KB = 5+ blocks
        let mut content = vec![0u8; 20_000];
        rand::thread_rng().fill_bytes(&mut content);

        write_file(&mut img, &secret, "/big", &content).unwrap();
        let data = read_file(&mut img, &secret, "/big").unwrap();
        assert_eq!(data, Some(content));
    }

    #[test]
    fn nonexistent_returns_none() {
        let (_tmp, mut img) = create_random_image(64);
        let secret = [42u8; 32];
        let data = read_file(&mut img, &secret, "/nope").unwrap();
        assert_eq!(data, None);
    }

    #[test]
    fn wrong_passphrase_returns_none() {
        let (_tmp, mut img) = create_random_image(64);
        let secret_a = [42u8; 32];
        let secret_b = [99u8; 32];

        write_file(&mut img, &secret_a, "/secret.txt", b"top secret").unwrap();
        let data = read_file(&mut img, &secret_b, "/secret.txt").unwrap();
        assert_eq!(data, None);
    }
}
