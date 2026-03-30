//! Integration test: slot collision handling on a small image.

use rand::RngCore;
use tempfile::NamedTempFile;
use voidfs::fs::file::{read_file, write_file};
use voidfs::store::image::ImageFile;
use voidfs::util::constants::BLOCK_SIZE;

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
fn multiple_small_files_on_small_image() {
    // 32 blocks is deliberately small to increase collision probability.
    // With MAX_SLOTS=5, we should still be able to store several single-block files.
    let (_tmp, mut img) = create_random_image(32);
    let secret = [42u8; 32];

    let mut written = Vec::new();

    // Write 8 small files
    for i in 0..8 {
        let path = format!("/file_{i}.txt");
        let content = format!("content of file {i}");
        write_file(&mut img, &secret, &path, content.as_bytes()).unwrap();
        written.push((path, content));
    }

    // Read them all back — some may have been overwritten by collisions,
    // but most should survive
    let mut readable = 0;
    for (path, expected) in &written {
        if let Some(data) = read_file(&mut img, &secret, path).unwrap() {
            assert_eq!(
                std::str::from_utf8(&data).unwrap(),
                expected,
                "file {path} has wrong content"
            );
            readable += 1;
        }
    }

    // With 32 blocks and 8 single-block files (each needing 1 block),
    // even with collisions most should be readable
    assert!(
        readable >= 4,
        "only {readable}/8 files readable — collision rate too high"
    );
}

#[test]
fn overwrite_same_file() {
    let (_tmp, mut img) = create_random_image(64);
    let secret = [42u8; 32];

    // Write, overwrite, verify latest version
    write_file(&mut img, &secret, "/test.txt", b"version 1").unwrap();
    write_file(&mut img, &secret, "/test.txt", b"version 2").unwrap();

    let data = read_file(&mut img, &secret, "/test.txt").unwrap();
    assert_eq!(data.as_deref(), Some(b"version 2".as_slice()));
}
