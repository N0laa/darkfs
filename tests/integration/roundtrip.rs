//! Integration test: write file → read file roundtrip with various sizes.

use rand::RngCore;
use darkfs::crypto::kdf::{derive_master_secret, KdfPreset};
use darkfs::fs::file::{read_file, write_file};
use darkfs::util::constants::{BLOCK_SIZE, DATA_IN_BLOCK0, DATA_IN_BLOCKN};

use crate::common::create_random_image;

fn test_roundtrip(data_size: usize) {
    // Use a large image to minimize collision risk with multi-block files
    let (_tmp, mut img) = create_random_image(4096);
    let image_size = img.total_blocks() * BLOCK_SIZE as u64;
    let secret = derive_master_secret(b"test-passphrase-1", image_size, KdfPreset::Dev).unwrap();

    let mut data = vec![0u8; data_size];
    if data_size > 0 {
        rand::thread_rng().fill_bytes(&mut data);
    }

    write_file(&mut img, &secret, "/test/file.bin", &data).unwrap();
    let result = read_file(&mut img, &secret, "/test/file.bin").unwrap().unwrap();
    assert_eq!(&*result, &data);
}

#[test]
fn roundtrip_empty() {
    test_roundtrip(0);
}

#[test]
fn roundtrip_one_byte() {
    test_roundtrip(1);
}

#[test]
fn roundtrip_exactly_block0_data() {
    test_roundtrip(DATA_IN_BLOCK0);
}

#[test]
fn roundtrip_block0_plus_one() {
    test_roundtrip(DATA_IN_BLOCK0 + 1);
}

#[test]
fn roundtrip_exactly_two_blocks() {
    test_roundtrip(DATA_IN_BLOCK0 + DATA_IN_BLOCKN);
}

#[test]
fn roundtrip_large_multi_block() {
    // ~100 KB = ~25 blocks
    test_roundtrip(100_000);
}
