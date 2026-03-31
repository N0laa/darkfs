//! Integration test: wrong passphrase returns empty filesystem, no error.

use darkfs::crypto::kdf::{derive_master_secret, KdfPreset};
use darkfs::fs::file::{read_file, write_file};
use darkfs::util::constants::BLOCK_SIZE;

use crate::common::create_random_image;

#[test]
fn wrong_passphrase_returns_none() {
    let (_tmp, mut img) = create_random_image(128);
    let image_size = img.total_blocks() * BLOCK_SIZE as u64;

    let secret_a =
        derive_master_secret(b"correct-horse-battery-staple", image_size, KdfPreset::Dev).unwrap();
    let secret_b = derive_master_secret(b"wrong-passphrase", image_size, KdfPreset::Dev).unwrap();

    write_file(&mut img, &secret_a, "/secret.txt", b"top secret data").unwrap();

    // Wrong passphrase: should get None, not an error
    let result = read_file(&mut img, &secret_b, "/secret.txt").unwrap();
    assert_eq!(result, None);
}

#[test]
fn any_passphrase_shows_empty() {
    let (_tmp, mut img) = create_random_image(128);
    let image_size = img.total_blocks() * BLOCK_SIZE as u64;

    // Write nothing — fresh random image
    // Any passphrase should see "no files"
    let secret = derive_master_secret(b"random-passphrase", image_size, KdfPreset::Dev).unwrap();
    let result = read_file(&mut img, &secret, "/anything").unwrap();
    assert_eq!(result, None);
}
