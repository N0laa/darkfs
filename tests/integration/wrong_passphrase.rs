//! Integration test: wrong passphrase returns empty filesystem, no error.

use rand::RngCore;
use tempfile::NamedTempFile;
use voidfs::crypto::kdf::{derive_master_secret, KdfPreset};
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
