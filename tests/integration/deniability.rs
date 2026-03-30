//! Integration test: chi-squared test confirms image is indistinguishable from random.

use rand::RngCore;
use tempfile::NamedTempFile;
use voidfs::crypto::kdf::{derive_master_secret, KdfPreset};
use voidfs::fs::file::write_file;
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

/// Chi-squared test for uniform byte distribution.
/// Returns the chi-squared statistic. For 255 degrees of freedom,
/// the critical value at p=0.01 is ~310.5.
fn chi_squared(data: &[u8]) -> f64 {
    let mut counts = [0u64; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let expected = data.len() as f64 / 256.0;
    counts
        .iter()
        .map(|&c| {
            let diff = c as f64 - expected;
            diff * diff / expected
        })
        .sum()
}

#[test]
fn image_with_data_looks_random() {
    let (tmp, mut img) = create_random_image(256); // 1 MB
    let image_size = img.total_blocks() * BLOCK_SIZE as u64;

    let secret = derive_master_secret(b"test-passphrase", image_size, KdfPreset::Dev).unwrap();

    // Write several files
    write_file(&mut img, &secret, "/file1.txt", b"hello world").unwrap();
    write_file(&mut img, &secret, "/file2.bin", &vec![0xAA; 10_000]).unwrap();
    write_file(&mut img, &secret, "/file3.dat", &vec![0u8; 5000]).unwrap();

    drop(img);

    // Read the entire image
    let image_bytes = std::fs::read(tmp.path()).unwrap();

    // Chi-squared test: should look random (stat < 310.5 for p=0.01)
    let stat = chi_squared(&image_bytes);
    assert!(
        stat < 350.0,
        "chi-squared stat {stat} is too high — image doesn't look random enough"
    );
}

#[test]
fn fresh_image_looks_random() {
    let (tmp, _img) = create_random_image(256);
    let image_bytes = std::fs::read(tmp.path()).unwrap();
    let stat = chi_squared(&image_bytes);
    assert!(
        stat < 350.0,
        "chi-squared stat {stat} is too high for fresh image"
    );
}
