//! Integration test: two passphrases on the same image, no interference.

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
fn two_users_independent_files() {
    let (_tmp, mut img) = create_random_image(512);
    let image_size = img.total_blocks() * BLOCK_SIZE as u64;

    let secret_a = derive_master_secret(b"user-a-passphrase", image_size, KdfPreset::Dev).unwrap();
    let secret_b = derive_master_secret(b"user-b-passphrase", image_size, KdfPreset::Dev).unwrap();

    // User A writes files
    write_file(&mut img, &secret_a, "/docs/notes.txt", b"Alice's notes").unwrap();
    write_file(&mut img, &secret_a, "/secret.key", b"alice-key-data").unwrap();

    // User B writes files (different virtual paths, same image)
    write_file(&mut img, &secret_b, "/data/report.csv", b"Bob's report").unwrap();
    write_file(&mut img, &secret_b, "/passwords.txt", b"bob-passwords").unwrap();

    // User A can read their files
    assert_eq!(
        read_file(&mut img, &secret_a, "/docs/notes.txt")
            .unwrap()
            .as_deref(),
        Some(b"Alice's notes".as_slice())
    );
    assert_eq!(
        read_file(&mut img, &secret_a, "/secret.key")
            .unwrap()
            .as_deref(),
        Some(b"alice-key-data".as_slice())
    );

    // User A cannot see User B's files
    assert_eq!(
        read_file(&mut img, &secret_a, "/data/report.csv").unwrap(),
        None
    );
    assert_eq!(
        read_file(&mut img, &secret_a, "/passwords.txt").unwrap(),
        None
    );

    // User B can read their files
    assert_eq!(
        read_file(&mut img, &secret_b, "/data/report.csv")
            .unwrap()
            .as_deref(),
        Some(b"Bob's report".as_slice())
    );
    assert_eq!(
        read_file(&mut img, &secret_b, "/passwords.txt")
            .unwrap()
            .as_deref(),
        Some(b"bob-passwords".as_slice())
    );

    // User B cannot see User A's files
    assert_eq!(
        read_file(&mut img, &secret_b, "/docs/notes.txt").unwrap(),
        None
    );
    assert_eq!(read_file(&mut img, &secret_b, "/secret.key").unwrap(), None);
}

#[test]
fn same_virtual_path_different_users() {
    let (_tmp, mut img) = create_random_image(512);
    let image_size = img.total_blocks() * BLOCK_SIZE as u64;

    let secret_a = derive_master_secret(b"user-a", image_size, KdfPreset::Dev).unwrap();
    let secret_b = derive_master_secret(b"user-b", image_size, KdfPreset::Dev).unwrap();

    // Both users write to the same virtual path
    write_file(&mut img, &secret_a, "/shared.txt", b"Alice's version").unwrap();
    write_file(&mut img, &secret_b, "/shared.txt", b"Bob's version").unwrap();

    // Each sees their own version
    assert_eq!(
        read_file(&mut img, &secret_a, "/shared.txt")
            .unwrap()
            .as_deref(),
        Some(b"Alice's version".as_slice())
    );
    assert_eq!(
        read_file(&mut img, &secret_b, "/shared.txt")
            .unwrap()
            .as_deref(),
        Some(b"Bob's version".as_slice())
    );
}
