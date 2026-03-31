//! Integration test: two passphrases on the same image, no interference.

use darkfs::crypto::kdf::{derive_master_secret, KdfPreset};
use darkfs::fs::file::{read_file, write_file};
use darkfs::util::constants::BLOCK_SIZE;

use crate::common::create_random_image;

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
    let d = read_file(&mut img, &secret_a, "/docs/notes.txt").unwrap().unwrap();
    assert_eq!(&*d, b"Alice's notes");
    let d = read_file(&mut img, &secret_a, "/secret.key").unwrap().unwrap();
    assert_eq!(&*d, b"alice-key-data");

    // User A cannot see User B's files
    assert!(read_file(&mut img, &secret_a, "/data/report.csv").unwrap().is_none());
    assert!(read_file(&mut img, &secret_a, "/passwords.txt").unwrap().is_none());

    // User B can read their files
    let d = read_file(&mut img, &secret_b, "/data/report.csv").unwrap().unwrap();
    assert_eq!(&*d, b"Bob's report");
    let d = read_file(&mut img, &secret_b, "/passwords.txt").unwrap().unwrap();
    assert_eq!(&*d, b"bob-passwords");

    // User B cannot see User A's files
    assert!(read_file(&mut img, &secret_b, "/docs/notes.txt").unwrap().is_none());
    assert!(read_file(&mut img, &secret_b, "/secret.key").unwrap().is_none());
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
    let d = read_file(&mut img, &secret_a, "/shared.txt").unwrap().unwrap();
    assert_eq!(&*d, b"Alice's version");
    let d = read_file(&mut img, &secret_b, "/shared.txt").unwrap().unwrap();
    assert_eq!(&*d, b"Bob's version");
}
