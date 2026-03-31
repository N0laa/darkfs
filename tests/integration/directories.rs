//! Integration tests for directory operations.

use darkfs::fs::directory::FileType;
use darkfs::fs::ops::{
    create_file, delete_file, list_dir, mkdir, read_file_data, rmdir, rmdir_recursive, stat,
};
use darkfs::util::errors::DarkError;

use crate::common::create_random_image;

#[test]
fn create_and_read_file() {
    let (_tmp, mut img) = create_random_image(1024);
    let secret = [42u8; 32];

    create_file(&mut img, &secret, "/hello.txt", b"hello world").unwrap();
    let data = read_file_data(&mut img, &secret, "/hello.txt")
        .unwrap()
        .unwrap();
    assert_eq!(&*data, b"hello world");
}

#[test]
fn create_file_updates_parent_dirindex() {
    let (_tmp, mut img) = create_random_image(1024);
    let secret = [42u8; 32];

    create_file(&mut img, &secret, "/a.txt", b"aaa").unwrap();
    create_file(&mut img, &secret, "/b.txt", b"bbb").unwrap();

    let root = list_dir(&mut img, &secret, "/").unwrap();
    assert_eq!(root.entries.len(), 2);
    assert!(root.contains("a.txt"));
    assert!(root.contains("b.txt"));
    assert_eq!(root.get_type("a.txt"), Some(FileType::File));
}

#[test]
fn mkdir_and_list() {
    let (_tmp, mut img) = create_random_image(1024);
    let secret = [42u8; 32];

    mkdir(&mut img, &secret, "/docs").unwrap();

    let root = list_dir(&mut img, &secret, "/").unwrap();
    assert!(root.contains("docs"));
    assert_eq!(root.get_type("docs"), Some(FileType::Directory));

    // New dir should be empty
    let docs = list_dir(&mut img, &secret, "/docs").unwrap();
    assert!(docs.entries.is_empty());
}

#[test]
fn nested_directories() {
    let (_tmp, mut img) = create_random_image(2048);
    let secret = [42u8; 32];

    mkdir(&mut img, &secret, "/a").unwrap();
    mkdir(&mut img, &secret, "/a/b").unwrap();
    mkdir(&mut img, &secret, "/a/b/c").unwrap();
    create_file(&mut img, &secret, "/a/b/c/deep.txt", b"deep content").unwrap();

    // Verify the full path works
    let data = read_file_data(&mut img, &secret, "/a/b/c/deep.txt")
        .unwrap()
        .unwrap();
    assert_eq!(&*data, b"deep content");

    // Verify directory listings
    let a = list_dir(&mut img, &secret, "/a").unwrap();
    assert!(a.contains("b"));
    assert_eq!(a.get_type("b"), Some(FileType::Directory));

    let c = list_dir(&mut img, &secret, "/a/b/c").unwrap();
    assert!(c.contains("deep.txt"));
}

#[test]
fn delete_file_removes_data_and_index() {
    let (_tmp, mut img) = create_random_image(1024);
    let secret = [42u8; 32];

    create_file(&mut img, &secret, "/secret.txt", b"top secret").unwrap();

    // Verify it exists
    assert!(read_file_data(&mut img, &secret, "/secret.txt")
        .unwrap()
        .is_some());

    // Delete it
    delete_file(&mut img, &secret, "/secret.txt").unwrap();

    // Data should be gone
    assert_eq!(
        read_file_data(&mut img, &secret, "/secret.txt").unwrap(),
        None
    );

    // Should be removed from parent index
    let root = list_dir(&mut img, &secret, "/").unwrap();
    assert!(!root.contains("secret.txt"));
}

#[test]
fn delete_nonexistent_file_fails() {
    let (_tmp, mut img) = create_random_image(1024);
    let secret = [42u8; 32];

    let result = delete_file(&mut img, &secret, "/nope.txt");
    assert!(matches!(result, Err(DarkError::FileNotFound)));
}

#[test]
fn rmdir_empty() {
    let (_tmp, mut img) = create_random_image(1024);
    let secret = [42u8; 32];

    mkdir(&mut img, &secret, "/empty_dir").unwrap();
    rmdir(&mut img, &secret, "/empty_dir").unwrap();

    let root = list_dir(&mut img, &secret, "/").unwrap();
    assert!(!root.contains("empty_dir"));
}

#[test]
fn rmdir_nonempty_fails() {
    let (_tmp, mut img) = create_random_image(1024);
    let secret = [42u8; 32];

    mkdir(&mut img, &secret, "/stuff").unwrap();
    create_file(&mut img, &secret, "/stuff/file.txt", b"data").unwrap();

    let result = rmdir(&mut img, &secret, "/stuff");
    assert!(matches!(result, Err(DarkError::DirectoryNotEmpty { .. })));
}

#[test]
fn rmdir_root_fails() {
    let (_tmp, mut img) = create_random_image(1024);
    let secret = [42u8; 32];

    let result = rmdir(&mut img, &secret, "/");
    assert!(matches!(result, Err(DarkError::InvalidOperation { .. })));
}

#[test]
fn mkdir_duplicate_fails() {
    let (_tmp, mut img) = create_random_image(1024);
    let secret = [42u8; 32];

    mkdir(&mut img, &secret, "/mydir").unwrap();
    let result = mkdir(&mut img, &secret, "/mydir");
    assert!(matches!(result, Err(DarkError::AlreadyExists { .. })));
}

#[test]
fn stat_returns_metadata() {
    let (_tmp, mut img) = create_random_image(1024);
    let secret = [42u8; 32];

    create_file(&mut img, &secret, "/info.txt", b"hello").unwrap();
    let header = stat(&mut img, &secret, "/info.txt").unwrap().unwrap();
    assert_eq!(header.file_size, 5);
    assert_eq!(header.block_count, 1);
    assert_eq!(header.version, 1);
}

#[test]
fn stat_nonexistent_returns_none() {
    let (_tmp, mut img) = create_random_image(1024);
    let secret = [42u8; 32];

    assert_eq!(stat(&mut img, &secret, "/nope").unwrap(), None);
}

#[test]
fn rmdir_recursive_deletes_everything() {
    let (_tmp, mut img) = create_random_image(4096);
    let secret = [42u8; 32];

    mkdir(&mut img, &secret, "/project").unwrap();
    mkdir(&mut img, &secret, "/project/src").unwrap();
    create_file(&mut img, &secret, "/project/README.md", b"# Readme").unwrap();
    create_file(&mut img, &secret, "/project/src/main.rs", b"fn main() {}").unwrap();
    create_file(
        &mut img,
        &secret,
        "/project/src/lib.rs",
        b"pub fn hello() {}",
    )
    .unwrap();

    // Verify structure exists
    let project = list_dir(&mut img, &secret, "/project").unwrap();
    assert_eq!(project.entries.len(), 2); // README.md + src

    // Recursive delete
    rmdir_recursive(&mut img, &secret, "/project").unwrap();

    // Everything should be gone
    let root = list_dir(&mut img, &secret, "/").unwrap();
    assert!(!root.contains("project"));

    assert_eq!(
        read_file_data(&mut img, &secret, "/project/README.md").unwrap(),
        None
    );
    assert_eq!(
        read_file_data(&mut img, &secret, "/project/src/main.rs").unwrap(),
        None
    );
}

#[test]
fn overwrite_file_preserves_dirindex() {
    let (_tmp, mut img) = create_random_image(1024);
    let secret = [42u8; 32];

    create_file(&mut img, &secret, "/data.bin", b"version 1").unwrap();
    create_file(&mut img, &secret, "/data.bin", b"version 2").unwrap();

    // Should still have exactly one entry, not duplicated
    let root = list_dir(&mut img, &secret, "/").unwrap();
    let count = root.entries.iter().filter(|e| e.name == "data.bin").count();
    assert_eq!(count, 1);

    // Should have the new data
    let data = read_file_data(&mut img, &secret, "/data.bin")
        .unwrap()
        .unwrap();
    assert_eq!(&*data, b"version 2");
}

#[test]
fn multiple_files_in_subdirectory() {
    let (_tmp, mut img) = create_random_image(2048);
    let secret = [42u8; 32];

    mkdir(&mut img, &secret, "/photos").unwrap();
    for i in 0..10 {
        let name = format!("/photos/img_{i:03}.jpg");
        let data = format!("fake jpeg data {i}");
        create_file(&mut img, &secret, &name, data.as_bytes()).unwrap();
    }

    let photos = list_dir(&mut img, &secret, "/photos").unwrap();
    assert_eq!(photos.entries.len(), 10);

    // Verify we can read them all back
    for i in 0..10 {
        let name = format!("/photos/img_{i:03}.jpg");
        let expected = format!("fake jpeg data {i}");
        let data = read_file_data(&mut img, &secret, &name).unwrap().unwrap();
        assert_eq!(&*data, expected.as_bytes());
    }
}
