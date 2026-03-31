//! Security-focused integration tests covering:
//! - Nonce reuse resistance (random nonces per write)
//! - Timing side-channel resistance (constant-time slot iteration)
//! - Collision tracking (no silent data loss)
//! - Path canonicalization and reserved name rejection
//! - Crash recovery (graceful error on corrupted blocks)
//! - Header structure leak resistance

use rand::RngCore;

use voidfs::crypto::cipher::decrypt_block;
use voidfs::crypto::kdf::{derive_master_secret, KdfPreset};
use voidfs::crypto::keys::derive_block_key;
use voidfs::crypto::locator::{block_offset, canonical_path};
use voidfs::fs::file::{read_file, write_file};
use voidfs::fs::ops::create_file;
use voidfs::store::image::ImageFile;
use voidfs::util::constants::*;

use crate::common::create_random_image;

// --- Nonce reuse resistance ---

#[test]
fn overwrite_produces_different_ciphertext() {
    let (tmp, mut img) = create_random_image(256);
    let secret = [42u8; 32];

    write_file(&mut img, &secret, "/reuse", b"version one content here").unwrap();
    drop(img);
    let snap1 = std::fs::read(tmp.path()).unwrap();

    let mut img = ImageFile::open(tmp.path()).unwrap();
    write_file(&mut img, &secret, "/reuse", b"version two content here").unwrap();
    drop(img);
    let snap2 = std::fs::read(tmp.path()).unwrap();

    // Find the changed block
    let mut changed = Vec::new();
    for b in 0..(snap1.len() / BLOCK_SIZE) {
        let s = b * BLOCK_SIZE;
        if snap1[s..s + BLOCK_SIZE] != snap2[s..s + BLOCK_SIZE] {
            changed.push(b);
        }
    }
    assert!(!changed.is_empty(), "overwrite should change at least one block");

    // Nonces (first 24 bytes) must differ
    let b = changed[0];
    let s = b * BLOCK_SIZE;
    assert_ne!(
        &snap1[s..s + NONCE_SIZE],
        &snap2[s..s + NONCE_SIZE],
        "nonces must differ across writes"
    );

    // XOR of ciphertext (after nonce) must be high-entropy — no plaintext leak
    let xor: Vec<u8> = (NONCE_SIZE..BLOCK_SIZE)
        .map(|i| snap1[s + i] ^ snap2[s + i])
        .collect();
    let entropy = shannon_entropy(&xor);
    assert!(
        entropy > 7.0,
        "ciphertext XOR entropy {entropy:.2} too low — possible nonce reuse"
    );
}

#[test]
fn same_content_same_key_produces_different_blocks() {
    let (_tmp, mut img) = create_random_image(256);
    let secret = [42u8; 32];

    // Write then overwrite with identical content — blocks must still differ on disk
    // because random nonces are used
    write_file(&mut img, &secret, "/same", b"identical").unwrap();

    let canon = canonical_path("/same");
    let total = img.total_blocks();
    let key = derive_block_key(&secret, &canon, 0).unwrap();

    // Find block 0
    let mut block_before = None;
    for slot in 0..MAX_SLOTS {
        let off = block_offset(&secret, &canon, 0, slot, total);
        let raw = img.read_block(off).unwrap();
        if decrypt_block(&key, &raw).is_ok() {
            block_before = Some(raw);
            break;
        }
    }
    let block_before = block_before.expect("should find block");

    // Overwrite with same content
    write_file(&mut img, &secret, "/same", b"identical").unwrap();

    let mut block_after = None;
    for slot in 0..MAX_SLOTS {
        let off = block_offset(&secret, &canon, 0, slot, total);
        let raw = img.read_block(off).unwrap();
        if decrypt_block(&key, &raw).is_ok() {
            block_after = Some(raw);
            break;
        }
    }
    let block_after = block_after.expect("should find block");

    // Random nonce means the on-disk block must differ
    assert_ne!(block_before, block_after, "same plaintext must produce different ciphertext");
}

// --- Timing side-channel resistance ---

#[test]
fn correct_and_wrong_passphrase_similar_timing() {
    let (_tmp, mut img) = create_random_image(256);
    let image_size = img.total_blocks() * BLOCK_SIZE as u64;

    let correct = derive_master_secret(b"correct", image_size, KdfPreset::Dev).unwrap();
    let wrong = derive_master_secret(b"wrong", image_size, KdfPreset::Dev).unwrap();

    write_file(&mut img, &correct, "/timing", b"secret").unwrap();

    // Warmup
    for _ in 0..10 {
        let _ = read_file(&mut img, &correct, "/timing");
        let _ = read_file(&mut img, &wrong, "/timing");
    }

    let n = 100;
    let mut ct = Vec::with_capacity(n);
    let mut wt = Vec::with_capacity(n);

    for _ in 0..n {
        let t = std::time::Instant::now();
        let _ = read_file(&mut img, &correct, "/timing");
        ct.push(t.elapsed().as_nanos() as f64);

        let t = std::time::Instant::now();
        let _ = read_file(&mut img, &wrong, "/timing");
        wt.push(t.elapsed().as_nanos() as f64);
    }

    let cm: f64 = ct.iter().sum::<f64>() / n as f64;
    let wm: f64 = wt.iter().sum::<f64>() / n as f64;
    let cs: f64 = (ct.iter().map(|&x| (x - cm).powi(2)).sum::<f64>() / (n - 1) as f64).sqrt();
    let ws: f64 = (wt.iter().map(|&x| (x - wm).powi(2)).sum::<f64>() / (n - 1) as f64).sqrt();

    let t_stat = (cm - wm) / ((cs * cs / n as f64) + (ws * ws / n as f64)).sqrt();

    // Allow |t| up to 3.0 — stricter than typical 2.0 but with margin for CI noise
    assert!(
        t_stat.abs() < 3.0,
        "timing difference significant: t={t_stat:.2}, correct={cm:.0}ns, wrong={wm:.0}ns"
    );
}

// --- Collision tracking ---

#[test]
fn collision_tracking_prevents_data_loss() {
    let (_tmp, mut img) = create_random_image(64);
    let secret = [42u8; 32];

    let mut written: Vec<(String, Vec<u8>)> = Vec::new();
    let mut failures = 0;

    for i in 0..200 {
        let path = format!("/f_{i}");
        let data = vec![(i & 0xFF) as u8; 100];
        match write_file(&mut img, &secret, &path, &data) {
            Ok(()) => written.push((path, data)),
            Err(_) => failures += 1,
        }
    }

    // Should have some rejections on a 64-block image
    assert!(failures > 0, "should have rejections on tiny image");

    // ALL successfully written files must be readable
    for (path, original) in &written {
        match read_file(&mut img, &secret, path) {
            Ok(Some(data)) => assert_eq!(&data, original, "{path} corrupted"),
            Ok(None) => panic!("{path} lost — collision tracking failed"),
            Err(e) => panic!("{path} error: {e}"),
        }
    }
}

#[test]
fn populate_claims_protects_across_sessions() {
    let (tmp, mut img) = create_random_image(64);
    let secret = [42u8; 32];

    // Write files in first session
    let mut written = Vec::new();
    for i in 0..20 {
        let path = format!("/pc_{i}");
        let data = vec![(i & 0xFF) as u8; 100];
        if write_file(&mut img, &secret, &path, &data).is_ok() {
            written.push((path, data));
        }
    }
    drop(img);

    // Open a new session, populate claims, then write more
    let mut img = ImageFile::open(tmp.path()).unwrap();
    // populate_claims walks dirindex which we didn't create (used write_file not create_file)
    // So verify the first session files are intact — read_slot claims offsets on success
    for (path, original) in &written {
        match read_file(&mut img, &secret, path) {
            Ok(Some(data)) => assert_eq!(&data, original, "{path} corrupted after reopen"),
            Ok(None) => panic!("{path} lost after reopen"),
            Err(e) => panic!("{path} error after reopen: {e}"),
        }
    }
    // read_slot claims offsets on success, so now new writes should avoid those offsets
    // Write more files — collision tracking (populated by reads above) should protect originals
    for i in 20..60 {
        let path = format!("/pc_{i}");
        let data = vec![(i & 0xFF) as u8; 100];
        let _ = write_file(&mut img, &secret, &path, &data);
    }
    // Original files should still be intact
    for (path, original) in &written {
        match read_file(&mut img, &secret, path) {
            Ok(Some(data)) => assert_eq!(&data, original, "{path} destroyed by second session writes"),
            other => panic!("{path} lost or errored: {other:?}"),
        }
    }
}

// --- Path canonicalization ---

#[test]
fn path_traversal_resolves_correctly() {
    assert_eq!(canonical_path("/foo/../bar"), "/bar");
    assert_eq!(canonical_path("/./test"), "/test");
    assert_eq!(canonical_path("//a//b//"), "/a/b");
    assert_eq!(canonical_path("/a/b/../../c"), "/c");
    assert_eq!(canonical_path("/../../../etc"), "/etc");
}

#[test]
fn reserved_name_dirindex_rejected() {
    let (_tmp, mut img) = create_random_image(256);
    let secret = [42u8; 32];

    let result = create_file(&mut img, &secret, "/.dirindex", b"malicious");
    assert!(result.is_err(), "creating .dirindex should be rejected");

    let result = create_file(&mut img, &secret, "/sub/.dirindex", b"malicious");
    assert!(result.is_err(), "creating /sub/.dirindex should be rejected");
}

#[test]
fn path_traversal_overwrites_same_file() {
    let (_tmp, mut img) = create_random_image(256);
    let secret = [42u8; 32];

    write_file(&mut img, &secret, "/target", b"original").unwrap();
    write_file(&mut img, &secret, "/sub/../target", b"overwritten").unwrap();

    let data = read_file(&mut img, &secret, "/target").unwrap();
    assert_eq!(data, Some(b"overwritten".to_vec()));
}

// --- Crash recovery ---

#[test]
fn corrupted_block_returns_error_not_panic() {
    let (_tmp, mut img) = create_random_image(1024);
    let secret = [42u8; 32];

    let file_size = DATA_IN_BLOCK0 + DATA_IN_BLOCKN * 4; // 5 blocks
    let mut data = vec![0u8; file_size];
    rand::thread_rng().fill_bytes(&mut data);
    write_file(&mut img, &secret, "/crash", &data).unwrap();

    // Verify pre-corruption read
    let readback = read_file(&mut img, &secret, "/crash").unwrap();
    assert_eq!(readback, Some(data));

    // Corrupt block 2
    let canon = canonical_path("/crash");
    let total = img.total_blocks();
    let key = derive_block_key(&secret, &canon, 2).unwrap();
    let mut corrupted = false;
    for slot in 0..MAX_SLOTS {
        let off = block_offset(&secret, &canon, 2, slot, total);
        let raw = img.read_block(off).unwrap();
        if decrypt_block(&key, &raw).is_ok() {
            let mut garbage = [0u8; BLOCK_SIZE];
            rand::thread_rng().fill_bytes(&mut garbage);
            img.write_block(off, &garbage).unwrap();
            corrupted = true;
            break;
        }
    }
    assert!(corrupted, "should find block 2");

    // Read should return an error, not panic
    let result = read_file(&mut img, &secret, "/crash");
    assert!(result.is_err(), "corrupted file should return error, not Ok");
}

// --- Header structure leak resistance ---

#[test]
fn ciphertext_bytes_show_no_bias_at_magic_positions() {
    let (_tmp, mut img) = create_random_image(4096);
    let secret = [42u8; 32];

    // Write 100 small files
    for i in 0..100 {
        write_file(&mut img, &secret, &format!("/b_{i:03}"), &vec![0xBB; 50]).unwrap();
    }

    // Collect ciphertext bytes at positions 0-7 (after nonce prefix) for each file's block 0
    let total = img.total_blocks();
    let mut samples: Vec<[u8; 8]> = Vec::new();
    for i in 0..100 {
        let canon = canonical_path(&format!("/b_{i:03}"));
        let key = derive_block_key(&secret, &canon, 0).unwrap();
        for slot in 0..MAX_SLOTS {
            let off = block_offset(&secret, &canon, 0, slot, total);
            let raw = img.read_block(off).unwrap();
            if decrypt_block(&key, &raw).is_ok() {
                let mut bytes = [0u8; 8];
                bytes.copy_from_slice(&raw[NONCE_SIZE..NONCE_SIZE + 8]);
                samples.push(bytes);
                break;
            }
        }
    }

    // Check each byte position for bias (z-test against uniform mean=127.5)
    for pos in 0..8 {
        let vals: Vec<f64> = samples.iter().map(|s| s[pos] as f64).collect();
        let n = vals.len() as f64;
        let mean: f64 = vals.iter().sum::<f64>() / n;
        let z = (mean - 127.5) / (73.9 / n.sqrt());
        assert!(
            z.abs() < 3.5,
            "byte position {pos} shows bias: mean={mean:.1}, z={z:.2}"
        );
    }
}

// --- Helper ---

fn shannon_entropy(data: &[u8]) -> f64 {
    let mut freq = [0u64; 256];
    for &b in data {
        freq[b as usize] += 1;
    }
    let n = data.len() as f64;
    freq.iter()
        .filter(|&&f| f > 0)
        .map(|&f| {
            let p = f as f64 / n;
            -p * p.log2()
        })
        .sum()
}
