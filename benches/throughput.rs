//! Throughput benchmarks for darkfs cryptographic primitives and file I/O.
//!
//! Run with: `cargo bench`

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use rand::RngCore;
use tempfile::NamedTempFile;

use darkfs::crypto::cipher::{decrypt_block, encrypt_block};
use darkfs::crypto::kdf::{derive_master_secret, KdfPreset};
use darkfs::crypto::keys::derive_block_key;
use darkfs::crypto::locator::{block_offset, canonical_path};
use darkfs::fs::file::{read_file, write_file};
use darkfs::store::image::ImageFile;
use darkfs::util::constants::{BLOCK_SIZE, PAYLOAD_SIZE};

fn create_random_image(num_blocks: u64) -> (NamedTempFile, ImageFile) {
    let tmp = NamedTempFile::new().expect("create tempfile");
    let size = num_blocks * BLOCK_SIZE as u64;
    let mut buf = vec![0u8; size as usize];
    rand::thread_rng().fill_bytes(&mut buf);
    std::io::Write::write_all(&mut tmp.as_file(), &buf).unwrap();
    let img = ImageFile::open(tmp.path()).unwrap();
    (tmp, img)
}

fn bench_kdf(c: &mut Criterion) {
    c.bench_function("kdf_dev", |b| {
        b.iter(|| {
            derive_master_secret(
                black_box(b"benchmark-passphrase"),
                black_box(64 * 1024 * 1024),
                KdfPreset::Dev,
            )
            .unwrap()
        })
    });
}

fn bench_encrypt_decrypt(c: &mut Criterion) {
    let key = [42u8; 32];
    let mut plaintext = [0u8; PAYLOAD_SIZE];
    rand::thread_rng().fill_bytes(&mut plaintext);

    let mut group = c.benchmark_group("block_cipher");
    group.throughput(Throughput::Bytes(PAYLOAD_SIZE as u64));

    group.bench_function("encrypt", |b| {
        b.iter(|| encrypt_block(black_box(&key), black_box(&plaintext)))
    });

    let encrypted = encrypt_block(&key, &plaintext).unwrap();
    group.bench_function("decrypt", |b| {
        b.iter(|| decrypt_block(black_box(&key), black_box(&encrypted)))
    });

    group.finish();
}

fn bench_key_derivation(c: &mut Criterion) {
    let secret = [42u8; 32];
    c.bench_function("hkdf_block_key", |b| {
        b.iter(|| {
            derive_block_key(
                black_box(&secret),
                black_box("/bench/file.txt"),
                black_box(0),
            )
        })
    });
}

fn bench_locator(c: &mut Criterion) {
    let secret = [42u8; 32];
    c.bench_function("block_offset", |b| {
        b.iter(|| {
            block_offset(
                black_box(&secret),
                black_box("/bench/file.txt"),
                black_box(0),
                black_box(0),
                black_box(16384),
            )
        })
    });

    c.bench_function("canonical_path", |b| {
        b.iter(|| canonical_path(black_box("//foo//bar//baz//")))
    });
}

fn bench_file_throughput(c: &mut Criterion) {
    let secret = [42u8; 32];

    let sizes: Vec<(String, usize)> = vec![
        ("1KB".into(), 1024),
        ("4KB".into(), 4096),
        ("16KB".into(), 16 * 1024),
        ("64KB".into(), 64 * 1024),
    ];

    let mut group = c.benchmark_group("file_write");
    for (label, size) in &sizes {
        let mut data = vec![0u8; *size];
        rand::thread_rng().fill_bytes(&mut data);
        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(BenchmarkId::new("write", label), size, |b, &size| {
            let (_tmp, mut img) = create_random_image(4096);
            let data = vec![0xAB; size];
            b.iter(|| {
                write_file(
                    black_box(&mut img),
                    black_box(&secret),
                    black_box("/bench.dat"),
                    black_box(&data),
                )
                .unwrap()
            })
        });
    }
    group.finish();

    let mut group = c.benchmark_group("file_read");
    for (label, size) in &sizes {
        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(BenchmarkId::new("read", label), size, |b, &size| {
            let (_tmp, mut img) = create_random_image(4096);
            let data = vec![0xAB; size];
            write_file(&mut img, &secret, "/bench.dat", &data).unwrap();
            b.iter(|| {
                read_file(
                    black_box(&mut img),
                    black_box(&secret),
                    black_box("/bench.dat"),
                )
                .unwrap()
            })
        });
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_kdf,
    bench_encrypt_decrypt,
    bench_key_derivation,
    bench_locator,
    bench_file_throughput,
);
criterion_main!(benches);
