//! stats-verify: Statistical verification that voidfs images are indistinguishable from random.
//!
//! Creates a voidfs image with ~100 files, then runs a battery of statistical tests
//! comparing it against a control image of pure /dev/urandom output.
//!
//! Usage:
//!   cargo run --bin stats-verify
//!   cargo run --bin stats-verify -- --image existing.img --control random.img
//!   cargo run --bin stats-verify -- --generate-only --image test.img --control ctrl.img

use std::collections::HashMap;
use std::fs::{self, File};
use std::io::Write;
use std::path::PathBuf;

use clap::Parser;
use rand::RngCore;

use voidfs::crypto::kdf::{derive_master_secret, KdfPreset};
use voidfs::fs::file::write_file;
use voidfs::store::image::ImageFile;
use voidfs::util::constants::BLOCK_SIZE;

// ─── CLI ─────────────────────────────────────────────────────────────────────

#[derive(Parser)]
#[command(
    name = "stats-verify",
    about = "Statistical verification of voidfs deniability"
)]
struct Cli {
    /// Path to a voidfs image (created if --generate-only or if missing with default)
    #[arg(long)]
    image: Option<PathBuf>,

    /// Path to a control random image (created if --generate-only or if missing with default)
    #[arg(long)]
    control: Option<PathBuf>,

    /// Only generate the images, don't run tests
    #[arg(long)]
    generate_only: bool,
}

// ─── Image generation ────────────────────────────────────────────────────────

const IMAGE_BLOCKS: u64 = 16384; // 64 MB
const _IMAGE_SIZE: u64 = IMAGE_BLOCKS * BLOCK_SIZE as u64;

fn create_random_image(path: &std::path::Path) {
    let mut file = File::create(path).expect("create image file");
    let mut rng = rand::thread_rng();
    let mut block = [0u8; BLOCK_SIZE];
    for _ in 0..IMAGE_BLOCKS {
        rng.fill_bytes(&mut block);
        file.write_all(&block).expect("write block");
    }
    file.flush().expect("flush");
}

fn create_voidfs_image(path: &std::path::Path) {
    // Start with a random image (like mkvoid)
    create_random_image(path);

    let mut img = ImageFile::open(path).expect("open image");
    let image_size = img.total_blocks() * BLOCK_SIZE as u64;
    let secret =
        derive_master_secret(b"stats-verify-passphrase", image_size, KdfPreset::Dev).unwrap();

    let mut rng = rand::thread_rng();

    // Write ~100 files of varying sizes
    let sizes: Vec<usize> = vec![
        // Tiny files
        0, 1, 2, 5, 10, 50, 100, 255, 256, 500, // Small files (within block 0 data area)
        1000, 2000, 3000, 4000, // Medium files (span 2+ blocks)
        5000, 8000, 10_000, 15_000, 20_000, // Larger files
        30_000, 50_000, 75_000, 100_000,
    ];

    let mut file_idx = 0;
    for &size in &sizes {
        for variant in 0..4 {
            let path_str = format!("/dir_{variant}/file_{file_idx}.dat");
            let mut data = vec![0u8; size];
            if size > 0 {
                rng.fill_bytes(&mut data);
            }
            write_file(&mut img, &secret, &path_str, &data).expect("write file");
            file_idx += 1;
        }
    }

    // Also write some files with specific byte patterns (worst case for entropy)
    write_file(&mut img, &secret, "/zeros.bin", &vec![0u8; 10_000]).unwrap();
    write_file(&mut img, &secret, "/ones.bin", &vec![0xFF; 10_000]).unwrap();
    write_file(
        &mut img,
        &secret,
        "/pattern.bin",
        &(0..10_000u32).map(|i| (i % 256) as u8).collect::<Vec<u8>>(),
    )
    .unwrap();
    write_file(&mut img, &secret, "/ascii.txt", b"Hello, this is a plain text file with predictable ASCII content. The quick brown fox jumps over the lazy dog. 0123456789 ABCDEFGHIJKLMNOPQRSTUVWXYZ abcdefghijklmnopqrstuvwxyz !@#$%^&*()").unwrap();

    println!("  Wrote {} files to voidfs image", file_idx + 4);
}

// ─── Test infrastructure ─────────────────────────────────────────────────────

struct TestResult {
    name: String,
    passed: bool,
    statistic: f64,
    threshold: f64,
    detail: String,
}

impl TestResult {
    fn display(&self) {
        let status = if self.passed { "PASS" } else { "FAIL" };
        println!(
            "  [{status}] {}: stat={:.4}, threshold={:.4} — {}",
            self.name, self.statistic, self.threshold, self.detail
        );
    }
}

// ─── Byte-level tests ────────────────────────────────────────────────────────

/// Chi-squared test on byte frequency distribution.
/// For 255 df, critical value at p=0.01 is ~310.5, at p=0.001 is ~341.4.
fn chi_squared_test(data: &[u8], label: &str) -> TestResult {
    let mut counts = [0u64; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let expected = data.len() as f64 / 256.0;
    let stat: f64 = counts
        .iter()
        .map(|&c| {
            let diff = c as f64 - expected;
            diff * diff / expected
        })
        .sum();

    // p=0.001 threshold for 255 df ≈ 341.4
    let threshold = 341.4;
    TestResult {
        name: format!("Chi-squared ({label})"),
        passed: stat < threshold,
        statistic: stat,
        threshold,
        detail: format!("df=255, expected uniform, n={}", data.len()),
    }
}

/// Kolmogorov-Smirnov test: max deviation of empirical CDF from uniform CDF.
fn ks_test(data: &[u8], label: &str) -> TestResult {
    let n = data.len() as f64;
    let mut counts = [0u64; 256];
    for &b in data {
        counts[b as usize] += 1;
    }

    let mut max_d: f64 = 0.0;
    let mut cumulative = 0.0;
    for (i, &count) in counts.iter().enumerate() {
        cumulative += count as f64 / n;
        let expected = (i + 1) as f64 / 256.0;
        let d = (cumulative - expected).abs();
        if d > max_d {
            max_d = d;
        }
    }

    // Critical value for KS test at p=0.01 with large n ≈ 1.628 / sqrt(n)
    // But for byte distributions (256 bins, not continuous), we use a looser bound
    let threshold = 2.0 / 256.0; // ~0.0078 — generous threshold
    TestResult {
        name: format!("Kolmogorov-Smirnov ({label})"),
        passed: max_d < threshold,
        statistic: max_d,
        threshold,
        detail: format!("max CDF deviation from uniform, n={}", data.len()),
    }
}

/// Mean byte value test (expected: ~127.5).
fn mean_byte_test(data: &[u8], label: &str) -> TestResult {
    let sum: f64 = data.iter().map(|&b| b as f64).sum();
    let mean = sum / data.len() as f64;
    let deviation = (mean - 127.5).abs();

    // For n=64MB, standard deviation of mean ≈ σ/√n ≈ 73.9/√(64M) ≈ 0.009
    // Allow 5σ deviation
    let threshold = 0.05;
    TestResult {
        name: format!("Mean byte value ({label})"),
        passed: deviation < threshold,
        statistic: mean,
        threshold: 127.5, // target value
        detail: format!("deviation from 127.5 = {deviation:.6}"),
    }
}

/// Serial correlation coefficient (expected: ~0.0 for random data).
fn serial_correlation_test(data: &[u8], label: &str) -> TestResult {
    let n = data.len() as f64;
    let mean: f64 = data.iter().map(|&b| b as f64).sum::<f64>() / n;

    let mut num = 0.0;
    let mut denom = 0.0;
    for i in 0..data.len() {
        let x = data[i] as f64 - mean;
        denom += x * x;
        if i + 1 < data.len() {
            let y = data[i + 1] as f64 - mean;
            num += x * y;
        }
    }

    let corr = if denom > 0.0 { num / denom } else { 0.0 };
    let threshold = 0.001; // very tight for 64MB of data
    TestResult {
        name: format!("Serial correlation ({label})"),
        passed: corr.abs() < threshold,
        statistic: corr,
        threshold,
        detail: "lag-1 autocorrelation coefficient".to_string(),
    }
}

// ─── Block-level tests ───────────────────────────────────────────────────────

/// Per-block Shannon entropy.
///
/// For 4096-byte blocks of truly random data, Shannon entropy is typically
/// ~7.95-7.97 bits/byte (below the theoretical max of 8.0 due to birthday-bound
/// byte collisions within each block). We check that no block has anomalously
/// low entropy, which would indicate structure leaking through encryption.
fn block_entropy_test(data: &[u8], label: &str) -> TestResult {
    let num_blocks = data.len() / BLOCK_SIZE;
    let mut min_entropy = f64::MAX;
    let mut min_block = 0;
    let mut suspiciously_low = 0; // count blocks below 7.85 (very unusual for random)

    for i in 0..num_blocks {
        let block = &data[i * BLOCK_SIZE..(i + 1) * BLOCK_SIZE];
        let entropy = shannon_entropy(block);
        if entropy < min_entropy {
            min_entropy = entropy;
            min_block = i;
        }
        if entropy < 7.85 {
            suspiciously_low += 1;
        }
    }

    // Minimum entropy for any single block of random data across 16K blocks
    // is typically ~7.91-7.94. Flag if it drops below 7.80.
    let threshold = 7.80;
    TestResult {
        name: format!("Block entropy ({label})"),
        passed: min_entropy > threshold && suspiciously_low == 0,
        statistic: min_entropy,
        threshold,
        detail: format!(
            "min at block {min_block}, {suspiciously_low}/{num_blocks} blocks below 7.85"
        ),
    }
}

fn shannon_entropy(data: &[u8]) -> f64 {
    let mut counts = [0u64; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let n = data.len() as f64;
    let mut entropy = 0.0;
    for &c in &counts {
        if c > 0 {
            let p = c as f64 / n;
            entropy -= p * p.log2();
        }
    }
    entropy
}

/// Block-to-block XOR hamming distance (expected: ~50% bits differ).
fn block_xor_test(data: &[u8], label: &str) -> TestResult {
    let num_blocks = data.len() / BLOCK_SIZE;
    let sample_count = 1000.min(num_blocks - 1);
    let mut total_ratio = 0.0;

    for i in 0..sample_count {
        let a = &data[i * BLOCK_SIZE..(i + 1) * BLOCK_SIZE];
        let b = &data[(i + 1) * BLOCK_SIZE..(i + 2) * BLOCK_SIZE];
        let differing_bits: u32 = a
            .iter()
            .zip(b.iter())
            .map(|(&x, &y)| (x ^ y).count_ones())
            .sum();
        total_ratio += differing_bits as f64 / (BLOCK_SIZE as f64 * 8.0);
    }

    let avg_ratio = total_ratio / sample_count as f64;
    let deviation = (avg_ratio - 0.5).abs();
    let threshold = 0.005; // within 0.5% of 50%
    TestResult {
        name: format!("Block XOR hamming ({label})"),
        passed: deviation < threshold,
        statistic: avg_ratio,
        threshold: 0.5,
        detail: format!("avg bit-difference ratio (target: 0.5), deviation={deviation:.6}"),
    }
}

/// Auto-correlation at various block lags (expected: ~0.0).
fn block_autocorrelation_test(data: &[u8], label: &str) -> TestResult {
    let num_blocks = data.len() / BLOCK_SIZE;
    let lags = [1, 2, 4, 8];
    let mut max_corr: f64 = 0.0;
    let mut worst_lag = 0;

    // Use first byte of each block as a simple proxy
    let block_vals: Vec<f64> = (0..num_blocks)
        .map(|i| data[i * BLOCK_SIZE] as f64)
        .collect();
    let mean: f64 = block_vals.iter().sum::<f64>() / block_vals.len() as f64;
    let var: f64 = block_vals
        .iter()
        .map(|&x| (x - mean) * (x - mean))
        .sum::<f64>();

    for &lag in &lags {
        if lag >= num_blocks {
            continue;
        }
        let cov: f64 = (0..num_blocks - lag)
            .map(|i| (block_vals[i] - mean) * (block_vals[i + lag] - mean))
            .sum();
        let corr = if var > 0.0 { (cov / var).abs() } else { 0.0 };
        if corr > max_corr {
            max_corr = corr;
            worst_lag = lag;
        }
    }

    let threshold = 0.02;
    TestResult {
        name: format!("Block autocorrelation ({label})"),
        passed: max_corr < threshold,
        statistic: max_corr,
        threshold,
        detail: format!("max correlation at lag {worst_lag}, tested lags: {lags:?}"),
    }
}

/// Duplicate block detection (expected: 0 duplicates in random data).
fn duplicate_block_test(data: &[u8], label: &str) -> TestResult {
    let num_blocks = data.len() / BLOCK_SIZE;

    // Hash each block and check for duplicates
    let mut seen = HashMap::new();
    let mut duplicates = 0;

    for i in 0..num_blocks {
        let block = &data[i * BLOCK_SIZE..(i + 1) * BLOCK_SIZE];
        // Use first 16 bytes as a fingerprint (collision probability negligible)
        let key: [u8; 16] = block[..16].try_into().unwrap();
        if let Some(&prev_idx) = seen.get(&key) {
            // Verify it's a real duplicate (not just fingerprint collision)
            let prev_block = &data[prev_idx * BLOCK_SIZE..(prev_idx + 1) * BLOCK_SIZE];
            if block == prev_block {
                duplicates += 1;
            }
        }
        seen.insert(key, i);
    }

    TestResult {
        name: format!("Duplicate blocks ({label})"),
        passed: duplicates == 0,
        statistic: duplicates as f64,
        threshold: 0.0,
        detail: format!("{duplicates} duplicate blocks out of {num_blocks}"),
    }
}

// ─── Bit-level tests ─────────────────────────────────────────────────────────

/// Monobit test: proportion of 1-bits should be ~50%.
fn monobit_test(data: &[u8], label: &str) -> TestResult {
    let total_bits = data.len() as f64 * 8.0;
    let ones: f64 = data.iter().map(|&b| b.count_ones() as f64).sum();
    let ratio = ones / total_bits;
    let deviation = (ratio - 0.5).abs();

    // For 64MB of data, expected std dev ≈ 0.5/√(64M*8) ≈ 0.000022
    let threshold = 0.0002;
    TestResult {
        name: format!("Monobit ({label})"),
        passed: deviation < threshold,
        statistic: ratio,
        threshold: 0.5,
        detail: format!("1-bit ratio (target: 0.5), deviation={deviation:.8}"),
    }
}

/// Runs test: number of runs of consecutive identical bits.
fn runs_test(data: &[u8], label: &str) -> TestResult {
    // Count runs (transitions between 0 and 1)
    let total_bits = data.len() * 8;
    let mut runs: u64 = 1;
    let mut prev_bit = (data[0] >> 7) & 1;

    for (byte_idx, &byte) in data.iter().enumerate() {
        let start_bit = if byte_idx == 0 { 6 } else { 7 };
        for bit_pos in (0..=start_bit).rev() {
            let bit = (byte >> bit_pos) & 1;
            if bit != prev_bit {
                runs += 1;
                prev_bit = bit;
            }
        }
    }

    // For random data, expected runs ≈ (2n-1)/3 where n is number of bits
    // But simpler: expected runs ≈ n/2 + 1
    let n = total_bits as f64;
    let expected_runs = n / 2.0 + 1.0;
    let std_dev = (n - 1.0).sqrt() / 2.0;
    let z_score = ((runs as f64) - expected_runs).abs() / std_dev;

    let threshold = 4.0; // 4 standard deviations
    TestResult {
        name: format!("Runs test ({label})"),
        passed: z_score < threshold,
        statistic: z_score,
        threshold,
        detail: format!("z-score (|observed - expected| / σ), runs={runs}"),
    }
}

/// Longest run of 1s in each block.
fn longest_run_test(data: &[u8], label: &str) -> TestResult {
    let num_blocks = data.len() / BLOCK_SIZE;
    let mut max_run = 0u32;
    let mut total_longest = 0u64;

    for i in 0..num_blocks {
        let block = &data[i * BLOCK_SIZE..(i + 1) * BLOCK_SIZE];
        let longest = longest_run_of_ones(block);
        total_longest += longest as u64;
        if longest > max_run {
            max_run = longest;
        }
    }

    let avg_longest = total_longest as f64 / num_blocks as f64;
    // For 4096 bytes (32768 bits), expected longest run of 1s ≈ log2(32768) ≈ 15
    // Allow range [10, 25] for average across blocks
    let in_range = (10.0..=25.0).contains(&avg_longest);
    TestResult {
        name: format!("Longest run of 1s ({label})"),
        passed: in_range && max_run < 50, // no block should have a run > 50
        statistic: avg_longest,
        threshold: 15.0,
        detail: format!("avg longest run per block (expected ~15), max single={max_run}"),
    }
}

fn longest_run_of_ones(data: &[u8]) -> u32 {
    let mut max_run = 0u32;
    let mut current_run = 0u32;
    for &byte in data {
        for bit_pos in (0..8).rev() {
            if (byte >> bit_pos) & 1 == 1 {
                current_run += 1;
                if current_run > max_run {
                    max_run = current_run;
                }
            } else {
                current_run = 0;
            }
        }
    }
    max_run
}

// ─── Structural tests ────────────────────────────────────────────────────────

/// Position bias: are the first N blocks statistically different from the rest?
fn position_bias_test(data: &[u8], label: &str) -> TestResult {
    let num_blocks = data.len() / BLOCK_SIZE;
    let first_n = 256.min(num_blocks / 4);

    let first_mean = byte_mean(&data[..first_n * BLOCK_SIZE]);
    let rest_mean = byte_mean(&data[first_n * BLOCK_SIZE..]);
    let diff = (first_mean - rest_mean).abs();

    // With 256 blocks (1MB), the std dev of mean byte value is ~73.9/√(1M) ≈ 0.074
    // So 3σ ≈ 0.22 — we need a threshold above that for reliable results
    let threshold = 0.25;
    TestResult {
        name: format!("Position bias ({label})"),
        passed: diff < threshold,
        statistic: diff,
        threshold,
        detail: format!("mean(first {first_n} blocks)={first_mean:.4}, mean(rest)={rest_mean:.4}"),
    }
}

fn byte_mean(data: &[u8]) -> f64 {
    data.iter().map(|&b| b as f64).sum::<f64>() / data.len() as f64
}

/// Compression test: gzip should achieve 0% reduction on random data.
fn compression_test(data: &[u8], label: &str) -> TestResult {
    // Simple run-length encoding as a proxy for compressibility
    // Count how many bytes differ from their predecessor
    let transitions = data.windows(2).filter(|w| w[0] != w[1]).count();
    let ratio = transitions as f64 / (data.len() - 1) as f64;

    // For random data, ~255/256 ≈ 0.9961 of byte pairs should differ
    let expected = 255.0 / 256.0;
    let deviation = (ratio - expected).abs();

    let threshold = 0.001;
    TestResult {
        name: format!("Compressibility ({label})"),
        passed: deviation < threshold,
        statistic: ratio,
        threshold: expected,
        detail: format!("byte-transition ratio (expected {expected:.4}), deviation={deviation:.6}"),
    }
}

/// Binary matrix rank test: divide data into 32x32 bit matrices and test ranks.
fn matrix_rank_test(data: &[u8], label: &str) -> TestResult {
    // Each 32x32 matrix needs 32*32/8 = 128 bytes
    let matrix_size = 128;
    let num_matrices = (data.len() / matrix_size).min(10_000);

    let mut rank_32 = 0u64;
    let mut rank_31 = 0u64;
    let mut rank_other = 0u64;

    for m in 0..num_matrices {
        let chunk = &data[m * matrix_size..(m + 1) * matrix_size];
        let rank = binary_matrix_rank(chunk, 32);
        match rank {
            32 => rank_32 += 1,
            31 => rank_31 += 1,
            _ => rank_other += 1,
        }
    }

    let n = num_matrices as f64;
    // Expected proportions for random 32x32 binary matrices:
    // P(rank=32) ≈ 0.2888, P(rank=31) ≈ 0.5776, P(rank≤30) ≈ 0.1336
    let expected_32 = 0.2888 * n;
    let expected_31 = 0.5776 * n;
    let expected_other = 0.1336 * n;

    let chi2 = (rank_32 as f64 - expected_32).powi(2) / expected_32
        + (rank_31 as f64 - expected_31).powi(2) / expected_31
        + (rank_other as f64 - expected_other).powi(2) / expected_other;

    // Chi-squared with 2 df, p=0.01 threshold ≈ 9.21
    let threshold = 9.21;
    TestResult {
        name: format!("Binary matrix rank ({label})"),
        passed: chi2 < threshold,
        statistic: chi2,
        threshold,
        detail: format!("rank32={rank_32}, rank31={rank_31}, other={rank_other}, n={num_matrices}"),
    }
}

/// Compute rank of a 32x32 binary matrix using Gaussian elimination over GF(2).
fn binary_matrix_rank(data: &[u8], size: usize) -> usize {
    let mut matrix = vec![0u32; size];
    for (row, entry) in matrix.iter_mut().enumerate() {
        let byte_offset = row * size / 8;
        let mut val: u32 = 0;
        for col_byte in 0..4 {
            if byte_offset + col_byte < data.len() {
                val |= (data[byte_offset + col_byte] as u32) << (24 - col_byte * 8);
            }
        }
        *entry = val;
    }

    let mut rank = 0;
    for col in 0..size {
        let mask = 1u32 << (31 - col);
        // Find pivot
        let pivot = matrix[rank..size]
            .iter()
            .position(|&v| v & mask != 0)
            .map(|p| p + rank);
        if let Some(pivot_row) = pivot {
            matrix.swap(rank, pivot_row);
            for row in 0..size {
                if row != rank && matrix[row] & mask != 0 {
                    matrix[row] ^= matrix[rank];
                }
            }
            rank += 1;
        }
    }
    rank
}

// ─── Main ────────────────────────────────────────────────────────────────────

fn run_all_tests(data: &[u8], label: &str) -> Vec<TestResult> {
    vec![
        // Byte-level tests
        chi_squared_test(data, label),
        ks_test(data, label),
        mean_byte_test(data, label),
        serial_correlation_test(data, label),
        // Block-level tests
        block_entropy_test(data, label),
        block_xor_test(data, label),
        block_autocorrelation_test(data, label),
        duplicate_block_test(data, label),
        // Bit-level tests
        monobit_test(data, label),
        runs_test(data, label),
        longest_run_test(data, label),
        matrix_rank_test(data, label),
        // Structural tests
        position_bias_test(data, label),
        compression_test(data, label),
    ]
}

fn main() {
    let cli = Cli::parse();

    let image_path = cli
        .image
        .unwrap_or_else(|| PathBuf::from("/tmp/voidfs_stats_test.img"));
    let control_path = cli
        .control
        .unwrap_or_else(|| PathBuf::from("/tmp/voidfs_stats_control.img"));

    // Generate images if they don't exist
    if !image_path.exists() || cli.generate_only {
        println!("Generating voidfs image at {} ...", image_path.display());
        create_voidfs_image(&image_path);
    }
    if !control_path.exists() || cli.generate_only {
        println!("Generating control image at {} ...", control_path.display());
        create_random_image(&control_path);
    }

    if cli.generate_only {
        println!("Images generated. Run without --generate-only to test.");
        return;
    }

    // Load images
    println!("Loading images...");
    let voidfs_data = fs::read(&image_path).expect("read voidfs image");
    let control_data = fs::read(&control_path).expect("read control image");

    assert_eq!(
        voidfs_data.len(),
        control_data.len(),
        "Images must be the same size"
    );
    println!(
        "Image size: {} bytes ({} blocks)\n",
        voidfs_data.len(),
        voidfs_data.len() / BLOCK_SIZE
    );

    // Run tests on control image
    println!("═══ Control image (pure random) ═══");
    let control_results = run_all_tests(&control_data, "control");
    for r in &control_results {
        r.display();
    }
    let control_pass = control_results.iter().filter(|r| r.passed).count();
    let control_total = control_results.len();
    println!("  → {control_pass}/{control_total} passed\n");

    // Run tests on voidfs image
    println!("═══ voidfs image (with ~100 encrypted files) ═══");
    let voidfs_results = run_all_tests(&voidfs_data, "voidfs");
    for r in &voidfs_results {
        r.display();
    }
    let voidfs_pass = voidfs_results.iter().filter(|r| r.passed).count();
    let voidfs_total = voidfs_results.len();
    println!("  → {voidfs_pass}/{voidfs_total} passed\n");

    // Summary
    println!("═══ DENIABILITY VERDICT ═══");
    let mut deniability_broken = false;
    for (vr, cr) in voidfs_results.iter().zip(control_results.iter()) {
        if !vr.passed && cr.passed {
            println!(
                "  ⚠ DENIABILITY BUG: {} fails on voidfs but passes on control",
                vr.name
            );
            deniability_broken = true;
        }
    }

    if deniability_broken {
        println!("\n  ✗ DENIABILITY IS BROKEN — voidfs image is distinguishable from random");
        std::process::exit(1);
    } else {
        println!("\n  ✓ ALL CLEAR — voidfs image is statistically indistinguishable from random");
    }

    // Cleanup
    let _ = fs::remove_file(&image_path);
    let _ = fs::remove_file(&control_path);
}
