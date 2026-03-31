//! mkdark: create a new void image filled with cryptographically secure random data.

use std::fs::File;
use std::io::Write;
use std::path::PathBuf;

use clap::Parser;
use rand::RngCore;

use darkfs::util::constants::BLOCK_SIZE;

#[derive(Parser)]
#[command(name = "mkdark", about = "Create a new void image")]
struct Cli {
    /// Image size (e.g. "64M", "2G", "1048576")
    #[arg(long)]
    size: String,

    /// Output file path
    #[arg(long)]
    output: PathBuf,
}

fn parse_size(s: &str) -> Result<u64, String> {
    let s = s.trim();
    if s.is_empty() {
        return Err("empty size".to_string());
    }

    let (num_str, multiplier) = match s.as_bytes().last() {
        Some(b'K' | b'k') => (&s[..s.len() - 1], 1024u64),
        Some(b'M' | b'm') => (&s[..s.len() - 1], 1024 * 1024),
        Some(b'G' | b'g') => (&s[..s.len() - 1], 1024 * 1024 * 1024),
        Some(b'T' | b't') => (&s[..s.len() - 1], 1024 * 1024 * 1024 * 1024),
        _ => (s, 1),
    };

    let num: u64 = num_str
        .parse()
        .map_err(|e| format!("invalid size number: {e}"))?;
    let total = num
        .checked_mul(multiplier)
        .ok_or_else(|| "size overflow".to_string())?;

    if total == 0 {
        return Err("size must be greater than zero".to_string());
    }
    if total % BLOCK_SIZE as u64 != 0 {
        return Err(format!(
            "size must be a multiple of block size ({BLOCK_SIZE})"
        ));
    }

    Ok(total)
}

fn main() {
    let cli = Cli::parse();

    let size = match parse_size(&cli.size) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Error: {e}");
            std::process::exit(1);
        }
    };

    let mut file = match File::create(&cli.output) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("Error creating {}: {e}", cli.output.display());
            std::process::exit(1);
        }
    };

    let num_blocks = size / BLOCK_SIZE as u64;
    let mut rng = rand::thread_rng();
    let mut block = [0u8; BLOCK_SIZE];

    for i in 0..num_blocks {
        rng.fill_bytes(&mut block);
        if let Err(e) = file.write_all(&block) {
            eprintln!("Error writing block {i}: {e}");
            std::process::exit(1);
        }
    }

    if let Err(e) = file.flush() {
        eprintln!("Error flushing: {e}");
        std::process::exit(1);
    }

    println!(
        "Created {} ({} bytes, {} blocks)",
        cli.output.display(),
        size,
        num_blocks
    );
}
