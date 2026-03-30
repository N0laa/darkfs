//! voidfs CLI: read and write files to a void image.

use std::fs;
use std::path::PathBuf;

use clap::{Parser, Subcommand};

use voidfs::crypto::kdf::{derive_master_secret, KdfPreset};
use voidfs::fs::file::{read_file, write_file};
use voidfs::store::image::ImageFile;

#[derive(Parser)]
#[command(
    name = "voidfs",
    about = "A deniable steganographic filesystem. Nothing to see here."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Write a file into the void image
    Write {
        /// Path to the void image
        #[arg(long)]
        image: PathBuf,

        /// Virtual file path inside the filesystem
        #[arg(long)]
        file: String,

        /// Path to the real file to read data from
        #[arg(long)]
        input: PathBuf,

        /// Use fast (dev) KDF parameters
        #[arg(long)]
        dev: bool,
    },

    /// Read a file from the void image
    Read {
        /// Path to the void image
        #[arg(long)]
        image: PathBuf,

        /// Virtual file path inside the filesystem
        #[arg(long)]
        file: String,

        /// Path to write the extracted file
        #[arg(long)]
        output: PathBuf,

        /// Use fast (dev) KDF parameters
        #[arg(long)]
        dev: bool,
    },
}

fn get_preset(dev: bool) -> KdfPreset {
    if dev {
        KdfPreset::Dev
    } else {
        KdfPreset::Prod
    }
}

fn main() {
    tracing_subscriber::fmt::init();

    let cli = Cli::parse();

    match cli.command {
        Command::Write {
            image,
            file,
            input,
            dev,
        } => {
            let passphrase = rpassword::prompt_password("Enter passphrase: ")
                .expect("failed to read passphrase");

            let data = fs::read(&input).unwrap_or_else(|e| {
                eprintln!("Error reading {}: {e}", input.display());
                std::process::exit(1);
            });

            let mut img = ImageFile::open(&image).unwrap_or_else(|e| {
                eprintln!("Error opening image: {e}");
                std::process::exit(1);
            });

            let image_size = img.total_blocks() * voidfs::util::constants::BLOCK_SIZE as u64;
            let secret = derive_master_secret(passphrase.as_bytes(), image_size, get_preset(dev))
                .unwrap_or_else(|e| {
                    eprintln!("KDF error: {e}");
                    std::process::exit(1);
                });

            write_file(&mut img, &secret, &file, &data).unwrap_or_else(|e| {
                eprintln!("Write error: {e}");
                std::process::exit(1);
            });

            println!("Wrote {} bytes to {}", data.len(), file);
        }

        Command::Read {
            image,
            file,
            output,
            dev,
        } => {
            let passphrase = rpassword::prompt_password("Enter passphrase: ")
                .expect("failed to read passphrase");

            let mut img = ImageFile::open(&image).unwrap_or_else(|e| {
                eprintln!("Error opening image: {e}");
                std::process::exit(1);
            });

            let image_size = img.total_blocks() * voidfs::util::constants::BLOCK_SIZE as u64;
            let secret = derive_master_secret(passphrase.as_bytes(), image_size, get_preset(dev))
                .unwrap_or_else(|e| {
                    eprintln!("KDF error: {e}");
                    std::process::exit(1);
                });

            match read_file(&mut img, &secret, &file) {
                Ok(Some(data)) => {
                    fs::write(&output, &data).unwrap_or_else(|e| {
                        eprintln!("Error writing {}: {e}", output.display());
                        std::process::exit(1);
                    });
                    println!("Read {} bytes from {}", data.len(), file);
                }
                Ok(None) => {
                    println!("File not found (or wrong passphrase).");
                }
                Err(e) => {
                    eprintln!("Read error: {e}");
                    std::process::exit(1);
                }
            }
        }
    }
}
