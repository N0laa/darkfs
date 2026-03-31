//! voidfs CLI: mount, read, and write files to a void image.

use std::fs;
use std::path::PathBuf;

use clap::{Parser, Subcommand};
use zeroize::Zeroizing;

use voidfs::crypto::kdf::{derive_master_secret, KdfPreset};
use voidfs::fs::file::read_file;
use voidfs::fs::ops::create_file;
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
    /// Mount a void image as a FUSE filesystem
    #[cfg(feature = "fuse")]
    Mount {
        /// Path to the void image
        image: PathBuf,

        /// Mount point directory
        mountpoint: PathBuf,

        /// Use fast (dev) KDF parameters
        #[arg(long)]
        dev: bool,
    },

    /// Unmount a void filesystem
    #[cfg(feature = "fuse")]
    Unmount {
        /// Mount point to unmount
        mountpoint: PathBuf,
    },

    /// Write a file into the void image (without FUSE)
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

    /// Show filesystem info (requires correct passphrase)
    Info {
        /// Path to the void image
        #[arg(long)]
        image: PathBuf,

        /// Use fast (dev) KDF parameters
        #[arg(long)]
        dev: bool,
    },

    /// Read a file from the void image (without FUSE)
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

fn prompt_passphrase() -> Zeroizing<String> {
    // Allow VOIDFS_PASSPHRASE env var for non-interactive/testing use
    if let Ok(pass) = std::env::var("VOIDFS_PASSPHRASE") {
        std::env::remove_var("VOIDFS_PASSPHRASE"); // clear immediately
        return Zeroizing::new(pass);
    }
    Zeroizing::new(
        rpassword::prompt_password("Enter passphrase: ").expect("failed to read passphrase"),
    )
}

fn format_size(bytes: u64) -> String {
    const KIB: u64 = 1024;
    const MIB: u64 = 1024 * 1024;
    const GIB: u64 = 1024 * 1024 * 1024;
    if bytes >= GIB {
        format!("{:.1} GiB", bytes as f64 / GIB as f64)
    } else if bytes >= MIB {
        format!("{:.1} MiB", bytes as f64 / MIB as f64)
    } else if bytes >= KIB {
        format!("{:.1} KiB", bytes as f64 / KIB as f64)
    } else {
        format!("{bytes} B")
    }
}

fn open_image_and_derive_secret(
    image: &std::path::Path,
    passphrase: &[u8],
    preset: KdfPreset,
) -> (ImageFile, Zeroizing<[u8; 32]>) {
    let img = ImageFile::open(image).unwrap_or_else(|e| {
        eprintln!("Error opening image: {e}");
        std::process::exit(1);
    });
    let image_size = img.total_blocks() * voidfs::util::constants::BLOCK_SIZE as u64;
    let secret = derive_master_secret(passphrase, image_size, preset).unwrap_or_else(|e| {
        eprintln!("KDF error: {e}");
        std::process::exit(1);
    });
    (img, secret)
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        #[cfg(feature = "fuse")]
        Command::Mount {
            image,
            mountpoint,
            dev,
        } => {
            let passphrase = prompt_passphrase();
            let (img, secret) =
                open_image_and_derive_secret(&image, passphrase.as_bytes(), get_preset(dev));

            let uid = unsafe { libc::getuid() };
            let gid = unsafe { libc::getgid() };
            let handler = voidfs::fuse::handler::VoidFsHandler::new(img, *secret, uid, gid);

            let options = vec![
                fuser::MountOption::FSName("fuse".to_string()),
                fuser::MountOption::AutoUnmount,
            ];

            println!("Mounting {} at {}", image.display(), mountpoint.display());
            if let Err(e) = fuser::mount2(handler, &mountpoint, &options) {
                eprintln!("Mount failed: {e}");
                std::process::exit(1);
            }
        }

        #[cfg(feature = "fuse")]
        Command::Unmount { mountpoint } => {
            // Use system umount command
            let status = std::process::Command::new("umount")
                .arg(&mountpoint)
                .status();
            match status {
                Ok(s) if s.success() => println!("Unmounted {}", mountpoint.display()),
                Ok(s) => {
                    eprintln!("umount failed with exit code {:?}", s.code());
                    std::process::exit(1);
                }
                Err(e) => {
                    eprintln!("Failed to run umount: {e}");
                    std::process::exit(1);
                }
            }
        }

        Command::Info { image, dev } => {
            let passphrase = prompt_passphrase();
            let (mut img, secret) =
                open_image_and_derive_secret(&image, passphrase.as_bytes(), get_preset(dev));

            let total_blocks = img.total_blocks();
            let image_size = total_blocks * voidfs::util::constants::BLOCK_SIZE as u64;

            let info = voidfs::fs::ops::fs_info(&mut img, &secret).unwrap_or_else(|e| {
                eprintln!("Error reading filesystem: {e}");
                std::process::exit(1);
            });

            println!("voidfs image: {}", image.display());
            println!(
                "  Image size:    {} ({} blocks)",
                format_size(image_size),
                total_blocks
            );
            println!("  Files:         {}", info.file_count);
            println!("  Directories:   {}", info.dir_count);
            println!("  Data stored:   {}", format_size(info.total_bytes));
            println!(
                "  Blocks used:   {} ({:.1}%)",
                info.total_blocks_used,
                info.total_blocks_used as f64 / total_blocks as f64 * 100.0
            );

            if info.file_count > 0 || info.dir_count > 0 {
                println!();
                let entries = voidfs::fs::ops::tree(&mut img, &secret).unwrap_or_default();
                for (path, entry_type, size) in &entries {
                    let marker = match entry_type {
                        voidfs::fs::directory::FileType::Directory => "/",
                        voidfs::fs::directory::FileType::File => "",
                    };
                    if *entry_type == voidfs::fs::directory::FileType::File {
                        println!("  {path}{marker}  ({})", format_size(*size));
                    } else {
                        println!("  {path}{marker}");
                    }
                }
            }
        }

        Command::Write {
            image,
            file,
            input,
            dev,
        } => {
            let passphrase = prompt_passphrase();
            let data = fs::read(&input).unwrap_or_else(|e| {
                eprintln!("Error reading {}: {e}", input.display());
                std::process::exit(1);
            });
            let (mut img, secret) =
                open_image_and_derive_secret(&image, passphrase.as_bytes(), get_preset(dev));

            // Populate collision tracking from existing files before writing
            voidfs::fs::ops::populate_claims(&mut img, &secret).unwrap_or_else(|e| {
                eprintln!("Warning: could not scan existing files: {e}");
            });

            create_file(&mut img, &secret, &file, &data).unwrap_or_else(|e| {
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
            let passphrase = prompt_passphrase();
            let (mut img, secret) =
                open_image_and_derive_secret(&image, passphrase.as_bytes(), get_preset(dev));

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
