//! voidfs CLI — a deniable steganographic vault.
//!
//! Usage:
//!   voidfs create <vault> <size>     Create a new vault (e.g. "10G", "500M")
//!   voidfs put <vault> <file> [name] Store a file in the vault
//!   voidfs get <vault> <name> [dest] Retrieve a file from the vault
//!   voidfs ls <vault>                List files in the vault
//!   voidfs rm <vault> <name>         Delete a file from the vault
//!   voidfs mkdir <vault> <dir>       Create a directory
//!   voidfs info <vault>              Show vault statistics
//!   voidfs mount <vault> <dir>       Mount as a FUSE filesystem
//!   voidfs unmount <dir>             Unmount a FUSE filesystem

use std::fs;
use std::io::Write as IoWrite;
use std::path::{Path, PathBuf};

use clap::{Parser, Subcommand};
use rand::RngCore;
use zeroize::Zeroizing;

use voidfs::crypto::kdf::{derive_master_secret, derive_session_secret, KdfPreset};
use voidfs::fs::file::read_file;
use voidfs::fs::ops::{create_file, delete_file, list_dir, mkdir, stat};
use voidfs::store::image::ImageFile;
use voidfs::store::superblock::{read_superblock, write_superblock, Superblock};
use voidfs::util::constants::BLOCK_SIZE;

#[derive(Parser)]
#[command(
    name = "voidfs",
    about = "A deniable steganographic vault. Nothing to see here.",
    version,
    after_help = "Examples:\n  voidfs create my.vault 1G\n  voidfs put my.vault secret.pdf\n  voidfs get my.vault secret.pdf .\n  voidfs ls my.vault"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Create a new vault filled with random data
    Create {
        /// Path for the new vault file
        vault: PathBuf,

        /// Vault size (e.g. "500M", "1G", "10G")
        size: String,
    },

    /// Store a file in the vault
    Put {
        /// Path to the vault
        vault: PathBuf,

        /// File to store
        input: PathBuf,

        /// Name inside the vault (defaults to the filename)
        #[arg(short, long)]
        name: Option<String>,
    },

    /// Retrieve a file from the vault
    Get {
        /// Path to the vault
        vault: PathBuf,

        /// Name of the file inside the vault
        name: String,

        /// Where to write it (defaults to current directory)
        dest: Option<PathBuf>,
    },

    /// List files in the vault
    Ls {
        /// Path to the vault
        vault: PathBuf,

        /// Directory to list (defaults to root)
        path: Option<String>,
    },

    /// Delete a file from the vault
    Rm {
        /// Path to the vault
        vault: PathBuf,

        /// Name of the file to delete
        name: String,
    },

    /// Create a directory in the vault
    Mkdir {
        /// Path to the vault
        vault: PathBuf,

        /// Directory name
        name: String,
    },

    /// Show vault info and file listing
    Info {
        /// Path to the vault
        vault: PathBuf,
    },

    /// Mount the vault as a FUSE filesystem
    #[cfg(feature = "fuse")]
    Mount {
        /// Path to the vault
        vault: PathBuf,

        /// Mount point directory
        mountpoint: PathBuf,

        /// Expected generation counter (for replay detection)
        #[arg(long)]
        expect_generation: Option<u64>,
    },

    /// Unmount a mounted vault
    #[cfg(feature = "fuse")]
    Unmount {
        /// Mount point to unmount
        mountpoint: PathBuf,
    },
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn get_preset() -> KdfPreset {
    if std::env::var("VOIDFS_DEV").is_ok() {
        KdfPreset::Dev
    } else {
        KdfPreset::Prod
    }
}

fn prompt_passphrase() -> Zeroizing<String> {
    if let Ok(pass) = std::env::var("VOIDFS_PASSPHRASE") {
        std::env::remove_var("VOIDFS_PASSPHRASE");
        return Zeroizing::new(pass);
    }
    Zeroizing::new(
        rpassword::prompt_password("Passphrase: ").expect("failed to read passphrase"),
    )
}

fn format_size(bytes: u64) -> String {
    const KIB: u64 = 1024;
    const MIB: u64 = 1024 * 1024;
    const GIB: u64 = 1024 * 1024 * 1024;
    if bytes >= GIB {
        format!("{:.1} GB", bytes as f64 / GIB as f64)
    } else if bytes >= MIB {
        format!("{:.1} MB", bytes as f64 / MIB as f64)
    } else if bytes >= KIB {
        format!("{:.1} KB", bytes as f64 / KIB as f64)
    } else {
        format!("{bytes} B")
    }
}

fn parse_size(s: &str) -> Result<u64, String> {
    let s = s.trim();
    if s.is_empty() {
        return Err("empty size".into());
    }
    let (num_str, mul) = match s.as_bytes().last() {
        Some(b'K' | b'k') => (&s[..s.len() - 1], 1024u64),
        Some(b'M' | b'm') => (&s[..s.len() - 1], 1024 * 1024),
        Some(b'G' | b'g') => (&s[..s.len() - 1], 1024 * 1024 * 1024),
        Some(b'T' | b't') => (&s[..s.len() - 1], 1024 * 1024 * 1024 * 1024),
        _ => (s, 1),
    };
    let num: u64 = num_str.parse().map_err(|e| format!("invalid size: {e}"))?;
    let total = num.checked_mul(mul).ok_or("size too large")?;
    if total == 0 {
        return Err("size must be > 0".into());
    }
    // Round up to block boundary
    let total = ((total + BLOCK_SIZE as u64 - 1) / BLOCK_SIZE as u64) * BLOCK_SIZE as u64;
    Ok(total)
}

/// Normalize a user-provided path: strip leading /, ensure it starts with /
fn normalize_path(name: &str) -> String {
    let name = name.trim_start_matches('/');
    if name.is_empty() {
        "/".to_string()
    } else {
        format!("/{name}")
    }
}

fn die(msg: &str) -> ! {
    eprintln!("Error: {msg}");
    std::process::exit(1);
}

/// Open vault, derive secrets, return everything needed for operations.
fn open_vault(
    vault: &Path,
) -> (ImageFile, Zeroizing<[u8; 32]>, Zeroizing<[u8; 32]>, Superblock) {
    let passphrase = prompt_passphrase();
    let preset = get_preset();

    let mut img = ImageFile::open(vault).unwrap_or_else(|e| {
        die(&format!("Cannot open vault: {e}"));
    });

    let image_size = img.total_blocks() * BLOCK_SIZE as u64;
    let master = derive_master_secret(passphrase.as_bytes(), image_size, preset)
        .unwrap_or_else(|e| die(&format!("Key derivation failed: {e}")));

    let sb = match read_superblock(&mut img, &master) {
        Ok(Some(sb)) => sb,
        Ok(None) => {
            let sb = Superblock::new();
            write_superblock(&mut img, &master, &sb)
                .unwrap_or_else(|e| die(&format!("Cannot initialize vault: {e}")));
            sb
        }
        Err(e) => die(&format!("Cannot read vault: {e}")),
    };

    let session = derive_session_secret(&master, &sb.random_salt)
        .unwrap_or_else(|e| die(&format!("Key derivation failed: {e}")));

    (img, master, session, sb)
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

fn cmd_create(vault: &Path, size_str: &str) {
    if vault.exists() {
        die(&format!("{} already exists", vault.display()));
    }

    let size = parse_size(size_str).unwrap_or_else(|e| die(&e));
    let num_blocks = size / BLOCK_SIZE as u64;

    println!("Creating {} vault...", format_size(size));

    let mut file = fs::File::create(vault)
        .unwrap_or_else(|e| die(&format!("Cannot create file: {e}")));

    let chunk_size = 16 * 1024 * 1024; // 16 MB at a time
    let mut remaining = size as usize;
    let mut buf = vec![0u8; chunk_size];

    while remaining > 0 {
        let n = remaining.min(chunk_size);
        rand::thread_rng().fill_bytes(&mut buf[..n]);
        file.write_all(&buf[..n])
            .unwrap_or_else(|e| die(&format!("Write failed: {e}")));
        remaining -= n;
    }
    file.flush().unwrap();

    println!(
        "Created {} ({} blocks). Use any passphrase to start storing files.",
        vault.display(),
        num_blocks
    );
}

fn cmd_put(vault: &Path, input: &Path, name_override: Option<&str>) {
    let filename = match name_override {
        Some(n) => n.to_string(),
        None => input
            .file_name()
            .map(|f| f.to_string_lossy().to_string())
            .unwrap_or_else(|| die("Cannot determine filename; use --name")),
    };
    let vpath = normalize_path(&filename);

    let data = fs::read(input)
        .unwrap_or_else(|e| die(&format!("Cannot read {}: {e}", input.display())));

    let (mut img, master, session, mut sb) = open_vault(vault);

    // Populate collision tracking
    voidfs::fs::ops::populate_claims(&mut img, &session).ok();

    create_file(&mut img, &session, &vpath, &data)
        .unwrap_or_else(|e| match e {
            voidfs::util::errors::VoidError::NoSlotAvailable { .. } => {
                die("Vault is full. Create a larger vault to store more files.");
            }
            _ => die(&format!("Write failed: {e}")),
        });

    // Update superblock
    sb.generation += 1;
    sb.file_count = sb.file_count.saturating_add(1);
    let _ = write_superblock(&mut img, &master, &sb);

    println!("Stored {} ({}) as {}", input.display(), format_size(data.len() as u64), vpath);
}

fn cmd_get(vault: &Path, name: &str, dest: Option<&Path>) {
    let vpath = normalize_path(name);

    let (mut img, _master, session, _sb) = open_vault(vault);

    match read_file(&mut img, &session, &vpath) {
        Ok(Some(data)) => {
            let out_path = match dest {
                Some(d) if d.is_dir() => {
                    let fname = vpath.rsplit('/').next().unwrap_or("file");
                    d.join(fname)
                }
                Some(d) => d.to_path_buf(),
                None => {
                    let fname = vpath.rsplit('/').next().unwrap_or("file");
                    PathBuf::from(fname)
                }
            };

            fs::write(&out_path, &*data)
                .unwrap_or_else(|e| die(&format!("Cannot write {}: {e}", out_path.display())));

            println!("Retrieved {} ({})", out_path.display(), format_size(data.len() as u64));
        }
        Ok(None) => {
            eprintln!("File not found (or wrong passphrase).");
            std::process::exit(1);
        }
        Err(e) => die(&format!("Read failed: {e}")),
    }
}

fn cmd_ls(vault: &Path, dir: Option<&str>) {
    let vpath = match dir {
        Some(d) => normalize_path(d),
        None => "/".to_string(),
    };

    let (mut img, _master, session, _sb) = open_vault(vault);

    let idx = list_dir(&mut img, &session, &vpath)
        .unwrap_or_else(|e| die(&format!("Cannot list: {e}")));

    if idx.entries.is_empty() {
        println!("(empty)");
        return;
    }

    for entry in &idx.entries {
        let suffix = match entry.entry_type {
            voidfs::fs::directory::FileType::Directory => "/",
            voidfs::fs::directory::FileType::File => "",
        };

        if entry.entry_type == voidfs::fs::directory::FileType::File {
            let full = if vpath == "/" {
                format!("/{}", entry.name)
            } else {
                format!("{}/{}", vpath, entry.name)
            };
            match stat(&mut img, &session, &full) {
                Ok(Some(h)) => println!("  {}{suffix}  {}", entry.name, format_size(h.file_size)),
                _ => println!("  {}{suffix}", entry.name),
            }
        } else {
            println!("  {}{suffix}", entry.name);
        }
    }
}

fn cmd_rm(vault: &Path, name: &str) {
    let vpath = normalize_path(name);

    let (mut img, master, session, mut sb) = open_vault(vault);

    voidfs::fs::ops::populate_claims(&mut img, &session).ok();

    delete_file(&mut img, &session, &vpath)
        .unwrap_or_else(|e| die(&format!("Delete failed: {e}")));

    sb.generation += 1;
    sb.file_count = sb.file_count.saturating_sub(1);
    let _ = write_superblock(&mut img, &master, &sb);

    println!("Deleted {}", vpath);
}

fn cmd_mkdir(vault: &Path, name: &str) {
    let vpath = normalize_path(name);

    let (mut img, master, session, mut sb) = open_vault(vault);

    voidfs::fs::ops::populate_claims(&mut img, &session).ok();

    mkdir(&mut img, &session, &vpath)
        .unwrap_or_else(|e| die(&format!("mkdir failed: {e}")));

    sb.generation += 1;
    let _ = write_superblock(&mut img, &master, &sb);

    println!("Created directory {}", vpath);
}

fn cmd_info(vault: &Path) {
    let (mut img, _master, session, sb) = open_vault(vault);

    let total_blocks = img.total_blocks();
    let image_size = total_blocks * BLOCK_SIZE as u64;

    let info = voidfs::fs::ops::fs_info(&mut img, &session)
        .unwrap_or_else(|e| die(&format!("Cannot read vault: {e}")));

    println!("Vault: {}", vault.display());
    println!("  Size:       {}", format_size(image_size));
    println!("  Files:      {}", info.file_count);
    println!("  Dirs:       {}", info.dir_count);
    println!("  Stored:     {}", format_size(info.total_bytes));
    println!(
        "  Used:       {:.1}% ({} of {} blocks)",
        info.total_blocks_used as f64 / total_blocks as f64 * 100.0,
        info.total_blocks_used,
        total_blocks,
    );
    println!("  Generation: {}", sb.generation);

    if info.file_count > 0 || info.dir_count > 0 {
        println!();
        let entries = voidfs::fs::ops::tree(&mut img, &session).unwrap_or_default();
        for (path, entry_type, size) in &entries {
            match entry_type {
                voidfs::fs::directory::FileType::File => {
                    println!("  {path}  ({})", format_size(*size));
                }
                voidfs::fs::directory::FileType::Directory => {
                    println!("  {path}/");
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Command::Create { vault, size } => {
            cmd_create(&vault, &size);
        }

        Command::Put { vault, input, name } => {
            cmd_put(&vault, &input, name.as_deref());
        }

        Command::Get { vault, name, dest } => {
            cmd_get(&vault, &name, dest.as_deref());
        }

        Command::Ls { vault, path } => {
            cmd_ls(&vault, path.as_deref());
        }

        Command::Rm { vault, name } => {
            cmd_rm(&vault, &name);
        }

        Command::Mkdir { vault, name } => {
            cmd_mkdir(&vault, &name);
        }

        Command::Info { vault } => {
            cmd_info(&vault);
        }

        #[cfg(feature = "fuse")]
        Command::Mount {
            vault,
            mountpoint,
            expect_generation,
        } => {
            let passphrase = prompt_passphrase();
            let (img, master, session, sb) = {
                let mut img = ImageFile::open(&vault)
                    .unwrap_or_else(|e| die(&format!("Cannot open vault: {e}")));
                let size = img.total_blocks() * BLOCK_SIZE as u64;
                let master = derive_master_secret(passphrase.as_bytes(), size, get_preset())
                    .unwrap_or_else(|e| die(&format!("Key derivation failed: {e}")));
                let sb = match read_superblock(&mut img, &master) {
                    Ok(Some(sb)) => sb,
                    Ok(None) => {
                        let sb = Superblock::new();
                        write_superblock(&mut img, &master, &sb).ok();
                        sb
                    }
                    Err(e) => die(&format!("Cannot read vault: {e}")),
                };
                let session = derive_session_secret(&master, &sb.random_salt)
                    .unwrap_or_else(|e| die(&format!("{e}")));
                (img, master, session, sb)
            };

            if let Some(expected) = expect_generation {
                if sb.generation < expected {
                    die(&format!(
                        "Warning: vault may have been tampered with (generation {} < expected {})",
                        sb.generation, expected
                    ));
                }
            }

            println!("Mounting {} at {}", vault.display(), mountpoint.display());
            println!("Generation: {}", sb.generation);

            let uid = unsafe { libc::getuid() };
            let gid = unsafe { libc::getgid() };
            let handler =
                voidfs::fuse::handler::VoidFsHandler::new(img, *master, *session, sb, uid, gid);

            let options = vec![
                fuser::MountOption::FSName("voidfs".to_string()),
                fuser::MountOption::AutoUnmount,
            ];

            if let Err(e) = fuser::mount2(handler, &mountpoint, &options) {
                die(&format!("Mount failed: {e}"));
            }
        }

        #[cfg(feature = "fuse")]
        Command::Unmount { mountpoint } => {
            let status = std::process::Command::new("umount")
                .arg(&mountpoint)
                .status();
            match status {
                Ok(s) if s.success() => println!("Unmounted {}", mountpoint.display()),
                Ok(s) => die(&format!("umount failed (exit code {:?})", s.code())),
                Err(e) => die(&format!("Cannot run umount: {e}")),
            }
        }
    }
}
