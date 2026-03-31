//! High-level filesystem operations: create, delete, rename, list.
//!
//! These operations manage both file data and directory indices, ensuring
//! that the `.dirindex` files stay consistent with the actual file data.

use crate::fs::directory::{read_dirindex, write_dirindex, DirIndex, FileType};
use crate::fs::file::{read_file, write_file};
use crate::fs::inode::FileHeader;
use crate::fs::path::{canonical_path, dirindex_path, filename_of, parent_of};
use crate::store::image::ImageFile;
use crate::store::slots::{erase_slot, read_slot};
use crate::util::constants::HEADER_SIZE;
use crate::util::errors::{VoidError, VoidResult};

/// Names reserved for internal use that cannot be used as filenames.
const RESERVED_NAMES: &[&str] = &[".dirindex"];

/// Check if a filename is reserved.
fn reject_reserved(name: &str) -> VoidResult<()> {
    if RESERVED_NAMES.contains(&name) {
        return Err(VoidError::ReservedName {
            name: name.to_string(),
        });
    }
    Ok(())
}

/// Create or overwrite a file and update the parent directory index.
///
/// If the parent directory's `.dirindex` doesn't exist yet, it is created.
/// If the file already exists in the parent index, the data is overwritten
/// but no duplicate entry is added.
pub fn create_file(
    image: &mut ImageFile,
    master_secret: &[u8; 32],
    path: &str,
    data: &[u8],
) -> VoidResult<()> {
    let canon = canonical_path(path);
    let parent = parent_of(&canon);
    let name = filename_of(&canon);
    reject_reserved(name)?;

    // Write the file data
    write_file(image, master_secret, &canon, data)?;

    // Update parent directory index
    let mut parent_idx = read_dirindex(image, master_secret, parent)?;
    parent_idx.add(name.to_string(), FileType::File);
    write_dirindex(image, master_secret, parent, &parent_idx)?;

    Ok(())
}

/// Read a file's data. Returns `None` if the file doesn't exist.
pub fn read_file_data(
    image: &mut ImageFile,
    master_secret: &[u8; 32],
    path: &str,
) -> VoidResult<Option<Vec<u8>>> {
    let canon = canonical_path(path);
    read_file(image, master_secret, &canon)
}

/// Delete a file: overwrite its blocks with random data and remove from parent index.
pub fn delete_file(image: &mut ImageFile, master_secret: &[u8; 32], path: &str) -> VoidResult<()> {
    let canon = canonical_path(path);
    let parent = parent_of(&canon);
    let name = filename_of(&canon);

    // Read the file header to find block count
    let block_count = match read_file_block_count(image, master_secret, &canon)? {
        Some(count) => count,
        None => return Err(VoidError::FileNotFound),
    };

    // Erase all blocks with random data
    for block_num in 0..block_count as u64 {
        erase_slot(image, master_secret, &canon, block_num)?;
    }

    // Remove from parent directory index
    let mut parent_idx = read_dirindex(image, master_secret, parent)?;
    parent_idx.remove(name);
    write_dirindex(image, master_secret, parent, &parent_idx)?;

    Ok(())
}

/// Create a directory: write an empty `.dirindex` and add to parent index.
///
/// The root directory `/` is implicit and does not need to be created.
pub fn mkdir(image: &mut ImageFile, master_secret: &[u8; 32], path: &str) -> VoidResult<()> {
    let canon = canonical_path(path);
    if canon == "/" {
        // Root always exists implicitly; create its dirindex if missing
        let idx = read_dirindex(image, master_secret, "/")?;
        write_dirindex(image, master_secret, "/", &idx)?;
        return Ok(());
    }

    let parent = parent_of(&canon);
    let name = filename_of(&canon);
    reject_reserved(name)?;

    // Check if already exists in parent
    let mut parent_idx = read_dirindex(image, master_secret, parent)?;
    if parent_idx.contains(name) {
        return Err(VoidError::AlreadyExists {
            path: canon.to_string(),
        });
    }

    // Write empty dirindex for the new directory
    let empty_idx = DirIndex::default();
    write_dirindex(image, master_secret, &canon, &empty_idx)?;

    // Add to parent directory index
    parent_idx.add(name.to_string(), FileType::Directory);
    write_dirindex(image, master_secret, parent, &parent_idx)?;

    Ok(())
}

/// Remove an empty directory.
///
/// Returns an error if the directory is not empty or doesn't exist.
pub fn rmdir(image: &mut ImageFile, master_secret: &[u8; 32], path: &str) -> VoidResult<()> {
    let canon = canonical_path(path);
    if canon == "/" {
        return Err(VoidError::InvalidOperation {
            reason: "cannot remove root directory".to_string(),
        });
    }

    let parent = parent_of(&canon);
    let name = filename_of(&canon);

    // Check that directory exists and is empty
    let dir_idx = read_dirindex(image, master_secret, &canon)?;
    if !dir_idx.entries.is_empty() {
        return Err(VoidError::DirectoryNotEmpty {
            path: canon.to_string(),
        });
    }

    // Erase the .dirindex file
    let idx_file_path = dirindex_path(&canon);
    if let Some(count) = read_file_block_count(image, master_secret, &idx_file_path)? {
        for block_num in 0..count as u64 {
            erase_slot(image, master_secret, &idx_file_path, block_num)?;
        }
    }

    // Remove from parent directory index
    let mut parent_idx = read_dirindex(image, master_secret, parent)?;
    parent_idx.remove(name);
    write_dirindex(image, master_secret, parent, &parent_idx)?;

    Ok(())
}

/// List the contents of a directory.
///
/// Returns the directory index, which may be empty (for a new or
/// nonexistent directory — these are indistinguishable by design).
pub fn list_dir(
    image: &mut ImageFile,
    master_secret: &[u8; 32],
    path: &str,
) -> VoidResult<DirIndex> {
    let canon = canonical_path(path);
    read_dirindex(image, master_secret, &canon)
}

/// Get the file header (metadata) for a file.
///
/// Returns `None` if the file doesn't exist.
pub fn stat(
    image: &mut ImageFile,
    master_secret: &[u8; 32],
    path: &str,
) -> VoidResult<Option<FileHeader>> {
    let canon = canonical_path(path);
    let payload0 = match read_slot(image, master_secret, &canon, 0)? {
        Some(p) => p,
        None => return Ok(None),
    };

    let header_bytes: [u8; HEADER_SIZE] = payload0[..HEADER_SIZE]
        .try_into()
        .expect("slice is HEADER_SIZE");
    match FileHeader::from_bytes(&header_bytes) {
        Ok(h) => Ok(Some(h)),
        Err(VoidError::InvalidMagic) => Ok(None),
        Err(e) => Err(e),
    }
}

/// Helper: read just the block count from a file's header (without reading all data).
fn read_file_block_count(
    image: &mut ImageFile,
    master_secret: &[u8; 32],
    canonical: &str,
) -> VoidResult<Option<u32>> {
    let payload0 = match read_slot(image, master_secret, canonical, 0)? {
        Some(p) => p,
        None => return Ok(None),
    };

    let header_bytes: [u8; HEADER_SIZE] = payload0[..HEADER_SIZE]
        .try_into()
        .expect("slice is HEADER_SIZE");
    match FileHeader::from_bytes(&header_bytes) {
        Ok(h) => Ok(Some(h.block_count)),
        Err(VoidError::InvalidMagic) => Ok(None),
        Err(e) => Err(e),
    }
}

/// Summary statistics about a filesystem visible under a given passphrase.
#[derive(Debug, Default)]
pub struct FsInfo {
    /// Total number of files found.
    pub file_count: u64,
    /// Total number of directories found (excluding root).
    pub dir_count: u64,
    /// Total bytes stored across all files.
    pub total_bytes: u64,
    /// Total blocks used by file data (not counting dirindex overhead).
    pub total_blocks_used: u64,
}

/// Walk the filesystem tree and gather statistics.
pub fn fs_info(image: &mut ImageFile, master_secret: &[u8; 32]) -> VoidResult<FsInfo> {
    let mut info = FsInfo::default();
    walk_dir_for_info(image, master_secret, "/", &mut info)?;
    Ok(info)
}

fn walk_dir_for_info(
    image: &mut ImageFile,
    master_secret: &[u8; 32],
    dir: &str,
    info: &mut FsInfo,
) -> VoidResult<()> {
    let dir_idx = read_dirindex(image, master_secret, dir)?;

    for entry in &dir_idx.entries {
        let child_path = if dir == "/" {
            format!("/{}", entry.name)
        } else {
            format!("{dir}/{}", entry.name)
        };

        match entry.entry_type {
            FileType::File => {
                info.file_count += 1;
                if let Some(header) = stat(image, master_secret, &child_path)? {
                    info.total_bytes += header.file_size;
                    info.total_blocks_used += header.block_count as u64;
                }
            }
            FileType::Directory => {
                info.dir_count += 1;
                walk_dir_for_info(image, master_secret, &child_path, info)?;
            }
        }
    }

    Ok(())
}

/// Walk the filesystem tree and collect all paths for display.
pub fn tree(
    image: &mut ImageFile,
    master_secret: &[u8; 32],
) -> VoidResult<Vec<(String, FileType, u64)>> {
    let mut entries = Vec::new();
    walk_dir_for_tree(image, master_secret, "/", &mut entries)?;
    Ok(entries)
}

fn walk_dir_for_tree(
    image: &mut ImageFile,
    master_secret: &[u8; 32],
    dir: &str,
    entries: &mut Vec<(String, FileType, u64)>,
) -> VoidResult<()> {
    let dir_idx = read_dirindex(image, master_secret, dir)?;

    for entry in &dir_idx.entries {
        let child_path = if dir == "/" {
            format!("/{}", entry.name)
        } else {
            format!("{dir}/{}", entry.name)
        };

        match entry.entry_type {
            FileType::File => {
                let size = stat(image, master_secret, &child_path)?
                    .map(|h| h.file_size)
                    .unwrap_or(0);
                entries.push((child_path, FileType::File, size));
            }
            FileType::Directory => {
                entries.push((child_path.clone(), FileType::Directory, 0));
                walk_dir_for_tree(image, master_secret, &child_path, entries)?;
            }
        }
    }

    Ok(())
}

/// Recursively delete a directory and all its contents.
pub fn rmdir_recursive(
    image: &mut ImageFile,
    master_secret: &[u8; 32],
    path: &str,
) -> VoidResult<()> {
    let canon = canonical_path(path);

    // Read directory contents
    let dir_idx = read_dirindex(image, master_secret, &canon)?;

    // Delete all entries
    for entry in &dir_idx.entries {
        let child_path = if canon == "/" {
            format!("/{}", entry.name)
        } else {
            format!("{}/{}", canon, entry.name)
        };

        match entry.entry_type {
            FileType::File => {
                // Erase file blocks
                if let Some(count) = read_file_block_count(image, master_secret, &child_path)? {
                    for block_num in 0..count as u64 {
                        erase_slot(image, master_secret, &child_path, block_num)?;
                    }
                }
            }
            FileType::Directory => {
                rmdir_recursive(image, master_secret, &child_path)?;
            }
        }
    }

    // Erase the dirindex itself
    let idx_file_path = dirindex_path(&canon);
    if let Some(count) = read_file_block_count(image, master_secret, &idx_file_path)? {
        for block_num in 0..count as u64 {
            erase_slot(image, master_secret, &idx_file_path, block_num)?;
        }
    }

    // Remove from parent (unless root)
    if canon != "/" {
        let parent = parent_of(&canon);
        let name = filename_of(&canon);
        let mut parent_idx = read_dirindex(image, master_secret, parent)?;
        parent_idx.remove(name);
        write_dirindex(image, master_secret, parent, &parent_idx)?;
    }

    Ok(())
}
