//! Directory index stored as a special `.dirindex` file.
//!
//! A directory is represented as a serialized list of [`DirEntry`] values,
//! stored as a regular encrypted file at `<dir_path>/.dirindex`. To list
//! a directory, we read and deserialize this file.

use serde::{Deserialize, Serialize};

use crate::fs::file::{read_file, write_file};
use crate::fs::path::dirindex_path;
use crate::store::image::ImageFile;
use crate::util::errors::{DarkError, DarkResult};

/// The type of a directory entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FileType {
    /// A regular file.
    File,
    /// A subdirectory.
    Directory,
}

/// A single entry in a directory listing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DirEntry {
    /// The entry name (not a full path — just the filename or subdirectory name).
    pub name: String,
    /// Whether this entry is a file or directory.
    pub entry_type: FileType,
}

/// A directory's contents — a list of entries.
///
/// Serialized with bincode and stored as a regular encrypted file.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DirIndex {
    /// The entries in this directory.
    pub entries: Vec<DirEntry>,
}

impl DirIndex {
    /// Serialize the directory index to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::serialize(self).expect("DirIndex serialization cannot fail")
    }

    /// Deserialize a directory index from bytes.
    pub fn from_bytes(data: &[u8]) -> Result<Self, bincode::Error> {
        bincode::deserialize(data)
    }

    /// Check if an entry with the given name exists.
    pub fn contains(&self, name: &str) -> bool {
        self.entries.iter().any(|e| e.name == name)
    }

    /// Validate that a directory entry name is safe.
    ///
    /// Rejects empty names, names longer than 255 bytes, names containing
    /// null bytes or slashes, and `.`/`..` entries.
    pub fn validate_name(name: &str) -> DarkResult<()> {
        if name.is_empty() {
            return Err(DarkError::InvalidName {
                reason: "name is empty".to_string(),
            });
        }
        if name.len() > 255 {
            return Err(DarkError::InvalidName {
                reason: "name exceeds 255 bytes".to_string(),
            });
        }
        if name.contains('\0') {
            return Err(DarkError::InvalidName {
                reason: "name contains null byte".to_string(),
            });
        }
        if name.contains('/') {
            return Err(DarkError::InvalidName {
                reason: "name contains slash".to_string(),
            });
        }
        if name == "." || name == ".." {
            return Err(DarkError::InvalidName {
                reason: "name is . or ..".to_string(),
            });
        }
        Ok(())
    }

    /// Add an entry. Returns `false` if an entry with that name already exists.
    ///
    /// Validates the name before adding. Rejects names containing null bytes,
    /// slashes, `.`/`..`, empty names, or names exceeding 255 bytes.
    pub fn add(&mut self, name: String, entry_type: FileType) -> DarkResult<bool> {
        Self::validate_name(&name)?;
        if self.contains(&name) {
            return Ok(false);
        }
        self.entries.push(DirEntry { name, entry_type });
        Ok(true)
    }

    /// Remove an entry by name. Returns `true` if it was found and removed.
    pub fn remove(&mut self, name: &str) -> bool {
        let len_before = self.entries.len();
        self.entries.retain(|e| e.name != name);
        self.entries.len() < len_before
    }

    /// Get the type of an entry by name.
    pub fn get_type(&self, name: &str) -> Option<FileType> {
        self.entries
            .iter()
            .find(|e| e.name == name)
            .map(|e| e.entry_type)
    }
}

/// Read a directory index from the image. Returns an empty index if not found.
pub fn read_dirindex(
    image: &mut ImageFile,
    master_secret: &[u8; 32],
    dir_path: &str,
) -> DarkResult<DirIndex> {
    let idx_path = dirindex_path(dir_path);
    match read_file(image, master_secret, &idx_path)? {
        Some(data) => Ok(DirIndex::from_bytes(&data).unwrap_or_default()),
        None => Ok(DirIndex::default()),
    }
}

/// Write a directory index to the image.
pub fn write_dirindex(
    image: &mut ImageFile,
    master_secret: &[u8; 32],
    dir_path: &str,
    index: &DirIndex,
) -> DarkResult<()> {
    let idx_path = dirindex_path(dir_path);
    let data = index.to_bytes();
    write_file(image, master_secret, &idx_path, &data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dirindex_roundtrip() {
        let mut idx = DirIndex::default();
        idx.add("file.txt".to_string(), FileType::File).unwrap();
        idx.add("subdir".to_string(), FileType::Directory).unwrap();

        let bytes = idx.to_bytes();
        let parsed = DirIndex::from_bytes(&bytes).unwrap();
        assert_eq!(idx, parsed);
    }

    #[test]
    fn empty_dirindex() {
        let idx = DirIndex::default();
        let bytes = idx.to_bytes();
        let parsed = DirIndex::from_bytes(&bytes).unwrap();
        assert!(parsed.entries.is_empty());
    }

    #[test]
    fn add_duplicate_returns_false() {
        let mut idx = DirIndex::default();
        assert!(idx.add("foo".to_string(), FileType::File).unwrap());
        assert!(!idx.add("foo".to_string(), FileType::File).unwrap());
    }

    #[test]
    fn remove_entry() {
        let mut idx = DirIndex::default();
        idx.add("a".to_string(), FileType::File).unwrap();
        idx.add("b".to_string(), FileType::File).unwrap();
        assert!(idx.remove("a"));
        assert!(!idx.contains("a"));
        assert!(idx.contains("b"));
    }

    #[test]
    fn remove_nonexistent() {
        let mut idx = DirIndex::default();
        assert!(!idx.remove("nope"));
    }

    #[test]
    fn get_type() {
        let mut idx = DirIndex::default();
        idx.add("file.txt".to_string(), FileType::File).unwrap();
        idx.add("subdir".to_string(), FileType::Directory).unwrap();
        assert_eq!(idx.get_type("file.txt"), Some(FileType::File));
        assert_eq!(idx.get_type("subdir"), Some(FileType::Directory));
        assert_eq!(idx.get_type("nope"), None);
    }

    #[test]
    fn reject_null_byte_name() {
        let mut idx = DirIndex::default();
        assert!(idx.add("evil\0name".to_string(), FileType::File).is_err());
    }

    #[test]
    fn reject_slash_name() {
        let mut idx = DirIndex::default();
        assert!(idx.add("a/b".to_string(), FileType::File).is_err());
    }

    #[test]
    fn reject_dot_names() {
        let mut idx = DirIndex::default();
        assert!(idx.add(".".to_string(), FileType::File).is_err());
        assert!(idx.add("..".to_string(), FileType::File).is_err());
    }

    #[test]
    fn reject_long_name() {
        let mut idx = DirIndex::default();
        let long = "x".repeat(256);
        assert!(idx.add(long, FileType::File).is_err());
    }

    #[test]
    fn accept_255_byte_name() {
        let mut idx = DirIndex::default();
        let name = "x".repeat(255);
        assert!(idx.add(name, FileType::File).unwrap());
    }
}
