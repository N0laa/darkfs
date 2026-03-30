//! Directory index stored as a special `.dirindex` file.
//!
//! A directory is represented as a serialized list of [`DirEntry`] values,
//! stored as a regular encrypted file at `<dir_path>/.dirindex`. To list
//! a directory, we read and deserialize this file.

use serde::{Deserialize, Serialize};

use crate::fs::file::{read_file, write_file};
use crate::fs::path::dirindex_path;
use crate::store::image::ImageFile;
use crate::util::errors::VoidResult;

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

    /// Add an entry. Returns `false` if an entry with that name already exists.
    pub fn add(&mut self, name: String, entry_type: FileType) -> bool {
        if self.contains(&name) {
            return false;
        }
        self.entries.push(DirEntry { name, entry_type });
        true
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
) -> VoidResult<DirIndex> {
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
) -> VoidResult<()> {
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
        idx.add("file.txt".to_string(), FileType::File);
        idx.add("subdir".to_string(), FileType::Directory);

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
        assert!(idx.add("foo".to_string(), FileType::File));
        assert!(!idx.add("foo".to_string(), FileType::File));
    }

    #[test]
    fn remove_entry() {
        let mut idx = DirIndex::default();
        idx.add("a".to_string(), FileType::File);
        idx.add("b".to_string(), FileType::File);
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
        idx.add("file.txt".to_string(), FileType::File);
        idx.add("subdir".to_string(), FileType::Directory);
        assert_eq!(idx.get_type("file.txt"), Some(FileType::File));
        assert_eq!(idx.get_type("subdir"), Some(FileType::Directory));
        assert_eq!(idx.get_type("nope"), None);
    }
}
