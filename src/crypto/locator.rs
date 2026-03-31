//! HMAC-SHA256 deterministic block location mapping.
//!
//! Every `(file_path, block_num, slot)` triple maps to a unique disk offset
//! via HMAC-SHA256. No allocation table is ever stored on disk.

use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Normalize a path into a canonical form.
///
/// Rules: split by `/`, discard empty and `.` segments, resolve `..` by
/// popping the previous segment, rejoin with `/`, prepend `/`.
///
/// ```
/// # use voidfs::crypto::locator::canonical_path;
/// assert_eq!(canonical_path(""), "/");
/// assert_eq!(canonical_path("/"), "/");
/// assert_eq!(canonical_path("foo"), "/foo");
/// assert_eq!(canonical_path("//a//b/"), "/a/b");
/// assert_eq!(canonical_path("/foo/bar"), "/foo/bar");
/// assert_eq!(canonical_path("/foo/../bar"), "/bar");
/// assert_eq!(canonical_path("/foo/./bar"), "/foo/bar");
/// assert_eq!(canonical_path("/../../../etc"), "/etc");
/// ```
pub fn canonical_path(path: &str) -> String {
    let mut resolved: Vec<&str> = Vec::new();
    for seg in path.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                resolved.pop();
            }
            s => resolved.push(s),
        }
    }
    if resolved.is_empty() {
        "/".to_string()
    } else {
        format!("/{}", resolved.join("/"))
    }
}

/// Compute the disk block index for a given `(path, block_num, slot)` triple.
///
/// Uses `HMAC-SHA256(key=master_secret, data=len(path) || path || block_num || slot)`,
/// then takes the first 8 bytes as a little-endian u64, modulo `total_blocks`.
///
/// The path length prefix ensures unambiguous encoding — without it, a path
/// ending in bytes matching block_num encoding could collide with a different
/// (path, block_num) pair.
pub fn block_offset(
    master_secret: &[u8; 32],
    path: &str,
    block_num: u64,
    slot: u32,
    total_blocks: u64,
) -> u64 {
    let mut mac = HmacSha256::new_from_slice(master_secret).expect("HMAC accepts any key length");
    mac.update(&(path.len() as u32).to_le_bytes()); // length prefix for unambiguous encoding
    mac.update(path.as_bytes());
    mac.update(&block_num.to_le_bytes());
    mac.update(&slot.to_le_bytes());
    let result = mac.finalize().into_bytes();

    let hash_bytes: [u8; 8] = result[..8].try_into().expect("slice is 8 bytes");
    u64::from_le_bytes(hash_bytes) % total_blocks
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_path_empty() {
        assert_eq!(canonical_path(""), "/");
    }

    #[test]
    fn canonical_path_root() {
        assert_eq!(canonical_path("/"), "/");
    }

    #[test]
    fn canonical_path_no_leading_slash() {
        assert_eq!(canonical_path("foo"), "/foo");
    }

    #[test]
    fn canonical_path_double_slashes() {
        assert_eq!(canonical_path("//a//b/"), "/a/b");
    }

    #[test]
    fn canonical_path_normal() {
        assert_eq!(canonical_path("/foo/bar"), "/foo/bar");
    }

    #[test]
    fn canonical_path_dotdot() {
        assert_eq!(canonical_path("/foo/../bar"), "/bar");
        assert_eq!(canonical_path("/a/b/c/../../d"), "/a/d");
        assert_eq!(canonical_path("/../../../etc"), "/etc");
    }

    #[test]
    fn canonical_path_dot() {
        assert_eq!(canonical_path("/foo/./bar"), "/foo/bar");
        assert_eq!(canonical_path("/."), "/");
    }

    #[test]
    fn canonical_path_trailing_slash() {
        assert_eq!(canonical_path("/foo/bar/"), "/foo/bar");
    }

    #[test]
    fn deterministic_offset() {
        let secret = [42u8; 32];
        let a = block_offset(&secret, "/test", 0, 0, 1000);
        let b = block_offset(&secret, "/test", 0, 0, 1000);
        assert_eq!(a, b);
    }

    #[test]
    fn different_slots_differ() {
        let secret = [42u8; 32];
        let a = block_offset(&secret, "/test", 0, 0, 100_000);
        let b = block_offset(&secret, "/test", 0, 1, 100_000);
        // With overwhelming probability, different slots produce different offsets.
        assert_ne!(a, b);
    }

    #[test]
    fn different_paths_differ() {
        let secret = [42u8; 32];
        let a = block_offset(&secret, "/foo", 0, 0, 100_000);
        let b = block_offset(&secret, "/bar", 0, 0, 100_000);
        assert_ne!(a, b);
    }

    #[test]
    fn different_block_nums_differ() {
        let secret = [42u8; 32];
        let a = block_offset(&secret, "/test", 0, 0, 100_000);
        let b = block_offset(&secret, "/test", 1, 0, 100_000);
        assert_ne!(a, b);
    }

    #[test]
    fn offset_within_range() {
        let secret = [99u8; 32];
        for i in 0..100 {
            let off = block_offset(&secret, "/file", i, 0, 500);
            assert!(off < 500);
        }
    }
}
