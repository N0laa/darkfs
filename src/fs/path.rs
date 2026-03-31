//! Path normalization, splitting, and utility functions.

pub use crate::crypto::locator::canonical_path;

/// Return the parent directory of a canonical path.
///
/// ```
/// # use voidfs::fs::path::parent_of;
/// assert_eq!(parent_of("/"), "/");
/// assert_eq!(parent_of("/foo"), "/");
/// assert_eq!(parent_of("/foo/bar"), "/foo");
/// assert_eq!(parent_of("/a/b/c"), "/a/b");
/// ```
pub fn parent_of(canonical: &str) -> &str {
    if canonical == "/" {
        return "/";
    }
    match canonical.rfind('/') {
        Some(0) => "/",
        Some(pos) => &canonical[..pos],
        None => "/",
    }
}

/// Return the filename (last component) of a canonical path.
///
/// ```
/// # use voidfs::fs::path::filename_of;
/// assert_eq!(filename_of("/foo"), "foo");
/// assert_eq!(filename_of("/foo/bar.txt"), "bar.txt");
/// assert_eq!(filename_of("/a/b/c"), "c");
/// ```
///
/// # Panics
///
/// Panics if called on `"/"` (root has no filename).
pub fn filename_of(canonical: &str) -> &str {
    assert!(canonical != "/", "root has no filename");
    match canonical.rfind('/') {
        Some(pos) => &canonical[pos + 1..],
        None => canonical,
    }
}

/// Join a parent directory path with a child name.
///
/// ```
/// # use voidfs::fs::path::join_path;
/// assert_eq!(join_path("/", "foo"), "/foo");
/// assert_eq!(join_path("/a", "b"), "/a/b");
/// assert_eq!(join_path("/a/b", "c"), "/a/b/c");
/// ```
pub fn join_path(parent: &str, name: &str) -> String {
    if parent == "/" {
        format!("/{name}")
    } else {
        format!("{parent}/{name}")
    }
}

/// Return the path to the `.dirindex` file for a directory.
///
/// ```
/// # use voidfs::fs::path::dirindex_path;
/// assert_eq!(dirindex_path("/"), "/.dirindex");
/// assert_eq!(dirindex_path("/foo"), "/foo/.dirindex");
/// assert_eq!(dirindex_path("/foo/bar"), "/foo/bar/.dirindex");
/// ```
pub fn dirindex_path(canonical_dir: &str) -> String {
    if canonical_dir == "/" {
        "/.dirindex".to_string()
    } else {
        format!("{canonical_dir}/.dirindex")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parent_of_root() {
        assert_eq!(parent_of("/"), "/");
    }

    #[test]
    fn parent_of_top_level() {
        assert_eq!(parent_of("/foo"), "/");
    }

    #[test]
    fn parent_of_nested() {
        assert_eq!(parent_of("/foo/bar"), "/foo");
        assert_eq!(parent_of("/a/b/c"), "/a/b");
    }

    #[test]
    fn filename_of_top_level() {
        assert_eq!(filename_of("/foo"), "foo");
    }

    #[test]
    fn filename_of_nested() {
        assert_eq!(filename_of("/foo/bar.txt"), "bar.txt");
    }

    #[test]
    fn join_path_root_parent() {
        assert_eq!(join_path("/", "foo"), "/foo");
    }

    #[test]
    fn join_path_nested() {
        assert_eq!(join_path("/a", "b"), "/a/b");
        assert_eq!(join_path("/a/b", "c"), "/a/b/c");
    }

    #[test]
    fn dirindex_path_root() {
        assert_eq!(dirindex_path("/"), "/.dirindex");
    }

    #[test]
    fn dirindex_path_nested() {
        assert_eq!(dirindex_path("/foo"), "/foo/.dirindex");
    }
}
