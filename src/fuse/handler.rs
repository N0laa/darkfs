//! FUSE trait implementation for voidfs.
//!
//! Maps between FUSE's inode-based interface and voidfs's path-based
//! encrypted block store. An in-memory inode table tracks the mapping
//! from inode numbers to canonical paths.

use std::collections::HashMap;
use std::ffi::OsStr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use fuser::{
    FileAttr, FileType, Filesystem, ReplyAttr, ReplyCreate, ReplyData, ReplyDirectory, ReplyEmpty,
    ReplyEntry, ReplyOpen, ReplyStatfs, ReplyWrite, Request,
};
use zeroize::Zeroizing;

use crate::fs::directory::FileType as VoidFileType;
use crate::fs::file::{read_file, write_file};
use crate::fs::ops::{self, list_dir};
use crate::fs::path::{filename_of, join_path, parent_of};
use crate::store::image::ImageFile;
use crate::store::superblock::{write_superblock, Superblock};
use crate::util::constants::BLOCK_SIZE;

const TTL: Duration = Duration::from_secs(1);
const ROOT_INO: u64 = 1;

/// The voidfs FUSE filesystem handler.
pub struct VoidFsHandler {
    image: ImageFile,
    master_secret: Zeroizing<[u8; 32]>,
    /// Session secret derived from master + per-image random salt.
    /// Used for all file encryption/decryption.
    session_secret: Zeroizing<[u8; 32]>,
    /// The superblock (updated on writes, flushed on destroy).
    superblock: Superblock,
    /// inode → canonical path
    ino_to_path: HashMap<u64, String>,
    /// canonical path → inode
    path_to_ino: HashMap<String, u64>,
    /// Next inode number to assign
    next_ino: u64,
    /// Open file handles: fh → (ino, buffered data for writes)
    open_files: HashMap<u64, OpenFile>,
    /// Next file handle
    next_fh: u64,
    /// uid/gid of the mounting user
    uid: u32,
    gid: u32,
}

struct OpenFile {
    ino: u64,
    /// Buffered data — loaded on open, flushed on release.
    /// Wrapped in [`Zeroizing`] so plaintext is securely erased on drop.
    data: Zeroizing<Vec<u8>>,
    dirty: bool,
}

/// Map a VoidError to an appropriate libc errno.
fn to_errno(e: &crate::util::errors::VoidError) -> i32 {
    use crate::util::errors::VoidError;
    match e {
        VoidError::FileNotFound => libc::ENOENT,
        VoidError::AlreadyExists { .. } => libc::EEXIST,
        VoidError::DirectoryNotEmpty { .. } => libc::ENOTEMPTY,
        VoidError::InvalidOperation { .. } => libc::EINVAL,
        VoidError::NoSlotAvailable { .. } => libc::ENOSPC,
        VoidError::ReservedName { .. } => libc::EINVAL,
        VoidError::FileTooLarge { .. } => libc::EFBIG,
        VoidError::Io(_) => libc::EIO,
        _ => libc::EIO,
    }
}

impl VoidFsHandler {
    /// Create a new FUSE handler with pre-derived secrets and superblock.
    pub fn new(
        image: ImageFile,
        master_secret: [u8; 32],
        session_secret: [u8; 32],
        superblock: Superblock,
        uid: u32,
        gid: u32,
    ) -> Self {
        let mut handler = Self {
            image,
            master_secret: Zeroizing::new(master_secret),
            session_secret: Zeroizing::new(session_secret),
            superblock,
            ino_to_path: HashMap::new(),
            path_to_ino: HashMap::new(),
            next_ino: ROOT_INO + 1,
            open_files: HashMap::new(),
            next_fh: 1,
            uid,
            gid,
        };
        handler.assign_ino("/".to_string());

        // Populate collision tracking from existing files on disk
        let _ = crate::fs::ops::populate_claims(&mut handler.image, &handler.session_secret);

        handler
    }

    fn assign_ino(&mut self, path: String) -> u64 {
        if let Some(&ino) = self.path_to_ino.get(&path) {
            return ino;
        }
        let ino = if path == "/" {
            ROOT_INO
        } else {
            let ino = self.next_ino;
            self.next_ino += 1;
            ino
        };
        self.ino_to_path.insert(ino, path.clone());
        self.path_to_ino.insert(path, ino);
        ino
    }

    fn get_path(&self, ino: u64) -> Option<&str> {
        self.ino_to_path.get(&ino).map(|s| s.as_str())
    }

    fn child_path(&self, parent_ino: u64, name: &OsStr) -> Option<String> {
        let parent = self.get_path(parent_ino)?;
        let name = name.to_str()?;
        if parent == "/" {
            Some(format!("/{name}"))
        } else {
            Some(format!("{parent}/{name}"))
        }
    }

    fn make_dir_attr(&self, ino: u64) -> FileAttr {
        let now = SystemTime::now();
        FileAttr {
            ino,
            size: 0,
            blocks: 0,
            atime: now,
            mtime: now,
            ctime: now,
            crtime: now,
            kind: FileType::Directory,
            perm: 0o755,
            nlink: 2,
            uid: self.uid,
            gid: self.gid,
            rdev: 0,
            blksize: BLOCK_SIZE as u32,
            flags: 0,
        }
    }

    fn make_file_attr(&self, ino: u64, size: u64, mode: u32) -> FileAttr {
        let now = SystemTime::now();
        let blocks = size.div_ceil(512); // 512-byte blocks for stat
        FileAttr {
            ino,
            size,
            blocks,
            atime: now,
            mtime: now,
            ctime: now,
            crtime: now,
            kind: FileType::RegularFile,
            perm: (mode & 0o7777) as u16,
            nlink: 1,
            uid: self.uid,
            gid: self.gid,
            rdev: 0,
            blksize: BLOCK_SIZE as u32,
            flags: 0,
        }
    }

    fn make_file_attr_from_header(
        &self,
        ino: u64,
        header: &crate::fs::inode::FileHeader,
    ) -> FileAttr {
        let to_systime = |ts: i64| UNIX_EPOCH + Duration::from_secs(ts.max(0) as u64);
        let blocks = header.file_size.div_ceil(512);
        FileAttr {
            ino,
            size: header.file_size,
            blocks,
            atime: to_systime(header.accessed_at),
            mtime: to_systime(header.modified_at),
            ctime: to_systime(header.modified_at),
            crtime: to_systime(header.created_at),
            kind: FileType::RegularFile,
            perm: (header.mode & 0o7777) as u16,
            nlink: 1,
            uid: self.uid,
            gid: self.gid,
            rdev: 0,
            blksize: BLOCK_SIZE as u32,
            flags: 0,
        }
    }
}

impl Filesystem for VoidFsHandler {
    fn lookup(&mut self, _req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEntry) {
        let child = match self.child_path(parent, name) {
            Some(p) => p,
            None => {
                reply.error(libc::ENOENT);
                return;
            }
        };

        // Check if it's a directory
        let parent_path = match self.get_path(parent) {
            Some(p) => p.to_string(),
            None => {
                reply.error(libc::ENOENT);
                return;
            }
        };

        let dir_idx = match list_dir(&mut self.image, &self.session_secret, &parent_path) {
            Ok(idx) => idx,
            Err(_) => {
                reply.error(libc::EIO);
                return;
            }
        };

        let name_str = match name.to_str() {
            Some(s) => s,
            None => {
                reply.error(libc::ENOENT);
                return;
            }
        };

        match dir_idx.get_type(name_str) {
            Some(VoidFileType::Directory) => {
                let ino = self.assign_ino(child);
                reply.entry(&TTL, &self.make_dir_attr(ino), 0);
            }
            Some(VoidFileType::File) => {
                let ino = self.assign_ino(child.clone());
                match ops::stat(&mut self.image, &self.session_secret, &child) {
                    Ok(Some(header)) => {
                        reply.entry(&TTL, &self.make_file_attr_from_header(ino, &header), 0);
                    }
                    Ok(None) => {
                        reply.error(libc::ENOENT);
                    }
                    Err(_) => {
                        reply.error(libc::EIO);
                    }
                }
            }
            None => {
                reply.error(libc::ENOENT);
            }
        }
    }

    fn getattr(&mut self, _req: &Request<'_>, ino: u64, _fh: Option<u64>, reply: ReplyAttr) {
        let path = match self.get_path(ino) {
            Some(p) => p.to_string(),
            None => {
                reply.error(libc::ENOENT);
                return;
            }
        };

        // Root is always a directory
        if path == "/" {
            reply.attr(&TTL, &self.make_dir_attr(ino));
            return;
        }

        // Check parent dirindex to determine type
        let parent = parent_of(&path).to_string();
        let name = match filename_of(&path) {
            Some(n) => n.to_string(),
            None => {
                // Root path — treat as directory
                reply.attr(&TTL, &self.make_dir_attr(ino));
                return;
            }
        };

        let dir_idx = match list_dir(&mut self.image, &self.session_secret, &parent) {
            Ok(idx) => idx,
            Err(_) => {
                reply.error(libc::EIO);
                return;
            }
        };

        match dir_idx.get_type(&name) {
            Some(VoidFileType::Directory) => {
                reply.attr(&TTL, &self.make_dir_attr(ino));
            }
            Some(VoidFileType::File) => {
                match ops::stat(&mut self.image, &self.session_secret, &path) {
                    Ok(Some(header)) => {
                        reply.attr(&TTL, &self.make_file_attr_from_header(ino, &header));
                    }
                    Ok(None) => {
                        reply.error(libc::ENOENT);
                    }
                    Err(_) => {
                        reply.error(libc::EIO);
                    }
                }
            }
            None => {
                // Could be a newly created entry not yet in dirindex — treat as not found
                reply.error(libc::ENOENT);
            }
        }
    }

    fn readdir(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        _fh: u64,
        offset: i64,
        mut reply: ReplyDirectory,
    ) {
        let path = match self.get_path(ino) {
            Some(p) => p.to_string(),
            None => {
                reply.error(libc::ENOENT);
                return;
            }
        };

        let dir_idx = match list_dir(&mut self.image, &self.session_secret, &path) {
            Ok(idx) => idx,
            Err(_) => {
                reply.error(libc::EIO);
                return;
            }
        };

        let entries: Vec<(u64, FileType, String)> = {
            let mut v = vec![
                (ino, FileType::Directory, ".".to_string()),
                (ino, FileType::Directory, "..".to_string()),
            ];
            for entry in &dir_idx.entries {
                let child = join_path(&path, &entry.name);
                let child_ino = self.assign_ino(child);
                let kind = match entry.entry_type {
                    VoidFileType::File => FileType::RegularFile,
                    VoidFileType::Directory => FileType::Directory,
                };
                v.push((child_ino, kind, entry.name.clone()));
            }
            v
        };

        for (i, (ino, kind, name)) in entries.iter().enumerate().skip(offset as usize) {
            if reply.add(*ino, (i + 1) as i64, *kind, name) {
                break; // buffer full
            }
        }
        reply.ok();
    }

    fn open(&mut self, _req: &Request<'_>, ino: u64, _flags: i32, reply: ReplyOpen) {
        let path = match self.get_path(ino) {
            Some(p) => p.to_string(),
            None => {
                reply.error(libc::ENOENT);
                return;
            }
        };

        // Load file data into buffer
        let data = match read_file(&mut self.image, &self.session_secret, &path) {
            Ok(Some(d)) => d,
            Ok(None) => Zeroizing::new(Vec::new()),
            Err(_) => {
                reply.error(libc::EIO);
                return;
            }
        };

        let fh = self.next_fh;
        self.next_fh += 1;
        self.open_files.insert(
            fh,
            OpenFile {
                ino,
                data,
                dirty: false,
            },
        );
        reply.opened(fh, 0);
    }

    fn read(
        &mut self,
        _req: &Request<'_>,
        _ino: u64,
        fh: u64,
        offset: i64,
        size: u32,
        _flags: i32,
        _lock_owner: Option<u64>,
        reply: ReplyData,
    ) {
        let file = match self.open_files.get(&fh) {
            Some(f) => f,
            None => {
                reply.error(libc::EBADF);
                return;
            }
        };

        let offset = offset as usize;
        if offset >= file.data.len() {
            reply.data(&[]);
        } else {
            let end = (offset + size as usize).min(file.data.len());
            reply.data(&file.data[offset..end]);
        }
    }

    fn write(
        &mut self,
        _req: &Request<'_>,
        _ino: u64,
        fh: u64,
        offset: i64,
        data: &[u8],
        _write_flags: u32,
        _flags: i32,
        _lock_owner: Option<u64>,
        reply: ReplyWrite,
    ) {
        let file = match self.open_files.get_mut(&fh) {
            Some(f) => f,
            None => {
                reply.error(libc::EBADF);
                return;
            }
        };

        let offset = offset as usize;
        let end = offset + data.len();

        // Extend buffer if needed
        if end > file.data.len() {
            file.data.resize(end, 0);
        }
        file.data[offset..end].copy_from_slice(data);
        file.dirty = true;

        reply.written(data.len() as u32);
    }

    fn flush(
        &mut self,
        _req: &Request<'_>,
        _ino: u64,
        fh: u64,
        _lock_owner: u64,
        reply: ReplyEmpty,
    ) {
        if let Some(file) = self.open_files.get(&fh) {
            if file.dirty {
                let ino = file.ino;
                let data = Zeroizing::new(file.data.to_vec()); // clone, auto-zeroized on drop
                let path = match self.get_path(ino) {
                    Some(p) => p.to_string(),
                    None => {
                        reply.error(libc::EIO);
                        return;
                    }
                };
                let result = write_file(&mut self.image, &self.session_secret, &path, &data);
                match result {
                    Ok(()) => {
                        self.open_files.get_mut(&fh).unwrap().dirty = false;
                    }
                    Err(_) => {
                        reply.error(libc::EIO);
                        return;
                    }
                }
            }
        }
        reply.ok();
    }

    fn release(
        &mut self,
        _req: &Request<'_>,
        _ino: u64,
        fh: u64,
        _flags: i32,
        _lock_owner: Option<u64>,
        _flush: bool,
        reply: ReplyEmpty,
    ) {
        if let Some(file) = self.open_files.remove(&fh) {
            if file.dirty {
                let path = match self.get_path(file.ino) {
                    Some(p) => p.to_string(),
                    None => {
                        reply.error(libc::EIO);
                        return;
                    }
                };
                if write_file(&mut self.image, &self.session_secret, &path, &file.data).is_err() {
                    reply.error(libc::EIO);
                    return;
                }
            }
        }
        reply.ok();
    }

    fn create(
        &mut self,
        _req: &Request<'_>,
        parent: u64,
        name: &OsStr,
        mode: u32,
        _umask: u32,
        _flags: i32,
        reply: ReplyCreate,
    ) {
        let child = match self.child_path(parent, name) {
            Some(p) => p,
            None => {
                reply.error(libc::EINVAL);
                return;
            }
        };

        // Create empty file
        if let Err(e) = ops::create_file(&mut self.image, &self.session_secret, &child, &[]) {
            reply.error(to_errno(&e));
            return;
        }

        let ino = self.assign_ino(child);
        let fh = self.next_fh;
        self.next_fh += 1;
        self.open_files.insert(
            fh,
            OpenFile {
                ino,
                data: Zeroizing::new(Vec::new()),
                dirty: false,
            },
        );

        let attr = self.make_file_attr(ino, 0, mode);
        reply.created(&TTL, &attr, 0, fh, 0);
    }

    fn unlink(&mut self, _req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEmpty) {
        let child = match self.child_path(parent, name) {
            Some(p) => p,
            None => {
                reply.error(libc::ENOENT);
                return;
            }
        };

        match ops::delete_file(&mut self.image, &self.session_secret, &child) {
            Ok(()) => reply.ok(),
            Err(ref e) => reply.error(to_errno(e)),
        }
    }

    fn mkdir(
        &mut self,
        _req: &Request<'_>,
        parent: u64,
        name: &OsStr,
        _mode: u32,
        _umask: u32,
        reply: ReplyEntry,
    ) {
        let child = match self.child_path(parent, name) {
            Some(p) => p,
            None => {
                reply.error(libc::EINVAL);
                return;
            }
        };

        if let Err(e) = ops::mkdir(&mut self.image, &self.session_secret, &child) {
            reply.error(to_errno(&e));
            return;
        }

        let ino = self.assign_ino(child);
        reply.entry(&TTL, &self.make_dir_attr(ino), 0);
    }

    fn rmdir(&mut self, _req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEmpty) {
        let child = match self.child_path(parent, name) {
            Some(p) => p,
            None => {
                reply.error(libc::ENOENT);
                return;
            }
        };

        match ops::rmdir(&mut self.image, &self.session_secret, &child) {
            Ok(()) => reply.ok(),
            Err(ref e) => reply.error(to_errno(e)),
        }
    }

    fn setattr(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        _mode: Option<u32>,
        _uid: Option<u32>,
        _gid: Option<u32>,
        size: Option<u64>,
        _atime: Option<fuser::TimeOrNow>,
        _mtime: Option<fuser::TimeOrNow>,
        _ctime: Option<SystemTime>,
        fh: Option<u64>,
        _crtime: Option<SystemTime>,
        _chgtime: Option<SystemTime>,
        _bkuptime: Option<SystemTime>,
        _flags: Option<u32>,
        reply: ReplyAttr,
    ) {
        // Handle truncate (size change)
        if let Some(new_size) = size {
            let new_size = new_size as usize;

            // If there's an open file handle, truncate the buffer
            if let Some(fh_id) = fh {
                if let Some(file) = self.open_files.get_mut(&fh_id) {
                    file.data.resize(new_size, 0);
                    file.dirty = true;
                    let attr = self.make_file_attr(ino, new_size as u64, 0o644);
                    reply.attr(&TTL, &attr);
                    return;
                }
            }

            // No open handle — read, truncate, write back
            let path = match self.get_path(ino) {
                Some(p) => p.to_string(),
                None => {
                    reply.error(libc::ENOENT);
                    return;
                }
            };

            let mut data = match read_file(&mut self.image, &self.session_secret, &path) {
                Ok(Some(d)) => d,
                Ok(None) => Zeroizing::new(Vec::new()),
                Err(_) => {
                    reply.error(libc::EIO);
                    return;
                }
            };

            data.resize(new_size, 0);
            if write_file(&mut self.image, &self.session_secret, &path, &data).is_err() {
                reply.error(libc::EIO);
                return;
            }

            let attr = self.make_file_attr(ino, new_size as u64, 0o644);
            reply.attr(&TTL, &attr);
            return;
        }

        // For other setattr calls, just return current attributes
        let path = match self.get_path(ino) {
            Some(p) => p.to_string(),
            None => {
                reply.error(libc::ENOENT);
                return;
            }
        };

        if path == "/" {
            reply.attr(&TTL, &self.make_dir_attr(ino));
            return;
        }

        match ops::stat(&mut self.image, &self.session_secret, &path) {
            Ok(Some(header)) => {
                reply.attr(&TTL, &self.make_file_attr_from_header(ino, &header));
            }
            Ok(None) => {
                // Might be a directory
                reply.attr(&TTL, &self.make_dir_attr(ino));
            }
            Err(_) => {
                reply.error(libc::EIO);
            }
        }
    }

    fn statfs(&mut self, _req: &Request<'_>, _ino: u64, reply: ReplyStatfs) {
        let total = self.image.total_blocks();
        reply.statfs(
            total,     // total blocks
            total / 2, // free blocks (estimate — we can't know precisely)
            total / 2, // available blocks
            0,         // total inodes (unknown)
            0,         // free inodes
            BLOCK_SIZE as u32,
            255, // max name length
            BLOCK_SIZE as u32,
        );
    }

    fn opendir(&mut self, _req: &Request<'_>, _ino: u64, _flags: i32, reply: ReplyOpen) {
        reply.opened(0, 0);
    }

    fn releasedir(
        &mut self,
        _req: &Request<'_>,
        _ino: u64,
        _fh: u64,
        _flags: i32,
        reply: ReplyEmpty,
    ) {
        reply.ok();
    }

    fn access(&mut self, _req: &Request<'_>, _ino: u64, _mask: i32, reply: ReplyEmpty) {
        reply.ok();
    }

    fn destroy(&mut self) {
        // Flush superblock with updated generation on unmount
        self.superblock.generation += 1;
        let _ = write_superblock(&mut self.image, &self.master_secret, &self.superblock);
    }
}
