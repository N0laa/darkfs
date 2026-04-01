# darkfs Architecture

## Design Principle

**The only secret is a passphrase in the user's head.** Everything else -- block locations, encryption keys, directory structure -- is deterministically derived from that passphrase. The design goal is that a static image is indistinguishable from random data; see [SECURITY.md](SECURITY.md) for what has been verified and what limitations remain.

## Layer Diagram

```
                         +-----------------+
                         |   FUSE / CLI    |  fuse/handler.rs, main.rs
                         +-----------------+
                                 |
                         +-----------------+
                         |   Filesystem    |  fs/ops.rs
                         |  (directories,  |  fs/directory.rs
                         |   file ops)     |  fs/file.rs, fs/inode.rs
                         +-----------------+
                                 |
                         +-----------------+
                         |   Block Store   |  store/slots.rs
                         |  (collision     |  store/image.rs
                         |   resolution,   |  store/superblock.rs
                         |   superblock)   |
                         +-----------------+
                                 |
                         +-----------------+
                         |     Crypto      |  crypto/kdf.rs
                         |  (keys, cipher, |  crypto/keys.rs
                         |   locator)      |  crypto/cipher.rs
                         |                 |  crypto/locator.rs
                         +-----------------+
```

## Key Derivation Chain

```
passphrase (user's head)
    |
    v
Argon2id(passphrase, salt=SHA256("darkfs-v1-{image_size}"), m=256MB, t=4)
    |
    v
master_secret: [u8; 32]    <-- Zeroizing, never written to disk
    |
    +---> superblock_offset = HMAC-SHA256(master_secret, "darkfs-superblock") % total_blocks
    |
    +---> superblock_key = HKDF-Expand(master_secret, "darkfs-superblock-key")
    |         --> decrypts the superblock to recover random_salt
    |
    +---> session_secret = HKDF-Expand(master_secret, "darkfs-session" || random_salt)
              |
              +---> block_offset = HMAC-SHA256(session_secret, len(path) || path || block_num || slot)
              |         --> disk block offset (where to read/write)
              |
              +---> block_key = HKDF-Expand(session_secret, "darkfs-block-key" || ... || epoch)
                        --> 32-byte XChaCha20 key (per block)
```

### Dual-Secret Architecture

- **master_secret**: derived from passphrase + image size. Used only for the superblock.
- **session_secret**: derived from master_secret + per-image random salt (stored in superblock). Used for all file operations.

This ensures two same-sized images with the same passphrase produce different file encryption keys (cross-image isolation), since each image has a unique random_salt generated on first use.

### Why deterministic salt?

Storing a random per-image salt on disk would break deniability -- it would be detectable metadata. Instead, the Argon2id salt is derived from the image size, which the user already knows. The per-image random salt is stored inside the encrypted superblock, which is itself indistinguishable from random data.

### Why XChaCha20 instead of ChaCha20?

XChaCha20 has a 24-byte (192-bit) nonce with birthday bound at ~2^96. Since nonces are generated randomly on every write, even at 2^48 writes the collision probability is ~2^-97 — completely negligible.

## Block Layout

Every block on disk is exactly 4096 bytes:

```
[24-byte random nonce | ciphertext | 16-byte Poly1305 auth tag]
|<----------------------- 4096 bytes ----------------------->|
```

The plaintext payload is 4056 bytes (4096 - 24 - 16).

For file block 0, the plaintext payload contains:

```
[FileHeader: 64 bytes] [file data: up to 3992 bytes] [zero padding]
|<---------------------- 4056 bytes ----------------------->|
```

FileHeader layout (64 bytes, little-endian):

```
Offset  Size  Field
0       8     magic ("VO1DF5\0\0") -- confirms correct decryption
8       1     version (1)
9       3     reserved (zeros)
12      8     file_size (bytes)
20      4     block_count
24      4     mode (POSIX permissions)
28      8     created_at (Unix timestamp)
36      8     modified_at
44      8     accessed_at
52      12    padding (zeros)
```

## Superblock

Each passphrase has an encrypted superblock at an HMAC-derived offset. It stores:

- **random_salt** (32 bytes): per-image nonce for session key derivation.
- **generation** (u64): monotonic counter for replay detection.
- **file_count** (u32): tracked files.
- **slot_map**: maps path hashes to slot indices for O(1) block lookups (max 305 entries).

The superblock is encrypted with a key derived from `master_secret` (not `session_secret`), since it must be readable before the session secret can be derived.

### Decoy Writes

Each superblock write is accompanied by 7 deterministic decoy writes at HMAC-derived offsets. This prevents an adversary with periodic snapshots from identifying the superblock by observing which block changes on every operation.

## Collision Resolution

Each logical block (identified by `path + block_num`) has `MAX_SLOTS = 16` candidate disk locations, computed by varying the `slot` parameter in the HMAC locator.

**Write algorithm (COW):**
1. For each slot 0..16 (always all 16, for timing resistance):
   - Compute disk offset via HMAC
   - Read existing block, try decrypting with our key
   - If decrypt succeeds: this slot is ours (remember it)
   - If decrypt fails: slot is available (remember first unclaimed one)
2. COW: prefer writing to a new slot (keeping old data intact)
3. Commit block 0 last (atomic marker)
4. Erase old COW slots + stale blocks from size-reducing overwrites
5. Pad writes with dummy random blocks to tier boundaries (1/16/256/4096)

**Read algorithm:**
1. For each slot 0..16 (always all 16, for timing resistance):
   - Compute disk offset, read block, try decrypt
   - Remember first successful result
2. Pad reads with dummy reads to tier boundaries (1/16/256/4096)
3. Return the result (or None if all 16 failed)

**Critical property:** We cannot distinguish "slot contains random noise" from "slot contains another filesystem's encrypted data." Both fail Poly1305 auth. This is what makes deniability work.

**Collision probability:** At fill fraction `f`, the probability that all 16 slots for a new block are occupied is `f^16`. At 50% full: 0.0015%. With 16 slots, practical fill rate is ~50-60% before slot exhaustion becomes likely.

## Directory Structure

Directories are stored as regular encrypted files with a special path convention:

```
Directory "/"     --> file at "/.dirindex"
Directory "/foo"  --> file at "/foo/.dirindex"
```

A DirIndex contains a bincode-serialized `Vec<DirEntry>`:
```rust
struct DirEntry {
    name: String,        // filename only, not full path
    entry_type: FileType // File or Directory
}
```

## Write Ordering (Crash Safety)

Files use copy-on-write (COW) multi-block writes for crash atomicity:

1. **Phase 1**: Write data blocks 1..N to *new* slots (old blocks remain intact)
2. **Phase 2**: Write block 0 (header + first data) — the atomic commit marker
3. **Phase 3**: Erase old COW slots (cleanup; failure here is harmless)
4. **Phase 4**: Erase stale blocks from previous larger version (forward secrecy)
5. **Phase 5**: Pad with dummy writes to tier boundary (side-channel mitigation)

If a crash occurs:
- During phase 1: old block 0 still points to old data, file unchanged
- During phase 2: old file intact (block 0 not yet updated)
- During phase 3-5: new file committed; old blocks are orphaned noise

## FUSE Handler

The FUSE handler (`fuse/handler.rs`) bridges between FUSE's inode-based API and darkfs's path-based storage:

- **Inode table**: In-memory `HashMap<u64, String>` mapping inode numbers to canonical paths. Built lazily as the kernel looks up entries.
- **Buffered I/O**: Files are loaded into memory on `open()`, modifications are buffered, and the entire file is re-encrypted and written on `release()` (close). This avoids partial-block writes but limits file size to available RAM.
- **No state on disk**: The inode table is ephemeral. On remount, inodes are reassigned.

## Attack Surface Analysis

### What an attacker sees (image at rest)
- A blob of data indistinguishable from `/dev/urandom` output
- Image size is a multiple of 4096 (common for disk images)
- No headers, no magic bytes, no partition table, no filesystem signatures

### What an attacker can do with the source code
- Compute HMAC locations for guessed passphrases
- Brute-force Argon2id (mitigated by 256 MiB memory cost)
- Observe that the binary is named "darkfs" (if found on the system)

### What an attacker can learn from multiple snapshots
- Which blocks changed between snapshots — decoy writes increase the noise, but shard positions are static and identifiable over many snapshots (see SECURITY.md DA-7)
- Approximate file sizes within tier boundaries (1/16/256/4096 blocks)

### What an attacker SHOULD NOT be able to learn (single-snapshot model)
- Whether the image contains any encrypted data at all
- How many filesystems exist on the image
- File names, directory structure, or file contents
- Which passphrase (if any) is "correct"

## Security Hardening Applied

| Fix | Description |
|-----|-------------|
| Random nonces per write | Fresh 24-byte nonce on every block write — no nonce reuse even on overwrite |
| Constant-time slot iteration | All 16 slots checked on every read/write/erase to prevent timing leaks |
| Timing equalization | Dummy encrypt on decrypt failure to equalize crypto work |
| COW multi-block writes | Crash-safe: data blocks written first, block 0 commits last |
| Stale block erasure | Overwriting with smaller file erases old excess blocks |
| Write-side I/O padding | Dummy writes pad to tier boundaries (matching read padding) |
| Superblock decoy writes | 7 deterministic decoy blocks written with each superblock update |
| Superblock overflow protection | Bounds check prevents panic on oversized slot map |
| Passphrase zeroization | `Zeroizing<String>` wrapper on passphrase input |
| Plaintext zeroization | All intermediate plaintext buffers zeroized on drop |
| Length-prefixed HMAC input | Path length prefix prevents concatenation ambiguity |
| Advisory file locking | `flock` exclusive lock prevents concurrent image access |
| Path validation | Reject null bytes, slashes, `.`/`..`, and reserved names in directory entries |

See [SECURITY.md](SECURITY.md) for the full audit report.
