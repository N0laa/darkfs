# voidfs Architecture

## Design Principle

**The only secret is a passphrase in the user's head.** Everything else -- block locations, encryption keys, directory structure -- is deterministically derived from that passphrase. The image file is indistinguishable from random data.

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
                         |   resolution)   |
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
Argon2id(passphrase, salt=SHA256("voidfs-v1-{image_size}"), m=256MB, t=4)
    |
    v
master_secret: [u8; 32]    <-- Zeroizing, never written to disk
    |
    +---> HMAC-SHA256(master_secret, len(path) || path || block_num || slot)
    |         --> disk block offset (where to read/write)
    |
    +---> HKDF-Extract(salt=master_secret, ikm=master_secret)
              |
              +---> HKDF-Expand(prk, "voidfs-block-key" || len(path) || path || block_num)
              |         --> 32-byte XChaCha20 key (per block)
              |
              +---> HKDF-Expand(prk, "voidfs-block-nonce" || len(path) || path || block_num)
                        --> 24-byte XChaCha20 nonce (per block)
```

### Why deterministic salt?

Storing a random per-image salt on disk would break deniability -- it would be detectable metadata. Instead, the salt is derived from the image size, which the user already knows. This means two same-sized images with the same passphrase produce the same master secret. This is acceptable because:
1. The passphrase provides the primary entropy
2. Argon2id with 256 MiB makes brute-force infeasible for strong passphrases
3. The alternative (random salt on disk) would completely defeat the threat model

### Why XChaCha20 instead of ChaCha20?

ChaCha20 has a 12-byte nonce with birthday bound at ~2^48. Since nonces are derived from HKDF (not random), collisions would be deterministic and exploitable. XChaCha20 has a 24-byte nonce with birthday bound at ~2^96, making derived nonces safe.

## Block Layout

Every block on disk is exactly 4096 bytes:

```
[encrypted_payload: 4080 bytes] [poly1305_auth_tag: 16 bytes]
|<----------------------- 4096 bytes ----------------------->|
```

For file block 0, the plaintext payload contains:

```
[FileHeader: 64 bytes] [file data: up to 4016 bytes] [zero padding]
|<---------------------- 4080 bytes ----------------------->|
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

## Collision Resolution

Each logical block (identified by `path + block_num`) has `MAX_SLOTS = 5` candidate disk locations, computed by varying the `slot` parameter in the HMAC locator.

**Write algorithm:**
1. For each slot 0..5 (always all 5, for timing resistance):
   - Compute disk offset via HMAC
   - Read existing block, try decrypting with our key
   - If decrypt succeeds: this slot is ours (remember it)
   - If decrypt fails: slot is available (remember first one)
2. Write to our own slot if found, otherwise first available
3. If all 5 slots are occupied by other data: `NoSlotAvailable` error

**Read algorithm:**
1. For each slot 0..5 (always all 5, for timing resistance):
   - Compute disk offset, read block, try decrypt
   - Remember first successful result
2. Return the result (or None if all 5 failed)

**Critical property:** We cannot distinguish "slot contains random noise" from "slot contains another filesystem's encrypted data." Both fail Poly1305 auth. This is what makes deniability work -- if we could detect other filesystems, so could an attacker.

**Collision probability:** At fill fraction `f`, the probability that all 5 slots for a new block are occupied is `f^5`. At 30% full: 0.24%. At 50% full: 3.1%. Keep utilization below 40% for reliable operation.

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

Files are written blocks 1..N first, then block 0 last. Block 0 contains the FileHeader which acts as a commit marker. If a crash occurs mid-write:
- Blocks 1..N may be partially written (orphaned noise)
- Block 0 still points to the old data (or doesn't exist for new files)
- The old file remains intact (or the new file simply doesn't appear)

## FUSE Handler

The FUSE handler (`fuse/handler.rs`) bridges between FUSE's inode-based API and voidfs's path-based storage:

- **Inode table**: In-memory `HashMap<u64, String>` mapping inode numbers to canonical paths. Built lazily as the kernel looks up entries.
- **Buffered I/O**: Files are loaded into memory on `open()`, modifications are buffered, and the entire file is re-encrypted and written on `release()` (close). This avoids partial-block writes but limits file size to available RAM.
- **No state on disk**: The inode table is ephemeral. On remount, inodes are reassigned. This is fine because FUSE doesn't persist inode numbers across mounts.

## Attack Surface Analysis

### What an attacker sees (image at rest)
- A blob of data indistinguishable from `/dev/urandom` output
- Image size is a multiple of 4096 (common for disk images)
- No headers, no magic bytes, no partition table, no filesystem signatures

### What an attacker can do with the source code
- Compute HMAC locations for guessed passphrases
- Brute-force Argon2id (mitigated by 256 MiB memory cost)
- Observe that the binary is named "voidfs" (if found on the system)

### What an attacker can learn from multiple snapshots
- Which blocks changed between snapshots (approximate file sizes)
- That block-aligned 4096-byte writes occurred (consistent with many programs)

### What an attacker CANNOT learn
- Whether the image contains any encrypted data at all
- How many filesystems exist on the image
- File names, directory structure, or file contents
- Which passphrase (if any) is "correct"

## Security Hardening Applied

| Fix | Description |
|-----|-------------|
| Constant-time slot iteration | All 5 slots checked on every read/write/erase to prevent timing leaks |
| Crash-safe write ordering | Block 0 written last as commit marker |
| Passphrase zeroization | `Zeroizing<String>` wrapper on passphrase input |
| Plaintext zeroization | Intermediate decrypt buffer zeroized before drop |
| Length-prefixed HMAC input | Path length prefix prevents concatenation ambiguity |

See [SECURITY.md](SECURITY.md) for the full audit report.
