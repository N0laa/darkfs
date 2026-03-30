# voidfs

**A deniable steganographic filesystem. Nothing to see here.**

voidfs is a FUSE-based encrypted filesystem where the entire disk image is indistinguishable from random data. No headers, no magic bytes, no metadata, no partition table -- nothing reveals whether the image is in use or was simply filled with `/dev/urandom`.

The only secret is a passphrase in your head. Everything else -- block locations, encryption keys, directory structure -- is deterministically derived from that passphrase.

## Key Properties

- **Deniable**: The image passes statistical randomness tests. There is no way to prove it contains a filesystem.
- **Multi-passphrase**: Multiple independent filesystems can coexist on the same image. Each passphrase reveals a different filesystem. Nobody can prove a second passphrase exists.
- **Wrong passphrase = empty filesystem**: Any passphrase "works" -- most just show an empty directory. No "wrong passphrase" error is ever returned.
- **Modern crypto**: XChaCha20-Poly1305, Argon2id, HKDF-SHA256, HMAC-SHA256.
- **Memory safe**: Written in Rust with `#![deny(unsafe_code)]`.

## Quick Start

```bash
# Build
cargo build --features fuse --release

# Create a 2 GiB void image (filled with random data)
mkvoid --size 2G --output vault.img

# Mount with passphrase
voidfs mount vault.img ~/private --dev    # --dev for fast KDF during development
Enter passphrase: ████████████

# Use like any normal directory
cp secret.pdf ~/private/
ls ~/private/
cat ~/private/secret.pdf

# Unmount
umount ~/private
# vault.img is now indistinguishable from random noise
```

## Installation

### Prerequisites

- Rust 1.70+
- macOS: [macFUSE](https://macfuse.github.io/) (`brew install macfuse`, approve in System Settings, reboot)
- Linux: `apt install libfuse3-dev pkg-config` (or equivalent)

### Build

```bash
# With FUSE support (mount/unmount commands)
cargo build --features fuse --release

# Without FUSE (library + direct read/write commands only)
cargo build --release
```

## Commands

### `mkvoid` -- Create a void image

```bash
mkvoid --size 64M --output vault.img
mkvoid --size 2G --output vault.img
```

### `voidfs mount` -- Mount as FUSE filesystem

```bash
voidfs mount vault.img ~/private
voidfs mount vault.img ~/private --dev    # fast KDF for development
```

### `voidfs unmount` -- Unmount

```bash
voidfs unmount ~/private
# or: umount ~/private
```

### `voidfs info` -- Show filesystem info

```bash
voidfs info --image vault.img --dev
```

Requires the correct passphrase. Shows file count, directory count, data stored, and a file listing.

### `voidfs write` / `voidfs read` -- Direct image access

```bash
# Write a file without mounting
voidfs write --image vault.img --file /secret.txt --input data.txt --dev

# Read a file without mounting
voidfs read --image vault.img --file /secret.txt --output recovered.txt --dev
```

## Multiple Passphrases (Deniability)

```bash
# Passphrase A: decoy filesystem with harmless files
voidfs mount vault.img ~/private    # enter passphrase A
cp family-photos/*.jpg ~/private/
umount ~/private

# Passphrase B: real sensitive data
voidfs mount vault.img ~/private    # enter passphrase B
cp classified.pdf ~/private/
umount ~/private

# Nobody can prove passphrase B exists.
# Nobody can prove there are 2 filesystems.
# If compelled to reveal a passphrase, give A.
```

## Threat Model

### What voidfs protects against

- **Disk seizure**: An attacker with the image file cannot determine if it contains data or is random noise.
- **Compelled disclosure**: You can reveal a decoy passphrase. The attacker cannot prove another passphrase exists.
- **Forensic analysis**: No headers, magic bytes, partition tables, or statistical anomalies.

### What voidfs does NOT protect against

- **Active surveillance**: An attacker watching your system while voidfs is running can observe I/O patterns, memory allocation (Argon2id uses 256 MiB), and the process name.
- **Multi-snapshot analysis**: An attacker comparing two copies of the image can see which blocks changed, revealing approximate file sizes.
- **Weak passphrases**: Use 12+ characters with high entropy. The deterministic salt (derived from image size) means dictionary attacks are amortized across all users with the same image size.
- **Rubber-hose cryptanalysis**: voidfs provides plausible deniability, not resistance to physical coercion.

### Crypto Stack

| Component | Algorithm | Purpose |
|-----------|-----------|---------|
| KDF | Argon2id (256 MiB, t=4) | Passphrase to master secret |
| Block encryption | XChaCha20-Poly1305 | Authenticated encryption per block |
| Key derivation | HKDF-SHA256 | Per-block key + nonce from master secret |
| Block location | HMAC-SHA256 | Deterministic mapping of (path, block) to disk offset |

## Performance

Benchmarks on Apple M-series (release build):

| Operation | Throughput |
|-----------|-----------|
| KDF (dev preset) | ~2.2 ms |
| Block encrypt (4080 B) | ~7 us |
| Block decrypt (4080 B) | ~9 us |
| File write (64 KB) | ~115 MiB/s |
| File read (64 KB) | ~152 MiB/s |

## Comparison with Existing Tools

| Feature | voidfs | VeraCrypt Hidden Volume | StegFS | Artifice |
|---------|--------|------------------------|--------|----------|
| IS the filesystem | Yes | No (hides inside another) | No (hides in free space) | No (hides in free space) |
| Multiple passphrases | Unlimited | 2 (outer + hidden) | Limited | Limited |
| No detectable structure | Yes | Header exists | Requires cover FS | Requires cover FS |
| Modern crypto | XChaCha20/Argon2id | AES/PBKDF2 | Varies | AES |
| Language | Rust | C/C++ | C | C |

## Limitations

- **Rename is O(file_size)**: Block locations are derived from file paths, so renaming requires re-encrypting all blocks. Currently not implemented (returns ENOSYS).
- **No journaling**: A crash during write can leave files in an inconsistent state. Block 0 is written last as a basic commit marker.
- **Collision risk**: At >50% image utilization, hash collisions become likely. Keep usage below 30-40% for safety.
- **No file locking**: Concurrent access to the same image will corrupt data.
- **macOS extended attributes**: Finder creates `._*` files on non-HFS filesystems. These are harmless encrypted data but consume blocks.

## License

MIT OR Apache-2.0
