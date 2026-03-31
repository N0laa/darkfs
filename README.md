# darkfs

**A deniable steganographic filesystem. Nothing to see here.**

darkfs is a FUSE-based encrypted filesystem where the entire disk image is indistinguishable from random data. No headers, no magic bytes, no metadata, no partition table — nothing reveals whether the image is in use or was simply filled with `/dev/urandom`.

The only secret is a passphrase in your head. Everything else — block locations, encryption keys, directory structure — is deterministically derived from that passphrase.

> **Warning**: This is experimental cryptographic software that has not been externally audited. It has undergone multiple internal security audits (see [SECURITY.md](SECURITY.md)) with all findings fixed, but should not be your only protection for life-critical data. Use alongside established tools, not as a replacement.

## Why darkfs?

Most encryption tools protect your data. darkfs goes further — it hides the fact that data exists at all.

This project started as a research question: **can software be truly invisible?** Not just encrypted, but indistinguishable from nothing. A file that looks like random noise. A filesystem that can't be proven to exist. A passphrase that can't be proven wrong.

Existing tools like VeraCrypt and LUKS do encryption well, but they leave fingerprints — headers, partition tables, magic bytes. An adversary doesn't need to break the crypto if they can simply prove you're hiding something. In a world where big tech and surveillance systems grow more capable every year, the ability to say "there's nothing here" — and have that be mathematically unfalsifiable — matters.

darkfs is for anyone who thinks that should be possible. Journalists, activists, researchers, or anyone who believes privacy isn't just about locking the door — it's about making the door disappear.

## How It Works

```
passphrase ──► Argon2id ──► master_secret
                                │
                  ┌─────────────┼─────────────┐
                  ▼             ▼             ▼
            superblock     session_secret   void mask
            (5-of-9       (per-block keys)  (ChaCha20
             shards)                         noise layer)
                  │             │             │
                  ▼             ▼             ▼
               ┌──────────────────────────────────┐
               │  Image: indistinguishable from    │
               │  /dev/urandom                     │
               └──────────────────────────────────┘
```

Every block on disk: `XChaCha20-Poly1305(data) XOR ChaCha20(mask)` — two independent encryption layers. The entire image passes all statistical randomness tests.

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

# Create a 2 GiB vault (filled with random data)
darkfs create vault.img 2G

# Store a file (enter passphrase when prompted)
darkfs put vault.img secret.pdf

# Retrieve a file
darkfs get vault.img secret.pdf .

# List files
darkfs ls vault.img

# Or mount with FUSE (requires --features fuse)
darkfs mount vault.img ~/private
cp document.pdf ~/private/
ls ~/private/
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

### `darkfs create` -- Create a vault

```bash
darkfs create vault.img 500M
darkfs create vault.img 2G
```

### `darkfs mount` -- Mount as FUSE filesystem

```bash
darkfs mount vault.img ~/private
```

### `darkfs unmount` -- Unmount

```bash
darkfs unmount ~/private
# or: umount ~/private
```

### `darkfs info` -- Show vault info

```bash
darkfs info vault.img
```

Requires the correct passphrase. Shows file count, directory count, data stored, and a file listing.

### `darkfs put` / `darkfs get` -- Direct vault access

```bash
# Store a file without mounting
darkfs put vault.img secret.txt

# Retrieve a file without mounting
darkfs get vault.img secret.txt .

# List files
darkfs ls vault.img

# Delete a file
darkfs rm vault.img secret.txt
```

## Multiple Passphrases (Deniability)

```bash
# Passphrase A: decoy filesystem with harmless files
darkfs mount vault.img ~/private    # enter passphrase A
cp family-photos/*.jpg ~/private/
umount ~/private

# Passphrase B: real sensitive data
darkfs mount vault.img ~/private    # enter passphrase B
cp classified.pdf ~/private/
umount ~/private

# Nobody can prove passphrase B exists.
# Nobody can prove there are 2 filesystems.
# If compelled to reveal a passphrase, give A.
```

## Threat Model

### What darkfs protects against

- **Disk seizure**: An attacker with the image file cannot determine if it contains data or is random noise.
- **Compelled disclosure**: You can reveal a decoy passphrase. The attacker cannot prove another passphrase exists.
- **Forensic analysis**: No headers, magic bytes, partition tables, or statistical anomalies.

### What darkfs does NOT protect against

- **Active surveillance**: An attacker watching your system while darkfs is running can observe I/O patterns, memory allocation (Argon2id uses 256 MiB), and the process name.
- **Multi-snapshot analysis**: An attacker comparing two copies of the image can see which blocks changed. Decoy writes and tier-based I/O padding limit what is revealed, but approximate file size (within tier boundaries) is still observable.
- **Weak passphrases**: Use 12+ characters with high entropy. The deterministic salt (derived from image size) means dictionary attacks are amortized across all users with the same image size.
- **Rubber-hose cryptanalysis**: darkfs provides plausible deniability, not resistance to physical coercion.

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

| Feature | darkfs | VeraCrypt Hidden Volume | StegFS | Artifice |
|---------|--------|------------------------|--------|----------|
| IS the filesystem | Yes | No (hides inside another) | No (hides in free space) | No (hides in free space) |
| Multiple passphrases | Unlimited | 2 (outer + hidden) | Limited | Limited |
| No detectable structure | Yes | Header exists | Requires cover FS | Requires cover FS |
| Modern crypto | XChaCha20/Argon2id | AES/PBKDF2 | Varies | AES |
| Language | Rust | C/C++ | C | C |

## Limitations

- **Rename is O(file_size)**: Block locations are derived from file paths, so renaming requires re-encrypting all blocks. Currently not implemented (returns ENOSYS).
- **No journaling**: A crash during write can leave files in an inconsistent state. Block 0 is written last as a basic commit marker.
- **Collision risk**: With 16-slot cuckoo hashing, practical fill rate is ~50-60%. Keep usage below 50% for safety.
- **No file locking**: Concurrent access to the same image will corrupt data.
- **macOS extended attributes**: Finder creates `._*` files on non-HFS filesystems. These are harmless encrypted data but consume blocks.

## Documentation

- [ARCHITECTURE.md](ARCHITECTURE.md) — Technical design, key derivation chain, block layout, collision resolution
- [SECURITY.md](SECURITY.md) — Security audit findings, threat model, known limitations
- [CONTRIBUTING.md](CONTRIBUTING.md) — Development setup, code style, testing guidelines
- [CHANGELOG.md](CHANGELOG.md) — Release history

## License

MPL-2.0
