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

### 1. Build

```bash
# Without FUSE (CLI only: put/get/ls/rm)
cargo build --release

# With FUSE (adds mount/unmount — requires macFUSE or libfuse3)
cargo build --features fuse --release
```

Prerequisites: Rust 1.70+. For FUSE: macOS needs [macFUSE](https://macfuse.github.io/), Linux needs `apt install libfuse3-dev pkg-config`.

### 2. Create a vault

```bash
darkfs create vault.img 1G
```

This fills a file with random noise. Right now it's just noise. A passphrase will give it meaning.

### 3. Store files

```bash
darkfs put vault.img secret.pdf          # enter passphrase when prompted
darkfs put vault.img taxes.xlsx
darkfs put vault.img --name /docs/notes.txt notes.txt
darkfs mkdir vault.img /photos
```

### 4. List and retrieve

```bash
darkfs ls vault.img                      # enter same passphrase
darkfs get vault.img secret.pdf .        # writes to current directory
darkfs info vault.img                    # file count, storage used, tree
```

### 5. Now try a wrong passphrase

```bash
darkfs ls vault.img                      # enter a DIFFERENT passphrase
# → (empty)
# No error. No "wrong password." Just... nothing.
```

This is the key moment. The system can't tell the difference between a wrong passphrase, a fresh vault, and a random file from `/dev/urandom`. All three look the same. **That's the deniability.**

### 6. Delete files

```bash
darkfs rm vault.img secret.pdf           # overwritten with random noise — gone
```

### 7. Mount as a folder (FUSE)

```bash
darkfs mount vault.img ~/private         # enter passphrase once
cp document.pdf ~/private/               # no passphrase needed
ls ~/private/                            # no passphrase needed
darkfs unmount ~/private                 # keys wiped from memory
```

## Passphrase Handling

Each CLI command (`put`, `get`, `ls`, `rm`, `info`, `mkdir`) prompts for the passphrase, derives keys, performs the operation, then wipes everything from memory and exits. This is the safest mode — keys exist only for milliseconds.

If entering the passphrase repeatedly is impractical, you have two options:

```bash
# Option 1: FUSE mount — enter passphrase once, use as a normal folder
darkfs mount vault.img ~/private
# Now use cp, mv, cat, etc. freely — no passphrase prompts
darkfs unmount ~/private                 # keys wiped on unmount

# Option 2: Environment variable — for scripts (use with caution)
DARKFS_PASSPHRASE="mypass" darkfs put vault.img file.txt
# The variable is cleared from the process environment after reading,
# but may still be visible in shell history or process listings.
```

## Multiple Passphrases (Deniability)

The same vault can hold multiple independent filesystems — one per passphrase. They don't know about each other. Nobody can prove more than one exists.

```bash
# Passphrase "vacation2024" — harmless decoy files
darkfs put vault.img beach.jpg
darkfs put vault.img recipes.txt

# Passphrase "kJ7$mQ9!xR2&nP4" — real secrets
darkfs put vault.img accounts.xlsx
darkfs put vault.img classified.pdf

# If compelled to reveal a passphrase, give "vacation2024".
# The adversary sees beach photos and recipes.
# They cannot prove another passphrase exists.
# They cannot prove the vault contains anything else.
```

## How passphrases work

There is no password database. Nothing is stored. The passphrase doesn't *unlock* anything — it *constructs* the filesystem.

```
passphrase → Argon2id → master_secret → HMAC → block positions + keys
```

Every passphrase deterministically generates a unique set of block positions and encryption keys. The correct passphrase generates positions that happen to contain encrypted data. A wrong passphrase generates positions that contain random noise — which is indistinguishable from "no data."

This means:
- **No "wrong password" error** — the system genuinely can't tell
- **No password recovery** — there's nothing to recover from
- **No proof of existence** — the vault looks identical whether it has 0 or 100 filesystems

> **The golden rule: remember your passphrase.** There is no reset. There is no recovery. There is no proof it ever existed. That's the point.

## Best Use Cases

**USB stick.** Create a vault on a flash drive. If the drive is lost, seized, or inspected, it looks like a corrupted or wiped drive — random data with no filesystem signature. Border agents, thieves, or forensic tools find nothing.

```bash
# Create a vault on a USB stick (replace with your device path)
darkfs create /Volumes/USBSTICK/random.bin 8G

# Store files
darkfs put /Volumes/USBSTICK/random.bin documents.zip

# On any other machine with darkfs installed
darkfs get /Volumes/USBSTICK/random.bin documents.zip .
```

**Portable file on cloud storage.** Upload `vault.img` to Dropbox, Google Drive, or any cloud service. It's just a blob of random bytes. The cloud provider can't identify it. Download it anywhere, enter your passphrase, get your files.

**Alongside real data.** Keep `random.bin` next to normal files on the same drive. It looks like a disk image, a swap file, or leftover data. Nobody can prove otherwise.

**Decoy under compulsion.** If forced to reveal a passphrase, give the decoy. The adversary sees harmless files. They have no way to determine if another passphrase exists — technically or mathematically.

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
