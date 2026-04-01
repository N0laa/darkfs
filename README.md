# darkfs

**A research project exploring deniable steganographic storage.**

> **This is a research prototype, not a production tool.** It has not been externally audited. Do not rely on it as your sole protection for sensitive data. The cryptographic properties described here are design goals being tested — not guarantees.

## What is this?

darkfs is a FUSE-based encrypted filesystem where the entire disk image is indistinguishable from random data. No headers, no magic bytes, no metadata, no partition table — nothing reveals whether the image is in use or was simply filled with `/dev/urandom`.

The only secret is a passphrase. Everything else — block locations, encryption keys, directory structure — is deterministically derived from it.

## Research question

**Can software be truly invisible?** Not just encrypted, but indistinguishable from nothing.

Existing tools like VeraCrypt and LUKS protect the *contents* of your data, but they announce its *existence* — headers, partition tables, magic bytes. An adversary doesn't need to break the crypto if they can simply prove you're hiding something.

This project explores whether a filesystem can be built where the storage medium is cryptographically indistinguishable from random noise. Where any passphrase produces a valid (empty) result. Where multiple independent filesystems coexist without any detectable boundary. Where the answer to "is there data here?" is mathematically unanswerable.

The current implementation demonstrates that this is feasible. The [SECURITY.md](SECURITY.md) documents what works, what doesn't, and what remains to be solved.

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

Every block on disk: `XChaCha20-Poly1305(data) XOR ChaCha20(mask)` — two independent encryption layers. In internal testing, the image passes statistical randomness tests (chi-squared, entropy, serial correlation). See [SECURITY.md](SECURITY.md) for details and caveats.

## Key Properties

- **Deniable**: A static image passes statistical randomness tests in internal testing. Multi-snapshot analysis reveals write patterns (see Threat Model).
- **Multi-passphrase**: Multiple independent filesystems can coexist on the same image. Each passphrase reveals a different filesystem. Under the single-snapshot threat model, an adversary cannot determine how many passphrases exist.
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
# Under single-snapshot analysis, the adversary cannot determine
# if another passphrase exists.
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

## Example scenarios

These illustrate the deniability properties being explored, not endorsements for specific use:

- **Portable media.** A vault on a USB stick looks like a corrupted or wiped drive — random data with no filesystem signature. Forensic tools find nothing to analyze.
- **Cloud storage.** A vault file uploaded to any cloud service is just a blob of random bytes. The provider cannot identify its purpose.
- **Multi-passphrase.** The same image can hold independent filesystems under different passphrases. Under the single-snapshot threat model, there is no detectable boundary between them.

## Threat Model

### What darkfs protects against

- **Single-snapshot disk seizure**: In internal testing, an attacker with a single copy of the image file cannot distinguish it from random noise using standard statistical tests.
- **Compelled disclosure**: A decoy passphrase reveals a decoy filesystem. Under the single-snapshot model, the attacker cannot determine if other passphrases exist.
- **Forensic analysis**: No headers, magic bytes, or partition tables. Internal statistical testing shows no anomalies, but this has not been verified by an external auditor.

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

## Related work

| Approach | darkfs | VeraCrypt Hidden Volume | StegFS | Artifice |
|---------|--------|------------------------|--------|----------|
| Deniability model | Image IS noise | Hides inside another volume | Hides in free space | Hides in free space |
| Multiple passphrases | Unlimited | 2 (outer + hidden) | Limited | Limited |
| Detectable structure | None | Header exists | Requires cover FS | Requires cover FS |
| Crypto | XChaCha20/Argon2id | AES/PBKDF2 | Varies | AES |
| Language | Rust | C/C++ | C | C |

## Known limitations

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
