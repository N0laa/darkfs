# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Security
- **CRITICAL**: Fixed `claim_file_blocks` using `decrypt_block` instead of `decrypt_block_masked`, which caused blocks 1..N of multi-block files to never be claimed during `populate_claims` — leading to silent data corruption on image reopen (DA-1)
- Superblock shards now void-masked with `encrypt_block_masked`, matching file blocks (DA-2)
- Superblock HMAC integrity check now uses constant-time comparison via `subtle::ConstantTimeEq` (DA-3)
- Timing equalization now runs ChaCha20 keystream only (no extra Poly1305), matching the success path exactly (DA-4)
- Dummy buffers in slot functions are now zeroized after use (DA-5)
- Superblock writes now include 7 random decoy blocks to mask shard positions in multi-snapshot analysis (DA-7)
- Added minimum image size validation (DA-9)
- Full deep security audit with 15 adversarial PoC tests

### Added
- `tests/pentest_round2.rs` — deep audit pentest suite
- `SECURITY.md` — comprehensive security audit documentation
- `CONTRIBUTING.md`
- `CHANGELOG.md`

## [0.1.0] — 2026-03-31

### Added
- Initial release
- Deniable steganographic filesystem with XChaCha20-Poly1305 + Argon2id
- FUSE mount support (feature-gated)
- CLI: create, put, get, ls, rm, mkdir, info, mount, unmount
- Multi-passphrase support (unlimited independent filesystems per image)
- QSMM integration: 5-of-9 shattered superblock, void masking
- 16-slot cuckoo hashing for block collision resolution
- COW multi-block writes for crash safety
- Tier-based I/O padding (read + write)
- Statistical verification tool (`stats-verify`)
