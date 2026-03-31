# darkfs Security Audit

Rounds 1–3 completed 2026-03-31. Round 4 pentest completed 2026-03-31.
Scope: crypto primitives, deniability, collision integrity, side channels, adversarial attacks, build hardening, penetration testing.

## Findings Summary

### Cryptographic (Step 1)

| # | Finding | Rating | Status |
|---|---------|--------|--------|
| C1 | ~~Nonce reuse on file overwrite~~ | ~~CRITICAL~~ | **FIXED** — random nonce per write |
| C2 | Nonce/key derivation is collision-free (length-prefixed HKDF info) | OK | Verified |
| C3 | Key separation is correct (distinct paths/blocks produce distinct keys) | OK | Verified |
| C4 | Deterministic salt enables precomputation for common image sizes | MEDIUM | By design — documented |
| C5 | HKDF salt=IKM is unconventional but safe with Argon2id output | LOW | Acceptable |
| C6 | XChaCha20-Poly1305 used correctly; tag always verified before returning data | OK | Verified |

### Deniability (Step 2)

| # | Finding | Rating | Status |
|---|---------|--------|--------|
| D1 | Static image: statistically indistinguishable from random | OK | **PASS** — verified by 14-test suite + Step 8 pentest |
| D2 | Two-snapshot diff reveals block count (approx file size) | MEDIUM | Known limitation |
| D3 | I/O pattern: 5-read-then-1-write per block | MEDIUM | Host-level only |
| D4 | Process name "darkfs" visible in ps/mount | HIGH | **FIXED** — FSName now configurable |
| D5 | DARKFS_PASSPHRASE env var visible in /proc | HIGH | Cleared after read; documented |
| D6 | Argon2id 256 MiB allocation is a behavioral signal | LOW | Inherent |
| D7 | Wrong passphrase: all 16 slots always iterated — timing leak eliminated | OK | **FIXED** |

### Collision & Integrity (Step 3)

| # | Finding | Rating | Status |
|---|---------|--------|--------|
| I1 | System unreliable above ~50% fill with MAX_SLOTS=16 | MEDIUM | Documented |
| I2 | Cross-passphrase block overwrites cause silent data loss | HIGH | Inherent to deniability |
| I3 | Crash-safe write ordering (block 0 last) | OK | **FIXED** |
| I4 | Crash during dirindex write can orphan files | MEDIUM | Documented |
| I5 | No file locking for concurrent access | HIGH | Documented |
| I6 | `.dirindex` filename collision possible | MEDIUM | Future fix |
| I7 | No path length validation | LOW | Future fix |

### Memory Safety & Side Channels (Step 4)

| # | Finding | Rating | Status |
|---|---------|--------|--------|
| S1 | master_secret in FUSE handler not Zeroizing | HIGH | **FIXED** |
| S2 | OpenFile.data (plaintext) not zeroized on close | MEDIUM | **FIXED** |
| S3 | flush() clones data without zeroizing clone | MEDIUM | **FIXED** |
| S4 | Passphrase in main.rs properly Zeroizing<String> | OK | Verified |
| S5 | Decrypted plaintext Vec zeroized in cipher.rs | OK | **FIXED** (Phase 1 audit) |
| S6 | Slot iteration constant-count (all 16 always) | OK | **FIXED** (Phase 1 audit) |
| S7 | Poly1305 tag comparison is constant-time (subtle crate) | OK | Verified |
| S8 | No mlock() — secrets can be swapped to disk | MEDIUM | Future fix |
| S9 | No core dump prevention | MEDIUM | Future fix |

### Adversarial Attacks (Step 6)

| Attack | Result | Notes |
|--------|--------|-------|
| Header scan | **FAILS** | No unencrypted structures on disk |
| Entropy analysis (NIST STS) | **FAILS** | Ciphertext is IND-CPA; passes all tests |
| Block pattern analysis | **FAILS** | Cannot distinguish encrypted from random blocks |
| Snapshot diff | **PARTIAL** | Reveals activity volume; superblock hidden by decoy writes |
| Memory forensics | **SUCCEEDS** | Master secret + path table + file buffers in RAM — **FIXED** (zeroize) |
| Known-plaintext | **FAILS** | Per-block HKDF keys; no KPA weakness in XChaCha20 |
| Birthday/HMAC brute-force | **FAILS** | Argon2id makes brute-force infeasible for strong passphrases |
| Cross-filesystem detection | **FAILS** | Core deniability property holds |
| SSD wear patterns | **THEORETICAL** | Requires firmware-level access; outside threat model |
| Compelled passphrase analysis | **OPERATIONAL** | Decoy must be plausible; user responsibility |

### Build & Deployment (Step 7)

| # | Finding | Status |
|---|---------|--------|
| B1 | All crypto deps are RustCrypto (audited) | OK |
| B2 | No network/telemetry deps | OK |
| B3 | Release: LTO + strip enabled | OK |
| B4 | Missing: panic=abort, codegen-units=1 | **FIXED** |
| B5 | Binary contains "darkfs" strings | Documented |
| B6 | tracing_subscriber unconditionally initialized | **FIXED** — gated |

### Final Penetration Test (Step 8)

Two 64MB images tested blind (one darkfs with 3 files, one pure /dev/urandom):

| Test | Image A | Image B | Distinguishable? |
|------|---------|---------|-------------------|
| Chi-squared | 239.24 | 260.60 | No (both < 341) |
| Mean byte | 127.4950 | 127.4947 | No |
| Serial correlation | -0.000312 | -0.000036 | No |
| Min block entropy | 7.9456 | 7.9438 | No |
| Monobit ratio | 0.499996 | 0.500001 | No |
| Compression ratio | 1.0003 | 1.0003 | No |
| Duplicate blocks | 0 | 0 | No |
| `file` command | "data" | "data" | No |

**Confidence: 0%. Cannot determine which image is darkfs. Deniability PASS.**

---

## Historical Finding: Nonce Reuse on Overwrite (C1) — FIXED

**Originally rated CRITICAL**, this was fixed by switching to random 24-byte nonces per write (see `cipher.rs`). Every block write generates a fresh random nonce, stored as the first 24 bytes of the on-disk block. Nonce collision probability at 2^48 writes is ~2^-97.

## Pentest Round 4 Findings

Full automated pentest with 25+ attacks across 7 categories. All findings below have been fixed.

| # | Finding | Severity | Status |
|---|---------|----------|--------|
| P1 | Stale blocks after size-reducing overwrite — old excess blocks not erased | HIGH | **FIXED** — `write_file` Phase 4 erases blocks `new_count..old_count` |
| P2 | Superblock serialization panic on >305 slot entries (buffer overflow) | HIGH | **FIXED** — bounds check returns `SuperblockFull` error |
| P2b | Stale `SUPERBLOCK_MAX_ENTRIES` constant (440 vs actual 305) | HIGH | **FIXED** — updated to 305 |
| P3 | Snapshot diff reveals superblock location (only block changing every write) | MEDIUM | **FIXED** — 7 deterministic decoy writes per superblock update |
| P4 | Write I/O count reveals exact file size (no write-side padding) | MEDIUM | **FIXED** — dummy writes pad to tier boundaries (1/16/256/4096) |
| P5 | `create_file("/")` panics via `assert!` in `filename_of` | LOW | **FIXED** — `filename_of` returns `Option`, callers return errors |
| P6 | Superblock is single point of failure (corrupt 1 block → total data loss) | MEDIUM | Known limitation — inherent to deniable design; documented |

### Attacks that failed (system is secure)

- HKDF salt==IKM distinguisher: chi-square 284.6, no bias
- XChaCha20 nonce birthday: collision at 2^48 writes is 2^-97
- Argon2id timing vs passphrase length: constant time
- Directory cycle stack overflow: path canonicalization prevents true cycles
- Deletion residue: erased blocks no longer decrypt
- Dual passphrase corruption: 0/100 files corrupted
- Statistical distinguishability (used vs fresh): identical chi-square, entropy, serial correlation
- Bincode deserialization OOM: rejects malformed data safely
- flock bypass: second open correctly returns ImageLocked
- Modular bias (u64 % total_blocks): ~1.4×10⁻¹³, negligible
- 500-file roundtrip integrity: all files byte-perfect
- 5000 create/delete cycles: no slot leaks or degradation

## Deniability Verdict

**At rest: PASS** — A static darkfs image is cryptographically and statistically indistinguishable from random data. Confirmed by 14-test statistical suite and blind penetration test.

**Under observation: PARTIAL** — Behavioral fingerprints exist (I/O patterns, memory allocation, process/mount names). All require active monitoring of the running system.

**Multi-snapshot: IMPROVED** — Random nonces prevent confidentiality breaks. Decoy writes mask superblock location. Write padding hides exact file sizes (observer learns only tier: 1/16/256/4096 blocks).

## Deep Security Audit (2026-03-31)

Full-source adversarial audit covering cryptographic analysis, deniability attacks, protocol-level attacks, implementation bugs, and side-channel analysis across both darkfs and qsmm codebases.

### New Findings

| # | Finding | Severity | Module | Status |
|---|---------|----------|--------|--------|
| DA-1 | `claim_file_blocks` uses `decrypt_block` (no void unmask) instead of `decrypt_block_masked` — blocks 1..N of multi-block files never claimed during `populate_claims`, enabling silent data corruption | **CRITICAL** | `fs/ops.rs:390` | **FIXED** |
| DA-2 | Superblock shards use `encrypt_block()` without void masking, while file blocks use `encrypt_block_masked()` — defense-in-depth gap | HIGH | `store/superblock.rs:383` | **FIXED** |
| DA-3 | Superblock integrity HMAC comparison uses non-constant-time `!=` instead of `subtle::ConstantTimeEq` | MEDIUM | `store/superblock.rs:248` | **FIXED** |
| DA-4 | Timing equalization is imperfect — failure path runs 2x Poly1305 vs 1x on success (extra ~2-5 us) | MEDIUM | `store/slots.rs:29` | **FIXED** |
| DA-5 | `dummy` buffer in slot functions contains decrypted plaintext but is never zeroized | MEDIUM | `store/slots.rs` | **FIXED** |
| DA-6 | `VOID_HW_ENTROPY` is a fixed constant — but file blocks use session_secret (per-image unique) as the void key, so masks ARE per-image unique in practice | ~~MEDIUM~~ FALSE POSITIVE | `crypto/cipher.rs:26` | N/A |
| DA-7 | Multi-snapshot analysis identifies shard positions: same 9 blocks change on every superblock update | MEDIUM | `store/superblock.rs` | **FIXED** |
| DA-8 | Multi-snapshot XOR of void-masked blocks: data region cancels when plaintext unchanged, revealing 1 bit per block | MEDIUM | qsmm `void/namespace.rs` | **FIXED** |
| DA-9 | No minimum image size validation — images with ≤ SHARD_N blocks leave no space for file data | LOW | `store/superblock.rs` | **FIXED** |

### DA-1: claim_file_blocks Data Corruption (CRITICAL)

**Attack scenario**: After reopening an image, `populate_claims()` walks the directory tree and attempts to claim block offsets for existing files. The `claim_file_blocks` function uses `decrypt_block()` (without void unmasking) to find each block's slot. Since all file blocks on disk are void-masked, `decrypt_block()` always fails, so blocks 1..N of multi-block files are never added to the claimed set. A subsequent file write whose HMAC-derived slot overlaps with an unclaimed block will silently overwrite it.

**Impact**: Silent data loss for any multi-block file after image reopen + new file write.

**PoC**: `tests/pentest_round2.rs::critical_claim_file_blocks_never_claims_multiblock`

**Fix**: In `ops.rs:390`, replace:
```rust
if crate::crypto::cipher::decrypt_block(&key, &raw).is_ok() {
```
with:
```rust
if crate::crypto::cipher::decrypt_block_masked(&key, &raw, master_secret, offset).is_ok() {
```

### DA-2: Superblock Shards Not Void-Masked (HIGH)

**Attack scenario**: File blocks are encrypted + void-masked (double layer). Superblock shards are only encrypted (single layer). While both look random individually, the inconsistency means an adversary with the master secret can identify shard blocks by checking which blocks change when void masking is applied/removed.

**Fix**: Use `encrypt_block_masked()` / `decrypt_block_masked()` for shard blocks in `superblock.rs`.

### DA-3: Non-Constant-Time HMAC Comparison (MEDIUM)

**Location**: `superblock.rs:248`: `if expected != actual`

**Fix**: `use subtle::ConstantTimeEq; if actual.ct_eq(&expected).unwrap_u8() == 0`

### DA-4: Timing Equalization Asymmetry (MEDIUM)

Success path: void_unmask (ChaCha20) + AEAD_decrypt (ChaCha20 + Poly1305) = 2x ChaCha20 + 1x Poly1305.
Failure path: void_unmask (ChaCha20) + AEAD_verify_fail (Poly1305) + equalize (ChaCha20 + Poly1305) = 2x ChaCha20 + 2x Poly1305.

**Fix**: Run dummy Poly1305 verify (not encrypt) in equalize, or always run both paths.

### DA-8: Multi-Snapshot XOR Data Leak (MEDIUM)

The void mask is deterministic per (seed, block_id). When the same block is sealed twice with identical data, XOR cancels the mask AND the data region, producing all zeros in the data portion. This reveals whether the plaintext changed (1 bit per block). When data changes, the XOR of the data region reveals the approximate plaintext length (zero/non-zero boundary within the tier).

**Fix**: Mix the per-seal random nonce into the mask derivation, making the mask stream unique per seal.

### Attacks that failed (system is secure)

- HKDF domain separation: all 12 info/domain strings are unique across qsmm and darkfs
- Known-plaintext on void mask: ChaCha20 is a PRF; recovering one block's mask doesn't help with others
- Malicious shard injection: AEAD encryption prevents false shard creation (adversary can only DoS)
- Session secret isolation: per-image random_salt ensures different encryption keys between images
- Shard position prediction: HMAC-SHA256 produces uniformly distributed offsets; no clustering detected
- Shard collision infinite loop: coupon collector bound; ~25 iterations worst case for 9-of-9

## Threat Model

1. Attacker has the source code and the image file
2. Attacker does NOT have the passphrase
3. Passphrase has >= 80 bits of entropy (recommended 12+ mixed chars)
4. Attacker may compel one passphrase (decoy filesystem)
5. Single-snapshot assumption: attacker sees the image at one point in time
6. No active surveillance of the running system

### Known Limitations

- **Deterministic salt** (C4): Argon2id salt derived from image size. Precomputation feasible for common sizes by well-funded adversaries. Mitigation: use non-standard image sizes.
- **Multi-snapshot** (D2): Block change patterns reveal write activity volume.
- **SSD wear-leveling**: Outside threat model; requires firmware-level access.
- **No mlock/core dump prevention** (S8/S9): Secrets can be swapped to disk or captured in core dumps.
- **Advisory locking** (I5): flock is best-effort; malicious processes can bypass.
- **Fill rate** (I1): Practical limit ~50-60% before slot exhaustion.
