# voidfs Security Audit — Phase 1

Audit date: 2026-03-30
Scope: Core crypto, deniability, collision integrity, side channels

## Summary

| # | Finding | Rating | Status |
|---|---------|--------|--------|
| C1 | Nonce reuse on file overwrite (deterministic encryption) | MEDIUM | By design — documented |
| C2 | HKDF salt=IKM is unconventional | LOW | Acceptable — documented |
| C3 | Deterministic salt enables precomputation for common image sizes | MEDIUM | By design — documented |
| C4 | Locator concatenation without length prefix | MEDIUM | **FIXED** |
| D1 | Two-snapshot diff reveals block count (approx file size) | MEDIUM | Known limitation |
| D2 | Process name/cmdline leaks voidfs usage | HIGH | Future: Phase 4 |
| D3 | Argon2id 256 MiB allocation is a behavioral signal | LOW | Inherent |
| D4 | tracing_subscriber initialized unconditionally | LOW | Future: Phase 4 |
| I1 | Partial write: block 0 written first causes unrecoverable corruption | HIGH | **FIXED** |
| I2 | No file locking for concurrent access | MEDIUM | Known limitation — Phase 4 |
| I3 | No fsync — flush() doesn't guarantee durability | LOW | Future |
| I4 | No path length or ".." validation | LOW | Future: Phase 2 |
| S1 | Passphrase not zeroized in main.rs | HIGH | **FIXED** |
| S2 | Timing leak: slot search short-circuits | HIGH | **FIXED** |
| S3 | Decrypted plaintext Vec not zeroized in cipher.rs | MEDIUM | **FIXED** |
| S4 | No mlock() — secrets can be swapped to disk | MEDIUM | Future: Phase 4 |

## Detailed Findings

### C1: Nonce Reuse on File Overwrite (MEDIUM — By Design)

When a file is overwritten at the same path, the same (key, nonce) pair encrypts different
plaintext. An attacker with two snapshots can XOR the ciphertexts to recover XOR of
plaintexts. This is inherent to deterministic encryption in deniable systems — storing a
random nonce or version counter would break deniability. Mitigated by: (1) the attacker
needs two snapshots, (2) XOR of plaintexts is not directly readable without additional
structure.

### C3: Deterministic Salt (MEDIUM — By Design)

Salt = SHA-256("voidfs-v1-{image_size}"). Two same-sized images with the same passphrase
produce the same master secret. An attacker can precompute Argon2id for common image sizes.
Mitigation: document minimum passphrase strength (12+ chars, high entropy). The Argon2id
m=256 MiB, t=4 makes brute-force infeasible for strong passphrases.

### C4: Locator Concatenation Without Length Prefix (MEDIUM — FIXED)

The HMAC input `path || block_num || slot` has no length prefix for the path, so a path
ending in bytes matching block_num encoding could theoretically collide. Fixed by prepending
path length as a 4-byte LE integer.

### I1: Partial Write — Block 0 First (HIGH — FIXED)

If `write_file` crashes after writing block 0 but before completing all blocks, the header
claims a size that can't be satisfied, making both old and new data unrecoverable. Fixed by
writing block 0 LAST (as a commit marker).

### S1: Passphrase Not Zeroized (HIGH — FIXED)

`rpassword::prompt_password()` returns a `String` that was never zeroized. Fixed by wrapping
in `Zeroizing<String>`.

### S2: Timing Leak in Slot Search (HIGH — FIXED)

`read_slot` returned on first successful decrypt, leaking which slot a file uses and whether
data exists (correct passphrase returns faster than wrong passphrase). This directly
undermines deniability. Fixed by always iterating all MAX_SLOTS candidates.

### S3: Decrypted Plaintext Not Zeroized (MEDIUM — FIXED)

The intermediate `Vec<u8>` from `chacha20poly1305::decrypt()` was dropped without zeroizing.
Fixed by zeroizing before drop.

### D1: Two-Snapshot Differential (MEDIUM — Known Limitation)

An attacker comparing two image snapshots can observe which blocks changed, revealing the
number of blocks written (and thus approximate file size). Future mitigation: dummy writes
to random blocks after real writes.

## Deniability Status

**At rest (static image analysis): PASS** — the image is statistically indistinguishable
from uniform random data. Verified by a 14-test statistical suite (chi-squared, KS,
monobit, runs, matrix rank, block entropy, autocorrelation, etc.).

**Under observation (runtime): PARTIAL** — behavioral fingerprints exist (Argon2id memory
allocation, I/O patterns, process name). These require active monitoring of the system
while voidfs is running.

## Threat Model Assumptions

1. Attacker has the voidfs source code (open source)
2. Attacker has the image file but NOT the passphrase
3. Attacker may have multiple snapshots of the image
4. Attacker may compel one passphrase (decoy filesystem)
5. Passphrase has >= 60 bits of entropy (12+ mixed chars)
