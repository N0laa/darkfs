# voidfs Security Audit

Full 8-step audit completed 2026-03-31.
Scope: crypto primitives, deniability, collision integrity, side channels, adversarial attacks, build hardening, final penetration test.

## Findings Summary

### Cryptographic (Step 1)

| # | Finding | Rating | Status |
|---|---------|--------|--------|
| C1 | Nonce reuse on file overwrite — same (key,nonce) encrypts different plaintext | CRITICAL | By design — documented below |
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
| D4 | Process name "voidfs" visible in ps/mount | HIGH | **FIXED** — FSName now configurable |
| D5 | VOIDFS_PASSPHRASE env var visible in /proc | HIGH | Cleared after read; documented |
| D6 | Argon2id 256 MiB allocation is a behavioral signal | LOW | Inherent |
| D7 | Wrong passphrase: all 5 slots always iterated — timing leak eliminated | OK | **FIXED** |

### Collision & Integrity (Step 3)

| # | Finding | Rating | Status |
|---|---------|--------|--------|
| I1 | System unreliable above ~40% fill; no warning | HIGH | Documented |
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
| S6 | Slot iteration constant-count (all 5 always) | OK | **FIXED** (Phase 1 audit) |
| S7 | Poly1305 tag comparison is constant-time (subtle crate) | OK | Verified |
| S8 | No mlock() — secrets can be swapped to disk | MEDIUM | Future fix |
| S9 | No core dump prevention | MEDIUM | Future fix |

### Adversarial Attacks (Step 6)

| Attack | Result | Notes |
|--------|--------|-------|
| Header scan | **FAILS** | No unencrypted structures on disk |
| Entropy analysis (NIST STS) | **FAILS** | Ciphertext is IND-CPA; passes all tests |
| Block pattern analysis | **FAILS** | Cannot distinguish encrypted from random blocks |
| Snapshot diff | **PARTIAL** | Reveals activity volume but not content or filesystem attribution |
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
| B5 | Binary contains "voidfs" strings | Documented |
| B6 | tracing_subscriber unconditionally initialized | **FIXED** — gated |

### Final Penetration Test (Step 8)

Two 64MB images tested blind (one voidfs with 3 files, one pure /dev/urandom):

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

**Confidence: 0%. Cannot determine which image is voidfs. Deniability PASS.**

---

## Critical Finding: Nonce Reuse on Overwrite (C1)

**Rating: CRITICAL (if multi-snapshot attacker is in scope)**

When a file is overwritten at the same path, the same (key, nonce) encrypts different plaintext. XChaCha20 is a stream cipher, so:
- `C1 XOR C2 = P1 XOR P2` — attacker recovers XOR of plaintexts
- Known-plaintext (e.g., FileHeader magic in block 0) recovers the keystream
- Poly1305 key reuse breaks authentication — forgeries possible

**Threat model scope**: This is only exploitable if the attacker has two snapshots of the same disk block (before and after overwrite). Sources: backups, VM snapshots, SSD wear-leveling, copy-on-write filesystems.

**Mitigations** (tradeoffs with deniability):
1. **SIV mode**: Use a nonce-misuse-resistant AEAD (e.g., AES-GCM-SIV). Nonce reuse only leaks whether plaintexts are identical, not their XOR. However, no XChaCha20-SIV exists in RustCrypto.
2. **Random nonce component**: Store a random value in the block — but this is detectable metadata.
3. **Document as known limitation**: If the threat model assumes single-snapshot, this is unexploitable.

**Current status**: Documented as a known design tradeoff. The threat model assumes single-snapshot analysis.

## Deniability Verdict

**At rest: PASS** — A static voidfs image is cryptographically and statistically indistinguishable from random data. Confirmed by 14-test statistical suite and blind penetration test.

**Under observation: PARTIAL** — Behavioral fingerprints exist (I/O patterns, memory allocation, process/mount names). All require active monitoring of the running system.

**Multi-snapshot: WEAK** — Nonce reuse on overwrite breaks confidentiality for changed blocks. Snapshot diffs reveal activity volume.

## Threat Model

1. Attacker has the source code and the image file
2. Attacker does NOT have the passphrase
3. Passphrase has >= 80 bits of entropy (recommended 12+ mixed chars)
4. Attacker may compel one passphrase (decoy filesystem)
5. Single-snapshot assumption: attacker sees the image at one point in time
6. No active surveillance of the running system
