# Contributing to darkfs

## Getting Started

```bash
git clone https://github.com/N0laa/darkfs.git
cd darkfs
cargo build
cargo test
```

For FUSE support (mount/unmount):
- macOS: install [macFUSE](https://macfuse.github.io/), then `cargo build --features fuse`
- Linux: `apt install libfuse3-dev pkg-config`, then `cargo build --features fuse`

## Development

```bash
# Run all tests
cargo test

# Run with fast KDF (for development)
DARKFS_DEV=1 cargo run -- put vault.img test.txt

# Run benchmarks
cargo bench

# Run the statistical verification tool
cargo run --bin stats-verify -- image_a.img image_b.img
```

### Project Structure

```
src/
  crypto/     Key derivation, encryption, block location mapping
  store/      Block I/O, collision resolution, superblock sharding
  fs/         File operations, directories, path handling
  fuse/       FUSE filesystem handler (feature-gated)
  util/       Constants, error types
tests/
  integration/  End-to-end tests
  common/       Shared test utilities
tools/          CLI utilities (mkdark, stats-verify)
benches/        Criterion benchmarks
```

### Code Style

- `#![deny(unsafe_code)]` is enforced. No exceptions.
- All secret material must use `Zeroize`/`ZeroizeOnDrop`.
- Error messages must not leak internal state (block offsets, file paths, image size).
- All slot iterations must be constant-count (timing resistance).
- New crypto constructions require tests AND a pentest entry.

## Testing

Every PR should pass:

```bash
cargo test                    # Unit + integration tests
cargo test --test pentest  # Security pentest suite
cargo clippy                  # Lints
```

### Writing Security Tests

Security-sensitive changes should include adversarial tests in `tests/pentest.rs`. Each test should document:
1. Severity (CRITICAL / HIGH / MEDIUM / LOW / INFO)
2. Attack scenario
3. What the test proves

## Security Issues

**Do not open a public issue for security vulnerabilities.** Instead, see [SECURITY.md](SECURITY.md) for responsible disclosure instructions.

## License

By contributing, you agree that your contributions will be licensed under MPL-2.0.
