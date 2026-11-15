# Contributing to `chrome2rust`

Thank you for your interest in contributing to `chrome2rust`!

## Code Architecture

The workspace is organized into modular crates:
- `crates/chrome2rust-core`: Core models, timestamps, profile/path discovery, SQLite safe snapshot reader, optional decryption primitives, and `tracing` logging setup.
- `crates/chrome2rust-cache`: Dual-backend Chrome HTTP cache readers (`Simple Cache` & `Blockfile`), `HttpResponseInfo` pickle decoder, decompression, extraction, deletion, and multi-format table exporter.
- `crates/chrome2rust-forensics`: Read-only Chrome `User Data` artifact analyzers (`History`, `Cookies`, `Login Data`, `Web Data`, `Bookmarks`, `Preferences`, `Extensions`, `Sessions` SNSS, `LevelDB` storage), cross-artifact findings, timeline, and SHA-256 chain-of-custody manifests.
- `crates/chrome2rust-report`: Air-gapped interactive HTML, JSON, and Markdown forensic report generators.
- `crates/chrome2rust-mcp`: Model Context Protocol (MCP) stdio server for AI agents and forensic workflows.
- `crates/chrome2rust-cli`: Unified command-line interface binary (`chrome2rust`).
- `crates/chrome2rust-gui`: Native cross-platform Classic Win32/MMC management console GUI (`chrome2rust-gui`).

## Development Workflow

1. Fork and clone the repository.
2. Ensure you have a recent stable Rust toolchain installed (`rustup update stable`).
3. Create a feature branch (`git checkout -b feature/my-enhancement`).
4. Run checks, linter, and tests:
   ```bash
   cargo check --workspace --all-targets
   cargo fmt -- --check
   cargo clippy --workspace --all-targets -- -D warnings
   cargo test --workspace
   ```
5. Commit with clear, descriptive commit messages and open a Pull Request on GitHub.

## Guidelines
- **Forensic Integrity**: Read-only temporary snapshots must be used for SQLite/LevelDB inspection so live profiles are never mutated outside explicit `cache delete` commands.
- **Zero External Runtime Dependencies**: All cache, SNSS, LevelDB, and report parsers remain 100% pure Rust without requiring external browser or Python runtimes.
- **Testing**: Include unit tests and integration tests for every new artifact parser or report feature.
- **Logging**: Use `tracing` macros (`trace!`, `debug!`, `info!`, `warn!`, `error!`) writing diagnostics to `stderr` so CLI `stdout` stays clean and scriptable.
