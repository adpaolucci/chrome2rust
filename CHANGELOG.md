# Changelog

All notable changes to `chrome2rust` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.1] - 2026-11-15

### Fixed
- **GUI Startup `RwLock` Deadlock (`chrome2rust-gui`)**: Hoisted `ctx.wants_keyboard_input()` outside `ctx.input(...)` in `AppState::handle_shortcuts` so `egui::Context` no longer self-deadlocks between an exclusive write lock and a nested read lock on Frame 0 before the Win32 window becomes visible.
- **Windows Console Window Suppression**: Enabled `#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]` in `chrome2rust-gui` so launching from Windows Explorer does not open an empty background console window.

### Changed
- **Default GUI Launch on `chrome2rust`**: Running `chrome2rust` without a subcommand now launches `chrome2rust-gui` instead of exiting with a CLI usage error.

## [0.2.0] - 2026-11-15

### Changed
- **Modular Multi-Crate Architecture**: Refactored into 7 specialized workspace crates (`chrome2rust-core`, `chrome2rust-cache`, `chrome2rust-forensics`, `chrome2rust-report`, `chrome2rust-mcp`, `chrome2rust-cli`, `chrome2rust-gui`) with unified workspace dependencies and LTO release profile.
- **Classic Win32/MMC Desktop Console (`chrome2rust-gui`)**: Split the monolithic GUI into modular `app`, `state`, and `views/` components with Classic Win2k/XP administrative styling (sunken white Console Tree, Win32 Details ListView, Classic Property Sheet inspector, flat utility toolbar, multi-segment sunken Status Bar, and etched GroupBox dialogs).

### Added
- **Model Context Protocol Server (`chrome2rust-mcp` & `chrome2rust mcp`)**: JSON-RPC 2.0 MCP server exposing Chrome profile discovery, cache scanning/inspection/extraction, `User Data` forensic analysis, and offline report generation tools to AI workflows.
- **Chain-of-Custody Audit Manifests (`chrome2rust-forensics::custody`)**: SHA-256 Merkle root and cryptographic artifact hash manifest generation in JSON/CSV formats (`--audit-manifest`).
- **Native OS File/Folder Pickers & Format Sniffer**: Added `chrome2rust pick`, global `--pick`/`--browse` flag, and `chrome2rust sniff` artifact classifier.
- **Deep Magic Signature & Extension Recovery (`chrome2rust-core::magic`)**: Expanded content identification across 60+ binary signatures (PE/ELF/Mach-O, WOFF/WOFF2/TTF/OTF, MP4/MOV/WEBM/AVIF/HEIC, MP3/FLAC/OGG/WAV, PDF/OLE2/OOXML/ZIP/7z/RAR/GZIP/ZSTD/XZ, WebP/PNG/JPEG/GIF/ICO/BMP, SQLite/WASMs), container inspection, text heuristics (`html`/`svg`/`xml`/`json`/`css`/`js`), `Content-Disposition` filename recovery, HTTP `Content-Type` vs. magic mismatch findings (`MIME Mismatch` column + `--use-detected-ext` extraction mode).
- **Structured `tracing` Logging & Signal Handling**: Added `--log-level` / `--log-file` structured stderr/file logging and clean `SIGINT` handling.
- **CI, Release Workflows & Governance Docs**: Added cross-platform GitHub Actions CI (`ubuntu-latest`, `windows-latest`, `macos-latest`), automated binary Release packaging, `rustfmt.toml`, `.cargo/config.toml`, `.gitattributes`, `CONTRIBUTING.md`, `SECURITY.md`, and `CODE_OF_CONDUCT.md`.

### Fixed & Hardened
- **Security Audit & Deep Fuzz Testing Hardening**: Hardened Simple Cache, Blockfile Cache, `HttpResponseInfo` pickle, `gzip`/`deflate`/`br`/`zstd` decompression bombs, LevelDB `.ldb`/`.log`, SNSS `Session`/`Tabs`, SQLite `History` deletion-gap arithmetic, filename/path sanitization (including Windows reserved device names), X.509/crypto helpers, and MCP JSON-RPC framing against malformed, truncated, or adversarial inputs.

## [0.1.0] - 2026-11-14

### Added
- Initial pure-Rust Chrome Simple Cache & Blockfile parser, `HttpResponseInfo` pickle decoder, transparent `gzip`/`deflate`/`br`/`zstd` decompression, extraction, safe deletion, and 8-format exporter.
- Complete Google Chrome `User Data` forensic analyzer (`Local State`, `History` + deletion gaps, `Cookies`, `Login Data`, `Web Data`, `Preferences`, `Bookmarks`, `Extensions`, SNSS `Sessions`/`Tabs`, pure-Rust `LevelDB` storage, `IndexedDB`, `Top Sites`, `Reporting and NEL`, unified timeline, and cross-artifact intelligence findings).
- Optional best-effort `v10`/`v11` decryption (`--decrypt`, `--key`, Linux `"peanuts"`, DB v24+ 32-byte domain hash stripping).
- Air-gapped offline HTML, JSON, Markdown, and bundled forensic report generators.
