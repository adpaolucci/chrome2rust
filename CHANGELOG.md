# Changelog

All notable changes to `chrome2rust` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.2] - 2026-11-19

### Changed
- **Dual-GUI Architecture (`chrome2rust-win32` + `chrome2rust-iced`)**: Replaced immediate-mode `eframe`/`egui` (`chrome2rust-gui`) with two specialized pure-Rust frontends: **`chrome2rust-win32`** (`winsafe 0.0.29`, zero-GPU native Win32 Common Controls v6, Per-Monitor DPI v2 manifest, embedded `app.ico`, COM dialogs) as the Windows default, and **`chrome2rust-iced`** (`iced 0.14` with `wgpu` + `tiny-skia` software rendering fallback and RGBA window icon) for Linux, macOS, and Windows (`chrome2rust gui --iced`).
- **Apache-2.0 Licensing & Attribution**: Standardized repository license to `Apache-2.0` (`LICENSE`, `NOTICE`, `Cargo.toml`, `smithery.yaml`, `README.md`) matching `robocopy2rust`.
- **MSRV `1.88`, Supply-Chain Audit & Packaging**: Pinned workspace `rust-version = "1.88"`, added `deny.toml` + `cargo-deny` CI job, Dependabot (`dependabot.yml`), GitHub issue/PR templates, updated GitHub Actions (`checkout@v7`, `upload-artifact@v7`, `download-artifact@v8`, `action-gh-release@v3`), and added ready-to-submit WinGet & Homebrew manifests in `packaging/`.

### Fixed
- **Target Folder Selection & Worker Superseding (`chrome2rust-win32`, `chrome2rust-iced`)**: Removed automatic Frame-0 loading of the default local Chrome `User Data` directory when launching without a `PATH` argument, and implemented monotonically versioned `load_generation` tracking so selecting a target folder always supersedes any in-flight scan.
- **Custom / Partial Target Folder Resolution (`chrome2rust-core`)**: Expanded `looks_like_profile_dir` and `resolve_target_path` to recognize modern `Network/Cookies`, `Login Data`, `Sessions`, `Local Storage/leveldb`, `Session Storage`, `IndexedDB`, and nested container folders (up to depth 3), and increased the `is_cache_data_dir` directory entry scan window.

### Added
- **Dual-GUI CLI Launcher & `--pick` Support (`chrome2rust-cli`)**: Running `chrome2rust` without arguments or `chrome2rust gui` launches `chrome2rust-win32` on Windows and `chrome2rust-iced` on Unix or via `--iced`, forwarding `[PATH]`, `--pick`/`--browse`, `--decrypt`, and `--key`.

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
