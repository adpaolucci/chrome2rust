# `chrome2rust` — High-Fidelity Google Chrome Cache Inspector & User Data Forensic Suite in Pure Rust

Part of the **GUAP** Ecosystem (`guap.ca`) • [**Project Hub & Web Documentation: https://chrome2rust.guap.ca**](https://chrome2rust.guap.ca) • [**Project Wiki**](https://github.com/adpaolucci/chrome2rust/wiki)

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)
[![CI](https://github.com/adpaolucci/chrome2rust/actions/workflows/ci.yml/badge.svg)](https://github.com/adpaolucci/chrome2rust/actions/workflows/ci.yml)
[![Rust: 2024](https://img.shields.io/badge/Rust-2024%20(1.88%2B)-orange.svg)](Cargo.toml)
[![Forensics: Read-Only](https://img.shields.io/badge/Forensics-Read--Only%20Snapshots-success.svg)](crates/chrome2rust-forensics)
[![Architecture: 8 Crates](https://img.shields.io/badge/Workspace-8%20Crates-emerald.svg)](Cargo.toml)
[![GUI: WinSafe Win32 + Iced 0.14](https://img.shields.io/badge/GUI-WinSafe%20Win32%20%2B%20Iced%200.14-cyan.svg)](crates/chrome2rust-win32)
[![MCP: stdio JSON-RPC](https://img.shields.io/badge/MCP-stdio%20JSON--RPC%202.0%20(29%20Tools)-purple.svg)](crates/chrome2rust-mcp)

Ready-to-submit **WinGet** & **Homebrew** manifests live in [`packaging/`](packaging/README.md).

**`chrome2rust`** is an ultra-fast, memory-safe, read-only cross-platform Chromium-family cache inspection and `User Data` forensic workstation written in **100% pure Rust**. Developed by **Andrew Paolucci**, it ships **two specialized pure-Rust desktop GUIs** alongside the CLI and MCP server:
1. **`chrome2rust-win32`** (**WinSafe `0.0.29`**) — Zero-GPU authentic native Win32 Common Controls GUI (ComCtl v6, Per-Monitor DPI v2, Vista+ COM dialogs), engineered for Windows Desktops, forensic triage over **Windows Server RDP**, and Hyper-V/VMware VMs.
2. **`chrome2rust-iced`** (**Iced `0.14`**) — Consistent cross-platform retained-mode GUI (`wgpu` + `tiny-skia` CPU fallback) shipping on **Linux**, **macOS**, and **Windows** (`chrome2rust gui --iced`).

---

## Architectural Comparison: `chrome2rust` vs. Legacy Forensic Tools

| Capability / Metric | `chrome2rust` (Pure Rust 1.88+) | `ChromeCacheView` (NirSoft) | `Hindsight` (Python / Obsidian) |
| :--- | :--- | :--- | :--- |
| **Cache Backends** | **Simple Cache (`*_0`/`*_1`) + Blockfile (`data_0..3`, `f_xxxxxx`)** | Partial Blockfile / legacy Simple | Simple Cache & Blockfile |
| **Transparent Decompression** | **Pure-Rust `gzip`, `deflate`, `br` (Brotli), `zstd` (Zstandard)** | External/OS decompression | Python `brotli`/`zstandard` dependencies |
| **Pickled HTTP Headers** | **Full `HttpResponseInfo`, TLS version, ALPN, X.509 cert chains** | Basic HTTP headers only | Raw headers; limited cert chain extraction |
| **Payload Magic Carving** | **60+ binary signatures with `Content-Type` mismatch detection** | Extension guessing from URL query | Basic MIME classification |
| **Locked Profile Snapshots** | **Non-destructive atomic WAL/SHM copying (zero mutation)** | Fails on locked files or locks DB | Copy without active WAL merge |
| **AI Agent Integration** | **Native `stdio` Model Context Protocol (MCP) server (29 tools)** | None | None |
| **Desktop GUI Console** | **Dual Pure-Rust GUIs: Native Win32 (`winsafe`) + Cross-Platform Iced `0.14` (`tiny-skia` fallback)** | Classic Win32 MFC (Windows-only) | Local web server in default browser |
| **Throughput & Footprint** | **> 50,000 entries/sec • < 25 MB static RAM** | Fast, but Windows-only | 100–500 MB RAM (Python GC overhead) |
| **Chain of Custody** | **RFC 6234 Balanced Binary Merkle Tree Root Hash** | Basic file hash list | Custom SQLite export log |

---
## Key Capabilities

| Capability | Details |
| :--- | :--- |
| **Dual-Backend HTTP Cache Engine** | Pure-Rust parsers for modern **Simple Cache** (`*_0` / `*_1` with CRC-32 & Key SHA-256 verification) and **Blockfile Cache** (`index`, `data_0`..`data_N`, `f_xxxxxx`, `RankingsNode` timestamps), tested against Chromium through v156+ |
| **`HttpResponseInfo` Pickle Decoder** | Extracts raw HTTP headers, `request_time`/`response_time`, network isolation partition keys (`URL`, `Web Site`, `Frame`), server socket IP:port, TLS version, ALPN protocol, DNS aliases, and X.509 certificate chains |
| **Transparent Payload Decompression** | Automatically decompresses `gzip`, `deflate`, `br` (Brotli), and `zstd` cached streams on preview, SHA-256 hashing, and disk extraction (preserving archive payloads when unencoded) |
| **Magic & Extension Recovery** | Pure-Rust deep payload identification across 60+ binary signatures, ISO-BMFF/RIFF/ZIP/OLE2 container inspection, text/JS/JSON/CSS/SVG/HTML heuristics, `Content-Disposition`, and URL query hints; flags HTTP `Content-Type` vs. magic mismatches |
| **Safe Read-Only Evidence Handling** | Snapshots locked SQLite stores together with `-wal`, `-shm`, and `-journal` sidecars before reading so live browser profiles are never mutated |
| **User Data Deep Forensics** | Analyzes `Local State`, `History` + `sqlite_sequence` deletion gaps, `Cookies`, `Login Data` + `insecure_credentials`, `Web Data`, `Preferences`, `Extensions` risk scoring, `Bookmarks`, SNSS `Sessions`/`Tabs`, pure-Rust `LevelDB` storage, and `IndexedDB` |
| **Optional Best-Effort Decryption** | Supports `v10`/`v11` decryption using user-supplied passphrases (`PBKDF2-HMAC-SHA1`), hex AES-128/256 keys, Linux `"peanuts"` fallback, and Chromium DB v24+ 32-byte domain hash stripping |
| **Chain-of-Custody Merkle Audits** | Computes deterministic per-artifact SHA-256 digests and balanced binary RFC 6234 Merkle roots exported as CSV or JSON (`--audit-manifest` / `chrome2rust custody`) |
| **Air-Gapped Forensic Reports** | Self-contained HTML (zero external CDN requests, interactive dark/light theme, SVG charts, sortable tables), JSON, and Markdown bundles |
| **Model Context Protocol (MCP)** | Built-in JSON-RPC 2.0 `stdio` MCP server (`chrome2rust mcp` & `chrome2rust-mcp`) exposing structured profile discovery, cache inspection, forensic analysis, reporting, and custody tools to AI agents |
| **Native Pure-Rust Dual GUIs** | Native WinSafe Win32 (`chrome2rust-win32`) on Windows + cross-platform Iced 0.14 (`chrome2rust-iced`) on Linux, macOS, and Windows (`--iced`) — zero WebView, Electron, or Node.js dependencies |

---

## Pre-Compiled Binaries & Direct Download

Self-contained native executables with **zero external runtime dependencies** are built for every release across Windows, Linux, and macOS:

| Platform | Target Architecture | Distribution Package | Included Binaries |
| :--- | :--- | :--- | :--- |
| **Windows (64-bit)** | `x86_64-pc-windows-msvc` | [**`chrome2rust-x86_64-pc-windows-msvc.zip`**](https://github.com/adpaolucci/chrome2rust/releases/latest/download/chrome2rust-x86_64-pc-windows-msvc.zip) | `chrome2rust.exe`, `chrome2rust-win32.exe`, `chrome2rust-iced.exe`, `chrome2rust-mcp.exe` |
| **Linux (64-bit)** | `x86_64-unknown-linux-gnu` | [**`chrome2rust-x86_64-unknown-linux-gnu.tar.gz`**](https://github.com/adpaolucci/chrome2rust/releases/latest/download/chrome2rust-x86_64-unknown-linux-gnu.tar.gz) | `chrome2rust`, `chrome2rust-iced`, `chrome2rust-mcp` |
| **macOS Apple Silicon** | `aarch64-apple-darwin` (M1–M4) | [**`chrome2rust-aarch64-apple-darwin.tar.gz`**](https://github.com/adpaolucci/chrome2rust/releases/latest/download/chrome2rust-aarch64-apple-darwin.tar.gz) | `chrome2rust`, `chrome2rust-iced`, `chrome2rust-mcp` |
| **macOS Intel** | `x86_64-apple-darwin` | [**`chrome2rust-x86_64-apple-darwin.tar.gz`**](https://github.com/adpaolucci/chrome2rust/releases/latest/download/chrome2rust-x86_64-apple-darwin.tar.gz) | `chrome2rust`, `chrome2rust-iced`, `chrome2rust-mcp` |

> Every release archive includes cryptographic `SHA256SUMS.txt` checksums alongside `chrome2rust` (CLI), `chrome2rust-win32` (Windows Native Win32 Console), `chrome2rust-iced` (Cross-Platform Iced Console), and `chrome2rust-mcp` (MCP server).

---

## Workspace Architecture

```text
chrome2rust/
├── Cargo.toml                         # Workspace root manifest (8 modular crates, MSRV 1.88, Apache-2.0)
├── deny.toml                          # cargo-deny v2 supply-chain & license audit policy
├── mcp.json                           # Standard MCP server client configuration
├── packaging/                         # WinGet & Homebrew package manager manifests
├── crates/
│   ├── chrome2rust-core/              # Foundation: discovery, format sniffer, crypto, WAL-safe SQLite snapshots, time, tracing logging
│   ├── chrome2rust-cache/             # Simple Cache (*_0/*_1) & Blockfile (data_0..3, f_*) parsers, HttpResponseInfo pickles, codecs, 8-format exporter
│   ├── chrome2rust-forensics/         # History, Cookies, Logins, Web Data, Extensions, SNSS Sessions, pure-Rust LevelDB, timeline, findings, Merkle custody
│   ├── chrome2rust-report/            # Self-contained offline HTML, JSON, and Markdown forensic report generators + end-to-end integration tests
│   ├── chrome2rust-mcp/               # Model Context Protocol (MCP) JSON-RPC 2.0 stdio server & standalone `chrome2rust-mcp` binary
│   ├── chrome2rust-cli/               # Unified CLI engine (`chrome2rust`): profiles, sniff, cache, analyze, report, custody, pick, gui, mcp
│   ├── chrome2rust-win32/             # Native zero-GPU Win32 desktop console on WinSafe 0.0.29 (`chrome2rust-win32`)
│   └── chrome2rust-iced/              # Cross-platform Iced 0.14 desktop console (`chrome2rust-iced`: Linux, macOS, Windows)
└── .github/workflows/                 # Cross-platform CI (`fmt`, `clippy`, `test`, `cargo-deny`, `release`) and GitHub Release packaging
```

---

## Supported Artifacts & Formats

### Browser & Profile Auto-Discovery
Automatically locates installed profiles across **Google Chrome**, **Chromium**, **Microsoft Edge**, **Brave**, **Opera**, and **Vivaldi** on Windows (`%LOCALAPPDATA%`), macOS (`~/Library/Application Support`), and Linux (`~/.config` & `~/.cache`).

### HTTP Cache Inspection & Extraction
- **Simple Cache**: `*_0` entry streams (Stream 0 EOF HTTP metadata + key SHA-256 + CRC-32; Stream 1 raw or `*_1` separate payload files).
- **Blockfile Cache**: `index` hash tables, `data_0`..`data_3` external ranking/block stores, standalone `f_xxxxxx` payload files, and deleted-entry recovery.
- **8 Structured Export Formats**: `table`, `csv`, `tsv`, `text`, `html` (horizontal table), `vhtml` (vertical record cards), `xml`, and `json`.
- **Payload Extraction**: Preserves `Last Accessed` / `Server Time` modification timestamps, supports URL / CacheName / CacheName+Ext naming, mirrors website `host/path` directories (`--website-dirs`), and handles collision-safe renaming.

### Chrome `User Data` Forensic Suite
- **`Local State` & `Last Version`**: Installed version, OS Crypt key metadata (`os_crypt.encrypted_key`, portal telemetry), active profiles, and enterprise policies.
- **`History` & `Downloads`**: URLs, typed/visit counts, decoded `PageTransition` chains, download state/danger classification & full URL redirect chains, omnibox `keyword_search_terms`, and `sqlite_sequence` deletion-gap estimation.
- **`Cookies` & `Login Data`**: Encryption scheme breakdown (`plaintext`, `v10`, `v11`, `v20` App-Bound, `dpapi`), optional best-effort decryption, and `insecure_credentials` flagging.
- **`Web Data`, `Preferences`, `Bookmarks`, `Extensions`**: Autofill history, addresses, card metadata, hierarchical bookmarks, permission extraction, and sideloaded/over-privileged extension risk flags.
- **`Sessions` & Site Storage**: SNSS (`Session_*` / `Tabs_*`) open & closed tab navigation stacks, pure-Rust `LevelDB` `.ldb` (Snappy/Zstd) + `.log` WAL replay for `Local Storage` and `Session Storage`, `IndexedDB` origin inventory, `Top Sites`, and `Reporting and NEL`.
- **Multi-Browser & Media Extensions (`guap-kit` Powered)**: Cross-browser support for **Firefox** (`cache2`, `places.sqlite`, cookie metadata, `mozlz4` bookmark backups/sessions, `formhistory.sqlite`, `addons`), **Opera** (Blink & Presto `dcache4.url`), **Safari** (`Cache.db`, `History.db`, `Bookmarks.plist` binary/XML), **Unified Multi-Browser Aggregators** (`BrowsingHistoryView`, `BrowserDownloadsView`, `BrowserAddonsView`, `WebBrowserBookmarksView`, `unified autofill`, `MyLastSearch`), and **Media Carving** (`ImageCacheViewer` EXIF/GPS & `VideoCacheView` MP4/M4S/WebM/HLS/DASH), all integrated with `guap-table` and `guap-export` CSV/Merkle custody.

---

## Quick Start & Compilation

### Prerequisites
- [Rust toolchain](https://rustup.rs/) (1.88 or newer / edition 2024).
- On Linux desktop builds of `chrome2rust-iced`: standard fontconfig/X11/Wayland/OpenGL development packages (`libssl-dev`, `libfontconfig1-dev`, `libgtk-3-dev`, `libx11-dev`, `libgl1-mesa-dev`, `libwayland-dev`, `libxkbcommon-dev`).

### Build Release Binaries
```bash
# Clone the repository
git clone https://github.com/adpaolucci/chrome2rust.git
cd chrome2rust

# Run all workspace unit and integration tests
cargo test --workspace

# Build optimized release binaries (`chrome2rust`, `chrome2rust-win32`, `chrome2rust-iced`, `chrome2rust-mcp`)
cargo build --workspace --release
```

### Build Headless / CLI-Only (Zero GUI Libraries Required)
```bash
cargo build --release -p chrome2rust-cli -p chrome2rust-mcp
```

### Launch Dual Desktop Consoles (`chrome2rust-win32` & `chrome2rust-iced`)
```bash
# Default launch: `chrome2rust-win32` on Windows, `chrome2rust-iced` on Linux/macOS
chrome2rust
chrome2rust gui

# Launch the cross-platform Iced 0.14 GUI explicitly on Windows (supports `ICED_BACKEND=tiny-skia`)
chrome2rust gui --iced

# Or invoke a desktop binary directly with a target directory:
chrome2rust-win32 "C:\Users\Alice\AppData\Local\Google\Chrome\User Data"
chrome2rust-iced "/path/to/Chrome/User Data"
```

---

## CLI Usage Guide

### 1. Discover Local Browser Profiles & Sniff Artifacts
```bash
# List discovered Chromium profiles and cache folders
chrome2rust profiles
chrome2rust profiles --json

# Identify file magic headers or Chrome directory layout
chrome2rust sniff "/path/to/Cache_Data/45b032600bc6b3f3_0"
chrome2rust sniff "/path/to/User Data" --json
```

### 2. Inspect, Filter, Extract & Export HTTP Cache Entries
```bash
# List cache entries (auto-discovers local browser cache if PATH is omitted, or pass --pick)
chrome2rust cache list "/path/to/Cache_Data" --format table --sort last-accessed --desc
chrome2rust cache list "/path/to/Profile" --content-type "image/" --last 7d -f csv -o images.csv
chrome2rust cache list "/path/to/Cache_Data" --filter "api" --hashes --columns url,content-type,size,sha256

# Extract decompressed cached payloads reconstructing host/path directory structure (recovering missing extensions)
chrome2rust cache extract "/path/to/Cache_Data" -o ./extracted --website-dirs --filename-mode url

# Extract while also replacing mismatched/spoofed filename extensions with magic-detected extensions
chrome2rust cache extract "/path/to/Cache_Data" -o ./extracted --website-dirs --use-detected-ext

# Deep-inspect headers, TLS/ALPN metadata, X.509 cert chains, and payload preview
chrome2rust cache inspect "/path/to/Cache_Data/45b032600bc6b3f3_0" --preview
chrome2rust cache inspect "/path/to/Cache_Data" --url "example.com" --dump-body ./body.bin

# Safe standalone cache file deletion (dry-run by default; pass --yes to commit)
chrome2rust cache delete "/path/to/Cache_Data" --url "ads"
chrome2rust cache delete "/path/to/Cache_Data" --url "ads" --yes
```

### 3. Full User Data Forensic Analysis & Offline Reports
```bash
# Terminal summary + forensic findings + top domains
chrome2rust analyze "/path/to/User Data"

# Structured JSON output with optional best-effort decryption and chain-of-custody CSV
chrome2rust analyze "/path/to/User Data" --decrypt --key "passphrase_or_hex" --json \
  --audit-manifest ./custody_manifest.csv > analysis.json

# Generate standalone HTML, JSON, Markdown, or full report bundle
chrome2rust report "/path/to/User Data" -f html -o ./case_report.html
chrome2rust report "/path/to/User Data" -f all -o ./forensic_bundle --decrypt
```

### 4. Chain-of-Custody SHA-256 & Merkle Verification (`custody`)
```bash
# Compute per-file SHA-256 digests and RFC 6234 Merkle root across a Chrome profile
chrome2rust custody "/path/to/User Data" -o ./custody.csv
chrome2rust custody "/path/to/User Data" -o ./custody.json --json
```

### 5. Native OS Picker & Global Diagnostics
```bash
# Launch native host OS folder/file picker interactively when target paths are omitted
chrome2rust --pick analyze --json

# Verbose tracing diagnostics (automatically written to stderr or --log-file)
chrome2rust --log-level debug --log-file ./chrome2rust.log analyze "/path/to/User Data"
```

### 6. Multi-Browser (`fx`, `opera`, `safari`, `unified`, `search-queries`) & Media Carving (`carve`)
```bash
# Firefox, Opera & Safari read-only inspection (pure-Rust mozlz4, bplist, cache2 & SQLite)
chrome2rust fx history "/path/to/places.sqlite" -f json
chrome2rust fx sessions "/path/to/sessionstore.jsonlz4" -f json
chrome2rust opera cache "/path/to/dcache4.url" -f json
chrome2rust safari bookmarks "/path/to/Bookmarks.plist" -f json

# Cross-browser unified views, search query extraction & media/EXIF/video carving
chrome2rust unified history "/path/to/places.sqlite" -f csv -o ./unified.csv --custody-manifest ./custody.json
chrome2rust search-queries "/path/to/places.sqlite" -f json
chrome2rust carve images "/path/to/sample_exif.jpg" -f json
chrome2rust carve video "/path/to/sample_fmp4.mp4" -f json
```

---

## Model Context Protocol (MCP) for AI Agents

`chrome2rust` includes a built-in [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) JSON-RPC 2.0 server (`chrome2rust mcp` or the standalone `chrome2rust-mcp` binary) exposing **29 read-only forensic tools** (`8` core Chromium tools + `21` multi-browser, search-query, and media-carving `TableProvider`s). All diagnostic logs stream to `stderr` so `stdout` carries clean JSON-RPC envelopes.

Core Chromium tools:
- **`chrome2rust_profiles`**, **`chrome2rust_sniff`**, **`chrome2rust_cache_list`**, **`chrome2rust_cache_inspect`**, **`chrome2rust_cache_extract`**, **`chrome2rust_analyze`**, **`chrome2rust_report`**, **`chrome2rust_custody`**

Multi-browser & media carving tools (all `readOnlyHint: true`, `destructiveHint: false`):
- **Firefox**: `chrome2rust_fx_cache`, `chrome2rust_fx_history`, `chrome2rust_fx_cookies`, `chrome2rust_fx_bookmarks`, `chrome2rust_fx_downloads`, `chrome2rust_fx_formhistory`, `chrome2rust_fx_addons`, `chrome2rust_fx_sessions`
- **Opera & Safari**: `chrome2rust_opera_cache`, `chrome2rust_opera_history`, `chrome2rust_safari_cache`, `chrome2rust_safari_history`, `chrome2rust_safari_bookmarks`
- **Unified & Media**: `chrome2rust_unified_history`, `chrome2rust_unified_downloads`, `chrome2rust_unified_addons`, `chrome2rust_unified_bookmarks`, `chrome2rust_unified_autofill`, `chrome2rust_search_queries`, `chrome2rust_carve_images`, `chrome2rust_carve_video`

Inspect schemas or start the stdio server:
```bash
chrome2rust mcp --tools
chrome2rust mcp
```

Client configuration ([`mcp.json`](mcp.json)):
```json
{
  "mcpServers": {
    "chrome2rust": {
      "command": "chrome2rust",
      "args": ["mcp"],
      "env": {
        "RUST_LOG": "warn"
      }
    }
  }
}
```

---

## Governance & Contributing

- [CONTRIBUTING.md](CONTRIBUTING.md)
- [SECURITY.md](SECURITY.md)
- [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)
- [CHANGELOG.md](CHANGELOG.md)
- [**Project Wiki**](https://github.com/adpaolucci/chrome2rust/wiki) ([Multi-Browser & Media Carving](https://github.com/adpaolucci/chrome2rust/wiki/Multi-Browser-and-Media-Carving), [CLI Reference](https://github.com/adpaolucci/chrome2rust/wiki/CLI-Reference), [MCP Server Guide](https://github.com/adpaolucci/chrome2rust/wiki/MCP-Server-Guide))

---

## Security Hardening & Supply Chain

- **`#![forbid(unsafe_code)]` Core & Tooling**: Compiled with `#![forbid(unsafe_code)]` across `core`, `cache`, `forensics`, `report`, `mcp`, `cli`, and `iced` (`unsafe` isolated strictly to native Win32 windowing calls in `chrome2rust-win32`).
- **Air-Gapped HTML Report & Export CSP**: Generated forensic reports and cache HTML exports enforce `Content-Security-Policy: default-src 'none'; ...` with zero network dependencies.
- **MSVC Binary Mitigations & SBOM**: Windows `x86_64` MSVC release builds combine `/STACK:16777216`, Control Flow Guard (`-C control-flow-guard=on`), and CET Shadow Stack (`/CETCOMPAT`), and all release archives ship `SBOM-crates.txt` (`cargo tree --workspace --locked`).

## License

Licensed under the [Apache License, Version 2.0](LICENSE) (see also [NOTICE](NOTICE)).


---

## Contributors & Acknowledgments

- **Andrew Paolucci (@adpaolucci)** &mdash; Project Creator, Systems Architect & Lead Software Developer.
- **Antigravity (Google DeepMind)** &mdash; Agentic AI Technical Collaborator (MCP server, multi-codec decompression pipeline, Simple Cache stream verification).
- **Chromium Open Source Project** &mdash; Specifications for Simple Cache, Blockfile, and Chromium User Data profiles.
- **Rust Ecosystem & Community** &mdash; Maintainers of `winsafe`, `iced`, `rusqlite`, `brotli`, `ruzstd`, `snap`, and `clap`.
