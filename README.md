# `chrome2rust` — High-Fidelity Google Chrome Cache Inspector & User Data Forensic Suite in Pure Rust

Part of the **GUAP** Ecosystem (`guap.ca`) • [**Project Hub & Web Documentation: https://chrome2rust.guap.ca**](https://chrome2rust.guap.ca)

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Rust: 1.88+](https://img.shields.io/badge/Rust-1.88%2B-orange.svg)](Cargo.toml)
[![Forensics: Read-Only](https://img.shields.io/badge/Forensics-Read--Only%20Snapshots-success.svg)](crates/chrome2rust-forensics)
[![Architecture: 7 Crates](https://img.shields.io/badge/Workspace-7%20Crates-emerald.svg)](Cargo.toml)
[![MCP: stdio JSON-RPC](https://img.shields.io/badge/MCP-stdio%20JSON--RPC%202.0-purple.svg)](crates/chrome2rust-mcp)
[![GUI: Win32 MMC](https://img.shields.io/badge/GUI-Win32%20MMC%20(egui)-cyan.svg)](crates/chrome2rust-gui)

**`chrome2rust`** is an ultra-fast, memory-safe, read-only cross-platform Chromium-family cache inspection and `User Data` forensic workstation written in **100% pure Rust**. Developed by **Andrew Paolucci**, it parses both **Simple Cache** and legacy **Blockfile Cache** backends alongside every major Chromium profile database (**History**, **Downloads**, **Cookies**, **Login Data**, **Web Data**, **Preferences**, **Extensions**, **Bookmarks**, **SNSS Sessions/Tabs**, **LevelDB Local/Session Storage**, and **IndexedDB**), producing unified chronological timelines, cross-artifact intelligence findings, SHA-256 chain-of-custody Merkle manifests, and air-gapped HTML/JSON/Markdown forensic report bundles.

---

## Architectural Comparison: `chrome2rust` vs. Legacy Forensic Tools

| Capability / Metric | `chrome2rust` (Pure Rust 1.88+) | `ChromeCacheView` (NirSoft) | `Hindsight` (Python / Obsidian) |
| :--- | :--- | :--- | :--- |
| **Cache Backends** | **Simple Cache (`*_0`/`*_1`) + Blockfile (`data_0..3`, `f_xxxxxx`)** | Partial Blockfile / legacy Simple | Simple Cache & Blockfile |
| **Transparent Decompression** | **Pure-Rust `gzip`, `deflate`, `br` (Brotli), `zstd` (Zstandard)** | External/OS decompression | Python `brotli`/`zstandard` dependencies |
| **Pickled HTTP Headers** | **Full `HttpResponseInfo`, TLS version, ALPN, X.509 cert chains** | Basic HTTP headers only | Raw headers; limited cert chain extraction |
| **Payload Magic Carving** | **60+ binary signatures with `Content-Type` mismatch detection** | Extension guessing from URL query | Basic MIME classification |
| **Locked Profile Snapshots** | **Non-destructive atomic WAL/SHM copying (zero mutation)** | Fails on locked files or locks DB | Copy without active WAL merge |
| **AI Agent Integration** | **Native `stdio` Model Context Protocol (MCP) server (8 tools)** | None | None |
| **Desktop GUI Console** | **Classic Win32 MMC (`chrome2rust-gui`, 0 MB WebView/Electron)** | Classic Win32 MFC (Windows-only) | Local web server in default browser |
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
| **Native Pure-Rust Desktop GUI** | Classic Win32/MMC administrative management console (`chrome2rust-gui`) with zero WebView, Electron, or Node.js dependencies |

---

## Pre-Compiled Binaries & Direct Download

Self-contained native executables with **zero external runtime dependencies** are built for every release across Windows, Linux, and macOS:

| Platform | Target Architecture | Distribution Package | Included Binaries |
| :--- | :--- | :--- | :--- |
| **Windows (64-bit)** | `x86_64-pc-windows-msvc` | [**`chrome2rust-x86_64-pc-windows-msvc.zip`**](https://github.com/adpaolucci/chrome2rust/releases/latest/download/chrome2rust-x86_64-pc-windows-msvc.zip) | `chrome2rust.exe`, `chrome2rust-gui.exe`, `chrome2rust-mcp.exe` |
| **Linux (64-bit)** | `x86_64-unknown-linux-gnu` | [**`chrome2rust-x86_64-unknown-linux-gnu.tar.gz`**](https://github.com/adpaolucci/chrome2rust/releases/latest/download/chrome2rust-x86_64-unknown-linux-gnu.tar.gz) | `chrome2rust`, `chrome2rust-gui`, `chrome2rust-mcp` |
| **macOS Apple Silicon** | `aarch64-apple-darwin` (M1–M4) | [**`chrome2rust-aarch64-apple-darwin.tar.gz`**](https://github.com/adpaolucci/chrome2rust/releases/latest/download/chrome2rust-aarch64-apple-darwin.tar.gz) | `chrome2rust`, `chrome2rust-gui`, `chrome2rust-mcp` |
| **macOS Intel** | `x86_64-apple-darwin` | [**`chrome2rust-x86_64-apple-darwin.tar.gz`**](https://github.com/adpaolucci/chrome2rust/releases/latest/download/chrome2rust-x86_64-apple-darwin.tar.gz) | `chrome2rust`, `chrome2rust-gui`, `chrome2rust-mcp` |

> Every release archive includes cryptographic `SHA256SUMS.txt` checksums alongside `chrome2rust` (CLI), `chrome2rust-gui` (Win32/MMC Desktop Console), and `chrome2rust-mcp` (MCP server).

---

## Workspace Architecture

```text
chrome2rust/
├── Cargo.toml                         # Workspace root manifest (7 modular crates)
├── mcp.json                           # Standard MCP server client configuration
├── crates/
│   ├── chrome2rust-core/              # Foundation: discovery, format sniffer, crypto, WAL-safe SQLite snapshots, time, tracing logging
│   ├── chrome2rust-cache/             # Simple Cache (*_0/*_1) & Blockfile (data_0..3, f_*) parsers, HttpResponseInfo pickles, codecs, 8-format exporter
│   ├── chrome2rust-forensics/         # History, Cookies, Logins, Web Data, Extensions, SNSS Sessions, pure-Rust LevelDB, timeline, findings, Merkle custody
│   ├── chrome2rust-report/            # Self-contained offline HTML, JSON, and Markdown forensic report generators + end-to-end integration tests
│   ├── chrome2rust-mcp/               # Model Context Protocol (MCP) JSON-RPC 2.0 stdio server & standalone `chrome2rust-mcp` binary
│   ├── chrome2rust-cli/               # Unified CLI engine (`chrome2rust`): profiles, sniff, cache, analyze, report, custody, pick, gui, mcp
│   └── chrome2rust-gui/               # Native Classic Win32/MMC desktop forensic workstation (`chrome2rust-gui`)
└── .github/workflows/                 # Cross-platform CI (`fmt`, `clippy`, `test`, `release`) and GitHub Release packaging
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

---

## Quick Start & Compilation

### Prerequisites
- [Rust toolchain](https://rustup.rs/) (1.88 or newer / edition 2024).
- On Linux desktop builds of `chrome2rust-gui`: standard X11/Wayland/OpenGL development packages (`libssl-dev`, `libgtk-3-dev`, `libx11-dev`, `libgl1-mesa-dev`, `libwayland-dev`, `libxkbcommon-dev`).

### Build Release Binaries
```bash
# Clone the repository
git clone https://github.com/adpaolucci/chrome2rust.git
cd chrome2rust

# Run all workspace unit and integration tests
cargo test --workspace

# Build optimized release binaries (`chrome2rust`, `chrome2rust-gui`, `chrome2rust-mcp`)
cargo build --workspace --release
```

### Build Headless / CLI-Only (Zero GUI Libraries Required)
```bash
cargo build --release -p chrome2rust-cli -p chrome2rust-mcp
```

### Launch Native Desktop Console
```bash
# Via CLI launcher:
chrome2rust gui

# Or pre-load a target directory directly:
chrome2rust-gui "/path/to/Chrome/User Data"
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

---

## Model Context Protocol (MCP) for AI Agents

`chrome2rust` includes a built-in [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) JSON-RPC 2.0 server (`chrome2rust mcp` or the standalone `chrome2rust-mcp` binary). All diagnostic logs stream to `stderr` so `stdout` carries clean JSON-RPC envelopes.

Available tools:
- **`chrome2rust_profiles`**: Discover local Chromium browsers, profiles, and cache folders.
- **`chrome2rust_sniff`**: Classify files or directories by magic signature and Chrome artifact type.
- **`chrome2rust_cache_list`**: Filter and enumerate HTTP cache entries as structured JSON.
- **`chrome2rust_cache_inspect`**: Retrieve full HTTP response headers, TLS/ALPN state, X.509 certificates, SHA-256 digest, and UTF-8 preview.
- **`chrome2rust_cache_extract`**: Decompress and export cached resources to an output folder.
- **`chrome2rust_analyze`**: Execute complete read-only `User Data` forensic analysis.
- **`chrome2rust_report`**: Generate offline HTML, JSON, Markdown, or bundled forensic reports.
- **`chrome2rust_custody`**: Compute deterministic SHA-256 digests and balanced RFC 6234 Merkle root manifests.

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

---

## License

MIT — see [LICENSE](LICENSE).


---

## Contributors & Acknowledgments

- **Andrew Paolucci (@adpaolucci)** &mdash; Project Creator, Systems Architect & Lead Software Developer.
- **Antigravity (Google DeepMind)** &mdash; Agentic AI Technical Collaborator (MCP server, multi-codec decompression pipeline, Simple Cache stream verification).
- **Chromium Open Source Project** &mdash; Specifications for Simple Cache, Blockfile, and Chromium User Data profiles.
- **Rust Ecosystem & Community** &mdash; Maintainers of `eframe`/`egui`, `rusqlite`, `brotli`, `ruzstd`, `snap`, and `clap`.
