# chrome2rust

A fast, read-only, cross-platform Rust workstation and CLI suite combining full **NirSoft ChromeCacheView** parity with a comprehensive **Google Chrome / Chromium User Data forensic analyzer and offline report generator**.

---

## Features

### 1. ChromeCacheView Parity (Simple Cache & Blockfile Cache)
- **Dual-Backend Cache Parsing**:
  - **Simple Cache** (`*_0`, `*_1` index entries) with CRC-32 verification and Key SHA-256 verification (tested against Chromium through v156+).
  - **Blockfile Cache** (`index`, `data_0`..`data_N`, `f_xxxxxx` separate files, deleted separate-file detection, and `RankingsNode` last-used timestamps).
- **Modern Partitioned Cache Keys**: Parses Chrome double-key / network isolation keys (`_dk_<site> <frame> <url>`) cleanly into `URL`, `Web Site`, and `Frame` columns.
- **Full `HttpResponseInfo` Pickle Decoding**: Decodes Chrome 2.x–156+ pickles (`extra_flags`, request/response/original timestamps, raw HTTP headers, TLS version, ALPN protocol, socket IP:port, DNS aliases, and embedded X.509 certificate chains).
- **Transparent Decompression**: Automatically decompresses `gzip`, `deflate`, `br` (Brotli), and `zstd` payloads on read, preview, SHA-256 hashing, and extraction.
- **Extraction & Export**:
  - Extract matching entries with `--filename-mode url|cache-name|cache-name-ext`, `--website-dirs` host/path directory reconstruction, preserved `Last Accessed` / `Server Time` modification timestamps, automatic collision renaming, and selective raw vs. decompressed output.
  - Export tables in **CSV**, **TSV (`tab`)**, **Tabular text**, **Plain Text**, **Horizontal HTML**, **Vertical HTML**, **XML**, and **JSON**.
  - Safely delete standalone `*_0` or `f_xxxxxx` files (with dry-run preview by default and `--yes` confirmation).

### 2. Google Chrome `User Data` Forensic Analysis
All SQLite artifacts (`History`, `Cookies`, `Login Data`, `Web Data`, `Top Sites`, `Favicons`, `Shortcuts`, `Reporting and NEL`, `ServerCertificate`) are analyzed using **forensically safe temporary snapshots** (copying `-wal`, `-shm`, and `-journal` sidecars) so locked live browser profiles can be read without mutating evidence.

- **`Local State` & `Last Version`**: Chrome version, `os_crypt` key presence/prefix/portal metadata, `last_active_profiles`, enterprise policies, and profile directory metadata.
- **Browsing History & Downloads (`History`)**: URLs, typed counts, hidden flags, visit chains with decoded `PageTransition` core types & qualifiers, download states/danger flags & full URL redirect chains, omnibox `keyword_search_terms`, plus **`sqlite_sequence` deletion-gap indicators**.
- **Cookies & Saved Credentials (`Network/Cookies`, `Login Data`)**:
  - Read-only structural & encryption scheme classification (`plaintext`, `v10`, `v11`, `v20` App-Bound, `dpapi`) by default.
  - **Optional best-effort decryption** (`--decrypt` / GUI settings) supporting supplied passphrases (`PBKDF2-HMAC-SHA1`), hex-encoded 16/32-byte AES keys, Linux `"peanuts"` fallback, and Chrome DB v24+ 32-byte SHA-256 host-hash prefix stripping.
  - Flags compromised/leaked/weak/reused passwords from `insecure_credentials`.
- **Autofill, Addresses, Cards & Search Engines (`Web Data`)**: Form autofill history, legacy `autofill_profiles` and modern `local_addresses`/`contact_info` tokens, payment card metadata, and custom search engines.
- **Extensions & Bookmarks (`Preferences`, `Secure Preferences`, `Extensions/`, `Bookmarks`)**: Installed extensions with Web Store verification, install timestamps, permission inventories, and risk flags (`UNPACKED`/`COMMAND_LINE` sideloading, `debugger`, `nativeMessaging`, `cookies`, `webRequest`, `<all_urls>`), plus recursive bookmark extraction.
- **SNSS Session Replay (`Sessions/Session_*`, `Sessions/Tabs_*`, legacy `Current/Last Session/Tabs`)**: Reconstructs open and recently closed tabs along with Back/Forward navigation stacks and detects `Sessions_Encrypted`.
- **Site Storage & Network State**: Pure-Rust read-only **LevelDB** reader (`.ldb` SSTables w/ Snappy/zstd blocks + `.log` WAL replay) for `Local Storage/leveldb` and `Session Storage`, `IndexedDB` origin inventory, `Top Sites`, `Shortcuts`, `Reporting and NEL`, and `Network Persistent State`.
- **Forensic Intelligence & Unified Timeline**:
  - Cross-correlates compromised credentials, dangerous downloads, sideloaded/over-privileged extensions, SQLite history sequence gaps, **cached HTML pages missing from History**, and deleted blockfile payloads.
  - Builds a unified chronological timeline across all artifact sources.

### 3. Unified Delivery: Desktop GUI + Modern CLI + Offline HTML/JSON/Markdown Reports
- **Native Desktop GUI (`egui` / `eframe`)**: ChromeCacheView workflow (`F8` docked Image/Text/Hex/Header preview pane, `F4` extract dialog, `Ctrl+Q` quick filter, Shift-click multi-column sorting, Properties dialog, Column chooser) paired with multi-tab forensic exploration and 1-click report export.
- **Interactive Self-Contained HTML Reports**: Zero external dependencies (works offline in air-gapped environments) featuring profile filtering, global search, inline SVG charts, sortable paginated tables, Dark/Light theme toggle, CSV export, and entry inspection modals.

---

## Building

### Full Desktop GUI + CLI
Requires standard X11/Wayland/OpenGL development libraries on Linux (e.g., `libgtk-3-dev`, `libgl-dev`, `libxkbcommon-dev`).

```bash
cargo build --release
```

### Headless CLI Only (No GUI Dependencies)
```bash
cargo build --release -p chrome2rust --no-default-features
```

---

## CLI Usage

Run with no arguments (or `chrome2rust gui`) to launch the desktop GUI, or use any subcommand:

```bash
# Discover local Chrome / Chromium / Edge / Brave / Opera / Vivaldi profiles
chrome2rust profiles
chrome2rust profiles --json

# Launch GUI pre-loaded with a target directory
chrome2rust gui "/path/to/Chrome/User Data"

# List cache entries (auto-discovers local browser cache if PATH is omitted)
chrome2rust cache list "/path/to/Cache_Data" --format table --sort last-accessed --desc
chrome2rust cache list "/path/to/Profile" --content-type "image/" --last 7d --format csv -o images.csv
chrome2rust cache list "/path/to/Cache_Data" --filter "api" --hashes --columns url,content-type,size,sha256

# Extract cached files cleanly (reconstructing website host/path directories)
chrome2rust cache extract "/path/to/Cache_Data" -o ./extracted --website-dirs --filename-mode url
chrome2rust cache extract "/path/to/Cache_Data" --content-type "text/html" -o ./html_dump

# Deep inspection of a single cache entry (headers, TLS/ALPN, X.509 certs, SHA-256, payload preview)
chrome2rust cache inspect "/path/to/Cache_Data/45b032600bc6b3f3_0" --preview
chrome2rust cache inspect "/path/to/Cache_Data" --url "example.com" --dump-body ./body.bin

# Safe standalone cache deletion (dry-run by default; pass --yes to delete)
chrome2rust cache delete "/path/to/Cache_Data" --url "ads"
chrome2rust cache delete "/path/to/Cache_Data" --url "ads" --yes

# Full User Data forensic analysis
chrome2rust analyze "/path/to/User Data"
chrome2rust analyze "/path/to/User Data" --decrypt --key "my_passphrase_or_hex_key" --json > analysis.json

# Generate standalone forensic reports (html, json, markdown, or all)
chrome2rust report "/path/to/User Data" -f html -o ./case_report.html
chrome2rust report "/path/to/User Data" -f all -o ./forensic_bundle --decrypt
```

---

## License

MIT — see [LICENSE](LICENSE).
