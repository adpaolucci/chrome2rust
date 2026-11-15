# `chrome2rust-mcp`

Model Context Protocol (MCP) JSON-RPC 2.0 stdio server exposing **chrome2rust** browser cache inspection and Google Chrome `User Data` forensic analysis capabilities to AI assistants and automation tools.

## Exposed Tools
- `chrome2rust_profiles` — Discover local Chromium-family browser profiles and cache directories.
- `chrome2rust_sniff` — Identify artifact format (`User Data`, Profile, Simple Cache, Blockfile, SQLite DB, SNSS, LevelDB).
- `chrome2rust_cache_list` — Scan, filter, sort, and summarize cached HTTP resources.
- `chrome2rust_cache_inspect` — Inspect HTTP response headers, TLS/ALPN metadata, X.509 cert chains, and payload preview.
- `chrome2rust_cache_extract` — Extract decompressed payloads with optional website directory reconstruction.
- `chrome2rust_analyze` — Analyze a Google Chrome `User Data` or profile directory (history, downloads, cookies, logins, extensions, sessions, storage, timeline, findings).
- `chrome2rust_report` — Generate offline HTML, JSON, Markdown, or bundled forensic reports.
- `chrome2rust_custody` — Compute deterministic SHA-256 Merkle root and file-level chain-of-custody manifest.

## Usage
```bash
# Run via main CLI
chrome2rust mcp

# Print JSON tool schemas
chrome2rust mcp --tools

# Or run standalone binary
chrome2rust-mcp
```
