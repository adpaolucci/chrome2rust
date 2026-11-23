#![forbid(unsafe_code)]

use chrome2rust_cache::export::{ExtractFilenameMode, ExtractOptions, extract_cache_entries};
use chrome2rust_cache::simple::parse_simple_entry_file;
use chrome2rust_cache::{CacheScanOptions, CacheSortField, load_cache_from_paths, sort_cache_entries};
use chrome2rust_core::crypto::CryptoOptions;
use chrome2rust_core::discovery::{ArtifactFormat, ArtifactSniffer, discover_local_browsers, resolve_target_path};
use chrome2rust_forensics::custody::{generate_custody_manifest, write_custody_manifest};
use chrome2rust_forensics::{AnalysisOptions, analyze_user_data};
use chrome2rust_report::{ReportFormat, write_report};
use serde_json::{Value, json};
use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};
use tracing::{debug, error, info};

pub const MCP_PROTOCOL_VERSION: &str = "2024-11-05";
pub const SERVER_NAME: &str = "chrome2rust-mcp";
pub const SERVER_VERSION: &str = env!("CARGO_PKG_VERSION");

pub fn get_tools_manifest() -> Value {
    json!([
        {
            "name": "chrome2rust_profiles",
            "description": "Discover local Chromium-family browsers, User Data directories, profiles, and HTTP caches.",
            "inputSchema": {
                "type": "object",
                "properties": {}
            }
        },
        {
            "name": "chrome2rust_sniff",
            "description": "Inspect file magic headers, container structures, missing/mismatched extensions, or directory layout to identify Chrome artifacts and cached payloads.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "path": { "type": "string", "description": "Path to file or directory" }
                },
                "required": ["path"]
            }
        },
        {
            "name": "chrome2rust_cache_list",
            "description": "Scan Simple Cache / Blockfile entries matching filters and return structured JSON metadata.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "path": { "type": "string", "description": "Path to Cache_Data, Profile, or User Data folder" },
                    "url": { "type": "string", "description": "Case-insensitive URL substring filter" },
                    "content_type": { "type": "string", "description": "MIME Content-Type substring filter" },
                    "filter": { "type": "string", "description": "Quick search across URL, server, IP, site, response" },
                    "no_zero_length": { "type": "boolean", "description": "Exclude zero-byte items" },
                    "hashes": { "type": "boolean", "description": "Compute SHA-256 payload digests" },
                    "limit": { "type": "integer", "description": "Maximum entries to return (default 100)" }
                },
                "required": ["path"]
            }
        },
        {
            "name": "chrome2rust_cache_inspect",
            "description": "Inspect headers, TLS/ALPN info, X.509 certificates, SHA-256 digest, and optional UTF-8 payload preview of a cached resource.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "path": { "type": "string", "description": "Path to *_0 file or cache/profile directory" },
                    "url": { "type": "string", "description": "Optional URL substring when path is a directory" },
                    "preview": { "type": "boolean", "description": "Include UTF-8 text preview when text-like" }
                },
                "required": ["path"]
            }
        },
        {
            "name": "chrome2rust_cache_extract",
            "description": "Extract cached payloads from Chrome cache into an output directory with decompression, extension recovery, and timestamp preservation.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "path": { "type": "string", "description": "Source Cache_Data, Profile, or User Data folder" },
                    "output_dir": { "type": "string", "description": "Destination directory for extracted files" },
                    "url": { "type": "string", "description": "Optional URL substring filter" },
                    "content_type": { "type": "string", "description": "Optional Content-Type substring filter" },
                    "website_dirs": { "type": "boolean", "description": "Reconstruct host/path directory tree" },
                    "prefer_detected_ext": { "type": "boolean", "description": "Replace existing mismatched extension with payload-detected extension" }
                },
                "required": ["path", "output_dir"]
            }
        },
        {
            "name": "chrome2rust_analyze",
            "description": "Run comprehensive read-only forensic analysis across Chrome User Data artifacts (history, downloads, cookies, logins, extensions, sessions, storage, findings, timeline).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "path": { "type": "string", "description": "Path to User Data root, Profile directory, or Cache directory" },
                    "decrypt": { "type": "boolean", "description": "Enable optional best-effort decryption (Cookies / Login Data)" },
                    "hashes": { "type": "boolean", "description": "Compute SHA-256 digests for cached payloads" }
                },
                "required": ["path"]
            }
        },
        {
            "name": "chrome2rust_report",
            "description": "Generate standalone HTML, JSON, Markdown, or bundled forensic reports from a Chrome User Data directory.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "path": { "type": "string", "description": "Path to Chrome User Data or Profile folder" },
                    "output": { "type": "string", "description": "Output file path or folder when format is 'all'" },
                    "format": { "type": "string", "description": "Report format: html, json, markdown, or all" },
                    "decrypt": { "type": "boolean", "description": "Enable optional best-effort decryption" }
                },
                "required": ["path", "output"]
            }
        },
        {
            "name": "chrome2rust_custody",
            "description": "Compute deterministic SHA-256 hashes and balanced Merkle root over artifacts in a Chrome User Data directory.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "path": { "type": "string", "description": "Path to Chrome artifact file or User Data folder" },
                    "output_manifest": { "type": "string", "description": "Optional CSV or JSON output path to persist custody manifest" }
                },
                "required": ["path"]
            }
        }
    ])
}

pub fn call_tool(name: &str, args: &Value) -> Result<Value, String> {
    match name {
        "chrome2rust_profiles" => {
            let browsers = discover_local_browsers();
            serde_json::to_value(browsers).map_err(|e| e.to_string())
        }
        "chrome2rust_sniff" => {
            let p_str = args["path"].as_str().ok_or("Missing required string 'path'")?;
            let path = Path::new(p_str);
            if !path.exists() {
                return Err(format!("Path does not exist: {p_str}"));
            }
            let mut insp = ArtifactSniffer::inspect_path(path);
            if insp.artifact_format == ArtifactFormat::SimpleCacheEntryFile && insp.detected_mime.is_none() {
                let parent = path.parent().unwrap_or_else(|| Path::new("."));
                if let Ok(Some(entry)) = parse_simple_entry_file(path, parent, &CacheScanOptions::default()) {
                    insp.detected_mime = entry.detected_content_type.or(entry.content_type);
                    insp.suggested_extension = entry.detected_extension;
                    insp.file_signature = entry.file_signature;
                    insp.extension_mismatch = entry.mime_mismatch;
                }
            }
            let resolved = resolve_target_path(path);
            Ok(json!({
                "path": p_str,
                "format": format!("{:?}", insp.artifact_format),
                "format_name": insp.artifact_format_name,
                "detected_mime": insp.detected_mime,
                "suggested_extension": insp.suggested_extension,
                "file_signature": insp.file_signature,
                "detection_source": insp.detection_source,
                "current_extension": insp.current_extension,
                "missing_extension": insp.missing_extension,
                "extension_mismatch": insp.extension_mismatch,
                "suggested_filename": insp.suggested_filename,
                "target_kind": resolved.kind,
                "profiles_found": resolved.profile_dirs.len(),
                "cache_dirs_found": resolved.cache_dirs.len(),
            }))
        }
        "chrome2rust_cache_list" => {
            let p_str = args["path"].as_str().ok_or("Missing required string 'path'")?;
            let target = resolve_target_path(Path::new(p_str));
            let dirs = if target.cache_dirs.is_empty() {
                vec![PathBuf::from(p_str)]
            } else {
                target.cache_dirs
            };
            let opts = CacheScanOptions {
                include_zero_length: !args["no_zero_length"].as_bool().unwrap_or(false),
                url_filter: args["url"].as_str().map(str::to_string),
                content_type_filter: args["content_type"].as_str().map(str::to_string),
                quick_filter: args["filter"].as_str().map(str::to_string),
                compute_hashes: args["hashes"].as_bool().unwrap_or(false),
                ..Default::default()
            };
            let (mut entries, warnings) = load_cache_from_paths(&dirs, &opts);
            sort_cache_entries(&mut entries, CacheSortField::LastAccessed, true, None);
            let limit = args["limit"].as_u64().unwrap_or(100) as usize;
            let total = entries.len();
            entries.truncate(limit);
            Ok(json!({
                "total_matched": total,
                "returned": entries.len(),
                "warnings": warnings,
                "entries": entries,
            }))
        }
        "chrome2rust_cache_inspect" => {
            let p_str = args["path"].as_str().ok_or("Missing required string 'path'")?;
            let path = Path::new(p_str);
            let entry = if path.is_file() {
                let parent = path.parent().unwrap_or_else(|| Path::new("."));
                let opts = CacheScanOptions {
                    compute_hashes: true,
                    ..Default::default()
                };
                parse_simple_entry_file(path, parent, &opts)
                    .map_err(|e| e.to_string())?
                    .ok_or_else(|| format!("Not a valid Simple Cache entry: {p_str}"))?
            } else {
                let target = resolve_target_path(path);
                let dirs = if target.cache_dirs.is_empty() {
                    vec![path.to_path_buf()]
                } else {
                    target.cache_dirs
                };
                let opts = CacheScanOptions {
                    quick_filter: args["url"].as_str().map(str::to_string),
                    compute_hashes: true,
                    ..Default::default()
                };
                let (mut entries, _) = load_cache_from_paths(&dirs, &opts);
                if entries.is_empty() {
                    return Err("No matching cache entry found".to_string());
                }
                entries.remove(0)
            };
            let preview_text = if args["preview"].as_bool().unwrap_or(false) {
                entry.read_decompressed_payload().ok().and_then(|bytes| {
                    let prefix = &bytes[..bytes.len().min(4096)];
                    let valid_len = match std::str::from_utf8(prefix) {
                        Ok(_) => prefix.len(),
                        Err(e) if e.error_len().is_none() => e.valid_up_to(),
                        Err(_) => return None,
                    };
                    if valid_len == 0 && !prefix.is_empty() {
                        return None;
                    }
                    std::str::from_utf8(&prefix[..valid_len]).ok().map(str::to_string)
                })
            } else {
                None
            };
            Ok(json!({
                "entry": entry,
                "preview_text": preview_text,
            }))
        }
        "chrome2rust_cache_extract" => {
            let p_str = args["path"].as_str().ok_or("Missing required string 'path'")?;
            let out_str = args["output_dir"]
                .as_str()
                .ok_or("Missing required string 'output_dir'")?;
            let target = resolve_target_path(Path::new(p_str));
            let dirs = if target.cache_dirs.is_empty() {
                vec![PathBuf::from(p_str)]
            } else {
                target.cache_dirs
            };
            let scan_opts = CacheScanOptions {
                url_filter: args["url"].as_str().map(str::to_string),
                content_type_filter: args["content_type"].as_str().map(str::to_string),
                ..Default::default()
            };
            let (entries, _) = load_cache_from_paths(&dirs, &scan_opts);
            let refs: Vec<_> = entries.iter().collect();
            let ext_opts = ExtractOptions {
                output_dir: PathBuf::from(out_str),
                filename_mode: ExtractFilenameMode::BasedOnUrl,
                use_website_dir_structure: args["website_dirs"].as_bool().unwrap_or(false),
                update_modified_time: true,
                new_name_if_exist: true,
                decompress: true,
                prefer_detected_extension: args["prefer_detected_ext"].as_bool().unwrap_or(false),
            };
            let summary = extract_cache_entries(&refs, &ext_opts).map_err(|e| e.to_string())?;
            serde_json::to_value(summary).map_err(|e| e.to_string())
        }
        "chrome2rust_analyze" => {
            let p_str = args["path"].as_str().ok_or("Missing required string 'path'")?;
            let decrypt = args["decrypt"].as_bool().unwrap_or(false);
            let hashes = args["hashes"].as_bool().unwrap_or(false);
            let opts = AnalysisOptions {
                cache_options: CacheScanOptions {
                    compute_hashes: hashes,
                    ..Default::default()
                },
                crypto_options: if decrypt {
                    CryptoOptions::best_effort()
                } else {
                    CryptoOptions::metadata_only()
                },
                extra_cache_dirs: Vec::new(),
                include_timeline: true,
            };
            let report = analyze_user_data(Path::new(p_str), &opts);
            serde_json::to_value(report).map_err(|e| e.to_string())
        }
        "chrome2rust_report" => {
            let p_str = args["path"].as_str().ok_or("Missing required string 'path'")?;
            let out_str = args["output"].as_str().ok_or("Missing required string 'output'")?;
            let fmt_str = args["format"].as_str().unwrap_or("html");
            let format = ReportFormat::from_name(fmt_str)?;
            let decrypt = args["decrypt"].as_bool().unwrap_or(false);
            let opts = AnalysisOptions {
                cache_options: CacheScanOptions {
                    compute_hashes: true,
                    ..Default::default()
                },
                crypto_options: if decrypt {
                    CryptoOptions::best_effort()
                } else {
                    CryptoOptions::metadata_only()
                },
                extra_cache_dirs: Vec::new(),
                include_timeline: true,
            };
            let report = analyze_user_data(Path::new(p_str), &opts);
            let written = write_report(&report, Path::new(out_str), format).map_err(|e| e.to_string())?;
            Ok(json!({
                "status": "success",
                "files_written": written,
                "summary": report.summary,
                "findings_count": report.findings.len(),
            }))
        }
        "chrome2rust_custody" => {
            let p_str = args["path"].as_str().ok_or("Missing required string 'path'")?;
            let manifest = generate_custody_manifest(Path::new(p_str)).map_err(|e| e.to_string())?;
            if let Some(out) = args["output_manifest"].as_str() {
                write_custody_manifest(&manifest, Path::new(out)).map_err(|e| e.to_string())?;
            }
            serde_json::to_value(manifest).map_err(|e| e.to_string())
        }
        other => Err(format!("Unknown chrome2rust MCP tool: {other}")),
    }
}

pub fn handle_jsonrpc_request(req: &Value) -> Option<Value> {
    let id = req.get("id").cloned();
    let method = req.get("method").and_then(|v| v.as_str()).unwrap_or("");
    debug!(method, "Received MCP JSON-RPC request");

    match method {
        m if m.starts_with("notifications/") => None,
        "ping" => Some(json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": {}
        })),
        "initialize" => Some(json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": {
                "protocolVersion": MCP_PROTOCOL_VERSION,
                "capabilities": {
                    "tools": {}
                },
                "serverInfo": {
                    "name": SERVER_NAME,
                    "version": SERVER_VERSION
                }
            }
        })),
        "tools/list" => Some(json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": {
                "tools": get_tools_manifest()
            }
        })),
        "tools/call" => {
            let params = &req["params"];
            let tool_name = params["name"].as_str().unwrap_or("");
            let args = &params["arguments"];
            let (text, is_err) = match call_tool(tool_name, args) {
                Ok(val) => (serde_json::to_string_pretty(&val).unwrap_or_default(), false),
                Err(msg) => (msg, true),
            };
            Some(json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": {
                    "content": [{ "type": "text", "text": text }],
                    "isError": is_err
                }
            }))
        }
        _ => id.map(|req_id| {
            json!({
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {
                    "code": -32601,
                    "message": format!("Method not found: {method}")
                }
            })
        }),
    }
}

pub fn run_stdio_server() -> Result<(), Box<dyn std::error::Error>> {
    info!(
        server = SERVER_NAME,
        version = SERVER_VERSION,
        "Starting chrome2rust MCP stdio server"
    );
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();

    for line_res in stdin.lock().lines() {
        let line = match line_res {
            Ok(l) => l,
            Err(e) => {
                error!(error = %e, "Failed reading MCP stdin line");
                break;
            }
        };
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        match serde_json::from_str::<Value>(trimmed) {
            Ok(req) => {
                if let Some(resp) = handle_jsonrpc_request(&req) {
                    let out = serde_json::to_string(&resp)?;
                    writeln!(stdout, "{out}")?;
                    stdout.flush()?;
                }
            }
            Err(e) => {
                let err_resp = json!({
                    "jsonrpc": "2.0",
                    "id": null,
                    "error": { "code": -32700, "message": format!("Parse error: {e}") }
                });
                writeln!(stdout, "{}", serde_json::to_string(&err_resp)?)?;
                stdout.flush()?;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_mcp_manifest_and_custody_dispatch() {
        let tools = get_tools_manifest();
        let arr = tools.as_array().unwrap();
        assert!(arr.len() >= 7);

        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join("Last Version"), "156.0.8078.79\n").unwrap();
        std::fs::write(dir.path().join("Local State"), r#"{"profile":{"info_cache":{}}}"#).unwrap();

        let rpc = json!({
            "jsonrpc": "2.0",
            "id": 7,
            "method": "tools/call",
            "params": {
                "name": "chrome2rust_sniff",
                "arguments": { "path": dir.path().to_string_lossy() }
            }
        });
        let resp = handle_jsonrpc_request(&rpc).unwrap();
        assert_eq!(resp["id"], 7);
        assert_eq!(resp["result"]["isError"], false);

        let custody = call_tool("chrome2rust_custody", &json!({ "path": dir.path().to_string_lossy() })).unwrap();
        assert_eq!(custody["artifact_count"], 2);
        assert_eq!(custody["merkle_root_sha256"].as_str().unwrap().len(), 64);

        // Verify extensionless file sniffing and prefer_detected_ext tool schema
        let webp_blob = dir.path().join("asset_blob");
        std::fs::write(&webp_blob, b"RIFF\x20\x00\x00\x00WEBPVP8 \x14\x00\x00\x00DATA").unwrap();
        let sn = call_tool("chrome2rust_sniff", &json!({ "path": webp_blob.to_string_lossy() })).unwrap();
        assert_eq!(sn["detected_mime"], "image/webp");
        assert_eq!(sn["suggested_extension"], "webp");
        assert_eq!(sn["missing_extension"], true);
        assert_eq!(sn["suggested_filename"], "asset_blob.webp");

        let extract_schema = arr.iter().find(|t| t["name"] == "chrome2rust_cache_extract").unwrap();
        assert!(extract_schema["inputSchema"]["properties"]["prefer_detected_ext"].is_object());

        // Verify UTF-8 multi-byte boundary at byte 4096 still returns preview_text
        let entry_path = dir.path().join("utf8_4096_0");
        let key = b"https://example.org/utf8";
        let mut payload = vec![b'a'; 4095];
        payload.extend_from_slice("€tail".as_bytes()); // 3-byte Euro sign straddles byte 4096
        let s0 = b"HTTP/1.1 200 OK\0Content-Type: text/plain; charset=utf-8\0\0";
        let mut s0_pickle = Vec::new();
        let h_aligned = s0.len().div_ceil(4) * 4;
        let plen = 4 + 8 + 8 + 4 + h_aligned;
        s0_pickle.extend_from_slice(&(plen as u32).to_le_bytes());
        s0_pickle.extend_from_slice(&3u32.to_le_bytes());
        s0_pickle.extend_from_slice(&0i64.to_le_bytes());
        s0_pickle.extend_from_slice(&0i64.to_le_bytes());
        s0_pickle.extend_from_slice(&(s0.len() as u32).to_le_bytes());
        s0_pickle.extend_from_slice(s0);
        s0_pickle.resize(s0_pickle.len() + (h_aligned - s0.len()), 0);
        let mut raw = Vec::new();
        raw.extend_from_slice(&0xfcfb_6d1b_a772_5c30u64.to_le_bytes());
        raw.extend_from_slice(&5u32.to_le_bytes());
        raw.extend_from_slice(&(key.len() as u32).to_le_bytes());
        raw.extend_from_slice(&0u64.to_le_bytes());
        raw.extend_from_slice(key);
        raw.extend_from_slice(&payload);
        raw.extend_from_slice(&0xf4fa_6f45_970d_41d8u64.to_le_bytes());
        raw.extend_from_slice(&[0u8; 16]);
        raw.extend_from_slice(&s0_pickle);
        raw.extend_from_slice(&0xf4fa_6f45_970d_41d8u64.to_le_bytes());
        raw.extend_from_slice(&0u32.to_le_bytes());
        raw.extend_from_slice(&0u32.to_le_bytes());
        raw.extend_from_slice(&(s0_pickle.len() as u32).to_le_bytes());
        raw.extend_from_slice(&0u32.to_le_bytes());
        std::fs::write(&entry_path, raw).unwrap();

        let inspected = call_tool(
            "chrome2rust_cache_inspect",
            &json!({ "path": entry_path.to_string_lossy(), "preview": true }),
        )
        .unwrap();
        assert_eq!(inspected["preview_text"].as_str().map(str::len), Some(4095));

        let ping_resp = handle_jsonrpc_request(&json!({
            "jsonrpc": "2.0",
            "id": 99,
            "method": "ping"
        }))
        .unwrap();
        assert_eq!(ping_resp["id"], 99);
        assert_eq!(ping_resp["result"], json!({}));

        assert!(
            handle_jsonrpc_request(&json!({
                "jsonrpc": "2.0",
                "method": "notifications/initialized"
            }))
            .is_none()
        );
    }
}
