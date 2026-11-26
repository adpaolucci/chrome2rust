#![forbid(unsafe_code)]

use chrome2rust_cache::carve_images::ImageCarveTableProvider;
use chrome2rust_cache::carve_video::VideoCarveTableProvider;
use chrome2rust_cache::export::{ExtractFilenameMode, ExtractOptions, extract_cache_entries};
use chrome2rust_cache::simple::parse_simple_entry_file;
use chrome2rust_cache::{CacheScanOptions, CacheSortField, load_cache_from_paths, sort_cache_entries};
use chrome2rust_core::crypto::CryptoOptions;
use chrome2rust_core::discovery::{
    ArtifactFormat, ArtifactSniffer, UnifiedBrowserKind, discover_local_browsers, resolve_target_path,
};
use chrome2rust_forensics::custody::{generate_custody_manifest, write_custody_manifest};
use chrome2rust_forensics::providers::{build_browser_tool_provider_by_id, build_browser_tool_providers};
use chrome2rust_forensics::search_queries::SearchQueriesTableProvider;
use chrome2rust_forensics::unified::{
    UnifiedAddonsTableProvider, UnifiedAutofillTableProvider, UnifiedBookmarksTableProvider,
    UnifiedDownloadsTableProvider, UnifiedHistoryTableProvider, UnifiedQueryOptions,
};
use chrome2rust_forensics::{AnalysisOptions, analyze_user_data};
use chrome2rust_report::{ReportFormat, write_report};
use guap_mcp::{ActionCommand, ActionRiskLevel, McpServerRegistry, McpToolError, PolicyMode};
use guap_table::{FilterExpr, GetNirQuery, SortDirection, TableData, TableProvider, TableQuery, TableSchema};
use serde_json::{Map, Value, json};
use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tracing::{debug, error, info};

pub const MCP_PROTOCOL_VERSION: &str = "2024-11-05";
pub const SERVER_NAME: &str = "chrome2rust-mcp";
pub const SERVER_VERSION: &str = env!("CARGO_PKG_VERSION");

const LEGACY_TOOL_NAMES: &[&str] = &[
    "chrome2rust_profiles",
    "chrome2rust_sniff",
    "chrome2rust_cache_list",
    "chrome2rust_cache_inspect",
    "chrome2rust_cache_extract",
    "chrome2rust_analyze",
    "chrome2rust_report",
    "chrome2rust_custody",
];

struct BrowserTableAction {
    tool_id: &'static str,
    description: &'static str,
    schema: TableSchema,
    default_path: Option<PathBuf>,
    policy: PolicyMode,
}

impl ActionCommand for BrowserTableAction {
    fn command_id(&self) -> &'static str {
        self.tool_id
    }

    fn description(&self) -> &'static str {
        self.description
    }

    fn risk_level(&self) -> ActionRiskLevel {
        ActionRiskLevel::ReadOnly
    }

    fn input_schema(&self) -> Value {
        let col_ids: Vec<Value> = self
            .schema
            .columns
            .iter()
            .map(|c| Value::String(c.id.clone()))
            .collect();
        let mut props = Map::new();
        props.insert(
            "path".to_string(),
            json!({
                "type": "string",
                "description": "Optional path to browser profile, cache directory, or multi-browser container (auto-discovers local browsers when omitted)"
            }),
        );
        props.insert(
            "filter".to_string(),
            json!({
                "description": "Filter expression string (GetNir syntax) or structured FilterExpr object"
            }),
        );
        props.insert(
            "sort".to_string(),
            json!({
                "type": "array",
                "description": "Sort clauses as [{ column, direction }]",
                "items": {
                    "type": "object",
                    "properties": {
                        "column": { "type": "string", "enum": col_ids },
                        "direction": { "type": "string", "enum": ["asc", "desc"] }
                    },
                    "required": ["column"]
                }
            }),
        );
        props.insert(
            "columns".to_string(),
            json!({
                "type": "array",
                "description": "Optional projected column IDs",
                "items": { "type": "string", "enum": col_ids }
            }),
        );
        props.insert(
            "offset".to_string(),
            json!({ "type": "integer", "minimum": 0, "default": 0 }),
        );
        props.insert("limit".to_string(), json!({ "type": "integer", "minimum": 1 }));
        if self.tool_id.starts_with("chrome2rust_unified_") || self.tool_id == "chrome2rust_search_queries" {
            props.insert(
                "browser".to_string(),
                json!({ "type": "string", "description": "Optional browser filter (chrome, edge, brave, opera, firefox, safari)" }),
            );
        }
        if self.tool_id == "chrome2rust_search_queries" {
            props.insert(
                "engine".to_string(),
                json!({ "type": "string", "description": "Optional search engine filter (Google, Bing, DuckDuckGo, Yahoo, Yandex, Baidu, YouTube, Brave Search)" }),
            );
        }
        if self.tool_id == "chrome2rust_carve_images" || self.tool_id == "chrome2rust_carve_video" {
            props.insert(
                "extract_dir".to_string(),
                json!({ "type": "string", "description": "Optional output directory to write carved media files" }),
            );
        }
        if self.tool_id == "chrome2rust_carve_images" {
            props.insert(
                "min_size".to_string(),
                json!({ "type": "integer", "minimum": 0, "description": "Minimum image payload size in bytes" }),
            );
        }

        json!({
            "type": "object",
            "properties": Value::Object(props),
            "additionalProperties": false
        })
    }

    fn execute(&self, args: &Value, _dry_run: bool) -> Result<Value, McpToolError> {
        let target_path = args
            .get("path")
            .and_then(Value::as_str)
            .filter(|s| !s.trim().is_empty())
            .map(PathBuf::from)
            .or_else(|| self.default_path.clone());

        let browser_filter = match args.get("browser").and_then(Value::as_str) {
            Some(b) if !b.trim().is_empty() => Some(
                UnifiedBrowserKind::from_filter(b)
                    .ok_or_else(|| McpToolError::InvalidParams(format!("unknown browser filter '{b}'")))?,
            ),
            _ => None,
        };

        let provider: Arc<dyn TableProvider> = match self.tool_id {
            "chrome2rust_unified_history" => Arc::new(UnifiedHistoryTableProvider::with_options(UnifiedQueryOptions {
                paths: target_path.into_iter().collect(),
                browser_filter,
                ..Default::default()
            })),
            "chrome2rust_unified_downloads" => {
                Arc::new(UnifiedDownloadsTableProvider::with_options(UnifiedQueryOptions {
                    paths: target_path.into_iter().collect(),
                    browser_filter,
                    ..Default::default()
                }))
            }
            "chrome2rust_unified_addons" => Arc::new(UnifiedAddonsTableProvider::with_options(UnifiedQueryOptions {
                paths: target_path.into_iter().collect(),
                browser_filter,
                ..Default::default()
            })),
            "chrome2rust_unified_bookmarks" => {
                Arc::new(UnifiedBookmarksTableProvider::with_options(UnifiedQueryOptions {
                    paths: target_path.into_iter().collect(),
                    browser_filter,
                    ..Default::default()
                }))
            }
            "chrome2rust_unified_autofill" => {
                Arc::new(UnifiedAutofillTableProvider::with_options(UnifiedQueryOptions {
                    paths: target_path.into_iter().collect(),
                    browser_filter,
                    ..Default::default()
                }))
            }
            "chrome2rust_search_queries" => {
                let engine_filter = args
                    .get("engine")
                    .and_then(Value::as_str)
                    .filter(|s| !s.trim().is_empty())
                    .map(str::to_string);
                Arc::new(SearchQueriesTableProvider::with_options(
                    UnifiedQueryOptions {
                        paths: target_path.into_iter().collect(),
                        browser_filter,
                        ..Default::default()
                    },
                    engine_filter,
                ))
            }
            "chrome2rust_carve_images" => {
                let extract_dir = match args.get("extract_dir") {
                    None | Some(Value::Null) => None,
                    Some(Value::String(s)) if s.trim().is_empty() => None,
                    Some(Value::String(s)) => {
                        if self.policy == PolicyMode::ReadOnlyOnly {
                            return Err(McpToolError::PolicyDenied(
                                "extract_dir writes carved files to disk and is denied under PolicyMode::ReadOnlyOnly"
                                    .into(),
                            ));
                        }
                        Some(PathBuf::from(s))
                    }
                    Some(_) => {
                        return Err(McpToolError::InvalidParams(
                            "'extract_dir' must be a string path".into(),
                        ));
                    }
                };
                let min_size = args
                    .get("min_size")
                    .and_then(Value::as_u64)
                    .and_then(|n| usize::try_from(n).ok());
                Arc::new(ImageCarveTableProvider::with_options(
                    target_path.into_iter().collect(),
                    extract_dir,
                    min_size,
                ))
            }
            "chrome2rust_carve_video" => {
                let extract_dir = match args.get("extract_dir") {
                    None | Some(Value::Null) => None,
                    Some(Value::String(s)) if s.trim().is_empty() => None,
                    Some(Value::String(s)) => {
                        if self.policy == PolicyMode::ReadOnlyOnly {
                            return Err(McpToolError::PolicyDenied(
                                "extract_dir writes carved files to disk and is denied under PolicyMode::ReadOnlyOnly"
                                    .into(),
                            ));
                        }
                        Some(PathBuf::from(s))
                    }
                    Some(_) => {
                        return Err(McpToolError::InvalidParams(
                            "'extract_dir' must be a string path".into(),
                        ));
                    }
                };
                Arc::new(VideoCarveTableProvider::with_options(
                    target_path.into_iter().collect(),
                    extract_dir,
                ))
            }
            _ => build_browser_tool_provider_by_id(self.tool_id, target_path.as_deref())
                .ok_or_else(|| McpToolError::NotFound(self.tool_id.to_string()))?,
        };

        let query = parse_mcp_table_query(&self.schema, args)?;
        let data = provider.query(&query)?;
        Ok(serialize_table_data(&data))
    }
}

fn parse_mcp_table_query(schema: &TableSchema, args: &Value) -> Result<TableQuery, McpToolError> {
    let obj = match args {
        Value::Null => return Ok(TableQuery::default()),
        Value::Object(m) => m,
        _ => return Err(McpToolError::InvalidParams("arguments must be a JSON object".into())),
    };

    let filter = match obj.get("filter") {
        None | Some(Value::Null) => None,
        Some(Value::String(s)) if s.trim().is_empty() => None,
        Some(Value::String(s)) => Some(GetNirQuery::parse_filter(s)?),
        Some(other) => {
            let expr: FilterExpr = serde_json::from_value(other.clone())
                .map_err(|e| McpToolError::InvalidParams(format!("invalid filter object: {e}")))?;
            Some(expr)
        }
    };

    let sort = match obj.get("sort") {
        None | Some(Value::Null) => Vec::new(),
        Some(Value::String(spec)) => {
            let parsed = GetNirQuery::parse_sort(spec)?;
            let mut resolved = Vec::with_capacity(parsed.len());
            for (col, dir) in parsed {
                let idx = schema
                    .column_index(&col)
                    .ok_or_else(|| McpToolError::InvalidParams(format!("invalid sort column '{col}'")))?;
                resolved.push((idx, dir));
            }
            resolved
        }
        Some(Value::Array(items)) => {
            let mut resolved = Vec::with_capacity(items.len());
            for item in items {
                let item_obj = item
                    .as_object()
                    .ok_or_else(|| McpToolError::InvalidParams("sort entries must be objects".into()))?;
                let col = item_obj
                    .get("column")
                    .and_then(Value::as_str)
                    .ok_or_else(|| McpToolError::InvalidParams("sort entry missing 'column'".into()))?;
                let idx = schema
                    .column_index(col)
                    .ok_or_else(|| McpToolError::InvalidParams(format!("invalid sort column '{col}'")))?;
                let dir = match item_obj.get("direction").and_then(Value::as_str) {
                    None | Some("asc") | Some("ASC") => SortDirection::Asc,
                    Some("desc") | Some("DESC") => SortDirection::Desc,
                    Some(other) => {
                        return Err(McpToolError::InvalidParams(format!("invalid sort direction '{other}'")));
                    }
                };
                resolved.push((idx, dir));
            }
            resolved
        }
        Some(_) => return Err(McpToolError::InvalidParams("'sort' must be an array or string".into())),
    };

    let columns = match obj.get("columns") {
        None | Some(Value::Null) => None,
        Some(Value::Array(arr)) => {
            let mut cols = Vec::with_capacity(arr.len());
            for item in arr {
                let c = item
                    .as_str()
                    .ok_or_else(|| McpToolError::InvalidParams("'columns' items must be strings".into()))?;
                cols.push(c.to_string());
            }
            Some(cols)
        }
        Some(_) => return Err(McpToolError::InvalidParams("'columns' must be an array".into())),
    };

    let offset = match obj.get("offset") {
        None | Some(Value::Null) => 0usize,
        Some(v) => v
            .as_u64()
            .and_then(|n| usize::try_from(n).ok())
            .ok_or_else(|| McpToolError::InvalidParams("'offset' must be a non-negative integer".into()))?,
    };

    let limit = match obj.get("limit") {
        None | Some(Value::Null) => None,
        Some(v) => {
            let n = v
                .as_u64()
                .and_then(|n| usize::try_from(n).ok())
                .filter(|&n| n > 0)
                .ok_or_else(|| McpToolError::InvalidParams("'limit' must be a positive integer".into()))?;
            Some(n)
        }
    };

    Ok(TableQuery {
        filter,
        sort,
        columns,
        offset,
        limit,
    })
}

fn serialize_table_data(data: &TableData) -> Value {
    let rows: Vec<Value> = data
        .rows
        .iter()
        .map(|row| {
            let mut row_obj = Map::with_capacity(data.schema.columns.len() + 2);
            row_obj.insert("row_id".to_string(), json!(row.id));
            for (idx, col) in data.schema.columns.iter().enumerate() {
                let val = row.cells.get(idx).map(|c| c.to_json_value()).unwrap_or(Value::Null);
                row_obj.insert(col.id.clone(), val);
            }
            if let Some(detail) = &row.detail_json {
                row_obj.insert("detail_json".to_string(), detail.clone());
            }
            Value::Object(row_obj)
        })
        .collect();

    json!({
        "tool_id": data.schema.tool_id,
        "title": data.schema.title,
        "total_rows": data.total_rows,
        "returned_rows": rows.len(),
        "columns": data.schema.columns,
        "rows": rows,
    })
}

/// Builds the `guap-mcp` server registry containing all 21 read-only browser tools.
pub fn build_guap_registry(default_path: Option<&Path>) -> McpServerRegistry {
    let mut registry = McpServerRegistry::new(PolicyMode::ReadOnlyOnly).with_server_info(SERVER_NAME, SERVER_VERSION);
    for provider in build_browser_tool_providers(default_path) {
        registry.register_action(Arc::new(BrowserTableAction {
            tool_id: provider.tool_id(),
            description: provider.description(),
            schema: provider.schema(),
            default_path: default_path.map(|p| p.to_path_buf()),
            policy: PolicyMode::ReadOnlyOnly,
        }));
    }
    registry
}

pub fn get_legacy_tools_manifest() -> Value {
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

pub fn get_tools_manifest() -> Value {
    let mut tools = get_legacy_tools_manifest().as_array().cloned().unwrap_or_default();
    if let Some(new_tools) = build_guap_registry(None).list_tools().as_array() {
        tools.extend(new_tools.iter().cloned());
    }
    Value::Array(tools)
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
        other => build_guap_registry(None).dispatch(other, args).map_err(|e| e.message),
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
            if LEGACY_TOOL_NAMES.contains(&tool_name) {
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
            } else {
                build_guap_registry(None).handle_jsonrpc_request(req)
            }
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

    #[test]
    fn test_mcp_all_29_tools_readonly_policy_and_r4_checks() {
        let manifest = get_tools_manifest();
        let arr = manifest.as_array().unwrap();
        assert_eq!(arr.len(), 29);
        assert!(!arr.iter().any(|t| t["name"] == "chrome2rust_cache_delete"));

        let new_tools: Vec<_> = arr
            .iter()
            .filter(|t| !LEGACY_TOOL_NAMES.contains(&t["name"].as_str().unwrap_or("")))
            .collect();
        assert_eq!(new_tools.len(), 21);
        for t in new_tools {
            assert_eq!(t["annotations"]["readOnlyHint"], true);
            assert_eq!(t["annotations"]["destructiveHint"], false);
        }

        // Test JSON-RPC initialize + tools/list + tools/call on new ReadOnly tools
        let init_resp = handle_jsonrpc_request(&json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize"
        }))
        .unwrap();
        assert_eq!(init_resp["result"]["protocolVersion"], MCP_PROTOCOL_VERSION);

        let list_resp = handle_jsonrpc_request(&json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list"
        }))
        .unwrap();
        assert_eq!(list_resp["result"]["tools"].as_array().unwrap().len(), 29);

        // Synthetic Firefox + Chrome Web Data fixture for R4 over MCP
        let dir = TempDir::new().unwrap();
        let fx = dir.path().join("FirefoxProfile");
        std::fs::create_dir_all(&fx).unwrap();
        let fxc = rusqlite::Connection::open(fx.join("cookies.sqlite")).unwrap();
        fxc.execute_batch(
            "CREATE TABLE moz_cookies(id INTEGER PRIMARY KEY, name TEXT, value TEXT, host TEXT, path TEXT, expiry INTEGER, lastAccessed INTEGER, creationTime INTEGER, isSecure INTEGER, isHttpOnly INTEGER, sameSite INTEGER);
             INSERT INTO moz_cookies VALUES (1, 'sid', 'SECRET_MCP_COOKIE_VAL', '.example.com', '/', 1800000000, 1794700800000000, 1794700000000000, 1, 1, 1);",
        )
        .unwrap();

        let ch = dir.path().join("ChromeUD").join("Default");
        std::fs::create_dir_all(&ch).unwrap();
        let wd = rusqlite::Connection::open(ch.join("Web Data")).unwrap();
        wd.execute_batch(
            "CREATE TABLE autofill(name TEXT, value TEXT, value_lower TEXT, date_created INTEGER, date_last_used INTEGER, count INTEGER);
             CREATE TABLE credit_cards(guid TEXT, name_on_card TEXT, expiration_month INTEGER, expiration_year INTEGER, card_number_encrypted BLOB, date_modified INTEGER, origin TEXT, use_count INTEGER, use_date INTEGER, billing_address_id TEXT, nickname TEXT);
             INSERT INTO autofill VALUES ('username', 'alice', 'alice', 1794700000, 1794700800, 2);
             INSERT INTO credit_cards VALUES ('cc1', 'SECRET_MCP_CARDHOLDER', 12, 2029, X'0102', 1794700800, '', 1, 1794700800, '', 'Visa');",
        )
        .unwrap();

        let fx_cookies_call = handle_jsonrpc_request(&json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "chrome2rust_fx_cookies",
                "arguments": { "path": fx.to_string_lossy() }
            }
        }))
        .unwrap();
        let cookies_txt = fx_cookies_call["result"]["content"][0]["text"].as_str().unwrap();
        assert!(cookies_txt.contains(".example.com"));
        assert!(!cookies_txt.contains("SECRET_MCP_COOKIE_VAL"));

        let af_call = handle_jsonrpc_request(&json!({
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {
                "name": "chrome2rust_unified_autofill",
                "arguments": { "path": dir.path().to_string_lossy() }
            }
        }))
        .unwrap();
        let af_txt = af_call["result"]["content"][0]["text"].as_str().unwrap();
        assert!(af_txt.contains("alice"));
        assert!(!af_txt.contains("SECRET_MCP_CARDHOLDER"));

        // B.2: extract_dir must be denied under PolicyMode::ReadOnlyOnly (-32003) and never write to disk
        for carve_tool in ["chrome2rust_carve_images", "chrome2rust_carve_video"] {
            let blocked_dir = dir.path().join(format!("blocked_{carve_tool}"));
            let resp = handle_jsonrpc_request(&json!({
                "jsonrpc": "2.0",
                "id": 5,
                "method": "tools/call",
                "params": {
                    "name": carve_tool,
                    "arguments": {
                        "path": dir.path().to_string_lossy(),
                        "extract_dir": blocked_dir.to_string_lossy()
                    }
                }
            }))
            .unwrap();
            assert_eq!(
                resp["error"]["code"], -32003,
                "expected PolicyDenied for {carve_tool}: {resp}"
            );
            assert!(!blocked_dir.exists());

            // Without extract_dir, read-only invocation succeeds
            let ok_resp = handle_jsonrpc_request(&json!({
                "jsonrpc": "2.0",
                "id": 6,
                "method": "tools/call",
                "params": {
                    "name": carve_tool,
                    "arguments": { "path": dir.path().to_string_lossy() }
                }
            }))
            .unwrap();
            assert_eq!(ok_resp["result"]["isError"], false);
        }
    }
}
