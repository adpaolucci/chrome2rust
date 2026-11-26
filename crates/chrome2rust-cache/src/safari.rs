use crate::decompress::decompress_payload_for_type;
use crate::hex_lower;
use crate::pickle::ParsedHeader;
use chrome2rust_core::discovery::{UnifiedBrowserKind, discover_safari_profiles, resolve_unified_targets};
use chrome2rust_core::error::DiagnosticWarning;
use chrome2rust_core::magic::detect_content;
use chrome2rust_core::plist::{PlistValue, parse_plist, resolve_keyed_ref};
use chrome2rust_core::sqlite_util::ForensicSqlite;
use chrome2rust_core::time::cf_absolute_time_to_datetime;
use chrono::{DateTime, NaiveDateTime, Utc};
use guap_table::{
    CellValue, ColumnDef, ColumnType, Row, SortDirection, TableData, TableError, TableProvider, TableQuery,
    TableSchema, apply_query,
};
use rusqlite::types::ValueRef;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SafariCacheEntry {
    pub url: String,
    pub status_code: Option<u16>,
    pub content_type: Option<String>,
    pub content_encoding: Option<String>,
    pub detected_content_type: Option<String>,
    pub detected_extension: Option<String>,
    #[serde(default)]
    pub mime_mismatch: bool,
    pub body_size: usize,
    pub timestamp: Option<DateTime<Utc>>,
    pub storage_policy: String,
    pub cache_file: Option<String>,
    pub headers: Vec<ParsedHeader>,
    pub payload_sha256: Option<String>,
    #[serde(skip)]
    pub inline_bytes: Option<Vec<u8>>,
    #[serde(skip)]
    pub fs_cached_path: Option<PathBuf>,
}

impl SafariCacheEntry {
    pub fn read_decompressed_payload(&self) -> Vec<u8> {
        let raw = if let Some(inline) = &self.inline_bytes {
            inline.clone()
        } else if let Some(fp) = &self.fs_cached_path {
            std::fs::read(fp).unwrap_or_default()
        } else {
            Vec::new()
        };
        if raw.is_empty() {
            return raw;
        }
        decompress_payload_for_type(&raw, self.content_encoding.as_deref(), self.content_type.as_deref()).unwrap_or(raw)
    }
}

fn decode_safari_storage_policy(p: i64) -> String {
    match p {
        0 => "Allowed".to_string(),
        1 => "AllowedInMemoryOnly".to_string(),
        2 => "NotAllowed".to_string(),
        other => format!("Policy({other})"),
    }
}

fn parse_safari_timestamp(val: ValueRef<'_>) -> Option<DateTime<Utc>> {
    match val {
        ValueRef::Real(f) => cf_absolute_time_to_datetime(f),
        ValueRef::Integer(i) => cf_absolute_time_to_datetime(i as f64),
        ValueRef::Text(bytes) => {
            let s = std::str::from_utf8(bytes).ok()?.trim();
            if let Ok(f) = s.parse::<f64>() {
                return cf_absolute_time_to_datetime(f);
            }
            if let Ok(dt) = DateTime::parse_from_rfc3339(s) {
                return Some(dt.with_timezone(&Utc));
            }
            for fmt in ["%Y-%m-%d %H:%M:%S%.f", "%Y-%m-%d %H:%M:%S"] {
                if let Ok(ndt) = NaiveDateTime::parse_from_str(s, fmt) {
                    return Some(ndt.and_utc());
                }
            }
            None
        }
        _ => None,
    }
}

#[derive(Default)]
struct SafariResponseMeta {
    status_code: Option<u16>,
    content_type: Option<String>,
    content_encoding: Option<String>,
    headers: Vec<ParsedHeader>,
}

/// Extracts HTTP status code, MIME type, Content-Encoding, and headers from Safari `Cache.db`
/// `response_object` (supports both flat plist Dicts and `NSKeyedArchiver` `$objects` tables).
fn extract_safari_response_meta(plist: &PlistValue) -> SafariResponseMeta {
    let mut meta = SafariResponseMeta::default();

    // Case 1: NSKeyedArchiver ($objects + $top)
    if let Some(objects) = plist.get("$objects").and_then(PlistValue::as_array) {
        for obj in objects {
            let Some(dict) = obj.as_dict() else {
                continue;
            };
            if meta.status_code.is_none()
                && let Some(sc) = dict
                    .get("statusCode")
                    .or_else(|| dict.get("Status"))
                    .and_then(PlistValue::as_i64)
                && (100..=599).contains(&sc)
            {
                meta.status_code = Some(sc as u16);
            }
            if meta.content_type.is_none()
                && let Some(mime_ref) = dict.get("MIMEType")
                && let Some(s) = resolve_keyed_ref(mime_ref, objects).as_str()
                && !s.is_empty()
            {
                meta.content_type = Some(s.to_string());
            }
            if let Some(hdrs_ref) = dict.get("allHeaderFields").or_else(|| dict.get("headers")) {
                let resolved = resolve_keyed_ref(hdrs_ref, objects);
                collect_plist_headers(resolved, Some(objects), &mut meta);
            }
            // NSDictionary encoded as NS.keys + NS.objects
            if let (Some(PlistValue::Array(keys)), Some(PlistValue::Array(vals))) =
                (dict.get("NS.keys"), dict.get("NS.objects"))
            {
                for (k_ref, v_ref) in keys.iter().zip(vals.iter()) {
                    if let (Some(k), Some(v)) = (
                        resolve_keyed_ref(k_ref, objects).as_str(),
                        resolve_keyed_ref(v_ref, objects).as_str(),
                    ) {
                        record_header(k, v, &mut meta);
                    }
                }
            }
        }
        if meta.status_code.is_some() || !meta.headers.is_empty() || meta.content_type.is_some() {
            return meta;
        }
    }

    // Case 2: Direct flat plist Dict or Array
    if let Some(dict) = plist.as_dict() {
        if let Some(sc) = dict
            .get("statusCode")
            .or_else(|| dict.get("Status"))
            .and_then(PlistValue::as_i64)
            && (100..=599).contains(&sc)
        {
            meta.status_code = Some(sc as u16);
        }
        if let Some(mime) = dict.get("MIMEType").and_then(PlistValue::as_str) {
            meta.content_type = Some(mime.to_string());
        }
        if let Some(hdrs) = dict.get("allHeaderFields").or_else(|| dict.get("headers")) {
            collect_plist_headers(hdrs, None, &mut meta);
        } else {
            collect_plist_headers(plist, None, &mut meta);
        }
    } else if let Some(arr) = plist.as_array() {
        for item in arr {
            if let Some(sc) = item.as_i64()
                && (100..=599).contains(&sc)
                && meta.status_code.is_none()
            {
                meta.status_code = Some(sc as u16);
            } else if item.as_dict().is_some() {
                collect_plist_headers(item, None, &mut meta);
            }
        }
    }

    meta
}

fn collect_plist_headers(val: &PlistValue, objects: Option<&[PlistValue]>, meta: &mut SafariResponseMeta) {
    let Some(dict) = val.as_dict() else {
        return;
    };
    for (k, v) in dict {
        if k.starts_with('$') || k == "statusCode" || k == "MIMEType" {
            continue;
        }
        let str_val = match objects {
            Some(objs) => resolve_keyed_ref(v, objs).as_str(),
            None => v.as_str(),
        };
        if let Some(sv) = str_val {
            record_header(k, sv, meta);
        }
    }
}

fn record_header(name: &str, value: &str, meta: &mut SafariResponseMeta) {
    if name.eq_ignore_ascii_case("content-type") && meta.content_type.is_none() {
        meta.content_type = Some(value.split(';').next().unwrap_or(value).trim().to_string());
    } else if name.eq_ignore_ascii_case("content-encoding") && meta.content_encoding.is_none() {
        meta.content_encoding = Some(value.trim().to_string());
    }
    meta.headers.push(ParsedHeader {
        name: name.to_string(),
        value: value.to_string(),
    });
}

fn sanitize_fs_cached_name(raw: &str) -> Option<String> {
    let trimmed = raw.trim_matches('\0').trim();
    if trimmed.is_empty() || trimmed.contains("..") || trimmed.contains('/') || trimmed.contains('\\') {
        return None;
    }
    Path::new(trimmed).file_name().map(|n| n.to_string_lossy().to_string())
}

pub fn parse_safari_cache_db(db_path: &Path, compute_hashes: bool) -> (Vec<SafariCacheEntry>, Vec<DiagnosticWarning>) {
    let mut warnings = Vec::new();
    let mut entries = Vec::new();

    let db = match ForensicSqlite::open_snapshot(db_path) {
        Ok(d) => d,
        Err(e) => {
            warnings.push(DiagnosticWarning::warn(
                "safari_cache",
                db_path,
                format!("Failed opening Safari Cache.db: {e}"),
            ));
            return (entries, warnings);
        }
    };

    let tables = db.list_tables();
    if !tables.contains("cfurl_cache_response") {
        return (entries, warnings);
    }

    let resp_cols = db.table_columns("cfurl_cache_response");
    let recv_cols = db.table_columns("cfurl_cache_receiver_data");
    let has_blob = tables.contains("cfurl_cache_blob_data");
    let has_recv = tables.contains("cfurl_cache_receiver_data");

    let storage_sel = if resp_cols.contains("storage_policy") {
        "r.storage_policy"
    } else {
        "0"
    };
    let blob_sel = if has_blob { "b.response_object" } else { "NULL" };
    let blob_join = if has_blob {
        "LEFT JOIN cfurl_cache_blob_data b ON r.entry_ID = b.entry_ID"
    } else {
        ""
    };
    let recv_sel = if has_recv { "d.receiver_data" } else { "NULL" };
    let is_fs_sel = if has_recv && recv_cols.contains("isDataOnFS") {
        "d.isDataOnFS"
    } else {
        "0"
    };
    let recv_join = if has_recv {
        "LEFT JOIN cfurl_cache_receiver_data d ON r.entry_ID = d.entry_ID"
    } else {
        ""
    };

    let sql = format!(
        "SELECT r.request_key, r.time_stamp, {storage_sel}, {blob_sel}, {recv_sel}, {is_fs_sel}
         FROM cfurl_cache_response r
         {blob_join}
         {recv_join}"
    );

    let fs_cache_dir = db_path
        .parent()
        .map(|p| p.join("fsCachedData"))
        .unwrap_or_else(|| PathBuf::from("fsCachedData"));

    if let Ok(mut stmt) = db.conn.prepare(&sql)
        && let Ok(mut rows) = stmt.query([])
    {
        while let Ok(Some(row)) = rows.next() {
            let url: String = row.get(0).unwrap_or_default();
            if url.is_empty() {
                continue;
            }
            let timestamp = row.get_ref(1).ok().and_then(parse_safari_timestamp);
            let storage_policy = decode_safari_storage_policy(row.get::<_, i64>(2).unwrap_or(0));

            let mut meta = SafariResponseMeta::default();
            if let Ok(Some(blob)) = row.get::<_, Option<Vec<u8>>>(3)
                && !blob.is_empty()
                && let Ok(plist) = parse_plist(&blob)
            {
                meta = extract_safari_response_meta(&plist);
            }

            let is_fs = row.get::<_, i64>(5).unwrap_or(0) != 0;
            let mut inline_bytes = None;
            let mut fs_cached_path = None;
            let mut cache_file = None;

            if let Ok(recv_ref) = row.get_ref(4) {
                match recv_ref {
                    ValueRef::Blob(b) => {
                        if is_fs {
                            if let Ok(fname_raw) = std::str::from_utf8(b)
                                && let Some(safe) = sanitize_fs_cached_name(fname_raw)
                            {
                                let cand = fs_cache_dir.join(&safe);
                                cache_file = Some(safe);
                                if cand.is_file() {
                                    fs_cached_path = Some(cand);
                                }
                            }
                        } else if !b.is_empty() {
                            inline_bytes = Some(b.to_vec());
                        }
                    }
                    ValueRef::Text(t) => {
                        if is_fs {
                            if let Ok(fname_raw) = std::str::from_utf8(t)
                                && let Some(safe) = sanitize_fs_cached_name(fname_raw)
                            {
                                let cand = fs_cache_dir.join(&safe);
                                cache_file = Some(safe);
                                if cand.is_file() {
                                    fs_cached_path = Some(cand);
                                }
                            }
                        } else if let Ok(fname_raw) = std::str::from_utf8(t)
                            && let Some(safe) = sanitize_fs_cached_name(fname_raw)
                            && fs_cache_dir.join(&safe).is_file()
                        {
                            let cand = fs_cache_dir.join(&safe);
                            cache_file = Some(safe);
                            fs_cached_path = Some(cand);
                        } else if !t.is_empty() {
                            inline_bytes = Some(t.to_vec());
                        }
                    }
                    _ => {}
                }
            }

            let mut entry = SafariCacheEntry {
                url,
                status_code: meta.status_code,
                content_type: meta.content_type,
                content_encoding: meta.content_encoding,
                detected_content_type: None,
                detected_extension: None,
                mime_mismatch: false,
                body_size: 0,
                timestamp,
                storage_policy,
                cache_file,
                headers: meta.headers,
                payload_sha256: None,
                inline_bytes,
                fs_cached_path,
            };

            let dec = entry.read_decompressed_payload();
            entry.body_size = dec.len();
            if !dec.is_empty() {
                let det = detect_content(&dec, entry.content_type.as_deref(), Some(&entry.url), None);
                entry.detected_content_type = det.mime;
                entry.detected_extension = det.extension;
                entry.mime_mismatch = det.mime_mismatch;
                if compute_hashes {
                    entry.payload_sha256 = Some(hex_lower(&Sha256::digest(&dec)));
                }
            }

            entries.push(entry);
        }
    }

    entries.sort_by(|a, b| b.timestamp.cmp(&a.timestamp).then_with(|| a.url.cmp(&b.url)));
    (entries, warnings)
}

pub fn scan_safari_cache(
    target: Option<&Path>,
    compute_hashes: bool,
) -> (Vec<SafariCacheEntry>, Vec<DiagnosticWarning>) {
    let mut warnings = Vec::new();
    let mut db_paths = Vec::new();

    if let Some(p) = target {
        if p.is_file() {
            db_paths.push(p.to_path_buf());
        } else if p.is_dir() {
            for cand in [p.join("Cache.db"), p.join("com.apple.Safari").join("Cache.db")] {
                if cand.is_file() && !db_paths.contains(&cand) {
                    db_paths.push(cand);
                }
            }
            if db_paths.is_empty() {
                for t in resolve_unified_targets(&[p.to_path_buf()]) {
                    if t.browser == UnifiedBrowserKind::Safari {
                        let cand = t.profile_dir.join("Cache.db");
                        if cand.is_file() && !db_paths.contains(&cand) {
                            db_paths.push(cand);
                        }
                        for c in t.cache_dirs {
                            let cand2 = c.join("Cache.db");
                            if cand2.is_file() && !db_paths.contains(&cand2) {
                                db_paths.push(cand2);
                            }
                        }
                    }
                }
            }
        }
    } else {
        for prof in discover_safari_profiles() {
            for c in prof.cache_dirs {
                let cand = c.join("Cache.db");
                if cand.is_file() && !db_paths.contains(&cand) {
                    db_paths.push(cand);
                }
            }
        }
    }

    let mut out = Vec::new();
    for dbp in db_paths {
        let (mut items, mut w) = parse_safari_cache_db(&dbp, compute_hashes);
        out.append(&mut items);
        warnings.append(&mut w);
    }
    (out, warnings)
}

pub struct SafariCacheTableProvider {
    target: Option<PathBuf>,
}

impl SafariCacheTableProvider {
    pub fn new(target: Option<PathBuf>) -> Self {
        Self { target }
    }
}

impl TableProvider for SafariCacheTableProvider {
    fn tool_id(&self) -> &'static str {
        "chrome2rust_safari_cache"
    }

    fn description(&self) -> &'static str {
        "Inspect Apple Safari Cache.db & fsCachedData entries (SafariCacheView equivalent)."
    }

    fn schema(&self) -> TableSchema {
        TableSchema::new(
            self.tool_id(),
            "Safari Cache.db Entries",
            vec![
                ColumnDef::new("url", "URL", ColumnType::Text).with_width_hint(320),
                ColumnDef::new("status_code", "Status", ColumnType::Uint).with_width_hint(70),
                ColumnDef::new("content_type", "Content Type", ColumnType::Text).with_width_hint(140),
                ColumnDef::new("body_size", "Body Size", ColumnType::BytesSize).with_width_hint(90),
                ColumnDef::new("timestamp", "Timestamp", ColumnType::Timestamp).with_width_hint(160),
                ColumnDef::new("storage_policy", "Storage Policy", ColumnType::Text).with_width_hint(130),
                ColumnDef::new("cache_file", "Cache File", ColumnType::Text).with_width_hint(160),
                ColumnDef::new("sha256", "SHA-256", ColumnType::Text).with_width_hint(180),
            ],
        )
        .with_default_sort(4, SortDirection::Desc)
    }

    fn query(&self, req: &TableQuery) -> Result<TableData, TableError> {
        let (entries, _) = scan_safari_cache(self.target.as_deref(), true);
        let rows: Vec<Row> = entries
            .into_iter()
            .enumerate()
            .map(|(idx, e)| {
                let raw = e.read_decompressed_payload();
                let ct = e
                    .content_type
                    .clone()
                    .or(e.detected_content_type.clone())
                    .unwrap_or_default();
                let mut row = Row::new(
                    idx as u64 + 1,
                    vec![
                        CellValue::Text(e.url.clone()),
                        e.status_code
                            .map(|s| CellValue::Uint(s as u64))
                            .unwrap_or(CellValue::Null),
                        CellValue::Text(ct),
                        CellValue::Bytes(e.body_size as u64),
                        e.timestamp.map(CellValue::Timestamp).unwrap_or(CellValue::Null),
                        CellValue::Text(e.storage_policy.clone()),
                        e.cache_file.clone().map(CellValue::Text).unwrap_or(CellValue::Null),
                        e.payload_sha256.clone().map(CellValue::Text).unwrap_or(CellValue::Null),
                    ],
                )
                .with_detail_json(serde_json::to_value(&e).unwrap_or_default());
                if !raw.is_empty() {
                    row = row.with_raw_bytes(raw[..raw.len().min(65536)].to_vec());
                }
                row
            })
            .collect();
        apply_query(&self.schema(), &rows, req)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrome2rust_core::plist::encode_bplist00;
    use rusqlite::Connection;
    use std::collections::BTreeMap;
    use tempfile::TempDir;

    #[test]
    fn test_safari_cache_db_nskeyed_and_fscacheddata() {
        let dir = TempDir::new().unwrap();
        let fs_dir = dir.path().join("fsCachedData");
        std::fs::create_dir_all(&fs_dir).unwrap();
        let uuid = "12345678-ABCD-4000-8000-000000000001";
        let payload = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR";
        std::fs::write(fs_dir.join(uuid), payload).unwrap();

        let mut hdrs = BTreeMap::new();
        hdrs.insert("Content-Type".into(), PlistValue::String("image/png".into()));
        let mut resp_obj = BTreeMap::new();
        resp_obj.insert("statusCode".into(), PlistValue::Integer(200));
        resp_obj.insert("allHeaderFields".into(), PlistValue::Uid(2));
        let mut arch = BTreeMap::new();
        arch.insert("$archiver".into(), PlistValue::String("NSKeyedArchiver".into()));
        arch.insert("$top".into(), PlistValue::Uid(1));
        arch.insert(
            "$objects".into(),
            PlistValue::Array(vec![
                PlistValue::String("$null".into()),
                PlistValue::Dict(resp_obj),
                PlistValue::Dict(hdrs),
            ]),
        );
        let bplist = encode_bplist00(&PlistValue::Dict(arch));

        let db_path = dir.path().join("Cache.db");
        let conn = Connection::open(&db_path).unwrap();
        conn.execute_batch(
            "CREATE TABLE cfurl_cache_response(entry_ID INTEGER PRIMARY KEY, request_key TEXT, time_stamp REAL, storage_policy INTEGER);
             CREATE TABLE cfurl_cache_blob_data(entry_ID INTEGER PRIMARY KEY, response_object BLOB);
             CREATE TABLE cfurl_cache_receiver_data(entry_ID INTEGER PRIMARY KEY, isDataOnFS INTEGER, receiver_data BLOB);",
        )
        .unwrap();
        conn.execute(
            "INSERT INTO cfurl_cache_response VALUES (1, 'https://apple.example.test/logo.png', 816393600.0, 0)",
            [],
        )
        .unwrap();
        conn.execute("INSERT INTO cfurl_cache_blob_data VALUES (1, ?1)", [&bplist])
            .unwrap();
        conn.execute(
            "INSERT INTO cfurl_cache_receiver_data VALUES (1, 1, ?1)",
            [uuid.as_bytes()],
        )
        .unwrap();

        let provider = SafariCacheTableProvider::new(Some(dir.path().to_path_buf()));
        let data = provider.query(&TableQuery::default()).unwrap();
        assert_eq!(data.total_rows, 1);
        assert_eq!(
            data.rows[0].cells[0],
            CellValue::Text("https://apple.example.test/logo.png".into())
        );
        assert_eq!(data.rows[0].cells[1], CellValue::Uint(200));
        assert_eq!(data.rows[0].cells[2], CellValue::Text("image/png".into()));
        assert_eq!(data.rows[0].cells[6], CellValue::Text(uuid.into()));
        assert_eq!(data.rows[0].raw_bytes.as_deref(), Some(payload.as_slice()));
    }

    #[test]
    fn test_safari_cache_db_text_inline_fallback_when_not_on_fs() {
        let dir = TempDir::new().unwrap();
        let db_path = dir.path().join("Cache.db");
        let conn = Connection::open(&db_path).unwrap();
        conn.execute_batch(
            "CREATE TABLE cfurl_cache_response(entry_ID INTEGER PRIMARY KEY, request_key TEXT, time_stamp REAL, storage_policy INTEGER);
             CREATE TABLE cfurl_cache_receiver_data(entry_ID INTEGER PRIMARY KEY, isDataOnFS INTEGER, receiver_data BLOB);",
        )
        .unwrap();
        conn.execute(
            "INSERT INTO cfurl_cache_response VALUES (1, 'https://apple.example.test/inline.html', 816393600.0, 0)",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO cfurl_cache_receiver_data VALUES (1, 0, '<html><body>Inline Text</body></html>')",
            [],
        )
        .unwrap();

        let (entries, _) = parse_safari_cache_db(&db_path, false);
        assert_eq!(entries.len(), 1);
        assert!(entries[0].cache_file.is_none());
        assert_eq!(
            entries[0].read_decompressed_payload(),
            b"<html><body>Inline Text</body></html>"
        );
    }
}
