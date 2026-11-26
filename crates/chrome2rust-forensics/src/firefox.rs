use crate::extensions::compute_extension_risks;
use chrome2rust_core::discovery::{UnifiedBrowserKind, discover_firefox_profiles, resolve_unified_targets};
use chrome2rust_core::error::DiagnosticWarning;
use chrome2rust_core::mozlz4::decompress_mozlz4;
use chrome2rust_core::sqlite_util::ForensicSqlite;
use chrome2rust_core::time::{prtime_us_to_datetime, unix_ms_to_datetime, unix_secs_to_datetime};
use chrono::{DateTime, Utc};
use guap_table::{
    CellValue, ColumnDef, ColumnType, Row, SortDirection, TableData, TableError, TableProvider, TableQuery,
    TableSchema, apply_query,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};

const MAX_BOOKMARK_DEPTH: usize = 64;

fn resolve_firefox_profile_dirs(target: Option<&Path>) -> Vec<(String, PathBuf)> {
    if let Some(p) = target {
        let resolved = resolve_unified_targets(&[p.to_path_buf()]);
        let fx: Vec<_> = resolved
            .into_iter()
            .filter(|t| t.browser == UnifiedBrowserKind::Firefox)
            .map(|t| (t.profile_name, t.profile_dir))
            .collect();
        if !fx.is_empty() {
            return fx;
        }
        let pname = p
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "Firefox".to_string());
        return vec![(pname, p.to_path_buf())];
    }
    discover_firefox_profiles()
        .into_iter()
        .map(|t| (t.profile_name, t.profile_dir))
        .collect()
}

// =========================================================================
// 1. fx history (`places.sqlite`)
// =========================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirefoxHistoryRecord {
    pub url: String,
    pub title: String,
    pub visit_date: Option<DateTime<Utc>>,
    pub visit_count: i64,
    pub visit_type: String,
    pub referrer: String,
    pub frecency: i64,
}

fn decode_fx_visit_type(vt: i64) -> &'static str {
    match vt {
        1 => "LINK",
        2 => "TYPED",
        3 => "BOOKMARK",
        4 => "EMBED",
        5 => "REDIRECT_PERMANENT",
        6 => "REDIRECT_TEMPORARY",
        7 => "DOWNLOAD",
        8 => "FRAMED_LINK",
        9 => "RELOAD",
        _ => "OTHER",
    }
}

pub fn parse_firefox_history(profile_dir: &Path, warnings: &mut Vec<DiagnosticWarning>) -> Vec<FirefoxHistoryRecord> {
    let db_path = profile_dir.join("places.sqlite");
    if !db_path.is_file() {
        return Vec::new();
    }
    let db = match ForensicSqlite::open_snapshot(&db_path) {
        Ok(d) => d,
        Err(e) => {
            warnings.push(DiagnosticWarning::warn(
                "fx_history",
                &db_path,
                format!("Failed opening places.sqlite: {e}"),
            ));
            return Vec::new();
        }
    };

    let tables = db.list_tables();
    let mut out = Vec::new();

    if tables.contains("moz_places") && tables.contains("moz_historyvisits") {
        type RawVisitRow = (i64, String, String, i64, i64, i64, i64, i64);
        let mut visit_urls: HashMap<i64, String> = HashMap::new();
        let mut raw_rows: Vec<RawVisitRow> = Vec::new();

        if let Ok(mut stmt) = db.conn.prepare(
            "SELECT v.id, p.url, COALESCE(p.title, ''), v.visit_date, p.visit_count, v.visit_type, v.from_visit, COALESCE(p.frecency, 0)
             FROM moz_historyvisits v
             JOIN moz_places p ON v.place_id = p.id
             ORDER BY v.visit_date DESC",
        ) && let Ok(rows) = stmt.query_map([], |r| {
            Ok((
                r.get::<_, i64>(0).unwrap_or(0),
                r.get::<_, String>(1).unwrap_or_default(),
                r.get::<_, String>(2).unwrap_or_default(),
                r.get::<_, i64>(3).unwrap_or(0),
                r.get::<_, i64>(4).unwrap_or(0),
                r.get::<_, i64>(5).unwrap_or(0),
                r.get::<_, i64>(6).unwrap_or(0),
                r.get::<_, i64>(7).unwrap_or(0),
            ))
        }) {
            for row in rows.flatten() {
                visit_urls.insert(row.0, row.1.clone());
                raw_rows.push(row);
            }
        }

        for (_vid, url, title, vdate, vcount, vtype, from_visit, frecency) in raw_rows {
            let referrer = visit_urls.get(&from_visit).cloned().unwrap_or_default();
            out.push(FirefoxHistoryRecord {
                url,
                title,
                visit_date: prtime_us_to_datetime(vdate),
                visit_count: vcount,
                visit_type: decode_fx_visit_type(vtype).to_string(),
                referrer,
                frecency,
            });
        }
    }

    // Fallback: include moz_places entries if moz_historyvisits had no rows
    if out.is_empty()
        && tables.contains("moz_places")
        && let Ok(mut stmt) = db.conn.prepare(
            "SELECT url, COALESCE(title, ''), COALESCE(last_visit_date, 0), visit_count, COALESCE(frecency, 0)
             FROM moz_places WHERE visit_count > 0 OR last_visit_date IS NOT NULL ORDER BY last_visit_date DESC",
        )
        && let Ok(rows) = stmt.query_map([], |r| {
            Ok(FirefoxHistoryRecord {
                url: r.get(0).unwrap_or_default(),
                title: r.get(1).unwrap_or_default(),
                visit_date: prtime_us_to_datetime(r.get::<_, i64>(2).unwrap_or(0)),
                visit_count: r.get(3).unwrap_or(0),
                visit_type: "PLACE".to_string(),
                referrer: String::new(),
                frecency: r.get(4).unwrap_or(0),
            })
        })
    {
        out.extend(rows.flatten());
    }

    out
}

pub struct FirefoxHistoryTableProvider {
    target: Option<PathBuf>,
}

impl FirefoxHistoryTableProvider {
    pub fn new(target: Option<PathBuf>) -> Self {
        Self { target }
    }
}

impl TableProvider for FirefoxHistoryTableProvider {
    fn tool_id(&self) -> &'static str {
        "chrome2rust_fx_history"
    }

    fn description(&self) -> &'static str {
        "Inspect Mozilla Firefox browsing history from places.sqlite (MZHistoryView equivalent)."
    }

    fn schema(&self) -> TableSchema {
        TableSchema::new(
            self.tool_id(),
            "Firefox History (places.sqlite)",
            vec![
                ColumnDef::new("url", "URL", ColumnType::Text).with_width_hint(300),
                ColumnDef::new("title", "Title", ColumnType::Text).with_width_hint(200),
                ColumnDef::new("visit_date", "Visit Date", ColumnType::Timestamp).with_width_hint(160),
                ColumnDef::new("visit_count", "Visit Count", ColumnType::Int).with_width_hint(85),
                ColumnDef::new("visit_type", "Visit Type", ColumnType::Text).with_width_hint(120),
                ColumnDef::new("referrer", "Referrer", ColumnType::Text).with_width_hint(220),
                ColumnDef::new("frecency", "Frecency", ColumnType::Int).with_width_hint(80),
            ],
        )
        .with_default_sort(2, SortDirection::Desc)
    }

    fn query(&self, req: &TableQuery) -> Result<TableData, TableError> {
        let mut warnings = Vec::new();
        let mut rows = Vec::new();
        for (_pname, pdir) in resolve_firefox_profile_dirs(self.target.as_deref()) {
            for rec in parse_firefox_history(&pdir, &mut warnings) {
                let id = rows.len() as u64 + 1;
                rows.push(
                    Row::new(
                        id,
                        vec![
                            CellValue::Text(rec.url.clone()),
                            CellValue::Text(rec.title.clone()),
                            rec.visit_date.map(CellValue::Timestamp).unwrap_or(CellValue::Null),
                            CellValue::Int(rec.visit_count),
                            CellValue::Text(rec.visit_type.clone()),
                            CellValue::Text(rec.referrer.clone()),
                            CellValue::Int(rec.frecency),
                        ],
                    )
                    .with_detail_json(serde_json::to_value(&rec).unwrap_or_default()),
                );
            }
        }
        apply_query(&self.schema(), &rows, req)
    }
}

// =========================================================================
// 2. fx cookies (`cookies.sqlite` — STRICTLY METADATA-ONLY, NO `value`!)
// =========================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirefoxCookieMetadataRecord {
    pub host: String,
    pub name: String,
    pub path: String,
    pub created: Option<DateTime<Utc>>,
    pub last_accessed: Option<DateTime<Utc>>,
    pub expiry: Option<DateTime<Utc>>,
    pub secure: bool,
    pub http_only: bool,
    pub same_site: String,
}

fn decode_same_site(val: i64) -> &'static str {
    match val {
        1 => "Lax",
        2 => "Strict",
        _ => "None",
    }
}

/// Parses Mozilla Firefox `cookies.sqlite` (`moz_cookies`) metadata ONLY.
/// Explicitly omits cookie `value` from both SQL SELECT and Rust output (R4 compliance).
pub fn parse_firefox_cookies_metadata(
    profile_dir: &Path,
    warnings: &mut Vec<DiagnosticWarning>,
) -> Vec<FirefoxCookieMetadataRecord> {
    let db_path = profile_dir.join("cookies.sqlite");
    if !db_path.is_file() {
        return Vec::new();
    }
    let db = match ForensicSqlite::open_snapshot(&db_path) {
        Ok(d) => d,
        Err(e) => {
            warnings.push(DiagnosticWarning::warn(
                "fx_cookies",
                &db_path,
                format!("Failed opening cookies.sqlite: {e}"),
            ));
            return Vec::new();
        }
    };

    let tables = db.list_tables();
    if !tables.contains("moz_cookies") {
        return Vec::new();
    }

    let cols = db.table_columns("moz_cookies");
    let same_site_col = if cols.contains("sameSite") { "sameSite" } else { "0" };
    let created_col = if cols.contains("creationTime") {
        "creationTime"
    } else {
        "0"
    };
    let last_col = if cols.contains("lastAccessed") {
        "lastAccessed"
    } else {
        "0"
    };
    let secure_col = if cols.contains("isSecure") { "isSecure" } else { "0" };
    let http_col = if cols.contains("isHttpOnly") { "isHttpOnly" } else { "0" };

    // R4 INVARIANT: `value` column is intentionally NEVER selected.
    let sql = format!(
        "SELECT host, name, path, {created_col}, {last_col}, expiry, {secure_col}, {http_col}, {same_site_col}
         FROM moz_cookies ORDER BY {last_col} DESC"
    );

    let mut out = Vec::new();
    if let Ok(mut stmt) = db.conn.prepare(&sql)
        && let Ok(rows) = stmt.query_map([], |r| {
            Ok(FirefoxCookieMetadataRecord {
                host: r.get(0).unwrap_or_default(),
                name: r.get(1).unwrap_or_default(),
                path: r.get(2).unwrap_or_default(),
                created: prtime_us_to_datetime(r.get::<_, i64>(3).unwrap_or(0)),
                last_accessed: prtime_us_to_datetime(r.get::<_, i64>(4).unwrap_or(0)),
                expiry: unix_secs_to_datetime(r.get::<_, i64>(5).unwrap_or(0)),
                secure: r.get::<_, i64>(6).unwrap_or(0) != 0,
                http_only: r.get::<_, i64>(7).unwrap_or(0) != 0,
                same_site: decode_same_site(r.get::<_, i64>(8).unwrap_or(0)).to_string(),
            })
        })
    {
        out.extend(rows.flatten());
    }
    out
}

pub struct FirefoxCookiesTableProvider {
    target: Option<PathBuf>,
}

impl FirefoxCookiesTableProvider {
    pub fn new(target: Option<PathBuf>) -> Self {
        Self { target }
    }
}

impl TableProvider for FirefoxCookiesTableProvider {
    fn tool_id(&self) -> &'static str {
        "chrome2rust_fx_cookies"
    }

    fn description(&self) -> &'static str {
        "Inspect Mozilla Firefox cookies.sqlite metadata only (host, name, path, flags, expiry; cookie values omitted) (MZCookiesView equivalent)."
    }

    fn schema(&self) -> TableSchema {
        TableSchema::new(
            self.tool_id(),
            "Firefox Cookies Metadata (cookies.sqlite)",
            vec![
                ColumnDef::new("host", "Host", ColumnType::Text).with_width_hint(180),
                ColumnDef::new("name", "Name", ColumnType::Text).with_width_hint(150),
                ColumnDef::new("path", "Path", ColumnType::Text).with_width_hint(100),
                ColumnDef::new("created", "Created", ColumnType::Timestamp).with_width_hint(160),
                ColumnDef::new("last_accessed", "Last Accessed", ColumnType::Timestamp).with_width_hint(160),
                ColumnDef::new("expiry", "Expiry", ColumnType::Timestamp).with_width_hint(160),
                ColumnDef::new("secure", "Secure", ColumnType::Bool).with_width_hint(70),
                ColumnDef::new("http_only", "HttpOnly", ColumnType::Bool).with_width_hint(80),
                ColumnDef::new("same_site", "SameSite", ColumnType::Text).with_width_hint(80),
            ],
        )
        .with_default_sort(4, SortDirection::Desc)
    }

    fn query(&self, req: &TableQuery) -> Result<TableData, TableError> {
        let mut warnings = Vec::new();
        let mut rows = Vec::new();
        for (_pname, pdir) in resolve_firefox_profile_dirs(self.target.as_deref()) {
            for rec in parse_firefox_cookies_metadata(&pdir, &mut warnings) {
                let id = rows.len() as u64 + 1;
                rows.push(
                    Row::new(
                        id,
                        vec![
                            CellValue::Text(rec.host.clone()),
                            CellValue::Text(rec.name.clone()),
                            CellValue::Text(rec.path.clone()),
                            rec.created.map(CellValue::Timestamp).unwrap_or(CellValue::Null),
                            rec.last_accessed.map(CellValue::Timestamp).unwrap_or(CellValue::Null),
                            rec.expiry.map(CellValue::Timestamp).unwrap_or(CellValue::Null),
                            CellValue::Bool(rec.secure),
                            CellValue::Bool(rec.http_only),
                            CellValue::Text(rec.same_site.clone()),
                        ],
                    )
                    .with_detail_json(serde_json::to_value(&rec).unwrap_or_default()),
                );
            }
        }
        apply_query(&self.schema(), &rows, req)
    }
}

// =========================================================================
// 3. fx bookmarks (`places.sqlite` + `bookmarkbackups/*.jsonlz4`)
// =========================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirefoxBookmarkRecord {
    pub title: String,
    pub url: String,
    pub folder_path: String,
    pub date_added: Option<DateTime<Utc>>,
    pub last_modified: Option<DateTime<Utc>>,
    pub guid: String,
    pub source_artifact: String,
}

pub fn parse_firefox_bookmarks(
    profile_dir: &Path,
    warnings: &mut Vec<DiagnosticWarning>,
) -> Vec<FirefoxBookmarkRecord> {
    let mut out = Vec::new();

    let db_path = profile_dir.join("places.sqlite");
    if db_path.is_file() {
        match ForensicSqlite::open_snapshot(&db_path) {
            Ok(db) => {
                let tables = db.list_tables();
                if tables.contains("moz_bookmarks") && tables.contains("moz_places") {
                    type BookmarkNode = (i64, i64, Option<i64>, String, i64, i64, String, Option<String>);
                    let mut nodes: HashMap<i64, BookmarkNode> = HashMap::new();
                    if let Ok(mut stmt) = db.conn.prepare(
                        "SELECT b.id, b.type, b.fk, b.parent, COALESCE(b.title, ''), COALESCE(b.dateAdded, 0), COALESCE(b.lastModified, 0), COALESCE(b.guid, ''), p.url
                         FROM moz_bookmarks b
                         LEFT JOIN moz_places p ON b.fk = p.id",
                    ) && let Ok(rows) = stmt.query_map([], |r| {
                        Ok((
                            r.get::<_, i64>(0).unwrap_or(0),
                            r.get::<_, i64>(1).unwrap_or(0),
                            r.get::<_, Option<i64>>(2).unwrap_or(None),
                            r.get::<_, i64>(3).unwrap_or(0),
                            r.get::<_, String>(4).unwrap_or_default(),
                            r.get::<_, i64>(5).unwrap_or(0),
                            r.get::<_, i64>(6).unwrap_or(0),
                            r.get::<_, String>(7).unwrap_or_default(),
                            r.get::<_, Option<String>>(8).unwrap_or(None),
                        ))
                    }) {
                        for row in rows.flatten() {
                            nodes.insert(row.0, (row.1, row.3, row.2, row.4, row.5, row.6, row.7, row.8));
                        }
                    }

                    for (&_id, (btype, parent, _fk, title, date_added, last_mod, guid, url_opt)) in &nodes {
                        if *btype == 1
                            && let Some(url) = url_opt
                            && !url.is_empty()
                        {
                            let mut chain = Vec::new();
                            let mut cur = *parent;
                            let mut seen = HashSet::new();
                            while cur > 0 && seen.insert(cur) && chain.len() < MAX_BOOKMARK_DEPTH {
                                if let Some((_, next_parent, _, ptitle, _, _, _, _)) = nodes.get(&cur) {
                                    if !ptitle.is_empty() {
                                        chain.push(ptitle.clone());
                                    }
                                    cur = *next_parent;
                                } else {
                                    break;
                                }
                            }
                            chain.reverse();
                            out.push(FirefoxBookmarkRecord {
                                title: title.clone(),
                                url: url.clone(),
                                folder_path: chain.join(" / "),
                                date_added: prtime_us_to_datetime(*date_added),
                                last_modified: prtime_us_to_datetime(*last_mod),
                                guid: guid.clone(),
                                source_artifact: "places.sqlite".to_string(),
                            });
                        }
                    }
                }
            }
            Err(e) => warnings.push(DiagnosticWarning::warn(
                "fx_bookmarks",
                &db_path,
                format!("Failed opening places.sqlite: {e}"),
            )),
        }
    }

    // Fallback / supplement from bookmarkbackups/*.jsonlz4 if places.sqlite had none
    if out.is_empty() {
        let backups_dir = profile_dir.join("bookmarkbackups");
        if backups_dir.is_dir()
            && let Ok(rd) = std::fs::read_dir(&backups_dir)
        {
            let mut candidates: Vec<PathBuf> = rd
                .flatten()
                .map(|e| e.path())
                .filter(|p| {
                    p.is_file()
                        && p.extension()
                            .is_some_and(|e| e.to_string_lossy().eq_ignore_ascii_case("jsonlz4"))
                })
                .collect();
            candidates.sort();
            if let Some(latest) = candidates.pop() {
                out.extend(parse_firefox_jsonlz4_bookmarks(&latest, warnings));
            }
        }
    }

    out
}

pub fn parse_firefox_jsonlz4_bookmarks(
    path: &Path,
    warnings: &mut Vec<DiagnosticWarning>,
) -> Vec<FirefoxBookmarkRecord> {
    let raw = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) => {
            warnings.push(DiagnosticWarning::warn(
                "fx_bookmarks",
                path,
                format!("Read error: {e}"),
            ));
            return Vec::new();
        }
    };
    let json_bytes = if raw.starts_with(b"mozLz40\0") {
        match decompress_mozlz4(&raw) {
            Ok(d) => d,
            Err(e) => {
                warnings.push(DiagnosticWarning::warn(
                    "fx_bookmarks",
                    path,
                    format!("mozLz40 decompress error: {e}"),
                ));
                return Vec::new();
            }
        }
    } else {
        raw
    };
    let val: serde_json::Value = match serde_json::from_slice(&json_bytes) {
        Ok(v) => v,
        Err(e) => {
            warnings.push(DiagnosticWarning::warn(
                "fx_bookmarks",
                path,
                format!("JSON parse error: {e}"),
            ));
            return Vec::new();
        }
    };
    let mut out = Vec::new();
    let src_name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "bookmarkbackups".to_string());
    walk_fx_json_bookmarks(&val, &[], 0, &src_name, &mut out);
    out
}

fn walk_fx_json_bookmarks(
    node: &serde_json::Value,
    folder_stack: &[String],
    depth: usize,
    source_artifact: &str,
    out: &mut Vec<FirefoxBookmarkRecord>,
) {
    if depth > MAX_BOOKMARK_DEPTH {
        return;
    }
    let Some(obj) = node.as_object() else {
        return;
    };
    let title = obj.get("title").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let type_code = obj.get("typeCode").and_then(|v| v.as_i64());
    let type_str = obj.get("type").and_then(|v| v.as_str()).unwrap_or("");
    let is_bookmark = type_code == Some(1) || type_str == "text/x-moz-place";

    if is_bookmark && let Some(url) = obj.get("uri").and_then(|v| v.as_str()) {
        out.push(FirefoxBookmarkRecord {
            title: title.clone(),
            url: url.to_string(),
            folder_path: folder_stack.join(" / "),
            date_added: obj
                .get("dateAdded")
                .and_then(|v| v.as_i64())
                .and_then(prtime_us_to_datetime),
            last_modified: obj
                .get("lastModified")
                .and_then(|v| v.as_i64())
                .and_then(prtime_us_to_datetime),
            guid: obj.get("guid").and_then(|v| v.as_str()).unwrap_or("").to_string(),
            source_artifact: source_artifact.to_string(),
        });
    }

    if let Some(children) = obj.get("children").and_then(|v| v.as_array()) {
        let mut next_stack = folder_stack.to_vec();
        if !title.is_empty() && !is_bookmark {
            next_stack.push(title);
        }
        for child in children {
            walk_fx_json_bookmarks(child, &next_stack, depth + 1, source_artifact, out);
        }
    }
}

pub struct FirefoxBookmarksTableProvider {
    target: Option<PathBuf>,
}

impl FirefoxBookmarksTableProvider {
    pub fn new(target: Option<PathBuf>) -> Self {
        Self { target }
    }
}

impl TableProvider for FirefoxBookmarksTableProvider {
    fn tool_id(&self) -> &'static str {
        "chrome2rust_fx_bookmarks"
    }

    fn description(&self) -> &'static str {
        "Inspect Mozilla Firefox bookmarks from places.sqlite and bookmarkbackups/*.jsonlz4."
    }

    fn schema(&self) -> TableSchema {
        TableSchema::new(
            self.tool_id(),
            "Firefox Bookmarks",
            vec![
                ColumnDef::new("title", "Title", ColumnType::Text).with_width_hint(180),
                ColumnDef::new("url", "URL", ColumnType::Text).with_width_hint(300),
                ColumnDef::new("folder_path", "Folder Path", ColumnType::Text).with_width_hint(180),
                ColumnDef::new("date_added", "Date Added", ColumnType::Timestamp).with_width_hint(160),
                ColumnDef::new("last_modified", "Last Modified", ColumnType::Timestamp).with_width_hint(160),
                ColumnDef::new("guid", "GUID", ColumnType::Text).with_width_hint(110),
                ColumnDef::new("source_artifact", "Source", ColumnType::Text).with_width_hint(140),
            ],
        )
        .with_default_sort(3, SortDirection::Desc)
    }

    fn query(&self, req: &TableQuery) -> Result<TableData, TableError> {
        let mut warnings = Vec::new();
        let mut rows = Vec::new();
        for (_pname, pdir) in resolve_firefox_profile_dirs(self.target.as_deref()) {
            for rec in parse_firefox_bookmarks(&pdir, &mut warnings) {
                let id = rows.len() as u64 + 1;
                rows.push(
                    Row::new(
                        id,
                        vec![
                            CellValue::Text(rec.title.clone()),
                            CellValue::Text(rec.url.clone()),
                            CellValue::Text(rec.folder_path.clone()),
                            rec.date_added.map(CellValue::Timestamp).unwrap_or(CellValue::Null),
                            rec.last_modified.map(CellValue::Timestamp).unwrap_or(CellValue::Null),
                            CellValue::Text(rec.guid.clone()),
                            CellValue::Text(rec.source_artifact.clone()),
                        ],
                    )
                    .with_detail_json(serde_json::to_value(&rec).unwrap_or_default()),
                );
            }
        }
        apply_query(&self.schema(), &rows, req)
    }
}

// =========================================================================
// 4. fx downloads (`places.sqlite` `moz_annos`)
// =========================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirefoxDownloadRecord {
    pub filename: String,
    pub source_url: String,
    pub target_path: String,
    pub start_time: Option<DateTime<Utc>>,
    pub end_time: Option<DateTime<Utc>>,
    pub bytes: u64,
    pub state: String,
    pub mime_type: String,
}

fn decode_fx_download_state(state: i64) -> &'static str {
    match state {
        0 => "IN_PROGRESS",
        1 => "COMPLETE",
        2 => "FAILED",
        3 => "CANCELLED",
        4 => "PAUSED",
        5 => "BLOCKED_PARENTAL",
        6 => "DIRTY",
        7 => "BLOCKED_CONTENT",
        _ => "UNKNOWN",
    }
}

fn file_uri_to_path(uri: &str) -> String {
    if let Ok(parsed) = url::Url::parse(uri)
        && parsed.scheme() == "file"
    {
        return parsed.path().to_string();
    }
    uri.trim_start_matches("file:///").to_string()
}

pub fn parse_firefox_downloads(
    profile_dir: &Path,
    warnings: &mut Vec<DiagnosticWarning>,
) -> Vec<FirefoxDownloadRecord> {
    let db_path = profile_dir.join("places.sqlite");
    if !db_path.is_file() {
        return Vec::new();
    }
    let db = match ForensicSqlite::open_snapshot(&db_path) {
        Ok(d) => d,
        Err(e) => {
            warnings.push(DiagnosticWarning::warn(
                "fx_downloads",
                &db_path,
                format!("Failed opening places.sqlite: {e}"),
            ));
            return Vec::new();
        }
    };

    let tables = db.list_tables();
    if !tables.contains("moz_annos") || !tables.contains("moz_anno_attributes") || !tables.contains("moz_places") {
        return Vec::new();
    }

    #[derive(Default)]
    struct RawDl {
        url: String,
        dest_uri: String,
        meta_json: String,
        date_added: i64,
    }

    let mut by_place: BTreeMap<i64, RawDl> = BTreeMap::new();
    if let Ok(mut stmt) = db.conn.prepare(
        "SELECT a.place_id, p.url, attr.name, COALESCE(a.content, ''), COALESCE(a.dateAdded, 0)
         FROM moz_annos a
         JOIN moz_anno_attributes attr ON a.anno_attribute_id = attr.id
         JOIN moz_places p ON a.place_id = p.id
         WHERE attr.name IN ('downloads/destinationFileURI', 'downloads/metaData')",
    ) && let Ok(rows) = stmt.query_map([], |r| {
        Ok((
            r.get::<_, i64>(0).unwrap_or(0),
            r.get::<_, String>(1).unwrap_or_default(),
            r.get::<_, String>(2).unwrap_or_default(),
            r.get::<_, String>(3).unwrap_or_default(),
            r.get::<_, i64>(4).unwrap_or(0),
        ))
    }) {
        for (pid, url, attr_name, content, date_added) in rows.flatten() {
            let entry = by_place.entry(pid).or_default();
            entry.url = url;
            if entry.date_added == 0 || (date_added > 0 && date_added < entry.date_added) {
                entry.date_added = date_added;
            }
            if attr_name == "downloads/destinationFileURI" {
                entry.dest_uri = content;
            } else if attr_name == "downloads/metaData" {
                entry.meta_json = content;
            }
        }
    }

    let mut out = Vec::new();
    for raw in by_place.into_values() {
        let meta: serde_json::Value = serde_json::from_str(&raw.meta_json).unwrap_or(serde_json::Value::Null);
        let target_path = file_uri_to_path(&raw.dest_uri);
        let filename = Path::new(&target_path)
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| {
                raw.url
                    .rsplit('/')
                    .next()
                    .unwrap_or("download")
                    .split('?')
                    .next()
                    .unwrap_or("download")
                    .to_string()
            });
        let state_code = meta.get("state").and_then(|v| v.as_i64()).unwrap_or(-1);
        let bytes = meta.get("fileSize").and_then(|v| v.as_u64()).unwrap_or(0);
        let end_time = meta
            .get("endTime")
            .and_then(|v| v.as_i64())
            .and_then(unix_ms_to_datetime);
        let mime_type = meta
            .get("contentType")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        out.push(FirefoxDownloadRecord {
            filename,
            source_url: raw.url,
            target_path,
            start_time: prtime_us_to_datetime(raw.date_added),
            end_time,
            bytes,
            state: decode_fx_download_state(state_code).to_string(),
            mime_type,
        });
    }

    out.sort_by_key(|a| std::cmp::Reverse(a.start_time));
    out
}

pub struct FirefoxDownloadsTableProvider {
    target: Option<PathBuf>,
}

impl FirefoxDownloadsTableProvider {
    pub fn new(target: Option<PathBuf>) -> Self {
        Self { target }
    }
}

impl TableProvider for FirefoxDownloadsTableProvider {
    fn tool_id(&self) -> &'static str {
        "chrome2rust_fx_downloads"
    }

    fn description(&self) -> &'static str {
        "Inspect Mozilla Firefox download history from places.sqlite moz_annos."
    }

    fn schema(&self) -> TableSchema {
        TableSchema::new(
            self.tool_id(),
            "Firefox Downloads (places.sqlite)",
            vec![
                ColumnDef::new("filename", "Filename", ColumnType::Text).with_width_hint(160),
                ColumnDef::new("source_url", "Source URL", ColumnType::Text).with_width_hint(260),
                ColumnDef::new("target_path", "Target Path", ColumnType::Text).with_width_hint(220),
                ColumnDef::new("start_time", "Start Time", ColumnType::Timestamp).with_width_hint(160),
                ColumnDef::new("end_time", "End Time", ColumnType::Timestamp).with_width_hint(160),
                ColumnDef::new("bytes", "Size", ColumnType::BytesSize).with_width_hint(90),
                ColumnDef::new("state", "State", ColumnType::Text).with_width_hint(110),
                ColumnDef::new("mime_type", "MIME Type", ColumnType::Text).with_width_hint(130),
            ],
        )
        .with_default_sort(3, SortDirection::Desc)
    }

    fn query(&self, req: &TableQuery) -> Result<TableData, TableError> {
        let mut warnings = Vec::new();
        let mut rows = Vec::new();
        for (_pname, pdir) in resolve_firefox_profile_dirs(self.target.as_deref()) {
            for rec in parse_firefox_downloads(&pdir, &mut warnings) {
                let id = rows.len() as u64 + 1;
                rows.push(
                    Row::new(
                        id,
                        vec![
                            CellValue::Text(rec.filename.clone()),
                            CellValue::Text(rec.source_url.clone()),
                            CellValue::Text(rec.target_path.clone()),
                            rec.start_time.map(CellValue::Timestamp).unwrap_or(CellValue::Null),
                            rec.end_time.map(CellValue::Timestamp).unwrap_or(CellValue::Null),
                            CellValue::Bytes(rec.bytes),
                            CellValue::Text(rec.state.clone()),
                            CellValue::Text(rec.mime_type.clone()),
                        ],
                    )
                    .with_detail_json(serde_json::to_value(&rec).unwrap_or_default()),
                );
            }
        }
        apply_query(&self.schema(), &rows, req)
    }
}

// =========================================================================
// 5. fx formhistory (`formhistory.sqlite` — Non-Credential Form Autofill)
// =========================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirefoxFormHistoryRecord {
    pub field_name: String,
    pub value: String,
    pub times_used: i64,
    pub first_used: Option<DateTime<Utc>>,
    pub last_used: Option<DateTime<Utc>>,
    pub guid: String,
}

pub fn parse_firefox_formhistory(
    profile_dir: &Path,
    warnings: &mut Vec<DiagnosticWarning>,
) -> Vec<FirefoxFormHistoryRecord> {
    let db_path = profile_dir.join("formhistory.sqlite");
    if !db_path.is_file() {
        return Vec::new();
    }
    let db = match ForensicSqlite::open_snapshot(&db_path) {
        Ok(d) => d,
        Err(e) => {
            warnings.push(DiagnosticWarning::warn(
                "fx_formhistory",
                &db_path,
                format!("Failed opening formhistory.sqlite: {e}"),
            ));
            return Vec::new();
        }
    };
    let tables = db.list_tables();
    if !tables.contains("moz_formhistory") {
        return Vec::new();
    }
    let cols = db.table_columns("moz_formhistory");
    let guid_col = if cols.contains("guid") {
        "COALESCE(guid, '')"
    } else {
        "''"
    };
    let sql = format!(
        "SELECT fieldname, value, COALESCE(timesUsed, 0), COALESCE(firstUsed, 0), COALESCE(lastUsed, 0), {guid_col}
         FROM moz_formhistory ORDER BY lastUsed DESC"
    );
    let mut out = Vec::new();
    if let Ok(mut stmt) = db.conn.prepare(&sql)
        && let Ok(rows) = stmt.query_map([], |r| {
            Ok(FirefoxFormHistoryRecord {
                field_name: r.get(0).unwrap_or_default(),
                value: r.get(1).unwrap_or_default(),
                times_used: r.get(2).unwrap_or(0),
                first_used: prtime_us_to_datetime(r.get::<_, i64>(3).unwrap_or(0)),
                last_used: prtime_us_to_datetime(r.get::<_, i64>(4).unwrap_or(0)),
                guid: r.get(5).unwrap_or_default(),
            })
        })
    {
        out.extend(rows.flatten());
    }
    out
}

pub struct FirefoxFormHistoryTableProvider {
    target: Option<PathBuf>,
}

impl FirefoxFormHistoryTableProvider {
    pub fn new(target: Option<PathBuf>) -> Self {
        Self { target }
    }
}

impl TableProvider for FirefoxFormHistoryTableProvider {
    fn tool_id(&self) -> &'static str {
        "chrome2rust_fx_formhistory"
    }

    fn description(&self) -> &'static str {
        "Inspect Mozilla Firefox non-credential form autofill history from formhistory.sqlite."
    }

    fn schema(&self) -> TableSchema {
        TableSchema::new(
            self.tool_id(),
            "Firefox Form History (formhistory.sqlite)",
            vec![
                ColumnDef::new("field_name", "Field Name", ColumnType::Text).with_width_hint(140),
                ColumnDef::new("value", "Value", ColumnType::Text).with_width_hint(220),
                ColumnDef::new("times_used", "Times Used", ColumnType::Int).with_width_hint(85),
                ColumnDef::new("first_used", "First Used", ColumnType::Timestamp).with_width_hint(160),
                ColumnDef::new("last_used", "Last Used", ColumnType::Timestamp).with_width_hint(160),
                ColumnDef::new("guid", "GUID", ColumnType::Text).with_width_hint(110),
            ],
        )
        .with_default_sort(4, SortDirection::Desc)
    }

    fn query(&self, req: &TableQuery) -> Result<TableData, TableError> {
        let mut warnings = Vec::new();
        let mut rows = Vec::new();
        for (_pname, pdir) in resolve_firefox_profile_dirs(self.target.as_deref()) {
            for rec in parse_firefox_formhistory(&pdir, &mut warnings) {
                let id = rows.len() as u64 + 1;
                rows.push(
                    Row::new(
                        id,
                        vec![
                            CellValue::Text(rec.field_name.clone()),
                            CellValue::Text(rec.value.clone()),
                            CellValue::Int(rec.times_used),
                            rec.first_used.map(CellValue::Timestamp).unwrap_or(CellValue::Null),
                            rec.last_used.map(CellValue::Timestamp).unwrap_or(CellValue::Null),
                            CellValue::Text(rec.guid.clone()),
                        ],
                    )
                    .with_detail_json(serde_json::to_value(&rec).unwrap_or_default()),
                );
            }
        }
        apply_query(&self.schema(), &rows, req)
    }
}

// =========================================================================
// 6. fx addons (`extensions.json` + `addons.json`)
// =========================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirefoxAddonRecord {
    pub addon_id: String,
    pub name: String,
    pub version: String,
    pub addon_type: String,
    pub active: bool,
    pub install_date: Option<DateTime<Utc>>,
    pub permissions: Vec<String>,
    pub host_permissions: Vec<String>,
    pub risk_flags: Vec<String>,
    pub location: String,
    pub source_uri: Option<String>,
}

pub fn parse_firefox_addons(profile_dir: &Path, warnings: &mut Vec<DiagnosticWarning>) -> Vec<FirefoxAddonRecord> {
    let mut extra_names: HashMap<String, String> = HashMap::new();
    let addons_path = profile_dir.join("addons.json");
    if addons_path.is_file()
        && let Ok(txt) = std::fs::read_to_string(&addons_path)
        && let Ok(val) = serde_json::from_str::<serde_json::Value>(&txt)
        && let Some(arr) = val.get("addons").and_then(|v| v.as_array())
    {
        for item in arr {
            if let (Some(id), Some(name)) = (
                item.get("id").and_then(|v| v.as_str()),
                item.get("name").and_then(|v| v.as_str()),
            ) {
                extra_names.insert(id.to_string(), name.to_string());
            }
        }
    }

    let ext_path = profile_dir.join("extensions.json");
    if !ext_path.is_file() {
        return Vec::new();
    }
    let text = match std::fs::read_to_string(&ext_path) {
        Ok(t) => t,
        Err(e) => {
            warnings.push(DiagnosticWarning::warn(
                "fx_addons",
                &ext_path,
                format!("Failed reading extensions.json: {e}"),
            ));
            return Vec::new();
        }
    };
    let val: serde_json::Value = match serde_json::from_str(&text) {
        Ok(v) => v,
        Err(e) => {
            warnings.push(DiagnosticWarning::warn(
                "fx_addons",
                &ext_path,
                format!("Failed parsing extensions.json: {e}"),
            ));
            return Vec::new();
        }
    };

    let mut out = Vec::new();
    if let Some(arr) = val.get("addons").and_then(|v| v.as_array()) {
        for item in arr {
            let addon_id = item.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string();
            if addon_id.is_empty() {
                continue;
            }
            let name = item
                .pointer("/defaultLocale/name")
                .and_then(|v| v.as_str())
                .or_else(|| item.pointer("/locales/0/name").and_then(|v| v.as_str()))
                .or_else(|| extra_names.get(&addon_id).map(String::as_str))
                .unwrap_or(&addon_id)
                .to_string();
            let version = item.get("version").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let addon_type = item
                .get("type")
                .and_then(|v| v.as_str())
                .unwrap_or("extension")
                .to_string();
            let active = item.get("active").and_then(|v| v.as_bool()).unwrap_or(false);
            let install_date = item
                .get("installDate")
                .and_then(|v| v.as_i64())
                .and_then(unix_ms_to_datetime);
            let location = item.get("location").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let source_uri = item.get("sourceURI").and_then(|v| v.as_str()).map(str::to_string);
            let signed_state = item.get("signedState").and_then(|v| v.as_i64());

            let mut permissions = Vec::new();
            let mut host_permissions = Vec::new();
            for ptr in ["/userPermissions/permissions", "/permissions"] {
                if let Some(pa) = item.pointer(ptr).and_then(|v| v.as_array()) {
                    for p in pa {
                        if let Some(s) = p.as_str()
                            && !permissions.iter().any(|x| x == s)
                        {
                            permissions.push(s.to_string());
                        }
                    }
                }
            }
            if let Some(oa) = item.pointer("/userPermissions/origins").and_then(|v| v.as_array()) {
                for o in oa {
                    if let Some(s) = o.as_str()
                        && !host_permissions.iter().any(|x| x == s)
                    {
                        host_permissions.push(s.to_string());
                    }
                }
            }

            let is_builtin = location.contains("system") || location.contains("builtin");
            let from_amo = source_uri.as_deref().is_some_and(|u| u.contains("addons.mozilla.org")) || is_builtin;
            let mut risk_flags = compute_extension_risks(&location, from_amo, &permissions, &host_permissions);
            if location == "app-temporary" {
                risk_flags.push("SIDELOADED:TEMPORARY".into());
            }
            if !is_builtin && signed_state.is_some_and(|s| s <= 0) {
                risk_flags.push("UNSIGNED".into());
            }

            out.push(FirefoxAddonRecord {
                addon_id,
                name,
                version,
                addon_type,
                active,
                install_date,
                permissions,
                host_permissions,
                risk_flags,
                location,
                source_uri,
            });
        }
    }
    out.sort_by_key(|a| a.name.to_ascii_lowercase());
    out
}

pub struct FirefoxAddonsTableProvider {
    target: Option<PathBuf>,
}

impl FirefoxAddonsTableProvider {
    pub fn new(target: Option<PathBuf>) -> Self {
        Self { target }
    }
}

impl TableProvider for FirefoxAddonsTableProvider {
    fn tool_id(&self) -> &'static str {
        "chrome2rust_fx_addons"
    }

    fn description(&self) -> &'static str {
        "Inspect Mozilla Firefox installed add-ons, extensions, permissions, and risk flags from extensions.json/addons.json."
    }

    fn schema(&self) -> TableSchema {
        TableSchema::new(
            self.tool_id(),
            "Firefox Add-ons & Extensions",
            vec![
                ColumnDef::new("addon_id", "Add-on ID", ColumnType::Text).with_width_hint(180),
                ColumnDef::new("name", "Name", ColumnType::Text).with_width_hint(180),
                ColumnDef::new("version", "Version", ColumnType::Text).with_width_hint(80),
                ColumnDef::new("addon_type", "Type", ColumnType::Text).with_width_hint(90),
                ColumnDef::new("active", "Active", ColumnType::Bool).with_width_hint(70),
                ColumnDef::new("install_date", "Install Date", ColumnType::Timestamp).with_width_hint(160),
                ColumnDef::new("permissions", "Permissions", ColumnType::Text).with_width_hint(200),
                ColumnDef::new("risk_flags", "Risk Flags", ColumnType::Text).with_width_hint(180),
                ColumnDef::new("location", "Location", ColumnType::Text).with_width_hint(120),
            ],
        )
        .with_default_sort(1, SortDirection::Asc)
    }

    fn query(&self, req: &TableQuery) -> Result<TableData, TableError> {
        let mut warnings = Vec::new();
        let mut rows = Vec::new();
        for (_pname, pdir) in resolve_firefox_profile_dirs(self.target.as_deref()) {
            for rec in parse_firefox_addons(&pdir, &mut warnings) {
                let id = rows.len() as u64 + 1;
                rows.push(
                    Row::new(
                        id,
                        vec![
                            CellValue::Text(rec.addon_id.clone()),
                            CellValue::Text(rec.name.clone()),
                            CellValue::Text(rec.version.clone()),
                            CellValue::Text(rec.addon_type.clone()),
                            CellValue::Bool(rec.active),
                            rec.install_date.map(CellValue::Timestamp).unwrap_or(CellValue::Null),
                            CellValue::Text(rec.permissions.join(", ")),
                            CellValue::Text(rec.risk_flags.join(", ")),
                            CellValue::Text(rec.location.clone()),
                        ],
                    )
                    .with_detail_json(serde_json::to_value(&rec).unwrap_or_default()),
                );
            }
        }
        apply_query(&self.schema(), &rows, req)
    }
}

// =========================================================================
// 7. fx sessions (`sessionstore.jsonlz4` / `recovery.jsonlz4`)
// =========================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirefoxSessionTabRecord {
    pub window_idx: usize,
    pub tab_idx: usize,
    pub title: String,
    pub url: String,
    pub last_accessed: Option<DateTime<Utc>>,
    pub pinned: bool,
    pub closed: bool,
    pub source_file: String,
}

pub fn parse_firefox_sessions(
    profile_dir: &Path,
    warnings: &mut Vec<DiagnosticWarning>,
) -> Vec<FirefoxSessionTabRecord> {
    let candidates = [
        profile_dir.join("sessionstore.jsonlz4"),
        profile_dir.join("sessionstore-backups").join("recovery.jsonlz4"),
        profile_dir.join("sessionstore-backups").join("recovery.baklz4"),
        profile_dir.join("sessionstore-backups").join("previous.jsonlz4"),
        profile_dir.join("sessionstore.json"),
        profile_dir.join("sessionstore.js"),
    ];

    let mut out = Vec::new();
    for cand in candidates {
        if !cand.is_file() {
            continue;
        }
        let raw = match std::fs::read(&cand) {
            Ok(b) => b,
            Err(e) => {
                warnings.push(DiagnosticWarning::warn(
                    "fx_sessions",
                    &cand,
                    format!("Read error: {e}"),
                ));
                continue;
            }
        };
        let json_bytes = if raw.starts_with(b"mozLz40\0") {
            match decompress_mozlz4(&raw) {
                Ok(d) => d,
                Err(e) => {
                    warnings.push(DiagnosticWarning::warn(
                        "fx_sessions",
                        &cand,
                        format!("mozLz40 decompress error: {e}"),
                    ));
                    continue;
                }
            }
        } else {
            raw
        };
        let val: serde_json::Value = match serde_json::from_slice(&json_bytes) {
            Ok(v) => v,
            Err(e) => {
                warnings.push(DiagnosticWarning::warn(
                    "fx_sessions",
                    &cand,
                    format!("JSON parse error: {e}"),
                ));
                continue;
            }
        };
        let src = cand
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();

        if let Some(windows) = val.get("windows").and_then(|v| v.as_array()) {
            for (w_idx, win) in windows.iter().enumerate() {
                if let Some(tabs) = win.get("tabs").and_then(|v| v.as_array()) {
                    for (t_idx, tab) in tabs.iter().enumerate() {
                        if let Some(rec) = extract_fx_tab(w_idx, t_idx, tab, false, &src) {
                            out.push(rec);
                        }
                    }
                }
                if let Some(ctabs) = win.get("_closedTabs").and_then(|v| v.as_array()) {
                    for (t_idx, ctab) in ctabs.iter().enumerate() {
                        let state = ctab.get("state").unwrap_or(ctab);
                        if let Some(mut rec) = extract_fx_tab(w_idx, t_idx, state, true, &src) {
                            if rec.last_accessed.is_none() {
                                rec.last_accessed = ctab
                                    .get("closedAt")
                                    .and_then(|v| v.as_i64())
                                    .and_then(unix_ms_to_datetime);
                            }
                            out.push(rec);
                        }
                    }
                }
            }
        }
        if let Some(cwins) = val.get("_closedWindows").and_then(|v| v.as_array()) {
            for (w_idx, win) in cwins.iter().enumerate() {
                if let Some(tabs) = win.get("tabs").and_then(|v| v.as_array()) {
                    for (t_idx, tab) in tabs.iter().enumerate() {
                        if let Some(rec) = extract_fx_tab(w_idx, t_idx, tab, true, &src) {
                            out.push(rec);
                        }
                    }
                }
            }
        }
        // Parse primary available session file without duplicating open tabs across backups
        if !out.is_empty() {
            break;
        }
    }

    out
}

fn extract_fx_tab(
    w_idx: usize,
    t_idx: usize,
    tab: &serde_json::Value,
    closed: bool,
    src: &str,
) -> Option<FirefoxSessionTabRecord> {
    let entries = tab.get("entries").and_then(|v| v.as_array())?;
    if entries.is_empty() {
        return None;
    }
    let idx_1based = tab
        .get("index")
        .and_then(|v| v.as_u64())
        .unwrap_or(entries.len() as u64) as usize;
    let active = idx_1based.saturating_sub(1).min(entries.len() - 1);
    let entry = &entries[active];
    let url = entry.get("url").and_then(|v| v.as_str()).unwrap_or("").to_string();
    if url.is_empty() {
        return None;
    }
    let title = entry.get("title").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let last_accessed = tab
        .get("lastAccessed")
        .and_then(|v| v.as_i64())
        .and_then(unix_ms_to_datetime);
    let pinned = tab.get("pinned").and_then(|v| v.as_bool()).unwrap_or(false);

    Some(FirefoxSessionTabRecord {
        window_idx: w_idx,
        tab_idx: t_idx,
        title,
        url,
        last_accessed,
        pinned,
        closed,
        source_file: src.to_string(),
    })
}

pub struct FirefoxSessionsTableProvider {
    target: Option<PathBuf>,
}

impl FirefoxSessionsTableProvider {
    pub fn new(target: Option<PathBuf>) -> Self {
        Self { target }
    }
}

impl TableProvider for FirefoxSessionsTableProvider {
    fn tool_id(&self) -> &'static str {
        "chrome2rust_fx_sessions"
    }

    fn description(&self) -> &'static str {
        "Inspect Mozilla Firefox open and closed session tabs from sessionstore.jsonlz4 / recovery.jsonlz4."
    }

    fn schema(&self) -> TableSchema {
        TableSchema::new(
            self.tool_id(),
            "Firefox Sessions (jsonlz4)",
            vec![
                ColumnDef::new("window_idx", "Window", ColumnType::Uint).with_width_hint(70),
                ColumnDef::new("tab_idx", "Tab", ColumnType::Uint).with_width_hint(65),
                ColumnDef::new("title", "Title", ColumnType::Text).with_width_hint(200),
                ColumnDef::new("url", "URL", ColumnType::Text).with_width_hint(300),
                ColumnDef::new("last_accessed", "Last Accessed", ColumnType::Timestamp).with_width_hint(160),
                ColumnDef::new("pinned", "Pinned", ColumnType::Bool).with_width_hint(70),
                ColumnDef::new("closed", "Closed", ColumnType::Bool).with_width_hint(70),
                ColumnDef::new("source_file", "Source File", ColumnType::Text).with_width_hint(150),
            ],
        )
        .with_default_sort(4, SortDirection::Desc)
    }

    fn query(&self, req: &TableQuery) -> Result<TableData, TableError> {
        let mut warnings = Vec::new();
        let mut rows = Vec::new();
        for (_pname, pdir) in resolve_firefox_profile_dirs(self.target.as_deref()) {
            for rec in parse_firefox_sessions(&pdir, &mut warnings) {
                let id = rows.len() as u64 + 1;
                rows.push(
                    Row::new(
                        id,
                        vec![
                            CellValue::Uint(rec.window_idx as u64),
                            CellValue::Uint(rec.tab_idx as u64),
                            CellValue::Text(rec.title.clone()),
                            CellValue::Text(rec.url.clone()),
                            rec.last_accessed.map(CellValue::Timestamp).unwrap_or(CellValue::Null),
                            CellValue::Bool(rec.pinned),
                            CellValue::Bool(rec.closed),
                            CellValue::Text(rec.source_file.clone()),
                        ],
                    )
                    .with_detail_json(serde_json::to_value(&rec).unwrap_or_default()),
                );
            }
        }
        apply_query(&self.schema(), &rows, req)
    }
}
