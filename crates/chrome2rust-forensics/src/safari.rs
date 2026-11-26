use chrome2rust_core::discovery::{UnifiedBrowserKind, discover_safari_profiles, resolve_unified_targets};
use chrome2rust_core::error::DiagnosticWarning;
use chrome2rust_core::plist::{PlistValue, parse_plist};
use chrome2rust_core::sqlite_util::ForensicSqlite;
use chrome2rust_core::time::cf_absolute_time_to_datetime;
use chrono::{DateTime, Utc};
use guap_table::{
    CellValue, ColumnDef, ColumnType, Row, SortDirection, TableData, TableError, TableProvider, TableQuery,
    TableSchema, apply_query,
};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

const MAX_SAFARI_BOOKMARK_DEPTH: usize = 64;

fn resolve_safari_dirs(target: Option<&Path>) -> Vec<(String, PathBuf)> {
    if let Some(p) = target {
        let resolved = resolve_unified_targets(&[p.to_path_buf()]);
        let sf: Vec<_> = resolved
            .into_iter()
            .filter(|t| t.browser == UnifiedBrowserKind::Safari)
            .map(|t| (t.profile_name, t.profile_dir))
            .collect();
        if !sf.is_empty() {
            return sf;
        }
        let dir = if p.is_file() {
            p.parent().unwrap_or(p).to_path_buf()
        } else {
            p.to_path_buf()
        };
        return vec![("Safari".to_string(), dir)];
    }
    discover_safari_profiles()
        .into_iter()
        .map(|t| (t.profile_name, t.profile_dir))
        .collect()
}

// =========================================================================
// 1. safari history (`History.db` + `History.plist`)
// =========================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SafariHistoryRecord {
    pub url: String,
    pub title: String,
    pub visit_time: Option<DateTime<Utc>>,
    pub visit_count: i64,
    pub origin: String,
    pub source_format: String,
}

fn decode_safari_origin(origin: i64) -> &'static str {
    match origin {
        0 => "Local",
        1 => "Synced",
        _ => "Other",
    }
}

pub fn parse_safari_history(profile_dir: &Path, warnings: &mut Vec<DiagnosticWarning>) -> Vec<SafariHistoryRecord> {
    let mut out = Vec::new();

    let db_path = profile_dir.join("History.db");
    if db_path.is_file() {
        match ForensicSqlite::open_snapshot(&db_path) {
            Ok(db) => {
                let tables = db.list_tables();
                if tables.contains("history_visits") && tables.contains("history_items") {
                    let vcols = db.table_columns("history_visits");
                    let origin_col = if vcols.contains("origin") { "v.origin" } else { "0" };
                    let sql = format!(
                        "SELECT i.url, COALESCE(v.title, ''), v.visit_time, COALESCE(i.visit_count, 1), {origin_col}
                         FROM history_visits v
                         JOIN history_items i ON v.history_item = i.id
                         ORDER BY v.visit_time DESC"
                    );
                    if let Ok(mut stmt) = db.conn.prepare(&sql)
                        && let Ok(rows) = stmt.query_map([], |r| {
                            Ok(SafariHistoryRecord {
                                url: r.get(0).unwrap_or_default(),
                                title: r.get(1).unwrap_or_default(),
                                visit_time: cf_absolute_time_to_datetime(r.get::<_, f64>(2).unwrap_or(0.0)),
                                visit_count: r.get(3).unwrap_or(1),
                                origin: decode_safari_origin(r.get::<_, i64>(4).unwrap_or(0)).to_string(),
                                source_format: "History.db".to_string(),
                            })
                        })
                    {
                        out.extend(rows.flatten());
                    }
                }
            }
            Err(e) => warnings.push(DiagnosticWarning::warn(
                "safari_history",
                &db_path,
                format!("Failed opening History.db: {e}"),
            )),
        }
    }

    let plist_path = profile_dir.join("History.plist");
    if plist_path.is_file()
        && let Ok(bytes) = std::fs::read(&plist_path)
    {
        match parse_plist(&bytes) {
            Ok(plist) => {
                if let Some(dates) = plist.get("WebHistoryDates").and_then(PlistValue::as_array) {
                    for item in dates {
                        let Some(url) = item.get("").and_then(PlistValue::as_str) else {
                            continue;
                        };
                        let title = item.get("title").and_then(PlistValue::as_str).unwrap_or("").to_string();
                        let visit_count = item.get("visitCount").and_then(PlistValue::as_i64).unwrap_or(1);
                        let visit_time = item.get("lastVisitedDate").and_then(|v| {
                            v.as_f64()
                                .or_else(|| v.as_str().and_then(|s| s.parse::<f64>().ok()))
                                .and_then(cf_absolute_time_to_datetime)
                                .or_else(|| v.as_date())
                        });
                        out.push(SafariHistoryRecord {
                            url: url.to_string(),
                            title,
                            visit_time,
                            visit_count,
                            origin: "Local".to_string(),
                            source_format: "History.plist".to_string(),
                        });
                    }
                }
            }
            Err(e) => warnings.push(DiagnosticWarning::warn(
                "safari_history",
                &plist_path,
                format!("Failed parsing History.plist: {e}"),
            )),
        }
    }

    out.sort_by(|a, b| b.visit_time.cmp(&a.visit_time).then_with(|| a.url.cmp(&b.url)));
    out
}

pub struct SafariHistoryTableProvider {
    target: Option<PathBuf>,
}

impl SafariHistoryTableProvider {
    pub fn new(target: Option<PathBuf>) -> Self {
        Self { target }
    }
}

impl TableProvider for SafariHistoryTableProvider {
    fn tool_id(&self) -> &'static str {
        "chrome2rust_safari_history"
    }

    fn description(&self) -> &'static str {
        "Inspect Apple Safari browsing history from History.db (CFAbsoluteTime) and History.plist (SafariHistoryView equivalent)."
    }

    fn schema(&self) -> TableSchema {
        TableSchema::new(
            self.tool_id(),
            "Safari Browsing History",
            vec![
                ColumnDef::new("url", "URL", ColumnType::Text).with_width_hint(300),
                ColumnDef::new("title", "Title", ColumnType::Text).with_width_hint(200),
                ColumnDef::new("visit_time", "Visit Time", ColumnType::Timestamp).with_width_hint(160),
                ColumnDef::new("visit_count", "Visit Count", ColumnType::Int).with_width_hint(85),
                ColumnDef::new("origin", "Origin", ColumnType::Text).with_width_hint(90),
                ColumnDef::new("source_format", "Source Format", ColumnType::Text).with_width_hint(110),
            ],
        )
        .with_default_sort(2, SortDirection::Desc)
    }

    fn query(&self, req: &TableQuery) -> Result<TableData, TableError> {
        let mut warnings = Vec::new();
        let mut rows = Vec::new();
        for (_pname, pdir) in resolve_safari_dirs(self.target.as_deref()) {
            for rec in parse_safari_history(&pdir, &mut warnings) {
                let id = rows.len() as u64 + 1;
                rows.push(
                    Row::new(
                        id,
                        vec![
                            CellValue::Text(rec.url.clone()),
                            CellValue::Text(rec.title.clone()),
                            rec.visit_time.map(CellValue::Timestamp).unwrap_or(CellValue::Null),
                            CellValue::Int(rec.visit_count),
                            CellValue::Text(rec.origin.clone()),
                            CellValue::Text(rec.source_format.clone()),
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
// 2. safari bookmarks (`Bookmarks.plist`)
// =========================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SafariBookmarkRecord {
    pub title: String,
    pub url: String,
    pub folder_path: String,
    pub uuid: String,
    pub date_added: Option<DateTime<Utc>>,
}

pub fn parse_safari_bookmarks(profile_dir: &Path, warnings: &mut Vec<DiagnosticWarning>) -> Vec<SafariBookmarkRecord> {
    let bm_path = profile_dir.join("Bookmarks.plist");
    if !bm_path.is_file() {
        return Vec::new();
    }
    let bytes = match std::fs::read(&bm_path) {
        Ok(b) => b,
        Err(e) => {
            warnings.push(DiagnosticWarning::warn(
                "safari_bookmarks",
                &bm_path,
                format!("Failed reading Bookmarks.plist: {e}"),
            ));
            return Vec::new();
        }
    };
    let plist = match parse_plist(&bytes) {
        Ok(p) => p,
        Err(e) => {
            warnings.push(DiagnosticWarning::warn(
                "safari_bookmarks",
                &bm_path,
                format!("Failed parsing Bookmarks.plist: {e}"),
            ));
            return Vec::new();
        }
    };
    let mut out = Vec::new();
    walk_safari_bookmarks(&plist, &[], 0, &mut out);
    out
}

fn walk_safari_bookmarks(
    node: &PlistValue,
    folder_stack: &[String],
    depth: usize,
    out: &mut Vec<SafariBookmarkRecord>,
) {
    if depth > MAX_SAFARI_BOOKMARK_DEPTH {
        return;
    }
    let Some(dict) = node.as_dict() else {
        return;
    };
    let bm_type = dict.get("WebBookmarkType").and_then(PlistValue::as_str).unwrap_or("");

    if bm_type == "WebBookmarkTypeLeaf" {
        if let Some(url) = dict.get("URLString").and_then(PlistValue::as_str) {
            let title = dict
                .get("URIDictionary")
                .and_then(|u| u.get("title"))
                .and_then(PlistValue::as_str)
                .or_else(|| dict.get("Title").and_then(PlistValue::as_str))
                .unwrap_or("")
                .to_string();
            let uuid = dict
                .get("WebBookmarkUUID")
                .and_then(PlistValue::as_str)
                .unwrap_or("")
                .to_string();
            let date_added = dict
                .get("ReadingList")
                .and_then(|rl| rl.get("DateAdded"))
                .and_then(PlistValue::as_date);
            out.push(SafariBookmarkRecord {
                title,
                url: url.to_string(),
                folder_path: folder_stack.join(" / "),
                uuid,
                date_added,
            });
        }
        return;
    }

    if let Some(children) = dict.get("Children").and_then(PlistValue::as_array) {
        let mut next_stack = folder_stack.to_vec();
        if let Some(folder_title) = dict.get("Title").and_then(PlistValue::as_str)
            && !folder_title.is_empty()
        {
            next_stack.push(folder_title.to_string());
        }
        for child in children {
            walk_safari_bookmarks(child, &next_stack, depth + 1, out);
        }
    }
}

pub struct SafariBookmarksTableProvider {
    target: Option<PathBuf>,
}

impl SafariBookmarksTableProvider {
    pub fn new(target: Option<PathBuf>) -> Self {
        Self { target }
    }
}

impl TableProvider for SafariBookmarksTableProvider {
    fn tool_id(&self) -> &'static str {
        "chrome2rust_safari_bookmarks"
    }

    fn description(&self) -> &'static str {
        "Inspect Apple Safari bookmarks recursively from Bookmarks.plist (bplist00 or XML plist)."
    }

    fn schema(&self) -> TableSchema {
        TableSchema::new(
            self.tool_id(),
            "Safari Bookmarks (Bookmarks.plist)",
            vec![
                ColumnDef::new("title", "Title", ColumnType::Text).with_width_hint(180),
                ColumnDef::new("url", "URL", ColumnType::Text).with_width_hint(300),
                ColumnDef::new("folder_path", "Folder Path", ColumnType::Text).with_width_hint(180),
                ColumnDef::new("uuid", "UUID", ColumnType::Text).with_width_hint(160),
                ColumnDef::new("date_added", "Date Added", ColumnType::Timestamp).with_width_hint(160),
            ],
        )
        .with_default_sort(0, SortDirection::Asc)
    }

    fn query(&self, req: &TableQuery) -> Result<TableData, TableError> {
        let mut warnings = Vec::new();
        let mut rows = Vec::new();
        for (_pname, pdir) in resolve_safari_dirs(self.target.as_deref()) {
            for rec in parse_safari_bookmarks(&pdir, &mut warnings) {
                let id = rows.len() as u64 + 1;
                rows.push(
                    Row::new(
                        id,
                        vec![
                            CellValue::Text(rec.title.clone()),
                            CellValue::Text(rec.url.clone()),
                            CellValue::Text(rec.folder_path.clone()),
                            CellValue::Text(rec.uuid.clone()),
                            rec.date_added.map(CellValue::Timestamp).unwrap_or(CellValue::Null),
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
// 3. Safari Downloads helper (`Downloads.plist`) for unified downloads
// =========================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SafariDownloadRecord {
    pub filename: String,
    pub download_url: String,
    pub target_path: String,
    pub start_time: Option<DateTime<Utc>>,
    pub end_time: Option<DateTime<Utc>>,
    pub total_bytes: u64,
    pub received_bytes: u64,
}

pub fn parse_safari_downloads(profile_dir: &Path) -> Vec<SafariDownloadRecord> {
    let dl_path = profile_dir.join("Downloads.plist");
    if !dl_path.is_file() {
        return Vec::new();
    }
    let Ok(bytes) = std::fs::read(&dl_path) else {
        return Vec::new();
    };
    let Ok(plist) = parse_plist(&bytes) else {
        return Vec::new();
    };
    let Some(items) = plist.get("DownloadHistory").and_then(PlistValue::as_array) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for item in items {
        let url = item
            .get("DownloadEntryURL")
            .and_then(PlistValue::as_str)
            .unwrap_or("")
            .to_string();
        if url.is_empty() {
            continue;
        }
        let target_path = item
            .get("DownloadEntryPath")
            .and_then(PlistValue::as_str)
            .unwrap_or("")
            .to_string();
        let filename = Path::new(&target_path)
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "download".to_string());
        let received = item
            .get("DownloadEntryProgressBytesSoFar")
            .and_then(PlistValue::as_i64)
            .unwrap_or(0)
            .max(0) as u64;
        let total = item
            .get("DownloadEntryProgressTotalToLoad")
            .and_then(PlistValue::as_i64)
            .unwrap_or(received as i64)
            .max(0) as u64;
        out.push(SafariDownloadRecord {
            filename,
            download_url: url,
            target_path,
            start_time: item.get("DownloadEntryDateAddedKey").and_then(PlistValue::as_date),
            end_time: item.get("DownloadEntryDateFinishedKey").and_then(PlistValue::as_date),
            total_bytes: total,
            received_bytes: received,
        });
    }
    out
}
