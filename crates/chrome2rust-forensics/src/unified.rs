use crate::bookmarks::parse_bookmarks;
use crate::extensions::parse_extensions;
use crate::firefox::{
    parse_firefox_addons, parse_firefox_bookmarks, parse_firefox_downloads, parse_firefox_formhistory,
    parse_firefox_history,
};
use crate::history::parse_history;
use crate::opera::{parse_opera_adr, parse_presto_global_history};
use crate::preferences::parse_preferences;
use crate::safari::{parse_safari_bookmarks, parse_safari_downloads, parse_safari_history};
use crate::webdata::parse_autofill_only;
use chrome2rust_core::discovery::{
    UnifiedBrowserKind, UnifiedProfileTarget, discover_all_browser_profiles, resolve_unified_targets,
};
use chrome2rust_core::error::DiagnosticWarning;
use chrono::{DateTime, Utc};
use guap_table::{
    CellValue, ColumnDef, ColumnType, Row, SortDirection, TableData, TableError, TableProvider, TableQuery,
    TableSchema, apply_query,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Default)]
pub struct UnifiedQueryOptions {
    pub paths: Vec<PathBuf>,
    pub browser_filter: Option<UnifiedBrowserKind>,
    pub profile_filter: Option<String>,
    pub since: Option<DateTime<Utc>>,
    pub until: Option<DateTime<Utc>>,
}

impl UnifiedQueryOptions {
    pub fn from_optional_path(target: Option<&Path>) -> Self {
        Self {
            paths: target.map(|p| vec![p.to_path_buf()]).unwrap_or_default(),
            ..Default::default()
        }
    }

    pub fn resolve_targets(&self) -> Vec<UnifiedProfileTarget> {
        let mut targets = if self.paths.is_empty() {
            discover_all_browser_profiles()
        } else {
            resolve_unified_targets(&self.paths)
        };
        if let Some(bf) = self.browser_filter {
            targets.retain(|t| t.browser.matches_filter(bf));
        }
        if let Some(ref pf) = self.profile_filter {
            let needle = pf.to_ascii_lowercase();
            targets.retain(|t| t.profile_name.to_ascii_lowercase().contains(&needle));
        }
        targets
    }

    fn time_in_range(&self, ts: Option<DateTime<Utc>>) -> bool {
        if let Some(since) = self.since
            && ts.is_none_or(|t| t < since)
        {
            return false;
        }
        if let Some(until) = self.until
            && ts.is_none_or(|t| t > until)
        {
            return false;
        }
        true
    }
}

fn is_chromium_like(kind: UnifiedBrowserKind) -> bool {
    !matches!(
        kind,
        UnifiedBrowserKind::Firefox | UnifiedBrowserKind::OperaPresto | UnifiedBrowserKind::Safari
    )
}

// =========================================================================
// 1. unified history (BrowsingHistoryView)
// =========================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnifiedHistoryRecord {
    pub browser: String,
    pub profile: String,
    pub url: String,
    pub title: String,
    pub visit_time: Option<DateTime<Utc>>,
    pub visit_count: i64,
    pub visit_type: String,
    pub referrer: String,
    pub duration_ms: i64,
    pub source_artifact: String,
}

pub fn collect_unified_history(opts: &UnifiedQueryOptions) -> (Vec<UnifiedHistoryRecord>, Vec<DiagnosticWarning>) {
    let mut warnings = Vec::new();
    let mut out = Vec::new();

    for t in opts.resolve_targets() {
        match t.browser {
            UnifiedBrowserKind::Firefox => {
                for rec in parse_firefox_history(&t.profile_dir, &mut warnings) {
                    if opts.time_in_range(rec.visit_date) {
                        out.push(UnifiedHistoryRecord {
                            browser: t.browser_name.clone(),
                            profile: t.profile_name.clone(),
                            url: rec.url,
                            title: rec.title,
                            visit_time: rec.visit_date,
                            visit_count: rec.visit_count,
                            visit_type: rec.visit_type,
                            referrer: rec.referrer,
                            duration_ms: 0,
                            source_artifact: "places.sqlite".to_string(),
                        });
                    }
                }
            }
            UnifiedBrowserKind::Safari => {
                for rec in parse_safari_history(&t.profile_dir, &mut warnings) {
                    if opts.time_in_range(rec.visit_time) {
                        out.push(UnifiedHistoryRecord {
                            browser: t.browser_name.clone(),
                            profile: t.profile_name.clone(),
                            url: rec.url,
                            title: rec.title,
                            visit_time: rec.visit_time,
                            visit_count: rec.visit_count,
                            visit_type: rec.origin,
                            referrer: String::new(),
                            duration_ms: 0,
                            source_artifact: rec.source_format,
                        });
                    }
                }
            }
            UnifiedBrowserKind::OperaPresto => {
                let gh = t.profile_dir.join("global_history.dat");
                if gh.is_file() {
                    for rec in parse_presto_global_history(&gh, &t.profile_name) {
                        if opts.time_in_range(rec.visit_time) {
                            out.push(UnifiedHistoryRecord {
                                browser: t.browser_name.clone(),
                                profile: t.profile_name.clone(),
                                url: rec.url,
                                title: rec.title,
                                visit_time: rec.visit_time,
                                visit_count: rec.visit_count,
                                visit_type: "PRESTO".to_string(),
                                referrer: rec.referrer,
                                duration_ms: 0,
                                source_artifact: rec.source_format,
                            });
                        }
                    }
                }
            }
            _ => {
                let hist = parse_history(&t.profile_dir, &mut warnings);
                let url_counts: HashMap<i64, i64> = hist.urls.iter().map(|u| (u.id, u.visit_count)).collect();
                let visit_urls: HashMap<i64, String> =
                    hist.visits.iter().map(|v| (v.visit_id, v.url.clone())).collect();
                let mut seen_urls = std::collections::HashSet::new();

                for v in &hist.visits {
                    seen_urls.insert(v.url_id);
                    if opts.time_in_range(v.visit_time) {
                        out.push(UnifiedHistoryRecord {
                            browser: t.browser_name.clone(),
                            profile: t.profile_name.clone(),
                            url: v.url.clone(),
                            title: v.title.clone(),
                            visit_time: v.visit_time,
                            visit_count: url_counts.get(&v.url_id).copied().unwrap_or(1),
                            visit_type: v.transition_core.clone(),
                            referrer: visit_urls.get(&v.from_visit).cloned().unwrap_or_default(),
                            duration_ms: v.visit_duration_ms,
                            source_artifact: "History".to_string(),
                        });
                    }
                }
                for u in &hist.urls {
                    if !seen_urls.contains(&u.id) && opts.time_in_range(u.last_visit_time) {
                        out.push(UnifiedHistoryRecord {
                            browser: t.browser_name.clone(),
                            profile: t.profile_name.clone(),
                            url: u.url.clone(),
                            title: u.title.clone(),
                            visit_time: u.last_visit_time,
                            visit_count: u.visit_count,
                            visit_type: "URL_ENTRY".to_string(),
                            referrer: String::new(),
                            duration_ms: 0,
                            source_artifact: "History (urls)".to_string(),
                        });
                    }
                }
            }
        }
    }

    out.sort_by(|a, b| b.visit_time.cmp(&a.visit_time).then_with(|| a.url.cmp(&b.url)));
    (out, warnings)
}

pub struct UnifiedHistoryTableProvider {
    opts: UnifiedQueryOptions,
}

impl UnifiedHistoryTableProvider {
    pub fn new(target: Option<PathBuf>) -> Self {
        Self {
            opts: UnifiedQueryOptions::from_optional_path(target.as_deref()),
        }
    }

    pub fn with_options(opts: UnifiedQueryOptions) -> Self {
        Self { opts }
    }
}

impl TableProvider for UnifiedHistoryTableProvider {
    fn tool_id(&self) -> &'static str {
        "chrome2rust_unified_history"
    }

    fn description(&self) -> &'static str {
        "Aggregate normalized browsing history across Chrome, Edge, Brave, Opera, Firefox, and Safari (BrowsingHistoryView equivalent)."
    }

    fn schema(&self) -> TableSchema {
        TableSchema::new(
            self.tool_id(),
            "Unified Multi-Browser History",
            vec![
                ColumnDef::new("browser", "Browser", ColumnType::Text).with_width_hint(120),
                ColumnDef::new("profile", "Profile", ColumnType::Text).with_width_hint(100),
                ColumnDef::new("url", "URL", ColumnType::Text).with_width_hint(280),
                ColumnDef::new("title", "Title", ColumnType::Text).with_width_hint(180),
                ColumnDef::new("visit_time", "Visit Time", ColumnType::Timestamp).with_width_hint(160),
                ColumnDef::new("visit_count", "Visit Count", ColumnType::Int).with_width_hint(85),
                ColumnDef::new("visit_type", "Visit Type", ColumnType::Text).with_width_hint(100),
                ColumnDef::new("referrer", "Referrer", ColumnType::Text).with_width_hint(200),
                ColumnDef::new("duration_ms", "Duration", ColumnType::Duration).with_width_hint(90),
                ColumnDef::new("source_artifact", "Source", ColumnType::Text).with_width_hint(120),
            ],
        )
        .with_default_sort(4, SortDirection::Desc)
    }

    fn query(&self, req: &TableQuery) -> Result<TableData, TableError> {
        let (records, _) = collect_unified_history(&self.opts);
        let rows: Vec<Row> = records
            .into_iter()
            .enumerate()
            .map(|(idx, r)| {
                Row::new(
                    idx as u64 + 1,
                    vec![
                        CellValue::Text(r.browser.clone()),
                        CellValue::Text(r.profile.clone()),
                        CellValue::Text(r.url.clone()),
                        CellValue::Text(r.title.clone()),
                        r.visit_time.map(CellValue::Timestamp).unwrap_or(CellValue::Null),
                        CellValue::Int(r.visit_count),
                        CellValue::Text(r.visit_type.clone()),
                        CellValue::Text(r.referrer.clone()),
                        CellValue::Int(r.duration_ms),
                        CellValue::Text(r.source_artifact.clone()),
                    ],
                )
                .with_detail_json(serde_json::to_value(&r).unwrap_or_default())
            })
            .collect();
        apply_query(&self.schema(), &rows, req)
    }
}

// =========================================================================
// 2. unified downloads (BrowserDownloadsView)
// =========================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnifiedDownloadRecord {
    pub browser: String,
    pub profile: String,
    pub filename: String,
    pub download_url: String,
    pub referrer: String,
    pub target_path: String,
    pub start_time: Option<DateTime<Utc>>,
    pub end_time: Option<DateTime<Utc>>,
    pub size_bytes: u64,
    pub received_bytes: u64,
    pub state: String,
    pub mime_type: String,
    pub danger_type: String,
}

pub fn collect_unified_downloads(opts: &UnifiedQueryOptions) -> (Vec<UnifiedDownloadRecord>, Vec<DiagnosticWarning>) {
    let mut warnings = Vec::new();
    let mut out = Vec::new();

    for t in opts.resolve_targets() {
        match t.browser {
            UnifiedBrowserKind::Firefox => {
                for rec in parse_firefox_downloads(&t.profile_dir, &mut warnings) {
                    if opts.time_in_range(rec.start_time) {
                        out.push(UnifiedDownloadRecord {
                            browser: t.browser_name.clone(),
                            profile: t.profile_name.clone(),
                            filename: rec.filename,
                            download_url: rec.source_url,
                            referrer: String::new(),
                            target_path: rec.target_path,
                            start_time: rec.start_time,
                            end_time: rec.end_time,
                            size_bytes: rec.bytes,
                            received_bytes: rec.bytes,
                            state: rec.state,
                            mime_type: rec.mime_type,
                            danger_type: String::new(),
                        });
                    }
                }
            }
            UnifiedBrowserKind::Safari => {
                for rec in parse_safari_downloads(&t.profile_dir) {
                    if opts.time_in_range(rec.start_time) {
                        let state = if rec.end_time.is_some()
                            || (rec.total_bytes > 0 && rec.received_bytes >= rec.total_bytes)
                        {
                            "COMPLETE"
                        } else {
                            "IN_PROGRESS"
                        };
                        out.push(UnifiedDownloadRecord {
                            browser: t.browser_name.clone(),
                            profile: t.profile_name.clone(),
                            filename: rec.filename,
                            download_url: rec.download_url,
                            referrer: String::new(),
                            target_path: rec.target_path,
                            start_time: rec.start_time,
                            end_time: rec.end_time,
                            size_bytes: rec.total_bytes,
                            received_bytes: rec.received_bytes,
                            state: state.to_string(),
                            mime_type: String::new(),
                            danger_type: String::new(),
                        });
                    }
                }
            }
            UnifiedBrowserKind::OperaPresto => {}
            _ => {
                let hist = parse_history(&t.profile_dir, &mut warnings);
                for d in hist.downloads {
                    if !opts.time_in_range(d.start_time) {
                        continue;
                    }
                    let target = if !d.target_path.is_empty() {
                        d.target_path.clone()
                    } else {
                        d.current_path.clone()
                    };
                    let filename = Path::new(&target)
                        .file_name()
                        .map(|n| n.to_string_lossy().to_string())
                        .filter(|s| !s.is_empty())
                        .unwrap_or_else(|| "download".to_string());
                    let download_url = d
                        .url_chain
                        .last()
                        .or_else(|| d.url_chain.first())
                        .cloned()
                        .unwrap_or_default();
                    let size_bytes = (d.total_bytes.max(d.received_bytes)).max(0) as u64;
                    let received_bytes = d.received_bytes.max(0) as u64;
                    let upper_state = d.state.to_ascii_uppercase();
                    let state = match upper_state.as_str() {
                        "INTERRUPTED" => "INTERRUPTED",
                        "CANCELLED" | "CANCELED" => "CANCELLED",
                        "IN_PROGRESS" => "IN_PROGRESS",
                        "COMPLETE" => "COMPLETE",
                        other => other,
                    };
                    out.push(UnifiedDownloadRecord {
                        browser: t.browser_name.clone(),
                        profile: t.profile_name.clone(),
                        filename,
                        download_url,
                        referrer: d.referrer,
                        target_path: target,
                        start_time: d.start_time,
                        end_time: d.end_time,
                        size_bytes,
                        received_bytes,
                        state: state.to_string(),
                        mime_type: d.mime_type,
                        danger_type: d.danger_type,
                    });
                }
            }
        }
    }

    out.sort_by(|a, b| {
        b.start_time
            .cmp(&a.start_time)
            .then_with(|| a.filename.cmp(&b.filename))
    });
    (out, warnings)
}

pub struct UnifiedDownloadsTableProvider {
    opts: UnifiedQueryOptions,
}

impl UnifiedDownloadsTableProvider {
    pub fn new(target: Option<PathBuf>) -> Self {
        Self {
            opts: UnifiedQueryOptions::from_optional_path(target.as_deref()),
        }
    }

    pub fn with_options(opts: UnifiedQueryOptions) -> Self {
        Self { opts }
    }
}

impl TableProvider for UnifiedDownloadsTableProvider {
    fn tool_id(&self) -> &'static str {
        "chrome2rust_unified_downloads"
    }

    fn description(&self) -> &'static str {
        "Aggregate normalized download histories across Chrome, Edge, Brave, Opera, Firefox, and Safari (BrowserDownloadsView equivalent)."
    }

    fn schema(&self) -> TableSchema {
        TableSchema::new(
            self.tool_id(),
            "Unified Browser Downloads",
            vec![
                ColumnDef::new("browser", "Browser", ColumnType::Text).with_width_hint(120),
                ColumnDef::new("profile", "Profile", ColumnType::Text).with_width_hint(100),
                ColumnDef::new("filename", "Filename", ColumnType::Text).with_width_hint(160),
                ColumnDef::new("download_url", "Download URL", ColumnType::Text).with_width_hint(260),
                ColumnDef::new("referrer", "Referrer", ColumnType::Text).with_width_hint(180),
                ColumnDef::new("target_path", "Target Path", ColumnType::Text).with_width_hint(220),
                ColumnDef::new("start_time", "Start Time", ColumnType::Timestamp).with_width_hint(160),
                ColumnDef::new("end_time", "End Time", ColumnType::Timestamp).with_width_hint(160),
                ColumnDef::new("size_bytes", "Size", ColumnType::BytesSize).with_width_hint(90),
                ColumnDef::new("state", "State", ColumnType::Text).with_width_hint(100),
                ColumnDef::new("mime_type", "MIME Type", ColumnType::Text).with_width_hint(120),
                ColumnDef::new("danger_type", "Danger Type", ColumnType::Text).with_width_hint(110),
            ],
        )
        .with_default_sort(6, SortDirection::Desc)
    }

    fn query(&self, req: &TableQuery) -> Result<TableData, TableError> {
        let (records, _) = collect_unified_downloads(&self.opts);
        let rows: Vec<Row> = records
            .into_iter()
            .enumerate()
            .map(|(idx, r)| {
                Row::new(
                    idx as u64 + 1,
                    vec![
                        CellValue::Text(r.browser.clone()),
                        CellValue::Text(r.profile.clone()),
                        CellValue::Text(r.filename.clone()),
                        CellValue::Text(r.download_url.clone()),
                        CellValue::Text(r.referrer.clone()),
                        CellValue::Text(r.target_path.clone()),
                        r.start_time.map(CellValue::Timestamp).unwrap_or(CellValue::Null),
                        r.end_time.map(CellValue::Timestamp).unwrap_or(CellValue::Null),
                        CellValue::Bytes(r.size_bytes),
                        CellValue::Text(r.state.clone()),
                        CellValue::Text(r.mime_type.clone()),
                        CellValue::Text(r.danger_type.clone()),
                    ],
                )
                .with_detail_json(serde_json::to_value(&r).unwrap_or_default())
            })
            .collect();
        apply_query(&self.schema(), &rows, req)
    }
}

// =========================================================================
// 3. unified addons (BrowserAddonsView)
// =========================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnifiedAddonRecord {
    pub browser: String,
    pub profile: String,
    pub addon_id: String,
    pub name: String,
    pub version: String,
    pub addon_type: String,
    pub enabled: bool,
    pub install_time: Option<DateTime<Utc>>,
    pub permissions_count: u64,
    pub permissions: Vec<String>,
    pub host_permissions: Vec<String>,
    pub risk_flags: Vec<String>,
    pub location: String,
    pub source_uri: Option<String>,
}

pub fn collect_unified_addons(opts: &UnifiedQueryOptions) -> (Vec<UnifiedAddonRecord>, Vec<DiagnosticWarning>) {
    let mut warnings = Vec::new();
    let mut out = Vec::new();

    for t in opts.resolve_targets() {
        if t.browser == UnifiedBrowserKind::Firefox {
            for ext in parse_firefox_addons(&t.profile_dir, &mut warnings) {
                if opts.time_in_range(ext.install_date) {
                    let pcount = (ext.permissions.len() + ext.host_permissions.len()) as u64;
                    out.push(UnifiedAddonRecord {
                        browser: t.browser_name.clone(),
                        profile: t.profile_name.clone(),
                        addon_id: ext.addon_id,
                        name: ext.name,
                        version: ext.version,
                        addon_type: ext.addon_type,
                        enabled: ext.active,
                        install_time: ext.install_date,
                        permissions_count: pcount,
                        permissions: ext.permissions,
                        host_permissions: ext.host_permissions,
                        risk_flags: ext.risk_flags,
                        location: ext.location,
                        source_uri: ext.source_uri,
                    });
                }
            }
        } else if is_chromium_like(t.browser) {
            let (_, prefs_json, sec_prefs_json) = parse_preferences(&t.profile_dir, &mut warnings);
            let exts = parse_extensions(
                &t.profile_dir,
                prefs_json.as_ref(),
                sec_prefs_json.as_ref(),
                &mut warnings,
            );
            for ext in exts {
                if opts.time_in_range(ext.install_time) {
                    let pcount = (ext.permissions.len() + ext.host_permissions.len()) as u64;
                    out.push(UnifiedAddonRecord {
                        browser: t.browser_name.clone(),
                        profile: t.profile_name.clone(),
                        addon_id: ext.id,
                        name: ext.name,
                        version: ext.version,
                        addon_type: "extension".to_string(),
                        enabled: ext.enabled,
                        install_time: ext.install_time,
                        permissions_count: pcount,
                        permissions: ext.permissions,
                        host_permissions: ext.host_permissions,
                        risk_flags: ext.risk_flags,
                        location: ext.location,
                        source_uri: ext.update_url,
                    });
                }
            }
        }
    }

    out.sort_by_key(|a| a.name.to_ascii_lowercase());
    (out, warnings)
}

pub struct UnifiedAddonsTableProvider {
    opts: UnifiedQueryOptions,
}

impl UnifiedAddonsTableProvider {
    pub fn new(target: Option<PathBuf>) -> Self {
        Self {
            opts: UnifiedQueryOptions::from_optional_path(target.as_deref()),
        }
    }

    pub fn with_options(opts: UnifiedQueryOptions) -> Self {
        Self { opts }
    }
}

impl TableProvider for UnifiedAddonsTableProvider {
    fn tool_id(&self) -> &'static str {
        "chrome2rust_unified_addons"
    }

    fn description(&self) -> &'static str {
        "Aggregate normalized browser extensions and add-ons with permission risk flags across Chromium and Firefox (BrowserAddonsView equivalent)."
    }

    fn schema(&self) -> TableSchema {
        TableSchema::new(
            self.tool_id(),
            "Unified Browser Add-ons & Extensions",
            vec![
                ColumnDef::new("browser", "Browser", ColumnType::Text).with_width_hint(120),
                ColumnDef::new("profile", "Profile", ColumnType::Text).with_width_hint(100),
                ColumnDef::new("addon_id", "Add-on ID", ColumnType::Text).with_width_hint(170),
                ColumnDef::new("name", "Name", ColumnType::Text).with_width_hint(170),
                ColumnDef::new("version", "Version", ColumnType::Text).with_width_hint(80),
                ColumnDef::new("enabled", "Enabled", ColumnType::Bool).with_width_hint(70),
                ColumnDef::new("install_time", "Install Time", ColumnType::Timestamp).with_width_hint(160),
                ColumnDef::new("permissions_count", "Perms", ColumnType::Uint).with_width_hint(65),
                ColumnDef::new("risk_flags", "Risk Flags", ColumnType::Text).with_width_hint(200),
                ColumnDef::new("addon_type", "Type", ColumnType::Text).with_width_hint(90),
                ColumnDef::new("location", "Location", ColumnType::Text).with_width_hint(120),
            ],
        )
        .with_default_sort(3, SortDirection::Asc)
    }

    fn query(&self, req: &TableQuery) -> Result<TableData, TableError> {
        let (records, _) = collect_unified_addons(&self.opts);
        let rows: Vec<Row> = records
            .into_iter()
            .enumerate()
            .map(|(idx, r)| {
                Row::new(
                    idx as u64 + 1,
                    vec![
                        CellValue::Text(r.browser.clone()),
                        CellValue::Text(r.profile.clone()),
                        CellValue::Text(r.addon_id.clone()),
                        CellValue::Text(r.name.clone()),
                        CellValue::Text(r.version.clone()),
                        CellValue::Bool(r.enabled),
                        r.install_time.map(CellValue::Timestamp).unwrap_or(CellValue::Null),
                        CellValue::Uint(r.permissions_count),
                        CellValue::Text(r.risk_flags.join(", ")),
                        CellValue::Text(r.addon_type.clone()),
                        CellValue::Text(r.location.clone()),
                    ],
                )
                .with_detail_json(serde_json::to_value(&r).unwrap_or_default())
            })
            .collect();
        apply_query(&self.schema(), &rows, req)
    }
}

// =========================================================================
// 4. unified bookmarks (WebBrowserBookmarksView)
// =========================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnifiedBookmarkRecord {
    pub browser: String,
    pub profile: String,
    pub folder_path: String,
    pub title: String,
    pub url: String,
    pub created: Option<DateTime<Utc>>,
    pub modified: Option<DateTime<Utc>>,
    pub guid: String,
    pub source_artifact: String,
}

pub fn collect_unified_bookmarks(opts: &UnifiedQueryOptions) -> (Vec<UnifiedBookmarkRecord>, Vec<DiagnosticWarning>) {
    let mut warnings = Vec::new();
    let mut out = Vec::new();

    for t in opts.resolve_targets() {
        match t.browser {
            UnifiedBrowserKind::Firefox => {
                for bm in parse_firefox_bookmarks(&t.profile_dir, &mut warnings) {
                    if opts.time_in_range(bm.date_added) {
                        out.push(UnifiedBookmarkRecord {
                            browser: t.browser_name.clone(),
                            profile: t.profile_name.clone(),
                            folder_path: bm.folder_path,
                            title: bm.title,
                            url: bm.url,
                            created: bm.date_added,
                            modified: bm.last_modified,
                            guid: bm.guid,
                            source_artifact: bm.source_artifact,
                        });
                    }
                }
            }
            UnifiedBrowserKind::Safari => {
                for bm in parse_safari_bookmarks(&t.profile_dir, &mut warnings) {
                    if opts.time_in_range(bm.date_added) {
                        out.push(UnifiedBookmarkRecord {
                            browser: t.browser_name.clone(),
                            profile: t.profile_name.clone(),
                            folder_path: bm.folder_path,
                            title: bm.title,
                            url: bm.url,
                            created: bm.date_added,
                            modified: None,
                            guid: bm.uuid,
                            source_artifact: "Bookmarks.plist".to_string(),
                        });
                    }
                }
            }
            UnifiedBrowserKind::OperaPresto => {
                for fname in ["opera6.adr", "bookmarks.adr"] {
                    let adr = t.profile_dir.join(fname);
                    if adr.is_file() {
                        for bm in parse_opera_adr(&adr) {
                            if opts.time_in_range(bm.created) {
                                out.push(UnifiedBookmarkRecord {
                                    browser: t.browser_name.clone(),
                                    profile: t.profile_name.clone(),
                                    folder_path: bm.folder_path,
                                    title: bm.title,
                                    url: bm.url,
                                    created: bm.created,
                                    modified: bm.visited,
                                    guid: bm.unique_id,
                                    source_artifact: fname.to_string(),
                                });
                            }
                        }
                    }
                }
            }
            _ => {
                for bm in parse_bookmarks(&t.profile_dir, &mut warnings) {
                    if opts.time_in_range(bm.date_added) {
                        out.push(UnifiedBookmarkRecord {
                            browser: t.browser_name.clone(),
                            profile: t.profile_name.clone(),
                            folder_path: bm.folder_path,
                            title: bm.name,
                            url: bm.url,
                            created: bm.date_added,
                            modified: bm.date_last_used,
                            guid: bm.guid,
                            source_artifact: "Bookmarks".to_string(),
                        });
                    }
                }
            }
        }
    }

    out.sort_by(|a, b| b.created.cmp(&a.created).then_with(|| a.title.cmp(&b.title)));
    (out, warnings)
}

pub struct UnifiedBookmarksTableProvider {
    opts: UnifiedQueryOptions,
}

impl UnifiedBookmarksTableProvider {
    pub fn new(target: Option<PathBuf>) -> Self {
        Self {
            opts: UnifiedQueryOptions::from_optional_path(target.as_deref()),
        }
    }

    pub fn with_options(opts: UnifiedQueryOptions) -> Self {
        Self { opts }
    }
}

impl TableProvider for UnifiedBookmarksTableProvider {
    fn tool_id(&self) -> &'static str {
        "chrome2rust_unified_bookmarks"
    }

    fn description(&self) -> &'static str {
        "Aggregate normalized bookmarks across Chrome, Edge, Brave, Opera, Firefox, and Safari (WebBrowserBookmarksView equivalent)."
    }

    fn schema(&self) -> TableSchema {
        TableSchema::new(
            self.tool_id(),
            "Unified Browser Bookmarks",
            vec![
                ColumnDef::new("browser", "Browser", ColumnType::Text).with_width_hint(120),
                ColumnDef::new("profile", "Profile", ColumnType::Text).with_width_hint(100),
                ColumnDef::new("folder_path", "Folder Path", ColumnType::Text).with_width_hint(170),
                ColumnDef::new("title", "Title", ColumnType::Text).with_width_hint(180),
                ColumnDef::new("url", "URL", ColumnType::Text).with_width_hint(280),
                ColumnDef::new("created", "Created", ColumnType::Timestamp).with_width_hint(160),
                ColumnDef::new("modified", "Modified", ColumnType::Timestamp).with_width_hint(160),
                ColumnDef::new("guid", "GUID", ColumnType::Text).with_width_hint(110),
                ColumnDef::new("source_artifact", "Source", ColumnType::Text).with_width_hint(120),
            ],
        )
        .with_default_sort(5, SortDirection::Desc)
    }

    fn query(&self, req: &TableQuery) -> Result<TableData, TableError> {
        let (records, _) = collect_unified_bookmarks(&self.opts);
        let rows: Vec<Row> = records
            .into_iter()
            .enumerate()
            .map(|(idx, r)| {
                Row::new(
                    idx as u64 + 1,
                    vec![
                        CellValue::Text(r.browser.clone()),
                        CellValue::Text(r.profile.clone()),
                        CellValue::Text(r.folder_path.clone()),
                        CellValue::Text(r.title.clone()),
                        CellValue::Text(r.url.clone()),
                        r.created.map(CellValue::Timestamp).unwrap_or(CellValue::Null),
                        r.modified.map(CellValue::Timestamp).unwrap_or(CellValue::Null),
                        CellValue::Text(r.guid.clone()),
                        CellValue::Text(r.source_artifact.clone()),
                    ],
                )
                .with_detail_json(serde_json::to_value(&r).unwrap_or_default())
            })
            .collect();
        apply_query(&self.schema(), &rows, req)
    }
}

// =========================================================================
// 5. unified autofill (STRICTLY NON-CREDENTIAL — R4 Safeguard)
// =========================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnifiedAutofillRecord {
    pub browser: String,
    pub profile: String,
    pub field_name: String,
    pub value: String,
    pub use_count: i64,
    pub first_used: Option<DateTime<Utc>>,
    pub last_used: Option<DateTime<Utc>>,
    pub source_db: String,
}

/// Aggregates ONLY non-credential form autofill entries (`Web Data` `autofill` via `parse_autofill_only`
/// and Firefox `formhistory.sqlite` `moz_formhistory`). Never reads cards, IBANs, or logins (R4).
pub fn collect_unified_autofill(opts: &UnifiedQueryOptions) -> (Vec<UnifiedAutofillRecord>, Vec<DiagnosticWarning>) {
    let mut warnings = Vec::new();
    let mut out = Vec::new();

    for t in opts.resolve_targets() {
        if t.browser == UnifiedBrowserKind::Firefox {
            for rec in parse_firefox_formhistory(&t.profile_dir, &mut warnings) {
                if opts.time_in_range(rec.last_used) {
                    out.push(UnifiedAutofillRecord {
                        browser: t.browser_name.clone(),
                        profile: t.profile_name.clone(),
                        field_name: rec.field_name,
                        value: rec.value,
                        use_count: rec.times_used,
                        first_used: rec.first_used,
                        last_used: rec.last_used,
                        source_db: "formhistory.sqlite".to_string(),
                    });
                }
            }
        } else if is_chromium_like(t.browser) {
            for rec in parse_autofill_only(&t.profile_dir, &mut warnings) {
                if opts.time_in_range(rec.date_last_used) {
                    out.push(UnifiedAutofillRecord {
                        browser: t.browser_name.clone(),
                        profile: t.profile_name.clone(),
                        field_name: rec.name,
                        value: rec.value,
                        use_count: rec.count,
                        first_used: rec.date_created,
                        last_used: rec.date_last_used,
                        source_db: "Web Data (autofill)".to_string(),
                    });
                }
            }
        }
    }

    out.sort_by(|a, b| {
        b.last_used
            .cmp(&a.last_used)
            .then_with(|| a.field_name.cmp(&b.field_name))
    });
    (out, warnings)
}

pub struct UnifiedAutofillTableProvider {
    opts: UnifiedQueryOptions,
}

impl UnifiedAutofillTableProvider {
    pub fn new(target: Option<PathBuf>) -> Self {
        Self {
            opts: UnifiedQueryOptions::from_optional_path(target.as_deref()),
        }
    }

    pub fn with_options(opts: UnifiedQueryOptions) -> Self {
        Self { opts }
    }
}

impl TableProvider for UnifiedAutofillTableProvider {
    fn tool_id(&self) -> &'static str {
        "chrome2rust_unified_autofill"
    }

    fn description(&self) -> &'static str {
        "Aggregate non-credential form autofill history from Chrome Web Data (autofill table only) and Firefox formhistory.sqlite."
    }

    fn schema(&self) -> TableSchema {
        TableSchema::new(
            self.tool_id(),
            "Unified Form Autofill History (Non-Credential)",
            vec![
                ColumnDef::new("browser", "Browser", ColumnType::Text).with_width_hint(120),
                ColumnDef::new("profile", "Profile", ColumnType::Text).with_width_hint(100),
                ColumnDef::new("field_name", "Field Name", ColumnType::Text).with_width_hint(140),
                ColumnDef::new("value", "Value", ColumnType::Text).with_width_hint(220),
                ColumnDef::new("use_count", "Use Count", ColumnType::Int).with_width_hint(85),
                ColumnDef::new("first_used", "First Used", ColumnType::Timestamp).with_width_hint(160),
                ColumnDef::new("last_used", "Last Used", ColumnType::Timestamp).with_width_hint(160),
                ColumnDef::new("source_db", "Source DB", ColumnType::Text).with_width_hint(140),
            ],
        )
        .with_default_sort(6, SortDirection::Desc)
    }

    fn query(&self, req: &TableQuery) -> Result<TableData, TableError> {
        let (records, _) = collect_unified_autofill(&self.opts);
        let rows: Vec<Row> = records
            .into_iter()
            .enumerate()
            .map(|(idx, r)| {
                Row::new(
                    idx as u64 + 1,
                    vec![
                        CellValue::Text(r.browser.clone()),
                        CellValue::Text(r.profile.clone()),
                        CellValue::Text(r.field_name.clone()),
                        CellValue::Text(r.value.clone()),
                        CellValue::Int(r.use_count),
                        r.first_used.map(CellValue::Timestamp).unwrap_or(CellValue::Null),
                        r.last_used.map(CellValue::Timestamp).unwrap_or(CellValue::Null),
                        CellValue::Text(r.source_db.clone()),
                    ],
                )
                .with_detail_json(serde_json::to_value(&r).unwrap_or_default())
            })
            .collect();
        apply_query(&self.schema(), &rows, req)
    }
}
