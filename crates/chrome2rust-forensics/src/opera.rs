use crate::history::parse_history;
use chrome2rust_core::discovery::{UnifiedBrowserKind, discover_opera_profiles, resolve_unified_targets};
use chrome2rust_core::error::DiagnosticWarning;
use chrome2rust_core::time::unix_secs_to_datetime;
use chrono::{DateTime, Utc};
use guap_table::{
    CellValue, ColumnDef, ColumnType, Row, SortDirection, TableData, TableError, TableProvider, TableQuery,
    TableSchema, apply_query,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperaHistoryRecord {
    pub url: String,
    pub title: String,
    pub visit_time: Option<DateTime<Utc>>,
    pub visit_count: i64,
    pub profile: String,
    pub source_format: String,
    pub referrer: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperaAdrBookmark {
    pub title: String,
    pub url: String,
    pub folder_path: String,
    pub created: Option<DateTime<Utc>>,
    pub visited: Option<DateTime<Utc>>,
    pub unique_id: String,
}

/// Parses Opera Presto `global_history.dat` (4-line records: title, url, unix_secs, popularity).
pub fn parse_presto_global_history(path: &Path, profile_name: &str) -> Vec<OperaHistoryRecord> {
    let Ok(bytes) = std::fs::read(path) else {
        return Vec::new();
    };
    let text = String::from_utf8_lossy(&bytes);
    let lines: Vec<&str> = text
        .lines()
        .map(|l| l.trim_end_matches('\r'))
        .filter(|l| !l.trim().is_empty())
        .collect();

    let mut out = Vec::new();
    let mut i = 0usize;
    while i + 3 < lines.len() {
        let title = lines[i].trim().to_string();
        let url = lines[i + 1].trim().to_string();
        let ts = lines[i + 2].trim().parse::<i64>().unwrap_or(0);
        let pop = lines[i + 3].trim().parse::<i64>().unwrap_or(1).max(1);
        if url.contains("://") || url.starts_with("opera:") {
            out.push(OperaHistoryRecord {
                url,
                title,
                visit_time: unix_secs_to_datetime(ts),
                visit_count: pop,
                profile: profile_name.to_string(),
                source_format: "Presto global_history.dat".to_string(),
                referrer: String::new(),
            });
            i += 4;
        } else {
            i += 1;
        }
    }
    out
}

/// Parses Opera Presto `opera6.adr` / `bookmarks.adr` (Opera Hotlist version 2.0).
pub fn parse_opera_adr(path: &Path) -> Vec<OperaAdrBookmark> {
    let Ok(bytes) = std::fs::read(path) else {
        return Vec::new();
    };
    let text = String::from_utf8_lossy(&bytes);
    let mut folder_stack: Vec<String> = Vec::new();
    let mut out = Vec::new();

    enum Section {
        None,
        Folder {
            name: String,
        },
        Url {
            name: String,
            url: String,
            created: Option<DateTime<Utc>>,
            visited: Option<DateTime<Utc>>,
            unique_id: String,
        },
    }

    let mut cur = Section::None;
    let flush = |sec: &mut Section, stack: &mut Vec<String>, out: &mut Vec<OperaAdrBookmark>| match std::mem::replace(
        sec,
        Section::None,
    ) {
        Section::Folder { name } => {
            stack.push(name);
        }
        Section::Url {
            name,
            url,
            created,
            visited,
            unique_id,
        } => {
            if !url.is_empty() {
                out.push(OperaAdrBookmark {
                    title: name,
                    url,
                    folder_path: stack.join(" / "),
                    created,
                    visited,
                    unique_id,
                });
            }
        }
        Section::None => {}
    };

    for raw_line in text.lines() {
        let line = raw_line.trim();
        if line == "#FOLDER" {
            flush(&mut cur, &mut folder_stack, &mut out);
            cur = Section::Folder { name: String::new() };
        } else if line == "#URL" {
            flush(&mut cur, &mut folder_stack, &mut out);
            cur = Section::Url {
                name: String::new(),
                url: String::new(),
                created: None,
                visited: None,
                unique_id: String::new(),
            };
        } else if line == "-" {
            flush(&mut cur, &mut folder_stack, &mut out);
            folder_stack.pop();
        } else if let Some((k, v)) = line.split_once('=') {
            let key = k.trim();
            let val = v.trim();
            match &mut cur {
                Section::Folder { name } => {
                    if key == "NAME" {
                        *name = val.to_string();
                    }
                }
                Section::Url {
                    name,
                    url,
                    created,
                    visited,
                    unique_id,
                } => match key {
                    "NAME" => *name = val.to_string(),
                    "URL" => *url = val.to_string(),
                    "CREATED" => *created = val.parse::<i64>().ok().and_then(unix_secs_to_datetime),
                    "VISITED" => *visited = val.parse::<i64>().ok().and_then(unix_secs_to_datetime),
                    "UNIQUEID" => *unique_id = val.to_string(),
                    _ => {}
                },
                Section::None => {}
            }
        }
    }
    flush(&mut cur, &mut folder_stack, &mut out);
    out
}

pub fn parse_opera_history(target: Option<&Path>, warnings: &mut Vec<DiagnosticWarning>) -> Vec<OperaHistoryRecord> {
    let targets = if let Some(p) = target {
        let resolved = resolve_unified_targets(&[p.to_path_buf()]);
        let op: Vec<_> = resolved
            .into_iter()
            .filter(|t| {
                matches!(
                    t.browser,
                    UnifiedBrowserKind::Opera | UnifiedBrowserKind::OperaGx | UnifiedBrowserKind::OperaPresto
                )
            })
            .collect();
        if op.is_empty() {
            // Treat explicit path directly as an Opera dir/file
            let pname = p
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_else(|| "Opera".to_string());
            let dir = if p.is_file() {
                p.parent().unwrap_or(p).to_path_buf()
            } else {
                p.to_path_buf()
            };
            vec![chrome2rust_core::discovery::UnifiedProfileTarget {
                browser: UnifiedBrowserKind::Opera,
                browser_name: "Opera".to_string(),
                profile_name: pname,
                profile_dir: dir,
                cache_dirs: Vec::new(),
            }]
        } else {
            op
        }
    } else {
        discover_opera_profiles()
    };

    let mut out = Vec::new();
    for t in targets {
        // Blink History SQLite
        if t.profile_dir.join("History").is_file() {
            let hist = parse_history(&t.profile_dir, warnings);
            let url_counts: HashMap<i64, i64> = hist.urls.iter().map(|u| (u.id, u.visit_count)).collect();
            let visit_urls: HashMap<i64, String> = hist.visits.iter().map(|v| (v.visit_id, v.url.clone())).collect();
            for v in &hist.visits {
                out.push(OperaHistoryRecord {
                    url: v.url.clone(),
                    title: v.title.clone(),
                    visit_time: v.visit_time,
                    visit_count: url_counts.get(&v.url_id).copied().unwrap_or(1),
                    profile: t.profile_name.clone(),
                    source_format: "Blink History SQLite".to_string(),
                    referrer: visit_urls.get(&v.from_visit).cloned().unwrap_or_default(),
                });
            }
            if hist.visits.is_empty() {
                for u in &hist.urls {
                    out.push(OperaHistoryRecord {
                        url: u.url.clone(),
                        title: u.title.clone(),
                        visit_time: u.last_visit_time,
                        visit_count: u.visit_count,
                        profile: t.profile_name.clone(),
                        source_format: "Blink History SQLite".to_string(),
                        referrer: String::new(),
                    });
                }
            }
        }

        // Presto global_history.dat
        let gh = t.profile_dir.join("global_history.dat");
        if gh.is_file() {
            out.extend(parse_presto_global_history(&gh, &t.profile_name));
        }

        // Presto bookmarks with VISITED timestamps
        for adr_name in ["opera6.adr", "bookmarks.adr"] {
            let adr = t.profile_dir.join(adr_name);
            if adr.is_file() {
                for bm in parse_opera_adr(&adr) {
                    if bm.visited.is_some() {
                        out.push(OperaHistoryRecord {
                            url: bm.url,
                            title: bm.title,
                            visit_time: bm.visited,
                            visit_count: 1,
                            profile: t.profile_name.clone(),
                            source_format: format!("Presto {adr_name}"),
                            referrer: String::new(),
                        });
                    }
                }
            }
        }
    }

    out.sort_by(|a, b| b.visit_time.cmp(&a.visit_time).then_with(|| a.url.cmp(&b.url)));
    out
}

pub struct OperaHistoryTableProvider {
    target: Option<PathBuf>,
}

impl OperaHistoryTableProvider {
    pub fn new(target: Option<PathBuf>) -> Self {
        Self { target }
    }
}

impl TableProvider for OperaHistoryTableProvider {
    fn tool_id(&self) -> &'static str {
        "chrome2rust_opera_history"
    }

    fn description(&self) -> &'static str {
        "Inspect Opera Blink (History SQLite) and Opera Presto (global_history.dat / opera6.adr) browsing history."
    }

    fn schema(&self) -> TableSchema {
        TableSchema::new(
            self.tool_id(),
            "Opera Browsing History",
            vec![
                ColumnDef::new("url", "URL", ColumnType::Text).with_width_hint(300),
                ColumnDef::new("title", "Title", ColumnType::Text).with_width_hint(200),
                ColumnDef::new("visit_time", "Visit Time", ColumnType::Timestamp).with_width_hint(160),
                ColumnDef::new("visit_count", "Visit Count", ColumnType::Int).with_width_hint(85),
                ColumnDef::new("profile", "Profile", ColumnType::Text).with_width_hint(100),
                ColumnDef::new("source_format", "Source Format", ColumnType::Text).with_width_hint(150),
            ],
        )
        .with_default_sort(2, SortDirection::Desc)
    }

    fn query(&self, req: &TableQuery) -> Result<TableData, TableError> {
        let mut warnings = Vec::new();
        let records = parse_opera_history(self.target.as_deref(), &mut warnings);
        let rows: Vec<Row> = records
            .into_iter()
            .enumerate()
            .map(|(idx, r)| {
                Row::new(
                    idx as u64 + 1,
                    vec![
                        CellValue::Text(r.url.clone()),
                        CellValue::Text(r.title.clone()),
                        r.visit_time.map(CellValue::Timestamp).unwrap_or(CellValue::Null),
                        CellValue::Int(r.visit_count),
                        CellValue::Text(r.profile.clone()),
                        CellValue::Text(r.source_format.clone()),
                    ],
                )
                .with_detail_json(serde_json::to_value(&r).unwrap_or_default())
            })
            .collect();
        apply_query(&self.schema(), &rows, req)
    }
}
