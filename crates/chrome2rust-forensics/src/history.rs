use chrome2rust_core::error::DiagnosticWarning;
use chrome2rust_core::sqlite_util::ForensicSqlite;
use chrome2rust_core::time::chrome_us_to_datetime;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HistoryAnalysis {
    pub urls: Vec<HistoryUrlRecord>,
    pub visits: Vec<HistoryVisitRecord>,
    pub downloads: Vec<DownloadRecord>,
    pub search_terms: Vec<SearchTermRecord>,
    pub deletion_indicators: HistoryDeletionIndicators,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoryUrlRecord {
    pub id: i64,
    pub url: String,
    pub title: String,
    pub visit_count: i64,
    pub typed_count: i64,
    pub last_visit_time: Option<DateTime<Utc>>,
    pub hidden: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoryVisitRecord {
    pub visit_id: i64,
    pub url_id: i64,
    pub url: String,
    pub title: String,
    pub visit_time: Option<DateTime<Utc>>,
    pub from_visit: i64,
    pub transition_raw: i64,
    pub transition_core: String,
    pub transition_qualifiers: Vec<String>,
    pub visit_duration_ms: i64,
    pub source: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DownloadRecord {
    pub id: i64,
    pub guid: String,
    pub current_path: String,
    pub target_path: String,
    pub url_chain: Vec<String>,
    pub start_time: Option<DateTime<Utc>>,
    pub end_time: Option<DateTime<Utc>>,
    pub received_bytes: i64,
    pub total_bytes: i64,
    pub state: String,
    pub danger_type: String,
    pub interrupt_reason: i64,
    pub mime_type: String,
    pub original_mime_type: String,
    pub referrer: String,
    pub tab_url: String,
    pub opened: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchTermRecord {
    pub url_id: i64,
    pub term: String,
    pub normalized_term: String,
    pub url: Option<String>,
    pub last_visit_time: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HistoryDeletionIndicators {
    pub urls_row_count: i64,
    pub urls_max_id: i64,
    pub urls_min_id: i64,
    pub urls_sqlite_seq: i64,
    pub urls_estimated_deleted: i64,
    pub visits_row_count: i64,
    pub visits_max_id: i64,
    pub visits_sqlite_seq: i64,
    pub visits_estimated_deleted: i64,
    pub hidden_urls_count: i64,
}

pub fn decode_transition(raw: i64) -> (String, Vec<String>) {
    let core_val = raw & 0xFF;
    let core = match core_val {
        0 => "LINK",
        1 => "TYPED",
        2 => "AUTO_BOOKMARK",
        3 => "AUTO_SUBFRAME",
        4 => "MANUAL_SUBFRAME",
        5 => "GENERATED",
        6 => "AUTO_TOPLEVEL",
        7 => "FORM_SUBMIT",
        8 => "RELOAD",
        9 => "KEYWORD",
        10 => "KEYWORD_GENERATED",
        other => return (format!("UNKNOWN({other})"), decode_qualifiers(raw)),
    };
    (core.to_string(), decode_qualifiers(raw))
}

fn decode_qualifiers(raw: i64) -> Vec<String> {
    let mut q = Vec::new();
    let u = raw as u32;
    if (u & 0x0080_0000) != 0 {
        q.push("BLOCKED".into());
    }
    if (u & 0x0100_0000) != 0 {
        q.push("FORWARD_BACK".into());
    }
    if (u & 0x0200_0000) != 0 {
        q.push("FROM_ADDRESS_BAR".into());
    }
    if (u & 0x0400_0000) != 0 {
        q.push("HOME_PAGE".into());
    }
    if (u & 0x0800_0000) != 0 {
        q.push("FROM_API".into());
    }
    if (u & 0x1000_0000) != 0 {
        q.push("CHAIN_START".into());
    }
    if (u & 0x2000_0000) != 0 {
        q.push("CHAIN_END".into());
    }
    if (u & 0x4000_0000) != 0 {
        q.push("CLIENT_REDIRECT".into());
    }
    if (u & 0x8000_0000) != 0 {
        q.push("SERVER_REDIRECT".into());
    }
    q
}

fn decode_download_state(state: i64) -> &'static str {
    match state {
        0 => "IN_PROGRESS",
        1 => "COMPLETE",
        2 => "CANCELLED",
        3 => "INTERRUPTED",
        _ => "UNKNOWN",
    }
}

fn decode_danger_type(dt: i64) -> &'static str {
    match dt {
        0 => "NOT_DANGEROUS",
        1 => "DANGEROUS_FILE",
        2 => "DANGEROUS_URL",
        3 => "DANGEROUS_CONTENT",
        4 => "MAYBE_DANGEROUS_CONTENT",
        5 => "UNCOMMON_CONTENT",
        6 => "USER_VALIDATED",
        7 => "DANGEROUS_HOST",
        8 => "POTENTIALLY_UNWANTED",
        9 => "ALLOWLISTED_BY_POLICY",
        10 => "ASYNC_SCANNING",
        11 => "BLOCKED_PASSWORD_PROTECTED",
        12 => "BLOCKED_TOO_LARGE",
        13 => "SENSITIVE_CONTENT_WARNING",
        14 => "SENSITIVE_CONTENT_BLOCK",
        15 => "DEEP_SCANNED_SAFE",
        16 => "DEEP_SCANNED_OPENED_DANGEROUS",
        17 => "PROMPT_FOR_SCANNING",
        18 => "BLOCKED_UNSUPPORTED_FILETYPE",
        _ => "UNKNOWN",
    }
}

fn decode_visit_source(src: i64) -> &'static str {
    match src {
        0 => "SYNCED",
        1 => "BROWSED",
        2 => "EXTENSION",
        3 => "FIREFOX_IMPORTED",
        4 => "IE_IMPORTED",
        5 => "SAFARI_IMPORTED",
        _ => "BROWSED",
    }
}

pub fn parse_history(profile_dir: &Path, warnings: &mut Vec<DiagnosticWarning>) -> HistoryAnalysis {
    let mut out = HistoryAnalysis::default();
    let db_path = profile_dir.join("History");
    if !db_path.is_file() {
        return out;
    }

    let db = match ForensicSqlite::open_snapshot(&db_path) {
        Ok(d) => d,
        Err(e) => {
            warnings.push(DiagnosticWarning::warn(
                "history",
                &db_path,
                format!("Failed to open History DB: {e}"),
            ));
            return out;
        }
    };

    let tables = db.list_tables();
    let mut url_map: HashMap<i64, (String, String, Option<DateTime<Utc>>)> = HashMap::new();

    if tables.contains("urls") {
        let cols = db.table_columns("urls");
        let has_hidden = cols.contains("hidden");
        let sql = format!(
            "SELECT id, url, title, visit_count, typed_count, last_visit_time, {} FROM urls ORDER BY last_visit_time DESC",
            if has_hidden { "hidden" } else { "0" }
        );
        if let Ok(mut stmt) = db.conn.prepare(&sql)
            && let Ok(rows) = stmt.query_map([], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1).unwrap_or_default(),
                    row.get::<_, String>(2).unwrap_or_default(),
                    row.get::<_, i64>(3).unwrap_or(0),
                    row.get::<_, i64>(4).unwrap_or(0),
                    row.get::<_, i64>(5).unwrap_or(0),
                    row.get::<_, i64>(6).unwrap_or(0),
                ))
            })
        {
            for r in rows.flatten() {
                let dt = chrome_us_to_datetime(r.5);
                let hidden = r.6 != 0;
                if hidden {
                    out.deletion_indicators.hidden_urls_count += 1;
                }
                url_map.insert(r.0, (r.1.clone(), r.2.clone(), dt));
                out.urls.push(HistoryUrlRecord {
                    id: r.0,
                    url: r.1,
                    title: r.2,
                    visit_count: r.3,
                    typed_count: r.4,
                    last_visit_time: dt,
                    hidden,
                });
            }
        }
    }

    let mut visit_sources: HashMap<i64, i64> = HashMap::new();
    if tables.contains("visit_source")
        && let Ok(mut stmt) = db.conn.prepare("SELECT id, source FROM visit_source")
        && let Ok(rows) = stmt.query_map([], |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)))
    {
        for (id, src) in rows.flatten() {
            visit_sources.insert(id, src);
        }
    }

    if tables.contains("visits") {
        let cols = db.table_columns("visits");
        let dur_col = if cols.contains("visit_duration") {
            "visit_duration"
        } else {
            "0"
        };
        let from_col = if cols.contains("from_visit") { "from_visit" } else { "0" };
        let trans_col = if cols.contains("transition") { "transition" } else { "0" };
        let sql = format!(
            "SELECT id, url, visit_time, {from_col}, {trans_col}, {dur_col} FROM visits ORDER BY visit_time DESC"
        );
        if let Ok(mut stmt) = db.conn.prepare(&sql)
            && let Ok(rows) = stmt.query_map([], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2).unwrap_or(0),
                    row.get::<_, i64>(3).unwrap_or(0),
                    row.get::<_, i64>(4).unwrap_or(0),
                    row.get::<_, i64>(5).unwrap_or(0),
                ))
            })
        {
            for r in rows.flatten() {
                let (url, title, _) = url_map
                    .get(&r.1)
                    .cloned()
                    .unwrap_or_else(|| (String::new(), String::new(), None));
                let (core, qualifiers) = decode_transition(r.4);
                let src_code = visit_sources.get(&r.0).copied().unwrap_or(1);
                out.visits.push(HistoryVisitRecord {
                    visit_id: r.0,
                    url_id: r.1,
                    url,
                    title,
                    visit_time: chrome_us_to_datetime(r.2),
                    from_visit: r.3,
                    transition_raw: r.4,
                    transition_core: core,
                    transition_qualifiers: qualifiers,
                    visit_duration_ms: r.5 / 1000,
                    source: decode_visit_source(src_code).to_string(),
                });
            }
        }
    }

    // Downloads & download url chains
    let mut url_chains: HashMap<i64, Vec<String>> = HashMap::new();
    if tables.contains("downloads_url_chains")
        && let Ok(mut stmt) = db
            .conn
            .prepare("SELECT id, chain_index, url FROM downloads_url_chains ORDER BY id, chain_index")
        && let Ok(rows) = stmt.query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, String>(2).unwrap_or_default(),
            ))
        })
    {
        for (id, _, url) in rows.flatten() {
            url_chains.entry(id).or_default().push(url);
        }
    }

    if tables.contains("downloads") {
        let cols = db.table_columns("downloads");
        let sel = |col: &str, default_expr: &str| -> String {
            if cols.contains(col) {
                col.to_string()
            } else {
                default_expr.to_string()
            }
        };
        let sql = format!(
            "SELECT id, {}, {}, {}, start_time, end_time, received_bytes, total_bytes, state, danger_type, interrupt_reason, {}, {}, {}, {}, {} FROM downloads ORDER BY start_time DESC",
            sel("guid", "''"),
            sel("current_path", "''"),
            sel("target_path", "''"),
            sel("mime_type", "''"),
            sel("original_mime_type", "''"),
            sel("referrer", "''"),
            sel("tab_url", "''"),
            sel("opened", "0"),
        );
        if let Ok(mut stmt) = db.conn.prepare(&sql)
            && let Ok(rows) = stmt.query_map([], |row| {
                Ok(DownloadRecord {
                    id: row.get(0)?,
                    guid: row.get::<_, String>(1).unwrap_or_default(),
                    current_path: row.get::<_, String>(2).unwrap_or_default(),
                    target_path: row.get::<_, String>(3).unwrap_or_default(),
                    url_chain: Vec::new(),
                    start_time: chrome_us_to_datetime(row.get::<_, i64>(4).unwrap_or(0)),
                    end_time: chrome_us_to_datetime(row.get::<_, i64>(5).unwrap_or(0)),
                    received_bytes: row.get::<_, i64>(6).unwrap_or(0),
                    total_bytes: row.get::<_, i64>(7).unwrap_or(0),
                    state: decode_download_state(row.get::<_, i64>(8).unwrap_or(-1)).to_string(),
                    danger_type: decode_danger_type(row.get::<_, i64>(9).unwrap_or(0)).to_string(),
                    interrupt_reason: row.get::<_, i64>(10).unwrap_or(0),
                    mime_type: row.get::<_, String>(11).unwrap_or_default(),
                    original_mime_type: row.get::<_, String>(12).unwrap_or_default(),
                    referrer: row.get::<_, String>(13).unwrap_or_default(),
                    tab_url: row.get::<_, String>(14).unwrap_or_default(),
                    opened: row.get::<_, i64>(15).unwrap_or(0) != 0,
                })
            })
        {
            for mut d in rows.flatten() {
                if let Some(chain) = url_chains.remove(&d.id) {
                    d.url_chain = chain;
                }
                out.downloads.push(d);
            }
        }
    }

    // Keyword search terms
    if tables.contains("keyword_search_terms") {
        let cols = db.table_columns("keyword_search_terms");
        let norm_col = if cols.contains("normalized_term") {
            "normalized_term"
        } else {
            "term"
        };
        let sql = format!("SELECT url_id, term, {norm_col} FROM keyword_search_terms");
        if let Ok(mut stmt) = db.conn.prepare(&sql)
            && let Ok(rows) = stmt.query_map([], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1).unwrap_or_default(),
                    row.get::<_, String>(2).unwrap_or_default(),
                ))
            })
        {
            for (url_id, term, norm) in rows.flatten() {
                let (url, _, dt) = url_map
                    .get(&url_id)
                    .cloned()
                    .unwrap_or((String::new(), String::new(), None));
                out.search_terms.push(SearchTermRecord {
                    url_id,
                    term,
                    normalized_term: norm,
                    url: if url.is_empty() { None } else { Some(url) },
                    last_visit_time: dt,
                });
            }
        }
    }

    // Deletion gap indicators via sqlite_sequence and MIN/MAX id
    let mut seqs: HashMap<String, i64> = HashMap::new();
    if tables.contains("sqlite_sequence")
        && let Ok(mut stmt) = db.conn.prepare("SELECT name, seq FROM sqlite_sequence")
        && let Ok(rows) = stmt.query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)))
    {
        for (name, seq) in rows.flatten() {
            seqs.insert(name, seq);
        }
    }

    if let Ok((cnt, min_id, max_id)) = db.conn.query_row(
        "SELECT COUNT(*), COALESCE(MIN(id), 0), COALESCE(MAX(id), 0) FROM urls",
        [],
        |r| Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?, r.get::<_, i64>(2)?)),
    ) {
        let seq = seqs.get("urls").copied().unwrap_or(max_id);
        let high = seq.max(max_id);
        out.deletion_indicators.urls_row_count = cnt;
        out.deletion_indicators.urls_min_id = min_id;
        out.deletion_indicators.urls_max_id = max_id;
        out.deletion_indicators.urls_sqlite_seq = seq;
        out.deletion_indicators.urls_estimated_deleted = (high - cnt).max(0);
    }

    if let Ok((cnt, max_id)) = db
        .conn
        .query_row("SELECT COUNT(*), COALESCE(MAX(id), 0) FROM visits", [], |r| {
            Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?))
        })
    {
        let seq = seqs.get("visits").copied().unwrap_or(max_id);
        let high = seq.max(max_id);
        out.deletion_indicators.visits_row_count = cnt;
        out.deletion_indicators.visits_max_id = max_id;
        out.deletion_indicators.visits_sqlite_seq = seq;
        out.deletion_indicators.visits_estimated_deleted = (high - cnt).max(0);
    }

    out
}
