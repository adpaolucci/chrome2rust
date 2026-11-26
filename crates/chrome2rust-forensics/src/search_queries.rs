use crate::firefox::parse_firefox_sessions;
use crate::history::parse_history;
use crate::sessions::parse_sessions;
use crate::unified::{UnifiedQueryOptions, collect_unified_history};
use chrome2rust_cache::unified_cache::load_unified_cache;
use chrome2rust_core::discovery::UnifiedBrowserKind;
use chrome2rust_core::error::DiagnosticWarning;
use chrono::{DateTime, Utc};
use guap_table::{
    CellValue, ColumnDef, ColumnType, Row, SortDirection, TableData, TableError, TableProvider, TableQuery,
    TableSchema, apply_query,
};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchQueryRecord {
    pub browser: String,
    pub profile: String,
    pub engine: String,
    pub search_query: String,
    pub search_time: Option<DateTime<Utc>>,
    pub result_url: String,
    pub search_url: String,
    pub source: String,
    pub match_via: String,
}

fn match_engine_and_params(host: &str, path: &str) -> Option<(&'static str, &'static [&'static str], bool)> {
    let h = host.trim_start_matches("www.").to_ascii_lowercase();
    let p = path.to_ascii_lowercase();

    if h == "google.com" || h.starts_with("google.") || h.ends_with(".google.com") || h.contains(".google.") {
        return Some(("Google", &["q", "as_q"], true));
    }
    if h == "bing.com" || h.ends_with(".bing.com") {
        return Some(("Bing", &["q"], false));
    }
    if h == "duckduckgo.com" || h.ends_with(".duckduckgo.com") {
        return Some(("DuckDuckGo", &["q"], false));
    }
    if h == "search.yahoo.com" || h.ends_with(".search.yahoo.com") || (h == "yahoo.com" && p.contains("/search")) {
        return Some(("Yahoo", &["p", "q"], false));
    }
    if h == "ya.ru" || h == "yandex.ru" || h.starts_with("yandex.") || h.ends_with(".yandex.ru") {
        return Some(("Yandex", &["text"], false));
    }
    if h == "baidu.com" || h.ends_with(".baidu.com") {
        return Some(("Baidu", &["wd", "word", "bs"], false));
    }
    if (h == "youtube.com" || h.ends_with(".youtube.com") || h == "youtu.be") && p.contains("/results") {
        return Some(("YouTube", &["search_query", "q"], false));
    }
    if h == "search.brave.com" {
        return Some(("Brave Search", &["q", "query"], false));
    }
    if h == "startpage.com" || h.ends_with(".startpage.com") {
        return Some(("Startpage", &["query", "q"], false));
    }
    if h == "ecosia.org" || h.ends_with(".ecosia.org") {
        return Some(("Ecosia", &["q"], false));
    }
    if p.contains("/search") || h.starts_with("search.") {
        return Some((
            "Generic Search",
            &["q", "query", "search_query", "wd", "text", "p"],
            false,
        ));
    }
    None
}

/// Extracts `(engine, decoded_query, match_via)` from a URL query string or hash fragment (`#q=...`).
pub fn extract_search_query_from_url(raw_url: &str) -> Option<(String, String, String)> {
    let parsed = url::Url::parse(raw_url).ok()?;
    let host = parsed.host_str()?;
    let (engine, params, check_frag) = match_engine_and_params(host, parsed.path())?;

    for target_key in params {
        for (k, v) in parsed.query_pairs() {
            if k == *target_key {
                let q = v.trim();
                if !q.is_empty() {
                    return Some((engine.to_string(), q.to_string(), "URL".to_string()));
                }
            }
        }
    }

    if let Some(frag) = parsed.fragment()
        && (check_frag || frag.contains("q="))
    {
        let frag_query = frag.trim_start_matches('?');
        for target_key in params {
            for (k, v) in url::form_urlencoded::parse(frag_query.as_bytes()) {
                if k == *target_key {
                    let q = v.trim();
                    if !q.is_empty() {
                        return Some((engine.to_string(), q.to_string(), "Fragment".to_string()));
                    }
                }
            }
        }
    }

    None
}

pub fn collect_search_queries(
    opts: &UnifiedQueryOptions,
    engine_filter: Option<&str>,
) -> (Vec<SearchQueryRecord>, Vec<DiagnosticWarning>) {
    let mut warnings = Vec::new();
    let mut out = Vec::new();
    let mut seen: HashSet<(String, String, String, String, String, Option<i64>)> = HashSet::new();

    let mut push_rec = |rec: SearchQueryRecord| {
        if let Some(ef) = engine_filter
            && !rec.engine.eq_ignore_ascii_case(ef)
        {
            return;
        }
        let key = (
            rec.browser.clone(),
            rec.profile.clone(),
            rec.engine.clone(),
            rec.search_query.to_ascii_lowercase(),
            rec.result_url.clone(),
            rec.search_time.map(|t| t.timestamp()),
        );
        if seen.insert(key) {
            out.push(rec);
        }
    };

    // 1. Unified History (direct URLs + referrer URLs)
    let (hist_records, mut hw) = collect_unified_history(opts);
    warnings.append(&mut hw);
    for h in hist_records {
        if let Some((engine, query, via)) = extract_search_query_from_url(&h.url) {
            push_rec(SearchQueryRecord {
                browser: h.browser.clone(),
                profile: h.profile.clone(),
                engine,
                search_query: query,
                search_time: h.visit_time,
                result_url: h.url.clone(),
                search_url: h.url.clone(),
                source: "History".to_string(),
                match_via: via,
            });
        } else if !h.referrer.is_empty()
            && let Some((engine, query, _)) = extract_search_query_from_url(&h.referrer)
        {
            push_rec(SearchQueryRecord {
                browser: h.browser,
                profile: h.profile,
                engine,
                search_query: query,
                search_time: h.visit_time,
                result_url: h.url,
                search_url: h.referrer,
                source: "History".to_string(),
                match_via: "Referer".to_string(),
            });
        }
    }

    let targets = opts.resolve_targets();

    // 2. Chromium keyword_search_terms + Sessions + Firefox Sessions
    for t in &targets {
        if t.browser == UnifiedBrowserKind::Firefox {
            for tab in parse_firefox_sessions(&t.profile_dir, &mut warnings) {
                if let Some((engine, query, via)) = extract_search_query_from_url(&tab.url) {
                    push_rec(SearchQueryRecord {
                        browser: t.browser_name.clone(),
                        profile: t.profile_name.clone(),
                        engine,
                        search_query: query,
                        search_time: tab.last_accessed,
                        result_url: tab.url.clone(),
                        search_url: tab.url,
                        source: "Session".to_string(),
                        match_via: via,
                    });
                }
            }
        } else if !matches!(t.browser, UnifiedBrowserKind::Safari | UnifiedBrowserKind::OperaPresto) {
            let hist = parse_history(&t.profile_dir, &mut warnings);
            let url_map: HashMap<i64, (&str, Option<DateTime<Utc>>)> = hist
                .urls
                .iter()
                .map(|u| (u.id, (u.url.as_str(), u.last_visit_time)))
                .collect();
            for st in &hist.search_terms {
                let Some((u_str, ts)) = url_map.get(&st.url_id) else {
                    continue;
                };
                let engine = url::Url::parse(u_str)
                    .ok()
                    .and_then(|u| {
                        u.host_str()
                            .and_then(|host| match_engine_and_params(host, u.path()).map(|m| m.0.to_string()))
                    })
                    .unwrap_or_else(|| "Browser Search".to_string());
                let term = st.term.trim();
                if !term.is_empty() {
                    push_rec(SearchQueryRecord {
                        browser: t.browser_name.clone(),
                        profile: t.profile_name.clone(),
                        engine,
                        search_query: term.to_string(),
                        search_time: *ts,
                        result_url: (*u_str).to_string(),
                        search_url: (*u_str).to_string(),
                        source: "History (keyword_search_terms)".to_string(),
                        match_via: "URL".to_string(),
                    });
                }
            }

            let sess = parse_sessions(&t.profile_dir, &mut warnings);
            for tab in sess.open_tabs.into_iter().chain(sess.closed_tabs) {
                let mut urls = vec![tab.current_url.clone()];
                for nav in tab.navigations {
                    if !nav.url.is_empty() && nav.url != tab.current_url {
                        urls.push(nav.url);
                    }
                }
                for u in urls {
                    if let Some((engine, query, via)) = extract_search_query_from_url(&u) {
                        push_rec(SearchQueryRecord {
                            browser: t.browser_name.clone(),
                            profile: t.profile_name.clone(),
                            engine,
                            search_query: query,
                            search_time: tab.timestamp,
                            result_url: u.clone(),
                            search_url: u,
                            source: "Session".to_string(),
                            match_via: via,
                        });
                    }
                }
            }
        }
    }

    // 3. Cache entries across all browsers (URL + HTTP Referer header)
    let (cache_items, mut cw) = load_unified_cache(&targets, false);
    warnings.append(&mut cw);
    for item in cache_items {
        if let Some((engine, query, via)) = extract_search_query_from_url(&item.url) {
            push_rec(SearchQueryRecord {
                browser: item.browser.clone(),
                profile: item.profile.clone(),
                engine,
                search_query: query,
                search_time: item.cache_time,
                result_url: item.url.clone(),
                search_url: item.url.clone(),
                source: "Cache".to_string(),
                match_via: via,
            });
        } else if let Some(referer) = item
            .headers
            .iter()
            .find(|h| h.name.eq_ignore_ascii_case("referer"))
            .map(|h| h.value.as_str())
            && let Some((engine, query, _)) = extract_search_query_from_url(referer)
        {
            push_rec(SearchQueryRecord {
                browser: item.browser,
                profile: item.profile,
                engine,
                search_query: query,
                search_time: item.cache_time,
                result_url: item.url,
                search_url: referer.to_string(),
                source: "Cache".to_string(),
                match_via: "Referer".to_string(),
            });
        }
    }

    out.sort_by(|a, b| {
        b.search_time
            .cmp(&a.search_time)
            .then_with(|| a.search_query.cmp(&b.search_query))
    });
    (out, warnings)
}

pub struct SearchQueriesTableProvider {
    opts: UnifiedQueryOptions,
    engine_filter: Option<String>,
}

impl SearchQueriesTableProvider {
    pub fn new(target: Option<PathBuf>) -> Self {
        Self {
            opts: UnifiedQueryOptions::from_optional_path(target.as_deref()),
            engine_filter: None,
        }
    }

    pub fn with_options(opts: UnifiedQueryOptions, engine_filter: Option<String>) -> Self {
        Self { opts, engine_filter }
    }
}

impl TableProvider for SearchQueriesTableProvider {
    fn tool_id(&self) -> &'static str {
        "chrome2rust_search_queries"
    }

    fn description(&self) -> &'static str {
        "Extract search engine queries (Google, Bing, DuckDuckGo, Yahoo, Yandex, Baidu, YouTube, Brave, Startpage, Ecosia) from history, cache URLs/Referer headers, and sessions (MyLastSearch equivalent)."
    }

    fn schema(&self) -> TableSchema {
        TableSchema::new(
            self.tool_id(),
            "Extracted Search Queries",
            vec![
                ColumnDef::new("browser", "Browser", ColumnType::Text).with_width_hint(120),
                ColumnDef::new("profile", "Profile", ColumnType::Text).with_width_hint(100),
                ColumnDef::new("engine", "Engine", ColumnType::Text).with_width_hint(100),
                ColumnDef::new("search_query", "Search Query", ColumnType::Text).with_width_hint(220),
                ColumnDef::new("search_time", "Search Time", ColumnType::Timestamp).with_width_hint(160),
                ColumnDef::new("result_url", "Result URL", ColumnType::Text).with_width_hint(260),
                ColumnDef::new("search_url", "Search URL", ColumnType::Text).with_width_hint(240),
                ColumnDef::new("source", "Source", ColumnType::Text).with_width_hint(90),
                ColumnDef::new("match_via", "Match Via", ColumnType::Text).with_width_hint(90),
            ],
        )
        .with_default_sort(4, SortDirection::Desc)
    }

    fn query(&self, req: &TableQuery) -> Result<TableData, TableError> {
        let (records, _) = collect_search_queries(&self.opts, self.engine_filter.as_deref());
        let rows: Vec<Row> = records
            .into_iter()
            .enumerate()
            .map(|(idx, r)| {
                Row::new(
                    idx as u64 + 1,
                    vec![
                        CellValue::Text(r.browser.clone()),
                        CellValue::Text(r.profile.clone()),
                        CellValue::Text(r.engine.clone()),
                        CellValue::Text(r.search_query.clone()),
                        r.search_time.map(CellValue::Timestamp).unwrap_or(CellValue::Null),
                        CellValue::Text(r.result_url.clone()),
                        CellValue::Text(r.search_url.clone()),
                        CellValue::Text(r.source.clone()),
                        CellValue::Text(r.match_via.clone()),
                    ],
                )
                .with_detail_json(serde_json::to_value(&r).unwrap_or_default())
            })
            .collect();
        apply_query(&self.schema(), &rows, req)
    }
}
