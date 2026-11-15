pub mod bookmarks;
pub mod cookies;
pub mod extensions;
pub mod findings;
pub mod history;
pub mod local_state;
pub mod logins;
pub mod preferences;
pub mod sessions;
pub mod storage;
pub mod timeline;
pub mod webdata;

use crate::cache::{CacheEntry, CacheScanOptions, load_cache_from_paths};
use crate::crypto::CryptoOptions;
use crate::discovery::{TargetKind, find_cache_dirs_in_profile, resolve_target_path};
use crate::error::DiagnosticWarning;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use self::bookmarks::{BookmarkRecord, parse_bookmarks};
use self::cookies::{CookieRecord, parse_cookies};
use self::extensions::{ExtensionRecord, parse_extensions};
use self::findings::{DomainStat, ForensicFinding, generate_findings_and_stats};
use self::history::{HistoryAnalysis, parse_history};
use self::local_state::{LocalStateInfo, parse_local_state};
use self::logins::{LoginRecord, parse_logins};
use self::preferences::{PreferencesSummary, parse_preferences};
use self::sessions::{SessionsAnalysis, parse_sessions};
use self::storage::{StorageAnalysis, parse_storage_and_misc};
use self::timeline::{TimelineEvent, build_unified_timeline};
use self::webdata::{WebDataAnalysis, parse_web_data};

#[derive(Debug, Clone)]
pub struct AnalysisOptions {
    pub cache_options: CacheScanOptions,
    pub crypto_options: CryptoOptions,
    pub extra_cache_dirs: Vec<PathBuf>,
    pub include_timeline: bool,
}

impl Default for AnalysisOptions {
    fn default() -> Self {
        Self {
            cache_options: CacheScanOptions {
                compute_hashes: true,
                ..Default::default()
            },
            crypto_options: CryptoOptions::metadata_only(),
            extra_cache_dirs: Vec::new(),
            include_timeline: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactFileStat {
    pub relative_path: String,
    pub size_bytes: u64,
    pub category: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileAnalysis {
    pub profile_name: String,
    pub profile_path: String,
    pub cache_dirs: Vec<String>,
    pub cache_entries: Vec<CacheEntry>,
    pub history: HistoryAnalysis,
    pub cookies: Vec<CookieRecord>,
    pub logins: Vec<LoginRecord>,
    pub web_data: WebDataAnalysis,
    pub bookmarks: Vec<BookmarkRecord>,
    pub preferences: PreferencesSummary,
    pub extensions: Vec<ExtensionRecord>,
    pub sessions: SessionsAnalysis,
    pub storage: StorageAnalysis,
    pub file_inventory: Vec<ArtifactFileStat>,
    pub total_profile_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserDataReport {
    pub generated_at: DateTime<Utc>,
    pub target_path: String,
    pub target_kind: TargetKind,
    pub tool_version: String,
    pub local_state: LocalStateInfo,
    pub profiles: Vec<ProfileAnalysis>,
    pub findings: Vec<ForensicFinding>,
    pub top_domains: Vec<DomainStat>,
    pub timeline: Vec<TimelineEvent>,
    pub warnings: Vec<DiagnosticWarning>,
    pub summary: ReportSummary,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ReportSummary {
    pub profile_count: usize,
    pub total_cache_entries: usize,
    pub total_cache_bytes: u64,
    pub total_history_urls: usize,
    pub total_history_visits: usize,
    pub total_downloads: usize,
    pub total_cookies: usize,
    pub total_logins: usize,
    pub total_autofill_entries: usize,
    pub total_bookmarks: usize,
    pub total_extensions: usize,
    pub total_open_tabs: usize,
    pub total_closed_tabs: usize,
    pub total_local_storage_keys: usize,
    pub total_timeline_events: usize,
    pub total_findings: usize,
    pub cache_content_type_breakdown: BTreeMap<String, usize>,
}

pub fn analyze_user_data(path: &Path, opts: &AnalysisOptions) -> UserDataReport {
    let mut warnings = Vec::new();
    let resolved = resolve_target_path(path);

    let local_state = match &resolved.user_data_dir {
        Some(ud) => parse_local_state(ud, &mut warnings),
        None => LocalStateInfo::default(),
    };

    let mut profiles = Vec::new();

    if resolved.kind == TargetKind::CacheDir {
        // Standalone cache directory analysis
        let mut cache_dirs = resolved.cache_dirs.clone();
        for extra in &opts.extra_cache_dirs {
            if !cache_dirs.contains(extra) {
                cache_dirs.push(extra.clone());
            }
        }
        let (cache_entries, mut cw) = load_cache_from_paths(&cache_dirs, &opts.cache_options);
        warnings.append(&mut cw);
        profiles.push(ProfileAnalysis {
            profile_name: "CacheOnly".to_string(),
            profile_path: path.display().to_string(),
            cache_dirs: cache_dirs.iter().map(|p| p.display().to_string()).collect(),
            cache_entries,
            history: HistoryAnalysis::default(),
            cookies: Vec::new(),
            logins: Vec::new(),
            web_data: WebDataAnalysis::default(),
            bookmarks: Vec::new(),
            preferences: PreferencesSummary::default(),
            extensions: Vec::new(),
            sessions: SessionsAnalysis::default(),
            storage: StorageAnalysis::default(),
            file_inventory: Vec::new(),
            total_profile_bytes: 0,
        });
    } else {
        for pdir in &resolved.profile_dirs {
            let pname = pdir
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_else(|| "Profile".to_string());

            let mut cache_dirs = find_cache_dirs_in_profile(pdir);
            // Also include Code Cache/js & extra cache dirs if explicitly passed
            for extra in &opts.extra_cache_dirs {
                if !cache_dirs.contains(extra) {
                    cache_dirs.push(extra.clone());
                }
            }
            let (cache_entries, mut cw) = load_cache_from_paths(&cache_dirs, &opts.cache_options);
            warnings.append(&mut cw);

            let history = parse_history(pdir, &mut warnings);
            let cookies = parse_cookies(pdir, &opts.crypto_options, &mut warnings);
            let logins = parse_logins(pdir, &opts.crypto_options, &mut warnings);
            let web_data = parse_web_data(pdir, &mut warnings);
            let bookmarks = parse_bookmarks(pdir, &mut warnings);
            let (preferences, prefs_json, sec_prefs_json) = parse_preferences(pdir, &mut warnings);
            let extensions = parse_extensions(
                pdir,
                prefs_json.as_ref(),
                sec_prefs_json.as_ref(),
                &mut warnings,
            );
            let sessions = parse_sessions(pdir, &mut warnings);
            let storage = parse_storage_and_misc(pdir, &mut warnings);
            let (file_inventory, total_profile_bytes) = inventory_profile_files(pdir);

            profiles.push(ProfileAnalysis {
                profile_name: pname,
                profile_path: pdir.display().to_string(),
                cache_dirs: cache_dirs.iter().map(|p| p.display().to_string()).collect(),
                cache_entries,
                history,
                cookies,
                logins,
                web_data,
                bookmarks,
                preferences,
                extensions,
                sessions,
                storage,
                file_inventory,
                total_profile_bytes,
            });
        }
    }

    let (findings, top_domains) = generate_findings_and_stats(&profiles);
    let timeline = if opts.include_timeline {
        build_unified_timeline(&profiles)
    } else {
        Vec::new()
    };

    let mut summary = ReportSummary {
        profile_count: profiles.len(),
        total_timeline_events: timeline.len(),
        total_findings: findings.len(),
        ..Default::default()
    };

    for p in &profiles {
        summary.total_cache_entries += p.cache_entries.len();
        for c in &p.cache_entries {
            summary.total_cache_bytes += c.file_size as u64;
            let cat = c
                .content_type
                .as_deref()
                .and_then(|ct| ct.split('/').next())
                .unwrap_or("unknown")
                .to_string();
            *summary.cache_content_type_breakdown.entry(cat).or_insert(0) += 1;
        }
        summary.total_history_urls += p.history.urls.len();
        summary.total_history_visits += p.history.visits.len();
        summary.total_downloads += p.history.downloads.len();
        summary.total_cookies += p.cookies.len();
        summary.total_logins += p.logins.len();
        summary.total_autofill_entries += p.web_data.autofill.len() + p.web_data.addresses.len();
        summary.total_bookmarks += p.bookmarks.len();
        summary.total_extensions += p.extensions.len();
        summary.total_open_tabs += p.sessions.open_tabs.len();
        summary.total_closed_tabs += p.sessions.closed_tabs.len();
        summary.total_local_storage_keys +=
            p.storage.local_storage.len() + p.storage.session_storage.len();
    }

    UserDataReport {
        generated_at: Utc::now(),
        target_path: path.display().to_string(),
        target_kind: resolved.kind,
        tool_version: env!("CARGO_PKG_VERSION").to_string(),
        local_state,
        profiles,
        findings,
        top_domains,
        timeline,
        warnings,
        summary,
    }
}

fn inventory_profile_files(profile_dir: &Path) -> (Vec<ArtifactFileStat>, u64) {
    let mut files = Vec::new();
    let mut total_bytes = 0u64;

    for entry in walkdir::WalkDir::new(profile_dir)
        .max_depth(3)
        .into_iter()
        .flatten()
    {
        if entry.file_type().is_file() {
            let size_bytes = entry.metadata().map(|m| m.len()).unwrap_or(0);
            total_bytes += size_bytes;
            let rel = entry
                .path()
                .strip_prefix(profile_dir)
                .map(|p| p.display().to_string())
                .unwrap_or_else(|_| entry.file_name().to_string_lossy().to_string());
            let category = classify_artifact_path(&rel).to_string();
            files.push(ArtifactFileStat {
                relative_path: rel,
                size_bytes,
                category,
            });
        }
    }
    files.sort_by(|a, b| b.size_bytes.cmp(&a.size_bytes));
    if files.len() > 200 {
        files.truncate(200);
    }
    (files, total_bytes)
}

fn classify_artifact_path(rel: &str) -> &'static str {
    let lower = rel.to_ascii_lowercase();
    if lower.starts_with("cache") || lower.contains("code cache") || lower.contains("gpucache") {
        "Cache"
    } else if lower.contains("history") || lower.contains("visited") || lower.contains("top sites") || lower.contains("shortcuts") {
        "Browsing History"
    } else if lower.contains("cookies") || lower.contains("network") || lower.contains("reporting") {
        "Network & Cookies"
    } else if lower.contains("login") || lower.contains("web data") || lower.contains("affiliation") {
        "Credentials & Autofill"
    } else if lower.contains("sessions") {
        "Sessions"
    } else if lower.contains("extensions") {
        "Extensions"
    } else if lower.contains("local storage") || lower.contains("session storage") || lower.contains("indexeddb") {
        "Site Storage"
    } else if lower.contains("preferences") || lower.contains("bookmarks") {
        "Settings & Bookmarks"
    } else {
        "Other"
    }
}
