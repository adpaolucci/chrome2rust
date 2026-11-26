use crate::firefox::{FirefoxCacheEntry, scan_firefox_cache};
use crate::opera::{OperaCacheEntry, scan_opera_cache};
use crate::pickle::ParsedHeader;
use crate::safari::{SafariCacheEntry, scan_safari_cache};
use crate::{CacheEntry, CacheScanOptions, load_cache_from_paths};
use chrome2rust_core::discovery::{
    UnifiedBrowserKind, UnifiedProfileTarget, discover_all_browser_profiles, resolve_unified_targets,
};
use chrome2rust_core::error::DiagnosticWarning;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub enum UnifiedCacheSource {
    Chromium(Box<CacheEntry>),
    Firefox(Box<FirefoxCacheEntry>),
    Opera(Box<OperaCacheEntry>),
    Safari(Box<SafariCacheEntry>),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnifiedCacheItem {
    pub browser: String,
    pub profile: String,
    pub cache_name: String,
    pub url: String,
    pub content_type: Option<String>,
    pub detected_content_type: Option<String>,
    pub detected_extension: Option<String>,
    pub mime_mismatch: bool,
    pub file_size: usize,
    pub cache_time: Option<DateTime<Utc>>,
    pub headers: Vec<ParsedHeader>,
    pub payload_sha256: Option<String>,
    #[serde(skip)]
    pub source: Option<UnifiedCacheSource>,
}

impl UnifiedCacheItem {
    pub fn read_decompressed_payload(&self) -> Vec<u8> {
        match &self.source {
            Some(UnifiedCacheSource::Chromium(e)) => e.read_decompressed_payload().unwrap_or_default(),
            Some(UnifiedCacheSource::Firefox(e)) => e.read_decompressed_payload(),
            Some(UnifiedCacheSource::Opera(e)) => e.read_decompressed_payload(),
            Some(UnifiedCacheSource::Safari(e)) => e.read_decompressed_payload(),
            None => Vec::new(),
        }
    }

    pub fn effective_content_type(&self) -> Option<&str> {
        if self.mime_mismatch {
            return self.detected_content_type.as_deref().or(self.content_type.as_deref());
        }
        self.detected_content_type.as_deref().or(self.content_type.as_deref())
    }
}

pub fn load_unified_cache_from_paths(
    paths: &[PathBuf],
    compute_hashes: bool,
) -> (Vec<UnifiedCacheItem>, Vec<DiagnosticWarning>) {
    let targets = if paths.is_empty() {
        discover_all_browser_profiles()
    } else {
        resolve_unified_targets(paths)
    };
    load_unified_cache(&targets, compute_hashes)
}

pub fn load_unified_cache(
    targets: &[UnifiedProfileTarget],
    compute_hashes: bool,
) -> (Vec<UnifiedCacheItem>, Vec<DiagnosticWarning>) {
    let mut items = Vec::new();
    let mut warnings = Vec::new();

    for t in targets {
        match t.browser {
            UnifiedBrowserKind::Firefox => {
                let scan_dirs = if t.cache_dirs.is_empty() {
                    vec![t.profile_dir.clone()]
                } else {
                    t.cache_dirs.clone()
                };
                for d in scan_dirs {
                    let (fx_entries, mut w) = scan_firefox_cache(Some(&d), compute_hashes);
                    warnings.append(&mut w);
                    for e in fx_entries {
                        items.push(UnifiedCacheItem {
                            browser: t.browser_name.clone(),
                            profile: t.profile_name.clone(),
                            cache_name: e.filename.clone(),
                            url: e.url.clone(),
                            content_type: e.content_type.clone(),
                            detected_content_type: e.detected_content_type.clone(),
                            detected_extension: e.detected_extension.clone(),
                            mime_mismatch: e.mime_mismatch,
                            file_size: e.file_size,
                            cache_time: e.last_fetched.or(e.last_modified),
                            headers: e.headers.clone(),
                            payload_sha256: e.payload_sha256.clone(),
                            source: Some(UnifiedCacheSource::Firefox(Box::new(e))),
                        });
                    }
                }
            }
            UnifiedBrowserKind::Opera | UnifiedBrowserKind::OperaGx | UnifiedBrowserKind::OperaPresto => {
                let scan_dirs = if t.cache_dirs.is_empty() {
                    vec![t.profile_dir.clone()]
                } else {
                    t.cache_dirs.clone()
                };
                for d in scan_dirs {
                    let (op_entries, mut w) = scan_opera_cache(Some(&d), compute_hashes);
                    warnings.append(&mut w);
                    for e in op_entries {
                        items.push(UnifiedCacheItem {
                            browser: t.browser_name.clone(),
                            profile: t.profile_name.clone(),
                            cache_name: e.cache_file.clone(),
                            url: e.url.clone(),
                            content_type: e.content_type.clone(),
                            detected_content_type: e.detected_content_type.clone(),
                            detected_extension: e.detected_extension.clone(),
                            mime_mismatch: e.mime_mismatch,
                            file_size: e.file_size,
                            cache_time: e.last_visited.or(e.last_modified),
                            headers: e.headers.clone(),
                            payload_sha256: e.payload_sha256.clone(),
                            source: Some(UnifiedCacheSource::Opera(Box::new(e))),
                        });
                    }
                }
            }
            UnifiedBrowserKind::Safari => {
                let scan_dirs = if t.cache_dirs.is_empty() {
                    vec![t.profile_dir.clone()]
                } else {
                    t.cache_dirs.clone()
                };
                for d in scan_dirs {
                    let (sf_entries, mut w) = scan_safari_cache(Some(&d), compute_hashes);
                    warnings.append(&mut w);
                    for e in sf_entries {
                        items.push(UnifiedCacheItem {
                            browser: t.browser_name.clone(),
                            profile: t.profile_name.clone(),
                            cache_name: e.cache_file.clone().unwrap_or_else(|| "Cache.db".into()),
                            url: e.url.clone(),
                            content_type: e.content_type.clone(),
                            detected_content_type: e.detected_content_type.clone(),
                            detected_extension: e.detected_extension.clone(),
                            mime_mismatch: e.mime_mismatch,
                            file_size: e.body_size,
                            cache_time: e.timestamp,
                            headers: e.headers.clone(),
                            payload_sha256: e.payload_sha256.clone(),
                            source: Some(UnifiedCacheSource::Safari(Box::new(e))),
                        });
                    }
                }
            }
            _ => {
                let scan_dirs = if t.cache_dirs.is_empty() {
                    vec![t.profile_dir.clone()]
                } else {
                    t.cache_dirs.clone()
                };
                let opts = CacheScanOptions {
                    compute_hashes,
                    ..Default::default()
                };
                let (entries, mut w) = load_cache_from_paths(&scan_dirs, &opts);
                warnings.append(&mut w);
                for e in entries {
                    items.push(UnifiedCacheItem {
                        browser: t.browser_name.clone(),
                        profile: t.profile_name.clone(),
                        cache_name: e.cache_name.clone(),
                        url: e.url.clone(),
                        content_type: e.content_type.clone(),
                        detected_content_type: e.detected_content_type.clone(),
                        detected_extension: e.detected_extension.clone(),
                        mime_mismatch: e.mime_mismatch,
                        file_size: e.file_size,
                        cache_time: e.last_accessed.or(e.record_created_time).or(e.server_time),
                        headers: e.headers.clone(),
                        payload_sha256: e.payload_sha256.clone(),
                        source: Some(UnifiedCacheSource::Chromium(Box::new(e))),
                    });
                }
            }
        }
    }

    (items, warnings)
}
