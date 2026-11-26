use crate::firefox::{
    FirefoxAddonsTableProvider, FirefoxBookmarksTableProvider, FirefoxCookiesTableProvider,
    FirefoxDownloadsTableProvider, FirefoxFormHistoryTableProvider, FirefoxHistoryTableProvider,
    FirefoxSessionsTableProvider,
};
use crate::opera::OperaHistoryTableProvider;
use crate::safari::{SafariBookmarksTableProvider, SafariHistoryTableProvider};
use crate::search_queries::SearchQueriesTableProvider;
use crate::unified::{
    UnifiedAddonsTableProvider, UnifiedAutofillTableProvider, UnifiedBookmarksTableProvider,
    UnifiedDownloadsTableProvider, UnifiedHistoryTableProvider,
};
use chrome2rust_cache::carve_images::ImageCarveTableProvider;
use chrome2rust_cache::carve_video::VideoCarveTableProvider;
use chrome2rust_cache::firefox::FirefoxCacheTableProvider;
use chrome2rust_cache::opera::OperaCacheTableProvider;
use chrome2rust_cache::safari::SafariCacheTableProvider;
use guap_table::TableProvider;
use std::path::Path;
use std::sync::Arc;

/// Builds all 21 read-only `guap_table::TableProvider` instances for the M2A browser tools.
pub fn build_browser_tool_providers(target: Option<&Path>) -> Vec<Arc<dyn TableProvider>> {
    let t = target.map(|p| p.to_path_buf());
    vec![
        // Firefox (8)
        Arc::new(FirefoxCacheTableProvider::new(t.clone())),
        Arc::new(FirefoxHistoryTableProvider::new(t.clone())),
        Arc::new(FirefoxCookiesTableProvider::new(t.clone())),
        Arc::new(FirefoxBookmarksTableProvider::new(t.clone())),
        Arc::new(FirefoxDownloadsTableProvider::new(t.clone())),
        Arc::new(FirefoxFormHistoryTableProvider::new(t.clone())),
        Arc::new(FirefoxAddonsTableProvider::new(t.clone())),
        Arc::new(FirefoxSessionsTableProvider::new(t.clone())),
        // Opera (2)
        Arc::new(OperaCacheTableProvider::new(t.clone())),
        Arc::new(OperaHistoryTableProvider::new(t.clone())),
        // Safari (3)
        Arc::new(SafariCacheTableProvider::new(t.clone())),
        Arc::new(SafariHistoryTableProvider::new(t.clone())),
        Arc::new(SafariBookmarksTableProvider::new(t.clone())),
        // Unified (5)
        Arc::new(UnifiedHistoryTableProvider::new(t.clone())),
        Arc::new(UnifiedDownloadsTableProvider::new(t.clone())),
        Arc::new(UnifiedAddonsTableProvider::new(t.clone())),
        Arc::new(UnifiedBookmarksTableProvider::new(t.clone())),
        Arc::new(UnifiedAutofillTableProvider::new(t.clone())),
        // Search & Carvers (3)
        Arc::new(SearchQueriesTableProvider::new(t.clone())),
        Arc::new(ImageCarveTableProvider::new(t.clone())),
        Arc::new(VideoCarveTableProvider::new(t)),
    ]
}

/// Builds a specific `TableProvider` by `tool_id` (`chrome2rust_fx_cache` .. `chrome2rust_carve_video`).
pub fn build_browser_tool_provider_by_id(tool_id: &str, target: Option<&Path>) -> Option<Arc<dyn TableProvider>> {
    let t = target.map(|p| p.to_path_buf());
    match tool_id {
        "chrome2rust_fx_cache" => Some(Arc::new(FirefoxCacheTableProvider::new(t))),
        "chrome2rust_fx_history" => Some(Arc::new(FirefoxHistoryTableProvider::new(t))),
        "chrome2rust_fx_cookies" => Some(Arc::new(FirefoxCookiesTableProvider::new(t))),
        "chrome2rust_fx_bookmarks" => Some(Arc::new(FirefoxBookmarksTableProvider::new(t))),
        "chrome2rust_fx_downloads" => Some(Arc::new(FirefoxDownloadsTableProvider::new(t))),
        "chrome2rust_fx_formhistory" => Some(Arc::new(FirefoxFormHistoryTableProvider::new(t))),
        "chrome2rust_fx_addons" => Some(Arc::new(FirefoxAddonsTableProvider::new(t))),
        "chrome2rust_fx_sessions" => Some(Arc::new(FirefoxSessionsTableProvider::new(t))),
        "chrome2rust_opera_cache" => Some(Arc::new(OperaCacheTableProvider::new(t))),
        "chrome2rust_opera_history" => Some(Arc::new(OperaHistoryTableProvider::new(t))),
        "chrome2rust_safari_cache" => Some(Arc::new(SafariCacheTableProvider::new(t))),
        "chrome2rust_safari_history" => Some(Arc::new(SafariHistoryTableProvider::new(t))),
        "chrome2rust_safari_bookmarks" => Some(Arc::new(SafariBookmarksTableProvider::new(t))),
        "chrome2rust_unified_history" => Some(Arc::new(UnifiedHistoryTableProvider::new(t))),
        "chrome2rust_unified_downloads" => Some(Arc::new(UnifiedDownloadsTableProvider::new(t))),
        "chrome2rust_unified_addons" => Some(Arc::new(UnifiedAddonsTableProvider::new(t))),
        "chrome2rust_unified_bookmarks" => Some(Arc::new(UnifiedBookmarksTableProvider::new(t))),
        "chrome2rust_unified_autofill" => Some(Arc::new(UnifiedAutofillTableProvider::new(t))),
        "chrome2rust_search_queries" => Some(Arc::new(SearchQueriesTableProvider::new(t))),
        "chrome2rust_carve_images" => Some(Arc::new(ImageCarveTableProvider::new(t))),
        "chrome2rust_carve_video" => Some(Arc::new(VideoCarveTableProvider::new(t))),
        _ => None,
    }
}
