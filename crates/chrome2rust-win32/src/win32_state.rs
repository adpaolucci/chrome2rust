use chrome2rust_cache::export::{
    CacheColumn, ExportFormat, ExtractFilenameMode, ExtractOptions, extract_cache_entries, render_cache_export,
};
use chrome2rust_cache::{
    CacheEntry, CacheScanOptions, CacheSortField, delete_cache_entries, matches_cache_filter, sort_cache_entries,
};
use chrome2rust_core::crypto::CryptoOptions;
use chrome2rust_core::discovery::{DiscoveredBrowser, discover_local_browsers};
use chrome2rust_core::time::format_local_opt;
use chrome2rust_forensics::custody::{CustodyManifest, generate_custody_manifest, write_custody_manifest};
use chrome2rust_forensics::findings::FindingSeverity;
use chrome2rust_forensics::providers::build_browser_tool_providers;
use chrome2rust_forensics::{AnalysisOptions, ProfileAnalysis, UserDataReport, analyze_user_data};
use chrome2rust_report::markdown::format_bytes;
use chrome2rust_report::{ReportFormat, write_report};
use guap_gui_win32::{Win32GridState, Win32TableHostConfig};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContentQuickCat {
    All,
    Images,
    Html,
    ScriptsStyles,
    JsonXml,
    MediaFonts,
}

impl ContentQuickCat {
    pub fn from_index(idx: Option<u32>) -> Self {
        match idx {
            Some(1) => Self::Images,
            Some(2) => Self::Html,
            Some(3) => Self::ScriptsStyles,
            Some(4) => Self::JsonXml,
            Some(5) => Self::MediaFonts,
            _ => Self::All,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PreviewMode {
    Auto,
    Headers,
    Hex,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HistorySubTab {
    Urls,
    Visits,
    Downloads,
    SearchTerms,
}

impl HistorySubTab {
    pub fn from_index(idx: Option<u32>) -> Self {
        match idx {
            Some(1) => Self::Visits,
            Some(2) => Self::Downloads,
            Some(3) => Self::SearchTerms,
            _ => Self::Urls,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredSubTab {
    Logins,
    Cookies,
    Autofill,
    AddressesCards,
}

impl CredSubTab {
    pub fn from_index(idx: Option<u32>) -> Self {
        match idx {
            Some(1) => Self::Cookies,
            Some(2) => Self::Autofill,
            Some(3) => Self::AddressesCards,
            _ => Self::Logins,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionSubTab {
    Tabs,
    LocalStorage,
    SessionStorage,
    MiscInventory,
}

impl SessionSubTab {
    pub fn from_index(idx: Option<u32>) -> Self {
        match idx {
            Some(1) => Self::LocalStorage,
            Some(2) => Self::SessionStorage,
            Some(3) => Self::MiscInventory,
            _ => Self::Tabs,
        }
    }
}

pub enum WorkerEvent {
    Status(u64, String),
    AnalysisFinished(u64, Box<UserDataReport>),
    Error(u64, String),
}

#[derive(Debug, Clone, Copy, Default)]
pub struct PollOutcome {
    pub status_changed: bool,
    pub finished: bool,
}

pub struct Win32State {
    pub path_input: String,
    pub discovered_browsers: Vec<DiscoveredBrowser>,
    pub report: Option<UserDataReport>,
    pub selected_profile_idx: Option<usize>,

    pub all_cache_entries: Vec<CacheEntry>,
    pub filtered_indices: Vec<usize>,
    pub selected_filtered_pos: Option<usize>,
    pub active_cache_columns: Vec<CacheColumn>,
    pub sort_primary: CacheSortField,
    pub sort_primary_desc: bool,
    pub sort_secondary: Option<(CacheSortField, bool)>,
    pub quick_filter: String,
    pub content_cat: ContentQuickCat,
    pub hide_zero_length: bool,
    pub show_millis: bool,
    pub preview_mode: PreviewMode,

    pub decrypt_enabled: bool,
    pub allow_peanuts: bool,
    pub keys_text: String,
    pub extract_prefer_detected_ext: bool,
    pub extract_website_dirs: bool,

    pub finding_sev_filter: Option<FindingSeverity>,
    pub findings_search: String,
    pub timeline_cat_filter: String,
    pub timeline_search: String,
    pub history_sub: HistorySubTab,
    pub history_search: String,
    pub cred_sub: CredSubTab,
    pub cred_search: String,
    pub ext_show_bookmarks: bool,
    pub ext_search: String,
    pub sess_sub: SessionSubTab,
    pub sess_search: String,

    pub custody_manifest: Option<CustodyManifest>,

    pub worker_rx: Option<Receiver<WorkerEvent>>,
    pub load_generation: u64,
    pub is_loading: bool,
    pub status_message: String,
    pub initial_load_path: Option<PathBuf>,
    pub initial_pick: bool,

    pub browser_grid: Win32GridState,
    pub browser_grid_loaded: bool,
}

impl Win32State {
    pub fn new(initial: &crate::LaunchArgs) -> Self {
        let browsers = discover_local_browsers();
        let initial_load_path = initial.path.clone();
        let path_input = initial_load_path
            .as_ref()
            .map(|p| p.display().to_string())
            .unwrap_or_default();

        Self {
            path_input,
            discovered_browsers: browsers,
            report: None,
            selected_profile_idx: None,

            all_cache_entries: Vec::new(),
            filtered_indices: Vec::new(),
            selected_filtered_pos: None,
            active_cache_columns: CacheColumn::default_columns(),
            sort_primary: CacheSortField::LastAccessed,
            sort_primary_desc: true,
            sort_secondary: None,
            quick_filter: String::new(),
            content_cat: ContentQuickCat::All,
            hide_zero_length: false,
            show_millis: false,
            preview_mode: PreviewMode::Auto,

            decrypt_enabled: initial.decrypt,
            allow_peanuts: true,
            keys_text: initial.keys.join("\n"),
            extract_prefer_detected_ext: true,
            extract_website_dirs: false,

            finding_sev_filter: None,
            findings_search: String::new(),
            timeline_cat_filter: "All".to_string(),
            timeline_search: String::new(),
            history_sub: HistorySubTab::Urls,
            history_search: String::new(),
            cred_sub: CredSubTab::Logins,
            cred_search: String::new(),
            ext_show_bookmarks: false,
            ext_search: String::new(),
            sess_sub: SessionSubTab::Tabs,
            sess_search: String::new(),

            custody_manifest: None,

            worker_rx: None,
            load_generation: 0,
            is_loading: false,
            status_message: "Ready — click Browse... to select a target folder or choose a discovered browser."
                .to_string(),
            initial_load_path,
            initial_pick: initial.pick,

            browser_grid: Win32GridState::new(Win32TableHostConfig::default(), Vec::new(), Vec::new()),
            browser_grid_loaded: false,
        }
    }

    pub fn ensure_browser_grid_loaded(&mut self) {
        if self.browser_grid_loaded {
            return;
        }
        let trimmed = self.path_input.trim();
        let target = if trimmed.is_empty() {
            None
        } else {
            Some(PathBuf::from(trimmed))
        };
        let providers = build_browser_tool_providers(target.as_deref());
        self.browser_grid = Win32GridState::new(
            Win32TableHostConfig {
                app_title: "Multi-Browser & Carvers".to_string(),
                dark_mode: false,
                show_hex_pane: true,
                default_export_dir: None,
            },
            providers,
            Vec::new(),
        );
        self.browser_grid_loaded = true;
    }

    pub fn crypto_options(&self) -> CryptoOptions {
        let supplied_keys = self
            .keys_text
            .lines()
            .flat_map(|l| l.split(','))
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .collect();
        CryptoOptions {
            decrypt_enabled: self.decrypt_enabled,
            supplied_keys,
            allow_linux_peanuts: self.allow_peanuts,
        }
    }

    pub fn start_load_from_input(&mut self) -> bool {
        let trimmed = self.path_input.trim().trim_matches('"').trim().to_string();
        if trimmed.is_empty() {
            return false;
        }
        self.start_load(PathBuf::from(trimmed));
        true
    }

    pub fn start_load(&mut self, path: PathBuf) {
        self.load_generation = self.load_generation.wrapping_add(1);
        let gen_id = self.load_generation;

        self.path_input = path.display().to_string();
        self.selected_profile_idx = None;
        self.selected_filtered_pos = None;
        self.browser_grid_loaded = false;

        if !path.exists() {
            self.is_loading = false;
            self.worker_rx = None;
            self.status_message = format!("Target path does not exist: {}", path.display());
            return;
        }

        self.is_loading = true;
        self.status_message = format!("Scanning {} ...", path.display());
        let crypto = self.crypto_options();
        let (tx, rx) = mpsc::channel();
        self.worker_rx = Some(rx);

        std::thread::spawn(move || {
            let _ = tx.send(WorkerEvent::Status(gen_id, format!("Analyzing {} ...", path.display())));
            let opts = AnalysisOptions {
                cache_options: CacheScanOptions {
                    compute_hashes: false,
                    ..Default::default()
                },
                crypto_options: crypto,
                extra_cache_dirs: Vec::new(),
                include_timeline: true,
            };
            match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| analyze_user_data(&path, &opts))) {
                Ok(report) => {
                    let _ = tx.send(WorkerEvent::AnalysisFinished(gen_id, Box::new(report)));
                }
                Err(_) => {
                    let _ = tx.send(WorkerEvent::Error(
                        gen_id,
                        format!("Analysis panicked while scanning {}", path.display()),
                    ));
                }
            }
        });
    }

    pub fn poll_worker(&mut self) -> PollOutcome {
        let mut outcome = PollOutcome::default();
        let mut events = Vec::new();
        if let Some(rx) = &self.worker_rx {
            while let Ok(ev) = rx.try_recv() {
                events.push(ev);
            }
        }
        for ev in events {
            match ev {
                WorkerEvent::Status(gen_id, msg) => {
                    if gen_id == self.load_generation {
                        self.status_message = msg;
                        outcome.status_changed = true;
                    }
                }
                WorkerEvent::Error(gen_id, msg) => {
                    if gen_id == self.load_generation {
                        self.is_loading = false;
                        self.worker_rx = None;
                        self.status_message = msg;
                        outcome.status_changed = true;
                        outcome.finished = true;
                    }
                }
                WorkerEvent::AnalysisFinished(gen_id, report) => {
                    if gen_id != self.load_generation {
                        continue;
                    }
                    self.is_loading = false;
                    self.worker_rx = None;
                    self.status_message = format!(
                        "Loaded {} ({:?}): {} profiles | {} cache entries ({}) | {} URLs | {} findings",
                        report.target_path,
                        report.target_kind,
                        report.summary.profile_count,
                        report.summary.total_cache_entries,
                        format_bytes(report.summary.total_cache_bytes),
                        report.summary.total_history_urls,
                        report.summary.total_findings,
                    );
                    self.report = Some(*report);
                    self.selected_profile_idx = None;
                    self.custody_manifest = None;
                    self.rebuild_cache_view();
                    outcome.status_changed = true;
                    outcome.finished = true;
                }
            }
        }
        outcome
    }

    pub fn visible_profiles(&self) -> Vec<(usize, &ProfileAnalysis)> {
        let Some(rep) = &self.report else {
            return Vec::new();
        };
        match self.selected_profile_idx {
            Some(idx) if idx < rep.profiles.len() => vec![(idx, &rep.profiles[idx])],
            _ => rep.profiles.iter().enumerate().collect(),
        }
    }

    pub fn rebuild_cache_view(&mut self) {
        self.all_cache_entries.clear();
        if let Some(rep) = &self.report {
            match self.selected_profile_idx {
                Some(idx) if idx < rep.profiles.len() => {
                    self.all_cache_entries
                        .extend(rep.profiles[idx].cache_entries.iter().cloned());
                }
                _ => {
                    for p in &rep.profiles {
                        self.all_cache_entries.extend(p.cache_entries.iter().cloned());
                    }
                }
            }
        }
        sort_cache_entries(
            &mut self.all_cache_entries,
            self.sort_primary,
            self.sort_primary_desc,
            self.sort_secondary,
        );
        self.apply_cache_filter();
    }

    pub fn apply_cache_filter(&mut self) {
        let scan_opts = CacheScanOptions {
            include_zero_length: !self.hide_zero_length,
            quick_filter: if self.quick_filter.trim().is_empty() {
                None
            } else {
                Some(self.quick_filter.trim().to_string())
            },
            ..Default::default()
        };

        self.filtered_indices.clear();
        for (i, entry) in self.all_cache_entries.iter().enumerate() {
            if !matches_cache_filter(entry, &scan_opts) {
                continue;
            }
            if !matches_quick_cat(entry, self.content_cat) {
                continue;
            }
            self.filtered_indices.push(i);
        }

        if let Some(pos) = self.selected_filtered_pos
            && pos >= self.filtered_indices.len()
        {
            self.selected_filtered_pos = None;
        }
    }

    pub fn toggle_sort(&mut self, field: CacheSortField, shift_held: bool) {
        if shift_held {
            if let Some((sec, sec_desc)) = self.sort_secondary {
                if sec == field {
                    self.sort_secondary = Some((field, !sec_desc));
                } else {
                    self.sort_secondary = Some((field, false));
                }
            } else {
                self.sort_secondary = Some((field, false));
            }
        } else if self.sort_primary == field {
            self.sort_primary_desc = !self.sort_primary_desc;
        } else {
            self.sort_primary = field;
            self.sort_primary_desc = matches!(
                field,
                CacheSortField::LastAccessed
                    | CacheSortField::ServerTime
                    | CacheSortField::RecordCreatedTime
                    | CacheSortField::ExpirationTime
                    | CacheSortField::FileSize
                    | CacheSortField::MimeMismatch
            );
        }
        sort_cache_entries(
            &mut self.all_cache_entries,
            self.sort_primary,
            self.sort_primary_desc,
            self.sort_secondary,
        );
        self.selected_filtered_pos = None;
        self.apply_cache_filter();
    }

    pub fn selected_cache_entry(&self) -> Option<&CacheEntry> {
        let fpos = self.selected_filtered_pos?;
        let raw_idx = *self.filtered_indices.get(fpos)?;
        self.all_cache_entries.get(raw_idx)
    }

    pub fn selected_or_filtered_entries(&self, selected_indices: &[usize], only_selected: bool) -> Vec<&CacheEntry> {
        if only_selected && !selected_indices.is_empty() {
            selected_indices
                .iter()
                .filter_map(|&fpos| self.filtered_indices.get(fpos))
                .filter_map(|&raw| self.all_cache_entries.get(raw))
                .collect()
        } else {
            self.filtered_indices
                .iter()
                .filter_map(|&raw| self.all_cache_entries.get(raw))
                .collect()
        }
    }

    pub fn format_entry_preview(&self, entry: &CacheEntry) -> String {
        let mut out = String::new();
        let det_ct = entry.detected_content_type.as_deref().unwrap_or("-");
        let det_ext = entry
            .detected_extension
            .as_deref()
            .map(|e| format!(".{e}"))
            .unwrap_or_else(|| "-".to_string());
        out.push_str(&format!("URL: {}\r\n", entry.url));
        out.push_str(&format!(
            "Declared: {} | Detected: {} ({}) | {} | {} | {}\r\n",
            entry.content_type.as_deref().unwrap_or("unknown"),
            det_ct,
            det_ext,
            format_bytes(entry.file_size as u64),
            entry.server_response,
            entry.cache_name
        ));
        if let Some(sig) = &entry.file_signature {
            out.push_str(&format!("Signature: {sig}\r\n"));
        }
        if entry.mime_mismatch {
            out.push_str("WARNING: Declared Content-Type contradicts detected payload signature!\r\n");
        }
        out.push_str("------------------------------------------------------------\r\n");

        if self.preview_mode == PreviewMode::Headers {
            out.push_str(&format!("{}\r\n", entry.server_response));
            for h in &entry.headers {
                out.push_str(&format!("{}: {}\r\n", h.name, h.value));
            }
            if !entry.certificates.is_empty() {
                out.push_str("\r\nX.509 Certificates:\r\n");
                for (i, c) in entry.certificates.iter().enumerate() {
                    out.push_str(&format!("[{i}] Subject: {}\r\n    Issuer: {}\r\n", c.subject, c.issuer));
                }
            }
            return out;
        }

        match entry.read_decompressed_payload() {
            Ok(bytes) => {
                if bytes.is_empty() {
                    out.push_str("Zero-length payload (header-only cache record).");
                    return out;
                }
                if self.preview_mode == PreviewMode::Auto {
                    let head = &bytes[..bytes.len().min(64 * 1024)];
                    if entry.is_text_like() || std::str::from_utf8(head).is_ok() {
                        let txt = String::from_utf8_lossy(head);
                        out.push_str(&txt.replace("\r\n", "\n").replace('\n', "\r\n"));
                        return out;
                    }
                }
                for (idx, chunk) in bytes[..bytes.len().min(4096)].chunks(16).enumerate() {
                    let hex: Vec<String> = chunk.iter().map(|b| format!("{b:02x}")).collect();
                    let ascii: String = chunk
                        .iter()
                        .map(|&b| {
                            if b.is_ascii_graphic() || b == b' ' {
                                b as char
                            } else {
                                '.'
                            }
                        })
                        .collect();
                    out.push_str(&format!("{:04x}: {:<47}  |{}|\r\n", idx * 16, hex.join(" "), ascii));
                }
                if bytes.len() > 4096 {
                    out.push_str(&format!("... ({} total bytes)\r\n", bytes.len()));
                }
            }
            Err(e) => {
                out.push_str(&format!("Payload unavailable: {e}"));
            }
        }
        out
    }

    pub fn format_entry_properties(&self, entry: &CacheEntry) -> String {
        let sha = entry.compute_sha256().unwrap_or_else(|| "-".to_string());
        let mut lines = vec![
            format!("URL: {}", entry.url),
            format!("Cache Name: {}", entry.cache_name),
            format!("Backend: {}", entry.backend.as_str()),
            format!("Cache File: {}", entry.cache_file_path),
            format!(
                "Declared Content-Type: {}",
                entry.raw_content_type.as_deref().unwrap_or("-")
            ),
            format!(
                "Detected Type: {}",
                entry.detected_content_type.as_deref().unwrap_or("-")
            ),
            format!(
                "Suggested Ext: {}",
                entry
                    .detected_extension
                    .as_deref()
                    .map(|e| format!(".{e}"))
                    .unwrap_or_else(|| "-".to_string())
            ),
            format!("File Signature: {}", entry.file_signature.as_deref().unwrap_or("-")),
            format!("MIME Mismatch: {}", if entry.mime_mismatch { "YES" } else { "No" }),
            format!("Decompressed Size: {} bytes", entry.file_size),
            format!("Compressed Size: {} bytes", entry.compressed_size),
            format!("SHA-256: {sha}"),
            format!("Last Accessed: {}", format_local_opt(entry.last_accessed, true)),
            format!("Server Time: {}", format_local_opt(entry.server_time, false)),
            format!(
                "TLS / ALPN: {} / {}",
                entry.tls_version.as_deref().unwrap_or("-"),
                entry.alpn_protocol.as_deref().unwrap_or("-")
            ),
            String::new(),
            format!("HTTP Response: {}", entry.server_response),
        ];
        for h in &entry.headers {
            lines.push(format!("  {}: {}", h.name, h.value));
        }
        lines.join("\n")
    }

    pub fn extract_entries(&mut self, entries: &[&CacheEntry], output_dir: &Path) -> String {
        let opts = ExtractOptions {
            output_dir: output_dir.to_path_buf(),
            filename_mode: ExtractFilenameMode::BasedOnUrl,
            use_website_dir_structure: self.extract_website_dirs,
            update_modified_time: true,
            new_name_if_exist: true,
            decompress: true,
            prefer_detected_extension: self.extract_prefer_detected_ext,
        };
        match extract_cache_entries(entries, &opts) {
            Ok(sum) => {
                let msg = format!(
                    "Extracted {} files ({}) to {} ({} skipped, {} failed).",
                    sum.extracted_count,
                    format_bytes(sum.bytes_written),
                    output_dir.display(),
                    sum.skipped_empty_or_deleted,
                    sum.failed_count
                );
                self.status_message = msg.clone();
                msg
            }
            Err(e) => {
                let msg = format!("Extraction failed: {e}");
                self.status_message = msg.clone();
                msg
            }
        }
    }

    pub fn export_table(&mut self, entries: &[CacheEntry], dest: &Path, fmt: ExportFormat) -> String {
        match render_cache_export(entries, fmt, &self.active_cache_columns, true, self.show_millis) {
            Ok(txt) => match std::fs::write(dest, txt) {
                Ok(()) => {
                    let msg = format!("Exported {} cache rows to {}", entries.len(), dest.display());
                    self.status_message = msg.clone();
                    msg
                }
                Err(e) => {
                    let msg = format!("Write error: {e}");
                    self.status_message = msg.clone();
                    msg
                }
            },
            Err(e) => {
                let msg = format!("Export error: {e}");
                self.status_message = msg.clone();
                msg
            }
        }
    }

    pub fn delete_entries(&mut self, entries: &[&CacheEntry]) -> String {
        let (deleted, skipped) = delete_cache_entries(entries);
        let msg = format!("Deleted {deleted} standalone cache files ({} skipped).", skipped.len());
        self.status_message = msg.clone();
        msg
    }

    pub fn write_forensic_report(&mut self, dest: &Path, format: ReportFormat) -> Result<String, String> {
        let Some(rep) = &self.report else {
            return Err("Load a Chrome profile/User Data directory before generating reports.".to_string());
        };
        match write_report(rep, dest, format) {
            Ok(written) => {
                let list: Vec<String> = written.iter().map(|p| p.display().to_string()).collect();
                let msg = format!("Saved forensic report: {}", list.join(", "));
                self.status_message = msg.clone();
                Ok(msg)
            }
            Err(e) => {
                let msg = format!("Report write failed: {e}");
                self.status_message = msg.clone();
                Err(msg)
            }
        }
    }

    pub fn generate_custody(&mut self, save_path: Option<&Path>) -> Result<CustodyManifest, String> {
        let trimmed = self.path_input.trim();
        if trimmed.is_empty() {
            return Err("Enter or select a Target path before generating custody hashes.".to_string());
        }
        let target = PathBuf::from(trimmed);
        match generate_custody_manifest(&target) {
            Ok(manifest) => {
                if let Some(out) = save_path {
                    write_custody_manifest(&manifest, out).map_err(|e| format!("Manifest write failed: {e}"))?;
                }
                self.status_message = format!(
                    "Chain-of-custody Merkle root computed across {} artifacts: {}",
                    manifest.artifact_count, manifest.merkle_root_sha256
                );
                self.custody_manifest = Some(manifest.clone());
                Ok(manifest)
            }
            Err(e) => Err(format!("Error generating manifest: {e}")),
        }
    }
}

pub fn matches_quick_cat(entry: &CacheEntry, cat: ContentQuickCat) -> bool {
    let ct = entry.effective_content_type().unwrap_or("");
    match cat {
        ContentQuickCat::All => true,
        ContentQuickCat::Images => ct.starts_with("image/"),
        ContentQuickCat::Html => ct.contains("html"),
        ContentQuickCat::ScriptsStyles => {
            ct.contains("javascript") || ct.contains("ecmascript") || ct.contains("typescript") || ct == "text/css"
        }
        ContentQuickCat::JsonXml => ct.contains("json") || ct.contains("xml"),
        ContentQuickCat::MediaFonts => {
            ct.starts_with("video/")
                || ct.starts_with("audio/")
                || ct.starts_with("font/")
                || ct == "application/vnd.ms-fontobject"
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    struct TempDirGuard(PathBuf);

    impl TempDirGuard {
        fn new(tag: &str) -> Self {
            let p = std::env::temp_dir().join(format!("chrome2rust_win32_test_{}_{}", tag, std::process::id()));
            let _ = std::fs::remove_dir_all(&p);
            std::fs::create_dir_all(&p).unwrap();
            Self(p)
        }
    }

    impl Drop for TempDirGuard {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn startup_does_not_force_default_directory_when_no_path_given() {
        let state = Win32State::new(&crate::LaunchArgs::default());
        assert!(state.initial_load_path.is_none());
        assert!(state.path_input.is_empty());
        assert!(!state.is_loading);
    }

    #[test]
    fn start_load_supersedes_in_flight_scan_with_selected_target_folder() {
        let dir_first = TempDirGuard::new("first");
        let dir_second = TempDirGuard::new("second");

        let p2_cache = dir_second.0.join("Cache").join("Cache_Data");
        std::fs::create_dir_all(&p2_cache).unwrap();
        std::fs::write(p2_cache.join("index"), b"\0").unwrap();
        std::fs::write(dir_second.0.join("History"), b"").unwrap();

        let mut state = Win32State::new(&crate::LaunchArgs::default());

        state.start_load(dir_first.0.clone());
        assert!(state.is_loading);
        assert_eq!(state.load_generation, 1);

        // Selecting a second target folder while still loading must supersede the first scan.
        state.start_load(dir_second.0.clone());
        assert!(state.is_loading);
        assert_eq!(state.load_generation, 2);
        assert_eq!(state.path_input, dir_second.0.display().to_string());

        for _ in 0..50 {
            let out = state.poll_worker();
            if out.finished && !state.is_loading && state.report.is_some() {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }

        let report = state
            .report
            .as_ref()
            .expect("selected target folder should finish loading");
        assert_eq!(report.target_path, dir_second.0.display().to_string());
    }
}
