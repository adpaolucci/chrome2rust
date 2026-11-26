use crate::LaunchArgs;
use crate::message::{
    ActiveModal, ContentQuickCat, CredSubTab, HistorySubTab, Message, PreviewMode, SessionSubTab, WorkspaceTab,
};
use crate::views;
use chrome2rust_cache::export::{
    CacheColumn, ExportFormat, ExtractFilenameMode, ExtractOptions, extract_cache_entries, render_cache_export,
};
use chrome2rust_cache::{
    CacheEntry, CacheScanOptions, CacheSortField, delete_cache_entries, matches_cache_filter, sort_cache_entries,
};
use chrome2rust_core::crypto::CryptoOptions;
use chrome2rust_core::discovery::{DiscoveredBrowser, discover_local_browsers};
use chrome2rust_forensics::custody::{CustodyManifest, generate_custody_manifest, write_custody_manifest};
use chrome2rust_forensics::findings::FindingSeverity;
use chrome2rust_forensics::providers::build_browser_tool_providers;
use chrome2rust_forensics::{AnalysisOptions, ProfileAnalysis, UserDataReport, analyze_user_data};
use chrome2rust_report::markdown::format_bytes;
use chrome2rust_report::{ReportFormat, write_report};
use guap_gui_iced::IcedDataGrid;
use iced::widget::{button, column, container, mouse_area, row, rule, space, text, text_input};
use iced::{Alignment, Color, Element, Length, Subscription, Task, Theme};
use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver};
use std::time::Duration;

pub struct LoadedPayloadPreview {
    pub entry_id: String,
    pub raw_bytes: Vec<u8>,
    pub text_preview: Option<String>,
    pub image_size: Option<[usize; 2]>,
    pub image_handle: Option<iced::widget::image::Handle>,
    pub error: Option<String>,
}

pub enum WorkerEvent {
    Status(u64, String),
    AnalysisFinished(u64, Box<UserDataReport>),
    Error(u64, String),
}

pub struct ExtractDialogState {
    pub only_selected: bool,
    pub output_dir: String,
    pub filename_mode: ExtractFilenameMode,
    pub website_dirs: bool,
    pub update_mtime: bool,
    pub new_name_if_exist: bool,
    pub decompress: bool,
    pub prefer_detected_extension: bool,
}

pub struct ExportTableDialogState {
    pub only_selected: bool,
    pub format: ExportFormat,
    pub include_header: bool,
}

pub struct CryptoDialogState {
    pub decrypt_enabled: bool,
    pub allow_peanuts: bool,
    pub keys_text: String,
}

pub struct CustodyDialogState {
    pub manifest: Option<CustodyManifest>,
    pub status: Option<String>,
}

pub struct App {
    pub path_input: String,
    pub discovered_browsers: Vec<DiscoveredBrowser>,
    pub report: Option<UserDataReport>,
    pub selected_profile_idx: Option<usize>,
    pub active_tab: WorkspaceTab,
    pub active_modal: ActiveModal,
    pub dark_mode: bool,

    // Cache inspector state
    pub all_cache_entries: Vec<CacheEntry>,
    pub filtered_indices: Vec<usize>,
    pub selected_rows: HashSet<usize>,
    pub active_cache_columns: Vec<CacheColumn>,
    pub sort_primary: CacheSortField,
    pub sort_primary_desc: bool,
    pub sort_secondary: Option<(CacheSortField, bool)>,
    pub quick_filter: String,
    pub show_console_tree: bool,
    pub show_preview_pane: bool,
    pub content_cat: ContentQuickCat,
    pub hide_zero_length: bool,
    pub show_millis: bool,
    pub preview_mode: PreviewMode,
    pub current_preview: Option<LoadedPayloadPreview>,
    pub properties_entry: Option<CacheEntry>,

    // Forensic workspace filters
    pub history_sub: HistorySubTab,
    pub cred_sub: CredSubTab,
    pub sess_sub: SessionSubTab,
    pub finding_sev_filter: Option<FindingSeverity>,
    pub timeline_cat_filter: String,
    pub forensic_search: String,
    pub selected_tab_nav_idx: Option<(usize, usize)>,

    // Dialog states
    pub extract_dlg: ExtractDialogState,
    pub export_dlg: ExportTableDialogState,
    pub crypto_dlg: CryptoDialogState,
    pub custody_dlg: CustodyDialogState,

    // Worker & status
    pub worker_rx: Option<Receiver<WorkerEvent>>,
    pub load_generation: u64,
    pub is_loading: bool,
    pub status_message: String,

    // 21-tool Multi-Browser & Carvers grid
    pub browser_grid: IcedDataGrid,
    pub browser_grid_loaded: bool,
}

impl App {
    pub fn new(initial: LaunchArgs) -> (Self, Task<Message>) {
        let browsers = discover_local_browsers();
        let initial_path = initial.path.clone();
        let path_input = initial_path
            .as_ref()
            .map(|p| p.display().to_string())
            .unwrap_or_default();

        let mut app = Self {
            path_input,
            discovered_browsers: browsers,
            report: None,
            selected_profile_idx: None,
            active_tab: WorkspaceTab::CacheInspector,
            active_modal: ActiveModal::None,
            dark_mode: false,

            all_cache_entries: Vec::new(),
            filtered_indices: Vec::new(),
            selected_rows: HashSet::new(),
            active_cache_columns: CacheColumn::default_columns(),
            sort_primary: CacheSortField::LastAccessed,
            sort_primary_desc: true,
            sort_secondary: None,
            quick_filter: String::new(),
            show_console_tree: true,
            show_preview_pane: true,
            content_cat: ContentQuickCat::All,
            hide_zero_length: false,
            show_millis: false,
            preview_mode: PreviewMode::Auto,
            current_preview: None,
            properties_entry: None,

            history_sub: HistorySubTab::Urls,
            cred_sub: CredSubTab::Logins,
            sess_sub: SessionSubTab::Tabs,
            finding_sev_filter: None,
            timeline_cat_filter: "All".to_string(),
            forensic_search: String::new(),
            selected_tab_nav_idx: None,

            extract_dlg: ExtractDialogState {
                only_selected: true,
                output_dir: "./extracted_cache".to_string(),
                filename_mode: ExtractFilenameMode::BasedOnUrl,
                website_dirs: false,
                update_mtime: true,
                new_name_if_exist: true,
                decompress: true,
                prefer_detected_extension: false,
            },
            export_dlg: ExportTableDialogState {
                only_selected: false,
                format: ExportFormat::Csv,
                include_header: true,
            },
            crypto_dlg: CryptoDialogState {
                decrypt_enabled: initial.decrypt,
                allow_peanuts: true,
                keys_text: initial.keys.join("\n"),
            },
            custody_dlg: CustodyDialogState {
                manifest: None,
                status: None,
            },

            worker_rx: None,
            load_generation: 0,
            is_loading: false,
            status_message:
                "Ready — click Open... to select a target folder, or choose a discovered browser in the Console Tree."
                    .into(),
            browser_grid: IcedDataGrid::new(Vec::new()).with_dark_mode(false),
            browser_grid_loaded: false,
        };

        if let Some(p) = initial_path {
            app.start_load(p);
        }

        (app, Task::none())
    }

    pub fn title(&self) -> String {
        if self.is_loading {
            "Chrome2Rust Management Console (Scanning...)".to_string()
        } else {
            "Chrome2Rust Management Console (Iced Cross-Platform)".to_string()
        }
    }

    pub fn theme(&self) -> Theme {
        if self.dark_mode { Theme::Dark } else { Theme::Light }
    }

    pub fn subscription(&self) -> Subscription<Message> {
        if self.is_loading {
            iced::time::every(Duration::from_millis(60)).map(|_| Message::PollWorker)
        } else {
            Subscription::none()
        }
    }

    pub fn crypto_options(&self) -> CryptoOptions {
        let supplied_keys = self
            .crypto_dlg
            .keys_text
            .lines()
            .flat_map(|l| l.split(','))
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .collect();
        CryptoOptions {
            decrypt_enabled: self.crypto_dlg.decrypt_enabled,
            supplied_keys,
            allow_linux_peanuts: self.crypto_dlg.allow_peanuts,
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
        self.selected_rows.clear();
        self.current_preview = None;

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

    pub fn poll_worker(&mut self) {
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
                    }
                }
                WorkerEvent::Error(gen_id, msg) => {
                    if gen_id == self.load_generation {
                        self.is_loading = false;
                        self.worker_rx = None;
                        self.status_message = msg;
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
                    self.custody_dlg.manifest = None;
                    self.custody_dlg.status = None;
                    self.browser_grid_loaded = false;
                    self.rebuild_cache_view();
                }
            }
        }
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

        let len = self.all_cache_entries.len();
        self.selected_rows.retain(|&idx| idx < len);
        self.refresh_preview_for_selection();
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
        self.selected_rows.clear();
        self.apply_cache_filter();
    }

    pub fn first_selected_cache_entry(&self) -> Option<&CacheEntry> {
        for &raw_idx in &self.filtered_indices {
            if self.selected_rows.contains(&raw_idx) {
                return self.all_cache_entries.get(raw_idx);
            }
        }
        None
    }

    pub fn selected_or_filtered_entries(&self, only_selected: bool) -> Vec<&CacheEntry> {
        if only_selected && !self.selected_rows.is_empty() {
            self.filtered_indices
                .iter()
                .filter(|idx| self.selected_rows.contains(idx))
                .filter_map(|&idx| self.all_cache_entries.get(idx))
                .collect()
        } else {
            self.filtered_indices
                .iter()
                .filter_map(|&idx| self.all_cache_entries.get(idx))
                .collect()
        }
    }

    pub fn refresh_preview_for_selection(&mut self) {
        if !self.show_preview_pane {
            return;
        }
        let Some(entry) = self.first_selected_cache_entry() else {
            self.current_preview = None;
            return;
        };
        if self.current_preview.as_ref().is_some_and(|p| p.entry_id == entry.id) {
            return;
        }

        let entry_id = entry.id.clone();
        match entry.read_decompressed_payload() {
            Ok(bytes) => {
                let mut image_handle = None;
                let mut image_size = None;
                if !bytes.is_empty()
                    && bytes.len() <= 20 * 1024 * 1024
                    && let Ok(dyn_img) = image::load_from_memory(&bytes)
                {
                    let rgba = dyn_img.to_rgba8();
                    let (w, h) = (rgba.width(), rgba.height());
                    image_size = Some([w as usize, h as usize]);
                    image_handle = Some(iced::widget::image::Handle::from_rgba(w, h, rgba.into_raw()));
                }
                let text_preview = if image_handle.is_none() && !bytes.is_empty() {
                    let head = &bytes[..bytes.len().min(64 * 1024)];
                    if entry.is_text_like() || std::str::from_utf8(head).is_ok() {
                        Some(String::from_utf8_lossy(head).into_owned())
                    } else {
                        None
                    }
                } else {
                    None
                };
                self.current_preview = Some(LoadedPayloadPreview {
                    entry_id,
                    raw_bytes: bytes,
                    text_preview,
                    image_size,
                    image_handle,
                    error: None,
                });
            }
            Err(e) => {
                self.current_preview = Some(LoadedPayloadPreview {
                    entry_id,
                    raw_bytes: Vec::new(),
                    text_preview: None,
                    image_size: None,
                    image_handle: None,
                    error: Some(e.to_string()),
                });
            }
        }
    }

    pub fn copy_selected_urls(&mut self) {
        let entries = self.selected_or_filtered_entries(true);
        if entries.is_empty() {
            self.status_message = "No cache entries selected to copy URLs.".into();
            return;
        }
        let urls: Vec<&str> = entries.iter().map(|e| e.url.as_str()).collect();
        if set_clipboard_text(&urls.join("\n")) {
            self.status_message = format!("Copied {} URLs to clipboard.", urls.len());
        } else {
            self.status_message = "Failed to access system clipboard.".into();
        }
    }

    pub fn copy_selected_rows_tsv(&mut self) {
        let entries: Vec<CacheEntry> = self.selected_or_filtered_entries(true).into_iter().cloned().collect();
        if entries.is_empty() {
            return;
        }
        match render_cache_export(
            &entries,
            ExportFormat::Tab,
            &self.active_cache_columns,
            true,
            self.show_millis,
        ) {
            Ok(tsv) => {
                if set_clipboard_text(&tsv) {
                    self.status_message = format!("Copied {} rows (TSV) to clipboard.", entries.len());
                } else {
                    self.status_message = "Clipboard unavailable.".into();
                }
            }
            Err(e) => self.status_message = format!("Copy error: {e}"),
        }
    }

    pub fn copy_preview_to_clipboard(&mut self) {
        if let Some(p) = &self.current_preview {
            if let Some(txt) = &p.text_preview {
                if set_clipboard_text(txt) {
                    self.status_message = "Copied preview text to clipboard.".into();
                }
                return;
            }
            if !p.raw_bytes.is_empty()
                && let Ok(img) = image::load_from_memory(&p.raw_bytes)
            {
                let rgba = img.to_rgba8();
                if let Ok(mut cb) = arboard::Clipboard::new() {
                    let img_data = arboard::ImageData {
                        width: rgba.width() as usize,
                        height: rgba.height() as usize,
                        bytes: std::borrow::Cow::Borrowed(rgba.as_raw()),
                    };
                    if cb.set_image(img_data).is_ok() {
                        self.status_message = "Copied preview image to clipboard.".into();
                        return;
                    }
                }
            }
        }
        self.status_message = "No text or image preview available to copy.".into();
    }

    pub fn trigger_report_save(&mut self, format: ReportFormat) {
        let Some(rep) = &self.report else {
            self.status_message = "Load a Chrome profile/User Data directory before generating reports.".into();
            return;
        };
        let dest = if format == ReportFormat::All {
            rfd::FileDialog::new()
                .set_title("Choose Directory for Full Report Bundle (HTML + JSON + MD)")
                .pick_folder()
        } else {
            let ext = match format {
                ReportFormat::Html => "html",
                ReportFormat::Json => "json",
                ReportFormat::Markdown => "md",
                ReportFormat::All => unreachable!(),
            };
            rfd::FileDialog::new()
                .set_title("Save Forensic Report")
                .set_file_name(format!("chrome2rust_forensic_report.{ext}"))
                .save_file()
        };

        if let Some(path) = dest {
            match write_report(rep, &path, format) {
                Ok(written) => {
                    let list: Vec<String> = written.iter().map(|p| p.display().to_string()).collect();
                    self.status_message = format!("Saved forensic report: {}", list.join(", "));
                }
                Err(e) => {
                    self.status_message = format!("Report write failed: {e}");
                }
            }
        }
    }

    pub fn generate_custody_for_target(&mut self) {
        let trimmed = self.path_input.trim();
        if trimmed.is_empty() {
            self.custody_dlg.status =
                Some("Error: Enter or select a Target path before generating custody hashes.".into());
            return;
        }
        let target = PathBuf::from(trimmed);
        match generate_custody_manifest(&target) {
            Ok(manifest) => {
                self.custody_dlg.status = Some(format!(
                    "Verified {} files ({}) | Merkle Root: {}...",
                    manifest.artifact_count,
                    format_bytes(manifest.total_bytes),
                    &manifest.merkle_root_sha256[..16.min(manifest.merkle_root_sha256.len())]
                ));
                self.status_message = format!(
                    "Chain-of-custody Merkle root computed across {} artifacts.",
                    manifest.artifact_count
                );
                self.custody_dlg.manifest = Some(manifest);
            }
            Err(e) => {
                self.custody_dlg.status = Some(format!("Error generating manifest: {e}"));
            }
        }
    }

    pub fn update(&mut self, message: Message) -> Task<Message> {
        match message {
            Message::PathInputChanged(s) => self.path_input = s,
            Message::BrowseAndLoad => {
                if let Some(folder) = pick_target_folder(&self.path_input) {
                    self.start_load(folder);
                }
            }
            Message::LoadFromInput => {
                if !self.start_load_from_input()
                    && let Some(folder) = pick_target_folder(&self.path_input)
                {
                    self.start_load(folder);
                }
            }
            Message::LoadPath(p) => self.start_load(p),
            Message::PollWorker => self.poll_worker(),
            Message::ToggleDarkMode => self.dark_mode = !self.dark_mode,

            Message::SelectProfile(idx) => {
                self.selected_profile_idx = idx;
                self.selected_rows.clear();
                self.rebuild_cache_view();
            }
            Message::SelectTab(tab) => {
                self.active_tab = tab;
                if tab == WorkspaceTab::BrowserTools && !self.browser_grid_loaded {
                    let trimmed = self.path_input.trim();
                    let target = if trimmed.is_empty() {
                        None
                    } else {
                        Some(PathBuf::from(trimmed))
                    };
                    self.browser_grid = IcedDataGrid::new(build_browser_tool_providers(target.as_deref()))
                        .with_dark_mode(self.dark_mode);
                    self.browser_grid_loaded = true;
                }
            }
            Message::ToggleConsoleTree => self.show_console_tree = !self.show_console_tree,
            Message::TogglePreviewPane => {
                self.show_preview_pane = !self.show_preview_pane;
                self.refresh_preview_for_selection();
            }

            Message::QuickFilterChanged(s) => {
                self.quick_filter = s;
                self.apply_cache_filter();
            }
            Message::ClearQuickFilter => {
                self.quick_filter.clear();
                self.apply_cache_filter();
            }
            Message::SetContentCat(cat) => {
                self.content_cat = cat;
                self.apply_cache_filter();
            }
            Message::ToggleHideZeroLength(b) => {
                self.hide_zero_length = b;
                self.apply_cache_filter();
            }
            Message::ToggleShowMillis(b) => self.show_millis = b,
            Message::ToggleSort(sf, shift) => self.toggle_sort(sf, shift),
            Message::SelectCacheRow(raw_idx) => {
                self.selected_rows.clear();
                self.selected_rows.insert(raw_idx);
                self.refresh_preview_for_selection();
            }
            Message::ToggleRowInSelection(raw_idx) => {
                if !self.selected_rows.remove(&raw_idx) {
                    self.selected_rows.insert(raw_idx);
                }
                self.refresh_preview_for_selection();
            }
            Message::SelectAllFiltered => {
                self.selected_rows = self.filtered_indices.iter().copied().collect();
                self.refresh_preview_for_selection();
            }
            Message::InvertSelectionFiltered => {
                for &raw_idx in &self.filtered_indices {
                    if !self.selected_rows.remove(&raw_idx) {
                        self.selected_rows.insert(raw_idx);
                    }
                }
                self.refresh_preview_for_selection();
            }
            Message::ClearSelection => {
                self.selected_rows.clear();
                self.refresh_preview_for_selection();
            }

            Message::SetPreviewMode(m) => self.preview_mode = m,
            Message::CopySelectedUrls => self.copy_selected_urls(),
            Message::CopySelectedRowsTsv => self.copy_selected_rows_tsv(),
            Message::CopyPreviewToClipboard => self.copy_preview_to_clipboard(),
            Message::InspectEntryProperties(raw_idx) => {
                if let Some(entry) = self.all_cache_entries.get(raw_idx) {
                    self.properties_entry = Some(entry.clone());
                    self.active_modal = ActiveModal::EntryProperties;
                }
            }

            Message::SetFindingSeverityFilter(s) => self.finding_sev_filter = s,
            Message::SetTimelineCategoryFilter(c) => self.timeline_cat_filter = c,
            Message::ForensicSearchChanged(s) => self.forensic_search = s,
            Message::SetHistorySubTab(s) => self.history_sub = s,
            Message::SetCredSubTab(s) => self.cred_sub = s,
            Message::SetSessionSubTab(s) => self.sess_sub = s,
            Message::SelectTabNav(pidx, tidx) => {
                if self.selected_tab_nav_idx == Some((pidx, tidx)) {
                    self.selected_tab_nav_idx = None;
                } else {
                    self.selected_tab_nav_idx = Some((pidx, tidx));
                }
            }

            Message::SaveReport(fmt) => self.trigger_report_save(fmt),
            Message::OpenModal(m) => {
                if m == ActiveModal::ExtractCache {
                    self.extract_dlg.only_selected = !self.selected_rows.is_empty();
                }
                self.active_modal = m;
            }
            Message::CloseModal => {
                self.properties_entry = None;
                self.active_modal = ActiveModal::None;
            }

            Message::ExtractOnlySelectedToggled(b) => self.extract_dlg.only_selected = b,
            Message::ExtractOutputDirChanged(s) => self.extract_dlg.output_dir = s,
            Message::BrowseExtractOutputDir => {
                if let Some(dir) = rfd::FileDialog::new().pick_folder() {
                    self.extract_dlg.output_dir = dir.display().to_string();
                }
            }
            Message::ExtractFilenameModeChanged(m) => self.extract_dlg.filename_mode = m.0,
            Message::ExtractWebsiteDirsToggled(b) => self.extract_dlg.website_dirs = b,
            Message::ExtractUpdateMtimeToggled(b) => self.extract_dlg.update_mtime = b,
            Message::ExtractNewNameToggled(b) => self.extract_dlg.new_name_if_exist = b,
            Message::ExtractDecompressToggled(b) => self.extract_dlg.decompress = b,
            Message::ExtractPreferDetectedExtToggled(b) => self.extract_dlg.prefer_detected_extension = b,
            Message::ConfirmExtractCache => {
                let only_sel = self.extract_dlg.only_selected && !self.selected_rows.is_empty();
                let refs = self.selected_or_filtered_entries(only_sel);
                let opts = ExtractOptions {
                    output_dir: PathBuf::from(self.extract_dlg.output_dir.trim()),
                    filename_mode: self.extract_dlg.filename_mode,
                    use_website_dir_structure: self.extract_dlg.website_dirs,
                    update_modified_time: self.extract_dlg.update_mtime,
                    new_name_if_exist: self.extract_dlg.new_name_if_exist,
                    decompress: self.extract_dlg.decompress,
                    prefer_detected_extension: self.extract_dlg.prefer_detected_extension,
                };
                match extract_cache_entries(&refs, &opts) {
                    Ok(sum) => {
                        self.status_message = format!(
                            "Extracted {} files ({}) to {} ({} skipped, {} failed).",
                            sum.extracted_count,
                            format_bytes(sum.bytes_written),
                            opts.output_dir.display(),
                            sum.skipped_empty_or_deleted,
                            sum.failed_count
                        );
                    }
                    Err(e) => {
                        self.status_message = format!("Extraction failed: {e}");
                    }
                }
                self.active_modal = ActiveModal::None;
            }

            Message::ExportOnlySelectedToggled(b) => self.export_dlg.only_selected = b,
            Message::ExportFormatChanged(f) => self.export_dlg.format = f.0,
            Message::ExportIncludeHeaderToggled(b) => self.export_dlg.include_header = b,
            Message::ConfirmExportCacheTable => {
                let ext = match self.export_dlg.format {
                    ExportFormat::Csv => "csv",
                    ExportFormat::Tab => "tsv",
                    ExportFormat::Tabular | ExportFormat::Text => "txt",
                    ExportFormat::HtmlHorizontal | ExportFormat::HtmlVertical => "html",
                    ExportFormat::Xml => "xml",
                    ExportFormat::Json => "json",
                };
                if let Some(dest) = rfd::FileDialog::new()
                    .set_file_name(format!("chrome_cache_export.{ext}"))
                    .save_file()
                {
                    let only_sel = self.export_dlg.only_selected && !self.selected_rows.is_empty();
                    let entries: Vec<_> = self
                        .selected_or_filtered_entries(only_sel)
                        .into_iter()
                        .cloned()
                        .collect();
                    match render_cache_export(
                        &entries,
                        self.export_dlg.format,
                        &self.active_cache_columns,
                        self.export_dlg.include_header,
                        self.show_millis,
                    ) {
                        Ok(txt) => match std::fs::write(&dest, txt) {
                            Ok(()) => {
                                self.status_message =
                                    format!("Exported {} cache rows to {}", entries.len(), dest.display());
                            }
                            Err(e) => self.status_message = format!("Write error: {e}"),
                        },
                        Err(e) => self.status_message = format!("Export error: {e}"),
                    }
                    self.active_modal = ActiveModal::None;
                }
            }

            Message::CryptoDecryptToggled(b) => self.crypto_dlg.decrypt_enabled = b,
            Message::CryptoPeanutsToggled(b) => self.crypto_dlg.allow_peanuts = b,
            Message::CryptoKeysChanged(s) => self.crypto_dlg.keys_text = s,
            Message::ApplyCryptoAndReload => {
                self.active_modal = ActiveModal::None;
                let _ = self.start_load_from_input();
            }

            Message::ToggleCacheColumn(col, checked) => {
                if checked {
                    if !self.active_cache_columns.contains(&col) {
                        self.active_cache_columns.push(col);
                    }
                } else if self.active_cache_columns.len() > 1 {
                    self.active_cache_columns.retain(|c| *c != col);
                }
            }
            Message::ResetDefaultColumns => {
                self.active_cache_columns = CacheColumn::default_columns();
            }

            Message::ConfirmDeleteSelected => {
                let refs = self.selected_or_filtered_entries(true);
                let (deleted, skipped) = delete_cache_entries(&refs);
                self.active_modal = ActiveModal::None;
                self.status_message = format!("Deleted {deleted} cache files ({} skipped).", skipped.len());
                let _ = self.start_load_from_input();
            }

            Message::ComputeCustodyManifest => self.generate_custody_for_target(),
            Message::SaveCustodyManifest => {
                if let Some(ref manifest) = self.custody_dlg.manifest
                    && let Some(dest) = rfd::FileDialog::new()
                        .set_title("Save Chain-of-Custody Manifest")
                        .set_file_name("custody_manifest.json")
                        .save_file()
                {
                    match write_custody_manifest(manifest, &dest) {
                        Ok(()) => {
                            self.custody_dlg.status = Some(format!("Saved manifest to {}", dest.display()));
                        }
                        Err(e) => {
                            self.custody_dlg.status = Some(format!("Error saving manifest: {e}"));
                        }
                    }
                }
            }
            Message::BrowserToolsGrid(grid_msg) => {
                return self.browser_grid.update(grid_msg).map(Message::BrowserToolsGrid);
            }
        }
        Task::none()
    }

    pub fn view(&self) -> Element<'_, Message> {
        let top_toolbar = self.view_top_toolbar();

        let center: Element<'_, Message> = match self.active_tab {
            WorkspaceTab::CacheInspector => views::cache_list::view_cache_list(self),
            WorkspaceTab::Overview => views::forensic_tabs::view_overview_tab(self),
            WorkspaceTab::Findings => views::forensic_tabs::view_findings_tab(self),
            WorkspaceTab::Timeline => views::forensic_tabs::view_timeline_tab(self),
            WorkspaceTab::HistoryDownloads => views::forensic_tabs::view_history_tab(self),
            WorkspaceTab::CredsCookies => views::forensic_tabs::view_creds_tab(self),
            WorkspaceTab::ExtensionsBookmarks => views::forensic_tabs::view_extensions_tab(self),
            WorkspaceTab::SessionsStorage => views::forensic_tabs::view_sessions_tab(self),
            WorkspaceTab::BrowserTools => self.browser_grid.view().map(Message::BrowserToolsGrid),
        };

        let mut body = row![].spacing(8).height(Length::Fill);
        if self.show_console_tree {
            body = body.push(
                container(views::sidebar::view_sidebar(self))
                    .width(Length::Fixed(255.0))
                    .height(Length::Fill)
                    .padding(8)
                    .style(container::bordered_box),
            );
        }
        body = body.push(container(center).width(Length::Fill).height(Length::Fill).padding(8));

        if self.active_tab == WorkspaceTab::CacheInspector && self.show_preview_pane {
            body = body.push(
                container(views::inspector_pane::view_inspector_pane(self))
                    .width(Length::Fixed(360.0))
                    .height(Length::Fill)
                    .padding(8)
                    .style(container::bordered_box),
            );
        }

        let status_bar = self.view_status_bar();

        let main_layout = column![top_toolbar, rule::horizontal(1), body, rule::horizontal(1), status_bar,]
            .width(Length::Fill)
            .height(Length::Fill);

        if self.active_modal == ActiveModal::None {
            main_layout.into()
        } else {
            let modal_card = views::modals::view_modal(self);
            let backdrop = mouse_area(
                container(modal_card)
                    .width(Length::Fill)
                    .height(Length::Fill)
                    .center_x(Length::Fill)
                    .center_y(Length::Fill)
                    .style(|_| container::Style {
                        background: Some(Color::from_rgba(0.0, 0.0, 0.0, 0.48).into()),
                        ..Default::default()
                    }),
            )
            .on_press(Message::CloseModal);

            iced::widget::stack![main_layout, backdrop].into()
        }
    }

    fn view_top_toolbar(&self) -> Element<'_, Message> {
        let controls = row![
            button(text("Open...").size(12))
                .on_press(Message::BrowseAndLoad)
                .style(button::primary),
            button(text("Refresh").size(12))
                .on_press(Message::LoadFromInput)
                .style(button::secondary),
            button(text("Extract...").size(12))
                .on_press(Message::OpenModal(ActiveModal::ExtractCache))
                .style(button::secondary),
            button(text("Export...").size(12))
                .on_press(Message::OpenModal(ActiveModal::ExportCacheTable))
                .style(button::secondary),
            button(text("HTML Report").size(12))
                .on_press(Message::SaveReport(ReportFormat::Html))
                .style(button::secondary),
            button(text("Bundle").size(12))
                .on_press(Message::SaveReport(ReportFormat::All))
                .style(button::secondary),
            button(text("Decrypt Keys").size(12))
                .on_press(Message::OpenModal(ActiveModal::DecryptionSettings))
                .style(button::secondary),
            button(text("Custody Audit").size(12))
                .on_press(Message::OpenModal(ActiveModal::CustodyManifest))
                .style(button::secondary),
            text("Target:").size(12),
            text_input("Chrome User Data, Profile, or Cache_Data path", &self.path_input)
                .on_input(Message::PathInputChanged)
                .on_submit(Message::LoadFromInput)
                .size(12)
                .width(Length::Fill),
            button(text("Load").size(12))
                .on_press(Message::LoadFromInput)
                .style(button::success),
            button(
                text(if self.show_console_tree {
                    "Hide Tree"
                } else {
                    "Show Tree"
                })
                .size(12)
            )
            .on_press(Message::ToggleConsoleTree)
            .style(button::secondary),
            button(
                text(if self.show_preview_pane {
                    "Hide Insp"
                } else {
                    "Show Insp"
                })
                .size(12)
            )
            .on_press(Message::TogglePreviewPane)
            .style(button::secondary),
            button(text(if self.dark_mode { "Light" } else { "Dark" }).size(12))
                .on_press(Message::ToggleDarkMode)
                .style(button::secondary),
        ]
        .spacing(5)
        .align_y(Alignment::Center);

        container(controls).padding([8, 10]).width(Length::Fill).into()
    }

    fn view_status_bar(&self) -> Element<'_, Message> {
        let profile_label = match (&self.report, self.selected_profile_idx) {
            (Some(r), Some(idx)) => r.profiles.get(idx).map(|p| p.profile_name.as_str()).unwrap_or("All"),
            (Some(_), None) => "All Profiles",
            (None, _) => "None",
        };
        let vis_bytes: u64 = self
            .filtered_indices
            .iter()
            .filter_map(|&idx| self.all_cache_entries.get(idx))
            .map(|e| e.file_size as u64)
            .sum();
        let cache_seg = format!(
            "Shown: {}/{} ({}) | Sel: {}",
            self.filtered_indices.len(),
            self.all_cache_entries.len(),
            format_bytes(vis_bytes),
            self.selected_rows.len()
        );
        let vsep = || container(rule::vertical(1)).height(Length::Fixed(16.0));
        let bar = row![
            text(&self.status_message).size(12).width(Length::Fill),
            vsep(),
            text(format!("{} ({})", self.active_tab.title(), profile_label)).size(12),
            vsep(),
            text(cache_seg).size(12),
            vsep(),
            text("Iced 0.14 (wgpu + tiny-skia fallback) | Read-Only").size(12),
            space::horizontal().width(Length::Fixed(4.0)),
        ]
        .spacing(10)
        .height(Length::Shrink)
        .align_y(Alignment::Center);

        container(bar)
            .padding([5, 10])
            .width(Length::Fill)
            .height(Length::Shrink)
            .style(container::bordered_box)
            .into()
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

fn pick_target_folder(current_input: &str) -> Option<PathBuf> {
    let mut dlg = rfd::FileDialog::new().set_title("Select Chrome User Data, Profile, or Cache Folder");
    let trimmed = current_input.trim().trim_matches('"').trim();
    if !trimmed.is_empty() {
        let p = PathBuf::from(trimmed);
        if p.is_dir() {
            dlg = dlg.set_directory(&p);
        } else if let Some(parent) = p.parent()
            && parent.is_dir()
        {
            dlg = dlg.set_directory(parent);
        }
    }
    dlg.pick_folder()
}

pub fn set_clipboard_text(text: &str) -> bool {
    if let Ok(mut cb) = arboard::Clipboard::new() {
        return cb.set_text(text.to_string()).is_ok();
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TempDirGuard(PathBuf);

    impl TempDirGuard {
        fn new(tag: &str) -> Self {
            let p = std::env::temp_dir().join(format!("chrome2rust_iced_test_{}_{}", tag, std::process::id()));
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
        let (app, _) = App::new(LaunchArgs::default());
        assert!(app.path_input.is_empty());
        assert!(!app.is_loading);
    }

    #[test]
    fn start_load_supersedes_in_flight_scan_with_selected_target_folder() {
        let dir_first = TempDirGuard::new("first");
        let dir_second = TempDirGuard::new("second");

        let p2_cache = dir_second.0.join("Cache").join("Cache_Data");
        std::fs::create_dir_all(&p2_cache).unwrap();
        std::fs::write(p2_cache.join("index"), b"\0").unwrap();
        std::fs::write(dir_second.0.join("History"), b"").unwrap();

        let (mut app, _) = App::new(LaunchArgs::default());

        app.start_load(dir_first.0.clone());
        assert!(app.is_loading);
        assert_eq!(app.load_generation, 1);

        // Selecting a second target folder while still loading must supersede the first scan.
        app.start_load(dir_second.0.clone());
        assert!(app.is_loading);
        assert_eq!(app.load_generation, 2);
        assert_eq!(app.path_input, dir_second.0.display().to_string());

        for _ in 0..50 {
            app.poll_worker();
            if !app.is_loading && app.report.is_some() {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }

        let report = app
            .report
            .as_ref()
            .expect("selected target folder should finish loading");
        assert_eq!(report.target_path, dir_second.0.display().to_string());
    }
}
