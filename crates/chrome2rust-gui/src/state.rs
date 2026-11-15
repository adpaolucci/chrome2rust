use chrome2rust_cache::export::{CacheColumn, ExportFormat, ExtractFilenameMode, render_cache_export};
use chrome2rust_cache::{CacheEntry, CacheScanOptions, CacheSortField, matches_cache_filter, sort_cache_entries};
use chrome2rust_core::crypto::CryptoOptions;
use chrome2rust_core::discovery::{DiscoveredBrowser, discover_local_browsers};
use chrome2rust_forensics::custody::{CustodyManifest, generate_custody_manifest};
use chrome2rust_forensics::findings::FindingSeverity;
use chrome2rust_forensics::{AnalysisOptions, ProfileAnalysis, UserDataReport, analyze_user_data};
use chrome2rust_report::markdown::format_bytes;
use chrome2rust_report::{ReportFormat, write_report};
use eframe::egui;
use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver};

#[derive(Debug, Clone, Default)]
pub struct LaunchArgs {
    pub path: Option<PathBuf>,
    pub decrypt: bool,
    pub keys: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkspaceTab {
    CacheInspector,
    Overview,
    Findings,
    Timeline,
    HistoryDownloads,
    CredsCookies,
    ExtensionsBookmarks,
    SessionsStorage,
}

impl WorkspaceTab {
    pub fn title(self) -> &'static str {
        match self {
            WorkspaceTab::CacheInspector => "Cache Inspector",
            WorkspaceTab::Overview => "Overview & Reports",
            WorkspaceTab::Findings => "Forensic Findings",
            WorkspaceTab::Timeline => "Unified Timeline",
            WorkspaceTab::HistoryDownloads => "History & Downloads",
            WorkspaceTab::CredsCookies => "Cookies, Logins & Autofill",
            WorkspaceTab::ExtensionsBookmarks => "Extensions & Bookmarks",
            WorkspaceTab::SessionsStorage => "Sessions & Storage",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActiveModal {
    None,
    ExtractCache,
    ExportCacheTable,
    DecryptionSettings,
    ChooseColumns,
    EntryProperties,
    ConfirmDelete,
    CustodyManifest,
    About,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PreviewMode {
    Auto,
    Headers,
    Hex,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContentQuickCat {
    All,
    Images,
    Html,
    ScriptsStyles,
    JsonXml,
    MediaFonts,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HistorySubTab {
    Urls,
    Visits,
    Downloads,
    SearchTerms,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredSubTab {
    Logins,
    Cookies,
    Autofill,
    AddressesCards,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionSubTab {
    Tabs,
    LocalStorage,
    SessionStorage,
    MiscInventory,
}

pub struct LoadedPayloadPreview {
    pub entry_id: String,
    pub raw_bytes: Vec<u8>,
    pub text_preview: Option<String>,
    pub image_size: Option<[usize; 2]>,
    pub texture: Option<egui::TextureHandle>,
    pub error: Option<String>,
}

pub enum WorkerEvent {
    AnalysisFinished(Box<UserDataReport>),
}

pub struct ExtractDialogState {
    pub only_selected: bool,
    pub output_dir: String,
    pub filename_mode: ExtractFilenameMode,
    pub website_dirs: bool,
    pub update_mtime: bool,
    pub new_name_if_exist: bool,
    pub decompress: bool,
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

pub struct AppState {
    pub path_input: String,
    pub discovered_browsers: Vec<DiscoveredBrowser>,
    pub report: Option<UserDataReport>,
    pub selected_profile_idx: Option<usize>,
    pub active_tab: WorkspaceTab,
    pub active_modal: ActiveModal,

    // Cache inspector state
    pub all_cache_entries: Vec<CacheEntry>,
    pub filtered_indices: Vec<usize>,
    pub selected_rows: HashSet<usize>,
    pub last_clicked_filtered_pos: Option<usize>,
    pub active_cache_columns: Vec<CacheColumn>,
    pub sort_primary: CacheSortField,
    pub sort_primary_desc: bool,
    pub sort_secondary: Option<(CacheSortField, bool)>,
    pub quick_filter: String,
    pub focus_quick_filter: bool,
    pub show_quick_filter_bar: bool,
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
    pub is_loading: bool,
    pub status_message: String,
    pub first_frame: bool,
    pub initial_load_path: Option<PathBuf>,
}

impl AppState {
    pub fn new(initial: LaunchArgs) -> Self {
        let browsers = discover_local_browsers();
        let default_path = initial.path.clone().or_else(|| {
            browsers.first().and_then(|b| {
                if b.user_data_dir.is_dir() {
                    Some(b.user_data_dir.clone())
                } else {
                    b.cache_root_dir.clone()
                }
            })
        });

        let path_input = default_path
            .as_ref()
            .map(|p| p.display().to_string())
            .unwrap_or_default();

        Self {
            path_input,
            discovered_browsers: browsers,
            report: None,
            selected_profile_idx: None,
            active_tab: WorkspaceTab::CacheInspector,
            active_modal: ActiveModal::None,

            all_cache_entries: Vec::new(),
            filtered_indices: Vec::new(),
            selected_rows: HashSet::new(),
            last_clicked_filtered_pos: None,
            active_cache_columns: CacheColumn::default_columns(),
            sort_primary: CacheSortField::LastAccessed,
            sort_primary_desc: true,
            sort_secondary: None,
            quick_filter: String::new(),
            focus_quick_filter: false,
            show_quick_filter_bar: true,
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
            is_loading: false,
            status_message: "Ready. Choose a Chrome User Data, Profile, or Cache directory.".into(),
            first_frame: true,
            initial_load_path: initial.path.or(default_path),
        }
    }

    pub fn crypto_options(&self) -> CryptoOptions {
        let supplied_keys = self
            .crypto_dlg
            .keys_text
            .lines()
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

    pub fn start_load(&mut self, path: PathBuf, ctx: &egui::Context) {
        if self.is_loading {
            return;
        }
        self.path_input = path.display().to_string();
        self.is_loading = true;
        self.status_message = format!("Analyzing {} ...", path.display());
        let crypto = self.crypto_options();
        let (tx, rx) = mpsc::channel();
        self.worker_rx = Some(rx);
        let ctx_clone = ctx.clone();

        std::thread::spawn(move || {
            let opts = AnalysisOptions {
                cache_options: CacheScanOptions {
                    compute_hashes: false,
                    ..Default::default()
                },
                crypto_options: crypto,
                extra_cache_dirs: Vec::new(),
                include_timeline: true,
            };
            let report = analyze_user_data(&path, &opts);
            let _ = tx.send(WorkerEvent::AnalysisFinished(Box::new(report)));
            ctx_clone.request_repaint();
        });
    }

    pub fn poll_worker(&mut self, ctx: &egui::Context) {
        let mut finished = None;
        if let Some(rx) = &self.worker_rx {
            while let Ok(ev) = rx.try_recv() {
                finished = Some(ev);
            }
        }
        if let Some(WorkerEvent::AnalysisFinished(report)) = finished {
            self.is_loading = false;
            self.worker_rx = None;
            let summary_msg = format!(
                "Loaded {} profiles | {} cache entries ({}) | {} URLs | {} findings",
                report.summary.profile_count,
                report.summary.total_cache_entries,
                format_bytes(report.summary.total_cache_bytes),
                report.summary.total_history_urls,
                report.summary.total_findings,
            );
            self.status_message = summary_msg;
            self.report = Some(*report);
            self.selected_profile_idx = None;
            self.custody_dlg.manifest = None;
            self.custody_dlg.status = None;
            self.rebuild_cache_view(ctx);
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

    pub fn rebuild_cache_view(&mut self, ctx: &egui::Context) {
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
        self.apply_cache_filter(ctx);
    }

    pub fn apply_cache_filter(&mut self, ctx: &egui::Context) {
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
        self.refresh_preview_for_selection(ctx);
    }

    pub fn toggle_sort(&mut self, field: CacheSortField, shift_held: bool, ctx: &egui::Context) {
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
            );
        }
        sort_cache_entries(
            &mut self.all_cache_entries,
            self.sort_primary,
            self.sort_primary_desc,
            self.sort_secondary,
        );
        self.selected_rows.clear();
        self.last_clicked_filtered_pos = None;
        self.apply_cache_filter(ctx);
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

    pub fn refresh_preview_for_selection(&mut self, ctx: &egui::Context) {
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
                let mut texture = None;
                let mut image_size = None;
                if !bytes.is_empty()
                    && bytes.len() <= 20 * 1024 * 1024
                    && let Ok(dyn_img) = image::load_from_memory(&bytes)
                {
                    let rgba = dyn_img.to_rgba8();
                    let size = [rgba.width() as usize, rgba.height() as usize];
                    let color_img = egui::ColorImage::from_rgba_unmultiplied(size, rgba.as_flat_samples().as_slice());
                    image_size = Some(size);
                    texture =
                        Some(ctx.load_texture(format!("preview_{entry_id}"), color_img, egui::TextureOptions::LINEAR));
                }
                let text_preview = if texture.is_none() && !bytes.is_empty() {
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
                    texture,
                    error: None,
                });
            }
            Err(e) => {
                self.current_preview = Some(LoadedPayloadPreview {
                    entry_id,
                    raw_bytes: Vec::new(),
                    text_preview: None,
                    image_size: None,
                    texture: None,
                    error: Some(e.to_string()),
                });
            }
        }
    }

    pub fn select_all_filtered(&mut self, ctx: &egui::Context) {
        self.selected_rows = self.filtered_indices.iter().copied().collect();
        self.refresh_preview_for_selection(ctx);
    }

    pub fn invert_selection_filtered(&mut self, ctx: &egui::Context) {
        for &raw_idx in &self.filtered_indices {
            if self.selected_rows.contains(&raw_idx) {
                self.selected_rows.remove(&raw_idx);
            } else {
                self.selected_rows.insert(raw_idx);
            }
        }
        self.refresh_preview_for_selection(ctx);
    }

    pub fn clear_selection(&mut self, ctx: &egui::Context) {
        self.selected_rows.clear();
        self.last_clicked_filtered_pos = None;
        self.refresh_preview_for_selection(ctx);
    }

    pub fn copy_selected_urls(&mut self) {
        let entries = self.selected_or_filtered_entries(true);
        if entries.is_empty() {
            self.status_message = "No cache entries selected to copy URLs.".into();
            return;
        }
        let urls: Vec<&str> = entries.iter().map(|e| e.url.as_str()).collect();
        let text = urls.join("\n");
        if set_clipboard_text(&text) {
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

    pub fn handle_shortcuts(&mut self, ctx: &egui::Context) {
        let mut copy_urls = false;
        let mut copy_rows = false;
        let mut copy_preview = false;
        let mut toggle_filter = false;
        let mut toggle_preview = false;
        let mut open_extract = false;
        let mut refresh = false;
        let mut select_all = false;
        let mut clear_sel = false;
        let mut open_props = false;
        let mut delete_sel = false;

        ctx.input(|i| {
            if i.modifiers.ctrl && i.key_pressed(egui::Key::Q) {
                toggle_filter = true;
            }
            if i.key_pressed(egui::Key::F8) {
                toggle_preview = true;
            }
            if i.key_pressed(egui::Key::F4) {
                open_extract = true;
            }
            if i.key_pressed(egui::Key::F5) {
                refresh = true;
            }
            if !ctx.wants_keyboard_input() {
                if i.modifiers.ctrl && i.key_pressed(egui::Key::U) {
                    copy_urls = true;
                }
                if i.modifiers.ctrl && i.key_pressed(egui::Key::C) {
                    copy_rows = true;
                }
                if i.modifiers.ctrl && i.key_pressed(egui::Key::P) {
                    copy_preview = true;
                }
                if i.modifiers.ctrl && i.key_pressed(egui::Key::A) {
                    select_all = true;
                }
                if i.modifiers.ctrl && i.key_pressed(egui::Key::D) {
                    clear_sel = true;
                }
                if i.key_pressed(egui::Key::Enter) {
                    open_props = true;
                }
                if i.key_pressed(egui::Key::Delete) {
                    delete_sel = true;
                }
            }
        });

        if toggle_filter {
            self.show_quick_filter_bar = !self.show_quick_filter_bar;
            if self.show_quick_filter_bar {
                self.focus_quick_filter = true;
            }
        }
        if toggle_preview {
            self.show_preview_pane = !self.show_preview_pane;
            self.refresh_preview_for_selection(ctx);
        }
        if open_extract {
            self.active_modal = ActiveModal::ExtractCache;
            self.extract_dlg.only_selected = !self.selected_rows.is_empty();
        }
        if refresh && !self.path_input.trim().is_empty() {
            self.start_load(PathBuf::from(self.path_input.trim()), ctx);
        }
        if select_all && self.active_tab == WorkspaceTab::CacheInspector {
            self.select_all_filtered(ctx);
        }
        if clear_sel && self.active_tab == WorkspaceTab::CacheInspector {
            self.clear_selection(ctx);
        }
        if copy_urls {
            self.copy_selected_urls();
        }
        if copy_rows {
            self.copy_selected_rows_tsv();
        }
        if copy_preview {
            self.copy_preview_to_clipboard();
        }
        if open_props && let Some(e) = self.first_selected_cache_entry().cloned() {
            self.properties_entry = Some(e);
            self.active_modal = ActiveModal::EntryProperties;
        }
        if delete_sel && !self.selected_rows.is_empty() {
            self.active_modal = ActiveModal::ConfirmDelete;
        }
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
}

pub fn matches_quick_cat(entry: &CacheEntry, cat: ContentQuickCat) -> bool {
    let ct = entry.content_type.as_deref().unwrap_or("");
    match cat {
        ContentQuickCat::All => true,
        ContentQuickCat::Images => ct.starts_with("image/"),
        ContentQuickCat::Html => ct.contains("html"),
        ContentQuickCat::ScriptsStyles => ct.contains("javascript") || ct.contains("ecmascript") || ct == "text/css",
        ContentQuickCat::JsonXml => ct.contains("json") || ct.contains("xml"),
        ContentQuickCat::MediaFonts => ct.starts_with("video/") || ct.starts_with("audio/") || ct.starts_with("font/"),
    }
}

pub fn set_clipboard_text(text: &str) -> bool {
    if let Ok(mut cb) = arboard::Clipboard::new() {
        return cb.set_text(text.to_string()).is_ok();
    }
    false
}
