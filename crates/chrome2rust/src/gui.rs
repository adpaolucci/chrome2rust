use crate::cli::GuiArgs;
use anyhow::{Result, anyhow};
use chrome2rust_core::cache::export::{
    CacheColumn, ExportFormat, ExtractFilenameMode, ExtractOptions, extract_cache_entries,
    render_cache_export,
};
use chrome2rust_core::cache::{
    CacheEntry, CacheScanOptions, CacheSortField, delete_cache_entries, matches_cache_filter,
    sort_cache_entries,
};
use chrome2rust_core::crypto::CryptoOptions;
use chrome2rust_core::discovery::{DiscoveredBrowser, discover_local_browsers};
use chrome2rust_core::forensics::findings::FindingSeverity;
use chrome2rust_core::forensics::{
    AnalysisOptions, ProfileAnalysis, UserDataReport, analyze_user_data,
};
use chrome2rust_core::report::markdown::format_bytes;
use chrome2rust_core::report::{ReportFormat, write_report};
use chrome2rust_core::time::format_local_opt;
use eframe::egui;
use egui_extras::{Column, TableBuilder};
use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WorkspaceTab {
    CacheViewer,
    Overview,
    Findings,
    Timeline,
    HistoryDownloads,
    CredsCookies,
    ExtensionsBookmarks,
    SessionsStorage,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PreviewMode {
    Auto,
    Headers,
    Hex,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ContentQuickCat {
    All,
    Images,
    Html,
    ScriptsStyles,
    JsonXml,
    MediaFonts,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HistorySubTab {
    Urls,
    Visits,
    Downloads,
    SearchTerms,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CredSubTab {
    Logins,
    Cookies,
    Autofill,
    AddressesCards,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SessionSubTab {
    Tabs,
    LocalStorage,
    SessionStorage,
    MiscInventory,
}

struct LoadedPayloadPreview {
    entry_id: String,
    raw_bytes: Vec<u8>,
    text_preview: Option<String>,
    image_size: Option<[usize; 2]>,
    texture: Option<egui::TextureHandle>,
    error: Option<String>,
}

enum WorkerEvent {
    AnalysisFinished(Box<UserDataReport>),
}

struct ExtractDialogState {
    open: bool,
    only_selected: bool,
    output_dir: String,
    filename_mode: ExtractFilenameMode,
    website_dirs: bool,
    update_mtime: bool,
    new_name_if_exist: bool,
    decompress: bool,
}

struct ExportTableDialogState {
    open: bool,
    only_selected: bool,
    format: ExportFormat,
    include_header: bool,
}

struct CryptoDialogState {
    open: bool,
    decrypt_enabled: bool,
    allow_peanuts: bool,
    keys_text: String,
}

pub struct Chrome2RustApp {
    path_input: String,
    discovered_browsers: Vec<DiscoveredBrowser>,
    report: Option<UserDataReport>,
    selected_profile_idx: Option<usize>, // None = All profiles
    active_tab: WorkspaceTab,

    // Cache view state
    all_cache_entries: Vec<CacheEntry>,
    filtered_indices: Vec<usize>,
    selected_rows: HashSet<usize>,
    last_clicked_filtered_pos: Option<usize>,
    active_cache_columns: Vec<CacheColumn>,
    sort_primary: CacheSortField,
    sort_primary_desc: bool,
    sort_secondary: Option<(CacheSortField, bool)>,
    quick_filter: String,
    focus_quick_filter: bool,
    show_quick_filter_bar: bool,
    content_cat: ContentQuickCat,
    hide_zero_length: bool,
    show_millis: bool,
    show_preview_pane: bool,
    preview_mode: PreviewMode,
    current_preview: Option<LoadedPayloadPreview>,
    properties_entry: Option<CacheEntry>,
    show_columns_dialog: bool,
    confirm_delete_open: bool,

    // Forensic sub-filters
    history_sub: HistorySubTab,
    cred_sub: CredSubTab,
    sess_sub: SessionSubTab,
    finding_sev_filter: Option<FindingSeverity>,
    timeline_cat_filter: String,
    forensic_search: String,
    selected_tab_nav_idx: Option<(usize, usize)>,

    // Dialogs & crypto
    extract_dlg: ExtractDialogState,
    export_dlg: ExportTableDialogState,
    crypto_dlg: CryptoDialogState,

    // Worker & status
    worker_rx: Option<Receiver<WorkerEvent>>,
    is_loading: bool,
    status_message: String,
    first_frame: bool,
    initial_load_path: Option<PathBuf>,
}

impl Chrome2RustApp {
    fn new(initial: GuiArgs) -> Self {
        let browsers = discover_local_browsers();
        let default_path = initial
            .path
            .clone()
            .or_else(|| {
                browsers
                    .first()
                    .and_then(|b| {
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
            active_tab: WorkspaceTab::CacheViewer,

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
            content_cat: ContentQuickCat::All,
            hide_zero_length: false,
            show_millis: false,
            show_preview_pane: true,
            preview_mode: PreviewMode::Auto,
            current_preview: None,
            properties_entry: None,
            show_columns_dialog: false,
            confirm_delete_open: false,

            history_sub: HistorySubTab::Urls,
            cred_sub: CredSubTab::Logins,
            sess_sub: SessionSubTab::Tabs,
            finding_sev_filter: None,
            timeline_cat_filter: "All".to_string(),
            forensic_search: String::new(),
            selected_tab_nav_idx: None,

            extract_dlg: ExtractDialogState {
                open: false,
                only_selected: true,
                output_dir: "./extracted_cache".to_string(),
                filename_mode: ExtractFilenameMode::BasedOnUrl,
                website_dirs: false,
                update_mtime: true,
                new_name_if_exist: true,
                decompress: true,
            },
            export_dlg: ExportTableDialogState {
                open: false,
                only_selected: false,
                format: ExportFormat::Csv,
                include_header: true,
            },
            crypto_dlg: CryptoDialogState {
                open: false,
                decrypt_enabled: initial.decrypt,
                allow_peanuts: true,
                keys_text: initial.keys.join("\n"),
            },

            worker_rx: None,
            is_loading: false,
            status_message: "Ready. Choose a Chrome User Data, Profile, or Cache folder.".to_string(),
            first_frame: true,
            initial_load_path: initial.path.or(default_path),
        }
    }

    fn crypto_options(&self) -> CryptoOptions {
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

    fn start_load(&mut self, path: PathBuf, ctx: &egui::Context) {
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
                    compute_hashes: false, // fast initial load; hashes computed on-demand
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

    fn poll_worker(&mut self, ctx: &egui::Context) {
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
            self.rebuild_cache_view(ctx);
        }
    }

    fn visible_profiles(&self) -> Vec<(usize, &ProfileAnalysis)> {
        let Some(rep) = &self.report else {
            return Vec::new();
        };
        match self.selected_profile_idx {
            Some(idx) if idx < rep.profiles.len() => vec![(idx, &rep.profiles[idx])],
            _ => rep.profiles.iter().enumerate().collect(),
        }
    }

    fn rebuild_cache_view(&mut self, ctx: &egui::Context) {
        self.all_cache_entries.clear();
        if let Some(rep) = &self.report {
            match self.selected_profile_idx {
                Some(idx) if idx < rep.profiles.len() => {
                    self.all_cache_entries
                        .extend(rep.profiles[idx].cache_entries.iter().cloned());
                }
                _ => {
                    for p in &rep.profiles {
                        self.all_cache_entries
                            .extend(p.cache_entries.iter().cloned());
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

    fn apply_cache_filter(&mut self, ctx: &egui::Context) {
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

        // Prune selected rows that are no longer valid indexes
        let len = self.all_cache_entries.len();
        self.selected_rows.retain(|&idx| idx < len);
        self.refresh_preview_for_selection(ctx);
    }

    fn toggle_sort(&mut self, field: CacheSortField, shift_held: bool, ctx: &egui::Context) {
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

    fn first_selected_cache_entry(&self) -> Option<&CacheEntry> {
        // Prefer lowest filtered row among selected_rows for deterministic preview
        for &raw_idx in &self.filtered_indices {
            if self.selected_rows.contains(&raw_idx) {
                return self.all_cache_entries.get(raw_idx);
            }
        }
        None
    }

    fn selected_or_filtered_entries(&self, only_selected: bool) -> Vec<&CacheEntry> {
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

    fn refresh_preview_for_selection(&mut self, ctx: &egui::Context) {
        if !self.show_preview_pane {
            return;
        }
        let Some(entry) = self.first_selected_cache_entry() else {
            self.current_preview = None;
            return;
        };
        if self
            .current_preview
            .as_ref()
            .is_some_and(|p| p.entry_id == entry.id)
        {
            return;
        }

        let entry_id = entry.id.clone();
        match entry.read_decompressed_payload() {
            Ok(bytes) => {
                let mut texture = None;
                let mut image_size = None;
                if !bytes.is_empty() && bytes.len() <= 20 * 1024 * 1024 {
                    if let Ok(dyn_img) = image::load_from_memory(&bytes) {
                        let rgba = dyn_img.to_rgba8();
                        let size = [rgba.width() as usize, rgba.height() as usize];
                        let color_img = egui::ColorImage::from_rgba_unmultiplied(
                            size,
                            rgba.as_flat_samples().as_slice(),
                        );
                        image_size = Some(size);
                        texture = Some(ctx.load_texture(
                            format!("preview_{entry_id}"),
                            color_img,
                            egui::TextureOptions::LINEAR,
                        ));
                    }
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

    fn copy_selected_urls(&mut self) {
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

    fn copy_selected_rows_tsv(&mut self) {
        let entries: Vec<CacheEntry> = self
            .selected_or_filtered_entries(true)
            .into_iter()
            .cloned()
            .collect();
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

    fn copy_preview_to_clipboard(&mut self) {
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

    fn handle_shortcuts(&mut self, ctx: &egui::Context) {
        let mut copy_urls = false;
        let mut copy_rows = false;
        let mut copy_preview = false;
        let mut toggle_filter = false;
        let mut toggle_preview = false;
        let mut open_extract = false;
        let mut refresh = false;
        let mut select_all = false;
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
            self.extract_dlg.open = true;
            self.extract_dlg.only_selected = !self.selected_rows.is_empty();
        }
        if refresh && !self.path_input.trim().is_empty() {
            self.start_load(PathBuf::from(self.path_input.trim()), ctx);
        }
        if select_all && self.active_tab == WorkspaceTab::CacheViewer {
            self.selected_rows = self.filtered_indices.iter().copied().collect();
            self.refresh_preview_for_selection(ctx);
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
        }
        if delete_sel && !self.selected_rows.is_empty() {
            self.confirm_delete_open = true;
        }
    }

    fn trigger_report_save(&mut self, format: ReportFormat) {
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
}

impl eframe::App for Chrome2RustApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        if self.first_frame {
            self.first_frame = false;
            if let Some(p) = self.initial_load_path.take()
                && p.exists()
            {
                self.start_load(p, ctx);
            }
        }

        self.poll_worker(ctx);
        self.handle_shortcuts(ctx);

        // Top Menu & Target Bar
        egui::TopBottomPanel::top("top_chrome_panel").show(ctx, |ui| {
            egui::MenuBar::new().ui(ui, |ui| {
                ui.menu_button("File", |ui| {
                    if ui.button("Open User Data / Profile / Cache...").clicked() {
                        ui.close();
                        if let Some(folder) = rfd::FileDialog::new().pick_folder() {
                            self.start_load(folder, ctx);
                        }
                    }
                    ui.menu_button("Discover Local Browsers", |ui| {
                        let browsers = self.discovered_browsers.clone();
                        if browsers.is_empty() {
                            ui.label("No local Chromium browsers detected");
                        } else {
                            for b in browsers {
                                ui.menu_button(b.name.clone(), |ui| {
                                    if b.user_data_dir.is_dir()
                                        && ui
                                            .button(format!(
                                                "Full User Data ({})",
                                                b.user_data_dir.display()
                                            ))
                                            .clicked()
                                    {
                                        ui.close();
                                        self.start_load(b.user_data_dir.clone(), ctx);
                                    }
                                    for p in &b.profiles {
                                        let label = format!(
                                            "Profile: {} ({})",
                                            p.dir_name,
                                            p.display_name.as_deref().unwrap_or("-")
                                        );
                                        if ui.button(label).clicked() {
                                            ui.close();
                                            self.start_load(p.path.clone(), ctx);
                                        }
                                        for c in &p.cache_dirs {
                                            if ui
                                                .button(format!("  Cache: {}", c.display()))
                                                .clicked()
                                            {
                                                ui.close();
                                                self.start_load(c.clone(), ctx);
                                            }
                                        }
                                    }
                                });
                            }
                        }
                    });
                    ui.separator();
                    if ui.button("Save Extracted Files... (F4)").clicked() {
                        ui.close();
                        self.extract_dlg.open = true;
                        self.extract_dlg.only_selected = !self.selected_rows.is_empty();
                    }
                    if ui.button("Export Cache Table...").clicked() {
                        ui.close();
                        self.export_dlg.open = true;
                    }
                    ui.separator();
                    if ui.button("Generate HTML Report...").clicked() {
                        ui.close();
                        self.trigger_report_save(ReportFormat::Html);
                    }
                    if ui.button("Generate JSON Report...").clicked() {
                        ui.close();
                        self.trigger_report_save(ReportFormat::Json);
                    }
                    if ui.button("Generate Markdown Report...").clicked() {
                        ui.close();
                        self.trigger_report_save(ReportFormat::Markdown);
                    }
                    if ui.button("Generate Full Bundle (HTML+JSON+MD)...").clicked() {
                        ui.close();
                        self.trigger_report_save(ReportFormat::All);
                    }
                    ui.separator();
                    if ui.button("Quit").clicked() {
                        ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                    }
                });

                ui.menu_button("Edit", |ui| {
                    if ui.button("Copy Selected URLs (Ctrl+U)").clicked() {
                        ui.close();
                        self.copy_selected_urls();
                    }
                    if ui.button("Copy Selected Rows TSV (Ctrl+C)").clicked() {
                        ui.close();
                        self.copy_selected_rows_tsv();
                    }
                    if ui.button("Copy Preview Text/Image (Ctrl+P)").clicked() {
                        ui.close();
                        self.copy_preview_to_clipboard();
                    }
                    if ui.button("Select All Filtered (Ctrl+A)").clicked() {
                        ui.close();
                        self.selected_rows = self.filtered_indices.iter().copied().collect();
                        self.refresh_preview_for_selection(ctx);
                    }
                    ui.separator();
                    if ui
                        .add_enabled(
                            !self.selected_rows.is_empty(),
                            egui::Button::new("Delete Selected Standalone Cache Files (Del)"),
                        )
                        .clicked()
                    {
                        ui.close();
                        self.confirm_delete_open = true;
                    }
                });

                ui.menu_button("View", |ui| {
                    if ui.checkbox(&mut self.show_preview_pane, "Show Preview Pane (F8)").changed() {
                        self.refresh_preview_for_selection(ctx);
                    }
                    ui.checkbox(&mut self.show_quick_filter_bar, "Show Quick Filter (Ctrl+Q)");
                    if ui.checkbox(&mut self.hide_zero_length, "Hide Zero-Length Files").changed() {
                        self.apply_cache_filter(ctx);
                    }
                    ui.checkbox(&mut self.show_millis, "Show Milliseconds in Dates");
                    ui.separator();
                    if ui.button("Choose Columns...").clicked() {
                        ui.close();
                        self.show_columns_dialog = true;
                    }
                    if ui.button("Decryption & Key Options...").clicked() {
                        ui.close();
                        self.crypto_dlg.open = true;
                    }
                });

                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if self.is_loading {
                        ui.spinner();
                        ui.label("Scanning...");
                    }
                });
            });

            ui.separator();

            // Target Path + Profile Selector + Actions
            ui.horizontal(|ui| {
                ui.label("Target:");
                let path_edit = ui.add_sized(
                    [420.0, 22.0],
                    egui::TextEdit::singleline(&mut self.path_input)
                        .hint_text("Chrome User Data, Profile, or Cache_Data path"),
                );
                if ui.button("Browse...").clicked() {
                    if let Some(folder) = rfd::FileDialog::new().pick_folder() {
                        self.start_load(folder, ctx);
                    }
                }
                let load_clicked = ui.button("Load / Refresh (F5)").clicked()
                    || (path_edit.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)));
                if load_clicked && !self.path_input.trim().is_empty() {
                    self.start_load(PathBuf::from(self.path_input.trim()), ctx);
                }

                if let Some(rep) = &self.report
                    && rep.profiles.len() > 1
                {
                    ui.separator();
                    let cur_label = match self.selected_profile_idx {
                        Some(i) => rep
                            .profiles
                            .get(i)
                            .map(|p| p.profile_name.as_str())
                            .unwrap_or("All Profiles"),
                        None => "All Profiles",
                    };
                    let mut changed = false;
                    egui::ComboBox::from_id_salt("gui_profile_selector")
                        .selected_text(cur_label)
                        .show_ui(ui, |ui| {
                            if ui
                                .selectable_value(&mut self.selected_profile_idx, None, "All Profiles")
                                .clicked()
                            {
                                changed = true;
                            }
                            for (idx, p) in rep.profiles.iter().enumerate() {
                                if ui
                                    .selectable_value(
                                        &mut self.selected_profile_idx,
                                        Some(idx),
                                        &p.profile_name,
                                    )
                                    .clicked()
                                {
                                    changed = true;
                                }
                            }
                        });
                    if changed {
                        self.selected_rows.clear();
                        self.rebuild_cache_view(ctx);
                    }
                }
            });

            ui.separator();

            // Main Workspace Tabs
            ui.horizontal_wrapped(|ui| {
                let mut tab_btn = |tab: WorkspaceTab, label: &str| {
                    let selected = self.active_tab == tab;
                    if ui.selectable_label(selected, label).clicked() {
                        self.active_tab = tab;
                    }
                };
                let (findings_n, hist_n, creds_n, ext_n, sess_n) = match &self.report {
                    Some(r) => (
                        r.findings.len(),
                        r.summary.total_history_urls,
                        r.summary.total_logins + r.summary.total_cookies,
                        r.summary.total_extensions + r.summary.total_bookmarks,
                        r.summary.total_open_tabs + r.summary.total_closed_tabs,
                    ),
                    None => (0, 0, 0, 0, 0),
                };
                tab_btn(
                    WorkspaceTab::CacheViewer,
                    &format!("Cache Viewer ({})", self.all_cache_entries.len()),
                );
                tab_btn(WorkspaceTab::Overview, "Overview & Report");
                tab_btn(WorkspaceTab::Findings, &format!("Findings ({findings_n})"));
                tab_btn(WorkspaceTab::Timeline, "Timeline");
                tab_btn(
                    WorkspaceTab::HistoryDownloads,
                    &format!("History & Downloads ({hist_n})"),
                );
                tab_btn(
                    WorkspaceTab::CredsCookies,
                    &format!("Cookies, Logins & Autofill ({creds_n})"),
                );
                tab_btn(
                    WorkspaceTab::ExtensionsBookmarks,
                    &format!("Extensions & Bookmarks ({ext_n})"),
                );
                tab_btn(
                    WorkspaceTab::SessionsStorage,
                    &format!("Sessions & Storage ({sess_n})"),
                );
            });
        });

        // Bottom Status Bar
        egui::TopBottomPanel::bottom("status_bar").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.label(&self.status_message);
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if self.active_tab == WorkspaceTab::CacheViewer {
                        let sel_bytes: u64 = self
                            .selected_rows
                            .iter()
                            .filter_map(|&idx| self.all_cache_entries.get(idx))
                            .map(|e| e.file_size as u64)
                            .sum();
                        let vis_bytes: u64 = self
                            .filtered_indices
                            .iter()
                            .filter_map(|&idx| self.all_cache_entries.get(idx))
                            .map(|e| e.file_size as u64)
                            .sum();
                        ui.label(format!(
                            "{} selected ({}) | {}/{} shown ({})",
                            self.selected_rows.len(),
                            format_bytes(sel_bytes),
                            self.filtered_indices.len(),
                            self.all_cache_entries.len(),
                            format_bytes(vis_bytes)
                        ));
                    }
                });
            });
        });

        // Preview Side Panel when inside Cache Viewer
        if self.active_tab == WorkspaceTab::CacheViewer && self.show_preview_pane {
            egui::SidePanel::right("cache_preview_panel")
                .default_width(380.0)
                .min_width(240.0)
                .resizable(true)
                .show(ctx, |ui| self.render_preview_pane(ui));
        }

        // Main Central Area
        egui::CentralPanel::default().show(ctx, |ui| {
            match self.active_tab {
                WorkspaceTab::CacheViewer => self.render_cache_viewer(ui, ctx),
                WorkspaceTab::Overview => self.render_overview_tab(ui),
                WorkspaceTab::Findings => self.render_findings_tab(ui),
                WorkspaceTab::Timeline => self.render_timeline_tab(ui),
                WorkspaceTab::HistoryDownloads => self.render_history_tab(ui),
                WorkspaceTab::CredsCookies => self.render_creds_tab(ui),
                WorkspaceTab::ExtensionsBookmarks => self.render_extensions_tab(ui),
                WorkspaceTab::SessionsStorage => self.render_sessions_tab(ui),
            }
        });

        // Modals
        self.render_extract_dialog(ctx);
        self.render_export_dialog(ctx);
        self.render_crypto_dialog(ctx);
        self.render_columns_dialog(ctx);
        self.render_properties_dialog(ctx);
        self.render_delete_confirm_dialog(ctx);
    }
}

impl Chrome2RustApp {
    fn render_cache_viewer(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        if self.show_quick_filter_bar {
            let mut filter_changed = false;
            ui.horizontal_wrapped(|ui| {
                ui.label("Filter:");
                let resp = ui.add_sized(
                    [260.0, 22.0],
                    egui::TextEdit::singleline(&mut self.quick_filter)
                        .hint_text("URL, type, server, site, IP..."),
                );
                if self.focus_quick_filter {
                    resp.request_focus();
                    self.focus_quick_filter = false;
                }
                if resp.changed() {
                    filter_changed = true;
                }
                if !self.quick_filter.is_empty() && ui.button("Clear").clicked() {
                    self.quick_filter.clear();
                    filter_changed = true;
                }

                ui.separator();
                for (cat, label) in [
                    (ContentQuickCat::All, "All"),
                    (ContentQuickCat::Images, "Images"),
                    (ContentQuickCat::Html, "HTML"),
                    (ContentQuickCat::ScriptsStyles, "JS/CSS"),
                    (ContentQuickCat::JsonXml, "JSON/XML"),
                    (ContentQuickCat::MediaFonts, "Media/Fonts"),
                ] {
                    if ui
                        .selectable_label(self.content_cat == cat, label)
                        .clicked()
                    {
                        self.content_cat = cat;
                        filter_changed = true;
                    }
                }
                ui.separator();
                if ui.checkbox(&mut self.hide_zero_length, "No 0B").changed() {
                    filter_changed = true;
                }
                ui.separator();
                if ui.button("Extract (F4)").clicked() {
                    self.extract_dlg.open = true;
                    self.extract_dlg.only_selected = !self.selected_rows.is_empty();
                }
                if ui.button("Export Table").clicked() {
                    self.export_dlg.open = true;
                }
                if ui.button("Copy URLs").clicked() {
                    self.copy_selected_urls();
                }
            });
            if filter_changed {
                self.apply_cache_filter(ctx);
            }
            ui.separator();
        }

        if self.filtered_indices.is_empty() {
            ui.centered_and_justified(|ui| {
                ui.label("No cache entries match the active filter (or no cache loaded yet).");
            });
            return;
        }

        let cols = self.active_cache_columns.clone();
        let mut clicked_sort: Option<(CacheSortField, bool)> = None;
        let mut clicked_row: Option<(usize, usize)> = None;
        let mut double_clicked_raw: Option<usize> = None;
        let mut context_action: Option<(usize, &'static str)> = None;

        let shift_down = ctx.input(|i| i.modifiers.shift);
        let ctrl_down = ctx.input(|i| i.modifiers.ctrl || i.modifiers.command);

        let mut builder = TableBuilder::new(ui)
            .id_salt("cache_entries_table")
            .striped(true)
            .resizable(true)
            .sense(egui::Sense::click());

        for col in &cols {
            let init_w = default_col_width(*col);
            builder = builder.column(Column::initial(init_w).at_least(50.0).clip(true));
        }

        builder
            .header(22.0, |mut header| {
                for col in &cols {
                    header.col(|ui| {
                        let sort_field = col_to_sort_field(*col);
                        let mut title = col.header().to_string();
                        if let Some(sf) = sort_field {
                            if self.sort_primary == sf {
                                title.push_str(if self.sort_primary_desc { " ▼" } else { " ▲" });
                            } else if let Some((sec, sec_d)) = self.sort_secondary
                                && sec == sf
                            {
                                title.push_str(if sec_d { " ²▼" } else { " ²▲" });
                            }
                        }
                        let resp = ui.add(
                            egui::Button::new(egui::RichText::new(title).strong())
                                .frame(false),
                        );
                        if resp.clicked()
                            && let Some(sf) = sort_field
                        {
                            clicked_sort = Some((sf, shift_down));
                        }
                    });
                }
            })
            .body(|body| {
                body.rows(20.0, self.filtered_indices.len(), |mut row| {
                    let fpos = row.index();
                    let raw_idx = self.filtered_indices[fpos];
                    let is_sel = self.selected_rows.contains(&raw_idx);
                    row.set_selected(is_sel);
                    let entry = &self.all_cache_entries[raw_idx];

                    for col in &cols {
                        row.col(|ui| {
                            let val = if *col == CacheColumn::FileSize && entry.file_size > 1024 {
                                format!("{} ({})", entry.file_size, format_bytes(entry.file_size as u64))
                            } else {
                                col.value(entry, self.show_millis)
                            };
                            ui.label(val);
                        });
                    }

                    let resp = row.response();
                    if resp.clicked() {
                        clicked_row = Some((fpos, raw_idx));
                    }
                    if resp.double_clicked() {
                        double_clicked_raw = Some(raw_idx);
                    }
                    resp.context_menu(|ui| {
                        if ui.button("Properties (Enter)").clicked() {
                            context_action = Some((raw_idx, "props"));
                            ui.close();
                        }
                        if ui.button("Copy URL (Ctrl+U)").clicked() {
                            context_action = Some((raw_idx, "copy_url"));
                            ui.close();
                        }
                        if ui.button("Extract Selected... (F4)").clicked() {
                            context_action = Some((raw_idx, "extract"));
                            ui.close();
                        }
                        if ui.button("Delete Standalone File... (Del)").clicked() {
                            context_action = Some((raw_idx, "delete"));
                            ui.close();
                        }
                    });
                });
            });

        if let Some((sf, shift)) = clicked_sort {
            self.toggle_sort(sf, shift, ctx);
        }

        if let Some((fpos, raw_idx)) = clicked_row {
            if shift_down && let Some(anchor) = self.last_clicked_filtered_pos {
                let (lo, hi) = if anchor <= fpos {
                    (anchor, fpos)
                } else {
                    (fpos, anchor)
                };
                if !ctrl_down {
                    self.selected_rows.clear();
                }
                for p in lo..=hi {
                    self.selected_rows.insert(self.filtered_indices[p]);
                }
            } else if ctrl_down {
                if self.selected_rows.contains(&raw_idx) {
                    self.selected_rows.remove(&raw_idx);
                } else {
                    self.selected_rows.insert(raw_idx);
                }
                self.last_clicked_filtered_pos = Some(fpos);
            } else {
                self.selected_rows.clear();
                self.selected_rows.insert(raw_idx);
                self.last_clicked_filtered_pos = Some(fpos);
            }
            self.refresh_preview_for_selection(ctx);
        }

        if let Some(raw_idx) = double_clicked_raw
            && let Some(entry) = self.all_cache_entries.get(raw_idx)
        {
            self.properties_entry = Some(entry.clone());
        }

        if let Some((raw_idx, act)) = context_action {
            if !self.selected_rows.contains(&raw_idx) {
                self.selected_rows.clear();
                self.selected_rows.insert(raw_idx);
                self.refresh_preview_for_selection(ctx);
            }
            match act {
                "props" => {
                    if let Some(e) = self.all_cache_entries.get(raw_idx) {
                        self.properties_entry = Some(e.clone());
                    }
                }
                "copy_url" => self.copy_selected_urls(),
                "extract" => {
                    self.extract_dlg.open = true;
                    self.extract_dlg.only_selected = true;
                }
                "delete" => {
                    self.confirm_delete_open = true;
                }
                _ => {}
            }
        }
    }

    fn render_preview_pane(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.heading("Preview");
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                ui.selectable_value(&mut self.preview_mode, PreviewMode::Hex, "Hex");
                ui.selectable_value(&mut self.preview_mode, PreviewMode::Headers, "Headers");
                ui.selectable_value(&mut self.preview_mode, PreviewMode::Auto, "Auto");
            });
        });
        ui.separator();

        let Some(entry) = self.first_selected_cache_entry().cloned() else {
            ui.label("Select a cached item to inspect its payload, HTTP headers, or image preview.");
            return;
        };

        ui.label(
            egui::RichText::new(&entry.url)
                .small()
                .strong(),
        );
        ui.label(
            egui::RichText::new(format!(
                "{} | {} | {} | {}",
                entry.content_type.as_deref().unwrap_or("unknown"),
                format_bytes(entry.file_size as u64),
                entry.server_response,
                entry.cache_name
            ))
            .small()
            .weak(),
        );

        ui.horizontal(|ui| {
            if ui.small_button("Copy Preview (Ctrl+P)").clicked() {
                self.copy_preview_to_clipboard();
            }
            if ui.small_button("Properties").clicked() {
                self.properties_entry = Some(entry.clone());
            }
        });
        ui.separator();

        if self.preview_mode == PreviewMode::Headers {
            egui::ScrollArea::vertical().show(ui, |ui| {
                ui.label(egui::RichText::new(&entry.server_response).monospace().strong());
                for h in &entry.headers {
                    ui.label(egui::RichText::new(format!("{}: {}", h.name, h.value)).monospace().small());
                }
                if !entry.certificates.is_empty() {
                    ui.separator();
                    ui.label(egui::RichText::new("Certificates:").strong());
                    for c in &entry.certificates {
                        ui.label(egui::RichText::new(format!("Subject: {}", c.subject)).monospace().small());
                        ui.label(egui::RichText::new(format!("Issuer: {}", c.issuer)).monospace().small());
                    }
                }
            });
            return;
        }

        let Some(prev) = &self.current_preview else {
            ui.label("Loading payload...");
            return;
        };
        if let Some(err) = &prev.error {
            ui.colored_label(egui::Color32::LIGHT_RED, format!("Payload unavailable: {err}"));
            return;
        }
        if prev.raw_bytes.is_empty() {
            ui.label("Zero-length payload (header-only cache record).");
            return;
        }

        if self.preview_mode == PreviewMode::Auto {
            if let Some(tex) = &prev.texture {
                if let Some([w, h]) = prev.image_size {
                    ui.label(format!("Image dimensions: {w} x {h} px"));
                }
                let avail = ui.available_size();
                let size = tex.size_vec2();
                let scale = (avail.x / size.x.max(1.0))
                    .min((avail.y - 24.0).max(60.0) / size.y.max(1.0))
                    .min(1.0);
                ui.image((tex.id(), size * scale));
                return;
            }
            if let Some(txt) = &prev.text_preview {
                egui::ScrollArea::both().show(ui, |ui| {
                    let mut display = txt.clone();
                    ui.add(
                        egui::TextEdit::multiline(&mut display)
                            .font(egui::TextStyle::Monospace)
                            .desired_width(f32::INFINITY)
                            .interactive(false),
                    );
                });
                return;
            }
        }

        // Hex view (either explicitly chosen or binary fallback)
        egui::ScrollArea::vertical().show(ui, |ui| {
            let mut dump = String::new();
            for (idx, chunk) in prev.raw_bytes[..prev.raw_bytes.len().min(4096)]
                .chunks(16)
                .enumerate()
            {
                let hex: Vec<String> = chunk.iter().map(|b| format!("{b:02x}")).collect();
                let ascii: String = chunk
                    .iter()
                    .map(|&b| if b.is_ascii_graphic() || b == b' ' { b as char } else { '.' })
                    .collect();
                dump.push_str(&format!("{:04x}: {:<47}  |{}|\n", idx * 16, hex.join(" "), ascii));
            }
            if prev.raw_bytes.len() > 4096 {
                dump.push_str(&format!("... ({} total bytes)\n", prev.raw_bytes.len()));
            }
            ui.add(
                egui::TextEdit::multiline(&mut dump)
                    .font(egui::TextStyle::Monospace)
                    .desired_width(f32::INFINITY)
                    .interactive(false),
            );
        });
    }

    fn render_overview_tab(&mut self, ui: &mut egui::Ui) {
        let Some(rep) = self.report.clone() else {
            ui.centered_and_justified(|ui| {
                ui.label("Open a Chrome User Data or Profile folder to inspect forensic overview & generate reports.");
            });
            return;
        };

        egui::ScrollArea::vertical().show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.heading("User Data Forensic Overview");
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.button("Full Bundle (HTML+JSON+MD)").clicked() {
                        self.trigger_report_save(ReportFormat::All);
                    }
                    if ui.button("Save Markdown Report").clicked() {
                        self.trigger_report_save(ReportFormat::Markdown);
                    }
                    if ui.button("Save JSON Report").clicked() {
                        self.trigger_report_save(ReportFormat::Json);
                    }
                    if ui.button("Save HTML Report").clicked() {
                        self.trigger_report_save(ReportFormat::Html);
                    }
                });
            });
            ui.separator();

            let s = &rep.summary;
            egui::Grid::new("overview_kpi_grid")
                .num_columns(4)
                .spacing([16.0, 10.0])
                .show(ui, |ui| {
                    kpi_card(ui, "Profiles", &s.profile_count.to_string());
                    kpi_card(
                        ui,
                        "Cache Entries",
                        &format!("{} ({})", s.total_cache_entries, format_bytes(s.total_cache_bytes)),
                    );
                    kpi_card(
                        ui,
                        "History URLs / Visits",
                        &format!("{} / {}", s.total_history_urls, s.total_history_visits),
                    );
                    kpi_card(ui, "Downloads", &s.total_downloads.to_string());
                    ui.end_row();

                    kpi_card(ui, "Cookies", &s.total_cookies.to_string());
                    kpi_card(ui, "Saved Logins", &s.total_logins.to_string());
                    kpi_card(ui, "Bookmarks", &s.total_bookmarks.to_string());
                    kpi_card(ui, "Extensions", &s.total_extensions.to_string());
                    ui.end_row();

                    kpi_card(
                        ui,
                        "Open / Closed Tabs",
                        &format!("{} / {}", s.total_open_tabs, s.total_closed_tabs),
                    );
                    kpi_card(ui, "Storage Keys", &s.total_local_storage_keys.to_string());
                    kpi_card(ui, "Timeline Events", &s.total_timeline_events.to_string());
                    kpi_card(ui, "Forensic Findings", &s.total_findings.to_string());
                    ui.end_row();
                });

            ui.separator();
            ui.heading("Local State & Encryption Status");
            let ls = &rep.local_state;
            ui.label(format!(
                "Chrome Version: {} | OS Crypt Key Present: {} ({}) | Country: {} | Policies: {}",
                ls.chrome_version.as_deref().unwrap_or("Unknown"),
                ls.os_crypt_encrypted_key_present,
                ls.os_crypt_key_prefix.as_deref().unwrap_or("-"),
                ls.variations_country.as_deref().unwrap_or("-"),
                ls.policy_count
            ));
            if let Some(portal) = &ls.os_crypt_portal_info {
                ui.label(format!("OS Crypt Portal: {portal}"));
            }

            if !ls.profile_summaries.is_empty() {
                ui.add_space(6.0);
                for pm in &ls.profile_summaries {
                    ui.label(format!(
                        "• {} — Name: {} | Email: {} | Ephemeral: {} | Active: {}",
                        pm.dir_name,
                        pm.name.as_deref().unwrap_or("-"),
                        pm.user_name.as_deref().unwrap_or("-"),
                        pm.is_ephemeral,
                        format_local_opt(pm.active_time, false),
                    ));
                }
            }

            ui.separator();
            ui.heading("Top Domains by Activity");
            for d in rep.top_domains.iter().take(25) {
                ui.label(format!(
                    "{:<36} | visits: {:<5} | cache: {:<4} ({}) | cookies: {}",
                    d.domain,
                    d.history_visits,
                    d.cache_items,
                    format_bytes(d.cache_bytes),
                    d.cookies
                ));
            }
        });
    }

    fn render_findings_tab(&mut self, ui: &mut egui::Ui) {
        let Some(rep) = &self.report else {
            ui.label("No User Data report loaded.");
            return;
        };

        ui.horizontal_wrapped(|ui| {
            ui.label("Severity:");
            if ui
                .selectable_label(self.finding_sev_filter.is_none(), "All")
                .clicked()
            {
                self.finding_sev_filter = None;
            }
            for sev in [
                FindingSeverity::Critical,
                FindingSeverity::High,
                FindingSeverity::Medium,
                FindingSeverity::Low,
                FindingSeverity::Info,
            ] {
                if ui
                    .selectable_label(
                        self.finding_sev_filter == Some(sev),
                        sev.as_str().to_ascii_uppercase(),
                    )
                    .clicked()
                {
                    self.finding_sev_filter = Some(sev);
                }
            }
            ui.separator();
            ui.label("Search:");
            ui.text_edit_singleline(&mut self.forensic_search);
        });
        ui.separator();

        let sel_pname: Option<String> = self
            .selected_profile_idx
            .and_then(|idx| rep.profiles.get(idx))
            .map(|p| p.profile_name.clone());
        let q = self.forensic_search.trim().to_ascii_lowercase();

        egui::ScrollArea::vertical().show(ui, |ui| {
            let mut shown = 0usize;
            for f in &rep.findings {
                if let Some(ref sp) = sel_pname
                    && &f.profile != sp
                {
                    continue;
                }
                if let Some(sv) = self.finding_sev_filter
                    && f.severity != sv
                {
                    continue;
                }
                if !q.is_empty()
                    && !f.title.to_ascii_lowercase().contains(&q)
                    && !f.summary.to_ascii_lowercase().contains(&q)
                    && !f.category.to_ascii_lowercase().contains(&q)
                    && !f.evidence.iter().any(|e| e.to_ascii_lowercase().contains(&q))
                {
                    continue;
                }
                shown += 1;
                egui::Frame::group(ui.style()).show(ui, |ui| {
                    ui.horizontal(|ui| {
                        let color = match f.severity {
                            FindingSeverity::Critical => egui::Color32::from_rgb(239, 68, 68),
                            FindingSeverity::High => egui::Color32::from_rgb(249, 115, 22),
                            FindingSeverity::Medium => egui::Color32::from_rgb(234, 179, 8),
                            FindingSeverity::Low => egui::Color32::from_rgb(34, 197, 94),
                            FindingSeverity::Info => egui::Color32::from_rgb(56, 189, 248),
                        };
                        ui.colored_label(color, format!("[{}]", f.severity.as_str().to_ascii_uppercase()));
                        ui.strong(&f.title);
                        ui.label(format!("({} / {})", f.profile, f.category));
                    });
                    ui.label(&f.summary);
                    if !f.evidence.is_empty() {
                        ui.collapsing(format!("Evidence ({})", f.evidence.len()), |ui| {
                            for ev in &f.evidence {
                                ui.label(egui::RichText::new(ev).monospace().small());
                            }
                        });
                    }
                });
                ui.add_space(4.0);
            }
            if shown == 0 {
                ui.label("No findings match the current filters.");
            }
        });
    }

    fn render_timeline_tab(&mut self, ui: &mut egui::Ui) {
        let Some(rep) = &self.report else {
            ui.label("No report loaded.");
            return;
        };

        ui.horizontal_wrapped(|ui| {
            for cat in [
                "All",
                "History",
                "Download",
                "Cache",
                "Cookie",
                "Credential",
                "Bookmark",
                "Extension",
                "Session",
            ] {
                if ui
                    .selectable_label(self.timeline_cat_filter == cat, cat)
                    .clicked()
                {
                    self.timeline_cat_filter = cat.to_string();
                }
            }
            ui.separator();
            ui.label("Search:");
            ui.text_edit_singleline(&mut self.forensic_search);
        });
        ui.separator();

        let sel_pname: Option<&str> = self
            .selected_profile_idx
            .and_then(|idx| rep.profiles.get(idx))
            .map(|p| p.profile_name.as_str());
        let q = self.forensic_search.trim().to_ascii_lowercase();

        let filtered: Vec<_> = rep
            .timeline
            .iter()
            .filter(|ev| {
                if let Some(sp) = sel_pname
                    && ev.profile != sp
                {
                    return false;
                }
                if self.timeline_cat_filter != "All" && ev.category != self.timeline_cat_filter {
                    return false;
                }
                if !q.is_empty()
                    && !ev.target.to_ascii_lowercase().contains(&q)
                    && !ev.details.to_ascii_lowercase().contains(&q)
                    && !ev.event_type.to_ascii_lowercase().contains(&q)
                {
                    return false;
                }
                true
            })
            .collect();

        TableBuilder::new(ui)
            .id_salt("forensic_timeline_table")
            .striped(true)
            .resizable(true)
            .column(Column::initial(155.0).clip(true))
            .column(Column::initial(85.0).clip(true))
            .column(Column::initial(90.0).clip(true))
            .column(Column::initial(150.0).clip(true))
            .column(Column::initial(340.0).clip(true))
            .column(Column::initial(260.0).clip(true))
            .column(Column::initial(130.0).clip(true))
            .header(22.0, |mut hdr| {
                for h in [
                    "Timestamp",
                    "Profile",
                    "Category",
                    "Event",
                    "Target",
                    "Details",
                    "Artifact",
                ] {
                    hdr.col(|ui| {
                        ui.strong(h);
                    });
                }
            })
            .body(|body| {
                body.rows(20.0, filtered.len(), |mut row| {
                    let ev = filtered[row.index()];
                    row.col(|ui| {
                        ui.label(format_local_opt(Some(ev.timestamp), false));
                    });
                    row.col(|ui| {
                        ui.label(&ev.profile);
                    });
                    row.col(|ui| {
                        ui.label(&ev.category);
                    });
                    row.col(|ui| {
                        ui.label(&ev.event_type);
                    });
                    row.col(|ui| {
                        ui.label(&ev.target);
                    });
                    row.col(|ui| {
                        ui.label(&ev.details);
                    });
                    row.col(|ui| {
                        ui.label(&ev.source_artifact);
                    });
                });
            });
    }

    fn render_history_tab(&mut self, ui: &mut egui::Ui) {
        if self.visible_profiles().is_empty() {
            ui.label("No profile loaded.");
            return;
        }

        ui.horizontal_wrapped(|ui| {
            ui.selectable_value(&mut self.history_sub, HistorySubTab::Urls, "URLs");
            ui.selectable_value(&mut self.history_sub, HistorySubTab::Visits, "Visits");
            ui.selectable_value(&mut self.history_sub, HistorySubTab::Downloads, "Downloads");
            ui.selectable_value(
                &mut self.history_sub,
                HistorySubTab::SearchTerms,
                "Search Terms",
            );
            ui.separator();
            ui.label("Search:");
            ui.text_edit_singleline(&mut self.forensic_search);
        });
        let profiles = self.visible_profiles();
        for (_, p) in &profiles {
            let di = &p.history.deletion_indicators;
            ui.label(
                egui::RichText::new(format!(
                    "[{}] URLs: {} (seq {}, est. deleted: {}, hidden: {}) | Visits: {} (seq {}, est. deleted: {})",
                    p.profile_name,
                    di.urls_row_count,
                    di.urls_sqlite_seq,
                    di.urls_estimated_deleted,
                    di.hidden_urls_count,
                    di.visits_row_count,
                    di.visits_sqlite_seq,
                    di.visits_estimated_deleted
                ))
                .small()
                .weak(),
            );
        }
        ui.separator();

        let q = self.forensic_search.trim().to_ascii_lowercase();
        match self.history_sub {
            HistorySubTab::Urls => {
                let mut rows = Vec::new();
                for (_, p) in &profiles {
                    for u in &p.history.urls {
                        if q.is_empty()
                            || u.url.to_ascii_lowercase().contains(&q)
                            || u.title.to_ascii_lowercase().contains(&q)
                        {
                            rows.push((&p.profile_name, u));
                        }
                    }
                }
                TableBuilder::new(ui)
                    .id_salt("hist_urls_tbl")
                    .striped(true)
                    .resizable(true)
                    .column(Column::initial(85.0).clip(true))
                    .column(Column::initial(150.0).clip(true))
                    .column(Column::initial(60.0))
                    .column(Column::initial(60.0))
                    .column(Column::initial(260.0).clip(true))
                    .column(Column::initial(420.0).clip(true))
                    .header(22.0, |mut h| {
                        for t in ["Profile", "Last Visit", "Visits", "Typed", "Title", "URL"] {
                            h.col(|ui| {
                                ui.strong(t);
                            });
                        }
                    })
                    .body(|b| {
                        b.rows(20.0, rows.len(), |mut r| {
                            let (pn, u) = rows[r.index()];
                            r.col(|ui| { ui.label(pn); });
                            r.col(|ui| { ui.label(format_local_opt(u.last_visit_time, false)); });
                            r.col(|ui| { ui.label(u.visit_count.to_string()); });
                            r.col(|ui| { ui.label(u.typed_count.to_string()); });
                            r.col(|ui| { ui.label(&u.title); });
                            r.col(|ui| { ui.label(&u.url); });
                        });
                    });
            }
            HistorySubTab::Visits => {
                let mut rows = Vec::new();
                for (_, p) in &profiles {
                    for v in &p.history.visits {
                        if q.is_empty()
                            || v.url.to_ascii_lowercase().contains(&q)
                            || v.title.to_ascii_lowercase().contains(&q)
                            || v.transition_core.to_ascii_lowercase().contains(&q)
                        {
                            rows.push((&p.profile_name, v));
                        }
                    }
                }
                TableBuilder::new(ui)
                    .id_salt("hist_visits_tbl")
                    .striped(true)
                    .resizable(true)
                    .column(Column::initial(85.0).clip(true))
                    .column(Column::initial(150.0).clip(true))
                    .column(Column::initial(120.0).clip(true))
                    .column(Column::initial(140.0).clip(true))
                    .column(Column::initial(85.0).clip(true))
                    .column(Column::initial(220.0).clip(true))
                    .column(Column::initial(360.0).clip(true))
                    .header(22.0, |mut h| {
                        for t in ["Profile", "Visit Time", "Transition", "Qualifiers", "Dur (ms)", "Title", "URL"] {
                            h.col(|ui| {
                                ui.strong(t);
                            });
                        }
                    })
                    .body(|b| {
                        b.rows(20.0, rows.len(), |mut r| {
                            let (pn, v) = rows[r.index()];
                            r.col(|ui| { ui.label(pn); });
                            r.col(|ui| { ui.label(format_local_opt(v.visit_time, false)); });
                            r.col(|ui| { ui.label(&v.transition_core); });
                            r.col(|ui| { ui.label(v.transition_qualifiers.join(", ")); });
                            r.col(|ui| { ui.label(v.visit_duration_ms.to_string()); });
                            r.col(|ui| { ui.label(&v.title); });
                            r.col(|ui| { ui.label(&v.url); });
                        });
                    });
            }
            HistorySubTab::Downloads => {
                let mut rows = Vec::new();
                for (_, p) in &profiles {
                    for d in &p.history.downloads {
                        let urls = d.url_chain.join(" -> ");
                        if q.is_empty()
                            || d.target_path.to_ascii_lowercase().contains(&q)
                            || urls.to_ascii_lowercase().contains(&q)
                        {
                            rows.push((&p.profile_name, d, urls));
                        }
                    }
                }
                TableBuilder::new(ui)
                    .id_salt("hist_dl_tbl")
                    .striped(true)
                    .resizable(true)
                    .column(Column::initial(85.0).clip(true))
                    .column(Column::initial(150.0).clip(true))
                    .column(Column::initial(95.0).clip(true))
                    .column(Column::initial(140.0).clip(true))
                    .column(Column::initial(90.0).clip(true))
                    .column(Column::initial(280.0).clip(true))
                    .column(Column::initial(360.0).clip(true))
                    .header(22.0, |mut h| {
                        for t in ["Profile", "Start Time", "State", "Danger", "Bytes", "Target Path", "URL Chain"] {
                            h.col(|ui| {
                                ui.strong(t);
                            });
                        }
                    })
                    .body(|b| {
                        b.rows(20.0, rows.len(), |mut r| {
                            let (pn, d, urls) = &rows[r.index()];
                            r.col(|ui| { ui.label(*pn); });
                            r.col(|ui| { ui.label(format_local_opt(d.start_time, false)); });
                            r.col(|ui| { ui.label(&d.state); });
                            r.col(|ui| { ui.label(&d.danger_type); });
                            r.col(|ui| { ui.label(format_bytes(d.total_bytes.max(d.received_bytes).max(0) as u64)); });
                            r.col(|ui| { ui.label(&d.target_path); });
                            r.col(|ui| { ui.label(urls); });
                        });
                    });
            }
            HistorySubTab::SearchTerms => {
                let mut rows = Vec::new();
                for (_, p) in &profiles {
                    for s in &p.history.search_terms {
                        if q.is_empty()
                            || s.term.to_ascii_lowercase().contains(&q)
                            || s.url.as_deref().unwrap_or("").to_ascii_lowercase().contains(&q)
                        {
                            rows.push((&p.profile_name, s));
                        }
                    }
                }
                TableBuilder::new(ui)
                    .id_salt("hist_kw_tbl")
                    .striped(true)
                    .resizable(true)
                    .column(Column::initial(90.0).clip(true))
                    .column(Column::initial(155.0).clip(true))
                    .column(Column::initial(240.0).clip(true))
                    .column(Column::initial(420.0).clip(true))
                    .header(22.0, |mut h| {
                        for t in ["Profile", "Last Visit", "Search Term", "URL"] {
                            h.col(|ui| { ui.strong(t); });
                        }
                    })
                    .body(|b| {
                        b.rows(20.0, rows.len(), |mut r| {
                            let (pn, s) = rows[r.index()];
                            r.col(|ui| { ui.label(pn); });
                            r.col(|ui| { ui.label(format_local_opt(s.last_visit_time, false)); });
                            r.col(|ui| { ui.label(&s.term); });
                            r.col(|ui| { ui.label(s.url.as_deref().unwrap_or("")); });
                        });
                    });
            }
        }
    }

    fn render_creds_tab(&mut self, ui: &mut egui::Ui) {
        if self.visible_profiles().is_empty() {
            ui.label("No profile loaded.");
            return;
        }

        ui.horizontal_wrapped(|ui| {
            ui.selectable_value(&mut self.cred_sub, CredSubTab::Logins, "Saved Logins");
            ui.selectable_value(&mut self.cred_sub, CredSubTab::Cookies, "Cookies");
            ui.selectable_value(&mut self.cred_sub, CredSubTab::Autofill, "Autofill");
            ui.selectable_value(
                &mut self.cred_sub,
                CredSubTab::AddressesCards,
                "Addresses & Cards",
            );
            ui.separator();
            if ui.button("Decryption Keys...").clicked() {
                self.crypto_dlg.open = true;
            }
            ui.separator();
            ui.label("Search:");
            ui.text_edit_singleline(&mut self.forensic_search);
        });
        ui.separator();

        let q = self.forensic_search.trim().to_ascii_lowercase();
        let profiles = self.visible_profiles();
        match self.cred_sub {
            CredSubTab::Logins => {
                let mut rows = Vec::new();
                for (_, p) in &profiles {
                    for l in &p.logins {
                        if q.is_empty()
                            || l.origin_url.to_ascii_lowercase().contains(&q)
                            || l.username_value.to_ascii_lowercase().contains(&q)
                        {
                            rows.push((&p.profile_name, l));
                        }
                    }
                }
                TableBuilder::new(ui)
                    .id_salt("creds_logins_tbl")
                    .striped(true)
                    .resizable(true)
                    .column(Column::initial(80.0).clip(true))
                    .column(Column::initial(260.0).clip(true))
                    .column(Column::initial(160.0).clip(true))
                    .column(Column::initial(75.0).clip(true))
                    .column(Column::initial(170.0).clip(true))
                    .column(Column::initial(60.0))
                    .column(Column::initial(150.0).clip(true))
                    .column(Column::initial(170.0).clip(true))
                    .header(22.0, |mut h| {
                        for t in ["Profile", "Origin URL", "Username", "Scheme", "Password / Status", "Uses", "Last Used", "Issues"] {
                            h.col(|ui| { ui.strong(t); });
                        }
                    })
                    .body(|b| {
                        b.rows(20.0, rows.len(), |mut r| {
                            let (pn, l) = rows[r.index()];
                            let pw = l.password_decrypted.clone().unwrap_or_else(|| format!("[Encrypted {} B]", l.password_encrypted_len));
                            r.col(|ui| { ui.label(pn); });
                            r.col(|ui| { ui.label(&l.origin_url); });
                            r.col(|ui| { ui.label(&l.username_value); });
                            r.col(|ui| { ui.label(l.encryption_scheme.as_str()); });
                            r.col(|ui| { ui.label(pw); });
                            r.col(|ui| { ui.label(l.times_used.to_string()); });
                            r.col(|ui| { ui.label(format_local_opt(l.date_last_used, false)); });
                            r.col(|ui| { ui.label(l.insecure_issues.join(", ")); });
                        });
                    });
            }
            CredSubTab::Cookies => {
                let mut rows = Vec::new();
                for (_, p) in &profiles {
                    for c in &p.cookies {
                        if q.is_empty()
                            || c.host_key.to_ascii_lowercase().contains(&q)
                            || c.name.to_ascii_lowercase().contains(&q)
                            || c.value.as_deref().unwrap_or("").to_ascii_lowercase().contains(&q)
                        {
                            rows.push((&p.profile_name, c));
                        }
                    }
                }
                TableBuilder::new(ui)
                    .id_salt("creds_cookies_tbl")
                    .striped(true)
                    .resizable(true)
                    .column(Column::initial(80.0).clip(true))
                    .column(Column::initial(200.0).clip(true))
                    .column(Column::initial(150.0).clip(true))
                    .column(Column::initial(70.0).clip(true))
                    .column(Column::initial(210.0).clip(true))
                    .column(Column::initial(60.0))
                    .column(Column::initial(65.0))
                    .column(Column::initial(110.0).clip(true))
                    .column(Column::initial(150.0).clip(true))
                    .header(22.0, |mut h| {
                        for t in ["Profile", "Host Key", "Name", "Scheme", "Value / Status", "Secure", "HttpOnly", "SameSite", "Expires"] {
                            h.col(|ui| { ui.strong(t); });
                        }
                    })
                    .body(|b| {
                        b.rows(20.0, rows.len(), |mut r| {
                            let (pn, c) = rows[r.index()];
                            let val = c.value.clone().unwrap_or_else(|| format!("[Encrypted {} B]", c.encrypted_len));
                            r.col(|ui| { ui.label(pn); });
                            r.col(|ui| { ui.label(&c.host_key); });
                            r.col(|ui| { ui.label(&c.name); });
                            r.col(|ui| { ui.label(c.encryption_scheme.as_str()); });
                            r.col(|ui| { ui.label(val); });
                            r.col(|ui| { ui.label(if c.is_secure { "Yes" } else { "No" }); });
                            r.col(|ui| { ui.label(if c.is_httponly { "Yes" } else { "No" }); });
                            r.col(|ui| { ui.label(&c.samesite); });
                            r.col(|ui| { ui.label(format_local_opt(c.expires_utc, false)); });
                        });
                    });
            }
            CredSubTab::Autofill => {
                let mut rows = Vec::new();
                for (_, p) in &profiles {
                    for a in &p.web_data.autofill {
                        if q.is_empty()
                            || a.name.to_ascii_lowercase().contains(&q)
                            || a.value.to_ascii_lowercase().contains(&q)
                        {
                            rows.push((&p.profile_name, a));
                        }
                    }
                }
                TableBuilder::new(ui)
                    .id_salt("creds_autofill_tbl")
                    .striped(true)
                    .resizable(true)
                    .column(Column::initial(85.0).clip(true))
                    .column(Column::initial(180.0).clip(true))
                    .column(Column::initial(260.0).clip(true))
                    .column(Column::initial(65.0))
                    .column(Column::initial(155.0).clip(true))
                    .column(Column::initial(155.0).clip(true))
                    .header(22.0, |mut h| {
                        for t in ["Profile", "Field Name", "Value", "Count", "Created", "Last Used"] {
                            h.col(|ui| { ui.strong(t); });
                        }
                    })
                    .body(|b| {
                        b.rows(20.0, rows.len(), |mut r| {
                            let (pn, a) = rows[r.index()];
                            r.col(|ui| { ui.label(pn); });
                            r.col(|ui| { ui.label(&a.name); });
                            r.col(|ui| { ui.label(&a.value); });
                            r.col(|ui| { ui.label(a.count.to_string()); });
                            r.col(|ui| { ui.label(format_local_opt(a.date_created, false)); });
                            r.col(|ui| { ui.label(format_local_opt(a.date_last_used, false)); });
                        });
                    });
            }
            CredSubTab::AddressesCards => {
                egui::ScrollArea::vertical().show(ui, |ui| {
                    ui.heading("Saved Addresses");
                    for (_, p) in &profiles {
                        for a in &p.web_data.addresses {
                            ui.label(format!(
                                "[{}] {} | {} | {} {} {} {} | {} (uses: {})",
                                p.profile_name, a.full_name, a.email, a.street_address, a.city, a.state, a.zipcode, a.phone, a.use_count
                            ));
                        }
                    }
                    ui.separator();
                    ui.heading("Saved Payment Card Metadata");
                    for (_, p) in &profiles {
                        for c in &p.web_data.credit_cards {
                            ui.label(format!(
                                "[{}] {} | {} | ****{} | Exp: {}/{} | uses: {}",
                                p.profile_name, c.name_on_card, c.network, c.last_four, c.expiration_month, c.expiration_year, c.use_count
                            ));
                        }
                    }
                });
            }
        }
    }

    fn render_extensions_tab(&mut self, ui: &mut egui::Ui) {
        if self.visible_profiles().is_empty() {
            ui.label("No profile loaded.");
            return;
        }
        ui.horizontal(|ui| {
            ui.label("Search Extensions / Bookmarks:");
            ui.text_edit_singleline(&mut self.forensic_search);
        });
        ui.separator();
        let q = self.forensic_search.trim().to_ascii_lowercase();
        let profiles = self.visible_profiles();

        egui::ScrollArea::vertical().show(ui, |ui| {
            ui.heading("Installed Extensions");
            for (_, p) in &profiles {
                for ext in &p.extensions {
                    if !q.is_empty()
                        && !ext.name.to_ascii_lowercase().contains(&q)
                        && !ext.id.to_ascii_lowercase().contains(&q)
                        && !ext.risk_flags.iter().any(|r| r.to_ascii_lowercase().contains(&q))
                    {
                        continue;
                    }
                    egui::Frame::group(ui.style()).show(ui, |ui| {
                        ui.horizontal_wrapped(|ui| {
                            ui.strong(&ext.name);
                            ui.label(format!("v{} ({}) [{} | {}]", ext.version, ext.id, p.profile_name, ext.location));
                            if !ext.risk_flags.is_empty() {
                                ui.colored_label(
                                    egui::Color32::from_rgb(249, 115, 22),
                                    format!("RISK: {}", ext.risk_flags.join(", ")),
                                );
                            }
                        });
                        if !ext.permissions.is_empty() {
                            ui.label(
                                egui::RichText::new(format!("Permissions: {}", ext.permissions.join(", ")))
                                    .small()
                                    .weak(),
                            );
                        }
                    });
                }
            }

            ui.separator();
            ui.heading("Bookmarks");
            for (_, p) in &profiles {
                for b in p.bookmarks.iter().take(500) {
                    if !q.is_empty()
                        && !b.name.to_ascii_lowercase().contains(&q)
                        && !b.url.to_ascii_lowercase().contains(&q)
                        && !b.folder_path.to_ascii_lowercase().contains(&q)
                    {
                        continue;
                    }
                    ui.label(format!(
                        "[{}] [{}] {} -> {}",
                        p.profile_name, b.folder_path, b.name, b.url
                    ));
                }
            }
        });
    }

    fn render_sessions_tab(&mut self, ui: &mut egui::Ui) {
        if self.visible_profiles().is_empty() {
            ui.label("No profile loaded.");
            return;
        }
        ui.horizontal_wrapped(|ui| {
            ui.selectable_value(&mut self.sess_sub, SessionSubTab::Tabs, "SNSS Open & Closed Tabs");
            ui.selectable_value(
                &mut self.sess_sub,
                SessionSubTab::LocalStorage,
                "Local Storage (LevelDB)",
            );
            ui.selectable_value(
                &mut self.sess_sub,
                SessionSubTab::SessionStorage,
                "Session Storage (LevelDB)",
            );
            ui.selectable_value(
                &mut self.sess_sub,
                SessionSubTab::MiscInventory,
                "IndexedDB, Top Sites & File Inventory",
            );
            ui.separator();
            ui.label("Search:");
            ui.text_edit_singleline(&mut self.forensic_search);
        });
        ui.separator();

        let q = self.forensic_search.trim().to_ascii_lowercase();
        let sess_sub = self.sess_sub;
        let mut next_nav = self.selected_tab_nav_idx;
        let profiles = self.visible_profiles();
        egui::ScrollArea::vertical().show(ui, |ui| {
            match sess_sub {
                SessionSubTab::Tabs => {
                    for (pidx, p) in &profiles {
                        if p.sessions.encrypted_sessions_present {
                            ui.colored_label(
                                egui::Color32::LIGHT_BLUE,
                                format!("[{}] Sessions_Encrypted directory detected.", p.profile_name),
                            );
                        }
                        let mut tabs: Vec<_> = p
                            .sessions
                            .open_tabs
                            .iter()
                            .chain(p.sessions.closed_tabs.iter())
                            .enumerate()
                            .collect();
                        tabs.retain(|(_, t)| {
                            q.is_empty()
                                || t.current_url.to_ascii_lowercase().contains(&q)
                                || t.current_title.to_ascii_lowercase().contains(&q)
                        });
                        for (tidx, t) in tabs {
                            let state_tag = if t.is_closed { "CLOSED" } else { "OPEN" };
                            let selected = next_nav == Some((*pidx, tidx));
                            if ui
                                .selectable_label(
                                    selected,
                                    format!(
                                        "[{}] [{}] Tab #{} ({}) {} -> {} [{} navs]",
                                        p.profile_name,
                                        state_tag,
                                        t.tab_id,
                                        t.source_file,
                                        t.current_title,
                                        t.current_url,
                                        t.navigations.len()
                                    ),
                                )
                                .clicked()
                            {
                                next_nav = Some((*pidx, tidx));
                            }
                            if selected {
                                for nav in &t.navigations {
                                    ui.label(
                                        egui::RichText::new(format!(
                                            "    [{}] {} -> {}",
                                            nav.index, nav.title, nav.url
                                        ))
                                        .monospace()
                                        .small(),
                                    );
                                }
                            }
                        }
                    }
                }
                SessionSubTab::LocalStorage => {
                    for (_, p) in &profiles {
                        for kv in &p.storage.local_storage {
                            if !q.is_empty()
                                && !kv.origin.to_ascii_lowercase().contains(&q)
                                && !kv.key.to_ascii_lowercase().contains(&q)
                                && !kv.value.to_ascii_lowercase().contains(&q)
                            {
                                continue;
                            }
                            ui.label(
                                egui::RichText::new(format!(
                                    "[{}] {} | {} = {}",
                                    p.profile_name, kv.origin, kv.key, kv.value
                                ))
                                .monospace()
                                .small(),
                            );
                        }
                    }
                }
                SessionSubTab::SessionStorage => {
                    for (_, p) in &profiles {
                        for kv in &p.storage.session_storage {
                            if !q.is_empty()
                                && !kv.origin.to_ascii_lowercase().contains(&q)
                                && !kv.key.to_ascii_lowercase().contains(&q)
                                && !kv.value.to_ascii_lowercase().contains(&q)
                            {
                                continue;
                            }
                            ui.label(
                                egui::RichText::new(format!(
                                    "[{}] {} | {} = {}",
                                    p.profile_name, kv.origin, kv.key, kv.value
                                ))
                                .monospace()
                                .small(),
                            );
                        }
                    }
                }
                SessionSubTab::MiscInventory => {
                    for (_, p) in &profiles {
                        ui.heading(format!("{} — IndexedDB / Top Sites / Largest Files", p.profile_name));
                        for idb in &p.storage.indexed_db_origins {
                            ui.label(format!(
                                "IndexedDB: {} ({} files, {})",
                                idb.origin_dir,
                                idb.file_count,
                                format_bytes(idb.total_bytes)
                            ));
                        }
                        for ts in &p.storage.top_sites {
                            ui.label(format!("TopSite #{}: {} ({})", ts.rank, ts.title, ts.url));
                        }
                        for nel in &p.storage.nel_policies {
                            ui.label(format!("NEL Policy: {} (IP: {}, group: {})", nel.origin, nel.received_ip, nel.group_name));
                        }
                        ui.separator();
                        for f in p.file_inventory.iter().take(100) {
                            if !q.is_empty()
                                && !f.relative_path.to_ascii_lowercase().contains(&q)
                                && !f.category.to_ascii_lowercase().contains(&q)
                            {
                                continue;
                            }
                            ui.label(
                                egui::RichText::new(format!(
                                    "{:<22} {:>10}  {}",
                                    f.category,
                                    format_bytes(f.size_bytes),
                                    f.relative_path
                                ))
                                .monospace()
                                .small(),
                            );
                        }
                    }
                }
            }
        });
        self.selected_tab_nav_idx = next_nav;
    }

    fn render_extract_dialog(&mut self, ctx: &egui::Context) {
        if !self.extract_dlg.open {
            return;
        }
        let mut open = self.extract_dlg.open;
        egui::Window::new("Copy / Extract Selected Cache Files")
            .open(&mut open)
            .collapsible(false)
            .resizable(false)
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.label("Output Directory:");
                    ui.text_edit_singleline(&mut self.extract_dlg.output_dir);
                    if ui.button("Browse...").clicked()
                        && let Some(dir) = rfd::FileDialog::new().pick_folder()
                    {
                        self.extract_dlg.output_dir = dir.display().to_string();
                    }
                });
                ui.separator();
                ui.checkbox(
                    &mut self.extract_dlg.only_selected,
                    format!(
                        "Extract only selected items ({} selected; if unchecked exports all {} filtered)",
                        self.selected_rows.len(),
                        self.filtered_indices.len()
                    ),
                );
                ui.horizontal(|ui| {
                    ui.label("Filename Mode:");
                    ui.radio_value(
                        &mut self.extract_dlg.filename_mode,
                        ExtractFilenameMode::BasedOnUrl,
                        "Based on URL",
                    );
                    ui.radio_value(
                        &mut self.extract_dlg.filename_mode,
                        ExtractFilenameMode::CacheName,
                        "Cache Name",
                    );
                    ui.radio_value(
                        &mut self.extract_dlg.filename_mode,
                        ExtractFilenameMode::CacheNameWithExtension,
                        "Cache Name + Ext",
                    );
                });
                ui.checkbox(
                    &mut self.extract_dlg.use_website_dirs_proxy(),
                    "Save files in website directory structure (host/path)",
                );
                ui.checkbox(
                    &mut self.extract_dlg.update_mtime,
                    "Update modified time of extracted files to Last Accessed",
                );
                ui.checkbox(
                    &mut self.extract_dlg.new_name_if_exist,
                    "Auto-rename on collision instead of overwriting",
                );
                ui.checkbox(
                    &mut self.extract_dlg.decompress,
                    "Decompress gzip / deflate / br / zstd payloads",
                );
                ui.separator();
                ui.horizontal(|ui| {
                    if ui.button("Extract Now").clicked() {
                        let only_sel = self.extract_dlg.only_selected && !self.selected_rows.is_empty();
                        let refs = self.selected_or_filtered_entries(only_sel);
                        let opts = ExtractOptions {
                            output_dir: PathBuf::from(self.extract_dlg.output_dir.trim()),
                            filename_mode: self.extract_dlg.filename_mode,
                            use_website_dir_structure: self.extract_dlg.website_dirs,
                            update_modified_time: self.extract_dlg.update_mtime,
                            new_name_if_exist: self.extract_dlg.new_name_if_exist,
                            decompress: self.extract_dlg.decompress,
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
                            Err(e) => self.status_message = format!("Extraction failed: {e}"),
                        }
                        self.extract_dlg.open = false;
                    }
                    if ui.button("Cancel").clicked() {
                        self.extract_dlg.open = false;
                    }
                });
            });
        if !open {
            self.extract_dlg.open = false;
        }
    }

    fn render_export_dialog(&mut self, ctx: &egui::Context) {
        if !self.export_dlg.open {
            return;
        }
        let mut open = self.export_dlg.open;
        egui::Window::new("Export Cache Table")
            .open(&mut open)
            .collapsible(false)
            .resizable(false)
            .show(ctx, |ui| {
                ui.checkbox(
                    &mut self.export_dlg.only_selected,
                    "Export only selected rows",
                );
                ui.checkbox(
                    &mut self.export_dlg.include_header,
                    "Include column headers",
                );
                ui.separator();
                for (fmt, lbl, ext) in [
                    (ExportFormat::Csv, "Comma-Delimited (CSV)", "csv"),
                    (ExportFormat::Tab, "Tab-Delimited (TSV)", "tsv"),
                    (ExportFormat::Tabular, "Tabular Text", "txt"),
                    (ExportFormat::Text, "Plain Text Records", "txt"),
                    (ExportFormat::HtmlHorizontal, "HTML Report (Horizontal)", "html"),
                    (ExportFormat::HtmlVertical, "HTML Report (Vertical)", "html"),
                    (ExportFormat::Xml, "XML File", "xml"),
                    (ExportFormat::Json, "JSON File", "json"),
                ] {
                    if ui.selectable_value(&mut self.export_dlg.format, fmt, lbl).clicked() {
                        let _ = ext;
                    }
                }
                ui.separator();
                ui.horizontal(|ui| {
                    if ui.button("Save As...").clicked() {
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
                            let only_sel =
                                self.export_dlg.only_selected && !self.selected_rows.is_empty();
                            let entries: Vec<CacheEntry> = self
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
                                        self.status_message = format!(
                                            "Exported {} cache rows to {}",
                                            entries.len(),
                                            dest.display()
                                        );
                                    }
                                    Err(e) => self.status_message = format!("Write error: {e}"),
                                },
                                Err(e) => self.status_message = format!("Export error: {e}"),
                            }
                            self.export_dlg.open = false;
                        }
                    }
                    if ui.button("Close").clicked() {
                        self.export_dlg.open = false;
                    }
                });
            });
        if !open {
            self.export_dlg.open = false;
        }
    }

    fn render_crypto_dialog(&mut self, ctx: &egui::Context) {
        if !self.crypto_dlg.open {
            return;
        }
        let mut open = self.crypto_dlg.open;
        egui::Window::new("Optional Decryption Settings")
            .open(&mut open)
            .collapsible(false)
            .show(ctx, |ui| {
                ui.checkbox(
                    &mut self.crypto_dlg.decrypt_enabled,
                    "Attempt best-effort decryption (Cookies & Login Data)",
                );
                ui.checkbox(
                    &mut self.crypto_dlg.allow_peanuts,
                    "Allow Linux Chromium default fallback key ('peanuts')",
                );
                ui.label("Additional Passphrases or Hex AES-128/256 Keys (one per line):");
                ui.add(
                    egui::TextEdit::multiline(&mut self.crypto_dlg.keys_text)
                        .desired_rows(4)
                        .desired_width(360.0),
                );
                ui.horizontal(|ui| {
                    if ui.button("Apply & Reload Profile").clicked() {
                        self.crypto_dlg.open = false;
                        if !self.path_input.trim().is_empty() {
                            self.start_load(PathBuf::from(self.path_input.trim()), ctx);
                        }
                    }
                    if ui.button("Cancel").clicked() {
                        self.crypto_dlg.open = false;
                    }
                });
            });
        if !open {
            self.crypto_dlg.open = false;
        }
    }

    fn render_columns_dialog(&mut self, ctx: &egui::Context) {
        if !self.show_columns_dialog {
            return;
        }
        let mut open = self.show_columns_dialog;
        egui::Window::new("Choose Cache Columns")
            .open(&mut open)
            .collapsible(false)
            .show(ctx, |ui| {
                let all_cols = [
                    CacheColumn::Url,
                    CacheColumn::ContentType,
                    CacheColumn::FileSize,
                    CacheColumn::CompressedSize,
                    CacheColumn::LastAccessed,
                    CacheColumn::ServerTime,
                    CacheColumn::RecordCreatedTime,
                    CacheColumn::ExpirationTime,
                    CacheColumn::ServerName,
                    CacheColumn::ServerResponse,
                    CacheColumn::ContentEncoding,
                    CacheColumn::CacheName,
                    CacheColumn::UrlLength,
                    CacheColumn::WebSite,
                    CacheColumn::Frame,
                    CacheColumn::ServerIp,
                    CacheColumn::DeletedFile,
                    CacheColumn::Sha256,
                    CacheColumn::Backend,
                ];
                for col in all_cols {
                    let mut checked = self.active_cache_columns.contains(&col);
                    if ui.checkbox(&mut checked, col.header()).changed() {
                        if checked {
                            self.active_cache_columns.push(col);
                        } else if self.active_cache_columns.len() > 1 {
                            self.active_cache_columns.retain(|c| *c != col);
                        }
                    }
                }
                if ui.button("Reset Default").clicked() {
                    self.active_cache_columns = CacheColumn::default_columns();
                }
            });
        if !open {
            self.show_columns_dialog = false;
        }
    }

    fn render_properties_dialog(&mut self, ctx: &egui::Context) {
        let Some(entry) = self.properties_entry.clone() else {
            return;
        };
        let mut open = true;
        egui::Window::new(format!("Properties: {}", entry.cache_name))
            .open(&mut open)
            .default_width(640.0)
            .default_height(480.0)
            .show(ctx, |ui| {
                egui::ScrollArea::vertical().show(ui, |ui| {
                    let sha = entry.compute_sha256().unwrap_or_else(|| "-".into());
                    for (k, v) in [
                        ("URL", entry.url.as_str()),
                        ("Raw Key", entry.raw_key.as_str()),
                        ("Web Site", entry.partition_website.as_deref().unwrap_or("-")),
                        ("Frame", entry.partition_frame.as_deref().unwrap_or("-")),
                        ("Backend", entry.backend.as_str()),
                        ("Cache File", entry.cache_file_path.as_str()),
                        ("Content-Type", entry.raw_content_type.as_deref().unwrap_or("-")),
                        ("Encoding", entry.content_encoding.as_deref().unwrap_or("identity")),
                        ("Decompressed Size", &format!("{} bytes", entry.file_size)),
                        ("Compressed Size", &format!("{} bytes", entry.compressed_size)),
                        ("SHA-256", &sha),
                        ("Last Accessed", &format_local_opt(entry.last_accessed, true)),
                        ("Server Time", &format_local_opt(entry.server_time, false)),
                        ("Created Time", &format_local_opt(entry.record_created_time, true)),
                        ("Expiration Time", &format_local_opt(entry.expiration_time, false)),
                        ("TLS / ALPN", &format!("{} / {}", entry.tls_version.as_deref().unwrap_or("-"), entry.alpn_protocol.as_deref().unwrap_or("-"))),
                    ] {
                        ui.horizontal(|ui| {
                            ui.strong(format!("{k}:"));
                            ui.label(egui::RichText::new(v).monospace());
                        });
                    }
                    ui.separator();
                    ui.strong(format!("HTTP Response Headers ({})", entry.server_response));
                    for h in &entry.headers {
                        ui.label(egui::RichText::new(format!("{}: {}", h.name, h.value)).monospace().small());
                    }
                    if !entry.certificates.is_empty() {
                        ui.separator();
                        ui.strong("X.509 Certificate Chain");
                        for (idx, c) in entry.certificates.iter().enumerate() {
                            ui.label(format!("[{idx}] Subject: {}", c.subject));
                            ui.label(format!("    Issuer: {}", c.issuer));
                            ui.label(format!("    Valid: {} -> {}", c.not_before.as_deref().unwrap_or("?"), c.not_after.as_deref().unwrap_or("?")));
                        }
                    }
                });
            });
        if !open {
            self.properties_entry = None;
        }
    }

    fn render_delete_confirm_dialog(&mut self, ctx: &egui::Context) {
        if !self.confirm_delete_open {
            return;
        }
        let count = self.selected_rows.len();
        let mut open = self.confirm_delete_open;
        egui::Window::new("Confirm Standalone Cache File Deletion")
            .open(&mut open)
            .collapsible(false)
            .show(ctx, |ui| {
                ui.label(format!(
                    "Delete {count} selected standalone cache files (*_0 or Blockfile f_xxxxxx)?\n\
                     (Items stored inside shared Blockfile data_N containers will be skipped.)"
                ));
                ui.horizontal(|ui| {
                    if ui.button("Delete Selected Files").clicked() {
                        let refs = self.selected_or_filtered_entries(true);
                        let (deleted, skipped) = delete_cache_entries(&refs);
                        self.confirm_delete_open = false;
                        self.status_message = format!(
                            "Deleted {deleted} cache files ({} skipped).",
                            skipped.len()
                        );
                        if !self.path_input.trim().is_empty() {
                            self.start_load(PathBuf::from(self.path_input.trim()), ctx);
                        }
                    }
                    if ui.button("Cancel").clicked() {
                        self.confirm_delete_open = false;
                    }
                });
            });
        if !open {
            self.confirm_delete_open = false;
        }
    }
}

impl ExtractDialogState {
    fn use_website_dirs_proxy(&mut self) -> &mut bool {
        &mut self.website_dirs
    }
}

fn matches_quick_cat(entry: &CacheEntry, cat: ContentQuickCat) -> bool {
    let ct = entry.content_type.as_deref().unwrap_or("");
    match cat {
        ContentQuickCat::All => true,
        ContentQuickCat::Images => ct.starts_with("image/"),
        ContentQuickCat::Html => ct.contains("html"),
        ContentQuickCat::ScriptsStyles => {
            ct.contains("javascript") || ct.contains("ecmascript") || ct == "text/css"
        }
        ContentQuickCat::JsonXml => ct.contains("json") || ct.contains("xml"),
        ContentQuickCat::MediaFonts => {
            ct.starts_with("video/") || ct.starts_with("audio/") || ct.starts_with("font/")
        }
    }
}

fn col_to_sort_field(col: CacheColumn) -> Option<CacheSortField> {
    match col {
        CacheColumn::Url => Some(CacheSortField::Url),
        CacheColumn::ContentType => Some(CacheSortField::ContentType),
        CacheColumn::FileSize | CacheColumn::CompressedSize => Some(CacheSortField::FileSize),
        CacheColumn::LastAccessed => Some(CacheSortField::LastAccessed),
        CacheColumn::ServerTime => Some(CacheSortField::ServerTime),
        CacheColumn::RecordCreatedTime => Some(CacheSortField::RecordCreatedTime),
        CacheColumn::ExpirationTime => Some(CacheSortField::ExpirationTime),
        CacheColumn::ServerName => Some(CacheSortField::ServerName),
        CacheColumn::ServerResponse => Some(CacheSortField::ServerResponse),
        CacheColumn::ContentEncoding => Some(CacheSortField::ContentEncoding),
        CacheColumn::CacheName => Some(CacheSortField::CacheName),
        CacheColumn::UrlLength => Some(CacheSortField::UrlLength),
        CacheColumn::WebSite => Some(CacheSortField::WebSite),
        CacheColumn::Frame => Some(CacheSortField::Frame),
        CacheColumn::ServerIp => Some(CacheSortField::ServerIp),
        CacheColumn::DeletedFile => Some(CacheSortField::DeletedFile),
        CacheColumn::Sha256 | CacheColumn::Backend => None,
    }
}

fn default_col_width(col: CacheColumn) -> f32 {
    match col {
        CacheColumn::Url => 320.0,
        CacheColumn::ContentType => 130.0,
        CacheColumn::FileSize | CacheColumn::CompressedSize => 110.0,
        CacheColumn::LastAccessed
        | CacheColumn::ServerTime
        | CacheColumn::RecordCreatedTime
        | CacheColumn::ExpirationTime => 150.0,
        CacheColumn::ServerName => 140.0,
        CacheColumn::ServerResponse => 130.0,
        CacheColumn::ContentEncoding => 85.0,
        CacheColumn::CacheName => 150.0,
        CacheColumn::UrlLength => 75.0,
        CacheColumn::WebSite | CacheColumn::Frame => 170.0,
        CacheColumn::ServerIp => 125.0,
        CacheColumn::DeletedFile => 75.0,
        CacheColumn::Sha256 => 220.0,
        CacheColumn::Backend => 95.0,
    }
}

fn kpi_card(ui: &mut egui::Ui, label: &str, value: &str) {
    egui::Frame::group(ui.style()).show(ui, |ui| {
        ui.set_min_width(175.0);
        ui.label(egui::RichText::new(label).small().weak());
        ui.label(egui::RichText::new(value).strong().size(16.0));
    });
}

fn set_clipboard_text(text: &str) -> bool {
    if let Ok(mut cb) = arboard::Clipboard::new() {
        return cb.set_text(text.to_string()).is_ok();
    }
    false
}

pub fn run_gui(args: GuiArgs) -> Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1400.0, 860.0])
            .with_min_inner_size([960.0, 600.0])
            .with_title("chrome2rust — Chrome Cache Viewer & Forensic Suite"),
        ..Default::default()
    };

    eframe::run_native(
        "chrome2rust",
        options,
        Box::new(|cc| {
            egui_extras::install_image_loaders(&cc.egui_ctx);
            Ok(Box::new(Chrome2RustApp::new(args)))
        }),
    )
    .map_err(|e| anyhow!("Failed launching GUI (ensure X11/Wayland display is available or use CLI subcommands): {e}"))
}
