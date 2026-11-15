use crate::state::{ActiveModal, AppState, WorkspaceTab};
use chrome2rust_report::ReportFormat;
use eframe::egui::{self, Color32, RichText, Stroke, Vec2};
use std::path::PathBuf;

pub fn pick_target_folder(current_input: &str) -> Option<PathBuf> {
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

pub fn render_ribbon(ctx: &egui::Context, state: &mut AppState) {
    // 1. Classic Win32 Menu Bar
    egui::TopBottomPanel::top("top_menu_bar")
        .frame(
            egui::Frame::NONE
                .fill(Color32::from_rgb(240, 240, 240))
                .stroke(Stroke::new(1.0_f32, Color32::from_rgb(200, 200, 200)))
                .inner_margin(egui::Margin::symmetric(4, 2)),
        )
        .show(ctx, |ui| {
            egui::MenuBar::new().ui(ui, |ui| {
                ui.menu_button("File", |ui| {
                    if ui.button("Open User Data / Profile / Cache...").clicked() {
                        ui.close();
                        if let Some(folder) = pick_target_folder(&state.path_input) {
                            state.start_load(folder, ctx);
                        }
                    }
                    ui.menu_button("Discover Local Browsers", |ui| {
                        let browsers = state.discovered_browsers.clone();
                        if browsers.is_empty() {
                            ui.label("No local Chromium browsers detected");
                        } else {
                            for b in browsers {
                                ui.menu_button(b.name.clone(), |ui| {
                                    if b.user_data_dir.is_dir()
                                        && ui
                                            .button(format!("Full User Data ({})", b.user_data_dir.display()))
                                            .clicked()
                                    {
                                        ui.close();
                                        state.start_load(b.user_data_dir.clone(), ctx);
                                    }
                                    for p in &b.profiles {
                                        let label = format!(
                                            "Profile: {} ({})",
                                            p.dir_name,
                                            p.display_name.as_deref().unwrap_or("-")
                                        );
                                        if ui.button(label).clicked() {
                                            ui.close();
                                            state.start_load(p.path.clone(), ctx);
                                        }
                                        for c in &p.cache_dirs {
                                            if ui.button(format!("  Cache: {}", c.display())).clicked() {
                                                ui.close();
                                                state.start_load(c.clone(), ctx);
                                            }
                                        }
                                    }
                                });
                            }
                        }
                    });
                    ui.separator();
                    if ui.button("Extract Cached Payloads...  (F4)").clicked() {
                        ui.close();
                        state.extract_dlg.only_selected = !state.selected_rows.is_empty();
                        state.active_modal = ActiveModal::ExtractCache;
                    }
                    if ui.button("Export Cache Table...").clicked() {
                        ui.close();
                        state.active_modal = ActiveModal::ExportCacheTable;
                    }
                    ui.separator();
                    if ui.button("Generate HTML Report...").clicked() {
                        ui.close();
                        state.trigger_report_save(ReportFormat::Html);
                    }
                    if ui.button("Generate JSON Report...").clicked() {
                        ui.close();
                        state.trigger_report_save(ReportFormat::Json);
                    }
                    if ui.button("Generate Markdown Report...").clicked() {
                        ui.close();
                        state.trigger_report_save(ReportFormat::Markdown);
                    }
                    if ui.button("Generate Full Report Bundle...").clicked() {
                        ui.close();
                        state.trigger_report_save(ReportFormat::All);
                    }
                    ui.separator();
                    if ui.button("Exit  (Alt+F4)").clicked() {
                        ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                    }
                });

                ui.menu_button("Action", |ui| {
                    if ui.button("Select All Filtered  (Ctrl+A)").clicked() {
                        ui.close();
                        state.select_all_filtered(ctx);
                    }
                    if ui.button("Invert Selection").clicked() {
                        ui.close();
                        state.invert_selection_filtered(ctx);
                    }
                    if ui.button("Clear Selection  (Ctrl+D)").clicked() {
                        ui.close();
                        state.clear_selection(ctx);
                    }
                    ui.separator();
                    if ui.button("Copy Selected URLs  (Ctrl+U)").clicked() {
                        ui.close();
                        state.copy_selected_urls();
                    }
                    if ui.button("Copy Selected Rows TSV  (Ctrl+C)").clicked() {
                        ui.close();
                        state.copy_selected_rows_tsv();
                    }
                    if ui.button("Copy Preview Text/Image  (Ctrl+P)").clicked() {
                        ui.close();
                        state.copy_preview_to_clipboard();
                    }
                    ui.separator();
                    if ui
                        .add_enabled(
                            !state.selected_rows.is_empty(),
                            egui::Button::new("Delete Standalone Cache Files...  (Del)"),
                        )
                        .clicked()
                    {
                        ui.close();
                        state.active_modal = ActiveModal::ConfirmDelete;
                    }
                });

                ui.menu_button("View", |ui| {
                    ui.checkbox(&mut state.show_console_tree, "Show Console Tree Pane");
                    if ui
                        .checkbox(&mut state.show_preview_pane, "Show Preview Property Sheet  (F8)")
                        .changed()
                    {
                        state.refresh_preview_for_selection(ctx);
                    }
                    ui.checkbox(&mut state.show_quick_filter_bar, "Show Filter Strip  (Ctrl+Q)");
                    if ui
                        .checkbox(&mut state.hide_zero_length, "Hide Zero-Length Files")
                        .changed()
                    {
                        state.apply_cache_filter(ctx);
                    }
                    ui.checkbox(&mut state.show_millis, "Show Milliseconds in Timestamps");
                    ui.separator();
                    if ui.button("Choose Cache Table Columns...").clicked() {
                        ui.close();
                        state.active_modal = ActiveModal::ChooseColumns;
                    }
                });

                ui.menu_button("Tools", |ui| {
                    if ui.button("Decryption & Key Options...").clicked() {
                        ui.close();
                        state.active_modal = ActiveModal::DecryptionSettings;
                    }
                    if ui.button("Chain-of-Custody SHA-256 Merkle Audit...").clicked() {
                        ui.close();
                        state.active_modal = ActiveModal::CustodyManifest;
                    }
                    ui.separator();
                    for tab in [
                        WorkspaceTab::CacheInspector,
                        WorkspaceTab::Overview,
                        WorkspaceTab::Findings,
                        WorkspaceTab::Timeline,
                        WorkspaceTab::HistoryDownloads,
                        WorkspaceTab::CredsCookies,
                        WorkspaceTab::ExtensionsBookmarks,
                        WorkspaceTab::SessionsStorage,
                    ] {
                        if ui.button(tab.title()).clicked() {
                            ui.close();
                            state.active_tab = tab;
                        }
                    }
                });

                ui.menu_button("Help", |ui| {
                    if ui.button("About Chrome2Rust...").clicked() {
                        ui.close();
                        state.active_modal = ActiveModal::About;
                    }
                });

                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if state.is_loading {
                        ui.spinner();
                        ui.label(
                            RichText::new("Scanning Chrome artifacts...")
                                .size(11.0)
                                .color(Color32::from_rgb(0, 51, 153)),
                        );
                    }
                });
            });
        });

    // 2. Classic Win32 Flat Utility Toolbar & Target Address Strip
    egui::TopBottomPanel::top("top_toolbar")
        .frame(
            egui::Frame::NONE
                .fill(Color32::from_rgb(236, 233, 216))
                .stroke(Stroke::new(1.0_f32, Color32::from_rgb(172, 168, 153)))
                .inner_margin(egui::Margin::symmetric(6, 3)),
        )
        .show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing = Vec2::new(3.0, 0.0);

                if toolbar_button(ui, "Open...", "Open Chrome User Data, Profile, or Cache directory").clicked()
                    && let Some(folder) = pick_target_folder(&state.path_input)
                {
                    state.start_load(folder, ctx);
                }
                if toolbar_button(ui, "Refresh (F5)", "Re-scan the current Target path").clicked()
                    && !state.start_load_from_input(ctx)
                    && let Some(folder) = pick_target_folder(&state.path_input)
                {
                    state.start_load(folder, ctx);
                }

                ui.separator();

                if toolbar_button(ui, "Extract (F4)", "Extract cached payloads to disk").clicked() {
                    state.extract_dlg.only_selected = !state.selected_rows.is_empty();
                    state.active_modal = ActiveModal::ExtractCache;
                }
                if toolbar_button(ui, "Export", "Export cache table in CSV/TSV/HTML/JSON/XML").clicked() {
                    state.active_modal = ActiveModal::ExportCacheTable;
                }
                if toolbar_button(ui, "HTML Report", "Save full offline HTML forensic report").clicked() {
                    state.trigger_report_save(ReportFormat::Html);
                }
                if toolbar_button(ui, "Bundle", "Save HTML + JSON + Markdown forensic bundle").clicked() {
                    state.trigger_report_save(ReportFormat::All);
                }

                ui.separator();

                if toolbar_button(ui, "Decrypt Keys", "Configure v10/v11 decryption passphrases or keys").clicked() {
                    state.active_modal = ActiveModal::DecryptionSettings;
                }
                if toolbar_button(ui, "Custody Audit", "Compute SHA-256 & Merkle root custody manifest").clicked() {
                    state.active_modal = ActiveModal::CustodyManifest;
                }

                ui.separator();

                ui.label(RichText::new("Target:").size(11.0).strong().color(Color32::BLACK));
                let avail_edit = (ui.available_width() - 96.0).clamp(140.0, 380.0);
                let path_edit = ui.add_sized(
                    [avail_edit, 21.0],
                    egui::TextEdit::singleline(&mut state.path_input)
                        .hint_text("User Data, Profile, or Cache_Data path"),
                );
                if path_edit.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                    let _ = state.start_load_from_input(ctx);
                }
                if toolbar_button(ui, "Load", "Analyze the Target path (or pick a folder if blank)").clicked()
                    && !state.start_load_from_input(ctx)
                    && let Some(folder) = pick_target_folder(&state.path_input)
                {
                    state.start_load(folder, ctx);
                }
            });
        });
}

fn toolbar_button(ui: &mut egui::Ui, label: &str, tooltip: &str) -> egui::Response {
    let btn = egui::Button::new(RichText::new(label).size(11.0).color(Color32::BLACK))
        .fill(Color32::from_rgb(240, 240, 240))
        .stroke(Stroke::new(1.0_f32, Color32::from_rgb(172, 172, 172)))
        .corner_radius(egui::CornerRadius::same(2))
        .min_size(Vec2::new(48.0, 21.0));
    ui.add(btn).on_hover_text(tooltip)
}
