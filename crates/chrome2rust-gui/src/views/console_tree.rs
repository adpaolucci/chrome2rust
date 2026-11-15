use crate::state::{AppState, WorkspaceTab};
use chrome2rust_report::markdown::format_bytes;
use eframe::egui::{self, Color32, RichText, ScrollArea, Stroke};

pub fn render_console_tree(ui: &mut egui::Ui, state: &mut AppState, ctx: &egui::Context) {
    ui.vertical(|ui| {
        // Classic Win32 Tree Header
        egui::Frame::NONE
            .fill(Color32::from_rgb(235, 235, 235))
            .stroke(Stroke::new(1.0_f32, Color32::from_rgb(180, 180, 180)))
            .inner_margin(egui::Margin::symmetric(5, 3))
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label(RichText::new("Console Tree").size(11.0).strong().color(Color32::BLACK));
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui.small_button("Reset").clicked() && state.selected_profile_idx.is_some() {
                            state.selected_profile_idx = None;
                            state.selected_rows.clear();
                            state.rebuild_cache_view(ctx);
                        }
                    });
                });
            });

        ui.add_space(2.0);

        // Sunken White TreeView Control (#7F9DB9 border)
        egui::Frame::NONE
            .fill(Color32::WHITE)
            .stroke(Stroke::new(1.0_f32, Color32::from_rgb(127, 157, 185)))
            .inner_margin(egui::Margin::symmetric(4, 4))
            .show(ui, |ui| {
                ScrollArea::vertical().show(ui, |ui| {
                    ui.set_width(ui.available_width());

                    // Section 1: Browser Profiles Store
                    ui.horizontal(|ui| {
                        ui.label(RichText::new("[-]").size(11.0).color(Color32::from_rgb(90, 90, 90)));
                        ui.label(
                            RichText::new("Chrome User Data Store")
                                .size(12.0)
                                .strong()
                                .color(Color32::BLACK),
                        );
                    });

                    ui.add_space(2.0);

                    if let Some(rep) = &state.report {
                        let total_items = rep.summary.total_cache_entries;
                        let mut next_profile = state.selected_profile_idx;
                        let mut changed_profile = false;

                        // All Profiles virtual root node
                        let all_active = state.selected_profile_idx.is_none();
                        let bg = if all_active {
                            Color32::from_rgb(49, 106, 197)
                        } else {
                            Color32::TRANSPARENT
                        };
                        let fg = if all_active { Color32::WHITE } else { Color32::BLACK };
                        egui::Frame::NONE
                            .fill(bg)
                            .inner_margin(egui::Margin::symmetric(4, 2))
                            .show(ui, |ui| {
                                ui.horizontal(|ui| {
                                    ui.add_space(6.0);
                                    if ui
                                        .selectable_label(
                                            all_active,
                                            RichText::new("All Profiles").size(11.5).strong().color(fg),
                                        )
                                        .clicked()
                                    {
                                        next_profile = None;
                                        changed_profile = true;
                                    }
                                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                        ui.label(RichText::new(format!("({total_items})")).size(10.5).color(
                                            if all_active {
                                                Color32::WHITE
                                            } else {
                                                Color32::from_rgb(120, 120, 120)
                                            },
                                        ));
                                    });
                                });
                            });

                        for (idx, p) in rep.profiles.iter().enumerate() {
                            let is_active = state.selected_profile_idx == Some(idx);
                            let p_bg = if is_active {
                                Color32::from_rgb(49, 106, 197)
                            } else {
                                Color32::TRANSPARENT
                            };
                            let p_fg = if is_active { Color32::WHITE } else { Color32::BLACK };
                            egui::Frame::NONE
                                .fill(p_bg)
                                .inner_margin(egui::Margin::symmetric(4, 2))
                                .show(ui, |ui| {
                                    ui.horizontal(|ui| {
                                        ui.add_space(14.0);
                                        if ui
                                            .selectable_label(
                                                is_active,
                                                RichText::new(&p.profile_name).size(11.5).color(p_fg),
                                            )
                                            .clicked()
                                        {
                                            next_profile = Some(idx);
                                            changed_profile = true;
                                        }
                                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                            ui.label(
                                                RichText::new(format!("({})", p.cache_entries.len())).size(10.5).color(
                                                    if is_active {
                                                        Color32::WHITE
                                                    } else {
                                                        Color32::from_rgb(120, 120, 120)
                                                    },
                                                ),
                                            );
                                        });
                                    });
                                });
                        }

                        if changed_profile && next_profile != state.selected_profile_idx {
                            state.selected_profile_idx = next_profile;
                            state.selected_rows.clear();
                            state.rebuild_cache_view(ctx);
                        }
                    } else {
                        ui.horizontal(|ui| {
                            ui.add_space(18.0);
                            ui.label(
                                RichText::new("(No target folder loaded)")
                                    .italics()
                                    .size(11.0)
                                    .color(Color32::from_rgb(130, 130, 130)),
                            );
                        });
                        ui.add_space(4.0);
                        ui.horizontal(|ui| {
                            ui.add_space(18.0);
                            if ui.small_button("Browse Target Folder...").clicked()
                                && let Some(folder) = crate::views::ribbon::pick_target_folder(&state.path_input)
                            {
                                state.start_load(folder, ctx);
                            }
                        });

                        let browser_choices: Vec<(String, std::path::PathBuf, usize)> = state
                            .discovered_browsers
                            .iter()
                            .filter_map(|b| {
                                let target = if b.user_data_dir.is_dir() {
                                    Some(b.user_data_dir.clone())
                                } else {
                                    b.cache_root_dir.clone()
                                };
                                target.map(|dir| (b.name.clone(), dir, b.profiles.len()))
                            })
                            .collect();

                        if !browser_choices.is_empty() {
                            ui.add_space(6.0);
                            ui.horizontal(|ui| {
                                ui.add_space(12.0);
                                ui.label(
                                    RichText::new("Detected Local Browsers:")
                                        .size(11.0)
                                        .strong()
                                        .color(Color32::from_rgb(60, 60, 60)),
                                );
                            });
                            for (name, dir, profile_count) in browser_choices {
                                ui.horizontal(|ui| {
                                    ui.add_space(18.0);
                                    let label = format!("{name} ({profile_count})");
                                    if ui
                                        .selectable_label(
                                            false,
                                            RichText::new(label).size(11.0).color(Color32::from_rgb(0, 51, 153)),
                                        )
                                        .on_hover_text(format!("Load {}", dir.display()))
                                        .clicked()
                                    {
                                        state.start_load(dir, ctx);
                                    }
                                });
                            }
                        }
                    }

                    ui.add_space(10.0);

                    // Section 2: Forensic Workspaces Navigation
                    ui.horizontal(|ui| {
                        ui.label(RichText::new("[-]").size(11.0).color(Color32::from_rgb(90, 90, 90)));
                        ui.label(
                            RichText::new("Forensic Workspaces")
                                .size(12.0)
                                .strong()
                                .color(Color32::BLACK),
                        );
                    });
                    ui.add_space(2.0);

                    let (cache_n, findings_n, tl_n, hist_n, creds_n, ext_n, sess_n, cache_bytes) = match &state.report {
                        Some(r) => (
                            state.all_cache_entries.len(),
                            r.findings.len(),
                            r.timeline.len(),
                            r.summary.total_history_urls,
                            r.summary.total_logins + r.summary.total_cookies,
                            r.summary.total_extensions + r.summary.total_bookmarks,
                            r.summary.total_open_tabs + r.summary.total_closed_tabs,
                            format_bytes(r.summary.total_cache_bytes),
                        ),
                        None => (0, 0, 0, 0, 0, 0, 0, "0 B".into()),
                    };

                    let items: [(WorkspaceTab, &str, String); 8] = [
                        (WorkspaceTab::CacheInspector, "HTTP Cache Entries", format!("{cache_n}")),
                        (WorkspaceTab::Overview, "Overview & Reports", cache_bytes),
                        (WorkspaceTab::Findings, "Forensic Findings", format!("{findings_n}")),
                        (WorkspaceTab::Timeline, "Unified Timeline", format!("{tl_n}")),
                        (
                            WorkspaceTab::HistoryDownloads,
                            "History & Downloads",
                            format!("{hist_n}"),
                        ),
                        (
                            WorkspaceTab::CredsCookies,
                            "Credentials & Cookies",
                            format!("{creds_n}"),
                        ),
                        (
                            WorkspaceTab::ExtensionsBookmarks,
                            "Extensions & Bookmarks",
                            format!("{ext_n}"),
                        ),
                        (WorkspaceTab::SessionsStorage, "Sessions & Storage", format!("{sess_n}")),
                    ];

                    for (tab, label, badge) in items {
                        let is_active = state.active_tab == tab;
                        let bg = if is_active {
                            Color32::from_rgb(49, 106, 197)
                        } else {
                            Color32::TRANSPARENT
                        };
                        let fg = if is_active { Color32::WHITE } else { Color32::BLACK };
                        let badge_fg = if is_active {
                            Color32::WHITE
                        } else {
                            Color32::from_rgb(0, 51, 153)
                        };

                        egui::Frame::NONE
                            .fill(bg)
                            .inner_margin(egui::Margin::symmetric(4, 2))
                            .show(ui, |ui| {
                                ui.horizontal(|ui| {
                                    ui.add_space(10.0);
                                    if ui
                                        .selectable_label(is_active, RichText::new(label).size(11.5).color(fg))
                                        .clicked()
                                    {
                                        state.active_tab = tab;
                                    }
                                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                        ui.label(RichText::new(format!("({badge})")).size(10.5).color(badge_fg));
                                    });
                                });
                            });
                    }
                });
            });
    });
}
