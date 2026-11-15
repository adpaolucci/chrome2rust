use crate::state::{ActiveModal, AppState, ContentQuickCat};
use chrome2rust_cache::CacheSortField;
use chrome2rust_cache::export::CacheColumn;
use chrome2rust_report::markdown::format_bytes;
use eframe::egui::{self, Color32, RichText, Stroke};
use egui_extras::{Column, TableBuilder};

pub fn render_cache_list(ui: &mut egui::Ui, state: &mut AppState, ctx: &egui::Context) {
    ui.vertical(|ui| {
        // Subheader showing active workspace, entry counts, and selection
        egui::Frame::NONE
            .fill(Color32::from_rgb(235, 235, 235))
            .stroke(Stroke::new(1.0_f32, Color32::from_rgb(180, 180, 180)))
            .inner_margin(egui::Margin::symmetric(5, 3))
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new(format!(
                            "HTTP Cache Inspector  ({} / {} entries displayed | {} selected)",
                            state.filtered_indices.len(),
                            state.all_cache_entries.len(),
                            state.selected_rows.len()
                        ))
                        .size(11.0)
                        .strong()
                        .color(Color32::BLACK),
                    );
                });
            });

        if state.show_quick_filter_bar {
            ui.add_space(2.0);
            let mut filter_changed = false;
            egui::Frame::NONE
                .fill(Color32::from_rgb(244, 243, 238))
                .stroke(Stroke::new(1.0_f32, Color32::from_rgb(172, 168, 153)))
                .inner_margin(egui::Margin::symmetric(5, 3))
                .show(ui, |ui| {
                    ui.horizontal_wrapped(|ui| {
                        ui.label(RichText::new("Filter:").size(11.0).strong().color(Color32::BLACK));
                        let resp = ui.add_sized(
                            [220.0, 20.0],
                            egui::TextEdit::singleline(&mut state.quick_filter)
                                .hint_text("URL, type, server, site, IP..."),
                        );
                        if state.focus_quick_filter {
                            resp.request_focus();
                            state.focus_quick_filter = false;
                        }
                        if resp.changed() {
                            filter_changed = true;
                        }
                        if !state.quick_filter.is_empty() && ui.small_button("Clear").clicked() {
                            state.quick_filter.clear();
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
                            if ui.selectable_label(state.content_cat == cat, label).clicked() {
                                state.content_cat = cat;
                                filter_changed = true;
                            }
                        }
                        ui.separator();
                        if ui.checkbox(&mut state.hide_zero_length, "No 0B").changed() {
                            filter_changed = true;
                        }
                        ui.separator();
                        if ui.small_button("Columns...").clicked() {
                            state.active_modal = ActiveModal::ChooseColumns;
                        }
                        if ui.small_button("Copy URLs").clicked() {
                            state.copy_selected_urls();
                        }
                    });
                });
            if filter_changed {
                state.apply_cache_filter(ctx);
            }
        }

        ui.add_space(2.0);

        // Sunken White ListView Container (#7F9DB9 border)
        egui::Frame::NONE
            .fill(Color32::WHITE)
            .stroke(Stroke::new(1.0_f32, Color32::from_rgb(127, 157, 185)))
            .inner_margin(egui::Margin::same(1))
            .show(ui, |ui| {
                ui.set_min_height(ui.available_height());

                if state.filtered_indices.is_empty() {
                    ui.centered_and_justified(|ui| {
                        ui.label(
                            RichText::new(
                                "No cache entries match the active filter (or no cache directory loaded yet).",
                            )
                            .size(11.5)
                            .color(Color32::from_rgb(110, 110, 110)),
                        );
                    });
                    return;
                }

                let cols = state.active_cache_columns.clone();
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
                                    if state.sort_primary == sf {
                                        title.push_str(if state.sort_primary_desc { " ▼" } else { " ▲" });
                                    } else if let Some((sec, sec_d)) = state.sort_secondary
                                        && sec == sf
                                    {
                                        title.push_str(if sec_d { " ²▼" } else { " ²▲" });
                                    }
                                }
                                let resp = ui.add(
                                    egui::Button::new(RichText::new(title).size(11.0).strong().color(Color32::BLACK))
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
                        body.rows(20.0, state.filtered_indices.len(), |mut row| {
                            let fpos = row.index();
                            let raw_idx = state.filtered_indices[fpos];
                            let is_sel = state.selected_rows.contains(&raw_idx);
                            row.set_selected(is_sel);
                            let entry = &state.all_cache_entries[raw_idx];

                            for col in &cols {
                                row.col(|ui| {
                                    let val = if *col == CacheColumn::FileSize && entry.file_size > 1024 {
                                        format!("{} ({})", entry.file_size, format_bytes(entry.file_size as u64))
                                    } else {
                                        col.value(entry, state.show_millis)
                                    };
                                    let fg = if is_sel { Color32::WHITE } else { Color32::BLACK };
                                    ui.label(RichText::new(val).size(11.0).color(fg));
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
                                if ui.button("Properties  (Enter)").clicked() {
                                    context_action = Some((raw_idx, "props"));
                                    ui.close();
                                }
                                if ui.button("Copy URL  (Ctrl+U)").clicked() {
                                    context_action = Some((raw_idx, "copy_url"));
                                    ui.close();
                                }
                                if ui.button("Extract Selected...  (F4)").clicked() {
                                    context_action = Some((raw_idx, "extract"));
                                    ui.close();
                                }
                                if ui.button("Delete Standalone File...  (Del)").clicked() {
                                    context_action = Some((raw_idx, "delete"));
                                    ui.close();
                                }
                            });
                        });
                    });

                if let Some((sf, shift)) = clicked_sort {
                    state.toggle_sort(sf, shift, ctx);
                }

                if let Some((fpos, raw_idx)) = clicked_row {
                    if shift_down && let Some(anchor) = state.last_clicked_filtered_pos {
                        let (lo, hi) = if anchor <= fpos { (anchor, fpos) } else { (fpos, anchor) };
                        if !ctrl_down {
                            state.selected_rows.clear();
                        }
                        for p in lo..=hi {
                            state.selected_rows.insert(state.filtered_indices[p]);
                        }
                    } else if ctrl_down {
                        if state.selected_rows.contains(&raw_idx) {
                            state.selected_rows.remove(&raw_idx);
                        } else {
                            state.selected_rows.insert(raw_idx);
                        }
                        state.last_clicked_filtered_pos = Some(fpos);
                    } else {
                        state.selected_rows.clear();
                        state.selected_rows.insert(raw_idx);
                        state.last_clicked_filtered_pos = Some(fpos);
                    }
                    state.refresh_preview_for_selection(ctx);
                }

                if let Some(raw_idx) = double_clicked_raw
                    && let Some(entry) = state.all_cache_entries.get(raw_idx)
                {
                    state.properties_entry = Some(entry.clone());
                    state.active_modal = ActiveModal::EntryProperties;
                }

                if let Some((raw_idx, act)) = context_action {
                    if !state.selected_rows.contains(&raw_idx) {
                        state.selected_rows.clear();
                        state.selected_rows.insert(raw_idx);
                        state.refresh_preview_for_selection(ctx);
                    }
                    match act {
                        "props" => {
                            if let Some(e) = state.all_cache_entries.get(raw_idx) {
                                state.properties_entry = Some(e.clone());
                                state.active_modal = ActiveModal::EntryProperties;
                            }
                        }
                        "copy_url" => state.copy_selected_urls(),
                        "extract" => {
                            state.extract_dlg.only_selected = true;
                            state.active_modal = ActiveModal::ExtractCache;
                        }
                        "delete" => {
                            state.active_modal = ActiveModal::ConfirmDelete;
                        }
                        _ => {}
                    }
                }
            });
    });
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
