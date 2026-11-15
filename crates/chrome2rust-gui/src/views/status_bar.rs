use crate::state::{AppState, WorkspaceTab};
use chrome2rust_report::markdown::format_bytes;
use eframe::egui::{self, Color32, RichText, Stroke};

pub fn render_status_bar(ctx: &egui::Context, state: &AppState) {
    let win_face = Color32::from_rgb(236, 233, 216);
    let win_border = Color32::from_rgb(172, 168, 153);

    egui::TopBottomPanel::bottom("status_bar")
        .frame(
            egui::Frame::NONE
                .fill(win_face)
                .stroke(Stroke::new(1.0_f32, win_border))
                .inner_margin(egui::Margin::symmetric(3, 2)),
        )
        .show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing = egui::vec2(3.0, 0.0);

                // Segment 1: Active status message
                sunken_status_panel(ui, 340.0, |ui| {
                    ui.label(RichText::new(&state.status_message).size(11.0).color(Color32::BLACK));
                });

                // Segment 2: Active Workspace / Profile
                let profile_label = match (&state.report, state.selected_profile_idx) {
                    (Some(r), Some(idx)) => r.profiles.get(idx).map(|p| p.profile_name.as_str()).unwrap_or("All"),
                    (Some(_), None) => "All Profiles",
                    (None, _) => "None",
                };
                sunken_status_panel(ui, 160.0, |ui| {
                    ui.label(
                        RichText::new(format!("{} ({})", state.active_tab.title(), profile_label))
                            .size(11.0)
                            .color(Color32::BLACK),
                    );
                });

                if state.active_tab == WorkspaceTab::CacheInspector {
                    let vis_bytes: u64 = state
                        .filtered_indices
                        .iter()
                        .filter_map(|&idx| state.all_cache_entries.get(idx))
                        .map(|e| e.file_size as u64)
                        .sum();
                    sunken_status_panel(ui, 175.0, |ui| {
                        ui.label(
                            RichText::new(format!(
                                "Shown: {}/{} ({})",
                                state.filtered_indices.len(),
                                state.all_cache_entries.len(),
                                format_bytes(vis_bytes)
                            ))
                            .size(11.0)
                            .color(Color32::BLACK),
                        );
                    });

                    let sel_bytes: u64 = state
                        .selected_rows
                        .iter()
                        .filter_map(|&idx| state.all_cache_entries.get(idx))
                        .map(|e| e.file_size as u64)
                        .sum();
                    sunken_status_panel(ui, 155.0, |ui| {
                        ui.label(
                            RichText::new(format!(
                                "Selected: {} ({})",
                                state.selected_rows.len(),
                                format_bytes(sel_bytes)
                            ))
                            .size(11.0)
                            .color(Color32::BLACK),
                        );
                    });
                }

                // Right-aligned architecture badge
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    sunken_status_panel(ui, 235.0, |ui| {
                        ui.label(
                            RichText::new("100% Pure Rust - Read-Only Forensics")
                                .size(11.0)
                                .color(Color32::from_rgb(80, 80, 80)),
                        );
                    });
                });
            });
        });
}

fn sunken_status_panel<R>(ui: &mut egui::Ui, width: f32, add_contents: impl FnOnce(&mut egui::Ui) -> R) -> R {
    let frame = egui::Frame::NONE
        .fill(Color32::from_rgb(244, 243, 238))
        .stroke(Stroke::new(1.0_f32, Color32::from_rgb(172, 168, 153)))
        .inner_margin(egui::Margin::symmetric(5, 1));

    ui.allocate_ui_with_layout(
        egui::vec2(width, 18.0),
        egui::Layout::left_to_right(egui::Align::Center),
        |ui| frame.show(ui, add_contents).inner,
    )
    .inner
}
