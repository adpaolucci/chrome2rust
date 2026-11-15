use crate::state::{ActiveModal, AppState, PreviewMode};
use chrome2rust_report::markdown::format_bytes;
use eframe::egui::{self, Color32, RichText, Stroke};

pub fn render_inspector_pane(ui: &mut egui::Ui, state: &mut AppState) {
    ui.vertical(|ui| {
        // Classic Win32 Details Property Header
        egui::Frame::NONE
            .fill(Color32::from_rgb(235, 235, 235))
            .stroke(Stroke::new(1.0_f32, Color32::from_rgb(180, 180, 180)))
            .inner_margin(egui::Margin::symmetric(5, 3))
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new("Details / Payload Inspector")
                            .size(11.0)
                            .strong()
                            .color(Color32::BLACK),
                    );
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        ui.selectable_value(&mut state.preview_mode, PreviewMode::Hex, "Hex");
                        ui.selectable_value(
                            &mut state.preview_mode,
                            PreviewMode::Headers,
                            "Headers",
                        );
                        ui.selectable_value(&mut state.preview_mode, PreviewMode::Auto, "Auto");
                    });
                });
            });

        ui.add_space(2.0);

        // Sunken White Inspector Pane
        egui::Frame::NONE
            .fill(Color32::WHITE)
            .stroke(Stroke::new(1.0_f32, Color32::from_rgb(127, 157, 185)))
            .inner_margin(egui::Margin::same(6))
            .show(ui, |ui| {
                ui.set_min_height(ui.available_height());

                let Some(entry) = state.first_selected_cache_entry().cloned() else {
                    ui.label(
                        RichText::new(
                            "Select a cached entry in the list to inspect its payload, HTTP response headers, or decoded image preview.",
                        )
                        .size(11.5)
                        .color(Color32::from_rgb(100, 100, 100)),
                    );
                    return;
                };

                // Metadata Header Frame
                egui::Frame::NONE
                    .fill(Color32::from_rgb(245, 245, 245))
                    .stroke(Stroke::new(1.0_f32, Color32::from_rgb(205, 205, 205)))
                    .inner_margin(egui::Margin::same(5))
                    .show(ui, |ui| {
                        ui.label(RichText::new(&entry.url).size(11.0).strong().color(Color32::BLACK));
                        let declared_ct = entry.content_type.as_deref().unwrap_or("unknown");
                        let det_str = match (&entry.detected_content_type, &entry.detected_extension) {
                            (Some(dt), Some(ext)) => format!("{dt} (.{ext})"),
                            (Some(dt), None) => dt.clone(),
                            (None, Some(ext)) => format!(".{ext}"),
                            (None, None) => "-".to_string(),
                        };
                        ui.label(
                            RichText::new(format!(
                                "Declared: {} | Detected: {} | {} | {} | {}",
                                declared_ct,
                                det_str,
                                format_bytes(entry.file_size as u64),
                                entry.server_response,
                                entry.cache_name
                            ))
                            .size(10.5)
                            .color(Color32::from_rgb(70, 70, 70)),
                        );
                        if let Some(sig) = &entry.file_signature {
                            ui.label(
                                RichText::new(format!("Signature: {sig}"))
                                    .size(10.5)
                                    .color(Color32::from_rgb(60, 60, 60)),
                            );
                        }
                        if let Some(disp) = &entry.content_disposition_filename {
                            ui.label(
                                RichText::new(format!("Disposition Filename: {disp}"))
                                    .size(10.5)
                                    .color(Color32::from_rgb(60, 60, 60)),
                            );
                        }
                        if entry.mime_mismatch {
                            ui.colored_label(
                                Color32::from_rgb(185, 0, 0),
                                "Warning: Declared Content-Type contradicts detected payload signature",
                            );
                        }
                        ui.add_space(2.0);
                        ui.horizontal(|ui| {
                            if ui.small_button("Copy Preview (Ctrl+P)").clicked() {
                                state.copy_preview_to_clipboard();
                            }
                            if ui.small_button("Properties (Enter)").clicked() {
                                state.properties_entry = Some(entry.clone());
                                state.active_modal = ActiveModal::EntryProperties;
                            }
                        });
                    });

                ui.add_space(4.0);

                if state.preview_mode == PreviewMode::Headers {
                    egui::ScrollArea::vertical().show(ui, |ui| {
                        ui.label(
                            RichText::new(&entry.server_response)
                                .monospace()
                                .size(11.5)
                                .strong()
                                .color(Color32::BLACK),
                        );
                        for h in &entry.headers {
                            ui.label(
                                RichText::new(format!("{}: {}", h.name, h.value))
                                    .monospace()
                                    .size(11.0)
                                    .color(Color32::BLACK),
                            );
                        }
                        if !entry.certificates.is_empty() {
                            ui.separator();
                            ui.label(
                                RichText::new("X.509 Certificates:")
                                    .strong()
                                    .size(11.0)
                                    .color(Color32::from_rgb(0, 51, 153)),
                            );
                            for c in &entry.certificates {
                                ui.label(
                                    RichText::new(format!("Subject: {}", c.subject))
                                        .monospace()
                                        .size(10.5),
                                );
                                ui.label(
                                    RichText::new(format!("Issuer: {}", c.issuer))
                                        .monospace()
                                        .size(10.5),
                                );
                            }
                        }
                    });
                    return;
                }

                let Some(prev) = &state.current_preview else {
                    ui.label("Loading payload...");
                    return;
                };
                if let Some(err) = &prev.error {
                    ui.colored_label(
                        Color32::from_rgb(180, 0, 0),
                        format!("Payload unavailable: {err}"),
                    );
                    return;
                }
                if prev.raw_bytes.is_empty() {
                    ui.label(
                        RichText::new("Zero-length payload (header-only cache record).")
                            .size(11.0)
                            .color(Color32::from_rgb(110, 110, 110)),
                    );
                    return;
                }

                if state.preview_mode == PreviewMode::Auto {
                    if let Some(tex) = &prev.texture {
                        if let Some([w, h]) = prev.image_size {
                            ui.label(
                                RichText::new(format!("Image dimensions: {w} x {h} px"))
                                    .size(11.0)
                                    .color(Color32::from_rgb(70, 70, 70)),
                            );
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

                // Hex viewer fallback or explicit Hex mode
                egui::ScrollArea::vertical().show(ui, |ui| {
                    let mut dump = String::new();
                    for (idx, chunk) in prev.raw_bytes[..prev.raw_bytes.len().min(4096)]
                        .chunks(16)
                        .enumerate()
                    {
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
                        dump.push_str(&format!(
                            "{:04x}: {:<47}  |{}|\n",
                            idx * 16,
                            hex.join(" "),
                            ascii
                        ));
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
            });
    });
}
