use crate::state::{ActiveModal, AppState};
use chrome2rust_cache::delete_cache_entries;
use chrome2rust_cache::export::{
    CacheColumn, ExportFormat, ExtractFilenameMode, ExtractOptions, extract_cache_entries, render_cache_export,
};
use chrome2rust_core::time::format_local_opt;
use chrome2rust_forensics::custody::write_custody_manifest;
use chrome2rust_report::markdown::format_bytes;
use eframe::egui::{self, Color32, RichText, Stroke, Vec2};
use std::path::PathBuf;

pub fn render_modals(ctx: &egui::Context, state: &mut AppState) {
    match state.active_modal {
        ActiveModal::None => {}

        ActiveModal::ExtractCache => {
            let mut is_open = true;
            egui::Window::new("Extract Cached Payloads")
                .open(&mut is_open)
                .collapsible(false)
                .resizable(false)
                .fixed_size(Vec2::new(540.0, 315.0))
                .show(ctx, |ui| {
                    win32_groupbox(ui, "Destination Folder", |ui| {
                        ui.horizontal(|ui| {
                            ui.label(RichText::new("Output Dir:").strong().size(11.0));
                            ui.add(egui::TextEdit::singleline(&mut state.extract_dlg.output_dir).desired_width(310.0));
                            if win32_dialog_button(ui, "Browse...")
                                && let Some(dir) = rfd::FileDialog::new().pick_folder()
                            {
                                state.extract_dlg.output_dir = dir.display().to_string();
                            }
                        });
                    });

                    ui.add_space(4.0);
                    win32_groupbox(ui, "Extraction Options", |ui| {
                        ui.checkbox(
                            &mut state.extract_dlg.only_selected,
                            format!(
                                "Extract only selected entries ({} selected; if unchecked exports {} shown)",
                                state.selected_rows.len(),
                                state.filtered_indices.len()
                            ),
                        );
                        ui.horizontal(|ui| {
                            ui.label(RichText::new("Filename Mode:").strong().size(11.0));
                            ui.radio_value(
                                &mut state.extract_dlg.filename_mode,
                                ExtractFilenameMode::BasedOnUrl,
                                "Based on URL",
                            );
                            ui.radio_value(
                                &mut state.extract_dlg.filename_mode,
                                ExtractFilenameMode::CacheName,
                                "Cache Name",
                            );
                            ui.radio_value(
                                &mut state.extract_dlg.filename_mode,
                                ExtractFilenameMode::CacheNameWithExtension,
                                "Cache Name + Ext",
                            );
                        });
                        ui.checkbox(
                            &mut state.extract_dlg.website_dirs,
                            "Reconstruct website directory hierarchy (host/path)",
                        );
                        ui.checkbox(
                            &mut state.extract_dlg.update_mtime,
                            "Preserve cached Last Accessed timestamps as file mtime",
                        );
                        ui.checkbox(
                            &mut state.extract_dlg.new_name_if_exist,
                            "Auto-rename duplicate filenames instead of overwriting",
                        );
                        ui.checkbox(
                            &mut state.extract_dlg.decompress,
                            "Automatically decompress gzip / deflate / br / zstd payloads",
                        );
                        ui.checkbox(
                            &mut state.extract_dlg.prefer_detected_extension,
                            "Replace mismatched filename extension with payload-detected extension",
                        );
                    });

                    ui.add_space(8.0);
                    ui.separator();
                    ui.add_space(4.0);
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if win32_dialog_button(ui, "Cancel") {
                            state.active_modal = ActiveModal::None;
                        }
                        if win32_dialog_button(ui, "Extract") {
                            let only_sel = state.extract_dlg.only_selected && !state.selected_rows.is_empty();
                            let refs = state.selected_or_filtered_entries(only_sel);
                            let opts = ExtractOptions {
                                output_dir: PathBuf::from(state.extract_dlg.output_dir.trim()),
                                filename_mode: state.extract_dlg.filename_mode,
                                use_website_dir_structure: state.extract_dlg.website_dirs,
                                update_modified_time: state.extract_dlg.update_mtime,
                                new_name_if_exist: state.extract_dlg.new_name_if_exist,
                                decompress: state.extract_dlg.decompress,
                                prefer_detected_extension: state.extract_dlg.prefer_detected_extension,
                            };
                            match extract_cache_entries(&refs, &opts) {
                                Ok(sum) => {
                                    state.status_message = format!(
                                        "Extracted {} files ({}) to {} ({} skipped, {} failed).",
                                        sum.extracted_count,
                                        format_bytes(sum.bytes_written),
                                        opts.output_dir.display(),
                                        sum.skipped_empty_or_deleted,
                                        sum.failed_count
                                    );
                                }
                                Err(e) => {
                                    state.status_message = format!("Extraction failed: {e}");
                                }
                            }
                            state.active_modal = ActiveModal::None;
                        }
                    });
                });
            if !is_open {
                state.active_modal = ActiveModal::None;
            }
        }

        ActiveModal::ExportCacheTable => {
            let mut is_open = true;
            egui::Window::new("Export Cache Table")
                .open(&mut is_open)
                .collapsible(false)
                .resizable(false)
                .fixed_size(Vec2::new(380.0, 320.0))
                .show(ctx, |ui| {
                    win32_groupbox(ui, "Scope & Headers", |ui| {
                        ui.checkbox(&mut state.export_dlg.only_selected, "Export only selected rows");
                        ui.checkbox(&mut state.export_dlg.include_header, "Include column headers");
                    });
                    ui.add_space(4.0);
                    win32_groupbox(ui, "Output Format", |ui| {
                        for (fmt, lbl) in [
                            (ExportFormat::Csv, "Comma-Delimited (CSV)"),
                            (ExportFormat::Tab, "Tab-Delimited (TSV)"),
                            (ExportFormat::Tabular, "Tabular Text"),
                            (ExportFormat::Text, "Plain Text Records"),
                            (ExportFormat::HtmlHorizontal, "HTML Table Report (Horizontal)"),
                            (ExportFormat::HtmlVertical, "HTML Record Cards (Vertical)"),
                            (ExportFormat::Xml, "XML Structured Feed"),
                            (ExportFormat::Json, "JSON Array"),
                        ] {
                            ui.selectable_value(&mut state.export_dlg.format, fmt, lbl);
                        }
                    });
                    ui.add_space(8.0);
                    ui.separator();
                    ui.add_space(4.0);
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if win32_dialog_button(ui, "Close") {
                            state.active_modal = ActiveModal::None;
                        }
                        if win32_dialog_button(ui, "Save As...") {
                            let ext = match state.export_dlg.format {
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
                                let only_sel = state.export_dlg.only_selected && !state.selected_rows.is_empty();
                                let entries: Vec<_> = state
                                    .selected_or_filtered_entries(only_sel)
                                    .into_iter()
                                    .cloned()
                                    .collect();
                                match render_cache_export(
                                    &entries,
                                    state.export_dlg.format,
                                    &state.active_cache_columns,
                                    state.export_dlg.include_header,
                                    state.show_millis,
                                ) {
                                    Ok(txt) => match std::fs::write(&dest, txt) {
                                        Ok(()) => {
                                            state.status_message =
                                                format!("Exported {} cache rows to {}", entries.len(), dest.display());
                                        }
                                        Err(e) => state.status_message = format!("Write error: {e}"),
                                    },
                                    Err(e) => state.status_message = format!("Export error: {e}"),
                                }
                                state.active_modal = ActiveModal::None;
                            }
                        }
                    });
                });
            if !is_open {
                state.active_modal = ActiveModal::None;
            }
        }

        ActiveModal::DecryptionSettings => {
            let mut is_open = true;
            egui::Window::new("Optional Decryption Settings")
                .open(&mut is_open)
                .collapsible(false)
                .resizable(false)
                .fixed_size(Vec2::new(430.0, 260.0))
                .show(ctx, |ui| {
                    win32_groupbox(ui, "Credential & Cookie Decryption", |ui| {
                        ui.checkbox(
                            &mut state.crypto_dlg.decrypt_enabled,
                            "Attempt best-effort decryption (Cookies & Login Data)",
                        );
                        ui.checkbox(
                            &mut state.crypto_dlg.allow_peanuts,
                            "Allow Linux Chromium default fallback key ('peanuts')",
                        );
                        ui.add_space(4.0);
                        ui.label(
                            RichText::new("Additional Passphrases or Hex AES-128/256 Keys (one per line):").size(11.0),
                        );
                        ui.add(
                            egui::TextEdit::multiline(&mut state.crypto_dlg.keys_text)
                                .desired_rows(4)
                                .desired_width(390.0),
                        );
                    });
                    ui.add_space(8.0);
                    ui.separator();
                    ui.add_space(4.0);
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if win32_dialog_button(ui, "Cancel") {
                            state.active_modal = ActiveModal::None;
                        }
                        if win32_dialog_button(ui, "Apply & Reload") {
                            state.active_modal = ActiveModal::None;
                            if !state.path_input.trim().is_empty() {
                                state.start_load(PathBuf::from(state.path_input.trim()), ctx);
                            }
                        }
                    });
                });
            if !is_open {
                state.active_modal = ActiveModal::None;
            }
        }

        ActiveModal::ChooseColumns => {
            let mut is_open = true;
            egui::Window::new("Choose Cache Columns")
                .open(&mut is_open)
                .collapsible(false)
                .resizable(false)
                .fixed_size(Vec2::new(340.0, 480.0))
                .show(ctx, |ui| {
                    win32_groupbox(ui, "Visible Cache Table Columns", |ui| {
                        egui::ScrollArea::vertical().max_height(360.0).show(ui, |ui| {
                            for col in CacheColumn::all_columns() {
                                let mut checked = state.active_cache_columns.contains(&col);
                                if ui.checkbox(&mut checked, col.header()).changed() {
                                    if checked {
                                        state.active_cache_columns.push(col);
                                    } else if state.active_cache_columns.len() > 1 {
                                        state.active_cache_columns.retain(|c| *c != col);
                                    }
                                }
                            }
                        });
                    });
                    ui.add_space(8.0);
                    ui.separator();
                    ui.add_space(4.0);
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if win32_dialog_button(ui, "OK") {
                            state.active_modal = ActiveModal::None;
                        }
                        if win32_dialog_button(ui, "Reset Default") {
                            state.active_cache_columns = CacheColumn::default_columns();
                        }
                    });
                });
            if !is_open {
                state.active_modal = ActiveModal::None;
            }
        }

        ActiveModal::EntryProperties => {
            let Some(entry) = state.properties_entry.clone() else {
                state.active_modal = ActiveModal::None;
                return;
            };
            let mut is_open = true;
            egui::Window::new(format!("Properties: {}", entry.cache_name))
                .open(&mut is_open)
                .default_width(640.0)
                .default_height(480.0)
                .show(ctx, |ui| {
                    egui::ScrollArea::vertical().show(ui, |ui| {
                        let sha = entry.compute_sha256().unwrap_or_else(|| "-".into());
                        let det_ct = entry.detected_content_type.as_deref().unwrap_or("-");
                        let det_ext = entry
                            .detected_extension
                            .as_deref()
                            .map(|e| format!(".{e}"))
                            .unwrap_or_else(|| "-".to_string());
                        let sig = entry.file_signature.as_deref().unwrap_or("-");
                        let disp = entry.content_disposition_filename.as_deref().unwrap_or("-");
                        let mismatch_str = if entry.mime_mismatch {
                            "YES - Declared Content-Type contradicts detected payload"
                        } else {
                            "No"
                        };
                        let decomp_sz = format!("{} bytes", entry.file_size);
                        let comp_sz = format!("{} bytes", entry.compressed_size);
                        let last_acc = format_local_opt(entry.last_accessed, true);
                        let srv_time = format_local_opt(entry.server_time, false);
                        let cre_time = format_local_opt(entry.record_created_time, true);
                        let exp_time = format_local_opt(entry.expiration_time, false);
                        let tls_alpn = format!(
                            "{} / {}",
                            entry.tls_version.as_deref().unwrap_or("-"),
                            entry.alpn_protocol.as_deref().unwrap_or("-")
                        );
                        win32_groupbox(ui, "Cache Entry Metadata", |ui| {
                            for (k, v) in [
                                ("URL", entry.url.as_str()),
                                ("Raw Key", entry.raw_key.as_str()),
                                ("Web Site", entry.partition_website.as_deref().unwrap_or("-")),
                                ("Frame", entry.partition_frame.as_deref().unwrap_or("-")),
                                ("Backend", entry.backend.as_str()),
                                ("Cache File", entry.cache_file_path.as_str()),
                                (
                                    "Declared Content-Type",
                                    entry.raw_content_type.as_deref().unwrap_or("-"),
                                ),
                                ("Detected Type", det_ct),
                                ("Suggested Ext", det_ext.as_str()),
                                ("File Signature", sig),
                                ("Disposition File", disp),
                                ("MIME Mismatch", mismatch_str),
                                ("Encoding", entry.content_encoding.as_deref().unwrap_or("identity")),
                                ("Decompressed Size", decomp_sz.as_str()),
                                ("Compressed Size", comp_sz.as_str()),
                                ("SHA-256", sha.as_str()),
                                ("Last Accessed", last_acc.as_str()),
                                ("Server Time", srv_time.as_str()),
                                ("Created Time", cre_time.as_str()),
                                ("Expiration Time", exp_time.as_str()),
                                ("TLS / ALPN", tls_alpn.as_str()),
                            ] {
                                ui.horizontal(|ui| {
                                    ui.strong(format!("{k}:"));
                                    let color = if k == "MIME Mismatch" && entry.mime_mismatch {
                                        Color32::from_rgb(185, 0, 0)
                                    } else {
                                        Color32::BLACK
                                    };
                                    ui.label(RichText::new(v).monospace().size(11.0).color(color));
                                });
                            }
                        });
                        ui.add_space(4.0);
                        win32_groupbox(
                            ui,
                            &format!("HTTP Response Headers ({})", entry.server_response),
                            |ui| {
                                for h in &entry.headers {
                                    ui.label(RichText::new(format!("{}: {}", h.name, h.value)).monospace().size(10.5));
                                }
                            },
                        );
                        if !entry.certificates.is_empty() {
                            ui.add_space(4.0);
                            win32_groupbox(ui, "X.509 Certificate Chain", |ui| {
                                for (idx, c) in entry.certificates.iter().enumerate() {
                                    ui.label(format!("[{idx}] Subject: {}", c.subject));
                                    ui.label(format!("    Issuer: {}", c.issuer));
                                    ui.label(format!(
                                        "    Valid: {} -> {}",
                                        c.not_before.as_deref().unwrap_or("?"),
                                        c.not_after.as_deref().unwrap_or("?")
                                    ));
                                }
                            });
                        }
                    });
                });
            if !is_open {
                state.properties_entry = None;
                state.active_modal = ActiveModal::None;
            }
        }

        ActiveModal::ConfirmDelete => {
            let count = state.selected_rows.len();
            let mut is_open = true;
            egui::Window::new("Confirm Standalone Cache File Deletion")
                .open(&mut is_open)
                .collapsible(false)
                .resizable(false)
                .fixed_size(Vec2::new(420.0, 150.0))
                .show(ctx, |ui| {
                    win32_groupbox(ui, "Confirm File Deletion", |ui| {
                        ui.label(format!(
                            "Delete {count} selected standalone cache files (*_0 or Blockfile f_xxxxxx)?\n\
                             (Entries stored inside shared Blockfile data_N containers are preserved.)"
                        ));
                    });
                    ui.add_space(8.0);
                    ui.separator();
                    ui.add_space(4.0);
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if win32_dialog_button(ui, "Cancel") {
                            state.active_modal = ActiveModal::None;
                        }
                        if win32_dialog_button(ui, "Delete") {
                            let refs = state.selected_or_filtered_entries(true);
                            let (deleted, skipped) = delete_cache_entries(&refs);
                            state.active_modal = ActiveModal::None;
                            state.status_message =
                                format!("Deleted {deleted} cache files ({} skipped).", skipped.len());
                            if !state.path_input.trim().is_empty() {
                                state.start_load(PathBuf::from(state.path_input.trim()), ctx);
                            }
                        }
                    });
                });
            if !is_open {
                state.active_modal = ActiveModal::None;
            }
        }

        ActiveModal::CustodyManifest => {
            let mut is_open = true;
            egui::Window::new("Chain-of-Custody SHA-256 Merkle Audit")
                .open(&mut is_open)
                .collapsible(false)
                .resizable(false)
                .fixed_size(Vec2::new(560.0, 340.0))
                .show(ctx, |ui| {
                    win32_groupbox(ui, "Evidence Scope", |ui| {
                        ui.label(format!(
                            "Target Path: {}",
                            if state.path_input.trim().is_empty() {
                                "(None selected)"
                            } else {
                                state.path_input.trim()
                            }
                        ));
                        ui.horizontal(|ui| {
                            if win32_dialog_button(ui, "Compute SHA-256 & Merkle Root") {
                                state.generate_custody_for_target();
                            }
                            if state.custody_dlg.manifest.is_some()
                                && win32_dialog_button(ui, "Save CSV / JSON...")
                                && let Some(dest) = rfd::FileDialog::new()
                                    .set_title("Save Chain-of-Custody Manifest")
                                    .set_file_name("custody_manifest.json")
                                    .save_file()
                                && let Some(ref manifest) = state.custody_dlg.manifest
                            {
                                match write_custody_manifest(manifest, &dest) {
                                    Ok(()) => {
                                        state.custody_dlg.status =
                                            Some(format!("Saved manifest to {}", dest.display()));
                                    }
                                    Err(e) => {
                                        state.custody_dlg.status = Some(format!("Error saving manifest: {e}"));
                                    }
                                }
                            }
                        });
                    });

                    if let Some(ref st) = state.custody_dlg.status {
                        ui.add_space(4.0);
                        let err = st.starts_with("Error");
                        let c = if err {
                            Color32::from_rgb(180, 0, 0)
                        } else {
                            Color32::from_rgb(0, 110, 0)
                        };
                        ui.label(RichText::new(st).color(c).size(11.0));
                    }

                    if let Some(ref m) = state.custody_dlg.manifest {
                        ui.add_space(4.0);
                        win32_groupbox(ui, "Merkle Verification Results", |ui| {
                            ui.label(
                                RichText::new(format!("Merkle Root (SHA-256): {}", m.merkle_root_sha256))
                                    .monospace()
                                    .size(10.5),
                            );
                            ui.label(format!(
                                "Hashed Files: {} | Total Volume: {}",
                                m.artifact_count,
                                format_bytes(m.total_bytes)
                            ));
                            egui::ScrollArea::vertical().max_height(110.0).show(ui, |ui| {
                                for a in m.artifacts.iter().take(150) {
                                    ui.label(
                                        RichText::new(format!(
                                            "[{}] {} | {}",
                                            a.category,
                                            &a.sha256[..16.min(a.sha256.len())],
                                            a.relative_path
                                        ))
                                        .monospace()
                                        .size(10.0),
                                    );
                                }
                            });
                        });
                    }

                    ui.add_space(6.0);
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if win32_dialog_button(ui, "Close") {
                            state.active_modal = ActiveModal::None;
                        }
                    });
                });
            if !is_open {
                state.active_modal = ActiveModal::None;
            }
        }

        ActiveModal::About => {
            let mut is_open = true;
            egui::Window::new("About Chrome2Rust")
                .open(&mut is_open)
                .collapsible(false)
                .resizable(false)
                .fixed_size(Vec2::new(450.0, 235.0))
                .show(ctx, |ui| {
                    ui.label(
                        RichText::new(format!("Chrome2Rust Management Console v{}", env!("CARGO_PKG_VERSION")))
                            .size(14.0)
                            .strong()
                            .color(Color32::from_rgb(0, 51, 153)),
                    );
                    ui.label(
                        RichText::new("Pure-Rust Google Chrome HTTP Cache Inspector & User Data Forensic Suite")
                            .size(11.0),
                    );
                    ui.add_space(6.0);
                    ui.separator();
                    ui.add_space(4.0);
                    ui.label("• 100% Pure Rust with zero WebView / Node.js / Electron runtime overhead");
                    ui.label("• Full Simple Cache (*_0) & Blockfile (data_0..data_3) inspection & extraction");
                    ui.label("• Complete User Data SQLite, SNSS Session/Tabs, LevelDB, and Extension forensics");
                    ui.label("• SHA-256 chain-of-custody Merkle manifests & offline HTML/JSON/MD reports");
                    ui.add_space(8.0);
                    ui.separator();
                    ui.add_space(4.0);
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if win32_dialog_button(ui, "OK") {
                            state.active_modal = ActiveModal::None;
                        }
                    });
                });
            if !is_open {
                state.active_modal = ActiveModal::None;
            }
        }
    }
}

fn win32_groupbox<R>(ui: &mut egui::Ui, title: &str, add_contents: impl FnOnce(&mut egui::Ui) -> R) -> R {
    ui.vertical(|ui| {
        ui.label(
            RichText::new(title)
                .size(11.0)
                .strong()
                .color(Color32::from_rgb(0, 51, 153)),
        );
        egui::Frame::NONE
            .fill(Color32::from_rgb(244, 243, 238))
            .stroke(Stroke::new(1.0_f32, Color32::from_rgb(180, 180, 180)))
            .inner_margin(egui::Margin::same(6))
            .show(ui, add_contents)
            .inner
    })
    .inner
}

fn win32_dialog_button(ui: &mut egui::Ui, text: &str) -> bool {
    let btn = egui::Button::new(RichText::new(text).size(11.0).color(Color32::BLACK))
        .fill(Color32::from_rgb(240, 240, 240))
        .stroke(Stroke::new(1.0_f32, Color32::from_rgb(160, 160, 160)))
        .corner_radius(egui::CornerRadius::same(2))
        .min_size(Vec2::new(75.0, 23.0));
    ui.add(btn).clicked()
}
