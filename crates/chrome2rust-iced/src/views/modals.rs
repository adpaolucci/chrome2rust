use crate::app::App;
use crate::message::{ActiveModal, ExportFormatChoice, FilenameModeChoice, Message};
use chrome2rust_cache::export::CacheColumn;
use chrome2rust_core::time::format_local_opt;
use chrome2rust_report::markdown::format_bytes;
use iced::widget::{
    button, checkbox, column, container, mouse_area, pick_list, row, rule, scrollable, text, text_input,
};
use iced::{Alignment, Color, Element, Font, Length};

pub fn view_modal(app: &App) -> Element<'_, Message> {
    let inner: Element<'_, Message> = match app.active_modal {
        ActiveModal::None => column![].into(),
        ActiveModal::ExtractCache => view_extract_modal(app),
        ActiveModal::ExportCacheTable => view_export_table_modal(app),
        ActiveModal::DecryptionSettings => view_decryption_modal(app),
        ActiveModal::ChooseColumns => view_columns_modal(app),
        ActiveModal::EntryProperties => view_properties_modal(app),
        ActiveModal::ConfirmDelete => view_confirm_delete_modal(app),
        ActiveModal::CustodyManifest => view_custody_modal(app),
        ActiveModal::About => view_about_modal(app),
    };

    mouse_area(
        container(inner)
            .padding(18)
            .width(Length::Fixed(600.0))
            .style(container::rounded_box),
    )
    .on_press(Message::OpenModal(app.active_modal))
    .into()
}

fn view_extract_modal(app: &App) -> Element<'_, Message> {
    column![
        text("Extract Cached Payloads").size(17),
        rule::horizontal(1),
        row![
            text("Output Dir:").size(12).width(Length::Fixed(90.0)),
            text_input("./extracted_cache", &app.extract_dlg.output_dir)
                .on_input(Message::ExtractOutputDirChanged)
                .size(12)
                .width(Length::Fill),
            button(text("Browse...").size(12))
                .on_press(Message::BrowseExtractOutputDir)
                .style(button::secondary),
        ]
        .spacing(8)
        .align_y(Alignment::Center),
        checkbox(app.extract_dlg.only_selected)
            .label(format!(
                "Extract only selected entries ({} selected; unchecked = {} shown)",
                app.selected_rows.len(),
                app.filtered_indices.len()
            ))
            .on_toggle(Message::ExtractOnlySelectedToggled),
        row![
            text("Filename Mode:").size(12).width(Length::Fixed(105.0)),
            pick_list(
                FilenameModeChoice::ALL,
                Some(FilenameModeChoice(app.extract_dlg.filename_mode)),
                Message::ExtractFilenameModeChanged,
            )
            .text_size(12),
        ]
        .spacing(8)
        .align_y(Alignment::Center),
        checkbox(app.extract_dlg.website_dirs)
            .label("Reconstruct website directory hierarchy (host/path)")
            .on_toggle(Message::ExtractWebsiteDirsToggled),
        checkbox(app.extract_dlg.update_mtime)
            .label("Preserve cached Last Accessed timestamps as file mtime")
            .on_toggle(Message::ExtractUpdateMtimeToggled),
        checkbox(app.extract_dlg.new_name_if_exist)
            .label("Auto-rename duplicate filenames instead of overwriting")
            .on_toggle(Message::ExtractNewNameToggled),
        checkbox(app.extract_dlg.decompress)
            .label("Automatically decompress gzip / deflate / br / zstd payloads")
            .on_toggle(Message::ExtractDecompressToggled),
        checkbox(app.extract_dlg.prefer_detected_extension)
            .label("Replace mismatched extension with payload-detected extension")
            .on_toggle(Message::ExtractPreferDetectedExtToggled),
        row![
            button(text("Extract").size(13))
                .on_press(Message::ConfirmExtractCache)
                .style(button::primary),
            button(text("Cancel").size(13))
                .on_press(Message::CloseModal)
                .style(button::secondary),
        ]
        .spacing(8),
    ]
    .spacing(8)
    .into()
}

fn view_export_table_modal(app: &App) -> Element<'_, Message> {
    column![
        text("Export Cache Table").size(17),
        rule::horizontal(1),
        checkbox(app.export_dlg.only_selected)
            .label("Export only selected rows")
            .on_toggle(Message::ExportOnlySelectedToggled),
        checkbox(app.export_dlg.include_header)
            .label("Include column headers")
            .on_toggle(Message::ExportIncludeHeaderToggled),
        row![
            text("Output Format:").size(12).width(Length::Fixed(100.0)),
            pick_list(
                ExportFormatChoice::ALL,
                Some(ExportFormatChoice(app.export_dlg.format)),
                Message::ExportFormatChanged,
            )
            .text_size(12),
        ]
        .spacing(8)
        .align_y(Alignment::Center),
        row![
            button(text("Save As...").size(13))
                .on_press(Message::ConfirmExportCacheTable)
                .style(button::primary),
            button(text("Close").size(13))
                .on_press(Message::CloseModal)
                .style(button::secondary),
        ]
        .spacing(8),
    ]
    .spacing(10)
    .into()
}

fn view_decryption_modal(app: &App) -> Element<'_, Message> {
    column![
        text("Optional Best-Effort Decryption Settings").size(17),
        rule::horizontal(1),
        checkbox(app.crypto_dlg.decrypt_enabled)
            .label("Attempt best-effort decryption (Cookies & Login Data)")
            .on_toggle(Message::CryptoDecryptToggled),
        checkbox(app.crypto_dlg.allow_peanuts)
            .label("Allow Linux Chromium default fallback key ('peanuts')")
            .on_toggle(Message::CryptoPeanutsToggled),
        text("Additional Passphrases or Hex AES-128/256 Keys (comma-separated):").size(12),
        text_input("passphrase or hex key", &app.crypto_dlg.keys_text)
            .on_input(Message::CryptoKeysChanged)
            .font(Font::MONOSPACE)
            .size(12),
        row![
            button(text("Apply & Reload").size(13))
                .on_press(Message::ApplyCryptoAndReload)
                .style(button::primary),
            button(text("Cancel").size(13))
                .on_press(Message::CloseModal)
                .style(button::secondary),
        ]
        .spacing(8),
    ]
    .spacing(10)
    .into()
}

fn view_columns_modal(app: &App) -> Element<'_, Message> {
    let mut cols_list = column![].spacing(4);
    for col in CacheColumn::all_columns() {
        let checked = app.active_cache_columns.contains(&col);
        cols_list = cols_list.push(
            checkbox(checked)
                .label(col.header())
                .on_toggle(move |b| Message::ToggleCacheColumn(col, b)),
        );
    }

    column![
        text("Choose Cache Columns").size(17),
        rule::horizontal(1),
        scrollable(cols_list).height(Length::Fixed(320.0)),
        row![
            button(text("OK").size(13))
                .on_press(Message::CloseModal)
                .style(button::primary),
            button(text("Reset Default").size(13))
                .on_press(Message::ResetDefaultColumns)
                .style(button::secondary),
        ]
        .spacing(8),
    ]
    .spacing(10)
    .into()
}

fn view_properties_modal(app: &App) -> Element<'_, Message> {
    let Some(entry) = &app.properties_entry else {
        return column![].into();
    };
    let sha = entry.compute_sha256().unwrap_or_else(|| "-".into());
    let det_ct = entry.detected_content_type.as_deref().unwrap_or("-");
    let det_ext = entry
        .detected_extension
        .as_deref()
        .map(|e| format!(".{e}"))
        .unwrap_or_else(|| "-".to_string());

    let mut body = column![
        text(format!("URL: {}", entry.url)).size(11).font(Font::MONOSPACE),
        text(format!("Backend: {}", entry.backend.as_str())).size(11),
        text(format!("Cache File: {}", entry.cache_file_path))
            .size(11)
            .font(Font::MONOSPACE),
        text(format!(
            "Declared Content-Type: {}",
            entry.raw_content_type.as_deref().unwrap_or("-")
        ))
        .size(11),
        text(format!("Detected Type: {det_ct} ({det_ext})")).size(11),
        text(format!(
            "File Signature: {}",
            entry.file_signature.as_deref().unwrap_or("-")
        ))
        .size(11),
        text(format!(
            "MIME Mismatch: {}",
            if entry.mime_mismatch { "YES" } else { "No" }
        ))
        .size(11),
        text(format!(
            "Sizes: {} decompressed / {} compressed",
            entry.file_size, entry.compressed_size
        ))
        .size(11),
        text(format!("SHA-256: {sha}")).size(11).font(Font::MONOSPACE),
        text(format!(
            "Last Accessed: {}",
            format_local_opt(entry.last_accessed, true)
        ))
        .size(11),
        text(format!("Server Time: {}", format_local_opt(entry.server_time, false))).size(11),
        text(format!(
            "TLS / ALPN: {} / {}",
            entry.tls_version.as_deref().unwrap_or("-"),
            entry.alpn_protocol.as_deref().unwrap_or("-")
        ))
        .size(11),
        rule::horizontal(1),
        text(format!("HTTP Headers ({}):", entry.server_response)).size(12),
    ]
    .spacing(3);

    for h in &entry.headers {
        body = body.push(text(format!("{}: {}", h.name, h.value)).size(11).font(Font::MONOSPACE));
    }

    column![
        text(format!("Properties: {}", entry.cache_name)).size(17),
        rule::horizontal(1),
        scrollable(body).height(Length::Fixed(380.0)),
        button(text("Close").size(13))
            .on_press(Message::CloseModal)
            .style(button::primary),
    ]
    .spacing(10)
    .into()
}

fn view_confirm_delete_modal(app: &App) -> Element<'_, Message> {
    column![
        text("Confirm Standalone Cache File Deletion")
            .size(17)
            .color(Color::from_rgb(0.75, 0.14, 0.14)),
        rule::horizontal(1),
        text(format!(
            "Delete {} selected standalone cache files (*_0 or Blockfile f_xxxxxx)?\n(Entries stored inside shared Blockfile data_N containers are preserved.)",
            app.selected_rows.len()
        ))
        .size(13),
        row![
            button(text("Delete").size(13))
                .on_press(Message::ConfirmDeleteSelected)
                .style(button::danger),
            button(text("Cancel").size(13))
                .on_press(Message::CloseModal)
                .style(button::secondary),
        ]
        .spacing(8),
    ]
    .spacing(10)
    .into()
}

fn view_custody_modal(app: &App) -> Element<'_, Message> {
    let mut col = column![
        text("Chain-of-Custody SHA-256 Merkle Audit").size(17),
        rule::horizontal(1),
        text(format!(
            "Target Path: {}",
            if app.path_input.trim().is_empty() {
                "(None selected)"
            } else {
                app.path_input.trim()
            }
        ))
        .size(12),
        row![
            button(text("Compute SHA-256 & Merkle Root").size(12))
                .on_press(Message::ComputeCustodyManifest)
                .style(button::primary),
            button(text("Save CSV / JSON...").size(12))
                .on_press_maybe(
                    app.custody_dlg
                        .manifest
                        .is_some()
                        .then_some(Message::SaveCustodyManifest)
                )
                .style(button::secondary),
        ]
        .spacing(8),
    ]
    .spacing(8);

    if let Some(ref st) = app.custody_dlg.status {
        col = col.push(text(st).size(12));
    }
    if let Some(ref m) = app.custody_dlg.manifest {
        col = col.push(
            text(format!("Merkle Root (SHA-256): {}", m.merkle_root_sha256))
                .size(11)
                .font(Font::MONOSPACE),
        );
        col = col.push(
            text(format!(
                "Artifacts Hashed: {} | Total Size: {}",
                m.artifact_count,
                format_bytes(m.total_bytes)
            ))
            .size(12),
        );
    }

    col = col.push(
        button(text("Close").size(13))
            .on_press(Message::CloseModal)
            .style(button::secondary),
    );
    col.into()
}

fn view_about_modal(app: &App) -> Element<'_, Message> {
    column![
        text(concat!("Chrome2Rust Forensic Workstation v", env!("CARGO_PKG_VERSION"))).size(17),
        rule::horizontal(1),
        text("Cross-Platform Iced 0.14 Edition (wgpu + tiny-skia CPU fallback)").size(13),
        text("Part of the GUAP Ecosystem (guap.ca) • Licensed under Apache-2.0").size(12),
        text(format!("Discovered local browsers: {}", app.discovered_browsers.len())).size(12),
        button(text("Close").size(13))
            .on_press(Message::CloseModal)
            .style(button::primary),
    ]
    .spacing(8)
    .into()
}
