use crate::app::App;
use crate::message::{ActiveModal, Message, PreviewMode};
use chrome2rust_report::markdown::format_bytes;
use iced::widget::{button, column, container, image, row, rule, scrollable, text};
use iced::{Alignment, Color, Element, Font, Length};

pub fn view_inspector_pane(app: &App) -> Element<'_, Message> {
    let header = row![
        text("Details / Inspector").size(14).width(Length::Fill),
        button(text("Auto").size(11))
            .on_press(Message::SetPreviewMode(PreviewMode::Auto))
            .style(if app.preview_mode == PreviewMode::Auto {
                button::primary
            } else {
                button::secondary
            }),
        button(text("Headers").size(11))
            .on_press(Message::SetPreviewMode(PreviewMode::Headers))
            .style(if app.preview_mode == PreviewMode::Headers {
                button::primary
            } else {
                button::secondary
            }),
        button(text("Hex").size(11))
            .on_press(Message::SetPreviewMode(PreviewMode::Hex))
            .style(if app.preview_mode == PreviewMode::Hex {
                button::primary
            } else {
                button::secondary
            }),
    ]
    .spacing(4)
    .align_y(Alignment::Center);

    let Some(entry) = app.first_selected_cache_entry() else {
        return column![
            header,
            rule::horizontal(1),
            text("Select a cached entry in the list to inspect its payload, HTTP response headers, or decoded image preview.")
                .size(12),
        ]
        .spacing(8)
        .into();
    };

    let det_str = match (&entry.detected_content_type, &entry.detected_extension) {
        (Some(dt), Some(ext)) => format!("{dt} (.{ext})"),
        (Some(dt), None) => dt.clone(),
        (None, Some(ext)) => format!(".{ext}"),
        (None, None) => "-".to_string(),
    };

    let mut meta = column![
        text(&entry.url).size(12),
        text(format!(
            "Declared: {} | Detected: {} | {} | {} | {}",
            entry.content_type.as_deref().unwrap_or("unknown"),
            det_str,
            format_bytes(entry.file_size as u64),
            entry.server_response,
            entry.cache_name
        ))
        .size(11),
    ]
    .spacing(4);

    if let Some(sig) = &entry.file_signature {
        meta = meta.push(text(format!("Signature: {sig}")).size(11));
    }
    if let Some(disp) = &entry.content_disposition_filename {
        meta = meta.push(text(format!("Disposition Filename: {disp}")).size(11));
    }
    if entry.mime_mismatch {
        meta = meta.push(
            text("Warning: Declared Content-Type contradicts detected payload signature")
                .size(11)
                .color(Color::from_rgb(0.75, 0.14, 0.14)),
        );
    }

    let first_raw_idx = app
        .filtered_indices
        .iter()
        .copied()
        .find(|idx| app.selected_rows.contains(idx));
    let mut actions = row![
        button(text("Copy Preview").size(11))
            .on_press(Message::CopyPreviewToClipboard)
            .style(button::secondary),
    ]
    .spacing(6);
    if let Some(raw_idx) = first_raw_idx {
        actions = actions.push(
            button(text("Properties...").size(11))
                .on_press(Message::InspectEntryProperties(raw_idx))
                .style(button::secondary),
        );
    }
    meta = meta.push(actions);

    let body: Element<'_, Message> = if app.preview_mode == PreviewMode::Headers {
        let mut hcol = column![text(&entry.server_response).size(12).font(Font::MONOSPACE)].spacing(3);
        for h in &entry.headers {
            hcol = hcol.push(text(format!("{}: {}", h.name, h.value)).size(11).font(Font::MONOSPACE));
        }
        if !entry.certificates.is_empty() {
            hcol = hcol.push(rule::horizontal(1));
            hcol = hcol.push(text("X.509 Certificates:").size(12));
            for c in &entry.certificates {
                hcol = hcol.push(text(format!("Subject: {}", c.subject)).size(11).font(Font::MONOSPACE));
                hcol = hcol.push(text(format!("Issuer: {}", c.issuer)).size(11).font(Font::MONOSPACE));
            }
        }
        scrollable(hcol).height(Length::Fill).into()
    } else if let Some(prev) = &app.current_preview {
        if let Some(err) = &prev.error {
            text(format!("Payload unavailable: {err}"))
                .size(12)
                .color(Color::from_rgb(0.75, 0.14, 0.14))
                .into()
        } else if prev.raw_bytes.is_empty() {
            text("Zero-length payload (header-only cache record).").size(12).into()
        } else if app.preview_mode == PreviewMode::Auto
            && let Some(handle) = &prev.image_handle
        {
            let mut col = column![].spacing(6);
            if let Some([w, h]) = prev.image_size {
                col = col.push(text(format!("Image dimensions: {w} x {h} px")).size(11));
            }
            col = col.push(image(handle.clone()).width(Length::Fill));
            scrollable(col).height(Length::Fill).into()
        } else if app.preview_mode == PreviewMode::Auto
            && let Some(txt) = &prev.text_preview
        {
            scrollable(text(txt).size(11).font(Font::MONOSPACE))
                .height(Length::Fill)
                .into()
        } else {
            let mut dump = String::new();
            for (idx, chunk) in prev.raw_bytes[..prev.raw_bytes.len().min(4096)].chunks(16).enumerate() {
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
                dump.push_str(&format!("{:04x}: {:<47}  |{}|\n", idx * 16, hex.join(" "), ascii));
            }
            if prev.raw_bytes.len() > 4096 {
                dump.push_str(&format!("... ({} total bytes)\n", prev.raw_bytes.len()));
            }
            scrollable(text(dump).size(11).font(Font::MONOSPACE))
                .height(Length::Fill)
                .into()
        }
    } else {
        text("Loading payload...").size(12).into()
    };

    let _ = ActiveModal::EntryProperties;
    column![
        header,
        rule::horizontal(1),
        container(meta)
            .padding(8)
            .width(Length::Fill)
            .style(container::bordered_box),
        container(body)
            .padding(8)
            .width(Length::Fill)
            .height(Length::Fill)
            .style(container::bordered_box),
    ]
    .spacing(8)
    .height(Length::Fill)
    .into()
}
