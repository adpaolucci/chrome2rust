use crate::app::App;
use crate::message::{ActiveModal, ContentQuickCat, Message};
use chrome2rust_cache::CacheSortField;
use chrome2rust_cache::export::CacheColumn;
use chrome2rust_report::markdown::format_bytes;
use iced::widget::{button, checkbox, column, container, row, rule, scrollable, text, text_input};
use iced::{Alignment, Color, Element, Font, Length};

const MAX_DISPLAY_ROWS: usize = 2_000;

pub fn view_cache_list(app: &App) -> Element<'_, Message> {
    let header = row![
        text(format!(
            "HTTP Cache Inspector  ({} / {} entries displayed | {} selected)",
            app.filtered_indices.len(),
            app.all_cache_entries.len(),
            app.selected_rows.len()
        ))
        .size(16)
        .width(Length::Fill),
        button(text("Select All").size(11))
            .on_press(Message::SelectAllFiltered)
            .style(button::secondary),
        button(text("Invert").size(11))
            .on_press(Message::InvertSelectionFiltered)
            .style(button::secondary),
        button(text("Clear Sel").size(11))
            .on_press(Message::ClearSelection)
            .style(button::secondary),
    ]
    .spacing(6)
    .align_y(Alignment::Center);

    let mut filter_bar = row![
        text("Filter:").size(12),
        text_input("URL, type, ext, sig, mismatch, server, IP...", &app.quick_filter)
            .on_input(Message::QuickFilterChanged)
            .size(12)
            .width(Length::Fixed(240.0)),
    ]
    .spacing(6)
    .align_y(Alignment::Center);

    if !app.quick_filter.is_empty() {
        filter_bar = filter_bar.push(
            button(text("Clear").size(11))
                .on_press(Message::ClearQuickFilter)
                .style(button::secondary),
        );
    }

    for &cat in ContentQuickCat::ALL {
        filter_bar = filter_bar.push(
            button(text(cat.label()).size(11))
                .on_press(Message::SetContentCat(cat))
                .style(if app.content_cat == cat {
                    button::primary
                } else {
                    button::secondary
                }),
        );
    }

    let filter_bar2 = row![
        checkbox(app.hide_zero_length)
            .label("Hide 0B")
            .on_toggle(Message::ToggleHideZeroLength),
        checkbox(app.show_millis)
            .label("Millis")
            .on_toggle(Message::ToggleShowMillis),
        button(text("Columns...").size(11))
            .on_press(Message::OpenModal(ActiveModal::ChooseColumns))
            .style(button::secondary),
        button(text("Copy URLs").size(11))
            .on_press(Message::CopySelectedUrls)
            .style(button::secondary),
        button(text("Copy TSV").size(11))
            .on_press(Message::CopySelectedRowsTsv)
            .style(button::secondary),
        button(text("Delete Sel...").size(11))
            .on_press_maybe((!app.selected_rows.is_empty()).then_some(Message::OpenModal(ActiveModal::ConfirmDelete)))
            .style(button::danger),
    ]
    .spacing(8)
    .align_y(Alignment::Center);

    let cols = &app.active_cache_columns;
    let body: Element<'_, Message> = if app.filtered_indices.is_empty() {
        container(text("No cache entries match the active filter (or no cache directory loaded yet).").size(13))
            .padding(16)
            .width(Length::Fill)
            .height(Length::Fill)
            .into()
    } else {
        let mut hdr_row = row![text("").width(Length::Fixed(24.0))]
            .spacing(6)
            .align_y(Alignment::Center);
        for col in cols.iter().take(7) {
            let sf = col_to_sort_field(*col);
            let mut title = col.header().to_string();
            if let Some(s) = sf
                && app.sort_primary == s
            {
                title.push_str(if app.sort_primary_desc { " v" } else { " ^" });
            }
            let w = col_width(*col);
            let btn = if let Some(s) = sf {
                button(text(title).size(11))
                    .on_press(Message::ToggleSort(s, false))
                    .style(button::text)
                    .width(w)
            } else {
                button(text(title).size(11)).style(button::text).width(w)
            };
            hdr_row = hdr_row.push(btn);
        }

        let mut rows_col = column![hdr_row, rule::horizontal(1)].spacing(3);

        for &raw_idx in app.filtered_indices.iter().take(MAX_DISPLAY_ROWS) {
            let entry = &app.all_cache_entries[raw_idx];
            let is_sel = app.selected_rows.contains(&raw_idx);

            let mut row_cells = row![
                button(text(if is_sel { "[x]" } else { "[ ]" }).size(11).font(Font::MONOSPACE))
                    .on_press(Message::ToggleRowInSelection(raw_idx))
                    .style(button::text)
                    .width(Length::Fixed(24.0)),
            ]
            .spacing(6)
            .align_y(Alignment::Center);

            for col in cols.iter().take(7) {
                let val = if *col == CacheColumn::FileSize && entry.file_size > 1024 {
                    format!("{} ({})", entry.file_size, format_bytes(entry.file_size as u64))
                } else {
                    col.value(entry, app.show_millis)
                };
                let display = truncate_display(&val, 48);
                let color = if entry.mime_mismatch
                    && matches!(*col, CacheColumn::MimeMismatch | CacheColumn::DetectedContentType)
                {
                    Color::from_rgb(0.75, 0.14, 0.14)
                } else if is_sel {
                    Color::from_rgb(0.05, 0.35, 0.78)
                } else {
                    Color::from_rgb(0.15, 0.15, 0.15)
                };
                row_cells = row_cells.push(text(display).size(11).color(color).width(col_width(*col)));
            }

            rows_col = rows_col.push(
                row![
                    button(row_cells)
                        .width(Length::Fill)
                        .on_press(Message::SelectCacheRow(raw_idx))
                        .style(if is_sel { button::secondary } else { button::text }),
                    button(text("Props").size(11))
                        .on_press(Message::InspectEntryProperties(raw_idx))
                        .style(button::secondary),
                ]
                .spacing(4)
                .align_y(Alignment::Center),
            );
        }

        if app.filtered_indices.len() > MAX_DISPLAY_ROWS {
            rows_col = rows_col.push(
                text(format!(
                    "... showing first {MAX_DISPLAY_ROWS} of {} entries (use Quick Filter to narrow results)",
                    app.filtered_indices.len()
                ))
                .size(11),
            );
        }

        scrollable(rows_col).height(Length::Fill).into()
    };

    column![
        header,
        container(column![filter_bar, filter_bar2].spacing(6))
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

fn col_width(col: CacheColumn) -> Length {
    match col {
        CacheColumn::Url => Length::FillPortion(3),
        CacheColumn::ContentType | CacheColumn::DetectedContentType | CacheColumn::FileSignature => {
            Length::FillPortion(2)
        }
        CacheColumn::LastAccessed
        | CacheColumn::ServerTime
        | CacheColumn::RecordCreatedTime
        | CacheColumn::ExpirationTime => Length::Fixed(140.0),
        CacheColumn::FileSize | CacheColumn::CompressedSize => Length::Fixed(105.0),
        _ => Length::Fixed(100.0),
    }
}

fn col_to_sort_field(col: CacheColumn) -> Option<CacheSortField> {
    match col {
        CacheColumn::Url => Some(CacheSortField::Url),
        CacheColumn::ContentType => Some(CacheSortField::ContentType),
        CacheColumn::DetectedContentType => Some(CacheSortField::DetectedContentType),
        CacheColumn::DetectedExtension => Some(CacheSortField::DetectedExtension),
        CacheColumn::FileSignature => Some(CacheSortField::FileSignature),
        CacheColumn::MimeMismatch => Some(CacheSortField::MimeMismatch),
        CacheColumn::FileSize | CacheColumn::CompressedSize => Some(CacheSortField::FileSize),
        CacheColumn::LastAccessed => Some(CacheSortField::LastAccessed),
        CacheColumn::ServerTime => Some(CacheSortField::ServerTime),
        CacheColumn::RecordCreatedTime => Some(CacheSortField::RecordCreatedTime),
        CacheColumn::ExpirationTime => Some(CacheSortField::ExpirationTime),
        CacheColumn::ServerName => Some(CacheSortField::ServerName),
        CacheColumn::ServerResponse => Some(CacheSortField::ServerResponse),
        CacheColumn::WebSite | CacheColumn::Frame => Some(CacheSortField::WebSite),
        CacheColumn::CacheName => Some(CacheSortField::CacheName),
        _ => None,
    }
}

fn truncate_display(s: &str, max_chars: usize) -> String {
    let mut chars = s.chars();
    let collected: String = chars.by_ref().take(max_chars).collect();
    if chars.next().is_some() {
        format!("{collected}...")
    } else {
        collected
    }
}
