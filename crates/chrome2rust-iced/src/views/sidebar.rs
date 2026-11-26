use crate::app::App;
use crate::message::{ActiveModal, Message, WorkspaceTab};
use chrome2rust_report::markdown::format_bytes;
use iced::widget::{button, column, row, rule, scrollable, text};
use iced::{Alignment, Element, Length};

pub fn view_sidebar(app: &App) -> Element<'_, Message> {
    let mut items = column![
        row![
            text("Console Tree").size(14).width(Length::Fill),
            button(text("Reset").size(11))
                .on_press(Message::SelectProfile(None))
                .style(button::secondary),
        ]
        .align_y(Alignment::Center),
        rule::horizontal(1),
    ]
    .spacing(4);

    if let Some(rep) = &app.report {
        let all_active = app.selected_profile_idx.is_none();
        items = items.push(
            button(text(format!("All Profiles ({})", rep.summary.total_cache_entries)).size(12))
                .width(Length::Fill)
                .on_press(Message::SelectProfile(None))
                .style(if all_active { button::primary } else { button::text }),
        );
        for (idx, p) in rep.profiles.iter().enumerate() {
            let is_active = app.selected_profile_idx == Some(idx);
            items = items.push(
                button(text(format!("  {} ({})", p.profile_name, p.cache_entries.len())).size(12))
                    .width(Length::Fill)
                    .on_press(Message::SelectProfile(Some(idx)))
                    .style(if is_active { button::primary } else { button::text }),
            );
        }
    } else {
        items = items.push(text("(No target folder loaded)").size(12));
        items = items.push(
            button(text("Browse Target Folder...").size(12))
                .width(Length::Fill)
                .on_press(Message::BrowseAndLoad)
                .style(button::secondary),
        );
        if !app.discovered_browsers.is_empty() {
            items = items.push(text("Detected Local Browsers:").size(12));
            for b in &app.discovered_browsers {
                let target = if b.user_data_dir.is_dir() {
                    Some(b.user_data_dir.clone())
                } else {
                    b.cache_root_dir.clone()
                };
                if let Some(dir) = target {
                    items = items.push(
                        button(text(format!("{} ({})", b.name, b.profiles.len())).size(12))
                            .width(Length::Fill)
                            .on_press(Message::LoadPath(dir))
                            .style(button::text),
                    );
                }
            }
        }
    }

    items = items.push(rule::horizontal(1));
    items = items.push(text("Forensic Workspaces").size(14));

    let (cache_n, findings_n, tl_n, hist_n, creds_n, ext_n, sess_n, cache_bytes) = match &app.report {
        Some(r) => (
            app.all_cache_entries.len(),
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

    for tab in WorkspaceTab::all() {
        let badge = match tab {
            WorkspaceTab::CacheInspector => format!("{cache_n}"),
            WorkspaceTab::Overview => cache_bytes.clone(),
            WorkspaceTab::Findings => format!("{findings_n}"),
            WorkspaceTab::Timeline => format!("{tl_n}"),
            WorkspaceTab::HistoryDownloads => format!("{hist_n}"),
            WorkspaceTab::CredsCookies => format!("{creds_n}"),
            WorkspaceTab::ExtensionsBookmarks => format!("{ext_n}"),
            WorkspaceTab::SessionsStorage => format!("{sess_n}"),
            WorkspaceTab::BrowserTools => "21".to_string(),
        };
        let active = app.active_tab == *tab;
        items = items.push(
            button(text(format!("{} ({badge})", tab.title())).size(12))
                .width(Length::Fill)
                .on_press(Message::SelectTab(*tab))
                .style(if active { button::primary } else { button::text }),
        );
    }

    items = items.push(rule::horizontal(1));
    items = items.push(
        row![
            button(text("Columns...").size(12))
                .width(Length::Fill)
                .on_press(Message::OpenModal(ActiveModal::ChooseColumns))
                .style(button::secondary),
            button(text("About").size(12))
                .width(Length::Fill)
                .on_press(Message::OpenModal(ActiveModal::About))
                .style(button::secondary),
        ]
        .spacing(4),
    );

    scrollable(items).height(Length::Fill).into()
}
