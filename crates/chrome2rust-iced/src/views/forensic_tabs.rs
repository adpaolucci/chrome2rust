use crate::app::App;
use crate::message::{ActiveModal, CredSubTab, HistorySubTab, Message, SessionSubTab};
use crate::views::{page_header, section_card};
use chrome2rust_core::time::format_local_opt;
use chrome2rust_forensics::findings::FindingSeverity;
use chrome2rust_report::ReportFormat;
use chrome2rust_report::markdown::format_bytes;
use iced::widget::{button, column, container, row, rule, scrollable, text, text_input};
use iced::{Alignment, Color, Element, Font, Length};

const MAX_TAB_ROWS: usize = 500;

pub fn view_overview_tab(app: &App) -> Element<'_, Message> {
    let right_hdr = row![
        button(text("Save HTML").size(12))
            .on_press(Message::SaveReport(ReportFormat::Html))
            .style(button::secondary),
        button(text("Save JSON").size(12))
            .on_press(Message::SaveReport(ReportFormat::Json))
            .style(button::secondary),
        button(text("Save Markdown").size(12))
            .on_press(Message::SaveReport(ReportFormat::Markdown))
            .style(button::secondary),
        button(text("Full Bundle").size(12))
            .on_press(Message::SaveReport(ReportFormat::All))
            .style(button::primary),
    ]
    .spacing(6);

    let header = page_header("Overview & Forensic Report Generation", right_hdr);

    let Some(rep) = &app.report else {
        return column![
            header,
            section_card(
                "No User Data Loaded",
                text("Open a Chrome User Data or Profile folder to inspect overview & generate reports.").size(13),
            ),
        ]
        .spacing(8)
        .into();
    };

    let s = &rep.summary;
    let kpis1 = row![
        kpi_box("Profiles", s.profile_count.to_string()),
        kpi_box(
            "Cache Entries",
            format!("{} ({})", s.total_cache_entries, format_bytes(s.total_cache_bytes)),
        ),
        kpi_box(
            "History URLs / Visits",
            format!("{} / {}", s.total_history_urls, s.total_history_visits),
        ),
        kpi_box("Downloads", s.total_downloads.to_string()),
    ]
    .spacing(8);

    let kpis2 = row![
        kpi_box("Cookies", s.total_cookies.to_string()),
        kpi_box("Saved Logins", s.total_logins.to_string()),
        kpi_box("Bookmarks", s.total_bookmarks.to_string()),
        kpi_box("Extensions", s.total_extensions.to_string()),
    ]
    .spacing(8);

    let kpis3 = row![
        kpi_box(
            "Open / Closed Tabs",
            format!("{} / {}", s.total_open_tabs, s.total_closed_tabs),
        ),
        kpi_box("Storage Keys", s.total_local_storage_keys.to_string()),
        kpi_box("Timeline Events", s.total_timeline_events.to_string()),
        kpi_box("Forensic Findings", s.total_findings.to_string()),
    ]
    .spacing(8);

    let ls = &rep.local_state;
    let mut ls_col = column![
        text(format!(
            "Chrome Version: {} | OS Crypt Key Present: {} ({}) | Country: {} | Policies: {}",
            ls.chrome_version.as_deref().unwrap_or("Unknown"),
            ls.os_crypt_encrypted_key_present,
            ls.os_crypt_key_prefix.as_deref().unwrap_or("-"),
            ls.variations_country.as_deref().unwrap_or("-"),
            ls.policy_count
        ))
        .size(12),
    ]
    .spacing(4);

    if let Some(portal) = &ls.os_crypt_portal_info {
        ls_col = ls_col.push(text(format!("OS Crypt Portal: {portal}")).size(12));
    }
    for pm in &ls.profile_summaries {
        ls_col = ls_col.push(
            text(format!(
                "• {} — Name: {} | Email: {} | Ephemeral: {} | Active: {}",
                pm.dir_name,
                pm.name.as_deref().unwrap_or("-"),
                pm.user_name.as_deref().unwrap_or("-"),
                pm.is_ephemeral,
                format_local_opt(pm.active_time, false),
            ))
            .size(12),
        );
    }

    let mut dom_col = column![].spacing(3);
    for d in rep.top_domains.iter().take(25) {
        dom_col = dom_col.push(
            text(format!(
                "{:<36} | visits: {:<5} | cache: {:<4} ({}) | cookies: {}",
                d.domain,
                d.history_visits,
                d.cache_items,
                format_bytes(d.cache_bytes),
                d.cookies
            ))
            .size(11)
            .font(Font::MONOSPACE),
        );
    }

    let content = column![
        kpis1,
        kpis2,
        kpis3,
        section_card("Local State & Encryption Status", ls_col),
        section_card("Top Domains by Activity", dom_col),
    ]
    .spacing(8);

    column![header, scrollable(content).height(Length::Fill)]
        .spacing(8)
        .height(Length::Fill)
        .into()
}

pub fn view_findings_tab(app: &App) -> Element<'_, Message> {
    let header = page_header("Automated Cross-Artifact Forensic Findings", text("").size(12));
    let Some(rep) = &app.report else {
        return column![header, text("No User Data report loaded.").size(13)]
            .spacing(8)
            .into();
    };

    let mut sev_row = row![
        text("Severity:").size(12),
        button(text("All").size(11))
            .on_press(Message::SetFindingSeverityFilter(None))
            .style(if app.finding_sev_filter.is_none() {
                button::primary
            } else {
                button::secondary
            }),
    ]
    .spacing(5)
    .align_y(Alignment::Center);

    for sev in [
        FindingSeverity::Critical,
        FindingSeverity::High,
        FindingSeverity::Medium,
        FindingSeverity::Low,
        FindingSeverity::Info,
    ] {
        sev_row = sev_row.push(
            button(text(sev.as_str().to_ascii_uppercase()).size(11))
                .on_press(Message::SetFindingSeverityFilter(Some(sev)))
                .style(if app.finding_sev_filter == Some(sev) {
                    button::primary
                } else {
                    button::secondary
                }),
        );
    }
    sev_row = sev_row.push(
        text_input("Search findings...", &app.forensic_search)
            .on_input(Message::ForensicSearchChanged)
            .size(12)
            .width(Length::Fill),
    );

    let sel_pname: Option<&str> = app
        .selected_profile_idx
        .and_then(|idx| rep.profiles.get(idx))
        .map(|p| p.profile_name.as_str());
    let q = app.forensic_search.trim().to_ascii_lowercase();

    let mut list = column![].spacing(6);
    let mut shown = 0usize;
    for f in &rep.findings {
        if let Some(sp) = sel_pname
            && f.profile != sp
        {
            continue;
        }
        if let Some(sv) = app.finding_sev_filter
            && f.severity != sv
        {
            continue;
        }
        if !q.is_empty()
            && !f.title.to_ascii_lowercase().contains(&q)
            && !f.summary.to_ascii_lowercase().contains(&q)
            && !f.category.to_ascii_lowercase().contains(&q)
            && !f.evidence.iter().any(|e| e.to_ascii_lowercase().contains(&q))
        {
            continue;
        }
        shown += 1;
        let sev_color = match f.severity {
            FindingSeverity::Critical => Color::from_rgb(0.75, 0.14, 0.14),
            FindingSeverity::High => Color::from_rgb(0.80, 0.30, 0.05),
            FindingSeverity::Medium => Color::from_rgb(0.68, 0.45, 0.05),
            FindingSeverity::Low => Color::from_rgb(0.08, 0.50, 0.24),
            FindingSeverity::Info => Color::from_rgb(0.05, 0.40, 0.70),
        };
        let mut card = column![
            row![
                text(format!("[{}]", f.severity.as_str().to_ascii_uppercase()))
                    .size(12)
                    .color(sev_color),
                text(&f.title).size(13),
                text(format!("({} / {})", f.profile, f.category)).size(11),
            ]
            .spacing(6),
            text(&f.summary).size(12),
        ]
        .spacing(4);
        for ev in f.evidence.iter().take(12) {
            card = card.push(text(format!("  • {ev}")).size(11).font(Font::MONOSPACE));
        }
        list = list.push(
            container(card)
                .padding(8)
                .width(Length::Fill)
                .style(container::bordered_box),
        );
    }

    if shown == 0 {
        list = list.push(text("No findings match the current filters.").size(13));
    }

    column![
        header,
        container(sev_row)
            .padding(8)
            .width(Length::Fill)
            .style(container::bordered_box),
        scrollable(list).height(Length::Fill),
    ]
    .spacing(8)
    .height(Length::Fill)
    .into()
}

pub fn view_timeline_tab(app: &App) -> Element<'_, Message> {
    let header = page_header("Unified Chronological Activity Timeline", text("").size(12));
    let Some(rep) = &app.report else {
        return column![header, text("No report loaded.").size(13)].spacing(8).into();
    };

    let mut filter_row = row![].spacing(4).align_y(Alignment::Center);
    for cat in [
        "All",
        "History",
        "Download",
        "Cache",
        "Cookie",
        "Credential",
        "Bookmark",
        "Extension",
        "Session",
    ] {
        filter_row = filter_row.push(
            button(text(cat).size(11))
                .on_press(Message::SetTimelineCategoryFilter(cat.to_string()))
                .style(if app.timeline_cat_filter == cat {
                    button::primary
                } else {
                    button::secondary
                }),
        );
    }
    filter_row = filter_row.push(
        text_input("Search timeline...", &app.forensic_search)
            .on_input(Message::ForensicSearchChanged)
            .size(12)
            .width(Length::Fill),
    );

    let sel_pname: Option<&str> = app
        .selected_profile_idx
        .and_then(|idx| rep.profiles.get(idx))
        .map(|p| p.profile_name.as_str());
    let q = app.forensic_search.trim().to_ascii_lowercase();

    let mut rows = column![
        row![
            text("Timestamp").size(11).width(Length::Fixed(150.0)),
            text("Profile").size(11).width(Length::Fixed(80.0)),
            text("Category").size(11).width(Length::Fixed(85.0)),
            text("Event").size(11).width(Length::Fixed(130.0)),
            text("Target").size(11).width(Length::FillPortion(2)),
            text("Details").size(11).width(Length::FillPortion(2)),
        ]
        .spacing(6),
        rule::horizontal(1),
    ]
    .spacing(4);

    let mut count = 0usize;
    for ev in &rep.timeline {
        if let Some(sp) = sel_pname
            && ev.profile != sp
        {
            continue;
        }
        if app.timeline_cat_filter != "All" && ev.category != app.timeline_cat_filter {
            continue;
        }
        if !q.is_empty()
            && !ev.target.to_ascii_lowercase().contains(&q)
            && !ev.details.to_ascii_lowercase().contains(&q)
            && !ev.event_type.to_ascii_lowercase().contains(&q)
        {
            continue;
        }
        rows = rows.push(
            row![
                text(format_local_opt(Some(ev.timestamp), false))
                    .size(11)
                    .font(Font::MONOSPACE)
                    .width(Length::Fixed(150.0)),
                text(&ev.profile).size(11).width(Length::Fixed(80.0)),
                text(&ev.category).size(11).width(Length::Fixed(85.0)),
                text(&ev.event_type).size(11).width(Length::Fixed(130.0)),
                text(&ev.target).size(11).width(Length::FillPortion(2)),
                text(&ev.details).size(11).width(Length::FillPortion(2)),
            ]
            .spacing(6),
        );
        count += 1;
        if count >= MAX_TAB_ROWS {
            break;
        }
    }

    column![
        header,
        container(filter_row)
            .padding(8)
            .width(Length::Fill)
            .style(container::bordered_box),
        container(scrollable(rows).height(Length::Fill))
            .padding(8)
            .width(Length::Fill)
            .height(Length::Fill)
            .style(container::bordered_box),
    ]
    .spacing(8)
    .height(Length::Fill)
    .into()
}

pub fn view_history_tab(app: &App) -> Element<'_, Message> {
    let header = page_header("History, Visits, Downloads & Search Terms", text("").size(12));
    let profiles = app.visible_profiles();
    if profiles.is_empty() {
        return column![header, text("No profile loaded.").size(13)].spacing(8).into();
    }

    let sub_row = row![
        subtab_btn(
            "URLs",
            app.history_sub == HistorySubTab::Urls,
            Message::SetHistorySubTab(HistorySubTab::Urls)
        ),
        subtab_btn(
            "Visits",
            app.history_sub == HistorySubTab::Visits,
            Message::SetHistorySubTab(HistorySubTab::Visits)
        ),
        subtab_btn(
            "Downloads",
            app.history_sub == HistorySubTab::Downloads,
            Message::SetHistorySubTab(HistorySubTab::Downloads)
        ),
        subtab_btn(
            "Search Terms",
            app.history_sub == HistorySubTab::SearchTerms,
            Message::SetHistorySubTab(HistorySubTab::SearchTerms)
        ),
        text_input("Search history...", &app.forensic_search)
            .on_input(Message::ForensicSearchChanged)
            .size(12)
            .width(Length::Fill),
    ]
    .spacing(6)
    .align_y(Alignment::Center);

    let mut gap_col = column![sub_row].spacing(4);
    for (_, p) in &profiles {
        let di = &p.history.deletion_indicators;
        gap_col = gap_col.push(
            text(format!(
                "[{}] URLs: {} (seq {}, est. deleted: {}, hidden: {}) | Visits: {} (seq {}, est. deleted: {})",
                p.profile_name,
                di.urls_row_count,
                di.urls_sqlite_seq,
                di.urls_estimated_deleted,
                di.hidden_urls_count,
                di.visits_row_count,
                di.visits_sqlite_seq,
                di.visits_estimated_deleted
            ))
            .size(11),
        );
    }

    let q = app.forensic_search.trim().to_ascii_lowercase();
    let mut rows = column![].spacing(4);
    let mut shown = 0usize;

    match app.history_sub {
        HistorySubTab::Urls => {
            for (_, p) in &profiles {
                for u in &p.history.urls {
                    if !q.is_empty()
                        && !u.url.to_ascii_lowercase().contains(&q)
                        && !u.title.to_ascii_lowercase().contains(&q)
                    {
                        continue;
                    }
                    rows = rows.push(
                        row![
                            text(&p.profile_name).size(11).width(Length::Fixed(80.0)),
                            text(format_local_opt(u.last_visit_time, false))
                                .size(11)
                                .width(Length::Fixed(140.0)),
                            text(format!("{} / {}", u.visit_count, u.typed_count))
                                .size(11)
                                .width(Length::Fixed(70.0)),
                            text(&u.title).size(11).width(Length::FillPortion(2)),
                            text(&u.url)
                                .size(11)
                                .font(Font::MONOSPACE)
                                .width(Length::FillPortion(3)),
                        ]
                        .spacing(6),
                    );
                    shown += 1;
                    if shown >= MAX_TAB_ROWS {
                        break;
                    }
                }
            }
        }
        HistorySubTab::Visits => {
            for (_, p) in &profiles {
                for v in &p.history.visits {
                    if !q.is_empty()
                        && !v.url.to_ascii_lowercase().contains(&q)
                        && !v.title.to_ascii_lowercase().contains(&q)
                        && !v.transition_core.to_ascii_lowercase().contains(&q)
                    {
                        continue;
                    }
                    rows = rows.push(
                        row![
                            text(&p.profile_name).size(11).width(Length::Fixed(80.0)),
                            text(format_local_opt(v.visit_time, false))
                                .size(11)
                                .width(Length::Fixed(140.0)),
                            text(&v.transition_core).size(11).width(Length::Fixed(105.0)),
                            text(format!("{} ms", v.visit_duration_ms))
                                .size(11)
                                .width(Length::Fixed(70.0)),
                            text(&v.title).size(11).width(Length::FillPortion(2)),
                            text(&v.url)
                                .size(11)
                                .font(Font::MONOSPACE)
                                .width(Length::FillPortion(3)),
                        ]
                        .spacing(6),
                    );
                    shown += 1;
                    if shown >= MAX_TAB_ROWS {
                        break;
                    }
                }
            }
        }
        HistorySubTab::Downloads => {
            for (_, p) in &profiles {
                for d in &p.history.downloads {
                    let urls = d.url_chain.join(" -> ");
                    if !q.is_empty()
                        && !d.target_path.to_ascii_lowercase().contains(&q)
                        && !urls.to_ascii_lowercase().contains(&q)
                    {
                        continue;
                    }
                    rows = rows.push(
                        row![
                            text(&p.profile_name).size(11).width(Length::Fixed(80.0)),
                            text(format_local_opt(d.start_time, false))
                                .size(11)
                                .width(Length::Fixed(140.0)),
                            text(&d.state).size(11).width(Length::Fixed(90.0)),
                            text(&d.danger_type).size(11).width(Length::Fixed(110.0)),
                            text(format_bytes(d.total_bytes.max(d.received_bytes).max(0) as u64))
                                .size(11)
                                .width(Length::Fixed(80.0)),
                            text(&d.target_path).size(11).width(Length::FillPortion(2)),
                            text(urls).size(11).font(Font::MONOSPACE).width(Length::FillPortion(2)),
                        ]
                        .spacing(6),
                    );
                    shown += 1;
                    if shown >= MAX_TAB_ROWS {
                        break;
                    }
                }
            }
        }
        HistorySubTab::SearchTerms => {
            for (_, p) in &profiles {
                for s in &p.history.search_terms {
                    if !q.is_empty()
                        && !s.term.to_ascii_lowercase().contains(&q)
                        && !s.url.as_deref().unwrap_or("").to_ascii_lowercase().contains(&q)
                    {
                        continue;
                    }
                    rows = rows.push(
                        row![
                            text(&p.profile_name).size(11).width(Length::Fixed(80.0)),
                            text(format_local_opt(s.last_visit_time, false))
                                .size(11)
                                .width(Length::Fixed(140.0)),
                            text(&s.term).size(11).width(Length::FillPortion(2)),
                            text(s.url.as_deref().unwrap_or(""))
                                .size(11)
                                .font(Font::MONOSPACE)
                                .width(Length::FillPortion(3)),
                        ]
                        .spacing(6),
                    );
                    shown += 1;
                    if shown >= MAX_TAB_ROWS {
                        break;
                    }
                }
            }
        }
    }

    column![
        header,
        container(gap_col)
            .padding(8)
            .width(Length::Fill)
            .style(container::bordered_box),
        container(scrollable(rows).height(Length::Fill))
            .padding(8)
            .width(Length::Fill)
            .height(Length::Fill)
            .style(container::bordered_box),
    ]
    .spacing(8)
    .height(Length::Fill)
    .into()
}

pub fn view_creds_tab(app: &App) -> Element<'_, Message> {
    let header = page_header(
        "Credentials, Cookies, Autofill & Payment Metadata",
        button(text("Decryption Keys...").size(12))
            .on_press(Message::OpenModal(ActiveModal::DecryptionSettings))
            .style(button::secondary),
    );
    let profiles = app.visible_profiles();
    if profiles.is_empty() {
        return column![header, text("No profile loaded.").size(13)].spacing(8).into();
    }

    let sub_row = row![
        subtab_btn(
            "Saved Logins",
            app.cred_sub == CredSubTab::Logins,
            Message::SetCredSubTab(CredSubTab::Logins)
        ),
        subtab_btn(
            "Cookies",
            app.cred_sub == CredSubTab::Cookies,
            Message::SetCredSubTab(CredSubTab::Cookies)
        ),
        subtab_btn(
            "Autofill",
            app.cred_sub == CredSubTab::Autofill,
            Message::SetCredSubTab(CredSubTab::Autofill)
        ),
        subtab_btn(
            "Addresses & Cards",
            app.cred_sub == CredSubTab::AddressesCards,
            Message::SetCredSubTab(CredSubTab::AddressesCards)
        ),
        text_input("Search credentials/cookies...", &app.forensic_search)
            .on_input(Message::ForensicSearchChanged)
            .size(12)
            .width(Length::Fill),
    ]
    .spacing(6)
    .align_y(Alignment::Center);

    let q = app.forensic_search.trim().to_ascii_lowercase();
    let mut rows = column![].spacing(4);
    let mut shown = 0usize;

    match app.cred_sub {
        CredSubTab::Logins => {
            for (_, p) in &profiles {
                for l in &p.logins {
                    if !q.is_empty()
                        && !l.origin_url.to_ascii_lowercase().contains(&q)
                        && !l.username_value.to_ascii_lowercase().contains(&q)
                    {
                        continue;
                    }
                    let pw = l
                        .password_decrypted
                        .clone()
                        .unwrap_or_else(|| format!("[Encrypted {} B]", l.password_encrypted_len));
                    rows = rows.push(
                        row![
                            text(&p.profile_name).size(11).width(Length::Fixed(80.0)),
                            text(&l.origin_url).size(11).width(Length::FillPortion(2)),
                            text(&l.username_value).size(11).width(Length::FillPortion(2)),
                            text(l.encryption_scheme.as_str()).size(11).width(Length::Fixed(70.0)),
                            text(pw).size(11).font(Font::MONOSPACE).width(Length::FillPortion(2)),
                        ]
                        .spacing(6),
                    );
                    shown += 1;
                    if shown >= MAX_TAB_ROWS {
                        break;
                    }
                }
            }
        }
        CredSubTab::Cookies => {
            for (_, p) in &profiles {
                for c in &p.cookies {
                    if !q.is_empty()
                        && !c.host_key.to_ascii_lowercase().contains(&q)
                        && !c.name.to_ascii_lowercase().contains(&q)
                        && !c.value.as_deref().unwrap_or("").to_ascii_lowercase().contains(&q)
                    {
                        continue;
                    }
                    let val = c
                        .value
                        .clone()
                        .unwrap_or_else(|| format!("[Encrypted {} B]", c.encrypted_len));
                    rows = rows.push(
                        row![
                            text(&p.profile_name).size(11).width(Length::Fixed(80.0)),
                            text(&c.host_key).size(11).width(Length::FillPortion(2)),
                            text(&c.name).size(11).width(Length::FillPortion(1)),
                            text(c.encryption_scheme.as_str()).size(11).width(Length::Fixed(70.0)),
                            text(val).size(11).font(Font::MONOSPACE).width(Length::FillPortion(2)),
                        ]
                        .spacing(6),
                    );
                    shown += 1;
                    if shown >= MAX_TAB_ROWS {
                        break;
                    }
                }
            }
        }
        CredSubTab::Autofill => {
            for (_, p) in &profiles {
                for a in &p.web_data.autofill {
                    if !q.is_empty()
                        && !a.name.to_ascii_lowercase().contains(&q)
                        && !a.value.to_ascii_lowercase().contains(&q)
                    {
                        continue;
                    }
                    rows = rows.push(
                        row![
                            text(&p.profile_name).size(11).width(Length::Fixed(80.0)),
                            text(&a.name).size(11).width(Length::FillPortion(1)),
                            text(&a.value).size(11).width(Length::FillPortion(2)),
                            text(a.count.to_string()).size(11).width(Length::Fixed(60.0)),
                            text(format_local_opt(a.date_last_used, false))
                                .size(11)
                                .width(Length::Fixed(140.0)),
                        ]
                        .spacing(6),
                    );
                    shown += 1;
                    if shown >= MAX_TAB_ROWS {
                        break;
                    }
                }
            }
        }
        CredSubTab::AddressesCards => {
            rows = rows.push(text("Saved Addresses").size(13));
            for (_, p) in &profiles {
                for a in &p.web_data.addresses {
                    rows = rows.push(
                        text(format!(
                            "[{}] {} | {} | {} {} {} {} | {} (uses: {})",
                            p.profile_name,
                            a.full_name,
                            a.email,
                            a.street_address,
                            a.city,
                            a.state,
                            a.zipcode,
                            a.phone,
                            a.use_count
                        ))
                        .size(11),
                    );
                }
            }
            rows = rows.push(rule::horizontal(1));
            rows = rows.push(text("Saved Payment Card Metadata").size(13));
            for (_, p) in &profiles {
                for c in &p.web_data.credit_cards {
                    rows = rows.push(
                        text(format!(
                            "[{}] {} | {} | ****{} | Exp: {}/{} | uses: {}",
                            p.profile_name,
                            c.name_on_card,
                            c.network,
                            c.last_four,
                            c.expiration_month,
                            c.expiration_year,
                            c.use_count
                        ))
                        .size(11),
                    );
                }
            }
        }
    }

    column![
        header,
        container(sub_row)
            .padding(8)
            .width(Length::Fill)
            .style(container::bordered_box),
        container(scrollable(rows).height(Length::Fill))
            .padding(8)
            .width(Length::Fill)
            .height(Length::Fill)
            .style(container::bordered_box),
    ]
    .spacing(8)
    .height(Length::Fill)
    .into()
}

pub fn view_extensions_tab(app: &App) -> Element<'_, Message> {
    let header = page_header("Installed Extensions & Hierarchical Bookmarks", text("").size(12));
    let profiles = app.visible_profiles();
    if profiles.is_empty() {
        return column![header, text("No profile loaded.").size(13)].spacing(8).into();
    }

    let search = row![
        text("Search Extensions / Bookmarks:").size(12),
        text_input("Filter...", &app.forensic_search)
            .on_input(Message::ForensicSearchChanged)
            .size(12)
            .width(Length::Fill),
    ]
    .spacing(8)
    .align_y(Alignment::Center);

    let q = app.forensic_search.trim().to_ascii_lowercase();
    let mut rows = column![text("Installed Extensions").size(14)].spacing(6);

    for (_, p) in &profiles {
        for ext in &p.extensions {
            if !q.is_empty()
                && !ext.name.to_ascii_lowercase().contains(&q)
                && !ext.id.to_ascii_lowercase().contains(&q)
                && !ext.risk_flags.iter().any(|r| r.to_ascii_lowercase().contains(&q))
            {
                continue;
            }
            let mut card = column![
                text(format!(
                    "{} v{} ({}) [{} | {}]",
                    ext.name, ext.version, ext.id, p.profile_name, ext.location
                ))
                .size(12),
            ]
            .spacing(3);
            if !ext.risk_flags.is_empty() {
                card = card.push(
                    text(format!("RISK: {}", ext.risk_flags.join(", ")))
                        .size(11)
                        .color(Color::from_rgb(0.80, 0.30, 0.05)),
                );
            }
            if !ext.permissions.is_empty() {
                card = card.push(text(format!("Permissions: {}", ext.permissions.join(", "))).size(11));
            }
            rows = rows.push(
                container(card)
                    .padding(8)
                    .width(Length::Fill)
                    .style(container::bordered_box),
            );
        }
    }

    rows = rows.push(rule::horizontal(1));
    rows = rows.push(text("Bookmarks").size(14));
    for (_, p) in &profiles {
        for b in p.bookmarks.iter().take(500) {
            if !q.is_empty()
                && !b.name.to_ascii_lowercase().contains(&q)
                && !b.url.to_ascii_lowercase().contains(&q)
                && !b.folder_path.to_ascii_lowercase().contains(&q)
            {
                continue;
            }
            rows = rows.push(
                text(format!(
                    "[{}] [{}] {} -> {}",
                    p.profile_name, b.folder_path, b.name, b.url
                ))
                .size(11),
            );
        }
    }

    column![
        header,
        container(search)
            .padding(8)
            .width(Length::Fill)
            .style(container::bordered_box),
        scrollable(rows).height(Length::Fill),
    ]
    .spacing(8)
    .height(Length::Fill)
    .into()
}

pub fn view_sessions_tab(app: &App) -> Element<'_, Message> {
    let header = page_header(
        "SNSS Sessions, LevelDB Storage, IndexedDB & File Inventory",
        text("").size(12),
    );
    let profiles = app.visible_profiles();
    if profiles.is_empty() {
        return column![header, text("No profile loaded.").size(13)].spacing(8).into();
    }

    let sub_row = row![
        subtab_btn(
            "SNSS Tabs",
            app.sess_sub == SessionSubTab::Tabs,
            Message::SetSessionSubTab(SessionSubTab::Tabs)
        ),
        subtab_btn(
            "Local Storage",
            app.sess_sub == SessionSubTab::LocalStorage,
            Message::SetSessionSubTab(SessionSubTab::LocalStorage)
        ),
        subtab_btn(
            "Session Storage",
            app.sess_sub == SessionSubTab::SessionStorage,
            Message::SetSessionSubTab(SessionSubTab::SessionStorage)
        ),
        subtab_btn(
            "IndexedDB & Files",
            app.sess_sub == SessionSubTab::MiscInventory,
            Message::SetSessionSubTab(SessionSubTab::MiscInventory)
        ),
        text_input("Search sessions/storage...", &app.forensic_search)
            .on_input(Message::ForensicSearchChanged)
            .size(12)
            .width(Length::Fill),
    ]
    .spacing(6)
    .align_y(Alignment::Center);

    let q = app.forensic_search.trim().to_ascii_lowercase();
    let mut rows = column![].spacing(4);

    match app.sess_sub {
        SessionSubTab::Tabs => {
            for (pidx, p) in &profiles {
                if p.sessions.encrypted_sessions_present {
                    rows = rows.push(
                        text(format!("[{}] Sessions_Encrypted directory detected.", p.profile_name))
                            .size(12)
                            .color(Color::from_rgb(0.05, 0.40, 0.70)),
                    );
                }
                for (tidx, t) in p
                    .sessions
                    .open_tabs
                    .iter()
                    .chain(p.sessions.closed_tabs.iter())
                    .enumerate()
                {
                    if !q.is_empty()
                        && !t.current_url.to_ascii_lowercase().contains(&q)
                        && !t.current_title.to_ascii_lowercase().contains(&q)
                    {
                        continue;
                    }
                    let state_tag = if t.is_closed { "CLOSED" } else { "OPEN" };
                    let selected = app.selected_tab_nav_idx == Some((*pidx, tidx));
                    rows = rows.push(
                        button(
                            text(format!(
                                "[{}] [{}] Tab #{} ({}) {} -> {} [{} navs]",
                                p.profile_name,
                                state_tag,
                                t.tab_id,
                                t.source_file,
                                t.current_title,
                                t.current_url,
                                t.navigations.len()
                            ))
                            .size(11),
                        )
                        .width(Length::Fill)
                        .on_press(Message::SelectTabNav(*pidx, tidx))
                        .style(if selected { button::primary } else { button::text }),
                    );
                    if selected {
                        for nav in &t.navigations {
                            rows = rows.push(
                                text(format!("    [{}] {} -> {}", nav.index, nav.title, nav.url))
                                    .size(11)
                                    .font(Font::MONOSPACE),
                            );
                        }
                    }
                }
            }
        }
        SessionSubTab::LocalStorage => {
            for (_, p) in &profiles {
                for kv in p.storage.local_storage.iter().take(MAX_TAB_ROWS) {
                    if !q.is_empty()
                        && !kv.origin.to_ascii_lowercase().contains(&q)
                        && !kv.key.to_ascii_lowercase().contains(&q)
                        && !kv.value.to_ascii_lowercase().contains(&q)
                    {
                        continue;
                    }
                    rows = rows.push(
                        text(format!(
                            "[{}] {} | {} = {}",
                            p.profile_name, kv.origin, kv.key, kv.value
                        ))
                        .size(11)
                        .font(Font::MONOSPACE),
                    );
                }
            }
        }
        SessionSubTab::SessionStorage => {
            for (_, p) in &profiles {
                for kv in p.storage.session_storage.iter().take(MAX_TAB_ROWS) {
                    if !q.is_empty()
                        && !kv.origin.to_ascii_lowercase().contains(&q)
                        && !kv.key.to_ascii_lowercase().contains(&q)
                        && !kv.value.to_ascii_lowercase().contains(&q)
                    {
                        continue;
                    }
                    rows = rows.push(
                        text(format!(
                            "[{}] {} | {} = {}",
                            p.profile_name, kv.origin, kv.key, kv.value
                        ))
                        .size(11)
                        .font(Font::MONOSPACE),
                    );
                }
            }
        }
        SessionSubTab::MiscInventory => {
            for (_, p) in &profiles {
                rows = rows.push(text(format!("{} — IndexedDB / Top Sites / File Inventory", p.profile_name)).size(13));
                for idb in &p.storage.indexed_db_origins {
                    rows = rows.push(
                        text(format!(
                            "IndexedDB: {} ({} files, {})",
                            idb.origin_dir,
                            idb.file_count,
                            format_bytes(idb.total_bytes)
                        ))
                        .size(11),
                    );
                }
                for ts in &p.storage.top_sites {
                    rows = rows.push(text(format!("TopSite #{}: {} ({})", ts.rank, ts.title, ts.url)).size(11));
                }
                for nel in &p.storage.nel_policies {
                    rows = rows.push(
                        text(format!(
                            "NEL Policy: {} (IP: {}, group: {})",
                            nel.origin, nel.received_ip, nel.group_name
                        ))
                        .size(11),
                    );
                }
                rows = rows.push(rule::horizontal(1));
                for f in p.file_inventory.iter().take(100) {
                    if !q.is_empty()
                        && !f.relative_path.to_ascii_lowercase().contains(&q)
                        && !f.category.to_ascii_lowercase().contains(&q)
                    {
                        continue;
                    }
                    rows = rows.push(
                        text(format!(
                            "{:<22} {:>10}  {}",
                            f.category,
                            format_bytes(f.size_bytes),
                            f.relative_path
                        ))
                        .size(11)
                        .font(Font::MONOSPACE),
                    );
                }
            }
        }
    }

    column![
        header,
        container(sub_row)
            .padding(8)
            .width(Length::Fill)
            .style(container::bordered_box),
        container(scrollable(rows).height(Length::Fill))
            .padding(8)
            .width(Length::Fill)
            .height(Length::Fill)
            .style(container::bordered_box),
    ]
    .spacing(8)
    .height(Length::Fill)
    .into()
}

fn kpi_box<'a>(label: &'a str, value: String) -> Element<'a, Message> {
    container(column![text(label).size(11), text(value).size(14)].spacing(2))
        .padding([8, 12])
        .width(Length::Fill)
        .style(container::bordered_box)
        .into()
}

fn subtab_btn<'a>(label: &'a str, active: bool, msg: Message) -> Element<'a, Message> {
    button(text(label).size(11))
        .on_press(msg)
        .style(if active { button::primary } else { button::secondary })
        .into()
}
