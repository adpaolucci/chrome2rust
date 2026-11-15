use crate::state::{ActiveModal, AppState, CredSubTab, HistorySubTab, SessionSubTab};
use chrome2rust_core::time::format_local_opt;
use chrome2rust_forensics::findings::FindingSeverity;
use chrome2rust_report::ReportFormat;
use chrome2rust_report::markdown::format_bytes;
use eframe::egui::{self, Color32, RichText, Stroke};
use egui_extras::{Column, TableBuilder};

fn win32_section_header(ui: &mut egui::Ui, title: &str) {
    egui::Frame::NONE
        .fill(Color32::from_rgb(235, 235, 235))
        .stroke(Stroke::new(1.0_f32, Color32::from_rgb(180, 180, 180)))
        .inner_margin(egui::Margin::symmetric(5, 3))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.label(RichText::new(title).size(11.0).strong().color(Color32::BLACK));
        });
}

fn sunken_white_container<R>(ui: &mut egui::Ui, add_contents: impl FnOnce(&mut egui::Ui) -> R) -> R {
    egui::Frame::NONE
        .fill(Color32::WHITE)
        .stroke(Stroke::new(1.0_f32, Color32::from_rgb(127, 157, 185)))
        .inner_margin(egui::Margin::same(6))
        .show(ui, |ui| {
            ui.set_min_width(ui.available_width());
            ui.set_min_height(ui.available_height());
            add_contents(ui)
        })
        .inner
}

fn kpi_card(ui: &mut egui::Ui, label: &str, value: &str) {
    egui::Frame::NONE
        .fill(Color32::from_rgb(244, 243, 238))
        .stroke(Stroke::new(1.0_f32, Color32::from_rgb(172, 168, 153)))
        .inner_margin(egui::Margin::same(6))
        .show(ui, |ui| {
            ui.set_min_width(175.0);
            ui.label(RichText::new(label).size(10.5).color(Color32::from_rgb(90, 90, 90)));
            ui.label(
                RichText::new(value)
                    .strong()
                    .size(15.0)
                    .color(Color32::from_rgb(0, 51, 153)),
            );
        });
}

pub fn render_overview_tab(ui: &mut egui::Ui, state: &mut AppState) {
    win32_section_header(ui, "Overview & Forensic Report Generation");
    ui.add_space(2.0);

    let Some(rep) = state.report.clone() else {
        sunken_white_container(ui, |ui| {
            ui.centered_and_justified(|ui| {
                ui.label("Open a Chrome User Data or Profile folder to inspect overview & generate reports.");
            });
        });
        return;
    };

    sunken_white_container(ui, |ui| {
        egui::ScrollArea::vertical().show(ui, |ui| {
            ui.horizontal_wrapped(|ui| {
                ui.label(
                    RichText::new("User Data Forensic Overview")
                        .size(13.0)
                        .strong()
                        .color(Color32::from_rgb(0, 51, 153)),
                );
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.button("Full Bundle (HTML+JSON+MD)").clicked() {
                        state.trigger_report_save(ReportFormat::All);
                    }
                    if ui.button("Save Markdown").clicked() {
                        state.trigger_report_save(ReportFormat::Markdown);
                    }
                    if ui.button("Save JSON").clicked() {
                        state.trigger_report_save(ReportFormat::Json);
                    }
                    if ui.button("Save HTML").clicked() {
                        state.trigger_report_save(ReportFormat::Html);
                    }
                });
            });
            ui.separator();

            let s = &rep.summary;
            egui::Grid::new("overview_kpi_grid")
                .num_columns(4)
                .spacing([12.0, 8.0])
                .show(ui, |ui| {
                    kpi_card(ui, "Profiles", &s.profile_count.to_string());
                    kpi_card(
                        ui,
                        "Cache Entries",
                        &format!("{} ({})", s.total_cache_entries, format_bytes(s.total_cache_bytes)),
                    );
                    kpi_card(
                        ui,
                        "History URLs / Visits",
                        &format!("{} / {}", s.total_history_urls, s.total_history_visits),
                    );
                    kpi_card(ui, "Downloads", &s.total_downloads.to_string());
                    ui.end_row();

                    kpi_card(ui, "Cookies", &s.total_cookies.to_string());
                    kpi_card(ui, "Saved Logins", &s.total_logins.to_string());
                    kpi_card(ui, "Bookmarks", &s.total_bookmarks.to_string());
                    kpi_card(ui, "Extensions", &s.total_extensions.to_string());
                    ui.end_row();

                    kpi_card(
                        ui,
                        "Open / Closed Tabs",
                        &format!("{} / {}", s.total_open_tabs, s.total_closed_tabs),
                    );
                    kpi_card(ui, "Storage Keys", &s.total_local_storage_keys.to_string());
                    kpi_card(ui, "Timeline Events", &s.total_timeline_events.to_string());
                    kpi_card(ui, "Forensic Findings", &s.total_findings.to_string());
                    ui.end_row();
                });

            ui.separator();
            ui.label(
                RichText::new("Local State & Encryption Status")
                    .strong()
                    .size(12.0)
                    .color(Color32::from_rgb(0, 51, 153)),
            );
            let ls = &rep.local_state;
            ui.label(format!(
                "Chrome Version: {} | OS Crypt Key Present: {} ({}) | Country: {} | Policies: {}",
                ls.chrome_version.as_deref().unwrap_or("Unknown"),
                ls.os_crypt_encrypted_key_present,
                ls.os_crypt_key_prefix.as_deref().unwrap_or("-"),
                ls.variations_country.as_deref().unwrap_or("-"),
                ls.policy_count
            ));
            if let Some(portal) = &ls.os_crypt_portal_info {
                ui.label(format!("OS Crypt Portal: {portal}"));
            }

            if !ls.profile_summaries.is_empty() {
                ui.add_space(4.0);
                for pm in &ls.profile_summaries {
                    ui.label(format!(
                        "• {} — Name: {} | Email: {} | Ephemeral: {} | Active: {}",
                        pm.dir_name,
                        pm.name.as_deref().unwrap_or("-"),
                        pm.user_name.as_deref().unwrap_or("-"),
                        pm.is_ephemeral,
                        format_local_opt(pm.active_time, false),
                    ));
                }
            }

            ui.separator();
            ui.label(
                RichText::new("Top Domains by Activity")
                    .strong()
                    .size(12.0)
                    .color(Color32::from_rgb(0, 51, 153)),
            );
            for d in rep.top_domains.iter().take(25) {
                ui.label(
                    RichText::new(format!(
                        "{:<36} | visits: {:<5} | cache: {:<4} ({}) | cookies: {}",
                        d.domain,
                        d.history_visits,
                        d.cache_items,
                        format_bytes(d.cache_bytes),
                        d.cookies
                    ))
                    .monospace()
                    .size(11.0),
                );
            }
        });
    });
}

pub fn render_findings_tab(ui: &mut egui::Ui, state: &mut AppState) {
    win32_section_header(ui, "Automated Cross-Artifact Forensic Findings");
    ui.add_space(2.0);

    let Some(rep) = &state.report else {
        sunken_white_container(ui, |ui| {
            ui.label("No User Data report loaded.");
        });
        return;
    };

    egui::Frame::NONE
        .fill(Color32::from_rgb(244, 243, 238))
        .stroke(Stroke::new(1.0_f32, Color32::from_rgb(172, 168, 153)))
        .inner_margin(egui::Margin::symmetric(5, 3))
        .show(ui, |ui| {
            ui.horizontal_wrapped(|ui| {
                ui.label(RichText::new("Severity:").size(11.0).strong());
                if ui.selectable_label(state.finding_sev_filter.is_none(), "All").clicked() {
                    state.finding_sev_filter = None;
                }
                for sev in [
                    FindingSeverity::Critical,
                    FindingSeverity::High,
                    FindingSeverity::Medium,
                    FindingSeverity::Low,
                    FindingSeverity::Info,
                ] {
                    if ui
                        .selectable_label(state.finding_sev_filter == Some(sev), sev.as_str().to_ascii_uppercase())
                        .clicked()
                    {
                        state.finding_sev_filter = Some(sev);
                    }
                }
                ui.separator();
                ui.label(RichText::new("Search:").size(11.0).strong());
                ui.text_edit_singleline(&mut state.forensic_search);
            });
        });
    ui.add_space(2.0);

    let sel_pname: Option<String> = state
        .selected_profile_idx
        .and_then(|idx| rep.profiles.get(idx))
        .map(|p| p.profile_name.clone());
    let q = state.forensic_search.trim().to_ascii_lowercase();

    sunken_white_container(ui, |ui| {
        egui::ScrollArea::vertical().show(ui, |ui| {
            let mut shown = 0usize;
            for f in &rep.findings {
                if let Some(ref sp) = sel_pname
                    && &f.profile != sp
                {
                    continue;
                }
                if let Some(sv) = state.finding_sev_filter
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
                egui::Frame::NONE
                    .fill(Color32::from_rgb(248, 248, 246))
                    .stroke(Stroke::new(1.0_f32, Color32::from_rgb(190, 190, 185)))
                    .inner_margin(egui::Margin::same(6))
                    .show(ui, |ui| {
                        ui.horizontal(|ui| {
                            let color = match f.severity {
                                FindingSeverity::Critical => Color32::from_rgb(185, 28, 28),
                                FindingSeverity::High => Color32::from_rgb(194, 65, 12),
                                FindingSeverity::Medium => Color32::from_rgb(161, 98, 7),
                                FindingSeverity::Low => Color32::from_rgb(21, 128, 61),
                                FindingSeverity::Info => Color32::from_rgb(3, 105, 161),
                            };
                            ui.colored_label(
                                color,
                                RichText::new(format!("[{}]", f.severity.as_str().to_ascii_uppercase())).strong(),
                            );
                            ui.strong(&f.title);
                            ui.label(
                                RichText::new(format!("({} / {})", f.profile, f.category))
                                    .size(11.0)
                                    .color(Color32::from_rgb(90, 90, 90)),
                            );
                        });
                        ui.label(&f.summary);
                        if !f.evidence.is_empty() {
                            ui.collapsing(format!("Evidence ({})", f.evidence.len()), |ui| {
                                for ev in &f.evidence {
                                    ui.label(RichText::new(ev).monospace().size(10.5));
                                }
                            });
                        }
                    });
                ui.add_space(4.0);
            }
            if shown == 0 {
                ui.label("No findings match the current filters.");
            }
        });
    });
}

pub fn render_timeline_tab(ui: &mut egui::Ui, state: &mut AppState) {
    win32_section_header(ui, "Unified Chronological Activity Timeline");
    ui.add_space(2.0);

    let Some(rep) = &state.report else {
        sunken_white_container(ui, |ui| {
            ui.label("No report loaded.");
        });
        return;
    };

    egui::Frame::NONE
        .fill(Color32::from_rgb(244, 243, 238))
        .stroke(Stroke::new(1.0_f32, Color32::from_rgb(172, 168, 153)))
        .inner_margin(egui::Margin::symmetric(5, 3))
        .show(ui, |ui| {
            ui.horizontal_wrapped(|ui| {
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
                    if ui.selectable_label(state.timeline_cat_filter == cat, cat).clicked() {
                        state.timeline_cat_filter = cat.to_string();
                    }
                }
                ui.separator();
                ui.label(RichText::new("Search:").size(11.0).strong());
                ui.text_edit_singleline(&mut state.forensic_search);
            });
        });
    ui.add_space(2.0);

    let sel_pname: Option<&str> = state
        .selected_profile_idx
        .and_then(|idx| rep.profiles.get(idx))
        .map(|p| p.profile_name.as_str());
    let q = state.forensic_search.trim().to_ascii_lowercase();

    let filtered: Vec<_> = rep
        .timeline
        .iter()
        .filter(|ev| {
            if let Some(sp) = sel_pname
                && ev.profile != sp
            {
                return false;
            }
            if state.timeline_cat_filter != "All" && ev.category != state.timeline_cat_filter {
                return false;
            }
            if !q.is_empty()
                && !ev.target.to_ascii_lowercase().contains(&q)
                && !ev.details.to_ascii_lowercase().contains(&q)
                && !ev.event_type.to_ascii_lowercase().contains(&q)
            {
                return false;
            }
            true
        })
        .collect();

    sunken_white_container(ui, |ui| {
        TableBuilder::new(ui)
            .id_salt("forensic_timeline_table")
            .striped(true)
            .resizable(true)
            .column(Column::initial(155.0).clip(true))
            .column(Column::initial(85.0).clip(true))
            .column(Column::initial(90.0).clip(true))
            .column(Column::initial(150.0).clip(true))
            .column(Column::initial(340.0).clip(true))
            .column(Column::initial(260.0).clip(true))
            .column(Column::initial(130.0).clip(true))
            .header(22.0, |mut hdr| {
                for h in [
                    "Timestamp",
                    "Profile",
                    "Category",
                    "Event",
                    "Target",
                    "Details",
                    "Artifact",
                ] {
                    hdr.col(|ui| {
                        ui.strong(h);
                    });
                }
            })
            .body(|body| {
                body.rows(20.0, filtered.len(), |mut row| {
                    let ev = filtered[row.index()];
                    row.col(|ui| {
                        ui.label(format_local_opt(Some(ev.timestamp), false));
                    });
                    row.col(|ui| {
                        ui.label(&ev.profile);
                    });
                    row.col(|ui| {
                        ui.label(&ev.category);
                    });
                    row.col(|ui| {
                        ui.label(&ev.event_type);
                    });
                    row.col(|ui| {
                        ui.label(&ev.target);
                    });
                    row.col(|ui| {
                        ui.label(&ev.details);
                    });
                    row.col(|ui| {
                        ui.label(&ev.source_artifact);
                    });
                });
            });
    });
}

pub fn render_history_tab(ui: &mut egui::Ui, state: &mut AppState) {
    win32_section_header(ui, "History, Visits, Downloads & Search Terms");
    ui.add_space(2.0);

    if state.visible_profiles().is_empty() {
        sunken_white_container(ui, |ui| {
            ui.label("No profile loaded.");
        });
        return;
    }

    egui::Frame::NONE
        .fill(Color32::from_rgb(244, 243, 238))
        .stroke(Stroke::new(1.0_f32, Color32::from_rgb(172, 168, 153)))
        .inner_margin(egui::Margin::symmetric(5, 3))
        .show(ui, |ui| {
            ui.horizontal_wrapped(|ui| {
                ui.selectable_value(&mut state.history_sub, HistorySubTab::Urls, "URLs");
                ui.selectable_value(&mut state.history_sub, HistorySubTab::Visits, "Visits");
                ui.selectable_value(&mut state.history_sub, HistorySubTab::Downloads, "Downloads");
                ui.selectable_value(&mut state.history_sub, HistorySubTab::SearchTerms, "Search Terms");
                ui.separator();
                ui.label(RichText::new("Search:").size(11.0).strong());
                ui.text_edit_singleline(&mut state.forensic_search);
            });
            for (_, p) in &state.visible_profiles() {
                let di = &p.history.deletion_indicators;
                ui.label(
                    RichText::new(format!(
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
                    .size(10.5)
                    .color(Color32::from_rgb(80, 80, 80)),
                );
            }
        });
    ui.add_space(2.0);

    let q = state.forensic_search.trim().to_ascii_lowercase();
    let hist_sub = state.history_sub;
    let profiles = state.visible_profiles();

    sunken_white_container(ui, |ui| match hist_sub {
        HistorySubTab::Urls => {
            let mut rows = Vec::new();
            for (_, p) in &profiles {
                for u in &p.history.urls {
                    if q.is_empty()
                        || u.url.to_ascii_lowercase().contains(&q)
                        || u.title.to_ascii_lowercase().contains(&q)
                    {
                        rows.push((&p.profile_name, u));
                    }
                }
            }
            TableBuilder::new(ui)
                .id_salt("hist_urls_tbl")
                .striped(true)
                .resizable(true)
                .column(Column::initial(85.0).clip(true))
                .column(Column::initial(150.0).clip(true))
                .column(Column::initial(60.0))
                .column(Column::initial(60.0))
                .column(Column::initial(260.0).clip(true))
                .column(Column::initial(420.0).clip(true))
                .header(22.0, |mut h| {
                    for t in ["Profile", "Last Visit", "Visits", "Typed", "Title", "URL"] {
                        h.col(|ui| {
                            ui.strong(t);
                        });
                    }
                })
                .body(|b| {
                    b.rows(20.0, rows.len(), |mut r| {
                        let (pn, u) = rows[r.index()];
                        r.col(|ui| {
                            ui.label(pn);
                        });
                        r.col(|ui| {
                            ui.label(format_local_opt(u.last_visit_time, false));
                        });
                        r.col(|ui| {
                            ui.label(u.visit_count.to_string());
                        });
                        r.col(|ui| {
                            ui.label(u.typed_count.to_string());
                        });
                        r.col(|ui| {
                            ui.label(&u.title);
                        });
                        r.col(|ui| {
                            ui.label(&u.url);
                        });
                    });
                });
        }
        HistorySubTab::Visits => {
            let mut rows = Vec::new();
            for (_, p) in &profiles {
                for v in &p.history.visits {
                    if q.is_empty()
                        || v.url.to_ascii_lowercase().contains(&q)
                        || v.title.to_ascii_lowercase().contains(&q)
                        || v.transition_core.to_ascii_lowercase().contains(&q)
                    {
                        rows.push((&p.profile_name, v));
                    }
                }
            }
            TableBuilder::new(ui)
                .id_salt("hist_visits_tbl")
                .striped(true)
                .resizable(true)
                .column(Column::initial(85.0).clip(true))
                .column(Column::initial(150.0).clip(true))
                .column(Column::initial(120.0).clip(true))
                .column(Column::initial(140.0).clip(true))
                .column(Column::initial(85.0).clip(true))
                .column(Column::initial(220.0).clip(true))
                .column(Column::initial(360.0).clip(true))
                .header(22.0, |mut h| {
                    for t in [
                        "Profile",
                        "Visit Time",
                        "Transition",
                        "Qualifiers",
                        "Dur (ms)",
                        "Title",
                        "URL",
                    ] {
                        h.col(|ui| {
                            ui.strong(t);
                        });
                    }
                })
                .body(|b| {
                    b.rows(20.0, rows.len(), |mut r| {
                        let (pn, v) = rows[r.index()];
                        r.col(|ui| {
                            ui.label(pn);
                        });
                        r.col(|ui| {
                            ui.label(format_local_opt(v.visit_time, false));
                        });
                        r.col(|ui| {
                            ui.label(&v.transition_core);
                        });
                        r.col(|ui| {
                            ui.label(v.transition_qualifiers.join(", "));
                        });
                        r.col(|ui| {
                            ui.label(v.visit_duration_ms.to_string());
                        });
                        r.col(|ui| {
                            ui.label(&v.title);
                        });
                        r.col(|ui| {
                            ui.label(&v.url);
                        });
                    });
                });
        }
        HistorySubTab::Downloads => {
            let mut rows = Vec::new();
            for (_, p) in &profiles {
                for d in &p.history.downloads {
                    let urls = d.url_chain.join(" -> ");
                    if q.is_empty()
                        || d.target_path.to_ascii_lowercase().contains(&q)
                        || urls.to_ascii_lowercase().contains(&q)
                    {
                        rows.push((&p.profile_name, d, urls));
                    }
                }
            }
            TableBuilder::new(ui)
                .id_salt("hist_dl_tbl")
                .striped(true)
                .resizable(true)
                .column(Column::initial(85.0).clip(true))
                .column(Column::initial(150.0).clip(true))
                .column(Column::initial(95.0).clip(true))
                .column(Column::initial(140.0).clip(true))
                .column(Column::initial(90.0).clip(true))
                .column(Column::initial(280.0).clip(true))
                .column(Column::initial(360.0).clip(true))
                .header(22.0, |mut h| {
                    for t in [
                        "Profile",
                        "Start Time",
                        "State",
                        "Danger",
                        "Bytes",
                        "Target Path",
                        "URL Chain",
                    ] {
                        h.col(|ui| {
                            ui.strong(t);
                        });
                    }
                })
                .body(|b| {
                    b.rows(20.0, rows.len(), |mut r| {
                        let (pn, d, urls) = &rows[r.index()];
                        r.col(|ui| {
                            ui.label(*pn);
                        });
                        r.col(|ui| {
                            ui.label(format_local_opt(d.start_time, false));
                        });
                        r.col(|ui| {
                            ui.label(&d.state);
                        });
                        r.col(|ui| {
                            ui.label(&d.danger_type);
                        });
                        r.col(|ui| {
                            ui.label(format_bytes(d.total_bytes.max(d.received_bytes).max(0) as u64));
                        });
                        r.col(|ui| {
                            ui.label(&d.target_path);
                        });
                        r.col(|ui| {
                            ui.label(urls);
                        });
                    });
                });
        }
        HistorySubTab::SearchTerms => {
            let mut rows = Vec::new();
            for (_, p) in &profiles {
                for s in &p.history.search_terms {
                    if q.is_empty()
                        || s.term.to_ascii_lowercase().contains(&q)
                        || s.url.as_deref().unwrap_or("").to_ascii_lowercase().contains(&q)
                    {
                        rows.push((&p.profile_name, s));
                    }
                }
            }
            TableBuilder::new(ui)
                .id_salt("hist_kw_tbl")
                .striped(true)
                .resizable(true)
                .column(Column::initial(90.0).clip(true))
                .column(Column::initial(155.0).clip(true))
                .column(Column::initial(240.0).clip(true))
                .column(Column::initial(420.0).clip(true))
                .header(22.0, |mut h| {
                    for t in ["Profile", "Last Visit", "Search Term", "URL"] {
                        h.col(|ui| {
                            ui.strong(t);
                        });
                    }
                })
                .body(|b| {
                    b.rows(20.0, rows.len(), |mut r| {
                        let (pn, s) = rows[r.index()];
                        r.col(|ui| {
                            ui.label(pn);
                        });
                        r.col(|ui| {
                            ui.label(format_local_opt(s.last_visit_time, false));
                        });
                        r.col(|ui| {
                            ui.label(&s.term);
                        });
                        r.col(|ui| {
                            ui.label(s.url.as_deref().unwrap_or(""));
                        });
                    });
                });
        }
    });
}

pub fn render_creds_tab(ui: &mut egui::Ui, state: &mut AppState) {
    win32_section_header(ui, "Credentials, Cookies, Autofill & Payment Metadata");
    ui.add_space(2.0);

    if state.visible_profiles().is_empty() {
        sunken_white_container(ui, |ui| {
            ui.label("No profile loaded.");
        });
        return;
    }

    let mut open_crypto_modal = false;
    egui::Frame::NONE
        .fill(Color32::from_rgb(244, 243, 238))
        .stroke(Stroke::new(1.0_f32, Color32::from_rgb(172, 168, 153)))
        .inner_margin(egui::Margin::symmetric(5, 3))
        .show(ui, |ui| {
            ui.horizontal_wrapped(|ui| {
                ui.selectable_value(&mut state.cred_sub, CredSubTab::Logins, "Saved Logins");
                ui.selectable_value(&mut state.cred_sub, CredSubTab::Cookies, "Cookies");
                ui.selectable_value(&mut state.cred_sub, CredSubTab::Autofill, "Autofill");
                ui.selectable_value(&mut state.cred_sub, CredSubTab::AddressesCards, "Addresses & Cards");
                ui.separator();
                if ui.small_button("Decryption Keys...").clicked() {
                    open_crypto_modal = true;
                }
                ui.separator();
                ui.label(RichText::new("Search:").size(11.0).strong());
                ui.text_edit_singleline(&mut state.forensic_search);
            });
        });
    if open_crypto_modal {
        state.active_modal = ActiveModal::DecryptionSettings;
    }
    ui.add_space(2.0);

    let q = state.forensic_search.trim().to_ascii_lowercase();
    let cred_sub = state.cred_sub;
    let profiles = state.visible_profiles();

    sunken_white_container(ui, |ui| match cred_sub {
        CredSubTab::Logins => {
            let mut rows = Vec::new();
            for (_, p) in &profiles {
                for l in &p.logins {
                    if q.is_empty()
                        || l.origin_url.to_ascii_lowercase().contains(&q)
                        || l.username_value.to_ascii_lowercase().contains(&q)
                    {
                        rows.push((&p.profile_name, l));
                    }
                }
            }
            TableBuilder::new(ui)
                .id_salt("creds_logins_tbl")
                .striped(true)
                .resizable(true)
                .column(Column::initial(80.0).clip(true))
                .column(Column::initial(260.0).clip(true))
                .column(Column::initial(160.0).clip(true))
                .column(Column::initial(75.0).clip(true))
                .column(Column::initial(170.0).clip(true))
                .column(Column::initial(60.0))
                .column(Column::initial(150.0).clip(true))
                .column(Column::initial(170.0).clip(true))
                .header(22.0, |mut h| {
                    for t in [
                        "Profile",
                        "Origin URL",
                        "Username",
                        "Scheme",
                        "Password / Status",
                        "Uses",
                        "Last Used",
                        "Issues",
                    ] {
                        h.col(|ui| {
                            ui.strong(t);
                        });
                    }
                })
                .body(|b| {
                    b.rows(20.0, rows.len(), |mut r| {
                        let (pn, l) = rows[r.index()];
                        let pw = l
                            .password_decrypted
                            .clone()
                            .unwrap_or_else(|| format!("[Encrypted {} B]", l.password_encrypted_len));
                        r.col(|ui| {
                            ui.label(pn);
                        });
                        r.col(|ui| {
                            ui.label(&l.origin_url);
                        });
                        r.col(|ui| {
                            ui.label(&l.username_value);
                        });
                        r.col(|ui| {
                            ui.label(l.encryption_scheme.as_str());
                        });
                        r.col(|ui| {
                            ui.label(pw);
                        });
                        r.col(|ui| {
                            ui.label(l.times_used.to_string());
                        });
                        r.col(|ui| {
                            ui.label(format_local_opt(l.date_last_used, false));
                        });
                        r.col(|ui| {
                            ui.label(l.insecure_issues.join(", "));
                        });
                    });
                });
        }
        CredSubTab::Cookies => {
            let mut rows = Vec::new();
            for (_, p) in &profiles {
                for c in &p.cookies {
                    if q.is_empty()
                        || c.host_key.to_ascii_lowercase().contains(&q)
                        || c.name.to_ascii_lowercase().contains(&q)
                        || c.value.as_deref().unwrap_or("").to_ascii_lowercase().contains(&q)
                    {
                        rows.push((&p.profile_name, c));
                    }
                }
            }
            TableBuilder::new(ui)
                .id_salt("creds_cookies_tbl")
                .striped(true)
                .resizable(true)
                .column(Column::initial(80.0).clip(true))
                .column(Column::initial(200.0).clip(true))
                .column(Column::initial(150.0).clip(true))
                .column(Column::initial(70.0).clip(true))
                .column(Column::initial(210.0).clip(true))
                .column(Column::initial(60.0))
                .column(Column::initial(65.0))
                .column(Column::initial(110.0).clip(true))
                .column(Column::initial(150.0).clip(true))
                .header(22.0, |mut h| {
                    for t in [
                        "Profile",
                        "Host Key",
                        "Name",
                        "Scheme",
                        "Value / Status",
                        "Secure",
                        "HttpOnly",
                        "SameSite",
                        "Expires",
                    ] {
                        h.col(|ui| {
                            ui.strong(t);
                        });
                    }
                })
                .body(|b| {
                    b.rows(20.0, rows.len(), |mut r| {
                        let (pn, c) = rows[r.index()];
                        let val = c
                            .value
                            .clone()
                            .unwrap_or_else(|| format!("[Encrypted {} B]", c.encrypted_len));
                        r.col(|ui| {
                            ui.label(pn);
                        });
                        r.col(|ui| {
                            ui.label(&c.host_key);
                        });
                        r.col(|ui| {
                            ui.label(&c.name);
                        });
                        r.col(|ui| {
                            ui.label(c.encryption_scheme.as_str());
                        });
                        r.col(|ui| {
                            ui.label(val);
                        });
                        r.col(|ui| {
                            ui.label(if c.is_secure { "Yes" } else { "No" });
                        });
                        r.col(|ui| {
                            ui.label(if c.is_httponly { "Yes" } else { "No" });
                        });
                        r.col(|ui| {
                            ui.label(&c.samesite);
                        });
                        r.col(|ui| {
                            ui.label(format_local_opt(c.expires_utc, false));
                        });
                    });
                });
        }
        CredSubTab::Autofill => {
            let mut rows = Vec::new();
            for (_, p) in &profiles {
                for a in &p.web_data.autofill {
                    if q.is_empty()
                        || a.name.to_ascii_lowercase().contains(&q)
                        || a.value.to_ascii_lowercase().contains(&q)
                    {
                        rows.push((&p.profile_name, a));
                    }
                }
            }
            TableBuilder::new(ui)
                .id_salt("creds_autofill_tbl")
                .striped(true)
                .resizable(true)
                .column(Column::initial(85.0).clip(true))
                .column(Column::initial(180.0).clip(true))
                .column(Column::initial(260.0).clip(true))
                .column(Column::initial(65.0))
                .column(Column::initial(155.0).clip(true))
                .column(Column::initial(155.0).clip(true))
                .header(22.0, |mut h| {
                    for t in ["Profile", "Field Name", "Value", "Count", "Created", "Last Used"] {
                        h.col(|ui| {
                            ui.strong(t);
                        });
                    }
                })
                .body(|b| {
                    b.rows(20.0, rows.len(), |mut r| {
                        let (pn, a) = rows[r.index()];
                        r.col(|ui| {
                            ui.label(pn);
                        });
                        r.col(|ui| {
                            ui.label(&a.name);
                        });
                        r.col(|ui| {
                            ui.label(&a.value);
                        });
                        r.col(|ui| {
                            ui.label(a.count.to_string());
                        });
                        r.col(|ui| {
                            ui.label(format_local_opt(a.date_created, false));
                        });
                        r.col(|ui| {
                            ui.label(format_local_opt(a.date_last_used, false));
                        });
                    });
                });
        }
        CredSubTab::AddressesCards => {
            egui::ScrollArea::vertical().show(ui, |ui| {
                ui.label(
                    RichText::new("Saved Addresses")
                        .strong()
                        .size(12.0)
                        .color(Color32::from_rgb(0, 51, 153)),
                );
                for (_, p) in &profiles {
                    for a in &p.web_data.addresses {
                        ui.label(format!(
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
                        ));
                    }
                }
                ui.separator();
                ui.label(
                    RichText::new("Saved Payment Card Metadata")
                        .strong()
                        .size(12.0)
                        .color(Color32::from_rgb(0, 51, 153)),
                );
                for (_, p) in &profiles {
                    for c in &p.web_data.credit_cards {
                        ui.label(format!(
                            "[{}] {} | {} | ****{} | Exp: {}/{} | uses: {}",
                            p.profile_name,
                            c.name_on_card,
                            c.network,
                            c.last_four,
                            c.expiration_month,
                            c.expiration_year,
                            c.use_count
                        ));
                    }
                }
            });
        }
    });
}

pub fn render_extensions_tab(ui: &mut egui::Ui, state: &mut AppState) {
    win32_section_header(ui, "Installed Extensions & Hierarchical Bookmarks");
    ui.add_space(2.0);

    if state.visible_profiles().is_empty() {
        sunken_white_container(ui, |ui| {
            ui.label("No profile loaded.");
        });
        return;
    }

    egui::Frame::NONE
        .fill(Color32::from_rgb(244, 243, 238))
        .stroke(Stroke::new(1.0_f32, Color32::from_rgb(172, 168, 153)))
        .inner_margin(egui::Margin::symmetric(5, 3))
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(RichText::new("Search Extensions / Bookmarks:").size(11.0).strong());
                ui.text_edit_singleline(&mut state.forensic_search);
            });
        });
    ui.add_space(2.0);

    let q = state.forensic_search.trim().to_ascii_lowercase();
    let profiles = state.visible_profiles();

    sunken_white_container(ui, |ui| {
        egui::ScrollArea::vertical().show(ui, |ui| {
            ui.label(
                RichText::new("Installed Extensions")
                    .strong()
                    .size(12.0)
                    .color(Color32::from_rgb(0, 51, 153)),
            );
            for (_, p) in &profiles {
                for ext in &p.extensions {
                    if !q.is_empty()
                        && !ext.name.to_ascii_lowercase().contains(&q)
                        && !ext.id.to_ascii_lowercase().contains(&q)
                        && !ext.risk_flags.iter().any(|r| r.to_ascii_lowercase().contains(&q))
                    {
                        continue;
                    }
                    egui::Frame::NONE
                        .fill(Color32::from_rgb(248, 248, 246))
                        .stroke(Stroke::new(1.0_f32, Color32::from_rgb(190, 190, 185)))
                        .inner_margin(egui::Margin::same(5))
                        .show(ui, |ui| {
                            ui.horizontal_wrapped(|ui| {
                                ui.strong(&ext.name);
                                ui.label(format!(
                                    "v{} ({}) [{} | {}]",
                                    ext.version, ext.id, p.profile_name, ext.location
                                ));
                                if !ext.risk_flags.is_empty() {
                                    ui.colored_label(
                                        Color32::from_rgb(194, 65, 12),
                                        format!("RISK: {}", ext.risk_flags.join(", ")),
                                    );
                                }
                            });
                            if !ext.permissions.is_empty() {
                                ui.label(
                                    RichText::new(format!("Permissions: {}", ext.permissions.join(", ")))
                                        .size(10.5)
                                        .color(Color32::from_rgb(80, 80, 80)),
                                );
                            }
                        });
                    ui.add_space(3.0);
                }
            }

            ui.separator();
            ui.label(
                RichText::new("Bookmarks")
                    .strong()
                    .size(12.0)
                    .color(Color32::from_rgb(0, 51, 153)),
            );
            for (_, p) in &profiles {
                for b in p.bookmarks.iter().take(500) {
                    if !q.is_empty()
                        && !b.name.to_ascii_lowercase().contains(&q)
                        && !b.url.to_ascii_lowercase().contains(&q)
                        && !b.folder_path.to_ascii_lowercase().contains(&q)
                    {
                        continue;
                    }
                    ui.label(format!(
                        "[{}] [{}] {} -> {}",
                        p.profile_name, b.folder_path, b.name, b.url
                    ));
                }
            }
        });
    });
}

pub fn render_sessions_tab(ui: &mut egui::Ui, state: &mut AppState) {
    win32_section_header(ui, "SNSS Sessions, LevelDB Storage, IndexedDB & File Inventory");
    ui.add_space(2.0);

    if state.visible_profiles().is_empty() {
        sunken_white_container(ui, |ui| {
            ui.label("No profile loaded.");
        });
        return;
    }

    egui::Frame::NONE
        .fill(Color32::from_rgb(244, 243, 238))
        .stroke(Stroke::new(1.0_f32, Color32::from_rgb(172, 168, 153)))
        .inner_margin(egui::Margin::symmetric(5, 3))
        .show(ui, |ui| {
            ui.horizontal_wrapped(|ui| {
                ui.selectable_value(&mut state.sess_sub, SessionSubTab::Tabs, "SNSS Open & Closed Tabs");
                ui.selectable_value(
                    &mut state.sess_sub,
                    SessionSubTab::LocalStorage,
                    "Local Storage (LevelDB)",
                );
                ui.selectable_value(
                    &mut state.sess_sub,
                    SessionSubTab::SessionStorage,
                    "Session Storage (LevelDB)",
                );
                ui.selectable_value(
                    &mut state.sess_sub,
                    SessionSubTab::MiscInventory,
                    "IndexedDB, Top Sites & File Inventory",
                );
                ui.separator();
                ui.label(RichText::new("Search:").size(11.0).strong());
                ui.text_edit_singleline(&mut state.forensic_search);
            });
        });
    ui.add_space(2.0);

    let q = state.forensic_search.trim().to_ascii_lowercase();
    let sess_sub = state.sess_sub;
    let mut next_nav = state.selected_tab_nav_idx;
    let profiles = state.visible_profiles();

    sunken_white_container(ui, |ui| {
        egui::ScrollArea::vertical().show(ui, |ui| match sess_sub {
            SessionSubTab::Tabs => {
                for (pidx, p) in &profiles {
                    if p.sessions.encrypted_sessions_present {
                        ui.colored_label(
                            Color32::from_rgb(3, 105, 161),
                            format!("[{}] Sessions_Encrypted directory detected.", p.profile_name),
                        );
                    }
                    let mut tabs: Vec<_> = p
                        .sessions
                        .open_tabs
                        .iter()
                        .chain(p.sessions.closed_tabs.iter())
                        .enumerate()
                        .collect();
                    tabs.retain(|(_, t)| {
                        q.is_empty()
                            || t.current_url.to_ascii_lowercase().contains(&q)
                            || t.current_title.to_ascii_lowercase().contains(&q)
                    });
                    for (tidx, t) in tabs {
                        let state_tag = if t.is_closed { "CLOSED" } else { "OPEN" };
                        let selected = next_nav == Some((*pidx, tidx));
                        if ui
                            .selectable_label(
                                selected,
                                format!(
                                    "[{}] [{}] Tab #{} ({}) {} -> {} [{} navs]",
                                    p.profile_name,
                                    state_tag,
                                    t.tab_id,
                                    t.source_file,
                                    t.current_title,
                                    t.current_url,
                                    t.navigations.len()
                                ),
                            )
                            .clicked()
                        {
                            next_nav = Some((*pidx, tidx));
                        }
                        if selected {
                            for nav in &t.navigations {
                                ui.label(
                                    RichText::new(format!("    [{}] {} -> {}", nav.index, nav.title, nav.url))
                                        .monospace()
                                        .size(10.5),
                                );
                            }
                        }
                    }
                }
            }
            SessionSubTab::LocalStorage => {
                for (_, p) in &profiles {
                    for kv in &p.storage.local_storage {
                        if !q.is_empty()
                            && !kv.origin.to_ascii_lowercase().contains(&q)
                            && !kv.key.to_ascii_lowercase().contains(&q)
                            && !kv.value.to_ascii_lowercase().contains(&q)
                        {
                            continue;
                        }
                        ui.label(
                            RichText::new(format!(
                                "[{}] {} | {} = {}",
                                p.profile_name, kv.origin, kv.key, kv.value
                            ))
                            .monospace()
                            .size(10.5),
                        );
                    }
                }
            }
            SessionSubTab::SessionStorage => {
                for (_, p) in &profiles {
                    for kv in &p.storage.session_storage {
                        if !q.is_empty()
                            && !kv.origin.to_ascii_lowercase().contains(&q)
                            && !kv.key.to_ascii_lowercase().contains(&q)
                            && !kv.value.to_ascii_lowercase().contains(&q)
                        {
                            continue;
                        }
                        ui.label(
                            RichText::new(format!(
                                "[{}] {} | {} = {}",
                                p.profile_name, kv.origin, kv.key, kv.value
                            ))
                            .monospace()
                            .size(10.5),
                        );
                    }
                }
            }
            SessionSubTab::MiscInventory => {
                for (_, p) in &profiles {
                    ui.label(
                        RichText::new(format!("{} — IndexedDB / Top Sites / Largest Files", p.profile_name))
                            .strong()
                            .size(12.0)
                            .color(Color32::from_rgb(0, 51, 153)),
                    );
                    for idb in &p.storage.indexed_db_origins {
                        ui.label(format!(
                            "IndexedDB: {} ({} files, {})",
                            idb.origin_dir,
                            idb.file_count,
                            format_bytes(idb.total_bytes)
                        ));
                    }
                    for ts in &p.storage.top_sites {
                        ui.label(format!("TopSite #{}: {} ({})", ts.rank, ts.title, ts.url));
                    }
                    for nel in &p.storage.nel_policies {
                        ui.label(format!(
                            "NEL Policy: {} (IP: {}, group: {})",
                            nel.origin, nel.received_ip, nel.group_name
                        ));
                    }
                    ui.separator();
                    for f in p.file_inventory.iter().take(100) {
                        if !q.is_empty()
                            && !f.relative_path.to_ascii_lowercase().contains(&q)
                            && !f.category.to_ascii_lowercase().contains(&q)
                        {
                            continue;
                        }
                        ui.label(
                            RichText::new(format!(
                                "{:<22} {:>10}  {}",
                                f.category,
                                format_bytes(f.size_bytes),
                                f.relative_path
                            ))
                            .monospace()
                            .size(10.5),
                        );
                    }
                }
            }
        });
    });

    state.selected_tab_nav_idx = next_nav;
}
