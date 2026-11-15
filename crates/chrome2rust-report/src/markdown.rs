use chrome2rust_core::time::format_utc_opt;
use chrome2rust_forensics::UserDataReport;
use std::fmt::Write;

pub fn render_markdown_report(report: &UserDataReport) -> String {
    let mut out = String::new();

    let _ = writeln!(out, "# Chrome Forensic Analysis Report (`chrome2rust`)");
    let _ = writeln!(out);
    let _ = writeln!(out, "- **Target Path:** `{}`", report.target_path);
    let _ = writeln!(out, "- **Target Kind:** `{:?}`", report.target_kind);
    let _ = writeln!(
        out,
        "- **Generated At:** {}",
        report.generated_at.format("%Y-%m-%d %H:%M:%S UTC")
    );
    let _ = writeln!(out, "- **Tool Version:** `{}`", report.tool_version);
    if let Some(ver) = &report.local_state.chrome_version {
        let _ = writeln!(out, "- **Detected Chrome Version:** `{ver}`");
    }
    let _ = writeln!(out);

    // Executive Summary KPIs
    let s = &report.summary;
    let _ = writeln!(out, "## Executive Summary");
    let _ = writeln!(out);
    let _ = writeln!(out, "| Metric | Value |");
    let _ = writeln!(out, "| --- | ---: |");
    let _ = writeln!(out, "| Profiles Analyzed | {} |", s.profile_count);
    let _ = writeln!(
        out,
        "| Cache Entries / Payload Size | {} ({}) |",
        s.total_cache_entries,
        format_bytes(s.total_cache_bytes)
    );
    let _ = writeln!(
        out,
        "| History URLs / Visits | {} / {} |",
        s.total_history_urls, s.total_history_visits
    );
    let _ = writeln!(out, "| Downloads | {} |", s.total_downloads);
    let _ = writeln!(out, "| Cookies | {} |", s.total_cookies);
    let _ = writeln!(out, "| Saved Logins | {} |", s.total_logins);
    let _ = writeln!(out, "| Autofill & Address Records | {} |", s.total_autofill_entries);
    let _ = writeln!(out, "| Bookmarks | {} |", s.total_bookmarks);
    let _ = writeln!(out, "| Extensions | {} |", s.total_extensions);
    let _ = writeln!(
        out,
        "| Session Tabs (Open / Closed) | {} / {} |",
        s.total_open_tabs, s.total_closed_tabs
    );
    let _ = writeln!(out, "| Local & Session Storage Keys | {} |", s.total_local_storage_keys);
    let _ = writeln!(out, "| Unified Timeline Events | {} |", s.total_timeline_events);
    let _ = writeln!(out, "| Forensic Findings | {} |", s.total_findings);
    let _ = writeln!(out);

    // Forensic Findings
    let _ = writeln!(out, "## Forensic Findings");
    let _ = writeln!(out);
    if report.findings.is_empty() {
        let _ = writeln!(out, "_No anomalies or elevated-risk findings detected._");
        let _ = writeln!(out);
    } else {
        for f in &report.findings {
            let _ = writeln!(
                out,
                "### [{}] {} — `{}` ({})",
                f.severity.as_str().to_ascii_uppercase(),
                f.title,
                f.profile,
                f.category
            );
            let _ = writeln!(out);
            let _ = writeln!(out, "{}", f.summary);
            if !f.evidence.is_empty() {
                let _ = writeln!(out);
                for ev in f.evidence.iter().take(20) {
                    let _ = writeln!(out, "- `{}`", ev.replace('`', "'"));
                }
            }
            let _ = writeln!(out);
        }
    }

    // Local State & Environment
    let ls = &report.local_state;
    let _ = writeln!(out, "## Local State & Environment");
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "- **OS Crypt Key Present:** {}",
        if ls.os_crypt_encrypted_key_present { "Yes" } else { "No" }
    );
    if let Some(prefix) = &ls.os_crypt_key_prefix {
        let _ = writeln!(out, "- **OS Crypt Key Prefix:** `{prefix}`");
    }
    if let Some(portal) = &ls.os_crypt_portal_info {
        let _ = writeln!(out, "- **OS Crypt Portal Info:** `{}`", md_cell(portal));
    }
    if !ls.last_active_profiles.is_empty() {
        let _ = writeln!(
            out,
            "- **Last Active Profiles:** {}",
            ls.last_active_profiles.join(", ")
        );
    }
    if let Some(country) = &ls.variations_country {
        let _ = writeln!(out, "- **Variations Country:** `{country}`");
    }
    let _ = writeln!(out, "- **Policy Keys Count:** {}", ls.policy_count);
    let _ = writeln!(out);

    if !ls.profile_summaries.is_empty() {
        let _ = writeln!(
            out,
            "| Dir Name | Profile Name | Account Email | GAIA Name | Active Time | Ephemeral |"
        );
        let _ = writeln!(out, "| --- | --- | --- | --- | --- | --- |");
        for pm in &ls.profile_summaries {
            let _ = writeln!(
                out,
                "| {} | {} | {} | {} | {} | {} |",
                md_cell(&pm.dir_name),
                md_cell(pm.name.as_deref().unwrap_or("")),
                md_cell(pm.user_name.as_deref().unwrap_or("")),
                md_cell(pm.gaia_name.as_deref().unwrap_or("")),
                md_cell(&format_utc_opt(pm.active_time, false)),
                if pm.is_ephemeral { "Yes" } else { "No" }
            );
        }
        let _ = writeln!(out);
    }

    // Top Domains
    if !report.top_domains.is_empty() {
        let _ = writeln!(out, "## Top Domains by Activity");
        let _ = writeln!(out);
        let _ = writeln!(
            out,
            "| Domain | History Visits | Cache Entries | Cache Size | Cookies |"
        );
        let _ = writeln!(out, "| --- | ---: | ---: | ---: | ---: |");
        for d in report.top_domains.iter().take(40) {
            let _ = writeln!(
                out,
                "| {} | {} | {} | {} | {} |",
                md_cell(&d.domain),
                d.history_visits,
                d.cache_items,
                format_bytes(d.cache_bytes),
                d.cookies
            );
        }
        let _ = writeln!(out);
    }

    // Cache Content-Type breakdown
    if !s.cache_content_type_breakdown.is_empty() {
        let _ = writeln!(out, "## Cache Content-Type Breakdown");
        let _ = writeln!(out);
        let _ = writeln!(out, "| Primary MIME Category | Entry Count |");
        let _ = writeln!(out, "| --- | ---: |");
        for (k, v) in &s.cache_content_type_breakdown {
            let _ = writeln!(out, "| {} | {} |", md_cell(k), v);
        }
        let _ = writeln!(out);
    }

    // Per-profile sections
    for p in &report.profiles {
        let _ = writeln!(out, "---");
        let _ = writeln!(out);
        let _ = writeln!(out, "## Profile: `{}`", p.profile_name);
        let _ = writeln!(out);
        let _ = writeln!(out, "- **Profile Path:** `{}`", p.profile_path);
        let _ = writeln!(
            out,
            "- **Profile Disk Size (top-3 levels):** {}",
            format_bytes(p.total_profile_bytes)
        );
        if !p.cache_dirs.is_empty() {
            let _ = writeln!(out, "- **Cache Directories:** `{}`", p.cache_dirs.join("`, `"));
        }
        let _ = writeln!(out);

        // Preferences
        let pref = &p.preferences;
        let has_pref_details = pref.profile_name.is_some()
            || pref.homepage.is_some()
            || pref.default_search_name.is_some()
            || pref.download_default_dir.is_some()
            || pref.safebrowsing_enabled.is_some()
            || pref.developer_mode.is_some()
            || pref.proxy_mode.is_some()
            || pref.accept_languages.is_some()
            || !pref.startup_urls.is_empty()
            || !pref.account_emails.is_empty()
            || !pref.top_level_keys.is_empty();
        if has_pref_details {
            let _ = writeln!(out, "### Settings & Preferences");
            let _ = writeln!(out);
            if let Some(pname) = &pref.profile_name {
                let _ = writeln!(out, "- **Profile Display Name:** {pname}");
            }
            if let Some(hp) = &pref.homepage {
                let _ = writeln!(out, "- **Homepage:** `{hp}`");
            }
            if let Some(ds) = &pref.default_search_name {
                let _ = writeln!(out, "- **Default Search Engine:** {ds}");
            }
            if let Some(dl) = &pref.download_default_dir {
                let _ = writeln!(out, "- **Download Directory:** `{dl}`");
            }
            if let Some(sb) = pref.safebrowsing_enabled {
                let _ = writeln!(out, "- **Safe Browsing Enabled:** {sb}");
            }
            if let Some(dev) = pref.developer_mode {
                let _ = writeln!(out, "- **Extensions Developer Mode:** {dev}");
            }
            if let Some(pm) = &pref.proxy_mode {
                let _ = writeln!(out, "- **Proxy Mode:** `{pm}`");
            }
            if let Some(lang) = &pref.accept_languages {
                let _ = writeln!(out, "- **Accept Languages:** `{lang}`");
            }
            if !pref.startup_urls.is_empty() {
                let _ = writeln!(out, "- **Startup URLs:** `{}`", pref.startup_urls.join("`, `"));
            }
            if !pref.account_emails.is_empty() {
                let _ = writeln!(out, "- **Signed-In Accounts:** {}", pref.account_emails.join(", "));
            }
            if !pref.top_level_keys.is_empty() {
                let _ = writeln!(out, "- **Preferences Top-Level Keys:** {}", pref.top_level_keys.len());
            }
            let _ = writeln!(out);
        }

        // History deletion indicators & recent URLs
        let di = &p.history.deletion_indicators;
        if di.urls_row_count > 0 || di.visits_row_count > 0 {
            let _ = writeln!(out, "### History Integrity & Top URLs");
            let _ = writeln!(out);
            let _ = writeln!(
                out,
                "- URLs: {} rows (max ID: {}, seq: {}, est. deleted gaps: {}, hidden: {})",
                di.urls_row_count, di.urls_max_id, di.urls_sqlite_seq, di.urls_estimated_deleted, di.hidden_urls_count
            );
            let _ = writeln!(
                out,
                "- Visits: {} rows (max ID: {}, seq: {}, est. deleted gaps: {})",
                di.visits_row_count, di.visits_max_id, di.visits_sqlite_seq, di.visits_estimated_deleted
            );
            let _ = writeln!(out);
            if !p.history.urls.is_empty() {
                let _ = writeln!(out, "| Last Visit (UTC) | Visits | Typed | Title | URL |");
                let _ = writeln!(out, "| --- | ---: | ---: | --- | --- |");
                for u in p.history.urls.iter().take(50) {
                    let _ = writeln!(
                        out,
                        "| {} | {} | {} | {} | {} |",
                        format_utc_opt(u.last_visit_time, false),
                        u.visit_count,
                        u.typed_count,
                        md_cell(&truncate_str(&u.title, 60)),
                        md_cell(&truncate_str(&u.url, 90)),
                    );
                }
                let _ = writeln!(out);
            }
        }

        // Downloads
        if !p.history.downloads.is_empty() {
            let _ = writeln!(out, "### Downloads ({})", p.history.downloads.len());
            let _ = writeln!(out);
            let _ = writeln!(out, "| Start Time | State | Danger | Size | Target Path | Source URL |");
            let _ = writeln!(out, "| --- | --- | --- | ---: | --- | --- |");
            for d in p.history.downloads.iter().take(100) {
                let url = d.url_chain.last().map(String::as_str).unwrap_or("");
                let _ = writeln!(
                    out,
                    "| {} | {} | {} | {} | {} | {} |",
                    format_utc_opt(d.start_time, false),
                    d.state,
                    d.danger_type,
                    format_bytes(d.total_bytes.max(d.received_bytes).max(0) as u64),
                    md_cell(&d.target_path),
                    md_cell(&truncate_str(url, 80)),
                );
            }
            let _ = writeln!(out);
        }

        // Saved Logins
        if !p.logins.is_empty() {
            let _ = writeln!(out, "### Saved Credentials ({})", p.logins.len());
            let _ = writeln!(out);
            let _ = writeln!(out, "| Origin URL | Username | Scheme | Decrypted | Uses | Issues |");
            let _ = writeln!(out, "| --- | --- | --- | --- | ---: | --- |");
            for l in &p.logins {
                let dec_display = match &l.password_decrypted {
                    Some(pw) => format!("Yes ({} chars)", pw.chars().count()),
                    None => format!("Encrypted ({} B)", l.password_encrypted_len),
                };
                let _ = writeln!(
                    out,
                    "| {} | {} | {} | {} | {} | {} |",
                    md_cell(&truncate_str(&l.origin_url, 60)),
                    md_cell(&l.username_value),
                    l.encryption_scheme.as_str(),
                    dec_display,
                    l.times_used,
                    md_cell(&l.insecure_issues.join(", ")),
                );
            }
            let _ = writeln!(out);
        }

        // Cookies summary
        if !p.cookies.is_empty() {
            let _ = writeln!(out, "### Cookies ({})", p.cookies.len());
            let _ = writeln!(out);
            let _ = writeln!(
                out,
                "| Host | Name | Scheme | Secure | HttpOnly | SameSite | Last Access |"
            );
            let _ = writeln!(out, "| --- | --- | --- | --- | --- | --- | --- |");
            for c in p.cookies.iter().take(60) {
                let _ = writeln!(
                    out,
                    "| {} | {} | {} | {} | {} | {} | {} |",
                    md_cell(&c.host_key),
                    md_cell(&truncate_str(&c.name, 40)),
                    c.encryption_scheme.as_str(),
                    c.is_secure,
                    c.is_httponly,
                    c.samesite,
                    format_utc_opt(c.last_access_utc, false),
                );
            }
            let _ = writeln!(out);
        }

        // Extensions
        if !p.extensions.is_empty() {
            let _ = writeln!(out, "### Extensions ({})", p.extensions.len());
            let _ = writeln!(out);
            let _ = writeln!(out, "| Name | ID | Version | Enabled | Location | Risk Flags |");
            let _ = writeln!(out, "| --- | --- | --- | --- | --- | --- |");
            for e in &p.extensions {
                let _ = writeln!(
                    out,
                    "| {} | `{}` | {} | {} | {} | {} |",
                    md_cell(&e.name),
                    md_cell(&e.id),
                    md_cell(&e.version),
                    e.enabled,
                    md_cell(&e.location),
                    md_cell(&e.risk_flags.join(", ")),
                );
            }
            let _ = writeln!(out);
        }

        // Sessions
        if !p.sessions.open_tabs.is_empty() || !p.sessions.closed_tabs.is_empty() {
            let _ = writeln!(
                out,
                "### Sessions ({} Open, {} Closed)",
                p.sessions.open_tabs.len(),
                p.sessions.closed_tabs.len()
            );
            let _ = writeln!(out);
            let _ = writeln!(out, "| State | Source | Title | Current URL | Nav Steps |");
            let _ = writeln!(out, "| --- | --- | --- | --- | ---: |");
            for t in p
                .sessions
                .open_tabs
                .iter()
                .chain(p.sessions.closed_tabs.iter())
                .take(80)
            {
                let _ = writeln!(
                    out,
                    "| {} | {} | {} | {} | {} |",
                    if t.is_closed { "Closed" } else { "Open" },
                    md_cell(&t.source_file),
                    md_cell(&truncate_str(&t.current_title, 45)),
                    md_cell(&truncate_str(&t.current_url, 80)),
                    t.navigations.len(),
                );
            }
            let _ = writeln!(out);
        }

        // Site Storage
        if !p.storage.local_storage.is_empty() || !p.storage.session_storage.is_empty() {
            let _ = writeln!(
                out,
                "### Site Storage (Local: {}, Session: {})",
                p.storage.local_storage.len(),
                p.storage.session_storage.len()
            );
            let _ = writeln!(out);
            let _ = writeln!(out, "| Origin | Key | Value Preview |");
            let _ = writeln!(out, "| --- | --- | --- |");
            for kv in p.storage.local_storage.iter().take(60) {
                let _ = writeln!(
                    out,
                    "| {} | {} | {} |",
                    md_cell(&kv.origin),
                    md_cell(&truncate_str(&kv.key, 40)),
                    md_cell(&truncate_str(&kv.value, 80)),
                );
            }
            let _ = writeln!(out);
        }

        // Top Cached Resources
        if !p.cache_entries.is_empty() {
            let _ = writeln!(out, "### Cached Resources (Top 50 of {})", p.cache_entries.len());
            let _ = writeln!(out);
            let _ = writeln!(out, "| Content-Type | Size | Status | Last Accessed | Server | URL |");
            let _ = writeln!(out, "| --- | ---: | --- | --- | --- | --- |");
            for c in p.cache_entries.iter().take(50) {
                let _ = writeln!(
                    out,
                    "| {} | {} | {} | {} | {} | {} |",
                    md_cell(c.content_type.as_deref().unwrap_or("")),
                    format_bytes(c.file_size as u64),
                    md_cell(&c.server_response),
                    format_utc_opt(c.last_accessed, false),
                    md_cell(c.server_name.as_deref().unwrap_or("")),
                    md_cell(&truncate_str(&c.url, 80)),
                );
            }
            let _ = writeln!(out);
        }
    }

    // Diagnostic Warnings
    if !report.warnings.is_empty() {
        let _ = writeln!(out, "## Diagnostic Warnings ({})", report.warnings.len());
        let _ = writeln!(out);
        let _ = writeln!(out, "| Severity | Component | Artifact | Message |");
        let _ = writeln!(out, "| --- | --- | --- | --- |");
        for w in &report.warnings {
            let _ = writeln!(
                out,
                "| {:?} | {} | {} | {} |",
                w.severity,
                md_cell(&w.component),
                md_cell(&w.artifact_path),
                md_cell(&w.message),
            );
        }
        let _ = writeln!(out);
    }

    out
}

pub fn format_bytes(bytes: u64) -> String {
    const KB: f64 = 1024.0;
    const MB: f64 = KB * 1024.0;
    const GB: f64 = MB * 1024.0;
    let b = bytes as f64;
    if b >= GB {
        format!("{:.2} GiB", b / GB)
    } else if b >= MB {
        format!("{:.2} MiB", b / MB)
    } else if b >= KB {
        format!("{:.1} KiB", b / KB)
    } else {
        format!("{bytes} B")
    }
}

fn md_cell(s: &str) -> String {
    s.replace('|', "\\|").replace(['\r', '\n'], " ")
}

fn truncate_str(s: &str, max_chars: usize) -> String {
    let mut chars = s.chars();
    let prefix: String = chars.by_ref().take(max_chars).collect();
    if chars.next().is_some() {
        format!("{prefix}...")
    } else {
        prefix
    }
}
