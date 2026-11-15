use super::ProfileAnalysis;
use chrome2rust_core::crypto::EncryptionScheme;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FindingSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl FindingSeverity {
    pub fn as_str(&self) -> &'static str {
        match self {
            FindingSeverity::Info => "info",
            FindingSeverity::Low => "low",
            FindingSeverity::Medium => "medium",
            FindingSeverity::High => "high",
            FindingSeverity::Critical => "critical",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForensicFinding {
    pub severity: FindingSeverity,
    pub profile: String,
    pub category: String,
    pub title: String,
    pub summary: String,
    pub evidence: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DomainStat {
    pub domain: String,
    pub history_visits: usize,
    pub cache_items: usize,
    pub cache_bytes: u64,
    pub cookies: usize,
}

pub fn generate_findings_and_stats(profiles: &[ProfileAnalysis]) -> (Vec<ForensicFinding>, Vec<DomainStat>) {
    let mut findings = Vec::new();
    let mut domain_map: HashMap<String, DomainStat> = HashMap::new();

    for p in profiles {
        let pname = &p.profile_name;

        // 1. Compromised / insecure credentials
        let insecure_logins: Vec<String> = p
            .logins
            .iter()
            .filter(|l| !l.insecure_issues.is_empty())
            .map(|l| {
                format!(
                    "{} (user: {}, issues: {})",
                    l.origin_url,
                    l.username_value,
                    l.insecure_issues.join(", ")
                )
            })
            .collect();
        if !insecure_logins.is_empty() {
            findings.push(ForensicFinding {
                severity: FindingSeverity::Critical,
                profile: pname.clone(),
                category: "Credentials".into(),
                title: format!("{} Compromised / Insecure Saved Credentials", insecure_logins.len()),
                summary: "Chrome recorded entries in the insecure_credentials table (leaked, phished, weak, or reused passwords).".into(),
                evidence: insecure_logins.into_iter().take(25).collect(),
            });
        }

        // 2. Dangerous or interrupted downloads
        let dangerous_dl: Vec<String> = p
            .history
            .downloads
            .iter()
            .filter(|d| d.danger_type != "NOT_DANGEROUS" && d.danger_type != "DEEP_SCANNED_SAFE")
            .map(|d| {
                format!(
                    "{} -> {} [{} / {}]",
                    d.url_chain.last().map(String::as_str).unwrap_or(""),
                    d.target_path,
                    d.danger_type,
                    d.state
                )
            })
            .collect();
        if !dangerous_dl.is_empty() {
            findings.push(ForensicFinding {
                severity: FindingSeverity::High,
                profile: pname.clone(),
                category: "Downloads".into(),
                title: format!("{} Flagged / Dangerous Downloads", dangerous_dl.len()),
                summary: "Downloads flagged by Safe Browsing or marked as uncommon/dangerous content.".into(),
                evidence: dangerous_dl.into_iter().take(25).collect(),
            });
        }

        // 3. Risky or sideloaded extensions
        let risky_exts: Vec<String> = p
            .extensions
            .iter()
            .filter(|e| !e.risk_flags.is_empty())
            .map(|e| {
                format!(
                    "{} ({}) v{} [{}]: {}",
                    e.name,
                    e.id,
                    e.version,
                    e.location,
                    e.risk_flags.join(", ")
                )
            })
            .collect();
        if !risky_exts.is_empty() {
            let has_sideload = p
                .extensions
                .iter()
                .any(|e| e.location == "UNPACKED" || e.location == "COMMAND_LINE");
            findings.push(ForensicFinding {
                severity: if has_sideload {
                    FindingSeverity::High
                } else {
                    FindingSeverity::Medium
                },
                profile: pname.clone(),
                category: "Extensions".into(),
                title: format!("{} Extensions with Elevated Permissions or Non-Webstore Origin", risky_exts.len()),
                summary: "Extensions loaded unpacked/sideloaded or requesting broad/sensitive permissions (debugger, cookies, webRequest, nativeMessaging, <all_urls>).".into(),
                evidence: risky_exts.into_iter().take(25).collect(),
            });
        }

        // 4. History deletion indicators (SQLite sequence gap)
        let di = &p.history.deletion_indicators;
        if di.urls_estimated_deleted > 0 || di.visits_estimated_deleted > 0 {
            findings.push(ForensicFinding {
                severity: FindingSeverity::Medium,
                profile: pname.clone(),
                category: "History Integrity".into(),
                title: "History ID Sequence Gap Detected".into(),
                summary: format!(
                    "SQLite sequence counters exceed surviving row counts (urls: ~{} missing IDs; visits: ~{} missing IDs; {} hidden URLs).",
                    di.urls_estimated_deleted, di.visits_estimated_deleted, di.hidden_urls_count
                ),
                evidence: vec![
                    format!("urls count={}, min_id={}, max_id={}, seq={}", di.urls_row_count, di.urls_min_id, di.urls_max_id, di.urls_sqlite_seq),
                    format!("visits count={}, max_id={}, seq={}", di.visits_row_count, di.visits_max_id, di.visits_sqlite_seq),
                ],
            });
        }

        // 5. Cache vs History discrepancy (HTML documents in Cache missing from History)
        let history_urls: HashSet<&str> = p.history.urls.iter().map(|u| u.url.as_str()).collect();
        let cache_html_missing: Vec<String> = p
            .cache_entries
            .iter()
            .filter(|c| {
                c.content_type.as_deref() == Some("text/html")
                    && !c.url.is_empty()
                    && !history_urls.contains(c.url.as_str())
            })
            .map(|c| {
                format!(
                    "{} (size: {} B, last accessed: {:?})",
                    c.url, c.file_size, c.last_accessed
                )
            })
            .collect();
        if !cache_html_missing.is_empty() {
            findings.push(ForensicFinding {
                severity: FindingSeverity::Medium,
                profile: pname.clone(),
                category: "Cross-Artifact".into(),
                title: format!("{} Cached HTML Pages Absent from History", cache_html_missing.len()),
                summary: "HTML documents present in HTTP cache that do not appear in the History urls table (may indicate selective history deletion, iframe embeds, or redirects).".into(),
                evidence: cache_html_missing.into_iter().take(20).collect(),
            });
        }

        // 6. Plaintext / weak cookies
        let plaintext_cookies: Vec<String> = p
            .cookies
            .iter()
            .filter(|c| c.encryption_scheme == EncryptionScheme::Plaintext)
            .map(|c| format!("{} | {} (secure={})", c.host_key, c.name, c.is_secure))
            .collect();
        if !plaintext_cookies.is_empty() {
            findings.push(ForensicFinding {
                severity: FindingSeverity::Low,
                profile: pname.clone(),
                category: "Cookies".into(),
                title: format!("{} Unencrypted Plaintext Cookies", plaintext_cookies.len()),
                summary: "Cookies stored without OS encryption wrapper (legacy or unencrypted profile state).".into(),
                evidence: plaintext_cookies.into_iter().take(20).collect(),
            });
        }

        // 7. Encrypted sessions / v20 App-Bound encryption presence
        if p.sessions.encrypted_sessions_present {
            findings.push(ForensicFinding {
                severity: FindingSeverity::Info,
                profile: pname.clone(),
                category: "Sessions".into(),
                title: "Sessions_Encrypted Directory Present".into(),
                summary:
                    "Chrome stored encrypted session artifacts in Sessions_Encrypted alongside SNSS session files."
                        .into(),
                evidence: vec![format!(
                    "Open tabs decoded from SNSS: {}, Closed tabs: {}",
                    p.sessions.open_tabs.len(),
                    p.sessions.closed_tabs.len()
                )],
            });
        }

        // 8. Deleted blockfile entries
        let deleted_cache: Vec<String> = p
            .cache_entries
            .iter()
            .filter(|c| c.deleted_file)
            .map(|c| format!("{} ({})", c.url, c.cache_name))
            .collect();
        if !deleted_cache.is_empty() {
            findings.push(ForensicFinding {
                severity: FindingSeverity::Info,
                profile: pname.clone(),
                category: "Cache".into(),
                title: format!("{} Deleted Blockfile Separate Cache Payloads", deleted_cache.len()),
                summary: "Blockfile index references external f_xxxxxx payload files no longer present on disk.".into(),
                evidence: deleted_cache.into_iter().take(20).collect(),
            });
        }

        // Aggregate domain stats
        for u in &p.history.urls {
            if let Some(host) = extract_host(&u.url) {
                let st = domain_map.entry(host.clone()).or_insert_with(|| DomainStat {
                    domain: host,
                    ..Default::default()
                });
                st.history_visits += u.visit_count.max(1) as usize;
            }
        }
        for c in &p.cache_entries {
            if let Some(host) = extract_host(&c.url) {
                let st = domain_map.entry(host.clone()).or_insert_with(|| DomainStat {
                    domain: host,
                    ..Default::default()
                });
                st.cache_items += 1;
                st.cache_bytes += c.file_size as u64;
            }
        }
        for ck in &p.cookies {
            let host = ck.host_key.trim_start_matches('.').to_ascii_lowercase();
            if !host.is_empty() {
                let st = domain_map.entry(host.clone()).or_insert_with(|| DomainStat {
                    domain: host,
                    ..Default::default()
                });
                st.cookies += 1;
            }
        }
    }

    findings.sort_by_key(|f| std::cmp::Reverse(f.severity));
    let mut domains: Vec<DomainStat> = domain_map.into_values().collect();
    domains.sort_by(|a, b| {
        (b.history_visits + b.cache_items)
            .cmp(&(a.history_visits + a.cache_items))
            .then_with(|| b.cache_bytes.cmp(&a.cache_bytes))
    });

    (findings, domains)
}

fn extract_host(raw_url: &str) -> Option<String> {
    url::Url::parse(raw_url)
        .ok()
        .and_then(|u| u.host_str().map(|h| h.to_ascii_lowercase()))
}
