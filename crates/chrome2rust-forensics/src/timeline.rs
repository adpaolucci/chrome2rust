use super::ProfileAnalysis;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineEvent {
    pub timestamp: DateTime<Utc>,
    pub profile: String,
    pub category: String,
    pub event_type: String,
    pub target: String,
    pub details: String,
    pub source_artifact: String,
}

pub fn build_unified_timeline(profiles: &[ProfileAnalysis]) -> Vec<TimelineEvent> {
    let mut events = Vec::new();

    for p in profiles {
        let pname = &p.profile_name;

        for v in &p.history.visits {
            if let Some(ts) = v.visit_time {
                events.push(TimelineEvent {
                    timestamp: ts,
                    profile: pname.clone(),
                    category: "History".into(),
                    event_type: format!("Visit ({})", v.transition_core),
                    target: v.url.clone(),
                    details: v.title.clone(),
                    source_artifact: "History".into(),
                });
            }
        }

        for d in &p.history.downloads {
            let url = d.url_chain.last().cloned().unwrap_or_default();
            if let Some(ts) = d.start_time {
                events.push(TimelineEvent {
                    timestamp: ts,
                    profile: pname.clone(),
                    category: "Download".into(),
                    event_type: format!("Download {} ({})", d.state, d.danger_type),
                    target: url,
                    details: format!("{} ({} bytes)", d.target_path, d.total_bytes),
                    source_artifact: "History/downloads".into(),
                });
            }
        }

        for c in &p.cache_entries {
            if let Some(ts) = c.last_accessed.or(c.record_created_time) {
                events.push(TimelineEvent {
                    timestamp: ts,
                    profile: pname.clone(),
                    category: "Cache".into(),
                    event_type: format!("Cached {}", c.content_type.as_deref().unwrap_or("resource")),
                    target: c.url.clone(),
                    details: format!("{} | {} bytes | {}", c.server_response, c.file_size, c.cache_name),
                    source_artifact: c.cache_name.clone(),
                });
            }
        }

        for ck in &p.cookies {
            if let Some(ts) = ck.creation_utc {
                events.push(TimelineEvent {
                    timestamp: ts,
                    profile: pname.clone(),
                    category: "Cookie".into(),
                    event_type: "Cookie Created".into(),
                    target: format!("{}{}", ck.host_key, ck.path),
                    details: format!(
                        "{} (scheme: {}, secure: {}, httponly: {})",
                        ck.name,
                        ck.encryption_scheme.as_str(),
                        ck.is_secure,
                        ck.is_httponly
                    ),
                    source_artifact: "Cookies".into(),
                });
            }
        }

        for lg in &p.logins {
            if let Some(ts) = lg.date_last_used.or(lg.date_created) {
                events.push(TimelineEvent {
                    timestamp: ts,
                    profile: pname.clone(),
                    category: "Credential".into(),
                    event_type: if lg.date_last_used.is_some() {
                        "Login Used".into()
                    } else {
                        "Login Saved".into()
                    },
                    target: lg.origin_url.clone(),
                    details: format!("user: {} (uses: {})", lg.username_value, lg.times_used),
                    source_artifact: lg.source_db.clone(),
                });
            }
        }

        for bm in &p.bookmarks {
            if let Some(ts) = bm.date_added {
                events.push(TimelineEvent {
                    timestamp: ts,
                    profile: pname.clone(),
                    category: "Bookmark".into(),
                    event_type: "Bookmark Added".into(),
                    target: bm.url.clone(),
                    details: format!("{} [{}]", bm.name, bm.folder_path),
                    source_artifact: "Bookmarks".into(),
                });
            }
        }

        for ext in &p.extensions {
            if let Some(ts) = ext.install_time {
                events.push(TimelineEvent {
                    timestamp: ts,
                    profile: pname.clone(),
                    category: "Extension".into(),
                    event_type: "Extension Installed".into(),
                    target: ext.id.clone(),
                    details: format!("{} v{} ({})", ext.name, ext.version, ext.location),
                    source_artifact: "Preferences".into(),
                });
            }
        }

        for tab in p.sessions.open_tabs.iter().chain(p.sessions.closed_tabs.iter()) {
            if let Some(ts) = tab.timestamp {
                events.push(TimelineEvent {
                    timestamp: ts,
                    profile: pname.clone(),
                    category: "Session".into(),
                    event_type: if tab.is_closed {
                        "Tab Closed".into()
                    } else {
                        "Tab Active".into()
                    },
                    target: tab.current_url.clone(),
                    details: tab.current_title.clone(),
                    source_artifact: tab.source_file.clone(),
                });
            }
        }
    }

    events.sort_by_key(|b| std::cmp::Reverse(b.timestamp));
    events
}
