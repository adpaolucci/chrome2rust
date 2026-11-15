use crate::error::DiagnosticWarning;
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PreferencesSummary {
    pub profile_name: Option<String>,
    pub account_emails: Vec<String>,
    pub homepage: Option<String>,
    pub homepage_is_newtabpage: Option<bool>,
    pub restore_on_startup: Option<i64>,
    pub startup_urls: Vec<String>,
    pub download_default_dir: Option<String>,
    pub safebrowsing_enabled: Option<bool>,
    pub default_search_name: Option<String>,
    pub default_search_url: Option<String>,
    pub proxy_mode: Option<String>,
    pub accept_languages: Option<String>,
    pub developer_mode: Option<bool>,
    pub top_level_keys: Vec<String>,
}

pub fn parse_preferences(
    profile_dir: &Path,
    warnings: &mut Vec<DiagnosticWarning>,
) -> (PreferencesSummary, Option<serde_json::Value>, Option<serde_json::Value>) {
    let mut summary = PreferencesSummary::default();

    let prefs_val = read_json_opt(&profile_dir.join("Preferences"), "preferences", warnings);
    let sec_val = read_json_opt(
        &profile_dir.join("Secure Preferences"),
        "secure_preferences",
        warnings,
    );

    if let Some(ref val) = prefs_val {
        if let Some(obj) = val.as_object() {
            summary.top_level_keys = obj.keys().cloned().collect();
            summary.top_level_keys.sort();
        }
        summary.profile_name = val
            .pointer("/profile/name")
            .and_then(|v| v.as_str())
            .map(str::to_string);
        if let Some(accts) = val.pointer("/account_info").and_then(|v| v.as_array()) {
            for a in accts {
                if let Some(email) = a.get("email").and_then(|v| v.as_str())
                    && !email.is_empty()
                {
                    summary.account_emails.push(email.to_string());
                }
            }
        }
        summary.homepage = val
            .pointer("/homepage")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(str::to_string);
        summary.homepage_is_newtabpage = val
            .pointer("/homepage_is_newtabpage")
            .and_then(|v| v.as_bool());
        summary.restore_on_startup = val
            .pointer("/session/restore_on_startup")
            .and_then(|v| v.as_i64());
        if let Some(urls) = val
            .pointer("/session/startup_urls")
            .and_then(|v| v.as_array())
        {
            for u in urls {
                if let Some(s) = u.as_str() {
                    summary.startup_urls.push(s.to_string());
                }
            }
        }
        summary.download_default_dir = val
            .pointer("/download/default_directory")
            .and_then(|v| v.as_str())
            .map(str::to_string);
        summary.safebrowsing_enabled = val
            .pointer("/safebrowsing/enabled")
            .and_then(|v| v.as_bool());
        summary.default_search_name = val
            .pointer("/default_search_provider_data/template_url_data/short_name")
            .and_then(|v| v.as_str())
            .map(str::to_string);
        summary.default_search_url = val
            .pointer("/default_search_provider_data/template_url_data/url")
            .and_then(|v| v.as_str())
            .map(str::to_string);
        summary.proxy_mode = val
            .pointer("/proxy/mode")
            .and_then(|v| v.as_str())
            .map(str::to_string);
        summary.accept_languages = val
            .pointer("/intl/accept_languages")
            .and_then(|v| v.as_str())
            .map(str::to_string);
        summary.developer_mode = val
            .pointer("/extensions/ui/developer_mode")
            .and_then(|v| v.as_bool());
    }

    (summary, prefs_val, sec_val)
}

fn read_json_opt(
    path: &Path,
    component: &str,
    warnings: &mut Vec<DiagnosticWarning>,
) -> Option<serde_json::Value> {
    if !path.is_file() {
        return None;
    }
    match std::fs::read_to_string(path) {
        Ok(raw) => match serde_json::from_str::<serde_json::Value>(&raw) {
            Ok(v) => Some(v),
            Err(e) => {
                warnings.push(DiagnosticWarning::warn(
                    component,
                    path,
                    format!("Failed to parse JSON: {e}"),
                ));
                None
            }
        },
        Err(e) => {
            warnings.push(DiagnosticWarning::warn(
                component,
                path,
                format!("Failed to read file: {e}"),
            ));
            None
        }
    }
}
