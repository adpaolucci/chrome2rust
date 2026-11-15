use chrome2rust_core::error::DiagnosticWarning;
use chrome2rust_core::time::unix_f64_to_datetime;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LocalStateInfo {
    pub chrome_version: Option<String>,
    pub os_crypt_encrypted_key_present: bool,
    pub os_crypt_key_prefix: Option<String>,
    pub os_crypt_portal_info: Option<String>,
    pub last_active_profiles: Vec<String>,
    pub profile_summaries: Vec<LocalStateProfileMeta>,
    pub variations_country: Option<String>,
    pub policy_count: usize,
    pub raw_top_keys: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalStateProfileMeta {
    pub dir_name: String,
    pub name: Option<String>,
    pub user_name: Option<String>,
    pub gaia_name: Option<String>,
    pub gaia_id: Option<String>,
    pub hosted_domain: Option<String>,
    pub active_time: Option<DateTime<Utc>>,
    pub is_ephemeral: bool,
    pub is_consented_primary_account: bool,
    pub enterprise_label: Option<String>,
}

pub fn parse_local_state(user_data_dir: &Path, warnings: &mut Vec<DiagnosticWarning>) -> LocalStateInfo {
    let mut info = LocalStateInfo::default();

    let last_ver_path = user_data_dir.join("Last Version");
    if let Ok(ver) = std::fs::read_to_string(&last_ver_path) {
        let trimmed = ver.trim().to_string();
        if !trimmed.is_empty() {
            info.chrome_version = Some(trimmed);
        }
    }

    let ls_path = user_data_dir.join("Local State");
    if !ls_path.is_file() {
        return info;
    }

    let raw = match std::fs::read_to_string(&ls_path) {
        Ok(s) => s,
        Err(e) => {
            warnings.push(DiagnosticWarning::warn(
                "local_state",
                &ls_path,
                format!("Could not read Local State: {e}"),
            ));
            return info;
        }
    };

    let val: serde_json::Value = match serde_json::from_str(&raw) {
        Ok(v) => v,
        Err(e) => {
            warnings.push(DiagnosticWarning::warn(
                "local_state",
                &ls_path,
                format!("Invalid Local State JSON: {e}"),
            ));
            return info;
        }
    };

    if let Some(obj) = val.as_object() {
        info.raw_top_keys = obj.keys().cloned().collect();
        info.raw_top_keys.sort();
    }

    if let Some(os_crypt) = val.get("os_crypt") {
        if let Some(enc_key) = os_crypt.get("encrypted_key").and_then(|v| v.as_str()) {
            info.os_crypt_encrypted_key_present = !enc_key.is_empty();
            info.os_crypt_key_prefix = Some(enc_key.chars().take(12).collect());
        }
        if let Some(app_bound) = os_crypt.get("app_bound_encrypted_key").and_then(|v| v.as_str()) {
            info.os_crypt_encrypted_key_present = true;
            info.os_crypt_key_prefix = Some(format!("app_bound:{}", app_bound.chars().take(12).collect::<String>()));
        }
        if let Some(portal) = os_crypt.get("portal") {
            info.os_crypt_portal_info = Some(portal.to_string());
        }
    }

    if let Some(vc) = val.get("variations_country").and_then(|v| v.as_str()) {
        info.variations_country = Some(vc.to_string());
    }

    if let Some(policy) = val.get("policy").and_then(|v| v.as_object()) {
        info.policy_count = policy.len();
    }

    if let Some(profile) = val.get("profile") {
        if let Some(arr) = profile.get("last_active_profiles").and_then(|v| v.as_array()) {
            for item in arr {
                if let Some(s) = item.as_str() {
                    info.last_active_profiles.push(s.to_string());
                }
            }
        }
        if let Some(ic) = profile.get("info_cache").and_then(|v| v.as_object()) {
            for (dir_name, meta) in ic {
                let active_time = meta
                    .get("active_time")
                    .and_then(|v| v.as_f64())
                    .and_then(unix_f64_to_datetime);
                info.profile_summaries.push(LocalStateProfileMeta {
                    dir_name: dir_name.clone(),
                    name: opt_non_empty(meta.get("name")),
                    user_name: opt_non_empty(meta.get("user_name")),
                    gaia_name: opt_non_empty(meta.get("gaia_name")),
                    gaia_id: opt_non_empty(meta.get("gaia_id")),
                    hosted_domain: opt_non_empty(meta.get("hosted_domain")),
                    active_time,
                    is_ephemeral: meta.get("is_ephemeral").and_then(|v| v.as_bool()).unwrap_or(false),
                    is_consented_primary_account: meta
                        .get("is_consented_primary_account")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false),
                    enterprise_label: opt_non_empty(meta.get("enterprise_label")),
                });
            }
            info.profile_summaries.sort_by(|a, b| a.dir_name.cmp(&b.dir_name));
        }
    }

    info
}

fn opt_non_empty(v: Option<&serde_json::Value>) -> Option<String> {
    v.and_then(|x| x.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}
