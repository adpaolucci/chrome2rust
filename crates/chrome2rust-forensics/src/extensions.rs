use chrome2rust_core::error::DiagnosticWarning;
use chrome2rust_core::time::chrome_str_us_to_datetime;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtensionRecord {
    pub id: String,
    pub name: String,
    pub version: String,
    pub description: String,
    pub enabled: bool,
    pub location: String,
    pub from_webstore: bool,
    pub install_time: Option<DateTime<Utc>>,
    pub manifest_version: Option<i64>,
    pub update_url: Option<String>,
    pub permissions: Vec<String>,
    pub host_permissions: Vec<String>,
    pub risk_flags: Vec<String>,
    pub disk_path: Option<String>,
}

fn decode_ext_location(loc: i64) -> &'static str {
    match loc {
        0 => "INVALID",
        1 => "INTERNAL",
        2 => "EXTERNAL_PREF",
        3 => "EXTERNAL_REGISTRY",
        4 => "UNPACKED",
        5 => "COMPONENT",
        6 => "EXTERNAL_PREF_DOWNLOAD",
        7 => "EXTERNAL_POLICY_DOWNLOAD",
        8 => "COMMAND_LINE",
        9 => "EXTERNAL_POLICY",
        10 => "EXTERNAL_COMPONENT",
        _ => "UNKNOWN",
    }
}

pub fn parse_extensions(
    profile_dir: &Path,
    prefs: Option<&serde_json::Value>,
    secure_prefs: Option<&serde_json::Value>,
    warnings: &mut Vec<DiagnosticWarning>,
) -> Vec<ExtensionRecord> {
    let mut by_id: HashMap<String, ExtensionRecord> = HashMap::new();

    // 1. Extract settings from Preferences and Secure Preferences
    for root in [prefs, secure_prefs].into_iter().flatten() {
        if let Some(settings) = root.pointer("/extensions/settings").and_then(|v| v.as_object()) {
            for (ext_id, obj) in settings {
                let manifest = obj.get("manifest");
                let name = manifest
                    .and_then(|m| m.get("name"))
                    .and_then(|v| v.as_str())
                    .unwrap_or(ext_id)
                    .to_string();
                let version = manifest
                    .and_then(|m| m.get("version"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let description = manifest
                    .and_then(|m| m.get("description"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let manifest_version = manifest
                    .and_then(|m| m.get("manifest_version"))
                    .and_then(|v| v.as_i64());
                let update_url = manifest
                    .and_then(|m| m.get("update_url"))
                    .and_then(|v| v.as_str())
                    .map(str::to_string);

                let state = obj.get("state").and_then(|v| v.as_i64()).unwrap_or(1);
                let location_code = obj.get("location").and_then(|v| v.as_i64()).unwrap_or(0);
                let location = decode_ext_location(location_code).to_string();
                let from_webstore = obj.get("from_webstore").and_then(|v| v.as_bool()).unwrap_or(false);

                let install_time = obj
                    .get("install_time")
                    .or_else(|| obj.get("first_install_time"))
                    .and_then(|v| v.as_str())
                    .and_then(chrome_str_us_to_datetime);

                let mut permissions = Vec::new();
                let mut host_permissions = Vec::new();
                if let Some(m) = manifest {
                    collect_str_array(m.get("permissions"), &mut permissions);
                    collect_str_array(m.get("host_permissions"), &mut host_permissions);
                }
                if let Some(ap) = obj.pointer("/active_permissions/api") {
                    collect_str_array(Some(ap), &mut permissions);
                }
                if let Some(ah) = obj.pointer("/active_permissions/explicit_host") {
                    collect_str_array(Some(ah), &mut host_permissions);
                }
                permissions.sort();
                permissions.dedup();
                host_permissions.sort();
                host_permissions.dedup();

                let risk_flags = compute_extension_risks(&location, from_webstore, &permissions, &host_permissions);

                let disk_path = obj.get("path").and_then(|v| v.as_str()).map(str::to_string);

                by_id.insert(
                    ext_id.clone(),
                    ExtensionRecord {
                        id: ext_id.clone(),
                        name,
                        version,
                        description,
                        enabled: state == 1,
                        location,
                        from_webstore,
                        install_time,
                        manifest_version,
                        update_url,
                        permissions,
                        host_permissions,
                        risk_flags,
                        disk_path,
                    },
                );
            }
        }
    }

    // 2. Scan Extensions/<ext_id>/<version>/manifest.json directly on disk
    let ext_dir = profile_dir.join("Extensions");
    if ext_dir.is_dir()
        && let Ok(ext_folders) = std::fs::read_dir(&ext_dir)
    {
        for ext_entry in ext_folders.flatten() {
            if !ext_entry.path().is_dir() {
                continue;
            }
            let ext_id = ext_entry.file_name().to_string_lossy().to_string();
            if let Ok(ver_folders) = std::fs::read_dir(ext_entry.path()) {
                for ver_entry in ver_folders.flatten() {
                    let manifest_path = ver_entry.path().join("manifest.json");
                    if !manifest_path.is_file() {
                        continue;
                    }
                    let raw = match std::fs::read_to_string(&manifest_path) {
                        Ok(s) => s,
                        Err(e) => {
                            warnings.push(DiagnosticWarning::warn(
                                "extensions",
                                &manifest_path,
                                format!("Failed reading manifest: {e}"),
                            ));
                            continue;
                        }
                    };
                    if let Ok(m) = serde_json::from_str::<serde_json::Value>(&raw) {
                        let name = m.get("name").and_then(|v| v.as_str()).unwrap_or(&ext_id).to_string();
                        let version = m.get("version").and_then(|v| v.as_str()).unwrap_or("").to_string();
                        let description = m.get("description").and_then(|v| v.as_str()).unwrap_or("").to_string();
                        let manifest_version = m.get("manifest_version").and_then(|v| v.as_i64());
                        let update_url = m.get("update_url").and_then(|v| v.as_str()).map(str::to_string);

                        let mut permissions = Vec::new();
                        let mut host_permissions = Vec::new();
                        collect_str_array(m.get("permissions"), &mut permissions);
                        collect_str_array(m.get("host_permissions"), &mut host_permissions);

                        let entry = by_id.entry(ext_id.clone()).or_insert_with(|| ExtensionRecord {
                            id: ext_id.clone(),
                            name: name.clone(),
                            version: version.clone(),
                            description: description.clone(),
                            enabled: true,
                            location: "ON_DISK".to_string(),
                            from_webstore: false,
                            install_time: None,
                            manifest_version,
                            update_url: update_url.clone(),
                            permissions: Vec::new(),
                            host_permissions: Vec::new(),
                            risk_flags: Vec::new(),
                            disk_path: Some(ver_entry.path().display().to_string()),
                        });

                        if entry.name == entry.id || entry.name.starts_with("__MSG_") {
                            entry.name = name;
                        }
                        if entry.version.is_empty() {
                            entry.version = version;
                        }
                        if entry.description.is_empty() {
                            entry.description = description;
                        }
                        if entry.disk_path.is_none() {
                            entry.disk_path = Some(ver_entry.path().display().to_string());
                        }
                        entry.permissions.extend(permissions);
                        entry.host_permissions.extend(host_permissions);
                        entry.permissions.sort();
                        entry.permissions.dedup();
                        entry.host_permissions.sort();
                        entry.host_permissions.dedup();
                        entry.risk_flags = compute_extension_risks(
                            &entry.location,
                            entry.from_webstore,
                            &entry.permissions,
                            &entry.host_permissions,
                        );
                    }
                }
            }
        }
    }

    let mut list: Vec<ExtensionRecord> = by_id.into_values().collect();
    list.sort_by_key(|a| a.name.to_ascii_lowercase());
    list
}

fn collect_str_array(val: Option<&serde_json::Value>, out: &mut Vec<String>) {
    if let Some(arr) = val.and_then(|v| v.as_array()) {
        for item in arr {
            if let Some(s) = item.as_str() {
                out.push(s.to_string());
            }
        }
    }
}

pub fn compute_extension_risks(
    location: &str,
    from_webstore: bool,
    permissions: &[String],
    host_permissions: &[String],
) -> Vec<String> {
    let mut risks = Vec::new();
    if location == "UNPACKED" || location == "COMMAND_LINE" {
        risks.push(format!("SIDELOADED:{location}"));
    } else if !from_webstore && location != "COMPONENT" && location != "EXTERNAL_COMPONENT" {
        risks.push("NON_WEBSTORE".into());
    }
    for p in permissions {
        match p.as_str() {
            "debugger" => risks.push("PERM:debugger".into()),
            "nativeMessaging" => risks.push("PERM:nativeMessaging".into()),
            "cookies" => risks.push("PERM:cookies".into()),
            "webRequest" | "webRequestBlocking" => risks.push(format!("PERM:{p}")),
            "proxy" => risks.push("PERM:proxy".into()),
            "clipboardRead" => risks.push("PERM:clipboardRead".into()),
            "management" => risks.push("PERM:management".into()),
            "<all_urls>" => risks.push("HOST:<all_urls>".into()),
            _ => {}
        }
    }
    for h in host_permissions {
        if (h.contains("<all_urls>") || h == "*://*/*" || h == "http://*/*" || h == "https://*/*")
            && !risks.iter().any(|r| r == "HOST:BROAD_ACCESS")
        {
            risks.push("HOST:BROAD_ACCESS".into());
        }
    }
    risks
}
