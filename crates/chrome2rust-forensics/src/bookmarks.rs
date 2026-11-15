use chrome2rust_core::error::DiagnosticWarning;
use chrome2rust_core::time::chrome_str_us_to_datetime;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BookmarkRecord {
    pub folder_path: String,
    pub name: String,
    pub url: String,
    pub guid: String,
    pub date_added: Option<DateTime<Utc>>,
    pub date_last_used: Option<DateTime<Utc>>,
}

pub fn parse_bookmarks(profile_dir: &Path, warnings: &mut Vec<DiagnosticWarning>) -> Vec<BookmarkRecord> {
    let mut out = Vec::new();
    for file_name in ["Bookmarks", "AccountBookmarks"] {
        let path = profile_dir.join(file_name);
        if !path.is_file() {
            continue;
        }
        let raw = match std::fs::read_to_string(&path) {
            Ok(s) => s,
            Err(e) => {
                warnings.push(DiagnosticWarning::warn(
                    "bookmarks",
                    &path,
                    format!("Failed to read {file_name}: {e}"),
                ));
                continue;
            }
        };
        let val: serde_json::Value = match serde_json::from_str(&raw) {
            Ok(v) => v,
            Err(e) => {
                warnings.push(DiagnosticWarning::warn(
                    "bookmarks",
                    &path,
                    format!("Invalid {file_name} JSON: {e}"),
                ));
                continue;
            }
        };

        if let Some(roots) = val.get("roots").and_then(|v| v.as_object()) {
            for (root_key, root_node) in roots {
                let root_name = root_node.get("name").and_then(|v| v.as_str()).unwrap_or(root_key);
                collect_bookmarks(root_node, root_name, &mut out);
            }
        }
    }
    out
}

fn collect_bookmarks(node: &serde_json::Value, folder: &str, out: &mut Vec<BookmarkRecord>) {
    let node_type = node.get("type").and_then(|v| v.as_str()).unwrap_or("");
    if node_type == "url" {
        let url = node.get("url").and_then(|v| v.as_str()).unwrap_or("").to_string();
        if !url.is_empty() {
            out.push(BookmarkRecord {
                folder_path: folder.to_string(),
                name: node.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                url,
                guid: node.get("guid").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                date_added: node
                    .get("date_added")
                    .and_then(|v| v.as_str())
                    .and_then(chrome_str_us_to_datetime),
                date_last_used: node
                    .get("date_last_used")
                    .and_then(|v| v.as_str())
                    .and_then(chrome_str_us_to_datetime),
            });
        }
    } else if let Some(children) = node.get("children").and_then(|v| v.as_array()) {
        for child in children {
            let child_type = child.get("type").and_then(|v| v.as_str()).unwrap_or("");
            if child_type == "folder" {
                let cname = child.get("name").and_then(|v| v.as_str()).unwrap_or("Folder");
                let sub_path = format!("{folder} / {cname}");
                collect_bookmarks(child, &sub_path, out);
            } else {
                collect_bookmarks(child, folder, out);
            }
        }
    }
}
