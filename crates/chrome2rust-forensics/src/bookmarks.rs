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
                collect_bookmarks(root_node, root_name, 0, &mut out);
            }
        }
    }
    out
}

const MAX_BOOKMARK_DEPTH: usize = 32;

fn collect_bookmarks(node: &serde_json::Value, folder: &str, depth: usize, out: &mut Vec<BookmarkRecord>) {
    if depth >= MAX_BOOKMARK_DEPTH {
        return;
    }
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
                collect_bookmarks(child, &sub_path, depth + 1, out);
            } else {
                collect_bookmarks(child, folder, depth + 1, out);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn build_nested_bookmarks_json(depth: usize) -> String {
        let mut node = serde_json::json!({
            "type": "url",
            "name": "Deep",
            "url": "https://example.com/"
        });
        for i in 0..depth {
            node = serde_json::json!({
                "type": "folder",
                "name": format!("F{i}"),
                "children": [node]
            });
        }
        serde_json::json!({
            "roots": {
                "bookmark_bar": {
                    "type": "folder",
                    "name": "Bookmark Bar",
                    "children": [
                        {
                            "type": "url",
                            "name": "Shallow",
                            "url": "https://shallow.example.com/"
                        },
                        node
                    ]
                }
            }
        })
        .to_string()
    }

    #[test]
    fn test_deeply_nested_bookmarks_do_not_overflow_stack() {
        let dir = TempDir::new().unwrap();

        // Depth 50 (~104 JSON nesting levels) passes serde_json (limit 128):
        // shallow bookmark is recovered, while 50-deep branch is capped at MAX_BOOKMARK_DEPTH (32)
        std::fs::write(dir.path().join("Bookmarks"), build_nested_bookmarks_json(50)).unwrap();
        let mut warnings = Vec::new();
        let records = parse_bookmarks(dir.path(), &mut warnings);
        assert!(warnings.is_empty(), "warnings: {warnings:?}");
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].name, "Shallow");

        // Depth 250 hits serde_json recursion guard cleanly with diagnostic warning
        std::fs::write(dir.path().join("Bookmarks"), build_nested_bookmarks_json(250)).unwrap();
        let mut warnings2 = Vec::new();
        let records2 = parse_bookmarks(dir.path(), &mut warnings2);
        assert_eq!(warnings2.len(), 1);
        assert!(records2.is_empty());
    }
}
