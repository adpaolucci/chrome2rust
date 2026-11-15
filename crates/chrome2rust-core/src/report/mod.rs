pub mod html;
pub mod json;
pub mod markdown;

use crate::error::ChromeError;
use crate::forensics::UserDataReport;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ReportFormat {
    Html,
    Json,
    Markdown,
    All,
}

impl ReportFormat {
    pub fn from_name(s: &str) -> Result<Self, String> {
        match s.trim().to_ascii_lowercase().as_str() {
            "html" | "htm" => Ok(Self::Html),
            "json" => Ok(Self::Json),
            "md" | "markdown" => Ok(Self::Markdown),
            "all" | "bundle" => Ok(Self::All),
            other => Err(format!(
                "Unsupported report format '{other}'. Expected html, json, markdown, or all"
            )),
        }
    }
}

pub fn render_single_report(
    report: &UserDataReport,
    format: ReportFormat,
) -> Result<String, ChromeError> {
    match format {
        ReportFormat::Html => html::render_html_report(report),
        ReportFormat::Json => json::render_json_report(report),
        ReportFormat::Markdown => Ok(markdown::render_markdown_report(report)),
        ReportFormat::All => Err(ChromeError::Export(
            "ReportFormat::All requires writing a report bundle to disk".into(),
        )),
    }
}

/// Writes the requested forensic report format(s) to `output`, returning the list of generated file paths.
///
/// - If `format` is `Html`, `Json`, or `Markdown` and `output` is a directory, writes
///   `forensic_report.<ext>` inside that directory.
/// - If `format` is `All`:
///   - If `output` is an existing directory or has no extension, treats `output` as an output directory
///     and creates `forensic_report.{html,json,md}` inside it.
///   - If `output` has a file extension (e.g. `case1.html`), writes sibling files
///     `case1.html`, `case1.json`, `case1.md` in its parent directory.
pub fn write_report(
    report: &UserDataReport,
    output: &Path,
    format: ReportFormat,
) -> Result<Vec<PathBuf>, ChromeError> {
    let mut written = Vec::new();

    match format {
        ReportFormat::All => {
            let (dir, stem) = if output.is_dir() || output.extension().is_none() {
                (output.to_path_buf(), "forensic_report".to_string())
            } else {
                let parent = output
                    .parent()
                    .filter(|p| !p.as_os_str().is_empty())
                    .unwrap_or_else(|| Path::new("."))
                    .to_path_buf();
                let stem = output
                    .file_stem()
                    .map(|s| s.to_string_lossy().to_string())
                    .filter(|s| !s.is_empty())
                    .unwrap_or_else(|| "forensic_report".to_string());
                (parent, stem)
            };

            std::fs::create_dir_all(&dir).map_err(|e| ChromeError::Io {
                path: dir.display().to_string(),
                source: e,
            })?;

            let html_path = dir.join(format!("{stem}.html"));
            let json_path = dir.join(format!("{stem}.json"));
            let md_path = dir.join(format!("{stem}.md"));

            write_string_file(&html_path, &html::render_html_report(report)?)?;
            written.push(html_path);
            write_string_file(&json_path, &json::render_json_report(report)?)?;
            written.push(json_path);
            write_string_file(&md_path, &markdown::render_markdown_report(report))?;
            written.push(md_path);
        }
        single => {
            let default_name = match single {
                ReportFormat::Html => "forensic_report.html",
                ReportFormat::Json => "forensic_report.json",
                ReportFormat::Markdown => "forensic_report.md",
                ReportFormat::All => unreachable!(),
            };
            let dest = if output.is_dir() {
                output.join(default_name)
            } else {
                output.to_path_buf()
            };
            if let Some(parent) = dest.parent().filter(|p| !p.as_os_str().is_empty()) {
                std::fs::create_dir_all(parent).map_err(|e| ChromeError::Io {
                    path: parent.display().to_string(),
                    source: e,
                })?;
            }
            let content = render_single_report(report, single)?;
            write_string_file(&dest, &content)?;
            written.push(dest);
        }
    }

    Ok(written)
}

fn write_string_file(path: &Path, content: &str) -> Result<(), ChromeError> {
    std::fs::write(path, content).map_err(|e| ChromeError::Io {
        path: path.display().to_string(),
        source: e,
    })
}
