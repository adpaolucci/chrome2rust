use super::CacheEntry;
use crate::error::ChromeError;
use crate::time::format_local_opt;
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExportFormat {
    Text,
    Tab,
    Csv,
    Tabular,
    HtmlHorizontal,
    HtmlVertical,
    Xml,
    Json,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CacheColumn {
    Url,
    ContentType,
    FileSize,
    CompressedSize,
    LastAccessed,
    ServerTime,
    RecordCreatedTime,
    ExpirationTime,
    ServerName,
    ServerResponse,
    ContentEncoding,
    CacheName,
    UrlLength,
    WebSite,
    Frame,
    ServerIp,
    DeletedFile,
    Sha256,
    Backend,
}

impl CacheColumn {
    pub fn header(&self) -> &'static str {
        match self {
            CacheColumn::Url => "URL",
            CacheColumn::ContentType => "Content Type",
            CacheColumn::FileSize => "File Size",
            CacheColumn::CompressedSize => "Compressed Size",
            CacheColumn::LastAccessed => "Last Accessed",
            CacheColumn::ServerTime => "Server Time",
            CacheColumn::RecordCreatedTime => "Record Created Time",
            CacheColumn::ExpirationTime => "Expiration Time",
            CacheColumn::ServerName => "Server Name",
            CacheColumn::ServerResponse => "Server Response",
            CacheColumn::ContentEncoding => "Content Encoding",
            CacheColumn::CacheName => "Cache Name",
            CacheColumn::UrlLength => "URL Length",
            CacheColumn::WebSite => "Web Site",
            CacheColumn::Frame => "Frame",
            CacheColumn::ServerIp => "Server IP Address",
            CacheColumn::DeletedFile => "Deleted File",
            CacheColumn::Sha256 => "SHA256",
            CacheColumn::Backend => "Backend",
        }
    }

    pub fn default_columns() -> Vec<CacheColumn> {
        vec![
            CacheColumn::Url,
            CacheColumn::ContentType,
            CacheColumn::FileSize,
            CacheColumn::LastAccessed,
            CacheColumn::ServerTime,
            CacheColumn::RecordCreatedTime,
            CacheColumn::ExpirationTime,
            CacheColumn::ServerName,
            CacheColumn::ServerResponse,
            CacheColumn::ContentEncoding,
            CacheColumn::CacheName,
            CacheColumn::UrlLength,
            CacheColumn::WebSite,
            CacheColumn::Frame,
            CacheColumn::ServerIp,
            CacheColumn::DeletedFile,
        ]
    }

    pub fn from_name(name: &str) -> Option<Self> {
        match name
            .trim()
            .to_ascii_lowercase()
            .replace([' ', '_', '-'], "")
            .as_str()
        {
            "url" => Some(Self::Url),
            "contenttype" => Some(Self::ContentType),
            "filesize" | "size" => Some(Self::FileSize),
            "compressedsize" => Some(Self::CompressedSize),
            "lastaccessed" => Some(Self::LastAccessed),
            "servertime" => Some(Self::ServerTime),
            "recordcreatedtime" | "createdtime" => Some(Self::RecordCreatedTime),
            "expirationtime" | "expires" => Some(Self::ExpirationTime),
            "servername" => Some(Self::ServerName),
            "serverresponse" => Some(Self::ServerResponse),
            "contentencoding" => Some(Self::ContentEncoding),
            "cachename" => Some(Self::CacheName),
            "urllength" => Some(Self::UrlLength),
            "website" => Some(Self::WebSite),
            "frame" => Some(Self::Frame),
            "serveripaddress" | "serverip" => Some(Self::ServerIp),
            "deletedfile" | "deleted" => Some(Self::DeletedFile),
            "sha256" => Some(Self::Sha256),
            "backend" => Some(Self::Backend),
            _ => None,
        }
    }

    pub fn value(&self, entry: &CacheEntry, show_millis: bool) -> String {
        match self {
            CacheColumn::Url => entry.url.clone(),
            CacheColumn::ContentType => entry.content_type.clone().unwrap_or_default(),
            CacheColumn::FileSize => entry.file_size.to_string(),
            CacheColumn::CompressedSize => entry.compressed_size.to_string(),
            CacheColumn::LastAccessed => format_local_opt(entry.last_accessed, show_millis),
            CacheColumn::ServerTime => format_local_opt(entry.server_time, false),
            CacheColumn::RecordCreatedTime => {
                format_local_opt(entry.record_created_time, show_millis)
            }
            CacheColumn::ExpirationTime => format_local_opt(entry.expiration_time, false),
            CacheColumn::ServerName => entry.server_name.clone().unwrap_or_default(),
            CacheColumn::ServerResponse => entry.server_response.clone(),
            CacheColumn::ContentEncoding => entry.content_encoding.clone().unwrap_or_default(),
            CacheColumn::CacheName => entry.cache_name.clone(),
            CacheColumn::UrlLength => entry.url_length.to_string(),
            CacheColumn::WebSite => entry.partition_website.clone().unwrap_or_default(),
            CacheColumn::Frame => entry.partition_frame.clone().unwrap_or_default(),
            CacheColumn::ServerIp => match (&entry.server_ip, entry.server_port) {
                (Some(ip), Some(port)) => format!("{ip}:{port}"),
                (Some(ip), None) => ip.clone(),
                _ => String::new(),
            },
            CacheColumn::DeletedFile => if entry.deleted_file { "Yes" } else { "No" }.to_string(),
            CacheColumn::Sha256 => entry.payload_sha256.clone().unwrap_or_default(),
            CacheColumn::Backend => entry.backend.as_str().to_string(),
        }
    }
}

pub fn render_cache_export(
    entries: &[CacheEntry],
    format: ExportFormat,
    columns: &[CacheColumn],
    include_header: bool,
    show_millis: bool,
) -> Result<String, ChromeError> {
    let cols = if columns.is_empty() {
        CacheColumn::default_columns()
    } else {
        columns.to_vec()
    };

    match format {
        ExportFormat::Json => serde_json::to_string_pretty(entries)
            .map_err(|e| ChromeError::Export(e.to_string())),
        ExportFormat::Csv => {
            let mut wtr = csv::Writer::from_writer(Vec::new());
            if include_header {
                let hdr: Vec<&str> = cols.iter().map(|c| c.header()).collect();
                wtr.write_record(&hdr)
                    .map_err(|e| ChromeError::Export(e.to_string()))?;
            }
            for e in entries {
                let row: Vec<String> = cols.iter().map(|c| c.value(e, show_millis)).collect();
                wtr.write_record(&row)
                    .map_err(|e| ChromeError::Export(e.to_string()))?;
            }
            let bytes = wtr
                .into_inner()
                .map_err(|e| ChromeError::Export(e.to_string()))?;
            String::from_utf8(bytes).map_err(|e| ChromeError::Export(e.to_string()))
        }
        ExportFormat::Tab => {
            let mut out = String::new();
            if include_header {
                let hdr: Vec<&str> = cols.iter().map(|c| c.header()).collect();
                out.push_str(&hdr.join("\t"));
                out.push('\n');
            }
            for e in entries {
                let row: Vec<String> = cols
                    .iter()
                    .map(|c| c.value(e, show_millis).replace(['\t', '\r', '\n'], " "))
                    .collect();
                out.push_str(&row.join("\t"));
                out.push('\n');
            }
            Ok(out)
        }
        ExportFormat::Tabular => {
            let mut widths: Vec<usize> = cols.iter().map(|c| c.header().len()).collect();
            let rows: Vec<Vec<String>> = entries
                .iter()
                .map(|e| {
                    cols.iter()
                        .enumerate()
                        .map(|(i, c)| {
                            let val = c.value(e, show_millis);
                            let capped = val.chars().count().min(80);
                            if capped > widths[i] {
                                widths[i] = capped;
                            }
                            val
                        })
                        .collect()
                })
                .collect();

            let mut out = String::new();
            if include_header {
                for (i, c) in cols.iter().enumerate() {
                    if i > 0 {
                        out.push_str("  ");
                    }
                    out.push_str(&format!("{:<width$}", c.header(), width = widths[i]));
                }
                out.push('\n');
                for (i, w) in widths.iter().enumerate() {
                    if i > 0 {
                        out.push_str("  ");
                    }
                    out.push_str(&"-".repeat(*w));
                }
                out.push('\n');
            }
            for row in rows {
                for (i, val) in row.iter().enumerate() {
                    if i > 0 {
                        out.push_str("  ");
                    }
                    out.push_str(&format!("{:<width$}", val, width = widths[i]));
                }
                out.push('\n');
            }
            Ok(out)
        }
        ExportFormat::Text => {
            let mut out = String::new();
            for (idx, e) in entries.iter().enumerate() {
                if idx > 0 {
                    out.push_str("==================================================\n");
                }
                for c in &cols {
                    out.push_str(&format!("{:<20}: {}\n", c.header(), c.value(e, show_millis)));
                }
            }
            Ok(out)
        }
        ExportFormat::HtmlHorizontal => {
            let mut out = String::from(
                "<!doctype html><html><head><meta charset=\"utf-8\"><title>ChromeCacheView Export - chrome2rust</title>\
                <style>body{font-family:system-ui,sans-serif;margin:20px;background:#0f172a;color:#e2e8f0;}\
                table{border-collapse:collapse;width:100%;font-size:13px;}th,td{border:1px solid #334155;padding:6px 8px;text-align:left;}\
                th{background:#1e293b;position:sticky;top:0;}tr:nth-child(even){background:#111827;}</style></head><body>\
                <h2>Cache Entries Export</h2><table>",
            );
            if include_header {
                out.push_str("<thead><tr>");
                for c in &cols {
                    out.push_str("<th>");
                    out.push_str(&escape_html(c.header()));
                    out.push_str("</th>");
                }
                out.push_str("</tr></thead>");
            }
            out.push_str("<tbody>");
            for e in entries {
                out.push_str("<tr>");
                for c in &cols {
                    out.push_str("<td>");
                    out.push_str(&escape_html(&c.value(e, show_millis)));
                    out.push_str("</td>");
                }
                out.push_str("</tr>");
            }
            out.push_str("</tbody></table></body></html>");
            Ok(out)
        }
        ExportFormat::HtmlVertical => {
            let mut out = String::from(
                "<!doctype html><html><head><meta charset=\"utf-8\"><title>ChromeCacheView Vertical Export - chrome2rust</title>\
                <style>body{font-family:system-ui,sans-serif;margin:20px;background:#0f172a;color:#e2e8f0;}\
                table{border-collapse:collapse;width:100%;margin-bottom:20px;font-size:13px;}th,td{border:1px solid #334155;padding:6px 8px;text-align:left;}\
                th{background:#1e293b;width:200px;}</style></head><body><h2>Cache Entries Export</h2>",
            );
            for (idx, e) in entries.iter().enumerate() {
                out.push_str(&format!("<h3>Item #{}</h3><table>", idx + 1));
                for c in &cols {
                    out.push_str("<tr><th>");
                    out.push_str(&escape_html(c.header()));
                    out.push_str("</th><td>");
                    out.push_str(&escape_html(&c.value(e, show_millis)));
                    out.push_str("</td></tr>");
                }
                out.push_str("</table>");
            }
            out.push_str("</body></html>");
            Ok(out)
        }
        ExportFormat::Xml => {
            let mut out = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<cache_items>\n");
            for e in entries {
                out.push_str("  <item>\n");
                for c in &cols {
                    let tag = c
                        .header()
                        .to_ascii_lowercase()
                        .replace(' ', "_");
                    out.push_str(&format!(
                        "    <{tag}>{}</{tag}>\n",
                        escape_xml(&c.value(e, show_millis))
                    ));
                }
                out.push_str("  </item>\n");
            }
            out.push_str("</cache_items>\n");
            Ok(out)
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExtractFilenameMode {
    BasedOnUrl,
    CacheName,
    CacheNameWithExtension,
}

#[derive(Debug, Clone)]
pub struct ExtractOptions {
    pub output_dir: PathBuf,
    pub filename_mode: ExtractFilenameMode,
    pub use_website_dir_structure: bool,
    pub update_modified_time: bool,
    pub new_name_if_exist: bool,
    pub decompress: bool,
}

impl Default for ExtractOptions {
    fn default() -> Self {
        Self {
            output_dir: PathBuf::from("./extracted_cache"),
            filename_mode: ExtractFilenameMode::BasedOnUrl,
            use_website_dir_structure: false,
            update_modified_time: true,
            new_name_if_exist: true,
            decompress: true,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ExtractSummary {
    pub extracted_count: usize,
    pub skipped_empty_or_deleted: usize,
    pub failed_count: usize,
    pub bytes_written: u64,
    pub errors: Vec<String>,
}

pub fn extract_cache_entries(entries: &[&CacheEntry], opts: &ExtractOptions) -> Result<ExtractSummary, ChromeError> {
    std::fs::create_dir_all(&opts.output_dir).map_err(|e| ChromeError::Io {
        path: opts.output_dir.display().to_string(),
        source: e,
    })?;

    let mut summary = ExtractSummary::default();

    for entry in entries {
        if entry.deleted_file {
            summary.skipped_empty_or_deleted += 1;
            continue;
        }
        let payload = if opts.decompress {
            entry.read_decompressed_payload()
        } else {
            entry.read_raw_payload()
        };

        let bytes = match payload {
            Ok(b) if !b.is_empty() => b,
            Ok(_) => {
                summary.skipped_empty_or_deleted += 1;
                continue;
            }
            Err(e) => {
                summary.failed_count += 1;
                summary.errors.push(format!("{}: {e}", entry.url));
                continue;
            }
        };

        let mut dest_path = build_extract_path(entry, opts);
        if let Some(parent) = dest_path.parent() {
            if let Err(e) = std::fs::create_dir_all(parent) {
                summary.failed_count += 1;
                summary.errors.push(format!("{}: {e}", dest_path.display()));
                continue;
            }
        }
        if opts.new_name_if_exist && dest_path.exists() {
            dest_path = next_available_filename(&dest_path);
        }

        match std::fs::File::create(&dest_path).and_then(|mut f| {
            f.write_all(&bytes)?;
            if opts.update_modified_time
                && let Some(mtime) = entry.last_accessed.or(entry.server_time)
            {
                let st: std::time::SystemTime = mtime.into();
                let times = std::fs::FileTimes::new().set_modified(st);
                let _ = f.set_times(times);
            }
            Ok(())
        }) {
            Ok(()) => {
                summary.extracted_count += 1;
                summary.bytes_written += bytes.len() as u64;
            }
            Err(e) => {
                summary.failed_count += 1;
                summary.errors.push(format!("{}: {e}", dest_path.display()));
            }
        }
    }

    Ok(summary)
}

fn build_extract_path(entry: &CacheEntry, opts: &ExtractOptions) -> PathBuf {
    let ext = infer_extension(entry);
    let sanitized_cache = sanitize_filename(&entry.cache_name);

    if opts.use_website_dir_structure {
        if let Ok(parsed) = url::Url::parse(&entry.url) {
            let host = parsed
                .host_str()
                .map(|h| match parsed.port() {
                    Some(p) => format!("{h}_{p}"),
                    None => h.to_string(),
                })
                .unwrap_or_else(|| "unknown_host".to_string());
            let mut dir = opts.output_dir.join(sanitize_filename(&host));
            let segs: Vec<&str> = parsed
                .path_segments()
                .map(|s| s.filter(|p| !p.is_empty()).collect())
                .unwrap_or_default();
            if segs.len() > 1 {
                for seg in &segs[..segs.len() - 1] {
                    dir = dir.join(sanitize_filename(seg));
                }
            }
            let file_part = match opts.filename_mode {
                ExtractFilenameMode::BasedOnUrl => {
                    let base = segs.last().copied().unwrap_or("index");
                    ensure_extension(&sanitize_filename(base), ext)
                }
                ExtractFilenameMode::CacheName => sanitized_cache,
                ExtractFilenameMode::CacheNameWithExtension => ensure_extension(&sanitized_cache, ext),
            };
            return dir.join(file_part);
        }
    }

    let filename = match opts.filename_mode {
        ExtractFilenameMode::BasedOnUrl => {
            let base = url::Url::parse(&entry.url)
                .ok()
                .and_then(|u| {
                    u.path_segments()
                        .and_then(|mut s| s.rfind(|p| !p.is_empty()).map(str::to_string))
                        .or_else(|| u.host_str().map(str::to_string))
                })
                .unwrap_or_else(|| sanitized_cache.clone());
            ensure_extension(&sanitize_filename(&base), ext)
        }
        ExtractFilenameMode::CacheName => sanitized_cache,
        ExtractFilenameMode::CacheNameWithExtension => ensure_extension(&sanitized_cache, ext),
    };

    opts.output_dir.join(filename)
}

fn ensure_extension(base: &str, ext: Option<&str>) -> String {
    let mut name = if base.is_empty() {
        "index".to_string()
    } else {
        base.to_string()
    };
    if let Some(e) = ext {
        let has_ext = Path::new(&name).extension().is_some();
        if !has_ext {
            name.push('.');
            name.push_str(e);
        }
    }
    name
}

fn infer_extension(entry: &CacheEntry) -> Option<&'static str> {
    let ct = entry.content_type.as_deref().unwrap_or("");
    match ct {
        "text/html" => Some("html"),
        "text/css" => Some("css"),
        "text/javascript" | "application/javascript" | "application/x-javascript" => Some("js"),
        "application/json" | "text/json" => Some("json"),
        "text/plain" => Some("txt"),
        "text/xml" | "application/xml" => Some("xml"),
        "image/png" => Some("png"),
        "image/jpeg" | "image/jpg" => Some("jpg"),
        "image/gif" => Some("gif"),
        "image/webp" => Some("webp"),
        "image/svg+xml" => Some("svg"),
        "image/x-icon" | "image/vnd.microsoft.icon" => Some("ico"),
        "font/woff2" => Some("woff2"),
        "font/woff" => Some("woff"),
        "application/wasm" => Some("wasm"),
        "application/pdf" => Some("pdf"),
        "video/mp4" => Some("mp4"),
        "audio/mpeg" => Some("mp3"),
        _ => None,
    }
}

pub fn sanitize_filename(name: &str) -> String {
    let mut out = String::with_capacity(name.len().min(180));
    for ch in name.chars().take(180) {
        if matches!(
            ch,
            '/' | '\\' | '?' | ':' | '*' | '"' | '<' | '>' | '|' | '\0'
        ) || ch.is_control()
        {
            out.push('_');
        } else {
            out.push(ch);
        }
    }
    let trimmed = out.trim_matches(['.', ' ']).to_string();
    if trimmed.is_empty() {
        "file".to_string()
    } else {
        trimmed
    }
}

fn next_available_filename(path: &Path) -> PathBuf {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let stem = path
        .file_stem()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| "file".to_string());
    let ext = path.extension().map(|e| e.to_string_lossy().to_string());

    for i in 1..10_000 {
        let candidate_name = match &ext {
            Some(e) => format!("{stem}_{i}.{e}"),
            None => format!("{stem}_{i}"),
        };
        let candidate = parent.join(candidate_name);
        if !candidate.exists() {
            return candidate;
        }
    }
    path.to_path_buf()
}

pub fn escape_html(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn escape_xml(s: &str) -> String {
    escape_html(s)
}
