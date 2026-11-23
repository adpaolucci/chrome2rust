use super::CacheEntry;
use chrome2rust_core::error::ChromeError;
use chrome2rust_core::time::format_local_opt;
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
    DetectedContentType,
    DetectedExtension,
    FileSignature,
    MimeMismatch,
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
            CacheColumn::DetectedContentType => "Detected Type",
            CacheColumn::DetectedExtension => "Detected Ext",
            CacheColumn::FileSignature => "File Signature",
            CacheColumn::MimeMismatch => "MIME Mismatch",
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
            CacheColumn::DetectedContentType,
            CacheColumn::DetectedExtension,
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

    pub fn all_columns() -> Vec<CacheColumn> {
        vec![
            CacheColumn::Url,
            CacheColumn::ContentType,
            CacheColumn::DetectedContentType,
            CacheColumn::DetectedExtension,
            CacheColumn::FileSignature,
            CacheColumn::MimeMismatch,
            CacheColumn::FileSize,
            CacheColumn::CompressedSize,
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
            CacheColumn::Sha256,
            CacheColumn::Backend,
        ]
    }

    pub fn from_name(name: &str) -> Option<Self> {
        match name.trim().to_ascii_lowercase().replace([' ', '_', '-'], "").as_str() {
            "url" => Some(Self::Url),
            "contenttype" => Some(Self::ContentType),
            "detectedcontenttype" | "detectedtype" | "realcontenttype" => Some(Self::DetectedContentType),
            "detectedextension" | "detectedext" | "extension" | "ext" => Some(Self::DetectedExtension),
            "filesignature" | "signature" | "magic" => Some(Self::FileSignature),
            "mimemismatch" | "mismatch" => Some(Self::MimeMismatch),
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
            CacheColumn::DetectedContentType => entry.detected_content_type.clone().unwrap_or_default(),
            CacheColumn::DetectedExtension => entry.detected_extension.clone().unwrap_or_default(),
            CacheColumn::FileSignature => entry.file_signature.clone().unwrap_or_default(),
            CacheColumn::MimeMismatch => if entry.mime_mismatch { "Yes" } else { "No" }.to_string(),
            CacheColumn::FileSize => entry.file_size.to_string(),
            CacheColumn::CompressedSize => entry.compressed_size.to_string(),
            CacheColumn::LastAccessed => format_local_opt(entry.last_accessed, show_millis),
            CacheColumn::ServerTime => format_local_opt(entry.server_time, false),
            CacheColumn::RecordCreatedTime => format_local_opt(entry.record_created_time, show_millis),
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
        ExportFormat::Json => serde_json::to_string_pretty(entries).map_err(|e| ChromeError::Export(e.to_string())),
        ExportFormat::Csv => {
            let mut wtr = csv::Writer::from_writer(Vec::new());
            if include_header {
                let hdr: Vec<&str> = cols.iter().map(|c| c.header()).collect();
                wtr.write_record(&hdr).map_err(|e| ChromeError::Export(e.to_string()))?;
            }
            for e in entries {
                let row: Vec<String> = cols
                    .iter()
                    .map(|c| neutralize_spreadsheet_cell(&c.value(e, show_millis)))
                    .collect();
                wtr.write_record(&row).map_err(|e| ChromeError::Export(e.to_string()))?;
            }
            let bytes = wtr.into_inner().map_err(|e| ChromeError::Export(e.to_string()))?;
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
                    .map(|c| neutralize_spreadsheet_cell(&c.value(e, show_millis)).replace(['\t', '\r', '\n'], " "))
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
                "<!doctype html><html><head><meta charset=\"utf-8\">\
                <meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none';\">\
                <title>Chrome Cache Export - chrome2rust</title>\
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
                "<!doctype html><html><head><meta charset=\"utf-8\">\
                <meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none';\">\
                <title>Chrome Cache Vertical Export - chrome2rust</title>\
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
                    let tag = c.header().to_ascii_lowercase().replace(' ', "_");
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
    pub prefer_detected_extension: bool,
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
            prefer_detected_extension: false,
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

        let mut dest_path = build_extract_path(entry, &bytes, opts);
        if let Some(parent) = dest_path.parent()
            && let Err(e) = std::fs::create_dir_all(parent)
        {
            summary.failed_count += 1;
            summary.errors.push(format!("{}: {e}", dest_path.display()));
            continue;
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

fn build_extract_path(entry: &CacheEntry, payload: &[u8], opts: &ExtractOptions) -> PathBuf {
    let det = chrome2rust_core::magic::detect_content(
        &payload[..payload.len().min(64 * 1024)],
        entry.content_type.as_deref(),
        Some(&entry.url),
        entry.content_disposition_filename.as_deref(),
    );
    let ext = det.extension.as_deref().or(entry.detected_extension.as_deref());
    let sanitized_cache = sanitize_filename(&entry.cache_name);

    if opts.use_website_dir_structure
        && let Ok(parsed) = url::Url::parse(&entry.url)
    {
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
            for seg in segs[..segs.len() - 1].iter().take(16) {
                dir = dir.join(sanitize_filename(seg));
            }
        }
        let file_part = match opts.filename_mode {
            ExtractFilenameMode::BasedOnUrl => {
                let (base, from_host) = if let Some(ref cd) = entry.content_disposition_filename
                    && !cd.trim().is_empty()
                {
                    (cd.clone(), false)
                } else if let Some(last) = segs.last() {
                    ((*last).to_string(), false)
                } else {
                    ("index".to_string(), false)
                };
                resolve_filename(
                    &sanitize_filename(&base),
                    from_host,
                    ext,
                    opts.prefer_detected_extension,
                )
            }
            ExtractFilenameMode::CacheName => sanitized_cache,
            ExtractFilenameMode::CacheNameWithExtension => {
                resolve_filename(&sanitized_cache, false, ext, opts.prefer_detected_extension)
            }
        };
        return dir.join(file_part);
    }

    let filename = match opts.filename_mode {
        ExtractFilenameMode::BasedOnUrl => {
            let (raw_base, from_host) = if let Some(ref cd) = entry.content_disposition_filename
                && !cd.trim().is_empty()
            {
                (cd.clone(), false)
            } else if let Ok(u) = url::Url::parse(&entry.url) {
                if let Some(last) = u.path_segments().and_then(|mut s| s.rfind(|p| !p.is_empty())) {
                    (last.to_string(), false)
                } else if let Some(host) = u.host_str() {
                    (host.to_string(), true)
                } else {
                    (sanitized_cache.clone(), false)
                }
            } else {
                (sanitized_cache.clone(), false)
            };
            resolve_filename(
                &sanitize_filename(&raw_base),
                from_host,
                ext,
                opts.prefer_detected_extension,
            )
        }
        ExtractFilenameMode::CacheName => sanitized_cache,
        ExtractFilenameMode::CacheNameWithExtension => {
            resolve_filename(&sanitized_cache, false, ext, opts.prefer_detected_extension)
        }
    };

    opts.output_dir.join(filename)
}

fn resolve_filename(base: &str, from_host: bool, detected_ext: Option<&str>, prefer_detected_ext: bool) -> String {
    let name = if base.is_empty() { "index" } else { base };
    let Some(ext) = detected_ext.filter(|e| !e.is_empty()) else {
        return name.to_string();
    };

    // Hostname root fallbacks (`example.com/`, `notion.so/`) do not carry file extensions
    if from_host {
        return format!("{name}.{ext}");
    }

    let Some((stem, existing_raw)) = name.rsplit_once('.') else {
        return format!("{name}.{ext}");
    };
    let existing = existing_raw.to_ascii_lowercase();

    // Dynamic server endpoints (image.php, get.ashx) or versioned dots (jquery-3.7.1) lack payload extensions
    if chrome2rust_core::magic::is_server_endpoint_extension(&existing)
        || !chrome2rust_core::magic::is_known_extension(&existing)
    {
        return format!("{name}.{ext}");
    }

    if prefer_detected_ext && !chrome2rust_core::magic::extensions_equivalent(&existing, ext) {
        return format!("{stem}.{ext}");
    }

    name.to_string()
}

pub fn sanitize_filename(name: &str) -> String {
    let mut out = String::with_capacity(name.len().min(180));
    for ch in name.chars().take(180) {
        if matches!(ch, '/' | '\\' | '?' | ':' | '*' | '"' | '<' | '>' | '|' | '\0') || ch.is_control() {
            out.push('_');
        } else {
            out.push(ch);
        }
    }
    let trimmed = out.trim_matches(['.', ' ']).to_string();
    if trimmed.is_empty() {
        return "file".to_string();
    }
    let stem = trimmed.split('.').next().unwrap_or(&trimmed);
    if is_windows_reserved_stem(stem) {
        format!("_{trimmed}")
    } else {
        trimmed
    }
}

fn is_windows_reserved_stem(stem: &str) -> bool {
    let up = stem.to_ascii_uppercase();
    matches!(
        up.as_str(),
        "CON"
            | "PRN"
            | "AUX"
            | "NUL"
            | "COM1"
            | "COM2"
            | "COM3"
            | "COM4"
            | "COM5"
            | "COM6"
            | "COM7"
            | "COM8"
            | "COM9"
            | "LPT1"
            | "LPT2"
            | "LPT3"
            | "LPT4"
            | "LPT5"
            | "LPT6"
            | "LPT7"
            | "LPT8"
            | "LPT9"
    )
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

fn neutralize_spreadsheet_cell(raw: &str) -> String {
    if raw.starts_with(['=', '+', '-', '@', '\t', '\r'])
        || raw.trim_start_matches(' ').starts_with(['=', '+', '-', '@'])
    {
        format!("'{raw}")
    } else {
        raw.to_string()
    }
}

fn escape_xml(s: &str) -> String {
    escape_html(s)
}

#[cfg(test)]
mod tests {
    use super::super::pickle::HttpResponseMetadata;
    use super::super::{CacheBackendKind, CacheLocationRef};
    use super::*;
    use chrome2rust_core::magic::ContentDetection;

    fn dummy_entry(url: &str, ct: Option<&str>, cd_name: Option<&str>) -> CacheEntry {
        let http = HttpResponseMetadata {
            content_type: ct.map(str::to_string),
            content_disposition_filename: cd_name.map(str::to_string),
            ..Default::default()
        };
        CacheEntry::from_metadata(
            "id1".into(),
            CacheBackendKind::SimpleCache,
            "abcdef01_0".into(),
            "/tmp/abcdef01_0".into(),
            url.into(),
            http,
            10,
            10,
            None,
            None,
            false,
            Some(true),
            None,
            ContentDetection::default(),
            CacheLocationRef {
                backend: CacheBackendKind::SimpleCache,
                cache_dir: PathBuf::from("/tmp"),
                primary_file: PathBuf::from("/tmp/abcdef01_0"),
                blockfile_stream1: None,
                simple_stream1_range: None,
                simple_alt_stream1_file: None,
            },
        )
    }

    #[test]
    fn test_build_extract_path_edge_cases() {
        let opts = ExtractOptions {
            output_dir: PathBuf::from("/tmp/out"),
            ..Default::default()
        };

        // 1. Root URL TLD guard (`notion.so/`, `example.com/`)
        let root_so = dummy_entry("https://notion.so/", None, None);
        let p_so = build_extract_path(&root_so, b"<!doctype html><html></html>", &opts);
        assert_eq!(p_so, PathBuf::from("/tmp/out/notion.so.html"));

        // 2. Versioned JS without .js extension
        let ver_js = dummy_entry(
            "https://cdn.example.com/jquery-3.7.1",
            Some("application/octet-stream"),
            None,
        );
        let p_js = build_extract_path(&ver_js, b"'use strict';\nconst x=1;", &opts);
        assert_eq!(p_js, PathBuf::from("/tmp/out/jquery-3.7.1.js"));

        // 3. Server script endpoint serving WebP
        let php_img = dummy_entry(
            "https://example.com/image.php?id=9",
            Some("application/octet-stream"),
            None,
        );
        let p_webp = build_extract_path(&php_img, b"RIFF\x12\x00\x00\x00WEBPVP8 ", &opts);
        assert_eq!(p_webp, PathBuf::from("/tmp/out/image.php.webp"));

        // 4. Content-Disposition filename overrides opaque endpoint
        let cd = dummy_entry(
            "https://example.com/download?id=99",
            Some("application/pdf"),
            Some("statement.pdf"),
        );
        let p_cd = build_extract_path(&cd, b"%PDF-1.7\n", &opts);
        assert_eq!(p_cd, PathBuf::from("/tmp/out/statement.pdf"));

        // 5. Masquerading .png -> .dll only when prefer_detected_extension is enabled
        let mut pe = vec![0u8; 128];
        pe[0..2].copy_from_slice(b"MZ");
        pe[0x3c..0x40].copy_from_slice(&64u32.to_le_bytes());
        pe[64..68].copy_from_slice(b"PE\0\0");
        pe[64 + 22..64 + 24].copy_from_slice(&0x2000u16.to_le_bytes());
        let evil = dummy_entry("https://evil.test/logo.png", Some("image/png"), None);
        assert_eq!(
            build_extract_path(&evil, &pe, &opts),
            PathBuf::from("/tmp/out/logo.png")
        );
        let opts_prefer = ExtractOptions {
            prefer_detected_extension: true,
            ..opts
        };
        assert_eq!(
            build_extract_path(&evil, &pe, &opts_prefer),
            PathBuf::from("/tmp/out/logo.dll")
        );
    }

    #[test]
    fn test_sanitize_filename_safety() {
        assert_eq!(sanitize_filename(""), "file");
        assert_eq!(sanitize_filename(".."), "file");
        assert_eq!(sanitize_filename("."), "file");
        assert_eq!(sanitize_filename("con"), "_con");
        assert_eq!(sanitize_filename("NUL.txt"), "_NUL.txt");
        assert_eq!(sanitize_filename("COM1.html"), "_COM1.html");
        assert_eq!(sanitize_filename("lpt9.png"), "_lpt9.png");
        assert_eq!(sanitize_filename("../evil\\file\0.js"), "_evil_file_.js");
    }

    #[test]
    fn test_csv_and_tab_export_neutralize_formula_injection() {
        let mut entry = dummy_entry("=cmd|' /C calc'!A0", Some("+evil/type"), None);
        entry.server_name = Some("  =HYPERLINK(\"https://evil.example\",\"Go\")".to_string());
        entry.file_signature = Some("-1+1".to_string());
        entry.detected_extension = Some("@ext".to_string());

        let cols = vec![
            CacheColumn::Url,
            CacheColumn::ContentType,
            CacheColumn::ServerName,
            CacheColumn::FileSignature,
            CacheColumn::DetectedExtension,
        ];
        let entries = [entry];

        let csv_out = render_cache_export(&entries, ExportFormat::Csv, &cols, true, false).unwrap();
        assert!(csv_out.contains("'=cmd|' /C calc'!A0"));
        assert!(csv_out.contains("'+evil/type"));
        assert!(csv_out.contains("\"'  =HYPERLINK("));
        assert!(csv_out.contains("'-1+1"));
        assert!(csv_out.contains("'@ext"));

        let tab_out = render_cache_export(&entries, ExportFormat::Tab, &cols, true, false).unwrap();
        assert!(tab_out.contains("'=cmd|' /C calc'!A0"));
        assert!(tab_out.contains("'+evil/type"));
        assert!(tab_out.contains("'  =HYPERLINK("));
        assert!(tab_out.contains("'-1+1"));
        assert!(tab_out.contains("'@ext"));
    }
}
