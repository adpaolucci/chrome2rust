#![forbid(unsafe_code)]

pub mod blockfile;
pub mod carve_images;
pub mod carve_video;
pub mod decompress;
pub mod exif;
pub mod export;
pub mod firefox;
pub mod opera;
pub mod pickle;
pub mod safari;
pub mod simple;
pub mod unified_cache;

use chrome2rust_core::error::{ChromeError, DiagnosticWarning};
use chrome2rust_core::magic::{ContentDetection, is_generic_mime};
use chrome2rust_core::time::{chrome_us_to_datetime, parse_http_date};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::path::PathBuf;
use walkdir::WalkDir;

use self::decompress::decompress_payload_for_type;
use self::pickle::{HttpResponseMetadata, ParsedCertSummary, ParsedHeader};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CacheBackendKind {
    SimpleCache,
    Blockfile,
}

impl CacheBackendKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            CacheBackendKind::SimpleCache => "SimpleCache",
            CacheBackendKind::Blockfile => "Blockfile",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheLocationRef {
    pub backend: CacheBackendKind,
    pub cache_dir: PathBuf,
    /// Path to primary file (`*_0` for Simple Cache, or `f_xxxxxx` / `data_N` for Blockfile)
    pub primary_file: PathBuf,
    /// For Blockfile: `(file_number, start_block, num_blocks, byte_len)` or `separate_file`
    pub blockfile_stream1: Option<BlockfileDataLocation>,
    /// For Simple Cache: start/end slice inside `primary_file` for raw stream 1 bytes, or separate `*_1` file
    pub simple_stream1_range: Option<(usize, usize)>,
    pub simple_alt_stream1_file: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BlockfileDataLocation {
    Block {
        file_number: u8,
        start_block: u16,
        block_size: usize,
        byte_len: usize,
    },
    SeparateFile {
        path: PathBuf,
        byte_len: usize,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheEntry {
    pub id: String,
    pub backend: CacheBackendKind,
    pub cache_name: String,
    pub cache_file_path: String,
    pub raw_key: String,
    pub url: String,
    pub url_length: usize,
    pub partition_website: Option<String>,
    pub partition_frame: Option<String>,
    pub content_type: Option<String>,
    pub raw_content_type: Option<String>,
    pub content_encoding: Option<String>,
    #[serde(default)]
    pub content_disposition_filename: Option<String>,
    #[serde(default)]
    pub detected_content_type: Option<String>,
    #[serde(default)]
    pub detected_extension: Option<String>,
    #[serde(default)]
    pub file_signature: Option<String>,
    #[serde(default)]
    pub mime_mismatch: bool,
    /// Compressed/stored payload length in bytes (stream 1).
    pub compressed_size: usize,
    /// Uncompressed payload length in bytes (if decompressible/known, else same as compressed_size).
    pub file_size: usize,
    pub last_accessed: Option<DateTime<Utc>>,
    pub server_time: Option<DateTime<Utc>>,
    pub record_created_time: Option<DateTime<Utc>>,
    pub expiration_time: Option<DateTime<Utc>>,
    pub server_name: Option<String>,
    pub server_response: String,
    pub status_code: Option<u16>,
    pub server_ip: Option<String>,
    pub server_port: Option<u16>,
    pub alpn_protocol: Option<String>,
    pub tls_version: Option<String>,
    pub dns_aliases: Vec<String>,
    pub certificates: Vec<ParsedCertSummary>,
    pub headers: Vec<ParsedHeader>,
    pub deleted_file: bool,
    pub crc32_valid: Option<bool>,
    pub payload_sha256: Option<String>,
    #[serde(skip)]
    pub location: Option<CacheLocationRef>,
}

impl CacheEntry {
    #[allow(clippy::too_many_arguments)]
    pub fn from_metadata(
        id: String,
        backend: CacheBackendKind,
        cache_name: String,
        cache_file_path: String,
        raw_key: String,
        http: HttpResponseMetadata,
        compressed_size: usize,
        file_size: usize,
        fs_created: Option<DateTime<Utc>>,
        fs_modified: Option<DateTime<Utc>>,
        deleted_file: bool,
        crc32_valid: Option<bool>,
        payload_sha256: Option<String>,
        detection: ContentDetection,
        location: CacheLocationRef,
    ) -> Self {
        let (url, partition_website, partition_frame) = parse_cache_key(&raw_key);
        let url_length = url.chars().count();
        let last_accessed = fs_modified.or(http.response_time).or(http.request_time);
        let record_created_time = http.original_response_time.or(fs_created).or(http.request_time);

        Self {
            id,
            backend,
            cache_name,
            cache_file_path,
            raw_key,
            url,
            url_length,
            partition_website,
            partition_frame,
            content_type: http.content_type,
            raw_content_type: http.raw_content_type,
            content_encoding: http.content_encoding,
            content_disposition_filename: http.content_disposition_filename,
            detected_content_type: detection.mime,
            detected_extension: detection.extension,
            file_signature: detection.signature,
            mime_mismatch: detection.mime_mismatch,
            compressed_size,
            file_size,
            last_accessed,
            server_time: http.server_time,
            record_created_time,
            expiration_time: http.expiration_time,
            server_name: http.server_name,
            server_response: http.status_line,
            status_code: http.status_code,
            server_ip: http.server_ip,
            server_port: http.server_port,
            alpn_protocol: http.alpn_protocol,
            tls_version: http.tls_version,
            dns_aliases: http.dns_aliases,
            certificates: http.certificates,
            headers: http.headers,
            deleted_file,
            crc32_valid,
            payload_sha256,
            location: Some(location),
        }
    }

    /// Returns the most accurate MIME type: prefers `detected_content_type` when declared MIME is
    /// missing, generic (`application/octet-stream`), or contradicted by payload magic bytes.
    pub fn effective_content_type(&self) -> Option<&str> {
        if self.mime_mismatch {
            return self.detected_content_type.as_deref().or(self.content_type.as_deref());
        }
        match self.content_type.as_deref() {
            Some(ct) if !is_generic_mime(ct) => Some(ct),
            other => self.detected_content_type.as_deref().or(other),
        }
    }

    /// Reads the raw stored payload bytes from disk.
    pub fn read_raw_payload(&self) -> Result<Vec<u8>, ChromeError> {
        let Some(loc) = &self.location else {
            return Err(ChromeError::InvalidFormat(
                "CacheEntry has no disk location attached".into(),
            ));
        };
        match loc.backend {
            CacheBackendKind::SimpleCache => {
                if let Some((start, end)) = loc.simple_stream1_range {
                    let bytes = std::fs::read(&loc.primary_file).map_err(|e| ChromeError::Io {
                        path: loc.primary_file.display().to_string(),
                        source: e,
                    })?;
                    if end <= bytes.len() && start < end {
                        return Ok(bytes[start..end].to_vec());
                    }
                }
                if let Some(alt) = &loc.simple_alt_stream1_file
                    && alt.is_file()
                {
                    return simple::read_simple_stream_file_payload(alt);
                }
                Ok(Vec::new())
            }
            CacheBackendKind::Blockfile => {
                if let Some(bf_loc) = &loc.blockfile_stream1 {
                    return blockfile::read_blockfile_data(&loc.cache_dir, bf_loc);
                }
                Ok(Vec::new())
            }
        }
    }

    /// Reads and transparently decompresses the payload (gzip, deflate, br, zstd).
    pub fn read_decompressed_payload(&self) -> Result<Vec<u8>, ChromeError> {
        let raw = self.read_raw_payload()?;
        if raw.is_empty() {
            return Ok(raw);
        }
        match decompress_payload_for_type(&raw, self.content_encoding.as_deref(), self.content_type.as_deref()) {
            Ok(dec) => Ok(dec),
            Err(_) => Ok(raw),
        }
    }

    /// Computes or returns cached SHA-256 hex digest of the decompressed payload.
    pub fn compute_sha256(&self) -> Option<String> {
        if let Some(h) = &self.payload_sha256 {
            return Some(h.clone());
        }
        let bytes = self.read_decompressed_payload().ok()?;
        if bytes.is_empty() {
            return None;
        }
        let digest = Sha256::digest(&bytes);
        Some(hex_lower(&digest))
    }

    pub fn is_image(&self) -> bool {
        self.effective_content_type().is_some_and(|ct| ct.starts_with("image/"))
    }

    pub fn is_text_like(&self) -> bool {
        let Some(ct) = self.effective_content_type() else {
            return false;
        };
        ct.starts_with("text/")
            || ct.contains("json")
            || ct.contains("javascript")
            || ct.contains("ecmascript")
            || ct.contains("typescript")
            || ct.contains("xml")
            || ct.contains("yaml")
            || ct.contains("toml")
            || ct.contains("svg")
            || ct.contains("mpegurl")
            || ct.contains("x-pem-file")
            || ct.contains("x-www-form-urlencoded")
    }
}

/// Parses Chrome cache keys including modern network-isolation / double-key (`_dk_`) partitioning
/// and Code Cache space-separated `<url> <origin>` keys:
/// - `1/0/_dk_https://site https://frame https://url`
/// - `_dk_https://site https://frame https://url`
/// - `1/0/https://url`
/// - `https://cdn.example/app.js https://example.com`
/// - `https://url`
pub fn parse_cache_key(raw_key: &str) -> (String, Option<String>, Option<String>) {
    let mut s = raw_key.trim();

    // Strip leading Chromium isolation prefixes such as "1/0/", "0/0/", "s/", "r/"
    loop {
        if let Some(rest) = strip_digits_slash_prefix(s) {
            s = rest;
        } else if s.starts_with("s/") || s.starts_with("r/") {
            s = &s[2..];
        } else {
            break;
        }
    }

    let first_http = s.find("http://").or_else(|| s.find("https://"));
    if let Some(dk_idx) = s.find("_dk_")
        && (dk_idx == 0 || s[..dk_idx].ends_with('/') || s[..dk_idx].ends_with(' '))
        && first_http.is_none_or(|h| dk_idx < h)
    {
        let after_dk = &s[dk_idx + 4..];
        let parts: Vec<&str> = after_dk.splitn(3, ' ').collect();
        match parts.as_slice() {
            [site, frame, url] => {
                let site_opt = non_empty_opt(site);
                let frame_opt = non_empty_opt(frame);
                return ((*url).to_string(), site_opt, frame_opt);
            }
            [site, url] => {
                return ((*url).to_string(), non_empty_opt(site), None);
            }
            [url] => {
                return ((*url).to_string(), None, None);
            }
            _ => {}
        }
    }

    // Legacy or unpartitioned key; sometimes space-separated metadata precedes URL
    if let Some(idx) = first_http {
        if idx > 0 {
            let prefix = s[..idx].trim();
            let url = s[idx..].trim();
            let mut prefix_parts = prefix.split_whitespace();
            let site = prefix_parts.next().and_then(non_empty_opt);
            let frame = prefix_parts.next().and_then(non_empty_opt);
            return (url.to_string(), site, frame);
        }
        // Code Cache key format: "<script_url> <top_frame_origin>"
        if let Some((first_url, rest)) = s.split_once(' ') {
            let trimmed_rest = rest.trim();
            if trimmed_rest.starts_with("http://")
                || trimmed_rest.starts_with("https://")
                || trimmed_rest.starts_with("null")
                || trimmed_rest.starts_with("chrome-extension://")
            {
                return (first_url.to_string(), non_empty_opt(trimmed_rest), None);
            }
        }
    }

    (s.to_string(), None, None)
}

fn strip_digits_slash_prefix(s: &str) -> Option<&str> {
    let slash = s.find('/')?;
    if slash > 0 && slash <= 4 && s[..slash].bytes().all(|b| b.is_ascii_digit()) {
        Some(&s[slash + 1..])
    } else {
        None
    }
}

fn non_empty_opt(s: &str) -> Option<String> {
    let t = s.trim();
    if t.is_empty() || t == "null" {
        None
    } else {
        Some(t.to_string())
    }
}

pub fn hex_lower(bytes: &[u8]) -> String {
    const LUT: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(LUT[(b >> 4) as usize] as char);
        s.push(LUT[(b & 0xf) as usize] as char);
    }
    s
}

#[derive(Debug, Clone)]
pub struct CacheScanOptions {
    pub include_zero_length: bool,
    pub url_filter: Option<String>,
    pub content_type_filter: Option<String>,
    pub quick_filter: Option<String>,
    pub min_size: Option<usize>,
    pub max_size: Option<usize>,
    pub since: Option<DateTime<Utc>>,
    pub until: Option<DateTime<Utc>>,
    pub compute_hashes: bool,
    pub decompress_sizes: bool,
}

impl Default for CacheScanOptions {
    fn default() -> Self {
        Self {
            include_zero_length: true,
            url_filter: None,
            content_type_filter: None,
            quick_filter: None,
            min_size: None,
            max_size: None,
            since: None,
            until: None,
            compute_hashes: false,
            decompress_sizes: true,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CacheSortField {
    Url,
    ContentType,
    DetectedContentType,
    DetectedExtension,
    FileSignature,
    MimeMismatch,
    FileSize,
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
}

impl CacheSortField {
    pub fn from_name(name: &str) -> Option<Self> {
        match name.trim().to_ascii_lowercase().replace([' ', '_', '-'], "").as_str() {
            "url" => Some(Self::Url),
            "contenttype" | "type" => Some(Self::ContentType),
            "detectedcontenttype" | "detectedtype" | "realcontenttype" => Some(Self::DetectedContentType),
            "detectedextension" | "detectedext" | "extension" | "ext" => Some(Self::DetectedExtension),
            "filesignature" | "signature" | "magic" => Some(Self::FileSignature),
            "mimemismatch" | "mismatch" => Some(Self::MimeMismatch),
            "filesize" | "size" => Some(Self::FileSize),
            "lastaccessed" | "lastaccess" => Some(Self::LastAccessed),
            "servertime" => Some(Self::ServerTime),
            "recordcreatedtime" | "created" => Some(Self::RecordCreatedTime),
            "expirationtime" | "expires" => Some(Self::ExpirationTime),
            "servername" | "server" => Some(Self::ServerName),
            "serverresponse" | "response" | "status" => Some(Self::ServerResponse),
            "contentencoding" | "encoding" => Some(Self::ContentEncoding),
            "cachename" | "name" => Some(Self::CacheName),
            "urllength" => Some(Self::UrlLength),
            "website" | "site" => Some(Self::WebSite),
            "frame" => Some(Self::Frame),
            "serveripaddress" | "serverip" | "ip" => Some(Self::ServerIp),
            "deletedfile" | "deleted" => Some(Self::DeletedFile),
            _ => None,
        }
    }
}

pub fn matches_cache_filter(entry: &CacheEntry, opts: &CacheScanOptions) -> bool {
    if !opts.include_zero_length && entry.file_size == 0 && entry.compressed_size == 0 {
        return false;
    }
    if let Some(min) = opts.min_size
        && entry.file_size < min
    {
        return false;
    }
    if let Some(max) = opts.max_size
        && entry.file_size > max
    {
        return false;
    }
    if let Some(url_sub) = &opts.url_filter
        && !url_sub.is_empty()
        && !entry.url.to_ascii_lowercase().contains(&url_sub.to_ascii_lowercase())
    {
        return false;
    }
    if let Some(ct_sub) = &opts.content_type_filter
        && !ct_sub.is_empty()
    {
        let needle = ct_sub.to_ascii_lowercase();
        let matches_ct = entry
            .content_type
            .as_deref()
            .is_some_and(|ct| ct.to_ascii_lowercase().contains(&needle))
            || entry
                .detected_content_type
                .as_deref()
                .is_some_and(|ct| ct.to_ascii_lowercase().contains(&needle))
            || entry
                .detected_extension
                .as_deref()
                .is_some_and(|ext| ext.to_ascii_lowercase().contains(&needle));
        if !matches_ct {
            return false;
        }
    }
    if let Some(since) = opts.since {
        let t = entry.last_accessed.or(entry.record_created_time).or(entry.server_time);
        if t.is_none_or(|dt| dt < since) {
            return false;
        }
    }
    if let Some(until) = opts.until {
        let t = entry.last_accessed.or(entry.record_created_time).or(entry.server_time);
        if t.is_none_or(|dt| dt > until) {
            return false;
        }
    }
    if let Some(q) = &opts.quick_filter
        && !q.is_empty()
    {
        let needle = q.to_ascii_lowercase();
        let in_url = entry.url.to_ascii_lowercase().contains(&needle);
        let in_ct = entry
            .content_type
            .as_deref()
            .is_some_and(|s| s.to_ascii_lowercase().contains(&needle));
        let in_det_ct = entry
            .detected_content_type
            .as_deref()
            .is_some_and(|s| s.to_ascii_lowercase().contains(&needle));
        let in_det_ext = entry
            .detected_extension
            .as_deref()
            .is_some_and(|s| s.to_ascii_lowercase().contains(&needle));
        let in_sig = entry
            .file_signature
            .as_deref()
            .is_some_and(|s| s.to_ascii_lowercase().contains(&needle));
        let in_disp = entry
            .content_disposition_filename
            .as_deref()
            .is_some_and(|s| s.to_ascii_lowercase().contains(&needle));
        let in_mismatch = entry.mime_mismatch && "mismatch".contains(&needle);
        let in_srv = entry
            .server_name
            .as_deref()
            .is_some_and(|s| s.to_ascii_lowercase().contains(&needle));
        let in_site = entry
            .partition_website
            .as_deref()
            .is_some_and(|s| s.to_ascii_lowercase().contains(&needle));
        let in_ip = entry
            .server_ip
            .as_deref()
            .is_some_and(|s| s.to_ascii_lowercase().contains(&needle));
        let in_cache = entry.cache_name.to_ascii_lowercase().contains(&needle);
        let in_status = entry.server_response.to_ascii_lowercase().contains(&needle);
        if !(in_url
            || in_ct
            || in_det_ct
            || in_det_ext
            || in_sig
            || in_disp
            || in_mismatch
            || in_srv
            || in_site
            || in_ip
            || in_cache
            || in_status)
        {
            return false;
        }
    }
    true
}

pub fn sort_cache_entries(
    entries: &mut [CacheEntry],
    primary: CacheSortField,
    primary_desc: bool,
    secondary: Option<(CacheSortField, bool)>,
) {
    entries.sort_by(|a, b| {
        let ord = cmp_cache_field(a, b, primary);
        let ord = if primary_desc { ord.reverse() } else { ord };
        if ord != std::cmp::Ordering::Equal {
            return ord;
        }
        if let Some((sec, sec_desc)) = secondary {
            let sord = cmp_cache_field(a, b, sec);
            if sec_desc { sord.reverse() } else { sord }
        } else {
            a.url.cmp(&b.url)
        }
    });
}

fn cmp_cache_field(a: &CacheEntry, b: &CacheEntry, field: CacheSortField) -> std::cmp::Ordering {
    match field {
        CacheSortField::Url => a.url.to_ascii_lowercase().cmp(&b.url.to_ascii_lowercase()),
        CacheSortField::ContentType => a
            .content_type
            .as_deref()
            .unwrap_or("")
            .cmp(b.content_type.as_deref().unwrap_or("")),
        CacheSortField::DetectedContentType => a
            .detected_content_type
            .as_deref()
            .unwrap_or("")
            .cmp(b.detected_content_type.as_deref().unwrap_or("")),
        CacheSortField::DetectedExtension => a
            .detected_extension
            .as_deref()
            .unwrap_or("")
            .cmp(b.detected_extension.as_deref().unwrap_or("")),
        CacheSortField::FileSignature => a
            .file_signature
            .as_deref()
            .unwrap_or("")
            .to_ascii_lowercase()
            .cmp(&b.file_signature.as_deref().unwrap_or("").to_ascii_lowercase()),
        CacheSortField::MimeMismatch => a.mime_mismatch.cmp(&b.mime_mismatch),
        CacheSortField::FileSize => a.file_size.cmp(&b.file_size),
        CacheSortField::LastAccessed => a.last_accessed.cmp(&b.last_accessed),
        CacheSortField::ServerTime => a.server_time.cmp(&b.server_time),
        CacheSortField::RecordCreatedTime => a.record_created_time.cmp(&b.record_created_time),
        CacheSortField::ExpirationTime => a.expiration_time.cmp(&b.expiration_time),
        CacheSortField::ServerName => a
            .server_name
            .as_deref()
            .unwrap_or("")
            .to_ascii_lowercase()
            .cmp(&b.server_name.as_deref().unwrap_or("").to_ascii_lowercase()),
        CacheSortField::ServerResponse => a.server_response.cmp(&b.server_response),
        CacheSortField::ContentEncoding => a
            .content_encoding
            .as_deref()
            .unwrap_or("")
            .cmp(b.content_encoding.as_deref().unwrap_or("")),
        CacheSortField::CacheName => a.cache_name.cmp(&b.cache_name),
        CacheSortField::UrlLength => a.url_length.cmp(&b.url_length),
        CacheSortField::WebSite => a
            .partition_website
            .as_deref()
            .unwrap_or("")
            .cmp(b.partition_website.as_deref().unwrap_or("")),
        CacheSortField::Frame => a
            .partition_frame
            .as_deref()
            .unwrap_or("")
            .cmp(b.partition_frame.as_deref().unwrap_or("")),
        CacheSortField::ServerIp => a
            .server_ip
            .as_deref()
            .unwrap_or("")
            .cmp(b.server_ip.as_deref().unwrap_or("")),
        CacheSortField::DeletedFile => a.deleted_file.cmp(&b.deleted_file),
    }
}

/// Scans one or more cache directories (handling Simple Cache, Blockfile Cache, or parent `Cache/` dirs).
pub fn load_cache_from_paths(paths: &[PathBuf], opts: &CacheScanOptions) -> (Vec<CacheEntry>, Vec<DiagnosticWarning>) {
    let mut entries = Vec::new();
    let mut warnings = Vec::new();
    let mut visited_dirs: HashSet<PathBuf> = HashSet::new();

    for root in paths {
        if !root.exists() {
            warnings.push(DiagnosticWarning::warn("cache", root, "Cache directory does not exist"));
            continue;
        }
        // Check if root itself is a cache dir, or contains Cache_Data / Cache subdirs
        let mut candidate_dirs = Vec::new();
        let cache_data = root.join("Cache_Data");
        if cache_data.is_dir() {
            candidate_dirs.push(cache_data);
        } else {
            candidate_dirs.push(root.clone());
        }

        // Also recurse up to depth 2 if user pointed to e.g. `Code Cache` or profile dir
        for entry in WalkDir::new(root).max_depth(3).into_iter().flatten() {
            if entry.file_type().is_dir() {
                let p = entry.path().to_path_buf();
                if chrome2rust_core::discovery::is_cache_data_dir(&p) && !candidate_dirs.contains(&p) {
                    candidate_dirs.push(p);
                }
            }
        }

        for dir in candidate_dirs {
            let canon = dir.canonicalize().unwrap_or_else(|_| dir.clone());
            if !visited_dirs.insert(canon) {
                continue;
            }

            if dir.join("data_0").is_file() || dir.join("data_1").is_file() {
                let (mut bf_entries, mut bf_warn) = blockfile::scan_blockfile_cache(&dir, opts);
                entries.append(&mut bf_entries);
                warnings.append(&mut bf_warn);
            } else {
                let (mut sc_entries, mut sc_warn) = simple::scan_simple_cache(&dir, opts);
                entries.append(&mut sc_entries);
                warnings.append(&mut sc_warn);
            }
        }
    }

    entries.retain(|e| matches_cache_filter(e, opts));
    (entries, warnings)
}

/// Deletes standalone cache files (`*_0` Simple Cache files or `f_xxxxxx` Blockfile separate files).
/// Entries embedded inside shared Blockfile `data_1`/`data_2`/`data_3` containers are skipped.
pub fn delete_cache_entries(entries: &[&CacheEntry]) -> (usize, Vec<String>) {
    let mut deleted = 0usize;
    let mut skipped = Vec::new();
    for entry in entries {
        let Some(loc) = &entry.location else {
            skipped.push(format!("{}: no file location", entry.cache_name));
            continue;
        };
        match loc.backend {
            CacheBackendKind::SimpleCache => {
                if loc.primary_file.is_file() {
                    if let Err(e) = std::fs::remove_file(&loc.primary_file) {
                        skipped.push(format!("{}: {e}", entry.cache_name));
                    } else {
                        if let Some(alt) = &loc.simple_alt_stream1_file
                            && alt.is_file()
                        {
                            let _ = std::fs::remove_file(alt);
                        }
                        deleted += 1;
                    }
                } else {
                    skipped.push(format!("{}: file already missing", entry.cache_name));
                }
            }
            CacheBackendKind::Blockfile => {
                if let Some(BlockfileDataLocation::SeparateFile { path, .. }) = &loc.blockfile_stream1 {
                    if path.is_file() {
                        if let Err(e) = std::fs::remove_file(path) {
                            skipped.push(format!("{}: {e}", entry.cache_name));
                        } else {
                            deleted += 1;
                        }
                    } else {
                        skipped.push(format!("{}: separate file already missing", entry.cache_name));
                    }
                } else {
                    skipped.push(format!(
                        "{}: embedded in blockfile data_N (cannot delete single entry)",
                        entry.cache_name
                    ));
                }
            }
        }
    }
    (deleted, skipped)
}

#[allow(dead_code)]
fn _keep_imports(_: fn(i64) -> Option<DateTime<Utc>>, _: fn(&str) -> Option<DateTime<Utc>>) {
    let _ = chrome_us_to_datetime;
    let _ = parse_http_date;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_partitioned_cache_keys() {
        let k1 = "1/0/_dk_https://example.com https://frame.example.com https://cdn.example.com/app.js";
        let (u1, s1, f1) = parse_cache_key(k1);
        assert_eq!(u1, "https://cdn.example.com/app.js");
        assert_eq!(s1.as_deref(), Some("https://example.com"));
        assert_eq!(f1.as_deref(), Some("https://frame.example.com"));

        let k2 = "_dk_http://127.0.0.1 http://127.0.0.1 http://127.0.0.1:8080/style.css";
        let (u2, s2, f2) = parse_cache_key(k2);
        assert_eq!(u2, "http://127.0.0.1:8080/style.css");
        assert_eq!(s2.as_deref(), Some("http://127.0.0.1"));
        assert_eq!(f2.as_deref(), Some("http://127.0.0.1"));

        let k3 = "https://plain.example.com/logo.png";
        let (u3, s3, f3) = parse_cache_key(k3);
        assert_eq!(u3, k3);
        assert_eq!(s3, None);
        assert_eq!(f3, None);

        let k4 = "https://cdn.example.com/bundle.js https://app.example.com";
        let (u4, s4, f4) = parse_cache_key(k4);
        assert_eq!(u4, "https://cdn.example.com/bundle.js");
        assert_eq!(s4.as_deref(), Some("https://app.example.com"));
        assert_eq!(f4, None);
    }
}
