use crate::decompress::decompress_payload_for_type;
use crate::hex_lower;
use crate::pickle::ParsedHeader;
use chrome2rust_core::discovery::{
    UnifiedBrowserKind, discover_firefox_profiles, find_firefox_cache_dirs, resolve_unified_targets,
};
use chrome2rust_core::error::DiagnosticWarning;
use chrome2rust_core::magic::detect_content;
use chrome2rust_core::time::unix_secs_to_datetime;
use chrono::{DateTime, Utc};
use guap_table::{
    CellValue, ColumnDef, ColumnType, Row, SortDirection, TableData, TableError, TableProvider, TableQuery,
    TableSchema, apply_query,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirefoxCacheEntry {
    pub entry_hash: String,
    pub filename: String,
    pub raw_key: String,
    pub url: String,
    pub status_code: Option<u16>,
    pub server_response: String,
    pub content_type: Option<String>,
    pub content_encoding: Option<String>,
    pub detected_content_type: Option<String>,
    pub detected_extension: Option<String>,
    #[serde(default)]
    pub mime_mismatch: bool,
    pub file_signature: Option<String>,
    pub file_size: usize,
    pub compressed_size: usize,
    pub fetch_count: u32,
    pub last_fetched: Option<DateTime<Utc>>,
    pub last_modified: Option<DateTime<Utc>>,
    pub expiration: Option<DateTime<Utc>>,
    pub frecency: u32,
    pub headers: Vec<ParsedHeader>,
    pub payload_sha256: Option<String>,
    #[serde(skip)]
    pub file_path: PathBuf,
    #[serde(skip)]
    pub payload_len: usize,
}

impl FirefoxCacheEntry {
    pub fn read_raw_payload(&self) -> Vec<u8> {
        if self.payload_len == 0 {
            return Vec::new();
        }
        let Ok(bytes) = std::fs::read(&self.file_path) else {
            return Vec::new();
        };
        let end = self.payload_len.min(bytes.len());
        bytes[..end].to_vec()
    }

    pub fn read_decompressed_payload(&self) -> Vec<u8> {
        let raw = self.read_raw_payload();
        if raw.is_empty() {
            return raw;
        }
        decompress_payload_for_type(&raw, self.content_encoding.as_deref(), self.content_type.as_deref()).unwrap_or(raw)
    }
}

/// Strips Firefox Necko partition prefixes (e.g. `:https://...`, `O^partitionKey=...:https://...`,
/// `a,b,:http://...`) to recover the underlying request URL.
pub fn normalize_firefox_cache_key(raw_key: &str) -> String {
    let trimmed = raw_key.trim_matches('\0').trim();
    if let Some(idx) = trimmed.find(":https://").or_else(|| trimmed.find(":http://")) {
        return trimmed[idx + 1..].to_string();
    }
    if let Some(idx) = trimmed.find("https://").or_else(|| trimmed.find("http://")) {
        return trimmed[idx..].to_string();
    }
    trimmed.to_string()
}

/// Solves Firefox cache2 `meta_offset = payload_len + 2 * chunk_count` where each 256 KiB chunk
/// carries a 2-byte CRC16 entry right before `meta_offset`.
fn solve_firefox_payload_len(meta_offset: usize) -> Option<usize> {
    if meta_offset == 0 {
        return Some(0);
    }
    const CHUNK_SIZE: usize = 262_144;
    let max_chunks = meta_offset / 2;
    let approx_chunks = meta_offset.div_ceil(CHUNK_SIZE).max(1);
    for c in approx_chunks..=(approx_chunks + 4).min(max_chunks) {
        if let Some(plen) = meta_offset.checked_sub(2 * c)
            && plen > 0
            && plen.div_ceil(CHUNK_SIZE) == c
        {
            return Some(plen);
        }
    }
    // Fallback brute check for edge sizes
    for c in 1..=max_chunks.min(4096) {
        if let Some(plen) = meta_offset.checked_sub(2 * c)
            && plen > 0
            && plen.div_ceil(CHUNK_SIZE) == c
        {
            return Some(plen);
        }
    }
    None
}

/// Parses a single Firefox `cache2/entries/<40-hex>` entry file.
pub fn parse_firefox_cache2_entry(path: &Path, compute_hashes: bool) -> Option<FirefoxCacheEntry> {
    let bytes = std::fs::read(path).ok()?;
    if bytes.len() < 32 {
        return None;
    }
    let len = bytes.len();
    let meta_offset = u32::from_be_bytes(bytes[len - 4..len].try_into().ok()?) as usize;
    if meta_offset > len - 4 {
        return None;
    }
    let meta = &bytes[meta_offset..len - 4];
    if meta.len() < 28 {
        return None;
    }

    let version = u32::from_be_bytes(meta[0..4].try_into().ok()?);
    let fetch_count = u32::from_be_bytes(meta[4..8].try_into().ok()?);
    let last_fetched_secs = u32::from_be_bytes(meta[8..12].try_into().ok()?) as i64;
    let last_modified_secs = u32::from_be_bytes(meta[12..16].try_into().ok()?) as i64;
    let frecency = u32::from_be_bytes(meta[16..20].try_into().ok()?);
    let expiration_secs = u32::from_be_bytes(meta[20..24].try_into().ok()?) as i64;
    let key_size = u32::from_be_bytes(meta[24..28].try_into().ok()?) as usize;

    let key_start: usize = if version >= 3 && meta.len() >= 32 { 32 } else { 28 };
    let key_end = key_start.checked_add(key_size)?;
    if key_end > meta.len() {
        return None;
    }

    let raw_key = String::from_utf8_lossy(&meta[key_start..key_end])
        .trim_end_matches('\0')
        .to_string();
    if raw_key.is_empty() {
        return None;
    }
    let url = normalize_firefox_cache_key(&raw_key);

    // Parse NUL-delimited metadata elements after key (skip optional trailing 4-byte metadata hash if misaligned).
    let mut elem_pos = key_end;
    if elem_pos < meta.len() && meta[elem_pos] == 0 {
        elem_pos += 1;
    }
    let mut response_head = String::new();
    let elem_slice = &meta[elem_pos..];
    let parts: Vec<&[u8]> = elem_slice.split(|&b| b == 0).collect();
    let mut i = 0usize;
    while i + 1 < parts.len() {
        let ek = String::from_utf8_lossy(parts[i]);
        if ek == "response-head" || ek == "original-response-headers" {
            let val = String::from_utf8_lossy(parts[i + 1]).to_string();
            if ek == "response-head" || response_head.is_empty() {
                response_head = val;
            }
            i += 2;
        } else {
            i += 2;
        }
    }

    let (status_code, server_response, headers, content_type, content_encoding) =
        parse_http_response_head(&response_head);

    let payload_len = solve_firefox_payload_len(meta_offset).unwrap_or(meta_offset);
    let raw_payload = &bytes[..payload_len.min(meta_offset)];
    let decompressed = decompress_payload_for_type(raw_payload, content_encoding.as_deref(), content_type.as_deref())
        .unwrap_or_else(|_| raw_payload.to_vec());

    let det = detect_content(&decompressed, content_type.as_deref(), Some(&url), None);
    let payload_sha256 = if compute_hashes && !decompressed.is_empty() {
        Some(hex_lower(&Sha256::digest(&decompressed)))
    } else {
        None
    };

    let filename = path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default();

    Some(FirefoxCacheEntry {
        entry_hash: filename.clone(),
        filename,
        raw_key,
        url,
        status_code,
        server_response,
        content_type,
        content_encoding,
        detected_content_type: det.mime,
        detected_extension: det.extension,
        mime_mismatch: det.mime_mismatch,
        file_signature: det.signature,
        file_size: decompressed.len(),
        compressed_size: payload_len,
        fetch_count,
        last_fetched: unix_secs_to_datetime(last_fetched_secs),
        last_modified: unix_secs_to_datetime(last_modified_secs),
        expiration: unix_secs_to_datetime(expiration_secs),
        frecency,
        headers,
        payload_sha256,
        file_path: path.to_path_buf(),
        payload_len,
    })
}

fn parse_http_response_head(head: &str) -> (Option<u16>, String, Vec<ParsedHeader>, Option<String>, Option<String>) {
    let mut lines = head.lines();
    let status_line = lines.next().unwrap_or("").trim().to_string();
    let status_code = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok());

    let mut headers = Vec::new();
    let mut content_type = None;
    let mut content_encoding = None;

    for line in lines {
        let t = line.trim();
        if t.is_empty() {
            continue;
        }
        if let Some((name, val)) = t.split_once(':') {
            let n = name.trim().to_string();
            let v = val.trim().to_string();
            if n.eq_ignore_ascii_case("content-type") && content_type.is_none() {
                content_type = Some(v.split(';').next().unwrap_or(&v).trim().to_string());
            } else if n.eq_ignore_ascii_case("content-encoding") && content_encoding.is_none() {
                content_encoding = Some(v.clone());
            }
            headers.push(ParsedHeader { name: n, value: v });
        }
    }

    (status_code, status_line, headers, content_type, content_encoding)
}

/// Scans one or more Firefox cache directories (`cache2/entries` or Firefox profile/root).
pub fn scan_firefox_cache(
    target: Option<&Path>,
    compute_hashes: bool,
) -> (Vec<FirefoxCacheEntry>, Vec<DiagnosticWarning>) {
    let mut warnings = Vec::new();
    let mut dirs = Vec::new();

    if let Some(p) = target {
        if p.is_file() {
            if let Some(entry) = parse_firefox_cache2_entry(p, compute_hashes) {
                return (vec![entry], warnings);
            }
            return (Vec::new(), warnings);
        }
        for d in find_firefox_cache_dirs(p) {
            if !dirs.contains(&d) {
                dirs.push(d);
            }
        }
        if dirs.is_empty() && p.is_dir() {
            // Also check Profiles/* subdirs or multi-browser container via resolve_unified_targets
            if let Ok(rd) = std::fs::read_dir(p.join("Profiles")) {
                for e in rd.flatten() {
                    for d in find_firefox_cache_dirs(&e.path()) {
                        if !dirs.contains(&d) {
                            dirs.push(d);
                        }
                    }
                }
            }
            if dirs.is_empty() {
                for t in resolve_unified_targets(&[p.to_path_buf()]) {
                    if t.browser == UnifiedBrowserKind::Firefox {
                        for d in t.cache_dirs {
                            if !dirs.contains(&d) {
                                dirs.push(d);
                            }
                        }
                    }
                }
            }
        }
    } else {
        for prof in discover_firefox_profiles() {
            for d in prof.cache_dirs {
                if !dirs.contains(&d) {
                    dirs.push(d);
                }
            }
        }
    }

    let mut entries = Vec::new();
    let mut visited_dirs = std::collections::HashSet::new();
    for dir in dirs {
        let entries_dir = if dir.join("entries").is_dir() {
            dir.join("entries")
        } else {
            dir
        };
        let canon = entries_dir.canonicalize().unwrap_or_else(|_| entries_dir.clone());
        if !visited_dirs.insert(canon) {
            continue;
        }
        let Ok(rd) = std::fs::read_dir(&entries_dir) else {
            warnings.push(DiagnosticWarning::warn(
                "fx_cache",
                &entries_dir,
                "Unable to read Firefox cache2 entries directory",
            ));
            continue;
        };
        for item in rd.flatten() {
            let fp = item.path();
            if !fp.is_file() {
                continue;
            }
            let fname = item.file_name().to_string_lossy().to_string();
            if fname.len() == 40
                && fname.bytes().all(|b| b.is_ascii_hexdigit())
                && let Some(parsed) = parse_firefox_cache2_entry(&fp, compute_hashes)
            {
                entries.push(parsed);
            }
        }
    }

    entries.sort_by(|a, b| b.last_fetched.cmp(&a.last_fetched).then_with(|| a.url.cmp(&b.url)));
    (entries, warnings)
}

/// Encodes a synthetic Firefox `cache2/entries/<hash>` file (primarily for tests & fixtures).
pub fn build_synthetic_firefox_cache2_entry(
    key: &str,
    response_head: &str,
    payload: &[u8],
    fetch_count: u32,
    last_fetched_secs: u32,
    expiration_secs: u32,
    frecency: u32,
) -> Vec<u8> {
    let mut out = Vec::from(payload);
    let chunks = if payload.is_empty() {
        0
    } else {
        payload.len().div_ceil(262_144)
    };
    out.resize(out.len() + chunks * 2, 0xAB); // synthetic 2-byte chunk CRCs
    let meta_offset = out.len() as u32;

    // v3 metadata header (32 bytes)
    out.extend_from_slice(&3u32.to_be_bytes());
    out.extend_from_slice(&fetch_count.to_be_bytes());
    out.extend_from_slice(&last_fetched_secs.to_be_bytes());
    out.extend_from_slice(&last_fetched_secs.to_be_bytes());
    out.extend_from_slice(&frecency.to_be_bytes());
    out.extend_from_slice(&expiration_secs.to_be_bytes());
    out.extend_from_slice(&(key.len() as u32).to_be_bytes());
    out.extend_from_slice(&0u32.to_be_bytes()); // flags
    out.extend_from_slice(key.as_bytes());
    out.push(0);
    out.extend_from_slice(b"response-head\0");
    out.extend_from_slice(response_head.as_bytes());
    out.push(0);
    out.extend_from_slice(&meta_offset.to_be_bytes());
    out
}

pub struct FirefoxCacheTableProvider {
    target: Option<PathBuf>,
}

impl FirefoxCacheTableProvider {
    pub fn new(target: Option<PathBuf>) -> Self {
        Self { target }
    }
}

impl TableProvider for FirefoxCacheTableProvider {
    fn tool_id(&self) -> &'static str {
        "chrome2rust_fx_cache"
    }

    fn description(&self) -> &'static str {
        "Inspect Mozilla Firefox cache2/entries metadata, HTTP headers, timestamps, and payloads."
    }

    fn schema(&self) -> TableSchema {
        TableSchema::new(
            self.tool_id(),
            "Firefox Cache2 Entries",
            vec![
                ColumnDef::new("url", "URL", ColumnType::Text).with_width_hint(320),
                ColumnDef::new("content_type", "Content Type", ColumnType::Text).with_width_hint(140),
                ColumnDef::new("file_size", "File Size", ColumnType::BytesSize).with_width_hint(90),
                ColumnDef::new("fetch_count", "Fetch Count", ColumnType::Uint).with_width_hint(85),
                ColumnDef::new("last_fetched", "Last Fetched", ColumnType::Timestamp).with_width_hint(160),
                ColumnDef::new("expiration", "Expiration", ColumnType::Timestamp).with_width_hint(160),
                ColumnDef::new("entry_hash", "Entry Hash", ColumnType::Text).with_width_hint(180),
                ColumnDef::new("filename", "Filename", ColumnType::Text).with_width_hint(140),
                ColumnDef::new("status_code", "Status", ColumnType::Uint).with_width_hint(70),
                ColumnDef::new("sha256", "SHA-256", ColumnType::Text).with_width_hint(180),
            ],
        )
        .with_default_sort(4, SortDirection::Desc)
    }

    fn query(&self, req: &TableQuery) -> Result<TableData, TableError> {
        let (entries, _) = scan_firefox_cache(self.target.as_deref(), true);
        let rows: Vec<Row> = entries
            .into_iter()
            .enumerate()
            .map(|(idx, e)| {
                let raw = e.read_decompressed_payload();
                let ct = e
                    .content_type
                    .clone()
                    .or(e.detected_content_type.clone())
                    .unwrap_or_default();
                let mut row = Row::new(
                    idx as u64 + 1,
                    vec![
                        CellValue::Text(e.url.clone()),
                        CellValue::Text(ct),
                        CellValue::Bytes(e.file_size as u64),
                        CellValue::Uint(e.fetch_count as u64),
                        e.last_fetched.map(CellValue::Timestamp).unwrap_or(CellValue::Null),
                        e.expiration.map(CellValue::Timestamp).unwrap_or(CellValue::Null),
                        CellValue::Text(e.entry_hash.clone()),
                        CellValue::Text(e.filename.clone()),
                        e.status_code
                            .map(|s| CellValue::Uint(s as u64))
                            .unwrap_or(CellValue::Null),
                        e.payload_sha256.clone().map(CellValue::Text).unwrap_or(CellValue::Null),
                    ],
                )
                .with_detail_json(serde_json::to_value(&e).unwrap_or_default());
                if !raw.is_empty() {
                    row = row.with_raw_bytes(raw[..raw.len().min(65536)].to_vec());
                }
                row
            })
            .collect();
        apply_query(&self.schema(), &rows, req)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::Compression;
    use flate2::write::GzEncoder;
    use std::io::Write;
    use tempfile::TempDir;

    #[test]
    fn test_firefox_cache2_entry_parsing_and_provider() {
        let dir = TempDir::new().unwrap();
        let entries_dir = dir.path().join("cache2").join("entries");
        std::fs::create_dir_all(&entries_dir).unwrap();

        let mut gz = GzEncoder::new(Vec::new(), Compression::default());
        gz.write_all(b"<html><body>Firefox Cache2 OK</body></html>").unwrap();
        let gz_bytes = gz.finish().unwrap();

        let raw = build_synthetic_firefox_cache2_entry(
            "O^partitionKey=%28https%2Cexample.org%29:https://example.org/index.html",
            "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Encoding: gzip\r\n",
            &gz_bytes,
            5,
            1_794_700_800,
            1_794_787_200,
            120,
        );
        let hash_name = "A1B2C3D4E5F60708090A0B0C0D0E0F1011121314";
        std::fs::write(entries_dir.join(hash_name), raw).unwrap();

        let provider = FirefoxCacheTableProvider::new(Some(dir.path().to_path_buf()));
        let data = provider.query(&TableQuery::default()).unwrap();
        assert_eq!(data.total_rows, 1);
        assert_eq!(
            data.rows[0].cells[0],
            CellValue::Text("https://example.org/index.html".into())
        );
        assert_eq!(data.rows[0].cells[1], CellValue::Text("text/html".into()));
        assert_eq!(data.rows[0].cells[3], CellValue::Uint(5));
        assert_eq!(
            data.rows[0].raw_bytes.as_deref(),
            Some(b"<html><body>Firefox Cache2 OK</body></html>".as_slice())
        );
    }
}
