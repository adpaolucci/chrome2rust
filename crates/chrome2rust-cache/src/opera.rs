use crate::decompress::decompress_payload_for_type;
use crate::pickle::ParsedHeader;
use crate::{CacheEntry, CacheScanOptions, hex_lower, load_cache_from_paths};
use chrome2rust_core::discovery::{
    UnifiedBrowserKind, discover_opera_profiles, find_cache_dirs_in_profile, resolve_unified_targets,
};
use chrome2rust_core::error::{ChromeError, DiagnosticWarning};
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
pub struct OperaCacheEntry {
    pub url: String,
    pub content_type: Option<String>,
    pub content_encoding: Option<String>,
    pub detected_content_type: Option<String>,
    pub detected_extension: Option<String>,
    #[serde(default)]
    pub mime_mismatch: bool,
    pub file_size: usize,
    pub last_visited: Option<DateTime<Utc>>,
    pub last_modified: Option<DateTime<Utc>>,
    pub cache_file: String,
    pub backend: String,
    pub headers: Vec<ParsedHeader>,
    pub payload_sha256: Option<String>,
    #[serde(skip)]
    pub disk_path: Option<PathBuf>,
    #[serde(skip)]
    pub blink_entry: Option<CacheEntry>,
}

impl OperaCacheEntry {
    pub fn read_decompressed_payload(&self) -> Vec<u8> {
        if let Some(blink) = &self.blink_entry {
            return blink.read_decompressed_payload().unwrap_or_default();
        }
        if let Some(path) = &self.disk_path
            && let Ok(raw) = std::fs::read(path)
        {
            return decompress_payload_for_type(&raw, self.content_encoding.as_deref(), self.content_type.as_deref())
                .unwrap_or(raw);
        }
        Vec::new()
    }
}

fn read_be_uint_n(slice: &[u8]) -> usize {
    let mut val = 0usize;
    for &b in slice {
        val = (val << 8) | (b as usize);
    }
    val
}

fn sanitize_presto_rel_path(cache_dir: &Path, rel: &str) -> Option<PathBuf> {
    let trimmed = rel.trim_matches('\0').trim();
    if trimmed.is_empty() {
        return None;
    }
    let mut out = cache_dir.to_path_buf();
    for comp in Path::new(trimmed).components() {
        if let std::path::Component::Normal(seg) = comp {
            out.push(seg);
        } else {
            return None;
        }
    }
    if out.is_file() { Some(out) } else { None }
}

/// Parses Opera Presto `dcache4.url` binary TLV index in pure safe Rust.
pub fn parse_presto_dcache4(dcache_path: &Path, compute_hashes: bool) -> Result<Vec<OperaCacheEntry>, ChromeError> {
    let bytes = std::fs::read(dcache_path).map_err(|e| ChromeError::Io {
        path: dcache_path.display().to_string(),
        source: e,
    })?;
    if bytes.len() < 12 {
        return Err(ChromeError::InvalidFormat(
            "dcache4.url shorter than 12-byte header".into(),
        ));
    }
    let tag_len = u16::from_be_bytes([bytes[8], bytes[9]]) as usize;
    let len_len = u16::from_be_bytes([bytes[10], bytes[11]]) as usize;
    if !(1..=2).contains(&tag_len) || !(1..=4).contains(&len_len) {
        return Err(ChromeError::InvalidFormat(format!(
            "unsupported dcache4.url TLV sizes: tag_len={tag_len}, len_len={len_len}"
        )));
    }

    let cache_dir = dcache_path.parent().unwrap_or_else(|| Path::new("."));
    let flag_mask = if tag_len == 1 { 0x80usize } else { 0x8000usize };

    let mut pos = 12usize;
    let mut out = Vec::new();
    while pos + tag_len <= bytes.len() {
        let tag = read_be_uint_n(&bytes[pos..pos + tag_len]);
        pos += tag_len;
        if (tag & flag_mask) != 0 {
            continue;
        }
        if pos + len_len > bytes.len() {
            break;
        }
        let rec_len = read_be_uint_n(&bytes[pos..pos + len_len]);
        pos += len_len;
        let Some(rec_end) = pos.checked_add(rec_len) else {
            break;
        };
        if rec_end > bytes.len() {
            break;
        }
        let payload = &bytes[pos..rec_end];
        pos = rec_end;

        if tag == 0x01
            && let Some(entry) = parse_presto_record(payload, cache_dir, tag_len, len_len, compute_hashes)
        {
            out.push(entry);
        }
    }

    Ok(out)
}

fn parse_presto_record(
    rec: &[u8],
    cache_dir: &Path,
    tag_len: usize,
    len_len: usize,
    compute_hashes: bool,
) -> Option<OperaCacheEntry> {
    let flag_mask = if tag_len == 1 { 0x80usize } else { 0x8000usize };
    let mut pos = 0usize;
    let mut url = String::new();
    let mut last_visited = None;
    let mut last_modified = None;
    let mut file_size = 0usize;
    let mut cache_file = String::new();
    let mut content_type = None;
    let mut content_encoding = None;
    let mut headers = Vec::new();

    while pos + tag_len <= rec.len() {
        let tag = read_be_uint_n(&rec[pos..pos + tag_len]);
        pos += tag_len;
        if (tag & flag_mask) != 0 {
            continue;
        }
        if pos + len_len > rec.len() {
            break;
        }
        let slen = read_be_uint_n(&rec[pos..pos + len_len]);
        pos += len_len;
        let send = pos.checked_add(slen)?;
        if send > rec.len() {
            break;
        }
        let val = &rec[pos..send];
        pos = send;

        match tag {
            0x03 => url = String::from_utf8_lossy(val).trim_end_matches('\0').to_string(),
            0x04 if val.len() >= 4 => {
                let ts = u32::from_be_bytes(val[0..4].try_into().ok()?) as i64;
                last_visited = unix_secs_to_datetime(ts);
            }
            0x05 if val.len() >= 4 => {
                let ts = u32::from_be_bytes(val[0..4].try_into().ok()?) as i64;
                last_modified = unix_secs_to_datetime(ts);
            }
            0x07 if val.len() >= 4 => {
                file_size = u32::from_be_bytes(val[0..4].try_into().ok()?) as usize;
            }
            0x08 => {
                cache_file = String::from_utf8_lossy(val).trim_end_matches('\0').to_string();
            }
            0x09 | 0x0A | 0x0B | 0x4A => {
                let hdr_text = String::from_utf8_lossy(val);
                if tag == 0x4A && !hdr_text.contains(':') && !hdr_text.trim().is_empty() {
                    content_type = Some(hdr_text.trim_end_matches('\0').trim().to_string());
                } else {
                    for line in hdr_text.lines() {
                        if let Some((n, v)) = line.split_once(':') {
                            let name = n.trim().to_string();
                            let v_clean = v.trim().trim_end_matches('\0').to_string();
                            if name.eq_ignore_ascii_case("content-type") && content_type.is_none() {
                                content_type = Some(v_clean.split(';').next().unwrap_or(&v_clean).trim().to_string());
                            } else if name.eq_ignore_ascii_case("content-encoding") && content_encoding.is_none() {
                                content_encoding = Some(v_clean.clone());
                            }
                            headers.push(ParsedHeader { name, value: v_clean });
                        }
                    }
                }
            }
            _ => {}
        }
    }

    if url.is_empty() {
        return None;
    }

    let disk_path = sanitize_presto_rel_path(cache_dir, &cache_file);
    let mut detected_content_type = None;
    let mut detected_extension = None;
    let mut mime_mismatch = false;
    let mut payload_sha256 = None;

    if let Some(ref dp) = disk_path
        && let Ok(raw) = std::fs::read(dp)
    {
        let dec =
            decompress_payload_for_type(&raw, content_encoding.as_deref(), content_type.as_deref()).unwrap_or(raw);
        if file_size == 0 {
            file_size = dec.len();
        }
        let det = detect_content(&dec, content_type.as_deref(), Some(&url), None);
        detected_content_type = det.mime;
        detected_extension = det.extension;
        mime_mismatch = det.mime_mismatch;
        if compute_hashes && !dec.is_empty() {
            payload_sha256 = Some(hex_lower(&Sha256::digest(&dec)));
        }
    }

    Some(OperaCacheEntry {
        url,
        content_type,
        content_encoding,
        detected_content_type,
        detected_extension,
        mime_mismatch,
        file_size,
        last_visited,
        last_modified,
        cache_file,
        backend: "Presto".to_string(),
        headers,
        payload_sha256,
        disk_path,
        blink_entry: None,
    })
}

pub fn scan_opera_cache(target: Option<&Path>, compute_hashes: bool) -> (Vec<OperaCacheEntry>, Vec<DiagnosticWarning>) {
    let mut warnings = Vec::new();
    let mut out = Vec::new();
    let mut blink_dirs = Vec::new();
    let mut presto_files = Vec::new();

    if let Some(p) = target {
        if p.is_file()
            && p.file_name()
                .is_some_and(|n| n.to_string_lossy().eq_ignore_ascii_case("dcache4.url"))
        {
            presto_files.push(p.to_path_buf());
        } else if p.is_dir() {
            for cand in [p.join("dcache4.url"), p.join("cache").join("dcache4.url")] {
                if cand.is_file() {
                    presto_files.push(cand);
                }
            }
            for c in find_cache_dirs_in_profile(p) {
                if !blink_dirs.contains(&c) {
                    blink_dirs.push(c);
                }
            }
            if blink_dirs.is_empty() && presto_files.is_empty() {
                for t in resolve_unified_targets(&[p.to_path_buf()]) {
                    if t.browser == UnifiedBrowserKind::OperaPresto {
                        for c in t.cache_dirs {
                            let dc = c.join("dcache4.url");
                            if dc.is_file() && !presto_files.contains(&dc) {
                                presto_files.push(dc);
                            }
                        }
                        let dc = t.profile_dir.join("dcache4.url");
                        if dc.is_file() && !presto_files.contains(&dc) {
                            presto_files.push(dc);
                        }
                    } else if matches!(t.browser, UnifiedBrowserKind::Opera | UnifiedBrowserKind::OperaGx) {
                        for c in t.cache_dirs {
                            if !blink_dirs.contains(&c) {
                                blink_dirs.push(c);
                            }
                        }
                    }
                }
                if blink_dirs.is_empty() && presto_files.is_empty() {
                    blink_dirs.push(p.to_path_buf());
                }
            }
        }
    } else {
        for prof in discover_opera_profiles() {
            if prof.browser == UnifiedBrowserKind::OperaPresto {
                for c in &prof.cache_dirs {
                    let dc = c.join("dcache4.url");
                    if dc.is_file() {
                        presto_files.push(dc);
                    }
                }
            } else {
                for c in prof.cache_dirs {
                    if !blink_dirs.contains(&c) {
                        blink_dirs.push(c);
                    }
                }
            }
        }
    }

    for dc in presto_files {
        match parse_presto_dcache4(&dc, compute_hashes) {
            Ok(mut items) => out.append(&mut items),
            Err(e) => warnings.push(DiagnosticWarning::warn(
                "opera_cache",
                &dc,
                format!("Failed parsing Presto dcache4.url: {e}"),
            )),
        }
    }

    if !blink_dirs.is_empty() {
        let opts = CacheScanOptions {
            compute_hashes,
            ..Default::default()
        };
        let (blink_entries, mut bw) = load_cache_from_paths(&blink_dirs, &opts);
        warnings.append(&mut bw);
        for be in blink_entries {
            out.push(OperaCacheEntry {
                url: be.url.clone(),
                content_type: be.content_type.clone(),
                content_encoding: be.content_encoding.clone(),
                detected_content_type: be.detected_content_type.clone(),
                detected_extension: be.detected_extension.clone(),
                mime_mismatch: be.mime_mismatch,
                file_size: be.file_size,
                last_visited: be.last_accessed,
                last_modified: be.server_time.or(be.record_created_time),
                cache_file: be.cache_name.clone(),
                backend: format!("Blink ({})", be.backend.as_str()),
                headers: be.headers.clone(),
                payload_sha256: be.payload_sha256.clone(),
                disk_path: None,
                blink_entry: Some(be),
            });
        }
    }

    out.sort_by(|a, b| b.last_visited.cmp(&a.last_visited).then_with(|| a.url.cmp(&b.url)));
    (out, warnings)
}

/// Builds a synthetic Opera Presto `dcache4.url` binary TLV index for tests.
pub fn build_synthetic_presto_dcache4(records: &[(&str, u32, u32, &str, &str)]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&0x0001_0000u32.to_be_bytes()); // version
    out.extend_from_slice(&1u32.to_be_bytes()); // id_num
    out.extend_from_slice(&1u16.to_be_bytes()); // tag_len = 1
    out.extend_from_slice(&2u16.to_be_bytes()); // len_len = 2

    for (url, last_visited, size, cache_file, content_type) in records {
        let mut inner = Vec::new();
        let mut push_tlv = |tag: u8, data: &[u8]| {
            inner.push(tag);
            inner.extend_from_slice(&(data.len() as u16).to_be_bytes());
            inner.extend_from_slice(data);
        };
        push_tlv(0x03, url.as_bytes());
        push_tlv(0x04, &last_visited.to_be_bytes());
        push_tlv(0x05, &last_visited.to_be_bytes());
        push_tlv(0x07, &size.to_be_bytes());
        push_tlv(0x08, cache_file.as_bytes());
        push_tlv(0x4A, content_type.as_bytes());

        out.push(0x01);
        out.extend_from_slice(&(inner.len() as u16).to_be_bytes());
        out.extend_from_slice(&inner);
    }
    out
}

pub struct OperaCacheTableProvider {
    target: Option<PathBuf>,
}

impl OperaCacheTableProvider {
    pub fn new(target: Option<PathBuf>) -> Self {
        Self { target }
    }
}

impl TableProvider for OperaCacheTableProvider {
    fn tool_id(&self) -> &'static str {
        "chrome2rust_opera_cache"
    }

    fn description(&self) -> &'static str {
        "Inspect Opera Blink (Stable/GX) and Opera Presto (dcache4.url) HTTP cache entries (OperaCacheView equivalent)."
    }

    fn schema(&self) -> TableSchema {
        TableSchema::new(
            self.tool_id(),
            "Opera HTTP Cache",
            vec![
                ColumnDef::new("url", "URL", ColumnType::Text).with_width_hint(320),
                ColumnDef::new("content_type", "Content Type", ColumnType::Text).with_width_hint(140),
                ColumnDef::new("file_size", "File Size", ColumnType::BytesSize).with_width_hint(90),
                ColumnDef::new("last_visited", "Last Visited", ColumnType::Timestamp).with_width_hint(160),
                ColumnDef::new("last_modified", "Last Modified", ColumnType::Timestamp).with_width_hint(160),
                ColumnDef::new("cache_file", "Cache File", ColumnType::Text).with_width_hint(140),
                ColumnDef::new("backend", "Backend", ColumnType::Text).with_width_hint(110),
                ColumnDef::new("sha256", "SHA-256", ColumnType::Text).with_width_hint(180),
            ],
        )
        .with_default_sort(3, SortDirection::Desc)
    }

    fn query(&self, req: &TableQuery) -> Result<TableData, TableError> {
        let (entries, _) = scan_opera_cache(self.target.as_deref(), true);
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
                        e.last_visited.map(CellValue::Timestamp).unwrap_or(CellValue::Null),
                        e.last_modified.map(CellValue::Timestamp).unwrap_or(CellValue::Null),
                        CellValue::Text(e.cache_file.clone()),
                        CellValue::Text(e.backend.clone()),
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
    use tempfile::TempDir;

    #[test]
    fn test_opera_presto_dcache4_and_provider() {
        let dir = TempDir::new().unwrap();
        let payload = b"console.log('opera presto');";
        std::fs::write(dir.path().join("opr00001.tmp"), payload).unwrap();
        let dc = build_synthetic_presto_dcache4(&[(
            "https://opera.example.test/app.js",
            1_794_700_800,
            payload.len() as u32,
            "opr00001.tmp",
            "application/javascript",
        )]);
        std::fs::write(dir.path().join("dcache4.url"), dc).unwrap();

        let provider = OperaCacheTableProvider::new(Some(dir.path().to_path_buf()));
        let data = provider.query(&TableQuery::default()).unwrap();
        assert_eq!(data.total_rows, 1);
        assert_eq!(
            data.rows[0].cells[0],
            CellValue::Text("https://opera.example.test/app.js".into())
        );
        assert_eq!(data.rows[0].cells[6], CellValue::Text("Presto".into()));
        assert_eq!(data.rows[0].raw_bytes.as_deref(), Some(payload.as_slice()));
    }
}
