use crate::error::DiagnosticWarning;
use crate::sqlite_util::ForensicSqlite;
use crate::time::chrome_us_to_datetime;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::Path;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StorageAnalysis {
    pub local_storage: Vec<LevelDbKvRecord>,
    pub session_storage: Vec<LevelDbKvRecord>,
    pub indexed_db_origins: Vec<IndexedDbOrigin>,
    pub top_sites: Vec<TopSiteRecord>,
    pub favicons_count: usize,
    pub shortcuts: Vec<ShortcutRecord>,
    pub reporting_endpoints: Vec<ReportingEndpointRecord>,
    pub nel_policies: Vec<NelPolicyRecord>,
    pub network_persistent_state: Option<serde_json::Value>,
    pub certificates_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LevelDbKvRecord {
    pub origin: String,
    pub key: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndexedDbOrigin {
    pub origin_dir: String,
    pub total_bytes: u64,
    pub file_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TopSiteRecord {
    pub url: String,
    pub rank: i64,
    pub title: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShortcutRecord {
    pub text: String,
    pub url: String,
    pub description: String,
    pub last_access_time: Option<DateTime<Utc>>,
    pub number_of_hits: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportingEndpointRecord {
    pub origin: String,
    pub group_name: String,
    pub url: String,
    pub priority: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NelPolicyRecord {
    pub origin: String,
    pub received_ip: String,
    pub group_name: String,
    pub expires: Option<DateTime<Utc>>,
    pub last_access: Option<DateTime<Utc>>,
}

pub fn parse_storage_and_misc(
    profile_dir: &Path,
    warnings: &mut Vec<DiagnosticWarning>,
) -> StorageAnalysis {
    let mut out = StorageAnalysis::default();

    // 1. Local Storage/leveldb
    let ls_dir = profile_dir.join("Local Storage").join("leveldb");
    if ls_dir.is_dir() {
        out.local_storage = read_chrome_leveldb(&ls_dir, true, warnings);
    }

    // 2. Session Storage (LevelDB)
    let ss_dir = profile_dir.join("Session Storage");
    if ss_dir.is_dir() {
        out.session_storage = read_chrome_leveldb(&ss_dir, false, warnings);
    }

    // 3. IndexedDB directory inventory
    let idb_dir = profile_dir.join("IndexedDB");
    if idb_dir.is_dir()
        && let Ok(rd) = std::fs::read_dir(&idb_dir)
    {
        for entry in rd.flatten() {
            let p = entry.path();
            if p.is_dir() {
                let mut total_bytes = 0u64;
                let mut file_count = 0usize;
                for item in walkdir::WalkDir::new(&p).into_iter().flatten() {
                    if item.file_type().is_file() {
                        file_count += 1;
                        total_bytes += item.metadata().map(|m| m.len()).unwrap_or(0);
                    }
                }
                out.indexed_db_origins.push(IndexedDbOrigin {
                    origin_dir: entry.file_name().to_string_lossy().to_string(),
                    total_bytes,
                    file_count,
                });
            }
        }
        out.indexed_db_origins
            .sort_by(|a, b| b.total_bytes.cmp(&a.total_bytes));
    }

    // 4. Top Sites
    let ts_path = profile_dir.join("Top Sites");
    if ts_path.is_file()
        && let Ok(db) = ForensicSqlite::open_snapshot(&ts_path)
        && db.list_tables().contains("top_sites")
        && let Ok(mut stmt) = db
            .conn
            .prepare("SELECT url, url_rank, title FROM top_sites ORDER BY url_rank ASC")
        && let Ok(rows) = stmt.query_map([], |r| {
            Ok(TopSiteRecord {
                url: r.get(0).unwrap_or_default(),
                rank: r.get(1).unwrap_or(0),
                title: r.get(2).unwrap_or_default(),
            })
        })
    {
        out.top_sites.extend(rows.flatten());
    }

    // 5. Favicons count
    let fav_path = profile_dir.join("Favicons");
    if fav_path.is_file()
        && let Ok(db) = ForensicSqlite::open_snapshot(&fav_path)
        && db.list_tables().contains("favicons")
        && let Ok(cnt) = db
            .conn
            .query_row("SELECT COUNT(*) FROM favicons", [], |r| r.get::<_, i64>(0))
    {
        out.favicons_count = cnt.max(0) as usize;
    }

    // 6. Shortcuts (Omnibox history)
    let sc_path = profile_dir.join("Shortcuts");
    if sc_path.is_file()
        && let Ok(db) = ForensicSqlite::open_snapshot(&sc_path)
        && db.list_tables().contains("omni_box_shortcuts")
        && let Ok(mut stmt) = db.conn.prepare(
            "SELECT text, url, description, last_access_time, number_of_hits FROM omni_box_shortcuts ORDER BY number_of_hits DESC",
        )
        && let Ok(rows) = stmt.query_map([], |r| {
            Ok(ShortcutRecord {
                text: r.get(0).unwrap_or_default(),
                url: r.get(1).unwrap_or_default(),
                description: r.get(2).unwrap_or_default(),
                last_access_time: chrome_us_to_datetime(r.get::<_, i64>(3).unwrap_or(0)),
                number_of_hits: r.get(4).unwrap_or(0),
            })
        })
    {
        out.shortcuts.extend(rows.flatten());
    }

    // 7. Reporting and NEL
    let nel_path = profile_dir.join("Reporting and NEL");
    if nel_path.is_file()
        && let Ok(db) = ForensicSqlite::open_snapshot(&nel_path)
    {
        let tables = db.list_tables();
        if tables.contains("reporting_endpoints")
            && let Ok(mut stmt) = db.conn.prepare(
                "SELECT origin_scheme, origin_host, origin_port, group_name, url, priority FROM reporting_endpoints",
            )
            && let Ok(rows) = stmt.query_map([], |r| {
                let sch: String = r.get(0).unwrap_or_default();
                let host: String = r.get(1).unwrap_or_default();
                let port: i64 = r.get(2).unwrap_or(0);
                Ok(ReportingEndpointRecord {
                    origin: format!("{sch}://{host}:{port}"),
                    group_name: r.get(3).unwrap_or_default(),
                    url: r.get(4).unwrap_or_default(),
                    priority: r.get(5).unwrap_or(0),
                })
            })
        {
            out.reporting_endpoints.extend(rows.flatten());
        }
        if tables.contains("nel_policies")
            && let Ok(mut stmt) = db.conn.prepare(
                "SELECT origin_scheme, origin_host, origin_port, received_ip_address, group_name, expires_us_since_epoch, last_access_us_since_epoch FROM nel_policies",
            )
            && let Ok(rows) = stmt.query_map([], |r| {
                let sch: String = r.get(0).unwrap_or_default();
                let host: String = r.get(1).unwrap_or_default();
                let port: i64 = r.get(2).unwrap_or(0);
                Ok(NelPolicyRecord {
                    origin: format!("{sch}://{host}:{port}"),
                    received_ip: r.get(3).unwrap_or_default(),
                    group_name: r.get(4).unwrap_or_default(),
                    expires: chrome_us_to_datetime(r.get::<_, i64>(5).unwrap_or(0)),
                    last_access: chrome_us_to_datetime(r.get::<_, i64>(6).unwrap_or(0)),
                })
            })
        {
            out.nel_policies.extend(rows.flatten());
        }
    }

    // 8. Network Persistent State JSON
    let nps_path = profile_dir.join("Network Persistent State");
    if nps_path.is_file()
        && let Ok(s) = std::fs::read_to_string(&nps_path)
        && let Ok(v) = serde_json::from_str::<serde_json::Value>(&s)
    {
        out.network_persistent_state = Some(v);
    }

    // 9. ServerCertificate count
    let cert_path = profile_dir.join("ServerCertificate");
    if cert_path.is_file()
        && let Ok(db) = ForensicSqlite::open_snapshot(&cert_path)
        && db.list_tables().contains("certificates")
        && let Ok(cnt) = db
            .conn
            .query_row("SELECT COUNT(*) FROM certificates", [], |r| r.get::<_, i64>(0))
    {
        out.certificates_count = cnt.max(0) as usize;
    }

    out
}

/// Pure-Rust read-only LevelDB reader that parses `.ldb` SSTables and `.log` WAL files
/// without acquiring locks or writing to the evidence directory.
fn read_chrome_leveldb(
    dir: &Path,
    is_local_storage: bool,
    warnings: &mut Vec<DiagnosticWarning>,
) -> Vec<LevelDbKvRecord> {
    let mut kv: BTreeMap<(String, String), Option<String>> = BTreeMap::new();

    let mut ldb_files = Vec::new();
    let mut log_files = Vec::new();
    if let Ok(rd) = std::fs::read_dir(dir) {
        for entry in rd.flatten() {
            let p = entry.path();
            if !p.is_file() {
                continue;
            }
            match p.extension().and_then(|e| e.to_str()) {
                Some("ldb") | Some("sst") => ldb_files.push(p),
                Some("log") => log_files.push(p),
                _ => {}
            }
        }
    }
    ldb_files.sort();
    log_files.sort();

    // Read SSTables first (older state)
    for ldb in ldb_files {
        match std::fs::read(&ldb) {
            Ok(bytes) => parse_ldb_table(&bytes, is_local_storage, &mut kv),
            Err(e) => warnings.push(DiagnosticWarning::warn(
                "leveldb",
                &ldb,
                format!("Failed reading SSTable: {e}"),
            )),
        }
    }

    // Replay WAL .log files (newer state)
    for log in log_files {
        match std::fs::read(&log) {
            Ok(bytes) => parse_leveldb_log(&bytes, is_local_storage, &mut kv),
            Err(e) => warnings.push(DiagnosticWarning::warn(
                "leveldb",
                &log,
                format!("Failed reading WAL log: {e}"),
            )),
        }
    }

    kv.into_iter()
        .filter_map(|((origin, key), val_opt)| {
            val_opt.map(|value| LevelDbKvRecord { origin, key, value })
        })
        .collect()
}

fn parse_leveldb_log(
    bytes: &[u8],
    is_local_storage: bool,
    kv: &mut BTreeMap<(String, String), Option<String>>,
) {
    const BLOCK_SIZE: usize = 32768;
    let mut pos = 0usize;
    let mut fragment_buf: Vec<u8> = Vec::new();

    while pos + 7 <= bytes.len() {
        let block_rem = BLOCK_SIZE - (pos % BLOCK_SIZE);
        if block_rem < 7 {
            pos += block_rem;
            continue;
        }
        let len = u16::from_le_bytes([bytes[pos + 4], bytes[pos + 5]]) as usize;
        let rec_type = bytes[pos + 6];
        pos += 7;
        if pos + len > bytes.len() {
            break;
        }
        let chunk = &bytes[pos..pos + len];
        pos += len;

        match rec_type {
            1 => {
                // FULL
                parse_write_batch(chunk, is_local_storage, kv);
            }
            2 => {
                // FIRST
                fragment_buf.clear();
                fragment_buf.extend_from_slice(chunk);
            }
            3 => {
                // MIDDLE
                fragment_buf.extend_from_slice(chunk);
            }
            4 => {
                // LAST
                fragment_buf.extend_from_slice(chunk);
                parse_write_batch(&fragment_buf, is_local_storage, kv);
                fragment_buf.clear();
            }
            _ => {}
        }
    }
}

fn parse_write_batch(
    batch: &[u8],
    is_local_storage: bool,
    kv: &mut BTreeMap<(String, String), Option<String>>,
) {
    if batch.len() < 12 {
        return;
    }
    let count = u32::from_le_bytes(batch[8..12].try_into().unwrap_or([0; 4])) as usize;
    let mut off = 12usize;

    for _ in 0..count.min(100_000) {
        if off >= batch.len() {
            break;
        }
        let tag = batch[off];
        off += 1;
        let Some(key_bytes) = read_varint_slice(batch, &mut off) else {
            break;
        };
        match tag {
            1 => {
                // Value (Put)
                let Some(val_bytes) = read_varint_slice(batch, &mut off) else {
                    break;
                };
                if let Some((origin, key)) = decode_storage_key(key_bytes, is_local_storage) {
                    let val = decode_storage_value(val_bytes);
                    kv.insert((origin, key), Some(val));
                }
            }
            0 => {
                // Deletion
                if let Some((origin, key)) = decode_storage_key(key_bytes, is_local_storage) {
                    kv.insert((origin, key), None);
                }
            }
            _ => break,
        }
    }
}

fn parse_ldb_table(
    bytes: &[u8],
    is_local_storage: bool,
    kv: &mut BTreeMap<(String, String), Option<String>>,
) {
    // LevelDB SSTable footer is 48 bytes; last 8 bytes = magic 0xdb4775248b80fb57
    if bytes.len() < 48 {
        return;
    }
    let footer = &bytes[bytes.len() - 48..];
    let magic = u64::from_le_bytes(footer[40..48].try_into().unwrap_or([0; 8]));
    if magic != 0xdb4775248b80fb57 {
        return;
    }
    let mut foff = 0usize;
    let _metaindex_off = read_varint64(footer, &mut foff);
    let _metaindex_len = read_varint64(footer, &mut foff);
    let Some(index_off) = read_varint64(footer, &mut foff) else {
        return;
    };
    let Some(index_len) = read_varint64(footer, &mut foff) else {
        return;
    };
    let Some(index_block) = read_ldb_block(bytes, index_off as usize, index_len as usize) else {
        return;
    };

    for (_, handle_bytes) in iter_ldb_block(&index_block) {
        let mut hoff = 0usize;
        let Some(boff) = read_varint64(&handle_bytes, &mut hoff) else {
            continue;
        };
        let Some(blen) = read_varint64(&handle_bytes, &mut hoff) else {
            continue;
        };
        let Some(data_block) = read_ldb_block(bytes, boff as usize, blen as usize) else {
            continue;
        };
        for (ikey, val_bytes) in iter_ldb_block(&data_block) {
            if ikey.len() < 8 {
                continue;
            }
            let user_key = &ikey[..ikey.len() - 8];
            let trailer = u64::from_le_bytes(ikey[ikey.len() - 8..].try_into().unwrap_or([0; 8]));
            let vtype = (trailer & 0xff) as u8;
            if let Some((origin, key)) = decode_storage_key(user_key, is_local_storage) {
                if vtype == 1 {
                    kv.insert((origin, key), Some(decode_storage_value(&val_bytes)));
                } else if vtype == 0 {
                    kv.insert((origin, key), None);
                }
            }
        }
    }
}

fn read_ldb_block(file: &[u8], offset: usize, size: usize) -> Option<Vec<u8>> {
    // Each block is followed by 5-byte trailer: compression_type (1B) + crc (4B)
    let end = offset.checked_add(size)?;
    if end + 5 > file.len() {
        return None;
    }
    let raw = &file[offset..end];
    let comp_type = file[end];
    match comp_type {
        0 => Some(raw.to_vec()),
        1 => snap::raw::Decoder::new().decompress_vec(raw).ok(),
        2 => ruzstd::decoding::StreamingDecoder::new(raw)
            .ok()
            .and_then(|mut d| {
                let mut out = Vec::new();
                std::io::Read::read_to_end(&mut d, &mut out).ok()?;
                Some(out)
            }),
        _ => None,
    }
}

fn iter_ldb_block(block: &[u8]) -> Vec<(Vec<u8>, Vec<u8>)> {
    let mut entries = Vec::new();
    if block.len() < 4 {
        return entries;
    }
    let num_restarts = u32::from_le_bytes(block[block.len() - 4..].try_into().unwrap_or([0; 4])) as usize;
    let restarts_bytes = num_restarts.saturating_mul(4);
    if restarts_bytes + 4 > block.len() {
        return entries;
    }
    let limit = block.len() - 4 - restarts_bytes;
    let mut off = 0usize;
    let mut prev_key: Vec<u8> = Vec::new();

    while off < limit {
        let Some(shared) = read_varint64(block, &mut off).map(|v| v as usize) else {
            break;
        };
        let Some(non_shared) = read_varint64(block, &mut off).map(|v| v as usize) else {
            break;
        };
        let Some(val_len) = read_varint64(block, &mut off).map(|v| v as usize) else {
            break;
        };
        if shared > prev_key.len() || off + non_shared + val_len > limit {
            break;
        }
        let mut key = prev_key[..shared].to_vec();
        key.extend_from_slice(&block[off..off + non_shared]);
        off += non_shared;
        let val = block[off..off + val_len].to_vec();
        off += val_len;
        prev_key = key.clone();
        entries.push((key, val));
    }

    entries
}

fn read_varint64(buf: &[u8], off: &mut usize) -> Option<u64> {
    let mut result = 0u64;
    let mut shift = 0u32;
    while *off < buf.len() && shift <= 63 {
        let b = buf[*off];
        *off += 1;
        result |= ((b & 0x7f) as u64) << shift;
        if (b & 0x80) == 0 {
            return Some(result);
        }
        shift += 7;
    }
    None
}

fn read_varint_slice<'a>(buf: &'a [u8], off: &mut usize) -> Option<&'a [u8]> {
    let len = read_varint64(buf, off)? as usize;
    if *off + len > buf.len() {
        return None;
    }
    let s = &buf[*off..*off + len];
    *off += len;
    Some(s)
}

fn decode_storage_key(raw: &[u8], is_local_storage: bool) -> Option<(String, String)> {
    if is_local_storage {
        // Chrome Local Storage key format: `_<origin>\x00<encoding_byte><key_bytes>`
        if let Some(after_underscore) = raw.strip_prefix(b"_") {
            if let Some(nul) = after_underscore.iter().position(|&b| b == 0) {
                let origin = String::from_utf8_lossy(&after_underscore[..nul]).into_owned();
                let key_part = &after_underscore[nul + 1..];
                let key = decode_chrome_encoded_text(key_part);
                return Some((origin, key));
            }
        }
        return None;
    }

    // Session Storage key format: `map-<id>-<key>` or `namespace-...`
    let s = String::from_utf8_lossy(raw).into_owned();
    if let Some(rest) = s.strip_prefix("map-")
        && let Some((map_id, key)) = rest.split_once('-')
    {
        return Some((format!("session-map-{map_id}"), key.to_string()));
    }
    None
}

fn decode_storage_value(raw: &[u8]) -> String {
    decode_chrome_encoded_text(raw)
}

fn decode_chrome_encoded_text(raw: &[u8]) -> String {
    if raw.is_empty() {
        return String::new();
    }
    match raw[0] {
        // 0x01 = Latin1 / UTF-8
        0x01 => String::from_utf8_lossy(&raw[1..]).into_owned(),
        // 0x00 = UTF-16LE
        0x00 => {
            let units: Vec<u16> = raw[1..]
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect();
            String::from_utf16_lossy(&units)
        }
        _ => String::from_utf8_lossy(raw).into_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_chromium_156_leveldb_wal_record() {
        // Real bytes captured from Chromium 156 Local Storage/leveldb/000003.log
        let log_bytes: &[u8] = b"\x9a\x1b\xdc5\x17\x00\x01\x01\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x01\x07VERSION\x011+F\xe8\xf1\x99\x00\x01\x02\x00\x00\x00\x00\x00\x00\x00\x03\x00\x00\x00\x01%_http://127.0.0.1:34699\x00\x01forensic_key\x0f\x01forensic_value\x01!METAACCESS:http://127.0.0.1:34699\t\x08\xa9\xa9\x9b\xed\xc2\xdb\xef\x17\x01\x1bMETA:http://127.0.0.1:34699\x0b\x08\xa9\xa9\x9b\xed\xc2\xdb\xef\x17\x10\x1c";
        let mut kv = BTreeMap::new();
        parse_leveldb_log(log_bytes, true, &mut kv);
        assert_eq!(
            kv.get(&("http://127.0.0.1:34699".to_string(), "forensic_key".to_string()))
                .and_then(|v| v.as_deref()),
            Some("forensic_value")
        );
    }
}
