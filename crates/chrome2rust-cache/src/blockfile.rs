use super::decompress::decompress_payload;
use super::pickle::{HttpResponseMetadata, parse_http_response_info};
use super::{BlockfileDataLocation, CacheBackendKind, CacheEntry, CacheLocationRef, CacheScanOptions, hex_lower};
use chrome2rust_core::error::{ChromeError, DiagnosticWarning};
use chrome2rust_core::time::{chrome_us_to_datetime, system_time_to_utc};
use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

const INDEX_MAGIC: u32 = 0xc103cac3;
const BLOCK_MAGIC: u32 = 0xc104cac3;
const INDEX_HEADER_SIZE: usize = 368;
const BLOCK_HEADER_SIZE: usize = 8192;

#[derive(Debug, Clone, Copy)]
struct DecodedAddr {
    raw: u32,
    is_initialized: bool,
    file_type: u8,
    num_blocks: usize,
    file_number: u8,
    start_block: u16,
    separate_file_id: u32,
}

impl DecodedAddr {
    fn from_u32(addr: u32) -> Self {
        let is_initialized = (addr & 0x8000_0000) != 0;
        let file_type = ((addr >> 28) & 0x7) as u8;
        let num_blocks = (((addr >> 24) & 0x3) + 1) as usize;
        let file_number = ((addr >> 16) & 0xFF) as u8;
        let start_block = (addr & 0xFFFF) as u16;
        let separate_file_id = addr & 0x0FFF_FFFF;
        Self {
            raw: addr,
            is_initialized,
            file_type,
            num_blocks,
            file_number,
            start_block,
            separate_file_id,
        }
    }

    fn block_size(&self) -> Option<usize> {
        match self.file_type {
            1 => Some(36),
            2 => Some(256),
            3 => Some(1024),
            4 => Some(4096),
            5 => Some(8),
            6 => Some(104),
            7 => Some(48),
            _ => None,
        }
    }

    fn is_separate_file(&self) -> bool {
        self.is_initialized && self.file_type == 0
    }
}

struct BlockFile {
    entry_size: usize,
    data: Vec<u8>,
}

#[allow(dead_code)]
fn read_u16_le(b: &[u8]) -> u16 {
    u16::from_le_bytes(b.try_into().unwrap_or([0; 2]))
}

fn read_u32_le(b: &[u8]) -> u32 {
    u32::from_le_bytes(b.try_into().unwrap_or([0; 4]))
}

fn read_i32_le(b: &[u8]) -> i32 {
    i32::from_le_bytes(b.try_into().unwrap_or([0; 4]))
}

fn read_i64_le(b: &[u8]) -> i64 {
    i64::from_le_bytes(b.try_into().unwrap_or([0; 8]))
}

pub fn scan_blockfile_cache(dir: &Path, opts: &CacheScanOptions) -> (Vec<CacheEntry>, Vec<DiagnosticWarning>) {
    let mut entries = Vec::new();
    let mut warnings = Vec::new();

    let index_path = dir.join("index");
    let index_bytes = match std::fs::read(&index_path) {
        Ok(b) => b,
        Err(e) => {
            warnings.push(DiagnosticWarning::warn(
                "blockfile_cache",
                &index_path,
                format!("Failed to read blockfile index: {e}"),
            ));
            return (entries, warnings);
        }
    };

    if index_bytes.len() < INDEX_HEADER_SIZE {
        warnings.push(DiagnosticWarning::warn(
            "blockfile_cache",
            &index_path,
            "Blockfile index shorter than IndexHeader (368 bytes)",
        ));
        return (entries, warnings);
    }

    let magic = read_u32_le(&index_bytes[0..4]);
    if magic != INDEX_MAGIC {
        warnings.push(DiagnosticWarning::warn(
            "blockfile_cache",
            &index_path,
            format!("Unexpected Blockfile index magic {magic:#x}"),
        ));
        return (entries, warnings);
    }

    let table_len = read_u32_le(&index_bytes[28..32]) as usize;
    let table_bytes_end = INDEX_HEADER_SIZE + table_len.saturating_mul(4);
    let max_buckets = (index_bytes.len() - INDEX_HEADER_SIZE) / 4;
    let bucket_count = table_len.min(max_buckets);
    if table_bytes_end > index_bytes.len() {
        warnings.push(DiagnosticWarning::warn(
            "blockfile_cache",
            &index_path,
            "Blockfile index table_len exceeds file length; reading available buckets",
        ));
    }

    // Load all data_0, data_1, data_2, data_3, data_4... files present
    let mut block_files: HashMap<u8, BlockFile> = HashMap::new();
    if let Ok(rd) = std::fs::read_dir(dir) {
        for item in rd.flatten() {
            let fname = item.file_name().to_string_lossy().to_string();
            if let Some(num_str) = fname.strip_prefix("data_")
                && let Ok(num) = num_str.parse::<u8>()
                && item.path().is_file()
                && let Ok(data) = std::fs::read(item.path())
                && data.len() >= BLOCK_HEADER_SIZE
                && read_u32_le(&data[0..4]) == BLOCK_MAGIC
            {
                let entry_size = read_u32_le(&data[12..16]) as usize;
                if entry_size > 0 {
                    block_files.insert(num, BlockFile { entry_size, data });
                }
            }
        }
    }

    let mut visited_addrs: HashSet<u32> = HashSet::new();

    for i in 0..bucket_count {
        let off = INDEX_HEADER_SIZE + i * 4;
        let mut addr_raw = read_u32_le(&index_bytes[off..off + 4]);
        let mut chain_steps = 0usize;

        while addr_raw != 0 && chain_steps < 1024 {
            chain_steps += 1;
            if !visited_addrs.insert(addr_raw) {
                break;
            }
            let addr = DecodedAddr::from_u32(addr_raw);
            if !addr.is_initialized || addr.is_separate_file() {
                break;
            }
            let Some(entry_bytes) = read_addr_slice(&block_files, addr, None) else {
                break;
            };
            if entry_bytes.len() < 96 {
                break;
            }

            let next_addr = read_u32_le(&entry_bytes[4..8]);
            let rankings_addr_raw = read_u32_le(&entry_bytes[8..12]);
            let state = read_i32_le(&entry_bytes[20..24]);
            let creation_time = chrome_us_to_datetime(read_i64_le(&entry_bytes[24..32]));
            let key_len = read_i32_le(&entry_bytes[32..36]).max(0) as usize;
            let long_key_raw = read_u32_le(&entry_bytes[36..40]);

            let data_sizes = [
                read_i32_le(&entry_bytes[40..44]),
                read_i32_le(&entry_bytes[44..48]),
                read_i32_le(&entry_bytes[48..52]),
                read_i32_le(&entry_bytes[52..56]),
            ];
            let data_addrs = [
                read_u32_le(&entry_bytes[56..60]),
                read_u32_le(&entry_bytes[60..64]),
                read_u32_le(&entry_bytes[64..68]),
                read_u32_le(&entry_bytes[68..72]),
            ];

            // Skip doomed/evicted placeholders if they have no key
            let raw_key = if key_len > 0 && long_key_raw == 0 {
                let inline_avail = entry_bytes.len().saturating_sub(96);
                let take = key_len.min(inline_avail);
                String::from_utf8_lossy(&entry_bytes[96..96 + take]).into_owned()
            } else if key_len > 0 && long_key_raw != 0 {
                let lk_addr = DecodedAddr::from_u32(long_key_raw);
                read_stream_bytes(dir, &block_files, lk_addr, key_len)
                    .map(|b| String::from_utf8_lossy(&b).into_owned())
                    .unwrap_or_default()
            } else {
                String::new()
            };

            if !raw_key.is_empty() && state != 2 {
                let mut last_used: Option<DateTime<Utc>> = None;
                if rankings_addr_raw != 0 {
                    let r_addr = DecodedAddr::from_u32(rankings_addr_raw);
                    if let Some(r_bytes) = read_addr_slice(&block_files, r_addr, Some(36))
                        && r_bytes.len() >= 16
                    {
                        last_used = chrome_us_to_datetime(read_i64_le(&r_bytes[0..8]));
                    }
                }

                // Stream 0: HTTP Response Info
                let s0_len = data_sizes[0].max(0) as usize;
                let s0_bytes = if s0_len > 0 && data_addrs[0] != 0 {
                    read_stream_bytes(dir, &block_files, DecodedAddr::from_u32(data_addrs[0]), s0_len)
                        .unwrap_or_default()
                } else {
                    Vec::new()
                };

                let http_meta: HttpResponseMetadata = if !s0_bytes.is_empty() {
                    parse_http_response_info(&s0_bytes)
                } else {
                    HttpResponseMetadata::default()
                };

                // Stream 1: Payload
                let s1_len = data_sizes[1].max(0) as usize;
                let s1_addr_raw = data_addrs[1];
                let s1_addr = DecodedAddr::from_u32(s1_addr_raw);
                let mut deleted_file = false;
                let mut primary_file = dir.join(format!("data_{}", addr.file_number));
                let mut cache_name = format!("data_{} [{}:{}]", addr.file_number, addr.start_block, addr.num_blocks);
                let mut fs_modified: Option<DateTime<Utc>> = None;

                let stream1_loc = if s1_addr_raw != 0 && s1_len > 0 {
                    if s1_addr.is_separate_file() {
                        let sep_name = format!("f_{:06x}", s1_addr.separate_file_id);
                        let sep_path = dir.join(&sep_name);
                        cache_name = sep_name;
                        primary_file = sep_path.clone();
                        if !sep_path.is_file() {
                            deleted_file = true;
                        } else if let Ok(md) = std::fs::metadata(&sep_path) {
                            fs_modified = md.modified().ok().and_then(system_time_to_utc);
                        }
                        Some(BlockfileDataLocation::SeparateFile {
                            path: sep_path,
                            byte_len: s1_len,
                        })
                    } else {
                        let block_sz = s1_addr.block_size().unwrap_or(256);
                        Some(BlockfileDataLocation::Block {
                            file_number: s1_addr.file_number,
                            start_block: s1_addr.start_block,
                            block_size: block_sz,
                            byte_len: s1_len,
                        })
                    }
                } else {
                    None
                };

                let mut file_size = s1_len;
                let mut payload_sha256 = None;
                if let Some(ref loc_b) = stream1_loc
                    && !deleted_file
                    && (opts.decompress_sizes || opts.compute_hashes)
                    && s1_len <= 16 * 1024 * 1024
                    && let Ok(raw_payload) = read_blockfile_data(dir, loc_b)
                {
                    let decompressed = match decompress_payload(&raw_payload, http_meta.content_encoding.as_deref()) {
                        Ok(v) => v,
                        Err(_) => raw_payload,
                    };
                    file_size = decompressed.len();
                    if opts.compute_hashes && !decompressed.is_empty() {
                        payload_sha256 = Some(hex_lower(&Sha256::digest(&decompressed)));
                    }
                }

                let loc = CacheLocationRef {
                    backend: CacheBackendKind::Blockfile,
                    cache_dir: dir.to_path_buf(),
                    primary_file: primary_file.clone(),
                    blockfile_stream1: stream1_loc,
                    simple_stream1_range: None,
                    simple_alt_stream1_file: None,
                };

                let effective_last_accessed = last_used.or(fs_modified).or(http_meta.response_time);

                let entry = CacheEntry::from_metadata(
                    format!("bf_{addr_raw:08x}"),
                    CacheBackendKind::Blockfile,
                    cache_name,
                    primary_file.display().to_string(),
                    raw_key,
                    http_meta,
                    s1_len,
                    file_size,
                    creation_time,
                    effective_last_accessed,
                    deleted_file,
                    None,
                    payload_sha256,
                    loc,
                );
                entries.push(entry);
            }

            addr_raw = next_addr;
        }
    }

    (entries, warnings)
}

fn read_addr_slice(block_files: &HashMap<u8, BlockFile>, addr: DecodedAddr, exact_len: Option<usize>) -> Option<&[u8]> {
    if !addr.is_initialized || addr.is_separate_file() {
        return None;
    }
    let bf = block_files.get(&addr.file_number)?;
    let block_size = addr.block_size().unwrap_or(bf.entry_size);
    let start = BLOCK_HEADER_SIZE + (addr.start_block as usize) * block_size;
    let total_alloc = addr.num_blocks * block_size;
    let len = exact_len.unwrap_or(total_alloc).min(total_alloc);
    if start + len > bf.data.len() {
        return None;
    }
    Some(&bf.data[start..start + len])
}

fn read_stream_bytes(
    dir: &Path,
    block_files: &HashMap<u8, BlockFile>,
    addr: DecodedAddr,
    byte_len: usize,
) -> Result<Vec<u8>, ChromeError> {
    if !addr.is_initialized || byte_len == 0 {
        return Ok(Vec::new());
    }
    if addr.is_separate_file() {
        let sep_path = dir.join(format!("f_{:06x}", addr.separate_file_id));
        let mut bytes = std::fs::read(&sep_path).map_err(|e| ChromeError::Io {
            path: sep_path.display().to_string(),
            source: e,
        })?;
        if bytes.len() > byte_len {
            bytes.truncate(byte_len);
        }
        return Ok(bytes);
    }
    let slice = read_addr_slice(block_files, addr, Some(byte_len))
        .ok_or_else(|| ChromeError::InvalidFormat(format!("Blockfile address out of bounds: {:#x}", addr.raw)))?;
    Ok(slice.to_vec())
}

pub fn read_blockfile_data(cache_dir: &Path, loc: &BlockfileDataLocation) -> Result<Vec<u8>, ChromeError> {
    match loc {
        BlockfileDataLocation::SeparateFile { path, byte_len } => {
            if !path.is_file() {
                return Err(ChromeError::NotFound(path.display().to_string()));
            }
            let mut bytes = std::fs::read(path).map_err(|e| ChromeError::Io {
                path: path.display().to_string(),
                source: e,
            })?;
            if bytes.len() > *byte_len {
                bytes.truncate(*byte_len);
            }
            Ok(bytes)
        }
        BlockfileDataLocation::Block {
            file_number,
            start_block,
            block_size,
            byte_len,
        } => {
            let file_path = cache_dir.join(format!("data_{file_number}"));
            let bytes = std::fs::read(&file_path).map_err(|e| ChromeError::Io {
                path: file_path.display().to_string(),
                source: e,
            })?;
            let start = BLOCK_HEADER_SIZE + (*start_block as usize) * (*block_size);
            let end = start + *byte_len;
            if end > bytes.len() {
                return Err(ChromeError::InvalidFormat(format!(
                    "Blockfile slice {start}..{end} exceeds {} ({} bytes)",
                    file_path.display(),
                    bytes.len()
                )));
            }
            Ok(bytes[start..end].to_vec())
        }
    }
}

#[allow(dead_code)]
fn _unused(_: u16, _: PathBuf) {}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_synthetic_blockfile_cache() {
        let dir = TempDir::new().unwrap();

        // 1. index file (368 + 64 * 4 bytes)
        let mut idx = vec![0u8; INDEX_HEADER_SIZE + 64 * 4];
        idx[0..4].copy_from_slice(&INDEX_MAGIC.to_le_bytes());
        idx[4..8].copy_from_slice(&0x0003_0000u32.to_le_bytes());
        idx[28..32].copy_from_slice(&64u32.to_le_bytes()); // table_len = 64
        // Bucket 5 -> data_1 (file_type=2 BLOCK_256), file_num=1, num_blocks=1 (0), start_block=0
        let entry_addr: u32 = 0x8000_0000 | (2 << 28) | (1 << 16);
        idx[INDEX_HEADER_SIZE + 5 * 4..INDEX_HEADER_SIZE + 6 * 4].copy_from_slice(&entry_addr.to_le_bytes());
        std::fs::write(dir.path().join("index"), &idx).unwrap();

        // 2. data_0 (RankingsNode 36-byte blocks)
        let mut d0 = vec![0u8; BLOCK_HEADER_SIZE + 36];
        d0[0..4].copy_from_slice(&BLOCK_MAGIC.to_le_bytes());
        d0[12..16].copy_from_slice(&36u32.to_le_bytes());
        let last_used: i64 = 13_439_176_738_790_740;
        d0[BLOCK_HEADER_SIZE..BLOCK_HEADER_SIZE + 8].copy_from_slice(&last_used.to_le_bytes());
        std::fs::write(dir.path().join("data_0"), &d0).unwrap();

        // 3. data_1 (256-byte blocks): block 0 = EntryStore, block 1 = HTTP response info pickle
        let mut d1 = vec![0u8; BLOCK_HEADER_SIZE + 512];
        d1[0..4].copy_from_slice(&BLOCK_MAGIC.to_le_bytes());
        d1[8..10].copy_from_slice(&1u16.to_le_bytes());
        d1[12..16].copy_from_slice(&256u32.to_le_bytes());

        // Build stream0 pickle in block 1
        let headers = b"HTTP/1.1 200 OK\0Content-Type: image/png\0Server: bf-test\0\0";
        let mut s0 = Vec::new();
        let h_aligned = headers.len().div_ceil(4) * 4;
        let plen = 4 + 8 + 8 + 4 + h_aligned;
        s0.extend_from_slice(&(plen as u32).to_le_bytes());
        s0.extend_from_slice(&3u32.to_le_bytes());
        s0.extend_from_slice(&last_used.to_le_bytes());
        s0.extend_from_slice(&last_used.to_le_bytes());
        s0.extend_from_slice(&(headers.len() as u32).to_le_bytes());
        s0.extend_from_slice(headers);
        s0.resize(s0.len() + (h_aligned - headers.len()), 0);
        d1[BLOCK_HEADER_SIZE + 256..BLOCK_HEADER_SIZE + 256 + s0.len()].copy_from_slice(&s0);

        // Separate file f_000007 for payload
        let payload = b"\x89PNG\r\n\x1a\nFAKEPNG";
        std::fs::write(dir.path().join("f_000007"), payload).unwrap();

        // Populate EntryStore at block 0
        let es = &mut d1[BLOCK_HEADER_SIZE..BLOCK_HEADER_SIZE + 256];
        let rank_addr: u32 = 0x8000_0000 | (1 << 28); // data_0 block 0
        let s0_addr: u32 = 0x8000_0000 | (2 << 28) | (1 << 16) | 1; // data_1 block 1
        let s1_addr: u32 = 0x8000_0000 | 7; // separate file f_000007
        let key = b"https://example.org/icon.png";

        es[8..12].copy_from_slice(&rank_addr.to_le_bytes());
        es[24..32].copy_from_slice(&last_used.to_le_bytes());
        es[32..36].copy_from_slice(&(key.len() as i32).to_le_bytes());
        es[40..44].copy_from_slice(&(s0.len() as i32).to_le_bytes());
        es[44..48].copy_from_slice(&(payload.len() as i32).to_le_bytes());
        es[56..60].copy_from_slice(&s0_addr.to_le_bytes());
        es[60..64].copy_from_slice(&s1_addr.to_le_bytes());
        es[96..96 + key.len()].copy_from_slice(key);
        std::fs::write(dir.path().join("data_1"), &d1).unwrap();

        let (entries, warnings) = scan_blockfile_cache(dir.path(), &CacheScanOptions::default());
        assert!(warnings.is_empty(), "warnings: {warnings:?}");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].url, "https://example.org/icon.png");
        assert_eq!(entries[0].content_type.as_deref(), Some("image/png"));
        assert_eq!(entries[0].cache_name, "f_000007");
        assert!(!entries[0].deleted_file);
        assert_eq!(entries[0].read_decompressed_payload().unwrap(), payload);

        // Now remove f_000007 and verify Deleted File detection!
        std::fs::remove_file(dir.path().join("f_000007")).unwrap();
        let (entries2, _) = scan_blockfile_cache(dir.path(), &CacheScanOptions::default());
        assert_eq!(entries2.len(), 1);
        assert!(entries2[0].deleted_file);
    }
}
