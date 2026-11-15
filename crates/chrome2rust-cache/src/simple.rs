use super::decompress::decompress_payload_for_type;
use super::pickle::{HttpResponseMetadata, parse_http_response_info};
use super::{CacheBackendKind, CacheEntry, CacheLocationRef, CacheScanOptions, hex_lower};
use chrome2rust_core::error::{ChromeError, DiagnosticWarning};
use chrome2rust_core::magic::{ContentDetection, detect_content};
use chrome2rust_core::time::system_time_to_utc;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

const SIMPLE_INITIAL_MAGIC: u64 = 0xfcfb6d1ba7725c30;
const SIMPLE_FINAL_MAGIC: u64 = 0xf4fa6f45970d41d8;
const FLAG_HAS_CRC32: u32 = 1 << 0;
const FLAG_HAS_KEY_SHA256: u32 = 1 << 1;

const HEADER_SIZE: usize = 24;
const EOF_SIZE: usize = 24;

#[derive(Debug, Clone, Copy)]
struct SimpleHeader {
    magic: u64,
    _version: u32,
    key_length: u32,
    _key_hash: u32,
    _zero: u32,
}

#[derive(Debug, Clone, Copy)]
struct SimpleEof {
    magic: u64,
    flags: u32,
    data_crc32: u32,
    stream_size: u32,
    _zero: u32,
}

fn read_u32_le(b: &[u8]) -> u32 {
    u32::from_le_bytes(b.try_into().unwrap_or([0; 4]))
}

fn read_u64_le(b: &[u8]) -> u64 {
    u64::from_le_bytes(b.try_into().unwrap_or([0; 8]))
}

fn parse_header(b: &[u8]) -> Option<SimpleHeader> {
    if b.len() < HEADER_SIZE {
        return None;
    }
    Some(SimpleHeader {
        magic: read_u64_le(&b[0..8]),
        _version: read_u32_le(&b[8..12]),
        key_length: read_u32_le(&b[12..16]),
        _key_hash: read_u32_le(&b[16..20]),
        _zero: read_u32_le(&b[20..24]),
    })
}

fn parse_eof(b: &[u8]) -> Option<SimpleEof> {
    if b.len() < EOF_SIZE {
        return None;
    }
    Some(SimpleEof {
        magic: read_u64_le(&b[0..8]),
        flags: read_u32_le(&b[8..12]),
        data_crc32: read_u32_le(&b[12..16]),
        stream_size: read_u32_le(&b[16..20]),
        _zero: read_u32_le(&b[20..24]),
    })
}

pub fn scan_simple_cache(dir: &Path, opts: &CacheScanOptions) -> (Vec<CacheEntry>, Vec<DiagnosticWarning>) {
    let mut entries = Vec::new();
    let mut warnings = Vec::new();

    let rd = match std::fs::read_dir(dir) {
        Ok(r) => r,
        Err(e) => {
            warnings.push(DiagnosticWarning::error(
                "simple_cache",
                dir,
                format!("Failed to read cache directory: {e}"),
            ));
            return (entries, warnings);
        }
    };

    for item in rd.flatten() {
        let path = item.path();
        if !path.is_file() {
            continue;
        }
        let fname = item.file_name().to_string_lossy().to_string();
        if !fname.ends_with("_0") {
            continue;
        }
        match parse_simple_entry_file(&path, dir, opts) {
            Ok(Some(entry)) => entries.push(entry),
            Ok(None) => {}
            Err(e) => warnings.push(DiagnosticWarning::warn("simple_cache", &path, e.to_string())),
        }
    }

    (entries, warnings)
}

pub fn parse_simple_entry_file(
    path: &Path,
    cache_dir: &Path,
    opts: &CacheScanOptions,
) -> Result<Option<CacheEntry>, ChromeError> {
    let bytes = std::fs::read(path).map_err(|e| ChromeError::Io {
        path: path.display().to_string(),
        source: e,
    })?;
    let md = std::fs::metadata(path).ok();
    let fs_created = md.as_ref().and_then(|m| m.created().ok()).and_then(system_time_to_utc);
    let fs_modified = md.as_ref().and_then(|m| m.modified().ok()).and_then(system_time_to_utc);

    if bytes.len() < HEADER_SIZE + EOF_SIZE {
        return Err(ChromeError::InvalidFormat("Simple Cache file truncated".into()));
    }
    let header = parse_header(&bytes[..HEADER_SIZE])
        .ok_or_else(|| ChromeError::InvalidFormat("Missing SimpleFileHeader".into()))?;
    if header.magic != SIMPLE_INITIAL_MAGIC {
        return Ok(None);
    }
    let key_len = header.key_length as usize;
    let key_end = HEADER_SIZE
        .checked_add(key_len)
        .ok_or_else(|| ChromeError::InvalidFormat("Key length overflow".into()))?;
    if key_end > bytes.len() {
        return Err(ChromeError::InvalidFormat("Key length exceeds file size".into()));
    }
    let raw_key_bytes = &bytes[HEADER_SIZE..key_end];
    let raw_key = String::from_utf8_lossy(raw_key_bytes).into_owned();
    let (parsed_url, _, _) = super::parse_cache_key(&raw_key);

    // Parse EOF for stream 0 at the end of the file
    let eof0_start = bytes.len() - EOF_SIZE;
    let eof0 =
        parse_eof(&bytes[eof0_start..]).ok_or_else(|| ChromeError::InvalidFormat("Missing SimpleFileEOF".into()))?;
    if eof0.magic != SIMPLE_FINAL_MAGIC {
        return Err(ChromeError::InvalidFormat(format!(
            "Unexpected EOF magic {:#x} (file may be open/incomplete)",
            eof0.magic
        )));
    }

    let sha_len = if (eof0.flags & FLAG_HAS_KEY_SHA256) != 0 {
        32usize
    } else {
        0usize
    };

    let s0_len = eof0.stream_size as usize;
    let s0_end = eof0_start
        .checked_sub(sha_len)
        .ok_or_else(|| ChromeError::InvalidFormat("Invalid SHA256 trailer offset".into()))?;
    let s0_start = s0_end
        .checked_sub(s0_len)
        .ok_or_else(|| ChromeError::InvalidFormat("Invalid stream0 length".into()))?;

    if s0_start < key_end {
        return Err(ChromeError::InvalidFormat("Stream 0 overlaps key".into()));
    }

    // Verify optional key SHA-256
    if sha_len == 32 {
        let expected_sha = &bytes[s0_end..eof0_start];
        let actual_sha = Sha256::digest(raw_key_bytes);
        if actual_sha.as_slice() != expected_sha {
            return Err(ChromeError::InvalidFormat("Key SHA-256 mismatch".into()));
        }
    }

    let stream0 = &bytes[s0_start..s0_end];
    let mut crc_ok = true;
    if (eof0.flags & FLAG_HAS_CRC32) != 0 && crc32fast::hash(stream0) != eof0.data_crc32 {
        crc_ok = false;
    }

    // Stream 1 sits between [key_end .. eof1_start], followed by a 24-byte SimpleFileEOF,
    // or in a sibling *_1 stream file when inline stream1 is empty/omitted.
    let (s1_range, s1_slice, alt_stream1_file) = if key_end.checked_add(EOF_SIZE).is_some_and(|e| s0_start >= e) {
        let eof1_start = s0_start - EOF_SIZE;
        if let Some(eof1) = parse_eof(&bytes[eof1_start..s0_start])
            && eof1.magic == SIMPLE_FINAL_MAGIC
        {
            // Note: in modern Chromium, eof1.stream_size is often 0 even when stream 1 has bytes!
            let slice = &bytes[key_end..eof1_start];
            if (eof1.flags & FLAG_HAS_CRC32) != 0 && crc32fast::hash(slice) != eof1.data_crc32 {
                crc_ok = false;
            }
            if !slice.is_empty() {
                (Some((key_end, eof1_start)), slice, None)
            } else {
                (None, &[][..], find_alt_stream_file(path))
            }
        } else {
            (None, &[][..], find_alt_stream_file(path))
        }
    } else {
        (None, &[][..], find_alt_stream_file(path))
    };

    let http_meta: HttpResponseMetadata = if !stream0.is_empty() {
        parse_http_response_info(stream0)
    } else {
        HttpResponseMetadata::default()
    };

    let alt_owned: Option<Vec<u8>>;
    let payload_slice: &[u8] = if !s1_slice.is_empty() {
        s1_slice
    } else if let Some(alt_path) = &alt_stream1_file {
        if let Ok(v) = read_simple_stream_file_payload(alt_path) {
            alt_owned = Some(v);
            alt_owned.as_deref().unwrap_or(&[])
        } else {
            &[]
        }
    } else {
        &[]
    };

    let compressed_size = payload_slice.len();
    let mut file_size = compressed_size;
    let mut payload_sha256 = None;
    let detection: ContentDetection = if !payload_slice.is_empty()
        && payload_slice.len() <= 16 * 1024 * 1024
        && (opts.decompress_sizes || opts.compute_hashes)
    {
        let decompressed = match decompress_payload_for_type(
            payload_slice,
            http_meta.content_encoding.as_deref(),
            http_meta.content_type.as_deref(),
        ) {
            Ok(v) => v,
            Err(_) => payload_slice.to_vec(),
        };
        file_size = decompressed.len();
        if opts.compute_hashes && !decompressed.is_empty() {
            payload_sha256 = Some(hex_lower(&Sha256::digest(&decompressed)));
        }
        detect_content(
            &decompressed[..decompressed.len().min(64 * 1024)],
            http_meta.content_type.as_deref(),
            Some(&parsed_url),
            http_meta.content_disposition_filename.as_deref(),
        )
    } else {
        let can_inspect_raw = !payload_slice.is_empty()
            && http_meta
                .content_encoding
                .as_deref()
                .is_none_or(|e| e.trim().is_empty() || e.eq_ignore_ascii_case("identity"));
        let sample = if can_inspect_raw {
            &payload_slice[..payload_slice.len().min(64 * 1024)]
        } else {
            &[]
        };
        detect_content(
            sample,
            http_meta.content_type.as_deref(),
            Some(&parsed_url),
            http_meta.content_disposition_filename.as_deref(),
        )
    };

    let cache_name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default();

    let loc = CacheLocationRef {
        backend: CacheBackendKind::SimpleCache,
        cache_dir: cache_dir.to_path_buf(),
        primary_file: path.to_path_buf(),
        blockfile_stream1: None,
        simple_stream1_range: s1_range,
        simple_alt_stream1_file: alt_stream1_file,
    };

    Ok(Some(CacheEntry::from_metadata(
        cache_name.clone(),
        CacheBackendKind::SimpleCache,
        cache_name,
        path.display().to_string(),
        raw_key,
        http_meta,
        compressed_size,
        file_size,
        fs_created,
        fs_modified,
        false,
        Some(crc_ok),
        payload_sha256,
        detection,
        loc,
    )))
}

fn find_alt_stream_file(primary_0: &Path) -> Option<PathBuf> {
    let s = primary_0.display().to_string();
    if let Some(stem) = s.strip_suffix("_0") {
        let p1 = PathBuf::from(format!("{stem}_1"));
        if p1.is_file() {
            return Some(p1);
        }
    }
    None
}

/// Reads a standalone Simple Cache stream file (`*_1` or `*_2`):
/// Layout: SimpleFileHeader + key + data + SimpleFileEOF
pub fn read_simple_stream_file_payload(path: &Path) -> Result<Vec<u8>, ChromeError> {
    let bytes = std::fs::read(path).map_err(|e| ChromeError::Io {
        path: path.display().to_string(),
        source: e,
    })?;
    if bytes.len() < HEADER_SIZE + EOF_SIZE {
        return Ok(Vec::new());
    }
    let header = parse_header(&bytes[..HEADER_SIZE])
        .ok_or_else(|| ChromeError::InvalidFormat("Invalid header in stream file".into()))?;
    if header.magic != SIMPLE_INITIAL_MAGIC {
        return Ok(Vec::new());
    }
    let Some(key_end) = HEADER_SIZE.checked_add(header.key_length as usize) else {
        return Ok(Vec::new());
    };
    let eof_start = bytes.len() - EOF_SIZE;
    let Some(eof) = parse_eof(&bytes[eof_start..]) else {
        return Ok(Vec::new());
    };
    if eof.magic != SIMPLE_FINAL_MAGIC || key_end > eof_start {
        return Ok(Vec::new());
    }
    let sha_len = if (eof.flags & FLAG_HAS_KEY_SHA256) != 0 {
        32usize
    } else {
        0usize
    };
    let data_end = eof_start.saturating_sub(sha_len);
    if data_end < key_end {
        return Ok(Vec::new());
    }
    Ok(bytes[key_end..data_end].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::TempDir;

    #[test]
    fn test_synthetic_simple_cache_entry_roundtrip() {
        let dir = TempDir::new().unwrap();
        let entry_path = dir.path().join("abcdef0123456789_0");

        let key = b"1/0/_dk_https://example.org https://example.org https://example.org/hello.txt";
        let payload = b"hello world from simple cache";

        // Build stream0 pickle
        let headers = b"HTTP/1.1 200 OK\0Content-Type: text/plain\0Server: rust-test\0\0";
        let mut s0 = Vec::new();
        let flags: u32 = 3; // version 3
        let req_time: i64 = 13_439_176_738_739_516;
        let resp_time: i64 = 13_439_176_738_790_740;
        let h_aligned = headers.len().div_ceil(4) * 4;
        let pickle_payload_len = 4 + 8 + 8 + 4 + h_aligned + 4 + 12 + 4;
        s0.extend_from_slice(&(pickle_payload_len as u32).to_le_bytes());
        s0.extend_from_slice(&flags.to_le_bytes());
        s0.extend_from_slice(&req_time.to_le_bytes());
        s0.extend_from_slice(&resp_time.to_le_bytes());
        s0.extend_from_slice(&(headers.len() as u32).to_le_bytes());
        s0.extend_from_slice(headers);
        s0.resize(s0.len() + (h_aligned - headers.len()), 0);
        // socket address 127.0.0.1:443
        s0.extend_from_slice(&9u32.to_le_bytes());
        s0.extend_from_slice(b"127.0.0.1\0\0\0");
        s0.extend_from_slice(&443u32.to_le_bytes());

        let mut file_bytes = Vec::new();
        file_bytes.extend_from_slice(&SIMPLE_INITIAL_MAGIC.to_le_bytes());
        file_bytes.extend_from_slice(&5u32.to_le_bytes());
        file_bytes.extend_from_slice(&(key.len() as u32).to_le_bytes());
        file_bytes.extend_from_slice(&0u32.to_le_bytes());
        file_bytes.extend_from_slice(&0u32.to_le_bytes());
        file_bytes.extend_from_slice(key);
        file_bytes.extend_from_slice(payload);
        // EOF1 with stream_size = 0 (Chromium 156 behavior!)
        file_bytes.extend_from_slice(&SIMPLE_FINAL_MAGIC.to_le_bytes());
        file_bytes.extend_from_slice(&FLAG_HAS_CRC32.to_le_bytes());
        file_bytes.extend_from_slice(&crc32fast::hash(payload).to_le_bytes());
        file_bytes.extend_from_slice(&0u32.to_le_bytes());
        file_bytes.extend_from_slice(&eof_zero_padding());
        // Stream 0 + key sha256 + EOF0
        file_bytes.extend_from_slice(&s0);
        file_bytes.extend_from_slice(&Sha256::digest(key));
        file_bytes.extend_from_slice(&SIMPLE_FINAL_MAGIC.to_le_bytes());
        file_bytes.extend_from_slice(&(FLAG_HAS_CRC32 | FLAG_HAS_KEY_SHA256).to_le_bytes());
        file_bytes.extend_from_slice(&crc32fast::hash(&s0).to_le_bytes());
        file_bytes.extend_from_slice(&(s0.len() as u32).to_le_bytes());
        file_bytes.extend_from_slice(&0u32.to_le_bytes());

        std::fs::File::create(&entry_path)
            .unwrap()
            .write_all(&file_bytes)
            .unwrap();

        let opts = CacheScanOptions {
            compute_hashes: true,
            ..Default::default()
        };
        let (entries, warnings) = scan_simple_cache(dir.path(), &opts);
        assert!(warnings.is_empty(), "warnings: {warnings:?}");
        assert_eq!(entries.len(), 1);
        let e = &entries[0];
        assert_eq!(e.url, "https://example.org/hello.txt");
        assert_eq!(e.partition_website.as_deref(), Some("https://example.org"));
        assert_eq!(e.content_type.as_deref(), Some("text/plain"));
        assert_eq!(e.server_name.as_deref(), Some("rust-test"));
        assert_eq!(e.server_ip.as_deref(), Some("127.0.0.1"));
        assert_eq!(e.server_port, Some(443));
        assert_eq!(e.crc32_valid, Some(true));
        assert_eq!(e.file_size, payload.len());
        assert_eq!(e.read_decompressed_payload().unwrap(), payload);
    }

    fn eof_zero_padding() -> [u8; 4] {
        [0u8; 4]
    }

    #[test]
    fn test_simple_cache_overflow_guards() {
        let dir = TempDir::new().unwrap();
        let entry_path = dir.path().join("badkey_0");
        let stream_path = dir.path().join("badkey_1");

        let mut bad = Vec::new();
        bad.extend_from_slice(&SIMPLE_INITIAL_MAGIC.to_le_bytes());
        bad.extend_from_slice(&5u32.to_le_bytes());
        bad.extend_from_slice(&u32::MAX.to_le_bytes()); // key_length = u32::MAX
        bad.extend_from_slice(&0u64.to_le_bytes());
        bad.extend_from_slice(&[0u8; EOF_SIZE]);
        std::fs::write(&entry_path, &bad).unwrap();
        std::fs::write(&stream_path, &bad).unwrap();

        assert!(parse_simple_entry_file(&entry_path, dir.path(), &CacheScanOptions::default()).is_err());
        assert!(read_simple_stream_file_payload(&stream_path).unwrap().is_empty());
    }
}
