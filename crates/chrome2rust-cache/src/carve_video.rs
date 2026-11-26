use crate::export::sanitize_filename;
use crate::hex_lower;
use crate::unified_cache::{UnifiedCacheItem, load_unified_cache_from_paths};
use chrome2rust_core::error::DiagnosticWarning;
use chrome2rust_core::magic::detect_content;
use chrono::{DateTime, Utc};
use guap_table::{
    CellValue, ColumnDef, ColumnType, Row, SortDirection, TableData, TableError, TableProvider, TableQuery,
    TableSchema, apply_query,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};

const MAX_REASSEMBLE_BYTES: usize = 512 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VideoCarveRecord {
    pub browser: String,
    pub profile: String,
    pub url: String,
    pub container_format: String,
    pub duration_hint: String,
    pub duration_secs: Option<f64>,
    pub file_size: u64,
    pub cache_time: Option<DateTime<Utc>>,
    pub segment_count: u64,
    pub reassembled: bool,
    pub codec_hint: String,
    pub sha256: String,
    pub cache_name: String,
    pub extracted_path: Option<String>,
}

#[derive(Debug, Clone, Default)]
struct VideoMeta {
    container: String,
    duration_secs: Option<f64>,
    codec_hint: String,
    is_init_segment: bool,
    is_media_segment: bool,
}

fn inspect_video_bytes(bytes: &[u8], url: &str, ct: Option<&str>) -> Option<VideoMeta> {
    if bytes.is_empty() {
        return None;
    }
    let det = detect_content(bytes, ct, Some(url), None);
    let ext = det.extension.as_deref().unwrap_or("");
    let mime = det.mime.as_deref().unwrap_or("");

    // 1. HLS .m3u8
    if ext == "m3u8" || mime.contains("mpegurl") || bytes.starts_with(b"#EXTM3U") {
        let dur = parse_hls_duration(bytes);
        return Some(VideoMeta {
            container: "HLS-M3U8".into(),
            duration_secs: dur,
            codec_hint: "HLS Playlist".into(),
            ..Default::default()
        });
    }

    // 2. DASH .mpd
    if ext == "mpd" || mime.contains("dash+xml") || is_dash_mpd_bytes(bytes) {
        let dur = parse_dash_mpd_duration(bytes);
        return Some(VideoMeta {
            container: "DASH-MPD".into(),
            duration_secs: dur,
            codec_hint: "MPEG-DASH Manifest".into(),
            ..Default::default()
        });
    }

    // 3. WebM (EBML)
    if bytes.starts_with(&[0x1A, 0x45, 0xDF, 0xA3]) {
        let (is_webm, dur, codec) = parse_webm_info(bytes);
        if is_webm || ext == "webm" || mime == "video/webm" {
            return Some(VideoMeta {
                container: "WebM".into(),
                duration_secs: dur,
                codec_hint: codec,
                ..Default::default()
            });
        }
    }

    // 4. MPEG-TS (188-byte or 192-byte M2TS)
    if let Some((stride, sync_off)) = detect_mpeg_ts_stride(bytes) {
        let dur = parse_mpeg_ts_pcr_duration(bytes, stride, sync_off);
        return Some(VideoMeta {
            container: if stride == 192 {
                "MPEG-M2TS".into()
            } else {
                "MPEG-TS".into()
            },
            duration_secs: dur,
            codec_hint: "MPEG-TS".into(),
            is_media_segment: true,
            ..Default::default()
        });
    }

    // 5. MP4 / M4S / fMP4 ISOBMFF
    if is_isobmff_video(bytes, url, ext, mime) {
        let (dur, codec, has_moov, has_moof, has_mdat) = parse_mp4_boxes(bytes);
        let is_m4s = url.to_ascii_lowercase().contains(".m4s") || ext == "m4s" || (has_moof && !has_moov);
        let is_init = has_moov && !has_moof && !has_mdat;
        return Some(VideoMeta {
            container: if is_m4s { "M4S-Segment".into() } else { "MP4".into() },
            duration_secs: dur,
            codec_hint: codec,
            is_init_segment: is_init,
            is_media_segment: has_moof || is_m4s,
        });
    }

    if mime.starts_with("video/") && !det.mime_mismatch {
        return Some(VideoMeta {
            container: ext.to_ascii_uppercase(),
            duration_secs: None,
            codec_hint: mime.to_string(),
            ..Default::default()
        });
    }

    None
}

fn is_dash_mpd_bytes(bytes: &[u8]) -> bool {
    let head = String::from_utf8_lossy(&bytes[..bytes.len().min(2048)]).to_ascii_lowercase();
    head.contains("<mpd")
}

fn is_isobmff_video(bytes: &[u8], url: &str, ext: &str, mime: &str) -> bool {
    if bytes.len() >= 8 && matches!(&bytes[4..8], b"ftyp" | b"styp" | b"sidx" | b"moov" | b"moof") {
        // Exclude AVIF/HEIF images
        if &bytes[4..8] == b"ftyp" && bytes.len() >= 12 {
            let brand = &bytes[8..12];
            if matches!(brand, b"avif" | b"avis" | b"heic" | b"heix" | b"mif1") {
                return false;
            }
        }
        return true;
    }
    matches!(ext, "mp4" | "m4s" | "m4v" | "mov") || mime == "video/mp4" || url.to_ascii_lowercase().ends_with(".m4s")
}

fn parse_mp4_boxes(bytes: &[u8]) -> (Option<f64>, String, bool, bool, bool) {
    let mut duration_secs = None;
    let mut codecs = Vec::new();
    let mut has_moov = false;
    let mut has_moof = false;
    let mut has_mdat = false;

    let mut pos = 0usize;
    while pos + 8 <= bytes.len() {
        let size32 = u32::from_be_bytes(bytes[pos..pos + 4].try_into().unwrap()) as usize;
        let kind = &bytes[pos + 4..pos + 8];
        let (hdr, total) = if size32 == 1 {
            let Some(hdr_end) = pos.checked_add(16) else {
                break;
            };
            if hdr_end > bytes.len() {
                break;
            }
            let Ok(s64) = usize::try_from(u64::from_be_bytes(bytes[pos + 8..hdr_end].try_into().unwrap())) else {
                break;
            };
            (16usize, s64)
        } else if size32 == 0 {
            (8usize, bytes.len() - pos)
        } else {
            (8usize, size32)
        };
        let Some(end) = pos.checked_add(total) else {
            break;
        };
        if total < hdr || end > bytes.len() {
            break;
        }
        let body = &bytes[pos + hdr..end];
        match kind {
            b"moov" => {
                has_moov = true;
                inspect_moov(body, &mut duration_secs, &mut codecs);
            }
            b"moof" => has_moof = true,
            b"mdat" => has_mdat = true,
            b"sidx" if duration_secs.is_none() => {
                duration_secs = parse_sidx_duration(body);
            }
            _ => {}
        }
        pos = end;
    }

    (duration_secs, codecs.join(","), has_moov, has_moof, has_mdat)
}

fn inspect_moov(moov: &[u8], duration_secs: &mut Option<f64>, codecs: &mut Vec<String>) {
    let mut pos = 0usize;
    while pos + 8 <= moov.len() {
        let size = u32::from_be_bytes(moov[pos..pos + 4].try_into().unwrap()) as usize;
        let kind = &moov[pos + 4..pos + 8];
        let Some(end) = pos.checked_add(size) else {
            break;
        };
        if size < 8 || end > moov.len() {
            break;
        }
        let body = &moov[pos + 8..end];
        if kind == b"mvhd" && !body.is_empty() {
            let ver = body[0];
            if ver == 0 && body.len() >= 20 {
                let ts = u32::from_be_bytes(body[12..16].try_into().unwrap());
                let dur = u32::from_be_bytes(body[16..20].try_into().unwrap()) as u64;
                if ts > 0 && dur > 0 {
                    *duration_secs = Some(dur as f64 / ts as f64);
                }
            } else if ver == 1 && body.len() >= 32 {
                let ts = u32::from_be_bytes(body[20..24].try_into().unwrap());
                let dur = u64::from_be_bytes(body[24..32].try_into().unwrap());
                if ts > 0 && dur > 0 {
                    *duration_secs = Some(dur as f64 / ts as f64);
                }
            }
        } else if matches!(kind, b"trak" | b"mdia" | b"minf" | b"stbl") {
            inspect_moov(body, duration_secs, codecs);
        } else if kind == b"stsd" && body.len() >= 16 {
            let entry_type = String::from_utf8_lossy(&body[12..16]).to_string();
            if entry_type.chars().all(|c| c.is_ascii_alphanumeric()) && !codecs.contains(&entry_type) {
                codecs.push(entry_type);
            }
        }
        pos = end;
    }
}

fn parse_sidx_duration(body: &[u8]) -> Option<f64> {
    if body.len() < 24 {
        return None;
    }
    let ver = body[0];
    let timescale = u32::from_be_bytes(body[8..12].try_into().ok()?);
    if timescale == 0 {
        return None;
    }
    let (ref_count_off, refs_start) = if ver == 0 {
        (22usize, 24usize)
    } else {
        (30usize, 32usize)
    };
    if body.len() < refs_start {
        return None;
    }
    let ref_count = u16::from_be_bytes(body[ref_count_off..ref_count_off + 2].try_into().ok()?) as usize;
    let mut total_ticks = 0u64;
    for i in 0..ref_count.min(1024) {
        let roff = refs_start + i * 12;
        if roff + 12 > body.len() {
            break;
        }
        let sub_dur = u32::from_be_bytes(body[roff + 4..roff + 8].try_into().ok()?) as u64;
        total_ticks += sub_dur;
    }
    if total_ticks > 0 {
        Some(total_ticks as f64 / timescale as f64)
    } else {
        None
    }
}

fn read_ebml_vint_id(b: &[u8], pos: usize) -> Option<(u32, usize)> {
    let first = *b.get(pos)?;
    if first == 0 {
        return None;
    }
    let len = first.leading_zeros() as usize + 1;
    if len > 4 || pos + len > b.len() {
        return None;
    }
    let mut val = 0u32;
    for i in 0..len {
        val = (val << 8) | (b[pos + i] as u32);
    }
    Some((val, pos + len))
}

fn read_ebml_vint_size(b: &[u8], pos: usize) -> Option<(Option<u64>, usize)> {
    let first = *b.get(pos)?;
    if first == 0 {
        return None;
    }
    let len = first.leading_zeros() as usize + 1;
    if len > 8 || pos + len > b.len() {
        return None;
    }
    let mask = 0xFFu8 >> len;
    let mut val = (first & mask) as u64;
    let mut all_ones = (first & mask) == mask;
    for i in 1..len {
        let byte = b[pos + i];
        if byte != 0xFF {
            all_ones = false;
        }
        val = (val << 8) | (byte as u64);
    }
    if all_ones {
        Some((None, pos + len))
    } else {
        Some((Some(val), pos + len))
    }
}

fn parse_webm_info(bytes: &[u8]) -> (bool, Option<f64>, String) {
    let mut is_webm = false;
    let mut timecode_scale = 1_000_000u64;
    let mut raw_duration: Option<f64> = None;

    let mut pos = 0usize;
    while pos < bytes.len() {
        let Some((id, p1)) = read_ebml_vint_id(bytes, pos) else {
            break;
        };
        let Some((size_opt, p2)) = read_ebml_vint_size(bytes, p1) else {
            break;
        };
        let data_len = size_opt.map(|s| s as usize).unwrap_or(bytes.len() - p2);
        let data_end = p2.saturating_add(data_len).min(bytes.len());

        match id {
            0x1A45_DFA3 | 0x1853_8067 | 0x1549_A966 => {
                // Master elements: descend inside
                pos = p2;
                continue;
            }
            0x4282 => {
                let dt = String::from_utf8_lossy(&bytes[p2..data_end]).to_ascii_lowercase();
                if dt.contains("webm") {
                    is_webm = true;
                }
            }
            0x002A_D7B1 => {
                if data_end > p2 && data_end - p2 <= 8 {
                    let mut v = 0u64;
                    for &byte in &bytes[p2..data_end] {
                        v = (v << 8) | (byte as u64);
                    }
                    if v > 0 {
                        timecode_scale = v;
                    }
                }
            }
            0x4489 => {
                if data_end - p2 == 4 {
                    raw_duration = Some(f32::from_be_bytes(bytes[p2..data_end].try_into().unwrap()) as f64);
                } else if data_end - p2 == 8 {
                    raw_duration = Some(f64::from_be_bytes(bytes[p2..data_end].try_into().unwrap()));
                }
            }
            _ => {}
        }

        if data_end <= pos {
            break;
        }
        pos = data_end;
    }

    let duration_secs = raw_duration.map(|d| (d * (timecode_scale as f64)) / 1_000_000_000.0);
    (
        is_webm,
        duration_secs,
        if is_webm { "WebM".into() } else { "Matroska".into() },
    )
}

fn detect_mpeg_ts_stride(b: &[u8]) -> Option<(usize, usize)> {
    if b.len() >= 377 && b[0] == 0x47 && b[188] == 0x47 && b[376] == 0x47 {
        Some((188, 0))
    } else if b.len() >= 389 && b[4] == 0x47 && b[196] == 0x47 && b[388] == 0x47 {
        Some((192, 4))
    } else {
        None
    }
}

fn parse_mpeg_ts_pcr_duration(b: &[u8], stride: usize, sync_off: usize) -> Option<f64> {
    let mut first_pcr: Option<u64> = None;
    let mut last_pcr: Option<u64> = None;
    let mut pos = sync_off;

    while pos + 188 <= b.len() {
        let p = &b[pos..pos + 188];
        if p[0] == 0x47 {
            let afc = (p[3] >> 4) & 0x03;
            if (afc == 2 || afc == 3) && p[4] >= 7 && (p[5] & 0x10) != 0 {
                let pcr_base = ((p[6] as u64) << 25)
                    | ((p[7] as u64) << 17)
                    | ((p[8] as u64) << 9)
                    | ((p[9] as u64) << 1)
                    | ((p[10] as u64) >> 7);
                if first_pcr.is_none() {
                    first_pcr = Some(pcr_base);
                }
                last_pcr = Some(pcr_base);
            }
        }
        pos += stride;
    }

    if let (Some(f), Some(l)) = (first_pcr, last_pcr) {
        let delta = if l >= f { l - f } else { ((1u64 << 33) - f) + l };
        if delta > 0 {
            return Some(delta as f64 / 90_000.0);
        }
    }
    None
}

fn parse_hls_duration(bytes: &[u8]) -> Option<f64> {
    let text = String::from_utf8_lossy(bytes);
    let mut total = 0.0f64;
    let mut any = false;
    for line in text.lines() {
        let t = line.trim();
        if let Some(rest) = t.strip_prefix("#EXTINF:") {
            let num_str = rest.split(',').next().unwrap_or("").trim();
            if let Ok(sec) = num_str.parse::<f64>()
                && sec.is_finite()
                && sec >= 0.0
            {
                total += sec;
                any = true;
            }
        }
    }
    if any { Some(total) } else { None }
}

fn parse_hls_segment_uris(bytes: &[u8], base_url: &str) -> Vec<String> {
    let text = String::from_utf8_lossy(bytes);
    let base = url::Url::parse(base_url).ok();
    let mut uris = Vec::new();
    for line in text.lines() {
        let t = line.trim();
        if t.is_empty() {
            continue;
        }
        if let Some(rest) = t.strip_prefix("#EXT-X-MAP:") {
            if let Some(uri_idx) = rest.find("URI=\"") {
                let after = &rest[uri_idx + 5..];
                if let Some(end) = after.find('"') {
                    let raw_uri = &after[..end];
                    uris.push(resolve_rel_uri(base.as_ref(), raw_uri));
                }
            }
        } else if !t.starts_with('#') {
            uris.push(resolve_rel_uri(base.as_ref(), t));
        }
    }
    uris
}

fn parse_iso8601_duration(raw: &str) -> Option<f64> {
    let s = raw.trim();
    let rest = s.strip_prefix("PT").or_else(|| s.strip_prefix("P0DT"))?;
    let mut total = 0.0f64;
    let mut num = String::new();
    for ch in rest.chars() {
        if ch.is_ascii_digit() || ch == '.' {
            num.push(ch);
        } else {
            let val = num.parse::<f64>().ok()?;
            num.clear();
            match ch {
                'H' | 'h' => total += val * 3600.0,
                'M' | 'm' => total += val * 60.0,
                'S' | 's' => total += val,
                _ => {}
            }
        }
    }
    Some(total)
}

fn parse_dash_mpd_duration(bytes: &[u8]) -> Option<f64> {
    let text = String::from_utf8_lossy(bytes);
    let key = "mediaPresentationDuration=\"";
    let idx = text.find(key)?;
    let rest = &text[idx + key.len()..];
    let end = rest.find('"')?;
    parse_iso8601_duration(&rest[..end])
}

fn parse_dash_segment_uris(bytes: &[u8], base_url: &str) -> Vec<String> {
    let text = String::from_utf8_lossy(bytes);
    let base = url::Url::parse(base_url).ok();
    let mut uris = Vec::new();
    for attr in ["sourceURL=\"", "media=\""] {
        let mut search = text.as_ref();
        while let Some(idx) = search.find(attr) {
            let after = &search[idx + attr.len()..];
            if let Some(end) = after.find('"') {
                let raw = &after[..end];
                if !raw.contains('$') {
                    uris.push(resolve_rel_uri(base.as_ref(), raw));
                }
                search = &after[end + 1..];
            } else {
                break;
            }
        }
    }
    uris
}

fn resolve_rel_uri(base: Option<&url::Url>, raw: &str) -> String {
    if raw.starts_with("http://") || raw.starts_with("https://") {
        return raw.to_string();
    }
    if let Some(b) = base
        && let Ok(joined) = b.join(raw)
    {
        return joined.to_string();
    }
    raw.to_string()
}

fn strip_query(u: &str) -> &str {
    u.split('?').next().unwrap_or(u)
}

fn parse_content_range(item: &UnifiedCacheItem) -> Option<(usize, usize, Option<usize>)> {
    let val = item
        .headers
        .iter()
        .find(|h| h.name.eq_ignore_ascii_case("content-range"))
        .map(|h| h.value.as_str())?;
    let rest = val.trim().strip_prefix("bytes ")?;
    let (range_part, total_part) = rest.split_once('/')?;
    let (s_str, e_str) = range_part.split_once('-')?;
    let start: usize = s_str.trim().parse().ok()?;
    let end: usize = e_str.trim().parse().ok()?;
    let total = total_part.trim().parse::<usize>().ok();
    Some((start, end, total))
}

fn normalize_segment_stem(url: &str) -> Option<(String, u64)> {
    let clean = strip_query(url);
    let (dir, file) = clean.rsplit_once('/')?;
    if file.is_empty() {
        return None;
    }
    let (base, ext_part) = match file.rsplit_once('.') {
        Some((b, e)) if !b.is_empty() && !e.is_empty() => (b, Some(e)),
        _ => (file, None),
    };
    let bytes = base.as_bytes();
    let end = bytes.iter().rposition(|b| b.is_ascii_digit())? + 1;
    let mut start = end;
    while start > 0 && bytes[start - 1].is_ascii_digit() {
        start -= 1;
    }
    let idx = base[start..end].parse::<u64>().ok()?;
    let stem_base = format!("{}{{N}}{}", &base[..start], &base[end..]);
    let stem_file = match ext_part {
        Some(e) => format!("{stem_base}.{e}"),
        None => stem_base,
    };
    Some((format!("{dir}/{stem_file}"), idx))
}

fn format_duration_hint(secs: Option<f64>) -> String {
    match secs {
        Some(s) if s.is_finite() && s >= 0.0 => format!("{s:.2}s"),
        _ => String::new(),
    }
}

fn maybe_extract_video(
    extract_dir: Option<&Path>,
    seq: &mut usize,
    url: &str,
    ext: &str,
    bytes: &[u8],
    warnings: &mut Vec<DiagnosticWarning>,
) -> Option<String> {
    let dir = extract_dir?;
    *seq += 1;
    let raw_name = url::Url::parse(url)
        .ok()
        .and_then(|u| {
            u.path_segments()
                .and_then(|mut s| s.rfind(|seg| !seg.is_empty()).map(str::to_string))
        })
        .unwrap_or_else(|| format!("video_{:04}", *seq));
    let safe_base = sanitize_filename(&raw_name);
    let fname = if let Some((stem, file_ext)) = safe_base.rsplit_once('.')
        && file_ext.eq_ignore_ascii_case(ext)
        && !stem.is_empty()
    {
        format!("{stem}_{:04}.{ext}", *seq)
    } else {
        format!("{safe_base}_{:04}.{ext}", *seq)
    };
    let dest = dir.join(fname);
    match std::fs::write(&dest, bytes) {
        Ok(()) => Some(dest.display().to_string()),
        Err(e) => {
            warnings.push(DiagnosticWarning::warn(
                "carve_video",
                &dest,
                format!("Failed writing carved video: {e}"),
            ));
            None
        }
    }
}

/// Carves cached video containers and manifests (`MP4/M4S`, `WebM`, `MPEG-TS`, `HLS .m3u8`, `DASH .mpd`)
/// and performs 3-pass stream/segment reassembly (manifest-driven, HTTP 206 Content-Range, and orphan segments).
pub fn carve_video(paths: &[PathBuf], extract_dir: Option<&Path>) -> (Vec<VideoCarveRecord>, Vec<DiagnosticWarning>) {
    let (items, mut warnings) = load_unified_cache_from_paths(paths, false);
    if let Some(dir) = extract_dir
        && let Err(e) = std::fs::create_dir_all(dir)
    {
        warnings.push(DiagnosticWarning::warn(
            "carve_video",
            dir,
            format!("Failed creating extract directory: {e}"),
        ));
    }

    struct Candidate {
        item: UnifiedCacheItem,
        bytes: Vec<u8>,
        meta: VideoMeta,
    }

    let mut candidates = Vec::new();
    let mut url_exact: HashMap<String, usize> = HashMap::new();
    let mut url_stripped: HashMap<String, usize> = HashMap::new();

    for item in items {
        let bytes = item.read_decompressed_payload();
        if bytes.is_empty() {
            continue;
        }
        if let Some(meta) = inspect_video_bytes(&bytes, &item.url, item.content_type.as_deref()) {
            let idx = candidates.len();
            url_exact.insert(item.url.clone(), idx);
            url_stripped.insert(strip_query(&item.url).to_string(), idx);
            candidates.push(Candidate { item, bytes, meta });
        }
    }

    let mut consumed = HashSet::new();
    let mut records = Vec::new();
    let mut seq = 0usize;

    // Pass 1: Manifest-driven reassembly (HLS .m3u8 and DASH .mpd)
    for idx in 0..candidates.len() {
        let container = candidates[idx].meta.container.clone();
        if container != "HLS-M3U8" && container != "DASH-MPD" {
            continue;
        }
        let seg_uris = if container == "HLS-M3U8" {
            parse_hls_segment_uris(&candidates[idx].bytes, &candidates[idx].item.url)
        } else {
            parse_dash_segment_uris(&candidates[idx].bytes, &candidates[idx].item.url)
        };

        let mut found_indices = Vec::new();
        for u in &seg_uris {
            let match_idx = url_exact
                .get(u)
                .copied()
                .or_else(|| url_stripped.get(strip_query(u)).copied());
            if let Some(mi) = match_idx
                && mi != idx
                && !found_indices.contains(&mi)
            {
                found_indices.push(mi);
            }
        }

        if !found_indices.is_empty() {
            let mut reassembled = Vec::new();
            for &mi in &found_indices {
                if reassembled.len().saturating_add(candidates[mi].bytes.len()) <= MAX_REASSEMBLE_BYTES {
                    reassembled.extend_from_slice(&candidates[mi].bytes);
                    consumed.insert(mi);
                }
            }
            consumed.insert(idx);
            let sha256 = hex_lower(&Sha256::digest(&reassembled));
            let label = if container == "HLS-M3U8" {
                "HLS-Reassembled"
            } else {
                "DASH-Reassembled"
            };
            let ext = if reassembled.starts_with(&[0x1A, 0x45, 0xDF, 0xA3]) {
                "webm"
            } else if detect_mpeg_ts_stride(&reassembled).is_some() {
                "ts"
            } else {
                "mp4"
            };
            let extracted_path = maybe_extract_video(
                extract_dir,
                &mut seq,
                &candidates[idx].item.url,
                ext,
                &reassembled,
                &mut warnings,
            );
            records.push(VideoCarveRecord {
                browser: candidates[idx].item.browser.clone(),
                profile: candidates[idx].item.profile.clone(),
                url: candidates[idx].item.url.clone(),
                container_format: label.to_string(),
                duration_hint: format_duration_hint(candidates[idx].meta.duration_secs),
                duration_secs: candidates[idx].meta.duration_secs,
                file_size: reassembled.len() as u64,
                cache_time: candidates[idx].item.cache_time,
                segment_count: found_indices.len() as u64,
                reassembled: true,
                codec_hint: candidates[idx].meta.codec_hint.clone(),
                sha256,
                cache_name: candidates[idx].item.cache_name.clone(),
                extracted_path,
            });
        }
    }

    // Pass 2: HTTP 206 Content-Range grouping
    type RangeGroupKey = (String, String, String);
    type RangePart = (usize, usize, usize);
    let mut range_groups: BTreeMap<RangeGroupKey, Vec<RangePart>> = BTreeMap::new();
    for (idx, cand) in candidates.iter().enumerate() {
        if consumed.contains(&idx) {
            continue;
        }
        if let Some((start, end, _)) = parse_content_range(&cand.item) {
            range_groups
                .entry((
                    cand.item.browser.clone(),
                    cand.item.profile.clone(),
                    strip_query(&cand.item.url).to_string(),
                ))
                .or_default()
                .push((start, end, idx));
        }
    }

    for ((browser, profile, url), mut parts) in range_groups {
        if parts.len() < 2 {
            continue;
        }
        parts.sort_by_key(|p| p.0);
        let mut combined = Vec::new();
        let mut written_up_to = 0usize;
        let seg_count = parts.len() as u64;
        for (start, _end, idx) in &parts {
            let chunk = &candidates[*idx].bytes;
            if *start <= written_up_to {
                let skip = written_up_to - *start;
                if skip < chunk.len() && combined.len().saturating_add(chunk.len() - skip) <= MAX_REASSEMBLE_BYTES {
                    combined.extend_from_slice(&chunk[skip..]);
                    written_up_to += chunk.len() - skip;
                }
            } else if combined.len().saturating_add(chunk.len()) <= MAX_REASSEMBLE_BYTES {
                combined.extend_from_slice(chunk);
                written_up_to = *start + chunk.len();
            }
            consumed.insert(*idx);
        }
        let first_idx = parts[0].2;
        let (dur, codec, _, _, _) = parse_mp4_boxes(&combined);
        let sha256 = hex_lower(&Sha256::digest(&combined));
        let extracted_path = maybe_extract_video(extract_dir, &mut seq, &url, "mp4", &combined, &mut warnings);
        records.push(VideoCarveRecord {
            browser,
            profile,
            url,
            container_format: format!("{}-RangeReassembled", candidates[first_idx].meta.container),
            duration_hint: format_duration_hint(dur.or(candidates[first_idx].meta.duration_secs)),
            duration_secs: dur.or(candidates[first_idx].meta.duration_secs),
            file_size: combined.len() as u64,
            cache_time: candidates[first_idx].item.cache_time,
            segment_count: seg_count,
            reassembled: true,
            codec_hint: if codec.is_empty() {
                candidates[first_idx].meta.codec_hint.clone()
            } else {
                codec
            },
            sha256,
            cache_name: candidates[first_idx].item.cache_name.clone(),
            extracted_path,
        });
    }

    // Pass 3: Orphan segment heuristic grouping
    let mut seg_groups: BTreeMap<(String, String, String), Vec<(u64, usize)>> = BTreeMap::new();
    for (idx, cand) in candidates.iter().enumerate() {
        if consumed.contains(&idx) || !cand.meta.is_media_segment {
            continue;
        }
        if let Some((stem, seq_num)) = normalize_segment_stem(&cand.item.url) {
            seg_groups
                .entry((cand.item.browser.clone(), cand.item.profile.clone(), stem))
                .or_default()
                .push((seq_num, idx));
        }
    }

    for ((browser, profile, stem), mut segs) in seg_groups {
        if segs.len() < 2 {
            continue;
        }
        segs.sort_by_key(|s| (s.0, candidates[s.1].item.cache_time));
        let dir_prefix = stem.rsplit_once('/').map(|(d, _)| d).unwrap_or("");
        let mut combined = Vec::new();
        let mut total_segs = 0u64;

        // Prepend matching sibling init segment if present in same dir
        for (i, c) in candidates.iter().enumerate() {
            let dir_matches = dir_prefix.is_empty()
                || strip_query(&c.item.url)
                    .rsplit_once('/')
                    .is_some_and(|(d, _)| d == dir_prefix);
            if !consumed.contains(&i)
                && c.meta.is_init_segment
                && c.item.browser == browser
                && c.item.profile == profile
                && dir_matches
                && c.bytes.len() <= MAX_REASSEMBLE_BYTES
            {
                combined.extend_from_slice(&c.bytes);
                consumed.insert(i);
                total_segs += 1;
                break;
            }
        }

        for &(_, idx) in &segs {
            if combined.len().saturating_add(candidates[idx].bytes.len()) <= MAX_REASSEMBLE_BYTES {
                combined.extend_from_slice(&candidates[idx].bytes);
                consumed.insert(idx);
                total_segs += 1;
            }
        }
        let first_idx = segs[0].1;
        let sha256 = hex_lower(&Sha256::digest(&combined));
        let extracted_path = maybe_extract_video(extract_dir, &mut seq, &stem, "mp4", &combined, &mut warnings);
        records.push(VideoCarveRecord {
            browser,
            profile,
            url: stem,
            container_format: "Segment-Reassembled".into(),
            duration_hint: format_duration_hint(candidates[first_idx].meta.duration_secs),
            duration_secs: candidates[first_idx].meta.duration_secs,
            file_size: combined.len() as u64,
            cache_time: candidates[first_idx].item.cache_time,
            segment_count: total_segs,
            reassembled: true,
            codec_hint: candidates[first_idx].meta.codec_hint.clone(),
            sha256,
            cache_name: candidates[first_idx].item.cache_name.clone(),
            extracted_path,
        });
    }

    // Standalone unconsumed entries
    for (idx, cand) in candidates.iter().enumerate() {
        if consumed.contains(&idx) {
            continue;
        }
        let ext = match cand.meta.container.as_str() {
            "WebM" => "webm",
            "MPEG-TS" => "ts",
            "MPEG-M2TS" => "m2ts",
            "HLS-M3U8" => "m3u8",
            "DASH-MPD" => "mpd",
            "M4S-Segment" => "m4s",
            _ => "mp4",
        };
        let sha256 = hex_lower(&Sha256::digest(&cand.bytes));
        let extracted_path =
            maybe_extract_video(extract_dir, &mut seq, &cand.item.url, ext, &cand.bytes, &mut warnings);
        records.push(VideoCarveRecord {
            browser: cand.item.browser.clone(),
            profile: cand.item.profile.clone(),
            url: cand.item.url.clone(),
            container_format: cand.meta.container.clone(),
            duration_hint: format_duration_hint(cand.meta.duration_secs),
            duration_secs: cand.meta.duration_secs,
            file_size: cand.bytes.len() as u64,
            cache_time: cand.item.cache_time,
            segment_count: 1,
            reassembled: false,
            codec_hint: cand.meta.codec_hint.clone(),
            sha256,
            cache_name: cand.item.cache_name.clone(),
            extracted_path,
        });
    }

    records.sort_by(|a, b| b.cache_time.cmp(&a.cache_time).then_with(|| a.url.cmp(&b.url)));
    (records, warnings)
}

pub struct VideoCarveTableProvider {
    paths: Vec<PathBuf>,
    extract_dir: Option<PathBuf>,
}

impl VideoCarveTableProvider {
    pub fn new(target: Option<PathBuf>) -> Self {
        Self {
            paths: target.into_iter().collect(),
            extract_dir: None,
        }
    }

    pub fn with_options(paths: Vec<PathBuf>, extract_dir: Option<PathBuf>) -> Self {
        Self { paths, extract_dir }
    }
}

impl TableProvider for VideoCarveTableProvider {
    fn tool_id(&self) -> &'static str {
        "chrome2rust_carve_video"
    }

    fn description(&self) -> &'static str {
        "Carve cached video streams & manifests (MP4/M4S, WebM, MPEG-TS, HLS .m3u8, DASH .mpd) with 3-pass segment reassembly (VideoCacheView equivalent)."
    }

    fn schema(&self) -> TableSchema {
        TableSchema::new(
            self.tool_id(),
            "Carved Cached Videos & Streams",
            vec![
                ColumnDef::new("browser", "Browser", ColumnType::Text).with_width_hint(110),
                ColumnDef::new("profile", "Profile", ColumnType::Text).with_width_hint(90),
                ColumnDef::new("url", "URL", ColumnType::Text).with_width_hint(260),
                ColumnDef::new("container_format", "Container", ColumnType::Text).with_width_hint(130),
                ColumnDef::new("duration_hint", "Duration", ColumnType::Text).with_width_hint(85),
                ColumnDef::new("duration_secs", "Duration (s)", ColumnType::Float).with_width_hint(85),
                ColumnDef::new("file_size", "Size", ColumnType::BytesSize).with_width_hint(90),
                ColumnDef::new("cache_time", "Cache Time", ColumnType::Timestamp).with_width_hint(155),
                ColumnDef::new("segment_count", "Segments", ColumnType::Uint).with_width_hint(75),
                ColumnDef::new("reassembled", "Reassembled", ColumnType::Bool).with_width_hint(85),
                ColumnDef::new("codec_hint", "Codec Hint", ColumnType::Text).with_width_hint(120),
                ColumnDef::new("sha256", "SHA-256", ColumnType::Text).with_width_hint(180),
                ColumnDef::new("cache_name", "Cache Name", ColumnType::Text).with_width_hint(120),
            ],
        )
        .with_default_sort(7, SortDirection::Desc)
    }

    fn query(&self, req: &TableQuery) -> Result<TableData, TableError> {
        let (records, _) = carve_video(&self.paths, self.extract_dir.as_deref());
        let rows: Vec<Row> = records
            .into_iter()
            .enumerate()
            .map(|(idx, r)| {
                Row::new(
                    idx as u64 + 1,
                    vec![
                        CellValue::Text(r.browser.clone()),
                        CellValue::Text(r.profile.clone()),
                        CellValue::Text(r.url.clone()),
                        CellValue::Text(r.container_format.clone()),
                        CellValue::Text(r.duration_hint.clone()),
                        r.duration_secs.map(CellValue::Float).unwrap_or(CellValue::Null),
                        CellValue::Bytes(r.file_size),
                        r.cache_time.map(CellValue::Timestamp).unwrap_or(CellValue::Null),
                        CellValue::Uint(r.segment_count),
                        CellValue::Bool(r.reassembled),
                        CellValue::Text(r.codec_hint.clone()),
                        CellValue::Text(r.sha256.clone()),
                        CellValue::Text(r.cache_name.clone()),
                    ],
                )
                .with_detail_json(serde_json::to_value(&r).unwrap_or_default())
            })
            .collect();
        apply_query(&self.schema(), &rows, req)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mp4_webm_mpegts_hls_dash_inspectors() {
        // 1. MP4 with mvhd v0 (timescale=1000, dur=5000 -> 5.0s)
        let mut mvhd = vec![0u8; 20];
        mvhd[12..16].copy_from_slice(&1000u32.to_be_bytes());
        mvhd[16..20].copy_from_slice(&5000u32.to_be_bytes());
        let mut moov = Vec::new();
        moov.extend_from_slice(&((8 + mvhd.len()) as u32).to_be_bytes());
        moov.extend_from_slice(b"mvhd");
        moov.extend_from_slice(&mvhd);
        let mut mp4 = Vec::new();
        mp4.extend_from_slice(&16u32.to_be_bytes());
        mp4.extend_from_slice(b"ftypisom");
        mp4.extend_from_slice(&[0; 4]);
        mp4.extend_from_slice(&((8 + moov.len()) as u32).to_be_bytes());
        mp4.extend_from_slice(b"moov");
        mp4.extend_from_slice(&moov);
        let mp4_meta = inspect_video_bytes(&mp4, "https://v.test/a.mp4", Some("video/mp4")).unwrap();
        assert_eq!(mp4_meta.container, "MP4");
        assert!((mp4_meta.duration_secs.unwrap() - 5.0).abs() < 0.001);

        // 2. WebM (EBML DocType="webm", TimecodeScale=1_000_000, Duration=12.5)
        let mut webm = vec![0x1A, 0x45, 0xDF, 0xA3, 0x88]; // EBML header len=8
        webm.extend_from_slice(&[0x42, 0x82, 0x84]); // DocType len=4
        webm.extend_from_slice(b"webm");
        webm.extend_from_slice(&[0x18, 0x53, 0x80, 0x67, 0xFF]); // Segment unknown len
        webm.extend_from_slice(&[0x15, 0x49, 0xA9, 0x66, 0x93]); // Info len=19
        webm.extend_from_slice(&[0x2A, 0xD7, 0xB1, 0x84]);
        webm.extend_from_slice(&1_000_000u32.to_be_bytes());
        webm.extend_from_slice(&[0x44, 0x89, 0x88]);
        webm.extend_from_slice(&12.5f64.to_be_bytes());
        let webm_meta = inspect_video_bytes(&webm, "https://v.test/b.webm", Some("video/webm")).unwrap();
        assert_eq!(webm_meta.container, "WebM");
        assert!((webm_meta.duration_secs.unwrap() - 0.0125).abs() < 0.0001);

        // 3. MPEG-TS 188-byte packets with PCR delta = 900_000 (10.0s)
        let mut ts = vec![0u8; 188 * 3];
        for (pkt_idx, pcr_base) in [(0usize, 90_000u64), (2usize, 990_000u64)] {
            let p = &mut ts[pkt_idx * 188..(pkt_idx + 1) * 188];
            p[0] = 0x47;
            p[3] = 0x20; // afc=2
            p[4] = 7;
            p[5] = 0x10; // PCR flag
            p[6] = ((pcr_base >> 25) & 0xFF) as u8;
            p[7] = ((pcr_base >> 17) & 0xFF) as u8;
            p[8] = ((pcr_base >> 9) & 0xFF) as u8;
            p[9] = ((pcr_base >> 1) & 0xFF) as u8;
            p[10] = (((pcr_base & 1) << 7) & 0x80) as u8;
        }
        ts[188] = 0x47;
        let ts_meta = inspect_video_bytes(&ts, "https://v.test/c.ts", Some("video/mp2t")).unwrap();
        assert_eq!(ts_meta.container, "MPEG-TS");
        assert!((ts_meta.duration_secs.unwrap() - 10.0).abs() < 0.001);

        // 4. HLS & DASH manifests
        let hls = b"#EXTM3U\n#EXTINF:4.0,\nseg1.ts\n#EXTINF:4.5,\nseg2.ts\n";
        let hls_meta = inspect_video_bytes(hls, "https://v.test/live.m3u8", None).unwrap();
        assert_eq!(hls_meta.container, "HLS-M3U8");
        assert!((hls_meta.duration_secs.unwrap() - 8.5).abs() < 0.001);

        let mpd = br#"<?xml version="1.0"?><MPD mediaPresentationDuration="PT1M15.5S"></MPD>"#;
        let mpd_meta = inspect_video_bytes(mpd, "https://v.test/manifest.mpd", None).unwrap();
        assert_eq!(mpd_meta.container, "DASH-MPD");
        assert!((mpd_meta.duration_secs.unwrap() - 75.5).abs() < 0.001);
    }

    #[test]
    fn test_mp4_isobmff_64bit_size_overflow_no_panic() {
        for s64 in [u64::MAX, u64::MAX - 4] {
            let mut mp4 = Vec::new();
            mp4.extend_from_slice(&16u32.to_be_bytes());
            mp4.extend_from_slice(b"ftypisom");
            mp4.extend_from_slice(&[0; 4]);
            mp4.extend_from_slice(&1u32.to_be_bytes());
            mp4.extend_from_slice(b"moov");
            mp4.extend_from_slice(&s64.to_be_bytes());
            mp4.extend_from_slice(&[0u8; 32]);

            let meta = inspect_video_bytes(&mp4, "https://v.test/bad64.mp4", Some("video/mp4")).unwrap();
            assert_eq!(meta.container, "MP4");
            assert_eq!(meta.duration_secs, None);
        }
    }

    #[test]
    fn test_m2ts_192byte_pcr_33bit_wraparound() {
        let mut m2ts = vec![0u8; 192 * 3];
        let first_pcr = (1u64 << 33) - 90_000;
        let last_pcr = 90_000u64;
        for (pkt_idx, pcr_base) in [(0usize, first_pcr), (2usize, last_pcr)] {
            let p = &mut m2ts[pkt_idx * 192 + 4..(pkt_idx + 1) * 192];
            p[0] = 0x47;
            p[3] = 0x20; // afc=2
            p[4] = 7;
            p[5] = 0x10; // PCR flag
            p[6] = ((pcr_base >> 25) & 0xFF) as u8;
            p[7] = ((pcr_base >> 17) & 0xFF) as u8;
            p[8] = ((pcr_base >> 9) & 0xFF) as u8;
            p[9] = ((pcr_base >> 1) & 0xFF) as u8;
            p[10] = (((pcr_base & 1) << 7) & 0x80) as u8;
        }
        m2ts[192 + 4] = 0x47;
        let meta = inspect_video_bytes(&m2ts, "https://v.test/wrap.m2ts", Some("video/mp2t")).unwrap();
        assert_eq!(meta.container, "MPEG-M2TS");
        assert!((meta.duration_secs.unwrap() - 2.0).abs() < 0.001);
    }

    #[test]
    fn test_normalize_segment_stem_trailing_digits_before_ext() {
        let (stem1, idx1) =
            normalize_segment_stem("https://orph2.test/v/17947008001234567890_1.m4s?token=abc").unwrap();
        let (stem2, idx2) = normalize_segment_stem("https://orph2.test/v/17947008001234567890_2.m4s").unwrap();
        assert_eq!(stem1, "https://orph2.test/v/17947008001234567890_{N}.m4s");
        assert_eq!(stem1, stem2);
        assert_eq!(idx1, 1);
        assert_eq!(idx2, 2);
    }
}
