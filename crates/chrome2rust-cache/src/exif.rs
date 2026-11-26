use serde::{Deserialize, Serialize};
use std::collections::HashSet;

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct ExifMetadata {
    pub byte_order: String,
    pub make: Option<String>,
    pub model: Option<String>,
    pub orientation: Option<u16>,
    pub software: Option<String>,
    pub date_time: Option<String>,
    pub date_time_original: Option<String>,
    pub date_time_digitized: Option<String>,
    pub pixel_x_dimension: Option<u32>,
    pub pixel_y_dimension: Option<u32>,
    pub lens_model: Option<String>,
    pub gps_latitude: Option<f64>,
    pub gps_longitude: Option<f64>,
    pub gps_altitude_m: Option<f64>,
    pub gps_timestamp: Option<String>,
}

impl ExifMetadata {
    pub fn summary(&self) -> String {
        let mut parts = Vec::new();
        if let Some(m) = &self.make {
            parts.push(m.clone());
        }
        if let Some(m) = &self.model {
            parts.push(m.clone());
        }
        if let Some(dt) = &self.date_time_original {
            parts.push(dt.clone());
        } else if let Some(dt) = &self.date_time {
            parts.push(dt.clone());
        }
        if let (Some(lat), Some(lon)) = (self.gps_latitude, self.gps_longitude) {
            parts.push(format!("GPS({lat:.5}, {lon:.5})"));
        }
        parts.join(" | ")
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ImageInfo {
    pub width: Option<u32>,
    pub height: Option<u32>,
    pub exif: Option<ExifMetadata>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Endian {
    Little,
    Big,
}

fn read_u16(b: &[u8], off: usize, e: Endian) -> Option<u16> {
    let s = b.get(off..off + 2)?;
    Some(match e {
        Endian::Little => u16::from_le_bytes([s[0], s[1]]),
        Endian::Big => u16::from_be_bytes([s[0], s[1]]),
    })
}

fn read_u32(b: &[u8], off: usize, e: Endian) -> Option<u32> {
    let s = b.get(off..off + 4)?;
    Some(match e {
        Endian::Little => u32::from_le_bytes([s[0], s[1], s[2], s[3]]),
        Endian::Big => u32::from_be_bytes([s[0], s[1], s[2], s[3]]),
    })
}

/// Inspects image dimensions and EXIF metadata across JPEG, PNG, GIF, WebP, AVIF, ICO, SVG, TIFF, BMP.
pub fn inspect_image_and_exif(bytes: &[u8], format_hint: Option<&str>) -> ImageInfo {
    let mut info = ImageInfo::default();
    if bytes.is_empty() {
        return info;
    }

    if bytes.starts_with(b"\x89PNG\r\n\x1a\n") {
        if bytes.len() >= 24 && &bytes[12..16] == b"IHDR" {
            info.width = Some(u32::from_be_bytes(bytes[16..20].try_into().unwrap()));
            info.height = Some(u32::from_be_bytes(bytes[20..24].try_into().unwrap()));
        }
        info.exif = extract_png_exif(bytes);
    } else if bytes.starts_with(b"\xFF\xD8\xFF") {
        let (w, h, exif) = parse_jpeg(bytes);
        info.width = w;
        info.height = h;
        info.exif = exif;
    } else if bytes.len() >= 10 && (bytes.starts_with(b"GIF87a") || bytes.starts_with(b"GIF89a")) {
        info.width = Some(u16::from_le_bytes([bytes[6], bytes[7]]) as u32);
        info.height = Some(u16::from_le_bytes([bytes[8], bytes[9]]) as u32);
    } else if bytes.len() >= 16 && &bytes[0..4] == b"RIFF" && &bytes[8..12] == b"WEBP" {
        let (w, h, exif) = parse_webp(bytes);
        info.width = w;
        info.height = h;
        info.exif = exif;
    } else if bytes.len() >= 12 && &bytes[4..8] == b"ftyp" {
        let (w, h, exif) = parse_avif(bytes);
        info.width = w;
        info.height = h;
        info.exif = exif;
    } else if bytes.len() >= 22 && &bytes[0..4] == b"\x00\x00\x01\x00" {
        let (w, h) = parse_ico(bytes);
        info.width = w;
        info.height = h;
    } else if bytes.len() >= 26 && bytes.starts_with(b"BM") {
        let dib_size = u32::from_le_bytes(bytes[14..18].try_into().unwrap());
        if dib_size >= 12 {
            if dib_size == 12 && bytes.len() >= 22 {
                info.width = Some(u16::from_le_bytes([bytes[18], bytes[19]]) as u32);
                info.height = Some(u16::from_le_bytes([bytes[20], bytes[21]]) as u32);
            } else {
                let w = i32::from_le_bytes(bytes[18..22].try_into().unwrap()).unsigned_abs();
                let h = i32::from_le_bytes(bytes[22..26].try_into().unwrap()).unsigned_abs();
                if w > 0 && h > 0 {
                    info.width = Some(w);
                    info.height = Some(h);
                }
            }
        }
    } else if bytes.len() >= 8 && (bytes.starts_with(b"II*\0") || bytes.starts_with(b"MM\0*")) {
        let exif = parse_tiff_exif(bytes);
        if let Some(ref ex) = exif {
            info.width = ex.pixel_x_dimension;
            info.height = ex.pixel_y_dimension;
        }
        info.exif = exif;
    } else if format_hint.is_some_and(|f| f.eq_ignore_ascii_case("svg"))
        || bytes.windows(4).take(512).any(|w| w.eq_ignore_ascii_case(b"<svg"))
    {
        let (w, h) = parse_svg_dims(bytes);
        info.width = w;
        info.height = h;
    }

    if info.width.is_none()
        && let Some(ref ex) = info.exif
    {
        info.width = ex.pixel_x_dimension;
    }
    if info.height.is_none()
        && let Some(ref ex) = info.exif
    {
        info.height = ex.pixel_y_dimension;
    }

    info
}

fn parse_jpeg(b: &[u8]) -> (Option<u32>, Option<u32>, Option<ExifMetadata>) {
    let mut pos = 2usize;
    let mut width = None;
    let mut height = None;
    let mut exif = None;

    while pos < b.len() {
        while pos < b.len() && b[pos] != 0xFF {
            pos += 1;
        }
        while pos < b.len() && b[pos] == 0xFF {
            pos += 1;
        }
        if pos >= b.len() {
            break;
        }
        let marker = b[pos];
        pos += 1;
        if marker == 0xD9 || marker == 0xDA {
            break;
        }
        if marker == 0x00 || marker == 0x01 || (0xD0..=0xD8).contains(&marker) {
            continue;
        }
        if pos + 2 > b.len() {
            break;
        }
        let seg_len = u16::from_be_bytes([b[pos], b[pos + 1]]) as usize;
        if seg_len < 2 || pos + seg_len > b.len() {
            break;
        }
        let seg = &b[pos + 2..pos + seg_len];
        pos += seg_len;

        if matches!(
            marker,
            0xC0..=0xC3 | 0xC5..=0xC7 | 0xC9..=0xCB | 0xCD..=0xCF
        ) && seg.len() >= 5
            && width.is_none()
        {
            height = Some(u16::from_be_bytes([seg[1], seg[2]]) as u32);
            width = Some(u16::from_be_bytes([seg[3], seg[4]]) as u32);
        } else if marker == 0xE1 && seg.starts_with(b"Exif\0\0") && exif.is_none() {
            exif = parse_tiff_exif(&seg[6..]);
        }
    }

    (width, height, exif)
}

fn extract_png_exif(b: &[u8]) -> Option<ExifMetadata> {
    let mut pos = 8usize;
    while pos + 12 <= b.len() {
        let len = u32::from_be_bytes(b[pos..pos + 4].try_into().ok()?) as usize;
        let kind = &b[pos + 4..pos + 8];
        let data_start = pos + 8;
        let data_end = data_start.checked_add(len)?;
        if data_end + 4 > b.len() {
            break;
        }
        if kind == b"eXIf" {
            let slice = &b[data_start..data_end];
            if let Some(ex) = parse_tiff_exif(slice.strip_prefix(b"Exif\0\0").unwrap_or(slice)) {
                return Some(ex);
            }
        } else if kind == b"IEND" {
            break;
        }
        pos = data_end + 4;
    }
    None
}

fn parse_webp(b: &[u8]) -> (Option<u32>, Option<u32>, Option<ExifMetadata>) {
    let mut width = None;
    let mut height = None;
    let mut exif = None;

    if b.len() >= 30 && &b[12..16] == b"VP8 " && b[23..26] == [0x9D, 0x01, 0x2A] {
        width = Some((u16::from_le_bytes([b[26], b[27]]) & 0x3FFF) as u32);
        height = Some((u16::from_le_bytes([b[28], b[29]]) & 0x3FFF) as u32);
    } else if b.len() >= 25 && &b[12..16] == b"VP8L" && b[20] == 0x2F {
        let v = u32::from_le_bytes([b[21], b[22], b[23], b[24]]);
        width = Some((v & 0x3FFF) + 1);
        height = Some(((v >> 14) & 0x3FFF) + 1);
    } else if b.len() >= 30 && &b[12..16] == b"VP8X" {
        let w = (b[24] as u32) | ((b[25] as u32) << 8) | ((b[26] as u32) << 16);
        let h = (b[27] as u32) | ((b[28] as u32) << 8) | ((b[29] as u32) << 16);
        width = Some(w + 1);
        height = Some(h + 1);
    }

    let mut pos = 12usize;
    while pos + 8 <= b.len() {
        let cid = &b[pos..pos + 4];
        let csize = u32::from_le_bytes(b[pos + 4..pos + 8].try_into().unwrap()) as usize;
        let dstart = pos + 8;
        let Some(dend) = dstart.checked_add(csize) else {
            break;
        };
        if dend > b.len() {
            break;
        }
        if cid == b"EXIF" && exif.is_none() {
            let slice = &b[dstart..dend];
            exif = parse_tiff_exif(slice.strip_prefix(b"Exif\0\0").unwrap_or(slice));
        }
        pos = dend + (csize & 1);
    }

    (width, height, exif)
}

fn parse_avif(b: &[u8]) -> (Option<u32>, Option<u32>, Option<ExifMetadata>) {
    let mut width = None;
    let mut height = None;
    walk_isobmff_ispe(b, 0, &mut width, &mut height);

    let exif = if b.len() <= 2 * 1024 * 1024 {
        b.windows(6)
            .position(|w| w == b"Exif\0\0")
            .and_then(|idx| parse_tiff_exif(&b[idx + 6..]))
    } else {
        None
    };

    (width, height, exif)
}

fn walk_isobmff_ispe(slice: &[u8], depth: usize, width: &mut Option<u32>, height: &mut Option<u32>) {
    if depth > 8 || width.is_some() {
        return;
    }
    let mut pos = 0usize;
    while pos + 8 <= slice.len() {
        let size32 = u32::from_be_bytes(slice[pos..pos + 4].try_into().unwrap()) as usize;
        let kind = &slice[pos + 4..pos + 8];
        let (hdr, total) = if size32 == 1 {
            let Some(hdr_end) = pos.checked_add(16) else {
                break;
            };
            if hdr_end > slice.len() {
                break;
            }
            let Ok(s64) = usize::try_from(u64::from_be_bytes(slice[pos + 8..hdr_end].try_into().unwrap())) else {
                break;
            };
            (16usize, s64)
        } else if size32 == 0 {
            (8usize, slice.len() - pos)
        } else {
            (8usize, size32)
        };
        let Some(end) = pos.checked_add(total) else {
            break;
        };
        if total < hdr || end > slice.len() {
            break;
        }
        let body = &slice[pos + hdr..end];
        if kind == b"ispe" && body.len() >= 12 {
            *width = Some(u32::from_be_bytes(body[4..8].try_into().unwrap()));
            *height = Some(u32::from_be_bytes(body[8..12].try_into().unwrap()));
            return;
        } else if kind == b"meta" && body.len() > 4 {
            walk_isobmff_ispe(&body[4..], depth + 1, width, height);
        } else if matches!(kind, b"iprp" | b"ipco") {
            walk_isobmff_ispe(body, depth + 1, width, height);
        }
        pos = end;
    }
}

fn parse_ico(b: &[u8]) -> (Option<u32>, Option<u32>) {
    let count = (u16::from_le_bytes([b[4], b[5]]) as usize).min(64);
    let mut best_w = 0u32;
    let mut best_h = 0u32;
    for i in 0..count {
        let off = 6 + i * 16;
        if off + 16 > b.len() {
            break;
        }
        let w = if b[off] == 0 { 256 } else { b[off] as u32 };
        let h = if b[off + 1] == 0 { 256 } else { b[off + 1] as u32 };
        if w * h >= best_w * best_h {
            best_w = w;
            best_h = h;
        }
    }
    if best_w > 0 {
        (Some(best_w), Some(best_h))
    } else {
        (None, None)
    }
}

fn parse_svg_dims(b: &[u8]) -> (Option<u32>, Option<u32>) {
    let head = String::from_utf8_lossy(&b[..b.len().min(4096)]);
    let Some(svg_idx) = head.to_ascii_lowercase().find("<svg") else {
        return (None, None);
    };
    let tag_slice = &head[svg_idx..];
    let end = tag_slice.find('>').unwrap_or(tag_slice.len());
    let tag = &tag_slice[..end];

    let w = extract_xml_attr_num(tag, "width");
    let h = extract_xml_attr_num(tag, "height");
    if w.is_some() && h.is_some() {
        return (w, h);
    }
    if let Some(vb) = extract_xml_attr_str(tag, "viewBox") {
        let nums: Vec<f64> = vb
            .split(|c: char| c.is_ascii_whitespace() || c == ',')
            .filter(|s| !s.is_empty())
            .filter_map(|s| s.parse::<f64>().ok())
            .collect();
        if nums.len() == 4 {
            return (
                w.or_else(|| Some(nums[2].round().max(0.0) as u32)),
                h.or_else(|| Some(nums[3].round().max(0.0) as u32)),
            );
        }
    }
    (w, h)
}

fn extract_xml_attr_str<'a>(tag: &'a str, attr: &str) -> Option<&'a str> {
    let lower = tag.to_ascii_lowercase();
    let needle = format!("{}=\"", attr.to_ascii_lowercase());
    if let Some(idx) = lower.find(&needle) {
        let rest = &tag[idx + needle.len()..];
        if let Some(end) = rest.find('"') {
            return Some(&rest[..end]);
        }
    }
    let needle_sq = format!("{}='", attr.to_ascii_lowercase());
    if let Some(idx) = lower.find(&needle_sq) {
        let rest = &tag[idx + needle_sq.len()..];
        if let Some(end) = rest.find('\'') {
            return Some(&rest[..end]);
        }
    }
    None
}

fn extract_xml_attr_num(tag: &str, attr: &str) -> Option<u32> {
    let raw = extract_xml_attr_str(tag, attr)?.trim();
    let num_part: String = raw.chars().take_while(|c| c.is_ascii_digit() || *c == '.').collect();
    if num_part.is_empty() {
        return None;
    }
    num_part.parse::<f64>().ok().map(|f| f.round().max(0.0) as u32)
}

// =========================================================================
// Pure-Rust TIFF / EXIF IFD0 + ExifIFD + GPS IFD Parser
// =========================================================================

pub fn parse_tiff_exif(tiff: &[u8]) -> Option<ExifMetadata> {
    if tiff.len() < 8 {
        return None;
    }
    let (endian, byte_order) = if &tiff[0..2] == b"II" {
        (Endian::Little, "LittleEndian (II)")
    } else if &tiff[0..2] == b"MM" {
        (Endian::Big, "BigEndian (MM)")
    } else {
        return None;
    };

    if read_u16(tiff, 2, endian)? != 0x002A {
        return None;
    }
    let ifd0_off = read_u32(tiff, 4, endian)? as usize;

    let mut meta = ExifMetadata {
        byte_order: byte_order.to_string(),
        ..Default::default()
    };
    let mut visited = HashSet::new();
    let mut exif_ifd_off = None;
    let mut gps_ifd_off = None;

    read_ifd(
        tiff,
        ifd0_off,
        endian,
        &mut visited,
        IfdKind::Ifd0,
        &mut meta,
        &mut exif_ifd_off,
        &mut gps_ifd_off,
    );

    if let Some(off) = exif_ifd_off {
        read_ifd(
            tiff,
            off,
            endian,
            &mut visited,
            IfdKind::Exif,
            &mut meta,
            &mut None,
            &mut None,
        );
    }
    if let Some(off) = gps_ifd_off {
        read_ifd(
            tiff,
            off,
            endian,
            &mut visited,
            IfdKind::Gps,
            &mut meta,
            &mut None,
            &mut None,
        );
    }

    Some(meta)
}

#[derive(Clone, Copy)]
enum IfdKind {
    Ifd0,
    Exif,
    Gps,
}

#[allow(clippy::too_many_arguments)]
fn read_ifd(
    tiff: &[u8],
    off: usize,
    endian: Endian,
    visited: &mut HashSet<usize>,
    kind: IfdKind,
    meta: &mut ExifMetadata,
    exif_ifd_out: &mut Option<usize>,
    gps_ifd_out: &mut Option<usize>,
) {
    if !visited.insert(off) || visited.len() > 16 || off + 2 > tiff.len() {
        return;
    }
    let count = (read_u16(tiff, off, endian).unwrap_or(0) as usize).min(512);

    let mut gps_lat_ref: Option<String> = None;
    let mut gps_lat_dms: Option<[f64; 3]> = None;
    let mut gps_lon_ref: Option<String> = None;
    let mut gps_lon_dms: Option<[f64; 3]> = None;
    let mut gps_alt_ref: Option<u8> = None;
    let mut gps_alt_val: Option<f64> = None;
    let mut gps_date: Option<String> = None;
    let mut gps_time: Option<String> = None;

    for i in 0..count {
        let entry_off = off + 2 + i * 12;
        if entry_off + 12 > tiff.len() {
            break;
        }
        let tag = read_u16(tiff, entry_off, endian).unwrap_or(0);
        let field_type = read_u16(tiff, entry_off + 2, endian).unwrap_or(0);
        let val_count = read_u32(tiff, entry_off + 4, endian).unwrap_or(0) as usize;

        let unit_size = match field_type {
            1 | 2 | 7 => 1usize,
            3 => 2usize,
            4 | 9 => 4usize,
            5 | 10 => 8usize,
            _ => continue,
        };
        let Some(total_bytes) = val_count.checked_mul(unit_size) else {
            continue;
        };
        if total_bytes == 0 || total_bytes > 64 * 1024 {
            continue;
        }

        let val_slice = if total_bytes <= 4 {
            &tiff[entry_off + 8..entry_off + 8 + total_bytes]
        } else {
            let Some(val_off) = read_u32(tiff, entry_off + 8, endian).map(|v| v as usize) else {
                continue;
            };
            let Some(val_end) = val_off.checked_add(total_bytes) else {
                continue;
            };
            let Some(slice) = tiff.get(val_off..val_end) else {
                continue;
            };
            slice
        };

        let read_ascii = || -> Option<String> {
            let s = String::from_utf8_lossy(val_slice)
                .trim_end_matches('\0')
                .trim()
                .to_string();
            if s.is_empty() { None } else { Some(s) }
        };
        let read_int = || -> Option<u32> {
            match field_type {
                3 if val_slice.len() >= 2 => read_u16(val_slice, 0, endian).map(|v| v as u32),
                4 if val_slice.len() >= 4 => read_u32(val_slice, 0, endian),
                _ => None,
            }
        };
        let read_rational = |idx: usize| -> Option<f64> {
            let base = idx * 8;
            let num = read_u32(val_slice, base, endian)?;
            let den = read_u32(val_slice, base + 4, endian)?;
            if den == 0 { None } else { Some(num as f64 / den as f64) }
        };

        match kind {
            IfdKind::Ifd0 => match tag {
                0x010F => meta.make = read_ascii(),
                0x0110 => meta.model = read_ascii(),
                0x0112 => meta.orientation = read_int().and_then(|v| u16::try_from(v).ok()),
                0x0131 => meta.software = read_ascii(),
                0x0132 => meta.date_time = read_ascii(),
                0x8769 => *exif_ifd_out = read_int().map(|v| v as usize),
                0x8825 => *gps_ifd_out = read_int().map(|v| v as usize),
                _ => {}
            },
            IfdKind::Exif => match tag {
                0x9003 => meta.date_time_original = read_ascii(),
                0x9004 => meta.date_time_digitized = read_ascii(),
                0xA002 => meta.pixel_x_dimension = read_int(),
                0xA003 => meta.pixel_y_dimension = read_int(),
                0xA434 => meta.lens_model = read_ascii(),
                _ => {}
            },
            IfdKind::Gps => match tag {
                0x0001 => gps_lat_ref = read_ascii(),
                0x0002 if val_count >= 3 => {
                    if let (Some(d), Some(m), Some(s)) = (read_rational(0), read_rational(1), read_rational(2)) {
                        gps_lat_dms = Some([d, m, s]);
                    }
                }
                0x0003 => gps_lon_ref = read_ascii(),
                0x0004 if val_count >= 3 => {
                    if let (Some(d), Some(m), Some(s)) = (read_rational(0), read_rational(1), read_rational(2)) {
                        gps_lon_dms = Some([d, m, s]);
                    }
                }
                0x0005 => gps_alt_ref = val_slice.first().copied(),
                0x0006 => gps_alt_val = read_rational(0),
                0x0007 if val_count >= 3 => {
                    if let (Some(h), Some(m), Some(s)) = (read_rational(0), read_rational(1), read_rational(2)) {
                        gps_time = Some(format!("{:02}:{:02}:{:02}", h as u32, m as u32, s as u32));
                    }
                }
                0x001D => gps_date = read_ascii(),
                _ => {}
            },
        }
    }

    if matches!(kind, IfdKind::Gps) {
        if let Some([d, m, s]) = gps_lat_dms {
            let mut dec = d + m / 60.0 + s / 3600.0;
            if gps_lat_ref.as_deref().is_some_and(|r| r.starts_with(['S', 's'])) {
                dec = -dec;
            }
            if (-90.0..=90.0).contains(&dec) {
                meta.gps_latitude = Some(dec);
            }
        }
        if let Some([d, m, s]) = gps_lon_dms {
            let mut dec = d + m / 60.0 + s / 3600.0;
            if gps_lon_ref.as_deref().is_some_and(|r| r.starts_with(['W', 'w'])) {
                dec = -dec;
            }
            if (-180.0..=180.0).contains(&dec) {
                meta.gps_longitude = Some(dec);
            }
        }
        if let Some(alt) = gps_alt_val {
            meta.gps_altitude_m = Some(if gps_alt_ref == Some(1) { -alt } else { alt });
        }
        if gps_date.is_some() || gps_time.is_some() {
            meta.gps_timestamp = Some(match (gps_date, gps_time) {
                (Some(d), Some(t)) => format!("{d} {t} UTC"),
                (Some(d), None) => d,
                (None, Some(t)) => t,
                (None, None) => unreachable!(),
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn push_u16(buf: &mut Vec<u8>, v: u16, be: bool) {
        buf.extend_from_slice(&if be { v.to_be_bytes() } else { v.to_le_bytes() });
    }

    fn push_u32(buf: &mut Vec<u8>, v: u32, be: bool) {
        buf.extend_from_slice(&if be { v.to_be_bytes() } else { v.to_le_bytes() });
    }

    fn build_synthetic_exif(be: bool) -> Vec<u8> {
        let mut tiff = Vec::new();
        tiff.extend_from_slice(if be { b"MM" } else { b"II" });
        push_u16(&mut tiff, 0x002A, be);
        push_u32(&mut tiff, 8, be); // IFD0 at offset 8

        // Layout:
        // IFD0 at 8: 4 entries (Make, Model, ExifIFD ptr, GPS IFD ptr) -> 2 + 4*12 + 4 = 54 bytes -> ends at 62
        // ExifIFD at 62: 1 entry (DateTimeOriginal) -> 2 + 1*12 + 4 = 18 bytes -> ends at 80
        // GPS IFD at 80: 4 entries (LatRef, Lat, LonRef, Lon) -> 2 + 4*12 + 4 = 54 bytes -> ends at 134
        let make = b"Canon\0"; // 6 bytes at 134
        let model = b"EOS R5\0"; // 7 bytes at 140
        let dto = b"2026:11:15 10:20:30\0"; // 20 bytes at 147
        // GPS Lat 3 rationals (24 bytes) at 167: 43/1, 39/1, 1152/100
        // GPS Lon 3 rationals (24 bytes) at 191: 79/1, 22/1, 5952/100

        // IFD0
        push_u16(&mut tiff, 4, be);
        // Make (0x010F, ASCII=2)
        push_u16(&mut tiff, 0x010F, be);
        push_u16(&mut tiff, 2, be);
        push_u32(&mut tiff, make.len() as u32, be);
        push_u32(&mut tiff, 134, be);
        // Model (0x0110, ASCII=2)
        push_u16(&mut tiff, 0x0110, be);
        push_u16(&mut tiff, 2, be);
        push_u32(&mut tiff, model.len() as u32, be);
        push_u32(&mut tiff, 140, be);
        // ExifIFD (0x8769, LONG=4)
        push_u16(&mut tiff, 0x8769, be);
        push_u16(&mut tiff, 4, be);
        push_u32(&mut tiff, 1, be);
        push_u32(&mut tiff, 62, be);
        // GPS IFD (0x8825, LONG=4)
        push_u16(&mut tiff, 0x8825, be);
        push_u16(&mut tiff, 4, be);
        push_u32(&mut tiff, 1, be);
        push_u32(&mut tiff, 80, be);
        push_u32(&mut tiff, 0, be);

        // ExifIFD at 62
        push_u16(&mut tiff, 1, be);
        push_u16(&mut tiff, 0x9003, be);
        push_u16(&mut tiff, 2, be);
        push_u32(&mut tiff, dto.len() as u32, be);
        push_u32(&mut tiff, 147, be);
        push_u32(&mut tiff, 0, be);

        // GPS IFD at 80
        push_u16(&mut tiff, 4, be);
        // LatRef (0x0001, ASCII=2, count=2 inline!)
        push_u16(&mut tiff, 0x0001, be);
        push_u16(&mut tiff, 2, be);
        push_u32(&mut tiff, 2, be);
        tiff.extend_from_slice(b"N\0\0\0");
        // Lat (0x0002, RATIONAL=5, count=3)
        push_u16(&mut tiff, 0x0002, be);
        push_u16(&mut tiff, 5, be);
        push_u32(&mut tiff, 3, be);
        push_u32(&mut tiff, 167, be);
        // LonRef (0x0003, ASCII=2, count=2 inline!)
        push_u16(&mut tiff, 0x0003, be);
        push_u16(&mut tiff, 2, be);
        push_u32(&mut tiff, 2, be);
        tiff.extend_from_slice(b"W\0\0\0");
        // Lon (0x0004, RATIONAL=5, count=3)
        push_u16(&mut tiff, 0x0004, be);
        push_u16(&mut tiff, 5, be);
        push_u32(&mut tiff, 3, be);
        push_u32(&mut tiff, 191, be);
        push_u32(&mut tiff, 0, be);

        assert_eq!(tiff.len(), 134);
        tiff.extend_from_slice(make);
        tiff.extend_from_slice(model);
        tiff.extend_from_slice(dto);
        assert_eq!(tiff.len(), 167);
        for (n, d) in [(43u32, 1u32), (39, 1), (1152, 100)] {
            push_u32(&mut tiff, n, be);
            push_u32(&mut tiff, d, be);
        }
        assert_eq!(tiff.len(), 191);
        for (n, d) in [(79u32, 1u32), (22, 1), (5952, 100)] {
            push_u32(&mut tiff, n, be);
            push_u32(&mut tiff, d, be);
        }
        tiff
    }

    #[test]
    fn test_tiff_exif_big_and_little_endian_with_gps() {
        for be in [true, false] {
            let tiff = build_synthetic_exif(be);
            let meta = parse_tiff_exif(&tiff).expect("valid tiff exif");
            assert_eq!(meta.make.as_deref(), Some("Canon"));
            assert_eq!(meta.model.as_deref(), Some("EOS R5"));
            assert_eq!(meta.date_time_original.as_deref(), Some("2026:11:15 10:20:30"));
            let lat = meta.gps_latitude.unwrap();
            let lon = meta.gps_longitude.unwrap();
            assert!((lat - 43.6532).abs() < 0.0001);
            assert!((lon - (-79.3832)).abs() < 0.0001);
        }
    }

    #[test]
    fn test_image_dimensions_across_formats() {
        // JPEG SOF0 (640x480) + APP1 Big-Endian EXIF
        let tiff = build_synthetic_exif(true);
        let mut jpeg = vec![0xFF, 0xD8, 0xFF, 0xE1];
        let app1_len = (2 + 6 + tiff.len()) as u16;
        jpeg.extend_from_slice(&app1_len.to_be_bytes());
        jpeg.extend_from_slice(b"Exif\0\0");
        jpeg.extend_from_slice(&tiff);
        jpeg.extend_from_slice(&[0xFF, 0xC0, 0x00, 0x0B, 0x08]);
        jpeg.extend_from_slice(&480u16.to_be_bytes());
        jpeg.extend_from_slice(&640u16.to_be_bytes());
        jpeg.extend_from_slice(&[0x01, 0x01, 0x11, 0x00, 0xFF, 0xD9]);
        let jinfo = inspect_image_and_exif(&jpeg, Some("jpg"));
        assert_eq!((jinfo.width, jinfo.height), (Some(640), Some(480)));
        assert_eq!(jinfo.exif.unwrap().make.as_deref(), Some("Canon"));

        // PNG IHDR (320x240) + eXIf Little-Endian
        let tiff_le = build_synthetic_exif(false);
        let mut png = Vec::from(*b"\x89PNG\r\n\x1a\n");
        png.extend_from_slice(&13u32.to_be_bytes());
        png.extend_from_slice(b"IHDR");
        png.extend_from_slice(&320u32.to_be_bytes());
        png.extend_from_slice(&240u32.to_be_bytes());
        png.extend_from_slice(&[8, 6, 0, 0, 0]);
        png.extend_from_slice(&[0; 4]);
        png.extend_from_slice(&(tiff_le.len() as u32).to_be_bytes());
        png.extend_from_slice(b"eXIf");
        png.extend_from_slice(&tiff_le);
        png.extend_from_slice(&[0; 4]);
        let pinfo = inspect_image_and_exif(&png, Some("png"));
        assert_eq!((pinfo.width, pinfo.height), (Some(320), Some(240)));
        assert_eq!(pinfo.exif.unwrap().model.as_deref(), Some("EOS R5"));

        // WebP VP8L (100x50)
        let mut webp = Vec::from(*b"RIFF\x20\x00\x00\x00WEBPVP8L");
        webp.extend_from_slice(&5u32.to_le_bytes());
        webp.push(0x2F);
        let packed = (99u32) | (49u32 << 14);
        webp.extend_from_slice(&packed.to_le_bytes());
        webp.push(0);
        let winfo = inspect_image_and_exif(&webp, Some("webp"));
        assert_eq!((winfo.width, winfo.height), (Some(100), Some(50)));

        // SVG viewBox
        let svg = br#"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 800 600"></svg>"#;
        let sinfo = inspect_image_and_exif(svg, Some("svg"));
        assert_eq!((sinfo.width, sinfo.height), (Some(800), Some(600)));
    }

    #[test]
    fn test_avif_isobmff_64bit_size_overflow_no_panic() {
        for s64 in [u64::MAX, u64::MAX - 4] {
            let mut avif = Vec::new();
            avif.extend_from_slice(&16u32.to_be_bytes());
            avif.extend_from_slice(b"ftypavif");
            avif.extend_from_slice(&[0; 4]);
            // Box at pos = 16 with size32 == 1 and huge 64-bit size
            avif.extend_from_slice(&1u32.to_be_bytes());
            avif.extend_from_slice(b"meta");
            avif.extend_from_slice(&s64.to_be_bytes());
            avif.extend_from_slice(&[0u8; 32]);

            let info = inspect_image_and_exif(&avif, Some("avif"));
            assert_eq!(info.width, None);
            assert_eq!(info.height, None);
        }
    }
}
