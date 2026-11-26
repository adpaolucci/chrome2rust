use crate::error::ChromeError;
use crate::time::{CF_ABSOLUTE_EPOCH_OFFSET_SECS, cf_absolute_time_to_datetime};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

const MAX_PLIST_DEPTH: usize = 64;
const MAX_PLIST_OBJECTS: usize = 2_000_000;
const MAX_PLIST_DECODED_NODES: usize = 250_000;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum PlistValue {
    Dict(BTreeMap<String, PlistValue>),
    Array(Vec<PlistValue>),
    String(String),
    Data(Vec<u8>),
    Integer(i64),
    Real(f64),
    Bool(bool),
    Date(DateTime<Utc>),
    Uid(u64),
}

impl PlistValue {
    pub fn as_dict(&self) -> Option<&BTreeMap<String, PlistValue>> {
        match self {
            Self::Dict(d) => Some(d),
            _ => None,
        }
    }

    pub fn as_array(&self) -> Option<&[PlistValue]> {
        match self {
            Self::Array(a) => Some(a),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::String(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Self::Integer(v) => Some(*v),
            Self::Uid(v) => i64::try_from(*v).ok(),
            _ => None,
        }
    }

    pub fn as_f64(&self) -> Option<f64> {
        match self {
            Self::Real(v) => Some(*v),
            Self::Integer(v) => Some(*v as f64),
            _ => None,
        }
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Self::Bool(b) => Some(*b),
            _ => None,
        }
    }

    pub fn as_date(&self) -> Option<DateTime<Utc>> {
        match self {
            Self::Date(dt) => Some(*dt),
            _ => None,
        }
    }

    pub fn as_data(&self) -> Option<&[u8]> {
        match self {
            Self::Data(d) => Some(d),
            _ => None,
        }
    }

    pub fn as_uid(&self) -> Option<u64> {
        match self {
            Self::Uid(u) => Some(*u),
            Self::Dict(d) => d
                .get("CF$UID")
                .and_then(PlistValue::as_i64)
                .and_then(|v| u64::try_from(v).ok()),
            _ => None,
        }
    }

    pub fn get(&self, key: &str) -> Option<&PlistValue> {
        self.as_dict()?.get(key)
    }
}

/// Resolves an `NSKeyedArchiver` `$objects` reference (`PlistValue::Uid(idx)` or `{ "CF$UID": idx }`),
/// or returns `val` directly if it is not a UID reference.
pub fn resolve_keyed_ref<'a>(val: &'a PlistValue, objects: &'a [PlistValue]) -> &'a PlistValue {
    if let Some(uid) = val.as_uid()
        && let Some(target) = objects.get(uid as usize)
    {
        return target;
    }
    val
}

/// Parses an Apple Property List (`bplist00` binary or XML plist) in pure safe Rust.
pub fn parse_plist(bytes: &[u8]) -> Result<PlistValue, ChromeError> {
    if bytes.starts_with(b"bplist00") {
        parse_bplist00(bytes)
    } else {
        let text = std::str::from_utf8(bytes)
            .map_err(|e| ChromeError::InvalidFormat(format!("invalid UTF-8 XML plist: {e}")))?;
        parse_xml_plist(text)
    }
}

fn read_be_uint(slice: &[u8]) -> Result<u64, ChromeError> {
    if slice.is_empty() || slice.len() > 8 {
        return Err(ChromeError::InvalidFormat("invalid bplist integer byte width".into()));
    }
    let mut buf = [0u8; 8];
    buf[8 - slice.len()..].copy_from_slice(slice);
    Ok(u64::from_be_bytes(buf))
}

fn parse_bplist00(bytes: &[u8]) -> Result<PlistValue, ChromeError> {
    if bytes.len() < 40 {
        return Err(ChromeError::InvalidFormat(
            "bplist00 smaller than minimum 40 bytes".into(),
        ));
    }
    let trailer = &bytes[bytes.len() - 32..];
    let offset_int_size = trailer[6] as usize;
    let object_ref_size = trailer[7] as usize;
    let num_objects = u64::from_be_bytes(trailer[8..16].try_into().unwrap()) as usize;
    let top_object = u64::from_be_bytes(trailer[16..24].try_into().unwrap()) as usize;
    let offset_table_offset = u64::from_be_bytes(trailer[24..32].try_into().unwrap()) as usize;

    if !matches!(offset_int_size, 1 | 2 | 4 | 8) || !matches!(object_ref_size, 1 | 2 | 4 | 8) {
        return Err(ChromeError::InvalidFormat("invalid bplist00 trailer int sizes".into()));
    }
    if num_objects == 0 || num_objects > MAX_PLIST_OBJECTS {
        return Err(ChromeError::InvalidFormat("invalid bplist00 object count".into()));
    }
    if top_object >= num_objects {
        return Err(ChromeError::InvalidFormat("bplist00 top_object out of bounds".into()));
    }
    let table_bytes = num_objects
        .checked_mul(offset_int_size)
        .ok_or_else(|| ChromeError::InvalidFormat("bplist00 offset table size overflow".into()))?;
    let table_end = offset_table_offset
        .checked_add(table_bytes)
        .ok_or_else(|| ChromeError::InvalidFormat("bplist00 offset table end overflow".into()))?;
    if offset_table_offset < 8 || table_end > bytes.len() - 32 {
        return Err(ChromeError::InvalidFormat("bplist00 offset table out of bounds".into()));
    }

    let mut offsets = Vec::with_capacity(num_objects);
    for i in 0..num_objects {
        let start = offset_table_offset + i * offset_int_size;
        let off = read_be_uint(&bytes[start..start + offset_int_size])? as usize;
        if off < 8 || off >= offset_table_offset {
            return Err(ChromeError::InvalidFormat(
                "bplist00 object offset out of bounds".into(),
            ));
        }
        offsets.push(off);
    }

    let ctx = BplistCtx {
        bytes,
        offset_table_offset,
        offsets,
        object_ref_size,
    };
    let mut visited = vec![false; ctx.offsets.len()];
    let mut remaining_budget = MAX_PLIST_DECODED_NODES;
    ctx.decode_object(top_object, 0, &mut visited, &mut remaining_budget)
}

struct BplistCtx<'a> {
    bytes: &'a [u8],
    offset_table_offset: usize,
    offsets: Vec<usize>,
    object_ref_size: usize,
}

impl<'a> BplistCtx<'a> {
    fn read_len(&self, obj_off: usize, low_nibble: u8) -> Result<(usize, usize), ChromeError> {
        if low_nibble != 0x0F {
            return Ok((low_nibble as usize, obj_off + 1));
        }
        let marker = *self
            .bytes
            .get(obj_off + 1)
            .ok_or_else(|| ChromeError::InvalidFormat("truncated bplist00 extended length".into()))?;
        if (marker & 0xF0) != 0x10 {
            return Err(ChromeError::InvalidFormat(
                "expected 0x1n integer for bplist00 extended length".into(),
            ));
        }
        let int_len = 1usize << (marker & 0x0F);
        let start = obj_off + 2;
        let end = start
            .checked_add(int_len)
            .ok_or_else(|| ChromeError::InvalidFormat("len overflow".into()))?;
        if end > self.offset_table_offset {
            return Err(ChromeError::InvalidFormat("truncated bplist00 extended integer".into()));
        }
        let val = read_be_uint(&self.bytes[start..end])? as usize;
        Ok((val, end))
    }

    fn decode_object(
        &self,
        obj_idx: usize,
        depth: usize,
        visited: &mut [bool],
        remaining_budget: &mut usize,
    ) -> Result<PlistValue, ChromeError> {
        if *remaining_budget == 0 {
            return Err(ChromeError::InvalidFormat(
                "bplist00 decoded node budget exceeded".into(),
            ));
        }
        *remaining_budget -= 1;
        if depth > MAX_PLIST_DEPTH {
            return Err(ChromeError::InvalidFormat("bplist00 max nesting depth exceeded".into()));
        }
        let Some(slot) = visited.get_mut(obj_idx) else {
            return Err(ChromeError::InvalidFormat("bplist00 object index out of range".into()));
        };
        if *slot {
            return Err(ChromeError::InvalidFormat("bplist00 cyclic object reference".into()));
        }
        *slot = true;

        let off = self.offsets[obj_idx];
        let marker = *self
            .bytes
            .get(off)
            .ok_or_else(|| ChromeError::InvalidFormat("bplist00 truncated object marker".into()))?;
        let kind = marker & 0xF0;
        let info = marker & 0x0F;

        let res = match kind {
            0x00 => match info {
                0x00 => Ok(PlistValue::Bool(false)), // null
                0x08 => Ok(PlistValue::Bool(false)),
                0x09 => Ok(PlistValue::Bool(true)),
                _ => Ok(PlistValue::Bool(false)),
            },
            0x10 => {
                let len = 1usize << info;
                let end = off
                    .checked_add(1 + len)
                    .ok_or_else(|| ChromeError::InvalidFormat("int overflow".into()))?;
                if end > self.offset_table_offset {
                    return Err(ChromeError::InvalidFormat("truncated bplist00 int".into()));
                }
                let slice = &self.bytes[off + 1..end];
                let val = if len == 8 {
                    i64::from_be_bytes(slice.try_into().unwrap())
                } else if len <= 4 {
                    read_be_uint(slice)? as i64
                } else {
                    // 16-byte integer -> truncate to signed i64
                    let mut buf = [0u8; 8];
                    buf.copy_from_slice(&slice[slice.len() - 8..]);
                    i64::from_be_bytes(buf)
                };
                Ok(PlistValue::Integer(val))
            }
            0x20 => {
                let len = 1usize << info;
                let end = off
                    .checked_add(1 + len)
                    .ok_or_else(|| ChromeError::InvalidFormat("real overflow".into()))?;
                if end > self.offset_table_offset {
                    return Err(ChromeError::InvalidFormat("truncated bplist00 real".into()));
                }
                let slice = &self.bytes[off + 1..end];
                let val = match len {
                    4 => f32::from_be_bytes(slice.try_into().unwrap()) as f64,
                    8 => f64::from_be_bytes(slice.try_into().unwrap()),
                    _ => return Err(ChromeError::InvalidFormat("unsupported bplist00 real width".into())),
                };
                Ok(PlistValue::Real(val))
            }
            0x30 => {
                if info != 0x03 || off + 9 > self.offset_table_offset {
                    return Err(ChromeError::InvalidFormat("invalid bplist00 date".into()));
                }
                let secs = f64::from_be_bytes(self.bytes[off + 1..off + 9].try_into().unwrap());
                let dt = cf_absolute_time_to_datetime(secs).unwrap_or_else(|| {
                    DateTime::<Utc>::from_timestamp(CF_ABSOLUTE_EPOCH_OFFSET_SECS as i64, 0).unwrap()
                });
                Ok(PlistValue::Date(dt))
            }
            0x40 => {
                let (len, start) = self.read_len(off, info)?;
                let end = start
                    .checked_add(len)
                    .ok_or_else(|| ChromeError::InvalidFormat("data overflow".into()))?;
                if end > self.offset_table_offset {
                    return Err(ChromeError::InvalidFormat("truncated bplist00 data".into()));
                }
                Ok(PlistValue::Data(self.bytes[start..end].to_vec()))
            }
            0x50 => {
                let (len, start) = self.read_len(off, info)?;
                let end = start
                    .checked_add(len)
                    .ok_or_else(|| ChromeError::InvalidFormat("ascii overflow".into()))?;
                if end > self.offset_table_offset {
                    return Err(ChromeError::InvalidFormat("truncated bplist00 ascii string".into()));
                }
                Ok(PlistValue::String(
                    String::from_utf8_lossy(&self.bytes[start..end]).to_string(),
                ))
            }
            0x60 => {
                let (char_count, start) = self.read_len(off, info)?;
                let byte_len = char_count
                    .checked_mul(2)
                    .ok_or_else(|| ChromeError::InvalidFormat("utf16 overflow".into()))?;
                let end = start
                    .checked_add(byte_len)
                    .ok_or_else(|| ChromeError::InvalidFormat("utf16 end overflow".into()))?;
                if end > self.offset_table_offset {
                    return Err(ChromeError::InvalidFormat("truncated bplist00 utf16 string".into()));
                }
                let units: Vec<u16> = self.bytes[start..end]
                    .as_chunks::<2>()
                    .0
                    .iter()
                    .map(|&[hi, lo]| u16::from_be_bytes([hi, lo]))
                    .collect();
                Ok(PlistValue::String(String::from_utf16_lossy(&units)))
            }
            0x80 => {
                let len = (info as usize) + 1;
                let end = off
                    .checked_add(1 + len)
                    .ok_or_else(|| ChromeError::InvalidFormat("uid overflow".into()))?;
                if end > self.offset_table_offset || len > 8 {
                    return Err(ChromeError::InvalidFormat("invalid bplist00 uid".into()));
                }
                let val = read_be_uint(&self.bytes[off + 1..end])?;
                Ok(PlistValue::Uid(val))
            }
            0xA0 => {
                let (count, start) = self.read_len(off, info)?;
                let ref_bytes = count
                    .checked_mul(self.object_ref_size)
                    .ok_or_else(|| ChromeError::InvalidFormat("array ref overflow".into()))?;
                let end = start
                    .checked_add(ref_bytes)
                    .ok_or_else(|| ChromeError::InvalidFormat("array end overflow".into()))?;
                if end > self.offset_table_offset {
                    return Err(ChromeError::InvalidFormat("truncated bplist00 array".into()));
                }
                let mut arr = Vec::with_capacity(count.min(4096));
                for i in 0..count {
                    let r_start = start + i * self.object_ref_size;
                    let r_idx = read_be_uint(&self.bytes[r_start..r_start + self.object_ref_size])? as usize;
                    arr.push(self.decode_object(r_idx, depth + 1, visited, remaining_budget)?);
                }
                Ok(PlistValue::Array(arr))
            }
            0xD0 => {
                let (count, start) = self.read_len(off, info)?;
                let total_refs = count
                    .checked_mul(2)
                    .and_then(|n| n.checked_mul(self.object_ref_size))
                    .ok_or_else(|| ChromeError::InvalidFormat("dict ref overflow".into()))?;
                let end = start
                    .checked_add(total_refs)
                    .ok_or_else(|| ChromeError::InvalidFormat("dict end overflow".into()))?;
                if end > self.offset_table_offset {
                    return Err(ChromeError::InvalidFormat("truncated bplist00 dict".into()));
                }
                let mut map = BTreeMap::new();
                for i in 0..count {
                    let k_start = start + i * self.object_ref_size;
                    let v_start = start + (count + i) * self.object_ref_size;
                    let k_idx = read_be_uint(&self.bytes[k_start..k_start + self.object_ref_size])? as usize;
                    let v_idx = read_be_uint(&self.bytes[v_start..v_start + self.object_ref_size])? as usize;
                    let key_val = self.decode_object(k_idx, depth + 1, visited, remaining_budget)?;
                    let key = match key_val {
                        PlistValue::String(s) => s,
                        PlistValue::Integer(n) => n.to_string(),
                        other => format!("{other:?}"),
                    };
                    let val = self.decode_object(v_idx, depth + 1, visited, remaining_budget)?;
                    map.insert(key, val);
                }
                Ok(PlistValue::Dict(map))
            }
            other => Err(ChromeError::InvalidFormat(format!(
                "unsupported bplist00 object marker 0x{other:02x}"
            ))),
        };

        visited[obj_idx] = false;
        res
    }
}

/// Encodes a `PlistValue` into a valid `bplist00` byte stream (useful for synthetic fixtures and tests).
pub fn encode_bplist00(root: &PlistValue) -> Vec<u8> {
    let mut objects: Vec<Vec<u8>> = Vec::new();
    let top = encode_bplist_node(root, &mut objects);

    let mut out = Vec::from(*b"bplist00");
    let mut offsets = Vec::with_capacity(objects.len());
    for obj in &objects {
        offsets.push(out.len() as u64);
        out.extend_from_slice(obj);
    }

    let offset_table_offset = out.len() as u64;
    for off in &offsets {
        out.extend_from_slice(&(*off as u32).to_be_bytes());
    }

    // 32-byte trailer: 6 zero bytes + offset_int_size(4) + object_ref_size(4) + num_objects + top + offset_table_offset
    out.extend_from_slice(&[0u8; 6]);
    out.push(4); // offset_int_size = 4
    out.push(4); // object_ref_size = 4
    out.extend_from_slice(&(objects.len() as u64).to_be_bytes());
    out.extend_from_slice(&(top as u64).to_be_bytes());
    out.extend_from_slice(&offset_table_offset.to_be_bytes());
    out
}

fn push_bplist_header(buf: &mut Vec<u8>, kind_hi: u8, len: usize) {
    if len < 15 {
        buf.push(kind_hi | (len as u8));
    } else {
        buf.push(kind_hi | 0x0F);
        if len <= u8::MAX as usize {
            buf.push(0x10);
            buf.push(len as u8);
        } else if len <= u16::MAX as usize {
            buf.push(0x11);
            buf.extend_from_slice(&(len as u16).to_be_bytes());
        } else {
            buf.push(0x12);
            buf.extend_from_slice(&(len as u32).to_be_bytes());
        }
    }
}

fn encode_bplist_node(val: &PlistValue, objects: &mut Vec<Vec<u8>>) -> usize {
    let idx = objects.len();
    objects.push(Vec::new());
    let mut buf = Vec::new();
    match val {
        PlistValue::Bool(false) => buf.push(0x08),
        PlistValue::Bool(true) => buf.push(0x09),
        PlistValue::Integer(v) => {
            buf.push(0x13);
            buf.extend_from_slice(&v.to_be_bytes());
        }
        PlistValue::Real(v) => {
            buf.push(0x23);
            buf.extend_from_slice(&v.to_be_bytes());
        }
        PlistValue::Date(dt) => {
            buf.push(0x33);
            let cf =
                (dt.timestamp() as f64) + (dt.timestamp_subsec_nanos() as f64 / 1e9) - CF_ABSOLUTE_EPOCH_OFFSET_SECS;
            buf.extend_from_slice(&cf.to_be_bytes());
        }
        PlistValue::Data(d) => {
            push_bplist_header(&mut buf, 0x40, d.len());
            buf.extend_from_slice(d);
        }
        PlistValue::String(s) => {
            if s.is_ascii() {
                push_bplist_header(&mut buf, 0x50, s.len());
                buf.extend_from_slice(s.as_bytes());
            } else {
                let units: Vec<u16> = s.encode_utf16().collect();
                push_bplist_header(&mut buf, 0x60, units.len());
                for u in units {
                    buf.extend_from_slice(&u.to_be_bytes());
                }
            }
        }
        PlistValue::Uid(u) => {
            buf.push(0x83);
            buf.extend_from_slice(&(*u as u32).to_be_bytes());
        }
        PlistValue::Array(arr) => {
            let child_ids: Vec<usize> = arr.iter().map(|c| encode_bplist_node(c, objects)).collect();
            push_bplist_header(&mut buf, 0xA0, child_ids.len());
            for cid in child_ids {
                buf.extend_from_slice(&(cid as u32).to_be_bytes());
            }
        }
        PlistValue::Dict(map) => {
            let mut k_ids = Vec::with_capacity(map.len());
            let mut v_ids = Vec::with_capacity(map.len());
            for (k, v) in map {
                k_ids.push(encode_bplist_node(&PlistValue::String(k.clone()), objects));
                v_ids.push(encode_bplist_node(v, objects));
            }
            push_bplist_header(&mut buf, 0xD0, map.len());
            for kid in k_ids {
                buf.extend_from_slice(&(kid as u32).to_be_bytes());
            }
            for vid in v_ids {
                buf.extend_from_slice(&(vid as u32).to_be_bytes());
            }
        }
    }
    objects[idx] = buf;
    idx
}

// =========================================================================
// Pure-Rust XML Plist Parser (Depth-Guarded)
// =========================================================================

enum XmlContainer {
    Dict {
        map: BTreeMap<String, PlistValue>,
        pending_key: Option<String>,
    },
    Array(Vec<PlistValue>),
}

fn parse_xml_plist(text: &str) -> Result<PlistValue, ChromeError> {
    let mut stack: Vec<XmlContainer> = Vec::new();
    let mut root: Option<PlistValue> = None;
    let bytes = text.as_bytes();
    let mut i = 0usize;

    while i < bytes.len() {
        let Some(rel_lt) = text[i..].find('<') else {
            break;
        };
        i += rel_lt;

        if text[i..].starts_with("<!--") {
            let end = text[i + 4..]
                .find("-->")
                .ok_or_else(|| ChromeError::InvalidFormat("unterminated XML comment in plist".into()))?;
            i = i + 4 + end + 3;
            continue;
        }
        if text[i..].starts_with("<?") {
            let end = text[i + 2..]
                .find("?>")
                .ok_or_else(|| ChromeError::InvalidFormat("unterminated XML processing instruction".into()))?;
            i = i + 2 + end + 2;
            continue;
        }
        if text[i..].starts_with("<!") {
            let end = text[i + 2..]
                .find('>')
                .ok_or_else(|| ChromeError::InvalidFormat("unterminated XML DOCTYPE".into()))?;
            i = i + 2 + end + 1;
            continue;
        }

        let Some(rel_gt) = text[i + 1..].find('>') else {
            return Err(ChromeError::InvalidFormat("unterminated XML tag in plist".into()));
        };
        let tag_raw = text[i + 1..i + 1 + rel_gt].trim();
        i = i + 1 + rel_gt + 1;

        if tag_raw.is_empty() {
            continue;
        }

        let self_closing = tag_raw.ends_with('/');
        let tag_clean = tag_raw.trim_end_matches('/').trim();
        let tag_name = tag_clean.split_whitespace().next().unwrap_or("");

        if let Some(close_name) = tag_name.strip_prefix('/') {
            match close_name {
                "plist" => {}
                "dict" => {
                    let top = stack
                        .pop()
                        .ok_or_else(|| ChromeError::InvalidFormat("unexpected </dict>".into()))?;
                    let XmlContainer::Dict { map, .. } = top else {
                        return Err(ChromeError::InvalidFormat("mismatched </dict>".into()));
                    };
                    push_xml_value(PlistValue::Dict(map), &mut stack, &mut root)?;
                }
                "array" => {
                    let top = stack
                        .pop()
                        .ok_or_else(|| ChromeError::InvalidFormat("unexpected </array>".into()))?;
                    let XmlContainer::Array(arr) = top else {
                        return Err(ChromeError::InvalidFormat("mismatched </array>".into()));
                    };
                    push_xml_value(PlistValue::Array(arr), &mut stack, &mut root)?;
                }
                _ => {}
            }
            continue;
        }

        match tag_name {
            "plist" => continue,
            "dict" => {
                if stack.len() >= MAX_PLIST_DEPTH {
                    return Err(ChromeError::InvalidFormat(
                        "XML plist max nesting depth exceeded".into(),
                    ));
                }
                if self_closing {
                    push_xml_value(PlistValue::Dict(BTreeMap::new()), &mut stack, &mut root)?;
                } else {
                    stack.push(XmlContainer::Dict {
                        map: BTreeMap::new(),
                        pending_key: None,
                    });
                }
            }
            "array" => {
                if stack.len() >= MAX_PLIST_DEPTH {
                    return Err(ChromeError::InvalidFormat(
                        "XML plist max nesting depth exceeded".into(),
                    ));
                }
                if self_closing {
                    push_xml_value(PlistValue::Array(Vec::new()), &mut stack, &mut root)?;
                } else {
                    stack.push(XmlContainer::Array(Vec::new()));
                }
            }
            "true" => push_xml_value(PlistValue::Bool(true), &mut stack, &mut root)?,
            "false" => push_xml_value(PlistValue::Bool(false), &mut stack, &mut root)?,
            "key" | "string" | "integer" | "real" | "date" | "data" => {
                let inner = if self_closing {
                    String::new()
                } else {
                    let close_tag = format!("</{tag_name}>");
                    let rel_close = text[i..]
                        .find(&close_tag)
                        .ok_or_else(|| ChromeError::InvalidFormat(format!("missing {close_tag} in XML plist")))?;
                    let raw_inner = &text[i..i + rel_close];
                    i += rel_close + close_tag.len();
                    decode_xml_entities(raw_inner)
                };

                if tag_name == "key" {
                    let Some(XmlContainer::Dict { pending_key, .. }) = stack.last_mut() else {
                        return Err(ChromeError::InvalidFormat("<key> outside <dict>".into()));
                    };
                    *pending_key = Some(inner);
                } else {
                    let val = match tag_name {
                        "string" => PlistValue::String(inner),
                        "integer" => {
                            let n = inner
                                .trim()
                                .parse::<i64>()
                                .map_err(|_| ChromeError::InvalidFormat(format!("invalid plist integer '{inner}'")))?;
                            PlistValue::Integer(n)
                        }
                        "real" => {
                            let f = inner
                                .trim()
                                .parse::<f64>()
                                .map_err(|_| ChromeError::InvalidFormat(format!("invalid plist real '{inner}'")))?;
                            PlistValue::Real(f)
                        }
                        "date" => {
                            let dt = DateTime::parse_from_rfc3339(inner.trim())
                                .map(|d| d.with_timezone(&Utc))
                                .map_err(|_| ChromeError::InvalidFormat(format!("invalid plist date '{inner}'")))?;
                            PlistValue::Date(dt)
                        }
                        "data" => PlistValue::Data(decode_base64_ws(&inner)?),
                        _ => unreachable!(),
                    };
                    push_xml_value(val, &mut stack, &mut root)?;
                }
            }
            _ => {}
        }
    }

    if !stack.is_empty() {
        return Err(ChromeError::InvalidFormat("unclosed container tag in XML plist".into()));
    }

    root.ok_or_else(|| ChromeError::InvalidFormat("empty or invalid XML plist".into()))
}

fn push_xml_value(
    val: PlistValue,
    stack: &mut [XmlContainer],
    root: &mut Option<PlistValue>,
) -> Result<(), ChromeError> {
    match stack.last_mut() {
        Some(XmlContainer::Array(arr)) => {
            arr.push(val);
            Ok(())
        }
        Some(XmlContainer::Dict { map, pending_key }) => {
            let key = pending_key
                .take()
                .ok_or_else(|| ChromeError::InvalidFormat("value inside <dict> without preceding <key>".into()))?;
            map.insert(key, val);
            Ok(())
        }
        None => {
            *root = Some(val);
            Ok(())
        }
    }
}

fn decode_xml_entities(input: &str) -> String {
    if !input.contains('&') {
        return input.to_string();
    }
    let mut out = String::with_capacity(input.len());
    let mut rest = input;
    while let Some(amp) = rest.find('&') {
        out.push_str(&rest[..amp]);
        let after_amp = &rest[amp + 1..];
        if let Some(semi) = after_amp.find(';') {
            let ent = &after_amp[..semi];
            let valid_span = !ent.is_empty() && !ent.bytes().any(|b| b == b'&' || b == b'<' || b.is_ascii_whitespace());
            let decoded = if valid_span {
                match ent {
                    "amp" => Some('&'),
                    "lt" => Some('<'),
                    "gt" => Some('>'),
                    "quot" => Some('"'),
                    "apos" => Some('\''),
                    _ if ent.starts_with("#x") || ent.starts_with("#X") => {
                        u32::from_str_radix(&ent[2..], 16).ok().and_then(char::from_u32)
                    }
                    _ if ent.starts_with('#') => ent[1..].parse::<u32>().ok().and_then(char::from_u32),
                    _ => None,
                }
            } else {
                None
            };
            if let Some(ch) = decoded {
                out.push(ch);
                rest = &after_amp[semi + 1..];
                continue;
            }
        }
        out.push('&');
        rest = after_amp;
    }
    out.push_str(rest);
    out
}

fn decode_base64_ws(input: &str) -> Result<Vec<u8>, ChromeError> {
    let mut cleaned = Vec::with_capacity(input.len());
    for b in input.bytes() {
        if !b.is_ascii_whitespace() {
            cleaned.push(b);
        }
    }
    if cleaned.is_empty() {
        return Ok(Vec::new());
    }
    if !cleaned.len().is_multiple_of(4) {
        return Err(ChromeError::InvalidFormat(
            "invalid base64 length in plist <data>".into(),
        ));
    }
    let mut out = Vec::with_capacity((cleaned.len() / 4) * 3);
    for chunk in cleaned.as_chunks::<4>().0 {
        let vals = [
            b64_val(chunk[0])?,
            b64_val(chunk[1])?,
            if chunk[2] == b'=' { 64 } else { b64_val(chunk[2])? },
            if chunk[3] == b'=' { 64 } else { b64_val(chunk[3])? },
        ];
        if vals[0] >= 64 || vals[1] >= 64 {
            return Err(ChromeError::InvalidFormat(
                "invalid base64 padding in plist <data>".into(),
            ));
        }
        out.push((vals[0] << 2) | (vals[1] >> 4));
        if vals[2] < 64 {
            out.push((vals[1] << 4) | (vals[2] >> 2));
            if vals[3] < 64 {
                out.push((vals[2] << 6) | vals[3]);
            }
        }
    }
    Ok(out)
}

fn b64_val(b: u8) -> Result<u8, ChromeError> {
    match b {
        b'A'..=b'Z' => Ok(b - b'A'),
        b'a'..=b'z' => Ok(b - b'a' + 26),
        b'0'..=b'9' => Ok(b - b'0' + 52),
        b'+' => Ok(62),
        b'/' => Ok(63),
        _ => Err(ChromeError::InvalidFormat(format!(
            "invalid base64 char '{}'",
            b as char
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xml_plist_parsing_bookmarks_and_data() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<!-- Safari Bookmarks -->
<dict>
    <key>Title</key>
    <string>Root &amp; Bar</string>
    <key>Children</key>
    <array>
        <dict>
            <key>WebBookmarkType</key>
            <string>WebBookmarkTypeLeaf</string>
            <key>URLString</key>
            <string>https://apple.com/</string>
            <key>Count</key>
            <integer>42</integer>
            <key>Pinned</key>
            <true/>
            <key>Payload</key>
            <data>SGVsbG8=</data>
        </dict>
    </array>
</dict>
</plist>"#;
        let parsed = parse_plist(xml.as_bytes()).unwrap();
        assert_eq!(parsed.get("Title").and_then(PlistValue::as_str), Some("Root & Bar"));
        let leaf = &parsed.get("Children").and_then(PlistValue::as_array).unwrap()[0];
        assert_eq!(
            leaf.get("URLString").and_then(PlistValue::as_str),
            Some("https://apple.com/")
        );
        assert_eq!(leaf.get("Count").and_then(PlistValue::as_i64), Some(42));
        assert_eq!(leaf.get("Pinned").and_then(PlistValue::as_bool), Some(true));
        assert_eq!(
            leaf.get("Payload").and_then(PlistValue::as_data),
            Some(b"Hello".as_slice())
        );
    }

    #[test]
    fn test_bplist00_encode_decode_with_uid_and_utf16() {
        let mut inner_dict = BTreeMap::new();
        inner_dict.insert("statusCode".to_string(), PlistValue::Integer(200));
        inner_dict.insert(
            "Content-Type".to_string(),
            PlistValue::String("text/html — UTF16".into()),
        );

        let mut root_dict = BTreeMap::new();
        root_dict.insert("$archiver".to_string(), PlistValue::String("NSKeyedArchiver".into()));
        root_dict.insert("$top".to_string(), PlistValue::Uid(1));
        root_dict.insert(
            "$objects".to_string(),
            PlistValue::Array(vec![PlistValue::String("$null".into()), PlistValue::Dict(inner_dict)]),
        );
        root_dict.insert("blob".to_string(), PlistValue::Data(vec![1, 2, 3, 4]));
        root_dict.insert(
            "when".to_string(),
            PlistValue::Date(DateTime::from_timestamp(1_794_700_800, 0).unwrap()),
        );

        let bytes = encode_bplist00(&PlistValue::Dict(root_dict));
        let decoded = parse_plist(&bytes).unwrap();
        let top_ref = decoded.get("$top").unwrap();
        let objects = decoded.get("$objects").and_then(PlistValue::as_array).unwrap();
        let resolved = resolve_keyed_ref(top_ref, objects);
        assert_eq!(resolved.get("statusCode").and_then(PlistValue::as_i64), Some(200));
        assert_eq!(
            resolved.get("Content-Type").and_then(PlistValue::as_str),
            Some("text/html — UTF16")
        );
        assert_eq!(
            decoded.get("blob").and_then(PlistValue::as_data),
            Some([1, 2, 3, 4].as_slice())
        );
    }

    fn build_diamond_dag_bplist(depth: usize) -> Vec<u8> {
        let num_objects = depth + 1;
        let mut out = Vec::from(*b"bplist00");
        let mut offsets = Vec::with_capacity(num_objects);
        for i in 0..depth {
            offsets.push(out.len() as u64);
            // 2-element array [i+1, i+1] with 1-byte object refs
            out.push(0xA2);
            out.push((i + 1) as u8);
            out.push((i + 1) as u8);
        }
        offsets.push(out.len() as u64);
        out.push(0x09); // bool true leaf

        let offset_table_offset = out.len() as u64;
        for off in &offsets {
            out.extend_from_slice(&(*off as u16).to_be_bytes());
        }
        out.extend_from_slice(&[0u8; 6]);
        out.push(2); // offset_int_size
        out.push(1); // object_ref_size
        out.extend_from_slice(&(num_objects as u64).to_be_bytes());
        out.extend_from_slice(&0u64.to_be_bytes()); // top_object = 0
        out.extend_from_slice(&offset_table_offset.to_be_bytes());
        out
    }

    #[test]
    fn test_bplist00_diamond_dag_budget_rejects_promptly() {
        for depth in [24usize, 60usize] {
            let dag = build_diamond_dag_bplist(depth);
            let start = std::time::Instant::now();
            let err = parse_plist(&dag).unwrap_err();
            let elapsed = start.elapsed();
            assert!(
                err.to_string().contains("budget"),
                "depth={depth} unexpected error: {err}"
            );
            assert!(
                elapsed < std::time::Duration::from_millis(100),
                "depth={depth} took too long: {elapsed:?}"
            );
        }
    }

    #[test]
    fn test_xml_plist_bare_amp_and_unclosed_trailing_tags() {
        let xml_amp = r#"<plist version="1.0"><dict><key>k</key><string>foo &amp &lt; bar</string></dict></plist>"#;
        let parsed = parse_plist(xml_amp.as_bytes()).unwrap();
        assert_eq!(parsed.get("k").and_then(PlistValue::as_str), Some("foo &amp < bar"));

        let xml_unclosed = r#"<plist><dict><key>a</key><string>1</string></dict><dict>"#;
        assert!(parse_plist(xml_unclosed.as_bytes()).is_err());

        let xml_unclosed_arr = r#"<plist><dict><key>a</key><string>1</string></dict><array>"#;
        assert!(parse_plist(xml_unclosed_arr.as_bytes()).is_err());
    }
}
