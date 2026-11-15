use chrome2rust_core::error::DiagnosticWarning;
use chrome2rust_core::time::chrome_us_to_datetime;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SessionsAnalysis {
    pub files_parsed: Vec<SessionFileMeta>,
    pub encrypted_sessions_present: bool,
    pub open_tabs: Vec<SessionTabRecord>,
    pub closed_tabs: Vec<SessionTabRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionFileMeta {
    pub filename: String,
    pub dialect: String,
    pub version: u32,
    pub command_count: usize,
    pub file_timestamp: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionNavigationEntry {
    pub index: i32,
    pub url: String,
    pub title: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionTabRecord {
    pub source_file: String,
    pub tab_id: i32,
    pub window_id: Option<i32>,
    pub selected_nav_index: Option<i32>,
    pub current_url: String,
    pub current_title: String,
    pub is_closed: bool,
    pub timestamp: Option<DateTime<Utc>>,
    pub navigations: Vec<SessionNavigationEntry>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SnssDialect {
    Session,
    Tabs,
}

pub fn parse_sessions(profile_dir: &Path, warnings: &mut Vec<DiagnosticWarning>) -> SessionsAnalysis {
    let mut out = SessionsAnalysis::default();

    let enc_dir = profile_dir.join("Sessions_Encrypted");
    if enc_dir.is_dir()
        && let Ok(mut rd) = std::fs::read_dir(&enc_dir)
        && rd.next().is_some()
    {
        out.encrypted_sessions_present = true;
    }

    let mut candidate_files: Vec<(std::path::PathBuf, SnssDialect)> = Vec::new();

    // Modern Sessions/ folder
    let sessions_dir = profile_dir.join("Sessions");
    if sessions_dir.is_dir()
        && let Ok(rd) = std::fs::read_dir(&sessions_dir)
    {
        for entry in rd.flatten() {
            let p = entry.path();
            if !p.is_file() {
                continue;
            }
            let name = entry.file_name().to_string_lossy().to_string();
            if name.starts_with("Session_") {
                candidate_files.push((p, SnssDialect::Session));
            } else if name.starts_with("Tabs_") {
                candidate_files.push((p, SnssDialect::Tabs));
            }
        }
    }

    // Legacy Chrome session files at profile root
    for (name, dialect) in [
        ("Current Session", SnssDialect::Session),
        ("Last Session", SnssDialect::Session),
        ("Current Tabs", SnssDialect::Tabs),
        ("Last Tabs", SnssDialect::Tabs),
    ] {
        let p = profile_dir.join(name);
        if p.is_file() {
            candidate_files.push((p, dialect));
        }
    }

    candidate_files.sort_by(|a, b| a.0.cmp(&b.0));

    for (path, dialect) in candidate_files {
        parse_snss_file(&path, dialect, &mut out, warnings);
    }

    out
}

fn parse_snss_file(
    path: &Path,
    dialect: SnssDialect,
    out: &mut SessionsAnalysis,
    warnings: &mut Vec<DiagnosticWarning>,
) {
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) => {
            warnings.push(DiagnosticWarning::warn(
                "sessions",
                path,
                format!("Failed to read SNSS file: {e}"),
            ));
            return;
        }
    };

    if bytes.len() < 8 || &bytes[0..4] != b"SNSS" {
        return;
    }

    let version = u32::from_le_bytes(bytes[4..8].try_into().unwrap_or([0; 4]));
    let fname = path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default();
    let file_ts = fname
        .split('_')
        .nth(1)
        .and_then(|s| s.parse::<i64>().ok())
        .and_then(chrome_us_to_datetime);

    let mut off = 8usize;
    let mut cmd_count = 0usize;

    let mut tabs: HashMap<i32, SessionTabRecord> = HashMap::new();
    let mut closed_windows: HashMap<i32, bool> = HashMap::new();

    while off + 2 <= bytes.len() {
        let size = u16::from_le_bytes([bytes[off], bytes[off + 1]]) as usize;
        off += 2;
        if size == 0 || off + size > bytes.len() {
            break;
        }
        let cmd_id = bytes[off];
        let payload = &bytes[off + 1..off + size];
        off += size;
        cmd_count += 1;

        match dialect {
            SnssDialect::Session => match cmd_id {
                // kCommandSetTabWindow = 0 (window_id: i32, tab_id: i32)
                0 if payload.len() >= 8 => {
                    let win_id = read_i32(&payload[0..4]);
                    let tab_id = read_i32(&payload[4..8]);
                    let tab = tabs.entry(tab_id).or_insert_with(|| new_tab(&fname, tab_id, false));
                    tab.window_id = Some(win_id);
                }
                // kCommandUpdateTabNavigation = 6 (Pickle)
                6 => {
                    if let Some((tab_id, nav)) = parse_nav_pickle(payload) {
                        let tab = tabs.entry(tab_id).or_insert_with(|| new_tab(&fname, tab_id, false));
                        upsert_nav(tab, nav);
                    }
                }
                // kCommandSetSelectedNavigationIndex = 7 (tab_id: i32, index: i32)
                7 if payload.len() >= 8 => {
                    let tab_id = read_i32(&payload[0..4]);
                    let idx = read_i32(&payload[4..8]);
                    let tab = tabs.entry(tab_id).or_insert_with(|| new_tab(&fname, tab_id, false));
                    tab.selected_nav_index = Some(idx);
                }
                // kCommandTabClosed = 12 (tab_id: i32, close_time: i64)
                12 | 16 if payload.len() >= 4 => {
                    let tab_id = read_i32(&payload[0..4]);
                    let close_time = if payload.len() >= 12 {
                        chrome_us_to_datetime(read_i64(&payload[4..12]))
                    } else {
                        None
                    };
                    let tab = tabs.entry(tab_id).or_insert_with(|| new_tab(&fname, tab_id, true));
                    tab.is_closed = true;
                    if close_time.is_some() {
                        tab.timestamp = close_time;
                    }
                }
                // kCommandWindowClosed = 13 / 17
                13 | 17 if payload.len() >= 4 => {
                    let win_id = read_i32(&payload[0..4]);
                    closed_windows.insert(win_id, true);
                }
                // kCommandSetTabLastActiveTime = 21 (tab_id: i32, pad/unused or time: i64)
                21 if payload.len() >= 16 => {
                    let tab_id = read_i32(&payload[0..4]);
                    let ts = chrome_us_to_datetime(read_i64(&payload[8..16]));
                    if let Some(t) = ts {
                        let tab = tabs.entry(tab_id).or_insert_with(|| new_tab(&fname, tab_id, false));
                        tab.timestamp = Some(t);
                    }
                }
                _ => {}
            },
            SnssDialect::Tabs => match cmd_id {
                // kCommandUpdateTabNavigation = 1 (Pickle)
                1 => {
                    if let Some((tab_id, nav)) = parse_nav_pickle(payload) {
                        let tab = tabs.entry(tab_id).or_insert_with(|| new_tab(&fname, tab_id, true));
                        upsert_nav(tab, nav);
                    }
                }
                // kCommandTab = 4 (tab_id: i32, index: i32, timestamp: i64)
                4 if payload.len() >= 16 => {
                    let tab_id = read_i32(&payload[0..4]);
                    let idx = read_i32(&payload[4..8]);
                    let ts = chrome_us_to_datetime(read_i64(&payload[8..16]));
                    let tab = tabs.entry(tab_id).or_insert_with(|| new_tab(&fname, tab_id, true));
                    tab.selected_nav_index = Some(idx);
                    if ts.is_some() {
                        tab.timestamp = ts;
                    }
                }
                _ => {}
            },
        }
    }

    out.files_parsed.push(SessionFileMeta {
        filename: fname,
        dialect: match dialect {
            SnssDialect::Session => "Session".into(),
            SnssDialect::Tabs => "Tabs".into(),
        },
        version,
        command_count: cmd_count,
        file_timestamp: file_ts,
    });

    let mut list: Vec<SessionTabRecord> = tabs.into_values().collect();
    list.sort_by_key(|t| t.tab_id);
    for mut tab in list {
        tab.navigations.sort_by_key(|n| n.index);
        if let Some(sel_idx) = tab.selected_nav_index
            && let Some(nav) = tab.navigations.iter().find(|n| n.index == sel_idx)
        {
            tab.current_url = nav.url.clone();
            tab.current_title = nav.title.clone();
        } else if let Some(last) = tab.navigations.last() {
            tab.current_url = last.url.clone();
            tab.current_title = last.title.clone();
        }
        if tab.current_url.is_empty() && tab.navigations.is_empty() {
            continue;
        }
        if let Some(wid) = tab.window_id
            && closed_windows.get(&wid).copied().unwrap_or(false)
        {
            tab.is_closed = true;
        }
        if tab.is_closed {
            out.closed_tabs.push(tab);
        } else {
            out.open_tabs.push(tab);
        }
    }
}

fn new_tab(source_file: &str, tab_id: i32, is_closed: bool) -> SessionTabRecord {
    SessionTabRecord {
        source_file: source_file.to_string(),
        tab_id,
        window_id: None,
        selected_nav_index: None,
        current_url: String::new(),
        current_title: String::new(),
        is_closed,
        timestamp: None,
        navigations: Vec::new(),
    }
}

fn upsert_nav(tab: &mut SessionTabRecord, nav: SessionNavigationEntry) {
    if let Some(existing) = tab.navigations.iter_mut().find(|n| n.index == nav.index) {
        *existing = nav;
    } else {
        tab.navigations.push(nav);
    }
}

fn parse_nav_pickle(payload: &[u8]) -> Option<(i32, SessionNavigationEntry)> {
    if payload.len() < 16 {
        return None;
    }
    let _pickle_len = u32::from_le_bytes(payload[0..4].try_into().ok()?);
    let mut off = 4usize;

    let tab_id = read_i32_at(payload, &mut off)?;
    let index = read_i32_at(payload, &mut off)?;
    let url = read_pickle_string(payload, &mut off)?;
    let title = read_pickle_string16(payload, &mut off).unwrap_or_default();

    Some((tab_id, SessionNavigationEntry { index, url, title }))
}

fn read_i32(b: &[u8]) -> i32 {
    i32::from_le_bytes(b.try_into().unwrap_or([0; 4]))
}

fn read_i64(b: &[u8]) -> i64 {
    i64::from_le_bytes(b.try_into().unwrap_or([0; 8]))
}

fn read_i32_at(buf: &[u8], off: &mut usize) -> Option<i32> {
    if *off + 4 > buf.len() {
        return None;
    }
    let val = read_i32(&buf[*off..*off + 4]);
    *off += 4;
    Some(val)
}

fn read_pickle_string(buf: &[u8], off: &mut usize) -> Option<String> {
    if *off + 4 > buf.len() {
        return None;
    }
    let len = u32::from_le_bytes(buf[*off..*off + 4].try_into().ok()?) as usize;
    *off += 4;
    if len > 1024 * 1024 || *off + len > buf.len() {
        return None;
    }
    let s = String::from_utf8_lossy(&buf[*off..*off + len]).into_owned();
    let aligned = len.div_ceil(4) * 4;
    *off = (*off + aligned).min(buf.len());
    Some(s)
}

fn read_pickle_string16(buf: &[u8], off: &mut usize) -> Option<String> {
    if *off + 4 > buf.len() {
        return None;
    }
    let char_len = u32::from_le_bytes(buf[*off..*off + 4].try_into().ok()?) as usize;
    *off += 4;
    let byte_len = char_len.checked_mul(2)?;
    if byte_len > 1024 * 1024 || *off + byte_len > buf.len() {
        return None;
    }
    let units: Vec<u16> = buf[*off..*off + byte_len]
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    let s = String::from_utf16_lossy(&units);
    let aligned = byte_len.div_ceil(4) * 4;
    *off = (*off + aligned).min(buf.len());
    Some(s)
}
