use crate::crypto::{CryptoOptions, EncryptionScheme, try_decrypt_chrome_blob};
use crate::error::DiagnosticWarning;
use crate::sqlite_util::ForensicSqlite;
use crate::time::chrome_us_to_datetime;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CookieRecord {
    pub host_key: String,
    pub top_frame_site_key: String,
    pub name: String,
    pub path: String,
    pub value: Option<String>,
    pub encryption_scheme: EncryptionScheme,
    pub encrypted_len: usize,
    pub creation_utc: Option<DateTime<Utc>>,
    pub expires_utc: Option<DateTime<Utc>>,
    pub last_access_utc: Option<DateTime<Utc>>,
    pub last_update_utc: Option<DateTime<Utc>>,
    pub is_secure: bool,
    pub is_httponly: bool,
    pub is_persistent: bool,
    pub samesite: String,
    pub source_scheme: String,
    pub source_port: i64,
    pub has_cross_site_ancestor: bool,
}

fn decode_samesite(val: i64) -> &'static str {
    match val {
        0 => "NO_RESTRICTION",
        1 => "LAX",
        2 => "STRICT",
        -1 => "UNSPECIFIED",
        _ => "UNKNOWN",
    }
}

fn decode_source_scheme(val: i64) -> &'static str {
    match val {
        0 => "UNSET",
        1 => "NON_SECURE",
        2 => "SECURE",
        _ => "UNKNOWN",
    }
}

pub fn parse_cookies(
    profile_dir: &Path,
    crypto: &CryptoOptions,
    warnings: &mut Vec<DiagnosticWarning>,
) -> Vec<CookieRecord> {
    let mut out = Vec::new();
    let candidates = [
        profile_dir.join("Network").join("Cookies"),
        profile_dir.join("Cookies"),
    ];
    let Some(db_path) = candidates.into_iter().find(|p| p.is_file()) else {
        return out;
    };

    let db = match ForensicSqlite::open_snapshot(&db_path) {
        Ok(d) => d,
        Err(e) => {
            warnings.push(DiagnosticWarning::warn(
                "cookies",
                &db_path,
                format!("Failed to open Cookies DB: {e}"),
            ));
            return out;
        }
    };

    let tables = db.list_tables();
    if !tables.contains("cookies") {
        return out;
    }
    let db_version = db
        .meta_value("version")
        .and_then(|s| s.parse::<i64>().ok());
    let cols = db.table_columns("cookies");
    let col = |name: &str, default_expr: &str| -> String {
        if cols.contains(name) {
            name.to_string()
        } else {
            default_expr.to_string()
        }
    };

    let sql = format!(
        "SELECT creation_utc, host_key, {}, name, value, encrypted_value, path, expires_utc, \
         is_secure, is_httponly, last_access_utc, {}, samesite, {}, {}, {}, {} \
         FROM cookies ORDER BY last_access_utc DESC",
        col("top_frame_site_key", "''"),
        col("is_persistent", "1"),
        col("source_scheme", "0"),
        col("source_port", "-1"),
        col("last_update_utc", "0"),
        col("has_cross_site_ancestor", "0"),
    );

    if let Ok(mut stmt) = db.conn.prepare(&sql)
        && let Ok(rows) = stmt.query_map([], |row| {
            Ok((
                row.get::<_, i64>(0).unwrap_or(0),
                row.get::<_, String>(1).unwrap_or_default(),
                row.get::<_, String>(2).unwrap_or_default(),
                row.get::<_, String>(3).unwrap_or_default(),
                row.get::<_, String>(4).unwrap_or_default(),
                row.get::<_, Vec<u8>>(5).unwrap_or_default(),
                row.get::<_, String>(6).unwrap_or_default(),
                row.get::<_, i64>(7).unwrap_or(0),
                row.get::<_, i64>(8).unwrap_or(0) != 0,
                row.get::<_, i64>(9).unwrap_or(0) != 0,
                row.get::<_, i64>(10).unwrap_or(0),
                row.get::<_, i64>(11).unwrap_or(1) != 0,
                row.get::<_, i64>(12).unwrap_or(-1),
                row.get::<_, i64>(13).unwrap_or(0),
                row.get::<_, i64>(14).unwrap_or(-1),
                row.get::<_, i64>(15).unwrap_or(0),
                row.get::<_, i64>(16).unwrap_or(0) != 0,
            ))
        })
    {
        for r in rows.flatten() {
            let (scheme, decrypted) = try_decrypt_chrome_blob(
                &r.5,
                &r.4,
                Some(&r.1),
                db_version,
                crypto,
            );
            out.push(CookieRecord {
                host_key: r.1,
                top_frame_site_key: r.2,
                name: r.3,
                path: r.6,
                value: decrypted,
                encryption_scheme: scheme,
                encrypted_len: r.5.len(),
                creation_utc: chrome_us_to_datetime(r.0),
                expires_utc: chrome_us_to_datetime(r.7),
                last_access_utc: chrome_us_to_datetime(r.10),
                last_update_utc: chrome_us_to_datetime(r.15),
                is_secure: r.8,
                is_httponly: r.9,
                is_persistent: r.11,
                samesite: decode_samesite(r.12).to_string(),
                source_scheme: decode_source_scheme(r.13).to_string(),
                source_port: r.14,
                has_cross_site_ancestor: r.16,
            });
        }
    }

    out
}
