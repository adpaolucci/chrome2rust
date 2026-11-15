use chrome2rust_core::crypto::{CryptoOptions, EncryptionScheme, try_decrypt_chrome_blob};
use chrome2rust_core::error::DiagnosticWarning;
use chrome2rust_core::sqlite_util::ForensicSqlite;
use chrome2rust_core::time::chrome_us_to_datetime;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginRecord {
    pub source_db: String,
    pub id: i64,
    pub origin_url: String,
    pub action_url: String,
    pub username_element: String,
    pub username_value: String,
    pub signon_realm: String,
    pub encryption_scheme: EncryptionScheme,
    pub password_encrypted_len: usize,
    pub password_decrypted: Option<String>,
    pub date_created: Option<DateTime<Utc>>,
    pub date_last_used: Option<DateTime<Utc>>,
    pub date_password_modified: Option<DateTime<Utc>>,
    pub times_used: i64,
    pub blacklisted_by_user: bool,
    pub insecure_issues: Vec<String>,
}

fn decode_insecurity_type(t: i64) -> &'static str {
    match t {
        0 => "LEAKED",
        1 => "PHISHED",
        2 => "WEAK",
        3 => "REUSED",
        _ => "UNKNOWN",
    }
}

pub fn parse_logins(
    profile_dir: &Path,
    crypto: &CryptoOptions,
    warnings: &mut Vec<DiagnosticWarning>,
) -> Vec<LoginRecord> {
    let mut out = Vec::new();
    for db_name in ["Login Data", "Login Data For Account"] {
        let db_path = profile_dir.join(db_name);
        if !db_path.is_file() {
            continue;
        }
        let db = match ForensicSqlite::open_snapshot(&db_path) {
            Ok(d) => d,
            Err(e) => {
                warnings.push(DiagnosticWarning::warn(
                    "logins",
                    &db_path,
                    format!("Failed to open {db_name}: {e}"),
                ));
                continue;
            }
        };
        let tables = db.list_tables();
        if !tables.contains("logins") {
            continue;
        }

        let mut issues_map: HashMap<i64, Vec<String>> = HashMap::new();
        if tables.contains("insecure_credentials")
            && let Ok(mut stmt) = db
                .conn
                .prepare("SELECT parent_id, insecurity_type, is_muted FROM insecure_credentials")
            && let Ok(rows) = stmt.query_map([], |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, i64>(1)?,
                    r.get::<_, i64>(2).unwrap_or(0) != 0,
                ))
            })
        {
            for (pid, itype, muted) in rows.flatten() {
                let label = if muted {
                    format!("{} (muted)", decode_insecurity_type(itype))
                } else {
                    decode_insecurity_type(itype).to_string()
                };
                issues_map.entry(pid).or_default().push(label);
            }
        }

        let cols = db.table_columns("logins");
        let col = |name: &str, default_expr: &str| -> String {
            if cols.contains(name) {
                name.to_string()
            } else {
                default_expr.to_string()
            }
        };

        let sql = format!(
            "SELECT {}, origin_url, action_url, username_element, username_value, password_value, \
             signon_realm, date_created, {}, {}, times_used, blacklisted_by_user FROM logins",
            col("id", "rowid"),
            col("date_last_used", "0"),
            col("date_password_modified", "0"),
        );

        if let Ok(mut stmt) = db.conn.prepare(&sql)
            && let Ok(rows) = stmt.query_map([], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1).unwrap_or_default(),
                    row.get::<_, String>(2).unwrap_or_default(),
                    row.get::<_, String>(3).unwrap_or_default(),
                    row.get::<_, String>(4).unwrap_or_default(),
                    row.get::<_, Vec<u8>>(5).unwrap_or_default(),
                    row.get::<_, String>(6).unwrap_or_default(),
                    row.get::<_, i64>(7).unwrap_or(0),
                    row.get::<_, i64>(8).unwrap_or(0),
                    row.get::<_, i64>(9).unwrap_or(0),
                    row.get::<_, i64>(10).unwrap_or(0),
                    row.get::<_, i64>(11).unwrap_or(0) != 0,
                ))
            })
        {
            for r in rows.flatten() {
                let (scheme, decrypted) = try_decrypt_chrome_blob(&r.5, "", None, None, crypto);
                let insecure_issues = issues_map.remove(&r.0).unwrap_or_default();
                out.push(LoginRecord {
                    source_db: db_name.to_string(),
                    id: r.0,
                    origin_url: r.1,
                    action_url: r.2,
                    username_element: r.3,
                    username_value: r.4,
                    signon_realm: r.6,
                    encryption_scheme: scheme,
                    password_encrypted_len: r.5.len(),
                    password_decrypted: decrypted,
                    date_created: chrome_us_to_datetime(r.7),
                    date_last_used: chrome_us_to_datetime(r.8),
                    date_password_modified: chrome_us_to_datetime(r.9),
                    times_used: r.10,
                    blacklisted_by_user: r.11,
                    insecure_issues,
                });
            }
        }
    }

    out
}
