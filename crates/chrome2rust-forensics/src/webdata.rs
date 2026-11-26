use chrome2rust_core::error::DiagnosticWarning;
use chrome2rust_core::sqlite_util::ForensicSqlite;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct WebDataAnalysis {
    pub autofill: Vec<AutofillRecord>,
    pub addresses: Vec<AutofillAddressRecord>,
    pub credit_cards: Vec<CreditCardMetaRecord>,
    pub search_engines: Vec<KeywordEngineRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutofillRecord {
    pub name: String,
    pub value: String,
    pub count: i64,
    pub date_created: Option<DateTime<Utc>>,
    pub date_last_used: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutofillAddressRecord {
    pub guid: String,
    pub full_name: String,
    pub company_name: String,
    pub street_address: String,
    pub city: String,
    pub state: String,
    pub zipcode: String,
    pub country_code: String,
    pub email: String,
    pub phone: String,
    pub use_count: i64,
    pub use_date: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreditCardMetaRecord {
    pub source_db: String,
    pub guid: String,
    pub name_on_card: String,
    pub expiration_month: i64,
    pub expiration_year: i64,
    pub last_four: String,
    pub network: String,
    pub nickname: String,
    pub use_count: i64,
    pub use_date: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeywordEngineRecord {
    pub short_name: String,
    pub keyword: String,
    pub url: String,
    pub usage_count: i64,
    pub date_created: Option<DateTime<Utc>>,
    pub last_visited: Option<DateTime<Utc>>,
}

fn webdata_ts(val: i64) -> Option<DateTime<Utc>> {
    if val <= 0 {
        return None;
    }
    if val > 10_000_000_000_000 {
        chrome2rust_core::time::chrome_us_to_datetime(val)
    } else if val > 100_000_000 {
        DateTime::from_timestamp(val, 0)
    } else {
        None
    }
}

/// Extracts ONLY non-credential form autofill entries (`autofill` table) from Chrome
/// `Web Data` / `Account Web Data`. Strictly NEVER queries `credit_cards`, `masked_credit_cards`,
/// `local_ibans`, `masked_ibans`, `server_card_metadata`, `cvc_storage`, or `Login Data` (R4 safeguard).
pub fn parse_autofill_only(profile_dir: &Path, warnings: &mut Vec<DiagnosticWarning>) -> Vec<AutofillRecord> {
    let mut out = Vec::new();

    for db_name in ["Web Data", "Account Web Data"] {
        let db_path = profile_dir.join(db_name);
        if !db_path.is_file() {
            continue;
        }
        let db = match ForensicSqlite::open_snapshot(&db_path) {
            Ok(d) => d,
            Err(e) => {
                warnings.push(DiagnosticWarning::warn(
                    "web_data_autofill",
                    &db_path,
                    format!("Failed to open {db_name}: {e}"),
                ));
                continue;
            }
        };
        let tables = db.list_tables();
        if tables.contains("autofill")
            && let Ok(mut stmt) = db.conn.prepare(
                "SELECT name, value, count, date_created, date_last_used FROM autofill ORDER BY date_last_used DESC",
            )
            && let Ok(rows) = stmt.query_map([], |r| {
                Ok(AutofillRecord {
                    name: r.get(0).unwrap_or_default(),
                    value: r.get(1).unwrap_or_default(),
                    count: r.get(2).unwrap_or(0),
                    date_created: webdata_ts(r.get::<_, i64>(3).unwrap_or(0)),
                    date_last_used: webdata_ts(r.get::<_, i64>(4).unwrap_or(0)),
                })
            })
        {
            out.extend(rows.flatten());
        }
    }

    out
}

pub fn parse_web_data(profile_dir: &Path, warnings: &mut Vec<DiagnosticWarning>) -> WebDataAnalysis {
    let mut out = WebDataAnalysis {
        autofill: parse_autofill_only(profile_dir, warnings),
        ..Default::default()
    };

    for db_name in ["Web Data", "Account Web Data"] {
        let db_path = profile_dir.join(db_name);
        if !db_path.is_file() {
            continue;
        }
        let db = match ForensicSqlite::open_snapshot(&db_path) {
            Ok(d) => d,
            Err(e) => {
                warnings.push(DiagnosticWarning::warn(
                    "web_data",
                    &db_path,
                    format!("Failed to open {db_name}: {e}"),
                ));
                continue;
            }
        };
        let tables = db.list_tables();

        // Legacy autofill_profiles + autofill_profile_names/emails/phones OR modern local_addresses/contact_info
        if tables.contains("autofill_profiles") {
            let mut names: HashMap<String, String> = HashMap::new();
            let mut emails: HashMap<String, String> = HashMap::new();
            let mut phones: HashMap<String, String> = HashMap::new();

            if tables.contains("autofill_profile_names")
                && let Ok(mut s) = db.conn.prepare("SELECT guid, full_name FROM autofill_profile_names")
                && let Ok(rows) = s.query_map([], |r| {
                    Ok((r.get::<_, String>(0)?, r.get::<_, String>(1).unwrap_or_default()))
                })
            {
                for (g, v) in rows.flatten() {
                    if !v.is_empty() {
                        names.insert(g, v);
                    }
                }
            }
            if tables.contains("autofill_profile_emails")
                && let Ok(mut s) = db.conn.prepare("SELECT guid, email FROM autofill_profile_emails")
                && let Ok(rows) = s.query_map([], |r| {
                    Ok((r.get::<_, String>(0)?, r.get::<_, String>(1).unwrap_or_default()))
                })
            {
                for (g, v) in rows.flatten() {
                    if !v.is_empty() {
                        emails.insert(g, v);
                    }
                }
            }
            if tables.contains("autofill_profile_phones")
                && let Ok(mut s) = db.conn.prepare("SELECT guid, number FROM autofill_profile_phones")
                && let Ok(rows) = s.query_map([], |r| {
                    Ok((r.get::<_, String>(0)?, r.get::<_, String>(1).unwrap_or_default()))
                })
            {
                for (g, v) in rows.flatten() {
                    if !v.is_empty() {
                        phones.insert(g, v);
                    }
                }
            }

            let cols = db.table_columns("autofill_profiles");
            let c = |n: &'static str| if cols.contains(n) { n } else { "''" };
            let sql = format!(
                "SELECT guid, {}, {}, {}, {}, {}, {}, use_count, use_date FROM autofill_profiles",
                c("company_name"),
                c("street_address"),
                c("city"),
                c("state"),
                c("zipcode"),
                c("country_code"),
            );
            if let Ok(mut stmt) = db.conn.prepare(&sql)
                && let Ok(rows) = stmt.query_map([], |r| {
                    let guid: String = r.get(0).unwrap_or_default();
                    Ok(AutofillAddressRecord {
                        full_name: names.get(&guid).cloned().unwrap_or_default(),
                        email: emails.get(&guid).cloned().unwrap_or_default(),
                        phone: phones.get(&guid).cloned().unwrap_or_default(),
                        guid,
                        company_name: r.get(1).unwrap_or_default(),
                        street_address: r.get(2).unwrap_or_default(),
                        city: r.get(3).unwrap_or_default(),
                        state: r.get(4).unwrap_or_default(),
                        zipcode: r.get(5).unwrap_or_default(),
                        country_code: r.get(6).unwrap_or_default(),
                        use_count: r.get(7).unwrap_or(0),
                        use_date: webdata_ts(r.get::<_, i64>(8).unwrap_or(0)),
                    })
                })
            {
                out.addresses.extend(rows.flatten());
            }
        }

        // Modern Chrome contact_info / local_addresses via type_tokens tables
        for addr_tbl in ["local_addresses", "contact_info"] {
            let token_tbl = format!("{addr_tbl}_type_tokens");
            if tables.contains(addr_tbl) && tables.contains(&token_tbl) {
                let mut tokens_by_guid: HashMap<String, HashMap<i64, String>> = HashMap::new();
                let tsql = format!("SELECT guid, type, value FROM {token_tbl}");
                if let Ok(mut stmt) = db.conn.prepare(&tsql)
                    && let Ok(rows) = stmt.query_map([], |r| {
                        Ok((
                            r.get::<_, String>(0)?,
                            r.get::<_, i64>(1)?,
                            r.get::<_, String>(2).unwrap_or_default(),
                        ))
                    })
                {
                    for (g, t, v) in rows.flatten() {
                        if !v.is_empty() {
                            tokens_by_guid.entry(g).or_default().insert(t, v);
                        }
                    }
                }

                let asql = format!("SELECT guid, use_count, use_date FROM {addr_tbl}");
                if let Ok(mut stmt) = db.conn.prepare(&asql)
                    && let Ok(rows) = stmt.query_map([], |r| {
                        Ok((
                            r.get::<_, String>(0)?,
                            r.get::<_, i64>(1).unwrap_or(0),
                            r.get::<_, i64>(2).unwrap_or(0),
                        ))
                    })
                {
                    for (guid, uc, ud) in rows.flatten() {
                        let map = tokens_by_guid.remove(&guid).unwrap_or_default();
                        out.addresses.push(AutofillAddressRecord {
                            guid,
                            full_name: map.get(&7).cloned().unwrap_or_default(),
                            email: map.get(&9).cloned().unwrap_or_default(),
                            phone: map.get(&14).cloned().unwrap_or_default(),
                            street_address: map.get(&77).or_else(|| map.get(&30)).cloned().unwrap_or_default(),
                            city: map.get(&33).cloned().unwrap_or_default(),
                            state: map.get(&34).cloned().unwrap_or_default(),
                            zipcode: map.get(&35).cloned().unwrap_or_default(),
                            country_code: map.get(&36).cloned().unwrap_or_default(),
                            company_name: map.get(&60).cloned().unwrap_or_default(),
                            use_count: uc,
                            use_date: webdata_ts(ud),
                        });
                    }
                }
            }
        }

        if tables.contains("credit_cards")
            && let Ok(mut stmt) = db.conn.prepare(
                "SELECT guid, name_on_card, expiration_month, expiration_year, use_count, use_date, nickname FROM credit_cards",
            )
            && let Ok(rows) = stmt.query_map([], |r| {
                Ok(CreditCardMetaRecord {
                    source_db: db_name.to_string(),
                    guid: r.get(0).unwrap_or_default(),
                    name_on_card: r.get(1).unwrap_or_default(),
                    expiration_month: r.get(2).unwrap_or(0),
                    expiration_year: r.get(3).unwrap_or(0),
                    last_four: String::new(),
                    network: String::new(),
                    nickname: r.get(6).unwrap_or_default(),
                    use_count: r.get(4).unwrap_or(0),
                    use_date: webdata_ts(r.get::<_, i64>(5).unwrap_or(0)),
                })
            })
        {
            out.credit_cards.extend(rows.flatten());
        }

        if tables.contains("masked_credit_cards")
            && let Ok(mut stmt) = db.conn.prepare(
                "SELECT id, name_on_card, network, last_four, exp_month, exp_year, nickname FROM masked_credit_cards",
            )
            && let Ok(rows) = stmt.query_map([], |r| {
                Ok(CreditCardMetaRecord {
                    source_db: db_name.to_string(),
                    guid: r.get(0).unwrap_or_default(),
                    name_on_card: r.get(1).unwrap_or_default(),
                    network: r.get(2).unwrap_or_default(),
                    last_four: r.get(3).unwrap_or_default(),
                    expiration_month: r.get(4).unwrap_or(0),
                    expiration_year: r.get(5).unwrap_or(0),
                    nickname: r.get(6).unwrap_or_default(),
                    use_count: 0,
                    use_date: None,
                })
            })
        {
            out.credit_cards.extend(rows.flatten());
        }

        if tables.contains("keywords")
            && let Ok(mut stmt) = db.conn.prepare(
                "SELECT short_name, keyword, url, usage_count, date_created, last_visited FROM keywords ORDER BY usage_count DESC",
            )
            && let Ok(rows) = stmt.query_map([], |r| {
                Ok(KeywordEngineRecord {
                    short_name: r.get(0).unwrap_or_default(),
                    keyword: r.get(1).unwrap_or_default(),
                    url: r.get(2).unwrap_or_default(),
                    usage_count: r.get(3).unwrap_or(0),
                    date_created: webdata_ts(r.get::<_, i64>(4).unwrap_or(0)),
                    last_visited: webdata_ts(r.get::<_, i64>(5).unwrap_or(0)),
                })
            })
        {
            out.search_engines.extend(rows.flatten());
        }
    }

    out
}
