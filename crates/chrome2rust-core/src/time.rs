use chrono::{DateTime, Duration, Local, NaiveDateTime, TimeZone, Utc};

/// Microseconds between Windows FILETIME/Chrome epoch (1601-01-01T00:00:00Z)
/// and Unix epoch (1970-01-01T00:00:00Z).
pub const CHROME_EPOCH_OFFSET_US: i64 = 11_644_473_600_000_000;
pub const CHROME_EPOCH_OFFSET_SECS: i64 = 11_644_473_600;

/// Seconds between Unix epoch (1970-01-01T00:00:00Z) and Apple Cocoa/CoreFoundation epoch (2001-01-01T00:00:00Z).
pub const CF_ABSOLUTE_EPOCH_OFFSET_SECS: f64 = 978_307_200.0;

/// Converts Mozilla PRTime (microseconds since 1970-01-01 UTC) into `DateTime<Utc>`.
pub fn prtime_us_to_datetime(us: i64) -> Option<DateTime<Utc>> {
    if !(31_536_000_000_000..=7_258_118_400_000_000).contains(&us) {
        return None;
    }
    DateTime::from_timestamp_micros(us)
}

/// Converts Unix seconds since 1970-01-01 UTC into `DateTime<Utc>`, rejecting sentinel/invalid dates.
pub fn unix_secs_to_datetime(secs: i64) -> Option<DateTime<Utc>> {
    if !(31_536_000..=7_258_118_400).contains(&secs) {
        return None;
    }
    DateTime::from_timestamp(secs, 0)
}

/// Converts Unix milliseconds since 1970-01-01 UTC into `DateTime<Utc>`, rejecting sentinel/invalid dates.
pub fn unix_ms_to_datetime(ms: i64) -> Option<DateTime<Utc>> {
    if !(31_536_000_000..=7_258_118_400_000).contains(&ms) {
        return None;
    }
    DateTime::from_timestamp_millis(ms)
}

/// Converts Apple CFAbsoluteTime / Cocoa Core Data seconds since 2001-01-01 UTC into `DateTime<Utc>`.
/// Also normalizes nanosecond-scaled values (`> 1e13`) occasionally seen in Safari `History.db`.
pub fn cf_absolute_time_to_datetime(val: f64) -> Option<DateTime<Utc>> {
    if !val.is_finite() || val == 0.0 {
        return None;
    }
    let secs = if val.abs() > 1e13 { val / 1e9 } else { val };
    let unix = secs + CF_ABSOLUTE_EPOCH_OFFSET_SECS;
    if !(31_536_000.0..=7_258_118_400.0).contains(&unix) {
        return None;
    }
    let whole = unix.trunc() as i64;
    let nanos = ((unix.fract().abs()) * 1_000_000_000.0).round() as u32;
    DateTime::from_timestamp(whole, nanos.min(999_999_999))
}

/// Converts Chrome/WebKit microsecond timestamp (microseconds since 1601-01-01 UTC)
/// into `DateTime<Utc>`. Returns `None` for zero, negative, or out-of-range sentinel values
/// (e.g., 1601-01-01 or 9999-12-31 placeholders).
pub fn chrome_us_to_datetime(us: i64) -> Option<DateTime<Utc>> {
    if us <= 0 {
        return None;
    }
    let unix_us = us.checked_sub(CHROME_EPOCH_OFFSET_US)?;
    // Reject dates earlier than 1971-01-01 or later than 2200-01-01 as invalid/sentinel
    if !(31_536_000_000_000..=7_258_118_400_000_000).contains(&unix_us) {
        return None;
    }
    DateTime::from_timestamp_micros(unix_us)
}

/// Converts a Chrome timestamp stored as a string (such as in Bookmarks `date_added`
/// or Preferences timestamps) into `DateTime<Utc>`.
pub fn chrome_str_us_to_datetime(s: &str) -> Option<DateTime<Utc>> {
    let trimmed = s.trim();
    if trimmed.is_empty() || trimmed == "0" {
        return None;
    }
    let val = trimmed.parse::<i64>().ok()?;
    if let Some(dt) = chrome_us_to_datetime(val) {
        return Some(dt);
    }
    // Fallback: sometimes stored as Unix microseconds or Unix milliseconds or Unix seconds
    if val > 1_000_000_000_000_000 {
        DateTime::from_timestamp_micros(val)
    } else if val > 1_000_000_000_000 {
        DateTime::from_timestamp_millis(val)
    } else if val > 100_000_000 {
        DateTime::from_timestamp(val, 0)
    } else {
        None
    }
}

/// Converts Unix timestamp in seconds (floating point, e.g. Local State `active_time`)
/// to `DateTime<Utc>`.
pub fn unix_f64_to_datetime(secs: f64) -> Option<DateTime<Utc>> {
    if !secs.is_finite() || secs <= 0.0 {
        return None;
    }
    if secs > 1e15 {
        // Actually Chrome microseconds
        return chrome_us_to_datetime(secs as i64);
    }
    let whole = secs.trunc() as i64;
    let nanos = ((secs.fract()) * 1_000_000_000.0).round() as u32;
    DateTime::from_timestamp(whole, nanos.min(999_999_999))
}

/// Converts Windows FILETIME (100-nanosecond intervals since 1601-01-01 UTC)
/// to `DateTime<Utc>`.
pub fn filetime_to_datetime(ft: u64) -> Option<DateTime<Utc>> {
    if ft == 0 {
        return None;
    }
    let us = (ft / 10) as i64;
    chrome_us_to_datetime(us)
}

/// Parses an HTTP header date (RFC 2822 / RFC 1123 / RFC 850 / ANSI C asctime).
pub fn parse_http_date(raw: &str) -> Option<DateTime<Utc>> {
    let s = raw.trim();
    if s.is_empty() {
        return None;
    }
    if let Ok(dt) = DateTime::parse_from_rfc2822(s) {
        return Some(dt.with_timezone(&Utc));
    }
    if let Ok(dt) = DateTime::parse_from_rfc3339(s) {
        return Some(dt.with_timezone(&Utc));
    }
    for fmt in [
        "%a, %d %b %Y %H:%M:%S GMT",
        "%a, %d %b %Y %H:%M:%S UTC",
        "%a, %d-%b-%Y %H:%M:%S GMT",
        "%A, %d-%b-%y %H:%M:%S GMT",
        "%a %b %e %H:%M:%S %Y",
    ] {
        if let Ok(naive) = NaiveDateTime::parse_from_str(s, fmt) {
            return Some(Utc.from_utc_datetime(&naive));
        }
    }
    None
}

/// Parses user-supplied date/time filter inputs (ISO-8601, `YYYY-MM-DD HH:MM:SS`, `YYYY-MM-DD`).
pub fn parse_user_datetime(input: &str) -> Result<DateTime<Utc>, String> {
    let s = input.trim();
    if let Ok(dt) = DateTime::parse_from_rfc3339(s) {
        return Ok(dt.with_timezone(&Utc));
    }
    for fmt in ["%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M"] {
        if let Ok(naive) = NaiveDateTime::parse_from_str(s, fmt) {
            if let Some(local_dt) = Local.from_local_datetime(&naive).earliest() {
                return Ok(local_dt.with_timezone(&Utc));
            }
            return Ok(Utc.from_utc_datetime(&naive));
        }
    }
    if let Ok(d) = chrono::NaiveDate::parse_from_str(s, "%Y-%m-%d") {
        let naive = d.and_hms_opt(0, 0, 0).ok_or("invalid date")?;
        return Ok(Utc.from_utc_datetime(&naive));
    }
    Err(format!(
        "Invalid date/time '{s}'. Expected RFC3339 (2026-11-14T12:00:00Z) or YYYY-MM-DD[ HH:MM:SS]"
    ))
}

/// Parses relative durations like "30s", "15m", "24h", "7d", "2w".
pub fn parse_relative_duration(spec: &str) -> Result<Duration, String> {
    let s = spec.trim().to_ascii_lowercase();
    if s.is_empty() {
        return Err("Empty duration specification".into());
    }
    let split_idx = s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len());
    let (num_str, unit) = s.split_at(split_idx);
    let val: i64 = num_str
        .parse()
        .map_err(|_| format!("Invalid duration number in '{spec}'"))?;
    let err_overflow = || format!("Duration value out of range in '{spec}'");
    match unit {
        "s" | "sec" | "secs" | "second" | "seconds" => Duration::try_seconds(val).ok_or_else(err_overflow),
        "m" | "min" | "mins" | "minute" | "minutes" => Duration::try_minutes(val).ok_or_else(err_overflow),
        "h" | "hr" | "hrs" | "hour" | "hours" => Duration::try_hours(val).ok_or_else(err_overflow),
        "d" | "day" | "days" | "" => Duration::try_days(val).ok_or_else(err_overflow),
        "w" | "wk" | "wks" | "week" | "weeks" => Duration::try_weeks(val).ok_or_else(err_overflow),
        _ => Err(format!(
            "Unsupported duration unit '{unit}' in '{spec}' (use s, m, h, d, w)"
        )),
    }
}

pub fn format_utc_opt(dt: Option<DateTime<Utc>>, with_millis: bool) -> String {
    match dt {
        Some(t) => {
            if with_millis {
                t.format("%Y-%m-%d %H:%M:%S%.3f UTC").to_string()
            } else {
                t.format("%Y-%m-%d %H:%M:%S UTC").to_string()
            }
        }
        None => String::new(),
    }
}

pub fn format_local_opt(dt: Option<DateTime<Utc>>, with_millis: bool) -> String {
    match dt {
        Some(t) => {
            let local: DateTime<Local> = t.with_timezone(&Local);
            if with_millis {
                local.format("%Y-%m-%d %H:%M:%S%.3f").to_string()
            } else {
                local.format("%Y-%m-%d %H:%M:%S").to_string()
            }
        }
        None => String::new(),
    }
}

pub fn system_time_to_utc(st: std::time::SystemTime) -> Option<DateTime<Utc>> {
    let dt: DateTime<Utc> = st.into();
    Some(dt)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Datelike;

    #[test]
    fn test_chrome_timestamp_conversion() {
        // From real Chromium 156 sample: 13439176738739516 -> 2026-11-15T00:38:58.739516Z
        let dt = chrome_us_to_datetime(13_439_176_738_739_516).expect("valid timestamp");
        assert_eq!(dt.year(), 2026);
        assert_eq!(dt.month(), 11);
        assert_eq!(dt.day(), 15);
    }

    #[test]
    fn test_zero_timestamp_is_none() {
        assert!(chrome_us_to_datetime(0).is_none());
        assert!(chrome_us_to_datetime(-1).is_none());
    }

    #[test]
    fn test_http_date_parsing() {
        let dt = parse_http_date("Sun, 15 Nov 2026 00:38:58 GMT").expect("valid http date");
        assert_eq!(dt.year(), 2026);
        assert_eq!(dt.month(), 11);
    }

    #[test]
    fn test_relative_duration() {
        assert_eq!(parse_relative_duration("30m").unwrap(), Duration::minutes(30));
        assert_eq!(parse_relative_duration("24h").unwrap(), Duration::hours(24));
        assert_eq!(parse_relative_duration("7d").unwrap(), Duration::days(7));
        assert!(parse_relative_duration("99999999999999d").is_err());
        assert!(parse_relative_duration("9223372036854775807s").is_err());
    }

    #[test]
    fn test_firefox_and_safari_epochs() {
        // 2026-11-15T00:00:00Z = 1_794_700_800 Unix secs
        let pr = prtime_us_to_datetime(1_794_700_800_000_000).expect("valid prtime");
        assert_eq!(pr.year(), 2026);
        assert_eq!(pr.month(), 11);
        assert_eq!(pr.day(), 15);
        assert!(prtime_us_to_datetime(0).is_none());

        let us = unix_secs_to_datetime(1_794_700_800).expect("valid unix secs");
        assert_eq!(us.year(), 2026);
        let um = unix_ms_to_datetime(1_794_700_800_123).expect("valid unix ms");
        assert_eq!(um.year(), 2026);

        let cf_secs = 1_794_700_800.0 - CF_ABSOLUTE_EPOCH_OFFSET_SECS;
        let cf = cf_absolute_time_to_datetime(cf_secs).expect("valid cf_absolute_time");
        assert_eq!(cf.year(), 2026);
        assert_eq!(cf.month(), 11);
        assert_eq!(cf.day(), 15);
        assert!(cf_absolute_time_to_datetime(0.0).is_none());
        assert!(cf_absolute_time_to_datetime(f64::NAN).is_none());
    }
}
