use chrome2rust_core::time::{chrome_us_to_datetime, parse_http_date};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use x509_parser::prelude::*;

// Flags from Chromium net/http/http_response_info.cc
const RESPONSE_INFO_VERSION_MASK: u32 = 0xFF;
const RESPONSE_INFO_HAS_CERT: u32 = 1 << 8;
const RESPONSE_INFO_HAS_SECURITY_BITS: u32 = 1 << 9;
const RESPONSE_INFO_HAS_CERT_STATUS: u32 = 1 << 10;
const RESPONSE_INFO_HAS_VARY_DATA: u32 = 1 << 11;
#[allow(dead_code)]
const RESPONSE_INFO_TRUNCATED: u32 = 1 << 12;
#[allow(dead_code)]
const RESPONSE_INFO_WAS_SPDY: u32 = 1 << 13;
#[allow(dead_code)]
const RESPONSE_INFO_WAS_ALPN: u32 = 1 << 14;
#[allow(dead_code)]
const RESPONSE_INFO_WAS_PROXY: u32 = 1 << 15;
const RESPONSE_INFO_HAS_SSL_CONNECTION_STATUS: u32 = 1 << 16;
const RESPONSE_INFO_HAS_ALPN_NEGOTIATED_PROTOCOL: u32 = 1 << 17;
const RESPONSE_INFO_HAS_CONNECTION_INFO: u32 = 1 << 18;
#[allow(dead_code)]
const RESPONSE_INFO_USE_HTTP_AUTHENTICATION: u32 = 1 << 19;
const RESPONSE_INFO_HAS_SIGNED_CERTIFICATE_TIMESTAMPS: u32 = 1 << 20;
#[allow(dead_code)]
const RESPONSE_INFO_UNUSED_SINCE_PREFETCH: u32 = 1 << 21;
const RESPONSE_INFO_HAS_KEY_EXCHANGE_GROUP: u32 = 1 << 22;
#[allow(dead_code)]
const RESPONSE_INFO_PKP_BYPASSED: u32 = 1 << 23;
const RESPONSE_INFO_HAS_STALENESS: u32 = 1 << 24;
const RESPONSE_INFO_HAS_PEER_SIGNATURE_ALGORITHM: u32 = 1 << 25;
#[allow(dead_code)]
const RESPONSE_INFO_RESTRICTED_PREFETCH: u32 = 1 << 26;
const RESPONSE_INFO_HAS_DNS_ALIASES: u32 = 1 << 27;
#[allow(dead_code)]
const RESPONSE_INFO_SINGLE_KEYED_CACHE_ENTRY_UNUSABLE: u32 = 1 << 28;
#[allow(dead_code)]
const RESPONSE_INFO_ENCRYPTED_CLIENT_HELLO: u32 = 1 << 29;
const RESPONSE_INFO_BROWSER_RUN_ID: u32 = 1 << 30;
const RESPONSE_INFO_HAS_EXTRA_FLAGS: u32 = 1 << 31;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParsedHeader {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParsedCertSummary {
    pub subject: String,
    pub issuer: String,
    pub not_before: Option<String>,
    pub not_after: Option<String>,
    pub der_len: usize,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HttpResponseMetadata {
    pub status_line: String,
    pub status_code: Option<u16>,
    pub headers: Vec<ParsedHeader>,
    pub content_type: Option<String>,
    pub raw_content_type: Option<String>,
    pub content_encoding: Option<String>,
    pub content_disposition_filename: Option<String>,
    pub server_name: Option<String>,
    pub server_time: Option<DateTime<Utc>>,
    pub last_modified: Option<DateTime<Utc>>,
    pub expiration_time: Option<DateTime<Utc>>,
    pub request_time: Option<DateTime<Utc>>,
    pub response_time: Option<DateTime<Utc>>,
    pub original_response_time: Option<DateTime<Utc>>,
    pub server_ip: Option<String>,
    pub server_port: Option<u16>,
    pub alpn_protocol: Option<String>,
    pub tls_version: Option<String>,
    pub dns_aliases: Vec<String>,
    pub certificates: Vec<ParsedCertSummary>,
    pub flags: u32,
    pub extra_flags: Option<u32>,
}

struct PickleReader<'a> {
    buf: &'a [u8],
    off: usize,
}

impl<'a> PickleReader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, off: 0 }
    }

    fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.off)
    }

    fn read_u32(&mut self) -> Option<u32> {
        if self.remaining() < 4 {
            return None;
        }
        let val = u32::from_le_bytes(self.buf[self.off..self.off + 4].try_into().ok()?);
        self.off += 4;
        Some(val)
    }

    fn read_i64(&mut self) -> Option<i64> {
        if self.remaining() < 8 {
            return None;
        }
        let val = i64::from_le_bytes(self.buf[self.off..self.off + 8].try_into().ok()?);
        self.off += 8;
        Some(val)
    }

    fn read_bytes_aligned(&mut self) -> Option<&'a [u8]> {
        let len = self.read_u32()? as usize;
        if len > 16 * 1024 * 1024 {
            return None;
        }
        let aligned = len.div_ceil(4).checked_mul(4)?;
        if self.remaining() < aligned {
            // If exact len fits at end without trailing padding
            if len <= self.remaining() {
                let slice = &self.buf[self.off..self.off + len];
                self.off += len;
                return Some(slice);
            }
            return None;
        }
        let slice = &self.buf[self.off..self.off + len];
        self.off += aligned;
        Some(slice)
    }

    fn read_string(&mut self) -> Option<String> {
        let bytes = self.read_bytes_aligned()?;
        Some(String::from_utf8_lossy(bytes).into_owned())
    }

    fn skip(&mut self, n: usize) -> bool {
        if self.remaining() < n {
            return false;
        }
        self.off += n;
        true
    }
}

/// Parses Chromium's `HttpResponseInfo` stream-0 pickle across Chrome 2.x through Chrome 156+.
/// Falls back cleanly to scanning raw HTTP headers if an unrecognized trailing flag is encountered.
pub fn parse_http_response_info(stream0: &[u8]) -> HttpResponseMetadata {
    let mut meta = HttpResponseMetadata::default();
    if stream0.len() < 12 {
        return meta;
    }

    let mut r = PickleReader::new(stream0);
    let Some(_pickle_payload_len) = r.read_u32() else {
        return meta;
    };
    let Some(flags) = r.read_u32() else {
        return meta;
    };
    meta.flags = flags;
    let _version = flags & RESPONSE_INFO_VERSION_MASK;

    // Chrome 132+ sets bit 31 (0x8000_0000) to store an extra_flags uint32 immediately after flags.
    if (flags & RESPONSE_INFO_HAS_EXTRA_FLAGS) != 0 {
        meta.extra_flags = r.read_u32();
    }

    if let Some(req_us) = r.read_i64() {
        meta.request_time = chrome_us_to_datetime(req_us);
    }
    if let Some(resp_us) = r.read_i64() {
        meta.response_time = chrome_us_to_datetime(resp_us);
    }

    // Modern Chrome (125+ / 132+) also writes `original_response_time` (64-bit Chrome timestamp)
    // right before the HTTP headers string length. Verify cleanly by checking whether `offset + 8`
    // holds a length prefix pointing at "HTTP/" (or whether `offset` itself holds "HTTP/").
    let looks_like_headers_at = |off: usize| -> bool {
        let Some(min_end) = off.checked_add(8) else {
            return false;
        };
        if min_end >= stream0.len() {
            return false;
        }
        let hlen = u32::from_le_bytes(stream0[off..off + 4].try_into().unwrap_or([0; 4])) as usize;
        let Some(end) = off.checked_add(4).and_then(|s| s.checked_add(hlen)) else {
            return false;
        };
        (8..=256 * 1024).contains(&hlen) && end <= stream0.len() && stream0[off + 4..].starts_with(b"HTTP/")
    };

    if !looks_like_headers_at(r.off)
        && r.off.checked_add(8).is_some_and(looks_like_headers_at)
        && let Some(orig_us) = r.read_i64()
    {
        meta.original_response_time = chrome_us_to_datetime(orig_us);
    }

    // Read raw HTTP headers (\0-separated lines terminated by \0\0)
    if let Some(header_bytes) = r.read_bytes_aligned() {
        parse_raw_http_headers(header_bytes, &mut meta);
    } else {
        // Fallback scan for HTTP/ header block anywhere in stream0
        if let Some(pos) = find_subslice(stream0, b"HTTP/") {
            parse_raw_http_headers(&stream0[pos..], &mut meta);
        }
        return meta;
    }

    // Now parse optional trailing metadata fields cleanly (stop gracefully on EOF/unexpected sizes)
    if (flags & RESPONSE_INFO_HAS_CERT) != 0
        && let Some(nb_certs) = r.read_u32()
    {
        for _ in 0..nb_certs.min(32) {
            let Some(der) = r.read_bytes_aligned() else {
                break;
            };
            if let Ok((_, cert)) = X509Certificate::from_der(der) {
                meta.certificates.push(ParsedCertSummary {
                    subject: cert.subject().to_string(),
                    issuer: cert.issuer().to_string(),
                    not_before: Some(cert.validity().not_before.to_string()),
                    not_after: Some(cert.validity().not_after.to_string()),
                    der_len: der.len(),
                });
            } else {
                meta.certificates.push(ParsedCertSummary {
                    subject: String::new(),
                    issuer: String::new(),
                    not_before: None,
                    not_after: None,
                    der_len: der.len(),
                });
            }
        }
    }

    if (flags & RESPONSE_INFO_HAS_CERT_STATUS) != 0 {
        let _ = r.read_u32();
    }
    if (flags & RESPONSE_INFO_HAS_SECURITY_BITS) != 0 {
        let _ = r.read_u32();
    }
    if (flags & RESPONSE_INFO_HAS_SSL_CONNECTION_STATUS) != 0
        && let Some(status) = r.read_u32()
    {
        let ver = (status >> 20) & 0x7;
        meta.tls_version = match ver {
            1 => Some("SSL 3.0".into()),
            2 => Some("TLS 1.0".into()),
            3 => Some("TLS 1.1".into()),
            4 => Some("TLS 1.2".into()),
            5 => Some("TLS 1.3".into()),
            6 => Some("QUIC".into()),
            _ => Some(format!("Unknown ({ver})")),
        };
    }
    if (flags & RESPONSE_INFO_HAS_SIGNED_CERTIFICATE_TIMESTAMPS) != 0
        && let Some(count) = r.read_u32()
    {
        for _ in 0..count.min(16) {
            let _ = r.read_bytes_aligned();
            let _ = r.read_u32();
            let _ = r.read_bytes_aligned();
        }
    }
    if (flags & RESPONSE_INFO_HAS_VARY_DATA) != 0 {
        let _ = r.skip(16);
    }

    // Read socket_address (host string + port u32)
    if let Some(host) = r.read_string() {
        let host_trimmed = host.trim_end_matches('\0').to_string();
        if !host_trimmed.is_empty() {
            meta.server_ip = Some(host_trimmed);
        }
        if let Some(port) = r.read_u32()
            && (1..=65535).contains(&port)
        {
            meta.server_port = Some(port as u16);
        }
    }

    if (flags & RESPONSE_INFO_HAS_ALPN_NEGOTIATED_PROTOCOL) != 0
        && let Some(alpn) = r.read_string()
    {
        let alpn = alpn.trim_end_matches('\0').to_string();
        if !alpn.is_empty() {
            meta.alpn_protocol = Some(alpn);
        }
    }
    if (flags & RESPONSE_INFO_HAS_CONNECTION_INFO) != 0 {
        let _ = r.read_u32();
    }
    if (flags & RESPONSE_INFO_HAS_KEY_EXCHANGE_GROUP) != 0 {
        let _ = r.read_u32();
    }
    if (flags & RESPONSE_INFO_HAS_STALENESS) != 0 {
        let _ = r.read_i64();
        let _ = r.read_i64();
    }
    if (flags & RESPONSE_INFO_HAS_PEER_SIGNATURE_ALGORITHM) != 0 {
        let _ = r.read_u32();
    }
    if (flags & RESPONSE_INFO_HAS_DNS_ALIASES) != 0
        && let Some(count) = r.read_u32()
    {
        for _ in 0..count.min(64) {
            if let Some(alias) = r.read_string() {
                let alias = alias.trim_end_matches('\0').to_string();
                if !alias.is_empty() {
                    meta.dns_aliases.push(alias);
                }
            } else {
                break;
            }
        }
    }
    if (flags & RESPONSE_INFO_BROWSER_RUN_ID) != 0 {
        let _ = r.read_i64();
    }

    meta
}

fn parse_raw_http_headers(raw: &[u8], meta: &mut HttpResponseMetadata) {
    let trimmed = raw.strip_suffix(b"\0\0").unwrap_or(raw);
    let mut lines = trimmed.split(|&b| b == 0).filter(|l| !l.is_empty());
    if let Some(status_bytes) = lines.next() {
        let status_line = String::from_utf8_lossy(status_bytes).trim().to_string();
        if let Some(code_str) = status_line.split_whitespace().nth(1) {
            meta.status_code = code_str.parse::<u16>().ok();
        }
        meta.status_line = status_line;
    }

    let mut max_age_secs: Option<i64> = None;
    let mut date_header: Option<DateTime<Utc>> = None;
    let mut expires_header: Option<DateTime<Utc>> = None;

    for line_bytes in lines {
        let line = String::from_utf8_lossy(line_bytes);
        if let Some((name, value)) = line.split_once(':') {
            let name_trim = name.trim().to_string();
            let val_trim = value.trim().to_string();
            let lower = name_trim.to_ascii_lowercase();
            match lower.as_str() {
                "content-type" => {
                    meta.raw_content_type = Some(val_trim.clone());
                    if let Some(norm) = chrome2rust_core::magic::normalize_mime(&val_trim) {
                        meta.content_type = Some(norm);
                    }
                }
                "content-disposition" => {
                    if meta.content_disposition_filename.is_none() {
                        meta.content_disposition_filename =
                            chrome2rust_core::magic::parse_content_disposition_filename(&val_trim);
                    }
                }
                "content-encoding" => {
                    if !val_trim.is_empty() {
                        meta.content_encoding = Some(val_trim.to_ascii_lowercase());
                    }
                }
                "server" => {
                    if !val_trim.is_empty() {
                        meta.server_name = Some(val_trim.clone());
                    }
                }
                "date" => {
                    date_header = parse_http_date(&val_trim);
                }
                "last-modified" => {
                    meta.last_modified = parse_http_date(&val_trim);
                }
                "expires" => {
                    expires_header = parse_http_date(&val_trim);
                }
                "cache-control" => {
                    for directive in val_trim.split(',') {
                        let d = directive.trim().to_ascii_lowercase();
                        if let Some(age_str) = d.strip_prefix("max-age=")
                            && let Ok(secs) = age_str.trim().trim_matches('"').parse::<i64>()
                        {
                            max_age_secs = Some(secs);
                        }
                    }
                }
                _ => {}
            }
            meta.headers.push(ParsedHeader {
                name: name_trim,
                value: val_trim,
            });
        }
    }

    meta.server_time = date_header.or(meta.last_modified);

    if let Some(max_age) = max_age_secs {
        let base = date_header.or(meta.response_time);
        if let Some(b) = base
            && let Some(delta) = Duration::try_seconds(max_age)
        {
            meta.expiration_time = b.checked_add_signed(delta);
        }
    } else if let Some(exp) = expires_header {
        meta.expiration_time = Some(exp);
    }
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_chromium_156_pickle() {
        // Real stream0 hex captured from Chromium 156.0.8078.79
        let hex = "d00000000300048006000000f5e3a52ddcbe2f0071f7a52ddcbe2f0071f7a52ddcbe2f008b000000485454502f312e3020323030204f4b005365727665723a2042617365485454502f302e3620507974686f6e2f332e31312e3200446174653a2053756e2c203135204e6f7620323032362030303a33393a333320474d5400436f6e74656e742d547970653a20746578742f6373730043616368652d436f6e74726f6c3a206d61782d6167653d33363030000000090000003132372e302e302e310000008b87000009000000ffffffff00000000";
        let bytes = (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect::<Vec<u8>>();

        let meta = parse_http_response_info(&bytes);
        assert_eq!(meta.status_line, "HTTP/1.0 200 OK");
        assert_eq!(meta.status_code, Some(200));
        assert_eq!(meta.content_type.as_deref(), Some("text/css"));
        assert_eq!(meta.server_name.as_deref(), Some("BaseHTTP/0.6 Python/3.11.2"));
        assert_eq!(meta.server_ip.as_deref(), Some("127.0.0.1"));
        assert_eq!(meta.server_port, Some(34699));
        assert!(meta.request_time.is_some());
        assert!(meta.response_time.is_some());
        assert!(meta.original_response_time.is_some());
        assert!(meta.expiration_time.is_some());
    }

    #[test]
    fn test_pickle_max_age_overflow_and_large_len() {
        // Huge max-age (i64::MAX) and quoted max-age must never panic
        let headers_big =
            b"HTTP/1.1 200 OK\0Date: Sun, 15 Nov 2026 00:00:00 GMT\0Cache-Control: max-age=9223372036854775807\0\0";
        let mut s0 = Vec::new();
        s0.extend_from_slice(&0u32.to_le_bytes());
        s0.extend_from_slice(&3u32.to_le_bytes());
        s0.extend_from_slice(&0i64.to_le_bytes());
        s0.extend_from_slice(&0i64.to_le_bytes());
        s0.extend_from_slice(&(headers_big.len() as u32).to_le_bytes());
        s0.extend_from_slice(headers_big);
        let meta = parse_http_response_info(&s0);
        assert_eq!(meta.status_code, Some(200));
        assert!(meta.expiration_time.is_none());

        // Quoted max-age="3600"
        let headers_quoted =
            b"HTTP/1.1 200 OK\0Date: Sun, 15 Nov 2026 00:00:00 GMT\0Cache-Control: max-age=\"3600\"\0\0";
        let mut s0_q = Vec::new();
        s0_q.extend_from_slice(&0u32.to_le_bytes());
        s0_q.extend_from_slice(&3u32.to_le_bytes());
        s0_q.extend_from_slice(&0i64.to_le_bytes());
        s0_q.extend_from_slice(&0i64.to_le_bytes());
        s0_q.extend_from_slice(&(headers_quoted.len() as u32).to_le_bytes());
        s0_q.extend_from_slice(headers_quoted);
        let meta_q = parse_http_response_info(&s0_q);
        assert!(meta_q.expiration_time.is_some());

        // Pickle aligned length = u32::MAX must fail cleanly
        let mut s0_max = Vec::new();
        s0_max.extend_from_slice(&0u32.to_le_bytes());
        s0_max.extend_from_slice(&3u32.to_le_bytes());
        s0_max.extend_from_slice(&0i64.to_le_bytes());
        s0_max.extend_from_slice(&0i64.to_le_bytes());
        s0_max.extend_from_slice(&u32::MAX.to_le_bytes());
        let meta_max = parse_http_response_info(&s0_max);
        assert_eq!(meta_max.status_code, None);
    }
}
