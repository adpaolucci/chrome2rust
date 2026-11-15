use aes::cipher::{BlockEncryptMut, KeyIvInit, block_padding::Pkcs7};
use chrome2rust_cache::export::{
    CacheColumn, ExportFormat, ExtractFilenameMode, ExtractOptions, extract_cache_entries, render_cache_export,
};
use chrome2rust_cache::{CacheScanOptions, CacheSortField, delete_cache_entries, sort_cache_entries};
use chrome2rust_core::crypto::{CryptoOptions, EncryptionScheme};
use chrome2rust_core::discovery::{TargetKind, resolve_target_path};
use chrome2rust_forensics::findings::FindingSeverity;
use chrome2rust_forensics::{AnalysisOptions, analyze_user_data};
use chrome2rust_report::{ReportFormat, write_report};
use flate2::Compression;
use flate2::write::GzEncoder;
use hmac::Hmac;
use pbkdf2::pbkdf2;
use rusqlite::Connection;
use sha1::Sha1;
use sha2::{Digest, Sha256};
use std::io::Write;
use tempfile::TempDir;

type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;

fn build_synthetic_user_data(root: &std::path::Path) {
    // 1. Last Version + Local State
    std::fs::write(root.join("Last Version"), "156.0.8078.79\n").unwrap();
    let local_state = serde_json::json!({
        "os_crypt": {
            "encrypted_key": "DPAPI_TEST_KEY"
        },
        "variations_country": "US",
        "profile": {
            "last_active_profiles": ["Default"],
            "info_cache": {
                "Default": {
                    "name": "Alice Investigation",
                    "user_name": "alice@example.org",
                    "gaia_name": "Alice",
                    "active_time": 1794680000.5,
                    "is_ephemeral": false
                }
            }
        }
    });
    std::fs::write(
        root.join("Local State"),
        serde_json::to_string_pretty(&local_state).unwrap(),
    )
    .unwrap();

    let def = root.join("Default");
    std::fs::create_dir_all(def.join("Cache").join("Cache_Data")).unwrap();
    std::fs::create_dir_all(def.join("Network")).unwrap();
    std::fs::create_dir_all(def.join("Sessions")).unwrap();
    std::fs::create_dir_all(def.join("Local Storage").join("leveldb")).unwrap();
    std::fs::create_dir_all(
        def.join("Extensions")
            .join("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
            .join("1.0.0"),
    )
    .unwrap();

    // 2. Preferences + Extension manifest
    let prefs = serde_json::json!({
        "profile": { "name": "Alice Investigation" },
        "account_info": [{ "email": "alice@example.org" }],
        "homepage": "https://portal.example.org/",
        "safebrowsing": { "enabled": true },
        "extensions": {
            "ui": { "developer_mode": true },
            "settings": {
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa": {
                    "location": 4,
                    "state": 1,
                    "from_webstore": false,
                    "install_time": "13439176738739516"
                }
            }
        }
    });
    std::fs::write(def.join("Preferences"), serde_json::to_string(&prefs).unwrap()).unwrap();
    let manifest = serde_json::json!({
        "name": "Test Audit Extension",
        "version": "1.0.0",
        "manifest_version": 3,
        "permissions": ["cookies", "debugger"],
        "host_permissions": ["<all_urls>"]
    });
    std::fs::write(
        def.join("Extensions")
            .join("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
            .join("1.0.0")
            .join("manifest.json"),
        serde_json::to_string(&manifest).unwrap(),
    )
    .unwrap();

    // 3. Bookmarks
    let bookmarks = serde_json::json!({
        "version": 1,
        "roots": {
            "bookmark_bar": {
                "type": "folder",
                "name": "Bookmarks bar",
                "children": [
                    {
                        "type": "url",
                        "name": "Example Portal",
                        "url": "https://portal.example.org/dashboard",
                        "guid": "bm-1",
                        "date_added": "13439176738739516"
                    }
                ]
            }
        }
    });
    std::fs::write(def.join("Bookmarks"), serde_json::to_string(&bookmarks).unwrap()).unwrap();

    // 4. History DB (urls, visits, downloads, downloads_url_chains, keyword_search_terms, sqlite_sequence w/ gap)
    {
        let conn = Connection::open(def.join("History")).unwrap();
        conn.execute_batch(
            "CREATE TABLE urls(id INTEGER PRIMARY KEY AUTOINCREMENT, url TEXT, title TEXT, visit_count INTEGER, typed_count INTEGER, last_visit_time INTEGER, hidden INTEGER);
             CREATE TABLE visits(id INTEGER PRIMARY KEY AUTOINCREMENT, url INTEGER, visit_time INTEGER, from_visit INTEGER, transition INTEGER, visit_duration INTEGER);
             CREATE TABLE downloads(id INTEGER PRIMARY KEY, guid TEXT, current_path TEXT, target_path TEXT, start_time INTEGER, end_time INTEGER, received_bytes INTEGER, total_bytes INTEGER, state INTEGER, danger_type INTEGER, interrupt_reason INTEGER, mime_type TEXT, original_mime_type TEXT, referrer TEXT, tab_url TEXT, opened INTEGER);
             CREATE TABLE downloads_url_chains(id INTEGER, chain_index INTEGER, url TEXT);
             CREATE TABLE keyword_search_terms(keyword_id INTEGER, url_id INTEGER, term TEXT, normalized_term TEXT);
             INSERT INTO urls(id, url, title, visit_count, typed_count, last_visit_time, hidden) VALUES (1, 'https://portal.example.org/login', 'Portal Login', 5, 2, 13439176738739516, 0);
             INSERT INTO urls(id, url, title, visit_count, typed_count, last_visit_time, hidden) VALUES (5, 'https://search.example.org/?q=rust+forensics', 'Search', 1, 0, 13439176800000000, 0);
             UPDATE sqlite_sequence SET seq = 10 WHERE name = 'urls';
             INSERT INTO visits(id, url, visit_time, from_visit, transition, visit_duration) VALUES (1, 1, 13439176738739516, 0, 1, 12000000);
             INSERT INTO visits(id, url, visit_time, from_visit, transition, visit_duration) VALUES (2, 5, 13439176800000000, 1, 0, 5000000);
             INSERT INTO downloads VALUES (1, 'dl-1', '/tmp/part', '/tmp/payload.exe', 13439176850000000, 13439176855000000, 4096, 4096, 1, 1, 0, 'application/x-msdownload', '', 'https://portal.example.org', '', 1);
             INSERT INTO downloads_url_chains VALUES (1, 0, 'https://cdn.example.org/payload.exe');
             INSERT INTO keyword_search_terms VALUES (1, 5, 'rust forensics', 'rust forensics');",
        )
        .unwrap();
    }

    // 5. Cookies DB (v24 encrypted with v10 + peanuts)
    {
        let mut key = [0u8; 16];
        let _ = pbkdf2::<Hmac<Sha1>>(b"peanuts", b"saltysalt", 1, &mut key);
        let iv = [0x20u8; 16];
        let mut pt = Sha256::digest(b"portal.example.org").to_vec();
        pt.extend_from_slice(b"secret_session_tok");
        let mut buf = vec![0u8; pt.len() + 16];
        buf[..pt.len()].copy_from_slice(&pt);
        let ct = Aes128CbcEnc::new_from_slices(&key, &iv)
            .unwrap()
            .encrypt_padded_mut::<Pkcs7>(&mut buf, pt.len())
            .unwrap();
        let mut blob = b"v10".to_vec();
        blob.extend_from_slice(ct);

        let conn = Connection::open(def.join("Network").join("Cookies")).unwrap();
        conn.execute_batch(
            "CREATE TABLE meta(key TEXT PRIMARY KEY, value TEXT);
             INSERT INTO meta VALUES ('version', '24');
             CREATE TABLE cookies(creation_utc INTEGER, host_key TEXT, top_frame_site_key TEXT, name TEXT, value TEXT, encrypted_value BLOB, path TEXT, expires_utc INTEGER, is_secure INTEGER, is_httponly INTEGER, last_access_utc INTEGER, is_persistent INTEGER, samesite INTEGER, source_scheme INTEGER, source_port INTEGER, last_update_utc INTEGER, has_cross_site_ancestor INTEGER);",
        )
        .unwrap();
        conn.execute(
            "INSERT INTO cookies VALUES (13439176738739516, 'portal.example.org', '', 'SID', '', ?1, '/', 13470712738739516, 1, 1, 13439176739000000, 1, 2, 2, 443, 13439176738739516, 0)",
            [&blob],
        )
        .unwrap();
    }

    // 6. Login Data w/ insecure_credentials
    {
        let conn = Connection::open(def.join("Login Data")).unwrap();
        conn.execute_batch(
            "CREATE TABLE logins(id INTEGER PRIMARY KEY, origin_url TEXT, action_url TEXT, username_element TEXT, username_value TEXT, password_value BLOB, signon_realm TEXT, date_created INTEGER, date_last_used INTEGER, date_password_modified INTEGER, times_used INTEGER, blacklisted_by_user INTEGER);
             CREATE TABLE insecure_credentials(parent_id INTEGER, insecurity_type INTEGER, is_muted INTEGER);
             INSERT INTO logins VALUES (1, 'https://portal.example.org/', 'https://portal.example.org/auth', 'user', 'alice', X'763130616263', 'https://portal.example.org/', 13439176738739516, 13439176800000000, 13439176738739516, 4, 0);
             INSERT INTO insecure_credentials VALUES (1, 0, 0);",
        )
        .unwrap();
    }

    // 7. Web Data
    {
        let conn = Connection::open(def.join("Web Data")).unwrap();
        conn.execute_batch(
            "CREATE TABLE autofill(name TEXT, value TEXT, value_lower TEXT, date_created INTEGER, date_last_used INTEGER, count INTEGER);
             INSERT INTO autofill VALUES ('email', 'alice@example.org', 'alice@example.org', 13439176738739516, 13439176800000000, 3);",
        )
        .unwrap();
    }

    // 8. SNSS Session File (one active tab, one closed tab)
    {
        let mut snss = Vec::new();
        snss.extend_from_slice(b"SNSS");
        snss.extend_from_slice(&3u32.to_le_bytes());

        // Helper to push UpdateTabNavigation (cmd 6)
        let push_nav = |buf: &mut Vec<u8>, tab_id: i32, idx: i32, url: &str, title: &str| {
            let url_b = url.as_bytes();
            let title_u16: Vec<u16> = title.encode_utf16().collect();
            let u_al = url_b.len().div_ceil(4) * 4;
            let t_bytes = title_u16.len() * 2;
            let t_al = t_bytes.div_ceil(4) * 4;
            let plen = 4 + 4 + 4 + u_al + 4 + t_al;
            let mut p = Vec::new();
            p.push(6u8); // cmd id
            p.extend_from_slice(&(plen as u32).to_le_bytes());
            p.extend_from_slice(&tab_id.to_le_bytes());
            p.extend_from_slice(&idx.to_le_bytes());
            p.extend_from_slice(&(url_b.len() as u32).to_le_bytes());
            p.extend_from_slice(url_b);
            p.resize(p.len() + (u_al - url_b.len()), 0);
            p.extend_from_slice(&(title_u16.len() as u32).to_le_bytes());
            for ch in title_u16 {
                p.extend_from_slice(&ch.to_le_bytes());
            }
            p.resize(p.len() + (t_al - t_bytes), 0);
            buf.extend_from_slice(&(p.len() as u16).to_le_bytes());
            buf.extend_from_slice(&p);
        };

        push_nav(&mut snss, 10, 0, "https://portal.example.org/dashboard", "Dashboard");
        push_nav(
            &mut snss,
            11,
            0,
            "https://secret.example.org/hidden.html",
            "Hidden Page",
        );

        // TabClosed (cmd 12) for tab 11
        let mut close_cmd = Vec::new();
        close_cmd.push(12u8);
        close_cmd.extend_from_slice(&11i32.to_le_bytes());
        close_cmd.extend_from_slice(&13_439_176_850_000_000i64.to_le_bytes());
        snss.extend_from_slice(&(close_cmd.len() as u16).to_le_bytes());
        snss.extend_from_slice(&close_cmd);

        std::fs::write(def.join("Sessions").join("Session_13439176738739516"), snss).unwrap();
    }

    // 9. Simple Cache entries: gzipped HTML missing from History + PNG image
    {
        let cache_dir = def.join("Cache").join("Cache_Data");
        let html_body = b"<html><body><h1>Cached Orphan HTML</h1></body></html>";
        let mut gz = GzEncoder::new(Vec::new(), Compression::default());
        gz.write_all(html_body).unwrap();
        let gz_bytes = gz.finish().unwrap();

        write_simple_cache_entry(
            &cache_dir.join("1111222233334444_0"),
            "1/0/_dk_https://orphan.example.org https://orphan.example.org https://orphan.example.org/page.html",
            "HTTP/1.1 200 OK\0Content-Type: text/html; charset=utf-8\0Content-Encoding: gzip\0Server: nginx\0\0",
            &gz_bytes,
            "93.184.216.34",
            443,
        );

        let png_stub = b"\x89PNG\r\n\x1a\nMOCKPNGDATA";
        write_simple_cache_entry(
            &cache_dir.join("5555666677778888_0"),
            "1/0/_dk_https://portal.example.org https://portal.example.org https://portal.example.org/logo",
            "HTTP/1.1 200 OK\0Content-Type: image/png\0Server: apache\0\0",
            png_stub,
            "93.184.216.34",
            443,
        );

        // WebP payload served without Content-Type or URL extension
        let webp_stub = b"RIFF\x20\x00\x00\x00WEBPVP8 \x14\x00\x00\x00TESTDATA";
        write_simple_cache_entry(
            &cache_dir.join("9999aaaabbbbcccc_0"),
            "1/0/_dk_https://cdn.example.org https://cdn.example.org https://cdn.example.org/media/asset-42",
            "HTTP/1.1 200 OK\0Server: cloudflare\0\0",
            webp_stub,
            "104.16.0.1",
            443,
        );

        // Spoofed Content-Type: image/png containing Windows PE executable
        let mut pe = vec![0u8; 128];
        pe[0..2].copy_from_slice(b"MZ");
        pe[0x3c..0x40].copy_from_slice(&64u32.to_le_bytes());
        pe[64..68].copy_from_slice(b"PE\0\0");
        write_simple_cache_entry(
            &cache_dir.join("dddd000011112222_0"),
            "1/0/_dk_https://cdn.example.org https://cdn.example.org https://cdn.example.org/badge.png",
            "HTTP/1.1 200 OK\0Content-Type: image/png\0Server: nginx\0\0",
            &pe,
            "104.16.0.2",
            443,
        );
    }
}

fn write_simple_cache_entry(path: &std::path::Path, key: &str, headers_nul: &str, payload: &[u8], ip: &str, port: u32) {
    let key_b = key.as_bytes();
    let hdr_b = headers_nul.as_bytes();
    let ip_b = ip.as_bytes();

    let h_al = hdr_b.len().div_ceil(4) * 4;
    let ip_al = ip_b.len().div_ceil(4) * 4;
    let plen = 4 + 8 + 8 + 4 + h_al + 4 + ip_al + 4;
    let mut s0 = Vec::new();
    s0.extend_from_slice(&(plen as u32).to_le_bytes());
    s0.extend_from_slice(&3u32.to_le_bytes());
    s0.extend_from_slice(&13_439_176_738_739_516i64.to_le_bytes());
    s0.extend_from_slice(&13_439_176_738_800_000i64.to_le_bytes());
    s0.extend_from_slice(&(hdr_b.len() as u32).to_le_bytes());
    s0.extend_from_slice(hdr_b);
    s0.resize(s0.len() + (h_al - hdr_b.len()), 0);
    s0.extend_from_slice(&(ip_b.len() as u32).to_le_bytes());
    s0.extend_from_slice(ip_b);
    s0.resize(s0.len() + (ip_al - ip_b.len()), 0);
    s0.extend_from_slice(&port.to_le_bytes());

    let mut out = Vec::new();
    out.extend_from_slice(&0xfcfb6d1ba7725c30u64.to_le_bytes());
    out.extend_from_slice(&5u32.to_le_bytes());
    out.extend_from_slice(&(key_b.len() as u32).to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(key_b);
    out.extend_from_slice(payload);
    // EOF1
    out.extend_from_slice(&0xf4fa6f45970d41d8u64.to_le_bytes());
    out.extend_from_slice(&1u32.to_le_bytes());
    out.extend_from_slice(&crc32fast::hash(payload).to_le_bytes());
    out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    // s0 + sha + EOF0
    out.extend_from_slice(&s0);
    out.extend_from_slice(&Sha256::digest(key_b));
    out.extend_from_slice(&0xf4fa6f45970d41d8u64.to_le_bytes());
    out.extend_from_slice(&3u32.to_le_bytes());
    out.extend_from_slice(&crc32fast::hash(&s0).to_le_bytes());
    out.extend_from_slice(&(s0.len() as u32).to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());

    std::fs::write(path, out).unwrap();
}

#[test]
fn test_full_user_data_analysis_and_reports() {
    let ud_tmp = TempDir::new().unwrap();
    build_synthetic_user_data(ud_tmp.path());

    // Verify target resolution classifies UserData root correctly
    let resolved = resolve_target_path(ud_tmp.path());
    assert_eq!(resolved.kind, TargetKind::UserDataRoot);
    assert_eq!(resolved.profile_dirs.len(), 1);
    assert_eq!(resolved.cache_dirs.len(), 1);

    // Run full analysis with best-effort decryption enabled
    let opts = AnalysisOptions {
        cache_options: CacheScanOptions {
            compute_hashes: true,
            ..Default::default()
        },
        crypto_options: CryptoOptions::best_effort(),
        extra_cache_dirs: Vec::new(),
        include_timeline: true,
    };

    let report = analyze_user_data(ud_tmp.path(), &opts);
    assert_eq!(report.local_state.chrome_version.as_deref(), Some("156.0.8078.79"));
    assert_eq!(report.summary.profile_count, 1);
    assert_eq!(report.summary.total_cache_entries, 4);
    assert_eq!(report.summary.total_history_urls, 2);
    assert_eq!(report.summary.total_history_visits, 2);
    assert_eq!(report.summary.total_downloads, 1);
    assert_eq!(report.summary.total_cookies, 1);
    assert_eq!(report.summary.total_logins, 1);
    assert_eq!(report.summary.total_bookmarks, 1);
    assert_eq!(report.summary.total_extensions, 1);
    assert_eq!(report.summary.total_open_tabs, 1);
    assert_eq!(report.summary.total_closed_tabs, 1);

    let prof = &report.profiles[0];
    // Cookie decryption with DB v24 SHA-256 domain strip
    assert_eq!(prof.cookies[0].encryption_scheme, EncryptionScheme::V10);
    assert_eq!(prof.cookies[0].value.as_deref(), Some("secret_session_tok"));

    // Verify content detection on extensionless WebP and spoofed PE badge.png
    let webp_entry = prof
        .cache_entries
        .iter()
        .find(|e| e.url.ends_with("/media/asset-42"))
        .unwrap();
    assert_eq!(webp_entry.detected_content_type.as_deref(), Some("image/webp"));
    assert_eq!(webp_entry.detected_extension.as_deref(), Some("webp"));
    assert!(!webp_entry.mime_mismatch);

    let spoofed_entry = prof
        .cache_entries
        .iter()
        .find(|e| e.url.ends_with("/badge.png"))
        .unwrap();
    assert!(spoofed_entry.mime_mismatch);
    assert_eq!(spoofed_entry.detected_extension.as_deref(), Some("exe"));

    // Extension risk flags
    assert!(!prof.extensions[0].risk_flags.is_empty());

    // Forensic intelligence findings triggered:
    // Critical insecure credential, High dangerous download + sideloaded ext + MIME mismatch,
    // Medium seq gap + cache orphan HTML
    assert!(report.findings.iter().any(|f| f.severity == FindingSeverity::Critical));
    assert!(report.findings.iter().any(|f| f.category == "Downloads"));
    assert!(report.findings.iter().any(|f| f.category == "History Integrity"));
    assert!(report.findings.iter().any(|f| f.category == "Cross-Artifact"));
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.category == "Cache" && f.severity == FindingSeverity::High && f.title.contains("MIME Mismatch"))
    );

    // Write full report bundle (HTML, JSON, Markdown)
    let out_dir = TempDir::new().unwrap();
    let written = write_report(&report, out_dir.path(), ReportFormat::All).unwrap();
    assert_eq!(written.len(), 3);
    for p in &written {
        assert!(p.is_file());
        assert!(std::fs::metadata(p).unwrap().len() > 500);
    }

    let html_content = std::fs::read_to_string(&written[0]).unwrap();
    assert!(html_content.contains("chrome2rust Forensic Report"));
    assert!(html_content.contains("orphan.example.org"));
    assert!(html_content.contains("image/webp"));
    assert!(html_content.contains("badge.png"));
    assert!(!html_content.contains("https://cdn.example.org/payload.exe</script>"));

    let md_content = std::fs::read_to_string(&written[2]).unwrap();
    assert!(md_content.contains("Alice Investigation"));
    assert!(md_content.contains("Compromised / Insecure Saved Credentials"));
    assert!(md_content.contains("Declared Type | Detected Type | Ext"));
    assert!(md_content.contains("MIME Mismatch"));
}

#[test]
fn test_cache_export_formats_extraction_and_delete() {
    let ud_tmp = TempDir::new().unwrap();
    build_synthetic_user_data(ud_tmp.path());

    let rep = analyze_user_data(ud_tmp.path(), &AnalysisOptions::default());
    let mut entries = rep.profiles[0].cache_entries.clone();
    sort_cache_entries(&mut entries, CacheSortField::Url, false, None);
    assert_eq!(entries.len(), 4);

    // Export in every supported cache table format
    let cols = CacheColumn::default_columns();
    for fmt in [
        ExportFormat::Csv,
        ExportFormat::Tab,
        ExportFormat::Tabular,
        ExportFormat::Text,
        ExportFormat::HtmlHorizontal,
        ExportFormat::HtmlVertical,
        ExportFormat::Xml,
        ExportFormat::Json,
    ] {
        let rendered = render_cache_export(&entries, fmt, &cols, true, false).unwrap();
        assert!(rendered.contains("orphan.example.org"));
        assert!(rendered.contains("portal.example.org"));
        assert!(rendered.contains("image/webp"));
    }

    // Extraction with website directory reconstruction + gunzip decompression + ext inference
    let ext_dir = TempDir::new().unwrap();
    let refs: Vec<_> = entries.iter().collect();
    let summary = extract_cache_entries(
        &refs,
        &ExtractOptions {
            output_dir: ext_dir.path().to_path_buf(),
            filename_mode: ExtractFilenameMode::BasedOnUrl,
            use_website_dir_structure: true,
            update_modified_time: true,
            new_name_if_exist: true,
            decompress: true,
            prefer_detected_extension: false,
        },
    )
    .unwrap();

    assert_eq!(summary.extracted_count, 4);
    assert_eq!(summary.failed_count, 0);

    let extracted_html = ext_dir.path().join("orphan.example.org").join("page.html");
    assert!(extracted_html.is_file());
    assert!(
        std::fs::read_to_string(&extracted_html)
            .unwrap()
            .contains("Cached Orphan HTML")
    );

    let extracted_png = ext_dir.path().join("portal.example.org").join("logo.png");
    assert!(extracted_png.is_file());

    let extracted_webp = ext_dir
        .path()
        .join("cdn.example.org")
        .join("media")
        .join("asset-42.webp");
    assert!(extracted_webp.is_file());

    // Delete one standalone Simple Cache entry
    let (deleted, skipped) = delete_cache_entries(&[&entries[0]]);
    assert_eq!(deleted, 1);
    assert!(skipped.is_empty());
}
