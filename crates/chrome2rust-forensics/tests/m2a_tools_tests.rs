use chrome2rust_cache::firefox::build_synthetic_firefox_cache2_entry;
use chrome2rust_cache::opera::build_synthetic_presto_dcache4;
use chrome2rust_core::mozlz4::compress_mozlz4_literals;
use chrome2rust_core::plist::{PlistValue, encode_bplist00};
use chrome2rust_forensics::firefox::parse_firefox_jsonlz4_bookmarks;
use chrome2rust_forensics::providers::{build_browser_tool_provider_by_id, build_browser_tool_providers};
use chrome2rust_forensics::webdata::parse_autofill_only;
use crc32fast::Hasher;
use flate2::Compression;
use flate2::write::GzEncoder;
use guap_export::{ExportFormat, ExportOptions, export_table, write_table_export};
use guap_table::{CellValue, GuapQuery, TableQuery};
use rusqlite::Connection;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::io::Write;
use std::path::Path;
use tempfile::TempDir;

fn write_simple_cache_entry(path: &Path, key: &str, headers_nul: &str, payload: &[u8]) {
    let key_b = key.as_bytes();
    let hdr_b = headers_nul.as_bytes();
    let ip_b = b"198.51.100.5";
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
    s0.extend_from_slice(&443u32.to_le_bytes());

    let mut h1 = Hasher::new();
    h1.update(payload);
    let crc1 = h1.finalize();
    let mut h0 = Hasher::new();
    h0.update(&s0);
    let crc0 = h0.finalize();

    let mut out = Vec::new();
    out.extend_from_slice(&0xfcfb6d1ba7725c30u64.to_le_bytes());
    out.extend_from_slice(&5u32.to_le_bytes());
    out.extend_from_slice(&(key_b.len() as u32).to_le_bytes());
    out.extend_from_slice(&0u64.to_le_bytes());
    out.extend_from_slice(key_b);
    out.extend_from_slice(payload);
    out.extend_from_slice(&0xf4fa6f45970d41d8u64.to_le_bytes());
    out.extend_from_slice(&1u32.to_le_bytes());
    out.extend_from_slice(&crc1.to_le_bytes());
    out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&s0);
    out.extend_from_slice(&Sha256::digest(key_b));
    out.extend_from_slice(&0xf4fa6f45970d41d8u64.to_le_bytes());
    out.extend_from_slice(&3u32.to_le_bytes());
    out.extend_from_slice(&crc0.to_le_bytes());
    out.extend_from_slice(&(s0.len() as u32).to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    std::fs::write(path, out).unwrap();
}

fn build_multi_browser_fixture() -> TempDir {
    let dir = TempDir::new().unwrap();
    let root = dir.path();

    // ---------------------------------------------------------------------
    // 1. Chrome profile (History, Bookmarks, Preferences, Web Data, Cache)
    // ---------------------------------------------------------------------
    let chrome_prof = root.join("ChromeUserData").join("Default");
    let chrome_cache = chrome_prof.join("Cache").join("Cache_Data");
    std::fs::create_dir_all(&chrome_cache).unwrap();
    std::fs::write(
        root.join("ChromeUserData").join("Local State"),
        r#"{"profile":{"info_cache":{"Default":{"name":"Work"}}}}"#,
    )
    .unwrap();

    let ch_hist = Connection::open(chrome_prof.join("History")).unwrap();
    ch_hist
        .execute_batch(
            "CREATE TABLE urls(id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER, typed_count INTEGER, last_visit_time INTEGER, hidden INTEGER);
             CREATE TABLE visits(id INTEGER PRIMARY KEY, url INTEGER, visit_time INTEGER, from_visit INTEGER, transition INTEGER, visit_duration INTEGER);
             CREATE TABLE downloads(id INTEGER PRIMARY KEY, guid TEXT, current_path TEXT, target_path TEXT, start_time INTEGER, end_time INTEGER, received_bytes INTEGER, total_bytes INTEGER, state INTEGER, danger_type INTEGER, interrupt_reason INTEGER, mime_type TEXT, original_mime_type TEXT, referrer TEXT, tab_url TEXT, opened INTEGER);
             CREATE TABLE downloads_url_chains(id INTEGER, chain_index INTEGER, url TEXT);
             CREATE TABLE keyword_search_terms(keyword_id INTEGER, url_id INTEGER, term TEXT, normalized_term TEXT);
             INSERT INTO urls VALUES (1, 'https://www.google.com/search?q=rust+exif+parser', 'Google Search', 2, 1, 13439176738739516, 0);
             INSERT INTO urls VALUES (2, 'https://docs.rs/guap-table', 'docs.rs', 1, 0, 13439176748739516, 0);
             INSERT INTO visits VALUES (1, 1, 13439176738739516, 0, 1, 500000);
             INSERT INTO visits VALUES (2, 2, 13439176748739516, 1, 0, 200000);
             INSERT INTO downloads VALUES (1, 'dl-1', '/tmp/report.pdf.crdownload', '/home/user/report.pdf', 13439176738000000, 13439176739000000, 4096, 4096, 1, 0, 0, 'application/pdf', 'application/pdf', 'https://example.org', '', 1);
             INSERT INTO downloads_url_chains VALUES (1, 0, 'https://cdn.example.org/report.pdf');
             INSERT INTO keyword_search_terms VALUES (1, 1, 'rust exif parser', 'rust exif parser');",
        )
        .unwrap();

    std::fs::write(
        chrome_prof.join("Bookmarks"),
        r#"{"roots":{"bookmark_bar":{"children":[{"type":"url","name":"GUAP Hub","url":"https://guap.ca","guid":"bm-ch-1","date_added":"13439176738739516"}],"name":"Bookmarks Bar","type":"folder"}}}"#,
    )
    .unwrap();
    std::fs::write(
        chrome_prof.join("Preferences"),
        r#"{"extensions":{"settings":{"ext_unpacked_1":{"location":4,"state":1,"from_webstore":false,"manifest":{"name":"Unpacked Debugger","version":"1.0","permissions":["debugger"],"host_permissions":["<all_urls>"]}}}}}"#,
    )
    .unwrap();

    // Web Data with BOTH autofill AND sensitive credit_cards/masked_credit_cards/local_ibans (R4 test!)
    let wd = Connection::open(chrome_prof.join("Web Data")).unwrap();
    wd.execute_batch(
        "CREATE TABLE autofill(name TEXT, value TEXT, value_lower TEXT, date_created INTEGER, date_last_used INTEGER, count INTEGER);
         CREATE TABLE credit_cards(guid TEXT, name_on_card TEXT, expiration_month INTEGER, expiration_year INTEGER, card_number_encrypted BLOB, date_modified INTEGER, origin TEXT, use_count INTEGER, use_date INTEGER, billing_address_id TEXT, nickname TEXT);
         CREATE TABLE masked_credit_cards(id TEXT, status TEXT, name_on_card TEXT, network TEXT, last_four TEXT, exp_month INTEGER, exp_year INTEGER, bank_name TEXT, nickname TEXT);
         CREATE TABLE local_ibans(guid TEXT, nickname TEXT, prefix TEXT, suffix TEXT, length INTEGER, value_encrypted BLOB);
         INSERT INTO autofill VALUES ('email', 'alice@example.org', 'alice@example.org', 1794700000, 1794700800, 4);
         INSERT INTO credit_cards VALUES ('cc-1', 'SECRET_CARDHOLDER_R4', 12, 2029, X'010203', 1794700800, '', 1, 1794700800, '', 'Personal Visa');
         INSERT INTO masked_credit_cards VALUES ('mc-1', 'VALID', 'SECRET_MASKED_R4', 'VISA', '4242', 12, 2029, 'Bank', 'Corp');
         INSERT INTO local_ibans VALUES ('ib-1', 'SECRET_IBAN_R4', 'DE89', '3000', 22, X'0102');",
    )
    .unwrap();

    // Simple Cache entries: Search Referer + PNG + MP4
    write_simple_cache_entry(
        &chrome_cache.join("aaaa000000000001_0"),
        "https://docs.rs/crate/latest",
        "HTTP/1.1 200 OK\0Content-Type: text/html\0Referer: https://www.bing.com/search?q=chrome2rust+referer+query\0\0",
        b"<html>ok</html>",
    );
    write_simple_cache_entry(
        &chrome_cache.join("aaaa000000000002_0"),
        "https://img.example.test/tiny.png",
        "HTTP/1.1 200 OK\0Content-Type: image/png\0\0",
        b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x20\x00\x00\x00\x10\x08\x06\x00\x00\x00",
    );
    let mut mp4 = vec![0u8; 44];
    mp4[0..4].copy_from_slice(&16u32.to_be_bytes());
    mp4[4..8].copy_from_slice(b"ftyp");
    mp4[8..12].copy_from_slice(b"isom");
    mp4[16..20].copy_from_slice(&28u32.to_be_bytes());
    mp4[20..24].copy_from_slice(b"moov");
    mp4[24..28].copy_from_slice(&20u32.to_be_bytes());
    mp4[28..32].copy_from_slice(b"mvhd");
    mp4[36..40].copy_from_slice(&1000u32.to_be_bytes());
    mp4[40..44].copy_from_slice(&3000u32.to_be_bytes());
    write_simple_cache_entry(
        &chrome_cache.join("aaaa000000000003_0"),
        "https://vid.example.test/clip.mp4",
        "HTTP/1.1 200 OK\0Content-Type: video/mp4\0\0",
        &mp4,
    );

    // ---------------------------------------------------------------------
    // 2. Firefox profile (all 8 fx tools)
    // ---------------------------------------------------------------------
    let fx_prof = root.join("FirefoxProfile");
    let fx_entries = fx_prof.join("cache2").join("entries");
    std::fs::create_dir_all(&fx_entries).unwrap();
    std::fs::create_dir_all(fx_prof.join("bookmarkbackups")).unwrap();
    std::fs::create_dir_all(fx_prof.join("sessionstore-backups")).unwrap();

    let mut gz = GzEncoder::new(Vec::new(), Compression::default());
    gz.write_all(b"<html>Firefox Search</html>").unwrap();
    let gz_bytes = gz.finish().unwrap();
    let fx_c2 = build_synthetic_firefox_cache2_entry(
        ":https://duckduckgo.com/?q=mozilla+forensics",
        "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Encoding: gzip\r\n",
        &gz_bytes,
        3,
        1_794_700_800,
        1_794_787_200,
        99,
    );
    std::fs::write(fx_entries.join("0123456789ABCDEF0123456789ABCDEF01234567"), fx_c2).unwrap();

    let places = Connection::open(fx_prof.join("places.sqlite")).unwrap();
    places
        .execute_batch(
            "CREATE TABLE moz_places(id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER, frecency INTEGER, last_visit_date INTEGER);
             CREATE TABLE moz_historyvisits(id INTEGER PRIMARY KEY, from_visit INTEGER, place_id INTEGER, visit_date INTEGER, visit_type INTEGER);
             CREATE TABLE moz_bookmarks(id INTEGER PRIMARY KEY, type INTEGER, fk INTEGER, parent INTEGER, position INTEGER, title TEXT, dateAdded INTEGER, lastModified INTEGER, guid TEXT);
             CREATE TABLE moz_anno_attributes(id INTEGER PRIMARY KEY, name TEXT);
             CREATE TABLE moz_annos(id INTEGER PRIMARY KEY, place_id INTEGER, anno_attribute_id INTEGER, content TEXT, dateAdded INTEGER);
             INSERT INTO moz_places VALUES (1, 'https://search.yahoo.com/search?p=fx+query', 'Yahoo Search', 2, 100, 1794700800000000);
             INSERT INTO moz_places VALUES (2, 'https://mozilla.org/en-US/', 'Mozilla', 1, 50, 1794700805000000);
             INSERT INTO moz_places VALUES (3, 'https://releases.mozilla.org/fx.tar.xz', 'Download', 0, 0, NULL);
             INSERT INTO moz_historyvisits VALUES (10, 0, 1, 1794700800000000, 2);
             INSERT INTO moz_historyvisits VALUES (11, 10, 2, 1794700805000000, 1);
             INSERT INTO moz_bookmarks VALUES (1, 2, NULL, 0, 0, 'Toolbar', 1794700000000000, 1794700000000000, 'root-guid');
             INSERT INTO moz_bookmarks VALUES (2, 1, 2, 1, 0, 'Mozilla Home', 1794700800000000, 1794700805000000, 'bm-fx-1');
             INSERT INTO moz_anno_attributes VALUES (1, 'downloads/destinationFileURI');
             INSERT INTO moz_anno_attributes VALUES (2, 'downloads/metaData');
             INSERT INTO moz_annos VALUES (1, 3, 1, 'file:///tmp/fx.tar.xz', 1794700800000000);
             INSERT INTO moz_annos VALUES (2, 3, 2, '{\"state\":1,\"endTime\":1794700810000,\"fileSize\":8192,\"contentType\":\"application/x-xz\"}', 1794700800000);",
        )
        .unwrap();

    // cookies.sqlite seeded with a SECRET cookie value that MUST NOT appear in output (R4!)
    let fxc = Connection::open(fx_prof.join("cookies.sqlite")).unwrap();
    fxc.execute_batch(
        "CREATE TABLE moz_cookies(id INTEGER PRIMARY KEY, name TEXT, value TEXT, host TEXT, path TEXT, expiry INTEGER, lastAccessed INTEGER, creationTime INTEGER, isSecure INTEGER, isHttpOnly INTEGER, sameSite INTEGER);
         INSERT INTO moz_cookies VALUES (1, 'sessionid', 'SECRET_COOKIE_VALUE_MUST_NOT_LEAK', '.example.org', '/', 1800000000, 1794700800000000, 1794700000000000, 1, 1, 2);",
    )
    .unwrap();

    let fxf = Connection::open(fx_prof.join("formhistory.sqlite")).unwrap();
    fxf.execute_batch(
        "CREATE TABLE moz_formhistory(id INTEGER PRIMARY KEY, fieldname TEXT, value TEXT, timesUsed INTEGER, firstUsed INTEGER, lastUsed INTEGER, guid TEXT);
         INSERT INTO moz_formhistory VALUES (1, 'searchbar-history', 'rust forensics', 3, 1794700000000000, 1794700800000000, 'fh-1');",
    )
    .unwrap();

    std::fs::write(
        fx_prof.join("extensions.json"),
        r#"{"addons":[{"id":"temp@example.org","version":"0.1","type":"extension","active":true,"location":"app-temporary","installDate":1794700800000,"signedState":0,"defaultLocale":{"name":"Temp FX Addon"},"userPermissions":{"permissions":["cookies"],"origins":["<all_urls>"]}}]}"#,
    )
    .unwrap();

    let sess_json = br#"{"windows":[{"tabs":[{"index":1,"pinned":true,"lastAccessed":1794700800000,"entries":[{"url":"https://www.youtube.com/results?search_query=rust+2024","title":"YouTube"}]}],"_closedTabs":[{"closedAt":1794700700000,"state":{"index":1,"entries":[{"url":"https://closed.example.org","title":"Closed Tab"}]}}]}]}"#;
    std::fs::write(
        fx_prof.join("sessionstore.jsonlz4"),
        compress_mozlz4_literals(sess_json),
    )
    .unwrap();

    // ---------------------------------------------------------------------
    // 3. Opera Presto (dcache4.url, global_history.dat, opera6.adr)
    // ---------------------------------------------------------------------
    let op_prof = root.join("OperaPresto");
    std::fs::create_dir_all(&op_prof).unwrap();
    std::fs::write(op_prof.join("opr00001.tmp"), b"<html>Presto</html>").unwrap();
    let dc = build_synthetic_presto_dcache4(&[(
        "https://yandex.ru/search/?text=opera+presto",
        1_794_700_800,
        19,
        "opr00001.tmp",
        "text/html",
    )]);
    std::fs::write(op_prof.join("dcache4.url"), dc).unwrap();
    std::fs::write(
        op_prof.join("global_history.dat"),
        "Presto Page\nhttps://www.baidu.com/s?wd=presto+history\n1794700800\n5\n",
    )
    .unwrap();
    std::fs::write(
        op_prof.join("opera6.adr"),
        "Opera Hotlist version 2.0\n\n#FOLDER\n\tNAME=Opera Folder\n\n#URL\n\tNAME=Opera BM\n\tURL=https://opera.com/\n\tCREATED=1794700800\n\tUNIQUEID=OP-1\n\n-\n",
    )
    .unwrap();

    // ---------------------------------------------------------------------
    // 4. Safari (Cache.db, History.db, Bookmarks.plist, Downloads.plist)
    // ---------------------------------------------------------------------
    let sf_prof = root.join("SafariData");
    let sf_fs = sf_prof.join("fsCachedData");
    std::fs::create_dir_all(&sf_fs).unwrap();
    std::fs::write(sf_fs.join("SF-UUID-1"), b"<html>Safari Cache</html>").unwrap();

    let mut sf_hdrs = BTreeMap::new();
    sf_hdrs.insert("Content-Type".into(), PlistValue::String("text/html".into()));
    let mut sf_resp = BTreeMap::new();
    sf_resp.insert("statusCode".into(), PlistValue::Integer(200));
    sf_resp.insert("allHeaderFields".into(), PlistValue::Dict(sf_hdrs));
    let sf_blob = encode_bplist00(&PlistValue::Dict(sf_resp));

    let sf_cdb = Connection::open(sf_prof.join("Cache.db")).unwrap();
    sf_cdb
        .execute_batch(
            "CREATE TABLE cfurl_cache_response(entry_ID INTEGER PRIMARY KEY, request_key TEXT, time_stamp REAL, storage_policy INTEGER);
             CREATE TABLE cfurl_cache_blob_data(entry_ID INTEGER PRIMARY KEY, response_object BLOB);
             CREATE TABLE cfurl_cache_receiver_data(entry_ID INTEGER PRIMARY KEY, isDataOnFS INTEGER, receiver_data BLOB);",
        )
        .unwrap();
    sf_cdb
        .execute(
            "INSERT INTO cfurl_cache_response VALUES (1, 'https://www.google.com/#q=safari+fragment', 816393600.0, 0)",
            [],
        )
        .unwrap();
    sf_cdb
        .execute("INSERT INTO cfurl_cache_blob_data VALUES (1, ?1)", [&sf_blob])
        .unwrap();
    sf_cdb
        .execute(
            "INSERT INTO cfurl_cache_receiver_data VALUES (1, 1, ?1)",
            [b"SF-UUID-1".as_slice()],
        )
        .unwrap();

    let sf_hdb = Connection::open(sf_prof.join("History.db")).unwrap();
    sf_hdb
        .execute_batch(
            "CREATE TABLE history_items(id INTEGER PRIMARY KEY, url TEXT, visit_count INTEGER);
             CREATE TABLE history_visits(id INTEGER PRIMARY KEY, history_item INTEGER, title TEXT, visit_time REAL, origin INTEGER);
             INSERT INTO history_items VALUES (1, 'https://search.brave.com/search?q=safari+history', 2);
             INSERT INTO history_visits VALUES (1, 1, 'Brave Search', 816393600.0, 0);",
        )
        .unwrap();

    let mut uri_dict = BTreeMap::new();
    uri_dict.insert("title".into(), PlistValue::String("Apple".into()));
    let mut leaf = BTreeMap::new();
    leaf.insert(
        "WebBookmarkType".into(),
        PlistValue::String("WebBookmarkTypeLeaf".into()),
    );
    leaf.insert("URLString".into(), PlistValue::String("https://apple.com/".into()));
    leaf.insert("URIDictionary".into(), PlistValue::Dict(uri_dict));
    leaf.insert("WebBookmarkUUID".into(), PlistValue::String("SF-BM-1".into()));
    let mut bar = BTreeMap::new();
    bar.insert(
        "WebBookmarkType".into(),
        PlistValue::String("WebBookmarkTypeList".into()),
    );
    bar.insert("Title".into(), PlistValue::String("BookmarksBar".into()));
    bar.insert("Children".into(), PlistValue::Array(vec![PlistValue::Dict(leaf)]));
    let mut bm_root = BTreeMap::new();
    bm_root.insert(
        "WebBookmarkType".into(),
        PlistValue::String("WebBookmarkTypeList".into()),
    );
    bm_root.insert("Children".into(), PlistValue::Array(vec![PlistValue::Dict(bar)]));
    std::fs::write(
        sf_prof.join("Bookmarks.plist"),
        encode_bplist00(&PlistValue::Dict(bm_root)),
    )
    .unwrap();

    dir
}

#[test]
fn test_all_21_table_providers_r4_compliance_and_exports() {
    let fixture = build_multi_browser_fixture();
    let root = fixture.path();

    let providers = build_browser_tool_providers(Some(root));
    assert_eq!(providers.len(), 21);

    for p in &providers {
        assert!(p.is_read_only(), "Provider {} must be read-only", p.tool_id());
        let data = p.query(&TableQuery::default()).unwrap();
        assert!(
            data.total_rows >= 1,
            "Expected >= 1 row for {}, got {}",
            p.tool_id(),
            data.total_rows
        );
    }

    // R4 Check 1: fx cookies MUST omit `value` completely
    let fx_cookies = build_browser_tool_provider_by_id("chrome2rust_fx_cookies", Some(root)).unwrap();
    let cookies_data = fx_cookies.query(&TableQuery::default()).unwrap();
    assert!(!cookies_data.schema.columns.iter().any(|c| c.id == "value"));
    let cookies_json =
        String::from_utf8(export_table(&cookies_data, ExportFormat::Json, &ExportOptions::default()).unwrap()).unwrap();
    assert!(!cookies_json.contains("SECRET_COOKIE_VALUE_MUST_NOT_LEAK"));
    assert!(cookies_json.contains("sessionid"));

    // R4 Check 2: unified autofill MUST NEVER query credit_cards / masked_credit_cards / local_ibans
    let unified_autofill = build_browser_tool_provider_by_id("chrome2rust_unified_autofill", Some(root)).unwrap();
    let autofill_data = unified_autofill.query(&TableQuery::default()).unwrap();
    assert_eq!(autofill_data.total_rows, 2); // Chrome autofill + Firefox formhistory
    let autofill_json =
        String::from_utf8(export_table(&autofill_data, ExportFormat::Json, &ExportOptions::default()).unwrap())
            .unwrap();
    assert!(autofill_json.contains("alice@example.org"));
    assert!(autofill_json.contains("rust forensics"));
    assert!(!autofill_json.contains("SECRET_CARDHOLDER_R4"));
    assert!(!autofill_json.contains("SECRET_MASKED_R4"));
    assert!(!autofill_json.contains("SECRET_IBAN_R4"));
    assert!(!autofill_json.contains("4242"));
    assert!(!autofill_json.contains("DE89"));

    // Direct parse_autofill_only R4 check
    let mut warn = Vec::new();
    let only_af = parse_autofill_only(&root.join("ChromeUserData").join("Default"), &mut warn);
    assert_eq!(only_af.len(), 1);
    assert_eq!(only_af[0].value, "alice@example.org");

    // Check unified history spans all 4 browser families
    let unified_hist = build_browser_tool_provider_by_id("chrome2rust_unified_history", Some(root)).unwrap();
    let hist_data = unified_hist.query(&TableQuery::default()).unwrap();
    assert!(hist_data.total_rows >= 5);
    let q = GuapQuery {
        filter_expr: Some("browser = 'Mozilla Firefox'".to_string()),
        ..Default::default()
    };
    let fx_only = q.execute_provider(unified_hist.as_ref()).unwrap();
    assert_eq!(fx_only.total_rows, 2);

    // Check unified addons risk flags across Chrome + Firefox
    let unified_addons = build_browser_tool_provider_by_id("chrome2rust_unified_addons", Some(root)).unwrap();
    let addons_data = unified_addons.query(&TableQuery::default()).unwrap();
    assert_eq!(addons_data.total_rows, 2);

    // Check unified bookmarks across Chrome, Firefox, Opera Presto, Safari
    let unified_bm = build_browser_tool_provider_by_id("chrome2rust_unified_bookmarks", Some(root)).unwrap();
    let bm_data = unified_bm.query(&TableQuery::default()).unwrap();
    assert_eq!(bm_data.total_rows, 4);

    // Check search-queries extracts across Google, Bing Referer, DDG, Yahoo, YouTube, Yandex, Baidu, Safari #q=
    let sq = build_browser_tool_provider_by_id("chrome2rust_search_queries", Some(root)).unwrap();
    let sq_data = sq.query(&TableQuery::default()).unwrap();
    let sq_json =
        String::from_utf8(export_table(&sq_data, ExportFormat::Json, &ExportOptions::default()).unwrap()).unwrap();
    for expected in [
        "rust exif parser",
        "chrome2rust referer query",
        "mozilla forensics",
        "fx query",
        "rust 2024",
        "opera presto",
        "presto history",
        "safari fragment",
        "safari history",
    ] {
        assert!(sq_json.contains(expected), "Missing search query '{expected}'");
    }

    // Check all 7 guap-export formats + SHA-256/512 CustodyManifest
    for fmt in [
        ExportFormat::Csv,
        ExportFormat::Tsv,
        ExportFormat::Json,
        ExportFormat::Jsonl,
        ExportFormat::Html,
        ExportFormat::HtmlVertical,
        ExportFormat::Markdown,
    ] {
        let out_bytes = export_table(&bm_data, fmt, &ExportOptions::default()).unwrap();
        assert!(!out_bytes.is_empty());
    }
    let exp_file = root.join("exports").join("bookmarks.csv");
    let manifest = write_table_export(&bm_data, &exp_file, ExportFormat::Csv, &ExportOptions::default()).unwrap();
    assert_eq!(manifest.merkle_root_sha256.len(), 64);
    assert_eq!(manifest.merkle_root_sha512.len(), 128);
    assert!(exp_file.is_file());

    // Check Firefox bookmarkbackups/*.jsonlz4 standalone fallback
    let bm_backup_dir = TempDir::new().unwrap();
    let backup_json = br#"{"title":"","children":[{"title":"Backup Folder","typeCode":2,"children":[{"title":"Backed Up","uri":"https://backup.mozilla.org/","typeCode":1,"guid":"bk-1"}]}]}"#;
    let bk_file = bm_backup_dir.path().join("bookmarks-2026.jsonlz4");
    std::fs::write(&bk_file, compress_mozlz4_literals(backup_json)).unwrap();
    let mut bk_warn = Vec::new();
    let bk_recs = parse_firefox_jsonlz4_bookmarks(&bk_file, &mut bk_warn);
    assert_eq!(bk_recs.len(), 1);
    assert_eq!(bk_recs[0].folder_path, "Backup Folder");
    assert_eq!(bk_recs[0].url, "https://backup.mozilla.org/");

    // Check fx sessions open + closed tabs
    let fx_sess = build_browser_tool_provider_by_id("chrome2rust_fx_sessions", Some(root)).unwrap();
    let sess_data = fx_sess.query(&TableQuery::default()).unwrap();
    assert_eq!(sess_data.total_rows, 2);
    assert!(sess_data.rows.iter().any(|r| r.cells[6] == CellValue::Bool(true)));
}
