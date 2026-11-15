use crc32fast::Hasher;
use flate2::Compression;
use flate2::write::GzEncoder;
use rusqlite::Connection;
use sha2::{Digest, Sha256};
use std::io::Write;
use std::process::Command;
use tempfile::TempDir;

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_chrome2rust"))
}

fn write_simple_entry(path: &std::path::Path, key: &str, headers_nul: &str, payload: &[u8], ip: &str, port: u32) {
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
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
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

fn make_cli_sample_user_data() -> TempDir {
    let dir = TempDir::new().unwrap();
    let root = dir.path();
    std::fs::write(root.join("Last Version"), "156.0.8078.79\n").unwrap();
    std::fs::write(
        root.join("Local State"),
        r#"{"profile":{"info_cache":{"Default":{"name":"CLI Profile"}}}}"#,
    )
    .unwrap();

    let def = root.join("Default");
    let cache_dir = def.join("Cache").join("Cache_Data");
    std::fs::create_dir_all(&cache_dir).unwrap();

    let conn = Connection::open(def.join("History")).unwrap();
    conn.execute_batch(
        "CREATE TABLE urls(id INTEGER PRIMARY KEY AUTOINCREMENT, url TEXT, title TEXT, visit_count INTEGER, typed_count INTEGER, last_visit_time INTEGER, hidden INTEGER);
         CREATE TABLE visits(id INTEGER PRIMARY KEY AUTOINCREMENT, url INTEGER, visit_time INTEGER, from_visit INTEGER, transition INTEGER, visit_duration INTEGER);
         INSERT INTO urls VALUES (1, 'https://example.test/', 'CLI Title', 3, 1, 13439176738739516, 0);
         INSERT INTO visits VALUES (1, 1, 13439176738739516, 0, 1, 1000000);",
    )
    .unwrap();

    let mut gz = GzEncoder::new(Vec::new(), Compression::default());
    gz.write_all(br#"{"ok":true,"tool":"chrome2rust"}"#).unwrap();
    let gz_bytes = gz.finish().unwrap();

    write_simple_entry(
        &cache_dir.join("aaaabbbbccccdddd_0"),
        "1/0/_dk_https://api.example.test https://api.example.test https://api.example.test/v1/status",
        "HTTP/1.1 200 OK\0Content-Type: application/json\0Content-Encoding: gzip\0Server: caddy\0\0",
        &gz_bytes,
        "203.0.113.10",
        443,
    );

    write_simple_entry(
        &cache_dir.join("eeeeffff00001111_0"),
        "1/0/_dk_https://static.example.test https://static.example.test https://static.example.test/empty.txt",
        "HTTP/1.1 204 No Content\0\0",
        b"",
        "203.0.113.11",
        443,
    );

    dir
}

#[test]
fn test_cli_help_profiles_sniff_and_mcp() {
    let short_help = bin().arg("-h").output().unwrap();
    assert!(short_help.status.success());
    let short_txt = String::from_utf8_lossy(&short_help.stdout);
    assert!(short_txt.contains("pure Rust"));
    assert!(short_txt.contains("Chrome HTTP cache inspector"));

    let help = bin().arg("--help").output().unwrap();
    assert!(help.status.success());
    let stdout = String::from_utf8_lossy(&help.stdout);
    assert!(stdout.contains("Simple Cache & Blockfile"));
    assert!(stdout.contains("profiles"));
    assert!(stdout.contains("sniff"));
    assert!(stdout.contains("cache"));
    assert!(stdout.contains("analyze"));
    assert!(stdout.contains("report"));
    assert!(stdout.contains("custody"));
    assert!(stdout.contains("mcp"));

    let profs = bin().args(["profiles", "--json"]).output().unwrap();
    assert!(profs.status.success());
    let parsed: serde_json::Value = serde_json::from_slice(&profs.stdout).unwrap();
    assert!(parsed.is_array());

    let mcp_tools = bin().args(["mcp", "--tools"]).output().unwrap();
    assert!(mcp_tools.status.success());
    let tools_json: serde_json::Value = serde_json::from_slice(&mcp_tools.stdout).unwrap();
    assert!(tools_json.as_array().unwrap().len() >= 8);
}

#[test]
fn test_cli_cache_analyze_report_sniff_and_custody() {
    let sample = make_cli_sample_user_data();
    let ud = sample.path();

    // 1. sniff directory and file
    let sn_dir = bin().args(["sniff", "--json"]).arg(ud).output().unwrap();
    assert!(sn_dir.status.success());
    let sn_dir_json: serde_json::Value = serde_json::from_slice(&sn_dir.stdout).unwrap();
    assert_eq!(sn_dir_json["artifact_format"], "UserDataRoot");

    let entry_file = ud
        .join("Default")
        .join("Cache")
        .join("Cache_Data")
        .join("aaaabbbbccccdddd_0");
    let sn_file = bin().args(["sniff", "--json"]).arg(&entry_file).output().unwrap();
    assert!(sn_file.status.success());
    let sn_file_json: serde_json::Value = serde_json::from_slice(&sn_file.stdout).unwrap();
    assert_eq!(sn_file_json["artifact_format"], "SimpleCacheEntryFile");

    // 2. cache list JSON with --hashes
    let list = bin()
        .args(["cache", "list"])
        .arg(ud)
        .args([
            "--format",
            "json",
            "--hashes",
            "--columns",
            "url,content-type,size,sha256",
        ])
        .output()
        .unwrap();
    assert!(
        list.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&list.stderr)
    );
    let arr: serde_json::Value = serde_json::from_slice(&list.stdout).unwrap();
    assert_eq!(arr.as_array().unwrap().len(), 2);

    // 3. cache list CSV filtering --no-zero-length --content-type json
    let csv_out = bin()
        .args(["cache", "list"])
        .arg(ud)
        .args(["--no-zero-length", "--content-type", "json", "-f", "csv"])
        .output()
        .unwrap();
    assert!(csv_out.status.success());
    let csv_txt = String::from_utf8_lossy(&csv_out.stdout);
    assert!(csv_txt.contains("api.example.test/v1/status"));
    assert!(!csv_txt.contains("empty.txt"));

    // 4. cache inspect --preview --dump-body
    let body_out = TempDir::new().unwrap();
    let dump_file = body_out.path().join("status.json");
    let insp = bin()
        .args(["cache", "inspect"])
        .arg(&entry_file)
        .args(["--preview", "--dump-body"])
        .arg(&dump_file)
        .output()
        .unwrap();
    assert!(insp.status.success());
    assert!(String::from_utf8_lossy(&insp.stdout).contains(r#""tool":"chrome2rust""#));
    assert_eq!(
        std::fs::read_to_string(&dump_file).unwrap(),
        r#"{"ok":true,"tool":"chrome2rust"}"#
    );

    // 5. cache extract --website-dirs
    let ext_out = TempDir::new().unwrap();
    let ext = bin()
        .args(["cache", "extract"])
        .arg(ud)
        .args(["-o"])
        .arg(ext_out.path())
        .args(["--website-dirs", "--no-zero-length"])
        .output()
        .unwrap();
    assert!(ext.status.success());
    let expected = ext_out.path().join("api.example.test").join("v1").join("status.json");
    assert!(expected.is_file());

    // 6. analyze --json --audit-manifest
    let custody_dir = TempDir::new().unwrap();
    let audit_csv = custody_dir.path().join("custody.csv");
    let an = bin()
        .args(["--audit-manifest"])
        .arg(&audit_csv)
        .args(["analyze"])
        .arg(ud)
        .args(["--json", "--hashes"])
        .output()
        .unwrap();
    assert!(an.status.success());
    let rep: serde_json::Value = serde_json::from_slice(&an.stdout).unwrap();
    assert_eq!(rep["summary"]["total_cache_entries"], 2);
    assert_eq!(rep["summary"]["total_history_urls"], 1);
    assert!(audit_csv.is_file());
    assert!(std::fs::read_to_string(&audit_csv).unwrap().contains("Merkle_Root"));

    // 7. custody subcommand --json
    let cust_json = custody_dir.path().join("custody.json");
    let cust = bin()
        .args(["custody", "--json", "-o"])
        .arg(&cust_json)
        .arg(ud)
        .output()
        .unwrap();
    assert!(cust.status.success());
    let cust_val: serde_json::Value = serde_json::from_slice(&cust.stdout).unwrap();
    assert_eq!(cust_val["merkle_root_sha256"].as_str().unwrap().len(), 64);
    assert!(cust_json.is_file());

    // 8. report -f all
    let rep_out = TempDir::new().unwrap();
    let rep_cmd = bin()
        .args(["report"])
        .arg(ud)
        .args(["-f", "all", "-o"])
        .arg(rep_out.path())
        .output()
        .unwrap();
    assert!(rep_cmd.status.success());
    assert!(rep_out.path().join("forensic_report.html").is_file());
    assert!(rep_out.path().join("forensic_report.json").is_file());
    assert!(rep_out.path().join("forensic_report.md").is_file());

    // 9. cache delete dry-run vs --yes
    let dry = bin()
        .args(["cache", "delete"])
        .arg(ud)
        .args(["--url", "empty.txt"])
        .output()
        .unwrap();
    assert!(dry.status.success());
    assert!(String::from_utf8_lossy(&dry.stdout).contains("Dry run"));
    assert!(ud.join("Default/Cache/Cache_Data/eeeeffff00001111_0").exists());

    let real_del = bin()
        .args(["cache", "delete"])
        .arg(ud)
        .args(["--url", "empty.txt", "--yes"])
        .output()
        .unwrap();
    assert!(real_del.status.success());
    assert!(!ud.join("Default/Cache/Cache_Data/eeeeffff00001111_0").exists());
}

#[test]
fn test_cli_sniff_and_extract_missing_or_mismatched_extensions() {
    let work = TempDir::new().unwrap();

    // 1. Sniff extensionless WebP payload
    let webp_file = work.path().join("payload_blob");
    std::fs::write(&webp_file, b"RIFF\x20\x00\x00\x00WEBPVP8 \x14\x00\x00\x00DATA").unwrap();
    let sn_webp = bin().args(["sniff", "--json"]).arg(&webp_file).output().unwrap();
    assert!(sn_webp.status.success());
    let sn_webp_json: serde_json::Value = serde_json::from_slice(&sn_webp.stdout).unwrap();
    assert_eq!(sn_webp_json["artifact_format"], "CachedPayloadFile");
    assert_eq!(sn_webp_json["detected_mime"], "image/webp");
    assert_eq!(sn_webp_json["suggested_extension"], "webp");
    assert_eq!(sn_webp_json["missing_extension"], true);
    assert_eq!(sn_webp_json["extension_mismatch"], false);
    assert_eq!(sn_webp_json["suggested_filename"], "payload_blob.webp");

    // 2. Sniff masqueraded PE executable disguised as avatar.png
    let mut pe = vec![0u8; 128];
    pe[0..2].copy_from_slice(b"MZ");
    pe[0x3c..0x40].copy_from_slice(&64u32.to_le_bytes());
    pe[64..68].copy_from_slice(b"PE\0\0");
    let fake_png = work.path().join("avatar.png");
    std::fs::write(&fake_png, &pe).unwrap();
    let sn_pe = bin().args(["sniff", "--json"]).arg(&fake_png).output().unwrap();
    assert!(sn_pe.status.success());
    let sn_pe_json: serde_json::Value = serde_json::from_slice(&sn_pe.stdout).unwrap();
    assert_eq!(sn_pe_json["current_extension"], "png");
    assert_eq!(sn_pe_json["suggested_extension"], "exe");
    assert_eq!(sn_pe_json["extension_mismatch"], true);
    assert_eq!(sn_pe_json["suggested_filename"], "avatar.exe");

    // 3. Build cache directory with challenging missing/ambiguous/spoofed extension entries
    let cache_dir = work.path().join("Cache_Data");
    std::fs::create_dir_all(&cache_dir).unwrap();

    // Server script endpoint returning PNG
    write_simple_entry(
        &cache_dir.join("0000000000000001_0"),
        "https://example.org/image.php",
        "HTTP/1.1 200 OK\0Content-Type: application/octet-stream\0\0",
        b"\x89PNG\r\n\x1a\nMOCKPNG",
        "93.184.216.34",
        443,
    );

    // Dotted versioned JS asset with missing Content-Type
    write_simple_entry(
        &cache_dir.join("0000000000000002_0"),
        "https://cdn.example.org/js/jquery-3.7.1",
        "HTTP/1.1 200 OK\0\0",
        b"'use strict';\nexport default function jq(){return 1;}",
        "93.184.216.35",
        443,
    );

    // Root hostname URL with HTML payload and no Content-Type
    write_simple_entry(
        &cache_dir.join("0000000000000003_0"),
        "https://home.example.org/",
        "HTTP/1.1 200 OK\0\0",
        b"<!DOCTYPE html><html><title>Home</title></html>",
        "93.184.216.36",
        443,
    );

    // Proxy resize endpoint with ?format=webp and WebP payload
    write_simple_entry(
        &cache_dir.join("0000000000000004_0"),
        "https://img.example.org/resize?id=9&format=webp",
        "HTTP/1.1 200 OK\0\0",
        b"RIFF\x20\x00\x00\x00WEBPVP8 \x14\x00\x00\x00WEBP",
        "93.184.216.37",
        443,
    );

    // Content-Disposition filename on generic download endpoint
    write_simple_entry(
        &cache_dir.join("0000000000000005_0"),
        "https://files.example.org/download?id=55",
        "HTTP/1.1 200 OK\0Content-Disposition: attachment; filename=\"quarterly-audit.pdf\"\0\0",
        b"%PDF-1.7\n%mock\n",
        "93.184.216.38",
        443,
    );

    // Spoofed image/png wrapping PE executable
    write_simple_entry(
        &cache_dir.join("0000000000000006_0"),
        "https://bad.example.org/icon.png",
        "HTTP/1.1 200 OK\0Content-Type: image/png\0\0",
        &pe,
        "93.184.216.39",
        443,
    );

    // Verify CSV listing includes new columns and detects mismatch
    let list_csv = bin()
        .args(["cache", "list"])
        .arg(&cache_dir)
        .args([
            "-f",
            "csv",
            "--columns",
            "url,content-type,detected-content-type,detected-extension,file-signature,mime-mismatch",
            "--sort",
            "mime-mismatch",
        ])
        .output()
        .unwrap();
    assert!(
        list_csv.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&list_csv.stderr)
    );
    let csv_txt = String::from_utf8_lossy(&list_csv.stdout);
    assert!(csv_txt.contains("Detected Type,Detected Ext,File Signature,MIME Mismatch"));
    assert!(csv_txt.contains("application/vnd.microsoft.portable-executable,exe,Windows PE32 Executable,Yes"));

    // Verify `cache inspect` surfaces detection fields
    let insp = bin()
        .args(["cache", "inspect"])
        .arg(cache_dir.join("0000000000000006_0"))
        .output()
        .unwrap();
    assert!(insp.status.success());
    let insp_txt = String::from_utf8_lossy(&insp.stdout);
    assert!(insp_txt.contains("Detected Type   : application/vnd.microsoft.portable-executable"));
    assert!(insp_txt.contains("Suggested Ext   : .exe"));
    assert!(insp_txt.contains("MIME Mismatch   : WARNING"));

    // Extract default (preserves spoofed URL extension .png, recovers missing extensions on others)
    let out_default = TempDir::new().unwrap();
    let ext1 = bin()
        .args(["cache", "extract"])
        .arg(&cache_dir)
        .args(["-o"])
        .arg(out_default.path())
        .args(["--website-dirs"])
        .output()
        .unwrap();
    assert!(ext1.status.success());
    assert!(out_default.path().join("example.org/image.php.png").is_file());
    assert!(out_default.path().join("cdn.example.org/js/jquery-3.7.1.js").is_file());
    assert!(out_default.path().join("home.example.org/index.html").is_file());
    assert!(out_default.path().join("img.example.org/resize.webp").is_file());
    assert!(
        out_default
            .path()
            .join("files.example.org/quarterly-audit.pdf")
            .is_file()
    );
    assert!(out_default.path().join("bad.example.org/icon.png").is_file());

    // Extract with --use-detected-ext (replaces spoofed .png with .exe)
    let out_forced = TempDir::new().unwrap();
    let ext2 = bin()
        .args(["cache", "extract"])
        .arg(&cache_dir)
        .args(["-o"])
        .arg(out_forced.path())
        .args(["--website-dirs", "--use-detected-ext"])
        .output()
        .unwrap();
    assert!(ext2.status.success());
    assert!(out_forced.path().join("bad.example.org/icon.exe").is_file());
    assert!(!out_forced.path().join("bad.example.org/icon.png").exists());
}
