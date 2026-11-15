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
