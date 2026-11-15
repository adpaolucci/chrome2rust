use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::Read;
use std::path::Path;
use walkdir::WalkDir;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactDigestRecord {
    pub relative_path: String,
    pub size_bytes: u64,
    pub sha256: String,
    pub category: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustodyManifest {
    pub generated_at: DateTime<Utc>,
    pub tool_version: String,
    pub target_path: String,
    pub artifact_count: usize,
    pub total_bytes: u64,
    pub merkle_root_sha256: String,
    pub artifacts: Vec<ArtifactDigestRecord>,
}

fn classify_artifact(rel: &str) -> String {
    let lower = rel.to_ascii_lowercase();
    if lower.contains("cache_data") || lower.contains("code cache") || lower.contains("gpucache") {
        "Cache".to_string()
    } else if lower.ends_with("history") || lower.ends_with("favicons") || lower.ends_with("top sites") {
        "BrowsingHistory".to_string()
    } else if lower.ends_with("cookies") || lower.ends_with("login data") || lower.ends_with("login data for account") {
        "CredentialsCookies".to_string()
    } else if lower.ends_with("web data") || lower.ends_with("local state") || lower.ends_with("preferences") {
        "ProfileWebData".to_string()
    } else if lower.contains("sessions") {
        "SessionData".to_string()
    } else if lower.contains("local storage") || lower.contains("session storage") || lower.contains("indexeddb") {
        "SiteStorage".to_string()
    } else if lower.contains("extensions") {
        "Extensions".to_string()
    } else {
        "Other".to_string()
    }
}

fn sha256_file(path: &Path) -> Result<(String, u64), std::io::Error> {
    let mut f = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    let mut total = 0u64;
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        total += n as u64;
    }
    Ok((format!("{:x}", hasher.finalize()), total))
}

/// Computes a balanced binary SHA-256 Merkle root over ordered artifact leaf hashes (RFC 6234).
pub fn compute_merkle_root(hex_hashes: &[String]) -> String {
    if hex_hashes.is_empty() {
        return format!("{:x}", Sha256::digest(b""));
    }
    let mut layer: Vec<Vec<u8>> = hex_hashes
        .iter()
        .map(|h| Sha256::digest(h.as_bytes()).to_vec())
        .collect();
    while layer.len() > 1 {
        let mut next = Vec::with_capacity(layer.len().div_ceil(2));
        for pair in layer.chunks(2) {
            let mut h = Sha256::new();
            h.update(&pair[0]);
            if pair.len() == 2 {
                h.update(&pair[1]);
            } else {
                h.update(&pair[0]);
            }
            next.push(h.finalize().to_vec());
        }
        layer = next;
    }
    let mut out = String::with_capacity(64);
    for b in &layer[0] {
        use std::fmt::Write;
        let _ = write!(out, "{b:02x}");
    }
    out
}

/// Generates a deterministic read-only SHA-256 chain-of-custody manifest over files in `target_dir`.
pub fn generate_custody_manifest(target: &Path) -> std::io::Result<CustodyManifest> {
    let mut files = Vec::new();
    if target.is_file() {
        files.push(target.to_path_buf());
    } else if target.is_dir() {
        for entry in WalkDir::new(target).follow_links(false).into_iter().flatten() {
            if entry.file_type().is_file() {
                files.push(entry.into_path());
            }
        }
    }
    files.sort();

    let mut artifacts = Vec::new();
    let mut total_bytes = 0u64;
    let mut hashes = Vec::new();

    for f in files {
        let rel = if target.is_dir() {
            f.strip_prefix(target)
                .map(|p| p.to_string_lossy().replace('\\', "/"))
                .unwrap_or_else(|_| f.display().to_string())
        } else {
            f.file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_else(|| f.display().to_string())
        };
        if let Ok((sha, sz)) = sha256_file(&f) {
            total_bytes += sz;
            hashes.push(format!("{rel}:{sha}"));
            artifacts.push(ArtifactDigestRecord {
                category: classify_artifact(&rel),
                relative_path: rel,
                size_bytes: sz,
                sha256: sha,
            });
        }
    }

    Ok(CustodyManifest {
        generated_at: Utc::now(),
        tool_version: env!("CARGO_PKG_VERSION").to_string(),
        target_path: target.display().to_string(),
        artifact_count: artifacts.len(),
        total_bytes,
        merkle_root_sha256: compute_merkle_root(&hashes),
        artifacts,
    })
}

pub fn write_custody_manifest(manifest: &CustodyManifest, dest: &Path) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(parent) = dest.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent)?;
    }
    let ext = dest
        .extension()
        .map(|s| s.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default();
    if ext == "csv" {
        let mut wtr = csv::Writer::from_path(dest)?;
        wtr.write_record(["Category", "Relative_Path", "Size_Bytes", "SHA256", "Merkle_Root"])?;
        for a in &manifest.artifacts {
            wtr.write_record([
                &a.category,
                &a.relative_path,
                &a.size_bytes.to_string(),
                &a.sha256,
                &manifest.merkle_root_sha256,
            ])?;
        }
        wtr.flush()?;
    } else {
        std::fs::write(dest, serde_json::to_string_pretty(manifest)?)?;
    }
    Ok(())
}
