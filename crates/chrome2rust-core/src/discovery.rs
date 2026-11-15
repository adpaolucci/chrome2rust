use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum BrowserKind {
    Chrome,
    ChromeBeta,
    ChromeDev,
    ChromeCanary,
    Chromium,
    Edge,
    Brave,
    Opera,
    Vivaldi,
    Yandex,
    Custom,
}

impl BrowserKind {
    pub fn display_name(&self) -> &'static str {
        match self {
            BrowserKind::Chrome => "Google Chrome",
            BrowserKind::ChromeBeta => "Google Chrome Beta",
            BrowserKind::ChromeDev => "Google Chrome Dev",
            BrowserKind::ChromeCanary => "Google Chrome Canary",
            BrowserKind::Chromium => "Chromium",
            BrowserKind::Edge => "Microsoft Edge",
            BrowserKind::Brave => "Brave",
            BrowserKind::Opera => "Opera",
            BrowserKind::Vivaldi => "Vivaldi",
            BrowserKind::Yandex => "Yandex Browser",
            BrowserKind::Custom => "Custom Chromium User Data",
        }
    }

    pub fn all_known() -> &'static [BrowserKind] {
        &[
            BrowserKind::Chrome,
            BrowserKind::ChromeBeta,
            BrowserKind::ChromeDev,
            BrowserKind::ChromeCanary,
            BrowserKind::Chromium,
            BrowserKind::Edge,
            BrowserKind::Brave,
            BrowserKind::Opera,
            BrowserKind::Vivaldi,
            BrowserKind::Yandex,
        ]
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveredBrowser {
    pub browser: BrowserKind,
    pub name: String,
    pub user_data_dir: PathBuf,
    pub cache_root_dir: Option<PathBuf>,
    pub profiles: Vec<DiscoveredProfile>,
    pub last_used_profile: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveredProfile {
    pub dir_name: String,
    pub path: PathBuf,
    pub display_name: Option<String>,
    pub user_email: Option<String>,
    pub gaia_name: Option<String>,
    pub hosted_domain: Option<String>,
    pub is_ephemeral: bool,
    pub is_last_used: bool,
    pub cache_dirs: Vec<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TargetKind {
    UserDataRoot,
    ProfileDir,
    CacheDir,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolvedTarget {
    pub kind: TargetKind,
    pub input_path: PathBuf,
    pub user_data_dir: Option<PathBuf>,
    pub profile_dirs: Vec<PathBuf>,
    pub cache_dirs: Vec<PathBuf>,
    pub last_used_profile: Option<String>,
}

/// Returns candidate User Data directories for known Chromium-based browsers on the current OS.
pub fn default_browser_locations() -> Vec<(BrowserKind, PathBuf, Option<PathBuf>)> {
    let mut out = Vec::new();

    #[cfg(target_os = "linux")]
    {
        if let Some(config) = dirs::config_dir() {
            let cache = dirs::cache_dir();
            let specs: &[(BrowserKind, &str, &str)] = &[
                (BrowserKind::Chrome, "google-chrome", "google-chrome"),
                (BrowserKind::ChromeBeta, "google-chrome-beta", "google-chrome-beta"),
                (
                    BrowserKind::ChromeDev,
                    "google-chrome-unstable",
                    "google-chrome-unstable",
                ),
                (BrowserKind::Chromium, "chromium", "chromium"),
                (BrowserKind::Edge, "microsoft-edge", "microsoft-edge"),
                (
                    BrowserKind::Brave,
                    "BraveSoftware/Brave-Browser",
                    "BraveSoftware/Brave-Browser",
                ),
                (BrowserKind::Opera, "opera", "opera"),
                (BrowserKind::Vivaldi, "vivaldi", "vivaldi"),
                (BrowserKind::Yandex, "yandex-browser", "yandex-browser"),
            ];
            for (kind, cfg_rel, cache_rel) in specs {
                out.push((*kind, config.join(cfg_rel), cache.as_ref().map(|c| c.join(cache_rel))));
            }
        }
    }

    #[cfg(target_os = "macos")]
    {
        if let Some(app_support) = dirs::data_dir() {
            let caches = dirs::cache_dir();
            let specs: &[(BrowserKind, &str, &str)] = &[
                (BrowserKind::Chrome, "Google/Chrome", "Google/Chrome"),
                (BrowserKind::ChromeBeta, "Google/Chrome Beta", "Google/Chrome Beta"),
                (BrowserKind::ChromeDev, "Google/Chrome Dev", "Google/Chrome Dev"),
                (
                    BrowserKind::ChromeCanary,
                    "Google/Chrome Canary",
                    "Google/Chrome Canary",
                ),
                (BrowserKind::Chromium, "Chromium", "Chromium"),
                (BrowserKind::Edge, "Microsoft Edge", "Microsoft Edge"),
                (
                    BrowserKind::Brave,
                    "BraveSoftware/Brave-Browser",
                    "BraveSoftware/Brave-Browser",
                ),
                (BrowserKind::Opera, "com.operasoftware.Opera", "com.operasoftware.Opera"),
                (BrowserKind::Vivaldi, "Vivaldi", "Vivaldi"),
                (BrowserKind::Yandex, "Yandex/YandexBrowser", "Yandex/YandexBrowser"),
            ];
            for (kind, rel, cache_rel) in specs {
                out.push((*kind, app_support.join(rel), caches.as_ref().map(|c| c.join(cache_rel))));
            }
        }
    }

    #[cfg(target_os = "windows")]
    {
        if let Some(local_app) = dirs::data_local_dir() {
            let roaming = dirs::data_dir();
            let specs: &[(BrowserKind, &str)] = &[
                (BrowserKind::Chrome, "Google\\Chrome\\User Data"),
                (BrowserKind::ChromeBeta, "Google\\Chrome Beta\\User Data"),
                (BrowserKind::ChromeDev, "Google\\Chrome Dev\\User Data"),
                (BrowserKind::ChromeCanary, "Google\\Chrome SxS\\User Data"),
                (BrowserKind::Chromium, "Chromium\\User Data"),
                (BrowserKind::Edge, "Microsoft\\Edge\\User Data"),
                (BrowserKind::Brave, "BraveSoftware\\Brave-Browser\\User Data"),
                (BrowserKind::Vivaldi, "Vivaldi\\User Data"),
                (BrowserKind::Yandex, "Yandex\\YandexBrowser\\User Data"),
            ];
            for (kind, rel) in specs {
                let p = local_app.join(rel);
                out.push((*kind, p, None));
            }
            if let Some(roam) = roaming {
                out.push((
                    BrowserKind::Opera,
                    roam.join("Opera Software\\Opera Stable"),
                    Some(local_app.join("Opera Software\\Opera Stable")),
                ));
            }
        }
    }

    out
}

/// Discovers all installed Chromium-family browsers on this machine whose User Data or Cache directories exist.
pub fn discover_local_browsers() -> Vec<DiscoveredBrowser> {
    let mut found = Vec::new();
    for (kind, user_data_dir, cache_root_dir) in default_browser_locations() {
        let ud_exists = user_data_dir.is_dir();
        let cache_exists = cache_root_dir.as_ref().is_some_and(|p| p.is_dir());
        if !ud_exists && !cache_exists {
            continue;
        }
        let (profiles, last_used) = if ud_exists {
            discover_profiles_in_user_data(&user_data_dir, cache_root_dir.as_deref())
        } else {
            (Vec::new(), None)
        };
        found.push(DiscoveredBrowser {
            browser: kind,
            name: kind.display_name().to_string(),
            user_data_dir,
            cache_root_dir,
            profiles,
            last_used_profile: last_used,
        });
    }
    found
}

/// Discovers profile folders within a Chrome `User Data` directory.
pub fn discover_profiles_in_user_data(
    user_data_dir: &Path,
    linux_cache_root: Option<&Path>,
) -> (Vec<DiscoveredProfile>, Option<String>) {
    let local_state_path = user_data_dir.join("Local State");
    let mut last_used: Option<String> = None;
    let mut info_cache: HashMap<String, serde_json::Value> = HashMap::new();

    if let Ok(text) = std::fs::read_to_string(&local_state_path)
        && let Ok(val) = serde_json::from_str::<serde_json::Value>(&text)
        && let Some(profile_obj) = val.get("profile")
    {
        if let Some(arr) = profile_obj.get("last_active_profiles").and_then(|v| v.as_array())
            && let Some(first) = arr.first().and_then(|v| v.as_str())
        {
            last_used = Some(first.to_string());
        }
        if last_used.is_none()
            && let Some(lu) = profile_obj.get("last_used").and_then(|v| v.as_str())
        {
            last_used = Some(lu.to_string());
        }
        if let Some(ic) = profile_obj.get("info_cache").and_then(|v| v.as_object()) {
            for (k, v) in ic {
                info_cache.insert(k.clone(), v.clone());
            }
        }
    }

    let mut profiles = Vec::new();
    if let Ok(entries) = std::fs::read_dir(user_data_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }
            let dir_name = entry.file_name().to_string_lossy().to_string();
            if !looks_like_profile_dir(&path, &dir_name) {
                continue;
            }
            let meta = info_cache.get(&dir_name);
            let display_name = meta
                .and_then(|m| m.get("name"))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            let user_email = meta
                .and_then(|m| m.get("user_name"))
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string());
            let gaia_name = meta
                .and_then(|m| m.get("gaia_name"))
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string());
            let hosted_domain = meta
                .and_then(|m| m.get("hosted_domain"))
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string());
            let is_ephemeral = meta
                .and_then(|m| m.get("is_ephemeral"))
                .and_then(|v| v.as_bool())
                .unwrap_or(false);

            let mut cache_dirs = find_cache_dirs_in_profile(&path);
            if let Some(cache_root) = linux_cache_root {
                let alt_profile = cache_root.join(&dir_name);
                if alt_profile.is_dir() {
                    for c in find_cache_dirs_in_profile(&alt_profile) {
                        if !cache_dirs.contains(&c) {
                            cache_dirs.push(c);
                        }
                    }
                }
            }

            let is_last_used = last_used.as_deref() == Some(dir_name.as_str());
            profiles.push(DiscoveredProfile {
                dir_name,
                path,
                display_name,
                user_email,
                gaia_name,
                hosted_domain,
                is_ephemeral,
                is_last_used,
                cache_dirs,
            });
        }
    }

    // Fallback: if Local State didn't declare last_used, pick newest Preferences/History mtime
    if last_used.is_none() && !profiles.is_empty() {
        let mut newest: Option<(std::time::SystemTime, usize)> = None;
        for (idx, p) in profiles.iter().enumerate() {
            for probe in ["History", "Preferences", "Cookies"] {
                if let Ok(md) = std::fs::metadata(p.path.join(probe))
                    && let Ok(mtime) = md.modified()
                    && newest.is_none_or(|(best, _)| mtime > best)
                {
                    newest = Some((mtime, idx));
                }
            }
        }
        if let Some((_, idx)) = newest {
            profiles[idx].is_last_used = true;
            last_used = Some(profiles[idx].dir_name.clone());
        }
    }

    profiles.sort_by(|a, b| {
        b.is_last_used
            .cmp(&a.is_last_used)
            .then_with(|| a.dir_name.cmp(&b.dir_name))
    });

    (profiles, last_used)
}

fn has_non_cache_profile_artifacts(path: &Path) -> bool {
    const PROFILE_FILES: &[&str] = &[
        "History",
        "Preferences",
        "Secure Preferences",
        "Bookmarks",
        "Cookies",
        "Web Data",
        "Login Data",
        "Login Data For Account",
        "Top Sites",
        "Shortcuts",
        "Favicons",
        "Visited Links",
        "Current Session",
        "Current Tabs",
        "Extension Cookies",
    ];
    if PROFILE_FILES.iter().any(|f| path.join(f).is_file()) {
        return true;
    }
    path.join("Network").join("Cookies").is_file()
        || path.join("Sessions").is_dir()
        || path.join("Local Storage").join("leveldb").is_dir()
        || path.join("Session Storage").is_dir()
        || path.join("IndexedDB").is_dir()
}

pub fn has_profile_artifacts(path: &Path) -> bool {
    has_non_cache_profile_artifacts(path) || !find_cache_dirs_in_profile(path).is_empty()
}

pub fn looks_like_profile_dir(path: &Path, dir_name: &str) -> bool {
    const EXCLUDED_SUBDIRS: &[&str] = &[
        "ShaderCache",
        "GrShaderCache",
        "GraphiteDawnCache",
        "Crashpad",
        "BrowserMetrics",
        "Safe Browsing",
        "Subresource Filter",
        "CertificateRevocation",
        "Crowd Deny",
        "FileTypePolicies",
        "MEIPreload",
        "OriginTrials",
        "PKIMetadata",
        "pnacl",
        "RecoveryImproved",
        "SSLErrorAssistant",
        "TLSDeprecationConfig",
        "TrustTokenKeyCommitments",
        "WasmTtsEngine",
        "WidevineCdm",
        "ZxcvbnData",
        "Cache",
        "Cache_Data",
        "Code Cache",
        "GPUCache",
        "DawnCache",
        "Media Cache",
        "System Cache",
        "Service Worker",
        "Network",
        "Sessions",
        "Local Storage",
        "Session Storage",
        "IndexedDB",
        "Extensions",
        "Storage",
        "blob_storage",
        "databases",
    ];
    if EXCLUDED_SUBDIRS.contains(&dir_name) {
        return false;
    }
    if (dir_name == "Default"
        || dir_name.starts_with("Profile ")
        || dir_name == "Guest Profile"
        || dir_name == "System Profile")
        && path.is_dir()
    {
        return true;
    }
    has_profile_artifacts(path)
}

/// Finds HTTP cache directories inside a profile directory (or cache profile directory),
/// preferring `Cache/Cache_Data`, `Cache`, `Media Cache/Cache_Data`, `Media Cache`, `GPUCache`, etc.
pub fn find_cache_dirs_in_profile(profile_dir: &Path) -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    let candidates = [
        profile_dir.join("Cache").join("Cache_Data"),
        profile_dir.join("Cache"),
        profile_dir.join("Media Cache").join("Cache_Data"),
        profile_dir.join("Media Cache"),
        profile_dir.join("GPUCache"),
    ];
    for cand in candidates {
        if cand.is_dir() && is_cache_data_dir(&cand) {
            dirs.push(cand);
        }
    }
    dirs
}

/// Checks whether a directory directly contains Simple Cache or Blockfile Cache files.
pub fn is_cache_data_dir(dir: &Path) -> bool {
    if !dir.is_dir() {
        return false;
    }
    if dir.join("index").is_file()
        || dir.join("the-real-index").is_file()
        || dir.join("index-dir").join("the-real-index").is_file()
        || dir.join("data_0").is_file()
        || dir.join("data_1").is_file()
    {
        return true;
    }
    if let Ok(rd) = std::fs::read_dir(dir) {
        for e in rd.flatten().take(512) {
            let name = e.file_name();
            let s = name.to_string_lossy();
            if s.ends_with("_0") || s.ends_with("_1") || s.starts_with("f_") {
                return true;
            }
        }
    }
    false
}

/// Recursively searches container subdirectories up to `max_depth` for profile or cache dirs.
fn find_nested_targets(root: &Path, max_depth: usize) -> (Vec<PathBuf>, Vec<PathBuf>, Option<PathBuf>) {
    use std::collections::VecDeque;

    let mut queue = VecDeque::new();
    let mut nested_profiles = Vec::new();
    let mut nested_caches = Vec::new();
    let mut detected_user_data: Option<PathBuf> = None;

    if let Ok(rd) = std::fs::read_dir(root) {
        for entry in rd.flatten() {
            let p = entry.path();
            if p.is_dir() {
                queue.push_back((p, 1usize));
            }
        }
    }

    while let Some((dir, depth)) = queue.pop_front() {
        let dir_name = dir
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();

        if detected_user_data.is_none() && dir.join("Local State").is_file() {
            detected_user_data = Some(dir.clone());
        }

        let cache_data_sub = dir.join("Cache_Data");
        if cache_data_sub.is_dir() && is_cache_data_dir(&cache_data_sub) && !has_non_cache_profile_artifacts(&dir) {
            if !nested_caches.contains(&cache_data_sub) {
                nested_caches.push(cache_data_sub);
            }
            continue;
        }
        if is_cache_data_dir(&dir) && !has_non_cache_profile_artifacts(&dir) {
            if !nested_caches.contains(&dir) {
                nested_caches.push(dir);
            }
            continue;
        }

        if looks_like_profile_dir(&dir, &dir_name) && !dir.join("Local State").is_file() {
            if !nested_profiles.contains(&dir) {
                nested_profiles.push(dir);
            }
            continue;
        }

        if depth < max_depth
            && let Ok(rd) = std::fs::read_dir(&dir)
        {
            for entry in rd.flatten() {
                let child = entry.path();
                if child.is_dir() {
                    queue.push_back((child, depth + 1));
                }
            }
        }
    }

    (nested_profiles, nested_caches, detected_user_data)
}

/// Classifies an arbitrary path given by the user into a Cache folder, Profile folder, or User Data root.
pub fn resolve_target_path(input: &Path) -> ResolvedTarget {
    let input_path = input.to_path_buf();

    // 1. Direct Cache_Data or Cache directory?
    let cache_data_sub = input.join("Cache_Data");
    if cache_data_sub.is_dir() && is_cache_data_dir(&cache_data_sub) && !has_non_cache_profile_artifacts(input) {
        return ResolvedTarget {
            kind: TargetKind::CacheDir,
            input_path,
            user_data_dir: None,
            profile_dirs: Vec::new(),
            cache_dirs: vec![cache_data_sub],
            last_used_profile: None,
        };
    }
    if is_cache_data_dir(input) && !has_non_cache_profile_artifacts(input) {
        return ResolvedTarget {
            kind: TargetKind::CacheDir,
            input_path: input_path.clone(),
            user_data_dir: None,
            profile_dirs: Vec::new(),
            cache_dirs: vec![input_path],
            last_used_profile: None,
        };
    }

    // 2. Profile directory (e.g. .../User Data/Default or custom exported profile)?
    let name = input
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default();
    if !input.join("Local State").is_file() && has_profile_artifacts(input) {
        let mut cache_dirs = find_cache_dirs_in_profile(input);
        if cache_dirs.is_empty() && input.join("Cache").is_dir() {
            cache_dirs.push(input.join("Cache"));
        }
        return ResolvedTarget {
            kind: TargetKind::ProfileDir,
            input_path: input_path.clone(),
            user_data_dir: input.parent().map(|p| p.to_path_buf()),
            profile_dirs: vec![input_path],
            cache_dirs,
            last_used_profile: Some(name),
        };
    }

    // 3. User Data root directory (contains Local State or Default / Profile N)?
    let (profiles, last_used) = discover_profiles_in_user_data(input, None);
    let mut profile_dirs: Vec<PathBuf> = profiles.iter().map(|p| p.path.clone()).collect();
    let mut cache_dirs = Vec::new();
    for p in &profiles {
        for c in &p.cache_dirs {
            if !cache_dirs.contains(c) {
                cache_dirs.push(c.clone());
            }
        }
    }

    if !profile_dirs.is_empty() || input.join("Local State").is_file() {
        return ResolvedTarget {
            kind: TargetKind::UserDataRoot,
            input_path: input_path.clone(),
            user_data_dir: Some(input_path),
            profile_dirs,
            cache_dirs,
            last_used_profile: last_used,
        };
    }

    // 4. Parent / extracted container directory containing nested profiles or cache dirs?
    let (nested_profiles, nested_caches, detected_user_data) = find_nested_targets(input, 3);
    if !nested_profiles.is_empty() {
        profile_dirs = nested_profiles;
        for pdir in &profile_dirs {
            for c in find_cache_dirs_in_profile(pdir) {
                if !cache_dirs.contains(&c) {
                    cache_dirs.push(c);
                }
            }
        }
        return ResolvedTarget {
            kind: TargetKind::UserDataRoot,
            input_path: input_path.clone(),
            user_data_dir: detected_user_data.or(Some(input_path)),
            profile_dirs,
            cache_dirs,
            last_used_profile: last_used,
        };
    }
    if !nested_caches.is_empty() {
        return ResolvedTarget {
            kind: TargetKind::CacheDir,
            input_path,
            user_data_dir: None,
            profile_dirs: Vec::new(),
            cache_dirs: nested_caches,
            last_used_profile: None,
        };
    }

    ResolvedTarget {
        kind: TargetKind::UserDataRoot,
        input_path: input_path.clone(),
        user_data_dir: Some(input_path),
        profile_dirs,
        cache_dirs,
        last_used_profile: last_used,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ArtifactFormat {
    UserDataRoot,
    ProfileDirectory,
    SimpleCacheDirectory,
    BlockfileCacheDirectory,
    SimpleCacheEntryFile,
    SimpleCacheStreamFile,
    BlockfileIndexOrData,
    SqliteDatabase,
    SnssSessionFile,
    LevelDbStorageDirectory,
    ChromeJsonMetadata,
    CachedPayloadFile,
    Unknown,
}

impl ArtifactFormat {
    pub fn name(&self) -> &'static str {
        match self {
            ArtifactFormat::UserDataRoot => "Chrome User Data Root Directory",
            ArtifactFormat::ProfileDirectory => "Chrome Profile Directory",
            ArtifactFormat::SimpleCacheDirectory => "Chrome Simple Cache Directory",
            ArtifactFormat::BlockfileCacheDirectory => "Chrome Blockfile Cache Directory",
            ArtifactFormat::SimpleCacheEntryFile => "Chrome Simple Cache Entry File (*_0)",
            ArtifactFormat::SimpleCacheStreamFile => "Chrome Simple Cache Stream File (*_1 / *_2)",
            ArtifactFormat::BlockfileIndexOrData => "Chrome Blockfile Cache Index / Data Container",
            ArtifactFormat::SqliteDatabase => "SQLite 3 Database (History / Cookies / Login Data / Web Data)",
            ArtifactFormat::SnssSessionFile => "Chrome SNSS Session / Tabs File",
            ArtifactFormat::LevelDbStorageDirectory => "LevelDB Storage Directory",
            ArtifactFormat::ChromeJsonMetadata => "Chrome JSON Metadata (Local State / Preferences / Bookmarks)",
            ArtifactFormat::CachedPayloadFile => "Cached Asset / Separate Payload File (f_xxxxxx or Extracted)",
            ArtifactFormat::Unknown => "Unknown Artifact",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactInspection {
    pub artifact_format: ArtifactFormat,
    pub artifact_format_name: String,
    pub detected_mime: Option<String>,
    pub suggested_extension: Option<String>,
    pub file_signature: Option<String>,
    pub detection_source: crate::magic::DetectionSource,
    pub current_extension: Option<String>,
    pub missing_extension: bool,
    pub extension_mismatch: bool,
    pub suggested_filename: Option<String>,
}

fn is_chrome_json_metadata_name(path: &Path) -> bool {
    let fname = path
        .file_name()
        .map(|n| n.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default();
    matches!(
        fname.as_str(),
        "local state"
            | "preferences"
            | "secure preferences"
            | "bookmarks"
            | "bookmarks.bak"
            | "network persistent state"
            | "transportsecurity"
    )
}

pub struct ArtifactSniffer;

impl ArtifactSniffer {
    pub fn sniff_path(path: &Path) -> ArtifactFormat {
        Self::inspect_path(path).artifact_format
    }

    pub fn inspect_path(path: &Path) -> ArtifactInspection {
        let make = |fmt: ArtifactFormat| ArtifactInspection {
            artifact_format: fmt,
            artifact_format_name: fmt.name().to_string(),
            detected_mime: None,
            suggested_extension: None,
            file_signature: None,
            detection_source: crate::magic::DetectionSource::Unknown,
            current_extension: None,
            missing_extension: false,
            extension_mismatch: false,
            suggested_filename: None,
        };

        if path.is_dir() {
            if path.join("data_0").is_file() || path.join("data_1").is_file() {
                return make(ArtifactFormat::BlockfileCacheDirectory);
            }
            if is_cache_data_dir(path) {
                return make(ArtifactFormat::SimpleCacheDirectory);
            }
            if (path.join("CURRENT").is_file() && path.join("MANIFEST-000001").is_file())
                || std::fs::read_dir(path).ok().is_some_and(|rd| {
                    rd.flatten()
                        .any(|e| e.file_name().to_string_lossy().starts_with("MANIFEST-"))
                })
            {
                return make(ArtifactFormat::LevelDbStorageDirectory);
            }
            let name = path
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_default();
            if looks_like_profile_dir(path, &name) && !path.join("Local State").is_file() {
                return make(ArtifactFormat::ProfileDirectory);
            }
            if path.join("Local State").is_file()
                || path.join("Default").is_dir()
                || path.join("Last Version").is_file()
            {
                return make(ArtifactFormat::UserDataRoot);
            }
            let resolved = resolve_target_path(path);
            let fmt = match resolved.kind {
                TargetKind::CacheDir => ArtifactFormat::SimpleCacheDirectory,
                TargetKind::ProfileDir => ArtifactFormat::ProfileDirectory,
                TargetKind::UserDataRoot if !resolved.profile_dirs.is_empty() => ArtifactFormat::UserDataRoot,
                _ => ArtifactFormat::Unknown,
            };
            return make(fmt);
        }

        if path.is_file() {
            use std::io::Read;
            let mut buf = vec![0u8; 64 * 1024];
            if let Ok(mut f) = std::fs::File::open(path)
                && let Ok(n) = f.read(&mut buf)
            {
                buf.truncate(n);
                let head = &buf[..];

                if head.starts_with(b"SQLite format 3\0") {
                    let mut insp = make(ArtifactFormat::SqliteDatabase);
                    insp.detected_mime = Some("application/vnd.sqlite3".to_string());
                    insp.suggested_extension = Some("sqlite".to_string());
                    insp.file_signature = Some("SQLite 3 Database".to_string());
                    insp.detection_source = crate::magic::DetectionSource::MagicSignature;
                    return insp;
                }
                if head.starts_with(b"SNSS") {
                    return make(ArtifactFormat::SnssSessionFile);
                }
                if n >= 8 && u64::from_le_bytes(head[0..8].try_into().unwrap_or([0; 8])) == 0xfcfb_6d1b_a772_5c30 {
                    let fname = path
                        .file_name()
                        .map(|n| n.to_string_lossy().to_string())
                        .unwrap_or_default();
                    if fname.ends_with("_1") || fname.ends_with("_2") {
                        let mut insp = make(ArtifactFormat::SimpleCacheStreamFile);
                        let file_len = f.metadata().ok().map(|m| m.len()).unwrap_or(n as u64);
                        // Peek inside Simple Cache stream payload past [24-byte header + key_len]
                        if n >= 24 {
                            let key_len = u32::from_le_bytes(head[12..16].try_into().unwrap_or([0; 4])) as usize;
                            let payload_off = 24usize.saturating_add(key_len);
                            if payload_off < head.len() {
                                let url_hint = std::str::from_utf8(&head[24..payload_off])
                                    .ok()
                                    .and_then(|k| k.split_whitespace().last())
                                    .map(|s| s.to_string());
                                let payload_end = if file_len == n as u64
                                    && payload_off.checked_add(24).is_some_and(|e| n >= e)
                                {
                                    let eof_start = n - 24;
                                    let eof_magic =
                                        u64::from_le_bytes(head[eof_start..eof_start + 8].try_into().unwrap_or([0; 8]));
                                    if eof_magic == 0xf4fa_6f45_970d_41d8 {
                                        let eof_flags = u32::from_le_bytes(
                                            head[eof_start + 8..eof_start + 12].try_into().unwrap_or([0; 4]),
                                        );
                                        let sha_len = if (eof_flags & 2) != 0 { 32usize } else { 0usize };
                                        eof_start.saturating_sub(sha_len).max(payload_off)
                                    } else {
                                        n
                                    }
                                } else {
                                    n
                                };
                                let inner = &head[payload_off..payload_end];
                                let det = crate::magic::detect_content(inner, None, url_hint.as_deref(), None);
                                insp.detected_mime = det.mime;
                                insp.suggested_extension = det.extension;
                                insp.file_signature = det.signature;
                                insp.detection_source = det.source;
                            }
                        }
                        return insp;
                    }
                    return make(ArtifactFormat::SimpleCacheEntryFile);
                }
                if n >= 4 {
                    let magic = u32::from_le_bytes(head[0..4].try_into().unwrap_or([0; 4]));
                    if magic == 0xc103_cac3 || magic == 0xc104_cac3 {
                        return make(ArtifactFormat::BlockfileIndexOrData);
                    }
                }

                let trimmed = head.iter().copied().find(|b| !b.is_ascii_whitespace());
                if trimmed == Some(b'{') && is_chrome_json_metadata_name(path) {
                    let mut insp = make(ArtifactFormat::ChromeJsonMetadata);
                    insp.detected_mime = Some("application/json".to_string());
                    insp.suggested_extension = Some("json".to_string());
                    insp.file_signature = Some("Chrome JSON Configuration".to_string());
                    insp.detection_source = crate::magic::DetectionSource::TextHeuristic;
                    return insp;
                }

                let det = crate::magic::detect_content(head, None, None, None);
                let fname = path
                    .file_name()
                    .map(|s| s.to_string_lossy().to_string())
                    .unwrap_or_default();
                let raw_ext = path
                    .extension()
                    .map(|e| e.to_string_lossy().to_ascii_lowercase())
                    .filter(|e| !e.is_empty());

                let current_extension = raw_ext
                    .as_deref()
                    .filter(|e| crate::magic::is_known_extension(e) && !crate::magic::is_server_endpoint_extension(e))
                    .map(str::to_string);

                let missing_extension = current_extension.is_none() && det.extension.is_some();
                let extension_mismatch = matches!(
                    (&current_extension, &det.extension),
                    (Some(cur), Some(det_ext)) if !crate::magic::extensions_equivalent(cur, det_ext)
                );

                let suggested_filename = if let Some(ref ext) = det.extension {
                    if missing_extension {
                        Some(format!("{fname}.{ext}"))
                    } else if extension_mismatch {
                        let stem = path
                            .file_stem()
                            .map(|s| s.to_string_lossy().to_string())
                            .unwrap_or_else(|| fname.clone());
                        Some(format!("{stem}.{ext}"))
                    } else {
                        None
                    }
                } else {
                    None
                };

                let fmt = if det.mime.is_some() || det.extension.is_some() {
                    ArtifactFormat::CachedPayloadFile
                } else if trimmed == Some(b'{') {
                    ArtifactFormat::ChromeJsonMetadata
                } else {
                    ArtifactFormat::Unknown
                };

                return ArtifactInspection {
                    artifact_format: fmt,
                    artifact_format_name: fmt.name().to_string(),
                    detected_mime: det.mime,
                    suggested_extension: det.extension,
                    file_signature: det.signature,
                    detection_source: det.source,
                    current_extension,
                    missing_extension,
                    extension_mismatch,
                    suggested_filename,
                };
            }
        }

        make(ArtifactFormat::Unknown)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_inspect_extensionless_and_mismatched_files() {
        let dir = TempDir::new().unwrap();

        // Extensionless Blockfile payload file containing WebP
        let raw_bf = dir.path().join("f_00001a");
        std::fs::write(&raw_bf, b"RIFF\x20\x00\x00\x00WEBPVP8 \x14\x00\x00\x00").unwrap();
        let insp = ArtifactSniffer::inspect_path(&raw_bf);
        assert_eq!(insp.artifact_format, ArtifactFormat::CachedPayloadFile);
        assert_eq!(insp.detected_mime.as_deref(), Some("image/webp"));
        assert_eq!(insp.suggested_extension.as_deref(), Some("webp"));
        assert!(insp.missing_extension);
        assert!(!insp.extension_mismatch);
        assert_eq!(insp.suggested_filename.as_deref(), Some("f_00001a.webp"));

        // Versioned extensionless asset
        let ver_js = dir.path().join("jquery-3.7.1");
        std::fs::write(&ver_js, b"'use strict';\nconst jQ=1;").unwrap();
        let insp_js = ArtifactSniffer::inspect_path(&ver_js);
        assert_eq!(insp_js.suggested_extension.as_deref(), Some("js"));
        assert!(insp_js.missing_extension);
        assert_eq!(insp_js.suggested_filename.as_deref(), Some("jquery-3.7.1.js"));

        // Masqueraded .png containing PE executable
        let mut pe = vec![0u8; 128];
        pe[0..2].copy_from_slice(b"MZ");
        pe[0x3c..0x40].copy_from_slice(&64u32.to_le_bytes());
        pe[64..68].copy_from_slice(b"PE\0\0");
        let fake_png = dir.path().join("avatar.png");
        std::fs::write(&fake_png, &pe).unwrap();
        let insp_pe = ArtifactSniffer::inspect_path(&fake_png);
        assert_eq!(insp_pe.current_extension.as_deref(), Some("png"));
        assert_eq!(insp_pe.suggested_extension.as_deref(), Some("exe"));
        assert!(insp_pe.extension_mismatch);
        assert_eq!(insp_pe.suggested_filename.as_deref(), Some("avatar.exe"));
    }

    #[test]
    fn test_resolve_custom_profile_with_network_cookies_only() {
        let dir = TempDir::new().unwrap();
        let custom_profile = dir.path().join("Subject_Alpha_Export");
        std::fs::create_dir_all(custom_profile.join("Network")).unwrap();
        std::fs::write(custom_profile.join("Network").join("Cookies"), b"SQLite format 3\0").unwrap();

        let resolved = resolve_target_path(&custom_profile);
        assert_eq!(resolved.kind, TargetKind::ProfileDir);
        assert_eq!(resolved.profile_dirs, vec![custom_profile]);
    }

    #[test]
    fn test_resolve_custom_profile_with_cache_only() {
        let dir = TempDir::new().unwrap();
        let custom_profile = dir.path().join("Exported_Cache_Profile");
        let cache_data = custom_profile.join("Cache").join("Cache_Data");
        std::fs::create_dir_all(&cache_data).unwrap();
        std::fs::write(cache_data.join("index"), b"\0\0\0\0").unwrap();

        let resolved = resolve_target_path(&custom_profile);
        assert_eq!(resolved.kind, TargetKind::ProfileDir);
        assert_eq!(resolved.profile_dirs, vec![custom_profile]);
        assert_eq!(resolved.cache_dirs, vec![cache_data.clone()]);

        // Direct selection of Cache or Cache_Data still resolves to CacheDir
        let direct_cache_parent = resolve_target_path(cache_data.parent().unwrap());
        assert_eq!(direct_cache_parent.kind, TargetKind::CacheDir);
        assert_eq!(direct_cache_parent.cache_dirs, vec![cache_data]);
    }

    #[test]
    fn test_resolve_nested_container_folder() {
        let dir = TempDir::new().unwrap();
        let container = dir.path().join("Case_Container");
        let nested_ud = container.join("Acquired").join("ChromeData");
        let profile = nested_ud.join("WorkProfile");
        std::fs::create_dir_all(profile.join("Cache").join("Cache_Data")).unwrap();
        std::fs::write(nested_ud.join("Local State"), br#"{"os_crypt":{}}"#).unwrap();
        std::fs::write(profile.join("Login Data"), b"SQLite format 3\0").unwrap();
        std::fs::write(profile.join("Cache").join("Cache_Data").join("index"), b"\0").unwrap();

        let resolved = resolve_target_path(&container);
        assert_eq!(resolved.kind, TargetKind::UserDataRoot);
        assert_eq!(resolved.user_data_dir, Some(nested_ud));
        assert_eq!(resolved.profile_dirs, vec![profile.clone()]);
        assert_eq!(resolved.cache_dirs, vec![profile.join("Cache").join("Cache_Data")]);
    }
}
