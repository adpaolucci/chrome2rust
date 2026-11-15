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
                (BrowserKind::ChromeDev, "google-chrome-unstable", "google-chrome-unstable"),
                (BrowserKind::Chromium, "chromium", "chromium"),
                (BrowserKind::Edge, "microsoft-edge", "microsoft-edge"),
                (BrowserKind::Brave, "BraveSoftware/Brave-Browser", "BraveSoftware/Brave-Browser"),
                (BrowserKind::Opera, "opera", "opera"),
                (BrowserKind::Vivaldi, "vivaldi", "vivaldi"),
                (BrowserKind::Yandex, "yandex-browser", "yandex-browser"),
            ];
            for (kind, cfg_rel, cache_rel) in specs {
                out.push((
                    *kind,
                    config.join(cfg_rel),
                    cache.as_ref().map(|c| c.join(cache_rel)),
                ));
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
                (BrowserKind::ChromeCanary, "Google/Chrome Canary", "Google/Chrome Canary"),
                (BrowserKind::Chromium, "Chromium", "Chromium"),
                (BrowserKind::Edge, "Microsoft Edge", "Microsoft Edge"),
                (BrowserKind::Brave, "BraveSoftware/Brave-Browser", "BraveSoftware/Brave-Browser"),
                (BrowserKind::Opera, "com.operasoftware.Opera", "com.operasoftware.Opera"),
                (BrowserKind::Vivaldi, "Vivaldi", "Vivaldi"),
                (BrowserKind::Yandex, "Yandex/YandexBrowser", "Yandex/YandexBrowser"),
            ];
            for (kind, rel, cache_rel) in specs {
                out.push((
                    *kind,
                    app_support.join(rel),
                    caches.as_ref().map(|c| c.join(cache_rel)),
                ));
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
                {
                    if newest.is_none_or(|(best, _)| mtime > best) {
                        newest = Some((mtime, idx));
                    }
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

pub fn looks_like_profile_dir(path: &Path, dir_name: &str) -> bool {
    if dir_name == "Default"
        || dir_name.starts_with("Profile ")
        || dir_name == "Guest Profile"
        || dir_name == "System Profile"
    {
        return true;
    }
    // Also detect custom-named profiles (like Opera or standalone profile directories)
    ["History", "Preferences", "Bookmarks", "Cookies", "Web Data"]
        .iter()
        .any(|f| path.join(f).exists())
}

/// Finds HTTP cache directories inside a profile directory (or cache profile directory),
/// preferring `Cache/Cache_Data`, `Cache`, `Code Cache/js`, etc.
pub fn find_cache_dirs_in_profile(profile_dir: &Path) -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    let candidates = [
        profile_dir.join("Cache").join("Cache_Data"),
        profile_dir.join("Cache"),
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
    if dir.join("index").is_file() || dir.join("data_0").is_file() || dir.join("data_1").is_file() {
        return true;
    }
    if let Ok(rd) = std::fs::read_dir(dir) {
        for e in rd.flatten().take(64) {
            let name = e.file_name();
            let s = name.to_string_lossy();
            if s.ends_with("_0") || s.starts_with("f_") {
                return true;
            }
        }
    }
    false
}

/// Classifies an arbitrary path given by the user into a Cache folder, Profile folder, or User Data root.
pub fn resolve_target_path(input: &Path) -> ResolvedTarget {
    let input_path = input.to_path_buf();

    // 1. Direct Cache_Data or Cache directory?
    let cache_data_sub = input.join("Cache_Data");
    if cache_data_sub.is_dir() && is_cache_data_dir(&cache_data_sub) {
        return ResolvedTarget {
            kind: TargetKind::CacheDir,
            input_path,
            user_data_dir: None,
            profile_dirs: Vec::new(),
            cache_dirs: vec![cache_data_sub],
            last_used_profile: None,
        };
    }
    if is_cache_data_dir(input) {
        return ResolvedTarget {
            kind: TargetKind::CacheDir,
            input_path: input_path.clone(),
            user_data_dir: None,
            profile_dirs: Vec::new(),
            cache_dirs: vec![input_path],
            last_used_profile: None,
        };
    }

    // 2. Profile directory (e.g. .../User Data/Default)?
    let name = input
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default();
    if looks_like_profile_dir(input, &name) && !input.join("Local State").is_file() {
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
    let profile_dirs: Vec<PathBuf> = profiles.iter().map(|p| p.path.clone()).collect();
    let mut cache_dirs = Vec::new();
    for p in &profiles {
        for c in &p.cache_dirs {
            if !cache_dirs.contains(c) {
                cache_dirs.push(c.clone());
            }
        }
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
