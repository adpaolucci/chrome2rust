#![forbid(unsafe_code)]

mod tools_cmd;

use anyhow::{Context, Result, anyhow, bail};
use chrome2rust_cache::export::{
    CacheColumn, ExportFormat, ExtractFilenameMode, ExtractOptions, extract_cache_entries, render_cache_export,
};
use chrome2rust_cache::simple::parse_simple_entry_file;
use chrome2rust_cache::{
    CacheBackendKind, CacheEntry, CacheScanOptions, CacheSortField, delete_cache_entries, load_cache_from_paths,
    sort_cache_entries,
};
use chrome2rust_core::crypto::CryptoOptions;
use chrome2rust_core::discovery::{
    ArtifactFormat, ArtifactSniffer, DiscoveredBrowser, TargetKind, discover_local_browsers, resolve_target_path,
};
use chrome2rust_core::logging::init_logging;
use chrome2rust_core::time::{format_local_opt, format_utc_opt, parse_relative_duration, parse_user_datetime};
use chrome2rust_forensics::custody::{generate_custody_manifest, write_custody_manifest};
use chrome2rust_forensics::findings::FindingSeverity;
use chrome2rust_forensics::{AnalysisOptions, UserDataReport, analyze_user_data};
use chrome2rust_report::markdown::format_bytes;
use chrome2rust_report::{ReportFormat, write_report};
use chrono::{DateTime, Utc};
use clap::{Args, Parser, Subcommand, ValueEnum};
use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use tracing::{info, warn};

static SHUTDOWN_FLAG: AtomicBool = AtomicBool::new(false);

pub fn is_shutdown_requested() -> bool {
    SHUTDOWN_FLAG.load(Ordering::Relaxed)
}

pub fn init_signal_handler() {
    let _ = ctrlc::set_handler(move || {
        if SHUTDOWN_FLAG.swap(true, Ordering::SeqCst) {
            eprintln!("\n[!] Force terminating on second interrupt.");
            std::process::exit(130);
        } else {
            eprintln!("\n[!] Interrupt received (SIGINT/Ctrl+C). Finishing active read operation cleanly...");
        }
    });
}

#[derive(Parser, Debug)]
#[command(
    name = "chrome2rust",
    author = "Chrome2Rust Contributors",
    version,
    about = "Universal high-performance Google Chrome HTTP cache inspector and User Data forensic suite in 100% pure Rust",
    long_about = "Analyze Google Chrome / Chromium HTTP caches (Simple Cache & Blockfile) and complete User Data directories in pure Rust.\n\nInvoke without arguments or run `chrome2rust gui` to launch the native desktop forensic console (`chrome2rust-win32` on Windows, `chrome2rust-iced` on Linux/macOS or via `--iced`)."
)]
pub struct Cli {
    /// Logging verbosity level (error, warn, info, debug, trace)
    #[arg(short, long, global = true, default_value = "warn")]
    pub log_level: String,

    /// Optional log output file path
    #[arg(long, global = true)]
    pub log_file: Option<PathBuf>,

    /// Optional output CSV or JSON path for SHA-256 chain-of-custody manifest
    #[arg(long, global = true, alias = "audit-log")]
    pub audit_manifest: Option<PathBuf>,

    /// Launch native host OS file/folder picker dialog when paths are omitted
    #[arg(long, global = true, alias = "browse")]
    pub pick: bool,

    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Discover local Chrome / Chromium / Edge / Brave / Opera / Vivaldi profiles and caches
    Profiles(ProfilesArgs),

    /// Identify Chrome artifact format via header magic bytes and directory heuristics
    Sniff(SniffArgs),

    /// Browse, filter, export, extract, inspect, or delete Chrome cache entries
    Cache {
        #[command(subcommand)]
        action: CacheSubcommand,
    },

    /// Perform full forensic analysis on a Chrome User Data or Profile directory
    Analyze(AnalyzeArgs),

    /// Generate standalone HTML, JSON, Markdown, or bundled forensic reports
    Report(ReportArgs),

    /// Generate cryptographic SHA-256 & balanced Merkle root chain-of-custody manifests
    Custody(CustodyArgs),

    /// Launch native host OS file/folder picker dialog and output the selected path
    Pick(PickArgs),

    /// Launch the desktop forensic GUI (`chrome2rust-win32` on Windows, `chrome2rust-iced` on Linux/macOS or with `--iced`)
    Gui(GuiArgs),

    /// Run Model Context Protocol (MCP) server over standard I/O (JSON-RPC)
    Mcp(McpArgs),

    /// Inspect Mozilla Firefox cache, history, cookies (metadata), bookmarks, downloads, formhistory, addons & sessions
    Fx {
        #[command(subcommand)]
        action: tools_cmd::FxSubcommand,
    },

    /// Inspect Opera Blink & Presto caches and history
    Opera {
        #[command(subcommand)]
        action: tools_cmd::OperaSubcommand,
    },

    /// Inspect Apple Safari cache, history & bookmarks
    Safari {
        #[command(subcommand)]
        action: tools_cmd::SafariSubcommand,
    },

    /// Aggregate normalized history, downloads, add-ons, bookmarks & non-credential autofill across all browsers
    Unified {
        #[command(subcommand)]
        action: tools_cmd::UnifiedSubcommand,
    },

    /// Extract search engine queries from history, cache URLs/Referer headers, and sessions (MyLastSearch equivalent)
    SearchQueries(tools_cmd::SearchQueriesArgs),

    /// Carve cached images (with EXIF/GPS) and video streams (MP4/WebM/TS/HLS/DASH) across browsers
    Carve {
        #[command(subcommand)]
        action: tools_cmd::CarveSubcommand,
    },
}

#[derive(Args, Debug, Default, Clone)]
pub struct GuiArgs {
    /// Optional User Data, Profile, or Cache directory to open immediately
    #[arg(value_name = "PATH")]
    pub path: Option<PathBuf>,

    /// Launch the cross-platform Iced GUI instead of the Windows-native Win32 GUI
    #[arg(long)]
    pub iced: bool,

    /// Enable optional best-effort decryption (for Cookies / Login Data)
    #[arg(long)]
    pub decrypt: bool,

    /// Encryption passphrase or 16/32-byte hex AES key (repeatable)
    #[arg(long = "key", value_name = "KEY_OR_HEX")]
    pub keys: Vec<String>,
}

#[derive(Args, Debug)]
pub struct ProfilesArgs {
    /// Output discovered browser profiles as JSON
    #[arg(long)]
    pub json: bool,
}

#[derive(Args, Debug)]
pub struct SniffArgs {
    /// Path to file or Chrome directory to inspect
    #[arg(value_name = "PATH")]
    pub path: Option<PathBuf>,

    /// Output inspection details as JSON
    #[arg(long)]
    pub json: bool,
}

#[derive(Args, Debug)]
pub struct CustodyArgs {
    /// Path to Chrome artifact file, Cache, Profile, or User Data directory
    #[arg(value_name = "PATH")]
    pub path: Option<PathBuf>,

    /// Write chain-of-custody manifest to CSV or JSON file
    #[arg(short = 'o', long)]
    pub output_manifest: Option<PathBuf>,

    /// Output complete manifest JSON to stdout
    #[arg(long)]
    pub json: bool,
}

#[derive(Args, Debug)]
pub struct PickArgs {
    /// Dialog type to launch: 'file', 'files', 'folder', or 'save'
    #[arg(short, long, default_value = "folder")]
    pub kind: String,

    /// Dialog window title
    #[arg(long)]
    pub title: Option<String>,

    /// Default file extension for save dialog (e.g. "html", "json", "csv")
    #[arg(long, default_value = "html")]
    pub ext: String,

    /// Initial folder to browse
    #[arg(long)]
    pub dir: Option<PathBuf>,
}

#[derive(Args, Debug)]
pub struct McpArgs {
    /// Print MCP tools manifest in JSON Schema format and exit
    #[arg(long)]
    pub tools: bool,
}

#[derive(Subcommand, Debug)]
pub enum CacheSubcommand {
    /// List / export cache entries matching optional filters
    List(CacheListArgs),

    /// Extract cached files from the Chrome cache into an output directory
    Extract(CacheExtractArgs),

    /// Inspect a single cache file (*_0) or entry URL in deep detail
    Inspect(CacheInspectArgs),

    /// Delete filtered standalone cache files (Simple *_0 or Blockfile f_xxxxxx)
    Delete(CacheDeleteArgs),
}

#[derive(Copy, Clone, Debug, ValueEnum)]
pub enum CliExportFormat {
    Table,
    Tabular,
    Csv,
    Tsv,
    Tab,
    Text,
    Html,
    Vhtml,
    Xml,
    Json,
}

impl From<CliExportFormat> for ExportFormat {
    fn from(f: CliExportFormat) -> Self {
        match f {
            CliExportFormat::Table | CliExportFormat::Tabular => ExportFormat::Tabular,
            CliExportFormat::Csv => ExportFormat::Csv,
            CliExportFormat::Tsv | CliExportFormat::Tab => ExportFormat::Tab,
            CliExportFormat::Text => ExportFormat::Text,
            CliExportFormat::Html => ExportFormat::HtmlHorizontal,
            CliExportFormat::Vhtml => ExportFormat::HtmlVertical,
            CliExportFormat::Xml => ExportFormat::Xml,
            CliExportFormat::Json => ExportFormat::Json,
        }
    }
}

#[derive(Copy, Clone, Debug, ValueEnum)]
pub enum CliFilenameMode {
    Url,
    CacheName,
    CacheNameExt,
}

impl From<CliFilenameMode> for ExtractFilenameMode {
    fn from(m: CliFilenameMode) -> Self {
        match m {
            CliFilenameMode::Url => ExtractFilenameMode::BasedOnUrl,
            CliFilenameMode::CacheName => ExtractFilenameMode::CacheName,
            CliFilenameMode::CacheNameExt => ExtractFilenameMode::CacheNameWithExtension,
        }
    }
}

#[derive(Args, Debug)]
pub struct CacheFilterArgs {
    /// Path to Cache, Cache_Data, Profile, or User Data folder (auto-discovers local browser if omitted)
    #[arg(value_name = "PATH")]
    pub path: Option<PathBuf>,

    /// Quick search substring across URL, Content-Type, Server, Web Site, IP, status
    #[arg(long)]
    pub filter: Option<String>,

    /// Case-insensitive URL substring filter
    #[arg(long)]
    pub url: Option<String>,

    /// Case-insensitive Content-Type substring filter (e.g. image/, text/html, application/json)
    #[arg(long)]
    pub content_type: Option<String>,

    /// Minimum decompressed payload size in bytes
    #[arg(long)]
    pub min_size: Option<usize>,

    /// Maximum decompressed payload size in bytes
    #[arg(long)]
    pub max_size: Option<usize>,

    /// Include entries accessed/created at or after this timestamp (RFC3339 or YYYY-MM-DD[ HH:MM:SS])
    #[arg(long)]
    pub since: Option<String>,

    /// Include entries accessed/created at or before this timestamp
    #[arg(long)]
    pub until: Option<String>,

    /// Include entries within the last duration (e.g. 30m, 24h, 7d, 2w)
    #[arg(long)]
    pub last: Option<String>,

    /// Exclude zero-length payload entries
    #[arg(long)]
    pub no_zero_length: bool,
}

#[derive(Args, Debug)]
pub struct CacheListArgs {
    #[command(flatten)]
    pub filter_args: CacheFilterArgs,

    /// Export / output format
    #[arg(short = 'f', long, value_enum, default_value_t = CliExportFormat::Table)]
    pub format: CliExportFormat,

    /// Comma-separated list of columns (e.g. url,content-type,detected-content-type,detected-extension,file-signature,mime-mismatch,size,last-accessed,server,sha256)
    #[arg(long)]
    pub columns: Option<String>,

    /// Write output to a file path instead of stdout (`-` also writes stdout)
    #[arg(short = 'o', long)]
    pub output: Option<PathBuf>,

    /// Primary sort field (url, content-type, detected-content-type, detected-extension, file-signature, mime-mismatch, size, last-accessed, server-time, created, expires, server, response, website, cache-name)
    #[arg(long, default_value = "last-accessed")]
    pub sort: String,

    /// Sort descending (default true when sorting by time, size, or mismatch unless overridden, false for text)
    #[arg(long)]
    pub desc: bool,

    /// Sort ascending explicitly
    #[arg(long)]
    pub asc: bool,

    /// Secondary tie-breaker sort field
    #[arg(long)]
    pub secondary_sort: Option<String>,

    /// Secondary sort descending
    #[arg(long)]
    pub secondary_desc: bool,

    /// Omit header line for table/csv/tsv exports
    #[arg(long)]
    pub no_header: bool,

    /// Show milliseconds in timestamps
    #[arg(long)]
    pub millis: bool,

    /// Compute SHA-256 digests of decompressed payloads
    #[arg(long)]
    pub hashes: bool,
}

#[derive(Args, Debug)]
pub struct CacheExtractArgs {
    #[command(flatten)]
    pub filter_args: CacheFilterArgs,

    /// Destination folder for extracted files
    #[arg(short = 'o', long, default_value = "./extracted_cache")]
    pub output_dir: PathBuf,

    /// How extracted files are named
    #[arg(long, value_enum, default_value_t = CliFilenameMode::Url)]
    pub filename_mode: CliFilenameMode,

    /// Save extracted files into subdirectories mirroring host/path structure
    #[arg(long)]
    pub website_dirs: bool,

    /// Do not update file modified timestamps to cached Last Accessed / Server Time
    #[arg(long)]
    pub no_update_mtime: bool,

    /// Overwrite existing files instead of appending a numeric suffix
    #[arg(long)]
    pub overwrite: bool,

    /// Save raw compressed payload bytes without gzip/br/zstd/deflate decompression
    #[arg(long)]
    pub no_decompress: bool,

    /// Replace existing filename extensions when magic/heuristic detection identifies a different type
    #[arg(long)]
    pub use_detected_ext: bool,
}

#[derive(Args, Debug)]
pub struct CacheInspectArgs {
    /// Path to a specific Simple Cache *_0 file, OR a cache/profile directory (with --url)
    #[arg(value_name = "PATH")]
    pub path: Option<PathBuf>,

    /// URL or cache-name substring to select entry when PATH is a directory
    #[arg(long)]
    pub url: Option<String>,

    /// Print UTF-8 or hex payload preview (up to 4 KiB)
    #[arg(long)]
    pub preview: bool,

    /// Dump full decompressed payload to a file
    #[arg(long, value_name = "FILE")]
    pub dump_body: Option<PathBuf>,

    /// Output inspection details as JSON
    #[arg(long)]
    pub json: bool,
}

#[derive(Args, Debug)]
pub struct CacheDeleteArgs {
    #[command(flatten)]
    pub filter_args: CacheFilterArgs,

    /// Actually perform deletion (without --yes, performs a dry-run preview)
    #[arg(long)]
    pub yes: bool,
}

#[derive(Args, Debug)]
pub struct AnalyzeArgs {
    /// Path to Chrome User Data root, Profile directory, or Cache directory (auto-discovers if omitted)
    #[arg(value_name = "PATH")]
    pub path: Option<PathBuf>,

    /// Attempt best-effort decryption of Cookies and Login Data
    #[arg(long)]
    pub decrypt: bool,

    /// Encryption passphrase or 16/32-byte hex AES key (repeatable)
    #[arg(long = "key", value_name = "KEY_OR_HEX")]
    pub keys: Vec<String>,

    /// Disable Chromium Linux fallback passphrase ("peanuts") during best-effort decryption
    #[arg(long)]
    pub no_peanuts: bool,

    /// Additional cache directory paths to scan (repeatable)
    #[arg(long = "extra-cache", value_name = "DIR")]
    pub extra_cache: Vec<PathBuf>,

    /// Compute SHA-256 digests of cached payloads
    #[arg(long)]
    pub hashes: bool,

    /// Output complete forensic analysis report as JSON to stdout
    #[arg(long)]
    pub json: bool,
}

#[derive(Args, Debug)]
pub struct ReportArgs {
    /// Path to Chrome User Data root, Profile directory, or Cache directory (auto-discovers if omitted)
    #[arg(value_name = "PATH")]
    pub path: Option<PathBuf>,

    /// Output file path (or output folder when --format all is used)
    #[arg(short = 'o', long, default_value = "./forensic_report.html")]
    pub output: PathBuf,

    /// Report format: html, json, markdown, or all
    #[arg(short = 'f', long, default_value = "html")]
    pub format: String,

    /// Attempt best-effort decryption of Cookies and Login Data
    #[arg(long)]
    pub decrypt: bool,

    /// Encryption passphrase or 16/32-byte hex AES key (repeatable)
    #[arg(long = "key", value_name = "KEY_OR_HEX")]
    pub keys: Vec<String>,

    /// Disable Chromium Linux fallback passphrase ("peanuts")
    #[arg(long)]
    pub no_peanuts: bool,

    /// Additional cache directory paths to scan (repeatable)
    #[arg(long = "extra-cache", value_name = "DIR")]
    pub extra_cache: Vec<PathBuf>,

    /// Skip SHA-256 hashing of cached payloads for faster scanning
    #[arg(long)]
    pub no_hashes: bool,
}

fn main() -> Result<()> {
    init_signal_handler();
    let cli = Cli::parse();

    if let Err(e) = init_logging(&cli.log_level, cli.log_file.as_deref()) {
        eprintln!("Warning: Failed to initialize logger: {e}");
    }

    let pick = cli.pick;
    let audit_manifest = cli.audit_manifest.clone();

    match cli.command.unwrap_or(Commands::Gui(GuiArgs::default())) {
        Commands::Profiles(args) => cmd_profiles(args),
        Commands::Sniff(args) => cmd_sniff(args, pick),
        Commands::Cache { action } => match action {
            CacheSubcommand::List(args) => cmd_cache_list(args, pick, audit_manifest.as_deref()),
            CacheSubcommand::Extract(args) => cmd_cache_extract(args, pick, audit_manifest.as_deref()),
            CacheSubcommand::Inspect(args) => cmd_cache_inspect(args, pick),
            CacheSubcommand::Delete(args) => cmd_cache_delete(args, pick),
        },
        Commands::Analyze(args) => cmd_analyze(args, pick, audit_manifest.as_deref()),
        Commands::Report(args) => cmd_report(args, pick, audit_manifest.as_deref()),
        Commands::Custody(args) => cmd_custody(args, pick),
        Commands::Pick(args) => cmd_pick(args),
        Commands::Gui(args) => cmd_gui(args, pick),
        Commands::Mcp(args) => cmd_mcp(args),
        Commands::Fx { action } => tools_cmd::run_fx(action, audit_manifest.as_deref()),
        Commands::Opera { action } => tools_cmd::run_opera(action, audit_manifest.as_deref()),
        Commands::Safari { action } => tools_cmd::run_safari(action, audit_manifest.as_deref()),
        Commands::Unified { action } => tools_cmd::run_unified(action, audit_manifest.as_deref()),
        Commands::SearchQueries(args) => tools_cmd::run_search_queries(args, audit_manifest.as_deref()),
        Commands::Carve { action } => tools_cmd::run_carve(action, audit_manifest.as_deref()),
    }
}

fn pick_source_dialog(title: &str) -> Option<PathBuf> {
    if std::io::stdin().is_terminal() {
        eprintln!("\nSelect Chrome artifact target type:");
        eprintln!("  [1] Folder (Chrome User Data, Profile, or Cache_Data directory)");
        eprintln!("  [2] Individual Artifact File (Simple *_0 entry, SQLite DB, SNSS, JSON)");
        eprint!("Choice [1/2] (default: 1): ");
        let mut choice = String::new();
        let _ = std::io::stdin().read_line(&mut choice);
        let trimmed = choice.trim().to_ascii_lowercase();
        if trimmed == "2" || trimmed == "f" || trimmed == "file" {
            return rfd::FileDialog::new().set_title(title).pick_file();
        }
    }
    rfd::FileDialog::new().set_title(title).pick_folder()
}

fn maybe_write_audit_manifest(target: &Path, manifest_dest: Option<&Path>) -> Result<()> {
    let Some(dest) = manifest_dest else {
        return Ok(());
    };
    let manifest = generate_custody_manifest(target)
        .with_context(|| format!("Failed generating chain-of-custody manifest for {}", target.display()))?;
    write_custody_manifest(&manifest, dest)
        .map_err(|e| anyhow!("Failed writing custody manifest to {}: {e}", dest.display()))?;
    info!(
        dest = %dest.display(),
        artifacts = manifest.artifact_count,
        merkle_root = %manifest.merkle_root_sha256,
        "Wrote SHA-256 chain-of-custody manifest"
    );
    Ok(())
}

fn cmd_profiles(args: ProfilesArgs) -> Result<()> {
    let browsers = discover_local_browsers();
    if args.json {
        println!("{}", serde_json::to_string_pretty(&browsers)?);
        return Ok(());
    }
    if browsers.is_empty() {
        println!("No standard local Chromium-family User Data or Cache directories found.");
        println!("Pass an explicit path to `chrome2rust cache list <PATH>` or `chrome2rust analyze <PATH>`.");
        return Ok(());
    }
    print_discovered_browsers(&browsers);
    Ok(())
}

fn print_discovered_browsers(browsers: &[DiscoveredBrowser]) {
    for b in browsers {
        println!("== {} ==", b.name);
        println!("  User Data : {}", b.user_data_dir.display());
        if let Some(cr) = &b.cache_root_dir {
            println!("  Cache Root: {}", cr.display());
        }
        if b.profiles.is_empty() {
            println!("  Profiles  : (none discovered)");
        } else {
            for p in &b.profiles {
                let tag = if p.is_last_used { " [last_used]" } else { "" };
                let label = p.display_name.as_deref().unwrap_or("-");
                let email = p.user_email.as_deref().unwrap_or("");
                let email_part = if email.is_empty() {
                    String::new()
                } else {
                    format!(" <{email}>")
                };
                println!("  - {} ({label}{email_part}){tag}", p.dir_name);
                println!("    Path  : {}", p.path.display());
                if !p.cache_dirs.is_empty() {
                    let cs: Vec<String> = p.cache_dirs.iter().map(|c| c.display().to_string()).collect();
                    println!("    Caches: {}", cs.join(", "));
                }
            }
        }
        println!();
    }
}

fn cmd_sniff(args: SniffArgs, pick: bool) -> Result<()> {
    let target = match args.path {
        Some(p) => p,
        None if pick => pick_source_dialog("Select Chrome Artifact File or Directory to Sniff")
            .ok_or_else(|| anyhow!("Selection canceled by user"))?,
        None => bail!("No path supplied. Provide <PATH> or pass --pick to choose interactively."),
    };
    if !target.exists() {
        bail!("Target path does not exist: {}", target.display());
    }

    let mut inspection = ArtifactSniffer::inspect_path(&target);
    if inspection.artifact_format == ArtifactFormat::SimpleCacheEntryFile && inspection.detected_mime.is_none() {
        let parent = target.parent().unwrap_or_else(|| Path::new("."));
        if let Ok(Some(entry)) = parse_simple_entry_file(&target, parent, &CacheScanOptions::default()) {
            inspection.detected_mime = entry.detected_content_type.or(entry.content_type);
            inspection.suggested_extension = entry.detected_extension;
            inspection.file_signature = entry.file_signature;
            inspection.extension_mismatch = entry.mime_mismatch;
        }
    }
    let resolved = resolve_target_path(&target);
    let file_bytes = std::fs::metadata(&target).map(|m| m.len()).unwrap_or(0);

    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "path": target.display().to_string(),
                "is_dir": target.is_dir(),
                "file_bytes": file_bytes,
                "artifact_format": inspection.artifact_format,
                "artifact_format_name": inspection.artifact_format_name,
                "detected_mime": inspection.detected_mime,
                "suggested_extension": inspection.suggested_extension,
                "file_signature": inspection.file_signature,
                "detection_source": inspection.detection_source,
                "current_extension": inspection.current_extension,
                "missing_extension": inspection.missing_extension,
                "extension_mismatch": inspection.extension_mismatch,
                "suggested_filename": inspection.suggested_filename,
                "resolved_target": resolved,
            }))?
        );
        return Ok(());
    }

    println!("============================================================");
    println!("chrome2rust Artifact Format Sniffer");
    println!("============================================================");
    println!("Path            : {}", target.display());
    println!(
        "Type            : {}",
        if target.is_dir() { "Directory" } else { "File" }
    );
    if !target.is_dir() {
        println!("Size            : {} ({} bytes)", format_bytes(file_bytes), file_bytes);
    }
    println!("Detected Format : {}", inspection.artifact_format_name);
    if let Some(mime) = &inspection.detected_mime {
        println!("Detected MIME   : {mime}");
    }
    if let Some(ext) = &inspection.suggested_extension {
        println!("Suggested Ext   : .{ext}");
    }
    if let Some(sig) = &inspection.file_signature {
        println!("File Signature  : {sig}");
    }
    if let Some(cur) = &inspection.current_extension {
        println!("Current Ext     : .{cur}");
    }
    if inspection.missing_extension {
        println!("Missing Ext     : Yes");
    }
    if inspection.extension_mismatch {
        println!("Ext Mismatch    : WARNING - Payload signature contradicts filename extension");
    }
    if let Some(name) = &inspection.suggested_filename {
        println!("Suggested Name  : {name}");
    }
    println!("Resolved Kind   : {}", default_target_kind_label(&resolved.kind));
    if !resolved.profile_dirs.is_empty() {
        println!("Profiles Found  : {}", resolved.profile_dirs.len());
    }
    if !resolved.cache_dirs.is_empty() {
        println!("Cache Dirs      : {}", resolved.cache_dirs.len());
    }
    println!("============================================================");
    Ok(())
}

fn resolve_cli_cache_dirs(path_opt: Option<&PathBuf>, pick: bool) -> Result<(Vec<PathBuf>, Option<PathBuf>)> {
    if let Some(p) = path_opt {
        if !p.exists() {
            bail!("Target path does not exist: {}", p.display());
        }
        let target = resolve_target_path(p);
        if target.cache_dirs.is_empty() {
            return Ok((vec![p.clone()], Some(p.clone())));
        }
        return Ok((target.cache_dirs, Some(p.clone())));
    }

    if pick
        && let Some(picked) = rfd::FileDialog::new()
            .set_title("Select Chrome User Data, Profile, or Cache Folder")
            .pick_folder()
    {
        let target = resolve_target_path(&picked);
        let dirs = if target.cache_dirs.is_empty() {
            vec![picked.clone()]
        } else {
            target.cache_dirs
        };
        return Ok((dirs, Some(picked)));
    }

    let browsers = discover_local_browsers();
    for b in &browsers {
        if let Some(p) = b.profiles.iter().find(|p| !p.cache_dirs.is_empty()) {
            return Ok((p.cache_dirs.clone(), Some(p.path.clone())));
        }
        if let Some(cr) = &b.cache_root_dir
            && cr.is_dir()
        {
            return Ok((vec![cr.clone()], Some(cr.clone())));
        }
    }
    bail!(
        "No target path specified and no local browser caches were discovered.\nRun `chrome2rust cache list <PATH>` with a Cache, Profile, or User Data path (or pass `--pick`)."
    );
}

fn resolve_cli_analysis_path(path_opt: Option<&PathBuf>, pick: bool) -> Result<PathBuf> {
    if let Some(p) = path_opt {
        if !p.exists() {
            bail!("Target path does not exist: {}", p.display());
        }
        return Ok(p.clone());
    }

    if pick
        && let Some(picked) = rfd::FileDialog::new()
            .set_title("Select Chrome User Data, Profile, or Cache Folder")
            .pick_folder()
    {
        return Ok(picked);
    }

    let browsers = discover_local_browsers();
    for b in &browsers {
        if b.user_data_dir.is_dir() {
            return Ok(b.user_data_dir.clone());
        }
    }
    bail!(
        "No target path specified and no local browser User Data directory was found.\nPass a path explicitly: `chrome2rust analyze <USER_DATA_DIR>` (or pass `--pick`)."
    );
}

fn build_cache_scan_options(f: &CacheFilterArgs, compute_hashes: bool) -> Result<CacheScanOptions> {
    let mut since: Option<DateTime<Utc>> = None;
    if let Some(s) = &f.since {
        since = Some(parse_user_datetime(s).map_err(|e| anyhow!(e))?);
    }
    if let Some(last_spec) = &f.last {
        let dur = parse_relative_duration(last_spec).map_err(|e| anyhow!(e))?;
        let cutoff = Utc::now()
            .checked_sub_signed(dur)
            .ok_or_else(|| anyhow!("Duration '{last_spec}' exceeds valid timestamp range"))?;
        since = Some(match since {
            Some(existing) => existing.max(cutoff),
            None => cutoff,
        });
    }
    let until = match &f.until {
        Some(u) => Some(parse_user_datetime(u).map_err(|e| anyhow!(e))?),
        None => None,
    };

    Ok(CacheScanOptions {
        include_zero_length: !f.no_zero_length,
        url_filter: f.url.clone(),
        content_type_filter: f.content_type.clone(),
        quick_filter: f.filter.clone(),
        min_size: f.min_size,
        max_size: f.max_size,
        since,
        until,
        compute_hashes,
        decompress_sizes: true,
    })
}

fn parse_columns(spec: Option<&str>) -> Result<Vec<CacheColumn>> {
    let Some(raw) = spec else {
        return Ok(CacheColumn::default_columns());
    };
    let mut cols = Vec::new();
    for part in raw.split(',') {
        let trimmed = part.trim();
        if trimmed.is_empty() {
            continue;
        }
        let col = CacheColumn::from_name(trimmed).ok_or_else(|| {
            anyhow!(
                "Unknown cache column '{trimmed}'. Valid columns: url, content-type, detected-content-type, detected-extension, file-signature, mime-mismatch, size, compressed-size, last-accessed, server-time, created, expires, server, response, encoding, cache-name, url-length, website, frame, server-ip, deleted, sha256, backend"
            )
        })?;
        cols.push(col);
    }
    if cols.is_empty() {
        return Ok(CacheColumn::default_columns());
    }
    Ok(cols)
}

fn cmd_cache_list(args: CacheListArgs, pick: bool, audit_manifest: Option<&Path>) -> Result<()> {
    let (dirs, root_ref) = resolve_cli_cache_dirs(args.filter_args.path.as_ref(), pick)?;
    let opts = build_cache_scan_options(&args.filter_args, args.hashes)?;
    let columns = parse_columns(args.columns.as_deref())?;

    if is_shutdown_requested() {
        bail!("Aborted by user interrupt");
    }

    let (mut entries, warnings) = load_cache_from_paths(&dirs, &opts);
    for w in &warnings {
        warn!(
            severity = ?w.severity,
            component = %w.component,
            artifact = %w.artifact_path,
            message = %w.message,
            "Cache warning"
        );
    }

    let primary =
        CacheSortField::from_name(&args.sort).ok_or_else(|| anyhow!("Unknown --sort field '{}'", args.sort))?;
    let default_desc = matches!(
        primary,
        CacheSortField::LastAccessed
            | CacheSortField::ServerTime
            | CacheSortField::RecordCreatedTime
            | CacheSortField::ExpirationTime
            | CacheSortField::FileSize
            | CacheSortField::MimeMismatch
    );
    let primary_desc = if args.asc {
        false
    } else if args.desc {
        true
    } else {
        default_desc
    };

    let secondary = match &args.secondary_sort {
        Some(s) => {
            let f = CacheSortField::from_name(s).ok_or_else(|| anyhow!("Unknown --secondary-sort field '{s}'"))?;
            Some((f, args.secondary_desc))
        }
        None => None,
    };

    sort_cache_entries(&mut entries, primary, primary_desc, secondary);

    let rendered = render_cache_export(&entries, args.format.into(), &columns, !args.no_header, args.millis)
        .map_err(|e| anyhow!(e.to_string()))?;

    match args.output {
        Some(out_path) if out_path.as_os_str() != "-" => {
            if let Some(parent) = out_path.parent().filter(|p| !p.as_os_str().is_empty()) {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(&out_path, &rendered)?;
            eprintln!("Wrote {} cache entries to {}", entries.len(), out_path.display());
        }
        _ => {
            print!("{rendered}");
        }
    }

    if let Some(target_path) = root_ref.as_deref().or_else(|| dirs.first().map(PathBuf::as_path)) {
        maybe_write_audit_manifest(target_path, audit_manifest)?;
    }

    Ok(())
}

fn cmd_cache_extract(args: CacheExtractArgs, pick: bool, audit_manifest: Option<&Path>) -> Result<()> {
    let (dirs, root_ref) = resolve_cli_cache_dirs(args.filter_args.path.as_ref(), pick)?;
    let scan_opts = build_cache_scan_options(&args.filter_args, false)?;
    let (entries, warnings) = load_cache_from_paths(&dirs, &scan_opts);
    for w in &warnings {
        warn!(
            severity = ?w.severity,
            component = %w.component,
            artifact = %w.artifact_path,
            message = %w.message,
            "Cache warning"
        );
    }

    let refs: Vec<&CacheEntry> = entries.iter().collect();
    let extract_opts = ExtractOptions {
        output_dir: args.output_dir.clone(),
        filename_mode: args.filename_mode.into(),
        use_website_dir_structure: args.website_dirs,
        update_modified_time: !args.no_update_mtime,
        new_name_if_exist: !args.overwrite,
        decompress: !args.no_decompress,
        prefer_detected_extension: args.use_detected_ext,
    };

    let summary = extract_cache_entries(&refs, &extract_opts).map_err(|e| anyhow!(e.to_string()))?;

    println!(
        "Extracted {} files ({} written) into {} | skipped (empty/deleted): {} | failed: {}",
        summary.extracted_count,
        format_bytes(summary.bytes_written),
        args.output_dir.display(),
        summary.skipped_empty_or_deleted,
        summary.failed_count
    );
    for err in summary.errors.iter().take(20) {
        eprintln!("  Error: {err}");
    }

    if let Some(target_path) = root_ref.as_deref().or_else(|| dirs.first().map(PathBuf::as_path)) {
        maybe_write_audit_manifest(target_path, audit_manifest)?;
    }
    Ok(())
}

fn cmd_cache_inspect(args: CacheInspectArgs, pick: bool) -> Result<()> {
    let path = match args.path {
        Some(p) => p,
        None if pick => pick_source_dialog("Select Chrome Simple Cache File (*_0) or Directory")
            .ok_or_else(|| anyhow!("Selection canceled by user"))?,
        None => bail!("Missing <PATH>. Provide a *_0 file or directory, or pass --pick."),
    };

    if !path.exists() {
        bail!("Path does not exist: {}", path.display());
    }

    let entry: CacheEntry = if path.is_file() {
        let parent = path.parent().unwrap_or_else(|| Path::new("."));
        let opts = CacheScanOptions {
            compute_hashes: true,
            ..Default::default()
        };
        parse_simple_entry_file(&path, parent, &opts)
            .map_err(|e| anyhow!(e.to_string()))?
            .ok_or_else(|| anyhow!("File is not a valid Simple Cache entry: {}", path.display()))?
    } else {
        let target = resolve_target_path(&path);
        let dirs = if target.cache_dirs.is_empty() {
            vec![path.clone()]
        } else {
            target.cache_dirs
        };
        let opts = CacheScanOptions {
            quick_filter: args.url.clone(),
            compute_hashes: true,
            ..Default::default()
        };
        let (mut entries, _) = load_cache_from_paths(&dirs, &opts);
        if entries.is_empty() {
            bail!("No cache entry found in {} matching {:?}", path.display(), args.url);
        }
        entries.remove(0)
    };

    if let Some(dump_path) = &args.dump_body {
        let payload = entry.read_decompressed_payload().map_err(|e| anyhow!(e.to_string()))?;
        if let Some(parent) = dump_path.parent().filter(|p| !p.as_os_str().is_empty()) {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(dump_path, &payload)?;
        eprintln!("Dumped {} bytes to {}", payload.len(), dump_path.display());
    }

    if args.json {
        println!("{}", serde_json::to_string_pretty(&entry)?);
        return Ok(());
    }

    println!("URL             : {}", entry.url);
    println!("Raw Key         : {}", entry.raw_key);
    if let Some(ws) = &entry.partition_website {
        println!("Web Site        : {ws}");
    }
    if let Some(fr) = &entry.partition_frame {
        println!("Frame           : {fr}");
    }
    println!("Backend         : {}", entry.backend.as_str());
    println!("Cache Name      : {}", entry.cache_name);
    println!("Cache File      : {}", entry.cache_file_path);
    println!(
        "Content-Type    : {}",
        entry
            .raw_content_type
            .as_deref()
            .or(entry.content_type.as_deref())
            .unwrap_or("-")
    );
    if let Some(det_ct) = &entry.detected_content_type {
        println!("Detected Type   : {det_ct}");
    }
    if let Some(ext) = &entry.detected_extension {
        println!("Suggested Ext   : .{ext}");
    }
    if let Some(sig) = &entry.file_signature {
        println!("File Signature  : {sig}");
    }
    if let Some(disp) = &entry.content_disposition_filename {
        println!("Disposition File: {disp}");
    }
    if entry.mime_mismatch {
        println!("MIME Mismatch   : WARNING - Declared Content-Type contradicts detected payload");
    }
    println!(
        "Encoding        : {}",
        entry.content_encoding.as_deref().unwrap_or("identity")
    );
    println!(
        "Size            : {} bytes (compressed stored: {} bytes)",
        entry.file_size, entry.compressed_size
    );
    if let Some(sha) = &entry.payload_sha256 {
        println!("SHA-256         : {sha}");
    }
    if let Some(crc) = entry.crc32_valid {
        println!("CRC-32 Valid    : {crc}");
    }
    println!("Server Response : {}", entry.server_response);
    println!("Server Name     : {}", entry.server_name.as_deref().unwrap_or("-"));
    println!(
        "Server IP       : {}",
        match (&entry.server_ip, entry.server_port) {
            (Some(ip), Some(p)) => format!("{ip}:{p}"),
            (Some(ip), None) => ip.clone(),
            _ => "-".into(),
        }
    );
    if let Some(tls) = &entry.tls_version {
        println!("TLS Version     : {tls}");
    }
    if let Some(alpn) = &entry.alpn_protocol {
        println!("ALPN Protocol   : {alpn}");
    }
    println!("Last Accessed   : {}", format_local_opt(entry.last_accessed, true));
    println!("Server Time     : {}", format_utc_opt(entry.server_time, false));
    println!(
        "Record Created  : {}",
        format_local_opt(entry.record_created_time, true)
    );
    println!("Expiration Time : {}", format_utc_opt(entry.expiration_time, false));

    if !entry.headers.is_empty() {
        println!("\n-- HTTP Response Headers --");
        for h in &entry.headers {
            println!("  {}: {}", h.name, h.value);
        }
    }

    if !entry.certificates.is_empty() {
        println!("\n-- X.509 Certificate Chain --");
        for (idx, cert) in entry.certificates.iter().enumerate() {
            println!("  [{}] Subject   : {}", idx, cert.subject);
            println!("      Issuer    : {}", cert.issuer);
            println!(
                "      Validity  : {} -> {}",
                cert.not_before.as_deref().unwrap_or("?"),
                cert.not_after.as_deref().unwrap_or("?")
            );
        }
    }

    if args.preview {
        let payload = entry.read_decompressed_payload().map_err(|e| anyhow!(e.to_string()))?;
        println!("\n-- Payload Preview ({} bytes total) --", payload.len());
        let slice = &payload[..payload.len().min(4096)];
        if entry.is_text_like() || std::str::from_utf8(slice).is_ok() {
            println!("{}", String::from_utf8_lossy(slice));
        } else {
            for (row_idx, chunk) in slice.chunks(16).enumerate().take(32) {
                let hex: Vec<String> = chunk.iter().map(|b| format!("{b:02x}")).collect();
                let ascii: String = chunk
                    .iter()
                    .map(|&b| {
                        if b.is_ascii_graphic() || b == b' ' {
                            b as char
                        } else {
                            '.'
                        }
                    })
                    .collect();
                println!("  {:04x}: {:47}  |{}|", row_idx * 16, hex.join(" "), ascii);
            }
        }
    }

    Ok(())
}

fn cmd_cache_delete(args: CacheDeleteArgs, pick: bool) -> Result<()> {
    let (dirs, _) = resolve_cli_cache_dirs(args.filter_args.path.as_ref(), pick)?;
    let opts = build_cache_scan_options(&args.filter_args, false)?;
    let (entries, _) = load_cache_from_paths(&dirs, &opts);

    if entries.is_empty() {
        println!("No matching cache entries found.");
        return Ok(());
    }

    if !args.yes {
        println!(
            "Dry run: {} matching entries would be evaluated for deletion (pass --yes to delete):",
            entries.len()
        );
        for e in entries.iter().take(25) {
            let deletable = match e.backend {
                CacheBackendKind::SimpleCache => true,
                CacheBackendKind::Blockfile => e.cache_name.starts_with("f_"),
            };
            println!(
                "  [{}] {} | {} ({})",
                if deletable { "deletable" } else { "embedded" },
                e.cache_name,
                e.url,
                format_bytes(e.file_size as u64)
            );
        }
        if entries.len() > 25 {
            println!("  ... and {} more", entries.len() - 25);
        }
        return Ok(());
    }

    let refs: Vec<&CacheEntry> = entries.iter().collect();
    let (deleted, skipped) = delete_cache_entries(&refs);
    println!("Deleted {deleted} standalone cache files ({} skipped).", skipped.len());
    for s in skipped.iter().take(20) {
        println!("  Skipped: {s}");
    }
    Ok(())
}

fn make_crypto_opts(decrypt: bool, keys: Vec<String>, no_peanuts: bool) -> CryptoOptions {
    CryptoOptions {
        decrypt_enabled: decrypt,
        supplied_keys: keys,
        allow_linux_peanuts: !no_peanuts,
    }
}

fn cmd_analyze(args: AnalyzeArgs, pick: bool, audit_manifest: Option<&Path>) -> Result<()> {
    let target = resolve_cli_analysis_path(args.path.as_ref(), pick)?;
    let opts = AnalysisOptions {
        cache_options: CacheScanOptions {
            compute_hashes: args.hashes,
            ..Default::default()
        },
        crypto_options: make_crypto_opts(args.decrypt, args.keys, args.no_peanuts),
        extra_cache_dirs: args.extra_cache,
        include_timeline: true,
    };

    let report = analyze_user_data(&target, &opts);
    maybe_write_audit_manifest(&target, audit_manifest)?;

    if args.json {
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }

    print_analysis_summary(&report);
    Ok(())
}

fn cmd_report(args: ReportArgs, pick: bool, audit_manifest: Option<&Path>) -> Result<()> {
    let target = resolve_cli_analysis_path(args.path.as_ref(), pick)?;
    let format = ReportFormat::from_name(&args.format).map_err(|e| anyhow!(e))?;
    let opts = AnalysisOptions {
        cache_options: CacheScanOptions {
            compute_hashes: !args.no_hashes,
            ..Default::default()
        },
        crypto_options: make_crypto_opts(args.decrypt, args.keys, args.no_peanuts),
        extra_cache_dirs: args.extra_cache,
        include_timeline: true,
    };

    let report = analyze_user_data(&target, &opts);
    let written = write_report(&report, &args.output, format).context("Failed writing forensic report")?;
    maybe_write_audit_manifest(&target, audit_manifest)?;

    println!("Generated forensic report for {}:", report.target_path);
    for p in written {
        println!("  -> {}", p.display());
    }
    println!(
        "Summary: {} profiles | {} cache entries ({}) | {} URLs | {} downloads | {} cookies | {} logins | {} findings",
        report.summary.profile_count,
        report.summary.total_cache_entries,
        format_bytes(report.summary.total_cache_bytes),
        report.summary.total_history_urls,
        report.summary.total_downloads,
        report.summary.total_cookies,
        report.summary.total_logins,
        report.summary.total_findings,
    );
    Ok(())
}

fn cmd_custody(args: CustodyArgs, pick: bool) -> Result<()> {
    let target = resolve_cli_analysis_path(args.path.as_ref(), pick)?;
    let manifest = generate_custody_manifest(&target)
        .with_context(|| format!("Failed generating chain-of-custody manifest for {}", target.display()))?;

    if let Some(dest) = &args.output_manifest {
        write_custody_manifest(&manifest, dest).map_err(|e| anyhow!("Failed writing custody manifest: {e}"))?;
        eprintln!(
            "Wrote custody manifest ({} files) to {}",
            manifest.artifact_count,
            dest.display()
        );
    }

    if args.json {
        println!("{}", serde_json::to_string_pretty(&manifest)?);
        return Ok(());
    }

    println!("============================================================");
    println!("chrome2rust Chain-of-Custody Manifest");
    println!("============================================================");
    println!("Target Path   : {}", manifest.target_path);
    println!("Tool Version  : chrome2rust {}", manifest.tool_version);
    println!("Generated At  : {}", manifest.generated_at.to_rfc3339());
    println!("Artifacts     : {}", manifest.artifact_count);
    println!(
        "Total Bytes   : {} ({} bytes)",
        format_bytes(manifest.total_bytes),
        manifest.total_bytes
    );
    println!("Merkle Root   : {}", manifest.merkle_root_sha256);
    println!("============================================================");
    for a in manifest.artifacts.iter().take(20) {
        println!(
            "  [{}] {}  {}  ({})",
            a.category,
            &a.sha256[..16],
            a.relative_path,
            format_bytes(a.size_bytes)
        );
    }
    if manifest.artifacts.len() > 20 {
        println!("  ... and {} additional hashed files", manifest.artifacts.len() - 20);
    }
    Ok(())
}

fn cmd_pick(args: PickArgs) -> Result<()> {
    let mut base = rfd::FileDialog::new();
    if let Some(ref title) = args.title {
        base = base.set_title(title);
    }
    if let Some(ref dir) = args.dir {
        base = base.set_directory(dir);
    }

    match args.kind.to_ascii_lowercase().as_str() {
        "folder" | "dir" => {
            if let Some(p) = base.pick_folder() {
                println!("{}", p.display());
            } else {
                std::process::exit(1);
            }
        }
        "files" | "multi" => {
            if let Some(paths) = base.pick_files() {
                for p in paths {
                    println!("{}", p.display());
                }
            } else {
                std::process::exit(1);
            }
        }
        "save" => {
            let ext = args.ext.trim_start_matches('.');
            let dlg = base.set_file_name(format!("forensic_output.{ext}"));
            if let Some(p) = dlg.save_file() {
                println!("{}", p.display());
            } else {
                std::process::exit(1);
            }
        }
        _ => {
            if let Some(p) = base.pick_file() {
                println!("{}", p.display());
            } else {
                std::process::exit(1);
            }
        }
    }
    Ok(())
}

fn cmd_gui(args: GuiArgs, pick: bool) -> Result<()> {
    let exe_dir = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(Path::to_path_buf));

    let resolve_candidate = |bin_name: &str| -> PathBuf {
        exe_dir
            .as_ref()
            .map(|d| d.join(bin_name))
            .filter(|p| p.is_file())
            .unwrap_or_else(|| PathBuf::from(bin_name))
    };

    let candidate = if cfg!(windows) && !args.iced {
        let win32_bin = resolve_candidate("chrome2rust-win32.exe");
        let iced_bin = resolve_candidate("chrome2rust-iced.exe");
        if win32_bin.is_file() || !iced_bin.is_file() {
            win32_bin
        } else {
            iced_bin
        }
    } else if cfg!(windows) {
        resolve_candidate("chrome2rust-iced.exe")
    } else {
        resolve_candidate("chrome2rust-iced")
    };

    let mut cmd = std::process::Command::new(&candidate);
    if let Some(path) = &args.path {
        cmd.arg(path);
    } else if pick {
        cmd.arg("--pick");
    }
    if args.decrypt {
        cmd.arg("--decrypt");
    }
    for k in &args.keys {
        cmd.arg("--key").arg(k);
    }

    cmd.spawn()
        .with_context(|| format!("Failed to launch GUI executable {}", candidate.display()))?;
    Ok(())
}

fn cmd_mcp(args: McpArgs) -> Result<()> {
    if args.tools {
        let tools = chrome2rust_mcp::get_tools_manifest();
        println!("{}", serde_json::to_string_pretty(&tools)?);
        return Ok(());
    }
    chrome2rust_mcp::run_stdio_server().map_err(|e| anyhow!(e.to_string()))
}

fn print_analysis_summary(report: &UserDataReport) {
    let s = &report.summary;
    println!("============================================================");
    println!("chrome2rust Forensic Analysis Summary");
    println!("============================================================");
    println!("Target Path     : {}", report.target_path);
    println!("Target Kind     : {}", default_target_kind_label(&report.target_kind));
    if let Some(v) = &report.local_state.chrome_version {
        println!("Chrome Version  : {v}");
    }
    println!(
        "OS Crypt Key    : {}",
        if report.local_state.os_crypt_encrypted_key_present {
            "Present"
        } else {
            "Absent"
        }
    );
    println!("Profiles        : {}", s.profile_count);
    println!(
        "HTTP Cache      : {} entries ({})",
        s.total_cache_entries,
        format_bytes(s.total_cache_bytes)
    );
    println!(
        "History         : {} URLs / {} visits / {} downloads",
        s.total_history_urls, s.total_history_visits, s.total_downloads
    );
    println!(
        "Creds & Cookies : {} logins | {} cookies | {} autofill",
        s.total_logins, s.total_cookies, s.total_autofill_entries
    );
    println!(
        "Bookmarks/Exts  : {} bookmarks | {} extensions",
        s.total_bookmarks, s.total_extensions
    );
    println!(
        "Sessions/Store  : {} open tabs | {} closed tabs | {} storage keys",
        s.total_open_tabs, s.total_closed_tabs, s.total_local_storage_keys
    );
    println!("Timeline Events : {}", s.total_timeline_events);

    println!("\n-- Forensic Findings ({}) --", report.findings.len());
    if report.findings.is_empty() {
        println!("  (none)");
    } else {
        for f in &report.findings {
            let icon = match f.severity {
                FindingSeverity::Critical => "CRIT",
                FindingSeverity::High => "HIGH",
                FindingSeverity::Medium => "MED ",
                FindingSeverity::Low => "LOW ",
                FindingSeverity::Info => "INFO",
            };
            println!("  [{icon}] [{}] {}: {}", f.profile, f.category, f.title);
            println!("         {}", f.summary);
        }
    }

    if !report.top_domains.is_empty() {
        println!("\n-- Top Domains --");
        for d in report.top_domains.iter().take(12) {
            println!(
                "  {:<35} visits={:<5} cache={:<4} ({}) cookies={}",
                d.domain,
                d.history_visits,
                d.cache_items,
                format_bytes(d.cache_bytes),
                d.cookies
            );
        }
    }

    if !report.warnings.is_empty() {
        println!("\n-- Diagnostic Warnings ({}) --", report.warnings.len());
        for w in report.warnings.iter().take(10) {
            println!(
                "  [{:?}:{}] {}: {}",
                w.severity, w.component, w.artifact_path, w.message
            );
        }
    }
}

pub fn default_target_kind_label(k: &TargetKind) -> &'static str {
    match k {
        TargetKind::UserDataRoot => "User Data Root",
        TargetKind::ProfileDir => "Profile Directory",
        TargetKind::CacheDir => "Cache Directory",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_parses_gui_iced_decrypt_and_key_flags() {
        let cli = Cli::try_parse_from([
            "chrome2rust",
            "gui",
            "--iced",
            "--decrypt",
            "--key",
            "secret",
            r"C:\ChromeData",
        ])
        .unwrap();
        match cli.command {
            Some(Commands::Gui(g)) => {
                assert!(g.iced);
                assert!(g.decrypt);
                assert_eq!(g.keys, vec!["secret"]);
                assert_eq!(g.path, Some(PathBuf::from(r"C:\ChromeData")));
            }
            other => panic!("Unexpected command: {other:?}"),
        }
    }
}
