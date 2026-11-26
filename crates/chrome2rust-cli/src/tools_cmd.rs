use anyhow::{Context, Result, anyhow};
use chrome2rust_cache::carve_images::ImageCarveTableProvider;
use chrome2rust_cache::carve_video::VideoCarveTableProvider;
use chrome2rust_core::discovery::UnifiedBrowserKind;
use chrome2rust_forensics::providers::build_browser_tool_provider_by_id;
use chrome2rust_forensics::search_queries::SearchQueriesTableProvider;
use chrome2rust_forensics::unified::{
    UnifiedAddonsTableProvider, UnifiedAutofillTableProvider, UnifiedBookmarksTableProvider,
    UnifiedDownloadsTableProvider, UnifiedHistoryTableProvider, UnifiedQueryOptions,
};
use chrome2rust_report::table_export::{
    parse_table_export_format, render_table_data_export, write_table_data_custody_manifest, write_table_data_export,
};
use clap::{Args, Subcommand};
use guap_export::ExportFormat;
use guap_table::{FilterExpr, GetNirQuery, SortDirection, TableData, TableProvider, TableQuery};
use std::path::{Path, PathBuf};
use std::sync::Arc;

#[derive(Args, Debug, Clone)]
pub struct TableToolArgs {
    /// Target browser profile, cache directory, or multi-browser container (auto-discovers local browsers when omitted)
    #[arg(value_name = "PATH")]
    pub path: Option<PathBuf>,

    /// Filter expression (GetNir syntax e.g. `url contains 'example'` or plain substring)
    #[arg(long)]
    pub filter: Option<String>,

    /// Sort specification (e.g. `visit_time:desc` or column name)
    #[arg(long)]
    pub sort: Option<String>,

    /// Sort descending when passing a plain column name to --sort
    #[arg(long)]
    pub desc: bool,

    /// Comma-separated list of column IDs to project
    #[arg(long, value_delimiter = ',')]
    pub columns: Option<Vec<String>>,

    /// Pagination row offset
    #[arg(long, default_value_t = 0)]
    pub offset: usize,

    /// Maximum rows to return
    #[arg(long)]
    pub limit: Option<usize>,

    /// Output format: table, csv, tsv, json, jsonl, html, vhtml, markdown
    #[arg(short = 'f', long, default_value = "table")]
    pub format: String,

    /// Write exported output to file instead of stdout
    #[arg(short = 'o', long)]
    pub output: Option<PathBuf>,

    /// Optional JSON custody manifest path (SHA-256 & SHA-512 Merkle roots)
    #[arg(long)]
    pub custody_manifest: Option<PathBuf>,

    /// Include detail_json field in JSON/JSONL exports
    #[arg(long)]
    pub detail: bool,
}

#[derive(Args, Debug, Clone)]
pub struct UnifiedTableToolArgs {
    #[command(flatten)]
    pub common: TableToolArgs,

    /// Filter to a specific browser (chrome, edge, brave, opera, firefox, safari)
    #[arg(long)]
    pub browser: Option<String>,
}

#[derive(Args, Debug, Clone)]
pub struct SearchQueriesArgs {
    #[command(flatten)]
    pub common: TableToolArgs,

    /// Filter to a specific browser (chrome, edge, brave, opera, firefox, safari)
    #[arg(long)]
    pub browser: Option<String>,

    /// Filter to a specific search engine (Google, Bing, DuckDuckGo, Yahoo, Yandex, Baidu, YouTube, Brave Search)
    #[arg(long)]
    pub engine: Option<String>,
}

#[derive(Args, Debug, Clone)]
pub struct CarveImagesArgs {
    #[command(flatten)]
    pub common: TableToolArgs,

    /// Optional directory to write carved image files with sanitized filenames
    #[arg(long)]
    pub extract_dir: Option<PathBuf>,

    /// Minimum image payload size in bytes
    #[arg(long)]
    pub min_size: Option<usize>,
}

#[derive(Args, Debug, Clone)]
pub struct CarveVideoArgs {
    #[command(flatten)]
    pub common: TableToolArgs,

    /// Optional directory to write carved / reassembled video files
    #[arg(long)]
    pub extract_dir: Option<PathBuf>,
}

#[derive(Subcommand, Debug)]
pub enum FxSubcommand {
    /// Inspect Mozilla Firefox cache2/entries (MZCacheView equivalent)
    Cache(TableToolArgs),
    /// Inspect Mozilla Firefox browsing history from places.sqlite (MZHistoryView equivalent)
    History(TableToolArgs),
    /// Inspect Mozilla Firefox cookies.sqlite metadata only (values omitted) (MZCookiesView equivalent)
    Cookies(TableToolArgs),
    /// Inspect Mozilla Firefox bookmarks from places.sqlite & bookmarkbackups/*.jsonlz4
    Bookmarks(TableToolArgs),
    /// Inspect Mozilla Firefox downloads from places.sqlite moz_annos
    Downloads(TableToolArgs),
    /// Inspect Mozilla Firefox non-credential form autofill history (formhistory.sqlite)
    Formhistory(TableToolArgs),
    /// Inspect Mozilla Firefox add-ons & extensions (extensions.json / addons.json)
    Addons(TableToolArgs),
    /// Inspect Mozilla Firefox open & closed session tabs (sessionstore.jsonlz4 / recovery.jsonlz4)
    Sessions(TableToolArgs),
}

#[derive(Subcommand, Debug)]
pub enum OperaSubcommand {
    /// Inspect Opera Blink & Presto (dcache4.url) HTTP caches (OperaCacheView equivalent)
    Cache(TableToolArgs),
    /// Inspect Opera Blink History SQLite & Presto global_history.dat / opera6.adr
    History(TableToolArgs),
}

#[derive(Subcommand, Debug)]
pub enum SafariSubcommand {
    /// Inspect Apple Safari Cache.db & fsCachedData (SafariCacheView equivalent)
    Cache(TableToolArgs),
    /// Inspect Apple Safari History.db & History.plist (SafariHistoryView equivalent)
    History(TableToolArgs),
    /// Inspect Apple Safari Bookmarks.plist recursively (bplist00 or XML plist)
    Bookmarks(TableToolArgs),
}

#[derive(Subcommand, Debug)]
pub enum UnifiedSubcommand {
    /// Aggregate normalized browsing history across Chrome, Edge, Brave, Opera, Firefox & Safari (BrowsingHistoryView)
    History(UnifiedTableToolArgs),
    /// Aggregate normalized download histories across browsers (BrowserDownloadsView)
    Downloads(UnifiedTableToolArgs),
    /// Aggregate normalized extensions/add-ons & risk flags across browsers (BrowserAddonsView)
    Addons(UnifiedTableToolArgs),
    /// Aggregate normalized bookmarks across browsers (WebBrowserBookmarksView)
    Bookmarks(UnifiedTableToolArgs),
    /// Aggregate non-credential form autofill across Web Data (autofill only) & Firefox formhistory.sqlite
    Autofill(UnifiedTableToolArgs),
}

#[derive(Subcommand, Debug)]
pub enum CarveSubcommand {
    /// Carve cached images with magic-byte validation, dimensions & pure-Rust TIFF/EXIF + GPS metadata (ImageCacheViewer)
    Images(CarveImagesArgs),
    /// Carve cached videos (MP4/M4S, WebM, MPEG-TS, HLS .m3u8, DASH .mpd) & 3-pass segment reassembly (VideoCacheView)
    Video(CarveVideoArgs),
}

pub fn run_fx(action: FxSubcommand, audit_manifest: Option<&Path>) -> Result<()> {
    let (tool_id, args) = match action {
        FxSubcommand::Cache(a) => ("chrome2rust_fx_cache", a),
        FxSubcommand::History(a) => ("chrome2rust_fx_history", a),
        FxSubcommand::Cookies(a) => ("chrome2rust_fx_cookies", a),
        FxSubcommand::Bookmarks(a) => ("chrome2rust_fx_bookmarks", a),
        FxSubcommand::Downloads(a) => ("chrome2rust_fx_downloads", a),
        FxSubcommand::Formhistory(a) => ("chrome2rust_fx_formhistory", a),
        FxSubcommand::Addons(a) => ("chrome2rust_fx_addons", a),
        FxSubcommand::Sessions(a) => ("chrome2rust_fx_sessions", a),
    };
    let provider = build_browser_tool_provider_by_id(tool_id, args.path.as_deref())
        .ok_or_else(|| anyhow!("unknown tool id: {tool_id}"))?;
    execute_provider_cmd(provider.as_ref(), &args, audit_manifest)
}

pub fn run_opera(action: OperaSubcommand, audit_manifest: Option<&Path>) -> Result<()> {
    let (tool_id, args) = match action {
        OperaSubcommand::Cache(a) => ("chrome2rust_opera_cache", a),
        OperaSubcommand::History(a) => ("chrome2rust_opera_history", a),
    };
    let provider = build_browser_tool_provider_by_id(tool_id, args.path.as_deref())
        .ok_or_else(|| anyhow!("unknown tool id: {tool_id}"))?;
    execute_provider_cmd(provider.as_ref(), &args, audit_manifest)
}

pub fn run_safari(action: SafariSubcommand, audit_manifest: Option<&Path>) -> Result<()> {
    let (tool_id, args) = match action {
        SafariSubcommand::Cache(a) => ("chrome2rust_safari_cache", a),
        SafariSubcommand::History(a) => ("chrome2rust_safari_history", a),
        SafariSubcommand::Bookmarks(a) => ("chrome2rust_safari_bookmarks", a),
    };
    let provider = build_browser_tool_provider_by_id(tool_id, args.path.as_deref())
        .ok_or_else(|| anyhow!("unknown tool id: {tool_id}"))?;
    execute_provider_cmd(provider.as_ref(), &args, audit_manifest)
}

fn parse_browser_filter(raw: Option<&str>) -> Result<Option<UnifiedBrowserKind>> {
    match raw {
        Some(s) if !s.trim().is_empty() => UnifiedBrowserKind::from_filter(s)
            .map(Some)
            .ok_or_else(|| anyhow!("Unsupported browser filter '{s}'")),
        _ => Ok(None),
    }
}

pub fn run_unified(action: UnifiedSubcommand, audit_manifest: Option<&Path>) -> Result<()> {
    match action {
        UnifiedSubcommand::History(a) => {
            let opts = UnifiedQueryOptions {
                paths: a.common.path.clone().into_iter().collect(),
                browser_filter: parse_browser_filter(a.browser.as_deref())?,
                ..Default::default()
            };
            let provider = UnifiedHistoryTableProvider::with_options(opts);
            execute_provider_cmd(&provider, &a.common, audit_manifest)
        }
        UnifiedSubcommand::Downloads(a) => {
            let opts = UnifiedQueryOptions {
                paths: a.common.path.clone().into_iter().collect(),
                browser_filter: parse_browser_filter(a.browser.as_deref())?,
                ..Default::default()
            };
            let provider = UnifiedDownloadsTableProvider::with_options(opts);
            execute_provider_cmd(&provider, &a.common, audit_manifest)
        }
        UnifiedSubcommand::Addons(a) => {
            let opts = UnifiedQueryOptions {
                paths: a.common.path.clone().into_iter().collect(),
                browser_filter: parse_browser_filter(a.browser.as_deref())?,
                ..Default::default()
            };
            let provider = UnifiedAddonsTableProvider::with_options(opts);
            execute_provider_cmd(&provider, &a.common, audit_manifest)
        }
        UnifiedSubcommand::Bookmarks(a) => {
            let opts = UnifiedQueryOptions {
                paths: a.common.path.clone().into_iter().collect(),
                browser_filter: parse_browser_filter(a.browser.as_deref())?,
                ..Default::default()
            };
            let provider = UnifiedBookmarksTableProvider::with_options(opts);
            execute_provider_cmd(&provider, &a.common, audit_manifest)
        }
        UnifiedSubcommand::Autofill(a) => {
            let opts = UnifiedQueryOptions {
                paths: a.common.path.clone().into_iter().collect(),
                browser_filter: parse_browser_filter(a.browser.as_deref())?,
                ..Default::default()
            };
            let provider = UnifiedAutofillTableProvider::with_options(opts);
            execute_provider_cmd(&provider, &a.common, audit_manifest)
        }
    }
}

pub fn run_search_queries(args: SearchQueriesArgs, audit_manifest: Option<&Path>) -> Result<()> {
    let opts = UnifiedQueryOptions {
        paths: args.common.path.clone().into_iter().collect(),
        browser_filter: parse_browser_filter(args.browser.as_deref())?,
        ..Default::default()
    };
    let provider = SearchQueriesTableProvider::with_options(opts, args.engine.clone());
    execute_provider_cmd(&provider, &args.common, audit_manifest)
}

pub fn run_carve(action: CarveSubcommand, audit_manifest: Option<&Path>) -> Result<()> {
    let provider: Arc<dyn TableProvider> = match action {
        CarveSubcommand::Images(ref a) => Arc::new(ImageCarveTableProvider::with_options(
            a.common.path.clone().into_iter().collect(),
            a.extract_dir.clone(),
            a.min_size,
        )),
        CarveSubcommand::Video(ref a) => Arc::new(VideoCarveTableProvider::with_options(
            a.common.path.clone().into_iter().collect(),
            a.extract_dir.clone(),
        )),
    };
    let common = match &action {
        CarveSubcommand::Images(a) => &a.common,
        CarveSubcommand::Video(a) => &a.common,
    };
    execute_provider_cmd(provider.as_ref(), common, audit_manifest)
}

fn build_table_query(provider: &dyn TableProvider, args: &TableToolArgs) -> Result<TableQuery> {
    let schema = provider.schema();
    let filter = match &args.filter {
        Some(f) if !f.trim().is_empty() => match GetNirQuery::parse_filter(f) {
            Ok(expr) => Some(expr),
            Err(_) => Some(FilterExpr::Contains {
                column: None,
                pattern: f.trim().to_string(),
                case_sensitive: false,
            }),
        },
        _ => None,
    };

    let sort = match &args.sort {
        Some(spec) if !spec.trim().is_empty() => {
            let parsed = GetNirQuery::parse_sort(spec).map_err(|e| anyhow!(e.to_string()))?;
            let mut resolved = Vec::with_capacity(parsed.len());
            for (col, mut dir) in parsed {
                let idx = schema
                    .column_index(&col)
                    .ok_or_else(|| anyhow!("Unknown sort column '{col}'"))?;
                if args.desc && !spec.contains(':') && !spec.starts_with('-') && !spec.starts_with('+') {
                    dir = SortDirection::Desc;
                }
                resolved.push((idx, dir));
            }
            resolved
        }
        _ => Vec::new(),
    };

    Ok(TableQuery {
        filter,
        sort,
        columns: args.columns.clone(),
        offset: args.offset,
        limit: args.limit,
    })
}

fn execute_provider_cmd(
    provider: &dyn TableProvider,
    args: &TableToolArgs,
    global_audit_manifest: Option<&Path>,
) -> Result<()> {
    let query = build_table_query(provider, args)?;
    let data = provider.query(&query).map_err(|e| anyhow!(e.to_string()))?;
    let manifest_dest = args.custody_manifest.as_deref().or(global_audit_manifest);

    if args.format.eq_ignore_ascii_case("table") {
        let rendered = render_console_table(&data);
        if let Some(out_path) = &args.output {
            if let Some(parent) = out_path.parent().filter(|p| !p.as_os_str().is_empty()) {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(out_path, &rendered).with_context(|| format!("Writing {}", out_path.display()))?;
            println!("Wrote {} ({} rows).", out_path.display(), data.rows.len());
        } else {
            print!("{rendered}");
        }
        if let Some(mp) = manifest_dest {
            let export_bytes =
                render_table_data_export(&data, ExportFormat::Json, args.detail).map_err(|e| anyhow!(e.to_string()))?;
            let label = args
                .output
                .as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|| "stdout".to_string());
            write_table_data_custody_manifest(&data, mp, &label, &export_bytes).map_err(|e| anyhow!(e.to_string()))?;
        }
        return Ok(());
    }

    let fmt = parse_table_export_format(&args.format).map_err(|e| anyhow!(e.to_string()))?;
    if let Some(out_path) = &args.output {
        let manifest = write_table_data_export(&data, out_path, fmt, manifest_dest, args.detail)
            .map_err(|e| anyhow!(e.to_string()))?;
        println!(
            "Exported {} rows to {} (SHA-256 Merkle root: {})",
            data.rows.len(),
            out_path.display(),
            manifest.merkle_root_sha256
        );
    } else {
        let bytes = render_table_data_export(&data, fmt, args.detail).map_err(|e| anyhow!(e.to_string()))?;
        if let Some(mp) = manifest_dest {
            write_table_data_custody_manifest(&data, mp, "stdout", &bytes).map_err(|e| anyhow!(e.to_string()))?;
        }
        let text = String::from_utf8_lossy(&bytes);
        print!("{text}");
    }

    Ok(())
}

fn render_console_table(data: &TableData) -> String {
    use std::fmt::Write;
    let mut out = String::new();
    let _ = writeln!(out, "{} ({} rows)", data.schema.title, data.total_rows);
    if data.schema.columns.is_empty() || data.rows.is_empty() {
        let _ = writeln!(out, "(no matching records)");
        return out;
    }

    let mut widths: Vec<usize> = data.schema.columns.iter().map(|c| c.label.len().max(4)).collect();
    let rendered_rows: Vec<Vec<String>> = data
        .rows
        .iter()
        .map(|row| {
            data.schema
                .columns
                .iter()
                .enumerate()
                .map(|(idx, col)| {
                    let s = row
                        .cells
                        .get(idx)
                        .map(|c| c.format_human(col.col_type))
                        .unwrap_or_default();
                    let truncated = if s.chars().count() > 64 {
                        let prefix: String = s.chars().take(61).collect();
                        format!("{prefix}...")
                    } else {
                        s
                    };
                    widths[idx] = widths[idx].max(truncated.chars().count()).min(64);
                    truncated
                })
                .collect()
        })
        .collect();

    let header: Vec<String> = data
        .schema
        .columns
        .iter()
        .enumerate()
        .map(|(i, c)| format!("{:<width$}", c.label, width = widths[i]))
        .collect();
    let _ = writeln!(out, "{}", header.join(" | "));
    let sep: Vec<String> = widths.iter().map(|&w| "-".repeat(w)).collect();
    let _ = writeln!(out, "{}", sep.join("-+-"));

    for r in rendered_rows {
        let line: Vec<String> = r
            .iter()
            .enumerate()
            .map(|(i, val)| format!("{:<width$}", val, width = widths[i]))
            .collect();
        let _ = writeln!(out, "{}", line.join(" | "));
    }
    out
}
