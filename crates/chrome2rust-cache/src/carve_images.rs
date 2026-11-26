use crate::exif::inspect_image_and_exif;
use crate::export::sanitize_filename;
use crate::hex_lower;
use crate::unified_cache::load_unified_cache_from_paths;
use chrome2rust_core::error::DiagnosticWarning;
use chrome2rust_core::magic::{DetectionSource, detect_content};
use chrono::{DateTime, Utc};
use guap_table::{
    CellValue, ColumnDef, ColumnType, Row, SortDirection, TableData, TableError, TableProvider, TableQuery,
    TableSchema, apply_query,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageCarveRecord {
    pub browser: String,
    pub profile: String,
    pub url: String,
    pub format: String,
    pub mime_type: String,
    pub width: Option<u32>,
    pub height: Option<u32>,
    pub file_size: u64,
    pub cache_time: Option<DateTime<Utc>>,
    pub make: Option<String>,
    pub model: Option<String>,
    pub date_time_original: Option<String>,
    pub gps_lat: Option<f64>,
    pub gps_lon: Option<f64>,
    pub exif_summary: String,
    pub sha256: String,
    pub cache_name: String,
    pub extracted_path: Option<String>,
}

fn is_valid_image_mime(mime: &str) -> bool {
    mime.starts_with("image/")
}

/// Carves valid cached images across all discovered/targeted browsers, extracting dimensions,
/// TIFF/EXIF metadata, SHA-256 digests, and rejecting masqueraded non-image payloads.
pub fn carve_images(
    paths: &[PathBuf],
    extract_dir: Option<&Path>,
    min_size: Option<usize>,
) -> (Vec<ImageCarveRecord>, Vec<DiagnosticWarning>) {
    let (items, mut warnings) = load_unified_cache_from_paths(paths, false);
    if let Some(dir) = extract_dir
        && let Err(e) = std::fs::create_dir_all(dir)
    {
        warnings.push(DiagnosticWarning::warn(
            "carve_images",
            dir,
            format!("Failed creating extract directory: {e}"),
        ));
    }

    let mut records = Vec::new();
    let mut seq = 0usize;

    for item in items {
        let bytes = item.read_decompressed_payload();
        if bytes.is_empty() {
            continue;
        }
        if let Some(min) = min_size
            && bytes.len() < min
        {
            continue;
        }

        let det = detect_content(&bytes, item.content_type.as_deref(), Some(&item.url), None);
        // Require verified byte-level detection; never carve unverified payloads via DeclaredContentType alone
        if !matches!(
            det.source,
            DetectionSource::MagicSignature | DetectionSource::ContainerInspection | DetectionSource::TextHeuristic
        ) {
            continue;
        }
        let Some(effective_mime) = det.mime.clone().filter(|m| is_valid_image_mime(m)) else {
            continue;
        };

        let ext = det.extension.clone().unwrap_or_else(|| match effective_mime.as_str() {
            "image/jpeg" => "jpg".into(),
            "image/png" | "image/apng" => "png".into(),
            "image/gif" => "gif".into(),
            "image/webp" => "webp".into(),
            "image/avif" => "avif".into(),
            "image/x-icon" | "image/vnd.microsoft.icon" => "ico".into(),
            "image/svg+xml" => "svg".into(),
            "image/tiff" => "tif".into(),
            "image/bmp" => "bmp".into(),
            _ => "img".into(),
        });

        let info = inspect_image_and_exif(&bytes, Some(&ext));
        let sha256 = hex_lower(&Sha256::digest(&bytes));
        let exif_summary = info.exif.as_ref().map(|e| e.summary()).unwrap_or_default();

        let extracted_path = if let Some(dir) = extract_dir {
            seq += 1;
            let raw_name = url::Url::parse(&item.url)
                .ok()
                .and_then(|u| {
                    u.path_segments()
                        .and_then(|mut s| s.rfind(|seg| !seg.is_empty()).map(str::to_string))
                })
                .unwrap_or_else(|| format!("carved_{seq:04}"));
            let safe_base = sanitize_filename(&raw_name);
            let fname = if let Some((stem, file_ext)) = safe_base.rsplit_once('.')
                && file_ext.eq_ignore_ascii_case(&ext)
                && !stem.is_empty()
            {
                format!("{stem}_{seq:04}.{ext}")
            } else {
                format!("{safe_base}_{seq:04}.{ext}")
            };
            let dest = dir.join(fname);
            match std::fs::write(&dest, &bytes) {
                Ok(()) => Some(dest.display().to_string()),
                Err(e) => {
                    warnings.push(DiagnosticWarning::warn(
                        "carve_images",
                        &dest,
                        format!("Failed writing carved image: {e}"),
                    ));
                    None
                }
            }
        } else {
            None
        };

        records.push(ImageCarveRecord {
            browser: item.browser,
            profile: item.profile,
            url: item.url,
            format: ext.to_ascii_uppercase(),
            mime_type: effective_mime,
            width: info.width,
            height: info.height,
            file_size: bytes.len() as u64,
            cache_time: item.cache_time,
            make: info.exif.as_ref().and_then(|e| e.make.clone()),
            model: info.exif.as_ref().and_then(|e| e.model.clone()),
            date_time_original: info.exif.as_ref().and_then(|e| e.date_time_original.clone()),
            gps_lat: info.exif.as_ref().and_then(|e| e.gps_latitude),
            gps_lon: info.exif.as_ref().and_then(|e| e.gps_longitude),
            exif_summary,
            sha256,
            cache_name: item.cache_name,
            extracted_path,
        });
    }

    records.sort_by(|a, b| b.cache_time.cmp(&a.cache_time).then_with(|| a.url.cmp(&b.url)));
    (records, warnings)
}

pub struct ImageCarveTableProvider {
    paths: Vec<PathBuf>,
    extract_dir: Option<PathBuf>,
    min_size: Option<usize>,
}

impl ImageCarveTableProvider {
    pub fn new(target: Option<PathBuf>) -> Self {
        Self {
            paths: target.into_iter().collect(),
            extract_dir: None,
            min_size: None,
        }
    }

    pub fn with_options(paths: Vec<PathBuf>, extract_dir: Option<PathBuf>, min_size: Option<usize>) -> Self {
        Self {
            paths,
            extract_dir,
            min_size,
        }
    }
}

impl TableProvider for ImageCarveTableProvider {
    fn tool_id(&self) -> &'static str {
        "chrome2rust_carve_images"
    }

    fn description(&self) -> &'static str {
        "Carve cached images across browsers with magic-byte validation, dimension extraction, and pure-Rust TIFF/EXIF IFD + GPS metadata (ImageCacheViewer equivalent)."
    }

    fn schema(&self) -> TableSchema {
        TableSchema::new(
            self.tool_id(),
            "Carved Cached Images & EXIF",
            vec![
                ColumnDef::new("browser", "Browser", ColumnType::Text).with_width_hint(110),
                ColumnDef::new("profile", "Profile", ColumnType::Text).with_width_hint(90),
                ColumnDef::new("url", "URL", ColumnType::Text).with_width_hint(260),
                ColumnDef::new("format", "Format", ColumnType::Text).with_width_hint(70),
                ColumnDef::new("mime_type", "MIME Type", ColumnType::Text).with_width_hint(110),
                ColumnDef::new("width", "Width", ColumnType::Uint).with_width_hint(65),
                ColumnDef::new("height", "Height", ColumnType::Uint).with_width_hint(65),
                ColumnDef::new("file_size", "Size", ColumnType::BytesSize).with_width_hint(85),
                ColumnDef::new("cache_time", "Cache Time", ColumnType::Timestamp).with_width_hint(155),
                ColumnDef::new("make", "Camera Make", ColumnType::Text).with_width_hint(100),
                ColumnDef::new("model", "Camera Model", ColumnType::Text).with_width_hint(110),
                ColumnDef::new("date_time_original", "EXIF Date", ColumnType::Text).with_width_hint(140),
                ColumnDef::new("gps_lat", "GPS Lat", ColumnType::Float).with_width_hint(90),
                ColumnDef::new("gps_lon", "GPS Lon", ColumnType::Float).with_width_hint(90),
                ColumnDef::new("exif_summary", "EXIF Summary", ColumnType::Text).with_width_hint(180),
                ColumnDef::new("sha256", "SHA-256", ColumnType::Text).with_width_hint(180),
                ColumnDef::new("cache_name", "Cache Name", ColumnType::Text).with_width_hint(120),
            ],
        )
        .with_default_sort(8, SortDirection::Desc)
    }

    fn query(&self, req: &TableQuery) -> Result<TableData, TableError> {
        let (records, _) = carve_images(&self.paths, self.extract_dir.as_deref(), self.min_size);
        let rows: Vec<Row> = records
            .into_iter()
            .enumerate()
            .map(|(idx, r)| {
                Row::new(
                    idx as u64 + 1,
                    vec![
                        CellValue::Text(r.browser.clone()),
                        CellValue::Text(r.profile.clone()),
                        CellValue::Text(r.url.clone()),
                        CellValue::Text(r.format.clone()),
                        CellValue::Text(r.mime_type.clone()),
                        r.width.map(|w| CellValue::Uint(w as u64)).unwrap_or(CellValue::Null),
                        r.height.map(|h| CellValue::Uint(h as u64)).unwrap_or(CellValue::Null),
                        CellValue::Bytes(r.file_size),
                        r.cache_time.map(CellValue::Timestamp).unwrap_or(CellValue::Null),
                        r.make.clone().map(CellValue::Text).unwrap_or(CellValue::Null),
                        r.model.clone().map(CellValue::Text).unwrap_or(CellValue::Null),
                        r.date_time_original
                            .clone()
                            .map(CellValue::Text)
                            .unwrap_or(CellValue::Null),
                        r.gps_lat.map(CellValue::Float).unwrap_or(CellValue::Null),
                        r.gps_lon.map(CellValue::Float).unwrap_or(CellValue::Null),
                        CellValue::Text(r.exif_summary.clone()),
                        CellValue::Text(r.sha256.clone()),
                        CellValue::Text(r.cache_name.clone()),
                    ],
                )
                .with_detail_json(serde_json::to_value(&r).unwrap_or_default())
            })
            .collect();
        apply_query(&self.schema(), &rows, req)
    }
}
