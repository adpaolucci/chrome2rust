use chrome2rust_core::error::ChromeError;
use guap_export::{
    CustodyLeaf, CustodyManifest, ExportFormat, ExportOptions, build_custody_manifest, export_table, sha256_hex,
    sha512_hex, write_custody_manifest_json, write_table_export,
};
use guap_table::{TableData, TableProvider, TableQuery};
use std::path::Path;

pub fn parse_table_export_format(s: &str) -> Result<ExportFormat, ChromeError> {
    match s.trim().to_ascii_lowercase().as_str() {
        "vhtml" => Ok(ExportFormat::HtmlVertical),
        other => ExportFormat::parse(other).map_err(|e| ChromeError::Export(e.to_string())),
    }
}

pub fn render_table_data_export(
    data: &TableData,
    format: ExportFormat,
    include_detail_json: bool,
) -> Result<Vec<u8>, ChromeError> {
    let opts = ExportOptions {
        include_detail_json,
        tool_version: env!("CARGO_PKG_VERSION").to_string(),
        ..Default::default()
    };
    export_table(data, format, &opts).map_err(|e| ChromeError::Export(e.to_string()))
}

pub fn export_table_provider(
    provider: &dyn TableProvider,
    query: &TableQuery,
    format: ExportFormat,
    include_detail_json: bool,
) -> Result<Vec<u8>, ChromeError> {
    let data = provider.query(query).map_err(|e| ChromeError::Export(e.to_string()))?;
    render_table_data_export(&data, format, include_detail_json)
}

pub fn write_table_data_export(
    data: &TableData,
    output_path: &Path,
    format: ExportFormat,
    manifest_path: Option<&Path>,
    include_detail_json: bool,
) -> Result<CustodyManifest, ChromeError> {
    let opts = ExportOptions {
        include_detail_json,
        tool_version: env!("CARGO_PKG_VERSION").to_string(),
        ..Default::default()
    };
    let manifest =
        write_table_export(data, output_path, format, &opts).map_err(|e| ChromeError::Export(e.to_string()))?;
    if let Some(mp) = manifest_path {
        write_custody_manifest_json(&manifest, mp).map_err(|e| ChromeError::Export(e.to_string()))?;
    }
    Ok(manifest)
}

pub fn write_table_data_custody_manifest(
    data: &TableData,
    manifest_path: &Path,
    artifact_label: &str,
    artifact_bytes: &[u8],
) -> Result<CustodyManifest, ChromeError> {
    let leaf = CustodyLeaf {
        index: 0,
        path: artifact_label.to_string(),
        size_bytes: artifact_bytes.len() as u64,
        sha256: sha256_hex(artifact_bytes),
        sha512: sha512_hex(artifact_bytes),
    };
    let manifest = build_custody_manifest(&data.schema.tool_id, env!("CARGO_PKG_VERSION"), vec![leaf]);
    write_custody_manifest_json(&manifest, manifest_path).map_err(|e| ChromeError::Export(e.to_string()))?;
    Ok(manifest)
}

pub fn write_table_provider_export(
    provider: &dyn TableProvider,
    query: &TableQuery,
    output_path: &Path,
    format: ExportFormat,
    manifest_path: Option<&Path>,
    include_detail_json: bool,
) -> Result<CustodyManifest, ChromeError> {
    let data = provider.query(query).map_err(|e| ChromeError::Export(e.to_string()))?;
    write_table_data_export(&data, output_path, format, manifest_path, include_detail_json)
}
