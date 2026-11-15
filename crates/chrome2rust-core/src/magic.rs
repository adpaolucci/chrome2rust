use serde::{Deserialize, Serialize};
use url::Url;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DetectionSource {
    MagicSignature,
    ContainerInspection,
    TextHeuristic,
    DeclaredContentType,
    ContentDisposition,
    UrlExtension,
    #[default]
    Unknown,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContentDetection {
    pub mime: Option<String>,
    pub extension: Option<String>,
    pub signature: Option<String>,
    pub source: DetectionSource,
    pub mime_mismatch: bool,
}

/// Normalizes an HTTP `Content-Type` header string (stripping parameters like `; charset=utf-8`).
pub fn normalize_mime(raw: &str) -> Option<String> {
    let main = raw.split(';').next()?.trim().to_ascii_lowercase();
    if main.is_empty() || !main.contains('/') {
        return None;
    }
    Some(match main.as_str() {
        "image/jpg" | "image/pjpeg" => "image/jpeg".to_string(),
        "image/x-png" => "image/png".to_string(),
        "image/x-ms-bmp" => "image/bmp".to_string(),
        "application/x-gzip" => "application/gzip".to_string(),
        "application/x-zip-compressed" => "application/zip".to_string(),
        "text/json" => "application/json".to_string(),
        "text/javascript"
        | "application/x-javascript"
        | "text/ecmascript"
        | "application/ecmascript"
        | "text/jscript" => "application/javascript".to_string(),
        "text/typescript" => "application/typescript".to_string(),
        "application/font-woff" => "font/woff".to_string(),
        "application/font-woff2" => "font/woff2".to_string(),
        "application/x-font-ttf" | "application/font-sfnt" => "font/ttf".to_string(),
        "application/x-font-opentype" => "font/otf".to_string(),
        _ => main,
    })
}

/// Returns true when `mime` is an unspecified binary fallback header.
pub fn is_generic_mime(mime: &str) -> bool {
    matches!(
        mime.trim().to_ascii_lowercase().as_str(),
        "" | "application/octet-stream"
            | "binary/octet-stream"
            | "application/binary"
            | "application/download"
            | "application/force-download"
            | "application/unknown"
            | "*/*"
    )
}

/// Canonical family key used to compare whether two MIME types represent the same underlying format.
fn canonical_family(mime: &str) -> String {
    let norm = normalize_mime(mime).unwrap_or_else(|| mime.trim().to_ascii_lowercase());
    match norm.as_str() {
        "text/javascript" => "application/javascript".to_string(),
        "image/apng" => "image/png".to_string(),
        "image/vnd.microsoft.icon" | "image/ico" => "image/x-icon".to_string(),
        "image/avif-sequence" => "image/avif".to_string(),
        "audio/wave" | "audio/x-wav" => "audio/wav".to_string(),
        "audio/mp3" | "audio/x-mpeg" | "audio/x-mp3" => "audio/mpeg".to_string(),
        "audio/x-aac" | "audio/aacp" => "audio/aac".to_string(),
        "audio/x-flac" => "audio/flac".to_string(),
        "audio/x-midi" | "audio/mid" => "audio/midi".to_string(),
        "video/avi" | "video/msvideo" => "video/x-msvideo".to_string(),
        "application/x-rar-compressed" | "application/x-rar" => "application/vnd.rar".to_string(),
        "application/x-sqlite3" => "application/vnd.sqlite3".to_string(),
        "application/x-msdownload" | "application/x-dosexec" => {
            "application/vnd.microsoft.portable-executable".to_string()
        }
        "application/x-mpegurl" | "audio/mpegurl" | "audio/x-mpegurl" => "application/vnd.apple.mpegurl".to_string(),
        "application/x-font-woff" => "font/woff".to_string(),
        "text/xml" => "application/xml".to_string(),
        "text/yaml" => "application/yaml".to_string(),
        other => other.to_string(),
    }
}

/// Maps a MIME type (with optional `; charset=...` parameters) to a preferred file extension without leading dot.
pub fn extension_from_mime(mime: &str) -> Option<&'static str> {
    let main = mime.split(';').next()?.trim().to_ascii_lowercase();
    match main.as_str() {
        // Web documents & scripts
        "text/html" => Some("html"),
        "application/xhtml+xml" => Some("xhtml"),
        "multipart/related" | "message/rfc822" => Some("mhtml"),
        "text/css" => Some("css"),
        "text/javascript"
        | "application/javascript"
        | "application/x-javascript"
        | "text/ecmascript"
        | "application/ecmascript"
        | "text/jscript" => Some("js"),
        "application/typescript" | "text/typescript" => Some("ts"),
        "application/json" | "text/json" => Some("json"),
        "application/ld+json" => Some("jsonld"),
        "application/manifest+json" => Some("webmanifest"),
        "text/plain" | "text/cache-manifest" => Some("txt"),
        "text/csv" | "application/csv" => Some("csv"),
        "text/tab-separated-values" => Some("tsv"),
        "text/markdown" => Some("md"),
        "text/xml" | "application/xml" => Some("xml"),
        "application/rss+xml" => Some("rss"),
        "application/atom+xml" => Some("atom"),
        "application/xslt+xml" => Some("xslt"),
        "text/yaml" | "application/yaml" | "application/x-yaml" => Some("yaml"),
        "application/toml" => Some("toml"),
        "text/vtt" => Some("vtt"),
        "application/x-subrip" => Some("srt"),
        "text/calendar" => Some("ics"),
        "text/vcard" | "text/x-vcard" => Some("vcf"),
        "application/x-www-form-urlencoded" | "text/event-stream" => Some("txt"),
        "application/webbundle" => Some("wbn"),

        // Images
        "image/png" | "image/x-png" | "image/apng" => Some("png"),
        "image/jpeg" | "image/jpg" | "image/pjpeg" => Some("jpg"),
        "image/gif" => Some("gif"),
        "image/webp" => Some("webp"),
        "image/avif" | "image/avif-sequence" => Some("avif"),
        "image/heic" => Some("heic"),
        "image/heif" => Some("heif"),
        "image/jxl" => Some("jxl"),
        "image/jp2" => Some("jp2"),
        "image/svg+xml" => Some("svg"),
        "image/x-icon" | "image/vnd.microsoft.icon" | "image/ico" => Some("ico"),
        "image/cur" | "image/x-win-bitmap" => Some("cur"),
        "image/bmp" | "image/x-ms-bmp" => Some("bmp"),
        "image/tiff" => Some("tiff"),
        "image/vnd.adobe.photoshop" => Some("psd"),
        "image/vnd.ms-dds" => Some("dds"),

        // Fonts
        "font/woff2" | "application/font-woff2" => Some("woff2"),
        "font/woff" | "application/font-woff" | "application/x-font-woff" => Some("woff"),
        "font/ttf" | "application/x-font-ttf" | "application/x-font-truetype" | "application/font-sfnt" => Some("ttf"),
        "font/otf" | "application/x-font-opentype" => Some("otf"),
        "font/collection" => Some("ttc"),
        "application/vnd.ms-fontobject" => Some("eot"),

        // Audio & Video & Streaming
        "video/mp4" | "application/mp4" => Some("mp4"),
        "video/iso.segment" => Some("m4s"),
        "video/webm" => Some("webm"),
        "video/ogg" => Some("ogv"),
        "video/quicktime" => Some("mov"),
        "video/x-msvideo" | "video/avi" | "video/msvideo" => Some("avi"),
        "video/x-matroska" => Some("mkv"),
        "video/x-flv" => Some("flv"),
        "video/mp2t" => Some("ts"),
        "video/mpeg" => Some("mpeg"),
        "video/3gpp" => Some("3gp"),
        "application/vnd.apple.mpegurl" | "application/x-mpegurl" | "audio/mpegurl" | "audio/x-mpegurl" => Some("m3u8"),
        "application/dash+xml" => Some("mpd"),
        "audio/mpeg" | "audio/mp3" | "audio/x-mpeg" | "audio/x-mp3" => Some("mp3"),
        "audio/mp4" | "audio/x-m4a" => Some("m4a"),
        "audio/aac" | "audio/aacp" | "audio/x-aac" => Some("aac"),
        "audio/ogg" | "application/ogg" => Some("ogg"),
        "audio/opus" => Some("opus"),
        "audio/webm" => Some("weba"),
        "audio/wav" | "audio/x-wav" | "audio/wave" => Some("wav"),
        "audio/flac" | "audio/x-flac" => Some("flac"),
        "audio/midi" | "audio/x-midi" | "audio/mid" => Some("mid"),

        // Archives, Executables, Documents & Forensics
        "application/wasm" => Some("wasm"),
        "application/pdf" => Some("pdf"),
        "application/postscript" => Some("ps"),
        "application/rtf" | "text/rtf" => Some("rtf"),
        "application/msword" => Some("doc"),
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document" => Some("docx"),
        "application/vnd.ms-excel" => Some("xls"),
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" => Some("xlsx"),
        "application/vnd.ms-powerpoint" => Some("ppt"),
        "application/vnd.openxmlformats-officedocument.presentationml.presentation" => Some("pptx"),
        "application/vnd.oasis.opendocument.text" => Some("odt"),
        "application/vnd.oasis.opendocument.spreadsheet" => Some("ods"),
        "application/vnd.oasis.opendocument.presentation" => Some("odp"),
        "application/epub+zip" => Some("epub"),
        "application/zip" | "application/x-zip-compressed" => Some("zip"),
        "application/gzip" | "application/x-gzip" => Some("gz"),
        "application/x-tar" => Some("tar"),
        "application/x-7z-compressed" => Some("7z"),
        "application/x-rar-compressed" | "application/vnd.rar" | "application/x-rar" => Some("rar"),
        "application/x-bzip2" => Some("bz2"),
        "application/zstd" => Some("zst"),
        "application/x-xz" => Some("xz"),
        "application/x-lz4" => Some("lz4"),
        "application/vnd.ms-cab-compressed" => Some("cab"),
        "application/x-apple-diskimage" => Some("dmg"),
        "application/vnd.apple.installer+xml" => Some("pkg"),
        "application/vnd.android.package-archive" => Some("apk"),
        "application/java-archive" => Some("jar"),
        "application/x-chrome-extension" => Some("crx"),
        "application/x-xpinstall" => Some("xpi"),
        "application/x-shockwave-flash" => Some("swf"),
        "application/x-msdownload" | "application/vnd.microsoft.portable-executable" | "application/x-dosexec" => {
            Some("exe")
        }
        "application/x-msi" => Some("msi"),
        "application/x-executable" | "application/x-elf" => Some("elf"),
        "application/x-sharedlib" => Some("so"),
        "application/x-mach-binary" => Some("macho"),
        "application/x-sqlite3" | "application/vnd.sqlite3" => Some("sqlite"),
        "application/x-protobuf" | "application/protobuf" | "application/grpc" => Some("pb"),
        "application/x-v8-bytecode" => Some("v8c"),
        "application/x-spirv" => Some("spv"),
        "application/pkix-cert" | "application/x-x509-ca-cert" => Some("crt"),
        "application/x-pem-file" => Some("pem"),
        "application/x-pkcs12" => Some("p12"),
        "application/x-ms-shortcut" => Some("lnk"),

        // Structured suffixes
        other if other.ends_with("+json") => Some("json"),
        other if other.ends_with("+xml") => Some("xml"),
        other if other.ends_with("+zip") => Some("zip"),
        _ => None,
    }
}

/// Maps a known extension (without dot) back to a representative MIME type.
pub fn mime_from_extension(ext: &str) -> Option<&'static str> {
    match ext.trim().trim_start_matches('.').to_ascii_lowercase().as_str() {
        "html" | "htm" => Some("text/html"),
        "xhtml" => Some("application/xhtml+xml"),
        "mhtml" | "mht" => Some("multipart/related"),
        "css" => Some("text/css"),
        "js" | "mjs" | "cjs" | "jsx" => Some("application/javascript"),
        "ts" | "tsx" | "mts" | "cts" => Some("application/typescript"),
        "json" | "map" => Some("application/json"),
        "jsonld" => Some("application/ld+json"),
        "webmanifest" => Some("application/manifest+json"),
        "txt" | "log" | "conf" | "ini" => Some("text/plain"),
        "csv" => Some("text/csv"),
        "tsv" => Some("text/tab-separated-values"),
        "md" | "markdown" => Some("text/markdown"),
        "xml" | "plist" => Some("application/xml"),
        "rss" => Some("application/rss+xml"),
        "atom" => Some("application/atom+xml"),
        "xsl" | "xslt" => Some("application/xslt+xml"),
        "yaml" | "yml" => Some("application/yaml"),
        "toml" => Some("application/toml"),
        "vtt" => Some("text/vtt"),
        "srt" => Some("application/x-subrip"),
        "ics" => Some("text/calendar"),
        "vcf" => Some("text/vcard"),
        "wbn" => Some("application/webbundle"),
        "png" | "apng" => Some("image/png"),
        "jpg" | "jpeg" | "jfif" => Some("image/jpeg"),
        "gif" => Some("image/gif"),
        "webp" => Some("image/webp"),
        "avif" => Some("image/avif"),
        "heic" => Some("image/heic"),
        "heif" => Some("image/heif"),
        "jxl" => Some("image/jxl"),
        "jp2" => Some("image/jp2"),
        "svg" => Some("image/svg+xml"),
        "ico" => Some("image/x-icon"),
        "cur" => Some("image/cur"),
        "bmp" => Some("image/bmp"),
        "tif" | "tiff" => Some("image/tiff"),
        "psd" => Some("image/vnd.adobe.photoshop"),
        "dds" => Some("image/vnd.ms-dds"),
        "woff2" => Some("font/woff2"),
        "woff" => Some("font/woff"),
        "ttf" => Some("font/ttf"),
        "otf" => Some("font/otf"),
        "ttc" => Some("font/collection"),
        "eot" => Some("application/vnd.ms-fontobject"),
        "mp4" | "m4v" => Some("video/mp4"),
        "m4s" => Some("video/iso.segment"),
        "webm" => Some("video/webm"),
        "ogv" => Some("video/ogg"),
        "mov" => Some("video/quicktime"),
        "avi" => Some("video/x-msvideo"),
        "mkv" => Some("video/x-matroska"),
        "flv" => Some("video/x-flv"),
        "mpeg" | "mpg" => Some("video/mpeg"),
        "m2ts" => Some("video/mp2t"),
        "3gp" => Some("video/3gpp"),
        "m3u8" | "m3u" => Some("application/vnd.apple.mpegurl"),
        "mpd" => Some("application/dash+xml"),
        "mp3" => Some("audio/mpeg"),
        "m4a" => Some("audio/mp4"),
        "aac" => Some("audio/aac"),
        "ogg" | "oga" => Some("audio/ogg"),
        "opus" => Some("audio/opus"),
        "weba" => Some("audio/webm"),
        "wav" => Some("audio/wav"),
        "flac" => Some("audio/flac"),
        "mid" | "midi" => Some("audio/midi"),
        "wasm" => Some("application/wasm"),
        "pdf" => Some("application/pdf"),
        "ps" | "eps" => Some("application/postscript"),
        "rtf" => Some("application/rtf"),
        "doc" => Some("application/msword"),
        "docx" => Some("application/vnd.openxmlformats-officedocument.wordprocessingml.document"),
        "xls" => Some("application/vnd.ms-excel"),
        "xlsx" => Some("application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"),
        "ppt" => Some("application/vnd.ms-powerpoint"),
        "pptx" => Some("application/vnd.openxmlformats-officedocument.presentationml.presentation"),
        "odt" => Some("application/vnd.oasis.opendocument.text"),
        "ods" => Some("application/vnd.oasis.opendocument.spreadsheet"),
        "odp" => Some("application/vnd.oasis.opendocument.presentation"),
        "epub" => Some("application/epub+zip"),
        "zip" => Some("application/zip"),
        "gz" | "tgz" => Some("application/gzip"),
        "tar" => Some("application/x-tar"),
        "7z" => Some("application/x-7z-compressed"),
        "rar" => Some("application/vnd.rar"),
        "bz2" => Some("application/x-bzip2"),
        "zst" => Some("application/zstd"),
        "xz" => Some("application/x-xz"),
        "lz4" => Some("application/x-lz4"),
        "cab" => Some("application/vnd.ms-cab-compressed"),
        "dmg" => Some("application/x-apple-diskimage"),
        "pkg" => Some("application/vnd.apple.installer+xml"),
        "apk" => Some("application/vnd.android.package-archive"),
        "jar" | "war" => Some("application/java-archive"),
        "crx" => Some("application/x-chrome-extension"),
        "xpi" => Some("application/x-xpinstall"),
        "swf" => Some("application/x-shockwave-flash"),
        "exe" | "dll" | "sys" => Some("application/vnd.microsoft.portable-executable"),
        "msi" => Some("application/x-msi"),
        "elf" => Some("application/x-elf"),
        "so" => Some("application/x-sharedlib"),
        "macho" | "dylib" => Some("application/x-mach-binary"),
        "sqlite" | "sqlite3" | "db" => Some("application/vnd.sqlite3"),
        "pb" => Some("application/x-protobuf"),
        "v8c" => Some("application/x-v8-bytecode"),
        "spv" => Some("application/x-spirv"),
        "crt" | "cer" | "der" => Some("application/pkix-cert"),
        "pem" => Some("application/x-pem-file"),
        "p12" | "pfx" => Some("application/x-pkcs12"),
        "lnk" => Some("application/x-ms-shortcut"),
        "bin" | "dat" | "iso" | "img" => Some("application/octet-stream"),
        _ => None,
    }
}

/// Returns true if `ext` is a recognized cached asset/document/binary extension.
/// Prevents host TLDs (`.com`, `.org`), numeric version segments (`jquery-3.7.1`),
/// or username dots (`alice.smith`) from being mistaken for file extensions.
pub fn is_known_extension(ext: &str) -> bool {
    mime_from_extension(ext).is_some()
}

/// Returns true for dynamic server script/endpoint extensions (`.php`, `.aspx`, `.ashx`, etc.)
/// that rarely reflect the actual cached HTTP payload type.
pub fn is_server_endpoint_extension(ext: &str) -> bool {
    matches!(
        ext.trim().trim_start_matches('.').to_ascii_lowercase().as_str(),
        "php"
            | "phtml"
            | "asp"
            | "aspx"
            | "ashx"
            | "asmx"
            | "axd"
            | "jsp"
            | "jspx"
            | "cgi"
            | "fcgi"
            | "pl"
            | "cfm"
            | "cfc"
            | "do"
            | "action"
            | "svc"
            | "py"
            | "rb"
    )
}

/// Normalizes synonymous extensions (e.g. `jpeg` -> `jpg`, `htm` -> `html`) for comparison.
pub fn extensions_equivalent(a: &str, b: &str) -> bool {
    let norm = |s: &str| match s.trim().trim_start_matches('.').to_ascii_lowercase().as_str() {
        "jpeg" | "jfif" => "jpg".to_string(),
        "htm" => "html".to_string(),
        "tif" => "tiff".to_string(),
        "yml" => "yaml".to_string(),
        "markdown" => "md".to_string(),
        "mjs" | "cjs" => "js".to_string(),
        "mts" | "cts" => "ts".to_string(),
        "m2ts" => "ts".to_string(),
        "mht" => "mhtml".to_string(),
        "m3u" => "m3u8".to_string(),
        "mpg" => "mpeg".to_string(),
        "m4v" => "mp4".to_string(),
        "eps" => "ps".to_string(),
        "tgz" => "gz".to_string(),
        "sqlite3" | "db" => "sqlite".to_string(),
        "cer" | "der" => "crt".to_string(),
        "pfx" => "p12".to_string(),
        "midi" => "mid".to_string(),
        "oga" => "ogg".to_string(),
        "apng" => "png".to_string(),
        other => other.to_string(),
    };
    norm(a) == norm(b)
}

/// Extracts and sanitizes a filename from an HTTP `Content-Disposition` header value.
/// Supports both `filename="..."` and RFC 5987 `filename*=UTF-8''...`.
pub fn parse_content_disposition_filename(header_val: &str) -> Option<String> {
    let mut rfc5987_name: Option<String> = None;
    let mut plain_name: Option<String> = None;

    for param in header_val.split(';') {
        let p = param.trim();
        let Some((k, v)) = p.split_once('=') else {
            continue;
        };
        let key = k.trim().to_ascii_lowercase();
        let val = v.trim();
        if key == "filename*" {
            let unquoted = val.trim_matches('"');
            let encoded = if let Some((_, rest)) = unquoted.split_once("''") {
                rest
            } else {
                unquoted
            };
            let decoded = percent_decode(encoded);
            if let Some(clean) = sanitize_basename(&decoded) {
                rfc5987_name = Some(clean);
            }
        } else if key == "filename" {
            let unquoted = val.trim_matches('"').trim_matches('\'');
            let decoded = percent_decode(unquoted);
            if let Some(clean) = sanitize_basename(&decoded) {
                plain_name = Some(clean);
            }
        }
    }

    rfc5987_name.or(plain_name)
}

fn sanitize_basename(raw: &str) -> Option<String> {
    let base = raw.rsplit(['/', '\\']).next().unwrap_or(raw).trim();
    if base.is_empty() || base == "." || base == ".." {
        return None;
    }
    let clean: String = base
        .chars()
        .filter(|c| !c.is_control() && !matches!(c, '/' | '\\' | '\0'))
        .collect();
    if clean.is_empty() { None } else { Some(clean) }
}

fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && let (Some(hi), Some(lo)) = (hex_val(bytes[i + 1]), hex_val(bytes[i + 2]))
        {
            out.push((hi << 4) | lo);
            i += 3;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Extracts a known file extension from a URL path segment or query string (`?format=webp`, `?filename=...`).
pub fn extension_from_url(url_str: &str) -> Option<String> {
    if let Some(after_data) = url_str.strip_prefix("data:") {
        let meta = after_data.split(',').next().unwrap_or("");
        let mime = meta.split(';').next().unwrap_or("").trim();
        if let Some(ext) = extension_from_mime(mime) {
            return Some(ext.to_string());
        }
        return None;
    }

    let parsed = Url::parse(url_str).ok()?;

    // 1. Check final path segment extension
    if let Some(mut segs) = parsed.path_segments()
        && let Some(last) = segs.rfind(|s| !s.is_empty())
    {
        let decoded = percent_decode(last);
        if let Some((_, raw_ext)) = decoded.rsplit_once('.') {
            let ext = raw_ext.trim().to_ascii_lowercase();
            if !ext.is_empty() && !is_server_endpoint_extension(&ext) && is_known_extension(&ext) {
                return Some(ext);
            }
        }
    }

    // 2. Check common CDN / image proxy / download query parameters
    for (k, v) in parsed.query_pairs() {
        let key = k.trim().to_ascii_lowercase();
        let val = v.trim();
        if val.is_empty() {
            continue;
        }
        match key.as_str() {
            "response-content-type" | "content-type" | "mime" | "mimetype" => {
                if let Some(ext) = extension_from_mime(val) {
                    return Some(ext.to_string());
                }
            }
            "response-content-disposition" | "content-disposition" => {
                if let Some(fname) = parse_content_disposition_filename(val)
                    && let Some((_, ext)) = fname.rsplit_once('.')
                {
                    let lower = ext.to_ascii_lowercase();
                    if is_known_extension(&lower) {
                        return Some(lower);
                    }
                }
            }
            "filename" | "file" | "name" | "download" | "attachment" => {
                if let Some((_, ext)) = val.rsplit_once('.') {
                    let lower = ext.to_ascii_lowercase();
                    if is_known_extension(&lower) {
                        return Some(lower);
                    }
                }
            }
            "format" | "fm" | "ext" | "extension" | "output" => {
                let lower = val.trim_start_matches('.').to_ascii_lowercase();
                if is_known_extension(&lower) {
                    return Some(lower);
                }
            }
            "type" => {
                let lower = val.trim_start_matches('.').to_ascii_lowercase();
                if let Some(ext) = extension_from_mime(&lower) {
                    return Some(ext.to_string());
                }
                if is_known_extension(&lower) {
                    return Some(lower);
                }
            }
            _ => {}
        }
    }

    None
}

/// Identifies a file or cached payload from raw/decompressed bytes alongside optional
/// HTTP `Content-Type`, `Content-Disposition` filename, and origin URL metadata.
pub fn detect_content(
    payload: &[u8],
    declared_ct: Option<&str>,
    url: Option<&str>,
    content_disp_filename: Option<&str>,
) -> ContentDetection {
    let declared_norm = declared_ct.and_then(normalize_mime);
    let url_ext = url.and_then(extension_from_url);
    let disp_ext = content_disp_filename
        .and_then(|f| f.rsplit_once('.'))
        .map(|(_, e)| e.trim().to_ascii_lowercase())
        .filter(|e| !e.is_empty() && !is_server_endpoint_extension(e) && is_known_extension(e));

    // 1. Inspect magic bytes / container structures on payload
    if !payload.is_empty() {
        if let Some((magic_mime, magic_ext, desc, src)) = detect_magic_bytes(payload) {
            // Refine generic container extensions if declared metadata / Content-Disposition / URL specifies a subtype
            let (final_mime, final_ext) = refine_container_type(
                magic_mime,
                magic_ext,
                declared_norm.as_deref(),
                disp_ext.as_deref(),
                url_ext.as_deref(),
            );
            let mime_mismatch = declared_norm
                .as_deref()
                .is_some_and(|decl| !is_generic_mime(decl) && !are_mimes_compatible(decl, &final_mime));
            return ContentDetection {
                mime: Some(final_mime),
                extension: Some(final_ext),
                signature: Some(desc.to_string()),
                source: src,
                mime_mismatch,
            };
        }

        // 2. Try text/markup/script/JSON heuristics
        if let Some((text_mime, text_ext, desc, src)) = detect_text_bytes(payload, url_ext.as_deref()) {
            let (final_mime, final_ext) = refine_text_type(
                text_mime,
                text_ext,
                declared_norm.as_deref(),
                disp_ext.as_deref(),
                url_ext.as_deref(),
            );
            let mime_mismatch = declared_norm
                .as_deref()
                .is_some_and(|decl| !is_generic_mime(decl) && !are_mimes_compatible(decl, &final_mime));
            return ContentDetection {
                mime: Some(final_mime),
                extension: Some(final_ext),
                signature: Some(desc.to_string()),
                source: src,
                mime_mismatch,
            };
        }
    }

    // 3. Declared specific HTTP Content-Type header
    if let Some(decl) = declared_norm.as_deref()
        && !is_generic_mime(decl)
    {
        let ext = extension_from_mime(decl).map(str::to_string).or(disp_ext).or(url_ext);
        return ContentDetection {
            mime: Some(decl.to_string()),
            extension: ext,
            signature: None,
            source: DetectionSource::DeclaredContentType,
            mime_mismatch: false,
        };
    }

    // 4. Content-Disposition filename extension
    if let Some(ext) = disp_ext {
        let mime = mime_from_extension(&ext).map(str::to_string);
        return ContentDetection {
            mime,
            extension: Some(ext),
            signature: None,
            source: DetectionSource::ContentDisposition,
            mime_mismatch: false,
        };
    }

    // 5. URL path/query extension
    if let Some(ext) = url_ext {
        let mime = mime_from_extension(&ext).map(str::to_string);
        return ContentDetection {
            mime,
            extension: Some(ext),
            signature: None,
            source: DetectionSource::UrlExtension,
            mime_mismatch: false,
        };
    }

    ContentDetection::default()
}

fn refine_container_type(
    magic_mime: &str,
    magic_ext: &str,
    declared: Option<&str>,
    disp_ext: Option<&str>,
    url_ext: Option<&str>,
) -> (String, String) {
    // ZIP holds docx/xlsx/pptx/apk/jar/epub/xpi; if ZIP scanner wasn't able to see subtype marker early in file,
    // honor declared or filename ZIP-family subtype rather than downgrading `.docx` -> `.zip`.
    if magic_mime == "application/zip" {
        if let Some(decl) = declared
            && let Some(decl_ext) = extension_from_mime(decl)
            && matches!(
                decl_ext,
                "docx" | "xlsx" | "pptx" | "odt" | "ods" | "odp" | "epub" | "apk" | "jar" | "xpi" | "crx"
            )
        {
            return (decl.to_string(), decl_ext.to_string());
        }
        for candidate in [disp_ext, url_ext].into_iter().flatten() {
            if matches!(
                candidate,
                "docx" | "xlsx" | "pptx" | "odt" | "ods" | "odp" | "epub" | "apk" | "jar" | "war" | "xpi" | "crx"
            ) {
                let mime = mime_from_extension(candidate).unwrap_or(magic_mime);
                return (mime.to_string(), candidate.to_string());
            }
        }
    }

    // OLE2 holds .doc/.xls/.ppt/.msi
    if magic_mime == "application/x-ole-storage" {
        if let Some(decl) = declared
            && let Some(decl_ext) = extension_from_mime(decl)
            && matches!(decl_ext, "doc" | "xls" | "ppt" | "msi")
        {
            return (decl.to_string(), decl_ext.to_string());
        }
        for candidate in [disp_ext, url_ext].into_iter().flatten() {
            if matches!(candidate, "doc" | "xls" | "ppt" | "msi") {
                let mime = mime_from_extension(candidate).unwrap_or(magic_mime);
                return (mime.to_string(), candidate.to_string());
            }
        }
    }

    // PE files can be .exe, .dll, or .sys
    if magic_mime == "application/vnd.microsoft.portable-executable" && magic_ext == "exe" {
        for candidate in [disp_ext, url_ext].into_iter().flatten() {
            if matches!(candidate, "sys" | "scr" | "cpl" | "ocx") {
                return (magic_mime.to_string(), candidate.to_string());
            }
        }
    }

    (magic_mime.to_string(), magic_ext.to_string())
}

fn refine_text_type(
    text_mime: &str,
    text_ext: &str,
    declared: Option<&str>,
    disp_ext: Option<&str>,
    url_ext: Option<&str>,
) -> (String, String) {
    // Preserve specific text subtypes (like text/css, text/csv, text/vtt, application/manifest+json, .mjs/.ts/.yaml)
    // when heuristic only classified generic text/plain, application/json, or application/xml.
    if text_mime == "text/plain" {
        if let Some(decl) = declared
            && !is_generic_mime(decl)
            && decl != "text/plain"
            && let Some(decl_ext) = extension_from_mime(decl)
            && is_text_mime(decl)
        {
            return (decl.to_string(), decl_ext.to_string());
        }
        for candidate in [disp_ext, url_ext].into_iter().flatten() {
            if let Some(m) = mime_from_extension(candidate)
                && is_text_mime(m)
            {
                return (m.to_string(), candidate.to_string());
            }
        }
    }

    if text_mime == "application/json" {
        if let Some(decl) = declared
            && (decl.ends_with("+json") || decl == "application/ld+json" || decl == "application/manifest+json")
            && let Some(decl_ext) = extension_from_mime(decl)
        {
            return (decl.to_string(), decl_ext.to_string());
        }
        for candidate in [disp_ext, url_ext].into_iter().flatten() {
            if matches!(candidate, "webmanifest" | "jsonld" | "map") {
                let m = mime_from_extension(candidate).unwrap_or("application/json");
                return (m.to_string(), candidate.to_string());
            }
        }
    }

    if text_mime == "application/xml" {
        if let Some(decl) = declared
            && (decl.ends_with("+xml") || decl == "image/svg+xml")
            && let Some(decl_ext) = extension_from_mime(decl)
        {
            return (decl.to_string(), decl_ext.to_string());
        }
        for candidate in [disp_ext, url_ext].into_iter().flatten() {
            if matches!(
                candidate,
                "svg" | "xhtml" | "rss" | "atom" | "xslt" | "xsl" | "plist" | "mpd"
            ) {
                let m = mime_from_extension(candidate).unwrap_or("application/xml");
                return (m.to_string(), candidate.to_string());
            }
        }
    }

    if text_mime == "application/javascript" {
        for candidate in [disp_ext, url_ext].into_iter().flatten() {
            if matches!(candidate, "mjs" | "cjs" | "jsx" | "ts" | "tsx") {
                let m = match candidate {
                    "ts" | "tsx" => "application/typescript",
                    other => mime_from_extension(other).unwrap_or("application/javascript"),
                };
                return (m.to_string(), candidate.to_string());
            }
        }
    }

    (text_mime.to_string(), text_ext.to_string())
}

fn is_text_mime(m: &str) -> bool {
    m.starts_with("text/")
        || m.contains("javascript")
        || m.contains("ecmascript")
        || m.contains("typescript")
        || m.contains("json")
        || m.contains("xml")
        || m.contains("yaml")
        || m.contains("toml")
        || m.contains("mpegurl")
        || matches!(
            m,
            "application/x-pem-file"
                | "application/x-subrip"
                | "application/postscript"
                | "application/rtf"
                | "multipart/related"
                | "message/rfc822"
        )
}

/// Checks if a declared HTTP MIME type is compatible with a detected MIME type
/// without flagging benign equivalents (`text/javascript` vs `application/javascript`, `+json`, etc.).
pub fn are_mimes_compatible(declared: &str, detected: &str) -> bool {
    if is_generic_mime(declared) {
        return true;
    }
    let d = canonical_family(declared);
    let a = canonical_family(detected);
    if d == a {
        return true;
    }

    // Parameterized structured suffixes
    if (d.ends_with("+json") || d == "application/manifest+json") && a == "application/json" {
        return true;
    }
    if d.ends_with("+xml")
        && matches!(
            a.as_str(),
            "application/xml"
                | "image/svg+xml"
                | "application/xhtml+xml"
                | "application/rss+xml"
                | "application/atom+xml"
        )
    {
        return true;
    }

    // Text subtypes delivered with text/plain aren't masquerading unless detected payload is binary
    if d == "text/plain" && is_text_mime(&a) {
        return true;
    }
    // Text/html vs XHTML / MHTML
    if matches!(d.as_str(), "text/html" | "application/xhtml+xml")
        && matches!(a.as_str(), "text/html" | "application/xhtml+xml")
    {
        return true;
    }
    // PEM certificate served under X.509 cert MIME
    if matches!(
        d.as_str(),
        "application/pkix-cert" | "application/x-x509-ca-cert" | "application/x-pem-file"
    ) && matches!(
        a.as_str(),
        "application/pkix-cert" | "application/x-x509-ca-cert" | "application/x-pem-file"
    ) {
        return true;
    }
    // JS served with text/plain or TypeScript transpilation equivalents
    if matches!(d.as_str(), "application/javascript" | "application/typescript")
        && matches!(
            a.as_str(),
            "application/javascript" | "application/typescript" | "text/plain"
        )
    {
        return true;
    }
    // CSS plain fallback on small fragments
    if d == "text/css" && a == "text/plain" {
        return true;
    }
    // ICO / CUR icon/cursor overlap
    if matches!(d.as_str(), "image/x-icon" | "image/cur") && matches!(a.as_str(), "image/x-icon" | "image/cur") {
        return true;
    }
    // HEIC / HEIF family overlap
    if matches!(d.as_str(), "image/heic" | "image/heif") && matches!(a.as_str(), "image/heic" | "image/heif") {
        return true;
    }
    // ZIP container subtypes
    if a == "application/zip"
        && matches!(
            d.as_str(),
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
                | "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
                | "application/vnd.openxmlformats-officedocument.presentationml.presentation"
                | "application/vnd.oasis.opendocument.text"
                | "application/vnd.oasis.opendocument.spreadsheet"
                | "application/vnd.oasis.opendocument.presentation"
                | "application/epub+zip"
                | "application/vnd.android.package-archive"
                | "application/java-archive"
                | "application/x-chrome-extension"
                | "application/x-xpinstall"
        )
    {
        return true;
    }
    // MP4 / fMP4 streaming
    if (d == "video/mp4" || d == "video/iso.segment" || d == "audio/mp4" || d == "application/mp4")
        && (a == "video/mp4" || a == "video/iso.segment" || a == "audio/mp4")
    {
        return true;
    }
    // WebM audio/video
    if (d == "video/webm" || d == "audio/webm") && (a == "video/webm" || a == "audio/webm") {
        return true;
    }
    // Ogg container
    if (d.starts_with("audio/ogg") || d == "application/ogg" || d == "audio/opus" || d == "video/ogg")
        && (a == "audio/ogg" || a == "application/ogg" || a == "audio/opus" || a == "video/ogg")
    {
        return true;
    }
    // SFNT fonts (TTF/OTF overlap)
    if matches!(
        d.as_str(),
        "font/ttf"
            | "font/otf"
            | "font/sfnt"
            | "application/font-sfnt"
            | "application/x-font-ttf"
            | "application/x-font-truetype"
            | "application/x-font-opentype"
    ) && matches!(a.as_str(), "font/ttf" | "font/otf")
    {
        return true;
    }

    false
}

/// Returns true if a MIME mismatch is security-relevant (executable, archive, script, or HTML
/// masquerading under an image/font/media/document MIME type, or binary under text).
pub fn is_high_risk_mime_mismatch(declared: &str, detected: &str) -> bool {
    if are_mimes_compatible(declared, detected) {
        return false;
    }
    let d = declared.trim().to_ascii_lowercase();
    let a = detected.trim().to_ascii_lowercase();

    let is_exec_or_archive = matches!(
        a.as_str(),
        "application/vnd.microsoft.portable-executable"
            | "application/x-elf"
            | "application/x-sharedlib"
            | "application/x-mach-binary"
            | "application/wasm"
            | "application/x-chrome-extension"
            | "application/x-ms-shortcut"
            | "application/zip"
            | "application/x-7z-compressed"
            | "application/vnd.rar"
            | "application/x-shockwave-flash"
    );

    if is_exec_or_archive {
        return true;
    }
    if (d.starts_with("image/") || d.starts_with("font/")) && !a.starts_with("image/") && !a.starts_with("font/") {
        return true;
    }
    if d.starts_with("text/") && !is_text_mime(&a) {
        return true;
    }
    false
}

/// Detects binary formats using file signatures and container inspection.
pub fn detect_magic_bytes(b: &[u8]) -> Option<(&'static str, &'static str, &'static str, DetectionSource)> {
    let len = b.len();
    if len == 0 {
        return None;
    }

    // PNG / APNG
    if b.starts_with(b"\x89PNG\r\n\x1a\n") {
        let head = &b[..len.min(512)];
        let desc = if find_subslice(head, b"acTL").is_some() {
            "APNG Animated Image"
        } else {
            "PNG Image"
        };
        return Some(("image/png", "png", desc, DetectionSource::MagicSignature));
    }

    // JPEG
    if len >= 3 && b[0] == 0xff && b[1] == 0xd8 && b[2] == 0xff {
        return Some(("image/jpeg", "jpg", "JPEG Image", DetectionSource::MagicSignature));
    }

    // GIF
    if b.starts_with(b"GIF87a") || b.starts_with(b"GIF89a") {
        return Some(("image/gif", "gif", "GIF Image", DetectionSource::MagicSignature));
    }

    // RIFF container: WEBP / WAVE / AVI / ANI
    if len >= 12 && b.starts_with(b"RIFF") {
        match &b[8..12] {
            b"WEBP" => {
                return Some((
                    "image/webp",
                    "webp",
                    "WebP Image (RIFF)",
                    DetectionSource::ContainerInspection,
                ));
            }
            b"WAVE" => {
                return Some((
                    "audio/wav",
                    "wav",
                    "WAV Audio (RIFF)",
                    DetectionSource::ContainerInspection,
                ));
            }
            b"AVI " => {
                return Some((
                    "video/x-msvideo",
                    "avi",
                    "AVI Video (RIFF)",
                    DetectionSource::ContainerInspection,
                ));
            }
            b"ACON" => {
                return Some((
                    "application/x-navi-animation",
                    "ani",
                    "Windows Animated Cursor",
                    DetectionSource::ContainerInspection,
                ));
            }
            _ => {}
        }
    }

    // JPEG XL (codestream or ISOBMFF container)
    if b.starts_with(b"\xff\x0a") || b.starts_with(b"\x00\x00\x00\x0cJXL \r\n\x87\n") {
        return Some(("image/jxl", "jxl", "JPEG XL Image", DetectionSource::MagicSignature));
    }

    // JPEG 2000
    if b.starts_with(b"\x00\x00\x00\x0cjP  \r\n\x87\n") {
        return Some(("image/jp2", "jp2", "JPEG 2000 Image", DetectionSource::MagicSignature));
    }

    // ISO BMFF (AVIF, HEIC, HEIF, MP4, M4A, MOV, fMP4 M4S)
    if len >= 12
        && let Some(hit) = detect_isobmff(b)
    {
        return Some(hit);
    }

    // ICO / CUR (verify resource count & directory bounds)
    if len >= 22 && (b.starts_with(b"\x00\x00\x01\x00") || b.starts_with(b"\x00\x00\x02\x00")) {
        let count = u16::from_le_bytes([b[4], b[5]]) as usize;
        if (1..=64).contains(&count) && b[9] == 0 {
            if b[2] == 1 {
                return Some((
                    "image/x-icon",
                    "ico",
                    "Windows Icon (ICO)",
                    DetectionSource::MagicSignature,
                ));
            }
            return Some((
                "image/cur",
                "cur",
                "Windows Cursor (CUR)",
                DetectionSource::MagicSignature,
            ));
        }
    }

    // BMP (verify DIB header size)
    if len >= 26 && b.starts_with(b"BM") {
        let dib_size = u32::from_le_bytes([b[14], b[15], b[16], b[17]]);
        if matches!(dib_size, 12 | 40 | 52 | 56 | 64 | 108 | 124) {
            return Some(("image/bmp", "bmp", "BMP Bitmap Image", DetectionSource::MagicSignature));
        }
    }

    // TIFF
    if b.starts_with(b"II*\x00") || b.starts_with(b"MM\x00*") {
        return Some(("image/tiff", "tiff", "TIFF Image", DetectionSource::MagicSignature));
    }

    // PSD & DDS
    if len >= 26 && b.starts_with(b"8BPS\x00\x01") {
        return Some((
            "image/vnd.adobe.photoshop",
            "psd",
            "Adobe Photoshop Document",
            DetectionSource::MagicSignature,
        ));
    }
    if len >= 128 && b.starts_with(b"DDS ") && u32::from_le_bytes([b[4], b[5], b[6], b[7]]) == 124 {
        return Some((
            "image/vnd.ms-dds",
            "dds",
            "DirectDraw Surface Texture",
            DetectionSource::MagicSignature,
        ));
    }

    // Fonts: WOFF2, WOFF, OTF, TTC, TTF, EOT
    if b.starts_with(b"wOF2") {
        return Some(("font/woff2", "woff2", "WOFF2 Web Font", DetectionSource::MagicSignature));
    }
    if b.starts_with(b"wOFF") {
        return Some(("font/woff", "woff", "WOFF Web Font", DetectionSource::MagicSignature));
    }
    if b.starts_with(b"OTTO") {
        return Some((
            "font/otf",
            "otf",
            "OpenType Font (CFF)",
            DetectionSource::MagicSignature,
        ));
    }
    if b.starts_with(b"ttcf") && len >= 12 {
        return Some((
            "font/collection",
            "ttc",
            "TrueType Font Collection",
            DetectionSource::MagicSignature,
        ));
    }
    if len >= 28 && (b.starts_with(b"\x00\x01\x00\x00") || b.starts_with(b"true")) && looks_like_sfnt_ttf(b) {
        return Some(("font/ttf", "ttf", "TrueType Font", DetectionSource::ContainerInspection));
    }
    if len >= 82 && &b[34..36] == b"LP" && matches!(b[36..40], [0, 0, 1, 0] | [1, 0, 2, 0] | [2, 0, 2, 0]) {
        return Some((
            "application/vnd.ms-fontobject",
            "eot",
            "Embedded OpenType Font",
            DetectionSource::MagicSignature,
        ));
    }

    // WebAssembly
    if b.starts_with(b"\x00asm\x01\x00\x00\x00") {
        return Some((
            "application/wasm",
            "wasm",
            "WebAssembly Binary Module",
            DetectionSource::MagicSignature,
        ));
    }

    // WebM / Matroska (EBML)
    if len >= 16 && b.starts_with(b"\x1a\x45\xdf\xa3") {
        let head = &b[..len.min(128)];
        if find_subslice(head, b"webm").is_some() {
            return Some((
                "video/webm",
                "webm",
                "WebM Media Container",
                DetectionSource::ContainerInspection,
            ));
        }
        return Some((
            "video/x-matroska",
            "mkv",
            "Matroska Media Container",
            DetectionSource::ContainerInspection,
        ));
    }

    // Ogg container
    if len >= 36 && b.starts_with(b"OggS") {
        let head = &b[..len.min(128)];
        if find_subslice(head, b"OpusHead").is_some() {
            return Some((
                "audio/opus",
                "opus",
                "Opus Audio (Ogg)",
                DetectionSource::ContainerInspection,
            ));
        }
        if find_subslice(head, b"\x80theora").is_some() {
            return Some((
                "video/ogg",
                "ogv",
                "Ogg Theora Video",
                DetectionSource::ContainerInspection,
            ));
        }
        return Some((
            "audio/ogg",
            "ogg",
            "Ogg Vorbis Audio",
            DetectionSource::ContainerInspection,
        ));
    }

    // FLAC, MIDI, FLV, MP3 (ID3), MPEG-TS
    if b.starts_with(b"fLaC") {
        return Some((
            "audio/flac",
            "flac",
            "FLAC Lossless Audio",
            DetectionSource::MagicSignature,
        ));
    }
    if len >= 14 && b.starts_with(b"MThd\x00\x00\x00\x06") {
        return Some(("audio/midi", "mid", "MIDI Sequence", DetectionSource::MagicSignature));
    }
    if len >= 9 && b.starts_with(b"FLV\x01") {
        return Some((
            "video/x-flv",
            "flv",
            "Flash Video (FLV)",
            DetectionSource::MagicSignature,
        ));
    }
    if len >= 10 && b.starts_with(b"ID3") && b[3] <= 4 {
        return Some(("audio/mpeg", "mp3", "MP3 Audio (ID3)", DetectionSource::MagicSignature));
    }
    if looks_like_raw_aac_adts(b) {
        return Some((
            "audio/aac",
            "aac",
            "AAC Audio (ADTS)",
            DetectionSource::ContainerInspection,
        ));
    }
    if looks_like_raw_mp3_frames(b) {
        return Some((
            "audio/mpeg",
            "mp3",
            "MP3 Audio (MPEG Frames)",
            DetectionSource::ContainerInspection,
        ));
    }
    if len >= 377 && b[0] == 0x47 && b[188] == 0x47 && b[376] == 0x47 {
        return Some((
            "video/mp2t",
            "ts",
            "MPEG Transport Stream",
            DetectionSource::ContainerInspection,
        ));
    }

    // PDF & PostScript
    if b.starts_with(b"%PDF-") {
        return Some((
            "application/pdf",
            "pdf",
            "PDF Document",
            DetectionSource::MagicSignature,
        ));
    }
    if b.starts_with(b"%!PS-Adobe-") {
        return Some((
            "application/postscript",
            "ps",
            "PostScript Document",
            DetectionSource::MagicSignature,
        ));
    }

    // Chrome Extension CRX (v2/v3)
    if len >= 12 && b.starts_with(b"Cr24") && matches!(u32::from_le_bytes([b[4], b[5], b[6], b[7]]), 2 | 3) {
        return Some((
            "application/x-chrome-extension",
            "crx",
            "Chrome Extension Package (CRX)",
            DetectionSource::MagicSignature,
        ));
    }

    // Flash SWF
    if len >= 8 && (b.starts_with(b"FWS") || b.starts_with(b"CWS") || b.starts_with(b"ZWS")) && (1..=60).contains(&b[3])
    {
        return Some((
            "application/x-shockwave-flash",
            "swf",
            "Adobe Flash (SWF)",
            DetectionSource::MagicSignature,
        ));
    }

    // WebBundle (Signed HTTP Exchanges / Chrome WebBundle)
    if b.starts_with(b"\x84\x48\xf0\x9f\x8c\x90\xf0\x9f\x93\xa6")
        || b.starts_with(b"\x86\x48\xf0\x9f\x8c\x90\xf0\x9f\x93\xa6")
    {
        return Some((
            "application/webbundle",
            "wbn",
            "WebBundle Archive",
            DetectionSource::MagicSignature,
        ));
    }

    // SQLite 3 Database
    if b.starts_with(b"SQLite format 3\0") {
        return Some((
            "application/vnd.sqlite3",
            "sqlite",
            "SQLite 3 Database",
            DetectionSource::MagicSignature,
        ));
    }

    // Windows PE Executable / DLL (verify e_lfanew -> PE\0\0 header)
    if let Some(pe) = detect_pe(b) {
        return Some(pe);
    }

    // ELF Executable / Shared Object
    if len >= 20 && b.starts_with(b"\x7fELF") && (1..=2).contains(&b[4]) && (1..=2).contains(&b[5]) {
        let e_type = if b[5] == 1 {
            u16::from_le_bytes([b[16], b[17]])
        } else {
            u16::from_be_bytes([b[16], b[17]])
        };
        if e_type == 3 {
            return Some((
                "application/x-sharedlib",
                "so",
                "ELF Shared Object / PIE",
                DetectionSource::MagicSignature,
            ));
        }
        return Some((
            "application/x-elf",
            "elf",
            "ELF Binary",
            DetectionSource::MagicSignature,
        ));
    }

    // Mach-O Executable / Fat Binary
    if len >= 20
        && matches!(
            &b[0..4],
            [0xfe, 0xed, 0xfa, 0xce] | [0xfe, 0xed, 0xfa, 0xcf] | [0xce, 0xfa, 0xed, 0xfe] | [0xcf, 0xfa, 0xed, 0xfe]
        )
    {
        return Some((
            "application/x-mach-binary",
            "macho",
            "Mach-O Executable / Dylib",
            DetectionSource::MagicSignature,
        ));
    }
    if len >= 28 && &b[0..4] == b"\xca\xfe\xba\xbe" && u32::from_be_bytes([b[4], b[5], b[6], b[7]]) <= 16 {
        return Some((
            "application/x-mach-binary",
            "macho",
            "Mach-O Universal Binary",
            DetectionSource::MagicSignature,
        ));
    }

    // ZIP + OOXML / JAR / APK / EPUB container inspection
    if len >= 30 && (b.starts_with(b"PK\x03\x04") || b.starts_with(b"PK\x05\x06")) {
        return Some(inspect_zip_container(b));
    }

    // Microsoft OLE2 Compound File Binary Format (DOC/XLS/PPT/MSI)
    if b.starts_with(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1") {
        let head = &b[..len.min(4096)];
        if find_subslice(head, b"WordDocument").is_some() || find_utf16_le(head, "WordDocument") {
            return Some((
                "application/msword",
                "doc",
                "Microsoft Word Document (OLE2)",
                DetectionSource::ContainerInspection,
            ));
        }
        if find_utf16_le(head, "Workbook") || find_subslice(head, b"Workbook").is_some() {
            return Some((
                "application/vnd.ms-excel",
                "xls",
                "Microsoft Excel Workbook (OLE2)",
                DetectionSource::ContainerInspection,
            ));
        }
        if find_utf16_le(head, "PowerPoint Document") {
            return Some((
                "application/vnd.ms-powerpoint",
                "ppt",
                "Microsoft PowerPoint Presentation (OLE2)",
                DetectionSource::ContainerInspection,
            ));
        }
        return Some((
            "application/x-ole-storage",
            "ole",
            "OLE2 Compound Binary Document",
            DetectionSource::MagicSignature,
        ));
    }

    // RTF
    if b.starts_with(b"{\\rtf") {
        return Some((
            "application/rtf",
            "rtf",
            "Rich Text Format (RTF)",
            DetectionSource::MagicSignature,
        ));
    }

    // Archives & Compressors
    if b.starts_with(b"7z\xbc\xaf\x27\x1c") {
        return Some((
            "application/x-7z-compressed",
            "7z",
            "7-Zip Archive",
            DetectionSource::MagicSignature,
        ));
    }
    if b.starts_with(b"Rar!\x1a\x07\x00") || b.starts_with(b"Rar!\x1a\x07\x01\x00") {
        return Some((
            "application/vnd.rar",
            "rar",
            "RAR Archive",
            DetectionSource::MagicSignature,
        ));
    }
    if len >= 3 && b.starts_with(b"\x1f\x8b\x08") {
        return Some((
            "application/gzip",
            "gz",
            "Gzip Compressed Stream",
            DetectionSource::MagicSignature,
        ));
    }
    if b.starts_with(b"\x28\xb5\x2f\xfd") {
        return Some((
            "application/zstd",
            "zst",
            "Zstandard Archive",
            DetectionSource::MagicSignature,
        ));
    }
    if len >= 4 && b.starts_with(b"BZh") && (b'1'..=b'9').contains(&b[3]) {
        return Some((
            "application/x-bzip2",
            "bz2",
            "Bzip2 Archive",
            DetectionSource::MagicSignature,
        ));
    }
    if b.starts_with(b"\xfd7zXZ\x00") {
        return Some((
            "application/x-xz",
            "xz",
            "XZ Compressed Stream",
            DetectionSource::MagicSignature,
        ));
    }
    if b.starts_with(b"\x04\x22\x4d\x18") {
        return Some(("application/x-lz4", "lz4", "LZ4 Frame", DetectionSource::MagicSignature));
    }
    if len >= 36 && b.starts_with(b"MSCF\x00\x00\x00\x00") {
        return Some((
            "application/vnd.ms-cab-compressed",
            "cab",
            "Microsoft Cabinet Archive",
            DetectionSource::MagicSignature,
        ));
    }
    if len >= 28 && b.starts_with(b"xar!") {
        return Some((
            "application/vnd.apple.installer+xml",
            "pkg",
            "XAR / macOS PKG Installer",
            DetectionSource::MagicSignature,
        ));
    }
    if len >= 512 && &b[len - 512..len - 508] == b"koly" {
        return Some((
            "application/x-apple-diskimage",
            "dmg",
            "Apple UDIF Disk Image",
            DetectionSource::MagicSignature,
        ));
    }
    if len >= 265 && &b[257..262] == b"ustar" {
        return Some((
            "application/x-tar",
            "tar",
            "POSIX TAR Archive",
            DetectionSource::MagicSignature,
        ));
    }

    // Windows Shortcut LNK
    if len >= 76 && b.starts_with(b"\x4c\x00\x00\x00\x01\x14\x02\x00\x00\x00\x00\x00\xc0\x00\x00\x00") {
        return Some((
            "application/x-ms-shortcut",
            "lnk",
            "Windows Shell Link (LNK)",
            DetectionSource::MagicSignature,
        ));
    }

    // SPIR-V Shader (GPUCache / DawnCache)
    if len >= 20 && b.starts_with(b"\x03\x02\x23\x07") && b[6] <= 2 {
        return Some((
            "application/x-spirv",
            "spv",
            "SPIR-V Shader Binary",
            DetectionSource::MagicSignature,
        ));
    }

    None
}

fn detect_isobmff(b: &[u8]) -> Option<(&'static str, &'static str, &'static str, DetectionSource)> {
    let box_len = u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as usize;

    match &b[4..8] {
        b"ftyp" => {
            if !(16..=1024).contains(&box_len) {
                return None;
            }
            let brand = &b[8..12];
            // Check AVIF / HEIC first across major brand & compatible brands
            let limit = box_len.min(b.len());
            let mut has_avif = matches!(brand, b"avif" | b"avis");
            let mut has_heic = matches!(brand, b"heic" | b"heix" | b"heim" | b"heis");
            let mut has_heif = matches!(brand, b"mif1" | b"msf1" | b"heif");

            let mut off = 16;
            while off + 4 <= limit {
                match &b[off..off + 4] {
                    b"avif" | b"avis" => has_avif = true,
                    b"heic" | b"heix" | b"heim" | b"heis" => has_heic = true,
                    b"mif1" | b"msf1" | b"heif" => has_heif = true,
                    _ => {}
                }
                off += 4;
            }

            if has_avif {
                return Some((
                    "image/avif",
                    "avif",
                    "AVIF Image (ISO BMFF)",
                    DetectionSource::ContainerInspection,
                ));
            }
            if has_heic {
                return Some((
                    "image/heic",
                    "heic",
                    "HEIC Image (ISO BMFF)",
                    DetectionSource::ContainerInspection,
                ));
            }
            if has_heif {
                return Some((
                    "image/heif",
                    "heif",
                    "HEIF Image (ISO BMFF)",
                    DetectionSource::ContainerInspection,
                ));
            }
            match brand {
                b"M4A " | b"M4B " | b"M4P " => Some((
                    "audio/mp4",
                    "m4a",
                    "MPEG-4 Audio (M4A)",
                    DetectionSource::ContainerInspection,
                )),
                b"qt  " => Some((
                    "video/quicktime",
                    "mov",
                    "Apple QuickTime Video",
                    DetectionSource::ContainerInspection,
                )),
                b"dash" | b"msdh" | b"cmfc" => Some((
                    "video/iso.segment",
                    "m4s",
                    "MPEG-DASH Media Segment",
                    DetectionSource::ContainerInspection,
                )),
                _ => Some((
                    "video/mp4",
                    "mp4",
                    "MP4 Media Container",
                    DetectionSource::ContainerInspection,
                )),
            }
        }
        b"styp" => {
            if !(16..=1024).contains(&box_len) {
                return None;
            }
            Some((
                "video/iso.segment",
                "m4s",
                "Fragmented MP4 Segment (styp)",
                DetectionSource::ContainerInspection,
            ))
        }
        b"sidx" => {
            if !(24..=1_048_576).contains(&box_len) {
                return None;
            }
            Some((
                "video/iso.segment",
                "m4s",
                "Fragmented MP4 Segment Index (sidx)",
                DetectionSource::ContainerInspection,
            ))
        }
        b"moof" => {
            if !(16..=67_108_864).contains(&box_len) || b.len() < 16 || &b[12..16] != b"mfhd" {
                return None;
            }
            Some((
                "video/iso.segment",
                "m4s",
                "Fragmented MP4 Media Segment (moof)",
                DetectionSource::ContainerInspection,
            ))
        }
        _ => None,
    }
}

fn looks_like_sfnt_ttf(b: &[u8]) -> bool {
    let num_tables = u16::from_be_bytes([b[4], b[5]]) as usize;
    if !(4..=64).contains(&num_tables) {
        return false;
    }
    let table_end = 12 + num_tables.min(4) * 16;
    if b.len() < table_end {
        return false;
    }
    // Check first table tag is printable ASCII SFNT tag
    b[12..16].iter().all(|&c| (0x20..=0x7e).contains(&c))
}

fn looks_like_raw_aac_adts(b: &[u8]) -> bool {
    let parse_frame = |slice: &[u8]| -> Option<(u8, usize)> {
        if slice.len() < 7 {
            return None;
        }
        // ADTS 12-bit syncword (0xFFF) + MPEG Layer 00
        if slice[0] != 0xff || (slice[1] & 0xf6) != 0xf0 {
            return None;
        }
        let freq_idx = (slice[2] >> 2) & 0x0f;
        if freq_idx >= 13 {
            return None;
        }
        let frame_len =
            (((slice[3] & 0x03) as usize) << 11) | ((slice[4] as usize) << 3) | (((slice[5] >> 5) as usize) & 0x07);
        if !(7..=8192).contains(&frame_len) {
            return None;
        }
        Some((freq_idx, frame_len))
    };

    let Some((freq1, len1)) = parse_frame(b) else {
        return false;
    };
    if len1 + 7 > b.len() {
        return false;
    }
    parse_frame(&b[len1..]).is_some_and(|(freq2, _)| freq1 == freq2)
}

fn looks_like_raw_mp3_frames(b: &[u8]) -> bool {
    let parse_frame = |slice: &[u8]| -> Option<(u8, u8, usize)> {
        if slice.len() < 4 {
            return None;
        }
        if slice[0] != 0xff || (slice[1] & 0xe0) != 0xe0 {
            return None;
        }
        let ver_bits = (slice[1] >> 3) & 0x03; // 0 = 2.5, 1 = reserved, 2 = 2, 3 = 1
        let layer = (slice[1] >> 1) & 0x03; // 1 = Layer III
        if ver_bits == 1 || layer != 1 {
            return None;
        }
        let br_idx = ((slice[2] >> 4) & 0x0f) as usize;
        let sr_idx = ((slice[2] >> 2) & 0x03) as usize;
        if br_idx == 0 || br_idx == 15 || sr_idx >= 3 {
            return None;
        }
        let padding = ((slice[2] >> 1) & 0x01) as usize;

        const SR_V1: [usize; 3] = [44100, 48000, 32000];
        const SR_V2: [usize; 3] = [22050, 24000, 16000];
        const SR_V25: [usize; 3] = [11025, 12000, 8000];
        const BR_V1_L3: [usize; 16] = [0, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 0];
        const BR_V2_L3: [usize; 16] = [0, 8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 144, 160, 0];

        let (sample_rate, bitrate_kbps, coeff) = if ver_bits == 3 {
            (SR_V1[sr_idx], BR_V1_L3[br_idx], 144usize)
        } else if ver_bits == 2 {
            (SR_V2[sr_idx], BR_V2_L3[br_idx], 72usize)
        } else {
            (SR_V25[sr_idx], BR_V2_L3[br_idx], 72usize)
        };
        let frame_size = coeff * (bitrate_kbps * 1000) / sample_rate + padding;
        if frame_size < 24 {
            return None;
        }
        Some((ver_bits, sr_idx as u8, frame_size))
    };

    let Some((ver1, sr1, len1)) = parse_frame(b) else {
        return false;
    };
    if len1 + 4 > b.len() {
        return false;
    }
    parse_frame(&b[len1..]).is_some_and(|(ver2, sr2, _)| ver1 == ver2 && sr1 == sr2)
}

fn detect_pe(b: &[u8]) -> Option<(&'static str, &'static str, &'static str, DetectionSource)> {
    if b.len() < 0x40 || !b.starts_with(b"MZ") {
        return None;
    }
    let e_lfanew = u32::from_le_bytes([b[0x3c], b[0x3d], b[0x3e], b[0x3f]]) as usize;
    if e_lfanew >= 0x40
        && e_lfanew.checked_add(24).is_some_and(|end| end <= b.len())
        && &b[e_lfanew..e_lfanew + 4] == b"PE\0\0"
    {
        let chars = u16::from_le_bytes([b[e_lfanew + 22], b[e_lfanew + 23]]);
        let opt_magic = if e_lfanew.checked_add(26).is_some_and(|end| end <= b.len()) {
            u16::from_le_bytes([b[e_lfanew + 24], b[e_lfanew + 25]])
        } else {
            0
        };
        let bitness = match opt_magic {
            0x020b => "PE32+",
            0x010b => "PE32",
            _ => "PE",
        };
        if (chars & 0x2000) != 0 {
            let desc = if bitness == "PE32+" {
                "Windows PE32+ DLL"
            } else {
                "Windows PE32 DLL"
            };
            return Some((
                "application/vnd.microsoft.portable-executable",
                "dll",
                desc,
                DetectionSource::MagicSignature,
            ));
        }
        let desc = if bitness == "PE32+" {
            "Windows PE32+ Executable"
        } else {
            "Windows PE32 Executable"
        };
        return Some((
            "application/vnd.microsoft.portable-executable",
            "exe",
            desc,
            DetectionSource::MagicSignature,
        ));
    }
    if find_subslice(&b[..b.len().min(256)], b"This program cannot be run in DOS mode").is_some() {
        return Some((
            "application/vnd.microsoft.portable-executable",
            "exe",
            "Windows PE Executable (DOS Stub)",
            DetectionSource::MagicSignature,
        ));
    }
    None
}

fn inspect_zip_container(b: &[u8]) -> (&'static str, &'static str, &'static str, DetectionSource) {
    let head = &b[..b.len().min(16 * 1024)];
    if find_subslice(head, b"mimetypeapplication/epub+zip").is_some() {
        return (
            "application/epub+zip",
            "epub",
            "EPUB E-Book Archive",
            DetectionSource::ContainerInspection,
        );
    }
    if find_subslice(head, b"mimetypeapplication/vnd.oasis.opendocument.text").is_some() {
        return (
            "application/vnd.oasis.opendocument.text",
            "odt",
            "OpenDocument Text (ODT)",
            DetectionSource::ContainerInspection,
        );
    }
    if find_subslice(head, b"mimetypeapplication/vnd.oasis.opendocument.spreadsheet").is_some() {
        return (
            "application/vnd.oasis.opendocument.spreadsheet",
            "ods",
            "OpenDocument Spreadsheet (ODS)",
            DetectionSource::ContainerInspection,
        );
    }
    if find_subslice(head, b"mimetypeapplication/vnd.oasis.opendocument.presentation").is_some() {
        return (
            "application/vnd.oasis.opendocument.presentation",
            "odp",
            "OpenDocument Presentation (ODP)",
            DetectionSource::ContainerInspection,
        );
    }
    if find_subslice(head, b"AndroidManifest.xml").is_some() {
        return (
            "application/vnd.android.package-archive",
            "apk",
            "Android Package (APK)",
            DetectionSource::ContainerInspection,
        );
    }
    if find_subslice(head, b"word/document.xml").is_some() || find_subslice(head, b"word/_rels/").is_some() {
        return (
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            "docx",
            "Microsoft Word Document (OOXML)",
            DetectionSource::ContainerInspection,
        );
    }
    if find_subslice(head, b"xl/workbook.xml").is_some() || find_subslice(head, b"xl/_rels/").is_some() {
        return (
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            "xlsx",
            "Microsoft Excel Workbook (OOXML)",
            DetectionSource::ContainerInspection,
        );
    }
    if find_subslice(head, b"ppt/presentation.xml").is_some() || find_subslice(head, b"ppt/_rels/").is_some() {
        return (
            "application/vnd.openxmlformats-officedocument.presentationml.presentation",
            "pptx",
            "Microsoft PowerPoint Presentation (OOXML)",
            DetectionSource::ContainerInspection,
        );
    }
    if find_subslice(head, b"META-INF/MANIFEST.MF").is_some() {
        return (
            "application/java-archive",
            "jar",
            "Java Archive (JAR)",
            DetectionSource::ContainerInspection,
        );
    }
    ("application/zip", "zip", "ZIP Archive", DetectionSource::MagicSignature)
}

fn decode_text_bom(b: &[u8]) -> Option<std::borrow::Cow<'_, [u8]>> {
    if let Some(rest) = b.strip_prefix(b"\xef\xbb\xbf") {
        return Some(std::borrow::Cow::Borrowed(rest));
    }
    let is_le = b.starts_with(b"\xff\xfe");
    let is_be = b.starts_with(b"\xfe\xff");
    if (is_le || is_be) && b.len() >= 4 {
        let raw = &b[2..b.len().min(64 * 1024)];
        let pairs = (0..raw.len() / 2).map(|i| {
            let pair = [raw[i * 2], raw[i * 2 + 1]];
            if is_le {
                u16::from_le_bytes(pair)
            } else {
                u16::from_be_bytes(pair)
            }
        });
        let mut out = String::new();
        for res in char::decode_utf16(pairs) {
            let Ok(ch) = res else {
                return None;
            };
            if ch == '\0' {
                return None;
            }
            out.push(ch);
        }
        if !out.is_empty() {
            return Some(std::borrow::Cow::Owned(out.into_bytes()));
        }
        return None;
    }
    Some(std::borrow::Cow::Borrowed(b))
}

/// Detects text-based formats (HTML, MHTML, SVG, XML, JSON, JS, CSS, M3U8, VTT, PEM, Plain Text).
pub fn detect_text_bytes(
    b: &[u8],
    url_ext_hint: Option<&str>,
) -> Option<(&'static str, &'static str, &'static str, DetectionSource)> {
    if b.is_empty() {
        return None;
    }

    let decoded = decode_text_bom(b)?;
    let slice = decoded.as_ref();
    let sample_len = valid_utf8_prefix_len(&slice[..slice.len().min(32 * 1024)]);
    let sample_bytes = &slice[..sample_len];
    if sample_bytes.is_empty() {
        return None;
    }

    let Ok(text) = std::str::from_utf8(sample_bytes) else {
        return None;
    };

    // Reject binary buffers containing NUL or excessive non-whitespace control characters
    let ctrl_count = text
        .bytes()
        .filter(|&c| c < 0x20 && !matches!(c, b'\n' | b'\r' | b'\t'))
        .count();
    if text.as_bytes().contains(&0) || ctrl_count > (sample_bytes.len() / 50).max(2) {
        return None;
    }

    let trimmed = text.trim_start();
    if trimmed.is_empty() {
        return Some(("text/plain", "txt", "Whitespace Text", DetectionSource::TextHeuristic));
    }
    let mut lower_end = trimmed.len().min(2048);
    while lower_end > 0 && !trimmed.is_char_boundary(lower_end) {
        lower_end -= 1;
    }
    let lower = trimmed[..lower_end].to_ascii_lowercase();

    // PEM Certificate / Key
    if trimmed.starts_with("-----BEGIN CERTIFICATE-----") {
        return Some((
            "application/x-pem-file",
            "pem",
            "PEM X.509 Certificate",
            DetectionSource::TextHeuristic,
        ));
    }

    // MHTML Web Archive
    if (lower.starts_with("from:") || lower.starts_with("mime-version:")) && lower.contains("multipart/related") {
        return Some((
            "multipart/related",
            "mhtml",
            "MHTML Web Archive",
            DetectionSource::TextHeuristic,
        ));
    }

    // HLS / WebVTT
    if trimmed.starts_with("#EXTM3U") {
        return Some((
            "application/vnd.apple.mpegurl",
            "m3u8",
            "HLS M3U8 Playlist",
            DetectionSource::TextHeuristic,
        ));
    }
    if trimmed.starts_with("WEBVTT") {
        return Some(("text/vtt", "vtt", "WebVTT Subtitles", DetectionSource::TextHeuristic));
    }

    // XML & XML-derived formats (SVG, HTML, XHTML, RSS, Atom, Plist)
    if lower.starts_with("<svg")
        || (lower.starts_with("<?xml") && lower.contains("<svg"))
        || (lower.starts_with("<!doctype svg") && lower.contains("<svg"))
        || (lower.starts_with("<!--")
            && lower.contains("<svg")
            && !lower.contains("<!doctype html")
            && !lower.contains("<html")
            && !lower.contains("<body"))
    {
        return Some((
            "image/svg+xml",
            "svg",
            "SVG Vector Image",
            DetectionSource::TextHeuristic,
        ));
    }
    if lower.starts_with("<!doctype html")
        || lower.starts_with("<html")
        || lower.starts_with("<head")
        || lower.starts_with("<body")
        || lower.starts_with("<meta ")
        || lower.starts_with("<script")
        || lower.starts_with("<title>")
        || (lower.starts_with("<!--")
            && (lower.contains("<!doctype html")
                || lower.contains("<html")
                || lower.contains("<head")
                || lower.contains("<body")
                || lower.contains("<div")))
    {
        return Some(("text/html", "html", "HTML Document", DetectionSource::TextHeuristic));
    }
    if lower.starts_with("<?xml") {
        if lower.contains("<html") {
            return Some((
                "application/xhtml+xml",
                "xhtml",
                "XHTML Document",
                DetectionSource::TextHeuristic,
            ));
        }
        if lower.contains("<rss") {
            return Some(("application/rss+xml", "rss", "RSS Feed", DetectionSource::TextHeuristic));
        }
        if lower.contains("<feed") {
            return Some((
                "application/atom+xml",
                "atom",
                "Atom Feed",
                DetectionSource::TextHeuristic,
            ));
        }
        if lower.contains("<!doctype plist") || lower.contains("<plist") {
            return Some((
                "application/xml",
                "plist",
                "Apple Property List (XML)",
                DetectionSource::TextHeuristic,
            ));
        }
        return Some(("application/xml", "xml", "XML Document", DetectionSource::TextHeuristic));
    }
    if lower.starts_with("<rss") {
        return Some(("application/rss+xml", "rss", "RSS Feed", DetectionSource::TextHeuristic));
    }
    if lower.starts_with("<feed") && lower.contains("xmlns") {
        return Some((
            "application/atom+xml",
            "atom",
            "Atom Feed",
            DetectionSource::TextHeuristic,
        ));
    }

    // JSON (validated via streaming IgnoredAny; accepts truncated prefix reads >= 16 KiB hitting EOF)
    if trimmed.starts_with('{') || trimmed.starts_with('[') {
        let json_window_len = valid_utf8_prefix_len(&slice[..slice.len().min(512 * 1024)]);
        let json_slice = &slice[..json_window_len];
        let is_valid_json = match serde_json::from_slice::<serde::de::IgnoredAny>(json_slice) {
            Ok(_) => true,
            Err(e) => json_slice.len() >= 16 * 1024 && e.is_eof(),
        };
        if is_valid_json {
            if (lower.contains("\"version\":3") || lower.contains("\"version\": 3"))
                && lower.contains("\"sources\"")
                && lower.contains("\"mappings\"")
            {
                return Some((
                    "application/json",
                    "map",
                    "JavaScript Source Map (JSON)",
                    DetectionSource::TextHeuristic,
                ));
            }
            if (lower.contains("\"short_name\"") || lower.contains("\"display\"")) && lower.contains("\"start_url\"") {
                return Some((
                    "application/manifest+json",
                    "webmanifest",
                    "Web App Manifest (JSON)",
                    DetectionSource::TextHeuristic,
                ));
            }
            return Some((
                "application/json",
                "json",
                "JSON Document",
                DetectionSource::TextHeuristic,
            ));
        }
    }

    // Strong JavaScript / ESM markers
    if starts_like_javascript(trimmed, &lower) {
        return Some((
            "application/javascript",
            "js",
            "JavaScript Source",
            DetectionSource::TextHeuristic,
        ));
    }

    // Strong CSS markers (check after JS because JS might contain CSS strings)
    if starts_like_css(trimmed, &lower) {
        return Some(("text/css", "css", "CSS Stylesheet", DetectionSource::TextHeuristic));
    }

    // Only emit UTF-8 Plain Text if buffer is completely valid UTF-8 (within scanned window)
    if slice.len() == sample_len || std::str::from_utf8(sample_bytes).is_ok() {
        let _ = url_ext_hint;
        return Some(("text/plain", "txt", "UTF-8 Text", DetectionSource::TextHeuristic));
    }

    None
}

fn starts_like_javascript(trimmed: &str, lower: &str) -> bool {
    let has_js_tokens = lower.contains("function(")
        || lower.contains("function (")
        || lower.contains("const ")
        || lower.contains("var ")
        || lower.contains("let ")
        || lower.contains("export ")
        || lower.contains("import ")
        || lower.contains("module.exports")
        || lower.contains("=>");

    trimmed.starts_with("'use strict'")
        || trimmed.starts_with("\"use strict\"")
        || trimmed.starts_with("(function(")
        || trimmed.starts_with("(function (")
        || trimmed.starts_with("(async function")
        || trimmed.starts_with("async function")
        || trimmed.starts_with("(()=>{")
        || trimmed.starts_with("(() => {")
        || trimmed.starts_with("(()=>")
        || trimmed.starts_with("(() =>")
        || trimmed.starts_with("!(()=>{")
        || trimmed.starts_with("!(() =>")
        || trimmed.starts_with("!function(")
        || trimmed.starts_with("!(function")
        || trimmed.starts_with("+function")
        || trimmed.starts_with("~function")
        || trimmed.starts_with("define([")
        || trimmed.starts_with("define(\"")
        || trimmed.starts_with("define('")
        || trimmed.starts_with("self.webpackChunk")
        || trimmed.starts_with("(self.webpackChunk")
        || trimmed.starts_with("self[\"webpackChunk")
        || trimmed.starts_with("(self[\"webpackChunk")
        || trimmed.starts_with("(window.webpackJsonp")
        || trimmed.starts_with("globalThis.")
        || lower.starts_with("import ")
        || lower.starts_with("export default ")
        || lower.starts_with("export function ")
        || lower.starts_with("export const ")
        || trimmed.contains("//# sourceMappingURL=")
        || trimmed.contains("/*# sourceMappingURL=")
        || (trimmed.starts_with("function ") && (trimmed.contains("){") || trimmed.contains(") {")))
        || ((lower.starts_with("var ") || lower.starts_with("const ") || lower.starts_with("let "))
            && lower.contains('=')
            && (lower.contains(';') || lower.contains("=>") || lower.contains("function")))
        || ((trimmed.starts_with("/*! ")
            || trimmed.starts_with("//!")
            || trimmed.starts_with("/**")
            || trimmed.starts_with("//"))
            && !lower.contains("<!doctype")
            && !lower.contains("<html")
            && has_js_tokens)
}

fn starts_like_css(trimmed: &str, lower: &str) -> bool {
    lower.starts_with("@charset ")
        || lower.starts_with("@import url(")
        || lower.starts_with("@font-face")
        || lower.starts_with("@keyframes ")
        || lower.starts_with("@media ")
        || lower.starts_with("@layer ")
        || trimmed.starts_with(":root{")
        || trimmed.starts_with(":root {")
        || (trimmed.starts_with("/*")
            && lower.contains('{')
            && lower.contains('}')
            && !lower.contains("function")
            && !lower.contains("=>")
            && !lower.contains("var ")
            && (lower.contains("color:")
                || lower.contains("margin:")
                || lower.contains("display:")
                || lower.contains("font-size:")
                || lower.contains("background:")))
}

fn valid_utf8_prefix_len(slice: &[u8]) -> usize {
    match std::str::from_utf8(slice) {
        Ok(_) => slice.len(),
        Err(e) => e.valid_up_to(),
    }
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn find_utf16_le(haystack: &[u8], ascii: &str) -> bool {
    let pattern: Vec<u8> = ascii.bytes().flat_map(|b| [b, 0]).collect();
    find_subslice(haystack, &pattern).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_magic_detection_and_missing_extensions() {
        let png = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR";
        let d_png = detect_content(png, None, Some("https://cdn.example.com/avatar/12345"), None);
        assert_eq!(d_png.mime.as_deref(), Some("image/png"));
        assert_eq!(d_png.extension.as_deref(), Some("png"));
        assert!(!d_png.mime_mismatch);

        // WebP masquerading with octet-stream header (should upgrade cleanly without mismatch alert)
        let webp = b"RIFF\x24\x00\x00\x00WEBPVP8 ";
        let d_webp = detect_content(
            webp,
            Some("application/octet-stream"),
            Some("https://pbs.twimg.com/media/AbcDef?format=webp"),
            None,
        );
        assert_eq!(d_webp.mime.as_deref(), Some("image/webp"));
        assert_eq!(d_webp.extension.as_deref(), Some("webp"));
        assert!(!d_webp.mime_mismatch);

        // AVIF ISO BMFF with compatible brand
        let mut avif = vec![0u8; 24];
        avif[0..4].copy_from_slice(&24u32.to_be_bytes());
        avif[4..8].copy_from_slice(b"ftyp");
        avif[8..12].copy_from_slice(b"mif1");
        avif[16..20].copy_from_slice(b"avif");
        let d_avif = detect_content(&avif, None, None, None);
        assert_eq!(d_avif.mime.as_deref(), Some("image/avif"));
        assert_eq!(d_avif.extension.as_deref(), Some("avif"));

        // Fragmented MP4 moof + mfhd larger than 512 bytes (.m4s)
        let mut moof = vec![0u8; 1024];
        moof[0..4].copy_from_slice(&1024u32.to_be_bytes());
        moof[4..8].copy_from_slice(b"moof");
        moof[8..12].copy_from_slice(&16u32.to_be_bytes());
        moof[12..16].copy_from_slice(b"mfhd");
        let d_m4s = detect_content(&moof, Some("video/mp4"), None, None);
        assert_eq!(d_m4s.mime.as_deref(), Some("video/iso.segment"));
        assert_eq!(d_m4s.extension.as_deref(), Some("m4s"));
        assert!(!d_m4s.mime_mismatch);

        // WOFF2 + WASM
        assert_eq!(
            detect_content(b"wOF2\x00\x01\x00\x00", None, None, None)
                .extension
                .as_deref(),
            Some("woff2")
        );
        assert_eq!(
            detect_content(b"\x00asm\x01\x00\x00\x00", None, None, None)
                .extension
                .as_deref(),
            Some("wasm")
        );
    }

    #[test]
    fn test_raw_aac_adts_and_raw_mp3_frames() {
        // Two valid ADTS frames of length 16 each, freq_idx = 4 (44100Hz)
        let mut aac = vec![0u8; 40];
        for start in [0usize, 16usize] {
            aac[start] = 0xff;
            aac[start + 1] = 0xf1;
            aac[start + 2] = 0x50; // profile=1, freq_idx=4 (0100 << 2)
            aac[start + 3] = 0x40;
            aac[start + 4] = 0x02; // (16 >> 3) = 2
            aac[start + 5] = 0x1f;
            aac[start + 6] = 0xfc;
        }
        let d_aac = detect_content(&aac, Some("audio/x-aac"), None, None);
        assert_eq!(d_aac.mime.as_deref(), Some("audio/aac"));
        assert_eq!(d_aac.extension.as_deref(), Some("aac"));
        assert!(!d_aac.mime_mismatch);

        // Two valid MPEG-1 Layer III 128kbps 44100Hz frames (frame_size = 144 * 128000 / 44100 = 417 bytes each)
        let mut mp3 = vec![0u8; 417 * 2 + 16];
        for start in [0usize, 417usize] {
            mp3[start] = 0xff;
            mp3[start + 1] = 0xfb; // MPEG 1 (11), Layer III (01), no CRC (1)
            mp3[start + 2] = 0x90; // br_idx = 9 (128kbps), sr_idx = 0 (44100Hz), pad = 0
            mp3[start + 3] = 0x00;
        }
        let d_mp3 = detect_content(&mp3, Some("audio/mp3"), None, None);
        assert_eq!(d_mp3.mime.as_deref(), Some("audio/mpeg"));
        assert_eq!(d_mp3.extension.as_deref(), Some("mp3"));
        assert!(!d_mp3.mime_mismatch);
    }

    #[test]
    fn test_pe_and_mime_mismatch_detection() {
        let mut pe = vec![0u8; 128];
        pe[0..2].copy_from_slice(b"MZ");
        pe[0x3c..0x40].copy_from_slice(&64u32.to_le_bytes());
        pe[64..68].copy_from_slice(b"PE\0\0");
        pe[64 + 22..64 + 24].copy_from_slice(&0x2000u16.to_le_bytes()); // IMAGE_FILE_DLL
        pe[64 + 24..64 + 26].copy_from_slice(&0x020bu16.to_le_bytes()); // PE32+

        let det = detect_content(&pe, Some("image/png"), Some("https://evil.test/logo.png"), None);
        assert_eq!(
            det.mime.as_deref(),
            Some("application/vnd.microsoft.portable-executable")
        );
        assert_eq!(det.extension.as_deref(), Some("dll"));
        assert!(det.mime_mismatch);
        assert!(is_high_risk_mime_mismatch("image/png", det.mime.as_deref().unwrap()));

        // application/x-msdownload matching PE without false mismatch
        let det_ok = detect_content(&pe, Some("application/x-msdownload"), None, None);
        assert!(!det_ok.mime_mismatch);
    }

    #[test]
    fn test_ooxml_odt_zip_and_text_heuristics() {
        let mut zip_docx = b"PK\x03\x04\x14\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x11\x00\x00\x00word/document.xml".to_vec();
        zip_docx.extend_from_slice(b"rest");
        let det = detect_content(&zip_docx, None, Some("https://example.org/get?id=1"), None);
        assert_eq!(det.extension.as_deref(), Some("docx"));

        let mut zip_odt = b"PK\x03\x04\x14\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\x00\x00\x00mimetypeapplication/vnd.oasis.opendocument.text".to_vec();
        zip_odt.extend_from_slice(b"rest");
        assert_eq!(
            detect_content(&zip_odt, None, None, None).extension.as_deref(),
            Some("odt")
        );

        let svg = b"<!-- icon --><svg xmlns=\"http://www.w3.org/2000/svg\"></svg>";
        assert_eq!(detect_content(svg, None, None, None).extension.as_deref(), Some("svg"));

        let mhtml = b"From: <Saved by Blink>\r\nSubject: Page\r\nMIME-Version: 1.0\r\nContent-Type: multipart/related; boundary=\"--abc\"\r\n\r\n";
        assert_eq!(
            detect_content(mhtml, None, None, None).extension.as_deref(),
            Some("mhtml")
        );

        let pem = b"-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n";
        assert!(!detect_content(pem, Some("text/plain"), None, None).mime_mismatch);
        assert_eq!(
            detect_content(pem, Some("text/plain"), None, None).extension.as_deref(),
            Some("pem")
        );

        let json = br#"{"hello":"world","n":42}"#;
        assert_eq!(
            detect_content(json, Some("text/plain"), None, None)
                .extension
                .as_deref(),
            Some("json")
        );
        assert!(!detect_content(json, Some("text/plain"), None, None).mime_mismatch);

        // Truncated > 16 KiB JSON payload should still classify as JSON (not text/plain)
        let mut big_json = br#"{"items":["#.to_vec();
        while big_json.len() < 20 * 1024 {
            big_json.extend_from_slice(br#"{"id":1,"name":"sample"},"#);
        }
        assert_eq!(
            detect_content(&big_json, None, None, None).extension.as_deref(),
            Some("json")
        );

        // JavaScript IIFE / arrow variants
        assert_eq!(
            detect_content(b"(()=>{console.log(1)})()", None, None, None)
                .extension
                .as_deref(),
            Some("js")
        );
        assert_eq!(
            detect_content(b"'use strict';\nconst a = 1; export default a;", None, None, None)
                .extension
                .as_deref(),
            Some("js")
        );
    }

    #[test]
    fn test_content_disposition_and_url_query_parsing() {
        assert_eq!(
            parse_content_disposition_filename("attachment; filename=\"../evil/report 2026.pdf\"").as_deref(),
            Some("report 2026.pdf")
        );
        assert_eq!(
            parse_content_disposition_filename(
                "attachment; filename=fallback.bin; filename*=UTF-8''invoice%20%231.xlsx"
            )
            .as_deref(),
            Some("invoice #1.xlsx")
        );

        assert_eq!(extension_from_url("https://example.com/"), None);
        assert_eq!(extension_from_url("https://cdn.example.com/lib/jquery-3.7.1"), None);
        assert_eq!(extension_from_url("https://cdn.example.com/image.php?id=55"), None);
        assert_eq!(
            extension_from_url("https://pbs.twimg.com/media/123?format=avif&name=orig").as_deref(),
            Some("avif")
        );
        assert_eq!(
            extension_from_url("https://cdn.example.com/assets/app.min.js?v=9").as_deref(),
            Some("js")
        );
    }

    #[test]
    fn test_text_utf8_boundary_2048_and_pe_overflow() {
        // Multi-byte UTF-8 char ('€', 3 bytes) straddling byte 2048 must not panic
        let mut s = "a".repeat(2047);
        s.push('€');
        s.push_str(" trailing text");
        let det = detect_text_bytes(s.as_bytes(), None);
        assert!(det.is_some());

        // Huge e_lfanew close to u32::MAX must not overflow or panic
        let mut mz = vec![0u8; 128];
        mz[0..2].copy_from_slice(b"MZ");
        mz[0x3c..0x40].copy_from_slice(&(u32::MAX - 8).to_le_bytes());
        assert!(detect_magic_bytes(&mz).is_none());
    }
}
