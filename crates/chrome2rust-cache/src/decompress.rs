use chrome2rust_core::error::ChromeError;
use flate2::read::{DeflateDecoder, GzDecoder, ZlibDecoder};
use std::io::Read;

/// Maximum decompressed payload size (128 MiB) to guard against malformed cache streams.
const MAX_DECOMPRESS_BYTES: usize = 128 * 1024 * 1024;

fn read_capped<R: Read>(mut reader: R) -> std::io::Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut buf = [0u8; 16 * 1024];
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        if out.len().saturating_add(n) > MAX_DECOMPRESS_BYTES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "decompressed payload exceeds 128 MiB safety cap",
            ));
        }
        out.extend_from_slice(&buf[..n]);
    }
    Ok(out)
}

/// Decompresses cached HTTP payload bytes using `Content-Encoding` (or magic byte detection).
pub fn decompress_payload(raw: &[u8], content_encoding: Option<&str>) -> Result<Vec<u8>, ChromeError> {
    decompress_payload_for_type(raw, content_encoding, None)
}

/// Decompresses cached HTTP payload bytes while avoiding auto-magic decompression on
/// unencoded archive downloads (`application/gzip`, `application/zstd`, `application/x-tar`).
pub fn decompress_payload_for_type(
    raw: &[u8],
    content_encoding: Option<&str>,
    content_type: Option<&str>,
) -> Result<Vec<u8>, ChromeError> {
    if raw.is_empty() {
        return Ok(Vec::new());
    }
    let enc = content_encoding.unwrap_or("").trim().to_ascii_lowercase();
    let ct = content_type
        .unwrap_or("")
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    let is_archive_ct = matches!(
        ct.as_str(),
        "application/gzip"
            | "application/x-gzip"
            | "application/zstd"
            | "application/x-tar"
            | "application/x-compressed"
    );

    let tokens: Vec<&str> = enc
        .split(',')
        .map(|part| part.split(';').next().unwrap_or("").trim())
        .filter(|t| !t.is_empty() && *t != "identity")
        .collect();

    if tokens.is_empty() {
        if !is_archive_ct && raw.starts_with(&[0x1f, 0x8b, 0x08]) {
            return read_capped(GzDecoder::new(raw)).map_err(|e| ChromeError::Decompress {
                encoding: "gzip".into(),
                message: e.to_string(),
            });
        }
        if !is_archive_ct && raw.starts_with(&[0x28, 0xb5, 0x2f, 0xfd]) {
            let mut dec = ruzstd::decoding::StreamingDecoder::new(raw).map_err(|e| ChromeError::Decompress {
                encoding: "zstd".into(),
                message: e.to_string(),
            })?;
            return read_capped(&mut dec).map_err(|e| ChromeError::Decompress {
                encoding: "zstd".into(),
                message: e.to_string(),
            });
        }
        return Ok(raw.to_vec());
    }

    // If any unrecognized encoding token is present (e.g. "broken"), do not guess or corrupt bytes
    if !tokens
        .iter()
        .all(|t| matches!(*t, "gzip" | "x-gzip" | "br" | "brotli" | "zstd" | "zst" | "deflate"))
    {
        return Ok(raw.to_vec());
    }

    // Decode right-to-left according to HTTP Content-Encoding application order (cap chain depth at 4)
    if tokens.len() > 4 {
        return Err(ChromeError::Decompress {
            encoding: enc,
            message: "excessive chained Content-Encoding layers".into(),
        });
    }

    let mut cur = raw.to_vec();
    for &tok in tokens.iter().rev() {
        cur = match tok {
            "gzip" | "x-gzip" => read_capped(GzDecoder::new(cur.as_slice())).map_err(|e| ChromeError::Decompress {
                encoding: "gzip".into(),
                message: e.to_string(),
            })?,
            "br" | "brotli" => {
                let dec = brotli::Decompressor::new(cur.as_slice(), 4096);
                read_capped(dec).map_err(|e| ChromeError::Decompress {
                    encoding: "br".into(),
                    message: e.to_string(),
                })?
            }
            "zstd" | "zst" => {
                let mut dec =
                    ruzstd::decoding::StreamingDecoder::new(cur.as_slice()).map_err(|e| ChromeError::Decompress {
                        encoding: "zstd".into(),
                        message: e.to_string(),
                    })?;
                read_capped(&mut dec).map_err(|e| ChromeError::Decompress {
                    encoding: "zstd".into(),
                    message: e.to_string(),
                })?
            }
            "deflate" => {
                // HTTP "deflate" is technically zlib-wrapped, though some servers emit raw deflate
                if let Ok(v) = read_capped(ZlibDecoder::new(cur.as_slice())) {
                    v
                } else {
                    read_capped(DeflateDecoder::new(cur.as_slice())).map_err(|e| ChromeError::Decompress {
                        encoding: "deflate".into(),
                        message: e.to_string(),
                    })?
                }
            }
            _ => unreachable!(),
        };
    }

    Ok(cur)
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::Compression;
    use flate2::write::GzEncoder;
    use std::io::Write;

    #[test]
    fn test_gzip_roundtrip() {
        let original = b"<html><body>chrome2rust gzip test</body></html>";
        let mut enc = GzEncoder::new(Vec::new(), Compression::default());
        enc.write_all(original).unwrap();
        let compressed = enc.finish().unwrap();

        let dec = decompress_payload(&compressed, Some("gzip")).unwrap();
        assert_eq!(dec, original);
    }

    #[test]
    fn test_brotli_roundtrip() {
        let original = b"console.log('brotli works in rust');".repeat(10);
        let mut compressed = Vec::new();
        {
            let mut writer = brotli::CompressorWriter::new(&mut compressed, 4096, 5, 22);
            writer.write_all(&original).unwrap();
        }
        let dec = decompress_payload(&compressed, Some("br")).unwrap();
        assert_eq!(dec, original);
    }

    #[test]
    fn test_archive_content_type_preserved_when_unencoded() {
        let mut enc = GzEncoder::new(Vec::new(), Compression::default());
        enc.write_all(b"archive-member-payload").unwrap();
        let gz_archive = enc.finish().unwrap();

        let kept = decompress_payload_for_type(&gz_archive, None, Some("application/gzip")).unwrap();
        assert_eq!(kept, gz_archive);

        // When explicitly transfer-encoded with Content-Encoding: gzip, still decompress
        let unwrapped = decompress_payload_for_type(&gz_archive, Some("gzip"), Some("text/plain")).unwrap();
        assert_eq!(unwrapped, b"archive-member-payload");
    }

    #[test]
    fn test_token_matching_rejects_bogus_substrings_and_handles_chains() {
        // "broken" contains "br" as substring, must NOT trigger Brotli decoding
        let raw = b"plain unencoded bytes";
        let out = decompress_payload(raw, Some("broken")).unwrap();
        assert_eq!(out, raw);

        // Chained "deflate, gzip" decodes gzip outer layer then deflate inner layer
        let inner_msg = b"chained encoding payload";
        let mut def = flate2::write::ZlibEncoder::new(Vec::new(), Compression::default());
        def.write_all(inner_msg).unwrap();
        let deflated = def.finish().unwrap();
        let mut gz = GzEncoder::new(Vec::new(), Compression::default());
        gz.write_all(&deflated).unwrap();
        let chained = gz.finish().unwrap();

        let decoded = decompress_payload(&chained, Some("deflate, gzip")).unwrap();
        assert_eq!(decoded, inner_msg);
    }
}
