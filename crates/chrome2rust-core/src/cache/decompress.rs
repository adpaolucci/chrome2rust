use crate::error::ChromeError;
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
        if out.len() + n > MAX_DECOMPRESS_BYTES {
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
    if raw.is_empty() {
        return Ok(Vec::new());
    }
    let enc = content_encoding
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();

    // Handle chained or primary encodings cleanly
    if enc.contains("gzip") || enc.contains("x-gzip") || (enc.is_empty() && raw.starts_with(&[0x1f, 0x8b])) {
        let dec = GzDecoder::new(raw);
        return read_capped(dec).map_err(|e| ChromeError::Decompress {
            encoding: "gzip".into(),
            message: e.to_string(),
        });
    }
    if enc.contains("br") {
        let dec = brotli::Decompressor::new(raw, 4096);
        return read_capped(dec).map_err(|e| ChromeError::Decompress {
            encoding: "br".into(),
            message: e.to_string(),
        });
    }
    if enc.contains("zstd") || (enc.is_empty() && raw.starts_with(&[0x28, 0xb5, 0x2f, 0xfd])) {
        let mut dec = ruzstd::decoding::StreamingDecoder::new(raw).map_err(|e| ChromeError::Decompress {
            encoding: "zstd".into(),
            message: e.to_string(),
        })?;
        return read_capped(&mut dec).map_err(|e| ChromeError::Decompress {
            encoding: "zstd".into(),
            message: e.to_string(),
        });
    }
    if enc.contains("deflate") {
        // HTTP "deflate" is technically zlib-wrapped, though some servers emit raw deflate
        if let Ok(v) = read_capped(ZlibDecoder::new(raw)) {
            return Ok(v);
        }
        return read_capped(DeflateDecoder::new(raw)).map_err(|e| ChromeError::Decompress {
            encoding: "deflate".into(),
            message: e.to_string(),
        });
    }

    Ok(raw.to_vec())
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
}
