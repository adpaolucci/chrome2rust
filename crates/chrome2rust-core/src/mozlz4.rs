use crate::error::ChromeError;

/// Mozilla `mozLz40\0` magic header (8 bytes).
pub const MOZLZ4_MAGIC: &[u8; 8] = b"mozLz40\0";

/// Safety cap on decompressed `mozLz40` output size (128 MiB).
pub const MAX_MOZLZ4_BYTES: usize = 128 * 1024 * 1024;

/// Decompresses a Mozilla `mozLz40\0` file (e.g. `sessionstore.jsonlz4`, `recovery.jsonlz4`,
/// `bookmarkbackups/*.jsonlz4`) in pure safe Rust.
pub fn decompress_mozlz4(input: &[u8]) -> Result<Vec<u8>, ChromeError> {
    if input.len() < 12 {
        return Err(ChromeError::InvalidFormat(
            "mozLz40 input shorter than 12-byte header".into(),
        ));
    }
    if &input[0..8] != MOZLZ4_MAGIC {
        return Err(ChromeError::InvalidFormat("missing mozLz40\\0 magic header".into()));
    }
    let expected_len = u32::from_le_bytes([input[8], input[9], input[10], input[11]]) as usize;
    if expected_len > MAX_MOZLZ4_BYTES {
        return Err(ChromeError::Decompress {
            encoding: "mozlz4".into(),
            message: format!("declared uncompressed size {expected_len} exceeds 128 MiB cap"),
        });
    }

    let src = &input[12..];
    if expected_len == 0 && src.is_empty() {
        return Ok(Vec::new());
    }

    let mut out = Vec::with_capacity(expected_len.min(4 * 1024 * 1024));
    let mut pos = 0usize;

    while pos < src.len() {
        let token = src[pos];
        pos += 1;

        let mut lit_len = (token >> 4) as usize;
        if lit_len == 15 {
            loop {
                let extra = *src.get(pos).ok_or_else(|| ChromeError::Decompress {
                    encoding: "mozlz4".into(),
                    message: "truncated literal length extension".into(),
                })?;
                pos += 1;
                lit_len = lit_len
                    .checked_add(extra as usize)
                    .ok_or_else(|| ChromeError::Decompress {
                        encoding: "mozlz4".into(),
                        message: "literal length overflow".into(),
                    })?;
                if lit_len > MAX_MOZLZ4_BYTES {
                    return Err(ChromeError::Decompress {
                        encoding: "mozlz4".into(),
                        message: "literal length exceeds 128 MiB cap".into(),
                    });
                }
                if extra != 255 {
                    break;
                }
            }
        }

        let lit_end = pos.checked_add(lit_len).ok_or_else(|| ChromeError::Decompress {
            encoding: "mozlz4".into(),
            message: "literal offset overflow".into(),
        })?;
        if lit_end > src.len() {
            return Err(ChromeError::Decompress {
                encoding: "mozlz4".into(),
                message: "truncated LZ4 literal block".into(),
            });
        }
        if out.len().saturating_add(lit_len) > MAX_MOZLZ4_BYTES {
            return Err(ChromeError::Decompress {
                encoding: "mozlz4".into(),
                message: "decompressed output exceeds 128 MiB cap".into(),
            });
        }
        out.extend_from_slice(&src[pos..lit_end]);
        pos = lit_end;

        if pos == src.len() {
            break;
        }

        if pos + 2 > src.len() {
            return Err(ChromeError::Decompress {
                encoding: "mozlz4".into(),
                message: "truncated LZ4 match offset".into(),
            });
        }
        let offset = u16::from_le_bytes([src[pos], src[pos + 1]]) as usize;
        pos += 2;
        if offset == 0 || offset > out.len() {
            return Err(ChromeError::Decompress {
                encoding: "mozlz4".into(),
                message: format!("invalid LZ4 match offset {offset} at output len {}", out.len()),
            });
        }

        let mut match_len = ((token & 0x0f) as usize) + 4;
        if (token & 0x0f) == 15 {
            loop {
                let extra = *src.get(pos).ok_or_else(|| ChromeError::Decompress {
                    encoding: "mozlz4".into(),
                    message: "truncated match length extension".into(),
                })?;
                pos += 1;
                match_len = match_len
                    .checked_add(extra as usize)
                    .ok_or_else(|| ChromeError::Decompress {
                        encoding: "mozlz4".into(),
                        message: "match length overflow".into(),
                    })?;
                if out.len().saturating_add(match_len) > MAX_MOZLZ4_BYTES {
                    return Err(ChromeError::Decompress {
                        encoding: "mozlz4".into(),
                        message: "match expansion exceeds 128 MiB cap".into(),
                    });
                }
                if extra != 255 {
                    break;
                }
            }
        }

        if out.len().saturating_add(match_len) > MAX_MOZLZ4_BYTES {
            return Err(ChromeError::Decompress {
                encoding: "mozlz4".into(),
                message: "decompressed output exceeds 128 MiB cap".into(),
            });
        }

        // Byte-by-byte copy handles overlapping RLE matches (offset < match_len) identically to LZ4 spec.
        for _ in 0..match_len {
            let b = out[out.len() - offset];
            out.push(b);
        }
    }

    if out.len() != expected_len {
        return Err(ChromeError::Decompress {
            encoding: "mozlz4".into(),
            message: format!("decompressed size {} does not match header {}", out.len(), expected_len),
        });
    }

    Ok(out)
}

/// Encodes `input` into a valid `mozLz40\0` stream (pure safe Rust, primarily for tests and fixtures).
pub fn compress_mozlz4_literals(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(12 + input.len() + 16);
    out.extend_from_slice(MOZLZ4_MAGIC);
    out.extend_from_slice(&(input.len() as u32).to_le_bytes());

    if !input.is_empty() {
        let len = input.len();
        let top = len.min(15) as u8;
        out.push(top << 4);
        if len >= 15 {
            let mut rem = len - 15;
            while rem >= 255 {
                out.push(255);
                rem -= 255;
            }
            out.push(rem as u8);
        }
        out.extend_from_slice(input);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mozlz4_roundtrip_literals_and_extended_length() {
        let small = br#"{"windows":[{"tabs":[{"entries":[{"url":"https://mozilla.org"}]}]}]}"#;
        let compressed = compress_mozlz4_literals(small);
        assert_eq!(decompress_mozlz4(&compressed).unwrap(), small);

        // Extended literal length (> 15 + 255)
        let big = vec![b'x'; 400];
        let compressed_big = compress_mozlz4_literals(&big);
        assert_eq!(decompress_mozlz4(&compressed_big).unwrap(), big);

        // Empty payload
        let empty = compress_mozlz4_literals(b"");
        assert_eq!(decompress_mozlz4(&empty).unwrap(), b"");
    }

    #[test]
    fn test_mozlz4_overlapping_rle_match() {
        // Construct LZ4 stream: literal "AB" (len 2), match offset 2, match_len 8 -> "ABABABABAB" (10 bytes)
        let mut raw = Vec::new();
        raw.extend_from_slice(MOZLZ4_MAGIC);
        raw.extend_from_slice(&10u32.to_le_bytes());
        // token: lit=2, match_len_nib = 8 - 4 = 4 -> 0x24
        raw.push(0x24);
        raw.extend_from_slice(b"AB");
        raw.extend_from_slice(&2u16.to_le_bytes());
        assert_eq!(decompress_mozlz4(&raw).unwrap(), b"ABABABABAB");
    }

    #[test]
    fn test_mozlz4_rejects_corrupt_or_oversized() {
        assert!(decompress_mozlz4(b"notmozlz4").is_err());
        let mut bad_size = Vec::from(*MOZLZ4_MAGIC);
        bad_size.extend_from_slice(&(200u32 * 1024 * 1024).to_le_bytes());
        assert!(decompress_mozlz4(&bad_size).is_err());

        // Bad offset = 0
        let mut bad_off = Vec::from(*MOZLZ4_MAGIC);
        bad_off.extend_from_slice(&5u32.to_le_bytes());
        bad_off.push(0x10);
        bad_off.push(b'a');
        bad_off.extend_from_slice(&0u16.to_le_bytes());
        assert!(decompress_mozlz4(&bad_off).is_err());
    }
}
