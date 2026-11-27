use aes::cipher::{BlockModeDecrypt, KeyIvInit, block_padding::Pkcs7};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce, aead::Aead};
use hmac::Hmac;
use pbkdf2::pbkdf2;
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use sha2::{Digest, Sha256};

type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EncryptionScheme {
    Plaintext,
    Empty,
    V10,
    V11,
    V20,
    Dpapi,
    Unknown,
}

impl EncryptionScheme {
    pub fn as_str(&self) -> &'static str {
        match self {
            EncryptionScheme::Plaintext => "plaintext",
            EncryptionScheme::Empty => "empty",
            EncryptionScheme::V10 => "v10",
            EncryptionScheme::V11 => "v11",
            EncryptionScheme::V20 => "v20",
            EncryptionScheme::Dpapi => "dpapi",
            EncryptionScheme::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct CryptoOptions {
    /// Whether best-effort decryption should be attempted (false = strictly metadata-only).
    pub decrypt_enabled: bool,
    /// User-supplied passphrases (used via PBKDF2-HMAC-SHA1 for Linux/macOS v10/v11)
    /// or hex-encoded 16-byte/32-byte raw AES keys.
    pub supplied_keys: Vec<String>,
    /// Allow Chromium's default Linux fallback key ("peanuts") when decrypt_enabled is true.
    pub allow_linux_peanuts: bool,
}

impl CryptoOptions {
    pub fn metadata_only() -> Self {
        Self::default()
    }

    pub fn best_effort() -> Self {
        Self {
            decrypt_enabled: true,
            supplied_keys: Vec::new(),
            allow_linux_peanuts: true,
        }
    }
}

pub fn classify_encrypted_blob(blob: &[u8], plaintext_fallback: &str) -> EncryptionScheme {
    if blob.is_empty() {
        if plaintext_fallback.is_empty() {
            EncryptionScheme::Empty
        } else {
            EncryptionScheme::Plaintext
        }
    } else if blob.starts_with(b"v10") {
        EncryptionScheme::V10
    } else if blob.starts_with(b"v11") {
        EncryptionScheme::V11
    } else if blob.starts_with(b"v20") {
        EncryptionScheme::V20
    } else if blob.len() > 4 && blob[0] == 0x01 && blob[1] == 0x00 && blob[2] == 0x00 && blob[3] == 0x00 {
        EncryptionScheme::Dpapi
    } else {
        EncryptionScheme::Unknown
    }
}

/// Attempts optional best-effort decryption of Chromium `encrypted_value` / `password_value` blobs.
/// Never reads OS keyrings automatically unless user supplies keys or `allow_linux_peanuts` is enabled.
/// Strips Chrome v130+ (DB meta version >= 24) 32-byte SHA-256 host/domain prefix when detected.
pub fn try_decrypt_chrome_blob(
    blob: &[u8],
    plaintext_fallback: &str,
    domain_hint: Option<&str>,
    db_version: Option<i64>,
    opts: &CryptoOptions,
) -> (EncryptionScheme, Option<String>) {
    let scheme = classify_encrypted_blob(blob, plaintext_fallback);
    if !plaintext_fallback.is_empty() && blob.is_empty() {
        return (EncryptionScheme::Plaintext, Some(plaintext_fallback.to_string()));
    }
    if !opts.decrypt_enabled || blob.len() <= 3 {
        return (scheme, None);
    }

    match scheme {
        EncryptionScheme::V10 | EncryptionScheme::V11 => {
            let payload = &blob[3..];
            // 1. Try user-supplied keys (raw 32-byte AES-256-GCM, raw 16-byte AES-128-CBC, or passphrase)
            for key_spec in &opts.supplied_keys {
                if let Some(raw_bytes) = decode_hex_if_exact(key_spec) {
                    if raw_bytes.len() == 32
                        && let Some(pt) = try_aes_256_gcm_chrome(payload, &raw_bytes)
                        && let Some(s) = extract_utf8_plaintext(&pt, domain_hint, db_version)
                    {
                        return (scheme, Some(s));
                    }
                    if raw_bytes.len() == 16
                        && let Some(pt) = try_aes_128_cbc_chrome(payload, &raw_bytes)
                        && let Some(s) = extract_utf8_plaintext(&pt, domain_hint, db_version)
                    {
                        return (scheme, Some(s));
                    }
                }
                // Try passphrase with Linux (1 iter) and macOS (1003 iters) PBKDF2
                for iters in [1u32, 1003u32] {
                    let key = derive_pbkdf2_key(key_spec.as_bytes(), iters);
                    if let Some(pt) = try_aes_128_cbc_chrome(payload, &key)
                        && let Some(s) = extract_utf8_plaintext(&pt, domain_hint, db_version)
                    {
                        return (scheme, Some(s));
                    }
                }
            }
            // 2. Try Linux Chromium default fallback key ("peanuts", 1 iter)
            if opts.allow_linux_peanuts {
                let key = derive_pbkdf2_key(b"peanuts", 1);
                if let Some(pt) = try_aes_128_cbc_chrome(payload, &key)
                    && let Some(s) = extract_utf8_plaintext(&pt, domain_hint, db_version)
                {
                    return (scheme, Some(s));
                }
            }
            (scheme, None)
        }
        EncryptionScheme::V20 => {
            // App-Bound Encryption (Windows Chrome 127+): if user directly supplied a 32-byte AES-256-GCM key
            let payload = &blob[3..];
            for key_spec in &opts.supplied_keys {
                if let Some(raw_bytes) = decode_hex_if_exact(key_spec)
                    && raw_bytes.len() == 32
                    && let Some(pt) = try_aes_256_gcm_chrome(payload, &raw_bytes)
                    && let Some(s) = extract_utf8_plaintext(&pt, domain_hint, db_version)
                {
                    return (scheme, Some(s));
                }
            }
            (scheme, None)
        }
        _ => (scheme, None),
    }
}

fn derive_pbkdf2_key(passphrase: &[u8], iterations: u32) -> [u8; 16] {
    let mut key = [0u8; 16];
    let _ = pbkdf2::<Hmac<Sha1>>(passphrase, b"saltysalt", iterations, &mut key);
    key
}

fn try_aes_128_cbc_chrome(ciphertext: &[u8], key: &[u8]) -> Option<Vec<u8>> {
    if key.len() != 16 || ciphertext.is_empty() || !ciphertext.len().is_multiple_of(16) {
        return None;
    }
    let iv = [0x20u8; 16];
    let mut buf = ciphertext.to_vec();
    let dec = Aes128CbcDec::new_from_slices(key, &iv).ok()?;
    let pt = dec.decrypt_padded::<Pkcs7>(&mut buf).ok()?;
    Some(pt.to_vec())
}

fn try_aes_256_gcm_chrome(payload: &[u8], key: &[u8]) -> Option<Vec<u8>> {
    // Format: 12-byte nonce || ciphertext || 16-byte tag
    if key.len() != 32 || payload.len() < 12 + 16 {
        return None;
    }
    let cipher = Aes256Gcm::new_from_slice(key).ok()?;
    let nonce = Nonce::try_from(&payload[..12]).ok()?;
    cipher.decrypt(&nonce, &payload[12..]).ok()
}

fn extract_utf8_plaintext(pt: &[u8], domain_hint: Option<&str>, db_version: Option<i64>) -> Option<String> {
    // Chrome DB meta.version >= 24 prepends SHA256(host_key) (32 bytes) to cookie values
    let has_v24_hash = db_version.is_some_and(|v| v >= 24) && pt.len() >= 32;
    if has_v24_hash {
        if let Some(domain) = domain_hint {
            let digest = Sha256::digest(domain.as_bytes());
            if pt[..32] == digest[..] {
                return std::str::from_utf8(&pt[32..]).ok().map(|s| s.to_string());
            }
        }
        // Even without exact domain match, if first 32 bytes are non-ASCII/binary and tail is valid UTF-8
        if std::str::from_utf8(pt).is_err()
            && let Ok(tail) = std::str::from_utf8(&pt[32..])
        {
            return Some(tail.to_string());
        }
    }
    if let Ok(s) = std::str::from_utf8(pt)
        && s.chars()
            .all(|c| !c.is_control() || c == '\t' || c == '\n' || c == '\r')
    {
        return Some(s.to_string());
    }
    // Fallback check for 32-byte domain hash when db_version wasn't passed
    if pt.len() > 32
        && let Some(domain) = domain_hint
    {
        let digest = Sha256::digest(domain.as_bytes());
        if pt[..32] == digest[..] {
            return std::str::from_utf8(&pt[32..]).ok().map(|s| s.to_string());
        }
    }
    None
}

fn decode_hex_if_exact(s: &str) -> Option<Vec<u8>> {
    let trimmed = s.trim().strip_prefix("0x").unwrap_or(s.trim());
    if trimmed.len() != 32 && trimmed.len() != 64 {
        return None;
    }
    if !trimmed.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = Vec::with_capacity(trimmed.len() / 2);
    for i in (0..trimmed.len()).step_by(2) {
        let byte = u8::from_str_radix(&trimmed[i..i + 2], 16).ok()?;
        out.push(byte);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes::cipher::{BlockModeEncrypt, block_padding::Pkcs7};

    #[test]
    fn test_linux_peanuts_v10_decrypt_with_v24_domain_hash() {
        type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;
        let key = derive_pbkdf2_key(b"peanuts", 1);
        let iv = [0x20u8; 16];
        let mut plaintext = Sha256::digest(b"127.0.0.1").to_vec();
        plaintext.extend_from_slice(b"abc123");

        let mut buf = vec![0u8; plaintext.len() + 16];
        buf[..plaintext.len()].copy_from_slice(&plaintext);
        let enc = Aes128CbcEnc::new_from_slices(&key, &iv).unwrap();
        let ct = enc.encrypt_padded::<Pkcs7>(&mut buf, plaintext.len()).unwrap();

        let mut blob = b"v10".to_vec();
        blob.extend_from_slice(ct);

        let (scheme, dec) =
            try_decrypt_chrome_blob(&blob, "", Some("127.0.0.1"), Some(24), &CryptoOptions::best_effort());
        assert_eq!(scheme, EncryptionScheme::V10);
        assert_eq!(dec.as_deref(), Some("abc123"));
    }
}
