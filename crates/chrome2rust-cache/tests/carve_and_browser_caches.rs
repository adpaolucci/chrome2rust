use chrome2rust_cache::carve_images::carve_images;
use chrome2rust_cache::carve_video::carve_video;
use crc32fast::Hasher;
use sha2::{Digest, Sha256};
use std::path::Path;
use tempfile::TempDir;

fn write_simple_entry_with_headers(path: &Path, key: &str, headers_nul: &str, payload: &[u8]) {
    let key_b = key.as_bytes();
    let hdr_b = headers_nul.as_bytes();
    let ip_b = b"203.0.113.10";

    let h_al = hdr_b.len().div_ceil(4) * 4;
    let ip_al = ip_b.len().div_ceil(4) * 4;
    let plen = 4 + 8 + 8 + 4 + h_al + 4 + ip_al + 4;
    let mut s0 = Vec::new();
    s0.extend_from_slice(&(plen as u32).to_le_bytes());
    s0.extend_from_slice(&3u32.to_le_bytes());
    s0.extend_from_slice(&13_439_176_738_739_516i64.to_le_bytes());
    s0.extend_from_slice(&13_439_176_738_800_000i64.to_le_bytes());
    s0.extend_from_slice(&(hdr_b.len() as u32).to_le_bytes());
    s0.extend_from_slice(hdr_b);
    s0.resize(s0.len() + (h_al - hdr_b.len()), 0);
    s0.extend_from_slice(&(ip_b.len() as u32).to_le_bytes());
    s0.extend_from_slice(ip_b);
    s0.resize(s0.len() + (ip_al - ip_b.len()), 0);
    s0.extend_from_slice(&443u32.to_le_bytes());

    let mut h1 = Hasher::new();
    h1.update(payload);
    let crc1 = h1.finalize();

    let mut h0 = Hasher::new();
    h0.update(&s0);
    let crc0 = h0.finalize();

    let mut out = Vec::new();
    out.extend_from_slice(&0xfcfb6d1ba7725c30u64.to_le_bytes());
    out.extend_from_slice(&5u32.to_le_bytes());
    out.extend_from_slice(&(key_b.len() as u32).to_le_bytes());
    out.extend_from_slice(&0u64.to_le_bytes());
    out.extend_from_slice(key_b);
    out.extend_from_slice(payload);
    out.extend_from_slice(&0xf4fa6f45970d41d8u64.to_le_bytes());
    out.extend_from_slice(&1u32.to_le_bytes());
    out.extend_from_slice(&crc1.to_le_bytes());
    out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&s0);
    out.extend_from_slice(&Sha256::digest(key_b));
    out.extend_from_slice(&0xf4fa6f45970d41d8u64.to_le_bytes());
    out.extend_from_slice(&3u32.to_le_bytes());
    out.extend_from_slice(&crc0.to_le_bytes());
    out.extend_from_slice(&(s0.len() as u32).to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    std::fs::write(path, out).unwrap();
}

fn push_u16_be(buf: &mut Vec<u8>, v: u16) {
    buf.extend_from_slice(&v.to_be_bytes());
}

fn push_u32_be(buf: &mut Vec<u8>, v: u32) {
    buf.extend_from_slice(&v.to_be_bytes());
}

fn build_be_exif() -> Vec<u8> {
    let mut tiff = Vec::from(*b"MM");
    push_u16_be(&mut tiff, 0x002A);
    push_u32_be(&mut tiff, 8);
    let make = b"Canon\0";
    let model = b"EOS R5\0";
    let dto = b"2026:11:15 10:20:30\0";

    push_u16_be(&mut tiff, 4);
    for (tag, ty, cnt, val) in [
        (0x010Fu16, 2u16, make.len() as u32, 134u32),
        (0x0110, 2, model.len() as u32, 140),
        (0x8769, 4, 1, 62),
        (0x8825, 4, 1, 80),
    ] {
        push_u16_be(&mut tiff, tag);
        push_u16_be(&mut tiff, ty);
        push_u32_be(&mut tiff, cnt);
        push_u32_be(&mut tiff, val);
    }
    push_u32_be(&mut tiff, 0);

    // ExifIFD at 62
    push_u16_be(&mut tiff, 1);
    push_u16_be(&mut tiff, 0x9003);
    push_u16_be(&mut tiff, 2);
    push_u32_be(&mut tiff, dto.len() as u32);
    push_u32_be(&mut tiff, 147);
    push_u32_be(&mut tiff, 0);

    // GPS IFD at 80
    push_u16_be(&mut tiff, 4);
    push_u16_be(&mut tiff, 0x0001);
    push_u16_be(&mut tiff, 2);
    push_u32_be(&mut tiff, 2);
    tiff.extend_from_slice(b"N\0\0\0");
    push_u16_be(&mut tiff, 0x0002);
    push_u16_be(&mut tiff, 5);
    push_u32_be(&mut tiff, 3);
    push_u32_be(&mut tiff, 167);
    push_u16_be(&mut tiff, 0x0003);
    push_u16_be(&mut tiff, 2);
    push_u32_be(&mut tiff, 2);
    tiff.extend_from_slice(b"W\0\0\0");
    push_u16_be(&mut tiff, 0x0004);
    push_u16_be(&mut tiff, 5);
    push_u32_be(&mut tiff, 3);
    push_u32_be(&mut tiff, 191);
    push_u32_be(&mut tiff, 0);

    tiff.extend_from_slice(make);
    tiff.extend_from_slice(model);
    tiff.extend_from_slice(dto);
    for (n, d) in [(43u32, 1u32), (39, 1), (1152, 100), (79, 1), (22, 1), (5952, 100)] {
        push_u32_be(&mut tiff, n);
        push_u32_be(&mut tiff, d);
    }
    tiff
}

#[test]
fn test_carve_images_and_reject_masqueraded_pe() {
    let dir = TempDir::new().unwrap();
    let cache_dir = dir.path().join("Cache").join("Cache_Data");
    std::fs::create_dir_all(&cache_dir).unwrap();
    let extract_dir = dir.path().join("carved_images");

    // 1. JPEG with BE EXIF + GPS
    let tiff = build_be_exif();
    let mut jpeg = vec![0xFF, 0xD8, 0xFF, 0xE1];
    jpeg.extend_from_slice(&((2 + 6 + tiff.len()) as u16).to_be_bytes());
    jpeg.extend_from_slice(b"Exif\0\0");
    jpeg.extend_from_slice(&tiff);
    jpeg.extend_from_slice(&[0xFF, 0xC0, 0x00, 0x0B, 0x08]);
    jpeg.extend_from_slice(&480u16.to_be_bytes());
    jpeg.extend_from_slice(&640u16.to_be_bytes());
    jpeg.extend_from_slice(&[0x01, 0x01, 0x11, 0x00, 0xFF, 0xD9]);
    write_simple_entry_with_headers(
        &cache_dir.join("0000000000000001_0"),
        "https://photos.example.test/photo.jpg",
        "HTTP/1.1 200 OK\0Content-Type: image/jpeg\0\0",
        &jpeg,
    );

    // 2. AVIF with ftyp + meta + iprp + ipco + ispe (1280x720)
    let mut ispe = Vec::new();
    ispe.extend_from_slice(&20u32.to_be_bytes());
    ispe.extend_from_slice(b"ispe");
    ispe.extend_from_slice(&0u32.to_be_bytes());
    ispe.extend_from_slice(&1280u32.to_be_bytes());
    ispe.extend_from_slice(&720u32.to_be_bytes());
    let mut ipco = Vec::new();
    ipco.extend_from_slice(&((8 + ispe.len()) as u32).to_be_bytes());
    ipco.extend_from_slice(b"ipco");
    ipco.extend_from_slice(&ispe);
    let mut iprp = Vec::new();
    iprp.extend_from_slice(&((8 + ipco.len()) as u32).to_be_bytes());
    iprp.extend_from_slice(b"iprp");
    iprp.extend_from_slice(&ipco);
    let mut meta = Vec::new();
    meta.extend_from_slice(&((12 + iprp.len()) as u32).to_be_bytes());
    meta.extend_from_slice(b"meta");
    meta.extend_from_slice(&0u32.to_be_bytes());
    meta.extend_from_slice(&iprp);
    let mut avif = Vec::new();
    avif.extend_from_slice(&16u32.to_be_bytes());
    avif.extend_from_slice(b"ftypavif");
    avif.extend_from_slice(&[0; 4]);
    avif.extend_from_slice(&meta);
    write_simple_entry_with_headers(
        &cache_dir.join("0000000000000002_0"),
        "https://photos.example.test/hero.avif",
        "HTTP/1.1 200 OK\0Content-Type: image/avif\0\0",
        &avif,
    );

    // 3. Masqueraded PE executable under Content-Type: image/png (MUST BE REJECTED)
    let mut pe = vec![0u8; 128];
    pe[0..2].copy_from_slice(b"MZ");
    pe[0x3c..0x40].copy_from_slice(&64u32.to_le_bytes());
    pe[64..68].copy_from_slice(b"PE\0\0");
    write_simple_entry_with_headers(
        &cache_dir.join("0000000000000003_0"),
        "https://evil.example.test/avatar.png",
        "HTTP/1.1 200 OK\0Content-Type: image/png\0\0",
        &pe,
    );

    // 4. Arbitrary non-image binary payload labeled Content-Type: image/png (MUST BE REJECTED)
    let non_image = vec![0x80u8; 128];
    write_simple_entry_with_headers(
        &cache_dir.join("0000000000000004_0"),
        "https://evil.test/shellcode.png",
        "HTTP/1.1 200 OK\0Content-Type: image/png\0\0",
        &non_image,
    );

    // 5. Two valid PNGs with identical basename `logo.png` (MUST NOT overwrite each other)
    let png_a = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x10\x00\x00\x00\x10\x08\x06\x00\x00\x00AAAA";
    let png_b = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x20\x00\x00\x00\x20\x08\x06\x00\x00\x00BBBB";
    write_simple_entry_with_headers(
        &cache_dir.join("0000000000000005_0"),
        "https://site-a.example.test/assets/logo.png",
        "HTTP/1.1 200 OK\0Content-Type: image/png\0\0",
        png_a,
    );
    write_simple_entry_with_headers(
        &cache_dir.join("0000000000000006_0"),
        "https://site-b.example.test/assets/logo.png",
        "HTTP/1.1 200 OK\0Content-Type: image/png\0\0",
        png_b,
    );

    let (records, _) = carve_images(&[cache_dir], Some(&extract_dir), None);
    assert_eq!(records.len(), 4);
    assert!(!records.iter().any(|r| r.url.contains("avatar.png")));
    assert!(!records.iter().any(|r| r.url.contains("shellcode.png")));

    let logo_recs: Vec<_> = records.iter().filter(|r| r.url.ends_with("/logo.png")).collect();
    assert_eq!(logo_recs.len(), 2);
    assert_ne!(logo_recs[0].extracted_path, logo_recs[1].extracted_path);
    assert!(Path::new(logo_recs[0].extracted_path.as_deref().unwrap()).is_file());
    assert!(Path::new(logo_recs[1].extracted_path.as_deref().unwrap()).is_file());

    let jpg = records.iter().find(|r| r.url.ends_with("photo.jpg")).unwrap();
    assert_eq!((jpg.width, jpg.height), (Some(640), Some(480)));
    assert_eq!(jpg.make.as_deref(), Some("Canon"));
    assert_eq!(jpg.model.as_deref(), Some("EOS R5"));
    assert_eq!(jpg.date_time_original.as_deref(), Some("2026:11:15 10:20:30"));
    assert!((jpg.gps_lat.unwrap() - 43.6532).abs() < 0.001);
    assert!((jpg.gps_lon.unwrap() - (-79.3832)).abs() < 0.001);
    assert!(Path::new(jpg.extracted_path.as_deref().unwrap()).is_file());

    let avif_rec = records.iter().find(|r| r.url.ends_with("hero.avif")).unwrap();
    assert_eq!((avif_rec.width, avif_rec.height), (Some(1280), Some(720)));
}

#[test]
fn test_carve_video_hls_dash_and_http_206_reassembly() {
    let dir = TempDir::new().unwrap();
    let cache_dir = dir.path().join("Cache").join("Cache_Data");
    std::fs::create_dir_all(&cache_dir).unwrap();
    let extract_dir = dir.path().join("carved_video");

    // 1. HLS manifest + init.mp4 + 2 m4s segments
    let m3u8 = b"#EXTM3U\n#EXT-X-MAP:URI=\"init.mp4\"\n#EXTINF:4.0,\nseg1.m4s\n#EXTINF:4.0,\nseg2.m4s\n";
    let init_bytes = b"\x00\x00\x00\x10ftypisom\x00\x00\x00\x00";
    let seg1 = b"\x00\x00\x00\x10moofSEG1DATA";
    let seg2 = b"\x00\x00\x00\x10moofSEG2DATA";
    write_simple_entry_with_headers(
        &cache_dir.join("1000000000000001_0"),
        "https://cdn.video.test/hls/master.m3u8",
        "HTTP/1.1 200 OK\0Content-Type: application/vnd.apple.mpegurl\0\0",
        m3u8,
    );
    write_simple_entry_with_headers(
        &cache_dir.join("1000000000000002_0"),
        "https://cdn.video.test/hls/init.mp4",
        "HTTP/1.1 200 OK\0Content-Type: video/mp4\0\0",
        init_bytes,
    );
    write_simple_entry_with_headers(
        &cache_dir.join("1000000000000003_0"),
        "https://cdn.video.test/hls/seg1.m4s",
        "HTTP/1.1 200 OK\0Content-Type: video/iso.segment\0\0",
        seg1,
    );
    write_simple_entry_with_headers(
        &cache_dir.join("1000000000000004_0"),
        "https://cdn.video.test/hls/seg2.m4s",
        "HTTP/1.1 200 OK\0Content-Type: video/iso.segment\0\0",
        seg2,
    );

    // 2. HTTP 206 Partial Content chunks for a standalone MP4
    let mut full_mp4 = Vec::from(*b"\x00\x00\x00\x10ftypmp42\x00\x00\x00\x00");
    full_mp4.extend_from_slice(b"\x00\x00\x00\x10mdat01234567");
    let split = full_mp4.len() / 2;
    write_simple_entry_with_headers(
        &cache_dir.join("2000000000000001_0"),
        "https://media.video.test/clip.mp4?t=1",
        &format!(
            "HTTP/1.1 206 Partial Content\0Content-Type: video/mp4\0Content-Range: bytes 0-{}/{}\0\0",
            split - 1,
            full_mp4.len()
        ),
        &full_mp4[..split],
    );
    write_simple_entry_with_headers(
        &cache_dir.join("2000000000000002_0"),
        "https://media.video.test/clip.mp4?t=2",
        &format!(
            "HTTP/1.1 206 Partial Content\0Content-Type: video/mp4\0Content-Range: bytes {}-{}/{}\0\0",
            split,
            full_mp4.len() - 1,
            full_mp4.len()
        ),
        &full_mp4[split..],
    );

    let (records, _) = carve_video(&[cache_dir], Some(&extract_dir));
    let hls = records
        .iter()
        .find(|r| r.container_format == "HLS-Reassembled")
        .expect("HLS-Reassembled record");
    assert!(hls.reassembled);
    assert_eq!(hls.segment_count, 3);
    assert_eq!(hls.file_size, (init_bytes.len() + seg1.len() + seg2.len()) as u64);
    assert!((hls.duration_secs.unwrap() - 8.0).abs() < 0.001);

    let range_mp4 = records
        .iter()
        .find(|r| r.container_format.contains("RangeReassembled"))
        .expect("HTTP 206 reassembled MP4");
    assert!(range_mp4.reassembled);
    assert_eq!(range_mp4.segment_count, 2);
    assert_eq!(range_mp4.file_size, full_mp4.len() as u64);
    let extracted_bytes = std::fs::read(range_mp4.extracted_path.as_deref().unwrap()).unwrap();
    assert_eq!(extracted_bytes, full_mp4);
}

#[test]
fn test_carve_video_orphan_timestamp_prefix_segments_and_init_reassembly() {
    let dir = TempDir::new().unwrap();
    let cache_dir = dir.path().join("Cache").join("Cache_Data");
    std::fs::create_dir_all(&cache_dir).unwrap();
    let extract_dir = dir.path().join("carved_orphan");

    // Init segment (ftyp + moov, no moof/mdat)
    let mut init_mp4 = Vec::new();
    init_mp4.extend_from_slice(&16u32.to_be_bytes());
    init_mp4.extend_from_slice(b"ftypisom");
    init_mp4.extend_from_slice(&[0; 4]);
    init_mp4.extend_from_slice(&8u32.to_be_bytes());
    init_mp4.extend_from_slice(b"moov");

    let seg1 = b"\x00\x00\x00\x10moofORPHAN1";
    let seg2 = b"\x00\x00\x00\x10moofORPHAN2";

    write_simple_entry_with_headers(
        &cache_dir.join("3000000000000001_0"),
        "https://orph2.test/v/init.mp4",
        "HTTP/1.1 200 OK\0Content-Type: video/mp4\0\0",
        &init_mp4,
    );
    write_simple_entry_with_headers(
        &cache_dir.join("3000000000000002_0"),
        "https://orph2.test/v/17947008001234567890_1.m4s",
        "HTTP/1.1 200 OK\0Content-Type: video/iso.segment\0\0",
        seg1,
    );
    write_simple_entry_with_headers(
        &cache_dir.join("3000000000000003_0"),
        "https://orph2.test/v/17947008001234567890_2.m4s",
        "HTTP/1.1 200 OK\0Content-Type: video/iso.segment\0\0",
        seg2,
    );

    let (records, _) = carve_video(&[cache_dir], Some(&extract_dir));
    assert_eq!(records.len(), 1, "expected 1 reassembled video, got: {records:?}");
    let rec = &records[0];
    assert!(rec.reassembled);
    assert_eq!(rec.container_format, "Segment-Reassembled");
    assert_eq!(rec.segment_count, 3);
    assert_eq!(rec.file_size, (init_mp4.len() + seg1.len() + seg2.len()) as u64);
    let out_bytes = std::fs::read(rec.extracted_path.as_deref().unwrap()).unwrap();
    let mut expected = Vec::new();
    expected.extend_from_slice(&init_mp4);
    expected.extend_from_slice(seg1);
    expected.extend_from_slice(seg2);
    assert_eq!(out_bytes, expected);
}
