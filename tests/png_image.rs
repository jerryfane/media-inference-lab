use std::fs;
use std::io::{self, Write};

use flate2::Compression;
use flate2::write::ZlibEncoder;
use media_inference_lab::png_image::{MAX_ENCODED_BYTES, SampleColor, decode, write_sheet};
use sha2::{Digest, Sha256};
use tempfile::tempdir;

const SIGNATURE: &[u8] = b"\x89PNG\r\n\x1a\n";

fn chunk(kind: &[u8; 4], data: &[u8]) -> Vec<u8> {
    let mut result = Vec::new();
    result.extend_from_slice(&(data.len() as u32).to_be_bytes());
    result.extend_from_slice(kind);
    result.extend_from_slice(data);
    let mut crc = !0u32;
    for byte in kind.iter().chain(data) {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0xedb8_8320 & 0u32.wrapping_sub(crc & 1));
        }
    }
    result.extend_from_slice(&(!crc).to_be_bytes());
    result
}

fn header(width: u32, height: u32, depth: u8, color: u8, interlaced: bool) -> Vec<u8> {
    let mut data = Vec::new();
    data.extend_from_slice(&width.to_be_bytes());
    data.extend_from_slice(&height.to_be_bytes());
    data.extend_from_slice(&[depth, color, 0, 0, u8::from(interlaced)]);
    chunk(b"IHDR", &data)
}

fn zlib(raw: &[u8]) -> Vec<u8> {
    let mut writer = ZlibEncoder::new(Vec::new(), Compression::fast());
    writer.write_all(raw).unwrap();
    writer.finish().unwrap()
}

fn from_compressed(width: u32, height: u32, depth: u8, color: u8, data: &[u8]) -> Vec<u8> {
    let mut result = SIGNATURE.to_vec();
    result.extend(header(width, height, depth, color, false));
    result.extend(chunk(b"IDAT", data));
    result.extend(chunk(b"IEND", &[]));
    result
}

fn image(width: u32, height: u32, depth: u8, color: u8, samples: &[u8]) -> Vec<u8> {
    let channels = match color {
        0 => 1,
        2 => 3,
        4 => 2,
        6 => 4,
        _ => panic!("test color"),
    };
    let row_size = width as usize * channels * usize::from(depth / 8);
    let mut raw = Vec::new();
    for row in samples.chunks_exact(row_size) {
        raw.push(0);
        raw.extend_from_slice(row);
    }
    from_compressed(width, height, depth, color, &zlib(&raw))
}

fn rejected(bytes: &[u8]) {
    let directory = tempdir().unwrap();
    let path = directory.path().join("malformed.png");
    fs::write(&path, bytes).unwrap();
    assert!(decode(&path).is_err(), "accepted malformed/unsupported PNG");
}

#[test]
fn preserves_each_supported_channel_layout_and_16bit_endianness() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("samples.png");
    for (code, color) in [
        (0, SampleColor::Gray),
        (2, SampleColor::Rgb),
        (4, SampleColor::GrayAlpha),
        (6, SampleColor::Rgba),
    ] {
        for depth in [8, 16] {
            let samples: Vec<u8> = (0..4 * color.channels() * usize::from(depth / 8))
                .map(|index| ((index * 137 + 1) % 256) as u8)
                .collect();
            let bytes = image(2, 2, depth, code, &samples);
            fs::write(&path, &bytes).unwrap();
            let decoded = decode(&path).unwrap();
            assert_eq!(decoded.samples(), samples);
            assert_eq!(decoded.encoded(), bytes);
            assert_eq!(decoded.identity().color, color);
            assert_eq!(decoded.identity().bit_depth, depth);
            assert_eq!(
                (decoded.identity().width, decoded.identity().height),
                (2, 2)
            );
            assert_eq!(decoded.identity().source_path, path);
            assert_eq!(decoded.identity().bytes, bytes.len() as u64);
            assert_eq!(
                decoded.identity().sha256,
                format!("{:x}", Sha256::digest(&bytes))
            );
            assert_eq!(
                decoded.identity().decoded_sha256,
                format!("{:x}", Sha256::digest(&samples))
            );
        }
    }
}

#[test]
fn adam7_is_deinterlaced_without_sample_changes() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("adam7.png");
    let (width, height) = (9u32, 7u32);
    let samples: Vec<u8> = (0..width * height)
        .flat_map(|value| ((value * 257 + 1) as u16).to_be_bytes())
        .collect();
    let mut filtered = Vec::new();
    for (x, y, dx, dy) in [
        (0, 0, 8, 8),
        (4, 0, 8, 8),
        (0, 4, 4, 8),
        (2, 0, 4, 4),
        (0, 2, 2, 4),
        (1, 0, 2, 2),
        (0, 1, 1, 2),
    ] {
        for row in (y..height).step_by(dy) {
            filtered.push(0);
            for column in (x..width).step_by(dx) {
                let offset = (row * width + column) as usize * 2;
                filtered.extend_from_slice(&samples[offset..offset + 2]);
            }
        }
    }
    let mut bytes = SIGNATURE.to_vec();
    bytes.extend(header(width, height, 16, 0, true));
    bytes.extend(chunk(b"IDAT", &zlib(&filtered)));
    bytes.extend(chunk(b"IEND", &[]));
    fs::write(&path, bytes).unwrap();
    assert_eq!(decode(&path).unwrap().samples(), samples);
}

#[test]
fn rejects_all_truncations_crc_failures_and_data_after_iend() {
    let bytes = image(2, 1, 8, 0, &[42, 17]);
    for end in 0..bytes.len() {
        rejected(&bytes[..end]);
    }
    for offset in [29, bytes.len() - 13, bytes.len() - 1] {
        let mut corrupt = bytes.clone();
        corrupt[offset] ^= 1;
        rejected(&corrupt);
    }
    let mut trailing = bytes.clone();
    trailing.extend_from_slice(b"garbage");
    rejected(&trailing);
    let mut duplicate_iend = bytes;
    duplicate_iend.extend(chunk(b"IEND", &[]));
    rejected(&duplicate_iend);
}

#[test]
fn rejects_bad_crc_even_for_ignored_ancillary_chunks() {
    for kind in [b"tEXt", b"zTXt", b"iTXt", b"iCCP", b"vpAg"] {
        let mut bytes = image(1, 1, 8, 0, &[42]);
        let mut extra = chunk(kind, b"ignored ancillary payload");
        *extra.last_mut().unwrap() ^= 1;
        bytes.splice(33..33, extra);
        rejected(&bytes);
    }
}

#[test]
fn rejects_malformed_recognized_metadata_instead_of_silently_discarding_it() {
    for extra in [
        chunk(b"gAMA", &[0]),
        chunk(b"pHYs", &[0; 8]),
        chunk(b"tRNS", &[0]),
        chunk(b"sRGB", &[4]),
    ] {
        let mut bytes = image(1, 1, 8, 0, &[42]);
        bytes.splice(33..33, extra);
        rejected(&bytes);
    }
}

#[test]
fn review_trns_rejects_wrong_lengths_and_alpha_color_types() {
    for depth in [8, 16] {
        for (code, channels, valid_length) in [(0, 1, 2), (2, 3, 6), (4, 2, 0), (6, 4, 0)] {
            let samples = vec![42; channels * usize::from(depth / 8)];
            for length in 0..=8 {
                if valid_length != 0 && length == valid_length {
                    continue;
                }
                let mut bytes = image(1, 1, depth, code, &samples);
                let mut transparency = vec![0; length];
                if length >= 2 {
                    transparency[1] = 42;
                }
                bytes.splice(33..33, chunk(b"tRNS", &transparency));
                rejected(&bytes);
            }
        }
    }
}

#[test]
fn review_trns_rejects_duplicate_and_misordered_transparency() {
    for (code, samples, transparency) in [
        (0, vec![42], vec![0, 42]),
        (2, vec![42, 43, 44], vec![0, 42, 0, 43, 0, 44]),
    ] {
        let mut late = image(1, 1, 8, code, &samples);
        let end = late.len() - 12;
        late.splice(end..end, chunk(b"tRNS", &transparency));
        rejected(&late);

        let mut duplicate = image(1, 1, 8, code, &samples);
        duplicate.splice(33..33, chunk(b"tRNS", &transparency));
        duplicate.splice(33..33, chunk(b"tRNS", &transparency));
        rejected(&duplicate);
    }
    let mut reversed_palette = image(1, 1, 8, 2, &[42, 43, 44]);
    reversed_palette.splice(33..33, chunk(b"PLTE", &[42, 43, 44]));
    reversed_palette.splice(33..33, chunk(b"tRNS", &[0, 42, 0, 43, 0, 44]));
    rejected(&reversed_palette);
}

#[test]
fn review_trns_preserves_valid_metadata_and_raw_samples_without_expansion() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("transparent.png");
    let sheet_path = directory.path().join("sheet.png");
    for depth in [8, 16] {
        for (code, color) in [(0, SampleColor::Gray), (2, SampleColor::Rgb)] {
            for palette in [false, true] {
                if palette && code == 0 {
                    continue;
                }
                let samples = if depth == 8 {
                    vec![42; color.channels()]
                } else {
                    [0x12, 0x34].repeat(color.channels())
                };
                let transparency = if depth == 8 {
                    [0, 42].repeat(color.channels())
                } else {
                    samples.clone()
                };
                let mut bytes = image(1, 1, depth, code, &samples);
                bytes.splice(33..33, chunk(b"tRNS", &transparency));
                if palette {
                    bytes.splice(33..33, chunk(b"PLTE", &[42, 42, 42]));
                }
                fs::write(&path, &bytes).unwrap();
                let decoded = decode(&path).unwrap();
                assert_eq!(decoded.encoded(), bytes);
                assert_eq!(
                    decoded.identity().sha256,
                    format!("{:x}", Sha256::digest(&bytes))
                );
                assert_eq!(decoded.samples(), samples);
                assert_eq!(decoded.identity().color, color);
                assert_eq!(decoded.identity().bit_depth, depth);
                let mut sheet = Vec::new();
                write_sheet(&decoded, &decoded, &mut sheet).unwrap();
                fs::write(&sheet_path, &sheet).unwrap();
                let sheet = decode(&sheet_path).unwrap();
                assert_eq!(sheet.samples(), samples.repeat(2));
                assert_eq!(sheet.identity().color, color);
                assert_eq!(sheet.identity().bit_depth, depth);
            }
        }
    }
}

#[test]
fn rejects_early_late_and_malformed_animation_chunks() {
    for kind in [b"acTL", b"fcTL", b"fdAT"] {
        for late in [false, true] {
            for data in [&[][..], &[0u8; 26][..]] {
                let mut bytes = image(1, 1, 8, 0, &[42]);
                let position = if late { bytes.len() - 12 } else { 33 };
                bytes.splice(position..position, chunk(kind, data));
                rejected(&bytes);
            }
        }
    }
}

#[test]
fn rejects_unsupported_layouts_dimensions_and_chunk_structure() {
    for (width, height, depth, color) in [
        (0, 1, 8, 0),
        (1, 0, 8, 0),
        (16385, 1, 8, 0),
        (1, 16385, 8, 0),
        (4096, 4097, 16, 6),
        (1, 1, 1, 0),
        (1, 1, 2, 0),
        (1, 1, 4, 0),
        (1, 1, 8, 3),
        (1, 1, 8, 1),
    ] {
        rejected(&from_compressed(
            width,
            height,
            depth,
            color,
            &zlib(&[0, 42]),
        ));
    }
    for extra in [
        chunk(b"ABCD", &[]),
        chunk(b"abcd", &[]),
        header(1, 1, 8, 0, false),
        chunk(b"PLTE", &[0, 0, 0]),
    ] {
        let mut bytes = image(1, 1, 8, 0, &[42]);
        bytes.splice(33..33, extra);
        rejected(&bytes);
    }
    let compressed = zlib(&[0, 42]);
    let mut bytes = SIGNATURE.to_vec();
    bytes.extend(header(1, 1, 8, 0, false));
    bytes.extend(chunk(b"IDAT", &compressed[..2]));
    bytes.extend(chunk(b"tEXt", b"key\0value"));
    bytes.extend(chunk(b"IDAT", &compressed[2..]));
    bytes.extend(chunk(b"IEND", &[]));
    rejected(&bytes);
}

#[test]
fn validates_complete_zlib_stream_and_exact_filtered_raster_size() {
    let compressed = zlib(&[0, 42]);
    // A raster-only decoder can produce the pixel before it sees the checksum.
    for removed in 1..=4 {
        rejected(&from_compressed(
            1,
            1,
            8,
            0,
            &compressed[..compressed.len() - removed],
        ));
    }
    let mut corrupt_checksum = compressed.clone();
    *corrupt_checksum.last_mut().unwrap() ^= 1;
    rejected(&from_compressed(1, 1, 8, 0, &corrupt_checksum));
    let mut trailing = compressed.clone();
    trailing.extend_from_slice(b"extra compressed bytes");
    rejected(&from_compressed(1, 1, 8, 0, &trailing));
    trailing = compressed.clone();
    trailing.extend_from_slice(&compressed);
    rejected(&from_compressed(1, 1, 8, 0, &trailing));
    for raw in [&[0][..], &[0, 42, 0][..], &[5, 42][..]] {
        rejected(&from_compressed(1, 1, 8, 0, &zlib(raw)));
    }
}

#[test]
fn accepts_consecutive_tiny_idat_chunks_and_maximum_axis() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("split.png");
    let mut bytes = SIGNATURE.to_vec();
    bytes.extend(header(1, 1, 8, 0, false));
    for byte in zlib(&[0, 42]) {
        bytes.extend(chunk(b"IDAT", &[byte]));
        bytes.extend(chunk(b"IDAT", &[]));
    }
    bytes.extend(chunk(b"IEND", &[]));
    fs::write(&path, bytes).unwrap();
    assert_eq!(decode(&path).unwrap().samples(), [42]);
    let samples = vec![31; 16384];
    fs::write(&path, image(16384, 1, 8, 0, &samples)).unwrap();
    assert_eq!(decode(&path).unwrap().samples(), samples);
}

#[test]
fn refuses_nonregular_symlink_and_oversized_files() {
    let directory = tempdir().unwrap();
    assert!(decode(directory.path()).is_err());
    let path = directory.path().join("large.png");
    fs::File::create(&path)
        .unwrap()
        .set_len(MAX_ENCODED_BYTES + 1)
        .unwrap();
    assert!(decode(&path).is_err());
    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;
        let source = directory.path().join("source.png");
        fs::write(&source, image(1, 1, 8, 0, &[42])).unwrap();
        let link = directory.path().join("link.png");
        symlink(source, &link).unwrap();
        assert!(decode(&link).is_err());
        let fifo = directory.path().join("fifo");
        let name = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
        assert!(decode(&fifo).is_err());
    }
}

#[test]
fn sheet_is_raw_reproducible_and_drops_source_metadata() {
    let directory = tempdir().unwrap();
    let left_path = directory.path().join("left.png");
    let right_path = directory.path().join("right.png");
    let sheet_path = directory.path().join("sheet.png");
    for depth in [8, 16] {
        for (code, channels) in [(0, 1usize), (2, 3), (4, 2), (6, 4)] {
            let row_bytes = 2 * channels * usize::from(depth / 8);
            let left: Vec<u8> = (0..row_bytes * 2).map(|n| (n * 7 + 1) as u8).collect();
            let right: Vec<u8> = left.iter().map(|value| value.wrapping_add(1)).collect();
            let mut encoded = image(2, 2, depth, code, &left);
            encoded.splice(33..33, chunk(b"gAMA", &45455u32.to_be_bytes()));
            encoded.splice(33..33, chunk(b"tEXt", b"Description\0raw sample source"));
            if code == 0 {
                encoded.splice(33..33, chunk(b"tRNS", &1u16.to_be_bytes()));
            }
            fs::write(&left_path, &encoded).unwrap();
            fs::write(&right_path, image(2, 2, depth, code, &right)).unwrap();
            let a = decode(&left_path).unwrap();
            let b = decode(&right_path).unwrap();
            assert_eq!(a.encoded(), encoded);
            assert_eq!(a.samples(), left);
            let mut sheet = Vec::new();
            write_sheet(&a, &b, &mut sheet).unwrap();
            let mut second = Vec::new();
            write_sheet(&a, &b, &mut second).unwrap();
            assert_eq!(sheet, second);
            let mut offset = 8;
            while offset < sheet.len() {
                let length =
                    u32::from_be_bytes(sheet[offset..offset + 4].try_into().unwrap()) as usize;
                assert!(matches!(
                    &sheet[offset + 4..offset + 8],
                    b"IHDR" | b"IDAT" | b"IEND"
                ));
                offset += length + 12;
            }
            fs::write(&sheet_path, sheet).unwrap();
            let decoded_sheet = decode(&sheet_path).unwrap();
            let expected: Vec<u8> = left
                .chunks_exact(row_bytes)
                .zip(right.chunks_exact(row_bytes))
                .flat_map(|(left, right)| left.iter().chain(right).copied())
                .collect();
            assert_eq!(decoded_sheet.samples(), expected);
            assert_eq!(
                (
                    decoded_sheet.identity().width,
                    decoded_sheet.identity().height
                ),
                (4, 2)
            );
            assert_eq!(decoded_sheet.identity().bit_depth, depth);
        }
    }
}

#[test]
fn sheet_rejects_layout_mismatch_and_propagates_final_write_failures() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("input.png");
    fs::write(&path, image(1, 1, 8, 0, &[1])).unwrap();
    let baseline = decode(&path).unwrap();
    for encoded in [
        image(2, 1, 8, 0, &[1, 2]),
        image(1, 2, 8, 0, &[1, 2]),
        image(1, 1, 16, 0, &[0, 1]),
        image(1, 1, 8, 4, &[1, 255]),
    ] {
        fs::write(&path, encoded).unwrap();
        assert!(write_sheet(&baseline, &decode(&path).unwrap(), Vec::new()).is_err());
    }
    struct FailAtEnd;
    impl Write for FailAtEnd {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if bytes == b"IEND" {
                Err(io::Error::other("final chunk refused"))
            } else {
                Ok(bytes.len())
            }
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    assert!(write_sheet(&baseline, &baseline, FailAtEnd).is_err());
}
