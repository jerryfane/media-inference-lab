use std::fs::{self, File, OpenOptions};
use std::io::{Cursor, Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail, ensure};
use flate2::{Decompress, FlushDecompress, Status};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const MAX_ENCODED_BYTES: u64 = 32 * 1024 * 1024;
pub const MAX_PIXELS: u64 = 16 * 1024 * 1024;
pub const MAX_DECODED_BYTES: usize = 128 * 1024 * 1024;
const MAX_AXIS: u32 = 16384;
const SIGNATURE: &[u8; 8] = b"\x89PNG\r\n\x1a\n";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SampleColor {
    Gray,
    GrayAlpha,
    Rgb,
    Rgba,
}

impl SampleColor {
    pub fn channels(self) -> usize {
        match self {
            Self::Gray => 1,
            Self::GrayAlpha => 2,
            Self::Rgb => 3,
            Self::Rgba => 4,
        }
    }

    fn png(self) -> png::ColorType {
        match self {
            Self::Gray => png::ColorType::Grayscale,
            Self::GrayAlpha => png::ColorType::GrayscaleAlpha,
            Self::Rgb => png::ColorType::Rgb,
            Self::Rgba => png::ColorType::Rgba,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PngIdentity {
    pub source_path: PathBuf,
    pub sha256: String,
    pub bytes: u64,
    pub decoded_sha256: String,
    pub width: u32,
    pub height: u32,
    pub color: SampleColor,
    pub bit_depth: u8,
}

#[derive(Debug)]
pub struct DecodedPng {
    identity: PngIdentity,
    samples: Vec<u8>,
    encoded: Vec<u8>,
}

impl DecodedPng {
    pub fn identity(&self) -> &PngIdentity {
        &self.identity
    }

    pub(crate) fn into_identity(self) -> PngIdentity {
        self.identity
    }

    pub fn samples(&self) -> &[u8] {
        &self.samples
    }

    pub fn encoded(&self) -> &[u8] {
        &self.encoded
    }
}

pub(crate) fn regular_file(path: &Path) -> Result<File> {
    let metadata = fs::symlink_metadata(path)?;
    ensure!(
        metadata.is_file() && !metadata.file_type().is_symlink(),
        "not a regular non-symlink file: {}",
        path.display()
    );
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options.open(path)?;
    ensure!(
        file.metadata()?.is_file(),
        "not a regular file: {}",
        path.display()
    );
    Ok(file)
}

struct Header {
    width: u32,
    height: u32,
    color: SampleColor,
    depth: u8,
    interlaced: bool,
}

impl Header {
    fn sample_bytes(&self) -> usize {
        self.color.channels() * usize::from(self.depth / 8)
    }

    fn decoded_bytes(&self) -> usize {
        self.width as usize * self.height as usize * self.sample_bytes()
    }

    fn filtered_bytes(&self) -> u64 {
        let pass = |x: u32, y: u32, dx: u32, dy: u32| {
            let width = self.width.saturating_sub(x).div_ceil(dx);
            let height = self.height.saturating_sub(y).div_ceil(dy);
            if width == 0 || height == 0 {
                0
            } else {
                (u64::from(width) * self.sample_bytes() as u64 + 1) * u64::from(height)
            }
        };
        if self.interlaced {
            [
                (0, 0, 8, 8),
                (4, 0, 8, 8),
                (0, 4, 4, 8),
                (2, 0, 4, 4),
                (0, 2, 2, 4),
                (1, 0, 2, 2),
                (0, 1, 1, 2),
            ]
            .into_iter()
            .map(|(x, y, dx, dy)| pass(x, y, dx, dy))
            .sum()
        } else {
            pass(0, 0, 1, 1)
        }
    }
}

fn u32_be(bytes: &[u8]) -> u32 {
    u32::from_be_bytes(bytes.try_into().expect("validated four-byte PNG field"))
}

// Check the entire envelope before decoding, including chunks following the image.
// Ancillary payloads remain uninterpreted; the decoder checks their CRCs without
// decompressing text or ICC profiles. Unknown critical chunks are not safe to ignore.
fn validate_envelope(encoded: &[u8]) -> Result<Header> {
    ensure!(encoded.starts_with(SIGNATURE), "not a PNG signature");
    let mut offset = SIGNATURE.len();
    let mut header = None;
    let mut seen_idat = false;
    let mut ended_idat = false;
    let mut seen_palette = false;
    let mut seen_transparency = false;
    while offset < encoded.len() {
        ensure!(encoded.len() - offset >= 12, "truncated PNG chunk");
        let length = u32_be(&encoded[offset..offset + 4]) as usize;
        ensure!(length <= 0x7fff_ffff, "invalid PNG chunk length");
        let end = offset
            .checked_add(12)
            .and_then(|n| n.checked_add(length))
            .context("PNG chunk length overflow")?;
        ensure!(end <= encoded.len(), "truncated PNG chunk data or CRC");
        let kind = &encoded[offset + 4..offset + 8];
        ensure!(
            kind.iter().all(u8::is_ascii_alphabetic) && kind[2].is_ascii_uppercase(),
            "invalid PNG chunk type"
        );
        ensure!(
            !matches!(kind, b"acTL" | b"fcTL" | b"fdAT"),
            "APNG is unsupported"
        );
        ensure!(
            header.is_some() || kind == b"IHDR",
            "IHDR must be the first PNG chunk"
        );
        let data = &encoded[offset + 8..end - 4];
        match kind {
            b"IHDR" => {
                ensure!(header.is_none() && length == 13, "invalid or repeated IHDR");
                let width = u32_be(&data[..4]);
                let height = u32_be(&data[4..8]);
                ensure!(
                    width > 0 && height > 0 && width <= MAX_AXIS && height <= MAX_AXIS,
                    "PNG dimensions must be nonzero and at most {MAX_AXIS} per axis"
                );
                ensure!(
                    u64::from(width) * u64::from(height) <= MAX_PIXELS,
                    "PNG exceeds pixel limit"
                );
                let depth = data[8];
                ensure!(
                    matches!(depth, 8 | 16),
                    "only 8-bit and 16-bit PNG samples are supported"
                );
                let color = match data[9] {
                    0 => SampleColor::Gray,
                    2 => SampleColor::Rgb,
                    4 => SampleColor::GrayAlpha,
                    6 => SampleColor::Rgba,
                    _ => bail!("indexed or unknown PNG color type is unsupported"),
                };
                ensure!(
                    data[10] == 0 && data[11] == 0 && data[12] <= 1,
                    "unsupported PNG compression, filter, or interlace method"
                );
                let parsed = Header {
                    width,
                    height,
                    color,
                    depth,
                    interlaced: data[12] == 1,
                };
                ensure!(
                    parsed.decoded_bytes() <= MAX_DECODED_BYTES,
                    "PNG exceeds decoded byte limit"
                );
                header = Some(parsed);
            }
            b"PLTE" => {
                ensure!(
                    !seen_palette
                        && !seen_idat
                        && !seen_transparency
                        && length > 0
                        && length <= 768
                        && length.is_multiple_of(3),
                    "invalid, repeated, or misplaced PLTE"
                );
                ensure!(
                    matches!(
                        header.as_ref().unwrap().color,
                        SampleColor::Rgb | SampleColor::Rgba
                    ),
                    "PLTE is invalid for grayscale PNG"
                );
                seen_palette = true;
            }
            b"tRNS" => {
                ensure!(
                    !seen_transparency && !seen_idat,
                    "tRNS must occur once, before image data and after any PLTE"
                );
                // png 0.18.1 accepts overlong and post-IDAT tRNS without a
                // BadAncillaryChunk event. Check structure here, not sample values.
                let expected = match header.as_ref().unwrap().color {
                    SampleColor::Gray => 2,
                    SampleColor::Rgb => 6,
                    SampleColor::GrayAlpha | SampleColor::Rgba => {
                        bail!("tRNS is forbidden for PNG color types with alpha")
                    }
                };
                ensure!(
                    length == expected,
                    "tRNS must contain exactly {expected} bytes"
                );
                seen_transparency = true;
            }
            b"IDAT" => {
                ensure!(!ended_idat, "PNG IDAT chunks must be consecutive");
                seen_idat = true;
            }
            b"IEND" => {
                ensure!(
                    length == 0 && seen_idat,
                    "invalid IEND or missing image data"
                );
                ensure!(end == encoded.len(), "trailing data after PNG IEND");
                return Ok(header.unwrap());
            }
            _ => ensure!(kind[0].is_ascii_lowercase(), "unknown critical PNG chunk"),
        }
        if seen_idat && kind != b"IDAT" {
            ended_idat = true;
        }
        offset = end;
    }
    bail!("PNG is missing terminal IEND")
}

// png's raster decoder deliberately discards data after the expected rows and
// allows bytes after the zlib stream. Validate the stream separately, with fixed
// scratch space, so truncated checksums and excess raster/compressed data fail.
fn validate_image_data(
    encoded: &[u8],
    expected: u64,
    checkpoint: &mut impl FnMut() -> Result<()>,
) -> Result<()> {
    let mut inflater = Decompress::new(true);
    let mut scratch = [0u8; 32 * 1024];
    let mut ended = false;
    let mut offset = SIGNATURE.len();
    while offset < encoded.len() {
        let length = u32_be(&encoded[offset..offset + 4]) as usize;
        let end = offset + 12 + length;
        if &encoded[offset + 4..offset + 8] == b"IDAT" {
            let mut input = &encoded[offset + 8..end - 4];
            while !input.is_empty() {
                checkpoint()?;
                ensure!(!ended, "trailing compressed data in PNG IDAT");
                let before_in = inflater.total_in();
                let before_out = inflater.total_out();
                let status = inflater
                    .decompress(input, &mut scratch, FlushDecompress::None)
                    .context("invalid PNG zlib stream or checksum")?;
                let consumed = (inflater.total_in() - before_in) as usize;
                ensure!(
                    inflater.total_out() <= expected,
                    "PNG has excess decompressed image data"
                );
                ensure!(
                    consumed > 0
                        || inflater.total_out() > before_out
                        || status == Status::StreamEnd,
                    "PNG decompression made no progress"
                );
                input = &input[consumed..];
                ended = status == Status::StreamEnd;
            }
        }
        offset = end;
    }
    while !ended {
        checkpoint()?;
        let before = inflater.total_out();
        let status = inflater
            .decompress(&[], &mut scratch, FlushDecompress::Finish)
            .context("truncated PNG zlib stream")?;
        ensure!(
            inflater.total_out() <= expected,
            "PNG has excess decompressed image data"
        );
        ended = status == Status::StreamEnd;
        ensure!(
            ended || inflater.total_out() > before,
            "truncated PNG zlib stream"
        );
    }
    ensure!(
        inflater.total_out() == expected,
        "PNG has incomplete image data"
    );
    Ok(())
}

fn validate_chunks(
    encoded: &[u8],
    options: png::DecodeOptions,
    checkpoint: &mut impl FnMut() -> Result<()>,
) -> Result<()> {
    // The high-level Reader ignores BadAncillaryChunk events. Inspect them here
    // rather than silently accepting malformed recognized metadata. With no
    // image buffer this pass checks chunks/CRCs but does not inflate IDAT.
    let mut decoder = png::StreamingDecoder::new_with_options(options);
    let mut remaining = encoded;
    while !remaining.is_empty() {
        checkpoint()?;
        let (consumed, event) = decoder.update(remaining, None)?;
        ensure!(
            !matches!(event, png::Decoded::BadAncillaryChunk(_)),
            "malformed recognized PNG ancillary chunk"
        );
        remaining = &remaining[consumed..];
    }
    Ok(())
}

/// Decode unchanged sample codes from a bounded static PNG snapshot. Sixteen-bit
/// samples are big-endian. No color management, alpha expansion, or orientation
/// transform is applied; original encoded bytes retain all source metadata.
/// Accepted files contain at most 32 MiB; reads check the bound after each
/// fixed-size block, including when a file grows after its metadata was checked.
pub fn decode(path: &Path) -> Result<DecodedPng> {
    decode_open_file(
        path, regular_file(path)?, MAX_ENCODED_BYTES, MAX_DECODED_BYTES, &mut || Ok(())
    )
}

pub(crate) fn read_open_file(
    mut file: File,
    max_bytes: u64,
    checkpoint: &mut impl FnMut() -> Result<()>,
) -> Result<Vec<u8>> {
    checkpoint()?;
    let metadata = file.metadata()?;
    let limit = max_bytes.min(MAX_ENCODED_BYTES);
    ensure!(metadata.is_file(), "PNG input is not a regular file");
    ensure!(metadata.len() <= limit, "PNG exceeds encoded byte limit");
    let mut encoded = Vec::with_capacity(metadata.len() as usize);
    let mut buffer = [0u8; 64 * 1024];
    loop {
        checkpoint()?;
        let next = (limit - encoded.len() as u64 + 1).min(buffer.len() as u64) as usize;
        let count = file.read(&mut buffer[..next])?;
        if count == 0 {
            break;
        }
        ensure!(
            (encoded.len() as u64).saturating_add(count as u64) <= limit,
            "PNG exceeds encoded byte limit"
        );
        encoded.extend_from_slice(&buffer[..count]);
    }
    Ok(encoded)
}

pub(crate) fn decode_open_file(
    path: &Path,
    file: File,
    max_bytes: u64,
    max_decoded_bytes: usize,
    checkpoint: &mut impl FnMut() -> Result<()>,
) -> Result<DecodedPng> {
    let encoded = read_open_file(file, max_bytes, checkpoint)?;
    decode_encoded(path, encoded, None, max_decoded_bytes, checkpoint)
}

pub(crate) fn decode_encoded(
    path: &Path,
    encoded: Vec<u8>,
    encoded_sha256: Option<String>,
    max_decoded_bytes: usize,
    checkpoint: &mut impl FnMut() -> Result<()>,
) -> Result<DecodedPng> {
    checkpoint()?;
    ensure!(
        encoded.starts_with(SIGNATURE),
        "unsupported image format: only static PNG stored rasters are supported"
    );
    let header =
        validate_envelope(&encoded).with_context(|| format!("invalid PNG {}", path.display()))?;
    ensure!(
        header.decoded_bytes() <= max_decoded_bytes,
        "aggregate decoded image byte limit exceeded"
    );
    let mut options = png::DecodeOptions::default();
    options.set_ignore_checksums(false);
    options.set_skip_ancillary_crc_failures(false);
    options.set_ignore_text_chunk(true);
    options.set_ignore_iccp_chunk(true);
    validate_chunks(&encoded, options.clone(), checkpoint)?;
    validate_image_data(&encoded, header.filtered_bytes(), checkpoint)?;
    checkpoint()?;
    // These exact retained bytes have already passed strict CRC and zlib checks.
    options.set_ignore_checksums(true);
    let mut decoder = png::Decoder::new_with_options(Cursor::new(&encoded), options);
    decoder.set_limits(png::Limits {
        bytes: MAX_DECODED_BYTES,
    });
    decoder.set_transformations(png::Transformations::IDENTITY);
    let mut reader = decoder
        .read_info()
        .context("invalid PNG header or metadata")?;
    ensure!(
        reader.output_buffer_size() == Some(header.decoded_bytes()),
        "unexpected PNG raster size"
    );
    let mut samples = vec![0; header.decoded_bytes()];
    let output = reader
        .next_frame(&mut samples)
        .context("invalid PNG image data")?;
    checkpoint()?;
    ensure!(
        output.width == header.width
            && output.height == header.height
            && output.color_type == header.color.png()
            && output.bit_depth as u8 == header.depth
            && output.buffer_size() == samples.len(),
        "PNG decoder changed sample layout"
    );
    reader.finish().context("invalid trailing PNG chunks")?;
    let identity = PngIdentity {
        source_path: path.to_path_buf(),
        sha256: encoded_sha256.unwrap_or_else(|| format!("{:x}", Sha256::digest(&encoded))),
        bytes: encoded.len() as u64,
        decoded_sha256: format!("{:x}", Sha256::digest(&samples)),
        width: header.width,
        height: header.height,
        color: header.color,
        bit_depth: header.depth,
    };
    checkpoint()?;
    Ok(DecodedPng {
        identity,
        samples,
        encoded,
    })
}

/// Write a reproducible, raw-sample A/B sheet: baseline on the left, candidate on
/// the right. Ancillary metadata is deliberately omitted, so this is not a
/// color-managed rendering or a claim of perceptual equivalence.
pub fn write_sheet(left: &DecodedPng, right: &DecodedPng, output: impl Write) -> Result<()> {
    let a = left.identity();
    let b = right.identity();
    ensure!(
        a.width == b.width
            && a.height == b.height
            && a.color == b.color
            && a.bit_depth == b.bit_depth,
        "A/B sheet requires identical dimensions, color channels, and bit depth"
    );
    let mut encoder = png::Encoder::new(output, a.width * 2, a.height);
    encoder.set_color(a.color.png());
    encoder.set_depth(if a.bit_depth == 16 {
        png::BitDepth::Sixteen
    } else {
        png::BitDepth::Eight
    });
    let mut writer = encoder.write_header()?;
    let row_bytes = a.width as usize * a.color.channels() * usize::from(a.bit_depth / 8);
    {
        let mut stream = writer.stream_writer()?;
        for (left_row, right_row) in left
            .samples
            .chunks_exact(row_bytes)
            .zip(right.samples.chunks_exact(row_bytes))
        {
            stream.write_all(left_row)?;
            stream.write_all(right_row)?;
        }
        stream.finish()?;
    }
    writer.finish()?;
    Ok(())
}
