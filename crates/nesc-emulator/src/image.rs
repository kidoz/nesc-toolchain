//! Dependency-free image encoders for rendered frames.
//!
//! These encoders turn a slice of `[R, G, B]` pixels (such as the output of
//! [`Machine::framebuffer_rgb`]) into a viewable file. Everything here uses only
//! the standard library; the PNG path implements CRC-32, Adler-32, and a
//! STORED-block zlib stream directly so no external crates are required.
//!
//! [`Machine::framebuffer_rgb`]: crate::Machine::framebuffer_rgb

/// 8-byte PNG file signature (`\x89PNG\r\n\x1a\n`).
const PNG_SIGNATURE: [u8; 8] = [0x89, b'P', b'N', b'G', b'\r', b'\n', 0x1a, b'\n'];

/// Maximum payload of a single uncompressed DEFLATE (`BTYPE=00`) block.
const STORED_BLOCK_LIMIT: usize = 0xffff;

/// Encodes RGB pixels as a binary (P6) PPM image.
///
/// The returned bytes are an ASCII header `P6\n{width} {height}\n255\n`
/// followed by `width * height * 3` raw RGB bytes.
///
/// If `rgb.len()` does not equal `width * height`, the pixel count is a
/// programming error: a `debug_assert!` fires in debug builds, and in release
/// builds the body is written best-effort by clamping to the shorter of the
/// requested dimensions and the supplied slice. The header always reflects the
/// requested `width` and `height`.
#[must_use]
pub fn encode_ppm(rgb: &[[u8; 3]], width: usize, height: usize) -> Vec<u8> {
    debug_assert!(
        rgb.len() == width.saturating_mul(height),
        "encode_ppm expects width * height pixels"
    );
    let expected = width.saturating_mul(height);
    let pixels = expected.min(rgb.len());
    let header = format!("P6\n{width} {height}\n255\n");
    let mut out = Vec::with_capacity(header.len() + expected * 3);
    out.extend_from_slice(header.as_bytes());
    for pixel in &rgb[..pixels] {
        out.extend_from_slice(pixel);
    }
    out
}

/// Encodes RGB pixels as a minimal, standards-valid 8-bit truecolor PNG.
///
/// The image is color type 2 (RGB), bit depth 8, no interlacing. The single
/// IDAT chunk carries a zlib stream built from uncompressed DEFLATE
/// (`BTYPE=00`) blocks, so the file is larger than a compressed encoder would
/// produce but opens in any conforming viewer. Correctness is prioritized over
/// size.
///
/// If `rgb.len()` does not equal `width * height`, a `debug_assert!` fires in
/// debug builds; in release builds missing pixels are emitted as black and
/// extra pixels are ignored, so the output always matches the declared
/// dimensions.
#[must_use]
pub fn encode_png(rgb: &[[u8; 3]], width: usize, height: usize) -> Vec<u8> {
    debug_assert!(
        rgb.len() == width.saturating_mul(height),
        "encode_png expects width * height pixels"
    );

    let mut out = Vec::new();
    out.extend_from_slice(&PNG_SIGNATURE);

    // IHDR: width, height, bit depth 8, color type 2, compression 0, filter 0,
    // interlace 0.
    let mut ihdr = Vec::with_capacity(13);
    ihdr.extend_from_slice(&(width as u32).to_be_bytes());
    ihdr.extend_from_slice(&(height as u32).to_be_bytes());
    ihdr.extend_from_slice(&[8, 2, 0, 0, 0]);
    write_chunk(&mut out, b"IHDR", &ihdr);

    // Filtered scanlines: each row is prefixed with filter byte 0 (None).
    let mut filtered = Vec::with_capacity(height.saturating_mul(width * 3 + 1));
    for y in 0..height {
        filtered.push(0);
        for x in 0..width {
            let pixel = rgb.get(y * width + x).copied().unwrap_or([0, 0, 0]);
            filtered.extend_from_slice(&pixel);
        }
    }

    let idat = zlib_stored(&filtered);
    write_chunk(&mut out, b"IDAT", &idat);
    write_chunk(&mut out, b"IEND", &[]);
    out
}

/// Appends a length-prefixed, CRC-checked PNG chunk to `out`.
fn write_chunk(out: &mut Vec<u8>, kind: &[u8; 4], data: &[u8]) {
    out.extend_from_slice(&(data.len() as u32).to_be_bytes());
    out.extend_from_slice(kind);
    out.extend_from_slice(data);
    let mut crc_input = Vec::with_capacity(4 + data.len());
    crc_input.extend_from_slice(kind);
    crc_input.extend_from_slice(data);
    out.extend_from_slice(&crc32(&crc_input).to_be_bytes());
}

/// Wraps `data` in a zlib stream using only uncompressed DEFLATE blocks.
fn zlib_stored(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    // zlib header: CMF=0x78 (deflate, 32 KiB window), FLG=0x01 (no dict, check
    // bits make 0x7801 a multiple of 31).
    out.extend_from_slice(&[0x78, 0x01]);

    if data.is_empty() {
        // A single empty final stored block.
        out.push(0x01);
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&(!0u16).to_le_bytes());
    } else {
        let mut offset = 0;
        while offset < data.len() {
            let remaining = data.len() - offset;
            let block = remaining.min(STORED_BLOCK_LIMIT);
            let final_block = offset + block >= data.len();
            out.push(u8::from(final_block));
            let len = block as u16;
            out.extend_from_slice(&len.to_le_bytes());
            out.extend_from_slice(&(!len).to_le_bytes());
            out.extend_from_slice(&data[offset..offset + block]);
            offset += block;
        }
    }

    out.extend_from_slice(&adler32(data).to_be_bytes());
    out
}

/// Computes the CRC-32 (ISO 3309 / PNG) of `data`.
fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xffff_ffff_u32;
    for &byte in data {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xedb8_8320 & mask);
        }
    }
    !crc
}

/// Computes the Adler-32 checksum of `data`.
fn adler32(data: &[u8]) -> u32 {
    const MOD_ADLER: u32 = 65_521;
    let mut a = 1_u32;
    let mut b = 0_u32;
    for &byte in data {
        a = (a + u32::from(byte)) % MOD_ADLER;
        b = (b + a) % MOD_ADLER;
    }
    (b << 16) | a
}

#[cfg(test)]
mod tests {
    use super::{PNG_SIGNATURE, adler32, crc32, encode_png, encode_ppm};

    #[test]
    fn crc32_matches_the_standard_iend_vector() {
        assert_eq!(crc32(b"IEND"), 0xAE42_6082);
    }

    #[test]
    fn adler32_matches_known_vectors() {
        assert_eq!(adler32(b""), 1);
        assert_eq!(adler32(b"abc"), 0x024D_0127);
    }

    #[test]
    fn ppm_header_and_body_length_are_exact() {
        let pixels = [[1, 2, 3], [4, 5, 6], [7, 8, 9], [10, 11, 12]];
        let ppm = encode_ppm(&pixels, 2, 2);
        let header = b"P6\n2 2\n255\n";
        assert_eq!(&ppm[..header.len()], header);
        assert_eq!(ppm.len() - header.len(), 12);
    }

    #[test]
    fn png_signature_ihdr_and_iend_are_well_formed() {
        let width = 3;
        let height = 2;
        let pixels = vec![[9, 8, 7]; width * height];
        let png = encode_png(&pixels, width, height);

        assert_eq!(&png[..8], b"\x89PNG\r\n\x1a\n");
        assert_eq!(&png[..8], &PNG_SIGNATURE);

        // First chunk after the signature is IHDR (length 13).
        assert_eq!(&png[8..12], &[0, 0, 0, 13]);
        assert_eq!(&png[12..16], b"IHDR");
        // IHDR width/height are big-endian at bytes 16..24.
        assert_eq!(&png[16..20], &(width as u32).to_be_bytes());
        assert_eq!(&png[20..24], &(height as u32).to_be_bytes());
        assert_eq!(png[24], 8); // bit depth
        assert_eq!(png[25], 2); // color type (truecolor)

        // The IHDR CRC covers the type and 13 data bytes.
        let ihdr_crc = crc32(&png[12..29]);
        assert_eq!(&png[29..33], &ihdr_crc.to_be_bytes());

        // The stream ends with a canonical, empty IEND chunk.
        let iend = [
            0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4e, 0x44, 0xae, 0x42, 0x60, 0x82,
        ];
        assert_eq!(&png[png.len() - 12..], &iend);
    }

    #[test]
    fn png_spans_multiple_stored_blocks_for_large_frames() {
        // 256x240 truecolor filtered data far exceeds one 65535-byte block.
        let width = 256;
        let height = 240;
        let pixels = vec![[0x24, 0x18, 0x00]; width * height];
        let png = encode_png(&pixels, width, height);
        assert_eq!(&png[..8], &PNG_SIGNATURE);
        // Ends with a valid IEND regardless of block count.
        let iend = [
            0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4e, 0x44, 0xae, 0x42, 0x60, 0x82,
        ];
        assert_eq!(&png[png.len() - 12..], &iend);
    }
}
