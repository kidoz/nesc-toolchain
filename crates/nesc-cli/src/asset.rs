//! Indexed-PNG to CHR tile conversion for the `nesc asset` subcommands.
//!
//! The importer accepts palette-indexed PNGs (color type 3) whose pixel
//! indices are NES pattern colors 0-3, and emits raw planar 2bpp CHR tiles in
//! row-major 8x8 tile order — the format `[assets] chr` embeds into CHR-ROM.
//! The PNG container, zlib stream, and DEFLATE decoder are implemented here
//! in safe Rust; the workspace deliberately carries no external decoders.

/// Palette-indexed image decoded from a PNG.
pub(crate) struct IndexedImage {
    /// Width in pixels.
    pub width: usize,
    /// Height in pixels.
    pub height: usize,
    /// Row-major palette indices, one byte per pixel.
    pub indices: Vec<u8>,
}

/// Decodes an indexed (color type 3) PNG into per-pixel palette indices.
///
/// # Errors
///
/// Returns a message for signature, chunk, CRC, header, compression, or
/// filter failures, and for unsupported PNG shapes (non-indexed color,
/// interlacing, bit depths other than 1, 2, 4, or 8).
pub(crate) fn decode_indexed_png(data: &[u8]) -> Result<IndexedImage, String> {
    const SIGNATURE: [u8; 8] = [137, 80, 78, 71, 13, 10, 26, 10];
    if data.len() < 8 || data[..8] != SIGNATURE {
        return Err("not a PNG file (bad signature)".to_owned());
    }

    let mut position = 8;
    let mut header: Option<(usize, usize, u8)> = None;
    let mut compressed = Vec::new();
    let mut finished = false;
    while position + 8 <= data.len() {
        let length = u32::from_be_bytes([
            data[position],
            data[position + 1],
            data[position + 2],
            data[position + 3],
        ]) as usize;
        let kind = &data[position + 4..position + 8];
        let body_start = position + 8;
        let body_end = body_start
            .checked_add(length)
            .filter(|end| end + 4 <= data.len())
            .ok_or_else(|| "PNG chunk overruns the file".to_owned())?;
        let body = &data[body_start..body_end];
        let stored_crc = u32::from_be_bytes([
            data[body_end],
            data[body_end + 1],
            data[body_end + 2],
            data[body_end + 3],
        ]);
        if crc32(&data[position + 4..body_end]) != stored_crc {
            return Err(format!(
                "PNG chunk `{}` fails its CRC check",
                String::from_utf8_lossy(kind)
            ));
        }
        match kind {
            b"IHDR" => {
                if body.len() != 13 {
                    return Err("PNG IHDR chunk has the wrong length".to_owned());
                }
                let width = u32::from_be_bytes([body[0], body[1], body[2], body[3]]) as usize;
                let height = u32::from_be_bytes([body[4], body[5], body[6], body[7]]) as usize;
                let bit_depth = body[8];
                let color_type = body[9];
                if color_type != 3 {
                    return Err(format!(
                        "PNG color type {color_type} is not supported; export an indexed \
                         (palette) PNG"
                    ));
                }
                if !matches!(bit_depth, 1 | 2 | 4 | 8) {
                    return Err(format!(
                        "indexed PNG bit depth {bit_depth} is not supported"
                    ));
                }
                if body[10] != 0 || body[11] != 0 {
                    return Err("PNG uses an unsupported compression or filter method".to_owned());
                }
                if body[12] != 0 {
                    return Err("interlaced (Adam7) PNGs are not supported".to_owned());
                }
                if width == 0 || height == 0 {
                    return Err("PNG has a zero dimension".to_owned());
                }
                header = Some((width, height, bit_depth));
            }
            b"IDAT" => compressed.extend_from_slice(body),
            b"IEND" => {
                finished = true;
                break;
            }
            _ => {}
        }
        position = body_end + 4;
    }
    if !finished {
        return Err("PNG is truncated before its IEND chunk".to_owned());
    }
    let (width, height, bit_depth) = header.ok_or_else(|| "PNG has no IHDR chunk".to_owned())?;

    let raw = zlib_decompress(&compressed)?;
    let stride = width
        .checked_mul(usize::from(bit_depth))
        .map(|bits| bits.div_ceil(8))
        .ok_or_else(|| "PNG dimensions overflow".to_owned())?;
    let expected = height
        .checked_mul(stride + 1)
        .ok_or_else(|| "PNG dimensions overflow".to_owned())?;
    if raw.len() != expected {
        return Err(format!(
            "PNG pixel data is {} bytes, expected {expected}",
            raw.len()
        ));
    }

    let mut rows = Vec::with_capacity(height * stride);
    let mut previous = vec![0u8; stride];
    for y in 0..height {
        let line_start = y * (stride + 1);
        let filter = raw[line_start];
        let mut line = raw[line_start + 1..line_start + 1 + stride].to_vec();
        unfilter_line(filter, &mut line, &previous)
            .map_err(|error| format!("PNG row {y}: {error}"))?;
        rows.extend_from_slice(&line);
        previous = line;
    }

    let mut indices = Vec::with_capacity(width * height);
    for y in 0..height {
        let line = &rows[y * stride..(y + 1) * stride];
        for x in 0..width {
            let index = match bit_depth {
                8 => line[x],
                4 => (line[x / 2] >> (4 - 4 * (x % 2))) & 0x0f,
                2 => (line[x / 4] >> (6 - 2 * (x % 4))) & 0x03,
                _ => (line[x / 8] >> (7 - (x % 8))) & 0x01,
            };
            indices.push(index);
        }
    }
    Ok(IndexedImage {
        width,
        height,
        indices,
    })
}

fn unfilter_line(filter: u8, line: &mut [u8], previous: &[u8]) -> Result<(), String> {
    // Indexed PNGs filter on whole bytes (bpp = 1 for depths <= 8).
    match filter {
        0 => {}
        1 => {
            for x in 1..line.len() {
                line[x] = line[x].wrapping_add(line[x - 1]);
            }
        }
        2 => {
            for x in 0..line.len() {
                line[x] = line[x].wrapping_add(previous[x]);
            }
        }
        3 => {
            for x in 0..line.len() {
                let left = if x > 0 { u16::from(line[x - 1]) } else { 0 };
                let up = u16::from(previous[x]);
                line[x] = line[x].wrapping_add(((left + up) / 2) as u8);
            }
        }
        4 => {
            for x in 0..line.len() {
                let left = if x > 0 { i32::from(line[x - 1]) } else { 0 };
                let up = i32::from(previous[x]);
                let up_left = if x > 0 { i32::from(previous[x - 1]) } else { 0 };
                let estimate = left + up - up_left;
                let delta_left = (estimate - left).abs();
                let delta_up = (estimate - up).abs();
                let delta_up_left = (estimate - up_left).abs();
                let paeth = if delta_left <= delta_up && delta_left <= delta_up_left {
                    left
                } else if delta_up <= delta_up_left {
                    up
                } else {
                    up_left
                };
                line[x] = line[x].wrapping_add(paeth as u8);
            }
        }
        _ => return Err(format!("unsupported PNG filter type {filter}")),
    }
    Ok(())
}

/// Converts a decoded indexed image into planar 2bpp CHR tiles in row-major
/// 8x8 tile order.
///
/// # Errors
///
/// Returns a message when the dimensions are not multiples of 8 or a pixel
/// uses a palette index above 3 (the NES 4-colors-per-tile constraint).
pub(crate) fn image_to_chr(image: &IndexedImage) -> Result<Vec<u8>, String> {
    if image.width % 8 != 0 || image.height % 8 != 0 {
        return Err(format!(
            "image is {}x{} pixels; CHR tiles need multiples of 8",
            image.width, image.height
        ));
    }
    let columns = image.width / 8;
    let rows = image.height / 8;
    let mut chr = Vec::with_capacity(columns * rows * 16);
    for tile_y in 0..rows {
        for tile_x in 0..columns {
            let mut plane0 = [0u8; 8];
            let mut plane1 = [0u8; 8];
            for y in 0..8 {
                for x in 0..8 {
                    let pixel_x = tile_x * 8 + x;
                    let pixel_y = tile_y * 8 + y;
                    let index = image.indices[pixel_y * image.width + pixel_x];
                    if index > 3 {
                        return Err(format!(
                            "tile ({tile_x},{tile_y}) pixel ({pixel_x},{pixel_y}) uses \
                             palette index {index}; CHR tiles allow indices 0-3"
                        ));
                    }
                    plane0[y] |= (index & 1) << (7 - x);
                    plane1[y] |= ((index >> 1) & 1) << (7 - x);
                }
            }
            chr.extend_from_slice(&plane0);
            chr.extend_from_slice(&plane1);
        }
    }
    Ok(chr)
}

fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xffff_ffff_u32;
    for byte in data {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            let mask = 0u32.wrapping_sub(crc & 1);
            crc = (crc >> 1) ^ (0xedb8_8320 & mask);
        }
    }
    !crc
}

/// Decompresses a zlib stream (RFC 1950 wrapper around DEFLATE).
///
/// # Errors
///
/// Returns a message for header, dictionary, DEFLATE, or checksum failures.
pub(crate) fn zlib_decompress(data: &[u8]) -> Result<Vec<u8>, String> {
    if data.len() < 6 {
        return Err("zlib stream is too short".to_owned());
    }
    let cmf = data[0];
    let flags = data[1];
    if cmf & 0x0f != 8 {
        return Err("zlib stream does not use the DEFLATE method".to_owned());
    }
    if (u16::from(cmf) << 8 | u16::from(flags)) % 31 != 0 {
        return Err("zlib header check failed".to_owned());
    }
    if flags & 0x20 != 0 {
        return Err("zlib preset dictionaries are not supported".to_owned());
    }
    let output = inflate(&data[2..data.len() - 4])?;
    let stored = u32::from_be_bytes([
        data[data.len() - 4],
        data[data.len() - 3],
        data[data.len() - 2],
        data[data.len() - 1],
    ]);
    if adler32(&output) != stored {
        return Err("zlib Adler-32 checksum mismatch".to_owned());
    }
    Ok(output)
}

fn adler32(data: &[u8]) -> u32 {
    let mut low = 1u32;
    let mut high = 0u32;
    for byte in data {
        low = (low + u32::from(*byte)) % 65_521;
        high = (high + low) % 65_521;
    }
    high << 16 | low
}

struct BitReader<'a> {
    data: &'a [u8],
    position: usize,
    bit: u32,
}

impl<'a> BitReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            position: 0,
            bit: 0,
        }
    }

    fn bits(&mut self, count: u32) -> Result<u32, String> {
        let mut value = 0u32;
        for offset in 0..count {
            let byte = self
                .data
                .get(self.position)
                .ok_or_else(|| "DEFLATE stream is truncated".to_owned())?;
            value |= u32::from(byte >> self.bit & 1) << offset;
            self.bit += 1;
            if self.bit == 8 {
                self.bit = 0;
                self.position += 1;
            }
        }
        Ok(value)
    }

    fn align(&mut self) {
        if self.bit != 0 {
            self.bit = 0;
            self.position += 1;
        }
    }

    fn stored_bytes(&mut self, length: usize) -> Result<&'a [u8], String> {
        self.align();
        let start = self.position;
        let end = start
            .checked_add(length)
            .filter(|end| *end <= self.data.len())
            .ok_or_else(|| "DEFLATE stored block overruns the stream".to_owned())?;
        self.position = end;
        Ok(&self.data[start..end])
    }
}

struct Huffman {
    counts: [u16; 16],
    symbols: Vec<u16>,
}

fn build_huffman(lengths: &[u8]) -> Result<Huffman, String> {
    let mut counts = [0u16; 16];
    for length in lengths {
        counts[usize::from(*length)] += 1;
    }
    counts[0] = 0;
    let mut offsets = [0u16; 16];
    for length in 1..16 {
        offsets[length] = offsets[length - 1] + counts[length - 1];
    }
    let mut symbols = vec![0u16; lengths.iter().filter(|length| **length != 0).count()];
    for (symbol, length) in lengths.iter().enumerate() {
        if *length != 0 {
            let slot = &mut offsets[usize::from(*length)];
            symbols[usize::from(*slot)] = symbol as u16;
            *slot += 1;
        }
    }
    Ok(Huffman { counts, symbols })
}

fn decode_symbol(reader: &mut BitReader<'_>, huffman: &Huffman) -> Result<u16, String> {
    let mut code = 0i32;
    let mut first = 0i32;
    let mut index = 0i32;
    for length in 1..16 {
        code |= reader.bits(1)? as i32;
        let count = i32::from(huffman.counts[length]);
        if code - first < count {
            return Ok(huffman.symbols[(index + (code - first)) as usize]);
        }
        index += count;
        first = (first + count) << 1;
        code <<= 1;
    }
    Err("invalid Huffman code in DEFLATE stream".to_owned())
}

const LENGTH_BASE: [u16; 29] = [
    3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131,
    163, 195, 227, 258,
];
const LENGTH_EXTRA: [u32; 29] = [
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0,
];
const DISTANCE_BASE: [u16; 30] = [
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537,
    2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577,
];
const DISTANCE_EXTRA: [u32; 30] = [
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13,
    13,
];

fn inflate(data: &[u8]) -> Result<Vec<u8>, String> {
    let mut reader = BitReader::new(data);
    let mut output = Vec::new();
    loop {
        let last = reader.bits(1)? == 1;
        let kind = reader.bits(2)?;
        match kind {
            0 => {
                // Stored blocks realign to a byte boundary before LEN/NLEN.
                reader.align();
                let length = reader.bits(16)? as usize;
                let complement = reader.bits(16)? as usize;
                if length != (!complement & 0xffff) {
                    return Err("DEFLATE stored block length check failed".to_owned());
                }
                let bytes = reader.stored_bytes(length)?;
                output.extend_from_slice(bytes);
            }
            1 => {
                let mut literal_lengths = [0u8; 288];
                for (symbol, length) in literal_lengths.iter_mut().enumerate() {
                    *length = match symbol {
                        0..=143 => 8,
                        144..=255 => 9,
                        256..=279 => 7,
                        _ => 8,
                    };
                }
                let literals = build_huffman(&literal_lengths)?;
                let distances = build_huffman(&[5u8; 30])?;
                inflate_block(&mut reader, &mut output, &literals, &distances)?;
            }
            2 => {
                let (literals, distances) = read_dynamic_tables(&mut reader)?;
                inflate_block(&mut reader, &mut output, &literals, &distances)?;
            }
            _ => return Err("reserved DEFLATE block type".to_owned()),
        }
        if last {
            return Ok(output);
        }
    }
}

fn read_dynamic_tables(reader: &mut BitReader<'_>) -> Result<(Huffman, Huffman), String> {
    const ORDER: [usize; 19] = [
        16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15,
    ];
    let literal_count = reader.bits(5)? as usize + 257;
    let distance_count = reader.bits(5)? as usize + 1;
    let code_length_count = reader.bits(4)? as usize + 4;
    let mut code_lengths = [0u8; 19];
    for slot in ORDER.iter().take(code_length_count) {
        code_lengths[*slot] = reader.bits(3)? as u8;
    }
    let code_length_table = build_huffman(&code_lengths)?;

    let mut lengths = vec![0u8; literal_count + distance_count];
    let mut position = 0;
    while position < lengths.len() {
        let symbol = decode_symbol(reader, &code_length_table)?;
        match symbol {
            0..=15 => {
                lengths[position] = symbol as u8;
                position += 1;
            }
            16 => {
                if position == 0 {
                    return Err("DEFLATE repeats a code length before any exists".to_owned());
                }
                let previous = lengths[position - 1];
                let repeat = reader.bits(2)? as usize + 3;
                for _ in 0..repeat {
                    if position >= lengths.len() {
                        return Err("DEFLATE code length repeat overflows".to_owned());
                    }
                    lengths[position] = previous;
                    position += 1;
                }
            }
            17 | 18 => {
                let repeat = if symbol == 17 {
                    reader.bits(3)? as usize + 3
                } else {
                    reader.bits(7)? as usize + 11
                };
                position = position
                    .checked_add(repeat)
                    .filter(|end| *end <= lengths.len())
                    .ok_or_else(|| "DEFLATE code length run overflows".to_owned())?;
            }
            _ => return Err("invalid DEFLATE code length symbol".to_owned()),
        }
    }
    let literals = build_huffman(&lengths[..literal_count])?;
    let distances = build_huffman(&lengths[literal_count..])?;
    Ok((literals, distances))
}

fn inflate_block(
    reader: &mut BitReader<'_>,
    output: &mut Vec<u8>,
    literals: &Huffman,
    distances: &Huffman,
) -> Result<(), String> {
    loop {
        let symbol = decode_symbol(reader, literals)?;
        match symbol {
            0..=255 => output.push(symbol as u8),
            256 => return Ok(()),
            257..=285 => {
                let slot = usize::from(symbol - 257);
                let length =
                    usize::from(LENGTH_BASE[slot]) + reader.bits(LENGTH_EXTRA[slot])? as usize;
                let distance_symbol = usize::from(decode_symbol(reader, distances)?);
                if distance_symbol >= DISTANCE_BASE.len() {
                    return Err("invalid DEFLATE distance symbol".to_owned());
                }
                let distance = usize::from(DISTANCE_BASE[distance_symbol])
                    + reader.bits(DISTANCE_EXTRA[distance_symbol])? as usize;
                if distance > output.len() {
                    return Err("DEFLATE back-reference reaches before the stream".to_owned());
                }
                let start = output.len() - distance;
                for offset in 0..length {
                    let byte = output[start + offset];
                    output.push(byte);
                }
            }
            _ => return Err("invalid DEFLATE literal symbol".to_owned()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{decode_indexed_png, image_to_chr, zlib_decompress};

    #[test]
    fn inflates_stored_fixed_and_dynamic_blocks() {
        // Python: zlib.compress(b"hello hello hello", 0) - stored blocks.
        let stored = [
            0x78, 0x01, 0x01, 0x11, 0x00, 0xee, 0xff, 0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x68,
            0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x3a, 0x2e, 0x06, 0x7d,
        ];
        assert_eq!(
            zlib_decompress(&stored).expect("stored blocks"),
            b"hello hello hello"
        );

        // Python: zlib.compress(b"hello hello hello", 9) - fixed Huffman
        // with a back-reference.
        let fixed = [
            0x78, 0xda, 0xcb, 0x48, 0xcd, 0xc9, 0xc9, 0x57, 0xc8, 0x40, 0x90, 0x00, 0x3a, 0x2e,
            0x06, 0x7d,
        ];
        assert_eq!(
            zlib_decompress(&fixed).expect("fixed Huffman"),
            b"hello hello hello"
        );

        // Python: zlib.compress((b'a'*7 + b'b'*3 + bytes(range(200,256)))*50, 9)
        // - a dynamic Huffman table over a skewed alphabet.
        let dynamic = [
            0x78, 0xda, 0xed, 0xcc, 0xd7, 0x11, 0x82, 0x40, 0x00, 0x05, 0xc0, 0x5a, 0xef, 0xaa,
            0x25, 0x4b, 0x06, 0x01, 0xc9, 0x19, 0x54, 0x44, 0x31, 0x11, 0x67, 0xa8, 0x82, 0x8f,
            0xb7, 0x05, 0x2c, 0x21, 0x3b, 0x4a, 0x29, 0xc3, 0x72, 0xbc, 0x20, 0x4a, 0x27, 0x59,
            0x51, 0x35, 0xdd, 0x30, 0x2d, 0xfb, 0xec, 0xb8, 0xde, 0xc5, 0x0f, 0xc2, 0x28, 0x4e,
            0xd2, 0x2c, 0x2f, 0xca, 0xaa, 0x6e, 0xda, 0xeb, 0xed, 0xde, 0x3d, 0xfa, 0xe7, 0x6b,
            0x78, 0x7f, 0xbe, 0xbf, 0xff, 0x38, 0xcd, 0xcb, 0x4a, 0x30, 0x60, 0xc0, 0x80, 0x01,
            0x03, 0x06, 0x0c, 0x18, 0x30, 0x60, 0xc0, 0x80, 0xe1, 0x30, 0xc3, 0x06, 0xda, 0x78,
            0x76, 0xe9,
        ];
        let mut expected = Vec::new();
        for _ in 0..50 {
            expected.extend_from_slice(&[b'a'; 7]);
            expected.extend_from_slice(&[b'b'; 3]);
            expected.extend(200..=255u8);
        }
        assert_eq!(
            zlib_decompress(&dynamic).expect("dynamic Huffman"),
            expected
        );
    }

    #[test]
    fn rejects_corrupt_zlib_checksums() {
        let mut stream = vec![
            0x78, 0xda, 0xcb, 0x48, 0xcd, 0xc9, 0xc9, 0x57, 0xc8, 0x40, 0x90, 0x00, 0x3a, 0x2e,
            0x06, 0x7d,
        ];
        let last = stream.len() - 1;
        stream[last] ^= 0xff;
        assert!(
            zlib_decompress(&stream)
                .expect_err("corrupt checksum")
                .contains("Adler-32")
        );
    }

    #[test]
    fn converts_indices_to_planar_tiles() {
        // 8x8 image: row y uses color y % 4.
        let indices = (0..64).map(|pixel| (pixel / 8 % 4) as u8).collect();
        let image = super::IndexedImage {
            width: 8,
            height: 8,
            indices,
        };
        let chr = image_to_chr(&image).expect("tile conversion");
        assert_eq!(chr.len(), 16);
        // Plane 0 holds the low color bit per row, plane 1 the high bit.
        assert_eq!(&chr[..8], &[0x00, 0xff, 0x00, 0xff, 0x00, 0xff, 0x00, 0xff]);
        assert_eq!(&chr[8..], &[0x00, 0x00, 0xff, 0xff, 0x00, 0x00, 0xff, 0xff]);
    }

    #[test]
    fn rejects_out_of_range_palette_indices_and_bad_dimensions() {
        let image = super::IndexedImage {
            width: 8,
            height: 8,
            indices: vec![4; 64],
        };
        assert!(
            image_to_chr(&image)
                .expect_err("palette index 4")
                .contains("indices 0-3")
        );
        let narrow = super::IndexedImage {
            width: 10,
            height: 8,
            indices: vec![0; 80],
        };
        assert!(
            image_to_chr(&narrow)
                .expect_err("width 10")
                .contains("multiples of 8")
        );
    }

    #[test]
    fn rejects_non_png_and_truncated_input() {
        assert!(decode_indexed_png(b"not a png").is_err());
        let truncated = [137, 80, 78, 71, 13, 10, 26, 10, 0, 0, 0, 13];
        assert!(decode_indexed_png(&truncated).is_err());
    }
}
