//! Dependency-free WAV encoder for captured APU PCM.
//!
//! [`encode_wav`] turns a slice of signed 16-bit mono samples (such as the
//! output of [`Machine::drain_audio_samples`]) into a canonical little-endian
//! RIFF/WAVE file. Everything here uses only the standard library.
//!
//! [`Machine::drain_audio_samples`]: crate::Machine::drain_audio_samples

/// Bytes in a canonical 16-bit PCM WAV header before the sample data.
const WAV_HEADER_LEN: usize = 44;

/// Encodes signed 16-bit mono samples as a canonical PCM WAV file.
///
/// The result is a standard little-endian RIFF/WAVE stream: a `RIFF` chunk
/// wrapping a `WAVE` form, a 16-byte `fmt ` chunk describing linear PCM
/// (`AudioFormat = 1`) with one channel and 16 bits per sample, and a `data`
/// chunk carrying the samples. The total length is always
/// `44 + samples.len() * 2` bytes.
#[must_use]
pub fn encode_wav(samples: &[i16], sample_rate: u32) -> Vec<u8> {
    const BITS_PER_SAMPLE: u16 = 16;
    const CHANNELS: u16 = 1;
    const BLOCK_ALIGN: u16 = CHANNELS * (BITS_PER_SAMPLE / 8);

    let data_len = samples.len() * usize::from(BLOCK_ALIGN);
    let byte_rate = sample_rate * u32::from(BLOCK_ALIGN);

    let mut out = Vec::with_capacity(WAV_HEADER_LEN + data_len);

    // RIFF chunk descriptor. The size covers everything after this field: the
    // `WAVE` tag, the `fmt ` chunk (8 + 16 bytes), and the `data` chunk header
    // (8 bytes) plus payload.
    out.extend_from_slice(b"RIFF");
    out.extend_from_slice(&((WAV_HEADER_LEN - 8 + data_len) as u32).to_le_bytes());
    out.extend_from_slice(b"WAVE");

    // `fmt ` sub-chunk: 16-byte body for linear PCM.
    out.extend_from_slice(b"fmt ");
    out.extend_from_slice(&16u32.to_le_bytes()); // sub-chunk size
    out.extend_from_slice(&1u16.to_le_bytes()); // AudioFormat = PCM
    out.extend_from_slice(&CHANNELS.to_le_bytes());
    out.extend_from_slice(&sample_rate.to_le_bytes());
    out.extend_from_slice(&byte_rate.to_le_bytes());
    out.extend_from_slice(&BLOCK_ALIGN.to_le_bytes());
    out.extend_from_slice(&BITS_PER_SAMPLE.to_le_bytes());

    // `data` sub-chunk: little-endian samples.
    out.extend_from_slice(b"data");
    out.extend_from_slice(&(data_len as u32).to_le_bytes());
    for &sample in samples {
        out.extend_from_slice(&sample.to_le_bytes());
    }

    out
}

#[cfg(test)]
mod tests {
    use super::{WAV_HEADER_LEN, encode_wav};

    #[test]
    fn header_declares_canonical_pcm_mono_layout() {
        let wav = encode_wav(&[0, 0], 44_100);

        assert_eq!(&wav[0..4], b"RIFF");
        // RIFF size covers everything after the first 8 bytes.
        assert_eq!(&wav[4..8], &((wav.len() - 8) as u32).to_le_bytes());
        assert_eq!(&wav[8..12], b"WAVE");

        assert_eq!(&wav[12..16], b"fmt ");
        assert_eq!(&wav[16..20], &16u32.to_le_bytes()); // PCM fmt body length
        assert_eq!(&wav[20..22], &1u16.to_le_bytes()); // AudioFormat = PCM
        assert_eq!(&wav[22..24], &1u16.to_le_bytes()); // channels
        assert_eq!(&wav[24..28], &44_100u32.to_le_bytes()); // sample rate
        assert_eq!(&wav[28..32], &88_200u32.to_le_bytes()); // byte rate
        assert_eq!(&wav[32..34], &2u16.to_le_bytes()); // block align
        assert_eq!(&wav[34..36], &16u16.to_le_bytes()); // bits per sample
    }

    #[test]
    fn data_chunk_size_and_total_length_are_exact() {
        let wav = encode_wav(&[0x0102, -1], 44_100);

        assert_eq!(&wav[36..40], b"data");
        // Two 16-bit samples occupy four bytes.
        assert_eq!(&wav[40..44], &4u32.to_le_bytes());
        assert_eq!(wav.len(), WAV_HEADER_LEN + 4);
        assert_eq!(wav.len(), 48);

        // Samples are stored little-endian in emission order.
        assert_eq!(&wav[44..46], &0x0102i16.to_le_bytes());
        assert_eq!(&wav[46..48], &(-1i16).to_le_bytes());
    }

    #[test]
    fn empty_input_produces_a_bare_header() {
        let wav = encode_wav(&[], 1_789_773);
        assert_eq!(wav.len(), WAV_HEADER_LEN);
        assert_eq!(&wav[40..44], &0u32.to_le_bytes()); // data size
        assert_eq!(&wav[24..28], &1_789_773u32.to_le_bytes());
    }
}
