//! Safe iNES and NES 2.0 ROM construction, inspection, and mapper models.

use std::error::Error;
use std::fmt;

const HEADER_LEN: usize = 16;
const TRAINER_LEN: usize = 512;
const PRG_UNIT: usize = 16 * 1024;
const CHR_UNIT: usize = 8 * 1024;

/// ROM header encoding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Format {
    /// Original iNES header.
    Ines,
    /// NES 2.0 header.
    Nes2,
}

/// Nametable mirroring metadata.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Mirroring {
    /// Horizontal arrangement.
    Horizontal,
    /// Vertical arrangement.
    Vertical,
    /// Cartridge-controlled four-screen arrangement.
    FourScreen,
}

/// Console timing metadata.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Region {
    /// NTSC timing.
    Ntsc,
    /// PAL timing.
    Pal,
    /// Compatible with both television standards.
    MultiRegion,
    /// Dendy timing.
    Dendy,
}

/// Validated cartridge metadata.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Metadata {
    /// Header encoding.
    pub format: Format,
    /// Mapper number.
    pub mapper: u16,
    /// NES 2.0 submapper number.
    pub submapper: u8,
    /// Nametable arrangement.
    pub mirroring: Mirroring,
    /// Whether persistent RAM is battery backed.
    pub battery: bool,
    /// Timing metadata.
    pub region: Region,
    /// PRG-ROM byte length.
    pub prg_rom_len: usize,
    /// CHR-ROM byte length; zero selects CHR RAM.
    pub chr_rom_len: usize,
}

/// Parsed ROM with owned cartridge bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Rom {
    /// Validated header metadata.
    pub metadata: Metadata,
    /// Optional 512-byte trainer.
    pub trainer: Option<Vec<u8>>,
    /// PRG-ROM contents.
    pub prg_rom: Vec<u8>,
    /// CHR-ROM contents; empty when the cartridge declares CHR RAM.
    pub chr_rom: Vec<u8>,
}

/// ROM parsing or construction failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RomError {
    message: String,
}

impl RomError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for RomError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl Error for RomError {}

/// Parses an untrusted iNES or NES 2.0 image without panicking.
///
/// # Errors
///
/// Returns a descriptive failure for invalid headers, impossible sizes, or
/// truncated cartridge data.
pub fn parse(bytes: &[u8]) -> Result<Rom, RomError> {
    let header = bytes
        .get(..HEADER_LEN)
        .ok_or_else(|| RomError::new("ROM is shorter than the 16-byte header"))?;
    if header[..4] != *b"NES\x1a" {
        return Err(RomError::new("ROM does not begin with the NES magic bytes"));
    }
    let format = if header[7] & 0x0c == 0x08 {
        Format::Nes2
    } else {
        Format::Ines
    };
    let mapper = u16::from(header[6] >> 4)
        | u16::from(header[7] & 0xf0)
        | if format == Format::Nes2 {
            u16::from(header[8] & 0x0f) << 8
        } else {
            0
        };
    let submapper = if format == Format::Nes2 {
        header[8] >> 4
    } else {
        0
    };
    let prg_rom_len = decode_size(header[4], header[9] & 0x0f, PRG_UNIT, format)?;
    let chr_rom_len = decode_size(header[5], header[9] >> 4, CHR_UNIT, format)?;
    let trainer_present = header[6] & 0x04 != 0;
    let mirroring = if header[6] & 0x08 != 0 {
        Mirroring::FourScreen
    } else if header[6] & 0x01 != 0 {
        Mirroring::Vertical
    } else {
        Mirroring::Horizontal
    };
    let region = match format {
        Format::Nes2 => match header[12] & 0x03 {
            0 => Region::Ntsc,
            1 => Region::Pal,
            2 => Region::MultiRegion,
            _ => Region::Dendy,
        },
        Format::Ines if header[9] & 1 != 0 => Region::Pal,
        Format::Ines => Region::Ntsc,
    };
    let trainer_start = HEADER_LEN;
    let prg_start = trainer_start + if trainer_present { TRAINER_LEN } else { 0 };
    let chr_start = prg_start
        .checked_add(prg_rom_len)
        .ok_or_else(|| RomError::new("PRG-ROM offset overflows the host address space"))?;
    let end = chr_start
        .checked_add(chr_rom_len)
        .ok_or_else(|| RomError::new("CHR-ROM offset overflows the host address space"))?;
    if bytes.len() < end {
        return Err(RomError::new(format!(
            "ROM declares {end} bytes but contains only {}",
            bytes.len()
        )));
    }
    let trainer = trainer_present.then(|| bytes[trainer_start..prg_start].to_vec());
    Ok(Rom {
        metadata: Metadata {
            format,
            mapper,
            submapper,
            mirroring,
            battery: header[6] & 0x02 != 0,
            region,
            prg_rom_len,
            chr_rom_len,
        },
        trainer,
        prg_rom: bytes[prg_start..chr_start].to_vec(),
        chr_rom: bytes[chr_start..end].to_vec(),
    })
}

/// Builds a deterministic ROM and validates its mapper layout.
///
/// # Errors
///
/// Returns a failure for unsupported size encodings, invalid trainer length,
/// or a layout incompatible with Mapper 0, 2, or 3.
pub fn build(rom: &Rom) -> Result<Vec<u8>, RomError> {
    validate(rom)?;
    let prg_units = rom.prg_rom.len() / PRG_UNIT;
    let chr_units = rom.chr_rom.len() / CHR_UNIT;
    let mut header = [0_u8; HEADER_LEN];
    header[..4].copy_from_slice(b"NES\x1a");
    header[4] = u8::try_from(prg_units & 0xff).expect("masked PRG size fits u8");
    header[5] = u8::try_from(chr_units & 0xff).expect("masked CHR size fits u8");
    header[6] = u8::try_from((rom.metadata.mapper & 0x0f) << 4).expect("mapper low nibble fits u8");
    header[6] |= match rom.metadata.mirroring {
        Mirroring::Horizontal => 0,
        Mirroring::Vertical => 1,
        Mirroring::FourScreen => 8,
    };
    if rom.metadata.battery {
        header[6] |= 2;
    }
    if rom.trainer.is_some() {
        header[6] |= 4;
    }
    header[7] = u8::try_from(rom.metadata.mapper & 0xf0).expect("mapper middle bits fit u8");
    match rom.metadata.format {
        Format::Ines => {
            if rom.metadata.mapper > 0xff || rom.metadata.submapper != 0 {
                return Err(RomError::new("iNES cannot encode this mapper or submapper"));
            }
            header[9] = u8::from(rom.metadata.region == Region::Pal);
        }
        Format::Nes2 => {
            header[7] |= 0x08;
            header[8] = (rom.metadata.submapper << 4)
                | u8::try_from((rom.metadata.mapper >> 8) & 0x0f)
                    .expect("mapper high nibble fits u8");
            header[9] = u8::try_from((prg_units >> 8) | ((chr_units >> 8) << 4))
                .map_err(|_| RomError::new("ROM size requires NES 2.0 exponent encoding"))?;
            header[12] = match rom.metadata.region {
                Region::Ntsc => 0,
                Region::Pal => 1,
                Region::MultiRegion => 2,
                Region::Dendy => 3,
            };
        }
    }
    let capacity = HEADER_LEN
        + rom.trainer.as_ref().map_or(0, Vec::len)
        + rom.prg_rom.len()
        + rom.chr_rom.len();
    let mut bytes = Vec::with_capacity(capacity);
    bytes.extend_from_slice(&header);
    if let Some(trainer) = &rom.trainer {
        bytes.extend_from_slice(trainer);
    }
    bytes.extend_from_slice(&rom.prg_rom);
    bytes.extend_from_slice(&rom.chr_rom);
    Ok(bytes)
}

fn validate(rom: &Rom) -> Result<(), RomError> {
    if rom.prg_rom.is_empty() || rom.prg_rom.len() % PRG_UNIT != 0 {
        return Err(RomError::new(
            "PRG-ROM must be a nonzero multiple of 16 KiB",
        ));
    }
    if rom.chr_rom.len() % CHR_UNIT != 0 {
        return Err(RomError::new("CHR-ROM must be a multiple of 8 KiB"));
    }
    if rom.metadata.prg_rom_len != rom.prg_rom.len()
        || rom.metadata.chr_rom_len != rom.chr_rom.len()
    {
        return Err(RomError::new(
            "header size metadata does not match cartridge contents",
        ));
    }
    if rom
        .trainer
        .as_ref()
        .is_some_and(|data| data.len() != TRAINER_LEN)
    {
        return Err(RomError::new("trainer must contain exactly 512 bytes"));
    }
    validate_layout(rom.metadata.mapper, rom.prg_rom.len(), rom.chr_rom.len())
}

fn validate_layout(mapper: u16, prg_len: usize, chr_len: usize) -> Result<(), RomError> {
    if prg_len == 0 || prg_len % PRG_UNIT != 0 || chr_len % CHR_UNIT != 0 {
        return Err(RomError::new("mapper banks are not aligned"));
    }
    match mapper {
        0 if (prg_len == PRG_UNIT || prg_len == PRG_UNIT * 2)
            && matches!(chr_len, 0 | CHR_UNIT) => {}
        2 if prg_len >= PRG_UNIT * 2 && matches!(chr_len, 0 | CHR_UNIT) => {}
        3 if (prg_len == PRG_UNIT || prg_len == PRG_UNIT * 2) && chr_len >= CHR_UNIT => {}
        0 => {
            return Err(RomError::new(
                "Mapper 0 requires 16/32 KiB PRG and 0/8 KiB CHR",
            ));
        }
        2 => {
            return Err(RomError::new(
                "Mapper 2 requires at least 32 KiB PRG and 0/8 KiB CHR",
            ));
        }
        3 => {
            return Err(RomError::new(
                "Mapper 3 requires 16/32 KiB PRG and at least 8 KiB CHR",
            ));
        }
        other => {
            return Err(RomError::new(format!(
                "Mapper {other} has no mapping model"
            )));
        }
    }
    Ok(())
}

fn decode_size(low: u8, high: u8, unit: usize, format: Format) -> Result<usize, RomError> {
    if format == Format::Nes2 && high == 0x0f {
        let exponent = low >> 2;
        let multiplier = usize::from((low & 0x03) * 2 + 1);
        return 1_usize
            .checked_shl(u32::from(exponent))
            .and_then(|value| value.checked_mul(multiplier))
            .ok_or_else(|| {
                RomError::new("NES 2.0 exponent size overflows the host address space")
            });
    }
    let units = usize::from(low)
        | if format == Format::Nes2 {
            usize::from(high) << 8
        } else {
            0
        };
    units
        .checked_mul(unit)
        .ok_or_else(|| RomError::new("ROM size overflows the host address space"))
}

/// CPU address distinct from a ROM file offset.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CpuAddress(pub u16);

/// PPU address distinct from a CHR-ROM offset.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PpuAddress(pub u16);

/// Physical PRG-ROM byte offset.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PrgOffset(pub usize);

/// Physical CHR-ROM byte offset.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChrOffset(pub usize);

/// Mutable mapper register state after reset.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MapperState {
    /// Selected 16 KiB PRG bank for Mapper 2.
    pub prg_bank: u8,
    /// Selected 8 KiB CHR bank for Mapper 3.
    pub chr_bank: u8,
}

/// Supported mapping model shared by tools.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Mapper {
    number: u16,
    prg_len: usize,
    chr_len: usize,
}

impl Mapper {
    /// Creates a validated Mapper 0, 2, or 3 model.
    ///
    /// # Errors
    ///
    /// Returns a failure when no safe model exists or the bank layout is invalid.
    pub fn new(number: u16, prg_len: usize, chr_len: usize) -> Result<Self, RomError> {
        validate_layout(number, prg_len, chr_len)?;
        Ok(Self {
            number,
            prg_len,
            chr_len,
        })
    }

    /// Maps a CPU cartridge address to a physical PRG byte.
    #[must_use]
    pub fn map_cpu(self, address: CpuAddress, state: MapperState) -> Option<PrgOffset> {
        let address = usize::from(address.0);
        if address < 0x8000 {
            return None;
        }
        match self.number {
            0 | 3 => Some(PrgOffset((address - 0x8000) % self.prg_len)),
            2 if address < 0xc000 => {
                let banks = self.prg_len / PRG_UNIT;
                let bank = usize::from(state.prg_bank) % banks.saturating_sub(1).max(1);
                Some(PrgOffset(bank * PRG_UNIT + (address - 0x8000)))
            }
            2 => Some(PrgOffset(self.prg_len - PRG_UNIT + (address - 0xc000))),
            _ => None,
        }
    }

    /// Maps a PPU pattern-table address to a physical CHR byte.
    #[must_use]
    pub fn map_ppu(self, address: PpuAddress, state: MapperState) -> Option<ChrOffset> {
        let address = usize::from(address.0);
        if address >= 0x2000 || self.chr_len == 0 {
            return None;
        }
        match self.number {
            0 | 2 => Some(ChrOffset(address)),
            3 => {
                let banks = self.chr_len / CHR_UNIT;
                let bank = usize::from(state.chr_bank) % banks;
                Some(ChrOffset(bank * CHR_UNIT + address))
            }
            _ => None,
        }
    }

    /// Applies a CPU mapper-register write.
    pub fn cpu_write(self, address: CpuAddress, value: u8, state: &mut MapperState) {
        if address.0 < 0x8000 {
            return;
        }
        match self.number {
            2 => state.prg_bank = value,
            3 => state.chr_bank = value,
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        CpuAddress, Format, Mapper, MapperState, Metadata, Mirroring, Region, Rom, build, parse,
    };

    fn nrom(format: Format, prg_len: usize) -> Rom {
        Rom {
            metadata: Metadata {
                format,
                mapper: 0,
                submapper: 0,
                mirroring: Mirroring::Vertical,
                battery: false,
                region: Region::Ntsc,
                prg_rom_len: prg_len,
                chr_rom_len: 0,
            },
            trainer: None,
            prg_rom: vec![0xea; prg_len],
            chr_rom: Vec::new(),
        }
    }

    #[test]
    fn round_trips_nes2_nrom() {
        let rom = nrom(Format::Nes2, 32 * 1024);
        let bytes = build(&rom).expect("ROM build");
        assert_eq!(parse(&bytes).expect("ROM parse"), rom);
    }

    #[test]
    fn rejects_truncated_declared_banks() {
        let mut bytes = build(&nrom(Format::Ines, 16 * 1024)).expect("ROM build");
        bytes.truncate(100);
        assert!(parse(&bytes).is_err());
    }

    #[test]
    fn uxrom_maps_last_bank_fixed() {
        let mapper = Mapper::new(2, 64 * 1024, 0).expect("Mapper 2");
        let state = MapperState {
            prg_bank: 1,
            chr_bank: 0,
        };
        assert_eq!(
            mapper.map_cpu(CpuAddress(0x8000), state).unwrap().0,
            16 * 1024
        );
        assert_eq!(
            mapper.map_cpu(CpuAddress(0xc000), state).unwrap().0,
            48 * 1024
        );
    }
}
