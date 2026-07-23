//! NES-aware linker for relocatable NOBJ inputs.

use std::collections::{BTreeMap, HashMap};
use std::error::Error;
use std::fmt;

use nesc_object::{Binding, Object, RelocationKind, SectionId, SectionPlacement, SymbolId};
use nesc_rom::{Format, Metadata, Mirroring, Region, Rom};

/// NES cartridge link settings.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LinkConfig {
    /// Cartridge mapper number.
    pub mapper: u16,
    /// NES 2.0 submapper number.
    pub submapper: u8,
    /// Header encoding.
    pub format: Format,
    /// PRG-ROM capacity in bytes.
    pub prg_rom_len: usize,
    /// CHR-ROM capacity in bytes; zero selects CHR RAM.
    pub chr_rom_len: usize,
    /// Nametable arrangement.
    pub mirroring: Mirroring,
    /// Battery-backed RAM flag.
    pub battery: bool,
    /// Timing metadata.
    pub region: Region,
}

/// Linked cartridge and reports.
#[derive(Clone, Debug)]
pub struct LinkedImage {
    /// Complete iNES or NES 2.0 file.
    pub rom: Vec<u8>,
    /// Linked PRG-ROM before the container header.
    pub prg_rom: Vec<u8>,
    /// Global symbol addresses.
    pub symbols: BTreeMap<String, u16>,
    /// Physical PRG-ROM bank containing each global symbol.
    pub symbol_banks: BTreeMap<String, u16>,
    /// Human-readable placement report.
    pub map: String,
}

/// Exact cartridge recovery input after assembly reconstruction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecoveryLinkInput<'a> {
    /// Original 16-byte container header.
    pub header: &'a [u8],
    /// Optional original trainer.
    pub trainer: Option<&'a [u8]>,
    /// PRG-ROM emitted by `nesc-asm`.
    pub prg_rom: &'a [u8],
    /// Original CHR-ROM.
    pub chr_rom: &'a [u8],
    /// Original bytes after declared cartridge regions.
    pub trailing: &'a [u8],
}

/// Exact relink result for a recovered cartridge project.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveredImage {
    /// Complete reconstructed container.
    pub rom: Vec<u8>,
    /// Reparsed cartridge metadata and regions.
    pub cartridge: Rom,
}

/// Link or relocation failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LinkError(pub String);

impl fmt::Display for LinkError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl Error for LinkError {}

/// Links objects into a supported NES cartridge.
///
/// Runtime/startup objects must precede generated program objects so reset
/// code remains at the beginning of PRG-ROM.
///
/// # Errors
///
/// Returns deterministic failures for invalid objects, duplicate or missing
/// symbols, overflowing sections, branch range, or invalid vectors.
pub fn link(objects: &[Object], config: LinkConfig) -> Result<LinkedImage, Vec<LinkError>> {
    match (config.mapper, config.submapper) {
        (0 | 3, 0) => link_fixed_prg(objects, config),
        (2, 0) => link_uxrom(objects, config),
        (0, submapper) | (2, submapper) | (3, submapper) => Err(vec![LinkError(format!(
            "Mapper {} requires submapper 0, not {submapper}",
            config.mapper
        ))]),
        (mapper, _) => Err(vec![LinkError(format!(
            "Mapper {mapper} is not supported by the compiler linker"
        ))]),
    }
}

fn link_fixed_prg(objects: &[Object], config: LinkConfig) -> Result<LinkedImage, Vec<LinkError>> {
    if !matches!(config.prg_rom_len, 0x4000 | 0x8000) {
        return Err(vec![LinkError(format!(
            "Mapper {} PRG-ROM must be 16 or 32 KiB",
            config.mapper
        ))]);
    }
    match config.mapper {
        0 if !matches!(config.chr_rom_len, 0 | 0x2000) => {
            return Err(vec![LinkError(
                "Mapper 0 CHR-ROM must be 0 or 8 KiB".to_owned(),
            )]);
        }
        3 if !(0x2000..=0x2000 * 256).contains(&config.chr_rom_len)
            || config.chr_rom_len % 0x2000 != 0 =>
        {
            return Err(vec![LinkError(
                "Mapper 3 CHR-ROM must contain 1 to 256 complete 8 KiB banks".to_owned(),
            )]);
        }
        _ => {}
    }
    let base = if config.prg_rom_len == 0x4000 {
        0xc000_u16
    } else {
        0x8000_u16
    };
    let mut errors = Vec::new();
    for object in objects {
        if let Err(object_errors) = object.validate() {
            errors.extend(
                object_errors
                    .into_iter()
                    .map(|error| LinkError(error.to_string())),
            );
        }
    }
    for object in objects {
        for section in &object.sections {
            if let SectionPlacement::Bank(bank) = section.placement {
                errors.push(LinkError(format!(
                    "section `{}` requests switchable bank {bank}, but Mapper {} has no switchable PRG-ROM window",
                    section.name, config.mapper
                )));
            }
        }
    }
    if !errors.is_empty() {
        return Err(errors);
    }

    let mut prg = vec![0xff; config.prg_rom_len];
    let mut placements = HashMap::<(usize, SectionId), usize>::new();
    let mut cursor = 0_usize;
    let vector_start = config.prg_rom_len - 6;
    let mut map = format!(
        "Mapper {} bank layout\nfixed PRG-ROM: ${base:04X}-$FFFF\n",
        config.mapper
    );
    if config.mapper == 3 {
        let chr_banks = config.chr_rom_len / 0x2000;
        map.push_str(&format!(
            "switchable CHR-ROM banks: 0-{} at PPU $0000-$1FFF\n",
            chr_banks - 1
        ));
    }
    for (object_index, object) in objects.iter().enumerate() {
        for section in &object.sections {
            cursor = align(cursor, usize::from(section.alignment));
            let end = cursor.saturating_add(section.bytes.len());
            if end > vector_start {
                errors.push(LinkError(format!(
                    "section `{}` overlaps the interrupt vectors",
                    section.name
                )));
                continue;
            }
            prg[cursor..end].copy_from_slice(&section.bytes);
            placements.insert((object_index, section.id), cursor);
            let address = u32::from(base) + cursor as u32;
            map.push_str(&format!(
                "${address:04X}-${:04X} {}\n",
                address + section.bytes.len().saturating_sub(1) as u32,
                section.name
            ));
            cursor = end;
        }
    }
    if !errors.is_empty() {
        return Err(errors);
    }

    let mut global_definitions = BTreeMap::<String, (usize, SymbolId)>::new();
    let mut symbol_addresses = HashMap::<(usize, SymbolId), u16>::new();
    for (object_index, object) in objects.iter().enumerate() {
        for symbol in &object.symbols {
            let Some(section) = symbol.section else {
                continue;
            };
            let placement = placements[&(object_index, section)];
            let address_u32 = u32::from(base) + placement as u32 + symbol.offset;
            let address = match u16::try_from(address_u32) {
                Ok(address) => address,
                Err(_) => {
                    errors.push(LinkError(format!(
                        "symbol `{}` exceeds CPU address space",
                        symbol.name
                    )));
                    continue;
                }
            };
            symbol_addresses.insert((object_index, symbol.id), address);
            if symbol.binding == Binding::Global
                && global_definitions
                    .insert(symbol.name.clone(), (object_index, symbol.id))
                    .is_some()
            {
                errors.push(LinkError(format!(
                    "duplicate global symbol `{}`",
                    symbol.name
                )));
            }
        }
    }
    if !errors.is_empty() {
        return Err(errors);
    }

    for (object_index, object) in objects.iter().enumerate() {
        for relocation in &object.relocations {
            let section_placement = placements[&(object_index, relocation.section)];
            let patch = section_placement + relocation.offset as usize;
            let symbol = &object.symbols[relocation.symbol.0 as usize];
            let target = if symbol.section.is_some() {
                symbol_addresses[&(object_index, symbol.id)]
            } else {
                let Some((definition_object, definition_symbol)) =
                    global_definitions.get(&symbol.name).copied()
                else {
                    errors.push(LinkError(format!(
                        "undefined global symbol `{}`",
                        symbol.name
                    )));
                    continue;
                };
                symbol_addresses[&(definition_object, definition_symbol)]
            };
            let target = i32::from(target) + relocation.addend;
            match relocation.kind {
                RelocationKind::Absolute16 => match u16::try_from(target) {
                    Ok(target) => {
                        prg[patch] = target as u8;
                        prg[patch + 1] = (target >> 8) as u8;
                    }
                    Err(_) => errors.push(LinkError(format!(
                        "absolute relocation to `{}` exceeds 16 bits",
                        symbol.name
                    ))),
                },
                RelocationKind::AbsoluteLow8 | RelocationKind::AbsoluteHigh8 => {
                    match u16::try_from(target) {
                        Ok(target) => {
                            prg[patch] = if relocation.kind == RelocationKind::AbsoluteLow8 {
                                target as u8
                            } else {
                                (target >> 8) as u8
                            };
                        }
                        Err(_) => errors.push(LinkError(format!(
                            "absolute relocation to `{}` exceeds 16 bits",
                            symbol.name
                        ))),
                    }
                }
                RelocationKind::Relative8 => {
                    let operand_address = i32::from(base) + patch as i32;
                    let displacement = target - (operand_address + 1);
                    match i8::try_from(displacement) {
                        Ok(displacement) => prg[patch] = displacement as u8,
                        Err(_) => errors.push(LinkError(format!(
                            "branch to `{}` is outside the signed 8-bit range",
                            symbol.name
                        ))),
                    }
                }
            }
        }
    }
    if !errors.is_empty() {
        return Err(errors);
    }

    for (index, name) in ["__nesc_nmi", "__nesc_reset", "__nesc_irq"]
        .iter()
        .enumerate()
    {
        let Some((object_index, symbol)) = global_definitions.get(*name).copied() else {
            errors.push(LinkError(format!(
                "required vector symbol `{name}` is undefined"
            )));
            continue;
        };
        let address = symbol_addresses[&(object_index, symbol)];
        let offset = vector_start + index * 2;
        prg[offset] = address as u8;
        prg[offset + 1] = (address >> 8) as u8;
    }
    if !errors.is_empty() {
        return Err(errors);
    }

    let symbols = global_definitions
        .iter()
        .map(|(name, (object, symbol))| (name.clone(), symbol_addresses[&(*object, *symbol)]))
        .collect::<BTreeMap<_, _>>();
    let symbol_banks = symbols
        .keys()
        .map(|name| (name.clone(), 0))
        .collect::<BTreeMap<_, _>>();
    let cartridge = Rom {
        metadata: Metadata {
            format: config.format,
            mapper: config.mapper,
            submapper: config.submapper,
            mirroring: config.mirroring,
            battery: config.battery,
            region: config.region,
            prg_rom_len: prg.len(),
            chr_rom_len: config.chr_rom_len,
        },
        trainer: None,
        prg_rom: prg.clone(),
        chr_rom: vec![0; config.chr_rom_len],
    };
    let rom = nesc_rom::build(&cartridge).map_err(|error| vec![LinkError(error.to_string())])?;
    nesc_rom::parse(&rom).map_err(|error| vec![LinkError(error.to_string())])?;
    Ok(LinkedImage {
        rom,
        prg_rom: prg,
        symbols,
        symbol_banks,
        map,
    })
}

#[derive(Clone, Copy, Debug)]
struct UxromPlacement {
    physical_offset: usize,
    cpu_address: u16,
    bank: u16,
}

fn link_uxrom(objects: &[Object], config: LinkConfig) -> Result<LinkedImage, Vec<LinkError>> {
    if config.prg_rom_len < 0x8000 || config.prg_rom_len % 0x4000 != 0 {
        return Err(vec![LinkError(
            "Mapper 2 PRG-ROM must contain at least two complete 16 KiB banks".to_owned(),
        )]);
    }
    if !matches!(config.chr_rom_len, 0 | 0x2000) {
        return Err(vec![LinkError(
            "Mapper 2 CHR-ROM must be 0 or 8 KiB".to_owned(),
        )]);
    }
    let bank_count = config.prg_rom_len / 0x4000;
    if bank_count > 256 {
        return Err(vec![LinkError(
            "Mapper 2 supports at most 256 PRG-ROM banks".to_owned(),
        )]);
    }
    let fixed_bank = u16::try_from(bank_count - 1).expect("bank count is bounded");
    let mut errors = Vec::new();
    for object in objects {
        if let Err(object_errors) = object.validate() {
            errors.extend(
                object_errors
                    .into_iter()
                    .map(|error| LinkError(error.to_string())),
            );
        }
    }
    if !errors.is_empty() {
        return Err(errors);
    }

    let mut prg = vec![0xff; config.prg_rom_len];
    let mut cursors = vec![0_usize; bank_count];
    let mut placements = HashMap::<(usize, SectionId), UxromPlacement>::new();
    let mut map = format!(
        "Mapper 2 bank layout\nfixed bank: {fixed_bank} at $C000-$FFFF\nswitchable banks: 0-{} at $8000-$BFFF\n",
        fixed_bank - 1
    );
    for (object_index, object) in objects.iter().enumerate() {
        for section in &object.sections {
            let bank = match section.placement {
                SectionPlacement::Any | SectionPlacement::Fixed => fixed_bank,
                SectionPlacement::Bank(bank) if bank < fixed_bank => bank,
                SectionPlacement::Bank(bank) => {
                    errors.push(LinkError(format!(
                        "section `{}` requests switchable bank {bank}, but Mapper 2 provides banks 0 through {}",
                        section.name,
                        fixed_bank - 1
                    )));
                    continue;
                }
            };
            let bank_index = usize::from(bank);
            let cursor = align(cursors[bank_index], usize::from(section.alignment));
            let limit = if bank == fixed_bank { 0x3ffa } else { 0x4000 };
            let end = cursor.saturating_add(section.bytes.len());
            if end > limit {
                let window = if bank == fixed_bank {
                    "fixed"
                } else {
                    "switchable"
                };
                errors.push(LinkError(format!(
                    "section `{}` exceeds Mapper 2 {window} bank {bank} capacity",
                    section.name
                )));
                continue;
            }
            let physical_offset = bank_index * 0x4000 + cursor;
            prg[physical_offset..physical_offset + section.bytes.len()]
                .copy_from_slice(&section.bytes);
            let cpu_base = if bank == fixed_bank { 0xc000 } else { 0x8000 };
            let cpu_address = cpu_base + u16::try_from(cursor).expect("bank cursor fits u16");
            placements.insert(
                (object_index, section.id),
                UxromPlacement {
                    physical_offset,
                    cpu_address,
                    bank,
                },
            );
            let end_address = u32::from(cpu_address) + section.bytes.len().saturating_sub(1) as u32;
            map.push_str(&format!(
                "bank {bank:03} ${cpu_address:04X}-${end_address:04X} {}\n",
                section.name
            ));
            cursors[bank_index] = end;
        }
    }
    if !errors.is_empty() {
        return Err(errors);
    }

    let mut global_definitions = BTreeMap::<String, (usize, SymbolId)>::new();
    let mut symbol_locations = HashMap::<(usize, SymbolId), (u16, u16)>::new();
    for (object_index, object) in objects.iter().enumerate() {
        for symbol in &object.symbols {
            let Some(section) = symbol.section else {
                continue;
            };
            let placement = placements[&(object_index, section)];
            let address = match u16::try_from(u32::from(placement.cpu_address) + symbol.offset) {
                Ok(address) => address,
                Err(_) => {
                    errors.push(LinkError(format!(
                        "symbol `{}` exceeds CPU address space",
                        symbol.name
                    )));
                    continue;
                }
            };
            symbol_locations.insert((object_index, symbol.id), (address, placement.bank));
            if symbol.binding == Binding::Global
                && global_definitions
                    .insert(symbol.name.clone(), (object_index, symbol.id))
                    .is_some()
            {
                errors.push(LinkError(format!(
                    "duplicate global symbol `{}`",
                    symbol.name
                )));
            }
        }
    }
    if !errors.is_empty() {
        return Err(errors);
    }

    let mut trampolines = BTreeMap::<(usize, SymbolId), u16>::new();
    for (object_index, object) in objects.iter().enumerate() {
        for relocation in &object.relocations {
            let source = placements[&(object_index, relocation.section)];
            let patch = source.physical_offset + relocation.offset as usize;
            let symbol = &object.symbols[relocation.symbol.0 as usize];
            let definition = if symbol.section.is_some() {
                (object_index, symbol.id)
            } else {
                let Some(definition) = global_definitions.get(&symbol.name).copied() else {
                    errors.push(LinkError(format!(
                        "undefined global symbol `{}`",
                        symbol.name
                    )));
                    continue;
                };
                definition
            };
            let (mut target, target_bank) = symbol_locations[&definition];
            let crosses_switchable_banks = target_bank != fixed_bank && source.bank != target_bank;
            if crosses_switchable_banks {
                let source_section = &object.sections[relocation.section.0 as usize];
                let is_call = relocation.kind == RelocationKind::Absolute16
                    && relocation.addend == 0
                    && relocation.offset > 0
                    && source_section.bytes[relocation.offset as usize - 1] == 0x20;
                if !is_call {
                    errors.push(LinkError(format!(
                        "reference to `{}` crosses from bank {} to switchable bank {target_bank}; only direct JSR calls can use a Mapper 2 trampoline",
                        symbol.name, source.bank
                    )));
                    continue;
                }
                target = if let Some(address) = trampolines.get(&definition).copied() {
                    address
                } else {
                    let bytes = uxrom_trampoline(target_bank as u8, target);
                    let cursor = cursors[usize::from(fixed_bank)];
                    let end = cursor.saturating_add(bytes.len());
                    if end > 0x3ffa {
                        errors.push(LinkError(format!(
                            "Mapper 2 trampoline for `{}` overlaps the interrupt vectors",
                            symbol.name
                        )));
                        continue;
                    }
                    let physical = usize::from(fixed_bank) * 0x4000 + cursor;
                    prg[physical..physical + bytes.len()].copy_from_slice(&bytes);
                    let address = 0xc000 + u16::try_from(cursor).expect("fixed cursor fits u16");
                    map.push_str(&format!(
                        "bank {fixed_bank:03} ${address:04X}-${:04X} __nesc_bankcall_{}\n",
                        u32::from(address) + bytes.len() as u32 - 1,
                        symbol.name
                    ));
                    cursors[usize::from(fixed_bank)] = end;
                    trampolines.insert(definition, address);
                    address
                };
            }
            let target = i32::from(target) + relocation.addend;
            match relocation.kind {
                RelocationKind::Absolute16 => match u16::try_from(target) {
                    Ok(target) => {
                        prg[patch] = target as u8;
                        prg[patch + 1] = (target >> 8) as u8;
                    }
                    Err(_) => errors.push(LinkError(format!(
                        "absolute relocation to `{}` exceeds 16 bits",
                        symbol.name
                    ))),
                },
                RelocationKind::AbsoluteLow8 | RelocationKind::AbsoluteHigh8 => {
                    match u16::try_from(target) {
                        Ok(target) => {
                            prg[patch] = if relocation.kind == RelocationKind::AbsoluteLow8 {
                                target as u8
                            } else {
                                (target >> 8) as u8
                            };
                        }
                        Err(_) => errors.push(LinkError(format!(
                            "absolute relocation to `{}` exceeds 16 bits",
                            symbol.name
                        ))),
                    }
                }
                RelocationKind::Relative8 => {
                    if source.bank != target_bank {
                        errors.push(LinkError(format!(
                            "relative branch to `{}` crosses PRG-ROM banks",
                            symbol.name
                        )));
                        continue;
                    }
                    let operand_address = i32::from(source.cpu_address) + relocation.offset as i32;
                    let displacement = target - (operand_address + 1);
                    match i8::try_from(displacement) {
                        Ok(displacement) => prg[patch] = displacement as u8,
                        Err(_) => errors.push(LinkError(format!(
                            "branch to `{}` is outside the signed 8-bit range",
                            symbol.name
                        ))),
                    }
                }
            }
        }
    }
    if !errors.is_empty() {
        return Err(errors);
    }

    let vector_start = config.prg_rom_len - 6;
    for (index, name) in ["__nesc_nmi", "__nesc_reset", "__nesc_irq"]
        .iter()
        .enumerate()
    {
        let Some(definition) = global_definitions.get(*name).copied() else {
            errors.push(LinkError(format!(
                "required vector symbol `{name}` is undefined"
            )));
            continue;
        };
        let (address, bank) = symbol_locations[&definition];
        if bank != fixed_bank {
            errors.push(LinkError(format!(
                "required vector symbol `{name}` must be in Mapper 2 fixed bank {fixed_bank}"
            )));
            continue;
        }
        let offset = vector_start + index * 2;
        prg[offset] = address as u8;
        prg[offset + 1] = (address >> 8) as u8;
    }
    if !errors.is_empty() {
        return Err(errors);
    }

    let symbols = global_definitions
        .iter()
        .map(|(name, definition)| (name.clone(), symbol_locations[definition].0))
        .collect::<BTreeMap<_, _>>();
    let symbol_banks = global_definitions
        .iter()
        .map(|(name, definition)| (name.clone(), symbol_locations[definition].1))
        .collect::<BTreeMap<_, _>>();
    let cartridge = Rom {
        metadata: Metadata {
            format: config.format,
            mapper: config.mapper,
            submapper: config.submapper,
            mirroring: config.mirroring,
            battery: config.battery,
            region: config.region,
            prg_rom_len: prg.len(),
            chr_rom_len: config.chr_rom_len,
        },
        trainer: None,
        prg_rom: prg.clone(),
        chr_rom: vec![0; config.chr_rom_len],
    };
    let rom = nesc_rom::build(&cartridge).map_err(|error| vec![LinkError(error.to_string())])?;
    nesc_rom::parse(&rom).map_err(|error| vec![LinkError(error.to_string())])?;
    Ok(LinkedImage {
        rom,
        prg_rom: prg,
        symbols,
        symbol_banks,
        map,
    })
}

fn uxrom_trampoline(bank: u8, target: u16) -> Vec<u8> {
    vec![
        0x85,
        0xfd, // sta $fd
        0x86,
        0xfe, // stx $fe
        0x84,
        0xff, // sty $ff
        0xa5,
        0xfc, // lda $fc
        0x48, // pha
        0xa9,
        bank, // lda #bank
        0x85,
        0xfc, // sta $fc
        0x8d,
        0x00,
        0x80, // sta $8000
        0xa5,
        0xfd, // lda $fd
        0xa6,
        0xfe, // ldx $fe
        0xa4,
        0xff, // ldy $ff
        0x20,
        target as u8,
        (target >> 8) as u8, // jsr target
        0x85,
        0xfd, // sta $fd
        0x86,
        0xfe, // stx $fe
        0x84,
        0xff, // sty $ff
        0x68, // pla
        0x85,
        0xfc, // sta $fc
        0x8d,
        0x00,
        0x80, // sta $8000
        0xa5,
        0xfd, // lda $fd
        0xa6,
        0xfe, // ldx $fe
        0xa4,
        0xff, // ldy $ff
        0x60, // rts
    ]
}

/// Relinks an exact supported recovery image through the shared ROM builder.
///
/// This path does not perform ordinary section placement or rewrite vectors:
/// those bytes are already explicit in the recovered assembly. It validates
/// the reconstructed container and supported mapper layout before returning it.
///
/// # Errors
///
/// Returns a deterministic error for inconsistent container parts, malformed
/// metadata, unsupported mappers, or invalid cartridge capacities.
pub fn relink_recovery(input: RecoveryLinkInput<'_>) -> Result<RecoveredImage, LinkError> {
    let rom = nesc_rom::rebuild_exact(nesc_rom::ExactImageParts {
        header: input.header,
        trainer: input.trainer,
        prg_rom: input.prg_rom,
        chr_rom: input.chr_rom,
        trailing: input.trailing,
    })
    .map_err(|error| LinkError(error.to_string()))?;
    let cartridge = nesc_rom::parse(&rom).map_err(|error| LinkError(error.to_string()))?;
    match cartridge.metadata.mapper {
        0 if !matches!(cartridge.prg_rom.len(), 0x4000 | 0x8000) => {
            return Err(LinkError(
                "Mapper 0 recovery requires 16 or 32 KiB PRG-ROM".to_owned(),
            ));
        }
        2 if cartridge.prg_rom.len() < 0x8000
            || cartridge.prg_rom.len() > 0x4000 * 256
            || cartridge.prg_rom.len() % 0x4000 != 0 =>
        {
            return Err(LinkError(
                "Mapper 2 recovery requires 2 to 256 complete 16 KiB PRG-ROM banks".to_owned(),
            ));
        }
        3 if !matches!(cartridge.prg_rom.len(), 0x4000 | 0x8000) => {
            return Err(LinkError(
                "Mapper 3 recovery requires 16 or 32 KiB PRG-ROM".to_owned(),
            ));
        }
        0 | 2 | 3 => {}
        mapper => {
            return Err(LinkError(format!(
                "recovery relinking supports Mapper 0, Mapper 2, and Mapper 3, not Mapper {mapper}"
            )));
        }
    }
    let valid_chr = if cartridge.metadata.mapper == 3 {
        (0x2000..=0x2000 * 256).contains(&cartridge.chr_rom.len())
            && cartridge.chr_rom.len() % 0x2000 == 0
    } else {
        matches!(cartridge.chr_rom.len(), 0 | 0x2000)
    };
    if !valid_chr {
        return Err(LinkError(format!(
            "Mapper {} recovery has an invalid CHR-ROM bank layout",
            cartridge.metadata.mapper
        )));
    }
    Ok(RecoveredImage { rom, cartridge })
}

/// Relinks an exact Mapper 0 recovery image.
///
/// # Errors
///
/// Returns a deterministic error for non-NROM input or invalid reconstruction
/// data.
pub fn relink_nrom(input: RecoveryLinkInput<'_>) -> Result<RecoveredImage, LinkError> {
    let recovered = relink_recovery(input)?;
    if recovered.cartridge.metadata.mapper != 0 {
        return Err(LinkError(format!(
            "NROM recovery relinking does not accept Mapper {}",
            recovered.cartridge.metadata.mapper
        )));
    }
    Ok(recovered)
}

fn align(value: usize, alignment: usize) -> usize {
    (value + alignment - 1) & !(alignment - 1)
}

#[cfg(test)]
mod tests {
    use nesc_object::{
        Binding, Object, Relocation, RelocationKind, SectionKind, SectionPlacement, SymbolKind,
    };
    use nesc_rom::{Format, Mirroring, Region};

    use super::{LinkConfig, RecoveryLinkInput, link, relink_nrom, relink_recovery};

    #[test]
    fn resolves_vectors_in_nrom() {
        let runtime = nesc_runtime::build();
        let mut program = Object::default();
        let code = program
            .add_section(".text", SectionKind::Code, 1)
            .expect("section");
        program.section_bytes_mut(code).unwrap().push(0x60);
        program
            .add_symbol("main", Some(code), 0, SymbolKind::Function, Binding::Global)
            .unwrap();
        let linked = link(
            &[runtime.object, program],
            LinkConfig {
                mapper: 0,
                submapper: 0,
                format: Format::Nes2,
                prg_rom_len: 0x8000,
                chr_rom_len: 0,
                mirroring: Mirroring::Horizontal,
                battery: false,
                region: Region::Ntsc,
            },
        )
        .expect("link");
        let reset = u16::from_le_bytes([linked.prg_rom[0x7ffc], linked.prg_rom[0x7ffd]]);
        assert_eq!(reset, linked.symbols["__nesc_reset"]);
        assert!(linked.symbols["main"] > reset);
    }

    #[test]
    fn links_fixed_prg_and_banked_chr_for_cnrom() {
        let runtime = nesc_runtime::build();
        let mut program = Object::default();
        let code = program
            .add_section(".text", SectionKind::Code, 1)
            .expect("section");
        program.section_bytes_mut(code).unwrap().push(0x60);
        program
            .add_symbol("main", Some(code), 0, SymbolKind::Function, Binding::Global)
            .unwrap();
        let linked = link(
            &[runtime.object, program],
            LinkConfig {
                mapper: 3,
                submapper: 0,
                format: Format::Nes2,
                prg_rom_len: 0x8000,
                chr_rom_len: 4 * 0x2000,
                mirroring: Mirroring::Vertical,
                battery: false,
                region: Region::Pal,
            },
        )
        .expect("Mapper 3 link");
        let parsed = nesc_rom::parse(&linked.rom).expect("valid Mapper 3 ROM");
        assert_eq!(parsed.metadata.mapper, 3);
        assert_eq!(parsed.chr_rom.len(), 4 * 0x2000);
        assert_eq!(linked.symbol_banks["main"], 0);
        assert!(linked.map.contains("Mapper 3 bank layout"));
        assert!(
            linked
                .map
                .contains("switchable CHR-ROM banks: 0-3 at PPU $0000-$1FFF")
        );
    }

    #[test]
    fn places_uxrom_functions_and_inserts_cross_bank_trampoline() {
        let runtime = nesc_runtime::build();
        let mut program = Object::default();
        let fixed = program
            .add_section_with_placement(".text.main", SectionKind::Code, 1, SectionPlacement::Fixed)
            .expect("fixed section");
        program
            .section_bytes_mut(fixed)
            .unwrap()
            .extend_from_slice(&[0x20, 0x00, 0x00, 0x60]);
        program
            .add_symbol(
                "main",
                Some(fixed),
                0,
                SymbolKind::Function,
                Binding::Global,
            )
            .unwrap();
        let banked = program
            .add_section_with_placement(
                ".text.banked",
                SectionKind::Code,
                1,
                SectionPlacement::Bank(1),
            )
            .expect("banked section");
        program.section_bytes_mut(banked).unwrap().push(0x60);
        let banked_symbol = program
            .add_symbol(
                "banked",
                Some(banked),
                0,
                SymbolKind::Function,
                Binding::Global,
            )
            .unwrap();
        program.add_relocation(Relocation {
            section: fixed,
            offset: 1,
            kind: RelocationKind::Absolute16,
            symbol: banked_symbol,
            addend: 0,
        });

        let linked = link(
            &[runtime.object, program],
            LinkConfig {
                mapper: 2,
                submapper: 0,
                format: Format::Nes2,
                prg_rom_len: 0x10000,
                chr_rom_len: 0,
                mirroring: Mirroring::Horizontal,
                battery: false,
                region: Region::Ntsc,
            },
        )
        .expect("Mapper 2 link");
        assert_eq!(linked.symbol_banks["banked"], 1);
        assert_eq!(linked.symbols["banked"], 0x8000);
        assert_eq!(linked.symbol_banks["main"], 3);
        let main_offset = 3 * 0x4000 + usize::from(linked.symbols["main"] - 0xc000);
        let trampoline = u16::from_le_bytes([
            linked.prg_rom[main_offset + 1],
            linked.prg_rom[main_offset + 2],
        ]);
        assert!((0xc000..=0xfff9).contains(&trampoline));
        assert_ne!(trampoline, linked.symbols["banked"]);
        assert!(linked.map.contains("__nesc_bankcall_banked"));
        let parsed = nesc_rom::parse(&linked.rom).expect("valid Mapper 2 ROM");
        assert_eq!(parsed.metadata.mapper, 2);
    }

    #[test]
    fn relinks_exact_recovery_container() {
        let cartridge = nesc_rom::Rom {
            metadata: nesc_rom::Metadata {
                format: Format::Ines,
                mapper: 0,
                submapper: 0,
                mirroring: Mirroring::Horizontal,
                battery: false,
                region: Region::Ntsc,
                prg_rom_len: 0x4000,
                chr_rom_len: 0x2000,
            },
            trainer: Some(vec![0x55; 512]),
            prg_rom: vec![0xea; 0x4000],
            chr_rom: vec![0xaa; 0x2000],
        };
        let mut original = nesc_rom::build(&cartridge).expect("ROM");
        original[10] = 0x7f;
        original.extend_from_slice(&[0xde, 0xad]);
        let rebuilt = relink_nrom(RecoveryLinkInput {
            header: &original[..16],
            trainer: cartridge.trainer.as_deref(),
            prg_rom: &cartridge.prg_rom,
            chr_rom: &cartridge.chr_rom,
            trailing: &original[original.len() - 2..],
        })
        .expect("relink");
        assert_eq!(rebuilt.rom, original);
        assert_eq!(rebuilt.cartridge, cartridge);
    }

    #[test]
    fn relinks_exact_uxrom_recovery_container() {
        let cartridge = nesc_rom::Rom {
            metadata: nesc_rom::Metadata {
                format: Format::Nes2,
                mapper: 2,
                submapper: 0,
                mirroring: Mirroring::Horizontal,
                battery: false,
                region: Region::Ntsc,
                prg_rom_len: 0x10000,
                chr_rom_len: 0,
            },
            trainer: None,
            prg_rom: vec![0xea; 0x10000],
            chr_rom: Vec::new(),
        };
        let mut original = nesc_rom::build(&cartridge).expect("ROM");
        original.extend_from_slice(&[0xde, 0xad]);
        let rebuilt = relink_recovery(RecoveryLinkInput {
            header: &original[..16],
            trainer: None,
            prg_rom: &cartridge.prg_rom,
            chr_rom: &[],
            trailing: &original[original.len() - 2..],
        })
        .expect("relink");
        assert_eq!(rebuilt.rom, original);
        assert_eq!(rebuilt.cartridge, cartridge);
    }

    #[test]
    fn relinks_exact_cnrom_recovery_container() {
        let cartridge = nesc_rom::Rom {
            metadata: nesc_rom::Metadata {
                format: Format::Nes2,
                mapper: 3,
                submapper: 0,
                mirroring: Mirroring::Vertical,
                battery: false,
                region: Region::Dendy,
                prg_rom_len: 0x8000,
                chr_rom_len: 4 * 0x2000,
            },
            trainer: None,
            prg_rom: vec![0xea; 0x8000],
            chr_rom: (0..4_u8)
                .flat_map(|bank| std::iter::repeat_n(bank, 0x2000))
                .collect(),
        };
        let mut original = nesc_rom::build(&cartridge).expect("ROM");
        original.extend_from_slice(&[0xde, 0xad]);
        let rebuilt = relink_recovery(RecoveryLinkInput {
            header: &original[..16],
            trainer: None,
            prg_rom: &cartridge.prg_rom,
            chr_rom: &cartridge.chr_rom,
            trailing: &original[original.len() - 2..],
        })
        .expect("relink");
        assert_eq!(rebuilt.rom, original);
        assert_eq!(rebuilt.cartridge, cartridge);
    }
}
