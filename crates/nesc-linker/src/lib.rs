//! NES-aware linker for relocatable NOBJ inputs.

use std::collections::{BTreeMap, HashMap};
use std::error::Error;
use std::fmt;

use nesc_object::{Binding, Object, RelocationKind, SectionId, SymbolId};
use nesc_rom::{Format, Metadata, Mirroring, Region, Rom};

/// Mapper 0 link settings.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LinkConfig {
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
    /// Human-readable placement report.
    pub map: String,
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

/// Links objects into a Mapper 0 cartridge.
///
/// Runtime/startup objects must precede generated program objects so reset
/// code remains at the beginning of PRG-ROM.
///
/// # Errors
///
/// Returns deterministic failures for invalid objects, duplicate or missing
/// symbols, overflowing sections, branch range, or invalid vectors.
pub fn link(objects: &[Object], config: LinkConfig) -> Result<LinkedImage, Vec<LinkError>> {
    if !matches!(config.prg_rom_len, 0x4000 | 0x8000) {
        return Err(vec![LinkError(
            "Mapper 0 PRG-ROM must be 16 or 32 KiB".to_owned(),
        )]);
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
    if !errors.is_empty() {
        return Err(errors);
    }

    let mut prg = vec![0xff; config.prg_rom_len];
    let mut placements = HashMap::<(usize, SectionId), usize>::new();
    let mut cursor = 0_usize;
    let vector_start = config.prg_rom_len - 6;
    let mut map = String::from("Mapper 0 bank layout\n");
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
    let cartridge = Rom {
        metadata: Metadata {
            format: config.format,
            mapper: 0,
            submapper: 0,
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
        map,
    })
}

fn align(value: usize, alignment: usize) -> usize {
    (value + alignment - 1) & !(alignment - 1)
}

#[cfg(test)]
mod tests {
    use nesc_object::{Binding, Object, SectionKind, SymbolKind};
    use nesc_rom::{Format, Mirroring, Region};

    use super::{LinkConfig, link};

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
}
