//! Validated relocatable object model shared by NesC and assembly inputs.

use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;

/// Stable section identifier.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SectionId(pub u32);

/// Stable symbol identifier.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SymbolId(pub u32);

/// Linker placement class.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SectionKind {
    /// Executable PRG-ROM bytes.
    Code,
    /// Immutable PRG-ROM bytes.
    ReadOnlyData,
}

/// Mapper-aware PRG-ROM placement requirement.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum SectionPlacement {
    /// Let the linker choose a safe location.
    #[default]
    Any,
    /// Place the section in the permanently mapped PRG-ROM bank.
    Fixed,
    /// Place the section in a numbered switchable PRG-ROM bank.
    Bank(u16),
}

/// Symbol visibility.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Binding {
    /// Visible only inside this object.
    Local,
    /// Exported or imported by name.
    Global,
}

/// Symbol category.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SymbolKind {
    /// Function entry.
    Function,
    /// Basic-block or data label.
    Label,
}

/// Relocatable section bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Section {
    /// Stable identifier.
    pub id: SectionId,
    /// Diagnostic and assembly name.
    pub name: String,
    /// Placement class.
    pub kind: SectionKind,
    /// Mapper-aware PRG-ROM placement requirement.
    pub placement: SectionPlacement,
    /// Required power-of-two alignment.
    pub alignment: u16,
    /// Encoded bytes with zero placeholders at relocation sites.
    pub bytes: Vec<u8>,
}

/// Defined or imported symbol.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Symbol {
    /// Stable identifier.
    pub id: SymbolId,
    /// Linker name.
    pub name: String,
    /// Defining section; absent for an import.
    pub section: Option<SectionId>,
    /// Byte offset within the defining section.
    pub offset: u32,
    /// Symbol category.
    pub kind: SymbolKind,
    /// Visibility.
    pub binding: Binding,
}

/// Relocation encoding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RelocationKind {
    /// Little-endian 16-bit absolute address.
    Absolute16,
    /// Signed branch displacement relative to the byte after the relocation.
    Relative8,
    /// Low byte of a 16-bit absolute address.
    AbsoluteLow8,
    /// High byte of a 16-bit absolute address.
    AbsoluteHigh8,
}

/// Symbolic patch within a section.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Relocation {
    /// Section containing the patch.
    pub section: SectionId,
    /// First placeholder byte.
    pub offset: u32,
    /// Patch encoding.
    pub kind: RelocationKind,
    /// Referenced symbol.
    pub symbol: SymbolId,
    /// Signed address adjustment.
    pub addend: i32,
}

/// One relocatable compilation unit.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Object {
    /// Sections in deterministic order.
    pub sections: Vec<Section>,
    /// Symbols in deterministic order.
    pub symbols: Vec<Symbol>,
    /// Relocations in emission order.
    pub relocations: Vec<Relocation>,
}

/// Object construction or validation failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObjectError(pub String);

impl fmt::Display for ObjectError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl Error for ObjectError {}

impl Object {
    /// Adds a section and returns its stable identifier.
    pub fn add_section(
        &mut self,
        name: impl Into<String>,
        kind: SectionKind,
        alignment: u16,
    ) -> Result<SectionId, ObjectError> {
        self.add_section_with_placement(name, kind, alignment, SectionPlacement::Any)
    }

    /// Adds a section with an explicit mapper-aware placement requirement.
    pub fn add_section_with_placement(
        &mut self,
        name: impl Into<String>,
        kind: SectionKind,
        alignment: u16,
        placement: SectionPlacement,
    ) -> Result<SectionId, ObjectError> {
        if alignment == 0 || !alignment.is_power_of_two() {
            return Err(ObjectError(
                "section alignment must be a power of two".to_owned(),
            ));
        }
        let id = SectionId(
            u32::try_from(self.sections.len())
                .map_err(|_| ObjectError("object contains too many sections".to_owned()))?,
        );
        self.sections.push(Section {
            id,
            name: name.into(),
            kind,
            placement,
            alignment,
            bytes: Vec::new(),
        });
        Ok(id)
    }

    /// Adds a symbol and returns its stable identifier.
    pub fn add_symbol(
        &mut self,
        name: impl Into<String>,
        section: Option<SectionId>,
        offset: u32,
        kind: SymbolKind,
        binding: Binding,
    ) -> Result<SymbolId, ObjectError> {
        let name = name.into();
        if name.is_empty() {
            return Err(ObjectError("symbol name cannot be empty".to_owned()));
        }
        let id = SymbolId(
            u32::try_from(self.symbols.len())
                .map_err(|_| ObjectError("object contains too many symbols".to_owned()))?,
        );
        self.symbols.push(Symbol {
            id,
            name,
            section,
            offset,
            kind,
            binding,
        });
        Ok(id)
    }

    /// Returns mutable section bytes.
    pub fn section_bytes_mut(&mut self, id: SectionId) -> Result<&mut Vec<u8>, ObjectError> {
        self.sections
            .get_mut(id.0 as usize)
            .map(|section| &mut section.bytes)
            .ok_or_else(|| ObjectError("section identifier is out of range".to_owned()))
    }

    /// Adds a relocation.
    pub fn add_relocation(&mut self, relocation: Relocation) {
        self.relocations.push(relocation);
    }

    /// Validates identifiers, ranges, symbols, and duplicate exports.
    ///
    /// # Errors
    ///
    /// Returns every structural failure found in deterministic order.
    pub fn validate(&self) -> Result<(), Vec<ObjectError>> {
        let mut errors = Vec::new();
        let mut globals = BTreeMap::<&str, SymbolId>::new();
        for (index, section) in self.sections.iter().enumerate() {
            if section.id.0 as usize != index {
                errors.push(ObjectError(format!(
                    "section `{}` has a noncanonical identifier",
                    section.name
                )));
            }
        }
        for (index, symbol) in self.symbols.iter().enumerate() {
            if symbol.id.0 as usize != index {
                errors.push(ObjectError(format!(
                    "symbol `{}` has a noncanonical identifier",
                    symbol.name
                )));
            }
            if let Some(section) = symbol.section {
                match self.sections.get(section.0 as usize) {
                    Some(section) if symbol.offset as usize <= section.bytes.len() => {}
                    Some(_) => errors.push(ObjectError(format!(
                        "symbol `{}` is outside its section",
                        symbol.name
                    ))),
                    None => errors.push(ObjectError(format!(
                        "symbol `{}` references an unknown section",
                        symbol.name
                    ))),
                }
            }
            if symbol.binding == Binding::Global
                && symbol.section.is_some()
                && globals.insert(&symbol.name, symbol.id).is_some()
            {
                errors.push(ObjectError(format!(
                    "global symbol `{}` is defined more than once",
                    symbol.name
                )));
            }
        }
        for relocation in &self.relocations {
            let width = match relocation.kind {
                RelocationKind::Absolute16 => 2,
                RelocationKind::Relative8
                | RelocationKind::AbsoluteLow8
                | RelocationKind::AbsoluteHigh8 => 1,
            };
            match self.sections.get(relocation.section.0 as usize) {
                Some(section)
                    if (relocation.offset as usize).saturating_add(width)
                        <= section.bytes.len() => {}
                Some(_) => errors.push(ObjectError("relocation is outside its section".to_owned())),
                None => errors.push(ObjectError(
                    "relocation references an unknown section".to_owned(),
                )),
            }
            if self.symbols.get(relocation.symbol.0 as usize).is_none() {
                errors.push(ObjectError(
                    "relocation references an unknown symbol".to_owned(),
                ));
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Binding, Object, Relocation, RelocationKind, SectionKind, SymbolKind};

    #[test]
    fn validates_relocation_ranges() {
        let mut object = Object::default();
        let code = object
            .add_section("code", SectionKind::Code, 1)
            .expect("section");
        object.section_bytes_mut(code).unwrap().push(0);
        let symbol = object
            .add_symbol("target", None, 0, SymbolKind::Function, Binding::Global)
            .expect("symbol");
        object.add_relocation(Relocation {
            section: code,
            offset: 0,
            kind: RelocationKind::Absolute16,
            symbol,
            addend: 0,
        });
        assert!(object.validate().is_err());
    }
}
