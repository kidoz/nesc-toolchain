//! Mapper-aware, lossless NES ROM disassembly.

mod decoder;

use std::collections::{BTreeMap, HashSet, VecDeque};
use std::error::Error;
use std::fmt;

use nesc_rom::{CpuAddress, Mapper, MapperState, PpuAddress, Rom};

pub use decoder::{
    AddressingMode, DecodeError, DecodedInstruction, FlowControl, Mnemonic, Opcode, decode, opcode,
};

const HEADER_LEN: usize = 16;
const TRAINER_LEN: usize = 512;
const PRG_BANK_LEN: usize = 16 * 1024;
const NMI_VECTOR: u16 = 0xfffa;
const RESET_VECTOR: u16 = 0xfffc;
const IRQ_VECTOR: u16 = 0xfffe;

/// Bounded-analysis settings for untrusted ROM input.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AnalysisLimits {
    /// Maximum decoded instruction count.
    pub max_instructions: usize,
    /// Maximum queued control-flow destinations.
    pub max_work_items: usize,
}

impl Default for AnalysisLimits {
    fn default() -> Self {
        Self {
            max_instructions: 1_000_000,
            max_work_items: 100_000,
        }
    }
}

/// Explicit classification assigned to each physical PRG byte.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ByteClassification {
    /// Not yet classified during traversal.
    Unknown,
    /// First byte of a proven official instruction.
    Code,
    /// Operand byte owned by the preceding instruction.
    CodeOperand,
    /// Unproven, conflicting, truncated, or undocumented data.
    Data,
}

/// Cartridge-qualified code address.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct BankAddress {
    /// Physical 16 KiB PRG bank.
    pub bank: u16,
    /// CPU-visible address for this decoded instance.
    pub cpu_address: u16,
}

/// Input vector that established a recursive traversal root.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VectorKind {
    Nmi,
    Reset,
    Irq,
}

impl VectorKind {
    const fn name(self) -> &'static str {
        match self {
            Self::Nmi => "nmi",
            Self::Reset => "reset",
            Self::Irq => "irq",
        }
    }
}

/// One validated vector entry point.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EntryPoint {
    /// Vector category.
    pub kind: VectorKind,
    /// Bank-qualified destination.
    pub address: BankAddress,
    /// Physical byte offset within PRG-ROM.
    pub prg_offset: usize,
    /// Stable emitted label.
    pub label: String,
}

/// One stable synthetic or vector-derived label.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Label {
    /// Bank-qualified address.
    pub address: BankAddress,
    /// Physical PRG offset.
    pub prg_offset: usize,
    /// Assembly spelling.
    pub name: String,
}

/// One decoded instruction with complete cartridge provenance.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Instruction {
    /// Physical 16 KiB PRG bank and mapped CPU address.
    pub address: BankAddress,
    /// Physical byte offset within PRG-ROM.
    pub prg_offset: usize,
    /// Mapper 2 switchable-bank states observed while this instruction executes.
    pub selected_prg_banks: Vec<Option<u16>>,
    /// Mapper 3 switchable CHR-bank states observed while this instruction executes.
    pub selected_chr_banks: Vec<Option<u16>>,
    /// Byte offset within the original ROM container.
    pub rom_file_offset: usize,
    /// Exact official instruction decoding.
    pub decoded: DecodedInstruction,
}

/// Direct or indirect edge that recursive traversal could not map safely.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnresolvedFlow {
    /// Instruction producing the unresolved edge.
    pub source: BankAddress,
    /// Physical source offset.
    pub prg_offset: usize,
    /// Flow category.
    pub flow: FlowControl,
    /// Encoded destination or indirect pointer.
    pub target: u16,
}

/// Non-fatal ambiguity or malformed metadata retained in the result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AnalysisNotice {
    /// Deterministic explanation.
    pub message: String,
}

/// Statically observed write to a mapper register.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MapperWrite {
    /// Instruction performing the write.
    pub source: BankAddress,
    /// Physical source offset.
    pub prg_offset: usize,
    /// CPU mapper-register address, when statically exact.
    pub register_address: Option<u16>,
    /// Written value, when statically known.
    pub value: Option<u8>,
    /// Kind of physical mapper bank selected by the write.
    pub bank_kind: MapperBankKind,
    /// Physical mapper bank selected by the write, when known.
    pub resulting_bank: Option<u16>,
}

/// Mapper-controlled cartridge region affected by a register write.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MapperBankKind {
    /// Switchable 16 KiB PRG-ROM bank.
    Prg,
    /// Switchable 8 KiB CHR-ROM bank.
    Chr,
}

/// Complete mapper-aware recursive-analysis result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Disassembly {
    /// Parsed cartridge, including original PRG and CHR bytes.
    pub rom: Rom,
    /// Decoded instructions ordered by physical PRG offset.
    pub instructions: BTreeMap<usize, Instruction>,
    /// Classification for every physical PRG byte.
    pub classification: Vec<ByteClassification>,
    /// Stable bank-qualified labels.
    pub labels: Vec<Label>,
    /// Valid vector traversal roots.
    pub entry_points: Vec<EntryPoint>,
    /// Explicit unresolved control-flow records.
    pub unresolved: Vec<UnresolvedFlow>,
    /// Mapper-register writes discovered during traversal.
    pub mapper_writes: Vec<MapperWrite>,
    /// Non-fatal analysis notices.
    pub notices: Vec<AnalysisNotice>,
}

impl Disassembly {
    /// Reconstructs PRG bytes from decoded instructions and classified data.
    #[must_use]
    pub fn recovered_prg(&self) -> Vec<u8> {
        let mut recovered = Vec::with_capacity(self.rom.prg_rom.len());
        let mut offset = 0;
        while offset < self.rom.prg_rom.len() {
            if let Some(instruction) = self.instructions.get(&offset) {
                recovered.extend_from_slice(instruction.decoded.bytes());
                offset += instruction.decoded.bytes().len();
            } else {
                recovered.push(self.rom.prg_rom[offset]);
                offset += 1;
            }
        }
        recovered
    }

    /// Verifies that classification and decoding preserve every PRG byte.
    ///
    /// # Errors
    ///
    /// Reports the first differing physical and container offset.
    pub fn verify_recovery(&self) -> Result<(), DisassemblyError> {
        let recovered = self.recovered_prg();
        if recovered == self.rom.prg_rom {
            return Ok(());
        }
        let offset = recovered
            .iter()
            .zip(&self.rom.prg_rom)
            .position(|(recovered, original)| recovered != original)
            .unwrap_or_else(|| recovered.len().min(self.rom.prg_rom.len()));
        Err(DisassemblyError::new(format!(
            "recovered PRG first differs at physical offset ${offset:05X}, container offset ${:05X}",
            self.prg_file_start() + offset
        )))
    }

    /// Verifies a rebuilt complete container against the original input.
    ///
    /// # Errors
    ///
    /// Reports the first differing file offset with its cartridge region and,
    /// for PRG-ROM, physical bank and mapped CPU address.
    pub fn verify_rom_rebuild(
        &self,
        original: &[u8],
        rebuilt: &[u8],
    ) -> Result<(), DisassemblyError> {
        if original == rebuilt {
            return Ok(());
        }
        let offset = original
            .iter()
            .zip(rebuilt)
            .position(|(original, rebuilt)| original != rebuilt)
            .unwrap_or_else(|| original.len().min(rebuilt.len()));
        let expected = format_optional_byte(original.get(offset));
        let actual = format_optional_byte(rebuilt.get(offset));
        Err(DisassemblyError::new(format!(
            "round-trip first differs at file offset ${offset:05X} in {}: expected {expected}, rebuilt {actual}",
            self.describe_file_offset(offset)
        )))
    }

    /// Renders deterministic ca65-style assembly with explicit data bytes.
    #[must_use]
    pub fn assembly(&self) -> String {
        render_assembly(self)
    }

    /// Renders recovered cartridge metadata.
    #[must_use]
    pub fn cartridge_manifest(&self) -> String {
        let metadata = &self.rom.metadata;
        format!(
            "format = \"{}\"\nmapper = {}\nsubmapper = {}\nmirroring = \"{}\"\nregion = \"{}\"\nbattery = {}\nprg-rom-bytes = {}\nchr-rom-bytes = {}\ntrainer = {}\n",
            match metadata.format {
                nesc_rom::Format::Ines => "ines",
                nesc_rom::Format::Nes2 => "nes2",
            },
            metadata.mapper,
            metadata.submapper,
            match metadata.mirroring {
                nesc_rom::Mirroring::Horizontal => "horizontal",
                nesc_rom::Mirroring::Vertical => "vertical",
                nesc_rom::Mirroring::FourScreen => "four-screen",
            },
            match metadata.region {
                nesc_rom::Region::Ntsc => "ntsc",
                nesc_rom::Region::Pal => "pal",
                nesc_rom::Region::MultiRegion => "multi-region",
                nesc_rom::Region::Dendy => "dendy",
            },
            metadata.battery,
            metadata.prg_rom_len,
            metadata.chr_rom_len,
            self.rom.trainer.is_some(),
        )
    }

    fn prg_file_start(&self) -> usize {
        HEADER_LEN + self.rom.trainer.as_ref().map_or(0, |_| TRAINER_LEN)
    }

    fn describe_file_offset(&self, file_offset: usize) -> String {
        if file_offset < HEADER_LEN {
            return "header".to_owned();
        }
        let prg_start = self.prg_file_start();
        if file_offset < prg_start {
            return format!("trainer offset ${:03X}", file_offset - HEADER_LEN);
        }
        let prg_end = prg_start + self.rom.prg_rom.len();
        if file_offset < prg_end {
            let prg_offset = file_offset - prg_start;
            let bank = physical_bank(prg_offset);
            let bank_offset = prg_offset % PRG_BANK_LEN;
            let cpu_address = cpu_address_for_offset(&self.rom, prg_offset);
            return format!(
                "PRG-ROM physical bank {bank:02X}, bank offset ${bank_offset:04X}, CPU ${cpu_address:04X}"
            );
        }
        let chr_end = prg_end + self.rom.chr_rom.len();
        if file_offset < chr_end {
            let chr_offset = file_offset - prg_end;
            return format!(
                "CHR-ROM physical bank {:02X}, bank offset ${:04X}, PPU ${:04X}",
                chr_offset / 0x2000,
                chr_offset % 0x2000,
                chr_offset % 0x2000
            );
        }
        format!("trailing data offset ${:05X}", file_offset - chr_end)
    }
}

fn format_optional_byte(byte: Option<&u8>) -> String {
    byte.map_or_else(|| "end of file".to_owned(), |byte| format!("${byte:02X}"))
}

/// Fatal ROM parsing, mapping, or resource-limit failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DisassemblyError {
    message: String,
}

impl DisassemblyError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    /// Returns the diagnostic text.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for DisassemblyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl Error for DisassemblyError {}

/// Parses and recursively analyzes a supported Mapper 0, Mapper 2, or Mapper 3 image.
///
/// # Errors
///
/// Returns a diagnostic for malformed input, an unsupported mapper, an
/// impossible cartridge layout, or exhausted analysis limits.
pub fn disassemble(bytes: &[u8], limits: AnalysisLimits) -> Result<Disassembly, DisassemblyError> {
    let rom = nesc_rom::parse(bytes).map_err(|error| DisassemblyError::new(error.to_string()))?;
    disassemble_rom(rom, limits)
}

/// Recursively analyzes a parsed Mapper 0, Mapper 2, or Mapper 3 image.
///
/// # Errors
///
/// Returns a diagnostic for an unsupported mapper, an impossible layout, or
/// exhausted analysis limits.
pub fn disassemble_rom(rom: Rom, limits: AnalysisLimits) -> Result<Disassembly, DisassemblyError> {
    if !matches!(rom.metadata.mapper, 0 | 2 | 3) {
        return Err(DisassemblyError::new(format!(
            "recursive disassembly supports Mapper 0, Mapper 2, and Mapper 3, not Mapper {}",
            rom.metadata.mapper
        )));
    }
    if limits.max_instructions == 0 || limits.max_work_items == 0 {
        return Err(DisassemblyError::new(
            "analysis limits must permit at least one instruction and work item",
        ));
    }
    let mapper = Mapper::new(rom.metadata.mapper, rom.prg_rom.len(), rom.chr_rom.len())
        .map_err(|error| DisassemblyError::new(error.to_string()))?;
    Analyzer::new(rom, mapper, limits).run()
}

struct Analyzer {
    rom: Rom,
    mapper: Mapper,
    limits: AnalysisLimits,
    instructions: BTreeMap<usize, Instruction>,
    classification: Vec<ByteClassification>,
    labels: BTreeMap<(usize, u16), String>,
    entry_points: Vec<EntryPoint>,
    unresolved: Vec<UnresolvedFlow>,
    mapper_writes: Vec<MapperWrite>,
    notices: Vec<AnalysisNotice>,
    work: VecDeque<WorkItem>,
    queued: HashSet<WorkItem>,
    visited: HashSet<WorkItem>,
    work_items: usize,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct WorkItem {
    cpu_address: u16,
    state: AbstractState,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct AbstractState {
    selected_prg_bank: Option<u8>,
    selected_chr_bank: Option<u8>,
    a: Option<u8>,
    x: Option<u8>,
    y: Option<u8>,
}

impl AbstractState {
    const fn reset() -> Self {
        Self {
            selected_prg_bank: Some(0),
            selected_chr_bank: Some(0),
            a: None,
            x: None,
            y: None,
        }
    }

    const fn forget_call_clobbers(mut self) -> Self {
        self.a = None;
        self.x = None;
        self.y = None;
        self
    }
}

impl Analyzer {
    fn new(rom: Rom, mapper: Mapper, limits: AnalysisLimits) -> Self {
        let classification = vec![ByteClassification::Unknown; rom.prg_rom.len()];
        Self {
            rom,
            mapper,
            limits,
            instructions: BTreeMap::new(),
            classification,
            labels: BTreeMap::new(),
            entry_points: Vec::new(),
            unresolved: Vec::new(),
            mapper_writes: Vec::new(),
            notices: Vec::new(),
            work: VecDeque::new(),
            queued: HashSet::new(),
            visited: HashSet::new(),
            work_items: 0,
        }
    }

    fn run(mut self) -> Result<Disassembly, DisassemblyError> {
        self.seed_vector(VectorKind::Nmi, NMI_VECTOR)?;
        self.seed_vector(VectorKind::Reset, RESET_VECTOR)?;
        self.seed_vector(VectorKind::Irq, IRQ_VECTOR)?;
        while let Some(item) = self.work.pop_front() {
            self.walk(item)?;
        }
        self.classification.iter_mut().for_each(|classification| {
            if *classification == ByteClassification::Unknown {
                *classification = ByteClassification::Data;
            }
        });
        let labels = self
            .labels
            .into_iter()
            .map(|((prg_offset, cpu_address), name)| Label {
                address: BankAddress {
                    bank: physical_bank(prg_offset),
                    cpu_address,
                },
                prg_offset,
                name,
            })
            .collect();
        Ok(Disassembly {
            rom: self.rom,
            instructions: self.instructions,
            classification: self.classification,
            labels,
            entry_points: self.entry_points,
            unresolved: self.unresolved,
            mapper_writes: self.mapper_writes,
            notices: self.notices,
        })
    }

    fn seed_vector(
        &mut self,
        kind: VectorKind,
        vector_address: u16,
    ) -> Result<(), DisassemblyError> {
        let state = AbstractState::reset();
        let Some(destination) = self.read_mapped_word(vector_address, state) else {
            self.notice(format!(
                "{} vector at ${vector_address:04X} is not readable from PRG-ROM",
                kind.name()
            ));
            return Ok(());
        };
        let Some(prg_offset) = self.map_cpu(destination, state) else {
            self.notice(format!(
                "{} vector targets unmapped CPU address ${destination:04X}",
                kind.name()
            ));
            return Ok(());
        };
        let label = format!(
            "{}_prg{:02X}_{destination:04X}",
            kind.name(),
            physical_bank(prg_offset)
        );
        self.labels.insert((prg_offset, destination), label.clone());
        self.entry_points.push(EntryPoint {
            kind,
            address: BankAddress {
                bank: physical_bank(prg_offset),
                cpu_address: destination,
            },
            prg_offset,
            label,
        });
        self.enqueue(destination, state)
    }

    fn walk(&mut self, item: WorkItem) -> Result<(), DisassemblyError> {
        let mut cpu_address = item.cpu_address;
        let mut state = item.state;
        loop {
            let current = WorkItem { cpu_address, state };
            if !self.visited.insert(current) {
                return Ok(());
            }
            let Some(prg_offset) = self.map_cpu(cpu_address, state) else {
                self.notice(format!(
                    "cannot map CPU address ${cpu_address:04X} with an unknown Mapper 2 bank"
                ));
                return Ok(());
            };
            let existing = self
                .instructions
                .get(&prg_offset)
                .map(|instruction| (instruction.address.cpu_address, instruction.decoded));
            let decoded = if let Some((existing_address, decoded)) = existing {
                if existing_address != cpu_address {
                    self.notice(format!(
                        "physical PRG offset ${prg_offset:05X} is reached through aliases ${:04X} and ${cpu_address:04X}",
                        existing_address
                    ));
                }
                decoded
            } else {
                if self.classification[prg_offset] == ByteClassification::CodeOperand {
                    self.notice(format!(
                        "control flow enters an instruction operand at PRG offset ${prg_offset:05X}"
                    ));
                    return Ok(());
                }
                if self.instructions.len() >= self.limits.max_instructions {
                    return Err(DisassemblyError::new(format!(
                        "instruction analysis limit {} exceeded",
                        self.limits.max_instructions
                    )));
                }
                let decoded = match self.decode_mapped(cpu_address, prg_offset, state) {
                    Ok(decoded) => decoded,
                    Err(DecodeError::UnsupportedOpcode(_)) | Err(DecodeError::Truncated { .. }) => {
                        self.classification[prg_offset] = ByteClassification::Data;
                        return Ok(());
                    }
                    Err(DecodeError::EmptyInput) => return Ok(()),
                };
                let instruction_len = decoded.bytes().len();
                let end = prg_offset + instruction_len;
                if self.classification[prg_offset + 1..end].contains(&ByteClassification::Code) {
                    self.classification[prg_offset] = ByteClassification::Data;
                    self.notice(format!(
                        "instruction at ${cpu_address:04X} overlaps an existing code start"
                    ));
                    return Ok(());
                }
                self.classification[prg_offset] = ByteClassification::Code;
                self.classification[prg_offset + 1..end].fill(ByteClassification::CodeOperand);
                decoded
            };
            let address = BankAddress {
                bank: physical_bank(prg_offset),
                cpu_address,
            };
            let flow = decoded.opcode.flow();
            let operand = decoded.operand();
            let selected_prg_bank = (self.rom.metadata.mapper == 2)
                .then(|| {
                    state.selected_prg_bank.and_then(|bank| {
                        self.mapper
                            .map_cpu(
                                CpuAddress(0x8000),
                                MapperState {
                                    prg_bank: bank,
                                    chr_bank: 0,
                                },
                            )
                            .map(|offset| physical_bank(offset.0))
                    })
                })
                .flatten();
            let selected_chr_bank = (self.rom.metadata.mapper == 3)
                .then(|| {
                    state.selected_chr_bank.and_then(|bank| {
                        self.mapper
                            .map_ppu(
                                PpuAddress(0),
                                MapperState {
                                    prg_bank: 0,
                                    chr_bank: bank,
                                },
                            )
                            .and_then(|offset| u16::try_from(offset.0 / 0x2000).ok())
                    })
                })
                .flatten();
            let rom_file_offset = self.prg_file_start() + prg_offset;
            self.instructions
                .entry(prg_offset)
                .and_modify(|instruction| {
                    if !instruction.selected_prg_banks.contains(&selected_prg_bank) {
                        instruction.selected_prg_banks.push(selected_prg_bank);
                        instruction.selected_prg_banks.sort_unstable();
                    }
                    if !instruction.selected_chr_banks.contains(&selected_chr_bank) {
                        instruction.selected_chr_banks.push(selected_chr_bank);
                        instruction.selected_chr_banks.sort_unstable();
                    }
                })
                .or_insert(Instruction {
                    address,
                    prg_offset,
                    selected_prg_banks: vec![selected_prg_bank],
                    selected_chr_banks: vec![selected_chr_bank],
                    rom_file_offset,
                    decoded,
                });
            let next = cpu_address.wrapping_add(u16::from(decoded.opcode.len()));
            self.apply_instruction_state(address, prg_offset, decoded, &mut state);
            match flow {
                FlowControl::Fallthrough => cpu_address = next,
                FlowControl::Branch => {
                    let target = next.wrapping_add_signed(i16::from(decoded.bytes()[1] as i8));
                    self.follow_direct(address, prg_offset, flow, target, state)?;
                    cpu_address = next;
                }
                FlowControl::Call => {
                    self.follow_direct(address, prg_offset, flow, operand, state)?;
                    state = state.forget_call_clobbers();
                    if self.rom.metadata.mapper == 2 {
                        state.selected_prg_bank = None;
                    } else if self.rom.metadata.mapper == 3 {
                        state.selected_chr_bank = None;
                    }
                    cpu_address = next;
                }
                FlowControl::Jump => {
                    self.follow_direct(address, prg_offset, flow, operand, state)?;
                    return Ok(());
                }
                FlowControl::IndirectJump => {
                    self.unresolved.push(UnresolvedFlow {
                        source: address,
                        prg_offset,
                        flow,
                        target: operand,
                    });
                    return Ok(());
                }
                FlowControl::Return | FlowControl::Interrupt => return Ok(()),
            }
        }
    }

    fn follow_direct(
        &mut self,
        source: BankAddress,
        prg_offset: usize,
        flow: FlowControl,
        target: u16,
        state: AbstractState,
    ) -> Result<(), DisassemblyError> {
        let Some(target_offset) = self.map_cpu(target, state) else {
            self.unresolved.push(UnresolvedFlow {
                source,
                prg_offset,
                flow,
                target,
            });
            return Ok(());
        };
        self.labels
            .entry((target_offset, target))
            .or_insert_with(|| synthetic_label(target_offset, target));
        self.enqueue(target, state)
    }

    fn enqueue(&mut self, cpu_address: u16, state: AbstractState) -> Result<(), DisassemblyError> {
        if self.map_cpu(cpu_address, state).is_none() {
            return Ok(());
        }
        let item = WorkItem { cpu_address, state };
        if !self.queued.insert(item) {
            return Ok(());
        }
        if self.work_items >= self.limits.max_work_items {
            return Err(DisassemblyError::new(format!(
                "control-flow work-item limit {} exceeded",
                self.limits.max_work_items
            )));
        }
        self.work_items += 1;
        self.work.push_back(item);
        Ok(())
    }

    fn read_mapped_word(&self, address: u16, state: AbstractState) -> Option<u16> {
        let low = self
            .map_cpu(address, state)
            .and_then(|offset| self.rom.prg_rom.get(offset))?;
        let high = self
            .map_cpu(address.wrapping_add(1), state)
            .and_then(|offset| self.rom.prg_rom.get(offset))?;
        Some(u16::from_le_bytes([*low, *high]))
    }

    fn map_cpu(&self, address: u16, state: AbstractState) -> Option<usize> {
        if self.rom.metadata.mapper == 2 && address < 0xc000 && state.selected_prg_bank.is_none() {
            return None;
        }
        self.mapper
            .map_cpu(
                CpuAddress(address),
                MapperState {
                    prg_bank: state.selected_prg_bank.unwrap_or(0),
                    chr_bank: 0,
                },
            )
            .map(|offset| offset.0)
            .filter(|offset| *offset < self.rom.prg_rom.len())
    }

    fn decode_mapped(
        &mut self,
        cpu_address: u16,
        prg_offset: usize,
        state: AbstractState,
    ) -> Result<DecodedInstruction, DecodeError> {
        let first = *self
            .rom
            .prg_rom
            .get(prg_offset)
            .ok_or(DecodeError::EmptyInput)?;
        let metadata = opcode(first).ok_or(DecodeError::UnsupportedOpcode(first))?;
        let required = usize::from(metadata.len());
        let mut bytes = Vec::with_capacity(required);
        for index in 0..required {
            let address = cpu_address.wrapping_add(u16::try_from(index).unwrap_or(0));
            let Some(mapped) = self.map_cpu(address, state) else {
                return Err(DecodeError::Truncated {
                    opcode: first,
                    required,
                    available: index,
                });
            };
            if mapped != prg_offset + index {
                self.notice(format!(
                    "instruction at prg:{:02X}:${cpu_address:04X} crosses a noncontiguous mapper window and remains data",
                    physical_bank(prg_offset)
                ));
                return Err(DecodeError::Truncated {
                    opcode: first,
                    required,
                    available: index,
                });
            }
            bytes.push(self.rom.prg_rom[mapped]);
        }
        decode(&bytes)
    }

    fn apply_instruction_state(
        &mut self,
        source: BankAddress,
        prg_offset: usize,
        decoded: DecodedInstruction,
        state: &mut AbstractState,
    ) {
        if matches!(self.rom.metadata.mapper, 2 | 3) {
            let stored_value = match decoded.opcode.mnemonic {
                Mnemonic::Sta => state.a,
                Mnemonic::Stx => state.x,
                Mnemonic::Sty => state.y,
                _ => None,
            };
            let writes_memory = matches!(
                decoded.opcode.mnemonic,
                Mnemonic::Sta
                    | Mnemonic::Stx
                    | Mnemonic::Sty
                    | Mnemonic::Asl
                    | Mnemonic::Lsr
                    | Mnemonic::Rol
                    | Mnemonic::Ror
                    | Mnemonic::Inc
                    | Mnemonic::Dec
            ) && decoded.opcode.mode != AddressingMode::Accumulator;
            let register_address =
                if writes_memory && decoded.opcode.mode == AddressingMode::Absolute {
                    (decoded.operand() >= 0x8000).then_some(decoded.operand())
                } else {
                    None
                };
            let uncertain_mapper_store = writes_memory
                && match decoded.opcode.mode {
                    AddressingMode::AbsoluteX | AddressingMode::AbsoluteY => {
                        decoded.operand() >= 0x7f01
                    }
                    AddressingMode::IndexedIndirect | AddressingMode::IndirectIndexed => true,
                    _ => false,
                };
            if register_address.is_some() || uncertain_mapper_store {
                let known_bank = register_address.is_some().then_some(stored_value).flatten();
                let (bank_kind, resulting_bank) = if self.rom.metadata.mapper == 2 {
                    state.selected_prg_bank = known_bank;
                    let resulting = state.selected_prg_bank.and_then(|bank| {
                        self.mapper
                            .map_cpu(
                                CpuAddress(0x8000),
                                MapperState {
                                    prg_bank: bank,
                                    chr_bank: 0,
                                },
                            )
                            .map(|offset| physical_bank(offset.0))
                    });
                    (MapperBankKind::Prg, resulting)
                } else {
                    state.selected_chr_bank = known_bank;
                    let resulting = state.selected_chr_bank.and_then(|bank| {
                        self.mapper
                            .map_ppu(
                                PpuAddress(0),
                                MapperState {
                                    prg_bank: 0,
                                    chr_bank: bank,
                                },
                            )
                            .and_then(|offset| u16::try_from(offset.0 / 0x2000).ok())
                    });
                    (MapperBankKind::Chr, resulting)
                };
                let write = MapperWrite {
                    source,
                    prg_offset,
                    register_address,
                    value: stored_value,
                    bank_kind,
                    resulting_bank,
                };
                if !self.mapper_writes.contains(&write) {
                    self.mapper_writes.push(write);
                }
            }
        }

        let immediate =
            (decoded.opcode.mode == AddressingMode::Immediate).then_some(decoded.operand() as u8);
        match decoded.opcode.mnemonic {
            Mnemonic::Lda => state.a = immediate,
            Mnemonic::Ldx => state.x = immediate,
            Mnemonic::Ldy => state.y = immediate,
            Mnemonic::Tax => state.x = state.a,
            Mnemonic::Tay => state.y = state.a,
            Mnemonic::Txa => state.a = state.x,
            Mnemonic::Tya => state.a = state.y,
            Mnemonic::Tsx => state.x = None,
            Mnemonic::Pla => state.a = None,
            Mnemonic::Inx => state.x = state.x.map(|value| value.wrapping_add(1)),
            Mnemonic::Dex => state.x = state.x.map(|value| value.wrapping_sub(1)),
            Mnemonic::Iny => state.y = state.y.map(|value| value.wrapping_add(1)),
            Mnemonic::Dey => state.y = state.y.map(|value| value.wrapping_sub(1)),
            Mnemonic::And => state.a = state.a.zip(immediate).map(|(left, right)| left & right),
            Mnemonic::Eor => state.a = state.a.zip(immediate).map(|(left, right)| left ^ right),
            Mnemonic::Ora => state.a = state.a.zip(immediate).map(|(left, right)| left | right),
            Mnemonic::Adc | Mnemonic::Sbc => state.a = None,
            Mnemonic::Asl | Mnemonic::Lsr | Mnemonic::Rol | Mnemonic::Ror
                if decoded.opcode.mode == AddressingMode::Accumulator =>
            {
                state.a = None;
            }
            Mnemonic::Bcc
            | Mnemonic::Bcs
            | Mnemonic::Beq
            | Mnemonic::Bit
            | Mnemonic::Bmi
            | Mnemonic::Bne
            | Mnemonic::Bpl
            | Mnemonic::Brk
            | Mnemonic::Bvc
            | Mnemonic::Bvs
            | Mnemonic::Clc
            | Mnemonic::Cld
            | Mnemonic::Cli
            | Mnemonic::Clv
            | Mnemonic::Cmp
            | Mnemonic::Cpx
            | Mnemonic::Cpy
            | Mnemonic::Dec
            | Mnemonic::Inc
            | Mnemonic::Jmp
            | Mnemonic::Jsr
            | Mnemonic::Nop
            | Mnemonic::Pha
            | Mnemonic::Php
            | Mnemonic::Plp
            | Mnemonic::Rti
            | Mnemonic::Rts
            | Mnemonic::Sec
            | Mnemonic::Sed
            | Mnemonic::Sei
            | Mnemonic::Sta
            | Mnemonic::Stx
            | Mnemonic::Sty
            | Mnemonic::Txs
            | Mnemonic::Asl
            | Mnemonic::Lsr
            | Mnemonic::Rol
            | Mnemonic::Ror => {}
        }
    }

    fn prg_file_start(&self) -> usize {
        HEADER_LEN + self.rom.trainer.as_ref().map_or(0, |_| TRAINER_LEN)
    }

    fn notice(&mut self, message: impl Into<String>) {
        self.notices.push(AnalysisNotice {
            message: message.into(),
        });
    }
}

fn physical_bank(prg_offset: usize) -> u16 {
    u16::try_from(prg_offset / PRG_BANK_LEN).unwrap_or(u16::MAX)
}

fn cpu_address_for_offset(rom: &Rom, prg_offset: usize) -> u16 {
    let bank_offset = u16::try_from(prg_offset % PRG_BANK_LEN).unwrap_or(0);
    match rom.metadata.mapper {
        2 if prg_offset / PRG_BANK_LEN == rom.prg_rom.len() / PRG_BANK_LEN - 1 => {
            0xc000 + bank_offset
        }
        2 => 0x8000 + bank_offset,
        _ if rom.prg_rom.len() == PRG_BANK_LEN => 0xc000 + bank_offset,
        _ => 0x8000 + u16::try_from(prg_offset).unwrap_or(0),
    }
}

fn synthetic_label(prg_offset: usize, cpu_address: u16) -> String {
    format!("L_prg{:02X}_{cpu_address:04X}", physical_bank(prg_offset))
}

fn render_assembly(disassembly: &Disassembly) -> String {
    let mapper = disassembly.rom.metadata.mapper;
    let mut assembly = format!(
        "; Deterministic Mapper {mapper} recovery generated by nesc-toolchain\n\
         ; Unproven and undocumented bytes remain explicit data.\n\
         .setcpu \"6502\"\n\
         .segment \"PRG\"\n"
    );
    if !disassembly.labels.is_empty() {
        assembly.push_str("\n; Stable bank-qualified CPU symbols\n");
        for label in &disassembly.labels {
            assembly.push_str(&format!(
                "{} = ${:04X} ; PRG bank {:02X}, offset ${:05X}\n",
                label.name, label.address.cpu_address, label.address.bank, label.prg_offset
            ));
        }
    }
    let mut offset = 0;
    while offset < disassembly.rom.prg_rom.len() {
        if offset % PRG_BANK_LEN == 0 {
            let bank = physical_bank(offset);
            let origin = cpu_address_for_offset(&disassembly.rom, offset);
            if mapper == 2 {
                assembly.push_str(&format!(
                    "\n; Physical PRG bank {bank:02X}\n.nesc_prg_bank {bank}, ${origin:04X}\n"
                ));
            } else {
                assembly.push_str(&format!(
                    "\n; Physical PRG bank {bank:02X}\n.org ${origin:04X}\n"
                ));
            }
        }
        if let Some(instruction) = disassembly.instructions.get(&offset) {
            assembly.push_str("    ");
            assembly.push_str(instruction.decoded.opcode.mnemonic.as_str());
            if let Some(operand) = render_operand(disassembly, instruction) {
                assembly.push(' ');
                assembly.push_str(&operand);
            }
            let mapper_state = match mapper {
                2 => format!(
                    " selected-prg:{}",
                    render_mapper_banks(&instruction.selected_prg_banks)
                ),
                3 => format!(
                    " selected-chr:{}",
                    render_mapper_banks(&instruction.selected_chr_banks)
                ),
                _ => String::new(),
            };
            assembly.push_str(&format!(
                " ; prg:{:02X}:${:04X}{mapper_state} file:${:05X}\n",
                instruction.address.bank,
                instruction.address.cpu_address,
                instruction.rom_file_offset
            ));
            offset += instruction.decoded.bytes().len();
            continue;
        }
        let start = offset;
        let bank_end = ((offset / PRG_BANK_LEN) + 1) * PRG_BANK_LEN;
        while offset < disassembly.rom.prg_rom.len()
            && offset < bank_end
            && offset - start < 16
            && !disassembly.instructions.contains_key(&offset)
        {
            offset += 1;
        }
        let bytes = &disassembly.rom.prg_rom[start..offset];
        assembly.push_str("    .byte ");
        for (index, byte) in bytes.iter().enumerate() {
            if index != 0 {
                assembly.push_str(", ");
            }
            assembly.push_str(&format!("${byte:02X}"));
        }
        assembly.push_str(&format!(" ; PRG offset ${start:05X}\n"));
    }
    if !disassembly.mapper_writes.is_empty() {
        assembly.push_str("\n; Mapper writes\n");
        for write in &disassembly.mapper_writes {
            assembly.push_str(&format!(
                "; prg:{:02X}:${:04X} address {} value {} resulting-{}-bank {}\n",
                write.source.bank,
                write.source.cpu_address,
                write
                    .register_address
                    .map_or_else(|| "unknown".to_owned(), |value| format!("${value:04X}")),
                write
                    .value
                    .map_or_else(|| "unknown".to_owned(), |value| format!("${value:02X}")),
                match write.bank_kind {
                    MapperBankKind::Prg => "prg",
                    MapperBankKind::Chr => "chr",
                },
                write
                    .resulting_bank
                    .map_or_else(|| "unknown".to_owned(), |value| format!("{value:02X}")),
            ));
        }
    }
    if !disassembly.unresolved.is_empty() {
        assembly.push_str("\n; Unresolved control flow\n");
        for unresolved in &disassembly.unresolved {
            assembly.push_str(&format!(
                "; prg:{:02X}:${:04X} {:?} target ${:04X}\n",
                unresolved.source.bank,
                unresolved.source.cpu_address,
                unresolved.flow,
                unresolved.target
            ));
        }
    }
    assembly
}

fn render_mapper_banks(banks: &[Option<u16>]) -> String {
    banks
        .iter()
        .map(|bank| bank.map_or_else(|| "?".to_owned(), |bank| format!("{bank:02X}")))
        .collect::<Vec<_>>()
        .join("|")
}

fn render_operand(disassembly: &Disassembly, instruction: &Instruction) -> Option<String> {
    let decoded = instruction.decoded;
    let operand = decoded.operand();
    let byte = operand as u8;
    let absolute_target = || {
        target_label(disassembly, instruction, operand).unwrap_or_else(|| format!("${operand:04X}"))
    };
    match decoded.opcode.mode {
        AddressingMode::Implied => None,
        AddressingMode::Accumulator => Some("a".to_owned()),
        AddressingMode::Immediate => Some(format!("#${byte:02X}")),
        AddressingMode::ZeroPage => Some(format!("${byte:02X}")),
        AddressingMode::ZeroPageX => Some(format!("${byte:02X},x")),
        AddressingMode::ZeroPageY => Some(format!("${byte:02X},y")),
        AddressingMode::Relative => {
            let delta = i16::from(decoded.opcode.len()) + i16::from(byte as i8);
            Some(if delta < 0 {
                format!("*-{}", -delta)
            } else {
                format!("*+{delta}")
            })
        }
        AddressingMode::Absolute => {
            if matches!(decoded.opcode.flow(), FlowControl::Call | FlowControl::Jump) {
                Some(absolute_target())
            } else {
                Some(format!("${operand:04X}"))
            }
        }
        AddressingMode::AbsoluteX => Some(format!("${operand:04X},x")),
        AddressingMode::AbsoluteY => Some(format!("${operand:04X},y")),
        AddressingMode::Indirect => Some(format!("(${operand:04X})")),
        AddressingMode::IndexedIndirect => Some(format!("(${byte:02X},x)")),
        AddressingMode::IndirectIndexed => Some(format!("(${byte:02X}),y")),
    }
}

fn target_label(
    disassembly: &Disassembly,
    instruction: &Instruction,
    cpu_address: u16,
) -> Option<String> {
    let target_bank = if disassembly.rom.metadata.mapper == 2 {
        if cpu_address >= 0xc000 {
            u16::try_from(disassembly.rom.prg_rom.len() / PRG_BANK_LEN - 1).ok()?
        } else if instruction.selected_prg_banks.len() == 1 {
            instruction.selected_prg_banks[0]?
        } else {
            return None;
        }
    } else {
        return disassembly
            .labels
            .iter()
            .find(|label| label.address.cpu_address == cpu_address)
            .map(|label| label.name.clone());
    };
    disassembly
        .labels
        .iter()
        .find(|label| label.address.cpu_address == cpu_address && label.address.bank == target_bank)
        .map(|label| label.name.clone())
}

#[cfg(test)]
mod tests {
    use nesc_rom::{Format, Metadata, Mirroring, Region, Rom, build};

    use super::{
        AnalysisLimits, ByteClassification, FlowControl, MapperBankKind, VectorKind, disassemble,
    };

    fn nrom_with_program(program: &[u8], reset: u16) -> Vec<u8> {
        let mut prg = vec![0xff; 16 * 1024];
        prg[..program.len()].copy_from_slice(program);
        let vectors = prg.len() - 6;
        for (offset, vector) in [(0, reset), (2, reset), (4, reset)] {
            prg[vectors + offset..vectors + offset + 2].copy_from_slice(&vector.to_le_bytes());
        }
        build(&Rom {
            metadata: Metadata {
                format: Format::Nes2,
                mapper: 0,
                submapper: 0,
                mirroring: Mirroring::Horizontal,
                battery: false,
                region: Region::Ntsc,
                prg_rom_len: prg.len(),
                chr_rom_len: 0,
            },
            trainer: None,
            prg_rom: prg,
            chr_rom: Vec::new(),
        })
        .expect("valid NROM")
    }

    fn uxrom_with_banked_call() -> Vec<u8> {
        let mut prg = vec![0xff; 4 * 16 * 1024];
        prg[16 * 1024..16 * 1024 + 3].copy_from_slice(&[0xa9, 0x2a, 0x60]);
        let fixed = 3 * 16 * 1024;
        prg[fixed..fixed + 9].copy_from_slice(&[
            0xa9, 0x01, // lda #1
            0x8d, 0x00, 0x80, // sta $8000
            0x20, 0x00, 0x80, // jsr $8000
            0x60, // rts
        ]);
        let vectors = prg.len() - 6;
        for offset in [0, 2, 4] {
            prg[vectors + offset..vectors + offset + 2].copy_from_slice(&0xc000_u16.to_le_bytes());
        }
        build(&Rom {
            metadata: Metadata {
                format: Format::Nes2,
                mapper: 2,
                submapper: 0,
                mirroring: Mirroring::Horizontal,
                battery: false,
                region: Region::Ntsc,
                prg_rom_len: prg.len(),
                chr_rom_len: 0,
            },
            trainer: None,
            prg_rom: prg,
            chr_rom: Vec::new(),
        })
        .expect("valid UxROM")
    }

    fn cnrom_with_chr_switch() -> Vec<u8> {
        let mut prg = vec![0xff; 16 * 1024];
        prg[..6].copy_from_slice(&[
            0xa9, 0x02, // lda #2
            0x8d, 0x00, 0x80, // sta $8000
            0x60, // rts
        ]);
        let vectors = prg.len() - 6;
        for offset in [0, 2, 4] {
            prg[vectors + offset..vectors + offset + 2].copy_from_slice(&0xc000_u16.to_le_bytes());
        }
        build(&Rom {
            metadata: Metadata {
                format: Format::Nes2,
                mapper: 3,
                submapper: 0,
                mirroring: Mirroring::Horizontal,
                battery: false,
                region: Region::Ntsc,
                prg_rom_len: prg.len(),
                chr_rom_len: 4 * 8 * 1024,
            },
            trainer: None,
            prg_rom: prg,
            chr_rom: (0..4_u8)
                .flat_map(|bank| std::iter::repeat_n(bank, 8 * 1024))
                .collect(),
        })
        .expect("valid CNROM")
    }

    #[test]
    fn follows_vectors_calls_branches_and_preserves_data() {
        let rom = nrom_with_program(
            &[
                0x20, 0x08, 0xc0, // jsr $c008
                0xd0, 0x02, // bne $c007
                0x02, 0xaa, // undocumented data
                0x60, // rts
                0xa9, 0x2a, 0x60, // lda #$2a; rts
            ],
            0xc000,
        );
        let disassembly = disassemble(&rom, AnalysisLimits::default()).expect("disassembly");
        disassembly
            .verify_recovery()
            .expect("lossless PRG recovery");
        assert_eq!(disassembly.instructions.len(), 5);
        assert_eq!(disassembly.classification[5], ByteClassification::Data);
        assert_eq!(disassembly.classification[6], ByteClassification::Data);
        assert!(
            disassembly
                .entry_points
                .iter()
                .any(|entry| entry.kind == VectorKind::Reset)
        );
        let assembly = disassembly.assembly();
        assert!(assembly.contains("jsr L_prg00_C008"));
        assert!(assembly.contains(".byte $02, $AA"));
    }

    #[test]
    fn records_indirect_jump_without_inventing_an_edge() {
        let rom = nrom_with_program(&[0x6c, 0x00, 0x02], 0xc000);
        let disassembly = disassemble(&rom, AnalysisLimits::default()).expect("disassembly");
        assert_eq!(disassembly.unresolved.len(), 1);
        assert_eq!(disassembly.unresolved[0].flow, FlowControl::IndirectJump);
        assert_eq!(disassembly.unresolved[0].target, 0x0200);
    }

    #[test]
    fn follows_known_uxrom_bank_writes_into_switchable_code() {
        let rom = uxrom_with_banked_call();
        let disassembly = disassemble(&rom, AnalysisLimits::default()).expect("disassembly");
        disassembly.verify_recovery().expect("lossless recovery");
        assert!(disassembly.instructions.contains_key(&(3 * 16 * 1024)));
        assert!(disassembly.instructions.contains_key(&(16 * 1024)));
        assert_eq!(disassembly.mapper_writes.len(), 1);
        assert_eq!(disassembly.mapper_writes[0].value, Some(1));
        assert_eq!(disassembly.mapper_writes[0].resulting_bank, Some(1));
        assert!(
            disassembly
                .labels
                .iter()
                .any(|label| { label.address.bank == 1 && label.address.cpu_address == 0x8000 })
        );
        let assembly = disassembly.assembly();
        assert!(assembly.contains("Deterministic Mapper 2 recovery"));
        assert!(assembly.contains(".nesc_prg_bank 1, $8000"));
        assert!(assembly.contains(".nesc_prg_bank 3, $C000"));
        assert!(assembly.contains("jsr L_prg01_8000"));
    }

    #[test]
    fn preserves_unknown_uxrom_bank_state_without_guessing_an_edge() {
        let original = uxrom_with_banked_call();
        let mut cartridge = nesc_rom::parse(&original).expect("UxROM parse");
        let fixed = 3 * 16 * 1024;
        cartridge.prg_rom[fixed..fixed + 10].copy_from_slice(&[
            0xad, 0x00, 0x00, // lda $0000
            0x8d, 0x00, 0x80, // sta $8000
            0x20, 0x00, 0x80, // jsr $8000
            0x60, // rts
        ]);
        let rom = build(&cartridge).expect("valid UxROM");
        let disassembly = disassemble(&rom, AnalysisLimits::default()).expect("disassembly");
        assert_eq!(disassembly.mapper_writes.len(), 1);
        assert_eq!(disassembly.mapper_writes[0].value, None);
        assert_eq!(disassembly.mapper_writes[0].resulting_bank, None);
        assert!(!disassembly.instructions.contains_key(&(16 * 1024)));
        assert!(disassembly.unresolved.iter().any(|flow| {
            flow.source.bank == 3 && flow.target == 0x8000 && flow.flow == FlowControl::Call
        }));
    }

    #[test]
    fn follows_cnrom_chr_bank_writes_without_changing_prg_flow() {
        let rom = cnrom_with_chr_switch();
        let disassembly = disassemble(&rom, AnalysisLimits::default()).expect("disassembly");
        disassembly.verify_recovery().expect("lossless recovery");
        assert_eq!(disassembly.mapper_writes.len(), 1);
        assert_eq!(disassembly.mapper_writes[0].bank_kind, MapperBankKind::Chr);
        assert_eq!(disassembly.mapper_writes[0].value, Some(2));
        assert_eq!(disassembly.mapper_writes[0].resulting_bank, Some(2));
        assert_eq!(
            disassembly.instructions[&5].selected_chr_banks,
            vec![Some(2)]
        );
        let assembly = disassembly.assembly();
        assert!(assembly.contains("Deterministic Mapper 3 recovery"));
        assert!(assembly.contains("selected-chr:02"));
        assert!(assembly.contains("resulting-chr-bank 02"));
    }

    #[test]
    fn enforces_instruction_resource_limit() {
        let rom = nrom_with_program(&[0xea, 0xea, 0x60], 0xc000);
        let error = disassemble(
            &rom,
            AnalysisLimits {
                max_instructions: 1,
                max_work_items: 8,
            },
        )
        .expect_err("instruction limit");
        assert!(error.message().contains("instruction analysis limit"));
    }

    #[test]
    fn rejects_unsupported_mapper_recursive_analysis() {
        let mut rom = nrom_with_program(&[0x60], 0xc000);
        rom[6] = 0x40;
        let error = disassemble(&rom, AnalysisLimits::default()).expect_err("Mapper 4");
        assert!(error.message().contains("Mapper 0, Mapper 2, and Mapper 3"));
    }

    #[test]
    fn reports_first_complete_rom_mismatch_with_mapping() {
        let rom = nrom_with_program(&[0x60], 0xc000);
        let disassembly = disassemble(&rom, AnalysisLimits::default()).expect("disassembly");
        let mut rebuilt = rom.clone();
        rebuilt[16 + 0x123] ^= 0xff;
        let error = disassembly
            .verify_rom_rebuild(&rom, &rebuilt)
            .expect_err("mismatch");
        assert!(error.message().contains("file offset $00133"));
        assert!(error.message().contains("physical bank 00"));
        assert!(error.message().contains("CPU $C123"));
    }
}
