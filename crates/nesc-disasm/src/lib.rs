//! Mapper-aware, lossless NES ROM disassembly.

mod decoder;

use std::collections::{BTreeMap, HashSet, VecDeque};
use std::error::Error;
use std::fmt;

use nesc_rom::{CpuAddress, Mapper, MapperState, Rom};

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

/// Complete NROM recursive-analysis result.
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

/// Parses and recursively analyzes an NROM image.
///
/// # Errors
///
/// Returns a diagnostic for malformed input, an unsupported mapper, an
/// impossible NROM layout, or exhausted analysis limits.
pub fn disassemble(bytes: &[u8], limits: AnalysisLimits) -> Result<Disassembly, DisassemblyError> {
    let rom = nesc_rom::parse(bytes).map_err(|error| DisassemblyError::new(error.to_string()))?;
    disassemble_rom(rom, limits)
}

/// Recursively analyzes a parsed NROM image.
///
/// # Errors
///
/// Returns a diagnostic for an unsupported mapper, an impossible layout, or
/// exhausted analysis limits.
pub fn disassemble_rom(rom: Rom, limits: AnalysisLimits) -> Result<Disassembly, DisassemblyError> {
    if rom.metadata.mapper != 0 {
        return Err(DisassemblyError::new(format!(
            "recursive disassembly currently supports Mapper 0, not Mapper {}",
            rom.metadata.mapper
        )));
    }
    if limits.max_instructions == 0 || limits.max_work_items == 0 {
        return Err(DisassemblyError::new(
            "analysis limits must permit at least one instruction and work item",
        ));
    }
    let mapper = Mapper::new(0, rom.prg_rom.len(), rom.chr_rom.len())
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
    notices: Vec<AnalysisNotice>,
    work: VecDeque<u16>,
    queued: HashSet<(usize, u16)>,
    work_items: usize,
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
            notices: Vec::new(),
            work: VecDeque::new(),
            queued: HashSet::new(),
            work_items: 0,
        }
    }

    fn run(mut self) -> Result<Disassembly, DisassemblyError> {
        self.seed_vector(VectorKind::Nmi, NMI_VECTOR)?;
        self.seed_vector(VectorKind::Reset, RESET_VECTOR)?;
        self.seed_vector(VectorKind::Irq, IRQ_VECTOR)?;
        while let Some(address) = self.work.pop_front() {
            self.walk(address)?;
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
            notices: self.notices,
        })
    }

    fn seed_vector(
        &mut self,
        kind: VectorKind,
        vector_address: u16,
    ) -> Result<(), DisassemblyError> {
        let Some(destination) = self.read_mapped_word(vector_address) else {
            self.notice(format!(
                "{} vector at ${vector_address:04X} is not readable from PRG-ROM",
                kind.name()
            ));
            return Ok(());
        };
        let Some(prg_offset) = self.map_cpu(destination) else {
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
        self.enqueue(destination)
    }

    fn walk(&mut self, mut cpu_address: u16) -> Result<(), DisassemblyError> {
        loop {
            let Some(prg_offset) = self.map_cpu(cpu_address) else {
                return Ok(());
            };
            if let Some(existing) = self.instructions.get(&prg_offset) {
                if existing.address.cpu_address != cpu_address {
                    self.notice(format!(
                        "physical PRG offset ${prg_offset:05X} is reached through aliases ${:04X} and ${cpu_address:04X}",
                        existing.address.cpu_address
                    ));
                }
                return Ok(());
            }
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
            let decoded = match decode(&self.rom.prg_rom[prg_offset..]) {
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
            let address = BankAddress {
                bank: physical_bank(prg_offset),
                cpu_address,
            };
            let flow = decoded.opcode.flow();
            let operand = decoded.operand();
            self.instructions.insert(
                prg_offset,
                Instruction {
                    address,
                    prg_offset,
                    rom_file_offset: self.prg_file_start() + prg_offset,
                    decoded,
                },
            );
            let next = cpu_address.wrapping_add(u16::from(decoded.opcode.len()));
            match flow {
                FlowControl::Fallthrough => cpu_address = next,
                FlowControl::Branch => {
                    let target = next.wrapping_add_signed(i16::from(decoded.bytes()[1] as i8));
                    self.follow_direct(address, prg_offset, flow, target)?;
                    cpu_address = next;
                }
                FlowControl::Call => {
                    self.follow_direct(address, prg_offset, flow, operand)?;
                    cpu_address = next;
                }
                FlowControl::Jump => {
                    self.follow_direct(address, prg_offset, flow, operand)?;
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
    ) -> Result<(), DisassemblyError> {
        let Some(target_offset) = self.map_cpu(target) else {
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
        self.enqueue(target)
    }

    fn enqueue(&mut self, cpu_address: u16) -> Result<(), DisassemblyError> {
        let Some(prg_offset) = self.map_cpu(cpu_address) else {
            return Ok(());
        };
        if !self.queued.insert((prg_offset, cpu_address)) {
            return Ok(());
        }
        if self.work_items >= self.limits.max_work_items {
            return Err(DisassemblyError::new(format!(
                "control-flow work-item limit {} exceeded",
                self.limits.max_work_items
            )));
        }
        self.work_items += 1;
        self.work.push_back(cpu_address);
        Ok(())
    }

    fn read_mapped_word(&self, address: u16) -> Option<u16> {
        let low = self
            .map_cpu(address)
            .and_then(|offset| self.rom.prg_rom.get(offset))?;
        let high = self
            .map_cpu(address.wrapping_add(1))
            .and_then(|offset| self.rom.prg_rom.get(offset))?;
        Some(u16::from_le_bytes([*low, *high]))
    }

    fn map_cpu(&self, address: u16) -> Option<usize> {
        self.mapper
            .map_cpu(CpuAddress(address), MapperState::default())
            .map(|offset| offset.0)
            .filter(|offset| *offset < self.rom.prg_rom.len())
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

fn synthetic_label(prg_offset: usize, cpu_address: u16) -> String {
    format!("L_prg{:02X}_{cpu_address:04X}", physical_bank(prg_offset))
}

fn render_assembly(disassembly: &Disassembly) -> String {
    let mut assembly = String::from(
        "; Deterministic Mapper 0 recovery generated by nesc-toolchain\n\
         ; Unproven and undocumented bytes remain explicit data.\n\
         .setcpu \"6502\"\n\
         .segment \"PRG\"\n",
    );
    let labels = labels_by_offset(&disassembly.labels);
    let mut offset = 0;
    while offset < disassembly.rom.prg_rom.len() {
        if offset % PRG_BANK_LEN == 0 {
            let origin = if disassembly.rom.prg_rom.len() == PRG_BANK_LEN {
                0xc000
            } else {
                0x8000 + u16::try_from(offset).unwrap_or(0)
            };
            assembly.push_str(&format!(
                "\n; Physical PRG bank {:02X}\n.org ${origin:04X}\n",
                physical_bank(offset)
            ));
        }
        if let Some(offset_labels) = labels.get(&offset) {
            for label in offset_labels {
                assembly.push_str(&label.name);
                assembly.push_str(":\n");
            }
        }
        if let Some(instruction) = disassembly.instructions.get(&offset) {
            assembly.push_str("    ");
            assembly.push_str(instruction.decoded.opcode.mnemonic.as_str());
            if let Some(operand) = render_operand(disassembly, instruction) {
                assembly.push(' ');
                assembly.push_str(&operand);
            }
            assembly.push_str(&format!(
                " ; prg:{:02X}:${:04X} file:${:05X}\n",
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
            && (offset == start || !labels.contains_key(&offset))
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

fn labels_by_offset(labels: &[Label]) -> BTreeMap<usize, Vec<&Label>> {
    let mut by_offset = BTreeMap::<usize, Vec<&Label>>::new();
    for label in labels {
        by_offset.entry(label.prg_offset).or_default().push(label);
    }
    by_offset
}

fn render_operand(disassembly: &Disassembly, instruction: &Instruction) -> Option<String> {
    let decoded = instruction.decoded;
    let operand = decoded.operand();
    let byte = operand as u8;
    let absolute_target =
        || target_label(disassembly, operand).unwrap_or_else(|| format!("${operand:04X}"));
    match decoded.opcode.mode {
        AddressingMode::Implied => None,
        AddressingMode::Accumulator => Some("a".to_owned()),
        AddressingMode::Immediate => Some(format!("#${byte:02X}")),
        AddressingMode::ZeroPage => Some(format!("${byte:02X}")),
        AddressingMode::ZeroPageX => Some(format!("${byte:02X},x")),
        AddressingMode::ZeroPageY => Some(format!("${byte:02X},y")),
        AddressingMode::Relative => {
            let next = instruction
                .address
                .cpu_address
                .wrapping_add(u16::from(decoded.opcode.len()));
            let target = next.wrapping_add_signed(i16::from(byte as i8));
            Some(target_label(disassembly, target).unwrap_or_else(|| format!("${target:04X}")))
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

fn target_label(disassembly: &Disassembly, cpu_address: u16) -> Option<String> {
    let mapper = Mapper::new(
        disassembly.rom.metadata.mapper,
        disassembly.rom.prg_rom.len(),
        disassembly.rom.chr_rom.len(),
    )
    .ok()?;
    let offset = mapper
        .map_cpu(CpuAddress(cpu_address), MapperState::default())?
        .0;
    disassembly
        .labels
        .iter()
        .find(|label| label.prg_offset == offset && label.address.cpu_address == cpu_address)
        .map(|label| label.name.clone())
}

#[cfg(test)]
mod tests {
    use nesc_rom::{Format, Metadata, Mirroring, Region, Rom, build};

    use super::{AnalysisLimits, ByteClassification, FlowControl, VectorKind, disassemble};

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
    fn rejects_non_nrom_recursive_analysis() {
        let mut rom = nrom_with_program(&[0x60], 0xc000);
        rom[6] = 0x20;
        let error = disassemble(&rom, AnalysisLimits::default()).expect_err("Mapper 2");
        assert!(error.message().contains("Mapper 0"));
    }
}
