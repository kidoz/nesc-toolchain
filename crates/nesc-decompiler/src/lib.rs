//! Provenance-rich 6502 semantic lifting, value, ABI, and type recovery.

mod nesc_emitter;
mod recovery_analysis;
mod rust_emitter;
mod structuring;
mod value_analysis;

pub use nesc_emitter::{NesCEmissionLimits, NesCEmitConfig, NesCProject, emit_nesc_project};
pub use recovery_analysis::{
    AbiByte, CallEdge, CallGraphCycle, CallingConvention, FunctionRecovery, PointerFact,
    RecoveredType, RecoveryAnalysis, RecoveryEvidence, RecoveryEvidenceKind, RecoveryLimits,
    Signedness, TypeFact, TypeSubject, Volatility, analyze_recovery,
};
pub use rust_emitter::{
    RustEmissionLimits, RustEmitConfig, RustProject, RustVerificationLimits, emit_rust_project,
    emit_rust_verification,
};
pub use structuring::{
    ControlEdge, ControlFlowAnalysis, ControlFlowLimits, CountedLoop, FallbackReason, LoopForm,
    RegionId, StructureEvidence, StructureEvidenceKind, StructuredFunction, StructuredRegion,
    StructuredRegionKind, structure_control_flow,
};

pub use value_analysis::{
    Barrier, BarrierKind, BlockValueState, ComparisonPredicate, Confidence, FunctionSummary,
    FunctionValueAnalysis, MemoryLocation, PhiInput, RecoveredCondition, RecoveredPredicate,
    StateVariable, UnknownReason, ValueAnalysis, ValueAnalysisLimits, ValueEvidence,
    ValueEvidenceKind, ValueExpression, ValueId, ValueNode, ValueOperator, analyze_values,
};

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::error::Error;
use std::fmt;

use nesc_disasm::{
    AddressingMode, BankAddress, Disassembly, FlowControl, Instruction as DisassembledInstruction,
    Mnemonic, VectorKind,
};

/// Resource limits for untrusted decompilation inputs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AnalysisLimits {
    /// Maximum basic-block count.
    pub max_blocks: usize,
    /// Maximum recovered function-root count.
    pub max_functions: usize,
    /// Maximum explicit control-flow edge count.
    pub max_edges: usize,
    /// Maximum semantic-operation count.
    pub max_operations: usize,
}

impl Default for AnalysisLimits {
    fn default() -> Self {
        Self {
            max_blocks: 200_000,
            max_functions: 100_000,
            max_edges: 500_000,
            max_operations: 2_000_000,
        }
    }
}

/// Stable physical and mapped identity for a basic block.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct BlockId {
    /// Physical 16 KiB PRG bank.
    pub bank: u16,
    /// Mapped CPU address selected by recursive analysis.
    pub cpu_address: u16,
    /// Physical byte offset within PRG-ROM.
    pub prg_offset: usize,
}

/// Stable recovered-function identifier.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct FunctionId(pub u32);

/// Exact source evidence attached to a lifted instruction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Provenance {
    /// Original ROM container offset.
    pub rom_file_offset: usize,
    /// Physical PRG-ROM offset.
    pub prg_offset: usize,
    /// Physical bank and mapped CPU address.
    pub address: BankAddress,
    /// Original encoded instruction bytes.
    pub bytes: Vec<u8>,
}

/// Ricoh CPU register represented by the semantic IR.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum Register {
    A,
    X,
    Y,
    StackPointer,
    ProgramCounter,
}

/// Individual processor status flag.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum Flag {
    Carry,
    Zero,
    InterruptDisable,
    Decimal,
    Break,
    Overflow,
    Negative,
}

/// Flags read and written by one instruction.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct FlagEffects {
    /// Flags whose incoming values affect the instruction.
    pub reads: Vec<Flag>,
    /// Flags assigned by the instruction.
    pub writes: Vec<Flag>,
}

/// NES CPU-bus address-space classification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AddressSpace {
    ZeroPage,
    InternalRam,
    PpuRegister,
    ApuRegister,
    IoRegister,
    Expansion,
    PrgRam,
    PrgRom,
    MapperRegister,
    Unknown,
}

/// Observable NES hardware behavior associated with a memory access.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HardwareEffect {
    Ppu,
    Apu,
    Controller,
    Dma,
    Mapper,
    Expansion,
}

/// Effective memory operand with explicit addressing and side-effect evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MemoryOperand {
    /// Original 6502 addressing mode.
    pub mode: AddressingMode,
    /// Encoded base or pointer value.
    pub encoded: u16,
    /// Index register applied by the addressing mode.
    pub index: Option<Register>,
    /// Whether the effective address is loaded indirectly through zero page.
    pub indirect: bool,
    /// Whether pointer arithmetic wraps within zero page.
    pub zero_page_wrap: bool,
    /// Conservatively classified target address space.
    pub address_space: AddressSpace,
    /// Known hardware subsystem affected by the access.
    pub hardware_effect: Option<HardwareEffect>,
    /// Whether the access must remain observable and ordered.
    pub volatile: bool,
}

/// Value source consumed by a semantic operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ValueSource {
    Register(Register),
    Immediate(u8),
    Memory(MemoryOperand),
    Status,
}

/// Writable destination of a semantic operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ValueTarget {
    Register(Register),
    Memory(MemoryOperand),
    Status,
}

/// Accumulator arithmetic or logical operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AccumulatorOperator {
    AddWithCarry,
    SubtractWithCarry,
    And,
    Or,
    ExclusiveOr,
}

/// Decimal-adjust behavior for arithmetic instructions.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DecimalBehavior {
    /// Operation has no decimal-sensitive interpretation.
    NotApplicable,
    /// Ricoh 2A03/2A07 ADC and SBC always use binary arithmetic.
    Ignored,
}

/// Shift or rotate behavior.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ShiftOperator {
    ArithmeticLeft,
    LogicalRight,
    RotateLeft,
    RotateRight,
}

/// Explicit hardware-stack control behavior.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StackControl {
    PushReturnAddress,
    PopReturnAddress,
    PushInterruptFrame,
    PopInterruptFrame,
}

/// One architecture-level semantic operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SemanticOperation {
    Load {
        destination: Register,
        source: ValueSource,
    },
    Store {
        destination: MemoryOperand,
        source: Register,
    },
    Accumulate {
        operator: AccumulatorOperator,
        source: ValueSource,
        carry_input: bool,
        decimal: DecimalBehavior,
    },
    Compare {
        left: Register,
        right: ValueSource,
    },
    TestBits {
        source: ValueSource,
    },
    Shift {
        operator: ShiftOperator,
        target: ValueTarget,
        carry_input: bool,
    },
    Adjust {
        target: ValueTarget,
        delta: i8,
    },
    Transfer {
        source: Register,
        destination: Register,
        update_negative_zero: bool,
    },
    SetFlag {
        flag: Flag,
        value: bool,
    },
    Push {
        source: ValueSource,
    },
    Pull {
        destination: ValueTarget,
        update_negative_zero: bool,
    },
    StackControl(StackControl),
    NoOperation,
}

/// One decoded instruction lifted without discarding machine-level evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SemanticInstruction {
    /// Original mnemonic.
    pub mnemonic: Mnemonic,
    /// Exact source evidence.
    pub provenance: Provenance,
    /// Ordered semantic effects.
    pub operations: Vec<SemanticOperation>,
    /// Processor flags read and written.
    pub flags: FlagEffects,
}

/// Conditional-branch predicate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BranchCondition {
    CarryClear,
    CarrySet,
    Equal,
    Minus,
    NotEqual,
    Plus,
    OverflowClear,
    OverflowSet,
}

/// A resolved block or explicit unresolved CPU destination.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BlockTarget {
    Resolved(BlockId),
    Unresolved { cpu_address: u16 },
}

/// Reason a block cannot continue with a proven edge.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StopReason {
    MissingInstruction { cpu_address: u16 },
    IndirectJump { pointer: u16 },
}

/// Complete control behavior at the end of a basic block.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Terminator {
    Fallthrough(BlockTarget),
    Branch {
        condition: BranchCondition,
        taken: BlockTarget,
        not_taken: BlockTarget,
    },
    Call {
        callee: BlockTarget,
        continuation: BlockTarget,
    },
    Jump(BlockTarget),
    Return,
    ReturnFromInterrupt,
    Interrupt,
    Stop(StopReason),
}

/// Bank-qualified basic block.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BasicBlock {
    /// Stable block identity.
    pub id: BlockId,
    /// Contiguous lifted instructions.
    pub instructions: Vec<SemanticInstruction>,
    /// Explicit terminal control behavior.
    pub terminator: Terminator,
}

/// Explicit graph edge category.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EdgeKind {
    Fallthrough,
    BranchTaken,
    BranchNotTaken,
    CallTarget,
    CallContinuation,
    Jump,
}

/// One resolved or unresolved graph edge.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Edge {
    /// Source block.
    pub source: BlockId,
    /// Relationship category.
    pub kind: EdgeKind,
    /// Resolved destination block.
    pub target: Option<BlockId>,
    /// Encoded CPU destination when resolution failed.
    pub unresolved_cpu_address: Option<u16>,
}

/// Proven reason a recovered function root exists.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FunctionEvidence {
    Vector(VectorKind),
    DirectCall(Provenance),
    ReachableComponent,
}

/// Recovered function root and its intraprocedural block set.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Function {
    /// Stable numeric identity.
    pub id: FunctionId,
    /// Stable synthetic or vector-derived name.
    pub name: String,
    /// Entry block.
    pub entry: BlockId,
    /// Blocks reachable without traversing into callees.
    pub blocks: Vec<BlockId>,
    /// Evidence establishing this root.
    pub evidence: Vec<FunctionEvidence>,
}

/// Complete semantic and control-flow analysis.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Program {
    /// Cartridge mapper whose reset-state mapping was analyzed.
    pub mapper: u16,
    /// Blocks ordered by stable identity.
    pub blocks: BTreeMap<BlockId, BasicBlock>,
    /// Explicit control-flow edges.
    pub edges: Vec<Edge>,
    /// Recovered function roots.
    pub functions: Vec<Function>,
}

/// Bounded analysis or graph-verification failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AnalysisError {
    message: String,
}

impl AnalysisError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    /// Returns the deterministic diagnostic text.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for AnalysisError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl Error for AnalysisError {}

/// Builds and verifies semantic IR and a bank-qualified CFG.
///
/// # Errors
///
/// Returns deterministic failures when resource limits are exhausted or the
/// constructed graph violates ownership, edge, terminator, or provenance
/// invariants.
pub fn analyze(
    disassembly: &Disassembly,
    limits: AnalysisLimits,
) -> Result<Program, Vec<AnalysisError>> {
    if disassembly.rom.metadata.mapper != 0 {
        return Err(vec![AnalysisError::new(format!(
            "semantic lifting currently supports Mapper 0, not Mapper {}",
            disassembly.rom.metadata.mapper
        ))]);
    }
    if limits.max_blocks == 0
        || limits.max_functions == 0
        || limits.max_edges == 0
        || limits.max_operations == 0
    {
        return Err(vec![AnalysisError::new(
            "decompiler limits must permit blocks, functions, edges, and operations",
        )]);
    }
    let leaders = discover_leaders(disassembly);
    if leaders.len() > limits.max_blocks {
        return Err(vec![AnalysisError::new(format!(
            "basic-block limit {} exceeded",
            limits.max_blocks
        ))]);
    }
    let block_ids = leaders
        .iter()
        .filter_map(|offset| {
            disassembly
                .instructions
                .get(offset)
                .map(|instruction| (*offset, block_id(instruction)))
        })
        .collect::<BTreeMap<_, _>>();
    let mut operation_count = 0_usize;
    let mut blocks = BTreeMap::new();
    for offset in &leaders {
        let Some(first) = disassembly.instructions.get(offset) else {
            continue;
        };
        let block = build_block(
            disassembly,
            first,
            &leaders,
            &block_ids,
            &mut operation_count,
            limits,
        )?;
        blocks.insert(block.id, block);
    }
    let edges = build_edges(&blocks);
    if edges.len() > limits.max_edges {
        return Err(vec![AnalysisError::new(format!(
            "control-flow edge limit {} exceeded",
            limits.max_edges
        ))]);
    }
    let functions = build_functions(disassembly, &blocks, &edges, limits)?;
    let program = Program {
        mapper: disassembly.rom.metadata.mapper,
        blocks,
        edges,
        functions,
    };
    program.verify()?;
    Ok(program)
}

impl Program {
    /// Verifies structural, provenance, and edge invariants.
    ///
    /// # Errors
    ///
    /// Returns every deterministic graph failure found.
    pub fn verify(&self) -> Result<(), Vec<AnalysisError>> {
        let mut errors = Vec::new();
        for (id, block) in &self.blocks {
            if *id != block.id {
                errors.push(AnalysisError::new(
                    "block map key differs from block identity",
                ));
            }
            let Some(first) = block.instructions.first() else {
                errors.push(AnalysisError::new(format!(
                    "block at PRG offset ${:05X} is empty",
                    block.id.prg_offset
                )));
                continue;
            };
            if first.provenance.prg_offset != block.id.prg_offset
                || first.provenance.address.bank != block.id.bank
                || first.provenance.address.cpu_address != block.id.cpu_address
            {
                errors.push(AnalysisError::new(format!(
                    "block at PRG offset ${:05X} does not match first-instruction provenance",
                    block.id.prg_offset
                )));
            }
            for pair in block.instructions.windows(2) {
                let expected = pair[0].provenance.prg_offset + pair[0].provenance.bytes.len();
                if pair[1].provenance.prg_offset != expected {
                    errors.push(AnalysisError::new(format!(
                        "block at PRG offset ${:05X} contains noncontiguous instructions",
                        block.id.prg_offset
                    )));
                }
            }
            for instruction in &block.instructions {
                if instruction.provenance.bytes.is_empty() {
                    errors.push(AnalysisError::new(format!(
                        "instruction at PRG offset ${:05X} has empty provenance",
                        instruction.provenance.prg_offset
                    )));
                }
                if instruction.operations.is_empty() {
                    errors.push(AnalysisError::new(format!(
                        "instruction at PRG offset ${:05X} has no semantic operations",
                        instruction.provenance.prg_offset
                    )));
                }
            }
            verify_targets(&block.terminator, &self.blocks, &mut errors);
        }
        if self.edges != build_edges(&self.blocks) {
            errors.push(AnalysisError::new(
                "explicit edge list does not match block terminators",
            ));
        }
        for edge in &self.edges {
            if !self.blocks.contains_key(&edge.source) {
                errors.push(AnalysisError::new("edge source block does not exist"));
            }
            if edge
                .target
                .is_some_and(|target| !self.blocks.contains_key(&target))
            {
                errors.push(AnalysisError::new("edge target block does not exist"));
            }
            if edge.target.is_some() == edge.unresolved_cpu_address.is_some() {
                errors.push(AnalysisError::new(
                    "edge must contain exactly one resolved or unresolved destination",
                ));
            }
        }
        for (index, function) in self.functions.iter().enumerate() {
            if function.id.0 as usize != index {
                errors.push(AnalysisError::new(format!(
                    "function `{}` has a noncanonical identifier",
                    function.name
                )));
            }
            if !self.blocks.contains_key(&function.entry) {
                errors.push(AnalysisError::new(format!(
                    "function `{}` entry block does not exist",
                    function.name
                )));
            }
            if !function.blocks.contains(&function.entry) {
                errors.push(AnalysisError::new(format!(
                    "function `{}` does not own its entry block",
                    function.name
                )));
            }
            if function
                .blocks
                .iter()
                .any(|block| !self.blocks.contains_key(block))
            {
                errors.push(AnalysisError::new(format!(
                    "function `{}` references an unknown block",
                    function.name
                )));
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    /// Renders deterministic analysis text for diagnostics and golden tests.
    #[must_use]
    pub fn render_text(&self) -> String {
        let mut text = format!(
            "mapper: {}\nfunctions: {}\nblocks: {}\nedges: {}\n",
            self.mapper,
            self.functions.len(),
            self.blocks.len(),
            self.edges.len()
        );
        for function in &self.functions {
            text.push_str(&format!(
                "\nfn {} {:?} entry=prg{:02X}:${:04X}\n",
                function.name, function.id, function.entry.bank, function.entry.cpu_address
            ));
            for block_id in &function.blocks {
                let block = &self.blocks[block_id];
                text.push_str(&format!(
                    "  block prg{:02X}:${:04X} offset=${:05X}\n",
                    block.id.bank, block.id.cpu_address, block.id.prg_offset
                ));
                for instruction in &block.instructions {
                    text.push_str(&format!(
                        "    ${:04X} {} {:?}\n",
                        instruction.provenance.address.cpu_address,
                        instruction.mnemonic,
                        instruction.operations
                    ));
                }
                text.push_str(&format!("    -> {:?}\n", block.terminator));
            }
        }
        text
    }
}

fn discover_leaders(disassembly: &Disassembly) -> BTreeSet<usize> {
    let mut leaders = BTreeSet::new();
    for entry in &disassembly.entry_points {
        if disassembly.instructions.contains_key(&entry.prg_offset) {
            leaders.insert(entry.prg_offset);
        }
    }
    for instruction in disassembly.instructions.values() {
        let offset = instruction.prg_offset;
        let next_offset = offset + instruction.decoded.bytes().len();
        match instruction.decoded.opcode.flow() {
            FlowControl::Branch => {
                if let Some(target) = direct_target(disassembly, instruction) {
                    leaders.insert(target);
                }
                if disassembly.instructions.contains_key(&next_offset) {
                    leaders.insert(next_offset);
                }
            }
            FlowControl::Call => {
                if let Some(target) = direct_target(disassembly, instruction) {
                    leaders.insert(target);
                }
                if disassembly.instructions.contains_key(&next_offset) {
                    leaders.insert(next_offset);
                }
            }
            FlowControl::Jump => {
                if let Some(target) = direct_target(disassembly, instruction) {
                    leaders.insert(target);
                }
            }
            FlowControl::Fallthrough
            | FlowControl::IndirectJump
            | FlowControl::Return
            | FlowControl::Interrupt => {}
        }
    }
    if leaders.is_empty()
        && let Some(offset) = disassembly.instructions.keys().next()
    {
        leaders.insert(*offset);
    }
    leaders
}

fn direct_target(
    disassembly: &Disassembly,
    instruction: &DisassembledInstruction,
) -> Option<usize> {
    let target = match instruction.decoded.opcode.flow() {
        FlowControl::Branch => {
            let next = instruction
                .address
                .cpu_address
                .wrapping_add(u16::from(instruction.decoded.opcode.len()));
            next.wrapping_add_signed(i16::from(instruction.decoded.bytes()[1] as i8))
        }
        FlowControl::Call | FlowControl::Jump => instruction.decoded.operand(),
        _ => return None,
    };
    offset_for_cpu(disassembly, target)
}

fn offset_for_cpu(disassembly: &Disassembly, cpu_address: u16) -> Option<usize> {
    disassembly
        .labels
        .iter()
        .find(|label| label.address.cpu_address == cpu_address)
        .map(|label| label.prg_offset)
        .or_else(|| {
            disassembly
                .entry_points
                .iter()
                .find(|entry| entry.address.cpu_address == cpu_address)
                .map(|entry| entry.prg_offset)
        })
        .or_else(|| {
            disassembly
                .instructions
                .values()
                .find(|instruction| instruction.address.cpu_address == cpu_address)
                .map(|instruction| instruction.prg_offset)
        })
        .filter(|offset| disassembly.instructions.contains_key(offset))
}

fn block_id(instruction: &DisassembledInstruction) -> BlockId {
    BlockId {
        bank: instruction.address.bank,
        cpu_address: instruction.address.cpu_address,
        prg_offset: instruction.prg_offset,
    }
}

fn build_block(
    disassembly: &Disassembly,
    first: &DisassembledInstruction,
    leaders: &BTreeSet<usize>,
    block_ids: &BTreeMap<usize, BlockId>,
    operation_count: &mut usize,
    limits: AnalysisLimits,
) -> Result<BasicBlock, Vec<AnalysisError>> {
    let id = block_id(first);
    let mut instructions = Vec::new();
    let mut current_offset = first.prg_offset;
    loop {
        let instruction = &disassembly.instructions[&current_offset];
        let lifted = lift_instruction(instruction);
        *operation_count = operation_count.saturating_add(lifted.operations.len());
        if *operation_count > limits.max_operations {
            return Err(vec![AnalysisError::new(format!(
                "semantic-operation limit {} exceeded",
                limits.max_operations
            ))]);
        }
        instructions.push(lifted);
        let next_offset = current_offset + instruction.decoded.bytes().len();
        let next_cpu = instruction
            .address
            .cpu_address
            .wrapping_add(u16::from(instruction.decoded.opcode.len()));
        let flow = instruction.decoded.opcode.flow();
        if flow != FlowControl::Fallthrough {
            let terminator = terminator_for(disassembly, instruction, next_offset, block_ids);
            return Ok(BasicBlock {
                id,
                instructions,
                terminator,
            });
        }
        if leaders.contains(&next_offset) {
            return Ok(BasicBlock {
                id,
                instructions,
                terminator: Terminator::Fallthrough(target_from_offset(
                    block_ids,
                    next_offset,
                    next_cpu,
                )),
            });
        }
        if !disassembly.instructions.contains_key(&next_offset) {
            return Ok(BasicBlock {
                id,
                instructions,
                terminator: Terminator::Stop(StopReason::MissingInstruction {
                    cpu_address: next_cpu,
                }),
            });
        }
        current_offset = next_offset;
    }
}

fn terminator_for(
    disassembly: &Disassembly,
    instruction: &DisassembledInstruction,
    next_offset: usize,
    block_ids: &BTreeMap<usize, BlockId>,
) -> Terminator {
    let next_cpu = instruction
        .address
        .cpu_address
        .wrapping_add(u16::from(instruction.decoded.opcode.len()));
    let direct = || {
        let cpu_address = match instruction.decoded.opcode.flow() {
            FlowControl::Branch => {
                next_cpu.wrapping_add_signed(i16::from(instruction.decoded.bytes()[1] as i8))
            }
            _ => instruction.decoded.operand(),
        };
        target_from_cpu(disassembly, block_ids, cpu_address)
    };
    match instruction.decoded.opcode.flow() {
        FlowControl::Branch => Terminator::Branch {
            condition: branch_condition(instruction.decoded.opcode.mnemonic),
            taken: direct(),
            not_taken: target_from_offset(block_ids, next_offset, next_cpu),
        },
        FlowControl::Call => Terminator::Call {
            callee: direct(),
            continuation: target_from_offset(block_ids, next_offset, next_cpu),
        },
        FlowControl::Jump => Terminator::Jump(direct()),
        FlowControl::IndirectJump => Terminator::Stop(StopReason::IndirectJump {
            pointer: instruction.decoded.operand(),
        }),
        FlowControl::Return if instruction.decoded.opcode.mnemonic == Mnemonic::Rti => {
            Terminator::ReturnFromInterrupt
        }
        FlowControl::Return => Terminator::Return,
        FlowControl::Interrupt => Terminator::Interrupt,
        FlowControl::Fallthrough => {
            Terminator::Fallthrough(target_from_offset(block_ids, next_offset, next_cpu))
        }
    }
}

fn target_from_cpu(
    disassembly: &Disassembly,
    block_ids: &BTreeMap<usize, BlockId>,
    cpu_address: u16,
) -> BlockTarget {
    offset_for_cpu(disassembly, cpu_address)
        .and_then(|offset| block_ids.get(&offset).copied())
        .map_or(
            BlockTarget::Unresolved { cpu_address },
            BlockTarget::Resolved,
        )
}

fn target_from_offset(
    block_ids: &BTreeMap<usize, BlockId>,
    offset: usize,
    cpu_address: u16,
) -> BlockTarget {
    block_ids.get(&offset).copied().map_or(
        BlockTarget::Unresolved { cpu_address },
        BlockTarget::Resolved,
    )
}

fn branch_condition(mnemonic: Mnemonic) -> BranchCondition {
    match mnemonic {
        Mnemonic::Bcc => BranchCondition::CarryClear,
        Mnemonic::Bcs => BranchCondition::CarrySet,
        Mnemonic::Beq => BranchCondition::Equal,
        Mnemonic::Bmi => BranchCondition::Minus,
        Mnemonic::Bne => BranchCondition::NotEqual,
        Mnemonic::Bpl => BranchCondition::Plus,
        Mnemonic::Bvc => BranchCondition::OverflowClear,
        Mnemonic::Bvs => BranchCondition::OverflowSet,
        _ => unreachable!("only branch mnemonics have branch terminators"),
    }
}

fn build_edges(blocks: &BTreeMap<BlockId, BasicBlock>) -> Vec<Edge> {
    let mut edges = Vec::new();
    for block in blocks.values() {
        match &block.terminator {
            Terminator::Fallthrough(target) => {
                edges.push(edge(block.id, EdgeKind::Fallthrough, target));
            }
            Terminator::Branch {
                taken, not_taken, ..
            } => {
                edges.push(edge(block.id, EdgeKind::BranchTaken, taken));
                edges.push(edge(block.id, EdgeKind::BranchNotTaken, not_taken));
            }
            Terminator::Call {
                callee,
                continuation,
            } => {
                edges.push(edge(block.id, EdgeKind::CallTarget, callee));
                edges.push(edge(block.id, EdgeKind::CallContinuation, continuation));
            }
            Terminator::Jump(target) => edges.push(edge(block.id, EdgeKind::Jump, target)),
            Terminator::Return
            | Terminator::ReturnFromInterrupt
            | Terminator::Interrupt
            | Terminator::Stop(_) => {}
        }
    }
    edges
}

fn edge(source: BlockId, kind: EdgeKind, target: &BlockTarget) -> Edge {
    match target {
        BlockTarget::Resolved(target) => Edge {
            source,
            kind,
            target: Some(*target),
            unresolved_cpu_address: None,
        },
        BlockTarget::Unresolved { cpu_address } => Edge {
            source,
            kind,
            target: None,
            unresolved_cpu_address: Some(*cpu_address),
        },
    }
}

fn build_functions(
    disassembly: &Disassembly,
    blocks: &BTreeMap<BlockId, BasicBlock>,
    edges: &[Edge],
    limits: AnalysisLimits,
) -> Result<Vec<Function>, Vec<AnalysisError>> {
    let by_offset = blocks
        .keys()
        .map(|id| (id.prg_offset, *id))
        .collect::<BTreeMap<_, _>>();
    let mut roots = BTreeMap::<BlockId, Vec<FunctionEvidence>>::new();
    for entry in &disassembly.entry_points {
        if let Some(block) = by_offset.get(&entry.prg_offset) {
            roots
                .entry(*block)
                .or_default()
                .push(FunctionEvidence::Vector(entry.kind));
        }
    }
    for edge in edges
        .iter()
        .filter(|edge| edge.kind == EdgeKind::CallTarget)
    {
        if let Some(target) = edge.target {
            let source = blocks[&edge.source]
                .instructions
                .last()
                .expect("verified nonempty block")
                .provenance
                .clone();
            roots
                .entry(target)
                .or_default()
                .push(FunctionEvidence::DirectCall(source));
        }
    }
    if roots.is_empty()
        && let Some(block) = blocks.keys().next()
    {
        roots.insert(*block, vec![FunctionEvidence::ReachableComponent]);
    }
    let mut covered = BTreeSet::<BlockId>::new();
    let mut functions = Vec::new();
    for (entry, evidence) in roots {
        if functions.len() >= limits.max_functions {
            return Err(vec![AnalysisError::new(format!(
                "function limit {} exceeded",
                limits.max_functions
            ))]);
        }
        let reachable = reachable_blocks(entry, edges);
        covered.extend(&reachable);
        let id = FunctionId(
            u32::try_from(functions.len())
                .map_err(|_| vec![AnalysisError::new("function identifier exceeds 32 bits")])?,
        );
        functions.push(Function {
            id,
            name: function_name(disassembly, entry, &evidence),
            entry,
            blocks: reachable.into_iter().collect(),
            evidence,
        });
    }
    let remaining = blocks.keys().copied().collect::<Vec<_>>();
    for entry in remaining {
        if covered.contains(&entry) {
            continue;
        }
        if functions.len() >= limits.max_functions {
            return Err(vec![AnalysisError::new(format!(
                "function limit {} exceeded",
                limits.max_functions
            ))]);
        }
        let reachable = reachable_blocks(entry, edges);
        covered.extend(&reachable);
        let id = FunctionId(
            u32::try_from(functions.len())
                .map_err(|_| vec![AnalysisError::new("function identifier exceeds 32 bits")])?,
        );
        functions.push(Function {
            id,
            name: format!("sub_prg{:02X}_{:04X}", entry.bank, entry.cpu_address),
            entry,
            blocks: reachable.into_iter().collect(),
            evidence: vec![FunctionEvidence::ReachableComponent],
        });
    }
    Ok(functions)
}

fn reachable_blocks(entry: BlockId, edges: &[Edge]) -> BTreeSet<BlockId> {
    let mut reached = BTreeSet::new();
    let mut work = VecDeque::from([entry]);
    while let Some(block) = work.pop_front() {
        if !reached.insert(block) {
            continue;
        }
        for edge in edges.iter().filter(|edge| {
            edge.source == block && edge.kind != EdgeKind::CallTarget && edge.target.is_some()
        }) {
            work.push_back(edge.target.expect("filtered resolved edge"));
        }
    }
    reached
}

fn function_name(
    disassembly: &Disassembly,
    entry: BlockId,
    evidence: &[FunctionEvidence],
) -> String {
    if evidence.contains(&FunctionEvidence::Vector(VectorKind::Reset)) {
        return format!("reset_prg{:02X}_{:04X}", entry.bank, entry.cpu_address);
    }
    disassembly
        .labels
        .iter()
        .find(|label| label.prg_offset == entry.prg_offset)
        .map(|label| label.name.clone())
        .unwrap_or_else(|| format!("sub_prg{:02X}_{:04X}", entry.bank, entry.cpu_address))
}

fn verify_targets(
    terminator: &Terminator,
    blocks: &BTreeMap<BlockId, BasicBlock>,
    errors: &mut Vec<AnalysisError>,
) {
    let mut verify = |target: &BlockTarget| {
        if let BlockTarget::Resolved(target) = target
            && !blocks.contains_key(target)
        {
            errors.push(AnalysisError::new("terminator target block does not exist"));
        }
    };
    match terminator {
        Terminator::Fallthrough(target) | Terminator::Jump(target) => verify(target),
        Terminator::Branch {
            taken, not_taken, ..
        } => {
            verify(taken);
            verify(not_taken);
        }
        Terminator::Call {
            callee,
            continuation,
        } => {
            verify(callee);
            verify(continuation);
        }
        Terminator::Return
        | Terminator::ReturnFromInterrupt
        | Terminator::Interrupt
        | Terminator::Stop(_) => {}
    }
}

/// Lifts one official decoded instruction into semantic operations.
#[must_use]
#[allow(clippy::too_many_lines)]
pub fn lift_instruction(instruction: &DisassembledInstruction) -> SemanticInstruction {
    let mnemonic = instruction.decoded.opcode.mnemonic;
    let read = || value_source(instruction, false);
    let write = || value_target(instruction, true);
    let operations = match mnemonic {
        Mnemonic::Lda => vec![SemanticOperation::Load {
            destination: Register::A,
            source: read(),
        }],
        Mnemonic::Ldx => vec![SemanticOperation::Load {
            destination: Register::X,
            source: read(),
        }],
        Mnemonic::Ldy => vec![SemanticOperation::Load {
            destination: Register::Y,
            source: read(),
        }],
        Mnemonic::Sta => vec![SemanticOperation::Store {
            destination: memory_operand(instruction, true),
            source: Register::A,
        }],
        Mnemonic::Stx => vec![SemanticOperation::Store {
            destination: memory_operand(instruction, true),
            source: Register::X,
        }],
        Mnemonic::Sty => vec![SemanticOperation::Store {
            destination: memory_operand(instruction, true),
            source: Register::Y,
        }],
        Mnemonic::Adc => vec![SemanticOperation::Accumulate {
            operator: AccumulatorOperator::AddWithCarry,
            source: read(),
            carry_input: true,
            decimal: DecimalBehavior::Ignored,
        }],
        Mnemonic::Sbc => vec![SemanticOperation::Accumulate {
            operator: AccumulatorOperator::SubtractWithCarry,
            source: read(),
            carry_input: true,
            decimal: DecimalBehavior::Ignored,
        }],
        Mnemonic::And => vec![SemanticOperation::Accumulate {
            operator: AccumulatorOperator::And,
            source: read(),
            carry_input: false,
            decimal: DecimalBehavior::NotApplicable,
        }],
        Mnemonic::Ora => vec![SemanticOperation::Accumulate {
            operator: AccumulatorOperator::Or,
            source: read(),
            carry_input: false,
            decimal: DecimalBehavior::NotApplicable,
        }],
        Mnemonic::Eor => vec![SemanticOperation::Accumulate {
            operator: AccumulatorOperator::ExclusiveOr,
            source: read(),
            carry_input: false,
            decimal: DecimalBehavior::NotApplicable,
        }],
        Mnemonic::Cmp => vec![SemanticOperation::Compare {
            left: Register::A,
            right: read(),
        }],
        Mnemonic::Cpx => vec![SemanticOperation::Compare {
            left: Register::X,
            right: read(),
        }],
        Mnemonic::Cpy => vec![SemanticOperation::Compare {
            left: Register::Y,
            right: read(),
        }],
        Mnemonic::Bit => vec![SemanticOperation::TestBits { source: read() }],
        Mnemonic::Asl | Mnemonic::Lsr | Mnemonic::Rol | Mnemonic::Ror => {
            vec![SemanticOperation::Shift {
                operator: match mnemonic {
                    Mnemonic::Asl => ShiftOperator::ArithmeticLeft,
                    Mnemonic::Lsr => ShiftOperator::LogicalRight,
                    Mnemonic::Rol => ShiftOperator::RotateLeft,
                    Mnemonic::Ror => ShiftOperator::RotateRight,
                    _ => unreachable!(),
                },
                target: write(),
                carry_input: matches!(mnemonic, Mnemonic::Rol | Mnemonic::Ror),
            }]
        }
        Mnemonic::Inc | Mnemonic::Dec => vec![SemanticOperation::Adjust {
            target: write(),
            delta: if mnemonic == Mnemonic::Inc { 1 } else { -1 },
        }],
        Mnemonic::Inx | Mnemonic::Dex | Mnemonic::Iny | Mnemonic::Dey => {
            let (register, delta) = match mnemonic {
                Mnemonic::Inx => (Register::X, 1),
                Mnemonic::Dex => (Register::X, -1),
                Mnemonic::Iny => (Register::Y, 1),
                Mnemonic::Dey => (Register::Y, -1),
                _ => unreachable!(),
            };
            vec![SemanticOperation::Adjust {
                target: ValueTarget::Register(register),
                delta,
            }]
        }
        Mnemonic::Tax
        | Mnemonic::Tay
        | Mnemonic::Tsx
        | Mnemonic::Txa
        | Mnemonic::Txs
        | Mnemonic::Tya => {
            let (source, destination, update_negative_zero) = match mnemonic {
                Mnemonic::Tax => (Register::A, Register::X, true),
                Mnemonic::Tay => (Register::A, Register::Y, true),
                Mnemonic::Tsx => (Register::StackPointer, Register::X, true),
                Mnemonic::Txa => (Register::X, Register::A, true),
                Mnemonic::Txs => (Register::X, Register::StackPointer, false),
                Mnemonic::Tya => (Register::Y, Register::A, true),
                _ => unreachable!(),
            };
            vec![SemanticOperation::Transfer {
                source,
                destination,
                update_negative_zero,
            }]
        }
        Mnemonic::Clc
        | Mnemonic::Cld
        | Mnemonic::Cli
        | Mnemonic::Clv
        | Mnemonic::Sec
        | Mnemonic::Sed
        | Mnemonic::Sei => {
            let (flag, value) = match mnemonic {
                Mnemonic::Clc => (Flag::Carry, false),
                Mnemonic::Cld => (Flag::Decimal, false),
                Mnemonic::Cli => (Flag::InterruptDisable, false),
                Mnemonic::Clv => (Flag::Overflow, false),
                Mnemonic::Sec => (Flag::Carry, true),
                Mnemonic::Sed => (Flag::Decimal, true),
                Mnemonic::Sei => (Flag::InterruptDisable, true),
                _ => unreachable!(),
            };
            vec![SemanticOperation::SetFlag { flag, value }]
        }
        Mnemonic::Pha => vec![SemanticOperation::Push {
            source: ValueSource::Register(Register::A),
        }],
        Mnemonic::Php => vec![SemanticOperation::Push {
            source: ValueSource::Status,
        }],
        Mnemonic::Pla => vec![SemanticOperation::Pull {
            destination: ValueTarget::Register(Register::A),
            update_negative_zero: true,
        }],
        Mnemonic::Plp => vec![SemanticOperation::Pull {
            destination: ValueTarget::Status,
            update_negative_zero: false,
        }],
        Mnemonic::Jsr => vec![SemanticOperation::StackControl(
            StackControl::PushReturnAddress,
        )],
        Mnemonic::Rts => vec![SemanticOperation::StackControl(
            StackControl::PopReturnAddress,
        )],
        Mnemonic::Brk => vec![SemanticOperation::StackControl(
            StackControl::PushInterruptFrame,
        )],
        Mnemonic::Rti => vec![SemanticOperation::StackControl(
            StackControl::PopInterruptFrame,
        )],
        Mnemonic::Bcc
        | Mnemonic::Bcs
        | Mnemonic::Beq
        | Mnemonic::Bmi
        | Mnemonic::Bne
        | Mnemonic::Bpl
        | Mnemonic::Bvc
        | Mnemonic::Bvs
        | Mnemonic::Jmp
        | Mnemonic::Nop => vec![SemanticOperation::NoOperation],
    };
    SemanticInstruction {
        mnemonic,
        provenance: Provenance {
            rom_file_offset: instruction.rom_file_offset,
            prg_offset: instruction.prg_offset,
            address: instruction.address,
            bytes: instruction.decoded.bytes().to_vec(),
        },
        operations,
        flags: flag_effects(mnemonic),
    }
}

fn value_source(instruction: &DisassembledInstruction, write: bool) -> ValueSource {
    match instruction.decoded.opcode.mode {
        AddressingMode::Immediate => ValueSource::Immediate(instruction.decoded.operand() as u8),
        AddressingMode::Accumulator => ValueSource::Register(Register::A),
        _ => ValueSource::Memory(memory_operand(instruction, write)),
    }
}

fn value_target(instruction: &DisassembledInstruction, write: bool) -> ValueTarget {
    if instruction.decoded.opcode.mode == AddressingMode::Accumulator {
        ValueTarget::Register(Register::A)
    } else {
        ValueTarget::Memory(memory_operand(instruction, write))
    }
}

fn memory_operand(instruction: &DisassembledInstruction, write: bool) -> MemoryOperand {
    let mode = instruction.decoded.opcode.mode;
    let encoded = instruction.decoded.operand();
    let index = match mode {
        AddressingMode::ZeroPageX | AddressingMode::AbsoluteX | AddressingMode::IndexedIndirect => {
            Some(Register::X)
        }
        AddressingMode::ZeroPageY | AddressingMode::AbsoluteY | AddressingMode::IndirectIndexed => {
            Some(Register::Y)
        }
        _ => None,
    };
    let indirect = matches!(
        mode,
        AddressingMode::Indirect
            | AddressingMode::IndexedIndirect
            | AddressingMode::IndirectIndexed
    );
    let zero_page_wrap = matches!(
        mode,
        AddressingMode::ZeroPageX
            | AddressingMode::ZeroPageY
            | AddressingMode::IndexedIndirect
            | AddressingMode::IndirectIndexed
    );
    let address_space = classify_address(mode, encoded, write);
    let hardware_effect = classify_hardware_effect(mode, encoded, write);
    MemoryOperand {
        mode,
        encoded,
        index,
        indirect,
        zero_page_wrap,
        address_space,
        hardware_effect,
        volatile: matches!(
            address_space,
            AddressSpace::PpuRegister
                | AddressSpace::ApuRegister
                | AddressSpace::IoRegister
                | AddressSpace::Expansion
                | AddressSpace::MapperRegister
                | AddressSpace::Unknown
        ),
    }
}

fn classify_hardware_effect(
    mode: AddressingMode,
    encoded: u16,
    write: bool,
) -> Option<HardwareEffect> {
    if mode == AddressingMode::Absolute {
        return classify_static_hardware_effect(encoded, write);
    }
    if matches!(mode, AddressingMode::AbsoluteX | AddressingMode::AbsoluteY) {
        let first = classify_static_hardware_effect(encoded, write);
        return encoded.checked_add(0xff).and_then(|last| {
            let last = classify_static_hardware_effect(last, write);
            (first == last).then_some(first).flatten()
        });
    }
    None
}

fn classify_static_hardware_effect(encoded: u16, write: bool) -> Option<HardwareEffect> {
    match encoded {
        0x2000..=0x3fff => Some(HardwareEffect::Ppu),
        0x4000..=0x4013 | 0x4015 => Some(HardwareEffect::Apu),
        0x4014 if write => Some(HardwareEffect::Dma),
        0x4016..=0x4017 if !write => Some(HardwareEffect::Controller),
        0x4016 => Some(HardwareEffect::Controller),
        0x4017 => Some(HardwareEffect::Apu),
        0x4020..=0x5fff => Some(HardwareEffect::Expansion),
        0x8000..=0xffff if write => Some(HardwareEffect::Mapper),
        _ => None,
    }
}

fn classify_address(mode: AddressingMode, encoded: u16, write: bool) -> AddressSpace {
    match mode {
        AddressingMode::ZeroPage | AddressingMode::ZeroPageX | AddressingMode::ZeroPageY => {
            AddressSpace::ZeroPage
        }
        AddressingMode::Absolute => classify_static_address(encoded, write),
        AddressingMode::AbsoluteX | AddressingMode::AbsoluteY => {
            let first = classify_static_address(encoded, write);
            encoded
                .checked_add(0xff)
                .map_or(AddressSpace::Unknown, |last| {
                    let last = classify_static_address(last, write);
                    if first == last {
                        first
                    } else {
                        AddressSpace::Unknown
                    }
                })
        }
        AddressingMode::Indirect
        | AddressingMode::IndexedIndirect
        | AddressingMode::IndirectIndexed => AddressSpace::Unknown,
        AddressingMode::Implied
        | AddressingMode::Accumulator
        | AddressingMode::Immediate
        | AddressingMode::Relative => AddressSpace::Unknown,
    }
}

fn classify_static_address(address: u16, write: bool) -> AddressSpace {
    match address {
        0x0000..=0x00ff => AddressSpace::ZeroPage,
        0x0100..=0x1fff => AddressSpace::InternalRam,
        0x2000..=0x3fff => AddressSpace::PpuRegister,
        0x4000..=0x4013 | 0x4015 => AddressSpace::ApuRegister,
        0x4014 | 0x4016..=0x401f => AddressSpace::IoRegister,
        0x4020..=0x5fff => AddressSpace::Expansion,
        0x6000..=0x7fff => AddressSpace::PrgRam,
        0x8000..=0xffff if write => AddressSpace::MapperRegister,
        0x8000..=0xffff => AddressSpace::PrgRom,
    }
}

fn flag_effects(mnemonic: Mnemonic) -> FlagEffects {
    use Flag::{Break as B, Overflow as V, Zero as Z};
    use Flag::{Carry as C, Decimal as D, InterruptDisable as I, Negative as N};
    let all = || vec![C, Z, I, D, B, V, N];
    match mnemonic {
        Mnemonic::Adc | Mnemonic::Sbc => FlagEffects {
            reads: vec![C],
            writes: vec![C, Z, V, N],
        },
        Mnemonic::And
        | Mnemonic::Eor
        | Mnemonic::Ora
        | Mnemonic::Lda
        | Mnemonic::Ldx
        | Mnemonic::Ldy
        | Mnemonic::Inc
        | Mnemonic::Dec
        | Mnemonic::Inx
        | Mnemonic::Iny
        | Mnemonic::Dex
        | Mnemonic::Dey
        | Mnemonic::Pla
        | Mnemonic::Tax
        | Mnemonic::Tay
        | Mnemonic::Tsx
        | Mnemonic::Txa
        | Mnemonic::Tya => FlagEffects {
            reads: Vec::new(),
            writes: vec![Z, N],
        },
        Mnemonic::Asl | Mnemonic::Lsr => FlagEffects {
            reads: Vec::new(),
            writes: vec![C, Z, N],
        },
        Mnemonic::Rol | Mnemonic::Ror => FlagEffects {
            reads: vec![C],
            writes: vec![C, Z, N],
        },
        Mnemonic::Cmp | Mnemonic::Cpx | Mnemonic::Cpy => FlagEffects {
            reads: Vec::new(),
            writes: vec![C, Z, N],
        },
        Mnemonic::Bit => FlagEffects {
            reads: Vec::new(),
            writes: vec![Z, V, N],
        },
        Mnemonic::Bcc | Mnemonic::Bcs => FlagEffects {
            reads: vec![C],
            writes: Vec::new(),
        },
        Mnemonic::Beq | Mnemonic::Bne => FlagEffects {
            reads: vec![Z],
            writes: Vec::new(),
        },
        Mnemonic::Bmi | Mnemonic::Bpl => FlagEffects {
            reads: vec![N],
            writes: Vec::new(),
        },
        Mnemonic::Bvc | Mnemonic::Bvs => FlagEffects {
            reads: vec![V],
            writes: Vec::new(),
        },
        Mnemonic::Clc | Mnemonic::Sec => FlagEffects {
            reads: Vec::new(),
            writes: vec![C],
        },
        Mnemonic::Cld | Mnemonic::Sed => FlagEffects {
            reads: Vec::new(),
            writes: vec![D],
        },
        Mnemonic::Cli | Mnemonic::Sei => FlagEffects {
            reads: Vec::new(),
            writes: vec![I],
        },
        Mnemonic::Clv => FlagEffects {
            reads: Vec::new(),
            writes: vec![V],
        },
        Mnemonic::Php => FlagEffects {
            reads: all(),
            writes: Vec::new(),
        },
        Mnemonic::Plp | Mnemonic::Rti => FlagEffects {
            reads: Vec::new(),
            writes: all(),
        },
        Mnemonic::Brk => FlagEffects {
            reads: all(),
            writes: vec![I],
        },
        Mnemonic::Jmp
        | Mnemonic::Jsr
        | Mnemonic::Nop
        | Mnemonic::Pha
        | Mnemonic::Rts
        | Mnemonic::Sta
        | Mnemonic::Stx
        | Mnemonic::Sty
        | Mnemonic::Txs => FlagEffects::default(),
    }
}

#[cfg(test)]
mod tests {
    use nesc_disasm::{
        AnalysisLimits as DisassemblyLimits, BankAddress, Instruction, decode, disassemble, opcode,
    };
    use nesc_rom::{Format, Metadata, Mirroring, Region, Rom, build};

    use super::{
        AddressSpace, AnalysisLimits, DecimalBehavior, EdgeKind, Flag, HardwareEffect,
        SemanticOperation, StopReason, Terminator, ValueSource, analyze, lift_instruction,
    };

    fn nrom(program: &[u8]) -> Vec<u8> {
        let mut prg = vec![0xff; 16 * 1024];
        prg[..program.len()].copy_from_slice(program);
        let vectors = prg.len() - 6;
        for offset in [0, 2, 4] {
            prg[vectors + offset..vectors + offset + 2].copy_from_slice(&0xc000_u16.to_le_bytes());
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
        .expect("ROM")
    }

    #[test]
    fn builds_functions_blocks_and_explicit_edges() {
        let bytes = nrom(&[
            0x20, 0x08, 0xc0, // jsr $c008
            0xd0, 0x02, // bne $c007
            0x02, 0xaa, // data
            0x60, // rts
            0xa9, 0x2a, 0x60, // lda #$2a; rts
        ]);
        let disassembly = disassemble(&bytes, DisassemblyLimits::default()).expect("disassembly");
        let program = analyze(&disassembly, AnalysisLimits::default()).expect("analysis");
        assert_eq!(program.functions.len(), 2);
        assert_eq!(program.blocks.len(), 4);
        assert!(
            program
                .edges
                .iter()
                .any(|edge| edge.kind == EdgeKind::CallTarget)
        );
        assert!(
            program
                .edges
                .iter()
                .any(|edge| edge.kind == EdgeKind::BranchTaken && edge.target.is_some())
        );
        assert!(
            program
                .edges
                .iter()
                .any(|edge| edge.kind == EdgeKind::BranchNotTaken && edge.target.is_none())
        );
        assert!(program.render_text().contains("reset_prg00_C000"));
    }

    #[test]
    fn classifies_volatile_memory_semantics() {
        let bytes = nrom(&[
            0xad, 0x02, 0x20, // lda $2002
            0x8d, 0x14, 0x40, // sta $4014
            0x60,
        ]);
        let disassembly = disassemble(&bytes, DisassemblyLimits::default()).expect("disassembly");
        let program = analyze(&disassembly, AnalysisLimits::default()).expect("analysis");
        let instructions = &program.blocks.values().next().expect("block").instructions;
        let SemanticOperation::Load {
            source: ValueSource::Memory(ppu),
            ..
        } = &instructions[0].operations[0]
        else {
            panic!("PPU load");
        };
        assert_eq!(ppu.address_space, AddressSpace::PpuRegister);
        assert!(ppu.volatile);
        let SemanticOperation::Store { destination, .. } = &instructions[1].operations[0] else {
            panic!("DMA store");
        };
        assert_eq!(destination.address_space, AddressSpace::IoRegister);
        assert_eq!(destination.hardware_effect, Some(HardwareEffect::Dma));
        assert!(destination.volatile);
    }

    #[test]
    fn lifts_every_official_opcode_with_provenance() {
        let mut count = 0;
        for byte in 0..=u8::MAX {
            let Some(metadata) = opcode(byte) else {
                continue;
            };
            let decoded = decode(&[byte, 0x34, 0x12]).expect("official opcode");
            let instruction = Instruction {
                address: BankAddress {
                    bank: 1,
                    cpu_address: 0xc000,
                },
                prg_offset: 0x4000,
                selected_prg_banks: vec![None],
                rom_file_offset: 0x4010,
                decoded,
            };
            let lifted = lift_instruction(&instruction);
            assert_eq!(lifted.mnemonic, metadata.mnemonic);
            assert!(!lifted.operations.is_empty(), "opcode ${byte:02X}");
            assert_eq!(lifted.provenance.bytes[0], byte);
            count += 1;
        }
        assert_eq!(count, 151);
    }

    #[test]
    fn verifier_rejects_empty_blocks_and_limits_are_bounded() {
        let bytes = nrom(&[0xea, 0x60]);
        let disassembly = disassemble(&bytes, DisassemblyLimits::default()).expect("disassembly");
        let error = analyze(
            &disassembly,
            AnalysisLimits {
                max_operations: 1,
                ..AnalysisLimits::default()
            },
        )
        .expect_err("operation limit");
        assert!(error[0].message().contains("semantic-operation limit"));

        let mut program = analyze(&disassembly, AnalysisLimits::default()).expect("analysis");
        program
            .blocks
            .values_mut()
            .next()
            .expect("block")
            .instructions
            .clear();
        let verification = program.verify().expect_err("empty block");
        assert!(verification[0].message().contains("is empty"));
    }

    #[test]
    fn records_indirect_control_flow_and_flag_dependencies() {
        let bytes = nrom(&[0x69, 0x01, 0xd0, 0x02, 0x6c, 0x00, 0x02]);
        let disassembly = disassemble(&bytes, DisassemblyLimits::default()).expect("disassembly");
        let program = analyze(&disassembly, AnalysisLimits::default()).expect("analysis");
        let adc = program
            .blocks
            .values()
            .flat_map(|block| &block.instructions)
            .find(|instruction| instruction.mnemonic == nesc_disasm::Mnemonic::Adc)
            .expect("ADC");
        assert_eq!(adc.flags.reads, [Flag::Carry]);
        assert_eq!(
            adc.flags.writes,
            [Flag::Carry, Flag::Zero, Flag::Overflow, Flag::Negative]
        );
        assert!(matches!(
            adc.operations[0],
            SemanticOperation::Accumulate {
                decimal: DecimalBehavior::Ignored,
                ..
            }
        ));
        let indirect = program
            .blocks
            .values()
            .find(|block| {
                matches!(
                    block.terminator,
                    Terminator::Stop(StopReason::IndirectJump { .. })
                )
            })
            .expect("indirect block");
        assert_eq!(
            indirect.terminator,
            Terminator::Stop(StopReason::IndirectJump { pointer: 0x0200 })
        );
    }
}
