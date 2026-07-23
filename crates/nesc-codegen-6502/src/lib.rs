//! Ricoh 2A03/2A07 code generation for verified NesC MIR.

mod abi;
mod allocation;
mod cost;
mod layout;
mod stack;

use std::collections::{BTreeSet, HashMap};
use std::error::Error;
use std::fmt;

use nesc_mir::{
    AddressSpace, AssemblyOutputTarget, AssemblyRegister, BinaryOperator, BlockId, Function,
    InlineAssembly, Instruction, InstructionKind, Module, SourceSpan, Terminator, TypeKind,
    UnaryOperator, ValueId,
};
use nesc_object::{
    Binding, Object, Relocation, RelocationKind, SectionId, SectionKind, SectionPlacement,
    SymbolId, SymbolKind,
};

pub use abi::{
    ARGUMENT_SPILL_BASE, ARGUMENT_SPILL_LEN, AbiLocation, RETURN_SPILL_BASE, RETURN_SPILL_LEN,
    argument_location, return_location,
};
pub use allocation::{
    AllocationEntry, BackendConfig, Location, RUNTIME_SCRATCH_END, RUNTIME_SCRATCH_START,
    ZeroPageRange, ZeroPageStrategy,
};
pub use cost::{CodegenGoal, SequenceCost};
pub use stack::StackReport;

/// Result of 6502 instruction selection.
#[derive(Clone, Debug)]
pub struct GeneratedCode {
    /// Relocatable machine code.
    pub object: Object,
    /// Symbolic assembly listing.
    pub assembly: String,
    /// Deterministic zero-page placement report.
    pub zero_page_report: String,
    /// Deterministic hardware-stack report.
    pub stack_report: String,
    /// Auditable instruction-selection decisions and their estimated costs.
    pub optimization_report: String,
    /// Structured hardware-stack analysis.
    pub stack: StackReport,
}

/// Source-backed instruction-selection failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CodegenError {
    /// Explanation.
    pub message: String,
    /// Source range when emitted from a MIR instruction.
    pub span: Option<SourceSpan>,
}

impl fmt::Display for CodegenError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl Error for CodegenError {}

fn arithmetic_helper_name(operator: BinaryOperator, signed: bool, bits: u16) -> Option<String> {
    match operator {
        BinaryOperator::Multiply => Some(format!("__nesc_mul_{bits}")),
        BinaryOperator::Divide => Some(format!(
            "__nesc_{}div_{bits}",
            if signed { "s" } else { "u" }
        )),
        BinaryOperator::Remainder => Some(format!(
            "__nesc_{}rem_{bits}",
            if signed { "s" } else { "u" }
        )),
        BinaryOperator::ShiftLeft => Some(format!("__nesc_shl_{bits}")),
        BinaryOperator::ShiftRight if signed => Some(format!("__nesc_ashr_{bits}")),
        BinaryOperator::ShiftRight => Some(format!("__nesc_lshr_{bits}")),
        _ => None,
    }
}

fn constant_arithmetic_is_self_contained(
    operator: BinaryOperator,
    signed: bool,
    constant: u64,
) -> bool {
    match operator {
        BinaryOperator::Multiply => constant == 0 || constant.is_power_of_two(),
        BinaryOperator::Divide => constant == 0 || (!signed && constant.is_power_of_two()),
        BinaryOperator::Remainder => constant == 0 || (!signed && constant.is_power_of_two()),
        BinaryOperator::ShiftLeft | BinaryOperator::ShiftRight => true,
        _ => false,
    }
}

fn required_arithmetic_helpers(
    module: &Module,
    constants: &HashMap<(u32, u32), u64>,
) -> BTreeSet<String> {
    let mut helpers = BTreeSet::new();
    for function in &module.functions {
        for instruction in function.blocks.iter().flat_map(|block| &block.instructions) {
            let InstructionKind::Binary {
                operator,
                left,
                right,
            } = instruction.kind
            else {
                continue;
            };
            let Some(result) = instruction.result else {
                continue;
            };
            let bits = allocation::type_size(&function.value_types[result.0 as usize]) * 8;
            if !(8..=32).contains(&bits) {
                continue;
            }
            let left_type = &function.value_types[left.0 as usize];
            let signed = left_type.pointer_depth == 0
                && matches!(
                    left_type.kind,
                    TypeKind::Integer(integer) if integer.is_signed()
                );
            if constants
                .get(&(function.id.0, right.0))
                .is_some_and(|constant| {
                    constant_arithmetic_is_self_contained(operator, signed, *constant)
                })
            {
                continue;
            }
            if let Some(helper) = arithmetic_helper_name(operator, signed, bits) {
                helpers.insert(helper);
            }
        }
    }
    helpers
}

fn add_instruction_cost(cost: &mut SequenceCost, bytes: u32, cycles: u32) {
    cost.bytes = cost.bytes.saturating_add(bytes);
    cost.base_cycles = cost.base_cycles.saturating_add(cycles);
}

fn location_instruction_cost(location: Location, read_modify_write: bool) -> (u32, u32) {
    match (location.zero_page, read_modify_write) {
        (true, false) => (2, 3),
        (false, false) => (3, 4),
        (true, true) => (2, 5),
        (false, true) => (3, 6),
    }
}

fn inline_shift_cost(
    source: Location,
    destination: Location,
    count: u16,
    operator: BinaryOperator,
    signed: bool,
) -> SequenceCost {
    let mut cost = SequenceCost {
        interrupt_safe: true,
        ..SequenceCost::default()
    };
    let copied = source.size.min(destination.size);
    for _ in 0..copied {
        let (bytes, cycles) = location_instruction_cost(source, false);
        add_instruction_cost(&mut cost, bytes, cycles);
        let (bytes, cycles) = location_instruction_cost(destination, false);
        add_instruction_cost(&mut cost, bytes, cycles);
    }
    for _ in copied..destination.size {
        add_instruction_cost(&mut cost, 2, 2);
        let (bytes, cycles) = location_instruction_cost(destination, false);
        add_instruction_cost(&mut cost, bytes, cycles);
    }
    for _ in 0..count {
        if operator == BinaryOperator::ShiftRight && signed {
            let (bytes, cycles) = location_instruction_cost(destination, false);
            add_instruction_cost(&mut cost, bytes, cycles);
            add_instruction_cost(&mut cost, 1, 2);
        }
        for _ in 0..destination.size {
            let (bytes, cycles) = location_instruction_cost(destination, true);
            add_instruction_cost(&mut cost, bytes, cycles);
        }
    }
    cost
}

fn helper_call_cost(
    left: Location,
    right: Location,
    destination: Location,
    operator: BinaryOperator,
    constant: u16,
) -> SequenceCost {
    let mut cost = SequenceCost {
        stack_bytes: 2,
        interrupt_safe: true,
        ..SequenceCost::default()
    };
    let arguments = [left, right]
        .into_iter()
        .flat_map(|location| (0..location.size).map(move |_| location))
        .collect::<Vec<_>>();
    for location in arguments.iter().skip(3) {
        let (bytes, cycles) = location_instruction_cost(*location, false);
        add_instruction_cost(&mut cost, bytes, cycles);
        add_instruction_cost(&mut cost, 2, 3);
    }
    for location in arguments.iter().take(3) {
        let (bytes, cycles) = location_instruction_cost(*location, false);
        add_instruction_cost(&mut cost, bytes, cycles);
    }
    add_instruction_cost(&mut cost, 3, 6);
    for _ in 0..destination.size.min(3) {
        let (bytes, cycles) = location_instruction_cost(destination, false);
        add_instruction_cost(&mut cost, bytes, cycles);
    }
    for _ in 3..destination.size {
        add_instruction_cost(&mut cost, 2, 3);
        let (bytes, cycles) = location_instruction_cost(destination, false);
        add_instruction_cost(&mut cost, bytes, cycles);
    }
    let width = u32::from(destination.size);
    let bits = width * 8;
    cost.runtime_cycles = match operator {
        BinaryOperator::Multiply => 48 + bits * (20 + 6 * width),
        BinaryOperator::Divide => 64 + bits * (28 + 10 * width),
        BinaryOperator::ShiftLeft | BinaryOperator::ShiftRight => {
            48 + bits * (18 + 5 * width) + u32::from(constant) * (6 + 5 * width)
        }
        _ => 0,
    };
    cost
}

/// Lowers verified MIR to a relocatable 6502 code section.
///
/// `nescall` flattens scalar values into little-endian bytes. The first three
/// argument and return bytes use A, X, and Y; remaining bytes use reserved
/// zero-page ABI slots.
///
/// # Errors
///
/// Returns failures for unsupported wide operations, address expressions, or
/// exhausted static temporary storage.
pub fn generate(module: &Module) -> Result<GeneratedCode, Vec<CodegenError>> {
    generate_with_config(module, &BackendConfig::default())
}

/// Lowers verified MIR using explicit target resource settings.
///
/// # Errors
///
/// Returns failures for invalid allocation ranges, exhausted RAM, stack-limit
/// violations, and unsupported machine operations.
pub fn generate_with_config(
    module: &Module,
    config: &BackendConfig,
) -> Result<GeneratedCode, Vec<CodegenError>> {
    let allocation = allocation::allocate(module, config)?;
    let stack = stack::analyze(module, config.stack_limit, &config.external_stack_bytes)?;
    let zero_page_report = allocation::render_report(&allocation);
    let stack_report = stack::render_report(&stack);
    let mut long_branches = BTreeSet::new();
    loop {
        let mut emitter = Emitter::new(
            module,
            allocation.clone(),
            config.goal,
            long_branches.clone(),
        )?;
        for function in &module.functions {
            if !function.blocks.is_empty() {
                emitter.function(function);
            }
        }
        if !emitter.errors.is_empty() {
            return Err(emitter.errors);
        }
        let overflowing = emitter.out_of_range_branches()?;
        if !overflowing.is_empty() {
            long_branches.extend(overflowing);
            continue;
        }
        emitter.append_rodata_assembly(module);
        emitter.finish_layout_report();
        emitter.object.validate().map_err(|errors| {
            errors
                .into_iter()
                .map(|error| CodegenError {
                    message: error.to_string(),
                    span: None,
                })
                .collect::<Vec<_>>()
        })?;
        return Ok(GeneratedCode {
            object: emitter.object,
            assembly: emitter.assembly,
            zero_page_report,
            stack_report,
            optimization_report: emitter.optimization_report,
            stack,
        });
    }
}

#[derive(Clone, Copy, Debug)]
struct BranchSite {
    id: u32,
    section: SectionId,
    operand_offset: u32,
    symbol: SymbolId,
}

#[derive(Clone, Copy, Debug, Default)]
struct LayoutStats {
    blocks_placed: u32,
    fallthrough_jumps: u32,
    conditional_fallthroughs: u32,
    inverted_branches: u32,
    bytes_saved: u32,
    weighted_branch_base_cycles: u64,
    weighted_branch_taken_cycles: u64,
    weighted_page_cross_cycles: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CpuRegister {
    A,
    X,
    Y,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum KnownValue {
    #[default]
    Unknown,
    Immediate(u8),
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct TrackedRegister {
    value: KnownValue,
    memory: Option<u16>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct RegisterState {
    a: TrackedRegister,
    x: TrackedRegister,
    y: TrackedRegister,
    nz_from: Option<CpuRegister>,
}

impl RegisterState {
    fn get(self, register: CpuRegister) -> TrackedRegister {
        match register {
            CpuRegister::A => self.a,
            CpuRegister::X => self.x,
            CpuRegister::Y => self.y,
        }
    }

    fn set(&mut self, register: CpuRegister, value: TrackedRegister) {
        match register {
            CpuRegister::A => self.a = value,
            CpuRegister::X => self.x = value,
            CpuRegister::Y => self.y = value,
        }
    }

    fn invalidate_register(&mut self, register: CpuRegister) {
        self.set(register, TrackedRegister::default());
        if self.nz_from == Some(register) {
            self.nz_from = None;
        }
    }

    fn invalidate_memory(&mut self, address: u16) {
        for register in [CpuRegister::A, CpuRegister::X, CpuRegister::Y] {
            let mut value = self.get(register);
            if value.memory == Some(address) {
                value.memory = None;
                self.set(register, value);
            }
        }
    }

    fn invalidate_all_memory(&mut self) {
        self.a.memory = None;
        self.x.memory = None;
        self.y.memory = None;
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct RegisterReuseStats {
    loads_removed: u32,
    bytes_saved: u32,
    cycles_saved: u32,
}

struct Emitter {
    object: Object,
    code: SectionId,
    function_sections: Vec<Option<SectionId>>,
    function_symbols: Vec<SymbolId>,
    block_symbols: HashMap<(u32, u32), SymbolId>,
    rodata_symbols: HashMap<u32, SymbolId>,
    helper_symbols: HashMap<String, SymbolId>,
    constants: HashMap<(u32, u32), u64>,
    unavoidable_helpers: BTreeSet<String>,
    goal: CodegenGoal,
    allocation: allocation::Allocation,
    assembly: String,
    optimization_report: String,
    label_counter: u32,
    branch_counter: u32,
    branch_sites: Vec<BranchSite>,
    long_branches: BTreeSet<u32>,
    layout_stats: LayoutStats,
    registers: RegisterState,
    register_reuse_stats: RegisterReuseStats,
    errors: Vec<CodegenError>,
}

struct ConstantArithmetic<'a> {
    operator: BinaryOperator,
    signed: bool,
    constant: u64,
    source: Location,
    right: Location,
    destination: Location,
    bit_width: u16,
    helper_name: &'a str,
    function_name: &'a str,
}

impl Emitter {
    fn new(
        module: &Module,
        allocation: allocation::Allocation,
        goal: CodegenGoal,
        long_branches: BTreeSet<u32>,
    ) -> Result<Self, Vec<CodegenError>> {
        let mut object = Object::default();
        let mut function_sections = Vec::with_capacity(module.functions.len());
        for function in &module.functions {
            let section = if function.blocks.is_empty() {
                None
            } else {
                let placement = match function.placement {
                    nesc_mir::BankPlacement::Fixed => SectionPlacement::Fixed,
                    nesc_mir::BankPlacement::Bank(bank) => SectionPlacement::Bank(bank),
                };
                Some(
                    object
                        .add_section_with_placement(
                            format!(".text.{}", function.name),
                            SectionKind::Code,
                            1,
                            placement,
                        )
                        .map_err(|error| {
                            vec![CodegenError {
                                message: error.to_string(),
                                span: None,
                            }]
                        })?,
                )
            };
            function_sections.push(section);
        }
        let code = function_sections
            .iter()
            .flatten()
            .copied()
            .next()
            .unwrap_or(SectionId(0));
        let mut function_symbols = Vec::with_capacity(module.functions.len());
        for function in &module.functions {
            let section = function_sections[function.id.0 as usize];
            let symbol = object
                .add_symbol(
                    &function.name,
                    section,
                    0,
                    SymbolKind::Function,
                    Binding::Global,
                )
                .map_err(|error| {
                    vec![CodegenError {
                        message: error.to_string(),
                        span: None,
                    }]
                })?;
            function_symbols.push(symbol);
        }
        let mut block_symbols = HashMap::new();
        let mut constants = HashMap::new();
        for function in &module.functions {
            for block in &function.blocks {
                let symbol = object
                    .add_symbol(
                        format!("{}.block{}", function.name, block.id.0),
                        function_sections[function.id.0 as usize],
                        0,
                        SymbolKind::Label,
                        Binding::Local,
                    )
                    .map_err(|error| {
                        vec![CodegenError {
                            message: error.to_string(),
                            span: None,
                        }]
                    })?;
                block_symbols.insert((function.id.0, block.id.0), symbol);
                for instruction in &block.instructions {
                    if let (Some(result), InstructionKind::Constant(value)) =
                        (instruction.result, &instruction.kind)
                    {
                        constants.insert((function.id.0, result.0), *value);
                    }
                }
            }
        }
        let mut rodata_symbols = HashMap::new();
        if module.global_data.iter().any(Option::is_some) {
            let rodata = object
                .add_section(".rodata", SectionKind::ReadOnlyData, 1)
                .map_err(|error| {
                    vec![CodegenError {
                        message: error.to_string(),
                        span: None,
                    }]
                })?;
            for (index, data) in module.global_data.iter().enumerate() {
                let Some(constant) = data else {
                    continue;
                };
                let offset = object.sections[rodata.0 as usize].bytes.len();
                let symbol = object
                    .add_symbol(
                        format!("__nesc_rodata_{index}"),
                        Some(rodata),
                        offset as u32,
                        SymbolKind::Label,
                        Binding::Local,
                    )
                    .map_err(|error| {
                        vec![CodegenError {
                            message: error.to_string(),
                            span: None,
                        }]
                    })?;
                object
                    .section_bytes_mut(rodata)
                    .expect("rodata section exists")
                    .extend_from_slice(&constant.bytes);
                rodata_symbols.insert(index as u32, symbol);
            }
        }
        let unavoidable_helpers = required_arithmetic_helpers(module, &constants);
        Ok(Self {
            object,
            code,
            function_sections,
            function_symbols,
            block_symbols,
            rodata_symbols,
            helper_symbols: HashMap::new(),
            constants,
            unavoidable_helpers,
            goal,
            allocation,
            assembly: ".segment \"CODE\"\n".to_owned(),
            optimization_report: format!("Code generation goal: {}\n", goal.name()),
            label_counter: 0,
            branch_counter: 0,
            branch_sites: Vec::new(),
            long_branches,
            layout_stats: LayoutStats::default(),
            registers: RegisterState::default(),
            register_reuse_stats: RegisterReuseStats::default(),
            errors: Vec::new(),
        })
    }

    fn function(&mut self, function: &Function) {
        self.code = self.function_sections[function.id.0 as usize]
            .expect("defined function has a code section");
        let function_symbol = self.function_symbols[function.id.0 as usize];
        self.define(function_symbol);
        self.assembly.push_str(&format!(
            "\n.export {}\n{}:\n",
            function.name, function.name
        ));
        self.parameter_prologue(function);
        let analysis = nesc_opt::analyze_control_flow(function);
        let order = layout::block_order(function);
        self.layout_stats.blocks_placed = self
            .layout_stats
            .blocks_placed
            .saturating_add(order.len() as u32);
        for (position, block_id) in order.iter().copied().enumerate() {
            let block = &function.blocks[block_id.0 as usize];
            let next = order.get(position + 1).copied();
            let block_symbol = self.block_symbols[&(function.id.0, block.id.0)];
            self.define(block_symbol);
            self.assembly
                .push_str(&format!("{}.block{}:\n", function.name, block.id.0));
            for instruction in &block.instructions {
                self.instruction(function, instruction);
            }
            if let Some(terminator) = &block.terminator {
                self.terminator(function, block.id, terminator, next, &analysis);
            }
        }
    }

    fn instruction(&mut self, function: &Function, instruction: &Instruction) {
        match &instruction.kind {
            InstructionKind::Constant(value) => {
                if let Some(result) = instruction.result {
                    let destination = self.value_location(function, result);
                    self.write_constant(destination, *value);
                }
            }
            InstructionKind::LoadLocal(local) => {
                if let Some(result) = instruction.result {
                    self.copy_location(
                        self.local_location(function, *local),
                        self.value_location(function, result),
                    );
                }
            }
            InstructionKind::StoreLocal { local, value } => {
                self.copy_location(
                    self.value_location(function, *value),
                    self.local_location(function, *local),
                );
            }
            InstructionKind::LoadGlobal(global) => {
                if let Some(result) = instruction.result {
                    let destination = self.value_location(function, result);
                    if let Some(symbol) = self.rodata_symbols.get(&global.0).copied() {
                        self.load_rodata(symbol, destination);
                    } else {
                        self.copy_location(self.global_location(*global), destination);
                    }
                }
            }
            InstructionKind::StoreGlobal { global, value } => {
                if self.rodata_symbols.contains_key(&global.0) {
                    self.error(
                        "cannot store to a const global placed in PRG-ROM",
                        instruction.span,
                    );
                } else {
                    self.copy_location(
                        self.value_location(function, *value),
                        self.global_location(*global),
                    );
                }
            }
            InstructionKind::AddressOfLocal(local) => {
                if let Some(result) = instruction.result {
                    self.write_constant(
                        self.value_location(function, result),
                        u64::from(self.local_location(function, *local).address),
                    );
                }
            }
            InstructionKind::AddressOfGlobal(global) => {
                if let Some(result) = instruction.result {
                    let destination = self.value_location(function, result);
                    if let Some(symbol) = self.rodata_symbols.get(&global.0).copied() {
                        self.write_symbol_address(symbol, destination);
                    } else {
                        self.write_constant(
                            destination,
                            u64::from(self.global_location(*global).address),
                        );
                    }
                }
            }
            InstructionKind::BoundsCheck { index, length } => {
                self.bounds_check(function, *index, *length);
            }
            InstructionKind::PointerOffset {
                base,
                offset,
                subtract,
            } => self.pointer_offset(function, instruction, *base, *offset, *subtract),
            InstructionKind::LoadIndirect { address, .. } => {
                self.load_indirect(function, instruction, *address);
            }
            InstructionKind::StoreIndirect {
                address,
                value,
                ty,
                address_space,
                volatile,
            } => {
                self.store_indirect(function, *address, *value, ty, *address_space, *volatile);
            }
            InstructionKind::Unary { operator, operand } => {
                self.unary(function, instruction, *operator, *operand);
            }
            InstructionKind::Binary {
                operator,
                left,
                right,
            } => self.binary(function, instruction, *operator, *left, *right),
            InstructionKind::Cast { value, .. } => self.cast(function, instruction, *value),
            InstructionKind::Call {
                function: callee,
                arguments,
            } => {
                self.call(function, instruction, *callee, arguments);
            }
            InstructionKind::InlineAssembly(assembly) => {
                self.inline_assembly(function, instruction, assembly);
            }
        }
    }

    fn inline_assembly(
        &mut self,
        function: &Function,
        instruction: &Instruction,
        assembly: &InlineAssembly,
    ) {
        for input in &assembly.inputs {
            let location = self.value_location(function, input.value);
            match input.register {
                AssemblyRegister::A => self.lda_location(location, 0),
                AssemblyRegister::X => self.ldx_location(location, 0),
                AssemblyRegister::Y => self.ldy_location(location, 0),
            }
        }
        let allowed_calls = assembly
            .calls
            .iter()
            .map(|callee| {
                self.object.symbols[self.function_symbols[callee.0 as usize].0 as usize]
                    .name
                    .clone()
            })
            .collect::<Vec<_>>();
        let assembled = match nesc_asm::assemble_inline_with_calls(
            &assembly.template,
            &allowed_calls,
            nesc_asm::AssemblyLimits::default(),
        ) {
            Ok(assembled) => assembled,
            Err(error) => {
                self.error(
                    format!("invalid inline assembly: {error}"),
                    instruction.span,
                );
                return;
            }
        };
        let base = self.code_len();
        self.object
            .section_bytes_mut(self.code)
            .expect("code section exists")
            .extend_from_slice(&assembled.bytes);
        for call in assembled.calls {
            let callee = assembly
                .calls
                .iter()
                .copied()
                .find(|callee| {
                    self.object.symbols[self.function_symbols[callee.0 as usize].0 as usize].name
                        == call.symbol
                })
                .expect("assembler only returns allowed call symbols");
            self.object.add_relocation(Relocation {
                section: self.code,
                offset: u32::try_from(base)
                    .expect("code section length fits u32")
                    .saturating_add(call.offset),
                kind: RelocationKind::Absolute16,
                symbol: self.function_symbols[callee.0 as usize],
                addend: 0,
            });
        }
        self.assembly.push_str("    ; begin NES_ASM\n");
        for line in assembly.template.lines() {
            if !line.trim().is_empty() {
                self.assembly.push_str("    ");
                self.assembly.push_str(line.trim());
                self.assembly.push('\n');
            }
        }
        self.assembly.push_str("    ; end NES_ASM\n");

        if !assembly.calls.is_empty() {
            self.registers = RegisterState::default();
        } else {
            if assembly.clobbers.a {
                self.registers.invalidate_register(CpuRegister::A);
            }
            if assembly.clobbers.x {
                self.registers.invalidate_register(CpuRegister::X);
            }
            if assembly.clobbers.y {
                self.registers.invalidate_register(CpuRegister::Y);
            }
            if assembly.clobbers.flags {
                self.registers.nz_from = None;
            }
            if assembly.clobbers.memory {
                self.registers.invalidate_all_memory();
            }
        }

        for output in &assembly.outputs {
            let location = match output.target {
                AssemblyOutputTarget::Local(local) => self.local_location(function, local),
                AssemblyOutputTarget::Global(global) => self.global_location(global),
            };
            match output.register {
                AssemblyRegister::A => self.sta_location(location, 0),
                AssemblyRegister::X => self.stx_location(location, 0),
                AssemblyRegister::Y => self.sty_location(location, 0),
            }
        }
    }

    fn pointer_offset(
        &mut self,
        function: &Function,
        instruction: &Instruction,
        base: ValueId,
        offset: ValueId,
        subtract: bool,
    ) {
        let Some(result) = instruction.result else {
            return;
        };
        let base = self.value_location(function, base);
        let offset = self.value_location(function, offset);
        let destination = self.value_location(function, result);
        self.emit_byte(
            if subtract { 0x38 } else { 0x18 },
            if subtract { "sec" } else { "clc" },
        );
        for byte in 0..destination.size.min(2) {
            self.lda_location(base, byte);
            let (zero_page, absolute, mnemonic) = if subtract {
                (0xe5, 0xed, "sbc")
            } else {
                (0x65, 0x6d, "adc")
            };
            self.memory_operation(zero_page, absolute, mnemonic, offset, byte);
            self.sta_location(destination, byte);
        }
    }

    fn prepare_indirect_address(&mut self, function: &Function, address: ValueId) {
        let address = self.value_location(function, address);
        self.lda_location(address, 0);
        self.sta_zero_page(ARGUMENT_SPILL_BASE);
        self.lda_location(address, 1);
        self.sta_zero_page(ARGUMENT_SPILL_BASE + 1);
    }

    fn load_indirect(&mut self, function: &Function, instruction: &Instruction, address: ValueId) {
        let Some(result) = instruction.result else {
            return;
        };
        let destination = self.value_location(function, result);
        self.prepare_indirect_address(function, address);
        for offset in 0..destination.size {
            self.ldy_immediate(offset as u8);
            self.emit_bytes(
                &[0xb1, ARGUMENT_SPILL_BASE],
                &format!("lda (${:02x}),y", ARGUMENT_SPILL_BASE),
            );
            self.registers.invalidate_register(CpuRegister::A);
            self.registers.nz_from = Some(CpuRegister::A);
            self.sta_location(destination, offset);
        }
    }

    fn store_indirect(
        &mut self,
        function: &Function,
        address: ValueId,
        value: ValueId,
        ty: &nesc_mir::Type,
        address_space: AddressSpace,
        volatile: bool,
    ) {
        let source = self.value_location(function, value);
        self.prepare_indirect_address(function, address);
        for offset in 0..source.size.min(allocation::type_size(ty)) {
            if volatile && address_space == AddressSpace::PpuRegister {
                self.store_ppu_register(source, offset);
            } else {
                self.ldy_immediate(offset as u8);
                self.lda_location(source, offset);
                self.emit_bytes(
                    &[0x91, ARGUMENT_SPILL_BASE],
                    &format!("sta (${:02x}),y", ARGUMENT_SPILL_BASE),
                );
                self.registers.invalidate_all_memory();
            }
        }
    }

    fn store_ppu_register(&mut self, source: Location, offset: u16) {
        let done_name = self.fresh_label("ppu_store_done");
        let done_symbol = self.local_symbol(&done_name);
        self.lda_zero_page(ARGUMENT_SPILL_BASE);
        if offset != 0 {
            self.emit_byte(0x18, "clc");
            self.immediate(0x69, "adc", offset as u8);
        }
        self.immediate(0x29, "and", 0x07);
        for register in 0x2000_u16..=0x2007 {
            let next_name = self.fresh_label("ppu_store_next");
            let next_symbol = self.local_symbol(&next_name);
            self.immediate(0xc9, "cmp", (register & 7) as u8);
            self.relative_symbol(0xd0, "bne", next_symbol);
            self.lda_location(source, offset);
            self.absolute_address(0x8d, "sta", register);
            self.absolute_symbol(0x4c, "jmp", done_symbol);
            self.define(next_symbol);
            self.assembly.push_str(&format!("{next_name}:\n"));
        }
        self.ldy_immediate(offset as u8);
        self.lda_location(source, offset);
        self.emit_bytes(
            &[0x91, ARGUMENT_SPILL_BASE],
            &format!("sta (${:02x}),y", ARGUMENT_SPILL_BASE),
        );
        self.registers.invalidate_all_memory();
        self.define(done_symbol);
        self.assembly.push_str(&format!("{done_name}:\n"));
    }

    fn bounds_check(&mut self, function: &Function, index: ValueId, length: u32) {
        let index_location = self.value_location(function, index);
        let trap_name = self.fresh_label("bounds_trap");
        let done_name = self.fresh_label("bounds_done");
        let trap_symbol = self.local_symbol(&trap_name);
        let done_symbol = self.local_symbol(&done_name);
        let index_type = &function.value_types[index.0 as usize];
        let signed = index_type.pointer_depth == 0
            && matches!(index_type.kind, TypeKind::Integer(integer) if integer.is_signed());

        if signed {
            self.lda_location(index_location, index_location.size - 1);
            self.relative_symbol(0x30, "bmi", trap_symbol);
        }
        for offset in (2..index_location.size).rev() {
            self.lda_location(index_location, offset);
            self.relative_symbol(0xd0, "bne", trap_symbol);
        }
        if index_location.size > 1 {
            self.lda_location(index_location, 1);
            self.immediate(0xc9, "cmp", (length >> 8) as u8);
            self.relative_symbol(0x90, "bcc", done_symbol);
            self.relative_symbol(0xd0, "bne", trap_symbol);
        } else if length > u32::from(u8::MAX) {
            self.absolute_symbol(0x4c, "jmp", done_symbol);
        }
        self.lda_location(index_location, 0);
        self.immediate(0xc9, "cmp", length as u8);
        self.relative_symbol(0x90, "bcc", done_symbol);
        self.define(trap_symbol);
        self.assembly.push_str(&format!("{trap_name}:\n"));
        let runtime_trap = self.helper_symbol("__nesc_trap");
        self.absolute_symbol(0x4c, "jmp", runtime_trap);
        self.define(done_symbol);
        self.assembly.push_str(&format!("{done_name}:\n"));
    }

    fn parameter_prologue(&mut self, function: &Function) {
        let mut byte_index = 0;
        for parameter in &function.parameters {
            let destination = self.local_location(function, *parameter);
            for offset in 0..destination.size {
                match argument_location(byte_index) {
                    Some(AbiLocation::A) => self.sta_location(destination, offset),
                    Some(AbiLocation::X) => self.stx_location(destination, offset),
                    Some(AbiLocation::Y) => self.sty_location(destination, offset),
                    Some(AbiLocation::ZeroPage(address)) => {
                        self.lda_zero_page(address);
                        self.sta_location(destination, offset);
                    }
                    None => {
                        self.errors.push(CodegenError {
                            message: format!(
                                "function `{}` needs more than {} argument bytes supported by nescall",
                                function.name,
                                3 + ARGUMENT_SPILL_LEN
                            ),
                            span: None,
                        });
                        return;
                    }
                }
                byte_index += 1;
            }
        }
    }

    fn write_constant(&mut self, destination: Location, value: u64) {
        for offset in 0..destination.size {
            let byte = if offset < 8 {
                (value >> (u32::from(offset) * 8)) as u8
            } else {
                0
            };
            self.lda_immediate(byte);
            self.sta_location(destination, offset);
        }
    }

    fn copy_location(&mut self, source: Location, destination: Location) {
        let copied = source.size.min(destination.size);
        for offset in 0..copied {
            self.lda_location(source, offset);
            self.sta_location(destination, offset);
        }
        for offset in copied..destination.size {
            self.lda_immediate(0);
            self.sta_location(destination, offset);
        }
    }

    fn cast(&mut self, function: &Function, instruction: &Instruction, value: ValueId) {
        let Some(result) = instruction.result else {
            return;
        };
        let source = self.value_location(function, value);
        let destination = self.value_location(function, result);
        let copied = source.size.min(destination.size);
        for offset in 0..copied {
            self.lda_location(source, offset);
            self.sta_location(destination, offset);
        }
        if destination.size <= copied {
            return;
        }

        let source_type = &function.value_types[value.0 as usize];
        let signed = source_type.pointer_depth == 0
            && matches!(
                source_type.kind,
                TypeKind::Integer(integer) if integer.is_signed()
            );
        if !signed {
            for offset in copied..destination.size {
                self.lda_immediate(0);
                self.sta_location(destination, offset);
            }
            return;
        }

        let negative_name = self.fresh_label("cast_negative");
        let fill_name = self.fresh_label("cast_fill");
        let negative_symbol = self.local_symbol(&negative_name);
        let fill_symbol = self.local_symbol(&fill_name);
        self.lda_location(source, source.size - 1);
        self.relative_symbol(0x30, "bmi", negative_symbol);
        self.lda_immediate(0);
        self.absolute_symbol(0x4c, "jmp", fill_symbol);
        self.define(negative_symbol);
        self.assembly.push_str(&format!("{negative_name}:\n"));
        self.lda_immediate(0xff);
        self.define(fill_symbol);
        self.assembly.push_str(&format!("{fill_name}:\n"));
        for offset in copied..destination.size {
            self.sta_location(destination, offset);
        }
    }

    fn call(
        &mut self,
        function: &Function,
        instruction: &Instruction,
        callee: nesc_mir::FunctionId,
        arguments: &[ValueId],
    ) {
        let locations = arguments
            .iter()
            .map(|argument| self.value_location(function, *argument))
            .collect::<Vec<_>>();
        let destination = instruction
            .result
            .map(|result| self.value_location(function, result));
        let symbol = self.function_symbols[callee.0 as usize];
        self.emit_call(&locations, destination, symbol, instruction.span);
    }

    fn emit_call(
        &mut self,
        arguments: &[Location],
        destination: Option<Location>,
        symbol: SymbolId,
        span: SourceSpan,
    ) {
        let bytes = arguments
            .iter()
            .flat_map(|location| (0..location.size).map(move |offset| (*location, offset)))
            .collect::<Vec<_>>();
        if bytes.len() > 3 + ARGUMENT_SPILL_LEN {
            self.error(
                format!(
                    "call needs {} argument bytes, but nescall supports at most {}",
                    bytes.len(),
                    3 + ARGUMENT_SPILL_LEN
                ),
                span,
            );
            return;
        }

        for (index, (location, offset)) in bytes.iter().enumerate().skip(3) {
            let Some(AbiLocation::ZeroPage(address)) = argument_location(index) else {
                unreachable!("argument byte count was checked")
            };
            self.lda_location(*location, *offset);
            self.sta_zero_page(address);
        }
        if let Some((location, offset)) = bytes.get(2) {
            self.ldy_location(*location, *offset);
        }
        if let Some((location, offset)) = bytes.get(1) {
            self.ldx_location(*location, *offset);
        }
        if let Some((location, offset)) = bytes.first() {
            self.lda_location(*location, *offset);
        }
        self.absolute_symbol(0x20, "jsr", symbol);

        if let Some(destination) = destination {
            for offset in 0..destination.size.min(3) {
                match return_location(usize::from(offset)) {
                    Some(AbiLocation::A) => self.sta_location(destination, offset),
                    Some(AbiLocation::X) => self.stx_location(destination, offset),
                    Some(AbiLocation::Y) => self.sty_location(destination, offset),
                    _ => unreachable!("first three return bytes use registers"),
                }
            }
            for offset in 3..destination.size {
                let Some(AbiLocation::ZeroPage(address)) = return_location(usize::from(offset))
                else {
                    self.error("return value is wider than the nescall ABI supports", span);
                    return;
                };
                self.lda_zero_page(address);
                self.sta_location(destination, offset);
            }
        }
    }

    fn unary(
        &mut self,
        function: &Function,
        instruction: &Instruction,
        operator: UnaryOperator,
        operand: ValueId,
    ) {
        let source = self.value_location(function, operand);
        let Some(result) = instruction.result else {
            return;
        };
        let destination = self.value_location(function, result);
        match operator {
            UnaryOperator::Plus => self.copy_location(source, destination),
            UnaryOperator::Negate => {
                self.emit_byte(0x18, "clc");
                for offset in 0..destination.size {
                    self.lda_location(source, offset);
                    self.immediate(0x49, "eor", 0xff);
                    self.immediate(0x69, "adc", u8::from(offset == 0));
                    self.sta_location(destination, offset);
                }
            }
            UnaryOperator::LogicalNot => {
                self.reduce_location(source);
                self.boolean_from_branch(0xf0, "beq");
                self.store_boolean(destination);
            }
            UnaryOperator::BitwiseNot => {
                for offset in 0..destination.size {
                    self.lda_location(source, offset);
                    self.immediate(0x49, "eor", 0xff);
                    self.sta_location(destination, offset);
                }
            }
            _ => {
                self.error(
                    "pointer and update unary operations require prior MIR lowering",
                    instruction.span,
                );
            }
        }
    }

    fn binary(
        &mut self,
        function: &Function,
        instruction: &Instruction,
        operator: BinaryOperator,
        left: ValueId,
        right: ValueId,
    ) {
        let left_location = self.value_location(function, left);
        let right_location = self.value_location(function, right);
        let Some(result) = instruction.result else {
            return;
        };
        let destination = self.value_location(function, result);
        match operator {
            BinaryOperator::Add => {
                self.emit_byte(0x18, "clc");
                for offset in 0..destination.size {
                    self.lda_location(left_location, offset);
                    self.memory_operation(0x65, 0x6d, "adc", right_location, offset);
                    self.sta_location(destination, offset);
                }
            }
            BinaryOperator::Subtract => {
                self.emit_byte(0x38, "sec");
                for offset in 0..destination.size {
                    self.lda_location(left_location, offset);
                    self.memory_operation(0xe5, 0xed, "sbc", right_location, offset);
                    self.sta_location(destination, offset);
                }
            }
            BinaryOperator::BitwiseAnd | BinaryOperator::BitwiseOr | BinaryOperator::BitwiseXor => {
                let (zero_page, absolute, mnemonic) = match operator {
                    BinaryOperator::BitwiseAnd => (0x25, 0x2d, "and"),
                    BinaryOperator::BitwiseOr => (0x05, 0x0d, "ora"),
                    BinaryOperator::BitwiseXor => (0x45, 0x4d, "eor"),
                    _ => unreachable!(),
                };
                for offset in 0..destination.size {
                    self.lda_location(left_location, offset);
                    self.memory_operation(zero_page, absolute, mnemonic, right_location, offset);
                    self.sta_location(destination, offset);
                }
            }
            BinaryOperator::Equal | BinaryOperator::NotEqual => {
                self.compare_equality(
                    left_location,
                    right_location,
                    destination,
                    operator == BinaryOperator::Equal,
                );
            }
            BinaryOperator::Less
            | BinaryOperator::LessEqual
            | BinaryOperator::Greater
            | BinaryOperator::GreaterEqual => {
                let left_type = &function.value_types[left.0 as usize];
                let signed = left_type.pointer_depth == 0
                    && matches!(
                        left_type.kind,
                        TypeKind::Integer(integer) if integer.is_signed()
                    );
                self.compare_order(left_location, right_location, destination, operator, signed);
            }
            BinaryOperator::LogicalAnd | BinaryOperator::LogicalOr => {
                self.reduce_location(left_location);
                self.sta_zero_page(ARGUMENT_SPILL_BASE);
                self.reduce_location(right_location);
                let (zero_page, absolute, mnemonic) = if operator == BinaryOperator::LogicalAnd {
                    (0x25, 0x2d, "and")
                } else {
                    (0x05, 0x0d, "ora")
                };
                self.memory_operation(
                    zero_page,
                    absolute,
                    mnemonic,
                    Location {
                        address: u16::from(ARGUMENT_SPILL_BASE),
                        size: 1,
                        zero_page: true,
                    },
                    0,
                );
                self.boolean_from_branch(0xd0, "bne");
                self.store_boolean(destination);
            }
            BinaryOperator::Multiply
            | BinaryOperator::Divide
            | BinaryOperator::Remainder
            | BinaryOperator::ShiftLeft
            | BinaryOperator::ShiftRight => self.arithmetic(
                function,
                instruction,
                operator,
                left,
                right,
                left_location,
                right_location,
                destination,
            ),
            _ => {
                self.error(
                    format!(
                        "{operator:?} on {}-byte values needs a 6502 runtime helper",
                        left_location.size
                    ),
                    instruction.span,
                );
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn arithmetic(
        &mut self,
        function: &Function,
        instruction: &Instruction,
        operator: BinaryOperator,
        left: ValueId,
        right: ValueId,
        left_location: Location,
        right_location: Location,
        destination: Location,
    ) {
        if !(1..=4).contains(&destination.size) {
            self.error(
                format!(
                    "{operator:?} on {}-byte values has no arithmetic lowering",
                    destination.size
                ),
                instruction.span,
            );
            return;
        }
        let left_type = &function.value_types[left.0 as usize];
        let signed = left_type.pointer_depth == 0
            && matches!(
                left_type.kind,
                TypeKind::Integer(integer) if integer.is_signed()
            );
        let constant = self.constants.get(&(function.id.0, right.0)).copied();
        let bit_width = destination.size * 8;
        let helper_name = arithmetic_helper_name(operator, signed, bit_width)
            .expect("arithmetic operator has a runtime helper");

        if matches!(operator, BinaryOperator::Divide | BinaryOperator::Remainder)
            && constant == Some(0)
        {
            self.error("division or remainder by constant zero", instruction.span);
            return;
        }
        if matches!(
            operator,
            BinaryOperator::ShiftLeft | BinaryOperator::ShiftRight
        ) && constant.is_some_and(|count| count >= u64::from(bit_width))
        {
            self.error(
                format!("constant shift count must be less than {bit_width}"),
                instruction.span,
            );
            return;
        }

        if let Some(value) = constant
            && self.constant_arithmetic(ConstantArithmetic {
                operator,
                signed,
                constant: value,
                source: left_location,
                right: right_location,
                destination,
                bit_width,
                helper_name: &helper_name,
                function_name: &function.name,
            })
        {
            return;
        }

        let symbol = self.helper_symbol(&helper_name);
        self.emit_call(
            &[left_location, right_location],
            Some(destination),
            symbol,
            instruction.span,
        );
    }

    fn constant_arithmetic(&mut self, arithmetic: ConstantArithmetic<'_>) -> bool {
        match arithmetic.operator {
            BinaryOperator::Multiply if arithmetic.constant == 0 => {
                self.write_constant(arithmetic.destination, 0);
                true
            }
            BinaryOperator::Multiply if arithmetic.constant.is_power_of_two() => {
                if !self.prefer_inline_shift(
                    &arithmetic,
                    arithmetic.constant.trailing_zeros() as u16,
                    BinaryOperator::ShiftLeft,
                    false,
                ) {
                    return false;
                }
                self.inline_shift(
                    arithmetic.source,
                    arithmetic.destination,
                    arithmetic.constant.trailing_zeros() as u16,
                    BinaryOperator::ShiftLeft,
                    false,
                );
                true
            }
            BinaryOperator::Divide
                if !arithmetic.signed && arithmetic.constant.is_power_of_two() =>
            {
                if !self.prefer_inline_shift(
                    &arithmetic,
                    arithmetic.constant.trailing_zeros() as u16,
                    BinaryOperator::ShiftRight,
                    false,
                ) {
                    return false;
                }
                self.inline_shift(
                    arithmetic.source,
                    arithmetic.destination,
                    arithmetic.constant.trailing_zeros() as u16,
                    BinaryOperator::ShiftRight,
                    false,
                );
                true
            }
            BinaryOperator::Remainder
                if !arithmetic.signed && arithmetic.constant.is_power_of_two() =>
            {
                let mask = arithmetic.constant - 1;
                for offset in 0..arithmetic.destination.size {
                    self.lda_location(arithmetic.source, offset);
                    self.immediate(0x29, "and", (mask >> (u32::from(offset) * 8)) as u8);
                    self.sta_location(arithmetic.destination, offset);
                }
                true
            }
            BinaryOperator::ShiftLeft | BinaryOperator::ShiftRight => {
                debug_assert!(arithmetic.constant < u64::from(arithmetic.bit_width));
                if !self.prefer_inline_shift(
                    &arithmetic,
                    arithmetic.constant as u16,
                    arithmetic.operator,
                    arithmetic.signed,
                ) {
                    return false;
                }
                self.inline_shift(
                    arithmetic.source,
                    arithmetic.destination,
                    arithmetic.constant as u16,
                    arithmetic.operator,
                    arithmetic.signed,
                );
                true
            }
            _ => false,
        }
    }

    fn prefer_inline_shift(
        &mut self,
        arithmetic: &ConstantArithmetic<'_>,
        count: u16,
        shift_operator: BinaryOperator,
        signed: bool,
    ) -> bool {
        if !self.unavoidable_helpers.contains(arithmetic.helper_name) {
            return true;
        }
        let inline = inline_shift_cost(
            arithmetic.source,
            arithmetic.destination,
            count,
            shift_operator,
            signed,
        );
        let helper = helper_call_cost(
            arithmetic.source,
            arithmetic.right,
            arithmetic.destination,
            arithmetic.operator,
            count,
        );
        let use_helper = self.goal.prefers(helper, inline);
        self.optimization_report.push_str(&format!(
            "{}: {:?} by {} ({} already linked): selected {}; inline {} bytes/{} cycles/zp {}/stack {}; helper {} bytes/{} cycles/zp {}/stack {}\n",
            arithmetic.function_name,
            arithmetic.operator,
            arithmetic.constant,
            arithmetic.helper_name,
            if use_helper { "helper" } else { "inline" },
            inline.rom_bytes(),
            inline.worst_case_cycles(),
            inline.zero_page_bytes,
            inline.stack_bytes,
            helper.rom_bytes(),
            helper.worst_case_cycles(),
            helper.zero_page_bytes,
            helper.stack_bytes,
        ));
        !use_helper
    }

    fn inline_shift(
        &mut self,
        source: Location,
        destination: Location,
        count: u16,
        operator: BinaryOperator,
        signed: bool,
    ) {
        self.copy_location(source, destination);
        for _ in 0..count {
            match operator {
                BinaryOperator::ShiftLeft => {
                    self.memory_operation(0x06, 0x0e, "asl", destination, 0);
                    for offset in 1..destination.size {
                        self.memory_operation(0x26, 0x2e, "rol", destination, offset);
                    }
                }
                BinaryOperator::ShiftRight if signed => {
                    self.lda_location(destination, destination.size - 1);
                    self.emit_byte(0x0a, "asl a");
                    self.registers.invalidate_register(CpuRegister::A);
                    self.registers.nz_from = Some(CpuRegister::A);
                    for offset in (0..destination.size).rev() {
                        self.memory_operation(0x66, 0x6e, "ror", destination, offset);
                    }
                }
                BinaryOperator::ShiftRight => {
                    self.memory_operation(0x46, 0x4e, "lsr", destination, destination.size - 1);
                    for offset in (0..destination.size - 1).rev() {
                        self.memory_operation(0x66, 0x6e, "ror", destination, offset);
                    }
                }
                _ => unreachable!("shift operator"),
            }
        }
    }

    fn terminator(
        &mut self,
        function: &Function,
        block: BlockId,
        terminator: &Terminator,
        next: Option<BlockId>,
        analysis: &nesc_opt::ControlFlowAnalysis,
    ) {
        match terminator {
            Terminator::Jump(block) => {
                if next == Some(*block) {
                    self.layout_stats.fallthrough_jumps =
                        self.layout_stats.fallthrough_jumps.saturating_add(1);
                    self.layout_stats.bytes_saved = self.layout_stats.bytes_saved.saturating_add(3);
                } else {
                    let symbol = self.block_symbol(function, *block);
                    self.absolute_symbol(0x4c, "jmp", symbol);
                }
            }
            Terminator::Branch {
                condition,
                then_block,
                else_block,
            } => {
                if then_block == else_block {
                    if next == Some(*then_block) {
                        self.layout_stats.fallthrough_jumps =
                            self.layout_stats.fallthrough_jumps.saturating_add(1);
                        self.layout_stats.bytes_saved =
                            self.layout_stats.bytes_saved.saturating_add(5);
                    } else {
                        let symbol = self.block_symbol(function, *then_block);
                        self.absolute_symbol(0x4c, "jmp", symbol);
                        self.layout_stats.bytes_saved =
                            self.layout_stats.bytes_saved.saturating_add(2);
                    }
                    return;
                }
                self.reduce_location(self.value_location(function, *condition));
                let source_frequency = analysis.block_frequency(block);
                if next == Some(*then_block) {
                    self.layout_stats.conditional_fallthroughs =
                        self.layout_stats.conditional_fallthroughs.saturating_add(1);
                    self.layout_stats.bytes_saved = self.layout_stats.bytes_saved.saturating_add(3);
                    self.layout_stats.inverted_branches =
                        self.layout_stats.inverted_branches.saturating_add(1);
                    self.record_branch_cost(
                        source_frequency,
                        analysis.block_frequency(*else_block),
                    );
                    let else_symbol = self.block_symbol(function, *else_block);
                    self.relative_symbol(0xf0, "beq", else_symbol);
                } else if next == Some(*else_block) {
                    self.layout_stats.conditional_fallthroughs =
                        self.layout_stats.conditional_fallthroughs.saturating_add(1);
                    self.layout_stats.bytes_saved = self.layout_stats.bytes_saved.saturating_add(3);
                    self.record_branch_cost(
                        source_frequency,
                        analysis.block_frequency(*then_block),
                    );
                    let then_symbol = self.block_symbol(function, *then_block);
                    self.relative_symbol(0xd0, "bne", then_symbol);
                } else {
                    self.record_branch_cost(
                        source_frequency,
                        analysis.block_frequency(*then_block),
                    );
                    let then_symbol = self.block_symbol(function, *then_block);
                    self.relative_symbol(0xd0, "bne", then_symbol);
                    let else_symbol = self.block_symbol(function, *else_block);
                    self.absolute_symbol(0x4c, "jmp", else_symbol);
                }
            }
            Terminator::Return(value) => {
                if let Some(value) = value {
                    let source = self.value_location(function, *value);
                    for offset in 3..source.size {
                        let Some(AbiLocation::ZeroPage(address)) =
                            return_location(usize::from(offset))
                        else {
                            self.errors.push(CodegenError {
                                message: "return value is wider than the nescall ABI supports"
                                    .to_owned(),
                                span: None,
                            });
                            return;
                        };
                        self.lda_location(source, offset);
                        self.sta_zero_page(address);
                    }
                    if source.size > 2 {
                        self.ldy_location(source, 2);
                    }
                    if source.size > 1 {
                        self.ldx_location(source, 1);
                    }
                    self.lda_location(source, 0);
                }
                self.emit_byte(0x60, "rts");
            }
            Terminator::Unreachable => self.emit_byte(0x02, ".byte $02 ; trap"),
        }
    }

    fn boolean_from_branch(&mut self, opcode: u8, mnemonic: &str) {
        let true_name = self.fresh_label("bool_true");
        let end_name = self.fresh_label("bool_end");
        let true_symbol = self.local_symbol(&true_name);
        let end_symbol = self.local_symbol(&end_name);
        self.relative_symbol(opcode, mnemonic, true_symbol);
        self.lda_immediate(0);
        self.absolute_symbol(0x4c, "jmp", end_symbol);
        self.define(true_symbol);
        self.assembly.push_str(&format!("{true_name}:\n"));
        self.lda_immediate(1);
        self.define(end_symbol);
        self.assembly.push_str(&format!("{end_name}:\n"));
    }

    fn reduce_location(&mut self, location: Location) {
        self.lda_location(location, 0);
        for offset in 1..location.size {
            self.memory_operation(0x05, 0x0d, "ora", location, offset);
        }
    }

    fn store_boolean(&mut self, destination: Location) {
        self.sta_location(destination, 0);
        for offset in 1..destination.size {
            self.lda_immediate(0);
            self.sta_location(destination, offset);
        }
    }

    fn compare_equality(
        &mut self,
        left: Location,
        right: Location,
        destination: Location,
        equal: bool,
    ) {
        let mismatch_name = self.fresh_label("compare_mismatch");
        let end_name = self.fresh_label("compare_end");
        let mismatch_symbol = self.local_symbol(&mismatch_name);
        let end_symbol = self.local_symbol(&end_name);
        for offset in 0..left.size {
            self.lda_location(left, offset);
            self.memory_operation(0xc5, 0xcd, "cmp", right, offset);
            self.relative_symbol(0xd0, "bne", mismatch_symbol);
        }
        self.lda_immediate(u8::from(equal));
        self.absolute_symbol(0x4c, "jmp", end_symbol);
        self.define(mismatch_symbol);
        self.assembly.push_str(&format!("{mismatch_name}:\n"));
        self.lda_immediate(u8::from(!equal));
        self.define(end_symbol);
        self.assembly.push_str(&format!("{end_name}:\n"));
        self.store_boolean(destination);
    }

    fn compare_order(
        &mut self,
        left: Location,
        right: Location,
        destination: Location,
        operator: BinaryOperator,
        signed: bool,
    ) {
        let (lower_left, lower_right, lower_is_true) = match operator {
            BinaryOperator::Less => (left, right, true),
            BinaryOperator::LessEqual => (right, left, false),
            BinaryOperator::Greater => (right, left, true),
            BinaryOperator::GreaterEqual => (left, right, false),
            _ => unreachable!("order comparison operator"),
        };
        let lower_name = self.fresh_label("compare_lower");
        let not_lower_name = self.fresh_label("compare_not_lower");
        let end_name = self.fresh_label("compare_end");
        let lower_symbol = self.local_symbol(&lower_name);
        let not_lower_symbol = self.local_symbol(&not_lower_name);
        let end_symbol = self.local_symbol(&end_name);
        self.branch_if_less(
            lower_left,
            lower_right,
            signed,
            lower_symbol,
            not_lower_symbol,
        );
        self.define(lower_symbol);
        self.assembly.push_str(&format!("{lower_name}:\n"));
        self.lda_immediate(u8::from(lower_is_true));
        self.absolute_symbol(0x4c, "jmp", end_symbol);
        self.define(not_lower_symbol);
        self.assembly.push_str(&format!("{not_lower_name}:\n"));
        self.lda_immediate(u8::from(!lower_is_true));
        self.define(end_symbol);
        self.assembly.push_str(&format!("{end_name}:\n"));
        self.store_boolean(destination);
    }

    fn branch_if_less(
        &mut self,
        left: Location,
        right: Location,
        signed: bool,
        lower_symbol: SymbolId,
        not_lower_symbol: SymbolId,
    ) {
        for offset in (0..left.size).rev() {
            if signed && offset == left.size - 1 {
                self.lda_location(left, offset);
                self.immediate(0x49, "eor", 0x80);
                self.sta_zero_page(ARGUMENT_SPILL_BASE);
                self.lda_location(right, offset);
                self.immediate(0x49, "eor", 0x80);
                self.sta_zero_page(ARGUMENT_SPILL_BASE + 1);
                self.lda_zero_page(ARGUMENT_SPILL_BASE);
                self.absolute_or_zero_page(
                    0xc5,
                    0xcd,
                    "cmp",
                    u16::from(ARGUMENT_SPILL_BASE + 1),
                    true,
                );
            } else {
                self.lda_location(left, offset);
                self.memory_operation(0xc5, 0xcd, "cmp", right, offset);
            }
            self.relative_symbol(0x90, "bcc", lower_symbol);
            self.relative_symbol(0xd0, "bne", not_lower_symbol);
        }
        self.absolute_symbol(0x4c, "jmp", not_lower_symbol);
    }

    fn block_symbol(&self, function: &Function, block: BlockId) -> SymbolId {
        self.block_symbols[&(function.id.0, block.0)]
    }

    fn global_location(&self, global: nesc_mir::GlobalId) -> Location {
        self.allocation.globals[global.0 as usize]
    }

    fn local_location(&self, function: &Function, local: nesc_mir::LocalId) -> Location {
        self.allocation.locals[&(function.id, local)]
    }

    fn value_location(&self, function: &Function, value: ValueId) -> Location {
        self.allocation.values[&(function.id, value)]
    }

    fn fresh_label(&mut self, prefix: &str) -> String {
        let value = self.label_counter;
        self.label_counter += 1;
        format!(".__nesc_{prefix}_{value}")
    }

    fn local_symbol(&mut self, name: &str) -> SymbolId {
        self.object
            .add_symbol(name, Some(self.code), 0, SymbolKind::Label, Binding::Local)
            .expect("generated symbol is valid")
    }

    fn helper_symbol(&mut self, name: &str) -> SymbolId {
        if let Some(symbol) = self.helper_symbols.get(name) {
            return *symbol;
        }
        let symbol = self
            .object
            .add_symbol(name, None, 0, SymbolKind::Function, Binding::Global)
            .expect("runtime helper symbol is valid");
        self.helper_symbols.insert(name.to_owned(), symbol);
        symbol
    }

    fn define(&mut self, symbol: SymbolId) {
        let offset = self.code_len();
        self.object.symbols[symbol.0 as usize].offset = offset as u32;
        self.registers = RegisterState::default();
    }

    fn lda_immediate(&mut self, value: u8) {
        self.load_immediate(CpuRegister::A, 0xa9, "lda", value);
    }

    fn ldy_immediate(&mut self, value: u8) {
        self.load_immediate(CpuRegister::Y, 0xa0, "ldy", value);
    }

    fn immediate(&mut self, opcode: u8, mnemonic: &str, value: u8) {
        self.emit_bytes(&[opcode, value], &format!("{mnemonic} #${value:02x}"));
        match opcode {
            0xc9 => self.registers.nz_from = None,
            0x29 | 0x49 | 0x69 | 0xe9 => {
                self.registers.invalidate_register(CpuRegister::A);
                self.registers.nz_from = Some(CpuRegister::A);
            }
            _ => self.registers = RegisterState::default(),
        }
    }

    fn load_immediate(&mut self, register: CpuRegister, opcode: u8, mnemonic: &str, value: u8) {
        if self.registers.get(register).value == KnownValue::Immediate(value)
            && self.registers.nz_from == Some(register)
        {
            self.record_reused_load(2, 2);
            return;
        }
        self.emit_bytes(&[opcode, value], &format!("{mnemonic} #${value:02x}"));
        self.registers.set(
            register,
            TrackedRegister {
                value: KnownValue::Immediate(value),
                memory: None,
            },
        );
        self.registers.nz_from = Some(register);
    }

    fn load_location(
        &mut self,
        register: CpuRegister,
        zero_page_opcode: u8,
        absolute_opcode: u8,
        mnemonic: &str,
        location: Location,
        offset: u16,
    ) {
        debug_assert!(offset < location.size);
        self.load_address(
            register,
            zero_page_opcode,
            absolute_opcode,
            mnemonic,
            location.address + offset,
            location.zero_page,
        );
    }

    fn load_address(
        &mut self,
        register: CpuRegister,
        zero_page_opcode: u8,
        absolute_opcode: u8,
        mnemonic: &str,
        address: u16,
        zero_page: bool,
    ) {
        if Self::trackable_memory(address)
            && self.registers.get(register).memory == Some(address)
            && self.registers.nz_from == Some(register)
        {
            self.record_reused_load(if zero_page { 2 } else { 3 }, if zero_page { 3 } else { 4 });
            return;
        }
        self.emit_address(
            zero_page_opcode,
            absolute_opcode,
            mnemonic,
            address,
            zero_page,
        );
        self.record_memory_load(register, address);
    }

    fn store_location(
        &mut self,
        register: CpuRegister,
        zero_page_opcode: u8,
        absolute_opcode: u8,
        mnemonic: &str,
        location: Location,
        offset: u16,
    ) {
        debug_assert!(offset < location.size);
        self.store_address(
            register,
            zero_page_opcode,
            absolute_opcode,
            mnemonic,
            location.address + offset,
            location.zero_page,
        );
    }

    fn store_address(
        &mut self,
        register: CpuRegister,
        zero_page_opcode: u8,
        absolute_opcode: u8,
        mnemonic: &str,
        address: u16,
        zero_page: bool,
    ) {
        self.emit_address(
            zero_page_opcode,
            absolute_opcode,
            mnemonic,
            address,
            zero_page,
        );
        self.record_memory_store(register, address);
    }

    fn lda_location(&mut self, location: Location, offset: u16) {
        self.load_location(CpuRegister::A, 0xa5, 0xad, "lda", location, offset);
    }

    fn sta_location(&mut self, location: Location, offset: u16) {
        self.store_location(CpuRegister::A, 0x85, 0x8d, "sta", location, offset);
    }

    /// Appends a readable listing of PRG-ROM constant payloads to the
    /// generated assembly text.
    fn append_rodata_assembly(&mut self, module: &Module) {
        if self.rodata_symbols.is_empty() {
            return;
        }
        self.assembly.push_str("\n.segment \"RODATA\"\n");
        let mut indices = self.rodata_symbols.keys().copied().collect::<Vec<_>>();
        indices.sort_unstable();
        for index in indices {
            let Some(Some(constant)) = module.global_data.get(index as usize) else {
                continue;
            };
            self.assembly.push_str(&format!("__nesc_rodata_{index}:"));
            for chunk in constant.bytes.chunks(8) {
                self.assembly.push_str("\n    .byte ");
                self.assembly.push_str(
                    &chunk
                        .iter()
                        .map(|byte| format!("${byte:02x}"))
                        .collect::<Vec<_>>()
                        .join(", "),
                );
            }
            self.assembly.push('\n');
        }
    }

    /// Copies a PRG-ROM constant into RAM storage byte by byte through
    /// symbol-relocated absolute loads.
    fn load_rodata(&mut self, symbol: SymbolId, destination: Location) {
        for offset in 0..destination.size {
            self.lda_absolute_symbol(symbol, offset);
            self.sta_location(destination, offset);
        }
    }

    fn lda_absolute_symbol(&mut self, symbol: SymbolId, addend: u16) {
        let name = self.object.symbols[symbol.0 as usize].name.clone();
        let assembly = if addend == 0 {
            format!("lda {name}")
        } else {
            format!("lda {name}+{addend}")
        };
        self.emit_byte(0xad, &assembly);
        let offset = self.code_len();
        self.emit_bytes(&[0, 0], "");
        self.object.add_relocation(Relocation {
            section: self.code,
            offset: offset as u32,
            kind: RelocationKind::Absolute16,
            symbol,
            addend: i32::from(addend),
        });
        self.registers.invalidate_register(CpuRegister::A);
        self.registers.nz_from = Some(CpuRegister::A);
    }

    /// Writes the link-time address of a PRG-ROM symbol into a little-endian
    /// pointer location through byte relocations.
    fn write_symbol_address(&mut self, symbol: SymbolId, destination: Location) {
        let name = self.object.symbols[symbol.0 as usize].name.clone();
        let parts = [
            (RelocationKind::AbsoluteLow8, '<'),
            (RelocationKind::AbsoluteHigh8, '>'),
        ];
        for offset in 0..destination.size {
            if let Some((kind, prefix)) = parts.get(usize::from(offset)).copied() {
                self.emit_byte(0xa9, &format!("lda #{prefix}{name}"));
                let operand = self.code_len();
                self.emit_byte(0, "");
                self.object.add_relocation(Relocation {
                    section: self.code,
                    offset: operand as u32,
                    kind,
                    symbol,
                    addend: 0,
                });
                self.registers.invalidate_register(CpuRegister::A);
                self.registers.nz_from = Some(CpuRegister::A);
            } else {
                self.lda_immediate(0);
            }
            self.sta_location(destination, offset);
        }
    }

    fn ldx_location(&mut self, location: Location, offset: u16) {
        self.load_location(CpuRegister::X, 0xa6, 0xae, "ldx", location, offset);
    }

    fn stx_location(&mut self, location: Location, offset: u16) {
        self.store_location(CpuRegister::X, 0x86, 0x8e, "stx", location, offset);
    }

    fn ldy_location(&mut self, location: Location, offset: u16) {
        self.load_location(CpuRegister::Y, 0xa4, 0xac, "ldy", location, offset);
    }

    fn sty_location(&mut self, location: Location, offset: u16) {
        self.store_location(CpuRegister::Y, 0x84, 0x8c, "sty", location, offset);
    }

    fn lda_zero_page(&mut self, address: u8) {
        self.load_address(CpuRegister::A, 0xa5, 0xad, "lda", u16::from(address), true);
    }

    fn sta_zero_page(&mut self, address: u8) {
        self.store_address(CpuRegister::A, 0x85, 0x8d, "sta", u16::from(address), true);
    }

    fn memory_operation(
        &mut self,
        zero_page_opcode: u8,
        absolute_opcode: u8,
        mnemonic: &str,
        location: Location,
        offset: u16,
    ) {
        debug_assert!(offset < location.size);
        self.absolute_or_zero_page(
            zero_page_opcode,
            absolute_opcode,
            mnemonic,
            location.address + offset,
            location.zero_page,
        );
    }

    fn absolute_or_zero_page(
        &mut self,
        zero_page_opcode: u8,
        absolute_opcode: u8,
        mnemonic: &str,
        address: u16,
        zero_page: bool,
    ) {
        self.emit_address(
            zero_page_opcode,
            absolute_opcode,
            mnemonic,
            address,
            zero_page,
        );
        self.record_memory_operation(
            if zero_page {
                zero_page_opcode
            } else {
                absolute_opcode
            },
            address,
        );
    }

    fn emit_address(
        &mut self,
        zero_page_opcode: u8,
        absolute_opcode: u8,
        mnemonic: &str,
        address: u16,
        zero_page: bool,
    ) {
        if zero_page {
            self.emit_bytes(
                &[zero_page_opcode, address as u8],
                &format!("{mnemonic} ${address:02x}"),
            );
        } else {
            self.absolute_address(absolute_opcode, mnemonic, address);
        }
    }

    fn absolute_address(&mut self, opcode: u8, mnemonic: &str, address: u16) {
        self.emit_bytes(
            &[opcode, address as u8, (address >> 8) as u8],
            &format!("{mnemonic} ${address:04x}"),
        );
        self.record_memory_operation(opcode, address);
    }

    fn record_memory_operation(&mut self, opcode: u8, address: u16) {
        match opcode {
            0xa5 | 0xad => self.record_memory_load(CpuRegister::A, address),
            0xa6 | 0xae => self.record_memory_load(CpuRegister::X, address),
            0xa4 | 0xac => self.record_memory_load(CpuRegister::Y, address),
            0x85 | 0x8d => self.record_memory_store(CpuRegister::A, address),
            0x86 | 0x8e => self.record_memory_store(CpuRegister::X, address),
            0x84 | 0x8c => self.record_memory_store(CpuRegister::Y, address),
            0x05 | 0x0d | 0x25 | 0x2d | 0x45 | 0x4d | 0x65 | 0x6d | 0xe5 | 0xed => {
                self.registers.invalidate_register(CpuRegister::A);
                self.registers.nz_from = Some(CpuRegister::A);
            }
            0xc5 | 0xcd => self.registers.nz_from = None,
            0x06 | 0x0e | 0x26 | 0x2e | 0x46 | 0x4e | 0x66 | 0x6e => {
                self.registers.invalidate_memory(address);
                self.registers.nz_from = None;
            }
            _ => self.registers = RegisterState::default(),
        }
    }

    fn record_memory_load(&mut self, register: CpuRegister, address: u16) {
        self.registers.set(
            register,
            TrackedRegister {
                value: KnownValue::Unknown,
                memory: Self::trackable_memory(address).then_some(address),
            },
        );
        self.registers.nz_from = Some(register);
    }

    fn record_memory_store(&mut self, register: CpuRegister, address: u16) {
        self.registers.invalidate_memory(address);
        if Self::trackable_memory(address) {
            let mut value = self.registers.get(register);
            value.memory = Some(address);
            self.registers.set(register, value);
        }
    }

    fn record_reused_load(&mut self, bytes: u32, cycles: u32) {
        self.register_reuse_stats.loads_removed =
            self.register_reuse_stats.loads_removed.saturating_add(1);
        self.register_reuse_stats.bytes_saved =
            self.register_reuse_stats.bytes_saved.saturating_add(bytes);
        self.register_reuse_stats.cycles_saved = self
            .register_reuse_stats
            .cycles_saved
            .saturating_add(cycles);
    }

    const fn trackable_memory(address: u16) -> bool {
        address < 0x0800
    }

    fn absolute_symbol(&mut self, opcode: u8, mnemonic: &str, symbol: SymbolId) {
        self.emit_byte(
            opcode,
            &format!("{mnemonic} {}", self.object.symbols[symbol.0 as usize].name),
        );
        let offset = self.code_len();
        self.emit_bytes(&[0, 0], "");
        self.object.add_relocation(Relocation {
            section: self.code,
            offset: offset as u32,
            kind: RelocationKind::Absolute16,
            symbol,
            addend: 0,
        });
        if opcode == 0x20 {
            self.registers = RegisterState::default();
        }
    }

    fn relative_symbol(&mut self, opcode: u8, mnemonic: &str, symbol: SymbolId) {
        let branch = self.branch_counter;
        self.branch_counter = self.branch_counter.saturating_add(1);
        if self.long_branches.contains(&branch) {
            let Some((inverse_opcode, inverse_mnemonic)) = inverse_branch(opcode) else {
                self.errors.push(CodegenError {
                    message: format!("cannot relax unsupported branch opcode ${opcode:02X}"),
                    span: None,
                });
                return;
            };
            let skip_label = format!(".__nesc_relax_{branch}");
            self.emit_bytes(
                &[inverse_opcode, 3],
                &format!("{inverse_mnemonic} {skip_label}"),
            );
            self.absolute_symbol(0x4c, "jmp", symbol);
            self.assembly.push_str(&format!("{skip_label}:\n"));
            return;
        }
        self.emit_byte(
            opcode,
            &format!("{mnemonic} {}", self.object.symbols[symbol.0 as usize].name),
        );
        let offset = self.code_len();
        self.emit_byte(0, "");
        self.object.add_relocation(Relocation {
            section: self.code,
            offset: offset as u32,
            kind: RelocationKind::Relative8,
            symbol,
            addend: 0,
        });
        self.branch_sites.push(BranchSite {
            id: branch,
            section: self.code,
            operand_offset: offset as u32,
            symbol,
        });
    }

    fn record_branch_cost(&mut self, source_frequency: u32, target_frequency: u32) {
        let taken_frequency = source_frequency.min(target_frequency);
        self.layout_stats.weighted_branch_base_cycles = self
            .layout_stats
            .weighted_branch_base_cycles
            .saturating_add(u64::from(source_frequency).saturating_mul(2));
        self.layout_stats.weighted_branch_taken_cycles = self
            .layout_stats
            .weighted_branch_taken_cycles
            .saturating_add(u64::from(taken_frequency));
        self.layout_stats.weighted_page_cross_cycles = self
            .layout_stats
            .weighted_page_cross_cycles
            .saturating_add(u64::from(taken_frequency));
    }

    fn out_of_range_branches(&self) -> Result<BTreeSet<u32>, Vec<CodegenError>> {
        let mut overflowing = BTreeSet::new();
        for site in &self.branch_sites {
            let symbol = &self.object.symbols[site.symbol.0 as usize];
            if symbol.section != Some(site.section) {
                return Err(vec![CodegenError {
                    message: format!("relative branch to `{}` crosses code sections", symbol.name),
                    span: None,
                }]);
            }
            let displacement = i64::from(symbol.offset)
                .saturating_sub(i64::from(site.operand_offset).saturating_add(1));
            if i8::try_from(displacement).is_err() {
                overflowing.insert(site.id);
            }
        }
        Ok(overflowing)
    }

    fn finish_layout_report(&mut self) {
        let relaxation_bytes = u32::try_from(self.long_branches.len())
            .unwrap_or(u32::MAX)
            .saturating_mul(3);
        self.optimization_report.push_str(&format!(
            "Control-flow blocks placed: {}\nFall-through jumps removed: {}\nConditional fall-throughs: {}\nBranches inverted: {}\nBranches relaxed: {}\nLayout bytes saved before relaxation: {}\nRelaxation bytes added: {}\nWeighted branch base cycles: {}\nWeighted taken-branch cycles: {}\nWeighted page-cross risk cycles: {}\nRegister loads removed: {}\nRegister-forwarding bytes saved: {}\nRegister-forwarding cycles saved: {}\n",
            self.layout_stats.blocks_placed,
            self.layout_stats.fallthrough_jumps,
            self.layout_stats.conditional_fallthroughs,
            self.layout_stats.inverted_branches,
            self.long_branches.len(),
            self.layout_stats.bytes_saved,
            relaxation_bytes,
            self.layout_stats.weighted_branch_base_cycles,
            self.layout_stats.weighted_branch_taken_cycles,
            self.layout_stats.weighted_page_cross_cycles,
            self.register_reuse_stats.loads_removed,
            self.register_reuse_stats.bytes_saved,
            self.register_reuse_stats.cycles_saved,
        ));
    }

    fn emit_byte(&mut self, byte: u8, assembly: &str) {
        self.object
            .section_bytes_mut(self.code)
            .expect("code section exists")
            .push(byte);
        if !assembly.is_empty() {
            self.assembly.push_str("    ");
            self.assembly.push_str(assembly);
            self.assembly.push('\n');
        }
    }

    fn emit_bytes(&mut self, bytes: &[u8], assembly: &str) {
        self.object
            .section_bytes_mut(self.code)
            .expect("code section exists")
            .extend_from_slice(bytes);
        if !assembly.is_empty() {
            self.assembly.push_str("    ");
            self.assembly.push_str(assembly);
            self.assembly.push('\n');
        }
    }

    fn code_len(&self) -> usize {
        self.object.sections[self.code.0 as usize].bytes.len()
    }

    fn error(&mut self, message: impl Into<String>, span: SourceSpan) {
        self.errors.push(CodegenError {
            message: message.into(),
            span: Some(span),
        });
    }
}

fn inverse_branch(opcode: u8) -> Option<(u8, &'static str)> {
    match opcode {
        0x10 => Some((0x30, "bmi")),
        0x30 => Some((0x10, "bpl")),
        0x50 => Some((0x70, "bvs")),
        0x70 => Some((0x50, "bvc")),
        0x90 => Some((0xb0, "bcs")),
        0xb0 => Some((0x90, "bcc")),
        0xd0 => Some((0xf0, "beq")),
        0xf0 => Some((0xd0, "bne")),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use nesc_mir::{
        AssemblyClobbers, AssemblyInput, AssemblyOutput, AssemblyOutputTarget, AssemblyRegister,
        BankPlacement, BasicBlock, BinaryOperator, BlockId, Effect, Function, FunctionId,
        InlineAssembly, Instruction, InstructionKind, Local, LocalId, Module, SourceId, SourceSpan,
        Terminator, Type, TypeKind, ValueId,
    };

    use super::{BackendConfig, CodegenGoal, generate, generate_with_config};

    #[test]
    fn emits_constant_return_and_function_symbol() {
        let ty = Type::scalar(TypeKind::Integer(nesc_mir::IntegerType::U8));
        let span = SourceSpan::new(SourceId::new(0), 0, 1);
        let module = Module {
            globals: Vec::new(),
            global_data: Vec::new(),
            functions: vec![Function {
                id: FunctionId(0),
                name: "main".to_owned(),
                placement: BankPlacement::Fixed,
                return_type: ty.clone(),
                parameters: Vec::new(),
                locals: Vec::new(),
                entry: Some(BlockId(0)),
                blocks: vec![BasicBlock {
                    id: BlockId(0),
                    instructions: vec![Instruction {
                        result: Some(ValueId(0)),
                        kind: InstructionKind::Constant(42),
                        effect: nesc_mir::Effect::Pure,
                        span,
                    }],
                    terminator: Some(Terminator::Return(Some(ValueId(0)))),
                }],
                value_types: vec![ty],
            }],
        };
        let generated = generate(&module).expect("code generation");
        assert!(generated.assembly.contains("main:"));
        assert!(generated.assembly.contains("lda #$2a"));
        assert!(
            generated
                .object
                .symbols
                .iter()
                .any(|symbol| symbol.name == "main")
        );
        assert_eq!(
            generated
                .assembly
                .lines()
                .filter(|line| line.trim_start().starts_with("lda "))
                .count(),
            1,
            "the return should reuse the accumulator value:\n{}",
            generated.assembly
        );
        assert!(
            generated
                .optimization_report
                .contains("Register loads removed: 1")
        );
        assert!(
            generated
                .optimization_report
                .contains("Register-forwarding bytes saved: 2")
        );
        assert!(
            generated
                .optimization_report
                .contains("Register-forwarding cycles saved: 3")
        );
    }

    #[test]
    fn reloads_register_values_after_calls() {
        let byte = Type::scalar(TypeKind::Integer(nesc_mir::IntegerType::U8));
        let void = Type::scalar(TypeKind::Void);
        let span = SourceSpan::new(SourceId::new(0), 0, 1);
        let module = Module {
            globals: Vec::new(),
            global_data: Vec::new(),
            functions: vec![
                Function {
                    id: FunctionId(0),
                    name: "main".to_owned(),
                    placement: BankPlacement::Fixed,
                    return_type: byte.clone(),
                    parameters: Vec::new(),
                    locals: Vec::new(),
                    entry: Some(BlockId(0)),
                    blocks: vec![BasicBlock {
                        id: BlockId(0),
                        instructions: vec![
                            Instruction {
                                result: Some(ValueId(0)),
                                kind: InstructionKind::Constant(7),
                                effect: Effect::Pure,
                                span,
                            },
                            Instruction {
                                result: None,
                                kind: InstructionKind::Call {
                                    function: FunctionId(1),
                                    arguments: Vec::new(),
                                },
                                effect: Effect::Call,
                                span,
                            },
                        ],
                        terminator: Some(Terminator::Return(Some(ValueId(0)))),
                    }],
                    value_types: vec![byte],
                },
                Function {
                    id: FunctionId(1),
                    name: "helper".to_owned(),
                    placement: BankPlacement::Fixed,
                    return_type: void,
                    parameters: Vec::new(),
                    locals: Vec::new(),
                    entry: None,
                    blocks: Vec::new(),
                    value_types: Vec::new(),
                },
            ],
        };

        let generated = generate(&module).expect("code generation");
        assert!(generated.assembly.contains("jsr helper"));
        assert_eq!(
            generated
                .assembly
                .lines()
                .filter(|line| line.trim_start().starts_with("lda "))
                .count(),
            2,
            "a call must invalidate caller-saved registers:\n{}",
            generated.assembly
        );
    }

    #[test]
    fn reloads_register_values_at_basic_block_boundaries() {
        let byte = Type::scalar(TypeKind::Integer(nesc_mir::IntegerType::U8));
        let span = SourceSpan::new(SourceId::new(0), 0, 1);
        let module = Module {
            globals: Vec::new(),
            global_data: Vec::new(),
            functions: vec![Function {
                id: FunctionId(0),
                name: "main".to_owned(),
                placement: BankPlacement::Fixed,
                return_type: byte.clone(),
                parameters: Vec::new(),
                locals: Vec::new(),
                entry: Some(BlockId(0)),
                blocks: vec![
                    BasicBlock {
                        id: BlockId(0),
                        instructions: vec![Instruction {
                            result: Some(ValueId(0)),
                            kind: InstructionKind::Constant(9),
                            effect: Effect::Pure,
                            span,
                        }],
                        terminator: Some(Terminator::Jump(BlockId(1))),
                    },
                    BasicBlock {
                        id: BlockId(1),
                        instructions: Vec::new(),
                        terminator: Some(Terminator::Return(Some(ValueId(0)))),
                    },
                ],
                value_types: vec![byte],
            }],
        };

        let generated = generate(&module).expect("code generation");
        assert_eq!(
            generated
                .assembly
                .lines()
                .filter(|line| line.trim_start().starts_with("lda "))
                .count(),
            2,
            "register facts must not cross control-flow joins:\n{}",
            generated.assembly
        );
    }

    #[test]
    fn emits_inline_assembly_operands_calls_and_stack_contract() {
        let byte = Type::scalar(TypeKind::Integer(nesc_mir::IntegerType::U8));
        let void = Type::scalar(TypeKind::Void);
        let span = SourceSpan::new(SourceId::new(0), 0, 1);
        let module = Module {
            globals: Vec::new(),
            global_data: Vec::new(),
            functions: vec![
                Function {
                    id: FunctionId(0),
                    name: "main".to_owned(),
                    placement: BankPlacement::Fixed,
                    return_type: void.clone(),
                    parameters: Vec::new(),
                    locals: vec![Local {
                        id: LocalId(0),
                        name: "result".to_owned(),
                        ty: byte.clone(),
                        parameter: false,
                    }],
                    entry: Some(BlockId(0)),
                    blocks: vec![BasicBlock {
                        id: BlockId(0),
                        instructions: vec![
                            Instruction {
                                result: Some(ValueId(0)),
                                kind: InstructionKind::Constant(7),
                                effect: Effect::Pure,
                                span,
                            },
                            Instruction {
                                result: None,
                                kind: InstructionKind::InlineAssembly(InlineAssembly {
                                    template: "pha\njsr helper\npla".to_owned(),
                                    inputs: vec![AssemblyInput {
                                        register: AssemblyRegister::A,
                                        value: ValueId(0),
                                    }],
                                    outputs: vec![AssemblyOutput {
                                        register: AssemblyRegister::X,
                                        target: AssemblyOutputTarget::Local(LocalId(0)),
                                    }],
                                    clobbers: AssemblyClobbers {
                                        a: true,
                                        flags: true,
                                        memory: true,
                                        ..AssemblyClobbers::default()
                                    },
                                    bank_effect: false,
                                    calls: vec![FunctionId(1)],
                                    stack_bytes: 1,
                                }),
                                effect: Effect::Volatile,
                                span,
                            },
                        ],
                        terminator: Some(Terminator::Return(None)),
                    }],
                    value_types: vec![byte],
                },
                Function {
                    id: FunctionId(1),
                    name: "helper".to_owned(),
                    placement: BankPlacement::Fixed,
                    return_type: void,
                    parameters: Vec::new(),
                    locals: Vec::new(),
                    entry: None,
                    blocks: Vec::new(),
                    value_types: Vec::new(),
                },
            ],
        };
        let generated = generate(&module).expect("code generation");
        assert!(generated.assembly.contains("; begin NES_ASM"));
        assert!(generated.assembly.contains("jsr helper"));
        assert_eq!(generated.stack.functions["main"], 6);
        let helper = generated
            .object
            .symbols
            .iter()
            .position(|symbol| symbol.name == "helper")
            .expect("helper symbol");
        assert!(generated.object.relocations.iter().any(|relocation| {
            relocation.symbol.0 as usize == helper
                && relocation.kind == nesc_object::RelocationKind::Absolute16
        }));
    }

    #[test]
    fn reuses_index_register_inputs_until_inline_assembly_clobbers_flags() {
        let byte = Type::scalar(TypeKind::Integer(nesc_mir::IntegerType::U8));
        let void = Type::scalar(TypeKind::Void);
        let span = SourceSpan::new(SourceId::new(0), 0, 1);
        let input_assembly = || Instruction {
            result: None,
            kind: InstructionKind::InlineAssembly(InlineAssembly {
                template: "nop".to_owned(),
                inputs: vec![AssemblyInput {
                    register: AssemblyRegister::X,
                    value: ValueId(0),
                }],
                outputs: Vec::new(),
                clobbers: AssemblyClobbers::default(),
                bank_effect: false,
                calls: Vec::new(),
                stack_bytes: 0,
            }),
            effect: Effect::Volatile,
            span,
        };
        let flags_clobber = Instruction {
            result: None,
            kind: InstructionKind::InlineAssembly(InlineAssembly {
                template: "nop".to_owned(),
                inputs: Vec::new(),
                outputs: Vec::new(),
                clobbers: AssemblyClobbers {
                    flags: true,
                    ..AssemblyClobbers::default()
                },
                bank_effect: false,
                calls: Vec::new(),
                stack_bytes: 0,
            }),
            effect: Effect::Volatile,
            span,
        };
        let module = Module {
            globals: Vec::new(),
            global_data: Vec::new(),
            functions: vec![Function {
                id: FunctionId(0),
                name: "main".to_owned(),
                placement: BankPlacement::Fixed,
                return_type: void,
                parameters: Vec::new(),
                locals: Vec::new(),
                entry: Some(BlockId(0)),
                blocks: vec![BasicBlock {
                    id: BlockId(0),
                    instructions: vec![
                        Instruction {
                            result: Some(ValueId(0)),
                            kind: InstructionKind::Constant(13),
                            effect: Effect::Pure,
                            span,
                        },
                        input_assembly(),
                        input_assembly(),
                        flags_clobber,
                        input_assembly(),
                    ],
                    terminator: Some(Terminator::Return(None)),
                }],
                value_types: vec![byte],
            }],
        };

        let generated = generate(&module).expect("code generation");
        assert_eq!(
            generated
                .assembly
                .lines()
                .filter(|line| line.trim_start().starts_with("ldx "))
                .count(),
            2,
            "the second input should reuse X, then the flag clobber should force a reload:\n{}",
            generated.assembly
        );
        assert!(
            generated
                .optimization_report
                .contains("Register loads removed: 1")
        );
    }

    #[test]
    fn selects_eight_bit_multiply_helper() {
        let ty = Type::scalar(TypeKind::Integer(nesc_mir::IntegerType::U8));
        let span = SourceSpan::new(SourceId::new(0), 0, 1);
        let module = Module {
            globals: Vec::new(),
            global_data: Vec::new(),
            functions: vec![Function {
                id: FunctionId(0),
                name: "multiply".to_owned(),
                placement: BankPlacement::Fixed,
                return_type: ty.clone(),
                parameters: vec![nesc_mir::LocalId(0), nesc_mir::LocalId(1)],
                locals: vec![
                    nesc_mir::Local {
                        id: nesc_mir::LocalId(0),
                        name: "left".to_owned(),
                        ty: ty.clone(),
                        parameter: true,
                    },
                    nesc_mir::Local {
                        id: nesc_mir::LocalId(1),
                        name: "right".to_owned(),
                        ty: ty.clone(),
                        parameter: true,
                    },
                ],
                entry: Some(BlockId(0)),
                blocks: vec![BasicBlock {
                    id: BlockId(0),
                    instructions: vec![
                        Instruction {
                            result: Some(ValueId(0)),
                            kind: InstructionKind::LoadLocal(nesc_mir::LocalId(0)),
                            effect: nesc_mir::Effect::Read,
                            span,
                        },
                        Instruction {
                            result: Some(ValueId(1)),
                            kind: InstructionKind::LoadLocal(nesc_mir::LocalId(1)),
                            effect: nesc_mir::Effect::Read,
                            span,
                        },
                        Instruction {
                            result: Some(ValueId(2)),
                            kind: InstructionKind::Binary {
                                operator: BinaryOperator::Multiply,
                                left: ValueId(0),
                                right: ValueId(1),
                            },
                            effect: nesc_mir::Effect::Pure,
                            span,
                        },
                    ],
                    terminator: Some(Terminator::Return(Some(ValueId(2)))),
                }],
                value_types: vec![ty.clone(), ty.clone(), ty],
            }],
        };
        let generated = generate(&module).expect("code generation");
        assert!(generated.assembly.contains("jsr __nesc_mul_8"));
        assert!(
            generated
                .object
                .symbols
                .iter()
                .any(|symbol| { symbol.name == "__nesc_mul_8" && symbol.section.is_none() })
        );
    }

    #[test]
    fn selects_shared_helper_or_inline_shift_from_codegen_goal() {
        let ty = Type::scalar(TypeKind::Integer(nesc_mir::IntegerType::U8));
        let span = SourceSpan::new(SourceId::new(0), 0, 1);
        let module = Module {
            globals: Vec::new(),
            global_data: Vec::new(),
            functions: vec![Function {
                id: FunctionId(0),
                name: "multiply".to_owned(),
                placement: BankPlacement::Fixed,
                return_type: ty.clone(),
                parameters: vec![LocalId(0), LocalId(1)],
                locals: vec![
                    Local {
                        id: LocalId(0),
                        name: "left".to_owned(),
                        ty: ty.clone(),
                        parameter: true,
                    },
                    Local {
                        id: LocalId(1),
                        name: "right".to_owned(),
                        ty: ty.clone(),
                        parameter: true,
                    },
                ],
                entry: Some(BlockId(0)),
                blocks: vec![BasicBlock {
                    id: BlockId(0),
                    instructions: vec![
                        Instruction {
                            result: Some(ValueId(0)),
                            kind: InstructionKind::LoadLocal(LocalId(0)),
                            effect: Effect::Read,
                            span,
                        },
                        Instruction {
                            result: Some(ValueId(1)),
                            kind: InstructionKind::LoadLocal(LocalId(1)),
                            effect: Effect::Read,
                            span,
                        },
                        Instruction {
                            result: Some(ValueId(2)),
                            kind: InstructionKind::Binary {
                                operator: BinaryOperator::Multiply,
                                left: ValueId(0),
                                right: ValueId(1),
                            },
                            effect: Effect::Pure,
                            span,
                        },
                        Instruction {
                            result: Some(ValueId(3)),
                            kind: InstructionKind::Constant(8),
                            effect: Effect::Pure,
                            span,
                        },
                        Instruction {
                            result: Some(ValueId(4)),
                            kind: InstructionKind::Binary {
                                operator: BinaryOperator::Multiply,
                                left: ValueId(0),
                                right: ValueId(3),
                            },
                            effect: Effect::Pure,
                            span,
                        },
                    ],
                    terminator: Some(Terminator::Return(Some(ValueId(4)))),
                }],
                value_types: vec![ty.clone(), ty.clone(), ty.clone(), ty.clone(), ty],
            }],
        };
        let min_size = generate_with_config(
            &module,
            &BackendConfig {
                goal: CodegenGoal::MinSize,
                ..BackendConfig::default()
            },
        )
        .expect("minimum-size code generation");
        let cycles = generate_with_config(
            &module,
            &BackendConfig {
                goal: CodegenGoal::Cycles,
                ..BackendConfig::default()
            },
        )
        .expect("cycle-oriented code generation");

        assert_eq!(min_size.assembly.matches("jsr __nesc_mul_8").count(), 2);
        assert_eq!(cycles.assembly.matches("jsr __nesc_mul_8").count(), 1);
        assert_eq!(cycles.assembly.matches("asl $").count(), 3);
        assert!(min_size.optimization_report.contains("selected helper"));
        assert!(cycles.optimization_report.contains("selected inline"));
    }

    #[test]
    fn places_a_hot_true_edge_as_an_inverted_fallthrough() {
        let byte = Type::scalar(TypeKind::Integer(nesc_mir::IntegerType::U8));
        let void = Type::scalar(TypeKind::Void);
        let span = SourceSpan::new(SourceId::new(0), 0, 1);
        let module = Module {
            globals: Vec::new(),
            global_data: Vec::new(),
            functions: vec![Function {
                id: FunctionId(0),
                name: "hot_layout".to_owned(),
                placement: BankPlacement::Fixed,
                return_type: void,
                parameters: vec![LocalId(0)],
                locals: vec![Local {
                    id: LocalId(0),
                    name: "condition".to_owned(),
                    ty: byte.clone(),
                    parameter: true,
                }],
                entry: Some(BlockId(0)),
                blocks: vec![
                    BasicBlock {
                        id: BlockId(0),
                        instructions: vec![Instruction {
                            result: Some(ValueId(0)),
                            kind: InstructionKind::LoadLocal(LocalId(0)),
                            effect: Effect::Read,
                            span,
                        }],
                        terminator: Some(Terminator::Branch {
                            condition: ValueId(0),
                            then_block: BlockId(1),
                            else_block: BlockId(3),
                        }),
                    },
                    BasicBlock {
                        id: BlockId(1),
                        instructions: Vec::new(),
                        terminator: Some(Terminator::Jump(BlockId(2))),
                    },
                    BasicBlock {
                        id: BlockId(2),
                        instructions: Vec::new(),
                        terminator: Some(Terminator::Branch {
                            condition: ValueId(0),
                            then_block: BlockId(1),
                            else_block: BlockId(4),
                        }),
                    },
                    BasicBlock {
                        id: BlockId(3),
                        instructions: Vec::new(),
                        terminator: Some(Terminator::Return(None)),
                    },
                    BasicBlock {
                        id: BlockId(4),
                        instructions: Vec::new(),
                        terminator: Some(Terminator::Return(None)),
                    },
                ],
                value_types: vec![byte],
            }],
        };

        let generated = generate(&module).expect("layout code generation");
        let block1 = generated
            .assembly
            .find("hot_layout.block1:")
            .expect("hot block label");
        let block3 = generated
            .assembly
            .find("hot_layout.block3:")
            .expect("cold block label");

        assert!(block1 < block3);
        assert!(generated.assembly.contains("beq hot_layout.block3"));
        assert!(!generated.assembly.contains("jmp hot_layout.block2"));
        assert!(
            generated
                .optimization_report
                .contains("Branches inverted: 1")
        );
        assert!(
            generated
                .optimization_report
                .contains("Fall-through jumps removed: 1")
        );
    }

    #[test]
    fn relaxes_an_out_of_range_conditional_branch() {
        let byte = Type::scalar(TypeKind::Integer(nesc_mir::IntegerType::U8));
        let void = Type::scalar(TypeKind::Void);
        let span = SourceSpan::new(SourceId::new(0), 0, 1);
        let module = Module {
            globals: Vec::new(),
            global_data: Vec::new(),
            functions: vec![Function {
                id: FunctionId(0),
                name: "long_branch".to_owned(),
                placement: BankPlacement::Fixed,
                return_type: void,
                parameters: vec![LocalId(0)],
                locals: vec![Local {
                    id: LocalId(0),
                    name: "condition".to_owned(),
                    ty: byte.clone(),
                    parameter: true,
                }],
                entry: Some(BlockId(0)),
                blocks: vec![
                    BasicBlock {
                        id: BlockId(0),
                        instructions: vec![Instruction {
                            result: Some(ValueId(0)),
                            kind: InstructionKind::LoadLocal(LocalId(0)),
                            effect: Effect::Read,
                            span,
                        }],
                        terminator: Some(Terminator::Branch {
                            condition: ValueId(0),
                            then_block: BlockId(1),
                            else_block: BlockId(2),
                        }),
                    },
                    BasicBlock {
                        id: BlockId(1),
                        instructions: vec![Instruction {
                            result: None,
                            kind: InstructionKind::InlineAssembly(InlineAssembly {
                                template: "nop\n".repeat(140),
                                inputs: Vec::new(),
                                outputs: Vec::new(),
                                clobbers: AssemblyClobbers::default(),
                                bank_effect: false,
                                calls: Vec::new(),
                                stack_bytes: 0,
                            }),
                            effect: Effect::Volatile,
                            span,
                        }],
                        terminator: Some(Terminator::Return(None)),
                    },
                    BasicBlock {
                        id: BlockId(2),
                        instructions: Vec::new(),
                        terminator: Some(Terminator::Return(None)),
                    },
                ],
                value_types: vec![byte],
            }],
        };

        let generated = generate(&module).expect("relaxed code generation");
        let target = generated
            .object
            .symbols
            .iter()
            .find(|symbol| symbol.name == "long_branch.block2")
            .expect("branch target");

        assert!(
            generated
                .object
                .relocations
                .iter()
                .any(|relocation| relocation.symbol == target.id
                    && relocation.kind == nesc_object::RelocationKind::Absolute16)
        );
        assert!(!generated.object.relocations.iter().any(|relocation| {
            relocation.symbol == target.id
                && relocation.kind == nesc_object::RelocationKind::Relative8
        }));
        assert!(generated.assembly.contains("bne .__nesc_relax_"));
        assert!(generated.assembly.contains("jmp long_branch.block2"));
        assert!(
            generated
                .optimization_report
                .contains("Branches relaxed: 1")
        );
    }
}
