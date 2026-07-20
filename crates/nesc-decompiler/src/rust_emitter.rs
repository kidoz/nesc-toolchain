use std::collections::BTreeMap;
use std::fmt::Write;

use nesc_disasm::AddressingMode;

use super::{
    AccumulatorOperator, AnalysisError, BlockId, ComparisonPredicate, Confidence,
    ControlFlowAnalysis, FallbackReason, Flag, LoopForm, MemoryOperand, Program,
    RecoveredCondition, RecoveredPredicate, RecoveryAnalysis, Register, SemanticOperation,
    ShiftOperator, StackControl, StateVariable, StructuredFunction, StructuredRegionKind,
    ValueAnalysis, ValueSource, ValueTarget,
};

/// Resource bounds for stable-Rust source generation from untrusted programs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RustEmissionLimits {
    /// Maximum recovered functions accepted by the emitter.
    pub max_functions: usize,
    /// Maximum semantic instructions accepted by the emitter.
    pub max_instructions: usize,
    /// Maximum structured regions accepted by the emitter.
    pub max_regions: usize,
    /// Maximum structured-region nesting rendered recursively.
    pub max_nesting: usize,
    /// Maximum bytes in the generated Rust source.
    pub max_source_bytes: usize,
}

impl Default for RustEmissionLimits {
    fn default() -> Self {
        Self {
            max_functions: 100_000,
            max_instructions: 1_000_000,
            max_regions: 2_000_000,
            max_nesting: 256,
            max_source_bytes: 64 * 1024 * 1024,
        }
    }
}

/// Stable-Rust project generation settings.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RustEmitConfig {
    /// Generated Cargo package name.
    pub crate_name: String,
    /// Filesystem path to the `nesc-decompile-runtime` crate.
    pub runtime_path: String,
    /// Reject any output that requires interpreter fallback.
    pub high_level_only: bool,
    /// Maximum nested JSR depth permitted inside one fallback invocation.
    pub max_fallback_call_depth: usize,
}

/// Complete generated stable-Rust project contents.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RustProject {
    /// Generated `Cargo.toml`.
    pub cargo_toml: String,
    /// Generated `src/lib.rs` host-side semantic translation.
    pub source: String,
    /// Deterministic confidence and fallback report.
    pub report_json: String,
}

/// Bounds for generated original-versus-translated Rust verification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RustVerificationLimits {
    /// Instruction budget assigned to each original and translated execution.
    pub instruction_limit: u64,
    /// Maximum generated integration-test source size.
    pub max_source_bytes: usize,
}

impl Default for RustVerificationLimits {
    fn default() -> Self {
        Self {
            instruction_limit: 1_000_000,
            max_source_bytes: 16 * 1024 * 1024,
        }
    }
}

/// Emits a stable Rust 2024 host-side semantic translation.
///
/// Structured regions become native Rust control flow. Any uncertain function
/// becomes an explicit bounded interpreter call over original bank-qualified
/// instruction bytes.
///
/// # Errors
///
/// Returns deterministic failures for malformed prerequisite analyses,
/// unsupported mappers, invalid settings, high-level-only fallback, or
/// exhausted source-generation limits.
pub fn emit_rust_project(
    program: &Program,
    values: &ValueAnalysis,
    recovery: &RecoveryAnalysis,
    control: &ControlFlowAnalysis,
    config: &RustEmitConfig,
    limits: RustEmissionLimits,
) -> Result<RustProject, Vec<AnalysisError>> {
    validate_limits(limits)?;
    program.verify()?;
    values.verify(program)?;
    recovery.verify(program, values)?;
    control.verify(program, values, recovery)?;
    if program.mapper != 0 {
        return Err(vec![AnalysisError::new(format!(
            "stable-Rust emission currently supports Mapper 0, not Mapper {}",
            program.mapper
        ))]);
    }
    validate_config(config)?;
    let instruction_count = program
        .blocks
        .values()
        .map(|block| block.instructions.len())
        .sum::<usize>();
    let region_count = control
        .functions
        .iter()
        .map(|function| function.regions.len())
        .sum::<usize>();
    if program.functions.len() > limits.max_functions {
        return Err(vec![AnalysisError::new(format!(
            "Rust emission function limit {} exceeded",
            limits.max_functions
        ))]);
    }
    if instruction_count > limits.max_instructions {
        return Err(vec![AnalysisError::new(format!(
            "Rust emission instruction limit {} exceeded",
            limits.max_instructions
        ))]);
    }
    if region_count > limits.max_regions {
        return Err(vec![AnalysisError::new(format!(
            "Rust emission region limit {} exceeded",
            limits.max_regions
        ))]);
    }

    let fallback_count = control
        .functions
        .iter()
        .flat_map(|function| &function.regions)
        .filter(|region| matches!(region.kind, StructuredRegionKind::Fallback { .. }))
        .count();
    if config.high_level_only && fallback_count != 0 {
        return Err(vec![AnalysisError::new(format!(
            "high-level-only Rust emission rejected {fallback_count} interpreter fallback region(s)"
        ))]);
    }

    let names = program
        .functions
        .iter()
        .map(|function| (function.id, rust_function_name(function.id, function.entry)))
        .collect::<BTreeMap<_, _>>();
    let mut emitter = Emitter {
        program,
        control,
        config,
        limits,
        names,
        source: String::new(),
    };
    emitter.emit(fallback_count != 0)?;
    Ok(RustProject {
        cargo_toml: cargo_toml(config),
        source: emitter.source,
        report_json: render_report(program, control),
    })
}

fn rust_function_name(function: super::FunctionId, entry: BlockId) -> String {
    format!(
        "fn_prg{:04x}_{:04x}_{}",
        entry.bank, entry.cpu_address, function.0
    )
}

/// Emits a generated integration test that differentially executes every
/// recovered function from four deterministic RAM states.
///
/// # Errors
///
/// Rejects unsupported cartridge layouts, invalid crate names, zero limits,
/// inconsistent PRG sizes, or excessive generated test source.
pub fn emit_rust_verification(
    program: &Program,
    prg_rom: &[u8],
    crate_name: &str,
    limits: RustVerificationLimits,
) -> Result<String, Vec<AnalysisError>> {
    program.verify()?;
    if program.mapper != 0 {
        return Err(vec![AnalysisError::new(format!(
            "Rust verification currently supports Mapper 0, not Mapper {}",
            program.mapper
        ))]);
    }
    if !matches!(prg_rom.len(), 0x4000 | 0x8000) {
        return Err(vec![AnalysisError::new(format!(
            "Mapper 0 verification requires 16 or 32 KiB PRG-ROM, not {} bytes",
            prg_rom.len()
        ))]);
    }
    if limits.instruction_limit == 0 || limits.max_source_bytes == 0 {
        return Err(vec![AnalysisError::new(
            "Rust verification limits must permit instructions and source bytes",
        )]);
    }
    let rust_crate = crate_name.replace('-', "_");
    if rust_crate.is_empty()
        || !rust_crate
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_alphabetic())
        || !rust_crate
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
    {
        return Err(vec![AnalysisError::new(
            "verification crate name is not a valid generated Rust identifier",
        )]);
    }

    let mut source = String::new();
    source.push_str(
        "use nesc_decompile_runtime::{\n    Bus, CodeSegment, CpuState, ExecutionBudget, ObservableEvent, RuntimeError,\n    interpret_function,\n};\n",
    );
    let _ = writeln!(source, "use {rust_crate} as recovered;");
    source.push_str("\nconst PRG_ROM: &[u8] = &[\n");
    for chunk in prg_rom.chunks(16) {
        source.push_str("    ");
        for byte in chunk {
            let _ = write!(source, "0x{byte:02x}, ");
        }
        source.push('\n');
    }
    source.push_str(
        "];

const ORIGINAL_CODE: &[CodeSegment] = &[
",
    );
    for block in program.blocks.values() {
        for instruction in &block.instructions {
            let bytes = instruction
                .provenance
                .bytes
                .iter()
                .map(|byte| format!("0x{byte:02x}"))
                .collect::<Vec<_>>()
                .join(", ");
            let _ = writeln!(
                source,
                "    CodeSegment {{ bank: {}, cpu_address: 0x{:04x}, bytes: &[{}] }},",
                instruction.provenance.address.bank,
                instruction.provenance.address.cpu_address,
                bytes
            );
        }
    }
    source.push_str(
        r#"];

#[derive(Clone)]
struct TestBus {
    ram: Box<[u8; 0x800]>,
    io: Box<[u8; 0x4000]>,
    prg_ram: Box<[u8; 0x2000]>,
    events: Vec<ObservableEvent>,
}

impl TestBus {
    fn with_pattern(pattern: u8) -> Self {
        let mut ram = Box::new([0; 0x800]);
        let mut prg_ram = Box::new([0; 0x2000]);
        for (index, byte) in ram.iter_mut().enumerate() {
            *byte = pattern.wrapping_add(index as u8);
        }
        for (index, byte) in prg_ram.iter_mut().enumerate() {
            *byte = pattern.wrapping_sub(index as u8);
        }
        Self {
            ram,
            io: Box::new([0; 0x4000]),
            prg_ram,
            events: Vec::new(),
        }
    }
}

impl Bus for TestBus {
    fn read(&mut self, state: &CpuState, address: u16) -> Result<u8, RuntimeError> {
        match address {
            0x0000..=0x1fff => Ok(self.ram[usize::from(address & 0x07ff)]),
            0x2000..=0x5fff => Ok(self.io[usize::from(address - 0x2000)]),
            0x6000..=0x7fff => Ok(self.prg_ram[usize::from(address - 0x6000)]),
            0x8000..=0xffff => {
                let offset = if PRG_ROM.len() == 0x4000 {
                    usize::from(address & 0x3fff)
                } else {
                    usize::from(address - 0x8000)
                };
                PRG_ROM.get(offset).copied().ok_or_else(|| RuntimeError::bus(state, "unmapped PRG read"))
            }
        }
    }

    fn write(&mut self, _state: &CpuState, address: u16, value: u8) -> Result<(), RuntimeError> {
        match address {
            0x0000..=0x1fff => self.ram[usize::from(address & 0x07ff)] = value,
            0x2000..=0x5fff => self.io[usize::from(address - 0x2000)] = value,
            0x6000..=0x7fff => self.prg_ram[usize::from(address - 0x6000)] = value,
            0x8000..=0xffff => {}
        }
        Ok(())
    }

    fn observe(&mut self, event: ObservableEvent) -> Result<(), RuntimeError> {
        self.events.push(event);
        Ok(())
    }

    fn mapped_prg_bank(&self, address: u16) -> Option<u16> {
        if PRG_ROM.len() == 0x4000 || address < 0xc000 { Some(0) } else { Some(1) }
    }
}

type Translation = fn(&mut CpuState, &mut TestBus, &mut ExecutionBudget) -> Result<(), RuntimeError>;

fn compare_translation(entry_bank: u16, entry: u16, translated: Translation, pattern: u8) {
    let mut original_state = CpuState::default();
    let mut translated_state = CpuState::default();
    original_state.status = nesc_decompile_runtime::ProcessorStatus::from_bits(pattern);
    translated_state.status = original_state.status;
    let mut original_bus = TestBus::with_pattern(pattern);
    let mut translated_bus = original_bus.clone();
"#,
    );
    let _ = writeln!(
        source,
        "    let mut original_budget = ExecutionBudget::new({}).expect(\"verification budget\");",
        limits.instruction_limit
    );
    let _ = writeln!(
        source,
        "    let mut translated_budget = ExecutionBudget::new({}).expect(\"verification budget\");",
        limits.instruction_limit
    );
    source.push_str(
        r#"    let original_result = interpret_function(
        &mut original_state,
        &mut original_bus,
        &mut original_budget,
        ORIGINAL_CODE,
        entry_bank,
        entry,
        256,
    );
    let translated_result = translated(
        &mut translated_state,
        &mut translated_bus,
        &mut translated_budget,
    );
    match (&original_result, &translated_result) {
        (Ok(()), Ok(())) => {}
        (Err(original), Err(translated)) => assert_eq!(
            translated.message, original.message,
            "different failures for pattern {pattern:#04x} at entry {entry:#06x}",
        ),
        _ => panic!(
            "termination differs for pattern {pattern:#04x} at entry {entry:#06x}: original={original_result:?}, translated={translated_result:?}",
        ),
    }
    assert_eq!(translated_state, original_state, "CPU state differs for pattern {pattern:#04x} at entry {entry:#06x}");
    assert_eq!(translated_bus.ram, original_bus.ram, "RAM differs for pattern {pattern:#04x} at entry {entry:#06x}");
    assert_eq!(translated_bus.io, original_bus.io, "I/O state differs for pattern {pattern:#04x} at entry {entry:#06x}");
    assert_eq!(translated_bus.prg_ram, original_bus.prg_ram, "PRG RAM differs for pattern {pattern:#04x} at entry {entry:#06x}");
    if translated_bus.events != original_bus.events {
        let first = translated_bus.events.iter().zip(&original_bus.events).position(|(translated, original)| translated != original).unwrap_or_else(|| translated_bus.events.len().min(original_bus.events.len()));
        panic!("first divergent observable event {first} for pattern {pattern:#04x} at entry {entry:#06x}: original={:?}, translated={:?}", original_bus.events.get(first), translated_bus.events.get(first));
    }
    assert_eq!(translated_budget.consumed(), original_budget.consumed(), "instruction use differs for pattern {pattern:#04x} at entry {entry:#06x}");
}
"#,
    );
    for function in &program.functions {
        let name = rust_function_name(function.id, function.entry);
        let _ = writeln!(
            source,
            "\n#[test]\nfn verify_{name}() {{\n    for pattern in [0x00_u8, 0x01, 0x7f, 0xff] {{\n        compare_translation({}, 0x{:04x}, recovered::{name}, pattern);\n    }}\n}}",
            function.entry.bank, function.entry.cpu_address
        );
    }
    if source.len() > limits.max_source_bytes {
        return Err(vec![AnalysisError::new(format!(
            "generated Rust verification source exceeds {} bytes",
            limits.max_source_bytes
        ))]);
    }
    Ok(source)
}

fn validate_limits(limits: RustEmissionLimits) -> Result<(), Vec<AnalysisError>> {
    if limits.max_functions == 0
        || limits.max_instructions == 0
        || limits.max_regions == 0
        || limits.max_nesting == 0
        || limits.max_source_bytes == 0
    {
        return Err(vec![AnalysisError::new(
            "Rust emission limits must permit functions, instructions, regions, nesting, and source bytes",
        )]);
    }
    Ok(())
}

fn validate_config(config: &RustEmitConfig) -> Result<(), Vec<AnalysisError>> {
    let valid_name = !config.crate_name.is_empty()
        && config
            .crate_name
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_alphabetic())
        && config.crate_name.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-' || byte == b'_'
        });
    if !valid_name {
        return Err(vec![AnalysisError::new(
            "generated Rust crate name must begin with an ASCII letter and contain lowercase letters, digits, '-' or '_'",
        )]);
    }
    if config.runtime_path.is_empty() {
        return Err(vec![AnalysisError::new(
            "generated Rust project requires a nonempty runtime path",
        )]);
    }
    if config.max_fallback_call_depth == 0 {
        return Err(vec![AnalysisError::new(
            "fallback call-depth limit must be greater than zero",
        )]);
    }
    Ok(())
}

struct Emitter<'a> {
    program: &'a Program,
    control: &'a ControlFlowAnalysis,
    config: &'a RustEmitConfig,
    limits: RustEmissionLimits,
    names: BTreeMap<super::FunctionId, String>,
    source: String,
}

impl Emitter<'_> {
    fn emit(&mut self, has_fallback: bool) -> Result<(), Vec<AnalysisError>> {
        self.line(0, "#![forbid(unsafe_code)]")?;
        self.line(0, "//! Host-side semantic translation of an NES ROM.")?;
        self.line(
            0,
            "//! Generated output is not Rust-to-NES compiler input and does not claim original source recovery.",
        )?;
        self.line(0, "")?;
        self.line(0, "use nesc_decompile_runtime as runtime;")?;
        self.line(0, "")?;
        self.line(
            0,
            &format!("pub const MAPPER: u16 = {};", self.program.mapper),
        )?;
        if has_fallback {
            self.line(0, "")?;
            self.line(0, "const ORIGINAL_CODE: &[runtime::CodeSegment] = &[")?;
            for block in self.program.blocks.values() {
                for instruction in &block.instructions {
                    let bytes = instruction
                        .provenance
                        .bytes
                        .iter()
                        .map(|byte| format!("0x{byte:02x}"))
                        .collect::<Vec<_>>()
                        .join(", ");
                    self.line(
                        1,
                        &format!(
                            "runtime::CodeSegment {{ bank: {}, cpu_address: 0x{:04x}, bytes: &[{}] }},",
                            instruction.provenance.address.bank,
                            instruction.provenance.address.cpu_address,
                            bytes
                        ),
                    )?;
                }
            }
            self.line(0, "];")?;
        }
        let functions = self.control.functions.clone();
        for structured in &functions {
            self.emit_function(structured)?;
        }
        Ok(())
    }

    fn emit_function(&mut self, structured: &StructuredFunction) -> Result<(), Vec<AnalysisError>> {
        let function = &self.program.functions[structured.function.0 as usize];
        let name = self.names[&function.id].clone();
        self.line(0, "")?;
        self.line(
            0,
            &format!(
                "/// Recovered `{}` at PRG bank {}, CPU ${:04X}; confidence {:?}.",
                function.name,
                function.entry.bank,
                function.entry.cpu_address,
                structured.confidence
            ),
        )?;
        self.line(
            0,
            &format!(
                "pub fn {name}<B: runtime::Bus>(state: &mut runtime::CpuState, bus: &mut B, budget: &mut runtime::ExecutionBudget) -> Result<(), runtime::RuntimeError> {{"
            ),
        )?;
        self.line(1, "let _ = &mut *bus;")?;
        self.emit_region(structured, structured.root, 1, 0)?;
        self.line(1, "Ok(())")?;
        self.line(0, "}")
    }

    fn emit_region(
        &mut self,
        function: &StructuredFunction,
        region_id: super::RegionId,
        indent: usize,
        depth: usize,
    ) -> Result<(), Vec<AnalysisError>> {
        if depth >= self.limits.max_nesting {
            return Err(vec![AnalysisError::new(format!(
                "Rust emission nesting limit {} exceeded",
                self.limits.max_nesting
            ))]);
        }
        let region = &function.regions[region_id.0 as usize];
        match &region.kind {
            StructuredRegionKind::Sequence { children } => {
                for child in children {
                    self.emit_region(function, *child, indent, depth + 1)?;
                }
            }
            StructuredRegionKind::Block { block } => self.emit_block(*block, indent)?,
            StructuredRegionKind::If {
                header,
                condition,
                then_region,
                else_region,
                ..
            } => {
                self.emit_block(*header, indent)?;
                self.line(indent, &format!("if {} {{", render_condition(condition)))?;
                if let Some(child) = then_region {
                    self.emit_region(function, *child, indent + 1, depth + 1)?;
                }
                if let Some(child) = else_region {
                    self.line(indent, "} else {")?;
                    self.emit_region(function, *child, indent + 1, depth + 1)?;
                }
                self.line(indent, "}")?;
            }
            StructuredRegionKind::Loop {
                header,
                condition,
                body,
                form,
                ..
            } => {
                match form {
                    LoopForm::While => self.line(indent, "// Proven natural loop.")?,
                    LoopForm::Counted(counted) => self.line(
                        indent,
                        &format!(
                            "// Counted natural loop: {} changes by {} toward {}.",
                            render_state_variable(counted.induction),
                            counted.step,
                            counted.bound
                        ),
                    )?,
                }
                self.line(indent, "while {")?;
                self.emit_block(*header, indent + 1)?;
                self.line(indent + 1, &render_condition(condition))?;
                self.line(indent, "} {")?;
                if let Some(child) = body {
                    self.emit_region(function, *child, indent + 1, depth + 1)?;
                }
                self.line(indent, "}")?;
            }
            StructuredRegionKind::Call { block, callee, .. } => {
                self.emit_block(*block, indent)?;
                let call = self.program.blocks[block]
                    .instructions
                    .last()
                    .expect("verified call block contains an instruction");
                let return_address = call
                    .provenance
                    .address
                    .cpu_address
                    .wrapping_add(call.provenance.bytes.len() as u16)
                    .wrapping_sub(1);
                self.line(
                    indent,
                    &format!(
                        "runtime::push(state, bus, budget, 0x{:02x})?;",
                        return_address >> 8
                    ),
                )?;
                self.line(
                    indent,
                    &format!(
                        "runtime::push(state, bus, budget, 0x{:02x})?;",
                        return_address as u8
                    ),
                )?;
                let name = &self.names[callee];
                self.line(indent, &format!("{name}(state, bus, budget)?;"))?;
                self.line(
                    indent,
                    "let return_low = runtime::pop(state, bus, budget)?;",
                )?;
                self.line(
                    indent,
                    "let return_high = runtime::pop(state, bus, budget)?;",
                )?;
                self.line(
                    indent,
                    "state.pc = u16::from_le_bytes([return_low, return_high]).wrapping_add(1);",
                )?;
            }
            StructuredRegionKind::Return { block, interrupt } => {
                self.emit_block(*block, indent)?;
                if *interrupt {
                    self.line(
                        indent,
                        "state.status = runtime::ProcessorStatus::from_bits(runtime::pop(state, bus, budget)?);",
                    )?;
                    self.line(
                        indent,
                        "let return_low = runtime::pop(state, bus, budget)?;",
                    )?;
                    self.line(
                        indent,
                        "let return_high = runtime::pop(state, bus, budget)?;",
                    )?;
                    self.line(
                        indent,
                        "state.pc = u16::from_le_bytes([return_low, return_high]);",
                    )?;
                }
            }
            StructuredRegionKind::Fallback { reason } => {
                let entry = self.program.functions[function.function.0 as usize].entry;
                self.line(
                    indent,
                    &format!("// Interpreter fallback: {}.", fallback_name(*reason)),
                )?;
                self.line(
                    indent,
                    &format!(
                        "runtime::interpret_function(state, bus, budget, ORIGINAL_CODE, {}, 0x{:04x}, {})?;",
                        entry.bank, entry.cpu_address, self.config.max_fallback_call_depth
                    ),
                )?;
            }
        }
        Ok(())
    }

    fn emit_block(&mut self, block_id: BlockId, indent: usize) -> Result<(), Vec<AnalysisError>> {
        let block = &self.program.blocks[&block_id];
        for instruction in &block.instructions {
            let provenance = &instruction.provenance;
            let bytes = provenance
                .bytes
                .iter()
                .map(|byte| format!("{byte:02X}"))
                .collect::<Vec<_>>()
                .join(" ");
            self.line(
                indent,
                &format!(
                    "// ROM +0x{:X}, PRG +0x{:X}, bank {}, CPU ${:04X}: {}",
                    provenance.rom_file_offset,
                    provenance.prg_offset,
                    provenance.address.bank,
                    provenance.address.cpu_address,
                    bytes
                ),
            )?;
            self.line(
                indent,
                &format!("state.bank = {};", provenance.address.bank),
            )?;
            self.line(
                indent,
                &format!("state.pc = 0x{:04x};", provenance.address.cpu_address),
            )?;
            self.line(indent, "budget.consume(state)?;")?;
            for operation in &instruction.operations {
                if matches!(operation, SemanticOperation::StackControl(_)) {
                    continue;
                }
                self.emit_operation(operation, indent)?;
            }
        }
        Ok(())
    }

    fn emit_operation(
        &mut self,
        operation: &SemanticOperation,
        indent: usize,
    ) -> Result<(), Vec<AnalysisError>> {
        match operation {
            SemanticOperation::Load {
                destination,
                source,
            } => {
                self.line(indent, "{")?;
                self.line(
                    indent + 1,
                    &format!(
                        "let value = runtime::read_source(state, bus, budget, {})?;",
                        render_source(source)?
                    ),
                )?;
                self.line(
                    indent + 1,
                    &format!(
                        "runtime::load(state, runtime::Register::{}, value);",
                        register_name(*destination)
                    ),
                )?;
                self.line(indent, "}")?;
            }
            SemanticOperation::Store {
                destination,
                source,
            } => {
                self.line(
                    indent,
                    &format!(
                        "runtime::write_target(state, bus, budget, runtime::ValueTarget::Memory({}), state.register(runtime::Register::{}))?;",
                        render_operand(destination)?,
                        register_name(*source)
                    ),
                )?;
            }
            SemanticOperation::Accumulate {
                operator, source, ..
            } => {
                self.line(indent, "{")?;
                self.line(
                    indent + 1,
                    &format!(
                        "let value = runtime::read_source(state, bus, budget, {})?;",
                        render_source(source)?
                    ),
                )?;
                self.line(
                    indent + 1,
                    &format!(
                        "runtime::accumulate(state, runtime::AccumulatorOperator::{}, value);",
                        accumulator_name(*operator)
                    ),
                )?;
                self.line(indent, "}")?;
            }
            SemanticOperation::Compare { left, right } => {
                self.line(indent, "{")?;
                self.line(
                    indent + 1,
                    &format!(
                        "let right = runtime::read_source(state, bus, budget, {})?;",
                        render_source(right)?
                    ),
                )?;
                self.line(
                    indent + 1,
                    &format!(
                        "runtime::compare(state, state.register(runtime::Register::{}), right);",
                        register_name(*left)
                    ),
                )?;
                self.line(indent, "}")?;
            }
            SemanticOperation::TestBits { source } => {
                self.line(indent, "{")?;
                self.line(
                    indent + 1,
                    &format!(
                        "let value = runtime::read_source(state, bus, budget, {})?;",
                        render_source(source)?
                    ),
                )?;
                self.line(indent + 1, "runtime::test_bits(state, value);")?;
                self.line(indent, "}")?;
            }
            SemanticOperation::Shift {
                operator, target, ..
            } => {
                self.line(indent, "{")?;
                self.line(
                    indent + 1,
                    &format!("let target = {};", render_target(target)?),
                )?;
                self.line(
                    indent + 1,
                    "let value = match target { runtime::ValueTarget::Register(register) => state.register(register), runtime::ValueTarget::Memory(operand) => runtime::read_source(state, bus, budget, runtime::ValueSource::Memory(operand))?, runtime::ValueTarget::Status => state.status.bits() };",
                )?;
                self.line(
                    indent + 1,
                    &format!(
                        "let output = runtime::shift(state, runtime::ShiftOperator::{}, value);",
                        shift_name(*operator)
                    ),
                )?;
                self.line(
                    indent + 1,
                    "runtime::write_target(state, bus, budget, target, output)?;",
                )?;
                self.line(indent, "}")?;
            }
            SemanticOperation::Adjust { target, delta } => {
                self.line(indent, "{")?;
                self.line(
                    indent + 1,
                    &format!("let target = {};", render_target(target)?),
                )?;
                self.line(
                    indent + 1,
                    "let value = match target { runtime::ValueTarget::Register(register) => state.register(register), runtime::ValueTarget::Memory(operand) => runtime::read_source(state, bus, budget, runtime::ValueSource::Memory(operand))?, runtime::ValueTarget::Status => state.status.bits() };",
                )?;
                self.line(
                    indent + 1,
                    &format!("let output = value.wrapping_add_signed({delta}_i8);"),
                )?;
                self.line(
                    indent + 1,
                    "runtime::write_target(state, bus, budget, target, output)?;",
                )?;
                self.line(indent + 1, "state.status.set_negative_zero(output);")?;
                self.line(indent, "}")?;
            }
            SemanticOperation::Transfer {
                source,
                destination,
                update_negative_zero,
            } => {
                self.line(
                    indent,
                    &format!(
                        "state.set_register(runtime::Register::{}, state.register(runtime::Register::{}));",
                        register_name(*destination),
                        register_name(*source)
                    ),
                )?;
                if *update_negative_zero {
                    self.line(
                        indent,
                        &format!(
                            "state.status.set_negative_zero(state.register(runtime::Register::{}));",
                            register_name(*destination)
                        ),
                    )?;
                }
            }
            SemanticOperation::SetFlag { flag, value } => self.line(
                indent,
                &format!(
                    "state.status.set(runtime::Flag::{}, {value});",
                    flag_name(*flag)
                ),
            )?,
            SemanticOperation::Push { source } => {
                self.line(indent, "{")?;
                self.line(
                    indent + 1,
                    &format!(
                        "let value = runtime::read_source(state, bus, budget, {})?;",
                        render_source(source)?
                    ),
                )?;
                self.line(indent + 1, "runtime::push(state, bus, budget, value)?;")?;
                self.line(indent, "}")?;
            }
            SemanticOperation::Pull {
                destination,
                update_negative_zero,
            } => {
                self.line(indent, "{")?;
                self.line(indent + 1, "let value = runtime::pop(state, bus, budget)?;")?;
                self.line(
                    indent + 1,
                    &format!(
                        "runtime::write_target(state, bus, budget, {}, value)?;",
                        render_target(destination)?
                    ),
                )?;
                if *update_negative_zero {
                    self.line(indent + 1, "state.status.set_negative_zero(value);")?;
                }
                self.line(indent, "}")?;
            }
            SemanticOperation::StackControl(StackControl::PushReturnAddress)
            | SemanticOperation::StackControl(StackControl::PopReturnAddress)
            | SemanticOperation::StackControl(StackControl::PushInterruptFrame)
            | SemanticOperation::StackControl(StackControl::PopInterruptFrame)
            | SemanticOperation::MapperWrite { .. }
            | SemanticOperation::NoOperation => {}
        }
        Ok(())
    }

    fn line(&mut self, indent: usize, line: &str) -> Result<(), Vec<AnalysisError>> {
        for _ in 0..indent {
            self.source.push_str("    ");
        }
        self.source.push_str(line);
        self.source.push('\n');
        if self.source.len() > self.limits.max_source_bytes {
            return Err(vec![AnalysisError::new(format!(
                "generated Rust source exceeds {} bytes",
                self.limits.max_source_bytes
            ))]);
        }
        Ok(())
    }
}

fn render_condition(condition: &RecoveredCondition) -> String {
    match condition.predicate {
        RecoveredPredicate::Comparison { predicate, .. } => match predicate {
            ComparisonPredicate::Equal => "state.status.get(runtime::Flag::Zero)".to_owned(),
            ComparisonPredicate::NotEqual => "!state.status.get(runtime::Flag::Zero)".to_owned(),
            ComparisonPredicate::UnsignedGreaterEqual => {
                "state.status.get(runtime::Flag::Carry)".to_owned()
            }
            ComparisonPredicate::UnsignedLess => {
                "!state.status.get(runtime::Flag::Carry)".to_owned()
            }
        },
        RecoveredPredicate::FlagValue { flag, expected, .. } => format!(
            "state.status.get(runtime::Flag::{}) == {expected}",
            flag_name(flag)
        ),
    }
}

fn render_source(source: &ValueSource) -> Result<String, Vec<AnalysisError>> {
    match source {
        ValueSource::Register(register) => Ok(format!(
            "runtime::ValueSource::Register(runtime::Register::{})",
            register_name(*register)
        )),
        ValueSource::Immediate(value) => {
            Ok(format!("runtime::ValueSource::Immediate(0x{value:02x})"))
        }
        ValueSource::Memory(operand) => Ok(format!(
            "runtime::ValueSource::Memory({})",
            render_operand(operand)?
        )),
        ValueSource::Status => Ok("runtime::ValueSource::Status".to_owned()),
    }
}

fn render_target(target: &ValueTarget) -> Result<String, Vec<AnalysisError>> {
    match target {
        ValueTarget::Register(register) => Ok(format!(
            "runtime::ValueTarget::Register(runtime::Register::{})",
            register_name(*register)
        )),
        ValueTarget::Memory(operand) => Ok(format!(
            "runtime::ValueTarget::Memory({})",
            render_operand(operand)?
        )),
        ValueTarget::Status => Ok("runtime::ValueTarget::Status".to_owned()),
    }
}

fn render_operand(operand: &MemoryOperand) -> Result<String, Vec<AnalysisError>> {
    let byte = operand.encoded as u8;
    let rendered = match operand.mode {
        AddressingMode::ZeroPage => format!("runtime::Operand::ZeroPage(0x{byte:02x})"),
        AddressingMode::ZeroPageX => format!("runtime::Operand::ZeroPageX(0x{byte:02x})"),
        AddressingMode::ZeroPageY => format!("runtime::Operand::ZeroPageY(0x{byte:02x})"),
        AddressingMode::Absolute => {
            format!("runtime::Operand::Absolute(0x{:04x})", operand.encoded)
        }
        AddressingMode::AbsoluteX => {
            format!("runtime::Operand::AbsoluteX(0x{:04x})", operand.encoded)
        }
        AddressingMode::AbsoluteY => {
            format!("runtime::Operand::AbsoluteY(0x{:04x})", operand.encoded)
        }
        AddressingMode::IndexedIndirect => {
            format!("runtime::Operand::IndexedIndirect(0x{byte:02x})")
        }
        AddressingMode::IndirectIndexed => {
            format!("runtime::Operand::IndirectIndexed(0x{byte:02x})")
        }
        mode => {
            return Err(vec![AnalysisError::new(format!(
                "cannot emit data operand with addressing mode {mode:?}"
            ))]);
        }
    };
    Ok(rendered)
}

const fn register_name(register: Register) -> &'static str {
    match register {
        Register::A => "A",
        Register::X => "X",
        Register::Y => "Y",
        Register::StackPointer => "StackPointer",
        Register::ProgramCounter => "ProgramCounter",
    }
}

const fn flag_name(flag: Flag) -> &'static str {
    match flag {
        Flag::Carry => "Carry",
        Flag::Zero => "Zero",
        Flag::InterruptDisable => "InterruptDisable",
        Flag::Decimal => "Decimal",
        Flag::Break => "Break",
        Flag::Overflow => "Overflow",
        Flag::Negative => "Negative",
    }
}

const fn accumulator_name(operator: AccumulatorOperator) -> &'static str {
    match operator {
        AccumulatorOperator::AddWithCarry => "AddWithCarry",
        AccumulatorOperator::SubtractWithCarry => "SubtractWithCarry",
        AccumulatorOperator::And => "And",
        AccumulatorOperator::Or => "Or",
        AccumulatorOperator::ExclusiveOr => "ExclusiveOr",
    }
}

const fn shift_name(operator: ShiftOperator) -> &'static str {
    match operator {
        ShiftOperator::ArithmeticLeft => "ArithmeticLeft",
        ShiftOperator::LogicalRight => "LogicalRight",
        ShiftOperator::RotateLeft => "RotateLeft",
        ShiftOperator::RotateRight => "RotateRight",
    }
}

fn render_state_variable(variable: StateVariable) -> String {
    match variable {
        StateVariable::Register(register) => format!("register {}", register_name(register)),
        StateVariable::Flag(flag) => format!("flag {}", flag_name(flag)),
        StateVariable::Memory(location) => format!("memory {location:?}"),
        StateVariable::MemoryEpoch => "memory epoch".to_owned(),
    }
}

const fn fallback_name(reason: FallbackReason) -> &'static str {
    match reason {
        FallbackReason::UnresolvedControl => "unresolved control flow",
        FallbackReason::IrreducibleControlFlow => "irreducible control flow",
        FallbackReason::RecursiveCallGraph => "recursive call graph",
        FallbackReason::MultipleLoopExits => "loop with multiple exits",
        FallbackReason::MissingConditionalMerge => "conditional without a proven merge",
        FallbackReason::OverlappingRegions => "overlapping structured regions",
        FallbackReason::InterruptControl => "interrupt control",
        FallbackReason::UnsupportedShape => "unsupported control-flow shape",
    }
}

fn cargo_toml(config: &RustEmitConfig) -> String {
    format!(
        "[package]\nname = {}\nversion = \"0.1.0\"\nedition = \"2024\"\nrust-version = \"1.85\"\npublish = false\n\n[dependencies]\nnesc-decompile-runtime = {{ path = {} }}\n\n[lints.rust]\nunsafe_code = \"forbid\"\n",
        toml_string(&config.crate_name),
        toml_string(&config.runtime_path)
    )
}

fn toml_string(value: &str) -> String {
    let mut output = String::from("\"");
    for character in value.chars() {
        match character {
            '\\' => output.push_str("\\\\"),
            '"' => output.push_str("\\\""),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            character if character.is_control() => {
                let _ = write!(output, "\\u{:04x}", character as u32);
            }
            character => output.push(character),
        }
    }
    output.push('"');
    output
}

fn render_report(program: &Program, control: &ControlFlowAnalysis) -> String {
    let mut report = format!(
        "{{\n  \"schema_version\": 1,\n  \"mapper\": {},\n  \"functions\": [\n",
        program.mapper
    );
    for (index, structured) in control.functions.iter().enumerate() {
        let function = &program.functions[structured.function.0 as usize];
        let fallbacks = structured
            .regions
            .iter()
            .filter_map(|region| match region.kind {
                StructuredRegionKind::Fallback { reason } => Some(reason),
                _ => None,
            })
            .collect::<Vec<_>>();
        let fallback_json = fallbacks
            .iter()
            .map(|reason| format!("\"{}\"", fallback_name(*reason)))
            .collect::<Vec<_>>()
            .join(", ");
        let _ = writeln!(
            report,
            "    {{\"id\": {}, \"name\": {}, \"bank\": {}, \"cpu_address\": {}, \"confidence\": \"{}\", \"fallbacks\": [{}]}}{}",
            function.id.0,
            json_string(&function.name),
            function.entry.bank,
            function.entry.cpu_address,
            confidence_name(structured.confidence),
            fallback_json,
            if index + 1 == control.functions.len() {
                ""
            } else {
                ","
            }
        );
    }
    report.push_str("  ]\n}\n");
    report
}

const fn confidence_name(confidence: Confidence) -> &'static str {
    match confidence {
        Confidence::Proven => "proven",
        Confidence::Conservative => "conservative",
        Confidence::Unknown => "unknown",
    }
}

fn json_string(value: &str) -> String {
    let mut output = String::from("\"");
    for character in value.chars() {
        match character {
            '\\' => output.push_str("\\\\"),
            '"' => output.push_str("\\\""),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            character if character.is_control() => {
                let _ = write!(output, "\\u{:04x}", character as u32);
            }
            character => output.push(character),
        }
    }
    output.push('"');
    output
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use std::process::Command;

    use nesc_disasm::{AnalysisLimits as DisassemblyLimits, disassemble};
    use nesc_rom::{Format, Metadata, Mirroring, Region, Rom, build};

    use super::{RustEmissionLimits, RustEmitConfig, emit_rust_project};
    use crate::{
        AnalysisLimits, ControlFlowLimits, RecoveryLimits, ValueAnalysisLimits, analyze,
        analyze_recovery, analyze_values, structure_control_flow,
    };

    fn program(bytes: &[u8]) -> crate::Program {
        let mut prg = vec![0xff; 16 * 1024];
        prg[..bytes.len()].copy_from_slice(bytes);
        let vectors = prg.len() - 6;
        for offset in [0, 2, 4] {
            prg[vectors + offset..vectors + offset + 2].copy_from_slice(&0xc000_u16.to_le_bytes());
        }
        let rom = build(&Rom {
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
        .expect("ROM");
        let disassembly = disassemble(&rom, DisassemblyLimits::default()).expect("disassembly");
        analyze(&disassembly, AnalysisLimits::default()).expect("CFG")
    }

    fn emit(program: &crate::Program, high_level_only: bool) -> super::RustProject {
        let values = analyze_values(program, ValueAnalysisLimits::default()).expect("values");
        let recovery =
            analyze_recovery(program, &values, RecoveryLimits::default()).expect("recovery");
        let control =
            structure_control_flow(program, &values, &recovery, ControlFlowLimits::default())
                .expect("control");
        emit_rust_project(
            program,
            &values,
            &recovery,
            &control,
            &RustEmitConfig {
                crate_name: "recovered_rom".to_owned(),
                runtime_path: runtime_path().to_string_lossy().into_owned(),
                high_level_only,
                max_fallback_call_depth: 64,
            },
            RustEmissionLimits::default(),
        )
        .expect("Rust project")
    }

    fn runtime_path() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../nesc-decompile-runtime")
    }

    fn check_project(project: &super::RustProject) {
        let directory = tempfile::tempdir().expect("temporary directory");
        fs::create_dir(directory.path().join("src")).expect("source directory");
        fs::write(directory.path().join("Cargo.toml"), &project.cargo_toml).expect("manifest");
        fs::write(directory.path().join("src/lib.rs"), &project.source).expect("source");
        let status = Command::new(env!("CARGO"))
            .args([
                "check",
                "--offline",
                "--quiet",
                "--manifest-path",
                directory
                    .path()
                    .join("Cargo.toml")
                    .to_str()
                    .expect("UTF-8 path"),
            ])
            .env("CARGO_TARGET_DIR", directory.path().join("target"))
            .env("RUSTFLAGS", "-D warnings")
            .status()
            .expect("cargo check");
        assert!(status.success());
    }

    fn check_differential_execution(project: &super::RustProject) {
        let directory = tempfile::tempdir().expect("temporary directory");
        fs::create_dir(directory.path().join("src")).expect("source directory");
        fs::create_dir(directory.path().join("tests")).expect("test directory");
        fs::write(directory.path().join("Cargo.toml"), &project.cargo_toml).expect("manifest");
        fs::write(directory.path().join("src/lib.rs"), &project.source).expect("source");
        fs::write(
            directory.path().join("tests/equivalence.rs"),
            r#"use nesc_decompile_runtime::{
    Bus, CodeSegment, CpuState, ExecutionBudget, ObservableEvent, RuntimeError,
    interpret_function,
};
use recovered_rom::fn_prg0000_c000_0;

struct TestBus {
    memory: Box<[u8; 65_536]>,
    events: Vec<ObservableEvent>,
}

impl TestBus {
    fn with_input(input: u8) -> Self {
        let mut memory = Box::new([0; 65_536]);
        memory[0] = input;
        Self { memory, events: Vec::new() }
    }
}

impl Bus for TestBus {
    fn read(&mut self, _state: &CpuState, address: u16) -> Result<u8, RuntimeError> {
        Ok(self.memory[usize::from(address)])
    }

    fn write(
        &mut self,
        _state: &CpuState,
        address: u16,
        value: u8,
    ) -> Result<(), RuntimeError> {
        self.memory[usize::from(address)] = value;
        Ok(())
    }

    fn observe(&mut self, event: ObservableEvent) -> Result<(), RuntimeError> {
        self.events.push(event);
        Ok(())
    }

    fn mapped_prg_bank(&self, _address: u16) -> Option<u16> {
        Some(0)
    }
}

#[test]
fn translated_control_flow_matches_original_bytes() {
    const CODE: &[CodeSegment] = &[CodeSegment {
        bank: 0,
        cpu_address: 0xc000,
        bytes: &[
            0xa5, 0x00, 0xf0, 0x05, 0xa9, 0x01, 0x4c, 0x0b, 0xc0, 0xa9, 0x02, 0x60,
        ],
    }];
    for input in [0_u8, 1] {
        let mut original_state = CpuState::default();
        let mut translated_state = CpuState::default();
        let mut original_bus = TestBus::with_input(input);
        let mut translated_bus = TestBus::with_input(input);
        let mut original_budget = ExecutionBudget::new(32).expect("budget");
        let mut translated_budget = ExecutionBudget::new(32).expect("budget");

        interpret_function(
            &mut original_state,
            &mut original_bus,
            &mut original_budget,
            CODE,
            0,
            0xc000,
            8,
        )
        .expect("original execution");
        fn_prg0000_c000_0(
            &mut translated_state,
            &mut translated_bus,
            &mut translated_budget,
        )
        .expect("translated execution");

        assert_eq!(translated_state, original_state);
        assert_eq!(translated_bus.memory, original_bus.memory);
        assert_eq!(translated_bus.events, original_bus.events);
        assert_eq!(translated_budget.consumed(), original_budget.consumed());
    }
}
"#,
        )
        .expect("equivalence test");
        let status = Command::new(env!("CARGO"))
            .args([
                "test",
                "--offline",
                "--quiet",
                "--manifest-path",
                directory
                    .path()
                    .join("Cargo.toml")
                    .to_str()
                    .expect("UTF-8 path"),
            ])
            .env("CARGO_TARGET_DIR", directory.path().join("target"))
            .env("RUSTFLAGS", "-D warnings")
            .status()
            .expect("cargo test");
        assert!(status.success());
    }

    #[test]
    fn emits_structured_stable_rust_that_compiles_with_warnings_denied() {
        let program = program(&[
            0xa5, 0x00, // lda $00
            0xf0, 0x05, // beq $c009
            0xa9, 0x01, // lda #1
            0x4c, 0x0b, 0xc0, // jmp $c00b
            0xa9, 0x02, // lda #2
            0x60, // rts
        ]);
        let project = emit(&program, true);
        assert!(project.source.contains("if state.status.get"));
        assert!(!project.source.contains("interpret_function"));
        assert!(project.report_json.contains("\"confidence\": \"proven\""));

        check_project(&project);
        check_differential_execution(&project);
    }

    #[test]
    fn emits_explicit_fallback_and_enforces_emission_limits() {
        let program = program(&[
            0x6c, 0x00, 0x02, // jmp ($0200)
        ]);
        let project = emit(&program, false);
        assert!(project.source.contains("interpret_function"));
        assert!(project.report_json.contains("unresolved control flow"));
        check_project(&project);

        let values = analyze_values(&program, ValueAnalysisLimits::default()).expect("values");
        let recovery =
            analyze_recovery(&program, &values, RecoveryLimits::default()).expect("recovery");
        let control =
            structure_control_flow(&program, &values, &recovery, ControlFlowLimits::default())
                .expect("control");
        let config = RustEmitConfig {
            crate_name: "recovered_rom".to_owned(),
            runtime_path: runtime_path().to_string_lossy().into_owned(),
            high_level_only: true,
            max_fallback_call_depth: 64,
        };
        let error = emit_rust_project(
            &program,
            &values,
            &recovery,
            &control,
            &config,
            RustEmissionLimits::default(),
        )
        .expect_err("fallback rejection");
        assert!(error[0].message().contains("high-level-only"));

        let error = emit_rust_project(
            &program,
            &values,
            &recovery,
            &control,
            &RustEmitConfig {
                high_level_only: false,
                ..config
            },
            RustEmissionLimits {
                max_source_bytes: 1,
                ..RustEmissionLimits::default()
            },
        )
        .expect_err("source limit");
        assert!(error[0].message().contains("source exceeds"));
    }

    #[test]
    fn preserves_hardware_stack_around_structured_calls() {
        let program = program(&[
            0x20, 0x04, 0xc0, // jsr $c004
            0x60, // rts
            0x60, // rts
        ]);
        let project = emit(&program, true);
        assert!(project.source.contains("runtime::push"));
        assert!(project.source.contains("let return_low = runtime::pop"));
        check_project(&project);
    }
}
