use std::collections::BTreeMap;
use std::fmt::Write;

use nesc_disasm::{AddressingMode, Disassembly, VectorKind};
use nesc_rom::{Format, Mirroring, Region};

use super::{
    AccumulatorOperator, AnalysisError, BlockId, BlockTarget, BranchCondition, ComparisonPredicate,
    Confidence, ControlFlowAnalysis, FallbackReason, Flag, LoopForm, MemoryOperand, Program,
    RecoveredCondition, RecoveredPredicate, RecoveryAnalysis, Register, SemanticOperation,
    ShiftOperator, StackControl, StateVariable, StopReason, StructuredFunction,
    StructuredRegionKind, Terminator, ValueAnalysis, ValueSource, ValueTarget,
};

/// Resource bounds for hybrid NesC generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NesCEmissionLimits {
    pub max_functions: usize,
    pub max_instructions: usize,
    pub max_regions: usize,
    pub max_nesting: usize,
    pub max_source_bytes: usize,
}

impl Default for NesCEmissionLimits {
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

/// Hybrid NesC project settings.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NesCEmitConfig {
    pub package_name: String,
    pub high_level_only: bool,
    pub verification: bool,
    pub fallback_instruction_limit: u16,
    pub max_fallback_call_depth: u8,
}

/// Generated NesC project contents.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NesCProject {
    pub manifest: String,
    pub source: String,
    pub report_json: String,
}

/// Emits a buildable Mapper 0 or Mapper 2 NesC project.
///
/// Reducible functions use ordinary NesC control flow. Uncertain functions
/// call a bounded target-side dispatcher over the recovered machine state.
///
/// # Errors
///
/// Rejects malformed analyses, unsupported cartridges, high-level-only
/// fallback, invalid settings, unrepresentable operands, and exhausted limits.
pub fn emit_nesc_project(
    disassembly: &Disassembly,
    program: &Program,
    values: &ValueAnalysis,
    recovery: &RecoveryAnalysis,
    control: &ControlFlowAnalysis,
    config: &NesCEmitConfig,
    limits: NesCEmissionLimits,
) -> Result<NesCProject, Vec<AnalysisError>> {
    validate(config, limits)?;
    program.verify()?;
    values.verify(program)?;
    recovery.verify(program, values)?;
    control.verify(program, values, recovery)?;
    if program.mapper != disassembly.rom.metadata.mapper {
        return Err(vec![AnalysisError::new(
            "semantic program mapper differs from the source cartridge",
        )]);
    }
    if !matches!(program.mapper, 0 | 2) {
        return Err(vec![AnalysisError::new(format!(
            "hybrid NesC emission supports Mapper 0 and Mapper 2, not Mapper {}",
            program.mapper
        ))]);
    }
    if disassembly.rom.metadata.region == Region::MultiRegion {
        return Err(vec![AnalysisError::new(
            "hybrid NesC emission cannot represent multi-region timing in NesC.toml",
        )]);
    }
    let instructions = program
        .blocks
        .values()
        .map(|block| block.instructions.len())
        .sum::<usize>();
    let regions = control
        .functions
        .iter()
        .map(|function| function.regions.len())
        .sum::<usize>();
    if program.functions.len() > limits.max_functions {
        return Err(vec![AnalysisError::new(format!(
            "NesC emission function limit {} exceeded",
            limits.max_functions
        ))]);
    }
    if instructions > limits.max_instructions {
        return Err(vec![AnalysisError::new(format!(
            "NesC emission instruction limit {} exceeded",
            limits.max_instructions
        ))]);
    }
    if regions > limits.max_regions {
        return Err(vec![AnalysisError::new(format!(
            "NesC emission region limit {} exceeded",
            limits.max_regions
        ))]);
    }
    let fallbacks = control
        .functions
        .iter()
        .flat_map(|function| &function.regions)
        .filter(|region| matches!(region.kind, StructuredRegionKind::Fallback { .. }))
        .count();
    if config.high_level_only && fallbacks != 0 {
        return Err(vec![AnalysisError::new(format!(
            "high-level-only NesC emission rejected {fallbacks} dispatcher fallback region(s)"
        ))]);
    }
    if config.verification && program.functions.len() > usize::from(u16::MAX) + 1 {
        return Err(vec![AnalysisError::new(
            "NesC verification cannot address more than 65536 recovered functions",
        )]);
    }
    let prg_bank_count = disassembly.rom.prg_rom.len() / (16 * 1024);
    if prg_bank_count > usize::from(u8::MAX) + 1 {
        return Err(vec![AnalysisError::new(format!(
            "hybrid NesC emission cannot represent {prg_bank_count} PRG banks"
        ))]);
    }
    let fixed_prg_bank = u16::try_from(prg_bank_count.saturating_sub(1))
        .map_err(|_| vec![AnalysisError::new("fixed PRG bank does not fit in u16")])?;
    let names = program
        .functions
        .iter()
        .map(|function| {
            (
                function.id,
                format!(
                    "fn_prg{:04x}_{:04x}_{}",
                    function.entry.bank, function.entry.cpu_address, function.id.0
                ),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let mut emitter = Emitter {
        program,
        control,
        config,
        limits,
        fixed_prg_bank,
        switchable_prg_banks: u16::try_from(prg_bank_count.saturating_sub(1)).map_err(|_| {
            vec![AnalysisError::new(
                "switchable PRG bank count does not fit in u16",
            )]
        })?,
        names,
        source: String::new(),
    };
    emitter.emit(fallbacks != 0)?;
    Ok(NesCProject {
        manifest: manifest(disassembly, config),
        source: emitter.source,
        report_json: report(program, control),
    })
}

fn validate(config: &NesCEmitConfig, limits: NesCEmissionLimits) -> Result<(), Vec<AnalysisError>> {
    let name_valid = !config.package_name.is_empty()
        && config
            .package_name
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_alphabetic())
        && config.package_name.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-' || byte == b'_'
        });
    if !name_valid {
        return Err(vec![AnalysisError::new(
            "generated NesC package name is invalid",
        )]);
    }
    if config.fallback_instruction_limit == 0 || config.max_fallback_call_depth == 0 {
        return Err(vec![AnalysisError::new(
            "NesC fallback limits must permit instructions and call depth",
        )]);
    }
    if limits.max_functions == 0
        || limits.max_instructions == 0
        || limits.max_regions == 0
        || limits.max_nesting == 0
        || limits.max_source_bytes == 0
    {
        return Err(vec![AnalysisError::new(
            "NesC emission limits must permit functions, instructions, regions, nesting, and source bytes",
        )]);
    }
    Ok(())
}

struct Emitter<'a> {
    program: &'a Program,
    control: &'a ControlFlowAnalysis,
    config: &'a NesCEmitConfig,
    limits: NesCEmissionLimits,
    fixed_prg_bank: u16,
    switchable_prg_banks: u16,
    names: BTreeMap<super::FunctionId, String>,
    source: String,
}

impl Emitter<'_> {
    fn emit(&mut self, has_fallback: bool) -> Result<(), Vec<AnalysisError>> {
        self.line(
            0,
            "/* Best-effort NesC translation; original names and source are not recovered. */",
        )?;
        self.line(0, "#include <nes.h>")?;
        self.line(0, "")?;
        self.emit_state_helpers(has_fallback)?;
        let functions = self.control.functions.clone();
        for function in &functions {
            let name = self.names[&function.function].clone();
            let placement = self.function_placement(function);
            self.line(
                0,
                &format!("{}static void {name}(void);", bank_attribute(placement)),
            )?;
        }
        if has_fallback {
            let blocks = self.program.blocks.keys().copied().collect::<Vec<_>>();
            for block in blocks {
                self.line(
                    0,
                    &format!("static void {}(void);", fallback_block_name(block)),
                )?;
            }
            self.line(0, "static void decompile_dispatch_once(void);")?;
            self.line(0, "static void decompile_fallback(u16 entry);")?;
        }
        if self.config.verification {
            self.line(0, "static void verification_dispatch(u16 test_case);")?;
            self.emit_verification_schedule_service()?;
        }
        for function in &functions {
            self.emit_function(function)?;
        }
        if has_fallback {
            self.emit_fallback_dispatcher()?;
        }
        if self.config.verification {
            self.emit_verification_dispatch()?;
        }
        let reset = self
            .program
            .functions
            .iter()
            .find(|function| {
                function.evidence.iter().any(|evidence| {
                    matches!(evidence, super::FunctionEvidence::Vector(VectorKind::Reset))
                })
            })
            .or_else(|| self.program.functions.first())
            .ok_or_else(|| vec![AnalysisError::new("NesC emission requires a function")])?;
        let reset_name = self.names[&reset.id].clone();
        self.line(0, "")?;
        self.line(0, "NES_MAIN int main(void) {")?;
        if self.config.verification {
            self.line(1, "u16 verification_case;")?;
            self.line(1, "cpu_a = 0;")?;
            self.line(1, "cpu_x = 0;")?;
            self.line(1, "cpu_y = 0;")?;
            self.line(1, "verification_step = 0;")?;
            self.line(1, "verification_schedule_kind = verification_load(0x7ff4);")?;
            self.line(
                1,
                "verification_schedule_step = (u16)(verification_load(0x7ff5) | ((u16)verification_load(0x7ff6) << 8));",
            )?;
        }
        self.line(1, "cpu_sp = 0xfd;")?;
        if self.config.verification {
            self.line(1, "cpu_status = verification_load(0x7ff2);")?;
        } else {
            self.line(1, "cpu_status = 0x24;")?;
        }
        if self.program.mapper == 2 {
            self.line(
                1,
                if self.config.verification {
                    "cpu_selected_prg_bank = verification_load(0x7ff3);"
                } else {
                    "cpu_selected_prg_bank = 0;"
                },
            )?;
        }
        self.line(
            1,
            &format!("cpu_budget = {};", self.config.fallback_instruction_limit),
        )?;
        if self.config.verification {
            self.line(1, "verification_store(0x7f00, 0);")?;
            self.line(1, "verification_store(0x7f01, 0);")?;
            self.line(1, "verification_store(0x7f02, 0);")?;
            self.line(1, "verification_store(0x7f0b, 0);")?;
            self.line(1, "verification_store(0x7f0c, 0);")?;
            self.line(1, "verification_store(0x7f0d, 0);")?;
            self.line(
                1,
                "verification_case = (u16)(verification_load(0x7ff0) | ((u16)verification_load(0x7ff1) << 8));",
            )?;
            self.line(
                1,
                "if ((verification_schedule_kind == 1) || (verification_schedule_kind == 2)) {",
            )?;
            self.line(2, "verification_prepare_case(verification_case);")?;
            self.line(2, "verification_service_schedule();")?;
            self.line(2, "verification_finish();")?;
            self.line(2, "verification_store(0x7f0d, 1);")?;
            self.line(2, "__nesc_trap();")?;
            self.line(1, "} else {")?;
            self.line(2, "verification_dispatch(verification_case);")?;
            self.line(2, "verification_finish();")?;
            self.line(1, "}")?;
        } else {
            self.line(1, &format!("cpu_pc = 0x{:04x};", reset.entry.cpu_address))?;
            self.line(1, &format!("{reset_name}();"))?;
        }
        self.line(1, "return 0;")?;
        self.line(0, "}")
    }

    fn emit_state_helpers(&mut self, has_fallback: bool) -> Result<(), Vec<AnalysisError>> {
        let mut declarations = vec![
            "static u8 cpu_a;",
            "static u8 cpu_x;",
            "static u8 cpu_y;",
            "static u8 cpu_sp;",
            "static u8 cpu_status;",
            "static u16 cpu_pc;",
            "static u16 cpu_budget;",
            "extern void __nesc_trap(void);",
        ];
        if self.program.mapper == 2 {
            declarations.insert(7, "static u8 cpu_selected_prg_bank;");
        }
        if has_fallback {
            declarations.extend([
                "static u8 fallback_running;",
                "static u8 fallback_call_depth;",
                "static u8 fallback_interrupt_depth;",
            ]);
        }
        if self.config.verification {
            declarations.extend([
                "static u8 verification_schedule_kind;",
                "static u16 verification_schedule_step;",
                "static u16 verification_step;",
            ]);
        }
        for declaration in declarations {
            self.line(0, declaration)?;
        }
        self.line(0, "")?;
        self.line(0, "static u8 cpu_flag(u8 mask) {")?;
        self.line(1, "return (u8)((cpu_status & mask) != 0);")?;
        self.line(0, "}")?;
        self.line(0, "static void cpu_set_flag(u8 mask, u8 value) {")?;
        self.line(1, "if (value != 0) {")?;
        self.line(2, "cpu_status = (u8)(cpu_status | mask);")?;
        self.line(1, "} else {")?;
        self.line(2, "cpu_status = (u8)(cpu_status & (u8)(mask ^ 0xff));")?;
        self.line(1, "}")?;
        self.line(0, "}")?;
        self.line(0, "static void cpu_set_nz(u8 value) {")?;
        self.line(1, "cpu_set_flag(0x80, (u8)((value & 0x80) != 0));")?;
        self.line(1, "cpu_set_flag(0x02, (u8)(value == 0));")?;
        self.line(0, "}")?;
        if self.config.verification {
            self.emit_verification_helpers()?;
        }
        self.line(0, "static u8 cpu_read(u16 address) {")?;
        if self.config.verification {
            self.line(1, "u8 value;")?;
            self.line(1, "if ((address >= 0x7000) && (address < 0x8000)) {")?;
            self.line(2, "verification_store(0x7f0c, 1);")?;
            self.line(2, "__nesc_trap();")?;
            self.line(1, "}")?;
            self.line(1, "if (address < 0x2000) {")?;
            self.line(
                2,
                "value = *((ptr<unknown, volatile u8>)(0x7000 + (address & 0x07ff)));",
            )?;
            self.line(1, "} else {")?;
            self.line(2, "value = *((ptr<unknown, volatile u8>)address);")?;
            self.line(1, "}")?;
            self.line(1, "if ((address >= 0x2000) && (address <= 0x4017)) {")?;
            self.line(2, "verification_observe(1, address, value);")?;
            self.line(1, "}")?;
            self.line(1, "return value;")?;
        } else {
            self.line(1, "return *((ptr<unknown, volatile u8>)address);")?;
        }
        self.line(0, "}")?;
        self.line(0, "static void cpu_write(u16 address, u8 value) {")?;
        if self.config.verification {
            self.line(1, "if ((address >= 0x7000) && (address < 0x8000)) {")?;
            self.line(2, "verification_store(0x7f0c, 1);")?;
            self.line(2, "__nesc_trap();")?;
            self.line(1, "}")?;
            self.line(1, "verification_observe_write(address, value);")?;
            self.line(1, "verification_bus_write(address, value);")?;
        } else {
            self.line(1, "*((ptr<unknown, volatile u8>)address) = value;")?;
        }
        if self.program.mapper == 2 {
            self.line(1, "if (address >= 0x8000) {")?;
            self.line(
                2,
                &format!(
                    "cpu_selected_prg_bank = (u8)(value % {});",
                    self.switchable_prg_banks
                ),
            )?;
            self.line(1, "}")?;
        }
        self.line(0, "}")?;
        self.line(0, "static void cpu_step(void) {")?;
        if self.config.verification {
            self.line(
                1,
                "if ((verification_schedule_kind == 3) && (verification_step == verification_schedule_step)) { verification_finish(); verification_store(0x7f0d, 1); __nesc_trap(); }",
            )?;
            self.line(1, "verification_step = (u16)(verification_step + 1);")?;
            self.line(
                1,
                "if (cpu_budget == 0) { verification_store(0x7f0b, 1); __nesc_trap(); }",
            )?;
        } else {
            self.line(1, "if (cpu_budget == 0) { __nesc_trap(); }")?;
        }
        self.line(1, "cpu_budget = (u16)(cpu_budget - 1);")?;
        self.line(0, "}")?;
        self.line(0, "static void cpu_push(u8 value) {")?;
        self.line(1, "cpu_write((u16)(0x0100 | cpu_sp), value);")?;
        self.line(1, "cpu_sp = (u8)(cpu_sp - 1);")?;
        self.line(0, "}")?;
        self.line(0, "static u8 cpu_pop(void) {")?;
        self.line(1, "cpu_sp = (u8)(cpu_sp + 1);")?;
        self.line(1, "return cpu_read((u16)(0x0100 | cpu_sp));")?;
        self.line(0, "}")?;
        self.line(0, "static u16 cpu_indexed_indirect(u8 pointer) {")?;
        self.line(1, "u8 base;")?;
        self.line(1, "u8 low;")?;
        self.line(1, "u8 high;")?;
        self.line(1, "base = (u8)(pointer + cpu_x);")?;
        self.line(1, "low = cpu_read(base);")?;
        self.line(1, "high = cpu_read((u8)(base + 1));")?;
        self.line(1, "return (u16)(low | ((u16)high << 8));")?;
        self.line(0, "}")?;
        self.line(0, "static u16 cpu_indirect_indexed(u8 pointer) {")?;
        self.line(1, "u8 low;")?;
        self.line(1, "u8 high;")?;
        self.line(1, "low = cpu_read(pointer);")?;
        self.line(1, "high = cpu_read((u8)(pointer + 1));")?;
        self.line(1, "return (u16)((u16)(low | ((u16)high << 8)) + cpu_y);")?;
        self.line(0, "}")?;
        self.line(0, "static void cpu_adc(u8 value) {")?;
        self.line(1, "u16 sum;")?;
        self.line(1, "u8 output;")?;
        self.line(1, "sum = (u16)((u16)cpu_a + value + cpu_flag(0x01));")?;
        self.line(1, "output = (u8)sum;")?;
        self.line(1, "cpu_set_flag(0x01, (u8)(sum > 0xff));")?;
        self.line(
            1,
            "cpu_set_flag(0x40, (u8)((((u8)((cpu_a ^ value) ^ 0xff)) & (cpu_a ^ output) & 0x80) != 0));",
        )?;
        self.line(1, "cpu_a = output;")?;
        self.line(1, "cpu_set_nz(cpu_a);")?;
        self.line(0, "}")?;
        self.line(
            0,
            "static void cpu_sbc(u8 value) { cpu_adc((u8)(value ^ 0xff)); }",
        )?;
        self.line(0, "static void cpu_compare(u8 left, u8 right) {")?;
        self.line(1, "cpu_set_flag(0x01, (u8)(left >= right));")?;
        self.line(1, "cpu_set_nz((u8)(left - right));")?;
        self.line(0, "}")?;
        Ok(())
    }

    fn emit_verification_helpers(&mut self) -> Result<(), Vec<AnalysisError>> {
        self.line(0, "static u8 verification_load(u16 address) {")?;
        self.line(1, "return *((ptr<unknown, volatile u8>)address);")?;
        self.line(0, "}")?;
        self.line(0, "static void verification_store(u16 address, u8 value) {")?;
        self.line(1, "*((ptr<unknown, volatile u8>)address) = value;")?;
        self.line(0, "}")?;
        self.line(
            0,
            "static void verification_observe(u8 kind, u16 address, u8 value) {",
        )?;
        self.line(1, "u8 count;")?;
        self.line(1, "u16 base;")?;
        self.line(1, "count = verification_load(0x7f00);")?;
        self.line(1, "if (count < 255) {")?;
        self.line(2, "base = (u16)(0x7b00 + ((u16)count << 2));")?;
        self.line(2, "verification_store(base, kind);")?;
        self.line(2, "verification_store((u16)(base + 1), (u8)address);")?;
        self.line(
            2,
            "verification_store((u16)(base + 2), (u8)(address >> 8));",
        )?;
        self.line(2, "verification_store((u16)(base + 3), value);")?;
        self.line(2, "verification_store(0x7f00, (u8)(count + 1));")?;
        self.line(1, "} else {")?;
        self.line(2, "verification_store(0x7f01, 1);")?;
        self.line(1, "}")?;
        self.line(0, "}")?;
        self.line(
            0,
            "static void verification_observe_write(u16 address, u8 value) {",
        )?;
        self.line(1, "if (address >= 0x8000) {")?;
        self.line(2, "verification_observe(3, address, value);")?;
        self.line(
            1,
            "} else if ((address >= 0x2000) && (address <= 0x4017)) {",
        )?;
        self.line(2, "if (address == 0x4014) {")?;
        self.line(3, "verification_observe(4, address, value);")?;
        self.line(2, "}")?;
        self.line(2, "verification_observe(2, address, value);")?;
        self.line(1, "}")?;
        self.line(0, "}")?;
        self.line(0, "static void verification_dma(u8 page) {")?;
        self.line(1, "u16 address;")?;
        self.line(1, "u8 offset;")?;
        self.line(1, "address = (u16)((u16)page << 8);")?;
        self.line(1, "offset = 0;")?;
        self.line(1, "while (offset != 0xff) {")?;
        self.line(2, "verification_store(0x2004, cpu_read(address));")?;
        self.line(2, "address = (u16)(address + 1);")?;
        self.line(2, "offset = (u8)(offset + 1);")?;
        self.line(1, "}")?;
        self.line(1, "verification_store(0x2004, cpu_read(address));")?;
        self.line(0, "}")?;
        self.line(
            0,
            "static void verification_bus_write(u16 address, u8 value) {",
        )?;
        self.line(1, "if (address == 0x4014) {")?;
        self.line(2, "verification_dma(value);")?;
        self.line(1, "} else if (address < 0x2000) {")?;
        self.line(
            2,
            "*((ptr<unknown, volatile u8>)(0x7000 + (address & 0x07ff))) = value;",
        )?;
        self.line(1, "} else {")?;
        self.line(2, "*((ptr<unknown, volatile u8>)address) = value;")?;
        self.line(1, "}")?;
        self.line(0, "}")?;
        self.line(0, "static void verification_finish(void) {")?;
        self.line(1, "verification_store(0x7f03, cpu_a);")?;
        self.line(1, "verification_store(0x7f04, cpu_x);")?;
        self.line(1, "verification_store(0x7f05, cpu_y);")?;
        self.line(1, "verification_store(0x7f06, cpu_sp);")?;
        self.line(1, "verification_store(0x7f07, cpu_status);")?;
        self.line(1, "verification_store(0x7f08, (u8)cpu_pc);")?;
        self.line(1, "verification_store(0x7f09, (u8)(cpu_pc >> 8));")?;
        if self.program.mapper == 2 {
            self.line(1, "verification_store(0x7f0a, cpu_selected_prg_bank);")?;
        } else {
            self.line(1, "verification_store(0x7f0a, 0);")?;
        }
        self.line(1, "verification_store(0x7f02, 0xa5);")?;
        self.line(0, "}")
    }

    fn emit_function(&mut self, function: &StructuredFunction) -> Result<(), Vec<AnalysisError>> {
        let recovered = &self.program.functions[function.function.0 as usize];
        let name = self.names[&function.function].clone();
        let placement = self.function_placement(function);
        self.line(0, "")?;
        self.line(
            0,
            &format!(
                "/* {}: PRG bank {}, CPU 0x{:04X}, confidence {:?}. */",
                recovered.name,
                recovered.entry.bank,
                recovered.entry.cpu_address,
                function.confidence
            ),
        )?;
        self.line(
            0,
            &format!("{}static void {name}(void) {{", bank_attribute(placement)),
        )?;
        if self.program.mapper == 2 && recovered.entry.bank != self.fixed_prg_bank {
            self.line(
                1,
                &format!("cpu_selected_prg_bank = {};", recovered.entry.bank),
            )?;
        }
        self.emit_region(function, function.root, 1, 0)?;
        self.line(0, "}")
    }

    fn function_placement(&self, function: &StructuredFunction) -> Option<u16> {
        let recovered = &self.program.functions[function.function.0 as usize];
        let has_fallback = function
            .regions
            .iter()
            .any(|region| matches!(region.kind, StructuredRegionKind::Fallback { .. }));
        let writes_mapper = recovered.blocks.iter().any(|block| {
            self.program.blocks[block]
                .instructions
                .iter()
                .flat_map(|instruction| &instruction.operations)
                .any(|operation| matches!(operation, SemanticOperation::MapperWrite { .. }))
        });
        (self.program.mapper == 2
            && recovered.entry.bank != self.fixed_prg_bank
            && !has_fallback
            && !writes_mapper)
            .then_some(recovered.entry.bank)
    }

    fn emit_region(
        &mut self,
        function: &StructuredFunction,
        region: super::RegionId,
        indent: usize,
        depth: usize,
    ) -> Result<(), Vec<AnalysisError>> {
        if depth >= self.limits.max_nesting {
            return Err(vec![AnalysisError::new(format!(
                "NesC emission nesting limit {} exceeded",
                self.limits.max_nesting
            ))]);
        }
        match function.regions[region.0 as usize].kind.clone() {
            StructuredRegionKind::Sequence { children } => {
                for child in children {
                    self.emit_region(function, child, indent, depth + 1)?;
                }
            }
            StructuredRegionKind::Block { block } => self.emit_block(block, indent)?,
            StructuredRegionKind::If {
                header,
                condition,
                then_region,
                else_region,
                ..
            } => {
                self.emit_block(header, indent)?;
                self.line(indent, &format!("if ({}) {{", condition_text(&condition)))?;
                if let Some(child) = then_region {
                    self.emit_region(function, child, indent + 1, depth + 1)?;
                }
                if let Some(child) = else_region {
                    self.line(indent, "} else {")?;
                    self.emit_region(function, child, indent + 1, depth + 1)?;
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
                    LoopForm::While => self.line(indent, "/* Proven natural loop. */")?,
                    LoopForm::Counted(counted) => self.line(
                        indent,
                        &format!(
                            "/* Counted loop: {} changes by {} toward {}. */",
                            state_name(counted.induction),
                            counted.step,
                            counted.bound
                        ),
                    )?,
                }
                self.line(indent, "while (true) {")?;
                self.emit_block(header, indent + 1)?;
                self.line(
                    indent + 1,
                    &format!("if (!({})) {{ break; }}", condition_text(&condition)),
                )?;
                if let Some(child) = body {
                    self.emit_region(function, child, indent + 1, depth + 1)?;
                }
                self.line(indent, "}")?;
            }
            StructuredRegionKind::Call { block, callee, .. } => {
                self.emit_block(block, indent)?;
                let callee_placement = self
                    .control
                    .functions
                    .get(callee.0 as usize)
                    .and_then(|function| self.function_placement(function));
                let restores_mapper = callee_placement.is_some_and(|bank| bank != block.bank);
                let call_indent = if restores_mapper {
                    self.line(indent, "{")?;
                    self.line(indent + 1, "u8 saved_prg_bank;")?;
                    self.line(indent + 1, "saved_prg_bank = cpu_selected_prg_bank;")?;
                    indent + 1
                } else {
                    indent
                };
                let call = self.program.blocks[&block]
                    .instructions
                    .last()
                    .expect("verified call block has an instruction");
                let return_address =
                    call.provenance.address.cpu_address + call.provenance.bytes.len() as u16 - 1;
                self.line(
                    call_indent,
                    &format!("cpu_push(0x{:02x});", return_address >> 8),
                )?;
                self.line(
                    call_indent,
                    &format!("cpu_push(0x{:02x});", return_address as u8),
                )?;
                let callee = self.names[&callee].clone();
                self.line(call_indent, &format!("{callee}();"))?;
                if restores_mapper {
                    self.line(call_indent, "cpu_selected_prg_bank = saved_prg_bank;")?;
                }
                self.line(call_indent, "{")?;
                self.line(call_indent + 1, "u8 return_low;")?;
                self.line(call_indent + 1, "u8 return_high;")?;
                self.line(call_indent + 1, "return_low = cpu_pop();")?;
                self.line(call_indent + 1, "return_high = cpu_pop();")?;
                self.line(
                    call_indent + 1,
                    "cpu_pc = (u16)((u16)(return_low | ((u16)return_high << 8)) + 1);",
                )?;
                self.line(call_indent, "}")?;
                if restores_mapper {
                    self.line(indent, "}")?;
                }
            }
            StructuredRegionKind::Return { block, interrupt } => {
                self.emit_block(block, indent)?;
                if interrupt {
                    self.line(indent, "cpu_status = cpu_pop();")?;
                    self.line(indent, "{")?;
                    self.line(indent + 1, "u8 return_low;")?;
                    self.line(indent + 1, "u8 return_high;")?;
                    self.line(indent + 1, "return_low = cpu_pop();")?;
                    self.line(indent + 1, "return_high = cpu_pop();")?;
                    self.line(
                        indent + 1,
                        "cpu_pc = (u16)(return_low | ((u16)return_high << 8));",
                    )?;
                    self.line(indent, "}")?;
                }
            }
            StructuredRegionKind::Fallback { reason } => {
                let entry = self.program.functions[function.function.0 as usize].entry;
                self.line(
                    indent,
                    &format!("/* Dispatcher fallback: {}. */", fallback_name(reason)),
                )?;
                self.line(
                    indent,
                    &format!("decompile_fallback(0x{:04x});", entry.cpu_address),
                )?;
            }
        }
        Ok(())
    }

    fn emit_block(&mut self, block: BlockId, indent: usize) -> Result<(), Vec<AnalysisError>> {
        let instructions = self.program.blocks[&block].instructions.clone();
        for instruction in instructions {
            let bytes = instruction
                .provenance
                .bytes
                .iter()
                .map(|byte| format!("{byte:02X}"))
                .collect::<Vec<_>>()
                .join(" ");
            self.line(
                indent,
                &format!(
                    "/* ROM +0x{:X}, PRG +0x{:X}, bank {}, CPU 0x{:04X}: {} */",
                    instruction.provenance.rom_file_offset,
                    instruction.provenance.prg_offset,
                    instruction.provenance.address.bank,
                    instruction.provenance.address.cpu_address,
                    bytes
                ),
            )?;
            self.line(
                indent,
                &format!(
                    "cpu_pc = 0x{:04x};",
                    instruction.provenance.address.cpu_address
                ),
            )?;
            self.line(indent, "cpu_step();")?;
            for operation in instruction.operations {
                if !matches!(operation, SemanticOperation::StackControl(_)) {
                    self.emit_operation(&operation, indent)?;
                }
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
                let destination = register(*destination);
                self.line(
                    indent,
                    &format!("{destination} = {};", source_text(source)?),
                )?;
                self.line(indent, &format!("cpu_set_nz({destination});"))?;
            }
            SemanticOperation::Store {
                destination,
                source,
            } => self.line(
                indent,
                &format!(
                    "cpu_write({}, {});",
                    address_text(destination)?,
                    register(*source)
                ),
            )?,
            SemanticOperation::Accumulate {
                operator, source, ..
            } => {
                let source = source_text(source)?;
                match operator {
                    AccumulatorOperator::AddWithCarry => {
                        self.line(indent, &format!("cpu_adc({source});"))?
                    }
                    AccumulatorOperator::SubtractWithCarry => {
                        self.line(indent, &format!("cpu_sbc({source});"))?
                    }
                    AccumulatorOperator::And => {
                        self.line(indent, &format!("cpu_a = (u8)(cpu_a & {source});"))?;
                        self.line(indent, "cpu_set_nz(cpu_a);")?;
                    }
                    AccumulatorOperator::Or => {
                        self.line(indent, &format!("cpu_a = (u8)(cpu_a | {source});"))?;
                        self.line(indent, "cpu_set_nz(cpu_a);")?;
                    }
                    AccumulatorOperator::ExclusiveOr => {
                        self.line(indent, &format!("cpu_a = (u8)(cpu_a ^ {source});"))?;
                        self.line(indent, "cpu_set_nz(cpu_a);")?;
                    }
                }
            }
            SemanticOperation::Compare { left, right } => self.line(
                indent,
                &format!("cpu_compare({}, {});", register(*left), source_text(right)?),
            )?,
            SemanticOperation::TestBits { source } => {
                self.line(indent, "{")?;
                self.line(indent + 1, "u8 value;")?;
                self.line(indent + 1, &format!("value = {};", source_text(source)?))?;
                self.line(
                    indent + 1,
                    "cpu_set_flag(0x02, (u8)((cpu_a & value) == 0));",
                )?;
                self.line(indent + 1, "cpu_set_flag(0x80, (u8)((value & 0x80) != 0));")?;
                self.line(indent + 1, "cpu_set_flag(0x40, (u8)((value & 0x40) != 0));")?;
                self.line(indent, "}")?;
            }
            SemanticOperation::Shift {
                operator, target, ..
            } => self.emit_shift(*operator, target, indent)?,
            SemanticOperation::Adjust { target, delta } => {
                self.line(indent, "{")?;
                self.line(indent + 1, "u8 value;")?;
                self.line(indent + 1, &format!("value = {};", target_read(target)?))?;
                if *delta >= 0 {
                    self.line(indent + 1, &format!("value = (u8)(value + {});", delta))?;
                } else {
                    self.line(
                        indent + 1,
                        &format!("value = (u8)(value - {});", delta.unsigned_abs()),
                    )?;
                }
                self.emit_target_write(target, "value", indent + 1)?;
                self.line(indent + 1, "cpu_set_nz(value);")?;
                self.line(indent, "}")?;
            }
            SemanticOperation::Transfer {
                source,
                destination,
                update_negative_zero,
            } => {
                self.line(
                    indent,
                    &format!("{} = {};", register(*destination), register(*source)),
                )?;
                if *update_negative_zero {
                    self.line(indent, &format!("cpu_set_nz({});", register(*destination)))?;
                }
            }
            SemanticOperation::SetFlag { flag, value } => self.line(
                indent,
                &format!("cpu_set_flag({}, {});", flag_mask(*flag), u8::from(*value)),
            )?,
            SemanticOperation::Push { source } => {
                self.line(indent, &format!("cpu_push({});", source_text(source)?))?
            }
            SemanticOperation::Pull {
                destination,
                update_negative_zero,
            } => {
                self.line(indent, "{")?;
                self.line(indent + 1, "u8 value;")?;
                self.line(indent + 1, "value = cpu_pop();")?;
                self.emit_target_write(destination, "value", indent + 1)?;
                if *update_negative_zero {
                    self.line(indent + 1, "cpu_set_nz(value);")?;
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

    fn emit_shift(
        &mut self,
        operator: ShiftOperator,
        target: &ValueTarget,
        indent: usize,
    ) -> Result<(), Vec<AnalysisError>> {
        self.line(indent, "{")?;
        self.line(indent + 1, "u8 value;")?;
        self.line(indent + 1, "u8 carry;")?;
        self.line(indent + 1, &format!("value = {};", target_read(target)?))?;
        self.line(indent + 1, "carry = cpu_flag(0x01);")?;
        match operator {
            ShiftOperator::ArithmeticLeft => {
                self.line(indent + 1, "cpu_set_flag(0x01, (u8)((value & 0x80) != 0));")?;
                self.line(indent + 1, "value = (u8)(value << 1);")?;
            }
            ShiftOperator::LogicalRight => {
                self.line(indent + 1, "cpu_set_flag(0x01, (u8)((value & 1) != 0));")?;
                self.line(indent + 1, "value = (u8)(value >> 1);")?;
            }
            ShiftOperator::RotateLeft => {
                self.line(indent + 1, "cpu_set_flag(0x01, (u8)((value & 0x80) != 0));")?;
                self.line(indent + 1, "value = (u8)((value << 1) | carry);")?;
            }
            ShiftOperator::RotateRight => {
                self.line(indent + 1, "cpu_set_flag(0x01, (u8)((value & 1) != 0));")?;
                self.line(indent + 1, "value = (u8)((value >> 1) | (carry << 7));")?;
            }
        }
        self.emit_target_write(target, "value", indent + 1)?;
        self.line(indent + 1, "cpu_set_nz(value);")?;
        self.line(indent, "}")
    }

    fn emit_target_write(
        &mut self,
        target: &ValueTarget,
        value: &str,
        indent: usize,
    ) -> Result<(), Vec<AnalysisError>> {
        match target {
            ValueTarget::Register(register_name) => {
                self.line(indent, &format!("{} = {value};", register(*register_name)))
            }
            ValueTarget::Memory(memory) => self.line(
                indent,
                &format!("cpu_write({}, {value});", address_text(memory)?),
            ),
            ValueTarget::Status => self.line(indent, &format!("cpu_status = {value};")),
        }
    }

    fn emit_verification_schedule_service(&mut self) -> Result<(), Vec<AnalysisError>> {
        let nmi = self.interrupt_function_name(VectorKind::Nmi);
        let irq = self.interrupt_function_name(VectorKind::Irq);
        self.line(0, "")?;
        self.line(0, "static void verification_service_schedule(void) {")?;
        self.line(1, "u8 kind;")?;
        self.line(1, "kind = verification_schedule_kind;")?;
        self.line(1, "verification_schedule_kind = 0;")?;
        if let Some(name) = nmi {
            self.emit_verification_interrupt_case(1, 0xfffa, &name)?;
        }
        if let Some(name) = irq {
            self.emit_verification_interrupt_case(2, 0xfffe, &name)?;
        }
        self.line(1, "__nesc_trap();")?;
        self.line(0, "}")
    }

    fn emit_verification_interrupt_case(
        &mut self,
        kind: u8,
        vector: u16,
        function_name: &str,
    ) -> Result<(), Vec<AnalysisError>> {
        self.line(1, &format!("if (kind == {kind}) {{"))?;
        self.line(2, &format!("verification_observe(5, 0x{vector:04x}, 0);"))?;
        self.line(2, "cpu_push((u8)(cpu_pc >> 8));")?;
        self.line(2, "cpu_push((u8)cpu_pc);")?;
        self.line(2, "cpu_push((u8)((cpu_status & 0xef) | 0x20));")?;
        self.line(2, "cpu_set_flag(0x04, 1);")?;
        self.line(2, &format!("{function_name}();"))?;
        self.line(2, "return;")?;
        self.line(1, "}")
    }

    fn interrupt_function_name(&self, vector: VectorKind) -> Option<String> {
        self.program
            .functions
            .iter()
            .find(|function| {
                function.evidence.iter().any(
                    |evidence| matches!(evidence, super::FunctionEvidence::Vector(kind) if *kind == vector),
                ) && function.blocks.iter().any(|block| {
                    matches!(
                        self.program.blocks[block].terminator,
                        Terminator::ReturnFromInterrupt
                    )
                })
            })
            .and_then(|function| self.names.get(&function.id).cloned())
    }

    fn emit_verification_dispatch(&mut self) -> Result<(), Vec<AnalysisError>> {
        self.line(0, "")?;
        self.line(0, "static void verification_prepare_case(u16 test_case) {")?;
        let functions = self.program.functions.clone();
        for (index, function) in functions.iter().enumerate() {
            self.line(1, &format!("if (test_case == {index}) {{"))?;
            self.line(
                2,
                &format!("cpu_pc = 0x{:04x};", function.entry.cpu_address),
            )?;
            self.line(2, "return;")?;
            self.line(1, "}")?;
        }
        self.line(1, "__nesc_trap();")?;
        self.line(0, "}")?;
        self.line(0, "")?;
        self.line(0, "static void verification_dispatch(u16 test_case) {")?;
        for (index, function) in functions.iter().enumerate() {
            let name = self.names[&function.id].clone();
            self.line(1, &format!("if (test_case == {index}) {{"))?;
            self.line(
                2,
                &format!("cpu_pc = 0x{:04x};", function.entry.cpu_address),
            )?;
            self.line(2, &format!("{name}();"))?;
            self.line(2, "return;")?;
            self.line(1, "}")?;
        }
        self.line(1, "__nesc_trap();")?;
        self.line(0, "}")
    }

    fn emit_fallback_dispatcher(&mut self) -> Result<(), Vec<AnalysisError>> {
        let blocks = self.program.blocks.values().cloned().collect::<Vec<_>>();
        for block in &blocks {
            self.line(0, "")?;
            self.line(
                0,
                &format!("static void {}(void) {{", fallback_block_name(block.id)),
            )?;
            self.emit_block(block.id, 1)?;
            self.emit_dispatch_terminator(block, 1)?;
            self.line(0, "}")?;
        }

        self.line(0, "")?;
        self.line(0, "static void decompile_dispatch_once(void) {")?;
        for block in &blocks {
            let condition = if self.program.mapper == 2
                && block.id.bank != self.fixed_prg_bank
                && block.id.cpu_address < 0xc000
            {
                format!(
                    "(cpu_selected_prg_bank == {}) && (cpu_pc == 0x{:04x})",
                    block.id.bank, block.id.cpu_address
                )
            } else {
                format!("cpu_pc == 0x{:04x}", block.id.cpu_address)
            };
            self.line(1, &format!("if ({condition}) {{"))?;
            self.line(2, &format!("{}();", fallback_block_name(block.id)))?;
            self.line(2, "return;")?;
            self.line(1, "}")?;
        }
        self.line(1, "__nesc_trap();")?;
        self.line(1, "fallback_running = 0;")?;
        self.line(0, "}")?;

        self.line(0, "")?;
        self.line(0, "static void decompile_fallback(u16 entry) {")?;
        self.line(1, "fallback_running = 1;")?;
        self.line(1, "fallback_call_depth = 0;")?;
        self.line(1, "fallback_interrupt_depth = 0;")?;
        self.line(1, "cpu_pc = entry;")?;
        self.line(1, "while (fallback_running != 0) {")?;
        self.line(2, "decompile_dispatch_once();")?;
        self.line(1, "}")?;
        self.line(0, "}")
    }

    fn emit_dispatch_terminator(
        &mut self,
        block: &super::BasicBlock,
        indent: usize,
    ) -> Result<(), Vec<AnalysisError>> {
        match &block.terminator {
            Terminator::Fallthrough(target) | Terminator::Jump(target) => {
                self.line(
                    indent,
                    &format!("cpu_pc = 0x{:04x};", target_address(target)),
                )?;
            }
            Terminator::Branch {
                condition,
                taken,
                not_taken,
            } => {
                self.line(indent, &format!("if ({}) {{", branch_text(*condition)))?;
                self.line(
                    indent + 1,
                    &format!("cpu_pc = 0x{:04x};", target_address(taken)),
                )?;
                self.line(indent, "} else {")?;
                self.line(
                    indent + 1,
                    &format!("cpu_pc = 0x{:04x};", target_address(not_taken)),
                )?;
                self.line(indent, "}")?;
            }
            Terminator::Call { callee, .. } => {
                let call = block
                    .instructions
                    .last()
                    .expect("verified call instruction");
                let return_address =
                    call.provenance.address.cpu_address + call.provenance.bytes.len() as u16 - 1;
                self.line(
                    indent,
                    &format!(
                        "if (fallback_call_depth >= {}) {{ __nesc_trap(); }}",
                        self.config.max_fallback_call_depth
                    ),
                )?;
                self.line(indent, &format!("cpu_push(0x{:02x});", return_address >> 8))?;
                self.line(
                    indent,
                    &format!("cpu_push(0x{:02x});", return_address as u8),
                )?;
                self.line(
                    indent,
                    "fallback_call_depth = (u8)(fallback_call_depth + 1);",
                )?;
                self.line(
                    indent,
                    &format!("cpu_pc = 0x{:04x};", target_address(callee)),
                )?;
            }
            Terminator::Return => {
                self.line(indent, "if (fallback_call_depth == 0) {")?;
                self.line(indent + 1, "fallback_running = 0;")?;
                self.line(indent, "} else {")?;
                self.line(indent + 1, "{")?;
                self.line(indent + 2, "u8 return_low;")?;
                self.line(indent + 2, "u8 return_high;")?;
                self.line(indent + 2, "return_low = cpu_pop();")?;
                self.line(indent + 2, "return_high = cpu_pop();")?;
                self.line(
                    indent + 2,
                    "cpu_pc = (u16)((u16)(return_low | ((u16)return_high << 8)) + 1);",
                )?;
                self.line(indent + 1, "}")?;
                self.line(
                    indent + 1,
                    "fallback_call_depth = (u8)(fallback_call_depth - 1);",
                )?;
                self.line(indent, "}")?;
            }
            Terminator::ReturnFromInterrupt => {
                self.line(
                    indent,
                    "if ((fallback_interrupt_depth == 0) && (fallback_call_depth == 0)) {",
                )?;
                self.line(indent + 1, "fallback_running = 0;")?;
                self.line(indent, "} else {")?;
                self.line(indent + 1, "cpu_status = cpu_pop();")?;
                self.line(indent + 1, "{")?;
                self.line(indent + 2, "u8 return_low;")?;
                self.line(indent + 2, "u8 return_high;")?;
                self.line(indent + 2, "return_low = cpu_pop();")?;
                self.line(indent + 2, "return_high = cpu_pop();")?;
                self.line(
                    indent + 2,
                    "cpu_pc = (u16)(return_low | ((u16)return_high << 8));",
                )?;
                self.line(indent + 1, "}")?;
                self.line(
                    indent + 1,
                    "if (fallback_interrupt_depth != 0) { fallback_interrupt_depth = (u8)(fallback_interrupt_depth - 1); }",
                )?;
                self.line(indent, "}")?;
            }
            Terminator::Interrupt => {
                if self.config.verification {
                    self.line(indent, "verification_observe(5, 0xfffe, 0);")?;
                }
                let pc = block
                    .instructions
                    .last()
                    .map_or(block.id.cpu_address, |instruction| {
                        instruction.provenance.address.cpu_address
                    });
                let return_address = pc.wrapping_add(2);
                self.line(indent, &format!("cpu_push(0x{:02x});", return_address >> 8))?;
                self.line(
                    indent,
                    &format!("cpu_push(0x{:02x});", return_address as u8),
                )?;
                self.line(indent, "cpu_push((u8)(cpu_status | 0x10));")?;
                self.line(indent, "cpu_set_flag(0x04, 1);")?;
                self.line(
                    indent,
                    "cpu_pc = (u16)(cpu_read(0xfffe) | ((u16)cpu_read(0xffff) << 8));",
                )?;
                self.line(
                    indent,
                    "fallback_interrupt_depth = (u8)(fallback_interrupt_depth + 1);",
                )?;
            }
            Terminator::Stop(StopReason::IndirectJump { pointer }) => {
                let high = (pointer & 0xff00) | (pointer.wrapping_add(1) & 0x00ff);
                self.line(indent, &format!("cpu_pc = (u16)(cpu_read(0x{pointer:04x}) | ((u16)cpu_read(0x{high:04x}) << 8));"))?;
            }
            Terminator::Stop(StopReason::MissingInstruction { cpu_address }) => {
                self.line(indent, &format!("cpu_pc = 0x{cpu_address:04x};"))?;
            }
        }
        Ok(())
    }

    fn line(&mut self, indent: usize, text: &str) -> Result<(), Vec<AnalysisError>> {
        for _ in 0..indent {
            self.source.push_str("    ");
        }
        self.source.push_str(text);
        self.source.push('\n');
        if self.source.len() > self.limits.max_source_bytes {
            return Err(vec![AnalysisError::new(format!(
                "generated NesC source exceeds {} bytes",
                self.limits.max_source_bytes
            ))]);
        }
        Ok(())
    }
}

fn source_text(source: &ValueSource) -> Result<String, Vec<AnalysisError>> {
    match source {
        ValueSource::Register(value) => Ok(register(*value).to_owned()),
        ValueSource::Immediate(value) => Ok(format!("0x{value:02x}")),
        ValueSource::Memory(memory) => Ok(format!("cpu_read({})", address_text(memory)?)),
        ValueSource::Status => Ok("cpu_status".to_owned()),
    }
}

fn bank_attribute(bank: Option<u16>) -> String {
    bank.map_or_else(String::new, |bank| {
        format!("NES_BANK({bank}) NES_NOINLINE ")
    })
}

fn fallback_block_name(block: BlockId) -> String {
    format!(
        "decompile_block_prg{:04x}_{:04x}",
        block.bank, block.cpu_address
    )
}

fn target_read(target: &ValueTarget) -> Result<String, Vec<AnalysisError>> {
    match target {
        ValueTarget::Register(value) => Ok(register(*value).to_owned()),
        ValueTarget::Memory(memory) => Ok(format!("cpu_read({})", address_text(memory)?)),
        ValueTarget::Status => Ok("cpu_status".to_owned()),
    }
}

fn address_text(memory: &MemoryOperand) -> Result<String, Vec<AnalysisError>> {
    let byte = memory.encoded as u8;
    match memory.mode {
        AddressingMode::ZeroPage => Ok(format!("0x{byte:02x}")),
        AddressingMode::ZeroPageX => Ok(format!("(u8)(0x{byte:02x} + cpu_x)")),
        AddressingMode::ZeroPageY => Ok(format!("(u8)(0x{byte:02x} + cpu_y)")),
        AddressingMode::Absolute => Ok(format!("0x{:04x}", memory.encoded)),
        AddressingMode::AbsoluteX => Ok(format!("(u16)(0x{:04x} + cpu_x)", memory.encoded)),
        AddressingMode::AbsoluteY => Ok(format!("(u16)(0x{:04x} + cpu_y)", memory.encoded)),
        AddressingMode::IndexedIndirect => Ok(format!("cpu_indexed_indirect(0x{byte:02x})")),
        AddressingMode::IndirectIndexed => Ok(format!("cpu_indirect_indexed(0x{byte:02x})")),
        mode => Err(vec![AnalysisError::new(format!(
            "cannot emit NesC data operand with addressing mode {mode:?}"
        ))]),
    }
}

const fn register(value: Register) -> &'static str {
    match value {
        Register::A => "cpu_a",
        Register::X => "cpu_x",
        Register::Y => "cpu_y",
        Register::StackPointer => "cpu_sp",
        Register::ProgramCounter => "cpu_pc",
    }
}

const fn flag_mask(flag: Flag) -> &'static str {
    match flag {
        Flag::Carry => "0x01",
        Flag::Zero => "0x02",
        Flag::InterruptDisable => "0x04",
        Flag::Decimal => "0x08",
        Flag::Break => "0x10",
        Flag::Overflow => "0x40",
        Flag::Negative => "0x80",
    }
}

fn condition_text(condition: &RecoveredCondition) -> String {
    match condition.predicate {
        RecoveredPredicate::Comparison { predicate, .. } => match predicate {
            ComparisonPredicate::Equal => "cpu_flag(0x02) != 0".to_owned(),
            ComparisonPredicate::NotEqual => "cpu_flag(0x02) == 0".to_owned(),
            ComparisonPredicate::UnsignedGreaterEqual => "cpu_flag(0x01) != 0".to_owned(),
            ComparisonPredicate::UnsignedLess => "cpu_flag(0x01) == 0".to_owned(),
        },
        RecoveredPredicate::FlagValue { flag, expected, .. } => format!(
            "cpu_flag({}) {} 0",
            flag_mask(flag),
            if expected { "!=" } else { "==" }
        ),
    }
}

const fn branch_text(condition: BranchCondition) -> &'static str {
    match condition {
        BranchCondition::CarryClear => "cpu_flag(0x01) == 0",
        BranchCondition::CarrySet => "cpu_flag(0x01) != 0",
        BranchCondition::Equal => "cpu_flag(0x02) != 0",
        BranchCondition::Minus => "cpu_flag(0x80) != 0",
        BranchCondition::NotEqual => "cpu_flag(0x02) == 0",
        BranchCondition::Plus => "cpu_flag(0x80) == 0",
        BranchCondition::OverflowClear => "cpu_flag(0x40) == 0",
        BranchCondition::OverflowSet => "cpu_flag(0x40) != 0",
    }
}

fn target_address(target: &BlockTarget) -> u16 {
    match target {
        BlockTarget::Resolved(block) => block.cpu_address,
        BlockTarget::Unresolved { cpu_address, .. } => *cpu_address,
    }
}

fn state_name(state: StateVariable) -> String {
    match state {
        StateVariable::Register(value) => register(value).to_owned(),
        StateVariable::Flag(value) => format!("status {}", flag_mask(value)),
        StateVariable::Memory(value) => format!("memory {value:?}"),
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
        FallbackReason::OverlappingRegions => "overlapping regions",
        FallbackReason::InterruptControl => "interrupt control",
        FallbackReason::UnsupportedShape => "unsupported control-flow shape",
    }
}

fn manifest(disassembly: &Disassembly, config: &NesCEmitConfig) -> String {
    let metadata = &disassembly.rom.metadata;
    let region = match metadata.region {
        Region::Ntsc => "ntsc",
        Region::Pal => "pal",
        Region::Dendy => "dendy",
        Region::MultiRegion => unreachable!("multi-region metadata is rejected before emission"),
    };
    let format = match metadata.format {
        Format::Ines => "ines",
        Format::Nes2 => "nes2",
    };
    let mirroring = match metadata.mirroring {
        Mirroring::Horizontal => "horizontal",
        Mirroring::Vertical => "vertical",
        Mirroring::FourScreen => "four-screen",
    };
    format!(
        "[package]\nname = \"{}\"\nversion = \"0.1.0\"\n\n[build]\nentry = \"src/main.c\"\nregion = \"{region}\"\nformat = \"{format}\"\n\n[cartridge]\nmapper = {}\nsubmapper = {}\nmirroring = \"{mirroring}\"\nprg-rom-kib = {}\nchr-rom-kib = {}\nbattery = {}\n\n[compiler]\noptimization = \"0\"\nsigned-overflow = \"wrap\"\nbounds-checks = \"elide-proven\"\nstack-limit = 192\n\n[memory.zero-page]\navailable = [\"0x00..0xEF\"]\nreserved = [\"0xF0..0xFF\"]\nstrategy = \"frequency\"\n\n[debug]\nsymbols = true\nsource-map = true\n",
        config.package_name,
        metadata.mapper,
        metadata.submapper,
        metadata.prg_rom_len / 1024,
        metadata.chr_rom_len / 1024,
        metadata.battery
    )
}

fn report(program: &Program, control: &ControlFlowAnalysis) -> String {
    let mut output = format!(
        "{{\n  \"schema_version\": 1,\n  \"language\": \"nesc\",\n  \"mapper\": {},\n  \"functions\": [\n",
        program.mapper
    );
    for (index, function) in control.functions.iter().enumerate() {
        let recovered = &program.functions[function.function.0 as usize];
        let fallback = function
            .regions
            .iter()
            .find_map(|region| match region.kind {
                StructuredRegionKind::Fallback { reason } => Some(reason),
                _ => None,
            });
        let _ = writeln!(
            output,
            "    {{\"id\": {}, \"name\": \"{}\", \"bank\": {}, \"cpu_address\": {}, \"confidence\": \"{}\", \"fallback\": {}}}{}",
            recovered.id.0,
            recovered.name.replace('"', "\\\""),
            recovered.entry.bank,
            recovered.entry.cpu_address,
            match function.confidence {
                Confidence::Proven => "proven",
                Confidence::Conservative => "conservative",
                Confidence::Unknown => "unknown",
            },
            fallback.map_or_else(
                || "null".to_owned(),
                |reason| format!("\"{}\"", fallback_name(reason))
            ),
            if index + 1 == control.functions.len() {
                ""
            } else {
                ","
            }
        );
    }
    output.push_str("  ]\n}\n");
    output
}
