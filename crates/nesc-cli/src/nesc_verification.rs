use std::fmt;

use nesc_compiler::BuildArtifacts;
use nesc_debug::{
    CpuCheckpoint, HardwareCheckpoint, MemoryValue, VerificationArtifact, VerificationCheckpoint,
    VerificationDivergence, VerificationEvent, VerificationStatus,
};
use nesc_decompiler::{Function, FunctionEvidence, Program, Terminator};
use nesc_disasm::VectorKind;
use nesc_emulator::{
    CpuState, EmulatorConfig, EventKind, InterruptKind, Machine, ObservableEvent, Termination,
};
use nesc_rom::MapperState;

const EVENT_BASE: usize = 0x1b00;
const EVENT_LIMIT: usize = 255;
const EVENT_COUNT: usize = 0x1f00;
const EVENT_OVERFLOW: usize = 0x1f01;
const COMPLETION: usize = 0x1f02;
const RESULT_A: usize = 0x1f03;
const RESULT_X: usize = 0x1f04;
const RESULT_Y: usize = 0x1f05;
const RESULT_SP: usize = 0x1f06;
const RESULT_STATUS: usize = 0x1f07;
const RESULT_PC_LOW: usize = 0x1f08;
const RESULT_PC_HIGH: usize = 0x1f09;
const RESULT_PRG_BANK: usize = 0x1f0a;
const BUDGET_EXHAUSTED: usize = 0x1f0b;
const WORKSPACE_CONFLICT: usize = 0x1f0c;
const CHECKPOINT_REACHED: usize = 0x1f0d;
const CONFIG_CASE_LOW: usize = 0x1ff0;
const CONFIG_CASE_HIGH: usize = 0x1ff1;
const CONFIG_STATUS: usize = 0x1ff2;
const CONFIG_PRG_BANK: usize = 0x1ff3;
const CONFIG_SCHEDULE_KIND: usize = 0x1ff4;
const CONFIG_SCHEDULE_STEP_LOW: usize = 0x1ff5;
const CONFIG_SCHEDULE_STEP_HIGH: usize = 0x1ff6;
const COMPLETION_MARKER: u8 = 0xa5;
const PHYSICAL_INSTRUCTION_MULTIPLIER: u64 = 128;
const FRAME_CHECKPOINT_LIMIT: usize = 2;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RootTermination {
    Returned,
    Checkpoint,
    Trap(u8),
    InstructionLimit,
}

impl fmt::Display for RootTermination {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Returned => formatter.write_str("returned"),
            Self::Checkpoint => formatter.write_str("reached the scheduled checkpoint"),
            Self::Trap(reason) => write!(formatter, "trapped with reason ${reason:02X}"),
            Self::InstructionLimit => formatter.write_str("reached the instruction limit"),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum VerificationSchedule {
    None,
    Nmi { instruction: u16 },
    Irq { instruction: u16 },
    FrameCheckpoint { instruction: u16 },
}

impl VerificationSchedule {
    const fn encoded(self) -> (u8, u16) {
        match self {
            Self::None => (0, 0),
            Self::Nmi { instruction } => (1, instruction),
            Self::Irq { instruction } => (2, instruction),
            Self::FrameCheckpoint { instruction } => (3, instruction),
        }
    }

    const fn kind(self) -> Option<&'static str> {
        match self {
            Self::None => None,
            Self::Nmi { .. } => Some("nmi"),
            Self::Irq { .. } => Some("irq"),
            Self::FrameCheckpoint { .. } => Some("frame"),
        }
    }

    const fn instruction(self) -> Option<u16> {
        match self {
            Self::None => None,
            Self::Nmi { instruction }
            | Self::Irq { instruction }
            | Self::FrameCheckpoint { instruction } => Some(instruction),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ExecutionConfig {
    initial_bank: u16,
    status: u8,
    controller: u8,
    instruction_limit: u64,
    schedule: VerificationSchedule,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SemanticEvent {
    kind: u8,
    address: u16,
    value: u8,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct HardwareState {
    apu_io: Box<[u8; 0x18]>,
    chr_ram: Box<[u8; 0x2000]>,
    palette: Box<[u8; 32]>,
    oam: Box<[u8; 256]>,
    nametable_ram: Box<[u8; 0x1000]>,
}

impl HardwareState {
    fn capture(machine: &Machine) -> Self {
        Self {
            apu_io: Box::new(*machine.apu_io()),
            chr_ram: Box::new(*machine.chr_ram()),
            palette: Box::new(*machine.palette()),
            oam: Box::new(*machine.oam()),
            nametable_ram: Box::new(*machine.nametable_ram()),
        }
    }
}

#[derive(Debug)]
struct OriginalResult {
    termination: RootTermination,
    cpu: CpuState,
    ram: Box<[u8; 0x800]>,
    prg_ram: Box<[u8; 0x2000]>,
    prg_bank: u8,
    hardware: HardwareState,
    events: Vec<SemanticEvent>,
}

#[derive(Debug)]
struct TranslatedResult {
    termination: RootTermination,
    cpu: Option<CpuState>,
    ram: Box<[u8; 0x800]>,
    prg_ram: Box<[u8; 0x2000]>,
    prg_bank: Option<u8>,
    hardware: HardwareState,
    events: Vec<SemanticEvent>,
}

pub(crate) struct VerificationReport {
    pub(crate) artifact: VerificationArtifact,
    pub(crate) executions: usize,
}

pub(crate) struct VerificationFailure {
    pub(crate) message: String,
    pub(crate) artifact: Box<VerificationArtifact>,
}

type ComparisonResult = Result<(), Box<VerificationDivergence>>;

struct VerificationCase<'a> {
    case_index: usize,
    function: &'a Function,
    initial_bank: u16,
    status: u8,
    controller: u8,
    schedule: VerificationSchedule,
    frame: Option<usize>,
    context: String,
}

pub(crate) fn verify(
    original_rom: &[u8],
    translated: &BuildArtifacts,
    program: &Program,
    instruction_limit: u64,
) -> Result<VerificationReport, VerificationFailure> {
    let mut artifact = base_artifact(program, instruction_limit);
    if instruction_limit == 0 {
        return Err(configuration_failure(
            artifact,
            "verification instruction limit must be greater than zero",
        ));
    }
    let main_address = translated
        .symbol_addresses
        .get("main")
        .copied()
        .ok_or_else(|| {
            configuration_failure(artifact.clone(), "generated ROM does not export `main`")
        })?;
    let original = nesc_rom::parse(original_rom).map_err(|error| {
        configuration_failure(
            artifact.clone(),
            format!("original ROM is invalid: {error}"),
        )
    })?;
    let translated_rom = nesc_rom::parse(&translated.rom).map_err(|error| {
        configuration_failure(
            artifact.clone(),
            format!("generated ROM is invalid: {error}"),
        )
    })?;
    if original.metadata.mapper != program.mapper
        || translated_rom.metadata.mapper != program.mapper
    {
        return Err(configuration_failure(
            artifact,
            "verification ROM mapper metadata does not match semantic analysis",
        ));
    }
    let prg_bank_count = original.prg_rom.len() / 0x4000;
    let switchable_banks = if program.mapper == 2 {
        prg_bank_count.saturating_sub(1)
    } else {
        1
    };
    if switchable_banks == 0 || switchable_banks > usize::from(u8::MAX) {
        return Err(configuration_failure(
            artifact,
            format!(
                "verification cannot represent {switchable_banks} switchable PRG bank contexts"
            ),
        ));
    }
    if program.functions.is_empty() {
        return Err(configuration_failure(
            artifact,
            "verification requires at least one recovered function",
        ));
    }

    let semantic_limit = instruction_limit.min(u64::from(u16::MAX));
    let translated_limit = semantic_limit
        .saturating_mul(PHYSICAL_INSTRUCTION_MULTIPLIER)
        .max(1_024);
    artifact.prg_banks = prg_bank_count;
    artifact.switchable_bank_contexts = switchable_banks;
    artifact.semantic_instruction_limit_per_execution = semantic_limit;
    artifact.generated_instruction_limit_per_execution = translated_limit;
    let profiles = [(0x20_u8, 0x00_u8), (0x21, 0x01), (0x6f, 0x80), (0xef, 0xff)];
    for (case_index, function) in program.functions.iter().enumerate() {
        if is_interrupt_handler(function, program) {
            continue;
        }
        for initial_bank in bank_contexts(program, function, switchable_banks) {
            for (status, controller) in profiles {
                let context = format!(
                    "function {} at PRG bank {}, CPU ${:04X}, initial bank {}, status ${status:02X}, controller ${controller:02X}",
                    function.id.0, function.entry.bank, function.entry.cpu_address, initial_bank
                );
                verify_case(
                    original_rom,
                    translated,
                    main_address,
                    semantic_limit,
                    translated_limit,
                    &mut artifact,
                    VerificationCase {
                        case_index,
                        function,
                        initial_bank,
                        status,
                        controller,
                        schedule: VerificationSchedule::None,
                        frame: None,
                        context,
                    },
                )?;
            }
        }
    }

    let reset_case = program
        .functions
        .iter()
        .position(|function| has_vector(function, VectorKind::Reset))
        .unwrap_or(0);
    let reset = &program.functions[reset_case];
    let reset_banks = bank_contexts(program, reset, switchable_banks);
    let has_nmi = program.functions.iter().any(|function| {
        has_vector(function, VectorKind::Nmi) && is_interrupt_handler(function, program)
    });
    let has_irq = program.functions.iter().any(|function| {
        has_vector(function, VectorKind::Irq) && is_interrupt_handler(function, program)
    });
    for initial_bank in reset_banks {
        for (label, schedule) in [
            (
                "NMI",
                has_nmi.then_some(VerificationSchedule::Nmi { instruction: 0 }),
            ),
            (
                "IRQ",
                has_irq.then_some(VerificationSchedule::Irq { instruction: 0 }),
            ),
        ] {
            let Some(schedule) = schedule else {
                continue;
            };
            let context = format!(
                "reset function {} with {label} before semantic instruction 0, initial bank {initial_bank}",
                reset.id.0
            );
            verify_case(
                original_rom,
                translated,
                main_address,
                semantic_limit,
                translated_limit,
                &mut artifact,
                VerificationCase {
                    case_index: reset_case,
                    function: reset,
                    initial_bank,
                    status: 0x20,
                    controller: 0,
                    schedule,
                    frame: None,
                    context,
                },
            )?;
        }

        let frame_checkpoints = discover_frame_checkpoints(
            original_rom,
            reset.entry.cpu_address,
            initial_bank,
            0x20,
            0,
            semantic_limit,
        )
        .map_err(|error| {
            execution_failure(
                &artifact,
                "original frame discovery",
                &format!("reset function {}, initial bank {initial_bank}", reset.id.0),
                error,
            )
        })?;
        for (frame_index, instruction) in frame_checkpoints.into_iter().enumerate() {
            let frame = frame_index + 1;
            let context = format!(
                "reset function {} at frame boundary {frame} after semantic instruction {instruction}, initial bank {initial_bank}",
                reset.id.0
            );
            verify_case(
                original_rom,
                translated,
                main_address,
                semantic_limit,
                translated_limit,
                &mut artifact,
                VerificationCase {
                    case_index: reset_case,
                    function: reset,
                    initial_bank,
                    status: 0x20,
                    controller: 0,
                    schedule: VerificationSchedule::FrameCheckpoint { instruction },
                    frame: Some(frame),
                    context,
                },
            )?;
        }
    }
    let executions = artifact.executions;
    Ok(VerificationReport {
        artifact,
        executions,
    })
}

#[allow(clippy::too_many_arguments)]
fn verify_case(
    original_rom: &[u8],
    translated: &BuildArtifacts,
    main_address: u16,
    semantic_limit: u64,
    translated_limit: u64,
    artifact: &mut VerificationArtifact,
    case: VerificationCase<'_>,
) -> Result<(), VerificationFailure> {
    let original_result = run_original(
        original_rom,
        case.function.entry.cpu_address,
        ExecutionConfig {
            initial_bank: case.initial_bank,
            status: case.status,
            controller: case.controller,
            instruction_limit: semantic_limit,
            schedule: case.schedule,
        },
    )
    .map_err(|error| execution_failure(artifact, "original execution", &case.context, error))?;
    let translated_result = run_translated(
        &translated.rom,
        main_address,
        case.case_index,
        ExecutionConfig {
            initial_bank: case.initial_bank,
            status: case.status,
            controller: case.controller,
            instruction_limit: translated_limit,
            schedule: case.schedule,
        },
    )
    .map_err(|error| execution_failure(artifact, "generated execution", &case.context, error))?;
    compare_results(&original_result, &translated_result, &case.context).map_err(
        |mut divergence| {
            if divergence.recent_original_events.is_empty() {
                divergence.recent_original_events = recent_events(&original_result.events);
            }
            if divergence.recent_generated_events.is_empty() {
                divergence.recent_generated_events = recent_events(&translated_result.events);
            }
            divergence_failure(artifact, *divergence)
        },
    )?;
    artifact.executions += 1;
    artifact.observable_events_compared += original_result.events.len();
    if case.schedule == VerificationSchedule::None {
        artifact.direct_function_executions += 1;
    } else {
        let checkpoint = checkpoint(artifact.checkpoints.len(), &case, &original_result);
        artifact.checkpoints.push(checkpoint);
        match case.schedule {
            VerificationSchedule::None => {}
            VerificationSchedule::Nmi { .. } => artifact.nmi_schedule_executions += 1,
            VerificationSchedule::Irq { .. } => artifact.irq_schedule_executions += 1,
            VerificationSchedule::FrameCheckpoint { .. } => {
                artifact.frame_boundary_executions += 1;
            }
        }
    }
    Ok(())
}

fn base_artifact(program: &Program, instruction_limit: u64) -> VerificationArtifact {
    VerificationArtifact {
        schema_version: 1,
        mode: "original-6502-vs-nesc".to_owned(),
        status: VerificationStatus::Passed,
        mapper: program.mapper,
        functions: program.functions.len(),
        input_profiles_per_bank_context: 4,
        frame_checkpoint_limit_per_bank_context: FRAME_CHECKPOINT_LIMIT,
        interrupt_schedule_instruction: 0,
        semantic_event_capacity: EVENT_LIMIT,
        ram_bytes_compared_per_completed_execution: 2048,
        prg_ram_bytes_compared_per_completed_execution: 4096,
        apu_io_bytes_compared_per_completed_execution: 24,
        chr_ram_bytes_compared_per_completed_execution: 8192,
        palette_bytes_compared_per_completed_execution: 32,
        oam_bytes_compared_per_completed_execution: 256,
        nametable_bytes_compared_per_completed_execution: 4096,
        verification_workspace: "0x7000..0x7fff".to_owned(),
        semantic_instruction_limit_per_execution: instruction_limit.min(u64::from(u16::MAX)),
        ..VerificationArtifact::default()
    }
}

fn configuration_failure(
    artifact: VerificationArtifact,
    message: impl Into<String>,
) -> VerificationFailure {
    let message = message.into();
    divergence_failure(
        &artifact,
        VerificationDivergence {
            category: "configuration".to_owned(),
            context: "verification setup".to_owned(),
            original: "valid configuration".to_owned(),
            generated: message,
            ..VerificationDivergence::default()
        },
    )
}

fn execution_failure(
    artifact: &VerificationArtifact,
    category: &str,
    context: &str,
    error: String,
) -> VerificationFailure {
    divergence_failure(
        artifact,
        VerificationDivergence {
            category: category.to_owned(),
            context: context.to_owned(),
            original: "completed".to_owned(),
            generated: error,
            ..VerificationDivergence::default()
        },
    )
}

fn divergence_failure(
    artifact: &VerificationArtifact,
    divergence: VerificationDivergence,
) -> VerificationFailure {
    let message = divergence.message();
    let mut artifact = artifact.clone();
    artifact.status = VerificationStatus::Failed;
    artifact.divergence = Some(divergence);
    VerificationFailure {
        message,
        artifact: Box::new(artifact),
    }
}

fn checkpoint(
    id: usize,
    case: &VerificationCase<'_>,
    result: &OriginalResult,
) -> VerificationCheckpoint {
    VerificationCheckpoint {
        id,
        kind: case.schedule.kind().unwrap_or("completion").to_owned(),
        function: case.function.id.0,
        entry_bank: case.function.entry.bank,
        entry_address: case.function.entry.cpu_address,
        initial_bank: case.initial_bank,
        status: case.status,
        controller: case.controller,
        frame: case.frame,
        semantic_instruction: case.schedule.instruction(),
        termination: result.termination.to_string(),
        cpu: CpuCheckpoint {
            a: result.cpu.a,
            x: result.cpu.x,
            y: result.cpu.y,
            sp: result.cpu.sp,
            status: result.cpu.status,
            pc: result.cpu.pc,
        },
        mapper_prg_bank: result.prg_bank,
        event_count: result.events.len(),
        recent_events: recent_events(&result.events),
        hardware: hardware_checkpoint(&result.hardware),
    }
}

fn hardware_checkpoint(hardware: &HardwareState) -> HardwareCheckpoint {
    HardwareCheckpoint {
        apu_io: sparse_memory(&hardware.apu_io[..], 0x4000),
        chr_ram: sparse_memory(&hardware.chr_ram[..], 0x0000),
        palette: sparse_memory(&hardware.palette[..], 0x3f00),
        oam: sparse_memory(&hardware.oam[..], 0x0000),
        nametable_ram: sparse_memory(&hardware.nametable_ram[..], 0x2000),
    }
}

fn sparse_memory(memory: &[u8], base: u16) -> Vec<MemoryValue> {
    memory
        .iter()
        .enumerate()
        .filter(|(_, value)| **value != 0)
        .map(|(index, value)| MemoryValue {
            address: base.saturating_add(index as u16),
            value: *value,
        })
        .collect()
}

fn recent_events(events: &[SemanticEvent]) -> Vec<VerificationEvent> {
    let start = events.len().saturating_sub(8);
    events[start..].iter().map(verification_event).collect()
}

fn verification_event(event: &SemanticEvent) -> VerificationEvent {
    VerificationEvent {
        kind: match event.kind {
            1 => "volatile-read",
            2 => "volatile-write",
            3 => "mapper-write",
            4 => "dma",
            5 => "interrupt",
            _ => "unknown",
        }
        .to_owned(),
        address: event.address,
        value: event.value,
    }
}

fn has_vector(function: &Function, vector: VectorKind) -> bool {
    function
        .evidence
        .iter()
        .any(|evidence| matches!(evidence, FunctionEvidence::Vector(kind) if *kind == vector))
}

fn is_interrupt_handler(function: &Function, program: &Program) -> bool {
    (has_vector(function, VectorKind::Nmi) || has_vector(function, VectorKind::Irq))
        && function.blocks.iter().any(|block| {
            matches!(
                program.blocks[block].terminator,
                Terminator::ReturnFromInterrupt
            )
        })
}

fn bank_contexts(program: &Program, function: &Function, switchable_banks: usize) -> Vec<u16> {
    if program.mapper == 2 && function.entry.cpu_address >= 0xc000 {
        (0..switchable_banks).map(|bank| bank as u16).collect()
    } else if program.mapper == 2 {
        vec![function.entry.bank]
    } else {
        vec![0]
    }
}

fn run_original(rom: &[u8], entry: u16, config: ExecutionConfig) -> Result<OriginalResult, String> {
    let mut machine = machine(rom)?;
    machine.reset().map_err(|error| error.to_string())?;
    machine.set_mapper_state(MapperState {
        prg_bank: config.initial_bank as u8,
        chr_bank: 0,
    });
    machine
        .set_controller(0, config.controller)
        .map_err(|error| error.to_string())?;
    *machine.cpu_mut() = CpuState {
        a: 0,
        x: 0,
        y: 0,
        sp: 0xfd,
        status: config.status,
        pc: entry,
    };
    machine.clear_events();
    let termination = run_root(&mut machine, config.instruction_limit, config.schedule)?;
    Ok(OriginalResult {
        termination,
        cpu: *machine.cpu(),
        ram: Box::new(*machine.ram()),
        prg_ram: Box::new(*machine.prg_ram()),
        prg_bank: machine.mapper_state().prg_bank,
        hardware: HardwareState::capture(&machine),
        events: original_events(machine.events()),
    })
}

fn run_translated(
    rom: &[u8],
    main_address: u16,
    case_index: usize,
    config: ExecutionConfig,
) -> Result<TranslatedResult, String> {
    let case_index = u16::try_from(case_index)
        .map_err(|_| format!("verification case {case_index} does not fit in u16"))?;
    let mut machine = machine(rom)?;
    {
        let prg_ram = machine.prg_ram_mut();
        prg_ram[CONFIG_CASE_LOW] = case_index as u8;
        prg_ram[CONFIG_CASE_HIGH] = (case_index >> 8) as u8;
        prg_ram[CONFIG_STATUS] = config.status;
        prg_ram[CONFIG_PRG_BANK] = config.initial_bank as u8;
        let (schedule_kind, schedule_step) = config.schedule.encoded();
        prg_ram[CONFIG_SCHEDULE_KIND] = schedule_kind;
        prg_ram[CONFIG_SCHEDULE_STEP_LOW] = schedule_step as u8;
        prg_ram[CONFIG_SCHEDULE_STEP_HIGH] = (schedule_step >> 8) as u8;
    }
    machine.reset().map_err(|error| error.to_string())?;
    machine.set_mapper_state(MapperState {
        prg_bank: config.initial_bank as u8,
        chr_bank: 0,
    });
    machine
        .set_controller(0, config.controller)
        .map_err(|error| error.to_string())?;
    reach_main(&mut machine, main_address)?;
    machine.clear_events();
    let termination = run_root(
        &mut machine,
        config.instruction_limit,
        VerificationSchedule::None,
    )?;
    let hardware = HardwareState::capture(&machine);
    decode_translation(machine.prg_ram(), termination, hardware)
}

fn machine(rom: &[u8]) -> Result<Machine, String> {
    Machine::from_rom_bytes(
        rom,
        EmulatorConfig {
            event_capacity: 65_536,
            ..EmulatorConfig::default()
        },
    )
    .map_err(|error| error.to_string())
}

fn reach_main(machine: &mut Machine, main_address: u16) -> Result<(), String> {
    for _ in 0..1_024 {
        if machine.cpu().pc == main_address {
            return Ok(());
        }
        let report = machine.step().map_err(|error| error.to_string())?;
        if let Some(termination) = report.termination {
            return Err(format!(
                "generated startup terminated before `main`: {termination:?}"
            ));
        }
    }
    Err("generated startup did not reach `main` within 1024 instructions".to_owned())
}

fn run_root(
    machine: &mut Machine,
    instruction_limit: u64,
    schedule: VerificationSchedule,
) -> Result<RootTermination, String> {
    let mut call_depth = 0_u32;
    let mut interrupt_depth = 0_u32;
    let mut instructions = 0_u64;
    let mut schedule_triggered = false;
    loop {
        if matches!(
            schedule,
            VerificationSchedule::FrameCheckpoint { instruction }
                if u64::from(instruction) == instructions
        ) {
            return Ok(RootTermination::Checkpoint);
        }
        let scheduled_interrupt = match schedule {
            VerificationSchedule::Nmi { instruction }
                if !schedule_triggered && u64::from(instruction) == instructions =>
            {
                Some(InterruptKind::Nmi)
            }
            VerificationSchedule::Irq { instruction }
                if !schedule_triggered && u64::from(instruction) == instructions =>
            {
                Some(InterruptKind::Irq)
            }
            _ => None,
        };
        if let Some(interrupt) = scheduled_interrupt {
            match interrupt {
                InterruptKind::Nmi => machine.request_nmi(),
                InterruptKind::Irq => machine.set_irq_line(true),
                InterruptKind::Brk => unreachable!("BRK is not an external schedule"),
            }
            let report = machine.step().map_err(|error| error.to_string())?;
            machine.set_irq_line(false);
            if report.interrupt != Some(interrupt) {
                return Err(format!(
                    "scheduled {interrupt:?} was not accepted at semantic instruction {instructions}"
                ));
            }
            schedule_triggered = true;
            interrupt_depth = interrupt_depth.saturating_add(1);
            continue;
        }
        let pc = machine.cpu().pc;
        let opcode = machine.peek(pc).map_err(|error| error.to_string())?;
        if call_depth == 0 && interrupt_depth == 0 && matches!(opcode, 0x40 | 0x60) {
            return Ok(RootTermination::Returned);
        }
        if instructions >= instruction_limit {
            return Ok(RootTermination::InstructionLimit);
        }
        let report = machine.step().map_err(|error| error.to_string())?;
        if let Some(Termination::Trap { reason }) = report.termination {
            return Ok(RootTermination::Trap(reason));
        }
        if report.interrupt.is_some() {
            interrupt_depth = interrupt_depth.saturating_add(1);
            continue;
        }
        instructions = instructions.saturating_add(1);
        if opcode == 0x20 {
            call_depth = call_depth.saturating_add(1);
        } else if opcode == 0x40 && interrupt_depth != 0 {
            interrupt_depth -= 1;
            if interrupt_depth == 0
                && schedule_triggered
                && matches!(
                    schedule,
                    VerificationSchedule::Nmi { .. } | VerificationSchedule::Irq { .. }
                )
            {
                return Ok(RootTermination::Checkpoint);
            }
        } else if opcode == 0x60 && call_depth != 0 {
            call_depth -= 1;
        }
    }
}

fn discover_frame_checkpoints(
    rom: &[u8],
    entry: u16,
    initial_bank: u16,
    status: u8,
    controller: u8,
    instruction_limit: u64,
) -> Result<Vec<u16>, String> {
    let mut machine = machine(rom)?;
    machine.reset().map_err(|error| error.to_string())?;
    machine.set_mapper_state(MapperState {
        prg_bank: initial_bank as u8,
        chr_bank: 0,
    });
    machine
        .set_controller(0, controller)
        .map_err(|error| error.to_string())?;
    *machine.cpu_mut() = CpuState {
        a: 0,
        x: 0,
        y: 0,
        sp: 0xfd,
        status,
        pc: entry,
    };
    let initial_frame = machine.frames();
    let mut call_depth = 0_u32;
    let mut interrupt_depth = 0_u32;
    let mut instructions = 0_u64;
    let mut checkpoints = Vec::new();
    while instructions < instruction_limit {
        let pc = machine.cpu().pc;
        let opcode = machine.peek(pc).map_err(|error| error.to_string())?;
        if call_depth == 0 && interrupt_depth == 0 && matches!(opcode, 0x40 | 0x60) {
            return Ok(checkpoints);
        }
        let report = machine.step().map_err(|error| error.to_string())?;
        if report.termination.is_some() {
            return Ok(checkpoints);
        }
        if report.interrupt.is_some() {
            interrupt_depth = interrupt_depth.saturating_add(1);
            continue;
        }
        instructions = instructions.saturating_add(1);
        if opcode == 0x20 {
            call_depth = call_depth.saturating_add(1);
        } else if opcode == 0x40 && interrupt_depth != 0 {
            interrupt_depth -= 1;
        } else if opcode == 0x60 && call_depth != 0 {
            call_depth -= 1;
        }
        while machine.frames() > initial_frame.saturating_add(checkpoints.len() as u64)
            && checkpoints.len() < FRAME_CHECKPOINT_LIMIT
        {
            checkpoints.push(
                u16::try_from(instructions)
                    .map_err(|_| "frame checkpoint does not fit in u16".to_owned())?,
            );
        }
        if checkpoints.len() == FRAME_CHECKPOINT_LIMIT {
            return Ok(checkpoints);
        }
    }
    Ok(checkpoints)
}

fn original_events(events: &std::collections::VecDeque<ObservableEvent>) -> Vec<SemanticEvent> {
    events
        .iter()
        .filter_map(|event| {
            let kind = match event.kind {
                EventKind::VolatileRead => 1,
                EventKind::VolatileWrite => 2,
                EventKind::MapperWrite => 3,
                EventKind::Dma => 4,
                EventKind::Interrupt => 5,
                EventKind::Instruction | EventKind::VBlank | EventKind::Frame | EventKind::Trap => {
                    return None;
                }
            };
            Some(SemanticEvent {
                kind,
                address: event.address.unwrap_or(0),
                value: event.value.unwrap_or(0),
            })
        })
        .collect()
}

fn decode_translation(
    prg_ram: &[u8; 0x2000],
    termination: RootTermination,
    hardware: HardwareState,
) -> Result<TranslatedResult, String> {
    if prg_ram[WORKSPACE_CONFLICT] != 0 {
        return Err(
            "translated execution accessed PRG RAM reserved for verification at $7000-$7FFF"
                .to_owned(),
        );
    }
    let termination = if prg_ram[CHECKPOINT_REACHED] != 0
        && matches!(termination, RootTermination::Trap(_))
    {
        RootTermination::Checkpoint
    } else if prg_ram[BUDGET_EXHAUSTED] != 0 && matches!(termination, RootTermination::Trap(_)) {
        RootTermination::InstructionLimit
    } else {
        termination
    };
    let count = usize::from(prg_ram[EVENT_COUNT]);
    if count > EVENT_LIMIT || prg_ram[EVENT_OVERFLOW] != 0 {
        return Err(format!(
            "semantic event log exceeded its {EVENT_LIMIT}-event bound"
        ));
    }
    let mut observable = Vec::new();
    let mut ram = Box::new([0_u8; 0x800]);
    ram.copy_from_slice(&prg_ram[0x1000..0x1800]);
    let mut logical_prg_ram = Box::new([0_u8; 0x2000]);
    logical_prg_ram[..0x1000].copy_from_slice(&prg_ram[..0x1000]);
    for index in 0..count {
        let base = EVENT_BASE + index * 4;
        let event = SemanticEvent {
            kind: prg_ram[base],
            address: u16::from_le_bytes([prg_ram[base + 1], prg_ram[base + 2]]),
            value: prg_ram[base + 3],
        };
        match event.kind {
            1..=5 => observable.push(event),
            kind => return Err(format!("semantic event log contains unknown kind {kind}")),
        }
    }
    let completed = prg_ram[COMPLETION] == COMPLETION_MARKER;
    let cpu = completed.then(|| CpuState {
        a: prg_ram[RESULT_A],
        x: prg_ram[RESULT_X],
        y: prg_ram[RESULT_Y],
        sp: prg_ram[RESULT_SP],
        status: prg_ram[RESULT_STATUS],
        pc: u16::from_le_bytes([prg_ram[RESULT_PC_LOW], prg_ram[RESULT_PC_HIGH]]),
    });
    Ok(TranslatedResult {
        termination,
        cpu,
        ram,
        prg_ram: logical_prg_ram,
        prg_bank: completed.then_some(prg_ram[RESULT_PRG_BANK]),
        hardware,
        events: observable,
    })
}

fn compare_results(
    original: &OriginalResult,
    translated: &TranslatedResult,
    context: &str,
) -> ComparisonResult {
    if translated.termination != original.termination {
        return Err(Box::new(divergence(
            "termination",
            context,
            None,
            original.termination.to_string(),
            translated.termination.to_string(),
        )));
    }
    if matches!(
        original.termination,
        RootTermination::Returned | RootTermination::Checkpoint
    ) {
        let translated_cpu = translated.cpu.ok_or_else(|| {
            Box::new(divergence(
                "completion record",
                context,
                None,
                "present".to_owned(),
                "missing".to_owned(),
            ))
        })?;
        if translated_cpu != original.cpu {
            return Err(Box::new(divergence(
                "CPU state",
                context,
                None,
                format!("{:?}", original.cpu),
                format!("{translated_cpu:?}"),
            )));
        }
        if translated.prg_bank != Some(original.prg_bank) {
            return Err(Box::new(divergence(
                "mapper state",
                context,
                Some("PRG bank".to_owned()),
                original.prg_bank.to_string(),
                format!("{:?}", translated.prg_bank),
            )));
        }
        compare_memory(
            "RAM",
            &original.ram[..],
            &translated.ram[..],
            0x0000,
            context,
        )?;
        compare_memory(
            "PRG RAM",
            &original.prg_ram[..0x1000],
            &translated.prg_ram[..0x1000],
            0x6000,
            context,
        )?;
        compare_memory(
            "APU I/O",
            &original.hardware.apu_io[..],
            &translated.hardware.apu_io[..],
            0x4000,
            context,
        )?;
        compare_memory(
            "CHR RAM",
            &original.hardware.chr_ram[..],
            &translated.hardware.chr_ram[..],
            0x0000,
            context,
        )?;
        compare_memory(
            "palette",
            &original.hardware.palette[..],
            &translated.hardware.palette[..],
            0x3f00,
            context,
        )?;
        compare_memory(
            "OAM",
            &original.hardware.oam[..],
            &translated.hardware.oam[..],
            0x0000,
            context,
        )?;
        compare_memory(
            "nametable RAM",
            &original.hardware.nametable_ram[..],
            &translated.hardware.nametable_ram[..],
            0x2000,
            context,
        )?;
    }
    if translated.events != original.events {
        let first = translated
            .events
            .iter()
            .zip(&original.events)
            .position(|(translated, original)| translated != original)
            .unwrap_or_else(|| translated.events.len().min(original.events.len()));
        let trace_start = first.saturating_sub(4);
        return Err(Box::new(VerificationDivergence {
            category: "semantic event".to_owned(),
            context: context.to_owned(),
            location: Some(first.to_string()),
            original: format!("{:?}", original.events.get(first)),
            generated: format!("{:?}", translated.events.get(first)),
            recent_original_events: original.events[trace_start..first.min(original.events.len())]
                .iter()
                .map(verification_event)
                .collect(),
            recent_generated_events: translated.events
                [trace_start.min(translated.events.len())..first.min(translated.events.len())]
                .iter()
                .map(verification_event)
                .collect(),
        }));
    }
    Ok(())
}

fn compare_memory(
    name: &str,
    original: &[u8],
    translated: &[u8],
    address_base: u16,
    context: &str,
) -> ComparisonResult {
    if let Some(index) = original
        .iter()
        .zip(translated)
        .position(|(original, translated)| original != translated)
    {
        return Err(Box::new(divergence(
            name,
            context,
            Some(format!(
                "${:04X}",
                address_base.saturating_add(index as u16)
            )),
            format!("${:02X}", original[index]),
            format!("${:02X}", translated[index]),
        )));
    }
    Ok(())
}

fn divergence(
    category: &str,
    context: &str,
    location: Option<String>,
    original: String,
    generated: String,
) -> VerificationDivergence {
    VerificationDivergence {
        category: category.to_owned(),
        context: context.to_owned(),
        location,
        original,
        generated,
        ..VerificationDivergence::default()
    }
}
