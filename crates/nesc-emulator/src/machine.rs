//! Deterministic bounded NES machine execution.

use std::collections::VecDeque;
use std::error::Error;
use std::fmt;

use nesc_disasm::{AddressingMode, Mnemonic, opcode};
use nesc_rom::{CpuAddress, Mapper, MapperState, Mirroring, PpuAddress, Region, Rom};

use crate::apu::{Apu, ApuState, ApuTiming};
use crate::cpu::{
    CpuState, FLAG_BREAK, FLAG_CARRY, FLAG_DECIMAL, FLAG_INTERRUPT_DISABLE, FLAG_NEGATIVE,
    FLAG_OVERFLOW, FLAG_UNUSED, FLAG_ZERO,
};

const IRQ_VECTOR: u16 = 0xfffe;
const RESET_VECTOR: u16 = 0xfffc;
const NMI_VECTOR: u16 = 0xfffa;
const STACK_BASE: u16 = 0x0100;

/// Width of one rendered NES frame in pixels.
pub const FRAME_WIDTH: usize = 256;
/// Height of one rendered NES frame in pixels.
pub const FRAME_HEIGHT: usize = 240;
/// Number of palette-index pixels in one rendered NES frame.
pub const FRAME_PIXELS: usize = FRAME_WIDTH * FRAME_HEIGHT;

/// Deterministic console timing selection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TimingProfile {
    Ntsc,
    Pal,
    Dendy,
}

impl TimingProfile {
    /// CPU-cycle ratio `(numerator, denominator)` for one PPU frame.
    #[must_use]
    pub const fn frame_cycle_ratio(self) -> (u64, u64) {
        match self {
            // 262 * 341 PPU dots at 3 dots per CPU cycle.
            Self::Ntsc => (89_342, 3),
            // 312 * 341 PPU dots at 3.2 dots per CPU cycle.
            Self::Pal => (531_960, 16),
            // 312 * 341 PPU dots at 3 dots per CPU cycle.
            Self::Dendy => (106_392, 3),
        }
    }

    /// CPU-cycle ratio from frame start to the vblank flag transition.
    #[must_use]
    pub const fn vblank_cycle_ratio(self) -> (u64, u64) {
        match self {
            // Scanline 241, dot 1.
            Self::Ntsc => (82_182, 3),
            // Scanline 241, dot 1 with the PAL 5/16 clock ratio.
            Self::Pal => (410_910, 16),
            // Dendy has 51 post-render scanlines; vblank starts at line 291.
            Self::Dendy => (99_232, 3),
        }
    }

    fn from_region(region: Region) -> Option<Self> {
        match region {
            Region::Ntsc => Some(Self::Ntsc),
            Region::Pal => Some(Self::Pal),
            Region::Dendy => Some(Self::Dendy),
            Region::MultiRegion => None,
        }
    }

    /// Current PPU frame, scanline, and dot at a CPU-cycle boundary.
    #[must_use]
    pub const fn ppu_position(self, cycles: u64) -> PpuPosition {
        let dots = match self {
            Self::Ntsc | Self::Dendy => cycles.saturating_mul(3),
            Self::Pal => cycles.saturating_mul(16) / 5,
        };
        let scanlines = match self {
            Self::Ntsc => 262,
            Self::Pal | Self::Dendy => 312,
        };
        let frame_dots = 341_u64 * scanlines;
        let frame_offset = dots % frame_dots;
        PpuPosition {
            frame: dots / frame_dots,
            scanline: (frame_offset / 341) as u16,
            dot: (frame_offset % 341) as u16,
        }
    }
}

/// PPU beam position derived from the selected console timing profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PpuPosition {
    pub frame: u64,
    pub scanline: u16,
    pub dot: u16,
}

/// CPU-visible and renderer-visible PPU state captured at a checkpoint.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PpuState {
    pub position: PpuPosition,
    pub ctrl: u8,
    pub mask: u8,
    pub status: u8,
    pub vram_address: u16,
    pub temporary_address: u16,
    pub fine_x: u8,
    pub write_toggle: bool,
    pub io_bus: u8,
    pub nmi_line: bool,
    pub nmi_pending: bool,
    pub fetch_address: u16,
    pub fetch_value: u8,
    pub background_pattern_shifts: [u16; 2],
    pub background_attribute_shifts: [u16; 2],
    pub background_latches: [u8; 4],
    pub secondary_oam_count: u8,
    pub sprite_evaluation: [u8; 2],
    pub oam_bus: u8,
}

/// Machine construction settings.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EmulatorConfig {
    /// Explicit timing override. Multi-region ROMs require one.
    pub timing: Option<TimingProfile>,
    /// Maximum retained observable-event count.
    pub event_capacity: usize,
    /// Optional address of the non-returning compiler trap routine.
    pub trap_address: Option<u16>,
    /// Optional RAM address containing the trap reason.
    pub trap_reason_address: Option<u16>,
}

impl Default for EmulatorConfig {
    fn default() -> Self {
        Self {
            timing: None,
            event_capacity: 65_536,
            trap_address: None,
            trap_reason_address: None,
        }
    }
}

/// Bounded run settings.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RunLimits {
    pub instruction_limit: u64,
    pub cycle_limit: u64,
}

impl Default for RunLimits {
    fn default() -> Self {
        Self {
            instruction_limit: 1_000_000,
            cycle_limit: 10_000_000,
        }
    }
}

/// Interrupt source handled by the CPU.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InterruptKind {
    Nmi,
    Irq,
    Brk,
}

/// Structured observable-event category.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EventKind {
    Instruction,
    VolatileRead,
    VolatileWrite,
    MapperWrite,
    Dma,
    Interrupt,
    VBlank,
    Frame,
    Trap,
}

/// CPU-bus access performed by the most recent instruction or interrupt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BusAccess {
    pub cycle: u64,
    pub pc: u16,
    pub physical_bank: Option<u16>,
    pub address: u16,
    pub value: u8,
    pub kind: BusAccessKind,
    pub dummy: bool,
    pub source: BusAccessSource,
}

/// Direction of one CPU-bus access.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BusAccessKind {
    Read,
    Write,
}

/// Hardware source that owns one CPU-bus clock.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BusAccessSource {
    Cpu,
    OamDma,
    DmcDma,
}

/// One deterministic execution event.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObservableEvent {
    pub cycle: u64,
    pub pc: u16,
    pub physical_bank: Option<u16>,
    pub address: Option<u16>,
    pub value: Option<u8>,
    pub kind: EventKind,
    /// Source information may be attached by a debugger or compiler mapping.
    pub source: Option<String>,
}

/// Why a bounded run stopped.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Termination {
    InstructionLimit,
    CycleLimit,
    Trap { reason: u8 },
}

/// Result of one CPU step.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StepReport {
    pub pc: u16,
    pub opcode: Option<u8>,
    pub cycles: u64,
    pub interrupt: Option<InterruptKind>,
    pub termination: Option<Termination>,
}

/// Result of advancing exactly one CPU clock while an instruction is pending.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CycleReport {
    pub cycle: u64,
    pub instruction_complete: bool,
    pub access: Option<BusAccess>,
    pub step: Option<StepReport>,
}

/// Result of a bounded machine run.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RunReport {
    pub instructions: u64,
    pub cycles: u64,
    pub frames: u64,
    pub dropped_events: u64,
    pub termination: Termination,
}

/// Comparable machine state captured at an explicit checkpoint.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MachineSnapshot {
    pub cpu: CpuState,
    pub cycles: u64,
    pub frames: u64,
    pub ram: Box<[u8; 0x800]>,
    pub prg_ram: Box<[u8; 0x2000]>,
    pub apu_io: Box<[u8; 0x18]>,
    pub apu: ApuState,
    pub chr_ram: Box<[u8; 0x2000]>,
    pub palette: Box<[u8; 32]>,
    pub oam: Box<[u8; 256]>,
    pub nametable_ram: Box<[u8; 0x1000]>,
    pub framebuffer: Box<[u8; FRAME_PIXELS]>,
    pub ppu: PpuState,
    pub mapper_state: MapperState,
}

/// Deterministic emulator failure with a bounded recent trace.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EmulatorError {
    pub message: String,
    pub pc: u16,
    pub cycle: u64,
    pub trace: Vec<ObservableEvent>,
}

impl fmt::Display for EmulatorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{} at PC ${:04X}, cycle {}",
            self.message, self.pc, self.cycle
        )?;
        for event in &self.trace {
            write!(
                formatter,
                "\n  cycle {}: {:?} pc=${:04X}",
                event.cycle, event.kind, event.pc
            )?;
            if let Some(address) = event.address {
                write!(formatter, " address=${address:04X}")?;
            }
            if let Some(value) = event.value {
                write!(formatter, " value=${value:02X}")?;
            }
        }
        Ok(())
    }
}

impl Error for EmulatorError {}

#[derive(Clone, Copy)]
struct AddressResult {
    address: u16,
    page_crossed: bool,
}

#[derive(Clone, Copy)]
enum MicroOperation {
    Read {
        address: u16,
        dummy: bool,
        semantic: bool,
    },
    Write {
        address: u16,
        value: u8,
        dummy: bool,
    },
    DmaRead {
        address: u16,
    },
    DmaWrite,
}

impl MicroOperation {
    const fn is_dummy(self) -> bool {
        match self {
            Self::Read { dummy, .. } | Self::Write { dummy, .. } => dummy,
            Self::DmaRead { .. } | Self::DmaWrite => false,
        }
    }

    const fn source(self) -> BusAccessSource {
        match self {
            Self::DmaRead { .. } | Self::DmaWrite => BusAccessSource::OamDma,
            Self::Read { .. } | Self::Write { .. } => BusAccessSource::Cpu,
        }
    }

    const fn allows_dmc_halt(self) -> bool {
        matches!(self, Self::Read { .. } | Self::DmaRead { .. })
    }
}

#[derive(Clone)]
struct PendingStep {
    report: StepReport,
    mnemonic: Option<Mnemonic>,
    initial_cpu: CpuState,
    final_cpu: CpuState,
    operations: VecDeque<MicroOperation>,
    dma_latch: u8,
    count_instruction: bool,
}

#[derive(Clone, Copy)]
struct BusAccessContext {
    cycle: u64,
    pc: u16,
    dummy: bool,
    source: BusAccessSource,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DmcDma {
    address: u16,
    clock: u8,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct ScanlineSprite {
    index: u8,
    x: u8,
    attributes: u8,
    pattern_low: u8,
    pattern_high: u8,
}

/// Public deterministic NES machine.
pub struct Machine {
    cpu: CpuState,
    cycles: u64,
    instructions: u64,
    frames: u64,
    timing: TimingProfile,
    ram: Box<[u8; 0x800]>,
    prg_ram: Box<[u8; 0x2000]>,
    apu_io: Box<[u8; 0x18]>,
    apu: Apu,
    prg_rom: Vec<u8>,
    chr_rom: Vec<u8>,
    chr_ram: Box<[u8; 0x2000]>,
    nametable_ram: Box<[u8; 0x1000]>,
    palette: Box<[u8; 32]>,
    oam: Box<[u8; 256]>,
    ppu_ctrl: u8,
    ppu_mask: u8,
    ppu_status: u8,
    oam_address: u8,
    ppu_address: u16,
    ppu_temporary_address: u16,
    ppu_fine_x: u8,
    ppu_write_toggle: bool,
    ppu_scroll_x: u8,
    ppu_scroll_y: u8,
    ppu_data_buffer: u8,
    ppu_io_bus: u8,
    ppu_nmi_line: bool,
    ppu_suppress_vblank: bool,
    ppu_fetch_address: u16,
    ppu_fetch_value: u8,
    background_next_tile: u8,
    background_next_attribute: u8,
    background_next_pattern_low: u8,
    background_next_pattern_high: u8,
    background_pattern_shift_low: u16,
    background_pattern_shift_high: u16,
    background_attribute_shift_low: u16,
    background_attribute_shift_high: u16,
    ppu_frame: u64,
    ppu_scanline: u16,
    ppu_dot: u16,
    ppu_dot_accumulator: u8,
    framebuffer: Box<[u8; FRAME_PIXELS]>,
    scanline_sprites: [ScanlineSprite; 8],
    scanline_sprite_count: u8,
    next_scanline_sprites: [ScanlineSprite; 8],
    next_scanline_sprite_count: u8,
    secondary_oam: [u8; 32],
    secondary_oam_indices: [u8; 8],
    secondary_oam_count: u8,
    sprite_evaluation_index: u8,
    sprite_evaluation_byte: u8,
    ppu_oam_bus: u8,
    controller_state: [u8; 2],
    controller_shift: [u8; 2],
    controller_strobe: bool,
    mapper: Mapper,
    mapper_state: MapperState,
    mirroring: Mirroring,
    pending_nmi: bool,
    pending_ppu_nmi: bool,
    irq_line: bool,
    stall_cycles: u64,
    events: VecDeque<ObservableEvent>,
    event_capacity: usize,
    dropped_events: u64,
    trap_address: Option<u16>,
    trap_reason_address: Option<u16>,
    last_bus_accesses: Vec<BusAccess>,
    pending_step: Option<PendingStep>,
    dmc_dma: Option<DmcDma>,
    bus_access_context: Option<BusAccessContext>,
    defer_dma: bool,
    planning: bool,
}

impl Machine {
    /// Parses a ROM and constructs a deterministic machine.
    ///
    /// # Errors
    ///
    /// Rejects malformed cartridges, unsupported mapper layouts, ambiguous
    /// timing, and zero event capacity.
    pub fn from_rom_bytes(bytes: &[u8], config: EmulatorConfig) -> Result<Self, EmulatorError> {
        let rom = nesc_rom::parse(bytes).map_err(|error| EmulatorError {
            message: error.to_string(),
            pc: 0,
            cycle: 0,
            trace: Vec::new(),
        })?;
        Self::from_rom(rom, config)
    }

    /// Constructs a deterministic machine from a validated cartridge.
    ///
    /// # Errors
    ///
    /// Rejects unsupported mapper layouts, ambiguous timing, and zero event
    /// capacity.
    pub fn from_rom(rom: Rom, config: EmulatorConfig) -> Result<Self, EmulatorError> {
        if config.event_capacity == 0 {
            return Err(construction_error(
                "event capacity must be greater than zero",
            ));
        }
        let timing = config
            .timing
            .or_else(|| TimingProfile::from_region(rom.metadata.region))
            .ok_or_else(|| {
                construction_error("multi-region ROM execution requires an explicit timing profile")
            })?;
        let mapper = Mapper::new(
            rom.metadata.mapper,
            rom.metadata.prg_rom_len,
            rom.metadata.chr_rom_len,
        )
        .map_err(|error| construction_error(error.to_string()))?;
        let apu_timing = match timing {
            TimingProfile::Ntsc => ApuTiming::Ntsc,
            TimingProfile::Pal => ApuTiming::Pal,
            TimingProfile::Dendy => ApuTiming::Dendy,
        };
        Ok(Self {
            cpu: CpuState::default(),
            cycles: 0,
            instructions: 0,
            frames: 0,
            timing,
            ram: Box::new([0; 0x800]),
            prg_ram: Box::new([0; 0x2000]),
            apu_io: Box::new([0; 0x18]),
            apu: Apu::new(apu_timing),
            prg_rom: rom.prg_rom,
            chr_rom: rom.chr_rom,
            chr_ram: Box::new([0; 0x2000]),
            nametable_ram: Box::new([0; 0x1000]),
            palette: Box::new([0; 32]),
            oam: Box::new([0; 256]),
            ppu_ctrl: 0,
            ppu_mask: 0,
            ppu_status: 0,
            oam_address: 0,
            ppu_address: 0,
            ppu_temporary_address: 0,
            ppu_fine_x: 0,
            ppu_write_toggle: false,
            ppu_scroll_x: 0,
            ppu_scroll_y: 0,
            ppu_data_buffer: 0,
            ppu_io_bus: 0,
            ppu_nmi_line: false,
            ppu_suppress_vblank: false,
            ppu_fetch_address: 0,
            ppu_fetch_value: 0,
            background_next_tile: 0,
            background_next_attribute: 0,
            background_next_pattern_low: 0,
            background_next_pattern_high: 0,
            background_pattern_shift_low: 0,
            background_pattern_shift_high: 0,
            background_attribute_shift_low: 0,
            background_attribute_shift_high: 0,
            ppu_frame: 0,
            ppu_scanline: 0,
            ppu_dot: 0,
            ppu_dot_accumulator: 0,
            framebuffer: Box::new([0; FRAME_PIXELS]),
            scanline_sprites: [ScanlineSprite::default(); 8],
            scanline_sprite_count: 0,
            next_scanline_sprites: [ScanlineSprite::default(); 8],
            next_scanline_sprite_count: 0,
            secondary_oam: [0xff; 32],
            secondary_oam_indices: [0xff; 8],
            secondary_oam_count: 0,
            sprite_evaluation_index: 0,
            sprite_evaluation_byte: 0,
            ppu_oam_bus: 0,
            controller_state: [0; 2],
            controller_shift: [0; 2],
            controller_strobe: false,
            mapper,
            mapper_state: MapperState::default(),
            mirroring: rom.metadata.mirroring,
            pending_nmi: false,
            pending_ppu_nmi: false,
            irq_line: false,
            stall_cycles: 0,
            events: VecDeque::new(),
            event_capacity: config.event_capacity,
            dropped_events: 0,
            trap_address: config.trap_address,
            trap_reason_address: config.trap_reason_address,
            last_bus_accesses: Vec::new(),
            pending_step: None,
            dmc_dma: None,
            bus_access_context: None,
            defer_dma: false,
            planning: false,
        })
    }

    /// Applies reset state and reads the reset vector.
    ///
    /// # Errors
    ///
    /// Fails when the reset vector is not mapped.
    pub fn reset(&mut self) -> Result<(), EmulatorError> {
        self.cpu = CpuState::default();
        self.mapper_state = MapperState::default();
        self.apu.reset();
        self.apu_io.fill(0);
        self.pending_nmi = false;
        self.pending_ppu_nmi = false;
        self.ppu_nmi_line = false;
        self.ppu_suppress_vblank = false;
        self.irq_line = false;
        self.pending_step = None;
        self.dmc_dma = None;
        self.bus_access_context = None;
        self.defer_dma = false;
        self.planning = false;
        self.cpu.pc = self.read_word(RESET_VECTOR)?;
        self.last_bus_accesses.clear();
        self.advance_cycles(7);
        Ok(())
    }

    /// Executes one instruction or pending interrupt.
    ///
    /// # Errors
    ///
    /// Fails on undocumented opcodes or required unmapped bus accesses.
    pub fn step(&mut self) -> Result<StepReport, EmulatorError> {
        loop {
            if let Some(report) = self.step_cycle()?.step {
                return Ok(report);
            }
        }
    }

    /// Advances exactly one CPU clock.
    ///
    /// One scheduled CPU-bus operation, including dummy accesses and DMA
    /// transfers, is performed on each clock. Architectural CPU state commits
    /// when the instruction's final clock completes.
    pub fn step_cycle(&mut self) -> Result<CycleReport, EmulatorError> {
        if self.pending_step.is_none() {
            if let Some(report) = self.prepare_step()? {
                return Ok(CycleReport {
                    cycle: self.cycles,
                    instruction_complete: true,
                    access: None,
                    step: Some(report),
                });
            }
        }
        let mut pending = self
            .pending_step
            .take()
            .ok_or_else(|| self.failure("cycle scheduler did not prepare an instruction"))?;
        if self.dmc_dma.is_none()
            && pending
                .operations
                .front()
                .is_some_and(|operation| operation.allows_dmc_halt())
        {
            self.dmc_dma = self
                .apu
                .begin_dmc_dma()
                .map(|address| DmcDma { address, clock: 0 });
        }
        if self.dmc_dma.is_some() {
            return self.perform_dmc_dma_cycle(pending);
        }
        let operation = pending.operations.pop_front().ok_or_else(|| {
            self.failure("cycle scheduler prepared an instruction without bus operations")
        })?;
        self.advance_cycles(1);
        self.bus_access_context = Some(BusAccessContext {
            cycle: self.cycles,
            pc: pending.report.pc,
            dummy: operation.is_dummy(),
            source: operation.source(),
        });
        let performed = self.perform_micro_operation(operation, &mut pending);
        self.bus_access_context = None;
        let access = performed?;
        if pending.operations.is_empty() {
            self.cpu = pending.final_cpu;
            if pending.count_instruction {
                self.instructions = self.instructions.saturating_add(1);
            }
            Ok(CycleReport {
                cycle: self.cycles,
                instruction_complete: true,
                access,
                step: Some(pending.report),
            })
        } else {
            self.pending_step = Some(pending);
            Ok(CycleReport {
                cycle: self.cycles,
                instruction_complete: false,
                access,
                step: None,
            })
        }
    }

    fn perform_dmc_dma_cycle(
        &mut self,
        mut pending: PendingStep,
    ) -> Result<CycleReport, EmulatorError> {
        let mut dma = self
            .dmc_dma
            .take()
            .ok_or_else(|| self.failure("DMC DMA clock has no active transfer"))?;
        let dummy = dma.clock < 3;
        self.advance_cycles(1);
        self.bus_access_context = Some(BusAccessContext {
            cycle: self.cycles,
            pc: pending.report.pc,
            dummy,
            source: BusAccessSource::DmcDma,
        });
        let before = self.last_bus_accesses.len();
        let address = if dummy {
            pending.report.pc
        } else {
            dma.address
        };
        let value = self.cpu_read(address);
        self.bus_access_context = None;
        let value = value?;
        if self.last_bus_accesses.len() != before + 1 {
            return Err(self.failure("one DMC DMA clock performed an invalid bus-access count"));
        }
        let access = self.last_bus_accesses.last().copied();
        pending.report.cycles = pending.report.cycles.saturating_add(1);
        if dummy {
            dma.clock += 1;
            self.dmc_dma = Some(dma);
        } else {
            self.apu.complete_dmc_dma(value);
            self.record(
                EventKind::Dma,
                Some(dma.address),
                Some(value),
                access.and_then(|access| access.physical_bank),
            );
        }
        self.pending_step = Some(pending);
        Ok(CycleReport {
            cycle: self.cycles,
            instruction_complete: false,
            access,
            step: None,
        })
    }

    fn prepare_step(&mut self) -> Result<Option<StepReport>, EmulatorError> {
        let initial_cpu = self.cpu;
        let initial_instructions = self.instructions;
        let initial_pending_nmi = self.pending_nmi;
        let initial_pending_ppu_nmi = self.pending_ppu_nmi;
        let initial_stall_cycles = self.stall_cycles;
        self.planning = true;
        self.last_bus_accesses.clear();
        let planned_report = self.begin_step();
        let final_cpu = self.cpu;
        let count_instruction = self.instructions > initial_instructions;
        let planned_stall_cycles = self.stall_cycles;
        let planned_accesses = std::mem::take(&mut self.last_bus_accesses);
        self.cpu = initial_cpu;
        self.instructions = initial_instructions;
        self.pending_nmi = initial_pending_nmi;
        self.pending_ppu_nmi = initial_pending_ppu_nmi;
        self.stall_cycles = initial_stall_cycles;
        self.planning = false;
        let mut report = planned_report?;
        if report.cycles == 0 {
            return self.begin_step().map(Some);
        }
        if planned_stall_cycles != 0 {
            let instruction_cycles = report
                .cycles
                .checked_sub(planned_stall_cycles)
                .ok_or_else(|| self.failure("DMA stall exceeds the complete step time"))?;
            let write_cycle = self.cycles.saturating_add(instruction_cycles);
            report.cycles = instruction_cycles
                .saturating_add(513)
                .saturating_add(write_cycle & 1);
        }
        let operations = build_micro_operations(report, initial_cpu, final_cpu, &planned_accesses)
            .map_err(|message| self.failure(message))?;
        if operations.len() as u64 != report.cycles {
            return Err(self.failure(format!(
                "cycle scheduler produced {} clocks for a {}-clock step",
                operations.len(),
                report.cycles
            )));
        }
        if report.interrupt == Some(InterruptKind::Nmi) {
            self.pending_nmi = false;
            self.pending_ppu_nmi = false;
        }
        self.last_bus_accesses.clear();
        self.pending_step = Some(PendingStep {
            report,
            mnemonic: report
                .opcode
                .and_then(opcode)
                .map(|instruction| instruction.mnemonic),
            initial_cpu,
            final_cpu,
            operations,
            dma_latch: 0,
            count_instruction,
        });
        Ok(None)
    }

    fn perform_micro_operation(
        &mut self,
        operation: MicroOperation,
        pending: &mut PendingStep,
    ) -> Result<Option<BusAccess>, EmulatorError> {
        let before = self.last_bus_accesses.len();
        match operation {
            MicroOperation::Read {
                address, semantic, ..
            } => {
                let value = self.cpu_read(address)?;
                if semantic {
                    apply_semantic_read(pending, value);
                }
            }
            MicroOperation::Write { address, value, .. } => {
                self.defer_dma = address == 0x4014;
                let result = self.cpu_write(address, value);
                self.defer_dma = false;
                result?;
            }
            MicroOperation::DmaRead { address } => {
                pending.dma_latch = self.cpu_read(address)?;
            }
            MicroOperation::DmaWrite => self.dma_write(pending.dma_latch),
        }
        if self.last_bus_accesses.len() != before + 1 {
            return Err(self.failure("one CPU clock performed an invalid number of bus accesses"));
        }
        let access = self.last_bus_accesses.last().copied();
        if before == 0 {
            if let Some(opcode) = pending.report.opcode {
                self.record_at(
                    EventKind::Instruction,
                    Some(pending.report.pc),
                    Some(opcode),
                    access.and_then(|access| access.physical_bank),
                    self.cycles,
                    pending.report.pc,
                );
            }
            if let Some(interrupt) = pending.report.interrupt {
                let vector = match interrupt {
                    InterruptKind::Nmi => NMI_VECTOR,
                    InterruptKind::Irq | InterruptKind::Brk => IRQ_VECTOR,
                };
                self.record_at(
                    EventKind::Interrupt,
                    Some(vector),
                    None,
                    None,
                    self.cycles,
                    pending.report.pc,
                );
            }
        }
        Ok(access)
    }

    fn begin_step(&mut self) -> Result<StepReport, EmulatorError> {
        self.last_bus_accesses.clear();
        if self.trap_address == Some(self.cpu.pc) {
            let reason = self
                .trap_reason_address
                .and_then(|address| self.peek(address).ok())
                .unwrap_or(0);
            self.record(EventKind::Trap, Some(self.cpu.pc), Some(reason), None);
            return Ok(StepReport {
                pc: self.cpu.pc,
                opcode: None,
                cycles: 0,
                interrupt: None,
                termination: Some(Termination::Trap { reason }),
            });
        }
        if self.pending_nmi || self.pending_ppu_nmi {
            self.pending_nmi = false;
            self.pending_ppu_nmi = false;
            return self.handle_external_interrupt(InterruptKind::Nmi, NMI_VECTOR);
        }
        if (self.irq_line || self.apu.irq_pending()) && !self.cpu.flag(FLAG_INTERRUPT_DISABLE) {
            return self.handle_external_interrupt(InterruptKind::Irq, IRQ_VECTOR);
        }

        let instruction_pc = self.cpu.pc;
        let opcode_byte = self.fetch()?;
        if opcode_byte == 0x02 {
            let reason = self.cpu.a;
            self.record_at(
                EventKind::Trap,
                Some(instruction_pc),
                Some(reason),
                self.physical_bank(instruction_pc),
                self.cycles,
                instruction_pc,
            );
            return Ok(StepReport {
                pc: instruction_pc,
                opcode: Some(opcode_byte),
                cycles: 0,
                interrupt: None,
                termination: Some(Termination::Trap { reason }),
            });
        }
        let instruction = opcode(opcode_byte).ok_or_else(|| {
            self.failure(format!(
                "undocumented opcode ${opcode_byte:02X} is not executable"
            ))
        })?;
        self.record_at(
            EventKind::Instruction,
            Some(instruction_pc),
            Some(opcode_byte),
            self.physical_bank(instruction_pc),
            self.cycles,
            instruction_pc,
        );
        self.stall_cycles = 0;
        let cycles = self.execute(instruction.mnemonic, instruction.mode)? + self.stall_cycles;
        self.cpu.status = (self.cpu.status & !FLAG_BREAK) | FLAG_UNUSED;
        self.instructions = self.instructions.saturating_add(1);
        Ok(StepReport {
            pc: instruction_pc,
            opcode: Some(opcode_byte),
            cycles,
            interrupt: (instruction.mnemonic == Mnemonic::Brk).then_some(InterruptKind::Brk),
            termination: None,
        })
    }

    /// Runs until a trap or a configured resource bound is reached.
    ///
    /// # Errors
    ///
    /// Rejects zero limits and propagates execution failures.
    pub fn run(&mut self, limits: RunLimits) -> Result<RunReport, EmulatorError> {
        if limits.instruction_limit == 0 || limits.cycle_limit == 0 {
            return Err(self.failure("run limits must permit instructions and cycles"));
        }
        let initial_instructions = self.instructions;
        let initial_cycles = self.cycles;
        let initial_dropped_events = self.dropped_events;
        loop {
            if self.instructions - initial_instructions >= limits.instruction_limit {
                return Ok(self.run_report(
                    initial_instructions,
                    initial_cycles,
                    initial_dropped_events,
                    Termination::InstructionLimit,
                ));
            }
            if self.cycles - initial_cycles >= limits.cycle_limit {
                return Ok(self.run_report(
                    initial_instructions,
                    initial_cycles,
                    initial_dropped_events,
                    Termination::CycleLimit,
                ));
            }
            let report = self.step()?;
            if let Some(termination) = report.termination {
                return Ok(self.run_report(
                    initial_instructions,
                    initial_cycles,
                    initial_dropped_events,
                    termination,
                ));
            }
        }
    }

    fn run_report(
        &self,
        initial_instructions: u64,
        initial_cycles: u64,
        initial_dropped_events: u64,
        termination: Termination,
    ) -> RunReport {
        RunReport {
            instructions: self.instructions - initial_instructions,
            cycles: self.cycles - initial_cycles,
            frames: self.frames,
            dropped_events: self.dropped_events - initial_dropped_events,
            termination,
        }
    }

    /// Sets the level-sensitive IRQ input.
    pub fn set_irq_line(&mut self, active: bool) {
        self.irq_line = active;
    }

    /// Queues one edge-triggered NMI.
    pub fn request_nmi(&mut self) {
        self.pending_nmi = true;
    }

    /// Supplies the current controller button mask for one port.
    pub fn set_controller(&mut self, port: usize, buttons: u8) -> Result<(), EmulatorError> {
        if port >= self.controller_state.len() {
            return Err(self.failure(format!("controller port {port} is out of range")));
        }
        self.controller_state[port] = buttons;
        if self.controller_strobe {
            self.controller_shift[port] = buttons;
        }
        Ok(())
    }

    /// Observational CPU-bus read without MMIO side effects.
    pub fn peek(&self, address: u16) -> Result<u8, EmulatorError> {
        match address {
            0x0000..=0x1fff => Ok(self.ram[usize::from(address & 0x07ff)]),
            0x2000..=0x3fff => self.peek_ppu_register(0x2000 | (address & 7)),
            0x4000..=0x4014 => Ok(self.apu_io[usize::from(address - 0x4000)]),
            0x4015 => Ok(self.apu.peek_status()),
            0x4016 | 0x4017 => {
                let port = usize::from(address - 0x4016);
                Ok((self.controller_shift[port] & 1) | 0x40)
            }
            0x4018..=0x5fff => Ok(0),
            0x6000..=0x7fff => Ok(self.prg_ram[usize::from(address - 0x6000)]),
            0x8000..=0xffff => self
                .mapper
                .map_cpu(CpuAddress(address), self.mapper_state)
                .and_then(|offset| self.prg_rom.get(offset.0).copied())
                .ok_or_else(|| self.failure(format!("unmapped PRG read ${address:04X}"))),
        }
    }

    /// Returns the physical 16 KiB PRG bank currently mapped at an address.
    ///
    /// This is observational and does not change mapper or MMIO state.
    #[must_use]
    pub fn mapped_prg_bank(&self, address: u16) -> Option<u16> {
        self.physical_bank(address)
    }

    /// CPU-bus accesses performed by the most recent instruction or interrupt.
    #[must_use]
    pub fn last_bus_accesses(&self) -> &[BusAccess] {
        &self.last_bus_accesses
    }

    #[must_use]
    pub const fn cpu(&self) -> &CpuState {
        &self.cpu
    }

    pub fn cpu_mut(&mut self) -> &mut CpuState {
        &mut self.cpu
    }

    #[must_use]
    pub const fn cycles(&self) -> u64 {
        self.cycles
    }

    #[cfg(test)]
    pub(crate) fn set_cycles_for_test(&mut self, cycles: u64) {
        self.cycles = cycles;
        let position = self.timing.ppu_position(cycles);
        self.frames = position.frame;
        self.ppu_frame = position.frame;
        self.ppu_scanline = position.scanline;
        self.ppu_dot = position.dot;
        self.ppu_dot_accumulator = match self.timing {
            TimingProfile::Ntsc | TimingProfile::Dendy => 0,
            TimingProfile::Pal => ((cycles.saturating_mul(16)) % 5) as u8,
        };
    }

    #[must_use]
    pub const fn instructions(&self) -> u64 {
        self.instructions
    }

    #[must_use]
    pub const fn frames(&self) -> u64 {
        self.frames
    }

    /// Selected deterministic timing profile.
    #[must_use]
    pub const fn timing_profile(&self) -> TimingProfile {
        self.timing
    }

    /// Current PPU beam position.
    #[must_use]
    pub const fn ppu_position(&self) -> PpuPosition {
        PpuPosition {
            frame: self.ppu_frame,
            scanline: self.ppu_scanline,
            dot: self.ppu_dot,
        }
    }

    /// Current CPU-visible and renderer-visible PPU state.
    #[must_use]
    pub const fn ppu_state(&self) -> PpuState {
        PpuState {
            position: self.ppu_position(),
            ctrl: self.ppu_ctrl,
            mask: self.ppu_mask,
            status: self.ppu_status,
            vram_address: self.ppu_address,
            temporary_address: self.ppu_temporary_address,
            fine_x: self.ppu_fine_x,
            write_toggle: self.ppu_write_toggle,
            io_bus: self.ppu_io_bus,
            nmi_line: self.ppu_nmi_line,
            nmi_pending: self.pending_ppu_nmi,
            fetch_address: self.ppu_fetch_address,
            fetch_value: self.ppu_fetch_value,
            background_pattern_shifts: [
                self.background_pattern_shift_low,
                self.background_pattern_shift_high,
            ],
            background_attribute_shifts: [
                self.background_attribute_shift_low,
                self.background_attribute_shift_high,
            ],
            background_latches: [
                self.background_next_tile,
                self.background_next_attribute,
                self.background_next_pattern_low,
                self.background_next_pattern_high,
            ],
            secondary_oam_count: self.secondary_oam_count,
            sprite_evaluation: [self.sprite_evaluation_index, self.sprite_evaluation_byte],
            oam_bus: self.ppu_oam_bus,
        }
    }

    /// Whether a cycle-stepped instruction or interrupt remains in progress.
    #[must_use]
    pub const fn instruction_pending(&self) -> bool {
        self.pending_step.is_some()
    }

    #[must_use]
    pub fn ram(&self) -> &[u8; 0x800] {
        &self.ram
    }

    pub fn ram_mut(&mut self) -> &mut [u8; 0x800] {
        &mut self.ram
    }

    #[must_use]
    pub fn prg_ram(&self) -> &[u8; 0x2000] {
        &self.prg_ram
    }

    pub fn prg_ram_mut(&mut self) -> &mut [u8; 0x2000] {
        &mut self.prg_ram
    }

    #[must_use]
    pub fn palette(&self) -> &[u8; 32] {
        &self.palette
    }

    #[must_use]
    pub fn oam(&self) -> &[u8; 256] {
        &self.oam
    }

    #[must_use]
    pub fn nametable_ram(&self) -> &[u8; 0x1000] {
        &self.nametable_ram
    }

    /// Palette-index pixels for the most recently drawn frame contents.
    #[must_use]
    pub fn framebuffer(&self) -> &[u8; FRAME_PIXELS] {
        &self.framebuffer
    }

    /// Stable checksum of the palette-index framebuffer for compact reports.
    #[must_use]
    pub fn framebuffer_checksum(&self) -> u64 {
        self.framebuffer
            .iter()
            .enumerate()
            .fold(0_u64, |checksum, (index, pixel)| {
                checksum.wrapping_add((index as u64 + 1).wrapping_mul(u64::from(*pixel)))
            })
    }

    #[must_use]
    pub fn apu_io(&self) -> &[u8; 0x18] {
        &self.apu_io
    }

    /// Current non-DMC channel, frame-counter, IRQ, and output state.
    #[must_use]
    pub fn apu_state(&self) -> ApuState {
        self.apu.state()
    }

    #[must_use]
    pub fn chr_ram(&self) -> &[u8; 0x2000] {
        &self.chr_ram
    }

    #[must_use]
    pub fn events(&self) -> &VecDeque<ObservableEvent> {
        &self.events
    }

    #[must_use]
    pub const fn dropped_events(&self) -> u64 {
        self.dropped_events
    }

    #[must_use]
    pub const fn mapper_state(&self) -> MapperState {
        self.mapper_state
    }

    pub fn set_mapper_state(&mut self, state: MapperState) {
        self.mapper_state = state;
    }

    pub fn clear_events(&mut self) {
        self.events.clear();
        self.dropped_events = 0;
    }

    /// Captures all state designated by the emulator comparison contract.
    #[must_use]
    pub fn snapshot(&self) -> MachineSnapshot {
        MachineSnapshot {
            cpu: self.cpu,
            cycles: self.cycles,
            frames: self.frames,
            ram: self.ram.clone(),
            prg_ram: self.prg_ram.clone(),
            apu_io: self.apu_io.clone(),
            apu: self.apu.state(),
            chr_ram: self.chr_ram.clone(),
            palette: self.palette.clone(),
            oam: self.oam.clone(),
            nametable_ram: self.nametable_ram.clone(),
            framebuffer: self.framebuffer.clone(),
            ppu: self.ppu_state(),
            mapper_state: self.mapper_state,
        }
    }

    fn handle_external_interrupt(
        &mut self,
        kind: InterruptKind,
        vector: u16,
    ) -> Result<StepReport, EmulatorError> {
        let pc = self.cpu.pc;
        self.push((pc >> 8) as u8)?;
        self.push(pc as u8)?;
        self.push((self.cpu.status & !FLAG_BREAK) | FLAG_UNUSED)?;
        self.cpu.set_flag(FLAG_INTERRUPT_DISABLE, true);
        self.cpu.pc = self.read_word(vector)?;
        self.record_at(
            EventKind::Interrupt,
            Some(vector),
            None,
            None,
            self.cycles,
            pc,
        );
        Ok(StepReport {
            pc,
            opcode: None,
            cycles: 7,
            interrupt: Some(kind),
            termination: None,
        })
    }

    #[allow(clippy::too_many_lines)]
    fn execute(&mut self, mnemonic: Mnemonic, mode: AddressingMode) -> Result<u64, EmulatorError> {
        match mnemonic {
            Mnemonic::Adc => {
                let (value, crossed) = self.read_operand(mode)?;
                self.adc(value);
                Ok(read_cycles(mode, crossed))
            }
            Mnemonic::And => {
                let (value, crossed) = self.read_operand(mode)?;
                self.cpu.a &= value;
                self.cpu.set_negative_zero(self.cpu.a);
                Ok(read_cycles(mode, crossed))
            }
            Mnemonic::Asl => self.shift(mode, Shift::Asl),
            Mnemonic::Bcc => self.branch(!self.cpu.flag(FLAG_CARRY)),
            Mnemonic::Bcs => self.branch(self.cpu.flag(FLAG_CARRY)),
            Mnemonic::Beq => self.branch(self.cpu.flag(FLAG_ZERO)),
            Mnemonic::Bit => {
                let (value, _) = self.read_operand(mode)?;
                self.cpu.set_flag(FLAG_ZERO, self.cpu.a & value == 0);
                self.cpu.set_flag(FLAG_NEGATIVE, value & FLAG_NEGATIVE != 0);
                self.cpu.set_flag(FLAG_OVERFLOW, value & FLAG_OVERFLOW != 0);
                Ok(if mode == AddressingMode::ZeroPage {
                    3
                } else {
                    4
                })
            }
            Mnemonic::Bmi => self.branch(self.cpu.flag(FLAG_NEGATIVE)),
            Mnemonic::Bne => self.branch(!self.cpu.flag(FLAG_ZERO)),
            Mnemonic::Bpl => self.branch(!self.cpu.flag(FLAG_NEGATIVE)),
            Mnemonic::Brk => {
                self.cpu.pc = self.cpu.pc.wrapping_add(1);
                let pc = self.cpu.pc;
                self.push((pc >> 8) as u8)?;
                self.push(pc as u8)?;
                self.push(self.cpu.status | FLAG_BREAK | FLAG_UNUSED)?;
                self.cpu.set_flag(FLAG_INTERRUPT_DISABLE, true);
                self.cpu.pc = self.read_word(IRQ_VECTOR)?;
                self.record(EventKind::Interrupt, Some(IRQ_VECTOR), None, None);
                Ok(7)
            }
            Mnemonic::Bvc => self.branch(!self.cpu.flag(FLAG_OVERFLOW)),
            Mnemonic::Bvs => self.branch(self.cpu.flag(FLAG_OVERFLOW)),
            Mnemonic::Clc => self.implied_flag(FLAG_CARRY, false),
            Mnemonic::Cld => self.implied_flag(FLAG_DECIMAL, false),
            Mnemonic::Cli => self.implied_flag(FLAG_INTERRUPT_DISABLE, false),
            Mnemonic::Clv => self.implied_flag(FLAG_OVERFLOW, false),
            Mnemonic::Cmp => {
                let (value, crossed) = self.read_operand(mode)?;
                self.compare(self.cpu.a, value);
                Ok(read_cycles(mode, crossed))
            }
            Mnemonic::Cpx => {
                let (value, _) = self.read_operand(mode)?;
                self.compare(self.cpu.x, value);
                Ok(compare_index_cycles(mode))
            }
            Mnemonic::Cpy => {
                let (value, _) = self.read_operand(mode)?;
                self.compare(self.cpu.y, value);
                Ok(compare_index_cycles(mode))
            }
            Mnemonic::Dec => self.adjust_memory(mode, false),
            Mnemonic::Dex => {
                self.cpu.x = self.cpu.x.wrapping_sub(1);
                self.cpu.set_negative_zero(self.cpu.x);
                Ok(2)
            }
            Mnemonic::Dey => {
                self.cpu.y = self.cpu.y.wrapping_sub(1);
                self.cpu.set_negative_zero(self.cpu.y);
                Ok(2)
            }
            Mnemonic::Eor => {
                let (value, crossed) = self.read_operand(mode)?;
                self.cpu.a ^= value;
                self.cpu.set_negative_zero(self.cpu.a);
                Ok(read_cycles(mode, crossed))
            }
            Mnemonic::Inc => self.adjust_memory(mode, true),
            Mnemonic::Inx => {
                self.cpu.x = self.cpu.x.wrapping_add(1);
                self.cpu.set_negative_zero(self.cpu.x);
                Ok(2)
            }
            Mnemonic::Iny => {
                self.cpu.y = self.cpu.y.wrapping_add(1);
                self.cpu.set_negative_zero(self.cpu.y);
                Ok(2)
            }
            Mnemonic::Jmp if mode == AddressingMode::Indirect => {
                let pointer = self.fetch_word()?;
                let low = self.cpu_read(pointer)?;
                let high_address = (pointer & 0xff00) | (pointer.wrapping_add(1) & 0x00ff);
                let high = self.cpu_read(high_address)?;
                self.cpu.pc = u16::from_le_bytes([low, high]);
                Ok(5)
            }
            Mnemonic::Jmp => {
                self.cpu.pc = self.fetch_word()?;
                Ok(3)
            }
            Mnemonic::Jsr => {
                let target = self.fetch_word()?;
                let return_address = self.cpu.pc.wrapping_sub(1);
                self.push((return_address >> 8) as u8)?;
                self.push(return_address as u8)?;
                self.cpu.pc = target;
                Ok(6)
            }
            Mnemonic::Lda => {
                let (value, crossed) = self.read_operand(mode)?;
                self.cpu.a = value;
                self.cpu.set_negative_zero(value);
                Ok(read_cycles(mode, crossed))
            }
            Mnemonic::Ldx => {
                let (value, crossed) = self.read_operand(mode)?;
                self.cpu.x = value;
                self.cpu.set_negative_zero(value);
                Ok(index_load_cycles(mode, crossed))
            }
            Mnemonic::Ldy => {
                let (value, crossed) = self.read_operand(mode)?;
                self.cpu.y = value;
                self.cpu.set_negative_zero(value);
                Ok(index_load_cycles(mode, crossed))
            }
            Mnemonic::Lsr => self.shift(mode, Shift::Lsr),
            Mnemonic::Nop => Ok(2),
            Mnemonic::Ora => {
                let (value, crossed) = self.read_operand(mode)?;
                self.cpu.a |= value;
                self.cpu.set_negative_zero(self.cpu.a);
                Ok(read_cycles(mode, crossed))
            }
            Mnemonic::Pha => {
                self.push(self.cpu.a)?;
                Ok(3)
            }
            Mnemonic::Php => {
                self.push(self.cpu.status | FLAG_BREAK | FLAG_UNUSED)?;
                Ok(3)
            }
            Mnemonic::Pla => {
                self.cpu.a = self.pop()?;
                self.cpu.set_negative_zero(self.cpu.a);
                Ok(4)
            }
            Mnemonic::Plp => {
                self.cpu.status = (self.pop()? & !FLAG_BREAK) | FLAG_UNUSED;
                Ok(4)
            }
            Mnemonic::Rol => self.shift(mode, Shift::Rol),
            Mnemonic::Ror => self.shift(mode, Shift::Ror),
            Mnemonic::Rti => {
                self.cpu.status = (self.pop()? & !FLAG_BREAK) | FLAG_UNUSED;
                let low = self.pop()?;
                let high = self.pop()?;
                self.cpu.pc = u16::from_le_bytes([low, high]);
                Ok(6)
            }
            Mnemonic::Rts => {
                let low = self.pop()?;
                let high = self.pop()?;
                self.cpu.pc = u16::from_le_bytes([low, high]).wrapping_add(1);
                Ok(6)
            }
            Mnemonic::Sbc => {
                let (value, crossed) = self.read_operand(mode)?;
                self.sbc(value);
                Ok(read_cycles(mode, crossed))
            }
            Mnemonic::Sec => self.implied_flag(FLAG_CARRY, true),
            Mnemonic::Sed => self.implied_flag(FLAG_DECIMAL, true),
            Mnemonic::Sei => self.implied_flag(FLAG_INTERRUPT_DISABLE, true),
            Mnemonic::Sta => {
                let address = self.operand_address(mode)?;
                self.cpu_write(address.address, self.cpu.a)?;
                Ok(store_cycles(mode))
            }
            Mnemonic::Stx => {
                let address = self.operand_address(mode)?;
                self.cpu_write(address.address, self.cpu.x)?;
                Ok(index_store_cycles(mode))
            }
            Mnemonic::Sty => {
                let address = self.operand_address(mode)?;
                self.cpu_write(address.address, self.cpu.y)?;
                Ok(index_store_cycles(mode))
            }
            Mnemonic::Tax => self.transfer(self.cpu.a, Register::X),
            Mnemonic::Tay => self.transfer(self.cpu.a, Register::Y),
            Mnemonic::Tsx => self.transfer(self.cpu.sp, Register::X),
            Mnemonic::Txa => self.transfer(self.cpu.x, Register::A),
            Mnemonic::Txs => {
                self.cpu.sp = self.cpu.x;
                Ok(2)
            }
            Mnemonic::Tya => self.transfer(self.cpu.y, Register::A),
        }
    }

    fn implied_flag(&mut self, flag: u8, value: bool) -> Result<u64, EmulatorError> {
        self.cpu.set_flag(flag, value);
        Ok(2)
    }

    fn transfer(&mut self, value: u8, destination: Register) -> Result<u64, EmulatorError> {
        match destination {
            Register::A => self.cpu.a = value,
            Register::X => self.cpu.x = value,
            Register::Y => self.cpu.y = value,
        }
        self.cpu.set_negative_zero(value);
        Ok(2)
    }

    fn branch(&mut self, taken: bool) -> Result<u64, EmulatorError> {
        let displacement = self.fetch()? as i8;
        if !taken {
            return Ok(2);
        }
        let before = self.cpu.pc;
        self.cpu.pc = self.cpu.pc.wrapping_add_signed(i16::from(displacement));
        Ok(3 + u64::from((before & 0xff00) != (self.cpu.pc & 0xff00)))
    }

    fn shift(&mut self, mode: AddressingMode, operation: Shift) -> Result<u64, EmulatorError> {
        if mode == AddressingMode::Accumulator {
            self.cpu.a = self.shift_value(self.cpu.a, operation);
            return Ok(2);
        }
        let address = self.operand_address(mode)?.address;
        let value = self.cpu_read(address)?;
        let output = self.shift_value(value, operation);
        self.cpu_write(address, output)?;
        Ok(modify_cycles(mode))
    }

    fn shift_value(&mut self, value: u8, operation: Shift) -> u8 {
        let carry_in = u8::from(self.cpu.flag(FLAG_CARRY));
        let output = match operation {
            Shift::Asl => {
                self.cpu.set_flag(FLAG_CARRY, value & 0x80 != 0);
                value << 1
            }
            Shift::Lsr => {
                self.cpu.set_flag(FLAG_CARRY, value & 1 != 0);
                value >> 1
            }
            Shift::Rol => {
                self.cpu.set_flag(FLAG_CARRY, value & 0x80 != 0);
                (value << 1) | carry_in
            }
            Shift::Ror => {
                self.cpu.set_flag(FLAG_CARRY, value & 1 != 0);
                (value >> 1) | (carry_in << 7)
            }
        };
        self.cpu.set_negative_zero(output);
        output
    }

    fn adjust_memory(
        &mut self,
        mode: AddressingMode,
        increment: bool,
    ) -> Result<u64, EmulatorError> {
        let address = self.operand_address(mode)?.address;
        let value = self.cpu_read(address)?;
        let output = if increment {
            value.wrapping_add(1)
        } else {
            value.wrapping_sub(1)
        };
        self.cpu_write(address, output)?;
        self.cpu.set_negative_zero(output);
        Ok(modify_cycles(mode))
    }

    fn read_operand(&mut self, mode: AddressingMode) -> Result<(u8, bool), EmulatorError> {
        if mode == AddressingMode::Immediate {
            return Ok((self.fetch()?, false));
        }
        if mode == AddressingMode::Accumulator {
            return Ok((self.cpu.a, false));
        }
        let address = self.operand_address(mode)?;
        Ok((self.cpu_read(address.address)?, address.page_crossed))
    }

    fn operand_address(&mut self, mode: AddressingMode) -> Result<AddressResult, EmulatorError> {
        let result = match mode {
            AddressingMode::ZeroPage => AddressResult {
                address: u16::from(self.fetch()?),
                page_crossed: false,
            },
            AddressingMode::ZeroPageX => AddressResult {
                address: u16::from(self.fetch()?.wrapping_add(self.cpu.x)),
                page_crossed: false,
            },
            AddressingMode::ZeroPageY => AddressResult {
                address: u16::from(self.fetch()?.wrapping_add(self.cpu.y)),
                page_crossed: false,
            },
            AddressingMode::Absolute => AddressResult {
                address: self.fetch_word()?,
                page_crossed: false,
            },
            AddressingMode::AbsoluteX | AddressingMode::AbsoluteY => {
                let base = self.fetch_word()?;
                let index = if mode == AddressingMode::AbsoluteX {
                    self.cpu.x
                } else {
                    self.cpu.y
                };
                let address = base.wrapping_add(u16::from(index));
                AddressResult {
                    address,
                    page_crossed: (base & 0xff00) != (address & 0xff00),
                }
            }
            AddressingMode::IndexedIndirect => {
                let pointer = self.fetch()?.wrapping_add(self.cpu.x);
                AddressResult {
                    address: self.read_word_zero_page(pointer)?,
                    page_crossed: false,
                }
            }
            AddressingMode::IndirectIndexed => {
                let pointer = self.fetch()?;
                let base = self.read_word_zero_page(pointer)?;
                let address = base.wrapping_add(u16::from(self.cpu.y));
                AddressResult {
                    address,
                    page_crossed: (base & 0xff00) != (address & 0xff00),
                }
            }
            _ => {
                return Err(self.failure(format!(
                    "addressing mode {mode:?} does not resolve a data address"
                )));
            }
        };
        Ok(result)
    }

    fn fetch(&mut self) -> Result<u8, EmulatorError> {
        let value = self.cpu_read(self.cpu.pc)?;
        self.cpu.pc = self.cpu.pc.wrapping_add(1);
        Ok(value)
    }

    fn fetch_word(&mut self) -> Result<u16, EmulatorError> {
        let low = self.fetch()?;
        let high = self.fetch()?;
        Ok(u16::from_le_bytes([low, high]))
    }

    fn read_word(&mut self, address: u16) -> Result<u16, EmulatorError> {
        let low = self.cpu_read(address)?;
        let high = self.cpu_read(address.wrapping_add(1))?;
        Ok(u16::from_le_bytes([low, high]))
    }

    fn read_word_zero_page(&mut self, address: u8) -> Result<u16, EmulatorError> {
        let low = self.cpu_read(u16::from(address))?;
        let high = self.cpu_read(u16::from(address.wrapping_add(1)))?;
        Ok(u16::from_le_bytes([low, high]))
    }

    fn cpu_read(&mut self, address: u16) -> Result<u8, EmulatorError> {
        let physical_bank = self.physical_bank(address);
        let value = if self.planning {
            self.planning_read(address)?
        } else {
            match address {
                0x0000..=0x1fff => self.ram[usize::from(address & 0x07ff)],
                0x2000..=0x3fff => self.read_ppu_register(0x2000 | (address & 7))?,
                0x4000..=0x4014 => self.apu_io[usize::from(address - 0x4000)],
                0x4015 => self.apu.read_status(),
                0x4016 | 0x4017 => self.read_controller(usize::from(address - 0x4016)),
                0x4018..=0x5fff => 0,
                0x6000..=0x7fff => self.prg_ram[usize::from(address - 0x6000)],
                0x8000..=0xffff => self
                    .mapper
                    .map_cpu(CpuAddress(address), self.mapper_state)
                    .and_then(|offset| self.prg_rom.get(offset.0).copied())
                    .ok_or_else(|| self.failure(format!("unmapped PRG read ${address:04X}")))?,
            }
        };
        if !self.planning && (0x2000..=0x4017).contains(&address) {
            self.record(EventKind::VolatileRead, Some(address), Some(value), None);
        }
        self.record_bus_access(address, value, BusAccessKind::Read, physical_bank);
        Ok(value)
    }

    fn cpu_write(&mut self, address: u16, value: u8) -> Result<(), EmulatorError> {
        let physical_bank = self.physical_bank(address);
        self.record_bus_access(address, value, BusAccessKind::Write, physical_bank);
        if self.planning {
            if address == 0x4014 {
                self.oam_dma(value)?;
            }
            return Ok(());
        }
        match address {
            0x0000..=0x1fff => self.ram[usize::from(address & 0x07ff)] = value,
            0x2000..=0x3fff => self.write_ppu_register(0x2000 | (address & 7), value)?,
            0x4000..=0x4013 | 0x4015 | 0x4017 => {
                self.apu_io[usize::from(address - 0x4000)] = value;
                self.apu.write_register(address, value);
            }
            0x4014 if self.defer_dma => {
                self.record(EventKind::Dma, Some(0x4014), Some(value), None);
            }
            0x4014 => self.oam_dma(value)?,
            0x4016 => self.write_controller_strobe(value),
            0x4018..=0x5fff => {}
            0x6000..=0x7fff => self.prg_ram[usize::from(address - 0x6000)] = value,
            0x8000..=0xffff => {
                self.mapper
                    .cpu_write(CpuAddress(address), value, &mut self.mapper_state);
                self.record(
                    EventKind::MapperWrite,
                    Some(address),
                    Some(value),
                    physical_bank,
                );
                return Ok(());
            }
        }
        if (0x2000..=0x4017).contains(&address) {
            self.record(EventKind::VolatileWrite, Some(address), Some(value), None);
        }
        Ok(())
    }

    fn planning_read(&self, address: u16) -> Result<u8, EmulatorError> {
        if (0x2000..=0x3fff).contains(&address) && (address & 7) == 7 {
            let ppu_address = self.ppu_address & 0x3fff;
            return if ppu_address >= 0x3f00 {
                self.peek_ppu(ppu_address)
            } else {
                Ok(self.ppu_data_buffer)
            };
        }
        self.peek(address)
    }

    fn record_bus_access(
        &mut self,
        address: u16,
        value: u8,
        kind: BusAccessKind,
        physical_bank: Option<u16>,
    ) {
        let context = self.bus_access_context.unwrap_or(BusAccessContext {
            cycle: self.cycles,
            pc: self.cpu.pc,
            dummy: false,
            source: BusAccessSource::Cpu,
        });
        self.last_bus_accesses.push(BusAccess {
            cycle: context.cycle,
            pc: context.pc,
            physical_bank,
            address,
            value,
            kind,
            dummy: context.dummy,
            source: context.source,
        });
    }

    fn dma_write(&mut self, value: u8) {
        self.record_bus_access(0x2004, value, BusAccessKind::Write, None);
        self.ppu_io_bus = value;
        self.write_oam_data(value);
    }

    fn read_ppu_register(&mut self, register: u16) -> Result<u8, EmulatorError> {
        let output = match register {
            0x2002 => {
                let value = (self.ppu_status & 0xe0) | (self.ppu_io_bus & 0x1f);
                let at_vblank_boundary =
                    self.ppu_scanline == self.vblank_scanline() && self.ppu_dot <= 2;
                if at_vblank_boundary && self.ppu_dot == 0 {
                    self.ppu_suppress_vblank = true;
                }
                self.ppu_status &= !0x80;
                self.ppu_write_toggle = false;
                if at_vblank_boundary {
                    self.pending_ppu_nmi = false;
                }
                self.update_ppu_nmi_line();
                value
            }
            0x2004 => self.read_oam_data(),
            0x2007 => {
                let address = self.ppu_address;
                let value = self.peek_ppu(address)?;
                let output = if address & 0x3fff >= 0x3f00 {
                    self.ppu_data_buffer = self.peek_ppu(address.wrapping_sub(0x1000))?;
                    (value & 0x3f) | (self.ppu_io_bus & 0xc0)
                } else {
                    let buffered = self.ppu_data_buffer;
                    self.ppu_data_buffer = value;
                    buffered
                };
                self.increment_ppu_address();
                output
            }
            _ => self.ppu_io_bus,
        };
        self.ppu_io_bus = output;
        Ok(output)
    }

    fn write_ppu_register(&mut self, register: u16, value: u8) -> Result<(), EmulatorError> {
        self.ppu_io_bus = value;
        match register {
            0x2000 => {
                self.ppu_ctrl = value;
                self.ppu_temporary_address =
                    (self.ppu_temporary_address & 0x73ff) | (u16::from(value & 0x03) << 10);
                self.update_ppu_nmi_line();
            }
            0x2001 => self.ppu_mask = value,
            0x2003 => self.oam_address = value,
            0x2004 => self.write_oam_data(value),
            0x2005 if !self.ppu_write_toggle => {
                self.ppu_scroll_x = value;
                self.ppu_temporary_address =
                    (self.ppu_temporary_address & !0x001f) | u16::from(value >> 3);
                self.ppu_fine_x = value & 0x07;
                self.ppu_write_toggle = true;
            }
            0x2005 => {
                self.ppu_scroll_y = value;
                self.ppu_temporary_address = (self.ppu_temporary_address & !0x73e0)
                    | (u16::from(value & 0x07) << 12)
                    | (u16::from(value & 0xf8) << 2);
                self.ppu_write_toggle = false;
            }
            0x2006 => {
                if !self.ppu_write_toggle {
                    self.ppu_temporary_address =
                        (self.ppu_temporary_address & 0x00ff) | (u16::from(value & 0x3f) << 8);
                    self.ppu_write_toggle = true;
                } else {
                    self.ppu_temporary_address =
                        (self.ppu_temporary_address & 0x7f00) | u16::from(value);
                    self.ppu_address = self.ppu_temporary_address;
                    self.ppu_write_toggle = false;
                }
            }
            0x2007 => {
                self.write_ppu(self.ppu_address, value)?;
                self.increment_ppu_address();
            }
            _ => {}
        }
        Ok(())
    }

    fn peek_ppu_register(&self, register: u16) -> Result<u8, EmulatorError> {
        match register {
            0x2002 => Ok((self.ppu_status & 0xe0) | (self.ppu_io_bus & 0x1f)),
            0x2004 => Ok(self.peek_oam_data()),
            0x2007 => {
                let address = self.ppu_address & 0x3fff;
                if address >= 0x3f00 {
                    self.peek_ppu(address)
                        .map(|value| (value & 0x3f) | (self.ppu_io_bus & 0xc0))
                } else {
                    Ok(self.ppu_data_buffer)
                }
            }
            _ => Ok(self.ppu_io_bus),
        }
    }

    fn read_oam_data(&self) -> u8 {
        self.peek_oam_data()
    }

    fn peek_oam_data(&self) -> u8 {
        if self.oam_rendering_active() {
            self.ppu_oam_bus
        } else {
            self.oam[usize::from(self.oam_address)]
        }
    }

    fn write_oam_data(&mut self, value: u8) {
        if self.oam_rendering_active() {
            self.oam_address = self.oam_address.wrapping_add(4);
        } else {
            self.oam[usize::from(self.oam_address)] = value;
            self.oam_address = self.oam_address.wrapping_add(1);
        }
    }

    fn oam_rendering_active(&self) -> bool {
        self.rendering_enabled()
            && (self.ppu_scanline < FRAME_HEIGHT as u16
                || self.ppu_scanline == self.pre_render_scanline())
            && (1..=320).contains(&self.ppu_dot)
    }

    fn increment_ppu_address(&mut self) {
        let increment = if self.ppu_ctrl & 0x04 == 0 { 1 } else { 32 };
        self.ppu_address = self.ppu_address.wrapping_add(increment) & 0x3fff;
    }

    fn peek_ppu(&self, address: u16) -> Result<u8, EmulatorError> {
        let address = address & 0x3fff;
        match address {
            0x0000..=0x1fff if self.chr_rom.is_empty() => Ok(self.chr_ram[usize::from(address)]),
            0x0000..=0x1fff => self
                .mapper
                .map_ppu(PpuAddress(address), self.mapper_state)
                .and_then(|offset| self.chr_rom.get(offset.0).copied())
                .ok_or_else(|| self.failure(format!("unmapped CHR read ${address:04X}"))),
            0x2000..=0x3eff => Ok(self.nametable_ram[self.nametable_index(address)]),
            0x3f00..=0x3fff => Ok(self.palette[palette_index(address)]),
            _ => unreachable!(),
        }
    }

    fn write_ppu(&mut self, address: u16, value: u8) -> Result<(), EmulatorError> {
        let address = address & 0x3fff;
        match address {
            0x0000..=0x1fff if self.chr_rom.is_empty() => {
                self.chr_ram[usize::from(address)] = value;
            }
            0x0000..=0x1fff => {}
            0x2000..=0x3eff => {
                let index = self.nametable_index(address);
                self.nametable_ram[index] = value;
            }
            0x3f00..=0x3fff => self.palette[palette_index(address)] = value,
            _ => unreachable!(),
        }
        Ok(())
    }

    fn nametable_index(&self, address: u16) -> usize {
        let offset = usize::from((address - 0x2000) & 0x0fff);
        let table = offset / 0x400;
        let inner = offset & 0x3ff;
        let physical = match self.mirroring {
            Mirroring::Horizontal => [0, 0, 1, 1][table],
            Mirroring::Vertical => [0, 1, 0, 1][table],
            Mirroring::FourScreen => table,
        };
        physical * 0x400 + inner
    }

    fn read_controller(&mut self, port: usize) -> u8 {
        if self.controller_strobe {
            self.controller_shift[port] = self.controller_state[port];
        }
        let value = self.controller_shift[port] & 1;
        if !self.controller_strobe {
            self.controller_shift[port] = (self.controller_shift[port] >> 1) | 0x80;
        }
        value | 0x40
    }

    fn write_controller_strobe(&mut self, value: u8) {
        let strobe = value & 1 != 0;
        if self.controller_strobe || strobe {
            self.controller_shift = self.controller_state;
        }
        self.controller_strobe = strobe;
    }

    fn oam_dma(&mut self, page: u8) -> Result<(), EmulatorError> {
        let base = u16::from(page) << 8;
        for offset in 0..=u8::MAX {
            let value = self.cpu_read(base | u16::from(offset))?;
            if !self.planning {
                let index = self.oam_address.wrapping_add(offset);
                self.oam[usize::from(index)] = value;
            }
        }
        let dma_cycles = 513 + (self.cycles & 1);
        self.stall_cycles = self.stall_cycles.saturating_add(dma_cycles);
        self.record(EventKind::Dma, Some(0x4014), Some(page), None);
        Ok(())
    }

    fn push(&mut self, value: u8) -> Result<(), EmulatorError> {
        self.cpu_write(STACK_BASE | u16::from(self.cpu.sp), value)?;
        self.cpu.sp = self.cpu.sp.wrapping_sub(1);
        Ok(())
    }

    fn pop(&mut self) -> Result<u8, EmulatorError> {
        self.cpu.sp = self.cpu.sp.wrapping_add(1);
        self.cpu_read(STACK_BASE | u16::from(self.cpu.sp))
    }

    fn adc(&mut self, value: u8) {
        let carry = u16::from(self.cpu.flag(FLAG_CARRY));
        let sum = u16::from(self.cpu.a) + u16::from(value) + carry;
        let output = sum as u8;
        let overflow = (!(self.cpu.a ^ value) & (self.cpu.a ^ output) & 0x80) != 0;
        self.cpu.set_flag(FLAG_CARRY, sum > 0xff);
        self.cpu.set_flag(FLAG_OVERFLOW, overflow);
        self.cpu.a = output;
        self.cpu.set_negative_zero(output);
    }

    fn sbc(&mut self, value: u8) {
        self.adc(!value);
    }

    fn compare(&mut self, left: u8, right: u8) {
        self.cpu.set_flag(FLAG_CARRY, left >= right);
        self.cpu.set_negative_zero(left.wrapping_sub(right));
    }

    fn advance_cycles(&mut self, cycles: u64) {
        let (dots_per_cycle, denominator) = match self.timing {
            TimingProfile::Ntsc | TimingProfile::Dendy => (3_u8, 1_u8),
            TimingProfile::Pal => (16, 5),
        };
        for _ in 0..cycles {
            self.cycles = self.cycles.saturating_add(1);
            self.apu.clock();
            self.ppu_dot_accumulator = self.ppu_dot_accumulator.saturating_add(dots_per_cycle);
            while self.ppu_dot_accumulator >= denominator {
                self.ppu_dot_accumulator -= denominator;
                self.clock_ppu_dot();
            }
        }
    }

    fn clock_ppu_dot(&mut self) {
        let pre_render = self.pre_render_scanline();
        let skip_odd_dot = self.timing == TimingProfile::Ntsc
            && self.ppu_frame & 1 != 0
            && self.rendering_enabled()
            && self.ppu_scanline == pre_render
            && self.ppu_dot == 339;
        if skip_odd_dot || self.ppu_dot == 340 {
            self.ppu_dot = 0;
            if self.ppu_scanline == pre_render {
                self.ppu_scanline = 0;
                self.ppu_frame = self.ppu_frame.saturating_add(1);
                self.frames = self.ppu_frame;
                self.record_at(EventKind::Frame, None, None, None, self.cycles, self.cpu.pc);
            } else {
                self.ppu_scanline += 1;
            }
        } else {
            self.ppu_dot += 1;
        }

        if self.ppu_dot == 0 {
            self.activate_scanline_sprites();
        }

        if self.ppu_scanline == self.vblank_scanline() && self.ppu_dot == 1 {
            if self.ppu_suppress_vblank {
                self.ppu_status &= !0x80;
            } else {
                self.ppu_status |= 0x80;
            }
            self.ppu_suppress_vblank = false;
            self.update_ppu_nmi_line();
            self.record_at(
                EventKind::VBlank,
                Some(0x2002),
                Some(self.ppu_status),
                None,
                self.cycles,
                self.cpu.pc,
            );
        }
        if self.ppu_scanline == pre_render && self.ppu_dot == 1 {
            self.ppu_status &= !0xe0;
            self.update_ppu_nmi_line();
        }

        if self.ppu_scanline < FRAME_HEIGHT as u16
            && (1..=FRAME_WIDTH as u16).contains(&self.ppu_dot)
        {
            self.render_pixel();
        }

        if self.rendering_enabled()
            && (self.ppu_scanline < FRAME_HEIGHT as u16 || self.ppu_scanline == pre_render)
        {
            self.clock_background_pipeline();
            self.clock_sprite_pipeline();
            if self.ppu_dot == 256 {
                self.increment_render_y();
            } else if self.ppu_dot == 257 {
                self.copy_render_x();
            }
            if self.ppu_scanline == pre_render && (280..=304).contains(&self.ppu_dot) {
                self.copy_render_y();
            }
        }
    }

    const fn pre_render_scanline(&self) -> u16 {
        match self.timing {
            TimingProfile::Ntsc => 261,
            TimingProfile::Pal | TimingProfile::Dendy => 311,
        }
    }

    const fn vblank_scanline(&self) -> u16 {
        match self.timing {
            TimingProfile::Ntsc | TimingProfile::Pal => 241,
            TimingProfile::Dendy => 291,
        }
    }

    const fn rendering_enabled(&self) -> bool {
        self.ppu_mask & 0x18 != 0
    }

    fn update_ppu_nmi_line(&mut self) {
        let active = self.ppu_status & 0x80 != 0 && self.ppu_ctrl & 0x80 != 0;
        if active && !self.ppu_nmi_line {
            self.pending_ppu_nmi = true;
        }
        self.ppu_nmi_line = active;
    }

    fn render_pixel(&mut self) {
        let x = (self.ppu_dot - 1) as usize;
        let y = usize::from(self.ppu_scanline);
        let (background_opaque, background_color) = self.background_pixel(x, y);
        let sprite = self.sprite_pixel(x);
        if let Some((_, _, _, index)) = sprite {
            if index == 0
                && background_opaque
                && x != FRAME_WIDTH - 1
                && self.ppu_mask & 0x18 == 0x18
            {
                self.ppu_status |= 0x40;
            }
        }
        let color = sprite.map_or(background_color, |(_, color, behind_background, _)| {
            if background_opaque && behind_background {
                background_color
            } else {
                color
            }
        });
        self.framebuffer[y * FRAME_WIDTH + x] = color;
    }

    fn background_pixel(&self, x: usize, _y: usize) -> (bool, u8) {
        let backdrop = self.render_palette_color(0x3f00);
        if self.ppu_mask & 0x08 == 0 || (x < 8 && self.ppu_mask & 0x02 == 0) {
            return (false, backdrop);
        }

        let selector = 0x8000_u16 >> self.ppu_fine_x;
        let pixel = u8::from(self.background_pattern_shift_low & selector != 0)
            | (u8::from(self.background_pattern_shift_high & selector != 0) << 1);
        let palette = u8::from(self.background_attribute_shift_low & selector != 0)
            | (u8::from(self.background_attribute_shift_high & selector != 0) << 1);
        if pixel == 0 {
            (false, backdrop)
        } else {
            (
                true,
                self.render_palette_color(0x3f00 + u16::from(palette * 4 + pixel)),
            )
        }
    }

    fn clock_background_pipeline(&mut self) {
        let fetch_dot = (1..=256).contains(&self.ppu_dot) || (321..=336).contains(&self.ppu_dot);
        if fetch_dot {
            self.background_pattern_shift_low <<= 1;
            self.background_pattern_shift_high <<= 1;
            self.background_attribute_shift_low <<= 1;
            self.background_attribute_shift_high <<= 1;
            match self.ppu_dot & 7 {
                1 => {
                    let address = 0x2000 | (self.ppu_address & 0x0fff);
                    self.background_next_tile = self.pipeline_ppu_read(address);
                }
                3 => {
                    let address = 0x23c0
                        | (self.ppu_address & 0x0c00)
                        | ((self.ppu_address >> 4) & 0x38)
                        | ((self.ppu_address >> 2) & 0x07);
                    let attribute = self.pipeline_ppu_read(address);
                    let shift = ((self.ppu_address >> 4) & 4) | (self.ppu_address & 2);
                    self.background_next_attribute = (attribute >> shift) & 3;
                }
                5 => {
                    let address = self.background_pattern_address(false);
                    self.background_next_pattern_low = self.pipeline_ppu_read(address);
                }
                7 => {
                    let address = self.background_pattern_address(true);
                    self.background_next_pattern_high = self.pipeline_ppu_read(address);
                }
                0 => {
                    self.load_background_shifters();
                    self.increment_render_x();
                }
                _ => {}
            }
        } else if matches!(self.ppu_dot, 337 | 339) {
            let address = 0x2000 | (self.ppu_address & 0x0fff);
            self.pipeline_ppu_read(address);
        }
    }

    fn background_pattern_address(&self, high_plane: bool) -> u16 {
        let pattern_base = if self.ppu_ctrl & 0x10 == 0 { 0 } else { 0x1000 };
        pattern_base
            + u16::from(self.background_next_tile) * 16
            + ((self.ppu_address >> 12) & 7)
            + u16::from(high_plane) * 8
    }

    fn load_background_shifters(&mut self) {
        self.background_pattern_shift_low = (self.background_pattern_shift_low & 0xff00)
            | u16::from(self.background_next_pattern_low);
        self.background_pattern_shift_high = (self.background_pattern_shift_high & 0xff00)
            | u16::from(self.background_next_pattern_high);
        let attribute_low = if self.background_next_attribute & 1 == 0 {
            0
        } else {
            0xff
        };
        let attribute_high = if self.background_next_attribute & 2 == 0 {
            0
        } else {
            0xff
        };
        self.background_attribute_shift_low =
            (self.background_attribute_shift_low & 0xff00) | attribute_low;
        self.background_attribute_shift_high =
            (self.background_attribute_shift_high & 0xff00) | attribute_high;
    }

    fn pipeline_ppu_read(&mut self, address: u16) -> u8 {
        let value = self.render_ppu_read(address);
        self.ppu_fetch_address = address & 0x3fff;
        self.ppu_fetch_value = value;
        value
    }

    fn clock_sprite_pipeline(&mut self) {
        match self.ppu_dot {
            1..=64 => self.clear_secondary_oam_clock(),
            65..=256 => self.evaluate_sprite_clock(),
            257..=320 => self.fetch_sprite_clock(),
            _ => {}
        }
    }

    fn clear_secondary_oam_clock(&mut self) {
        if self.ppu_dot == 1 {
            self.secondary_oam_count = 0;
            self.secondary_oam_indices.fill(0xff);
            self.sprite_evaluation_index = 0;
            self.sprite_evaluation_byte = 0;
        }
        self.ppu_oam_bus = 0xff;
        if self.ppu_dot & 1 == 0 {
            self.secondary_oam[usize::from(self.ppu_dot / 2 - 1)] = 0xff;
        }
    }

    fn evaluate_sprite_clock(&mut self) {
        if self.sprite_evaluation_index >= 64 {
            self.ppu_oam_bus = 0xff;
            return;
        }
        if self.ppu_dot & 1 != 0 {
            let address = usize::from(self.sprite_evaluation_index) * 4
                + usize::from(self.sprite_evaluation_byte);
            self.ppu_oam_bus = self.oam[address];
            return;
        }

        if self.secondary_oam_count < 8 {
            self.copy_evaluated_sprite_byte();
        } else {
            let target = self.sprite_target_scanline();
            if self.sprite_row(self.ppu_oam_bus, target).is_some() {
                self.ppu_status |= 0x20;
            }
            self.sprite_evaluation_byte = (self.sprite_evaluation_byte + 1) & 3;
            self.sprite_evaluation_index = self.sprite_evaluation_index.saturating_add(1);
        }
    }

    fn copy_evaluated_sprite_byte(&mut self) {
        let destination =
            usize::from(self.secondary_oam_count) * 4 + usize::from(self.sprite_evaluation_byte);
        if self.sprite_evaluation_byte == 0 {
            let target = self.sprite_target_scanline();
            if self.sprite_row(self.ppu_oam_bus, target).is_none() {
                self.sprite_evaluation_index = self.sprite_evaluation_index.saturating_add(1);
                return;
            }
            self.secondary_oam_indices[usize::from(self.secondary_oam_count)] =
                self.sprite_evaluation_index;
        }
        self.secondary_oam[destination] = self.ppu_oam_bus;
        if self.sprite_evaluation_byte == 3 {
            self.secondary_oam_count += 1;
            self.sprite_evaluation_index = self.sprite_evaluation_index.saturating_add(1);
            self.sprite_evaluation_byte = 0;
        } else {
            self.sprite_evaluation_byte += 1;
        }
    }

    fn fetch_sprite_clock(&mut self) {
        let slot = usize::from((self.ppu_dot - 257) / 8);
        let fetch_clock = (self.ppu_dot - 257) & 7;
        if self.ppu_dot == 257 {
            self.next_scanline_sprites.fill(ScanlineSprite::default());
            self.next_scanline_sprite_count = 0;
        }
        let secondary_base = slot * 4;
        match fetch_clock {
            0..=3 => {
                self.ppu_oam_bus = self.secondary_oam[secondary_base + usize::from(fetch_clock)];
                if fetch_clock == 0 {
                    self.next_scanline_sprites[slot].index = self.secondary_oam_indices[slot];
                } else if fetch_clock == 2 {
                    self.next_scanline_sprites[slot].attributes = self.ppu_oam_bus;
                } else if fetch_clock == 3 {
                    self.next_scanline_sprites[slot].x = self.ppu_oam_bus;
                }
            }
            4 => {
                let address = self.sprite_pattern_address(slot, false);
                self.next_scanline_sprites[slot].pattern_low = self.pipeline_ppu_read(address);
            }
            6 => {
                let address = self.sprite_pattern_address(slot, true);
                self.next_scanline_sprites[slot].pattern_high = self.pipeline_ppu_read(address);
            }
            7 if slot < usize::from(self.secondary_oam_count) => {
                self.next_scanline_sprite_count = (slot + 1) as u8;
            }
            _ => {}
        }
    }

    fn sprite_pattern_address(&self, slot: usize, high_plane: bool) -> u16 {
        let base = slot * 4;
        let y = self.secondary_oam[base];
        let tile = self.secondary_oam[base + 1];
        let attributes = self.secondary_oam[base + 2];
        let height = if self.ppu_ctrl & 0x20 == 0 { 8 } else { 16 };
        let mut row = self
            .sprite_row(y, self.sprite_target_scanline())
            .unwrap_or(0);
        if attributes & 0x80 != 0 {
            row = height - 1 - row;
        }
        let (pattern_base, tile, row) = if height == 16 {
            (
                u16::from(tile & 1) * 0x1000,
                (tile & 0xfe).wrapping_add(row / 8),
                row & 7,
            )
        } else {
            (
                if self.ppu_ctrl & 0x08 == 0 { 0 } else { 0x1000 },
                tile,
                row,
            )
        };
        pattern_base + u16::from(tile) * 16 + u16::from(row) + u16::from(high_plane) * 8
    }

    fn sprite_row(&self, y: u8, target: u16) -> Option<u8> {
        let height = if self.ppu_ctrl & 0x20 == 0 { 8 } else { 16 };
        let row = (target as u8).wrapping_sub(y.wrapping_add(1));
        (row < height).then_some(row)
    }

    fn sprite_target_scanline(&self) -> u16 {
        if self.ppu_scanline == self.pre_render_scanline() {
            0
        } else {
            self.ppu_scanline.saturating_add(1)
        }
    }

    fn activate_scanline_sprites(&mut self) {
        if self.ppu_scanline < FRAME_HEIGHT as u16 {
            self.scanline_sprites = self.next_scanline_sprites;
            self.scanline_sprite_count = self.next_scanline_sprite_count;
        } else {
            self.scanline_sprites.fill(ScanlineSprite::default());
            self.scanline_sprite_count = 0;
        }
    }

    fn sprite_pixel(&self, x: usize) -> Option<(u8, u8, bool, u8)> {
        if self.ppu_mask & 0x10 == 0 || (x < 8 && self.ppu_mask & 0x04 == 0) {
            return None;
        }
        for sprite in self
            .scanline_sprites
            .iter()
            .take(usize::from(self.scanline_sprite_count))
        {
            let offset = x.wrapping_sub(usize::from(sprite.x));
            if offset >= 8 {
                continue;
            }
            let bit = if sprite.attributes & 0x40 == 0 {
                7 - offset
            } else {
                offset
            };
            let low = (sprite.pattern_low >> bit) & 1;
            let high = (sprite.pattern_high >> bit) & 1;
            let pixel = low | (high << 1);
            if pixel == 0 {
                continue;
            }
            let palette = sprite.attributes & 0x03;
            let color = self.render_palette_color(0x3f10 + u16::from(palette * 4 + pixel));
            return Some((pixel, color, sprite.attributes & 0x20 != 0, sprite.index));
        }
        None
    }

    fn render_palette_color(&self, address: u16) -> u8 {
        let color = self.render_ppu_read(address) & 0x3f;
        if self.ppu_mask & 0x01 == 0 {
            color
        } else {
            color & 0x30
        }
    }

    fn render_ppu_read(&self, address: u16) -> u8 {
        let address = address & 0x3fff;
        match address {
            0x0000..=0x1fff if self.chr_rom.is_empty() => self.chr_ram[usize::from(address)],
            0x0000..=0x1fff => self
                .mapper
                .map_ppu(PpuAddress(address), self.mapper_state)
                .and_then(|offset| self.chr_rom.get(offset.0).copied())
                .unwrap_or(0),
            0x2000..=0x3eff => self.nametable_ram[self.nametable_index(address)],
            0x3f00..=0x3fff => self.palette[palette_index(address)],
            _ => unreachable!(),
        }
    }

    fn increment_render_x(&mut self) {
        if self.ppu_address & 0x001f == 31 {
            self.ppu_address &= !0x001f;
            self.ppu_address ^= 0x0400;
        } else {
            self.ppu_address += 1;
        }
    }

    fn increment_render_y(&mut self) {
        if self.ppu_address & 0x7000 != 0x7000 {
            self.ppu_address += 0x1000;
            return;
        }
        self.ppu_address &= !0x7000;
        let mut coarse_y = (self.ppu_address & 0x03e0) >> 5;
        if coarse_y == 29 {
            coarse_y = 0;
            self.ppu_address ^= 0x0800;
        } else if coarse_y == 31 {
            coarse_y = 0;
        } else {
            coarse_y += 1;
        }
        self.ppu_address = (self.ppu_address & !0x03e0) | (coarse_y << 5);
    }

    fn copy_render_x(&mut self) {
        self.ppu_address = (self.ppu_address & !0x041f) | (self.ppu_temporary_address & 0x041f);
    }

    fn copy_render_y(&mut self) {
        self.ppu_address = (self.ppu_address & !0x7be0) | (self.ppu_temporary_address & 0x7be0);
    }

    fn physical_bank(&self, address: u16) -> Option<u16> {
        self.mapper
            .map_cpu(CpuAddress(address), self.mapper_state)
            .map(|offset| (offset.0 / 0x4000) as u16)
    }

    fn record(
        &mut self,
        kind: EventKind,
        address: Option<u16>,
        value: Option<u8>,
        physical_bank: Option<u16>,
    ) {
        self.record_at(
            kind,
            address,
            value,
            physical_bank,
            self.cycles,
            self.cpu.pc,
        );
    }

    fn record_at(
        &mut self,
        kind: EventKind,
        address: Option<u16>,
        value: Option<u8>,
        physical_bank: Option<u16>,
        cycle: u64,
        pc: u16,
    ) {
        if self.planning {
            return;
        }
        if self.events.len() == self.event_capacity {
            self.events.pop_front();
            self.dropped_events = self.dropped_events.saturating_add(1);
        }
        self.events.push_back(ObservableEvent {
            cycle,
            pc,
            physical_bank,
            address,
            value,
            kind,
            source: None,
        });
    }

    fn failure(&self, message: impl Into<String>) -> EmulatorError {
        const ERROR_TRACE_LIMIT: usize = 16;
        EmulatorError {
            message: message.into(),
            pc: self.cpu.pc,
            cycle: self.cycles,
            trace: self
                .events
                .iter()
                .rev()
                .take(ERROR_TRACE_LIMIT)
                .cloned()
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
                .collect(),
        }
    }
}

fn build_micro_operations(
    report: StepReport,
    initial_cpu: CpuState,
    final_cpu: CpuState,
    accesses: &[BusAccess],
) -> Result<VecDeque<MicroOperation>, String> {
    let mut operations = if let Some(opcode_byte) = report.opcode {
        let instruction = opcode(opcode_byte)
            .ok_or_else(|| format!("cannot schedule undocumented opcode ${opcode_byte:02X}"))?;
        schedule_instruction(
            instruction.mnemonic,
            instruction.mode,
            initial_cpu,
            final_cpu,
            report.cycles,
            accesses,
        )?
    } else {
        schedule_interrupt(initial_cpu, accesses)?
    };

    let dma_page = operations.iter().find_map(|operation| match operation {
        MicroOperation::Write {
            address: 0x4014,
            value,
            ..
        } => Some(*value),
        _ => None,
    });
    if let Some(page) = dma_page {
        let base_cycles = operations.len() as u64;
        let stall_cycles = report.cycles.checked_sub(base_cycles).ok_or_else(|| {
            "DMA cycle count is shorter than its triggering instruction".to_owned()
        })?;
        let idle_cycles = stall_cycles
            .checked_sub(512)
            .ok_or_else(|| "DMA stall omits required transfer clocks".to_owned())?;
        if !(1..=2).contains(&idle_cycles) {
            return Err(format!(
                "DMA requires one or two alignment clocks, got {idle_cycles}"
            ));
        }
        for _ in 0..idle_cycles {
            operations.push_back(dummy_read(final_cpu.pc));
        }
        let base = u16::from(page) << 8;
        for offset in 0..=u8::MAX {
            operations.push_back(MicroOperation::DmaRead {
                address: base | u16::from(offset),
            });
            operations.push_back(MicroOperation::DmaWrite);
        }
    }
    Ok(operations)
}

fn schedule_interrupt(
    initial_cpu: CpuState,
    accesses: &[BusAccess],
) -> Result<VecDeque<MicroOperation>, String> {
    require_accesses(accesses, 5, "external interrupt")?;
    Ok(VecDeque::from([
        dummy_read(initial_cpu.pc),
        dummy_read(initial_cpu.pc),
        logical(accesses[0]),
        logical(accesses[1]),
        logical(accesses[2]),
        logical(accesses[3]),
        logical(accesses[4]),
    ]))
}

fn schedule_instruction(
    mnemonic: Mnemonic,
    mode: AddressingMode,
    initial_cpu: CpuState,
    final_cpu: CpuState,
    cycles: u64,
    accesses: &[BusAccess],
) -> Result<VecDeque<MicroOperation>, String> {
    if is_branch(mnemonic) {
        return schedule_branch(initial_cpu, final_cpu, cycles, accesses);
    }
    if is_modify(mnemonic, mode) {
        let mut operations = schedule_modify(mode, accesses)?;
        mark_semantic_read(&mut operations)?;
        return Ok(operations);
    }
    if is_store(mnemonic) {
        return schedule_store(mode, accesses);
    }
    let mut operations = match mnemonic {
        Mnemonic::Brk => {
            require_accesses(accesses, 6, "BRK")?;
            VecDeque::from([
                logical(accesses[0]),
                dummy_read(initial_cpu.pc.wrapping_add(1)),
                logical(accesses[1]),
                logical(accesses[2]),
                logical(accesses[3]),
                logical(accesses[4]),
                logical(accesses[5]),
            ])
        }
        Mnemonic::Jmp if mode == AddressingMode::Indirect => {
            require_accesses(accesses, 5, "indirect JMP")?;
            accesses[..5].iter().copied().map(logical).collect()
        }
        Mnemonic::Jmp => {
            require_accesses(accesses, 3, "absolute JMP")?;
            accesses[..3].iter().copied().map(logical).collect()
        }
        Mnemonic::Jsr => {
            require_accesses(accesses, 5, "JSR")?;
            VecDeque::from([
                logical(accesses[0]),
                logical(accesses[1]),
                dummy_read(STACK_BASE | u16::from(initial_cpu.sp)),
                logical(accesses[3]),
                logical(accesses[4]),
                logical(accesses[2]),
            ])
        }
        Mnemonic::Pha | Mnemonic::Php => {
            require_accesses(accesses, 2, "stack push")?;
            VecDeque::from([
                logical(accesses[0]),
                dummy_read(initial_cpu.pc.wrapping_add(1)),
                logical(accesses[1]),
            ])
        }
        Mnemonic::Pla | Mnemonic::Plp => {
            require_accesses(accesses, 2, "stack pull")?;
            VecDeque::from([
                logical(accesses[0]),
                dummy_read(initial_cpu.pc.wrapping_add(1)),
                dummy_read(STACK_BASE | u16::from(initial_cpu.sp)),
                logical(accesses[1]),
            ])
        }
        Mnemonic::Rti => {
            require_accesses(accesses, 4, "RTI")?;
            VecDeque::from([
                logical(accesses[0]),
                dummy_read(initial_cpu.pc.wrapping_add(1)),
                dummy_read(STACK_BASE | u16::from(initial_cpu.sp)),
                logical(accesses[1]),
                logical(accesses[2]),
                logical(accesses[3]),
            ])
        }
        Mnemonic::Rts => {
            require_accesses(accesses, 3, "RTS")?;
            VecDeque::from([
                logical(accesses[0]),
                dummy_read(initial_cpu.pc.wrapping_add(1)),
                dummy_read(STACK_BASE | u16::from(initial_cpu.sp)),
                logical(accesses[1]),
                logical(accesses[2]),
                dummy_read(final_cpu.pc.wrapping_sub(1)),
            ])
        }
        _ if matches!(mode, AddressingMode::Implied | AddressingMode::Accumulator) => {
            require_accesses(accesses, 1, "implied instruction")?;
            VecDeque::from([
                logical(accesses[0]),
                dummy_read(initial_cpu.pc.wrapping_add(1)),
            ])
        }
        _ => schedule_read(mode, accesses)?,
    };
    if is_alu_read(mnemonic) {
        mark_semantic_read(&mut operations)?;
    }
    Ok(operations)
}

fn schedule_read(
    mode: AddressingMode,
    accesses: &[BusAccess],
) -> Result<VecDeque<MicroOperation>, String> {
    let operations = match mode {
        AddressingMode::Immediate => {
            require_accesses(accesses, 2, "immediate read")?;
            VecDeque::from([logical(accesses[0]), logical(accesses[1])])
        }
        AddressingMode::ZeroPage => {
            require_accesses(accesses, 3, "zero-page read")?;
            accesses[..3].iter().copied().map(logical).collect()
        }
        AddressingMode::ZeroPageX | AddressingMode::ZeroPageY => {
            require_accesses(accesses, 3, "indexed zero-page read")?;
            VecDeque::from([
                logical(accesses[0]),
                logical(accesses[1]),
                dummy_read(u16::from(accesses[1].value)),
                logical(accesses[2]),
            ])
        }
        AddressingMode::Absolute => {
            require_accesses(accesses, 4, "absolute read")?;
            accesses[..4].iter().copied().map(logical).collect()
        }
        AddressingMode::AbsoluteX | AddressingMode::AbsoluteY => {
            require_accesses(accesses, 4, "indexed absolute read")?;
            let base = operand_word(accesses, 1)?;
            let effective = accesses[3].address;
            let mut result = VecDeque::from([
                logical(accesses[0]),
                logical(accesses[1]),
                logical(accesses[2]),
            ]);
            if base & 0xff00 != effective & 0xff00 {
                result.push_back(dummy_read(indexed_dummy_address(base, effective)));
            }
            result.push_back(logical(accesses[3]));
            result
        }
        AddressingMode::IndexedIndirect => {
            require_accesses(accesses, 5, "indexed-indirect read")?;
            VecDeque::from([
                logical(accesses[0]),
                logical(accesses[1]),
                dummy_read(u16::from(accesses[1].value)),
                logical(accesses[2]),
                logical(accesses[3]),
                logical(accesses[4]),
            ])
        }
        AddressingMode::IndirectIndexed => {
            require_accesses(accesses, 5, "indirect-indexed read")?;
            let base = u16::from_le_bytes([accesses[2].value, accesses[3].value]);
            let effective = accesses[4].address;
            let mut result = VecDeque::from([
                logical(accesses[0]),
                logical(accesses[1]),
                logical(accesses[2]),
                logical(accesses[3]),
            ]);
            if base & 0xff00 != effective & 0xff00 {
                result.push_back(dummy_read(indexed_dummy_address(base, effective)));
            }
            result.push_back(logical(accesses[4]));
            result
        }
        _ => return Err(format!("cannot schedule read addressing mode {mode:?}")),
    };
    Ok(operations)
}

fn schedule_store(
    mode: AddressingMode,
    accesses: &[BusAccess],
) -> Result<VecDeque<MicroOperation>, String> {
    let operations = match mode {
        AddressingMode::ZeroPage => {
            require_accesses(accesses, 3, "zero-page store")?;
            accesses[..3].iter().copied().map(logical).collect()
        }
        AddressingMode::ZeroPageX | AddressingMode::ZeroPageY => {
            require_accesses(accesses, 3, "indexed zero-page store")?;
            VecDeque::from([
                logical(accesses[0]),
                logical(accesses[1]),
                dummy_read(u16::from(accesses[1].value)),
                logical(accesses[2]),
            ])
        }
        AddressingMode::Absolute => {
            require_accesses(accesses, 4, "absolute store")?;
            accesses[..4].iter().copied().map(logical).collect()
        }
        AddressingMode::AbsoluteX | AddressingMode::AbsoluteY => {
            require_accesses(accesses, 4, "indexed absolute store")?;
            let base = operand_word(accesses, 1)?;
            let effective = accesses[3].address;
            VecDeque::from([
                logical(accesses[0]),
                logical(accesses[1]),
                logical(accesses[2]),
                dummy_read(indexed_dummy_address(base, effective)),
                logical(accesses[3]),
            ])
        }
        AddressingMode::IndexedIndirect => {
            require_accesses(accesses, 5, "indexed-indirect store")?;
            VecDeque::from([
                logical(accesses[0]),
                logical(accesses[1]),
                dummy_read(u16::from(accesses[1].value)),
                logical(accesses[2]),
                logical(accesses[3]),
                logical(accesses[4]),
            ])
        }
        AddressingMode::IndirectIndexed => {
            require_accesses(accesses, 5, "indirect-indexed store")?;
            let base = u16::from_le_bytes([accesses[2].value, accesses[3].value]);
            let effective = accesses[4].address;
            VecDeque::from([
                logical(accesses[0]),
                logical(accesses[1]),
                logical(accesses[2]),
                logical(accesses[3]),
                dummy_read(indexed_dummy_address(base, effective)),
                logical(accesses[4]),
            ])
        }
        _ => return Err(format!("cannot schedule store addressing mode {mode:?}")),
    };
    Ok(operations)
}

fn schedule_modify(
    mode: AddressingMode,
    accesses: &[BusAccess],
) -> Result<VecDeque<MicroOperation>, String> {
    let operations = match mode {
        AddressingMode::ZeroPage => {
            require_accesses(accesses, 4, "zero-page modify")?;
            VecDeque::from([
                logical(accesses[0]),
                logical(accesses[1]),
                logical(accesses[2]),
                dummy_write(accesses[2].address, accesses[2].value),
                logical(accesses[3]),
            ])
        }
        AddressingMode::ZeroPageX | AddressingMode::ZeroPageY => {
            require_accesses(accesses, 4, "indexed zero-page modify")?;
            VecDeque::from([
                logical(accesses[0]),
                logical(accesses[1]),
                dummy_read(u16::from(accesses[1].value)),
                logical(accesses[2]),
                dummy_write(accesses[2].address, accesses[2].value),
                logical(accesses[3]),
            ])
        }
        AddressingMode::Absolute => {
            require_accesses(accesses, 5, "absolute modify")?;
            VecDeque::from([
                logical(accesses[0]),
                logical(accesses[1]),
                logical(accesses[2]),
                logical(accesses[3]),
                dummy_write(accesses[3].address, accesses[3].value),
                logical(accesses[4]),
            ])
        }
        AddressingMode::AbsoluteX | AddressingMode::AbsoluteY => {
            require_accesses(accesses, 5, "indexed absolute modify")?;
            let base = operand_word(accesses, 1)?;
            let effective = accesses[3].address;
            VecDeque::from([
                logical(accesses[0]),
                logical(accesses[1]),
                logical(accesses[2]),
                dummy_read(indexed_dummy_address(base, effective)),
                logical(accesses[3]),
                dummy_write(accesses[3].address, accesses[3].value),
                logical(accesses[4]),
            ])
        }
        _ => return Err(format!("cannot schedule modify addressing mode {mode:?}")),
    };
    Ok(operations)
}

fn schedule_branch(
    initial_cpu: CpuState,
    final_cpu: CpuState,
    cycles: u64,
    accesses: &[BusAccess],
) -> Result<VecDeque<MicroOperation>, String> {
    require_accesses(accesses, 2, "branch")?;
    let sequential = initial_cpu.pc.wrapping_add(2);
    let mut operations = VecDeque::from([logical(accesses[0]), logical(accesses[1])]);
    if cycles >= 3 {
        operations.push_back(dummy_read(sequential));
        if cycles == 4 {
            operations.push_back(dummy_read(indexed_dummy_address(sequential, final_cpu.pc)));
        }
    }
    Ok(operations)
}

const fn is_branch(mnemonic: Mnemonic) -> bool {
    matches!(
        mnemonic,
        Mnemonic::Bcc
            | Mnemonic::Bcs
            | Mnemonic::Beq
            | Mnemonic::Bmi
            | Mnemonic::Bne
            | Mnemonic::Bpl
            | Mnemonic::Bvc
            | Mnemonic::Bvs
    )
}

const fn is_store(mnemonic: Mnemonic) -> bool {
    matches!(mnemonic, Mnemonic::Sta | Mnemonic::Stx | Mnemonic::Sty)
}

const fn is_modify(mnemonic: Mnemonic, mode: AddressingMode) -> bool {
    matches!(
        mnemonic,
        Mnemonic::Asl
            | Mnemonic::Dec
            | Mnemonic::Inc
            | Mnemonic::Lsr
            | Mnemonic::Rol
            | Mnemonic::Ror
    ) && !matches!(mode, AddressingMode::Accumulator)
}

const fn is_alu_read(mnemonic: Mnemonic) -> bool {
    matches!(
        mnemonic,
        Mnemonic::Adc
            | Mnemonic::And
            | Mnemonic::Bit
            | Mnemonic::Cmp
            | Mnemonic::Cpx
            | Mnemonic::Cpy
            | Mnemonic::Eor
            | Mnemonic::Lda
            | Mnemonic::Ldx
            | Mnemonic::Ldy
            | Mnemonic::Ora
            | Mnemonic::Sbc
    )
}

fn mark_semantic_read(operations: &mut VecDeque<MicroOperation>) -> Result<(), String> {
    let semantic = operations.iter_mut().rev().find_map(|operation| {
        if let MicroOperation::Read {
            dummy: false,
            semantic,
            ..
        } = operation
        {
            Some(semantic)
        } else {
            None
        }
    });
    let semantic = semantic.ok_or_else(|| "instruction has no semantic operand read".to_owned())?;
    *semantic = true;
    Ok(())
}

fn apply_semantic_read(pending: &mut PendingStep, value: u8) {
    let Some(mnemonic) = pending.mnemonic else {
        return;
    };
    if matches!(
        mnemonic,
        Mnemonic::Asl
            | Mnemonic::Dec
            | Mnemonic::Inc
            | Mnemonic::Lsr
            | Mnemonic::Rol
            | Mnemonic::Ror
    ) {
        let mut cpu = pending.initial_cpu;
        let carry_in = u8::from(cpu.flag(FLAG_CARRY));
        let output = match mnemonic {
            Mnemonic::Asl => {
                cpu.set_flag(FLAG_CARRY, value & 0x80 != 0);
                value << 1
            }
            Mnemonic::Lsr => {
                cpu.set_flag(FLAG_CARRY, value & 1 != 0);
                value >> 1
            }
            Mnemonic::Rol => {
                cpu.set_flag(FLAG_CARRY, value & 0x80 != 0);
                (value << 1) | carry_in
            }
            Mnemonic::Ror => {
                cpu.set_flag(FLAG_CARRY, value & 1 != 0);
                (value >> 1) | (carry_in << 7)
            }
            Mnemonic::Inc => value.wrapping_add(1),
            Mnemonic::Dec => value.wrapping_sub(1),
            _ => unreachable!(),
        };
        cpu.set_negative_zero(output);
        cpu.pc = pending.final_cpu.pc;
        pending.final_cpu = cpu;
        for operation in &mut pending.operations {
            if let MicroOperation::Write {
                value: scheduled,
                dummy,
                ..
            } = operation
            {
                *scheduled = if *dummy { value } else { output };
            }
        }
        return;
    }

    let mut cpu = pending.initial_cpu;
    match mnemonic {
        Mnemonic::Adc => adc_cpu(&mut cpu, value),
        Mnemonic::And => {
            cpu.a &= value;
            cpu.set_negative_zero(cpu.a);
        }
        Mnemonic::Bit => {
            cpu.set_flag(FLAG_ZERO, cpu.a & value == 0);
            cpu.set_flag(FLAG_NEGATIVE, value & FLAG_NEGATIVE != 0);
            cpu.set_flag(FLAG_OVERFLOW, value & FLAG_OVERFLOW != 0);
        }
        Mnemonic::Cmp => {
            let left = cpu.a;
            compare_cpu(&mut cpu, left, value);
        }
        Mnemonic::Cpx => {
            let left = cpu.x;
            compare_cpu(&mut cpu, left, value);
        }
        Mnemonic::Cpy => {
            let left = cpu.y;
            compare_cpu(&mut cpu, left, value);
        }
        Mnemonic::Eor => {
            cpu.a ^= value;
            cpu.set_negative_zero(cpu.a);
        }
        Mnemonic::Lda => {
            cpu.a = value;
            cpu.set_negative_zero(value);
        }
        Mnemonic::Ldx => {
            cpu.x = value;
            cpu.set_negative_zero(value);
        }
        Mnemonic::Ldy => {
            cpu.y = value;
            cpu.set_negative_zero(value);
        }
        Mnemonic::Ora => {
            cpu.a |= value;
            cpu.set_negative_zero(cpu.a);
        }
        Mnemonic::Sbc => adc_cpu(&mut cpu, !value),
        _ => return,
    }
    cpu.pc = pending.final_cpu.pc;
    pending.final_cpu = cpu;
}

fn adc_cpu(cpu: &mut CpuState, value: u8) {
    let carry = u16::from(cpu.flag(FLAG_CARRY));
    let sum = u16::from(cpu.a) + u16::from(value) + carry;
    let output = sum as u8;
    let overflow = (!(cpu.a ^ value) & (cpu.a ^ output) & 0x80) != 0;
    cpu.set_flag(FLAG_CARRY, sum > 0xff);
    cpu.set_flag(FLAG_OVERFLOW, overflow);
    cpu.a = output;
    cpu.set_negative_zero(output);
}

fn compare_cpu(cpu: &mut CpuState, left: u8, right: u8) {
    cpu.set_flag(FLAG_CARRY, left >= right);
    cpu.set_negative_zero(left.wrapping_sub(right));
}

fn logical(access: BusAccess) -> MicroOperation {
    match access.kind {
        BusAccessKind::Read => MicroOperation::Read {
            address: access.address,
            dummy: false,
            semantic: false,
        },
        BusAccessKind::Write => MicroOperation::Write {
            address: access.address,
            value: access.value,
            dummy: false,
        },
    }
}

const fn dummy_read(address: u16) -> MicroOperation {
    MicroOperation::Read {
        address,
        dummy: true,
        semantic: false,
    }
}

const fn dummy_write(address: u16, value: u8) -> MicroOperation {
    MicroOperation::Write {
        address,
        value,
        dummy: true,
    }
}

fn operand_word(accesses: &[BusAccess], start: usize) -> Result<u16, String> {
    let low = accesses
        .get(start)
        .ok_or_else(|| "missing low operand byte".to_owned())?
        .value;
    let high = accesses
        .get(start + 1)
        .ok_or_else(|| "missing high operand byte".to_owned())?
        .value;
    Ok(u16::from_le_bytes([low, high]))
}

const fn indexed_dummy_address(base: u16, effective: u16) -> u16 {
    (base & 0xff00) | (effective & 0x00ff)
}

fn require_accesses(accesses: &[BusAccess], expected: usize, context: &str) -> Result<(), String> {
    if accesses.len() < expected {
        return Err(format!(
            "{context} produced {} logical bus accesses; expected at least {expected}",
            accesses.len()
        ));
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum Register {
    A,
    X,
    Y,
}

#[derive(Clone, Copy)]
enum Shift {
    Asl,
    Lsr,
    Rol,
    Ror,
}

fn construction_error(message: impl Into<String>) -> EmulatorError {
    EmulatorError {
        message: message.into(),
        pc: 0,
        cycle: 0,
        trace: Vec::new(),
    }
}

const fn read_cycles(mode: AddressingMode, page_crossed: bool) -> u64 {
    let base = match mode {
        AddressingMode::Immediate => 2,
        AddressingMode::ZeroPage => 3,
        AddressingMode::ZeroPageX | AddressingMode::ZeroPageY => 4,
        AddressingMode::Absolute => 4,
        AddressingMode::AbsoluteX | AddressingMode::AbsoluteY => 4,
        AddressingMode::IndexedIndirect => 6,
        AddressingMode::IndirectIndexed => 5,
        _ => 0,
    };
    base + if page_crossed
        && matches!(
            mode,
            AddressingMode::AbsoluteX | AddressingMode::AbsoluteY | AddressingMode::IndirectIndexed
        ) {
        1
    } else {
        0
    }
}

const fn index_load_cycles(mode: AddressingMode, page_crossed: bool) -> u64 {
    read_cycles(mode, page_crossed)
}

const fn compare_index_cycles(mode: AddressingMode) -> u64 {
    match mode {
        AddressingMode::Immediate => 2,
        AddressingMode::ZeroPage => 3,
        AddressingMode::Absolute => 4,
        _ => 0,
    }
}

const fn store_cycles(mode: AddressingMode) -> u64 {
    match mode {
        AddressingMode::ZeroPage => 3,
        AddressingMode::ZeroPageX | AddressingMode::ZeroPageY => 4,
        AddressingMode::Absolute => 4,
        AddressingMode::AbsoluteX | AddressingMode::AbsoluteY => 5,
        AddressingMode::IndexedIndirect | AddressingMode::IndirectIndexed => 6,
        _ => 0,
    }
}

const fn index_store_cycles(mode: AddressingMode) -> u64 {
    match mode {
        AddressingMode::ZeroPage => 3,
        AddressingMode::ZeroPageX | AddressingMode::ZeroPageY => 4,
        AddressingMode::Absolute => 4,
        _ => 0,
    }
}

const fn modify_cycles(mode: AddressingMode) -> u64 {
    match mode {
        AddressingMode::ZeroPage => 5,
        AddressingMode::ZeroPageX | AddressingMode::ZeroPageY => 6,
        AddressingMode::Absolute => 6,
        AddressingMode::AbsoluteX | AddressingMode::AbsoluteY => 7,
        _ => 0,
    }
}

fn palette_index(address: u16) -> usize {
    let mut index = usize::from((address - 0x3f00) & 0x1f);
    if matches!(index, 0x10 | 0x14 | 0x18 | 0x1c) {
        index -= 0x10;
    }
    index
}

#[cfg(test)]
mod hardware_tests {
    use nesc_rom::{Format, Metadata};

    use super::*;

    fn machine_with_chr(mapper: u16, mirroring: Mirroring, chr_rom: Vec<u8>) -> Machine {
        let mut prg_rom = vec![0xea; 32 * 1024];
        let vectors = prg_rom.len() - 6;
        for offset in [0, 2, 4] {
            prg_rom[vectors + offset..vectors + offset + 2]
                .copy_from_slice(&0x8000_u16.to_le_bytes());
        }
        Machine::from_rom(
            Rom {
                metadata: Metadata {
                    format: Format::Nes2,
                    mapper,
                    submapper: 0,
                    mirroring,
                    battery: false,
                    region: Region::Ntsc,
                    prg_rom_len: prg_rom.len(),
                    chr_rom_len: chr_rom.len(),
                },
                trainer: None,
                prg_rom,
                chr_rom,
            },
            EmulatorConfig::default(),
        )
        .expect("PPU test machine")
    }

    fn solid_tiles() -> Vec<u8> {
        let mut chr = vec![0; 8 * 1024];
        chr[16..24].fill(0xff);
        chr[32..40].fill(0xff);
        chr
    }

    fn clock_first_rendered_scanline(machine: &mut Machine, target_dot: u16) {
        machine.ppu_scanline = machine.pre_render_scanline();
        machine.ppu_dot = 0;
        for _ in 0..400 {
            if machine.ppu_scanline == 0 && machine.ppu_dot == target_dot {
                return;
            }
            machine.clock_ppu_dot();
        }
        panic!(
            "PPU did not reach scanline 0 dot {target_dot}; stopped at {:?}",
            machine.ppu_position()
        );
    }

    #[test]
    fn implements_scroll_and_address_write_latches() {
        let mut machine = machine_with_chr(0, Mirroring::Horizontal, solid_tiles());
        machine
            .write_ppu_register(0x2000, 0x03)
            .expect("PPUCTRL write");
        machine
            .write_ppu_register(0x2005, 0x2d)
            .expect("first PPUSCROLL write");
        assert_eq!(machine.ppu_fine_x, 5);
        assert!(machine.ppu_write_toggle);
        machine
            .write_ppu_register(0x2005, 0x56)
            .expect("second PPUSCROLL write");
        assert!(!machine.ppu_write_toggle);
        assert_eq!(machine.ppu_scroll_x, 0x2d);
        assert_eq!(machine.ppu_scroll_y, 0x56);
        assert_eq!(machine.ppu_temporary_address & 0x0c00, 0x0c00);
        assert_eq!(machine.ppu_temporary_address & 0x001f, 5);
        assert_eq!((machine.ppu_temporary_address >> 5) & 0x1f, 10);
        assert_eq!((machine.ppu_temporary_address >> 12) & 7, 6);

        machine
            .write_ppu_register(0x2006, 0x21)
            .expect("high PPUADDR write");
        assert!(machine.ppu_write_toggle);
        machine
            .write_ppu_register(0x2006, 0x34)
            .expect("low PPUADDR write");
        assert_eq!(machine.ppu_address, 0x2134);
        assert_eq!(machine.ppu_temporary_address, 0x2134);
        assert!(!machine.ppu_write_toggle);

        machine.ppu_status = 0x80;
        assert_eq!(machine.read_ppu_register(0x2002).expect("PPUSTATUS"), 0x94);
        assert_eq!(machine.ppu_status & 0x80, 0);
        assert!(!machine.ppu_write_toggle);
    }

    #[test]
    fn models_the_shared_ppu_io_bus_latch() {
        let mut machine = machine_with_chr(0, Mirroring::Horizontal, solid_tiles());
        machine
            .write_ppu_register(0x2000, 0x1b)
            .expect("PPUCTRL write");
        machine.ppu_status = 0xa0;

        assert_eq!(machine.read_ppu_register(0x2002).expect("PPUSTATUS"), 0xbb);
        assert_eq!(machine.ppu_io_bus, 0xbb);
        assert_eq!(
            machine
                .read_ppu_register(0x2005)
                .expect("write-only register read"),
            0xbb
        );

        machine
            .write_ppu_register(0x2002, 0x47)
            .expect("read-only register write");
        assert_eq!(machine.peek(0x2000).expect("observational open bus"), 0x47);
        assert_eq!(machine.ppu_state().io_bus, 0x47);

        machine.write_ppu(0x3f00, 0xff).expect("palette write");
        machine
            .write_ppu_register(0x2000, 0xc0)
            .expect("refresh high open-bus bits");
        machine.ppu_address = 0x3f00;
        assert_eq!(
            machine.read_ppu_register(0x2007).expect("palette read"),
            0xff
        );
        assert_eq!(machine.palette[0], 0xff);
    }

    #[test]
    fn suppresses_boundary_vblank_nmis_for_every_timing_profile() {
        for timing in [
            TimingProfile::Ntsc,
            TimingProfile::Pal,
            TimingProfile::Dendy,
        ] {
            let mut before = machine_with_chr(0, Mirroring::Horizontal, solid_tiles());
            before.timing = timing;
            before.ppu_ctrl = 0x80;
            before.ppu_scanline = before.vblank_scanline();
            before.ppu_dot = 0;
            assert_eq!(
                before.read_ppu_register(0x2002).expect("early status") & 0x80,
                0
            );
            before.clock_ppu_dot();
            assert_eq!(before.ppu_status & 0x80, 0, "{timing:?} suppression");
            assert!(!before.ppu_nmi_line, "{timing:?} NMI line");
            assert!(!before.pending_ppu_nmi, "{timing:?} pending NMI");

            let mut same = machine_with_chr(0, Mirroring::Horizontal, solid_tiles());
            same.timing = timing;
            same.ppu_ctrl = 0x80;
            same.ppu_scanline = same.vblank_scanline();
            same.ppu_dot = 0;
            same.clock_ppu_dot();
            assert!(same.ppu_nmi_line, "{timing:?} asserted NMI line");
            assert!(same.pending_ppu_nmi, "{timing:?} queued NMI");
            assert_ne!(
                same.read_ppu_register(0x2002).expect("status at vblank") & 0x80,
                0
            );
            assert!(!same.ppu_nmi_line, "{timing:?} cancelled NMI line");
            assert!(!same.pending_ppu_nmi, "{timing:?} cancelled pending NMI");
            same.request_nmi();
            same.read_ppu_register(0x2002)
                .expect("status does not cancel an external NMI");
            assert!(same.pending_nmi, "{timing:?} external NMI retained");

            let mut one_later = machine_with_chr(0, Mirroring::Horizontal, solid_tiles());
            one_later.timing = timing;
            one_later.ppu_ctrl = 0x80;
            one_later.ppu_scanline = one_later.vblank_scanline();
            one_later.ppu_dot = 0;
            one_later.clock_ppu_dot();
            one_later.clock_ppu_dot();
            assert_ne!(
                one_later
                    .read_ppu_register(0x2002)
                    .expect("status one dot after vblank")
                    & 0x80,
                0
            );
            assert!(
                !one_later.pending_ppu_nmi,
                "{timing:?} one-dot-late cancellation"
            );

            let mut late = machine_with_chr(0, Mirroring::Horizontal, solid_tiles());
            late.timing = timing;
            late.ppu_ctrl = 0x80;
            late.ppu_scanline = late.vblank_scanline();
            late.ppu_dot = 0;
            for _ in 0..3 {
                late.clock_ppu_dot();
            }
            assert_ne!(
                late.read_ppu_register(0x2002)
                    .expect("status after suppression window")
                    & 0x80,
                0
            );
            assert!(late.pending_ppu_nmi, "{timing:?} retained NMI edge");
        }
    }

    #[test]
    fn raises_nmi_edges_when_control_is_enabled_during_vblank() {
        let mut machine = machine_with_chr(0, Mirroring::Horizontal, solid_tiles());
        machine.ppu_status = 0x80;
        machine
            .write_ppu_register(0x2000, 0x80)
            .expect("enable NMI");
        assert!(machine.ppu_nmi_line);
        assert!(machine.pending_ppu_nmi);

        machine.pending_ppu_nmi = false;
        machine.write_ppu_register(0x2000, 0).expect("disable NMI");
        assert!(!machine.ppu_nmi_line);
        machine
            .write_ppu_register(0x2000, 0x80)
            .expect("re-enable NMI");
        assert!(machine.ppu_nmi_line);
        assert!(
            machine.pending_ppu_nmi,
            "a new low-to-high edge queues another NMI"
        );
        let report = machine.step().expect("PPU NMI entry");
        assert_eq!(report.interrupt, Some(InterruptKind::Nmi));
        assert!(!machine.pending_ppu_nmi);
    }

    #[test]
    fn restricts_oamdata_access_while_the_ppu_is_rendering() {
        let mut machine = machine_with_chr(0, Mirroring::Horizontal, solid_tiles());
        machine.ppu_mask = 0x18;
        machine.ppu_scanline = 32;
        machine.ppu_dot = 100;
        machine.oam_address = 0x20;
        machine.oam[0x20] = 0x55;
        machine.ppu_oam_bus = 0x5a;

        machine
            .write_ppu_register(0x2004, 0xaa)
            .expect("rendering OAMDATA write");
        assert_eq!(machine.oam[0x20], 0x55);
        assert_eq!(machine.oam_address, 0x24);
        assert_eq!(machine.ppu_io_bus, 0xaa);

        machine.oam_address = 0x20;
        assert_eq!(
            machine
                .read_ppu_register(0x2004)
                .expect("rendering OAMDATA read"),
            0x5a
        );
        assert_eq!(machine.ppu_io_bus, 0x5a);

        machine.ppu_mask = 0;
        machine
            .write_ppu_register(0x2004, 0xcc)
            .expect("blanked OAMDATA write");
        assert_eq!(machine.oam[0x20], 0xcc);
        assert_eq!(machine.oam_address, 0x21);
    }

    #[test]
    fn fetches_background_tiles_on_the_hardware_dot_cadence() {
        let mut machine = machine_with_chr(0, Mirroring::Horizontal, solid_tiles());
        machine.write_ppu(0x2000, 1).expect("tile index");
        machine.write_ppu(0x23c0, 2).expect("attribute byte");
        machine.ppu_mask = 0x08;
        machine.ppu_scanline = machine.pre_render_scanline();
        machine.ppu_dot = 320;

        machine.clock_ppu_dot();
        assert_eq!(machine.ppu_dot, 321);
        assert_eq!(machine.ppu_fetch_address, 0x2000);
        assert_eq!(machine.background_next_tile, 1);
        machine.clock_ppu_dot();
        machine.clock_ppu_dot();
        assert_eq!(machine.ppu_dot, 323);
        assert_eq!(machine.ppu_fetch_address, 0x23c0);
        assert_eq!(machine.background_next_attribute, 2);
        machine.clock_ppu_dot();
        machine.clock_ppu_dot();
        assert_eq!(machine.ppu_dot, 325);
        assert_eq!(machine.ppu_fetch_address, 0x0010);
        assert_eq!(machine.background_next_pattern_low, 0xff);
        machine.clock_ppu_dot();
        machine.clock_ppu_dot();
        assert_eq!(machine.ppu_dot, 327);
        assert_eq!(machine.ppu_fetch_address, 0x0018);
        assert_eq!(machine.background_next_pattern_high, 0);
        machine.clock_ppu_dot();
        assert_eq!(machine.ppu_dot, 328);
        assert_eq!(machine.background_pattern_shift_low & 0xff, 0xff);
        assert_eq!(machine.background_attribute_shift_low & 0xff, 0);
        assert_eq!(machine.background_attribute_shift_high & 0xff, 0xff);
        assert_eq!(machine.ppu_address & 0x001f, 1);
    }

    #[test]
    fn evaluates_fetches_and_activates_sprites_at_exact_windows() {
        let mut machine = machine_with_chr(0, Mirroring::Horizontal, solid_tiles());
        for index in 0..9 {
            machine.oam[index * 4] = 0xff;
            machine.oam[index * 4 + 1] = 2;
            machine.oam[index * 4 + 3] = (index * 8) as u8;
        }
        machine.ppu_mask = 0x10;
        machine.ppu_scanline = machine.pre_render_scanline();
        machine.ppu_dot = 0;

        while machine.ppu_dot < 64 {
            machine.clock_ppu_dot();
        }
        assert_eq!(machine.secondary_oam, [0xff; 32]);
        assert_eq!(machine.ppu_oam_bus, 0xff);

        while machine.ppu_dot < 66 {
            machine.clock_ppu_dot();
        }
        assert_eq!(machine.ppu_oam_bus, 0xff);
        assert_eq!(
            machine.read_ppu_register(0x2004).expect("evaluation bus"),
            0xff
        );

        while machine.ppu_dot < 130 {
            machine.clock_ppu_dot();
        }
        assert_eq!(machine.secondary_oam_count, 8);
        assert_ne!(machine.ppu_status & 0x20, 0, "sprite overflow search");

        while machine.ppu_dot < 320 {
            machine.clock_ppu_dot();
        }
        assert_eq!(machine.next_scanline_sprite_count, 8);
        assert_eq!(machine.next_scanline_sprites[0].index, 0);
        assert_eq!(machine.next_scanline_sprites[0].pattern_low, 0xff);
        assert_eq!(machine.next_scanline_sprites[0].x, 0);

        while !(machine.ppu_scanline == 0 && machine.ppu_dot == 0) {
            machine.clock_ppu_dot();
        }
        assert_eq!(machine.scanline_sprite_count, 8);
        assert_eq!(machine.scanline_sprites[0].index, 0);
    }

    #[test]
    fn reproduces_the_sprite_overflow_diagonal_scan_bug() {
        let mut machine = machine_with_chr(0, Mirroring::Horizontal, solid_tiles());
        for index in 0..8 {
            machine.oam[index * 4] = 0xff;
        }
        machine.oam[8 * 4] = 0;
        machine.oam[9 * 4] = 0;
        machine.oam[9 * 4 + 1] = 0xff;
        machine.ppu_mask = 0x08;
        machine.ppu_scanline = machine.pre_render_scanline();
        machine.ppu_dot = 0;

        while machine.ppu_dot < 132 {
            machine.clock_ppu_dot();
        }

        assert_eq!(machine.secondary_oam_count, 8);
        assert_eq!(machine.sprite_evaluation_index, 10);
        assert_eq!(machine.sprite_evaluation_byte, 2);
        assert_ne!(
            machine.ppu_status & 0x20,
            0,
            "sprite 10 tile byte is interpreted as a Y coordinate"
        );
    }

    #[test]
    fn renders_scrolled_background_pixels_to_palette_indices() {
        let mut machine = machine_with_chr(0, Mirroring::Horizontal, solid_tiles());
        machine.write_ppu(0x2001, 1).expect("second tile");
        machine.write_ppu(0x3f01, 0x21).expect("background palette");
        machine
            .write_ppu_register(0x2005, 8)
            .expect("horizontal scroll");
        machine
            .write_ppu_register(0x2005, 0)
            .expect("vertical scroll");
        machine
            .write_ppu_register(0x2001, 0x0a)
            .expect("background rendering");

        clock_first_rendered_scanline(&mut machine, 3);

        assert_eq!(&machine.framebuffer()[..3], &[0x21; 3]);
        assert_eq!(
            machine.ppu_position(),
            PpuPosition {
                frame: 1,
                scanline: 0,
                dot: 3,
            }
        );
        assert_eq!(machine.snapshot().framebuffer[0], 0x21);
    }

    #[test]
    fn composes_sprites_and_sets_sprite_status_flags() {
        let mut machine = machine_with_chr(0, Mirroring::Horizontal, solid_tiles());
        machine.write_ppu(0x2000, 1).expect("background tile");
        machine.write_ppu(0x3f01, 0x11).expect("background palette");
        machine.write_ppu(0x3f11, 0x2a).expect("sprite palette");
        machine.oam[0] = 0xff;
        machine.oam[1] = 2;
        machine.oam[2] = 0;
        machine.oam[3] = 0;
        machine
            .write_ppu_register(0x2001, 0x1e)
            .expect("background and sprite rendering");

        clock_first_rendered_scanline(&mut machine, 3);

        assert_eq!(&machine.framebuffer()[..3], &[0x2a; 3]);
        assert_ne!(machine.ppu_status & 0x40, 0, "sprite zero hit");

        let mut overflow = machine_with_chr(0, Mirroring::Horizontal, solid_tiles());
        for index in 0..9 {
            overflow.oam[index * 4] = 0xff;
            overflow.oam[index * 4 + 1] = 2;
            overflow.oam[index * 4 + 3] = (index * 8) as u8;
        }
        overflow.ppu_mask = 0x14;
        clock_first_rendered_scanline(&mut overflow, 1);
        assert_ne!(overflow.ppu_status & 0x20, 0, "sprite overflow");
    }

    #[test]
    fn renderer_observes_mapper_three_chr_bank_selection() {
        let mut chr = vec![0; 16 * 1024];
        chr[16..24].fill(0xff);
        chr[8 * 1024 + 24..8 * 1024 + 32].fill(0xff);
        let mut machine = machine_with_chr(3, Mirroring::Vertical, chr);
        machine.write_ppu(0x2000, 1).expect("tile selection");
        machine.write_ppu(0x3f01, 0x12).expect("pattern value one");
        machine.write_ppu(0x3f02, 0x24).expect("pattern value two");
        machine.mapper_state.chr_bank = 1;
        machine.ppu_mask = 0x0a;

        clock_first_rendered_scanline(&mut machine, 1);

        assert_eq!(machine.framebuffer()[0], 0x24);
    }

    #[test]
    fn clocks_region_vblank_boundaries_and_ntsc_odd_frames() {
        for (timing, boundary) in [
            (TimingProfile::Ntsc, 27_394),
            (TimingProfile::Pal, 25_682),
            (TimingProfile::Dendy, 33_078),
        ] {
            let mut machine = machine_with_chr(0, Mirroring::Horizontal, solid_tiles());
            machine.timing = timing;
            machine.set_cycles_for_test(boundary - 1);
            machine.advance_cycles(1);
            assert_ne!(machine.ppu_status & 0x80, 0, "{timing:?} vblank");
            assert!(
                machine
                    .events
                    .iter()
                    .any(|event| { event.kind == EventKind::VBlank && event.cycle == boundary })
            );
        }

        let mut ntsc = machine_with_chr(0, Mirroring::Horizontal, solid_tiles());
        ntsc.ppu_mask = 0x08;
        ntsc.advance_cycles(59_561);
        let frame_cycles = ntsc
            .events
            .iter()
            .filter(|event| event.kind == EventKind::Frame)
            .map(|event| event.cycle)
            .collect::<Vec<_>>();
        assert_eq!(frame_cycles, vec![29_781, 59_561]);
        assert_eq!(ntsc.frames, 2);
    }

    #[test]
    fn rendering_reads_follow_cartridge_nametable_mirroring() {
        let mut horizontal = machine_with_chr(0, Mirroring::Horizontal, solid_tiles());
        horizontal.write_ppu(0x2000, 0x31).expect("first nametable");
        assert_eq!(
            horizontal.peek_ppu(0x2400).expect("horizontal mirror"),
            0x31
        );
        horizontal
            .write_ppu(0x2800, 0x42)
            .expect("second nametable");
        assert_eq!(
            horizontal.peek_ppu(0x2c00).expect("horizontal mirror"),
            0x42
        );

        let mut vertical = machine_with_chr(0, Mirroring::Vertical, solid_tiles());
        vertical.write_ppu(0x2000, 0x53).expect("first nametable");
        assert_eq!(vertical.peek_ppu(0x2800).expect("vertical mirror"), 0x53);
        vertical.write_ppu(0x2400, 0x64).expect("second nametable");
        assert_eq!(vertical.peek_ppu(0x2c00).expect("vertical mirror"), 0x64);
    }

    #[test]
    fn exposes_and_clears_apu_frame_irq_through_status_reads() {
        let mut machine = machine_with_chr(0, Mirroring::Horizontal, solid_tiles());
        machine.advance_cycles(29_829);
        assert!(machine.apu_state().frame_irq_pending);
        assert_ne!(
            machine.peek(0x4015).expect("observational APU status") & 0x40,
            0
        );
        assert!(machine.apu_state().frame_irq_pending);

        assert_ne!(machine.cpu_read(0x4015).expect("APU status read") & 0x40, 0);
        assert!(!machine.apu_state().frame_irq_pending);

        machine.advance_cycles(29_829);
        machine.cpu.set_flag(FLAG_INTERRUPT_DISABLE, false);
        let report = machine.step().expect("APU frame IRQ entry");
        assert_eq!(report.interrupt, Some(InterruptKind::Irq));
        assert_eq!(machine.snapshot().apu, machine.apu_state());
    }

    #[test]
    fn stalls_cpu_for_traced_dmc_fetch_and_delivers_irq() {
        let mut machine = machine_with_chr(0, Mirroring::Horizontal, solid_tiles());
        machine.reset().expect("reset");
        machine.cpu.set_flag(FLAG_INTERRUPT_DISABLE, false);
        machine.apu.write_register(0x4010, 0x80);
        machine.apu.write_register(0x4012, 0);
        machine.apu.write_register(0x4013, 0);
        machine.apu.write_register(0x4015, 0x10);

        let mut accesses = Vec::new();
        let report = loop {
            let cycle = machine.step_cycle().expect("DMC and NOP clock");
            accesses.push(cycle.access.expect("one access per clock"));
            if let Some(report) = cycle.step {
                break report;
            }
        };
        assert_eq!(report.cycles, 6);
        assert_eq!(
            accesses[..4]
                .iter()
                .map(|access| (access.address, access.dummy, access.source))
                .collect::<Vec<_>>(),
            vec![
                (0x8000, true, BusAccessSource::DmcDma),
                (0x8000, true, BusAccessSource::DmcDma),
                (0x8000, true, BusAccessSource::DmcDma),
                (0xc000, false, BusAccessSource::DmcDma),
            ]
        );
        assert_eq!(accesses[3].value, 0xea);
        assert!(machine.apu_state().dmc_irq_pending);
        assert_eq!(machine.peek(0x4015).expect("DMC status") & 0x90, 0x80);
        assert!(machine.events.iter().any(|event| {
            event.kind == EventKind::Dma
                && event.address == Some(0xc000)
                && event.value == Some(0xea)
        }));

        let interrupt = machine.step().expect("DMC IRQ entry");
        assert_eq!(interrupt.interrupt, Some(InterruptKind::Irq));
        assert_ne!(machine.cpu_read(0x4015).expect("status read") & 0x80, 0);
        assert!(machine.apu_state().dmc_irq_pending);
        machine.cpu_write(0x4015, 0).expect("disable DMC");
        assert!(!machine.apu_state().dmc_irq_pending);
    }

    #[test]
    fn dmc_fetch_preempts_and_extends_oam_dma() {
        let mut machine = machine_with_chr(0, Mirroring::Horizontal, solid_tiles());
        machine.prg_rom[..7].copy_from_slice(&[0xea, 0x8d, 0x14, 0x40, 0x8d, 0x14, 0x40]);
        for (index, byte) in machine.ram.iter_mut().enumerate().take(256) {
            *byte = index as u8;
        }
        machine.reset().expect("reset");
        machine.apu.write_register(0x4010, 0x4f);
        machine.apu.write_register(0x4012, 0);
        machine.apu.write_register(0x4013, 1);
        machine.apu.write_register(0x4015, 0x10);
        machine.step().expect("NOP with initial DMC fetch");
        machine.step().expect("first OAM DMA primes DMC output");

        let mut accesses = Vec::new();
        let report = loop {
            let cycle = machine.step_cycle().expect("combined DMA clock");
            accesses.push(cycle.access.expect("one access per DMA clock"));
            if let Some(report) = cycle.step {
                break report;
            }
        };
        let dmc = accesses
            .iter()
            .filter(|access| access.source == BusAccessSource::DmcDma)
            .collect::<Vec<_>>();
        assert_eq!(dmc.len(), 4, "APU state: {:?}", machine.apu_state());
        assert_eq!(dmc[3].address, 0xc001);
        assert!(!dmc[3].dummy);
        assert_eq!(
            accesses
                .iter()
                .filter(|access| access.source == BusAccessSource::OamDma)
                .count(),
            512
        );
        assert!(matches!(report.cycles, 521 | 522));
        assert_eq!(&machine.oam()[..], &machine.ram()[..256]);
    }
}
