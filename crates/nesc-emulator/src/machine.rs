//! Deterministic bounded NES machine execution.

use std::collections::VecDeque;
use std::error::Error;
use std::fmt;

use nesc_disasm::{AddressingMode, Mnemonic, opcode};
use nesc_rom::{CpuAddress, Mapper, MapperState, Mirroring, PpuAddress, Region, Rom};

use crate::cpu::{
    CpuState, FLAG_BREAK, FLAG_CARRY, FLAG_DECIMAL, FLAG_INTERRUPT_DISABLE, FLAG_NEGATIVE,
    FLAG_OVERFLOW, FLAG_UNUSED, FLAG_ZERO,
};

const IRQ_VECTOR: u16 = 0xfffe;
const RESET_VECTOR: u16 = 0xfffc;
const NMI_VECTOR: u16 = 0xfffa;
const STACK_BASE: u16 = 0x0100;

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

    const fn frames_at(self, cycles: u64) -> u64 {
        let (numerator, denominator) = self.frame_cycle_ratio();
        cycles.saturating_mul(denominator) / numerator
    }

    const fn frame_boundary(self, frame: u64) -> u64 {
        let (numerator, denominator) = self.frame_cycle_ratio();
        div_ceil(frame.saturating_mul(numerator), denominator)
    }

    const fn vblank_boundary(self, frame: u64) -> u64 {
        let (frame_numerator, frame_denominator) = self.frame_cycle_ratio();
        let (vblank_numerator, vblank_denominator) = self.vblank_cycle_ratio();
        let frame_offset = frame
            .saturating_mul(frame_numerator)
            .saturating_mul(vblank_denominator)
            / frame_denominator;
        div_ceil(
            frame_offset.saturating_add(vblank_numerator),
            vblank_denominator,
        )
    }

    fn from_region(region: Region) -> Option<Self> {
        match region {
            Region::Ntsc => Some(Self::Ntsc),
            Region::Pal => Some(Self::Pal),
            Region::Dendy => Some(Self::Dendy),
            Region::MultiRegion => None,
        }
    }
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
    pub chr_ram: Box<[u8; 0x2000]>,
    pub palette: Box<[u8; 32]>,
    pub oam: Box<[u8; 256]>,
    pub nametable_ram: Box<[u8; 0x1000]>,
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
    ppu_address_high: bool,
    ppu_scroll_high: bool,
    ppu_data_buffer: u8,
    controller_state: [u8; 2],
    controller_shift: [u8; 2],
    controller_strobe: bool,
    mapper: Mapper,
    mapper_state: MapperState,
    mirroring: Mirroring,
    pending_nmi: bool,
    irq_line: bool,
    stall_cycles: u64,
    events: VecDeque<ObservableEvent>,
    event_capacity: usize,
    dropped_events: u64,
    trap_address: Option<u16>,
    trap_reason_address: Option<u16>,
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
        Ok(Self {
            cpu: CpuState::default(),
            cycles: 0,
            instructions: 0,
            frames: 0,
            timing,
            ram: Box::new([0; 0x800]),
            prg_ram: Box::new([0; 0x2000]),
            apu_io: Box::new([0; 0x18]),
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
            ppu_address_high: true,
            ppu_scroll_high: true,
            ppu_data_buffer: 0,
            controller_state: [0; 2],
            controller_shift: [0; 2],
            controller_strobe: false,
            mapper,
            mapper_state: MapperState::default(),
            mirroring: rom.metadata.mirroring,
            pending_nmi: false,
            irq_line: false,
            stall_cycles: 0,
            events: VecDeque::new(),
            event_capacity: config.event_capacity,
            dropped_events: 0,
            trap_address: config.trap_address,
            trap_reason_address: config.trap_reason_address,
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
        self.pending_nmi = false;
        self.irq_line = false;
        self.cpu.pc = self.read_word(RESET_VECTOR)?;
        self.advance_cycles(7);
        Ok(())
    }

    /// Executes one instruction or pending interrupt.
    ///
    /// # Errors
    ///
    /// Fails on undocumented opcodes or required unmapped bus accesses.
    pub fn step(&mut self) -> Result<StepReport, EmulatorError> {
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
        if self.pending_nmi {
            self.pending_nmi = false;
            return self.handle_external_interrupt(InterruptKind::Nmi, NMI_VECTOR);
        }
        if self.irq_line && !self.cpu.flag(FLAG_INTERRUPT_DISABLE) {
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
        self.advance_cycles(cycles);
        Ok(StepReport {
            pc: instruction_pc,
            opcode: Some(opcode_byte),
            cycles,
            interrupt: None,
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
            0x2000..=0x3fff => match 0x2000 | (address & 7) {
                0x2000 => Ok(self.ppu_ctrl),
                0x2001 => Ok(self.ppu_mask),
                0x2002 => Ok(self.ppu_status),
                0x2003 => Ok(self.oam_address),
                0x2004 => Ok(self.oam[usize::from(self.oam_address)]),
                0x2007 => self.peek_ppu(self.ppu_address),
                _ => Ok(0),
            },
            0x4000..=0x4015 => Ok(self.apu_io[usize::from(address - 0x4000)]),
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

    #[must_use]
    pub const fn instructions(&self) -> u64 {
        self.instructions
    }

    #[must_use]
    pub const fn frames(&self) -> u64 {
        self.frames
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

    #[must_use]
    pub fn apu_io(&self) -> &[u8; 0x18] {
        &self.apu_io
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
            chr_ram: self.chr_ram.clone(),
            palette: self.palette.clone(),
            oam: self.oam.clone(),
            nametable_ram: self.nametable_ram.clone(),
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
        self.advance_cycles(7);
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
        let value = match address {
            0x0000..=0x1fff => self.ram[usize::from(address & 0x07ff)],
            0x2000..=0x3fff => self.read_ppu_register(0x2000 | (address & 7))?,
            0x4000..=0x4015 => self.apu_io[usize::from(address - 0x4000)],
            0x4016 | 0x4017 => self.read_controller(usize::from(address - 0x4016)),
            0x4018..=0x5fff => 0,
            0x6000..=0x7fff => self.prg_ram[usize::from(address - 0x6000)],
            0x8000..=0xffff => self
                .mapper
                .map_cpu(CpuAddress(address), self.mapper_state)
                .and_then(|offset| self.prg_rom.get(offset.0).copied())
                .ok_or_else(|| self.failure(format!("unmapped PRG read ${address:04X}")))?,
        };
        if (0x2000..=0x4017).contains(&address) {
            self.record(EventKind::VolatileRead, Some(address), Some(value), None);
        }
        Ok(value)
    }

    fn cpu_write(&mut self, address: u16, value: u8) -> Result<(), EmulatorError> {
        match address {
            0x0000..=0x1fff => self.ram[usize::from(address & 0x07ff)] = value,
            0x2000..=0x3fff => self.write_ppu_register(0x2000 | (address & 7), value)?,
            0x4000..=0x4013 | 0x4015 | 0x4017 => {
                self.apu_io[usize::from(address - 0x4000)] = value;
            }
            0x4014 => self.oam_dma(value)?,
            0x4016 => self.write_controller_strobe(value),
            0x4018..=0x5fff => {}
            0x6000..=0x7fff => self.prg_ram[usize::from(address - 0x6000)] = value,
            0x8000..=0xffff => {
                self.mapper
                    .cpu_write(CpuAddress(address), value, &mut self.mapper_state);
                self.record(EventKind::MapperWrite, Some(address), Some(value), None);
                return Ok(());
            }
        }
        if (0x2000..=0x4017).contains(&address) {
            self.record(EventKind::VolatileWrite, Some(address), Some(value), None);
        }
        Ok(())
    }

    fn read_ppu_register(&mut self, register: u16) -> Result<u8, EmulatorError> {
        match register {
            0x2002 => {
                let value = self.ppu_status;
                self.ppu_status &= !0x80;
                self.ppu_address_high = true;
                self.ppu_scroll_high = true;
                Ok(value)
            }
            0x2004 => Ok(self.oam[usize::from(self.oam_address)]),
            0x2007 => {
                let address = self.ppu_address;
                let value = self.peek_ppu(address)?;
                let output = if address & 0x3fff >= 0x3f00 {
                    self.ppu_data_buffer = self.peek_ppu(address.wrapping_sub(0x1000))?;
                    value
                } else {
                    let buffered = self.ppu_data_buffer;
                    self.ppu_data_buffer = value;
                    buffered
                };
                self.increment_ppu_address();
                Ok(output)
            }
            _ => Ok(0),
        }
    }

    fn write_ppu_register(&mut self, register: u16, value: u8) -> Result<(), EmulatorError> {
        match register {
            0x2000 => {
                let nmi_was_enabled = self.ppu_ctrl & 0x80 != 0;
                self.ppu_ctrl = value;
                if !nmi_was_enabled && value & 0x80 != 0 && self.ppu_status & 0x80 != 0 {
                    self.pending_nmi = true;
                }
            }
            0x2001 => self.ppu_mask = value,
            0x2003 => self.oam_address = value,
            0x2004 => {
                self.oam[usize::from(self.oam_address)] = value;
                self.oam_address = self.oam_address.wrapping_add(1);
            }
            0x2005 => self.ppu_scroll_high = !self.ppu_scroll_high,
            0x2006 => {
                if self.ppu_address_high {
                    self.ppu_address = u16::from(value & 0x3f) << 8;
                } else {
                    self.ppu_address = (self.ppu_address & 0xff00) | u16::from(value);
                }
                self.ppu_address_high = !self.ppu_address_high;
            }
            0x2007 => {
                self.write_ppu(self.ppu_address, value)?;
                self.increment_ppu_address();
            }
            _ => {}
        }
        Ok(())
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
            let index = self.oam_address.wrapping_add(offset);
            self.oam[usize::from(index)] = value;
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
        let before = self.cycles;
        let after = before.saturating_add(cycles);
        let before_frame = self.timing.frames_at(before);
        let after_frame = self.timing.frames_at(after);
        let vblank = self.timing.vblank_boundary(before_frame);
        if before < vblank && after >= vblank {
            self.ppu_status |= 0x80;
            self.record_at(
                EventKind::VBlank,
                Some(0x2002),
                Some(self.ppu_status),
                None,
                vblank,
                self.cpu.pc,
            );
            if self.ppu_ctrl & 0x80 != 0 {
                self.pending_nmi = true;
            }
        }
        if after_frame > before_frame {
            self.frames = after_frame;
            self.ppu_status &= !0x80;
            self.record_at(
                EventKind::Frame,
                None,
                None,
                None,
                self.timing.frame_boundary(after_frame),
                self.cpu.pc,
            );
            let next_vblank = self.timing.vblank_boundary(after_frame);
            if after >= next_vblank {
                self.ppu_status |= 0x80;
                self.record_at(
                    EventKind::VBlank,
                    Some(0x2002),
                    Some(self.ppu_status),
                    None,
                    next_vblank,
                    self.cpu.pc,
                );
                if self.ppu_ctrl & 0x80 != 0 {
                    self.pending_nmi = true;
                }
            }
        }
        self.cycles = after;
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

const fn div_ceil(numerator: u64, denominator: u64) -> u64 {
    numerator / denominator + if numerator % denominator == 0 { 0 } else { 1 }
}
