use std::collections::{BTreeMap, VecDeque};
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use nesc_disasm::{AddressingMode, opcode};
use nesc_emulator::{
    BusAccess, BusAccessKind, CycleReport, EmulatorConfig, Machine, StepReport, Termination,
    TimingProfile,
};

const MAX_METADATA_BYTES: u64 = 16 * 1024 * 1024;
const MAX_ROM_BYTES: u64 = 64 * 1024 * 1024;
const MAX_METADATA_ENTRIES: usize = 100_000;
const MAX_MEMORY_LENGTH: usize = 256;
const TRACE_CAPACITY: usize = 256;
const CYCLE_TRACE_CAPACITY: usize = 4_096;

/// Bank-qualified debugger address.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct DebugAddress {
    pub bank: Option<u16>,
    pub address: u16,
}

impl fmt::Display for DebugAddress {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(bank) = self.bank {
            write!(formatter, "{bank:03}:${:04X}", self.address)
        } else {
            write!(formatter, "${:04X}", self.address)
        }
    }
}

/// Compiler source record associated with a bank-qualified address.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceLocation {
    pub address: DebugAddress,
    pub path: PathBuf,
    pub start: usize,
    pub length: usize,
    pub symbol: String,
}

impl fmt::Display for SourceLocation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{}:{}:{} ({})",
            self.path.display(),
            self.start,
            self.length,
            self.symbol
        )
    }
}

/// Bounded execution settings and optional compiler metadata paths.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DebugSessionConfig {
    pub instruction_limit: u64,
    pub cycle_limit: u64,
    pub timing: Option<TimingProfile>,
    pub symbols_path: Option<PathBuf>,
    pub source_map_path: Option<PathBuf>,
}

impl Default for DebugSessionConfig {
    fn default() -> Self {
        Self {
            instruction_limit: 1_000_000,
            cycle_limit: 10_000_000,
            timing: None,
            symbols_path: None,
            source_map_path: None,
        }
    }
}

/// Result of one debugger command.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DebugCommandOutput {
    pub text: String,
    pub quit: bool,
}

/// Thread-safe cooperative pause signal for a running debugger session.
#[derive(Clone, Debug, Default)]
pub struct DebugPauseHandle {
    requested: Arc<AtomicBool>,
}

impl DebugPauseHandle {
    /// Requests that the session stop at its next cooperative check.
    pub fn request_pause(&self) {
        self.requested.store(true, Ordering::Release);
    }

    fn take_request(&self) -> bool {
        self.requested.swap(false, Ordering::AcqRel)
    }

    fn clear(&self) {
        self.requested.store(false, Ordering::Release);
    }
}

/// ROM debugger construction, parsing, or execution failure.
#[derive(Debug)]
pub enum DebugSessionError {
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    Emulator(nesc_emulator::EmulatorError),
    InvalidMetadata {
        path: PathBuf,
        line: usize,
        message: String,
    },
    InputTooLarge {
        path: PathBuf,
        bytes: u64,
        limit: u64,
    },
    Command(String),
}

impl fmt::Display for DebugSessionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { path, source } => {
                write!(formatter, "could not read `{}`: {source}", path.display())
            }
            Self::Emulator(error) => error.fmt(formatter),
            Self::InvalidMetadata {
                path,
                line,
                message,
            } => write!(
                formatter,
                "invalid debugger metadata `{}:{line}`: {message}",
                path.display()
            ),
            Self::InputTooLarge { path, bytes, limit } => write!(
                formatter,
                "debugger input `{}` is {bytes} bytes; limit is {limit}",
                path.display()
            ),
            Self::Command(message) => formatter.write_str(message),
        }
    }
}

impl std::error::Error for DebugSessionError {}

impl From<nesc_emulator::EmulatorError> for DebugSessionError {
    fn from(error: nesc_emulator::EmulatorError) -> Self {
        Self::Emulator(error)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WatchKind {
    Read,
    Write,
    ReadWrite,
}

impl WatchKind {
    const fn matches(self, access: BusAccessKind) -> bool {
        matches!(self, Self::ReadWrite)
            || matches!(
                (self, access),
                (Self::Read, BusAccessKind::Read) | (Self::Write, BusAccessKind::Write)
            )
    }
}

impl fmt::Display for WatchKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Read => formatter.write_str("read"),
            Self::Write => formatter.write_str("write"),
            Self::ReadWrite => formatter.write_str("read/write"),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Watchpoint {
    address: u16,
    kind: WatchKind,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct DebugSymbol {
    address: DebugAddress,
    name: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct TraceEntry {
    address: DebugAddress,
    opcode: Option<u8>,
    cycles: u64,
    source: Option<SourceLocation>,
}

enum InstructionExecution {
    Complete(StepReport),
    Watchpoint(String),
}

/// Deterministic ROM debugger session.
pub struct DebugSession {
    machine: Machine,
    mapper: u16,
    prg_banks: usize,
    symbols: Vec<DebugSymbol>,
    symbols_by_name: BTreeMap<String, DebugAddress>,
    sources: Vec<SourceLocation>,
    breakpoints: BTreeMap<u32, DebugAddress>,
    watchpoints: BTreeMap<u32, Watchpoint>,
    next_stop_id: u32,
    trace_enabled: bool,
    trace: VecDeque<TraceEntry>,
    cycle_trace: VecDeque<BusAccess>,
    instruction_limit: u64,
    cycle_limit: u64,
    pause: DebugPauseHandle,
    pending_trace_address: Option<DebugAddress>,
}

impl DebugSession {
    /// Loads a ROM and optional sibling `.sym` and `.source-map` files.
    pub fn load(rom_path: &Path, config: DebugSessionConfig) -> Result<Self, DebugSessionError> {
        let bytes = read_bounded(rom_path, MAX_ROM_BYTES)?;
        let symbol_path = config
            .symbols_path
            .clone()
            .or_else(|| sibling_path(rom_path, "sym").filter(|path| path.is_file()));
        let source_map_path = config
            .source_map_path
            .clone()
            .or_else(|| sibling_path(rom_path, "source-map").filter(|path| path.is_file()));
        let symbols = symbol_path
            .as_deref()
            .map(read_metadata)
            .transpose()?
            .unwrap_or_default();
        let source_map = source_map_path
            .as_deref()
            .map(read_metadata)
            .transpose()?
            .unwrap_or_default();
        Self::from_rom_bytes(
            &bytes,
            &symbols,
            symbol_path.as_deref(),
            &source_map,
            source_map_path.as_deref(),
            config,
        )
    }

    /// Creates a session from ROM bytes and compiler metadata text.
    pub fn from_rom_bytes(
        bytes: &[u8],
        symbols: &str,
        symbols_path: Option<&Path>,
        source_map: &str,
        source_map_path: Option<&Path>,
        config: DebugSessionConfig,
    ) -> Result<Self, DebugSessionError> {
        if config.instruction_limit == 0 || config.cycle_limit == 0 {
            return Err(DebugSessionError::Command(
                "debugger execution limits must be greater than zero".to_owned(),
            ));
        }
        let rom = nesc_rom::parse(bytes)
            .map_err(|error| DebugSessionError::Command(format!("ROM is invalid: {error}")))?;
        let mapper = rom.metadata.mapper;
        let prg_banks = rom.prg_rom.len() / 0x4000;
        let parsed_symbols = parse_symbols(
            symbols,
            symbols_path.unwrap_or_else(|| Path::new("<symbols>")),
        )?;
        let sources = parse_source_map(
            source_map,
            source_map_path.unwrap_or_else(|| Path::new("<source-map>")),
        )?;
        let symbols_by_name = parsed_symbols
            .iter()
            .map(|symbol| (symbol.name.clone(), symbol.address))
            .collect();
        let mut machine = Machine::from_rom(
            rom,
            EmulatorConfig {
                timing: config.timing,
                event_capacity: 65_536,
                ..EmulatorConfig::default()
            },
        )?;
        machine.reset()?;
        Ok(Self {
            machine,
            mapper,
            prg_banks,
            symbols: parsed_symbols,
            symbols_by_name,
            sources,
            breakpoints: BTreeMap::new(),
            watchpoints: BTreeMap::new(),
            next_stop_id: 1,
            trace_enabled: false,
            trace: VecDeque::new(),
            cycle_trace: VecDeque::new(),
            instruction_limit: config.instruction_limit,
            cycle_limit: config.cycle_limit,
            pause: DebugPauseHandle::default(),
            pending_trace_address: None,
        })
    }

    /// Executes one debugger command.
    pub fn execute_command(
        &mut self,
        command: &str,
    ) -> Result<DebugCommandOutput, DebugSessionError> {
        let command = command.trim();
        if command.is_empty() {
            return Ok(output(String::new()));
        }
        let mut parts = command.split_whitespace();
        let name = parts.next().expect("nonempty command has a name");
        let arguments = parts.collect::<Vec<_>>();
        let text = match name {
            "run" => {
                require_count(name, &arguments, 0)?;
                self.machine.reset()?;
                self.trace.clear();
                self.cycle_trace.clear();
                self.resume(false)?
            }
            "continue" | "c" => {
                require_count(name, &arguments, 0)?;
                self.resume(true)?
            }
            "pause" => {
                require_count(name, &arguments, 0)?;
                self.pause.clear();
                "Execution is paused.\n".to_owned()
            }
            "step" | "s" => {
                require_count(name, &arguments, 0)?;
                self.step_once("instruction step")?
            }
            "step-cycle" => {
                require_count(name, &arguments, 0)?;
                self.step_cycle()?
            }
            "step-frame" => {
                require_count(name, &arguments, 0)?;
                self.step_frame()?
            }
            "step-source" => {
                require_count(name, &arguments, 0)?;
                self.step_source()?
            }
            "next" => {
                require_count(name, &arguments, 0)?;
                self.next()?
            }
            "finish" => {
                require_count(name, &arguments, 0)?;
                self.finish()?
            }
            "break" => self.add_breakpoint(&arguments)?,
            "delete" => self.delete_stop(&arguments)?,
            "watch" => self.add_watchpoint(&arguments, WatchKind::ReadWrite)?,
            "watch-read" => self.add_watchpoint(&arguments, WatchKind::Read)?,
            "watch-write" => self.add_watchpoint(&arguments, WatchKind::Write)?,
            "registers" => {
                require_count(name, &arguments, 0)?;
                self.render_registers()
            }
            "memory" => self.render_memory_command(&arguments)?,
            "disassemble" => self.render_disassembly_command(&arguments)?,
            "stack" => {
                require_count(name, &arguments, 0)?;
                self.render_stack()?
            }
            "source" => {
                require_count(name, &arguments, 0)?;
                self.render_source()
            }
            "symbols" => {
                require_count(name, &arguments, 0)?;
                self.render_symbols()
            }
            "ppu" => {
                require_count(name, &arguments, 0)?;
                self.render_ppu()?
            }
            "apu" => {
                require_count(name, &arguments, 0)?;
                self.render_apu()
            }
            "cartridge" => {
                require_count(name, &arguments, 0)?;
                self.render_cartridge()
            }
            "trace" => self.trace_command(&arguments)?,
            "reset" => {
                require_count(name, &arguments, 0)?;
                self.machine.reset()?;
                self.trace.clear();
                self.cycle_trace.clear();
                format!("Reset at {}\n", self.current_address())
            }
            "help" => help_text().to_owned(),
            "quit" | "q" => {
                require_count(name, &arguments, 0)?;
                return Ok(DebugCommandOutput {
                    text: String::new(),
                    quit: true,
                });
            }
            _ => {
                return Err(DebugSessionError::Command(format!(
                    "unknown debugger command `{name}`; use `help`"
                )));
            }
        };
        Ok(output(text))
    }

    /// Current bank-qualified program counter.
    #[must_use]
    pub fn current_address(&self) -> DebugAddress {
        let address = self.machine.cpu().pc;
        DebugAddress {
            bank: self.machine.mapped_prg_bank(address),
            address,
        }
    }

    /// One-line description printed when a session opens.
    #[must_use]
    pub fn greeting(&self) -> String {
        format!(
            "Loaded Mapper {} ROM with {} PRG banks at {}\nType `help` for debugger commands.\n",
            self.mapper,
            self.prg_banks,
            self.current_address()
        )
    }

    /// Returns a signal that another thread may use to pause bounded execution.
    #[must_use]
    pub fn pause_handle(&self) -> DebugPauseHandle {
        self.pause.clone()
    }

    fn step_once(&mut self, reason: &str) -> Result<String, DebugSessionError> {
        let report = match self.execute_one()? {
            InstructionExecution::Complete(report) => report,
            InstructionExecution::Watchpoint(stop) => return Ok(stop),
        };
        if let Some(termination) = report.termination {
            return Ok(self.render_termination(termination));
        }
        Ok(self.render_stop(reason))
    }

    fn step_cycle(&mut self) -> Result<String, DebugSessionError> {
        let cycle = self.execute_cycle()?;
        if let Some(stop) = self.watchpoint_stop_for(cycle.access) {
            return Ok(stop);
        }
        if let Some(report) = cycle.step {
            if let Some(termination) = report.termination {
                return Ok(self.render_termination(termination));
            }
        }
        let position = self.machine.ppu_position();
        let state = if cycle.instruction_complete {
            "instruction complete"
        } else {
            "instruction pending"
        };
        Ok(format!(
            "Cycle {}: {state}; PPU frame {}, scanline {}, dot {}\n{}",
            cycle.cycle,
            position.frame,
            position.scanline,
            position.dot,
            self.render_registers()
        ))
    }

    fn resume(&mut self, skip_current_breakpoint: bool) -> Result<String, DebugSessionError> {
        let initial_instructions = self.machine.instructions();
        let initial_cycles = self.machine.cycles();
        let mut first = true;
        loop {
            if self.pause.take_request() {
                return Ok(self.render_stop("pause requested"));
            }
            if !first || !skip_current_breakpoint {
                if let Some((id, _)) = self.breakpoint_at_current() {
                    return Ok(self.render_stop(&format!("breakpoint {id}")));
                }
            }
            first = false;
            if self
                .machine
                .instructions()
                .saturating_sub(initial_instructions)
                >= self.instruction_limit
            {
                return Ok(self.render_stop("instruction limit"));
            }
            if self.machine.cycles().saturating_sub(initial_cycles) >= self.cycle_limit {
                return Ok(self.render_stop("cycle limit"));
            }
            let report = loop {
                if self.pause.take_request() {
                    return Ok(self.render_stop("pause requested"));
                }
                if self.machine.cycles().saturating_sub(initial_cycles) >= self.cycle_limit {
                    return Ok(self.render_stop("cycle limit"));
                }
                let cycle = self.execute_cycle()?;
                if let Some(stop) = self.watchpoint_stop_for(cycle.access) {
                    return Ok(stop);
                }
                if let Some(report) = cycle.step {
                    break report;
                }
            };
            if let Some(termination) = report.termination {
                return Ok(self.render_termination(termination));
            }
        }
    }

    fn step_frame(&mut self) -> Result<String, DebugSessionError> {
        let frame = self.machine.frames();
        let initial_instructions = self.machine.instructions();
        let initial_cycles = self.machine.cycles();
        while self.machine.frames() == frame {
            if self.pause.take_request() {
                return Ok(self.render_stop("pause requested"));
            }
            if self.limit_reached(initial_instructions, initial_cycles) {
                return Ok(self.render_stop("execution limit before next frame"));
            }
            let cycle = self.execute_cycle()?;
            if let Some(stop) = self.watchpoint_stop_for(cycle.access) {
                return Ok(stop);
            }
            if let Some(report) = cycle.step {
                if let Some(termination) = report.termination {
                    return Ok(self.render_termination(termination));
                }
                if let Some(stop) = self.breakpoint_stop() {
                    return Ok(stop);
                }
            }
        }
        Ok(self.render_stop("frame boundary"))
    }

    fn step_source(&mut self) -> Result<String, DebugSessionError> {
        let initial_source = self.source_for(self.current_address()).cloned();
        let initial_instructions = self.machine.instructions();
        let initial_cycles = self.machine.cycles();
        loop {
            if self.pause.take_request() {
                return Ok(self.render_stop("pause requested"));
            }
            if self.limit_reached(initial_instructions, initial_cycles) {
                return Ok(self.render_stop("execution limit before source change"));
            }
            let report = match self.execute_one()? {
                InstructionExecution::Complete(report) => report,
                InstructionExecution::Watchpoint(stop) => return Ok(stop),
            };
            if let Some(termination) = report.termination {
                return Ok(self.render_termination(termination));
            }
            if let Some(stop) = self.breakpoint_stop() {
                return Ok(stop);
            }
            if self.source_for(self.current_address()) != initial_source.as_ref() {
                return Ok(self.render_stop("source location changed"));
            }
        }
    }

    fn next(&mut self) -> Result<String, DebugSessionError> {
        let pc = self.machine.cpu().pc;
        if self.machine.peek(pc)? != 0x20 {
            return self.step_once("next instruction");
        }
        let return_address = pc.wrapping_add(3);
        let return_bank = self.machine.mapped_prg_bank(return_address);
        let initial_instructions = self.machine.instructions();
        let initial_cycles = self.machine.cycles();
        loop {
            if self.pause.take_request() {
                return Ok(self.render_stop("pause requested"));
            }
            if self.limit_reached(initial_instructions, initial_cycles) {
                return Ok(self.render_stop("execution limit while stepping over call"));
            }
            let report = match self.execute_one()? {
                InstructionExecution::Complete(report) => report,
                InstructionExecution::Watchpoint(stop) => return Ok(stop),
            };
            if let Some(termination) = report.termination {
                return Ok(self.render_termination(termination));
            }
            if let Some(stop) = self.breakpoint_stop() {
                return Ok(stop);
            }
            if self.machine.cpu().pc == return_address
                && self.machine.mapped_prg_bank(return_address) == return_bank
            {
                return Ok(self.render_stop("returned from call"));
            }
        }
    }

    fn finish(&mut self) -> Result<String, DebugSessionError> {
        let initial_instructions = self.machine.instructions();
        let initial_cycles = self.machine.cycles();
        let mut nested_calls = 0_u32;
        loop {
            if self.pause.take_request() {
                return Ok(self.render_stop("pause requested"));
            }
            if self.limit_reached(initial_instructions, initial_cycles) {
                return Ok(self.render_stop("execution limit while finishing function"));
            }
            let report = match self.execute_one()? {
                InstructionExecution::Complete(report) => report,
                InstructionExecution::Watchpoint(stop) => return Ok(stop),
            };
            if let Some(termination) = report.termination {
                return Ok(self.render_termination(termination));
            }
            if let Some(stop) = self.breakpoint_stop() {
                return Ok(stop);
            }
            match report.opcode {
                Some(0x20) => nested_calls = nested_calls.saturating_add(1),
                Some(0x40 | 0x60) if nested_calls == 0 => {
                    return Ok(self.render_stop("returned from function"));
                }
                Some(0x60) => nested_calls -= 1,
                _ => {}
            }
        }
    }

    fn execute_one(&mut self) -> Result<InstructionExecution, DebugSessionError> {
        loop {
            let cycle = self.execute_cycle()?;
            if let Some(stop) = self.watchpoint_stop_for(cycle.access) {
                return Ok(InstructionExecution::Watchpoint(stop));
            }
            if let Some(report) = cycle.step {
                return Ok(InstructionExecution::Complete(report));
            }
        }
    }

    fn execute_cycle(&mut self) -> Result<CycleReport, DebugSessionError> {
        if !self.machine.instruction_pending() {
            self.pending_trace_address = Some(self.current_address());
        }
        let cycle = self.machine.step_cycle()?;
        if self.trace_enabled {
            if let Some(access) = cycle.access {
                if self.cycle_trace.len() == CYCLE_TRACE_CAPACITY {
                    self.cycle_trace.pop_front();
                }
                self.cycle_trace.push_back(access);
            }
        }
        if let Some(report) = cycle.step {
            let address = self.pending_trace_address.take().unwrap_or(DebugAddress {
                bank: self.machine.mapped_prg_bank(report.pc),
                address: report.pc,
            });
            self.record_trace(address, report);
        }
        Ok(cycle)
    }

    fn record_trace(&mut self, address: DebugAddress, report: StepReport) {
        if !self.trace_enabled {
            return;
        }
        if self.trace.len() == TRACE_CAPACITY {
            self.trace.pop_front();
        }
        self.trace.push_back(TraceEntry {
            address,
            opcode: report.opcode,
            cycles: report.cycles,
            source: self.source_for(address).cloned(),
        });
    }

    fn limit_reached(&self, instructions: u64, cycles: u64) -> bool {
        self.machine.instructions().saturating_sub(instructions) >= self.instruction_limit
            || self.machine.cycles().saturating_sub(cycles) >= self.cycle_limit
    }

    fn add_breakpoint(&mut self, arguments: &[&str]) -> Result<String, DebugSessionError> {
        require_count("break", arguments, 1)?;
        let address = self.parse_address(arguments[0])?;
        let id = self.allocate_stop_id();
        self.breakpoints.insert(id, address);
        Ok(format!("Breakpoint {id} at {address}\n"))
    }

    fn add_watchpoint(
        &mut self,
        arguments: &[&str],
        kind: WatchKind,
    ) -> Result<String, DebugSessionError> {
        require_count("watch", arguments, 1)?;
        let address = parse_u16(arguments[0])?;
        let id = self.allocate_stop_id();
        self.watchpoints.insert(id, Watchpoint { address, kind });
        Ok(format!("Watchpoint {id} ({kind}) at ${address:04X}\n"))
    }

    fn delete_stop(&mut self, arguments: &[&str]) -> Result<String, DebugSessionError> {
        require_count("delete", arguments, 1)?;
        let id = arguments[0].parse::<u32>().map_err(|_| {
            DebugSessionError::Command(format!("invalid breakpoint identifier `{}`", arguments[0]))
        })?;
        if self.breakpoints.remove(&id).is_some() || self.watchpoints.remove(&id).is_some() {
            Ok(format!("Deleted stop {id}\n"))
        } else {
            Err(DebugSessionError::Command(format!(
                "stop {id} does not exist"
            )))
        }
    }

    fn allocate_stop_id(&mut self) -> u32 {
        let id = self.next_stop_id;
        self.next_stop_id = self.next_stop_id.saturating_add(1);
        id
    }

    fn parse_address(&self, text: &str) -> Result<DebugAddress, DebugSessionError> {
        if let Some(address) = self.symbols_by_name.get(text) {
            return Ok(*address);
        }
        parse_debug_address(text)
    }

    fn breakpoint_at_current(&self) -> Option<(u32, DebugAddress)> {
        let current = self.current_address();
        self.breakpoints.iter().find_map(|(id, breakpoint)| {
            (breakpoint.address == current.address
                && breakpoint
                    .bank
                    .is_none_or(|bank| current.bank == Some(bank)))
            .then_some((*id, *breakpoint))
        })
    }

    fn breakpoint_stop(&self) -> Option<String> {
        self.breakpoint_at_current()
            .map(|(id, _)| self.render_stop(&format!("breakpoint {id}")))
    }

    fn watchpoint_stop_for(&self, access: Option<BusAccess>) -> Option<String> {
        let access = access?;
        self.watchpoints.iter().find_map(|(id, watchpoint)| {
            (watchpoint.address == access.address && watchpoint.kind.matches(access.kind))
                .then(|| self.render_watchpoint_stop(*id, access))
        })
    }

    fn render_watchpoint_stop(&self, id: u32, access: BusAccess) -> String {
        format!(
            "Stopped at watchpoint {id} on cycle {}: {:?} ${:04X} = ${:02X}{}\n{}",
            access.cycle,
            access.kind,
            access.address,
            access.value,
            if access.dummy { " (dummy)" } else { "" },
            self.render_registers()
        )
    }

    fn render_stop(&self, reason: &str) -> String {
        let mut text = format!("Stopped: {reason} at {}\n", self.current_address());
        if let Some(source) = self.source_for(self.current_address()) {
            text.push_str(&format!("Source: {source}\n"));
        }
        text.push_str(&self.render_registers());
        if self.trace_enabled {
            text.push_str(&self.render_recent_trace(8));
        }
        text
    }

    fn render_termination(&self, termination: Termination) -> String {
        self.render_stop(&format!("termination {termination:?}"))
    }

    fn render_registers(&self) -> String {
        let cpu = self.machine.cpu();
        format!(
            "A=${:02X} X=${:02X} Y=${:02X} SP=${:02X} P=${:02X} PC=${:04X} cycles={} instructions={} frames={}\n",
            cpu.a,
            cpu.x,
            cpu.y,
            cpu.sp,
            cpu.status,
            cpu.pc,
            self.machine.cycles(),
            self.machine.instructions(),
            self.machine.frames()
        )
    }

    fn render_memory_command(&self, arguments: &[&str]) -> Result<String, DebugSessionError> {
        require_count("memory", arguments, 2)?;
        let address = parse_u16(arguments[0])?;
        let length = parse_usize(arguments[1], "memory length")?;
        if length == 0 || length > MAX_MEMORY_LENGTH {
            return Err(DebugSessionError::Command(format!(
                "memory length must be between 1 and {MAX_MEMORY_LENGTH}"
            )));
        }
        let mut bytes = Vec::with_capacity(length);
        for offset in 0..length {
            let offset = u16::try_from(offset).expect("bounded memory length fits u16");
            bytes.push(self.machine.peek(address.wrapping_add(offset))?);
        }
        Ok(render_byte_rows(address, &bytes))
    }

    fn render_disassembly_command(&self, arguments: &[&str]) -> Result<String, DebugSessionError> {
        require_count("disassemble", arguments, 2)?;
        let requested = self.parse_address(arguments[0])?;
        if requested.bank.is_some()
            && requested.bank != self.machine.mapped_prg_bank(requested.address)
        {
            return Err(DebugSessionError::Command(format!(
                "{} is not currently mapped; selected PRG bank is {}",
                requested,
                self.machine.mapper_state().prg_bank
            )));
        }
        let mut address = requested.address;
        let count = parse_usize(arguments[1], "instruction count")?;
        if count == 0 || count > 256 {
            return Err(DebugSessionError::Command(
                "instruction count must be between 1 and 256".to_owned(),
            ));
        }
        let mut text = String::new();
        for _ in 0..count {
            let bank = self.machine.mapped_prg_bank(address);
            let opcode_byte = self.machine.peek(address)?;
            let Some(metadata) = opcode(opcode_byte) else {
                text.push_str(&format!(
                    "{}:${address:04X}  {opcode_byte:02X}       .byte ${opcode_byte:02X}\n",
                    format_bank(bank)
                ));
                address = address.wrapping_add(1);
                continue;
            };
            let length = usize::from(metadata.len());
            let mut bytes = Vec::with_capacity(length);
            for offset in 0..length {
                bytes.push(self.machine.peek(address.wrapping_add(offset as u16))?);
            }
            let operand = u16::from_le_bytes([
                bytes.get(1).copied().unwrap_or(0),
                bytes.get(2).copied().unwrap_or(0),
            ]);
            let encoded = bytes
                .iter()
                .map(|byte| format!("{byte:02X}"))
                .collect::<Vec<_>>()
                .join(" ");
            let symbol = self
                .symbol_at(DebugAddress { bank, address })
                .map_or_else(String::new, |name| format!(" <{name}>"));
            text.push_str(&format!(
                "{}:${address:04X}  {encoded:<8} {}{}{}\n",
                format_bank(bank),
                metadata.mnemonic,
                format_operand(metadata.mode, operand, address),
                symbol
            ));
            address = address.wrapping_add(u16::from(metadata.len()));
        }
        Ok(text)
    }

    fn render_stack(&self) -> Result<String, DebugSessionError> {
        let sp = self.machine.cpu().sp;
        if sp == u8::MAX {
            return Ok("Hardware stack is empty.\n".to_owned());
        }
        let start = sp.wrapping_add(1);
        let bytes = (start..=u8::MAX)
            .map(|offset| self.machine.peek(0x0100 | u16::from(offset)))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(render_byte_rows(0x0100 | u16::from(start), &bytes))
    }

    fn render_source(&self) -> String {
        self.source_for(self.current_address()).map_or_else(
            || format!("No source mapping for {}.\n", self.current_address()),
            |source| format!("{} -> {source}\n", self.current_address()),
        )
    }

    fn render_symbols(&self) -> String {
        if self.symbols.is_empty() {
            return "No symbols loaded.\n".to_owned();
        }
        self.symbols
            .iter()
            .map(|symbol| format!("{} {}\n", symbol.address, symbol.name))
            .collect()
    }

    fn render_ppu(&self) -> Result<String, DebugSessionError> {
        let state = self.machine.ppu_state();
        Ok(format!(
            "Timing: {:?}\nFrame {}, scanline {}, dot {}\nCTRL=${:02X} MASK=${:02X} STATUS=${:02X}\nVRAM=${:04X} TEMP=${:04X} fine X={} write toggle={}\nFramebuffer: 256x240 palette indices, {} nonzero pixels, checksum ${:016X}\nCHR RAM: {} nonzero bytes\nPalette: {} nonzero bytes\nOAM: {} nonzero bytes\nNametable RAM: {} nonzero bytes\n",
            self.machine.timing_profile(),
            state.position.frame,
            state.position.scanline,
            state.position.dot,
            state.ctrl,
            state.mask,
            state.status,
            state.vram_address,
            state.temporary_address,
            state.fine_x,
            state.write_toggle,
            nonzero(self.machine.framebuffer()),
            self.machine.framebuffer_checksum(),
            nonzero(self.machine.chr_ram()),
            nonzero(self.machine.palette()),
            nonzero(self.machine.oam()),
            nonzero(self.machine.nametable_ram())
        ))
    }

    fn render_apu(&self) -> String {
        let state = self.machine.apu_state();
        let mode = if state.five_step_mode {
            "five-step"
        } else {
            "four-step"
        };
        let irq = if state.frame_irq_pending {
            "pending"
        } else {
            "clear"
        };
        let mut text = format!(
            "Timing: {:?}\nFrame counter: cycle {}, {mode}, IRQ {irq}\nStatus=${:02X} lengths={:?}\nOutput: pulse={:?} triangle={} noise={} mixed={} checksum=${:016X}\nRegisters:\n",
            self.machine.timing_profile(),
            state.frame_counter_cycle,
            state.channel_status,
            state.length_counters,
            state.pulse_outputs,
            state.triangle_output,
            state.noise_output,
            state.mixed_output,
            state.output_checksum,
        );
        for (offset, value) in self.machine.apu_io().iter().enumerate() {
            text.push_str(&format!("${:04X} = ${value:02X}\n", 0x4000 + offset));
        }
        text
    }

    fn render_cartridge(&self) -> String {
        let state = self.machine.mapper_state();
        format!(
            "Mapper {} with {} PRG banks\nSelected PRG bank: {}\nSelected CHR bank: {}\nCurrent mapping: {}\n",
            self.mapper,
            self.prg_banks,
            state.prg_bank,
            state.chr_bank,
            self.current_address()
        )
    }

    fn trace_command(&mut self, arguments: &[&str]) -> Result<String, DebugSessionError> {
        require_count("trace", arguments, 1)?;
        match arguments[0] {
            "on" => {
                self.trace_enabled = true;
                Ok("Instruction and bus-clock trace enabled.\n".to_owned())
            }
            "off" => {
                self.trace_enabled = false;
                Ok("Instruction and bus-clock trace disabled.\n".to_owned())
            }
            "show" => Ok(self.render_recent_trace(TRACE_CAPACITY)),
            value => Err(DebugSessionError::Command(format!(
                "invalid trace mode `{value}`; expected `on`, `off`, or `show`"
            ))),
        }
    }

    fn render_recent_trace(&self, limit: usize) -> String {
        if self.trace.is_empty() && self.cycle_trace.is_empty() {
            return "Trace is empty.\n".to_owned();
        }
        let mut text = String::new();
        if !self.trace.is_empty() {
            text.push_str("Recent instructions:\n");
            let start = self.trace.len().saturating_sub(limit);
            for entry in self.trace.iter().skip(start) {
                text.push_str(&format!("  {}", entry.address));
                if let Some(opcode) = entry.opcode {
                    text.push_str(&format!(" opcode=${opcode:02X}"));
                }
                text.push_str(&format!(" +{} cycles", entry.cycles));
                if let Some(source) = &entry.source {
                    text.push_str(&format!(" {source}"));
                }
                text.push('\n');
            }
        }
        if !self.cycle_trace.is_empty() {
            text.push_str("Recent bus clocks:\n");
            let start = self.cycle_trace.len().saturating_sub(limit);
            for access in self.cycle_trace.iter().skip(start) {
                let direction = match access.kind {
                    BusAccessKind::Read => 'R',
                    BusAccessKind::Write => 'W',
                };
                text.push_str(&format!(
                    "  cycle {} pc=${:04X} {direction} ${:04X}=${:02X}{}",
                    access.cycle,
                    access.pc,
                    access.address,
                    access.value,
                    if access.dummy { " dummy" } else { "" }
                ));
                if let Some(bank) = access.physical_bank {
                    text.push_str(&format!(" bank={bank:03}"));
                }
                text.push('\n');
            }
        }
        text
    }

    fn source_for(&self, address: DebugAddress) -> Option<&SourceLocation> {
        self.sources
            .iter()
            .filter(|source| {
                source.address.address <= address.address
                    && source
                        .address
                        .bank
                        .is_none_or(|bank| address.bank == Some(bank))
            })
            .max_by_key(|source| source.address.address)
    }

    fn symbol_at(&self, address: DebugAddress) -> Option<&str> {
        self.symbols
            .iter()
            .find(|symbol| {
                symbol.address == address
                    || (symbol.address.address == address.address && symbol.address.bank.is_none())
            })
            .map(|symbol| symbol.name.as_str())
    }
}

fn output(text: String) -> DebugCommandOutput {
    DebugCommandOutput { text, quit: false }
}

fn sibling_path(path: &Path, extension: &str) -> Option<PathBuf> {
    let stem = path.file_stem()?;
    Some(path.with_file_name(format!("{}.{}", stem.to_string_lossy(), extension)))
}

fn read_bounded(path: &Path, limit: u64) -> Result<Vec<u8>, DebugSessionError> {
    let metadata = fs::metadata(path).map_err(|source| DebugSessionError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    if metadata.len() > limit {
        return Err(DebugSessionError::InputTooLarge {
            path: path.to_path_buf(),
            bytes: metadata.len(),
            limit,
        });
    }
    fs::read(path).map_err(|source| DebugSessionError::Io {
        path: path.to_path_buf(),
        source,
    })
}

fn read_metadata(path: &Path) -> Result<String, DebugSessionError> {
    let bytes = read_bounded(path, MAX_METADATA_BYTES)?;
    String::from_utf8(bytes).map_err(|error| DebugSessionError::InvalidMetadata {
        path: path.to_path_buf(),
        line: 0,
        message: error.to_string(),
    })
}

fn parse_symbols(contents: &str, path: &Path) -> Result<Vec<DebugSymbol>, DebugSessionError> {
    bounded_lines(contents, path)?
        .filter(|(_, line)| !line.trim().is_empty())
        .map(|(index, line)| {
            let mut parts = line.split_whitespace();
            let address = parts
                .next()
                .ok_or_else(|| metadata_error(path, index, "missing address"))?;
            let name = parts
                .next()
                .ok_or_else(|| metadata_error(path, index, "missing symbol name"))?;
            if parts.next().is_some() {
                return Err(metadata_error(path, index, "unexpected trailing fields"));
            }
            Ok(DebugSymbol {
                address: parse_debug_address(address)
                    .map_err(|error| metadata_error(path, index, error.to_string()))?,
                name: name.to_owned(),
            })
        })
        .collect()
}

fn parse_source_map(contents: &str, path: &Path) -> Result<Vec<SourceLocation>, DebugSessionError> {
    bounded_lines(contents, path)?
        .filter(|(_, line)| !line.trim().is_empty())
        .map(|(index, line)| {
            let (location, remainder) = line
                .split_once(char::is_whitespace)
                .ok_or_else(|| metadata_error(path, index, "missing source record"))?;
            let remainder = remainder.trim();
            let (source_span, symbol) = remainder
                .rsplit_once(char::is_whitespace)
                .ok_or_else(|| metadata_error(path, index, "missing source symbol"))?;
            let (path_and_start, length) = source_span
                .rsplit_once(':')
                .ok_or_else(|| metadata_error(path, index, "missing source length"))?;
            let (source_path, start) = path_and_start
                .rsplit_once(':')
                .ok_or_else(|| metadata_error(path, index, "missing source start"))?;
            Ok(SourceLocation {
                address: parse_debug_address(location)
                    .map_err(|error| metadata_error(path, index, error.to_string()))?,
                path: PathBuf::from(source_path),
                start: start
                    .parse()
                    .map_err(|_| metadata_error(path, index, "invalid source start"))?,
                length: length
                    .parse()
                    .map_err(|_| metadata_error(path, index, "invalid source length"))?,
                symbol: symbol.to_owned(),
            })
        })
        .collect()
}

fn bounded_lines<'a>(
    contents: &'a str,
    path: &Path,
) -> Result<impl Iterator<Item = (usize, &'a str)>, DebugSessionError> {
    if contents.lines().count() > MAX_METADATA_ENTRIES {
        return Err(DebugSessionError::InvalidMetadata {
            path: path.to_path_buf(),
            line: 0,
            message: format!("contains more than {MAX_METADATA_ENTRIES} entries"),
        });
    }
    Ok(contents
        .lines()
        .enumerate()
        .map(|(index, line)| (index + 1, line)))
}

fn metadata_error(path: &Path, line: usize, message: impl Into<String>) -> DebugSessionError {
    DebugSessionError::InvalidMetadata {
        path: path.to_path_buf(),
        line,
        message: message.into(),
    }
}

fn parse_debug_address(text: &str) -> Result<DebugAddress, DebugSessionError> {
    if let Some((bank, address)) = text.split_once(':') {
        let bank = parse_bank(bank)?;
        return Ok(DebugAddress {
            bank: Some(bank),
            address: parse_u16(address)?,
        });
    }
    Ok(DebugAddress {
        bank: None,
        address: parse_u16(text)?,
    })
}

fn parse_bank(text: &str) -> Result<u16, DebugSessionError> {
    if let Some(hex) = text.strip_prefix("0x").or_else(|| text.strip_prefix('$')) {
        return u16::from_str_radix(hex, 16)
            .map_err(|_| DebugSessionError::Command(format!("invalid PRG bank `{text}`")));
    }
    text.parse::<u16>()
        .map_err(|_| DebugSessionError::Command(format!("invalid PRG bank `{text}`")))
}

fn parse_u16(text: &str) -> Result<u16, DebugSessionError> {
    let value = text
        .strip_prefix('$')
        .or_else(|| text.strip_prefix("0x"))
        .unwrap_or(text);
    u16::from_str_radix(value, 16)
        .map_err(|_| DebugSessionError::Command(format!("invalid 16-bit address `{text}`")))
}

fn parse_usize(text: &str, description: &str) -> Result<usize, DebugSessionError> {
    text.parse::<usize>()
        .map_err(|_| DebugSessionError::Command(format!("invalid {description} `{text}`")))
}

fn require_count(name: &str, arguments: &[&str], count: usize) -> Result<(), DebugSessionError> {
    if arguments.len() == count {
        Ok(())
    } else {
        Err(DebugSessionError::Command(format!(
            "`{name}` expects {count} argument(s), received {}",
            arguments.len()
        )))
    }
}

fn render_byte_rows(address: u16, bytes: &[u8]) -> String {
    let mut text = String::new();
    for (row, chunk) in bytes.chunks(16).enumerate() {
        text.push_str(&format!(
            "${:04X}: ",
            address.wrapping_add((row * 16) as u16)
        ));
        for byte in chunk {
            text.push_str(&format!("{byte:02X} "));
        }
        text.push('\n');
    }
    text
}

fn format_bank(bank: Option<u16>) -> String {
    bank.map_or_else(|| "---".to_owned(), |bank| format!("{bank:03}"))
}

fn format_operand(mode: AddressingMode, operand: u16, address: u16) -> String {
    match mode {
        AddressingMode::Implied => String::new(),
        AddressingMode::Accumulator => " a".to_owned(),
        AddressingMode::Immediate => format!(" #${:02X}", operand as u8),
        AddressingMode::ZeroPage => format!(" ${:02X}", operand as u8),
        AddressingMode::ZeroPageX => format!(" ${:02X},x", operand as u8),
        AddressingMode::ZeroPageY => format!(" ${:02X},y", operand as u8),
        AddressingMode::Relative => {
            let target = address
                .wrapping_add(2)
                .wrapping_add_signed(i16::from(operand as u8 as i8));
            format!(" ${target:04X}")
        }
        AddressingMode::Absolute => format!(" ${operand:04X}"),
        AddressingMode::AbsoluteX => format!(" ${operand:04X},x"),
        AddressingMode::AbsoluteY => format!(" ${operand:04X},y"),
        AddressingMode::Indirect => format!(" (${operand:04X})"),
        AddressingMode::IndexedIndirect => format!(" (${:02X},x)", operand as u8),
        AddressingMode::IndirectIndexed => format!(" (${:02X}),y", operand as u8),
    }
}

fn nonzero(values: &[u8]) -> usize {
    values.iter().filter(|value| **value != 0).count()
}

fn help_text() -> &'static str {
    "run | continue | pause\nstep | step-cycle | step-frame | step-source | next | finish\nbreak <address-or-symbol> | delete <id>\nwatch <address> | watch-read <address> | watch-write <address>\nregisters | memory <address> <length> | disassemble <address> <count> | stack\nsource | symbols | ppu | apu | cartridge\ntrace on | trace off | trace show\nreset | quit\n"
}

#[cfg(test)]
mod tests {
    use nesc_rom::{Format, Metadata, Mirroring, Region, Rom, build};

    use super::*;

    fn nrom() -> Vec<u8> {
        let mut prg = vec![0xea; 32 * 1024];
        prg[..11].copy_from_slice(&[
            0xa9, 0x2a, // lda #$2a
            0x85, 0x10, // sta $10
            0x20, 0x10, 0x80, // jsr $8010
            0xea, // nop
            0x4c, 0x08, 0x80, // jmp $8008
        ]);
        prg[0x10..0x13].copy_from_slice(&[
            0xa2, 0x07, // ldx #7
            0x60, // rts
        ]);
        let vectors = prg.len() - 6;
        for offset in [0, 2, 4] {
            prg[vectors + offset..vectors + offset + 2].copy_from_slice(&0x8000_u16.to_le_bytes());
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
        .expect("NROM")
    }

    fn uxrom() -> Vec<u8> {
        let mut prg = vec![0xea; 3 * 16 * 1024];
        prg[16 * 1024..16 * 1024 + 4].copy_from_slice(&[
            0xea, // nop in bank 1
            0x4c, 0x00, 0x80, // jmp $8000
        ]);
        let fixed = 2 * 16 * 1024;
        prg[fixed..fixed + 8].copy_from_slice(&[
            0xa9, 0x01, // lda #1
            0x8d, 0x00, 0x80, // sta $8000
            0x4c, 0x00, 0x80, // jmp $8000
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
        .expect("UxROM")
    }

    fn nrom_session() -> DebugSession {
        DebugSession::from_rom_bytes(
            &nrom(),
            "8000 reset\n8010 worker\n",
            None,
            "8000 src/main.c:0:10 reset\n8010 src/main.c:20:8 worker\n",
            None,
            DebugSessionConfig {
                instruction_limit: 100,
                cycle_limit: 1_000,
                ..DebugSessionConfig::default()
            },
        )
        .expect("debug session")
    }

    #[test]
    fn stops_at_symbols_and_resolves_source() {
        let mut session = nrom_session();
        assert!(
            session
                .execute_command("source")
                .expect("source")
                .text
                .contains("src/main.c:0:10")
        );
        session.execute_command("break worker").expect("breakpoint");
        let stopped = session.execute_command("continue").expect("continue").text;
        assert!(stopped.contains("breakpoint 1"), "{stopped}");
        assert_eq!(session.current_address().address, 0x8010);
        assert!(stopped.contains("src/main.c:20:8"), "{stopped}");
    }

    #[test]
    fn steps_over_calls_and_stops_on_bus_writes() {
        let mut session = nrom_session();
        session.execute_command("step").expect("LDA");
        session.execute_command("step").expect("STA");
        let next = session.execute_command("next").expect("step over").text;
        assert!(next.contains("returned from call"), "{next}");
        assert_eq!(session.current_address().address, 0x8007);

        let mut session = nrom_session();
        session
            .execute_command("watch-write $0010")
            .expect("watchpoint");
        let stopped = session.execute_command("continue").expect("continue").text;
        assert!(stopped.contains("watchpoint 1"), "{stopped}");
        assert!(stopped.contains("Write $0010 = $2A"), "{stopped}");
        assert!(
            session
                .execute_command("memory $0010 1")
                .expect("memory")
                .text
                .contains("2A")
        );
    }

    #[test]
    fn stops_watchpoints_on_the_exact_bus_clock_and_traces_dummy_reads() {
        let mut session = nrom_session();
        session
            .execute_command("watch-read $8000")
            .expect("opcode watchpoint");
        let stopped = session.execute_command("continue").expect("continue").text;
        assert!(stopped.contains("watchpoint 1 on cycle 8"), "{stopped}");
        assert!(session.machine.instruction_pending());
        assert_eq!(session.machine.cpu().pc, 0x8000);

        let mut session = nrom_session();
        session.execute_command("step").expect("LDA");
        session.execute_command("step").expect("STA");
        session.execute_command("next").expect("JSR");
        session.execute_command("trace on").expect("trace");
        session
            .execute_command("watch-read $8008")
            .expect("dummy read watchpoint");
        let stopped = session.execute_command("step").expect("NOP").text;
        assert!(stopped.contains("Read $8008 = $4C (dummy)"), "{stopped}");
        let trace = session.execute_command("trace show").expect("trace").text;
        assert!(trace.contains("Recent bus clocks:"), "{trace}");
        assert!(trace.contains("R $8008=$4C dummy"), "{trace}");
    }

    #[test]
    fn steps_cycles_and_source_locations_and_honors_pause_requests() {
        let mut session = nrom_session();
        let first = session
            .execute_command("step-cycle")
            .expect("first cycle")
            .text;
        assert!(first.contains("instruction pending"), "{first}");
        let second = session
            .execute_command("step-cycle")
            .expect("second cycle")
            .text;
        assert!(second.contains("instruction complete"), "{second}");
        let ppu = session.execute_command("ppu").expect("PPU state").text;
        assert!(ppu.contains("Timing: Ntsc"), "{ppu}");
        assert!(ppu.contains("scanline 0, dot 27"), "{ppu}");
        assert!(ppu.contains("VRAM=$0000 TEMP=$0000 fine X=0"), "{ppu}");
        assert!(
            ppu.contains("Framebuffer: 256x240 palette indices"),
            "{ppu}"
        );
        let apu = session.execute_command("apu").expect("APU state").text;
        assert!(apu.contains("Frame counter: cycle 9, four-step"), "{apu}");
        assert!(apu.contains("Output: pulse=[0, 0]"), "{apu}");
        assert!(apu.contains("Registers:\n$4000 = $00"), "{apu}");

        let mut session = nrom_session();
        let source = session
            .execute_command("step-source")
            .expect("source step")
            .text;
        assert!(source.contains("source location changed"), "{source}");
        assert_eq!(session.current_address().address, 0x8010);

        let mut session = nrom_session();
        let pause = session.pause_handle();
        pause.request_pause();
        let stopped = session.execute_command("continue").expect("pause").text;
        assert!(stopped.contains("pause requested"), "{stopped}");
        assert_eq!(session.current_address().address, 0x8000);
    }

    #[test]
    fn honors_mapper_two_bank_qualified_breakpoints() {
        let mut session = DebugSession::from_rom_bytes(
            &uxrom(),
            "002:C000 reset\n001:8000 banked\n",
            None,
            "",
            None,
            DebugSessionConfig {
                instruction_limit: 100,
                cycle_limit: 1_000,
                ..DebugSessionConfig::default()
            },
        )
        .expect("UxROM session");
        session
            .execute_command("break 001:$8000")
            .expect("banked breakpoint");
        let stopped = session.execute_command("continue").expect("continue").text;
        assert!(stopped.contains("breakpoint 1"), "{stopped}");
        assert_eq!(
            session.current_address(),
            DebugAddress {
                bank: Some(1),
                address: 0x8000
            }
        );
        assert!(
            session
                .execute_command("cartridge")
                .expect("cartridge")
                .text
                .contains("Selected PRG bank: 1")
        );
        let cycle = session
            .execute_command("step-cycle")
            .expect("banked instruction cycle")
            .text;
        assert!(cycle.contains("instruction pending"), "{cycle}");
        assert_eq!(session.current_address().bank, Some(1));
    }
}
