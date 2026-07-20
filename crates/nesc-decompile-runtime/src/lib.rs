//! Host-side semantic runtime for stable-Rust NES decompilation output.

use std::error::Error;
use std::fmt;

use nesc_disasm::{AddressingMode, Mnemonic, decode};

const CARRY: u8 = 0x01;
const ZERO: u8 = 0x02;
const INTERRUPT_DISABLE: u8 = 0x04;
const DECIMAL: u8 = 0x08;
const BREAK: u8 = 0x10;
const UNUSED: u8 = 0x20;
const OVERFLOW: u8 = 0x40;
const NEGATIVE: u8 = 0x80;

/// Bounded runtime failure with the first failing machine location.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeError {
    /// Deterministic explanation.
    pub message: String,
    /// Physical PRG bank active at the failure.
    pub bank: u16,
    /// CPU program counter at the failure.
    pub pc: u16,
    /// Instructions consumed before the failure.
    pub instructions: u64,
}

impl RuntimeError {
    /// Creates a bus or host-environment failure at the current CPU location.
    #[must_use]
    pub fn bus(state: &CpuState, message: impl Into<String>) -> Self {
        Self::at(state, 0, message)
    }

    fn at(state: &CpuState, instructions: u64, message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            bank: state.bank,
            pc: state.pc,
            instructions,
        }
    }
}

impl fmt::Display for RuntimeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{} at PRG bank {}, PC ${:04X}, after {} instructions",
            self.message, self.bank, self.pc, self.instructions
        )
    }
}

impl Error for RuntimeError {}

/// Ordered CPU-bus access category used for differential verification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AccessKind {
    Read,
    Write,
}

/// One observable bus event produced by translated or interpreted code.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ObservableEvent {
    /// Number of instructions already entered in the shared budget.
    pub instruction: u64,
    /// CPU location that caused the access.
    pub pc: u16,
    /// Physical PRG bank associated with that location.
    pub bank: u16,
    /// CPU-bus address.
    pub address: u16,
    /// Value read or written.
    pub value: u8,
    /// Access direction.
    pub kind: AccessKind,
}

/// Host-side CPU bus used by generated semantic translations.
pub trait Bus {
    /// Reads one CPU-bus byte, including any hardware side effects.
    ///
    /// # Errors
    ///
    /// Returns a bounded runtime error for unmapped or rejected accesses.
    fn read(&mut self, state: &CpuState, address: u16) -> Result<u8, RuntimeError>;

    /// Writes one CPU-bus byte, including mapper and MMIO side effects.
    ///
    /// # Errors
    ///
    /// Returns a bounded runtime error for unmapped or rejected accesses.
    fn write(&mut self, state: &CpuState, address: u16, value: u8) -> Result<(), RuntimeError>;

    /// Records an ordered observable event. The default accepts the event.
    ///
    /// # Errors
    ///
    /// A host may reject an event or stop at a differential checkpoint.
    fn observe(&mut self, _event: ObservableEvent) -> Result<(), RuntimeError> {
        Ok(())
    }

    /// Returns the physical PRG bank currently mapped at an executable address.
    fn mapped_prg_bank(&self, _address: u16) -> Option<u16> {
        None
    }
}

/// Shared instruction budget for translated and fallback execution.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExecutionBudget {
    limit: u64,
    consumed: u64,
}

impl ExecutionBudget {
    /// Creates a positive instruction budget.
    ///
    /// # Errors
    ///
    /// Rejects a zero limit.
    pub fn new(limit: u64) -> Result<Self, RuntimeError> {
        if limit == 0 {
            return Err(RuntimeError {
                message: "execution limit must be greater than zero".to_owned(),
                bank: 0,
                pc: 0,
                instructions: 0,
            });
        }
        Ok(Self { limit, consumed: 0 })
    }

    /// Charges one instruction at the current CPU location.
    ///
    /// # Errors
    ///
    /// Fails before executing an instruction beyond the configured limit.
    pub fn consume(&mut self, state: &CpuState) -> Result<(), RuntimeError> {
        if self.consumed >= self.limit {
            return Err(RuntimeError::at(
                state,
                self.consumed,
                format!("instruction limit {} exceeded", self.limit),
            ));
        }
        self.consumed += 1;
        Ok(())
    }

    /// Returns the number of instructions charged so far.
    #[must_use]
    pub const fn consumed(self) -> u64 {
        self.consumed
    }
}

/// Processor status register with explicit flag access.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProcessorStatus(u8);

impl Default for ProcessorStatus {
    fn default() -> Self {
        Self(UNUSED | INTERRUPT_DISABLE)
    }
}

impl ProcessorStatus {
    /// Builds a status value while retaining the hardware's unused high bit.
    #[must_use]
    pub const fn from_bits(bits: u8) -> Self {
        Self(bits | UNUSED)
    }

    /// Returns the packed status byte.
    #[must_use]
    pub const fn bits(self) -> u8 {
        self.0 | UNUSED
    }

    /// Reads one processor flag.
    #[must_use]
    pub const fn get(self, flag: Flag) -> bool {
        self.0 & flag.mask() != 0
    }

    /// Assigns one processor flag.
    pub fn set(&mut self, flag: Flag, value: bool) {
        if value {
            self.0 |= flag.mask();
        } else {
            self.0 &= !flag.mask();
        }
        self.0 |= UNUSED;
    }

    /// Updates the negative and zero flags from an eight-bit result.
    pub fn set_negative_zero(&mut self, value: u8) {
        self.set(Flag::Negative, value & NEGATIVE != 0);
        self.set(Flag::Zero, value == 0);
    }
}

/// Individual Ricoh CPU status flag.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Flag {
    Carry,
    Zero,
    InterruptDisable,
    Decimal,
    Break,
    Overflow,
    Negative,
}

impl Flag {
    const fn mask(self) -> u8 {
        match self {
            Self::Carry => CARRY,
            Self::Zero => ZERO,
            Self::InterruptDisable => INTERRUPT_DISABLE,
            Self::Decimal => DECIMAL,
            Self::Break => BREAK,
            Self::Overflow => OVERFLOW,
            Self::Negative => NEGATIVE,
        }
    }
}

/// Complete host-side CPU state retained by generated Rust.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CpuState {
    pub a: u8,
    pub x: u8,
    pub y: u8,
    pub sp: u8,
    pub pc: u16,
    pub bank: u16,
    pub status: ProcessorStatus,
}

impl Default for CpuState {
    fn default() -> Self {
        Self {
            a: 0,
            x: 0,
            y: 0,
            sp: 0xfd,
            pc: 0,
            bank: 0,
            status: ProcessorStatus::default(),
        }
    }
}

/// Register named by one lifted semantic operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Register {
    A,
    X,
    Y,
    StackPointer,
    ProgramCounter,
}

impl CpuState {
    /// Reads the low byte represented by a semantic register.
    #[must_use]
    pub const fn register(self, register: Register) -> u8 {
        match register {
            Register::A => self.a,
            Register::X => self.x,
            Register::Y => self.y,
            Register::StackPointer => self.sp,
            Register::ProgramCounter => self.pc as u8,
        }
    }

    /// Writes a semantic register without assigning arithmetic flags.
    pub fn set_register(&mut self, register: Register, value: u8) {
        match register {
            Register::A => self.a = value,
            Register::X => self.x = value,
            Register::Y => self.y = value,
            Register::StackPointer => self.sp = value,
            Register::ProgramCounter => self.pc = (self.pc & 0xff00) | u16::from(value),
        }
    }
}

/// Effective-address form preserved from the original instruction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Operand {
    ZeroPage(u8),
    ZeroPageX(u8),
    ZeroPageY(u8),
    Absolute(u16),
    AbsoluteX(u16),
    AbsoluteY(u16),
    IndexedIndirect(u8),
    IndirectIndexed(u8),
}

/// Runtime value source used by generated semantic statements.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ValueSource {
    Register(Register),
    Immediate(u8),
    Memory(Operand),
    Status,
}

/// Runtime destination used by generated semantic statements.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ValueTarget {
    Register(Register),
    Memory(Operand),
    Status,
}

/// Accumulator operation retained from 6502 semantics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AccumulatorOperator {
    AddWithCarry,
    SubtractWithCarry,
    And,
    Or,
    ExclusiveOr,
}

/// Shift or rotate operation retained from 6502 semantics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ShiftOperator {
    ArithmeticLeft,
    LogicalRight,
    RotateLeft,
    RotateRight,
}

/// Reads and records one bus byte.
///
/// # Errors
///
/// Propagates bus and observation failures.
pub fn read_u8<B: Bus>(
    state: &CpuState,
    bus: &mut B,
    budget: &ExecutionBudget,
    address: u16,
) -> Result<u8, RuntimeError> {
    let value = bus.read(state, address)?;
    bus.observe(ObservableEvent {
        instruction: budget.consumed(),
        pc: state.pc,
        bank: state.bank,
        address,
        value,
        kind: AccessKind::Read,
    })?;
    Ok(value)
}

/// Writes and records one bus byte.
///
/// # Errors
///
/// Propagates bus and observation failures.
pub fn write_u8<B: Bus>(
    state: &CpuState,
    bus: &mut B,
    budget: &ExecutionBudget,
    address: u16,
    value: u8,
) -> Result<(), RuntimeError> {
    bus.write(state, address, value)?;
    bus.observe(ObservableEvent {
        instruction: budget.consumed(),
        pc: state.pc,
        bank: state.bank,
        address,
        value,
        kind: AccessKind::Write,
    })
}

fn effective_address<B: Bus>(
    state: &CpuState,
    bus: &mut B,
    budget: &ExecutionBudget,
    operand: Operand,
) -> Result<u16, RuntimeError> {
    match operand {
        Operand::ZeroPage(address) => Ok(u16::from(address)),
        Operand::ZeroPageX(address) => Ok(u16::from(address.wrapping_add(state.x))),
        Operand::ZeroPageY(address) => Ok(u16::from(address.wrapping_add(state.y))),
        Operand::Absolute(address) => Ok(address),
        Operand::AbsoluteX(address) => Ok(address.wrapping_add(u16::from(state.x))),
        Operand::AbsoluteY(address) => Ok(address.wrapping_add(u16::from(state.y))),
        Operand::IndexedIndirect(pointer) => {
            let pointer = pointer.wrapping_add(state.x);
            let low = read_u8(state, bus, budget, u16::from(pointer))?;
            let high = read_u8(state, bus, budget, u16::from(pointer.wrapping_add(1)))?;
            Ok(u16::from_le_bytes([low, high]))
        }
        Operand::IndirectIndexed(pointer) => {
            let low = read_u8(state, bus, budget, u16::from(pointer))?;
            let high = read_u8(state, bus, budget, u16::from(pointer.wrapping_add(1)))?;
            Ok(u16::from_le_bytes([low, high]).wrapping_add(u16::from(state.y)))
        }
    }
}

/// Reads a generated value source exactly once.
///
/// # Errors
///
/// Propagates bus and observation failures.
pub fn read_source<B: Bus>(
    state: &CpuState,
    bus: &mut B,
    budget: &ExecutionBudget,
    source: ValueSource,
) -> Result<u8, RuntimeError> {
    match source {
        ValueSource::Register(register) => Ok(state.register(register)),
        ValueSource::Immediate(value) => Ok(value),
        ValueSource::Memory(operand) => {
            let address = effective_address(state, bus, budget, operand)?;
            read_u8(state, bus, budget, address)
        }
        ValueSource::Status => Ok(state.status.bits() | BREAK),
    }
}

/// Writes a generated value target exactly once.
///
/// # Errors
///
/// Propagates bus and observation failures.
pub fn write_target<B: Bus>(
    state: &mut CpuState,
    bus: &mut B,
    budget: &ExecutionBudget,
    target: ValueTarget,
    value: u8,
) -> Result<(), RuntimeError> {
    match target {
        ValueTarget::Register(register) => state.set_register(register, value),
        ValueTarget::Memory(operand) => {
            let address = effective_address(state, bus, budget, operand)?;
            write_u8(state, bus, budget, address, value)?;
        }
        ValueTarget::Status => state.status = ProcessorStatus::from_bits(value),
    }
    Ok(())
}

/// Executes a lifted load and assigns negative/zero flags.
pub fn load(state: &mut CpuState, destination: Register, value: u8) {
    state.set_register(destination, value);
    state.status.set_negative_zero(value);
}

/// Executes lifted accumulator arithmetic or logic.
pub fn accumulate(state: &mut CpuState, operator: AccumulatorOperator, value: u8) {
    match operator {
        AccumulatorOperator::AddWithCarry | AccumulatorOperator::SubtractWithCarry => {
            let operand = if operator == AccumulatorOperator::SubtractWithCarry {
                !value
            } else {
                value
            };
            let carry = u16::from(state.status.get(Flag::Carry));
            let result = u16::from(state.a) + u16::from(operand) + carry;
            let output = result as u8;
            let overflow = (!(state.a ^ operand) & (state.a ^ output) & NEGATIVE) != 0;
            state.status.set(Flag::Carry, result > 0xff);
            state.status.set(Flag::Overflow, overflow);
            state.a = output;
        }
        AccumulatorOperator::And => state.a &= value,
        AccumulatorOperator::Or => state.a |= value,
        AccumulatorOperator::ExclusiveOr => state.a ^= value,
    }
    state.status.set_negative_zero(state.a);
}

/// Executes a lifted unsigned comparison.
pub fn compare(state: &mut CpuState, left: u8, right: u8) {
    state.status.set(Flag::Carry, left >= right);
    state.status.set_negative_zero(left.wrapping_sub(right));
}

/// Executes the 6502 BIT flag behavior.
pub fn test_bits(state: &mut CpuState, value: u8) {
    state.status.set(Flag::Zero, state.a & value == 0);
    state.status.set(Flag::Negative, value & NEGATIVE != 0);
    state.status.set(Flag::Overflow, value & OVERFLOW != 0);
}

/// Executes a lifted shift or rotate and returns the output byte.
pub fn shift(state: &mut CpuState, operator: ShiftOperator, value: u8) -> u8 {
    let carry_in = u8::from(state.status.get(Flag::Carry));
    let (output, carry_out) = match operator {
        ShiftOperator::ArithmeticLeft => (value << 1, value & NEGATIVE != 0),
        ShiftOperator::LogicalRight => (value >> 1, value & 1 != 0),
        ShiftOperator::RotateLeft => ((value << 1) | carry_in, value & NEGATIVE != 0),
        ShiftOperator::RotateRight => ((value >> 1) | (carry_in << 7), value & 1 != 0),
    };
    state.status.set(Flag::Carry, carry_out);
    state.status.set_negative_zero(output);
    output
}

/// Pushes one byte on the emulated hardware stack.
///
/// # Errors
///
/// Propagates bus and observation failures.
pub fn push<B: Bus>(
    state: &mut CpuState,
    bus: &mut B,
    budget: &ExecutionBudget,
    value: u8,
) -> Result<(), RuntimeError> {
    write_u8(state, bus, budget, 0x0100 | u16::from(state.sp), value)?;
    state.sp = state.sp.wrapping_sub(1);
    Ok(())
}

/// Pops one byte from the emulated hardware stack.
///
/// # Errors
///
/// Propagates bus and observation failures.
pub fn pop<B: Bus>(
    state: &mut CpuState,
    bus: &mut B,
    budget: &ExecutionBudget,
) -> Result<u8, RuntimeError> {
    state.sp = state.sp.wrapping_add(1);
    read_u8(state, bus, budget, 0x0100 | u16::from(state.sp))
}

/// One immutable original-code range available to fallback interpretation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CodeSegment {
    pub bank: u16,
    pub cpu_address: u16,
    pub bytes: &'static [u8],
}

/// Interprets a recovered function until its outermost RTS or RTI.
///
/// # Errors
///
/// Fails on missing or ambiguous code, unofficial/truncated opcodes, rejected
/// bus access, excessive call nesting, or instruction-budget exhaustion.
pub fn interpret_function<B: Bus>(
    state: &mut CpuState,
    bus: &mut B,
    budget: &mut ExecutionBudget,
    code: &[CodeSegment],
    entry_bank: u16,
    entry: u16,
    max_call_depth: usize,
) -> Result<(), RuntimeError> {
    if max_call_depth == 0 {
        return Err(RuntimeError::at(
            state,
            budget.consumed(),
            "fallback call-depth limit must be greater than zero",
        ));
    }
    state.bank = entry_bank;
    state.pc = entry;
    let mut call_depth = 0_usize;
    let mut interrupt_depth = 0_usize;
    loop {
        budget.consume(state)?;
        let instruction_pc = state.pc;
        let segment = code_segment(code, bus, state)?;
        state.bank = segment.bank;
        let offset = usize::from(instruction_pc.wrapping_sub(segment.cpu_address));
        let decoded = decode(&segment.bytes[offset..]).map_err(|error| {
            RuntimeError::at(
                state,
                budget.consumed(),
                format!("could not decode fallback instruction: {error}"),
            )
        })?;
        let operand = decoded.operand();
        let next = instruction_pc.wrapping_add(u16::from(decoded.opcode.len()));
        match decoded.opcode.mnemonic {
            Mnemonic::Adc => {
                let value = interpreter_value(state, bus, budget, decoded.opcode.mode, operand)?;
                accumulate(state, AccumulatorOperator::AddWithCarry, value);
                state.pc = next;
            }
            Mnemonic::And | Mnemonic::Eor | Mnemonic::Ora | Mnemonic::Sbc => {
                let value = interpreter_value(state, bus, budget, decoded.opcode.mode, operand)?;
                let operator = match decoded.opcode.mnemonic {
                    Mnemonic::And => AccumulatorOperator::And,
                    Mnemonic::Eor => AccumulatorOperator::ExclusiveOr,
                    Mnemonic::Ora => AccumulatorOperator::Or,
                    Mnemonic::Sbc => AccumulatorOperator::SubtractWithCarry,
                    _ => unreachable!(),
                };
                accumulate(state, operator, value);
                state.pc = next;
            }
            Mnemonic::Asl | Mnemonic::Lsr | Mnemonic::Rol | Mnemonic::Ror => {
                let operator = match decoded.opcode.mnemonic {
                    Mnemonic::Asl => ShiftOperator::ArithmeticLeft,
                    Mnemonic::Lsr => ShiftOperator::LogicalRight,
                    Mnemonic::Rol => ShiftOperator::RotateLeft,
                    Mnemonic::Ror => ShiftOperator::RotateRight,
                    _ => unreachable!(),
                };
                let target = interpreter_target(decoded.opcode.mode, operand)?;
                let value = match target {
                    ValueTarget::Register(register) => state.register(register),
                    ValueTarget::Memory(memory) => {
                        read_source(state, bus, budget, ValueSource::Memory(memory))?
                    }
                    ValueTarget::Status => unreachable!(),
                };
                let output = shift(state, operator, value);
                write_target(state, bus, budget, target, output)?;
                state.pc = next;
            }
            Mnemonic::Bcc
            | Mnemonic::Bcs
            | Mnemonic::Beq
            | Mnemonic::Bmi
            | Mnemonic::Bne
            | Mnemonic::Bpl
            | Mnemonic::Bvc
            | Mnemonic::Bvs => {
                let taken = match decoded.opcode.mnemonic {
                    Mnemonic::Bcc => !state.status.get(Flag::Carry),
                    Mnemonic::Bcs => state.status.get(Flag::Carry),
                    Mnemonic::Beq => state.status.get(Flag::Zero),
                    Mnemonic::Bmi => state.status.get(Flag::Negative),
                    Mnemonic::Bne => !state.status.get(Flag::Zero),
                    Mnemonic::Bpl => !state.status.get(Flag::Negative),
                    Mnemonic::Bvc => !state.status.get(Flag::Overflow),
                    Mnemonic::Bvs => state.status.get(Flag::Overflow),
                    _ => unreachable!(),
                };
                state.pc = if taken {
                    next.wrapping_add_signed(i16::from(operand as u8 as i8))
                } else {
                    next
                };
            }
            Mnemonic::Bit => {
                let value = interpreter_value(state, bus, budget, decoded.opcode.mode, operand)?;
                test_bits(state, value);
                state.pc = next;
            }
            Mnemonic::Brk => {
                let return_address = next.wrapping_add(1);
                push(state, bus, budget, (return_address >> 8) as u8)?;
                push(state, bus, budget, return_address as u8)?;
                push(state, bus, budget, state.status.bits() | BREAK)?;
                state.status.set(Flag::InterruptDisable, true);
                let low = read_u8(state, bus, budget, 0xfffe)?;
                let high = read_u8(state, bus, budget, 0xffff)?;
                state.pc = u16::from_le_bytes([low, high]);
                interrupt_depth = interrupt_depth.saturating_add(1);
            }
            Mnemonic::Clc
            | Mnemonic::Cld
            | Mnemonic::Cli
            | Mnemonic::Clv
            | Mnemonic::Sec
            | Mnemonic::Sed
            | Mnemonic::Sei => {
                let (flag, value) = match decoded.opcode.mnemonic {
                    Mnemonic::Clc => (Flag::Carry, false),
                    Mnemonic::Cld => (Flag::Decimal, false),
                    Mnemonic::Cli => (Flag::InterruptDisable, false),
                    Mnemonic::Clv => (Flag::Overflow, false),
                    Mnemonic::Sec => (Flag::Carry, true),
                    Mnemonic::Sed => (Flag::Decimal, true),
                    Mnemonic::Sei => (Flag::InterruptDisable, true),
                    _ => unreachable!(),
                };
                state.status.set(flag, value);
                state.pc = next;
            }
            Mnemonic::Cmp | Mnemonic::Cpx | Mnemonic::Cpy => {
                let right = interpreter_value(state, bus, budget, decoded.opcode.mode, operand)?;
                let left = match decoded.opcode.mnemonic {
                    Mnemonic::Cmp => state.a,
                    Mnemonic::Cpx => state.x,
                    Mnemonic::Cpy => state.y,
                    _ => unreachable!(),
                };
                compare(state, left, right);
                state.pc = next;
            }
            Mnemonic::Dec | Mnemonic::Inc => {
                let target = interpreter_target(decoded.opcode.mode, operand)?;
                let ValueTarget::Memory(memory) = target else {
                    unreachable!();
                };
                let value = read_source(state, bus, budget, ValueSource::Memory(memory))?;
                let output = if decoded.opcode.mnemonic == Mnemonic::Inc {
                    value.wrapping_add(1)
                } else {
                    value.wrapping_sub(1)
                };
                write_target(state, bus, budget, target, output)?;
                state.status.set_negative_zero(output);
                state.pc = next;
            }
            Mnemonic::Dex | Mnemonic::Dey | Mnemonic::Inx | Mnemonic::Iny => {
                let (register, delta) = match decoded.opcode.mnemonic {
                    Mnemonic::Dex => (Register::X, -1_i8),
                    Mnemonic::Dey => (Register::Y, -1_i8),
                    Mnemonic::Inx => (Register::X, 1_i8),
                    Mnemonic::Iny => (Register::Y, 1_i8),
                    _ => unreachable!(),
                };
                let output = state.register(register).wrapping_add_signed(delta);
                state.set_register(register, output);
                state.status.set_negative_zero(output);
                state.pc = next;
            }
            Mnemonic::Jmp => {
                state.pc = if decoded.opcode.mode == AddressingMode::Indirect {
                    let low = read_u8(state, bus, budget, operand)?;
                    let high_address = (operand & 0xff00) | (operand.wrapping_add(1) & 0x00ff);
                    let high = read_u8(state, bus, budget, high_address)?;
                    u16::from_le_bytes([low, high])
                } else {
                    operand
                };
            }
            Mnemonic::Jsr => {
                if call_depth >= max_call_depth {
                    return Err(RuntimeError::at(
                        state,
                        budget.consumed(),
                        format!("fallback call-depth limit {max_call_depth} exceeded"),
                    ));
                }
                let return_address = next.wrapping_sub(1);
                push(state, bus, budget, (return_address >> 8) as u8)?;
                push(state, bus, budget, return_address as u8)?;
                call_depth += 1;
                state.pc = operand;
            }
            Mnemonic::Lda | Mnemonic::Ldx | Mnemonic::Ldy => {
                let value = interpreter_value(state, bus, budget, decoded.opcode.mode, operand)?;
                let register = match decoded.opcode.mnemonic {
                    Mnemonic::Lda => Register::A,
                    Mnemonic::Ldx => Register::X,
                    Mnemonic::Ldy => Register::Y,
                    _ => unreachable!(),
                };
                load(state, register, value);
                state.pc = next;
            }
            Mnemonic::Nop => state.pc = next,
            Mnemonic::Pha => {
                push(state, bus, budget, state.a)?;
                state.pc = next;
            }
            Mnemonic::Php => {
                push(state, bus, budget, state.status.bits() | BREAK)?;
                state.pc = next;
            }
            Mnemonic::Pla => {
                state.a = pop(state, bus, budget)?;
                state.status.set_negative_zero(state.a);
                state.pc = next;
            }
            Mnemonic::Plp => {
                state.status = ProcessorStatus::from_bits(pop(state, bus, budget)?);
                state.pc = next;
            }
            Mnemonic::Rti => {
                if interrupt_depth == 0 && call_depth == 0 {
                    return Ok(());
                }
                state.status = ProcessorStatus::from_bits(pop(state, bus, budget)?);
                let low = pop(state, bus, budget)?;
                let high = pop(state, bus, budget)?;
                state.pc = u16::from_le_bytes([low, high]);
                interrupt_depth = interrupt_depth.saturating_sub(1);
            }
            Mnemonic::Rts => {
                if call_depth == 0 {
                    return Ok(());
                }
                let low = pop(state, bus, budget)?;
                let high = pop(state, bus, budget)?;
                state.pc = u16::from_le_bytes([low, high]).wrapping_add(1);
                call_depth -= 1;
            }
            Mnemonic::Sta | Mnemonic::Stx | Mnemonic::Sty => {
                let target = interpreter_target(decoded.opcode.mode, operand)?;
                let value = match decoded.opcode.mnemonic {
                    Mnemonic::Sta => state.a,
                    Mnemonic::Stx => state.x,
                    Mnemonic::Sty => state.y,
                    _ => unreachable!(),
                };
                write_target(state, bus, budget, target, value)?;
                state.pc = next;
            }
            Mnemonic::Tax
            | Mnemonic::Tay
            | Mnemonic::Tsx
            | Mnemonic::Txa
            | Mnemonic::Txs
            | Mnemonic::Tya => {
                let (source, destination, update_flags) = match decoded.opcode.mnemonic {
                    Mnemonic::Tax => (Register::A, Register::X, true),
                    Mnemonic::Tay => (Register::A, Register::Y, true),
                    Mnemonic::Tsx => (Register::StackPointer, Register::X, true),
                    Mnemonic::Txa => (Register::X, Register::A, true),
                    Mnemonic::Txs => (Register::X, Register::StackPointer, false),
                    Mnemonic::Tya => (Register::Y, Register::A, true),
                    _ => unreachable!(),
                };
                let value = state.register(source);
                state.set_register(destination, value);
                if update_flags {
                    state.status.set_negative_zero(value);
                }
                state.pc = next;
            }
        }
    }
}

fn interpreter_value<B: Bus>(
    state: &CpuState,
    bus: &mut B,
    budget: &ExecutionBudget,
    mode: AddressingMode,
    operand: u16,
) -> Result<u8, RuntimeError> {
    if mode == AddressingMode::Immediate {
        Ok(operand as u8)
    } else {
        let source = ValueSource::Memory(interpreter_operand(mode, operand)?);
        read_source(state, bus, budget, source)
    }
}

fn interpreter_target(mode: AddressingMode, operand: u16) -> Result<ValueTarget, RuntimeError> {
    if mode == AddressingMode::Accumulator {
        Ok(ValueTarget::Register(Register::A))
    } else {
        Ok(ValueTarget::Memory(interpreter_operand(mode, operand)?))
    }
}

fn interpreter_operand(mode: AddressingMode, operand: u16) -> Result<Operand, RuntimeError> {
    let byte = operand as u8;
    match mode {
        AddressingMode::ZeroPage => Ok(Operand::ZeroPage(byte)),
        AddressingMode::ZeroPageX => Ok(Operand::ZeroPageX(byte)),
        AddressingMode::ZeroPageY => Ok(Operand::ZeroPageY(byte)),
        AddressingMode::Absolute => Ok(Operand::Absolute(operand)),
        AddressingMode::AbsoluteX => Ok(Operand::AbsoluteX(operand)),
        AddressingMode::AbsoluteY => Ok(Operand::AbsoluteY(operand)),
        AddressingMode::IndexedIndirect => Ok(Operand::IndexedIndirect(byte)),
        AddressingMode::IndirectIndexed => Ok(Operand::IndirectIndexed(byte)),
        _ => Err(RuntimeError {
            message: format!("addressing mode {mode:?} is not a data operand"),
            bank: 0,
            pc: 0,
            instructions: 0,
        }),
    }
}

fn code_segment<'a, B: Bus>(
    code: &'a [CodeSegment],
    bus: &B,
    state: &CpuState,
) -> Result<&'a CodeSegment, RuntimeError> {
    let mapped_bank = bus.mapped_prg_bank(state.pc);
    let mut matches = code.iter().filter(|segment| {
        let length = u16::try_from(segment.bytes.len()).unwrap_or(u16::MAX);
        let end = segment.cpu_address.saturating_add(length);
        segment.cpu_address <= state.pc
            && state.pc < end
            && mapped_bank.is_none_or(|bank| bank == segment.bank)
    });
    let first = matches.next().ok_or_else(|| {
        RuntimeError::at(
            state,
            0,
            format!("no fallback code covers CPU address ${:04X}", state.pc),
        )
    })?;
    if matches.next().is_some() {
        return Err(RuntimeError::at(
            state,
            0,
            format!(
                "fallback code at CPU address ${:04X} is bank-ambiguous",
                state.pc
            ),
        ));
    }
    Ok(first)
}

#[cfg(test)]
mod tests {
    use super::{
        AccessKind, Bus, CodeSegment, CpuState, ExecutionBudget, ObservableEvent, RuntimeError,
        interpret_function,
    };

    struct TestBus {
        memory: [u8; 65_536],
        events: Vec<ObservableEvent>,
    }

    impl Default for TestBus {
        fn default() -> Self {
            Self {
                memory: [0; 65_536],
                events: Vec::new(),
            }
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
    fn interprets_wrapping_loop_and_records_bus_events() {
        let code = [CodeSegment {
            bank: 0,
            cpu_address: 0xc000,
            bytes: &[
                0xa2, 0xfe, // ldx #$fe
                0xe8, // inx
                0x86, 0x02, // stx $02
                0xe0, 0x00, // cpx #0
                0xd0, 0xf9, // bne $c002
                0x60, // rts
            ],
        }];
        let mut state = CpuState::default();
        let mut bus = TestBus::default();
        let mut budget = ExecutionBudget::new(32).expect("budget");
        interpret_function(&mut state, &mut bus, &mut budget, &code, 0, 0xc000, 8)
            .expect("fallback");
        assert_eq!(state.x, 0);
        assert_eq!(bus.memory[2], 0);
        assert_eq!(budget.consumed(), 10);
        assert!(bus.events.iter().any(|event| {
            event.kind == AccessKind::Write && event.address == 2 && event.value == 0xff
        }));
    }

    #[test]
    fn bounds_fallback_execution_and_rejects_ambiguous_banks() {
        let loop_code = [CodeSegment {
            bank: 0,
            cpu_address: 0xc000,
            bytes: &[0x4c, 0x00, 0xc0],
        }];
        let mut state = CpuState::default();
        let mut bus = TestBus::default();
        let mut budget = ExecutionBudget::new(2).expect("budget");
        let error = interpret_function(&mut state, &mut bus, &mut budget, &loop_code, 0, 0xc000, 8)
            .expect_err("limit");
        assert!(error.message.contains("instruction limit"));

        let ambiguous = [
            loop_code[0],
            CodeSegment {
                bank: 1,
                cpu_address: 0xc000,
                bytes: &[0x60],
            },
        ];
        let mut unqualified_bus = TestBus::default();
        let mut ambiguous_budget = ExecutionBudget::new(1).expect("budget");
        unqualified_bus.memory[0] = 0;
        struct UnknownBank(TestBus);
        impl Bus for UnknownBank {
            fn read(&mut self, state: &CpuState, address: u16) -> Result<u8, RuntimeError> {
                self.0.read(state, address)
            }
            fn write(
                &mut self,
                state: &CpuState,
                address: u16,
                value: u8,
            ) -> Result<(), RuntimeError> {
                self.0.write(state, address, value)
            }
        }
        let mut unknown = UnknownBank(unqualified_bus);
        let error = interpret_function(
            &mut state,
            &mut unknown,
            &mut ambiguous_budget,
            &ambiguous,
            0,
            0xc000,
            8,
        )
        .expect_err("ambiguous");
        assert!(error.message.contains("bank-ambiguous"));
    }
}
