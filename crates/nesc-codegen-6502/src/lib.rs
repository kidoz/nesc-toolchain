//! Ricoh 2A03/2A07 code generation for verified NesC MIR.

mod abi;
mod allocation;
mod stack;

use std::collections::HashMap;
use std::error::Error;
use std::fmt;

use nesc_mir::{
    BinaryOperator, BlockId, Function, Instruction, InstructionKind, Module, SourceSpan,
    Terminator, TypeKind, UnaryOperator, ValueId,
};
use nesc_object::{
    Binding, Object, Relocation, RelocationKind, SectionId, SectionKind, SymbolId, SymbolKind,
};

pub use abi::{
    ARGUMENT_SPILL_BASE, ARGUMENT_SPILL_LEN, AbiLocation, RETURN_SPILL_BASE, RETURN_SPILL_LEN,
    argument_location, return_location,
};
pub use allocation::{
    AllocationEntry, BackendConfig, Location, RUNTIME_SCRATCH_END, RUNTIME_SCRATCH_START,
    ZeroPageRange, ZeroPageStrategy,
};
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
    let stack = stack::analyze(module, config.stack_limit)?;
    let zero_page_report = allocation::render_report(&allocation);
    let stack_report = stack::render_report(&stack);
    let mut emitter = Emitter::new(module, allocation)?;
    for function in &module.functions {
        if !function.blocks.is_empty() {
            emitter.function(function);
        }
    }
    if emitter.errors.is_empty() {
        emitter.object.validate().map_err(|errors| {
            errors
                .into_iter()
                .map(|error| CodegenError {
                    message: error.to_string(),
                    span: None,
                })
                .collect::<Vec<_>>()
        })?;
        Ok(GeneratedCode {
            object: emitter.object,
            assembly: emitter.assembly,
            zero_page_report,
            stack_report,
            stack,
        })
    } else {
        Err(emitter.errors)
    }
}

struct Emitter {
    object: Object,
    code: SectionId,
    function_symbols: Vec<SymbolId>,
    block_symbols: HashMap<(u32, u32), SymbolId>,
    helper_symbols: HashMap<String, SymbolId>,
    constants: HashMap<(u32, u32), u64>,
    allocation: allocation::Allocation,
    assembly: String,
    label_counter: u32,
    errors: Vec<CodegenError>,
}

impl Emitter {
    fn new(module: &Module, allocation: allocation::Allocation) -> Result<Self, Vec<CodegenError>> {
        let mut object = Object::default();
        let code = object
            .add_section(".text", SectionKind::Code, 1)
            .map_err(|error| {
                vec![CodegenError {
                    message: error.to_string(),
                    span: None,
                }]
            })?;
        let mut function_symbols = Vec::with_capacity(module.functions.len());
        for function in &module.functions {
            let section = (!function.blocks.is_empty()).then_some(code);
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
                        Some(code),
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
        Ok(Self {
            object,
            code,
            function_symbols,
            block_symbols,
            helper_symbols: HashMap::new(),
            constants,
            allocation,
            assembly: ".segment \"CODE\"\n".to_owned(),
            label_counter: 0,
            errors: Vec::new(),
        })
    }

    fn function(&mut self, function: &Function) {
        let function_symbol = self.function_symbols[function.id.0 as usize];
        self.define(function_symbol);
        self.assembly.push_str(&format!(
            "\n.export {}\n{}:\n",
            function.name, function.name
        ));
        self.parameter_prologue(function);
        for block in &function.blocks {
            let block_symbol = self.block_symbols[&(function.id.0, block.id.0)];
            self.define(block_symbol);
            self.assembly
                .push_str(&format!("{}.block{}:\n", function.name, block.id.0));
            for instruction in &block.instructions {
                self.instruction(function, instruction);
            }
            if let Some(terminator) = &block.terminator {
                self.terminator(function, terminator);
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
                    self.copy_location(
                        self.global_location(*global),
                        self.value_location(function, result),
                    );
                }
            }
            InstructionKind::StoreGlobal { global, value } => {
                self.copy_location(
                    self.value_location(function, *value),
                    self.global_location(*global),
                );
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
                    self.write_constant(
                        self.value_location(function, result),
                        u64::from(self.global_location(*global).address),
                    );
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
                address, value, ty, ..
            } => {
                self.store_indirect(function, *address, *value, ty);
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
            self.sta_location(destination, offset);
        }
    }

    fn store_indirect(
        &mut self,
        function: &Function,
        address: ValueId,
        value: ValueId,
        ty: &nesc_mir::Type,
    ) {
        let source = self.value_location(function, value);
        self.prepare_indirect_address(function, address);
        for offset in 0..source.size.min(allocation::type_size(ty)) {
            self.ldy_immediate(offset as u8);
            self.lda_location(source, offset);
            self.emit_bytes(
                &[0x91, ARGUMENT_SPILL_BASE],
                &format!("sta (${:02x}),y", ARGUMENT_SPILL_BASE),
            );
        }
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
            && self.constant_arithmetic(
                operator,
                signed,
                value,
                left_location,
                destination,
                bit_width,
            )
        {
            return;
        }

        let bits = destination.size * 8;
        let name = match operator {
            BinaryOperator::Multiply => format!("__nesc_mul_{bits}"),
            BinaryOperator::Divide => {
                format!("__nesc_{}div_{bits}", if signed { "s" } else { "u" })
            }
            BinaryOperator::Remainder => {
                format!("__nesc_{}rem_{bits}", if signed { "s" } else { "u" })
            }
            BinaryOperator::ShiftLeft => format!("__nesc_shl_{bits}"),
            BinaryOperator::ShiftRight if signed => format!("__nesc_ashr_{bits}"),
            BinaryOperator::ShiftRight => format!("__nesc_lshr_{bits}"),
            _ => unreachable!("arithmetic helper operator"),
        };
        let symbol = self.helper_symbol(&name);
        self.emit_call(
            &[left_location, right_location],
            Some(destination),
            symbol,
            instruction.span,
        );
    }

    fn constant_arithmetic(
        &mut self,
        operator: BinaryOperator,
        signed: bool,
        constant: u64,
        source: Location,
        destination: Location,
        bit_width: u16,
    ) -> bool {
        match operator {
            BinaryOperator::Multiply if constant == 0 => {
                self.write_constant(destination, 0);
                true
            }
            BinaryOperator::Multiply if constant.is_power_of_two() => {
                self.inline_shift(
                    source,
                    destination,
                    constant.trailing_zeros() as u16,
                    BinaryOperator::ShiftLeft,
                    false,
                );
                true
            }
            BinaryOperator::Divide if !signed && constant.is_power_of_two() => {
                self.inline_shift(
                    source,
                    destination,
                    constant.trailing_zeros() as u16,
                    BinaryOperator::ShiftRight,
                    false,
                );
                true
            }
            BinaryOperator::Remainder if !signed && constant.is_power_of_two() => {
                let mask = constant - 1;
                for offset in 0..destination.size {
                    self.lda_location(source, offset);
                    self.immediate(0x29, "and", (mask >> (u32::from(offset) * 8)) as u8);
                    self.sta_location(destination, offset);
                }
                true
            }
            BinaryOperator::ShiftLeft | BinaryOperator::ShiftRight => {
                debug_assert!(constant < u64::from(bit_width));
                self.inline_shift(source, destination, constant as u16, operator, signed);
                true
            }
            _ => false,
        }
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

    fn terminator(&mut self, function: &Function, terminator: &Terminator) {
        match terminator {
            Terminator::Jump(block) => {
                let symbol = self.block_symbol(function, *block);
                self.absolute_symbol(0x4c, "jmp", symbol);
            }
            Terminator::Branch {
                condition,
                then_block,
                else_block,
            } => {
                self.reduce_location(self.value_location(function, *condition));
                let then_symbol = self.block_symbol(function, *then_block);
                self.relative_symbol(0xd0, "bne", then_symbol);
                let else_symbol = self.block_symbol(function, *else_block);
                self.absolute_symbol(0x4c, "jmp", else_symbol);
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
    }

    fn lda_immediate(&mut self, value: u8) {
        self.emit_bytes(&[0xa9, value], &format!("lda #${value:02x}"));
    }

    fn ldy_immediate(&mut self, value: u8) {
        self.emit_bytes(&[0xa0, value], &format!("ldy #${value:02x}"));
    }

    fn immediate(&mut self, opcode: u8, mnemonic: &str, value: u8) {
        self.emit_bytes(&[opcode, value], &format!("{mnemonic} #${value:02x}"));
    }

    fn lda_location(&mut self, location: Location, offset: u16) {
        self.memory_operation(0xa5, 0xad, "lda", location, offset);
    }

    fn sta_location(&mut self, location: Location, offset: u16) {
        self.memory_operation(0x85, 0x8d, "sta", location, offset);
    }

    fn ldx_location(&mut self, location: Location, offset: u16) {
        self.memory_operation(0xa6, 0xae, "ldx", location, offset);
    }

    fn stx_location(&mut self, location: Location, offset: u16) {
        self.memory_operation(0x86, 0x8e, "stx", location, offset);
    }

    fn ldy_location(&mut self, location: Location, offset: u16) {
        self.memory_operation(0xa4, 0xac, "ldy", location, offset);
    }

    fn sty_location(&mut self, location: Location, offset: u16) {
        self.memory_operation(0x84, 0x8c, "sty", location, offset);
    }

    fn lda_zero_page(&mut self, address: u8) {
        self.absolute_or_zero_page(0xa5, 0xad, "lda", u16::from(address), true);
    }

    fn sta_zero_page(&mut self, address: u8) {
        self.absolute_or_zero_page(0x85, 0x8d, "sta", u16::from(address), true);
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
    }

    fn relative_symbol(&mut self, opcode: u8, mnemonic: &str, symbol: SymbolId) {
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

#[cfg(test)]
mod tests {
    use nesc_mir::{
        BasicBlock, BinaryOperator, BlockId, Function, FunctionId, Instruction, InstructionKind,
        Module, SourceId, SourceSpan, Terminator, Type, TypeKind, ValueId,
    };

    use super::generate;

    #[test]
    fn emits_constant_return_and_function_symbol() {
        let ty = Type::scalar(TypeKind::Integer(nesc_mir::IntegerType::U8));
        let span = SourceSpan::new(SourceId::new(0), 0, 1);
        let module = Module {
            globals: Vec::new(),
            functions: vec![Function {
                id: FunctionId(0),
                name: "main".to_owned(),
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
    }

    #[test]
    fn selects_eight_bit_multiply_helper() {
        let ty = Type::scalar(TypeKind::Integer(nesc_mir::IntegerType::U8));
        let span = SourceSpan::new(SourceId::new(0), 0, 1);
        let module = Module {
            globals: Vec::new(),
            functions: vec![Function {
                id: FunctionId(0),
                name: "multiply".to_owned(),
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
}
