//! Ricoh 2A03/2A07 code generation for verified NesC MIR.

use std::collections::HashMap;
use std::error::Error;
use std::fmt;

use nesc_mir::{
    BinaryOperator, BlockId, Function, Instruction, InstructionKind, Module, SourceSpan,
    Terminator, UnaryOperator, ValueId,
};
use nesc_object::{
    Binding, Object, Relocation, RelocationKind, SectionId, SectionKind, SymbolId, SymbolKind,
};

/// Result of 6502 instruction selection.
#[derive(Clone, Debug)]
pub struct GeneratedCode {
    /// Relocatable machine code.
    pub object: Object,
    /// Symbolic assembly listing.
    pub assembly: String,
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
/// The initial public `nescall` subset passes up to three 8-bit arguments in
/// A, X, and Y and returns an 8-bit scalar in A.
///
/// # Errors
///
/// Returns failures for unsupported wide operations, address expressions, or
/// exhausted static temporary storage.
pub fn generate(module: &Module) -> Result<GeneratedCode, Vec<CodegenError>> {
    let mut emitter = Emitter::new(module)?;
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
    frame_indices: HashMap<u32, u16>,
    assembly: String,
    label_counter: u32,
    errors: Vec<CodegenError>,
}

impl Emitter {
    fn new(module: &Module) -> Result<Self, Vec<CodegenError>> {
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
        let mut frame_indices = HashMap::new();
        for function in &module.functions {
            if !function.blocks.is_empty() {
                let index = u16::try_from(frame_indices.len()).map_err(|_| {
                    vec![CodegenError {
                        message: "too many defined functions for static frame allocation"
                            .to_owned(),
                        span: None,
                    }]
                })?;
                if index >= 12 {
                    return Err(vec![CodegenError {
                        message: "initial backend supports at most 12 static function frames"
                            .to_owned(),
                        span: None,
                    }]);
                }
                frame_indices.insert(function.id.0, index);
            }
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
            }
        }
        Ok(Self {
            object,
            code,
            function_symbols,
            block_symbols,
            frame_indices,
            assembly: ".segment \"CODE\"\n".to_owned(),
            label_counter: 0,
            errors: Vec::new(),
        })
    }

    fn function(&mut self, function: &Function) {
        if function.locals.len() > 16 {
            self.errors.push(CodegenError {
                message: format!(
                    "function `{}` requires more than 16 static local slots",
                    function.name
                ),
                span: None,
            });
            return;
        }
        let function_symbol = self.function_symbols[function.id.0 as usize];
        self.define(function_symbol);
        self.assembly.push_str(&format!(
            "\n.export {}\n{}:\n",
            function.name, function.name
        ));
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
                self.lda_immediate(*value as u8);
                self.store_result(function, instruction);
            }
            InstructionKind::LoadLocal(local) => {
                self.lda_absolute(self.local_address(function, local.0));
                self.store_result(function, instruction);
            }
            InstructionKind::StoreLocal { local, value } => {
                self.lda_absolute(self.value_address(function, *value));
                self.sta_absolute(self.local_address(function, local.0));
            }
            InstructionKind::LoadGlobal(global) => {
                self.lda_absolute(global_address(global.0));
                self.store_result(function, instruction);
            }
            InstructionKind::StoreGlobal { global, value } => {
                self.lda_absolute(self.value_address(function, *value));
                self.sta_absolute(global_address(global.0));
            }
            InstructionKind::Unary { operator, operand } => {
                self.unary(function, instruction, *operator, *operand);
            }
            InstructionKind::Binary {
                operator,
                left,
                right,
            } => self.binary(function, instruction, *operator, *left, *right),
            InstructionKind::Cast { value, .. } => {
                self.lda_absolute(self.value_address(function, *value));
                self.store_result(function, instruction);
            }
            InstructionKind::Call {
                function: callee,
                arguments,
            } => {
                if arguments.len() > 3 {
                    self.error(
                        "nescall currently supports at most three register arguments",
                        instruction.span,
                    );
                    return;
                }
                if let Some(value) = arguments.first() {
                    self.lda_absolute(self.value_address(function, *value));
                }
                if let Some(value) = arguments.get(1) {
                    self.ldx_absolute(self.value_address(function, *value));
                }
                if let Some(value) = arguments.get(2) {
                    self.ldy_absolute(self.value_address(function, *value));
                }
                self.absolute_symbol(0x20, "jsr", self.function_symbols[callee.0 as usize]);
                self.store_result(function, instruction);
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
        self.lda_absolute(self.value_address(function, operand));
        match operator {
            UnaryOperator::Plus => {}
            UnaryOperator::Negate => {
                self.emit_byte(0x49, "eor #$ff");
                self.emit_byte(0xff, "");
                self.emit_byte(0x18, "clc");
                self.emit_byte(0x69, "adc #$01");
                self.emit_byte(0x01, "");
            }
            UnaryOperator::LogicalNot => self.boolean_from_branch(0xf0, "beq"),
            UnaryOperator::BitwiseNot => {
                self.emit_byte(0x49, "eor #$ff");
                self.emit_byte(0xff, "");
            }
            _ => {
                self.error(
                    "pointer and update unary operations require prior MIR lowering",
                    instruction.span,
                );
                return;
            }
        }
        self.store_result(function, instruction);
    }

    fn binary(
        &mut self,
        function: &Function,
        instruction: &Instruction,
        operator: BinaryOperator,
        left: ValueId,
        right: ValueId,
    ) {
        let left_address = self.value_address(function, left);
        let right_address = self.value_address(function, right);
        self.lda_absolute(left_address);
        match operator {
            BinaryOperator::Add => {
                self.emit_byte(0x18, "clc");
                self.absolute_address(0x6d, "adc", right_address);
            }
            BinaryOperator::Subtract => {
                self.emit_byte(0x38, "sec");
                self.absolute_address(0xed, "sbc", right_address);
            }
            BinaryOperator::BitwiseAnd => self.absolute_address(0x2d, "and", right_address),
            BinaryOperator::BitwiseOr => self.absolute_address(0x0d, "ora", right_address),
            BinaryOperator::BitwiseXor => self.absolute_address(0x4d, "eor", right_address),
            BinaryOperator::Equal | BinaryOperator::NotEqual => {
                self.absolute_address(0xcd, "cmp", right_address);
                let (opcode, mnemonic) = if operator == BinaryOperator::Equal {
                    (0xf0, "beq")
                } else {
                    (0xd0, "bne")
                };
                self.boolean_from_branch(opcode, mnemonic);
            }
            BinaryOperator::Less => {
                self.absolute_address(0xcd, "cmp", right_address);
                self.boolean_from_branch(0x90, "bcc");
            }
            BinaryOperator::GreaterEqual => {
                self.absolute_address(0xcd, "cmp", right_address);
                self.boolean_from_branch(0xb0, "bcs");
            }
            _ => {
                self.error(
                    "this MIR binary operation needs a runtime helper",
                    instruction.span,
                );
                return;
            }
        }
        self.store_result(function, instruction);
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
                self.lda_absolute(self.value_address(function, *condition));
                let then_symbol = self.block_symbol(function, *then_block);
                self.relative_symbol(0xd0, "bne", then_symbol);
                let else_symbol = self.block_symbol(function, *else_block);
                self.absolute_symbol(0x4c, "jmp", else_symbol);
            }
            Terminator::Return(value) => {
                if let Some(value) = value {
                    self.lda_absolute(self.value_address(function, *value));
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

    fn store_result(&mut self, function: &Function, instruction: &Instruction) {
        if let Some(result) = instruction.result {
            if result.0 >= 64 {
                self.error(
                    "function requires more than 64 temporary values",
                    instruction.span,
                );
            } else {
                self.sta_absolute(self.value_address(function, result));
            }
        }
    }

    fn block_symbol(&self, function: &Function, block: BlockId) -> SymbolId {
        self.block_symbols[&(function.id.0, block.0)]
    }

    fn local_address(&self, function: &Function, local: u32) -> u16 {
        let frame = self.frame_indices[&function.id.0];
        0x0300 + frame * 0x20 + u16::try_from(local.saturating_mul(2)).unwrap_or(0)
    }

    fn value_address(&self, function: &Function, value: ValueId) -> u16 {
        let frame = self.frame_indices[&function.id.0];
        0x0500 + frame * 0x40 + u16::try_from(value.0).unwrap_or(0)
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

    fn define(&mut self, symbol: SymbolId) {
        let offset = self.code_len();
        self.object.symbols[symbol.0 as usize].offset = offset as u32;
    }

    fn lda_immediate(&mut self, value: u8) {
        self.emit_bytes(&[0xa9, value], &format!("lda #${value:02x}"));
    }

    fn lda_absolute(&mut self, address: u16) {
        self.absolute_address(0xad, "lda", address);
    }

    fn sta_absolute(&mut self, address: u16) {
        self.absolute_address(0x8d, "sta", address);
    }

    fn ldx_absolute(&mut self, address: u16) {
        self.absolute_address(0xae, "ldx", address);
    }

    fn ldy_absolute(&mut self, address: u16) {
        self.absolute_address(0xac, "ldy", address);
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

fn global_address(global: u32) -> u16 {
    0x0200 + u16::try_from(global.saturating_mul(4)).unwrap_or(u16::MAX)
}

#[cfg(test)]
mod tests {
    use nesc_mir::{
        BasicBlock, BlockId, Function, FunctionId, Instruction, InstructionKind, Module, SourceId,
        SourceSpan, Terminator, Type, TypeKind, ValueId,
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
}
