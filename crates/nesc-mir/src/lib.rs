//! Control-flow intermediate representation and verifier for NesC.

use std::collections::{HashMap, HashSet};
use std::fmt;

pub use nesc_hir::{
    BinaryOperator, FunctionId, GlobalId, IntegerType, SourceId, SourceSpan, Type, TypeKind,
    UnaryOperator,
};
use nesc_hir::{Expression, ExpressionKind, Module as HirModule, Statement};

/// Stable basic-block identifier.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct BlockId(pub u32);

/// Stable virtual-value identifier.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ValueId(pub u32);

/// Stable local-slot identifier.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct LocalId(pub u32);

/// Side-effect classification used by optimization and code generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Effect {
    /// No observable effect and no memory access.
    Pure,
    /// Non-volatile memory read.
    Read,
    /// Non-volatile memory write.
    Write,
    /// Call with effects described by its callee contract.
    Call,
    /// Volatile or hardware-observable access.
    Volatile,
    /// Runtime trap.
    Trap,
}

/// MIR module.
#[derive(Clone, Debug)]
pub struct Module {
    /// Function declarations and definitions.
    pub functions: Vec<Function>,
    /// Global object types indexed by `GlobalId`.
    pub globals: Vec<Type>,
}

/// MIR function.
#[derive(Clone, Debug)]
pub struct Function {
    /// Stable HIR function identifier.
    pub id: FunctionId,
    /// Linker-visible name.
    pub name: String,
    /// Return type.
    pub return_type: Type,
    /// Parameter slots.
    pub parameters: Vec<LocalId>,
    /// Local slots and their exact types.
    pub locals: Vec<Local>,
    /// Entry block for a definition.
    pub entry: Option<BlockId>,
    /// Control-flow blocks; empty for declarations.
    pub blocks: Vec<BasicBlock>,
    /// Type table indexed by virtual value.
    pub value_types: Vec<Type>,
}

/// Function-local storage slot.
#[derive(Clone, Debug)]
pub struct Local {
    /// Stable slot identifier.
    pub id: LocalId,
    /// Source name.
    pub name: String,
    /// Exact slot type.
    pub ty: Type,
    /// Whether this slot represents a parameter.
    pub parameter: bool,
}

/// Basic block with one required terminator.
#[derive(Clone, Debug)]
pub struct BasicBlock {
    /// Stable block identifier.
    pub id: BlockId,
    /// Instructions in execution order.
    pub instructions: Vec<Instruction>,
    /// Control transfer ending the block.
    pub terminator: Option<Terminator>,
}

/// MIR instruction.
#[derive(Clone, Debug)]
pub struct Instruction {
    /// Produced virtual value, absent for stores and void calls.
    pub result: Option<ValueId>,
    /// Instruction operation.
    pub kind: InstructionKind,
    /// Observable-effect classification.
    pub effect: Effect,
    /// Original source range.
    pub span: SourceSpan,
}

/// MIR instruction operation.
#[derive(Clone, Debug)]
pub enum InstructionKind {
    /// Integer or boolean constant.
    Constant(u64),
    /// Read a local slot.
    LoadLocal(LocalId),
    /// Write a local slot.
    StoreLocal {
        /// Destination slot.
        local: LocalId,
        /// Stored value.
        value: ValueId,
    },
    /// Read a global object.
    LoadGlobal(GlobalId),
    /// Write a global object.
    StoreGlobal {
        /// Destination object.
        global: GlobalId,
        /// Stored value.
        value: ValueId,
    },
    /// Prefix arithmetic or logical operation.
    Unary {
        /// Operation.
        operator: UnaryOperator,
        /// Operand.
        operand: ValueId,
    },
    /// Binary arithmetic, comparison, or logical operation.
    Binary {
        /// Operation.
        operator: BinaryOperator,
        /// Left operand.
        left: ValueId,
        /// Right operand.
        right: ValueId,
    },
    /// Explicit numeric conversion.
    Cast {
        /// Converted value.
        value: ValueId,
        /// Destination type.
        target: Type,
    },
    /// Direct call.
    Call {
        /// Statically resolved callee.
        function: FunctionId,
        /// Arguments in evaluation order.
        arguments: Vec<ValueId>,
    },
}

/// Required control transfer at the end of a block.
#[derive(Clone, Debug)]
pub enum Terminator {
    /// Unconditional transfer.
    Jump(BlockId),
    /// Boolean transfer.
    Branch {
        /// Condition value.
        condition: ValueId,
        /// Destination for a nonzero condition.
        then_block: BlockId,
        /// Destination for a zero condition.
        else_block: BlockId,
    },
    /// Function return.
    Return(Option<ValueId>),
    /// Deliberately unreachable control flow.
    Unreachable,
}

/// Failure to lower a checked HIR construct supported by a later compiler increment.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LoweringError {
    /// Human-readable explanation.
    pub message: String,
    /// Source range of the unsupported construct.
    pub span: SourceSpan,
}

/// MIR verification failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerificationError {
    /// Function containing the failure.
    pub function: FunctionId,
    /// Block containing the failure when applicable.
    pub block: Option<BlockId>,
    /// Deterministic explanation.
    pub message: String,
}

impl fmt::Display for VerificationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "function {:?}", self.function)?;
        if let Some(block) = self.block {
            write!(formatter, ", block {:?}", block)?;
        }
        write!(formatter, ": {}", self.message)
    }
}

/// Lowers structured HIR into control-flow MIR.
///
/// # Errors
///
/// Returns source-backed failures for constructs not representable by the
/// current MIR contract.
pub fn lower(hir: &HirModule) -> Result<Module, Vec<LoweringError>> {
    let globals = hir
        .globals
        .iter()
        .map(|global| global.variable.ty.clone())
        .collect::<Vec<_>>();
    let mut errors = Vec::new();
    let mut functions = Vec::with_capacity(hir.functions.len());
    for function in &hir.functions {
        let Some(body) = &function.body else {
            let locals = function
                .parameters
                .iter()
                .enumerate()
                .map(|(index, parameter)| Local {
                    id: LocalId(u32::try_from(index).expect("parameter count fits u32")),
                    name: parameter
                        .name
                        .clone()
                        .unwrap_or_else(|| format!("$arg{index}")),
                    ty: parameter.ty.clone(),
                    parameter: true,
                })
                .collect::<Vec<_>>();
            functions.push(Function {
                id: function.id,
                name: function.name.clone(),
                return_type: function.signature.return_type.clone(),
                parameters: locals.iter().map(|local| local.id).collect(),
                locals,
                entry: None,
                blocks: Vec::new(),
                value_types: Vec::new(),
            });
            continue;
        };
        let mut builder = Builder::new(hir, function);
        builder.lower_block(body, false);
        builder.finish();
        errors.append(&mut builder.errors);
        functions.push(builder.function);
    }
    if errors.is_empty() {
        Ok(Module { functions, globals })
    } else {
        Err(errors)
    }
}

/// Verifies all functions in a MIR module.
///
/// # Errors
///
/// Returns every structural, reference, and type-table failure found.
pub fn verify(module: &Module) -> Result<(), Vec<VerificationError>> {
    let mut errors = Vec::new();
    for function in &module.functions {
        verify_function(module, function, &mut errors);
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

struct Builder<'a> {
    hir: &'a HirModule,
    function: Function,
    current: BlockId,
    scopes: Vec<HashMap<String, LocalId>>,
    loops: Vec<(BlockId, BlockId)>,
    errors: Vec<LoweringError>,
}

impl<'a> Builder<'a> {
    fn new(hir: &'a HirModule, source: &nesc_hir::Function) -> Self {
        let entry = BlockId(0);
        let mut builder = Self {
            hir,
            function: Function {
                id: source.id,
                name: source.name.clone(),
                return_type: source.signature.return_type.clone(),
                parameters: Vec::new(),
                locals: Vec::new(),
                entry: Some(entry),
                blocks: vec![BasicBlock {
                    id: entry,
                    instructions: Vec::new(),
                    terminator: None,
                }],
                value_types: Vec::new(),
            },
            current: entry,
            scopes: vec![HashMap::new()],
            loops: Vec::new(),
            errors: Vec::new(),
        };
        for (index, parameter) in source.parameters.iter().enumerate() {
            let name = parameter
                .name
                .clone()
                .unwrap_or_else(|| format!("$arg{index}"));
            let local = builder.add_local(name.clone(), parameter.ty.clone(), true);
            builder.function.parameters.push(local);
            builder.scopes[0].insert(name, local);
        }
        builder
    }

    fn finish(&mut self) {
        if !self.terminated(self.current) {
            let terminator = if self.function.return_type.kind == TypeKind::Void {
                Terminator::Return(None)
            } else {
                Terminator::Unreachable
            };
            self.terminate(terminator);
        }
    }

    fn lower_block(&mut self, block: &nesc_hir::Block, create_scope: bool) {
        if create_scope {
            self.scopes.push(HashMap::new());
        }
        for statement in &block.statements {
            self.lower_statement(statement);
        }
        if create_scope {
            self.scopes.pop();
        }
    }

    fn lower_statement(&mut self, statement: &Statement) {
        match statement {
            Statement::Block(block) => self.lower_block(block, true),
            Statement::Variable(variable) => {
                let local = self.add_local(variable.name.clone(), variable.ty.clone(), false);
                self.scopes
                    .last_mut()
                    .expect("builder has a scope")
                    .insert(variable.name.clone(), local);
                if let Some(initializer) = &variable.initializer
                    && let Some(value) = self.lower_expression(initializer)
                {
                    self.emit(
                        None,
                        InstructionKind::StoreLocal { local, value },
                        Effect::Write,
                        variable.span,
                    );
                }
            }
            Statement::Expression { expression, .. } => {
                if let Some(expression) = expression {
                    self.lower_expression(expression);
                }
            }
            Statement::If {
                condition,
                then_branch,
                else_branch,
                ..
            } => self.lower_if(condition, then_branch, else_branch.as_deref()),
            Statement::While {
                condition, body, ..
            } => self.lower_while(condition, body),
            Statement::For {
                initializer,
                condition,
                increment,
                body,
                ..
            } => self.lower_for(
                initializer.as_ref(),
                condition.as_ref(),
                increment.as_ref(),
                body,
            ),
            Statement::Break { span, .. } => {
                if let Some((_, exit)) = self.loops.last().copied() {
                    self.terminate(Terminator::Jump(exit));
                    self.current = self.new_block();
                } else {
                    self.unsupported("`break` has no loop target", *span);
                }
            }
            Statement::Continue { span, .. } => {
                if let Some((continuation, _)) = self.loops.last().copied() {
                    self.terminate(Terminator::Jump(continuation));
                    self.current = self.new_block();
                } else {
                    self.unsupported("`continue` has no loop target", *span);
                }
            }
            Statement::Return { value, .. } => {
                let value = value
                    .as_ref()
                    .and_then(|expression| self.lower_expression(expression));
                self.terminate(Terminator::Return(value));
                self.current = self.new_block();
            }
        }
    }

    fn lower_if(
        &mut self,
        condition: &Expression,
        then_branch: &Statement,
        else_branch: Option<&Statement>,
    ) {
        let Some(condition) = self.lower_expression(condition) else {
            return;
        };
        let then_block = self.new_block();
        let else_block = self.new_block();
        let join_block = self.new_block();
        self.terminate(Terminator::Branch {
            condition,
            then_block,
            else_block,
        });
        self.current = then_block;
        self.lower_statement(then_branch);
        if !self.terminated(self.current) {
            self.terminate(Terminator::Jump(join_block));
        }
        self.current = else_block;
        if let Some(else_branch) = else_branch {
            self.lower_statement(else_branch);
        }
        if !self.terminated(self.current) {
            self.terminate(Terminator::Jump(join_block));
        }
        self.current = join_block;
    }

    fn lower_while(&mut self, condition: &Expression, body: &Statement) {
        let header = self.new_block();
        let body_block = self.new_block();
        let exit = self.new_block();
        self.terminate(Terminator::Jump(header));
        self.current = header;
        let Some(condition) = self.lower_expression(condition) else {
            return;
        };
        self.terminate(Terminator::Branch {
            condition,
            then_block: body_block,
            else_block: exit,
        });
        self.current = body_block;
        self.loops.push((header, exit));
        self.lower_statement(body);
        self.loops.pop();
        if !self.terminated(self.current) {
            self.terminate(Terminator::Jump(header));
        }
        self.current = exit;
    }

    fn lower_for(
        &mut self,
        initializer: Option<&Expression>,
        condition: Option<&Expression>,
        increment: Option<&Expression>,
        body: &Statement,
    ) {
        if let Some(initializer) = initializer {
            self.lower_expression(initializer);
        }
        let header = self.new_block();
        let body_block = self.new_block();
        let increment_block = self.new_block();
        let exit = self.new_block();
        self.terminate(Terminator::Jump(header));
        self.current = header;
        if let Some(condition) = condition {
            if let Some(condition) = self.lower_expression(condition) {
                self.terminate(Terminator::Branch {
                    condition,
                    then_block: body_block,
                    else_block: exit,
                });
            }
        } else {
            self.terminate(Terminator::Jump(body_block));
        }
        self.current = body_block;
        self.loops.push((increment_block, exit));
        self.lower_statement(body);
        self.loops.pop();
        if !self.terminated(self.current) {
            self.terminate(Terminator::Jump(increment_block));
        }
        self.current = increment_block;
        if let Some(increment) = increment {
            self.lower_expression(increment);
        }
        if !self.terminated(self.current) {
            self.terminate(Terminator::Jump(header));
        }
        self.current = exit;
    }

    fn lower_expression(&mut self, expression: &Expression) -> Option<ValueId> {
        let ty = expression.ty.clone()?;
        match &expression.kind {
            ExpressionKind::Integer(literal) => Some(self.value_instruction(
                InstructionKind::Constant(literal.value),
                Effect::Pure,
                expression.span,
                ty,
            )),
            ExpressionKind::Boolean(value) => Some(self.value_instruction(
                InstructionKind::Constant(u64::from(*value)),
                Effect::Pure,
                expression.span,
                ty,
            )),
            ExpressionKind::Character(value) => Some(self.value_instruction(
                InstructionKind::Constant(u64::from(*value)),
                Effect::Pure,
                expression.span,
                ty,
            )),
            ExpressionKind::Name(name) => self.load_name(name, expression.span, ty),
            ExpressionKind::Unary { operator, operand } => {
                if matches!(
                    operator,
                    UnaryOperator::Increment | UnaryOperator::Decrement
                ) {
                    return self.lower_update(*operator, operand, false, expression.span, ty);
                }
                let operand = self.lower_expression(operand)?;
                Some(self.value_instruction(
                    InstructionKind::Unary {
                        operator: *operator,
                        operand,
                    },
                    Effect::Pure,
                    expression.span,
                    ty,
                ))
            }
            ExpressionKind::Binary {
                operator,
                left,
                right,
            } => {
                let left = self.lower_expression(left)?;
                let right = self.lower_expression(right)?;
                Some(self.value_instruction(
                    InstructionKind::Binary {
                        operator: *operator,
                        left,
                        right,
                    },
                    Effect::Pure,
                    expression.span,
                    ty,
                ))
            }
            ExpressionKind::Assignment {
                operator,
                target,
                value,
            } => self.lower_assignment(*operator, target, value, expression.span, ty),
            ExpressionKind::Call {
                function,
                arguments,
            } => {
                let function_id = self.hir.function_names.get(function).copied()?;
                let mut values = Vec::with_capacity(arguments.len());
                for argument in arguments {
                    values.push(self.lower_expression(argument)?);
                }
                if ty.kind == TypeKind::Void && ty.pointer_depth == 0 {
                    self.emit(
                        None,
                        InstructionKind::Call {
                            function: function_id,
                            arguments: values,
                        },
                        Effect::Call,
                        expression.span,
                    );
                    None
                } else {
                    Some(self.value_instruction(
                        InstructionKind::Call {
                            function: function_id,
                            arguments: values,
                        },
                        Effect::Call,
                        expression.span,
                        ty,
                    ))
                }
            }
            ExpressionKind::Cast {
                ty: target,
                expression: value,
            } => {
                let value = self.lower_expression(value)?;
                Some(self.value_instruction(
                    InstructionKind::Cast {
                        value,
                        target: target.clone(),
                    },
                    Effect::Pure,
                    expression.span,
                    ty,
                ))
            }
            ExpressionKind::Postfix { operator, operand } => {
                self.lower_update(*operator, operand, true, expression.span, ty)
            }
            ExpressionKind::String(_)
            | ExpressionKind::Index { .. }
            | ExpressionKind::Field { .. } => {
                self.unsupported(
                    "expression lowering is not available for this construct",
                    expression.span,
                );
                None
            }
        }
    }

    fn lower_assignment(
        &mut self,
        operator: BinaryOperator,
        target: &Expression,
        value: &Expression,
        span: SourceSpan,
        ty: Type,
    ) -> Option<ValueId> {
        let ExpressionKind::Name(name) = &target.kind else {
            self.unsupported("only named assignment targets are lowered", target.span);
            return None;
        };
        let right = self.lower_expression(value)?;
        let stored = if operator == BinaryOperator::Assign {
            right
        } else {
            let left = self.load_name(name, target.span, ty.clone())?;
            self.value_instruction(
                InstructionKind::Binary {
                    operator,
                    left,
                    right,
                },
                Effect::Pure,
                span,
                ty,
            )
        };
        self.store_name(name, stored, span);
        Some(stored)
    }

    fn lower_update(
        &mut self,
        operator: UnaryOperator,
        operand: &Expression,
        postfix: bool,
        span: SourceSpan,
        ty: Type,
    ) -> Option<ValueId> {
        let ExpressionKind::Name(name) = &operand.kind else {
            self.unsupported("only named increment targets are lowered", operand.span);
            return None;
        };
        let old = self.load_name(name, operand.span, ty.clone())?;
        let one =
            self.value_instruction(InstructionKind::Constant(1), Effect::Pure, span, ty.clone());
        let operation = if operator == UnaryOperator::Increment {
            BinaryOperator::Add
        } else {
            BinaryOperator::Subtract
        };
        let new = self.value_instruction(
            InstructionKind::Binary {
                operator: operation,
                left: old,
                right: one,
            },
            Effect::Pure,
            span,
            ty,
        );
        self.store_name(name, new, span);
        Some(if postfix { old } else { new })
    }

    fn load_name(&mut self, name: &str, span: SourceSpan, ty: Type) -> Option<ValueId> {
        if let Some(local) = self.local(name) {
            return Some(self.value_instruction(
                InstructionKind::LoadLocal(local),
                Effect::Read,
                span,
                ty,
            ));
        }
        if let Some(global) = self.hir.global_names.get(name).copied() {
            return Some(self.value_instruction(
                InstructionKind::LoadGlobal(global),
                Effect::Read,
                span,
                ty,
            ));
        }
        if let Some((value, _)) = self.hir.constants.get(name) {
            return Some(self.value_instruction(
                InstructionKind::Constant(*value),
                Effect::Pure,
                span,
                ty,
            ));
        }
        self.unsupported(format!("resolved name `{name}` has no MIR storage"), span);
        None
    }

    fn store_name(&mut self, name: &str, value: ValueId, span: SourceSpan) {
        if let Some(local) = self.local(name) {
            self.emit(
                None,
                InstructionKind::StoreLocal { local, value },
                Effect::Write,
                span,
            );
        } else if let Some(global) = self.hir.global_names.get(name).copied() {
            self.emit(
                None,
                InstructionKind::StoreGlobal { global, value },
                Effect::Write,
                span,
            );
        } else {
            self.unsupported(format!("resolved name `{name}` is not writable"), span);
        }
    }

    fn local(&self, name: &str) -> Option<LocalId> {
        self.scopes
            .iter()
            .rev()
            .find_map(|scope| scope.get(name).copied())
    }

    fn add_local(&mut self, name: String, ty: Type, parameter: bool) -> LocalId {
        let id = LocalId(u32::try_from(self.function.locals.len()).expect("local count fits u32"));
        self.function.locals.push(Local {
            id,
            name,
            ty,
            parameter,
        });
        id
    }

    fn value_instruction(
        &mut self,
        kind: InstructionKind,
        effect: Effect,
        span: SourceSpan,
        ty: Type,
    ) -> ValueId {
        let value =
            ValueId(u32::try_from(self.function.value_types.len()).expect("value count fits u32"));
        self.function.value_types.push(ty);
        self.emit(Some(value), kind, effect, span);
        value
    }

    fn emit(
        &mut self,
        result: Option<ValueId>,
        kind: InstructionKind,
        effect: Effect,
        span: SourceSpan,
    ) {
        self.block_mut(self.current).instructions.push(Instruction {
            result,
            kind,
            effect,
            span,
        });
    }

    fn terminate(&mut self, terminator: Terminator) {
        let block = self.block_mut(self.current);
        if block.terminator.is_none() {
            block.terminator = Some(terminator);
        }
    }

    fn new_block(&mut self) -> BlockId {
        let id = BlockId(u32::try_from(self.function.blocks.len()).expect("block count fits u32"));
        self.function.blocks.push(BasicBlock {
            id,
            instructions: Vec::new(),
            terminator: None,
        });
        id
    }

    fn block_mut(&mut self, id: BlockId) -> &mut BasicBlock {
        &mut self.function.blocks[id.0 as usize]
    }

    fn terminated(&self, id: BlockId) -> bool {
        self.function.blocks[id.0 as usize].terminator.is_some()
    }

    fn unsupported(&mut self, message: impl Into<String>, span: SourceSpan) {
        self.errors.push(LoweringError {
            message: message.into(),
            span,
        });
    }
}

fn verify_function(module: &Module, function: &Function, errors: &mut Vec<VerificationError>) {
    if function.blocks.is_empty() {
        if function.entry.is_some() {
            verification_error(errors, function.id, None, "declaration has an entry block");
        }
        return;
    }
    let Some(entry) = function.entry else {
        verification_error(errors, function.id, None, "definition has no entry block");
        return;
    };
    if entry.0 as usize >= function.blocks.len() {
        verification_error(errors, function.id, None, "entry block is out of range");
    }
    let mut defined = HashSet::new();
    for (block_index, block) in function.blocks.iter().enumerate() {
        let expected = BlockId(u32::try_from(block_index).expect("block count fits u32"));
        if block.id != expected {
            verification_error(
                errors,
                function.id,
                Some(block.id),
                "block identifier does not match its index",
            );
        }
        for instruction in &block.instructions {
            verify_instruction(module, function, block.id, instruction, &defined, errors);
            if let Some(result) = instruction.result {
                if result.0 as usize >= function.value_types.len() {
                    verification_error(
                        errors,
                        function.id,
                        Some(block.id),
                        "result value has no type",
                    );
                }
                if !defined.insert(result) {
                    verification_error(
                        errors,
                        function.id,
                        Some(block.id),
                        "value is defined more than once",
                    );
                }
            }
        }
        let Some(terminator) = &block.terminator else {
            verification_error(
                errors,
                function.id,
                Some(block.id),
                "block has no terminator",
            );
            continue;
        };
        match terminator {
            Terminator::Jump(target) => verify_target(function, block.id, *target, errors),
            Terminator::Branch {
                condition,
                then_block,
                else_block,
            } => {
                verify_value(function, block.id, *condition, &defined, errors);
                verify_target(function, block.id, *then_block, errors);
                verify_target(function, block.id, *else_block, errors);
            }
            Terminator::Return(value) => {
                if let Some(value) = value {
                    verify_value(function, block.id, *value, &defined, errors);
                    if function.return_type.kind == TypeKind::Void {
                        verification_error(
                            errors,
                            function.id,
                            Some(block.id),
                            "void function returns a value",
                        );
                    }
                } else if function.return_type.kind != TypeKind::Void {
                    verification_error(
                        errors,
                        function.id,
                        Some(block.id),
                        "non-void function returns no value",
                    );
                }
            }
            Terminator::Unreachable => {}
        }
    }
}

fn verify_instruction(
    module: &Module,
    function: &Function,
    block: BlockId,
    instruction: &Instruction,
    defined: &HashSet<ValueId>,
    errors: &mut Vec<VerificationError>,
) {
    let mut operands = Vec::new();
    match &instruction.kind {
        InstructionKind::Constant(_) => {}
        InstructionKind::LoadLocal(local) => {
            if local.0 as usize >= function.locals.len() {
                verification_error(
                    errors,
                    function.id,
                    Some(block),
                    "local load is out of range",
                );
            }
        }
        InstructionKind::StoreLocal { local, value } => {
            if local.0 as usize >= function.locals.len() {
                verification_error(
                    errors,
                    function.id,
                    Some(block),
                    "local store is out of range",
                );
            }
            operands.push(*value);
        }
        InstructionKind::LoadGlobal(global) => {
            if global.0 as usize >= module.globals.len() {
                verification_error(
                    errors,
                    function.id,
                    Some(block),
                    "global load is out of range",
                );
            }
        }
        InstructionKind::StoreGlobal { global, value } => {
            if global.0 as usize >= module.globals.len() {
                verification_error(
                    errors,
                    function.id,
                    Some(block),
                    "global store is out of range",
                );
            }
            operands.push(*value);
        }
        InstructionKind::Unary { operand, .. } => operands.push(*operand),
        InstructionKind::Binary { left, right, .. } => {
            operands.push(*left);
            operands.push(*right);
        }
        InstructionKind::Cast { value, .. } => operands.push(*value),
        InstructionKind::Call {
            function: callee,
            arguments,
        } => {
            operands.extend(arguments.iter().copied());
            let Some(callee) = module.functions.get(callee.0 as usize) else {
                verification_error(errors, function.id, Some(block), "callee is out of range");
                return;
            };
            if arguments.len() != callee.parameters.len() && !callee.blocks.is_empty() {
                verification_error(
                    errors,
                    function.id,
                    Some(block),
                    "call argument count does not match callee",
                );
            }
        }
    }
    for operand in operands {
        verify_value(function, block, operand, defined, errors);
    }
    let produces_value = !matches!(
        instruction.kind,
        InstructionKind::StoreLocal { .. } | InstructionKind::StoreGlobal { .. }
    );
    if produces_value
        && instruction.result.is_none()
        && !matches!(instruction.kind, InstructionKind::Call { .. })
    {
        verification_error(
            errors,
            function.id,
            Some(block),
            "value-producing instruction has no result",
        );
    }
}

fn verify_value(
    function: &Function,
    block: BlockId,
    value: ValueId,
    defined: &HashSet<ValueId>,
    errors: &mut Vec<VerificationError>,
) {
    if value.0 as usize >= function.value_types.len() {
        verification_error(
            errors,
            function.id,
            Some(block),
            "value identifier is out of range",
        );
    } else if !defined.contains(&value) {
        verification_error(
            errors,
            function.id,
            Some(block),
            "value is used before definition",
        );
    }
}

fn verify_target(
    function: &Function,
    block: BlockId,
    target: BlockId,
    errors: &mut Vec<VerificationError>,
) {
    if target.0 as usize >= function.blocks.len() {
        verification_error(
            errors,
            function.id,
            Some(block),
            "block target is out of range",
        );
    }
}

fn verification_error(
    errors: &mut Vec<VerificationError>,
    function: FunctionId,
    block: Option<BlockId>,
    message: &str,
) {
    errors.push(VerificationError {
        function,
        block,
        message: message.to_owned(),
    });
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::tempdir;

    use nesc_frontend::{FrontendConfig, check};

    use super::{Terminator, lower, verify};

    #[test]
    fn lowers_control_flow_and_passes_verifier() {
        let directory = tempdir().expect("temporary directory");
        let source = directory.path().join("main.c");
        fs::write(
            &source,
            "NES_MAIN int main(void) { u8 x = 0; while (x < 3) { x++; } return x; }",
        )
        .expect("source");
        let checked = check(&FrontendConfig::new(source)).expect("frontend");
        let hir = nesc_hir::lower(checked);
        let mir = lower(&hir).expect("MIR lowering");
        verify(&mir).expect("valid MIR");
        assert!(mir.functions[0].blocks.len() >= 4);
    }

    #[test]
    fn verifier_rejects_missing_terminator() {
        let directory = tempdir().expect("temporary directory");
        let source = directory.path().join("main.c");
        fs::write(&source, "NES_MAIN int main(void) { return 0; }").expect("source");
        let checked = check(&FrontendConfig::new(source)).expect("frontend");
        let hir = nesc_hir::lower(checked);
        let mut mir = lower(&hir).expect("MIR lowering");
        mir.functions[0].blocks[0].terminator = None;
        let errors = verify(&mir).expect_err("invalid MIR");
        assert!(
            errors
                .iter()
                .any(|error| error.message == "block has no terminator")
        );
        mir.functions[0].blocks[0].terminator = Some(Terminator::Unreachable);
    }
}
