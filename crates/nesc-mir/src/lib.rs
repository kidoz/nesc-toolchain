//! Control-flow intermediate representation and verifier for NesC.

use std::collections::{HashMap, HashSet};
use std::fmt;

pub use nesc_hir::{
    AddressSpace, BinaryOperator, FunctionId, GlobalId, IntegerType, SourceId, SourceSpan, Type,
    TypeKind, UnaryOperator,
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
    /// Address of a function-local object.
    AddressOfLocal(LocalId),
    /// Address of a global object.
    AddressOfGlobal(GlobalId),
    /// Checked fixed-array index before address calculation.
    BoundsCheck {
        /// Runtime index value.
        index: ValueId,
        /// Exclusive element count.
        length: u32,
    },
    /// Adds a byte offset to a 16-bit pointer.
    PointerOffset {
        /// Base pointer.
        base: ValueId,
        /// Unsigned byte offset.
        offset: ValueId,
        /// Whether to subtract instead of add.
        subtract: bool,
    },
    /// CPU-bus load through a pointer.
    LoadIndirect {
        /// Effective CPU address.
        address: ValueId,
        /// Pointer address space.
        address_space: AddressSpace,
        /// Whether this access is observable.
        volatile: bool,
    },
    /// CPU-bus store through a pointer.
    StoreIndirect {
        /// Effective CPU address.
        address: ValueId,
        /// Stored scalar value.
        value: ValueId,
        /// Destination object type.
        ty: Type,
        /// Pointer address space.
        address_space: AddressSpace,
        /// Whether this access is observable.
        volatile: bool,
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

/// Fixed-array bounds-check lowering policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BoundsChecks {
    /// Emit no runtime checks.
    Off,
    /// Retain every fixed-array check.
    Trap,
    /// Remove only checks proven in range.
    ElideProven,
}

/// MIR construction settings supplied by the project manifest.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LoweringConfig {
    /// Fixed-array bounds behavior.
    pub bounds_checks: BoundsChecks,
}

impl Default for LoweringConfig {
    fn default() -> Self {
        Self {
            bounds_checks: BoundsChecks::ElideProven,
        }
    }
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
    lower_with_config(hir, LoweringConfig::default())
}

/// Lowers structured HIR with explicit semantic policies.
///
/// # Errors
///
/// Returns source-backed failures for constructs not representable by MIR.
pub fn lower_with_config(
    hir: &HirModule,
    config: LoweringConfig,
) -> Result<Module, Vec<LoweringError>> {
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
        let mut builder = Builder::new(hir, function, config);
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
    config: LoweringConfig,
}

impl<'a> Builder<'a> {
    fn new(hir: &'a HirModule, source: &nesc_hir::Function, config: LoweringConfig) -> Self {
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
            config,
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
                        if variable.ty.is_volatile {
                            Effect::Volatile
                        } else {
                            Effect::Write
                        },
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
                if *operator == UnaryOperator::AddressOf {
                    return self.lower_address(operand);
                }
                if *operator == UnaryOperator::Dereference {
                    let pointer_type = operand.ty.clone()?;
                    let address = self.lower_expression(operand)?;
                    return Some(self.value_instruction(
                        InstructionKind::LoadIndirect {
                            address,
                            address_space: pointer_type.address_space,
                            volatile: ty.is_volatile,
                        },
                        if ty.is_volatile {
                            Effect::Volatile
                        } else {
                            Effect::Read
                        },
                        expression.span,
                        ty,
                    ));
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
                if matches!(operator, BinaryOperator::Add | BinaryOperator::Subtract)
                    && left.ty.as_ref().is_some_and(|ty| ty.pointer_depth > 0)
                {
                    let pointer_type = left.ty.clone()?;
                    let base = self.lower_expression(left)?;
                    let offset =
                        self.lower_scaled_offset(right, pointee_size(&pointer_type), right.span)?;
                    return Some(self.value_instruction(
                        InstructionKind::PointerOffset {
                            base,
                            offset,
                            subtract: *operator == BinaryOperator::Subtract,
                        },
                        Effect::Pure,
                        expression.span,
                        ty,
                    ));
                }
                let left_type = left.ty.clone()?;
                let right_type = right.ty.clone()?;
                let left_span = left.span;
                let right_span = right.span;
                let left = self.lower_expression(left)?;
                let right = self.lower_expression(right)?;
                let (left, right) = if ty.kind != TypeKind::Bool && ty.pointer_depth == 0 {
                    (
                        self.cast_if_needed(left, &left_type, &ty, left_span),
                        self.cast_if_needed(right, &right_type, &ty, right_span),
                    )
                } else {
                    (left, right)
                };
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
            ExpressionKind::Index { .. } => {
                let (address, address_space) = self.lower_address_with_space(expression)?;
                Some(self.value_instruction(
                    InstructionKind::LoadIndirect {
                        address,
                        address_space,
                        volatile: ty.is_volatile,
                    },
                    if ty.is_volatile {
                        Effect::Volatile
                    } else {
                        Effect::Read
                    },
                    expression.span,
                    ty,
                ))
            }
            ExpressionKind::String(_) | ExpressionKind::Field { .. } => {
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
        match &target.kind {
            ExpressionKind::Name(name) => {
                let right = self.lower_expression(value)?;
                let stored = if operator == BinaryOperator::Assign {
                    right
                } else if ty.pointer_depth > 0
                    && matches!(operator, BinaryOperator::Add | BinaryOperator::Subtract)
                {
                    let offset =
                        self.scale_value(right, value.ty.as_ref()?, pointee_size(&ty), value.span);
                    let left = self.load_name(name, target.span, ty.clone())?;
                    self.value_instruction(
                        InstructionKind::PointerOffset {
                            base: left,
                            offset,
                            subtract: operator == BinaryOperator::Subtract,
                        },
                        Effect::Pure,
                        span,
                        ty,
                    )
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
            ExpressionKind::Unary {
                operator: UnaryOperator::Dereference,
                operand,
            } => {
                let pointer_type = operand.ty.clone()?;
                let address = self.lower_expression(operand)?;
                self.lower_indirect_assignment(
                    operator,
                    address,
                    pointer_type.address_space,
                    target,
                    value,
                    span,
                    ty,
                )
            }
            ExpressionKind::Index { .. } => {
                let (address, address_space) = self.lower_address_with_space(target)?;
                self.lower_indirect_assignment(
                    operator,
                    address,
                    address_space,
                    target,
                    value,
                    span,
                    ty,
                )
            }
            _ => {
                self.unsupported("assignment target has no lowered address", target.span);
                None
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn lower_indirect_assignment(
        &mut self,
        operator: BinaryOperator,
        address: ValueId,
        address_space: AddressSpace,
        target: &Expression,
        value: &Expression,
        span: SourceSpan,
        ty: Type,
    ) -> Option<ValueId> {
        let right = self.lower_expression(value)?;
        let stored = if operator == BinaryOperator::Assign {
            right
        } else {
            let left = self.value_instruction(
                InstructionKind::LoadIndirect {
                    address,
                    address_space,
                    volatile: ty.is_volatile,
                },
                if ty.is_volatile {
                    Effect::Volatile
                } else {
                    Effect::Read
                },
                target.span,
                ty.clone(),
            );
            self.value_instruction(
                InstructionKind::Binary {
                    operator,
                    left,
                    right,
                },
                Effect::Pure,
                span,
                ty.clone(),
            )
        };
        self.emit(
            None,
            InstructionKind::StoreIndirect {
                address,
                value: stored,
                ty: ty.clone(),
                address_space,
                volatile: ty.is_volatile,
            },
            if ty.is_volatile {
                Effect::Volatile
            } else {
                Effect::Write
            },
            span,
        );
        Some(stored)
    }

    fn lower_address(&mut self, expression: &Expression) -> Option<ValueId> {
        self.lower_address_with_space(expression)
            .map(|(address, _)| address)
    }

    fn lower_address_with_space(
        &mut self,
        expression: &Expression,
    ) -> Option<(ValueId, AddressSpace)> {
        match &expression.kind {
            ExpressionKind::Name(name) => {
                let mut pointer_type = expression.ty.clone()?;
                pointer_type.pointer_depth = pointer_type.pointer_depth.saturating_add(1);
                pointer_type.array_lengths.clear();
                if let Some(local) = self.local(name) {
                    let value = self.value_instruction(
                        InstructionKind::AddressOfLocal(local),
                        Effect::Pure,
                        expression.span,
                        pointer_type,
                    );
                    return Some((value, AddressSpace::InternalRam));
                }
                if let Some(global) = self.hir.global_names.get(name).copied() {
                    let value = self.value_instruction(
                        InstructionKind::AddressOfGlobal(global),
                        Effect::Pure,
                        expression.span,
                        pointer_type,
                    );
                    return Some((value, AddressSpace::InternalRam));
                }
                self.unsupported(
                    format!("resolved name `{name}` has no address"),
                    expression.span,
                );
                None
            }
            ExpressionKind::Unary {
                operator: UnaryOperator::Dereference,
                operand,
            } => {
                let pointer_type = operand.ty.clone()?;
                self.lower_expression(operand)
                    .map(|address| (address, pointer_type.address_space))
            }
            ExpressionKind::Index { base, index } => {
                let base_type = base.ty.clone()?;
                let (base_address, address_space) = if base_type.array_lengths.is_empty() {
                    (self.lower_expression(base)?, base_type.address_space)
                } else {
                    self.lower_address_with_space(base)?
                };
                let index_value = self.lower_expression(index)?;
                if let Some(length) = base_type.array_lengths.first().copied()
                    && self.should_check_bounds(index, length)
                {
                    self.emit(
                        None,
                        InstructionKind::BoundsCheck {
                            index: index_value,
                            length,
                        },
                        Effect::Trap,
                        index.span,
                    );
                }
                let element_type = expression.ty.clone()?;
                let offset = self.scale_value(
                    index_value,
                    &element_type,
                    type_size(&element_type),
                    index.span,
                );
                let mut pointer_type = element_type;
                pointer_type.pointer_depth = pointer_type.pointer_depth.saturating_add(1);
                pointer_type.array_lengths.clear();
                pointer_type.address_space = address_space;
                let address = self.value_instruction(
                    InstructionKind::PointerOffset {
                        base: base_address,
                        offset,
                        subtract: false,
                    },
                    Effect::Pure,
                    expression.span,
                    pointer_type,
                );
                Some((address, address_space))
            }
            _ => {
                self.unsupported("expression has no address", expression.span);
                None
            }
        }
    }

    fn lower_scaled_offset(
        &mut self,
        expression: &Expression,
        scale: u16,
        span: SourceSpan,
    ) -> Option<ValueId> {
        let value = self.lower_expression(expression)?;
        Some(self.scale_value(value, expression.ty.as_ref()?, scale, span))
    }

    fn cast_if_needed(
        &mut self,
        value: ValueId,
        source: &Type,
        target: &Type,
        span: SourceSpan,
    ) -> ValueId {
        if source == target {
            value
        } else {
            self.value_instruction(
                InstructionKind::Cast {
                    value,
                    target: target.clone(),
                },
                Effect::Pure,
                span,
                target.clone(),
            )
        }
    }

    fn scale_value(
        &mut self,
        value: ValueId,
        source_type: &Type,
        scale: u16,
        span: SourceSpan,
    ) -> ValueId {
        let address_type = Type::scalar(TypeKind::Integer(IntegerType::U16));
        let widened = if source_type == &address_type {
            value
        } else {
            self.value_instruction(
                InstructionKind::Cast {
                    value,
                    target: address_type.clone(),
                },
                Effect::Pure,
                span,
                address_type.clone(),
            )
        };
        if scale <= 1 {
            return widened;
        }
        let factor = self.value_instruction(
            InstructionKind::Constant(u64::from(scale)),
            Effect::Pure,
            span,
            address_type.clone(),
        );
        self.value_instruction(
            InstructionKind::Binary {
                operator: BinaryOperator::Multiply,
                left: widened,
                right: factor,
            },
            Effect::Pure,
            span,
            address_type,
        )
    }

    fn should_check_bounds(&self, index: &Expression, length: u32) -> bool {
        match self.config.bounds_checks {
            BoundsChecks::Off => false,
            BoundsChecks::Trap => true,
            BoundsChecks::ElideProven => !matches!(
                index.kind,
                ExpressionKind::Integer(ref literal) if literal.value < u64::from(length)
            ),
        }
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
        if ty.pointer_depth > 0 {
            let offset_type = Type::scalar(TypeKind::Integer(IntegerType::U16));
            let offset = self.value_instruction(
                InstructionKind::Constant(u64::from(pointee_size(&ty))),
                Effect::Pure,
                span,
                offset_type,
            );
            let new = self.value_instruction(
                InstructionKind::PointerOffset {
                    base: old,
                    offset,
                    subtract: operator == UnaryOperator::Decrement,
                },
                Effect::Pure,
                span,
                ty,
            );
            self.store_name(name, new, span);
            return Some(if postfix { old } else { new });
        }
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
        let effect = if ty.is_volatile {
            Effect::Volatile
        } else {
            Effect::Read
        };
        if let Some(local) = self.local(name) {
            return Some(self.value_instruction(
                InstructionKind::LoadLocal(local),
                effect,
                span,
                ty,
            ));
        }
        if let Some(global) = self.hir.global_names.get(name).copied() {
            return Some(self.value_instruction(
                InstructionKind::LoadGlobal(global),
                effect,
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
            let effect = if self.function.locals[local.0 as usize].ty.is_volatile {
                Effect::Volatile
            } else {
                Effect::Write
            };
            self.emit(
                None,
                InstructionKind::StoreLocal { local, value },
                effect,
                span,
            );
        } else if let Some(global) = self.hir.global_names.get(name).copied() {
            let effect = if self.hir.globals[global.0 as usize].variable.ty.is_volatile {
                Effect::Volatile
            } else {
                Effect::Write
            };
            self.emit(
                None,
                InstructionKind::StoreGlobal { global, value },
                effect,
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

fn type_size(ty: &Type) -> u16 {
    let element_size = if ty.pointer_depth > 0 {
        2
    } else {
        u16::from(ty.integer_width().unwrap_or(0).div_ceil(8).max(1))
    };
    ty.array_lengths.iter().fold(element_size, |size, length| {
        size.saturating_mul(u16::try_from(*length).unwrap_or(u16::MAX))
    })
}

fn pointee_size(pointer: &Type) -> u16 {
    let mut pointee = pointer.clone();
    pointee.pointer_depth = pointee.pointer_depth.saturating_sub(1);
    type_size(&pointee)
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
        InstructionKind::AddressOfLocal(local) => {
            if local.0 as usize >= function.locals.len() {
                verification_error(
                    errors,
                    function.id,
                    Some(block),
                    "local address is out of range",
                );
            }
        }
        InstructionKind::AddressOfGlobal(global) => {
            if global.0 as usize >= module.globals.len() {
                verification_error(
                    errors,
                    function.id,
                    Some(block),
                    "global address is out of range",
                );
            }
        }
        InstructionKind::BoundsCheck { index, .. } => operands.push(*index),
        InstructionKind::PointerOffset { base, offset, .. } => {
            operands.push(*base);
            operands.push(*offset);
        }
        InstructionKind::LoadIndirect { address, .. } => operands.push(*address),
        InstructionKind::StoreIndirect { address, value, .. } => {
            operands.push(*address);
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
        InstructionKind::StoreLocal { .. }
            | InstructionKind::StoreGlobal { .. }
            | InstructionKind::StoreIndirect { .. }
            | InstructionKind::BoundsCheck { .. }
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

    use super::{InstructionKind, Terminator, lower, verify};

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

    #[test]
    fn lowers_fixed_array_addresses_bounds_and_indirect_accesses() {
        let directory = tempdir().expect("temporary directory");
        let source = directory.path().join("main.c");
        fs::write(
            &source,
            "NES_MAIN int main(void) { u8 values[2]; u8 i = 1; values[i] = 3; return values[i]; }",
        )
        .expect("source");
        let checked = check(&FrontendConfig::new(source)).expect("frontend");
        let hir = nesc_hir::lower(checked);
        let mir = lower(&hir).expect("MIR lowering");
        verify(&mir).expect("valid MIR");
        let instructions = mir.functions[0]
            .blocks
            .iter()
            .flat_map(|block| &block.instructions)
            .collect::<Vec<_>>();
        assert!(
            instructions.iter().any(|instruction| {
                matches!(instruction.kind, InstructionKind::AddressOfLocal(_))
            })
        );
        assert!(instructions.iter().any(|instruction| {
            matches!(
                instruction.kind,
                InstructionKind::BoundsCheck { length: 2, .. }
            )
        }));
        assert!(instructions.iter().any(|instruction| {
            matches!(instruction.kind, InstructionKind::PointerOffset { .. })
        }));
        assert!(instructions.iter().any(|instruction| {
            matches!(instruction.kind, InstructionKind::LoadIndirect { .. })
        }));
        assert!(instructions.iter().any(|instruction| {
            matches!(instruction.kind, InstructionKind::StoreIndirect { .. })
        }));
    }
}
