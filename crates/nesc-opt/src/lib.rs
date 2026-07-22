//! Target-aware optimization passes for NesC MIR.

mod control_flow;

use std::collections::{HashMap, HashSet};

use nesc_mir::{
    BinaryOperator, Effect, Function, InstructionKind, Module, Terminator, Type, TypeKind,
    UnaryOperator, ValueId,
};

pub use control_flow::{ControlFlowAnalysis, NaturalLoop, analyze_control_flow};

/// Optimization policy selected by the project manifest.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum OptimizationProfile {
    /// Preserve MIR without running optimization passes.
    #[default]
    O0,
    /// Run inexpensive local simplifications.
    O1,
    /// Run the complete general-purpose pipeline.
    O2,
    /// Favor smaller generated code without excessive cycle cost.
    Size,
    /// Favor the smallest generated code.
    MinSize,
    /// Favor lower execution cost.
    Cycles,
}

impl OptimizationProfile {
    /// Stable manifest spelling used in reports.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::O0 => "0",
            Self::O1 => "1",
            Self::O2 => "2",
            Self::Size => "size",
            Self::MinSize => "min-size",
            Self::Cycles => "cycles",
        }
    }
}

/// Deterministic counts of transformations performed.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct OptimizationReport {
    /// Policy used to select the pass pipeline.
    pub profile: OptimizationProfile,
    /// Instructions replaced by constants.
    pub constants_folded: usize,
    /// Nonvolatile local loads replaced by propagated constants.
    pub constants_propagated: usize,
    /// Constant branches replaced by jumps.
    pub branches_simplified: usize,
    /// Unused pure instructions removed.
    pub instructions_removed: usize,
    /// Defined functions included in control-flow analysis.
    pub functions_analyzed: usize,
    /// Natural loops found across analyzed functions.
    pub natural_loops: usize,
    /// Greatest natural-loop nesting depth found in one function.
    pub maximum_loop_depth: usize,
}

/// Runs the initial semantics-preserving MIR optimizer.
#[must_use]
pub fn optimize(module: &mut Module) -> OptimizationReport {
    optimize_with_profile(module, OptimizationProfile::O2)
}

/// Runs the MIR passes selected by an explicit optimization policy.
#[must_use]
pub fn optimize_with_profile(
    module: &mut Module,
    profile: OptimizationProfile,
) -> OptimizationReport {
    let mut report = OptimizationReport {
        profile,
        ..OptimizationReport::default()
    };
    for function in &mut module.functions {
        if function.blocks.is_empty() {
            continue;
        }
        let control_flow = analyze_control_flow(function);
        report.functions_analyzed += 1;
        report.natural_loops += control_flow.loops.len();
        report.maximum_loop_depth = report
            .maximum_loop_depth
            .max(control_flow.maximum_loop_depth());
        match profile {
            OptimizationProfile::O0 => {}
            OptimizationProfile::O1 => fold_constants(function, &mut report),
            OptimizationProfile::O2
            | OptimizationProfile::Size
            | OptimizationProfile::MinSize
            | OptimizationProfile::Cycles => {
                propagate_constants(function, &control_flow, &mut report);
                simplify_branches(function, &mut report);
                remove_dead_values(function, &mut report);
            }
        }
    }
    report
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum ConstantValue {
    #[default]
    Unknown,
    Constant(u64),
    Varying,
}

fn propagate_constants(
    function: &mut Function,
    control_flow: &ControlFlowAnalysis,
    report: &mut OptimizationReport,
) {
    let blocked_locals = propagation_blocked_locals(function);
    let local_count = function.locals.len();
    let mut outgoing = vec![None::<Vec<ConstantValue>>; function.blocks.len()];
    let mut values = vec![ConstantValue::Unknown; function.value_types.len()];

    loop {
        let mut changed = false;
        for block in &function.blocks {
            if !control_flow.reachable[block.id.0 as usize] {
                continue;
            }
            let incoming = if Some(block.id) == function.entry {
                Some(vec![ConstantValue::Varying; local_count])
            } else {
                merge_predecessor_states(&control_flow.predecessors[block.id.0 as usize], &outgoing)
            };
            let Some(mut locals) = incoming else {
                continue;
            };
            for instruction in &block.instructions {
                let result_value = evaluate_instruction(
                    instruction,
                    &function.value_types,
                    &locals,
                    &blocked_locals,
                    &values,
                );
                if let Some(result) = instruction.result {
                    let slot = &mut values[result.0 as usize];
                    if *slot != result_value {
                        *slot = result_value;
                        changed = true;
                    }
                }
                apply_local_effects(instruction, &mut locals, &blocked_locals, &values);
            }
            let output = &mut outgoing[block.id.0 as usize];
            if output.as_ref() != Some(&locals) {
                *output = Some(locals);
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }

    for block in &mut function.blocks {
        if !control_flow.reachable[block.id.0 as usize] {
            continue;
        }
        for instruction in &mut block.instructions {
            let Some(result) = instruction.result else {
                continue;
            };
            let ConstantValue::Constant(value) = values[result.0 as usize] else {
                continue;
            };
            let propagated = matches!(instruction.kind, InstructionKind::LoadLocal(local) if !blocked_locals[local.0 as usize]);
            let folded = matches!(
                instruction.kind,
                InstructionKind::Unary { .. }
                    | InstructionKind::Binary { .. }
                    | InstructionKind::Cast { .. }
            );
            if !propagated && !folded {
                continue;
            }
            instruction.kind = InstructionKind::Constant(value);
            instruction.effect = Effect::Pure;
            if propagated {
                report.constants_propagated += 1;
            } else {
                report.constants_folded += 1;
            }
        }
    }
}

fn propagation_blocked_locals(function: &Function) -> Vec<bool> {
    let mut blocked = function
        .locals
        .iter()
        .map(|local| local.ty.is_volatile)
        .collect::<Vec<_>>();
    for instruction in function.blocks.iter().flat_map(|block| &block.instructions) {
        if let InstructionKind::AddressOfLocal(local) = instruction.kind {
            blocked[local.0 as usize] = true;
        }
    }
    blocked
}

fn merge_predecessor_states(
    predecessors: &[nesc_mir::BlockId],
    outgoing: &[Option<Vec<ConstantValue>>],
) -> Option<Vec<ConstantValue>> {
    let mut states = predecessors
        .iter()
        .filter_map(|predecessor| outgoing[predecessor.0 as usize].as_ref());
    let mut merged = states.next()?.clone();
    for state in states {
        for (value, incoming) in merged.iter_mut().zip(state) {
            if *value != *incoming {
                *value = ConstantValue::Varying;
            }
        }
    }
    Some(merged)
}

fn evaluate_instruction(
    instruction: &nesc_mir::Instruction,
    value_types: &[Type],
    locals: &[ConstantValue],
    blocked_locals: &[bool],
    values: &[ConstantValue],
) -> ConstantValue {
    let Some(result) = instruction.result else {
        return ConstantValue::Varying;
    };
    let ty = &value_types[result.0 as usize];
    match &instruction.kind {
        InstructionKind::Constant(value) => ConstantValue::Constant(*value),
        InstructionKind::LoadLocal(local) if !blocked_locals[local.0 as usize] => {
            locals[local.0 as usize]
        }
        InstructionKind::Unary { operator, operand } => constant_operand(values, *operand)
            .and_then(|value| fold_unary(*operator, value, ty))
            .map_or(ConstantValue::Varying, ConstantValue::Constant),
        InstructionKind::Binary {
            operator,
            left,
            right,
        } => constant_operand(values, *left)
            .zip(constant_operand(values, *right))
            .and_then(|(left, right)| fold_binary(*operator, left, right, ty))
            .map_or(ConstantValue::Varying, ConstantValue::Constant),
        InstructionKind::Cast { value, target } => constant_operand(values, *value)
            .map(|value| ConstantValue::Constant(truncate(value, target)))
            .unwrap_or(ConstantValue::Varying),
        _ => ConstantValue::Varying,
    }
}

fn constant_operand(values: &[ConstantValue], value: ValueId) -> Option<u64> {
    match values[value.0 as usize] {
        ConstantValue::Constant(value) => Some(value),
        ConstantValue::Unknown | ConstantValue::Varying => None,
    }
}

fn apply_local_effects(
    instruction: &nesc_mir::Instruction,
    locals: &mut [ConstantValue],
    blocked_locals: &[bool],
    values: &[ConstantValue],
) {
    match &instruction.kind {
        InstructionKind::StoreLocal { local, value } => {
            locals[local.0 as usize] = if blocked_locals[local.0 as usize] {
                ConstantValue::Varying
            } else {
                match values[value.0 as usize] {
                    ConstantValue::Constant(value) => ConstantValue::Constant(value),
                    ConstantValue::Unknown | ConstantValue::Varying => ConstantValue::Varying,
                }
            };
        }
        InstructionKind::InlineAssembly(assembly) => {
            if assembly.clobbers.memory {
                locals.fill(ConstantValue::Varying);
            }
            for output in &assembly.outputs {
                if let nesc_mir::AssemblyOutputTarget::Local(local) = output.target {
                    locals[local.0 as usize] = ConstantValue::Varying;
                }
            }
        }
        _ => {}
    }
}

fn fold_constants(function: &mut Function, report: &mut OptimizationReport) {
    let mut constants = HashMap::<ValueId, u64>::new();
    for block in &mut function.blocks {
        for instruction in &mut block.instructions {
            let Some(result) = instruction.result else {
                continue;
            };
            let value = match &instruction.kind {
                InstructionKind::Constant(value) => Some(*value),
                InstructionKind::Unary { operator, operand } => {
                    constants.get(operand).and_then(|value| {
                        fold_unary(*operator, *value, &function.value_types[result.0 as usize])
                    })
                }
                InstructionKind::Binary {
                    operator,
                    left,
                    right,
                } => constants
                    .get(left)
                    .zip(constants.get(right))
                    .and_then(|(left, right)| {
                        fold_binary(
                            *operator,
                            *left,
                            *right,
                            &function.value_types[result.0 as usize],
                        )
                    }),
                InstructionKind::Cast { value, target } => {
                    constants.get(value).map(|value| truncate(*value, target))
                }
                _ => None,
            };
            if let Some(value) = value {
                constants.insert(result, value);
                if !matches!(instruction.kind, InstructionKind::Constant(_)) {
                    instruction.kind = InstructionKind::Constant(value);
                    instruction.effect = Effect::Pure;
                    report.constants_folded += 1;
                }
            }
        }
    }
}

fn simplify_branches(function: &mut Function, report: &mut OptimizationReport) {
    let constants = function
        .blocks
        .iter()
        .flat_map(|block| &block.instructions)
        .filter_map(
            |instruction| match (&instruction.result, &instruction.kind) {
                (Some(result), InstructionKind::Constant(value)) => Some((*result, *value)),
                _ => None,
            },
        )
        .collect::<HashMap<_, _>>();
    for block in &mut function.blocks {
        let replacement = match block.terminator.as_ref() {
            Some(Terminator::Branch {
                condition,
                then_block,
                else_block,
            }) => constants.get(condition).map(|condition| {
                Terminator::Jump(if *condition == 0 {
                    *else_block
                } else {
                    *then_block
                })
            }),
            _ => None,
        };
        if let Some(replacement) = replacement {
            block.terminator = Some(replacement);
            report.branches_simplified += 1;
        }
    }
}

fn remove_dead_values(function: &mut Function, report: &mut OptimizationReport) {
    loop {
        let mut used = HashSet::<ValueId>::new();
        for block in &function.blocks {
            for instruction in &block.instructions {
                instruction_operands(&instruction.kind, &mut used);
            }
            if let Some(terminator) = &block.terminator {
                match terminator {
                    Terminator::Branch { condition, .. } => {
                        used.insert(*condition);
                    }
                    Terminator::Return(Some(value)) => {
                        used.insert(*value);
                    }
                    Terminator::Jump(_) | Terminator::Return(None) | Terminator::Unreachable => {}
                }
            }
        }
        let before = function
            .blocks
            .iter()
            .map(|block| block.instructions.len())
            .sum::<usize>();
        for block in &mut function.blocks {
            block.instructions.retain(|instruction| {
                instruction.result.is_none_or(|result| {
                    used.contains(&result) || instruction.effect != Effect::Pure
                })
            });
        }
        let after = function
            .blocks
            .iter()
            .map(|block| block.instructions.len())
            .sum::<usize>();
        report.instructions_removed += before - after;
        if before == after {
            break;
        }
    }
}

fn instruction_operands(kind: &InstructionKind, used: &mut HashSet<ValueId>) {
    match kind {
        InstructionKind::StoreLocal { value, .. }
        | InstructionKind::StoreGlobal { value, .. }
        | InstructionKind::Cast { value, .. } => {
            used.insert(*value);
        }
        InstructionKind::BoundsCheck { index, .. }
        | InstructionKind::LoadIndirect { address: index, .. } => {
            used.insert(*index);
        }
        InstructionKind::PointerOffset { base, offset, .. } => {
            used.insert(*base);
            used.insert(*offset);
        }
        InstructionKind::StoreIndirect { address, value, .. } => {
            used.insert(*address);
            used.insert(*value);
        }
        InstructionKind::Unary { operand, .. } => {
            used.insert(*operand);
        }
        InstructionKind::Binary { left, right, .. } => {
            used.insert(*left);
            used.insert(*right);
        }
        InstructionKind::Call { arguments, .. } => used.extend(arguments.iter().copied()),
        InstructionKind::InlineAssembly(assembly) => {
            used.extend(assembly.inputs.iter().map(|input| input.value));
        }
        InstructionKind::Constant(_)
        | InstructionKind::LoadLocal(_)
        | InstructionKind::LoadGlobal(_)
        | InstructionKind::AddressOfLocal(_)
        | InstructionKind::AddressOfGlobal(_) => {}
    }
}

fn fold_unary(operator: UnaryOperator, value: u64, ty: &Type) -> Option<u64> {
    let value = truncate(value, ty);
    match operator {
        UnaryOperator::Plus => Some(value),
        UnaryOperator::Negate => Some(truncate(value.wrapping_neg(), ty)),
        UnaryOperator::LogicalNot => Some(u64::from(value == 0)),
        UnaryOperator::BitwiseNot => Some(truncate(!value, ty)),
        UnaryOperator::AddressOf
        | UnaryOperator::Dereference
        | UnaryOperator::Increment
        | UnaryOperator::Decrement => None,
    }
}

fn fold_binary(operator: BinaryOperator, left: u64, right: u64, ty: &Type) -> Option<u64> {
    let left = truncate(left, ty);
    let right = truncate(right, ty);
    let width = type_width(ty);
    let signed = ty.pointer_depth == 0
        && matches!(ty.kind, TypeKind::Integer(integer) if integer.is_signed());
    let signed_left = sign_extend(left, width);
    let signed_right = sign_extend(right, width);
    let value = match operator {
        BinaryOperator::Add => left.wrapping_add(right),
        BinaryOperator::Subtract => left.wrapping_sub(right),
        BinaryOperator::Multiply => left.wrapping_mul(right),
        BinaryOperator::Divide if right == 0 => return None,
        BinaryOperator::Divide if signed => (signed_left / signed_right) as u64,
        BinaryOperator::Divide => left / right,
        BinaryOperator::Remainder if right == 0 => return None,
        BinaryOperator::Remainder if signed => (signed_left % signed_right) as u64,
        BinaryOperator::Remainder => left % right,
        BinaryOperator::ShiftLeft if right >= u64::from(width) => return None,
        BinaryOperator::ShiftLeft => left.wrapping_shl(right as u32),
        BinaryOperator::ShiftRight if right >= u64::from(width) => return None,
        BinaryOperator::ShiftRight if signed => (signed_left >> right) as u64,
        BinaryOperator::ShiftRight => left >> right,
        BinaryOperator::Less => u64::from(if signed {
            signed_left < signed_right
        } else {
            left < right
        }),
        BinaryOperator::LessEqual => u64::from(if signed {
            signed_left <= signed_right
        } else {
            left <= right
        }),
        BinaryOperator::Greater => u64::from(if signed {
            signed_left > signed_right
        } else {
            left > right
        }),
        BinaryOperator::GreaterEqual => u64::from(if signed {
            signed_left >= signed_right
        } else {
            left >= right
        }),
        BinaryOperator::Equal => u64::from(left == right),
        BinaryOperator::NotEqual => u64::from(left != right),
        BinaryOperator::BitwiseAnd => left & right,
        BinaryOperator::BitwiseXor => left ^ right,
        BinaryOperator::BitwiseOr => left | right,
        BinaryOperator::LogicalAnd => u64::from(left != 0 && right != 0),
        BinaryOperator::LogicalOr => u64::from(left != 0 || right != 0),
        BinaryOperator::Assign => return None,
    };
    Some(truncate(value, ty))
}

fn truncate(value: u64, ty: &Type) -> u64 {
    let width = type_width(ty);
    if width >= 64 {
        value
    } else {
        value & ((1_u64 << width) - 1)
    }
}

fn type_width(ty: &Type) -> u8 {
    if ty.pointer_depth > 0 {
        16
    } else {
        ty.integer_width().unwrap_or(16)
    }
}

fn sign_extend(value: u64, width: u8) -> i64 {
    let shift = 64 - width;
    ((value << shift) as i64) >> shift
}

#[cfg(test)]
mod tests {
    use nesc_mir::{
        BankPlacement, BasicBlock, BinaryOperator, BlockId, Function, FunctionId, Instruction,
        InstructionKind, Local, LocalId, Module, Terminator, Type, TypeKind, ValueId,
    };

    use super::{Effect, OptimizationProfile, optimize, optimize_with_profile};

    #[test]
    fn folds_arithmetic_and_constant_branch() {
        let ty = Type::scalar(TypeKind::Integer(nesc_mir::IntegerType::I16));
        let mut module = Module {
            globals: Vec::new(),
            functions: vec![Function {
                id: FunctionId(0),
                name: "main".to_owned(),
                placement: BankPlacement::Fixed,
                return_type: ty.clone(),
                parameters: Vec::new(),
                locals: Vec::new(),
                entry: Some(BlockId(0)),
                blocks: vec![
                    BasicBlock {
                        id: BlockId(0),
                        instructions: vec![
                            Instruction {
                                result: Some(ValueId(0)),
                                kind: InstructionKind::Constant(2),
                                effect: Effect::Pure,
                                span: nesc_mir::SourceSpan::new(nesc_mir::SourceId::new(0), 0, 1),
                            },
                            Instruction {
                                result: Some(ValueId(1)),
                                kind: InstructionKind::Constant(3),
                                effect: Effect::Pure,
                                span: nesc_mir::SourceSpan::new(nesc_mir::SourceId::new(0), 2, 1),
                            },
                            Instruction {
                                result: Some(ValueId(2)),
                                kind: InstructionKind::Binary {
                                    operator: nesc_mir::BinaryOperator::Add,
                                    left: ValueId(0),
                                    right: ValueId(1),
                                },
                                effect: Effect::Pure,
                                span: nesc_mir::SourceSpan::new(nesc_mir::SourceId::new(0), 0, 3),
                            },
                        ],
                        terminator: Some(Terminator::Branch {
                            condition: ValueId(2),
                            then_block: BlockId(1),
                            else_block: BlockId(2),
                        }),
                    },
                    BasicBlock {
                        id: BlockId(1),
                        instructions: Vec::new(),
                        terminator: Some(Terminator::Return(Some(ValueId(2)))),
                    },
                    BasicBlock {
                        id: BlockId(2),
                        instructions: Vec::new(),
                        terminator: Some(Terminator::Unreachable),
                    },
                ],
                value_types: vec![ty.clone(), ty.clone(), ty],
            }],
        };
        let report = optimize(&mut module);
        assert_eq!(report.constants_folded, 1);
        assert_eq!(report.branches_simplified, 1);
        assert!(matches!(
            module.functions[0].blocks[0].terminator,
            Some(Terminator::Jump(BlockId(1)))
        ));
    }

    #[test]
    fn basic_profile_keeps_dead_values_for_faster_compilation() {
        let ty = Type::scalar(TypeKind::Integer(nesc_mir::IntegerType::U8));
        let function = Function {
            id: FunctionId(0),
            name: "main".to_owned(),
            placement: BankPlacement::Fixed,
            return_type: Type::scalar(TypeKind::Void),
            parameters: Vec::new(),
            locals: Vec::new(),
            entry: Some(BlockId(0)),
            blocks: vec![BasicBlock {
                id: BlockId(0),
                instructions: vec![Instruction {
                    result: Some(ValueId(0)),
                    kind: InstructionKind::Constant(7),
                    effect: Effect::Pure,
                    span: nesc_mir::SourceSpan::new(nesc_mir::SourceId::new(0), 0, 1),
                }],
                terminator: Some(Terminator::Return(None)),
            }],
            value_types: vec![ty],
        };
        let mut basic = Module {
            globals: Vec::new(),
            functions: vec![function.clone()],
        };
        let mut balanced = Module {
            globals: Vec::new(),
            functions: vec![function],
        };

        let basic_report = optimize_with_profile(&mut basic, OptimizationProfile::O1);
        let balanced_report = optimize_with_profile(&mut balanced, OptimizationProfile::O2);

        assert_eq!(basic_report.profile, OptimizationProfile::O1);
        assert_eq!(basic.functions[0].blocks[0].instructions.len(), 1);
        assert_eq!(balanced_report.instructions_removed, 1);
        assert!(balanced.functions[0].blocks[0].instructions.is_empty());
    }

    #[test]
    fn propagates_a_local_constant_across_blocks() {
        let ty = Type::scalar(TypeKind::Integer(nesc_mir::IntegerType::U8));
        let span = nesc_mir::SourceSpan::new(nesc_mir::SourceId::new(0), 0, 1);
        let mut module = Module {
            globals: Vec::new(),
            functions: vec![Function {
                id: FunctionId(0),
                name: "main".to_owned(),
                placement: BankPlacement::Fixed,
                return_type: ty.clone(),
                parameters: Vec::new(),
                locals: vec![Local {
                    id: LocalId(0),
                    name: "value".to_owned(),
                    ty: ty.clone(),
                    parameter: false,
                }],
                entry: Some(BlockId(0)),
                blocks: vec![
                    BasicBlock {
                        id: BlockId(0),
                        instructions: vec![
                            Instruction {
                                result: Some(ValueId(0)),
                                kind: InstructionKind::Constant(7),
                                effect: Effect::Pure,
                                span,
                            },
                            Instruction {
                                result: None,
                                kind: InstructionKind::StoreLocal {
                                    local: LocalId(0),
                                    value: ValueId(0),
                                },
                                effect: Effect::Write,
                                span,
                            },
                        ],
                        terminator: Some(Terminator::Jump(BlockId(1))),
                    },
                    BasicBlock {
                        id: BlockId(1),
                        instructions: vec![
                            Instruction {
                                result: Some(ValueId(1)),
                                kind: InstructionKind::LoadLocal(LocalId(0)),
                                effect: Effect::Read,
                                span,
                            },
                            Instruction {
                                result: Some(ValueId(2)),
                                kind: InstructionKind::Constant(1),
                                effect: Effect::Pure,
                                span,
                            },
                            Instruction {
                                result: Some(ValueId(3)),
                                kind: InstructionKind::Binary {
                                    operator: BinaryOperator::Add,
                                    left: ValueId(1),
                                    right: ValueId(2),
                                },
                                effect: Effect::Pure,
                                span,
                            },
                        ],
                        terminator: Some(Terminator::Return(Some(ValueId(3)))),
                    },
                ],
                value_types: vec![ty.clone(), ty.clone(), ty.clone(), ty],
            }],
        };

        let report = optimize_with_profile(&mut module, OptimizationProfile::O2);

        assert_eq!(report.constants_propagated, 1);
        assert_eq!(report.constants_folded, 1);
        assert!(
            module.functions[0].blocks[1]
                .instructions
                .iter()
                .any(|instruction| instruction.result == Some(ValueId(3))
                    && matches!(instruction.kind, InstructionKind::Constant(8)))
        );
        nesc_mir::verify(&module).expect("optimized MIR remains valid");
    }

    #[test]
    fn does_not_propagate_disagreeing_predecessor_values() {
        let ty = Type::scalar(TypeKind::Integer(nesc_mir::IntegerType::U8));
        let span = nesc_mir::SourceSpan::new(nesc_mir::SourceId::new(0), 0, 1);
        let mut module = Module {
            globals: Vec::new(),
            functions: vec![Function {
                id: FunctionId(0),
                name: "choose".to_owned(),
                placement: BankPlacement::Fixed,
                return_type: ty.clone(),
                parameters: vec![LocalId(0)],
                locals: vec![
                    Local {
                        id: LocalId(0),
                        name: "condition".to_owned(),
                        ty: ty.clone(),
                        parameter: true,
                    },
                    Local {
                        id: LocalId(1),
                        name: "value".to_owned(),
                        ty: ty.clone(),
                        parameter: false,
                    },
                ],
                entry: Some(BlockId(0)),
                blocks: vec![
                    BasicBlock {
                        id: BlockId(0),
                        instructions: vec![Instruction {
                            result: Some(ValueId(0)),
                            kind: InstructionKind::LoadLocal(LocalId(0)),
                            effect: Effect::Read,
                            span,
                        }],
                        terminator: Some(Terminator::Branch {
                            condition: ValueId(0),
                            then_block: BlockId(1),
                            else_block: BlockId(2),
                        }),
                    },
                    BasicBlock {
                        id: BlockId(1),
                        instructions: vec![
                            Instruction {
                                result: Some(ValueId(1)),
                                kind: InstructionKind::Constant(1),
                                effect: Effect::Pure,
                                span,
                            },
                            Instruction {
                                result: None,
                                kind: InstructionKind::StoreLocal {
                                    local: LocalId(1),
                                    value: ValueId(1),
                                },
                                effect: Effect::Write,
                                span,
                            },
                        ],
                        terminator: Some(Terminator::Jump(BlockId(3))),
                    },
                    BasicBlock {
                        id: BlockId(2),
                        instructions: vec![
                            Instruction {
                                result: Some(ValueId(2)),
                                kind: InstructionKind::Constant(2),
                                effect: Effect::Pure,
                                span,
                            },
                            Instruction {
                                result: None,
                                kind: InstructionKind::StoreLocal {
                                    local: LocalId(1),
                                    value: ValueId(2),
                                },
                                effect: Effect::Write,
                                span,
                            },
                        ],
                        terminator: Some(Terminator::Jump(BlockId(3))),
                    },
                    BasicBlock {
                        id: BlockId(3),
                        instructions: vec![Instruction {
                            result: Some(ValueId(3)),
                            kind: InstructionKind::LoadLocal(LocalId(1)),
                            effect: Effect::Read,
                            span,
                        }],
                        terminator: Some(Terminator::Return(Some(ValueId(3)))),
                    },
                ],
                value_types: vec![ty.clone(), ty.clone(), ty.clone(), ty],
            }],
        };

        let report = optimize_with_profile(&mut module, OptimizationProfile::O2);

        assert_eq!(report.constants_propagated, 0);
        assert!(matches!(
            module.functions[0].blocks[3].instructions[0].kind,
            InstructionKind::LoadLocal(LocalId(1))
        ));
        nesc_mir::verify(&module).expect("optimized MIR remains valid");
    }

    #[test]
    fn does_not_propagate_address_taken_local_values() {
        let ty = Type::scalar(TypeKind::Integer(nesc_mir::IntegerType::U8));
        let mut pointer = ty.clone();
        pointer.pointer_depth = 1;
        let span = nesc_mir::SourceSpan::new(nesc_mir::SourceId::new(0), 0, 1);
        let mut module = Module {
            globals: Vec::new(),
            functions: vec![Function {
                id: FunctionId(0),
                name: "address_taken".to_owned(),
                placement: BankPlacement::Fixed,
                return_type: ty.clone(),
                parameters: Vec::new(),
                locals: vec![Local {
                    id: LocalId(0),
                    name: "value".to_owned(),
                    ty: ty.clone(),
                    parameter: false,
                }],
                entry: Some(BlockId(0)),
                blocks: vec![BasicBlock {
                    id: BlockId(0),
                    instructions: vec![
                        Instruction {
                            result: Some(ValueId(0)),
                            kind: InstructionKind::Constant(7),
                            effect: Effect::Pure,
                            span,
                        },
                        Instruction {
                            result: None,
                            kind: InstructionKind::StoreLocal {
                                local: LocalId(0),
                                value: ValueId(0),
                            },
                            effect: Effect::Write,
                            span,
                        },
                        Instruction {
                            result: Some(ValueId(1)),
                            kind: InstructionKind::AddressOfLocal(LocalId(0)),
                            effect: Effect::Pure,
                            span,
                        },
                        Instruction {
                            result: Some(ValueId(2)),
                            kind: InstructionKind::LoadLocal(LocalId(0)),
                            effect: Effect::Read,
                            span,
                        },
                    ],
                    terminator: Some(Terminator::Return(Some(ValueId(2)))),
                }],
                value_types: vec![ty.clone(), pointer, ty],
            }],
        };

        let report = optimize_with_profile(&mut module, OptimizationProfile::O2);

        assert_eq!(report.constants_propagated, 0);
        assert!(matches!(
            module.functions[0].blocks[0]
                .instructions
                .iter()
                .find(|instruction| instruction.result == Some(ValueId(2)))
                .expect("retained load")
                .kind,
            InstructionKind::LoadLocal(LocalId(0))
        ));
        nesc_mir::verify(&module).expect("optimized MIR remains valid");
    }
}
