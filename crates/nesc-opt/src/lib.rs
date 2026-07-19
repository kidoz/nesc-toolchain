//! Target-aware optimization passes for NesC MIR.

use std::collections::{HashMap, HashSet};

use nesc_mir::{
    BinaryOperator, Effect, Function, InstructionKind, Module, Terminator, Type, TypeKind,
    UnaryOperator, ValueId,
};

/// Deterministic counts of transformations performed.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct OptimizationReport {
    /// Instructions replaced by constants.
    pub constants_folded: usize,
    /// Constant branches replaced by jumps.
    pub branches_simplified: usize,
    /// Unused pure instructions removed.
    pub instructions_removed: usize,
}

/// Runs the initial semantics-preserving MIR optimizer.
#[must_use]
pub fn optimize(module: &mut Module) -> OptimizationReport {
    let mut report = OptimizationReport::default();
    for function in &mut module.functions {
        fold_constants(function, &mut report);
        simplify_branches(function, &mut report);
        remove_dead_values(function, &mut report);
    }
    report
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
        BasicBlock, BlockId, Function, FunctionId, Instruction, InstructionKind, Module,
        Terminator, Type, TypeKind, ValueId,
    };

    use super::{Effect, optimize};

    #[test]
    fn folds_arithmetic_and_constant_branch() {
        let ty = Type::scalar(TypeKind::Integer(nesc_mir::IntegerType::I16));
        let mut module = Module {
            globals: Vec::new(),
            functions: vec![Function {
                id: FunctionId(0),
                name: "main".to_owned(),
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
}
