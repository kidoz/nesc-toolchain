//! Frequency-guided physical basic-block placement.

use std::cmp::Reverse;

use nesc_mir::{BlockId, Function, Terminator};

/// Returns a deterministic trace order with hot successors placed as fall-throughs.
pub(crate) fn block_order(function: &Function) -> Vec<BlockId> {
    let analysis = nesc_opt::analyze_control_flow(function);
    let block_count = function.blocks.len();
    let mut placed = vec![false; block_count];
    let mut order = Vec::with_capacity(block_count);

    let mut seed = function
        .entry
        .filter(|block| (block.0 as usize) < block_count);
    while order.len() < block_count {
        let Some(mut current) = seed.or_else(|| next_seed(&placed, &analysis.block_frequencies))
        else {
            break;
        };
        loop {
            let index = current.0 as usize;
            if index >= block_count || placed[index] {
                break;
            }
            placed[index] = true;
            order.push(current);
            let Some(successor) = successors(function.blocks[index].terminator.as_ref())
                .into_iter()
                .filter(|successor| {
                    (successor.0 as usize) < block_count && !placed[successor.0 as usize]
                })
                .max_by_key(|successor| {
                    (analysis.block_frequency(*successor), Reverse(successor.0))
                })
            else {
                break;
            };
            current = successor;
        }
        seed = next_seed(&placed, &analysis.block_frequencies);
    }
    order
}

fn next_seed(placed: &[bool], frequencies: &[u32]) -> Option<BlockId> {
    placed
        .iter()
        .enumerate()
        .filter(|(_, placed)| !**placed)
        .map(|(index, _)| BlockId(index as u32))
        .max_by_key(|block| {
            (
                frequencies.get(block.0 as usize).copied().unwrap_or(0),
                Reverse(block.0),
            )
        })
}

fn successors(terminator: Option<&Terminator>) -> Vec<BlockId> {
    match terminator {
        Some(Terminator::Jump(target)) => vec![*target],
        Some(Terminator::Branch {
            then_block,
            else_block,
            ..
        }) if then_block == else_block => vec![*then_block],
        Some(Terminator::Branch {
            then_block,
            else_block,
            ..
        }) => vec![*then_block, *else_block],
        Some(Terminator::Return(_) | Terminator::Unreachable) | None => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use nesc_mir::{
        BankPlacement, BasicBlock, BlockId, Function, FunctionId, Terminator, Type, TypeKind,
        ValueId,
    };

    use super::block_order;

    #[test]
    fn places_the_loop_trace_before_a_cold_successor() {
        let function = Function {
            id: FunctionId(0),
            name: "layout".to_owned(),
            placement: BankPlacement::Fixed,
            return_type: Type::scalar(TypeKind::Void),
            parameters: Vec::new(),
            locals: Vec::new(),
            entry: Some(BlockId(0)),
            blocks: vec![
                BasicBlock {
                    id: BlockId(0),
                    instructions: Vec::new(),
                    terminator: Some(Terminator::Branch {
                        condition: ValueId(0),
                        then_block: BlockId(1),
                        else_block: BlockId(2),
                    }),
                },
                BasicBlock {
                    id: BlockId(1),
                    instructions: Vec::new(),
                    terminator: Some(Terminator::Return(None)),
                },
                BasicBlock {
                    id: BlockId(2),
                    instructions: Vec::new(),
                    terminator: Some(Terminator::Jump(BlockId(3))),
                },
                BasicBlock {
                    id: BlockId(3),
                    instructions: Vec::new(),
                    terminator: Some(Terminator::Branch {
                        condition: ValueId(1),
                        then_block: BlockId(2),
                        else_block: BlockId(4),
                    }),
                },
                BasicBlock {
                    id: BlockId(4),
                    instructions: Vec::new(),
                    terminator: Some(Terminator::Return(None)),
                },
            ],
            value_types: vec![Type::scalar(TypeKind::Bool), Type::scalar(TypeKind::Bool)],
        };

        assert_eq!(
            block_order(&function),
            vec![BlockId(0), BlockId(2), BlockId(3), BlockId(4), BlockId(1)]
        );
    }
}
