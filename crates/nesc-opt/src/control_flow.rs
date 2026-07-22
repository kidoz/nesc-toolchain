//! Deterministic control-flow analysis shared by optimization and code generation.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use nesc_mir::{BlockId, Function, Terminator};

const LOOP_FREQUENCY_MULTIPLIER: u32 = 10;

/// One natural loop identified by a back edge to a dominating header.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NaturalLoop {
    /// Dominating block targeted by one or more back edges.
    pub header: BlockId,
    /// Deterministically ordered blocks in the loop body, including the header.
    pub blocks: Vec<BlockId>,
}

/// CFG relationships and conservative execution-frequency estimates.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ControlFlowAnalysis {
    /// Whether each block is reachable from the function entry.
    pub reachable: Vec<bool>,
    /// Predecessors indexed by block identifier.
    pub predecessors: Vec<Vec<BlockId>>,
    /// Dominators indexed by block identifier.
    pub dominators: Vec<BTreeSet<BlockId>>,
    /// Natural loops ordered by header identifier.
    pub loops: Vec<NaturalLoop>,
    /// Relative execution weight indexed by block identifier.
    pub block_frequencies: Vec<u32>,
}

impl ControlFlowAnalysis {
    /// Returns the relative execution weight for a block.
    #[must_use]
    pub fn block_frequency(&self, block: BlockId) -> u32 {
        self.block_frequencies
            .get(block.0 as usize)
            .copied()
            .unwrap_or(0)
    }

    /// Returns the greatest natural-loop nesting depth in the function.
    #[must_use]
    pub fn maximum_loop_depth(&self) -> usize {
        (0..self.reachable.len())
            .map(|index| {
                let block = BlockId(index as u32);
                self.loops
                    .iter()
                    .filter(|natural_loop| natural_loop.blocks.contains(&block))
                    .count()
            })
            .max()
            .unwrap_or(0)
    }
}

/// Computes reachability, predecessors, dominators, natural loops, and weights.
#[must_use]
pub fn analyze_control_flow(function: &Function) -> ControlFlowAnalysis {
    let block_count = function.blocks.len();
    let successors = function
        .blocks
        .iter()
        .map(|block| terminator_successors(block.terminator.as_ref(), block_count))
        .collect::<Vec<_>>();
    let mut predecessors = vec![Vec::new(); block_count];
    for (source, targets) in successors.iter().enumerate() {
        for target in targets {
            predecessors[target.0 as usize].push(BlockId(source as u32));
        }
    }
    for blocks in &mut predecessors {
        blocks.sort_unstable();
        blocks.dedup();
    }

    let mut reachable = vec![false; block_count];
    if let Some(entry) = function
        .entry
        .filter(|entry| (entry.0 as usize) < block_count)
    {
        let mut pending = VecDeque::from([entry]);
        reachable[entry.0 as usize] = true;
        while let Some(block) = pending.pop_front() {
            for successor in &successors[block.0 as usize] {
                if !reachable[successor.0 as usize] {
                    reachable[successor.0 as usize] = true;
                    pending.push_back(*successor);
                }
            }
        }
    }

    let reachable_blocks = reachable
        .iter()
        .enumerate()
        .filter_map(|(index, reachable)| reachable.then_some(BlockId(index as u32)))
        .collect::<BTreeSet<_>>();
    let mut dominators = vec![BTreeSet::new(); block_count];
    if let Some(entry) = function
        .entry
        .filter(|entry| (entry.0 as usize) < block_count)
    {
        for block in &reachable_blocks {
            dominators[block.0 as usize] = if *block == entry {
                BTreeSet::from([entry])
            } else {
                reachable_blocks.clone()
            };
        }
        loop {
            let mut changed = false;
            for block in reachable_blocks
                .iter()
                .copied()
                .filter(|block| *block != entry)
            {
                let mut incoming = predecessors[block.0 as usize]
                    .iter()
                    .copied()
                    .filter(|predecessor| reachable[predecessor.0 as usize]);
                let mut updated = incoming.next().map_or_else(BTreeSet::new, |predecessor| {
                    dominators[predecessor.0 as usize].clone()
                });
                for predecessor in incoming {
                    updated = updated
                        .intersection(&dominators[predecessor.0 as usize])
                        .copied()
                        .collect();
                }
                updated.insert(block);
                if updated != dominators[block.0 as usize] {
                    dominators[block.0 as usize] = updated;
                    changed = true;
                }
            }
            if !changed {
                break;
            }
        }
    }

    let mut loop_blocks = BTreeMap::<BlockId, BTreeSet<BlockId>>::new();
    for (source_index, targets) in successors.iter().enumerate() {
        let source = BlockId(source_index as u32);
        if !reachable[source_index] {
            continue;
        }
        for header in targets {
            if !dominators[source_index].contains(header) {
                continue;
            }
            let natural_loop = loop_blocks.entry(*header).or_default();
            natural_loop.insert(*header);
            if natural_loop.insert(source) {
                let mut pending = vec![source];
                while let Some(block) = pending.pop() {
                    for predecessor in &predecessors[block.0 as usize] {
                        if natural_loop.insert(*predecessor) && *predecessor != *header {
                            pending.push(*predecessor);
                        }
                    }
                }
            }
        }
    }
    let loops = loop_blocks
        .into_iter()
        .map(|(header, blocks)| NaturalLoop {
            header,
            blocks: blocks.into_iter().collect(),
        })
        .collect::<Vec<_>>();
    let block_frequencies = reachable
        .iter()
        .enumerate()
        .map(|(index, reachable)| {
            if !reachable {
                return 0;
            }
            let block = BlockId(index as u32);
            let depth = loops
                .iter()
                .filter(|natural_loop| natural_loop.blocks.contains(&block))
                .count();
            (0..depth).fold(1_u32, |weight, _| {
                weight.saturating_mul(LOOP_FREQUENCY_MULTIPLIER)
            })
        })
        .collect();

    ControlFlowAnalysis {
        reachable,
        predecessors,
        dominators,
        loops,
        block_frequencies,
    }
}

fn terminator_successors(terminator: Option<&Terminator>, block_count: usize) -> Vec<BlockId> {
    let mut successors = match terminator {
        Some(Terminator::Jump(target)) => vec![*target],
        Some(Terminator::Branch {
            then_block,
            else_block,
            ..
        }) => vec![*then_block, *else_block],
        Some(Terminator::Return(_) | Terminator::Unreachable) | None => Vec::new(),
    };
    successors.retain(|block| (block.0 as usize) < block_count);
    successors.sort_unstable();
    successors.dedup();
    successors
}

#[cfg(test)]
mod tests {
    use nesc_mir::{
        BankPlacement, BasicBlock, BlockId, Function, FunctionId, Terminator, Type, TypeKind,
    };

    use super::analyze_control_flow;

    #[test]
    fn finds_dominators_natural_loops_and_relative_frequencies() {
        let function = Function {
            id: FunctionId(0),
            name: "looping".to_owned(),
            placement: BankPlacement::Fixed,
            return_type: Type::scalar(TypeKind::Void),
            parameters: Vec::new(),
            locals: Vec::new(),
            entry: Some(BlockId(0)),
            blocks: vec![
                BasicBlock {
                    id: BlockId(0),
                    instructions: Vec::new(),
                    terminator: Some(Terminator::Jump(BlockId(1))),
                },
                BasicBlock {
                    id: BlockId(1),
                    instructions: Vec::new(),
                    terminator: Some(Terminator::Branch {
                        condition: nesc_mir::ValueId(0),
                        then_block: BlockId(2),
                        else_block: BlockId(4),
                    }),
                },
                BasicBlock {
                    id: BlockId(2),
                    instructions: Vec::new(),
                    terminator: Some(Terminator::Jump(BlockId(3))),
                },
                BasicBlock {
                    id: BlockId(3),
                    instructions: Vec::new(),
                    terminator: Some(Terminator::Jump(BlockId(1))),
                },
                BasicBlock {
                    id: BlockId(4),
                    instructions: Vec::new(),
                    terminator: Some(Terminator::Return(None)),
                },
                BasicBlock {
                    id: BlockId(5),
                    instructions: Vec::new(),
                    terminator: Some(Terminator::Return(None)),
                },
            ],
            value_types: vec![Type::scalar(TypeKind::Bool)],
        };

        let analysis = analyze_control_flow(&function);

        assert_eq!(analysis.predecessors[1], vec![BlockId(0), BlockId(3)]);
        assert!(analysis.dominators[3].contains(&BlockId(1)));
        assert_eq!(analysis.loops.len(), 1);
        assert_eq!(analysis.loops[0].header, BlockId(1));
        assert_eq!(
            analysis.loops[0].blocks,
            vec![BlockId(1), BlockId(2), BlockId(3)]
        );
        assert_eq!(analysis.block_frequencies, vec![1, 10, 10, 10, 1, 0]);
        assert_eq!(analysis.maximum_loop_depth(), 1);
    }

    #[test]
    fn compounds_frequency_for_nested_natural_loops() {
        let function = Function {
            id: FunctionId(0),
            name: "nested".to_owned(),
            placement: BankPlacement::Fixed,
            return_type: Type::scalar(TypeKind::Void),
            parameters: Vec::new(),
            locals: Vec::new(),
            entry: Some(BlockId(0)),
            blocks: vec![
                BasicBlock {
                    id: BlockId(0),
                    instructions: Vec::new(),
                    terminator: Some(Terminator::Jump(BlockId(1))),
                },
                BasicBlock {
                    id: BlockId(1),
                    instructions: Vec::new(),
                    terminator: Some(Terminator::Branch {
                        condition: nesc_mir::ValueId(0),
                        then_block: BlockId(2),
                        else_block: BlockId(6),
                    }),
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
                        condition: nesc_mir::ValueId(1),
                        then_block: BlockId(4),
                        else_block: BlockId(5),
                    }),
                },
                BasicBlock {
                    id: BlockId(4),
                    instructions: Vec::new(),
                    terminator: Some(Terminator::Jump(BlockId(3))),
                },
                BasicBlock {
                    id: BlockId(5),
                    instructions: Vec::new(),
                    terminator: Some(Terminator::Jump(BlockId(1))),
                },
                BasicBlock {
                    id: BlockId(6),
                    instructions: Vec::new(),
                    terminator: Some(Terminator::Return(None)),
                },
            ],
            value_types: vec![Type::scalar(TypeKind::Bool), Type::scalar(TypeKind::Bool)],
        };

        let analysis = analyze_control_flow(&function);

        assert_eq!(analysis.loops.len(), 2);
        assert_eq!(analysis.maximum_loop_depth(), 2);
        assert_eq!(analysis.block_frequencies, vec![1, 10, 10, 100, 100, 10, 1]);
    }
}
