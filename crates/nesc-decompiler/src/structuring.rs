use std::collections::{BTreeMap, BTreeSet, VecDeque};

use super::{
    AnalysisError, BlockId, BlockTarget, ComparisonPredicate, Confidence, Function, FunctionId,
    FunctionValueAnalysis, Program, Provenance, RecoveredCondition, RecoveredPredicate,
    RecoveryAnalysis, StateVariable, Terminator, ValueAnalysis, ValueExpression, ValueId,
    ValueOperator,
};

const MAX_SAFE_NESTING: usize = 1_024;

/// Resource bounds for structuring untrusted control-flow graphs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ControlFlowLimits {
    /// Maximum structured regions across all functions.
    pub max_regions: usize,
    /// Maximum fixed-point iterations for graph facts.
    pub max_iterations: usize,
    /// Maximum graph-edge visits per function.
    pub max_graph_steps: usize,
    /// Maximum recursive structured-region nesting.
    pub max_nesting: usize,
    /// Maximum blocks retained in explicit fallbacks.
    pub max_fallback_blocks: usize,
}

impl Default for ControlFlowLimits {
    fn default() -> Self {
        Self {
            max_regions: 2_000_000,
            max_iterations: 10_000,
            max_graph_steps: 20_000_000,
            max_nesting: 256,
            max_fallback_blocks: 1_000_000,
        }
    }
}

/// Stable identifier for one structured region.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RegionId(pub u32);

/// One intraprocedural control-flow edge.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ControlEdge {
    /// Source block.
    pub source: BlockId,
    /// Destination block.
    pub target: BlockId,
}

/// Reason a function or region must retain interpreter or assembly fallback.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum FallbackReason {
    /// Control reaches an unresolved target or indirect jump.
    UnresolvedControl,
    /// A cyclic region has multiple entries.
    IrreducibleControlFlow,
    /// Direct function calls form a recursive component.
    RecursiveCallGraph,
    /// A natural loop has multiple exits not yet representable safely.
    MultipleLoopExits,
    /// A conditional has no proven common merge.
    MissingConditionalMerge,
    /// Region paths overlap in a way the tree cannot represent.
    OverlappingRegions,
    /// Interrupt entry or termination cannot be represented as ordinary flow.
    InterruptControl,
    /// A reducible graph shape is not yet safely representable.
    UnsupportedShape,
}

/// Evidence category for one structured inference.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum StructureEvidenceKind {
    /// Dominance establishes region ownership.
    Dominance,
    /// Post-dominance establishes a merge.
    PostDominance,
    /// A target dominating its predecessor establishes a back edge.
    BackEdge,
    /// Reverse predecessor closure establishes a natural loop.
    NaturalLoop,
    /// SSA flag analysis supplies a branch predicate.
    BranchPredicate,
    /// SSA induction and comparison evidence supplies a counted loop.
    CountedInduction,
    /// Direct call resolution supplies a call node.
    DirectCall,
    /// Machine control semantics supply a return node.
    Return,
    /// Graph analysis proves a recursive call component.
    RecursiveCall,
    /// Graph analysis proves multiple cyclic entries.
    IrreducibleGraph,
    /// Control-flow analysis retains an unresolved target.
    UnresolvedControl,
    /// Conservative fallback preserves an unrepresented region.
    ConservativeFallback,
}

/// Provenance-bearing support for a structured region.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StructureEvidence {
    /// Evidence category.
    pub kind: StructureEvidenceKind,
    /// Exact instruction evidence when applicable.
    pub provenance: Option<Provenance>,
}

/// Counted-loop facts recovered from SSA.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CountedLoop {
    /// Induction machine-state location.
    pub induction: StateVariable,
    /// Wrapping change applied on each iteration.
    pub step: i8,
    /// Proven eight-bit comparison bound.
    pub bound: u8,
}

/// Safely recovered loop form.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LoopForm {
    /// General condition-controlled loop.
    While,
    /// Restricted counted loop with SSA evidence.
    Counted(CountedLoop),
}

/// Structured control behavior and owned child regions.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StructuredRegionKind {
    /// Ordered structured children.
    Sequence { children: Vec<RegionId> },
    /// Straight-line block followed by its single successor.
    Block { block: BlockId },
    /// Conditional branches that reconverge at a proven merge.
    If {
        header: BlockId,
        condition: RecoveredCondition,
        then_region: Option<RegionId>,
        else_region: Option<RegionId>,
        merge: BlockId,
    },
    /// Natural loop with a unique exit.
    Loop {
        header: BlockId,
        condition: RecoveredCondition,
        body: Option<RegionId>,
        exit: BlockId,
        form: LoopForm,
    },
    /// Direct call followed by a resolved continuation.
    Call {
        block: BlockId,
        callee: FunctionId,
        continuation: BlockId,
    },
    /// Ordinary or interrupt return.
    Return { block: BlockId, interrupt: bool },
    /// Explicit fallback preserving all listed blocks.
    Fallback { reason: FallbackReason },
}

/// One structured region with aggregate block ownership.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StructuredRegion {
    /// Canonical region identifier.
    pub id: RegionId,
    /// Structured behavior.
    pub kind: StructuredRegionKind,
    /// Canonically ordered blocks covered by this region and its children.
    pub blocks: Vec<BlockId>,
    /// Confidence in the complete region structure.
    pub confidence: Confidence,
    /// Evidence supporting the structure or fallback.
    pub evidence: Vec<StructureEvidence>,
}

/// Structured result and graph facts for one function.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StructuredFunction {
    /// Recovered function identity.
    pub function: FunctionId,
    /// Root structured region.
    pub root: RegionId,
    /// Regions in canonical identifier order.
    pub regions: Vec<StructuredRegion>,
    /// Dominator sets for every function block.
    pub dominators: BTreeMap<BlockId, Vec<BlockId>>,
    /// Post-dominator sets for every function block.
    pub post_dominators: BTreeMap<BlockId, Vec<BlockId>>,
    /// Proven back edges.
    pub back_edges: Vec<ControlEdge>,
    /// Overall structure confidence.
    pub confidence: Confidence,
}

/// Complete structured control-flow analysis.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ControlFlowAnalysis {
    /// Per-function results in canonical function order.
    pub functions: Vec<StructuredFunction>,
}

/// Structures reducible control flow and emits explicit conservative fallbacks.
///
/// # Errors
///
/// Returns deterministic failures for invalid prerequisite analyses, exhausted
/// limits, or malformed structured references.
pub fn structure_control_flow(
    program: &Program,
    values: &ValueAnalysis,
    recovery: &RecoveryAnalysis,
    limits: ControlFlowLimits,
) -> Result<ControlFlowAnalysis, Vec<AnalysisError>> {
    if limits.max_regions == 0
        || limits.max_iterations == 0
        || limits.max_graph_steps == 0
        || limits.max_nesting == 0
        || limits.max_fallback_blocks == 0
    {
        return Err(vec![AnalysisError::new(
            "control-flow limits must permit regions, iterations, graph walks, nesting, and fallbacks",
        )]);
    }
    program.verify()?;
    values.verify(program)?;
    recovery.verify(program, values)?;

    let mut total_regions = 0_usize;
    let mut total_fallback_blocks = 0_usize;
    let mut functions = Vec::with_capacity(program.functions.len());
    for function in &program.functions {
        let structured = structure_function(program, values, recovery, function, limits)?;
        total_regions = total_regions.saturating_add(structured.regions.len());
        total_fallback_blocks = total_fallback_blocks.saturating_add(
            structured
                .regions
                .iter()
                .filter(|region| matches!(region.kind, StructuredRegionKind::Fallback { .. }))
                .map(|region| region.blocks.len())
                .sum::<usize>(),
        );
        if total_regions > limits.max_regions {
            return Err(vec![AnalysisError::new(format!(
                "structured-region limit {} exceeded",
                limits.max_regions
            ))]);
        }
        if total_fallback_blocks > limits.max_fallback_blocks {
            return Err(vec![AnalysisError::new(format!(
                "fallback-block limit {} exceeded",
                limits.max_fallback_blocks
            ))]);
        }
        functions.push(structured);
    }
    let analysis = ControlFlowAnalysis { functions };
    analysis.verify(program, values, recovery)?;
    Ok(analysis)
}

#[derive(Clone)]
struct FunctionGraph {
    successors: BTreeMap<BlockId, Vec<BlockId>>,
    predecessors: BTreeMap<BlockId, Vec<BlockId>>,
}

#[derive(Clone)]
struct NaturalLoop {
    header: BlockId,
    blocks: BTreeSet<BlockId>,
    latches: BTreeSet<BlockId>,
    exits: BTreeSet<BlockId>,
}

struct GraphFacts {
    graph: FunctionGraph,
    dominators: BTreeMap<BlockId, BTreeSet<BlockId>>,
    post_dominators: BTreeMap<BlockId, BTreeSet<BlockId>>,
    back_edges: Vec<ControlEdge>,
    loops: BTreeMap<BlockId, NaturalLoop>,
    irreducible: bool,
}

fn structure_function(
    program: &Program,
    values: &ValueAnalysis,
    recovery: &RecoveryAnalysis,
    function: &Function,
    limits: ControlFlowLimits,
) -> Result<StructuredFunction, Vec<AnalysisError>> {
    let facts = analyze_graph(program, function, limits)?;
    let value_analysis = &values.functions[function.id.0 as usize];
    let recursive = recovery
        .cycles
        .iter()
        .any(|cycle| cycle.functions.contains(&function.id));
    let unresolved = function.blocks.iter().any(|block| {
        matches!(
            program.blocks[block].terminator,
            Terminator::Fallthrough(BlockTarget::Unresolved { .. })
                | Terminator::Jump(BlockTarget::Unresolved { .. })
                | Terminator::Branch {
                    taken: BlockTarget::Unresolved { .. },
                    ..
                }
                | Terminator::Branch {
                    not_taken: BlockTarget::Unresolved { .. },
                    ..
                }
                | Terminator::Call {
                    callee: BlockTarget::Unresolved { .. },
                    ..
                }
                | Terminator::Call {
                    continuation: BlockTarget::Unresolved { .. },
                    ..
                }
                | Terminator::Stop(_)
        )
    });
    let interrupt = function
        .blocks
        .iter()
        .any(|block| matches!(program.blocks[block].terminator, Terminator::Interrupt));

    let fallback = if recursive {
        Some(FallbackReason::RecursiveCallGraph)
    } else if unresolved {
        Some(FallbackReason::UnresolvedControl)
    } else if facts.irreducible {
        Some(FallbackReason::IrreducibleControlFlow)
    } else if interrupt {
        Some(FallbackReason::InterruptControl)
    } else {
        None
    };

    let mut builder = RegionBuilder {
        program,
        recovery,
        function,
        values: value_analysis,
        facts: &facts,
        regions: Vec::new(),
        claimed: BTreeSet::new(),
        limits,
        graph_steps: 0,
    };
    let root = if let Some(reason) = fallback {
        builder
            .fallback(function.blocks.iter().copied().collect(), reason)
            .map_err(build_errors)?
    } else {
        let allowed = function.blocks.iter().copied().collect::<BTreeSet<_>>();
        match builder.sequence(function.entry, None, &allowed, 0) {
            Ok(root) if builder.claimed == allowed => root,
            Ok(_) => {
                builder.regions.clear();
                builder.claimed.clear();
                builder
                    .fallback(allowed, FallbackReason::UnsupportedShape)
                    .map_err(build_errors)?
            }
            Err(BuildError::Fallback(reason)) => {
                builder.regions.clear();
                builder.claimed.clear();
                builder.fallback(allowed, reason).map_err(build_errors)?
            }
            Err(BuildError::Analysis(error)) => return Err(vec![error]),
        }
    };
    let confidence = builder.regions[root.0 as usize].confidence;
    Ok(StructuredFunction {
        function: function.id,
        root,
        regions: builder.regions,
        dominators: set_map_to_vectors(&facts.dominators),
        post_dominators: set_map_to_vectors(&facts.post_dominators),
        back_edges: facts.back_edges,
        confidence,
    })
}

fn analyze_graph(
    program: &Program,
    function: &Function,
    limits: ControlFlowLimits,
) -> Result<GraphFacts, Vec<AnalysisError>> {
    let graph = function_graph(program, function);
    let mut steps = 0_usize;
    let dominators = compute_dominators(function, &graph, limits, &mut steps)?;
    let post_dominators = compute_post_dominators(function, &graph, limits, &mut steps)?;
    let mut back_edges = Vec::new();
    for (source, successors) in &graph.successors {
        for target in successors {
            steps = checked_step(steps, limits.max_graph_steps)?;
            if dominators[source].contains(target) {
                back_edges.push(ControlEdge {
                    source: *source,
                    target: *target,
                });
            }
        }
    }
    back_edges.sort();
    back_edges.dedup();
    let loops = natural_loops(&graph, &back_edges, limits, &mut steps)?;
    let irreducible = contains_irreducible_scc(function, &graph, &dominators, limits, &mut steps)?;
    Ok(GraphFacts {
        graph,
        dominators,
        post_dominators,
        back_edges,
        loops,
        irreducible,
    })
}

fn function_graph(program: &Program, function: &Function) -> FunctionGraph {
    let owned = function.blocks.iter().copied().collect::<BTreeSet<_>>();
    let mut successors = function
        .blocks
        .iter()
        .map(|block| (*block, Vec::new()))
        .collect::<BTreeMap<_, _>>();
    let mut predecessors = successors.clone();
    for edge in &program.edges {
        if edge.kind == super::EdgeKind::CallTarget || !owned.contains(&edge.source) {
            continue;
        }
        let Some(target) = edge.target.filter(|target| owned.contains(target)) else {
            continue;
        };
        successors.entry(edge.source).or_default().push(target);
        predecessors.entry(target).or_default().push(edge.source);
    }
    for edges in successors.values_mut().chain(predecessors.values_mut()) {
        edges.sort();
        edges.dedup();
    }
    FunctionGraph {
        successors,
        predecessors,
    }
}

fn compute_dominators(
    function: &Function,
    graph: &FunctionGraph,
    limits: ControlFlowLimits,
    steps: &mut usize,
) -> Result<BTreeMap<BlockId, BTreeSet<BlockId>>, Vec<AnalysisError>> {
    let all = function.blocks.iter().copied().collect::<BTreeSet<_>>();
    let mut sets = function
        .blocks
        .iter()
        .map(|block| {
            (
                *block,
                if *block == function.entry {
                    BTreeSet::from([*block])
                } else {
                    all.clone()
                },
            )
        })
        .collect::<BTreeMap<_, _>>();
    for iteration in 0..limits.max_iterations {
        let previous = sets.clone();
        let mut changed = false;
        for block in function
            .blocks
            .iter()
            .copied()
            .filter(|block| *block != function.entry)
        {
            let predecessors = &graph.predecessors[&block];
            let mut next = if let Some(first) = predecessors.first() {
                previous[first].clone()
            } else {
                BTreeSet::new()
            };
            for predecessor in predecessors.iter().skip(1) {
                *steps = checked_step(*steps, limits.max_graph_steps)?;
                next = next.intersection(&previous[predecessor]).copied().collect();
            }
            next.insert(block);
            if sets[&block] != next {
                sets.insert(block, next);
                changed = true;
            }
        }
        if !changed {
            return Ok(sets);
        }
        if iteration + 1 == limits.max_iterations {
            return Err(vec![AnalysisError::new(format!(
                "dominator analysis did not converge within {} iterations",
                limits.max_iterations
            ))]);
        }
    }
    unreachable!("positive iteration limit")
}

fn compute_post_dominators(
    function: &Function,
    graph: &FunctionGraph,
    limits: ControlFlowLimits,
    steps: &mut usize,
) -> Result<BTreeMap<BlockId, BTreeSet<BlockId>>, Vec<AnalysisError>> {
    let all = function.blocks.iter().copied().collect::<BTreeSet<_>>();
    let exits = function
        .blocks
        .iter()
        .copied()
        .filter(|block| graph.successors[block].is_empty())
        .collect::<BTreeSet<_>>();
    let mut sets = function
        .blocks
        .iter()
        .map(|block| {
            (
                *block,
                if exits.contains(block) {
                    BTreeSet::from([*block])
                } else {
                    all.clone()
                },
            )
        })
        .collect::<BTreeMap<_, _>>();
    for iteration in 0..limits.max_iterations {
        let previous = sets.clone();
        let mut changed = false;
        for block in function
            .blocks
            .iter()
            .copied()
            .filter(|block| !exits.contains(block))
        {
            let successors = &graph.successors[&block];
            if successors.is_empty() {
                continue;
            }
            let mut next = previous[&successors[0]].clone();
            for successor in successors.iter().skip(1) {
                *steps = checked_step(*steps, limits.max_graph_steps)?;
                next = next.intersection(&previous[successor]).copied().collect();
            }
            next.insert(block);
            if sets[&block] != next {
                sets.insert(block, next);
                changed = true;
            }
        }
        if !changed {
            return Ok(sets);
        }
        if iteration + 1 == limits.max_iterations {
            return Err(vec![AnalysisError::new(format!(
                "post-dominator analysis did not converge within {} iterations",
                limits.max_iterations
            ))]);
        }
    }
    unreachable!("positive iteration limit")
}

fn checked_step(steps: usize, limit: usize) -> Result<usize, Vec<AnalysisError>> {
    let next = steps.saturating_add(1);
    if next > limit {
        Err(vec![AnalysisError::new(format!(
            "control-flow graph-walk limit {limit} exceeded"
        ))])
    } else {
        Ok(next)
    }
}

fn natural_loops(
    graph: &FunctionGraph,
    back_edges: &[ControlEdge],
    limits: ControlFlowLimits,
    steps: &mut usize,
) -> Result<BTreeMap<BlockId, NaturalLoop>, Vec<AnalysisError>> {
    let mut loops = BTreeMap::<BlockId, NaturalLoop>::new();
    for edge in back_edges {
        let mut blocks = BTreeSet::from([edge.target, edge.source]);
        let mut queue = VecDeque::new();
        if edge.source != edge.target {
            queue.push_back(edge.source);
        }
        while let Some(block) = queue.pop_front() {
            for predecessor in &graph.predecessors[&block] {
                *steps = checked_step(*steps, limits.max_graph_steps)?;
                if blocks.insert(*predecessor) && *predecessor != edge.target {
                    queue.push_back(*predecessor);
                }
            }
        }
        let entry = loops.entry(edge.target).or_insert_with(|| NaturalLoop {
            header: edge.target,
            blocks: BTreeSet::new(),
            latches: BTreeSet::new(),
            exits: BTreeSet::new(),
        });
        entry.blocks.extend(blocks);
        entry.latches.insert(edge.source);
    }
    for natural_loop in loops.values_mut() {
        for block in &natural_loop.blocks {
            for successor in &graph.successors[block] {
                *steps = checked_step(*steps, limits.max_graph_steps)?;
                if !natural_loop.blocks.contains(successor) {
                    natural_loop.exits.insert(*successor);
                }
            }
        }
    }
    Ok(loops)
}

fn contains_irreducible_scc(
    function: &Function,
    graph: &FunctionGraph,
    dominators: &BTreeMap<BlockId, BTreeSet<BlockId>>,
    limits: ControlFlowLimits,
    steps: &mut usize,
) -> Result<bool, Vec<AnalysisError>> {
    let mut reachability = BTreeMap::new();
    for seed in &function.blocks {
        let mut reached = BTreeSet::new();
        let mut queue = VecDeque::from([*seed]);
        while let Some(block) = queue.pop_front() {
            for successor in &graph.successors[&block] {
                *steps = checked_step(*steps, limits.max_graph_steps)?;
                if reached.insert(*successor) {
                    queue.push_back(*successor);
                }
            }
        }
        reachability.insert(*seed, reached);
    }

    let mut remaining = function.blocks.iter().copied().collect::<BTreeSet<_>>();
    while let Some(seed) = remaining.first().copied() {
        let component = remaining
            .iter()
            .copied()
            .filter(|candidate| {
                (*candidate == seed || reachability[&seed].contains(candidate))
                    && (*candidate == seed || reachability[candidate].contains(&seed))
            })
            .collect::<BTreeSet<_>>();
        for block in &component {
            remaining.remove(block);
        }
        let cyclic = component.len() > 1 || graph.successors[&seed].contains(&seed);
        if !cyclic {
            continue;
        }
        let mut entries = component
            .iter()
            .copied()
            .filter(|block| {
                graph.predecessors[block]
                    .iter()
                    .any(|predecessor| !component.contains(predecessor))
            })
            .collect::<BTreeSet<_>>();
        if component.contains(&function.entry) {
            entries.insert(function.entry);
        }
        if entries.len() != 1 {
            return Ok(true);
        }
        let header = *entries.first().expect("one entry");
        if component
            .iter()
            .any(|block| !dominators[block].contains(&header))
        {
            return Ok(true);
        }
    }
    Ok(false)
}

fn set_map_to_vectors(
    sets: &BTreeMap<BlockId, BTreeSet<BlockId>>,
) -> BTreeMap<BlockId, Vec<BlockId>> {
    sets.iter()
        .map(|(block, values)| (*block, values.iter().copied().collect()))
        .collect()
}

enum BuildError {
    Fallback(FallbackReason),
    Analysis(AnalysisError),
}

fn build_errors(error: BuildError) -> Vec<AnalysisError> {
    match error {
        BuildError::Analysis(error) => vec![error],
        BuildError::Fallback(reason) => vec![AnalysisError::new(format!(
            "could not create conservative fallback for {reason:?}"
        ))],
    }
}

type BuildResult<T> = Result<T, BuildError>;

struct RegionBuilder<'a> {
    program: &'a Program,
    recovery: &'a RecoveryAnalysis,
    function: &'a Function,
    values: &'a FunctionValueAnalysis,
    facts: &'a GraphFacts,
    regions: Vec<StructuredRegion>,
    claimed: BTreeSet<BlockId>,
    limits: ControlFlowLimits,
    graph_steps: usize,
}

impl RegionBuilder<'_> {
    fn sequence(
        &mut self,
        start: BlockId,
        stop: Option<BlockId>,
        allowed: &BTreeSet<BlockId>,
        depth: usize,
    ) -> BuildResult<RegionId> {
        let nesting_limit = self.limits.max_nesting.min(MAX_SAFE_NESTING);
        if depth >= nesting_limit {
            return Err(BuildError::Analysis(AnalysisError::new(format!(
                "structured-region nesting limit {nesting_limit} exceeded"
            ))));
        }
        let mut children = Vec::new();
        let mut current = Some(start);
        while let Some(block) = current {
            if Some(block) == stop {
                break;
            }
            if !allowed.contains(&block) || self.claimed.contains(&block) {
                return Err(BuildError::Fallback(FallbackReason::OverlappingRegions));
            }
            if let Some(natural_loop) = self.facts.loops.get(&block).cloned() {
                let (region, next) = self.structure_loop(&natural_loop, allowed, depth + 1)?;
                children.push(region);
                current = Some(next);
                continue;
            }

            let terminator = self.program.blocks[&block].terminator.clone();
            match terminator {
                Terminator::Branch {
                    taken: BlockTarget::Resolved(taken),
                    not_taken: BlockTarget::Resolved(not_taken),
                    ..
                } => {
                    let (region, merge) =
                        self.structure_if(block, taken, not_taken, stop, allowed, depth + 1)?;
                    children.push(region);
                    current = Some(merge);
                }
                Terminator::Fallthrough(BlockTarget::Resolved(next))
                | Terminator::Jump(BlockTarget::Resolved(next)) => {
                    children.push(self.block_region(block)?);
                    current = Some(next);
                }
                Terminator::Call {
                    callee: BlockTarget::Resolved(_),
                    continuation: BlockTarget::Resolved(continuation),
                } => {
                    children.push(self.call_region(block, continuation)?);
                    current = Some(continuation);
                }
                Terminator::Return => {
                    children.push(self.return_region(block, false)?);
                    current = None;
                }
                Terminator::ReturnFromInterrupt => {
                    children.push(self.return_region(block, true)?);
                    current = None;
                }
                Terminator::Interrupt => {
                    return Err(BuildError::Fallback(FallbackReason::InterruptControl));
                }
                Terminator::Fallthrough(BlockTarget::Unresolved { .. })
                | Terminator::Jump(BlockTarget::Unresolved { .. })
                | Terminator::Branch { .. }
                | Terminator::Call { .. }
                | Terminator::Stop(_) => {
                    return Err(BuildError::Fallback(FallbackReason::UnresolvedControl));
                }
            }
        }
        if children.is_empty() {
            return Err(BuildError::Fallback(FallbackReason::UnsupportedShape));
        }
        self.sequence_region(children)
    }

    fn structure_if(
        &mut self,
        header: BlockId,
        taken: BlockId,
        not_taken: BlockId,
        stop: Option<BlockId>,
        allowed: &BTreeSet<BlockId>,
        depth: usize,
    ) -> BuildResult<(RegionId, BlockId)> {
        let merge = immediate_post_dominator(header, &self.facts.post_dominators).ok_or(
            BuildError::Fallback(FallbackReason::MissingConditionalMerge),
        )?;
        if !allowed.contains(&merge) && Some(merge) != stop {
            return Err(BuildError::Fallback(FallbackReason::OverlappingRegions));
        }
        let condition = self.condition(header)?;
        self.claimed.insert(header);

        let then_blocks = self.arm_blocks(header, taken, merge, allowed)?;
        let else_blocks = self.arm_blocks(header, not_taken, merge, allowed)?;
        if then_blocks.intersection(&else_blocks).next().is_some() {
            return Err(BuildError::Fallback(FallbackReason::OverlappingRegions));
        }
        let then_region = if taken == merge {
            None
        } else {
            let region = self.sequence(taken, Some(merge), &then_blocks, depth)?;
            if !then_blocks.iter().all(|block| self.claimed.contains(block)) {
                return Err(BuildError::Fallback(FallbackReason::UnsupportedShape));
            }
            Some(region)
        };
        let else_region = if not_taken == merge {
            None
        } else {
            let region = self.sequence(not_taken, Some(merge), &else_blocks, depth)?;
            if !else_blocks.iter().all(|block| self.claimed.contains(block)) {
                return Err(BuildError::Fallback(FallbackReason::UnsupportedShape));
            }
            Some(region)
        };
        let mut blocks = BTreeSet::from([header]);
        blocks.extend(then_blocks);
        blocks.extend(else_blocks);
        let confidence = child_confidence(
            condition.confidence,
            [then_region, else_region]
                .into_iter()
                .flatten()
                .map(|region| self.regions[region.0 as usize].confidence),
        );
        let evidence = vec![
            StructureEvidence {
                kind: StructureEvidenceKind::Dominance,
                provenance: None,
            },
            StructureEvidence {
                kind: StructureEvidenceKind::PostDominance,
                provenance: None,
            },
            StructureEvidence {
                kind: StructureEvidenceKind::BranchPredicate,
                provenance: Some(condition.provenance.clone()),
            },
        ];
        let region = self.make_region(
            StructuredRegionKind::If {
                header,
                condition,
                then_region,
                else_region,
                merge,
            },
            blocks,
            confidence,
            evidence,
        )?;
        Ok((region, merge))
    }

    fn structure_loop(
        &mut self,
        natural_loop: &NaturalLoop,
        allowed: &BTreeSet<BlockId>,
        depth: usize,
    ) -> BuildResult<(RegionId, BlockId)> {
        if natural_loop.exits.is_empty() {
            return Err(BuildError::Fallback(FallbackReason::UnsupportedShape));
        }
        if natural_loop.exits.len() > 1 {
            return Err(BuildError::Fallback(FallbackReason::MultipleLoopExits));
        }
        if !natural_loop.blocks.is_subset(allowed) {
            return Err(BuildError::Fallback(FallbackReason::OverlappingRegions));
        }
        let exit = *natural_loop.exits.first().expect("one exit");
        let Terminator::Branch {
            taken: BlockTarget::Resolved(taken),
            not_taken: BlockTarget::Resolved(not_taken),
            ..
        } = self.program.blocks[&natural_loop.header].terminator
        else {
            return Err(BuildError::Fallback(FallbackReason::UnsupportedShape));
        };
        let (body_entry, condition) = if natural_loop.blocks.contains(&taken) && not_taken == exit {
            (taken, self.condition(natural_loop.header)?)
        } else if natural_loop.blocks.contains(&not_taken) && taken == exit {
            (
                not_taken,
                negate_condition(self.condition(natural_loop.header)?),
            )
        } else {
            return Err(BuildError::Fallback(FallbackReason::UnsupportedShape));
        };
        self.claimed.insert(natural_loop.header);
        let body_blocks = natural_loop
            .blocks
            .iter()
            .copied()
            .filter(|block| *block != natural_loop.header)
            .collect::<BTreeSet<_>>();
        let body = if body_entry == natural_loop.header {
            None
        } else {
            let body = self.sequence(body_entry, Some(natural_loop.header), &body_blocks, depth)?;
            if !body_blocks.iter().all(|block| self.claimed.contains(block)) {
                return Err(BuildError::Fallback(FallbackReason::UnsupportedShape));
            }
            Some(body)
        };
        let form = recover_loop_form(self.values, natural_loop.header, &condition);
        let mut evidence = vec![
            StructureEvidence {
                kind: StructureEvidenceKind::BackEdge,
                provenance: None,
            },
            StructureEvidence {
                kind: StructureEvidenceKind::NaturalLoop,
                provenance: None,
            },
            StructureEvidence {
                kind: StructureEvidenceKind::BranchPredicate,
                provenance: Some(condition.provenance.clone()),
            },
        ];
        if matches!(form, LoopForm::Counted(_)) {
            evidence.push(StructureEvidence {
                kind: StructureEvidenceKind::CountedInduction,
                provenance: Some(condition.provenance.clone()),
            });
        }
        let confidence = child_confidence(
            condition.confidence,
            body.into_iter()
                .map(|region| self.regions[region.0 as usize].confidence),
        );
        let region = self.make_region(
            StructuredRegionKind::Loop {
                header: natural_loop.header,
                condition,
                body,
                exit,
                form,
            },
            natural_loop.blocks.clone(),
            confidence,
            evidence,
        )?;
        Ok((region, exit))
    }

    fn arm_blocks(
        &mut self,
        header: BlockId,
        start: BlockId,
        merge: BlockId,
        allowed: &BTreeSet<BlockId>,
    ) -> BuildResult<BTreeSet<BlockId>> {
        if start == merge {
            return Ok(BTreeSet::new());
        }
        let mut reached = BTreeSet::new();
        let mut queue = VecDeque::from([start]);
        while let Some(block) = queue.pop_front() {
            if block == merge {
                continue;
            }
            if !allowed.contains(&block) || !self.facts.dominators[&block].contains(&header) {
                return Err(BuildError::Fallback(FallbackReason::OverlappingRegions));
            }
            if !reached.insert(block) {
                continue;
            }
            for successor in &self.facts.graph.successors[&block] {
                self.step()?;
                if *successor != merge {
                    queue.push_back(*successor);
                }
            }
        }
        Ok(reached)
    }

    fn block_region(&mut self, block: BlockId) -> BuildResult<RegionId> {
        self.claimed.insert(block);
        self.make_region(
            StructuredRegionKind::Block { block },
            BTreeSet::from([block]),
            Confidence::Proven,
            vec![StructureEvidence {
                kind: StructureEvidenceKind::Dominance,
                provenance: block_provenance(self.program, block),
            }],
        )
    }

    fn call_region(&mut self, block: BlockId, continuation: BlockId) -> BuildResult<RegionId> {
        let call = self
            .recovery
            .calls
            .iter()
            .find(|call| call.caller == self.function.id && call.call_site == block)
            .ok_or(BuildError::Fallback(FallbackReason::UnresolvedControl))?;
        let callee = call
            .callee
            .ok_or(BuildError::Fallback(FallbackReason::UnresolvedControl))?;
        self.claimed.insert(block);
        self.make_region(
            StructuredRegionKind::Call {
                block,
                callee,
                continuation,
            },
            BTreeSet::from([block]),
            call.confidence,
            vec![StructureEvidence {
                kind: StructureEvidenceKind::DirectCall,
                provenance: call
                    .evidence
                    .iter()
                    .find_map(|evidence| evidence.provenance.clone()),
            }],
        )
    }

    fn return_region(&mut self, block: BlockId, interrupt: bool) -> BuildResult<RegionId> {
        self.claimed.insert(block);
        self.make_region(
            StructuredRegionKind::Return { block, interrupt },
            BTreeSet::from([block]),
            Confidence::Proven,
            vec![StructureEvidence {
                kind: StructureEvidenceKind::Return,
                provenance: block_provenance(self.program, block),
            }],
        )
    }

    fn condition(&self, block: BlockId) -> BuildResult<RecoveredCondition> {
        self.values
            .conditions
            .iter()
            .find(|condition| condition.block == block)
            .cloned()
            .ok_or(BuildError::Fallback(FallbackReason::UnsupportedShape))
    }

    fn sequence_region(&mut self, children: Vec<RegionId>) -> BuildResult<RegionId> {
        if children.len() == 1 {
            return Ok(children[0]);
        }
        let mut blocks = BTreeSet::new();
        let mut confidence = Confidence::Proven;
        for child in &children {
            let child = &self.regions[child.0 as usize];
            blocks.extend(child.blocks.iter().copied());
            confidence = confidence.max(child.confidence);
        }
        self.make_region(
            StructuredRegionKind::Sequence { children },
            blocks,
            confidence,
            vec![StructureEvidence {
                kind: StructureEvidenceKind::Dominance,
                provenance: None,
            }],
        )
    }

    fn fallback(
        &mut self,
        blocks: BTreeSet<BlockId>,
        reason: FallbackReason,
    ) -> BuildResult<RegionId> {
        if blocks.len() > self.limits.max_fallback_blocks {
            return Err(BuildError::Analysis(AnalysisError::new(format!(
                "fallback-block limit {} exceeded",
                self.limits.max_fallback_blocks
            ))));
        }
        self.claimed.extend(blocks.iter().copied());
        let kind = match reason {
            FallbackReason::RecursiveCallGraph => StructureEvidenceKind::RecursiveCall,
            FallbackReason::IrreducibleControlFlow => StructureEvidenceKind::IrreducibleGraph,
            FallbackReason::UnresolvedControl => StructureEvidenceKind::UnresolvedControl,
            _ => StructureEvidenceKind::ConservativeFallback,
        };
        let provenance = blocks
            .first()
            .and_then(|block| block_provenance(self.program, *block));
        self.make_region(
            StructuredRegionKind::Fallback { reason },
            blocks,
            Confidence::Unknown,
            vec![StructureEvidence { kind, provenance }],
        )
    }

    fn make_region(
        &mut self,
        kind: StructuredRegionKind,
        blocks: BTreeSet<BlockId>,
        confidence: Confidence,
        evidence: Vec<StructureEvidence>,
    ) -> BuildResult<RegionId> {
        if self.regions.len() >= self.limits.max_regions {
            return Err(BuildError::Analysis(AnalysisError::new(format!(
                "structured-region limit {} exceeded",
                self.limits.max_regions
            ))));
        }
        let id = RegionId(u32::try_from(self.regions.len()).map_err(|_| {
            BuildError::Analysis(AnalysisError::new(
                "structured-region identifier exceeds 32 bits",
            ))
        })?);
        self.regions.push(StructuredRegion {
            id,
            kind,
            blocks: blocks.into_iter().collect(),
            confidence,
            evidence,
        });
        Ok(id)
    }

    fn step(&mut self) -> BuildResult<()> {
        self.graph_steps = checked_step(self.graph_steps, self.limits.max_graph_steps)
            .map_err(|mut errors| BuildError::Analysis(errors.remove(0)))?;
        Ok(())
    }
}

fn immediate_post_dominator(
    block: BlockId,
    post_dominators: &BTreeMap<BlockId, BTreeSet<BlockId>>,
) -> Option<BlockId> {
    let strict = post_dominators[&block]
        .iter()
        .copied()
        .filter(|candidate| *candidate != block)
        .collect::<Vec<_>>();
    strict.iter().copied().find(|candidate| {
        strict
            .iter()
            .all(|other| other == candidate || !post_dominators[other].contains(candidate))
    })
}

fn negate_condition(mut condition: RecoveredCondition) -> RecoveredCondition {
    condition.predicate = match condition.predicate {
        RecoveredPredicate::Comparison {
            predicate,
            left,
            right,
        } => RecoveredPredicate::Comparison {
            predicate: match predicate {
                ComparisonPredicate::Equal => ComparisonPredicate::NotEqual,
                ComparisonPredicate::NotEqual => ComparisonPredicate::Equal,
                ComparisonPredicate::UnsignedGreaterEqual => ComparisonPredicate::UnsignedLess,
                ComparisonPredicate::UnsignedLess => ComparisonPredicate::UnsignedGreaterEqual,
            },
            left,
            right,
        },
        RecoveredPredicate::FlagValue {
            flag,
            value,
            expected,
        } => RecoveredPredicate::FlagValue {
            flag,
            value,
            expected: !expected,
        },
    };
    condition
}

fn recover_loop_form(
    values: &FunctionValueAnalysis,
    header: BlockId,
    condition: &RecoveredCondition,
) -> LoopForm {
    let RecoveredPredicate::Comparison { left, right, .. } = condition.predicate else {
        return LoopForm::While;
    };
    let candidates = [(left, right), (right, left)];
    for (induction, bound) in candidates {
        let Some((variable, step)) = induction_update(values, induction, header) else {
            continue;
        };
        let Some(bound) = values.constant(bound) else {
            continue;
        };
        return LoopForm::Counted(CountedLoop {
            induction: variable,
            step,
            bound,
        });
    }
    LoopForm::While
}

fn induction_update(
    values: &FunctionValueAnalysis,
    value: ValueId,
    header: BlockId,
) -> Option<(StateVariable, i8)> {
    let mut current = value;
    let mut visiting = BTreeSet::new();
    loop {
        if !visiting.insert(current) {
            return None;
        }
        let node = values.values.get(current.0 as usize)?;
        match &node.expression {
            ValueExpression::Binary {
                operator: ValueOperator::WrappingAdjust(step),
                left,
                ..
            } => return phi_variable(values, *left, header).map(|variable| (variable, *step)),
            ValueExpression::Copy(source) => current = *source,
            _ => return None,
        }
    }
}

fn phi_variable(
    values: &FunctionValueAnalysis,
    value: ValueId,
    header: BlockId,
) -> Option<StateVariable> {
    let mut current = value;
    let mut visiting = BTreeSet::new();
    loop {
        if !visiting.insert(current) {
            return None;
        }
        let node = values.values.get(current.0 as usize)?;
        match &node.expression {
            ValueExpression::Phi {
                block, variable, ..
            } if *block == header => return Some(*variable),
            ValueExpression::Copy(source) => current = *source,
            _ => return None,
        }
    }
}

fn child_confidence(base: Confidence, children: impl Iterator<Item = Confidence>) -> Confidence {
    children.fold(base, Confidence::max)
}

fn block_provenance(program: &Program, block: BlockId) -> Option<Provenance> {
    program.blocks[&block]
        .instructions
        .last()
        .map(|instruction| instruction.provenance.clone())
}

impl ControlFlowAnalysis {
    /// Verifies graph facts, region references, nesting, and exact block coverage.
    ///
    /// # Errors
    ///
    /// Returns every deterministic structural failure found.
    pub fn verify(
        &self,
        program: &Program,
        values: &ValueAnalysis,
        recovery: &RecoveryAnalysis,
    ) -> Result<(), Vec<AnalysisError>> {
        let mut errors = Vec::new();
        if let Err(mut prerequisite) = values.verify(program) {
            errors.append(&mut prerequisite);
        }
        if let Err(mut prerequisite) = recovery.verify(program, values) {
            errors.append(&mut prerequisite);
        }
        if self.functions.len() != program.functions.len() {
            errors.push(AnalysisError::new(
                "control-flow analysis does not contain every function",
            ));
        }
        for (index, structured) in self.functions.iter().enumerate() {
            if structured.function.0 as usize != index {
                errors.push(AnalysisError::new(
                    "structured function order is noncanonical",
                ));
                continue;
            }
            let function = &program.functions[index];
            let owned = function.blocks.iter().copied().collect::<BTreeSet<_>>();
            if structured.regions.get(structured.root.0 as usize).is_none() {
                errors.push(AnalysisError::new(
                    "structured function references an unknown root region",
                ));
                continue;
            }
            if structured.regions[structured.root.0 as usize]
                .blocks
                .iter()
                .copied()
                .collect::<BTreeSet<_>>()
                != owned
            {
                errors.push(AnalysisError::new(
                    "root structured region does not cover its complete function",
                ));
            }
            verify_graph_facts(structured, function, program, &mut errors);
            let mut leaves = BTreeSet::new();
            for (region_index, region) in structured.regions.iter().enumerate() {
                if region.id.0 as usize != region_index {
                    errors.push(AnalysisError::new(
                        "structured-region identifier is noncanonical",
                    ));
                }
                let valid_blocks = !region.blocks.is_empty()
                    && strictly_sorted(&region.blocks)
                    && region.blocks.iter().all(|block| owned.contains(block));
                if !valid_blocks {
                    errors.push(AnalysisError::new(
                        "structured region has invalid block ownership",
                    ));
                }
                if region.evidence.is_empty() {
                    errors.push(AnalysisError::new(
                        "structured region lacks supporting evidence",
                    ));
                }
                if !valid_blocks {
                    continue;
                }
                verify_region(
                    region,
                    &structured.regions,
                    program,
                    function,
                    &mut leaves,
                    &mut errors,
                );
            }
            if leaves != owned {
                errors.push(AnalysisError::new(
                    "structured leaves do not cover every function block exactly once",
                ));
            }
            let mut reachable = BTreeSet::new();
            collect_regions(
                structured.root,
                &structured.regions,
                &mut reachable,
                &mut errors,
            );
            if reachable.len() != structured.regions.len() {
                errors.push(AnalysisError::new(
                    "structured function contains unreachable regions",
                ));
            }
            if structured.confidence != structured.regions[structured.root.0 as usize].confidence {
                errors.push(AnalysisError::new(
                    "structured function confidence differs from its root",
                ));
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    /// Renders deterministic graph facts and structured regions.
    #[must_use]
    pub fn render_text(&self) -> String {
        let mut text = format!("structured-functions: {}\n", self.functions.len());
        for function in &self.functions {
            text.push_str(&format!(
                "\nfunction f{} root=r{} regions={} back-edges={} [{:?}]\n",
                function.function.0,
                function.root.0,
                function.regions.len(),
                function.back_edges.len(),
                function.confidence
            ));
            for edge in &function.back_edges {
                text.push_str(&format!(
                    "  back-edge prg{:02X}:${:04X} -> prg{:02X}:${:04X}\n",
                    edge.source.bank,
                    edge.source.cpu_address,
                    edge.target.bank,
                    edge.target.cpu_address
                ));
            }
            for region in &function.regions {
                text.push_str(&format!(
                    "  r{} {:?} blocks={:?} [{:?}]\n",
                    region.id.0, region.kind, region.blocks, region.confidence
                ));
            }
        }
        text
    }
}

fn verify_graph_facts(
    structured: &StructuredFunction,
    function: &Function,
    program: &Program,
    errors: &mut Vec<AnalysisError>,
) {
    let owned = function.blocks.iter().copied().collect::<BTreeSet<_>>();
    let graph_keys_valid = structured
        .dominators
        .keys()
        .copied()
        .collect::<BTreeSet<_>>()
        == owned
        && structured
            .post_dominators
            .keys()
            .copied()
            .collect::<BTreeSet<_>>()
            == owned;
    for sets in [&structured.dominators, &structured.post_dominators] {
        if sets.keys().copied().collect::<BTreeSet<_>>() != owned {
            errors.push(AnalysisError::new(
                "structured graph facts do not cover every function block",
            ));
        }
        for (block, values) in sets {
            if !values.contains(block)
                || !strictly_sorted(values)
                || values.iter().any(|value| !owned.contains(value))
            {
                errors.push(AnalysisError::new(
                    "structured graph fact contains invalid block references",
                ));
            }
        }
    }
    if !graph_keys_valid {
        return;
    }
    if !strictly_sorted(&structured.back_edges) {
        errors.push(AnalysisError::new("back edges are noncanonical"));
    }
    let graph = function_graph(program, function);
    if structured.dominators.get(&function.entry) != Some(&vec![function.entry]) {
        errors.push(AnalysisError::new("function entry has invalid dominators"));
    }
    for block in function
        .blocks
        .iter()
        .copied()
        .filter(|block| *block != function.entry)
    {
        let predecessors = &graph.predecessors[&block];
        let mut expected = if let Some(first) = predecessors.first() {
            structured.dominators[first]
                .iter()
                .copied()
                .collect::<BTreeSet<_>>()
        } else {
            BTreeSet::new()
        };
        for predecessor in predecessors.iter().skip(1) {
            expected = expected
                .intersection(&structured.dominators[predecessor].iter().copied().collect())
                .copied()
                .collect();
        }
        expected.insert(block);
        if structured.dominators[&block] != expected.iter().copied().collect::<Vec<_>>() {
            errors.push(AnalysisError::new(
                "dominator sets do not satisfy CFG equations",
            ));
        }
    }
    let exits = function
        .blocks
        .iter()
        .copied()
        .filter(|block| graph.successors[block].is_empty())
        .collect::<BTreeSet<_>>();
    for block in &function.blocks {
        let expected = if exits.contains(block) {
            BTreeSet::from([*block])
        } else {
            let successors = &graph.successors[block];
            if successors.is_empty() {
                BTreeSet::from([*block])
            } else {
                let mut expected = structured.post_dominators[&successors[0]]
                    .iter()
                    .copied()
                    .collect::<BTreeSet<_>>();
                for successor in successors.iter().skip(1) {
                    expected = expected
                        .intersection(
                            &structured.post_dominators[successor]
                                .iter()
                                .copied()
                                .collect(),
                        )
                        .copied()
                        .collect();
                }
                expected.insert(*block);
                expected
            }
        };
        if structured.post_dominators[block] != expected.iter().copied().collect::<Vec<_>>() {
            errors.push(AnalysisError::new(
                "post-dominator sets do not satisfy CFG equations",
            ));
        }
    }
    for edge in &structured.back_edges {
        if !graph
            .successors
            .get(&edge.source)
            .is_some_and(|successors| successors.contains(&edge.target))
            || !structured
                .dominators
                .get(&edge.source)
                .is_some_and(|dominators| dominators.contains(&edge.target))
        {
            errors.push(AnalysisError::new(
                "back edge is not a dominance-qualified CFG edge",
            ));
        }
    }
    let expected_back_edges = graph
        .successors
        .iter()
        .flat_map(|(source, targets)| {
            targets.iter().filter_map(|target| {
                structured.dominators[source]
                    .contains(target)
                    .then_some(ControlEdge {
                        source: *source,
                        target: *target,
                    })
            })
        })
        .collect::<Vec<_>>();
    if structured.back_edges != expected_back_edges {
        errors.push(AnalysisError::new(
            "back-edge collection is incomplete or noncanonical",
        ));
    }
}

fn verify_region(
    region: &StructuredRegion,
    regions: &[StructuredRegion],
    program: &Program,
    function: &Function,
    leaves: &mut BTreeSet<BlockId>,
    errors: &mut Vec<AnalysisError>,
) {
    let region_blocks = region.blocks.iter().copied().collect::<BTreeSet<_>>();
    match &region.kind {
        StructuredRegionKind::Sequence { children } => {
            if children.len() < 2 {
                errors.push(AnalysisError::new(
                    "structured sequence has fewer than two children",
                ));
            }
            verify_child_union(children, &region_blocks, regions, errors);
        }
        StructuredRegionKind::Block { block } => {
            if region_blocks != BTreeSet::from([*block]) {
                errors.push(AnalysisError::new(
                    "straight-line region owns unexpected blocks",
                ));
            }
            insert_leaf(*block, leaves, errors);
        }
        StructuredRegionKind::If {
            header,
            condition,
            then_region,
            else_region,
            merge,
        } => {
            let children = [*then_region, *else_region]
                .into_iter()
                .flatten()
                .collect::<Vec<_>>();
            let mut expected = BTreeSet::from([*header]);
            for child in &children {
                if let Some(child) = regions.get(child.0 as usize) {
                    expected.extend(child.blocks.iter().copied());
                }
            }
            if expected != region_blocks
                || condition.block != *header
                || region_blocks.contains(merge)
            {
                errors.push(AnalysisError::new(
                    "conditional region has invalid ownership or merge",
                ));
            }
            verify_disjoint_children(&children, regions, errors);
            insert_leaf(*header, leaves, errors);
        }
        StructuredRegionKind::Loop {
            header,
            condition,
            body,
            exit,
            ..
        } => {
            let mut expected = BTreeSet::from([*header]);
            if let Some(body) = body.and_then(|body| regions.get(body.0 as usize)) {
                expected.extend(body.blocks.iter().copied());
            }
            if expected != region_blocks
                || condition.block != *header
                || region_blocks.contains(exit)
            {
                errors.push(AnalysisError::new(
                    "loop region has invalid ownership or exit",
                ));
            }
            insert_leaf(*header, leaves, errors);
        }
        StructuredRegionKind::Call {
            block,
            callee,
            continuation,
        } => {
            let continuation_matches = program.blocks.get(block).is_some_and(|basic| {
                matches!(
                    basic.terminator,
                    Terminator::Call {
                        continuation: BlockTarget::Resolved(target),
                        ..
                    } if target == *continuation
                )
            });
            if region_blocks != BTreeSet::from([*block])
                || program.functions.get(callee.0 as usize).is_none()
                || !continuation_matches
            {
                errors.push(AnalysisError::new(
                    "call region is inconsistent with its CFG",
                ));
            }
            insert_leaf(*block, leaves, errors);
        }
        StructuredRegionKind::Return { block, interrupt } => {
            let expected = program.blocks.get(block).is_some_and(|basic| {
                if *interrupt {
                    matches!(basic.terminator, Terminator::ReturnFromInterrupt)
                } else {
                    matches!(basic.terminator, Terminator::Return)
                }
            });
            if region_blocks != BTreeSet::from([*block]) || !expected {
                errors.push(AnalysisError::new(
                    "return region is inconsistent with its CFG",
                ));
            }
            insert_leaf(*block, leaves, errors);
        }
        StructuredRegionKind::Fallback { .. } => {
            if region_blocks != function.blocks.iter().copied().collect::<BTreeSet<_>>() {
                errors.push(AnalysisError::new(
                    "fallback region does not preserve the complete function",
                ));
            }
            for block in &region.blocks {
                insert_leaf(*block, leaves, errors);
            }
        }
    }
}

fn verify_child_union(
    children: &[RegionId],
    expected: &BTreeSet<BlockId>,
    regions: &[StructuredRegion],
    errors: &mut Vec<AnalysisError>,
) {
    verify_disjoint_children(children, regions, errors);
    let mut union = BTreeSet::new();
    for child in children {
        let Some(child) = regions.get(child.0 as usize) else {
            errors.push(AnalysisError::new(
                "structured region references an unknown child",
            ));
            continue;
        };
        union.extend(child.blocks.iter().copied());
    }
    if &union != expected {
        errors.push(AnalysisError::new(
            "structured child blocks do not match their parent",
        ));
    }
}

fn verify_disjoint_children(
    children: &[RegionId],
    regions: &[StructuredRegion],
    errors: &mut Vec<AnalysisError>,
) {
    let mut owned = BTreeSet::new();
    for child in children {
        let Some(child) = regions.get(child.0 as usize) else {
            errors.push(AnalysisError::new(
                "structured region references an unknown child",
            ));
            continue;
        };
        for block in &child.blocks {
            if !owned.insert(*block) {
                errors.push(AnalysisError::new(
                    "structured siblings overlap in block ownership",
                ));
            }
        }
    }
}

fn insert_leaf(block: BlockId, leaves: &mut BTreeSet<BlockId>, errors: &mut Vec<AnalysisError>) {
    if !leaves.insert(block) {
        errors.push(AnalysisError::new(
            "function block appears in multiple structured leaves",
        ));
    }
}

fn collect_regions(
    region: RegionId,
    regions: &[StructuredRegion],
    reachable: &mut BTreeSet<RegionId>,
    errors: &mut Vec<AnalysisError>,
) {
    let mut active = BTreeSet::new();
    let mut stack = vec![(region, false)];
    while let Some((current, expanded)) = stack.pop() {
        if expanded {
            active.remove(&current);
            reachable.insert(current);
            continue;
        }
        if reachable.contains(&current) {
            continue;
        }
        if !active.insert(current) {
            errors.push(AnalysisError::new("structured regions contain a cycle"));
            continue;
        }
        let Some(node) = regions.get(current.0 as usize) else {
            errors.push(AnalysisError::new(
                "structured region references an unknown child",
            ));
            active.remove(&current);
            continue;
        };
        stack.push((current, true));
        for child in region_children(&node.kind).into_iter().rev() {
            stack.push((child, false));
        }
    }
}

fn region_children(kind: &StructuredRegionKind) -> Vec<RegionId> {
    match kind {
        StructuredRegionKind::Sequence { children } => children.clone(),
        StructuredRegionKind::If {
            then_region,
            else_region,
            ..
        } => [*then_region, *else_region].into_iter().flatten().collect(),
        StructuredRegionKind::Loop { body, .. } => body.iter().copied().collect(),
        StructuredRegionKind::Block { .. }
        | StructuredRegionKind::Call { .. }
        | StructuredRegionKind::Return { .. }
        | StructuredRegionKind::Fallback { .. } => Vec::new(),
    }
}

fn strictly_sorted<T: Ord>(values: &[T]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

#[cfg(test)]
mod tests {
    use nesc_disasm::{AnalysisLimits as DisassemblyLimits, disassemble};
    use nesc_rom::{Format, Metadata, Mirroring, Region, Rom, build};

    use super::{
        ControlFlowLimits, FallbackReason, LoopForm, RegionId, StructuredRegionKind,
        structure_control_flow,
    };
    use crate::{
        AnalysisLimits, RecoveryLimits, ValueAnalysisLimits, analyze, analyze_recovery,
        analyze_values,
    };

    fn program(bytes: &[u8]) -> crate::Program {
        let mut prg = vec![0xff; 16 * 1024];
        prg[..bytes.len()].copy_from_slice(bytes);
        let vectors = prg.len() - 6;
        for offset in [0, 2, 4] {
            prg[vectors + offset..vectors + offset + 2].copy_from_slice(&0xc000_u16.to_le_bytes());
        }
        let rom = build(&Rom {
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
        .expect("ROM");
        let disassembly = disassemble(&rom, DisassemblyLimits::default()).expect("disassembly");
        analyze(&disassembly, AnalysisLimits::default()).expect("CFG")
    }

    fn structure(program: &crate::Program) -> super::ControlFlowAnalysis {
        let values = analyze_values(program, ValueAnalysisLimits::default()).expect("values");
        let recovery =
            analyze_recovery(program, &values, RecoveryLimits::default()).expect("recovery");
        structure_control_flow(program, &values, &recovery, ControlFlowLimits::default())
            .expect("structure")
    }

    #[test]
    fn structures_if_else_with_a_proven_merge() {
        let program = program(&[
            0xa5, 0x00, // lda $00
            0xf0, 0x05, // beq $c009
            0xa9, 0x01, // lda #1
            0x4c, 0x0b, 0xc0, // jmp $c00b
            0xa9, 0x02, // lda #2
            0x60, // rts
        ]);
        let analysis = structure(&program);
        let function = &analysis.functions[0];
        let conditional = function
            .regions
            .iter()
            .find_map(|region| match &region.kind {
                StructuredRegionKind::If { merge, .. } => Some(*merge),
                _ => None,
            })
            .expect("conditional");
        assert_eq!(conditional.cpu_address, 0xc00b);
        assert!(
            function.dominators[&conditional]
                .iter()
                .any(|block| block.cpu_address == 0xc000)
        );
        assert_eq!(analysis.render_text(), analysis.render_text());
    }

    #[test]
    fn recovers_a_counted_natural_loop() {
        let counted_program = program(&[
            0xa2, 0x00, // ldx #0
            0xe8, // inx
            0xe0, 0x03, // cpx #3
            0xd0, 0xfb, // bne $c002
            0x60, // rts
        ]);
        let analysis = structure(&counted_program);
        let function = &analysis.functions[0];
        assert_eq!(function.back_edges.len(), 1);
        let counted = function
            .regions
            .iter()
            .find_map(|region| match region.kind {
                StructuredRegionKind::Loop {
                    form: LoopForm::Counted(counted),
                    ..
                } => Some(counted),
                _ => None,
            });
        let counted = counted.expect("counted loop");
        assert_eq!(counted.step, 1);
        assert_eq!(counted.bound, 3);
        assert_eq!(
            counted.induction,
            crate::StateVariable::Register(crate::Register::X)
        );

        let while_program = program(&[
            0xa5, 0x00, // lda $00
            0xf0, 0x05, // beq $c009
            0xe6, 0x01, // inc $01
            0x4c, 0x00, 0xc0, // jmp $c000
            0x60, // rts
        ]);
        let while_analysis = structure(&while_program);
        assert!(while_analysis.functions[0].regions.iter().any(|region| {
            matches!(
                region.kind,
                StructuredRegionKind::Loop {
                    form: LoopForm::While,
                    ..
                }
            )
        }));
    }

    #[test]
    fn structures_direct_calls_and_returns() {
        let program = program(&[
            0x20, 0x04, 0xc0, // jsr $c004
            0x60, // rts
            0x60, // rts
        ]);
        let analysis = structure(&program);
        assert!(
            analysis.functions[0]
                .regions
                .iter()
                .any(|region| matches!(region.kind, StructuredRegionKind::Call { .. }))
        );
        assert!(
            analysis.functions[0]
                .regions
                .iter()
                .any(|region| matches!(region.kind, StructuredRegionKind::Return { .. }))
        );
    }

    #[test]
    fn falls_back_for_irreducible_and_unresolved_control() {
        let irreducible_program = program(&[
            0xa5, 0x00, // lda $00
            0xf0, 0x05, // beq $c009
            0x4c, 0x09, 0xc0, // jmp $c009
            0xff, 0xff, // unclassified gap
            0xd0, 0xf9, // bne $c004
            0x60, // rts
        ]);
        let irreducible = structure(&irreducible_program);
        assert!(matches!(
            irreducible.functions[0].regions[0].kind,
            StructuredRegionKind::Fallback {
                reason: FallbackReason::IrreducibleControlFlow
            }
        ));

        let unresolved_program = program(&[
            0x6c, 0x00, 0x02, // jmp ($0200)
        ]);
        let unresolved = structure(&unresolved_program);
        assert!(matches!(
            unresolved.functions[0].regions[0].kind,
            StructuredRegionKind::Fallback {
                reason: FallbackReason::UnresolvedControl
            }
        ));
    }

    #[test]
    fn falls_back_for_recursive_call_graphs() {
        let program = program(&[
            0x20, 0x00, 0xc0, // jsr $c000
            0x60, // rts
        ]);
        let analysis = structure(&program);
        assert!(matches!(
            analysis.functions[0].regions[0].kind,
            StructuredRegionKind::Fallback {
                reason: FallbackReason::RecursiveCallGraph
            }
        ));
    }

    #[test]
    fn enforces_limits_and_verifies_region_references() {
        let program = program(&[
            0xa5, 0x00, // lda $00
            0xf0, 0x05, // beq $c009
            0xa9, 0x01, // lda #1
            0x4c, 0x0b, 0xc0, // jmp $c00b
            0xa9, 0x02, // lda #2
            0x60, // rts
        ]);
        let values = analyze_values(&program, ValueAnalysisLimits::default()).expect("values");
        let recovery =
            analyze_recovery(&program, &values, RecoveryLimits::default()).expect("recovery");
        let error = structure_control_flow(
            &program,
            &values,
            &recovery,
            ControlFlowLimits {
                max_regions: 1,
                ..ControlFlowLimits::default()
            },
        )
        .expect_err("region limit");
        assert!(error[0].message().contains("structured-region limit"));

        let mut analysis =
            structure_control_flow(&program, &values, &recovery, ControlFlowLimits::default())
                .expect("structure");
        analysis.functions[0].root = RegionId(u32::MAX);
        assert!(analysis.verify(&program, &values, &recovery).is_err());
    }
}
