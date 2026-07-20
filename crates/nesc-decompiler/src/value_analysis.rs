use std::collections::{BTreeMap, BTreeSet};

use nesc_disasm::Mnemonic;

use super::{
    AccumulatorOperator, AddressSpace, AnalysisError, BasicBlock, BlockId, BlockTarget, EdgeKind,
    Flag, Function, FunctionId, HardwareEffect, MemoryOperand, Program, Provenance, Register,
    SemanticInstruction, SemanticOperation, ShiftOperator, StopReason, Terminator, ValueSource,
    ValueTarget,
};

/// Bounds for SSA construction over untrusted control-flow graphs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ValueAnalysisLimits {
    /// Maximum values across all recovered functions.
    pub max_values: usize,
    /// Maximum phi inputs across all recovered functions.
    pub max_phi_inputs: usize,
    /// Maximum fixed-point iterations per function.
    pub max_iterations: usize,
    /// Maximum recorded analysis barriers.
    pub max_barriers: usize,
}

impl Default for ValueAnalysisLimits {
    fn default() -> Self {
        Self {
            max_values: 4_000_000,
            max_phi_inputs: 2_000_000,
            max_iterations: 1_000,
            max_barriers: 1_000_000,
        }
    }
}

/// Stable identifier for a recovered SSA value.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ValueId(pub u32);

/// Precisely tracked nonvolatile memory cell.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum MemoryLocation {
    ZeroPage(u8),
    InternalRam(u16),
    PrgRam(u16),
}

/// Machine-state component represented in SSA.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum StateVariable {
    Register(Register),
    Flag(Flag),
    Memory(MemoryLocation),
    /// Version for imprecise or externally observable memory.
    MemoryEpoch,
}

/// Arithmetic or logical value operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ValueOperator {
    AddWithCarry,
    SubtractWithCarry,
    And,
    Or,
    ExclusiveOr,
    ShiftLeft,
    ShiftRight,
    RotateLeft,
    RotateRight,
    WrappingAdjust(i8),
}

/// Comparison represented by a boolean value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ComparisonPredicate {
    Equal,
    NotEqual,
    UnsignedGreaterEqual,
    UnsignedLess,
}

/// One incoming value of a phi definition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PhiInput {
    /// Predecessor block; absent for the synthetic function-entry state.
    pub predecessor: Option<BlockId>,
    /// Incoming SSA value.
    pub value: ValueId,
}

/// Why an exact value could not be retained.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UnknownReason {
    VolatileRead,
    UnknownMemory,
    CallClobber,
    StatusValue,
    StatusRestore,
    Interrupt,
}

/// Definition of one SSA value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ValueExpression {
    Input(StateVariable),
    Constant(u8),
    Phi {
        block: BlockId,
        variable: StateVariable,
        inputs: Vec<PhiInput>,
    },
    Copy(ValueId),
    Load {
        operand: MemoryOperand,
        dependencies: Vec<ValueId>,
    },
    Binary {
        operator: ValueOperator,
        left: ValueId,
        right: ValueId,
        carry: Option<ValueId>,
    },
    Compare {
        predicate: ComparisonPredicate,
        left: ValueId,
        right: ValueId,
    },
    FlagFrom {
        flag: Flag,
        mnemonic: Mnemonic,
        inputs: Vec<ValueId>,
    },
    Unknown(UnknownReason),
}

/// Strength of a recovered fact.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum Confidence {
    Proven,
    Conservative,
    Unknown,
}

/// Evidence category retained for a value or summary.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ValueEvidenceKind {
    FunctionEntry,
    MachineSemantics,
    ControlFlowJoin,
    VolatileBarrier,
    CallBarrier,
    UnresolvedControl,
}

/// Evidence supporting a recovered definition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValueEvidence {
    /// Evidence category.
    pub kind: ValueEvidenceKind,
    /// Exact instruction evidence when applicable.
    pub provenance: Option<Provenance>,
}

/// One stable SSA value and its evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValueNode {
    /// Canonical value identifier.
    pub id: ValueId,
    /// State variable defined by the value, when any.
    pub variable: Option<StateVariable>,
    /// Value definition.
    pub expression: ValueExpression,
    /// Confidence in the definition.
    pub confidence: Confidence,
    /// Supporting evidence.
    pub evidence: Vec<ValueEvidence>,
}

/// Analysis barrier category.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BarrierKind {
    VolatileRead,
    VolatileWrite,
    Dma,
    MapperWrite,
    UnknownMemoryWrite,
    Call,
    Interrupt,
    UnresolvedControl,
}

/// Explicit point where value propagation is conservatively limited.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Barrier {
    /// Barrier category.
    pub kind: BarrierKind,
    /// Owning basic block.
    pub block: BlockId,
    /// Instruction evidence when available.
    pub provenance: Option<Provenance>,
}

/// Recovered branch predicate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RecoveredPredicate {
    Comparison {
        predicate: ComparisonPredicate,
        left: ValueId,
        right: ValueId,
    },
    FlagValue {
        flag: Flag,
        value: ValueId,
        expected: bool,
    },
}

/// Evidence-scored branch condition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveredCondition {
    /// Branching block.
    pub block: BlockId,
    /// Recovered predicate.
    pub predicate: RecoveredPredicate,
    /// Confidence level.
    pub confidence: Confidence,
    /// Source instruction.
    pub provenance: Provenance,
}

/// Entry and exit SSA state for one basic block.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct BlockValueState {
    /// Merged values at block entry.
    pub entry: BTreeMap<StateVariable, ValueId>,
    /// Values after the block terminator's instruction effects.
    pub exit: BTreeMap<StateVariable, ValueId>,
}

/// Conservative recovered function interface.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FunctionSummary {
    /// Function being summarized.
    pub function: FunctionId,
    /// Entry values consumed before a proven local definition.
    pub inputs: Vec<StateVariable>,
    /// State components changed on at least one return path.
    pub outputs: Vec<StateVariable>,
    /// State components assigned or invalidated by the function.
    pub clobbers: Vec<StateVariable>,
    /// Overall inference confidence.
    pub confidence: Confidence,
    /// Evidence categories that reduced confidence.
    pub evidence: Vec<ValueEvidenceKind>,
}

/// SSA/value result for one recovered function.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FunctionValueAnalysis {
    /// Recovered function identity.
    pub function: FunctionId,
    /// Canonical values in identifier order.
    pub values: Vec<ValueNode>,
    /// Per-block entry and exit states.
    pub blocks: BTreeMap<BlockId, BlockValueState>,
    /// Recovered branch conditions.
    pub conditions: Vec<RecoveredCondition>,
    /// Explicit propagation barriers.
    pub barriers: Vec<Barrier>,
    /// Conservative interface summary.
    pub summary: FunctionSummary,
}

impl FunctionValueAnalysis {
    /// Returns a proven constant after following copies and constant phis.
    #[must_use]
    pub fn constant(&self, value: ValueId) -> Option<u8> {
        constant_from(&self.values, value, &mut BTreeSet::new())
    }
}

/// Complete value analysis for the recovered program.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValueAnalysis {
    /// Per-function results in canonical function order.
    pub functions: Vec<FunctionValueAnalysis>,
}

/// Constructs bounded SSA, value, flag, memory, and function summaries.
///
/// # Errors
///
/// Returns deterministic failures for exhausted limits or invalid value,
/// block, phi, condition, and summary references.
pub fn analyze_values(
    program: &Program,
    limits: ValueAnalysisLimits,
) -> Result<ValueAnalysis, Vec<AnalysisError>> {
    if limits.max_values == 0
        || limits.max_phi_inputs == 0
        || limits.max_iterations == 0
        || limits.max_barriers == 0
    {
        return Err(vec![AnalysisError::new(
            "value-analysis limits must permit values, phi inputs, iterations, and barriers",
        )]);
    }
    program.verify()?;
    let mut total_values = 0_usize;
    let mut total_phi_inputs = 0_usize;
    let mut total_barriers = 0_usize;
    let mut functions = Vec::with_capacity(program.functions.len());
    for function in &program.functions {
        let analysis = analyze_function(program, function, limits)?;
        total_values = total_values.saturating_add(analysis.values.len());
        total_phi_inputs = total_phi_inputs.saturating_add(
            analysis
                .values
                .iter()
                .filter_map(|value| match &value.expression {
                    ValueExpression::Phi { inputs, .. } => Some(inputs.len()),
                    _ => None,
                })
                .sum::<usize>(),
        );
        total_barriers = total_barriers.saturating_add(analysis.barriers.len());
        if total_values > limits.max_values {
            return Err(vec![AnalysisError::new(format!(
                "SSA value limit {} exceeded",
                limits.max_values
            ))]);
        }
        if total_phi_inputs > limits.max_phi_inputs {
            return Err(vec![AnalysisError::new(format!(
                "phi-input limit {} exceeded",
                limits.max_phi_inputs
            ))]);
        }
        if total_barriers > limits.max_barriers {
            return Err(vec![AnalysisError::new(format!(
                "analysis-barrier limit {} exceeded",
                limits.max_barriers
            ))]);
        }
        functions.push(analysis);
    }
    let result = ValueAnalysis { functions };
    result.verify(program)?;
    Ok(result)
}

impl ValueAnalysis {
    /// Verifies all value identifiers, phis, states, conditions, and summaries.
    ///
    /// # Errors
    ///
    /// Returns every deterministic structural failure found.
    pub fn verify(&self, program: &Program) -> Result<(), Vec<AnalysisError>> {
        let mut errors = Vec::new();
        if self.functions.len() != program.functions.len() {
            errors.push(AnalysisError::new(
                "value analysis does not contain every recovered function",
            ));
        }
        for (index, analysis) in self.functions.iter().enumerate() {
            if analysis.function.0 as usize != index {
                errors.push(AnalysisError::new(
                    "value-analysis function order is noncanonical",
                ));
            }
            let Some(function) = program.functions.get(analysis.function.0 as usize) else {
                errors.push(AnalysisError::new(
                    "value analysis references an unknown function",
                ));
                continue;
            };
            for (value_index, value) in analysis.values.iter().enumerate() {
                if value.id.0 as usize != value_index {
                    errors.push(AnalysisError::new("SSA value identifier is noncanonical"));
                }
                verify_expression(value, &analysis.values, function, program, &mut errors);
            }
            if analysis.blocks.len() != function.blocks.len()
                || function
                    .blocks
                    .iter()
                    .any(|block| !analysis.blocks.contains_key(block))
            {
                errors.push(AnalysisError::new(
                    "value analysis does not contain every function block exactly once",
                ));
            }
            for (block, state) in &analysis.blocks {
                if !function.blocks.contains(block) {
                    errors.push(AnalysisError::new(
                        "value state references a block outside its function",
                    ));
                }
                for value in state.entry.values().chain(state.exit.values()) {
                    if analysis.values.get(value.0 as usize).is_none() {
                        errors.push(AnalysisError::new(
                            "block state references an unknown SSA value",
                        ));
                    }
                }
            }
            for condition in &analysis.conditions {
                if !function.blocks.contains(&condition.block) {
                    errors.push(AnalysisError::new(
                        "recovered condition belongs to another function",
                    ));
                }
                for value in predicate_values(&condition.predicate) {
                    if analysis.values.get(value.0 as usize).is_none() {
                        errors.push(AnalysisError::new(
                            "recovered condition references an unknown SSA value",
                        ));
                    }
                }
            }
            if analysis
                .barriers
                .iter()
                .any(|barrier| !function.blocks.contains(&barrier.block))
            {
                errors.push(AnalysisError::new(
                    "analysis barrier belongs to another function",
                ));
            }
            if analysis
                .barriers
                .iter()
                .enumerate()
                .any(|(index, barrier)| analysis.barriers[..index].contains(barrier))
            {
                errors.push(AnalysisError::new("analysis contains duplicate barriers"));
            }
            if analysis.summary.function != analysis.function {
                errors.push(AnalysisError::new(
                    "function summary identity does not match value analysis",
                ));
            }
            if !strictly_sorted(&analysis.summary.inputs)
                || !strictly_sorted(&analysis.summary.outputs)
                || !strictly_sorted(&analysis.summary.clobbers)
                || !strictly_sorted(&analysis.summary.evidence)
            {
                errors.push(AnalysisError::new(
                    "function summary collections are noncanonical",
                ));
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    /// Renders deterministic SSA, condition, barrier, and summary text.
    #[must_use]
    pub fn render_text(&self) -> String {
        let mut text = format!("value-functions: {}\n", self.functions.len());
        for function in &self.functions {
            text.push_str(&format!(
                "\nfunction {:?} values={} barriers={} confidence={:?}\n",
                function.function,
                function.values.len(),
                function.barriers.len(),
                function.summary.confidence
            ));
            for value in &function.values {
                text.push_str(&format!(
                    "  v{} {:?} = {:?} [{:?}]\n",
                    value.id.0, value.variable, value.expression, value.confidence
                ));
            }
            for condition in &function.conditions {
                text.push_str(&format!(
                    "  condition prg{:02X}:${:04X} {:?} [{:?}]\n",
                    condition.block.bank,
                    condition.block.cpu_address,
                    condition.predicate,
                    condition.confidence
                ));
            }
            for barrier in &function.barriers {
                text.push_str(&format!(
                    "  barrier prg{:02X}:${:04X} {:?} {:?}\n",
                    barrier.block.bank,
                    barrier.block.cpu_address,
                    barrier.kind,
                    barrier
                        .provenance
                        .as_ref()
                        .map(|provenance| provenance.prg_offset)
                ));
            }
            text.push_str(&format!("  summary {:?}\n", function.summary));
        }
        text
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum DefinitionKey {
    Input(StateVariable),
    Constant(u8),
    Phi(BlockId, StateVariable),
    Instruction(usize, u16, StateVariable),
    Load(usize, u16),
    Barrier(BlockId, usize, StateVariable, u8),
    CallReturn(BlockId),
}

struct Builder<'a> {
    program: &'a Program,
    function: &'a Function,
    values: Vec<ValueNode>,
    definitions: BTreeMap<DefinitionKey, ValueId>,
    states: BTreeMap<BlockId, BlockValueState>,
    tracked: Vec<StateVariable>,
    inputs_read: BTreeSet<StateVariable>,
    clobbers: BTreeSet<StateVariable>,
    barriers: Vec<Barrier>,
    changed: bool,
}

fn analyze_function(
    program: &Program,
    function: &Function,
    limits: ValueAnalysisLimits,
) -> Result<FunctionValueAnalysis, Vec<AnalysisError>> {
    let tracked = tracked_variables(program, function);
    let mut builder = Builder {
        program,
        function,
        values: Vec::new(),
        definitions: BTreeMap::new(),
        states: BTreeMap::new(),
        tracked,
        inputs_read: BTreeSet::new(),
        clobbers: BTreeSet::new(),
        barriers: Vec::new(),
        changed: false,
    };
    // Unary expressions use the canonical zero value as their unused right
    // operand, and zero/one are also needed by flag recovery.
    builder.constant(0);
    builder.constant(1);
    for iteration in 0..limits.max_iterations {
        builder.changed = false;
        for block_id in &function.blocks {
            builder.process_block(*block_id)?;
            if builder.values.len() > limits.max_values {
                return Err(vec![AnalysisError::new(format!(
                    "SSA value limit {} exceeded while analyzing function `{}`",
                    limits.max_values, function.name
                ))]);
            }
            let phi_inputs = builder
                .values
                .iter()
                .filter_map(|value| match &value.expression {
                    ValueExpression::Phi { inputs, .. } => Some(inputs.len()),
                    _ => None,
                })
                .sum::<usize>();
            if phi_inputs > limits.max_phi_inputs {
                return Err(vec![AnalysisError::new(format!(
                    "phi-input limit {} exceeded while analyzing function `{}`",
                    limits.max_phi_inputs, function.name
                ))]);
            }
            if builder.barriers.len() > limits.max_barriers {
                return Err(vec![AnalysisError::new(format!(
                    "analysis-barrier limit {} exceeded while analyzing function `{}`",
                    limits.max_barriers, function.name
                ))]);
            }
        }
        if !builder.changed {
            let conditions = builder.recover_conditions();
            let summary = builder.build_summary();
            return Ok(FunctionValueAnalysis {
                function: function.id,
                values: builder.values,
                blocks: builder.states,
                conditions,
                barriers: builder.barriers,
                summary,
            });
        }
        if iteration + 1 == limits.max_iterations {
            return Err(vec![AnalysisError::new(format!(
                "value analysis for function `{}` did not converge within {} iterations",
                function.name, limits.max_iterations
            ))]);
        }
    }
    unreachable!("positive iteration limit")
}

impl Builder<'_> {
    fn process_block(&mut self, block_id: BlockId) -> Result<(), Vec<AnalysisError>> {
        let block = self.program.blocks[&block_id].clone();
        let entry = self.merge_entry(block_id)?;
        let mut state = entry.clone();
        for instruction in &block.instructions {
            self.transfer_instruction(block_id, instruction, &mut state);
        }
        let previous = self
            .states
            .insert(block_id, BlockValueState { entry, exit: state });
        if previous.as_ref() != self.states.get(&block_id) {
            self.changed = true;
        }
        self.record_control_barrier(&block);
        Ok(())
    }

    fn merge_entry(
        &mut self,
        block: BlockId,
    ) -> Result<BTreeMap<StateVariable, ValueId>, Vec<AnalysisError>> {
        let predecessors = predecessors(self.program, self.function, block);
        let mut state = BTreeMap::new();
        let tracked = self.tracked.clone();
        for variable in tracked {
            let mut inputs = Vec::new();
            if block == self.function.entry || predecessors.is_empty() {
                inputs.push(PhiInput {
                    predecessor: None,
                    value: self.input(variable),
                });
            }
            for (predecessor, kind) in &predecessors {
                let predecessor_value = self
                    .states
                    .get(predecessor)
                    .and_then(|state| state.exit.get(&variable))
                    .copied();
                let value = predecessor_value.unwrap_or_else(|| self.input(variable));
                let value = if *kind == EdgeKind::CallContinuation && call_clobbers(variable) {
                    self.clobbers.insert(variable);
                    self.call_barrier_value(block, *predecessor, variable)
                } else if *kind == EdgeKind::CallContinuation
                    && variable == StateVariable::Register(Register::StackPointer)
                {
                    self.call_return_stack_value(*predecessor, value)
                } else {
                    value
                };
                inputs.push(PhiInput {
                    predecessor: Some(*predecessor),
                    value,
                });
            }
            inputs.sort_by_key(|input| input.predecessor);
            inputs.dedup();
            let first = inputs[0].value;
            let value = if inputs.iter().all(|input| input.value == first) {
                first
            } else {
                self.define(
                    DefinitionKey::Phi(block, variable),
                    Some(variable),
                    ValueExpression::Phi {
                        block,
                        variable,
                        inputs,
                    },
                    Confidence::Proven,
                    vec![ValueEvidence {
                        kind: ValueEvidenceKind::ControlFlowJoin,
                        provenance: None,
                    }],
                )
            };
            state.insert(variable, value);
        }
        Ok(state)
    }

    fn transfer_instruction(
        &mut self,
        block: BlockId,
        instruction: &SemanticInstruction,
        state: &mut BTreeMap<StateVariable, ValueId>,
    ) {
        let mut slot = 0_u16;
        let mut semantic_inputs = Vec::new();
        let mut primary_result = None;
        for flag in &instruction.flags.reads {
            let _ = self.read(state, StateVariable::Flag(*flag));
        }
        for operation in &instruction.operations {
            match operation {
                SemanticOperation::Load {
                    destination,
                    source,
                } => {
                    let source = self.read_source(block, instruction, source, state, &mut slot);
                    semantic_inputs.push(source);
                    let variable = StateVariable::Register(*destination);
                    let value = self.instruction_value(
                        instruction,
                        &mut slot,
                        variable,
                        ValueExpression::Copy(source),
                    );
                    self.write(state, variable, value);
                    primary_result = Some(value);
                }
                SemanticOperation::Store {
                    destination,
                    source,
                } => {
                    let source = self.read(state, StateVariable::Register(*source));
                    semantic_inputs.push(source);
                    if let Some(variable) = precise_memory(destination) {
                        let value = self.instruction_value(
                            instruction,
                            &mut slot,
                            variable,
                            ValueExpression::Copy(source),
                        );
                        self.write(state, variable, value);
                        self.touch_memory_epoch(instruction, state, &mut slot);
                    } else {
                        let _ = self.read_address_dependencies(destination, state);
                        self.memory_barrier(
                            block,
                            instruction,
                            state,
                            destination,
                            &mut slot,
                            true,
                        );
                    }
                }
                SemanticOperation::Accumulate {
                    operator,
                    source,
                    carry_input,
                    ..
                } => {
                    let left = self.read(state, StateVariable::Register(Register::A));
                    let right = self.read_source(block, instruction, source, state, &mut slot);
                    let carry =
                        carry_input.then(|| self.read(state, StateVariable::Flag(Flag::Carry)));
                    semantic_inputs.extend([left, right]);
                    if let Some(carry) = carry {
                        semantic_inputs.push(carry);
                    }
                    let variable = StateVariable::Register(Register::A);
                    let expression = fold_binary(
                        &self.values,
                        accumulator_operator(*operator),
                        left,
                        right,
                        carry,
                    );
                    let value =
                        self.instruction_value(instruction, &mut slot, variable, expression);
                    self.write(state, variable, value);
                    primary_result = Some(value);
                }
                SemanticOperation::Compare { left, right } => {
                    let left = self.read(state, StateVariable::Register(*left));
                    let right = self.read_source(block, instruction, right, state, &mut slot);
                    semantic_inputs.extend([left, right]);
                }
                SemanticOperation::TestBits { source } => {
                    semantic_inputs.push(self.read(state, StateVariable::Register(Register::A)));
                    let source = self.read_source(block, instruction, source, state, &mut slot);
                    semantic_inputs.push(source);
                }
                SemanticOperation::Shift {
                    operator,
                    target,
                    carry_input,
                } => {
                    let source = self.read_target(block, instruction, target, state, &mut slot);
                    let carry =
                        carry_input.then(|| self.read(state, StateVariable::Flag(Flag::Carry)));
                    semantic_inputs.push(source);
                    if let Some(carry) = carry {
                        semantic_inputs.push(carry);
                    }
                    let expression = fold_shift(&self.values, *operator, source, carry);
                    let result =
                        self.write_target(block, instruction, target, expression, state, &mut slot);
                    primary_result = Some(result);
                }
                SemanticOperation::Adjust { target, delta } => {
                    let source = self.read_target(block, instruction, target, state, &mut slot);
                    semantic_inputs.push(source);
                    let expression = if let Some(value) =
                        constant_from(&self.values, source, &mut BTreeSet::new())
                    {
                        ValueExpression::Constant(value.wrapping_add_signed(*delta))
                    } else {
                        ValueExpression::Binary {
                            operator: ValueOperator::WrappingAdjust(*delta),
                            left: source,
                            right: self.constant(0),
                            carry: None,
                        }
                    };
                    let result =
                        self.write_target(block, instruction, target, expression, state, &mut slot);
                    primary_result = Some(result);
                }
                SemanticOperation::Transfer {
                    source,
                    destination,
                    ..
                } => {
                    let source = self.read(state, StateVariable::Register(*source));
                    semantic_inputs.push(source);
                    let variable = StateVariable::Register(*destination);
                    let value = self.instruction_value(
                        instruction,
                        &mut slot,
                        variable,
                        ValueExpression::Copy(source),
                    );
                    self.write(state, variable, value);
                    primary_result = Some(value);
                }
                SemanticOperation::SetFlag { flag, value } => {
                    let variable = StateVariable::Flag(*flag);
                    let constant = self.constant(u8::from(*value));
                    let value = self.instruction_value(
                        instruction,
                        &mut slot,
                        variable,
                        ValueExpression::Copy(constant),
                    );
                    self.write(state, variable, value);
                }
                SemanticOperation::Push { source } => {
                    let source = self.read_source(block, instruction, source, state, &mut slot);
                    semantic_inputs.push(source);
                    self.stack_adjust(instruction, state, &mut slot, -1);
                    self.touch_memory_epoch(instruction, state, &mut slot);
                    self.kill_stack_aliases(block, instruction, state, &mut slot);
                }
                SemanticOperation::Pull {
                    destination,
                    update_negative_zero: _,
                } => {
                    let _ = self.read(state, StateVariable::MemoryEpoch);
                    self.stack_adjust(instruction, state, &mut slot, 1);
                    if let Some(variable) = target_variable(destination) {
                        let value = self.instruction_value_with_confidence(
                            instruction,
                            &mut slot,
                            variable,
                            ValueExpression::Unknown(UnknownReason::UnknownMemory),
                            Confidence::Conservative,
                        );
                        self.write(state, variable, value);
                        primary_result = Some(value);
                    }
                }
                SemanticOperation::StackControl(effect) => {
                    use super::StackControl::{
                        PopInterruptFrame, PopReturnAddress, PushInterruptFrame, PushReturnAddress,
                    };
                    match effect {
                        PushReturnAddress => {
                            self.stack_adjust(instruction, state, &mut slot, -2);
                            self.touch_memory_epoch(instruction, state, &mut slot);
                        }
                        PopReturnAddress => self.stack_adjust(instruction, state, &mut slot, 2),
                        PushInterruptFrame => {
                            self.stack_adjust(instruction, state, &mut slot, -3);
                            self.touch_memory_epoch(instruction, state, &mut slot);
                            self.kill_stack_aliases(block, instruction, state, &mut slot);
                            self.record_barrier(
                                BarrierKind::Interrupt,
                                block,
                                Some(instruction.provenance.clone()),
                            );
                        }
                        PopInterruptFrame => {
                            self.stack_adjust(instruction, state, &mut slot, 3);
                        }
                    }
                    if matches!(effect, PushReturnAddress) {
                        self.kill_stack_aliases(block, instruction, state, &mut slot);
                    }
                }
                SemanticOperation::MapperWrite { .. } => {}
                SemanticOperation::NoOperation => {}
            }
        }
        self.update_written_flags(
            instruction,
            state,
            &semantic_inputs,
            primary_result,
            &mut slot,
        );
    }

    fn read_source(
        &mut self,
        block: BlockId,
        instruction: &SemanticInstruction,
        source: &ValueSource,
        state: &mut BTreeMap<StateVariable, ValueId>,
        slot: &mut u16,
    ) -> ValueId {
        match source {
            ValueSource::Register(register) => self.read(state, StateVariable::Register(*register)),
            ValueSource::Immediate(value) => self.constant(*value),
            ValueSource::Status => self.unknown_status(instruction, slot),
            ValueSource::Memory(memory) => {
                if let Some(variable) = precise_memory(memory) {
                    self.read(state, variable)
                } else {
                    let dependencies = self.read_address_dependencies(memory, state);
                    if memory.volatile {
                        self.record_barrier(
                            BarrierKind::VolatileRead,
                            block,
                            Some(instruction.provenance.clone()),
                        );
                    }
                    let key = DefinitionKey::Load(instruction.provenance.prg_offset, *slot);
                    *slot = slot.saturating_add(1);
                    self.define(
                        key,
                        None,
                        if memory.volatile {
                            ValueExpression::Unknown(UnknownReason::VolatileRead)
                        } else {
                            ValueExpression::Load {
                                operand: memory.clone(),
                                dependencies,
                            }
                        },
                        if memory.volatile {
                            Confidence::Conservative
                        } else {
                            Confidence::Proven
                        },
                        vec![ValueEvidence {
                            kind: if memory.volatile {
                                ValueEvidenceKind::VolatileBarrier
                            } else {
                                ValueEvidenceKind::MachineSemantics
                            },
                            provenance: Some(instruction.provenance.clone()),
                        }],
                    )
                }
            }
        }
    }

    fn read_target(
        &mut self,
        block: BlockId,
        instruction: &SemanticInstruction,
        target: &ValueTarget,
        state: &mut BTreeMap<StateVariable, ValueId>,
        slot: &mut u16,
    ) -> ValueId {
        match target {
            ValueTarget::Register(register) => self.read(state, StateVariable::Register(*register)),
            ValueTarget::Status => self.unknown_status(instruction, slot),
            ValueTarget::Memory(memory) => self.read_source(
                block,
                instruction,
                &ValueSource::Memory(memory.clone()),
                state,
                slot,
            ),
        }
    }

    fn read_address_dependencies(
        &mut self,
        memory: &MemoryOperand,
        state: &BTreeMap<StateVariable, ValueId>,
    ) -> Vec<ValueId> {
        let mut dependencies = Vec::new();
        if let Some(index) = memory.index {
            dependencies.push(self.read(state, StateVariable::Register(index)));
        }
        dependencies.push(self.read(state, StateVariable::MemoryEpoch));
        dependencies
    }

    fn write_target(
        &mut self,
        block: BlockId,
        instruction: &SemanticInstruction,
        target: &ValueTarget,
        expression: ValueExpression,
        state: &mut BTreeMap<StateVariable, ValueId>,
        slot: &mut u16,
    ) -> ValueId {
        match target {
            ValueTarget::Register(register) => {
                let variable = StateVariable::Register(*register);
                let value = self.instruction_value(instruction, slot, variable, expression);
                self.write(state, variable, value);
                value
            }
            ValueTarget::Memory(memory) => {
                if let Some(variable) = precise_memory(memory) {
                    let value = self.instruction_value(instruction, slot, variable, expression);
                    self.write(state, variable, value);
                    self.touch_memory_epoch(instruction, state, slot);
                    value
                } else {
                    let value = self.define(
                        DefinitionKey::Load(instruction.provenance.prg_offset, *slot),
                        None,
                        expression,
                        Confidence::Conservative,
                        machine_evidence(instruction),
                    );
                    *slot = slot.saturating_add(1);
                    self.memory_barrier(block, instruction, state, memory, slot, true);
                    value
                }
            }
            ValueTarget::Status => self.unknown_status(instruction, slot),
        }
    }

    fn update_written_flags(
        &mut self,
        instruction: &SemanticInstruction,
        state: &mut BTreeMap<StateVariable, ValueId>,
        inputs: &[ValueId],
        result: Option<ValueId>,
        slot: &mut u16,
    ) {
        for flag in &instruction.flags.writes {
            let variable = StateVariable::Flag(*flag);
            if matches!(
                instruction.mnemonic,
                Mnemonic::Clc
                    | Mnemonic::Cld
                    | Mnemonic::Cli
                    | Mnemonic::Clv
                    | Mnemonic::Sec
                    | Mnemonic::Sed
                    | Mnemonic::Sei
            ) {
                continue;
            }
            let expression = if matches!(instruction.mnemonic, Mnemonic::Plp | Mnemonic::Rti) {
                ValueExpression::Unknown(if instruction.mnemonic == Mnemonic::Rti {
                    UnknownReason::Interrupt
                } else {
                    UnknownReason::StatusRestore
                })
            } else {
                flag_expression(&self.values, instruction.mnemonic, *flag, inputs, result)
            };
            let confidence = if matches!(
                expression,
                ValueExpression::Unknown(UnknownReason::StatusRestore | UnknownReason::Interrupt)
            ) {
                Confidence::Conservative
            } else {
                Confidence::Proven
            };
            let value = self.instruction_value_with_confidence(
                instruction,
                slot,
                variable,
                expression,
                confidence,
            );
            self.write(state, variable, value);
        }
    }

    fn merge_phi_update(
        &mut self,
        id: ValueId,
        expression: ValueExpression,
        confidence: Confidence,
        evidence: Vec<ValueEvidence>,
    ) {
        let node = &mut self.values[id.0 as usize];
        if node.expression != expression
            || node.confidence != confidence
            || node.evidence != evidence
        {
            node.expression = expression;
            node.confidence = confidence;
            node.evidence = evidence;
            self.changed = true;
        }
    }

    fn define(
        &mut self,
        key: DefinitionKey,
        variable: Option<StateVariable>,
        expression: ValueExpression,
        confidence: Confidence,
        evidence: Vec<ValueEvidence>,
    ) -> ValueId {
        if let Some(id) = self.definitions.get(&key).copied() {
            self.merge_phi_update(id, expression, confidence, evidence);
            return id;
        }
        let id = ValueId(u32::try_from(self.values.len()).unwrap_or(u32::MAX));
        self.values.push(ValueNode {
            id,
            variable,
            expression,
            confidence,
            evidence,
        });
        self.definitions.insert(key, id);
        self.changed = true;
        id
    }

    fn input(&mut self, variable: StateVariable) -> ValueId {
        self.define(
            DefinitionKey::Input(variable),
            Some(variable),
            ValueExpression::Input(variable),
            Confidence::Unknown,
            vec![ValueEvidence {
                kind: ValueEvidenceKind::FunctionEntry,
                provenance: None,
            }],
        )
    }

    fn constant(&mut self, value: u8) -> ValueId {
        self.define(
            DefinitionKey::Constant(value),
            None,
            ValueExpression::Constant(value),
            Confidence::Proven,
            Vec::new(),
        )
    }

    fn instruction_value(
        &mut self,
        instruction: &SemanticInstruction,
        slot: &mut u16,
        variable: StateVariable,
        expression: ValueExpression,
    ) -> ValueId {
        self.instruction_value_with_confidence(
            instruction,
            slot,
            variable,
            expression,
            Confidence::Proven,
        )
    }

    fn instruction_value_with_confidence(
        &mut self,
        instruction: &SemanticInstruction,
        slot: &mut u16,
        variable: StateVariable,
        expression: ValueExpression,
        confidence: Confidence,
    ) -> ValueId {
        let key = DefinitionKey::Instruction(instruction.provenance.prg_offset, *slot, variable);
        *slot = slot.saturating_add(1);
        self.define(
            key,
            Some(variable),
            expression,
            confidence,
            machine_evidence(instruction),
        )
    }

    fn call_barrier_value(
        &mut self,
        block: BlockId,
        predecessor: BlockId,
        variable: StateVariable,
    ) -> ValueId {
        let provenance = self.program.blocks[&predecessor]
            .instructions
            .last()
            .map(|instruction| instruction.provenance.clone());
        self.define(
            DefinitionKey::Barrier(block, predecessor.prg_offset, variable, 1),
            Some(variable),
            ValueExpression::Unknown(UnknownReason::CallClobber),
            Confidence::Conservative,
            vec![ValueEvidence {
                kind: ValueEvidenceKind::CallBarrier,
                provenance,
            }],
        )
    }

    fn call_return_stack_value(&mut self, call_block: BlockId, pushed: ValueId) -> ValueId {
        let expression =
            if let Some(value) = constant_from(&self.values, pushed, &mut BTreeSet::new()) {
                ValueExpression::Constant(value.wrapping_add(2))
            } else {
                ValueExpression::Binary {
                    operator: ValueOperator::WrappingAdjust(2),
                    left: pushed,
                    right: self.constant(0),
                    carry: None,
                }
            };
        let provenance = self.program.blocks[&call_block]
            .instructions
            .last()
            .map(|instruction| instruction.provenance.clone());
        self.define(
            DefinitionKey::CallReturn(call_block),
            Some(StateVariable::Register(Register::StackPointer)),
            expression,
            Confidence::Proven,
            vec![ValueEvidence {
                kind: ValueEvidenceKind::MachineSemantics,
                provenance,
            }],
        )
    }

    fn read(
        &mut self,
        state: &BTreeMap<StateVariable, ValueId>,
        variable: StateVariable,
    ) -> ValueId {
        let value = match state.get(&variable).copied() {
            Some(value) => value,
            None => self.input(variable),
        };
        if depends_on_input(&self.values, value, variable, &mut BTreeSet::new()) {
            self.inputs_read.insert(variable);
        }
        value
    }

    fn write(
        &mut self,
        state: &mut BTreeMap<StateVariable, ValueId>,
        variable: StateVariable,
        value: ValueId,
    ) {
        state.insert(variable, value);
        self.clobbers.insert(variable);
    }

    fn stack_adjust(
        &mut self,
        instruction: &SemanticInstruction,
        state: &mut BTreeMap<StateVariable, ValueId>,
        slot: &mut u16,
        delta: i8,
    ) {
        let variable = StateVariable::Register(Register::StackPointer);
        let source = self.read(state, variable);
        let expression =
            if let Some(value) = constant_from(&self.values, source, &mut BTreeSet::new()) {
                ValueExpression::Constant(value.wrapping_add_signed(delta))
            } else {
                ValueExpression::Binary {
                    operator: ValueOperator::WrappingAdjust(delta),
                    left: source,
                    right: self.constant(0),
                    carry: None,
                }
            };
        let value = self.instruction_value(instruction, slot, variable, expression);
        self.write(state, variable, value);
    }

    fn unknown_status(&mut self, instruction: &SemanticInstruction, slot: &mut u16) -> ValueId {
        let key = DefinitionKey::Load(instruction.provenance.prg_offset, *slot);
        *slot = slot.saturating_add(1);
        self.define(
            key,
            None,
            ValueExpression::Unknown(UnknownReason::StatusValue),
            Confidence::Conservative,
            machine_evidence(instruction),
        )
    }

    fn touch_memory_epoch(
        &mut self,
        instruction: &SemanticInstruction,
        state: &mut BTreeMap<StateVariable, ValueId>,
        slot: &mut u16,
    ) {
        let variable = StateVariable::MemoryEpoch;
        let value = self.instruction_value_with_confidence(
            instruction,
            slot,
            variable,
            ValueExpression::Unknown(UnknownReason::UnknownMemory),
            Confidence::Conservative,
        );
        self.write(state, variable, value);
    }

    fn memory_barrier(
        &mut self,
        block: BlockId,
        instruction: &SemanticInstruction,
        state: &mut BTreeMap<StateVariable, ValueId>,
        memory: &MemoryOperand,
        slot: &mut u16,
        write: bool,
    ) {
        let kind = match memory.hardware_effect {
            Some(HardwareEffect::Dma) => BarrierKind::Dma,
            Some(HardwareEffect::Mapper) => BarrierKind::MapperWrite,
            _ if memory.volatile && write => BarrierKind::VolatileWrite,
            _ => BarrierKind::UnknownMemoryWrite,
        };
        if matches!(
            memory.address_space,
            AddressSpace::ZeroPage
                | AddressSpace::InternalRam
                | AddressSpace::PrgRam
                | AddressSpace::Unknown
        ) {
            self.kill_memory(block, instruction, state, slot, kind);
        } else {
            let variable = StateVariable::MemoryEpoch;
            let value = self.instruction_value_with_confidence(
                instruction,
                slot,
                variable,
                ValueExpression::Unknown(UnknownReason::UnknownMemory),
                Confidence::Conservative,
            );
            self.write(state, variable, value);
            self.record_barrier(kind, block, Some(instruction.provenance.clone()));
        }
    }

    fn kill_memory(
        &mut self,
        block: BlockId,
        instruction: &SemanticInstruction,
        state: &mut BTreeMap<StateVariable, ValueId>,
        slot: &mut u16,
        kind: BarrierKind,
    ) {
        let variables = self
            .tracked
            .iter()
            .copied()
            .filter(|variable| {
                matches!(
                    variable,
                    StateVariable::Memory(_) | StateVariable::MemoryEpoch
                )
            })
            .collect::<Vec<_>>();
        for variable in variables {
            let value = self.instruction_value_with_confidence(
                instruction,
                slot,
                variable,
                ValueExpression::Unknown(UnknownReason::UnknownMemory),
                Confidence::Conservative,
            );
            self.write(state, variable, value);
        }
        self.record_barrier(kind, block, Some(instruction.provenance.clone()));
    }

    fn kill_stack_aliases(
        &mut self,
        block: BlockId,
        instruction: &SemanticInstruction,
        state: &mut BTreeMap<StateVariable, ValueId>,
        slot: &mut u16,
    ) {
        let variables = self
            .tracked
            .iter()
            .copied()
            .filter(|variable| {
                matches!(
                    variable,
                    StateVariable::Memory(MemoryLocation::InternalRam(0x0100..=0x01ff))
                )
            })
            .collect::<Vec<_>>();
        if variables.is_empty() {
            return;
        }
        for variable in variables {
            let value = self.instruction_value_with_confidence(
                instruction,
                slot,
                variable,
                ValueExpression::Unknown(UnknownReason::UnknownMemory),
                Confidence::Conservative,
            );
            self.write(state, variable, value);
        }
        self.record_barrier(
            BarrierKind::UnknownMemoryWrite,
            block,
            Some(instruction.provenance.clone()),
        );
    }

    fn record_barrier(
        &mut self,
        kind: BarrierKind,
        block: BlockId,
        provenance: Option<Provenance>,
    ) {
        let barrier = Barrier {
            kind,
            block,
            provenance,
        };
        if !self.barriers.contains(&barrier) {
            self.barriers.push(barrier);
        }
    }

    fn record_control_barrier(&mut self, block: &BasicBlock) {
        let provenance = block
            .instructions
            .last()
            .map(|instruction| instruction.provenance.clone());
        if matches!(block.terminator, Terminator::Call { .. }) {
            self.record_barrier(BarrierKind::Call, block.id, provenance.clone());
        }
        match &block.terminator {
            Terminator::Interrupt | Terminator::ReturnFromInterrupt => {
                self.record_barrier(BarrierKind::Interrupt, block.id, provenance);
            }
            Terminator::Stop(StopReason::IndirectJump { .. }) => {
                self.record_barrier(BarrierKind::UnresolvedControl, block.id, provenance);
            }
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
            } => self.record_barrier(BarrierKind::UnresolvedControl, block.id, provenance),
            Terminator::Fallthrough(BlockTarget::Resolved(_))
            | Terminator::Jump(BlockTarget::Resolved(_))
            | Terminator::Branch { .. }
            | Terminator::Call { .. }
            | Terminator::Return
            | Terminator::Stop(StopReason::MissingInstruction { .. }) => {}
        }
    }

    fn recover_conditions(&self) -> Vec<RecoveredCondition> {
        let mut conditions = Vec::new();
        for block_id in &self.function.blocks {
            let block = &self.program.blocks[block_id];
            let Terminator::Branch { condition, .. } = block.terminator else {
                continue;
            };
            let (flag, expected) = branch_flag(condition);
            let Some(state) = self.states.get(block_id) else {
                continue;
            };
            let Some(value) = state.exit.get(&StateVariable::Flag(flag)).copied() else {
                continue;
            };
            let (predicate, confidence) = recover_predicate(&self.values, flag, value, expected);
            conditions.push(RecoveredCondition {
                block: *block_id,
                predicate,
                confidence,
                provenance: block
                    .instructions
                    .last()
                    .expect("nonempty block")
                    .provenance
                    .clone(),
            });
        }
        conditions
    }

    fn build_summary(&self) -> FunctionSummary {
        let mut outputs = BTreeSet::new();
        for block_id in &self.function.blocks {
            let block = &self.program.blocks[block_id];
            if !matches!(
                block.terminator,
                Terminator::Return | Terminator::ReturnFromInterrupt
            ) {
                continue;
            }
            if let Some(state) = self.states.get(block_id) {
                for (variable, value) in &state.exit {
                    let input = self.definitions.get(&DefinitionKey::Input(*variable));
                    if input != Some(value) {
                        outputs.insert(*variable);
                    }
                }
            }
        }
        let confidence = if self
            .barriers
            .iter()
            .any(|barrier| barrier.kind == BarrierKind::UnresolvedControl)
        {
            Confidence::Unknown
        } else if self.barriers.is_empty() {
            Confidence::Proven
        } else {
            Confidence::Conservative
        };
        let mut evidence = self
            .barriers
            .iter()
            .map(|barrier| match barrier.kind {
                BarrierKind::Call => ValueEvidenceKind::CallBarrier,
                BarrierKind::UnresolvedControl => ValueEvidenceKind::UnresolvedControl,
                _ => ValueEvidenceKind::VolatileBarrier,
            })
            .collect::<Vec<_>>();
        evidence.sort();
        evidence.dedup();
        FunctionSummary {
            function: self.function.id,
            inputs: self.inputs_read.iter().copied().collect(),
            outputs: outputs.into_iter().collect(),
            clobbers: self.clobbers.iter().copied().collect(),
            confidence,
            evidence,
        }
    }
}

fn tracked_variables(program: &Program, function: &Function) -> Vec<StateVariable> {
    let mut tracked = BTreeSet::from([
        StateVariable::Register(Register::A),
        StateVariable::Register(Register::X),
        StateVariable::Register(Register::Y),
        StateVariable::Register(Register::StackPointer),
        StateVariable::Flag(Flag::Carry),
        StateVariable::Flag(Flag::Zero),
        StateVariable::Flag(Flag::InterruptDisable),
        StateVariable::Flag(Flag::Decimal),
        StateVariable::Flag(Flag::Break),
        StateVariable::Flag(Flag::Overflow),
        StateVariable::Flag(Flag::Negative),
        StateVariable::MemoryEpoch,
    ]);
    for block in &function.blocks {
        for instruction in &program.blocks[block].instructions {
            for operation in &instruction.operations {
                for memory in operation_memory(operation) {
                    if let Some(variable) = precise_memory(memory) {
                        tracked.insert(variable);
                    }
                }
            }
        }
    }
    tracked.into_iter().collect()
}

fn operation_memory(operation: &SemanticOperation) -> Vec<&MemoryOperand> {
    let mut memory = Vec::new();
    match operation {
        SemanticOperation::Load { source: value, .. }
        | SemanticOperation::Accumulate { source: value, .. }
        | SemanticOperation::TestBits { source: value }
        | SemanticOperation::Push { source: value } => {
            if let ValueSource::Memory(operand) = value {
                memory.push(operand);
            }
        }
        SemanticOperation::Compare { right, .. } => {
            if let ValueSource::Memory(operand) = right {
                memory.push(operand);
            }
        }
        SemanticOperation::Store { destination, .. } => memory.push(destination),
        SemanticOperation::Shift { target: value, .. }
        | SemanticOperation::Adjust { target: value, .. }
        | SemanticOperation::Pull {
            destination: value, ..
        } => {
            if let ValueTarget::Memory(operand) = value {
                memory.push(operand);
            }
        }
        SemanticOperation::Transfer { .. }
        | SemanticOperation::SetFlag { .. }
        | SemanticOperation::StackControl(_)
        | SemanticOperation::MapperWrite { .. }
        | SemanticOperation::NoOperation => {}
    }
    memory
}

fn precise_memory(memory: &MemoryOperand) -> Option<StateVariable> {
    if memory.volatile || memory.index.is_some() || memory.indirect {
        return None;
    }
    let location = match memory.address_space {
        AddressSpace::ZeroPage => MemoryLocation::ZeroPage(memory.encoded as u8),
        AddressSpace::InternalRam => {
            let canonical = memory.encoded & 0x07ff;
            if canonical <= 0x00ff {
                MemoryLocation::ZeroPage(canonical as u8)
            } else {
                MemoryLocation::InternalRam(canonical)
            }
        }
        AddressSpace::PrgRam => MemoryLocation::PrgRam(memory.encoded),
        _ => return None,
    };
    Some(StateVariable::Memory(location))
}

fn target_variable(target: &ValueTarget) -> Option<StateVariable> {
    match target {
        ValueTarget::Register(register) => Some(StateVariable::Register(*register)),
        ValueTarget::Memory(memory) => precise_memory(memory),
        ValueTarget::Status => None,
    }
}

fn predecessors(
    program: &Program,
    function: &Function,
    block: BlockId,
) -> Vec<(BlockId, EdgeKind)> {
    let mut predecessors = program
        .edges
        .iter()
        .filter(|edge| {
            edge.target == Some(block)
                && edge.kind != EdgeKind::CallTarget
                && function.blocks.contains(&edge.source)
        })
        .map(|edge| (edge.source, edge.kind))
        .collect::<Vec<_>>();
    predecessors.sort_by_key(|(block, kind)| (*block, edge_kind_rank(*kind)));
    predecessors.dedup();
    predecessors
}

fn edge_kind_rank(kind: EdgeKind) -> u8 {
    match kind {
        EdgeKind::Fallthrough => 0,
        EdgeKind::BranchTaken => 1,
        EdgeKind::BranchNotTaken => 2,
        EdgeKind::CallTarget => 3,
        EdgeKind::CallContinuation => 4,
        EdgeKind::Jump => 5,
    }
}

fn call_clobbers(variable: StateVariable) -> bool {
    !matches!(variable, StateVariable::Register(Register::StackPointer))
}

fn machine_evidence(instruction: &SemanticInstruction) -> Vec<ValueEvidence> {
    vec![ValueEvidence {
        kind: ValueEvidenceKind::MachineSemantics,
        provenance: Some(instruction.provenance.clone()),
    }]
}

fn accumulator_operator(operator: AccumulatorOperator) -> ValueOperator {
    match operator {
        AccumulatorOperator::AddWithCarry => ValueOperator::AddWithCarry,
        AccumulatorOperator::SubtractWithCarry => ValueOperator::SubtractWithCarry,
        AccumulatorOperator::And => ValueOperator::And,
        AccumulatorOperator::Or => ValueOperator::Or,
        AccumulatorOperator::ExclusiveOr => ValueOperator::ExclusiveOr,
    }
}

fn fold_binary(
    values: &[ValueNode],
    operator: ValueOperator,
    left: ValueId,
    right: ValueId,
    carry: Option<ValueId>,
) -> ValueExpression {
    let known_left = constant_from(values, left, &mut BTreeSet::new());
    let known_right = constant_from(values, right, &mut BTreeSet::new());
    let known_carry = carry.and_then(|value| constant_from(values, value, &mut BTreeSet::new()));
    if let (Some(left_constant), Some(right_constant)) = (known_left, known_right) {
        let value = match operator {
            ValueOperator::AddWithCarry if carry.is_none() || known_carry.is_some() => {
                left_constant
                    .wrapping_add(right_constant)
                    .wrapping_add(known_carry.unwrap_or(0) & 1)
            }
            ValueOperator::SubtractWithCarry if carry.is_none() || known_carry.is_some() => {
                left_constant
                    .wrapping_sub(right_constant)
                    .wrapping_sub(1_u8.wrapping_sub(known_carry.unwrap_or(1) & 1))
            }
            ValueOperator::And => left_constant & right_constant,
            ValueOperator::Or => left_constant | right_constant,
            ValueOperator::ExclusiveOr => left_constant ^ right_constant,
            _ => {
                return ValueExpression::Binary {
                    operator,
                    left,
                    right,
                    carry,
                };
            }
        };
        return ValueExpression::Constant(value);
    }
    ValueExpression::Binary {
        operator,
        left,
        right,
        carry,
    }
}

fn fold_shift(
    values: &[ValueNode],
    operator: ShiftOperator,
    source: ValueId,
    carry: Option<ValueId>,
) -> ValueExpression {
    let known_source = constant_from(values, source, &mut BTreeSet::new());
    let known_carry = carry.and_then(|value| constant_from(values, value, &mut BTreeSet::new()));
    if let Some(source_value) = known_source {
        let value = match operator {
            ShiftOperator::ArithmeticLeft => Some(source_value << 1),
            ShiftOperator::LogicalRight => Some(source_value >> 1),
            ShiftOperator::RotateLeft => known_carry.map(|carry| (source_value << 1) | (carry & 1)),
            ShiftOperator::RotateRight => {
                known_carry.map(|carry| (source_value >> 1) | ((carry & 1) << 7))
            }
        };
        if let Some(value) = value {
            return ValueExpression::Constant(value);
        }
    }
    ValueExpression::Binary {
        operator: match operator {
            ShiftOperator::ArithmeticLeft => ValueOperator::ShiftLeft,
            ShiftOperator::LogicalRight => ValueOperator::ShiftRight,
            ShiftOperator::RotateLeft => ValueOperator::RotateLeft,
            ShiftOperator::RotateRight => ValueOperator::RotateRight,
        },
        left: source,
        right: ValueId(0),
        carry,
    }
}

fn flag_expression(
    values: &[ValueNode],
    mnemonic: Mnemonic,
    flag: Flag,
    inputs: &[ValueId],
    result: Option<ValueId>,
) -> ValueExpression {
    if matches!(mnemonic, Mnemonic::Cmp | Mnemonic::Cpx | Mnemonic::Cpy) && inputs.len() >= 2 {
        return match flag {
            Flag::Zero => ValueExpression::Compare {
                predicate: ComparisonPredicate::Equal,
                left: inputs[0],
                right: inputs[1],
            },
            Flag::Carry => ValueExpression::Compare {
                predicate: ComparisonPredicate::UnsignedGreaterEqual,
                left: inputs[0],
                right: inputs[1],
            },
            _ => ValueExpression::FlagFrom {
                flag,
                mnemonic,
                inputs: inputs.to_vec(),
            },
        };
    }
    if flag == Flag::Zero
        && let Some(result) = result
        && let Some(zero) = find_constant(values, 0)
    {
        return fold_compare(values, ComparisonPredicate::Equal, result, zero);
    }
    if let Some(value) = fold_known_flag(values, mnemonic, flag, inputs, result) {
        return ValueExpression::Constant(u8::from(value));
    }
    ValueExpression::FlagFrom {
        flag,
        mnemonic,
        inputs: inputs.to_vec(),
    }
}

fn fold_compare(
    values: &[ValueNode],
    predicate: ComparisonPredicate,
    left: ValueId,
    right: ValueId,
) -> ValueExpression {
    let left_constant = constant_from(values, left, &mut BTreeSet::new());
    let right_constant = constant_from(values, right, &mut BTreeSet::new());
    if let (Some(left), Some(right)) = (left_constant, right_constant) {
        let result = match predicate {
            ComparisonPredicate::Equal => left == right,
            ComparisonPredicate::NotEqual => left != right,
            ComparisonPredicate::UnsignedGreaterEqual => left >= right,
            ComparisonPredicate::UnsignedLess => left < right,
        };
        ValueExpression::Constant(u8::from(result))
    } else {
        ValueExpression::Compare {
            predicate,
            left,
            right,
        }
    }
}

fn fold_known_flag(
    values: &[ValueNode],
    mnemonic: Mnemonic,
    flag: Flag,
    inputs: &[ValueId],
    result: Option<ValueId>,
) -> Option<bool> {
    let result_value = result.and_then(|value| constant_from(values, value, &mut BTreeSet::new()));
    match flag {
        Flag::Zero => result_value.map(|value| value == 0),
        Flag::Negative => result_value.map(|value| value & 0x80 != 0),
        Flag::Carry if matches!(mnemonic, Mnemonic::Adc | Mnemonic::Sbc) && inputs.len() >= 3 => {
            let left = constant_from(values, inputs[0], &mut BTreeSet::new())?;
            let right = constant_from(values, inputs[1], &mut BTreeSet::new())?;
            let carry = constant_from(values, inputs[2], &mut BTreeSet::new())? & 1;
            Some(if mnemonic == Mnemonic::Adc {
                u16::from(left) + u16::from(right) + u16::from(carry) > 0xff
            } else {
                u16::from(left) >= u16::from(right) + u16::from(1 - carry)
            })
        }
        Flag::Carry
            if matches!(
                mnemonic,
                Mnemonic::Asl | Mnemonic::Lsr | Mnemonic::Rol | Mnemonic::Ror
            ) =>
        {
            let source = constant_from(values, inputs[0], &mut BTreeSet::new())?;
            Some(if matches!(mnemonic, Mnemonic::Asl | Mnemonic::Rol) {
                source & 0x80 != 0
            } else {
                source & 1 != 0
            })
        }
        _ => None,
    }
}

fn find_constant(values: &[ValueNode], constant: u8) -> Option<ValueId> {
    values
        .iter()
        .find(|value| value.expression == ValueExpression::Constant(constant))
        .map(|value| value.id)
}

fn constant_from(
    values: &[ValueNode],
    id: ValueId,
    visiting: &mut BTreeSet<ValueId>,
) -> Option<u8> {
    if !visiting.insert(id) {
        return None;
    }
    let result = match &values.get(id.0 as usize)?.expression {
        ValueExpression::Constant(value) => Some(*value),
        ValueExpression::Copy(source) => constant_from(values, *source, visiting),
        ValueExpression::Phi { inputs, .. } => {
            let mut inputs = inputs.iter();
            let first = constant_from(values, inputs.next()?.value, visiting)?;
            inputs
                .all(|input| constant_from(values, input.value, visiting) == Some(first))
                .then_some(first)
        }
        _ => None,
    };
    visiting.remove(&id);
    result
}

fn depends_on_input(
    values: &[ValueNode],
    id: ValueId,
    variable: StateVariable,
    visiting: &mut BTreeSet<ValueId>,
) -> bool {
    if !visiting.insert(id) {
        return false;
    }
    let depends = match values.get(id.0 as usize).map(|value| &value.expression) {
        Some(ValueExpression::Input(input)) => *input == variable,
        Some(ValueExpression::Copy(source)) => {
            depends_on_input(values, *source, variable, visiting)
        }
        Some(ValueExpression::Phi { inputs, .. }) => inputs
            .iter()
            .any(|input| depends_on_input(values, input.value, variable, visiting)),
        _ => false,
    };
    visiting.remove(&id);
    depends
}

fn recover_predicate(
    values: &[ValueNode],
    flag: Flag,
    value: ValueId,
    expected: bool,
) -> (RecoveredPredicate, Confidence) {
    if let Some(ValueNode {
        expression:
            ValueExpression::Compare {
                predicate,
                left,
                right,
            },
        ..
    }) = values.get(value.0 as usize)
    {
        return (
            RecoveredPredicate::Comparison {
                predicate: if expected {
                    *predicate
                } else {
                    invert_comparison(*predicate)
                },
                left: *left,
                right: *right,
            },
            Confidence::Proven,
        );
    }
    (
        RecoveredPredicate::FlagValue {
            flag,
            value,
            expected,
        },
        Confidence::Conservative,
    )
}

fn invert_comparison(predicate: ComparisonPredicate) -> ComparisonPredicate {
    match predicate {
        ComparisonPredicate::Equal => ComparisonPredicate::NotEqual,
        ComparisonPredicate::NotEqual => ComparisonPredicate::Equal,
        ComparisonPredicate::UnsignedGreaterEqual => ComparisonPredicate::UnsignedLess,
        ComparisonPredicate::UnsignedLess => ComparisonPredicate::UnsignedGreaterEqual,
    }
}

fn branch_flag(condition: super::BranchCondition) -> (Flag, bool) {
    use super::BranchCondition::{
        CarryClear, CarrySet, Equal, Minus, NotEqual, OverflowClear, OverflowSet, Plus,
    };
    match condition {
        CarryClear => (Flag::Carry, false),
        CarrySet => (Flag::Carry, true),
        Equal => (Flag::Zero, true),
        NotEqual => (Flag::Zero, false),
        Minus => (Flag::Negative, true),
        Plus => (Flag::Negative, false),
        OverflowClear => (Flag::Overflow, false),
        OverflowSet => (Flag::Overflow, true),
    }
}

fn verify_expression(
    node: &ValueNode,
    values: &[ValueNode],
    function: &Function,
    program: &Program,
    errors: &mut Vec<AnalysisError>,
) {
    let referenced = expression_values(&node.expression);
    if referenced
        .iter()
        .any(|value| values.get(value.0 as usize).is_none())
    {
        errors.push(AnalysisError::new(
            "SSA expression references an unknown value",
        ));
    }
    if let ValueExpression::Phi {
        block,
        variable,
        inputs,
    } = &node.expression
    {
        if node.variable != Some(*variable) {
            errors.push(AnalysisError::new(
                "phi variable does not match its value definition",
            ));
        }
        if !function.blocks.contains(block) {
            errors.push(AnalysisError::new(
                "phi belongs to a block outside its function",
            ));
        }
        if inputs.is_empty() {
            errors.push(AnalysisError::new("phi has no incoming values"));
        }
        if inputs.iter().any(|input| {
            input
                .predecessor
                .is_some_and(|predecessor| !function.blocks.contains(&predecessor))
        }) {
            errors.push(AnalysisError::new(
                "phi predecessor belongs to another function",
            ));
        }
        if inputs.iter().enumerate().any(|(index, input)| {
            inputs[..index]
                .iter()
                .any(|prior| prior.predecessor == input.predecessor)
        }) {
            errors.push(AnalysisError::new("phi contains duplicate inputs"));
        }
        let actual_predecessors = predecessors(program, function, *block)
            .into_iter()
            .map(|(predecessor, _)| predecessor)
            .collect::<BTreeSet<_>>();
        if inputs.iter().any(|input| {
            input
                .predecessor
                .is_some_and(|predecessor| !actual_predecessors.contains(&predecessor))
        }) {
            errors.push(AnalysisError::new(
                "phi input is not a control-flow predecessor",
            ));
        }
        if inputs.iter().any(|input| input.predecessor.is_none())
            && *block != function.entry
            && !actual_predecessors.is_empty()
        {
            errors.push(AnalysisError::new(
                "phi has a synthetic input outside a function entry",
            ));
        }
    }
}

fn strictly_sorted<T: Ord>(values: &[T]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

fn expression_values(expression: &ValueExpression) -> Vec<ValueId> {
    match expression {
        ValueExpression::Phi { inputs, .. } => inputs.iter().map(|input| input.value).collect(),
        ValueExpression::Copy(value) => vec![*value],
        ValueExpression::Binary {
            left, right, carry, ..
        } => {
            let mut values = vec![*left, *right];
            values.extend(carry);
            values
        }
        ValueExpression::Compare { left, right, .. } => vec![*left, *right],
        ValueExpression::Load { dependencies, .. }
        | ValueExpression::FlagFrom {
            inputs: dependencies,
            ..
        } => dependencies.clone(),
        ValueExpression::Input(_) | ValueExpression::Constant(_) | ValueExpression::Unknown(_) => {
            Vec::new()
        }
    }
}

fn predicate_values(predicate: &RecoveredPredicate) -> Vec<ValueId> {
    match predicate {
        RecoveredPredicate::Comparison { left, right, .. } => vec![*left, *right],
        RecoveredPredicate::FlagValue { value, .. } => vec![*value],
    }
}

#[cfg(test)]
mod tests {
    use nesc_disasm::{AnalysisLimits as DisassemblyLimits, disassemble};
    use nesc_rom::{Format, Metadata, Mirroring, Region, Rom, build};

    use super::{
        BarrierKind, ComparisonPredicate, RecoveredPredicate, StateVariable, ValueAnalysisLimits,
        ValueExpression, analyze_values,
    };
    use crate::{AnalysisLimits, Flag, Register, analyze};

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

    #[test]
    fn recovers_compare_branch_condition() {
        let program = program(&[
            0xa9, 0x10, // lda #$10
            0xc9, 0x10, // cmp #$10
            0xd0, 0x02, // bne $c008
            0xa9, 0x20, // lda #$20
            0x60, // rts
        ]);
        let analysis = analyze_values(&program, ValueAnalysisLimits::default()).expect("values");
        let condition = &analysis.functions[0].conditions[0];
        assert!(matches!(
            condition.predicate,
            RecoveredPredicate::Comparison {
                predicate: ComparisonPredicate::NotEqual,
                ..
            }
        ));
        assert_eq!(condition.confidence, super::Confidence::Proven);
    }

    #[test]
    fn creates_loop_phi_for_index_register() {
        let program = program(&[
            0xa2, 0x00, // ldx #0
            0xe8, // inx
            0xe0, 0x03, // cpx #3
            0xd0, 0xfb, // bne $c002
            0x60, // rts
        ]);
        let analysis = analyze_values(&program, ValueAnalysisLimits::default()).expect("values");
        assert!(analysis.functions[0].values.iter().any(|value| {
            matches!(
                value.expression,
                ValueExpression::Phi {
                    variable: StateVariable::Register(Register::X),
                    ..
                }
            )
        }));
    }

    #[test]
    fn folds_carry_chain_constants() {
        let program = program(&[
            0x18, // clc
            0xa9, 0xff, // lda #$ff
            0x69, 0x01, // adc #1
            0x69, 0x00, // adc #0
            0x60, // rts
        ]);
        let analysis = analyze_values(&program, ValueAnalysisLimits::default()).expect("values");
        let function = &analysis.functions[0];
        let return_block = program.functions[0]
            .blocks
            .iter()
            .find(|block| matches!(program.blocks[block].terminator, crate::Terminator::Return))
            .expect("return block");
        let a = function.blocks[return_block].exit[&StateVariable::Register(Register::A)];
        assert_eq!(function.constant(a), Some(1));
        let carry = function.blocks[return_block].exit[&StateVariable::Flag(Flag::Carry)];
        assert_eq!(function.constant(carry), Some(0));
    }

    #[test]
    fn canonicalizes_zero_page_aliases_and_preserves_ram_across_mmio() {
        let program = program(&[
            0xa9, 0x2a, // lda #$2a
            0x85, 0x10, // sta $10
            0xa9, 0x01, // lda #1
            0x8d, 0x00, 0x20, // sta $2000
            0xad, 0x10, 0x00, // lda $0010
            0x60, // rts
        ]);
        let analysis = analyze_values(&program, ValueAnalysisLimits::default()).expect("values");
        let function = &analysis.functions[0];
        let return_block = function
            .blocks
            .keys()
            .find(|block| matches!(program.blocks[block].terminator, crate::Terminator::Return))
            .expect("return block");
        let a = function.blocks[return_block].exit[&StateVariable::Register(Register::A)];
        assert_eq!(function.constant(a), Some(0x2a));
        assert!(
            function
                .barriers
                .iter()
                .any(|barrier| barrier.kind == BarrierKind::VolatileWrite)
        );
    }

    #[test]
    fn invalidates_ram_for_imprecise_indexed_writes() {
        let program = program(&[
            0xa9, 0x2a, // lda #$2a
            0x85, 0x10, // sta $10
            0xa2, 0x00, // ldx #0
            0x95, 0x20, // sta $20,x
            0xa5, 0x10, // lda $10
            0x60, // rts
        ]);
        let analysis = analyze_values(&program, ValueAnalysisLimits::default()).expect("values");
        let function = &analysis.functions[0];
        let return_block = function
            .blocks
            .keys()
            .find(|block| matches!(program.blocks[block].terminator, crate::Terminator::Return))
            .expect("return block");
        let a = function.blocks[return_block].exit[&StateVariable::Register(Register::A)];
        assert_eq!(function.constant(a), None);
        assert!(
            function
                .barriers
                .iter()
                .any(|barrier| barrier.kind == BarrierKind::UnknownMemoryWrite)
        );
    }

    #[test]
    fn records_flag_inputs_and_restores_the_caller_stack_pointer() {
        let branch_program = program(&[
            0xd0, 0x02, // bne $c004
            0x60, // rts
            0xea, // nop
            0x60, // rts
        ]);
        let branch_analysis =
            analyze_values(&branch_program, ValueAnalysisLimits::default()).expect("branch values");
        assert!(
            branch_analysis.functions[0]
                .summary
                .inputs
                .contains(&StateVariable::Flag(Flag::Zero))
        );

        let call_program = program(&[
            0xa2, 0x80, // ldx #$80
            0x9a, // txs
            0x20, 0x08, 0xc0, // jsr $c008
            0x60, // rts
            0xea, // nop
            0x60, // rts
        ]);
        let call_analysis =
            analyze_values(&call_program, ValueAnalysisLimits::default()).expect("call values");
        let caller = &call_analysis.functions[0];
        let continuation = caller
            .blocks
            .iter()
            .find(|(block, _)| block.cpu_address == 0xc006)
            .map(|(_, state)| state)
            .expect("call continuation");
        let stack_pointer = continuation.entry[&StateVariable::Register(Register::StackPointer)];
        assert_eq!(caller.constant(stack_pointer), Some(0x80));
    }

    #[test]
    fn records_volatile_dma_call_and_unresolved_barriers() {
        let program = program(&[
            0xad, 0x02, 0x20, // lda $2002
            0x8d, 0x14, 0x40, // sta $4014
            0x20, 0x0c, 0xc0, // jsr $c00c
            0x6c, 0x00, 0x02, // jmp ($0200)
            0x60, // rts
        ]);
        let analysis = analyze_values(&program, ValueAnalysisLimits::default()).expect("values");
        let kinds = analysis.functions[0]
            .barriers
            .iter()
            .map(|barrier| barrier.kind)
            .collect::<Vec<_>>();
        assert!(kinds.contains(&BarrierKind::VolatileRead));
        assert!(kinds.contains(&BarrierKind::Dma));
        assert!(kinds.contains(&BarrierKind::Call));
        assert!(kinds.contains(&BarrierKind::UnresolvedControl));
    }

    #[test]
    fn enforces_limits_and_verifies_value_references() {
        let program = program(&[0xa9, 0x01, 0x60]);
        let error = analyze_values(
            &program,
            ValueAnalysisLimits {
                max_values: 1,
                ..ValueAnalysisLimits::default()
            },
        )
        .expect_err("value limit");
        assert!(error[0].message().contains("SSA value limit"));

        let mut analysis =
            analyze_values(&program, ValueAnalysisLimits::default()).expect("values");
        analysis.functions[0].values[0].id = super::ValueId(u32::MAX);
        assert!(analysis.verify(&program).is_err());
        assert!(analysis.render_text().contains("value-functions"));
    }
}
