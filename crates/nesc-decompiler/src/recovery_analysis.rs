use std::collections::{BTreeMap, BTreeSet, VecDeque};

use nesc_codegen_6502::{
    ARGUMENT_SPILL_LEN, AbiLocation, RETURN_SPILL_LEN, argument_location, return_location,
};
use nesc_disasm::{AddressingMode, VectorKind};

use super::{
    AddressSpace, AnalysisError, BlockId, BlockTarget, ComparisonPredicate, Confidence, EdgeKind,
    Flag, Function, FunctionEvidence, FunctionId, FunctionValueAnalysis, MemoryLocation,
    MemoryOperand, Program, Provenance, Register, SemanticInstruction, SemanticOperation,
    StateVariable, Terminator, UnknownReason, ValueAnalysis, ValueEvidenceKind, ValueExpression,
    ValueId, ValueSource, ValueTarget,
};

const REGISTER_ABI_BYTES: usize = 3;

/// Resource bounds for call, signature, and type recovery over untrusted input.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecoveryLimits {
    /// Maximum direct or unresolved call sites.
    pub max_call_edges: usize,
    /// Maximum flattened argument and return bytes.
    pub max_abi_bytes: usize,
    /// Maximum recovered value-type facts.
    pub max_type_facts: usize,
    /// Maximum recovered pointer-storage facts.
    pub max_pointer_facts: usize,
    /// Maximum graph-edge visits during cycle discovery.
    pub max_graph_steps: usize,
}

impl Default for RecoveryLimits {
    fn default() -> Self {
        Self {
            max_call_edges: 100_000,
            max_abi_bytes: 1_000_000,
            max_type_facts: 4_000_000,
            max_pointer_facts: 1_000_000,
            max_graph_steps: 10_000_000,
        }
    }
}

/// Calling behavior established by machine-code evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CallingConvention {
    /// The public flattened-byte ABI is conservatively supported by use sites.
    NesCall,
    /// Interrupt entry and `RTI` establish interrupt calling behavior.
    NesCallIrq,
    /// Available evidence does not establish a project ABI.
    Unknown,
}

/// Signed interpretation inferred for an integer bit pattern.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Signedness {
    /// Operations establish a signed interpretation.
    Signed,
    /// Operations establish an unsigned interpretation.
    Unsigned,
    /// Width is known but signed interpretation is not.
    Unknown,
}

/// Conservative high-level type shape.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RecoveredType {
    /// Processor boolean or comparison result.
    Boolean,
    /// Fixed-width integer bit pattern.
    Integer {
        /// Exact storage width.
        bits: u8,
        /// Recovered signed interpretation.
        signedness: Signedness,
    },
    /// CPU address stored as a two-byte little-endian value.
    CpuAddress {
        /// Address space reached through the pointer.
        address_space: AddressSpace,
        /// Width of one pointed-to element.
        pointee_bits: u8,
        /// Recovered volatile interpretation.
        volatility: Volatility,
    },
}

/// Volatile interpretation of a recovered pointer target.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Volatility {
    /// Target accesses must be volatile.
    Volatile,
    /// Target accesses are established as ordinary memory.
    NonVolatile,
    /// Indirect addressing does not establish target volatility.
    Unknown,
}

/// Evidence category for calls, signatures, and types.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum RecoveryEvidenceKind {
    /// A direct control-transfer target was resolved.
    DirectControlFlow,
    /// NMI or IRQ vector identifies interrupt entry.
    InterruptVector,
    /// Function exits through `RTI`.
    ReturnFromInterrupt,
    /// A machine location is read from function-entry state.
    FunctionEntryRead,
    /// Caller consumes a post-call machine location.
    CallerUse,
    /// Locations form a prefix of the public ABI layout.
    AbiLayout,
    /// The 6502 machine representation establishes width.
    MachineWidth,
    /// Flag or comparison semantics establish a boolean.
    BooleanSemantics,
    /// Carry-based comparison establishes unsigned interpretation.
    UnsignedComparison,
    /// An indirect operand establishes pointer storage.
    IndirectAddressing,
    /// Direct calls establish a recursive component.
    CallCycle,
    /// A call target could not be resolved to a function.
    UnresolvedControl,
}

/// Provenance-bearing support for a recovered fact.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryEvidence {
    /// Evidence category.
    pub kind: RecoveryEvidenceKind,
    /// Exact instruction evidence when applicable.
    pub provenance: Option<Provenance>,
}

/// One bank-qualified call-graph edge.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CallEdge {
    /// Function containing the call site.
    pub caller: FunctionId,
    /// Resolved target function, when established.
    pub callee: Option<FunctionId>,
    /// Bank-qualified calling block.
    pub call_site: BlockId,
    /// Encoded CPU target even when function resolution failed.
    pub target_cpu_address: u16,
    /// Confidence in target resolution.
    pub confidence: Confidence,
    /// Evidence establishing the edge.
    pub evidence: Vec<RecoveryEvidence>,
}

/// One strongly connected component in the direct-call graph.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CallGraphCycle {
    /// Canonically ordered strongly connected functions.
    pub functions: Vec<FunctionId>,
    /// Confidence that the component is cyclic.
    pub confidence: Confidence,
    /// Direct-call evidence within the component.
    pub evidence: Vec<RecoveryEvidence>,
}

/// One flattened argument or return byte.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AbiByte {
    /// Flattened byte index in the public ABI.
    pub index: usize,
    /// Register or zero-page machine location.
    pub location: StateVariable,
    /// Conservatively recovered byte type.
    pub ty: RecoveredType,
    /// Confidence in interpreting this location as an ABI byte.
    pub confidence: Confidence,
    /// Entry-read or caller-use evidence.
    pub evidence: Vec<RecoveryEvidence>,
}

/// Recovered interface and machine effects for one function.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FunctionRecovery {
    /// Recovered function identity.
    pub function: FunctionId,
    /// Calling behavior supported by available evidence.
    pub convention: CallingConvention,
    /// Contiguous flattened argument-byte prefix.
    pub parameter_bytes: Vec<AbiByte>,
    /// Contiguous flattened return-byte prefix.
    pub return_bytes: Vec<AbiByte>,
    /// Entry machine state not classified as ABI arguments.
    pub unclassified_inputs: Vec<StateVariable>,
    /// State assigned or invalidated by the function.
    pub clobbers: Vec<StateVariable>,
    /// Hardware call-frame bytes consumed by entry and return behavior.
    pub call_frame_bytes: u8,
    /// Overall recovery confidence.
    pub confidence: Confidence,
    /// Evidence supporting the recovered interface.
    pub evidence: Vec<RecoveryEvidence>,
}

/// Subject of a recovered scalar type fact.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct TypeSubject {
    /// Function owning the SSA value.
    pub function: FunctionId,
    /// Value whose type is described.
    pub value: ValueId,
}

/// Type shape associated with one SSA value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TypeFact {
    /// Canonical type-fact subject.
    pub subject: TypeSubject,
    /// Recovered type shape.
    pub ty: RecoveredType,
    /// Confidence in the complete type shape.
    pub confidence: Confidence,
    /// Machine-semantics evidence.
    pub evidence: Vec<RecoveryEvidence>,
}

/// Two-byte storage used as an indirect CPU address.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PointerFact {
    /// Function containing the indirect access.
    pub function: FunctionId,
    /// Low-byte storage location.
    pub low: MemoryLocation,
    /// High-byte storage location with zero-page wrapping.
    pub high: MemoryLocation,
    /// Recovered pointer shape.
    pub ty: RecoveredType,
    /// Confidence in the pointer interpretation.
    pub confidence: Confidence,
    /// Indirect-addressing evidence.
    pub evidence: Vec<RecoveryEvidence>,
}

/// Complete call-graph, signature, and type recovery result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryAnalysis {
    /// Direct and unresolved call sites.
    pub calls: Vec<CallEdge>,
    /// Strongly connected direct-call components.
    pub cycles: Vec<CallGraphCycle>,
    /// Per-function calling and interface recovery.
    pub functions: Vec<FunctionRecovery>,
    /// Per-value scalar type facts.
    pub types: Vec<TypeFact>,
    /// Fixed zero-page pointer-storage facts.
    pub pointers: Vec<PointerFact>,
}

/// Recovers direct calls, conservative ABI signatures, and type shapes.
///
/// # Errors
///
/// Returns deterministic failures for invalid prerequisite analysis, exhausted
/// limits, or malformed recovered references.
pub fn analyze_recovery(
    program: &Program,
    values: &ValueAnalysis,
    limits: RecoveryLimits,
) -> Result<RecoveryAnalysis, Vec<AnalysisError>> {
    if limits.max_call_edges == 0
        || limits.max_abi_bytes == 0
        || limits.max_type_facts == 0
        || limits.max_pointer_facts == 0
        || limits.max_graph_steps == 0
    {
        return Err(vec![AnalysisError::new(
            "recovery limits must permit calls, ABI bytes, type facts, pointers, and graph walks",
        )]);
    }
    program.verify()?;
    values.verify(program)?;

    let calls = recover_calls(program, limits.max_call_edges)?;
    let cycles = recover_cycles(program, &calls, limits.max_graph_steps)?;
    let functions = recover_signatures(program, values, &calls, &cycles, limits.max_abi_bytes)?;
    let types = recover_types(values, limits.max_type_facts)?;
    let pointers = recover_pointers(program, limits.max_pointer_facts)?;
    let analysis = RecoveryAnalysis {
        calls,
        cycles,
        functions,
        types,
        pointers,
    };
    analysis.verify(program, values)?;
    Ok(analysis)
}

fn recover_calls(program: &Program, limit: usize) -> Result<Vec<CallEdge>, Vec<AnalysisError>> {
    let entries = program
        .functions
        .iter()
        .map(|function| (function.entry, function.id))
        .collect::<BTreeMap<_, _>>();
    let owners = function_owners(program)?;
    let mut calls = Vec::new();
    for block in program.blocks.values() {
        let Terminator::Call { callee, .. } = &block.terminator else {
            continue;
        };
        let Some(caller) = owners.get(&block.id).copied() else {
            continue;
        };
        if calls.len() >= limit {
            return Err(vec![AnalysisError::new(format!(
                "call-edge limit {limit} exceeded"
            ))]);
        }
        let provenance = block
            .instructions
            .last()
            .expect("verified nonempty block")
            .provenance
            .clone();
        let (callee, target_cpu_address, confidence, kind) = match callee {
            BlockTarget::Resolved(target) => (
                entries.get(target).copied(),
                target.cpu_address,
                if entries.contains_key(target) {
                    Confidence::Proven
                } else {
                    Confidence::Unknown
                },
                if entries.contains_key(target) {
                    RecoveryEvidenceKind::DirectControlFlow
                } else {
                    RecoveryEvidenceKind::UnresolvedControl
                },
            ),
            BlockTarget::Unresolved { cpu_address } => (
                None,
                *cpu_address,
                Confidence::Unknown,
                RecoveryEvidenceKind::UnresolvedControl,
            ),
        };
        calls.push(CallEdge {
            caller,
            callee,
            call_site: block.id,
            target_cpu_address,
            confidence,
            evidence: vec![RecoveryEvidence {
                kind,
                provenance: Some(provenance),
            }],
        });
    }
    calls.sort_by_key(|call| (call.caller, call.call_site));
    Ok(calls)
}

fn function_owners(program: &Program) -> Result<BTreeMap<BlockId, FunctionId>, Vec<AnalysisError>> {
    let mut owners = BTreeMap::new();
    for function in &program.functions {
        for block in &function.blocks {
            if owners
                .insert(*block, function.id)
                .is_some_and(|owner| owner != function.id)
            {
                return Err(vec![AnalysisError::new(format!(
                    "block prg{:02X}:${:04X} belongs to multiple recovered functions",
                    block.bank, block.cpu_address
                ))]);
            }
        }
    }
    if owners.len() != program.blocks.len() {
        return Err(vec![AnalysisError::new(
            "recovered functions do not own every basic block exactly once",
        )]);
    }
    Ok(owners)
}

fn recover_cycles(
    program: &Program,
    calls: &[CallEdge],
    max_steps: usize,
) -> Result<Vec<CallGraphCycle>, Vec<AnalysisError>> {
    let mut adjacency = program
        .functions
        .iter()
        .map(|function| (function.id, BTreeSet::new()))
        .collect::<BTreeMap<_, _>>();
    for call in calls {
        if let Some(callee) = call.callee {
            adjacency.entry(call.caller).or_default().insert(callee);
        }
    }
    let mut steps = 0_usize;
    let mut reachability = BTreeMap::new();
    for function in &program.functions {
        let mut reached = BTreeSet::new();
        let mut queue = VecDeque::from([function.id]);
        while let Some(current) = queue.pop_front() {
            for target in &adjacency[&current] {
                steps = steps.saturating_add(1);
                if steps > max_steps {
                    return Err(vec![AnalysisError::new(format!(
                        "call-graph walk limit {max_steps} exceeded"
                    ))]);
                }
                if reached.insert(*target) {
                    queue.push_back(*target);
                }
            }
        }
        reachability.insert(function.id, reached);
    }

    let mut remaining = program
        .functions
        .iter()
        .map(|function| function.id)
        .collect::<BTreeSet<_>>();
    let mut cycles = Vec::new();
    while let Some(seed) = remaining.first().copied() {
        let component = remaining
            .iter()
            .copied()
            .filter(|candidate| {
                (*candidate == seed || reachability[&seed].contains(candidate))
                    && (*candidate == seed || reachability[candidate].contains(&seed))
            })
            .collect::<Vec<_>>();
        for function in &component {
            remaining.remove(function);
        }
        let cyclic = component.len() > 1 || adjacency[&seed].contains(&seed);
        if cyclic {
            let provenance = calls
                .iter()
                .find(|call| {
                    component.contains(&call.caller)
                        && call
                            .callee
                            .is_some_and(|callee| component.contains(&callee))
                })
                .and_then(|call| call.evidence.first())
                .and_then(|evidence| evidence.provenance.clone());
            cycles.push(CallGraphCycle {
                functions: component,
                confidence: Confidence::Proven,
                evidence: vec![RecoveryEvidence {
                    kind: RecoveryEvidenceKind::CallCycle,
                    provenance,
                }],
            });
        }
    }
    Ok(cycles)
}

fn recover_signatures(
    program: &Program,
    values: &ValueAnalysis,
    calls: &[CallEdge],
    cycles: &[CallGraphCycle],
    max_abi_bytes: usize,
) -> Result<Vec<FunctionRecovery>, Vec<AnalysisError>> {
    let mut total_bytes = 0_usize;
    let mut recovered = Vec::with_capacity(program.functions.len());
    for function in &program.functions {
        let value_analysis = &values.functions[function.id.0 as usize];
        let (parameter_bytes, parameter_gap) = recover_parameter_bytes(value_analysis);
        let return_bytes = recover_return_bytes(function, program, values, calls);
        total_bytes = total_bytes
            .saturating_add(parameter_bytes.len())
            .saturating_add(return_bytes.len());
        if total_bytes > max_abi_bytes {
            return Err(vec![AnalysisError::new(format!(
                "ABI-byte limit {max_abi_bytes} exceeded"
            ))]);
        }

        let selected_inputs = parameter_bytes
            .iter()
            .map(|byte| byte.location)
            .collect::<BTreeSet<_>>();
        let unclassified_inputs = value_analysis
            .summary
            .inputs
            .iter()
            .copied()
            .filter(|input| !selected_inputs.contains(input))
            .collect::<Vec<_>>();
        let interrupt = is_interrupt_function(function, program);
        let has_direct_caller = calls.iter().any(|call| call.callee == Some(function.id));
        let abi_evidence = !parameter_bytes.is_empty() || !return_bytes.is_empty();
        let convention = if interrupt {
            CallingConvention::NesCallIrq
        } else if has_direct_caller && abi_evidence && !parameter_gap {
            CallingConvention::NesCall
        } else {
            CallingConvention::Unknown
        };
        let mut evidence =
            signature_evidence(function, calls, &parameter_bytes, &return_bytes, interrupt);
        evidence.sort_by_key(|item| (item.kind, evidence_offset(item)));
        evidence.dedup();
        let in_cycle = cycles
            .iter()
            .any(|cycle| cycle.functions.contains(&function.id));
        if in_cycle {
            evidence.push(RecoveryEvidence {
                kind: RecoveryEvidenceKind::CallCycle,
                provenance: None,
            });
        }
        let confidence = if in_cycle || convention == CallingConvention::Unknown {
            Confidence::Unknown
        } else if convention == CallingConvention::NesCallIrq {
            Confidence::Proven
        } else {
            Confidence::Conservative
        };
        recovered.push(FunctionRecovery {
            function: function.id,
            convention,
            parameter_bytes,
            return_bytes,
            unclassified_inputs,
            clobbers: value_analysis.summary.clobbers.clone(),
            call_frame_bytes: if interrupt {
                3
            } else if has_direct_caller {
                2
            } else {
                0
            },
            confidence,
            evidence,
        });
    }
    Ok(recovered)
}

fn recover_parameter_bytes(analysis: &FunctionValueAnalysis) -> (Vec<AbiByte>, bool) {
    let inputs = analysis
        .summary
        .inputs
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    let mut bytes = Vec::new();
    let mut gap = false;
    let mut saw_gap = false;
    for index in 0..REGISTER_ABI_BYTES + ARGUMENT_SPILL_LEN {
        let location = argument_state(index).expect("public ABI byte range");
        if inputs.contains(&location) {
            if saw_gap {
                gap = true;
                continue;
            }
            bytes.push(AbiByte {
                index,
                location,
                ty: byte_type(),
                confidence: Confidence::Conservative,
                evidence: vec![
                    RecoveryEvidence {
                        kind: RecoveryEvidenceKind::FunctionEntryRead,
                        provenance: None,
                    },
                    RecoveryEvidence {
                        kind: RecoveryEvidenceKind::AbiLayout,
                        provenance: None,
                    },
                ],
            });
        } else {
            saw_gap = true;
        }
    }
    (bytes, gap)
}

fn recover_return_bytes(
    function: &Function,
    program: &Program,
    values: &ValueAnalysis,
    calls: &[CallEdge],
) -> Vec<AbiByte> {
    let call_sites = calls
        .iter()
        .filter(|call| call.callee == Some(function.id))
        .collect::<Vec<_>>();
    if call_sites.is_empty() {
        return Vec::new();
    }
    let mut bytes = Vec::new();
    for index in 0..REGISTER_ABI_BYTES + RETURN_SPILL_LEN {
        let location = return_state(index).expect("public ABI byte range");
        let mut used_at = None;
        for call in &call_sites {
            let caller_values = &values.functions[call.caller.0 as usize];
            if call_result_used(program, caller_values, call, location) {
                used_at = call
                    .evidence
                    .first()
                    .and_then(|evidence| evidence.provenance.clone());
                break;
            }
        }
        if let Some(provenance) = used_at {
            bytes.push(AbiByte {
                index,
                location,
                ty: byte_type(),
                confidence: Confidence::Conservative,
                evidence: vec![
                    RecoveryEvidence {
                        kind: RecoveryEvidenceKind::CallerUse,
                        provenance: Some(provenance),
                    },
                    RecoveryEvidence {
                        kind: RecoveryEvidenceKind::AbiLayout,
                        provenance: None,
                    },
                ],
            });
        } else {
            break;
        }
    }
    bytes
}

fn call_result_used(
    program: &Program,
    caller: &FunctionValueAnalysis,
    call: &CallEdge,
    variable: StateVariable,
) -> bool {
    let call_provenance = call
        .evidence
        .first()
        .and_then(|evidence| evidence.provenance.as_ref());
    let seeds = caller
        .values
        .iter()
        .filter(|node| {
            node.variable == Some(variable)
                && node.expression == ValueExpression::Unknown(UnknownReason::CallClobber)
                && node.evidence.iter().any(|evidence| {
                    evidence.kind == ValueEvidenceKind::CallBarrier
                        && evidence.provenance.as_ref() == call_provenance
                })
        })
        .map(|node| node.id)
        .collect::<BTreeSet<_>>();
    if seeds.is_empty() {
        return false;
    }

    for (block_id, state) in &caller.blocks {
        let Some(entry) = state.entry.get(&variable).copied() else {
            continue;
        };
        if !depends_on_any(&caller.values, entry, &seeds, &mut BTreeSet::new()) {
            continue;
        }
        let block = &program.blocks[block_id];
        for instruction in &block.instructions {
            if instruction_reads(instruction, variable) {
                return true;
            }
            if instruction_writes(instruction, variable) {
                break;
            }
        }
    }
    false
}

fn is_interrupt_function(function: &Function, program: &Program) -> bool {
    let vector = function.evidence.iter().any(|evidence| {
        matches!(
            evidence,
            FunctionEvidence::Vector(VectorKind::Nmi | VectorKind::Irq)
        )
    });
    vector
        && function.blocks.iter().any(|block| {
            matches!(
                program.blocks[block].terminator,
                Terminator::ReturnFromInterrupt
            )
        })
}

fn signature_evidence(
    function: &Function,
    calls: &[CallEdge],
    parameters: &[AbiByte],
    returns: &[AbiByte],
    interrupt: bool,
) -> Vec<RecoveryEvidence> {
    let mut evidence = Vec::new();
    if interrupt {
        evidence.push(RecoveryEvidence {
            kind: RecoveryEvidenceKind::InterruptVector,
            provenance: None,
        });
        evidence.push(RecoveryEvidence {
            kind: RecoveryEvidenceKind::ReturnFromInterrupt,
            provenance: None,
        });
    }
    if !parameters.is_empty() {
        evidence.push(RecoveryEvidence {
            kind: RecoveryEvidenceKind::FunctionEntryRead,
            provenance: None,
        });
    }
    if !parameters.is_empty() || !returns.is_empty() {
        evidence.push(RecoveryEvidence {
            kind: RecoveryEvidenceKind::AbiLayout,
            provenance: None,
        });
    }
    for call in calls.iter().filter(|call| call.callee == Some(function.id)) {
        evidence.extend(call.evidence.iter().cloned());
    }
    if !returns.is_empty() {
        evidence.extend(
            returns
                .iter()
                .flat_map(|byte| byte.evidence.iter())
                .filter(|item| item.kind == RecoveryEvidenceKind::CallerUse)
                .cloned(),
        );
    }
    evidence
}

fn evidence_offset(evidence: &RecoveryEvidence) -> usize {
    evidence
        .provenance
        .as_ref()
        .map_or(usize::MAX, |provenance| provenance.prg_offset)
}

fn argument_state(index: usize) -> Option<StateVariable> {
    argument_location(index).map(abi_state)
}

fn return_state(index: usize) -> Option<StateVariable> {
    return_location(index).map(abi_state)
}

fn abi_state(location: AbiLocation) -> StateVariable {
    match location {
        AbiLocation::A => StateVariable::Register(Register::A),
        AbiLocation::X => StateVariable::Register(Register::X),
        AbiLocation::Y => StateVariable::Register(Register::Y),
        AbiLocation::ZeroPage(address) => StateVariable::Memory(MemoryLocation::ZeroPage(address)),
    }
}

fn byte_type() -> RecoveredType {
    RecoveredType::Integer {
        bits: 8,
        signedness: Signedness::Unknown,
    }
}

fn depends_on_any(
    values: &[super::ValueNode],
    value: ValueId,
    seeds: &BTreeSet<ValueId>,
    visiting: &mut BTreeSet<ValueId>,
) -> bool {
    if seeds.contains(&value) {
        return true;
    }
    if !visiting.insert(value) {
        return false;
    }
    let depends = values.get(value.0 as usize).is_some_and(|node| {
        expression_inputs(&node.expression)
            .into_iter()
            .any(|input| depends_on_any(values, input, seeds, visiting))
    });
    visiting.remove(&value);
    depends
}

fn expression_inputs(expression: &ValueExpression) -> Vec<ValueId> {
    match expression {
        ValueExpression::Phi { inputs, .. } => inputs.iter().map(|input| input.value).collect(),
        ValueExpression::Copy(value) => vec![*value],
        ValueExpression::Load { dependencies, .. }
        | ValueExpression::FlagFrom {
            inputs: dependencies,
            ..
        } => dependencies.clone(),
        ValueExpression::Binary {
            left, right, carry, ..
        } => {
            let mut inputs = vec![*left, *right];
            inputs.extend(carry);
            inputs
        }
        ValueExpression::Compare { left, right, .. } => vec![*left, *right],
        ValueExpression::Input(_) | ValueExpression::Constant(_) | ValueExpression::Unknown(_) => {
            Vec::new()
        }
    }
}

fn instruction_reads(instruction: &SemanticInstruction, variable: StateVariable) -> bool {
    if let StateVariable::Flag(flag) = variable
        && instruction.flags.reads.contains(&flag)
    {
        return true;
    }
    instruction
        .operations
        .iter()
        .any(|operation| operation_reads(operation, variable))
}

fn instruction_writes(instruction: &SemanticInstruction, variable: StateVariable) -> bool {
    if let StateVariable::Flag(flag) = variable
        && instruction.flags.writes.contains(&flag)
    {
        return true;
    }
    instruction
        .operations
        .iter()
        .any(|operation| operation_writes(operation, variable))
}

fn operation_reads(operation: &SemanticOperation, variable: StateVariable) -> bool {
    match operation {
        SemanticOperation::Load { source, .. } => source_reads(source, variable),
        SemanticOperation::Store {
            destination,
            source,
        } => variable == StateVariable::Register(*source) || address_reads(destination, variable),
        SemanticOperation::Accumulate {
            source,
            carry_input,
            ..
        } => {
            variable == StateVariable::Register(Register::A)
                || source_reads(source, variable)
                || (*carry_input && variable == StateVariable::Flag(Flag::Carry))
        }
        SemanticOperation::Compare { left, right } => {
            variable == StateVariable::Register(*left) || source_reads(right, variable)
        }
        SemanticOperation::TestBits { source } => {
            variable == StateVariable::Register(Register::A) || source_reads(source, variable)
        }
        SemanticOperation::Shift {
            target,
            carry_input,
            ..
        } => {
            target_reads(target, variable)
                || (*carry_input && variable == StateVariable::Flag(Flag::Carry))
        }
        SemanticOperation::Adjust { target, .. } => target_reads(target, variable),
        SemanticOperation::Transfer { source, .. } => variable == StateVariable::Register(*source),
        SemanticOperation::Push { source } => source_reads(source, variable),
        SemanticOperation::StackControl(_) => {
            variable == StateVariable::Register(Register::StackPointer)
        }
        SemanticOperation::Pull { .. }
        | SemanticOperation::SetFlag { .. }
        | SemanticOperation::NoOperation => false,
    }
}

fn operation_writes(operation: &SemanticOperation, variable: StateVariable) -> bool {
    match operation {
        SemanticOperation::Load { destination, .. } => {
            variable == StateVariable::Register(*destination)
        }
        SemanticOperation::Store { destination, .. } => {
            memory_state(destination) == Some(variable) || variable == StateVariable::MemoryEpoch
        }
        SemanticOperation::Accumulate { .. } => variable == StateVariable::Register(Register::A),
        SemanticOperation::Shift { target, .. } | SemanticOperation::Adjust { target, .. } => {
            target_writes(target, variable)
        }
        SemanticOperation::Transfer { destination, .. } => {
            variable == StateVariable::Register(*destination)
        }
        SemanticOperation::SetFlag { flag, .. } => variable == StateVariable::Flag(*flag),
        SemanticOperation::Push { .. } => variable == StateVariable::MemoryEpoch,
        SemanticOperation::Pull { destination, .. } => target_writes(destination, variable),
        SemanticOperation::StackControl(_) => {
            variable == StateVariable::Register(Register::StackPointer)
                || variable == StateVariable::MemoryEpoch
        }
        SemanticOperation::Compare { .. }
        | SemanticOperation::TestBits { .. }
        | SemanticOperation::NoOperation => false,
    }
}

fn source_reads(source: &ValueSource, variable: StateVariable) -> bool {
    match source {
        ValueSource::Register(register) => variable == StateVariable::Register(*register),
        ValueSource::Memory(memory) => {
            memory_state(memory) == Some(variable) || address_reads(memory, variable)
        }
        ValueSource::Status => matches!(variable, StateVariable::Flag(_)),
        ValueSource::Immediate(_) => false,
    }
}

fn target_reads(target: &ValueTarget, variable: StateVariable) -> bool {
    match target {
        ValueTarget::Register(register) => variable == StateVariable::Register(*register),
        ValueTarget::Memory(memory) => {
            memory_state(memory) == Some(variable) || address_reads(memory, variable)
        }
        ValueTarget::Status => matches!(variable, StateVariable::Flag(_)),
    }
}

fn target_writes(target: &ValueTarget, variable: StateVariable) -> bool {
    match target {
        ValueTarget::Register(register) => variable == StateVariable::Register(*register),
        ValueTarget::Memory(memory) => {
            memory_state(memory) == Some(variable) || variable == StateVariable::MemoryEpoch
        }
        ValueTarget::Status => matches!(variable, StateVariable::Flag(_)),
    }
}

fn address_reads(memory: &MemoryOperand, variable: StateVariable) -> bool {
    memory
        .index
        .is_some_and(|index| variable == StateVariable::Register(index))
        || (memory.indirect && variable == StateVariable::MemoryEpoch)
}

fn memory_state(memory: &MemoryOperand) -> Option<StateVariable> {
    if memory.volatile || memory.index.is_some() || memory.indirect {
        return None;
    }
    let location = match memory.address_space {
        AddressSpace::ZeroPage => MemoryLocation::ZeroPage(memory.encoded as u8),
        AddressSpace::InternalRam => {
            let canonical = memory.encoded & 0x07ff;
            if canonical <= 0xff {
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

fn recover_types(
    values: &ValueAnalysis,
    max_type_facts: usize,
) -> Result<Vec<TypeFact>, Vec<AnalysisError>> {
    let mut facts = BTreeMap::<TypeSubject, TypeFact>::new();
    for function in &values.functions {
        for node in &function.values {
            if node.variable == Some(StateVariable::MemoryEpoch) {
                continue;
            }
            let subject = TypeSubject {
                function: function.function,
                value: node.id,
            };
            let boolean = matches!(node.variable, Some(StateVariable::Flag(_)))
                || matches!(
                    node.expression,
                    ValueExpression::Compare { .. } | ValueExpression::FlagFrom { .. }
                );
            let provenance = node
                .evidence
                .iter()
                .find_map(|evidence| evidence.provenance.clone());
            facts.insert(
                subject,
                TypeFact {
                    subject,
                    ty: if boolean {
                        RecoveredType::Boolean
                    } else {
                        byte_type()
                    },
                    confidence: Confidence::Proven,
                    evidence: vec![RecoveryEvidence {
                        kind: if boolean {
                            RecoveryEvidenceKind::BooleanSemantics
                        } else {
                            RecoveryEvidenceKind::MachineWidth
                        },
                        provenance: provenance.clone(),
                    }],
                },
            );
            if let ValueExpression::Compare {
                predicate:
                    ComparisonPredicate::UnsignedGreaterEqual | ComparisonPredicate::UnsignedLess,
                left,
                right,
            } = node.expression
            {
                for value in [left, right] {
                    refine_unsigned(
                        &mut facts,
                        TypeSubject {
                            function: function.function,
                            value,
                        },
                        provenance.clone(),
                    );
                }
            }
            if facts.len() > max_type_facts {
                return Err(vec![AnalysisError::new(format!(
                    "type-fact limit {max_type_facts} exceeded"
                ))]);
            }
        }
    }
    Ok(facts.into_values().collect())
}

fn refine_unsigned(
    facts: &mut BTreeMap<TypeSubject, TypeFact>,
    subject: TypeSubject,
    provenance: Option<Provenance>,
) {
    let Some(fact) = facts.get_mut(&subject) else {
        return;
    };
    if matches!(fact.ty, RecoveredType::Boolean) {
        return;
    }
    fact.ty = RecoveredType::Integer {
        bits: 8,
        signedness: Signedness::Unsigned,
    };
    fact.confidence = Confidence::Conservative;
    let evidence = RecoveryEvidence {
        kind: RecoveryEvidenceKind::UnsignedComparison,
        provenance,
    };
    if !fact.evidence.contains(&evidence) {
        fact.evidence.push(evidence);
    }
}

fn recover_pointers(
    program: &Program,
    max_pointer_facts: usize,
) -> Result<Vec<PointerFact>, Vec<AnalysisError>> {
    let owners = function_owners(program)?;
    let mut pointers = BTreeMap::<(FunctionId, u8), PointerFact>::new();
    for block in program.blocks.values() {
        let Some(function) = owners.get(&block.id).copied() else {
            continue;
        };
        for instruction in &block.instructions {
            for memory in instruction
                .operations
                .iter()
                .flat_map(operation_memories)
                .filter(|memory| memory.mode == AddressingMode::IndirectIndexed)
            {
                let low_address = memory.encoded as u8;
                let evidence = RecoveryEvidence {
                    kind: RecoveryEvidenceKind::IndirectAddressing,
                    provenance: Some(instruction.provenance.clone()),
                };
                let entry =
                    pointers
                        .entry((function, low_address))
                        .or_insert_with(|| PointerFact {
                            function,
                            low: MemoryLocation::ZeroPage(low_address),
                            high: MemoryLocation::ZeroPage(low_address.wrapping_add(1)),
                            ty: RecoveredType::CpuAddress {
                                address_space: AddressSpace::Unknown,
                                pointee_bits: 8,
                                volatility: Volatility::Unknown,
                            },
                            confidence: Confidence::Conservative,
                            evidence: Vec::new(),
                        });
                if !entry.evidence.contains(&evidence) {
                    entry.evidence.push(evidence);
                }
                if pointers.len() > max_pointer_facts {
                    return Err(vec![AnalysisError::new(format!(
                        "pointer-fact limit {max_pointer_facts} exceeded"
                    ))]);
                }
            }
        }
    }
    Ok(pointers.into_values().collect())
}

fn operation_memories(operation: &SemanticOperation) -> Vec<&MemoryOperand> {
    match operation {
        SemanticOperation::Load {
            source: ValueSource::Memory(memory),
            ..
        }
        | SemanticOperation::Accumulate {
            source: ValueSource::Memory(memory),
            ..
        }
        | SemanticOperation::Compare {
            right: ValueSource::Memory(memory),
            ..
        }
        | SemanticOperation::TestBits {
            source: ValueSource::Memory(memory),
        }
        | SemanticOperation::Push {
            source: ValueSource::Memory(memory),
        }
        | SemanticOperation::Store {
            destination: memory,
            ..
        }
        | SemanticOperation::Shift {
            target: ValueTarget::Memory(memory),
            ..
        }
        | SemanticOperation::Adjust {
            target: ValueTarget::Memory(memory),
            ..
        }
        | SemanticOperation::Pull {
            destination: ValueTarget::Memory(memory),
            ..
        } => vec![memory],
        SemanticOperation::Load { .. }
        | SemanticOperation::Accumulate { .. }
        | SemanticOperation::Compare { .. }
        | SemanticOperation::TestBits { .. }
        | SemanticOperation::Shift { .. }
        | SemanticOperation::Adjust { .. }
        | SemanticOperation::Push { .. }
        | SemanticOperation::Pull { .. }
        | SemanticOperation::Transfer { .. }
        | SemanticOperation::SetFlag { .. }
        | SemanticOperation::StackControl(_)
        | SemanticOperation::NoOperation => Vec::new(),
    }
}

impl RecoveryAnalysis {
    /// Verifies call ownership, cycle membership, ABI layout, and type references.
    ///
    /// # Errors
    ///
    /// Returns every deterministic structural failure found.
    pub fn verify(
        &self,
        program: &Program,
        values: &ValueAnalysis,
    ) -> Result<(), Vec<AnalysisError>> {
        let mut errors = Vec::new();
        if self.functions.len() != program.functions.len() {
            errors.push(AnalysisError::new(
                "recovery analysis does not contain every function",
            ));
        }
        let owners = match function_owners(program) {
            Ok(owners) => owners,
            Err(mut ownership_errors) => {
                errors.append(&mut ownership_errors);
                BTreeMap::new()
            }
        };
        if !strictly_sorted_by(&self.calls, |call| (call.caller, call.call_site)) {
            errors.push(AnalysisError::new("call graph is noncanonical"));
        }
        for call in &self.calls {
            if owners.get(&call.call_site) != Some(&call.caller) {
                errors.push(AnalysisError::new(
                    "call site does not belong to its caller",
                ));
            }
            if !matches!(
                program.blocks[&call.call_site].terminator,
                Terminator::Call { .. }
            ) {
                errors.push(AnalysisError::new("call graph references a non-call block"));
            }
            if call
                .callee
                .is_some_and(|callee| program.functions.get(callee.0 as usize).is_none())
            {
                errors.push(AnalysisError::new(
                    "call graph references an unknown callee",
                ));
            }
            if let Some(callee) = call.callee {
                let entry = program.functions[callee.0 as usize].entry;
                if !program.edges.iter().any(|edge| {
                    edge.source == call.call_site
                        && edge.kind == EdgeKind::CallTarget
                        && edge.target == Some(entry)
                }) {
                    errors.push(AnalysisError::new(
                        "resolved call lacks its call-target edge",
                    ));
                }
            }
        }
        if !strictly_sorted_by(&self.cycles, |cycle| cycle.functions.clone()) {
            errors.push(AnalysisError::new("call cycles are noncanonical"));
        }
        for cycle in &self.cycles {
            if cycle.functions.is_empty() || !strictly_sorted(&cycle.functions) {
                errors.push(AnalysisError::new(
                    "call cycle has empty or noncanonical membership",
                ));
            }
            if cycle
                .functions
                .iter()
                .any(|function| program.functions.get(function.0 as usize).is_none())
            {
                errors.push(AnalysisError::new(
                    "call cycle references an unknown function",
                ));
            }
        }
        for (index, function) in self.functions.iter().enumerate() {
            if function.function.0 as usize != index {
                errors.push(AnalysisError::new(
                    "recovered function order is noncanonical",
                ));
                continue;
            }
            verify_abi_bytes(&function.parameter_bytes, true, &mut errors);
            verify_abi_bytes(&function.return_bytes, false, &mut errors);
            if !strictly_sorted(&function.unclassified_inputs)
                || !strictly_sorted(&function.clobbers)
            {
                errors.push(AnalysisError::new(
                    "recovered function state collections are noncanonical",
                ));
            }
            if function.convention == CallingConvention::NesCall
                && function.parameter_bytes.is_empty()
                && function.return_bytes.is_empty()
            {
                errors.push(AnalysisError::new(
                    "nescall recovery lacks argument or return evidence",
                ));
            }
            if function.convention == CallingConvention::NesCall && function.call_frame_bytes != 2 {
                errors.push(AnalysisError::new(
                    "nescall recovery has an invalid call-frame size",
                ));
            }
            if function.convention == CallingConvention::NesCallIrq
                && function.call_frame_bytes != 3
            {
                errors.push(AnalysisError::new(
                    "interrupt convention has an invalid call-frame size",
                ));
            }
        }
        if !strictly_sorted_by(&self.types, |fact| fact.subject) {
            errors.push(AnalysisError::new("type facts are noncanonical"));
        }
        for fact in &self.types {
            let Some(function) = values.functions.get(fact.subject.function.0 as usize) else {
                errors.push(AnalysisError::new(
                    "type fact references an unknown function",
                ));
                continue;
            };
            if function.values.get(fact.subject.value.0 as usize).is_none() {
                errors.push(AnalysisError::new(
                    "type fact references an unknown SSA value",
                ));
            }
        }
        if !strictly_sorted_by(&self.pointers, |pointer| (pointer.function, pointer.low)) {
            errors.push(AnalysisError::new("pointer facts are noncanonical"));
        }
        for pointer in &self.pointers {
            if program.functions.get(pointer.function.0 as usize).is_none() {
                errors.push(AnalysisError::new(
                    "pointer fact references an unknown function",
                ));
            }
            let valid_pair = matches!(
                (pointer.low, pointer.high),
                (MemoryLocation::ZeroPage(low), MemoryLocation::ZeroPage(high))
                    if high == low.wrapping_add(1)
            );
            if !valid_pair {
                errors.push(AnalysisError::new(
                    "pointer storage is not a wrapping zero-page pair",
                ));
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    /// Renders deterministic call, signature, cycle, and type recovery text.
    #[must_use]
    pub fn render_text(&self) -> String {
        let mut text = format!(
            "recovery-functions: {} calls={} cycles={} types={} pointers={}\n",
            self.functions.len(),
            self.calls.len(),
            self.cycles.len(),
            self.types.len(),
            self.pointers.len()
        );
        for call in &self.calls {
            text.push_str(&format!(
                "call f{} prg{:02X}:${:04X} -> {:?} ${:04X} [{:?}]\n",
                call.caller.0,
                call.call_site.bank,
                call.call_site.cpu_address,
                call.callee,
                call.target_cpu_address,
                call.confidence
            ));
        }
        for cycle in &self.cycles {
            text.push_str(&format!(
                "cycle {:?} [{:?}]\n",
                cycle.functions, cycle.confidence
            ));
        }
        for function in &self.functions {
            text.push_str(&format!(
                "function f{} {:?} args={} returns={} inputs={:?} clobbers={:?} frame={} [{:?}]\n",
                function.function.0,
                function.convention,
                function.parameter_bytes.len(),
                function.return_bytes.len(),
                function.unclassified_inputs,
                function.clobbers,
                function.call_frame_bytes,
                function.confidence
            ));
        }
        for fact in &self.types {
            text.push_str(&format!(
                "type f{}:v{} {:?} [{:?}]\n",
                fact.subject.function.0, fact.subject.value.0, fact.ty, fact.confidence
            ));
        }
        for pointer in &self.pointers {
            text.push_str(&format!(
                "pointer f{} {:?}+{:?} {:?} [{:?}]\n",
                pointer.function.0, pointer.low, pointer.high, pointer.ty, pointer.confidence
            ));
        }
        text
    }
}

fn verify_abi_bytes(bytes: &[AbiByte], arguments: bool, errors: &mut Vec<AnalysisError>) {
    for (index, byte) in bytes.iter().enumerate() {
        let expected = if arguments {
            argument_state(index)
        } else {
            return_state(index)
        };
        if byte.index != index || Some(byte.location) != expected {
            errors.push(AnalysisError::new(
                "recovered ABI bytes do not form a canonical prefix",
            ));
            return;
        }
    }
}

fn strictly_sorted<T: Ord>(values: &[T]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

fn strictly_sorted_by<T, K: Ord>(values: &[T], key: impl Fn(&T) -> K) -> bool {
    values.windows(2).all(|pair| key(&pair[0]) < key(&pair[1]))
}

#[cfg(test)]
mod tests {
    use nesc_disasm::{AnalysisLimits as DisassemblyLimits, disassemble};
    use nesc_rom::{Format, Metadata, Mirroring, Region, Rom, build};

    use super::{
        CallingConvention, RecoveredType, RecoveryLimits, Signedness, TypeSubject, analyze_recovery,
    };
    use crate::{
        AnalysisLimits, MemoryLocation, ValueAnalysisLimits, ValueId, analyze, analyze_values,
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

    fn recovery(program: &crate::Program) -> super::RecoveryAnalysis {
        let values = analyze_values(program, ValueAnalysisLimits::default()).expect("values");
        analyze_recovery(program, &values, RecoveryLimits::default()).expect("recovery")
    }

    #[test]
    fn recovers_conservative_nescall_bytes_from_both_sides_of_a_call() {
        let program = program(&[
            0xa9, 0x05, // lda #5
            0x20, 0x08, 0xc0, // jsr $c008
            0x85, 0x10, // sta $10
            0x60, // rts
            0x18, // clc
            0x69, 0x01, // adc #1
            0x60, // rts
        ]);
        let analysis = recovery(&program);
        assert_eq!(analysis.calls.len(), 1);
        let callee = &analysis.functions[1];
        assert_eq!(callee.convention, CallingConvention::NesCall);
        assert_eq!(callee.parameter_bytes.len(), 1);
        assert_eq!(callee.return_bytes.len(), 1);
        assert_eq!(callee.parameter_bytes[0].index, 0);
        assert_eq!(callee.return_bytes[0].index, 0);
        assert_eq!(callee.confidence, crate::Confidence::Conservative);
        assert_eq!(analysis.render_text(), analysis.render_text());
    }

    #[test]
    fn leaves_nonprefix_machine_inputs_unclassified() {
        let program = program(&[
            0xa2, 0x05, // ldx #5
            0x20, 0x06, 0xc0, // jsr $c006
            0x60, // rts
            0x8a, // txa
            0x60, // rts
        ]);
        let analysis = recovery(&program);
        let callee = &analysis.functions[1];
        assert_eq!(callee.convention, CallingConvention::Unknown);
        assert!(callee.parameter_bytes.is_empty());
        assert!(
            callee
                .unclassified_inputs
                .contains(&crate::StateVariable::Register(crate::Register::X))
        );
    }

    #[test]
    fn follows_register_bytes_into_reserved_zero_page_slots() {
        let program = program(&[
            0x20, 0x0c, 0xc0, // jsr $c00c
            0x85, 0x10, // sta $10
            0x86, 0x11, // stx $11
            0x84, 0x12, // sty $12
            0xa5, 0xf8, // lda $f8
            0x60, // rts
            0x85, 0x20, // sta $20
            0x86, 0x21, // stx $21
            0x84, 0x22, // sty $22
            0xa5, 0xf0, // lda $f0
            0x60, // rts
        ]);
        let analysis = recovery(&program);
        let callee = &analysis.functions[1];
        assert_eq!(callee.parameter_bytes.len(), 4);
        assert_eq!(callee.return_bytes.len(), 4);
        assert_eq!(
            callee.parameter_bytes[3].location,
            crate::StateVariable::Memory(MemoryLocation::ZeroPage(0xf0))
        );
        assert_eq!(
            callee.return_bytes[3].location,
            crate::StateVariable::Memory(MemoryLocation::ZeroPage(0xf8))
        );
    }

    #[test]
    fn preserves_unresolved_call_targets() {
        let program = program(&[
            0x20, 0x00, 0xc1, // jsr into undecoded data
            0x60, // rts
        ]);
        let analysis = recovery(&program);
        assert_eq!(analysis.calls.len(), 1);
        assert_eq!(analysis.calls[0].callee, None);
        assert_eq!(analysis.calls[0].target_cpu_address, 0xc100);
        assert_eq!(analysis.calls[0].confidence, crate::Confidence::Unknown);
    }

    #[test]
    fn detects_interrupt_conventions_and_recursive_calls() {
        let interrupt_program = program(&[0x40]); // rti
        let interrupt = recovery(&interrupt_program);
        assert_eq!(
            interrupt.functions[0].convention,
            CallingConvention::NesCallIrq
        );
        assert_eq!(interrupt.functions[0].call_frame_bytes, 3);

        let recursive_program = program(&[
            0x20, 0x00, 0xc0, // jsr $c000
            0x60, // rts
        ]);
        let recursive = recovery(&recursive_program);
        assert_eq!(recursive.cycles.len(), 1);
        assert_eq!(recursive.cycles[0].functions, vec![crate::FunctionId(0)]);
        assert_eq!(
            recursive.functions[0].confidence,
            crate::Confidence::Unknown
        );
    }

    #[test]
    fn recovers_unsigned_comparison_and_zero_page_pointer_facts() {
        let comparison_program = program(&[
            0xa9, 0x01, // lda #1
            0xc9, 0x02, // cmp #2
            0xb0, 0x00, // bcs $c006
            0x60, // rts
        ]);
        let comparison = recovery(&comparison_program);
        assert!(comparison.types.iter().any(|fact| {
            matches!(
                fact.ty,
                RecoveredType::Integer {
                    bits: 8,
                    signedness: Signedness::Unsigned
                }
            )
        }));

        let pointer_program = program(&[
            0xa0, 0x00, // ldy #0
            0xb1, 0x20, // lda ($20),y
            0x60, // rts
        ]);
        let pointer = recovery(&pointer_program);
        assert_eq!(pointer.pointers.len(), 1);
        assert_eq!(pointer.pointers[0].low, MemoryLocation::ZeroPage(0x20));
        assert_eq!(pointer.pointers[0].high, MemoryLocation::ZeroPage(0x21));
    }

    #[test]
    fn enforces_limits_and_verifies_type_references() {
        let program = program(&[
            0xa9, 0x05, // lda #5
            0x20, 0x08, 0xc0, // jsr $c008
            0x85, 0x10, // sta $10
            0x60, // rts
            0x18, // clc
            0x69, 0x01, // adc #1
            0x60, // rts
        ]);
        let values = analyze_values(&program, ValueAnalysisLimits::default()).expect("values");
        let error = analyze_recovery(
            &program,
            &values,
            RecoveryLimits {
                max_abi_bytes: 1,
                ..RecoveryLimits::default()
            },
        )
        .expect_err("ABI limit");
        assert!(error[0].message().contains("ABI-byte limit"));

        let mut analysis =
            analyze_recovery(&program, &values, RecoveryLimits::default()).expect("recovery");
        analysis.types[0].subject = TypeSubject {
            function: crate::FunctionId(0),
            value: ValueId(u32::MAX),
        };
        assert!(analysis.verify(&program, &values).is_err());
    }
}
