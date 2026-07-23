use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet, HashMap};

use nesc_mir::{
    Function, FunctionId, GlobalId, Instruction, InstructionKind, LocalId, Module, Terminator,
    Type, ValueId,
};

use crate::{CodegenError, CodegenGoal};

/// First internal-RAM byte reserved for arithmetic runtime helpers.
pub const RUNTIME_SCRATCH_START: u16 = 0x0700;
/// First byte after the arithmetic runtime scratch block.
pub const RUNTIME_SCRATCH_END: u16 = 0x0714;
/// First internal-RAM byte of the page-aligned shadow-OAM region reserved for
/// the runtime (mirrors `nesc_runtime::SHADOW_OAM_ADDRESS`). The DMA runtime
/// copies this 256-byte page to sprite memory, so the allocator must never
/// hand any of it to a global.
pub const SHADOW_OAM_ADDRESS: u16 = 0x0200;
/// First internal-RAM byte after the reserved 256-byte shadow-OAM page.
pub const SHADOW_OAM_END: u16 = SHADOW_OAM_ADDRESS + 0x0100;

/// Inclusive zero-page address range.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ZeroPageRange {
    /// First address.
    pub start: u8,
    /// Last address.
    pub end: u8,
}

/// Zero-page allocation priority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ZeroPageStrategy {
    /// Prioritize slots by aggregate loop-weighted access frequency.
    Frequency,
    /// Prioritize slots by estimated byte-access cycle savings.
    Cycles,
}

/// Target resource settings for code generation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BackendConfig {
    /// Instruction-selection preference.
    pub goal: CodegenGoal,
    /// Addresses the compiler may allocate.
    pub zero_page_available: Vec<ZeroPageRange>,
    /// Addresses excluded even when they overlap an available range.
    pub zero_page_reserved: Vec<ZeroPageRange>,
    /// Allocation priority.
    pub zero_page_strategy: ZeroPageStrategy,
    /// Maximum hardware-stack use in bytes.
    pub stack_limit: u16,
    /// Additional stack use declared by standalone assembly functions.
    pub external_stack_bytes: BTreeMap<String, u16>,
}

impl Default for BackendConfig {
    fn default() -> Self {
        Self {
            goal: CodegenGoal::Balanced,
            zero_page_available: vec![ZeroPageRange {
                start: 0x00,
                end: 0xef,
            }],
            zero_page_reserved: vec![ZeroPageRange {
                start: 0xf0,
                end: 0xff,
            }],
            zero_page_strategy: ZeroPageStrategy::Frequency,
            stack_limit: 192,
            external_stack_bytes: BTreeMap::new(),
        }
    }
}

/// Allocated byte-addressed storage.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Location {
    /// First byte address.
    pub address: u16,
    /// Storage width in bytes.
    pub size: u16,
    /// Whether the address uses zero-page encoding.
    pub zero_page: bool,
}

/// One allocation report entry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AllocationEntry {
    /// Diagnostic storage name.
    pub name: String,
    /// Assigned location.
    pub location: Location,
    /// Loop-weighted number of expected storage accesses.
    pub access_weight: u32,
}

/// Complete deterministic storage allocation.
#[derive(Clone, Debug)]
pub(crate) struct Allocation {
    pub globals: Vec<Location>,
    pub locals: HashMap<(FunctionId, LocalId), Location>,
    pub values: HashMap<(FunctionId, ValueId), Location>,
    pub entries: Vec<AllocationEntry>,
    pub zero_page_used: usize,
    pub zero_page_free: usize,
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
enum RequestKey {
    Global(GlobalId),
    Local(FunctionId, LocalId),
    Value(FunctionId, ValueId),
}

struct Request {
    key: RequestKey,
    name: String,
    size: u16,
    accesses: u32,
}

struct AccessCounts {
    globals: HashMap<GlobalId, u32>,
    locals: HashMap<(FunctionId, LocalId), u32>,
    values: HashMap<(FunctionId, ValueId), u32>,
}

struct FunctionStorageAnalysis {
    reusable: BTreeSet<RequestKey>,
    interferences: HashMap<RequestKey, BTreeSet<RequestKey>>,
}

struct StorageSlot {
    function: Option<FunctionId>,
    size: u16,
    access_weight: u32,
    occupants: Vec<Request>,
}

pub(crate) fn allocate(
    module: &Module,
    config: &BackendConfig,
) -> Result<Allocation, Vec<CodegenError>> {
    for range in config
        .zero_page_available
        .iter()
        .chain(&config.zero_page_reserved)
    {
        if range.start > range.end {
            return Err(vec![CodegenError {
                message: format!(
                    "invalid zero-page range ${:02X}..${:02X}",
                    range.start, range.end
                ),
                span: None,
            }]);
        }
    }
    let access_counts = access_counts(module);
    let storage_analyses = module
        .functions
        .iter()
        .filter(|function| !function.blocks.is_empty())
        .map(|function| (function.id, analyze_function_storage(function)))
        .collect::<HashMap<_, _>>();
    let mut requests = Vec::new();
    for (index, ty) in module.globals.iter().enumerate() {
        // Globals with folded constant payloads live in PRG-ROM and never
        // receive RAM storage.
        if module.global_data.get(index).is_some_and(Option::is_some) {
            continue;
        }
        requests.push(Request {
            key: RequestKey::Global(GlobalId(index as u32)),
            name: format!("global.{index}"),
            size: type_size(ty),
            accesses: access_counts
                .globals
                .get(&GlobalId(index as u32))
                .copied()
                .unwrap_or(0),
        });
    }
    for function in &module.functions {
        if function.blocks.is_empty() {
            continue;
        }
        for local in &function.locals {
            requests.push(Request {
                key: RequestKey::Local(function.id, local.id),
                name: format!("{}.local.{}", function.name, local.name),
                size: type_size(&local.ty),
                accesses: access_counts
                    .locals
                    .get(&(function.id, local.id))
                    .copied()
                    .unwrap_or(0),
            });
        }
        for (index, ty) in function.value_types.iter().enumerate() {
            requests.push(Request {
                key: RequestKey::Value(function.id, ValueId(index as u32)),
                name: format!("{}.value.{index}", function.name),
                size: type_size(ty),
                accesses: access_counts
                    .values
                    .get(&(function.id, ValueId(index as u32)))
                    .copied()
                    .unwrap_or(0),
            });
        }
    }
    let slots = form_storage_slots(requests, &storage_analyses, config.zero_page_strategy);

    let mut available = [false; 256];
    for range in &config.zero_page_available {
        for address in range.start..=range.end {
            available[usize::from(address)] = true;
        }
    }
    for range in &config.zero_page_reserved {
        for address in range.start..=range.end {
            available[usize::from(address)] = false;
        }
    }
    available[0xf0..=0xff].fill(false);
    let total_available = available.iter().filter(|slot| **slot).count();
    // Internal-RAM globals bump-allocate above the reserved shadow-OAM page so
    // the DMA source page is never overwritten by compiler storage.
    let mut internal_cursor = SHADOW_OAM_END;
    let mut globals = vec![
        Location {
            address: 0,
            size: 0,
            zero_page: false,
        };
        module.globals.len()
    ];
    let mut locals = HashMap::new();
    let mut values = HashMap::new();
    let mut entries = Vec::new();
    let mut zero_page_used = 0;
    // Free bytes below the runtime arithmetic scratch that a wider request had
    // to skip over. Reclaimed for later requests small enough to fit so the
    // fixed scratch hole does not waste internal RAM.
    let mut scratch_gap: Option<(u16, u16)> = None;

    for slot in slots {
        let location = find_zero_page(&available, slot.size).map_or_else(
            || {
                if let Some((gap_start, gap_end)) = scratch_gap {
                    if slot.size <= gap_end - gap_start {
                        let address = gap_start;
                        let next = gap_start + slot.size;
                        scratch_gap = (next < gap_end).then_some((next, gap_end));
                        return Location {
                            address,
                            size: slot.size,
                            zero_page: false,
                        };
                    }
                }
                if internal_cursor < RUNTIME_SCRATCH_END
                    && internal_cursor.saturating_add(slot.size) > RUNTIME_SCRATCH_START
                {
                    if internal_cursor < RUNTIME_SCRATCH_START {
                        scratch_gap = Some((internal_cursor, RUNTIME_SCRATCH_START));
                    }
                    internal_cursor = RUNTIME_SCRATCH_END;
                }
                let location = Location {
                    address: internal_cursor,
                    size: slot.size,
                    zero_page: false,
                };
                internal_cursor = internal_cursor.saturating_add(slot.size);
                location
            },
            |start| {
                available[start..start + usize::from(slot.size)].fill(false);
                zero_page_used += usize::from(slot.size);
                Location {
                    address: start as u16,
                    size: slot.size,
                    zero_page: true,
                }
            },
        );
        if location.address.saturating_add(location.size) > 0x0800 {
            return Err(vec![CodegenError {
                message: "compiler storage exceeds the 2 KiB internal RAM capacity".to_owned(),
                span: None,
            }]);
        }
        for request in slot.occupants {
            match request.key {
                RequestKey::Global(global) => globals[global.0 as usize] = location,
                RequestKey::Local(function, local) => {
                    locals.insert((function, local), location);
                }
                RequestKey::Value(function, value) => {
                    values.insert((function, value), location);
                }
            }
            entries.push(AllocationEntry {
                name: request.name,
                location,
                access_weight: request.accesses,
            });
        }
    }

    Ok(Allocation {
        globals,
        locals,
        values,
        entries,
        zero_page_used,
        zero_page_free: total_available.saturating_sub(zero_page_used),
    })
}

fn form_storage_slots(
    mut requests: Vec<Request>,
    analyses: &HashMap<FunctionId, FunctionStorageAnalysis>,
    strategy: ZeroPageStrategy,
) -> Vec<StorageSlot> {
    requests.sort_by_key(|request| {
        let degree = request_function(request.key)
            .and_then(|function| analyses.get(&function))
            .and_then(|analysis| analysis.interferences.get(&request.key))
            .map_or(0, BTreeSet::len);
        (
            Reverse(degree),
            Reverse(spill_cost(request.accesses, request.size, strategy)),
        )
    });

    let mut slots = Vec::<StorageSlot>::new();
    for request in requests {
        let function = request_function(request.key);
        let analysis = function.and_then(|function| analyses.get(&function));
        let reusable = analysis.is_some_and(|analysis| analysis.reusable.contains(&request.key));
        let reusable_slot = if reusable {
            slots.iter().position(|slot| {
                slot.function == function
                    && slot.size == request.size
                    && slot.occupants.iter().all(|occupant| {
                        !analysis.is_some_and(|analysis| {
                            analysis
                                .interferences
                                .get(&request.key)
                                .is_some_and(|neighbors| neighbors.contains(&occupant.key))
                        })
                    })
            })
        } else {
            None
        };
        if let Some(index) = reusable_slot {
            let slot = &mut slots[index];
            slot.access_weight = slot.access_weight.saturating_add(request.accesses);
            slot.occupants.push(request);
        } else {
            slots.push(StorageSlot {
                function: reusable.then_some(function).flatten(),
                size: request.size,
                access_weight: request.accesses,
                occupants: vec![request],
            });
        }
    }
    slots.sort_by_key(|slot| Reverse(spill_cost(slot.access_weight, slot.size, strategy)));
    slots
}

fn spill_cost(access_weight: u32, size: u16, strategy: ZeroPageStrategy) -> u64 {
    match strategy {
        ZeroPageStrategy::Frequency => u64::from(access_weight),
        ZeroPageStrategy::Cycles => u64::from(access_weight) * u64::from(size),
    }
}

fn request_function(key: RequestKey) -> Option<FunctionId> {
    match key {
        RequestKey::Local(function, _) | RequestKey::Value(function, _) => Some(function),
        RequestKey::Global(_) => None,
    }
}

fn analyze_function_storage(function: &Function) -> FunctionStorageAnalysis {
    let mut pinned_locals = function
        .locals
        .iter()
        .filter(|local| {
            local.parameter || local.ty.is_volatile || !local.ty.array_lengths.is_empty()
        })
        .map(|local| local.id)
        .collect::<BTreeSet<_>>();
    for block in &function.blocks {
        for instruction in &block.instructions {
            if let InstructionKind::AddressOfLocal(local) = instruction.kind {
                pinned_locals.insert(local);
            }
        }
    }

    let mut reusable = function
        .locals
        .iter()
        .filter(|local| !pinned_locals.contains(&local.id))
        .map(|local| RequestKey::Local(function.id, local.id))
        .collect::<BTreeSet<_>>();
    reusable.extend(
        function
            .value_types
            .iter()
            .enumerate()
            .map(|(index, _)| RequestKey::Value(function.id, ValueId(index as u32))),
    );

    let mut uses = vec![BTreeSet::new(); function.blocks.len()];
    let mut definitions = vec![BTreeSet::new(); function.blocks.len()];
    for block in &function.blocks {
        let index = block.id.0 as usize;
        for instruction in &block.instructions {
            let (instruction_uses, instruction_definitions) =
                instruction_storage(function.id, instruction, &reusable);
            for key in instruction_uses {
                if !definitions[index].contains(&key) {
                    uses[index].insert(key);
                }
            }
            definitions[index].extend(instruction_definitions);
        }
        if let Some(terminator) = &block.terminator {
            for key in terminator_storage(function.id, terminator) {
                if !definitions[index].contains(&key) {
                    uses[index].insert(key);
                }
            }
        }
    }

    let mut live_in = vec![BTreeSet::new(); function.blocks.len()];
    let mut live_out = vec![BTreeSet::new(); function.blocks.len()];
    loop {
        let mut changed = false;
        for block in function.blocks.iter().rev() {
            let index = block.id.0 as usize;
            let mut outgoing = BTreeSet::new();
            if let Some(terminator) = &block.terminator {
                for successor in terminator_successors(terminator) {
                    outgoing.extend(live_in[successor.0 as usize].iter().copied());
                }
            }
            let mut incoming = uses[index].clone();
            incoming.extend(outgoing.difference(&definitions[index]).copied());
            if outgoing != live_out[index] || incoming != live_in[index] {
                live_out[index] = outgoing;
                live_in[index] = incoming;
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }

    let mut interferences = reusable
        .iter()
        .copied()
        .map(|key| (key, BTreeSet::new()))
        .collect::<HashMap<_, _>>();
    for block in &function.blocks {
        let mut live = live_out[block.id.0 as usize].clone();
        if let Some(terminator) = &block.terminator {
            let term_uses = terminator_storage(function.id, terminator);
            connect_uses(&mut interferences, &term_uses, &live);
            live.extend(term_uses);
        }
        for instruction in block.instructions.iter().rev() {
            let (instruction_uses, instruction_definitions) =
                instruction_storage(function.id, instruction, &reusable);
            for definition in &instruction_definitions {
                connect_key_to_set(&mut interferences, *definition, &live);
                connect_key_to_keys(&mut interferences, *definition, &instruction_uses);
                connect_key_to_keys(&mut interferences, *definition, &instruction_definitions);
            }
            for definition in &instruction_definitions {
                live.remove(definition);
            }
            connect_uses(&mut interferences, &instruction_uses, &live);
            live.extend(instruction_uses);
        }
    }
    FunctionStorageAnalysis {
        reusable,
        interferences,
    }
}

fn instruction_storage(
    function: FunctionId,
    instruction: &Instruction,
    reusable: &BTreeSet<RequestKey>,
) -> (Vec<RequestKey>, Vec<RequestKey>) {
    let uses = instruction_operands(&instruction.kind)
        .into_iter()
        .map(|value| RequestKey::Value(function, value))
        .collect::<Vec<_>>();
    let mut definitions = instruction
        .result
        .map(|value| vec![RequestKey::Value(function, value)])
        .unwrap_or_default();
    let mut uses = uses;
    match &instruction.kind {
        InstructionKind::LoadLocal(local) => {
            let key = RequestKey::Local(function, *local);
            if reusable.contains(&key) {
                uses.push(key);
            }
        }
        InstructionKind::StoreLocal { local, .. } => {
            let key = RequestKey::Local(function, *local);
            if reusable.contains(&key) {
                definitions.push(key);
            }
        }
        InstructionKind::InlineAssembly(assembly) => {
            definitions.extend(assembly.outputs.iter().filter_map(|output| {
                let nesc_mir::AssemblyOutputTarget::Local(local) = output.target else {
                    return None;
                };
                let key = RequestKey::Local(function, local);
                reusable.contains(&key).then_some(key)
            }));
        }
        _ => {}
    }
    (uses, definitions)
}

fn instruction_operands(kind: &InstructionKind) -> Vec<ValueId> {
    match kind {
        InstructionKind::Constant(_)
        | InstructionKind::LoadLocal(_)
        | InstructionKind::LoadGlobal(_)
        | InstructionKind::AddressOfLocal(_)
        | InstructionKind::AddressOfGlobal(_) => Vec::new(),
        InstructionKind::StoreLocal { value, .. }
        | InstructionKind::StoreGlobal { value, .. }
        | InstructionKind::Cast { value, .. } => vec![*value],
        InstructionKind::BoundsCheck { index, .. } => vec![*index],
        InstructionKind::PointerOffset { base, offset, .. }
        | InstructionKind::Binary {
            left: base,
            right: offset,
            ..
        } => vec![*base, *offset],
        InstructionKind::LoadIndirect { address, .. }
        | InstructionKind::Unary {
            operand: address, ..
        } => vec![*address],
        InstructionKind::StoreIndirect { address, value, .. } => vec![*address, *value],
        InstructionKind::Call { arguments, .. } => arguments.clone(),
        InstructionKind::InlineAssembly(assembly) => {
            assembly.inputs.iter().map(|input| input.value).collect()
        }
    }
}

fn terminator_storage(function: FunctionId, terminator: &Terminator) -> Vec<RequestKey> {
    match terminator {
        Terminator::Branch { condition, .. } => {
            vec![RequestKey::Value(function, *condition)]
        }
        Terminator::Return(Some(value)) => vec![RequestKey::Value(function, *value)],
        Terminator::Jump(_) | Terminator::Return(None) | Terminator::Unreachable => Vec::new(),
    }
}

fn terminator_successors(terminator: &Terminator) -> Vec<nesc_mir::BlockId> {
    match terminator {
        Terminator::Jump(target) => vec![*target],
        Terminator::Branch {
            then_block,
            else_block,
            ..
        } => vec![*then_block, *else_block],
        Terminator::Return(_) | Terminator::Unreachable => Vec::new(),
    }
}

fn connect_uses(
    interferences: &mut HashMap<RequestKey, BTreeSet<RequestKey>>,
    keys: &[RequestKey],
    live: &BTreeSet<RequestKey>,
) {
    for key in keys {
        connect_key_to_set(interferences, *key, live);
    }
    for (index, key) in keys.iter().enumerate() {
        connect_key_to_keys(interferences, *key, &keys[index + 1..]);
    }
}

fn connect_key_to_set(
    interferences: &mut HashMap<RequestKey, BTreeSet<RequestKey>>,
    key: RequestKey,
    others: &BTreeSet<RequestKey>,
) {
    for other in others {
        connect_keys(interferences, key, *other);
    }
}

fn connect_key_to_keys(
    interferences: &mut HashMap<RequestKey, BTreeSet<RequestKey>>,
    key: RequestKey,
    others: &[RequestKey],
) {
    for other in others {
        connect_keys(interferences, key, *other);
    }
}

fn connect_keys(
    interferences: &mut HashMap<RequestKey, BTreeSet<RequestKey>>,
    left: RequestKey,
    right: RequestKey,
) {
    if left == right {
        return;
    }
    if let Some(neighbors) = interferences.get_mut(&left) {
        neighbors.insert(right);
    }
    if let Some(neighbors) = interferences.get_mut(&right) {
        neighbors.insert(left);
    }
}

fn access_counts(module: &Module) -> AccessCounts {
    let mut globals = HashMap::new();
    let mut locals = HashMap::new();
    let mut values = HashMap::new();
    for function in &module.functions {
        let control_flow = nesc_opt::analyze_control_flow(function);
        for block in &function.blocks {
            let weight = control_flow.block_frequency(block.id);
            for instruction in &block.instructions {
                if let Some(result) = instruction.result {
                    bump_by(&mut values, (function.id, result), weight);
                }
                match &instruction.kind {
                    InstructionKind::Constant(_) => {}
                    InstructionKind::LoadLocal(local) => {
                        bump_by(&mut locals, (function.id, *local), weight);
                    }
                    InstructionKind::StoreLocal { local, value } => {
                        bump_by(&mut locals, (function.id, *local), weight);
                        bump_by(&mut values, (function.id, *value), weight);
                    }
                    InstructionKind::LoadGlobal(global) => {
                        bump_by(&mut globals, *global, weight);
                    }
                    InstructionKind::StoreGlobal { global, value } => {
                        bump_by(&mut globals, *global, weight);
                        bump_by(&mut values, (function.id, *value), weight);
                    }
                    InstructionKind::AddressOfLocal(local) => {
                        bump_by(&mut locals, (function.id, *local), weight);
                    }
                    InstructionKind::AddressOfGlobal(global) => {
                        bump_by(&mut globals, *global, weight);
                    }
                    InstructionKind::BoundsCheck { index, .. }
                    | InstructionKind::LoadIndirect { address: index, .. } => {
                        bump_by(&mut values, (function.id, *index), weight);
                    }
                    InstructionKind::PointerOffset { base, offset, .. } => {
                        bump_by(&mut values, (function.id, *base), weight);
                        bump_by(&mut values, (function.id, *offset), weight);
                    }
                    InstructionKind::StoreIndirect { address, value, .. } => {
                        bump_by(&mut values, (function.id, *address), weight);
                        bump_by(&mut values, (function.id, *value), weight);
                    }
                    InstructionKind::Unary { operand, .. } => {
                        bump_by(&mut values, (function.id, *operand), weight);
                    }
                    InstructionKind::Binary { left, right, .. } => {
                        bump_by(&mut values, (function.id, *left), weight);
                        bump_by(&mut values, (function.id, *right), weight);
                    }
                    InstructionKind::Cast { value, .. } => {
                        bump_by(&mut values, (function.id, *value), weight);
                    }
                    InstructionKind::Call { arguments, .. } => {
                        for argument in arguments {
                            bump_by(&mut values, (function.id, *argument), weight);
                        }
                    }
                    InstructionKind::InlineAssembly(assembly) => {
                        for input in &assembly.inputs {
                            bump_by(&mut values, (function.id, input.value), weight);
                        }
                        for output in &assembly.outputs {
                            match output.target {
                                nesc_mir::AssemblyOutputTarget::Local(local) => {
                                    bump_by(&mut locals, (function.id, local), weight);
                                }
                                nesc_mir::AssemblyOutputTarget::Global(global) => {
                                    bump_by(&mut globals, global, weight);
                                }
                            }
                        }
                    }
                }
            }
            match &block.terminator {
                Some(Terminator::Branch { condition, .. }) => {
                    bump_by(&mut values, (function.id, *condition), weight);
                }
                Some(Terminator::Return(Some(value))) => {
                    bump_by(&mut values, (function.id, *value), weight);
                }
                _ => {}
            }
        }
    }
    AccessCounts {
        globals,
        locals,
        values,
    }
}

fn bump_by<Key: Eq + std::hash::Hash>(counts: &mut HashMap<Key, u32>, key: Key, weight: u32) {
    if weight == 0 {
        return;
    }
    let count = counts.entry(key).or_default();
    *count = count.saturating_add(weight);
}

pub(crate) fn type_size(ty: &Type) -> u16 {
    let element_size = if ty.pointer_depth > 0 {
        2
    } else {
        u16::from(ty.integer_width().unwrap_or(0).div_ceil(8).max(1))
    };
    ty.array_lengths.iter().fold(element_size, |size, length| {
        size.saturating_mul(u16::try_from(*length).unwrap_or(u16::MAX))
    })
}

fn find_zero_page(available: &[bool; 256], size: u16) -> Option<usize> {
    let size = usize::from(size);
    if size == 0 || size > available.len() {
        return None;
    }
    (0..=available.len() - size)
        .find(|start| available[*start..*start + size].iter().all(|slot| *slot))
}

pub(crate) fn render_report(allocation: &Allocation) -> String {
    let mut report = String::from("Zero-page allocation\n--------------------\n");
    let mut slots = BTreeMap::<(u16, u16), Vec<&AllocationEntry>>::new();
    for entry in allocation
        .entries
        .iter()
        .filter(|entry| entry.location.zero_page)
    {
        slots
            .entry((entry.location.address, entry.location.size))
            .or_default()
            .push(entry);
    }
    for ((address, size), occupants) in slots {
        let end = address + size - 1;
        let names = occupants
            .iter()
            .map(|entry| entry.name.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        let access_weight = occupants.iter().fold(0_u32, |total, entry| {
            total.saturating_add(entry.access_weight)
        });
        let shared = if occupants.len() > 1 { ", shared" } else { "" };
        if end == address {
            report.push_str(&format!(
                "${address:02X}      {names} (weight {access_weight}{shared})\n"
            ));
        } else {
            report.push_str(&format!(
                "${address:02X}-${end:02X} {names} (weight {access_weight}{shared})\n"
            ));
        }
    }
    report.push_str(&format!(
        "\nUsed: {} bytes\nFree: {} bytes\n",
        allocation.zero_page_used, allocation.zero_page_free
    ));
    report
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use nesc_mir::{
        BankPlacement, BasicBlock, BinaryOperator, BlockId, Effect, Function, FunctionId,
        Instruction, InstructionKind, Local, LocalId, Module, SourceId, SourceSpan, Terminator,
        Type, TypeKind, ValueId,
    };

    use super::{
        BackendConfig, RUNTIME_SCRATCH_END, RUNTIME_SCRATCH_START, Request, RequestKey,
        SHADOW_OAM_END, ZeroPageRange, ZeroPageStrategy, access_counts, allocate,
        form_storage_slots, render_report,
    };

    #[test]
    fn weights_loop_body_accesses_above_cold_accesses() {
        let ty = Type::scalar(TypeKind::Bool);
        let span = SourceSpan::new(SourceId::new(0), 0, 1);
        let module = Module {
            globals: Vec::new(),
            global_data: Vec::new(),
            functions: vec![Function {
                id: FunctionId(0),
                name: "weighted".to_owned(),
                placement: BankPlacement::Fixed,
                return_type: Type::scalar(TypeKind::Void),
                parameters: Vec::new(),
                locals: vec![
                    Local {
                        id: LocalId(0),
                        name: "cold".to_owned(),
                        ty: ty.clone(),
                        parameter: false,
                    },
                    Local {
                        id: LocalId(1),
                        name: "hot".to_owned(),
                        ty: ty.clone(),
                        parameter: false,
                    },
                ],
                entry: Some(BlockId(0)),
                blocks: vec![
                    BasicBlock {
                        id: BlockId(0),
                        instructions: vec![
                            Instruction {
                                result: Some(ValueId(0)),
                                kind: InstructionKind::Constant(1),
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
                                kind: InstructionKind::LoadLocal(LocalId(0)),
                                effect: Effect::Read,
                                span,
                            },
                        ],
                        terminator: Some(Terminator::Jump(BlockId(1))),
                    },
                    BasicBlock {
                        id: BlockId(1),
                        instructions: vec![Instruction {
                            result: Some(ValueId(2)),
                            kind: InstructionKind::LoadLocal(LocalId(1)),
                            effect: Effect::Read,
                            span,
                        }],
                        terminator: Some(Terminator::Branch {
                            condition: ValueId(2),
                            then_block: BlockId(2),
                            else_block: BlockId(3),
                        }),
                    },
                    BasicBlock {
                        id: BlockId(2),
                        instructions: vec![Instruction {
                            result: None,
                            kind: InstructionKind::StoreLocal {
                                local: LocalId(1),
                                value: ValueId(0),
                            },
                            effect: Effect::Write,
                            span,
                        }],
                        terminator: Some(Terminator::Jump(BlockId(1))),
                    },
                    BasicBlock {
                        id: BlockId(3),
                        instructions: Vec::new(),
                        terminator: Some(Terminator::Return(None)),
                    },
                ],
                value_types: vec![ty.clone(), ty.clone(), ty],
            }],
        };

        let counts = access_counts(&module);

        assert_eq!(counts.locals[&(FunctionId(0), LocalId(0))], 2);
        assert_eq!(counts.locals[&(FunctionId(0), LocalId(1))], 20);
    }

    #[test]
    fn reuses_storage_for_nonoverlapping_values() {
        let ty = Type::scalar(TypeKind::Integer(nesc_mir::IntegerType::U8));
        let span = SourceSpan::new(SourceId::new(0), 0, 1);
        let module = Module {
            globals: Vec::new(),
            global_data: Vec::new(),
            functions: vec![Function {
                id: FunctionId(0),
                name: "reuse".to_owned(),
                placement: BankPlacement::Fixed,
                return_type: Type::scalar(TypeKind::Void),
                parameters: Vec::new(),
                locals: vec![Local {
                    id: LocalId(0),
                    name: "destination".to_owned(),
                    ty: ty.clone(),
                    parameter: false,
                }],
                entry: Some(BlockId(0)),
                blocks: vec![BasicBlock {
                    id: BlockId(0),
                    instructions: vec![
                        Instruction {
                            result: Some(ValueId(0)),
                            kind: InstructionKind::Constant(1),
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
                            kind: InstructionKind::Constant(2),
                            effect: Effect::Pure,
                            span,
                        },
                        Instruction {
                            result: None,
                            kind: InstructionKind::StoreLocal {
                                local: LocalId(0),
                                value: ValueId(1),
                            },
                            effect: Effect::Write,
                            span,
                        },
                    ],
                    terminator: Some(Terminator::Return(None)),
                }],
                value_types: vec![ty.clone(), ty],
            }],
        };
        let allocation = allocate(
            &module,
            &BackendConfig {
                zero_page_available: Vec::new(),
                zero_page_reserved: Vec::new(),
                ..BackendConfig::default()
            },
        )
        .expect("reusable allocation");

        assert_eq!(
            allocation.values[&(FunctionId(0), ValueId(0))].address,
            allocation.values[&(FunctionId(0), ValueId(1))].address
        );
    }

    #[test]
    fn reuses_storage_for_nonoverlapping_source_locals() {
        let ty = Type::scalar(TypeKind::Integer(nesc_mir::IntegerType::U8));
        let span = SourceSpan::new(SourceId::new(0), 0, 1);
        let module = Module {
            globals: Vec::new(),
            global_data: Vec::new(),
            functions: vec![Function {
                id: FunctionId(0),
                name: "locals".to_owned(),
                placement: BankPlacement::Fixed,
                return_type: ty.clone(),
                parameters: Vec::new(),
                locals: vec![
                    Local {
                        id: LocalId(0),
                        name: "first".to_owned(),
                        ty: ty.clone(),
                        parameter: false,
                    },
                    Local {
                        id: LocalId(1),
                        name: "second".to_owned(),
                        ty: ty.clone(),
                        parameter: false,
                    },
                ],
                entry: Some(BlockId(0)),
                blocks: vec![BasicBlock {
                    id: BlockId(0),
                    instructions: vec![
                        Instruction {
                            result: Some(ValueId(0)),
                            kind: InstructionKind::Constant(1),
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
                            kind: InstructionKind::LoadLocal(LocalId(0)),
                            effect: Effect::Read,
                            span,
                        },
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
                        Instruction {
                            result: Some(ValueId(3)),
                            kind: InstructionKind::LoadLocal(LocalId(1)),
                            effect: Effect::Read,
                            span,
                        },
                    ],
                    terminator: Some(Terminator::Return(Some(ValueId(3)))),
                }],
                value_types: vec![ty.clone(), ty.clone(), ty.clone(), ty],
            }],
        };
        let allocation = allocate(
            &module,
            &BackendConfig {
                zero_page_available: Vec::new(),
                zero_page_reserved: Vec::new(),
                ..BackendConfig::default()
            },
        )
        .expect("source-local reuse");

        assert_eq!(
            allocation.locals[&(FunctionId(0), LocalId(0))].address,
            allocation.locals[&(FunctionId(0), LocalId(1))].address
        );
    }

    #[test]
    fn pins_parameters_and_address_taken_locals() {
        let ty = Type::scalar(TypeKind::Integer(nesc_mir::IntegerType::U8));
        let pointer = Type {
            pointer_depth: 1,
            ..ty.clone()
        };
        let span = SourceSpan::new(SourceId::new(0), 0, 1);
        let module = Module {
            globals: Vec::new(),
            global_data: Vec::new(),
            functions: vec![Function {
                id: FunctionId(0),
                name: "pinned".to_owned(),
                placement: BankPlacement::Fixed,
                return_type: pointer.clone(),
                parameters: vec![LocalId(0)],
                locals: vec![
                    Local {
                        id: LocalId(0),
                        name: "parameter".to_owned(),
                        ty: ty.clone(),
                        parameter: true,
                    },
                    Local {
                        id: LocalId(1),
                        name: "addressed".to_owned(),
                        ty,
                        parameter: false,
                    },
                ],
                entry: Some(BlockId(0)),
                blocks: vec![BasicBlock {
                    id: BlockId(0),
                    instructions: vec![Instruction {
                        result: Some(ValueId(0)),
                        kind: InstructionKind::AddressOfLocal(LocalId(1)),
                        effect: Effect::Pure,
                        span,
                    }],
                    terminator: Some(Terminator::Return(Some(ValueId(0)))),
                }],
                value_types: vec![pointer],
            }],
        };
        let allocation = allocate(
            &module,
            &BackendConfig {
                zero_page_available: Vec::new(),
                zero_page_reserved: Vec::new(),
                ..BackendConfig::default()
            },
        )
        .expect("pinned allocation");
        let parameter = allocation.locals[&(FunctionId(0), LocalId(0))];
        let addressed = allocation.locals[&(FunctionId(0), LocalId(1))];

        assert_ne!(parameter.address, addressed.address);
        assert_ne!(
            addressed.address,
            allocation.values[&(FunctionId(0), ValueId(0))].address
        );
    }

    #[test]
    fn aggregates_shared_slot_cost_before_zero_page_placement() {
        let ty = Type::scalar(TypeKind::Integer(nesc_mir::IntegerType::U8));
        let span = SourceSpan::new(SourceId::new(0), 0, 1);
        let mut instructions = Vec::new();
        for value in 0..3 {
            instructions.push(Instruction {
                result: Some(ValueId(value)),
                kind: InstructionKind::LoadGlobal(nesc_mir::GlobalId(0)),
                effect: Effect::Read,
                span,
            });
        }
        for value in 3..7 {
            instructions.push(Instruction {
                result: Some(ValueId(value)),
                kind: InstructionKind::Constant(u64::from(value)),
                effect: Effect::Pure,
                span,
            });
        }
        let module = Module {
            globals: vec![ty.clone()],
            global_data: Vec::new(),
            functions: vec![Function {
                id: FunctionId(0),
                name: "aggregate".to_owned(),
                placement: BankPlacement::Fixed,
                return_type: Type::scalar(TypeKind::Void),
                parameters: Vec::new(),
                locals: Vec::new(),
                entry: Some(BlockId(0)),
                blocks: vec![BasicBlock {
                    id: BlockId(0),
                    instructions,
                    terminator: Some(Terminator::Return(None)),
                }],
                value_types: vec![ty; 7],
            }],
        };
        let allocation = allocate(
            &module,
            &BackendConfig {
                zero_page_available: vec![ZeroPageRange { start: 2, end: 2 }],
                zero_page_reserved: Vec::new(),
                ..BackendConfig::default()
            },
        )
        .expect("aggregate spill cost");

        assert!(!allocation.globals[0].zero_page);
        for value in 0..7 {
            assert!(allocation.values[&(FunctionId(0), ValueId(value))].zero_page);
        }
        assert_eq!(allocation.zero_page_used, 1);
        assert!(render_report(&allocation).contains("(weight 7, shared)"));
    }

    #[test]
    fn spill_strategies_make_distinct_width_tradeoffs() {
        let requests = || {
            vec![
                Request {
                    key: RequestKey::Global(nesc_mir::GlobalId(0)),
                    name: "frequent-byte".to_owned(),
                    size: 1,
                    accesses: 5,
                },
                Request {
                    key: RequestKey::Global(nesc_mir::GlobalId(1)),
                    name: "cycle-heavy-word".to_owned(),
                    size: 2,
                    accesses: 3,
                },
            ]
        };
        let analyses = HashMap::new();

        let frequency = form_storage_slots(requests(), &analyses, ZeroPageStrategy::Frequency);
        let cycles = form_storage_slots(requests(), &analyses, ZeroPageStrategy::Cycles);

        assert!(matches!(
            frequency[0].occupants[0].key,
            RequestKey::Global(nesc_mir::GlobalId(0))
        ));
        assert!(matches!(
            cycles[0].occupants[0].key,
            RequestKey::Global(nesc_mir::GlobalId(1))
        ));
    }

    #[test]
    fn keeps_value_storage_isolated_between_functions() {
        let ty = Type::scalar(TypeKind::Integer(nesc_mir::IntegerType::U8));
        let span = SourceSpan::new(SourceId::new(0), 0, 1);
        let function = |id: u32, name: &str| Function {
            id: FunctionId(id),
            name: name.to_owned(),
            placement: BankPlacement::Fixed,
            return_type: ty.clone(),
            parameters: Vec::new(),
            locals: Vec::new(),
            entry: Some(BlockId(0)),
            blocks: vec![BasicBlock {
                id: BlockId(0),
                instructions: vec![Instruction {
                    result: Some(ValueId(0)),
                    kind: InstructionKind::Constant(u64::from(id)),
                    effect: Effect::Pure,
                    span,
                }],
                terminator: Some(Terminator::Return(Some(ValueId(0)))),
            }],
            value_types: vec![ty.clone()],
        };
        let module = Module {
            globals: Vec::new(),
            global_data: Vec::new(),
            functions: vec![function(0, "main"), function(1, "nmi")],
        };
        let allocation = allocate(
            &module,
            &BackendConfig {
                zero_page_available: Vec::new(),
                zero_page_reserved: Vec::new(),
                ..BackendConfig::default()
            },
        )
        .expect("function-isolated allocation");

        assert_ne!(
            allocation.values[&(FunctionId(0), ValueId(0))].address,
            allocation.values[&(FunctionId(1), ValueId(0))].address
        );
    }

    #[test]
    fn keeps_simultaneous_operands_and_results_in_distinct_storage() {
        let ty = Type::scalar(TypeKind::Integer(nesc_mir::IntegerType::U8));
        let span = SourceSpan::new(SourceId::new(0), 0, 1);
        let module = Module {
            globals: Vec::new(),
            global_data: Vec::new(),
            functions: vec![Function {
                id: FunctionId(0),
                name: "overlap".to_owned(),
                placement: BankPlacement::Fixed,
                return_type: ty.clone(),
                parameters: Vec::new(),
                locals: Vec::new(),
                entry: Some(BlockId(0)),
                blocks: vec![BasicBlock {
                    id: BlockId(0),
                    instructions: vec![
                        Instruction {
                            result: Some(ValueId(0)),
                            kind: InstructionKind::Constant(1),
                            effect: Effect::Pure,
                            span,
                        },
                        Instruction {
                            result: Some(ValueId(1)),
                            kind: InstructionKind::Constant(2),
                            effect: Effect::Pure,
                            span,
                        },
                        Instruction {
                            result: Some(ValueId(2)),
                            kind: InstructionKind::Binary {
                                operator: BinaryOperator::Add,
                                left: ValueId(0),
                                right: ValueId(1),
                            },
                            effect: Effect::Pure,
                            span,
                        },
                    ],
                    terminator: Some(Terminator::Return(Some(ValueId(2)))),
                }],
                value_types: vec![ty.clone(), ty.clone(), ty],
            }],
        };
        let allocation = allocate(
            &module,
            &BackendConfig {
                zero_page_available: Vec::new(),
                zero_page_reserved: Vec::new(),
                ..BackendConfig::default()
            },
        )
        .expect("interference-aware allocation");
        let locations = [ValueId(0), ValueId(1), ValueId(2)]
            .map(|value| allocation.values[&(FunctionId(0), value)].address);

        assert_ne!(locations[0], locations[1]);
        assert_ne!(locations[0], locations[2]);
        assert_ne!(locations[1], locations[2]);
    }

    #[test]
    fn promotes_hot_loop_storage_before_cold_storage() {
        let ty = Type::scalar(TypeKind::Bool);
        let span = SourceSpan::new(SourceId::new(0), 0, 1);
        let module = Module {
            globals: vec![ty.clone(), ty.clone()],
            global_data: Vec::new(),
            functions: vec![Function {
                id: FunctionId(0),
                name: "weighted".to_owned(),
                placement: BankPlacement::Fixed,
                return_type: Type::scalar(TypeKind::Void),
                parameters: Vec::new(),
                locals: Vec::new(),
                entry: Some(BlockId(0)),
                blocks: vec![
                    BasicBlock {
                        id: BlockId(0),
                        instructions: vec![
                            Instruction {
                                result: Some(ValueId(0)),
                                kind: InstructionKind::Constant(1),
                                effect: Effect::Pure,
                                span,
                            },
                            Instruction {
                                result: None,
                                kind: InstructionKind::StoreGlobal {
                                    global: nesc_mir::GlobalId(0),
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
                        instructions: Vec::new(),
                        terminator: Some(Terminator::Branch {
                            condition: ValueId(0),
                            then_block: BlockId(2),
                            else_block: BlockId(3),
                        }),
                    },
                    BasicBlock {
                        id: BlockId(2),
                        instructions: vec![Instruction {
                            result: None,
                            kind: InstructionKind::StoreGlobal {
                                global: nesc_mir::GlobalId(1),
                                value: ValueId(0),
                            },
                            effect: Effect::Write,
                            span,
                        }],
                        terminator: Some(Terminator::Jump(BlockId(1))),
                    },
                    BasicBlock {
                        id: BlockId(3),
                        instructions: Vec::new(),
                        terminator: Some(Terminator::Return(None)),
                    },
                ],
                value_types: vec![ty],
            }],
        };
        let allocation = allocate(
            &module,
            &BackendConfig {
                zero_page_available: vec![ZeroPageRange { start: 2, end: 3 }],
                zero_page_reserved: Vec::new(),
                ..BackendConfig::default()
            },
        )
        .expect("weighted allocation");

        assert!(!allocation.globals[0].zero_page);
        assert!(allocation.globals[1].zero_page);
        assert!(allocation.values[&(FunctionId(0), ValueId(0))].zero_page);
    }

    #[test]
    fn respects_available_and_reserved_ranges() {
        let module = Module {
            functions: Vec::new(),
            global_data: Vec::new(),
            globals: vec![
                Type::scalar(TypeKind::Integer(nesc_mir::IntegerType::U16)),
                Type::scalar(TypeKind::Integer(nesc_mir::IntegerType::U8)),
            ],
        };
        let config = BackendConfig {
            zero_page_available: vec![ZeroPageRange { start: 2, end: 7 }],
            zero_page_reserved: vec![ZeroPageRange { start: 3, end: 3 }],
            ..BackendConfig::default()
        };
        let allocation = allocate(&module, &config).expect("allocation");
        assert_eq!(allocation.globals[0].address, 4);
        assert_eq!(allocation.globals[1].address, 2);
    }

    #[test]
    fn reserves_complete_array_storage() {
        let mut array = Type::scalar(TypeKind::Integer(nesc_mir::IntegerType::U16));
        array.array_lengths.push(32);
        let module = Module {
            functions: Vec::new(),
            global_data: Vec::new(),
            globals: vec![
                array,
                Type::scalar(TypeKind::Integer(nesc_mir::IntegerType::U8)),
            ],
        };
        let config = BackendConfig {
            zero_page_available: vec![ZeroPageRange {
                start: 0xf0,
                end: 0xff,
            }],
            zero_page_reserved: Vec::new(),
            ..BackendConfig::default()
        };
        let allocation = allocate(&module, &config).expect("allocation");
        assert_eq!(allocation.globals[0].address, 0x0300);
        assert_eq!(allocation.globals[0].size, 64);
        assert_eq!(allocation.globals[1].address, 0x0340);
    }

    #[test]
    fn skips_runtime_arithmetic_scratch() {
        let mut array = Type::scalar(TypeKind::Integer(nesc_mir::IntegerType::U8));
        array.array_lengths.push(0x0400);
        let module = Module {
            functions: Vec::new(),
            global_data: Vec::new(),
            globals: vec![
                array,
                Type::scalar(TypeKind::Integer(nesc_mir::IntegerType::U8)),
            ],
        };
        let config = BackendConfig {
            zero_page_available: vec![ZeroPageRange {
                start: 0xf0,
                end: 0xff,
            }],
            zero_page_reserved: Vec::new(),
            ..BackendConfig::default()
        };
        let allocation = allocate(&module, &config).expect("allocation");
        assert_eq!(allocation.globals[0].address, 0x0300);
        assert_eq!(allocation.globals[1].address, RUNTIME_SCRATCH_END);
    }

    #[test]
    fn never_allocates_the_reserved_shadow_oam_page() {
        // Force spilling into internal RAM by making zero page unavailable.
        let module = Module {
            functions: Vec::new(),
            global_data: Vec::new(),
            globals: vec![
                Type::scalar(TypeKind::Integer(nesc_mir::IntegerType::U8)),
                Type::scalar(TypeKind::Integer(nesc_mir::IntegerType::U16)),
            ],
        };
        let config = BackendConfig {
            zero_page_available: Vec::new(),
            zero_page_reserved: Vec::new(),
            ..BackendConfig::default()
        };
        let allocation = allocate(&module, &config).expect("allocation");
        for global in &allocation.globals {
            assert!(
                !global.zero_page,
                "expected internal-RAM spill without zero page"
            );
            assert!(
                global.address >= SHADOW_OAM_END,
                "global at ${:04X} overlaps the reserved shadow-OAM page",
                global.address
            );
        }
    }

    #[test]
    fn reclaims_the_gap_left_below_the_runtime_scratch() {
        // A wide value that straddles the scratch hole leaves a small gap just
        // below it; a later narrower value must backfill that reclaimed byte
        // instead of wasting it.
        let mut filler = Type::scalar(TypeKind::Integer(nesc_mir::IntegerType::U8));
        filler
            .array_lengths
            .push(u32::from(RUNTIME_SCRATCH_START - SHADOW_OAM_END - 1));
        let module = Module {
            functions: Vec::new(),
            global_data: Vec::new(),
            globals: vec![
                filler,
                Type::scalar(TypeKind::Integer(nesc_mir::IntegerType::U16)),
                Type::scalar(TypeKind::Integer(nesc_mir::IntegerType::U8)),
            ],
        };
        let config = BackendConfig {
            zero_page_available: Vec::new(),
            zero_page_reserved: Vec::new(),
            ..BackendConfig::default()
        };
        let allocation = allocate(&module, &config).expect("allocation");
        assert_eq!(allocation.globals[0].address, SHADOW_OAM_END);
        // The 2-byte value cannot fit in the final byte before the scratch, so
        // it lands past the scratch block.
        assert_eq!(allocation.globals[1].address, RUNTIME_SCRATCH_END);
        // The trailing 1-byte value reclaims the abandoned byte at $06FF.
        assert_eq!(allocation.globals[2].address, RUNTIME_SCRATCH_START - 1);
    }
}
