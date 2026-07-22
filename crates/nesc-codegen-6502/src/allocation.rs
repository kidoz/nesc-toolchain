use std::cmp::Reverse;
use std::collections::{BTreeMap, HashMap};

use nesc_mir::{FunctionId, GlobalId, InstructionKind, LocalId, Module, Terminator, Type, ValueId};

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
    /// Allocate stable objects before temporary values.
    Frequency,
    /// Allocate temporary values before stable objects.
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
    let mut requests = Vec::new();
    for (index, ty) in module.globals.iter().enumerate() {
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
    match config.zero_page_strategy {
        ZeroPageStrategy::Frequency => {
            requests.sort_by_key(|request| Reverse(request.accesses));
        }
        ZeroPageStrategy::Cycles => {
            requests.sort_by_key(|request| {
                Reverse(u64::from(request.accesses) * u64::from(request.size))
            });
        }
    }

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

    for request in requests {
        let location = find_zero_page(&available, request.size).map_or_else(
            || {
                if let Some((gap_start, gap_end)) = scratch_gap {
                    if request.size <= gap_end - gap_start {
                        let address = gap_start;
                        let next = gap_start + request.size;
                        scratch_gap = (next < gap_end).then_some((next, gap_end));
                        return Location {
                            address,
                            size: request.size,
                            zero_page: false,
                        };
                    }
                }
                if internal_cursor < RUNTIME_SCRATCH_END
                    && internal_cursor.saturating_add(request.size) > RUNTIME_SCRATCH_START
                {
                    if internal_cursor < RUNTIME_SCRATCH_START {
                        scratch_gap = Some((internal_cursor, RUNTIME_SCRATCH_START));
                    }
                    internal_cursor = RUNTIME_SCRATCH_END;
                }
                let location = Location {
                    address: internal_cursor,
                    size: request.size,
                    zero_page: false,
                };
                internal_cursor = internal_cursor.saturating_add(request.size);
                location
            },
            |start| {
                available[start..start + usize::from(request.size)].fill(false);
                zero_page_used += usize::from(request.size);
                Location {
                    address: start as u16,
                    size: request.size,
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

    Ok(Allocation {
        globals,
        locals,
        values,
        entries,
        zero_page_used,
        zero_page_free: total_available.saturating_sub(zero_page_used),
    })
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
    for entry in allocation
        .entries
        .iter()
        .filter(|entry| entry.location.zero_page)
    {
        let end = entry.location.address + entry.location.size - 1;
        if end == entry.location.address {
            report.push_str(&format!(
                "${:02X}      {} (weight {})\n",
                entry.location.address, entry.name, entry.access_weight
            ));
        } else {
            report.push_str(&format!(
                "${:02X}-${end:02X} {} (weight {})\n",
                entry.location.address, entry.name, entry.access_weight
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
    use nesc_mir::{
        BankPlacement, BasicBlock, BlockId, Effect, Function, FunctionId, Instruction,
        InstructionKind, Local, LocalId, Module, SourceId, SourceSpan, Terminator, Type, TypeKind,
        ValueId,
    };

    use super::{
        BackendConfig, RUNTIME_SCRATCH_END, RUNTIME_SCRATCH_START, SHADOW_OAM_END, ZeroPageRange,
        access_counts, allocate,
    };

    #[test]
    fn weights_loop_body_accesses_above_cold_accesses() {
        let ty = Type::scalar(TypeKind::Bool);
        let span = SourceSpan::new(SourceId::new(0), 0, 1);
        let module = Module {
            globals: Vec::new(),
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
    fn promotes_hot_loop_storage_before_cold_storage() {
        let ty = Type::scalar(TypeKind::Bool);
        let span = SourceSpan::new(SourceId::new(0), 0, 1);
        let module = Module {
            globals: vec![ty.clone(), ty.clone()],
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
