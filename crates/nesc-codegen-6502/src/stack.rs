use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use nesc_mir::{BankPlacement, BinaryOperator, FunctionId, InstructionKind, Module};

use crate::CodegenError;

/// Static hardware-stack usage report.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StackReport {
    /// Maximum bytes consumed by nested calls and conservative callee saves.
    pub maximum_call_path: u16,
    /// Reserved interrupt entry overhead.
    pub interrupt_overhead: u16,
    /// Combined worst-case use.
    pub estimated_total: u16,
    /// Per-function maximum starting at that function.
    pub functions: BTreeMap<String, u16>,
}

struct CallGraph {
    callees: HashMap<FunctionId, BTreeSet<FunctionId>>,
    banked_overhead: HashMap<(FunctionId, FunctionId), u16>,
}

pub(crate) fn analyze(
    module: &Module,
    limit: u16,
    external_stack_bytes: &BTreeMap<String, u16>,
) -> Result<StackReport, Vec<CodegenError>> {
    let mut calls = HashMap::<FunctionId, BTreeSet<FunctionId>>::new();
    let mut banked_call_overhead = HashMap::<(FunctionId, FunctionId), u16>::new();
    let mut helper_callers = HashSet::new();
    let mut inline_stack = HashMap::<FunctionId, u16>::new();
    let external_stack = module
        .functions
        .iter()
        .filter(|function| function.blocks.is_empty())
        .filter_map(|function| {
            external_stack_bytes
                .get(&function.name)
                .copied()
                .map(|bytes| (function.id, bytes))
        })
        .collect::<HashMap<_, _>>();
    for function in &module.functions {
        if function.blocks.is_empty() {
            continue;
        }
        let mut callees = BTreeSet::new();
        for instruction in function.blocks.iter().flat_map(|block| &block.instructions) {
            match &instruction.kind {
                InstructionKind::Call {
                    function: callee, ..
                } => {
                    callees.insert(*callee);
                    record_banked_call(
                        module,
                        function.id,
                        function.placement,
                        *callee,
                        &mut banked_call_overhead,
                    );
                }
                InstructionKind::Binary {
                    operator:
                        BinaryOperator::Multiply
                        | BinaryOperator::Divide
                        | BinaryOperator::Remainder
                        | BinaryOperator::ShiftLeft
                        | BinaryOperator::ShiftRight,
                    ..
                } => {
                    helper_callers.insert(function.id);
                }
                InstructionKind::InlineAssembly(assembly) => {
                    callees.extend(assembly.calls.iter().copied());
                    for callee in &assembly.calls {
                        record_banked_call(
                            module,
                            function.id,
                            function.placement,
                            *callee,
                            &mut banked_call_overhead,
                        );
                    }
                    inline_stack
                        .entry(function.id)
                        .and_modify(|bytes| *bytes = (*bytes).max(assembly.stack_bytes))
                        .or_insert(assembly.stack_bytes);
                }
                _ => {}
            }
        }
        calls.insert(function.id, callees);
    }
    let call_graph = CallGraph {
        callees: calls,
        banked_overhead: banked_call_overhead,
    };
    let mut memo = HashMap::new();
    let mut functions = BTreeMap::new();
    let mut maximum_call_path = 0;
    for function in &module.functions {
        if function.blocks.is_empty() {
            if let Some(bytes) = external_stack_bytes.get(&function.name) {
                let usage = 3_u16.saturating_add(*bytes);
                maximum_call_path = maximum_call_path.max(usage);
                functions.insert(function.name.clone(), usage);
            }
            continue;
        }
        let usage = call_usage(
            function.id,
            &call_graph,
            &helper_callers,
            &inline_stack,
            &external_stack,
            &mut memo,
            &mut HashSet::new(),
        )?;
        maximum_call_path = maximum_call_path.max(usage);
        functions.insert(function.name.clone(), usage);
    }
    let interrupt_overhead = 3;
    let estimated_total = maximum_call_path.saturating_add(interrupt_overhead);
    if estimated_total > limit {
        return Err(vec![CodegenError {
            message: format!(
                "estimated hardware-stack use of {estimated_total} bytes exceeds the configured limit of {limit}"
            ),
            span: None,
        }]);
    }
    Ok(StackReport {
        maximum_call_path,
        interrupt_overhead,
        estimated_total,
        functions,
    })
}

fn record_banked_call(
    module: &Module,
    caller: FunctionId,
    caller_placement: BankPlacement,
    callee: FunctionId,
    overhead: &mut HashMap<(FunctionId, FunctionId), u16>,
) {
    let Some(target) = module.functions.get(callee.0 as usize) else {
        return;
    };
    let crosses_to_switchable = match (caller_placement, target.placement) {
        (_, BankPlacement::Fixed) => false,
        (BankPlacement::Bank(left), BankPlacement::Bank(right)) => left != right,
        (BankPlacement::Fixed, BankPlacement::Bank(_)) => true,
    };
    if crosses_to_switchable {
        overhead.insert((caller, callee), 3);
    }
}

fn call_usage(
    function: FunctionId,
    call_graph: &CallGraph,
    helper_callers: &HashSet<FunctionId>,
    inline_stack: &HashMap<FunctionId, u16>,
    external_stack: &HashMap<FunctionId, u16>,
    memo: &mut HashMap<FunctionId, u16>,
    visiting: &mut HashSet<FunctionId>,
) -> Result<u16, Vec<CodegenError>> {
    if let Some(usage) = memo.get(&function) {
        return Ok(*usage);
    }
    if !visiting.insert(function) {
        return Err(vec![CodegenError {
            message: "recursive call graph cannot be bounded for hardware-stack analysis"
                .to_owned(),
            span: None,
        }]);
    }
    let mut nested = u16::from(helper_callers.contains(&function)) * 2;
    if let Some(callees) = call_graph.callees.get(&function) {
        for callee in callees {
            let usage = if call_graph.callees.contains_key(callee) {
                call_usage(
                    *callee,
                    call_graph,
                    helper_callers,
                    inline_stack,
                    external_stack,
                    memo,
                    visiting,
                )?
            } else {
                3_u16.saturating_add(external_stack.get(callee).copied().unwrap_or(0))
            };
            let overhead = call_graph
                .banked_overhead
                .get(&(function, *callee))
                .copied()
                .unwrap_or(0);
            nested = nested.max(usage.saturating_add(overhead));
        }
    }
    nested = nested.saturating_add(inline_stack.get(&function).copied().unwrap_or(0));
    visiting.remove(&function);
    let usage = nested.saturating_add(2);
    memo.insert(function, usage);
    Ok(usage)
}

pub(crate) fn render_report(report: &StackReport) -> String {
    let mut output = String::from("Stack usage\n-----------\n");
    for (function, bytes) in &report.functions {
        output.push_str(&format!("{function:<20} {bytes} bytes\n"));
    }
    output.push_str(&format!(
        "\nMaximum call path: {} bytes\nInterrupt overhead: {} bytes\nEstimated total: {} bytes\n",
        report.maximum_call_path, report.interrupt_overhead, report.estimated_total
    ));
    output
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeSet, HashMap, HashSet};

    use nesc_mir::FunctionId;

    use super::{CallGraph, call_usage};

    fn call_graph(callees: HashMap<FunctionId, BTreeSet<FunctionId>>) -> CallGraph {
        CallGraph {
            callees,
            banked_overhead: HashMap::new(),
        }
    }

    #[test]
    fn includes_external_leaf_calls() {
        let calls = HashMap::from([(FunctionId(0), BTreeSet::from([FunctionId(1)]))]);
        let graph = call_graph(calls);
        let usage = call_usage(
            FunctionId(0),
            &graph,
            &HashSet::new(),
            &HashMap::new(),
            &HashMap::new(),
            &mut HashMap::new(),
            &mut HashSet::new(),
        )
        .expect("acyclic graph");
        assert_eq!(usage, 5);
    }

    #[test]
    fn includes_declared_external_stack_use() {
        let calls = HashMap::from([(FunctionId(0), BTreeSet::from([FunctionId(1)]))]);
        let graph = call_graph(calls);
        let usage = call_usage(
            FunctionId(0),
            &graph,
            &HashSet::new(),
            &HashMap::new(),
            &HashMap::from([(FunctionId(1), 4)]),
            &mut HashMap::new(),
            &mut HashSet::new(),
        )
        .expect("acyclic graph");
        assert_eq!(usage, 9);
    }

    #[test]
    fn includes_cross_bank_trampoline_use() {
        let calls = HashMap::from([(FunctionId(0), BTreeSet::from([FunctionId(1)]))]);
        let graph = CallGraph {
            callees: calls,
            banked_overhead: HashMap::from([((FunctionId(0), FunctionId(1)), 3)]),
        };
        let usage = call_usage(
            FunctionId(0),
            &graph,
            &HashSet::new(),
            &HashMap::new(),
            &HashMap::new(),
            &mut HashMap::new(),
            &mut HashSet::new(),
        )
        .expect("acyclic graph");
        assert_eq!(usage, 8);
    }

    #[test]
    fn rejects_recursive_graphs() {
        let calls = HashMap::from([(FunctionId(0), BTreeSet::from([FunctionId(0)]))]);
        let graph = call_graph(calls);
        let errors = call_usage(
            FunctionId(0),
            &graph,
            &HashSet::new(),
            &HashMap::new(),
            &HashMap::new(),
            &mut HashMap::new(),
            &mut HashSet::new(),
        )
        .expect_err("recursive graph");
        assert!(errors[0].message.contains("recursive call graph"));
    }

    #[test]
    fn includes_arithmetic_helper_calls() {
        let calls = HashMap::from([(FunctionId(0), BTreeSet::new())]);
        let graph = call_graph(calls);
        let usage = call_usage(
            FunctionId(0),
            &graph,
            &HashSet::from([FunctionId(0)]),
            &HashMap::new(),
            &HashMap::new(),
            &mut HashMap::new(),
            &mut HashSet::new(),
        )
        .expect("acyclic graph");
        assert_eq!(usage, 4);
    }
}
