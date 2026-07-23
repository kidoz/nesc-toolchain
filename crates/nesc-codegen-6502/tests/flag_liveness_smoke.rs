use nesc_codegen_6502::generate;
use nesc_mir::{
    AssemblyClobbers, AssemblyInput, AssemblyRegister, BankPlacement, BasicBlock, BinaryOperator,
    BlockId, Effect, Function, FunctionId, InlineAssembly, Instruction, InstructionKind, Module,
    SourceId, SourceSpan, Terminator, Type, TypeKind, ValueId,
};

fn byte() -> Type {
    Type::scalar(TypeKind::Integer(nesc_mir::IntegerType::U8))
}

fn span() -> SourceSpan {
    SourceSpan::new(SourceId::new(0), 0, 1)
}

#[test]
fn forwards_a_when_load_flags_are_dead() {
    let module = Module {
        globals: Vec::new(),
        global_data: Vec::new(),
        functions: vec![Function {
            id: FunctionId(0),
            name: "main".to_owned(),
            placement: BankPlacement::Fixed,
            return_type: byte(),
            parameters: Vec::new(),
            locals: Vec::new(),
            entry: Some(BlockId(0)),
            blocks: vec![BasicBlock {
                id: BlockId(0),
                instructions: vec![
                    Instruction {
                        result: Some(ValueId(0)),
                        kind: InstructionKind::Constant(23),
                        effect: Effect::Pure,
                        span: span(),
                    },
                    Instruction {
                        result: None,
                        kind: InstructionKind::InlineAssembly(InlineAssembly {
                            template: "nop".to_owned(),
                            inputs: vec![AssemblyInput {
                                register: AssemblyRegister::X,
                                value: ValueId(0),
                            }],
                            outputs: Vec::new(),
                            clobbers: AssemblyClobbers::default(),
                            bank_effect: false,
                            calls: Vec::new(),
                            stack_bytes: 0,
                        }),
                        effect: Effect::Volatile,
                        span: span(),
                    },
                ],
                terminator: Some(Terminator::Return(Some(ValueId(0)))),
            }],
            value_types: vec![byte()],
        }],
    };
    let generated = generate(&module).expect("code generation");
    assert!(
        generated
            .optimization_report
            .contains("Flag-dead loads removed: 1")
    );
}

#[test]
fn fuses_a_single_use_comparison_with_its_branch() {
    let mut module = Module {
        globals: Vec::new(),
        global_data: Vec::new(),
        functions: vec![Function {
            id: FunctionId(0),
            name: "compare".to_owned(),
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
                            span: span(),
                        },
                        Instruction {
                            result: Some(ValueId(1)),
                            kind: InstructionKind::Constant(2),
                            effect: Effect::Pure,
                            span: span(),
                        },
                        Instruction {
                            result: Some(ValueId(2)),
                            kind: InstructionKind::Binary {
                                operator: BinaryOperator::Equal,
                                left: ValueId(0),
                                right: ValueId(1),
                            },
                            effect: Effect::Pure,
                            span: span(),
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
                    terminator: Some(Terminator::Return(None)),
                },
                BasicBlock {
                    id: BlockId(2),
                    instructions: Vec::new(),
                    terminator: Some(Terminator::Return(None)),
                },
            ],
            value_types: vec![byte(), byte(), byte()],
        }],
    };
    let generated = generate(&module).expect("code generation");
    assert!(
        generated
            .optimization_report
            .contains("Condition materializations removed: 1")
    );
    assert!(!generated.assembly.contains(".__nesc_compare_"));

    module.functions[0].blocks[0].terminator = Some(Terminator::Branch {
        condition: ValueId(2),
        then_block: BlockId(1),
        else_block: BlockId(1),
    });
    let generated = generate(&module).expect("redundant comparison code generation");
    assert!(!generated.assembly.contains("cmp $"));
    assert!(
        generated
            .optimization_report
            .contains("Redundant comparisons removed: 1")
    );
}
