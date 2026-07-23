use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use nesc_diagnostics::Diagnostic;

use crate::{
    AddressSpace, AssemblyRegister, BinaryOperator, Block, Declaration, Expression, ExpressionKind,
    Function, InlineAssembly, IntegerLiteral, IntegerSuffix, IntegerType, MacroDefinition, Program,
    SourceMap, SourceSpan, Statement, StorageClass, Type, TypeKind, UnaryOperator, Variable,
};

/// Kind of a resolved global symbol.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SymbolKind {
    /// Function and its parameter types.
    Function {
        /// Ordered argument types.
        parameters: Vec<Type>,
        /// Whether a body is present.
        defined: bool,
    },
    /// Global variable.
    Variable,
    /// Preprocessor integer constant.
    Constant(u64),
}

/// Resolved global symbol.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Symbol {
    /// Symbol spelling.
    pub name: String,
    /// Value or return type.
    pub ty: Type,
    /// Symbol category.
    pub kind: SymbolKind,
    /// First declaration range when source-backed.
    pub span: Option<SourceSpan>,
}

/// Semantically checked syntax tree and symbol table.
#[derive(Clone, Debug)]
pub struct CheckedProgram {
    /// Typed syntax tree.
    pub program: Program,
    /// Deterministically ordered global symbols.
    pub symbols: BTreeMap<String, Symbol>,
    /// Source map retained for subsequent lowering and diagnostics.
    pub sources: SourceMap,
}

pub(crate) fn check(
    mut program: Program,
    sources: SourceMap,
    macros: &BTreeMap<String, MacroDefinition>,
    test_mode: bool,
    diagnostics: &mut Vec<Diagnostic>,
) -> Result<CheckedProgram, Vec<Diagnostic>> {
    let mut checker = Checker {
        sources: &sources,
        symbols: BTreeMap::new(),
        diagnostics,
        call_graph: BTreeMap::new(),
    };
    checker.add_macro_constants(macros);
    checker.collect_declarations(&program);
    checker.validate_entry(&program, !test_mode);
    checker.validate_tests(&program);
    checker.check_bodies(&mut program);
    checker.reject_recursion();
    if checker.diagnostics.is_empty() {
        Ok(CheckedProgram {
            program,
            symbols: checker.symbols,
            sources,
        })
    } else {
        Err(checker.diagnostics.clone())
    }
}

struct Checker<'a> {
    sources: &'a SourceMap,
    symbols: BTreeMap<String, Symbol>,
    diagnostics: &'a mut Vec<Diagnostic>,
    call_graph: BTreeMap<String, BTreeSet<String>>,
}

struct FunctionChecker<'a, 'b> {
    sources: &'a SourceMap,
    symbols: &'a BTreeMap<String, Symbol>,
    diagnostics: &'b mut Vec<Diagnostic>,
    scopes: Vec<HashMap<String, Type>>,
    return_type: Type,
    calls: BTreeSet<String>,
    loop_depth: usize,
    test_function: bool,
}

impl Checker<'_> {
    fn add_macro_constants(&mut self, macros: &BTreeMap<String, MacroDefinition>) {
        for (name, definition) in macros {
            if definition.parameters.is_none()
                && let Some(value) = parse_macro_integer(&definition.replacement)
            {
                let literal = IntegerLiteral {
                    value,
                    radix: 10,
                    suffix: None,
                };
                self.symbols.insert(
                    name.clone(),
                    Symbol {
                        name: name.clone(),
                        ty: literal_type(&literal)
                            .unwrap_or_else(|| Type::scalar(TypeKind::Integer(IntegerType::U32))),
                        kind: SymbolKind::Constant(value),
                        span: None,
                    },
                );
            }
        }
    }

    fn collect_declarations(&mut self, program: &Program) {
        for declaration in &program.declarations {
            match declaration {
                Declaration::Function(function) => self.collect_function(function),
                Declaration::Variable(variable) => self.collect_variable(variable),
            }
        }
    }

    fn collect_function(&mut self, function: &Function) {
        self.validate_attributes(&function.attributes, true);
        if !function.return_type.array_lengths.is_empty() {
            self.error(
                "E1300",
                "functions cannot return arrays",
                function.span,
                "invalid return type",
            );
        }
        let parameters = function
            .parameters
            .iter()
            .map(|parameter| parameter.ty.clone())
            .collect::<Vec<_>>();
        if let Some(existing) = self.symbols.get_mut(&function.name) {
            let SymbolKind::Function {
                parameters: existing_parameters,
                defined,
            } = &mut existing.kind
            else {
                self.error(
                    "E1301",
                    format!(
                        "`{}` is declared as both a function and an object",
                        function.name
                    ),
                    function.span,
                    "conflicting declaration",
                );
                return;
            };
            if existing.ty != function.return_type || *existing_parameters != parameters {
                self.error(
                    "E1302",
                    format!("conflicting declaration of function `{}`", function.name),
                    function.span,
                    "signature differs from the first declaration",
                );
            } else if function.body.is_some() && *defined {
                self.error(
                    "E1303",
                    format!("function `{}` is defined more than once", function.name),
                    function.span,
                    "duplicate definition",
                );
            } else {
                *defined |= function.body.is_some();
            }
            return;
        }
        self.symbols.insert(
            function.name.clone(),
            Symbol {
                name: function.name.clone(),
                ty: function.return_type.clone(),
                kind: SymbolKind::Function {
                    parameters,
                    defined: function.body.is_some(),
                },
                span: Some(function.span),
            },
        );
    }

    fn collect_variable(&mut self, variable: &Variable) {
        self.validate_attributes(&variable.attributes, false);
        if variable.ty.kind == TypeKind::Void && variable.ty.pointer_depth == 0 {
            self.error(
                "E1304",
                format!("variable `{}` has type `void`", variable.name),
                variable.span,
                "objects require a sized type",
            );
        }
        if self.symbols.contains_key(&variable.name) {
            self.error(
                "E1305",
                format!(
                    "global symbol `{}` is declared more than once",
                    variable.name
                ),
                variable.span,
                "duplicate global declaration",
            );
        } else {
            self.symbols.insert(
                variable.name.clone(),
                Symbol {
                    name: variable.name.clone(),
                    ty: variable.ty.clone(),
                    kind: SymbolKind::Variable,
                    span: Some(variable.span),
                },
            );
        }
    }

    fn validate_attributes(&mut self, attributes: &[crate::Attribute], function: bool) {
        for attribute in attributes {
            let expected_arguments = match attribute.name.as_str() {
                "bank" | "segment" | "cycle_budget" | "align" => 1,
                "main" | "reset" | "nmi" | "irq" | "zero_page" | "fixed_bank" | "noinline"
                | "always_inline" | "interrupt_safe" | "optimize_size" | "optimize_cycles"
                | "used" | "export" | "import" => 0,
                _ => {
                    self.error(
                        "E1306",
                        format!("unknown NES attribute `{}`", attribute.name),
                        attribute.span,
                        "unsupported attribute",
                    );
                    continue;
                }
            };
            if attribute.arguments.len() != expected_arguments {
                self.error(
                    "E1307",
                    format!(
                        "attribute `{}` expects {expected_arguments} argument(s)",
                        attribute.name
                    ),
                    attribute.span,
                    "incorrect attribute arguments",
                );
            }
            let function_only = matches!(
                attribute.name.as_str(),
                "main"
                    | "reset"
                    | "nmi"
                    | "irq"
                    | "noinline"
                    | "always_inline"
                    | "interrupt_safe"
                    | "cycle_budget"
                    | "optimize_size"
                    | "optimize_cycles"
            );
            if function_only && !function {
                self.error(
                    "E1308",
                    format!("attribute `{}` requires a function", attribute.name),
                    attribute.span,
                    "attribute is not valid on an object",
                );
            }
        }
    }

    fn validate_entry(&mut self, program: &Program, required: bool) {
        let entries = program
            .declarations
            .iter()
            .filter_map(|declaration| match declaration {
                Declaration::Function(function)
                    if function.body.is_some()
                        && function
                            .attributes
                            .iter()
                            .any(|attribute| attribute.name == "main") =>
                {
                    Some(function)
                }
                _ => None,
            })
            .collect::<Vec<_>>();
        match entries.as_slice() {
            [] if required => self.diagnostics.push(
                Diagnostic::error("E1309", "program has no `NES_MAIN` function")
                    .with_help("mark one defined function with `NES_MAIN`"),
            ),
            [] => {}
            [function] => {
                if !function.parameters.is_empty()
                    || function.return_type != Type::scalar(TypeKind::Integer(IntegerType::I16))
                {
                    self.error(
                        "E1310",
                        "`NES_MAIN` must have the signature `int main(void)`",
                        function.span,
                        "invalid program entry signature",
                    );
                }
            }
            _ => {
                for function in entries.iter().skip(1) {
                    self.error(
                        "E1311",
                        "program has more than one `NES_MAIN` function",
                        function.span,
                        "duplicate program entry",
                    );
                }
            }
        }
    }

    fn validate_tests(&mut self, program: &Program) {
        let mut names = BTreeSet::new();
        for function in program
            .declarations
            .iter()
            .filter_map(|declaration| match declaration {
                Declaration::Function(function) if function.test.is_some() => Some(function),
                _ => None,
            })
        {
            let test = function.test.as_ref().expect("filtered test function");
            if test.name.is_empty() {
                self.error(
                    "E1314",
                    "`NES_TEST` name must not be empty",
                    test.name_span,
                    "empty test name",
                );
            } else if !names.insert(test.name.clone()) {
                self.error(
                    "E1315",
                    format!("test name `{}` is declared more than once", test.name),
                    test.name_span,
                    "duplicate test name",
                );
            }
            for attribute in &function.attributes {
                if matches!(
                    attribute.name.as_str(),
                    "main" | "reset" | "nmi" | "irq" | "bank"
                ) {
                    self.error(
                        "E1316",
                        format!("attribute `{}` is not valid on `NES_TEST`", attribute.name),
                        attribute.span,
                        "tests execute from the fixed runtime entry",
                    );
                }
            }
            let budgets = function
                .attributes
                .iter()
                .filter(|attribute| attribute.name == "cycle_budget")
                .collect::<Vec<_>>();
            if budgets.len() > 1 {
                self.error(
                    "E1317",
                    "`NES_TEST` declares `NES_CYCLE_BUDGET` more than once",
                    budgets[1].span,
                    "duplicate cycle budget",
                );
            }
            if let Some(argument) = budgets
                .first()
                .and_then(|attribute| attribute.arguments.first())
                && !matches!(&argument.kind, ExpressionKind::Integer(literal) if literal.value > 0)
            {
                self.error(
                    "E1318",
                    "`NES_CYCLE_BUDGET` requires a positive integer literal",
                    argument.span,
                    "invalid cycle budget",
                );
            }
        }
    }

    fn check_bodies(&mut self, program: &mut Program) {
        for declaration in &mut program.declarations {
            match declaration {
                Declaration::Function(function) => {
                    let Some(body) = function.body.as_mut() else {
                        continue;
                    };
                    let mut function_checker = FunctionChecker {
                        sources: self.sources,
                        symbols: &self.symbols,
                        diagnostics: self.diagnostics,
                        scopes: vec![HashMap::new()],
                        return_type: function.return_type.clone(),
                        calls: BTreeSet::new(),
                        loop_depth: 0,
                        test_function: function.test.is_some(),
                    };
                    for parameter in &function.parameters {
                        if let Some(name) = &parameter.name {
                            if function_checker.scopes[0]
                                .insert(name.clone(), parameter.ty.clone())
                                .is_some()
                            {
                                function_checker.error(
                                    "E1312",
                                    format!("parameter `{name}` is declared more than once"),
                                    parameter.span,
                                    "duplicate parameter",
                                );
                            }
                        }
                    }
                    function_checker.block(body, false);
                    self.call_graph
                        .insert(function.name.clone(), function_checker.calls);
                }
                Declaration::Variable(variable) => {
                    if let Some(initializer) = &mut variable.initializer {
                        let mut function_checker = FunctionChecker {
                            sources: self.sources,
                            symbols: &self.symbols,
                            diagnostics: self.diagnostics,
                            scopes: vec![HashMap::new()],
                            return_type: Type::scalar(TypeKind::Void),
                            calls: BTreeSet::new(),
                            loop_depth: 0,
                            test_function: false,
                        };
                        if matches!(initializer.kind, ExpressionKind::Array(_)) {
                            if !variable.ty.is_const
                                || variable.ty.pointer_depth > 0
                                || variable.ty.array_lengths.is_empty()
                            {
                                function_checker.error(
                                    "E1353",
                                    format!(
                                        "aggregate initializer for `{}` requires a `const` \
                                         fixed-size array global",
                                        variable.name
                                    ),
                                    initializer.span,
                                    "invalid aggregate initializer",
                                );
                            } else {
                                let mut element = variable.ty.clone();
                                element.array_lengths = Vec::new();
                                function_checker.aggregate_initializer(
                                    &variable.ty.array_lengths,
                                    &element,
                                    initializer,
                                );
                            }
                        } else {
                            let actual = function_checker.expression(initializer);
                            function_checker.require_conversion(
                                initializer,
                                actual.as_ref(),
                                &variable.ty,
                            );
                            if variable.ty.is_const
                                && !constant_expression(&self.symbols, initializer)
                            {
                                self.error(
                                    "E1319",
                                    format!(
                                        "`const` global `{}` requires a constant expression \
                                         initializer",
                                        variable.name
                                    ),
                                    initializer.span,
                                    "not a compile-time constant",
                                );
                            }
                        }
                    }
                }
            }
        }
    }

    fn reject_recursion(&mut self) {
        let mut visiting = HashSet::new();
        let mut visited = HashSet::new();
        let names = self.call_graph.keys().cloned().collect::<Vec<_>>();
        for name in names {
            let mut path = Vec::new();
            if let Some(cycle) = find_cycle(
                &name,
                &self.call_graph,
                &mut visiting,
                &mut visited,
                &mut path,
            ) {
                let span = self.symbols.get(&cycle[0]).and_then(|symbol| symbol.span);
                let message = format!("recursive call cycle: {}", cycle.join(" -> "));
                if let Some(span) = span {
                    self.error("E1313", message, span, "recursion is not supported");
                } else {
                    self.diagnostics.push(Diagnostic::error("E1313", message));
                }
                break;
            }
        }
    }

    fn error(&mut self, code: &str, message: impl Into<String>, span: SourceSpan, label: &str) {
        self.diagnostics
            .push(self.sources.error(code, message, span, label));
    }
}

impl FunctionChecker<'_, '_> {
    fn block(&mut self, block: &mut Block, create_scope: bool) {
        if create_scope {
            self.scopes.push(HashMap::new());
        }
        for statement in &mut block.statements {
            self.statement(statement);
        }
        if create_scope {
            self.scopes.pop();
        }
    }

    fn statement(&mut self, statement: &mut Statement) {
        match statement {
            Statement::Block(block) => self.block(block, true),
            Statement::Variable(variable) => self.variable(variable),
            Statement::Expression { expression, .. } => {
                if let Some(expression) = expression {
                    self.expression(expression);
                }
            }
            Statement::InlineAssembly(assembly) => self.inline_assembly(assembly),
            Statement::If {
                condition,
                then_branch,
                else_branch,
                ..
            } => {
                self.condition(condition);
                self.statement(then_branch);
                if let Some(else_branch) = else_branch {
                    self.statement(else_branch);
                }
            }
            Statement::While {
                condition, body, ..
            } => {
                self.condition(condition);
                self.loop_depth += 1;
                self.statement(body);
                self.loop_depth -= 1;
            }
            Statement::For {
                initializer,
                condition,
                increment,
                body,
                ..
            } => {
                if let Some(initializer) = initializer {
                    self.expression(initializer);
                }
                if let Some(condition) = condition {
                    self.condition(condition);
                }
                if let Some(increment) = increment {
                    self.expression(increment);
                }
                self.loop_depth += 1;
                self.statement(body);
                self.loop_depth -= 1;
            }
            Statement::Break { span, .. } | Statement::Continue { span, .. } => {
                if self.loop_depth == 0 {
                    self.error(
                        "E1320",
                        "loop control statement outside a loop",
                        *span,
                        "no enclosing loop",
                    );
                }
            }
            Statement::Return { value, span, .. } => match (value, &self.return_type.kind) {
                (None, TypeKind::Void) => {}
                (None, _) => self.error(
                    "E1321",
                    "non-void function must return a value",
                    *span,
                    "return value is missing",
                ),
                (Some(value), TypeKind::Void) => {
                    self.expression(value);
                    self.error(
                        "E1322",
                        "void function cannot return a value",
                        value.span,
                        "remove the return value",
                    );
                }
                (Some(value), _) => {
                    let actual = self.expression(value);
                    let expected = self.return_type.clone();
                    self.require_conversion(value, actual.as_ref(), &expected);
                }
            },
        }
    }

    fn inline_assembly(&mut self, assembly: &mut InlineAssembly) {
        let mut inputs = HashSet::new();
        for input in &mut assembly.inputs {
            if !inputs.insert(input.register) {
                self.error(
                    "E1346",
                    format!(
                        "inline assembly register {} has more than one input",
                        assembly_register_name(input.register)
                    ),
                    input.value.span,
                    "duplicate register input",
                );
            }
            let ty = self.expression(&mut input.value);
            if ty
                .as_ref()
                .and_then(Type::integer_width)
                .is_none_or(|width| width > 8)
            {
                self.error(
                    "E1347",
                    "inline assembly register inputs must be 8-bit integer values",
                    input.value.span,
                    "value does not fit in one CPU register",
                );
            }
        }

        let mut outputs = HashSet::new();
        for output in &assembly.outputs {
            if !outputs.insert(output.register) {
                self.error(
                    "E1348",
                    format!(
                        "inline assembly register {} has more than one output",
                        assembly_register_name(output.register)
                    ),
                    output.span,
                    "duplicate register output",
                );
            }
            if assembly_register_clobbered(assembly, output.register) {
                self.error(
                    "E1349",
                    format!(
                        "inline assembly register {} cannot be both an output and a clobber",
                        assembly_register_name(output.register)
                    ),
                    output.span,
                    "conflicting assembly contract",
                );
            }
            let ty = self
                .scopes
                .iter()
                .rev()
                .find_map(|scope| scope.get(&output.target))
                .or_else(|| {
                    self.symbols.get(&output.target).and_then(|symbol| {
                        matches!(symbol.kind, SymbolKind::Variable).then_some(&symbol.ty)
                    })
                });
            match ty {
                None => self.error(
                    "E1350",
                    format!("unknown inline assembly output `{}`", output.target),
                    output.span,
                    "writable variable required here",
                ),
                Some(ty) if ty.is_const || ty.integer_width().is_none_or(|width| width > 8) => {
                    self.error(
                        "E1351",
                        "inline assembly outputs require a writable 8-bit integer variable",
                        output.span,
                        "invalid output variable",
                    );
                }
                Some(_) => {}
            }
        }

        for (callee, span) in &assembly.calls {
            match self.symbols.get(callee) {
                Some(Symbol {
                    kind: SymbolKind::Function { .. },
                    ..
                }) => {
                    self.calls.insert(callee.clone());
                }
                _ => self.error(
                    "E1352",
                    format!("unknown inline assembly callee `{callee}`"),
                    *span,
                    "declared function required here",
                ),
            }
        }
    }

    fn variable(&mut self, variable: &mut Variable) {
        if variable.storage == StorageClass::Extern {
            self.error(
                "E1323",
                "local `extern` declarations are not supported",
                variable.span,
                "move the declaration to file scope",
            );
        }
        if variable.ty.kind == TypeKind::Void && variable.ty.pointer_depth == 0 {
            self.error(
                "E1304",
                format!("variable `{}` has type `void`", variable.name),
                variable.span,
                "objects require a sized type",
            );
        }
        if let Some(initializer) = &mut variable.initializer {
            let actual = self.expression(initializer);
            self.require_conversion(initializer, actual.as_ref(), &variable.ty);
        }
        let scope = self.scopes.last_mut().expect("function has a scope");
        if scope
            .insert(variable.name.clone(), variable.ty.clone())
            .is_some()
        {
            self.error(
                "E1324",
                format!("local `{}` is declared more than once", variable.name),
                variable.span,
                "duplicate declaration in this block",
            );
        }
    }

    /// Validates one dimension of a `const` global aggregate initializer:
    /// shape against the array lengths, element conversion, and constness.
    /// Shorter initializer lists zero-fill the remaining elements.
    fn aggregate_initializer(
        &mut self,
        dimensions: &[u32],
        element: &Type,
        expression: &mut Expression,
    ) {
        let span = expression.span;
        match dimensions.split_first() {
            Some((&length, rest)) => {
                if let ExpressionKind::Array(elements) = &mut expression.kind {
                    if elements.len() > length as usize {
                        self.error(
                            "E1354",
                            format!(
                                "initializer supplies {} elements for an array of {length}",
                                elements.len()
                            ),
                            span,
                            "too many initializer elements",
                        );
                    }
                    for nested in elements.iter_mut().take(length as usize) {
                        self.aggregate_initializer(rest, element, nested);
                    }
                } else {
                    self.error(
                        "E1353",
                        "array dimension requires a brace-enclosed initializer list",
                        span,
                        "expected `{ … }` here",
                    );
                }
            }
            None => {
                if matches!(expression.kind, ExpressionKind::Array(_)) {
                    self.error(
                        "E1353",
                        "initializer nests deeper than the array type",
                        span,
                        "unexpected `{ … }`",
                    );
                    return;
                }
                let actual = self.expression(expression);
                self.require_conversion(expression, actual.as_ref(), element);
                if !constant_expression(self.symbols, expression) {
                    self.error(
                        "E1319",
                        "`const` array initializer elements must be constant expressions",
                        span,
                        "not a compile-time constant",
                    );
                }
            }
        }
    }

    fn condition(&mut self, expression: &mut Expression) {
        let ty = self.expression(expression);
        if ty
            .as_ref()
            .is_some_and(|ty| !ty.is_integer() && ty.pointer_depth == 0)
        {
            self.error(
                "E1325",
                "condition must be an integer, boolean, or pointer",
                expression.span,
                "invalid condition type",
            );
        }
    }

    fn expression(&mut self, expression: &mut Expression) -> Option<Type> {
        let ty = match &mut expression.kind {
            ExpressionKind::Integer(literal) => match literal_type(literal) {
                Some(ty) => Some(ty),
                None => {
                    self.error(
                        "E1204",
                        "integer literal is not representable by any NesC integer type",
                        expression.span,
                        "value is too large",
                    );
                    None
                }
            },
            ExpressionKind::Boolean(_) => Some(Type::scalar(TypeKind::Bool)),
            ExpressionKind::Character(_) => Some(Type::scalar(TypeKind::Integer(IntegerType::I16))),
            ExpressionKind::String(_) => {
                let mut ty = Type::scalar(TypeKind::Integer(IntegerType::U8));
                ty.is_const = true;
                ty.pointer_depth = 1;
                Some(ty)
            }
            ExpressionKind::Name(name) => self.lookup_name(name, expression.span),
            ExpressionKind::Array(elements) => {
                for element in elements.iter_mut() {
                    self.expression(element);
                }
                self.error(
                    "E1353",
                    "aggregate initializers are only allowed on `const` global arrays",
                    expression.span,
                    "invalid aggregate expression",
                );
                None
            }
            ExpressionKind::Unary { operator, operand } => {
                let operand_type = self.expression(operand);
                self.unary_type(*operator, operand, operand_type)
            }
            ExpressionKind::Binary {
                operator,
                left,
                right,
            } => {
                let left_type = self.expression(left);
                let right_type = self.expression(right);
                self.binary_type(*operator, left, right, left_type, right_type)
            }
            ExpressionKind::Assignment {
                operator,
                target,
                value,
            } => {
                let target_type = self.expression(target);
                let value_type = self.expression(value);
                if !is_assignable(target) {
                    self.error(
                        "E1326",
                        "assignment target is not writable",
                        target.span,
                        "expected a variable, dereference, index, or field",
                    );
                }
                if target_type.as_ref().is_some_and(|ty| ty.is_const) {
                    self.error(
                        "E1327",
                        "cannot assign through a const-qualified type",
                        target.span,
                        "const object is not writable",
                    );
                }
                if target_type.as_ref().is_some_and(|ty| {
                    matches!(
                        ty.address_space,
                        AddressSpace::PrgRom | AddressSpace::ChrRom
                    )
                }) {
                    self.error(
                        "E1344",
                        "cannot write through a read-only ROM address space",
                        target.span,
                        "ROM storage is not writable",
                    );
                }
                if *operator != BinaryOperator::Assign {
                    self.binary_type(
                        *operator,
                        target,
                        value,
                        target_type.clone(),
                        value_type.clone(),
                    );
                }
                if let Some(expected) = &target_type {
                    self.require_conversion(value, value_type.as_ref(), expected);
                }
                target_type
            }
            ExpressionKind::Call {
                function,
                arguments,
            } => self.call_type(function, arguments, expression.span),
            ExpressionKind::TestAssertEq { actual, expected } => {
                let actual_type = self.expression(actual);
                let expected_type = self.expression(expected);
                if !self.test_function {
                    self.error(
                        "E1346",
                        "`NES_ASSERT_EQ` may only be used inside `NES_TEST`",
                        expression.span,
                        "assertion outside a test",
                    );
                }
                for (operand, ty) in [
                    (actual.as_ref(), actual_type.as_ref()),
                    (expected.as_ref(), expected_type.as_ref()),
                ] {
                    if ty.is_some_and(|ty| !ty.is_integer()) {
                        self.error(
                            "E1347",
                            "`NES_ASSERT_EQ` operands must be integer scalars",
                            operand.span,
                            "unsupported assertion operand",
                        );
                    }
                }
                Some(Type::scalar(TypeKind::Void))
            }
            ExpressionKind::Cast { ty, expression } => {
                self.expression(expression);
                Some(ty.clone())
            }
            ExpressionKind::Index { base, index } => {
                let mut base_type = self.expression(base);
                let index_type = self.expression(index);
                if index_type.as_ref().is_some_and(|ty| !ty.is_integer()) {
                    self.error(
                        "E1328",
                        "array index must be an integer",
                        index.span,
                        "invalid index type",
                    );
                }
                match base_type.as_mut() {
                    Some(ty) if !ty.array_lengths.is_empty() => {
                        ty.array_lengths.remove(0);
                        Some(ty.clone())
                    }
                    Some(ty) if ty.pointer_depth > 0 => {
                        ty.pointer_depth -= 1;
                        Some(ty.clone())
                    }
                    _ => {
                        self.error(
                            "E1329",
                            "indexing requires an array or pointer",
                            base.span,
                            "invalid indexed value",
                        );
                        None
                    }
                }
            }
            ExpressionKind::Field { base, .. } => {
                self.expression(base);
                self.error(
                    "E1330",
                    "structure field resolution is not implemented yet",
                    expression.span,
                    "structure declarations are not available in this compiler build",
                );
                None
            }
            ExpressionKind::Postfix { operator, operand } => {
                let operand_type = self.expression(operand);
                self.unary_type(*operator, operand, operand_type)
            }
        };
        expression.ty = ty.clone();
        ty
    }

    fn lookup_name(&mut self, name: &str, span: SourceSpan) -> Option<Type> {
        for scope in self.scopes.iter().rev() {
            if let Some(ty) = scope.get(name) {
                return Some(ty.clone());
            }
        }
        match self.symbols.get(name) {
            Some(Symbol {
                kind: SymbolKind::Function { .. },
                ..
            }) => {
                self.error(
                    "E1331",
                    "function pointers are not supported",
                    span,
                    "call the function directly",
                );
                None
            }
            Some(symbol) => Some(symbol.ty.clone()),
            None => {
                self.error(
                    "E1332",
                    format!("unknown name `{name}`"),
                    span,
                    "name is not declared in this scope",
                );
                None
            }
        }
    }

    fn unary_type(
        &mut self,
        operator: UnaryOperator,
        operand: &Expression,
        operand_type: Option<Type>,
    ) -> Option<Type> {
        let mut ty = operand_type?;
        match operator {
            UnaryOperator::LogicalNot => Some(Type::scalar(TypeKind::Bool)),
            UnaryOperator::AddressOf => {
                if !is_assignable(operand) {
                    self.error(
                        "E1333",
                        "address-of requires an object expression",
                        operand.span,
                        "temporary value has no address",
                    );
                }
                ty.pointer_depth = ty.pointer_depth.saturating_add(1);
                Some(ty)
            }
            UnaryOperator::Dereference => {
                if ty.pointer_depth == 0 {
                    self.error(
                        "E1334",
                        "dereference requires a pointer",
                        operand.span,
                        "value is not a pointer",
                    );
                    None
                } else {
                    ty.pointer_depth -= 1;
                    Some(ty)
                }
            }
            UnaryOperator::Increment | UnaryOperator::Decrement => {
                if !is_assignable(operand) {
                    self.error(
                        "E1326",
                        "increment or decrement target is not writable",
                        operand.span,
                        "expected an object expression",
                    );
                }
                if !ty.is_integer() && ty.pointer_depth == 0 {
                    self.error(
                        "E1335",
                        "increment and decrement require an integer or pointer",
                        operand.span,
                        "invalid operand type",
                    );
                }
                Some(ty)
            }
            UnaryOperator::Plus | UnaryOperator::Negate | UnaryOperator::BitwiseNot => {
                if !ty.is_integer() {
                    self.error(
                        "E1336",
                        "unary arithmetic requires an integer",
                        operand.span,
                        "invalid operand type",
                    );
                    None
                } else {
                    Some(promote(ty))
                }
            }
        }
    }

    fn binary_type(
        &mut self,
        operator: BinaryOperator,
        left: &Expression,
        right: &Expression,
        left_type: Option<Type>,
        right_type: Option<Type>,
    ) -> Option<Type> {
        let left_type = left_type?;
        let right_type = right_type?;
        let comparison = matches!(
            operator,
            BinaryOperator::Less
                | BinaryOperator::LessEqual
                | BinaryOperator::Greater
                | BinaryOperator::GreaterEqual
                | BinaryOperator::Equal
                | BinaryOperator::NotEqual
                | BinaryOperator::LogicalAnd
                | BinaryOperator::LogicalOr
        );
        if left_type.is_integer() && right_type.is_integer() {
            if target_distinct_mismatch(&left_type, &right_type) {
                self.error(
                    "E1337",
                    "target-specific scalar types require an explicit cast",
                    right.span,
                    "cast both operands to a common type",
                );
                return None;
            }
            let common = usual_arithmetic_conversion(left_type, right_type);
            return Some(if comparison {
                Type::scalar(TypeKind::Bool)
            } else {
                common
            });
        }
        if matches!(operator, BinaryOperator::Add | BinaryOperator::Subtract)
            && left_type.pointer_depth > 0
            && right_type.is_integer()
        {
            return Some(left_type);
        }
        if comparison && left_type.pointer_depth > 0 && right_type.pointer_depth > 0 {
            if left_type.address_space != right_type.address_space {
                self.error(
                    "E1345",
                    "pointer comparison requires matching address spaces",
                    left.span.through(right.span),
                    "cast explicitly to a common pointer type",
                );
                return None;
            }
            return Some(Type::scalar(TypeKind::Bool));
        }
        self.error(
            "E1338",
            "binary operands do not have compatible types",
            left.span.through(right.span),
            "invalid operand types",
        );
        None
    }

    fn call_type(
        &mut self,
        function: &str,
        arguments: &mut [Expression],
        span: SourceSpan,
    ) -> Option<Type> {
        let Some(symbol) = self.symbols.get(function) else {
            for argument in arguments {
                self.expression(argument);
            }
            self.error(
                "E1339",
                format!("unknown function `{function}`"),
                span,
                "declare the function before calling it",
            );
            return None;
        };
        let SymbolKind::Function { parameters, .. } = &symbol.kind else {
            self.error(
                "E1340",
                format!("`{function}` is not a function"),
                span,
                "object cannot be called",
            );
            return None;
        };
        let parameters = parameters.clone();
        let return_type = symbol.ty.clone();
        if arguments.len() != parameters.len() {
            self.error(
                "E1341",
                format!(
                    "function `{function}` expects {} argument(s), but {} were provided",
                    parameters.len(),
                    arguments.len()
                ),
                span,
                "incorrect argument count",
            );
        }
        for (index, argument) in arguments.iter_mut().enumerate() {
            let actual = self.expression(argument);
            if let Some(expected) = parameters.get(index) {
                self.require_conversion(argument, actual.as_ref(), expected);
            }
        }
        self.calls.insert(function.to_owned());
        Some(return_type)
    }

    fn require_conversion(
        &mut self,
        expression: &Expression,
        actual: Option<&Type>,
        expected: &Type,
    ) {
        let Some(actual) = actual else {
            return;
        };
        if actual == expected {
            return;
        }
        if target_distinct_mismatch(actual, expected) {
            self.error(
                "E1342",
                "conversion involving a target-specific scalar requires an explicit cast",
                expression.span,
                "add an explicit cast",
            );
            return;
        }
        if actual.is_integer() && expected.is_integer() {
            if let ExpressionKind::Integer(literal) = &expression.kind
                && !literal_fits(literal.value, expected)
            {
                self.error(
                    "E1204",
                    format!("value does not fit in `{}`", type_name(expected)),
                    expression.span,
                    "constant is not exactly representable",
                );
            }
            return;
        }
        if actual.pointer_depth == expected.pointer_depth
            && actual.pointer_depth > 0
            && actual.kind == expected.kind
            && actual.address_space == expected.address_space
        {
            return;
        }
        self.error(
            "E1343",
            format!(
                "cannot implicitly convert `{}` to `{}`",
                type_name(actual),
                type_name(expected)
            ),
            expression.span,
            "incompatible types",
        );
    }

    fn error(&mut self, code: &str, message: impl Into<String>, span: SourceSpan, label: &str) {
        self.diagnostics
            .push(self.sources.error(code, message, span, label));
    }
}

fn parse_macro_integer(replacement: &str) -> Option<u64> {
    let spelling = replacement.trim();
    let digit_end = spelling
        .find(|character: char| character.is_ascii_alphabetic())
        .unwrap_or(spelling.len());
    let spelling = &spelling[..digit_end];
    if let Some(hex) = spelling
        .strip_prefix("0x")
        .or_else(|| spelling.strip_prefix("0X"))
    {
        u64::from_str_radix(hex, 16).ok()
    } else if let Some(binary) = spelling
        .strip_prefix("0b")
        .or_else(|| spelling.strip_prefix("0B"))
    {
        u64::from_str_radix(binary, 2).ok()
    } else {
        spelling.parse().ok()
    }
}

fn literal_type(literal: &IntegerLiteral) -> Option<Type> {
    let integer = match literal.suffix {
        Some(IntegerSuffix::U8) if literal.value <= u8::MAX.into() => IntegerType::U8,
        Some(IntegerSuffix::I8) if literal.value <= i8::MAX as u64 => IntegerType::I8,
        Some(IntegerSuffix::U16) if literal.value <= u16::MAX.into() => IntegerType::U16,
        Some(IntegerSuffix::I16) if literal.value <= i16::MAX as u64 => IntegerType::I16,
        Some(IntegerSuffix::U24) if literal.value <= 0xFF_FFFF => IntegerType::U24,
        Some(IntegerSuffix::I24) if literal.value <= 0x7F_FFFF => IntegerType::I24,
        Some(IntegerSuffix::U32) if literal.value <= u32::MAX.into() => IntegerType::U32,
        Some(IntegerSuffix::I32) if literal.value <= i32::MAX as u64 => IntegerType::I32,
        Some(_) => return None,
        None if literal.value <= i16::MAX as u64 => IntegerType::I16,
        None if literal.value <= u16::MAX.into() => IntegerType::U16,
        None if literal.value <= 0x7F_FFFF => IntegerType::I24,
        None if literal.value <= 0xFF_FFFF => IntegerType::U24,
        None if literal.value <= i32::MAX as u64 => IntegerType::I32,
        None if literal.value <= u32::MAX.into() => IntegerType::U32,
        None => return None,
    };
    Some(Type::scalar(TypeKind::Integer(integer)))
}

fn literal_fits(value: u64, ty: &Type) -> bool {
    if ty.pointer_depth != 0 {
        return false;
    }
    match ty.kind {
        TypeKind::Bool => value <= 1,
        TypeKind::Integer(integer) if integer.is_signed() => {
            value <= ((1_u64 << (integer.width() - 1)) - 1)
        }
        TypeKind::Integer(integer) => value <= ((1_u64 << integer.width()) - 1),
        TypeKind::Void => false,
    }
}

fn promote(ty: Type) -> Type {
    match ty.kind {
        TypeKind::Bool | TypeKind::Integer(IntegerType::U8 | IntegerType::I8) => {
            Type::scalar(TypeKind::Integer(IntegerType::I16))
        }
        _ => ty,
    }
}

fn usual_arithmetic_conversion(left: Type, right: Type) -> Type {
    let left = promote(left);
    let right = promote(right);
    let (TypeKind::Integer(left_integer), TypeKind::Integer(right_integer)) =
        (left.kind, right.kind)
    else {
        return left;
    };
    let width = left_integer.width().max(right_integer.width());
    let signed = if left_integer.is_signed() == right_integer.is_signed() {
        left_integer.is_signed()
    } else {
        let unsigned_width = if left_integer.is_signed() {
            right_integer.width()
        } else {
            left_integer.width()
        };
        let signed_width = if left_integer.is_signed() {
            left_integer.width()
        } else {
            right_integer.width()
        };
        signed_width > unsigned_width
    };
    Type::scalar(TypeKind::Integer(match (width, signed) {
        (8, false) => IntegerType::U8,
        (8, true) => IntegerType::I8,
        (16, false) => IntegerType::U16,
        (16, true) => IntegerType::I16,
        (24, false) => IntegerType::U24,
        (24, true) => IntegerType::I24,
        (32, false) => IntegerType::U32,
        (32, true) => IntegerType::I32,
        _ => IntegerType::I16,
    }))
}

fn target_distinct_mismatch(left: &Type, right: &Type) -> bool {
    match (left.kind, right.kind) {
        (TypeKind::Integer(left), TypeKind::Integer(right)) => {
            (left.is_target_distinct() || right.is_target_distinct()) && left != right
        }
        _ => false,
    }
}

/// Returns whether an expression folds to a compile-time constant usable in a
/// PRG-ROM `const` global initializer.
fn constant_expression(symbols: &BTreeMap<String, Symbol>, expression: &Expression) -> bool {
    match &expression.kind {
        ExpressionKind::Integer(_) | ExpressionKind::Boolean(_) | ExpressionKind::Character(_) => {
            true
        }
        ExpressionKind::Name(name) => matches!(
            symbols.get(name),
            Some(Symbol {
                kind: SymbolKind::Constant(_),
                ..
            })
        ),
        ExpressionKind::Unary { operator, operand } => {
            matches!(
                operator,
                UnaryOperator::Plus
                    | UnaryOperator::Negate
                    | UnaryOperator::BitwiseNot
                    | UnaryOperator::LogicalNot
            ) && constant_expression(symbols, operand)
        }
        ExpressionKind::Binary {
            operator,
            left,
            right,
        } => {
            *operator != BinaryOperator::Assign
                && constant_expression(symbols, left)
                && constant_expression(symbols, right)
        }
        ExpressionKind::Cast {
            expression: inner, ..
        } => constant_expression(symbols, inner),
        _ => false,
    }
}

fn is_assignable(expression: &Expression) -> bool {
    matches!(
        expression.kind,
        ExpressionKind::Name(_)
            | ExpressionKind::Index { .. }
            | ExpressionKind::Field { .. }
            | ExpressionKind::Unary {
                operator: UnaryOperator::Dereference,
                ..
            }
    )
}

fn assembly_register_name(register: AssemblyRegister) -> &'static str {
    match register {
        AssemblyRegister::A => "A",
        AssemblyRegister::X => "X",
        AssemblyRegister::Y => "Y",
    }
}

fn assembly_register_clobbered(assembly: &InlineAssembly, register: AssemblyRegister) -> bool {
    match register {
        AssemblyRegister::A => assembly.clobbers.a,
        AssemblyRegister::X => assembly.clobbers.x,
        AssemblyRegister::Y => assembly.clobbers.y,
    }
}

fn type_name(ty: &Type) -> String {
    let base = match ty.kind {
        TypeKind::Void => "void",
        TypeKind::Bool => "bool",
        TypeKind::Integer(IntegerType::U8) => "u8",
        TypeKind::Integer(IntegerType::I8) => "i8",
        TypeKind::Integer(IntegerType::U16) => "u16",
        TypeKind::Integer(IntegerType::I16) => "i16",
        TypeKind::Integer(IntegerType::U24) => "u24",
        TypeKind::Integer(IntegerType::I24) => "i24",
        TypeKind::Integer(IntegerType::U32) => "u32",
        TypeKind::Integer(IntegerType::I32) => "i32",
        TypeKind::Integer(IntegerType::Addr) => "addr",
        TypeKind::Integer(IntegerType::ZeroPageAddress) => "zp_addr",
        TypeKind::Integer(IntegerType::Bank) => "bank",
        TypeKind::Integer(IntegerType::Tile) => "tile",
        TypeKind::Integer(IntegerType::Palette) => "palette",
    };
    if ty.pointer_depth > 0 && ty.address_space != AddressSpace::Unknown {
        let address_space = match ty.address_space {
            AddressSpace::Unknown => unreachable!("handled by the outer condition"),
            AddressSpace::ZeroPage => "zero_page",
            AddressSpace::InternalRam => "internal_ram",
            AddressSpace::PpuRegister => "ppu_register",
            AddressSpace::ApuRegister => "apu_register",
            AddressSpace::IoRegister => "io_register",
            AddressSpace::PrgRom => "prg_rom",
            AddressSpace::PrgRam => "prg_ram",
            AddressSpace::ChrRom => "chr_rom",
            AddressSpace::ChrRam => "chr_ram",
            AddressSpace::MapperRegister => "mapper_register",
        };
        format!("ptr<{address_space}, {base}>")
    } else {
        format!("{base}{}", "*".repeat(ty.pointer_depth.into()))
    }
}

fn find_cycle(
    name: &str,
    graph: &BTreeMap<String, BTreeSet<String>>,
    visiting: &mut HashSet<String>,
    visited: &mut HashSet<String>,
    path: &mut Vec<String>,
) -> Option<Vec<String>> {
    if visited.contains(name) {
        return None;
    }
    if let Some(position) = path.iter().position(|item| item == name) {
        let mut cycle = path[position..].to_vec();
        cycle.push(name.to_owned());
        return Some(cycle);
    }
    if !visiting.insert(name.to_owned()) {
        return None;
    }
    path.push(name.to_owned());
    if let Some(callees) = graph.get(name) {
        for callee in callees {
            if graph.contains_key(callee)
                && let Some(cycle) = find_cycle(callee, graph, visiting, visited, path)
            {
                return Some(cycle);
            }
        }
    }
    path.pop();
    visiting.remove(name);
    visited.insert(name.to_owned());
    None
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    use crate::{PreprocessedFile, SourceMap};

    #[test]
    fn reports_narrowing_integer_initializer() {
        let source = "NES_MAIN int main(void) { u8 color = 300; return 0; }";
        let mut sources = SourceMap::new();
        let id = sources.add(PathBuf::from("test.c"), source.to_owned());
        let file = PreprocessedFile::new(id, source.to_owned());
        let mut diagnostics = Vec::new();
        let tokens = crate::lexer::lex(&file, &sources, &mut diagnostics);
        let program = crate::parser::parse(tokens, &sources, &mut diagnostics).expect("program");
        let result = super::check(program, sources, &BTreeMap::new(), false, &mut diagnostics);
        assert!(result.is_err());
        assert!(
            diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code() == "E1204")
        );
    }

    #[test]
    fn rejects_non_constant_const_global_initializer() {
        let source = "u8 seed;\nconst u8 copy = seed;\nNES_MAIN int main(void) { return 0; }";
        let mut sources = SourceMap::new();
        let id = sources.add(PathBuf::from("test.c"), source.to_owned());
        let file = PreprocessedFile::new(id, source.to_owned());
        let mut diagnostics = Vec::new();
        let tokens = crate::lexer::lex(&file, &sources, &mut diagnostics);
        let program = crate::parser::parse(tokens, &sources, &mut diagnostics).expect("program");
        let result = super::check(program, sources, &BTreeMap::new(), false, &mut diagnostics);
        assert!(result.is_err());
        assert!(
            diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code() == "E1319")
        );
    }

    #[test]
    fn accepts_constant_expression_const_global_initializer() {
        let source = "const u8 mask = (u8)(0x30 + 0x0F);\nNES_MAIN int main(void) { return 0; }";
        let mut sources = SourceMap::new();
        let id = sources.add(PathBuf::from("test.c"), source.to_owned());
        let file = PreprocessedFile::new(id, source.to_owned());
        let mut diagnostics = Vec::new();
        let tokens = crate::lexer::lex(&file, &sources, &mut diagnostics);
        let program = crate::parser::parse(tokens, &sources, &mut diagnostics).expect("program");
        let result = super::check(program, sources, &BTreeMap::new(), false, &mut diagnostics);
        assert!(result.is_ok(), "{diagnostics:?}");
    }

    #[test]
    fn rejects_misshapen_aggregate_initializers() {
        let check_source = |source: &str| {
            let mut sources = SourceMap::new();
            let id = sources.add(PathBuf::from("test.c"), source.to_owned());
            let file = PreprocessedFile::new(id, source.to_owned());
            let mut diagnostics = Vec::new();
            let tokens = crate::lexer::lex(&file, &sources, &mut diagnostics);
            let program =
                crate::parser::parse(tokens, &sources, &mut diagnostics).expect("program");
            let result = super::check(program, sources, &BTreeMap::new(), false, &mut diagnostics);
            (result.is_ok(), diagnostics)
        };

        let (ok, diagnostics) =
            check_source("u8 table[2] = {1u8, 2u8};\nNES_MAIN int main(void) { return 0; }");
        assert!(!ok);
        assert!(diagnostics.iter().any(|d| d.code() == "E1353"));

        let (ok, diagnostics) = check_source(
            "const u8 table[2] = {1u8, 2u8, 3u8};\nNES_MAIN int main(void) { return 0; }",
        );
        assert!(!ok);
        assert!(diagnostics.iter().any(|d| d.code() == "E1354"));

        let (ok, diagnostics) =
            check_source("const u8 table[3] = {1u8, 2u8,};\nNES_MAIN int main(void) { return 0; }");
        assert!(ok, "{diagnostics:?}");
    }

    #[test]
    fn checks_test_only_programs_and_rejects_assertions_outside_tests() {
        let check_source = |source: &str, test_mode: bool| {
            let mut sources = SourceMap::new();
            let id = sources.add(PathBuf::from("test.c"), source.to_owned());
            let file = PreprocessedFile::new(id, source.to_owned());
            let mut diagnostics = Vec::new();
            let tokens = crate::lexer::lex(&file, &sources, &mut diagnostics);
            let program =
                crate::parser::parse(tokens, &sources, &mut diagnostics).expect("program");
            let result = super::check(
                program,
                sources,
                &BTreeMap::new(),
                test_mode,
                &mut diagnostics,
            );
            (result, diagnostics)
        };

        let (result, diagnostics) =
            check_source("NES_TEST(\"works\") { NES_ASSERT_EQ(1u8, 1u8); }", true);
        assert!(result.is_ok(), "{diagnostics:?}");

        let (result, diagnostics) = check_source(
            "NES_MAIN int main(void) { NES_ASSERT_EQ(1u8, 1u8); return 0; }",
            false,
        );
        assert!(result.is_err());
        assert!(
            diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code() == "E1346")
        );
    }
}
