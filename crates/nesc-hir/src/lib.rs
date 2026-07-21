//! Shared high-level intermediate representation for NesC programs.

use std::collections::BTreeMap;

pub use nesc_frontend::{
    AddressSpace, AssemblyClobbers, AssemblyInput, AssemblyOutput, AssemblyRegister, Attribute,
    BinaryOperator, Block, Expression, ExpressionKind, InlineAssembly, IntegerType, Linkage,
    Parameter, SourceId, SourceMap, SourceSpan, Statement, TestMetadata, Type, TypeKind,
    UnaryOperator, Variable,
};
use nesc_frontend::{CheckedProgram, Declaration};

/// Stable function identifier.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct FunctionId(pub u32);

/// Stable global-object identifier.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct GlobalId(pub u32);

/// Function signature shared by callers and definitions.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FunctionSignature {
    /// Return type.
    pub return_type: Type,
    /// Parameter types in calling order.
    pub parameters: Vec<Type>,
}

/// HIR function declaration or definition.
#[derive(Clone, Debug)]
pub struct Function {
    /// Stable identifier.
    pub id: FunctionId,
    /// Linker-visible spelling.
    pub name: String,
    /// Emulator-backed test metadata retained for tooling.
    pub test: Option<TestMetadata>,
    /// Resolved signature.
    pub signature: FunctionSignature,
    /// Named parameters.
    pub parameters: Vec<Parameter>,
    /// Typed source-level attributes.
    pub attributes: Vec<Attribute>,
    /// Link visibility.
    pub linkage: Linkage,
    /// Structured typed body.
    pub body: Option<Block>,
    /// Declaration source range.
    pub span: SourceSpan,
}

/// HIR global object.
#[derive(Clone, Debug)]
pub struct Global {
    /// Stable identifier.
    pub id: GlobalId,
    /// Typed source declaration.
    pub variable: Variable,
}

/// Typed module with stable symbol identifiers.
#[derive(Clone, Debug)]
pub struct Module {
    /// Function declarations and definitions.
    pub functions: Vec<Function>,
    /// Global objects.
    pub globals: Vec<Global>,
    /// Function lookup table.
    pub function_names: BTreeMap<String, FunctionId>,
    /// Global lookup table.
    pub global_names: BTreeMap<String, GlobalId>,
    /// Integer constants retained from preprocessing.
    pub constants: BTreeMap<String, (u64, Type)>,
    /// Source map retained for diagnostics and debug emission.
    pub sources: SourceMap,
}

impl Module {
    /// Returns a function by stable identifier.
    #[must_use]
    pub fn function(&self, id: FunctionId) -> Option<&Function> {
        self.functions.get(id.0 as usize)
    }

    /// Returns a global by stable identifier.
    #[must_use]
    pub fn global(&self, id: GlobalId) -> Option<&Global> {
        self.globals.get(id.0 as usize)
    }
}

/// Lowers a checked syntax tree into stable-ID HIR.
#[must_use]
pub fn lower(checked: CheckedProgram) -> Module {
    let mut functions = Vec::<Function>::new();
    let mut globals = Vec::<Global>::new();
    let mut function_names = BTreeMap::<String, FunctionId>::new();
    let mut global_names = BTreeMap::<String, GlobalId>::new();

    let constants = checked
        .symbols
        .iter()
        .filter_map(|(name, symbol)| match symbol.kind {
            nesc_frontend::SymbolKind::Constant(value) => {
                Some((name.clone(), (value, symbol.ty.clone())))
            }
            _ => None,
        })
        .collect();

    for declaration in checked.program.declarations {
        match declaration {
            Declaration::Function(function) => {
                if let Some(id) = function_names.get(&function.name).copied() {
                    if function.body.is_some()
                        && let Some(existing) = functions.get_mut(id.0 as usize)
                    {
                        existing.body = function.body;
                        existing.attributes = function.attributes;
                        existing.test = function.test;
                        existing.span = function.span;
                    }
                    continue;
                }
                let id =
                    FunctionId(u32::try_from(functions.len()).expect("function count fits in u32"));
                function_names.insert(function.name.clone(), id);
                functions.push(Function {
                    id,
                    name: function.name,
                    test: function.test,
                    signature: FunctionSignature {
                        return_type: function.return_type,
                        parameters: function
                            .parameters
                            .iter()
                            .map(|parameter| parameter.ty.clone())
                            .collect(),
                    },
                    parameters: function.parameters,
                    attributes: function.attributes,
                    linkage: function.linkage,
                    body: function.body,
                    span: function.span,
                });
            }
            Declaration::Variable(variable) => {
                let id = GlobalId(u32::try_from(globals.len()).expect("global count fits in u32"));
                global_names.insert(variable.name.clone(), id);
                globals.push(Global { id, variable });
            }
        }
    }

    if let Some(span) = functions
        .iter()
        .find(|function| function.test.is_some())
        .map(|function| function.span)
    {
        let name = "__nesc_test_assert_eq".to_owned();
        let id = FunctionId(u32::try_from(functions.len()).expect("function count fits in u32"));
        let scalar = Type::scalar(TypeKind::Integer(IntegerType::U32));
        function_names.insert(name.clone(), id);
        functions.push(Function {
            id,
            name,
            test: None,
            signature: FunctionSignature {
                return_type: Type::scalar(TypeKind::Void),
                parameters: vec![scalar.clone(), scalar.clone()],
            },
            parameters: vec![
                Parameter {
                    ty: scalar.clone(),
                    name: Some("actual".to_owned()),
                    span,
                },
                Parameter {
                    ty: scalar,
                    name: Some("expected".to_owned()),
                    span,
                },
            ],
            attributes: Vec::new(),
            linkage: Linkage::External,
            body: None,
            span,
        });
    }

    Module {
        functions,
        globals,
        function_names,
        global_names,
        constants,
        sources: checked.sources,
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::tempdir;

    use nesc_frontend::{FrontendConfig, check};

    use super::{FunctionId, lower};

    #[test]
    fn assigns_deterministic_function_ids() {
        let directory = tempdir().expect("temporary directory");
        let source = directory.path().join("main.c");
        fs::write(
            &source,
            "int helper(void) { return 1; } NES_MAIN int main(void) { return helper(); }",
        )
        .expect("source");
        let checked = check(&FrontendConfig::new(source)).expect("frontend");
        let module = lower(checked);
        assert_eq!(module.function_names["helper"], FunctionId(0));
        assert_eq!(module.function_names["main"], FunctionId(1));
    }
}
