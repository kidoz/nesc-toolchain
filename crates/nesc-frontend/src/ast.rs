use crate::{IntegerLiteral, SourceSpan};

/// Stable syntax-node identifier.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct NodeId(pub u32);

/// Parsed NesC program.
#[derive(Clone, Debug)]
pub struct Program {
    /// Top-level declarations in source order.
    pub declarations: Vec<Declaration>,
}

/// Top-level declaration.
#[derive(Clone, Debug)]
pub enum Declaration {
    /// Function declaration or definition.
    Function(Function),
    /// Global variable.
    Variable(Variable),
}

/// Link visibility of a declaration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Linkage {
    /// Visible only inside the translation unit.
    Internal,
    /// Visible to the linker.
    External,
}

/// Storage spelling attached to a declaration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StorageClass {
    /// No explicit storage spelling.
    Automatic,
    /// `static`.
    Static,
    /// `extern`.
    Extern,
}

/// Language-level NES attribute.
#[derive(Clone, Debug)]
pub struct Attribute {
    /// Attribute name without the SDK prefix.
    pub name: String,
    /// Attribute arguments retained as expressions.
    pub arguments: Vec<Expression>,
    /// Source range of the complete attribute.
    pub span: SourceSpan,
}

/// Function declaration or definition.
#[derive(Clone, Debug)]
pub struct Function {
    /// Stable syntax identifier.
    pub id: NodeId,
    /// Source-level attributes.
    pub attributes: Vec<Attribute>,
    /// Link visibility.
    pub linkage: Linkage,
    /// Return type.
    pub return_type: Type,
    /// Function name.
    pub name: String,
    /// Emulator-backed test metadata for reserved `NES_TEST` definitions.
    pub test: Option<TestMetadata>,
    /// Ordered parameters.
    pub parameters: Vec<Parameter>,
    /// Function body; absent for a declaration.
    pub body: Option<Block>,
    /// Complete declaration range.
    pub span: SourceSpan,
}

/// Source metadata retained for one reserved `NES_TEST` definition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TestMetadata {
    /// Human-readable test name.
    pub name: String,
    /// String-literal source range used for diagnostics.
    pub name_span: SourceSpan,
}

/// Named function parameter.
#[derive(Clone, Debug)]
pub struct Parameter {
    /// Parameter type.
    pub ty: Type,
    /// Parameter name, absent for unnamed prototypes.
    pub name: Option<String>,
    /// Parameter source range.
    pub span: SourceSpan,
}

/// Variable declaration.
#[derive(Clone, Debug)]
pub struct Variable {
    /// Stable syntax identifier.
    pub id: NodeId,
    /// Source-level attributes.
    pub attributes: Vec<Attribute>,
    /// Storage spelling.
    pub storage: StorageClass,
    /// Link visibility.
    pub linkage: Linkage,
    /// Declared type.
    pub ty: Type,
    /// Variable name.
    pub name: String,
    /// Initial value.
    pub initializer: Option<Expression>,
    /// Complete declaration range.
    pub span: SourceSpan,
}

/// NesC type with explicit qualifiers and pointer depth.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Type {
    /// Base type.
    pub kind: TypeKind,
    /// Read-only qualification.
    pub is_const: bool,
    /// Observable-access qualification.
    pub is_volatile: bool,
    /// Number of ordinary `unknown`-address-space pointers.
    pub pointer_depth: u8,
    /// Address space used by the outermost pointer.
    pub address_space: AddressSpace,
    /// Fixed array lengths from outermost to innermost.
    pub array_lengths: Vec<u32>,
}

impl Type {
    /// Creates an unqualified scalar type.
    #[must_use]
    pub const fn scalar(kind: TypeKind) -> Self {
        Self {
            kind,
            is_const: false,
            is_volatile: false,
            pointer_depth: 0,
            address_space: AddressSpace::Unknown,
            array_lengths: Vec::new(),
        }
    }

    /// Returns whether this type is an integer scalar.
    #[must_use]
    pub const fn is_integer(&self) -> bool {
        self.pointer_depth == 0 && matches!(self.kind, TypeKind::Integer(_) | TypeKind::Bool)
    }

    /// Returns the integer width when this is an integer scalar.
    #[must_use]
    pub const fn integer_width(&self) -> Option<u8> {
        if self.pointer_depth != 0 {
            return None;
        }
        match self.kind {
            TypeKind::Bool => Some(1),
            TypeKind::Integer(integer) => Some(integer.width()),
            TypeKind::Void => None,
        }
    }
}

/// NES CPU-bus address-space classification carried by pointer types.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AddressSpace {
    /// Pointer may alias any CPU-bus address.
    Unknown,
    /// Zero page.
    ZeroPage,
    /// Internal CPU RAM.
    InternalRam,
    /// PPU register window.
    PpuRegister,
    /// APU register window.
    ApuRegister,
    /// General I/O register window.
    IoRegister,
    /// Program ROM.
    PrgRom,
    /// Program RAM.
    PrgRam,
    /// Character ROM.
    ChrRom,
    /// Character RAM.
    ChrRam,
    /// Cartridge mapper registers.
    MapperRegister,
}

/// Base type category.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TypeKind {
    /// No value.
    Void,
    /// Boolean value.
    Bool,
    /// Integer or target-specific integer type.
    Integer(IntegerType),
}

/// Primitive integer and target-specific scalar types.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IntegerType {
    /// Unsigned 8-bit integer.
    U8,
    /// Signed 8-bit integer.
    I8,
    /// Unsigned 16-bit integer.
    U16,
    /// Signed 16-bit integer.
    I16,
    /// Unsigned 24-bit integer.
    U24,
    /// Signed 24-bit integer.
    I24,
    /// Unsigned 32-bit integer.
    U32,
    /// Signed 32-bit integer.
    I32,
    /// CPU address.
    Addr,
    /// Zero-page address.
    ZeroPageAddress,
    /// PRG bank number.
    Bank,
    /// Tile index.
    Tile,
    /// Palette index.
    Palette,
}

impl IntegerType {
    /// Returns the exact storage width in bits.
    #[must_use]
    pub const fn width(self) -> u8 {
        match self {
            Self::U8
            | Self::I8
            | Self::ZeroPageAddress
            | Self::Bank
            | Self::Tile
            | Self::Palette => 8,
            Self::U16 | Self::I16 | Self::Addr => 16,
            Self::U24 | Self::I24 => 24,
            Self::U32 | Self::I32 => 32,
        }
    }

    /// Returns whether ordinary arithmetic interprets the value as signed.
    #[must_use]
    pub const fn is_signed(self) -> bool {
        matches!(self, Self::I8 | Self::I16 | Self::I24 | Self::I32)
    }

    /// Returns whether this is a target-distinct scalar requiring explicit casts.
    #[must_use]
    pub const fn is_target_distinct(self) -> bool {
        matches!(
            self,
            Self::Addr | Self::ZeroPageAddress | Self::Bank | Self::Tile | Self::Palette
        )
    }
}

/// Compound statement.
#[derive(Clone, Debug)]
pub struct Block {
    /// Stable syntax identifier.
    pub id: NodeId,
    /// Ordered statements.
    pub statements: Vec<Statement>,
    /// Complete block range.
    pub span: SourceSpan,
}

/// Ricoh 2A03 register used by an inline-assembly operand.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum AssemblyRegister {
    /// Accumulator.
    A,
    /// X index register.
    X,
    /// Y index register.
    Y,
}

/// Value loaded into a register before an inline-assembly block.
#[derive(Clone, Debug)]
pub struct AssemblyInput {
    /// Destination CPU register.
    pub register: AssemblyRegister,
    /// Source value expression.
    pub value: Expression,
}

/// Variable receiving a register after an inline-assembly block.
#[derive(Clone, Debug)]
pub struct AssemblyOutput {
    /// Source CPU register.
    pub register: AssemblyRegister,
    /// Writable local or global object name.
    pub target: String,
    /// Target name source range.
    pub span: SourceSpan,
}

/// Declared CPU and memory state changed by inline assembly.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct AssemblyClobbers {
    /// Accumulator may change.
    pub a: bool,
    /// X register may change.
    pub x: bool,
    /// Y register may change.
    pub y: bool,
    /// Processor flags may change.
    pub flags: bool,
    /// Arbitrary memory may change.
    pub memory: bool,
}

/// Target-specific inline 6502 assembly statement.
#[derive(Clone, Debug)]
pub struct InlineAssembly {
    /// Stable syntax identifier.
    pub id: NodeId,
    /// Assembly source using the official 6502 instruction set.
    pub template: String,
    /// Register inputs evaluated before the block.
    pub inputs: Vec<AssemblyInput>,
    /// Register outputs stored after the block.
    pub outputs: Vec<AssemblyOutput>,
    /// Declared state changes.
    pub clobbers: AssemblyClobbers,
    /// Whether mapper bank state may change.
    pub bank_effect: bool,
    /// Direct callees entered by the assembly source.
    pub calls: Vec<(String, SourceSpan)>,
    /// Maximum additional hardware-stack bytes used by the block.
    pub stack_bytes: u16,
    /// Complete statement range.
    pub span: SourceSpan,
}

/// Statement node.
#[derive(Clone, Debug)]
pub enum Statement {
    /// Nested block.
    Block(Block),
    /// Local variable.
    Variable(Variable),
    /// Expression followed by a semicolon.
    Expression {
        /// Stable syntax identifier.
        id: NodeId,
        /// Expression, absent for an empty statement.
        expression: Option<Expression>,
        /// Statement range.
        span: SourceSpan,
    },
    /// Volatile target-specific inline assembly.
    InlineAssembly(InlineAssembly),
    /// Conditional branch.
    If {
        /// Stable syntax identifier.
        id: NodeId,
        /// Condition expression.
        condition: Expression,
        /// Executed for a true condition.
        then_branch: Box<Statement>,
        /// Executed for a false condition.
        else_branch: Option<Box<Statement>>,
        /// Statement range.
        span: SourceSpan,
    },
    /// Pre-tested loop.
    While {
        /// Stable syntax identifier.
        id: NodeId,
        /// Loop condition.
        condition: Expression,
        /// Loop body.
        body: Box<Statement>,
        /// Statement range.
        span: SourceSpan,
    },
    /// Restricted three-clause loop.
    For {
        /// Stable syntax identifier.
        id: NodeId,
        /// Initial expression.
        initializer: Option<Expression>,
        /// Continuation condition.
        condition: Option<Expression>,
        /// Iteration expression.
        increment: Option<Expression>,
        /// Loop body.
        body: Box<Statement>,
        /// Statement range.
        span: SourceSpan,
    },
    /// Leaves the nearest loop.
    Break {
        /// Stable syntax identifier.
        id: NodeId,
        /// Statement range.
        span: SourceSpan,
    },
    /// Advances the nearest loop.
    Continue {
        /// Stable syntax identifier.
        id: NodeId,
        /// Statement range.
        span: SourceSpan,
    },
    /// Leaves a function.
    Return {
        /// Stable syntax identifier.
        id: NodeId,
        /// Returned value.
        value: Option<Expression>,
        /// Statement range.
        span: SourceSpan,
    },
}

impl Statement {
    /// Returns the complete source range.
    #[must_use]
    pub const fn span(&self) -> SourceSpan {
        match self {
            Self::Block(block) => block.span,
            Self::Variable(variable) => variable.span,
            Self::InlineAssembly(assembly) => assembly.span,
            Self::Expression { span, .. }
            | Self::If { span, .. }
            | Self::While { span, .. }
            | Self::For { span, .. }
            | Self::Break { span, .. }
            | Self::Continue { span, .. }
            | Self::Return { span, .. } => *span,
        }
    }
}

/// Expression node.
#[derive(Clone, Debug)]
pub struct Expression {
    /// Stable syntax identifier.
    pub id: NodeId,
    /// Expression form.
    pub kind: ExpressionKind,
    /// Type assigned by semantic analysis.
    pub ty: Option<Type>,
    /// Complete expression range.
    pub span: SourceSpan,
}

/// Expression form.
#[derive(Clone, Debug)]
pub enum ExpressionKind {
    /// Integer literal.
    Integer(IntegerLiteral),
    /// Boolean literal.
    Boolean(bool),
    /// Character literal.
    Character(u8),
    /// String literal.
    String(String),
    /// Name reference.
    Name(String),
    /// Prefix operation.
    Unary {
        /// Operation.
        operator: UnaryOperator,
        /// Operand.
        operand: Box<Expression>,
    },
    /// Infix operation.
    Binary {
        /// Operation.
        operator: BinaryOperator,
        /// Left operand.
        left: Box<Expression>,
        /// Right operand.
        right: Box<Expression>,
    },
    /// Assignment operation.
    Assignment {
        /// Assignment or compound-assignment operation.
        operator: BinaryOperator,
        /// Destination expression.
        target: Box<Expression>,
        /// Source expression.
        value: Box<Expression>,
    },
    /// Direct function call before name resolution.
    Call {
        /// Required direct function name.
        function: String,
        /// Arguments in source evaluation order.
        arguments: Vec<Expression>,
    },
    /// Typed equality assertion reserved for emulator-backed tests.
    TestAssertEq {
        /// Value computed exactly once before the expected expression.
        actual: Box<Expression>,
        /// Expected value computed exactly once after the actual expression.
        expected: Box<Expression>,
    },
    /// Explicit conversion.
    Cast {
        /// Destination type.
        ty: Type,
        /// Converted value.
        expression: Box<Expression>,
    },
    /// Fixed-array indexing.
    Index {
        /// Array or pointer expression.
        base: Box<Expression>,
        /// Index expression.
        index: Box<Expression>,
    },
    /// Structure field access.
    Field {
        /// Structure expression.
        base: Box<Expression>,
        /// Field name.
        field: String,
        /// Whether source used pointer access.
        through_pointer: bool,
    },
    /// Postfix increment or decrement.
    Postfix {
        /// Operation.
        operator: UnaryOperator,
        /// Updated expression.
        operand: Box<Expression>,
    },
}

/// Prefix or postfix operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UnaryOperator {
    /// Arithmetic identity.
    Plus,
    /// Arithmetic negation.
    Negate,
    /// Logical negation.
    LogicalNot,
    /// Bitwise complement.
    BitwiseNot,
    /// Address acquisition.
    AddressOf,
    /// Pointer dereference.
    Dereference,
    /// Increment.
    Increment,
    /// Decrement.
    Decrement,
}

/// Binary or assignment operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BinaryOperator {
    /// Addition.
    Add,
    /// Subtraction.
    Subtract,
    /// Multiplication.
    Multiply,
    /// Division.
    Divide,
    /// Remainder.
    Remainder,
    /// Left shift.
    ShiftLeft,
    /// Right shift.
    ShiftRight,
    /// Less-than comparison.
    Less,
    /// Less-than-or-equal comparison.
    LessEqual,
    /// Greater-than comparison.
    Greater,
    /// Greater-than-or-equal comparison.
    GreaterEqual,
    /// Equality comparison.
    Equal,
    /// Inequality comparison.
    NotEqual,
    /// Bitwise AND.
    BitwiseAnd,
    /// Bitwise XOR.
    BitwiseXor,
    /// Bitwise OR.
    BitwiseOr,
    /// Short-circuit logical AND.
    LogicalAnd,
    /// Short-circuit logical OR.
    LogicalOr,
    /// Simple assignment.
    Assign,
}
