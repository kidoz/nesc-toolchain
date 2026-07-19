use crate::SourceSpan;

/// Exact suffix attached to an integer literal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IntegerSuffix {
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
}

/// Parsed integer token with its radix and explicit suffix.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IntegerLiteral {
    /// Mathematical literal value before type selection.
    pub value: u64,
    /// Source radix.
    pub radix: u32,
    /// Explicit exact-width suffix.
    pub suffix: Option<IntegerSuffix>,
}

/// Lexical token category.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TokenKind {
    /// Identifier spelling.
    Identifier(String),
    /// Integer literal.
    Integer(IntegerLiteral),
    /// Decoded string literal.
    String(String),
    /// Decoded character literal.
    Character(u8),
    /// `void`.
    Void,
    /// `bool`.
    Bool,
    /// `static`.
    Static,
    /// `extern`.
    Extern,
    /// `const`.
    Const,
    /// `volatile`.
    Volatile,
    /// `struct`.
    Struct,
    /// `enum`.
    Enum,
    /// `typedef`.
    Typedef,
    /// `if`.
    If,
    /// `else`.
    Else,
    /// `while`.
    While,
    /// `for`.
    For,
    /// `break`.
    Break,
    /// `continue`.
    Continue,
    /// `return`.
    Return,
    /// `switch`.
    Switch,
    /// `case`.
    Case,
    /// `default`.
    Default,
    /// `true`.
    True,
    /// `false`.
    False,
    /// `unsigned`.
    Unsigned,
    /// `signed`.
    Signed,
    /// `char`.
    Char,
    /// `short`.
    Short,
    /// `int`.
    Int,
    /// `long`.
    Long,
    /// `(`.
    LeftParen,
    /// `)`.
    RightParen,
    /// `{`.
    LeftBrace,
    /// `}`.
    RightBrace,
    /// `[`.
    LeftBracket,
    /// `]`.
    RightBracket,
    /// `;`.
    Semicolon,
    /// `,`.
    Comma,
    /// `.`.
    Dot,
    /// `:`.
    Colon,
    /// `?`.
    Question,
    /// `+`.
    Plus,
    /// `-`.
    Minus,
    /// `*`.
    Star,
    /// `/`.
    Slash,
    /// `%`.
    Percent,
    /// `&`.
    Ampersand,
    /// `|`.
    Pipe,
    /// `^`.
    Caret,
    /// `~`.
    Tilde,
    /// `!`.
    Bang,
    /// `=`.
    Equal,
    /// `<`.
    Less,
    /// `>`.
    Greater,
    /// `++`.
    PlusPlus,
    /// `--`.
    MinusMinus,
    /// `->`.
    Arrow,
    /// `==`.
    EqualEqual,
    /// `!=`.
    BangEqual,
    /// `<=`.
    LessEqual,
    /// `>=`.
    GreaterEqual,
    /// `&&`.
    AmpersandAmpersand,
    /// `||`.
    PipePipe,
    /// `<<`.
    ShiftLeft,
    /// `>>`.
    ShiftRight,
    /// `+=`.
    PlusEqual,
    /// `-=`.
    MinusEqual,
    /// `*=`.
    StarEqual,
    /// `/=`.
    SlashEqual,
    /// `%=`.
    PercentEqual,
    /// `&=`.
    AmpersandEqual,
    /// `|=`.
    PipeEqual,
    /// `^=`.
    CaretEqual,
    /// `<<=`.
    ShiftLeftEqual,
    /// `>>=`.
    ShiftRightEqual,
    /// End of the translation unit.
    End,
}

/// Token and its original source range.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Token {
    /// Token category.
    pub kind: TokenKind,
    /// Original source range.
    pub span: SourceSpan,
}

impl Token {
    /// Creates a token.
    #[must_use]
    pub const fn new(kind: TokenKind, span: SourceSpan) -> Self {
        Self { kind, span }
    }
}
