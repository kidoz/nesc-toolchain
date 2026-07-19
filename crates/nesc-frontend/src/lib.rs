//! Preprocessing, parsing, and semantic analysis for NesC.

mod ast;
mod lexer;
mod macro_expansion;
mod parser;
mod preprocessor;
mod sema;
mod source;
mod token;

pub use ast::{
    AddressSpace, Attribute, BinaryOperator, Block, Declaration, Expression, ExpressionKind,
    Function, IntegerType, Linkage, NodeId, Parameter, Program, Statement, StorageClass, Type,
    TypeKind, UnaryOperator, Variable,
};
pub use preprocessor::{MacroDefinition, PreprocessedFile, TranslationUnit};
pub use sema::{CheckedProgram, Symbol, SymbolKind};
pub use source::{Source, SourceId, SourceMap, SourceSpan};
pub use token::{IntegerLiteral, IntegerSuffix, Token, TokenKind};

use std::path::{Path, PathBuf};

use nesc_diagnostics::Diagnostic;

/// Input settings for a frontend invocation.
#[derive(Clone, Debug)]
pub struct FrontendConfig {
    /// Source file that owns the program entry point.
    pub entry: PathBuf,
    /// User and SDK include search directories in lookup order.
    pub include_directories: Vec<PathBuf>,
}

impl FrontendConfig {
    /// Creates settings for an entry source.
    #[must_use]
    pub fn new(entry: impl Into<PathBuf>) -> Self {
        Self {
            entry: entry.into(),
            include_directories: Vec::new(),
        }
    }

    /// Appends an include search directory.
    #[must_use]
    pub fn with_include_directory(mut self, directory: impl Into<PathBuf>) -> Self {
        self.include_directories.push(directory.into());
        self
    }
}

/// Parses and checks one NesC translation unit.
///
/// # Errors
///
/// Returns deterministic diagnostics for preprocessing, lexical, syntactic,
/// or semantic failures.
pub fn check(config: &FrontendConfig) -> Result<CheckedProgram, Vec<Diagnostic>> {
    let unit = preprocessor::preprocess(&config.entry, &config.include_directories)?;
    let mut diagnostics = Vec::new();
    let mut tokens = Vec::new();

    for file in unit.files() {
        let mut file_tokens = lexer::lex(file, unit.sources(), &mut diagnostics);
        if matches!(
            file_tokens.last().map(|token| &token.kind),
            Some(TokenKind::End)
        ) {
            file_tokens.pop();
        }
        tokens.extend(file_tokens);
    }

    tokens = macro_expansion::expand(tokens, unit.macros(), unit.sources(), &mut diagnostics);

    let eof_span = unit
        .files()
        .last()
        .map_or(SourceSpan::new(SourceId::new(0), 0, 0), |file| {
            SourceSpan::new(file.source_id(), file.text().len(), 0)
        });
    tokens.push(Token::new(TokenKind::End, eof_span));

    if !diagnostics.is_empty() {
        return Err(diagnostics);
    }

    let program = parser::parse(tokens, unit.sources(), &mut diagnostics);
    if !diagnostics.is_empty() {
        return Err(diagnostics);
    }

    let program = program.expect("parser returns a program without diagnostics");
    sema::check(
        program,
        unit.sources().clone(),
        unit.macros(),
        &mut diagnostics,
    )
    .and_then(|checked| {
        if diagnostics.is_empty() {
            Ok(checked)
        } else {
            Err(diagnostics)
        }
    })
}

/// Checks a source file using no additional include directories.
///
/// # Errors
///
/// Returns frontend diagnostics when the source is invalid.
pub fn check_file(entry: impl AsRef<Path>) -> Result<CheckedProgram, Vec<Diagnostic>> {
    check(&FrontendConfig::new(entry.as_ref()))
}
