//! Bounded 6502 assembly for NesC interoperability and ROM recovery.

use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;

use nesc_disasm::{AddressingMode, Opcode, opcode};
use nesc_object::{
    Binding, Object, Relocation, RelocationKind, SectionKind, SectionPlacement, SymbolId,
    SymbolKind,
};

/// Resource bounds applied while parsing generated recovery assembly.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AssemblyLimits {
    /// Maximum UTF-8 source size.
    pub max_source_bytes: usize,
    /// Maximum source line count.
    pub max_lines: usize,
    /// Maximum number of symbols.
    pub max_symbols: usize,
    /// Maximum emitted byte count.
    pub max_output_bytes: usize,
}

impl Default for AssemblyLimits {
    fn default() -> Self {
        Self {
            max_source_bytes: 16 * 1024 * 1024,
            max_lines: 2_000_000,
            max_symbols: 200_000,
            max_output_bytes: 4 * 1024 * 1024,
        }
    }
}

/// Deterministic assembly failure with an optional one-based line number.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AssemblyError {
    line: Option<usize>,
    message: String,
}

/// One unresolved direct call emitted by inline assembly.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InlineCall {
    /// Byte offset of the little-endian call operand.
    pub offset: u32,
    /// Declared linker symbol.
    pub symbol: String,
}

/// Relocatable result of an inline-assembly snippet.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InlineAssembly {
    /// Encoded official 6502 instructions and data.
    pub bytes: Vec<u8>,
    /// Direct-call operands requiring linker relocation.
    pub calls: Vec<InlineCall>,
}

/// Source location for an exported assembly function.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AssemblySymbol {
    /// Exported function name.
    pub name: String,
    /// One-based definition line.
    pub line: usize,
}

/// Relocatable assembly module and its compiler contracts.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AssemblyModule {
    /// Shared NesC/assembly object representation.
    pub object: Object,
    /// Maximum additional stack use for each exported function.
    pub stack_bytes: BTreeMap<String, u16>,
    /// Export locations retained for source-map output.
    pub exports: Vec<AssemblySymbol>,
    /// Import locations retained for ABI diagnostics.
    pub imports: Vec<AssemblySymbol>,
}

impl AssemblyError {
    fn global(message: impl Into<String>) -> Self {
        Self {
            line: None,
            message: message.into(),
        }
    }

    fn at(line: usize, message: impl Into<String>) -> Self {
        Self {
            line: Some(line),
            message: message.into(),
        }
    }

    /// Returns the one-based source line when the error belongs to a line.
    #[must_use]
    pub const fn line(&self) -> Option<usize> {
        self.line
    }

    /// Returns the error detail without its line prefix.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for AssemblyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(line) = self.line {
            write!(formatter, "assembly line {line}: {}", self.message)
        } else {
            formatter.write_str(&self.message)
        }
    }
}

impl Error for AssemblyError {}

#[derive(Clone, Debug, Eq, PartialEq)]
enum Statement {
    SetCpu,
    Segment(String),
    Export(String),
    Import(String),
    Bank(SectionPlacement),
    Stack {
        symbol: String,
        bytes: u16,
    },
    Origin(u16),
    Equate(String, u16),
    Label(String),
    Bytes(Vec<u8>),
    Instruction {
        mnemonic: String,
        operand: Option<String>,
        opcode: Opcode,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct LocatedStatement {
    line: usize,
    statement: Statement,
}

/// Assembles the deterministic source subset emitted by `nesc-disasm`.
///
/// The accepted subset includes `.setcpu`, `.segment`, `.org`, `.byte`,
/// absolute symbol assignments, labels, and every official 6502 instruction.
/// It deliberately rejects undocumented opcodes and unrelated directives.
///
/// # Errors
///
/// Returns a bounded, line-qualified diagnostic for invalid syntax, duplicate
/// symbols, invalid addressing, branch overflow, or an unexpected PRG size.
pub fn assemble_recovery(
    source: &str,
    expected_prg_len: usize,
    limits: AssemblyLimits,
) -> Result<Vec<u8>, AssemblyError> {
    if source.len() > limits.max_source_bytes {
        return Err(AssemblyError::global(format!(
            "assembly source exceeds the {}-byte limit",
            limits.max_source_bytes
        )));
    }
    if expected_prg_len > limits.max_output_bytes {
        return Err(AssemblyError::global(format!(
            "expected PRG size exceeds the {}-byte output limit",
            limits.max_output_bytes
        )));
    }
    let statements = parse(source, limits)?;
    for located in &statements {
        match &located.statement {
            Statement::Segment(name) if name == "PRG" => {}
            Statement::Segment(name) => {
                return Err(AssemblyError::at(
                    located.line,
                    format!("recovery assembly does not support segment `{name}`"),
                ));
            }
            Statement::Export(_)
            | Statement::Import(_)
            | Statement::Bank(_)
            | Statement::Stack { .. } => {
                return Err(AssemblyError::at(
                    located.line,
                    "module directives are not valid in recovery assembly",
                ));
            }
            _ => {}
        }
    }
    let symbols = collect_symbols(&statements, limits)?;
    emit(&statements, &symbols, expected_prg_len, limits)
}

/// Assembles a position-independent inline-assembly snippet.
///
/// The inline subset accepts official 6502 instructions and `.byte`. Labels,
/// equates, origin changes, and segment directives are rejected because the
/// surrounding compiler owns section placement and relocations. Branches must
/// use a current-location expression such as `*+4` or `*-6`.
///
/// # Errors
///
/// Returns a bounded, line-qualified diagnostic for invalid or
/// position-dependent source.
pub fn assemble_inline(source: &str, limits: AssemblyLimits) -> Result<Vec<u8>, AssemblyError> {
    assemble_inline_with_calls(source, &[], limits).map(|assembly| assembly.bytes)
}

/// Assembles inline source while retaining declared `JSR` symbol relocations.
///
/// Every symbolic `JSR` operand must appear in `allowed_calls`; other symbolic
/// operands remain invalid in the position-independent inline subset.
///
/// # Errors
///
/// Returns a bounded, line-qualified diagnostic for invalid source or an
/// undeclared symbolic call.
pub fn assemble_inline_with_calls(
    source: &str,
    allowed_calls: &[String],
    limits: AssemblyLimits,
) -> Result<InlineAssembly, AssemblyError> {
    if source.len() > limits.max_source_bytes {
        return Err(AssemblyError::global(format!(
            "assembly source exceeds the {}-byte limit",
            limits.max_source_bytes
        )));
    }
    let mut parsed = parse(source, limits)?;
    let mut expected_len = 0_usize;
    let mut calls = Vec::new();
    for located in &mut parsed {
        match &mut located.statement {
            Statement::Bytes(bytes) => expected_len = expected_len.saturating_add(bytes.len()),
            Statement::Instruction {
                mnemonic,
                operand,
                opcode,
            } => {
                if opcode.mode == AddressingMode::Relative
                    && !operand.as_deref().is_some_and(|value| {
                        value.replace(' ', "").to_ascii_lowercase().starts_with('*')
                    })
                {
                    return Err(AssemblyError::at(
                        located.line,
                        "inline branch target must be relative to the current location",
                    ));
                }
                if mnemonic == "jsr"
                    && let Some(symbol) = operand.as_ref()
                    && is_plain_symbol(symbol)
                {
                    let declared = allowed_calls
                        .iter()
                        .find(|allowed| allowed.eq_ignore_ascii_case(symbol))
                        .cloned()
                        .ok_or_else(|| {
                            AssemblyError::at(
                                located.line,
                                format!("inline call to undeclared symbol `{symbol}`"),
                            )
                        })?;
                    calls.push(InlineCall {
                        offset: u32::try_from(expected_len + 1).map_err(|_| {
                            AssemblyError::at(located.line, "inline call offset is too large")
                        })?,
                        symbol: declared,
                    });
                    *operand = Some("$0000".to_owned());
                }
                expected_len = expected_len.saturating_add(usize::from(opcode.len()));
            }
            Statement::SetCpu | Statement::Segment(_) | Statement::Origin(_) => {
                return Err(AssemblyError::at(
                    located.line,
                    "inline assembly cannot change the CPU, segment, or origin",
                ));
            }
            Statement::Equate(_, _)
            | Statement::Label(_)
            | Statement::Export(_)
            | Statement::Import(_)
            | Statement::Bank(_)
            | Statement::Stack { .. } => {
                return Err(AssemblyError::at(
                    located.line,
                    "inline assembly cannot define symbols",
                ));
            }
        }
    }
    if expected_len > limits.max_output_bytes {
        return Err(AssemblyError::global(format!(
            "assembly exceeds the {}-byte output limit",
            limits.max_output_bytes
        )));
    }
    let mut statements = Vec::with_capacity(parsed.len() + 1);
    statements.push(LocatedStatement {
        line: 1,
        statement: Statement::Origin(0),
    });
    statements.extend(parsed);
    let bytes = emit(&statements, &BTreeMap::new(), expected_len, limits)?;
    Ok(InlineAssembly { bytes, calls })
}

/// Assembles one standalone source file into the shared relocatable object
/// representation.
///
/// Modules use `.segment "CODE"`, `.export name`, `.import name`, an optional
/// module-wide `.nesc_bank fixed|number`, and one `.nesc_stack name, bytes`
/// contract for every exported function. Symbolic 16-bit operands and branch
/// targets become linker relocations.
///
/// # Errors
///
/// Returns bounded diagnostics for malformed source, unsupported directives,
/// symbol conflicts, missing stack contracts, or invalid relocations.
pub fn assemble_module(
    source: &str,
    module_name: &str,
    limits: AssemblyLimits,
) -> Result<AssemblyModule, AssemblyError> {
    if source.len() > limits.max_source_bytes {
        return Err(AssemblyError::global(format!(
            "assembly source exceeds the {}-byte limit",
            limits.max_source_bytes
        )));
    }
    let statements = parse(source, limits)?;
    let mut labels = BTreeMap::<String, (String, u32, usize)>::new();
    let mut equates = BTreeMap::<String, u16>::new();
    let mut exports = BTreeMap::<String, (String, usize)>::new();
    let mut imports = BTreeMap::<String, (String, usize)>::new();
    let mut stack_contracts = BTreeMap::<String, (u16, usize)>::new();
    let mut placement = SectionPlacement::Any;
    let mut bank_directive = None;
    let mut in_code = false;
    let mut offset = 0_u32;

    for located in &statements {
        match &located.statement {
            Statement::SetCpu => {}
            Statement::Segment(name) if name == "CODE" => in_code = true,
            Statement::Segment(name) => {
                return Err(AssemblyError::at(
                    located.line,
                    format!("assembly modules do not support segment `{name}`"),
                ));
            }
            Statement::Origin(_) => {
                return Err(AssemblyError::at(
                    located.line,
                    "relocatable assembly modules cannot set an origin",
                ));
            }
            Statement::Equate(name, value) => {
                let key = name.to_ascii_lowercase();
                if equates.insert(key.clone(), *value).is_some() || labels.contains_key(&key) {
                    return Err(AssemblyError::at(
                        located.line,
                        format!("symbol `{name}` is defined more than once"),
                    ));
                }
            }
            Statement::Label(name) => {
                require_code_segment(in_code, located.line)?;
                let key = name.to_ascii_lowercase();
                if labels
                    .insert(key.clone(), (name.clone(), offset, located.line))
                    .is_some()
                    || equates.contains_key(&key)
                {
                    return Err(AssemblyError::at(
                        located.line,
                        format!("symbol `{name}` is defined more than once"),
                    ));
                }
            }
            Statement::Export(name) => {
                insert_module_directive(&mut exports, name, located.line, ".export")?;
            }
            Statement::Import(name) => {
                insert_module_directive(&mut imports, name, located.line, ".import")?;
            }
            Statement::Bank(requested) => {
                if bank_directive.replace(located.line).is_some() {
                    return Err(AssemblyError::at(
                        located.line,
                        "`.nesc_bank` appears more than once",
                    ));
                }
                placement = *requested;
            }
            Statement::Stack { symbol, bytes } => {
                let key = symbol.to_ascii_lowercase();
                if stack_contracts
                    .insert(key, (*bytes, located.line))
                    .is_some()
                {
                    return Err(AssemblyError::at(
                        located.line,
                        format!("stack use for `{symbol}` is declared more than once"),
                    ));
                }
            }
            Statement::Bytes(bytes) => {
                require_code_segment(in_code, located.line)?;
                advance_module_offset(&mut offset, bytes.len(), located.line, limits)?;
            }
            Statement::Instruction { opcode, .. } => {
                require_code_segment(in_code, located.line)?;
                advance_module_offset(
                    &mut offset,
                    usize::from(opcode.len()),
                    located.line,
                    limits,
                )?;
            }
        }
        if labels.len().saturating_add(imports.len()) > limits.max_symbols {
            return Err(AssemblyError::global(format!(
                "assembly exceeds the {}-symbol limit",
                limits.max_symbols
            )));
        }
    }

    for (key, (name, line)) in &exports {
        let Some((label_name, _, _)) = labels.get(key) else {
            return Err(AssemblyError::at(
                *line,
                format!("exported function `{name}` has no label definition"),
            ));
        };
        if label_name != name {
            return Err(AssemblyError::at(
                *line,
                format!("export `{name}` must match label spelling `{label_name}` exactly"),
            ));
        }
        if imports.contains_key(key) {
            return Err(AssemblyError::at(
                *line,
                format!("symbol `{name}` cannot be both imported and exported"),
            ));
        }
        if !stack_contracts.contains_key(key) {
            return Err(AssemblyError::at(
                *line,
                format!("exported function `{name}` requires a `.nesc_stack` contract"),
            ));
        }
    }
    for (key, (_, line)) in &imports {
        if labels.contains_key(key) {
            return Err(AssemblyError::at(
                *line,
                "an imported symbol cannot also be defined in the same module",
            ));
        }
    }
    for (key, (_, line)) in &stack_contracts {
        if !exports.contains_key(key) {
            return Err(AssemblyError::at(
                *line,
                "`.nesc_stack` requires an exported function",
            ));
        }
    }

    let mut object = Object::default();
    let section = object
        .add_section_with_placement(
            format!(".text.{module_name}"),
            SectionKind::Code,
            1,
            placement,
        )
        .map_err(|error| AssemblyError::global(error.to_string()))?;
    let mut symbol_ids = BTreeMap::<String, SymbolId>::new();
    let mut export_locations = Vec::new();
    let mut import_locations = Vec::new();
    for (key, (name, symbol_offset, line)) in &labels {
        let exported = exports.contains_key(key);
        let symbol = object
            .add_symbol(
                name,
                Some(section),
                *symbol_offset,
                if exported {
                    SymbolKind::Function
                } else {
                    SymbolKind::Label
                },
                if exported {
                    Binding::Global
                } else {
                    Binding::Local
                },
            )
            .map_err(|error| AssemblyError::at(*line, error.to_string()))?;
        symbol_ids.insert(key.clone(), symbol);
        if exported {
            export_locations.push(AssemblySymbol {
                name: name.clone(),
                line: *line,
            });
        }
    }
    for (key, (name, line)) in &imports {
        let symbol = object
            .add_symbol(name, None, 0, SymbolKind::Function, Binding::Global)
            .map_err(|error| AssemblyError::at(*line, error.to_string()))?;
        symbol_ids.insert(key.clone(), symbol);
        import_locations.push(AssemblySymbol {
            name: name.clone(),
            line: *line,
        });
    }

    let mut output = Vec::with_capacity(offset as usize);
    for located in &statements {
        match &located.statement {
            Statement::Bytes(bytes) => append(&mut output, bytes, located.line, limits)?,
            Statement::Instruction {
                mnemonic,
                operand,
                opcode,
            } => {
                if let Some(symbol_name) = relocation_symbol(operand.as_deref(), opcode.mode) {
                    let key = symbol_name.to_ascii_lowercase();
                    if !equates.contains_key(&key) {
                        let symbol = symbol_ids.get(&key).copied().ok_or_else(|| {
                            AssemblyError::at(
                                located.line,
                                format!("undefined assembly symbol `{symbol_name}`"),
                            )
                        })?;
                        let kind = relocation_kind(opcode.mode).ok_or_else(|| {
                            AssemblyError::at(
                                located.line,
                                format!(
                                    "symbolic operand `{symbol_name}` requires an unsupported 8-bit relocation"
                                ),
                            )
                        })?;
                        output.push(opcode.byte);
                        let relocation_offset = u32::try_from(output.len()).map_err(|_| {
                            AssemblyError::at(located.line, "assembly output offset is too large")
                        })?;
                        match kind {
                            RelocationKind::Absolute16 => output.extend_from_slice(&[0, 0]),
                            RelocationKind::Relative8 => output.push(0),
                        }
                        object.add_relocation(Relocation {
                            section,
                            offset: relocation_offset,
                            kind,
                            symbol,
                            addend: 0,
                        });
                        continue;
                    }
                }
                let encoded = encode_instruction(
                    mnemonic,
                    operand.as_deref(),
                    *opcode,
                    u16::try_from(output.len()).map_err(|_| {
                        AssemblyError::at(located.line, "assembly module exceeds 64 KiB")
                    })?,
                    &equates,
                    located.line,
                )?;
                append(&mut output, &encoded, located.line, limits)?;
            }
            Statement::SetCpu
            | Statement::Segment(_)
            | Statement::Origin(_)
            | Statement::Equate(_, _)
            | Statement::Label(_)
            | Statement::Export(_)
            | Statement::Import(_)
            | Statement::Bank(_)
            | Statement::Stack { .. } => {}
        }
    }
    *object
        .section_bytes_mut(section)
        .map_err(|error| AssemblyError::global(error.to_string()))? = output;
    object.validate().map_err(|errors| {
        AssemblyError::global(
            errors
                .into_iter()
                .map(|error| error.to_string())
                .collect::<Vec<_>>()
                .join("; "),
        )
    })?;
    let stack_bytes = exports
        .iter()
        .map(|(key, (name, _))| (name.clone(), stack_contracts[key].0))
        .collect();
    Ok(AssemblyModule {
        object,
        stack_bytes,
        exports: export_locations,
        imports: import_locations,
    })
}

fn require_code_segment(in_code: bool, line: usize) -> Result<(), AssemblyError> {
    if in_code {
        Ok(())
    } else {
        Err(AssemblyError::at(
            line,
            "emitted assembly must follow `.segment \"CODE\"`",
        ))
    }
}

fn advance_module_offset(
    offset: &mut u32,
    amount: usize,
    line: usize,
    limits: AssemblyLimits,
) -> Result<(), AssemblyError> {
    let amount =
        u32::try_from(amount).map_err(|_| AssemblyError::at(line, "assembly item is too large"))?;
    *offset = offset
        .checked_add(amount)
        .ok_or_else(|| AssemblyError::at(line, "assembly output offset overflows"))?;
    if *offset as usize > limits.max_output_bytes {
        return Err(AssemblyError::at(
            line,
            format!(
                "assembly exceeds the {}-byte output limit",
                limits.max_output_bytes
            ),
        ));
    }
    Ok(())
}

fn insert_module_directive(
    directives: &mut BTreeMap<String, (String, usize)>,
    name: &str,
    line: usize,
    directive: &str,
) -> Result<(), AssemblyError> {
    if directives
        .insert(name.to_ascii_lowercase(), (name.to_owned(), line))
        .is_some()
    {
        Err(AssemblyError::at(
            line,
            format!("`{directive}` for `{name}` appears more than once"),
        ))
    } else {
        Ok(())
    }
}

fn relocation_symbol(operand: Option<&str>, mode: AddressingMode) -> Option<String> {
    let compact = operand?.replace(' ', "").to_ascii_lowercase();
    let operand = compact.as_str();
    let expression = match mode {
        AddressingMode::Relative | AddressingMode::Absolute | AddressingMode::ZeroPage => operand,
        AddressingMode::AbsoluteX | AddressingMode::ZeroPageX => operand.strip_suffix(",x")?,
        AddressingMode::AbsoluteY | AddressingMode::ZeroPageY => operand.strip_suffix(",y")?,
        AddressingMode::Indirect => operand.strip_prefix('(')?.strip_suffix(')')?,
        AddressingMode::IndexedIndirect => operand.strip_prefix('(')?.strip_suffix(",x)")?,
        AddressingMode::IndirectIndexed => operand.strip_prefix('(')?.strip_suffix("),y")?,
        AddressingMode::Immediate => operand.strip_prefix('#')?,
        AddressingMode::Implied | AddressingMode::Accumulator => return None,
    }
    .trim();
    is_plain_symbol(expression).then_some(expression.to_owned())
}

fn relocation_kind(mode: AddressingMode) -> Option<RelocationKind> {
    match mode {
        AddressingMode::Relative => Some(RelocationKind::Relative8),
        AddressingMode::Absolute
        | AddressingMode::AbsoluteX
        | AddressingMode::AbsoluteY
        | AddressingMode::Indirect => Some(RelocationKind::Absolute16),
        AddressingMode::Implied
        | AddressingMode::Accumulator
        | AddressingMode::Immediate
        | AddressingMode::ZeroPage
        | AddressingMode::ZeroPageX
        | AddressingMode::ZeroPageY
        | AddressingMode::IndexedIndirect
        | AddressingMode::IndirectIndexed => None,
    }
}

fn is_plain_symbol(value: &str) -> bool {
    let value = value.trim();
    let mut characters = value.chars();
    characters
        .next()
        .is_some_and(|character| character == '_' || character.is_ascii_alphabetic())
        && characters.all(|character| character == '_' || character.is_ascii_alphanumeric())
}

fn parse(source: &str, limits: AssemblyLimits) -> Result<Vec<LocatedStatement>, AssemblyError> {
    let mut statements = Vec::new();
    for (index, original) in source.lines().enumerate() {
        let line = index + 1;
        if line > limits.max_lines {
            return Err(AssemblyError::global(format!(
                "assembly source exceeds the {}-line limit",
                limits.max_lines
            )));
        }
        let text = original
            .split_once(';')
            .map_or(original, |(code, _)| code)
            .trim();
        if text.is_empty() {
            continue;
        }
        let statement = parse_statement(text, line)?;
        statements.push(LocatedStatement { line, statement });
    }
    Ok(statements)
}

fn parse_statement(text: &str, line: usize) -> Result<Statement, AssemblyError> {
    if text.eq_ignore_ascii_case(".setcpu \"6502\"") {
        return Ok(Statement::SetCpu);
    }
    if let Some(value) = text.strip_prefix(".segment ") {
        let value = value.trim();
        let Some(name) = value
            .strip_prefix('"')
            .and_then(|value| value.strip_suffix('"'))
        else {
            return Err(AssemblyError::at(
                line,
                "`.segment` requires a quoted segment name",
            ));
        };
        return Ok(Statement::Segment(name.to_ascii_uppercase()));
    }
    if let Some(name) = text.strip_prefix(".export ") {
        let name = name.trim();
        validate_symbol(name, line)?;
        return Ok(Statement::Export(name.to_owned()));
    }
    if let Some(name) = text.strip_prefix(".import ") {
        let name = name.trim();
        validate_symbol(name, line)?;
        return Ok(Statement::Import(name.to_owned()));
    }
    if let Some(contract) = text.strip_prefix(".nesc_stack ") {
        let Some((symbol, bytes)) = contract.split_once(',') else {
            return Err(AssemblyError::at(
                line,
                "`.nesc_stack` requires `symbol, bytes`",
            ));
        };
        let symbol = symbol.trim();
        validate_symbol(symbol, line)?;
        return Ok(Statement::Stack {
            symbol: symbol.to_owned(),
            bytes: parse_u16(bytes.trim(), line)?,
        });
    }
    if let Some(bank) = text.strip_prefix(".nesc_bank ") {
        let bank = bank.trim();
        return if bank.eq_ignore_ascii_case("fixed") {
            Ok(Statement::Bank(SectionPlacement::Fixed))
        } else {
            parse_u16(bank, line).map(|bank| Statement::Bank(SectionPlacement::Bank(bank)))
        };
    }
    if let Some(value) = text.strip_prefix(".org ") {
        return parse_u16(value.trim(), line).map(Statement::Origin);
    }
    if let Some(values) = text.strip_prefix(".byte ") {
        let bytes = values
            .split(',')
            .map(|value| parse_u8(value.trim(), line))
            .collect::<Result<Vec<_>, _>>()?;
        if bytes.is_empty() {
            return Err(AssemblyError::at(line, "`.byte` requires a value"));
        }
        return Ok(Statement::Bytes(bytes));
    }
    if text.starts_with('.') {
        return Err(AssemblyError::at(
            line,
            format!("unsupported directive `{text}`"),
        ));
    }
    if let Some(name) = text.strip_suffix(':') {
        validate_symbol(name, line)?;
        return Ok(Statement::Label(name.to_owned()));
    }
    if let Some((name, value)) = text.split_once('=') {
        let name = name.trim();
        validate_symbol(name, line)?;
        return Ok(Statement::Equate(
            name.to_owned(),
            parse_u16(value.trim(), line)?,
        ));
    }
    let (mnemonic, operand) = text
        .split_once(char::is_whitespace)
        .map_or((text, None), |(mnemonic, operand)| {
            (mnemonic, Some(operand.trim()))
        });
    let mnemonic = mnemonic.to_ascii_lowercase();
    let operand = operand
        .filter(|operand| !operand.is_empty())
        .map(str::to_owned);
    let instruction = select_opcode(&mnemonic, operand.as_deref(), line)?;
    Ok(Statement::Instruction {
        mnemonic,
        operand,
        opcode: instruction,
    })
}

fn validate_symbol(name: &str, line: usize) -> Result<(), AssemblyError> {
    let mut characters = name.chars();
    let valid_start = characters
        .next()
        .is_some_and(|character| character == '_' || character.is_ascii_alphabetic());
    if !valid_start
        || !characters.all(|character| character == '_' || character.is_ascii_alphanumeric())
    {
        return Err(AssemblyError::at(line, format!("invalid symbol `{name}`")));
    }
    Ok(())
}

fn collect_symbols(
    statements: &[LocatedStatement],
    limits: AssemblyLimits,
) -> Result<BTreeMap<String, u16>, AssemblyError> {
    let mut symbols = BTreeMap::new();
    let mut pc = None::<u32>;
    for located in statements {
        match &located.statement {
            Statement::Origin(origin) => pc = Some(u32::from(*origin)),
            Statement::Equate(name, value) => {
                insert_symbol(&mut symbols, name, *value, located.line, limits)?;
            }
            Statement::Label(name) => {
                let address = pc.ok_or_else(|| {
                    AssemblyError::at(located.line, "label appears before the first `.org`")
                })?;
                insert_symbol(&mut symbols, name, address as u16, located.line, limits)?;
            }
            Statement::Bytes(bytes) => advance_pc(&mut pc, bytes.len(), located.line)?,
            Statement::Instruction { opcode, .. } => {
                advance_pc(&mut pc, usize::from(opcode.len()), located.line)?;
            }
            Statement::SetCpu
            | Statement::Segment(_)
            | Statement::Export(_)
            | Statement::Import(_)
            | Statement::Bank(_)
            | Statement::Stack { .. } => {}
        }
    }
    Ok(symbols)
}

fn insert_symbol(
    symbols: &mut BTreeMap<String, u16>,
    name: &str,
    value: u16,
    line: usize,
    limits: AssemblyLimits,
) -> Result<(), AssemblyError> {
    if symbols.len() >= limits.max_symbols {
        return Err(AssemblyError::global(format!(
            "assembly exceeds the {}-symbol limit",
            limits.max_symbols
        )));
    }
    if symbols.insert(name.to_ascii_lowercase(), value).is_some() {
        return Err(AssemblyError::at(
            line,
            format!("symbol `{name}` is defined more than once"),
        ));
    }
    Ok(())
}

fn emit(
    statements: &[LocatedStatement],
    symbols: &BTreeMap<String, u16>,
    expected_prg_len: usize,
    limits: AssemblyLimits,
) -> Result<Vec<u8>, AssemblyError> {
    let mut output = Vec::with_capacity(expected_prg_len);
    let mut pc = None::<u32>;
    for located in statements {
        match &located.statement {
            Statement::Origin(origin) => {
                if let Some(current) = pc
                    && current as u16 != *origin
                {
                    return Err(AssemblyError::at(
                        located.line,
                        format!(
                            "`.org` changes the location from ${:04X} to ${origin:04X}",
                            current as u16
                        ),
                    ));
                }
                pc = Some(u32::from(*origin));
            }
            Statement::Bytes(bytes) => {
                require_origin(pc, located.line)?;
                append(&mut output, bytes, located.line, limits)?;
                advance_pc(&mut pc, bytes.len(), located.line)?;
            }
            Statement::Instruction {
                mnemonic,
                operand,
                opcode,
            } => {
                let address = require_origin(pc, located.line)? as u16;
                let encoded = encode_instruction(
                    mnemonic,
                    operand.as_deref(),
                    *opcode,
                    address,
                    symbols,
                    located.line,
                )?;
                append(&mut output, &encoded, located.line, limits)?;
                advance_pc(&mut pc, encoded.len(), located.line)?;
            }
            Statement::SetCpu
            | Statement::Segment(_)
            | Statement::Equate(_, _)
            | Statement::Label(_)
            | Statement::Export(_)
            | Statement::Import(_)
            | Statement::Bank(_)
            | Statement::Stack { .. } => {}
        }
    }
    if output.len() != expected_prg_len {
        return Err(AssemblyError::global(format!(
            "assembled PRG contains {} bytes; expected {expected_prg_len}",
            output.len()
        )));
    }
    Ok(output)
}

fn require_origin(pc: Option<u32>, line: usize) -> Result<u32, AssemblyError> {
    pc.ok_or_else(|| AssemblyError::at(line, "emitted bytes appear before the first `.org`"))
}

fn advance_pc(pc: &mut Option<u32>, amount: usize, line: usize) -> Result<(), AssemblyError> {
    let address = require_origin(*pc, line)?;
    *pc = Some(
        address
            .checked_add(u32::try_from(amount).map_err(|_| {
                AssemblyError::at(line, "instruction size exceeds the address space")
            })?)
            .ok_or_else(|| AssemblyError::at(line, "assembly location counter overflows"))?,
    );
    Ok(())
}

fn append(
    output: &mut Vec<u8>,
    bytes: &[u8],
    line: usize,
    limits: AssemblyLimits,
) -> Result<(), AssemblyError> {
    if output.len().saturating_add(bytes.len()) > limits.max_output_bytes {
        return Err(AssemblyError::at(
            line,
            format!(
                "assembly exceeds the {}-byte output limit",
                limits.max_output_bytes
            ),
        ));
    }
    output.extend_from_slice(bytes);
    Ok(())
}

fn select_opcode(
    mnemonic: &str,
    operand: Option<&str>,
    line: usize,
) -> Result<Opcode, AssemblyError> {
    let candidates = (0..=u8::MAX)
        .filter_map(opcode)
        .filter(|candidate| candidate.mnemonic.as_str() == mnemonic)
        .collect::<Vec<_>>();
    if candidates.is_empty() {
        return Err(AssemblyError::at(
            line,
            format!("unknown official 6502 mnemonic `{mnemonic}`"),
        ));
    }
    let mode = infer_mode(&candidates, operand, line)?;
    candidates
        .into_iter()
        .find(|candidate| candidate.mode == mode)
        .ok_or_else(|| {
            AssemblyError::at(
                line,
                format!("`{mnemonic}` does not support {mode:?} addressing"),
            )
        })
}

fn infer_mode(
    candidates: &[Opcode],
    operand: Option<&str>,
    line: usize,
) -> Result<AddressingMode, AssemblyError> {
    let has = |mode| candidates.iter().any(|candidate| candidate.mode == mode);
    let Some(operand) = operand else {
        return Ok(AddressingMode::Implied);
    };
    let compact = operand.replace(' ', "").to_ascii_lowercase();
    if compact == "a" {
        return Ok(AddressingMode::Accumulator);
    }
    if compact.starts_with('#') {
        return Ok(AddressingMode::Immediate);
    }
    if has(AddressingMode::Relative) {
        return Ok(AddressingMode::Relative);
    }
    if compact.starts_with('(') && compact.ends_with(",x)") {
        return Ok(AddressingMode::IndexedIndirect);
    }
    if compact.starts_with('(') && compact.ends_with("),y") {
        return Ok(AddressingMode::IndirectIndexed);
    }
    if compact.starts_with('(') && compact.ends_with(')') {
        return Ok(AddressingMode::Indirect);
    }
    if let Some(base) = compact.strip_suffix(",x") {
        return Ok(
            if has(AddressingMode::ZeroPageX) && expression_is_byte(base) {
                AddressingMode::ZeroPageX
            } else {
                AddressingMode::AbsoluteX
            },
        );
    }
    if let Some(base) = compact.strip_suffix(",y") {
        return Ok(
            if has(AddressingMode::ZeroPageY) && expression_is_byte(base) {
                AddressingMode::ZeroPageY
            } else {
                AddressingMode::AbsoluteY
            },
        );
    }
    if has(AddressingMode::ZeroPage) && expression_is_byte(&compact) {
        return Ok(AddressingMode::ZeroPage);
    }
    if has(AddressingMode::Absolute) {
        return Ok(AddressingMode::Absolute);
    }
    Err(AssemblyError::at(
        line,
        format!("cannot infer addressing mode for operand `{operand}`"),
    ))
}

fn expression_is_byte(expression: &str) -> bool {
    expression
        .strip_prefix('$')
        .is_some_and(|digits| digits.len() <= 2 && u8::from_str_radix(digits, 16).is_ok())
        || expression
            .strip_prefix("0x")
            .is_some_and(|digits| digits.len() <= 2 && u8::from_str_radix(digits, 16).is_ok())
        || expression.parse::<u8>().is_ok()
}

fn encode_instruction(
    mnemonic: &str,
    operand: Option<&str>,
    opcode: Opcode,
    address: u16,
    symbols: &BTreeMap<String, u16>,
    line: usize,
) -> Result<Vec<u8>, AssemblyError> {
    let mut encoded = vec![opcode.byte];
    match opcode.mode {
        AddressingMode::Implied | AddressingMode::Accumulator => {}
        AddressingMode::Relative => {
            let operand = operand.expect("relative instruction has an operand");
            let displacement = relative_displacement(operand, address, symbols, line)?;
            encoded.push(displacement as u8);
        }
        AddressingMode::Immediate
        | AddressingMode::ZeroPage
        | AddressingMode::ZeroPageX
        | AddressingMode::ZeroPageY
        | AddressingMode::IndexedIndirect
        | AddressingMode::IndirectIndexed => {
            let value = operand_value(operand, opcode.mode, symbols, line)?;
            let byte = u8::try_from(value).map_err(|_| {
                AssemblyError::at(
                    line,
                    format!("operand for `{mnemonic}` does not fit in one byte"),
                )
            })?;
            encoded.push(byte);
        }
        AddressingMode::Absolute
        | AddressingMode::AbsoluteX
        | AddressingMode::AbsoluteY
        | AddressingMode::Indirect => {
            let value = operand_value(operand, opcode.mode, symbols, line)?;
            encoded.extend_from_slice(&value.to_le_bytes());
        }
    }
    Ok(encoded)
}

fn operand_value(
    operand: Option<&str>,
    mode: AddressingMode,
    symbols: &BTreeMap<String, u16>,
    line: usize,
) -> Result<u16, AssemblyError> {
    let operand = operand.ok_or_else(|| AssemblyError::at(line, "instruction needs an operand"))?;
    let compact = operand.replace(' ', "").to_ascii_lowercase();
    let expression = match mode {
        AddressingMode::Immediate => compact.strip_prefix('#'),
        AddressingMode::ZeroPageX | AddressingMode::AbsoluteX => compact.strip_suffix(",x"),
        AddressingMode::ZeroPageY | AddressingMode::AbsoluteY => compact.strip_suffix(",y"),
        AddressingMode::Indirect => compact
            .strip_prefix('(')
            .and_then(|value| value.strip_suffix(')')),
        AddressingMode::IndexedIndirect => compact
            .strip_prefix('(')
            .and_then(|value| value.strip_suffix(",x)")),
        AddressingMode::IndirectIndexed => compact
            .strip_prefix('(')
            .and_then(|value| value.strip_suffix("),y")),
        AddressingMode::ZeroPage | AddressingMode::Absolute => Some(compact.as_str()),
        AddressingMode::Implied | AddressingMode::Accumulator | AddressingMode::Relative => None,
    }
    .ok_or_else(|| AssemblyError::at(line, format!("invalid operand `{operand}`")))?;
    evaluate(expression, symbols, line)
}

fn relative_displacement(
    operand: &str,
    address: u16,
    symbols: &BTreeMap<String, u16>,
    line: usize,
) -> Result<i8, AssemblyError> {
    let compact = operand.replace(' ', "").to_ascii_lowercase();
    if let Some(delta) = parse_current_delta(&compact, line)? {
        return i8::try_from(delta - 2).map_err(|_| {
            AssemblyError::at(
                line,
                format!("relative expression `{operand}` is out of range"),
            )
        });
    }
    let target = evaluate(&compact, symbols, line)?;
    let displacement = i32::from(target) - (i32::from(address) + 2);
    i8::try_from(displacement)
        .map_err(|_| AssemblyError::at(line, format!("branch target `{operand}` is out of range")))
}

fn parse_current_delta(expression: &str, line: usize) -> Result<Option<i16>, AssemblyError> {
    let Some(rest) = expression.strip_prefix('*') else {
        return Ok(None);
    };
    if rest.is_empty() {
        return Ok(Some(0));
    }
    let (negative, digits) = if let Some(digits) = rest.strip_prefix('+') {
        (false, digits)
    } else if let Some(digits) = rest.strip_prefix('-') {
        (true, digits)
    } else {
        return Err(AssemblyError::at(
            line,
            format!("invalid current-location expression `{expression}`"),
        ));
    };
    let magnitude = digits.parse::<i16>().map_err(|_| {
        AssemblyError::at(
            line,
            format!("invalid current-location expression `{expression}`"),
        )
    })?;
    Ok(Some(if negative { -magnitude } else { magnitude }))
}

fn evaluate(
    expression: &str,
    symbols: &BTreeMap<String, u16>,
    line: usize,
) -> Result<u16, AssemblyError> {
    if let Ok(value) = parse_u16(expression, line) {
        return Ok(value);
    }
    symbols
        .get(expression)
        .copied()
        .ok_or_else(|| AssemblyError::at(line, format!("undefined symbol or value `{expression}`")))
}

fn parse_u8(value: &str, line: usize) -> Result<u8, AssemblyError> {
    let value = parse_u16(value, line)?;
    u8::try_from(value)
        .map_err(|_| AssemblyError::at(line, format!("value `{value}` does not fit in one byte")))
}

fn parse_u16(value: &str, line: usize) -> Result<u16, AssemblyError> {
    let parsed = if let Some(hex) = value.strip_prefix('$') {
        u16::from_str_radix(hex, 16)
    } else if let Some(hex) = value.strip_prefix("0x") {
        u16::from_str_radix(hex, 16)
    } else {
        value.parse::<u16>()
    };
    parsed.map_err(|_| AssemblyError::at(line, format!("invalid 16-bit value `{value}`")))
}

#[cfg(test)]
mod tests {
    use nesc_disasm::{AddressingMode, opcode};

    use super::{
        AssemblyLimits, assemble_inline, assemble_inline_with_calls, assemble_module,
        assemble_recovery,
    };

    #[test]
    fn assembles_relocatable_module_contracts() {
        let source = r#"
            .setcpu "6502"
            .segment "CODE"
            .export fast_collision
            .import helper
            .nesc_bank 1
            .nesc_stack fast_collision, 2
            fast_collision:
                jsr helper
                bne finished
            finished:
                rts
        "#;
        let module = assemble_module(source, "collision", AssemblyLimits::default())
            .expect("assembly module");
        assert_eq!(module.object.sections[0].bytes, [0x20, 0, 0, 0xd0, 0, 0x60]);
        assert_eq!(
            module.object.sections[0].placement,
            nesc_object::SectionPlacement::Bank(1)
        );
        assert_eq!(module.object.relocations.len(), 2);
        assert_eq!(
            module.object.relocations[0].kind,
            nesc_object::RelocationKind::Absolute16
        );
        assert_eq!(
            module.object.relocations[1].kind,
            nesc_object::RelocationKind::Relative8
        );
        assert_eq!(module.stack_bytes["fast_collision"], 2);
        assert_eq!(module.exports[0].name, "fast_collision");
    }

    #[test]
    fn rejects_export_without_stack_contract() {
        let error = assemble_module(
            ".segment \"CODE\"\n.export missing\nmissing:\n rts",
            "missing",
            AssemblyLimits::default(),
        )
        .expect_err("missing stack contract");
        assert!(error.message().contains("requires a `.nesc_stack`"));
    }

    #[test]
    fn assembles_position_independent_inline_source() {
        let bytes = assemble_inline("lda #$80\nsta $2000\nbne *-3", AssemblyLimits::default())
            .expect("inline assembly");
        assert_eq!(bytes, [0xa9, 0x80, 0x8d, 0x00, 0x20, 0xd0, 0xfb]);
    }

    #[test]
    fn rejects_position_dependent_inline_source() {
        let label = assemble_inline("again:\nbne again", AssemblyLimits::default())
            .expect_err("label must be rejected");
        assert!(label.message().contains("cannot define symbols"));
    }

    #[test]
    fn retains_declared_inline_call_relocations() {
        let assembled = assemble_inline_with_calls(
            "lda #1\njsr helper\nrts",
            &["helper".to_owned()],
            AssemblyLimits::default(),
        )
        .expect("declared inline call");
        assert_eq!(assembled.bytes, [0xa9, 1, 0x20, 0, 0, 0x60]);
        assert_eq!(assembled.calls[0].offset, 3);
        assert_eq!(assembled.calls[0].symbol, "helper");

        let error = assemble_inline_with_calls("jsr missing", &[], AssemblyLimits::default())
            .expect_err("undeclared inline call");
        assert!(error.message().contains("undeclared symbol"));
    }

    #[test]
    fn assembles_instructions_labels_and_data() {
        let source = r#"
            .setcpu "6502"
            .segment "PRG"
            target = $C008
            .org $C000
            jsr target
            bne *+4
            .byte $02, $AA, $60
            lda #$2A
            rts
        "#;
        let bytes = assemble_recovery(source, 11, AssemblyLimits::default()).expect("assembly");
        assert_eq!(
            bytes,
            [
                0x20, 0x08, 0xc0, 0xd0, 0x02, 0x02, 0xaa, 0x60, 0xa9, 0x2a, 0x60
            ]
        );
    }

    #[test]
    fn rejects_unsupported_directives_and_wrong_size() {
        let directive = assemble_recovery(".incbin \"game.nes\"", 1, AssemblyLimits::default())
            .expect_err("unsupported directive");
        assert!(directive.message().contains("unsupported directive"));

        let size = assemble_recovery(".org $C000\n.byte $00", 2, AssemblyLimits::default())
            .expect_err("wrong output size");
        assert!(size.message().contains("expected 2"));
    }

    #[test]
    fn reassembles_every_official_opcode_form() {
        let mut source = String::from(".setcpu \"6502\"\n.segment \"PRG\"\n.org $8000\n");
        let mut expected = Vec::new();
        for byte in 0..=u8::MAX {
            let Some(opcode) = opcode(byte) else {
                continue;
            };
            source.push_str(opcode.mnemonic.as_str());
            let operand = match opcode.mode {
                AddressingMode::Implied => None,
                AddressingMode::Accumulator => Some("a"),
                AddressingMode::Immediate => Some("#$5A"),
                AddressingMode::ZeroPage => Some("$5A"),
                AddressingMode::ZeroPageX => Some("$5A,x"),
                AddressingMode::ZeroPageY => Some("$5A,y"),
                AddressingMode::Relative => Some("*+2"),
                AddressingMode::Absolute => Some("$1234"),
                AddressingMode::AbsoluteX => Some("$1234,x"),
                AddressingMode::AbsoluteY => Some("$1234,y"),
                AddressingMode::Indirect => Some("($1234)"),
                AddressingMode::IndexedIndirect => Some("($5A,x)"),
                AddressingMode::IndirectIndexed => Some("($5A),y"),
            };
            if let Some(operand) = operand {
                source.push(' ');
                source.push_str(operand);
            }
            source.push('\n');
            expected.push(byte);
            match opcode.mode.instruction_len() {
                1 => {}
                2 => expected.push(if opcode.mode == AddressingMode::Relative {
                    0
                } else {
                    0x5a
                }),
                3 => expected.extend_from_slice(&[0x34, 0x12]),
                _ => unreachable!("official instruction length"),
            }
        }
        let assembled = assemble_recovery(&source, expected.len(), AssemblyLimits::default())
            .expect("all official opcodes");
        assert_eq!(assembled, expected);
    }
}
