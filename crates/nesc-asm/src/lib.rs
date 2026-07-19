//! Bounded 6502 assembly for NesC interoperability and ROM recovery.

use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;

use nesc_disasm::{AddressingMode, Opcode, opcode};

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
    Segment,
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
    let symbols = collect_symbols(&statements, limits)?;
    emit(&statements, &symbols, expected_prg_len, limits)
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
    if text.eq_ignore_ascii_case(".segment \"PRG\"") {
        return Ok(Statement::Segment);
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
            Statement::SetCpu | Statement::Segment => {}
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
            | Statement::Segment
            | Statement::Equate(_, _)
            | Statement::Label(_) => {}
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

    use super::{AssemblyLimits, assemble_recovery};

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
