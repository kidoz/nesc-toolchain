use std::error::Error;
use std::fmt;

/// Official NMOS 6502 instruction mnemonic supported by the Ricoh CPU.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum Mnemonic {
    Adc,
    And,
    Asl,
    Bcc,
    Bcs,
    Beq,
    Bit,
    Bmi,
    Bne,
    Bpl,
    Brk,
    Bvc,
    Bvs,
    Clc,
    Cld,
    Cli,
    Clv,
    Cmp,
    Cpx,
    Cpy,
    Dec,
    Dex,
    Dey,
    Eor,
    Inc,
    Inx,
    Iny,
    Jmp,
    Jsr,
    Lda,
    Ldx,
    Ldy,
    Lsr,
    Nop,
    Ora,
    Pha,
    Php,
    Pla,
    Plp,
    Rol,
    Ror,
    Rti,
    Rts,
    Sbc,
    Sec,
    Sed,
    Sei,
    Sta,
    Stx,
    Sty,
    Tax,
    Tay,
    Tsx,
    Txa,
    Txs,
    Tya,
}

impl Mnemonic {
    /// Returns canonical lower-case assembly spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Adc => "adc",
            Self::And => "and",
            Self::Asl => "asl",
            Self::Bcc => "bcc",
            Self::Bcs => "bcs",
            Self::Beq => "beq",
            Self::Bit => "bit",
            Self::Bmi => "bmi",
            Self::Bne => "bne",
            Self::Bpl => "bpl",
            Self::Brk => "brk",
            Self::Bvc => "bvc",
            Self::Bvs => "bvs",
            Self::Clc => "clc",
            Self::Cld => "cld",
            Self::Cli => "cli",
            Self::Clv => "clv",
            Self::Cmp => "cmp",
            Self::Cpx => "cpx",
            Self::Cpy => "cpy",
            Self::Dec => "dec",
            Self::Dex => "dex",
            Self::Dey => "dey",
            Self::Eor => "eor",
            Self::Inc => "inc",
            Self::Inx => "inx",
            Self::Iny => "iny",
            Self::Jmp => "jmp",
            Self::Jsr => "jsr",
            Self::Lda => "lda",
            Self::Ldx => "ldx",
            Self::Ldy => "ldy",
            Self::Lsr => "lsr",
            Self::Nop => "nop",
            Self::Ora => "ora",
            Self::Pha => "pha",
            Self::Php => "php",
            Self::Pla => "pla",
            Self::Plp => "plp",
            Self::Rol => "rol",
            Self::Ror => "ror",
            Self::Rti => "rti",
            Self::Rts => "rts",
            Self::Sbc => "sbc",
            Self::Sec => "sec",
            Self::Sed => "sed",
            Self::Sei => "sei",
            Self::Sta => "sta",
            Self::Stx => "stx",
            Self::Sty => "sty",
            Self::Tax => "tax",
            Self::Tay => "tay",
            Self::Tsx => "tsx",
            Self::Txa => "txa",
            Self::Txs => "txs",
            Self::Tya => "tya",
        }
    }
}

impl fmt::Display for Mnemonic {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Official 6502 operand encoding.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum AddressingMode {
    Implied,
    Accumulator,
    Immediate,
    ZeroPage,
    ZeroPageX,
    ZeroPageY,
    Relative,
    Absolute,
    AbsoluteX,
    AbsoluteY,
    Indirect,
    IndexedIndirect,
    IndirectIndexed,
}

impl AddressingMode {
    /// Encoded instruction length in bytes.
    #[must_use]
    pub const fn instruction_len(self) -> u8 {
        match self {
            Self::Implied | Self::Accumulator => 1,
            Self::Immediate
            | Self::ZeroPage
            | Self::ZeroPageX
            | Self::ZeroPageY
            | Self::Relative
            | Self::IndexedIndirect
            | Self::IndirectIndexed => 2,
            Self::Absolute | Self::AbsoluteX | Self::AbsoluteY | Self::Indirect => 3,
        }
    }
}

/// Control-flow behavior needed by recursive traversal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FlowControl {
    Fallthrough,
    Branch,
    Call,
    Jump,
    IndirectJump,
    Return,
    Interrupt,
}

/// Static metadata for one official opcode byte.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Opcode {
    pub byte: u8,
    pub mnemonic: Mnemonic,
    pub mode: AddressingMode,
}

impl Opcode {
    const fn new(byte: u8, mnemonic: Mnemonic, mode: AddressingMode) -> Self {
        Self {
            byte,
            mnemonic,
            mode,
        }
    }

    /// Encoded instruction length.
    #[must_use]
    pub const fn len(self) -> u8 {
        self.mode.instruction_len()
    }

    /// Returns whether this instruction has no operand bytes.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.len() == 1
    }

    /// Control-flow behavior for recursive analysis.
    #[must_use]
    pub const fn flow(self) -> FlowControl {
        match self.mnemonic {
            Mnemonic::Bcc
            | Mnemonic::Bcs
            | Mnemonic::Beq
            | Mnemonic::Bmi
            | Mnemonic::Bne
            | Mnemonic::Bpl
            | Mnemonic::Bvc
            | Mnemonic::Bvs => FlowControl::Branch,
            Mnemonic::Jsr => FlowControl::Call,
            Mnemonic::Jmp if matches!(self.mode, AddressingMode::Indirect) => {
                FlowControl::IndirectJump
            }
            Mnemonic::Jmp => FlowControl::Jump,
            Mnemonic::Rti | Mnemonic::Rts => FlowControl::Return,
            Mnemonic::Brk => FlowControl::Interrupt,
            _ => FlowControl::Fallthrough,
        }
    }
}

/// One decoded instruction without cartridge placement metadata.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DecodedInstruction {
    pub opcode: Opcode,
    bytes: [u8; 3],
}

impl DecodedInstruction {
    /// Exact encoded bytes.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes[..usize::from(self.opcode.len())]
    }

    /// Little-endian operand value, or zero for implied operations.
    #[must_use]
    pub const fn operand(self) -> u16 {
        u16::from_le_bytes([self.bytes[1], self.bytes[2]])
    }
}

/// Failure to decode one byte sequence as an official instruction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DecodeError {
    UnsupportedOpcode(u8),
    Truncated {
        opcode: u8,
        required: usize,
        available: usize,
    },
    EmptyInput,
}

impl fmt::Display for DecodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedOpcode(opcode) => {
                write!(formatter, "${opcode:02X} is not an official 6502 opcode")
            }
            Self::Truncated {
                opcode,
                required,
                available,
            } => write!(
                formatter,
                "opcode ${opcode:02X} requires {required} bytes but only {available} remain"
            ),
            Self::EmptyInput => formatter.write_str("no opcode byte is available"),
        }
    }
}

impl Error for DecodeError {}

/// Decodes one official instruction from the start of `bytes`.
///
/// # Errors
///
/// Returns a failure for an empty input, an undocumented opcode, or a
/// truncated operand.
pub fn decode(bytes: &[u8]) -> Result<DecodedInstruction, DecodeError> {
    let byte = *bytes.first().ok_or(DecodeError::EmptyInput)?;
    let opcode = opcode(byte).ok_or(DecodeError::UnsupportedOpcode(byte))?;
    let required = usize::from(opcode.len());
    if bytes.len() < required {
        return Err(DecodeError::Truncated {
            opcode: byte,
            required,
            available: bytes.len(),
        });
    }
    let mut encoded = [0; 3];
    encoded[..required].copy_from_slice(&bytes[..required]);
    Ok(DecodedInstruction {
        opcode,
        bytes: encoded,
    })
}

/// Returns metadata for an official opcode byte.
#[must_use]
#[allow(clippy::too_many_lines)]
pub const fn opcode(byte: u8) -> Option<Opcode> {
    use AddressingMode as A;
    use Mnemonic as M;
    macro_rules! op {
        ($mnemonic:ident, $mode:ident) => {
            Some(Opcode::new(byte, M::$mnemonic, A::$mode))
        };
    }
    match byte {
        0x00 => op!(Brk, Implied),
        0x01 => op!(Ora, IndexedIndirect),
        0x05 => op!(Ora, ZeroPage),
        0x06 => op!(Asl, ZeroPage),
        0x08 => op!(Php, Implied),
        0x09 => op!(Ora, Immediate),
        0x0a => op!(Asl, Accumulator),
        0x0d => op!(Ora, Absolute),
        0x0e => op!(Asl, Absolute),
        0x10 => op!(Bpl, Relative),
        0x11 => op!(Ora, IndirectIndexed),
        0x15 => op!(Ora, ZeroPageX),
        0x16 => op!(Asl, ZeroPageX),
        0x18 => op!(Clc, Implied),
        0x19 => op!(Ora, AbsoluteY),
        0x1d => op!(Ora, AbsoluteX),
        0x1e => op!(Asl, AbsoluteX),
        0x20 => op!(Jsr, Absolute),
        0x21 => op!(And, IndexedIndirect),
        0x24 => op!(Bit, ZeroPage),
        0x25 => op!(And, ZeroPage),
        0x26 => op!(Rol, ZeroPage),
        0x28 => op!(Plp, Implied),
        0x29 => op!(And, Immediate),
        0x2a => op!(Rol, Accumulator),
        0x2c => op!(Bit, Absolute),
        0x2d => op!(And, Absolute),
        0x2e => op!(Rol, Absolute),
        0x30 => op!(Bmi, Relative),
        0x31 => op!(And, IndirectIndexed),
        0x35 => op!(And, ZeroPageX),
        0x36 => op!(Rol, ZeroPageX),
        0x38 => op!(Sec, Implied),
        0x39 => op!(And, AbsoluteY),
        0x3d => op!(And, AbsoluteX),
        0x3e => op!(Rol, AbsoluteX),
        0x40 => op!(Rti, Implied),
        0x41 => op!(Eor, IndexedIndirect),
        0x45 => op!(Eor, ZeroPage),
        0x46 => op!(Lsr, ZeroPage),
        0x48 => op!(Pha, Implied),
        0x49 => op!(Eor, Immediate),
        0x4a => op!(Lsr, Accumulator),
        0x4c => op!(Jmp, Absolute),
        0x4d => op!(Eor, Absolute),
        0x4e => op!(Lsr, Absolute),
        0x50 => op!(Bvc, Relative),
        0x51 => op!(Eor, IndirectIndexed),
        0x55 => op!(Eor, ZeroPageX),
        0x56 => op!(Lsr, ZeroPageX),
        0x58 => op!(Cli, Implied),
        0x59 => op!(Eor, AbsoluteY),
        0x5d => op!(Eor, AbsoluteX),
        0x5e => op!(Lsr, AbsoluteX),
        0x60 => op!(Rts, Implied),
        0x61 => op!(Adc, IndexedIndirect),
        0x65 => op!(Adc, ZeroPage),
        0x66 => op!(Ror, ZeroPage),
        0x68 => op!(Pla, Implied),
        0x69 => op!(Adc, Immediate),
        0x6a => op!(Ror, Accumulator),
        0x6c => op!(Jmp, Indirect),
        0x6d => op!(Adc, Absolute),
        0x6e => op!(Ror, Absolute),
        0x70 => op!(Bvs, Relative),
        0x71 => op!(Adc, IndirectIndexed),
        0x75 => op!(Adc, ZeroPageX),
        0x76 => op!(Ror, ZeroPageX),
        0x78 => op!(Sei, Implied),
        0x79 => op!(Adc, AbsoluteY),
        0x7d => op!(Adc, AbsoluteX),
        0x7e => op!(Ror, AbsoluteX),
        0x81 => op!(Sta, IndexedIndirect),
        0x84 => op!(Sty, ZeroPage),
        0x85 => op!(Sta, ZeroPage),
        0x86 => op!(Stx, ZeroPage),
        0x88 => op!(Dey, Implied),
        0x8a => op!(Txa, Implied),
        0x8c => op!(Sty, Absolute),
        0x8d => op!(Sta, Absolute),
        0x8e => op!(Stx, Absolute),
        0x90 => op!(Bcc, Relative),
        0x91 => op!(Sta, IndirectIndexed),
        0x94 => op!(Sty, ZeroPageX),
        0x95 => op!(Sta, ZeroPageX),
        0x96 => op!(Stx, ZeroPageY),
        0x98 => op!(Tya, Implied),
        0x99 => op!(Sta, AbsoluteY),
        0x9a => op!(Txs, Implied),
        0x9d => op!(Sta, AbsoluteX),
        0xa0 => op!(Ldy, Immediate),
        0xa1 => op!(Lda, IndexedIndirect),
        0xa2 => op!(Ldx, Immediate),
        0xa4 => op!(Ldy, ZeroPage),
        0xa5 => op!(Lda, ZeroPage),
        0xa6 => op!(Ldx, ZeroPage),
        0xa8 => op!(Tay, Implied),
        0xa9 => op!(Lda, Immediate),
        0xaa => op!(Tax, Implied),
        0xac => op!(Ldy, Absolute),
        0xad => op!(Lda, Absolute),
        0xae => op!(Ldx, Absolute),
        0xb0 => op!(Bcs, Relative),
        0xb1 => op!(Lda, IndirectIndexed),
        0xb4 => op!(Ldy, ZeroPageX),
        0xb5 => op!(Lda, ZeroPageX),
        0xb6 => op!(Ldx, ZeroPageY),
        0xb8 => op!(Clv, Implied),
        0xb9 => op!(Lda, AbsoluteY),
        0xba => op!(Tsx, Implied),
        0xbc => op!(Ldy, AbsoluteX),
        0xbd => op!(Lda, AbsoluteX),
        0xbe => op!(Ldx, AbsoluteY),
        0xc0 => op!(Cpy, Immediate),
        0xc1 => op!(Cmp, IndexedIndirect),
        0xc4 => op!(Cpy, ZeroPage),
        0xc5 => op!(Cmp, ZeroPage),
        0xc6 => op!(Dec, ZeroPage),
        0xc8 => op!(Iny, Implied),
        0xc9 => op!(Cmp, Immediate),
        0xca => op!(Dex, Implied),
        0xcc => op!(Cpy, Absolute),
        0xcd => op!(Cmp, Absolute),
        0xce => op!(Dec, Absolute),
        0xd0 => op!(Bne, Relative),
        0xd1 => op!(Cmp, IndirectIndexed),
        0xd5 => op!(Cmp, ZeroPageX),
        0xd6 => op!(Dec, ZeroPageX),
        0xd8 => op!(Cld, Implied),
        0xd9 => op!(Cmp, AbsoluteY),
        0xdd => op!(Cmp, AbsoluteX),
        0xde => op!(Dec, AbsoluteX),
        0xe0 => op!(Cpx, Immediate),
        0xe1 => op!(Sbc, IndexedIndirect),
        0xe4 => op!(Cpx, ZeroPage),
        0xe5 => op!(Sbc, ZeroPage),
        0xe6 => op!(Inc, ZeroPage),
        0xe8 => op!(Inx, Implied),
        0xe9 => op!(Sbc, Immediate),
        0xea => op!(Nop, Implied),
        0xec => op!(Cpx, Absolute),
        0xed => op!(Sbc, Absolute),
        0xee => op!(Inc, Absolute),
        0xf0 => op!(Beq, Relative),
        0xf1 => op!(Sbc, IndirectIndexed),
        0xf5 => op!(Sbc, ZeroPageX),
        0xf6 => op!(Inc, ZeroPageX),
        0xf8 => op!(Sed, Implied),
        0xf9 => op!(Sbc, AbsoluteY),
        0xfd => op!(Sbc, AbsoluteX),
        0xfe => op!(Inc, AbsoluteX),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::{AddressingMode, DecodeError, Mnemonic, decode, opcode};

    #[test]
    fn classifies_every_opcode_byte_without_panicking() {
        let official = (0..=u8::MAX).filter(|byte| opcode(*byte).is_some()).count();
        assert_eq!(official, 151);
    }

    #[test]
    fn decodes_representative_addressing_modes() {
        let immediate = decode(&[0xa9, 0x42]).expect("LDA immediate");
        assert_eq!(immediate.opcode.mnemonic, Mnemonic::Lda);
        assert_eq!(immediate.opcode.mode, AddressingMode::Immediate);
        assert_eq!(immediate.bytes(), &[0xa9, 0x42]);

        let indirect = decode(&[0x6c, 0x34, 0x12]).expect("JMP indirect");
        assert_eq!(indirect.opcode.mode, AddressingMode::Indirect);
        assert_eq!(indirect.operand(), 0x1234);
    }

    #[test]
    fn rejects_undocumented_and_truncated_instructions() {
        assert_eq!(decode(&[0x02]), Err(DecodeError::UnsupportedOpcode(0x02)));
        assert_eq!(
            decode(&[0x4c, 0x00]),
            Err(DecodeError::Truncated {
                opcode: 0x4c,
                required: 3,
                available: 2,
            })
        );
    }
}
