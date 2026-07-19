use nesc_object::{Binding, Relocation, RelocationKind, SymbolId, SymbolKind};

use crate::RuntimeEmitter;

const ARGUMENT_SPILL_BASE: u8 = 0xf0;
const RETURN_SPILL_BASE: u8 = 0xf8;

/// Internal RAM reserved for arithmetic helpers. Helpers are not reentrant;
/// interrupt handlers must not call them without preserving this block.
pub(crate) const SCRATCH_BASE: u16 = 0x0700;
const LEFT: u16 = SCRATCH_BASE;
const RIGHT: u16 = SCRATCH_BASE + 4;
const RESULT: u16 = SCRATCH_BASE + 8;
const WORK: u16 = SCRATCH_BASE + 12;
const ITERATIONS: u16 = SCRATCH_BASE + 16;
const SIGN: u16 = SCRATCH_BASE + 17;
const REMAINDER_SIGN: u16 = SCRATCH_BASE + 18;
const SHIFT_REMAINDER: u16 = SCRATCH_BASE + 19;

#[derive(Clone, Copy)]
enum DivisionResult {
    Quotient,
    Remainder,
}

#[derive(Clone, Copy)]
enum ShiftKind {
    Left,
    LogicalRight,
    ArithmeticRight,
}

impl RuntimeEmitter {
    pub(super) fn arithmetic_helpers(
        &mut self,
        required: Option<&BTreeSet<String>>,
        trap: SymbolId,
    ) {
        for width in 1..=4 {
            let bits = width * 8;
            if requested(required, &format!("__nesc_mul_{bits}")) {
                self.multiply(width);
            }
            for (signed, result, operation) in [
                (false, DivisionResult::Quotient, "udiv"),
                (true, DivisionResult::Quotient, "sdiv"),
                (false, DivisionResult::Remainder, "urem"),
                (true, DivisionResult::Remainder, "srem"),
            ] {
                if requested(required, &format!("__nesc_{operation}_{bits}")) {
                    self.divide(width, signed, result, trap);
                }
            }
            for (kind, operation) in [
                (ShiftKind::Left, "shl"),
                (ShiftKind::LogicalRight, "lshr"),
                (ShiftKind::ArithmeticRight, "ashr"),
            ] {
                if requested(required, &format!("__nesc_{operation}_{bits}")) {
                    self.shift(width, kind);
                }
            }
        }
    }

    fn multiply(&mut self, width: u16) {
        let bits = width * 8;
        let name = format!("__nesc_mul_{bits}");
        self.define(&name);
        self.store_binary_arguments(width);
        self.clear(RESULT, width);
        self.load_immediate(bits as u8);
        self.store_absolute(ITERATIONS);

        let loop_name = format!("{name}.loop");
        let skip_name = format!("{name}.skip_add");
        let loop_symbol = self.label(&loop_name);
        self.shift_right_logical(RIGHT, width);
        let skip_symbol = self.local_symbol(&skip_name);
        self.relative(0x90, "bcc", skip_symbol);
        self.add_memory(RESULT, LEFT, width);
        self.define_label(skip_symbol, &skip_name);
        self.shift_left(LEFT, width);
        self.decrement_absolute(ITERATIONS);
        self.relative(0xd0, "bne", loop_symbol);
        self.return_value(RESULT, width);
    }

    fn divide(&mut self, width: u16, signed: bool, result_kind: DivisionResult, trap: SymbolId) {
        let bits = width * 8;
        let operation = match result_kind {
            DivisionResult::Quotient => "div",
            DivisionResult::Remainder => "rem",
        };
        let prefix = if signed { "s" } else { "u" };
        let name = format!("__nesc_{prefix}{operation}_{bits}");
        self.define(&name);
        self.store_binary_arguments(width);
        self.trap_if_zero(RIGHT, width, trap, &name);
        if signed {
            self.prepare_signed_division(width, &name);
        }
        self.clear(RESULT, width);
        self.clear(WORK, width);
        self.load_immediate(bits as u8);
        self.store_absolute(ITERATIONS);

        let loop_name = format!("{name}.loop");
        let subtract_name = format!("{name}.subtract");
        let next_name = format!("{name}.next");
        let loop_symbol = self.label(&loop_name);
        self.shift_left(LEFT, width);
        self.rotate_left(WORK, width);
        self.shift_left(RESULT, width);

        let subtract_symbol = self.local_symbol(&subtract_name);
        let next_symbol = self.local_symbol(&next_name);
        for offset in (0..width).rev() {
            self.load_absolute(WORK + offset);
            self.compare_absolute(RIGHT + offset);
            self.relative(0x90, "bcc", next_symbol);
            self.relative(0xd0, "bne", subtract_symbol);
        }
        self.absolute(0x4c, "jmp", subtract_symbol);
        self.define_label(subtract_symbol, &subtract_name);
        self.subtract_memory(WORK, RIGHT, width);
        self.load_absolute(RESULT);
        self.immediate(0x09, "ora", 1);
        self.store_absolute(RESULT);
        self.define_label(next_symbol, &next_name);
        self.decrement_absolute(ITERATIONS);
        let loop_done_name = format!("{name}.loop_done");
        let loop_done_symbol = self.local_symbol(&loop_done_name);
        self.relative(0xf0, "beq", loop_done_symbol);
        self.absolute(0x4c, "jmp", loop_symbol);
        self.define_label(loop_done_symbol, &loop_done_name);

        let output = match result_kind {
            DivisionResult::Quotient => RESULT,
            DivisionResult::Remainder => WORK,
        };
        if signed {
            let sign = match result_kind {
                DivisionResult::Quotient => SIGN,
                DivisionResult::Remainder => REMAINDER_SIGN,
            };
            self.apply_sign(output, sign, width, &name);
        }
        self.return_value(output, width);
    }

    fn shift(&mut self, width: u16, kind: ShiftKind) {
        let bits = width * 8;
        let operation = match kind {
            ShiftKind::Left => "shl",
            ShiftKind::LogicalRight => "lshr",
            ShiftKind::ArithmeticRight => "ashr",
        };
        let name = format!("__nesc_{operation}_{bits}");
        self.define(&name);
        self.store_binary_arguments(width);
        self.copy(LEFT, RESULT, width);
        self.clear(SHIFT_REMAINDER, 1);
        self.load_immediate(bits as u8);
        self.store_absolute(ITERATIONS);

        let reduce_name = format!("{name}.reduce");
        let reduced_name = format!("{name}.reduced_bit");
        let reduce_symbol = self.label(&reduce_name);
        self.shift_left(RIGHT, width);
        self.rotate_left(SHIFT_REMAINDER, 1);
        self.load_absolute(SHIFT_REMAINDER);
        self.immediate(0xc9, "cmp", bits as u8);
        let reduced_symbol = self.local_symbol(&reduced_name);
        self.relative(0x90, "bcc", reduced_symbol);
        self.immediate(0xe9, "sbc", bits as u8);
        self.store_absolute(SHIFT_REMAINDER);
        self.define_label(reduced_symbol, &reduced_name);
        self.decrement_absolute(ITERATIONS);
        self.relative(0xd0, "bne", reduce_symbol);

        self.load_absolute(SHIFT_REMAINDER);
        let done_name = format!("{name}.done");
        let done_symbol = self.local_symbol(&done_name);
        self.relative(0xf0, "beq", done_symbol);
        let shift_name = format!("{name}.shift");
        let shift_symbol = self.label(&shift_name);
        match kind {
            ShiftKind::Left => self.shift_left(RESULT, width),
            ShiftKind::LogicalRight => self.shift_right_logical(RESULT, width),
            ShiftKind::ArithmeticRight => self.shift_right_arithmetic(RESULT, width),
        }
        self.decrement_absolute(SHIFT_REMAINDER);
        self.relative(0xd0, "bne", shift_symbol);
        self.define_label(done_symbol, &done_name);
        self.return_value(RESULT, width);
    }

    fn store_binary_arguments(&mut self, width: u16) {
        for index in 0..width * 2 {
            let destination = if index < width {
                LEFT + index
            } else {
                RIGHT + index - width
            };
            match index {
                0 => self.store_absolute(destination),
                1 => self.store_x_absolute(destination),
                2 => self.store_y_absolute(destination),
                _ => {
                    self.load_zero_page(ARGUMENT_SPILL_BASE + (index - 3) as u8);
                    self.store_absolute(destination);
                }
            }
        }
    }

    fn return_value(&mut self, source: u16, width: u16) {
        for offset in 3..width {
            self.load_absolute(source + offset);
            self.store_zero_page(RETURN_SPILL_BASE + (offset - 3) as u8);
        }
        if width > 2 {
            self.load_y_absolute(source + 2);
        }
        if width > 1 {
            self.load_x_absolute(source + 1);
        }
        self.load_absolute(source);
        self.emit(&[0x60], "rts");
    }

    fn trap_if_zero(&mut self, source: u16, width: u16, trap: SymbolId, function: &str) {
        self.load_absolute(source);
        for offset in 1..width {
            self.operation_absolute(0x0d, "ora", source + offset);
        }
        let nonzero_name = format!("{function}.nonzero");
        let nonzero_symbol = self.local_symbol(&nonzero_name);
        self.relative(0xd0, "bne", nonzero_symbol);
        self.absolute(0x4c, "jmp", trap);
        self.define_label(nonzero_symbol, &nonzero_name);
    }

    fn prepare_signed_division(&mut self, width: u16, function: &str) {
        self.load_absolute(LEFT + width - 1);
        self.store_absolute(REMAINDER_SIGN);
        self.operation_absolute(0x4d, "eor", RIGHT + width - 1);
        self.store_absolute(SIGN);
        self.negate_if_negative(LEFT, width, &format!("{function}.left"));
        self.negate_if_negative(RIGHT, width, &format!("{function}.right"));
    }

    fn negate_if_negative(&mut self, source: u16, width: u16, prefix: &str) {
        let negative_name = format!("{prefix}.negative");
        let ready_name = format!("{prefix}.ready");
        let negative_symbol = self.local_symbol(&negative_name);
        let ready_symbol = self.local_symbol(&ready_name);
        self.load_absolute(source + width - 1);
        self.relative(0x30, "bmi", negative_symbol);
        self.absolute(0x4c, "jmp", ready_symbol);
        self.define_label(negative_symbol, &negative_name);
        self.negate(source, width);
        self.define_label(ready_symbol, &ready_name);
    }

    fn apply_sign(&mut self, source: u16, sign: u16, width: u16, function: &str) {
        let negative_name = format!("{function}.result_negative");
        let ready_name = format!("{function}.result_ready");
        let negative_symbol = self.local_symbol(&negative_name);
        let ready_symbol = self.local_symbol(&ready_name);
        self.load_absolute(sign);
        self.relative(0x30, "bmi", negative_symbol);
        self.absolute(0x4c, "jmp", ready_symbol);
        self.define_label(negative_symbol, &negative_name);
        self.negate(source, width);
        self.define_label(ready_symbol, &ready_name);
    }

    fn negate(&mut self, source: u16, width: u16) {
        self.emit(&[0x18], "clc");
        for offset in 0..width {
            self.load_absolute(source + offset);
            self.immediate(0x49, "eor", 0xff);
            self.immediate(0x69, "adc", u8::from(offset == 0));
            self.store_absolute(source + offset);
        }
    }

    fn add_memory(&mut self, destination: u16, source: u16, width: u16) {
        self.emit(&[0x18], "clc");
        for offset in 0..width {
            self.load_absolute(destination + offset);
            self.operation_absolute(0x6d, "adc", source + offset);
            self.store_absolute(destination + offset);
        }
    }

    fn subtract_memory(&mut self, destination: u16, source: u16, width: u16) {
        self.emit(&[0x38], "sec");
        for offset in 0..width {
            self.load_absolute(destination + offset);
            self.operation_absolute(0xed, "sbc", source + offset);
            self.store_absolute(destination + offset);
        }
    }

    fn shift_left(&mut self, source: u16, width: u16) {
        self.operation_absolute(0x0e, "asl", source);
        for offset in 1..width {
            self.operation_absolute(0x2e, "rol", source + offset);
        }
    }

    fn rotate_left(&mut self, source: u16, width: u16) {
        for offset in 0..width {
            self.operation_absolute(0x2e, "rol", source + offset);
        }
    }

    fn shift_right_logical(&mut self, source: u16, width: u16) {
        self.operation_absolute(0x4e, "lsr", source + width - 1);
        for offset in (0..width - 1).rev() {
            self.operation_absolute(0x6e, "ror", source + offset);
        }
    }

    fn shift_right_arithmetic(&mut self, source: u16, width: u16) {
        self.load_absolute(source + width - 1);
        self.emit(&[0x0a], "asl a");
        for offset in (0..width).rev() {
            self.operation_absolute(0x6e, "ror", source + offset);
        }
    }

    fn clear(&mut self, destination: u16, width: u16) {
        self.load_immediate(0);
        for offset in 0..width {
            self.store_absolute(destination + offset);
        }
    }

    fn copy(&mut self, source: u16, destination: u16, width: u16) {
        for offset in 0..width {
            self.load_absolute(source + offset);
            self.store_absolute(destination + offset);
        }
    }

    fn load_immediate(&mut self, value: u8) {
        self.emit(&[0xa9, value], &format!("lda #${value:02x}"));
    }

    fn immediate(&mut self, opcode: u8, mnemonic: &str, value: u8) {
        self.emit(&[opcode, value], &format!("{mnemonic} #${value:02x}"));
    }

    fn load_absolute(&mut self, address: u16) {
        self.operation_absolute(0xad, "lda", address);
    }

    fn load_x_absolute(&mut self, address: u16) {
        self.operation_absolute(0xae, "ldx", address);
    }

    fn load_y_absolute(&mut self, address: u16) {
        self.operation_absolute(0xac, "ldy", address);
    }

    fn store_absolute(&mut self, address: u16) {
        self.operation_absolute(0x8d, "sta", address);
    }

    fn store_x_absolute(&mut self, address: u16) {
        self.operation_absolute(0x8e, "stx", address);
    }

    fn store_y_absolute(&mut self, address: u16) {
        self.operation_absolute(0x8c, "sty", address);
    }

    fn load_zero_page(&mut self, address: u8) {
        self.emit(&[0xa5, address], &format!("lda ${address:02x}"));
    }

    fn store_zero_page(&mut self, address: u8) {
        self.emit(&[0x85, address], &format!("sta ${address:02x}"));
    }

    fn compare_absolute(&mut self, address: u16) {
        self.operation_absolute(0xcd, "cmp", address);
    }

    fn decrement_absolute(&mut self, address: u16) {
        self.operation_absolute(0xce, "dec", address);
    }

    fn operation_absolute(&mut self, opcode: u8, mnemonic: &str, address: u16) {
        self.emit(
            &[opcode, address as u8, (address >> 8) as u8],
            &format!("{mnemonic} ${address:04x}"),
        );
    }

    fn local_symbol(&mut self, name: &str) -> SymbolId {
        self.object
            .add_symbol(name, Some(self.code), 0, SymbolKind::Label, Binding::Local)
            .expect("runtime label")
    }

    fn label(&mut self, name: &str) -> SymbolId {
        let symbol = self.local_symbol(name);
        self.define_label(symbol, name);
        symbol
    }

    fn define_label(&mut self, symbol: SymbolId, name: &str) {
        self.object.symbols[symbol.0 as usize].offset = self.bytes().len() as u32;
        self.assembly.push_str(&format!("{name}:\n"));
    }

    fn relative(&mut self, opcode: u8, mnemonic: &str, symbol: SymbolId) {
        let name = self.object.symbols[symbol.0 as usize].name.clone();
        self.emit(&[opcode], &format!("{mnemonic} {name}"));
        let offset = self.bytes().len() as u32;
        self.emit(&[0], "");
        self.object.add_relocation(Relocation {
            section: self.code,
            offset,
            kind: RelocationKind::Relative8,
            symbol,
            addend: 0,
        });
    }
}

fn requested(required: Option<&BTreeSet<String>>, name: &str) -> bool {
    required.is_none_or(|required| required.contains(name))
}
use std::collections::BTreeSet;
