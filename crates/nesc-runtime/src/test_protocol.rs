use std::collections::BTreeSet;

use nesc_object::{Binding, Relocation, RelocationKind, SymbolId, SymbolKind};

use crate::{
    RuntimeEmitter, TEST_ACTUAL_ADDRESS, TEST_EXPECTED_ADDRESS, TEST_STATUS_ADDRESS,
    TEST_STATUS_ASSERTION_FAILED,
};

const ARGUMENT_SPILL_BASE: u8 = 0xf0;

impl RuntimeEmitter {
    pub(super) fn test_helpers(&mut self, required: Option<&BTreeSet<String>>) {
        if required.is_some_and(|required| required.contains("__nesc_test_assert_eq")) {
            self.test_assert_eq();
        }
    }

    fn test_assert_eq(&mut self) {
        self.define("__nesc_test_assert_eq");

        self.test_store_absolute(0x8d, "sta", TEST_ACTUAL_ADDRESS);
        self.test_store_absolute(0x8e, "stx", TEST_ACTUAL_ADDRESS + 1);
        self.test_store_absolute(0x8c, "sty", TEST_ACTUAL_ADDRESS + 2);
        self.emit(&[0xa5, ARGUMENT_SPILL_BASE], "lda $f0");
        self.test_store_absolute(0x8d, "sta", TEST_ACTUAL_ADDRESS + 3);

        for offset in 0..4_u16 {
            self.emit(
                &[0xa5, ARGUMENT_SPILL_BASE + 1 + offset as u8],
                &format!("lda ${:02x}", ARGUMENT_SPILL_BASE + 1 + offset as u8),
            );
            self.test_store_absolute(0x8d, "sta", TEST_EXPECTED_ADDRESS + offset);
        }

        let failed = self.test_local_symbol("__nesc_test_assert_eq.failed");
        for offset in 0..4_u16 {
            self.test_load_absolute(TEST_ACTUAL_ADDRESS + offset);
            self.test_compare_absolute(TEST_EXPECTED_ADDRESS + offset);
            self.test_relative(0xd0, "bne", failed);
        }
        self.emit(&[0x60], "rts");

        self.test_define_label(failed, "__nesc_test_assert_eq.failed");
        self.emit(
            &[0xa9, TEST_STATUS_ASSERTION_FAILED],
            "lda #$02 ; assertion failed",
        );
        self.test_store_absolute(0x8d, "sta", TEST_STATUS_ADDRESS);
        self.emit(&[0x60], "rts");
    }

    fn test_store_absolute(&mut self, opcode: u8, mnemonic: &str, address: u16) {
        self.emit(
            &[opcode, address as u8, (address >> 8) as u8],
            &format!("{mnemonic} ${address:04x}"),
        );
    }

    fn test_load_absolute(&mut self, address: u16) {
        self.emit(
            &[0xad, address as u8, (address >> 8) as u8],
            &format!("lda ${address:04x}"),
        );
    }

    fn test_compare_absolute(&mut self, address: u16) {
        self.emit(
            &[0xcd, address as u8, (address >> 8) as u8],
            &format!("cmp ${address:04x}"),
        );
    }

    fn test_local_symbol(&mut self, name: &str) -> SymbolId {
        self.object
            .add_symbol(name, Some(self.code), 0, SymbolKind::Label, Binding::Local)
            .expect("test runtime label")
    }

    fn test_define_label(&mut self, symbol: SymbolId, name: &str) {
        self.object.symbols[symbol.0 as usize].offset = self.bytes().len() as u32;
        self.assembly.push_str(&format!("{name}:\n"));
    }

    fn test_relative(&mut self, opcode: u8, mnemonic: &str, symbol: SymbolId) {
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
