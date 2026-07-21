//! NES startup and minimal hardware runtime for generated programs.

mod arithmetic;
mod test_protocol;

use std::collections::BTreeSet;

use nesc_object::{
    Binding, Object, Relocation, RelocationKind, SectionId, SectionKind, SectionPlacement,
    SymbolId, SymbolKind,
};

/// PRG-RAM byte written by the generated test runtime when execution changes state.
pub const TEST_STATUS_ADDRESS: u16 = 0x6000;
/// First byte of the little-endian actual value retained after an assertion failure.
pub const TEST_ACTUAL_ADDRESS: u16 = 0x6001;
/// First byte of the little-endian expected value retained after an assertion failure.
pub const TEST_EXPECTED_ADDRESS: u16 = 0x6005;
/// Test is still executing.
pub const TEST_STATUS_RUNNING: u8 = 0;
/// Test returned without an assertion failure.
pub const TEST_STATUS_PASSED: u8 = 1;
/// An equality assertion failed; the mailbox contains both values.
pub const TEST_STATUS_ASSERTION_FAILED: u8 = 2;

/// Generated startup/runtime object and symbolic assembly.
#[derive(Clone, Debug)]
pub struct Runtime {
    /// Relocatable runtime code.
    pub object: Object,
    /// Assembly listing.
    pub assembly: String,
}

/// Builds the Mapper 0 startup and initial SDK runtime.
#[must_use]
pub fn build() -> Runtime {
    build_selected(None, "main", false)
}

/// Builds startup and SDK support with only the requested arithmetic helpers.
#[must_use]
pub fn build_for(required_helpers: &BTreeSet<String>) -> Runtime {
    build_selected(Some(required_helpers), "main", false)
}

/// Builds startup and SDK support with a selected emulator-test entry.
#[must_use]
pub fn build_for_test(required_helpers: &BTreeSet<String>, entry: &str) -> Runtime {
    build_selected(Some(required_helpers), entry, true)
}

fn build_selected(
    required_helpers: Option<&BTreeSet<String>>,
    entry: &str,
    test_protocol: bool,
) -> Runtime {
    let mut emitter = RuntimeEmitter::new(entry);
    emitter.reset(test_protocol);
    emitter.simple_interrupt("__nesc_nmi");
    emitter.simple_interrupt("__nesc_irq");
    emitter.simple_return("nes_init");
    emitter.wait("nes_wait_vblank");
    emitter.wait("nes_wait_frame");
    emitter.enable_rendering();
    emitter.disable_rendering();
    emitter.background_color();
    emitter.controller();
    emitter.simple_return("nes_oam_dma");
    let trap = emitter.trap();
    emitter.arithmetic_helpers(required_helpers, trap);
    emitter.test_helpers(required_helpers);
    Runtime {
        object: emitter.object,
        assembly: emitter.assembly,
    }
}

struct RuntimeEmitter {
    object: Object,
    code: SectionId,
    entry: SymbolId,
    assembly: String,
}

impl RuntimeEmitter {
    fn new(entry: &str) -> Self {
        let mut object = Object::default();
        let code = object
            .add_section_with_placement(".runtime", SectionKind::Code, 1, SectionPlacement::Fixed)
            .expect("runtime section");
        let entry = object
            .add_symbol(entry, None, 0, SymbolKind::Function, Binding::Global)
            .expect("entry import");
        Self {
            object,
            code,
            entry,
            assembly: ".segment \"RUNTIME\"\n".to_owned(),
        }
    }

    fn reset(&mut self, test_protocol: bool) {
        self.define("__nesc_reset");
        self.emit(&[0x78], "sei");
        self.emit(&[0xd8], "cld");
        self.emit(&[0xa2, 0xff], "ldx #$ff");
        self.emit(&[0x9a], "txs");
        self.emit(&[0xe8], "inx");
        self.emit(&[0x86, 0xfc], "stx $fc ; selected PRG bank shadow");
        self.emit(&[0x8e, 0x00, 0x20], "stx $2000");
        self.emit(&[0x8e, 0x01, 0x20], "stx $2001");
        if test_protocol {
            self.emit(&[0xa9, TEST_STATUS_RUNNING], "lda #$00 ; test running");
            self.emit(&[0x8d, 0x00, 0x60], "sta $6000 ; test status");
        }
        self.absolute(0x20, "jsr", self.entry);
        if test_protocol {
            self.emit(&[0xad, 0x00, 0x60], "lda $6000 ; test status");
            self.emit(&[0xd0, 0x05], "bne __nesc_halt");
            self.emit(&[0xa9, TEST_STATUS_PASSED], "lda #$01 ; test passed");
            self.emit(&[0x8d, 0x00, 0x60], "sta $6000 ; test status");
        }
        let halt = self.define_local("__nesc_halt");
        self.assembly.push_str("__nesc_halt:\n");
        self.absolute(0x4c, "jmp", halt);
    }

    fn simple_interrupt(&mut self, name: &str) {
        self.define(name);
        self.emit(&[0x40], "rti");
    }

    fn simple_return(&mut self, name: &str) {
        self.define(name);
        self.emit(&[0x60], "rts");
    }

    fn trap(&mut self) -> SymbolId {
        let symbol = self.define("__nesc_trap");
        self.emit(&[0x02], ".byte $02 ; runtime trap");
        symbol
    }

    fn wait(&mut self, name: &str) {
        self.define(name);
        self.assembly.push_str(&format!("{name}.loop:\n"));
        self.emit(&[0x2c, 0x02, 0x20], "bit $2002");
        self.emit(&[0x10, 0xfb], &format!("bpl {name}.loop"));
        self.emit(&[0x60], "rts");
    }

    fn enable_rendering(&mut self) {
        self.define("nes_enable_rendering");
        self.emit(&[0xa9, 0x1e], "lda #$1e");
        self.emit(&[0x8d, 0x01, 0x20], "sta $2001");
        self.emit(&[0x60], "rts");
    }

    fn disable_rendering(&mut self) {
        self.define("nes_disable_rendering");
        self.emit(&[0xa9, 0x00], "lda #$00");
        self.emit(&[0x8d, 0x01, 0x20], "sta $2001");
        self.emit(&[0x60], "rts");
    }

    fn background_color(&mut self) {
        self.define("nes_set_background_color");
        self.emit(&[0x48], "pha");
        self.emit(&[0xa9, 0x3f], "lda #$3f");
        self.emit(&[0x8d, 0x06, 0x20], "sta $2006");
        self.emit(&[0xa9, 0x00], "lda #$00");
        self.emit(&[0x8d, 0x06, 0x20], "sta $2006");
        self.emit(&[0x68], "pla");
        self.emit(&[0x8d, 0x07, 0x20], "sta $2007");
        self.emit(&[0x60], "rts");
    }

    fn controller(&mut self) {
        self.define("nes_read_controller");
        self.emit(&[0xa9, 0x00], "lda #$00");
        self.emit(&[0x60], "rts");
    }

    fn define(&mut self, name: &str) -> SymbolId {
        let offset = self.bytes().len() as u32;
        let symbol = self
            .object
            .add_symbol(
                name,
                Some(self.code),
                offset,
                SymbolKind::Function,
                Binding::Global,
            )
            .expect("runtime symbol");
        self.assembly
            .push_str(&format!("\n.export {name}\n{name}:\n"));
        symbol
    }

    fn define_local(&mut self, name: &str) -> SymbolId {
        self.object
            .add_symbol(
                name,
                Some(self.code),
                self.bytes().len() as u32,
                SymbolKind::Label,
                Binding::Local,
            )
            .expect("runtime label")
    }

    fn absolute(&mut self, opcode: u8, mnemonic: &str, symbol: SymbolId) {
        let name = self.object.symbols[symbol.0 as usize].name.clone();
        self.emit(&[opcode], &format!("{mnemonic} {name}"));
        let offset = self.bytes().len() as u32;
        self.emit(&[0, 0], "");
        self.object.add_relocation(Relocation {
            section: self.code,
            offset,
            kind: RelocationKind::Absolute16,
            symbol,
            addend: 0,
        });
    }

    fn emit(&mut self, bytes: &[u8], assembly: &str) {
        self.object
            .section_bytes_mut(self.code)
            .expect("runtime section")
            .extend_from_slice(bytes);
        if !assembly.is_empty() {
            self.assembly.push_str("    ");
            self.assembly.push_str(assembly);
            self.assembly.push('\n');
        }
    }

    fn bytes(&self) -> &[u8] {
        &self.object.sections[self.code.0 as usize].bytes
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::{build, build_for, build_for_test};

    #[test]
    fn runtime_exports_reset_and_sdk_symbols() {
        let runtime = build();
        runtime.object.validate().expect("valid runtime object");
        for name in [
            "__nesc_reset",
            "__nesc_nmi",
            "__nesc_irq",
            "__nesc_trap",
            "__nesc_mul_8",
            "__nesc_udiv_16",
            "__nesc_srem_24",
            "__nesc_ashr_32",
            "nes_wait_frame",
            "nes_set_background_color",
        ] {
            assert!(
                runtime
                    .object
                    .symbols
                    .iter()
                    .any(|symbol| symbol.name == name)
            );
        }
        let byte_count = runtime
            .object
            .sections
            .iter()
            .map(|section| section.bytes.len())
            .sum::<usize>();
        assert!(byte_count < 16 * 1024, "runtime is {byte_count} bytes");
    }

    #[test]
    fn emits_only_requested_arithmetic_helpers() {
        let required = BTreeSet::from(["__nesc_mul_16".to_owned()]);
        let runtime = build_for(&required);
        runtime.object.validate().expect("valid selected runtime");
        assert!(
            runtime
                .object
                .symbols
                .iter()
                .any(|symbol| symbol.name == "__nesc_mul_16")
        );
        assert!(
            !runtime
                .object
                .symbols
                .iter()
                .any(|symbol| symbol.name == "__nesc_mul_8")
        );
        assert!(!runtime.assembly.contains("__nesc_udiv_16"));
    }

    #[test]
    fn emits_selected_test_entry_and_assertion_mailbox_helper() {
        let required = BTreeSet::from(["__nesc_test_assert_eq".to_owned()]);
        let runtime = build_for_test(&required, "__nesc_test_0000");
        runtime
            .object
            .validate()
            .expect("valid test runtime object");
        assert!(runtime.assembly.contains("jsr __nesc_test_0000"));
        assert!(runtime.assembly.contains("__nesc_test_assert_eq:"));
        assert!(runtime.assembly.contains("sta $6000 ; test status"));
    }
}
