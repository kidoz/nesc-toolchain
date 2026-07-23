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

/// First internal-RAM byte of the reserved, page-aligned shadow-OAM region.
///
/// Sprite writers stage OAM bytes here and [`RuntimeEmitter::oam_dma`] copies
/// the whole page to sprite memory. The 6502 backend's RAM allocator reserves
/// this page (`nesc_codegen_6502` `SHADOW_OAM_ADDRESS`), so it never overlaps
/// compiler-managed storage.
pub const SHADOW_OAM_ADDRESS: u16 = 0x0200;
/// High byte (page number) of [`SHADOW_OAM_ADDRESS`], used as the `$4014` DMA
/// source page and as the high byte of every sprite-byte store.
pub const SHADOW_OAM_PAGE: u8 = (SHADOW_OAM_ADDRESS >> 8) as u8;

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
    emitter.ppu_address();
    emitter.ppu_data();
    emitter.controller();
    emitter.oam_dma();
    emitter.sprite_position();
    emitter.sprite_tile();
    emitter.sprite_attributes();
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

    fn ppu_address(&mut self) {
        // nescall: little-endian u16 lands with the low byte in A and the
        // high byte in X. PPUADDR latches the high byte first.
        self.define("nes_set_ppu_address");
        self.emit(&[0x8e, 0x06, 0x20], "stx $2006 ; high byte");
        self.emit(&[0x8d, 0x06, 0x20], "sta $2006 ; low byte");
        self.emit(&[0x60], "rts");
    }

    fn ppu_data(&mut self) {
        // nescall: value arrives in A.
        self.define("nes_write_ppu_data");
        self.emit(&[0x8d, 0x07, 0x20], "sta $2007");
        self.emit(&[0x60], "rts");
    }

    fn controller(&mut self) {
        // nescall: port arrives in A. Result mask returned in A, assembled
        // MSB-first so the first serial bit read (button A) lands in bit 7,
        // matching the `NES_BUTTON_*` layout in `sdk/include/controller.h`.
        self.define("nes_read_controller");
        self.emit(&[0xaa], "tax ; X = port select ($4016 + port)");
        self.emit(&[0xa9, 0x01], "lda #$01");
        self.emit(&[0x8d, 0x16, 0x40], "sta $4016 ; strobe on");
        self.emit(&[0xa9, 0x00], "lda #$00");
        self.emit(&[0x8d, 0x16, 0x40], "sta $4016 ; strobe off");
        self.emit(&[0xa0, 0x08], "ldy #$08 ; 8 buttons");
        self.assembly.push_str("nes_read_controller.loop:\n");
        self.emit(&[0xbd, 0x16, 0x40], "lda $4016,x ; port 0 or 1");
        self.emit(&[0x4a], "lsr a ; button bit -> carry");
        self.emit(&[0x26, 0xf0], "rol $f0 ; carry -> result, shift MSB-first");
        self.emit(&[0x88], "dey");
        self.emit(&[0xd0, 0xf7], "bne nes_read_controller.loop");
        self.emit(&[0xa5, 0xf0], "lda $f0 ; return mask");
        self.emit(&[0x60], "rts");
    }

    fn oam_dma(&mut self) {
        // Reset OAMADDR then trigger the sprite DMA from the reserved page.
        self.define("nes_oam_dma");
        self.emit(&[0xa9, 0x00], "lda #$00");
        self.emit(&[0x8d, 0x03, 0x20], "sta $2003 ; OAMADDR = 0");
        self.emit(
            &[0xa9, SHADOW_OAM_PAGE],
            &format!("lda #${SHADOW_OAM_PAGE:02X} ; shadow-OAM page"),
        );
        self.emit(&[0x8d, 0x14, 0x40], "sta $4014 ; OAM DMA");
        self.emit(&[0x60], "rts");
    }

    fn sprite_position(&mut self) {
        // nescall: sprite in A, x in X, y in Y. Byte offset is sprite*4 into
        // the shadow page; +0 = Y, +3 = X.
        self.define("nes_set_sprite_position");
        self.emit(&[0x86, 0xf0], "stx $f0 ; save x");
        self.emit(&[0x84, 0xf1], "sty $f1 ; save y");
        self.emit(&[0x0a], "asl a");
        self.emit(&[0x0a], "asl a ; A = sprite * 4");
        self.emit(&[0xaa], "tax ; X = OAM byte offset");
        self.emit(&[0xa5, 0xf1], "lda $f1 ; y");
        self.emit(
            &[0x9d, 0x00, SHADOW_OAM_PAGE],
            &format!("sta ${SHADOW_OAM_PAGE:02X}00,x ; +0 = Y"),
        );
        self.emit(&[0xa5, 0xf0], "lda $f0 ; x");
        self.emit(
            &[0x9d, 0x03, SHADOW_OAM_PAGE],
            &format!("sta ${SHADOW_OAM_PAGE:02X}03,x ; +3 = X"),
        );
        self.emit(&[0x60], "rts");
    }

    fn sprite_tile(&mut self) {
        // nescall: sprite in A, tile in X. Byte offset sprite*4, +1 = tile.
        self.define("nes_set_sprite_tile");
        self.emit(&[0x86, 0xf0], "stx $f0 ; save tile");
        self.emit(&[0x0a], "asl a");
        self.emit(&[0x0a], "asl a ; A = sprite * 4");
        self.emit(&[0xaa], "tax ; X = OAM byte offset");
        self.emit(&[0xa5, 0xf0], "lda $f0 ; tile");
        self.emit(
            &[0x9d, 0x01, SHADOW_OAM_PAGE],
            &format!("sta ${SHADOW_OAM_PAGE:02X}01,x ; +1 = tile"),
        );
        self.emit(&[0x60], "rts");
    }

    fn sprite_attributes(&mut self) {
        // nescall: sprite in A, attributes in X. Byte offset sprite*4, +2 = attr.
        self.define("nes_set_sprite_attributes");
        self.emit(&[0x86, 0xf0], "stx $f0 ; save attributes");
        self.emit(&[0x0a], "asl a");
        self.emit(&[0x0a], "asl a ; A = sprite * 4");
        self.emit(&[0xaa], "tax ; X = OAM byte offset");
        self.emit(&[0xa5, 0xf0], "lda $f0 ; attributes");
        self.emit(
            &[0x9d, 0x02, SHADOW_OAM_PAGE],
            &format!("sta ${SHADOW_OAM_PAGE:02X}02,x ; +2 = attributes"),
        );
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

    use super::{Runtime, SHADOW_OAM_PAGE, build, build_for, build_for_test};

    fn routine_bytes(runtime: &Runtime, name: &str) -> Vec<u8> {
        let symbol = runtime
            .object
            .symbols
            .iter()
            .find(|symbol| symbol.name == name)
            .unwrap_or_else(|| panic!("missing symbol {name}"));
        let section = symbol.section.expect("routine section");
        let bytes = &runtime.object.sections[section.0 as usize].bytes;
        bytes[symbol.offset as usize..].to_vec()
    }

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

    #[test]
    fn emits_controller_and_sprite_routines_with_expected_opcodes() {
        let runtime = build();
        runtime.object.validate().expect("valid runtime object");
        for name in [
            "nes_read_controller",
            "nes_oam_dma",
            "nes_set_sprite_position",
            "nes_set_sprite_tile",
            "nes_set_sprite_attributes",
        ] {
            assert!(
                runtime
                    .object
                    .symbols
                    .iter()
                    .any(|symbol| symbol.name == name),
                "missing export {name}"
            );
        }

        // Strobe $4016, then shift eight serial bits in MSB-first so button A
        // (the first bit) lands in bit 7 to match `NES_BUTTON_A = 0x80`.
        assert!(
            routine_bytes(&runtime, "nes_read_controller").starts_with(&[
                0xaa, 0xa9, 0x01, 0x8d, 0x16, 0x40, 0xa9, 0x00, 0x8d, 0x16, 0x40, 0xa0, 0x08, 0xbd,
                0x16, 0x40, 0x4a, 0x26, 0xf0, 0x88, 0xd0, 0xf7, 0xa5, 0xf0, 0x60,
            ])
        );

        // OAMADDR = 0, then DMA the reserved shadow page through $4014.
        assert!(routine_bytes(&runtime, "nes_oam_dma").starts_with(&[
            0xa9,
            0x00,
            0x8d,
            0x03,
            0x20,
            0xa9,
            SHADOW_OAM_PAGE,
            0x8d,
            0x14,
            0x40,
            0x60,
        ]));

        // sprite in A, x in X, y in Y: offset = sprite*4; +0 = Y, +3 = X.
        assert!(
            routine_bytes(&runtime, "nes_set_sprite_position").starts_with(&[
                0x86,
                0xf0,
                0x84,
                0xf1,
                0x0a,
                0x0a,
                0xaa,
                0xa5,
                0xf1,
                0x9d,
                0x00,
                SHADOW_OAM_PAGE,
                0xa5,
                0xf0,
                0x9d,
                0x03,
                SHADOW_OAM_PAGE,
                0x60,
            ])
        );

        // sprite in A, tile in X: +1 = tile.
        assert!(
            routine_bytes(&runtime, "nes_set_sprite_tile").starts_with(&[
                0x86,
                0xf0,
                0x0a,
                0x0a,
                0xaa,
                0xa5,
                0xf0,
                0x9d,
                0x01,
                SHADOW_OAM_PAGE,
                0x60,
            ])
        );

        // sprite in A, attributes in X: +2 = attributes.
        assert!(
            routine_bytes(&runtime, "nes_set_sprite_attributes").starts_with(&[
                0x86,
                0xf0,
                0x0a,
                0x0a,
                0xaa,
                0xa5,
                0xf0,
                0x9d,
                0x02,
                SHADOW_OAM_PAGE,
                0x60,
            ])
        );
    }
}
