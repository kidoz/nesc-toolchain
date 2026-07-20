//! Public Ricoh 2A03/2A07 CPU state.

/// Carry flag bit.
pub const FLAG_CARRY: u8 = 0x01;
/// Zero flag bit.
pub const FLAG_ZERO: u8 = 0x02;
/// Interrupt-disable flag bit.
pub const FLAG_INTERRUPT_DISABLE: u8 = 0x04;
/// Decimal flag bit. The Ricoh CPU stores it but ignores it for arithmetic.
pub const FLAG_DECIMAL: u8 = 0x08;
/// Break marker used only in status values pushed to the stack.
pub const FLAG_BREAK: u8 = 0x10;
/// Reserved status bit, always set in visible CPU state.
pub const FLAG_UNUSED: u8 = 0x20;
/// Overflow flag bit.
pub const FLAG_OVERFLOW: u8 = 0x40;
/// Negative flag bit.
pub const FLAG_NEGATIVE: u8 = 0x80;

/// Complete programmer-visible Ricoh CPU state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CpuState {
    pub a: u8,
    pub x: u8,
    pub y: u8,
    pub sp: u8,
    pub status: u8,
    pub pc: u16,
}

impl Default for CpuState {
    fn default() -> Self {
        Self {
            a: 0,
            x: 0,
            y: 0,
            sp: 0xfd,
            status: FLAG_INTERRUPT_DISABLE | FLAG_UNUSED,
            pc: 0,
        }
    }
}

impl CpuState {
    pub(crate) fn flag(self, flag: u8) -> bool {
        self.status & flag != 0
    }

    pub(crate) fn set_flag(&mut self, flag: u8, value: bool) {
        if value {
            self.status |= flag;
        } else {
            self.status &= !flag;
        }
        self.status |= FLAG_UNUSED;
    }

    pub(crate) fn set_negative_zero(&mut self, value: u8) {
        self.set_flag(FLAG_NEGATIVE, value & 0x80 != 0);
        self.set_flag(FLAG_ZERO, value == 0);
    }
}
