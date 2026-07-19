//! Public `nescall` byte layout.
//!
//! Scalar arguments and returns are flattened into little-endian bytes. A, X,
//! and Y carry the first three bytes, followed by reserved zero-page slots.
//! A, X, Y, and all ABI slots are caller-saved. Ordinary calls use only the
//! two-byte JSR return address on the hardware stack. Stack analysis reserves
//! one additional save byte for an imported callee.

/// Reserved zero-page base for argument bytes after A, X, and Y.
pub const ARGUMENT_SPILL_BASE: u8 = 0xf0;
/// Number of argument bytes available in reserved zero page.
pub const ARGUMENT_SPILL_LEN: usize = 8;
/// Reserved zero-page base for return bytes after A, X, and Y.
pub const RETURN_SPILL_BASE: u8 = 0xf8;
/// Number of return bytes available in reserved zero page.
pub const RETURN_SPILL_LEN: usize = 4;

/// Register or reserved-memory location for one flattened ABI byte.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AbiLocation {
    /// Accumulator.
    A,
    /// X register.
    X,
    /// Y register.
    Y,
    /// Reserved zero-page byte.
    ZeroPage(u8),
}

/// Returns the public `nescall` location for a flattened argument byte.
#[must_use]
pub fn argument_location(index: usize) -> Option<AbiLocation> {
    match index {
        0 => Some(AbiLocation::A),
        1 => Some(AbiLocation::X),
        2 => Some(AbiLocation::Y),
        index if index - 3 < ARGUMENT_SPILL_LEN => Some(AbiLocation::ZeroPage(
            ARGUMENT_SPILL_BASE + (index - 3) as u8,
        )),
        _ => None,
    }
}

/// Returns the public `nescall` location for a flattened return byte.
#[must_use]
pub fn return_location(index: usize) -> Option<AbiLocation> {
    match index {
        0 => Some(AbiLocation::A),
        1 => Some(AbiLocation::X),
        2 => Some(AbiLocation::Y),
        index if index - 3 < RETURN_SPILL_LEN => {
            Some(AbiLocation::ZeroPage(RETURN_SPILL_BASE + (index - 3) as u8))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::{AbiLocation, argument_location, return_location};

    #[test]
    fn assigns_registers_then_reserved_zero_page() {
        assert_eq!(argument_location(0), Some(AbiLocation::A));
        assert_eq!(argument_location(2), Some(AbiLocation::Y));
        assert_eq!(argument_location(3), Some(AbiLocation::ZeroPage(0xf0)));
        assert_eq!(return_location(3), Some(AbiLocation::ZeroPage(0xf8)));
    }
}
