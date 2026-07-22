//! Shared size and cycle accounting for instruction-sequence selection.

/// Backend preference derived from the project optimization setting.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum CodegenGoal {
    /// Balance local code size and execution cost.
    #[default]
    Balanced,
    /// Prefer smaller code while rejecting severe cycle regressions.
    Size,
    /// Prefer the smallest complete linked result.
    MinSize,
    /// Prefer the lowest estimated execution cost.
    Cycles,
}

/// Resource estimate for one legal 6502 instruction sequence.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SequenceCost {
    /// Bytes emitted at the operation site.
    pub bytes: u32,
    /// Cycles that execute regardless of control flow.
    pub base_cycles: u32,
    /// Additional cycles from taken branches.
    pub taken_branch_cycles: u32,
    /// Additional cycles when an indexed access crosses a page.
    pub page_cross_cycles: u32,
    /// Additional runtime code pulled into the linked image.
    pub runtime_bytes: u32,
    /// Cycles spent inside runtime support.
    pub runtime_cycles: u32,
    /// Additional zero-page storage required by the sequence.
    pub zero_page_bytes: u16,
    /// Maximum additional hardware-stack use.
    pub stack_bytes: u16,
    /// Additional bytes needed for mapper bank switching.
    pub bank_switch_bytes: u16,
    /// Additional cycles needed for mapper bank switching.
    pub bank_switch_cycles: u32,
    /// Whether the sequence preserves the current interrupt-safety contract.
    pub interrupt_safe: bool,
}

impl SequenceCost {
    /// Total contribution to the linked ROM.
    #[must_use]
    pub const fn rom_bytes(self) -> u32 {
        self.bytes
            .saturating_add(self.runtime_bytes)
            .saturating_add(self.bank_switch_bytes as u32)
    }

    /// Conservative execution estimate including conditional costs.
    #[must_use]
    pub const fn worst_case_cycles(self) -> u32 {
        self.base_cycles
            .saturating_add(self.taken_branch_cycles)
            .saturating_add(self.page_cross_cycles)
            .saturating_add(self.runtime_cycles)
            .saturating_add(self.bank_switch_cycles)
    }
}

impl CodegenGoal {
    /// Stable name used in generated reports.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Balanced => "balanced",
            Self::Size => "size",
            Self::MinSize => "min-size",
            Self::Cycles => "cycles",
        }
    }

    /// Returns true when `candidate` is preferred over `baseline`.
    #[must_use]
    pub const fn prefers(self, candidate: SequenceCost, baseline: SequenceCost) -> bool {
        if !candidate.interrupt_safe {
            return false;
        }
        let candidate_bytes = candidate.rom_bytes();
        let baseline_bytes = baseline.rom_bytes();
        let candidate_cycles = candidate.worst_case_cycles();
        let baseline_cycles = baseline.worst_case_cycles();
        match self {
            Self::Balanced => {
                candidate_bytes < baseline_bytes && candidate_cycles <= baseline_cycles
            }
            Self::Size => {
                candidate_bytes.saturating_add(1) < baseline_bytes
                    && candidate_cycles <= baseline_cycles.saturating_mul(16)
            }
            Self::MinSize => {
                candidate_bytes < baseline_bytes
                    || (candidate_bytes == baseline_bytes && candidate_cycles < baseline_cycles)
            }
            Self::Cycles => {
                candidate_cycles < baseline_cycles
                    || (candidate_cycles == baseline_cycles && candidate_bytes < baseline_bytes)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{CodegenGoal, SequenceCost};

    #[test]
    fn goals_make_different_size_cycle_tradeoffs() {
        let inline = SequenceCost {
            bytes: 20,
            base_cycles: 30,
            interrupt_safe: true,
            ..SequenceCost::default()
        };
        let helper = SequenceCost {
            bytes: 10,
            base_cycles: 12,
            runtime_cycles: 80,
            stack_bytes: 2,
            interrupt_safe: true,
            ..SequenceCost::default()
        };

        assert!(CodegenGoal::Size.prefers(helper, inline));
        assert!(CodegenGoal::MinSize.prefers(helper, inline));
        assert!(!CodegenGoal::Balanced.prefers(helper, inline));
        assert!(!CodegenGoal::Cycles.prefers(helper, inline));
    }

    #[test]
    fn unsafe_candidate_is_never_selected() {
        let baseline = SequenceCost {
            bytes: 20,
            base_cycles: 20,
            interrupt_safe: true,
            ..SequenceCost::default()
        };
        let candidate = SequenceCost {
            bytes: 1,
            base_cycles: 1,
            interrupt_safe: false,
            ..SequenceCost::default()
        };
        assert!(!CodegenGoal::MinSize.prefers(candidate, baseline));
    }
}
