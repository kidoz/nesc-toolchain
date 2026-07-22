//! Deterministic NES execution, observable traces, and compiler verification.

mod apu;
mod audio;
mod cpu;
mod image;
mod machine;
mod palette;

use std::collections::BTreeMap;

pub use apu::ApuState;
pub use audio::encode_wav;
pub use cpu::CpuState;
pub use image::{encode_png, encode_ppm};
pub use machine::{
    BusAccess, BusAccessKind, BusAccessSource, CycleReport, EmulatorConfig, EmulatorError,
    EventKind, FRAME_HEIGHT, FRAME_PIXELS, FRAME_WIDTH, InterruptKind, Machine, MachineSnapshot,
    ObservableEvent, PpuPosition, PpuState, RunLimits, RunReport, StepReport, Termination,
    TimingProfile,
};
pub use palette::NES_PALETTE_RGB;

/// First difference between two ordered observable-event traces.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EventDivergence {
    pub index: usize,
    pub original: Option<ObservableEvent>,
    pub translated: Option<ObservableEvent>,
}

/// Finds the first value or length difference between two event traces.
#[must_use]
pub fn first_divergent_event(
    original: &[ObservableEvent],
    translated: &[ObservableEvent],
) -> Option<EventDivergence> {
    let shared = original.len().min(translated.len());
    for index in 0..shared {
        if original[index] != translated[index] {
            return Some(EventDivergence {
                index,
                original: Some(original[index].clone()),
                translated: Some(translated[index].clone()),
            });
        }
    }
    (original.len() != translated.len()).then(|| EventDivergence {
        index: shared,
        original: original.get(shared).cloned(),
        translated: translated.get(shared).cloned(),
    })
}

/// Successful compiler boot observation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BootReport {
    /// CPU cycles executed.
    pub cycles: u64,
    /// Frame boundaries crossed.
    pub frames: u64,
    /// Generated entry address reached.
    pub main_address: u16,
    /// Final universal background color.
    pub background_color: u8,
}

/// Final state of one generated `NES_TEST` execution.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TestOutcome {
    /// The selected test returned without a failed assertion.
    Passed,
    /// The first equality assertion failed.
    AssertionFailed { actual: u32, expected: u32 },
    /// Compiler-generated trap execution terminated the test.
    Trap { reason: u8 },
    /// The instruction bound was exhausted before completion.
    InstructionLimit,
    /// The CPU-cycle bound was exhausted before completion.
    CycleLimit,
}

/// Bounded execution report for one generated `NES_TEST` ROM.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TestReport {
    pub instructions: u64,
    pub cycles: u64,
    pub frames: u64,
    pub outcome: TestOutcome,
}

/// Executes one generated test ROM until its runtime mailbox, a trap, or a bound stops it.
///
/// # Errors
///
/// Rejects malformed ROMs, missing runtime symbols, zero limits, undocumented opcodes, and
/// required unmapped bus accesses.
pub fn run_test_rom(
    rom_bytes: &[u8],
    symbols: &BTreeMap<String, u16>,
    limits: RunLimits,
) -> Result<TestReport, EmulatorError> {
    if limits.instruction_limit == 0 || limits.cycle_limit == 0 {
        return Err(EmulatorError {
            message: "test limits must permit instructions and cycles".to_owned(),
            pc: 0,
            cycle: 0,
            trace: Vec::new(),
        });
    }
    let trap_address = symbols
        .get("__nesc_trap")
        .copied()
        .ok_or_else(|| EmulatorError {
            message: "symbol table does not contain `__nesc_trap`".to_owned(),
            pc: 0,
            cycle: 0,
            trace: Vec::new(),
        })?;
    let mut machine = Machine::from_rom_bytes(
        rom_bytes,
        EmulatorConfig {
            trap_address: Some(trap_address),
            ..EmulatorConfig::default()
        },
    )?;
    machine.reset()?;
    let initial_cycles = machine.cycles();
    let initial_instructions = machine.instructions();
    loop {
        let step = machine.step()?;
        let instructions = machine.instructions().saturating_sub(initial_instructions);
        let cycles = machine.cycles().saturating_sub(initial_cycles);
        let report = |outcome| TestReport {
            instructions,
            cycles,
            frames: machine.frames(),
            outcome,
        };
        if let Some(Termination::Trap { reason }) = step.termination {
            return Ok(report(TestOutcome::Trap { reason }));
        }
        match machine.peek(nesc_runtime::TEST_STATUS_ADDRESS)? {
            nesc_runtime::TEST_STATUS_RUNNING => {}
            nesc_runtime::TEST_STATUS_PASSED => return Ok(report(TestOutcome::Passed)),
            nesc_runtime::TEST_STATUS_ASSERTION_FAILED => {
                let read_u32 = |address| -> Result<u32, EmulatorError> {
                    let mut bytes = [0; 4];
                    for (offset, byte) in bytes.iter_mut().enumerate() {
                        *byte = machine.peek(address + offset as u16)?;
                    }
                    Ok(u32::from_le_bytes(bytes))
                };
                return Ok(report(TestOutcome::AssertionFailed {
                    actual: read_u32(nesc_runtime::TEST_ACTUAL_ADDRESS)?,
                    expected: read_u32(nesc_runtime::TEST_EXPECTED_ADDRESS)?,
                }));
            }
            status => {
                return Err(EmulatorError {
                    message: format!("test runtime reported unknown status ${status:02X}"),
                    pc: machine.cpu().pc,
                    cycle: machine.cycles(),
                    trace: machine.events().iter().rev().take(16).cloned().collect(),
                });
            }
        }
        if instructions >= limits.instruction_limit {
            return Ok(report(TestOutcome::InstructionLimit));
        }
        if cycles >= limits.cycle_limit {
            return Ok(report(TestOutcome::CycleLimit));
        }
    }
}

/// Runs the first compiler milestone boot oracle.
///
/// # Errors
///
/// Fails on malformed ROMs, missing symbols, illegal instructions, unmapped
/// accesses, wrong palette output, unexpected traps, or the cycle bound.
pub fn verify_compiler_boot(
    rom_bytes: &[u8],
    symbols: &BTreeMap<String, u16>,
    expected_color: u8,
    cycle_limit: u64,
) -> Result<BootReport, EmulatorError> {
    let main = symbols.get("main").copied().ok_or_else(|| EmulatorError {
        message: "symbol table does not contain `main`".to_owned(),
        pc: 0,
        cycle: 0,
        trace: Vec::new(),
    })?;
    if cycle_limit == 0 {
        return Err(EmulatorError {
            message: "boot cycle limit must be greater than zero".to_owned(),
            pc: 0,
            cycle: 0,
            trace: Vec::new(),
        });
    }
    let mut machine = Machine::from_rom_bytes(rom_bytes, EmulatorConfig::default())?;
    machine.reset()?;
    let mut reached_main = false;
    let mut palette_frame = None;
    while machine.cycles() < cycle_limit {
        if machine.cpu().pc == main {
            reached_main = true;
        }
        let report = machine.step()?;
        if let Some(Termination::Trap { reason }) = report.termination {
            return Err(EmulatorError {
                message: format!("runtime trap {reason} reached during boot"),
                pc: machine.cpu().pc,
                cycle: machine.cycles(),
                trace: machine.events().iter().rev().take(16).cloned().collect(),
            });
        }
        if machine.palette()[0] == expected_color && palette_frame.is_none() {
            palette_frame = Some(machine.frames());
        }
        if reached_main
            && palette_frame.is_some_and(|frame| machine.frames() >= frame.saturating_add(2))
        {
            return Ok(BootReport {
                cycles: machine.cycles(),
                frames: machine.frames(),
                main_address: main,
                background_color: machine.palette()[0],
            });
        }
    }
    Err(EmulatorError {
        message: format!(
            "boot oracle timed out; reached_main={reached_main}, palette=${:02X}, frames={}, retained_vblank_events={}, retained_vblank_reads={}",
            machine.palette()[0],
            machine.frames(),
            machine
                .events()
                .iter()
                .filter(|event| event.kind == EventKind::VBlank)
                .count(),
            machine
                .events()
                .iter()
                .filter(|event| {
                    event.kind == EventKind::VolatileRead
                        && event.address == Some(0x2002)
                        && event.value.is_some_and(|value| value & 0x80 != 0)
                })
                .count()
        ),
        pc: machine.cpu().pc,
        cycle: machine.cycles(),
        trace: machine.events().iter().rev().take(16).cloned().collect(),
    })
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use nesc_disasm::opcode;
    use nesc_rom::{Format, Metadata, Mirroring, Region, Rom, build};

    use super::{
        BusAccess, BusAccessKind, EmulatorConfig, EventKind, InterruptKind, Machine, RunLimits,
        StepReport, Termination, TestOutcome, TimingProfile, first_divergent_event, run_test_rom,
    };

    fn rom_with_program(program: &[u8], region: Region) -> Vec<u8> {
        let mut prg = vec![0xea; 32 * 1024];
        prg[..program.len()].copy_from_slice(program);
        let vectors = prg.len() - 6;
        prg[vectors..vectors + 2].copy_from_slice(&0x9000_u16.to_le_bytes());
        prg[vectors + 2..vectors + 4].copy_from_slice(&0x8000_u16.to_le_bytes());
        prg[vectors + 4..vectors + 6].copy_from_slice(&0xa000_u16.to_le_bytes());
        build(&Rom {
            metadata: Metadata {
                format: Format::Nes2,
                mapper: 0,
                submapper: 0,
                mirroring: Mirroring::Horizontal,
                battery: false,
                region,
                prg_rom_len: prg.len(),
                chr_rom_len: 0,
            },
            trainer: None,
            prg_rom: prg,
            chr_rom: Vec::new(),
        })
        .expect("ROM")
    }

    fn clock_instruction(machine: &mut Machine) -> (StepReport, Vec<BusAccess>) {
        let mut accesses = Vec::new();
        loop {
            let cycle = machine.step_cycle().expect("CPU clock");
            accesses.push(cycle.access.expect("one bus access per CPU clock"));
            if let Some(report) = cycle.step {
                return (report, accesses);
            }
        }
    }

    #[test]
    fn executes_every_official_opcode_without_an_unsupported_path() {
        let mut count = 0;
        for byte in 0..=u8::MAX {
            if opcode(byte).is_none() {
                continue;
            }
            count += 1;
            let rom = rom_with_program(&[byte, 0, 0], Region::Ntsc);
            let mut machine =
                Machine::from_rom_bytes(&rom, EmulatorConfig::default()).expect("machine");
            machine.reset().expect("reset");
            let report = machine
                .step()
                .unwrap_or_else(|error| panic!("official opcode ${byte:02X} failed: {error}"));
            assert!(report.cycles > 0, "opcode ${byte:02X} consumed no cycles");
        }
        assert_eq!(count, 151);
    }

    #[test]
    fn executes_register_memory_stack_and_page_crossing_semantics() {
        let rom = rom_with_program(
            &[
                0xa2, 0x01, // ldx #1
                0xa9, 0x80, // lda #$80
                0x9d, 0xff, 0x01, // sta $01ff,x
                0x48, // pha
                0xa9, 0x00, // lda #0
                0x68, // pla
                0x1d, 0xff, 0x01, // ora $01ff,x
            ],
            Region::Ntsc,
        );
        let mut machine =
            Machine::from_rom_bytes(&rom, EmulatorConfig::default()).expect("machine");
        machine.reset().expect("reset");
        let initial_sp = machine.cpu().sp;
        for _ in 0..7 {
            machine.step().expect("instruction");
        }
        assert_eq!(machine.cpu().a, 0x80);
        assert_eq!(machine.cpu().sp, initial_sp);
        assert_eq!(machine.ram()[0x200], 0x80);
        assert_eq!(machine.cycles(), 7 + 2 + 2 + 5 + 3 + 2 + 4 + 5);
    }

    #[test]
    fn schedules_indexed_reads_and_read_modify_writes_per_clock() {
        let rom = rom_with_program(
            &[
                0xa2, 0x01, // ldx #1
                0xbd, 0xff, 0x01, // lda $01ff,x
                0xe6, 0x10, // inc $10
            ],
            Region::Ntsc,
        );
        let mut machine =
            Machine::from_rom_bytes(&rom, EmulatorConfig::default()).expect("machine");
        machine.reset().expect("reset");
        machine.ram_mut()[0x0200] = 0x80;
        machine.ram_mut()[0x0010] = 0x2a;
        machine.step().expect("load index");

        let (load, accesses) = clock_instruction(&mut machine);
        assert_eq!(load.cycles, 5);
        assert_eq!(
            accesses
                .iter()
                .map(|access| (access.address, access.kind, access.dummy))
                .collect::<Vec<_>>(),
            vec![
                (0x8002, BusAccessKind::Read, false),
                (0x8003, BusAccessKind::Read, false),
                (0x8004, BusAccessKind::Read, false),
                (0x0100, BusAccessKind::Read, true),
                (0x0200, BusAccessKind::Read, false),
            ]
        );
        assert_eq!(machine.cpu().a, 0x80);

        let first = machine.step_cycle().expect("INC opcode clock");
        let second = machine.step_cycle().expect("INC operand clock");
        let third = machine.step_cycle().expect("INC read clock");
        let fourth = machine.step_cycle().expect("INC dummy write clock");
        assert_eq!(machine.ram()[0x0010], 0x2a);
        let fifth = machine.step_cycle().expect("INC final write clock");
        assert!(fifth.instruction_complete);
        assert_eq!(machine.ram()[0x0010], 0x2b);
        assert_eq!(
            [first, second, third, fourth, fifth]
                .map(|cycle| cycle.access.expect("INC bus access"))
                .map(|access| (access.address, access.kind, access.dummy)),
            [
                (0x8005, BusAccessKind::Read, false),
                (0x8006, BusAccessKind::Read, false),
                (0x0010, BusAccessKind::Read, false),
                (0x0010, BusAccessKind::Write, true),
                (0x0010, BusAccessKind::Write, false),
            ]
        );
    }

    #[test]
    fn uses_the_value_observed_on_the_scheduled_mmio_read_clock() {
        let rom = rom_with_program(&[0xad, 0x02, 0x20], Region::Ntsc); // lda $2002
        let mut machine =
            Machine::from_rom_bytes(&rom, EmulatorConfig::default()).expect("machine");
        machine.reset().expect("reset");
        machine.set_cycles_for_test(27_390);

        let (report, accesses) = clock_instruction(&mut machine);
        assert_eq!(report.cycles, 4);
        assert_eq!(accesses[3].cycle, 27_394);
        assert_eq!(accesses[3].address, 0x2002);
        assert_eq!(accesses[3].value & 0x80, 0x80);
        assert_eq!(machine.cpu().a & 0x80, 0x80);
        assert_eq!(machine.peek(0x2002).expect("PPU status") & 0x80, 0);

        let rom = rom_with_program(
            &[
                0x2c, 0x02, 0x20, // bit $2002
                0x10, 0xfb, // bpl $8000
            ],
            Region::Ntsc,
        );
        let mut machine =
            Machine::from_rom_bytes(&rom, EmulatorConfig::default()).expect("machine");
        machine.reset().expect("reset");
        machine.set_cycles_for_test(27_390);
        machine.step().expect("vblank BIT");
        assert_ne!(machine.cpu().status & 0x80, 0);
        machine.step().expect("not-taken BPL");
        assert_eq!(machine.cpu().pc, 0x8005);

        let mut machine =
            Machine::from_rom_bytes(&rom, EmulatorConfig::default()).expect("machine");
        machine.reset().expect("reset");
        while machine.cpu().pc != 0x8005 && machine.cycles() < 30_000 {
            machine.step().expect("vblank polling instruction");
        }
        assert_eq!(machine.cpu().pc, 0x8005);
    }

    #[test]
    fn handles_irq_nmi_and_rti_with_hardware_stack_frames() {
        let mut program = vec![0xea; 0x2001];
        program[..2].copy_from_slice(&[0x58, 0xea]); // cli; nop
        program[0x1000] = 0x40; // NMI handler at $9000: rti
        program[0x2000] = 0x40; // IRQ handler at $a000: rti
        let rom = rom_with_program(&program, Region::Ntsc);
        let mut machine =
            Machine::from_rom_bytes(&rom, EmulatorConfig::default()).expect("machine");
        machine.reset().expect("reset");
        machine.step().expect("cli");
        let return_pc = machine.cpu().pc;
        machine.set_irq_line(true);
        let irq = machine.step().expect("IRQ");
        assert_eq!(irq.interrupt, Some(InterruptKind::Irq));
        assert_eq!(machine.cpu().pc, 0xa000);
        machine.set_irq_line(false);
        machine.step().expect("RTI");
        assert_eq!(machine.cpu().pc, return_pc);

        machine.request_nmi();
        let nmi = machine.step().expect("NMI");
        assert_eq!(nmi.interrupt, Some(InterruptKind::Nmi));
        assert_eq!(machine.cpu().pc, 0x9000);
        machine.step().expect("RTI");
        assert_eq!(machine.cpu().pc, return_pc);
    }

    #[test]
    fn records_controller_ppu_and_dma_events_with_bounded_storage() {
        let rom = rom_with_program(
            &[
                0xa9, 0x01, 0x8d, 0x16, 0x40, // strobe on
                0xa9, 0x00, 0x8d, 0x16, 0x40, // strobe off
                0xad, 0x16, 0x40, // read controller
                0xa9, 0x00, 0x8d, 0x14, 0x40, // DMA page zero
            ],
            Region::Ntsc,
        );
        let mut machine = Machine::from_rom_bytes(
            &rom,
            EmulatorConfig {
                event_capacity: 12,
                ..EmulatorConfig::default()
            },
        )
        .expect("machine");
        machine.reset().expect("reset");
        machine.set_controller(0, 1).expect("controller");
        for _ in 0..8 {
            machine.step().expect("instruction");
        }
        assert_eq!(machine.cpu().a, 0);
        assert!(machine.events().len() <= 12);
        assert!(
            machine
                .events()
                .iter()
                .any(|event| event.kind == EventKind::Dma)
        );
        assert!(
            machine
                .events()
                .iter()
                .any(|event| event.kind == EventKind::VolatileRead)
        );
    }

    #[test]
    fn keeps_region_timing_explicit_and_stops_at_bounds() {
        let rom = rom_with_program(&[0x4c, 0x00, 0x80], Region::MultiRegion);
        assert!(Machine::from_rom_bytes(&rom, EmulatorConfig::default()).is_err());
        let mut machine = Machine::from_rom_bytes(
            &rom,
            EmulatorConfig {
                timing: Some(TimingProfile::Dendy),
                ..EmulatorConfig::default()
            },
        )
        .expect("explicit timing");
        machine.reset().expect("reset");
        let report = machine
            .run(RunLimits {
                instruction_limit: 4,
                cycle_limit: 100,
            })
            .expect("bounded run");
        assert_eq!(report.termination, Termination::InstructionLimit);
        assert_eq!(report.instructions, 4);
        assert_eq!(report.frames, 0);
    }

    #[test]
    fn observes_test_mailbox_completion_and_bounds() {
        let passed = rom_with_program(
            &[
                0xa9,
                nesc_runtime::TEST_STATUS_PASSED, // lda #passed
                0x8d,
                0x00,
                0x60, // sta test status
                0x4c,
                0x05,
                0x80, // halt
            ],
            Region::Ntsc,
        );
        let symbols = BTreeMap::from([("__nesc_trap".to_owned(), 0x9000)]);
        let report = run_test_rom(
            &passed,
            &symbols,
            RunLimits {
                instruction_limit: 10,
                cycle_limit: 100,
            },
        )
        .expect("test execution");
        assert_eq!(report.outcome, TestOutcome::Passed);
        assert_eq!(report.instructions, 2);

        let looping = rom_with_program(&[0x4c, 0x00, 0x80], Region::Ntsc);
        let report = run_test_rom(
            &looping,
            &symbols,
            RunLimits {
                instruction_limit: 3,
                cycle_limit: 100,
            },
        )
        .expect("bounded test execution");
        assert_eq!(report.outcome, TestOutcome::InstructionLimit);
    }

    #[test]
    fn applies_distinct_ntsc_and_dendy_frame_timing() {
        assert_eq!(TimingProfile::Ntsc.frame_cycle_ratio(), (89_342, 3));
        assert_eq!(TimingProfile::Pal.frame_cycle_ratio(), (531_960, 16));
        assert_eq!(TimingProfile::Dendy.frame_cycle_ratio(), (106_392, 3));
        assert_eq!(TimingProfile::Dendy.vblank_cycle_ratio(), (99_232, 3));
        let rom = rom_with_program(&[0x4c, 0x00, 0x80], Region::MultiRegion);
        let run = |timing| {
            let mut machine = Machine::from_rom_bytes(
                &rom,
                EmulatorConfig {
                    timing: Some(timing),
                    ..EmulatorConfig::default()
                },
            )
            .expect("machine");
            machine.reset().expect("reset");
            machine
                .run(RunLimits {
                    instruction_limit: 20_000,
                    cycle_limit: 30_000,
                })
                .expect("run");
            machine
        };
        let ntsc = run(TimingProfile::Ntsc);
        let dendy = run(TimingProfile::Dendy);
        assert_eq!(ntsc.frames(), 1);
        assert_eq!(dendy.frames(), 0);
        assert!(
            ntsc.events()
                .iter()
                .any(|event| event.kind == EventKind::Frame)
        );
    }

    #[test]
    fn executes_uxrom_mapper_writes_with_physical_bank_events() {
        let mut prg = vec![0xea; 4 * 16 * 1024];
        prg[16 * 1024..16 * 1024 + 2].copy_from_slice(&[0xa9, 0x42]);
        let fixed = 3 * 16 * 1024;
        prg[fixed..fixed + 8].copy_from_slice(&[
            0xa9, 0x01, // lda #1
            0x8d, 0x00, 0x80, // sta $8000
            0x4c, 0x00, 0x80, // jmp $8000
        ]);
        let vectors = prg.len() - 6;
        for offset in [0, 2, 4] {
            prg[vectors + offset..vectors + offset + 2].copy_from_slice(&0xc000_u16.to_le_bytes());
        }
        let rom = build(&Rom {
            metadata: Metadata {
                format: Format::Nes2,
                mapper: 2,
                submapper: 0,
                mirroring: Mirroring::Vertical,
                battery: false,
                region: Region::Ntsc,
                prg_rom_len: prg.len(),
                chr_rom_len: 0,
            },
            trainer: None,
            prg_rom: prg,
            chr_rom: Vec::new(),
        })
        .expect("UxROM");
        let mut machine =
            Machine::from_rom_bytes(&rom, EmulatorConfig::default()).expect("machine");
        machine.reset().expect("reset");
        machine.step().expect("bank number");
        let (_, mapper_write) = clock_instruction(&mut machine);
        assert_eq!(mapper_write.len(), 4);
        assert_eq!(mapper_write[0].physical_bank, Some(3));
        assert_eq!(mapper_write[3].address, 0x8000);
        assert_eq!(mapper_write[3].physical_bank, Some(0));
        assert_eq!(machine.mapped_prg_bank(0x8000), Some(1));
        machine.step().expect("jump to switchable bank");
        let banked_fetch = machine.step_cycle().expect("banked opcode fetch");
        assert_eq!(
            banked_fetch.access.expect("banked access").physical_bank,
            Some(1)
        );
        machine.step().expect("finish banked load");
        assert_eq!(machine.cpu().a, 0x42);
        assert!(
            machine
                .events()
                .iter()
                .any(|event| event.kind == EventKind::MapperWrite)
        );
        assert!(machine.events().iter().any(|event| {
            event.kind == EventKind::Instruction
                && event.address == Some(0x8000)
                && event.physical_bank == Some(1)
        }));
    }

    #[test]
    fn captures_comparable_checkpoints_and_first_event_divergence() {
        let rom = rom_with_program(&[0xa9, 0x21, 0x85, 0x10], Region::Ntsc);
        let mut original =
            Machine::from_rom_bytes(&rom, EmulatorConfig::default()).expect("machine");
        let mut translated =
            Machine::from_rom_bytes(&rom, EmulatorConfig::default()).expect("machine");
        original.reset().expect("reset");
        translated.reset().expect("reset");
        for _ in 0..2 {
            original.step().expect("instruction");
            translated.step().expect("instruction");
        }
        assert_eq!(original.snapshot(), translated.snapshot());
        let original_events = original.events().iter().cloned().collect::<Vec<_>>();
        let mut translated_events = translated.events().iter().cloned().collect::<Vec<_>>();
        assert_eq!(
            first_divergent_event(&original_events, &translated_events),
            None
        );
        translated_events[1].value = Some(0xff);
        let divergence =
            first_divergent_event(&original_events, &translated_events).expect("first divergence");
        assert_eq!(divergence.index, 1);
    }

    #[test]
    fn exposes_observational_bus_accesses_for_watchpoints() {
        let rom = rom_with_program(&[0xa9, 0x2a, 0x85, 0x10], Region::Ntsc);
        let mut machine =
            Machine::from_rom_bytes(&rom, EmulatorConfig::default()).expect("machine");
        machine.reset().expect("reset");
        machine.step().expect("load accumulator");
        machine.step().expect("store zero page");
        assert!(machine.last_bus_accesses().iter().any(|access| {
            access.kind == super::BusAccessKind::Write
                && access.address == 0x0010
                && access.value == 0x2a
        }));
        let accesses = machine.last_bus_accesses().to_vec();
        assert_eq!(machine.peek(0x0010).expect("observational read"), 0x2a);
        assert_eq!(machine.last_bus_accesses(), accesses);
        assert_eq!(machine.mapped_prg_bank(0x8000), Some(0));
    }

    #[test]
    fn advances_instructions_interrupts_and_dma_one_cpu_clock_at_a_time() {
        let rom = rom_with_program(
            &[
                0xa9, 0x00, // lda #0
                0x8d, 0x14, 0x40, // sta $4014
            ],
            Region::Ntsc,
        );
        let mut machine =
            Machine::from_rom_bytes(&rom, EmulatorConfig::default()).expect("machine");
        machine.reset().expect("reset");
        let initial_cycles = machine.cycles();
        let first = machine.step_cycle().expect("first LDA clock");
        assert!(!first.instruction_complete);
        assert!(first.step.is_none());
        assert_eq!(machine.cycles(), initial_cycles + 1);
        assert!(machine.instruction_pending());
        let second = machine.step_cycle().expect("second LDA clock");
        assert!(second.instruction_complete);
        assert_eq!(second.step.expect("LDA report").cycles, 2);
        assert_eq!(machine.cycles(), initial_cycles + 2);
        assert!(!machine.instruction_pending());

        let dma_start = machine.cycles();
        let mut dma_clocks = 0_u64;
        let mut dma_accesses = Vec::new();
        let dma = loop {
            dma_clocks += 1;
            let cycle = machine.step_cycle().expect("DMA instruction clock");
            dma_accesses.push(cycle.access.expect("DMA bus access"));
            if let Some(report) = cycle.step {
                break report;
            }
        };
        assert_eq!(dma_clocks, dma.cycles);
        assert_eq!(dma.cycles, 518);
        assert_eq!(machine.cycles(), dma_start + dma.cycles);
        assert_eq!(dma_accesses.len(), 518);
        assert_eq!(dma_accesses[0].address, 0x8002);
        assert_eq!(dma_accesses[3].address, 0x4014);
        assert_eq!(dma_accesses[3].kind, BusAccessKind::Write);
        assert!(dma_accesses[4].dummy);
        assert!(dma_accesses[5].dummy);
        assert_eq!(dma_accesses[6].address, 0x0000);
        assert_eq!(dma_accesses[6].kind, BusAccessKind::Read);
        assert_eq!(dma_accesses[7].address, 0x2004);
        assert_eq!(dma_accesses[7].kind, BusAccessKind::Write);
        assert_eq!(dma_accesses[516].address, 0x00ff);
        assert_eq!(dma_accesses[517].address, 0x2004);

        machine.request_nmi();
        let interrupt_start = machine.cycles();
        let mut interrupt_clocks = 0_u64;
        let mut interrupt_accesses = Vec::new();
        let interrupt = loop {
            interrupt_clocks += 1;
            let cycle = machine.step_cycle().expect("NMI clock");
            interrupt_accesses.push(cycle.access.expect("NMI bus access"));
            if let Some(report) = cycle.step {
                break report;
            }
        };
        assert_eq!(interrupt_clocks, 7);
        assert_eq!(interrupt.interrupt, Some(InterruptKind::Nmi));
        assert_eq!(machine.cycles(), interrupt_start + 7);
        assert_eq!(
            interrupt_accesses
                .iter()
                .map(|access| (access.address, access.kind, access.dummy))
                .collect::<Vec<_>>(),
            vec![
                (0x8005, BusAccessKind::Read, true),
                (0x8005, BusAccessKind::Read, true),
                (0x01fd, BusAccessKind::Write, false),
                (0x01fc, BusAccessKind::Write, false),
                (0x01fb, BusAccessKind::Write, false),
                (0xfffa, BusAccessKind::Read, false),
                (0xfffb, BusAccessKind::Read, false),
            ]
        );
    }

    #[test]
    fn reports_ppu_positions_for_every_timing_profile() {
        assert_eq!(
            TimingProfile::Ntsc.ppu_position(114),
            super::PpuPosition {
                frame: 0,
                scanline: 1,
                dot: 1,
            }
        );
        assert_eq!(
            TimingProfile::Pal.ppu_position(5),
            super::PpuPosition {
                frame: 0,
                scanline: 0,
                dot: 16,
            }
        );
        assert_eq!(
            TimingProfile::Dendy.ppu_position(114),
            super::PpuPosition {
                frame: 0,
                scanline: 1,
                dot: 1,
            }
        );
    }
}
