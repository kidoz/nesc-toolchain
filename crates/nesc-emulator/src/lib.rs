//! Deterministic NES execution, observable traces, and compiler verification.

mod cpu;
mod machine;

use std::collections::BTreeMap;

pub use cpu::CpuState;
pub use machine::{
    BusAccess, BusAccessKind, EmulatorConfig, EmulatorError, EventKind, InterruptKind, Machine,
    MachineSnapshot, ObservableEvent, RunLimits, RunReport, StepReport, Termination, TimingProfile,
};

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
            "boot oracle timed out; reached_main={reached_main}, palette=${:02X}",
            machine.palette()[0]
        ),
        pc: machine.cpu().pc,
        cycle: machine.cycles(),
        trace: machine.events().iter().rev().take(16).cloned().collect(),
    })
}

#[cfg(test)]
mod tests {
    use nesc_disasm::opcode;
    use nesc_rom::{Format, Metadata, Mirroring, Region, Rom, build};

    use super::{
        EmulatorConfig, EventKind, InterruptKind, Machine, RunLimits, Termination, TimingProfile,
        first_divergent_event,
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
        for _ in 0..4 {
            machine.step().expect("instruction");
        }
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
}
