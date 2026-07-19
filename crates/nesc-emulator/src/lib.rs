//! Deterministic NES boot harness for compiler-generated Mapper 0 ROMs.

use std::collections::{BTreeMap, VecDeque};
use std::error::Error;
use std::fmt;

use nesc_rom::{CpuAddress, Mapper, MapperState};

const NTSC_FRAME_CYCLES: u64 = 29_781;
const NTSC_VBLANK_CYCLE: u64 = 27_394;
const TRACE_LIMIT: usize = 16;

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

/// Bounded boot-oracle failure with recent bus/control trace.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EmulatorError {
    /// First failure explanation.
    pub message: String,
    /// Program counter at failure.
    pub pc: u16,
    /// CPU cycle at failure.
    pub cycle: u64,
    /// Recent deterministic events.
    pub trace: Vec<String>,
}

impl fmt::Display for EmulatorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{} at PC ${:04X}, cycle {}",
            self.message, self.pc, self.cycle
        )?;
        for event in &self.trace {
            write!(formatter, "\n  {event}")?;
        }
        Ok(())
    }
}

impl Error for EmulatorError {}

/// Runs the first compiler milestone boot oracle.
///
/// # Errors
///
/// Fails on malformed ROMs, missing symbols, illegal instructions, unmapped
/// accesses, wrong palette output, or the cycle bound.
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
    let rom = nesc_rom::parse(rom_bytes).map_err(|error| EmulatorError {
        message: error.to_string(),
        pc: 0,
        cycle: 0,
        trace: Vec::new(),
    })?;
    let mapper = Mapper::new(
        rom.metadata.mapper,
        rom.metadata.prg_rom_len,
        rom.metadata.chr_rom_len,
    )
    .map_err(|error| EmulatorError {
        message: error.to_string(),
        pc: 0,
        cycle: 0,
        trace: Vec::new(),
    })?;
    let mut machine = Machine::new(rom.prg_rom, mapper);
    machine.reset()?;
    let mut reached_main = false;
    let mut palette_frame = None;
    while machine.cycles < cycle_limit {
        if machine.pc == main {
            reached_main = true;
            machine.record(format!("reached main at ${main:04X}"));
        }
        machine.step()?;
        if machine.palette[0] == expected_color && palette_frame.is_none() {
            palette_frame = Some(machine.frames);
            machine.record(format!("palette[$3F00] = ${expected_color:02X}"));
        }
        if reached_main
            && palette_frame.is_some_and(|frame| machine.frames >= frame.saturating_add(2))
        {
            return Ok(BootReport {
                cycles: machine.cycles,
                frames: machine.frames,
                main_address: main,
                background_color: machine.palette[0],
            });
        }
    }
    Err(machine.failure(format!(
        "boot oracle timed out; reached_main={reached_main}, palette=${:02X}",
        machine.palette[0]
    )))
}

struct Machine {
    a: u8,
    x: u8,
    y: u8,
    sp: u8,
    status: u8,
    pc: u16,
    cycles: u64,
    frames: u64,
    vblank: bool,
    ram: [u8; 0x800],
    palette: [u8; 32],
    ppu_address: u16,
    ppu_high_byte: bool,
    prg: Vec<u8>,
    mapper: Mapper,
    mapper_state: MapperState,
    trace: VecDeque<String>,
}

impl Machine {
    fn new(prg: Vec<u8>, mapper: Mapper) -> Self {
        Self {
            a: 0,
            x: 0,
            y: 0,
            sp: 0xfd,
            status: 0x24,
            pc: 0,
            cycles: 0,
            frames: 0,
            vblank: false,
            ram: [0; 0x800],
            palette: [0; 32],
            ppu_address: 0,
            ppu_high_byte: true,
            prg,
            mapper,
            mapper_state: MapperState::default(),
            trace: VecDeque::new(),
        }
    }

    fn reset(&mut self) -> Result<(), EmulatorError> {
        let low = self.read(0xfffc)?;
        let high = self.read(0xfffd)?;
        self.pc = u16::from_le_bytes([low, high]);
        self.record(format!("reset vector -> ${:04X}", self.pc));
        Ok(())
    }

    fn step(&mut self) -> Result<(), EmulatorError> {
        let instruction_pc = self.pc;
        let opcode = self.fetch()?;
        self.record(format!("${instruction_pc:04X}: ${opcode:02X}"));
        let cycles = match opcode {
            0x78 => {
                self.status |= 0x04;
                2
            }
            0xd8 => {
                self.status &= !0x08;
                2
            }
            0xa9 => {
                self.a = self.fetch()?;
                self.set_nz(self.a);
                2
            }
            0xa2 => {
                self.x = self.fetch()?;
                self.set_nz(self.x);
                2
            }
            0xa4..=0xa6 => {
                let address = u16::from(self.fetch()?);
                let value = self.read(address)?;
                match opcode {
                    0xa5 => self.a = value,
                    0xa6 => self.x = value,
                    0xa4 => self.y = value,
                    _ => unreachable!(),
                }
                self.set_nz(value);
                3
            }
            0xad => {
                let address = self.fetch_word()?;
                self.a = self.read(address)?;
                self.set_nz(self.a);
                4
            }
            0xae => {
                let address = self.fetch_word()?;
                self.x = self.read(address)?;
                self.set_nz(self.x);
                4
            }
            0xac => {
                let address = self.fetch_word()?;
                self.y = self.read(address)?;
                self.set_nz(self.y);
                4
            }
            0x8d => {
                let address = self.fetch_word()?;
                self.write(address, self.a)?;
                4
            }
            0x8e => {
                let address = self.fetch_word()?;
                self.write(address, self.x)?;
                4
            }
            0x8c => {
                let address = self.fetch_word()?;
                self.write(address, self.y)?;
                4
            }
            0x84..=0x86 => {
                let address = u16::from(self.fetch()?);
                let value = match opcode {
                    0x85 => self.a,
                    0x86 => self.x,
                    0x84 => self.y,
                    _ => unreachable!(),
                };
                self.write(address, value)?;
                3
            }
            0x9a => {
                self.sp = self.x;
                2
            }
            0xe8 => {
                self.x = self.x.wrapping_add(1);
                self.set_nz(self.x);
                2
            }
            0x18 => {
                self.status &= !1;
                2
            }
            0x38 => {
                self.status |= 1;
                2
            }
            0x69 => {
                let value = self.fetch()?;
                self.adc(value);
                2
            }
            0x49 => {
                self.a ^= self.fetch()?;
                self.set_nz(self.a);
                2
            }
            0x6d | 0xed | 0x2d | 0x0d | 0x4d | 0xcd => {
                let address = self.fetch_word()?;
                let value = self.read(address)?;
                match opcode {
                    0x6d => self.adc(value),
                    0xed => self.sbc(value),
                    0x2d => {
                        self.a &= value;
                        self.set_nz(self.a);
                    }
                    0x0d => {
                        self.a |= value;
                        self.set_nz(self.a);
                    }
                    0x4d => {
                        self.a ^= value;
                        self.set_nz(self.a);
                    }
                    0xcd => self.compare(self.a, value),
                    _ => unreachable!(),
                }
                4
            }
            0x65 | 0xe5 | 0x25 | 0x05 | 0x45 | 0xc5 => {
                let address = u16::from(self.fetch()?);
                let value = self.read(address)?;
                match opcode {
                    0x65 => self.adc(value),
                    0xe5 => self.sbc(value),
                    0x25 => {
                        self.a &= value;
                        self.set_nz(self.a);
                    }
                    0x05 => {
                        self.a |= value;
                        self.set_nz(self.a);
                    }
                    0x45 => {
                        self.a ^= value;
                        self.set_nz(self.a);
                    }
                    0xc5 => self.compare(self.a, value),
                    _ => unreachable!(),
                }
                3
            }
            0x2c => {
                let address = self.fetch_word()?;
                let value = self.read(address)?;
                self.status = (self.status & !(0x80 | 0x40 | 0x02))
                    | (value & (0x80 | 0x40))
                    | (u8::from(self.a & value == 0) * 0x02);
                4
            }
            0x20 => {
                let target = self.fetch_word()?;
                let return_address = self.pc.wrapping_sub(1);
                self.push((return_address >> 8) as u8)?;
                self.push(return_address as u8)?;
                self.pc = target;
                6
            }
            0x60 => {
                let low = self.pop()?;
                let high = self.pop()?;
                self.pc = u16::from_le_bytes([low, high]).wrapping_add(1);
                6
            }
            0x4c => {
                self.pc = self.fetch_word()?;
                3
            }
            0x48 => {
                self.push(self.a)?;
                3
            }
            0x68 => {
                self.a = self.pop()?;
                self.set_nz(self.a);
                4
            }
            0x10 | 0x30 | 0xf0 | 0xd0 | 0x90 | 0xb0 => {
                let displacement = self.fetch()? as i8;
                let taken = match opcode {
                    0x10 => self.status & 0x80 == 0,
                    0x30 => self.status & 0x80 != 0,
                    0xf0 => self.status & 0x02 != 0,
                    0xd0 => self.status & 0x02 == 0,
                    0x90 => self.status & 1 == 0,
                    0xb0 => self.status & 1 != 0,
                    _ => unreachable!(),
                };
                if taken {
                    self.pc = self.pc.wrapping_add_signed(i16::from(displacement));
                    3
                } else {
                    2
                }
            }
            0x40 => return Err(self.failure("unexpected interrupt return")),
            0x02 => return Err(self.failure("generated runtime trap or unreachable instruction")),
            _ => {
                return Err(self.failure(format!("illegal or unsupported opcode ${opcode:02X}")));
            }
        };
        self.advance(cycles);
        Ok(())
    }

    fn fetch(&mut self) -> Result<u8, EmulatorError> {
        let value = self.read(self.pc)?;
        self.pc = self.pc.wrapping_add(1);
        Ok(value)
    }

    fn fetch_word(&mut self) -> Result<u16, EmulatorError> {
        let low = self.fetch()?;
        let high = self.fetch()?;
        Ok(u16::from_le_bytes([low, high]))
    }

    fn read(&mut self, address: u16) -> Result<u8, EmulatorError> {
        match address {
            0x0000..=0x1fff => Ok(self.ram[usize::from(address & 0x07ff)]),
            0x2000..=0x3fff => match 0x2000 | (address & 7) {
                0x2002 => {
                    let value = u8::from(self.vblank) << 7;
                    self.vblank = false;
                    self.ppu_high_byte = true;
                    Ok(value)
                }
                register => Err(self.failure(format!("unsupported PPU read ${register:04X}"))),
            },
            0x8000..=0xffff => self
                .mapper
                .map_cpu(CpuAddress(address), self.mapper_state)
                .and_then(|offset| self.prg.get(offset.0).copied())
                .ok_or_else(|| self.failure(format!("unmapped PRG read ${address:04X}"))),
            _ => Err(self.failure(format!("unmapped CPU read ${address:04X}"))),
        }
    }

    fn write(&mut self, address: u16, value: u8) -> Result<(), EmulatorError> {
        match address {
            0x0000..=0x1fff => self.ram[usize::from(address & 0x07ff)] = value,
            0x2000..=0x3fff => match 0x2000 | (address & 7) {
                0x2000 | 0x2001 => {}
                0x2006 => {
                    if self.ppu_high_byte {
                        self.ppu_address = u16::from(value & 0x3f) << 8;
                    } else {
                        self.ppu_address = (self.ppu_address & 0xff00) | u16::from(value);
                    }
                    self.ppu_high_byte = !self.ppu_high_byte;
                }
                0x2007 => {
                    if (0x3f00..=0x3fff).contains(&self.ppu_address) {
                        let index = usize::from((self.ppu_address - 0x3f00) & 0x1f);
                        self.palette[index] = value;
                    }
                    self.ppu_address = self.ppu_address.wrapping_add(1);
                }
                register => {
                    return Err(self.failure(format!("unsupported PPU write ${register:04X}")));
                }
            },
            0x8000..=0xffff => {
                self.mapper
                    .cpu_write(CpuAddress(address), value, &mut self.mapper_state);
            }
            _ => return Err(self.failure(format!("unmapped CPU write ${address:04X}"))),
        }
        self.record(format!("write ${address:04X} = ${value:02X}"));
        Ok(())
    }

    fn push(&mut self, value: u8) -> Result<(), EmulatorError> {
        self.write(0x0100 | u16::from(self.sp), value)?;
        self.sp = self.sp.wrapping_sub(1);
        Ok(())
    }

    fn pop(&mut self) -> Result<u8, EmulatorError> {
        self.sp = self.sp.wrapping_add(1);
        self.read(0x0100 | u16::from(self.sp))
    }

    fn adc(&mut self, value: u8) {
        let carry = u16::from(self.status & 1);
        let result = u16::from(self.a) + u16::from(value) + carry;
        let output = result as u8;
        let overflow = (!(self.a ^ value) & (self.a ^ output) & 0x80) != 0;
        self.status =
            (self.status & !(1 | 0x40)) | u8::from(result > 0xff) | (u8::from(overflow) << 6);
        self.a = output;
        self.set_nz(output);
    }

    fn sbc(&mut self, value: u8) {
        self.adc(!value);
    }

    fn compare(&mut self, left: u8, right: u8) {
        self.status = (self.status & !1) | u8::from(left >= right);
        self.set_nz(left.wrapping_sub(right));
    }

    fn set_nz(&mut self, value: u8) {
        self.status = (self.status & !(0x80 | 0x02)) | (value & 0x80) | (u8::from(value == 0) << 1);
    }

    fn advance(&mut self, cycles: u64) {
        let before = self.cycles % NTSC_FRAME_CYCLES;
        self.cycles += cycles;
        let new_frames = self.cycles / NTSC_FRAME_CYCLES;
        if new_frames > self.frames {
            self.frames = new_frames;
            self.vblank = false;
            self.record(format!("frame {}", self.frames));
        }
        let after = self.cycles % NTSC_FRAME_CYCLES;
        if (before < NTSC_VBLANK_CYCLE && after >= NTSC_VBLANK_CYCLE)
            || (before > after && after >= NTSC_VBLANK_CYCLE)
        {
            self.vblank = true;
            self.record(format!("vblank frame {}", self.frames));
        }
    }

    fn record(&mut self, event: String) {
        if self.trace.len() == TRACE_LIMIT {
            self.trace.pop_front();
        }
        self.trace
            .push_back(format!("cycle {}: {event}", self.cycles));
    }

    fn failure(&self, message: impl Into<String>) -> EmulatorError {
        EmulatorError {
            message: message.into(),
            pc: self.pc,
            cycle: self.cycles,
            trace: self.trace.iter().cloned().collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use nesc_rom::Mapper;

    use super::Machine;

    #[test]
    fn executes_codegen_zero_page_and_register_sequences() {
        let program = [
            0xa9, 0x80, 0x85, 0x10, 0xa2, 0x22, 0x86, 0x11, 0xa4, 0x10, 0x84, 0x12, 0x8c, 0x00,
            0x02, 0xa6, 0x11, 0xa5, 0x10, 0x18, 0x65, 0x11, 0x38, 0xe5, 0x11, 0x25, 0x12, 0x05,
            0x11, 0x45, 0x11, 0xc5, 0x10, 0xa5, 0x10, 0x30, 0x02, 0xa9, 0x00, 0xa9, 0x01, 0x8d,
            0x01, 0x02,
        ];
        let mut prg = vec![0; 32 * 1024];
        prg[..program.len()].copy_from_slice(&program);
        let mapper = Mapper::new(0, prg.len(), 0).expect("NROM mapper");
        let mut machine = Machine::new(prg, mapper);
        machine.pc = 0x8000;

        for _ in 0..21 {
            machine.step().expect("supported instruction");
        }

        assert_eq!(machine.a, 1);
        assert_eq!(machine.x, 0x22);
        assert_eq!(machine.y, 0x80);
        assert_eq!(machine.ram[0x12], 0x80);
        assert_eq!(machine.ram[0x200], 0x80);
        assert_eq!(machine.ram[0x201], 1);
    }
}
