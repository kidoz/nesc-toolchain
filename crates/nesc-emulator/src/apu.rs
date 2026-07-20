//! Deterministic Ricoh APU channel and sample-reader timing.

const LENGTH_TABLE: [u8; 32] = [
    10, 254, 20, 2, 40, 4, 80, 6, 160, 8, 60, 10, 14, 12, 26, 14, 12, 16, 24, 18, 48, 20, 96, 22,
    192, 24, 72, 26, 16, 28, 32, 30,
];

const DUTY_TABLE: [[u8; 8]; 4] = [
    [0, 1, 0, 0, 0, 0, 0, 0],
    [0, 1, 1, 0, 0, 0, 0, 0],
    [0, 1, 1, 1, 1, 0, 0, 0],
    [1, 0, 0, 1, 1, 1, 1, 1],
];

const TRIANGLE_TABLE: [u8; 32] = [
    15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12,
    13, 14, 15,
];

const NTSC_NOISE_PERIODS: [u16; 16] = [
    4, 8, 16, 32, 64, 96, 128, 160, 202, 254, 380, 508, 762, 1016, 2034, 4068,
];
const PAL_NOISE_PERIODS: [u16; 16] = [
    4, 8, 14, 30, 60, 88, 118, 148, 188, 236, 354, 472, 708, 944, 1890, 3778,
];
const NTSC_DMC_PERIODS: [u16; 16] = [
    428, 380, 340, 320, 286, 254, 226, 214, 190, 160, 142, 128, 106, 85, 72, 54,
];
const PAL_DMC_PERIODS: [u16; 16] = [
    398, 354, 316, 298, 276, 236, 210, 198, 176, 148, 132, 118, 98, 78, 66, 50,
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ApuTiming {
    Ntsc,
    Pal,
    Dendy,
}

impl ApuTiming {
    const fn frame_steps(self) -> [u32; 5] {
        match self {
            Self::Ntsc | Self::Dendy => [7_457, 14_913, 22_371, 29_829, 37_281],
            Self::Pal => [8_313, 16_627, 24_939, 33_253, 41_565],
        }
    }

    const fn noise_periods(self) -> &'static [u16; 16] {
        match self {
            Self::Ntsc | Self::Dendy => &NTSC_NOISE_PERIODS,
            Self::Pal => &PAL_NOISE_PERIODS,
        }
    }

    const fn dmc_periods(self) -> &'static [u16; 16] {
        match self {
            Self::Ntsc | Self::Dendy => &NTSC_DMC_PERIODS,
            Self::Pal => &PAL_DMC_PERIODS,
        }
    }
}

/// Public APU state captured at deterministic emulator checkpoints.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ApuState {
    pub cycles: u64,
    pub frame_counter_cycle: u32,
    pub five_step_mode: bool,
    pub frame_irq_pending: bool,
    pub channel_status: u8,
    pub length_counters: [u8; 4],
    pub pulse_outputs: [u8; 2],
    pub triangle_output: u8,
    pub noise_output: u8,
    pub dmc_output: u8,
    pub dmc_active: bool,
    pub dmc_irq_pending: bool,
    pub dmc_rate_index: u8,
    pub dmc_timer_counter: u16,
    pub dmc_current_address: u16,
    pub dmc_bytes_remaining: u16,
    pub dmc_sample_buffer: Option<u8>,
    pub dmc_bits_remaining: u8,
    pub dmc_silence: bool,
    pub mixed_output: u16,
    pub output_checksum: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Dmc {
    irq_enabled: bool,
    loop_flag: bool,
    rate_index: u8,
    timer_counter: u16,
    output_level: u8,
    sample_address: u16,
    sample_length: u16,
    current_address: u16,
    bytes_remaining: u16,
    sample_buffer: Option<u8>,
    shift_register: u8,
    bits_remaining: u8,
    silence: bool,
    dma_in_flight: bool,
    irq_pending: bool,
}

impl Default for Dmc {
    fn default() -> Self {
        Self {
            irq_enabled: false,
            loop_flag: false,
            rate_index: 0,
            timer_counter: 0,
            output_level: 0,
            sample_address: 0xc000,
            sample_length: 1,
            current_address: 0xc000,
            bytes_remaining: 0,
            sample_buffer: None,
            shift_register: 0,
            bits_remaining: 8,
            silence: true,
            dma_in_flight: false,
            irq_pending: false,
        }
    }
}

impl Dmc {
    fn write_control(&mut self, value: u8) {
        self.irq_enabled = value & 0x80 != 0;
        self.loop_flag = value & 0x40 != 0;
        self.rate_index = value & 0x0f;
        if !self.irq_enabled {
            self.irq_pending = false;
        }
    }

    fn write_output(&mut self, value: u8) {
        self.output_level = value & 0x7f;
    }

    fn write_address(&mut self, value: u8) {
        self.sample_address = 0xc000 | (u16::from(value) << 6);
    }

    fn write_length(&mut self, value: u8) {
        self.sample_length = u16::from(value) * 16 + 1;
    }

    fn set_enabled(&mut self, enabled: bool) {
        self.irq_pending = false;
        if !enabled {
            self.bytes_remaining = 0;
            self.dma_in_flight = false;
        } else if self.bytes_remaining == 0 {
            self.restart_sample();
        }
    }

    fn restart_sample(&mut self) {
        self.current_address = self.sample_address;
        self.bytes_remaining = self.sample_length;
    }

    fn clock_timer(&mut self, periods: &[u16; 16]) {
        if self.timer_counter == 0 {
            self.timer_counter = periods[usize::from(self.rate_index)] - 1;
            self.clock_output();
        } else {
            self.timer_counter -= 1;
        }
    }

    fn clock_output(&mut self) {
        if !self.silence {
            if self.shift_register & 1 == 0 {
                if self.output_level >= 2 {
                    self.output_level -= 2;
                }
            } else if self.output_level <= 125 {
                self.output_level += 2;
            }
        }
        self.shift_register >>= 1;
        self.bits_remaining -= 1;
        if self.bits_remaining == 0 {
            self.bits_remaining = 8;
            if let Some(sample) = self.sample_buffer.take() {
                self.shift_register = sample;
                self.silence = false;
            } else {
                self.silence = true;
            }
        }
    }

    fn begin_dma(&mut self) -> Option<u16> {
        if self.sample_buffer.is_some() || self.bytes_remaining == 0 || self.dma_in_flight {
            return None;
        }
        self.dma_in_flight = true;
        Some(self.current_address)
    }

    fn complete_dma(&mut self, value: u8) {
        if !self.dma_in_flight {
            return;
        }
        self.dma_in_flight = false;
        self.sample_buffer = Some(value);
        self.current_address = if self.current_address == 0xffff {
            0x8000
        } else {
            self.current_address + 1
        };
        self.bytes_remaining -= 1;
        if self.bytes_remaining == 0 {
            if self.loop_flag {
                self.restart_sample();
            } else if self.irq_enabled {
                self.irq_pending = true;
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct Envelope {
    period: u8,
    constant: bool,
    loop_flag: bool,
    start: bool,
    divider: u8,
    decay: u8,
}

impl Envelope {
    fn write_control(&mut self, value: u8) {
        self.period = value & 0x0f;
        self.constant = value & 0x10 != 0;
        self.loop_flag = value & 0x20 != 0;
    }

    fn restart(&mut self) {
        self.start = true;
    }

    fn clock(&mut self) {
        if self.start {
            self.start = false;
            self.decay = 15;
            self.divider = self.period;
        } else if self.divider == 0 {
            self.divider = self.period;
            if self.decay == 0 {
                if self.loop_flag {
                    self.decay = 15;
                }
            } else {
                self.decay -= 1;
            }
        } else {
            self.divider -= 1;
        }
    }

    const fn output(self) -> u8 {
        if self.constant {
            self.period
        } else {
            self.decay
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct Pulse {
    enabled: bool,
    duty: u8,
    duty_step: u8,
    length_counter: u8,
    timer_period: u16,
    timer_counter: u16,
    envelope: Envelope,
    sweep_enabled: bool,
    sweep_period: u8,
    sweep_negate: bool,
    sweep_shift: u8,
    sweep_divider: u8,
    sweep_reload: bool,
}

impl Pulse {
    fn write_control(&mut self, value: u8) {
        self.duty = value >> 6;
        self.envelope.write_control(value);
    }

    fn write_sweep(&mut self, value: u8) {
        self.sweep_enabled = value & 0x80 != 0;
        self.sweep_period = ((value >> 4) & 0x07) + 1;
        self.sweep_negate = value & 0x08 != 0;
        self.sweep_shift = value & 0x07;
        self.sweep_reload = true;
    }

    fn write_timer_low(&mut self, value: u8) {
        self.timer_period = (self.timer_period & 0x0700) | u16::from(value);
    }

    fn write_timer_high(&mut self, value: u8) {
        self.timer_period = (self.timer_period & 0x00ff) | (u16::from(value & 0x07) << 8);
        if self.enabled {
            self.length_counter = LENGTH_TABLE[usize::from(value >> 3)];
        }
        self.duty_step = 0;
        self.envelope.restart();
    }

    fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
        if !enabled {
            self.length_counter = 0;
        }
    }

    fn clock_timer(&mut self) {
        if self.timer_counter == 0 {
            self.timer_counter = self.timer_period;
            self.duty_step = (self.duty_step + 1) & 7;
        } else {
            self.timer_counter -= 1;
        }
    }

    fn clock_length(&mut self) {
        if !self.envelope.loop_flag && self.length_counter != 0 {
            self.length_counter -= 1;
        }
    }

    fn sweep_target(self, first_channel: bool) -> Option<u16> {
        let change = self.timer_period >> self.sweep_shift;
        if self.sweep_negate {
            self.timer_period
                .checked_sub(change + u16::from(first_channel))
        } else {
            self.timer_period.checked_add(change)
        }
    }

    fn sweep_muted(self, first_channel: bool) -> bool {
        self.timer_period < 8
            || self
                .sweep_target(first_channel)
                .is_none_or(|target| target > 0x07ff)
    }

    fn clock_sweep(&mut self, first_channel: bool) {
        if self.sweep_divider == 0
            && self.sweep_enabled
            && self.sweep_shift != 0
            && !self.sweep_muted(first_channel)
        {
            self.timer_period = self
                .sweep_target(first_channel)
                .expect("unmuted sweep has a target");
        }
        if self.sweep_divider == 0 || self.sweep_reload {
            self.sweep_divider = self.sweep_period;
            self.sweep_reload = false;
        } else {
            self.sweep_divider -= 1;
        }
    }

    fn clock_quarter(&mut self) {
        self.envelope.clock();
    }

    fn clock_half(&mut self, first_channel: bool) {
        self.clock_length();
        self.clock_sweep(first_channel);
    }

    fn output(self, first_channel: bool) -> u8 {
        if !self.enabled
            || self.length_counter == 0
            || self.sweep_muted(first_channel)
            || DUTY_TABLE[usize::from(self.duty)][usize::from(self.duty_step)] == 0
        {
            0
        } else {
            self.envelope.output()
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct Triangle {
    enabled: bool,
    control: bool,
    length_counter: u8,
    linear_reload: u8,
    linear_counter: u8,
    linear_reload_flag: bool,
    timer_period: u16,
    timer_counter: u16,
    sequence_step: u8,
}

impl Triangle {
    fn write_control(&mut self, value: u8) {
        self.control = value & 0x80 != 0;
        self.linear_reload = value & 0x7f;
    }

    fn write_timer_low(&mut self, value: u8) {
        self.timer_period = (self.timer_period & 0x0700) | u16::from(value);
    }

    fn write_timer_high(&mut self, value: u8) {
        self.timer_period = (self.timer_period & 0x00ff) | (u16::from(value & 0x07) << 8);
        if self.enabled {
            self.length_counter = LENGTH_TABLE[usize::from(value >> 3)];
        }
        self.linear_reload_flag = true;
    }

    fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
        if !enabled {
            self.length_counter = 0;
        }
    }

    fn clock_timer(&mut self) {
        if self.timer_counter == 0 {
            self.timer_counter = self.timer_period;
            if self.enabled
                && self.length_counter != 0
                && self.linear_counter != 0
                && self.timer_period >= 2
            {
                self.sequence_step = (self.sequence_step + 1) & 31;
            }
        } else {
            self.timer_counter -= 1;
        }
    }

    fn clock_quarter(&mut self) {
        if self.linear_reload_flag {
            self.linear_counter = self.linear_reload;
        } else if self.linear_counter != 0 {
            self.linear_counter -= 1;
        }
        if !self.control {
            self.linear_reload_flag = false;
        }
    }

    fn clock_half(&mut self) {
        if !self.control && self.length_counter != 0 {
            self.length_counter -= 1;
        }
    }

    const fn output(self) -> u8 {
        if self.enabled && self.length_counter != 0 && self.linear_counter != 0 {
            TRIANGLE_TABLE[self.sequence_step as usize]
        } else {
            0
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Noise {
    enabled: bool,
    length_counter: u8,
    mode: bool,
    period_index: u8,
    timer_counter: u16,
    shift_register: u16,
    envelope: Envelope,
}

impl Default for Noise {
    fn default() -> Self {
        Self {
            enabled: false,
            length_counter: 0,
            mode: false,
            period_index: 0,
            timer_counter: 0,
            shift_register: 1,
            envelope: Envelope::default(),
        }
    }
}

impl Noise {
    fn write_control(&mut self, value: u8) {
        self.envelope.write_control(value);
    }

    fn write_period(&mut self, value: u8) {
        self.mode = value & 0x80 != 0;
        self.period_index = value & 0x0f;
    }

    fn write_length(&mut self, value: u8) {
        if self.enabled {
            self.length_counter = LENGTH_TABLE[usize::from(value >> 3)];
        }
        self.envelope.restart();
    }

    fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
        if !enabled {
            self.length_counter = 0;
        }
    }

    fn clock_timer(&mut self, periods: &[u16; 16]) {
        if self.timer_counter == 0 {
            self.timer_counter = periods[usize::from(self.period_index)] - 1;
            let tap = if self.mode { 6 } else { 1 };
            let feedback = (self.shift_register & 1) ^ ((self.shift_register >> tap) & 1);
            self.shift_register = (self.shift_register >> 1) | (feedback << 14);
        } else {
            self.timer_counter -= 1;
        }
    }

    fn clock_quarter(&mut self) {
        self.envelope.clock();
    }

    fn clock_half(&mut self) {
        if !self.envelope.loop_flag && self.length_counter != 0 {
            self.length_counter -= 1;
        }
    }

    fn output(self) -> u8 {
        if self.enabled && self.length_counter != 0 && self.shift_register & 1 == 0 {
            self.envelope.output()
        } else {
            0
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Apu {
    timing: ApuTiming,
    cycles: u64,
    frame_counter_cycle: u32,
    five_step_mode: bool,
    frame_irq_inhibit: bool,
    frame_irq_pending: bool,
    frame_reset_delay: Option<u8>,
    pulse: [Pulse; 2],
    triangle: Triangle,
    noise: Noise,
    dmc: Dmc,
    output_checksum: u64,
}

impl Apu {
    pub(crate) fn new(timing: ApuTiming) -> Self {
        Self {
            timing,
            cycles: 0,
            frame_counter_cycle: 0,
            five_step_mode: false,
            frame_irq_inhibit: false,
            frame_irq_pending: false,
            frame_reset_delay: None,
            pulse: [Pulse::default(); 2],
            triangle: Triangle::default(),
            noise: Noise::default(),
            dmc: Dmc::default(),
            output_checksum: 0,
        }
    }

    pub(crate) fn reset(&mut self) {
        *self = Self::new(self.timing);
    }

    pub(crate) fn clock(&mut self) {
        self.cycles = self.cycles.saturating_add(1);
        self.frame_counter_cycle = self.frame_counter_cycle.saturating_add(1);

        if self.cycles & 1 == 0 {
            self.pulse[0].clock_timer();
            self.pulse[1].clock_timer();
        }
        self.triangle.clock_timer();
        self.noise.clock_timer(self.timing.noise_periods());
        self.dmc.clock_timer(self.timing.dmc_periods());

        if let Some(delay) = self.frame_reset_delay {
            if delay <= 1 {
                self.frame_reset_delay = None;
                self.frame_counter_cycle = 0;
                if self.five_step_mode {
                    self.clock_quarter();
                    self.clock_half();
                }
            } else {
                self.frame_reset_delay = Some(delay - 1);
            }
        } else {
            self.clock_frame_counter();
        }

        let mixed = self.mixed_output();
        self.output_checksum =
            self.output_checksum.wrapping_mul(1_099_511_628_211) ^ u64::from(mixed);
    }

    fn clock_frame_counter(&mut self) {
        let steps = self.timing.frame_steps();
        let cycle = self.frame_counter_cycle;
        if cycle == steps[0] || cycle == steps[2] {
            self.clock_quarter();
        } else if cycle == steps[1] {
            self.clock_quarter();
            self.clock_half();
        } else if !self.five_step_mode && cycle == steps[3] {
            self.clock_quarter();
            self.clock_half();
            if !self.frame_irq_inhibit {
                self.frame_irq_pending = true;
            }
            self.frame_counter_cycle = 0;
        } else if self.five_step_mode && cycle == steps[4] {
            self.clock_quarter();
            self.clock_half();
            self.frame_counter_cycle = 0;
        }
    }

    fn clock_quarter(&mut self) {
        self.pulse[0].clock_quarter();
        self.pulse[1].clock_quarter();
        self.triangle.clock_quarter();
        self.noise.clock_quarter();
    }

    fn clock_half(&mut self) {
        self.pulse[0].clock_half(true);
        self.pulse[1].clock_half(false);
        self.triangle.clock_half();
        self.noise.clock_half();
    }

    pub(crate) fn write_register(&mut self, address: u16, value: u8) {
        match address {
            0x4000 => self.pulse[0].write_control(value),
            0x4001 => self.pulse[0].write_sweep(value),
            0x4002 => self.pulse[0].write_timer_low(value),
            0x4003 => self.pulse[0].write_timer_high(value),
            0x4004 => self.pulse[1].write_control(value),
            0x4005 => self.pulse[1].write_sweep(value),
            0x4006 => self.pulse[1].write_timer_low(value),
            0x4007 => self.pulse[1].write_timer_high(value),
            0x4008 => self.triangle.write_control(value),
            0x400a => self.triangle.write_timer_low(value),
            0x400b => self.triangle.write_timer_high(value),
            0x400c => self.noise.write_control(value),
            0x400e => self.noise.write_period(value),
            0x400f => self.noise.write_length(value),
            0x4010 => self.dmc.write_control(value),
            0x4011 => self.dmc.write_output(value),
            0x4012 => self.dmc.write_address(value),
            0x4013 => self.dmc.write_length(value),
            0x4015 => {
                self.pulse[0].set_enabled(value & 0x01 != 0);
                self.pulse[1].set_enabled(value & 0x02 != 0);
                self.triangle.set_enabled(value & 0x04 != 0);
                self.noise.set_enabled(value & 0x08 != 0);
                self.dmc.set_enabled(value & 0x10 != 0);
            }
            0x4017 => {
                self.five_step_mode = value & 0x80 != 0;
                self.frame_irq_inhibit = value & 0x40 != 0;
                if self.frame_irq_inhibit {
                    self.frame_irq_pending = false;
                }
                self.frame_reset_delay = Some(if self.cycles & 1 == 0 { 3 } else { 4 });
            }
            _ => {}
        }
    }

    pub(crate) fn peek_status(&self) -> u8 {
        u8::from(self.pulse[0].length_counter != 0)
            | (u8::from(self.pulse[1].length_counter != 0) << 1)
            | (u8::from(self.triangle.length_counter != 0) << 2)
            | (u8::from(self.noise.length_counter != 0) << 3)
            | (u8::from(self.dmc.bytes_remaining != 0) << 4)
            | (u8::from(self.frame_irq_pending) << 6)
            | (u8::from(self.dmc.irq_pending) << 7)
    }

    pub(crate) fn read_status(&mut self) -> u8 {
        let status = self.peek_status();
        self.frame_irq_pending = false;
        status
    }

    pub(crate) const fn irq_pending(&self) -> bool {
        self.frame_irq_pending || self.dmc.irq_pending
    }

    pub(crate) fn begin_dmc_dma(&mut self) -> Option<u16> {
        self.dmc.begin_dma()
    }

    pub(crate) fn complete_dmc_dma(&mut self, value: u8) {
        self.dmc.complete_dma(value);
    }

    fn mixed_output(&self) -> u16 {
        u16::from(self.pulse[0].output(true))
            + u16::from(self.pulse[1].output(false))
            + u16::from(self.triangle.output())
            + u16::from(self.noise.output())
            + u16::from(self.dmc.output_level)
    }

    pub(crate) fn state(&self) -> ApuState {
        let pulse_outputs = [self.pulse[0].output(true), self.pulse[1].output(false)];
        let triangle_output = self.triangle.output();
        let noise_output = self.noise.output();
        let dmc_output = self.dmc.output_level;
        ApuState {
            cycles: self.cycles,
            frame_counter_cycle: self.frame_counter_cycle,
            five_step_mode: self.five_step_mode,
            frame_irq_pending: self.frame_irq_pending,
            channel_status: self.peek_status() & 0x1f,
            length_counters: [
                self.pulse[0].length_counter,
                self.pulse[1].length_counter,
                self.triangle.length_counter,
                self.noise.length_counter,
            ],
            pulse_outputs,
            triangle_output,
            noise_output,
            dmc_output,
            dmc_active: self.dmc.bytes_remaining != 0,
            dmc_irq_pending: self.dmc.irq_pending,
            dmc_rate_index: self.dmc.rate_index,
            dmc_timer_counter: self.dmc.timer_counter,
            dmc_current_address: self.dmc.current_address,
            dmc_bytes_remaining: self.dmc.bytes_remaining,
            dmc_sample_buffer: self.dmc.sample_buffer,
            dmc_bits_remaining: self.dmc.bits_remaining,
            dmc_silence: self.dmc.silence,
            mixed_output: u16::from(pulse_outputs[0])
                + u16::from(pulse_outputs[1])
                + u16::from(triangle_output)
                + u16::from(noise_output)
                + u16::from(dmc_output),
            output_checksum: self.output_checksum,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raises_region_specific_four_step_frame_irqs() {
        for (timing, boundary) in [
            (ApuTiming::Ntsc, 29_829),
            (ApuTiming::Pal, 33_253),
            (ApuTiming::Dendy, 29_829),
        ] {
            let mut apu = Apu::new(timing);
            for _ in 0..boundary - 1 {
                apu.clock();
            }
            assert!(!apu.irq_pending(), "early {timing:?} frame IRQ");
            apu.clock();
            assert!(apu.irq_pending(), "missing {timing:?} frame IRQ");
            assert_ne!(apu.read_status() & 0x40, 0);
            assert!(!apu.irq_pending(), "status read must clear frame IRQ");
        }
    }

    #[test]
    fn five_step_mode_clocks_immediately_and_never_raises_frame_irq() {
        let mut apu = Apu::new(ApuTiming::Ntsc);
        apu.write_register(0x4015, 0x01);
        apu.write_register(0x4000, 0x1f);
        apu.write_register(0x4002, 8);
        apu.write_register(0x4003, 0);
        apu.write_register(0x4017, 0xc0);
        for _ in 0..4 {
            apu.clock();
        }
        assert_eq!(apu.pulse[0].envelope.decay, 15);
        for _ in 0..40_000 {
            apu.clock();
        }
        assert!(!apu.irq_pending());
    }

    #[test]
    fn clocks_pulse_triangle_noise_and_length_counters() {
        let mut apu = Apu::new(ApuTiming::Ntsc);
        apu.write_register(0x4015, 0x0d);
        apu.write_register(0x4000, 0xdf);
        apu.write_register(0x4002, 8);
        apu.write_register(0x4003, 0);
        apu.write_register(0x4008, 0x81);
        apu.write_register(0x400a, 2);
        apu.write_register(0x400b, 0);
        apu.write_register(0x400c, 0x1f);
        apu.write_register(0x400e, 0);
        apu.write_register(0x400f, 0);

        let initial_lengths = apu.state().length_counters;
        let mut observed = [false; 3];
        for _ in 0..14_913 {
            apu.clock();
            let state = apu.state();
            observed[0] |= state.pulse_outputs[0] != 0;
            observed[1] |= state.triangle_output != 0;
            observed[2] |= state.noise_output != 0;
        }
        assert_eq!(observed, [true; 3]);
        assert_eq!(apu.state().length_counters[0], initial_lengths[0] - 1);
        assert_eq!(apu.state().length_counters[2], initial_lengths[2]);
        assert_eq!(apu.state().length_counters[3], initial_lengths[3] - 1);
        assert_ne!(apu.state().output_checksum, 0);
    }

    #[test]
    fn disabling_channels_clears_length_status() {
        let mut apu = Apu::new(ApuTiming::Ntsc);
        apu.write_register(0x4015, 0x0f);
        for address in [0x4003, 0x4007, 0x400b, 0x400f] {
            apu.write_register(address, 0);
        }
        assert_eq!(apu.peek_status() & 0x0f, 0x0f);
        apu.write_register(0x4015, 0);
        assert_eq!(apu.peek_status() & 0x0f, 0);
    }

    #[test]
    fn applies_pulse_sweep_and_region_specific_noise_periods() {
        let mut apu = Apu::new(ApuTiming::Ntsc);
        apu.write_register(0x4015, 0x01);
        apu.write_register(0x4002, 100);
        apu.write_register(0x4003, 0);
        apu.write_register(0x4001, 0x81);
        apu.clock_half();
        assert_eq!(apu.pulse[0].timer_period, 150);

        let mut ntsc = Apu::new(ApuTiming::Ntsc);
        ntsc.write_register(0x400e, 2);
        ntsc.clock();
        assert_eq!(ntsc.noise.timer_counter, 15);

        let mut pal = Apu::new(ApuTiming::Pal);
        pal.write_register(0x400e, 2);
        pal.clock();
        assert_eq!(pal.noise.timer_counter, 13);
    }

    #[test]
    fn configures_fetches_wraps_and_reports_dmc_status() {
        let mut apu = Apu::new(ApuTiming::Ntsc);
        apu.write_register(0x4010, 0x8f);
        apu.write_register(0x4011, 0xff);
        apu.write_register(0x4012, 0xff);
        apu.write_register(0x4013, 2);
        apu.write_register(0x4015, 0x10);
        let state = apu.state();
        assert_eq!(state.dmc_output, 0x7f);
        assert_eq!(state.dmc_current_address, 0xffc0);
        assert_eq!(state.dmc_bytes_remaining, 33);
        assert_ne!(apu.peek_status() & 0x10, 0);
        assert_eq!(apu.begin_dmc_dma(), Some(0xffc0));
        apu.complete_dmc_dma(0xa5);
        assert_eq!(apu.state().dmc_sample_buffer, Some(0xa5));
        assert_eq!(apu.state().dmc_current_address, 0xffc1);
        assert_eq!(apu.state().dmc_bytes_remaining, 32);

        apu.dmc.sample_buffer = None;
        apu.dmc.current_address = 0xffff;
        apu.dmc.bytes_remaining = 2;
        assert_eq!(apu.begin_dmc_dma(), Some(0xffff));
        apu.complete_dmc_dma(0x5a);
        assert_eq!(apu.state().dmc_current_address, 0x8000);
    }

    #[test]
    fn loops_or_raises_and_clears_dmc_irq() {
        let mut irq = Apu::new(ApuTiming::Ntsc);
        irq.write_register(0x4010, 0x80);
        irq.write_register(0x4015, 0x10);
        assert_eq!(irq.begin_dmc_dma(), Some(0xc000));
        irq.complete_dmc_dma(0xff);
        assert!(irq.state().dmc_irq_pending);
        assert_ne!(irq.read_status() & 0x80, 0);
        assert!(irq.state().dmc_irq_pending, "status reads retain DMC IRQ");
        irq.write_register(0x4015, 0);
        assert!(!irq.state().dmc_irq_pending);

        let mut looping = Apu::new(ApuTiming::Ntsc);
        looping.write_register(0x4010, 0xc0);
        looping.write_register(0x4015, 0x10);
        assert_eq!(looping.begin_dmc_dma(), Some(0xc000));
        looping.complete_dmc_dma(0);
        assert!(looping.state().dmc_active);
        assert_eq!(looping.state().dmc_bytes_remaining, 1);
        assert!(!looping.state().dmc_irq_pending);
    }

    #[test]
    fn clocks_dmc_output_and_region_specific_rates() {
        let mut ntsc = Apu::new(ApuTiming::Ntsc);
        ntsc.write_register(0x4010, 0x0f);
        ntsc.dmc.output_level = 64;
        ntsc.dmc.shift_register = 1;
        ntsc.dmc.bits_remaining = 1;
        ntsc.dmc.silence = false;
        ntsc.clock();
        assert_eq!(ntsc.state().dmc_output, 66);
        assert_eq!(ntsc.dmc.timer_counter, 53);

        let mut pal = Apu::new(ApuTiming::Pal);
        pal.write_register(0x4010, 0x0f);
        pal.clock();
        assert_eq!(pal.dmc.timer_counter, 49);
    }
}
