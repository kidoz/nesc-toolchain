# nesc-toolchain

[![Language: Rust](https://img.shields.io/badge/language-Rust-dea584.svg)](https://www.rust-lang.org/)
![Rust edition: 2024](https://img.shields.io/badge/Rust%20edition-2024-dea584.svg)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

An optimizing compiler and ROM-development toolkit for NES-compatible hardware.

`nesc-toolchain` compiles **NesC**, a restricted freestanding C-like language,
to Ricoh 2A03/2A07 machine code and packages the result as an iNES or NES 2.0
ROM. The toolkit is written in stable Rust 2024.

> [!IMPORTANT]
> The compiler currently generates Mapper 0 (NROM), Mapper 2 (UxROM), and
> Mapper 3 (CNROM) ROMs. Recursive disassembly, exact assembly round trips,
> bank-qualified semantic CFG lifting, stable Rust emission, hybrid NesC
> emission, and differential verification accept all three mappers.
> SSA/value, call-graph, calling-convention, conservative type, and reducible
> control-flow recovery support hybrid NesC and stable Rust 2024 translation
> with bounded fallback. Differential verification is available for both outputs.

## Highlights

- Preprocessing, parsing, semantic analysis, typed HIR, verified MIR, and safe
  optimization passes with inter-block constant propagation and natural-loop
  analysis
- Ricoh 2A03/2A07 code generation with a stable `nescall` ABI, zero-page
  allocation weighted by loop frequency, stack reports, profile-driven
  arithmetic selection, hot fall-through placement, branch relaxation, and
  auditable size/cycle estimates
- Fixed arrays, pointer arithmetic, typed CPU-bus address spaces, volatile
  indirect access, and configurable bounds checks
- Verified `NES_ASM` blocks with register operands, explicit clobbers, symbolic
  call relocations, mapper-bank effects, and hardware-stack accounting
- Relocatable standalone `.s` modules with typed NesC imports and exports,
  symbolic cross-module relocations, source maps, and stack contracts
- Mapper 0, Mapper 2, and Mapper 3 linking with fixed PRG, switchable PRG or
  CHR placement, safe cross-bank call trampolines, bank-qualified symbols, and
  deterministic emulator boot verification
- Public bounded emulator execution for all 151 official CPU opcodes, reset,
  interrupts, controller I/O, DMA, mapper writes, region timing, checkpoints,
  and first-divergence event traces
- Dot-driven NTSC/PAL/Dendy PPU timing with scrolling-register latches,
  background and sprite composition, sprite status flags, mapper-aware CHR
  reads, nametable mirroring, shared I/O bus behavior, vblank-boundary NMI
  cancellation, background fetch and shift-register timing, secondary-OAM
  evaluation, timed sprite fetches, the sprite-overflow scan bug, and a
  checkpointed palette-index framebuffer
- CPU-clock-driven APU frame sequencing with pulse, triangle, and noise channel
  timers, envelopes, length and linear counters, pulse sweeps, frame IRQs, and
  deterministic output checksums
- DMC sample playback with regional rates, bounded DAC updates, address
  wrapping, looping, IRQs, four-clock traced CPU stalls, and OAM DMA
  arbitration
- `nesc new`, `nesc check`, `nesc build`, `nesc run`, `nesc inspect`, Mapper 0/2/3
  `nesc test`, `nesc disassemble`, `nesc decompile --emit=nesc`, and
  `nesc decompile --emit=rust` workflows
- Deterministic `nesc run` frame execution that renders a ROM to a palette-index
  framebuffer and emits dependency-free PNG/PPM frame images, per-frame
  framebuffer hashes, and applies a per-frame controller-input script
- Emulator-backed `NES_TEST` discovery with independently linked test ROMs,
  typed single-evaluation `NES_ASSERT_EQ`, source-attached failures, per-test
  cycle budgets, name filtering, and bounded NTSC/PAL/Dendy execution
- `nesc debug` inspection of verification summaries, interrupt and frame
  checkpoints, sparse PPU/APU state, cartridge banks, event traces, and the
  first structured divergence
- Interactive and scripted Mapper 0/2/3 ROM debugging with instruction, cycle,
  frame, source, and call stepping; cooperative pause; bank-qualified
  breakpoints; exact-clock CPU-bus watchpoints and traces; source and symbol
  lookup; hardware state; disassembly; stack inspection; and bounded execution
- Bounded SSA construction with constant and flag propagation, precise RAM
  facts, explicit hardware barriers, branch predicates, and function summaries
- Bank-qualified call graphs, recursive-component detection, evidence-scored
  `nescall` signatures, and conservative scalar and pointer type facts
- Dominance-backed `if`, natural-loop, counted-loop, call, and return regions
  with explicit fallbacks for unresolved, recursive, or irreducible control
- Stable Rust 2024 semantic translation using explicit CPU state, ordered bus
  events, shared instruction budgets, and original-byte interpreter fallback
- Hybrid NesC output with native reducible control flow and a bounded
  target-side dispatcher for unresolved or irreducible functions
- Original-6502-versus-Rust differential checks across deterministic CPU and
  memory states, with the generated tests and pass report retained as artifacts
- Original-6502-versus-NesC emulator checks across recovered functions,
  deterministic inputs, Mapper 2 PRG and Mapper 3 CHR bank contexts, scheduled
  NMI/IRQ entry, and equivalent multi-frame PPU/APU checkpoints
- Rustc-style diagnostics with source spans and suggested corrections

## Current status

| Capability | Availability |
| --- | --- |
| Cargo workspace and crate boundaries | Available |
| `nesc new` | Available |
| `nesc check` for manifests and source semantics | Available |
| Emulator-backed `nesc test` discovery, assertions, filtering, and execution | Available |
| NesC preprocessing and parsing | Available |
| HIR, MIR, verification, and optimization | Available |
| Profile-specific MIR pipelines and 6502 sequence cost reports | Available |
| Inter-block constant propagation and loop-weighted zero-page allocation | Available |
| Frequency-guided block placement, branch inversion, and branch relaxation | Available |
| Target-specific inline 6502 assembly | Available |
| Standalone relocatable 6502 assembly modules | Available |
| 6502 code generation and Mapper 0/2/3 linking | Available |
| ROM construction and inspection | Available |
| Official 6502 decoding and recursive Mapper 0/2/3 disassembly | Available |
| Lossless Mapper 0/2/3 assembly recovery and exact ROM round trips | Available |
| Bank-qualified Mapper 0/2/3 CFG and semantic 6502 IR | Available as a library |
| SSA/value, ABI/type, and reducible control-flow recovery | Available as a library |
| Mapper 0/2/3 stable Rust translation with bounded fallback | Available |
| Mapper 0/2/3 hybrid NesC translation with bounded dispatcher fallback | Available |
| Mapper 0/2/3 original-versus-Rust differential verification | Available |
| Mapper 0/2/3 original-versus-NesC differential verification with interrupt and multi-frame hardware checkpoints | Available |
| Structured verification artifact inspection with `nesc debug` | Available |
| Interactive and scripted Mapper 0/2/3 ROM debugger | Available |
| CPU-cycle stepping and NTSC/PAL/Dendy PPU beam position | Available |
| Per-clock official CPU bus operations, dummy accesses, interrupts, and OAM DMA | Available |
| PPU background/sprite rendering and palette-index framebuffer | Available |
| Deterministic `nesc run` frame execution with PNG/PPM export, framebuffer hashing, and scripted controller input | Available |
| Deterministic APU audio capture with WAV export (`nesc run --wav`) | Available |
| Visual `nesc debug` framebuffer, sprite/OAM, nametable, and palette inspection | Available |
| PPU I/O latch, vblank/NMI boundary behavior, and rendering-time OAM restrictions | Available |
| PPU background fetch pipeline, secondary OAM, timed sprite fetches, and overflow bug | Available |
| APU pulse, triangle, noise, frame-counter, and IRQ timing | Available |
| DMC sample fetching, output, CPU stalls, looping, and IRQ timing | Available |
| Deterministic CPU/bus execution and boot verification | Available as a library |

## Quick start

The repository pins its Rust toolchain in `rust-toolchain.toml`. From the
repository root:

```bash
cargo run -p nesc-cli -- new demo
cd demo
cargo run --manifest-path ../Cargo.toml -p nesc-cli -- check
cargo run --manifest-path ../Cargo.toml -p nesc-cli -- build
cargo run --manifest-path ../Cargo.toml -p nesc-cli -- \
  run target/demo.nes --frames 3 --hash --png --out target/frames
cargo run --manifest-path ../Cargo.toml -p nesc-cli -- \
  disassemble target/demo.nes --round-trip-check
cargo run --manifest-path ../Cargo.toml -p nesc-cli -- \
  decompile target/demo.nes --emit=rust --verify --output target/demo-rust
cargo run --manifest-path ../Cargo.toml -p nesc-cli -- \
  decompile target/demo.nes --emit=nesc --verify --output target/demo-nesc
cargo run --manifest-path ../Cargo.toml -p nesc-cli -- \
  debug target/demo-nesc --view checkpoints
cargo run --manifest-path ../Cargo.toml -p nesc-cli -- \
  debug target/demo.nes --command "break main" --command continue
```

Expected output:

```text
Created `demo` at demo
Checked `demo` v0.1.0 (src/main.c)
Built `demo` at target
Disassembled `target/demo.nes` into target/demo-disassembly (..., exact ROM round trip verified)
Decompiled `target/demo.nes` into target/demo-rust as host-side stable Rust (..., verified)
Decompiled `target/demo.nes` into target/demo-nesc as hybrid NesC (..., verified with ... executions)
No verification checkpoints recorded.
Loaded Mapper 0 ROM with ... PRG banks at ...
Stopped: breakpoint 1 at ...
```

The generated project contains:

```text
demo/
├── .gitignore
├── NesC.toml
├── README.md
└── src/
    └── main.c
```

## Running and viewing frames

`nesc run` executes a built `.nes` ROM in the deterministic emulator, renders
whole video frames, and emits the results for inspection and regression testing:

```bash
nesc run target/demo.nes --frames 3 --hash --png --out target/frames
nesc run target/demo.nes --frames 120 --input inputs.txt --png --out target/play
nesc run target/demo.nes --region pal --ppm --out target/frames
```

- `--frames N` renders `N` frames (default `1`).
- `--png` / `--ppm` write dependency-free `frame.png` / `frame.ppm` (single frame)
  or `frame-000.png…` (multiple frames) into `--out`; `--png` is the default when
  `--out` is set with neither flag.
- `--hash` prints one deterministic `frame <i>: <checksum>` line per frame, for
  golden-frame regression checks.
- `--region ntsc|pal|dendy` overrides the ROM's declared timing.
- `--input FILE` applies a per-frame controller script: one line per frame,
  `P1 P2`, where each port field is `-` for none or letters from
  `A B S(elect) T(=sTart) U D L R` (for example `RA -` holds Right+A on port 1).
- `--wav` captures deterministic APU audio and writes `audio.wav` to `--out`.

Rendering, framebuffer hashing, frame stepping, and audio capture are
deterministic across runs and regions, so `--hash` output and captured audio are
stable and suitable for committed goldens.

The interactive `nesc debug` ROM debugger adds visual inspection over the running
machine: `framebuffer <path>` writes the current frame as PNG (or PPM by
extension), and `oam`, `nametable`, and `palette` dump the sprite list, the
nametable-0 tile map, and the active palette with its RGB colors.

## Emulator-backed tests

`nesc test` discovers reserved test definitions in the project entry source,
links each test as an independent ROM entry, and executes it in the
deterministic emulator. A test-only source does not require `NES_MAIN`:

```c
NES_CYCLE_BUDGET(2000) NES_TEST("addition works") {
    u8 result = 10u8 + 20u8;

    NES_ASSERT_EQ(result, 30u8);
}
```

Run every test or select names containing a substring:

```bash
cargo run -p nesc-cli -- test
cargo run -p nesc-cli -- test --filter addition
```

Each assertion evaluates its actual value before its expected value and
evaluates both exactly once. Failure diagnostics retain both 32-bit values and
the test source range. `NES_CYCLE_BUDGET` sets a smaller per-test bound than
the command-wide `--cycle-limit`; `--instruction-limit` independently bounds
instruction execution. Mapper 0, Mapper 2, and Mapper 3 projects use their
manifest-selected NTSC, PAL, or Dendy timing.

## Inline assembly

`NES_ASM` embeds bounded official-6502 source as a volatile statement. Its
contract names every compiler value crossing the block and every resource the
source may change:

```c
extern void assembly_helper(void);

u8 run_assembly(u8 input) {
    u8 output;
    NES_ASM(
        "pha\njsr assembly_helper\npla",
        NES_ASM_INPUT_A(input),
        NES_ASM_OUTPUT_X(output),
        NES_CLOBBER_A,
        NES_CLOBBER_FLAGS,
        NES_CLOBBER_MEMORY,
        NES_ASM_CALL(assembly_helper),
        NES_ASM_STACK(1)
    );
    return output;
}
```

Inputs and outputs support the `A`, `X`, and `Y` registers. Other contract
items are `NES_CLOBBER_A`, `NES_CLOBBER_X`, `NES_CLOBBER_Y`,
`NES_CLOBBER_FLAGS`, `NES_CLOBBER_MEMORY`, `NES_ASM_BANK_EFFECT`,
`NES_ASM_CALL(function)`, and `NES_ASM_STACK(bytes)`. Symbolic `jsr` operands
must have a matching call declaration and become linker relocations. Inline
branches use current-location expressions such as `*+4`; labels, equates, and
section-placement directives remain owned by the compiler.

The conventional form is also accepted with `a`, `x`, and `y` constraints:

```c
asm volatile ("tax" : "=x"(output) : "a"(input) : "flags", "memory");
```

Use `NES_ASM` when the contract must also describe direct calls, mapper-bank
effects, or additional hardware-stack use.

## Standalone assembly

List assembly modules explicitly so their link order is deterministic:

```toml
[build]
entry = "src/main.c"
assembly = ["src/collision.s"]
region = "ntsc"
format = "nes2"
```

An exported assembly function needs a matching typed `extern` declaration:

```c
extern u8 fast_collision(u8 value);
```

```asm
.setcpu "6502"
.segment "CODE"
.export fast_collision
.nesc_bank fixed
.nesc_stack fast_collision, 0

fast_collision:
    clc
    adc #1
    rts
```

Modules use the same object symbols and absolute or relative relocations as
compiled NesC. `.import name` references another typed function; a compiled
NesC definition must use `NES_EXPORT` before assembly may import it.
`.nesc_stack name, bytes` declares the maximum extra hardware-stack use after
entry, including nested `jsr` return addresses and explicit pushes but excluding
the caller's `jsr` into the exported routine. `.nesc_bank fixed` keeps the whole
module in the permanently mapped bank; `.nesc_bank 1` places it in switchable
bank 1. A banked assembly export must have the matching `NES_BANK(number)` on
its typed `extern` declaration. Origins and undocumented opcodes are rejected
in relocatable modules.

## Mapper 2 projects

UxROM projects use at least two complete 16 KiB PRG-ROM banks. The last bank is
permanently mapped at `$C000-$FFFF`; numbered banks are mapped at
`$8000-$BFFF`. Unannotated functions, startup, runtime helpers, and interrupt
handlers stay in the fixed bank. Use `NES_BANK(number)` for code that belongs in
a switchable bank:

```c
NES_BANK(1) NES_NOINLINE u8 banked_color(void) {
    return 0x2Au8;
}
```

Calls from fixed code or a different switchable bank use linker-generated
trampolines that preserve A, X, Y, the prior bank selection, and `nescall`
return values. The stack report includes the trampoline's additional three
bytes. Entry and interrupt functions cannot use `NES_BANK`.

`nesc disassemble` follows statically known UxROM mapper writes into
switchable code, keeps every instruction and label qualified by its physical
PRG bank, and records unknown mapper state instead of inventing an edge.
Recovered assembly uses `.nesc_prg_bank number, origin` to preserve repeated
`$8000` switchable windows. `--round-trip-check` reconstructs the complete
header, trainer, PRG-ROM, CHR-ROM, and trailing bytes exactly.

`nesc decompile --emit=rust` translates proven UxROM regions and retains
unknown bank selections in bounded interpreter fallback. Hybrid NesC output
preserves the Mapper 2 cartridge layout, places proven switchable functions
with `NES_BANK`, tracks mapper writes, and qualifies fallback dispatch by
physical PRG bank. For either output, `--verify` compares bounded executions
across recovered functions, deterministic input profiles, and every applicable
switchable-bank context. NesC verification compares CPU state, RAM, PRG RAM,
mapper state, APU registers, CHR RAM, palette, OAM, nametable RAM, ordered
semantic bus events, and termination through the deterministic emulator.
Recognized `RTI`-terminated NMI and IRQ handlers run from emulated interrupt
stack frames before reset semantic instruction zero. When reset execution
crosses either of its first two frames within the instruction bound, the
verifier locates that original instruction boundary and compares generated
state at the equivalent semantic checkpoint. Verification-only DMA copies
from the isolated semantic RAM shadow, so OAM comparison observes original
source bytes instead of compiler-runtime RAM. Coverage counts are retained in
`verification.json`. Unknown bank selections remain unresolved rather than
selecting a guessed target, and verification reports an actionable failure
when the conservative fallback cannot reproduce an exercised execution.
Target-side NesC verification reserves `$7000-$7FFF` for its isolated RAM
shadow, event log, and result record; an exercised source access to that
workspace is rejected instead of being compared unsafely.

## Mapper 3 projects

CNROM projects use 16 or 32 KiB of fixed PRG-ROM and between 1 and 256 complete
8 KiB CHR-ROM banks. A volatile write anywhere in `$8000-$FFFF` selects the
PPU-visible CHR bank. The linker rejects PRG-bank placement annotations because
CNROM does not switch CPU code, and its map report lists the fixed PRG window
and every available CHR bank.

`nesc disassemble` keeps CNROM control flow in the fixed physical PRG mapping
while recording each proven or unknown CHR-bank write. Exact recovery preserves
every CHR byte in `chr.bin`. Rust and hybrid NesC translation retain the mapper
write as an ordered bus effect, and `--verify` executes every recovered function
from each initial CHR-bank context. Verification compares the final physical
CHR bank independently from the PRG mapping.

## ROM debugger

Pass a `.nes` file to `nesc debug` to open the command shell. Sibling `.sym`
and `.source-map` files are loaded automatically; explicit files can be passed
with `--symbols` and `--source-map`.

```bash
nesc debug target/demo.nes
```

The shell supports:

```text
run                  continue              pause
step                 step-cycle            step-frame
step-source          next                  finish
break main           break 001:$8000       delete 1
watch $0010          watch-read $2002      watch-write $4000
registers            memory $0000 64       disassemble main 12
stack                source                symbols
ppu                  apu                   cartridge
trace on             trace off             trace show
reset                quit
```

Breakpoint addresses may include a physical PRG bank, which prevents repeated
Mapper 2 CPU-window addresses from being confused. Memory inspection uses
observational reads, so reading PPU, controller, or mapper state through the
debugger does not trigger emulated side effects. Watchpoints stop on the exact
CPU clock that performs a matching access, including mirrored RAM, PPU/APU
registers, dummy reads and writes, alternating OAM DMA transfers, stack
traffic, and mapper writes. `trace show` includes a bounded bus-clock trace
with cycle, PC, direction, address, value, dummy-access status, and physical
PRG bank.

For automation, repeat `--command` to run a bounded command sequence without
the shell:

```bash
nesc debug target/demo.nes \
  --command "break main" \
  --command continue \
  --command registers \
  --command "disassemble main 8"
```

Every resume command enforces instruction and cycle limits. `step-cycle`
advances the CPU timing clock once and reports the current PPU frame, scanline,
and dot. Long resume commands check a thread-safe cooperative pause signal on
every clock; the interactive shell's `pause` command confirms that execution
is already stopped at its command boundary.

Every official instruction schedules one bus operation per CPU clock: opcode
and operand fetches, indexed-address penalties, branch dummy reads,
read-modify-write double writes, stack and control-flow traffic, interrupt
entry, and parity-correct 513/514-clock OAM DMA. Bus and MMIO effects occur on
their scheduled clocks; architectural register state commits on the final
instruction clock. DMC sample fetches preempt readable CPU or OAM DMA clocks,
retain their bus source in debugger traces, and extend the interrupted
instruction by four clocks. The PPU beam now runs dot by dot, renders scrolled
background tiles and evaluated sprites through cartridge CHR mapping, updates
sprite-zero-hit and overflow status, and retains a 256x240 palette-index
framebuffer in machine checkpoints. The debugger's `ppu` command reports the
rendering registers, shared I/O bus latch, NMI line and pending edge, and a
stable framebuffer checksum. Background pixels now come from dot-scheduled
nametable, attribute, and pattern fetches feeding pattern and palette shift
registers. Sprite processing clears secondary OAM, evaluates primary OAM,
reproduces the diagonal overflow scan, fetches sprite patterns during dots
257-320, and activates them on the following scanline. PPU status reads combine
the status flags with the latched low bits and suppress or cancel vblank NMIs at
the boundary. Rendering-time OAMDATA reads observe the live internal OAM bus.

The APU runs once per CPU clock with region-specific four-step and five-step
frame sequencing. Pulse, triangle, and noise channel state is retained in
machine checkpoints, `$4015` exposes and clears frame IRQ state, and IRQs enter
the normal CPU interrupt path. The debugger's `apu` command reports channel
lengths, instantaneous outputs, and a stable output checksum. Its DMC view also
reports sample-reader address, remaining bytes, sample buffering, timer state,
silence, and IRQ state.

## Verification artifact inspection

Verified hybrid NesC output contains a versioned `verification.json`. Pass the
file or its project directory to `nesc debug`:

```bash
nesc debug target/demo-nesc
nesc debug target/demo-nesc --view checkpoints
nesc debug target/demo-nesc --view ppu --checkpoint 0
nesc debug target/demo-nesc --view apu --checkpoint 0
nesc debug target/demo-nesc --view cartridge --checkpoint 0
nesc debug target/demo-nesc --view trace --checkpoint 0
nesc debug target/demo-nesc --view divergence
```

Checkpoint state is recorded after successful scheduled NMI, IRQ, and frame
comparisons. Hardware arrays use sparse nonzero address/value entries to keep
the artifact bounded. A failed verification still writes the artifact before
returning its diagnostic, so `--view divergence` can show the first mismatch
and recent original and generated semantic events.

```toml
[cartridge]
mapper = 2
submapper = 0
mirroring = "horizontal"
prg-rom-kib = 64
chr-rom-kib = 8
battery = false
```

## Project manifest

Every NesC project uses `NesC.toml`:

```toml
[package]
name = "demo"
version = "0.1.0"

[build]
entry = "src/main.c"
assembly = []
region = "ntsc"
format = "nes2"

[cartridge]
mapper = 0
submapper = 0
mirroring = "horizontal"
prg-rom-kib = 32
chr-rom-kib = 8
battery = false

[compiler]
optimization = "size"
signed-overflow = "wrap"
bounds-checks = "elide-proven"
stack-limit = 192

[memory.zero-page]
available = ["0x00..0xEF"]
reserved = ["0xF0..0xFF"]
strategy = "frequency"

[debug]
symbols = true
source-map = true
```

The checker rejects unsafe entry paths, missing source files, unsupported
compiler cartridge layouts, invalid NROM capacities, overlapping zero-page
ranges, malformed versions, invalid stack limits, and source-level type errors.

Optimization accepts `"0"`, `"1"`, `"2"`, `"size"`, `"min-size"`, and
`"cycles"`. The stronger MIR settings propagate predecessor-agreed local
constants, simplify constant branches, and remove dead pure values. Natural
loop depth supplies relative execution weights to zero-page placement.
Size-oriented code generation can reuse an arithmetic helper that is already
required elsewhere, while cycle-oriented code generation keeps constant shifts
inline. The backend places hot CFG successors as fall-throughs, inverts a
conditional when its true edge becomes the fall-through, removes redundant
jumps, and expands any relative branch outside the signed 8-bit range. Each
build writes an `.optimization` report beside the ROM, assembly, map, symbols,
source map, zero-page report, and stack report. CFG liveness also lets the
storage allocator reuse same-width virtual values and non-address-sensitive
source locals within one function. Aggregate loop-weighted spill cost selects
physical zero-page slots, and the report groups every shared occupant.
Globals, parameters, volatile or aggregate locals, address-taken locals, and
storage owned by different functions stay isolated.

## Workspace

The workspace separates frontend, intermediate representation, optimization,
backend, object, linker, ROM, emulator, debugger, and reverse-engineering
concerns. Core implementation crates include:

| Crate | Responsibility |
| --- | --- |
| `nesc-cli` | Command parsing and user workflows |
| `nesc-project` | Manifest parsing, validation, and project generation |
| `nesc-diagnostics` | Structured source diagnostics |
| `nesc-frontend`, `nesc-hir`, `nesc-mir` | Parsing, type checking, lowering, and verification |
| `nesc-opt` | MIR optimization passes |
| `nesc-codegen-6502`, `nesc-runtime` | Machine-code selection and runtime support |
| `nesc-object`, `nesc-linker`, `nesc-rom` | Relocatable objects, linking, and cartridge containers |
| `nesc-emulator` | Deterministic generated-ROM verification |
| `nesc-debug` | ROM debugger sessions and verification artifact inspection |
| `nesc-decompiler`, `nesc-decompile-runtime` | ROM analysis, stable Rust emission, and host execution |

SDK declarations live under `sdk/include/`.

## Development

Run every quality gate before submitting a change:

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
```

CI runs the same commands on pushes and pull requests.

## Next work

1. Add accumulator forwarding, register reuse, and flag-liveness optimization
2. Add call-graph-aware storage overlays while preserving interrupt isolation

## License

Licensed under the [MIT License](LICENSE).

Copyright © 2026 Aleksandr Pavlov &lt;ckidoz@gmail.com&gt;.
