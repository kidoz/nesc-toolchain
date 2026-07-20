# nesc-toolchain

[![Language: Rust](https://img.shields.io/badge/language-Rust-dea584.svg)](https://www.rust-lang.org/)
![Rust edition: 2024](https://img.shields.io/badge/Rust%20edition-2024-dea584.svg)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

An optimizing compiler and ROM-development toolkit for NES-compatible hardware.

`nesc-toolchain` compiles **NesC**, a restricted freestanding C-like language,
to Ricoh 2A03/2A07 machine code and packages the result as an iNES or NES 2.0
ROM. The toolkit is written in stable Rust 2024.

> [!IMPORTANT]
> The compiler currently generates Mapper 0 ROMs. Mapper-aware ROM models for
> UxROM and CNROM exist. Recursive disassembly currently accepts Mapper 0 ROMs;
> SSA/value, call-graph, calling-convention, conservative type, and reducible
> control-flow recovery support hybrid NesC and stable Rust 2024 translation
> with bounded fallback. Differential verification is available for Rust output.

## Highlights

- Preprocessing, parsing, semantic analysis, typed HIR, verified MIR, and safe
  optimization passes
- Ricoh 2A03/2A07 code generation with a stable `nescall` ABI, zero-page
  allocation, stack reports, and reference-driven arithmetic helpers
- Fixed arrays, pointer arithmetic, typed CPU-bus address spaces, volatile
  indirect access, and configurable bounds checks
- Mapper 0 linking, iNES/NES 2.0 ROM construction, symbols, source maps, and
  deterministic emulator boot verification
- Public bounded emulator execution for all 151 official CPU opcodes, reset,
  interrupts, controller I/O, DMA, mapper writes, region timing, checkpoints,
  and first-divergence event traces
- `nesc new`, `nesc check`, `nesc build`, `nesc inspect`, Mapper 0
  `nesc disassemble`, `nesc decompile --emit=nesc`, and
  `nesc decompile --emit=rust` workflows
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
- Rustc-style diagnostics with source spans and suggested corrections

## Current status

| Capability | Availability |
| --- | --- |
| Cargo workspace and crate boundaries | Available |
| `nesc new` | Available |
| `nesc check` for manifests and source semantics | Available |
| NesC preprocessing and parsing | Available |
| HIR, MIR, verification, and optimization | Available |
| 6502 code generation and Mapper 0 linking | Available |
| ROM construction and inspection | Available |
| Official 6502 decoding and recursive Mapper 0 disassembly | Available |
| Bank-qualified NROM CFG and semantic 6502 IR | Available as a library |
| SSA/value, ABI/type, and reducible control-flow recovery | Available as a library |
| Stable Rust host-side translation with bounded fallback | Available |
| Hybrid NesC translation with bounded dispatcher fallback | Available |
| Original-versus-Rust differential verification | Available |
| Deterministic CPU/bus execution and boot verification | Available as a library |
| Complete PPU/APU timing and debugger integration | Planned |

## Quick start

The repository pins its Rust toolchain in `rust-toolchain.toml`. From the
repository root:

```bash
cargo run -p nesc-cli -- new demo
cd demo
cargo run --manifest-path ../Cargo.toml -p nesc-cli -- check
cargo run --manifest-path ../Cargo.toml -p nesc-cli -- build
cargo run --manifest-path ../Cargo.toml -p nesc-cli -- \
  disassemble target/demo.nes --round-trip-check
cargo run --manifest-path ../Cargo.toml -p nesc-cli -- \
  decompile target/demo.nes --emit=rust --verify --output target/demo-rust
cargo run --manifest-path ../Cargo.toml -p nesc-cli -- \
  decompile target/demo.nes --emit=nesc --output target/demo-nesc
```

Expected output:

```text
Created `demo` at demo
Checked `demo` v0.1.0 (src/main.c)
Built `demo` at target
Disassembled `target/demo.nes` into target/demo-disassembly (..., exact ROM round trip verified)
Decompiled `target/demo.nes` into target/demo-rust as host-side stable Rust (..., verified)
Decompiled `target/demo.nes` into target/demo-nesc as hybrid NesC (...)
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

## Project manifest

Every NesC project uses `NesC.toml`:

```toml
[package]
name = "demo"
version = "0.1.0"

[build]
entry = "src/main.c"
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

1. Complete PPU/APU timing and debugger integration
2. Add mapper-aware compilation for UxROM and CNROM
3. Extend recovery and verification to bank-switched cartridges and compiled
   NesC output
4. Expand optimization quality and generated-code cost modeling

## License

Licensed under the [MIT License](LICENSE).

Copyright © 2026 Aleksandr Pavlov &lt;ckidoz@gmail.com&gt;.
