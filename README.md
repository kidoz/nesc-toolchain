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
> higher-level NesC and Rust recovery remains under development.

## Highlights

- Preprocessing, parsing, semantic analysis, typed HIR, verified MIR, and safe
  optimization passes
- Ricoh 2A03/2A07 code generation with a stable `nescall` ABI, zero-page
  allocation, stack reports, and reference-driven arithmetic helpers
- Fixed arrays, pointer arithmetic, typed CPU-bus address spaces, volatile
  indirect access, and configurable bounds checks
- Mapper 0 linking, iNES/NES 2.0 ROM construction, symbols, source maps, and
  deterministic emulator boot verification
- `nesc new`, `nesc check`, `nesc build`, `nesc inspect`, and Mapper 0
  `nesc disassemble` workflows
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
| Deterministic emulator boot verification | Available as a library |
| Debugger and higher-level ROM-to-code decompiler | Planned |

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
```

Expected output:

```text
Created `demo` at demo
Checked `demo` v0.1.0 (src/main.c)
Built `demo` at target
Disassembled `target/demo.nes` into target/demo-disassembly (..., PRG recovery verified)
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

1. Complete debugger integration and richer emulator timing coverage
2. Add mapper-aware compilation for UxROM and CNROM
3. Extend disassembly to bank-switched cartridges and add verified NesC/Rust
   decompilation
4. Expand optimization quality and generated-code cost modeling

## License

Licensed under the [MIT License](LICENSE).

Copyright © 2026 Aleksandr Pavlov &lt;ckidoz@gmail.com&gt;.
