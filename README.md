# nesc-toolchain

An optimizing compiler and ROM-development toolkit for NES-compatible hardware.

`nesc-toolchain` compiles **NesC**, a restricted freestanding C-like language,
to Ricoh 2A03/2A07 machine code and packages the result as an iNES or NES 2.0
ROM. The toolkit is written in stable Rust 2024.

> [!IMPORTANT]
> The repository currently provides its workspace foundation, project
> generation, manifest validation, SDK headers, and structured diagnostics.
> Source compilation and ROM generation are not available yet.

## Highlights

- Stable Rust workspace with explicit compiler boundaries
- `nesc new` starter-project generation without overwriting existing paths
- `nesc check` validation for project structure and `NesC.toml`
- Mapper 0 cartridge constraints and zero-page reservation checks
- Rustc-style diagnostics with source spans and suggested corrections
- Initial NES SDK headers for PPU, controller, sprite, audio, and mapper access
- Deterministic formatting, linting, and test gates in CI

## Current status

| Capability | Availability |
| --- | --- |
| Cargo workspace and crate boundaries | Available |
| `nesc new` | Available |
| `nesc check` for project manifests | Available |
| NesC preprocessing and parsing | Planned |
| HIR, MIR, and optimization | Planned |
| 6502 code generation and linking | Planned |
| ROM construction and inspection | Planned |
| Emulator, debugger, and decompiler | Planned |

## Quick start

The repository pins its Rust toolchain in `rust-toolchain.toml`. From the
repository root:

```bash
cargo run -p nesc-cli -- new demo
cd demo
cargo run --manifest-path ../Cargo.toml -p nesc-cli -- check
```

Expected output:

```text
Created `demo` at demo
Checked `demo` v0.1.0 (src/main.c)
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
mappers, invalid NROM capacities, overlapping zero-page ranges, malformed
versions, and invalid stack limits.

## Workspace

The workspace separates frontend, intermediate representation, optimization,
backend, object, linker, ROM, emulator, debugger, and reverse-engineering
concerns. Currently implemented behavior lives in:

| Crate | Responsibility |
| --- | --- |
| `nesc-cli` | Command parsing and user workflows |
| `nesc-project` | Manifest parsing, validation, and project generation |
| `nesc-diagnostics` | Structured source diagnostics |

SDK declarations live under `sdk/include/`.

## Development

Run every quality gate before submitting a change:

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
```

CI runs the same commands on pushes and pull requests.

## Roadmap

1. NesC lexer, parser, and typed syntax tree
2. HIR, control-flow MIR, and verification
3. Safe optimization passes
4. Ricoh 2A03/2A07 code generation
5. Mapper 0 linking and ROM construction
6. Deterministic emulator and debugger
7. Advanced optimization and mapper-aware compilation
8. ROM disassembly and verified NesC/Rust decompilation

## License

Licensed under the [MIT License](LICENSE).

Copyright © 2026 Aleksandr Pavlov &lt;ckidoz@gmail.com&gt;.
