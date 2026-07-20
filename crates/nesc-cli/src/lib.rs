//! Command-line parsing and initial project workflows.

mod nesc_verification;

use std::ffi::OsString;
use std::fs;
use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};
use std::process::{Command as ProcessCommand, ExitCode};

use clap::{Parser, Subcommand, ValueEnum};
use nesc_asm::AssemblyLimits;
use nesc_compiler::{BuildArtifacts, CompilerConfig, build_project, check_project};
use nesc_debug::{
    DebugRequest, DebugSession, DebugSessionConfig, VerificationView, load_verification,
    render_verification,
};
use nesc_decompiler::{
    AnalysisLimits as DecompilerLimits, ControlFlowLimits, NesCEmissionLimits, NesCEmitConfig,
    RecoveryLimits, RustEmissionLimits, RustEmitConfig, RustVerificationLimits,
    ValueAnalysisLimits, analyze, analyze_recovery, analyze_values, emit_nesc_project,
    emit_rust_project, emit_rust_verification, structure_control_flow,
};
use nesc_diagnostics::Diagnostic;
use nesc_disasm::{AnalysisLimits, ByteClassification, Disassembly, disassemble};
use nesc_linker::{RecoveryLinkInput, relink_recovery};
use nesc_project::{Project, create_project};

/// Top-level command-line arguments.
#[derive(Debug, Parser)]
#[command(name = "nesc", version, about = "NesC compiler and NES ROM toolkit")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Create a new NesC project.
    New {
        /// Project/package name.
        name: String,
        /// Destination directory; defaults to the project name.
        #[arg(long, value_name = "DIRECTORY")]
        path: Option<PathBuf>,
    },
    /// Validate a NesC project without generating code.
    Check {
        /// Path to the project manifest.
        #[arg(long, default_value = "NesC.toml", value_name = "FILE")]
        manifest_path: PathBuf,
    },
    /// Compile and link a NesC project into NES artifacts.
    Build {
        /// Path to the project manifest.
        #[arg(long, default_value = "NesC.toml", value_name = "FILE")]
        manifest_path: PathBuf,
        /// Artifact directory; defaults to `<project>/target`.
        #[arg(long, value_name = "DIRECTORY")]
        target_dir: Option<PathBuf>,
    },
    /// Inspect an iNES or NES 2.0 ROM header.
    Inspect {
        /// ROM file to inspect.
        #[arg(value_name = "ROM")]
        rom: PathBuf,
    },
    /// Recover a Mapper 0 or Mapper 2 image as deterministic 6502 assembly and cartridge data.
    #[command(alias = "disasm")]
    Disassemble {
        /// ROM file to analyze.
        #[arg(value_name = "ROM")]
        rom: PathBuf,
        /// Destination directory; defaults beside the ROM.
        #[arg(long, value_name = "DIRECTORY")]
        output: Option<PathBuf>,
        /// Code discovery strategy.
        #[arg(long, value_enum, default_value_t = AnalysisKind::Recursive)]
        analysis: AnalysisKind,
        /// Verify that decoded instructions and data reproduce every PRG byte.
        #[arg(long)]
        round_trip_check: bool,
        /// Maximum number of instructions accepted from untrusted input.
        #[arg(long, default_value_t = 1_000_000)]
        max_instructions: usize,
        /// Maximum number of control-flow destinations accepted from untrusted input.
        #[arg(long, default_value_t = 100_000)]
        max_work_items: usize,
    },
    /// Translate Mapper 0/2 to host Rust or hybrid NesC.
    Decompile {
        /// ROM file to translate.
        #[arg(value_name = "ROM")]
        rom: PathBuf,
        /// Destination directory; defaults beside the ROM.
        #[arg(long, value_name = "DIRECTORY")]
        output: Option<PathBuf>,
        /// Generated source language.
        #[arg(long, value_enum, default_value_t = DecompileKind::Rust)]
        emit: DecompileKind,
        /// Reject output if any interpreter fallback is required.
        #[arg(long)]
        high_level_only: bool,
        /// Differentially verify generated code against the original 6502 instructions.
        #[arg(long)]
        verify: bool,
        /// Maximum number of instructions accepted from untrusted input.
        #[arg(long, default_value_t = 1_000_000)]
        max_instructions: usize,
        /// Maximum number of control-flow destinations accepted from untrusted input.
        #[arg(long, default_value_t = 100_000)]
        max_work_items: usize,
    },
    /// Debug a ROM or inspect a structured verification artifact.
    Debug {
        /// ROM, verification JSON file, or decompiled project directory.
        #[arg(value_name = "ROM_OR_VERIFICATION")]
        input: PathBuf,
        /// Verification artifact view to render.
        #[arg(long, value_enum)]
        view: Option<DebugViewKind>,
        /// Checkpoint identifier; state views default to the last checkpoint.
        #[arg(long, value_name = "ID")]
        checkpoint: Option<usize>,
        /// Symbol file; defaults to the ROM's sibling `.sym` file.
        #[arg(long, value_name = "FILE")]
        symbols: Option<PathBuf>,
        /// Source-map file; defaults to the ROM's sibling `.source-map` file.
        #[arg(long, value_name = "FILE")]
        source_map: Option<PathBuf>,
        /// Execute a debugger command; may be repeated for scripted sessions.
        #[arg(long = "command", value_name = "COMMAND")]
        commands: Vec<String>,
        /// Maximum instructions executed by one resume command.
        #[arg(long, default_value_t = 1_000_000)]
        instruction_limit: u64,
        /// Maximum CPU cycles executed by one resume command.
        #[arg(long, default_value_t = 10_000_000)]
        cycle_limit: u64,
        /// Explicit timing for a multi-region ROM.
        #[arg(long, value_enum)]
        timing: Option<DebugTimingKind>,
    },
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum AnalysisKind {
    Recursive,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum DecompileKind {
    Nesc,
    Rust,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum DebugViewKind {
    Summary,
    Checkpoints,
    Ppu,
    Apu,
    Cartridge,
    Trace,
    Divergence,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum DebugTimingKind {
    Ntsc,
    Pal,
    Dendy,
}

impl From<DebugTimingKind> for nesc_emulator::TimingProfile {
    fn from(value: DebugTimingKind) -> Self {
        match value {
            DebugTimingKind::Ntsc => Self::Ntsc,
            DebugTimingKind::Pal => Self::Pal,
            DebugTimingKind::Dendy => Self::Dendy,
        }
    }
}

impl From<DebugViewKind> for VerificationView {
    fn from(value: DebugViewKind) -> Self {
        match value {
            DebugViewKind::Summary => Self::Summary,
            DebugViewKind::Checkpoints => Self::Checkpoints,
            DebugViewKind::Ppu => Self::Ppu,
            DebugViewKind::Apu => Self::Apu,
            DebugViewKind::Cartridge => Self::Cartridge,
            DebugViewKind::Trace => Self::Trace,
            DebugViewKind::Divergence => Self::Divergence,
        }
    }
}

/// Parses and executes a CLI invocation.
#[must_use]
pub fn run<I, T>(args: I, stdout: &mut dyn Write, stderr: &mut dyn Write) -> ExitCode
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    run_with_input(args, &mut std::io::empty(), stdout, stderr)
}

/// Parses and executes a CLI invocation with input available to interactive commands.
#[must_use]
pub fn run_with_input<I, T>(
    args: I,
    input: &mut dyn BufRead,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> ExitCode
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    let cli = match Cli::try_parse_from(args) {
        Ok(cli) => cli,
        Err(error) => {
            let _ = write!(stderr, "{error}");
            return ExitCode::from(2);
        }
    };

    let command = match cli.command {
        Command::Debug {
            input: debug_input,
            view,
            checkpoint,
            symbols,
            source_map,
            commands,
            instruction_limit,
            cycle_limit,
            timing,
        } => {
            return run_debug(
                &debug_input,
                view,
                checkpoint,
                symbols,
                source_map,
                &commands,
                instruction_limit,
                cycle_limit,
                timing,
                input,
                stdout,
                stderr,
            );
        }
        command => command,
    };

    match execute(command) {
        Ok(message) => {
            if writeln!(stdout, "{message}").is_err() {
                return ExitCode::FAILURE;
            }
            ExitCode::SUCCESS
        }
        Err(diagnostics) => {
            for diagnostic in diagnostics {
                if write!(stderr, "{}", diagnostic.render()).is_err() {
                    break;
                }
            }
            ExitCode::FAILURE
        }
    }
}

fn execute(command: Command) -> Result<String, Vec<Diagnostic>> {
    match command {
        Command::New { name, path } => {
            let destination = path.unwrap_or_else(|| PathBuf::from(&name));
            create_project(&name, &destination)
                .map(|created| format!("Created `{}` at {}", name, created.display()))
                .map_err(|diagnostic| vec![*diagnostic])
        }
        Command::Check { manifest_path } => {
            let project = Project::load(&manifest_path)?;
            check_project(&project, &CompilerConfig::bundled_sdk())?;
            Ok(format!(
                "Checked `{}` v{} ({})",
                project.manifest().package.name,
                project.manifest().package.version,
                project.entry_path().display()
            ))
        }
        Command::Build {
            manifest_path,
            target_dir,
        } => {
            let project = Project::load(&manifest_path)?;
            let artifacts = build_project(&project, &CompilerConfig::bundled_sdk())?;
            let target = target_dir.unwrap_or_else(|| project.root().join("target"));
            write_artifacts(&target, &project.manifest().package.name, &artifacts)?;
            Ok(format!(
                "Built `{}` at {}",
                project.manifest().package.name,
                target.display()
            ))
        }
        Command::Inspect { rom } => inspect_rom(&rom),
        Command::Disassemble {
            rom,
            output,
            analysis: AnalysisKind::Recursive,
            round_trip_check,
            max_instructions,
            max_work_items,
        } => disassemble_rom_file(
            &rom,
            output.as_deref(),
            round_trip_check,
            AnalysisLimits {
                max_instructions,
                max_work_items,
            },
        ),
        Command::Decompile {
            rom,
            output,
            emit,
            high_level_only,
            verify,
            max_instructions,
            max_work_items,
        } => decompile_rom_file(
            &rom,
            output.as_deref(),
            emit,
            high_level_only,
            verify,
            AnalysisLimits {
                max_instructions,
                max_work_items,
            },
        ),
        Command::Debug { .. } => unreachable!("debug commands are handled before dispatch"),
    }
}

#[allow(clippy::too_many_arguments)]
fn run_debug(
    path: &Path,
    view: Option<DebugViewKind>,
    checkpoint: Option<usize>,
    symbols: Option<PathBuf>,
    source_map: Option<PathBuf>,
    commands: &[String],
    instruction_limit: u64,
    cycle_limit: u64,
    timing: Option<DebugTimingKind>,
    input: &mut dyn BufRead,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> ExitCode {
    if is_rom_path(path) {
        if view.is_some() || checkpoint.is_some() {
            return write_debug_error(
                stderr,
                "E4302",
                "`--view` and `--checkpoint` apply only to verification artifacts",
            );
        }
        let mut session = match DebugSession::load(
            path,
            DebugSessionConfig {
                instruction_limit,
                cycle_limit,
                timing: timing.map(Into::into),
                symbols_path: symbols,
                source_map_path: source_map,
            },
        ) {
            Ok(session) => session,
            Err(error) => return write_debug_error(stderr, "E4302", &error.to_string()),
        };
        if write!(stdout, "{}", session.greeting()).is_err() {
            return ExitCode::FAILURE;
        }
        if commands.is_empty() {
            return run_debug_shell(&mut session, input, stdout, stderr);
        }
        for command in commands {
            match session.execute_command(command) {
                Ok(result) => {
                    if write!(stdout, "{}", result.text).is_err() {
                        return ExitCode::FAILURE;
                    }
                    if result.quit {
                        break;
                    }
                }
                Err(error) => return write_debug_error(stderr, "E4303", &error.to_string()),
            }
        }
        ExitCode::SUCCESS
    } else {
        if symbols.is_some() || source_map.is_some() || !commands.is_empty() || timing.is_some() {
            return write_debug_error(
                stderr,
                "E4300",
                "ROM debugger settings require a `.nes` input",
            );
        }
        match debug_verification(path, view.unwrap_or(DebugViewKind::Summary), checkpoint) {
            Ok(message) => {
                if writeln!(stdout, "{message}").is_err() {
                    ExitCode::FAILURE
                } else {
                    ExitCode::SUCCESS
                }
            }
            Err(diagnostics) => {
                for diagnostic in diagnostics {
                    if write!(stderr, "{}", diagnostic.render()).is_err() {
                        break;
                    }
                }
                ExitCode::FAILURE
            }
        }
    }
}

fn run_debug_shell(
    session: &mut DebugSession,
    input: &mut dyn BufRead,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> ExitCode {
    let mut line = String::new();
    loop {
        if write!(stdout, "nesc-debug> ")
            .and_then(|()| stdout.flush())
            .is_err()
        {
            return ExitCode::FAILURE;
        }
        line.clear();
        match input.read_line(&mut line) {
            Ok(0) => return ExitCode::SUCCESS,
            Ok(_) => match session.execute_command(&line) {
                Ok(result) => {
                    if write!(stdout, "{}", result.text).is_err() {
                        return ExitCode::FAILURE;
                    }
                    if result.quit {
                        return ExitCode::SUCCESS;
                    }
                }
                Err(error) => {
                    let diagnostic = Diagnostic::error("E4303", error.to_string());
                    if write!(stderr, "{}", diagnostic.render()).is_err() {
                        return ExitCode::FAILURE;
                    }
                }
            },
            Err(error) => {
                return write_debug_error(
                    stderr,
                    "E4303",
                    &format!("could not read debugger command: {error}"),
                );
            }
        }
    }
}

fn is_rom_path(path: &Path) -> bool {
    path.extension()
        .is_some_and(|extension| extension.eq_ignore_ascii_case("nes"))
}

fn write_debug_error(stderr: &mut dyn Write, code: &'static str, message: &str) -> ExitCode {
    let diagnostic = Diagnostic::error(code, message);
    let _ = write!(stderr, "{}", diagnostic.render());
    ExitCode::FAILURE
}

fn debug_verification(
    path: &Path,
    view: DebugViewKind,
    checkpoint: Option<usize>,
) -> Result<String, Vec<Diagnostic>> {
    let artifact = load_verification(path)
        .map_err(|error| vec![Diagnostic::error("E4300", error.to_string())])?;
    render_verification(
        &artifact,
        DebugRequest {
            view: view.into(),
            checkpoint,
        },
    )
    .map_err(|error| vec![Diagnostic::error("E4301", error.to_string())])
}

fn write_artifacts(
    target: &Path,
    name: &str,
    artifacts: &BuildArtifacts,
) -> Result<(), Vec<Diagnostic>> {
    fs::create_dir_all(target).map_err(|error| {
        vec![Diagnostic::error(
            "E4000",
            format!(
                "could not create artifact directory `{}`: {error}",
                target.display()
            ),
        )]
    })?;
    for (extension, contents) in [
        ("nes", artifacts.rom.as_slice()),
        ("asm", artifacts.assembly.as_bytes()),
        ("map", artifacts.map.as_bytes()),
        ("sym", artifacts.symbols.as_bytes()),
        ("source-map", artifacts.source_map.as_bytes()),
        ("zero-page", artifacts.zero_page.as_bytes()),
        ("stack", artifacts.stack.as_bytes()),
    ] {
        let path = target.join(format!("{name}.{extension}"));
        fs::write(&path, contents).map_err(|error| {
            vec![Diagnostic::error(
                "E4001",
                format!("could not write artifact `{}`: {error}", path.display()),
            )]
        })?;
    }
    Ok(())
}

fn inspect_rom(path: &Path) -> Result<String, Vec<Diagnostic>> {
    let bytes = fs::read(path).map_err(|error| {
        vec![Diagnostic::error(
            "E4002",
            format!("could not read ROM `{}`: {error}", path.display()),
        )]
    })?;
    let rom = nesc_rom::parse(&bytes)
        .map_err(|error| vec![Diagnostic::error("E4003", error.to_string())])?;
    Ok(format!(
        "{}: {:?}, Mapper {}, submapper {}, {} KiB PRG, {} KiB CHR, {:?}, {:?}",
        path.display(),
        rom.metadata.format,
        rom.metadata.mapper,
        rom.metadata.submapper,
        rom.metadata.prg_rom_len / 1024,
        rom.metadata.chr_rom_len / 1024,
        rom.metadata.mirroring,
        rom.metadata.region
    ))
}

fn disassemble_rom_file(
    path: &Path,
    output: Option<&Path>,
    round_trip_check: bool,
    limits: AnalysisLimits,
) -> Result<String, Vec<Diagnostic>> {
    let bytes = fs::read(path).map_err(|error| {
        vec![Diagnostic::error(
            "E4100",
            format!("could not read ROM `{}`: {error}", path.display()),
        )]
    })?;
    let disassembly = disassemble(&bytes, limits)
        .map_err(|error| vec![Diagnostic::error("E4101", error.to_string())])?;
    if round_trip_check {
        verify_disassembly_round_trip(&bytes, &disassembly)?;
    }
    let destination = output
        .map(Path::to_path_buf)
        .unwrap_or_else(|| default_disassembly_path(path));
    write_disassembly(&destination, &bytes, &disassembly)?;
    Ok(format!(
        "Disassembled `{}` into {} ({} instructions, {} data bytes{})",
        path.display(),
        destination.display(),
        disassembly.instructions.len(),
        disassembly
            .classification
            .iter()
            .filter(|classification| **classification == ByteClassification::Data)
            .count(),
        if round_trip_check {
            ", exact ROM round trip verified"
        } else {
            ""
        }
    ))
}

fn verify_disassembly_round_trip(
    original: &[u8],
    disassembly: &Disassembly,
) -> Result<(), Vec<Diagnostic>> {
    let assembly = disassembly.assembly();
    let rebuilt_prg = nesc_asm::assemble_recovery(
        &assembly,
        disassembly.rom.prg_rom.len(),
        AssemblyLimits::default(),
    )
    .map_err(|error| {
        vec![Diagnostic::error(
            "E4102",
            format!("could not assemble recovered PRG-ROM: {error}"),
        )]
    })?;
    let declared_len = 16
        + disassembly.rom.trainer.as_ref().map_or(0, Vec::len)
        + disassembly.rom.prg_rom.len()
        + disassembly.rom.chr_rom.len();
    let trailing = original.get(declared_len..).ok_or_else(|| {
        vec![Diagnostic::error(
            "E4102",
            "parsed cartridge regions exceed the original ROM file",
        )]
    })?;
    let rebuilt = relink_recovery(RecoveryLinkInput {
        header: &original[..16],
        trainer: disassembly.rom.trainer.as_deref(),
        prg_rom: &rebuilt_prg,
        chr_rom: &disassembly.rom.chr_rom,
        trailing,
    })
    .map_err(|error| {
        vec![Diagnostic::error(
            "E4102",
            format!("could not relink recovered ROM: {error}"),
        )]
    })?;
    disassembly
        .verify_rom_rebuild(original, &rebuilt.rom)
        .map_err(|error| vec![Diagnostic::error("E4102", error.to_string())])
}

fn default_disassembly_path(path: &Path) -> PathBuf {
    let stem = path
        .file_stem()
        .unwrap_or(path.as_os_str())
        .to_string_lossy();
    path.parent()
        .unwrap_or_else(|| Path::new("."))
        .join(format!("{stem}-disassembly"))
}

fn write_disassembly(
    destination: &Path,
    original: &[u8],
    disassembly: &Disassembly,
) -> Result<(), Vec<Diagnostic>> {
    fs::create_dir(destination).map_err(|error| {
        vec![
            Diagnostic::error(
                "E4103",
                format!(
                    "could not create disassembly directory `{}`: {error}",
                    destination.display()
                ),
            )
            .with_help("choose a new directory with `--output`; existing output is never replaced"),
        ]
    })?;

    let declared_len = 16
        + disassembly.rom.trainer.as_ref().map_or(0, Vec::len)
        + disassembly.rom.prg_rom.len()
        + disassembly.rom.chr_rom.len();
    let assembly = disassembly.assembly();
    let cartridge_manifest = disassembly.cartridge_manifest();
    let mut artifacts: Vec<(&str, &[u8])> = vec![
        ("header.bin", &original[..16]),
        ("prg.asm", assembly.as_bytes()),
        ("cartridge.toml", cartridge_manifest.as_bytes()),
    ];
    if let Some(trainer) = &disassembly.rom.trainer {
        artifacts.push(("trainer.bin", trainer));
    }
    if !disassembly.rom.chr_rom.is_empty() {
        artifacts.push(("chr.bin", &disassembly.rom.chr_rom));
    }
    if original.len() > declared_len {
        artifacts.push(("trailing.bin", &original[declared_len..]));
    }

    let analysis = render_analysis_report(disassembly, original.len().saturating_sub(declared_len));
    artifacts.push(("analysis.txt", analysis.as_bytes()));
    for (name, contents) in artifacts {
        let artifact = destination.join(name);
        fs::write(&artifact, contents).map_err(|error| {
            vec![Diagnostic::error(
                "E4104",
                format!("could not write artifact `{}`: {error}", artifact.display()),
            )]
        })?;
    }
    Ok(())
}

fn render_analysis_report(disassembly: &Disassembly, trailing_bytes: usize) -> String {
    let data_bytes = disassembly
        .classification
        .iter()
        .filter(|classification| **classification == ByteClassification::Data)
        .count();
    let mut report = format!(
        "mapper: {}\nprg-bytes: {}\ninstructions: {}\ndata-bytes: {data_bytes}\nmapper-writes: {}\nunresolved-control-flow: {}\nnotices: {}\ntrailing-bytes: {trailing_bytes}\n",
        disassembly.rom.metadata.mapper,
        disassembly.rom.prg_rom.len(),
        disassembly.instructions.len(),
        disassembly.mapper_writes.len(),
        disassembly.unresolved.len(),
        disassembly.notices.len(),
    );
    for write in &disassembly.mapper_writes {
        report.push_str(&format!(
            "mapper-write: prg:{:02X}:${:04X} address={} value={} resulting-bank={}\n",
            write.source.bank,
            write.source.cpu_address,
            write
                .register_address
                .map_or_else(|| "unknown".to_owned(), |value| format!("${value:04X}")),
            write
                .value
                .map_or_else(|| "unknown".to_owned(), |value| format!("${value:02X}")),
            write
                .resulting_bank
                .map_or_else(|| "unknown".to_owned(), |value| format!("{value:02X}")),
        ));
    }
    for unresolved in &disassembly.unresolved {
        report.push_str(&format!(
            "unresolved: prg:{:02X}:${:04X} {:?} ${:04X}\n",
            unresolved.source.bank,
            unresolved.source.cpu_address,
            unresolved.flow,
            unresolved.target
        ));
    }
    for notice in &disassembly.notices {
        report.push_str("notice: ");
        report.push_str(&notice.message);
        report.push('\n');
    }
    report
}

fn decompile_rom_file(
    path: &Path,
    output: Option<&Path>,
    emit: DecompileKind,
    high_level_only: bool,
    verify: bool,
    limits: AnalysisLimits,
) -> Result<String, Vec<Diagnostic>> {
    let bytes = fs::read(path).map_err(|error| {
        vec![Diagnostic::error(
            "E4200",
            format!("could not read ROM `{}`: {error}", path.display()),
        )]
    })?;
    let disassembly = disassemble(&bytes, limits)
        .map_err(|error| vec![Diagnostic::error("E4201", error.to_string())])?;
    let program = analyze(&disassembly, DecompilerLimits::default())
        .map_err(|errors| decompiler_diagnostics("E4202", "semantic analysis", errors))?;
    let values = analyze_values(&program, ValueAnalysisLimits::default())
        .map_err(|errors| decompiler_diagnostics("E4203", "value analysis", errors))?;
    let recovery = analyze_recovery(&program, &values, RecoveryLimits::default())
        .map_err(|errors| decompiler_diagnostics("E4204", "function recovery", errors))?;
    let control =
        structure_control_flow(&program, &values, &recovery, ControlFlowLimits::default())
            .map_err(|errors| {
                decompiler_diagnostics("E4205", "control-flow structuring", errors)
            })?;
    let crate_name = decompiled_crate_name(path);
    let destination = output
        .map(Path::to_path_buf)
        .unwrap_or_else(|| default_decompilation_path(path, emit));
    let fallback_count = control
        .functions
        .iter()
        .flat_map(|function| &function.regions)
        .filter(|region| {
            matches!(
                region.kind,
                nesc_decompiler::StructuredRegionKind::Fallback { .. }
            )
        })
        .count();
    match emit {
        DecompileKind::Rust => {
            let runtime_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../nesc-decompile-runtime")
                .canonicalize()
                .map_err(|error| {
                    vec![Diagnostic::error(
                        "E4206",
                        format!("could not locate decompilation runtime: {error}"),
                    )]
                })?;
            let generated = emit_rust_project(
                &program,
                &values,
                &recovery,
                &control,
                &RustEmitConfig {
                    crate_name: crate_name.clone(),
                    runtime_path: runtime_path.to_string_lossy().into_owned(),
                    high_level_only,
                    max_fallback_call_depth: 256,
                },
                RustEmissionLimits::default(),
            )
            .map_err(|errors| decompiler_diagnostics("E4206", "Rust emission", errors))?;
            let verification = verify
                .then(|| {
                    emit_rust_verification(
                        &program,
                        &disassembly.rom.prg_rom,
                        &crate_name,
                        RustVerificationLimits {
                            instruction_limit: limits.max_instructions as u64,
                            ..RustVerificationLimits::default()
                        },
                    )
                })
                .transpose()
                .map_err(|errors| {
                    decompiler_diagnostics("E4209", "Rust verification generation", errors)
                })?;
            write_rust_project(&destination, &generated, verification.as_deref())?;
            if verify {
                run_rust_verification(
                    &destination,
                    program.functions.len(),
                    limits.max_instructions as u64,
                    program.mapper,
                    disassembly.rom.prg_rom.len() / (16 * 1024),
                )?;
            }
            Ok(format!(
                "Decompiled `{}` into {} as host-side stable Rust ({} functions, {} fallbacks{})",
                path.display(),
                destination.display(),
                program.functions.len(),
                fallback_count,
                if verify { ", verified" } else { "" }
            ))
        }
        DecompileKind::Nesc => {
            let generated = emit_nesc_project(
                &disassembly,
                &program,
                &values,
                &recovery,
                &control,
                &NesCEmitConfig {
                    package_name: crate_name,
                    high_level_only,
                    verification: verify,
                    fallback_instruction_limit: u16::try_from(
                        limits.max_instructions.min(usize::from(u16::MAX)),
                    )
                    .expect("bounded NesC instruction limit fits in u16"),
                    max_fallback_call_depth: u8::MAX,
                },
                NesCEmissionLimits::default(),
            )
            .map_err(|errors| decompiler_diagnostics("E4211", "NesC emission", errors))?;
            write_nesc_project(&destination, &generated)?;
            let verification = if verify {
                let project = Project::load(destination.join("NesC.toml"))?;
                let artifacts = build_project(&project, &CompilerConfig::bundled_sdk())?;
                let target = destination.join("target");
                write_artifacts(&target, &project.manifest().package.name, &artifacts)?;
                match nesc_verification::verify(
                    &bytes,
                    &artifacts,
                    &program,
                    limits.max_instructions as u64,
                ) {
                    Ok(report) => {
                        write_nesc_verification(&destination, &report.artifact)?;
                        Some(report.executions)
                    }
                    Err(failure) => {
                        write_nesc_verification(&destination, &failure.artifact)?;
                        return Err(vec![Diagnostic::error(
                            "E4212",
                            format!(
                                "generated NesC failed differential verification: {}",
                                failure.message
                            ),
                        )]);
                    }
                }
            } else {
                None
            };
            Ok(format!(
                "Decompiled `{}` into {} as hybrid NesC ({} functions, {} fallbacks{})",
                path.display(),
                destination.display(),
                program.functions.len(),
                fallback_count,
                verification.map_or_else(String::new, |executions| {
                    format!(", verified with {executions} executions")
                })
            ))
        }
    }
}

fn write_nesc_verification(
    destination: &Path,
    artifact: &nesc_debug::VerificationArtifact,
) -> Result<(), Vec<Diagnostic>> {
    let path = destination.join("verification.json");
    let json = artifact.to_json().map_err(|error| {
        vec![Diagnostic::error(
            "E4212",
            format!("could not serialize NesC verification report: {error}"),
        )]
    })?;
    fs::write(&path, json).map_err(|error| {
        vec![Diagnostic::error(
            "E4212",
            format!(
                "could not write NesC verification report `{}`: {error}",
                path.display()
            ),
        )]
    })
}

fn decompiler_diagnostics(
    code: &'static str,
    context: &str,
    errors: Vec<nesc_decompiler::AnalysisError>,
) -> Vec<Diagnostic> {
    errors
        .into_iter()
        .map(|error| Diagnostic::error(code, format!("{context}: {error}")))
        .collect()
}

fn default_decompilation_path(path: &Path, emit: DecompileKind) -> PathBuf {
    let stem = path
        .file_stem()
        .unwrap_or(path.as_os_str())
        .to_string_lossy();
    path.parent()
        .unwrap_or_else(|| Path::new("."))
        .join(format!(
            "{stem}-{}",
            match emit {
                DecompileKind::Nesc => "nesc",
                DecompileKind::Rust => "rust",
            }
        ))
}

fn decompiled_crate_name(path: &Path) -> String {
    let stem = path
        .file_stem()
        .unwrap_or(path.as_os_str())
        .to_string_lossy();
    let normalized = stem
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() {
                character.to_ascii_lowercase()
            } else {
                '_'
            }
        })
        .collect::<String>();
    let normalized = normalized.trim_matches('_');
    if normalized.is_empty() || !normalized.starts_with(char::is_alphabetic) {
        "decompiled_rom".to_owned()
    } else {
        format!("decompiled_{normalized}")
    }
}

fn write_rust_project(
    destination: &Path,
    project: &nesc_decompiler::RustProject,
    verification: Option<&str>,
) -> Result<(), Vec<Diagnostic>> {
    fs::create_dir(destination).map_err(|error| {
        vec![
            Diagnostic::error(
                "E4207",
                format!(
                    "could not create decompilation directory `{}`: {error}",
                    destination.display()
                ),
            )
            .with_help("choose a new directory with `--output`; existing output is never replaced"),
        ]
    })?;
    let source_directory = destination.join("src");
    fs::create_dir(&source_directory).map_err(|error| {
        vec![Diagnostic::error(
            "E4208",
            format!(
                "could not create source directory `{}`: {error}",
                source_directory.display()
            ),
        )]
    })?;
    for (path, contents) in [
        (destination.join("Cargo.toml"), project.cargo_toml.as_str()),
        (source_directory.join("lib.rs"), project.source.as_str()),
        (
            destination.join("decompilation.json"),
            project.report_json.as_str(),
        ),
    ] {
        fs::write(&path, contents).map_err(|error| {
            vec![Diagnostic::error(
                "E4208",
                format!("could not write artifact `{}`: {error}", path.display()),
            )]
        })?;
    }
    if let Some(verification) = verification {
        let tests_directory = destination.join("tests");
        fs::create_dir(&tests_directory).map_err(|error| {
            vec![Diagnostic::error(
                "E4208",
                format!(
                    "could not create verification directory `{}`: {error}",
                    tests_directory.display()
                ),
            )]
        })?;
        let path = tests_directory.join("decompilation_verification.rs");
        fs::write(&path, verification).map_err(|error| {
            vec![Diagnostic::error(
                "E4208",
                format!("could not write artifact `{}`: {error}", path.display()),
            )]
        })?;
    }
    Ok(())
}

fn write_nesc_project(
    destination: &Path,
    project: &nesc_decompiler::NesCProject,
) -> Result<(), Vec<Diagnostic>> {
    fs::create_dir(destination).map_err(|error| {
        vec![
            Diagnostic::error(
                "E4207",
                format!(
                    "could not create decompilation directory `{}`: {error}",
                    destination.display()
                ),
            )
            .with_help("choose a new directory with `--output`; existing output is never replaced"),
        ]
    })?;
    let source_directory = destination.join("src");
    fs::create_dir(&source_directory).map_err(|error| {
        vec![Diagnostic::error(
            "E4208",
            format!(
                "could not create source directory `{}`: {error}",
                source_directory.display()
            ),
        )]
    })?;
    for (path, contents) in [
        (destination.join("NesC.toml"), project.manifest.as_str()),
        (source_directory.join("main.c"), project.source.as_str()),
        (
            destination.join("decompilation.json"),
            project.report_json.as_str(),
        ),
    ] {
        fs::write(&path, contents).map_err(|error| {
            vec![Diagnostic::error(
                "E4208",
                format!("could not write artifact `{}`: {error}", path.display()),
            )]
        })?;
    }
    Ok(())
}

fn run_rust_verification(
    destination: &Path,
    function_count: usize,
    instruction_limit: u64,
    mapper: u16,
    prg_bank_count: usize,
) -> Result<(), Vec<Diagnostic>> {
    let output = ProcessCommand::new("cargo")
        .arg("test")
        .arg("--offline")
        .arg("--quiet")
        .arg("--manifest-path")
        .arg(destination.join("Cargo.toml"))
        .env("CARGO_TARGET_DIR", destination.join("target/verification"))
        .env("RUSTFLAGS", "-D warnings")
        .output()
        .map_err(|error| {
            vec![Diagnostic::error(
                "E4209",
                format!("could not start generated Rust verification: {error}"),
            )]
        })?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        let details = if stderr.trim().is_empty() {
            stdout.trim()
        } else {
            stderr.trim()
        };
        let details = details.chars().take(8_192).collect::<String>();
        return Err(vec![Diagnostic::error(
            "E4209",
            format!("generated Rust failed differential verification: {details}"),
        )]);
    }
    let switchable_bank_contexts = if mapper == 2 {
        prg_bank_count.saturating_sub(1)
    } else {
        1
    };
    let report = format!(
        "{{\n  \"schema_version\": 1,\n  \"mode\": \"original-6502-vs-rust\",\n  \"status\": \"passed\",\n  \"mapper\": {mapper},\n  \"prg_banks\": {prg_bank_count},\n  \"functions\": {function_count},\n  \"input_patterns_per_bank_context\": 4,\n  \"switchable_bank_contexts\": {switchable_bank_contexts},\n  \"instruction_limit_per_execution\": {instruction_limit}\n}}\n"
    );
    let path = destination.join("verification.json");
    fs::write(&path, report).map_err(|error| {
        vec![Diagnostic::error(
            "E4209",
            format!(
                "could not write verification report `{}`: {error}",
                path.display()
            ),
        )]
    })
}

#[cfg(test)]
mod tests {
    use std::process::ExitCode;

    use super::run;

    #[test]
    fn clap_errors_use_exit_code_two() {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let status = run(["nesc", "unknown"], &mut stdout, &mut stderr);

        assert_eq!(status, ExitCode::from(2));
        assert!(stdout.is_empty());
        assert!(
            String::from_utf8(stderr)
                .expect("UTF-8")
                .contains("unrecognized subcommand")
        );
    }
}
