//! Command-line parsing and initial project workflows.

use std::ffi::OsString;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand, ValueEnum};
use nesc_asm::AssemblyLimits;
use nesc_compiler::{BuildArtifacts, CompilerConfig, build_project, check_project};
use nesc_diagnostics::Diagnostic;
use nesc_disasm::{AnalysisLimits, ByteClassification, Disassembly, disassemble};
use nesc_linker::{RecoveryLinkInput, relink_nrom};
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
    /// Recover an NROM image as deterministic 6502 assembly and cartridge data.
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
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum AnalysisKind {
    Recursive,
}

/// Parses and executes a CLI invocation.
#[must_use]
pub fn run<I, T>(args: I, stdout: &mut dyn Write, stderr: &mut dyn Write) -> ExitCode
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

    match execute(cli.command) {
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
    }
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
    let rebuilt = relink_nrom(RecoveryLinkInput {
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
        "mapper: {}\nprg-bytes: {}\ninstructions: {}\ndata-bytes: {data_bytes}\nunresolved-control-flow: {}\nnotices: {}\ntrailing-bytes: {trailing_bytes}\n",
        disassembly.rom.metadata.mapper,
        disassembly.rom.prg_rom.len(),
        disassembly.instructions.len(),
        disassembly.unresolved.len(),
        disassembly.notices.len(),
    );
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
