//! Command-line parsing and initial project workflows.

use std::ffi::OsString;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use nesc_compiler::{BuildArtifacts, CompilerConfig, build_project, check_project};
use nesc_diagnostics::Diagnostic;
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
