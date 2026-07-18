//! Command-line parsing and initial project workflows.

use std::ffi::OsString;
use std::io::Write;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
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
        Command::Check { manifest_path } => Project::load(&manifest_path).map(|project| {
            format!(
                "Checked `{}` v{} ({})",
                project.manifest().package.name,
                project.manifest().package.version,
                project.entry_path().display()
            )
        }),
    }
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
