//! Top-level orchestration for the NesC compilation pipeline.

use std::path::{Path, PathBuf};

use nesc_diagnostics::Diagnostic;
use nesc_frontend::{CheckedProgram, FrontendConfig};
use nesc_project::{Optimization, Project};

/// Compiler settings that are independent of a project manifest.
#[derive(Clone, Debug)]
pub struct CompilerConfig {
    /// SDK header directory.
    pub sdk_include_directory: PathBuf,
    /// Additional include search directories.
    pub include_directories: Vec<PathBuf>,
}

impl CompilerConfig {
    /// Creates compiler settings using an SDK header directory.
    #[must_use]
    pub fn new(sdk_include_directory: impl Into<PathBuf>) -> Self {
        Self {
            sdk_include_directory: sdk_include_directory.into(),
            include_directories: Vec::new(),
        }
    }

    /// Creates settings for the SDK included in this source checkout.
    #[must_use]
    pub fn bundled_sdk() -> Self {
        Self::new(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../..")
                .join("sdk/include"),
        )
    }

    /// Appends a user include search directory.
    #[must_use]
    pub fn with_include_directory(mut self, directory: impl Into<PathBuf>) -> Self {
        self.include_directories.push(directory.into());
        self
    }
}

/// Validated frontend result ready for HIR lowering.
#[derive(Clone, Debug)]
pub struct CheckedProject {
    /// Typed syntax tree and symbol table.
    pub frontend: CheckedProgram,
    /// Stable-ID high-level IR.
    pub hir: nesc_hir::Module,
    /// Verified control-flow IR.
    pub mir: nesc_mir::Module,
    /// Counts from the selected optimization pipeline.
    pub optimization: nesc_opt::OptimizationReport,
}

/// Validates and type-checks a project.
///
/// # Errors
///
/// Returns preprocessing, syntax, or semantic diagnostics.
pub fn check_project(
    project: &Project,
    config: &CompilerConfig,
) -> Result<CheckedProject, Vec<Diagnostic>> {
    let mut frontend = FrontendConfig::new(project.entry_path());
    frontend
        .include_directories
        .extend(config.include_directories.iter().cloned());
    frontend
        .include_directories
        .push(config.sdk_include_directory.clone());
    let frontend = nesc_frontend::check(&frontend)?;
    let hir = nesc_hir::lower(frontend.clone());
    let mut mir = nesc_mir::lower(&hir).map_err(|errors| {
        errors
            .into_iter()
            .map(|error| {
                hir.sources.error(
                    "E2000",
                    error.message,
                    error.span,
                    "could not lower this expression to MIR",
                )
            })
            .collect::<Vec<_>>()
    })?;
    let optimization = if project.manifest().compiler.optimization == Optimization::O0 {
        nesc_opt::OptimizationReport::default()
    } else {
        nesc_opt::optimize(&mut mir)
    };
    nesc_mir::verify(&mir).map_err(|errors| {
        errors
            .into_iter()
            .map(|error| Diagnostic::error("E2001", format!("invalid MIR: {error}")))
            .collect::<Vec<_>>()
    })?;
    Ok(CheckedProject {
        frontend,
        hir,
        mir,
        optimization,
    })
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use nesc_project::{Project, create_project};

    use super::{CompilerConfig, check_project};

    #[test]
    fn checks_generated_project_through_frontend() {
        let temporary = tempdir().expect("temporary directory");
        let project_path = temporary.path().join("demo");
        create_project("demo", &project_path).expect("project");
        let project = Project::load(project_path.join("NesC.toml")).expect("manifest");

        let checked = check_project(&project, &CompilerConfig::bundled_sdk()).expect("frontend");
        assert!(checked.frontend.symbols.contains_key("main"));
        assert!(checked.frontend.symbols.contains_key("nes_wait_frame"));
        assert!(!checked.mir.functions.is_empty());
    }
}
