//! Top-level orchestration for the NesC compilation pipeline.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use nesc_diagnostics::Diagnostic;
use nesc_frontend::{CheckedProgram, FrontendConfig};
use nesc_project::{Mirroring, Optimization, Project, Region, RomFormat};

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

/// Complete in-memory build artifacts.
#[derive(Clone, Debug)]
pub struct BuildArtifacts {
    /// Containerized NES ROM bytes.
    pub rom: Vec<u8>,
    /// Symbolic 6502 assembly.
    pub assembly: String,
    /// Section and bank placement report.
    pub map: String,
    /// Global symbol table.
    pub symbols: String,
    /// Source-to-symbol mapping.
    pub source_map: String,
    /// Zero-page storage placement report.
    pub zero_page: String,
    /// Static hardware-stack usage report.
    pub stack: String,
    /// Resolved global addresses for tooling and boot verification.
    pub symbol_addresses: BTreeMap<String, u16>,
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

/// Compiles and links a project into Mapper 0 artifacts.
///
/// # Errors
///
/// Returns frontend, instruction-selection, relocation, or cartridge-layout
/// diagnostics.
pub fn build_project(
    project: &Project,
    config: &CompilerConfig,
) -> Result<BuildArtifacts, Vec<Diagnostic>> {
    let checked = check_project(project, config)?;
    let backend_config = backend_config(project);
    let generated = nesc_codegen_6502::generate_with_config(&checked.mir, &backend_config)
        .map_err(|errors| {
            errors
                .into_iter()
                .map(|error| match error.span {
                    Some(span) => checked.hir.sources.error(
                        "E3000",
                        error.message,
                        span,
                        "cannot select a legal 6502 instruction sequence",
                    ),
                    None => Diagnostic::error("E3000", error.message),
                })
                .collect::<Vec<_>>()
        })?;
    let required_helpers = generated
        .object
        .symbols
        .iter()
        .filter(|symbol| symbol.section.is_none() && symbol.name.starts_with("__nesc_"))
        .map(|symbol| symbol.name.clone())
        .collect::<BTreeSet<_>>();
    let runtime = nesc_runtime::build_for(&required_helpers);
    let link_config = linker_config(project)?;
    let linked = nesc_linker::link(
        &[runtime.object.clone(), generated.object.clone()],
        link_config,
    )
    .map_err(|errors| {
        errors
            .into_iter()
            .map(|error| Diagnostic::error("E3001", error.to_string()))
            .collect::<Vec<_>>()
    })?;
    let symbols = linked
        .symbols
        .iter()
        .map(|(name, address)| format!("{address:04X} {name}\n"))
        .collect::<String>();
    let mut source_map = String::new();
    for function in &checked.hir.functions {
        let Some(address) = linked.symbols.get(&function.name) else {
            continue;
        };
        if let Some(source) = checked.hir.sources.get(function.span.source) {
            source_map.push_str(&format!(
                "{address:04X} {}:{}:{} {}\n",
                source.path().display(),
                function.span.start,
                function.span.len,
                function.name
            ));
        }
    }
    Ok(BuildArtifacts {
        rom: linked.rom,
        assembly: format!("{}\n{}", runtime.assembly, generated.assembly),
        map: linked.map,
        symbols,
        source_map,
        zero_page: generated.zero_page_report,
        stack: generated.stack_report,
        symbol_addresses: linked.symbols,
    })
}

fn backend_config(project: &Project) -> nesc_codegen_6502::BackendConfig {
    let zero_page = &project.manifest().memory.zero_page;
    let ranges = |values: &[String]| {
        values
            .iter()
            .filter_map(|value| nesc_project::parse_zero_page_range(value))
            .map(|(start, end)| nesc_codegen_6502::ZeroPageRange { start, end })
            .collect()
    };
    nesc_codegen_6502::BackendConfig {
        zero_page_available: ranges(&zero_page.available),
        zero_page_reserved: ranges(&zero_page.reserved),
        zero_page_strategy: match zero_page.strategy {
            nesc_project::ZeroPageStrategy::Frequency => {
                nesc_codegen_6502::ZeroPageStrategy::Frequency
            }
            nesc_project::ZeroPageStrategy::Cycles => nesc_codegen_6502::ZeroPageStrategy::Cycles,
        },
        stack_limit: project.manifest().compiler.stack_limit,
    }
}

fn linker_config(project: &Project) -> Result<nesc_linker::LinkConfig, Vec<Diagnostic>> {
    let cartridge = &project.manifest().cartridge;
    let mirroring = match cartridge.mirroring {
        Mirroring::Horizontal => nesc_rom::Mirroring::Horizontal,
        Mirroring::Vertical => nesc_rom::Mirroring::Vertical,
        Mirroring::FourScreen => nesc_rom::Mirroring::FourScreen,
        Mirroring::SingleScreenLower | Mirroring::SingleScreenUpper => {
            return Err(vec![Diagnostic::error(
                "E3002",
                "Mapper 0 does not support single-screen mirroring",
            )]);
        }
    };
    Ok(nesc_linker::LinkConfig {
        format: match project.manifest().build.format {
            RomFormat::Ines => nesc_rom::Format::Ines,
            RomFormat::Nes2 => nesc_rom::Format::Nes2,
        },
        prg_rom_len: cartridge.prg_rom_kib as usize * 1024,
        chr_rom_len: cartridge.chr_rom_kib as usize * 1024,
        mirroring,
        battery: cartridge.battery,
        region: match project.manifest().build.region {
            Region::Ntsc => nesc_rom::Region::Ntsc,
            Region::Pal => nesc_rom::Region::Pal,
            Region::Dendy => nesc_rom::Region::Dendy,
        },
    })
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::tempdir;

    use nesc_project::{Project, create_project};

    use super::{CompilerConfig, build_project, check_project};

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

    #[test]
    fn builds_generated_project_into_nrom() {
        let temporary = tempdir().expect("temporary directory");
        let project_path = temporary.path().join("demo");
        create_project("demo", &project_path).expect("project");
        fs::write(
            project_path.join("src/main.c"),
            r#"#include <nes.h>

static u8 color;

NES_MAIN int main(void) {
    nes_wait_vblank();
    color = 0x21;
    nes_set_background_color(color);
    while (true) {
        nes_wait_frame();
    }
}
"#,
        )
        .expect("milestone source");
        let project = Project::load(project_path.join("NesC.toml")).expect("manifest");

        let artifacts = build_project(&project, &CompilerConfig::bundled_sdk()).expect("build");
        let rom = nesc_rom::parse(&artifacts.rom).expect("parse generated ROM");
        assert_eq!(rom.metadata.mapper, 0);
        assert!(artifacts.symbols.contains("main"));
        assert!(artifacts.assembly.contains("__nesc_reset:"));
        assert!(artifacts.zero_page.contains("Zero-page allocation"));
        assert!(artifacts.stack.contains("Estimated total:"));
        let boot = nesc_emulator::verify_compiler_boot(
            &artifacts.rom,
            &artifacts.symbol_addresses,
            0x21,
            200_000,
        )
        .expect("boot oracle");
        assert_eq!(boot.background_color, 0x21);
        assert!(boot.frames >= 2);
    }

    #[test]
    fn executes_wide_nescall_arithmetic() {
        let temporary = tempdir().expect("temporary directory");
        let project_path = temporary.path().join("wide-call");
        create_project("wide-call", &project_path).expect("project");
        fs::write(
            project_path.join("src/main.c"),
            r#"#include <nes.h>

u16 add_words(u16 left, u16 right) {
    return left + right;
}

NES_MAIN int main(void) {
    u16 total = add_words(0x1201, 0x0033);
    nes_wait_vblank();
    nes_set_background_color((u8)total);
    while (true) {
        nes_wait_frame();
    }
}
"#,
        )
        .expect("wide-call source");
        let project = Project::load(project_path.join("NesC.toml")).expect("manifest");

        let artifacts = build_project(&project, &CompilerConfig::bundled_sdk()).expect("build");
        assert!(artifacts.assembly.contains("adc $"));
        assert!(artifacts.assembly.contains("stx $"));
        let boot = nesc_emulator::verify_compiler_boot(
            &artifacts.rom,
            &artifacts.symbol_addresses,
            0x34,
            200_000,
        )
        .expect("wide nescall boot oracle");
        assert_eq!(boot.background_color, 0x34);
    }
}
