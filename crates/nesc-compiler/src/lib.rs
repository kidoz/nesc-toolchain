//! Top-level orchestration for the NesC compilation pipeline.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use nesc_diagnostics::{Diagnostic, SourceFile, Span};
use nesc_frontend::{CheckedProgram, FrontendConfig};
use nesc_project::{BoundsChecks, Mirroring, Optimization, Project, Region, RomFormat};

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
    /// Validated standalone assembly modules.
    pub assembly: Vec<CheckedAssembly>,
}

/// One validated standalone assembly input.
#[derive(Clone, Debug)]
pub struct CheckedAssembly {
    /// Source path used by diagnostics and source maps.
    pub path: PathBuf,
    /// Original source retained for symbolic assembly artifacts.
    pub source: String,
    /// Relocatable object and stack contracts.
    pub module: nesc_asm::AssemblyModule,
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
    /// MIR transformation counts and backend sequence decisions.
    pub optimization: String,
    /// Resolved global addresses for tooling and boot verification.
    pub symbol_addresses: BTreeMap<String, u16>,
}

/// One source-backed test discovered from a reserved `NES_TEST` definition.
#[derive(Clone, Debug)]
pub struct TestDefinition {
    /// Human-readable test name.
    pub name: String,
    /// Generated linker-visible entry symbol.
    pub symbol: String,
    /// Per-test cycle limit declared with `NES_CYCLE_BUDGET`.
    pub cycle_budget: Option<u64>,
    /// Owned source used for failure diagnostics.
    pub source: SourceFile,
    /// Complete test definition range.
    pub span: Span,
}

/// One independently linked test ROM and its discovery metadata.
#[derive(Clone, Debug)]
pub struct BuiltTest {
    pub definition: TestDefinition,
    pub artifacts: BuildArtifacts,
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
    check_project_with_mode(project, config, false)
}

fn check_project_with_mode(
    project: &Project,
    config: &CompilerConfig,
    test_mode: bool,
) -> Result<CheckedProject, Vec<Diagnostic>> {
    let mut frontend = FrontendConfig::new(project.entry_path());
    frontend.test_mode = test_mode;
    frontend
        .include_directories
        .extend(config.include_directories.iter().cloned());
    frontend
        .include_directories
        .push(config.sdk_include_directory.clone());
    let frontend = nesc_frontend::check(&frontend)?;
    let hir = nesc_hir::lower(frontend.clone());
    let bounds_checks = match project.manifest().compiler.bounds_checks {
        BoundsChecks::Off => nesc_mir::BoundsChecks::Off,
        BoundsChecks::Trap => nesc_mir::BoundsChecks::Trap,
        BoundsChecks::ElideProven => nesc_mir::BoundsChecks::ElideProven,
    };
    let mut mir = nesc_mir::lower_with_config(&hir, nesc_mir::LoweringConfig { bounds_checks })
        .map_err(|errors| {
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
    let profile = match project.manifest().compiler.optimization {
        Optimization::O0 => nesc_opt::OptimizationProfile::O0,
        Optimization::O1 => nesc_opt::OptimizationProfile::O1,
        Optimization::O2 => nesc_opt::OptimizationProfile::O2,
        Optimization::Size => nesc_opt::OptimizationProfile::Size,
        Optimization::MinSize => nesc_opt::OptimizationProfile::MinSize,
        Optimization::Cycles => nesc_opt::OptimizationProfile::Cycles,
    };
    let optimization = nesc_opt::optimize_with_profile(&mut mir, profile);
    nesc_mir::verify(&mir).map_err(|errors| {
        errors
            .into_iter()
            .map(|error| Diagnostic::error("E2001", format!("invalid MIR: {error}")))
            .collect::<Vec<_>>()
    })?;
    let assembly = check_assembly_modules(project, &hir)?;
    Ok(CheckedProject {
        frontend,
        hir,
        mir,
        optimization,
        assembly,
    })
}

fn check_assembly_modules(
    project: &Project,
    hir: &nesc_hir::Module,
) -> Result<Vec<CheckedAssembly>, Vec<Diagnostic>> {
    let mut checked = Vec::new();
    let mut diagnostics = Vec::new();
    for path in project.assembly_paths() {
        let source = match std::fs::read_to_string(&path) {
            Ok(source) => source,
            Err(error) => {
                diagnostics.push(Diagnostic::error(
                    "E2100",
                    format!(
                        "could not read assembly source `{}`: {error}",
                        path.display()
                    ),
                ));
                continue;
            }
        };
        let module_name = path
            .file_stem()
            .and_then(|name| name.to_str())
            .unwrap_or("assembly");
        let module = match nesc_asm::assemble_module(
            &source,
            module_name,
            nesc_asm::AssemblyLimits::default(),
        ) {
            Ok(module) => module,
            Err(error) => {
                diagnostics.push(assembly_diagnostic(&path, &source, &error));
                continue;
            }
        };
        validate_assembly_abi(&path, &source, &module, hir, &mut diagnostics);
        checked.push(CheckedAssembly {
            path,
            source,
            module,
        });
    }
    if diagnostics.is_empty() {
        Ok(checked)
    } else {
        Err(diagnostics)
    }
}

fn validate_assembly_abi(
    path: &Path,
    source: &str,
    module: &nesc_asm::AssemblyModule,
    hir: &nesc_hir::Module,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let assembly_placement = module
        .object
        .sections
        .first()
        .map(|section| section.placement)
        .unwrap_or(nesc_object::SectionPlacement::Any);
    for exported in &module.exports {
        match hir
            .function_names
            .get(&exported.name)
            .and_then(|id| hir.function(*id))
        {
            Some(function)
                if function.body.is_none() && function.linkage == nesc_hir::Linkage::External =>
            {
                let declared_placement = function
                    .attributes
                    .iter()
                    .find_map(|attribute| match attribute.name.as_str() {
                        "fixed_bank" => Some(nesc_object::SectionPlacement::Fixed),
                        "bank" => attribute.arguments.first().and_then(|argument| {
                            if let nesc_hir::ExpressionKind::Integer(literal) = &argument.kind {
                                u16::try_from(literal.value)
                                    .ok()
                                    .map(nesc_object::SectionPlacement::Bank)
                            } else {
                                None
                            }
                        }),
                        _ => None,
                    })
                    .unwrap_or(nesc_object::SectionPlacement::Fixed);
                let effective_assembly_placement = match assembly_placement {
                    nesc_object::SectionPlacement::Any => nesc_object::SectionPlacement::Fixed,
                    placement => placement,
                };
                if effective_assembly_placement != declared_placement {
                    diagnostics.push(assembly_source_diagnostic(
                        path,
                        source,
                        exported.line,
                        "E2103",
                        format!(
                            "assembly export `{}` does not match its NesC bank declaration",
                            exported.name
                        ),
                        "bank placement mismatch",
                    ));
                }
            }
            Some(_) => diagnostics.push(assembly_source_diagnostic(
                path,
                source,
                exported.line,
                "E2101",
                format!(
                    "assembly export `{}` requires a matching `extern` NesC declaration",
                    exported.name
                ),
                "conflicting NesC definition or linkage",
            )),
            None => diagnostics.push(assembly_source_diagnostic(
                path,
                source,
                exported.line,
                "E2101",
                format!(
                    "assembly export `{}` has no matching NesC declaration",
                    exported.name
                ),
                "declare this function with `extern` in NesC",
            )),
        }
    }
    for imported in &module.imports {
        match hir
            .function_names
            .get(&imported.name)
            .and_then(|id| hir.function(*id))
        {
            Some(function)
                if function.body.is_none()
                    || function
                        .attributes
                        .iter()
                        .any(|attribute| attribute.name == "export") => {}
            Some(_) => diagnostics.push(assembly_source_diagnostic(
                path,
                source,
                imported.line,
                "E2102",
                format!(
                    "assembly import `{}` refers to a NesC definition without `NES_EXPORT`",
                    imported.name
                ),
                "add `NES_EXPORT` to the NesC definition",
            )),
            None => diagnostics.push(assembly_source_diagnostic(
                path,
                source,
                imported.line,
                "E2102",
                format!(
                    "assembly import `{}` has no matching NesC function declaration",
                    imported.name
                ),
                "declare the imported function in NesC",
            )),
        }
    }
}

fn assembly_diagnostic(path: &Path, source: &str, error: &nesc_asm::AssemblyError) -> Diagnostic {
    error.line().map_or_else(
        || {
            Diagnostic::error(
                "E2100",
                format!("invalid assembly module: {}", error.message()),
            )
        },
        |line| {
            assembly_source_diagnostic(
                path,
                source,
                line,
                "E2100",
                format!("invalid assembly module: {}", error.message()),
                "assembly error",
            )
        },
    )
}

fn assembly_source_diagnostic(
    path: &Path,
    source: &str,
    line: usize,
    code: &str,
    message: impl Into<String>,
    label: &str,
) -> Diagnostic {
    let (start, len) = line_span(source, line);
    Diagnostic::error(code, message).with_source(
        SourceFile::new(path, source),
        Span::new(start, len),
        label,
    )
}

fn line_span(source: &str, line: usize) -> (usize, usize) {
    let mut start = 0;
    for (index, text) in source.split_inclusive('\n').enumerate() {
        if index + 1 == line {
            return (start, text.trim_end_matches('\n').len().max(1));
        }
        start += text.len();
    }
    (
        source.len().saturating_sub(1),
        usize::from(!source.is_empty()),
    )
}

/// Compiles and links a project into supported NES cartridge artifacts.
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
    build_checked_project(project, &checked, "main", false)
}

/// Discovers, compiles, and independently links every `NES_TEST` definition.
///
/// # Errors
///
/// Returns frontend, instruction-selection, relocation, cartridge-layout, or missing-test
/// diagnostics.
pub fn build_tests(
    project: &Project,
    config: &CompilerConfig,
) -> Result<Vec<BuiltTest>, Vec<Diagnostic>> {
    let checked = check_project_with_mode(project, config, true)?;
    let definitions = checked
        .hir
        .functions
        .iter()
        .filter_map(|function| {
            let test = function.test.as_ref()?;
            let source = checked.hir.sources.get(function.span.source)?;
            let cycle_budget = function
                .attributes
                .iter()
                .find(|attribute| attribute.name == "cycle_budget")
                .and_then(|attribute| attribute.arguments.first())
                .and_then(|argument| match &argument.kind {
                    nesc_hir::ExpressionKind::Integer(literal) => Some(literal.value),
                    _ => None,
                });
            Some(TestDefinition {
                name: test.name.clone(),
                symbol: function.name.clone(),
                cycle_budget,
                source: SourceFile::new(source.path(), source.text()),
                span: Span::new(function.span.start, function.span.len),
            })
        })
        .collect::<Vec<_>>();
    if definitions.is_empty() {
        return Err(vec![
            Diagnostic::error("E2200", "project contains no `NES_TEST` definitions")
                .with_help("add `NES_TEST(\"name\") { ... }` to the project entry source"),
        ]);
    }
    definitions
        .into_iter()
        .map(|definition| {
            let artifacts = build_checked_project(project, &checked, &definition.symbol, true)?;
            Ok(BuiltTest {
                definition,
                artifacts,
            })
        })
        .collect()
}

fn build_checked_project(
    project: &Project,
    checked: &CheckedProject,
    entry: &str,
    test_runtime: bool,
) -> Result<BuildArtifacts, Vec<Diagnostic>> {
    let external_stack_bytes = assembly_stack_contracts(&checked.assembly)?;
    let backend_config = backend_config(project, external_stack_bytes);
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
    let runtime = if test_runtime {
        nesc_runtime::build_for_test(&required_helpers, entry)
    } else {
        nesc_runtime::build_for(&required_helpers)
    };
    let link_config = linker_config(project)?;
    let chr = load_chr_asset(project)?;
    let mut objects = Vec::with_capacity(checked.assembly.len() + 2);
    objects.push(runtime.object.clone());
    objects.extend(
        checked
            .assembly
            .iter()
            .map(|assembly| assembly.module.object.clone()),
    );
    objects.push(generated.object.clone());
    let linked = nesc_linker::link_with_chr(&objects, link_config, &chr).map_err(|errors| {
        errors
            .into_iter()
            .map(|error| Diagnostic::error("E3001", error.to_string()))
            .collect::<Vec<_>>()
    })?;
    let banked_symbols = project.manifest().cartridge.mapper == 2;
    let symbols = linked
        .symbols
        .iter()
        .map(|(name, address)| {
            if banked_symbols {
                format!("{:03}:{address:04X} {name}\n", linked.symbol_banks[name])
            } else {
                format!("{address:04X} {name}\n")
            }
        })
        .collect::<String>();
    let mut source_map = String::new();
    for function in &checked.hir.functions {
        let Some(address) = linked.symbols.get(&function.name) else {
            continue;
        };
        if let Some(source) = checked.hir.sources.get(function.span.source) {
            let location = if banked_symbols {
                format!("{:03}:{address:04X}", linked.symbol_banks[&function.name])
            } else {
                format!("{address:04X}")
            };
            source_map.push_str(&format!(
                "{location} {}:{}:{} {}\n",
                source.path().display(),
                function.span.start,
                function.span.len,
                function.name
            ));
        }
    }
    for assembly in &checked.assembly {
        for exported in &assembly.module.exports {
            let Some(address) = linked.symbols.get(&exported.name) else {
                continue;
            };
            let location = if banked_symbols {
                format!("{:03}:{address:04X}", linked.symbol_banks[&exported.name])
            } else {
                format!("{address:04X}")
            };
            source_map.push_str(&format!(
                "{location} {}:{}:1 {}\n",
                assembly.path.display(),
                exported.line,
                exported.name
            ));
        }
    }
    let assembly_sources = checked
        .assembly
        .iter()
        .map(|assembly| {
            format!(
                "\n; standalone module {}\n{}",
                assembly.path.display(),
                assembly.source
            )
        })
        .collect::<String>();
    Ok(BuildArtifacts {
        rom: linked.rom,
        assembly: format!(
            "{}{}\n{}",
            runtime.assembly, assembly_sources, generated.assembly
        ),
        map: linked.map,
        symbols,
        source_map,
        zero_page: generated.zero_page_report,
        stack: generated.stack_report,
        optimization: format!(
            "Optimization: {}\nFunctions analyzed: {}\nNatural loops: {}\nMaximum loop depth: {}\nConstants folded: {}\nConstants propagated: {}\nBranches simplified: {}\nInstructions removed: {}\n\n{}",
            checked.optimization.profile.name(),
            checked.optimization.functions_analyzed,
            checked.optimization.natural_loops,
            checked.optimization.maximum_loop_depth,
            checked.optimization.constants_folded,
            checked.optimization.constants_propagated,
            checked.optimization.branches_simplified,
            checked.optimization.instructions_removed,
            generated.optimization_report,
        ),
        symbol_addresses: linked.symbols,
    })
}

fn assembly_stack_contracts(
    assembly: &[CheckedAssembly],
) -> Result<BTreeMap<String, u16>, Vec<Diagnostic>> {
    let mut contracts = BTreeMap::new();
    let mut diagnostics = Vec::new();
    for input in assembly {
        for (name, bytes) in &input.module.stack_bytes {
            if contracts.insert(name.clone(), *bytes).is_some() {
                diagnostics.push(Diagnostic::error(
                    "E2103",
                    format!("assembly function `{name}` is exported by more than one module"),
                ));
            }
        }
    }
    if diagnostics.is_empty() {
        Ok(contracts)
    } else {
        Err(diagnostics)
    }
}

fn backend_config(
    project: &Project,
    external_stack_bytes: BTreeMap<String, u16>,
) -> nesc_codegen_6502::BackendConfig {
    let zero_page = &project.manifest().memory.zero_page;
    let ranges = |values: &[String]| {
        values
            .iter()
            .filter_map(|value| nesc_project::parse_zero_page_range(value))
            .map(|(start, end)| nesc_codegen_6502::ZeroPageRange { start, end })
            .collect()
    };
    nesc_codegen_6502::BackendConfig {
        goal: match project.manifest().compiler.optimization {
            Optimization::Size => nesc_codegen_6502::CodegenGoal::Size,
            Optimization::MinSize => nesc_codegen_6502::CodegenGoal::MinSize,
            Optimization::Cycles => nesc_codegen_6502::CodegenGoal::Cycles,
            Optimization::O0 | Optimization::O1 | Optimization::O2 => {
                nesc_codegen_6502::CodegenGoal::Balanced
            }
        },
        zero_page_available: ranges(&zero_page.available),
        zero_page_reserved: ranges(&zero_page.reserved),
        zero_page_strategy: match zero_page.strategy {
            nesc_project::ZeroPageStrategy::Frequency => {
                nesc_codegen_6502::ZeroPageStrategy::Frequency
            }
            nesc_project::ZeroPageStrategy::Cycles => nesc_codegen_6502::ZeroPageStrategy::Cycles,
        },
        stack_limit: project.manifest().compiler.stack_limit,
        external_stack_bytes,
    }
}

/// Loads the raw planar 2bpp CHR payload declared by `assets.chr`.
///
/// Returns an empty payload when the manifest declares no CHR asset.
fn load_chr_asset(project: &Project) -> Result<Vec<u8>, Vec<Diagnostic>> {
    let Some(path) = &project.manifest().assets.chr else {
        return Ok(Vec::new());
    };
    let full_path = project.root().join(path);
    let bytes = std::fs::read(&full_path).map_err(|error| {
        vec![
            Diagnostic::error(
                "E3003",
                format!("cannot read CHR asset `{}`: {error}", full_path.display()),
            )
            .with_help("check the `assets.chr` path in NesC.toml"),
        ]
    })?;
    let capacity = project.manifest().cartridge.chr_rom_kib as usize * 1024;
    if bytes.is_empty() || bytes.len() % 16 != 0 || bytes.len() > capacity {
        return Err(vec![
            Diagnostic::error(
                "E3004",
                format!(
                    "CHR asset `{}` is {} bytes; expected non-empty whole 16-byte tiles \
                     within the {capacity}-byte CHR-ROM capacity",
                    path.display(),
                    bytes.len()
                ),
            )
            .with_help("pad or trim the tile data, or raise `cartridge.chr-rom-kib`"),
        ]);
    }
    Ok(bytes)
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
                format!(
                    "Mapper {} does not support single-screen mirroring",
                    cartridge.mapper
                ),
            )]);
        }
    };
    Ok(nesc_linker::LinkConfig {
        mapper: cartridge.mapper,
        submapper: cartridge.submapper,
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

    use super::{CompilerConfig, build_project, build_tests, check_project};

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
    fn builds_and_executes_a_cross_bank_uxrom_call() {
        let temporary = tempdir().expect("temporary directory");
        let project_path = temporary.path().join("uxrom-call");
        create_project("uxrom-call", &project_path).expect("project");
        let manifest_path = project_path.join("NesC.toml");
        let manifest = fs::read_to_string(&manifest_path)
            .expect("manifest source")
            .replace("\nmapper = 0\n", "\nmapper = 2\n")
            .replace("prg-rom-kib = 32", "prg-rom-kib = 64");
        fs::write(&manifest_path, manifest).expect("Mapper 2 manifest");
        fs::write(
            project_path.join("src/main.c"),
            r#"#include <nes.h>

NES_BANK(1) NES_NOINLINE u8 banked_color(void) {
    return 0x2Au8;
}

NES_MAIN int main(void) {
    nes_wait_vblank();
    nes_set_background_color(banked_color());
    while (true) { nes_wait_frame(); }
}
"#,
        )
        .expect("Mapper 2 source");
        let project = Project::load(&manifest_path).expect("manifest");
        let artifacts = build_project(&project, &CompilerConfig::bundled_sdk()).expect("build");
        let rom = nesc_rom::parse(&artifacts.rom).expect("parse generated ROM");
        assert_eq!(rom.metadata.mapper, 2);
        assert!(artifacts.symbols.contains("001:8000 banked_color"));
        assert!(artifacts.map.contains("__nesc_bankcall_banked_color"));
        let boot = nesc_emulator::verify_compiler_boot(
            &artifacts.rom,
            &artifacts.symbol_addresses,
            0x2a,
            200_000,
        )
        .expect("Mapper 2 boot oracle");
        assert_eq!(boot.background_color, 0x2a);
    }

    #[test]
    fn builds_and_executes_a_cnrom_chr_bank_write() {
        let temporary = tempdir().expect("temporary directory");
        let project_path = temporary.path().join("cnrom-bank");
        create_project("cnrom-bank", &project_path).expect("project");
        let manifest_path = project_path.join("NesC.toml");
        let manifest = fs::read_to_string(&manifest_path)
            .expect("manifest source")
            .replace("\nmapper = 0\n", "\nmapper = 3\n")
            .replace("chr-rom-kib = 8", "chr-rom-kib = 32");
        fs::write(&manifest_path, manifest).expect("Mapper 3 manifest");
        fs::write(
            project_path.join("src/main.c"),
            r#"#include <nes.h>

NES_MAIN int main(void) {
    ptr<mapper_register, volatile u8> chr_bank =
        (ptr<mapper_register, volatile u8>)0x8000u16;
    *chr_bank = 2u8;
    nes_wait_vblank();
    nes_set_background_color(0x2Au8);
    while (true) { nes_wait_frame(); }
}
"#,
        )
        .expect("Mapper 3 source");
        let project = Project::load(&manifest_path).expect("manifest");
        let artifacts = build_project(&project, &CompilerConfig::bundled_sdk()).expect("build");
        let rom = nesc_rom::parse(&artifacts.rom).expect("parse generated ROM");
        assert_eq!(rom.metadata.mapper, 3);
        assert_eq!(rom.chr_rom.len(), 32 * 1024);
        assert!(artifacts.map.contains("switchable CHR-ROM banks: 0-3"));

        let mut machine = nesc_emulator::Machine::from_rom_bytes(
            &artifacts.rom,
            nesc_emulator::EmulatorConfig::default(),
        )
        .expect("Mapper 3 machine");
        machine.reset().expect("reset");
        for _ in 0..1_024 {
            if machine.mapper_state().chr_bank == 2 {
                break;
            }
            machine.step().expect("bounded execution");
        }
        assert_eq!(machine.mapper_state().chr_bank, 2);
        let boot = nesc_emulator::verify_compiler_boot(
            &artifacts.rom,
            &artifacts.symbol_addresses,
            0x2a,
            200_000,
        )
        .expect("Mapper 3 boot oracle");
        assert_eq!(boot.background_color, 0x2a);
    }

    #[test]
    fn rejects_switchable_entry_functions() {
        let temporary = tempdir().expect("temporary directory");
        let project_path = temporary.path().join("banked-entry");
        create_project("banked-entry", &project_path).expect("project");
        fs::write(
            project_path.join("src/main.c"),
            "#include <nes.h>\nNES_MAIN NES_BANK(0) int main(void) { return 0; }\n",
        )
        .expect("banked entry source");
        let project = Project::load(project_path.join("NesC.toml")).expect("manifest");
        let diagnostics = check_project(&project, &CompilerConfig::bundled_sdk())
            .expect_err("switchable entry rejected");
        assert!(diagnostics.iter().any(|diagnostic| {
            diagnostic.code() == "E2000"
                && diagnostic
                    .render()
                    .contains("entry or interrupt function `main` must remain in the fixed bank")
        }));
    }

    #[test]
    fn executes_inline_assembly_in_a_generated_rom() {
        let temporary = tempdir().expect("temporary directory");
        let project_path = temporary.path().join("inline-assembly");
        create_project("inline-assembly", &project_path).expect("project");
        fs::write(
            project_path.join("src/main.c"),
            r#"#include <nes.h>

NES_MAIN int main(void) {
    u8 color;
    NES_ASM(
        "lda #$2A",
        NES_ASM_OUTPUT_A(color),
        NES_CLOBBER_FLAGS
    );
    nes_wait_vblank();
    nes_set_background_color(color);
    while (true) { nes_wait_frame(); }
}
"#,
        )
        .expect("inline assembly source");
        let project = Project::load(project_path.join("NesC.toml")).expect("manifest");
        let artifacts = build_project(&project, &CompilerConfig::bundled_sdk()).expect("build");
        assert!(artifacts.assembly.contains("; begin NES_ASM"));
        let boot = nesc_emulator::verify_compiler_boot(
            &artifacts.rom,
            &artifacts.symbol_addresses,
            0x2a,
            200_000,
        )
        .expect("inline assembly boot oracle");
        assert_eq!(boot.background_color, 0x2a);
    }

    #[test]
    fn links_nesc_and_standalone_assembly_functions() {
        let temporary = tempdir().expect("temporary directory");
        let project_path = temporary.path().join("assembly-module");
        create_project("assembly-module", &project_path).expect("project");
        let manifest_path = project_path.join("NesC.toml");
        let manifest = fs::read_to_string(&manifest_path).expect("manifest source");
        fs::write(
            &manifest_path,
            manifest.replace("assembly = []", "assembly = [\"src/double.s\"]"),
        )
        .expect("assembly manifest");
        fs::write(
            project_path.join("src/main.c"),
            r#"#include <nes.h>

extern u8 assembly_double(u8 value);

NES_EXPORT u8 double_value(u8 value) {
    return value + value;
}

NES_MAIN int main(void) {
    nes_wait_vblank();
    nes_set_background_color(assembly_double(0x15u8));
    while (true) { nes_wait_frame(); }
}
"#,
        )
        .expect("NesC source");
        fs::write(
            project_path.join("src/double.s"),
            r#".setcpu "6502"
.segment "CODE"
.import double_value
.export assembly_double
.nesc_stack assembly_double, 2

assembly_double:
    jsr double_value
    rts
"#,
        )
        .expect("assembly source");
        let project = Project::load(&manifest_path).expect("manifest");
        let artifacts = build_project(&project, &CompilerConfig::bundled_sdk()).expect("build");
        assert!(artifacts.assembly.contains("standalone module"));
        assert!(artifacts.map.contains(".text.double"));
        assert!(artifacts.stack.contains("assembly_double"));
        assert!(artifacts.source_map.contains("src/double.s"));
        let boot = nesc_emulator::verify_compiler_boot(
            &artifacts.rom,
            &artifacts.symbol_addresses,
            0x2a,
            200_000,
        )
        .expect("standalone assembly boot oracle");
        assert_eq!(boot.background_color, 0x2a);
    }

    #[test]
    fn links_switchable_uxrom_assembly_functions() {
        let temporary = tempdir().expect("temporary directory");
        let project_path = temporary.path().join("banked-assembly");
        create_project("banked-assembly", &project_path).expect("project");
        let manifest_path = project_path.join("NesC.toml");
        let manifest = fs::read_to_string(&manifest_path)
            .expect("manifest source")
            .replace("assembly = []", "assembly = [\"src/color.s\"]")
            .replace("\nmapper = 0\n", "\nmapper = 2\n")
            .replace("prg-rom-kib = 32", "prg-rom-kib = 64");
        fs::write(&manifest_path, manifest).expect("Mapper 2 assembly manifest");
        fs::write(
            project_path.join("src/main.c"),
            r#"#include <nes.h>

NES_BANK(1) extern u8 assembly_color(void);

NES_MAIN int main(void) {
    nes_wait_vblank();
    nes_set_background_color(assembly_color());
    while (true) { nes_wait_frame(); }
}
"#,
        )
        .expect("NesC source");
        fs::write(
            project_path.join("src/color.s"),
            r#".setcpu "6502"
.segment "CODE"
.export assembly_color
.nesc_bank 1
.nesc_stack assembly_color, 0

assembly_color:
    lda #$2A
    rts
"#,
        )
        .expect("assembly source");
        let project = Project::load(&manifest_path).expect("manifest");
        let artifacts = build_project(&project, &CompilerConfig::bundled_sdk()).expect("build");
        assert!(artifacts.symbols.contains("001:8000 assembly_color"));
        assert!(artifacts.map.contains("__nesc_bankcall_assembly_color"));
        let boot = nesc_emulator::verify_compiler_boot(
            &artifacts.rom,
            &artifacts.symbol_addresses,
            0x2a,
            200_000,
        )
        .expect("banked assembly boot oracle");
        assert_eq!(boot.background_color, 0x2a);
    }

    #[test]
    fn rejects_untyped_assembly_exports() {
        let temporary = tempdir().expect("temporary directory");
        let project_path = temporary.path().join("untyped-assembly");
        create_project("untyped-assembly", &project_path).expect("project");
        let manifest_path = project_path.join("NesC.toml");
        let manifest = fs::read_to_string(&manifest_path)
            .expect("manifest source")
            .replace("assembly = []", "assembly = [\"src/orphan.s\"]");
        fs::write(&manifest_path, manifest).expect("assembly manifest");
        fs::write(
            project_path.join("src/orphan.s"),
            ".segment \"CODE\"\n.import main\n.export orphan\n.nesc_stack orphan, 0\norphan:\n rts\n",
        )
        .expect("assembly source");
        let project = Project::load(&manifest_path).expect("manifest");
        let diagnostics = check_project(&project, &CompilerConfig::bundled_sdk())
            .expect_err("untyped export rejected");
        assert!(
            diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code() == "E2101")
        );
        assert!(
            diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code() == "E2102")
        );
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

    #[test]
    fn executes_runtime_arithmetic_helpers() {
        let temporary = tempdir().expect("temporary directory");
        let project_path = temporary.path().join("arithmetic");
        create_project("arithmetic", &project_path).expect("project");
        fs::write(
            project_path.join("src/main.c"),
            r#"#include <nes.h>

u16 mul16(u16 a, u16 b) { return a * b; }
u24 mul24(u24 a, u24 b) { return a * b; }
u32 mul32(u32 a, u32 b) { return a * b; }

u16 udiv16(u16 a, u16 b) { return a / b; }
u24 udiv24(u24 a, u24 b) { return a / b; }
u32 udiv32(u32 a, u32 b) { return a / b; }
u16 urem16(u16 a, u16 b) { return a % b; }
u24 urem24(u24 a, u24 b) { return a % b; }
u32 urem32(u32 a, u32 b) { return a % b; }

i16 sdiv16(i16 a, i16 b) { return a / b; }
i24 sdiv24(i24 a, i24 b) { return a / b; }
i32 sdiv32(i32 a, i32 b) { return a / b; }
i16 srem16(i16 a, i16 b) { return a % b; }
i24 srem24(i24 a, i24 b) { return a % b; }
i32 srem32(i32 a, i32 b) { return a % b; }

u16 shl16(u16 a, u16 count) { return a << count; }
u24 shl24(u24 a, u24 count) { return a << count; }
u32 shl32(u32 a, u32 count) { return a << count; }
u16 shr16(u16 a, u16 count) { return a >> count; }
u24 shr24(u24 a, u24 count) { return a >> count; }
u32 shr32(u32 a, u32 count) { return a >> count; }
i16 ashr16(i16 a, i16 count) { return a >> count; }
i24 ashr24(i24 a, i24 count) { return a >> count; }
i32 ashr32(i32 a, i32 count) { return a >> count; }

NES_MAIN int main(void) {
    nes_wait_vblank();
    if (
        mul16(300u16, 7u16) == 2100u16 &&
        mul16(0xFFFFu16, 2u16) == 0xFFFEu16 &&
        mul24(0x010203u24, 17u24) == 0x112233u24 &&
        mul24(0xFFFFFFu24, 2u24) == 0xFFFFFEu24 &&
        mul32(0x00010003u32, 257u32) == 0x01010303u32 &&
        mul32(0xFFFFFFFFu32, 2u32) == 0xFFFFFFFEu32 &&
        udiv16(300u16, 7u16) == 42u16 && urem16(300u16, 7u16) == 6u16 &&
        udiv16(7u16, 300u16) == 0u16 && urem16(7u16, 300u16) == 7u16 &&
        udiv24(0x010203u24, 17u24) == 3885u24 && urem24(0x010203u24, 17u24) == 6u24 &&
        udiv32(0x00010003u32, 257u32) == 255u32 && urem32(0x00010003u32, 257u32) == 4u32 &&
        sdiv16(-300i16, 7i16) == -42i16 && srem16(-300i16, 7i16) == -6i16 &&
        sdiv16(300i16, -7i16) == -42i16 && srem16(300i16, -7i16) == 6i16 &&
        sdiv16(-300i16, -7i16) == 42i16 && srem16(-300i16, -7i16) == -6i16 &&
        sdiv24(-50000i24, 300i24) == -166i24 && srem24(-50000i24, 300i24) == -200i24 &&
        sdiv32(-100000i32, 300i32) == -333i32 && srem32(-100000i32, 300i32) == -100i32 &&
        shl16(0x1234u16, 20u16) == 0x2340u16 && shr16(0x1234u16, 20u16) == 0x0123u16 &&
        shl16(0x1234u16, 0x0104u16) == 0x2340u16 &&
        shl24(0x654321u24, 29u24) == 0xA86420u24 && shr24(0x654321u24, 29u24) == 0x032A19u24 &&
        shl24(1u24, 0x010000u24) == 0x010000u24 &&
        shl32(0x80000001u32, 36u32) == 0x00000010u32 && shr32(0x80000001u32, 36u32) == 0x08000000u32 &&
        shl32(1u32, 0x00000104u32) == 0x00000010u32 &&
        ashr16(-300i16, 3i16) == -38i16 &&
        ashr24(-50000i24, 4i24) == -3125i24 &&
        ashr32(-100000i32, 7i32) == -782i32
    ) {
        nes_set_background_color(0x2A);
    } else {
        nes_set_background_color(0x16);
    }
    while (true) { nes_wait_frame(); }
}
"#,
        )
        .expect("arithmetic source");
        let manifest_path = project_path.join("NesC.toml");
        let manifest = fs::read_to_string(&manifest_path).expect("manifest source");
        for optimization in ["0", "1", "2", "size", "min-size", "cycles"] {
            fs::write(
                &manifest_path,
                manifest.replace(
                    "optimization = \"size\"",
                    &format!("optimization = \"{optimization}\""),
                ),
            )
            .expect("optimization manifest");
            let project = Project::load(&manifest_path).expect("manifest");
            let artifacts = build_project(&project, &CompilerConfig::bundled_sdk()).expect("build");
            let boot = nesc_emulator::verify_compiler_boot(
                &artifacts.rom,
                &artifacts.symbol_addresses,
                0x2a,
                500_000,
            )
            .unwrap_or_else(|error| panic!("{optimization} arithmetic boot oracle: {error}"));
            assert_eq!(boot.background_color, 0x2a);
        }
    }

    #[test]
    fn preserves_shared_helper_arithmetic_across_optimization_settings() {
        let temporary = tempdir().expect("temporary directory");
        let project_path = temporary.path().join("arithmetic-costs");
        create_project("arithmetic-costs", &project_path).expect("project");
        fs::write(
            project_path.join("src/main.c"),
            r#"#include <nes.h>

u8 mixed_product(u8 value, u8 multiplier) {
    return (value * multiplier) + (value * 8u8);
}

NES_MAIN int main(void) {
    nes_wait_vblank();
    nes_set_background_color(mixed_product(3u8, 2u8));
    while (true) { nes_wait_frame(); }
}
"#,
        )
        .expect("arithmetic cost source");
        let manifest_path = project_path.join("NesC.toml");
        let manifest = fs::read_to_string(&manifest_path).expect("manifest source");

        for optimization in ["0", "1", "2", "size", "min-size", "cycles"] {
            fs::write(
                &manifest_path,
                manifest.replace(
                    "optimization = \"size\"",
                    &format!("optimization = \"{optimization}\""),
                ),
            )
            .expect("optimization manifest");
            let project = Project::load(&manifest_path).expect("manifest");
            let artifacts = build_project(&project, &CompilerConfig::bundled_sdk())
                .unwrap_or_else(|errors| panic!("{optimization} build: {errors:#?}"));
            let expected_goal = match optimization {
                "size" => "size",
                "min-size" => "min-size",
                "cycles" => "cycles",
                _ => "balanced",
            };
            assert!(
                artifacts
                    .optimization
                    .contains(&format!("Optimization: {optimization}"))
            );
            assert!(
                artifacts
                    .optimization
                    .contains(&format!("Code generation goal: {expected_goal}"))
            );
            if optimization == "min-size" {
                assert!(artifacts.optimization.contains("selected helper"));
                assert_eq!(artifacts.assembly.matches("jsr __nesc_mul_16").count(), 2);
            }
            if optimization == "cycles" {
                assert!(artifacts.optimization.contains("selected inline"));
                assert_eq!(artifacts.assembly.matches("jsr __nesc_mul_16").count(), 1);
            }
            let boot = nesc_emulator::verify_compiler_boot(
                &artifacts.rom,
                &artifacts.symbol_addresses,
                0x1e,
                200_000,
            )
            .unwrap_or_else(|error| panic!("{optimization} cost-model boot oracle: {error}"));
            assert_eq!(boot.background_color, 0x1e);
        }
    }

    #[test]
    fn preserves_inter_block_constants_and_loops_across_optimization_settings() {
        let temporary = tempdir().expect("temporary directory");
        let project_path = temporary.path().join("control-flow-costs");
        create_project("control-flow-costs", &project_path).expect("project");
        fs::write(
            project_path.join("src/main.c"),
            r#"#include <nes.h>

u8 calculate_color(u8 condition) {
    u8 stable = 7u8;
    if (condition) {
        stable = 7u8;
    } else {
        stable = 7u8;
    }
    u8 total = 0u8;
    u8 index = 0u8;
    while (index < 3u8) {
        total = total + stable;
        index = index + 1u8;
    }
    return total;
}

NES_MAIN int main(void) {
    nes_wait_vblank();
    nes_set_background_color(calculate_color(nes_read_controller(0u8)));
    while (true) { nes_wait_frame(); }
}
"#,
        )
        .expect("control-flow cost source");
        let manifest_path = project_path.join("NesC.toml");
        let manifest = fs::read_to_string(&manifest_path).expect("manifest source");

        for optimization in ["0", "1", "2", "size", "min-size", "cycles"] {
            fs::write(
                &manifest_path,
                manifest.replace(
                    "optimization = \"size\"",
                    &format!("optimization = \"{optimization}\""),
                ),
            )
            .expect("optimization manifest");
            let project = Project::load(&manifest_path).expect("manifest");
            let artifacts = build_project(&project, &CompilerConfig::bundled_sdk())
                .unwrap_or_else(|errors| panic!("{optimization} build: {errors:#?}"));
            assert!(artifacts.optimization.contains("Natural loops: 2"));
            assert!(artifacts.optimization.contains("Maximum loop depth: 1"));
            assert!(
                artifacts
                    .optimization
                    .contains("Control-flow blocks placed: ")
            );
            assert!(
                artifacts
                    .optimization
                    .contains("Weighted page-cross risk cycles: ")
            );
            assert!(artifacts.zero_page.contains("(weight "));
            if matches!(optimization, "2" | "size" | "min-size" | "cycles") {
                let propagated = artifacts
                    .optimization
                    .lines()
                    .find_map(|line| line.strip_prefix("Constants propagated: "))
                    .and_then(|count| count.parse::<usize>().ok())
                    .expect("constant propagation count");
                assert!(propagated > 0, "{optimization} propagation report");
            }
            let boot = nesc_emulator::verify_compiler_boot(
                &artifacts.rom,
                &artifacts.symbol_addresses,
                0x15,
                200_000,
            )
            .unwrap_or_else(|error| panic!("{optimization} CFG boot oracle: {error}"));
            assert_eq!(boot.background_color, 0x15);
        }
    }

    #[test]
    fn diagnoses_invalid_constant_arithmetic() {
        let temporary = tempdir().expect("temporary directory");
        let project_path = temporary.path().join("invalid-arithmetic");
        create_project("invalid-arithmetic", &project_path).expect("project");
        fs::write(
            project_path.join("src/main.c"),
            r#"#include <nes.h>

u16 invalid(u16 value) {
    u16 quotient = value / 0u16;
    return quotient << 16u16;
}

NES_MAIN int main(void) { return (int)invalid(1u16); }
"#,
        )
        .expect("invalid arithmetic source");
        let project = Project::load(project_path.join("NesC.toml")).expect("manifest");

        let errors = build_project(&project, &CompilerConfig::bundled_sdk())
            .expect_err("invalid constant arithmetic");
        let rendered = errors
            .iter()
            .map(nesc_diagnostics::Diagnostic::render)
            .collect::<String>();
        assert!(rendered.contains("division or remainder by constant zero"));
        assert!(rendered.contains("constant shift count must be less than 16"));
    }

    #[test]
    fn traps_on_runtime_zero_divisor() {
        let temporary = tempdir().expect("temporary directory");
        let project_path = temporary.path().join("zero-divisor");
        create_project("zero-divisor", &project_path).expect("project");
        fs::write(
            project_path.join("src/main.c"),
            r#"#include <nes.h>

u16 divide(u16 value, u16 divisor) { return value / divisor; }

NES_MAIN int main(void) {
    u16 result = divide(100u16, 0u16);
    nes_set_background_color((u8)result);
    while (true) { nes_wait_frame(); }
}
"#,
        )
        .expect("zero-divisor source");
        let project = Project::load(project_path.join("NesC.toml")).expect("manifest");
        let artifacts = build_project(&project, &CompilerConfig::bundled_sdk()).expect("build");

        let error = nesc_emulator::verify_compiler_boot(
            &artifacts.rom,
            &artifacts.symbol_addresses,
            0x64,
            200_000,
        )
        .expect_err("runtime division trap");
        assert!(error.message.contains("runtime trap"));
    }

    #[test]
    fn inlines_power_of_two_arithmetic() {
        let temporary = tempdir().expect("temporary directory");
        let project_path = temporary.path().join("inline-arithmetic");
        create_project("inline-arithmetic", &project_path).expect("project");
        fs::write(
            project_path.join("src/main.c"),
            r#"#include <nes.h>

u16 power_arithmetic(u16 value) {
    return value * 8u16 + value / 8u16 + value % 8u16 +
           (value << 3u16) + (value >> 3u16);
}

NES_MAIN int main(void) {
    nes_wait_vblank();
    nes_set_background_color((u8)power_arithmetic(0x1234u16));
    while (true) { nes_wait_frame(); }
}
"#,
        )
        .expect("inline arithmetic source");
        let project = Project::load(project_path.join("NesC.toml")).expect("manifest");
        let artifacts = build_project(&project, &CompilerConfig::bundled_sdk()).expect("build");

        for helper in [
            "jsr __nesc_mul_16",
            "jsr __nesc_udiv_16",
            "jsr __nesc_urem_16",
            "jsr __nesc_shl_16",
            "jsr __nesc_lshr_16",
        ] {
            assert!(!artifacts.assembly.contains(helper), "unexpected {helper}");
        }
        let boot = nesc_emulator::verify_compiler_boot(
            &artifacts.rom,
            &artifacts.symbol_addresses,
            0xd0,
            200_000,
        )
        .expect("inline arithmetic boot oracle");
        assert_eq!(boot.background_color, 0xd0);
    }

    #[test]
    fn executes_arrays_pointers_and_typed_volatile_bus_accesses() {
        let temporary = tempdir().expect("temporary directory");
        let project_path = temporary.path().join("pointer-memory");
        create_project("pointer-memory", &project_path).expect("project");
        fs::write(
            project_path.join("src/main.c"),
            r#"#include <nes.h>

static u8 values[3];

u8 read_value(u8 index) {
    return values[index];
}

NES_MAIN int main(void) {
    u8 local[2];
    u8 *pointer = &local[0];
    ptr<ppu_register, volatile u8> ppu_address =
        (ptr<ppu_register, volatile u8>)0x2006u16;
    ptr<ppu_register, volatile u8> ppu_data =
        (ptr<ppu_register, volatile u8>)0x2007u16;

    values[0] = 0x10;
    values[1] = 0x20;
    pointer[0] = values[0];
    pointer[1] = read_value(1);

    nes_wait_vblank();
    *ppu_address = 0x3F;
    *ppu_address = 0x00;
    *ppu_data = pointer[0] + pointer[1];
    while (true) { nes_wait_frame(); }
}
"#,
        )
        .expect("pointer-memory source");
        let manifest_path = project_path.join("NesC.toml");
        let manifest = fs::read_to_string(&manifest_path).expect("manifest source");

        for optimization in ["0", "1", "2", "size", "min-size", "cycles"] {
            fs::write(
                &manifest_path,
                manifest.replace(
                    "optimization = \"size\"",
                    &format!("optimization = \"{optimization}\""),
                ),
            )
            .expect("optimization manifest");
            let project = Project::load(&manifest_path).expect("manifest");
            let artifacts = build_project(&project, &CompilerConfig::bundled_sdk())
                .unwrap_or_else(|errors| panic!("{optimization} pointer build: {errors:#?}"));
            assert!(artifacts.assembly.contains("lda ($f0),y"));
            assert!(artifacts.assembly.contains("sta ($f0),y"));
            assert!(artifacts.assembly.contains("jmp __nesc_trap"));
            assert!(!artifacts.assembly.contains(".export __nesc_mul_"));
            let boot = nesc_emulator::verify_compiler_boot(
                &artifacts.rom,
                &artifacts.symbol_addresses,
                0x30,
                300_000,
            )
            .unwrap_or_else(|error| panic!("{optimization} pointer boot oracle: {error}"));
            assert_eq!(boot.background_color, 0x30);
        }
    }

    #[test]
    fn applies_manifest_bounds_policy() {
        let temporary = tempdir().expect("temporary directory");
        let project_path = temporary.path().join("bounds-policy");
        create_project("bounds-policy", &project_path).expect("project");
        fs::write(
            project_path.join("src/main.c"),
            r#"static u8 values[2];
u8 read_value(u8 index) { return values[index]; }
NES_MAIN int main(void) { return read_value(1); }
"#,
        )
        .expect("bounds source");
        let manifest_path = project_path.join("NesC.toml");
        let manifest = fs::read_to_string(&manifest_path).expect("manifest source");

        let project = Project::load(&manifest_path).expect("elide manifest");
        let checked = check_project(&project, &CompilerConfig::bundled_sdk()).expect("elide MIR");
        assert!(checked.mir.functions.iter().any(|function| {
            function.blocks.iter().any(|block| {
                block.instructions.iter().any(|instruction| {
                    matches!(
                        instruction.kind,
                        nesc_mir::InstructionKind::BoundsCheck { .. }
                    )
                })
            })
        }));

        fs::write(
            &manifest_path,
            manifest.replace(
                "bounds-checks = \"elide-proven\"",
                "bounds-checks = \"off\"",
            ),
        )
        .expect("off manifest");
        let project = Project::load(&manifest_path).expect("off manifest");
        let checked = check_project(&project, &CompilerConfig::bundled_sdk()).expect("off MIR");
        assert!(!checked.mir.functions.iter().any(|function| {
            function.blocks.iter().any(|block| {
                block.instructions.iter().any(|instruction| {
                    matches!(
                        instruction.kind,
                        nesc_mir::InstructionKind::BoundsCheck { .. }
                    )
                })
            })
        }));
    }

    #[test]
    fn traps_on_runtime_out_of_bounds_index() {
        let temporary = tempdir().expect("temporary directory");
        let project_path = temporary.path().join("bounds-trap");
        create_project("bounds-trap", &project_path).expect("project");
        fs::write(
            project_path.join("src/main.c"),
            r#"static u8 values[2];
u8 read_value(u8 index) { return values[index]; }
NES_MAIN int main(void) { return read_value(2); }
"#,
        )
        .expect("bounds trap source");
        let project = Project::load(project_path.join("NesC.toml")).expect("manifest");
        let artifacts = build_project(&project, &CompilerConfig::bundled_sdk()).expect("build");
        let error = nesc_emulator::verify_compiler_boot(
            &artifacts.rom,
            &artifacts.symbol_addresses,
            0x21,
            50_000,
        )
        .expect_err("bounds trap");
        assert!(error.message.contains("runtime trap"));
    }

    #[test]
    fn rejects_writes_through_rom_pointers() {
        let temporary = tempdir().expect("temporary directory");
        let project_path = temporary.path().join("rom-write");
        create_project("rom-write", &project_path).expect("project");
        fs::write(
            project_path.join("src/main.c"),
            r#"NES_MAIN int main(void) {
    ptr<prg_rom, u8> data = (ptr<prg_rom, u8>)0x8000u16;
    *data = 1;
    return 0;
}
"#,
        )
        .expect("ROM write source");
        let project = Project::load(project_path.join("NesC.toml")).expect("manifest");
        let errors = check_project(&project, &CompilerConfig::bundled_sdk())
            .expect_err("ROM write diagnostic");
        assert!(errors.iter().any(|error| error.code() == "E1344"));
    }

    #[test]
    fn builds_and_executes_independent_test_roms() {
        let temporary = tempdir().expect("temporary directory");
        let project_path = temporary.path().join("test-project");
        create_project("test-project", &project_path).expect("project");
        fs::write(
            project_path.join("src/main.c"),
            r#"NES_CYCLE_BUDGET(2000) NES_TEST("addition works") {
    u8 result = 10u8 + 20u8;
    NES_ASSERT_EQ(result, 30u8);
}

NES_TEST("failure values") {
    NES_ASSERT_EQ(41u8, 42u8);
}
"#,
        )
        .expect("test source");
        let project = Project::load(project_path.join("NesC.toml")).expect("manifest");
        let tests = build_tests(&project, &CompilerConfig::bundled_sdk()).expect("test builds");
        assert_eq!(tests.len(), 2);
        assert_eq!(tests[0].definition.name, "addition works");
        assert_eq!(tests[0].definition.cycle_budget, Some(2000));
        assert!(tests[0].artifacts.assembly.contains("jsr __nesc_test_0000"));

        let run = |test: &super::BuiltTest| {
            nesc_emulator::run_test_rom(
                &test.artifacts.rom,
                &test.artifacts.symbol_addresses,
                nesc_emulator::RunLimits {
                    instruction_limit: 10_000,
                    cycle_limit: test.definition.cycle_budget.unwrap_or(100_000),
                },
            )
            .expect("test execution")
        };
        assert_eq!(run(&tests[0]).outcome, nesc_emulator::TestOutcome::Passed);
        assert_eq!(
            run(&tests[1]).outcome,
            nesc_emulator::TestOutcome::AssertionFailed {
                actual: 41,
                expected: 42,
            }
        );
    }

    #[test]
    fn builds_and_executes_prg_rom_const_data_reads() {
        let temporary = tempdir().expect("temporary directory");
        let project_path = temporary.path().join("rom-data");
        create_project("rom-data", &project_path).expect("project");
        fs::write(
            project_path.join("src/main.c"),
            r#"#include <nes.h>

const u8 base_color = 0x20u8;
const u8 shades[4] = {1u8, 2u8, 0x0Au8, 4u8};

NES_MAIN int main(void) {
    u8 color = (u8)(base_color + shades[2u8]);
    nes_wait_vblank();
    nes_set_background_color(color);
    while (true) { nes_wait_frame(); }
}
"#,
        )
        .expect("ROM data source");
        let project = Project::load(project_path.join("NesC.toml")).expect("manifest");
        let artifacts = build_project(&project, &CompilerConfig::bundled_sdk()).expect("build");
        assert!(artifacts.map.contains(".rodata"), "{}", artifacts.map);
        assert!(artifacts.assembly.contains("__nesc_rodata_"));
        let boot = nesc_emulator::verify_compiler_boot(
            &artifacts.rom,
            &artifacts.symbol_addresses,
            0x2a,
            200_000,
        )
        .expect("ROM data boot oracle");
        assert_eq!(boot.background_color, 0x2a);
    }

    #[test]
    fn executes_tests_reading_prg_rom_const_tables() {
        let temporary = tempdir().expect("temporary directory");
        let project_path = temporary.path().join("rom-data-tests");
        create_project("rom-data-tests", &project_path).expect("project");
        fs::write(
            project_path.join("src/main.c"),
            r#"const u8 answer = 42u8;
const u8 table[3] = {10u8, 20u8, 30u8};
const u16 word = 0x1234u16;

NES_TEST("rom scalar") {
    NES_ASSERT_EQ(answer, 42u8);
}

NES_TEST("rom array") {
    NES_ASSERT_EQ(table[1u8], 20u8);
    NES_ASSERT_EQ(word, 0x1234u16);
}

NES_TEST("rom table sum") {
    u8 total = 0u8;
    u8 i;
    for (i = 0u8; i < 3u8; i++) {
        total = (u8)(total + table[i]);
    }
    NES_ASSERT_EQ(total, 60u8);
}
"#,
        )
        .expect("ROM data test source");
        let project = Project::load(project_path.join("NesC.toml")).expect("manifest");
        let tests = build_tests(&project, &CompilerConfig::bundled_sdk()).expect("test builds");
        assert_eq!(tests.len(), 3);
        for test in &tests {
            let run = nesc_emulator::run_test_rom(
                &test.artifacts.rom,
                &test.artifacts.symbol_addresses,
                nesc_emulator::RunLimits {
                    instruction_limit: 100_000,
                    cycle_limit: 1_000_000,
                },
            )
            .expect("test execution");
            assert_eq!(
                run.outcome,
                nesc_emulator::TestOutcome::Passed,
                "test `{}` failed",
                test.definition.name
            );
        }
    }

    #[test]
    fn builds_and_renders_embedded_chr_tiles() {
        let temporary = tempdir().expect("temporary directory");
        let project_path = temporary.path().join("chr-demo");
        create_project("chr-demo", &project_path).expect("project");

        // Tile 0 stays blank; tile 1 is solid color 1 (plane 0 all ones).
        let mut chr = vec![0u8; 32];
        chr[16..24].fill(0xff);
        fs::create_dir_all(project_path.join("assets")).expect("assets directory");
        fs::write(project_path.join("assets/tiles.chr"), &chr).expect("CHR asset");

        let manifest_path = project_path.join("NesC.toml");
        let manifest = fs::read_to_string(&manifest_path).expect("manifest source");
        fs::write(
            &manifest_path,
            format!("{manifest}\n[assets]\nchr = \"assets/tiles.chr\"\n"),
        )
        .expect("manifest with CHR asset");

        fs::write(
            project_path.join("src/main.c"),
            r#"#include <nes.h>

NES_MAIN int main(void) {
    nes_set_sprite_position(0u8, 0x40u8, 0x30u8);
    nes_set_sprite_tile(0u8, 1u8);
    nes_set_sprite_attributes(0u8, 0u8);
    nes_wait_vblank();
    nes_set_ppu_address(0x3F11u16);
    nes_write_ppu_data(0x30u8);
    nes_oam_dma();
    nes_enable_rendering();
    while (true) { nes_wait_frame(); }
}
"#,
        )
        .expect("CHR demo source");

        let project = Project::load(&manifest_path).expect("manifest");
        let artifacts = build_project(&project, &CompilerConfig::bundled_sdk()).expect("build");
        let rom = nesc_rom::parse(&artifacts.rom).expect("parse generated ROM");
        assert_eq!(&rom.chr_rom[..32], &chr[..]);
        assert!(rom.chr_rom[32..].iter().all(|byte| *byte == 0));

        let mut machine = nesc_emulator::Machine::from_rom_bytes(
            &artifacts.rom,
            nesc_emulator::EmulatorConfig::default(),
        )
        .expect("CHR machine");
        machine.reset().expect("reset");
        machine
            .run_frames(
                5,
                nesc_emulator::RunLimits {
                    instruction_limit: 2_000_000,
                    cycle_limit: 2_000_000,
                },
            )
            .expect("rendered frames");
        let sprite_pixels = machine
            .framebuffer()
            .iter()
            .filter(|pixel| **pixel == 0x30)
            .count();
        assert_eq!(
            sprite_pixels, 64,
            "expected the full 8x8 embedded tile to render"
        );
    }

    #[test]
    fn renders_metasprite_and_background_through_sdk_helpers() {
        let temporary = tempdir().expect("temporary directory");
        let project_path = temporary.path().join("sdk-render");
        create_project("sdk-render", &project_path).expect("project");

        // Tiles 1-5 are solid color 1; tile 0 stays blank.
        let mut chr = vec![0u8; 6 * 16];
        for tile in 1..=5 {
            chr[tile * 16..tile * 16 + 8].fill(0xff);
        }
        fs::create_dir_all(project_path.join("assets")).expect("assets directory");
        fs::write(project_path.join("assets/tiles.chr"), &chr).expect("CHR asset");
        let manifest_path = project_path.join("NesC.toml");
        let manifest = fs::read_to_string(&manifest_path).expect("manifest source");
        fs::write(
            &manifest_path,
            format!("{manifest}\n[assets]\nchr = \"assets/tiles.chr\"\n"),
        )
        .expect("manifest with CHR asset");

        fs::write(
            project_path.join("src/main.c"),
            r#"#include <nes.h>
#include <metasprite.h>
#include <nametable.h>

NES_MAIN int main(void) {
    nes_metasprite_draw(0u8, 0x40u8, 0x40u8, 1u8, 0u8);
    nes_wait_vblank();
    nes_set_palette_color(1u8, 0x21u8);
    nes_set_palette_color(17u8, 0x30u8);
    nes_set_tile(4u8, 4u8, 5u8);
    nes_oam_dma();
    nes_set_ppu_address(0x0000u16);
    nes_enable_rendering();
    while (true) { nes_wait_frame(); }
}
"#,
        )
        .expect("SDK render source");

        let project = Project::load(&manifest_path).expect("manifest");
        let artifacts = build_project(&project, &CompilerConfig::bundled_sdk()).expect("build");
        let mut machine = nesc_emulator::Machine::from_rom_bytes(
            &artifacts.rom,
            nesc_emulator::EmulatorConfig::default(),
        )
        .expect("SDK render machine");
        machine.reset().expect("reset");
        machine
            .run_frames(
                5,
                nesc_emulator::RunLimits {
                    instruction_limit: 2_000_000,
                    cycle_limit: 2_000_000,
                },
            )
            .expect("rendered frames");
        let framebuffer = machine.framebuffer();
        let sprite_pixels = framebuffer.iter().filter(|pixel| **pixel == 0x30).count();
        let background_pixels = framebuffer.iter().filter(|pixel| **pixel == 0x21).count();
        assert_eq!(
            sprite_pixels, 256,
            "expected the full 16x16 metasprite to render"
        );
        assert_eq!(
            background_pixels, 64,
            "expected the background tile written through nes_set_tile to render"
        );
    }

    #[test]
    fn stages_sprites_in_shadow_oam_and_dmas_them_into_sprite_memory() {
        let temporary = tempdir().expect("temporary directory");
        let project_path = temporary.path().join("sprite-dma");
        create_project("sprite-dma", &project_path).expect("project");
        fs::write(
            project_path.join("src/main.c"),
            r#"#include <nes.h>

NES_MAIN int main(void) {
    nes_set_sprite_position(2u8, 0x40u8, 0x30u8);
    nes_set_sprite_tile(2u8, 0x55u8);
    nes_set_sprite_attributes(2u8, 0x03u8);
    nes_oam_dma();
    while (true) { nes_wait_frame(); }
}
"#,
        )
        .expect("sprite source");
        let project = Project::load(project_path.join("NesC.toml")).expect("manifest");
        let artifacts = build_project(&project, &CompilerConfig::bundled_sdk()).expect("build");

        let mut machine = nesc_emulator::Machine::from_rom_bytes(
            &artifacts.rom,
            nesc_emulator::EmulatorConfig::default(),
        )
        .expect("machine");
        machine.reset().expect("reset");
        for _ in 0..200_000 {
            if machine.oam()[9] == 0x55 {
                break;
            }
            machine.step().expect("bounded execution");
        }

        // Sprite 2 occupies OAM bytes 8..12 as Y, tile, attributes, X.
        let oam = machine.oam();
        assert_eq!(oam[8], 0x30, "sprite 2 Y");
        assert_eq!(oam[9], 0x55, "sprite 2 tile");
        assert_eq!(oam[10], 0x03, "sprite 2 attributes");
        assert_eq!(oam[11], 0x40, "sprite 2 X");
    }

    #[test]
    fn reads_a_controller_mask_through_the_nescall_abi() {
        let temporary = tempdir().expect("temporary directory");
        let project_path = temporary.path().join("controller-read");
        create_project("controller-read", &project_path).expect("project");
        fs::write(
            project_path.join("src/main.c"),
            r#"#include <nes.h>

NES_MAIN int main(void) {
    u8 mask = nes_read_controller(0u8);
    nes_set_sprite_tile(0u8, mask);
    nes_oam_dma();
    while (true) { nes_wait_frame(); }
}
"#,
        )
        .expect("controller source");
        let project = Project::load(project_path.join("NesC.toml")).expect("manifest");
        let artifacts = build_project(&project, &CompilerConfig::bundled_sdk()).expect("build");

        let mut machine = nesc_emulator::Machine::from_rom_bytes(
            &artifacts.rom,
            nesc_emulator::EmulatorConfig::default(),
        )
        .expect("machine");
        machine.reset().expect("reset");
        // The emulator returns serial bits low-to-high; `nes_read_controller`
        // assembles them MSB-first, so pressing the first two buttons (0x03)
        // yields `NES_BUTTON_A | NES_BUTTON_B` (0xC0).
        machine.set_controller(0, 0x03).expect("controller");
        for _ in 0..200_000 {
            if machine.oam()[1] != 0 {
                break;
            }
            machine.step().expect("bounded execution");
        }

        assert_eq!(machine.oam()[1], 0xc0, "assembled controller mask");
    }
}
