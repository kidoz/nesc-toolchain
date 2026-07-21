use std::fs;
use std::path::{Component, Path, PathBuf};

use nesc_diagnostics::{Diagnostic, SourceFile, Span};
use serde::Deserialize;

/// Fully parsed `NesC.toml` manifest.
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct Manifest {
    /// Package identity.
    pub package: Package,
    /// Compilation inputs and target format.
    pub build: Build,
    /// Cartridge layout.
    pub cartridge: Cartridge,
    /// Compiler policies.
    pub compiler: Compiler,
    /// Memory reservations.
    pub memory: Memory,
    /// Debug artifact settings.
    #[serde(default)]
    pub debug: Debug,
}

/// Package identity fields.
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct Package {
    /// Package name used for output artifacts.
    pub name: String,
    /// Package semantic version.
    pub version: String,
}

/// Build configuration.
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct Build {
    /// Entry NesC source, relative to the project root.
    pub entry: PathBuf,
    /// Standalone relocatable 6502 assembly modules.
    #[serde(default)]
    pub assembly: Vec<PathBuf>,
    /// Console timing profile.
    pub region: Region,
    /// ROM container format.
    pub format: RomFormat,
}

/// Supported timing profiles.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Region {
    /// Nintendo NTSC timing.
    Ntsc,
    /// Nintendo PAL timing.
    Pal,
    /// Dendy timing.
    Dendy,
}

/// Supported ROM container formats.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum RomFormat {
    /// Legacy iNES format.
    Ines,
    /// NES 2.0 format.
    Nes2,
}

/// Cartridge layout and metadata.
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct Cartridge {
    /// iNES mapper number.
    pub mapper: u16,
    /// NES 2.0 submapper number.
    pub submapper: u8,
    /// Nametable mirroring mode.
    pub mirroring: Mirroring,
    /// PRG-ROM capacity in KiB.
    pub prg_rom_kib: u32,
    /// CHR-ROM capacity in KiB; zero selects CHR RAM.
    pub chr_rom_kib: u32,
    /// Whether persistent cartridge RAM is battery backed.
    pub battery: bool,
}

/// Cartridge nametable mirroring.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum Mirroring {
    /// Horizontal arrangement.
    Horizontal,
    /// Vertical arrangement.
    Vertical,
    /// Single-screen lower bank.
    SingleScreenLower,
    /// Single-screen upper bank.
    SingleScreenUpper,
    /// Four-screen arrangement.
    FourScreen,
}

/// Compiler policy settings.
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct Compiler {
    /// Optimization preference.
    pub optimization: Optimization,
    /// Signed-overflow behavior.
    pub signed_overflow: SignedOverflow,
    /// Fixed-array bounds-check behavior.
    pub bounds_checks: BoundsChecks,
    /// Maximum permitted hardware-stack use.
    pub stack_limit: u16,
}

/// Optimization selection from a manifest.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
pub enum Optimization {
    /// Debug-oriented `-O0`.
    #[serde(rename = "0")]
    O0,
    /// Basic `-O1`.
    #[serde(rename = "1")]
    O1,
    /// General `-O2`.
    #[serde(rename = "2")]
    O2,
    /// Size-oriented `-Os`.
    #[serde(rename = "size")]
    Size,
    /// Aggressive size-oriented `-Oz`.
    #[serde(rename = "min-size")]
    MinSize,
    /// Cycle-oriented `-Ocycles`.
    #[serde(rename = "cycles")]
    Cycles,
}

/// Signed-overflow policy.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum SignedOverflow {
    /// Wrap the two's-complement bit pattern.
    Wrap,
    /// Require a proof that overflow cannot occur.
    Error,
    /// Insert a runtime trap where overflow may occur.
    Trap,
}

/// Fixed-array bounds-check policy.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum BoundsChecks {
    /// Emit no runtime checks.
    Off,
    /// Check every index.
    Trap,
    /// Remove checks only when proven safe.
    ElideProven,
}

/// Memory configuration.
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct Memory {
    /// Zero-page allocation policy.
    pub zero_page: ZeroPage,
}

/// Zero-page availability and reservations.
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct ZeroPage {
    /// Inclusive address ranges available to the compiler.
    pub available: Vec<String>,
    /// Inclusive address ranges unavailable to the compiler.
    pub reserved: Vec<String>,
    /// Allocation priority strategy.
    pub strategy: ZeroPageStrategy,
}

/// Zero-page allocation strategy.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum ZeroPageStrategy {
    /// Prefer frequently accessed values.
    Frequency,
    /// Prefer values with the largest cycle savings.
    Cycles,
}

/// Debug artifact settings.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct Debug {
    /// Emit symbols.
    #[serde(default)]
    pub symbols: bool,
    /// Emit source maps.
    #[serde(default)]
    pub source_map: bool,
}

/// A manifest together with the source needed for precise diagnostics.
#[derive(Clone, Debug)]
pub struct ManifestDocument {
    path: PathBuf,
    source: String,
    manifest: Manifest,
}

impl ManifestDocument {
    /// Returns the manifest path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Returns the parsed manifest.
    #[must_use]
    pub const fn manifest(&self) -> &Manifest {
        &self.manifest
    }

    /// Builds a diagnostic attached to the first matching field name.
    #[must_use]
    pub fn field_error(
        &self,
        code: impl Into<String>,
        message: impl Into<String>,
        field: &str,
        label: impl Into<String>,
    ) -> Diagnostic {
        let offset = self.source.find(field).unwrap_or(0);
        Diagnostic::error(code, message).with_source(
            SourceFile::new(&self.path, &self.source),
            Span::new(offset, field.len()),
            label,
        )
    }
}

/// Reads, parses, and semantically validates a `NesC.toml` manifest.
///
/// # Errors
///
/// Returns one or more structured diagnostics for I/O, TOML, or semantic
/// failures.
pub fn load_manifest(path: &Path) -> Result<ManifestDocument, Vec<Diagnostic>> {
    let source = fs::read_to_string(path).map_err(|error| {
        vec![Diagnostic::error(
            "E0001",
            format!("could not read manifest `{}`: {error}", path.display()),
        )]
    })?;

    let manifest = toml::from_str::<Manifest>(&source).map_err(|error| {
        let span = error.span().map_or_else(
            || Span::new(0, 1),
            |range| Span::new(range.start, range.len()),
        );
        vec![
            Diagnostic::error("E0002", "invalid `NesC.toml` manifest")
                .with_source(
                    SourceFile::new(path, &source),
                    span,
                    error.message().to_owned(),
                )
                .with_help("fix the manifest syntax or unsupported field"),
        ]
    })?;

    let document = ManifestDocument {
        path: path.to_path_buf(),
        source,
        manifest,
    };
    let diagnostics = validate_manifest(&document);

    if diagnostics.is_empty() {
        Ok(document)
    } else {
        Err(diagnostics)
    }
}

fn validate_manifest(document: &ManifestDocument) -> Vec<Diagnostic> {
    let manifest = document.manifest();
    let mut diagnostics = Vec::new();

    if !valid_package_name(&manifest.package.name) {
        diagnostics.push(document.field_error(
            "E0100",
            format!("invalid package name `{}`", manifest.package.name),
            "name",
            "use ASCII letters, digits, `-`, or `_`, starting with a letter",
        ));
    }

    if !valid_semver(&manifest.package.version) {
        diagnostics.push(document.field_error(
            "E0101",
            format!("invalid package version `{}`", manifest.package.version),
            "version",
            "expected `major.minor.patch` using decimal integers",
        ));
    }

    if !safe_relative_path(&manifest.build.entry) {
        diagnostics.push(document.field_error(
            "E0102",
            "project entry must be a safe relative path",
            "entry",
            "absolute paths and parent-directory traversal are not allowed",
        ));
    }

    let mut assembly_paths = std::collections::BTreeSet::new();
    for path in &manifest.build.assembly {
        if !safe_relative_path(path) {
            diagnostics.push(document.field_error(
                "E0107",
                format!(
                    "assembly source `{}` must be a safe relative path",
                    path.display()
                ),
                "assembly",
                "absolute paths and parent-directory traversal are not allowed",
            ));
        } else if path.extension().and_then(|value| value.to_str()) != Some("s") {
            diagnostics.push(document.field_error(
                "E0107",
                format!(
                    "assembly source `{}` must use the `.s` extension",
                    path.display()
                ),
                "assembly",
                "expected a 6502 assembly source file",
            ));
        } else if !assembly_paths.insert(path) {
            diagnostics.push(document.field_error(
                "E0107",
                format!(
                    "assembly source `{}` is listed more than once",
                    path.display()
                ),
                "assembly",
                "duplicate assembly source",
            ));
        }
    }

    validate_cartridge(document, &mut diagnostics);

    if !(1..=256).contains(&manifest.compiler.stack_limit) {
        diagnostics.push(document.field_error(
            "E0106",
            "stack limit must be between 1 and 256 bytes",
            "stack-limit",
            "outside the 6502 hardware-stack capacity",
        ));
    }

    validate_zero_page(document, &mut diagnostics);
    diagnostics
}

fn validate_cartridge(document: &ManifestDocument, diagnostics: &mut Vec<Diagnostic>) {
    let cartridge = &document.manifest().cartridge;

    if !matches!(cartridge.mapper, 0 | 2 | 3) {
        diagnostics.push(
            document
                .field_error(
                    "E0103",
                    format!("mapper {} is not implemented", cartridge.mapper),
                    "mapper",
                    "only Mapper 0 (NROM), Mapper 2 (UxROM), and Mapper 3 (CNROM) are accepted",
                )
                .with_help("set `cartridge.mapper` to 0, 2, or 3"),
        );
        return;
    }

    if cartridge.submapper != 0 {
        diagnostics.push(document.field_error(
            "E0104",
            format!("Mapper {} requires submapper 0", cartridge.mapper),
            "submapper",
            "unsupported cartridge submapper",
        ));
    }

    match cartridge.mapper {
        0 if !matches!(cartridge.prg_rom_kib, 16 | 32) => {
            diagnostics.push(document.field_error(
                "E0104",
                "Mapper 0 PRG-ROM must be 16 or 32 KiB",
                "prg-rom-kib",
                "invalid NROM PRG-ROM capacity",
            ));
        }
        2 if cartridge.prg_rom_kib < 32
            || cartridge.prg_rom_kib > 4_096
            || cartridge.prg_rom_kib % 16 != 0 =>
        {
            diagnostics.push(document.field_error(
                "E0104",
                "Mapper 2 PRG-ROM must contain 2 to 256 complete 16 KiB banks",
                "prg-rom-kib",
                "invalid UxROM PRG-ROM capacity",
            ));
        }
        3 if !matches!(cartridge.prg_rom_kib, 16 | 32) => {
            diagnostics.push(document.field_error(
                "E0104",
                "Mapper 3 PRG-ROM must be 16 or 32 KiB",
                "prg-rom-kib",
                "invalid CNROM PRG-ROM capacity",
            ));
        }
        _ => {}
    }

    if cartridge.mapper == 3 {
        if cartridge.chr_rom_kib == 0
            || cartridge.chr_rom_kib % 8 != 0
            || cartridge.chr_rom_kib > 2_048
        {
            diagnostics.push(document.field_error(
                "E0104",
                "Mapper 3 CHR-ROM must contain 1 to 256 complete 8 KiB banks",
                "chr-rom-kib",
                "CNROM requires banked CHR ROM",
            ));
        }
    } else if !matches!(cartridge.chr_rom_kib, 0 | 8) {
        diagnostics.push(document.field_error(
            "E0104",
            format!("Mapper {} CHR-ROM must be 0 or 8 KiB", cartridge.mapper),
            "chr-rom-kib",
            "use zero for CHR RAM or eight for CHR ROM",
        ));
    }
}

fn validate_zero_page(document: &ManifestDocument, diagnostics: &mut Vec<Diagnostic>) {
    let zero_page = &document.manifest().memory.zero_page;
    let mut claimed = [None; 256];

    if zero_page.available.is_empty() {
        diagnostics.push(document.field_error(
            "E0105",
            "zero page must contain at least one available range",
            "available",
            "no storage is available to the compiler",
        ));
    }

    for (kind, ranges) in [
        ("available", &zero_page.available),
        ("reserved", &zero_page.reserved),
    ] {
        for range in ranges {
            let Some((start, end)) = parse_zero_page_range(range) else {
                diagnostics.push(document.field_error(
                    "E0105",
                    format!("invalid zero-page range `{range}`"),
                    kind,
                    "expected an inclusive range such as `0x00..0xEF`",
                ));
                continue;
            };

            for address in start..=end {
                let slot = &mut claimed[usize::from(address)];
                if let Some(previous) = slot {
                    diagnostics.push(document.field_error(
                        "E0105",
                        format!(
                            "zero-page address ${address:02X} appears in both `{previous}` and `{kind}` ranges"
                        ),
                        kind,
                        "overlapping zero-page range",
                    ));
                    break;
                }
                *slot = Some(kind);
            }
        }
    }
}

/// Parses an inclusive zero-page range accepted by the manifest format.
#[must_use]
pub fn parse_zero_page_range(value: &str) -> Option<(u8, u8)> {
    let (start, end) = value.split_once("..")?;
    let start = parse_u8(start)?;
    let end = parse_u8(end.strip_prefix('=').unwrap_or(end))?;
    (start <= end).then_some((start, end))
}

fn parse_u8(value: &str) -> Option<u8> {
    let value = value.trim();
    value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .map_or_else(
            || value.parse().ok(),
            |hex| u8::from_str_radix(hex, 16).ok(),
        )
}

fn valid_package_name(name: &str) -> bool {
    let mut characters = name.chars();
    characters
        .next()
        .is_some_and(|first| first.is_ascii_alphabetic())
        && characters
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '-' | '_'))
}

fn valid_semver(version: &str) -> bool {
    let parts = version.split('.').collect::<Vec<_>>();
    parts.len() == 3
        && parts
            .iter()
            .all(|part| !part.is_empty() && part.parse::<u64>().is_ok())
}

fn safe_relative_path(path: &Path) -> bool {
    !path.as_os_str().is_empty()
        && !path.is_absolute()
        && path
            .components()
            .all(|component| matches!(component, Component::Normal(_) | Component::CurDir))
}

#[cfg(test)]
mod tests {
    use super::{parse_zero_page_range, valid_package_name, valid_semver};

    #[test]
    fn parses_zero_page_ranges() {
        assert_eq!(parse_zero_page_range("0x00..0xEF"), Some((0x00, 0xEF)));
        assert_eq!(parse_zero_page_range("16..=31"), Some((16, 31)));
        assert_eq!(parse_zero_page_range("0x20..0x10"), None);
        assert_eq!(parse_zero_page_range("invalid"), None);
    }

    #[test]
    fn validates_package_names() {
        assert!(valid_package_name("pong-demo_2"));
        assert!(!valid_package_name("2-pong"));
        assert!(!valid_package_name("pong/demo"));
    }

    #[test]
    fn validates_simple_semantic_versions() {
        assert!(valid_semver("0.1.0"));
        assert!(!valid_semver("0.1"));
        assert!(!valid_semver("next"));
    }
}
