//! Read-only inspection of structured decompilation verification artifacts.

mod session;

pub use session::{
    DebugAddress, DebugCommandOutput, DebugPauseHandle, DebugSession, DebugSessionConfig,
    DebugSessionError, SourceLocation,
};

use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

const MAX_ARTIFACT_BYTES: u64 = 32 * 1024 * 1024;

/// Result recorded by differential verification.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum VerificationStatus {
    /// Every executed comparison matched.
    #[default]
    Passed,
    /// Verification stopped at the first divergence.
    Failed,
}

impl fmt::Display for VerificationStatus {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Passed => formatter.write_str("passed"),
            Self::Failed => formatter.write_str("failed"),
        }
    }
}

/// CPU register snapshot at a verified checkpoint.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct CpuCheckpoint {
    pub a: u8,
    pub x: u8,
    pub y: u8,
    pub sp: u8,
    pub status: u8,
    pub pc: u16,
}

/// One semantically observable event.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct VerificationEvent {
    pub kind: String,
    pub address: u16,
    pub value: u8,
}

/// A nonzero byte in a hardware address space.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct MemoryValue {
    pub address: u16,
    pub value: u8,
}

/// Sparse hardware state captured at a checkpoint.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct HardwareCheckpoint {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub apu_io: Vec<MemoryValue>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub chr_ram: Vec<MemoryValue>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub palette: Vec<MemoryValue>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub oam: Vec<MemoryValue>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub nametable_ram: Vec<MemoryValue>,
}

/// A successful interrupt or frame checkpoint comparison.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct VerificationCheckpoint {
    pub id: usize,
    pub kind: String,
    pub function: u32,
    pub entry_bank: u16,
    pub entry_address: u16,
    pub initial_bank: u16,
    pub status: u8,
    pub controller: u8,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub frame: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub semantic_instruction: Option<u16>,
    pub termination: String,
    pub cpu: CpuCheckpoint,
    pub mapper_prg_bank: u8,
    #[serde(default)]
    pub mapper_chr_bank: u8,
    pub event_count: usize,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub recent_events: Vec<VerificationEvent>,
    #[serde(default)]
    pub hardware: HardwareCheckpoint,
}

/// First mismatch observed by differential verification.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct VerificationDivergence {
    pub category: String,
    pub context: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub location: Option<String>,
    pub original: String,
    pub generated: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub recent_original_events: Vec<VerificationEvent>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub recent_generated_events: Vec<VerificationEvent>,
}

impl VerificationDivergence {
    /// Formats the divergence as one actionable diagnostic sentence.
    #[must_use]
    pub fn message(&self) -> String {
        let location = self
            .location
            .as_deref()
            .map_or_else(String::new, |value| format!(" at {value}"));
        format!(
            "{} differs{location} for {}: original {}, generated {}",
            self.category, self.context, self.original, self.generated
        )
    }
}

/// Versioned differential-verification artifact.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default)]
pub struct VerificationArtifact {
    pub schema_version: u32,
    pub mode: String,
    pub status: VerificationStatus,
    pub mapper: u16,
    pub prg_banks: usize,
    pub chr_banks: usize,
    pub functions: usize,
    pub input_profiles_per_bank_context: usize,
    pub switchable_bank_contexts: usize,
    pub executions: usize,
    pub direct_function_executions: usize,
    pub nmi_schedule_executions: usize,
    pub irq_schedule_executions: usize,
    pub frame_checkpoint_limit_per_bank_context: usize,
    pub frame_boundary_executions: usize,
    pub interrupt_schedule_instruction: u16,
    pub observable_events_compared: usize,
    pub semantic_event_capacity: usize,
    pub ram_bytes_compared_per_completed_execution: usize,
    pub prg_ram_bytes_compared_per_completed_execution: usize,
    pub apu_io_bytes_compared_per_completed_execution: usize,
    pub chr_ram_bytes_compared_per_completed_execution: usize,
    pub palette_bytes_compared_per_completed_execution: usize,
    pub oam_bytes_compared_per_completed_execution: usize,
    pub nametable_bytes_compared_per_completed_execution: usize,
    pub verification_workspace: String,
    pub semantic_instruction_limit_per_execution: u64,
    pub generated_instruction_limit_per_execution: u64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub checkpoints: Vec<VerificationCheckpoint>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub divergence: Option<VerificationDivergence>,
}

impl VerificationArtifact {
    /// Serializes the artifact as deterministic, readable JSON.
    pub fn to_json(&self) -> Result<String, DebugError> {
        let mut json = serde_json::to_string_pretty(self).map_err(DebugError::Json)?;
        json.push('\n');
        Ok(json)
    }
}

/// Read-only artifact view.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VerificationView {
    Summary,
    Checkpoints,
    Ppu,
    Apu,
    Cartridge,
    Trace,
    Divergence,
}

/// Artifact rendering request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DebugRequest {
    pub view: VerificationView,
    pub checkpoint: Option<usize>,
}

/// Artifact loading or rendering failure.
#[derive(Debug)]
pub enum DebugError {
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    TooLarge {
        path: PathBuf,
        bytes: u64,
    },
    Json(serde_json::Error),
    InvalidArtifact(String),
    UnsupportedSchema(u32),
    MissingCheckpoint(usize),
    NoCheckpoints,
}

impl fmt::Display for DebugError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { path, source } => {
                write!(formatter, "could not read `{}`: {source}", path.display())
            }
            Self::TooLarge { path, bytes } => write!(
                formatter,
                "verification artifact `{}` is {bytes} bytes; limit is {MAX_ARTIFACT_BYTES}",
                path.display()
            ),
            Self::Json(error) => write!(formatter, "invalid verification artifact: {error}"),
            Self::InvalidArtifact(message) => {
                write!(formatter, "invalid verification artifact: {message}")
            }
            Self::UnsupportedSchema(version) => {
                write!(
                    formatter,
                    "unsupported verification schema version {version}"
                )
            }
            Self::MissingCheckpoint(id) => {
                write!(formatter, "verification checkpoint {id} does not exist")
            }
            Self::NoCheckpoints => {
                formatter.write_str("verification artifact contains no checkpoints")
            }
        }
    }
}

impl std::error::Error for DebugError {}

/// Loads `verification.json` from a file or project directory.
pub fn load_verification(path: &Path) -> Result<VerificationArtifact, DebugError> {
    let path = if path.is_dir() {
        path.join("verification.json")
    } else {
        path.to_path_buf()
    };
    let metadata = fs::metadata(&path).map_err(|source| DebugError::Io {
        path: path.clone(),
        source,
    })?;
    if metadata.len() > MAX_ARTIFACT_BYTES {
        return Err(DebugError::TooLarge {
            path,
            bytes: metadata.len(),
        });
    }
    let contents = fs::read_to_string(&path).map_err(|source| DebugError::Io { path, source })?;
    parse_verification(&contents)
}

#[derive(Deserialize)]
struct ArtifactHeader {
    schema_version: u32,
    mode: String,
    status: VerificationStatus,
}

fn parse_verification(contents: &str) -> Result<VerificationArtifact, DebugError> {
    let header: ArtifactHeader = serde_json::from_str(contents).map_err(DebugError::Json)?;
    if header.schema_version != 1 {
        return Err(DebugError::UnsupportedSchema(header.schema_version));
    }
    if header.mode.trim().is_empty() {
        return Err(DebugError::InvalidArtifact(
            "`mode` must not be empty".to_owned(),
        ));
    }
    let _status = header.status;
    serde_json::from_str(contents).map_err(DebugError::Json)
}

/// Renders one human-readable verification view.
pub fn render_verification(
    artifact: &VerificationArtifact,
    request: DebugRequest,
) -> Result<String, DebugError> {
    match request.view {
        VerificationView::Summary => Ok(render_summary(artifact)),
        VerificationView::Checkpoints => Ok(render_checkpoints(artifact)),
        VerificationView::Divergence => Ok(render_divergence(artifact)),
        VerificationView::Ppu => {
            let checkpoint = select_checkpoint(artifact, request.checkpoint)?;
            let mut output = checkpoint_heading(checkpoint);
            render_memory(&mut output, "CHR RAM", &checkpoint.hardware.chr_ram);
            render_memory(&mut output, "palette", &checkpoint.hardware.palette);
            render_memory(&mut output, "OAM", &checkpoint.hardware.oam);
            render_memory(
                &mut output,
                "nametable RAM",
                &checkpoint.hardware.nametable_ram,
            );
            Ok(output)
        }
        VerificationView::Apu => {
            let checkpoint = select_checkpoint(artifact, request.checkpoint)?;
            let mut output = checkpoint_heading(checkpoint);
            render_memory(&mut output, "APU I/O", &checkpoint.hardware.apu_io);
            Ok(output)
        }
        VerificationView::Cartridge => {
            let checkpoint = select_checkpoint(artifact, request.checkpoint)?;
            Ok(format!(
                "Mapper {} with {} PRG banks and {} CHR banks\nCheckpoint {}: entry bank {}, initial mapper bank {}, final PRG bank {}, final CHR bank {}\n",
                artifact.mapper,
                artifact.prg_banks,
                artifact.chr_banks,
                checkpoint.id,
                checkpoint.entry_bank,
                checkpoint.initial_bank,
                checkpoint.mapper_prg_bank,
                checkpoint.mapper_chr_bank
            ))
        }
        VerificationView::Trace => {
            let checkpoint = select_checkpoint(artifact, request.checkpoint)?;
            let mut output = checkpoint_heading(checkpoint);
            if checkpoint.recent_events.is_empty() {
                output.push_str("No semantic events recorded.\n");
            } else {
                for event in &checkpoint.recent_events {
                    output.push_str(&format_event(event));
                }
            }
            Ok(output)
        }
    }
}

fn render_summary(artifact: &VerificationArtifact) -> String {
    let mut output = format!(
        "Verification {}\nMode: {}\nMapper: {}\nPRG banks: {}\nCHR banks: {}\nFunctions: {}\nExecutions: {}\nCheckpoints: {}\nObservable events: {}\n",
        artifact.status,
        artifact.mode,
        artifact.mapper,
        artifact.prg_banks,
        artifact.chr_banks,
        artifact.functions,
        artifact.executions,
        artifact.checkpoints.len(),
        artifact.observable_events_compared
    );
    if let Some(divergence) = &artifact.divergence {
        output.push_str("Divergence: ");
        output.push_str(&divergence.message());
        output.push('\n');
    }
    output
}

fn render_checkpoints(artifact: &VerificationArtifact) -> String {
    if artifact.checkpoints.is_empty() {
        return "No verification checkpoints recorded.\n".to_owned();
    }
    artifact
        .checkpoints
        .iter()
        .map(|checkpoint| {
            let position = checkpoint.semantic_instruction.map_or_else(
                || "completion".to_owned(),
                |instruction| format!("instruction {instruction}"),
            );
            format!(
                "{}: {} function {} prg:{:02X}:${:04X}, initial bank {}, {position}, PC ${:04X}, {} events\n",
                checkpoint.id,
                checkpoint.kind,
                checkpoint.function,
                checkpoint.entry_bank,
                checkpoint.entry_address,
                checkpoint.initial_bank,
                checkpoint.cpu.pc,
                checkpoint.event_count
            )
        })
        .collect()
}

fn render_divergence(artifact: &VerificationArtifact) -> String {
    let Some(divergence) = &artifact.divergence else {
        return "No divergence recorded.\n".to_owned();
    };
    let mut output = format!("{}\n", divergence.message());
    render_events(
        &mut output,
        "Recent original events",
        &divergence.recent_original_events,
    );
    render_events(
        &mut output,
        "Recent generated events",
        &divergence.recent_generated_events,
    );
    output
}

fn select_checkpoint(
    artifact: &VerificationArtifact,
    id: Option<usize>,
) -> Result<&VerificationCheckpoint, DebugError> {
    match id {
        Some(id) => artifact
            .checkpoints
            .iter()
            .find(|checkpoint| checkpoint.id == id)
            .ok_or(DebugError::MissingCheckpoint(id)),
        None => artifact.checkpoints.last().ok_or(DebugError::NoCheckpoints),
    }
}

fn checkpoint_heading(checkpoint: &VerificationCheckpoint) -> String {
    format!(
        "Checkpoint {} ({}, function {}, PC ${:04X})\n",
        checkpoint.id, checkpoint.kind, checkpoint.function, checkpoint.cpu.pc
    )
}

fn render_memory(output: &mut String, name: &str, values: &[MemoryValue]) {
    output.push_str(name);
    output.push(':');
    if values.is_empty() {
        output.push_str(" all zero\n");
        return;
    }
    output.push('\n');
    for value in values {
        output.push_str(&format!(
            "  ${:04X} = ${:02X}\n",
            value.address, value.value
        ));
    }
}

fn render_events(output: &mut String, label: &str, events: &[VerificationEvent]) {
    if events.is_empty() {
        return;
    }
    output.push_str(label);
    output.push_str(":\n");
    for event in events {
        output.push_str(&format_event(event));
    }
}

fn format_event(event: &VerificationEvent) -> String {
    format!(
        "  {} ${:04X} = ${:02X}\n",
        event.kind, event.address, event.value
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn artifact() -> VerificationArtifact {
        VerificationArtifact {
            schema_version: 1,
            mode: "original-6502-vs-nesc".to_owned(),
            mapper: 2,
            prg_banks: 3,
            functions: 4,
            executions: 12,
            checkpoints: vec![VerificationCheckpoint {
                id: 0,
                kind: "frame".to_owned(),
                function: 1,
                entry_bank: 2,
                entry_address: 0xc000,
                initial_bank: 0,
                cpu: CpuCheckpoint {
                    pc: 0xc010,
                    ..CpuCheckpoint::default()
                },
                mapper_prg_bank: 1,
                mapper_chr_bank: 0,
                event_count: 1,
                recent_events: vec![VerificationEvent {
                    kind: "mapper-write".to_owned(),
                    address: 0x8000,
                    value: 1,
                }],
                hardware: HardwareCheckpoint {
                    palette: vec![MemoryValue {
                        address: 0x3f00,
                        value: 0x0f,
                    }],
                    ..HardwareCheckpoint::default()
                },
                ..VerificationCheckpoint::default()
            }],
            ..VerificationArtifact::default()
        }
    }

    #[test]
    fn artifact_round_trips_and_renders_views() {
        let artifact = artifact();
        let json = artifact.to_json().expect("serialize artifact");
        let parsed: VerificationArtifact = serde_json::from_str(&json).expect("parse artifact");
        assert_eq!(parsed, artifact);
        let checkpoints = render_verification(
            &parsed,
            DebugRequest {
                view: VerificationView::Checkpoints,
                checkpoint: None,
            },
        )
        .expect("render checkpoints");
        assert!(checkpoints.contains("frame function 1"));
        let ppu = render_verification(
            &parsed,
            DebugRequest {
                view: VerificationView::Ppu,
                checkpoint: Some(0),
            },
        )
        .expect("render PPU");
        assert!(ppu.contains("$3F00 = $0F"));
    }

    #[test]
    fn reports_missing_checkpoint() {
        let error = render_verification(
            &artifact(),
            DebugRequest {
                view: VerificationView::Trace,
                checkpoint: Some(9),
            },
        )
        .expect_err("missing checkpoint");
        assert!(error.to_string().contains("checkpoint 9"));
    }

    #[test]
    fn rejects_missing_and_unknown_artifact_headers() {
        let missing = parse_verification("{}").expect_err("missing header");
        assert!(missing.to_string().contains("missing field"));
        let unknown = parse_verification(
            r#"{"schema_version":2,"mode":"original-6502-vs-nesc","status":"passed"}"#,
        )
        .expect_err("unknown schema");
        assert!(unknown.to_string().contains("schema version 2"));
    }
}
