//! NesC project loading, validation, and starter generation.

mod manifest;
mod scaffold;

pub use manifest::{
    BoundsChecks, Manifest, ManifestDocument, Mirroring, Optimization, Region, RomFormat,
    SignedOverflow, ZeroPageStrategy, load_manifest,
};
pub use scaffold::create_project;

use std::path::{Path, PathBuf};

use nesc_diagnostics::Diagnostic;

/// A validated NesC project rooted beside its manifest.
#[derive(Clone, Debug)]
pub struct Project {
    root: PathBuf,
    document: ManifestDocument,
}

impl Project {
    /// Loads and validates a project manifest and its referenced entry source.
    ///
    /// # Errors
    ///
    /// Returns all diagnostics found while reading or validating the project.
    pub fn load(manifest_path: impl AsRef<Path>) -> Result<Self, Vec<Diagnostic>> {
        let document = load_manifest(manifest_path.as_ref())?;
        let root = document
            .path()
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .to_path_buf();
        let entry_path = root.join(&document.manifest().build.entry);
        let mut diagnostics = Vec::new();

        if document
            .manifest()
            .build
            .entry
            .extension()
            .and_then(|value| value.to_str())
            != Some("c")
        {
            diagnostics.push(document.field_error(
                "E0110",
                "the project entry must use the `.c` extension",
                "entry",
                "expected a NesC source file",
            ));
        }

        if !entry_path.is_file() {
            diagnostics.push(
                document
                    .field_error(
                        "E0111",
                        format!("project entry `{}` does not exist", entry_path.display()),
                        "entry",
                        "missing entry source",
                    )
                    .with_help("create the source file or update `build.entry`"),
            );
        }

        if diagnostics.is_empty() {
            Ok(Self { root, document })
        } else {
            Err(diagnostics)
        }
    }

    /// Returns the project root directory.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Returns the validated manifest.
    #[must_use]
    pub fn manifest(&self) -> &Manifest {
        self.document.manifest()
    }

    /// Returns the resolved entry-source path.
    #[must_use]
    pub fn entry_path(&self) -> PathBuf {
        self.root.join(&self.manifest().build.entry)
    }
}
