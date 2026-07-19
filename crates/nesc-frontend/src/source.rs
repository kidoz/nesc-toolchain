use std::collections::HashMap;
use std::path::{Path, PathBuf};

use nesc_diagnostics::{Diagnostic, SourceFile, Span};

/// Stable identifier for one source file in a frontend invocation.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SourceId(u32);

impl SourceId {
    /// Creates an identifier from its numeric representation.
    #[must_use]
    pub const fn new(value: u32) -> Self {
        Self(value)
    }

    /// Returns the numeric representation.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }
}

/// A byte range tied to a stable source identifier.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SourceSpan {
    /// Source containing the range.
    pub source: SourceId,
    /// First byte of the range.
    pub start: usize,
    /// Number of bytes in the range.
    pub len: usize,
}

impl SourceSpan {
    /// Creates a source range.
    #[must_use]
    pub const fn new(source: SourceId, start: usize, len: usize) -> Self {
        Self { source, start, len }
    }

    /// Returns a range covering both input ranges.
    #[must_use]
    pub fn through(self, end: Self) -> Self {
        if self.source != end.source {
            return self;
        }
        let limit = end.start.saturating_add(end.len);
        Self::new(self.source, self.start, limit.saturating_sub(self.start))
    }
}

/// Immutable source contents and display path.
#[derive(Clone, Debug)]
pub struct Source {
    id: SourceId,
    path: PathBuf,
    text: String,
}

impl Source {
    /// Returns the stable source identifier.
    #[must_use]
    pub const fn id(&self) -> SourceId {
        self.id
    }

    /// Returns the source path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Returns the original source text.
    #[must_use]
    pub fn text(&self) -> &str {
        &self.text
    }
}

/// Sources loaded by one frontend invocation.
#[derive(Clone, Debug, Default)]
pub struct SourceMap {
    sources: Vec<Source>,
    paths: HashMap<PathBuf, SourceId>,
}

impl SourceMap {
    /// Creates an empty source map.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds source text or returns the existing identifier for the path.
    pub fn add(&mut self, path: PathBuf, text: String) -> SourceId {
        if let Some(id) = self.paths.get(&path) {
            return *id;
        }
        let value = u32::try_from(self.sources.len()).expect("source count fits in u32");
        let id = SourceId::new(value);
        self.sources.push(Source {
            id,
            path: path.clone(),
            text,
        });
        self.paths.insert(path, id);
        id
    }

    /// Returns a source by identifier.
    #[must_use]
    pub fn get(&self, id: SourceId) -> Option<&Source> {
        self.sources.get(id.get() as usize)
    }

    /// Builds a source-attached error diagnostic.
    #[must_use]
    pub fn error(
        &self,
        code: &str,
        message: impl Into<String>,
        span: SourceSpan,
        label: impl Into<String>,
    ) -> Diagnostic {
        let diagnostic = Diagnostic::error(code, message);
        self.attach(diagnostic, span, label)
    }

    /// Attaches a source range and label when the source is available.
    #[must_use]
    pub fn attach(
        &self,
        diagnostic: Diagnostic,
        span: SourceSpan,
        label: impl Into<String>,
    ) -> Diagnostic {
        self.get(span.source).map_or(diagnostic.clone(), |source| {
            diagnostic.with_source(
                SourceFile::new(source.path(), source.text()),
                Span::new(span.start, span.len),
                label,
            )
        })
    }
}
