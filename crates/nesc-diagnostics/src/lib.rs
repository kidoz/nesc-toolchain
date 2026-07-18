//! Structured, deterministic diagnostics shared across the toolchain.

use std::fmt::{self, Write as _};
use std::path::{Path, PathBuf};

/// Severity of a compiler diagnostic.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Severity {
    /// Compilation cannot continue successfully.
    Error,
    /// Compilation can continue, but the input is suspicious.
    Warning,
    /// Informational optimization or analysis feedback.
    Remark,
}

impl Severity {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Error => "error",
            Self::Warning => "warning",
            Self::Remark => "remark",
        }
    }
}

/// A byte range in a UTF-8 source file.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Span {
    /// First byte in the range.
    pub start: usize,
    /// Number of bytes covered by the range.
    pub len: usize,
}

impl Span {
    /// Creates a span from a start offset and byte length.
    #[must_use]
    pub const fn new(start: usize, len: usize) -> Self {
        Self { start, len }
    }
}

/// Source text and its display path.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceFile {
    path: PathBuf,
    text: String,
}

impl SourceFile {
    /// Creates an owned source file used when rendering diagnostics.
    #[must_use]
    pub fn new(path: impl Into<PathBuf>, text: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            text: text.into(),
        }
    }

    /// Returns the source path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Returns the source contents.
    #[must_use]
    pub fn text(&self) -> &str {
        &self.text
    }
}

/// A single structured diagnostic.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Diagnostic {
    severity: Severity,
    code: String,
    message: String,
    source: Option<SourceFile>,
    span: Option<Span>,
    label: Option<String>,
    help: Option<String>,
}

impl Diagnostic {
    /// Creates an error diagnostic.
    #[must_use]
    pub fn error(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self::new(Severity::Error, code, message)
    }

    /// Creates a warning diagnostic.
    #[must_use]
    pub fn warning(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self::new(Severity::Warning, code, message)
    }

    /// Creates a remark diagnostic.
    #[must_use]
    pub fn remark(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self::new(Severity::Remark, code, message)
    }

    fn new(severity: Severity, code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            severity,
            code: code.into(),
            message: message.into(),
            source: None,
            span: None,
            label: None,
            help: None,
        }
    }

    /// Attaches source text, a span, and a primary label.
    #[must_use]
    pub fn with_source(mut self, source: SourceFile, span: Span, label: impl Into<String>) -> Self {
        self.source = Some(source);
        self.span = Some(span);
        self.label = Some(label.into());
        self
    }

    /// Attaches a suggested correction or next action.
    #[must_use]
    pub fn with_help(mut self, help: impl Into<String>) -> Self {
        self.help = Some(help.into());
        self
    }

    /// Returns the diagnostic severity.
    #[must_use]
    pub const fn severity(&self) -> Severity {
        self.severity
    }

    /// Returns the stable diagnostic code.
    #[must_use]
    pub fn code(&self) -> &str {
        &self.code
    }

    /// Renders this diagnostic deterministically without terminal color.
    #[must_use]
    pub fn render(&self) -> String {
        let mut output = format!(
            "{}[{}]: {}\n",
            self.severity.as_str(),
            self.code,
            self.message
        );

        if let (Some(source), Some(span)) = (&self.source, self.span) {
            let location = locate(source.text(), span.start);
            let line_number_width = location.line.to_string().len();
            let marker_width = marker_width(source.text(), span, location.line_end);
            let label = self.label.as_deref().unwrap_or_default();

            let _ = writeln!(
                output,
                "  --> {}:{}:{}",
                source.path().display(),
                location.line,
                location.column
            );
            let _ = writeln!(
                output,
                "{space:>width$} |",
                space = "",
                width = line_number_width
            );
            let _ = writeln!(
                output,
                "{:>width$} | {}",
                location.line,
                &source.text()[location.line_start..location.line_end],
                width = line_number_width
            );
            let _ = writeln!(
                output,
                "{space:>width$} | {indent}{markers} {label}",
                space = "",
                width = line_number_width,
                indent = " ".repeat(location.column.saturating_sub(1)),
                markers = "^".repeat(marker_width)
            );
        }

        if let Some(help) = &self.help {
            let _ = writeln!(output, "  = help: {help}");
        }

        output
    }
}

impl fmt::Display for Diagnostic {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.render())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Location {
    line: usize,
    column: usize,
    line_start: usize,
    line_end: usize,
}

fn locate(source: &str, requested_offset: usize) -> Location {
    let offset = floor_char_boundary(source, requested_offset.min(source.len()));
    let line_start = source[..offset].rfind('\n').map_or(0, |index| index + 1);
    let line_end = source[offset..]
        .find('\n')
        .map_or(source.len(), |index| offset + index);
    let line = source[..line_start]
        .bytes()
        .filter(|byte| *byte == b'\n')
        .count()
        + 1;
    let column = source[line_start..offset].chars().count() + 1;

    Location {
        line,
        column,
        line_start,
        line_end,
    }
}

fn marker_width(source: &str, span: Span, line_end: usize) -> usize {
    let start = floor_char_boundary(source, span.start.min(source.len()));
    let end = floor_char_boundary(source, span.start.saturating_add(span.len).min(line_end));
    source[start..end].chars().count().max(1)
}

fn floor_char_boundary(source: &str, mut index: usize) -> usize {
    while !source.is_char_boundary(index) {
        index -= 1;
    }
    index
}

#[cfg(test)]
mod tests {
    use super::{Diagnostic, Severity, SourceFile, Span};

    #[test]
    fn renders_source_location_and_help() {
        let diagnostic = Diagnostic::error("E1204", "value does not fit in `u8`")
            .with_source(
                SourceFile::new("src/main.c", "void main() {\n    u8 color = 300;\n}\n"),
                Span::new(29, 3),
                "expected a value from 0 to 255",
            )
            .with_help("use a representable value");

        let rendered = diagnostic.render();
        assert!(rendered.contains("error[E1204]: value does not fit in `u8`"));
        assert!(rendered.contains("--> src/main.c:2:16"));
        assert!(rendered.contains("^^^ expected a value from 0 to 255"));
        assert!(rendered.contains("= help: use a representable value"));
    }

    #[test]
    fn warning_exposes_its_severity_and_code() {
        let diagnostic = Diagnostic::warning("W0001", "example");
        assert_eq!(diagnostic.severity(), Severity::Warning);
        assert_eq!(diagnostic.code(), "W0001");
    }

    #[test]
    fn clamps_spans_to_utf8_boundaries() {
        let diagnostic = Diagnostic::error("E0001", "bad token").with_source(
            SourceFile::new("unicode.c", "é"),
            Span::new(1, 8),
            "token",
        );
        assert!(diagnostic.render().contains("unicode.c:1:1"));
    }
}
