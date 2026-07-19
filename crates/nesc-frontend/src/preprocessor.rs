use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::path::{Component, Path, PathBuf};

use nesc_diagnostics::{Diagnostic, SourceFile, Span};

use crate::{SourceId, SourceMap};

/// A retained macro definition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MacroDefinition {
    /// Formal parameter names for a function-like macro.
    pub parameters: Option<Vec<String>>,
    /// Unexpanded replacement spelling.
    pub replacement: String,
}

/// Source text with inactive and directive lines blanked without moving bytes.
#[derive(Clone, Debug)]
pub struct PreprocessedFile {
    source_id: SourceId,
    text: String,
}

impl PreprocessedFile {
    pub(crate) fn new(source_id: SourceId, text: String) -> Self {
        Self { source_id, text }
    }

    /// Returns the original source identifier.
    #[must_use]
    pub const fn source_id(&self) -> SourceId {
        self.source_id
    }

    /// Returns text ready for lexical analysis.
    #[must_use]
    pub fn text(&self) -> &str {
        &self.text
    }
}

/// Ordered source files and preprocessor state for one translation unit.
#[derive(Clone, Debug)]
pub struct TranslationUnit {
    sources: SourceMap,
    files: Vec<PreprocessedFile>,
    macros: BTreeMap<String, MacroDefinition>,
}

impl TranslationUnit {
    /// Returns loaded sources.
    #[must_use]
    pub const fn sources(&self) -> &SourceMap {
        &self.sources
    }

    /// Returns source fragments in inclusion order.
    #[must_use]
    pub fn files(&self) -> &[PreprocessedFile] {
        &self.files
    }

    /// Returns retained macro definitions.
    #[must_use]
    pub const fn macros(&self) -> &BTreeMap<String, MacroDefinition> {
        &self.macros
    }
}

#[derive(Clone, Copy, Debug)]
struct Conditional {
    parent_active: bool,
    branch_taken: bool,
    active: bool,
    saw_else: bool,
}

struct Preprocessor<'a> {
    include_directories: &'a [PathBuf],
    sources: SourceMap,
    files: Vec<PreprocessedFile>,
    macros: BTreeMap<String, MacroDefinition>,
    completed: HashSet<PathBuf>,
    include_stack: Vec<PathBuf>,
    diagnostics: Vec<Diagnostic>,
}

pub(crate) fn preprocess(
    entry: &Path,
    include_directories: &[PathBuf],
) -> Result<TranslationUnit, Vec<Diagnostic>> {
    let mut processor = Preprocessor {
        include_directories,
        sources: SourceMap::new(),
        files: Vec::new(),
        macros: predefined_macros(),
        completed: HashSet::new(),
        include_stack: Vec::new(),
        diagnostics: Vec::new(),
    };
    processor.process_file(entry);

    if processor.diagnostics.is_empty() {
        Ok(TranslationUnit {
            sources: processor.sources,
            files: processor.files,
            macros: processor.macros,
        })
    } else {
        Err(processor.diagnostics)
    }
}

fn predefined_macros() -> BTreeMap<String, MacroDefinition> {
    BTreeMap::from([
        (
            "__NESC__".to_owned(),
            MacroDefinition {
                parameters: None,
                replacement: "1".to_owned(),
            },
        ),
        (
            "__NESC_VERSION__".to_owned(),
            MacroDefinition {
                parameters: None,
                replacement: "100".to_owned(),
            },
        ),
        (
            "__NESC_REGION_NTSC__".to_owned(),
            MacroDefinition {
                parameters: None,
                replacement: "1".to_owned(),
            },
        ),
        (
            "__NESC_MAPPER__".to_owned(),
            MacroDefinition {
                parameters: None,
                replacement: "0".to_owned(),
            },
        ),
    ])
}

impl Preprocessor<'_> {
    fn process_file(&mut self, requested_path: &Path) {
        let path = normalize_existing_path(requested_path);
        if self.completed.contains(&path) {
            return;
        }
        if let Some(position) = self.include_stack.iter().position(|item| item == &path) {
            let mut cycle = self.include_stack[position..]
                .iter()
                .map(|item| item.display().to_string())
                .collect::<Vec<_>>();
            cycle.push(path.display().to_string());
            self.diagnostics.push(
                Diagnostic::error("E1003", "active include cycle")
                    .with_help(format!("include chain: {}", cycle.join(" -> "))),
            );
            return;
        }

        let source = match fs::read_to_string(&path) {
            Ok(source) => source,
            Err(error) => {
                self.diagnostics.push(Diagnostic::error(
                    "E1000",
                    format!("could not read source `{}`: {error}", path.display()),
                ));
                return;
            }
        };
        let source_id = self.sources.add(path.clone(), source.clone());
        self.include_stack.push(path.clone());
        let filtered = self.process_contents(&path, &source);
        self.include_stack.pop();
        self.completed.insert(path);
        self.files.push(PreprocessedFile::new(source_id, filtered));
    }

    fn process_contents(&mut self, path: &Path, source: &str) -> String {
        let mut output = String::with_capacity(source.len());
        let mut conditionals = Vec::<Conditional>::new();

        for line in source.split_inclusive('\n') {
            let trimmed = line.trim_start();
            if let Some(directive) = trimmed.strip_prefix('#') {
                self.process_directive(
                    path,
                    source,
                    line,
                    directive.trim_start(),
                    &mut conditionals,
                );
                blank_line(&mut output, line);
            } else if current_active(&conditionals) {
                output.push_str(line);
            } else {
                blank_line(&mut output, line);
            }
        }

        if !source.is_empty() && !source.ends_with('\n') && output.len() < source.len() {
            output.extend(std::iter::repeat_n(' ', source.len() - output.len()));
        }
        if !conditionals.is_empty() {
            self.diagnostics.push(source_error(
                path,
                source,
                source.len().saturating_sub(1),
                1,
                "E1008",
                "unterminated preprocessor conditional",
                "expected `#endif`",
            ));
        }
        output
    }

    fn process_directive(
        &mut self,
        path: &Path,
        source: &str,
        line: &str,
        directive: &str,
        conditionals: &mut Vec<Conditional>,
    ) {
        let (name, rest) = split_word(directive);
        let active = current_active(conditionals);
        match name {
            "include" if active => self.include(path, source, line, rest.trim()),
            "define" if active => self.define(path, source, line, rest.trim()),
            "undef" if active => self.undefine(path, source, line, rest.trim()),
            "ifdef" => self.enter_conditional(conditionals, self.macros.contains_key(rest.trim())),
            "ifndef" => {
                self.enter_conditional(conditionals, !self.macros.contains_key(rest.trim()));
            }
            "if" => {
                let condition = evaluate_condition(rest.trim(), &self.macros).unwrap_or(false);
                self.enter_conditional(conditionals, condition);
            }
            "elif" => self.else_if(path, source, line, rest, conditionals),
            "else" => self.otherwise(path, source, line, conditionals),
            "endif" => {
                if conditionals.pop().is_none() {
                    self.directive_error(path, source, line, "E1007", "unmatched `#endif`");
                }
            }
            "error" if active => self.directive_error(
                path,
                source,
                line,
                "E1009",
                &format!("preprocessor error: {}", rest.trim()),
            ),
            "line" | "" => {}
            _ if !active => {}
            _ => self.directive_error(
                path,
                source,
                line,
                "E1004",
                &format!("unsupported preprocessor directive `#{name}`"),
            ),
        }
    }

    fn include(&mut self, including: &Path, source: &str, line: &str, spelling: &str) {
        let Some((name, quoted)) = parse_include(spelling) else {
            self.directive_error(
                including,
                source,
                line,
                "E1001",
                "malformed include directive",
            );
            return;
        };
        let Some(path) = self.resolve_include(including, name, quoted) else {
            self.directive_error(
                including,
                source,
                line,
                "E1002",
                &format!("include file `{name}` was not found"),
            );
            return;
        };
        self.process_file(&path);
    }

    fn resolve_include(&self, including: &Path, name: &str, quoted: bool) -> Option<PathBuf> {
        let requested = Path::new(name);
        if !safe_include_path(requested) {
            return None;
        }
        if quoted {
            if let Some(parent) = including.parent() {
                let candidate = parent.join(requested);
                if candidate.is_file() {
                    return Some(candidate);
                }
            }
        }
        self.include_directories
            .iter()
            .map(|directory| directory.join(requested))
            .find(|candidate| candidate.is_file())
    }

    fn define(&mut self, path: &Path, source: &str, line: &str, definition: &str) {
        let (head, replacement) = split_word(definition);
        if head.is_empty() {
            self.directive_error(path, source, line, "E1010", "macro name is missing");
            return;
        }
        if head.starts_with("__nesc_") {
            self.directive_error(
                path,
                source,
                line,
                "E1011",
                "reserved `__nesc_` macro names cannot be defined",
            );
            return;
        }

        let (name, parameters, replacement) = if let Some(open) = head.find('(') {
            let Some(close) = definition.find(')') else {
                self.directive_error(
                    path,
                    source,
                    line,
                    "E1012",
                    "unterminated macro parameter list",
                );
                return;
            };
            let name = &head[..open];
            let parameters = definition[open + 1..close]
                .split(',')
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(ToOwned::to_owned)
                .collect::<Vec<_>>();
            if definition[open + 1..close].contains("...") {
                self.directive_error(
                    path,
                    source,
                    line,
                    "E1015",
                    "variadic macros are not supported",
                );
                return;
            }
            (name, Some(parameters), definition[close + 1..].trim())
        } else {
            (head, None, replacement.trim())
        };

        if replacement.contains("##") || replacement.contains("# ") {
            self.directive_error(
                path,
                source,
                line,
                "E1013",
                "token pasting and stringification are not supported",
            );
            return;
        }
        self.macros.insert(
            name.to_owned(),
            MacroDefinition {
                parameters,
                replacement: replacement.to_owned(),
            },
        );
    }

    fn undefine(&mut self, path: &Path, source: &str, line: &str, name: &str) {
        if name.starts_with("__nesc_") {
            self.directive_error(
                path,
                source,
                line,
                "E1014",
                "reserved `__nesc_` macro names cannot be undefined",
            );
            return;
        }
        self.macros.remove(name);
    }

    fn enter_conditional(&self, conditionals: &mut Vec<Conditional>, condition: bool) {
        let parent_active = current_active(conditionals);
        conditionals.push(Conditional {
            parent_active,
            branch_taken: condition,
            active: parent_active && condition,
            saw_else: false,
        });
    }

    fn else_if(
        &mut self,
        path: &Path,
        source: &str,
        line: &str,
        expression: &str,
        conditionals: &mut [Conditional],
    ) {
        let condition = evaluate_condition(expression.trim(), &self.macros).unwrap_or(false);
        let Some(current) = conditionals.last_mut() else {
            self.directive_error(path, source, line, "E1007", "unmatched `#elif`");
            return;
        };
        if current.saw_else {
            self.directive_error(path, source, line, "E1007", "`#elif` after `#else`");
            return;
        }
        current.active = current.parent_active && !current.branch_taken && condition;
        current.branch_taken |= condition;
    }

    fn otherwise(
        &mut self,
        path: &Path,
        source: &str,
        line: &str,
        conditionals: &mut [Conditional],
    ) {
        let Some(current) = conditionals.last_mut() else {
            self.directive_error(path, source, line, "E1007", "unmatched `#else`");
            return;
        };
        if current.saw_else {
            self.directive_error(path, source, line, "E1007", "duplicate `#else`");
            return;
        }
        current.active = current.parent_active && !current.branch_taken;
        current.branch_taken = true;
        current.saw_else = true;
    }

    fn directive_error(
        &mut self,
        path: &Path,
        source: &str,
        line: &str,
        code: &str,
        message: &str,
    ) {
        let offset = line_offset(source, line);
        self.diagnostics.push(source_error(
            path,
            source,
            offset,
            line.trim_end_matches('\n').len().max(1),
            code,
            message,
            "invalid preprocessor directive",
        ));
    }
}

fn current_active(conditionals: &[Conditional]) -> bool {
    conditionals.last().is_none_or(|state| state.active)
}

fn evaluate_condition(
    expression: &str,
    macros: &BTreeMap<String, MacroDefinition>,
) -> Option<bool> {
    let expression = expression.trim();
    if let Some(name) = expression
        .strip_prefix("defined(")
        .and_then(|value| value.strip_suffix(')'))
    {
        return Some(macros.contains_key(name.trim()));
    }
    if let Some(name) = expression.strip_prefix("defined ") {
        return Some(macros.contains_key(name.trim()));
    }
    if let Some(expression) = expression.strip_prefix('!') {
        return evaluate_condition(expression, macros).map(|value| !value);
    }
    if let Some(definition) = macros.get(expression) {
        return evaluate_condition(&definition.replacement, macros);
    }
    parse_preprocessor_integer(expression).map(|value| value != 0)
}

fn parse_preprocessor_integer(value: &str) -> Option<u64> {
    let value = value.trim();
    if let Some(hex) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        u64::from_str_radix(hex, 16).ok()
    } else if let Some(binary) = value
        .strip_prefix("0b")
        .or_else(|| value.strip_prefix("0B"))
    {
        u64::from_str_radix(binary, 2).ok()
    } else {
        value.parse().ok()
    }
}

fn parse_include(spelling: &str) -> Option<(&str, bool)> {
    if let Some(rest) = spelling.strip_prefix('"') {
        rest.find('"').map(|end| (&rest[..end], true))
    } else if let Some(rest) = spelling.strip_prefix('<') {
        rest.find('>').map(|end| (&rest[..end], false))
    } else {
        None
    }
}

fn safe_include_path(path: &Path) -> bool {
    !path.is_absolute()
        && path
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
}

fn split_word(value: &str) -> (&str, &str) {
    value
        .find(char::is_whitespace)
        .map_or((value, ""), |index| (&value[..index], &value[index..]))
}

fn blank_line(output: &mut String, line: &str) {
    let content_len = line.strip_suffix('\n').map_or(line.len(), str::len);
    output.extend(std::iter::repeat_n(' ', content_len));
    if line.ends_with('\n') {
        output.push('\n');
    }
}

fn line_offset(source: &str, line: &str) -> usize {
    let source_start = source.as_ptr() as usize;
    let line_start = line.as_ptr() as usize;
    line_start.saturating_sub(source_start).min(source.len())
}

fn source_error(
    path: &Path,
    source: &str,
    start: usize,
    len: usize,
    code: &str,
    message: &str,
    label: &str,
) -> Diagnostic {
    Diagnostic::error(code, message).with_source(
        SourceFile::new(path, source),
        Span::new(start, len),
        label,
    )
}

fn normalize_existing_path(path: &Path) -> PathBuf {
    path.canonicalize().unwrap_or_else(|_| path.to_path_buf())
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::tempdir;

    use super::preprocess;

    #[test]
    fn follows_includes_and_preserves_source_offsets() {
        let directory = tempdir().expect("temporary directory");
        fs::write(
            directory.path().join("values.h"),
            "#define VALUE 7\nu8 value;\n",
        )
        .expect("header");
        fs::write(
            directory.path().join("main.c"),
            "#include \"values.h\"\nint main(void) { return 0; }\n",
        )
        .expect("source");

        let unit = preprocess(&directory.path().join("main.c"), &[]).expect("preprocessed");
        assert_eq!(unit.files.len(), 2);
        assert_eq!(unit.files[0].text.find("u8 value"), Some(16));
        assert!(unit.macros.contains_key("VALUE"));
    }

    #[test]
    fn rejects_active_include_cycles() {
        let directory = tempdir().expect("temporary directory");
        fs::write(directory.path().join("a.h"), "#include \"b.h\"\n").expect("a");
        fs::write(directory.path().join("b.h"), "#include \"a.h\"\n").expect("b");

        let error = preprocess(&directory.path().join("a.h"), &[]).expect_err("cycle");
        assert_eq!(error[0].code(), "E1003");
    }
}
