use std::collections::{BTreeMap, HashSet};

use nesc_diagnostics::Diagnostic;

use crate::{MacroDefinition, SourceMap, SourceSpan, Token, TokenKind};

const EXPANSION_LIMIT: usize = 64;

pub(crate) fn expand(
    tokens: Vec<Token>,
    macros: &BTreeMap<String, MacroDefinition>,
    sources: &SourceMap,
    diagnostics: &mut Vec<Diagnostic>,
) -> Vec<Token> {
    let mut disabled = HashSet::new();
    expand_inner(tokens, macros, sources, diagnostics, &mut disabled, 0)
}

fn expand_inner(
    tokens: Vec<Token>,
    macros: &BTreeMap<String, MacroDefinition>,
    sources: &SourceMap,
    diagnostics: &mut Vec<Diagnostic>,
    disabled: &mut HashSet<String>,
    depth: usize,
) -> Vec<Token> {
    let mut output = Vec::new();
    let mut position = 0;
    while position < tokens.len() {
        let token = &tokens[position];
        let TokenKind::Identifier(name) = &token.kind else {
            output.push(token.clone());
            position += 1;
            continue;
        };
        let Some(definition) = macros.get(name) else {
            output.push(token.clone());
            position += 1;
            continue;
        };
        if disabled.contains(name) {
            output.push(token.clone());
            position += 1;
            continue;
        }
        if depth >= EXPANSION_LIMIT {
            diagnostics.push(
                sources
                    .error(
                        "E1016",
                        "macro expansion limit exceeded",
                        token.span,
                        "recursive expansion starts here",
                    )
                    .with_help("break the recursive macro definition"),
            );
            output.push(token.clone());
            position += 1;
            continue;
        }

        let (arguments, consumed, invocation_span) =
            if let Some(parameters) = &definition.parameters {
                if !tokens
                    .get(position + 1)
                    .is_some_and(|token| token.kind == TokenKind::LeftParen)
                {
                    output.push(token.clone());
                    position += 1;
                    continue;
                }
                let Some((arguments, end)) = collect_arguments(&tokens, position + 1) else {
                    diagnostics.push(sources.error(
                        "E1017",
                        format!("unterminated invocation of macro `{name}`"),
                        token.span,
                        "macro invocation starts here",
                    ));
                    output.push(token.clone());
                    position += 1;
                    continue;
                };
                if arguments.len() != parameters.len() {
                    diagnostics.push(sources.error(
                        "E1018",
                        format!(
                            "macro `{name}` expects {} argument(s), but {} were provided",
                            parameters.len(),
                            arguments.len()
                        ),
                        token.span.through(tokens[end].span),
                        "incorrect macro argument count",
                    ));
                    position = end + 1;
                    continue;
                }
                (
                    Some(
                        parameters
                            .iter()
                            .cloned()
                            .zip(arguments)
                            .collect::<BTreeMap<_, _>>(),
                    ),
                    end - position + 1,
                    token.span.through(tokens[end].span),
                )
            } else {
                (None, 1, token.span)
            };

        let mut replacement = lex_replacement(definition, invocation_span, sources, diagnostics);
        if let Some(arguments) = arguments {
            replacement = substitute(replacement, &arguments);
        }
        disabled.insert(name.clone());
        output.extend(expand_inner(
            replacement,
            macros,
            sources,
            diagnostics,
            disabled,
            depth + 1,
        ));
        disabled.remove(name);
        position += consumed;
    }
    output
}

fn collect_arguments(tokens: &[Token], open: usize) -> Option<(Vec<Vec<Token>>, usize)> {
    let mut arguments = Vec::<Vec<Token>>::new();
    let mut current = Vec::new();
    let mut depth = 0_usize;
    let mut position = open + 1;
    if tokens
        .get(position)
        .is_some_and(|token| token.kind == TokenKind::RightParen)
    {
        return Some((Vec::new(), position));
    }
    while position < tokens.len() {
        match tokens[position].kind {
            TokenKind::LeftParen => {
                depth += 1;
                current.push(tokens[position].clone());
            }
            TokenKind::RightParen if depth == 0 => {
                arguments.push(current);
                return Some((arguments, position));
            }
            TokenKind::RightParen => {
                depth -= 1;
                current.push(tokens[position].clone());
            }
            TokenKind::Comma if depth == 0 => arguments.push(std::mem::take(&mut current)),
            TokenKind::End => return None,
            _ => current.push(tokens[position].clone()),
        }
        position += 1;
    }
    None
}

fn lex_replacement(
    definition: &MacroDefinition,
    invocation_span: SourceSpan,
    sources: &SourceMap,
    diagnostics: &mut Vec<Diagnostic>,
) -> Vec<Token> {
    let diagnostic_start = diagnostics.len();
    let mut tokens = crate::lexer::lex_fragment(
        invocation_span.source,
        &definition.replacement,
        sources,
        diagnostics,
    );
    if matches!(tokens.last().map(|token| &token.kind), Some(TokenKind::End)) {
        tokens.pop();
    }
    for token in &mut tokens {
        token.span = invocation_span;
    }
    if diagnostics.len() > diagnostic_start {
        diagnostics.truncate(diagnostic_start);
        diagnostics.push(sources.error(
            "E1019",
            "invalid token in macro replacement",
            invocation_span,
            "macro expands here",
        ));
    }
    tokens
}

fn substitute(replacement: Vec<Token>, arguments: &BTreeMap<String, Vec<Token>>) -> Vec<Token> {
    let mut output = Vec::new();
    for token in replacement {
        if let TokenKind::Identifier(name) = &token.kind
            && let Some(argument) = arguments.get(name)
        {
            output.extend(argument.iter().cloned());
            continue;
        }
        output.push(token);
    }
    output
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    use crate::{MacroDefinition, PreprocessedFile, SourceMap, TokenKind};

    use super::expand;

    #[test]
    fn expands_function_macro_with_argument_tokens() {
        let source = "TWICE(3)";
        let mut sources = SourceMap::new();
        let id = sources.add(PathBuf::from("test.c"), source.to_owned());
        let file = PreprocessedFile::new(id, source.to_owned());
        let mut diagnostics = Vec::new();
        let tokens = crate::lexer::lex(&file, &sources, &mut diagnostics);
        let macros = BTreeMap::from([(
            "TWICE".to_owned(),
            MacroDefinition {
                parameters: Some(vec!["x".to_owned()]),
                replacement: "((x) + (x))".to_owned(),
            },
        )]);
        let expanded = expand(tokens, &macros, &sources, &mut diagnostics);
        assert!(diagnostics.is_empty());
        assert_eq!(
            expanded
                .iter()
                .filter(|token| matches!(token.kind, TokenKind::Integer(_)))
                .count(),
            2
        );
    }
}
