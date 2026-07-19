use nesc_diagnostics::Diagnostic;

use crate::{
    IntegerLiteral, IntegerSuffix, PreprocessedFile, SourceMap, SourceSpan, Token, TokenKind,
};

pub(crate) fn lex(
    file: &PreprocessedFile,
    sources: &SourceMap,
    diagnostics: &mut Vec<Diagnostic>,
) -> Vec<Token> {
    Lexer {
        source: file.text(),
        source_id: file.source_id(),
        offset: 0,
        sources,
        diagnostics,
        tokens: Vec::new(),
    }
    .run()
}

pub(crate) fn lex_fragment(
    source_id: crate::SourceId,
    source: &str,
    sources: &SourceMap,
    diagnostics: &mut Vec<Diagnostic>,
) -> Vec<Token> {
    Lexer {
        source,
        source_id,
        offset: 0,
        sources,
        diagnostics,
        tokens: Vec::new(),
    }
    .run()
}

struct Lexer<'a> {
    source: &'a str,
    source_id: crate::SourceId,
    offset: usize,
    sources: &'a SourceMap,
    diagnostics: &'a mut Vec<Diagnostic>,
    tokens: Vec<Token>,
}

impl Lexer<'_> {
    fn run(mut self) -> Vec<Token> {
        while self.offset < self.source.len() {
            self.skip_trivia();
            if self.offset >= self.source.len() {
                break;
            }
            let start = self.offset;
            let byte = self.bytes()[self.offset];
            if byte.is_ascii_alphabetic() || byte == b'_' {
                self.identifier(start);
            } else if byte.is_ascii_digit() {
                self.integer(start);
            } else if byte == b'"' {
                self.string(start);
            } else if byte == b'\'' {
                self.character(start);
            } else {
                self.punctuation(start);
            }
        }
        self.tokens.push(Token::new(
            TokenKind::End,
            SourceSpan::new(self.source_id, self.source.len(), 0),
        ));
        self.tokens
    }

    fn skip_trivia(&mut self) {
        loop {
            while self
                .bytes()
                .get(self.offset)
                .is_some_and(u8::is_ascii_whitespace)
            {
                self.offset += 1;
            }
            if self.starts_with("//") {
                self.offset += 2;
                while self.offset < self.source.len() && self.bytes()[self.offset] != b'\n' {
                    self.offset += 1;
                }
            } else if self.starts_with("/*") {
                let start = self.offset;
                self.offset += 2;
                if let Some(end) = self.source[self.offset..].find("*/") {
                    self.offset += end + 2;
                } else {
                    self.offset = self.source.len();
                    self.error(
                        "E1100",
                        "unterminated block comment",
                        start,
                        self.source.len().saturating_sub(start),
                        "comment starts here",
                    );
                }
            } else {
                break;
            }
        }
    }

    fn identifier(&mut self, start: usize) {
        self.offset += 1;
        while self
            .bytes()
            .get(self.offset)
            .is_some_and(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
        {
            self.offset += 1;
        }
        let spelling = &self.source[start..self.offset];
        let kind = match spelling {
            "void" => TokenKind::Void,
            "bool" => TokenKind::Bool,
            "static" => TokenKind::Static,
            "extern" => TokenKind::Extern,
            "const" => TokenKind::Const,
            "volatile" => TokenKind::Volatile,
            "struct" => TokenKind::Struct,
            "enum" => TokenKind::Enum,
            "typedef" => TokenKind::Typedef,
            "if" => TokenKind::If,
            "else" => TokenKind::Else,
            "while" => TokenKind::While,
            "for" => TokenKind::For,
            "break" => TokenKind::Break,
            "continue" => TokenKind::Continue,
            "return" => TokenKind::Return,
            "switch" => TokenKind::Switch,
            "case" => TokenKind::Case,
            "default" => TokenKind::Default,
            "true" => TokenKind::True,
            "false" => TokenKind::False,
            "unsigned" => TokenKind::Unsigned,
            "signed" => TokenKind::Signed,
            "char" => TokenKind::Char,
            "short" => TokenKind::Short,
            "int" => TokenKind::Int,
            "long" => TokenKind::Long,
            _ => TokenKind::Identifier(spelling.to_owned()),
        };
        self.push(kind, start);
    }

    fn integer(&mut self, start: usize) {
        let (radix, prefix) = if self.starts_with("0x") || self.starts_with("0X") {
            (16, 2)
        } else if self.starts_with("0b") || self.starts_with("0B") {
            (2, 2)
        } else {
            (10, 0)
        };
        self.offset += prefix;
        let digits_start = self.offset;
        while self
            .bytes()
            .get(self.offset)
            .is_some_and(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
        {
            self.offset += 1;
        }
        let spelling = &self.source[digits_start..self.offset];
        let suffix_start = spelling
            .find(|character: char| !character.is_digit(radix) && character != '_')
            .unwrap_or(spelling.len());
        let digits = spelling[..suffix_start].replace('_', "");
        let suffix_spelling = &spelling[suffix_start..];
        let suffix = match suffix_spelling {
            "" => None,
            "u8" => Some(IntegerSuffix::U8),
            "i8" => Some(IntegerSuffix::I8),
            "u16" => Some(IntegerSuffix::U16),
            "i16" => Some(IntegerSuffix::I16),
            "u24" => Some(IntegerSuffix::U24),
            "i24" => Some(IntegerSuffix::I24),
            "u32" => Some(IntegerSuffix::U32),
            "i32" => Some(IntegerSuffix::I32),
            _ => {
                self.error(
                    "E1102",
                    "invalid integer literal suffix",
                    start + prefix + suffix_start,
                    suffix_spelling.len().max(1),
                    "expected an exact NesC integer suffix",
                );
                None
            }
        };
        match u64::from_str_radix(&digits, radix) {
            Ok(value) if !digits.is_empty() => self.push(
                TokenKind::Integer(IntegerLiteral {
                    value,
                    radix,
                    suffix,
                }),
                start,
            ),
            _ => self.error(
                "E1101",
                "invalid integer literal",
                start,
                self.offset.saturating_sub(start),
                "digits do not match the literal radix",
            ),
        }
    }

    fn string(&mut self, start: usize) {
        self.offset += 1;
        let mut value = String::new();
        while self.offset < self.source.len() {
            match self.bytes()[self.offset] {
                b'"' => {
                    self.offset += 1;
                    self.push(TokenKind::String(value), start);
                    return;
                }
                b'\n' => break,
                b'\\' => {
                    self.offset += 1;
                    if let Some(byte) = self.escape(start) {
                        value.push(char::from(byte));
                    }
                }
                byte if byte.is_ascii() => {
                    value.push(char::from(byte));
                    self.offset += 1;
                }
                _ => {
                    let character = self.source[self.offset..]
                        .chars()
                        .next()
                        .expect("valid UTF-8");
                    value.push(character);
                    self.offset += character.len_utf8();
                }
            }
        }
        self.error(
            "E1103",
            "unterminated string literal",
            start,
            self.offset.saturating_sub(start).max(1),
            "string starts here",
        );
    }

    fn character(&mut self, start: usize) {
        self.offset += 1;
        let value = if self.bytes().get(self.offset) == Some(&b'\\') {
            self.offset += 1;
            self.escape(start)
        } else {
            self.bytes().get(self.offset).copied().inspect(|_| {
                self.offset += 1;
            })
        };
        if self.bytes().get(self.offset) != Some(&b'\'') {
            self.error(
                "E1104",
                "invalid character literal",
                start,
                self.offset.saturating_sub(start).max(1),
                "expected one byte and a closing quote",
            );
            while self.offset < self.source.len()
                && !matches!(self.bytes()[self.offset], b'\'' | b'\n')
            {
                self.offset += 1;
            }
            if self.bytes().get(self.offset) == Some(&b'\'') {
                self.offset += 1;
            }
            return;
        }
        self.offset += 1;
        if let Some(value) = value {
            self.push(TokenKind::Character(value), start);
        }
    }

    fn escape(&mut self, start: usize) -> Option<u8> {
        let value = match self.bytes().get(self.offset).copied() {
            Some(b'n') => b'\n',
            Some(b'r') => b'\r',
            Some(b't') => b'\t',
            Some(b'0') => 0,
            Some(b'\\') => b'\\',
            Some(b'\'') => b'\'',
            Some(b'"') => b'"',
            Some(_) => {
                self.error(
                    "E1105",
                    "unsupported escape sequence",
                    self.offset.saturating_sub(1),
                    2,
                    "unsupported escape",
                );
                self.offset += 1;
                return None;
            }
            None => {
                self.error(
                    "E1103",
                    "unterminated literal",
                    start,
                    self.offset.saturating_sub(start),
                    "literal starts here",
                );
                return None;
            }
        };
        self.offset += 1;
        Some(value)
    }

    fn punctuation(&mut self, start: usize) {
        const SYMBOLS: &[(&str, TokenKind)] = &[
            (">>=", TokenKind::ShiftRightEqual),
            ("<<=", TokenKind::ShiftLeftEqual),
            ("++", TokenKind::PlusPlus),
            ("--", TokenKind::MinusMinus),
            ("->", TokenKind::Arrow),
            ("==", TokenKind::EqualEqual),
            ("!=", TokenKind::BangEqual),
            ("<=", TokenKind::LessEqual),
            (">=", TokenKind::GreaterEqual),
            ("&&", TokenKind::AmpersandAmpersand),
            ("||", TokenKind::PipePipe),
            ("<<", TokenKind::ShiftLeft),
            (">>", TokenKind::ShiftRight),
            ("+=", TokenKind::PlusEqual),
            ("-=", TokenKind::MinusEqual),
            ("*=", TokenKind::StarEqual),
            ("/=", TokenKind::SlashEqual),
            ("%=", TokenKind::PercentEqual),
            ("&=", TokenKind::AmpersandEqual),
            ("|=", TokenKind::PipeEqual),
            ("^=", TokenKind::CaretEqual),
            ("(", TokenKind::LeftParen),
            (")", TokenKind::RightParen),
            ("{", TokenKind::LeftBrace),
            ("}", TokenKind::RightBrace),
            ("[", TokenKind::LeftBracket),
            ("]", TokenKind::RightBracket),
            (";", TokenKind::Semicolon),
            (",", TokenKind::Comma),
            (".", TokenKind::Dot),
            (":", TokenKind::Colon),
            ("?", TokenKind::Question),
            ("+", TokenKind::Plus),
            ("-", TokenKind::Minus),
            ("*", TokenKind::Star),
            ("/", TokenKind::Slash),
            ("%", TokenKind::Percent),
            ("&", TokenKind::Ampersand),
            ("|", TokenKind::Pipe),
            ("^", TokenKind::Caret),
            ("~", TokenKind::Tilde),
            ("!", TokenKind::Bang),
            ("=", TokenKind::Equal),
            ("<", TokenKind::Less),
            (">", TokenKind::Greater),
        ];
        if let Some((spelling, kind)) = SYMBOLS
            .iter()
            .find(|(spelling, _)| self.starts_with(spelling))
        {
            self.offset += spelling.len();
            self.push(kind.clone(), start);
        } else {
            let character = self.source[self.offset..]
                .chars()
                .next()
                .expect("offset is in source");
            self.offset += character.len_utf8();
            self.error(
                "E1106",
                format!("unexpected character `{character}`"),
                start,
                character.len_utf8(),
                "not part of NesC syntax",
            );
        }
    }

    fn push(&mut self, kind: TokenKind, start: usize) {
        self.tokens.push(Token::new(
            kind,
            SourceSpan::new(self.source_id, start, self.offset.saturating_sub(start)),
        ));
    }

    fn error(
        &mut self,
        code: &str,
        message: impl Into<String>,
        start: usize,
        len: usize,
        label: &str,
    ) {
        self.diagnostics.push(self.sources.error(
            code,
            message,
            SourceSpan::new(self.source_id, start, len),
            label,
        ));
    }

    fn bytes(&self) -> &[u8] {
        self.source.as_bytes()
    }

    fn starts_with(&self, value: &str) -> bool {
        self.source[self.offset..].starts_with(value)
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use crate::{PreprocessedFile, SourceMap, TokenKind};

    use super::lex;

    fn tokens(source: &str) -> (Vec<crate::Token>, Vec<nesc_diagnostics::Diagnostic>) {
        let mut sources = SourceMap::new();
        let id = sources.add(PathBuf::from("test.c"), source.to_owned());
        let file = PreprocessedFile::new(id, source.to_owned());
        let mut diagnostics = Vec::new();
        (lex(&file, &sources, &mut diagnostics), diagnostics)
    }

    #[test]
    fn lexes_exact_integer_suffix_and_operators() {
        let (tokens, diagnostics) = tokens("u8 x = 0x21u8; x <<= 1;");
        assert!(diagnostics.is_empty());
        assert!(matches!(tokens[0].kind, TokenKind::Identifier(ref name) if name == "u8"));
        assert!(matches!(tokens[3].kind, TokenKind::Integer(ref value) if value.value == 0x21));
        assert!(
            tokens
                .iter()
                .any(|token| token.kind == TokenKind::ShiftLeftEqual)
        );
    }

    #[test]
    fn diagnoses_unterminated_comment() {
        let (_, diagnostics) = tokens("int main(void) { /* missing");
        assert_eq!(diagnostics[0].code(), "E1100");
    }
}
