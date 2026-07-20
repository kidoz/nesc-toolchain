use nesc_diagnostics::Diagnostic;

use crate::{
    AddressSpace, AssemblyClobbers, AssemblyInput, AssemblyOutput, AssemblyRegister, Attribute,
    BinaryOperator, Block, Declaration, Expression, ExpressionKind, Function, InlineAssembly,
    IntegerType, Linkage, NodeId, Parameter, Program, SourceMap, SourceSpan, Statement,
    StorageClass, Token, TokenKind, Type, TypeKind, UnaryOperator, Variable,
};

pub(crate) fn parse(
    tokens: Vec<Token>,
    sources: &SourceMap,
    diagnostics: &mut Vec<Diagnostic>,
) -> Option<Program> {
    Parser {
        tokens,
        position: 0,
        next_node: 0,
        sources,
        diagnostics,
    }
    .program()
}

struct Parser<'a> {
    tokens: Vec<Token>,
    position: usize,
    next_node: u32,
    sources: &'a SourceMap,
    diagnostics: &'a mut Vec<Diagnostic>,
}

#[derive(Clone, Copy)]
struct DeclarationPrefix {
    storage: StorageClass,
    linkage: Linkage,
    start: SourceSpan,
}

impl Parser<'_> {
    fn program(mut self) -> Option<Program> {
        let mut declarations = Vec::new();
        while !self.at(&TokenKind::End) {
            let before = self.position;
            if let Some(declaration) = self.declaration() {
                declarations.push(declaration);
            } else {
                self.synchronize_declaration();
            }
            if self.position == before {
                self.position += 1;
            }
        }
        if self.diagnostics.is_empty() {
            Some(Program { declarations })
        } else {
            None
        }
    }

    fn declaration(&mut self) -> Option<Declaration> {
        let attributes = self.attributes()?;
        let prefix = self.declaration_prefix();
        let mut ty = self.parse_type()?;
        let (name, name_span) = self.declarator(&mut ty, true)?;

        if self.consume(&TokenKind::LeftParen).is_some() {
            let parameters = self.parameters()?;
            let body = if self.at(&TokenKind::LeftBrace) {
                Some(self.block()?)
            } else {
                self.expect(
                    &TokenKind::Semicolon,
                    "E1202",
                    "expected `;` after function declaration",
                )?;
                None
            };
            let end = body
                .as_ref()
                .map_or_else(|| self.previous().span, |parsed_body| parsed_body.span);
            return Some(Declaration::Function(Function {
                id: self.node_id(),
                attributes,
                linkage: prefix.linkage,
                return_type: ty,
                name,
                parameters,
                body,
                span: prefix.start.through(end),
            }));
        }

        self.array_suffixes(&mut ty)?;
        let initializer = if self.consume(&TokenKind::Equal).is_some() {
            Some(self.expression()?)
        } else {
            None
        };
        let end = self.expect(
            &TokenKind::Semicolon,
            "E1202",
            "expected `;` after variable declaration",
        )?;
        Some(Declaration::Variable(Variable {
            id: self.node_id(),
            attributes,
            storage: prefix.storage,
            linkage: prefix.linkage,
            ty,
            name,
            initializer,
            span: prefix.start.through(end.span).through(name_span),
        }))
    }

    fn declaration_prefix(&mut self) -> DeclarationPrefix {
        let start = self.current().span;
        let storage = if self.consume(&TokenKind::Static).is_some() {
            StorageClass::Static
        } else if self.consume(&TokenKind::Extern).is_some() {
            StorageClass::Extern
        } else {
            StorageClass::Automatic
        };
        let linkage = if storage == StorageClass::Static {
            Linkage::Internal
        } else {
            Linkage::External
        };
        DeclarationPrefix {
            storage,
            linkage,
            start,
        }
    }

    fn attributes(&mut self) -> Option<Vec<Attribute>> {
        let mut attributes = Vec::new();
        while let TokenKind::Identifier(name) = &self.current().kind {
            let name = name.clone();
            if name == "__nesc_attribute__" {
                let start = self.advance().span;
                self.expect(
                    &TokenKind::LeftParen,
                    "E1201",
                    "expected `(` after reserved attribute syntax",
                )?;
                let (attribute_name, _) = self.identifier("expected an attribute name")?;
                let mut arguments = Vec::new();
                while self.consume(&TokenKind::Comma).is_some() {
                    arguments.push(self.expression()?);
                }
                let end = self.expect(
                    &TokenKind::RightParen,
                    "E1201",
                    "expected `)` after attribute",
                )?;
                attributes.push(Attribute {
                    name: attribute_name,
                    arguments,
                    span: start.through(end.span),
                });
                continue;
            }
            let Some(attribute_name) = sdk_attribute_name(&name) else {
                break;
            };
            let start = self.advance().span;
            let mut arguments = Vec::new();
            let end = if self.consume(&TokenKind::LeftParen).is_some() {
                if !self.at(&TokenKind::RightParen) {
                    loop {
                        arguments.push(self.expression()?);
                        if self.consume(&TokenKind::Comma).is_none() {
                            break;
                        }
                    }
                }
                self.expect(
                    &TokenKind::RightParen,
                    "E1201",
                    "expected `)` after attribute arguments",
                )?
                .span
            } else {
                start
            };
            attributes.push(Attribute {
                name: attribute_name.to_owned(),
                arguments,
                span: start.through(end),
            });
        }
        Some(attributes)
    }

    fn parse_type(&mut self) -> Option<Type> {
        let mut is_const = false;
        let mut is_volatile = false;
        while self.at(&TokenKind::Const) || self.at(&TokenKind::Volatile) {
            is_const |= self.consume(&TokenKind::Const).is_some();
            is_volatile |= self.consume(&TokenKind::Volatile).is_some();
        }

        if matches!(&self.current().kind, TokenKind::Identifier(name) if name == "ptr")
            && self
                .tokens
                .get(self.position + 1)
                .is_some_and(|token| token.kind == TokenKind::Less)
        {
            self.advance();
            self.expect(&TokenKind::Less, "E1202", "expected `<` after `ptr`")?;
            let (space, space_span) = self.identifier("expected an NES address space")?;
            let Some(address_space) = address_space(&space) else {
                self.error_at(
                    "E1206",
                    format!("unknown NES address space `{space}`"),
                    space_span,
                    "use a documented CPU-bus address space",
                );
                return None;
            };
            self.expect(
                &TokenKind::Comma,
                "E1202",
                "expected `,` after pointer address space",
            )?;
            let mut pointee = self.parse_type()?;
            self.expect(
                &TokenKind::Greater,
                "E1202",
                "expected `>` after pointer pointee type",
            )?;
            pointee.pointer_depth = pointee.pointer_depth.saturating_add(1);
            pointee.address_space = address_space;
            pointee.is_const |= is_const;
            pointee.is_volatile |= is_volatile;
            return Some(pointee);
        }

        let kind = match &self.current().kind {
            TokenKind::Void => {
                self.advance();
                TypeKind::Void
            }
            TokenKind::Bool => {
                self.advance();
                TypeKind::Bool
            }
            TokenKind::Identifier(name) => {
                let integer = integer_type_name(name)?;
                self.advance();
                TypeKind::Integer(integer)
            }
            TokenKind::Unsigned => {
                self.advance();
                TypeKind::Integer(self.c_integer_spelling(false))
            }
            TokenKind::Signed => {
                self.advance();
                TypeKind::Integer(self.c_integer_spelling(true))
            }
            TokenKind::Char => {
                self.advance();
                TypeKind::Integer(IntegerType::I8)
            }
            TokenKind::Short | TokenKind::Int => {
                self.advance();
                TypeKind::Integer(IntegerType::I16)
            }
            TokenKind::Long => {
                self.advance();
                TypeKind::Integer(IntegerType::I32)
            }
            _ => {
                self.error_current(
                    "E1200",
                    "expected a NesC type",
                    "use a fixed-width type such as `u8` or `i16`",
                );
                return None;
            }
        };

        while self.at(&TokenKind::Const) || self.at(&TokenKind::Volatile) {
            is_const |= self.consume(&TokenKind::Const).is_some();
            is_volatile |= self.consume(&TokenKind::Volatile).is_some();
        }
        Some(Type {
            kind,
            is_const,
            is_volatile,
            pointer_depth: 0,
            address_space: AddressSpace::Unknown,
            array_lengths: Vec::new(),
        })
    }

    fn c_integer_spelling(&mut self, signed: bool) -> IntegerType {
        if self.consume(&TokenKind::Char).is_some() {
            if signed {
                IntegerType::I8
            } else {
                IntegerType::U8
            }
        } else if self.consume(&TokenKind::Long).is_some() {
            if signed {
                IntegerType::I32
            } else {
                IntegerType::U32
            }
        } else {
            let _ = self.consume(&TokenKind::Short);
            let _ = self.consume(&TokenKind::Int);
            if signed {
                IntegerType::I16
            } else {
                IntegerType::U16
            }
        }
    }

    fn declarator(&mut self, ty: &mut Type, require_name: bool) -> Option<(String, SourceSpan)> {
        while self.consume(&TokenKind::Star).is_some() {
            ty.pointer_depth = ty.pointer_depth.saturating_add(1);
            while self.at(&TokenKind::Const) || self.at(&TokenKind::Volatile) {
                self.advance();
            }
        }
        if require_name {
            self.identifier("expected a declaration name")
        } else if matches!(self.current().kind, TokenKind::Identifier(_)) {
            self.identifier("expected a parameter name")
        } else {
            Some((String::new(), self.current().span))
        }
    }

    fn array_suffixes(&mut self, ty: &mut Type) -> Option<()> {
        while self.consume(&TokenKind::LeftBracket).is_some() {
            let token = self.advance().clone();
            let TokenKind::Integer(literal) = token.kind else {
                self.error_at(
                    "E1205",
                    "array length must be an integer literal",
                    token.span,
                    "expected a fixed length",
                );
                return None;
            };
            let Ok(length) = u32::try_from(literal.value) else {
                self.error_at(
                    "E1205",
                    "array length is too large",
                    token.span,
                    "length does not fit in 32 bits",
                );
                return None;
            };
            ty.array_lengths.push(length);
            self.expect(
                &TokenKind::RightBracket,
                "E1202",
                "expected `]` after array length",
            )?;
        }
        Some(())
    }

    fn parameters(&mut self) -> Option<Vec<Parameter>> {
        if self.at(&TokenKind::Void)
            && self
                .tokens
                .get(self.position + 1)
                .is_some_and(|token| token.kind == TokenKind::RightParen)
        {
            self.advance();
            self.advance();
            return Some(Vec::new());
        }
        if self.consume(&TokenKind::RightParen).is_some() {
            return Some(Vec::new());
        }
        let mut parameters = Vec::new();
        loop {
            let start = self.current().span;
            let mut ty = self.parse_type()?;
            let (name, name_span) = self.declarator(&mut ty, false)?;
            self.array_suffixes(&mut ty)?;
            parameters.push(Parameter {
                ty,
                name: (!name.is_empty()).then_some(name),
                span: start.through(name_span),
            });
            if self.consume(&TokenKind::Comma).is_none() {
                break;
            }
        }
        self.expect(
            &TokenKind::RightParen,
            "E1202",
            "expected `)` after parameters",
        )?;
        Some(parameters)
    }

    fn block(&mut self) -> Option<Block> {
        let start = self
            .expect(&TokenKind::LeftBrace, "E1202", "expected `{`")?
            .span;
        let mut statements = Vec::new();
        while !self.at(&TokenKind::RightBrace) && !self.at(&TokenKind::End) {
            let before = self.position;
            if let Some(statement) = self.statement() {
                statements.push(statement);
            } else {
                self.synchronize_statement();
            }
            if self.position == before {
                self.position += 1;
            }
        }
        let end = self.expect(&TokenKind::RightBrace, "E1202", "expected `}` after block")?;
        Some(Block {
            id: self.node_id(),
            statements,
            span: start.through(end.span),
        })
    }

    fn statement(&mut self) -> Option<Statement> {
        if self.at(&TokenKind::LeftBrace) {
            return self.block().map(Statement::Block);
        }
        if matches!(&self.current().kind, TokenKind::Identifier(name) if name == "NES_ASM") {
            return self.inline_assembly_statement();
        }
        if matches!(&self.current().kind, TokenKind::Identifier(name) if name == "asm") {
            return self.standard_inline_assembly_statement();
        }
        if self.consume(&TokenKind::If).is_some() {
            return self.if_statement();
        }
        if self.consume(&TokenKind::While).is_some() {
            return self.while_statement();
        }
        if self.consume(&TokenKind::For).is_some() {
            return self.for_statement();
        }
        if let Some(start) = self.consume(&TokenKind::Break) {
            let end = self.expect(&TokenKind::Semicolon, "E1202", "expected `;` after `break`")?;
            return Some(Statement::Break {
                id: self.node_id(),
                span: start.span.through(end.span),
            });
        }
        if let Some(start) = self.consume(&TokenKind::Continue) {
            let end = self.expect(
                &TokenKind::Semicolon,
                "E1202",
                "expected `;` after `continue`",
            )?;
            return Some(Statement::Continue {
                id: self.node_id(),
                span: start.span.through(end.span),
            });
        }
        if let Some(start) = self.consume(&TokenKind::Return) {
            let value = if self.at(&TokenKind::Semicolon) {
                None
            } else {
                Some(self.expression()?)
            };
            let end = self.expect(
                &TokenKind::Semicolon,
                "E1202",
                "expected `;` after return value",
            )?;
            return Some(Statement::Return {
                id: self.node_id(),
                value,
                span: start.span.through(end.span),
            });
        }
        if self.is_declaration_start() {
            return self.local_variable().map(Statement::Variable);
        }
        let start = self.current().span;
        let expression = if self.at(&TokenKind::Semicolon) {
            None
        } else {
            Some(self.expression()?)
        };
        let end = self.expect(
            &TokenKind::Semicolon,
            "E1202",
            "expected `;` after expression",
        )?;
        Some(Statement::Expression {
            id: self.node_id(),
            expression,
            span: start.through(end.span),
        })
    }

    fn inline_assembly_statement(&mut self) -> Option<Statement> {
        let start = self.advance().span;
        self.expect(
            &TokenKind::LeftParen,
            "E1202",
            "expected `(` after `NES_ASM`",
        )?;
        let mut template = String::new();
        while let TokenKind::String(value) = &self.current().kind {
            template.push_str(value);
            self.advance();
        }
        if template.is_empty() {
            self.error_current(
                "E1203",
                "`NES_ASM` requires a non-empty string literal",
                "assembly source required here",
            );
            return None;
        }

        let mut inputs = Vec::new();
        let mut outputs = Vec::new();
        let mut clobbers = AssemblyClobbers::default();
        let mut bank_effect = false;
        let mut calls = Vec::new();
        let mut stack_bytes = 0;
        let mut stack_declared = false;
        while self.consume(&TokenKind::Comma).is_some() {
            let (metadata, metadata_span) = self.identifier("expected `NES_ASM` metadata")?;
            match metadata.as_str() {
                "NES_CLOBBER_A" => clobbers.a = true,
                "NES_CLOBBER_X" => clobbers.x = true,
                "NES_CLOBBER_Y" => clobbers.y = true,
                "NES_CLOBBER_FLAGS" => clobbers.flags = true,
                "NES_CLOBBER_MEMORY" => clobbers.memory = true,
                "NES_ASM_BANK_EFFECT" => bank_effect = true,
                "NES_ASM_INPUT_A" | "NES_ASM_INPUT_X" | "NES_ASM_INPUT_Y" => {
                    let register = assembly_register(&metadata).expect("matched input register");
                    self.expect(
                        &TokenKind::LeftParen,
                        "E1202",
                        "expected `(` after assembly input",
                    )?;
                    let value = self.expression()?;
                    self.expect(
                        &TokenKind::RightParen,
                        "E1202",
                        "expected `)` after assembly input",
                    )?;
                    inputs.push(AssemblyInput { register, value });
                }
                "NES_ASM_OUTPUT_A" | "NES_ASM_OUTPUT_X" | "NES_ASM_OUTPUT_Y" => {
                    let register = assembly_register(&metadata).expect("matched output register");
                    self.expect(
                        &TokenKind::LeftParen,
                        "E1202",
                        "expected `(` after assembly output",
                    )?;
                    let (target, span) = self.identifier("expected an assembly output variable")?;
                    self.expect(
                        &TokenKind::RightParen,
                        "E1202",
                        "expected `)` after assembly output",
                    )?;
                    outputs.push(AssemblyOutput {
                        register,
                        target,
                        span,
                    });
                }
                "NES_ASM_CALL" => {
                    self.expect(
                        &TokenKind::LeftParen,
                        "E1202",
                        "expected `(` after `NES_ASM_CALL`",
                    )?;
                    let (callee, span) = self.identifier("expected a directly called function")?;
                    self.expect(
                        &TokenKind::RightParen,
                        "E1202",
                        "expected `)` after directly called function",
                    )?;
                    calls.push((callee, span));
                }
                "NES_ASM_STACK" => {
                    self.expect(
                        &TokenKind::LeftParen,
                        "E1202",
                        "expected `(` after `NES_ASM_STACK`",
                    )?;
                    let token = self.advance().clone();
                    let TokenKind::Integer(literal) = token.kind else {
                        self.error_at(
                            "E1203",
                            "assembly stack use must be an integer literal",
                            token.span,
                            "integer literal required here",
                        );
                        return None;
                    };
                    let Ok(bytes) = u16::try_from(literal.value) else {
                        self.error_at(
                            "E1204",
                            "assembly stack use exceeds 65535 bytes",
                            token.span,
                            "value is too large",
                        );
                        return None;
                    };
                    if stack_declared {
                        self.error_at(
                            "E1203",
                            "`NES_ASM_STACK` may only appear once",
                            metadata_span,
                            "duplicate stack declaration",
                        );
                        return None;
                    }
                    stack_declared = true;
                    stack_bytes = bytes;
                    self.expect(
                        &TokenKind::RightParen,
                        "E1202",
                        "expected `)` after assembly stack use",
                    )?;
                }
                _ => {
                    self.error_at(
                        "E1203",
                        format!("unknown `NES_ASM` metadata `{metadata}`"),
                        metadata_span,
                        "unsupported assembly contract item",
                    );
                    return None;
                }
            }
        }
        self.expect(
            &TokenKind::RightParen,
            "E1202",
            "expected `)` after `NES_ASM` metadata",
        )?;
        let end = self.expect(
            &TokenKind::Semicolon,
            "E1202",
            "expected `;` after `NES_ASM`",
        )?;
        Some(Statement::InlineAssembly(InlineAssembly {
            id: self.node_id(),
            template,
            inputs,
            outputs,
            clobbers,
            bank_effect,
            calls,
            stack_bytes,
            span: start.through(end.span),
        }))
    }

    fn standard_inline_assembly_statement(&mut self) -> Option<Statement> {
        let start = self.advance().span;
        self.expect(
            &TokenKind::Volatile,
            "E1202",
            "inline `asm` must be declared `volatile`",
        )?;
        self.expect(
            &TokenKind::LeftParen,
            "E1202",
            "expected `(` after `asm volatile`",
        )?;
        let mut template = String::new();
        while let TokenKind::String(value) = &self.current().kind {
            template.push_str(value);
            self.advance();
        }
        if template.is_empty() {
            self.error_current(
                "E1203",
                "inline `asm` requires a non-empty string literal",
                "assembly source required here",
            );
            return None;
        }
        self.expect(
            &TokenKind::Colon,
            "E1202",
            "expected `:` before assembly outputs",
        )?;
        let mut outputs = Vec::new();
        while !self.at(&TokenKind::Colon) {
            let token = self.advance().clone();
            let TokenKind::String(constraint) = token.kind else {
                self.error_at(
                    "E1203",
                    "assembly output requires a string constraint",
                    token.span,
                    "constraint required here",
                );
                return None;
            };
            let Some(register) = assembly_constraint(&constraint, true) else {
                self.error_at(
                    "E1203",
                    format!("unsupported assembly output constraint `{constraint}`"),
                    token.span,
                    "use `=a`, `=x`, or `=y`",
                );
                return None;
            };
            self.expect(
                &TokenKind::LeftParen,
                "E1202",
                "expected `(` after assembly output constraint",
            )?;
            let (target, span) = self.identifier("expected an assembly output variable")?;
            self.expect(
                &TokenKind::RightParen,
                "E1202",
                "expected `)` after assembly output",
            )?;
            outputs.push(AssemblyOutput {
                register,
                target,
                span,
            });
            if self.consume(&TokenKind::Comma).is_none() {
                break;
            }
        }
        self.expect(
            &TokenKind::Colon,
            "E1202",
            "expected `:` before assembly inputs",
        )?;
        let mut inputs = Vec::new();
        while !self.at(&TokenKind::Colon) {
            let token = self.advance().clone();
            let TokenKind::String(constraint) = token.kind else {
                self.error_at(
                    "E1203",
                    "assembly input requires a string constraint",
                    token.span,
                    "constraint required here",
                );
                return None;
            };
            let Some(register) = assembly_constraint(&constraint, false) else {
                self.error_at(
                    "E1203",
                    format!("unsupported assembly input constraint `{constraint}`"),
                    token.span,
                    "use `a`, `x`, or `y`",
                );
                return None;
            };
            self.expect(
                &TokenKind::LeftParen,
                "E1202",
                "expected `(` after assembly input constraint",
            )?;
            let value = self.expression()?;
            self.expect(
                &TokenKind::RightParen,
                "E1202",
                "expected `)` after assembly input",
            )?;
            inputs.push(AssemblyInput { register, value });
            if self.consume(&TokenKind::Comma).is_none() {
                break;
            }
        }
        self.expect(
            &TokenKind::Colon,
            "E1202",
            "expected `:` before assembly clobbers",
        )?;
        let mut clobbers = AssemblyClobbers::default();
        while !self.at(&TokenKind::RightParen) {
            let token = self.advance().clone();
            let TokenKind::String(clobber) = token.kind else {
                self.error_at(
                    "E1203",
                    "assembly clobber requires a string literal",
                    token.span,
                    "clobber name required here",
                );
                return None;
            };
            match clobber.as_str() {
                "a" => clobbers.a = true,
                "x" => clobbers.x = true,
                "y" => clobbers.y = true,
                "flags" => clobbers.flags = true,
                "memory" => clobbers.memory = true,
                _ => {
                    self.error_at(
                        "E1203",
                        format!("unsupported assembly clobber `{clobber}`"),
                        token.span,
                        "unknown clobber name",
                    );
                    return None;
                }
            }
            if self.consume(&TokenKind::Comma).is_none() {
                break;
            }
        }
        self.expect(
            &TokenKind::RightParen,
            "E1202",
            "expected `)` after inline assembly",
        )?;
        let end = self.expect(
            &TokenKind::Semicolon,
            "E1202",
            "expected `;` after inline assembly",
        )?;
        Some(Statement::InlineAssembly(InlineAssembly {
            id: self.node_id(),
            template,
            inputs,
            outputs,
            clobbers,
            bank_effect: false,
            calls: Vec::new(),
            stack_bytes: 0,
            span: start.through(end.span),
        }))
    }

    fn local_variable(&mut self) -> Option<Variable> {
        let attributes = self.attributes()?;
        let prefix = self.declaration_prefix();
        let mut ty = self.parse_type()?;
        let (name, _) = self.declarator(&mut ty, true)?;
        self.array_suffixes(&mut ty)?;
        let initializer = if self.consume(&TokenKind::Equal).is_some() {
            Some(self.expression()?)
        } else {
            None
        };
        let end = self.expect(
            &TokenKind::Semicolon,
            "E1202",
            "expected `;` after local variable",
        )?;
        Some(Variable {
            id: self.node_id(),
            attributes,
            storage: prefix.storage,
            linkage: Linkage::Internal,
            ty,
            name,
            initializer,
            span: prefix.start.through(end.span),
        })
    }

    fn if_statement(&mut self) -> Option<Statement> {
        let start = self.previous().span;
        self.expect(&TokenKind::LeftParen, "E1202", "expected `(` after `if`")?;
        let condition = self.expression()?;
        self.expect(
            &TokenKind::RightParen,
            "E1202",
            "expected `)` after condition",
        )?;
        let then_branch = Box::new(self.statement()?);
        let else_branch = if self.consume(&TokenKind::Else).is_some() {
            Some(Box::new(self.statement()?))
        } else {
            None
        };
        let end = else_branch
            .as_deref()
            .unwrap_or(then_branch.as_ref())
            .span();
        Some(Statement::If {
            id: self.node_id(),
            condition,
            then_branch,
            else_branch,
            span: start.through(end),
        })
    }

    fn while_statement(&mut self) -> Option<Statement> {
        let start = self.previous().span;
        self.expect(&TokenKind::LeftParen, "E1202", "expected `(` after `while`")?;
        let condition = self.expression()?;
        self.expect(
            &TokenKind::RightParen,
            "E1202",
            "expected `)` after condition",
        )?;
        let body = Box::new(self.statement()?);
        let span = start.through(body.span());
        Some(Statement::While {
            id: self.node_id(),
            condition,
            body,
            span,
        })
    }

    fn for_statement(&mut self) -> Option<Statement> {
        let start = self.previous().span;
        self.expect(&TokenKind::LeftParen, "E1202", "expected `(` after `for`")?;
        if self.is_declaration_start() {
            self.error_current(
                "E1211",
                "declarations in `for` initializers are not supported",
                "declare the loop variable before the loop",
            );
            return None;
        }
        let initializer = self.expression_until_semicolon()?;
        let condition = self.expression_until_semicolon()?;
        let increment = if self.at(&TokenKind::RightParen) {
            None
        } else {
            Some(self.expression()?)
        };
        self.expect(
            &TokenKind::RightParen,
            "E1202",
            "expected `)` after `for` clauses",
        )?;
        let body = Box::new(self.statement()?);
        let span = start.through(body.span());
        Some(Statement::For {
            id: self.node_id(),
            initializer,
            condition,
            increment,
            body,
            span,
        })
    }

    fn expression_until_semicolon(&mut self) -> Option<Option<Expression>> {
        let expression = if self.at(&TokenKind::Semicolon) {
            None
        } else {
            Some(self.expression()?)
        };
        self.expect(&TokenKind::Semicolon, "E1202", "expected `;` in `for`")?;
        Some(expression)
    }

    fn expression(&mut self) -> Option<Expression> {
        self.assignment()
    }

    fn assignment(&mut self) -> Option<Expression> {
        let target = self.binary(1)?;
        let operator = match self.current().kind {
            TokenKind::Equal => Some(BinaryOperator::Assign),
            TokenKind::PlusEqual => Some(BinaryOperator::Add),
            TokenKind::MinusEqual => Some(BinaryOperator::Subtract),
            TokenKind::StarEqual => Some(BinaryOperator::Multiply),
            TokenKind::SlashEqual => Some(BinaryOperator::Divide),
            TokenKind::PercentEqual => Some(BinaryOperator::Remainder),
            TokenKind::AmpersandEqual => Some(BinaryOperator::BitwiseAnd),
            TokenKind::PipeEqual => Some(BinaryOperator::BitwiseOr),
            TokenKind::CaretEqual => Some(BinaryOperator::BitwiseXor),
            TokenKind::ShiftLeftEqual => Some(BinaryOperator::ShiftLeft),
            TokenKind::ShiftRightEqual => Some(BinaryOperator::ShiftRight),
            _ => None,
        };
        let Some(operator) = operator else {
            return Some(target);
        };
        self.advance();
        let value = self.assignment()?;
        let span = target.span.through(value.span);
        Some(Expression {
            id: self.node_id(),
            kind: ExpressionKind::Assignment {
                operator,
                target: Box::new(target),
                value: Box::new(value),
            },
            ty: None,
            span,
        })
    }

    fn binary(&mut self, minimum_precedence: u8) -> Option<Expression> {
        let mut left = self.unary()?;
        while let Some((operator, precedence)) = binary_operator(&self.current().kind) {
            if precedence < minimum_precedence {
                break;
            }
            self.advance();
            let right = self.binary(precedence + 1)?;
            let span = left.span.through(right.span);
            left = Expression {
                id: self.node_id(),
                kind: ExpressionKind::Binary {
                    operator,
                    left: Box::new(left),
                    right: Box::new(right),
                },
                ty: None,
                span,
            };
        }
        Some(left)
    }

    fn unary(&mut self) -> Option<Expression> {
        let operator = match self.current().kind {
            TokenKind::Plus => Some(UnaryOperator::Plus),
            TokenKind::Minus => Some(UnaryOperator::Negate),
            TokenKind::Bang => Some(UnaryOperator::LogicalNot),
            TokenKind::Tilde => Some(UnaryOperator::BitwiseNot),
            TokenKind::Ampersand => Some(UnaryOperator::AddressOf),
            TokenKind::Star => Some(UnaryOperator::Dereference),
            TokenKind::PlusPlus => Some(UnaryOperator::Increment),
            TokenKind::MinusMinus => Some(UnaryOperator::Decrement),
            _ => None,
        };
        if let Some(operator) = operator {
            let start = self.advance().span;
            let operand = self.unary()?;
            let span = start.through(operand.span);
            return Some(Expression {
                id: self.node_id(),
                kind: ExpressionKind::Unary {
                    operator,
                    operand: Box::new(operand),
                },
                ty: None,
                span,
            });
        }
        if self.at(&TokenKind::LeftParen) && self.looks_like_cast() {
            let start = self.advance().span;
            let mut ty = self.parse_type()?;
            while self.consume(&TokenKind::Star).is_some() {
                ty.pointer_depth = ty.pointer_depth.saturating_add(1);
            }
            self.expect(
                &TokenKind::RightParen,
                "E1202",
                "expected `)` after cast type",
            )?;
            let expression = self.unary()?;
            let span = start.through(expression.span);
            return Some(Expression {
                id: self.node_id(),
                kind: ExpressionKind::Cast {
                    ty,
                    expression: Box::new(expression),
                },
                ty: None,
                span,
            });
        }
        self.postfix()
    }

    fn postfix(&mut self) -> Option<Expression> {
        let mut expression = self.primary()?;
        loop {
            if self.consume(&TokenKind::LeftParen).is_some() {
                let ExpressionKind::Name(function) = expression.kind else {
                    self.error_at(
                        "E1210",
                        "indirect function calls are not supported",
                        expression.span,
                        "call a named function directly",
                    );
                    return None;
                };
                let mut arguments = Vec::new();
                if !self.at(&TokenKind::RightParen) {
                    loop {
                        arguments.push(self.expression()?);
                        if self.consume(&TokenKind::Comma).is_none() {
                            break;
                        }
                    }
                }
                let end = self.expect(
                    &TokenKind::RightParen,
                    "E1202",
                    "expected `)` after call arguments",
                )?;
                expression = Expression {
                    id: self.node_id(),
                    kind: ExpressionKind::Call {
                        function,
                        arguments,
                    },
                    ty: None,
                    span: expression.span.through(end.span),
                };
            } else if self.consume(&TokenKind::LeftBracket).is_some() {
                let index = self.expression()?;
                let end = self.expect(
                    &TokenKind::RightBracket,
                    "E1202",
                    "expected `]` after index",
                )?;
                expression = Expression {
                    id: self.node_id(),
                    kind: ExpressionKind::Index {
                        base: Box::new(expression.clone()),
                        index: Box::new(index),
                    },
                    ty: None,
                    span: expression.span.through(end.span),
                };
            } else if self.at(&TokenKind::Dot) || self.at(&TokenKind::Arrow) {
                let through_pointer = self.consume(&TokenKind::Arrow).is_some();
                if !through_pointer {
                    self.advance();
                }
                let (field, field_span) = self.identifier("expected a field name")?;
                expression = Expression {
                    id: self.node_id(),
                    kind: ExpressionKind::Field {
                        base: Box::new(expression.clone()),
                        field,
                        through_pointer,
                    },
                    ty: None,
                    span: expression.span.through(field_span),
                };
            } else if self.at(&TokenKind::PlusPlus) || self.at(&TokenKind::MinusMinus) {
                let operator = if self.consume(&TokenKind::PlusPlus).is_some() {
                    UnaryOperator::Increment
                } else {
                    self.advance();
                    UnaryOperator::Decrement
                };
                let end = self.previous().span;
                expression = Expression {
                    id: self.node_id(),
                    kind: ExpressionKind::Postfix {
                        operator,
                        operand: Box::new(expression.clone()),
                    },
                    ty: None,
                    span: expression.span.through(end),
                };
            } else {
                break;
            }
        }
        Some(expression)
    }

    fn primary(&mut self) -> Option<Expression> {
        let token = self.advance().clone();
        let kind = match token.kind {
            TokenKind::Integer(value) => ExpressionKind::Integer(value),
            TokenKind::True => ExpressionKind::Boolean(true),
            TokenKind::False => ExpressionKind::Boolean(false),
            TokenKind::Character(value) => ExpressionKind::Character(value),
            TokenKind::String(value) => ExpressionKind::String(value),
            TokenKind::Identifier(name) => ExpressionKind::Name(name),
            TokenKind::LeftParen => {
                let mut expression = self.expression()?;
                let end = self.expect(
                    &TokenKind::RightParen,
                    "E1202",
                    "expected `)` after expression",
                )?;
                expression.span = token.span.through(end.span);
                return Some(expression);
            }
            _ => {
                self.error_at(
                    "E1203",
                    "expected an expression",
                    token.span,
                    "expression required here",
                );
                return None;
            }
        };
        Some(Expression {
            id: self.node_id(),
            kind,
            ty: None,
            span: token.span,
        })
    }

    fn looks_like_cast(&self) -> bool {
        self.tokens
            .get(self.position + 1)
            .is_some_and(|token| is_type_start(&token.kind))
    }

    fn is_declaration_start(&self) -> bool {
        let mut position = self.position;
        while self.tokens.get(position).is_some_and(|token| {
            matches!(token.kind, TokenKind::Static | TokenKind::Extern)
                || matches!(&token.kind, TokenKind::Identifier(name) if sdk_attribute_name(name).is_some())
        }) {
            position += 1;
        }
        self.tokens
            .get(position)
            .is_some_and(|token| is_type_start(&token.kind))
    }

    fn synchronize_declaration(&mut self) {
        while !self.at(&TokenKind::End) {
            if self.previous().kind == TokenKind::Semicolon {
                return;
            }
            if self.at(&TokenKind::RightBrace) || self.is_declaration_start() {
                return;
            }
            self.position += 1;
        }
    }

    fn synchronize_statement(&mut self) {
        while !self.at(&TokenKind::End) && !self.at(&TokenKind::RightBrace) {
            if self.previous().kind == TokenKind::Semicolon {
                return;
            }
            if matches!(
                self.current().kind,
                TokenKind::If
                    | TokenKind::While
                    | TokenKind::For
                    | TokenKind::Break
                    | TokenKind::Continue
                    | TokenKind::Return
            ) {
                return;
            }
            self.position += 1;
        }
    }

    fn identifier(&mut self, message: &str) -> Option<(String, SourceSpan)> {
        let token = self.advance().clone();
        if let TokenKind::Identifier(name) = token.kind {
            Some((name, token.span))
        } else {
            self.error_at("E1201", message, token.span, "identifier required here");
            None
        }
    }

    fn expect(&mut self, kind: &TokenKind, code: &str, message: &str) -> Option<Token> {
        if self.at(kind) {
            Some(self.advance().clone())
        } else {
            self.error_current(code, message, "unexpected token");
            None
        }
    }

    fn consume(&mut self, kind: &TokenKind) -> Option<Token> {
        if self.at(kind) {
            Some(self.advance().clone())
        } else {
            None
        }
    }

    fn at(&self, kind: &TokenKind) -> bool {
        same_variant(&self.current().kind, kind)
    }

    fn current(&self) -> &Token {
        &self.tokens[self.position.min(self.tokens.len() - 1)]
    }

    fn previous(&self) -> &Token {
        &self.tokens[self.position.saturating_sub(1)]
    }

    fn advance(&mut self) -> &Token {
        let position = self.position;
        if !self.at(&TokenKind::End) {
            self.position += 1;
        }
        &self.tokens[position]
    }

    fn node_id(&mut self) -> NodeId {
        let id = NodeId(self.next_node);
        self.next_node = self
            .next_node
            .checked_add(1)
            .expect("syntax node count fits u32");
        id
    }

    fn error_current(&mut self, code: &str, message: &str, label: &str) {
        self.error_at(code, message, self.current().span, label);
    }

    fn error_at(&mut self, code: &str, message: impl Into<String>, span: SourceSpan, label: &str) {
        self.diagnostics
            .push(self.sources.error(code, message, span, label));
    }
}

fn integer_type_name(name: &str) -> Option<IntegerType> {
    match name {
        "u8" => Some(IntegerType::U8),
        "i8" => Some(IntegerType::I8),
        "u16" => Some(IntegerType::U16),
        "i16" => Some(IntegerType::I16),
        "u24" => Some(IntegerType::U24),
        "i24" => Some(IntegerType::I24),
        "u32" => Some(IntegerType::U32),
        "i32" => Some(IntegerType::I32),
        "addr" => Some(IntegerType::Addr),
        "zp_addr" => Some(IntegerType::ZeroPageAddress),
        "bank" => Some(IntegerType::Bank),
        "tile" => Some(IntegerType::Tile),
        "palette" => Some(IntegerType::Palette),
        _ => None,
    }
}

fn assembly_register(name: &str) -> Option<AssemblyRegister> {
    if name.ends_with("_A") {
        Some(AssemblyRegister::A)
    } else if name.ends_with("_X") {
        Some(AssemblyRegister::X)
    } else if name.ends_with("_Y") {
        Some(AssemblyRegister::Y)
    } else {
        None
    }
}

fn assembly_constraint(constraint: &str, output: bool) -> Option<AssemblyRegister> {
    match (constraint, output) {
        ("a", false) | ("=a", true) => Some(AssemblyRegister::A),
        ("x", false) | ("=x", true) => Some(AssemblyRegister::X),
        ("y", false) | ("=y", true) => Some(AssemblyRegister::Y),
        _ => None,
    }
}

fn sdk_attribute_name(name: &str) -> Option<&'static str> {
    match name {
        "NES_MAIN" => Some("main"),
        "NES_RESET" => Some("reset"),
        "NES_NMI" => Some("nmi"),
        "NES_IRQ" => Some("irq"),
        "NES_ZEROPAGE" => Some("zero_page"),
        "NES_FIXED_BANK" => Some("fixed_bank"),
        "NES_BANK" => Some("bank"),
        "NES_SEGMENT" => Some("segment"),
        "NES_NOINLINE" => Some("noinline"),
        "NES_ALWAYS_INLINE" => Some("always_inline"),
        "NES_INTERRUPT_SAFE" => Some("interrupt_safe"),
        "NES_CYCLE_BUDGET" => Some("cycle_budget"),
        "NES_OPTIMIZE_SIZE" => Some("optimize_size"),
        "NES_OPTIMIZE_CYCLES" => Some("optimize_cycles"),
        "NES_ALIGN" => Some("align"),
        "NES_USED" => Some("used"),
        "NES_EXPORT" => Some("export"),
        "NES_IMPORT" => Some("import"),
        _ => None,
    }
}

fn is_type_start(kind: &TokenKind) -> bool {
    matches!(
        kind,
        TokenKind::Void
            | TokenKind::Bool
            | TokenKind::Const
            | TokenKind::Volatile
            | TokenKind::Unsigned
            | TokenKind::Signed
            | TokenKind::Char
            | TokenKind::Short
            | TokenKind::Int
            | TokenKind::Long
    ) || matches!(kind, TokenKind::Identifier(name) if integer_type_name(name).is_some() || name == "ptr")
}

fn address_space(name: &str) -> Option<AddressSpace> {
    match name {
        "unknown" => Some(AddressSpace::Unknown),
        "zero_page" => Some(AddressSpace::ZeroPage),
        "internal_ram" => Some(AddressSpace::InternalRam),
        "ppu_register" => Some(AddressSpace::PpuRegister),
        "apu_register" => Some(AddressSpace::ApuRegister),
        "io_register" => Some(AddressSpace::IoRegister),
        "prg_rom" => Some(AddressSpace::PrgRom),
        "prg_ram" => Some(AddressSpace::PrgRam),
        "chr_rom" => Some(AddressSpace::ChrRom),
        "chr_ram" => Some(AddressSpace::ChrRam),
        "mapper_register" => Some(AddressSpace::MapperRegister),
        _ => None,
    }
}

fn same_variant(left: &TokenKind, right: &TokenKind) -> bool {
    std::mem::discriminant(left) == std::mem::discriminant(right)
}

fn binary_operator(kind: &TokenKind) -> Option<(BinaryOperator, u8)> {
    match kind {
        TokenKind::PipePipe => Some((BinaryOperator::LogicalOr, 1)),
        TokenKind::AmpersandAmpersand => Some((BinaryOperator::LogicalAnd, 2)),
        TokenKind::Pipe => Some((BinaryOperator::BitwiseOr, 3)),
        TokenKind::Caret => Some((BinaryOperator::BitwiseXor, 4)),
        TokenKind::Ampersand => Some((BinaryOperator::BitwiseAnd, 5)),
        TokenKind::EqualEqual => Some((BinaryOperator::Equal, 6)),
        TokenKind::BangEqual => Some((BinaryOperator::NotEqual, 6)),
        TokenKind::Less => Some((BinaryOperator::Less, 7)),
        TokenKind::LessEqual => Some((BinaryOperator::LessEqual, 7)),
        TokenKind::Greater => Some((BinaryOperator::Greater, 7)),
        TokenKind::GreaterEqual => Some((BinaryOperator::GreaterEqual, 7)),
        TokenKind::ShiftLeft => Some((BinaryOperator::ShiftLeft, 8)),
        TokenKind::ShiftRight => Some((BinaryOperator::ShiftRight, 8)),
        TokenKind::Plus => Some((BinaryOperator::Add, 9)),
        TokenKind::Minus => Some((BinaryOperator::Subtract, 9)),
        TokenKind::Star => Some((BinaryOperator::Multiply, 10)),
        TokenKind::Slash => Some((BinaryOperator::Divide, 10)),
        TokenKind::Percent => Some((BinaryOperator::Remainder, 10)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use crate::{AssemblyRegister, Declaration, PreprocessedFile, SourceMap, Statement};

    use super::parse;

    #[test]
    fn parses_function_control_flow_and_attribute() {
        let source = "NES_MAIN int main(void) { u8 x = 1u8; while (x < 3) { x++; } return x; }";
        let mut sources = SourceMap::new();
        let id = sources.add(PathBuf::from("test.c"), source.to_owned());
        let file = PreprocessedFile::new(id, source.to_owned());
        let mut diagnostics = Vec::new();
        let tokens = crate::lexer::lex(&file, &sources, &mut diagnostics);
        let program = parse(tokens, &sources, &mut diagnostics).expect("program");
        assert!(diagnostics.is_empty());
        let Declaration::Function(function) = &program.declarations[0] else {
            panic!("function expected");
        };
        assert_eq!(function.attributes[0].name, "main");
        assert!(function.body.is_some());
    }

    #[test]
    fn parses_standard_volatile_inline_assembly() {
        let source = r#"
            NES_MAIN int main(void) {
                u8 input;
                u8 output;
                asm volatile ("tax" : "=x"(output) : "a"(input) : "flags");
                return output;
            }
        "#;
        let mut sources = SourceMap::new();
        let id = sources.add(PathBuf::from("test.c"), source.to_owned());
        let file = PreprocessedFile::new(id, source.to_owned());
        let mut diagnostics = Vec::new();
        let tokens = crate::lexer::lex(&file, &sources, &mut diagnostics);
        let program = parse(tokens, &sources, &mut diagnostics).expect("program");
        assert!(diagnostics.is_empty());
        let Declaration::Function(function) = &program.declarations[0] else {
            panic!("function expected");
        };
        let Statement::InlineAssembly(assembly) =
            &function.body.as_ref().expect("body").statements[2]
        else {
            panic!("inline assembly expected");
        };
        assert_eq!(assembly.template, "tax");
        assert_eq!(assembly.inputs[0].register, AssemblyRegister::A);
        assert_eq!(assembly.outputs[0].register, AssemblyRegister::X);
        assert!(assembly.clobbers.flags);
    }
}
