// Copyright 2026 Cyravell Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::model::AnalysisCompleteness;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuoteType {
    None,
    Single,
    Double,
    Mixed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokenKind {
    /// A regular command word or argument
    Word {
        raw: String,
        unquoted: String,
        quote_type: QuoteType,
    },
    /// Command separator: `;`
    Semicolon,
    /// Pipeline operator: `|`
    Pipe,
    /// Conditional AND: `&&`
    AndIf,
    /// Conditional OR: `||`
    OrIf,
    /// Asynchronous/background: `&`
    Ampersand,
    /// Output redirection: `>`
    RedirectOut(String),
    /// Append redirection: `>>`
    RedirectAppend(String),
    /// Input redirection: `<`
    RedirectIn(String),
    /// Standard error redirection: `2>`
    RedirectErr(String),
    /// Standard error append redirection: `2>>`
    RedirectErrAppend(String),
    /// Combined stdout & stderr: `&>` or `>&`
    RedirectAll(String),
    /// Command substitution: `$(...)` or backticks
    CommandSubstitution { content: String, is_backtick: bool },
    /// Environment variable expansion: `$VAR` or `${VAR}`
    VariableExpansion(String),
}

#[derive(Debug, Clone)]
pub struct Token {
    pub kind: TokenKind,
    pub start_pos: usize,
    pub end_pos: usize,
}

pub struct LexerResult {
    pub tokens: Vec<Token>,
    pub completeness: AnalysisCompleteness,
    pub notes: Vec<String>,
}

pub fn tokenize(input: &str) -> LexerResult {
    let mut tokens = Vec::new();
    let mut notes = Vec::new();
    let mut completeness = AnalysisCompleteness::Complete;

    let chars: Vec<(usize, char)> = input.char_indices().collect();
    let len = chars.len();
    let mut idx = 0;

    while idx < len {
        let (pos, c) = chars[idx];

        // 1. Whitespace
        if c.is_whitespace() {
            idx += 1;
            continue;
        }

        // 2. Operators outside quotes
        // Check 2-character operators first: &&, ||, >>, 2>, &>
        if idx + 1 < len {
            let next_c = chars[idx + 1].1;
            if c == '&' && next_c == '&' {
                tokens.push(Token {
                    kind: TokenKind::AndIf,
                    start_pos: pos,
                    end_pos: chars[idx + 1].0 + 1,
                });
                idx += 2;
                continue;
            }
            if c == '|' && next_c == '|' {
                tokens.push(Token {
                    kind: TokenKind::OrIf,
                    start_pos: pos,
                    end_pos: chars[idx + 1].0 + 1,
                });
                idx += 2;
                continue;
            }
            if c == '>' && next_c == '>' {
                tokens.push(Token {
                    kind: TokenKind::RedirectAppend(String::new()),
                    start_pos: pos,
                    end_pos: chars[idx + 1].0 + 1,
                });
                idx += 2;
                continue;
            }
            if c == '&' && next_c == '>' {
                tokens.push(Token {
                    kind: TokenKind::RedirectAll(String::new()),
                    start_pos: pos,
                    end_pos: chars[idx + 1].0 + 1,
                });
                idx += 2;
                continue;
            }
            if c == '2' && next_c == '>' {
                // Check if 2>>
                if idx + 2 < len && chars[idx + 2].1 == '>' {
                    tokens.push(Token {
                        kind: TokenKind::RedirectErrAppend(String::new()),
                        start_pos: pos,
                        end_pos: chars[idx + 2].0 + 1,
                    });
                    idx += 3;
                    continue;
                } else {
                    tokens.push(Token {
                        kind: TokenKind::RedirectErr(String::new()),
                        start_pos: pos,
                        end_pos: chars[idx + 1].0 + 1,
                    });
                    idx += 2;
                    continue;
                }
            }
        }

        // Single character operators
        if c == ';' {
            tokens.push(Token {
                kind: TokenKind::Semicolon,
                start_pos: pos,
                end_pos: pos + 1,
            });
            idx += 1;
            continue;
        }
        if c == '|' {
            tokens.push(Token {
                kind: TokenKind::Pipe,
                start_pos: pos,
                end_pos: pos + 1,
            });
            idx += 1;
            continue;
        }
        if c == '&' {
            tokens.push(Token {
                kind: TokenKind::Ampersand,
                start_pos: pos,
                end_pos: pos + 1,
            });
            idx += 1;
            continue;
        }
        if c == '>' {
            tokens.push(Token {
                kind: TokenKind::RedirectOut(String::new()),
                start_pos: pos,
                end_pos: pos + 1,
            });
            idx += 1;
            continue;
        }
        if c == '<' {
            tokens.push(Token {
                kind: TokenKind::RedirectIn(String::new()),
                start_pos: pos,
                end_pos: pos + 1,
            });
            idx += 1;
            continue;
        }

        // 3. Command substitution: $(...) or `...`
        if c == '$' && idx + 1 < len && chars[idx + 1].1 == '(' {
            let start = pos;
            idx += 2; // skip '$('
            let mut depth = 1;
            let mut sub_content = String::new();
            let mut closed = false;

            while idx < len {
                let (_, sc) = chars[idx];
                if sc == '(' {
                    depth += 1;
                    sub_content.push(sc);
                } else if sc == ')' {
                    depth -= 1;
                    if depth == 0 {
                        closed = true;
                        idx += 1;
                        break;
                    } else {
                        sub_content.push(sc);
                    }
                } else {
                    sub_content.push(sc);
                }
                idx += 1;
            }

            if !closed {
                completeness = AnalysisCompleteness::Partial;
                notes.push("Unclosed command substitution '$(' in input".to_string());
            }

            tokens.push(Token {
                kind: TokenKind::CommandSubstitution {
                    content: sub_content,
                    is_backtick: false,
                },
                start_pos: start,
                end_pos: if idx < len { chars[idx].0 } else { input.len() },
            });
            continue;
        }

        if c == '`' {
            let start = pos;
            idx += 1;
            let mut sub_content = String::new();
            let mut closed = false;

            while idx < len {
                let (_, sc) = chars[idx];
                if sc == '`' {
                    closed = true;
                    idx += 1;
                    break;
                }
                sub_content.push(sc);
                idx += 1;
            }

            if !closed {
                completeness = AnalysisCompleteness::Partial;
                notes.push("Unclosed backtick command substitution in input".to_string());
            }

            tokens.push(Token {
                kind: TokenKind::CommandSubstitution {
                    content: sub_content,
                    is_backtick: true,
                },
                start_pos: start,
                end_pos: if idx < len { chars[idx].0 } else { input.len() },
            });
            continue;
        }

        // 4. Words (can be quoted, unquoted, or mixed)
        let word_start = pos;
        let mut raw = String::new();
        let mut unquoted = String::new();
        let mut single_quotes_count = 0;
        let mut double_quotes_count = 0;

        while idx < len {
            let (_, wc) = chars[idx];

            // If we are at an operator or whitespace outside of quotes, break word
            if wc.is_whitespace() || wc == ';' || wc == '|' || wc == '&' || wc == '<' || wc == '>' {
                break;
            }

            if wc == '\'' {
                // Single quoted block
                raw.push('\'');
                idx += 1;
                single_quotes_count += 1;
                let mut closed = false;
                while idx < len {
                    let (_, sqc) = chars[idx];
                    raw.push(sqc);
                    idx += 1;
                    if sqc == '\'' {
                        closed = true;
                        break;
                    }
                    unquoted.push(sqc);
                }
                if !closed {
                    completeness = AnalysisCompleteness::Partial;
                    notes.push("Unclosed single quote in command word".to_string());
                }
            } else if wc == '"' {
                // Double quoted block
                raw.push('"');
                idx += 1;
                double_quotes_count += 1;
                let mut closed = false;
                while idx < len {
                    let (_, dqc) = chars[idx];
                    raw.push(dqc);
                    idx += 1;
                    if dqc == '\\' && idx < len {
                        // Escaped char inside double quote
                        let (_, esc) = chars[idx];
                        raw.push(esc);
                        idx += 1;
                        if esc == '"' || esc == '\\' || esc == '$' || esc == '`' {
                            unquoted.push(esc);
                        } else {
                            unquoted.push('\\');
                            unquoted.push(esc);
                        }
                    } else if dqc == '"' {
                        closed = true;
                        break;
                    } else {
                        unquoted.push(dqc);
                    }
                }
                if !closed {
                    completeness = AnalysisCompleteness::Partial;
                    notes.push("Unclosed double quote in command word".to_string());
                }
            } else if wc == '\\' {
                // Backslash escape outside quotes
                raw.push('\\');
                idx += 1;
                if idx < len {
                    let (_, esc) = chars[idx];
                    raw.push(esc);
                    unquoted.push(esc);
                    idx += 1;
                } else {
                    completeness = AnalysisCompleteness::Partial;
                    notes.push("Trailing backslash escape at end of command".to_string());
                }
            } else {
                // Normal character
                raw.push(wc);
                unquoted.push(wc);
                idx += 1;
            }
        }

        let quote_type = match (single_quotes_count > 0, double_quotes_count > 0) {
            (true, true) => QuoteType::Mixed,
            (true, false) => QuoteType::Single,
            (false, true) => QuoteType::Double,
            (false, false) => QuoteType::None,
        };

        tokens.push(Token {
            kind: TokenKind::Word {
                raw,
                unquoted,
                quote_type,
            },
            start_pos: word_start,
            end_pos: if idx < len { chars[idx].0 } else { input.len() },
        });
    }

    LexerResult {
        tokens,
        completeness,
        notes,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_quoted_semicolon_not_operator() {
        let res = tokenize("echo \"hello; rm -rf /\"");
        assert_eq!(res.completeness, AnalysisCompleteness::Complete);
        assert_eq!(res.tokens.len(), 2);

        match &res.tokens[0].kind {
            TokenKind::Word { unquoted, .. } => assert_eq!(unquoted, "echo"),
            _ => panic!("Expected Word"),
        }
        match &res.tokens[1].kind {
            TokenKind::Word {
                unquoted,
                quote_type,
                ..
            } => {
                assert_eq!(unquoted, "hello; rm -rf /");
                assert_eq!(*quote_type, QuoteType::Double);
            }
            _ => panic!("Expected Word"),
        }
    }

    #[test]
    fn test_escaped_semicolon_not_operator() {
        let res = tokenize("find . -exec ls {} \\;");
        assert_eq!(res.completeness, AnalysisCompleteness::Complete);
        // None of the tokens should be Semicolon
        for t in &res.tokens {
            assert!(!matches!(t.kind, TokenKind::Semicolon));
        }
    }

    #[test]
    fn test_operators_detected_outside_quotes() {
        let res = tokenize("cat file.txt | grep error && echo done; ls");
        assert_eq!(res.completeness, AnalysisCompleteness::Complete);

        let ops: Vec<&TokenKind> = res
            .tokens
            .iter()
            .map(|t| &t.kind)
            .filter(|k| matches!(k, TokenKind::Pipe | TokenKind::AndIf | TokenKind::Semicolon))
            .collect();

        assert_eq!(ops.len(), 3);
        assert!(matches!(ops[0], TokenKind::Pipe));
        assert!(matches!(ops[1], TokenKind::AndIf));
        assert!(matches!(ops[2], TokenKind::Semicolon));
    }

    #[test]
    fn test_unclosed_quote_marked_partial() {
        let res = tokenize("rm -rf \"unclosed");
        assert_eq!(res.completeness, AnalysisCompleteness::Partial);
        assert!(res
            .notes
            .iter()
            .any(|n| n.contains("Unclosed double quote")));
    }
}
