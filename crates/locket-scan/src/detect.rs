//! Internal token tokenization and detection helpers shared by scan and redact.

use crate::FindingKind;
use crate::rules::{EntropyRule, is_high_entropy_token_with_rule, is_provider_token};

#[derive(Debug, Clone, Copy)]
pub struct Detection<'a> {
    pub start: usize,
    pub end: usize,
    pub line: usize,
    pub column: usize,
    pub kind: FindingKind,
    pub marker: Option<&'a str>,
}

#[derive(Debug, Clone, Copy)]
struct Token<'a> {
    value: &'a str,
    start: usize,
    line: usize,
    column: usize,
}

#[derive(Debug, Clone, Copy)]
struct CandidateSegment<'a> {
    value: &'a str,
    start: usize,
    end: usize,
    relative_start: usize,
}

pub fn sensitive_detections(text: &str) -> Vec<Detection<'static>> {
    sensitive_detections_with_entropy_rule(text, EntropyRule::default())
}

pub fn sensitive_detections_with_entropy_rule(
    text: &str,
    entropy_rule: EntropyRule,
) -> Vec<Detection<'static>> {
    let mut detections = Vec::new();

    for token in printable_tokens(text) {
        for candidate in candidate_segments(token) {
            if is_provider_token(candidate.value) {
                detections.push(Detection {
                    start: candidate.start,
                    end: candidate.end,
                    line: token.line,
                    column: token.column + token.value[..candidate.relative_start].chars().count(),
                    kind: FindingKind::ProviderTokenPattern,
                    marker: None,
                });
            } else if is_high_entropy_token_with_rule(candidate.value, entropy_rule) {
                detections.push(Detection {
                    start: candidate.start,
                    end: candidate.end,
                    line: token.line,
                    column: token.column + token.value[..candidate.relative_start].chars().count(),
                    kind: FindingKind::HighEntropy,
                    marker: None,
                });
            }
        }
    }

    detections
}

pub fn line_column(text: &str, byte_index: usize) -> (usize, usize) {
    let mut line = 1;
    let mut column = 1;
    for character in text[..byte_index].chars() {
        if character == '\n' {
            line += 1;
            column = 1;
        } else {
            column += 1;
        }
    }
    (line, column)
}

fn candidate_segments(token: Token<'_>) -> Vec<CandidateSegment<'_>> {
    let mut candidates = Vec::new();
    let mut segment_start = 0;

    for (index, character) in token.value.char_indices() {
        if is_token_boundary(character) {
            push_candidate_segment(&mut candidates, token, segment_start, index);
            segment_start = index + character.len_utf8();
        }
    }

    push_candidate_segment(&mut candidates, token, segment_start, token.value.len());
    candidates
}

fn push_candidate_segment<'a>(
    candidates: &mut Vec<CandidateSegment<'a>>,
    token: Token<'a>,
    relative_start: usize,
    relative_end: usize,
) {
    if relative_start < relative_end {
        candidates.push(CandidateSegment {
            value: &token.value[relative_start..relative_end],
            start: token.start + relative_start,
            end: token.start + relative_end,
            relative_start,
        });
    }
}

const fn is_token_boundary(character: char) -> bool {
    matches!(
        character,
        '=' | ':' | '"' | '\'' | '`' | ',' | ';' | '(' | ')' | '[' | ']' | '{' | '}' | '<' | '>'
    )
}

fn printable_tokens(text: &str) -> Vec<Token<'_>> {
    let mut tokens = Vec::new();
    let mut token_start = None;
    let mut token_line = 1;
    let mut token_column = 1;
    let mut line = 1;
    let mut column = 1;

    for (index, character) in text.char_indices() {
        if character == '\n' {
            if let Some(start) = token_start.take() {
                tokens.push(Token {
                    value: &text[start..index],
                    start,
                    line: token_line,
                    column: token_column,
                });
            }
            line += 1;
            column = 1;
            continue;
        }

        if character.is_whitespace() || character.is_control() {
            if let Some(start) = token_start.take() {
                tokens.push(Token {
                    value: &text[start..index],
                    start,
                    line: token_line,
                    column: token_column,
                });
            }
        } else if token_start.is_none() {
            token_start = Some(index);
            token_line = line;
            token_column = column;
        }

        column += 1;
    }

    if let Some(start) = token_start {
        tokens.push(Token { value: &text[start..], start, line: token_line, column: token_column });
    }

    tokens
}
