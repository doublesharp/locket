#![allow(clippy::panic)]
#![allow(clippy::unwrap_used)]
#[allow(unused_imports)]
use super::*;

use proptest::prelude::*;

fn valid_key_strategy() -> impl Strategy<Value = String> {
    let first = prop::char::ranges(std::borrow::Cow::Borrowed(&[
        'A'..='Z',
        '_'..='_',
    ]));
    let rest = prop::collection::vec(
        prop::char::ranges(std::borrow::Cow::Borrowed(&[
            'A'..='Z',
            '0'..='9',
            '_'..='_',
        ])),
        0..20,
    );
    (first, rest).prop_map(|(f, r)| {
        let mut s = String::new();
        s.push(f);
        s.extend(r);
        s
    })
}

fn clean_value_strategy() -> impl Strategy<Value = String> {
    prop::collection::vec(
        prop::char::ranges(std::borrow::Cow::Borrowed(&[
            ' '..='~',
        ]))
        .prop_filter("no NUL, no newline, no quote", |c| {
            *c != '\0' && *c != '\n' && *c != '\r' && *c != '"' && *c != '\''
        }),
        0..40,
    )
    .prop_map(|chars| chars.into_iter().collect())
}

proptest! {
    #[test]
    fn bare_assignment_round_trips(key in valid_key_strategy(), value in clean_value_strategy()) {
        let input = format!("{key}={value}\n");
        let entries = crate::parse_env_import(&input);
        prop_assert_eq!(entries.len(), 1);
        match &entries[0] {
            crate::EnvImportEntry::Secret { key: k, value: v } => {
                prop_assert_eq!(k.as_str(), key.as_str());
                prop_assert_eq!(v.as_str(), value.trim());
            }
            crate::EnvImportEntry::Invalid => {
                prop_assert!(false, "expected Secret, got Invalid for input: {input:?}");
            }
        }
    }

    #[test]
    fn double_quoted_value_is_unquoted(key in valid_key_strategy(), value in clean_value_strategy()) {
        let input = format!("{key}=\"{value}\"\n");
        let entries = crate::parse_env_import(&input);
        prop_assert_eq!(entries.len(), 1);
        match &entries[0] {
            crate::EnvImportEntry::Secret { value: v, .. } => {
                prop_assert_eq!(v.as_str(), value.as_str());
            }
            crate::EnvImportEntry::Invalid => {
                prop_assert!(false, "double-quoted value should parse as Secret");
            }
        }
    }

    #[test]
    fn single_quoted_value_is_unquoted(key in valid_key_strategy(), value in clean_value_strategy()) {
        let input = format!("{key}='{value}'\n");
        let entries = crate::parse_env_import(&input);
        prop_assert_eq!(entries.len(), 1);
        match &entries[0] {
            crate::EnvImportEntry::Secret { value: v, .. } => {
                prop_assert_eq!(v.as_str(), value.as_str());
            }
            crate::EnvImportEntry::Invalid => {
                prop_assert!(false, "single-quoted value should parse as Secret");
            }
        }
    }

    #[test]
    fn export_prefix_is_stripped(key in valid_key_strategy(), value in clean_value_strategy()) {
        let input = format!("export {key}={value}\n");
        let entries = crate::parse_env_import(&input);
        prop_assert_eq!(entries.len(), 1);
        match &entries[0] {
            crate::EnvImportEntry::Secret { key: k, .. } => {
                prop_assert_eq!(k.as_str(), key.as_str());
            }
            crate::EnvImportEntry::Invalid => {
                prop_assert!(false, "export-prefixed line should parse as Secret");
            }
        }
    }

    #[test]
    fn comment_lines_produce_no_entries(suffix in "[^\n]*") {
        let input = format!("#{suffix}\n");
        let entries = crate::parse_env_import(&input);
        prop_assert_eq!(entries.len(), 0, "comment lines must be filtered out");
    }

    #[test]
    fn blank_lines_produce_no_entries(spaces in " *") {
        let input = format!("{spaces}\n");
        let entries = crate::parse_env_import(&input);
        prop_assert_eq!(entries.len(), 0, "blank lines must be filtered out");
    }

    #[test]
    fn line_without_equals_is_invalid(key in valid_key_strategy()) {
        let input = format!("{key}\n");
        let entries = crate::parse_env_import(&input);
        prop_assert_eq!(entries.len(), 1);
        prop_assert!(
            matches!(entries[0], crate::EnvImportEntry::Invalid),
            "line without '=' must be Invalid"
        );
    }

    #[test]
    fn value_with_null_byte_is_invalid(key in valid_key_strategy(), suffix in "[a-zA-Z]*") {
        let input = format!("{key}=bad\x00{suffix}\n");
        let entries = crate::parse_env_import(&input);
        prop_assert_eq!(entries.len(), 1);
        prop_assert!(
            matches!(entries[0], crate::EnvImportEntry::Invalid),
            "null byte in value must be Invalid"
        );
    }

    #[test]
    fn unmatched_double_quote_is_invalid(key in valid_key_strategy(), value in "[a-zA-Z0-9]+") {
        let input = format!("{key}=\"{value}\n");
        let entries = crate::parse_env_import(&input);
        prop_assert_eq!(entries.len(), 1);
        prop_assert!(
            matches!(entries[0], crate::EnvImportEntry::Invalid),
            "unmatched leading double-quote must be Invalid for input: {input:?}"
        );
    }

    #[test]
    fn unmatched_single_quote_is_invalid(key in valid_key_strategy(), value in "[a-zA-Z0-9]+") {
        let input = format!("{key}='{value}\n");
        let entries = crate::parse_env_import(&input);
        prop_assert_eq!(entries.len(), 1);
        prop_assert!(
            matches!(entries[0], crate::EnvImportEntry::Invalid),
            "unmatched leading single-quote must be Invalid for input: {input:?}"
        );
    }

    #[test]
    fn multi_line_input_entry_count_matches_non_blank_non_comment_lines(
        keys in prop::collection::vec(valid_key_strategy(), 1..5),
        values in prop::collection::vec(clean_value_strategy(), 1..5),
    ) {
        let min_len = keys.len().min(values.len());
        let mut input = String::new();
        for i in 0..min_len {
            input.push_str(&format!("{}={}\n", keys[i], values[i]));
        }
        let entries = crate::parse_env_import(&input);
        prop_assert_eq!(entries.len(), min_len, "one entry per K=V line");
    }

    #[test]
    fn secret_values_never_exceed_raw_input_length(
        key in valid_key_strategy(),
        value in clean_value_strategy(),
    ) {
        let input = format!("{key}={value}\n");
        let entries = crate::parse_env_import(&input);
        if let Some(crate::EnvImportEntry::Secret { value: v, .. }) = entries.first() {
            prop_assert!(
                v.len() <= input.len(),
                "parsed value length should not exceed raw input length"
            );
        }
    }
}
