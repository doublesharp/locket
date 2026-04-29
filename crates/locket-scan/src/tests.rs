use super::{
    FindingKind, KnownRedaction, RULE_ID_HIGH_ENTROPY, ScanFinding, is_default_high_entropy_token,
    is_high_entropy_token, partition_inline_suppressions, redact_text,
    redact_text_with_known_values, scan_text, shannon_entropy,
};

#[test]
fn entropy_is_zero_for_empty_or_repeated_tokens() {
    assert!(shannon_entropy("").abs() < f64::EPSILON);
    assert!(shannon_entropy("aaaaaaaaaaaaaaaaaaaa").abs() < f64::EPSILON);
}

#[test]
fn default_rule_rejects_short_tokens() {
    assert!(!is_default_high_entropy_token("aB3$dE5&gH7*"));
}

#[test]
fn default_rule_rejects_whitespace_and_control_characters() {
    assert!(!is_default_high_entropy_token("abcd efgh ijkl mnop qrst uvwx yz12"));
    assert!(!is_default_high_entropy_token("abcd\nefghijklmnopqrstuvwxyz123456"));
}

#[test]
fn default_rule_flags_high_entropy_tokens() {
    assert!(is_default_high_entropy_token("Z9a$kLmN2pQx7R!sT4vW8yB3cD6eF"));
}

#[test]
fn custom_threshold_can_be_lowered() {
    assert!(is_high_entropy_token("abcabcabcabcabcabcab", 20, 1.0));
}

#[test]
fn scan_text_reports_metadata_without_token_values() {
    let token = "sk_live_sampleTokenValue123";
    let findings = scan_text("config.txt", &format!("prefix\n  {token}\n"));

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].path_label, "config.txt");
    assert_eq!(findings[0].line, 2);
    assert_eq!(findings[0].column, 3);
    assert_eq!(findings[0].token_length, token.len());
    assert_eq!(findings[0].kind, FindingKind::ProviderTokenPattern);
    assert!(!format!("{:?}", findings[0]).contains(token));
}

#[test]
fn scan_text_flags_default_high_entropy_tokens() {
    let token = "Z9a$kLmN2pQx7R!sT4vW8yB3cD6eF";
    let findings = scan_text("notes.txt", token);

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].line, 1);
    assert_eq!(findings[0].column, 1);
    assert_eq!(findings[0].token_length, token.len());
    assert_eq!(findings[0].kind, FindingKind::HighEntropy);
    assert!(!format!("{:?}", findings[0]).contains(token));
}

#[test]
fn scan_text_flags_env_file_names_without_reading_values() {
    let findings = scan_text("service/.env.local", "DATABASE_URL=postgres://user:pass@host/db");

    assert!(findings.iter().any(|finding| finding.kind == FindingKind::EnvFileMarker));
    assert!(!format!("{findings:?}").contains("postgres://user:pass@host/db"));
}

#[test]
fn redact_text_replaces_provider_and_high_entropy_tokens() {
    let provider = "github_pat_sampleTokenValue123";
    let entropy = "Z9a$kLmN2pQx7R!sT4vW8yB3cD6eF";
    let result = redact_text(&format!("token={provider}\nrandom={entropy}\n"));

    assert!(!result.text.contains(provider));
    assert!(!result.text.contains(entropy));
    assert!(result.text.contains("lk_redacted_PROVIDER_TOKEN"));
    assert!(result.text.contains("lk_redacted_HIGH_ENTROPY"));
    assert_eq!(result.counts.get(&FindingKind::ProviderTokenPattern), Some(&1));
    assert_eq!(result.counts.get(&FindingKind::HighEntropy), Some(&1));
}

#[test]
fn redact_text_replaces_known_values_with_specific_markers() {
    let result = redact_text_with_known_values(
        "db=postgres://localhost/app token=sk_test_sampleTokenValue123\n",
        &[KnownRedaction { value: "postgres://localhost/app", marker: "lk_redacted_DATABASE_URL" }],
    );

    assert!(!result.text.contains("postgres://localhost/app"));
    assert!(result.text.contains("db=lk_redacted_DATABASE_URL"));
    assert!(result.text.contains("token=lk_redacted_PROVIDER_TOKEN"));
    assert_eq!(result.counts.get(&FindingKind::KnownSecretValue), Some(&1));
    assert_eq!(result.counts.get(&FindingKind::ProviderTokenPattern), Some(&1));
}

#[test]
fn known_value_redaction_wins_over_pattern_redaction() {
    let provider = "sk_test_sampleTokenValue123";
    let result = redact_text_with_known_values(
        &format!("token={provider}\n"),
        &[KnownRedaction { value: provider, marker: "lk_redacted_OPENAI_API_KEY" }],
    );

    assert_eq!(result.text, "token=lk_redacted_OPENAI_API_KEY\n");
    assert_eq!(result.counts.get(&FindingKind::KnownSecretValue), Some(&1));
    assert_eq!(result.counts.get(&FindingKind::ProviderTokenPattern), None);
}

#[test]
fn longer_known_value_wins_when_known_values_start_together() {
    let result = redact_text_with_known_values(
        "token=abcdef",
        &[
            KnownRedaction { value: "abc", marker: "lk_redacted_SHORT" },
            KnownRedaction { value: "abcdef", marker: "lk_redacted_LONG" },
        ],
    );

    assert_eq!(result.text, "token=lk_redacted_LONG");
    assert_eq!(result.counts.get(&FindingKind::KnownSecretValue), Some(&1));
}

#[test]
fn empty_known_values_are_ignored() {
    let result = redact_text_with_known_values(
        "plain text",
        &[KnownRedaction { value: "", marker: "lk_redacted_EMPTY" }],
    );

    assert_eq!(result.text, "plain text");
    assert!(result.counts.is_empty());
}

#[test]
fn scan_text_reports_candidate_column_after_boundaries() {
    let token = "sk_live_sampleTokenValue123";
    let findings = scan_text("config.json", &format!("  api_key=\"{token}\""));

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].line, 1);
    assert_eq!(findings[0].column, 12);
    assert_eq!(findings[0].token_length, token.len());
    assert_eq!(findings[0].kind, FindingKind::ProviderTokenPattern);
}

#[test]
fn inline_suppression_removes_high_entropy_findings_on_same_line() {
    let entropy = "Z9a$kLmN2pQx7R!sT4vW8yB3cD6eF";
    let text = format!("token={entropy} # locket-allow: known random fixture\n");
    let findings = scan_text("notes.txt", &text);

    let result = partition_inline_suppressions(&text, findings);

    assert!(result.kept.is_empty());
    assert_eq!(result.suppressed.len(), 1);
    let suppressed = &result.suppressed[0];
    assert_eq!(suppressed.kind, FindingKind::HighEntropy);
    assert_eq!(suppressed.rule_id, RULE_ID_HIGH_ENTROPY);
    assert_eq!(suppressed.path_label, "notes.txt");
    assert_eq!(suppressed.line, 1);
    assert_eq!(suppressed.reason, "known random fixture");
    assert!(!format!("{suppressed:?}").contains(entropy));
}

#[test]
fn inline_suppression_supports_next_line_marker() {
    let entropy = "Z9a$kLmN2pQx7R!sT4vW8yB3cD6eF";
    let text = format!("// locket-allow-next-line: fixture\n{entropy}\n");
    let findings = scan_text("notes.txt", &text);

    let result = partition_inline_suppressions(&text, findings);

    assert!(result.kept.is_empty());
    assert_eq!(result.suppressed.len(), 1);
    assert_eq!(result.suppressed[0].kind, FindingKind::HighEntropy);
    assert_eq!(result.suppressed[0].line, 2);
    assert_eq!(result.suppressed[0].reason, "fixture");
}

#[test]
fn next_line_marker_skips_blank_lines_to_next_non_empty_line() {
    let entropy = "Z9a$kLmN2pQx7R!sT4vW8yB3cD6eF";
    let text = format!("// locket-allow-next-line\n\n   \n{entropy}\n");
    let findings = scan_text("notes.txt", &text);

    let result = partition_inline_suppressions(&text, findings);

    assert!(result.kept.is_empty());
    assert_eq!(result.suppressed.len(), 1);
    assert_eq!(result.suppressed[0].line, 4);
    assert_eq!(result.suppressed[0].reason, "");
}

#[test]
fn inline_suppression_does_not_silence_known_secret_matches() {
    let path = "leak.txt";
    let suppressed_finding = ScanFinding {
        path_label: path.to_owned(),
        line: 1,
        column: 1,
        token_length: 16,
        kind: FindingKind::KnownSecretValue,
    };
    let text = "secret-value # locket-allow: hide it\n";

    let result = partition_inline_suppressions(text, vec![suppressed_finding.clone()]);

    assert_eq!(result.kept, vec![suppressed_finding]);
    assert!(result.suppressed.is_empty());
}

#[test]
fn inline_suppression_does_not_silence_provider_token_or_env_file_findings() {
    let provider_token = "sk_live_sampleTokenValue123";
    let text = format!("token={provider_token} # locket-allow: nope\n");
    let findings = scan_text(".env.local", &text);

    let result = partition_inline_suppressions(&text, findings);

    assert!(result.suppressed.is_empty());
    assert!(result.kept.iter().any(|finding| finding.kind == FindingKind::ProviderTokenPattern));
    assert!(result.kept.iter().any(|finding| finding.kind == FindingKind::EnvFileMarker));
}

#[test]
fn next_line_marker_on_last_line_is_a_noop() {
    let text = "// locket-allow-next-line: nothing follows\n";
    let findings = scan_text("notes.txt", text);

    let result = partition_inline_suppressions(text, findings);

    assert!(result.kept.is_empty());
    assert!(result.suppressed.is_empty());
}

#[test]
fn line_marker_does_not_match_next_line_marker_substring() {
    let entropy = "Z9a$kLmN2pQx7R!sT4vW8yB3cD6eF";
    let text = format!("token={entropy} # locket-allow-next-line: previous-line note\n");
    let findings = scan_text("notes.txt", &text);

    let result = partition_inline_suppressions(&text, findings);

    assert_eq!(result.kept.len(), 1);
    assert_eq!(result.kept[0].kind, FindingKind::HighEntropy);
    assert!(result.suppressed.is_empty());
}
