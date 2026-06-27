//! Helpers for pasteable CLI handoffs.

pub fn shell_quote(value: &str) -> String {
    if value.is_empty() {
        return "''".to_owned();
    }
    if value.chars().all(is_shell_safe_char) {
        return value.to_owned();
    }
    format!("'{}'", value.replace('\'', "'\\''"))
}

pub fn shell_words_command<I, S>(parts: I) -> String
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    parts.into_iter().map(|part| shell_quote(part.as_ref())).collect::<Vec<_>>().join(" ")
}

pub fn heredoc_command(command: &str, text: &str, base_delimiter: &str) -> String {
    let delimiter = heredoc_delimiter_for(text, base_delimiter);
    format!("cat <<'{delimiter}' | {command}\n{text}\n{delimiter}")
}

fn heredoc_delimiter_for(text: &str, base_delimiter: &str) -> String {
    let used_lines = text.lines().collect::<std::collections::BTreeSet<_>>();
    let mut delimiter = base_delimiter.to_owned();
    let mut suffix = 0_u32;
    while used_lines.contains(delimiter.as_str()) {
        suffix = suffix.saturating_add(1);
        delimiter = format!("{base_delimiter}_{suffix}");
    }
    delimiter
}

const fn is_shell_safe_char(value: char) -> bool {
    value.is_ascii_alphanumeric() || matches!(value, '_' | '-' | '.' | '/' | ':' | '@' | '%' | '+')
}
