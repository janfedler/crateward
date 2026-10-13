//! Text from hostile input, made safe to store and to show. Control
//! characters are escaped because PostgreSQL `jsonb` rejects NUL and
//! terminals act on escape sequences. Bidirectional and invisible
//! characters are escaped because they make a page show something other
//! than the bytes (Trojan Source).

/// Whether a character must not appear literally.
#[must_use]
pub fn must_escape(c: char) -> bool {
    c.is_control()
        || matches!(
            c,
            '\u{200B}'..='\u{200F}'
                | '\u{202A}'..='\u{202E}'
                | '\u{2060}'..='\u{2069}'
                | '\u{FEFF}'
        )
}

/// The character itself, or `\u{..}` if it [must be escaped](must_escape).
#[must_use]
pub fn escape(c: char) -> String {
    if must_escape(c) {
        format!("\\u{{{:x}}}", u32::from(c))
    } else {
        c.to_string()
    }
}

/// Replaces every honeytoken value in `text`. They are fake by
/// construction, but a reader should not have to know that.
#[must_use]
pub fn redact(text: &str, tokens: &[String]) -> String {
    tokens
        .iter()
        .filter(|t| !t.is_empty())
        .fold(text.to_owned(), |text, token| {
            text.replace(token.as_str(), "[honeytoken]")
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_control_bidi_and_invisible_characters() {
        let shown: String = "a\0\u{1b}\u{85}\u{202e}\u{2063}\u{feff}é"
            .chars()
            .map(escape)
            .collect();

        assert_eq!(shown, "a\\u{0}\\u{1b}\\u{85}\\u{202e}\\u{2063}\\u{feff}é");
    }
}
