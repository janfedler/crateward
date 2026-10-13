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

/// A moment in UTC, split into calendar fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Utc {
    /// Year.
    pub year: i64,
    /// Month, 1 to 12.
    pub month: i64,
    /// Day of the month, from 1.
    pub day: i64,
    /// Hour, 0 to 23.
    pub hour: i64,
    /// Minute.
    pub minute: i64,
    /// Second.
    pub second: i64,
}

impl Utc {
    /// Seconds since the epoch as calendar fields.
    #[must_use]
    pub const fn from_epoch(secs: i64) -> Self {
        let days = secs.div_euclid(86_400);
        let rest = secs.rem_euclid(86_400);

        // Civil date from days since 1970-01-01 (Howard Hinnant's algorithm).
        let z = days + 719_468;
        let era = z.div_euclid(146_097);
        let doe = z.rem_euclid(146_097);
        let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        let mp = (5 * doy + 2) / 153;
        let day = doy - (153 * mp + 2) / 5 + 1;
        let month = if mp < 10 { mp + 3 } else { mp - 9 };
        let year = yoe + era * 400 + if month <= 2 { 1 } else { 0 };

        Self {
            year,
            month,
            day,
            hour: rest / 3600,
            minute: (rest % 3600) / 60,
            second: rest % 60,
        }
    }

    /// RFC 3339 with a `Z`, as CycloneDX timestamps are written.
    #[must_use]
    pub fn rfc3339(self) -> String {
        format!(
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
            self.year, self.month, self.day, self.hour, self.minute, self.second
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epoch_seconds_become_rfc3339() {
        assert_eq!(Utc::from_epoch(0).rfc3339(), "1970-01-01T00:00:00Z");
        assert_eq!(
            Utc::from_epoch(1_790_000_000).rfc3339(),
            "2026-09-21T14:13:20Z"
        );
        assert_eq!(
            Utc::from_epoch(951_782_400).rfc3339(),
            "2000-02-29T00:00:00Z"
        );
        assert_eq!(Utc::from_epoch(-1).rfc3339(), "1969-12-31T23:59:59Z");
    }

    #[test]
    fn escapes_control_bidi_and_invisible_characters() {
        let shown: String = "a\0\u{1b}\u{85}\u{202e}\u{2063}\u{feff}é"
            .chars()
            .map(escape)
            .collect();

        assert_eq!(shown, "a\\u{0}\\u{1b}\\u{85}\\u{202e}\\u{2063}\\u{feff}é");
    }
}
