//! A minimal DNS responder: every `A` question gets the fake internet's
//! address, everything else an empty answer.
//!
//! Only the header and the first question are parsed (RFC 1035 section
//! 4.1). Compression pointers are refused in questions, where no resolver
//! uses them, so parsing is a bounded forward scan.

use std::net::Ipv4Addr;

/// Query type `A`.
pub const TYPE_A: u16 = 1;

/// The first question of a query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Question {
    /// The name, dot separated, lowercase ASCII (other bytes escaped).
    pub name: String,
    /// Query type.
    pub qtype: u16,
    /// Query class.
    pub qclass: u16,
    /// Offset just past the question.
    end: usize,
}

fn u16_at(data: &[u8], at: usize) -> Option<u16> {
    let bytes = data.get(at..at.checked_add(2)?)?;
    Some(u16::from_be_bytes([*bytes.first()?, *bytes.get(1)?]))
}

/// Parses the first question of a query. Returns `None` for anything that
/// is not a well formed standard query.
#[must_use]
pub fn parse_query(data: &[u8]) -> Option<Question> {
    let flags = u16_at(data, 2)?;
    // QR must be 0 (query) and the opcode 0 (standard query).
    if flags & 0x8000 != 0 || (flags >> 11) & 0xF != 0 {
        return None;
    }
    if u16_at(data, 4)? == 0 {
        return None;
    }
    let mut at = 12;
    let mut labels = Vec::new();
    let mut total = 0_usize;
    loop {
        let len = usize::from(*data.get(at)?);
        at += 1;
        if len == 0 {
            break;
        }
        // Compression pointers and the reserved label types.
        if len & 0xC0 != 0 {
            return None;
        }
        total += len + 1;
        if total > 255 {
            return None;
        }
        let label = data.get(at..at + len)?;
        labels.push(
            label
                .iter()
                .map(|&b| match b {
                    b'A'..=b'Z' => char::from(b.to_ascii_lowercase()).to_string(),
                    b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' => char::from(b).to_string(),
                    other => format!("\\{other:03}"),
                })
                .collect::<String>(),
        );
        at += len;
    }
    Some(Question {
        name: labels.join("."),
        qtype: u16_at(data, at)?,
        qclass: u16_at(data, at + 2)?,
        end: at + 4,
    })
}

/// Builds the response to `query`: the question echoed, and one `A` record
/// with `address` if the question asked for `A` in class `IN`.
#[must_use]
pub fn answer(query: &[u8], question: &Question, address: Ipv4Addr) -> Option<Vec<u8>> {
    let id = query.get(..2)?;
    let asked = query.get(12..question.end)?;
    let answers: u16 = u16::from(question.qtype == TYPE_A && question.qclass == 1);
    let mut out = Vec::with_capacity(asked.len() + 32);
    out.extend_from_slice(id);
    // QR, AA and RD copied from the query, RA set, NOERROR.
    let rd = query.get(2).map_or(0, |b| b & 0x01);
    out.extend_from_slice(&[0x84 | rd, 0x80]);
    out.extend_from_slice(&1_u16.to_be_bytes());
    out.extend_from_slice(&answers.to_be_bytes());
    out.extend_from_slice(&[0, 0, 0, 0]);
    out.extend_from_slice(asked);
    if answers == 1 {
        // Name as a pointer to the question at offset 12, type A, class
        // IN, TTL 60, four bytes of address.
        out.extend_from_slice(&[0xC0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4]);
        out.extend_from_slice(&address.octets());
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn query(name: &str, qtype: u16) -> Vec<u8> {
        let mut q = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        for label in name.split('.') {
            q.push(u8::try_from(label.len()).unwrap());
            q.extend_from_slice(label.as_bytes());
        }
        q.push(0);
        q.extend_from_slice(&qtype.to_be_bytes());
        q.extend_from_slice(&1_u16.to_be_bytes());
        q
    }

    #[test]
    fn a_queries_get_the_sink_address() {
        let q = query("Evil.Example.com", TYPE_A);
        let question = parse_query(&q).unwrap();
        assert_eq!(question.name, "evil.example.com");
        let a = answer(&q, &question, Ipv4Addr::new(10, 0, 2, 1)).unwrap();
        assert_eq!(&a[..2], &[0x12, 0x34]);
        assert_eq!(u16::from_be_bytes([a[6], a[7]]), 1);
        assert_eq!(&a[a.len() - 4..], &[10, 0, 2, 1]);
    }

    #[test]
    fn other_types_get_no_records_and_garbage_is_refused() {
        let q = query("example.com", 28);
        let question = parse_query(&q).unwrap();
        let a = answer(&q, &question, Ipv4Addr::LOCALHOST).unwrap();
        assert_eq!(u16::from_be_bytes([a[6], a[7]]), 0);
        assert!(parse_query(&[0; 5]).is_none());
        let mut pointer = query("a.b", TYPE_A);
        pointer[12] = 0xC0;
        assert!(parse_query(&pointer).is_none());
    }

    proptest::proptest! {
        #[test]
        fn parsing_never_panics(data in proptest::collection::vec(proptest::num::u8::ANY, 0..600)) {
            if let Some(q) = parse_query(&data) {
                let _ = answer(&data, &q, Ipv4Addr::LOCALHOST);
            }
        }
    }
}
