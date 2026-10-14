//! Recognizes what a guest sends on a TCP connection: an HTTP request (its
//! request line and `Host`), a TLS ClientHello (its server name), or
//! something else.

use crateward_core::report::network::Sniffed;

const METHODS: &[&str] = &[
    "GET", "POST", "PUT", "HEAD", "DELETE", "OPTIONS", "PATCH", "CONNECT", "TRACE",
];

/// Longest header value kept.
const MAX_VALUE: usize = 256;

fn printable(bytes: &[u8]) -> String {
    bytes
        .iter()
        .take(MAX_VALUE)
        .map(|&b| {
            if b.is_ascii_graphic() || b == b' ' {
                char::from(b).to_string()
            } else {
                format!("\\x{b:02x}")
            }
        })
        .collect()
}

/// Whether the buffer holds a complete HTTP header block, and where the
/// body starts.
#[must_use]
pub fn http_header_end(data: &[u8]) -> Option<usize> {
    data.windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|p| p + 4)
}

/// The `Content-Length` of an HTTP request, if given and sane.
#[must_use]
pub fn content_length(headers: &[u8]) -> Option<usize> {
    headers
        .split(|&b| b == b'\n')
        .filter_map(|line| {
            let line = line.strip_suffix(b"\r").unwrap_or(line);
            let colon = line.iter().position(|&b| b == b':')?;
            let (name, value) = line.split_at(colon);
            name.eq_ignore_ascii_case(b"content-length").then(|| {
                std::str::from_utf8(value.get(1..)?)
                    .ok()?
                    .trim()
                    .parse()
                    .ok()
            })?
        })
        .next()
}

fn sniff_http(data: &[u8]) -> Option<Sniffed> {
    let line_end = data.windows(2).position(|w| w == b"\r\n")?;
    let line = data.get(..line_end)?;
    let mut parts = line.split(|&b| b == b' ');
    let method = std::str::from_utf8(parts.next()?).ok()?;
    if !METHODS.contains(&method) {
        return None;
    }

    let target = printable(parts.next()?);
    let mut host = None;
    let mut user_agent = None;
    let headers = data.get(line_end + 2..http_header_end(data).unwrap_or(data.len()))?;
    for header in headers.split(|&b| b == b'\n') {
        let header = header.strip_suffix(b"\r").unwrap_or(header);
        let Some(colon) = header.iter().position(|&b| b == b':') else {
            continue;
        };

        let (name, value) = header.split_at(colon);
        let value = value.get(1..).unwrap_or_default().trim_ascii();
        if name.eq_ignore_ascii_case(b"host") {
            host = Some(printable(value));
        } else if name.eq_ignore_ascii_case(b"user-agent") {
            user_agent = Some(printable(value));
        }
    }

    Some(Sniffed::Http {
        method: method.to_owned(),
        target,
        host,
        user_agent,
    })
}

/// A bounds checked reader over a byte slice.
struct Reader<'a> {
    data: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let out = self.data.get(self.at..self.at.checked_add(n)?)?;
        self.at += n;

        Some(out)
    }

    fn u8(&mut self) -> Option<usize> {
        self.take(1)?.first().map(|&b| usize::from(b))
    }

    fn u16(&mut self) -> Option<usize> {
        let b = self.take(2)?;

        Some(usize::from(u16::from_be_bytes([*b.first()?, *b.get(1)?])))
    }
}

/// The server name of a TLS ClientHello (RFC 8446 section 4.1.2, RFC 6066
/// section 3), from the first record only.
fn sni(data: &[u8]) -> Option<Option<String>> {
    let mut r = Reader { data, at: 0 };

    // Record header: handshake, version, length.
    if r.u8()? != 22 {
        return None;
    }

    r.take(2)?;
    let record = r.u16()?;
    let body = r.take(record).or_else(|| data.get(5..))?;
    let mut h = Reader { data: body, at: 0 };
    if h.u8()? != 1 {
        return None;
    }

    h.take(3)?; // handshake length
    h.take(2 + 32)?; // legacy version, random
    let session = h.u8()?;
    h.take(session)?;
    let suites = h.u16()?;
    h.take(suites)?;
    let compression = h.u8()?;
    h.take(compression)?;
    let Some(extensions_len) = h.u16() else {
        return Some(None);
    };

    let mut e = Reader {
        data: h.take(extensions_len).unwrap_or_default(),
        at: 0,
    };

    while let (Some(kind), Some(len)) = (e.u16(), e.u16()) {
        let ext = e.take(len)?;

        if kind != 0 {
            continue;
        }

        let mut s = Reader { data: ext, at: 0 };
        s.u16()?; // list length

        if s.u8()? == 0 {
            let name_len = s.u16()?;
            return Some(Some(printable(s.take(name_len)?)));
        }
    }

    Some(None)
}

/// Classifies the first bytes of a connection.
#[must_use]
pub fn sniff(data: &[u8]) -> Sniffed {
    if let Some(http) = sniff_http(data) {
        return http;
    }

    match sni(data) {
        Some(sni) => Sniffed::Tls { sni },
        None => Sniffed::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http_requests_are_recognized() {
        let req = b"GET /payload.sh HTTP/1.1\r\nHost: evil.example\r\nUser-Agent: curl/8\r\n\r\n";

        assert_eq!(
            sniff(req),
            Sniffed::Http {
                method: "GET".into(),
                target: "/payload.sh".into(),
                host: Some("evil.example".into()),
                user_agent: Some("curl/8".into()),
            }
        );
        assert_eq!(http_header_end(req), Some(req.len()));
        assert_eq!(
            content_length(b"POST / HTTP/1.1\r\nContent-Length: 12\r\n\r\n"),
            Some(12)
        );
    }

    #[test]
    fn tls_client_hello_names_its_server() {
        // A minimal ClientHello with one extension: server_name "a.io".
        let name = b"a.io";
        let mut ext = vec![0, 0];
        let list_len = 3 + name.len();
        ext.extend_from_slice(&u16::try_from(list_len + 2).unwrap().to_be_bytes());
        ext.extend_from_slice(&u16::try_from(list_len).unwrap().to_be_bytes());
        ext.push(0);
        ext.extend_from_slice(&u16::try_from(name.len()).unwrap().to_be_bytes());
        ext.extend_from_slice(name);
        let mut hello = vec![3, 3];
        hello.extend_from_slice(&[0; 32]);
        hello.extend_from_slice(&[0, 0, 2, 0x13, 0x01, 1, 0]);
        hello.extend_from_slice(&u16::try_from(ext.len()).unwrap().to_be_bytes());
        hello.extend_from_slice(&ext);
        let mut handshake = vec![1, 0];
        handshake.extend_from_slice(&u16::try_from(hello.len()).unwrap().to_be_bytes());
        handshake.extend_from_slice(&hello);
        let mut record = vec![22, 3, 1];
        record.extend_from_slice(&u16::try_from(handshake.len()).unwrap().to_be_bytes());
        record.extend_from_slice(&handshake);

        assert_eq!(
            sniff(&record),
            Sniffed::Tls {
                sni: Some("a.io".into())
            }
        );
    }

    #[test]
    fn anything_else_is_unknown() {
        assert_eq!(sniff(b"SSH-2.0-OpenSSH\r\n"), Sniffed::Unknown);
        assert_eq!(sniff(b""), Sniffed::Unknown);
    }

    proptest::proptest! {
        #[test]
        fn sniffing_never_panics(data in proptest::collection::vec(proptest::num::u8::ANY, 0..800)) {
            let _ = sniff(&data);
            let _ = content_length(&data);
        }
    }
}
