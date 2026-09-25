//! TLS termination with Crateward's own certificate authority.
//!
//! The guest image trusts the authority's certificate. For each server name
//! a guest asks for, the fake internet issues a leaf certificate on the fly,
//! completes the handshake and reads what the guest sends in plain text.
//! Tools that pin certificates or carry their own root list (for example
//! `webpki-roots`) refuse the handshake; the server name is logged either
//! way.
//!
//! The authority's parameters are fixed in this module, so the issuer can
//! be rebuilt from its private key alone; no certificate parser is needed.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, Issuer, KeyPair,
    KeyUsagePurpose,
};
use rustls::crypto::ring::sign::any_supported_type;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;

/// Server names issued per run; later names get the fallback certificate.
const MAX_NAMES: usize = 256;

/// Name used when a client sends no server name, or an invalid one.
const FALLBACK_NAME: &str = "localhost";

/// The authority's fixed parameters.
fn ca_params() -> CertificateParams {
    let mut params = CertificateParams::default();
    let mut name = DistinguishedName::new();
    name.push(DnType::CommonName, "Crateward fake internet CA");
    name.push(DnType::OrganizationName, "Crateward");
    params.distinguished_name = name;
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    params
}

/// A new authority: its certificate and its private key, both PEM.
///
/// # Errors
///
/// Fails if key generation or signing fails.
pub fn generate_ca() -> Result<(String, String), rcgen::Error> {
    let key = KeyPair::generate()?;
    let cert = ca_params().self_signed(&key)?;
    Ok((cert.pem(), key.serialize_pem()))
}

/// Issues leaf certificates for server names, signed by the authority.
pub struct Authority {
    issuer: Issuer<'static, KeyPair>,
    ca: CertificateDer<'static>,
    leaves: Mutex<HashMap<String, Arc<CertifiedKey>>>,
}

impl std::fmt::Debug for Authority {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Authority")
    }
}

impl Authority {
    /// The authority from its certificate and private key, both PEM. The
    /// certificate must come from [`generate_ca`].
    ///
    /// # Errors
    ///
    /// Fails if the key or certificate does not parse.
    pub fn from_pem(cert_pem: &str, key_pem: &str) -> Result<Self, String> {
        let key = KeyPair::from_pem(key_pem).map_err(|e| e.to_string())?;
        let ca = pem_der(cert_pem).ok_or("the certificate is not PEM")?;
        Ok(Self {
            issuer: Issuer::new(ca_params(), key),
            ca,
            leaves: Mutex::new(HashMap::new()),
        })
    }

    fn issue(&self, name: &str) -> Option<Arc<CertifiedKey>> {
        let key = KeyPair::generate().ok()?;
        let params = CertificateParams::new(vec![name.to_owned()]).ok()?;
        let cert = params.signed_by(&key, &self.issuer).ok()?;
        let der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));
        let signer = any_supported_type(&der).ok()?;
        Some(Arc::new(CertifiedKey::new(
            vec![cert.der().clone(), self.ca.clone()],
            signer,
        )))
    }

    /// The certificate for `name`, issued once and cached.
    #[must_use]
    pub fn leaf(&self, name: &str) -> Option<Arc<CertifiedKey>> {
        let mut leaves = self.leaves.lock().ok()?;
        if let Some(leaf) = leaves.get(name) {
            return Some(Arc::clone(leaf));
        }
        let name = if leaves.len() < MAX_NAMES {
            name
        } else {
            FALLBACK_NAME
        };
        let leaf = self.issue(name).or_else(|| self.issue(FALLBACK_NAME))?;
        leaves.insert(name.to_owned(), Arc::clone(&leaf));
        Some(leaf)
    }
}

impl ResolvesServerCert for Authority {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        self.leaf(client_hello.server_name().unwrap_or(FALLBACK_NAME))
    }
}

/// Decodes the first PEM block of a text.
fn pem_der(pem: &str) -> Option<CertificateDer<'static>> {
    let body: String = pem
        .lines()
        .skip_while(|l| !l.starts_with("-----BEGIN"))
        .skip(1)
        .take_while(|l| !l.starts_with("-----END"))
        .collect();
    base64_decode(&body).map(CertificateDer::from)
}

fn base64_decode(text: &str) -> Option<Vec<u8>> {
    let value = |c: u8| -> Option<u32> {
        Some(u32::from(match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        }))
    };
    let clean: Vec<u8> = text.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    let trimmed = clean
        .strip_suffix(b"==")
        .or_else(|| clean.strip_suffix(b"="))
        .unwrap_or(&clean);
    let mut out = Vec::with_capacity(trimmed.len() * 3 / 4);
    let mut acc = 0_u32;
    let mut bits = 0;
    for &c in trimmed {
        acc = (acc << 6) | value(c)?;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(u8::try_from((acc >> bits) & 0xFF).ok()?);
        }
    }
    Some(out)
}

/// A TLS configuration that issues certificates from `authority`.
///
/// # Errors
///
/// Fails if the ring provider rejects the default protocol versions.
pub fn server_config(
    authority: Arc<Authority>,
) -> Result<Arc<rustls::ServerConfig>, rustls::Error> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    Ok(Arc::new(
        rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()?
            .with_no_client_auth()
            .with_cert_resolver(authority),
    ))
}

/// Splits PEM text into the certificate and the private key blocks.
#[must_use]
pub fn split_pem(text: &str) -> Option<(String, String)> {
    let block = |begin: &str| {
        let start = text.find(begin)?;
        let rest = text.get(start..)?;
        let end = rest.find("-----END")?;
        let close = rest
            .get(end..)?
            .find('\n')
            .map_or(rest.len(), |n| end + n + 1);
        rest.get(..close).map(str::to_owned)
    };
    Some((
        block("-----BEGIN CERTIFICATE-----")?,
        block("-----BEGIN PRIVATE KEY-----")?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_matches_known_values() {
        assert_eq!(base64_decode("aGVsbG8=").unwrap(), b"hello");
        assert_eq!(base64_decode("aGk=").unwrap(), b"hi");
        assert!(base64_decode("a$b=").is_none());
    }

    #[test]
    fn a_generated_authority_issues_cached_leaves() {
        let (cert, key) = generate_ca().unwrap();
        let both = format!("{cert}{key}");
        let (c, k) = split_pem(&both).unwrap();
        assert_eq!((c.as_str(), k.as_str()), (cert.as_str(), key.as_str()));
        let authority = Authority::from_pem(&cert, &key).unwrap();
        let a = authority.leaf("evil.example").unwrap();
        let b = authority.leaf("evil.example").unwrap();
        assert!(Arc::ptr_eq(&a, &b));
        assert_eq!(a.cert.len(), 2);
        assert!(authority.leaf("not a valid name").is_some());
        server_config(Arc::new(authority)).unwrap();
    }
}
