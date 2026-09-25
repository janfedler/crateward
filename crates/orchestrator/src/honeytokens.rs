//! Honeytokens: fake credentials planted where malware looks for real ones.
//!
//! Every job gets fresh values, generated on the host after restore and
//! never part of the snapshot. Each value is unique, so finding one in
//! fake internet traffic or on the scratch disk proves that this job's code
//! read it and names the job. The formats follow the real ones closely
//! enough to pass the format checks that stealers apply (`cio` plus 32
//! characters for crates.io, `ghp_` plus 36 for GitHub, `AKIA` plus 16 for
//! AWS), but none of them is valid anywhere.

use crateward_core::protocol::{FileSpec, PathSpec};
use rand::RngExt;
use rand::distr::Alphanumeric;

/// The builder's home directory in the guest, on the scratch disk.
pub const HOME: &str = "/work/home";

/// One planted value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Token {
    /// What it imitates, for example `cargo_registry_token`.
    pub kind: &'static str,
    /// The distinctive value to look for.
    pub value: String,
}

/// The honeytokens of one job and where they go.
#[derive(Debug, Clone)]
pub struct Honeytokens {
    /// Every planted value.
    pub tokens: Vec<Token>,
    /// Directories to create under [`HOME`], with the builder as owner.
    pub directories: Vec<PathSpec>,
    /// Files to write.
    pub files: Vec<FileSpec>,
    /// Environment variables for the job.
    pub env: Vec<(String, String)>,
}

fn random(rng: &mut impl rand::Rng, len: usize) -> String {
    (0..len)
        .map(|_| char::from(rng.sample(Alphanumeric)))
        .collect()
}

fn upper(rng: &mut impl rand::Rng, len: usize) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    (0..len)
        .map(|_| {
            let i = rng.random_range(0..CHARS.len());
            char::from(CHARS.get(i).copied().unwrap_or(b'A'))
        })
        .collect()
}

impl Honeytokens {
    /// Generates a fresh set for one job. `owner` is the builder's UID.
    #[must_use]
    pub fn generate(rng: &mut impl rand::Rng, owner: u32) -> Self {
        let cargo = format!("cio{}", random(rng, 32));
        let github_file = format!("ghp_{}", random(rng, 36));
        let github_env = format!("ghp_{}", random(rng, 36));
        let aws_id = format!("AKIA{}", upper(rng, 16));
        let aws_secret = random(rng, 40);
        let ssh_marker = random(rng, 64);
        let ssh_key = format!(
            "-----BEGIN OPENSSH PRIVATE KEY-----\n\
             b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\n\
             {ssh_marker}\n\
             -----END OPENSSH PRIVATE KEY-----\n"
        );
        let dir = |path: &str, mode: u32| PathSpec {
            path: format!("{HOME}{path}"),
            owner,
            mode,
        };
        let file = |path: &str, mode: u32, contents: String| FileSpec {
            path: dir(path, mode),
            contents: contents.into_bytes(),
        };
        Self {
            tokens: vec![
                Token {
                    kind: "cargo_registry_token",
                    value: cargo.clone(),
                },
                Token {
                    kind: "github_token_file",
                    value: github_file.clone(),
                },
                Token {
                    kind: "github_token_env",
                    value: github_env.clone(),
                },
                Token {
                    kind: "aws_access_key_id",
                    value: aws_id.clone(),
                },
                Token {
                    kind: "aws_secret_access_key",
                    value: aws_secret.clone(),
                },
                Token {
                    kind: "ssh_private_key",
                    value: ssh_marker,
                },
            ],
            directories: vec![
                dir("", 0o755),
                dir("/.cargo", 0o755),
                dir("/.ssh", 0o700),
                dir("/.aws", 0o755),
            ],
            files: vec![
                file(
                    "/.cargo/credentials.toml",
                    0o600,
                    format!("[registry]\ntoken = \"{cargo}\"\n"),
                ),
                file("/.ssh/id_ed25519", 0o600, ssh_key),
                file(
                    "/.aws/credentials",
                    0o600,
                    format!(
                        "[default]\naws_access_key_id = {aws_id}\naws_secret_access_key = {aws_secret}\n"
                    ),
                ),
                file(
                    "/.git-credentials",
                    0o600,
                    format!("https://builder:{github_file}@github.com\n"),
                ),
            ],
            env: vec![("GITHUB_TOKEN".into(), github_env)],
        }
    }

    /// Kind and value pairs for the store.
    #[must_use]
    pub fn records(&self) -> Vec<(String, String)> {
        self.tokens
            .iter()
            .map(|t| (t.kind.to_owned(), t.value.clone()))
            .collect()
    }

    /// The tokens that occur in `haystack`.
    #[must_use]
    pub fn found_in<'a>(tokens: &'a [Token], haystack: &[u8]) -> Vec<&'a Token> {
        tokens
            .iter()
            .filter(|t| {
                haystack
                    .windows(t.value.len())
                    .any(|w| w == t.value.as_bytes())
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use rand::SeedableRng;

    use super::*;

    #[test]
    fn values_are_unique_formatted_and_findable() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(7);
        let a = Honeytokens::generate(&mut rng, 1000);
        let b = Honeytokens::generate(&mut rng, 1000);
        assert_ne!(a.records(), b.records());
        let cargo = &a.tokens[0].value;
        assert!(cargo.starts_with("cio") && cargo.len() == 35);
        assert!(a.tokens[3].value.starts_with("AKIA") && a.tokens[3].value.len() == 20);
        let leaked = format!("POST /x HTTP/1.1\r\n\r\ntoken={cargo}");
        let found = Honeytokens::found_in(&a.tokens, leaked.as_bytes());
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].kind, "cargo_registry_token");
        assert!(Honeytokens::found_in(&b.tokens, leaked.as_bytes()).is_empty());
        assert!(a.files.iter().all(|f| f.path.path.starts_with(HOME)));
    }
}
