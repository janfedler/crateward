//! Honeytokens: fake credentials planted where malware looks for real ones.
//!
//! Every job gets fresh values, generated on the host after restore and
//! never part of the snapshot. Each value is unique, so finding one in
//! fake internet traffic or on the scratch disk proves that this job's code
//! read it and names the job. The formats follow the real ones closely
//! enough to pass the format checks that stealers apply (`cio` plus 32
//! characters for crates.io, `ghp_` plus 36 for GitHub, `AKIA` plus 16 for
//! AWS), but none of them is valid anywhere.

use crateward_core::guest::HOME;
use crateward_core::protocol::{FileSpec, PathSpec};
use rand::RngExt;
use rand::distr::Alphanumeric;

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

/// The private key file: a fixed header, the job's marker and a footer.
fn ssh_key(marker: &str) -> String {
    format!(
        "-----BEGIN OPENSSH PRIVATE KEY-----\n\
         b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\n\
         {marker}\n\
         -----END OPENSSH PRIVATE KEY-----\n"
    )
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
        let dir = |path: &str, mode: u32| PathSpec {
            path: format!("{HOME}{path}"),
            owner,
            mode,
        };
        let file = |path: &str, contents: String| FileSpec {
            path: dir(path, 0o600),
            contents: contents.into_bytes(),
        };
        let token = |kind, value: &str| Token {
            kind,
            value: value.to_owned(),
        };
        Self {
            tokens: vec![
                token("cargo_registry_token", &cargo),
                token("github_token_file", &github_file),
                token("github_token_env", &github_env),
                token("aws_access_key_id", &aws_id),
                token("aws_secret_access_key", &aws_secret),
                token("ssh_private_key", &ssh_marker),
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
                    format!("[registry]\ntoken = \"{cargo}\"\n"),
                ),
                file("/.ssh/id_ed25519", ssh_key(&ssh_marker)),
                file(
                    "/.aws/credentials",
                    format!(
                        "[default]\naws_access_key_id = {aws_id}\naws_secret_access_key = {aws_secret}\n"
                    ),
                ),
                file(
                    "/.git-credentials",
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

    #[test]
    fn every_token_lands_in_its_file_with_its_mode() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(7);
        let set = Honeytokens::generate(&mut rng, 1000);
        let kinds: Vec<_> = set.tokens.iter().map(|t| t.kind).collect();
        assert_eq!(
            kinds,
            [
                "cargo_registry_token",
                "github_token_file",
                "github_token_env",
                "aws_access_key_id",
                "aws_secret_access_key",
                "ssh_private_key",
            ]
        );
        let value = |kind: &str| {
            set.tokens
                .iter()
                .find(|t| t.kind == kind)
                .unwrap()
                .value
                .clone()
        };
        let directories: Vec<_> = set
            .directories
            .iter()
            .map(|d| (d.path.as_str(), d.owner, d.mode))
            .collect();
        assert_eq!(
            directories,
            [
                ("/work/home", 1000, 0o755),
                ("/work/home/.cargo", 1000, 0o755),
                ("/work/home/.ssh", 1000, 0o700),
                ("/work/home/.aws", 1000, 0o755),
            ]
        );
        let files: Vec<_> = set
            .files
            .iter()
            .map(|f| {
                let text = String::from_utf8(f.contents.clone()).unwrap();
                (f.path.path.as_str(), f.path.owner, f.path.mode, text)
            })
            .collect();
        let ssh = format!(
            "-----BEGIN OPENSSH PRIVATE KEY-----\n\
             b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\n\
             {}\n\
             -----END OPENSSH PRIVATE KEY-----\n",
            value("ssh_private_key")
        );
        assert_eq!(
            files,
            [
                (
                    "/work/home/.cargo/credentials.toml",
                    1000,
                    0o600,
                    format!(
                        "[registry]\ntoken = \"{}\"\n",
                        value("cargo_registry_token")
                    )
                ),
                ("/work/home/.ssh/id_ed25519", 1000, 0o600, ssh),
                (
                    "/work/home/.aws/credentials",
                    1000,
                    0o600,
                    format!(
                        "[default]\naws_access_key_id = {}\naws_secret_access_key = {}\n",
                        value("aws_access_key_id"),
                        value("aws_secret_access_key")
                    )
                ),
                (
                    "/work/home/.git-credentials",
                    1000,
                    0o600,
                    format!(
                        "https://builder:{}@github.com\n",
                        value("github_token_file")
                    )
                ),
            ]
        );
        assert_eq!(
            set.env,
            [("GITHUB_TOKEN".to_owned(), value("github_token_env"))]
        );
        assert_eq!(value("github_token_file").len(), 40);
        assert_eq!(value("github_token_env").len(), 40);
        assert_ne!(value("github_token_file"), value("github_token_env"));
        assert_eq!(value("aws_secret_access_key").len(), 40);
        assert_eq!(value("ssh_private_key").len(), 64);
    }

    #[test]
    fn a_seed_gives_the_same_values() {
        let make = || Honeytokens::generate(&mut rand::rngs::StdRng::seed_from_u64(7), 1000);
        let expected = make().records();
        assert_eq!(make().records(), expected);
    }
}
