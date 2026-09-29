//! Popularity from the crates.io database dump.
//!
//! The dump (`db-dump.tar.gz`, about 1.9 GB, refreshed daily) is streamed,
//! never stored. The tarball's CSV files are sorted by name, so one pass
//! reads, in order: `crate_downloads.csv`, `crates.csv`,
//! `default_versions.csv` and `dependencies.csv`. From them come the total
//! downloads of every crate and its reverse dependency count: the number of
//! distinct crates whose default version depends on it, ignoring dev
//! dependencies (kind 2 in crates.io's `DependencyKind`: 0 normal, 1 build,
//! 2 dev). Columns are read by header name, so their order does not matter.
//!
//! The counts drive priorities (updates to popular crates first) and the
//! warm set of the build cache warmer (M1.5).

use std::collections::{HashMap, HashSet};
use std::io::Read;

use crateward_core::http::{HttpError, PoliteClient};
use crateward_core::store::{Store, StoreError};

/// Statistics of one crate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrateStat {
    /// Name as published.
    pub name: String,
    /// All time downloads.
    pub downloads: i64,
    /// Crates whose default version depends on this one (not as a dev
    /// dependency).
    pub reverse_dependencies: i64,
}

/// Why the dump could not be read.
#[derive(Debug, thiserror::Error)]
pub enum DumpError {
    /// Reading the archive failed.
    #[error("reading the dump: {0}")]
    Io(#[from] std::io::Error),
    /// A CSV file is malformed or lacks a column.
    #[error("{file}: {reason}")]
    Csv {
        /// The file.
        file: &'static str,
        /// What is wrong.
        reason: String,
    },
    /// A required file was not in the dump.
    #[error("the dump has no {0}")]
    Missing(&'static str),
    /// The download failed.
    #[error(transparent)]
    Http(#[from] HttpError),
    /// The server has no dump.
    #[error("the dump is missing")]
    NotFound,
    /// The parser task panicked or was cancelled.
    #[error(transparent)]
    Task(#[from] tokio::task::JoinError),
    /// Storing the statistics failed.
    #[error(transparent)]
    Store(#[from] StoreError),
}

fn column(headers: &csv::StringRecord, file: &'static str, name: &str) -> Result<usize, DumpError> {
    headers
        .iter()
        .position(|h| h == name)
        .ok_or(DumpError::Csv {
            file,
            reason: format!("no column {name}"),
        })
}

fn csv_error(file: &'static str) -> impl Fn(csv::Error) -> DumpError {
    move |e| DumpError::Csv {
        file,
        reason: e.to_string(),
    }
}

/// Reads the rows of a CSV entry, calling `row` with the requested columns.
fn each_row<R: Read>(
    reader: R,
    file: &'static str,
    columns: &[&str],
    mut row: impl FnMut(&[&str]),
) -> Result<(), DumpError> {
    let mut csv = csv::ReaderBuilder::new()
        .has_headers(true)
        .from_reader(reader);
    let headers = csv.headers().map_err(csv_error(file))?.clone();
    let indexes = columns
        .iter()
        .map(|c| column(&headers, file, c))
        .collect::<Result<Vec<_>, _>>()?;
    let mut record = csv::StringRecord::new();
    while csv.read_record(&mut record).map_err(csv_error(file))? {
        let values: Vec<&str> = indexes
            .iter()
            .map(|&i| record.get(i).unwrap_or_default())
            .collect();
        row(&values);
    }
    Ok(())
}

fn id(text: &str) -> Option<i64> {
    text.parse().ok()
}

/// Parses a gzip compressed dump stream into statistics per crate.
///
/// # Errors
///
/// Fails if the archive or a needed CSV file is malformed or missing.
pub fn parse<R: Read>(compressed: R) -> Result<Vec<CrateStat>, DumpError> {
    let mut archive = tar::Archive::new(flate2::read::GzDecoder::new(compressed));
    let mut names: HashMap<i64, String> = HashMap::new();
    let mut downloads: HashMap<i64, i64> = HashMap::new();
    // Default version ID to the crate it belongs to.
    let mut defaults: HashMap<i64, i64> = HashMap::new();
    let mut edges: HashSet<(i64, i64)> = HashSet::new();
    let mut seen = HashSet::new();
    for entry in archive.entries()? {
        let entry = entry?;
        let path = entry.path()?.to_string_lossy().into_owned();
        let Some(file) = path.rsplit('/').next() else {
            continue;
        };
        match file {
            "crate_downloads.csv" => each_row(
                entry,
                "crate_downloads.csv",
                &["crate_id", "downloads"],
                |v| {
                    if let (Some(c), Some(d)) =
                        (v.first().and_then(|x| id(x)), v.get(1).and_then(|x| id(x)))
                    {
                        downloads.insert(c, d);
                    }
                },
            )?,
            "crates.csv" => each_row(entry, "crates.csv", &["id", "name"], |v| {
                if let (Some(c), Some(n)) = (v.first().and_then(|x| id(x)), v.get(1)) {
                    names.insert(c, (*n).to_owned());
                }
            })?,
            "default_versions.csv" => each_row(
                entry,
                "default_versions.csv",
                &["crate_id", "version_id"],
                |v| {
                    if let (Some(c), Some(ver)) =
                        (v.first().and_then(|x| id(x)), v.get(1).and_then(|x| id(x)))
                    {
                        defaults.insert(ver, c);
                    }
                },
            )?,
            "dependencies.csv" => each_row(
                entry,
                "dependencies.csv",
                &["version_id", "crate_id", "kind"],
                |v| {
                    let dev = v.get(2).is_some_and(|k| *k == "2");
                    if let (false, Some(ver), Some(target)) = (
                        dev,
                        v.first().and_then(|x| id(x)),
                        v.get(1).and_then(|x| id(x)),
                    ) && let Some(&dependent) = defaults.get(&ver)
                        && dependent != target
                    {
                        edges.insert((dependent, target));
                    }
                },
            )?,
            _ => continue,
        }
        seen.insert(file.to_owned());
        if seen.len() == 4 {
            break;
        }
    }
    for needed in [
        "crate_downloads.csv",
        "crates.csv",
        "default_versions.csv",
        "dependencies.csv",
    ] {
        if !seen.contains(needed) {
            return Err(DumpError::Missing(needed));
        }
    }
    let mut reverse: HashMap<i64, i64> = HashMap::new();
    for (_, target) in edges {
        *reverse.entry(target).or_default() += 1;
    }
    Ok(names
        .into_iter()
        .map(|(crate_id, name)| CrateStat {
            name,
            downloads: downloads.get(&crate_id).copied().unwrap_or(0),
            reverse_dependencies: reverse.get(&crate_id).copied().unwrap_or(0),
        })
        .collect())
}

/// A synchronous reader over chunks sent from an async download, so the
/// parser can run on a blocking thread while the download streams.
struct ChannelReader {
    rx: tokio::sync::mpsc::Receiver<bytes::Bytes>,
    current: bytes::Bytes,
}

impl Read for ChannelReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        while self.current.is_empty() {
            match self.rx.blocking_recv() {
                Some(chunk) => self.current = chunk,
                None => return Ok(0),
            }
        }
        let n = buf.len().min(self.current.len());
        buf.get_mut(..n)
            .unwrap_or_default()
            .copy_from_slice(self.current.get(..n).unwrap_or_default());
        self.current = self.current.slice(n..);
        Ok(n)
    }
}

/// Downloads and parses the dump, then stores the statistics. Returns the
/// number of crates updated.
///
/// # Errors
///
/// Fails if the download, the parse or the store fails.
pub async fn refresh(client: &PoliteClient, url: &str, store: &Store) -> Result<u64, DumpError> {
    let mut response = client.stream(url).await?.ok_or(DumpError::NotFound)?;
    let (tx, rx) = tokio::sync::mpsc::channel(64);
    let parser = tokio::task::spawn_blocking(move || {
        parse(ChannelReader {
            rx,
            current: bytes::Bytes::new(),
        })
    });
    while let Some(chunk) = response.chunk().await.map_err(HttpError::from)? {
        // The parser stops reading after the four files it needs.
        if tx.send(chunk).await.is_err() {
            break;
        }
    }
    drop(tx);
    let stats = parser.await??;
    let rows: Vec<(String, i64, i64)> = stats
        .into_iter()
        .map(|s| (s.name, s.downloads, s.reverse_dependencies))
        .collect();
    Ok(store.upsert_crate_stats(&rows).await?)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dump(files: &[(&str, &str)]) -> Vec<u8> {
        let mut builder = tar::Builder::new(Vec::new());
        for (name, body) in files {
            let mut header = tar::Header::new_gnu();
            header.set_size(u64::try_from(body.len()).unwrap());
            header.set_mode(0o644);
            header.set_cksum();
            builder
                .append_data(
                    &mut header,
                    format!("2026-09-24-020016/data/{name}"),
                    body.as_bytes(),
                )
                .unwrap();
        }
        let tar = builder.into_inner().unwrap();
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        std::io::Write::write_all(&mut gz, &tar).unwrap();
        gz.finish().unwrap()
    }

    #[test]
    fn counts_distinct_non_dev_reverse_dependencies_of_default_versions() {
        let bytes = dump(&[
            ("crate_downloads.csv", "crate_id,downloads\n1,1000\n2,50\n"),
            (
                "crates.csv",
                "id,name,readme\n1,serde,\"multi\nline, readme\"\n2,app,x\n3,tool,y\n",
            ),
            // Crate 2's default version is 20, crate 3's is 30.
            (
                "default_versions.csv",
                "crate_id,version_id,num_versions\n2,20,1\n3,30,1\n",
            ),
            // 20 depends on serde twice (counted once), 30 only as dev,
            // 21 is not a default version.
            (
                "dependencies.csv",
                "id,version_id,crate_id,kind\n1,20,1,0\n2,20,1,1\n3,30,1,2\n4,21,1,0\n",
            ),
        ]);
        let mut stats = parse(bytes.as_slice()).unwrap();
        stats.sort_by(|a, b| a.name.cmp(&b.name));
        let serde = stats.iter().find(|s| s.name == "serde").unwrap();
        assert_eq!(serde.downloads, 1000);
        assert_eq!(serde.reverse_dependencies, 1);
        assert_eq!(
            stats.iter().find(|s| s.name == "tool").unwrap().downloads,
            0
        );
    }

    #[test]
    fn a_missing_file_is_an_error() {
        let bytes = dump(&[("crates.csv", "id,name\n1,a\n")]);
        assert!(matches!(
            parse(bytes.as_slice()),
            Err(DumpError::Missing(_))
        ));
    }
}
