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
//! The counts drive priorities: updates to popular crates first.

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
fn each_row<R: Read, const N: usize>(
    reader: R,
    file: &'static str,
    columns: [&str; N],
    mut row: impl FnMut([&str; N]),
) -> Result<(), DumpError> {
    let mut csv = csv::ReaderBuilder::new()
        .has_headers(true)
        .from_reader(reader);
    let headers = csv.headers().map_err(csv_error(file))?.clone();
    let mut indexes = [0; N];
    for (index, name) in indexes.iter_mut().zip(columns) {
        *index = column(&headers, file, name)?;
    }
    let mut record = csv::StringRecord::new();
    while csv.read_record(&mut record).map_err(csv_error(file))? {
        row(indexes.map(|i| record.get(i).unwrap_or_default()));
    }
    Ok(())
}

fn id(text: &str) -> Option<i64> {
    text.parse().ok()
}

const DOWNLOADS: &str = "crate_downloads.csv";
const CRATES: &str = "crates.csv";
const DEFAULTS: &str = "default_versions.csv";
const DEPENDENCIES: &str = "dependencies.csv";
/// The files `parse` reads, in the order the dump has them.
const FILES: [&str; 4] = [DOWNLOADS, CRATES, DEFAULTS, DEPENDENCIES];

/// What the four files say, by crate ID.
#[derive(Default)]
struct Tables {
    names: HashMap<i64, String>,
    downloads: HashMap<i64, i64>,
    /// Default version ID to the crate it belongs to.
    defaults: HashMap<i64, i64>,
    /// Dependent crate and dependency, each pair once.
    edges: HashSet<(i64, i64)>,
}

impl Tables {
    /// Reads the file if it is one of the four. Returns whether it was.
    fn read(&mut self, name: &str, entry: impl Read) -> Result<bool, DumpError> {
        match name {
            DOWNLOADS => each_row(entry, DOWNLOADS, ["crate_id", "downloads"], |[c, d]| {
                if let (Some(c), Some(d)) = (id(c), id(d)) {
                    self.downloads.insert(c, d);
                }
            })?,
            CRATES => each_row(entry, CRATES, ["id", "name"], |[c, name]| {
                if let Some(c) = id(c) {
                    self.names.insert(c, name.to_owned());
                }
            })?,
            DEFAULTS => each_row(entry, DEFAULTS, ["crate_id", "version_id"], |[c, v]| {
                if let (Some(c), Some(v)) = (id(c), id(v)) {
                    self.defaults.insert(v, c);
                }
            })?,
            DEPENDENCIES => each_row(
                entry,
                DEPENDENCIES,
                ["version_id", "crate_id", "kind"],
                |[version, target, kind]| {
                    // Kind 2 is a dev dependency.
                    if let (Some(version), Some(target)) = (id(version), id(target))
                        && kind != "2"
                        && let Some(&dependent) = self.defaults.get(&version)
                        && dependent != target
                    {
                        self.edges.insert((dependent, target));
                    }
                },
            )?,
            _ => return Ok(false),
        }
        Ok(true)
    }

    /// The statistics of every crate, counting each dependent once.
    fn stats(self) -> Vec<CrateStat> {
        let mut reverse: HashMap<i64, i64> = HashMap::new();
        for (_, target) in self.edges {
            *reverse.entry(target).or_default() += 1;
        }
        self.names
            .into_iter()
            .map(|(crate_id, name)| CrateStat {
                name,
                downloads: self.downloads.get(&crate_id).copied().unwrap_or(0),
                reverse_dependencies: reverse.get(&crate_id).copied().unwrap_or(0),
            })
            .collect()
    }
}

/// Parses a gzip compressed dump stream into statistics per crate.
///
/// # Errors
///
/// Fails if the archive or a needed CSV file is malformed or missing.
pub fn parse<R: Read>(compressed: R) -> Result<Vec<CrateStat>, DumpError> {
    let mut archive = tar::Archive::new(flate2::read::GzDecoder::new(compressed));
    let mut tables = Tables::default();
    let mut seen = HashSet::new();
    for entry in archive.entries()? {
        let entry = entry?;
        let path = entry.path()?.to_string_lossy().into_owned();
        let name = path.rsplit('/').next().unwrap_or_default();
        if tables.read(name, entry)? {
            seen.insert(name.to_owned());
        }
        if seen.len() == FILES.len() {
            break;
        }
    }
    if let Some(missing) = FILES.into_iter().find(|file| !seen.contains(*file)) {
        return Err(DumpError::Missing(missing));
    }
    Ok(tables.stats())
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

    /// The tar of the files, with the end of archive marker.
    fn tar_of(files: &[(&str, &str)]) -> Vec<u8> {
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
        builder.into_inner().unwrap()
    }

    fn gzip(tar: &[u8]) -> Vec<u8> {
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        std::io::Write::write_all(&mut gz, tar).unwrap();
        gz.finish().unwrap()
    }

    fn dump(files: &[(&str, &str)]) -> Vec<u8> {
        gzip(&tar_of(files))
    }

    const DOWNLOADS: (&str, &str) = ("crate_downloads.csv", "crate_id,downloads\n1,100\n");
    const CRATES: (&str, &str) = ("crates.csv", "id,name\n1,serde\n2,app\n");
    const DEFAULTS: (&str, &str) = ("default_versions.csv", "crate_id,version_id\n2,20\n");
    const DEPENDENCIES: (&str, &str) = ("dependencies.csv", "version_id,crate_id,kind\n20,1,0\n");

    fn sorted(bytes: &[u8]) -> Vec<(String, i64, i64)> {
        let mut stats: Vec<_> = parse(bytes)
            .unwrap()
            .into_iter()
            .map(|s| (s.name, s.downloads, s.reverse_dependencies))
            .collect();
        stats.sort();
        stats
    }

    fn csv_error(result: Result<Vec<CrateStat>, DumpError>) -> (&'static str, String) {
        match result {
            Err(DumpError::Csv { file, reason }) => (file, reason),
            other => panic!("not a csv error: {other:?}"),
        }
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
    fn the_files_are_read_by_header_name_in_any_column_order() {
        let bytes = dump(&[
            (
                "crate_downloads.csv",
                "downloads,extra,crate_id\n100,x,1\n7,y,2\n",
            ),
            ("crates.csv", "name,id\nserde,1\napp,2\n"),
            ("default_versions.csv", "version_id,crate_id\n20,2\n"),
            ("dependencies.csv", "kind,crate_id,version_id\n0,1,20\n"),
        ]);
        assert_eq!(
            sorted(&bytes),
            vec![("app".to_owned(), 7, 0), ("serde".to_owned(), 100, 1)]
        );
    }

    #[test]
    fn a_crate_is_counted_once_per_dependent_and_never_for_itself() {
        let bytes = dump(&[
            DOWNLOADS,
            ("crates.csv", "id,name\n1,serde\n2,app\n3,tool\n4,lonely\n"),
            (
                "default_versions.csv",
                "crate_id,version_id\n1,10\n2,20\n3,30\n4,40\n",
            ),
            (
                "dependencies.csv",
                "version_id,crate_id,kind\n10,1,0\n20,1,0\n20,1,1\n30,1,0\n30,2,1\n40,9,0\n",
            ),
        ]);
        assert_eq!(
            sorted(&bytes),
            vec![
                ("app".to_owned(), 0, 1),
                ("lonely".to_owned(), 0, 0),
                ("serde".to_owned(), 100, 2),
                ("tool".to_owned(), 0, 0),
            ]
        );
    }

    #[test]
    fn rows_with_unusable_numbers_are_skipped() {
        let bytes = dump(&[
            (
                "crate_downloads.csv",
                "crate_id,downloads\nx,5\n1,many\n1,\n2,8\n",
            ),
            ("crates.csv", "id,name\n1,serde\nn,ghost\n2,app\n"),
            (
                "default_versions.csv",
                "crate_id,version_id\n2,20\n2,v\nc,21\n",
            ),
            (
                "dependencies.csv",
                "version_id,crate_id,kind\n20,1,0\n20,y,0\nz,1,0\n",
            ),
        ]);
        assert_eq!(
            sorted(&bytes),
            vec![("app".to_owned(), 8, 0), ("serde".to_owned(), 0, 1)]
        );
    }

    #[test]
    fn the_first_missing_file_in_reading_order_is_named() {
        for (files, missing) in [
            (vec![CRATES, DEFAULTS, DEPENDENCIES], "crate_downloads.csv"),
            (vec![DOWNLOADS, DEFAULTS, DEPENDENCIES], "crates.csv"),
            (
                vec![DOWNLOADS, CRATES, DEPENDENCIES],
                "default_versions.csv",
            ),
            (vec![DOWNLOADS, CRATES, DEFAULTS], "dependencies.csv"),
            (vec![], "crate_downloads.csv"),
            (vec![DEPENDENCIES], "crate_downloads.csv"),
        ] {
            let bytes = dump(&files);
            match parse(bytes.as_slice()) {
                Err(DumpError::Missing(name)) => assert_eq!(name, missing),
                other => panic!("expected {missing} to be missing: {other:?}"),
            }
        }
    }

    #[test]
    fn a_missing_column_names_the_file_and_the_column() {
        let bytes = dump(&[
            DOWNLOADS,
            ("crates.csv", "id,title\n1,serde\n"),
            DEFAULTS,
            DEPENDENCIES,
        ]);
        assert_eq!(
            csv_error(parse(bytes.as_slice())),
            ("crates.csv", "no column name".to_owned())
        );
        let bytes = dump(&[
            DOWNLOADS,
            CRATES,
            DEFAULTS,
            ("dependencies.csv", "version_id,crate_id\n20,1\n"),
        ]);
        assert_eq!(
            csv_error(parse(bytes.as_slice())),
            ("dependencies.csv", "no column kind".to_owned())
        );
    }

    #[test]
    fn other_files_are_skipped_and_reading_stops_after_the_four() {
        let files = [
            ("README.md", "not csv \u{0}\u{1}"),
            DOWNLOADS,
            ("versions.csv", "\"unterminated"),
            CRATES,
            DEFAULTS,
            DEPENDENCIES,
        ];
        assert_eq!(
            sorted(&dump(&files)),
            vec![("app".to_owned(), 0, 0), ("serde".to_owned(), 100, 1)]
        );
        // Whatever follows the fourth file is never read.
        let mut tar = tar_of(&files);
        tar.truncate(tar.len() - 1024);
        tar.extend([0xFF_u8; 512]);
        assert_eq!(sorted(&gzip(&tar)).len(), 2);
    }

    #[test]
    fn a_file_that_comes_twice_is_read_twice_until_all_four_were_seen() {
        let bytes = dump(&[
            DOWNLOADS,
            CRATES,
            ("crates.csv", "id,name\n3,extra\n"),
            DEFAULTS,
            DEPENDENCIES,
        ]);
        assert_eq!(
            sorted(&bytes),
            vec![
                ("app".to_owned(), 0, 0),
                ("extra".to_owned(), 0, 0),
                ("serde".to_owned(), 100, 1),
            ]
        );
    }

    #[test]
    fn garbage_is_an_io_error() {
        assert!(matches!(
            parse(&b"not a gzip stream"[..]),
            Err(DumpError::Io(_))
        ));
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
