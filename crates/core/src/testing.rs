//! Setup shared by the tests that need a real PostgreSQL.
//!
//! The database comes from `CRATEWARD_TEST_DATABASE_URL` (for example
//! `host=/var/run/postgresql dbname=crateward_test`). Each [`TestDb`] works
//! in a schema of its own. Without the variable the tests skip, unless
//! `CRATEWARD_REQUIRE_DB=1`, which CI sets so that a missing database fails
//! instead of passing silently.
//!
//! Enabled with the `testing` feature, which only tests turn on.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use tokio_postgres::{Client, NoTls};

use crate::job::{Limits, Stage, StageLimits};
use crate::retry::RetryPolicy;
use crate::store::{Policies, Store};

/// A private schema in the test database.
pub struct TestDb {
    config: String,
    schema: String,
    admin: Client,
}

impl TestDb {
    /// A new, empty schema whose name starts with `prefix`, or `None` when
    /// no test database is configured.
    ///
    /// # Panics
    ///
    /// If `CRATEWARD_REQUIRE_DB` is set but no database is, or the schema
    /// cannot be created.
    pub async fn new(prefix: &str) -> Option<Self> {
        static NEXT: AtomicU32 = AtomicU32::new(0);
        let Ok(config) = std::env::var("CRATEWARD_TEST_DATABASE_URL") else {
            assert!(
                std::env::var("CRATEWARD_REQUIRE_DB").is_err(),
                "CRATEWARD_REQUIRE_DB is set but CRATEWARD_TEST_DATABASE_URL is not"
            );

            eprintln!("skipping: CRATEWARD_TEST_DATABASE_URL is not set");
            return None;
        };

        let n = NEXT.fetch_add(1, Ordering::SeqCst);
        let schema = format!("{prefix}_{}_{n}", std::process::id());
        let admin = connect(&config).await;
        admin
            .batch_execute(&format!(
                "DROP SCHEMA IF EXISTS {schema} CASCADE; CREATE SCHEMA {schema}"
            ))
            .await
            .unwrap();

        Some(Self {
            config,
            schema,
            admin,
        })
    }

    /// The connection string of the test database.
    #[must_use]
    pub fn config(&self) -> &str {
        &self.config
    }

    /// The schema's name.
    #[must_use]
    pub fn schema(&self) -> &str {
        &self.schema
    }

    /// A connection outside the schema, for setup the store does not offer.
    #[must_use]
    pub const fn admin(&self) -> &Client {
        &self.admin
    }

    /// A new connection whose session uses the schema.
    ///
    /// # Panics
    ///
    /// If the database cannot be reached.
    pub async fn client(&self) -> Client {
        let client = connect(&self.config).await;
        client
            .batch_execute(&format!("SET search_path TO {}", self.schema))
            .await
            .unwrap();
        client
    }

    /// A store on the schema.
    pub async fn store(&self) -> Store {
        Store::from_client(self.client().await)
    }

    /// A store on the schema, with every migration applied.
    ///
    /// # Panics
    ///
    /// If a migration fails.
    pub async fn migrated(&self) -> Store {
        let mut store = self.store().await;
        store.migrate().await.unwrap();
        store
    }

    /// Drops the schema and everything in it.
    ///
    /// # Panics
    ///
    /// If the schema cannot be dropped.
    pub async fn drop(self) {
        self.admin
            .batch_execute(&format!("DROP SCHEMA {} CASCADE", self.schema))
            .await
            .unwrap();
    }
}

async fn connect(config: &str) -> Client {
    let (client, connection) = tokio_postgres::connect(config, NoTls).await.unwrap();
    tokio::spawn(connection);
    client
}

/// Retry policies for tests: three attempts, two infrastructure retries and
/// a backoff from one to ten minutes for every stage.
///
/// # Panics
///
/// Never, the bounds are valid.
#[must_use]
pub fn policies() -> Policies {
    let policy = RetryPolicy::new(Duration::from_secs(60), Duration::from_secs(600)).unwrap();
    Policies {
        limits: Limits::uniform(StageLimits {
            max_attempts: 3,
            max_infrastructure_retries: 2,
        }),
        backoff: Stage::ALL
            .iter()
            .map(|stage| (stage.name(), policy))
            .collect::<BTreeMap<_, _>>(),
    }
}
