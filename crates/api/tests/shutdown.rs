//! A shutdown does not wait for an open overview page: its live updates end
//! when SIGTERM arrives. This file is its own test binary because it sends
//! SIGTERM to its own process.
//!
//! Needs `CRATEWARD_TEST_DATABASE_URL`, like `job_page.rs`.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;
use std::time::Duration;

use crateward_api::{AppState, router};
use crateward_core::app::Stop;
use crateward_core::store::Store;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

async fn connect(config: &str, schema: &str) -> Store {
    let (client, connection) = tokio_postgres::connect(config, tokio_postgres::NoTls)
        .await
        .unwrap();
    tokio::spawn(connection);
    client
        .batch_execute(&format!("SET search_path TO {schema}"))
        .await
        .unwrap();
    Store::from_client(client)
}

#[tokio::test]
async fn sigterm_ends_open_live_updates() {
    let Ok(config) = std::env::var("CRATEWARD_TEST_DATABASE_URL") else {
        assert!(
            std::env::var("CRATEWARD_REQUIRE_DB").is_err(),
            "CRATEWARD_REQUIRE_DB is set but CRATEWARD_TEST_DATABASE_URL is not"
        );
        eprintln!("skipping: CRATEWARD_TEST_DATABASE_URL is not set");
        return;
    };
    let schema = format!("api_shutdown_{}", std::process::id());
    let (admin, connection) = tokio_postgres::connect(&config, tokio_postgres::NoTls)
        .await
        .unwrap();
    tokio::spawn(connection);
    admin
        .batch_execute(&format!("CREATE SCHEMA {schema}"))
        .await
        .unwrap();
    connect(&config, &schema).await.migrate().await.unwrap();

    let stop = Stop::install().unwrap();
    let state = AppState {
        reader: connect(&config, &schema).await,
        writer: connect(&config, &schema).await,
        stop: stop.clone(),
    };
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = tokio::spawn(
        axum::serve(listener, router(Arc::new(state), port))
            .with_graceful_shutdown(async move { stop.wait().await })
            .into_future(),
    );

    let mut page = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let request = format!("GET /events HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n");
    page.write_all(request.as_bytes()).await.unwrap();
    let mut head = [0; 12];
    page.read_exact(&mut head).await.unwrap();
    assert_eq!(&head, b"HTTP/1.1 200");

    rustix::process::kill_process(rustix::process::getpid(), rustix::process::Signal::TERM)
        .unwrap();
    let finished = tokio::time::timeout(Duration::from_secs(10), server).await;

    admin
        .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
        .await
        .unwrap();
    assert!(finished.is_ok(), "the server still waits for the open page");
}
