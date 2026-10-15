//! A shutdown does not wait for an open overview page: its live updates end
//! when SIGTERM arrives. This file is its own test binary because it sends
//! SIGTERM to its own process.
//!
//! The database setup is `crateward_core::testing`.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;
use std::time::Duration;

use crateward_api::jobs_list::Backlog;
use crateward_api::{AppState, router};
use crateward_core::app::Stop;
use crateward_core::testing::TestDb;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

#[tokio::test]
async fn sigterm_ends_open_live_updates() {
    let Some(db) = TestDb::new("api_shutdown").await else {
        return;
    };

    db.migrated().await;

    let stop = Stop::install().unwrap();
    let state = AppState {
        reader: db.store().await,
        writer: db.store().await,
        stop: stop.clone(),
        backlog: Backlog::default(),
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

    db.drop().await;

    assert!(finished.is_ok(), "the server still waits for the open page");
}
