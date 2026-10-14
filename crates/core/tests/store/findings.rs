//! Disclosures from report to publication.

use super::*;

/// A high verdict.
fn high() -> Verdict {
    Verdict {
        score: 90,
        level: RiskLevel::from_score(90),
        coverage: Coverage::DynamicLinux,
        evidence: Vec::new(),
        profile: Vec::new(),
        new_behavior: Vec::new(),
        analyzer_version: 1,
    }
}

async fn enqueue(store: &mut Store, name: &str, version: &str) -> JobId {
    store
        .enqueue(&new_job(name, version, 0))
        .await
        .unwrap()
        .unwrap()
}

/// Gives `job` a high verdict that a human confirmed.
async fn confirm(store: &Store, job: JobId) {
    store.record_verdict(job, &high()).await.unwrap();
    store
        .set_review(job, Review::Confirmed, None)
        .await
        .unwrap();
}

async fn report(store: &Store, job: JobId) -> Result<(), DisclosureRefusal> {
    store
        .record_report(job, DisclosureKind::Malicious, "help@crates.io", None, None)
        .await
        .unwrap()
}

#[tokio::test]
async fn findings_are_reported_resolved_and_only_then_published() {
    let Some(db) = TestDb::new("test").await else {
        return;
    };

    let mut store = db.migrated().await;
    let job = enqueue(&mut store, "evil", "0.1.0").await;

    // No verdict, then an unconfirmed one: nothing is reported.
    assert_eq!(
        report(&store, job).await,
        Err(DisclosureRefusal::NotConfirmed)
    );

    store.record_verdict(job, &high()).await.unwrap();
    store.set_review(job, Review::Pending, None).await.unwrap();

    assert_eq!(
        report(&store, job).await,
        Err(DisclosureRefusal::NotConfirmed)
    );

    // Publishing needs a report, then a resolution.
    assert_eq!(
        store.publish_finding(job, "evil").await.unwrap(),
        Err(DisclosureRefusal::NotReported)
    );
    assert_eq!(
        store.mark_resolved(job, None).await.unwrap(),
        Err(DisclosureRefusal::NotReported)
    );

    confirm(&store, job).await;

    assert_eq!(report(&store, job).await, Ok(()));
    assert_eq!(
        store.publish_finding(job, "evil").await.unwrap(),
        Err(DisclosureRefusal::NotResolved)
    );
    assert!(store.published_findings().await.unwrap().is_empty());
    assert_eq!(
        store.mark_resolved(job, Some("CRATES-1")).await.unwrap(),
        Ok(())
    );
    assert_eq!(
        store.publish_finding(job, "Bad/Slug").await.unwrap(),
        Err(DisclosureRefusal::BadSlug)
    );
    assert_eq!(
        store.publish_finding(job, "evil-0-1-0").await.unwrap(),
        Ok(())
    );

    let record = store.disclosure(job).await.unwrap().unwrap();
    assert_eq!(record.reference.as_deref(), Some("CRATES-1"));
    assert!(record.resolved_on.is_some() && record.published_on.is_some());

    let published = store.published_findings().await.unwrap();
    assert_eq!(published.len(), 1);
    assert_eq!(
        (published[0].name.as_str(), published[0].slug.as_str()),
        ("evil", "evil-0-1-0")
    );
    assert!(store.disclosure(JobId(i64::MAX)).await.unwrap().is_none());

    db.drop().await;
}

#[tokio::test]
async fn a_page_belongs_to_one_crate_and_its_versions() {
    let Some(db) = TestDb::new("test").await else {
        return;
    };

    let mut store = db.migrated().await;
    let mut publish = async |name: &str, version: &str| {
        let job = enqueue(&mut store, name, version).await;
        confirm(&store, job).await;
        report(&store, job).await.unwrap();
        store.mark_resolved(job, None).await.unwrap().unwrap();

        store.publish_finding(job, "evil-0-1-0").await.unwrap()
    };

    assert_eq!(publish("evil", "0.1.0").await, Ok(()));

    // A second crate cannot take the page, another version may share it.
    assert_eq!(
        publish("worse", "0.2.0").await,
        Err(DisclosureRefusal::SlugTaken)
    );
    assert_eq!(publish("evil", "0.1.1").await, Ok(()));
    assert_eq!(store.published_findings().await.unwrap().len(), 2);

    db.drop().await;
}

#[tokio::test]
async fn a_crate_removed_before_its_report_may_be_published() {
    let Some(db) = TestDb::new("test").await else {
        return;
    };

    // crates.io removed a crate before it was reported: no report, but
    // resolved, so it may be published. Only a confirmed verdict counts.
    let mut store = db.migrated().await;
    let gone = enqueue(&mut store, "gone", "0.1.0").await;

    assert_eq!(
        store.record_removal(gone, None).await.unwrap(),
        Err(DisclosureRefusal::NotConfirmed)
    );

    confirm(&store, gone).await;
    let note = Some("removed on 2026-10-01");

    assert_eq!(store.record_removal(gone, note).await.unwrap(), Ok(()));

    let record = store.disclosure(gone).await.unwrap().unwrap();
    assert_eq!(record.kind, DisclosureKind::Malicious);
    assert!(record.reported_on.is_none() && record.reported_to.is_none());
    assert!(record.resolved_on.is_some());
    assert_eq!(record.reported(), crateward_core::store::REMOVED_FIRST);
    assert_eq!(store.publish_finding(gone, "gone").await.unwrap(), Ok(()));

    let published = store.published_findings().await.unwrap();
    assert!(
        published
            .iter()
            .any(|f| f.slug == "gone" && f.reported_on.is_none())
    );

    // A report recorded later fills the report in.
    assert_eq!(report(&store, gone).await, Ok(()));

    let record = store.disclosure(gone).await.unwrap().unwrap();
    assert!(record.reported_on.is_some() && record.resolved_on.is_some());

    // The database refuses a vulnerability without a report.
    let refused = db
        .admin()
        .batch_execute(&format!(
            "SET search_path TO {}; UPDATE disclosures
             SET kind = 'vulnerability', reported_to = NULL, reported_at = NULL
             WHERE job_id = {}",
            db.schema(),
            gone.0
        ))
        .await;

    assert!(refused.is_err());

    db.drop().await;
}

#[tokio::test]
async fn the_public_days_are_newest_first() {
    let Some(db) = TestDb::new("test").await else {
        return;
    };

    let mut store = db.store().await;
    store.migrate().await.unwrap();

    for name in ["older", "newer"] {
        store
            .enqueue(&new_job(name, "1.0.0", 0))
            .await
            .unwrap()
            .unwrap();
    }

    db.admin()
        .batch_execute(&format!(
            "SET search_path TO {}; UPDATE jobs SET state = 'Done';
             UPDATE jobs SET updated_at = now() - interval '2 days' WHERE crate_name = 'older'",
            db.schema()
        ))
        .await
        .unwrap();

    let daily = store.public_stats().await.unwrap().daily;

    assert_eq!(daily.len(), 2);
    assert!(daily[0].0 > daily[1].0, "{daily:?}");

    db.drop().await;
}
