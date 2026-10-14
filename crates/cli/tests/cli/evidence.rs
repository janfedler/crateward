//! Evidence packs.

use super::*;

fn json_file(pack: &Path, name: &str) -> Value {
    let text = std::fs::read_to_string(pack.join(name)).unwrap();

    assert!(
        text.ends_with("}\n") || text.ends_with("]\n") || text == "null\n",
        "{name}"
    );

    serde_json::from_str(&text).unwrap()
}

/// What [`seed`] stored besides the job.
struct Seeded {
    job: JobId,
    triage: Value,
    reasons: Value,
    diff: Value,
    report: Value,
    packages: Value,
}

/// A fetched job with a verdict, a static report, two runs, a resolution
/// and the original crate file, with the honeytoken in several of them.
async fn seed(db: &mut Db, site: &Site) -> Seeded {
    let entry = json!({"name": "evil", "vers": "0.1.0", "note": TOKEN});
    let job = db.job("evil", "0.1.0", entry).await;
    let store = &mut db.store;
    let lease = Duration::from_secs(30);
    store
        .claim(Stage::Fetch, "fetcher-1", lease)
        .await
        .unwrap()
        .unwrap();
    let policies = policies();
    let done = store.complete(job, "fetcher-1", JobEvent::Fetched, &policies, false);
    done.await.unwrap();
    store
        .record_honeytokens(job, &[("crates_io".to_owned(), TOKEN.to_owned())])
        .await
        .unwrap();
    store.record_verdict(job, &verdict()).await.unwrap();
    let file = CrateFile {
        sha256: CKSUM.parse().unwrap(),
        sha512: None,
        name: "evil".to_owned(),
        version: "0.1.0".to_owned(),
        blake3: None,
        compressed_bytes: 5,
        unpacked_bytes: 9,
        stored_bytes: None,
        report: json!({}),
    };

    store.record_crate_file(&file).await.unwrap();
    let report = json!({"findings": []});
    let cksum = CKSUM.parse().unwrap();
    store
        .record_static_report(&cksum, 7, true, Some("high"), &report)
        .await
        .unwrap();
    let (triage, reasons, diff) = (
        json!({"decision": "dynamic"}),
        json!(["build script"]),
        json!({"added": 1}),
    );

    store
        .record_job_static(job, &triage, &reasons, Some(&diff))
        .await
        .unwrap();
    store
        .record_run(job, "full", "completed", &json!({"network": TOKEN}))
        .await
        .unwrap();
    store
        .record_run(job, "check", "completed", &json!({"tokens": [TOKEN]}))
        .await
        .unwrap();
    let packages = json!([{"name": "evil", "version": "0.1.0"}]);
    store
        .record_fetch(job, Some(&format!("# {TOKEN}\n")), None, &packages)
        .await
        .unwrap();
    let originals = site.path("data/originals");
    std::fs::create_dir_all(&originals).unwrap();
    std::fs::write(originals.join(format!("{CKSUM}.crate")), b"crate bytes").unwrap();

    Seeded {
        job,
        triage,
        reasons,
        diff,
        report,
        packages,
    }
}

#[tokio::test]
async fn evidence_writes_a_redacted_and_checksummed_pack() {
    let Some(mut db) = Db::new().await else {
        return;
    };

    let site = Site::new(&db.url);
    let Seeded {
        job,
        triage,
        reasons,
        diff,
        report,
        packages,
    } = seed(&mut db, &site).await;

    let pack = site.path("pack");
    let id = job.0.to_string();
    let ran = site.run(&["evidence", &id, "--out", pack.to_str().unwrap()]);
    let names = [
        "job.json",
        "verdict.json",
        "static.json",
        "runs.json",
        "resolution.json",
        "evil-0.1.0.crate",
        "SHA256SUMS",
    ];

    let listing: String = names.iter().map(|n| format!("  {n}\n")).collect();
    ran.expect(
        0,
        &format!("wrote 7 files to {}\n{listing}", pack.display()),
        "",
    );

    let mut record = json_file(&pack, "job.json");
    let at = record["events"][0]["at_unix"].take();

    assert!(at.as_u64().unwrap() > 1_700_000_000, "{at}");

    let expected = json!({
        "id": job.0,
        "name": "evil",
        "version": "0.1.0",
        "sha256": CKSUM,
        "state": {
            "attempts": 0, "coverage": null, "dynamic_runs": 0, "escalated": false,
            "failure": null, "infrastructure_retries": 0, "last_build": null,
            "outcome": null, "run_kind": "check", "state": "fetched", "triage": null,
        },
        "index_entry": {"name": "evil", "vers": "0.1.0", "note": "[honeytoken]"},
        "events": [{
            "at_unix": null, "from": "Discovered", "to": "Fetched",
            "event": {"kind": "fetched"}, "effect": {"kind": "none"},
        }],
    });

    assert_eq!(record, expected);

    let raw = std::fs::read_to_string(pack.join("job.json")).unwrap();
    assert!(raw.starts_with("{\n  \""), "{raw}");
    assert!(raw.contains("\n  \"events\": [\n    {\n"), "{raw}");

    let expected = json!({"verdict": verdict(), "review": "none"});

    assert_eq!(json_file(&pack, "verdict.json"), expected);

    let expected = json!({
        "triage": triage,
        "reasons": reasons,
        "diff": diff,
        "report": {"analyzer_version": 7, "report": report},
    });

    assert_eq!(json_file(&pack, "static.json"), expected);

    let expected = json!([
        {"kind": "check", "report": {"tokens": ["[honeytoken]"]}},
        {"kind": "full", "report": {"network": "[honeytoken]"}},
    ]);

    assert_eq!(json_file(&pack, "runs.json"), expected);

    let expected = json!({"packages": packages, "lockfile": "# [honeytoken]\n"});
    assert_eq!(json_file(&pack, "resolution.json"), expected);
    assert_eq!(
        std::fs::read(pack.join("evil-0.1.0.crate")).unwrap(),
        b"crate bytes"
    );

    let sums = std::fs::read_to_string(pack.join("SHA256SUMS")).unwrap();
    let mut lines = sums.lines();
    for name in &names[..6] {
        use sha2::Digest as _;
        let digest = sha2::Sha256::digest(std::fs::read(pack.join(name)).unwrap());

        assert_eq!(lines.next().unwrap(), format!("{digest:x}  {name}"));
    }

    assert_eq!(lines.next(), None);

    for name in names {
        let text = std::fs::read(pack.join(name)).unwrap();

        assert!(
            !text.windows(TOKEN.len()).any(|w| w == TOKEN.as_bytes()),
            "{name}"
        );
    }

    db.drop().await;
}

#[tokio::test]
async fn evidence_of_a_bare_job_and_the_ways_it_fails() {
    let Some(db) = Db::new().await else { return };
    let site = Site::new(&db.url);
    let job = db.job("evil", "0.1.0", json!({})).await;
    let id = job.0.to_string();
    let pack = site.path("pack");
    let pack_arg = pack.to_str().unwrap();
    let ran = site.run(&["evidence", &id, "--out", pack_arg]);

    assert_eq!(
        (ran.code, ran.err.as_str().lines().count()),
        (0, 1),
        "{}",
        ran.err
    );
    assert!(
        ran.err.starts_with("the original crate file is missing ("),
        "{}",
        ran.err
    );
    assert!(
        ran.err.ends_with("), so the pack has none\n"),
        "{}",
        ran.err
    );

    let listing = [
        "job.json",
        "verdict.json",
        "static.json",
        "runs.json",
        "resolution.json",
        "SHA256SUMS",
    ];

    let listing: String = listing.iter().map(|n| format!("  {n}\n")).collect();
    assert_eq!(
        ran.out,
        format!("wrote 6 files to {}\n{listing}", pack.display())
    );
    assert_eq!(json_file(&pack, "verdict.json"), Value::Null);

    let expected = json!({"triage": null, "reasons": null, "diff": null, "report": null});
    assert_eq!(json_file(&pack, "static.json"), expected);
    assert_eq!(json_file(&pack, "runs.json"), json!([]));

    let expected = json!({"packages": null, "lockfile": null});
    assert_eq!(json_file(&pack, "resolution.json"), expected);

    let again = site.run(&["evidence", &id, "--out", pack_arg]);
    assert_eq!((again.code, again.out.as_str()), (1, ""));
    assert!(
        again.err.starts_with(&format!("{}: ", pack.display())),
        "{}",
        again.err
    );

    let other = site.path("other");
    let unknown = site.run(&["evidence", "999999", "--out", other.to_str().unwrap()]);
    unknown.expect(1, "", "no job 999999\n");

    assert!(!other.exists());

    db.drop().await;
}
