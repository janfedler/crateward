use std::process::Command;

use super::*;
use crateward_core::paths::host::MKFS_EXT4;

/// Builds an ext4 image from a directory with `mkfs.ext4 -d`, as the
/// orchestrator formats scratch disks with the same tool.
fn image(files: &[(&str, &[u8], u32)]) -> Option<Vec<u8>> {
    use std::os::unix::fs::PermissionsExt;

    build_image(|root| {
        for (path, data, mode) in files {
            let full = root.join(path.trim_start_matches('/'));
            std::fs::create_dir_all(full.parent().unwrap_or(root))?;
            std::fs::write(&full, data)?;
            std::fs::set_permissions(&full, std::fs::Permissions::from_mode(*mode))?;
        }

        Ok(())
    })
}

/// Builds an ext4 image of what `populate` puts below the root.
fn build_image(populate: impl FnOnce(&Path) -> io::Result<()>) -> Option<Vec<u8>> {
    let dir = std::env::temp_dir().join(format!(
        "cw-scratch-{}-{}",
        std::process::id(),
        rand::random::<u32>()
    ));

    let root = dir.join("root");
    std::fs::create_dir_all(root.join("target/debug")).ok()?;
    std::fs::create_dir_all(root.join("home/.cargo")).ok()?;
    populate(&root).ok()?;
    let out = dir.join("scratch.img");
    let status = Command::new(MKFS_EXT4)
        .args(["-q", "-F", "-d"])
        .arg(&root)
        .arg(&out)
        .arg("8M")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .ok()?;

    let data = status.success().then(|| std::fs::read(&out).ok()).flatten();
    let _ = std::fs::remove_dir_all(&dir);

    data
}

fn spec() -> ScanSpec {
    ScanSpec {
        tokens: vec!["cioSECRETTOKEN0123".into()],
        planted: vec!["/work/home/.cargo/credentials.toml".into()],
        created: vec![
            "/work/home".into(),
            "/work/home/.cargo".into(),
            "/work/target".into(),
        ],
        environment: vec!["/work/home/.cargo".into(), "C.UTF-8".into()],
    }
}

#[test]
fn finds_what_a_job_left_outside_the_build() {
    let Some(data) = image(&[
        (
            "/home/.cargo/credentials.toml",
            b"token = \"cioSECRETTOKEN0123\"",
            0o600,
        ),
        ("/target/debug/libx.rlib", b"normal output", 0o644),
        ("/target/debug/deps/libx-0123abcd.rmeta", b"metadata", 0o644),
        ("/target/debug/deps/x-0123abcd.d", b"dep info", 0o644),
        ("/target/debug/build-script-build", b"\x7fELF...", 0o755),
        (
            "/target/debug/out/stolen.txt",
            b"xx cioSECRETTOKEN0123 xx",
            0o644,
        ),
        (
            "/home/.config/autostart/evil.desktop",
            b"[Desktop Entry]",
            0o644,
        ),
        ("/home/.local/bin/dropper", b"\x7fELF payload", 0o644),
        ("/home/.cargo/.global-cache", b"sqlite", 0o644),
    ]) else {
        eprintln!("skipping: mkfs.ext4 is not available");
        return;
    };

    let fs = Ext4::load(Box::new(data)).unwrap();
    let report = scan(&fs, &spec());

    assert!(report.error.is_none(), "{:?}", report.error);

    let paths: Vec<&str> = report
        .outside_build
        .iter()
        .map(|e| e.path.as_str())
        .collect();

    assert!(paths.contains(&"/work/home/.config/autostart/evil.desktop"));
    assert!(paths.contains(&"/work/home/.local/bin/dropper"));
    assert!(!paths.iter().any(|p| p.starts_with("/work/target")));
    assert!(!paths.contains(&"/work/home/.cargo/.global-cache"));
    assert!(!paths.contains(&"/work/home/.cargo/credentials.toml"));
    assert_eq!(
        report
            .executables_outside_target
            .iter()
            .map(|e| e.path.as_str())
            .collect::<Vec<_>>(),
        ["/work/home/.local/bin/dropper"]
    );
    assert_eq!(
        report.tokens_found,
        [(0, "/work/target/debug/out/stolen.txt".to_owned())]
    );
    assert_eq!(report.environment_dumps, Some(Vec::new()));
    assert!(report.planted_changed.is_empty());
    assert!(report.files >= 7);
    assert_eq!(report.units, ["libx-0123abcd.rmeta"]);
}

#[test]
fn a_token_with_the_rest_of_the_environment_is_a_dump() {
    // A dump whose values lie in two reads, a token without the
    // environment, and the environment without a token.
    let mut split = b"LANG=\"C.UTF-8\" ".to_vec();
    split.resize(64 * 1024 - 4, b' ');
    split.extend_from_slice(b"GITHUB_TOKEN=\"cioSECRETTOKEN0123\" CARGO_HOME=/work/home/.cargo");
    let Some(data) = image(&[
        (
            "/target/debug/build/z-0123456789abcdef/output",
            &split,
            0o644,
        ),
        (
            "/target/debug/build/y-0123456789abcdef/output",
            b"cioSECRETTOKEN0123",
            0o644,
        ),
        ("/target/debug/env", b"C.UTF-8 /work/home/.cargo", 0o644),
    ]) else {
        eprintln!("skipping: mkfs.ext4 is not available");
        return;
    };

    let fs = Ext4::load(Box::new(data)).unwrap();
    let report = scan(&fs, &spec());

    assert_eq!(report.tokens_found.len(), 2);
    assert_eq!(
        report.environment_dumps,
        Some(vec![
            "/work/target/debug/build/z-0123456789abcdef/output".to_owned()
        ])
    );
}

fn mkfifo(path: &Path) -> io::Result<()> {
    let status = Command::new("mkfifo").arg(path).status()?;

    status
        .success()
        .then_some(())
        .ok_or_else(|| io::Error::other("mkfifo failed"))
}

fn paths(entries: &[Entry]) -> Vec<&str> {
    let mut paths: Vec<&str> = entries.iter().map(|e| e.path.as_str()).collect();
    paths.sort_unstable();

    paths
}

#[test]
fn sorts_what_a_job_left_into_the_lists_of_the_report() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::os::unix::net::UnixListener;
    let Some(data) = build_image(|root| {
        let write = |path: &str, mode: u32| {
            let path = root.join(path);
            std::fs::create_dir_all(path.parent().unwrap_or(root))?;
            std::fs::write(&path, b"data")?;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        };

        write("home/.local/su", 0o4755)?;
        write(".warm/upper/debug/deps/libw-0123456789abcdef.rlib", 0o755)?;
        write(".warm/other/tool", 0o755)?;
        write("target/debug/deps/z.so", 0o644)?;
        write("target/debug/deps/z.d", 0o644)?;
        write("target/debug/deps/sub/libq.rlib", 0o644)?;
        let local = root.join("home/.local");
        std::fs::create_dir(local.join("sgdir"))?;
        std::fs::set_permissions(local.join("sgdir"), std::fs::Permissions::from_mode(0o2755))?;
        symlink("/etc/passwd", local.join("abs"))?;
        symlink("../../etc", local.join("up"))?;
        symlink("/work/target/debug/x", local.join("in"))?;
        symlink("notes", local.join("rel"))?;
        symlink("/etc/shadow", root.join("target/debug/link"))?;
        mkfifo(&local.join("pipe"))?;
        mkfifo(&root.join("target/debug/fifo"))?;
        UnixListener::bind(local.join("sock"))?;
        Ok(())
    }) else {
        eprintln!("skipping: mkfs.ext4 is not available");
        return;
    };

    let fs = Ext4::load(Box::new(data)).unwrap();
    let report = scan(&fs, &spec());

    assert_eq!(report.error, None);
    assert!(!report.incomplete);
    assert_eq!(
        paths(&report.outside_build),
        [
            "/work/home/.local",
            "/work/home/.local/abs",
            "/work/home/.local/in",
            "/work/home/.local/pipe",
            "/work/home/.local/rel",
            "/work/home/.local/sgdir",
            "/work/home/.local/sock",
            "/work/home/.local/su",
            "/work/home/.local/up",
        ]
    );
    assert_eq!(paths(&report.setid), ["/work/home/.local/su"]);
    assert_eq!(
        paths(&report.special),
        [
            "/work/home/.local/pipe",
            "/work/home/.local/sock",
            "/work/target/debug/fifo",
        ]
    );
    assert_eq!(
        paths(&report.links_outside),
        [
            "/work/home/.local/abs",
            "/work/home/.local/up",
            "/work/target/debug/link",
        ]
    );
    assert_eq!(
        paths(&report.executables_outside_target),
        ["/work/.warm/other/tool", "/work/home/.local/su"]
    );

    let mut units = report.units.clone();
    units.sort_unstable();

    assert_eq!(units, ["libw-0123456789abcdef.rlib", "z.so"]);
    assert_eq!(
        (report.files, report.bytes, report.directories),
        (6, 24, 14)
    );
    assert_eq!(report.omitted, 0);
    assert_eq!(
        report.planted_changed,
        ["/work/home/.cargo/credentials.toml"]
    );

    let link = report
        .links_outside
        .iter()
        .find(|e| e.path.ends_with("/abs"));

    let link = link.unwrap();

    assert_eq!(
        (link.kind.as_str(), link.target.as_deref()),
        ("symlink", Some("/etc/passwd"))
    );

    let su = report.setid.first().unwrap();
    assert_eq!(
        (su.kind.as_str(), su.mode & 0o7777, su.size),
        ("file", 0o4755, 4)
    );
}

#[test]
fn paths_tell_what_they_belong_to() {
    for build in [
        "/target",
        "/target/debug/x",
        "/.warm",
        "/.warm/upper/x",
        "/lost+found",
    ] {
        assert!(in_build_area(build), "{build}");
    }

    for other in ["/targets", "/home/target", "/.warmer", "/home/.cargo", "/"] {
        assert!(!in_build_area(other), "{other}");
    }

    assert!(is_cargo_state("/home/.cargo/.package-cache-mutate"));
    assert!(is_cargo_state("/home/.cargo/registry/CACHEDIR.TAG"));
    assert!(!is_cargo_state("/home/.cargo/registry/src"));
    assert!(!is_cargo_state("/home/.cargo/config.toml"));
    assert_eq!(
        unit_name("/target/debug/deps/libx-1.rlib"),
        Some("libx-1.rlib")
    );
    assert_eq!(unit_name("/.warm/upper/debug/deps/x-1.so"), Some("x-1.so"));
    assert_eq!(unit_name("/target/debug/deps/x-1.d"), None);
    assert_eq!(unit_name("/target/debug/deps/sub/x-1.rlib"), None);
    assert_eq!(unit_name("/target/release/deps/x-1.rlib"), None);
    assert!(leaves_scratch("/etc/passwd"));
    assert!(leaves_scratch("a/../b"));
    assert!(!leaves_scratch("/work/target/x"));
    assert!(!leaves_scratch("notes.txt"));
}

#[test]
fn a_walk_that_goes_too_deep_is_incomplete() {
    let deep = format!("/deep{}/x", "/d".repeat(MAX_DEPTH + 2));
    let Some(data) = image(&[(deep.as_str(), b"x", 0o644)]) else {
        eprintln!("skipping: mkfs.ext4 is not available");
        return;
    };

    let fs = Ext4::load(Box::new(data)).unwrap();
    let report = scan(&fs, &spec());

    assert_eq!(report.error, None);
    assert!(report.incomplete);

    // The file below the limit is not seen.
    assert_eq!(report.files, 0);
}

#[test]
fn exports_the_target_directory_only() {
    let Some(data) = image(&[
        ("/target/debug/deps/libx-0123.rmeta", b"metadata", 0o4755),
        ("/target/debug/.fingerprint/x-0123/lib-x", b"fp", 0o644),
        (
            "/target/debug/.fingerprint/stub-crate-0123456789abcdef/lib",
            b"fp",
            0o644,
        ),
        (
            "/target/debug/deps/libstub_crate-0123456789abcdef.rmeta",
            b"m",
            0o644,
        ),
        (
            "/target/debug/deps/stub_crate-0123456789abcdef.d",
            b"d",
            0o644,
        ),
        ("/home/.cargo/credentials.toml", b"secret", 0o600),
    ]) else {
        return;
    };

    let fs = Ext4::load(Box::new(data)).unwrap();
    let mut tar = Vec::new();
    export(&fs, &mut tar, &["stub-crate".into()]).unwrap();
    let mut archive = tar::Archive::new(tar.as_slice());
    let mut seen = Vec::new();

    for entry in archive.entries().unwrap() {
        let entry = entry.unwrap();
        let path = entry.path().unwrap().to_string_lossy().into_owned();
        if path.ends_with(".rmeta") {
            // Set ID bits never survive.
            assert_eq!(entry.header().mode().unwrap(), 0o755);
        }

        seen.push(path);
    }

    assert!(seen.contains(&"target/debug/deps/libx-0123.rmeta".to_owned()));
    assert!(seen.contains(&"target/debug/.fingerprint/x-0123/lib-x".to_owned()));
    assert!(seen.iter().all(|p| p.starts_with("target/")));
    assert!(seen.iter().all(|p| !p.contains("stub")), "{seen:?}");
}

#[test]
fn unit_owners_follow_cargo_names() {
    let h = "0123456789abcdef";

    assert_eq!(
        unit_owner("target/debug/.fingerprint", &format!("serde-json-{h}")).as_deref(),
        Some("serde_json")
    );
    assert_eq!(
        unit_owner("target/debug/deps", &format!("libserde_json-{h}.rmeta")).as_deref(),
        Some("serde_json")
    );
    assert_eq!(
        unit_owner("target/debug/deps", &format!("serde_json-{h}.d")).as_deref(),
        Some("serde_json")
    );
    assert_eq!(
        unit_owner("target/debug/deps", &format!("liblibc-{h}.rmeta")).as_deref(),
        Some("libc")
    );
    assert_eq!(
        unit_owner("target/debug/build", &format!("ring-{h}")).as_deref(),
        Some("ring")
    );
    assert_eq!(unit_owner("target/debug", "deps"), None);
    assert_eq!(unit_owner("target/debug/deps", "short-123.rmeta"), None);
}

#[test]
fn a_superblock_larger_than_its_image_is_rejected() {
    // The shape of the fuzz finding: a huge block count and one block
    // per group, which asked `ext4-view` for 8 GiB.
    let mut sb = vec![0_u8; 1024];
    sb[0x4..0x8].copy_from_slice(&u32::MAX.to_le_bytes());
    sb[0x20..0x24].copy_from_slice(&1_u32.to_le_bytes());

    assert!(matches!(
        check_geometry(&sb, 1 << 20),
        Err(GeometryError::TooLarge { .. })
    ));

    sb[0x4..0x8].copy_from_slice(&1024_u32.to_le_bytes());

    assert_eq!(check_geometry(&sb, 1 << 20), Ok(()));

    sb[0x150..0x154].copy_from_slice(&1_u32.to_le_bytes());

    assert!(matches!(
        check_geometry(&sb, 1 << 20),
        Err(GeometryError::TooLarge { .. })
    ));

    let Some(data) = image(&[("/target/debug/x", b"x", 0o644)]) else {
        return;
    };

    assert_eq!(check_geometry(&data[1024..2048], data.len() as u64), Ok(()));
}

#[test]
fn a_superblock_that_cannot_be_read_or_makes_no_sense_is_named() {
    let sb = vec![0_u8; 1024];

    assert_eq!(
        check_geometry(&sb[..100], 1 << 20),
        Err(GeometryError::Truncated)
    );
    assert_eq!(check_geometry(&sb, 1 << 20), Err(GeometryError::Impossible));
}

#[test]
fn a_target_directory_nested_too_deeply_is_refused() {
    let deep = format!("/target{}/x", "/d".repeat(MAX_DEPTH + 2));
    let Some(data) = image(&[(deep.as_str(), b"x", 0o644)]) else {
        return;
    };

    let fs = Ext4::load(Box::new(data)).unwrap();
    assert!(matches!(
        export(&fs, io::sink(), &[]),
        Err(ExportError::TooDeep)
    ));
}

#[test]
fn garbage_is_an_error_not_a_panic() {
    let mut data = vec![0_u8; 4 * 1024 * 1024];
    for (i, b) in data.iter_mut().enumerate() {
        *b = (i.wrapping_mul(2_654_435_761) >> 13) as u8;
    }

    assert!(Ext4::load(Box::new(data)).is_err());
}

#[test]
fn a_missing_planted_file_is_reported() {
    let Some(data) = image(&[("/target/debug/x", b"x", 0o644)]) else {
        return;
    };

    let fs = Ext4::load(Box::new(data)).unwrap();
    let report = scan(&fs, &spec());

    assert_eq!(
        report.planted_changed,
        ["/work/home/.cargo/credentials.toml"]
    );
}
