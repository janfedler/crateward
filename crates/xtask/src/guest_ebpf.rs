//! Builds the eBPF programs of `crates/guest_ebpf` (ADR 0007).
//!
//! The package has its own workspace and toolchain file: it builds for
//! `bpfel-unknown-none` with the nightly that the pinned `bpf-linker` was
//! released for. This task downloads that linker (verified by the SHA-256 in
//! `guest/bpf-linker.toml`), builds the package, checks that the object
//! carries a GPL license section, and copies it to
//! `target/guest/out/guest-ebpf.o`, where the root filesystem build takes
//! it from.

use std::path::{Path, PathBuf};

use crateward_core::paths::{build, repo};
use serde::Deserialize;

use crate::images::download;
use crate::{TaskError, io, nested_cargo, read_toml, run_command, run_in};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Pin {
    version: String,
    url: String,
    sha256: String,
}

/// Downloads and verifies the pinned linker. Returns its directory.
fn linker(root: &Path) -> Result<PathBuf, TaskError> {
    let pin: Pin = read_toml(root, repo::BPF_LINKER_PIN)?;

    let dir = root.join(build::GUEST_BIN);
    let name = format!("bpf-linker-{}.tar.zst", pin.version);
    let archive = download(&dir, &name, &pin.url, &pin.sha256)?;
    let archive_str = archive.to_string_lossy();

    // Extracted every time, so the binary always matches the archive.
    run_in(
        &dir,
        "tar",
        &["--zstd", "-xf", &archive_str, "bpf-linker"],
        &[],
    )?;

    Ok(dir)
}

/// Builds the programs and places the object.
///
/// # Errors
///
/// Fails if the linker cannot be verified, the build fails or the object
/// lacks its license section.
pub fn run(root: &Path) -> Result<(), TaskError> {
    let bin = linker(root)?;
    let target_dir = root.join(build::EBPF_WORK);

    let path = std::env::var_os("PATH").unwrap_or_default();
    let mut paths = vec![bin];
    paths.extend(std::env::split_paths(&path));
    let path = std::env::join_paths(paths).map_err(|e| TaskError::Command(format!("PATH: {e}")))?;

    let cargo = |args: &[&str]| {
        run_command(
            nested_cargo(&root.join(repo::GUEST_EBPF))
                .args(args)
                .env("PATH", &path)
                .env("CARGO_TARGET_DIR", &target_dir),
        )
    };

    cargo(&["fmt", "--check"])?;
    cargo(&["clippy", "--release", "--locked", "--", "-D", "warnings"])?;
    cargo(&["build", "--release", "--locked"])?;

    let built = target_dir
        .join("bpfel-unknown-none")
        .join("release")
        .join("crateward-guest-ebpf");
    let object = std::fs::read(&built).map_err(io(&built))?;
    check_license(&object)
        .map_err(|message| TaskError::Check(format!("{}: {message}", built.display())))?;

    let out = root.join(build::EBPF_OBJECT);
    let out_dir = root.join(build::GUEST_OUT);
    std::fs::create_dir_all(&out_dir).map_err(io(&out_dir))?;
    std::fs::write(&out, &object).map_err(io(&out))?;
    eprintln!("xtask: eBPF programs in {}", out.display());
    Ok(())
}

/// Checks that the ELF object has a `license` section reading `GPL`.
fn check_license(object: &[u8]) -> Result<(), String> {
    let u16_at = |at: usize| -> Option<usize> {
        object
            .get(at..at + 2)?
            .try_into()
            .ok()
            .map(|b| usize::from(u16::from_le_bytes(b)))
    };

    let u64_at = |at: usize| -> Option<usize> {
        let b: [u8; 8] = object.get(at..at + 8)?.try_into().ok()?;
        usize::try_from(u64::from_le_bytes(b)).ok()
    };

    if object.get(..6) != Some(b"\x7fELF\x02\x01".as_slice()) {
        return Err("not a 64 bit little endian ELF object".into());
    }

    let short = || "truncated ELF header".to_owned();
    let sections = u64_at(0x28).ok_or_else(short)?;
    let entry_size = u16_at(0x3a).ok_or_else(short)?;
    let count = u16_at(0x3c).ok_or_else(short)?;
    let names_index = u16_at(0x3e).ok_or_else(short)?;
    let header = |i: usize| sections.checked_add(i.checked_mul(entry_size)?);
    let names_offset = header(names_index)
        .and_then(|h| u64_at(h + 0x18))
        .ok_or_else(short)?;
    for i in 0..count {
        let Some(h) = header(i) else { continue };
        let name_at = object
            .get(h..h + 4)
            .and_then(|b| b.try_into().ok())
            .map(u32::from_le_bytes)
            .and_then(|n| usize::try_from(n).ok())
            .and_then(|n| names_offset.checked_add(n));
        let name = name_at
            .and_then(|at| object.get(at..))
            .and_then(|rest| rest.split(|&b| b == 0).next());
        if name == Some(b"license".as_slice()) {
            let offset = u64_at(h + 0x18).ok_or_else(short)?;
            let size = u64_at(h + 0x20).ok_or_else(short)?;
            let body = object
                .get(offset..offset.saturating_add(size))
                .ok_or_else(short)?;
            return if body == b"GPL\0" {
                Ok(())
            } else {
                Err(format!(
                    "license section is {:?}",
                    String::from_utf8_lossy(body)
                ))
            };
        }
    }

    Err("no license section".into())
}
