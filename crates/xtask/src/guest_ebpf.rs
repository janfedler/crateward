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

use crateward_core::bytes::{u16_le, u32_le, u64_le};
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
    if object.get(..6) != Some(b"\x7fELF\x02\x01".as_slice()) {
        return Err("not a 64 bit little endian ELF object".into());
    }

    let body = license(object).ok_or("no readable license section")?;
    if body != b"GPL\0" {
        return Err(format!(
            "license section is {:?}",
            String::from_utf8_lossy(body)
        ));
    }

    Ok(())
}

/// The contents of the section named `license`, if the section headers
/// can be read.
fn license(object: &[u8]) -> Option<&[u8]> {
    let offset = |at: usize| usize::try_from(u64_le(object, at)?).ok();
    let sections = offset(0x28)?;
    let entry_size = usize::from(u16_le(object, 0x3a)?);
    let count = usize::from(u16_le(object, 0x3c)?);
    let header = |i: usize| sections.checked_add(i.checked_mul(entry_size)?);
    let names = offset(header(usize::from(u16_le(object, 0x3e)?))?.checked_add(0x18)?)?;

    for i in 0..count {
        let h = header(i)?;
        let name_at = names.checked_add(usize::try_from(u32_le(object, h)?).ok()?)?;
        let name = object.get(name_at..)?.split(|&b| b == 0).next()?;
        if name == b"license" {
            let start = offset(h.checked_add(0x18)?)?;
            let size = offset(h.checked_add(0x20)?)?;

            return object.get(start..start.checked_add(size)?);
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An ELF object with a section name table and a `license` section.
    fn object(license: &[u8]) -> Vec<u8> {
        let mut o = vec![0_u8; 224];
        o[..6].copy_from_slice(b"\x7fELF\x02\x01");
        o[0x28..0x30].copy_from_slice(&96_u64.to_le_bytes());
        o[0x3a..0x3c].copy_from_slice(&64_u16.to_le_bytes());
        o[0x3c..0x3e].copy_from_slice(&2_u16.to_le_bytes());
        o[64..73].copy_from_slice(b"\0license\0");
        o[80..80 + license.len()].copy_from_slice(license);

        for (header, name, offset, size) in [(96, 0, 64, 9), (160, 1, 80, license.len())] {
            o[header..header + 4].copy_from_slice(&(name as u32).to_le_bytes());
            o[header + 0x18..header + 0x20].copy_from_slice(&(offset as u64).to_le_bytes());
            o[header + 0x20..header + 0x28].copy_from_slice(&(size as u64).to_le_bytes());
        }

        o
    }

    #[test]
    fn only_a_gpl_license_section_passes() {
        assert_eq!(check_license(&object(b"GPL\0")), Ok(()));
        assert!(
            check_license(&object(b"MIT\0"))
                .unwrap_err()
                .contains("MIT")
        );
        assert!(check_license(b"\x7fELF\x01\x01").is_err());

        let mut truncated = object(b"GPL\0");
        truncated.truncate(190);

        assert_eq!(
            check_license(&truncated),
            Err("no readable license section".into())
        );
    }
}
