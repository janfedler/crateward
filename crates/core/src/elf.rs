//! Minimal ELF inspection to prove a binary is statically linked.
//!
//! A binary that names a program interpreter (`PT_INTERP`) needs a dynamic
//! loader. The guest agent must not have one, because a crate under
//! analysis could replace the guest's loader. Binaries started inside a
//! jail must not either, because a jail has no loader at all. Reading two
//! header fields is simpler and more precise than parsing `file` output.

use crate::bytes::{u16_le, u32_le, u64_le};

/// Program header type of an interpreter request.
const PT_INTERP: u32 = 3;

/// Whether a little endian 64 bit ELF file has no `PT_INTERP` header.
///
/// # Errors
///
/// Returns a message if the input is not a little endian ELF64 file or its
/// program header table is truncated.
pub fn is_static(bytes: &[u8]) -> Result<bool, &'static str> {
    if bytes.get(..4) != Some(b"\x7fELF".as_slice()) {
        return Err("not an ELF file");
    }

    if bytes.get(4) != Some(&2) || bytes.get(5) != Some(&1) {
        return Err("not a little endian ELF64 file");
    }

    let truncated = "truncated ELF header";
    let phoff = u64_le(bytes, 0x20).ok_or(truncated)?;
    let phentsize = u16_le(bytes, 0x36).ok_or(truncated)?;
    let phnum = u16_le(bytes, 0x38).ok_or(truncated)?;
    let phoff = usize::try_from(phoff).map_err(|_| truncated)?;
    for index in 0..usize::from(phnum) {
        let entry = index
            .checked_mul(usize::from(phentsize))
            .and_then(|offset| offset.checked_add(phoff))
            .ok_or(truncated)?;
        let kind = u32_le(bytes, entry).ok_or("truncated program header table")?;
        if kind == PT_INTERP {
            return Ok(false);
        }
    }

    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_non_elf_input() {
        assert!(is_static(b"not elf").is_err());
        assert!(is_static(b"").is_err());
    }

    #[test]
    fn the_running_test_binary_is_classified_without_error() {
        // The test binary itself is a valid ELF file on Linux. Whether it is
        // static depends on the host target, so only the parse is checked.
        let me = std::env::current_exe().unwrap();
        let bytes = std::fs::read(me).unwrap();

        assert!(is_static(&bytes).is_ok());
    }
}
