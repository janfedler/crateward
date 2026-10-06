//! POSIX access ACLs, written directly as the kernel's extended attribute.
//!
//! A slot's root directory is owned by the orchestrator, so the orchestrator
//! can always clean it up, even when Firecracker (running as the slot's
//! subordinate UID) created files inside. An ACL entry grants that one UID
//! access. No other user, and no group, gets any. The owner of a file may
//! set its ACL without privileges.
//!
//! The format is `struct posix_acl_xattr_header` followed by sorted
//! `struct posix_acl_xattr_entry` records, little endian, as defined in the
//! kernel's `include/uapi/linux/posix_acl_xattr.h`.

use std::path::Path;

/// `POSIX_ACL_XATTR_VERSION`.
const VERSION: u32 = 2;
/// Tags from `include/uapi/linux/posix_acl.h`.
const ACL_USER_OBJ: u16 = 0x01;
const ACL_USER: u16 = 0x02;
const ACL_GROUP_OBJ: u16 = 0x04;
const ACL_MASK: u16 = 0x10;
const ACL_OTHER: u16 = 0x20;
/// `ACL_UNDEFINED_ID`, used by entries that carry no ID.
const UNDEFINED_ID: u32 = u32::MAX;
/// Read, write and search permission.
const RWX: u16 = 0o7;

/// Encodes an access ACL: the owner and each of `uids` get full access.
/// The owning group and everybody else get none.
#[must_use]
pub fn owner_and_users_only(uids: &[u32]) -> Vec<u8> {
    // Entries must be sorted by tag, then ID.
    let mut users = uids.to_vec();
    users.sort_unstable();
    users.dedup();
    let entries = std::iter::once((ACL_USER_OBJ, RWX, UNDEFINED_ID))
        .chain(users.into_iter().map(|uid| (ACL_USER, RWX, uid)))
        .chain([
            (ACL_GROUP_OBJ, 0, UNDEFINED_ID),
            (ACL_MASK, RWX, UNDEFINED_ID),
            (ACL_OTHER, 0, UNDEFINED_ID),
        ]);

    let mut out = Vec::with_capacity(4 + (uids.len() + 4) * 8);
    out.extend_from_slice(&VERSION.to_le_bytes());

    for (tag, perm, id) in entries {
        out.extend_from_slice(&tag.to_le_bytes());
        out.extend_from_slice(&perm.to_le_bytes());
        out.extend_from_slice(&id.to_le_bytes());
    }

    out
}

/// Sets the access ACL of `path` to [`owner_and_users_only`] for one UID.
///
/// # Errors
///
/// Fails if the filesystem does not support ACLs or the caller does not own
/// the file.
pub fn grant_user(path: &Path, uid: u32) -> std::io::Result<()> {
    grant_users(path, &[uid])
}

/// Sets the access ACL of `path` to [`owner_and_users_only`].
///
/// # Errors
///
/// Fails if the filesystem does not support ACLs or the caller does not own
/// the file.
pub fn grant_users(path: &Path, uids: &[u32]) -> std::io::Result<()> {
    rustix::fs::setxattr(
        path,
        "system.posix_acl_access",
        &owner_and_users_only(uids),
        rustix::fs::XattrFlags::empty(),
    )
    .map_err(std::io::Error::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encoding_matches_the_kernel_layout() {
        let bytes = owner_and_users_only(&[160_000]);

        assert_eq!(bytes.len(), 4 + 5 * 8);
        assert_eq!(bytes[..4], 2_u32.to_le_bytes());

        // Second entry: ACL_USER with rwx for the given UID.
        assert_eq!(bytes[12..14], ACL_USER.to_le_bytes());
        assert_eq!(bytes[14..16], 7_u16.to_le_bytes());
        assert_eq!(bytes[16..20], 160_000_u32.to_le_bytes());
    }

    #[test]
    fn several_users_are_sorted_and_deduplicated() {
        let bytes = owner_and_users_only(&[160_002, 160_000, 160_002]);
        let ids: Vec<u32> = bytes[4..]
            .chunks(8)
            .filter(|e| e[..2] == ACL_USER.to_le_bytes())
            .map(|e| u32::from_le_bytes([e[4], e[5], e[6], e[7]]))
            .collect();

        assert_eq!(ids, [160_000, 160_002]);
        assert_eq!(bytes.len(), 4 + 6 * 8);
    }

    #[test]
    fn getfacl_reads_back_what_was_written() {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/acl-tests")
            .join(std::process::id().to_string());
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        grant_user(&dir, 160_000).unwrap();
        let out = std::process::Command::new("getfacl")
            .args(["--numeric", "--omit-header"])
            .arg(&dir)
            .output();
        std::fs::remove_dir_all(&dir).unwrap();

        // getfacl is optional on developer machines.
        let Ok(out) = out else { return };
        let text = String::from_utf8_lossy(&out.stdout);

        assert!(text.contains("user:160000:rwx"), "{text}");
        assert!(text.contains("group::---"), "{text}");
        assert!(text.contains("other::---"), "{text}");
    }
}
