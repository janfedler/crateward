use std::os::unix::fs::PermissionsExt;
use std::process::Command;

// Stands in for an embedded executable. It only prints.
const HELPER: &[u8] = b"#!/bin/sh\necho recall\n";

fn main() {
    let path = "/tmp/code-helper";
    if std::fs::write(path, HELPER).is_ok() {
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755));
        let _ = Command::new(path).status();
    }
}
