#![no_main]

use libfuzzer_sys::fuzz_target;
use crateward_orchestrator::scratch::{ScanSpec, check_geometry, scan};
use ext4_view::Ext4;

// Scratch disks: an ext4 image the guest wrote, possibly crafted. The
// child checks the geometry before it loads the image, and so does this.
fuzz_target!(|data: &[u8]| {
    let Some(superblock) = data.get(1024..2048) else { return };
    if check_geometry(superblock, data.len() as u64).is_err() {
        return;
    }
    if let Ok(fs) = Ext4::load(Box::new(data.to_vec())) {
        let spec = ScanSpec {
            tokens: vec!["cioTOKEN".into()],
            planted: vec!["/work/home/.cargo/credentials.toml".into()],
            created: Vec::new(),
        };
        let _ = scan(&fs, &spec);
    }
});
