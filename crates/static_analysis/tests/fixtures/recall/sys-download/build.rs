use std::process::Command;

fn main() {
    let out = std::env::var("OUT_DIR").unwrap_or_default();
    if std::env::var("RECALL_LIB_DIR").is_err() {
        let _ = Command::new("curl")
            .args(["-sL", "-o"])
            .arg(format!("{out}/librecall.a"))
            .arg("https://github.com/recall/recall/releases/download/v1.0.0/librecall.a")
            .status();
    }

    println!("cargo:rustc-link-search=native={out}");
    println!("cargo:rustc-link-lib=static=recall");
}
