fn main() {
    let out = std::env::var("OUT_DIR").unwrap_or_default();
    let code = "pub const ANSWER: u32 = 42;\n";
    let _ = std::fs::write(format!("{out}/generated.rs"), code);
    println!("cargo:rerun-if-changed=build.rs");
}
