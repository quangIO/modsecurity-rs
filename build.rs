use std::path::PathBuf;

fn main() -> miette::Result<()> {
    let mut b = autocxx_build::Builder::new("src/lib.rs", [] as [PathBuf; 0]).build()?;
    b.flag_if_supported("-std=c++14").compile("autocxx-demo"); // arbitrary library name, pick anything
    println!("cargo:rerun-if-changed=src/lib.rs");
    println!("cargo:rustc-link-lib=modsecurity");
    Ok(())
}
