//! Embeds `yw-app.manifest` (comctl32 v6 controls, Per-Monitor-V2 DPI) into the binary only
//! (spec/04 §1.6, spec/01 §2.4: the one allowed build script prints link arguments only).

fn main() {
    let Some(dir) = std::env::var_os("CARGO_MANIFEST_DIR") else {
        return;
    };
    let manifest = std::path::Path::new(&dir).join("yw-app.manifest");
    println!("cargo:rerun-if-changed=yw-app.manifest");
    println!("cargo:rustc-link-arg-bins=/MANIFEST:EMBED");
    println!(
        "cargo:rustc-link-arg-bins=/MANIFESTINPUT:{}",
        manifest.display()
    );
}
