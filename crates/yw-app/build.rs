//! Embeds `yw-app.manifest` (comctl32 v6 controls, Per-Monitor-V2 DPI) and links the committed
//! icon resources `icons/yw-app.res` (`RT_GROUP_ICON` 1, written by `scripts/make-icons.mjs`) into
//! the binary only (spec/04 §1.6–1.7, spec/01 §2.4: the one allowed build script prints link
//! arguments only).

fn main() {
    let Some(dir) = std::env::var_os("CARGO_MANIFEST_DIR") else {
        return;
    };
    let dir = std::path::Path::new(&dir);
    println!("cargo:rerun-if-changed=yw-app.manifest");
    println!("cargo:rerun-if-changed=icons/yw-app.res");
    println!("cargo:rustc-link-arg-bins=/MANIFEST:EMBED");
    println!(
        "cargo:rustc-link-arg-bins=/MANIFESTINPUT:{}",
        dir.join("yw-app.manifest").display()
    );
    // link.exe converts a .res input with cvtres; the file holds only icon resources.
    println!(
        "cargo:rustc-link-arg-bins={}",
        dir.join("icons").join("yw-app.res").display()
    );
}
