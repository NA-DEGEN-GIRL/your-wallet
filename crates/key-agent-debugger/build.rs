//! Embeds the deterministic Windows version resource in the debugger candidate.

#![allow(
    clippy::print_stdout,
    reason = "Cargo build scripts communicate link metadata on stdout"
)]

use std::{env, error::Error, io, path::PathBuf};

const WINDOWS_TARGET: &str = "x86_64-pc-windows-msvc";
const RESOURCE_SOURCE: &str = "key-agent-debugger.rc";

fn main() -> Result<(), Box<dyn Error>> {
    println!("cargo:rerun-if-changed={RESOURCE_SOURCE}");

    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return Ok(());
    }

    let target = env::var("TARGET")
        .map_err(|_| io::Error::other("Cargo must provide TARGET to build scripts"))?;
    if target != WINDOWS_TARGET {
        return Err(io::Error::other(
            "key-agent-debugger release resources require the Windows x64 MSVC target",
        )
        .into());
    }
    if env::var("CARGO_PKG_VERSION").as_deref() != Ok("0.1.0") {
        return Err(io::Error::other(
            "key-agent-debugger VERSIONINFO must be updated with the package version",
        )
        .into());
    }

    let manifest_dir = env::var_os("CARGO_MANIFEST_DIR")
        .map(PathBuf::from)
        .ok_or_else(|| io::Error::other("Cargo must provide CARGO_MANIFEST_DIR"))?;
    let output_dir = env::var_os("OUT_DIR")
        .map(PathBuf::from)
        .ok_or_else(|| io::Error::other("Cargo must provide OUT_DIR"))?;
    let resource = output_dir.join("key-agent-debugger.res");

    let mut compiler = find_msvc_tools::find(&target, "rc.exe")
        .ok_or_else(|| io::Error::other("the Windows resource compiler was unavailable"))?;
    let result = compiler
        .arg("/nologo")
        .arg("/fo")
        .arg(&resource)
        .arg(manifest_dir.join(RESOURCE_SOURCE))
        .output()?;
    if !result.status.success() {
        return Err(io::Error::other("the Windows version resource failed to compile").into());
    }

    let resource = resource
        .to_str()
        .ok_or_else(|| io::Error::other("the resource output path was not valid Unicode"))?;
    println!("cargo:rustc-link-arg-bin=key-agent-debugger={resource}");
    Ok(())
}
