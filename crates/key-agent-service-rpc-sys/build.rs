//! Compiles checked-in MIDL artifacts and the handwritten RPC boundary shim.

#![allow(
    clippy::print_stdout,
    reason = "Cargo build scripts communicate link metadata on stdout"
)]

use std::{env, error::Error, io, path::PathBuf};

fn main() -> Result<(), Box<dyn Error>> {
    for path in [
        "idl/key_agent_service_rpc.idl",
        "idl/key_agent_service_rpc.acf",
        "generated/key_agent_service_rpc.h",
        "generated/key_agent_service_rpc_c.c",
        "generated/key_agent_service_rpc_s.c",
        "native/key_agent_service_rpc_shim.c",
        "native/key_agent_service_rpc_shim.h",
    ] {
        println!("cargo:rerun-if-changed={path}");
    }

    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return Ok(());
    }

    if env::var("CARGO_CFG_TARGET_ARCH").as_deref() != Ok("x86_64") {
        return Err(io::Error::other(
            "key-agent-service-rpc-sys supports only Windows x64 in Phase 1",
        )
        .into());
    }
    if env::var("CARGO_CFG_TARGET_ENV").as_deref() != Ok("msvc") {
        return Err(
            io::Error::other("key-agent-service-rpc-sys requires the Windows MSVC target").into(),
        );
    }

    let Some(manifest_dir) = env::var_os("CARGO_MANIFEST_DIR") else {
        return Err(
            io::Error::other("Cargo must provide CARGO_MANIFEST_DIR to build scripts").into(),
        );
    };
    let crate_root = PathBuf::from(manifest_dir);

    let mut generated = cc::Build::new();
    generated
        .include(crate_root.join("generated"))
        .file(crate_root.join("generated/key_agent_service_rpc_c.c"))
        .file(crate_root.join("generated/key_agent_service_rpc_s.c"))
        .define("WIN32_LEAN_AND_MEAN", None)
        .define("NOMINMAX", None)
        .define("_WIN32_WINNT", "0x0A00")
        .warnings(false)
        .flag_if_supported("/guard:cf")
        .flag_if_supported("/sdl")
        .flag_if_supported("/GS")
        .flag_if_supported("/Brepro")
        .compile("your_wallet_key_agent_rpc_generated");

    let mut shim = cc::Build::new();
    shim.include(crate_root.join("generated"))
        .include(crate_root.join("native"))
        .file(crate_root.join("native/key_agent_service_rpc_shim.c"))
        .define("WIN32_LEAN_AND_MEAN", None)
        .define("NOMINMAX", None)
        .define("_WIN32_WINNT", "0x0A00")
        .warnings(true)
        .warnings_into_errors(true)
        .flag_if_supported("/W4")
        .flag_if_supported("/WX")
        .flag_if_supported("/guard:cf")
        .flag_if_supported("/sdl")
        .flag_if_supported("/GS")
        .flag_if_supported("/Brepro")
        .compile("your_wallet_key_agent_rpc_shim");

    println!("cargo:rustc-link-lib=Rpcrt4");
    Ok(())
}
