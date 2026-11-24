//! Source checks of yw-android (2026-11-25 A2-4b; spec/15 §5.3, §3.2). They read this crate's
//! `src` folder, so they run on the Windows gate even for the Android-only modules.

use std::path::PathBuf;

/// Every `.rs` file of `src` with its text (comments included).
fn sources() -> Vec<(String, String)> {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    for entry in std::fs::read_dir(&dir).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().is_some_and(|ext| ext == "rs") {
            let name = path.file_name().unwrap().to_string_lossy().into_owned();
            files.push((name, std::fs::read_to_string(&path).unwrap()));
        }
    }
    files.sort();
    assert!(files.len() >= 10, "src was read");
    files
}

/// Lines that are code, not comments.
fn code_lines(text: &str) -> impl Iterator<Item = &str> {
    text.lines()
        .map(str::trim)
        .filter(|line| !line.starts_with("//"))
}

/// spec/15 §5.3: `M_PURGE` is the NDK r30 `malloc.h` value -101, and `purge.rs` is the only file
/// that declares or calls `mallopt`, which it calls once, with `M_PURGE` (no option argument).
#[test]
fn purge_is_the_one_mallopt() {
    let mut seen = false;
    for (name, text) in sources() {
        let calls: Vec<&str> = code_lines(&text)
            .filter(|line| line.contains("mallopt"))
            .collect();
        if name == "purge.rs" {
            seen = true;
            assert_eq!(
                calls,
                [
                    "fn mallopt(option: c_int, value: c_int) -> c_int;",
                    "let done = unsafe { mallopt(M_PURGE, 0) };",
                ],
                "purge.rs"
            );
            let consts: Vec<&str> = code_lines(&text)
                .filter(|line| line.contains("M_PURGE") && line.contains("const"))
                .collect();
            assert_eq!(consts, ["const M_PURGE: c_int = -101;"]);
        } else if name != "source_checks.rs" {
            assert!(calls.is_empty(), "{name} names mallopt");
        }
    }
    assert!(seen, "purge.rs was read");
}

/// The device round trip (a vault from the public test vector under a fixed password) is compiled
/// only with `--cfg yw_device_test` (spec/09 §2.6): `lib.rs` declares it under that cfg, and only
/// `shell.rs` names it, under the same cfg.
#[test]
fn the_device_test_is_cfg_gated() {
    for (name, text) in sources() {
        let lines: Vec<&str> = code_lines(&text).collect();
        for (at, line) in lines.iter().enumerate() {
            if !(line.contains("devtest") && (line.contains("mod ") || line.contains("devtest::")))
            {
                continue;
            }
            assert!(
                matches!(name.as_str(), "lib.rs" | "shell.rs" | "source_checks.rs"),
                "{name} names devtest: {line}"
            );
            let before = at.checked_sub(1).and_then(|prev| lines.get(prev)).copied();
            match name.as_str() {
                "lib.rs" => assert_eq!(
                    (before, *line),
                    (
                        Some("#[cfg(all(target_os = \"android\", yw_device_test))]"),
                        "mod devtest;"
                    )
                ),
                "shell.rs" => assert_eq!(before, Some("#[cfg(yw_device_test)]"), "{line}"),
                _ => {}
            }
        }
    }
}

/// spec/15 §5.2 (2026-11-25 A2-4b review): Java makes the device key only in the create
/// request's handler `DeviceKeys.make`; its wrap and unwrap never call `create()` (a missing key
/// is `KEY_MISSING` for both), and the I/O thread sends only a create frame there.
#[test]
fn only_the_create_request_makes_the_device_key() {
    let java = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../android/app/src/main/java/dev/yw/app");
    let keys = std::fs::read_to_string(java.join("DeviceKeys.java")).unwrap();
    let mut method = "";
    let mut makers = Vec::new();
    for line in code_lines(&keys) {
        if line.starts_with("static Answer ") || line.starts_with("private static ") {
            method = line;
        }
        if line.contains("create()") && !line.starts_with("private static SecretKey create()") {
            makers.push((method, line));
        }
    }
    assert_eq!(
        makers,
        [("static Answer make(byte[] frame) {", "create();")],
        "DeviceKeys.java"
    );
    let io = std::fs::read_to_string(java.join("IoLoop.java")).unwrap();
    let calls: Vec<&str> = code_lines(&io)
        .filter(|line| line.contains("DeviceKeys.make("))
        .collect();
    assert_eq!(calls, ["answer = DeviceKeys.make(frame);"]);
    let guard: Vec<&str> = code_lines(&io)
        .filter(|line| line.contains("IoFrame.makesKey("))
        .collect();
    assert_eq!(guard, ["} else if (IoFrame.makesKey(frame)) {"]);
}

/// Rust never calls Java (spec/15 §3.2): no thread attach, no global reference, no method call
/// entry of the JNI table in any code line.
#[test]
fn rust_never_calls_java() {
    for (name, text) in sources() {
        if name == "source_checks.rs" {
            continue;
        }
        for line in code_lines(&text) {
            for word in [
                "AttachCurrentThread",
                "NewGlobalRef",
                "CallVoidMethod",
                "CallObjectMethod",
                "CallStaticVoidMethod",
                "GetMethodID",
                "GetStaticMethodID",
            ] {
                assert!(!line.contains(word), "{name}: {line}");
            }
        }
    }
}
