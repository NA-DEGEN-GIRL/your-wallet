//! R-H1 (spec/05 §7.1, §10.2): only the exact pinned origin passes; at most 8 extra arguments.

use std::ffi::OsString;
use std::os::windows::ffi::OsStringExt;

use yw_host::{EXIT_ARGS, check_args, pinned_extension_id};

const ID_FILE: &str = include_str!("../../../extension/extension-id.txt");

fn argv(list: &[&str]) -> Vec<OsString> {
    std::iter::once("yw-host.exe")
        .chain(list.iter().copied())
        .map(OsString::from)
        .collect()
}

fn origin() -> String {
    format!(
        "chrome-extension://{}/",
        pinned_extension_id().unwrap_or_default()
    )
}

#[test]
fn r_h1_pinned_id_is_the_shared_file() {
    let id = pinned_extension_id().unwrap();
    assert_eq!(id, ID_FILE.trim_end());
    assert_eq!(id.len(), 32);
    assert!(id.bytes().all(|b| (b'a'..=b'p').contains(&b)));
}

#[test]
fn r_h1_exact_origin_passes_with_up_to_eight_extra_arguments() {
    let origin = origin();
    assert_eq!(check_args(&argv(&[&origin])), Ok(origin.clone()));
    assert_eq!(
        check_args(&argv(&[&origin, "--parent-window=0"])),
        Ok(origin.clone())
    );
    let mut eight = vec![origin.as_str()];
    eight.extend(["x"; 8]);
    assert_eq!(check_args(&argv(&eight)), Ok(origin.clone()));
    eight.push("x");
    assert_eq!(check_args(&argv(&eight)), Err(EXIT_ARGS));
}

#[test]
fn r_h1_other_origins_are_rejected() {
    let origin = origin();
    let id = pinned_extension_id().unwrap();
    let rejected = [
        origin.trim_end_matches('/').to_owned(),
        origin.to_uppercase(),
        format!("chrome-extension://{}/", id.to_uppercase()),
        format!("CHROME-EXTENSION://{id}/"),
        "chrome-extension://abcdefghijklmnopabcdefghijklmnop/".to_owned(),
        format!("{origin}/"),
        format!("{origin} "),
        format!(" {origin}"),
        format!("chrome-extension://{id}/index.html"),
        format!("https://{id}/"),
        String::new(),
    ];
    for candidate in &rejected {
        assert_eq!(
            check_args(&argv(&[candidate])),
            Err(EXIT_ARGS),
            "{candidate}"
        );
    }
    assert_eq!(check_args(&argv(&[])), Err(EXIT_ARGS));
    assert_eq!(check_args(&[]), Err(EXIT_ARGS));
    assert_eq!(
        check_args(&argv(&["--parent-window=0", &origin])),
        Err(EXIT_ARGS)
    );
    // Not valid UTF-16 (lone surrogate) after the origin text.
    let mut wide: Vec<u16> = origin.encode_utf16().collect();
    wide.push(0xD800);
    let odd = vec![OsString::from("yw-host.exe"), OsString::from_wide(&wide)];
    assert_eq!(check_args(&odd), Err(EXIT_ARGS));
}
