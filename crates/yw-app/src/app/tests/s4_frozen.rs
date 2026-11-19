//! S4 F-A freeze (spec/15 §11.4 S4, 2026-11-19; plan critique A-10 as amended by B-9): the
//! approval and secret tests frozen at the owner's checkpoint F-A keep their names and bodies for
//! the rest of S4.
//!
//! `s4_flow/frozen-tests.txt` holds one line per frozen `#[test]` fn: the file it was in at F-A
//! (relative to `crates/`), its leaf name, `ignored` or `run`, and the first 8 bytes (hex) of the
//! SHA-256 of its normalized text. No value, address or path outside the repository.
//!
//! The gate test [`frozen_tests_keep_their_names_and_bodies`] scans every `.rs` file under the
//! `src` and `tests` folders of every crate (read only), so a frozen test may move to another
//! module path, file or crate (S4 W0, E1, E2) and is still found by its leaf name. For every line
//! a `#[test]` fn of that leaf name with the same hash must exist (a multiset match: two frozen
//! tests named `print` need two bodies), so the frozen names are a subset of the tests and no
//! frozen body changed. A test that ran at F-A must not be `#[ignore]`d now; an ignored one may
//! run in the gate later (B-9: the ignored set only shrinks, in S4 B7 and P8, named in their
//! commit bodies).
//!
//! Normalized text: the fn from `fn` to its closing brace plus its attributes other than
//! `#[test]`, `#[ignore …]`, `#[expect(…)]`, `#[allow(…)]` and `#[doc …]`; comments dropped;
//! whitespace outside string and char literals dropped; a comma right before `)`, `]` or `}`
//! dropped (rustfmt adds or removes it when a moved body is indented differently). Literals stay
//! byte for byte. A test made by a `macro_rules!` of the form `$test:ident => $name:literal`
//! (the S4 flow and lifecycle goldens) is the macro's test fn with `$test` and `$name` replaced
//! by the invocation entry.
//!
//! The frozen set (plan §4.1 + critique A-4): every test of yw-engine `approval_interaction.rs`,
//! `approval_golden.rs`, `approval_sim_states.rs`, yw-app `tests/approval_input.rs`, yw-core
//! `evm_approval.rs` and yw-app `tests/btc_app_flow.rs`; the census golden comparisons of
//! `s3_census.rs`; every test of `app_approval_flow_tests.rs`, `app_approval_lifecycle_tests.rs`
//! and `ui/tour_secrets.rs`; the golden and golden-name tests of `app_approval_input_tests.rs`;
//! the eight A-4 tests of `app_chain_sites.rs`. Not frozen: the seam self-tests
//! (`app_approval_flow_support.rs`, `app/secret_seam.rs`; their seams go in B1a/B1b, B7 and P8)
//! and the source checks S1–S3 (`app_approval_input_tests.rs`; re-pointed in B2/B4, plan §4.4
//! and A-20).
//!
//! [`print_frozen_tests`] wrote the file at F-A (`#[ignore]`, recording only; the file is frozen:
//! no line of it is ever removed or changed, plan §4.3 FZ).

use std::path::{Path, PathBuf};

const FROZEN: &str = include_str!("s4_flow/frozen-tests.txt");

/// Lines of `frozen-tests.txt` at F-A (the check cannot pass on an emptied file, A-20).
const FROZEN_LINES: usize = 206;

/// Which tests of a file are frozen.
enum Pick {
    All,
    Only(&'static [&'static str]),
}

/// The frozen set at F-A, by the file each test was in then (used by the recorder only).
const FROZEN_SET: [(&str, Pick); 12] = [
    ("yw-engine/tests/approval_interaction.rs", Pick::All),
    ("yw-engine/tests/approval_golden.rs", Pick::All),
    ("yw-engine/tests/approval_sim_states.rs", Pick::All),
    ("yw-app/tests/approval_input.rs", Pick::All),
    ("yw-core/tests/evm_approval.rs", Pick::All),
    ("yw-app/tests/btc_app_flow.rs", Pick::All),
    (
        "yw-app/src/app/tests/s3_census.rs",
        Pick::Only(&[
            "command_census_matches_the_golden",
            "edit_census_matches_the_golden",
            "check_census_matches_the_golden",
            "write_scenarios_match_the_golden",
            "scenarios_match_the_golden",
        ]),
    ),
    ("yw-app/src/app_approval_flow_tests.rs", Pick::All),
    ("yw-app/src/app_approval_lifecycle_tests.rs", Pick::All),
    (
        "yw-app/src/app_approval_input_tests.rs",
        Pick::Only(&[
            "golden_input_a01",
            "golden_input_keys",
            "golden_input_panel",
            "golden_input_ai_body",
            "golden_reentry_open",
            "golden_reentry_click",
            "golden_reentry_capture_taken",
            "golden_reentry_while_borrowed",
            "print",
            "the_input_goldens_hold_only_known_rows",
        ]),
    ),
    ("yw-app/src/ui/tour_secrets.rs", Pick::All),
    (
        "yw-app/src/app_chain_sites.rs",
        Pick::Only(&[
            "a_failed_preview_is_the_window_failure_and_closing_answers_4001",
            "approved_requests_go_to_the_key_worker_or_the_presign_check",
            "a_send_is_answered_after_its_first_round",
            "send_failures_and_the_lock_answer_every_waiter",
            "signed_transactions_answer_only_while_the_grant_holds",
            "signatures_and_hashes_answer_only_while_the_grant_holds",
            "a_card_step_waiting_for_its_pin_ends_when_its_site_goes",
            "a_refused_pin_after_the_site_went_ends_the_step_quietly",
        ]),
    ),
];

/// One `#[test]` fn found in the sources.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Found {
    /// The file, relative to `crates/`, with `/`.
    path: String,
    leaf: String,
    ignored: bool,
    hash: String,
}

impl Found {
    fn line(&self) -> String {
        let state = if self.ignored { "ignored" } else { "run" };
        format!("{} {} {state} {}", self.path, self.leaf, self.hash)
    }
}

/// Source text with comments and code whitespace removed: each char with `true` when it is code
/// (outside a string or char literal).
struct Normalized {
    text: Vec<char>,
    code: Vec<bool>,
}

fn is_ident(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

impl Normalized {
    #[expect(
        clippy::too_many_lines,
        reason = "one small lexer: comments, strings, chars"
    )]
    fn new(source: &str) -> Self {
        let chars: Vec<char> = source.chars().collect();
        let mut out = Self {
            text: Vec::new(),
            code: Vec::new(),
        };
        let at = |i: usize| chars.get(i).copied();
        let mut i = 0;
        while let Some(c) = at(i) {
            let next = at(i + 1);
            if c == '/' && next == Some('/') {
                while at(i).is_some_and(|c| c != '\n') {
                    i += 1;
                }
                continue;
            }
            if c == '/' && next == Some('*') {
                let mut depth = 0usize;
                while let Some(c) = at(i) {
                    if c == '/' && at(i + 1) == Some('*') {
                        depth += 1;
                        i += 2;
                    } else if c == '*' && at(i + 1) == Some('/') {
                        depth -= 1;
                        i += 2;
                        if depth == 0 {
                            break;
                        }
                    } else {
                        i += 1;
                    }
                }
                continue;
            }
            if c.is_whitespace() {
                i += 1;
                continue;
            }
            if c == 'r' {
                let prev = i.checked_sub(1).and_then(at);
                let prefix = match prev {
                    Some(p) if p == 'b' || p == 'c' => {
                        !i.checked_sub(2).and_then(at).is_some_and(is_ident)
                    }
                    Some(p) => !is_ident(p),
                    None => true,
                };
                let mut j = i + 1;
                while at(j) == Some('#') {
                    j += 1;
                }
                if prefix && at(j) == Some('"') {
                    let hashes = j - i - 1;
                    for &ch in &chars[i..=j] {
                        out.push(ch, false);
                    }
                    i = j + 1;
                    while let Some(c) = at(i) {
                        out.push(c, false);
                        i += 1;
                        if c == '"' && (0..hashes).all(|h| at(i + h) == Some('#')) {
                            for _ in 0..hashes {
                                out.push('#', false);
                            }
                            i += hashes;
                            break;
                        }
                    }
                    continue;
                }
            }
            if c == '"' {
                out.push(c, false);
                i += 1;
                while let Some(c) = at(i) {
                    out.push(c, false);
                    i += 1;
                    if c == '\\' {
                        if let Some(escaped) = at(i) {
                            out.push(escaped, false);
                            i += 1;
                        }
                    } else if c == '"' {
                        break;
                    }
                }
                continue;
            }
            if c == '\'' {
                if next == Some('\\') {
                    out.push(c, false);
                    i += 1;
                    while let Some(c) = at(i) {
                        out.push(c, false);
                        i += 1;
                        if c == '\\' {
                            if let Some(escaped) = at(i) {
                                out.push(escaped, false);
                                i += 1;
                            }
                        } else if c == '\'' {
                            break;
                        }
                    }
                    continue;
                }
                if next.is_some() && at(i + 2) == Some('\'') {
                    for &ch in &chars[i..i + 3] {
                        out.push(ch, false);
                    }
                    i += 3;
                    continue;
                }
            }
            out.push(c, true);
            i += 1;
        }
        out
    }

    /// Appends one char; a code comma right before a closing bracket is dropped.
    fn push(&mut self, c: char, code: bool) {
        if code
            && matches!(c, ')' | ']' | '}')
            && self.text.last() == Some(&',')
            && self.code.last() == Some(&true)
        {
            self.text.pop();
            self.code.pop();
        }
        self.text.push(c);
        self.code.push(code);
    }

    /// `word` starts at `at`, all of it code.
    fn has(&self, at: usize, word: &str) -> bool {
        word.chars()
            .enumerate()
            .all(|(k, c)| self.text.get(at + k) == Some(&c) && self.code.get(at + k) == Some(&true))
    }

    /// The index of the bracket closing the one at `open` (code brackets of any kind).
    fn closing(&self, open: usize) -> Option<usize> {
        let mut depth = 0usize;
        for i in open..self.text.len() {
            if !self.code[i] {
                continue;
            }
            match self.text[i] {
                '(' | '[' | '{' => depth += 1,
                ')' | ']' | '}' => {
                    depth = depth.checked_sub(1)?;
                    if depth == 0 {
                        return Some(i);
                    }
                }
                _ => {}
            }
        }
        None
    }

    fn slice(&self, from: usize, to_inclusive: usize) -> String {
        self.text[from..=to_inclusive].iter().collect()
    }

    /// The first code `c` at or after `from`, before `end`.
    fn find(&self, from: usize, end: usize, c: char) -> Option<usize> {
        (from..end).find(|&i| self.code[i] && self.text[i] == c)
    }
}

/// A `#[test]` fn whose attribute run starts at `at`: (leaf name, ignored, hashed text, end).
/// `None` when the run is not a test fn's.
fn test_fn_at(n: &Normalized, at: usize, end: usize) -> Option<(String, bool, String, usize)> {
    let mut attrs = Vec::new();
    let mut j = at;
    while n.has(j, "#[") {
        let close = n.closing(j + 1)?;
        attrs.push(n.slice(j, close));
        j = close + 1;
    }
    if !attrs.iter().any(|attr| attr == "#[test]") {
        return None;
    }
    for visibility in ["pub(crate)", "pub(super)", "pub"] {
        if n.has(j, visibility) && n.has(j + visibility.len(), "fn") {
            j += visibility.len();
            break;
        }
    }
    if !n.has(j, "fn") {
        return None;
    }
    let name_end =
        (j + 2..end).find(|&i| !n.code[i] || !(is_ident(n.text[i]) || n.text[i] == '$'))?;
    let leaf: String = n.text[j + 2..name_end].iter().collect();
    let open = n.find(name_end, end, '{')?;
    let close = n.closing(open)?;
    let ignored = attrs.iter().any(|attr| attr.starts_with("#[ignore"));
    let mut hashed = String::new();
    for attr in &attrs {
        let dropped = attr == "#[test]"
            || ["#[ignore", "#[expect(", "#[allow(", "#[doc"]
                .iter()
                .any(|prefix| attr.starts_with(prefix));
        if !dropped {
            hashed.push_str(attr);
        }
    }
    hashed.push_str(&n.slice(j, close));
    Some((leaf, ignored, hashed, close))
}

fn short_hash(text: &str) -> String {
    use std::fmt::Write as _;
    let mut hex = String::new();
    for byte in &yw_core::codec::sha256(text.as_bytes())[..8] {
        let _ = write!(hex, "{byte:02x}");
    }
    hex
}

/// Every `#[test]` fn of one source file, in source order (macro-made ones at their invocation).
fn tests_of(path: &str, source: &str) -> Vec<Found> {
    let n = Normalized::new(source);
    let len = n.text.len();
    let mut found = Vec::new();
    let mut templates: Vec<(String, bool, String)> = Vec::new();
    let mut macro_spans: Vec<(usize, usize)> = Vec::new();
    // `macro_rules! NAME { … #[test] … fn $test() { … } … }`
    let mut i = 0;
    while i < len {
        if n.has(i, "macro_rules!") {
            let name_from = i + "macro_rules!".len();
            let Some(open) = (name_from..len).find(|&k| n.code[k] && "{([".contains(n.text[k]))
            else {
                break;
            };
            let name: String = n.text[name_from..open].iter().collect();
            let close = n.closing(open).unwrap_or(len - 1);
            let mut k = open;
            while k < close {
                if n.has(k, "#[")
                    && let Some((leaf, ignored, hashed, end)) = test_fn_at(&n, k, close)
                {
                    if leaf == "$test" {
                        templates.push((name.clone(), ignored, hashed));
                    }
                    k = end;
                }
                k += 1;
            }
            macro_spans.push((i, close));
            i = close;
        }
        i += 1;
    }
    let inside_macro = |at: usize| macro_spans.iter().any(|&(from, to)| at >= from && at <= to);
    let mut i = 0;
    while i < len {
        if inside_macro(i) {
            i += 1;
            continue;
        }
        if n.has(i, "#[")
            && let Some((leaf, ignored, hashed, end)) = test_fn_at(&n, i, len)
        {
            if !leaf.starts_with('$') {
                found.push(Found {
                    path: path.to_owned(),
                    leaf,
                    ignored,
                    hash: short_hash(&hashed),
                });
            }
            i = end + 1;
            continue;
        }
        for (name, ignored, template) in &templates {
            let call = format!("{name}!");
            if n.has(i, &call)
                && (i == 0 || !is_ident(n.text[i - 1]))
                && let Some(open) = i
                    .checked_add(call.len())
                    .filter(|&o| o < len && n.code[o] && "{([".contains(n.text[o]))
                && let Some(close) = n.closing(open)
            {
                for entry in split_entries(&n, open + 1, close) {
                    let Some((test, literal)) = entry.split_once("=>") else {
                        continue;
                    };
                    let hashed = template.replace("$test", test).replace("$name", literal);
                    found.push(Found {
                        path: path.to_owned(),
                        leaf: test.to_owned(),
                        ignored: *ignored,
                        hash: short_hash(&hashed),
                    });
                }
                i = close;
            }
        }
        i += 1;
    }
    found
}

/// The comma-separated entries between `from` and `to` (exclusive) at bracket depth 0.
fn split_entries(n: &Normalized, from: usize, to: usize) -> Vec<String> {
    let mut entries = Vec::new();
    let mut current = String::new();
    let mut depth = 0usize;
    for i in from..to {
        let c = n.text[i];
        if n.code[i] {
            match c {
                '(' | '[' | '{' => depth += 1,
                ')' | ']' | '}' => depth = depth.saturating_sub(1),
                ',' if depth == 0 => {
                    entries.push(std::mem::take(&mut current));
                    continue;
                }
                _ => {}
            }
        }
        current.push(c);
    }
    if !current.is_empty() {
        entries.push(current);
    }
    entries
}

fn crates_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..")
}

/// Every `.rs` under `dir` that names `#[test]`, as (path relative to `crates/`, text).
fn sources(root: &Path, dir: &Path, out: &mut Vec<(String, String)>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    let mut paths: Vec<PathBuf> = entries.map(|entry| entry.unwrap().path()).collect();
    paths.sort();
    for path in paths {
        if path.is_dir() {
            sources(root, &path, out);
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            let text = std::fs::read_to_string(&path).unwrap();
            if text.contains("#[test]") {
                let relative = path
                    .strip_prefix(root)
                    .unwrap()
                    .components()
                    .map(|part| part.as_os_str().to_string_lossy().into_owned())
                    .collect::<Vec<_>>()
                    .join("/");
                out.push((relative, text));
            }
        }
    }
}

/// Every `#[test]` fn in the `src` and `tests` folders of every crate.
fn all_tests() -> Vec<Found> {
    let root = crates_dir();
    let mut crates: Vec<PathBuf> = std::fs::read_dir(&root)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.join("Cargo.toml").is_file())
        .collect();
    crates.sort();
    assert!(crates.len() >= 2, "the crates folder was not found");
    let mut files = Vec::new();
    for krate in &crates {
        sources(&root, &krate.join("src"), &mut files);
        sources(&root, &krate.join("tests"), &mut files);
    }
    files
        .iter()
        .flat_map(|(path, text)| tests_of(path, text))
        .collect()
}

/// One line of `frozen-tests.txt`.
struct Entry<'a> {
    path: &'a str,
    leaf: &'a str,
    ignored: bool,
    hash: &'a str,
}

fn entries() -> Vec<Entry<'static>> {
    FROZEN
        .lines()
        .map(|line| {
            let parts: Vec<&str> = line.split(' ').collect();
            assert!(parts.len() == 4, "malformed line: {line}");
            assert!(
                parts[2] == "run" || parts[2] == "ignored",
                "malformed line: {line}"
            );
            assert!(
                parts[3].len() == 16 && parts[3].chars().all(|c| c.is_ascii_hexdigit()),
                "malformed line: {line}"
            );
            Entry {
                path: parts[0],
                leaf: parts[1],
                ignored: parts[2] == "ignored",
                hash: parts[3],
            }
        })
        .collect()
}

/// Gate test step 23 (2026-11-19, S4 F-A): every frozen test still exists under its leaf name
/// with an unchanged normalized body, and none that ran at F-A is ignored now.
#[test]
fn frozen_tests_keep_their_names_and_bodies() {
    let frozen = entries();
    assert_eq!(
        frozen.len(),
        FROZEN_LINES,
        "frozen-tests.txt lost or gained lines"
    );
    let found = all_tests();
    let mut used = vec![false; found.len()];
    let mut errors = Vec::new();
    for entry in &frozen {
        let pick = found.iter().enumerate().position(|(k, test)| {
            !used[k]
                && test.leaf == entry.leaf
                && test.hash == entry.hash
                && (entry.ignored || !test.ignored)
        });
        if let Some(k) = pick {
            used[k] = true;
            continue;
        }
        let same_name: Vec<String> = found
            .iter()
            .filter(|test| test.leaf == entry.leaf)
            .map(Found::line)
            .collect();
        errors.push(format!(
            "frozen {} ({} at F-A, {}, {}): no #[test] fn with that name and body; found: {:?}",
            entry.leaf,
            entry.path,
            if entry.ignored { "ignored" } else { "run" },
            entry.hash,
            same_name
        ));
    }
    assert!(errors.is_empty(), "{}", errors.join("\n"));
}

/// The normalization drops layout and comments only: a renamed call, a changed literal or an
/// added `#[ignore]` on a run test is seen; the macro form hashes like the written-out fn.
#[test]
fn the_body_hash_ignores_layout_and_comments_only() {
    let base = "#[test]\nfn a() {\n    check(\"x  y\", '}', r#\"{\"#); // note\n}\n";
    let layout = "#[test]\n#[expect(clippy::x, reason = \"r\")]\nfn a() { /* c */ check(\n        \"x  y\",\n        '}',\n        r#\"{\"#,\n    );\n}\n";
    let literal = "#[test]\nfn a() {\n    check(\"x y\", '}', r#\"{\"#);\n}\n";
    let call = "#[test]\nfn a() {\n    chek(\"x  y\", '}', r#\"{\"#);\n}\n";
    let ignored =
        "#[test]\n#[ignore = \"slow\"]\nfn a() {\n    check(\"x  y\", '}', r#\"{\"#);\n}\n";
    let one = |source: &str| {
        let tests = tests_of("x.rs", source);
        assert_eq!(tests.len(), 1, "{source}");
        tests[0].clone()
    };
    assert_eq!(one(base).hash, one(layout).hash);
    assert_ne!(one(base).hash, one(literal).hash);
    assert_ne!(one(base).hash, one(call).hash);
    assert_eq!(one(base).hash, one(ignored).hash);
    assert!(one(ignored).ignored && !one(base).ignored);

    let written = "#[test]\n#[ignore = \"w\"]\nfn golden_x() {\n    run(\"x\");\n}\n";
    let made = "macro_rules! t {\n    ($($test:ident => $name:literal),* $(,)?) => {\n        $(\n            #[test]\n            #[ignore = \"w\"]\n            fn $test() {\n                run($name);\n            }\n        )*\n    };\n}\n\nt! {\n    golden_x => \"x\",\n    golden_y => \"y\",\n}\n";
    let tests = tests_of("x.rs", made);
    assert_eq!(
        tests
            .iter()
            .map(|test| test.leaf.as_str())
            .collect::<Vec<_>>(),
        ["golden_x", "golden_y"]
    );
    assert!(tests[0].ignored);
    assert_eq!(tests[0].hash, one(written).hash);
    assert_ne!(tests[0].hash, tests[1].hash);
    // `#[cfg(test)]` modules, lifetimes and nested attributes are not tests.
    let other = "#[cfg(test)]\nmod t {\n    fn f<'a>(x: &'a str) -> char { 'a' }\n    #[derive(Debug)]\n    struct S;\n}\n";
    assert!(tests_of("x.rs", other).is_empty());
}

/// Writes `frozen-tests.txt` into `YW_S4_FLOW_OUT` (recording at F-A only), else compares the
/// set computed from `FROZEN_SET` with the committed file.
#[test]
#[ignore = "F-A recording of s4_flow/frozen-tests.txt (S4)"]
fn print_frozen_tests() {
    let all = all_tests();
    let mut out = String::new();
    for (path, pick) in &FROZEN_SET {
        let in_file: Vec<&Found> = all.iter().filter(|test| test.path == *path).collect();
        let chosen: Vec<&Found> = match pick {
            Pick::All => {
                assert!(!in_file.is_empty(), "no test in {path}");
                in_file
            }
            Pick::Only(names) => {
                for name in *names {
                    let count = in_file.iter().filter(|test| test.leaf == *name).count();
                    assert_eq!(count, 1, "{name} in {path}");
                }
                in_file
                    .into_iter()
                    .filter(|test| names.contains(&test.leaf.as_str()))
                    .collect()
            }
        };
        for test in chosen {
            out.push_str(&test.line());
            out.push('\n');
        }
    }
    if let Some(dir) = std::env::var_os("YW_S4_FLOW_OUT") {
        let dir = PathBuf::from(dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("frozen-tests.txt"), &out).unwrap();
        return;
    }
    assert_eq!(out, FROZEN);
}
