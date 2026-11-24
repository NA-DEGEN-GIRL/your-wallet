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
//!
//! 2026-11-19 (F-A review): two gaps closed. (1) The hash above covers only the `#[test]` fn,
//! and most frozen tests are one-line calls (`run(name)`, `run_group(..)`, `compare(..)`): the
//! code that runs and compares was not pinned. `s4_flow/frozen-helpers.txt` now holds one line
//! per non-test item of the frozen test files and their two seam files (`HELPER_SET`), plus the
//! source checks S1–S3: F-A path, kind, name, hash (same normalization, from the keyword), rule.
//! Rule `fixed` (the drivers that run a scenario and compare it with its golden, and every item
//! of the engine and core approval test files): never changes. `mutable`: only a planned S4
//! commit may re-record (or remove) the line, naming it in its body with the reason and the
//! goldens it kept byte-equal. A commit list (S1–S3): only those commits. The gate test
//! [`frozen_helpers_keep_their_bodies`] checks every line. (2) A source scan cannot see that a
//! frozen test is compiled out; [`frozen_tests_are_compiled`] (gate step s4fz) compares the
//! compiled test list with the sources. Before this note the claim "every test of a file is
//! frozen" meant only the `#[test]` fn text. This file, `frozen-tests.txt` and
//! `frozen-helpers.txt` are in the FZ frozen-file list (spec/09 §2.1): no `-` line after the
//! F-A review commit except what a line's rule allows.
//!
//! 2026-11-23 (spec/15 §11.4 S5-0, spec/09 §2.1; S5 plan §1.4, owner item O-2 recommended,
//! 주인 상시 결정(2026-11-21): 권고안): the S4 freeze ends with S4, and these rules carry on as the
//! S5 safety net. Golden **content** stays byte-equal for all of S5 (`s3_census`, `s4_flow`,
//! `s4_secret`, the engine/core/app approval goldens). `frozen-tests.txt` is no longer "never
//! changed": a line's hash column may be re-recorded only by a named S5 commit (a word of
//! `PLANNED`, since 2026-11-24 [`ENDED`]) whose diff of that test is a path, accessor or type rename with the same
//! assertions, recorded twice with different `TMP` by [`print_frozen_tests`] (which since S5-0
//! re-computes the hash column only) and listed in the commit body with its reason; the paths,
//! leaf names, the line count (206) and the run/ignored states never change
//! ([`frozen_test_names_never_change`]). S5-0 re-recorded the 23 lines whose bodies named the
//! S4d E1 test-path shims and the S2 facade entries, or the three wallet fields that became
//! accessors (spec/15 §18 28, 31 (가)). `fixed` lines of `frozen-helpers.txt` stay fixed; `mutable`
//! lines may be re-recorded by a named S4 or S5 commit; the commit-list lines change only in their
//! listed commits (S3 gains `S5-10`, declared in S5-0). Gate steps `winui` and `s4fz` stay.
//!
//! 2026-11-24 (S5 final review; spec/15 §18 40 (1), spec/09 §2.1; 주인 상시 결정(2026-11-21):
//! 권고안): S5 is done and the rule above ends with it, the strictest way. Golden content stays
//! byte-equal; no commit re-records a hash column of `frozen-tests.txt` or a `fixed`, `mutable`
//! or commit-list line of `frozen-helpers.txt`. Code holds this now, not only review: both files
//! hash to [`CLOSED_DIGEST`] ([`frozen_files_are_closed_after_s5`]), the S4 and S5 step words are
//! the closed set [`ENDED`], valid only in the commit lists the file held at S5's end
//! ([`ended_steps_are_a_closed_word_set`]), and [`PLANNED`] (later steps) is empty. A later plan
//! that must change a frozen line adds its step's word to `PLANNED` and re-records
//! `CLOSED_DIGEST` in one commit, with the owner's approval. The recorders [`print_frozen_tests`]
//! and [`print_frozen_helpers`] stay for review: their output must equal the committed files.
//! Gate steps `winui` and `s4fz` stay while the frozen set exists.

use std::collections::{BTreeSet, HashMap};
use std::path::{Path, PathBuf};

const FROZEN: &str = include_str!("s4_flow/frozen-tests.txt");

/// Lines of `frozen-tests.txt` at F-A (the check cannot pass on an emptied file, A-20).
const FROZEN_LINES: usize = 206;

/// The first 8 bytes (hex) of the SHA-256 of `frozen-tests.txt` without its hash column (each
/// line's path, leaf name and state, each line ending in a newline): what no S5 re-recording may
/// change (2026-11-23, S5-0).
const FROZEN_NAMES_DIGEST: &str = "b5ccc769b0e6d94b";

/// Which tests of a file are frozen.
enum Pick {
    All,
    Only(&'static [&'static str]),
}

/// The frozen set at F-A, by the file each test was in then (the F-A recorder chose the lines
/// from it; since S5-0 [`print_frozen_tests`] re-computes the hash column of the committed lines
/// instead, and [`frozen_set_names_the_committed_files`] keeps this list true to the file).
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

/// The `macro_rules!` of a file, as (spans, test templates): a template is a macro holding a
/// `#[test] fn $test` (name, ignored, hashed text of that fn).
#[expect(clippy::type_complexity, reason = "two plain lists returned together")]
fn macro_templates(n: &Normalized) -> (Vec<(usize, usize)>, Vec<(String, bool, String)>) {
    let len = n.text.len();
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
                    && let Some((leaf, ignored, hashed, end)) = test_fn_at(n, k, close)
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
    (macro_spans, templates)
}

/// Every `#[test]` fn of one source file, in source order (macro-made ones at their invocation).
fn tests_of(path: &str, source: &str) -> Vec<Found> {
    let n = Normalized::new(source);
    let len = n.text.len();
    let mut found = Vec::new();
    let (macro_spans, templates) = macro_templates(&n);
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

/// One non-test item of a source file (a helper of the tests in it).
#[derive(Debug, Clone, PartialEq, Eq)]
struct Item {
    kind: &'static str,
    /// The item name with the inline module path inside the file (`tests::first_round`); an
    /// `impl` is named by its header (`HandlerforInert`), a macro call by `name!`.
    name: String,
    hash: String,
}

/// Item keywords as they start the normalized text (whitespace dropped), longest first where one
/// is a prefix of another, with the kind they record and whether the item ends with a block.
const ITEM_KEYWORDS: [(&str, &str, bool); 16] = [
    ("constfn", "fn", true),
    ("unsafefn", "fn", true),
    ("asyncfn", "fn", true),
    ("fn", "fn", true),
    ("const", "const", false),
    ("static", "static", false),
    ("struct", "struct", true),
    ("enum", "enum", true),
    ("union", "union", true),
    ("unsafeimpl", "impl", true),
    ("impl", "impl", true),
    ("type", "type", false),
    ("trait", "trait", true),
    ("use", "use", false),
    ("externcrate", "use", false),
    ("mod", "mod", true),
];

/// The end of the item whose keyword starts at `at`: its first depth-0 `;`, or (`braced`) the
/// `}` closing its first depth-0 block (and a `;` right after it).
fn item_end(n: &Normalized, at: usize, to: usize, braced: bool) -> Option<usize> {
    let mut depth = 0usize;
    for k in at..to {
        if !n.code[k] {
            continue;
        }
        match n.text[k] {
            '{' if depth == 0 && braced => {
                let close = n.closing(k)?;
                return Some(if n.has(close + 1, ";") {
                    close + 1
                } else {
                    close
                });
            }
            '(' | '[' | '{' => depth += 1,
            ')' | ']' | '}' => depth = depth.checked_sub(1)?,
            ';' if depth == 0 => return Some(k),
            _ => {}
        }
    }
    None
}

/// Every non-test item of one source file: functions, constants, statics, types, `impl`
/// blocks, `macro_rules!` and item-level macro calls, also inside inline modules (named with the
/// module path). Not items: `use`, `mod x;`, `#[test]` fns, test-template macros and their calls
/// (their tests are in `frozen-tests.txt`). The hashed text is normalized like a test's (from
/// the keyword, so a visibility change on a move does not count; `#[expect]`, `#[allow]` and
/// `#[doc]` dropped).
fn items_of(source: &str) -> Vec<Item> {
    let n = Normalized::new(source);
    let (_, templates) = macro_templates(&n);
    let template_names: Vec<&str> = templates.iter().map(|(name, ..)| name.as_str()).collect();
    let mut out = Vec::new();
    items_in(&n, 0, n.text.len(), "", &template_names, &mut out);
    out
}

fn items_in(
    n: &Normalized,
    from: usize,
    to: usize,
    prefix: &str,
    templates: &[&str],
    out: &mut Vec<Item>,
) {
    let mut i = from;
    while i < to {
        if n.has(i, "#![") {
            let Some(close) = n.closing(i + 2) else {
                return;
            };
            i = close + 1;
            continue;
        }
        let mut attrs = Vec::new();
        let mut j = i;
        while n.has(j, "#[") {
            let Some(close) = n.closing(j + 1) else {
                return;
            };
            attrs.push(n.slice(j, close));
            j = close + 1;
        }
        if n.has(j, "pub(") {
            let Some(close) = n.closing(j + 3) else {
                return;
            };
            j = close + 1;
        } else if n.has(j, "pub") {
            j += 3;
        }
        let word_end = (j..to)
            .find(|&k| !n.code[k] || !is_ident(n.text[k]))
            .unwrap_or(to);
        let word: String = n.text[j..word_end].iter().collect();
        let ident_from = |from: usize| -> String {
            (from..to)
                .take_while(|&k| n.code[k] && is_ident(n.text[k]))
                .map(|k| n.text[k])
                .collect()
        };
        let (kind, name, braced) = if word == "macro_rules" && n.has(word_end, "!") {
            ("macro", ident_from(word_end + 1), true)
        } else if !word.is_empty() && n.has(word_end, "!") {
            ("invoke", format!("{word}!"), true)
        } else if let Some(&(keyword, kind, braced)) = ITEM_KEYWORDS
            .iter()
            .find(|(keyword, ..)| word.starts_with(keyword))
        {
            let name = if kind == "impl" {
                let open = n.find(j, to, '{').unwrap_or(j);
                n.text[j + keyword.len()..open].iter().collect()
            } else {
                word[keyword.len()..].to_owned()
            };
            (kind, name, braced)
        } else {
            ("other", String::new(), true)
        };
        let Some(end) = item_end(n, j, to, braced) else {
            return;
        };
        let template = (kind == "macro" && templates.contains(&name.as_str()))
            || (kind == "invoke" && templates.contains(&name.trim_end_matches('!')));
        let test = attrs.iter().any(|attr| attr == "#[test]");
        if kind == "mod" {
            if n.text[end] == '}'
                && let Some(open) = n.find(j, end, '{')
            {
                items_in(
                    n,
                    open + 1,
                    end,
                    &format!("{prefix}{name}::"),
                    templates,
                    out,
                );
            }
        } else if !(matches!(kind, "use" | "other") || template || test) {
            let mut hashed = String::new();
            for attr in &attrs {
                if !["#[expect(", "#[allow(", "#[doc"]
                    .iter()
                    .any(|dropped| attr.starts_with(dropped))
                {
                    hashed.push_str(attr);
                }
            }
            hashed.push_str(&n.slice(j, end));
            out.push(Item {
                kind,
                name: format!("{prefix}{name}"),
                hash: short_hash(&hashed),
            });
        }
        i = end + 1;
    }
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

/// For each frozen entry, the found test it matches (same leaf, same hash, not ignored when it
/// ran at F-A; each found test used once, in file order).
fn match_entries(frozen: &[Entry<'_>], found: &[Found]) -> Vec<Option<usize>> {
    let mut used = vec![false; found.len()];
    frozen
        .iter()
        .map(|entry| {
            let pick = found.iter().enumerate().position(|(k, test)| {
                !used[k]
                    && test.leaf == entry.leaf
                    && test.hash == entry.hash
                    && (entry.ignored || !test.ignored)
            });
            if let Some(k) = pick {
                used[k] = true;
            }
            pick
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
    let picks = match_entries(&frozen, &found);
    let mut errors = Vec::new();
    for (entry, pick) in frozen.iter().zip(&picks) {
        if pick.is_some() {
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

// ---- Pinned helpers (2026-11-19, S4 F-A review) ----------------------------------------------

const HELPERS: &str = include_str!("s4_flow/frozen-helpers.txt");

/// Lines of `frozen-helpers.txt`. A commit that may remove a `mutable` line (its helper is gone)
/// lowers this in the same commit and names the line (the check cannot pass on an emptied file;
/// after S5 only a later step of [`PLANNED`], 2026-11-24).
/// 2026-11-19 (S4 F1 review): 639 → 642, the three new `mutable` helpers of the F1 key and mouse
/// scenarios (`shown_request`, `press_trace`, `l1_press_past_deadline`) are pinned too.
/// 2026-11-19 (S4 B1a): 642 → 641, the `mutable` line `fn core_clock` of
/// `app_approval_flow_support.rs` is gone (the test `BrowserCore`s take the App's injected clock).
/// 2026-11-19 (S4 B1b): 641 → 637, the `mutable` lines `fn set_clock`, `fn installed_clock`,
/// `fn clock_now_ms` and `fn clock_now_unix_ms` of `app_approval_flow_support.rs` are gone (the
/// `TEST_CLOCK` seam: every App time read is an injected-clock read).
/// 2026-11-19 (S4 B6): 637 → 640, the `mutable` lines `fn gate_state`,
/// `fn stale_window_input_is_dropped` and `fn connect_toggle_stale_layout` of
/// `app_approval_flow_tests.rs` (the critique A-12 and A-13 scenarios).
/// 2026-11-20 (S4 P8): 640 → 639, the `mutable` line `fn set_refuse` of `app/secret_seam.rs` is
/// gone (`TEST_SECRET_REFUSE` removed; the refusal is the recording secret host's,
/// `app::tests::s4_secret::host::refuse`).
/// 2026-11-20 (S4 P8 review): 639 → 640, the `mutable` line of P8's second `impl Fixture` block
/// of `app_approval_flow_support.rs` (`approve_standard_headless`), which `print_frozen_helpers`
/// records and P8's file had left out; net for P8: 640 (−1 `fn set_refuse`, +1 this block).
/// 2026-11-20 (S4 P10b): 640 → 643, the three new `mutable` items of `app/secret_seam.rs`
/// (`invoke thread_local!` of `TEST_AFTER_QUEUED`, `fn log_after`, `fn applied`: the lock-order
/// record of the approval close under the outbox).
const HELPER_LINES: usize = 643;

/// The planned S4 commits (plan §5 with critique round 2), the only words of a commit-list rule.
/// 2026-11-21 (owner decision, second batch before S4c part 2; spec/15 §11.4 S4, §18 18;
/// spec/09 §2.1 (3)): 54 → 57, the in-place flip of every wallet fn to `impl Wallet`: `W14c`
/// (the row: both halves and their review fixes) and its halves `W14c-1` (re-block only) and
/// `W14c-2` (header flip and the associated-fn call sites). A rule word must equal a commit name,
/// so a rule that one half alone may change needs that half's own name. No line of
/// `frozen-helpers.txt` names them yet; S3's list (`…,W14a,W14b,E1`) needs no `W14c` (an in-place
/// flip keeps the `ai_*` text it scans). The words `F14`, `F15`, `F16`, `F17` and `F19` are not
/// added: no frozen line's rule names those owner-approved fixes; F14 and F15 left every frozen
/// line byte-equal, and F16, F17 and F19 must too (or stop for the owner).
/// 2026-11-23 (spec/15 §11.4 S5-0; S5 plan §1.4, §6): 57 → 69, the S5 rows `S5-0` … `S5-10` and
/// `Z-e`: a `mutable` line or a `frozen-tests.txt` hash column is re-recorded only by a commit of
/// one of these rows (or of the S4 rows above) that names the line, and a commit-list rule may
/// name them (S3's list gains `S5-10`, where the AI step becomes a `Cmd::Approval` input).
/// 2026-11-24 (S5 final review; spec/15 §18 40 (1), spec/09 §2.1): renamed from `PLANNED` to
/// `ENDED`. Every one of these steps is done, so these words are a closed set: a commit-list rule
/// that names one must be one of the lists the file held at S5's end ([`ENDED_LISTS`]), and no
/// new list may name them. A later step's words go in [`PLANNED`].
const ENDED: [&str; 69] = [
    "F1", "F2", "B1a", "B1b", "B2", "B3", "B4a", "B4b", "B5", "B6", "B7", "Z-a", "P1", "P2", "P3",
    "P4", "P5", "P6", "P7a1", "P7a2", "P7b", "P8", "P9", "P10", "Z-b", "W0", "W1", "W2", "W3",
    "W3a", "W3b", "W4", "W5", "W6", "W7", "W8", "W9", "W10", "W11", "W12", "W13", "W14a", "W14b",
    "W14c", "W14c-1", "W14c-2", "W15", "Z-c", "E0a", "E0b", "E0c", "E1", "E2", "E3a", "E3b", "E4",
    "Z-d", "S5-0", "S5-1", "S5-2", "S5-3", "S5-4", "S5-5", "S5-6", "S5-7", "S5-8", "S5-9", "S5-10",
    "Z-e",
];

/// The planned steps after S5 that may change a frozen line (2026-11-24, S5 final review;
/// spec/15 §18 40 (1)): none. A later plan that must change a frozen line adds its step's word
/// here, with the owner's approval, in the commit that also re-records [`CLOSED_DIGEST`]; a rule
/// that names such a word names only such words.
const PLANNED: [&str; 0] = [];

/// The commit-list rules of `frozen-helpers.txt` at S5's end (the source checks S1–S3,
/// [`SOURCE_CHECKS`]): the only rules that may name a word of [`ENDED`] (2026-11-24, S5 final
/// review; spec/15 §18 40 (1)).
const ENDED_LISTS: [&str; 3] = [
    "B2,B4a,B4b,B5,E1",
    "B2,B4a,B4b,B5",
    "B2,B4a,B4b,B5,W14a,W14b,E1,S5-10",
];

/// The first 8 bytes (hex) of the SHA-256 of `frozen-tests.txt` followed by
/// `frozen-helpers.txt`, both whole (2026-11-24, S5 final review; spec/15 §18 40 (1), spec/09
/// §2.1). After S5 no commit re-records a hash column, a `fixed` or a `mutable` line or a commit
/// list: `mutable` lines are as closed as `fixed` ones. Before, the files were checked line by
/// line against the sources only, so a re-recorded line passed and only review stopped it (the
/// Z-e review's probe: `deliver_keys` changed, its line re-recorded and `Z-e` added to S3's list
/// left the six `s4_frozen` tests green). A later step that must change a frozen line changes this
/// in the same owner-approved commit that adds its word to [`PLANNED`].
const CLOSED_DIGEST: &str = "bca0a2e19fba4c8f";

/// A frozen test file whose non-test items are pinned: its F-A path, the name prefix of the
/// pinned items (`tests::` = only the inline test module), the drivers (the code that runs a
/// scenario and compares it with its golden: rule `fixed`), and the rule of every other item.
struct HelperFile {
    path: &'static str,
    prefix: &'static str,
    fixed: &'static [&'static str],
    rest: &'static str,
}

/// The pinned helper files (FA review, A-10 as amended by B-9): the frozen-test files of
/// `FROZEN_SET` and the two seam files their tests run on. Not pinned: the shared integration
/// helpers `yw-engine/tests/{common,btc_support}/` (many unfrozen tests use them; they build
/// inputs, and what a frozen test compares stays in the frozen file).
const HELPER_SET: [HelperFile; 14] = [
    HelperFile {
        path: "yw-engine/tests/approval_interaction.rs",
        prefix: "",
        fixed: &[],
        rest: "fixed",
    },
    HelperFile {
        path: "yw-engine/tests/approval_golden.rs",
        prefix: "",
        fixed: &[],
        rest: "fixed",
    },
    HelperFile {
        path: "yw-engine/tests/approval_sim_states.rs",
        prefix: "",
        fixed: &[],
        rest: "fixed",
    },
    HelperFile {
        path: "yw-app/tests/approval_input.rs",
        prefix: "",
        fixed: &[],
        rest: "fixed",
    },
    HelperFile {
        path: "yw-core/tests/evm_approval.rs",
        prefix: "",
        fixed: &[],
        rest: "fixed",
    },
    HelperFile {
        path: "yw-app/tests/btc_app_flow.rs",
        prefix: "",
        fixed: &[],
        rest: "mutable",
    },
    HelperFile {
        path: "yw-app/src/app/tests/s3_census.rs",
        prefix: "",
        fixed: &[
            "compare",
            "COMMANDS",
            "EDITS",
            "CHECKS",
            "WRITES",
            "SCENARIOS",
        ],
        rest: "mutable",
    },
    HelperFile {
        path: "yw-app/src/app_approval_flow_tests.rs",
        prefix: "",
        fixed: &["run", "golden_of", "first_difference", "GOLDEN"],
        rest: "mutable",
    },
    HelperFile {
        path: "yw-app/src/app_approval_lifecycle_tests.rs",
        prefix: "",
        fixed: &["run", "golden_of", "GOLDEN"],
        rest: "mutable",
    },
    HelperFile {
        path: "yw-app/src/app_approval_input_tests.rs",
        prefix: "",
        fixed: &[
            "first_difference",
            "compare",
            "run_group",
            "run_reentry",
            "write_out",
            "INPUT",
            "REENTRY",
        ],
        rest: "mutable",
    },
    HelperFile {
        path: "yw-app/src/ui/tour_secrets.rs",
        prefix: "",
        fixed: &["record", "first_difference", "SECRET_GOLDEN", "LOCK_GOLDEN"],
        rest: "mutable",
    },
    HelperFile {
        path: "yw-app/src/app_chain_sites.rs",
        prefix: "tests::",
        fixed: &[],
        rest: "mutable",
    },
    HelperFile {
        path: "yw-app/src/app_approval_flow_support.rs",
        prefix: "",
        fixed: &[],
        rest: "mutable",
    },
    HelperFile {
        path: "yw-app/src/app/secret_seam.rs",
        prefix: "",
        fixed: &[],
        rest: "mutable",
    },
];

/// The source checks S1–S3 of `app_approval_input_tests.rs` (plan §4.4): not frozen (B2, B4 and
/// B5 re-point them), pinned so that only those commits may change them (FA review). Each
/// change must keep what it asserts: S1 `topmost(true)` and `MA_ACTIVATEANDEAT`, S2 the
/// `physical` Enter expression with `injected`, S3 the scan that no AI code names the gate.
/// 2026-11-23 (S4d E1; owner decision 2026-11-21, second batch, pre-approved, spec/15 §18 18): S1
/// may change in `E1` too, so it follows the flow half to yw-engine (it reads both halves since,
/// and still asserts `topmost(true)` and `MA_ACTIVATEANDEAT`).
/// 2026-11-23 (spec/15 §11.4 S5-0; S5 plan §1.4): S3 may change in `S5-10` too, where the AI
/// panel's step becomes a `Cmd::Approval` input (it still asserts that no AI code names the gate).
const SOURCE_CHECKS: [(&str, &str); 3] = [
    (
        "approval_window_is_topmost_and_eats_activating_clicks",
        "B2,B4a,B4b,B5,E1",
    ),
    (
        "approve_enter_is_physical_and_not_injected",
        "B2,B4a,B4b,B5",
    ),
    (
        "ai_never_touches_the_gate",
        "B2,B4a,B4b,B5,W14a,W14b,E1,S5-10",
    ),
];
const SOURCE_CHECKS_PATH: &str = "yw-app/src/app_approval_input_tests.rs";

/// One line of `frozen-helpers.txt`: F-A path, kind (`test` for S1–S3), name, hash, rule.
struct HelperLine<'a> {
    path: &'a str,
    kind: &'a str,
    name: &'a str,
    hash: &'a str,
    rule: &'a str,
}

const KINDS: [&str; 12] = [
    "fn", "const", "static", "struct", "enum", "union", "impl", "type", "trait", "macro", "invoke",
    "test",
];

/// `fixed`, `mutable`, a commit list of S5's end ([`ENDED_LISTS`], each of whose words is in
/// [`ENDED`]), or a list of later steps' words only ([`PLANNED`]). 2026-11-24 (S5 final review;
/// spec/15 §18 40 (1)): before, any list of planned S4 and S5 words was valid, so a new list could
/// still name an S5 step.
fn rule_is_valid(rule: &str) -> bool {
    rule == "fixed"
        || rule == "mutable"
        || (ENDED_LISTS.contains(&rule) && rule.split(',').all(|commit| ENDED.contains(&commit)))
        || rule.split(',').all(|commit| PLANNED.contains(&commit))
}

/// After S5 the two frozen files are closed (2026-11-24, S5 final review; spec/15 §18 40 (1)):
/// both whole files hash to [`CLOSED_DIGEST`], so no hash column, `fixed` or `mutable` line or
/// commit list is re-recorded without a change here.
#[test]
fn frozen_files_are_closed_after_s5() {
    let mut both = String::from(FROZEN);
    both.push_str(HELPERS);
    assert_eq!(
        short_hash(&both),
        CLOSED_DIGEST,
        "frozen-tests.txt or frozen-helpers.txt changed after S5: only a later step named in \
         PLANNED with the owner's approval may change them (spec/15 §18 40, spec/09 §2.1)"
    );
}

/// The rule words after S5 (2026-11-24, S5 final review; spec/15 §18 40 (1)): the S5 end's
/// lists stay valid, but no new list names an ended step, not even one more word on an old list.
#[test]
fn ended_steps_are_a_closed_word_set() {
    for rule in ["fixed", "mutable"].into_iter().chain(ENDED_LISTS) {
        assert!(rule_is_valid(rule), "{rule}");
    }
    for (name, rule) in SOURCE_CHECKS {
        assert!(ENDED_LISTS.contains(&rule), "{name}: {rule}");
    }
    for rule in [
        "Z-e",
        "S5-0",
        "W14c",
        "B2,B4a,B4b,B5,W14a,W14b,E1,S5-10,Z-e",
        "B2,B4a,B4b,B5,E1,S5-10",
        "",
        "fixed,mutable",
    ] {
        assert!(!rule_is_valid(rule), "{rule}");
    }
    assert!(PLANNED.iter().all(|word| !ENDED.contains(word)));
}

fn helper_lines() -> Vec<HelperLine<'static>> {
    HELPERS
        .lines()
        .map(|line| {
            let parts: Vec<&str> = line.split(' ').collect();
            assert!(parts.len() == 5, "malformed line: {line}");
            assert!(KINDS.contains(&parts[1]), "malformed line: {line}");
            assert!(
                parts[3].len() == 16 && parts[3].chars().all(|c| c.is_ascii_hexdigit()),
                "malformed line: {line}"
            );
            assert!(rule_is_valid(parts[4]), "malformed line: {line}");
            HelperLine {
                path: parts[0],
                kind: parts[1],
                name: parts[2],
                hash: parts[3],
                rule: parts[4],
            }
        })
        .collect()
}

/// The files that hold the frozen tests of each F-A file now (where a moved helper must be).
fn homes(frozen: &[Entry<'_>], found: &[Found]) -> HashMap<String, BTreeSet<String>> {
    let mut homes: HashMap<String, BTreeSet<String>> = HashMap::new();
    for (entry, pick) in frozen.iter().zip(match_entries(frozen, found)) {
        if let Some(k) = pick {
            homes
                .entry(entry.path.to_owned())
                .or_default()
                .insert(found[k].path.clone());
        }
    }
    homes
}

/// Gate test step 23 (2026-11-19, S4 F-A review): every pinned helper of a frozen test file
/// (`frozen-helpers.txt`) still exists with an unchanged normalized text. It must be in its F-A
/// file while that file exists; once a planned commit moved the file away, in a file that holds
/// frozen tests of that F-A file (a helper moves with its tests; an unchanged copy left
/// elsewhere does not count). S1–S3 (`test` lines) must still run.
#[test]
fn frozen_helpers_keep_their_bodies() {
    let lines = helper_lines();
    assert_eq!(
        lines.len(),
        HELPER_LINES,
        "frozen-helpers.txt lost or gained lines"
    );
    let root = crates_dir();
    let found = all_tests();
    let homes = homes(&entries(), &found);
    let mut parsed: HashMap<String, (Vec<Item>, Vec<Found>)> = HashMap::new();
    let mut used: BTreeSet<(String, bool, usize)> = BTreeSet::new();
    let mut errors = Vec::new();
    for line in &lines {
        let files: Vec<String> = if root.join(line.path).is_file() {
            vec![line.path.to_owned()]
        } else {
            homes
                .get(line.path)
                .map(|set| set.iter().cloned().collect())
                .unwrap_or_default()
        };
        let mut hit = false;
        for file in &files {
            let (items, tests) = parsed.entry(file.clone()).or_insert_with(|| {
                let text = std::fs::read_to_string(root.join(file)).unwrap();
                (items_of(&text), tests_of(file, &text))
            });
            let pick = if line.kind == "test" {
                tests
                    .iter()
                    .enumerate()
                    .position(|(k, test)| {
                        !used.contains(&(file.clone(), true, k))
                            && test.leaf == line.name
                            && test.hash == line.hash
                            && !test.ignored
                    })
                    .map(|k| (true, k))
            } else {
                items
                    .iter()
                    .enumerate()
                    .position(|(k, item)| {
                        !used.contains(&(file.clone(), false, k))
                            && item.kind == line.kind
                            && item.name == line.name
                            && item.hash == line.hash
                    })
                    .map(|k| (false, k))
            };
            if let Some((test, k)) = pick {
                used.insert((file.clone(), test, k));
                hit = true;
                break;
            }
        }
        if !hit {
            errors.push(format!(
                "pinned {} {} ({}, {}, rule {}): not found unchanged in {files:?}; only a commit \
                 the rule allows may re-record it (spec/09 §2.1)",
                line.kind, line.name, line.path, line.hash, line.rule
            ));
        }
    }
    assert!(errors.is_empty(), "{}", errors.join("\n"));
}

/// Gate step s4fz (2026-11-19, S4 F-A review): the frozen tests are compiled into the gate's
/// `cargo test --workspace` and the ones that ran at F-A still run. `scripts/check.ps1` lists the
/// compiled tests (`-- --list` and `-- --list --ignored`) and passes, for every frozen leaf name
/// (`frozen-tests.txt` and the `test` lines of `frozen-helpers.txt`), the compiled and the
/// ignored count in `YW_S4_COMPILED` (`leaf=all/ignored;…`). For each leaf, every `#[test]` fn
/// of that name in the sources must be compiled (a crate- or module-level `cfg`, a missing
/// `mod`/`#[path]` line, `test = false` or an unchanged copy in a file that is not compiled
/// leaves fewer compiled than in the sources), and every one not `#[ignore]`d there must run.
#[test]
#[ignore = "gate step s4fz: needs the compiled test list in YW_S4_COMPILED"]
fn frozen_tests_are_compiled() {
    let listed = std::env::var("YW_S4_COMPILED").unwrap_or_default();
    assert!(
        !listed.is_empty(),
        "YW_S4_COMPILED is not set: run scripts/check.ps1 -Step s4fz"
    );
    let mut compiled: HashMap<&str, (usize, usize)> = HashMap::new();
    for pair in listed.split(';') {
        let (leaf, counts) = pair.split_once('=').expect("leaf=all/ignored");
        let (all, ignored) = counts.split_once('/').expect("leaf=all/ignored");
        compiled.insert(leaf, (all.parse().unwrap(), ignored.parse().unwrap()));
    }
    let helpers = helper_lines();
    let leaves: BTreeSet<&str> = entries()
        .iter()
        .map(|entry| entry.leaf)
        .chain(
            helpers
                .iter()
                .filter(|line| line.kind == "test")
                .map(|line| line.name),
        )
        .collect();
    assert!(leaves.len() > SOURCE_CHECKS.len(), "no frozen leaf names");
    let found = all_tests();
    let mut errors = Vec::new();
    for leaf in &leaves {
        let Some(&(all, ignored)) = compiled.get(leaf) else {
            errors.push(format!("{leaf}: not in YW_S4_COMPILED"));
            continue;
        };
        let in_sources = found.iter().filter(|test| test.leaf == *leaf).count();
        let run_in_sources = found
            .iter()
            .filter(|test| test.leaf == *leaf && !test.ignored)
            .count();
        let run = all.saturating_sub(ignored);
        if all < in_sources {
            errors.push(format!(
                "{leaf}: {in_sources} #[test] fn in the sources, {all} compiled (a cfg, a missing \
                 mod or #[path] line, test = false, or a copy in a file that is not compiled)"
            ));
        }
        if run < run_in_sources {
            errors.push(format!(
                "{leaf}: {run_in_sources} not #[ignore]d in the sources, {run} run by the gate"
            ));
        }
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

/// The F-A files whose frozen tests are in another file now (relative to `crates/`): the eight
/// A-4 tests of `app_chain_sites.rs` are in its `#[path]` child `app/tests/chain_sites.rs` since
/// S4 W0 (2026-11-21).
const MOVED: [(&str, &str); 1] = [(
    "yw-app/src/app_chain_sites.rs",
    "yw-app/src/app/tests/chain_sites.rs",
)];

/// `frozen-tests.txt` with each line's hash column re-computed (2026-11-23, S5-0): a line whose
/// test is unchanged keeps its hash (the same match as [`match_entries`]); every other line takes
/// the hash of the test of its leaf name in the file that holds that F-A file's frozen tests now
/// (its F-A file, or [`MOVED`]), in file order, not `#[ignore]`d if it ran at F-A. Paths, leaf
/// names, states and the line order are the file's own.
fn rerecorded_frozen_tests() -> String {
    use std::fmt::Write as _;
    let frozen = entries();
    let found = all_tests();
    let picks = match_entries(&frozen, &found);
    let mut used = vec![false; found.len()];
    for k in picks.iter().flatten() {
        used[*k] = true;
    }
    let mut out = String::new();
    for (entry, pick) in frozen.iter().zip(&picks) {
        let hash = if let Some(k) = pick {
            found[*k].hash.clone()
        } else {
            let home = MOVED
                .iter()
                .find(|(then, _)| *then == entry.path)
                .map_or(entry.path, |(_, now)| *now);
            let k = found.iter().enumerate().position(|(k, test)| {
                !used[k]
                    && test.path == home
                    && test.leaf == entry.leaf
                    && (entry.ignored || !test.ignored)
            });
            assert!(
                k.is_some(),
                "{} {}: no test in {home}",
                entry.path,
                entry.leaf
            );
            let k = k.unwrap();
            used[k] = true;
            found[k].hash.clone()
        };
        let state = if entry.ignored { "ignored" } else { "run" };
        let _ = writeln!(out, "{} {} {state} {hash}", entry.path, entry.leaf);
    }
    out
}

/// Writes `frozen-tests.txt` with its hash column re-computed ([`rerecorded_frozen_tests`]) into
/// `YW_S4_FLOW_OUT`, else compares that with the committed file. Recording only: at F-A (then
/// from [`FROZEN_SET`]), and since S5-0 in a named S5 commit, which lists every changed line
/// (2026-11-23; before, the F-A recorder chose the lines from `FROZEN_SET`, and it could not run
/// after S4 W0 moved the A-4 tests).
#[test]
#[ignore = "re-records the hash column of s4_flow/frozen-tests.txt (S5-0)"]
fn print_frozen_tests() {
    let out = rerecorded_frozen_tests();
    if let Some(dir) = std::env::var_os("YW_S4_FLOW_OUT") {
        let dir = PathBuf::from(dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("frozen-tests.txt"), &out).unwrap();
        return;
    }
    assert_eq!(out, FROZEN);
}

/// What an S5 re-recording may not change (2026-11-23, S5-0): the paths, leaf names, the count
/// and the run/ignored states of `frozen-tests.txt` ([`FROZEN_NAMES_DIGEST`]).
#[test]
fn frozen_test_names_never_change() {
    use std::fmt::Write as _;
    let frozen = entries();
    assert_eq!(frozen.len(), FROZEN_LINES);
    let mut names = String::new();
    for entry in &frozen {
        let state = if entry.ignored { "ignored" } else { "run" };
        let _ = writeln!(names, "{} {} {state}", entry.path, entry.leaf);
    }
    assert_eq!(
        short_hash(&names),
        FROZEN_NAMES_DIGEST,
        "frozen-tests.txt paths, names or states"
    );
}

/// [`FROZEN_SET`] names exactly the files of `frozen-tests.txt`, in its order, and each
/// `Pick::Only` list exactly the leaf names of its file's lines (2026-11-23, S5-0: the recorder
/// no longer reads the set, so this keeps it true).
#[test]
fn frozen_set_names_the_committed_files() {
    let frozen = entries();
    let mut files: Vec<&str> = Vec::new();
    for entry in &frozen {
        if files.last() != Some(&entry.path) {
            files.push(entry.path);
        }
    }
    let set: Vec<&str> = FROZEN_SET.iter().map(|(path, _)| *path).collect();
    assert_eq!(files, set);
    for (path, pick) in &FROZEN_SET {
        let leaves: BTreeSet<&str> = frozen
            .iter()
            .filter(|entry| entry.path == *path)
            .map(|entry| entry.leaf)
            .collect();
        assert!(!leaves.is_empty(), "{path}");
        if let Pick::Only(names) = pick {
            assert_eq!(
                leaves,
                names.iter().copied().collect::<BTreeSet<_>>(),
                "{path}"
            );
        }
    }
}

/// The helper items are the non-test items of a file, with the inline module path; tests,
/// `use`, `mod x;`, test-template macros and their calls are not items; the hash ignores layout,
/// comments and visibility, and sees a changed body or an added early `return`.
#[test]
fn helper_items_are_the_non_test_items() {
    let source = "//! doc\n#![allow(x)]\nuse a::b;\n#[path = \"x.rs\"]\nmod x;\nconst GOLDEN: &str = include_str!(\"g.txt\");\npub(super) fn run(name: &str) {\n    check(name);\n}\nstruct Rec<'a> {\n    a: &'a str,\n}\nimpl<'a> Rec<'a> {\n    fn new() -> Self { todo() }\n}\nimpl Handler for Inert {}\nmacro_rules! t {\n    ($($test:ident => $name:literal),* $(,)?) => {\n        $(\n            #[test]\n            fn $test() { run($name); }\n        )*\n    };\n}\nt! { golden_x => \"x\" }\nthread_local! { static S: u8 = 0; }\n#[cfg(test)]\nmod tests {\n    #[test]\n    fn a() {}\n    fn first_round(x: [u8; 2]) -> u8 { x[0] }\n    type Scenario = fn() -> Vec<String>;\n}\n";
    let items = items_of(source);
    let names: Vec<(&str, &str)> = items
        .iter()
        .map(|item| (item.kind, item.name.as_str()))
        .collect();
    assert_eq!(
        names,
        [
            ("const", "GOLDEN"),
            ("fn", "run"),
            ("struct", "Rec"),
            ("impl", "<'a>Rec<'a>"),
            ("impl", "HandlerforInert"),
            ("invoke", "thread_local!"),
            ("fn", "tests::first_round"),
            ("type", "tests::Scenario"),
        ]
    );
    let run = |source: &str| {
        items_of(source)
            .into_iter()
            .find(|item| item.name == "run")
            .unwrap()
            .hash
    };
    let base = "fn run(name: &str) {\n    check(name);\n}\n";
    let layout = "/// d\n#[expect(clippy::x, reason = \"r\")]\npub(crate) fn run(name: &str) { check(name) ; }\n";
    let early = "fn run(name: &str) {\n    if !name.is_empty() { return; }\n    check(name);\n}\n";
    assert_eq!(run(base), run(layout));
    assert_ne!(run(base), run(early));
}

/// Writes `frozen-helpers.txt` into `YW_S4_FLOW_OUT` (recording only: at the F-A review, and in
/// a commit the rule of a line allows, which then names every changed line), else compares the
/// set computed from `HELPER_SET` and `SOURCE_CHECKS` with the committed file.
#[test]
#[ignore = "recording of s4_flow/frozen-helpers.txt (S4 F-A review)"]
fn print_frozen_helpers() {
    use std::fmt::Write as _;
    let root = crates_dir();
    let mut out = String::new();
    for file in &HELPER_SET {
        let text = std::fs::read_to_string(root.join(file.path)).unwrap();
        let items: Vec<Item> = items_of(&text)
            .into_iter()
            .filter(|item| item.name.starts_with(file.prefix))
            .collect();
        assert!(!items.is_empty(), "no helper in {}", file.path);
        for name in file.fixed {
            let count = items.iter().filter(|item| item.name == *name).count();
            assert_eq!(count, 1, "{name} in {}", file.path);
        }
        for item in &items {
            let rule = if file.fixed.contains(&item.name.as_str()) {
                "fixed"
            } else {
                file.rest
            };
            let _ = writeln!(
                out,
                "{} {} {} {} {rule}",
                file.path, item.kind, item.name, item.hash
            );
        }
    }
    let text = std::fs::read_to_string(root.join(SOURCE_CHECKS_PATH)).unwrap();
    let tests = tests_of(SOURCE_CHECKS_PATH, &text);
    for (name, rule) in SOURCE_CHECKS {
        let matching: Vec<&Found> = tests.iter().filter(|test| test.leaf == name).collect();
        assert!(
            matching.len() == 1 && !matching[0].ignored,
            "{name} in {SOURCE_CHECKS_PATH}"
        );
        let _ = writeln!(
            out,
            "{SOURCE_CHECKS_PATH} test {name} {} {rule}",
            matching[0].hash
        );
    }
    for line in out.lines() {
        assert!(line.split(' ').count() == 5 && line.is_ascii(), "{line}");
    }
    if let Some(dir) = std::env::var_os("YW_S4_FLOW_OUT") {
        let dir = PathBuf::from(dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("frozen-helpers.txt"), &out).unwrap();
        return;
    }
    assert_eq!(out, HELPERS);
}
