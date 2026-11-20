//! S4 P9 (spec/15 §11.4 S4, plan §4.4 source check S5 `no_result_read_after_its_emit`,
//! 2026-11-20): no handler reads an effect's result after emitting it.
//!
//! Four effects are answered: the approval window's open (`Effect::Approval(Open)` →
//! `Cmd::ApprovalOpened`), a secret window's open (`SecretEffect::OpenInput`/`OpenDisplay` →
//! `Cmd::SecretOpened`), a copy (`Effect::CopyText` → `Cmd::CopyDone`) and a launch
//! (`Effect::OpenUrl` → `Cmd::Opened`, `Effect::OpenFolder` → `Cmd::FolderMissing`). While the
//! executor applies effects at once the answer is handled before `emit` returns, so code after
//! the emitting call sees the result; with an outbox (P10) it would not. The check reads the
//! production sources of yw-app (comments, strings and `#[cfg(test)]` items blanked) and, for
//! every call that emits one of them, takes what runs after that call inside its fn (see
//! [`after_call`]: the rest of its block, then of each enclosing block, without the sibling
//! arms of a `match` or the `else` of an `if`, the whole body of an enclosing loop, up to a
//! `return`, `break` or `continue`). There:
//!
//! - after an approval window's open (`show_next_approval` and the fns that only call it)
//!   nothing may run: every caller with later steps hands them to the open
//!   (`App::show_next_approval_then`, `AfterOpen`);
//! - after a secret window's open, nothing reads the session (`secret_purpose()`,
//!   `secret_open()`, `secret_session`, `secret_form(..)`), directly or through a fn that does;
//!   form operations travel with the session (`AfterShown::Forms`);
//! - after a copy, nothing reads or writes the copy mark (`self.copied`) or the band
//!   (`self.info`), directly or through a fn that does;
//! - after a launch, nothing reads the launcher or writes the band (`self.info`), directly or
//!   through a fn that does.
//!
//! "Through a fn that does" is one level: a fn whose own body names the token. The check finds
//! every site it counts (it cannot pass on nothing, critique A-20) and checks its reader on
//! made-up code first (it can fail).

use std::collections::BTreeSet;
use std::path::Path;

/// Test code among yw-app's `src` files (each is a `#[cfg(test)]` module, or a file of one):
/// not scanned. Other files are scanned with their `#[cfg(test)]` items blanked.
const TEST_FILES: [&str; 8] = [
    "app/secret_seam.rs",
    "app/tests.rs",
    "app_approval_flow_support.rs",
    "app_approval_headless_host.rs",
    "app_approval_smoke.rs",
    "store/tests.rs",
    "ui/secret/tests.rs",
    "ui/tour.rs",
];

/// Whether `rel` (a `/` path under `src`) is test code.
fn is_test_file(rel: &str) -> bool {
    TEST_FILES.contains(&rel)
        || rel.starts_with("app/tests/")
        || rel.starts_with("ui/tour")
        || rel.ends_with("_tests.rs")
}

/// The production sources of yw-app: `(path under src, code)`, code as [`code_only`] leaves it.
fn production_code() -> Vec<(String, String)> {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut found = Vec::new();
    let mut stack = vec![src.clone()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                let rel = path
                    .strip_prefix(&src)
                    .unwrap()
                    .to_string_lossy()
                    .replace('\\', "/");
                if !is_test_file(&rel) {
                    let text = std::fs::read_to_string(&path).unwrap();
                    found.push((rel, without_test_items(&code_only(&text))));
                }
            }
        }
    }
    found.sort();
    found
}

const fn is_ident(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

/// `text` with comments and string and char literals replaced by spaces (newlines kept, same
/// byte length), so braces and names in them are not code.
fn code_only(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = bytes.to_vec();
    let blank = |out: &mut Vec<u8>, from: usize, to: usize| {
        for byte in out.iter_mut().take(to.min(bytes.len())).skip(from) {
            if *byte != b'\n' {
                *byte = b' ';
            }
        }
    };
    let mut at = 0;
    while at < bytes.len() {
        let rest = &bytes[at..];
        let prev_ident = at > 0 && is_ident(bytes[at - 1]);
        if rest.starts_with(b"//") {
            let end = rest
                .iter()
                .position(|&b| b == b'\n')
                .map_or(bytes.len(), |n| at + n);
            blank(&mut out, at, end);
            at = end;
        } else if rest.starts_with(b"/*") {
            let end = text[at + 2..]
                .find("*/")
                .map_or(bytes.len(), |n| at + 2 + n + 2);
            blank(&mut out, at, end);
            at = end;
        } else if rest.first() == Some(&b'r')
            && (!prev_ident || (at > 1 && bytes[at - 1] == b'b' && !is_ident(bytes[at - 2])))
            && rest.iter().skip(1).find(|&&b| b != b'#') == Some(&b'"')
        {
            let hashes = rest.iter().skip(1).take_while(|&&b| b == b'#').count();
            let close = format!("\"{}", "#".repeat(hashes));
            let open = at + 2 + hashes;
            let end = text[open..]
                .find(&close)
                .map_or(bytes.len(), |n| open + n + close.len());
            blank(&mut out, at + 1, end);
            at = end;
        } else if rest.first() == Some(&b'"') {
            let mut end = at + 1;
            while end < bytes.len() && bytes[end] != b'"' {
                end += if bytes[end] == b'\\' { 2 } else { 1 };
            }
            blank(&mut out, at, end + 1);
            at = end + 1;
        } else if rest.first() == Some(&b'\'') {
            // A char literal ('x', '\n', '\u{..}', a multi-byte char); else a lifetime.
            let end = if rest.get(1) == Some(&b'\\') {
                text[at + 2..].find('\'').map(|n| at + 2 + n + 1)
            } else {
                text[at + 1..]
                    .chars()
                    .next()
                    .map(|c| at + 1 + c.len_utf8())
                    .filter(|&n| bytes.get(n) == Some(&b'\''))
                    .map(|n| n + 1)
            };
            if let Some(end) = end {
                blank(&mut out, at, end);
                at = end;
            } else {
                at += 1;
            }
        } else {
            at += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// The byte offset of the brace that closes the one at `open` (or the end).
fn close_of(code: &[u8], open: usize) -> usize {
    let mut depth = 0_usize;
    for (at, &byte) in code.iter().enumerate().skip(open) {
        match byte {
            b'{' => depth += 1,
            b'}' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return at;
                }
            }
            _ => {}
        }
    }
    code.len().saturating_sub(1)
}

/// `code` with each `#[cfg(test)]` item blanked: from the attribute to the first `;` or `,` at
/// depth 0, to the closing brace at depth 0 that no `else` follows, or to the end of the block
/// it is the last item of.
fn without_test_items(code: &str) -> String {
    let mut out = code.as_bytes().to_vec();
    let mut from = 0;
    while let Some(found) = code[from..].find("#[cfg(test)]") {
        let start = from + found;
        let bytes = code.as_bytes();
        let mut depth = 0_i32;
        let mut end = bytes.len();
        let mut at = start + "#[cfg(test)]".len();
        while at < bytes.len() {
            match bytes[at] {
                b'(' | b'[' | b'{' => depth += 1,
                b')' | b']' => depth -= 1,
                b'}' => {
                    depth -= 1;
                    if depth < 0 {
                        // The item was the last one of its block (a field, an arm).
                        end = at;
                        break;
                    }
                    if depth == 0 && !code[at + 1..].trim_start().starts_with("else") {
                        end = at + 1;
                        break;
                    }
                }
                b';' | b',' if depth == 0 => {
                    end = at + 1;
                    break;
                }
                _ => {}
            }
            at += 1;
        }
        for byte in &mut out[start..end] {
            if *byte != b'\n' {
                *byte = b' ';
            }
        }
        from = end;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// The blocks (`{`, `}` offsets) that hold offset `at`, innermost first.
fn enclosing(code: &[u8], at: usize) -> Vec<(usize, usize)> {
    let mut open = Vec::new();
    for (index, &byte) in code.iter().enumerate().take(at) {
        match byte {
            b'{' => open.push(index),
            b'}' => {
                open.pop();
            }
            _ => {}
        }
    }
    open.iter()
        .rev()
        .map(|&brace| (brace, close_of(code, brace)))
        .collect()
}

/// The text before the block at `open` back to the previous `;`, `{` or `}`: its `fn`, `if`,
/// `loop`, `match` or arm head.
fn head(code: &str, open: usize) -> &str {
    let start = code[..open].rfind([';', '{', '}']).map_or(0, |at| at + 1);
    &code[start..open]
}

fn has_word(text: &str, word: &str) -> bool {
    text.match_indices(word).any(|(at, _)| {
        let bytes = text.as_bytes();
        (at == 0 || !is_ident(bytes[at - 1]))
            && bytes.get(at + word.len()).is_none_or(|&b| !is_ident(b))
    })
}

fn starts_with_word(text: &str, word: &str) -> bool {
    text.starts_with(word)
        && text
            .as_bytes()
            .get(word.len())
            .is_none_or(|&b| !is_ident(b))
}

/// Whether `thing` (an offset inside the block opened at `open`) is in an arm of the `match`
/// that block is the body of: a `=>` at the block's own depth after its last `;` or `,`.
fn in_arm(code: &[u8], open: usize, thing: usize) -> bool {
    let mut depth = 0_i32;
    let (mut arrow, mut sep) = (None, None);
    let mut at = open + 1;
    while at < thing {
        match code[at] {
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' | b'}' => depth -= 1,
            b'=' if depth == 0 && code.get(at + 1) == Some(&b'>') => arrow = Some(at),
            b';' | b',' if depth == 0 => sep = Some(at),
            _ => {}
        }
        at += 1;
    }
    arrow.is_some() && arrow > sep
}

/// What runs after the call that starts at `start` and ends at `end`, inside its fn: the rest
/// of its block; then, block by block outwards, the rest of the enclosing block after the inner
/// one, skipping the `else` branches that follow an `if` block and the sibling arms of a
/// `match`; the whole body of an enclosing loop (it may run again); up to the fn's own block.
/// A `return`, `break` or `continue` right after (at any level) ends it, named.
pub(crate) fn after_call(code: &str, start: usize, end: usize) -> String {
    let bytes = code.as_bytes();
    let mut out = String::new();
    let mut pos = end;
    let mut thing = start;
    for (open, close) in enclosing(bytes, start) {
        let seg = if in_arm(bytes, open, thing) {
            ""
        } else {
            &code[pos.min(close)..close]
        };
        let lead = seg.trim_start().trim_start_matches([';', ',']).trim_start();
        if let Some(word) = ["return", "break", "continue"]
            .into_iter()
            .find(|word| starts_with_word(lead, word))
        {
            out.push_str(word);
            return out;
        }
        out.push_str(seg);
        let block_head = head(code, open);
        if has_word(block_head, "fn") {
            return out;
        }
        if ["loop", "while", "for"]
            .iter()
            .any(|word| has_word(block_head, word))
        {
            out.push_str(" <loop> ");
            out.push_str(&code[open + 1..close]);
        }
        pos = close + 1;
        while starts_with_word(code[pos..].trim_start(), "else") {
            let Some(brace) = code[pos..].find('{') else {
                break;
            };
            pos = close_of(bytes, pos + brace) + 1;
        }
        thing = open;
    }
    out
}

/// The name of the fn whose body holds offset `at`.
fn fn_at(code: &str, at: usize) -> Option<String> {
    enclosing(code.as_bytes(), at)
        .into_iter()
        .find_map(|(open, _)| {
            let block_head = head(code, open);
            let (_, after) = block_head.rsplit_once("fn ")?;
            has_word(block_head, "fn").then(|| {
                after
                    .trim_start()
                    .chars()
                    .take_while(|&c| c.is_ascii_alphanumeric() || c == '_')
                    .collect()
            })
        })
}

/// One call site: the file, the fn it is in, the called name, and its offsets.
struct Site {
    file: String,
    func: String,
    name: String,
    start: usize,
    end: usize,
}

/// The offset after the parenthesis that closes the first one at or after `from`.
fn paren_end(code: &[u8], from: usize) -> usize {
    let mut depth = 0_usize;
    for (at, &byte) in code.iter().enumerate().skip(from) {
        match byte {
            b'(' => depth += 1,
            b')' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return at + 1;
                }
            }
            _ => {}
        }
    }
    code.len()
}

/// Every `self.<name>(` call of one of `names` in `code`.
fn calls(file: &str, code: &str, names: &BTreeSet<String>) -> Vec<Site> {
    let bytes = code.as_bytes();
    let mut sites = Vec::new();
    for name in names {
        let pattern = format!(".{name}(");
        for (at, _) in code.match_indices(&pattern) {
            let before = code[..at].trim_end();
            let receiver_ok = before.ends_with("self")
                && before
                    .len()
                    .checked_sub(5)
                    .is_none_or(|i| !is_ident(before.as_bytes()[i]));
            if receiver_ok {
                let start = before.len() - 4;
                sites.push(Site {
                    file: file.to_owned(),
                    func: fn_at(code, at).unwrap_or_default(),
                    name: name.clone(),
                    start,
                    end: paren_end(bytes, at + pattern.len() - 1),
                });
            }
        }
    }
    sites
}

/// Every `self.emit(` call whose argument holds `literal`: `(file, fn, call start, call end)`.
fn emits_of(files: &[(String, String)], literal: &str) -> Vec<Site> {
    let mut sites = Vec::new();
    for (file, code) in files {
        for (at, _) in code.match_indices(literal) {
            let Some(emit) = code[..at].rfind("self.emit(") else {
                continue;
            };
            let end = paren_end(code.as_bytes(), emit + "self.emit".len());
            if end > at {
                sites.push(Site {
                    file: file.clone(),
                    func: fn_at(code, at).unwrap_or_default(),
                    name: literal.to_owned(),
                    start: emit,
                    end,
                });
            }
        }
    }
    sites
}

/// The fns (by name) whose body is one call of a fn in `set`: the wrappers, added to `set`
/// until none is new (`show_next_approval`, `open_input`, `copy_text`, …).
fn add_wrappers(files: &[(String, String)], set: &mut BTreeSet<String>) {
    loop {
        let mut new = Vec::new();
        for (file, code) in files {
            for site in calls(file, code, set) {
                if set.contains(&site.func) {
                    continue;
                }
                let Some((open, close)) = enclosing(code.as_bytes(), site.start)
                    .into_iter()
                    .find(|&(open, _)| has_word(head(code, open), "fn"))
                else {
                    continue;
                };
                let body: String = code[open + 1..close]
                    .chars()
                    .filter(|c| !c.is_whitespace())
                    .collect();
                let call: String = code[site.start..site.end]
                    .chars()
                    .filter(|c| !c.is_whitespace())
                    .collect();
                if body == call || body == format!("{call};") {
                    new.push(site.func);
                }
            }
        }
        let before = set.len();
        set.extend(new);
        if set.len() == before {
            return;
        }
    }
}

/// The fns whose own body names one of `tokens` (one level of "reads through a fn").
fn readers(files: &[(String, String)], tokens: &[&str]) -> BTreeSet<String> {
    let mut found = BTreeSet::new();
    for (_, code) in files {
        for token in tokens {
            for (at, _) in code.match_indices(token) {
                if let Some(func) = fn_at(code, at) {
                    found.insert(func);
                }
            }
        }
    }
    found
}

/// The tokens and one-level reader calls in `after`.
fn reads_in(after: &str, tokens: &[&str], through: &BTreeSet<String>) -> Vec<String> {
    let mut hits: Vec<String> = tokens
        .iter()
        .filter(|token| after.contains(**token))
        .map(|token| (*token).to_owned())
        .collect();
    for func in through {
        let call = format!(".{func}(");
        if after.contains(&call) {
            hits.push(call);
        }
    }
    hits
}

/// [`after_call`] on made-up code: it must see what the S5 rule is about, and only that.
fn after_call_reads_what_runs_after() {
    let after = |code: &str, call: &str| -> String {
        let code = code_only(code);
        let start = code.find(call).unwrap();
        let end = paren_end(code.as_bytes(), start);
        after_call(&code, start, end)
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect()
    };
    // Straight on, then out of the `if`; the `else` branch is not after.
    let code = "fn f(&mut self) { if a { self.open(); } else { self.other(); } self.next(); }";
    assert_eq!(after(code, "self.open("), ";self.next();");
    // A sibling arm is not after; what follows the `match` is.
    let code = "fn f(&mut self) { match a { A => self.open(), B => { self.b(); } } self.c(); }";
    assert_eq!(after(code, "self.open("), "self.c();");
    let code = "fn f(&mut self) { match a { A => { self.open(); } B => self.b(), } self.c(); }";
    assert_eq!(after(code, "self.open("), ";self.c();");
    // A loop runs its body again; a `return` ends it.
    let code = "fn f(&mut self) { for x in y { self.a(); self.open(); } }";
    assert!(after(code, "self.open(").contains("<loop>self.a();"));
    let code = "fn f(&mut self) { for x in y { self.open(); return; } self.z(); }";
    assert_eq!(after(code, "self.open("), "return");
    // Comments and strings are no code.
    let code = "fn f(&mut self) { self.open(\"}\"); // self.read()\n }";
    assert_eq!(after(code, "self.open("), ";");
    // The shape P9 converted: a step after `show_next_approval` in its fn is seen.
    let code =
        "fn f(&mut self) { if shown { self.show_next_approval(); } self.card_site_check(); }";
    assert_eq!(
        after(code, "self.show_next_approval("),
        ";self.card_site_check();"
    );
}

/// What one kind of answered effect checks: its sites and what may not follow them.
struct Kind {
    what: &'static str,
    /// The fns that emit it (by name) and the effect literals emitted elsewhere.
    emitters: &'static [&'static str],
    literals: &'static [&'static str],
    /// Where the literal may be emitted: only in `emitters` (`true`) or anywhere.
    literal_in_emitters: bool,
    /// The tokens no code after a site may name (`None`: nothing may run after it at all).
    tokens: Option<&'static [&'static str]>,
    /// At least this many sites (A-20; the counts at P9, 2026-11-20).
    min_sites: usize,
}

const KINDS: [Kind; 4] = [
    Kind {
        what: "approval window open",
        emitters: &["open_approval", "show_next_approval_with"],
        literals: &["ApprovalEffect::Open {"],
        literal_in_emitters: true,
        tokens: None,
        min_sites: 18,
    },
    Kind {
        what: "secret window open",
        emitters: &["open_input_with", "open_display_with"],
        literals: &["SecretEffect::OpenInput {", "SecretEffect::OpenDisplay {"],
        literal_in_emitters: true,
        tokens: Some(&[
            "secret_purpose(",
            "secret_open(",
            "secret_session",
            "secret_form(",
        ]),
        min_sites: 69,
    },
    Kind {
        what: "copy",
        emitters: &["copy"],
        literals: &["Effect::CopyText {"],
        literal_in_emitters: true,
        tokens: Some(&["self.copied", "self.info"]),
        min_sites: 25,
    },
    Kind {
        what: "launch",
        emitters: &["open_explorer"],
        literals: &["Effect::OpenUrl {", "Effect::OpenFolder("],
        literal_in_emitters: false,
        tokens: Some(&["launcher", "self.info"]),
        min_sites: 15,
    },
];

/// The sites of `kind` and what is wrong after them.
fn check_kind(files: &[(String, String)], kind: &Kind) -> (usize, Vec<String>) {
    let mut errors = Vec::new();
    let mut names: BTreeSet<String> = kind.emitters.iter().map(|&n| n.to_owned()).collect();
    let mut literal_sites = Vec::new();
    for literal in kind.literals {
        for site in emits_of(files, literal) {
            if kind.literal_in_emitters && !names.contains(&site.func) {
                errors.push(format!(
                    "{}: {} emitted in fn {} (only in {:?})",
                    site.file, literal, site.func, kind.emitters
                ));
            }
            literal_sites.push(site);
        }
    }
    add_wrappers(files, &mut names);
    let through = kind.tokens.map_or_else(BTreeSet::new, |tokens| {
        let mut set = readers(files, tokens);
        set.retain(|func| !names.contains(func));
        set
    });
    let mut sites = literal_sites;
    for (file, code) in files {
        sites.extend(calls(file, code, &names));
    }
    for site in &sites {
        let code = &files.iter().find(|(file, _)| *file == site.file).unwrap().1;
        let after = after_call(code, site.start, site.end);
        let problem = match kind.tokens {
            None => {
                let rest: String = after
                    .chars()
                    .filter(|c| !c.is_whitespace() && !matches!(c, ';' | ',' | '}' | ')'))
                    .collect();
                (!rest.is_empty() && rest != "return").then(|| rest.chars().take(160).collect())
            }
            Some(tokens) => {
                let hits = reads_in(&after, tokens, &through);
                (!hits.is_empty()).then(|| hits.join(" "))
            }
        };
        if let Some(problem) = problem {
            errors.push(format!(
                "{}: fn {} after {} ({}): {problem}",
                site.file, site.func, site.name, kind.what
            ));
        }
    }
    (sites.len(), errors)
}

/// The S5 source check (module doc). Reads yw-app's `src` only.
#[test]
fn no_result_read_after_its_emit() {
    after_call_reads_what_runs_after();
    let files = production_code();
    assert!(files.len() > 50, "scanned {} files", files.len());
    assert!(files.iter().any(|(file, _)| file == "app_approval.rs"));
    let mut errors = Vec::new();
    let mut counts = Vec::new();
    for kind in &KINDS {
        let (sites, mut found) = check_kind(&files, kind);
        assert!(
            sites >= kind.min_sites,
            "{}: {sites} sites (at least {})",
            kind.what,
            kind.min_sites
        );
        counts.push((kind.what, sites));
        errors.append(&mut found);
    }
    // The one-level readers this rule leans on are found.
    let secret = readers(&files, KINDS[1].tokens.unwrap_or_default());
    for reader in ["yk_show_counters", "card_site_check", "secret_form"] {
        assert!(secret.contains(reader), "{reader} reads the secret session");
    }
    assert!(errors.is_empty(), "{counts:?}\n{}", errors.join("\n"));
}

/// 2026-11-20 (S4 P9): what an opener leaves for after its approval window's open
/// (`AfterOpen`) runs once, with the answer to that open only, after the answer's own steps; and
/// at once when no window was asked for (here: nothing queued). Headless, no window.
#[test]
fn an_openers_later_steps_follow_the_answer_to_its_open() {
    use yw_engine::approval::flow::{OpenOutcome, ShownId};
    use yw_engine::cmd::Cmd;

    use crate::app_approval::AfterOpen;
    use crate::errors::ErrorCode;

    let (mut app, dir) = super::unlocked_app("after-open", false);
    let answer = |shown| Cmd::ApprovalOpened {
        shown,
        outcome: OpenOutcome::Failed(ErrorCode::App009),
        wide: false,
    };
    // Nothing to show: `show_next_approval`'s own repaint, then the step's.
    let _ = app.controls.take_shell_log();
    app.show_next_approval_then(AfterOpen::CardSiteCheckThenRefresh);
    assert_eq!(app.controls.take_shell_log(), ["refresh", "refresh"]);
    assert!(app.evm.after_open.is_empty());
    // A step kept for window `shown`: another window's answer leaves it; its own runs it once
    // (this answer is stale — no flow — so the step is all it does).
    let shown = ShownId(u64::MAX);
    app.evm
        .after_open
        .push((shown, AfterOpen::CardSiteCheckThenRefresh));
    app.on_cmd(answer(ShownId(u64::MAX - 1)));
    assert_eq!(app.controls.take_shell_log(), Vec::<String>::new());
    assert_eq!(app.evm.after_open.len(), 1);
    app.on_cmd(answer(shown));
    assert_eq!(app.controls.take_shell_log(), ["refresh"]);
    assert!(app.evm.after_open.is_empty());
    app.on_cmd(answer(shown));
    assert_eq!(app.controls.take_shell_log(), Vec::<String>::new());
    // The rest of a Bitcoin batch: none left but the batch's repaint.
    app.evm
        .after_open
        .push((shown, AfterOpen::BtcRest(Vec::new())));
    assert_eq!(
        format!("{:?}", app.evm.after_open),
        "[(ShownId(18446744073709551615), BtcRest(0))]"
    );
    app.on_cmd(answer(shown));
    assert_eq!(app.controls.take_shell_log(), ["refresh"]);
    let _ = std::fs::remove_dir_all(dir);
}

/// 2026-11-20 (S4 P9): a secret window's form operations wait in its session until the window is
/// shown, are handed out once, and print as names and lengths only.
#[test]
fn form_steps_wait_for_the_shown_window() {
    use yw_engine::secret::{SecretFormOp, SecretKind};

    use crate::app::Purpose;
    use crate::secret_session::{AfterShown, SecretSession};

    let text = "a line of sixteen";
    let forms = AfterShown::Forms(vec![
        SecretFormOp::Error(Some(text.to_owned())),
        SecretFormOp::Details(vec![text.to_owned(), text.to_owned()]),
    ]);
    let mut session = SecretSession::new(7, SecretKind::Mnemonic, Purpose::ImportMnemonic, false);
    session.then_when_shown(forms.clone());
    let printed = format!("{session:?}");
    assert!(
        printed
            .contains("after_shown: Some(Forms([Error { len: Some(17) }, Details { lines: 2 }]))"),
        "{printed}"
    );
    assert!(!printed.contains("sixteen"), "{printed}");
    assert_eq!(session.mark_shown(), Some(forms));
    assert_eq!(session.mark_shown(), None);
}
