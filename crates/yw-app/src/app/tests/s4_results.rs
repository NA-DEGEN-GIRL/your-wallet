//! S4 P9 (spec/15 §11.4 S4, plan §4.4 source check S5 `no_result_read_after_its_emit`,
//! 2026-11-20): no handler reads an effect's result after emitting it.
//!
//! Four effects are answered: the approval window's open (`Effect::Approval(Open)` →
//! `Cmd::ApprovalOpened`), a secret window's open (`SecretEffect::OpenInput`/`OpenDisplay` →
//! `Cmd::SecretOpened`), a copy (`Effect::CopyText` → `Cmd::CopyDone`) and a launch
//! (`Effect::OpenUrl` → `Cmd::Opened`, `Effect::OpenFolder` → `Cmd::FolderMissing`). While the
//! executor applies effects at once the answer is handled before `emit` returns, so code after
//! the emitting call sees the result; with an outbox (P10) it would not. The check reads the
//! production sources of yw-app and yw-engine (comments, strings and `#[cfg(test)]` items
//! blanked) and, for every call that emits one of them, takes what runs after that call inside
//! its fn (see [`after_call`]: the rest of its block, then of each enclosing block, without the
//! sibling arms of a `match` or the `else` of an `if`, the whole body of an enclosing loop, up
//! to a `return`; after a `break` what follows its loop, after a `continue` its loop's body
//! again and what follows). An emitting call is a call of an emitting fn or of a fn in which
//! nothing runs after such a call (a tail emitter: `card_open_pin`, `sync_browser`, …), through
//! `self.`, a closure's `app.`, `Self::` or `App::`; any other use of such a fn fails. There:
//!
//! - after an approval window's open nothing may run: every caller with later steps hands them
//!   to the open (`App::show_next_approval_then`, `AfterOpen`), or is a line of
//!   [`PENDING_P10`] that P10 decides;
//! - after a secret window's open, nothing reads the session (`secret_purpose()`,
//!   `secret_open()`, `secret_session`, `secret_form(..)`), directly or through a fn that does;
//!   form operations travel with the session (`AfterShown::Forms`);
//! - after a copy, nothing reads or writes the copy mark (`self.copied`) or the band
//!   (`self.info`), directly or through a fn that does;
//! - after a launch, nothing reads the launcher or writes the band (`self.info`), directly or
//!   through a fn that does.
//!
//! "Through a fn that does" is one level: a fn whose own body names the token (each kind pins
//! the readers it found, `readers_floor`). A site whose opening path never reaches the code
//! after it is a line of [`ENDS_ON_ITS_PATH`] with its reason. The check finds every site it
//! counts (it cannot pass on nothing, critique A-20) and checks its reader on made-up code
//! first (it can fail).
//!
//! 2026-11-20 (P9 review): before, the check read yw-app only, followed only fns whose whole
//! body was one emitting call, ended at `break`/`continue` and counted `self.` calls only, so a
//! caller of a fn that opens as its last step (`card_begin` after `card_open_pin`) and every
//! entry-level step after an open (`refresh` after `sync_browser`, the grant revocations, the
//! Bitcoin handlers, …) went unchecked. Those are now [`PENDING_P10`].

use std::collections::{BTreeMap, BTreeSet};
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

/// The same for yw-engine's `src` (its `#[cfg(test)]` module files and `testkit`).
const ENGINE_TEST_FILES: [&str; 3] = ["explain/tests.rs", "testkit.rs", "walletconnect/tests.rs"];

/// Whether `rel` (a `/` path under a crate's `src`) is test code.
fn is_test_file(engine: bool, rel: &str) -> bool {
    if engine {
        return ENGINE_TEST_FILES.contains(&rel) || rel.ends_with("_tests.rs");
    }
    TEST_FILES.contains(&rel)
        || rel.starts_with("app/tests/")
        || rel.starts_with("ui/tour")
        || rel.ends_with("_tests.rs")
}

/// One scanned source: its `crate/src/path`, its code as [`code_only`] and
/// [`without_test_items`] leave it, and its blocks.
struct Src {
    file: String,
    code: String,
    blocks: Vec<Block>,
}

impl Src {
    fn new(file: String, code: String) -> Self {
        let blocks = blocks_of(code.as_bytes());
        Self { file, code, blocks }
    }
}

/// One `{ … }` block: its brace offsets and the block it is in (an index).
struct Block {
    open: usize,
    close: usize,
    parent: Option<usize>,
}

/// Every block of `code`, by opening offset (an unclosed one ends at the end).
fn blocks_of(code: &[u8]) -> Vec<Block> {
    let mut blocks: Vec<Block> = Vec::new();
    let mut stack: Vec<usize> = Vec::new();
    for (at, &byte) in code.iter().enumerate() {
        match byte {
            b'{' => {
                blocks.push(Block {
                    open: at,
                    close: code.len().saturating_sub(1),
                    parent: stack.last().copied(),
                });
                stack.push(blocks.len() - 1);
            }
            b'}' => {
                if let Some(index) = stack.pop() {
                    blocks[index].close = at;
                }
            }
            _ => {}
        }
    }
    blocks
}

/// The production sources of yw-app and yw-engine. 2026-11-20 (P9 review, critique A-20):
/// yw-engine's `src` too, so an emitter or reader that moves there (S4c/S4d) stays in the
/// check.
fn production_code() -> Vec<Src> {
    let crates = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    let mut found = Vec::new();
    for krate in ["yw-app", "yw-engine"] {
        let src = crates.join(krate).join("src");
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
                    if !is_test_file(krate == "yw-engine", &rel) {
                        let text = std::fs::read_to_string(&path).unwrap();
                        found.push(Src::new(
                            format!("{krate}/src/{rel}"),
                            without_test_items(&code_only(&text)),
                        ));
                    }
                }
            }
        }
    }
    found.sort_by(|a, b| a.file.cmp(&b.file));
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
fn enclosing(blocks: &[Block], at: usize) -> Vec<(usize, usize)> {
    let mut current = blocks
        .partition_point(|block| block.open < at)
        .checked_sub(1);
    while let Some(index) = current {
        if blocks[index].close >= at {
            break;
        }
        current = blocks[index].parent;
    }
    let mut out = Vec::new();
    while let Some(index) = current {
        out.push((blocks[index].open, blocks[index].close));
        current = blocks[index].parent;
    }
    out
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
/// A `return` right after (at any level) ends it, named. A `break` right after leaves the
/// blocks up to the innermost loop and goes on after that loop; a `continue` does the same but
/// first takes that loop's whole body (it runs again). Both are named. 2026-11-20 (P9 review):
/// before, `break` and `continue` ended it like `return`, so code after the loop was missed.
/// A labelled `break`/`continue` is refused by [`no_result_read_after_its_emit`] (none today).
fn after_call(code: &str, blocks: &[Block], start: usize, end: usize) -> String {
    let bytes = code.as_bytes();
    let mut out = String::new();
    let mut pos = end;
    let mut thing = start;
    // Leaving blocks up to the innermost loop after a `break` (`false`) or `continue` (`true`).
    let mut escaping: Option<bool> = None;
    for (open, close) in enclosing(blocks, start) {
        let block_head = head(code, open);
        let is_fn = has_word(block_head, "fn");
        let is_loop = ["loop", "while", "for"]
            .iter()
            .any(|word| has_word(block_head, word));
        if escaping.is_none() {
            let seg = if in_arm(bytes, open, thing) {
                ""
            } else {
                &code[pos.min(close)..close]
            };
            let lead = seg.trim_start().trim_start_matches([';', ',']).trim_start();
            if starts_with_word(lead, "return") {
                out.push_str("return");
                return out;
            }
            if let Some(word) = ["break", "continue"]
                .into_iter()
                .find(|word| starts_with_word(lead, word))
            {
                out.push_str(word);
                out.push(' ');
                escaping = Some(word == "continue");
            } else {
                out.push_str(seg);
            }
        }
        if is_fn {
            return out;
        }
        if let Some(again) = escaping {
            if !is_loop {
                // This block ends here; nothing more of it runs.
                thing = open;
                continue;
            }
            escaping = None;
            if again {
                out.push_str(" <loop> ");
                out.push_str(&code[open + 1..close]);
            }
        } else if is_loop {
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
fn fn_at(code: &str, blocks: &[Block], at: usize) -> Option<String> {
    enclosing(blocks, at).into_iter().find_map(|(open, _)| {
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

/// One call site: the file (an index into the scanned sources), the fn it is in, the called
/// name, and its offsets.
struct Site {
    src: usize,
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

/// Whether `before` (code up to a `.` or `::`) ends with the word `word`.
fn ends_with_word(before: &str, word: &str) -> bool {
    before.ends_with(word)
        && before
            .len()
            .checked_sub(word.len() + 1)
            .is_none_or(|i| !is_ident(before.as_bytes()[i]))
}

/// The receivers of a counted call: `self.<name>(`, a closure's or `Forward`'s
/// `app.<name>(`, `Self::<name>(`, `App::<name>(`.
const DOT_RECEIVERS: [&str; 2] = ["self", "app"];
const PATH_RECEIVERS: [&str; 2] = ["Self", "App"];

/// Every counted call ([`DOT_RECEIVERS`], [`PATH_RECEIVERS`]) of one of `names` in `file`.
/// 2026-11-20 (P9 review): before, only `self.<name>(`; any other way to reach one of `names`
/// (another receiver, a fn pointer) is listed by [`other_uses`] and refused.
fn calls(src: usize, file: &Src, names: &BTreeSet<String>) -> Vec<Site> {
    let code = &file.code;
    let bytes = code.as_bytes();
    let mut sites = Vec::new();
    for name in names {
        for (sep, receivers) in [(".", &DOT_RECEIVERS[..]), ("::", &PATH_RECEIVERS[..])] {
            let pattern = format!("{sep}{name}(");
            for (at, _) in code.match_indices(&pattern) {
                if at > 0 && sep == "." && bytes[at - 1] == b':' {
                    continue;
                }
                let before = code[..at].trim_end();
                let Some(receiver) = receivers.iter().find(|r| ends_with_word(before, r)) else {
                    continue;
                };
                sites.push(Site {
                    src,
                    func: fn_at(code, &file.blocks, at).unwrap_or_default(),
                    name: name.clone(),
                    start: before.len() - receiver.len(),
                    end: paren_end(bytes, at + pattern.len() - 1),
                });
            }
        }
    }
    sites
}

/// Method calls named like an emitter that are another type's method, not `App`'s: `(file,
/// name, receiver)`. `SecretField::copy` (a secret field's own copy, no effect).
const NOT_APP: [(&str, &str, &str); 1] = [("yw-app/src/ui/secret.rs", "copy", "field")];

/// The uses of one of `names` that [`calls`] does not count: `.<name>(` on another receiver
/// (unless [`NOT_APP`]), `Self::<name>` or `App::<name>` without a call (a fn pointer).
/// `.<name>` without a call is a field, and `<Type>::<name>` another type's fn: not uses.
fn other_uses(files: &[Src], names: &BTreeSet<String>) -> Vec<String> {
    let mut found = Vec::new();
    for Src { file, code, blocks } in files {
        let bytes = code.as_bytes();
        for name in names {
            for sep in [".", "::"] {
                let pattern = format!("{sep}{name}");
                for (at, _) in code.match_indices(&pattern) {
                    let after = at + pattern.len();
                    if bytes.get(after).is_some_and(|&b| is_ident(b))
                        || (sep == "." && at > 0 && bytes[at - 1] == b':')
                    {
                        continue;
                    }
                    let before = code[..at].trim_end();
                    let called = bytes.get(after) == Some(&b'(');
                    let receiver: String = before
                        .chars()
                        .rev()
                        .take_while(|&c| c.is_ascii_alphanumeric() || c == '_')
                        .collect::<Vec<_>>()
                        .into_iter()
                        .rev()
                        .collect();
                    let refused = if sep == "." {
                        called
                            && !DOT_RECEIVERS.contains(&receiver.as_str())
                            && !NOT_APP.contains(&(file.as_str(), name.as_str(), &receiver))
                    } else {
                        !called && PATH_RECEIVERS.contains(&receiver.as_str())
                    };
                    if refused {
                        let line_start = code[..at].rfind('\n').map_or(0, |n| n + 1);
                        let line_end = code[at..].find('\n').map_or(code.len(), |n| at + n);
                        found.push(format!(
                            "{file}: fn {}: {}",
                            fn_at(code, blocks, at).unwrap_or_default(),
                            code[line_start..line_end].trim()
                        ));
                    }
                }
            }
        }
    }
    found
}

/// Every `self.emit(` call whose argument holds `literal`.
fn emits_of(files: &[Src], literal: &str) -> Vec<Site> {
    let mut sites = Vec::new();
    for (src, file) in files.iter().enumerate() {
        let code = &file.code;
        for (at, _) in code.match_indices(literal) {
            let Some(emit) = code[..at].rfind("self.emit(") else {
                continue;
            };
            let end = paren_end(code.as_bytes(), emit + "self.emit".len());
            if end > at {
                sites.push(Site {
                    src,
                    func: fn_at(code, &file.blocks, at).unwrap_or_default(),
                    name: literal.to_owned(),
                    start: emit,
                    end,
                });
            }
        }
    }
    sites
}

/// What is left of `after` (an [`after_call`] text) once separators and closing brackets are
/// dropped.
fn rest_of(after: &str) -> String {
    after
        .chars()
        .filter(|c| !c.is_whitespace() && !matches!(c, ';' | ',' | '}' | ')'))
        .collect()
}

/// Whether `rest` (a [`rest_of`] text) runs nothing: empty, or (after an optional `return`) a
/// plain value — names, paths, literals and constructors (a capitalised name before each `(`:
/// `None`, `Ok(()`, `Reply::Handled(0`, `Some(reply`), no method, macro, assignment or
/// reference.
fn runs_nothing(rest: &str) -> bool {
    let value = rest.strip_prefix("return").unwrap_or(rest);
    let operators = ['.', '!', '=', '&', '[', '?', '|', '+', '-', '*', '<', '>'];
    if value.contains(operators) || has_word(value, "self") {
        return false;
    }
    value.match_indices('(').all(|(at, _)| {
        let name: String = value[..at]
            .chars()
            .rev()
            .take_while(|&c| c.is_ascii_alphanumeric() || c == '_')
            .collect();
        name.chars().last().is_none_or(|c| c.is_ascii_uppercase())
    })
}

/// What runs after `site` inside its fn ([`after_call`]).
fn after_site(files: &[Src], site: &Site) -> String {
    let file = &files[site.src];
    after_call(&file.code, &file.blocks, site.start, site.end)
}

/// Whether nothing of `site`'s fn runs after it (its tail call).
fn is_tail(files: &[Src], site: &Site) -> bool {
    runs_nothing(&rest_of(&after_site(files, site)))
}

/// The effect executor: it applies every effect and feeds each answer to `on_cmd`, so it would
/// make every emitting fn an emitter of everything. Its own order is P10's (plan §3.4).
const EXECUTOR: [&str; 1] = ["emit"];

/// The tail emitters, added to `set` until none is new: the fns in which nothing runs after one
/// of their calls of a fn in `set` (`show_next_approval`, `open_input`, `card_open_pin`,
/// `sync_browser`, …), except the executor ([`EXECUTOR`]). Their callers are sites in turn.
/// 2026-11-20 (P9 review): before, only fns whose whole body was one such call counted, so a
/// caller of a fn that opens a window as its last step was not checked (`card_begin` after
/// `card_open_pin`).
fn add_wrappers(files: &[Src], set: &mut BTreeSet<String>) {
    let mut todo = set.clone();
    while !todo.is_empty() {
        let mut new = BTreeSet::new();
        for (src, file) in files.iter().enumerate() {
            for site in calls(src, file, &todo) {
                if !site.func.is_empty()
                    && !set.contains(&site.func)
                    && !EXECUTOR.contains(&site.func.as_str())
                    && is_tail(files, &site)
                {
                    new.insert(site.func);
                }
            }
        }
        set.extend(new.iter().cloned());
        todo = new;
    }
}

/// The fns whose own body names one of `tokens` (one level of "reads through a fn").
fn readers(files: &[Src], tokens: &[&str]) -> BTreeSet<String> {
    let mut found = BTreeSet::new();
    for file in files {
        for token in tokens {
            for (at, _) in file.code.match_indices(token) {
                if let Some(func) = fn_at(&file.code, &file.blocks, at) {
                    found.insert(func);
                }
            }
        }
    }
    found
}

/// The tokens and one-level reader calls (`.<reader>(`, `::<reader>(`) in `after`.
fn reads_in(after: &str, tokens: &[&str], through: &BTreeSet<String>) -> Vec<String> {
    let mut hits: Vec<String> = tokens
        .iter()
        .filter(|token| after.contains(**token))
        .map(|token| (*token).to_owned())
        .collect();
    for func in through {
        for call in [format!(".{func}("), format!("::{func}(")] {
            if after.contains(&call) {
                hits.push(call);
            }
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
        after_call(&code, &blocks_of(code.as_bytes()), start, end)
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
    // 2026-11-20 (P9 review): a `break` goes on after its loop; a `continue` runs the loop's
    // body again, then what follows the loop.
    let code = "fn f(&mut self) { for x in y { self.open(); break; } self.secret_purpose(); }";
    assert_eq!(after(code, "self.open("), "breakself.secret_purpose();");
    let code = "fn f(&mut self) { for x in y { self.a(); if c { self.open(); continue; } \
                self.b(); } self.z(); }";
    let seen = after(code, "self.open(");
    assert!(seen.starts_with("continue<loop>self.a();"), "{seen}");
    assert!(
        seen.contains("self.b();") && seen.ends_with("self.z();"),
        "{seen}"
    );
    let code = "fn f(&mut self) { loop { match a { A => { self.open(); break; } B => {} } } \
                self.z(); }";
    assert_eq!(after(code, "self.open("), "breakself.z();");
    // What counts as running nothing after a call.
    for rest in [
        "",
        "return",
        "None",
        "returnNone",
        "Ok((",
        "Reply::Handled(0",
        "Some(reply",
    ] {
        assert!(runs_nothing(rest), "{rest}");
    }
    for rest in ["self.refresh(", "logging::info(&[", "x=1", "self.b", "f(x"] {
        assert!(!runs_nothing(rest), "{rest}");
    }
    // Every receiver is seen: `Self::`/`App::` and a closure's `app.` are calls, another
    // receiver or a fn pointer is refused, a field or another type's fn is no use.
    let file = Src::new(
        "made-up".to_owned(),
        code_only(
            "fn f(&mut self) { Self::open(self); App::open(self); run(|app| app.open()); \
             other.open(); let g = Self::open; self.open = 1; Other::open(); }",
        ),
    );
    let names: BTreeSet<String> = ["open".to_owned()].into();
    assert_eq!(calls(0, &file, &names).len(), 3);
    let refused = other_uses(std::slice::from_ref(&file), &names);
    assert_eq!(refused.len(), 2, "{refused:?}");
    // A fn whose last step is an open is an opener: a read after it in its caller is seen.
    let files = [Src::new(
        "made-up".to_owned(),
        code_only(
            "fn open_input_with(&mut self) {} \
             fn card_open_pin(&mut self) { let x = 1; if x { self.open_input_with(); } } \
             fn card_begin(&mut self) { self.card_open_pin(); let _ = self.secret_purpose(); }",
        ),
    )];
    let mut openers: BTreeSet<String> = ["open_input_with".to_owned()].into();
    add_wrappers(&files, &mut openers);
    assert!(openers.contains("card_open_pin") && !openers.contains("card_begin"));
    let site = calls(0, &files[0], &openers)
        .into_iter()
        .find(|site| site.func == "card_begin")
        .unwrap();
    assert!(after_site(&files, &site).contains("self.secret_purpose("));
}

/// What one kind of answered effect checks: its sites and what may not follow them.
struct Kind {
    /// Its name in [`PENDING_P10`] and [`ENDS_ON_ITS_PATH`].
    key: &'static str,
    what: &'static str,
    /// The fns that emit it (by name) and the effect literals emitted elsewhere.
    emitters: &'static [&'static str],
    literals: &'static [&'static str],
    /// Where the literal may be emitted: only in `emitters` (`true`) or anywhere.
    literal_in_emitters: bool,
    /// The tokens no code after a site may name (`None`: nothing may run after it at all).
    tokens: Option<&'static [&'static str]>,
    /// At least this many sites (A-20; the counts at P9, 2026-11-20, raised by the P9 review
    /// the same day when the tail emitters and the second crate came in: 18 → 294, 69 → 126,
    /// 25 → 50, 15 → 27).
    min_sites: usize,
    /// The one-level readers (fns whose own body names a token) that must still be found
    /// (2026-11-20, P9 review): one renamed or moved out of the scanned code fails here
    /// instead of dropping out of the check. New readers need no entry. Not listed: the
    /// `Debug` impls named `fmt` in yw-engine that print a `self.info` of their own.
    readers_floor: &'static [&'static str],
}

const KINDS: [Kind; 4] = [
    Kind {
        key: "approval",
        what: "approval window open",
        emitters: &["open_approval", "show_next_approval_with"],
        literals: &["ApprovalEffect::Open {"],
        literal_in_emitters: true,
        tokens: None,
        min_sites: 294,
        readers_floor: &[],
    },
    Kind {
        key: "secret",
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
        min_sites: 126,
        readers_floor: &[
            "apply_secret_effect",
            "begin_secret",
            "card_counters",
            "card_site_check",
            "card_tick",
            "close_secret",
            "enter_target",
            "escape_target",
            "first_run_pending",
            "on_imported_key_busy",
            "on_key_imported",
            "on_secret_opened",
            "on_yk_connect_verified",
            "on_yk_counters",
            "on_yk_pin_changed",
            "on_yk_pins_set",
            "on_yk_protected",
            "password_failure",
            "recovery_failure",
            "secret_form",
            "secret_open",
            "secret_purpose",
            "shortcut_target",
            "tab_shortcut_target",
            "take_display_secret",
            "with_clock",
            "yk_connect_pin_submit",
            "yk_pin_job",
            "yk_show_counters",
        ],
    },
    Kind {
        key: "copy",
        what: "copy",
        emitters: &["copy"],
        literals: &["Effect::CopyText {"],
        literal_in_emitters: true,
        tokens: Some(&["self.copied", "self.info"]),
        min_sites: 50,
        readers_floor: &[
            "apply_form_action",
            "begin_generate",
            "begin_rpc_import",
            "card_notice_clear",
            "card_notice_set",
            "confirm_yes",
            "copied_tick",
            "copy_done",
            "copy_line",
            "delete_rpc_json",
            "discard_first_run",
            "due",
            "enter_screen",
            "explorer_reset",
            "explorer_save_edit",
            "finish_rpc_import",
            "generate",
            "generate_and_report",
            "items",
            "layout_and_paint",
            "on_command",
            "on_core",
            "on_folder_missing",
            "on_key_imported",
            "on_key_result",
            "on_opened",
            "on_sites",
            "on_status",
            "on_wallet_reset",
            "on_yk",
            "on_yk_outcome",
            "on_yubikey_enrolled",
            "open_chain_form",
            "open_explorer",
            "prune_dormant",
            "refuse_receive",
            "request_delete_chain",
            "save_autolock",
            "save_mnemonic_label",
            "save_rename",
            "save_settings",
            "save_template_credentials",
            "set_info",
            "sol_save_fees",
            "start_repin",
            "tick",
            "toggle_evm_token_hidden",
            "toggle_sol_token_hidden",
            "yk_note",
            "yk_save_card_name",
        ],
    },
    Kind {
        key: "launch",
        what: "launch",
        emitters: &["open_explorer"],
        literals: &["Effect::OpenUrl {", "Effect::OpenFolder("],
        literal_in_emitters: false,
        tokens: Some(&["launcher", "self.info"]),
        min_sites: 27,
        readers_floor: &[
            "apply_form_action",
            "begin_generate",
            "begin_rpc_import",
            "card_notice_clear",
            "card_notice_set",
            "confirm_yes",
            "copy_done",
            "copy_explorer_tx",
            "delete_rpc_json",
            "discard_first_run",
            "emit",
            "enter_screen",
            "explorer_reset",
            "explorer_save_edit",
            "finish_rpc_import",
            "generate",
            "generate_and_report",
            "layout_and_paint",
            "on_folder_missing",
            "on_key_imported",
            "on_key_result",
            "on_opened",
            "on_sites",
            "on_status",
            "on_wallet_reset",
            "on_yk",
            "on_yk_outcome",
            "on_yubikey_enrolled",
            "open_chain_form",
            "open_folder",
            "prune_dormant",
            "refuse_receive",
            "request_delete_chain",
            "save_autolock",
            "save_mnemonic_label",
            "save_rename",
            "save_settings",
            "save_template_credentials",
            "set_info",
            "sol_save_fees",
            "start_repin",
            "toggle_evm_token_hidden",
            "toggle_sol_token_hidden",
            "yk_note",
            "yk_save_card_name",
        ],
    },
];

/// The sites where code runs after an open in the same entry and that P10 (the outbox flip,
/// plan §4.6 rule 2) decides (2026-11-20, P9 review), one per line: `kind file fn called
/// sites` (the file under `yw-app/src`). Each is the first fn up from an opener in which something runs after it, so
/// one line covers that fn's callers too. Under the inline executor the open is answered before
/// the call returns, so the code after it sees the answer as it always did (byte-equal; the
/// census, `s4_flow`, `s4_secret` and `tour_forms` pin it). P10 converts or orders each one and
/// removes its line; a site that is not here fails, and so does a line no longer found or a
/// count that changed. spec/15 §11.4 S4 row (P9 review note) names them.
const PENDING_P10: [&str; 63] = [
    // The next step of the same entry: the next event or timer step, the next mapped step of
    // the same window message, the rest of the press or answer handler.
    "approval app.rs drain_events evm_rpc_event 1",
    "approval app.rs drain_events on_dapp_event 1",
    "approval app.rs drain_events on_key_result 1",
    "approval app.rs lock browser_lock_begin 1",
    "approval app.rs on_cmd on_approval_opened 1",
    "approval app.rs on_cmd on_press 1",
    "approval app.rs on_command on_cmd 2",
    "approval app.rs on_key_result btc_after_meta 1",
    "approval app.rs tick btc_tick 1",
    "approval app_approval.rs on_approval_input approval_event 1",
    "approval app_approval.rs run_step run_step 1",
    "approval app_approval.rs run_steps run_step 1",
    "approval app_evm.rs evm_tick tick_approval 1",
    // The repaint: `refresh` syncs the dApp view (which may show the next request) before its
    // `Effect::Render`; every caller of `refresh` goes on after it.
    "approval app.rs refresh sync_browser 1",
    // A revoked grant or a removed account or chain ends its waiting requests, then the grants
    // are written, logged and repainted.
    "approval app.rs confirm_yes delete_chain 1",
    "approval app.rs hide_selected account_removed_from_sites 3",
    "approval app_browser.rs disconnect_site revoke_waiting 1",
    "approval app_browser.rs evm_key_removed_from_sites account_removed_from_sites 1",
    "approval app_browser.rs network_url_changed btc_url_changed 1",
    "approval app_browser.rs persist_grant_change revoke_waiting 3",
    "approval app_chain_sites.rs chain_grants_removed revoke_waiting 1",
    "approval app_chain_sites.rs disconnect_chain_site revoke_waiting 1",
    // A prepare that fails ends its request and shows the next one; the caller goes on with
    // the view, the AI draft or the signing.
    "approval app_approval.rs consume_and_sign btc_consumed 1",
    "approval app_approval.rs on_approval_opened rebuild_view 1",
    "approval app_approval.rs on_prepared show_ready_draft 1",
    "approval app_approval.rs on_typed_facts show_ready_draft 1",
    "approval app_approval.rs prepare_site show_ready_draft 1",
    "approval app_approval.rs start_prepare prepare_btc 1",
    "approval app_approval.rs start_prepare prepare_hypercore 1",
    "approval app_approval.rs start_prepare prepare_site 1",
    "approval app_approval.rs start_prepare prepare_sol 1",
    "approval app_approval.rs start_prepare prepare_transaction 1",
    "approval app_approval.rs start_prepare prepare_zec 1",
    // A Bitcoin screen action (or a journal or Zcash event) queues a request; the handler then
    // fills a field or repaints.
    "approval app_btc.rs btc_call_and_repaint btc_call 1",
    "approval app_btc.rs btc_form btc_call 1",
    "approval app_btc.rs btc_journal_changed btc_call 1",
    "approval app_btc_commands.rs btc_apply_field btc_call 1",
    "approval app_btc_commands.rs btc_set_unit btc_call 1",
    "approval app_btc_commands.rs btc_toggle_max btc_call 1",
    "approval app_btc_commands.rs on_btc btc_call 6",
    "approval app_btc_commands.rs on_btc btc_continue 1",
    "approval app_btc_commands.rs on_btc btc_discover 2",
    "approval app_btc_commands.rs on_btc btc_mismatch_keep_meta 1",
    "approval app_btc_commands.rs on_btc btc_mismatch_use_settings 1",
    "approval app_btc_commands.rs on_btc btc_new_receive_address 1",
    "approval app_btc_commands.rs on_btc btc_open_bump 1",
    "approval app_btc_commands.rs on_btc btc_open_receive 1",
    "approval app_btc_commands.rs on_btc btc_open_send 1",
    "approval app_btc_commands.rs on_btc btc_refresh 1",
    "approval app_btc_commands.rs on_btc btc_reset_tip 1",
    "approval app_btc_commands.rs on_btc btc_review 1",
    "approval app_btc_commands.rs on_btc btc_review_bump 1",
    "approval app_btc_commands.rs on_btc btc_select_tab 1",
    "approval app_btc_commands.rs on_btc btc_set_indexer 3",
    "approval app_btc_commands.rs on_btc btc_settings_network 2",
    "approval app_btc_commands.rs on_btc btc_toggle_enabled 1",
    "approval app_btc_commands.rs on_btc on_btc_esplora 1",
    "approval app_btc_commands.rs on_btc on_btc_indexed 1",
    "approval app_btc_commands.rs on_btc_esplora btc_default_esplora_url 1",
    "approval app_btc_commands.rs on_btc_esplora btc_save_esplora_url 1",
    "approval app_btc_commands.rs on_btc_indexed btc_call 1",
    "approval app_evm.rs evm_key_outcome btc_journal_changed 1",
    "approval app_zec.rs zec_rpc_event zec_enqueue 1",
];

/// Sites the check reports whose opening path never reaches the code after them (it has no
/// paths), each with the reason; they stay after P10. Same lines as [`PENDING_P10`].
const ENDS_ON_ITS_PATH: [&str; 1] = [
    // `card_filter` opens the PIN window again (`card_unused` → `card_open_pin`) only on its
    // `KeyOutcome::CardUnused` path, which returns `None`; `on_key_result` returns at once on
    // `None` (`let Some(outcome) = … else { return; }`), so its later session reads never run
    // after that open.
    "secret app.rs on_key_result card_filter 1",
];

/// One site with code after it that the rule refuses.
struct Finding {
    file: String,
    func: String,
    name: String,
    problem: String,
}

/// What [`check_kind`] found for one kind.
struct Checked {
    sites: usize,
    emitters: BTreeSet<String>,
    misplaced: Vec<String>,
    findings: Vec<Finding>,
}

/// The sites of `kind` and what is wrong after them.
fn check_kind(files: &[Src], kind: &Kind) -> Checked {
    let mut misplaced = Vec::new();
    let mut names: BTreeSet<String> = kind.emitters.iter().map(|&n| n.to_owned()).collect();
    let mut literal_sites = Vec::new();
    for literal in kind.literals {
        for site in emits_of(files, literal) {
            if kind.literal_in_emitters && !names.contains(&site.func) {
                misplaced.push(format!(
                    "{}: {} emitted in fn {} (only in {:?})",
                    files[site.src].file, literal, site.func, kind.emitters
                ));
            }
            literal_sites.push(site);
        }
    }
    // A fn that emits the literal as its last step is an emitter too (its callers are sites).
    for site in &literal_sites {
        if is_tail(files, site) {
            names.insert(site.func.clone());
        }
    }
    add_wrappers(files, &mut names);
    let through = kind.tokens.map_or_else(BTreeSet::new, |tokens| {
        let mut set = readers(files, tokens);
        set.retain(|func| !names.contains(func));
        set
    });
    let mut sites = literal_sites;
    for (src, file) in files.iter().enumerate() {
        sites.extend(calls(src, file, &names));
    }
    let mut findings = Vec::new();
    for site in &sites {
        let after = after_site(files, site);
        let problem = match kind.tokens {
            None => {
                let rest = rest_of(&after);
                (!runs_nothing(&rest)).then(|| rest.chars().take(160).collect())
            }
            Some(tokens) => {
                let hits = reads_in(&after, tokens, &through);
                (!hits.is_empty()).then(|| hits.join(" "))
            }
        };
        if let Some(problem) = problem {
            findings.push(Finding {
                file: files[site.src].file.clone(),
                func: site.func.clone(),
                name: site.name.clone(),
                problem,
            });
        }
    }
    Checked {
        sites: sites.len(),
        emitters: names,
        misplaced,
        findings,
    }
}

/// The S5 source check (module doc).
#[test]
fn no_result_read_after_its_emit() {
    after_call_reads_what_runs_after();
    let files = production_code();
    assert!(files.len() > 100, "scanned {} files", files.len());
    for file in ["yw-app/src/app_approval.rs", "yw-engine/src/effect.rs"] {
        assert!(files.iter().any(|src| src.file == file), "{file} scanned");
    }
    // `after_call` takes a `break`/`continue` to the innermost loop: no labelled one.
    for src in &files {
        assert!(
            !src.code.contains("break '") && !src.code.contains("continue '"),
            "{}: a labelled break or continue (after_call does not follow labels)",
            src.file
        );
    }
    let mut errors = Vec::new();
    let mut counts = Vec::new();
    let mut found: BTreeMap<(String, String, String, String), (usize, String)> = BTreeMap::new();
    for kind in &KINDS {
        let checked = check_kind(&files, kind);
        assert!(
            checked.sites >= kind.min_sites,
            "{}: {} sites (at least {})",
            kind.what,
            checked.sites,
            kind.min_sites
        );
        counts.push((kind.key, checked.sites));
        errors.extend(checked.misplaced);
        for other in other_uses(&files, &checked.emitters) {
            errors.push(format!(
                "{}: not a counted call of an emitter: {other}",
                kind.key
            ));
        }
        if let Some(tokens) = kind.tokens {
            let all = readers(&files, tokens);
            for reader in kind.readers_floor {
                if !all.contains(*reader) {
                    errors.push(format!("{}: reader {reader} no longer found", kind.key));
                }
            }
        }
        for finding in checked.findings {
            let file = finding
                .file
                .strip_prefix("yw-app/src/")
                .unwrap_or(&finding.file)
                .to_owned();
            let entry = found
                .entry((kind.key.to_owned(), file, finding.func, finding.name))
                .or_default();
            entry.0 += 1;
            entry.1 = finding.problem;
        }
    }
    let listed: BTreeMap<_, _> = PENDING_P10
        .iter()
        .chain(ENDS_ON_ITS_PATH.iter())
        .map(|line| {
            let words: Vec<&str> = line.split_whitespace().collect();
            assert_eq!(words.len(), 5, "{line}: not `kind file fn called sites`");
            let key = (
                words[0].to_owned(),
                words[1].to_owned(),
                words[2].to_owned(),
                words[3].to_owned(),
            );
            (key, words[4].parse::<usize>().unwrap())
        })
        .collect();
    assert_eq!(
        listed.len(),
        PENDING_P10.len() + ENDS_ON_ITS_PATH.len(),
        "a line listed twice"
    );
    for (key, (sites, problem)) in &found {
        match listed.get(key) {
            None => errors.push(format!("{key:?} ({sites} sites): {problem}")),
            Some(&listed_sites) if listed_sites != *sites => errors.push(format!(
                "{key:?}: {sites} sites, {listed_sites} listed: {problem}"
            )),
            Some(_) => {}
        }
    }
    for key in listed.keys() {
        if !found.contains_key(key) {
            errors.push(format!(
                "{key:?} listed but no longer found: remove its line"
            ));
        }
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
