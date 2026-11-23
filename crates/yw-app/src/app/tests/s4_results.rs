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
//!   to the open (`Wallet::show_next_approval_then`, `AfterOpen`; since P10a also
//!   `Wallet::after_pending_open`, [`DEFERRALS`]), or is a line of [`NEXT_CALL_OF_AN_ENTRY`] or
//!   [`READS_NO_ANSWER`] with its reason;
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
//! Bitcoin handlers, …) went unchecked. Those were `PENDING_P10` (63 lines).
//!
//! 2026-11-20 (S4 P10a): `PENDING_P10` is gone (0 lines). Of its 63 lines, 48 are sites that
//! hand the code that ran after their call to the open's answer (`AfterOpen` through
//! `Wallet::after_pending_open`, which runs it at once while no open waits — always, while effects
//! are applied at once) or call the Bitcoin controller through `Wallet::btc_update`, which executes
//! no action and so opens nothing; the entries' next calls are [`NEXT_CALL_OF_AN_ENTRY`]
//! (drained between in P10b), two paths that never open are [`ENDS_ON_ITS_PATH`], and six sites
//! whose later code reads and changes nothing an open's answer does are [`READS_NO_ANSWER`], each
//! with its reason. A deferral whose argument is a plain value ([`without_deferrals`]) runs
//! nothing after the open. A `return` later in a block ends what runs after a call there
//! ([`return_statement`]); a `;` inside brackets no longer ends a fn's head ([`head`]).
//!
//! 2026-11-20 (S4 P10b): the outbox. `emit` only queues; the executor is `App::drain` (was
//! `emit`, [`EXECUTOR`]), which applies the queue and hands each answer to the logic. A call
//! that a drain follows (`self.drain()`, or a closure's `app.drain()`, right after it) has
//! nothing after it ([`after_site`]): its effects and their answers are handled before the next
//! statement, so its fn is no tail emitter. The shell's entries drain after each call into the
//! logic, so [`NEXT_CALL_OF_AN_ENTRY`] is empty; `on_key_result` drains after its handler
//! `key_result`.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use yw_engine::testkit::WalletTestExt;

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
/// `loop`, `match` or arm head. 2026-11-20 (S4 P10a): a `;` inside brackets (an array type
/// `[u8; 32]` in a fn's parameters) is part of the head; before, it ended it, so such a fn was
/// not found as the fn of its calls (no site's fn, no tail emitter) and its end not seen.
fn head(code: &str, open: usize) -> &str {
    let bytes = code.as_bytes();
    let mut depth = 0_i32;
    let mut at = open;
    while at > 0 {
        at -= 1;
        match bytes[at] {
            b')' | b']' => depth += 1,
            b'(' | b'[' => depth -= 1,
            b';' | b'{' | b'}' if depth <= 0 => return &code[at + 1..open],
            _ => {}
        }
    }
    &code[..open]
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
/// 2026-11-20 (S4 P10a): a `return` later in a block, as a statement of that block (not inside
/// a nested block, call or closure), ends it there too, named ([`return_statement`]); before,
/// only one right after the call did, and the blocks around were read on as if it fell through.
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
            } else if let Some(at) = return_statement(seg) {
                out.push_str(&seg[..at]);
                out.push_str("return");
                return out;
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

/// The offset in `seg` (the rest of one block) of a `return` that is a statement of that block:
/// outside every bracket of `seg`, after a `;` or `}` (2026-11-20, S4 P10a). `None` if none.
fn return_statement(seg: &str) -> Option<usize> {
    let bytes = seg.as_bytes();
    let mut depth = 0_i32;
    for (at, &byte) in bytes.iter().enumerate() {
        match byte {
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' | b'}' => depth -= 1,
            b'r' if depth == 0
                && starts_with_word(&seg[at..], "return")
                && (at == 0 || !is_ident(bytes[at - 1]))
                && seg[..at].trim_end().ends_with([';', '}']) =>
            {
                return Some(at);
            }
            _ => {}
        }
    }
    None
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
/// `app.<name>(`, `Self::<name>(`, `App::<name>(`. 2026-11-22 (S4c W15): also the shell's
/// `self.wallet.<name>(` (non-test builds have no `DerefMut`, so the shell names the wallet),
/// and `main.rs`'s `state.<name>(` (its start steps' and loop observer's `App` borrow, which
/// now reaches `Cmd::Input` through `App::note_input`).
const DOT_RECEIVERS: [&str; 4] = ["self", "app", "self.wallet", "state"];
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
                    // 2026-11-22 (S4c W15): `self.wallet.<name>` is the receiver `self.wallet`.
                    let receiver = if receiver == "wallet" && ends_with_word(before, "self.wallet")
                    {
                        "self.wallet".to_owned()
                    } else {
                        receiver
                    };
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

/// Every `self.emit(` call whose argument holds `literal` (2026-11-22, S4c W15: or
/// `self.wallet.emit(`, the shell's way to queue one, non-test builds having no `DerefMut`).
fn emits_of(files: &[Src], literal: &str) -> Vec<Site> {
    let mut sites = Vec::new();
    for (src, file) in files.iter().enumerate() {
        let code = &file.code;
        for (at, _) in code.match_indices(literal) {
            let Some((emit, receiver)) = ["self.emit(", "self.wallet.emit("]
                .into_iter()
                .filter_map(|call| Some((code[..at].rfind(call)?, call)))
                .max_by_key(|&(emit, _)| emit)
            else {
                continue;
            };
            let end = paren_end(code.as_bytes(), emit + receiver.len() - 1);
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

/// The fns through which a step hands itself to the answer of the open still waiting for one
/// ([`Wallet::after_pending_open`](crate::app::Wallet::after_pending_open), 2026-11-20, S4 P10a).
const DEFERRALS: [&str; 1] = ["after_pending_open"];

/// `after` (an [`after_call`] text) without its deferrals: `self.<deferral>(<value>)` whose
/// argument runs nothing ([`runs_nothing`]: a variant built from names and literals, no call,
/// method or operator) is dropped, so a site whose later steps all go through a deferral runs
/// nothing after its open (2026-11-20, S4 P10a). A deferral whose argument computes something
/// stays (it would run before the answer).
fn without_deferrals(after: &str) -> String {
    let mut out = after.to_owned();
    for name in DEFERRALS {
        let pattern = format!("self.{name}(");
        let mut from = 0;
        while let Some(found) = out[from..].find(&pattern) {
            let start = from + found;
            let open = start + pattern.len() - 1;
            let end = paren_end(out.as_bytes(), open);
            let argument = &out[open + 1..end.saturating_sub(1).max(open + 1)];
            if runs_nothing(&rest_of(argument)) {
                out.replace_range(start..end, "");
                from = start;
            } else {
                from = end;
            }
        }
    }
    out
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

/// What runs after `site` inside its fn ([`after_call`]); `None` when the next statement is a
/// drain (`self.drain()`, a closure's or `Forward`'s `app.drain()`), which applies the effects
/// the call emitted and hands their answers to the logic before anything else runs, so nothing
/// after it can miss an answer and the fn is no tail emitter (2026-11-20, S4 P10b: the outbox; an
/// entry ends with a drain).
fn after_site(files: &[Src], site: &Site) -> Option<String> {
    let file = &files[site.src];
    let after = after_call(&file.code, &file.blocks, site.start, site.end);
    (!drains_first(&after)).then_some(after)
}

/// Whether `after` (an [`after_call`] text) starts with a drain, closing brackets and
/// separators aside (2026-11-20, S4 P10b).
fn drains_first(after: &str) -> bool {
    let lead =
        after.trim_start_matches(|c: char| c.is_whitespace() || matches!(c, ';' | ',' | '}' | ')'));
    ["self.drain()", "app.drain()"]
        .iter()
        .any(|drain| lead.starts_with(drain))
}

/// Whether nothing of `site`'s fn runs after it (its tail call). A drain right after is not a
/// tail (2026-11-20, S4 P10b).
fn is_tail(files: &[Src], site: &Site) -> bool {
    after_site(files, site).is_some_and(|after| runs_nothing(&rest_of(&after)))
}

/// The effect executor: it applies every effect and feeds each answer to `on_cmd`, so it would
/// make every emitting fn an emitter of everything. Its own order is P10's (plan §3.4).
/// 2026-11-20 (S4 P10b): `drain` (before, `emit`, which applied each effect at once and now only
/// queues it).
const EXECUTOR: [&str; 1] = ["drain"];

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
    assert!(
        after_site(&files, &site)
            .unwrap()
            .contains("self.secret_purpose(")
    );
    deferrals_and_returns_on_made_up_code();
    a_drain_ends_what_runs_after();
}

/// 2026-11-20 (S4 P10a), on made-up code: a `return` later in a block ends what runs after a
/// call there (one in a nested block does not); a fn with an array parameter is still the fn of
/// its calls and its end is still seen; a deferral with a plain argument runs nothing after an
/// open, one that computes its argument does, and a fn ending in a deferral is an opener for its
/// callers.
fn deferrals_and_returns_on_made_up_code() {
    let after = |code: &str, call: &str| -> String {
        let code = code_only(code);
        let start = code.find(call).unwrap();
        let end = paren_end(code.as_bytes(), start);
        after_call(&code, &blocks_of(code.as_bytes()), start, end)
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect()
    };
    let code = "fn f(&mut self) { if a { self.open(); self.later(); return; } self.z(); }";
    assert_eq!(after(code, "self.open("), ";self.later();return");
    let code = "fn f(&mut self) { if a { self.open(); if b { return; } self.later(); } self.z(); }";
    assert_eq!(
        after(code, "self.open("),
        ";ifb{return;}self.later();self.z();"
    );
    let code = "fn f(&mut self) { self.open(); let g = |x| { return x; }; self.z(); }";
    assert!(after(code, "self.open(").ends_with("self.z();"));
    let code = "fn h(&mut self, k: &[u8; 32]) { self.open(); } fn i(&mut self) { self.z(); }";
    assert_eq!(after(code, "self.open("), ";");
    let file = Src::new("made-up".to_owned(), code_only(code));
    let at = file.code.find("self.open(").unwrap();
    assert_eq!(fn_at(&file.code, &file.blocks, at).as_deref(), Some("h"));
    // Deferrals.
    let plain = "; self.after_pending_open(AfterOpen::Refresh); return";
    assert!(runs_nothing(&rest_of(&without_deferrals(plain))));
    let computed = "; self.after_pending_open(AfterOpen::Note(self.label())); ";
    assert!(!runs_nothing(&rest_of(&without_deferrals(computed))));
    let then = "; self.after_pending_open(AfterOpen::Steps(rest)); self.z();";
    assert_eq!(rest_of(&without_deferrals(then)), "self.z(");
    let files = [Src::new(
        "made-up".to_owned(),
        code_only(
            "fn opener(&mut self) {} \
             fn after_pending_open(&mut self, after: AfterOpen) { self.opener(); } \
             fn f(&mut self) { self.opener(); self.after_pending_open(AfterOpen::A); } \
             fn g(&mut self) { self.f(); self.z(); }",
        ),
    )];
    let mut openers: BTreeSet<String> = ["opener".to_owned()].into();
    add_wrappers(&files, &mut openers);
    assert!(
        openers.contains("f") && !openers.contains("g"),
        "{openers:?}"
    );
    let site_in = |func: &str, name: &str| {
        calls(0, &files[0], &openers)
            .into_iter()
            .find(|site| site.func == func && site.name == name)
            .unwrap()
    };
    let in_f = after_site(&files, &site_in("f", "opener")).unwrap();
    assert!(!runs_nothing(&rest_of(&in_f)));
    assert!(runs_nothing(&rest_of(&without_deferrals(&in_f))));
    let in_g = after_site(&files, &site_in("g", "f")).unwrap();
    assert!(!runs_nothing(&rest_of(&without_deferrals(&in_g))));
}

/// 2026-11-20 (S4 P10b), on made-up code: a drain right after a call (also after its `match` or
/// block) applies what it emitted first: nothing runs after it, and its fn is no opener; a drain
/// later on, or only in one branch, does not count.
fn a_drain_ends_what_runs_after() {
    let files = [Src::new(
        "made-up".to_owned(),
        code_only(
            "fn open_input_with(&mut self) {} \
             fn entry(&mut self) { match x { A => self.open_input_with(), _ => {} } \
             self.drain(); let _ = self.secret_purpose(); } \
             fn early(&mut self) { self.open_input_with(); let _ = self.secret_purpose(); \
             self.drain(); } \
             fn branch(&mut self) { if a { self.open_input_with(); } else { self.drain(); } \
             let _ = self.secret_purpose(); }",
        ),
    )];
    let mut openers: BTreeSet<String> = ["open_input_with".to_owned()].into();
    add_wrappers(&files, &mut openers);
    assert!(!openers.contains("entry"), "{openers:?}");
    let after_in = |func: &str| {
        let site = calls(0, &files[0], &openers)
            .into_iter()
            .find(|site| site.func == func)
            .unwrap();
        after_site(&files, &site)
    };
    assert_eq!(after_in("entry"), None);
    assert!(after_in("early").unwrap().contains("self.secret_purpose("));
    assert!(after_in("branch").unwrap().contains("self.secret_purpose("));
}

/// What one kind of answered effect checks: its sites and what may not follow them.
struct Kind {
    /// Its name in [`NEXT_CALL_OF_AN_ENTRY`], [`READS_NO_ANSWER`] and [`ENDS_ON_ITS_PATH`].
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
    /// 25 → 50, 15 → 27). 2026-11-20 (S4 P10a): approval 294 → 323, as the fns that hand their
    /// later steps to an open's answer end in `after_pending_open` and so are openers too.
    /// 2026-11-20 (S4 P10b): approval 323 → 301, as the shell entries that drain right after a
    /// call into the logic (`on_key_result`, `dispatch`, each event of `drain_events`, each part
    /// of `tick`, the approval window's inputs and its timer's tail) are no tail emitters any
    /// more ([`after_site`]).
    min_sites: usize,
    /// The one-level readers (fns whose own body names a token) that must still be found
    /// (2026-11-20, P9 review): one renamed or moved out of the scanned code fails here
    /// instead of dropping out of the check. New readers need no entry. Not listed: the
    /// `Debug` impls named `fmt` in yw-engine that print a `self.info` of their own.
    /// 2026-11-22 (S4c W12, preflight critic C12): the copy and launch floors name
    /// `on_secret_action` instead of `apply_form_action`: the time-out notice (`self.info`) moved
    /// with the wallet's half of the secret form's actions.
    /// 2026-11-22 (S4c W13, critique B-5): they name `on_rpc_json_read` and
    /// `on_rpc_json_deleted` instead of `begin_rpc_import` and `delete_rpc_json`: the import
    /// band (`self.info`) moved with the wallet's halves of the `rpc.json` read and delete.
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
        min_sites: 301,
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
        // 2026-11-23 (S4d E1): `apply_secret_effect` reads the session through the engine's
        // `secret_unshown` now (the shell cannot name the private field across crates).
        readers_floor: &[
            "secret_unshown",
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
            // 2026-11-23 (S4d E0b): `Wallet::new` builds the session field (was `with_clock`'s
            // `Wallet` literal).
            "new",
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
            "begin_generate",
            "on_rpc_json_read",
            "card_notice_clear",
            "card_notice_set",
            "confirm_yes",
            "copied_tick",
            "copy_done",
            "copy_line",
            "on_rpc_json_deleted",
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
            // 2026-11-22 (S4c W15): `on_command`'s `self.copied = None` is the wallet's
            // `forget_copy_mark` (below), and `tick`'s `copied_tick` call `timer_part`'s.
            "on_core",
            "on_folder_missing",
            "on_key_imported",
            "key_result",
            "on_opened",
            "on_secret_action",
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
            "timer_part",
            "forget_copy_mark",
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
            "begin_generate",
            "on_rpc_json_read",
            "card_notice_clear",
            "card_notice_set",
            "confirm_yes",
            "copy_done",
            "copy_explorer_tx",
            "on_rpc_json_deleted",
            "discard_first_run",
            "apply",
            "enter_screen",
            "explorer_reset",
            "explorer_save_edit",
            "finish_rpc_import",
            "generate",
            "generate_and_report",
            "layout_and_paint",
            "on_folder_missing",
            "on_key_imported",
            "key_result",
            "on_opened",
            "on_secret_action",
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

/// Sites where a shell entry calls into the logic again after a call that may open (2026-11-20,
/// S4 P10a; were `PENDING_P10` lines of the P9 review), one per line: `kind file fn called
/// sites` (the file under `yw-app/src`). They are the entries' own next steps: each worker event
/// of `drain_events`, each part of the main timer's `tick`, each `Cmd` of `on_command` (the
/// form, the press, then the shell's Enter/Esc resolution), each mapped step of an approval
/// window's message (`run_steps`, `run_step`). P10b drains the outbox after each such call
/// (plan §3.4: the answer of an open is handled before the entry's next call), so nothing of a
/// later call runs before an earlier call's answer: safe under drain-per-call. A site that is in
/// no list fails, and so does a line no longer found or a count that changed.
///
/// 2026-11-20 (S4 P10b): empty — those entries drain right after each such call now
/// ([`after_site`]: a call a drain follows has nothing after it), which removed the eight lines
/// `drain_events evm_rpc_event`, `drain_events on_dapp_event`, `drain_events on_key_result`,
/// `on_command on_cmd` (2), `tick btc_tick`, `tick evm_tick`, `run_step run_step` and `run_steps
/// run_step`. A new site of this kind is a missing drain.
const NEXT_CALL_OF_AN_ENTRY: [&str; 0] = [];

/// Sites whose code after the call reads and changes nothing the open's answer reads or changes
/// (2026-11-20, S4 P10a; were `PENDING_P10` lines), each with the reason. With the outbox (P10b)
/// that code runs before the answer instead of after it; the answer (`on_approval_opened`: the
/// AI reservation, the width, the first view, the preparation; the opener's `AfterOpen` steps)
/// and that code touch different state, so the state after both is the same, and an effect that
/// code emits queues behind the open and is applied after the answer in the same drain. Not
/// converted because the fn would become an opener for every caller (each revoke and removal
/// path, the shell's press entry, every `refresh`).
const READS_NO_ANSWER: [&str; 9] = [
    // After the press: the press input is put back (the outer press's) and this press's is
    // wiped (`used`, debug: its unread credential count). An open's answer reads no press input:
    // `take_cred` (core, RPC, LLM and EVM settings handlers) and `take_clip`/`take_image` (the
    // `WalletConnect` pair press) are press handlers, none reached from `on_approval_opened`,
    // `start_prepare` or an `AfterOpen` step.
    "approval yw-engine/src/wallet/mod.rs on_cmd on_press 1",
    // `sync_browser` opens only at the first sync of an unlocked dApp view (`browser.unlocked`
    // false → true: `after_browser_unlock` → `show_next_approval`); after it, `refresh` emits
    // `Effect::Render`, which reads nothing here: queued behind the open, it is applied after the
    // answer, laying out the state after it. That first sync is the meta load's screen change or
    // repaint (`KeyOutcome::Meta(Ok)`, which hands its later chain hooks to the answer:
    // `AfterOpen::AfterMeta`) or a backup confirmation's last step (`set_screen(Screen::Done)`).
    "approval yw-engine/src/wallet/mod.rs refresh sync_browser 1",
    // `revoke_waiting` opens the next window only when it ends the shown request (a signing
    // request of that origin and family) and hands its card check to the open; then the grants
    // are written to meta (the answer reads no grant or site of meta), `site.disconnected` is
    // logged and `refresh` repaints (as above). Same for the chain families.
    "approval yw-engine/src/wallet/app_browser.rs disconnect_site revoke_waiting 1",
    "approval yw-engine/src/wallet/app_chain_sites.rs disconnect_chain_site revoke_waiting 1",
    // The next account's or origin's removal ends waiting requests (the opened window's request
    // is shown, not waiting) and writes grants; then the grants are written and the count logged.
    // If a later account or origin is also the opened window's request's, that window is ended
    // in the same entry: applied at once it was made, prepared and closed; with the outbox its
    // open is stale when applied (critique A-3: nothing made, the answer ignored). The dApp's
    // answer (4100) is the same either way; P10b's `s4_flow`/`s4_secret` decide the A-3 lines.
    "approval yw-engine/src/wallet/app_browser.rs evm_key_removed_from_sites account_removed_from_sites 1",
    "approval yw-engine/src/wallet/app_chain_sites.rs chain_grants_removed revoke_waiting 1",
    // 2026-11-21 (S4 W1): the main window's pointer press. `hold_down` (shell) sends only
    // `Cmd::HoldBegin` to the logic (`reset_hold_begin`: S22's gate, its progress, `refresh`),
    // which opens no approval window; it counts because `on_cmd` also routes an open's answer.
    // After it, the drop-downs' close and its repaint read and change nothing an open's answer
    // does. Before W1 the hold's logic ran inside `hold_down` (`refresh`, a listed site above).
    "approval app.rs on_main_msg hold_down 1",
    // 2026-11-22 (S4c W15): the press entry's first step and the loop observer's. `note_input`
    // sends only `Cmd::Input` (the idle clock's restart), which opens no approval window;
    // it counts because `on_cmd` also routes an open's answer. After it come the drop-downs' close,
    // the press (`on_command`), or the observer's navigation key and its drain (`main.rs`): none
    // reads or changes what an open's answer does. Before W15 `note_input` wrote the idle clock
    // itself and called nothing.
    "approval app.rs on_command note_input 1",
    "approval main.rs main note_input 1",
];

/// Sites the check reports whose opening path never reaches the code after them (it has no
/// paths), each with the reason; they stay after P10.
const ENDS_ON_ITS_PATH: [&str; 3] = [
    // `card_filter` opens the PIN window again (`card_unused` → `card_open_pin`) only on its
    // `KeyOutcome::CardUnused` path, which returns `None`; `on_key_result` returns at once on
    // `None` (`let Some(outcome) = … else { return; }`), so its later session reads never run
    // after that open.
    // 2026-11-20 (S4 P10b): `on_key_result`'s handler is `key_result` (the entry drains).
    "secret yw-engine/src/wallet/mod.rs key_result card_filter 1",
    // 2026-11-20 (S4 P10a; was a `PENDING_P10` line): `browser_lock_begin` sets
    // `browser.locking` before its `sync_browser` (and returns before it without a browser), so
    // `vault_view` is never `Unlocked` or `PassphraseUnverified` there and the unlock arm
    // (`after_browser_unlock`, the only open in `sync_browser`) never runs. (2026-11-21, S4 W3a:
    // in the lock's first half `lock_steps`; before, in `lock`.)
    "approval yw-engine/src/wallet/mod.rs lock_steps browser_lock_begin 1",
    // 2026-11-20 (S4 P10a; was a `PENDING_P10` line): `btc_url_changed`'s controller call
    // (`BtcUi::url_changed`) returns one `BtcAction::Rpc` (the session reset), which `btc_apply`
    // sends; only `BtcAction::Enqueue` and `SetMeta`'s grant removal open an approval window.
    "approval yw-engine/src/wallet/app_browser.rs network_url_changed btc_url_changed 1",
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
        // 2026-11-20 (S4 P10b): the executor's own calls (`drain` hands each answer to `on_cmd`)
        // and a call a drain follows are no finding.
        if EXECUTOR.contains(&site.func.as_str()) {
            continue;
        }
        let Some(after) = after_site(files, site) else {
            continue;
        };
        let problem = match kind.tokens {
            None => {
                // 2026-11-20 (S4 P10a): steps handed to the open's answer do not run after it.
                let rest = rest_of(&without_deferrals(&after));
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
    let listed: BTreeMap<_, _> = NEXT_CALL_OF_AN_ENTRY
        .iter()
        .chain(READS_NO_ANSWER.iter())
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
        NEXT_CALL_OF_AN_ENTRY.len() + READS_NO_ANSWER.len() + ENDS_ON_ITS_PATH.len(),
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

    use yw_engine::errors::ErrorCode;
    use yw_engine::wallet::app_approval::AfterOpen;

    let (mut app, dir) = super::unlocked_app("after-open", false);
    let answer = |shown| Cmd::ApprovalOpened {
        shown,
        outcome: OpenOutcome::Failed(ErrorCode::App009),
        wide: false,
    };
    // Nothing to show: `show_next_approval`'s own repaint, then the step's.
    let _ = app.controls.take_shell_log();
    app.show_next_approval_then(AfterOpen::CardSiteCheckThenRefresh);
    app.drain();
    assert_eq!(app.controls.take_shell_log(), ["refresh", "refresh"]);
    assert!(app.after_open_steps().is_empty());
    // A step kept for window `shown`: another window's answer leaves it; its own runs it once
    // (this answer is stale — no flow — so the step is all it does).
    let shown = ShownId(u64::MAX);
    app.keep_after_open(shown, AfterOpen::CardSiteCheckThenRefresh);
    app.dispatch(answer(ShownId(u64::MAX - 1)));
    assert_eq!(app.controls.take_shell_log(), Vec::<String>::new());
    assert_eq!(app.after_open_steps().len(), 1);
    app.dispatch(answer(shown));
    assert_eq!(app.controls.take_shell_log(), ["refresh"]);
    assert!(app.after_open_steps().is_empty());
    app.dispatch(answer(shown));
    assert_eq!(app.controls.take_shell_log(), Vec::<String>::new());
    // The rest of a Bitcoin batch: none left but the batch's repaint.
    app.keep_after_open(shown, AfterOpen::BtcRest(Vec::new()));
    assert_eq!(
        format!("{:?}", app.after_open_steps()),
        "[(ShownId(18446744073709551615), BtcRest(0))]"
    );
    app.dispatch(answer(shown));
    assert_eq!(app.controls.take_shell_log(), ["refresh"]);
    let _ = std::fs::remove_dir_all(dir);
}

/// 2026-11-20 (S4 P10a): `after_pending_open` runs a step at once while no approval-window open
/// waits for its answer (always, while effects are applied at once) and otherwise keeps it for
/// the newest open that waits; that open's answer no longer waits and runs the kept steps once,
/// in order, after its own steps; another window's answer leaves them. The kept steps print
/// names, counts and lengths only. Headless, no window. 2026-11-20 (S4 P10b): the answers go in
/// through `dispatch` and the step run at once is drained, as a shell entry does (the outbox).
#[test]
fn steps_after_an_open_wait_for_its_answer() {
    use yw_engine::approval::flow::{OpenOutcome, ShownId};
    use yw_engine::cmd::Cmd;

    use yw_engine::errors::ErrorCode;
    use yw_engine::wallet::app_approval::AfterOpen;

    let (mut app, dir) = super::unlocked_app("after-pending", false);
    let answer = |shown| Cmd::ApprovalOpened {
        shown,
        outcome: OpenOutcome::Failed(ErrorCode::App009),
        wide: false,
    };
    let _ = app.controls.take_shell_log();
    // Nothing waits: at once (2026-11-20, S4 P10b: its repaint is applied when the entry drains).
    assert_eq!(app.open_unanswered(), None);
    app.after_pending_open(AfterOpen::Refresh);
    app.drain();
    assert_eq!(app.controls.take_shell_log(), ["refresh"]);
    // An open waits (as it will with the outbox): kept for it, in order.
    let shown = ShownId(u64::MAX);
    app.set_open_unanswered(Some(shown));
    app.after_pending_open(AfterOpen::Refresh);
    app.after_pending_open(AfterOpen::RefreshUnlessActed(true));
    app.after_pending_open(AfterOpen::HiddenNote("계정 2".to_owned()));
    assert_eq!(app.controls.take_shell_log(), Vec::<String>::new());
    assert_eq!(
        format!("{:?}", app.after_open_steps()),
        "[(ShownId(18446744073709551615), Refresh), (ShownId(18446744073709551615), \
         RefreshUnlessActed(true)), (ShownId(18446744073709551615), HiddenNote(4))]"
    );
    // Another window's answer leaves them, and the open still waits.
    app.dispatch(answer(ShownId(u64::MAX - 1)));
    assert_eq!(app.open_unanswered(), Some(shown));
    assert_eq!(app.after_open_steps().len(), 3);
    assert_eq!(app.controls.take_shell_log(), Vec::<String>::new());
    // Its own answer (stale here: no flow, so no steps of its own): no longer waiting, the kept
    // steps once, in order (the note's repaint is the second `refresh`).
    let banners = app.banners.len();
    app.dispatch(answer(shown));
    assert_eq!(app.open_unanswered(), None);
    assert!(app.after_open_steps().is_empty());
    assert_eq!(app.controls.take_shell_log(), ["refresh", "refresh"]);
    assert_eq!(app.banners.len(), banners + 1);
    app.dispatch(answer(shown));
    assert_eq!(app.controls.take_shell_log(), Vec::<String>::new());
    assert_eq!(
        format!(
            "{:?}",
            AfterOpen::Steps(vec![
                AfterOpen::EvmTickRest(7),
                AfterOpen::Finish(yw_engine::approval::QueueOutcome::Approved),
                AfterOpen::SetScreen(yw_engine::wallet::Screen::Main),
            ])
        ),
        "Steps([EvmTickRest(7), Finish(Approved), SetScreen])"
    );
    let _ = std::fs::remove_dir_all(dir);
}

/// 2026-11-20 (S4 P9): a secret window's form operations wait in its session until the window is
/// shown, are handed out once, and print as names and lengths only.
#[test]
fn form_steps_wait_for_the_shown_window() {
    use yw_engine::secret::{SecretFormOp, SecretKind};

    use yw_engine::testkit::SessionTestExt;
    use yw_engine::wallet::Purpose;
    use yw_engine::wallet::secret_session::AfterShown;

    let text = "a line of sixteen";
    let forms = AfterShown::Forms(vec![
        SecretFormOp::Error(Some(text.to_owned())),
        SecretFormOp::Details(vec![text.to_owned(), text.to_owned()]),
    ]);
    let mut session =
        yw_engine::testkit::secret_session(7, SecretKind::Mnemonic, Purpose::ImportMnemonic, false);
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

// ---- The outbox's source checks (2026-11-20, S4 P10b; plan §4.4 S4, critique A-14 S9, A-16 S10) --

/// The scanned source `file` (`crate/src/path`); fails when it was not scanned (A-20).
/// `app.rs` and its wallet half `app/wallet.rs` as one source (2026-11-23, S4d E0b: split there),
/// for the checks that find a fn or the `Wallet` fields of either; it keeps `app.rs`'s name.
fn app_and_wallet(files: &[Src]) -> Src {
    let app = src_of(files, "yw-app/src/app.rs");
    // 2026-11-23 (S4d E1): the wallet half is yw-engine's `wallet/mod.rs` (was `app/wallet.rs`).
    let all = production_code();
    let wallet = src_of(&all, "yw-engine/src/wallet/mod.rs");
    Src::new(
        "yw-app/src/app.rs".to_owned(),
        format!(
            "{}
{}",
            app.code, wallet.code
        ),
    )
}

/// yw-app's sources and yw-engine's wallet (2026-11-23, S4d E1): the scans that looked at
/// yw-app's files see the wallet code where it moved (`yw-engine/src/wallet/`).
fn in_app_or_wallet(file: &str) -> bool {
    file.starts_with("yw-app/") || file.starts_with("yw-engine/src/wallet/")
}

fn src_of<'a>(files: &'a [Src], file: &str) -> &'a Src {
    let found = files.iter().find(|src| src.file == file);
    assert!(found.is_some(), "{file} not scanned");
    found.unwrap()
}

/// The bodies (from `fn` to the closing brace) of every fn named `name` in `src`.
fn fn_bodies<'a>(src: &'a Src, name: &str) -> Vec<&'a str> {
    let code = &src.code;
    let mut bodies = Vec::new();
    for pattern in [format!("fn {name}("), format!("fn {name}<")] {
        for (at, _) in code.match_indices(&pattern) {
            if at > 0 && is_ident(code.as_bytes()[at - 1]) {
                continue;
            }
            let Some(open) = code[at..].find('{').map(|n| at + n) else {
                continue;
            };
            bodies.push(&code[at..=close_of(code.as_bytes(), open)]);
        }
    }
    bodies
}

/// The blocks of `impl Handler for …` in `src` (the trait named plain or by path).
fn handler_impls(src: &Src) -> Vec<&str> {
    let code = &src.code;
    let mut impls = Vec::new();
    for (at, _) in code.match_indices("impl ") {
        if at > 0 && is_ident(code.as_bytes()[at - 1]) {
            continue;
        }
        let Some(open) = code[at..].find('{').map(|n| at + n) else {
            continue;
        };
        let head = code[at..open]
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");
        if head.starts_with("impl Handler for ")
            || head.starts_with("impl yw_win::ui::Handler for ")
        {
            impls.push(&code[at..=close_of(code.as_bytes(), open)]);
        }
    }
    impls
}

/// The body block of every fn of `src` (the outermost block whose head names `fn`), with the
/// fn's name.
fn fn_blocks(src: &Src) -> Vec<(String, &str)> {
    let mut found = Vec::new();
    for block in &src.blocks {
        let block_head = head(&src.code, block.open);
        let Some((_, after)) = block_head.rsplit_once("fn ") else {
            continue;
        };
        if !has_word(block_head, "fn") {
            continue;
        }
        let name: String = after
            .trim_start()
            .chars()
            .take_while(|&c| c.is_ascii_alphanumeric() || c == '_')
            .collect();
        found.push((name, &src.code[block.open..=block.close]));
    }
    found
}

/// S4 `effects_are_never_posted` (plan §4.4, 2026-11-20 S4 P10b): the effect executor
/// (`app_effects.rs`) posts no message, keeps no poster and starts no thread — every effect is
/// applied inside the `App` borrow of the entry that emitted it (`App::drain`), never deferred
/// past it (spec/01 §7.7, spec/15 §11.4 S3 item 4). Also: `emit` only queues, and `drain`
/// empties the queue in order.
#[test]
fn effects_are_never_posted() {
    let files = production_code();
    let effects = src_of(&files, "yw-app/src/app_effects.rs");
    for banned in ["PostMessage", ".post(", "Poster", "poster", "spawn("] {
        assert!(
            !effects.code.contains(banned),
            "app_effects.rs names {banned}"
        );
    }
    // 2026-11-23 (S4d E0b): `emit` and `next_effect` are in the wallet half `app/wallet.rs`
    // (were `app_effects.rs`'s `impl Wallet` block).
    let wallet_src = src_of(&files, "yw-engine/src/wallet/mod.rs");
    let emit = fn_bodies(wallet_src, "emit");
    assert_eq!(emit.len(), 1, "one emit");
    assert!(
        emit[0].contains("self.outbox.push_back(effect);")
            && !emit[0].contains("self.apply(")
            && !emit[0].contains(".drain()")
            && !emit[0].contains("self.on_cmd("),
        "emit only queues: {}",
        emit[0]
    );
    // 2026-11-21 (S4 W3, plan §3.4): the queue is the wallet's — `emit` and `next_effect` are
    // `impl Wallet` fns, and the drain takes one effect at a time through `next_effect` (before,
    // `while let Some(effect) = self.outbox.pop_front()` on `App`'s queue).
    let next = fn_bodies(wallet_src, "next_effect");
    assert_eq!(next.len(), 1, "one next_effect");
    let next_flat: String = next[0].split_whitespace().collect();
    assert!(
        next_flat.ends_with("{self.outbox.pop_front()}"),
        "next_effect takes the oldest effect: {}",
        next[0]
    );
    // 2026-11-23 (S4d E0b): each is inside an `impl Wallet` block of `app/wallet.rs`, and
    // `app_effects.rs` has no `impl Wallet` block left (before, both were checked in its own
    // `impl Wallet` block).
    for (name, body) in [("emit", emit[0]), ("next_effect", next[0])] {
        let at = wallet_src.code.find(body).unwrap_or_default();
        let block = wallet_src.code[..at].rfind("impl Wallet {");
        assert!(block.is_some(), "{name} is an impl Wallet fn");
        let block = block.unwrap_or_default();
        let end = close_of(wallet_src.code.as_bytes(), block + "impl Wallet ".len());
        assert!(block < at && at < end, "{name} is an impl Wallet fn");
    }
    assert!(
        !effects.code.contains("impl Wallet {"),
        "app_effects.rs holds no wallet code"
    );
    let app_impl = effects.code.find("impl App {");
    assert!(app_impl.is_some(), "an impl App");
    let app_at = app_impl.unwrap_or_default();
    let drain = fn_bodies(effects, "drain");
    assert_eq!(drain.len(), 1, "one drain");
    let drain_at = effects.code.find(drain[0]).unwrap_or_default();
    assert!(app_at < drain_at, "drain is the shell's (impl App)");
    assert!(
        drain[0].contains("while let Some(effect) = self.wallet.next_effect()")
            && !drain[0].contains("outbox.pop_front()")
            && !drain[0].contains("outbox.drain("),
        "drain empties the queue in order, one effect at a time: {}",
        drain[0]
    );
}

/// The fns of the `App` a handler block calls on its borrow (`app.<fn>(`, not `self.app.` or
/// `x.app.`), without the borrow itself and the outbox's check and drain.
fn logic_calls(block: &str) -> Vec<String> {
    let bytes = block.as_bytes();
    let mut calls = Vec::new();
    for (at, _) in block.match_indices("app.") {
        if at > 0 && (is_ident(bytes[at - 1]) || bytes[at - 1] == b'.') {
            continue;
        }
        let rest = &block[at + "app.".len()..];
        let name: String = rest.chars().take_while(|&c| is_ident_char(c)).collect();
        if name.is_empty() || !rest[name.len()..].starts_with('(') {
            continue;
        }
        if !matches!(
            name.as_str(),
            "try_borrow_mut" | "assert_outbox_empty" | "drain"
        ) {
            calls.push(name);
        }
    }
    calls
}

const fn is_ident_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

/// The entry fns of `files`: their body, whitespace aside, is one call into the logic, then the
/// drain, then (if any) the reply — `{ let reply = self.<fn>(..); self.drain(); reply }` or
/// `{ self.<fn>(..); self.drain(); }` (`on_main`, `secret_entry`, `surface_entry`, `dispatch`).
fn entry_fns(files: &[Src]) -> BTreeSet<String> {
    let mut entries = BTreeSet::new();
    for src in files {
        for (name, block) in fn_blocks(src) {
            let flat = block.split_whitespace().collect::<Vec<_>>().join(" ");
            let shaped = (flat.starts_with("{ let reply = self.")
                && flat.ends_with("); self.drain(); reply }"))
                || (flat.starts_with("{ self.") && flat.ends_with("); self.drain(); }"));
            if shaped && flat.matches(';').count() == 2 {
                entries.insert(name);
            }
        }
    }
    entries
}

/// S9 `every_handler_drains` (critique A-14, 2026-11-20 S4 P10b): every window handler of
/// yw-app (`impl Handler for`) checks that the outbox is empty when its message arrives
/// (`assert_outbox_empty`) and drains before it returns, and so does `main.rs`'s loop observer.
/// 2026-11-20 (S4 P10b review): every arm — each call a handler makes into the logic on its
/// borrow (`app.<fn>(`) is a call of an entry fn that drains itself ([`entry_fns`]: the call,
/// `self.drain();`, the reply). Before, a handler passed when it called any fn whose body
/// drained somewhere, so the main `Forward`'s secret arm (`on_secret`, which does not drain)
/// passed through its main arm's `on_main`; a mutation that removed `Forward`'s own drain after
/// the arms kept every test green. A drain after the calls may stay (a second, empty drain) but
/// covers no call. Finds at least the main and the approval windows' `Forward` and their three
/// entry calls (A-20).
#[test]
fn every_handler_drains() {
    let files: Vec<Src> = production_code()
        .into_iter()
        .filter(|src| in_app_or_wallet(&src.file))
        .collect();
    let entries = entry_fns(&files);
    for entry in ["on_main", "secret_entry", "surface_entry", "dispatch"] {
        assert!(
            entries.contains(entry),
            "{entry} is not an entry that drains"
        );
    }
    let mut handlers = 0;
    let mut entry_calls = BTreeSet::new();
    for src in &files {
        for block in handler_impls(src) {
            handlers += 1;
            assert!(
                block.contains(".assert_outbox_empty()"),
                "{}: a handler that does not check the outbox when a message arrives",
                src.file
            );
            let calls = logic_calls(block);
            assert!(
                !calls.is_empty(),
                "{}: a handler that calls no logic",
                src.file
            );
            for call in calls {
                assert!(
                    entries.contains(&call),
                    "{}: a handler calls `app.{call}(`, which is not an entry that drains itself",
                    src.file
                );
                entry_calls.insert(call);
            }
        }
    }
    assert!(handlers >= 2, "{handlers} handlers found");
    for entry in ["on_main", "secret_entry", "surface_entry"] {
        assert!(entry_calls.contains(entry), "no handler calls {entry}");
    }
    // The made-up handler of a lost drain fails (the secret arm before the P10b review).
    let lost = "fn on(&mut self) -> Reply { let Ok(mut app) = app.try_borrow_mut() else { return \
                Reply::Default; }; app.assert_outbox_empty(); let reply = match self.target { \
                Target::Main => app.on_main(window, msg), Target::Secret(serial) => \
                app.on_secret(serial, window, msg), }; app.drain(); reply }";
    assert_eq!(logic_calls(lost), ["on_main", "on_secret"]);
    assert!(
        !entries.contains("on_secret"),
        "on_secret drains nothing itself"
    );
    let main = src_of(&files, "yw-app/src/main.rs");
    let observer = main
        .code
        .find("observer.try_borrow_mut()")
        .expect("the loop observer");
    let rest = &main.code[observer..];
    let check = rest
        .find("state.assert_outbox_empty();")
        .expect("its check");
    let drain = rest.find("state.drain();").expect("its drain");
    assert!(check < drain, "the observer checks, then drains");
}

/// S10 (critique A-16, 2026-11-20 S4 P10b): the dApp answer, the RPC and the key jobs stay
/// direct sends, never effects — no `Effect` variant names one and the executor sends none — so
/// the outbox cannot reorder them against the logic. A grant check and the answer it guards stay
/// in one fn with no `emit` between them (spec/05 §4.5), and no `emit` comes before a broadcast
/// in its fn (the journal result and its `RpcJob::Broadcast`, spec/03 §4.3).
#[test]
fn answers_and_jobs_are_never_effects() {
    let files = production_code();
    let effect = src_of(&files, "yw-engine/src/effect.rs");
    let start = effect
        .code
        .find("pub enum Effect {")
        .expect("the Effect enum");
    let open = start + "pub enum Effect ".len();
    let variants = &effect.code[open..=close_of(effect.code.as_bytes(), open)];
    // Whole names (`AwaitKeyLock` is the lock's wait for the key worker, not a key job).
    for banned in [
        "Respond",
        "Reply",
        "Rpc",
        "RpcJob",
        "Key",
        "KeyJob",
        "Broadcast",
        "Sign",
    ] {
        assert!(
            !has_word(variants, banned),
            "an Effect variant names {banned}"
        );
    }
    let app = src_of(&files, "yw-app/src/app.rs");
    let approval = src_of(&files, "yw-app/src/app_approval.rs");
    let secret_arm = fn_bodies(app, "apply_secret_effect");
    let approval_arm = fn_bodies(approval, "apply_approval_effect");
    assert_eq!((secret_arm.len(), approval_arm.len()), (1, 1));
    let executor = [
        src_of(&files, "yw-app/src/app_effects.rs").code.as_str(),
        secret_arm[0],
        approval_arm[0],
    ];
    for code in executor {
        for banned in [".respond(", ".rpc(", ".key(", "rpc_tx", "key_queue"] {
            assert!(!code.contains(banned), "the executor sends {banned}");
        }
    }
    let mut guarded = 0;
    let mut broadcasts = 0;
    for src in &files {
        for (name, body) in fn_blocks(src) {
            if let (Some(check), Some(answer)) =
                (body.find("_grant_holds("), body.rfind(".respond("))
                && check < answer
            {
                guarded += 1;
                assert!(
                    !body[check..answer].contains("self.emit("),
                    "{}: fn {name} emits between its grant check and its answer",
                    src.file
                );
            }
            if let Some(at) = body.find("RpcJob::Broadcast") {
                broadcasts += 1;
                assert!(
                    !body[..at].contains("self.emit("),
                    "{}: fn {name} emits before its broadcast",
                    src.file
                );
            }
        }
    }
    assert!(guarded >= 2, "{guarded} grant-checked answers found");
    assert!(broadcasts >= 2, "{broadcasts} broadcasts found");
}

// ---- The wallet/shell split's source check (2026-11-21, S4 W2; plan §3.3–§3.4 D-4) ---------

/// The fns a wallet field may be changed through when called on it.
const MUTATING: [&str; 26] = [
    "as_mut",
    "clear",
    "clone_from",
    "drain",
    "entry",
    "extend",
    "get_mut",
    "get_or_insert",
    "get_or_insert_with",
    "insert",
    "iter_mut",
    "pop",
    "pop_back",
    "pop_front",
    "push",
    "push_back",
    "push_front",
    "remove",
    "replace",
    "retain",
    "set",
    "sort",
    "swap",
    "take",
    "take_if",
    "truncate",
];

/// The calls the executor makes into the wallet, each with its reason (2026-11-21, S4 W2): not
/// followed, and allowed only from the fn named. Nothing else of the executor writes wallet
/// state but the cells of [`EXECUTOR_CELL_WRITES`] (2026-11-21, S4 W2 review).
const EXECUTOR_WALLET_CALLS: [(&str, &str, &str); 3] = [
    (
        "clear_secret_clip",
        "drop_clip_notice",
        "the clip-clear notices (spec/04 §4.8): the fn is shared with the main tick (a shell \
         entry) and `SecretEffect::ClearClip` (the lock's clear); its band changes are the \
         wallet's, made where the clear's result is known",
    ),
    ("clear_secret_clip", "notice", "the same notices"),
    (
        "clear_secret_clip",
        "refresh",
        "the repaint of those notices",
    ),
];

/// The methods an executor fn that takes `&mut self` may call on a wallet field, each with why it
/// only reads (2026-11-21, S4 W2 review: before, the check matched a list of mutating names,
/// [`MUTATING`], so a `&mut self` method of a wallet part — `idle.input`, `wait.screen_changed`,
/// a flow method — went unseen). Any other method called on a wallet field there fails. In a
/// `&self` fn a call through a wallet field can write only through a cell ([`MUTATING`]'s
/// `set`/`replace`/`take`/`swap`, and [`EXECUTOR_CELL_WRITES`]).
const READ_ONLY_CALLS: [(&str, &str); 4] = [
    ("as_ref", "a shared view of an `Option`"),
    ("len", "a length"),
    ("now_ms", "the injected clock (`Clock::now_ms`, `&self`)"),
    (
        "wait_beyond",
        "`Effect::AwaitKeyLock`: the shell waits for the key worker's lock signal \
         (`LockSignal::wait_beyond`, `&self`, a `Mutex`/`Condvar` read)",
    ),
];

/// The wallet cells the executor writes, each as (fn, the cell's receiver, reason) (2026-11-21,
/// S4 W2 review: the check followed only `&mut self` fns, so these `&self` writes of the render
/// builders went unseen and the docs called the clip notices the only exception). Every
/// `borrow_mut()`/`try_borrow_mut()` in an executor fn, on any receiver (a local alias of a
/// wallet field too), must be listed here, and every line here must be found.
const EXECUTOR_CELL_WRITES: [(&str, &str, &str); 2] = [
    (
        "sites_page",
        "browser.site_rows.keys",
        "S13's drawn row → grant map (`BrowserUi.site_rows.keys`), cleared and refilled while \
         `render_main` builds the page; the disconnect presses (`SitesPress`, a `Row`) read it. \
         Not a W2 change (there before S4); it leaves the wallet — shell state, or an answer \
         `Cmd` — before the render builders leave `impl App` (S5, D-21)",
    ),
    (
        "wc_session_cards",
        "self.wc.rows",
        "the drawn `WalletConnect` session row → topic map (`WcUi.rows`), the same way: \
         refilled by the render, read by `WcPress::Disconnect`",
    ),
];

/// The executor fns [`the_executor_writes_no_wallet_state`] must reach (critique A-20). 2026-11-21
/// (S4 W2 review): `items` and the two fns of [`EXECUTOR_CELL_WRITES`], the `&self` render
/// builders, which the check now follows too.
const EXECUTOR_TARGETS: [&str; 24] = [
    "items",
    "sites_page",
    "wc_session_cards",
    "apply",
    "apply_approval_effect",
    "open_approval_window",
    "close_approval_shell",
    "apply_secret_effect",
    "open_input_window",
    "make_display_window",
    "show_display",
    "show_secret",
    "apply_form_op",
    "close_secret_window",
    "clear_secret_clip",
    "clear_secret_clip_at_exit",
    "open_folder",
    "render_main",
    "raise_main",
    "reveal_id",
    "screen_entered",
    "screen_leaving",
    "tab_top",
    "overlay_closed_in_place",
];

/// The wallet's fields: the names declared in `pub struct Wallet { … }` of `app.rs` (2026-11-23,
/// S4d E0b: of its wallet half `app/wallet.rs`; callers pass [`app_and_wallet`]).
fn wallet_fields(app: &Src) -> BTreeSet<String> {
    let start = app.code.find("pub struct Wallet {");
    assert!(start.is_some(), "pub struct Wallet found");
    let open = start.unwrap_or_default() + "pub struct Wallet ".len();
    let body = &app.code[open + 1..close_of(app.code.as_bytes(), open)];
    let mut fields = BTreeSet::new();
    for line in body.lines() {
        let line = line.trim();
        let line = line.strip_prefix("pub(crate) ").unwrap_or(line);
        // 2026-11-23 (S4d E0b): the private fields are `pub(super)` in `app::wallet`.
        let line = line.strip_prefix("pub(super) ").unwrap_or(line);
        // 2026-11-23 (S4d E1): what the shell reads is `pub` in yw-engine.
        let line = line.strip_prefix("pub ").unwrap_or(line);
        if let Some((name, _)) = line.split_once(':')
            && !name.is_empty()
            && name.bytes().all(is_ident)
        {
            fields.insert(name.to_owned());
        }
    }
    fields
}

/// `body` with its whitespace folded, none around a `.` (a chain over several lines reads as
/// one), and `self.wallet.` as `self.`.
fn normalized(body: &str) -> String {
    body.split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .replace(" .", ".")
        .replace(". ", ".")
        .replace("self.wallet.", "self.")
}

/// What in `body` writes a wallet field (one of `fields`), as the `self.` chain found: an
/// assignment to the field or to a part of it, a `&mut` borrow of it, or a call of one of
/// [`MUTATING`] on it (through `self.` or `self.wallet.`).
fn wallet_writes(body: &str, fields: &BTreeSet<String>) -> Vec<String> {
    let text = normalized(body);
    let bytes = text.as_bytes();
    let mut found = Vec::new();
    for (at, _) in text.match_indices("self.") {
        if at > 0 && (is_ident(bytes[at - 1]) || bytes[at - 1] == b'.') {
            continue;
        }
        let mut end = at + "self".len();
        let mut segments = Vec::new();
        while bytes.get(end) == Some(&b'.') {
            let start = end + 1;
            let mut stop = start;
            while stop < bytes.len() && is_ident(bytes[stop]) {
                stop += 1;
            }
            if stop == start {
                break;
            }
            segments.push(&text[start..stop]);
            end = stop;
        }
        if !segments
            .first()
            .is_some_and(|field| fields.contains(*field))
        {
            continue;
        }
        let rest = text[end..].trim_start();
        let assigns = (rest.starts_with('=') && !rest.starts_with("==") && !rest.starts_with("=>"))
            || ["+=", "-=", "*=", "/=", "|=", "&=", "^="]
                .iter()
                .any(|op| rest.starts_with(op));
        let mutating = rest.starts_with('(')
            && segments.len() > 1
            && segments.last().is_some_and(|name| MUTATING.contains(name));
        if text[..at].trim_end().ends_with("&mut") || assigns || mutating {
            found.push(text[at..end].to_owned());
        }
    }
    found
}

/// The method calls in `body` on a wallet field (one of `fields`), as (the `self.` chain, the
/// method): `self.evm.queue.len(` is (`self.evm.queue`, `len`) (2026-11-21, S4 W2 review).
fn wallet_calls(body: &str, fields: &BTreeSet<String>) -> Vec<(String, String)> {
    let text = normalized(body);
    let bytes = text.as_bytes();
    let mut found = Vec::new();
    for (at, _) in text.match_indices("self.") {
        if at > 0 && (is_ident(bytes[at - 1]) || bytes[at - 1] == b'.') {
            continue;
        }
        let mut end = at + "self".len();
        let mut chain_end = end;
        let mut segments = Vec::new();
        while bytes.get(end) == Some(&b'.') {
            let start = end + 1;
            let mut stop = start;
            while stop < bytes.len() && is_ident(bytes[stop]) {
                stop += 1;
            }
            if stop == start {
                break;
            }
            segments.push(&text[start..stop]);
            chain_end = end;
            end = stop;
        }
        if segments.len() > 1
            && fields.contains(segments[0])
            && text[end..].trim_start().starts_with('(')
            && let Some(method) = segments.last()
        {
            found.push((text[at..chain_end].to_owned(), (*method).to_owned()));
        }
    }
    found
}

/// Where `body` takes the whole wallet (2026-11-21, S4 W2 review): `self.wallet` itself (a `&mut`
/// alias, or passed whole), a `Self { … }`/`App { … }` pattern that names `wallet`, `&mut *self`
/// or `deref_mut(`. Each hands out the wallet beyond what [`wallet_writes`] reads.
fn whole_wallet(body: &str) -> Vec<String> {
    let text = normalized(body);
    let bytes = text.as_bytes();
    let mut found = Vec::new();
    for (at, _) in text.match_indices("self.wallet") {
        let end = at + "self.wallet".len();
        if (at == 0 || !(is_ident(bytes[at - 1]) || bytes[at - 1] == b'.'))
            && bytes.get(end).is_none_or(|&b| !is_ident(b) && b != b'.')
        {
            found.push("self.wallet".to_owned());
        }
    }
    for pattern in ["Self {", "App {"] {
        for (at, _) in text.match_indices(pattern) {
            if at > 0 && is_ident(bytes[at - 1]) {
                continue;
            }
            let open = at + pattern.len() - 1;
            let close = close_of(bytes, open);
            if has_word(&text[open..close], "wallet") {
                found.push(format!("{pattern} wallet"));
            }
        }
    }
    for pattern in ["&mut *self", "&mut **self", "deref_mut("] {
        found.extend(text.match_indices(pattern).map(|(_, hit)| hit.to_owned()));
    }
    found
}

/// The receivers of the `borrow_mut()`/`try_borrow_mut()` calls in `body`, as written
/// (2026-11-21, S4 W2 review): `browser.site_rows.keys` for `browser.site_rows.keys.borrow_mut()`.
fn cell_writes(body: &str) -> Vec<String> {
    let text = normalized(body);
    let bytes = text.as_bytes();
    let mut found = Vec::new();
    for call in [".borrow_mut(", ".try_borrow_mut("] {
        for (at, _) in text.match_indices(call) {
            let mut start = at;
            while start > 0 && (is_ident(bytes[start - 1]) || bytes[start - 1] == b'.') {
                start -= 1;
            }
            found.push(text[start..at].to_owned());
        }
    }
    found
}

/// What the executor fn `name` (its `body`, whether it takes `&mut self`) does to the wallet
/// against the rules of [`the_executor_writes_no_wallet_state`]: the findings, and how many of
/// [`EXECUTOR_CELL_WRITES`] it makes (2026-11-21, S4 W2 review).
fn executor_findings(
    name: &str,
    body: &str,
    takes_mut: bool,
    fields: &BTreeSet<String>,
) -> (Vec<String>, usize) {
    let mut findings: Vec<String> = wallet_writes(body, fields)
        .into_iter()
        .map(|chain| format!("writes {chain}"))
        .collect();
    findings.extend(
        whole_wallet(body)
            .into_iter()
            .map(|whole| format!("takes {whole}")),
    );
    if takes_mut {
        for (chain, method) in wallet_calls(body, fields) {
            if !READ_ONLY_CALLS.iter().any(|&(known, _)| known == method) {
                findings.push(format!("calls {chain}.{method}"));
            }
        }
    }
    let mut listed = 0;
    for receiver in cell_writes(body) {
        if EXECUTOR_CELL_WRITES
            .iter()
            .any(|&(from, cell, _)| from == name && cell == receiver)
        {
            listed += 1;
        } else {
            findings.push(format!("borrows {receiver} mutably"));
        }
    }
    (findings, listed)
}

/// The fns of `impl App` blocks in `files` (the type named plain or by path), by name: each
/// body with whether it takes `&mut self`.
fn app_fns(files: &[Src]) -> BTreeMap<String, Vec<(String, String, bool)>> {
    impl_fns(files, "App")
}

/// The fns of the `impl <ty>` blocks in `files` (`App` or `Wallet`, named plain or by its
/// `crate::app::` path), by name: each body with whether it takes `&mut self` (2026-11-21, S4
/// W3: was `app_fns` alone).
fn impl_fns(files: &[Src], ty: &str) -> BTreeMap<String, Vec<(String, String, bool)>> {
    let plain = format!("impl {ty}");
    let pathed = format!("impl crate::app::{ty}");
    let mut fns: BTreeMap<String, Vec<(String, String, bool)>> = BTreeMap::new();
    for src in files {
        let impls: Vec<(usize, usize)> = src
            .blocks
            .iter()
            .filter(|block| {
                let block_head = head(&src.code, block.open)
                    .split_whitespace()
                    .collect::<Vec<_>>()
                    .join(" ");
                block_head == plain || block_head == pathed
            })
            .map(|block| (block.open, block.close))
            .collect();
        for block in &src.blocks {
            if !impls
                .iter()
                .any(|&(open, close)| open < block.open && block.close < close)
            {
                continue;
            }
            let fn_head = head(&src.code, block.open);
            let Some((_, after)) = fn_head.rsplit_once("fn ") else {
                continue;
            };
            if !has_word(fn_head, "fn") {
                continue;
            }
            let name: String = after
                .trim_start()
                .chars()
                .take_while(|&c| c.is_ascii_alphanumeric() || c == '_')
                .collect();
            let takes_mut = fn_head
                .split_whitespace()
                .collect::<String>()
                .contains("&mutself");
            fns.entry(name).or_default().push((
                src.file.clone(),
                src.code[block.open..=block.close].to_owned(),
                takes_mut,
            ));
        }
    }
    fns
}

/// The names of the `App` fns `body` calls on `self` (`self.<fn>(`, through `self.wallet.` too).
fn self_calls(body: &str) -> BTreeSet<String> {
    let text = normalized(body);
    let bytes = text.as_bytes();
    let mut calls = BTreeSet::new();
    for (at, _) in text.match_indices("self.") {
        if at > 0 && (is_ident(bytes[at - 1]) || bytes[at - 1] == b'.') {
            continue;
        }
        let start = at + "self.".len();
        let mut stop = start;
        while stop < bytes.len() && is_ident(bytes[stop]) {
            stop += 1;
        }
        if stop > start && text[stop..].trim_start().starts_with('(') {
            calls.insert(text[start..stop].to_owned());
        }
    }
    calls
}

/// The names of the `App` fns `body` calls (2026-11-21, S4 W7 review): `self.<fn>(` (through
/// `self.wallet.` too, as [`self_calls`]), `Self::<fn>(`, `App::<fn>(` and a closure's or
/// `Forward`'s `app.<fn>(` (through `app.wallet.` too) — the receivers [`calls`] counts
/// ([`DOT_RECEIVERS`], [`PATH_RECEIVERS`]). [`shell_closure`] and [`shell_reach`] follow these;
/// before, they followed `self.<fn>(` only ([`self_calls`]), so a wallet fn that called a shell
/// fn as `Self::drain(self)`, `App::drain(self)` or `run(|app| app.drain())` passed
/// [`wallet_fns_name_no_shell`]. A name another type's path or receiver calls
/// (`Other::drain(`, `self.app.drain(`, `my_app.drain(`) is not counted. 2026-11-22 (S4 W9
/// review): also a call on a name `body` types as an `App` ([`typed_app_names`]: a closure's
/// `|x: &mut Self| x.drain()`, through `x.wallet.` too); before, a closure's parameter counted
/// only when it was named `app`, so that probe in a W9 fn passed.
fn app_calls(body: &str) -> BTreeSet<String> {
    let mut text = normalized(body).replace("app.wallet.", "app.");
    let typed = typed_app_names(&text);
    for name in &typed {
        text = text.replace(&format!("{name}.wallet."), &format!("{name}."));
    }
    let bytes = text.as_bytes();
    let mut calls = BTreeSet::new();
    let receivers = ["self.", "app.", "Self::", "App::"]
        .into_iter()
        .map(str::to_owned)
        .chain(typed.iter().map(|name| format!("{name}.")));
    for receiver in receivers {
        let receiver = receiver.as_str();
        for (at, _) in text.match_indices(receiver) {
            if at > 0 && (is_ident(bytes[at - 1]) || bytes[at - 1] == b'.') {
                continue;
            }
            let start = at + receiver.len();
            let mut stop = start;
            while stop < bytes.len() && is_ident(bytes[stop]) {
                stop += 1;
            }
            if stop > start && text[stop..].trim_start().starts_with('(') {
                calls.insert(text[start..stop].to_owned());
            }
        }
    }
    calls
}

/// The names `text` (a normalized body) binds with an `App` type (2026-11-22, S4 W9 review):
/// `<name>: &Self`, `&mut Self`, `&App` or `&mut App` (also with a lifetime or a path to `App`),
/// as a closure's parameter or a typed `let`. [`app_calls`] counts calls on them. A name bound
/// with no type (`|me| me.drain()`, `let me = &mut *self;`) is not found: it stays unchecked
/// until W14c ([`wallet_fns_name_no_shell`]).
fn typed_app_names(text: &str) -> BTreeSet<String> {
    let bytes = text.as_bytes();
    let mut names = BTreeSet::new();
    for (at, _) in text.match_indices(':') {
        if bytes.get(at + 1) == Some(&b':') || (at > 0 && bytes[at - 1] == b':') {
            continue;
        }
        let Some(mut rest) = text[at + 1..].trim_start().strip_prefix('&') else {
            continue;
        };
        rest = rest.trim_start();
        if let Some(lifetime) = rest.strip_prefix('\'') {
            rest = lifetime.trim_start_matches(|c: char| c.is_ascii_alphanumeric() || c == '_');
            rest = rest.trim_start();
        }
        if let Some(after_mut) = rest.strip_prefix("mut ") {
            rest = after_mut.trim_start();
        }
        let path_len = rest
            .bytes()
            .take_while(|&b| is_ident(b) || b == b':')
            .count();
        let last = rest[..path_len].rsplit("::").next().unwrap_or_default();
        if last != "Self" && last != "App" {
            continue;
        }
        let before = text[..at].trim_end();
        let name_len = before.bytes().rev().take_while(|&b| is_ident(b)).count();
        let name = &before[before.len() - name_len..];
        if !name.is_empty() && name != "self" && name != "app" {
            names.insert(name.to_owned());
        }
    }
    names
}

/// D-4 `the_executor_writes_no_wallet_state` (2026-11-21, S4 W2; plan §3.3–§3.4 D-4, preflight
/// §3 W2, spec/04 §1.3): `App` is the wallet ([`wallet_fields`]: `pub struct Wallet`) plus the
/// shell's fields, and the effect executor — `App::apply` and every fn of `impl App` it reaches
/// through `self.` calls, plus the display window's shell halves `make_display_window` and
/// `show_display` — writes no wallet field ([`wallet_writes`]), takes no whole wallet
/// ([`whole_wallet`]), calls only [`READ_ONLY_CALLS`] on a wallet field where it takes
/// `&mut self` ([`wallet_calls`]), borrows no cell mutably but [`EXECUTOR_CELL_WRITES`]
/// ([`cell_writes`]) and calls into the wallet's `impl App` fns only as
/// [`EXECUTOR_WALLET_CALLS`] lists. So the executor's wallet writes are the clip notices of
/// `clear_secret_clip` and the two drawn-row maps the render builders refill, each listed with
/// its reason. 2026-11-21 (S4 W2 review): before, only `&mut self` fns were followed (the render
/// builders `render_main` reaches were taken to change nothing, and those two cell writes went
/// unseen), and only [`MUTATING`] calls, assignments and `&mut` borrows through `self.` counted
/// (a `&mut self.wallet` alias, a `Self { wallet: … }` pattern or `self.idle.input(..)` passed).
/// What the scanners still miss: a write inside a method of a wallet part's own type (only
/// `impl App` fns are followed) and a cell written through a method other than
/// `borrow_mut`/`try_borrow_mut`/[`MUTATING`]. The plan's `Shell::apply(effect, &Wallet)`
/// cannot be typed while the render builders are `impl App` (D-21, until S5), so this check
/// stands in for it. The one value that moves from the wallet into the shell, a display window's
/// secret, is the composition's: only `display_window_handoff` (called by
/// `open_display_composed`, which only `App::drain` calls) takes or drops it, and the executor
/// reaches none of the three. The scanners are tried on made-up code
/// ([`wallet_writes_and_self_calls_on_made_up_code`]: they can fail) and the
/// check finds its targets (it cannot pass on nothing, critique A-20). 2026-11-22 (S4c
/// W14c-2): the wallet's fns are `impl Wallet` now, so a wallet fn the executor calls is found
/// there: one that takes `&mut self` fails unless [`EXECUTOR_WALLET_CALLS`] lists the call (the
/// list is checked first; before, it only stopped the descent), and a `&self` one (the render
/// helpers that flipped with the wallet fns) is followed and scanned like an `impl App` fn.
#[test]
fn the_executor_writes_no_wallet_state() {
    let files: Vec<Src> = production_code()
        .into_iter()
        .filter(|src| in_app_or_wallet(&src.file))
        .collect();
    let app = &app_and_wallet(&files);
    let fields = wallet_fields(app);
    for field in [
        "mode",
        "evm",
        "form",
        "secret_session",
        "banners",
        "settings",
    ] {
        assert!(fields.contains(field), "wallet field {field} found");
    }
    // 2026-11-21 (S4 W3, plan §3.4): the outbox is the wallet's (before, the shell's).
    assert!(fields.contains("outbox"), "wallet field outbox found");
    for shell in ["controls", "main", "approval_win", "secret", "launcher"] {
        assert!(!fields.contains(shell), "{shell} is the shell's");
    }
    let fns = app_fns(&files);
    // 2026-11-21 (S4 W3): the wallet's own fns (`impl Wallet`: `emit`, `next_effect`, …) that take
    // `&mut self` are never called by the executor (`main_hidden` and other `&self` reads may be).
    let wallet_fns = impl_fns(&files, "Wallet");
    for name in ["emit", "next_effect", "main_hidden"] {
        assert!(
            wallet_fns.contains_key(name),
            "fn {name} of impl Wallet found"
        );
    }
    let wallet_writers: BTreeSet<String> = wallet_fns
        .iter()
        .filter(|(_, bodies)| bodies.iter().any(|(_, _, takes_mut)| *takes_mut))
        .map(|(name, _)| name.clone())
        .collect();
    assert!(wallet_writers.contains("emit") && !wallet_writers.contains("main_hidden"));
    let mut reached = BTreeSet::new();
    let mut cells = 0;
    let mut todo = vec![
        "apply".to_owned(),
        "make_display_window".to_owned(),
        "show_display".to_owned(),
    ];
    while let Some(name) = todo.pop() {
        if !reached.insert(name.clone()) {
            continue;
        }
        // 2026-11-22 (S4c W14c-2): a wallet fn the executor reaches is `impl Wallet` now; the
        // `&self` ones (the render helpers that flipped with the wallet fns) are followed like
        // the `impl App` ones, the `&mut self` ones are refused but the listed calls.
        let bodies = fns.get(&name).or_else(|| wallet_fns.get(&name));
        assert!(
            bodies.is_some(),
            "fn {name} of impl App or impl Wallet found"
        );
        for (file, body, takes_mut) in bodies.into_iter().flatten() {
            let (findings, listed) = executor_findings(&name, body, *takes_mut, &fields);
            assert!(
                findings.is_empty(),
                "{file}: the executor's fn {name} changes wallet state: {findings:?}"
            );
            cells += listed;
            // 2026-11-21 (S4 W2 review): every `impl App` fn called, `&self` ones too (before,
            // only `&mut self` ones, so the render builders' cell writes went unseen).
            for call in self_calls(body) {
                if EXECUTOR_WALLET_CALLS
                    .iter()
                    .any(|&(from, to, _)| from == name && to == call)
                {
                    continue;
                }
                assert!(
                    !wallet_writers.contains(&call),
                    "{file}: the executor's fn {name} calls the wallet's fn {call}"
                );
                if fns.contains_key(&call) || wallet_fns.contains_key(&call) {
                    todo.push(call);
                }
            }
        }
    }
    assert_eq!(
        cells,
        EXECUTOR_CELL_WRITES.len(),
        "every listed cell write found once"
    );
    for composition in [
        "open_display_composed",
        "display_window_handoff",
        "take_display_secret",
        "drop_display_secret",
        "hand_display_secret",
        "on_cmd",
        "emit",
    ] {
        assert!(
            !reached.contains(composition),
            "the executor reaches {composition}"
        );
    }
    for target in EXECUTOR_TARGETS {
        assert!(
            reached.contains(target),
            "the executor's fn {target} reached"
        );
    }
    the_display_secret_moves_only_in_the_composition(&files);
}

/// The scanners of [`the_executor_writes_no_wallet_state`] on made-up code: they can fail.
#[test]
fn wallet_writes_and_self_calls_on_made_up_code() {
    let made_up: BTreeSet<String> = ["form", "evm", "banners"]
        .into_iter()
        .map(str::to_owned)
        .collect();
    assert_eq!(
        wallet_writes(
            "{ self.form.set(a, b); let n = self.evm.queue.len(); \
             self.wallet.banners.push(n); if self.form == x {} let m = &mut self.evm; \
             self.controls.set(1); self.evm.next_shown += 1; self.scroll = 0; \
             self.banners.retain(|b| b.ok); }",
            &made_up,
        ),
        [
            "self.form.set",
            "self.banners.push",
            "self.evm",
            "self.evm.next_shown",
            "self.banners.retain",
        ]
    );
    assert_eq!(
        self_calls("{ self.render_main(); self.wallet.notice(x); self.evm.job(); }"),
        ["notice", "render_main"]
            .into_iter()
            .map(str::to_owned)
            .collect::<BTreeSet<_>>()
    );
    // 2026-11-21 (S4 W2 review): aliases, whole-wallet patterns, any non-read call where the fn
    // takes `&mut self`, and cell borrows (listed or not).
    let fields: BTreeSet<String> = ["copied", "idle", "evm", "wc", "browser", "clock"]
        .into_iter()
        .map(str::to_owned)
        .collect();
    let findings =
        |name: &str, body: &str, takes_mut: bool| executor_findings(name, body, takes_mut, &fields);
    assert_eq!(
        findings(
            "arm",
            "{ let wallet = &mut self.wallet; wallet.copied = None; self.wallet.idle.input(0); }",
            true,
        ),
        (
            vec![
                "takes self.wallet".to_owned(),
                "calls self.idle.input".to_owned()
            ],
            0
        )
    );
    assert_eq!(
        findings(
            "arm",
            "{ let Self { wallet: Wallet { evm, .. }, fonts, .. } = self; evm.queue.clear(); \
             let w = &mut **self; self.deref_mut(); }",
            true,
        ),
        (
            vec![
                "takes Self { wallet".to_owned(),
                "takes &mut **self".to_owned(),
                "takes deref_mut(".to_owned()
            ],
            0
        )
    );
    assert_eq!(
        wallet_calls(
            "{ self.evm.queue.len(); self.wallet.clock.now_ms(); self.controls.set(1); }",
            &fields
        ),
        [
            ("self.evm.queue".to_owned(), "len".to_owned()),
            ("self.clock".to_owned(), "now_ms".to_owned())
        ]
    );
    // Read-only calls pass where the fn takes `&mut self`; any call passes in a `&self` fn,
    // where only a cell can be written.
    let reads = "{ let n = self.evm.queue.len(); let t = self.clock.now_ms(); \
                 let shown = self.evm.approval.as_ref(); self.evm.approval.paint(n); }";
    assert_eq!(
        findings("arm", reads, true),
        (vec!["calls self.evm.approval.paint".to_owned()], 0)
    );
    assert_eq!(findings("arm", reads, false), (Vec::new(), 0));
    let cells = "{ let keys = browser.site_rows.keys.borrow_mut(); \
                 let rows = self.wc.rows.borrow_mut(); }";
    assert_eq!(
        findings("sites_page", cells, false),
        (vec!["borrows self.wc.rows mutably".to_owned()], 1)
    );
    assert_eq!(
        findings("other", cells, false),
        (
            vec![
                "borrows browser.site_rows.keys mutably".to_owned(),
                "borrows self.wc.rows mutably".to_owned()
            ],
            0
        )
    );
    assert_eq!(
        cell_writes("{ x.try_borrow_mut(); self.wc.rows .borrow_mut(); }"),
        ["self.wc.rows", "x"]
    );
}

/// The rest of [`the_executor_writes_no_wallet_state`]: only `display_window_handoff` takes or
/// drops a display secret, and only `App::drain` calls the composition `open_display_composed`.
fn the_display_secret_moves_only_in_the_composition(files: &[Src]) {
    // The secret's move: only the composition takes or drops it.
    // 2026-11-22 (S4c W15): through `self.` or `self.wallet.` ([`normalized`]); the composition
    // names the wallet since non-test builds have no `DerefMut`.
    // 2026-11-23 (S4d E1, preflight O-3): the shell's composition calls the engine's hand-off
    // `hand_display_secret` (a verified window's take, any other's drop), which alone calls the
    // crate-private take and drop (before, the composition called those two itself).
    // 2026-11-23 (S4d E2 review): a call on any receiver counts (a method call `x.call(` or a
    // path call `X::call(`); before, only `self.`/`self.wallet.`, so a call through a local
    // binding (`let w = &mut self.wallet; w.hand_display_secret(..)`) was not seen. The one
    // exception is testkit's test-only shell model, checked below.
    let calls_it = |body: &str, call: &str| {
        body.contains(&format!(".{call}")) || body.contains(&format!("::{call}"))
    };
    let mut handoffs = 0;
    for src in files {
        for (name, body) in fn_blocks(src) {
            let body = normalized(body);
            for call in [
                "take_display_secret(",
                "drop_display_secret(",
                "hand_display_secret(",
            ] {
                if calls_it(&body, call) {
                    handoffs += 1;
                    assert!(
                        (name == "display_window_handoff" && call == "hand_display_secret(")
                            || (name == "hand_display_secret"
                                && (call == "take_display_secret("
                                    || call == "drop_display_secret("))
                            || (name == "drop_display_secret" && call == "take_display_secret("),
                        "{}: fn {name} calls {call}",
                        src.file
                    );
                }
            }
        }
    }
    assert_eq!(
        handoffs, 4,
        "the composition's hand-off, the hand-off's take and drop, and the drop's take"
    );
    // The named exception (2026-11-23, S4d E2 review): `yw_engine::testkit` (test code, not in
    // `files`; `testkit_is_named_only_by_tests` keeps it out of production) calls the hand-off
    // once, in its shell model with `Verified` for a window it made, and wipes the secret at
    // once; and its `WalletTestExt` wraps the crate-private take once for the engine's tests.
    let testkit = normalized(&code_only(
        &std::fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../yw-engine/src/testkit.rs"),
        )
        .unwrap(),
    ));
    let count = |pattern: &str| testkit.matches(pattern).count();
    assert_eq!(
        (
            count(".hand_display_secret("),
            count(".hand_display_secret(serial, DisplayCheck::Verified)"),
            count("::hand_display_secret("),
        ),
        (1, 1, 0),
        "testkit's model: one verified hand-off"
    );
    assert_eq!(
        (
            count(".take_display_secret("),
            count("Self::take_display_secret(self, serial)"),
            count("::take_display_secret("),
        ),
        (0, 1, 1),
        "testkit: the test extension's one wrapper of the take"
    );
    assert_eq!(
        count("drop_display_secret("),
        0,
        "testkit drops no display secret itself"
    );
    let effects = src_of(files, "yw-app/src/app_effects.rs");
    let drain = fn_bodies(effects, "drain");
    assert_eq!(drain.len(), 1, "one drain");
    let drain: String = drain[0].split_whitespace().collect();
    assert!(
        drain.contains("=>Some(self.open_display_composed(")
            && drain.contains("effect=>self.apply(effect),"),
        "the drain hands a display open to the composition: {drain}"
    );
    let callers = files
        .iter()
        .flat_map(|src| {
            fn_blocks(src)
                .into_iter()
                .map(move |(name, body)| (src, name, body))
        })
        .filter(|(_, _, body)| body.contains("self.open_display_composed("))
        .map(|(src, name, _)| format!("{}:{name}", src.file))
        .collect::<Vec<_>>();
    assert_eq!(callers, ["yw-app/src/app_effects.rs:drain"]);
}

// ---- The shell's way into the wallet (2026-11-22, S4c W15; plan §3.3–§3.4, D-21) ---------------

/// The wallet fns that take `&mut self` and that the shell's code (non-test `impl App`) calls,
/// each as (shell fn, wallet fn, reason) (2026-11-22, S4c W15; owner's second batch item 1,
/// critique B-1, B-5): non-test builds have no `App` → `Wallet` `DerefMut`, so every such call
/// names the wallet (`self.wallet.<fn>(`), and
/// [`the_shell_writes_wallet_state_only_through_entries`] allows these and nothing else. They are
/// the wallet's entries: a `Cmd` (`on_cmd`), the outbox (`next_effect`), the typed in-process
/// entries of what may hold a secret (a worker's event, a secret window's action, the display
/// secret's move, the `rpc.json` plan), the shell's compositions around its own waits (lock,
/// shutdown) and the named wallet steps of shell code that S5 turns into `Cmd`s or answers
/// (2026-11-23, S4 end: S4d kept them; was "S4d/S5").
const SHELL_WALLET_CALLS: [(&str, &str, &str); 46] = [
    (
        "dispatch",
        "on_cmd",
        "a `Cmd` from the shell (plan §3.4: `App::dispatch`)",
    ),
    (
        "drain",
        "next_effect",
        "the outbox, one effect at a time (plan §3.4, critic C13)",
    ),
    (
        "drain",
        "on_cmd",
        "an applied effect's answer, and the main-window mirror's `Cmd::MainHidden` (B-10)",
    ),
    (
        "cred_check",
        "take_cred_log",
        "debug builds: the credential edits the logic took, for the shell's comparison (B-11)",
    ),
    (
        "on_main_msg",
        "on_cmd",
        "`Cmd::HoldEnd`, `Cmd::Activate` and `Cmd::Tick` (`ReadsDue`) of the main window's messages",
    ),
    ("on_main_msg", "refresh", "the layout after `WM_SIZE`"),
    (
        "on_main_msg",
        "close_pickers",
        "a click on the window itself closes an open drop-down (2026-11-12)",
    ),
    (
        "hold_down",
        "on_cmd",
        "`Cmd::HoldBegin` (S22's hold area, W1)",
    ),
    (
        "hold_move",
        "on_cmd",
        "`Cmd::HoldEnd` (the pointer left the held area, W1)",
    ),
    (
        "note_input",
        "on_cmd",
        "`Cmd::Input` (the idle clock, spec/04 §5.1)",
    ),
    (
        "escape_key",
        "close_pickers",
        "Esc closes an open drop-down (P4)",
    ),
    ("escape_key", "refresh", "the layout after that"),
    (
        "on_command",
        "close_pickers",
        "a press closes an open drop-down first (2026-11-12)",
    ),
    (
        "on_command",
        "forget_copy_mark",
        "an id that is no press only clears the copy mark (S3 D3)",
    ),
    (
        "on_command",
        "refresh",
        "the layout after a closed drop-down",
    ),
    (
        "show_main",
        "refresh",
        "the first layout of the main window shown",
    ),
    (
        "register_session",
        "error_banner",
        "E-APP-004 after the session registration's last retry (spec/04 §1.4-6)",
    ),
    (
        "set_install_commit",
        "install_commit_read",
        "`main.rs`'s start: the installation record's commit",
    ),
    (
        "note_wer_unprotected",
        "wer_unprotected_noted",
        "`main.rs`'s start: crash reports may be written (review L9)",
    ),
    (
        "start_banner",
        "banner",
        "`main.rs`'s start: refused settings, unreadable `apikeys.dpapi`",
    ),
    (
        "start_fill_template_gaps",
        "fill_template_gaps",
        "`main.rs`'s start: networks added since the addresses were made",
    ),
    (
        "attach_browser",
        "browser_attached",
        "`main.rs`'s start: the dispatcher (the pipe end stays the shell's, W1)",
    ),
    (
        "attach_workers",
        "workers_attached",
        "`main.rs`'s start: the event queue and the RPC sender (the threads are the shell's)",
    ),
    (
        "clear_secret_clip",
        "drop_clip_notice",
        "the clip-clear notices (spec/04 §4.8), where the clipboard answered",
    ),
    ("clear_secret_clip", "notice", "the same notices"),
    (
        "clear_secret_clip",
        "refresh",
        "the repaint of those notices",
    ),
    (
        "clear_earlier_secret_clip",
        "notice",
        "a copy an earlier run left, cleared late",
    ),
    (
        "copy_secret",
        "drop_clip_notice",
        "a new secret copy replaced one whose clear was noticed (spec/04 §4.8)",
    ),
    ("copy_secret", "refresh", "the repaint of that band"),
    (
        "lock",
        "lock_steps",
        "the lock's composition (spec/04 §5.3, W3a): the first half, then the `Suspend` drain",
    ),
    (
        "lock",
        "lock_after_wait",
        "the second half, after the key worker's lock",
    ),
    (
        "shutdown",
        "shutdown_begin",
        "the shutdown's composition (spec/04 §1.5, W3b): the mode and the queue's items",
    ),
    (
        "shutdown",
        "shutdown_steps",
        "after the pipe server: the dispatcher, `WalletConnect`, the wallet's lock",
    ),
    (
        "shutdown",
        "shutdown_after_wait",
        "after the 5 s wait: the workers told to stop",
    ),
    (
        "drain_events",
        "worker_event",
        "a worker's event, typed in-process (a key outcome can hold a secret, plan §7.1)",
    ),
    // 2026-11-23 (S4d E1, preflight O-3): the engine's one hand-off `hand_display_secret` (the
    // take for a verified window, the drop for any other); before, the two calls below.
    (
        "display_window_handoff",
        "hand_display_secret",
        "the display secret moves into a window verified as capture-excluded (D-4, §7.2); any \
         other window result drops (wipes) it",
    ),
    (
        "apply_form_action",
        "on_secret_action",
        "a secret window's action, typed in-process (a submission holds secrets, §7.3)",
    ),
    (
        "run_step",
        "toggle_ai_panel",
        "`Step::AiExpand`: the shown flow's AI panel (no `Cmd::Approval`: see `AnyWindow`)",
    ),
    (
        "run_step",
        "ai_tick",
        "`Step::TimerTail` after the window timer's `Tick` (B6 review: no id check)",
    ),
    (
        "run_step",
        "rebuild_view_with",
        "the same tail: the view while the simulation runs",
    ),
    (
        "paint_ai_body",
        "hold_shown_ai_for_ack",
        "the AI panel's held flag before the AI body paints (spec/06 §3.2; never the gate)",
    ),
    (
        "open_extension_help",
        "set_screen",
        "S23 (B-5: its way back is shell state; a yw-app `Screen` is no `Cmd` data before E0a)",
    ),
    (
        "close_extension_help",
        "return_to",
        "S23's `← 돌아가기` (the same)",
    ),
    (
        "on_ext",
        "emit",
        "`Effect::OpenFolder(Folder::Extension)`, which the shell resolves (P3)",
    ),
    (
        "on_ext",
        "copy_with_band",
        "S23's two copies, the path the shell found (B-5) and the page address",
    ),
    (
        "on_rpc_import",
        "finish_rpc_import",
        "the import's confirmation (B-5: the wallet's half of `rpc.json`, W13)",
    ),
];

/// [`SHELL_WALLET_CALLS`]'s `rpc.json` lines (2026-11-22, S4c W15, critique B-5): the shell's
/// three fns of the import hand the rest to the wallet's typed halves (W13).
const SHELL_WALLET_RPC_CALLS: [(&str, &str, &str); 4] = [
    ("on_rpc_import", "rpc_import_cancel", "the import's `취소`"),
    (
        "on_rpc_import",
        "rpc_json_delete_asked",
        "`rpc.json 지우기…` or its `취소`",
    ),
    (
        "delete_rpc_json",
        "on_rpc_json_deleted",
        "the delete's result, typed in-process",
    ),
    (
        "begin_rpc_import",
        "on_rpc_json_read",
        "the parsed plan, typed in-process (it holds RPC URLs and a token, §7)",
    ),
];

/// The methods the shell may call on a wallet field it names through `self.wallet.` (a read the
/// split borrow needs), each with why it only reads (2026-11-22, S4c W15).
const SHELL_WALLET_READS: [(&str, &str); 3] = [
    ("as_ref", "a shared view of an `Option`"),
    ("is_some", "whether an `Option` holds a value"),
    ("now_ms", "the injected clock (`Clock::now_ms`, `&self`)"),
];

/// The `self.wallet.` chains of `body`, whitespace aside, as (the names after `self.wallet.`,
/// whether a call follows): `self.wallet.on_cmd(x)` is (`["on_cmd"]`, true),
/// `self.wallet.evm.approval.as_ref()` is (`["evm", "approval", "as_ref"]`, true),
/// `self.wallet.evm.next_shown` is (`["evm", "next_shown"]`, false).
fn wallet_chains(body: &str) -> Vec<(Vec<String>, bool)> {
    let text = body
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .replace(" .", ".")
        .replace(". ", ".");
    let bytes = text.as_bytes();
    let mut found = Vec::new();
    for (at, _) in text.match_indices("self.wallet.") {
        if at > 0 && (is_ident(bytes[at - 1]) || bytes[at - 1] == b'.') {
            continue;
        }
        let mut end = at + "self.wallet".len();
        let mut names = Vec::new();
        while bytes.get(end) == Some(&b'.') {
            let start = end + 1;
            let mut stop = start;
            while stop < bytes.len() && is_ident(bytes[stop]) {
                stop += 1;
            }
            if stop == start {
                break;
            }
            names.push(text[start..stop].to_owned());
            end = stop;
        }
        let called = text[end..].trim_start().starts_with('(');
        found.push((names, called));
    }
    found
}

/// `the_shell_writes_wallet_state_only_through_entries` (2026-11-22, S4c W15; plan §3.3–§3.4,
/// D-21, owner's second batch item 1, preflight §0 item 3): non-test builds have no `App` →
/// `Wallet` `DerefMut` (production code has `Deref` only), so the compiler refuses any write of
/// the wallet's state through `App` there; what the compiler allows — naming the wallet
/// (`self.wallet.`) — is checked here. In every non-test `impl App` fn: no wallet field is written
/// ([`wallet_writes`]), the whole wallet is never taken ([`whole_wallet`]), a wallet cell is
/// borrowed mutably only as [`EXECUTOR_CELL_WRITES`] lists, a wallet fn that takes `&mut self`
/// is called only as [`SHELL_WALLET_CALLS`] (and [`SHELL_WALLET_RPC_CALLS`]) list, and a method
/// called on a wallet field named through `self.wallet.` is one of [`SHELL_WALLET_READS`]. Every
/// listed call is found, with its reason (A-20). Before W15, `impl App` code wrote the wallet
/// through `DerefMut` and only the executor was checked
/// ([`the_executor_writes_no_wallet_state`], which stays).
#[test]
fn the_shell_writes_wallet_state_only_through_entries() {
    let files: Vec<Src> = production_code()
        .into_iter()
        .filter(|src| in_app_or_wallet(&src.file))
        .collect();
    let app = &app_and_wallet(&files);
    assert!(
        app.code.contains("impl core::ops::Deref for App {"),
        "App derefs to the wallet"
    );
    assert!(
        !app.code.contains("DerefMut for App"),
        "non-test builds have no App → Wallet DerefMut"
    );
    let fields = wallet_fields(app);
    let shell_fns = app_fns(&files);
    assert!(shell_fns.len() > 300, "{} impl App fns", shell_fns.len());
    let wallet_fns = impl_fns(&files, "Wallet");
    let writers: BTreeSet<&str> = wallet_fns
        .iter()
        .filter(|(_, bodies)| bodies.iter().any(|(_, _, takes_mut)| *takes_mut))
        .map(|(name, _)| name.as_str())
        .collect();
    assert!(writers.contains("on_cmd") && writers.contains("emit"));
    let listed: Vec<(&str, &str, &str)> = SHELL_WALLET_CALLS
        .iter()
        .chain(SHELL_WALLET_RPC_CALLS.iter())
        .copied()
        .collect();
    let mut seen = BTreeSet::new();
    let mut findings = Vec::new();
    for (name, bodies) in &shell_fns {
        for (file, body, _) in bodies {
            findings.extend(
                wallet_writes(body, &fields)
                    .into_iter()
                    .map(|chain| format!("{file}: {name} writes {chain}")),
            );
            // The constructor builds the wallet (`Self { wallet: Wallet { .. }, .. }`).
            if name != "with_clock" {
                findings.extend(
                    whole_wallet(body)
                        .into_iter()
                        .map(|whole| format!("{file}: {name} takes {whole}")),
                );
            }
            for receiver in cell_writes(body) {
                let first = receiver
                    .trim_start_matches("self.wallet.")
                    .trim_start_matches("self.")
                    .split('.')
                    .next()
                    .unwrap_or_default();
                let allowed = EXECUTOR_CELL_WRITES
                    .iter()
                    .any(|&(from, cell, _)| from == name && cell == receiver);
                if fields.contains(first) && !allowed {
                    findings.push(format!("{file}: {name} borrows {receiver} mutably"));
                }
            }
            for (names, called) in wallet_chains(body) {
                match names.as_slice() {
                    [wallet_fn] if called => {
                        if !writers.contains(wallet_fn.as_str()) {
                            continue;
                        }
                        if listed
                            .iter()
                            .any(|&(from, to, _)| from == name && to == wallet_fn)
                        {
                            seen.insert((name.clone(), wallet_fn.clone()));
                        } else {
                            findings.push(format!("{file}: {name} calls the wallet's {wallet_fn}"));
                        }
                    }
                    [_, .., method]
                        if called
                            && !SHELL_WALLET_READS.iter().any(|&(read, _)| read == method) =>
                    {
                        findings.push(format!(
                            "{file}: {name} calls self.wallet.{}",
                            names.join(".")
                        ));
                    }
                    _ => {}
                }
            }
        }
    }
    assert!(findings.is_empty(), "{findings:#?}");
    for (from, to, reason) in &listed {
        assert!(!reason.is_empty(), "{from} → {to}: no reason");
        assert!(
            writers.contains(to),
            "{from} → {to}: not a wallet fn that takes &mut self"
        );
        assert!(
            seen.contains(&((*from).to_owned(), (*to).to_owned())),
            "{from} → {to}: not found"
        );
    }
}

/// The scanner of [`the_shell_writes_wallet_state_only_through_entries`] on made-up code: it can
/// fail (2026-11-22, S4c W15).
#[test]
fn wallet_chains_on_made_up_code() {
    assert_eq!(
        wallet_chains(
            "{ self.wallet.on_cmd(Cmd::Input); let a = self.wallet.evm.next_shown; \
             self.wallet .evm.approval\n.as_ref(); self.wallets.x(); my.self.wallet.y(); \
             self.wallet.idle.input(0); }"
        ),
        [
            (vec!["on_cmd".to_owned()], true),
            (vec!["evm".to_owned(), "next_shown".to_owned()], false),
            (
                vec!["evm".to_owned(), "approval".to_owned(), "as_ref".to_owned()],
                true
            ),
            (vec!["idle".to_owned(), "input".to_owned()], true),
        ]
    );
}

// ---- The wallet fns' source check (2026-11-21, S4 W3; preflight §3.0, critique B-2) ------------

/// The fns that are wallet code but still `impl App` (preflight §3.0: the prep form; W14c makes
/// them `impl Wallet` in place), each with the S4c row that names it. A row's commit removes
/// the last shell reach of its fns and adds them here; [`wallet_fns_name_no_shell`] keeps them
/// that way until the flip. W3 (2026-11-21): the core services and the helpers the families call
/// (critique B-2; preflight §3 W3, incl. `after_settings_saved`, `bind_llm_key_to` and
/// `reconcile_settings`, which `save_settings`, `save_apikeys` and `verify_settings` call).
/// W3a (2026-11-21, critique B-1, preflight §3 W3a): the lock's two wallet halves and the
/// wallet's own lock (`lock` itself is the shell's composition: it drains for `Suspend`), every
/// per-family lock step they call (`sol_dapp_lock` through `sol_lock`) and the secret session's
/// fns (`lock` closes it; W11 opens it).
/// W4 (2026-11-21, preflight §3 W4, critique B-4): the address book (`app_book.rs`, its handler
/// `on_book` and its row presses; `on_book_row`'s offset write is `Effect::ScrollTop` since W4),
/// hidden accounts (`app_hidden.rs` but the render builder `hidden_items`), the token lists
/// (`app_tokens.rs`), the Bitcoin account view (`app_btc_view.rs`, incl. the self-less
/// `btc_source`) and the drop-down handlers of `ui/screens_links.rs` (`close_pickers`,
/// `on_links`; P6 left them there). `ui/screens_book.rs` holds no handler (B-4).
/// W5 (2026-11-21, preflight §3 W5): the AI explanation's settings (`app_llm.rs`: the worker's
/// lifecycle through `Services`, the S15 `AI 설명` handler `on_llm` and its edits, the key, the
/// connection test and its answer `on_llm_test`) and the explorer links (`app_explorer.rs`: the
/// templates, the URL helpers, the S15 card's form, the account cards' and send results' links and
/// the `Cmd::Opened` answer `on_opened`); `Launcher` is the shell's since W1. Neither file had
/// shell reach left (S4b P2 and P3 removed it), so the row only lists its fns.
/// W6 (2026-11-21, preflight §3 W6): the received history (`app_received.rs`: which cards are
/// shown, the list keys, the read jobs, the main-timer part `received_tick`, which reads the
/// wallet's main-window mirror `main_hidden` since W3, the answers and the activity cards' presses;
/// `received_lock` is W3a's) and the side-file choices (`app_sidecar.rs`: the E-VLT-006 overlays'
/// key results and presses and the journal hold of the send forms). The overlays' render
/// builders (`journal_send_items`, `journal_closed_items`, `refusal_items`, `advanced_link`,
/// `meta_overlay`, `journal_overlay`) stay out (D-21; S4d E0c), and with them the free fn
/// `local_time` (`yw_win::time::local_wall_ms`): no wallet fn formats a local time (plan D-30).
/// Neither file had shell reach left, so the row only lists its fns.
/// W7 (2026-11-21, preflight §3 W7): `HyperCore` (`app_hypercore.rs`: the Hyperliquid site facts,
/// the reads and the main-timer part `hc_tick`, which reads the wallet's main-window mirror
/// `main_hidden` since W3, the S-HC form, its review, prepare, consumed handler and signing
/// results) and Zcash (`app_zec.rs`: the tab, the account and its key source, the reads, the
/// review, plan and queue entry, prepare, the consumed handler, the key worker's outcomes — the
/// journal before the broadcast — and the tracking; `zec_lock` is W3a's), with their handlers in
/// `ui/screens_hypercore.rs` (`on_hc`, `on_hc_edit`) and `ui/screens_zec.rs` (`on_zec_edit`,
/// `on_zec`, `on_zec_indexed`). The approval entry they call (`show_next_approval`,
/// `show_ready_draft_at`, `after_pending_open`, `approval_lang`, `show_failure` in
/// `app_approval.rs`) is W14a's, and the render helpers `hc_foldable`, `zec_hw_slots` and
/// `zec_evm_indices` flip at W14c (preflight §3.0). Neither file had shell reach left, so the row
/// only lists its fns. W7 review (2026-11-21): the check follows every call receiver
/// ([`app_calls`]); before, only `self.<fn>(` calls, so "no transitive shell reach" held for those
/// only. `prepare_hypercore`'s `Self::new_approval_id()` (W10's, self-less and pure) is the one
/// `Self::` call of a W7 fn, and no W7 fn calls through a closure's `app.`.
/// W8 (2026-11-21, preflight §3 W8): Solana (`app_sol.rs`: the cluster, endpoint and accounts,
/// the tab, adding, renaming and hiding accounts, the balances and tokens, the main-timer part
/// `sol_balance_tick`, which reads the wallet's main-window mirror `main_hidden` since W3, the
/// send form, its review, prepare, preview, consumed handler, pre-sign check, signing results,
/// tracking and the account scan, incl. the self-less `sol_text`; `app_sol_commands.rs`: the
/// handlers `on_sol_edit`, `on_sol`, `on_sol_indexed` and their helpers; `app_sol_dapp.rs`: the
/// dApp transaction's refusal, prepare, preview, draft, consumed handler, pre-sign check,
/// signing result — the grant re-check before the answer — and broadcast; `sol_lock` and
/// `sol_dapp_lock` are W3a's, the test adapter `on_sol_command` is test code). The approval
/// entry they call (`show_next_approval`, `show_ready_draft`, `show_ready_draft_at`,
/// `approval_lang`, `show_failure` in `app_approval.rs`) is W14a's, the browser and card fns
/// (`respond`, `push_sign_waiter`, `take_sign_waiter`, `card_begin` …) W11's, and the render
/// helpers `sol_activity_tx_ids` and `sol_picker_entries` flip at W14c (preflight §3.0). None of
/// the three files had shell reach left, so the row only lists its fns. `on_sol_previewed` and
/// `sol_dapp_draft` call W10's `Self::new_approval_id()` (self-less and pure); no W8 fn calls
/// through a closure's `app.`.
/// W9 (2026-11-22, preflight §3 W9): Bitcoin (`app_btc.rs`'s `impl App` block: the controller
/// calls `btc_call`, `btc_update`, `btc_call_and_repaint` and the batch `btc_apply`/
/// `btc_apply_rest`, the settings save, the tab, the main-timer part `btc_tick`, the key
/// worker's and the RPC worker's results, the network and indexer settings, discovery, receive
/// and copy, the send and bump forms and their reviews, the signed-transaction choices, prepare,
/// the consumed handler `btc_consumed`, `btc_approval_finished`, the account labels and the
/// controller context `btc_ctx`; `btc_lock` is W3a's, the `BtcUi` controller above the block is
/// no `impl App`; `app_btc_commands.rs`: the form reads and writes, the handlers `on_btc_edit`,
/// `on_btc`, `on_btc_esplora`, `on_btc_indexed`, `on_btc_activity` and their helpers; the test
/// adapter `on_btc_command` is test code). The approval entry they call
/// (`show_next_approval_then`, `show_ready_draft_at`, `after_pending_open`, `approval_lang`,
/// `show_failure` in `app_approval.rs`) is W14a's, the card and site fns (`card_begin`,
/// `btc_selected_card_gate`, `btc_addresses_removed_from_sites`) W11's and the backup gates
/// (`btc_backup_gate`, `mn_send_blocked`, `mn_unconfirmed`, `backup_refused_text`,
/// `mnemonic_tagged`) W12's. Neither file had shell reach left, so the row only lists its fns.
/// `prepare_btc` calls W10's `Self::new_approval_id()` (self-less and pure); no W9 fn calls
/// through a closure's `app.`.
/// W10 (2026-11-22, preflight §3 W10): EVM (`app_evm.rs`'s `impl App` block: the active chain
/// and its job, the account choice and the own accounts, the known addresses and token lists,
/// the unlock part `evm_after_unlock`, the key worker's outcomes with the signing result
/// `on_signed` — the result to `browser_tx_signed` (W11's), then the broadcast job; on `Ok` that
/// call only files the site's waiter under the tx hash, and the grant re-check and the answer
/// are `browser_broadcast`'s when the broadcast result arrives (2026-11-22 W10 review: the
/// goldens pin that `on_signed` still makes the call, not its order within the entry, which no
/// answer can observe) — and the signing slots, the RPC worker's events, the balances, the
/// chain check, the tracking and the broadcast result `on_broadcast`, the main-timer parts
/// `evm_tick`, `evm_tick_rest` and `evm_balance_tick`, which reads the wallet's main-window mirror
/// `main_hidden` since W3, the send timer, the send form, its quote and review, replace, resend
/// and discard, the copy helpers and their answer `copy_done`, the token lookup, the chain form,
/// its probe, delete and re-pin, the fee caps, the text helpers and the self-less
/// `new_approval_id`; `rpc` is W3's, `evm_lock` W3a's, and the approval queue entry
/// `enqueue_app` and `approval_finished` W14a's; `app_evm_commands.rs`: the form reads, the
/// handlers `on_evm_edit`, `on_evm`, `on_evm_indexed` and their helpers, and the self-less
/// `record_hash`). The approval entry they call (`enqueue_app`, `after_pending_open`,
/// `on_simulating`, `on_typed_facts`, `on_prepared`, `on_resimulated`, `tick_approval`) is
/// W14a's, the browser and card fns (`browser_tx_signed`, `browser_broadcast`,
/// `browser_sign_cancelled`, `browser_tick`, `chain_removed_from_sites`, `reset_read_chain`,
/// `evm_selected_card_gate`) W11's, the phrase fns (`evm_selected_gate`, `mn_send_blocked`,
/// `evm_account_unconfirmed`, `backup_refused_text`, `mnemonic_account`, `mnemonic_named`,
/// `mnemonic_source`) W12's, and the render helpers `activity_rows` (`RENDER_LOCAL_TIME`, gone
/// 2026-11-22 S4d E0c) and
/// `picker_entries` flip at W14c (preflight §3.0). Neither file had shell reach left, so the row
/// only lists its fns. `on_send_timer`'s closure `|app: &Self|` reads a wallet field only (no
/// call); no other W10 fn takes an `App` in a closure or calls through an `App::`/`Self::` path.
/// W11 (2026-11-22, preflight §3 W11, critique B-4): the dApp sites, the browser core, the
/// grants, the waiters and the card step (`app_chain_sites.rs`: the Solana and Bitcoin sites'
/// rows, connect choices, preflight, sign drafts, the waiter `chain_waiter`, the grant re-checks
/// `sol_grant_holds`/`btc_grant_holds`/`chain_grant_holds` and the answer
/// `browser_chain_message_signed`, the removals and `disconnect_chain_site`; `app_browser.rs`:
/// the grant writes `write_grants`/`flush_grant_writes`, the main-timer part `browser_tick`, the
/// unlock parts, the dApp event `on_dapp_event` and its answer `respond`, the grants, the
/// refusals, the site request and its unlock window `open_unlock_for_dapp` (the secret seam, W3a's
/// `open_input*`), cancel, preflight, revoke and disconnect, the account, key and chain
/// removals, the connect result, the sign waiters and their grant re-checks `evm_grant_holds`/
/// `waiter_grant_holds` before the answers `browser_tx_signed`, `browser_message_signed`,
/// `browser_sign_cancelled` and `browser_broadcast` (spec/05 §4.5), `network_url_changed`,
/// `reset_read_chain` and `waiting_origins`; `vault_view`, `wallet_view` and `sync_browser` are
/// W3's, `browser_lock_begin` W3a's; the pipe server is the shell's `PipeHost` since W1;
/// `app_card.rs`: the card names, enrolment, the card step `card_begin` with its gates, PIN window
/// `card_open_pin`, submit, cancel, `card_site_gone`/`card_site_check`, the step's form lines and
/// notices, its release and outcome filter and the main-timer part `card_tick`; `card_lock` is
/// W3a's; `ui/screens_sites.rs`: the S13 handler `on_sites`). The render builders stay out (D-21;
/// S4d E0c): `card_pin_banner` (its callers are the screens' render code) and S13's
/// `sites_page`, `sites_screen`, `chain_site_cards` and `unlock_pending_text`; `Page::button`
/// (B-4's `button`) is no `impl App` fn, and the test adapters `browser_view_current` and
/// `on_sites_command` are test code. The approval entry they call (`show_next_approval`,
/// `show_next_approval_then`, `after_pending_open`, `approval_lang`, `close_approval_window` in
/// `app_approval.rs`, `approval_finished` in `app_evm.rs`) is W14a's, the phrase and `YubiKey` fns
/// (`btc_source_unconfirmed`, `evm_account_unconfirmed`, `sol_source_unconfirmed`,
/// `refuse_unconfirmed`, `mn_connect_tag`, `mnemonic_named`, `yk_enrolled`) W12's and the
/// `WalletConnect` fns (`origin_display`, `site_origin_text`, `wc_after_unlock`,
/// `wc_disconnect_all`, `wc_grants_changed`) W13's. None of the four files had shell reach left,
/// so the row only lists its fns. The self-less `chain_waiter`, `passphrase_refusal`,
/// `card_role`, `card_outcome_ticket` and `card_outcome_matches` are called as `Self::<fn>(`
/// (W14c-2 rewrites those paths, critic C10); no W11 fn takes an `App` in a closure.
/// 2026-11-22 (S4 W11): a `static`, not a `const` (before, `const`): at 617 entries the table
/// passes clippy's `large_const_arrays` size (16 KiB), and a `static` is one copy, not one per use.
/// W12 (2026-11-22, preflight §3 W12, critic C12): imported keys, recovery phrases and the
/// `YubiKey` purposes (`app_keys.rs`: the imported keys, the key start, reveal and removal and
/// the S-keys handler `on_keys`; `app_mnemonics.rs`: the phrases' names and accounts, the backup
/// gates, the S-mnemonics handlers `on_mn`/`on_mn_edit`, the phrase windows' submit, cancel and
/// hold `mn_submit`/`mn_cancel`/`mn_hold_complete` and the key worker's outcomes;
/// `app_yubikey.rs`, `app_yubikey/connect.rs`, `app_yubikey/manage.rs`: the wizard, its PIN,
/// counter and card-secret windows, the connect and manage flows, their handlers and outcomes;
/// `yk_words_dropped` is W3a's, the test adapter `on_keys_command` is test code) and, in
/// `app.rs`, the secret windows' purposes: `on_submit`, `preview_import`, `on_cancel`,
/// `challenge_id` and the wallet's half of the secret form's actions, `on_secret_action` (the
/// typed in-process entry `SecretAction`, plan §3.6), with its read `secret_session_is`. The
/// shell's `apply_form_action` keeps the window's own arms (repaint, paste, copy) and calls it;
/// before W12 that one fn held both halves (critic C12). The phrase banners' render builders
/// `mn_receive_banner`, `mn_signing_banner` and `mn_backup_now` stay out (D-21; S4d E0c). The
/// approval entry they call (`approval_lang`) is W14a's, the `WalletConnect` fn `origin_display`
/// W13's, and the render helpers `{evm,sol,btc,zec}_removed` (`ui/removed.rs`) flip at W14c.
/// W3b (2026-11-22, preflight §3 W3b, critique B-3, critic C11; after W12 as C2.2 orders it):
/// the core screens, the key results, the settings and the RPC rows of `app.rs` — the key
/// worker's results `key_result` (the entry `on_key_result`, which drains, stays the shell's),
/// the vault status `on_status`, `reload_after_failed_start`, the RPC test answer
/// `on_rpc_event`, the core screens' handler `on_core` and its rows `on_core_row`, the RPC rows
/// and templates (`delete_rpc_url`, `save_template_credentials` … `test_network`,
/// `open_rpc_row`), the account choice, rename, hiding and auto-lock saves, the `완료` screens
/// (`clear_done`, `done_connect*`), `close_overlay_in_place`, `confirm_yes`, the settings
/// file's accept and restore, the receive refusal `refuse_receive`, the early reads `reads_due`
/// and the idle part `idle_tick` with `idle_window`, `first_run_pending` and
/// `discard_first_run`. Two had shell reach, removed here: `idle_window` read the shell's
/// secret window record (`App::secret`) and now reads the wallet's secret session (its kind,
/// serial and shown flag); `on_core`'s `종료` arm called the shell's composition `shutdown`,
/// which is now split like the lock (owner's second batch item 1): the wallet's halves
/// `shutdown_begin`, `shutdown_steps` (the wallet's own lock for `Shutdown`, a `WalletLock`,
/// which has no `Suspend`) and `shutdown_after_wait`, listed here, and the shell's `App::shutdown`,
/// which `on_command` runs right after the press ([`the_shutdown_composition_runs_from_the_shell`]).
/// `after_settings_saved`, `bind_llm_key_to` and `reconcile_settings` are W3's (preflight §3
/// W3). The approval entry they call (`show_next_approval`, `after_pending_open`, …) is W14a's
/// and the reset and `WalletConnect` fns (`on_wallet_reset`, `reset_absorbs_load`,
/// `wc_disconnect_all`, …) W13's.
/// W13 (2026-11-22, preflight §3 W13, critique B-4, B-5): the reset and `WalletConnect`
/// (`app_reset.rs`'s `impl App` block: the timed waits `needs_accounts`, `wait_tick`,
/// `wait_retry`, `sends_in_flight`, S22's open, cancel, phrase and state replacement, the reset
/// `reset_execute` (the lock first, the file moves on the key worker) and its result
/// `on_wallet_reset`, `reset_absorbs_load`, the hold's wallet halves `reset_hold_begin` and
/// `reset_hold_tick`, the handlers `on_reset`/`on_reset_edit` and their helpers; `request_meta`
/// is W3's, `hold_cancel` W3a's, the hold area's hit test and capture the shell's since W1;
/// `app_walletconnect.rs`'s two `impl App` blocks: the session origins and the approval
/// window's decoration `wc_peer_of` … `wc_connect_patch`, the worker's lifetime through
/// `Services` (`wc_start` … `wc_shutdown`), its events `on_wc_event`, the session store, the
/// grant pruning, pairing and the QR inputs the shell read with the press, the project id and
/// the disconnects; `ui/screens_walletconnect.rs`: the panel's handlers `on_wc` and
/// `on_wc_edit`, B-4) and the wallet's halves of the `rpc.json` import (critique B-5: the
/// shell's press handler `on_rpc_import` and `begin_rpc_import`/`delete_rpc_json` find, read
/// and delete the file, O-13; the parsed plan enters through the typed in-process entry
/// `on_rpc_json_read`, never a `Cmd`, and waits in the wallet for `finish_rpc_import`, which
/// applies it, saves, fills the template's gaps and queues the tests; `rpc_import_cancel`,
/// `rpc_json_delete_asked`, `on_rpc_json_deleted` and the band helper `push_rejected`; before
/// W13 those writes were in the shell's fns, [`the_rpc_import_plan_enters_the_wallet_typed`]).
/// The render builders stay out (D-21; S4d E0c): the panel's `wc_panel`, `wc_setup_card`,
/// `wc_project_row`, `wc_session_cards` and the import card `rpc_import_section`; the test
/// adapter `on_rpc_import_command` is test code. The approval entry they call
/// (`approval_finished` in `app_evm.rs`, `approval_lang` in `app_approval.rs`) is W14a's. None
/// of the files had other shell reach left, so the row lists its fns; no W13 fn is self-less
/// or takes an `App` in a closure.
/// W14a (2026-11-22, preflight §3 W14a, critic C5; owner's second batch: the approval code
/// stays in `app_approval.rs`, no `wallet_approval.rs`): the approval queue, prepare and results
/// (`app_approval.rs`: the queue entry `show_next_approval*` and the steps kept for an open
/// `run_after_open` … `approval_open_answered`, the connect state, the open `open_approval` and
/// its answer `on_approval_opened`, `approval_open_failed`, the preparation `start_prepare`,
/// `prepare_transaction`, `prepare_site`, the message chain and language helpers, the results
/// `on_typed_facts`, `on_simulating`, `on_prepared`, `on_resimulated`, the drafts
/// `show_ready_draft*`, the failure `show_failure`, the end `close_approval_window`/
/// `finish_approval`, `shown_now`, the main-timer part `tick_approval` and the view
/// `rebuild_view*`; `app_evm.rs`: the app send's queue entry `enqueue_app` and
/// `approval_finished`) and the AI explanation's flow, which the preflight left unplaced
/// (`llm_busy`, `ai_after`, `ai_ready*`, `ai_tick`, `ai_retry`, `on_llm_done`). Their last shell
/// reach is removed here: `ai_after` invalidated the AI body and A01 and `ai_tick` the AI body
/// (`approval_win`); both now emit `Effect::Approval(ApprovalEffect::RepaintAi)` (standing
/// decision, spec/15 §18 23). The test builds' pairing check `assert_flow_and_window_in_step`
/// (the shell's) is no longer called by `on_approval_opened` and `close_approval_window` (critic
/// C5; `App::drain` checks it; [`wallet_fns_name_no_shell_in_test_builds`]). The shell's fns of
/// the file stay out: the executor arm `apply_approval_effect` and its window fns, the window
/// procedures, `run_steps`/`run_step`, the paint fns, `ai_scroll_by` and the tests' entries. The
/// approval entry's W14b half (`approved`, `start_resimulation`, `consume_and_sign`,
/// `dispatch_evm_sign`, `on_approval_input`, `approval_event`, `retry_action`) is W14b's.
/// `prepare_transaction`, `prepare_site` and `on_typed_facts` call W10's self-less
/// `new_approval_id` as `Self::new_approval_id()` (W14c-2 rewrites those paths, critic C10); no
/// W14a fn takes an `App` in a closure.
/// W14b (2026-11-22, preflight §3 W14b, critic C5; in place, no `wallet_approval.rs`): approve,
/// re-simulation and consume (`app_approval.rs`: `approved` — the L4(c) chain check, then the
/// fresh-simulation decision —, `start_resimulation`, `consume_and_sign`, the only production
/// `.consume(` ([`the_only_consume_is_wallet_code`]), `dispatch_evm_sign`, the flow's input
/// handler `on_approval_input` and `approval_event`, and `retry_action`, which the preflight
/// left unplaced). Their last shell reach is removed here: `on_approval_input` called the test
/// builds' pairing check `assert_flow_and_window_in_step` first (critic C5); the shell's senders
/// `window_event`/`window_signal` make it right before they send the input. The window's
/// sampling, mapping and sending stay the shell's (`window_event`, `window_signal`, `run_step`).
/// The card, waiter and grant fns they call (`card_begin`, `push_sign_waiter`, …) are W11's, the
/// consumed handlers (`sol_consumed`, `btc_consumed`, `zec_consumed`, `hc_consumed`,
/// `sol_dapp_consumed`) W7's–W9's and the AI flow (`ai_retry`) W14a's. `consume_and_sign` calls
/// W11's self-less `chain_waiter` as `Self::chain_waiter(` (W14c-2, critic C10); no W14b fn
/// takes an `App` in a closure.
/// W14c (2026-11-22, preflight §3 W14c, critic C10, C16; owner's second batch item 1): the flip.
/// W14c-1 re-blocked the `impl App` blocks so that every run of listed fns is a block of its own;
/// W14c-2 made those blocks `impl Wallet` in place (no fn changed file), so every fn listed here
/// is now `impl Wallet` and [`wallet_fns_name_no_shell`] finds them there. The row adds the
/// `impl App` render helpers the listed fns call, which flip with them (preflight §3.0, plus
/// what that list missed): `account_label`, `activity_rows`, `meta_activity_row`,
/// `record_status`, `evm_pref_title`, `network_label`, `evm_last_balance`, `evm_removed`,
/// `picker_entries`, `picker_known`, `card_source`, `sol_activity_counterparties`,
/// `sol_activity_tx_ids`, `sol_picker_entries`, `sol_last_balance`, `sol_removed`,
/// `btc_last_balance`, `btc_removed`, `zec_activity_recipients` (called across a line break, so
/// W14c-1's call scan missed it and W14c-2 gave it its block), `zec_evm_indices`,
/// `zec_hw_slots`, `zec_last_balance`, `zec_removed` and `hc_foldable`. `activity_rows` and
/// `meta_activity_row` still format a local time through `format_local`
/// (`RENDER_LOCAL_TIME`, plan D-30: S5's; 2026-11-22 S4d E0c: no longer, see below).
/// W15 (2026-11-22, plan §5 W15 as the owner's second batch amends it, critique B-1, B-5): the
/// wallet's `on_cmd` and its routers (`on_press`, `on_family`, `on_field_edit`; before, `impl
/// App`), the plain-data entries it now takes (`activate` for `Cmd::Activate`, `timer_part` for
/// `Cmd::Tick`), the worker events' typed entry `worker_event` (was the `match` of
/// `App::drain_events`), and the wallet halves the shell's former writes became:
/// `on_folder_missing` (`Cmd::FolderMissing`), `drop_clip_notice`, `forget_copy_mark`,
/// `toggle_ai_panel` (`Step::AiExpand`), `hold_shown_ai_for_ack` (the AI body's paint) and the
/// start steps `install_commit_read`, `wer_unprotected_noted`, `browser_attached`,
/// `workers_attached`. Each is called from the shell only as [`SHELL_WALLET_CALLS`] lists.
static WALLET_FNS: [(&str, &str); 989] = [
    ("W3", "key"),
    ("W3", "set_mode"),
    ("W3", "passphrase_unverified"),
    ("W3", "set_screen"),
    ("W3", "return_to"),
    ("W3", "remembered_place"),
    ("W3", "enter_screen"),
    ("W3", "refresh"),
    ("W3", "banner"),
    ("W3", "notice"),
    ("W3", "error_banner"),
    ("W3", "clock"),
    ("W3", "secret_purpose"),
    ("W3", "secret_form"),
    ("W3", "secret_open"),
    ("W3", "recovered_text"),
    ("W3", "recovery_failure"),
    ("W3", "password_failure"),
    ("W3", "save_meta"),
    ("W3", "save_settings"),
    ("W3", "after_settings_saved"),
    ("W3", "save_apikeys"),
    ("W3", "bind_llm_key_to"),
    ("W3", "verify_settings"),
    ("W3", "reconcile_settings"),
    ("W3", "url_networks"),
    ("W3", "network_name"),
    ("W3", "account_rows"),
    ("W3", "form_text"),
    ("W3", "form_text_wiping"),
    ("W3", "take_cred"),
    ("W3", "read_cred"),
    ("W3", "template_key"),
    ("W3", "template_stored"),
    ("W3", "template_addresses"),
    ("W3", "generation_plan"),
    ("W3", "fill_template_gaps"),
    ("W3", "set_rpc_message"),
    ("W3", "queue_rpc_tests"),
    ("W3", "next_rpc_test"),
    ("W3", "rpc"),
    ("W3", "request_meta"),
    ("W3", "vault_view"),
    ("W3", "wallet_view"),
    ("W3", "sync_browser"),
    ("W3a", "lock_steps"),
    ("W3a", "lock_after_wait"),
    ("W3a", "lock_wallet"),
    ("W3a", "browser_lock_begin"),
    ("W3a", "card_lock"),
    ("W3a", "close_secret"),
    ("W3a", "evm_lock"),
    ("W3a", "sol_lock"),
    ("W3a", "sol_dapp_lock"),
    ("W3a", "btc_lock"),
    ("W3a", "zec_lock"),
    ("W3a", "received_lock"),
    ("W3a", "hold_cancel"),
    ("W3a", "yk_words_dropped"),
    ("W3a", "begin_secret"),
    ("W3a", "open_input"),
    ("W3a", "open_input_then"),
    ("W3a", "open_input_with"),
    ("W3a", "on_secret_opened"),
    ("W3a", "open_display"),
    ("W3a", "open_display_then"),
    ("W3a", "open_display_with"),
    ("W3a", "take_display_secret"),
    ("W3a", "drop_display_secret"),
    ("W4", "book_look_alike"),
    ("W4", "send_look_alike"),
    ("W4", "book_rows"),
    ("W4", "target_contacts"),
    ("W4", "favorite_contacts"),
    ("W4", "in_book"),
    ("W4", "send_target"),
    ("W4", "send_recipient"),
    ("W4", "result_recipient"),
    ("W4", "fill_recipient"),
    ("W4", "open_save_prompt"),
    ("W4", "save_prompt"),
    ("W4", "save_book_form"),
    ("W4", "toggle_favorite"),
    ("W4", "delete_book_entry"),
    ("W4", "activity_counterparty"),
    ("W4", "save_activity_address"),
    ("W4", "on_book_edit"),
    ("W4", "on_book"),
    ("W4", "book_chip"),
    ("W4", "book_btc_pick"),
    ("W4", "on_book_row"),
    ("W4", "book_copy"),
    ("W4", "btc_picker_entries"),
    ("W4", "hidden_rows"),
    ("W4", "on_hidden"),
    ("W4", "unhide"),
    ("W4", "evm_token_hidden"),
    ("W4", "evm_hide_zero"),
    ("W4", "evm_token_rows"),
    ("W4", "toggle_evm_token_hidden"),
    ("W4", "set_evm_hide_zero"),
    ("W4", "request_delete_token"),
    ("W4", "token_delete_target"),
    ("W4", "delete_token"),
    ("W4", "token_delete_target_of"),
    ("W4", "sol_token_network"),
    ("W4", "sol_token_hidden"),
    ("W4", "toggle_sol_token_hidden"),
    ("W4", "btc_label_of"),
    ("W4", "btc_is_hidden"),
    ("W4", "btc_source"),
    ("W4", "btc_source_text"),
    ("W4", "btc_visible_rows"),
    ("W4", "btc_hidden_balance"),
    ("W4", "btc_can_hide"),
    ("W4", "btc_rename_start"),
    ("W4", "btc_rename_cancel"),
    ("W4", "btc_save_rename"),
    ("W4", "btc_hide_selected"),
    ("W4", "close_pickers"),
    ("W4", "on_links"),
    ("W5", "llm_reconfigure"),
    ("W5", "llm_shutdown"),
    ("W5", "open_llm_settings"),
    ("W5", "on_llm_edit"),
    ("W5", "llm_message"),
    ("W5", "llm_delete_key"),
    ("W5", "llm_preset"),
    ("W5", "llm_set_effort"),
    ("W5", "on_llm"),
    ("W5", "llm_toggle"),
    ("W5", "llm_key_withheld"),
    ("W5", "llm_confirm_on"),
    ("W5", "llm_save"),
    ("W5", "llm_save_key"),
    ("W5", "llm_store_key"),
    ("W5", "llm_test"),
    ("W5", "on_llm_test"),
    ("W5", "events_queue"),
    ("W5", "llm_running"),
    ("W5", "user_chain_explorer"),
    ("W5", "explorer_default_templates"),
    ("W5", "explorer_override"),
    ("W5", "explorer_templates"),
    ("W5", "explorer_url"),
    ("W5", "explorer_tx_url"),
    ("W5", "explorer_address_url"),
    ("W5", "open_explorer_tx"),
    ("W5", "open_explorer_address"),
    ("W5", "copy_explorer_tx"),
    ("W5", "open_explorer"),
    ("W5", "on_opened"),
    ("W5", "explorer_networks"),
    ("W5", "explorer_net_name"),
    ("W5", "on_explorer_edit"),
    ("W5", "explorer_start_edit"),
    ("W5", "explorer_cancel_edit"),
    ("W5", "explorer_store"),
    ("W5", "explorer_save_edit"),
    ("W5", "explorer_reset"),
    ("W5", "explorer_card"),
    ("W5", "explorer_result"),
    ("W5", "explorer_activity"),
    ("W5", "on_explorer"),
    ("W5", "explorer_activity_link"),
    ("W6", "received_shown"),
    ("W6", "received_explorer_net"),
    ("W6", "received_key"),
    ("W6", "received_tokens"),
    ("W6", "received_kind"),
    ("W6", "received_pending"),
    ("W6", "received_list"),
    ("W6", "received_pending_sum"),
    ("W6", "received_start"),
    ("W6", "received_tick"),
    ("W6", "received_now"),
    ("W6", "received_event"),
    ("W6", "on_received"),
    ("W6", "meta_unreadable"),
    ("W6", "journal_unreadable"),
    ("W6", "choose_sidecar"),
    ("W6", "journal_choice_closed"),
    ("W6", "on_sidecar_resolved"),
    ("W6", "on_sidecar"),
    ("W6", "reset_elapsed"),
    ("W6", "journal_hold"),
    ("W7", "hl_site_facts"),
    ("W7", "hl_l1_origin"),
    ("W7", "hc_network"),
    ("W7", "hc_endpoint"),
    ("W7", "hc_visible"),
    ("W7", "hc_refresh"),
    ("W7", "hc_tick"),
    ("W7", "hc_rpc_event"),
    ("W7", "hc_set_status"),
    ("W7", "hc_open_form"),
    ("W7", "hc_evm_tokens"),
    ("W7", "hc_spot_rows"),
    ("W7", "hc_balances"),
    ("W7", "hc_available"),
    ("W7", "hc_form_available"),
    ("W7", "hc_fill_max"),
    ("W7", "hc_build"),
    ("W7", "hc_validate"),
    ("W7", "hc_toggle_ack"),
    ("W7", "hc_can_review"),
    ("W7", "hc_review"),
    ("W7", "prepare_hypercore"),
    ("W7", "hc_consumed"),
    ("W7", "hc_message_signed"),
    ("W7", "hc_sign_cancelled"),
    ("W7", "hc_approval_finished"),
    ("W7", "hc_open_from_evm"),
    ("W7", "hc_system_recipient_error"),
    ("W7", "zec_tab_active"),
    ("W7", "zec_select_tab"),
    ("W7", "zec_network"),
    ("W7", "zec_account"),
    ("W7", "zec_records"),
    ("W7", "zec_known"),
    ("W7", "zec_check_recipient"),
    ("W7", "zec_journal_damaged"),
    ("W7", "zec_url"),
    ("W7", "zec_ensure_account"),
    ("W7", "zec_apply_source"),
    ("W7", "zec_hw_state"),
    ("W7", "zec_card_records_changed"),
    ("W7", "zec_accounts_using_card"),
    ("W7", "zec_all_terminal"),
    ("W7", "zec_source_in_use"),
    ("W7", "zec_use_hardware"),
    ("W7", "zec_imported_keys"),
    ("W7", "zec_selected_imported"),
    ("W7", "zec_use_mnemonic"),
    ("W7", "zec_source_label"),
    ("W7", "zec_use_imported"),
    ("W7", "zec_imported"),
    ("W7", "zec_remove_block"),
    ("W7", "zec_imported_removed"),
    ("W7", "zec_set_account"),
    ("W7", "zec_enable"),
    ("W7", "zec_disable"),
    ("W7", "zec_set_indexer"),
    ("W7", "zec_refresh"),
    ("W7", "zec_tick"),
    ("W7", "zec_backup_gate"),
    ("W7", "zec_review"),
    ("W7", "zec_plan"),
    ("W7", "zec_enqueue"),
    ("W7", "prepare_zec"),
    ("W7", "zec_consumed"),
    ("W7", "zec_approval_finished"),
    ("W7", "zec_card_cancelled"),
    ("W7", "zec_key_outcome"),
    ("W7", "zec_send"),
    ("W7", "zec_resend_due"),
    ("W7", "zec_journal"),
    ("W7", "zec_rpc_event"),
    ("W7", "zec_track"),
    ("W7", "on_hc"),
    ("W7", "on_hc_edit"),
    ("W7", "on_zec_edit"),
    ("W7", "on_zec"),
    ("W7", "on_zec_indexed"),
    ("W8", "sol_cluster"),
    ("W8", "sol_endpoint"),
    ("W8", "sol_account_rows"),
    ("W8", "sol_selected"),
    ("W8", "sol_records"),
    ("W8", "sol_journal_damaged"),
    ("W8", "sol_pending"),
    ("W8", "sol_label"),
    ("W8", "sol_title"),
    ("W8", "sol_known"),
    ("W8", "sol_select_tab"),
    ("W8", "sol_ensure_account"),
    ("W8", "sol_add_account_clicked"),
    ("W8", "sol_add_account_of"),
    ("W8", "sol_add_account"),
    ("W8", "sol_select_account"),
    ("W8", "sol_save_rename"),
    ("W8", "sol_hide_selected"),
    ("W8", "sol_mnemonic_account_added"),
    ("W8", "on_sol_keys"),
    ("W8", "sol_refresh_balances"),
    ("W8", "sol_balance"),
    ("W8", "sol_token_holdings"),
    ("W8", "sol_token_holding"),
    ("W8", "sol_assets"),
    ("W8", "sol_select_asset"),
    ("W8", "sol_rpc_event"),
    ("W8", "sol_tick"),
    ("W8", "sol_balance_tick"),
    ("W8", "sol_open_send"),
    ("W8", "sol_can_resend"),
    ("W8", "sol_send_again"),
    ("W8", "sol_form_sender"),
    ("W8", "sol_validate_send"),
    ("W8", "sol_fill_max"),
    ("W8", "sol_scan_target"),
    ("W8", "sol_move_target_ok"),
    ("W8", "sol_can_review"),
    ("W8", "sol_review_blocker"),
    ("W8", "sol_review_item"),
    ("W8", "sol_review"),
    ("W8", "sol_approval_finished"),
    ("W8", "prepare_sol"),
    ("W8", "on_sol_previewed"),
    ("W8", "sol_consumed"),
    ("W8", "sol_consumed_card"),
    ("W8", "sol_presign"),
    ("W8", "sol_abort_message"),
    ("W8", "sol_send_failed"),
    ("W8", "sol_abort_sign"),
    ("W8", "on_sol_presigned"),
    ("W8", "on_sol_signed"),
    ("W8", "sol_sign_cancelled"),
    ("W8", "sol_schedule_tracking"),
    ("W8", "sol_send_now_target"),
    ("W8", "sol_send_now"),
    ("W8", "sol_tick_tracking"),
    ("W8", "on_sol_tracked"),
    ("W8", "sol_record_status"),
    ("W8", "sol_url_changed"),
    ("W8", "sol_copy_address"),
    ("W8", "sol_open_scan"),
    ("W8", "sol_scan_again"),
    ("W8", "sol_scan_balances"),
    ("W8", "sol_start_scan"),
    ("W8", "sol_scan_rows"),
    ("W8", "sol_scan_add"),
    ("W8", "sol_scan_move"),
    ("W8", "sol_text"),
    ("W8", "sol_edit_text"),
    ("W8", "on_sol_edit"),
    ("W8", "sol_set_cluster"),
    ("W8", "sol_save_fees"),
    ("W8", "on_sol"),
    ("W8", "on_sol_indexed"),
    ("W8", "sol_dapp_refusal"),
    ("W8", "prepare_sol_dapp"),
    ("W8", "on_sol_dapp_previewed"),
    ("W8", "sol_dapp_draft"),
    ("W8", "sol_dapp_consumed"),
    ("W8", "sol_dapp_presign"),
    ("W8", "on_sol_dapp_presigned"),
    ("W8", "sol_dapp_send_failed"),
    ("W8", "on_sol_dapp_signed"),
    ("W8", "sol_dapp_min_context_slot"),
    ("W8", "browser_sol_broadcast"),
    ("W9", "btc_call"),
    ("W9", "btc_controller"),
    ("W9", "btc_update"),
    ("W9", "btc_call_and_repaint"),
    ("W9", "btc_apply"),
    ("W9", "btc_apply_rest"),
    ("W9", "btc_save_settings"),
    ("W9", "btc_tab_active"),
    ("W9", "btc_select_tab"),
    ("W9", "btc_after_meta"),
    ("W9", "btc_journal_changed"),
    ("W9", "btc_open_tab_if_idle"),
    ("W9", "btc_tick"),
    ("W9", "btc_key_outcome"),
    ("W9", "btc_rpc_event"),
    ("W9", "btc_url_changed"),
    ("W9", "btc_enable"),
    ("W9", "btc_disable"),
    ("W9", "btc_choose_network"),
    ("W9", "btc_mismatch_keep_meta"),
    ("W9", "btc_mismatch_use_settings"),
    ("W9", "btc_set_indexer"),
    ("W9", "btc_save_esplora_url"),
    ("W9", "btc_default_esplora_url"),
    ("W9", "btc_test_esplora_url"),
    ("W9", "btc_confirm_yes"),
    ("W9", "btc_confirm_no"),
    ("W9", "btc_refresh"),
    ("W9", "btc_discover"),
    ("W9", "btc_cancel_discovery"),
    ("W9", "btc_open_receive"),
    ("W9", "btc_new_receive_address"),
    ("W9", "btc_copy_address"),
    ("W9", "btc_card_address"),
    ("W9", "btc_copy_card_address"),
    ("W9", "btc_open_send"),
    ("W9", "btc_form"),
    ("W9", "btc_review"),
    ("W9", "btc_open_bump"),
    ("W9", "btc_review_bump"),
    ("W9", "btc_continue"),
    ("W9", "btc_cancel_signed"),
    ("W9", "btc_reset_tip"),
    ("W9", "btc_toggle_address_ack"),
    ("W9", "btc_rebroadcast"),
    ("W9", "btc_abandon"),
    ("W9", "btc_esplora_broadcast"),
    ("W9", "btc_freeze"),
    ("W9", "prepare_btc"),
    ("W9", "btc_consumed"),
    ("W9", "btc_approval_finished"),
    ("W9", "btc_account_label"),
    ("W9", "btc_mnemonic_busy"),
    ("W9", "btc_pick_mnemonic"),
    ("W9", "btc_ctx"),
    ("W9", "btc_field_text"),
    ("W9", "btc_apply_field"),
    ("W9", "btc_drop_stale_typed"),
    ("W9", "btc_sync_form"),
    ("W9", "on_btc_edit"),
    ("W9", "btc_set_unit"),
    ("W9", "btc_toggle_max"),
    ("W9", "btc_settings_network"),
    ("W9", "btc_toggle_enabled"),
    ("W9", "on_btc"),
    ("W9", "on_btc_esplora"),
    ("W9", "on_btc_indexed"),
    ("W9", "on_btc_activity"),
    ("W10", "active_chain"),
    ("W10", "chain_job"),
    ("W10", "selected_account"),
    ("W10", "selected_pref"),
    ("W10", "hardware_selected"),
    ("W10", "preferred_account"),
    ("W10", "account_of"),
    ("W10", "own_accounts"),
    ("W10", "own_account_rows"),
    ("W10", "known_addresses"),
    ("W10", "address_book_facts"),
    ("W10", "chain_tokens"),
    ("W10", "evm_after_unlock"),
    ("W10", "evm_key_outcome"),
    ("W10", "on_signed"),
    ("W10", "release_signing"),
    ("W10", "evm_sign_locked"),
    ("W10", "evm_sign_cancelled"),
    ("W10", "release_slot"),
    ("W10", "evm_rpc_event"),
    ("W10", "on_balances"),
    ("W10", "on_recipient_code"),
    ("W10", "on_chain_check"),
    ("W10", "evm_balances_due"),
    ("W10", "refresh_balances"),
    ("W10", "native_balance"),
    ("W10", "token_balance"),
    ("W10", "group"),
    ("W10", "open_groups"),
    ("W10", "schedule_tracking"),
    ("W10", "tick_tracking"),
    ("W10", "apply_transitions"),
    ("W10", "on_broadcast"),
    ("W10", "evm_tick"),
    ("W10", "evm_tick_rest"),
    ("W10", "evm_balance_tick"),
    ("W10", "send_edit_wait_ms"),
    ("W10", "arm_send_timer"),
    ("W10", "on_send_timer"),
    ("W10", "send_asset_meta"),
    ("W10", "send_in_flight"),
    ("W10", "open_send"),
    ("W10", "intent"),
    ("W10", "validate_send"),
    ("W10", "request_quote"),
    ("W10", "on_quote"),
    ("W10", "on_balances_for_form"),
    ("W10", "fill_max"),
    ("W10", "can_review"),
    ("W10", "review_blocker"),
    ("W10", "review_item"),
    ("W10", "review_send"),
    ("W10", "replace_group"),
    ("W10", "account_source"),
    ("W10", "resend_group"),
    ("W10", "discard_group"),
    ("W10", "copy_text"),
    ("W10", "copy_address_text"),
    ("W10", "copy_with_band"),
    ("W10", "copy"),
    ("W10", "copy_done"),
    ("W10", "copied_tick"),
    ("W10", "lookup_token"),
    ("W10", "save_token"),
    ("W10", "open_chain_form"),
    ("W10", "save_chain_form"),
    ("W10", "set_chain_message"),
    ("W10", "on_probe"),
    ("W10", "commit_chain"),
    ("W10", "request_delete_chain"),
    ("W10", "delete_chain"),
    ("W10", "start_repin"),
    ("W10", "commit_repin"),
    ("W10", "pinned_genesis"),
    ("W10", "select_caps_chain"),
    ("W10", "save_caps"),
    ("W10", "native_text"),
    ("W10", "endpoint_text"),
    ("W10", "settings_ref"),
    ("W10", "new_approval_id"),
    ("W10", "evm_edit_text"),
    ("W10", "on_evm_edit"),
    ("W10", "evm_reread"),
    ("W10", "on_evm"),
    ("W10", "send_token_row"),
    ("W10", "send_asset_at"),
    ("W10", "choose_send_asset"),
    ("W10", "on_evm_indexed"),
    ("W10", "record_hash"),
    ("W11", "btc_network_now"),
    ("W11", "sol_dapp_rows"),
    ("W11", "btc_dapp_rows"),
    ("W11", "chain_unlocked_refusal"),
    ("W11", "sol_connect_waits_for_account"),
    ("W11", "chain_connect_choices"),
    ("W11", "sol_connect_choices"),
    ("W11", "btc_connect_choices"),
    ("W11", "chain_choices_current"),
    ("W11", "chain_connect_approved"),
    ("W11", "btc_grant_covering"),
    ("W11", "chain_site_preflight"),
    ("W11", "chain_sign_draft"),
    ("W11", "chain_waiter"),
    ("W11", "sol_grant_holds"),
    ("W11", "btc_grant_holds"),
    ("W11", "chain_grant_holds"),
    ("W11", "browser_chain_message_signed"),
    ("W11", "sol_account_removed_from_sites"),
    ("W11", "btc_addresses_removed_from_sites"),
    ("W11", "chain_grants_removed"),
    ("W11", "disconnect_chain_site"),
    ("W11", "write_grants"),
    ("W11", "flush_grant_writes"),
    ("W11", "browser_tick"),
    ("W11", "browser_vault_loaded"),
    ("W11", "after_browser_unlock"),
    ("W11", "on_dapp_event"),
    ("W11", "respond"),
    ("W11", "browser_grants"),
    ("W11", "chain_grants"),
    ("W11", "grant_of"),
    ("W11", "slot_held"),
    ("W11", "unlocked_refusal"),
    ("W11", "refuse_site"),
    ("W11", "connect_refused_notice"),
    ("W11", "on_site_request"),
    ("W11", "open_unlock_for_dapp"),
    ("W11", "dapp_unlock_dismissed"),
    ("W11", "cancel_site"),
    ("W11", "site_finished"),
    ("W11", "passphrase_refusal"),
    ("W11", "site_preflight"),
    ("W11", "persist_grant_change"),
    ("W11", "revoke_waiting"),
    ("W11", "disconnect_site"),
    ("W11", "disconnect_all_sites"),
    ("W11", "account_removed_from_sites"),
    ("W11", "evm_key_removed_from_sites"),
    ("W11", "hardware_site_accounts"),
    ("W11", "hardware_accounts_reloaded"),
    ("W11", "chain_removed_from_sites"),
    ("W11", "connect_approved"),
    ("W11", "push_sign_waiter"),
    ("W11", "take_sign_waiter"),
    ("W11", "evm_grant_holds"),
    ("W11", "waiter_grant_holds"),
    ("W11", "browser_tx_signed"),
    ("W11", "browser_message_signed"),
    ("W11", "browser_sign_cancelled"),
    ("W11", "browser_broadcast"),
    ("W11", "network_url_changed"),
    ("W11", "reset_read_chain"),
    ("W11", "waiting_origins"),
    ("W11", "card_names"),
    ("W11", "card_name"),
    ("W11", "card_name_list"),
    ("W11", "pin_context"),
    ("W11", "enrol_yubikey"),
    ("W11", "on_yubikey_enrolled"),
    ("W11", "card_after_meta"),
    ("W11", "on_hardware_keys"),
    ("W11", "card_role"),
    ("W11", "card_begin"),
    ("W11", "card_on_defaults"),
    ("W11", "evm_card_gate"),
    ("W11", "evm_selected_card_gate"),
    ("W11", "evm_account_card_gate"),
    ("W11", "sol_card_gate"),
    ("W11", "btc_source_card_gate"),
    ("W11", "btc_selected_card_gate"),
    ("W11", "zec_card_gate"),
    ("W11", "card_connect_tag"),
    ("W11", "refuse_card_defaults"),
    ("W11", "card_counters"),
    ("W11", "card_step_card"),
    ("W11", "card_details"),
    ("W11", "card_open_pin"),
    ("W11", "card_waiting"),
    ("W11", "card_waiting_id"),
    ("W11", "card_submit"),
    ("W11", "card_cancel"),
    ("W11", "card_site_gone"),
    ("W11", "card_site_check"),
    ("W11", "card_form"),
    ("W11", "card_form_shown"),
    ("W11", "card_form_line"),
    ("W11", "card_notice_set"),
    ("W11", "card_notice_clear"),
    ("W11", "card_resolve_cancelled"),
    ("W11", "card_resolve_failed"),
    ("W11", "card_release"),
    ("W11", "card_unused"),
    ("W11", "card_outcome_ticket"),
    ("W11", "card_outcome_matches"),
    ("W11", "card_filter"),
    ("W11", "card_tick"),
    ("W11", "card_abandon_sol"),
    ("W11", "card_abandon_dapp"),
    ("W11", "on_sites"),
    ("W12", "key_only"),
    ("W12", "imported_count"),
    ("W12", "can_remove_imported"),
    ("W12", "imported_of"),
    ("W12", "can_import"),
    ("W12", "open_key_import"),
    ("W12", "key_start_open"),
    ("W12", "key_start_cancel"),
    ("W12", "key_start_next"),
    ("W12", "key_start_password"),
    ("W12", "key_start_key"),
    ("W12", "on_key_start_preview"),
    ("W12", "key_start_commit"),
    ("W12", "key_start_wrong"),
    ("W12", "on_key_imported"),
    ("W12", "imported_reveal"),
    ("W12", "btc_evm_shared_reveal"),
    ("W12", "imported_remove"),
    ("W12", "on_imported_key_busy"),
    ("W12", "imported_confirmed"),
    ("W12", "imported_target_text"),
    ("W12", "imported_removed"),
    ("W12", "on_evm_raw_key_removed"),
    ("W12", "on_imported_key_removed"),
    ("W12", "on_keys"),
    ("W12", "mnemonic_label"),
    ("W12", "primary_mnemonic_label"),
    ("W12", "several_mnemonics"),
    ("W12", "mnemonic_tagged"),
    ("W12", "mnemonic_tag"),
    ("W12", "mnemonic_named"),
    ("W12", "mnemonic_busy"),
    ("W12", "mnemonic_first_address"),
    ("W12", "mnemonic_account_counts"),
    ("W12", "mnemonic_account_rows"),
    ("W12", "mnemonic_account"),
    ("W12", "mnemonic_source"),
    ("W12", "mnemonic_account_mut"),
    ("W12", "can_add_account"),
    ("W12", "add_account_clicked"),
    ("W12", "add_primary_account"),
    ("W12", "unlocked"),
    ("W12", "mn_phrases_editable"),
    ("W12", "mn_primary_pending"),
    ("W12", "mn_backup_gate"),
    ("W12", "evm_backup_gate"),
    ("W12", "mn_unconfirmed"),
    ("W12", "evm_account_unconfirmed"),
    ("W12", "sol_backup_gate"),
    ("W12", "sol_source_unconfirmed"),
    ("W12", "btc_source_unconfirmed"),
    ("W12", "btc_backup_gate"),
    ("W12", "evm_selected_gate"),
    ("W12", "refuse_unconfirmed"),
    ("W12", "backup_refused_text"),
    ("W12", "mn_send_blocked"),
    ("W12", "mn_connect_tag"),
    ("W12", "on_mn"),
    ("W12", "on_mn_preview"),
    ("W12", "mn_remove_clicked"),
    ("W12", "mn_remove_reset"),
    ("W12", "mn_leaving"),
    ("W12", "mn_remove_unconfirmed"),
    ("W12", "mn_remove_confirmed"),
    ("W12", "on_mn_edit"),
    ("W12", "mn_set_remove_typed"),
    ("W12", "on_chain_pick"),
    ("W12", "open_mn_input"),
    ("W12", "save_mnemonic_label"),
    ("W12", "mn_submit"),
    ("W12", "mn_cancel"),
    ("W12", "mn_hold_complete"),
    ("W12", "after_change"),
    ("W12", "mn_chain_accounts_removed"),
    ("W12", "on_mn_outcome"),
    ("W12", "yk_network"),
    ("W12", "yk_open_wizard"),
    ("W12", "yk_leaving"),
    ("W12", "yk_wizard"),
    ("W12", "yk_abandon_asks"),
    ("W12", "yk_close_wizard"),
    ("W12", "yk_plan_next"),
    ("W12", "yk_send_preview"),
    ("W12", "yk_import"),
    ("W12", "yk_piv_credentials"),
    ("W12", "yk_factory_key"),
    ("W12", "yk_key_bytes"),
    ("W12", "yk_run"),
    ("W12", "yk_submit"),
    ("W12", "yk_cancel"),
    ("W12", "yk_hold_complete"),
    ("W12", "yk_result_serial"),
    ("W12", "yk_pin_serial"),
    ("W12", "yk_pin_defaults"),
    ("W12", "yk_pin_job"),
    ("W12", "yk_open_pin_action"),
    ("W12", "yk_open_card_secret"),
    ("W12", "yk_card_counters"),
    ("W12", "yk_counter_kinds"),
    ("W12", "yk_show_counters"),
    ("W12", "yk_counter_forms"),
    ("W12", "on_yk_counters"),
    ("W12", "yk_take_last_try"),
    ("W12", "yk_take_puk_last_try"),
    ("W12", "yk_note_last_try"),
    ("W12", "yk_enter_credentials"),
    ("W12", "on_yk_identified"),
    ("W12", "on_yk_occupied"),
    ("W12", "yk_pins_first"),
    ("W12", "yk_card_on_defaults"),
    ("W12", "yk_pin_later"),
    ("W12", "yk_identify_again"),
    ("W12", "on_yk_management"),
    ("W12", "on_yk_protected"),
    ("W12", "on_yk_pins_set"),
    ("W12", "yk_new_wallet"),
    ("W12", "yk_new_wallet_start"),
    ("W12", "on_yk_outcome"),
    ("W12", "yk_note"),
    ("W12", "on_yk_preview"),
    ("W12", "yk_enrolled"),
    ("W12", "on_yk_checked"),
    ("W12", "on_yk_pin_changed"),
    ("W12", "yk_defaults_done"),
    ("W12", "yk_remove"),
    ("W12", "yk_can_remove"),
    ("W12", "yk_remove_confirmed"),
    ("W12", "yk_save_card_name"),
    ("W12", "on_yk"),
    ("W12", "on_yk_edit"),
    ("W12", "yk_set_text"),
    ("W12", "yk_connect_networks"),
    ("W12", "yk_open_connect"),
    ("W12", "yk_connect_new_wallet"),
    ("W12", "yk_connect_password"),
    ("W12", "yk_connect_begin"),
    ("W12", "yk_connect_form"),
    ("W12", "yk_connect_rescan"),
    ("W12", "on_yk_scanned"),
    ("W12", "yk_connect_choose"),
    ("W12", "yk_connect_next"),
    ("W12", "yk_connect_back"),
    ("W12", "yk_connect_pin"),
    ("W12", "yk_connect_pin_lines"),
    ("W12", "yk_connect_pin_submit"),
    ("W12", "on_yk_connect_verified"),
    ("W12", "yk_connect_save"),
    ("W12", "on_yk_connect"),
    ("W12", "yk_manage_record"),
    ("W12", "yk_reslot_open"),
    ("W12", "yk_clear_open"),
    ("W12", "yk_manage_close"),
    ("W12", "reslot"),
    ("W12", "clear_flow"),
    ("W12", "yk_other_records"),
    ("W12", "yk_reslot_next"),
    ("W12", "yk_reslot_send_preview"),
    ("W12", "yk_reslot_import"),
    ("W12", "yk_reslot_backup"),
    ("W12", "yk_clear_allowed"),
    ("W12", "yk_clear_lost"),
    ("W12", "yk_clear_ready"),
    ("W12", "yk_clear_run"),
    ("W12", "yk_clear_after_admin"),
    ("W12", "yk_clear_job"),
    ("W12", "yk_manage_submit"),
    ("W12", "yk_manage_cancel"),
    ("W12", "on_yk_manage"),
    ("W12", "on_reslot_preview"),
    ("W12", "on_reslotted"),
    ("W12", "yk_flag_defaults"),
    ("W12", "on_cleared"),
    ("W12", "on_yk_manage_press"),
    ("W12", "on_yk_manage_edit"),
    ("W12", "yk_manage_set_text"),
    ("W12", "on_secret_action"),
    ("W12", "secret_session_is"),
    ("W12", "on_submit"),
    ("W12", "preview_import"),
    ("W12", "on_cancel"),
    ("W12", "challenge_id"),
    ("W3b", "reads_due"),
    ("W3b", "idle_window"),
    ("W3b", "idle_tick"),
    ("W3b", "first_run_pending"),
    ("W3b", "discard_first_run"),
    ("W3b", "shutdown_begin"),
    ("W3b", "shutdown_steps"),
    ("W3b", "shutdown_after_wait"),
    ("W3b", "on_rpc_event"),
    ("W3b", "key_result"),
    ("W3b", "on_status"),
    ("W3b", "reload_after_failed_start"),
    ("W3b", "settings_accept_file"),
    ("W3b", "settings_restore"),
    ("W3b", "refuse_receive"),
    ("W3b", "on_core"),
    ("W3b", "on_core_row"),
    ("W3b", "delete_rpc_url"),
    ("W3b", "select_account"),
    ("W3b", "save_rename"),
    ("W3b", "hide_selected"),
    ("W3b", "save_autolock"),
    ("W3b", "save_template_credentials"),
    ("W3b", "prune_dormant"),
    ("W3b", "delete_template_credentials"),
    ("W3b", "begin_generate"),
    ("W3b", "generate_and_report"),
    ("W3b", "generate"),
    ("W3b", "save_replacement"),
    ("W3b", "test_all_networks"),
    ("W3b", "test_network"),
    ("W3b", "open_rpc_row"),
    ("W3b", "clear_done"),
    ("W3b", "done_connect"),
    ("W3b", "done_connect_with"),
    ("W3b", "close_overlay_in_place"),
    ("W3b", "confirm_yes"),
    ("W13", "needs_accounts"),
    ("W13", "wait_tick"),
    ("W13", "wait_retry"),
    ("W13", "sends_in_flight"),
    ("W13", "open_reset"),
    ("W13", "cancel_reset"),
    ("W13", "reset_phrase_changed"),
    ("W13", "replace_reset"),
    ("W13", "reset_execute"),
    ("W13", "on_wallet_reset"),
    ("W13", "reset_absorbs_load"),
    ("W13", "reset_hold_begin"),
    ("W13", "reset_hold_tick"),
    ("W13", "on_reset"),
    ("W13", "on_reset_edit"),
    ("W13", "reset_list_files"),
    ("W13", "forget_vault_state"),
    ("W13", "wc_peer_of"),
    ("W13", "site_approval_origin"),
    ("W13", "origin_display"),
    ("W13", "site_origin_text"),
    ("W13", "wc_decorate_draft"),
    ("W13", "wc_connect_patch"),
    ("W13", "wc_start"),
    ("W13", "wc_send"),
    ("W13", "wc_grants_changed"),
    ("W13", "wc_store"),
    ("W13", "wc_after_unlock"),
    ("W13", "wc_shutdown"),
    ("W13", "on_wc_event"),
    ("W13", "wc_proposal_end_text"),
    ("W13", "wc_store_is_current"),
    ("W13", "wc_persist"),
    ("W13", "wc_prune_grants"),
    ("W13", "wc_pair"),
    ("W13", "wc_notice"),
    ("W13", "wc_pair_pixels"),
    ("W13", "wc_clipboard_qr"),
    ("W13", "wc_file_qr"),
    ("W13", "wc_save_project"),
    ("W13", "wc_disconnect"),
    ("W13", "wc_clipboard_connect"),
    ("W13", "wc_disconnect_all"),
    ("W13", "on_wc"),
    ("W13", "on_wc_edit"),
    ("W13", "rpc_import_cancel"),
    ("W13", "rpc_json_delete_asked"),
    ("W13", "on_rpc_json_deleted"),
    ("W13", "on_rpc_json_read"),
    ("W13", "finish_rpc_import"),
    ("W13", "push_rejected"),
    ("W14a", "show_next_approval"),
    ("W14a", "show_next_approval_then"),
    ("W14a", "show_next_approval_with"),
    ("W14a", "run_after_open"),
    ("W14a", "close_if_shown"),
    ("W14a", "btc_receive_shown"),
    ("W14a", "esplora_field_shows"),
    ("W14a", "after_pending_open"),
    ("W14a", "approval_open_answered"),
    ("W14a", "connect_state"),
    ("W14a", "connect_origin_chain"),
    ("W14a", "evm_chain_label"),
    ("W14a", "refresh_connect_chain"),
    ("W14a", "open_approval"),
    ("W14a", "on_approval_opened"),
    ("W14a", "approval_open_failed"),
    ("W14a", "start_prepare"),
    ("W14a", "prepare_transaction"),
    ("W14a", "prepare_site"),
    ("W14a", "message_chain_failure"),
    ("W14a", "approval_lang"),
    ("W14a", "message_chain"),
    ("W14a", "on_typed_facts"),
    ("W14a", "show_failure"),
    ("W14a", "close_approval_window"),
    ("W14a", "shown_now"),
    ("W14a", "finish_approval"),
    ("W14a", "on_simulating"),
    ("W14a", "on_prepared"),
    ("W14a", "show_ready_draft"),
    ("W14a", "show_ready_draft_at"),
    ("W14a", "on_resimulated"),
    ("W14a", "tick_approval"),
    ("W14a", "rebuild_view"),
    ("W14a", "rebuild_view_with"),
    ("W14a", "enqueue_app"),
    ("W14a", "approval_finished"),
    ("W14a", "llm_busy"),
    ("W14a", "ai_after"),
    ("W14a", "ai_ready"),
    ("W14a", "ai_ready_tx"),
    ("W14a", "ai_ready_message"),
    ("W14a", "ai_ready_typed"),
    ("W14a", "ai_tick"),
    ("W14a", "ai_retry"),
    ("W14a", "on_llm_done"),
    ("W14b", "approved"),
    ("W14b", "start_resimulation"),
    ("W14b", "consume_and_sign"),
    ("W14b", "dispatch_evm_sign"),
    ("W14b", "on_approval_input"),
    ("W14b", "approval_event"),
    ("W14b", "retry_action"),
    ("W14c", "account_label"),
    ("W14c", "activity_rows"),
    ("W14c", "meta_activity_row"),
    ("W14c", "record_status"),
    ("W14c", "evm_pref_title"),
    ("W14c", "network_label"),
    ("W14c", "evm_last_balance"),
    ("W14c", "evm_removed"),
    ("W14c", "picker_entries"),
    ("W14c", "picker_known"),
    ("W14c", "card_source"),
    ("W14c", "sol_activity_counterparties"),
    ("W14c", "sol_activity_tx_ids"),
    ("W14c", "sol_picker_entries"),
    ("W14c", "sol_last_balance"),
    ("W14c", "sol_removed"),
    ("W14c", "btc_last_balance"),
    ("W14c", "btc_removed"),
    ("W14c", "zec_activity_recipients"),
    ("W14c", "zec_evm_indices"),
    ("W14c", "zec_hw_slots"),
    ("W14c", "zec_last_balance"),
    ("W14c", "zec_removed"),
    ("W14c", "hc_foldable"),
    ("W15", "on_cmd"),
    ("W15", "on_press"),
    ("W15", "on_family"),
    ("W15", "on_field_edit"),
    ("W15", "activate"),
    ("W15", "timer_part"),
    ("W15", "worker_event"),
    ("W15", "hold_shown_ai_for_ack"),
    ("W15", "on_folder_missing"),
    ("W15", "drop_clip_notice"),
    ("W15", "forget_copy_mark"),
    ("W15", "toggle_ai_panel"),
    ("W15", "install_commit_read"),
    ("W15", "wer_unprotected_noted"),
    ("W15", "browser_attached"),
    ("W15", "workers_attached"),
    // 2026-11-23 (S4d E0b): the wallet's constructor (the field initializers of
    // `App::with_clock`'s `Wallet` literal).
    ("E0b", "new"),
    // 2026-11-23 (S4d E1): the display secret's one hand-off (preflight O-3), the shell's read
    // of an open, unshown session and of the queue's length, and the read-only accessors the
    // test traits (`yw_engine::testkit`) use. 2026-11-23 (S4d E1 review): `test_secret_session_mut`,
    // the slot itself, became the setup steps `test_set_secret_session`/`test_open_secret_session`.
    ("E1", "hand_display_secret"),
    ("E1", "secret_unshown"),
    ("E1", "queued_effects"),
    ("E1", "test_secret_session"),
    ("E1", "test_set_secret_session"),
    ("E1", "test_open_secret_session"),
    ("E1", "test_secret_serial"),
    ("E1", "test_import_held"),
    ("E1", "test_challenge"),
];

/// The `self.` field names `body` reads or writes: the first segment of each `self.` chain that
/// is not a call (`self.wallet.` counted as `self.`).
fn self_fields(body: &str) -> BTreeSet<String> {
    let text = normalized(body);
    let bytes = text.as_bytes();
    let mut found = BTreeSet::new();
    for (at, _) in text.match_indices("self.") {
        if at > 0 && (is_ident(bytes[at - 1]) || bytes[at - 1] == b'.') {
            continue;
        }
        let start = at + "self.".len();
        let mut stop = start;
        while stop < bytes.len() && is_ident(bytes[stop]) {
            stop += 1;
        }
        if stop > start && !text[stop..].trim_start().starts_with('(') {
            found.insert(text[start..stop].to_owned());
        }
    }
    found
}

/// The `impl App` fns whose own body names a shell field (`shell`) or `yw_win`: the shell's fns
/// by what they touch (one level; a wallet fn still in `impl App` that reaches the shell is among
/// them until its row removes that reach).
fn shell_namers(
    fns: &BTreeMap<String, Vec<(String, String, bool)>>,
    shell: &BTreeSet<String>,
) -> BTreeSet<String> {
    fns.iter()
        .filter(|(_, bodies)| {
            bodies.iter().any(|(_, body, _)| {
                body.contains("yw_win") || self_fields(body).iter().any(|f| shell.contains(f))
            })
        })
        .map(|(name, _)| name.clone())
        .collect()
}

/// The shell's fns as a fixed point (2026-11-21, S4 W3 review: before, only `seed` — the fns that
/// name a shell field or `yw_win` themselves, [`shell_namers`], and [`SHELL_FNS`] — so a wallet fn
/// that reached the shell through an `impl App` helper went unseen): `seed` plus every `impl App`
/// fn that calls ([`app_calls`]: `self.<fn>(`, `Self::<fn>(`, `App::<fn>(`, a closure's
/// `app.<fn>(`; 2026-11-21, S4 W7 review: before, `self.<fn>(` only) a fn already in the set,
/// until it stops growing.
fn shell_closure(
    fns: &BTreeMap<String, Vec<(String, String, bool)>>,
    seed: BTreeSet<String>,
) -> BTreeSet<String> {
    let mut shell_fns = seed;
    loop {
        let more: Vec<String> = fns
            .iter()
            .filter(|(name, _)| !shell_fns.contains(*name))
            .filter(|(_, bodies)| {
                bodies
                    .iter()
                    .any(|(_, body, _)| app_calls(body).iter().any(|c| shell_fns.contains(c)))
            })
            .map(|(name, _)| name.clone())
            .collect();
        if more.is_empty() {
            return shell_fns;
        }
        shell_fns.extend(more);
    }
}

/// The module-level fns of `files` (2026-11-21, S4 W6 review): a fn none of whose enclosing
/// blocks is anything but a `mod` (no `impl`, `trait` or fn), by name, each body with its file.
fn free_fns(files: &[Src]) -> BTreeMap<String, Vec<(String, String)>> {
    let mut fns: BTreeMap<String, Vec<(String, String)>> = BTreeMap::new();
    for src in files {
        for block in &src.blocks {
            let fn_head = head(&src.code, block.open);
            let Some((_, after)) = fn_head.rsplit_once("fn ") else {
                continue;
            };
            if !has_word(fn_head, "fn") {
                continue;
            }
            let mut parent = block.parent;
            let mut top = true;
            while let Some(index) = parent {
                let outer = head(&src.code, src.blocks[index].open);
                if !has_word(outer, "mod") || has_word(outer, "fn") {
                    top = false;
                    break;
                }
                parent = src.blocks[index].parent;
            }
            if !top {
                continue;
            }
            let name: String = after
                .trim_start()
                .chars()
                .take_while(|&c| c.is_ascii_alphanumeric() || c == '_')
                .collect();
            fns.entry(name).or_default().push((
                src.file.clone(),
                src.code[block.open..=block.close].to_owned(),
            ));
        }
    }
    fns
}

/// The module a yw-app source file is (2026-11-21, S4 W6 review): its file stem, its folder's
/// name for a `mod.rs`, `crate` for the crate root.
fn module_stem(file: &str) -> &str {
    let path = file.strip_suffix(".rs").unwrap_or(file);
    let mut parts = path.rsplit('/');
    match parts.next().unwrap_or_default() {
        "mod" => parts.next().unwrap_or_default(),
        "main" | "lib" => "crate",
        stem => stem,
    }
}

/// The `use … ;` statements of `code`.
fn use_statements(code: &str) -> Vec<&str> {
    code.match_indices("use ")
        .filter(|&(at, _)| at == 0 || !is_ident(code.as_bytes()[at - 1]))
        .map(|(at, _)| {
            let end = code[at..].find(';').map_or(code.len(), |n| at + n);
            &code[at..end]
        })
        .collect()
}

/// Which yw-app free fns of `set` (`(file, name)`) `body`, a fn of `caller`, calls (2026-11-21,
/// S4 W6 review): the name followed by `(` or `::<`, not after `.` (a method), `fn ` (a
/// definition) or an identifier character, and either bare — in the file that defines it, or
/// where a `use` statement of `caller` names it (or `*`) with its module — or after a path whose
/// last segment is its module ([`module_stem`]; `super`/`self` in its own file, `crate` for the
/// crate root). So `Instant::now(` or another module's `start(` is not a call of `server::start`.
fn free_calls(body: &str, caller: &Src, set: &BTreeSet<(String, String)>) -> BTreeSet<String> {
    let text = normalized(body);
    let bytes = text.as_bytes();
    let uses = use_statements(&caller.code);
    let mut calls = BTreeSet::new();
    for (file, name) in set {
        let stem = module_stem(file);
        let same_file = *file == caller.file;
        let imported = same_file
            || uses
                .iter()
                .any(|stmt| has_word(stmt, stem) && (has_word(stmt, name) || stmt.contains('*')));
        for (at, _) in text.match_indices(name.as_str()) {
            let stop = at + name.len();
            if bytes.get(stop).is_some_and(|&b| is_ident(b)) {
                continue;
            }
            let rest = text[stop..].trim_start();
            if !(rest.starts_with('(') || rest.starts_with("::<")) {
                continue;
            }
            let before = &text[..at];
            if before
                .as_bytes()
                .last()
                .is_some_and(|&b| is_ident(b) || b == b'.')
                || ends_with_word(before.trim_end(), "fn")
            {
                continue;
            }
            let counts = match before.strip_suffix("::") {
                None => imported,
                Some(path) => {
                    let start = path
                        .bytes()
                        .rposition(|b| !(is_ident(b) || b == b':'))
                        .map_or(0, |n| n + 1);
                    let last = path[start..].rsplit("::").next().unwrap_or_default();
                    last == stem || (same_file && (last == "super" || last == "self"))
                }
            };
            if counts {
                calls.insert(name.clone());
            }
        }
    }
    calls
}

/// The shell's free fns as a fixed point (2026-11-21, S4 W6 review; plan D-30): every yw-app
/// module-level fn ([`free_fns`]) whose body names `yw_win` (`ui::screens_sidecar::local_time`,
/// `app_sidecar` before 2026-11-22 S4d E0c, which reads `yw_win::time::local_wall_ms`), plus every one that calls ([`free_calls`]) a fn already
/// in the set, until it stops growing; as `(file, name)`.
fn shell_free_fns(
    files: &[Src],
    free: &BTreeMap<String, Vec<(String, String)>>,
) -> BTreeSet<(String, String)> {
    let all = || {
        free.iter()
            .flat_map(|(name, bodies)| bodies.iter().map(move |(file, body)| (file, name, body)))
    };
    let mut set: BTreeSet<(String, String)> = all()
        .filter(|(_, _, body)| body.contains("yw_win"))
        .map(|(file, name, _)| (file.clone(), name.clone()))
        .collect();
    loop {
        let more: Vec<(String, String)> = all()
            .filter(|(file, name, _)| !set.contains(&((*file).clone(), (*name).clone())))
            .filter(|(file, _, body)| !free_calls(body, src_of(files, file), &set).is_empty())
            .map(|(file, name, _)| (file.clone(), name.clone()))
            .collect();
        if more.is_empty() {
            return set;
        }
        set.extend(more);
    }
}

/// What in `body` (a wallet fn's) reaches the shell: a shell field, `yw_win`, a call of a
/// shell fn (`shell_fns`, the fixed point of [`shell_closure`]; any receiver [`app_calls`] counts
/// since the W7 review, 2026-11-21, before `self.<fn>(` only) or, since the W6 review
/// (2026-11-21), a call of a shell free fn (`shell_free`, [`shell_free_fns`]: before, a wallet fn
/// that called `local_time` passed).
fn shell_reach(
    body: &str,
    caller: &Src,
    shell: &BTreeSet<String>,
    shell_fns: &BTreeSet<String>,
    shell_free: &BTreeSet<(String, String)>,
) -> Vec<String> {
    let mut found: Vec<String> = self_fields(body)
        .into_iter()
        .filter(|field| shell.contains(field))
        .map(|field| format!("names self.{field}"))
        .collect();
    if body.contains("yw_win") {
        found.push("names yw_win".to_owned());
    }
    found.extend(
        app_calls(body)
            .into_iter()
            .filter(|call| shell_fns.contains(call))
            .map(|call| format!("calls App::{call}")),
    );
    found.extend(
        free_calls(body, caller, shell_free)
            .into_iter()
            .map(|call| format!("calls {call}")),
    );
    found
}

// 2026-11-22 (S4d E0c): `RENDER_LOCAL_TIME` is gone. `activity_rows` and `meta_activity_row`
// return the row's time as `ActivityRowView::time_unix_ms`, and the render code
// (`evm_main_sections`) prints it with `format_local` (plan D-30), so no wallet fn calls a shell
// free fn and none is excused. Its text was:
// The `impl App` render helpers that format a local time through a shell free fn and that
// [`WALLET_FNS`] fns reach (2026-11-21, S4 W6 review): `activity_rows` (`ui/screens_evm.rs`, its
// `format_local`, `yw_win::time::local_wall_ms`), which W4's `activity_counterparty` and
// `on_links` call for a row's counterparty, and its row helper `meta_activity_row` (the same
// `format_local`). Plan "Left out of S4": `local_wall_ms` in render helpers is S5's, and the
// render helpers wallet fns call flip with them at W14c or move (preflight §3.0); so
// [`wallet_fns_name_no_shell`] does not count a call of these as shell reach, and a new one
// fails it. 2026-11-22 (S4c W14c-2): both flipped with the wallet fns (`impl Wallet`, row W14c
// of [`WALLET_FNS`]); their own call of `format_local` is the one shell free-fn call a listed
// fn may make, and only these two may make it.

/// `wallet_fns_name_no_shell` (2026-11-21, S4 W3; preflight §3.0 prep rows, critique B-2, B-11,
/// A-20): every fn of [`WALLET_FNS`] — wallet code that stays `impl App` until W14c flips it in
/// place — names no shell field (`pub struct App`'s fields but `wallet`), no `yw_win`, and calls
/// no shell fn ([`SHELL_FNS`], every `impl App` fn that names a shell field or `yw_win` itself,
/// [`shell_namers`], and every `impl App` fn that calls one of those, at any depth,
/// [`shell_closure`]). So the flip can make them `impl Wallet` without a body change, and a later
/// row cannot give one of them shell reach again unseen, directly or through `impl App` helpers
/// (calls written `self.<fn>(`, `Self::<fn>(`, `App::<fn>(` or a closure's `app.<fn>(`,
/// [`app_calls`]; 2026-11-21, S4 W3 review: before, one level only, so a wallet fn that called a
/// helper which called `render_main` passed; 2026-11-21, S4 W7 review: before, only calls written
/// `self.<fn>(` were followed, so `Self::drain(self)` in a W7 fn passed). The check finds every
/// listed fn (it cannot pass on nothing), and its scanners are tried on made-up code
/// ([`shell_reach_on_made_up_code`], [`app_calls_on_made_up_code`]). 2026-11-21 (S4 W6 review): the shell's free fns too
/// ([`shell_free_fns`]: yw-app module-level fns that name `yw_win`, at any depth): a listed fn
/// that calls one (`local_time`, plan D-30's local time) reaches the shell, and so does an
/// `impl App` fn that calls one (a seed of [`shell_closure`]) but `RENDER_LOCAL_TIME`; before,
/// only `self.<fn>(` calls were followed, so a wallet fn that called `local_time` passed and
/// D-30's "no wallet fn calls `local_time`" (spec/04 §1.3 W6) was not checked.
/// 2026-11-21 (S4 W8 review): two forms stay unchecked until W14c, where the compiler checks
/// the `impl Wallet` bodies instead: `self` reborrowed or rebound and the shell fn called on the
/// new name (`let me = &mut *self; me.drain();`), and an `App::<fn>`/`Self::<fn>` path taken as a
/// value with no call (`let f: fn(&mut App) = App::drain; f(self);`). The review's mutation
/// probes of both in W8 fns were not caught, nor were their callers reported. A grep of the three
/// Solana files for a `&mut *self` or `= self;` rebind, a bare `self` passed on and an
/// `App::`/`Self::` path not followed by a call found neither form in an `impl App` body at W8
/// (only doc comments name such paths).
/// 2026-11-22 (S4 W9 review): a closure's parameter counted only when it was named `app`, so
/// `let _ = |x: &mut Self| x.drain();` in the W9 fn `btc_set_unit` passed. Now a name the body
/// types as an `App` (`&Self`, `&mut Self`, `&App`, `&mut App`, [`typed_app_names`]) is a
/// receiver too. A closure's parameter with no type and another name (`|me| me.drain()`) is the
/// first form above (a rebind) and stays unchecked until W14c. No listed W9 fn has a closure
/// that takes an `App` (in `app_btc.rs` and `app_btc_commands.rs` only the test adapter
/// `on_btc_command`'s `|app, press|` does, and it is not listed).
/// 2026-11-22 (S4c W14c-2, the flip): every listed fn is now `impl Wallet` (in place, the same
/// file), so the check finds them among the `impl Wallet` fns and fails on one still in an
/// `impl App` block; the compiler now rejects a shell field or a shell fn on `self` in their
/// bodies (the two forms above included: `self` is a `Wallet` there), and the scan keeps
/// checking what the compiler allows, `yw_win` and the shell's free fns (but `format_local` in
/// `RENDER_LOCAL_TIME`, gone 2026-11-22 S4d E0c). It also checks that `impl Wallet` holds nothing
/// else but the wallet's
/// own fns of before the flip ([`WALLET_OWN_FNS`]), so a new wallet fn is listed here.
/// 2026-11-22 (S4c W14c review): the compiler allows the type name `App` in a wallet fn (a
/// review probe `let _probe: Option<&App> = None;` in `Wallet::on_sites` compiled and passed),
/// so every `impl Wallet` fn is also scanned for it ([`names_app`]); before, the W14c-2 text
/// above said the compiler rejected `App` too. 2026-11-22 (S4d E0c): without the
/// `RENDER_LOCAL_TIME` exception the fn is short enough for clippy (its `too_many_lines`
/// expectation went).
#[test]
fn wallet_fns_name_no_shell() {
    // 2026-11-23 (spec/15 §11.4 S4d E1, preflight E1): every `impl Wallet` is in yw-engine
    // (`yw-engine/src/wallet/`), which depends on no yw-app or yw-win item, so the compiler now
    // refuses what this scan looked for (a shell field, a shell fn, `yw_win`, the type `App` in a
    // wallet fn; before E1, the scan of yw-app's `impl Wallet` fns with `shell_reach`). It checks
    // that every listed fn ([`WALLET_FNS`], [`WALLET_OWN_FNS`]) is an `impl Wallet` fn there, that
    // nothing else is one, and that no `impl Wallet` fn is anywhere else.
    let files = production_code();
    let wallet = impl_fns(&files, "Wallet");
    assert!(wallet.len() > 900, "{} impl Wallet fns found", wallet.len());
    let mut errors = Vec::new();
    for (name, bodies) in &wallet {
        for (file, _, _) in bodies {
            if !file.starts_with("yw-engine/src/wallet/") {
                errors.push(format!(
                    "{file}: impl Wallet fn {name} outside yw-engine's wallet"
                ));
            }
        }
    }
    for &(row, name) in &WALLET_FNS {
        if !wallet.contains_key(name) {
            errors.push(format!("{row} {name}: no fn of impl Wallet"));
        }
    }
    assert!(
        errors.is_empty(),
        "{}",
        errors.join(
            "
"
        )
    );
    let names: BTreeSet<&str> = WALLET_FNS.iter().map(|&(_, name)| name).collect();
    assert_eq!(names.len(), WALLET_FNS.len(), "a fn listed twice");
    for name in WALLET_OWN_FNS {
        assert!(
            wallet.contains_key(name),
            "the wallet's own fn {name} found"
        );
        assert!(!names.contains(name), "{name} is listed and own");
    }
    let unlisted: Vec<&String> = wallet
        .keys()
        .filter(|name| !names.contains(name.as_str()) && !WALLET_OWN_FNS.contains(&name.as_str()))
        .collect();
    assert!(
        unlisted.is_empty(),
        "impl Wallet fns not listed: {unlisted:?}"
    );
}

/// Whether `code` names the type `App`: the word `App` alone or after `app::`, not as a variant
/// (`Enum::App`) ([`names_app`]).
fn names_the_app_type(code: &str) -> bool {
    let bytes = code.as_bytes();
    code.match_indices("App").any(|(at, word)| {
        let alone = (at == 0 || !is_ident(bytes[at - 1]))
            && bytes.get(at + word.len()).is_none_or(|&b| !is_ident(b));
        let before = code[..at].trim_end();
        alone && (!before.ends_with("::") || ends_with_word(before, "app::"))
    })
}

#[test]
fn names_the_app_type_on_made_up_code() {
    for code in [
        "let _probe: Option<&App> = None;",
        "Box<dyn FnOnce(&mut App)>",
        "crate::app::App::drain",
        "App",
    ] {
        assert!(names_the_app_type(code), "{code}");
    }
    for code in [
        "QueueSource::App",
        "QueuedItem::App(item) => item",
        "SignWaiter::App => true",
        "AppMode::Unlocked",
        "yw_engine::wallet::AppMode",
        "Apple",
        "MyApp",
    ] {
        assert!(!names_the_app_type(code), "{code}");
    }
}

/// The `impl Wallet` fns of before the flip (2026-11-22, S4c W14c-2): the outbox's `emit` and
/// `next_effect` (S4 W3), the main-window mirror's read `main_hidden` (W3) and the debug builds'
/// credential log `take_cred_log` (W3). With [`WALLET_FNS`] they are every `impl Wallet` fn
/// ([`wallet_fns_name_no_shell`]).
const WALLET_OWN_FNS: [&str; 4] = ["emit", "next_effect", "main_hidden", "take_cred_log"];

/// The yw-app production sources as test builds compile them (2026-11-22, S4 W14a): as
/// [`production_code`] leaves them, but with their `#[cfg(test)]` items kept.
fn test_build_code() -> Vec<Src> {
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
                if !is_test_file(false, &rel) {
                    let text = std::fs::read_to_string(&path).unwrap();
                    found.push(Src::new(format!("yw-app/src/{rel}"), code_only(&text)));
                }
            }
        }
    }
    found.sort_by(|a, b| a.file.cmp(&b.file));
    found
}

/// `wallet_fns_name_no_shell_in_test_builds` (2026-11-22, S4 W14a, preflight critic C5):
/// [`wallet_fns_name_no_shell`] reads the code release builds compile, so a `#[cfg(test)]`
/// statement of a listed fn that calls a shell fn went unseen — the flow's calls of
/// `assert_flow_and_window_in_step` (a `#[cfg(test)]` fn of the shell that reads
/// `approval_win`) in `on_approval_opened`, `close_approval_window` and `on_approval_input`
/// were such statements, and W14c, which makes the listed fns `impl Wallet`, would not compile
/// in test builds. Here the same scan runs over the yw-app sources with their `#[cfg(test)]`
/// items kept ([`test_build_code`]): no listed fn calls an `impl App` fn of the test build's
/// shell closure ([`shell_namers`] plus [`SHELL_FNS`], at any depth, [`shell_closure`]) that
/// the release build's scan does not already reject, i.e. a test-only shell fn. It finds
/// `assert_flow_and_window_in_step` among them (A-20). 2026-11-22 (S4c W14c-2): the listed fns
/// are read from the test build's `impl Wallet` blocks (the compiler now also rejects such a
/// call there; the scan keeps the reason readable). 2026-11-22 (S4c W14c review): and no
/// `impl Wallet` fn of the test build names the type `App` ([`names_app`]).
#[test]
fn wallet_fns_name_no_shell_in_test_builds() {
    // 2026-11-23 (S4d E1): the wallet fns are yw-engine's, compiled without yw-app's `cfg(test)`,
    // so a test build of yw-app holds no `impl Wallet` fn (before E1, this scanned them for calls
    // of test-only shell fns and the type `App`). The test-only pairing check stays the shell's.
    let files = test_build_code();
    assert!(
        impl_fns(&files, "Wallet").is_empty(),
        "a yw-app test build holds no impl Wallet fn"
    );
    assert!(
        app_fns(&files).contains_key("assert_flow_and_window_in_step"),
        "the test builds' pairing check is a shell fn"
    );
}

/// `the_only_consume_is_wallet_code` (2026-11-22, S4 W14b; plan W14b row "the only `.consume(`
/// is in `wallet_approval.rs`", in place since the owner's second batch keeps the approval code
/// in `app_approval.rs`; AGENTS.md §6 "Single use", plan §6 "only `consume` creates
/// `Approved`"): the production code of yw-app and yw-engine (test items blanked) holds exactly
/// one `.consume(` call, the approval store's in `consume_and_sign` of `app_approval.rs`, on the
/// flow's issued request, and that fn is wallet code ([`WALLET_FNS`], W14b), so no shell fn
/// consumes and W14c makes it `impl Wallet`. Before W14b nothing checked the count; the store's
/// own tests (`x14_one_shot_consumption`) pin that only `consume` makes an `Approved`.
///
/// 2026-11-22 (S4 W14ab review): the check found only the method-call text `.consume(`, so a
/// path call (`ApprovalStore::consume(&mut self.evm.store, …)`, `<_>::consume(`) or the method
/// named as a value (`.map(ApprovalStore::consume)`) got past it. It now counts every
/// `consume` identifier token of the production code (whole word, a `fn consume` too), so the
/// one site is the only mention of the name at all.
#[test]
fn the_only_consume_is_wallet_code() {
    let files = production_code();
    let mut sites = Vec::new();
    for src in &files {
        let bytes = src.code.as_bytes();
        for (at, word) in src.code.match_indices("consume") {
            let before = at.checked_sub(1).and_then(|i| bytes.get(i).copied());
            let after = bytes.get(at + word.len()).copied();
            if before.is_some_and(is_ident) || after.is_some_and(is_ident) {
                continue;
            }
            let func = fn_at(&src.code, &src.blocks, at).unwrap_or_default();
            sites.push(format!("{}:{func}", src.file));
        }
    }
    assert_eq!(
        sites,
        ["yw-engine/src/wallet/app_approval.rs:consume_and_sign"]
    );
    assert!(
        WALLET_FNS.contains(&("W14b", "consume_and_sign")),
        "consume_and_sign is wallet code"
    );
    let body = fn_bodies(
        src_of(&files, "yw-engine/src/wallet/app_approval.rs"),
        "consume_and_sign",
    );
    assert_eq!(body.len(), 1, "one consume_and_sign");
    let body = normalized(body[0]);
    for step in [
        "let Some(request) = flow.issued().cloned() else { return; };",
        "match self.evm.store.consume(request.id, request.digest, now) {",
    ] {
        assert!(body.contains(step), "consume_and_sign lost {step}");
    }
}

// ---- S7: the approval capability is engine-only (2026-11-23, S4d E4) ------------------------

/// The enums whose variant `Approved` [`capability_names`] lets through after `<enum>::`: an
/// approval queue's outcome and an approval window's status, not the consent token
/// `yw_core::approval::Approved`. Each is checked to be a yw-engine enum with that variant.
const APPROVED_VARIANT_OWNERS: [&str; 2] = ["QueueOutcome", "InteractionStatus"];

/// The wallet's consent steps that take no `Approved` themselves (critique A-15): the one
/// `consume` (`consume_and_sign`), the card step's PIN answers, which sign with or drop the
/// approval it holds (`card_submit`, `card_cancel`), and the signing waiter that a consumed
/// approval answers through (`push_sign_waiter`). With the `impl Wallet` fns that take an
/// `Approved` ([`wallet_fn_heads`]) they are crate-private in yw-engine and unnamed in yw-app's
/// code. 2026-11-23 (S4d final review, A-15, D-22): also the steps that complete a user's
/// consent or a hold without an `Approved`: the dApp connect windows' grant writes
/// (`connect_approved`, `chain_connect_approved`, which save a grant and answer the site), the
/// reset that the 2 s hold guards (`reset_execute`), the W08 backup holds' completions
/// (`mn_hold_complete`, `yk_hold_complete`) and the `YubiKey` PIN window's open
/// (`yk_open_card_secret`). E1 had made them `#[doc(hidden)] pub` because only yw-app's tests
/// called them; they are `pub(crate)` again and the tests reach them through
/// `testkit::WalletTestExt`.
const CONSENT_STEPS: [&str; 10] = [
    "consume_and_sign",
    "card_submit",
    "card_cancel",
    "push_sign_waiter",
    "connect_approved",
    "chain_connect_approved",
    "reset_execute",
    "mn_hold_complete",
    "yk_hold_complete",
    "yk_open_card_secret",
];

/// The `impl Wallet` fns that take an `Approved` which the S4d preflight (row E4) and critique
/// A-15 name: the scan must find each among them (A-20).
const NAMED_APPROVAL_TAKERS: [&str; 7] = [
    "card_begin",
    "dispatch_evm_sign",
    "sol_consumed",
    "sol_dapp_consumed",
    "btc_consumed",
    "hc_consumed",
    "zec_consumed",
];

/// yw-engine's always-compiled test entries (`testkit`) and the traits and probe through which
/// yw-app's tests reach the consent steps (spec/15 §18 28). `testkit_is_named_only_by_tests`
/// (`card_pcsc.rs`) keeps the module out of yw-app's and yw-engine's code; here the names too.
const TEST_ENTRIES: [&str; 5] = [
    "testkit",
    "WalletTestExt",
    "FlowTestExt",
    "SessionTestExt",
    "StoreProbe",
];

/// The fields of yw-engine's wallet that hold an `Approved` or the `ApprovalStore` (type,
/// field): the scan must find each (A-20), and none is `pub`.
const APPROVAL_HOLDERS: [(&str, &str); 4] = [
    ("CardStep", "approved"),
    ("EvmUi", "store"),
    ("PendingDappSign", "approved"),
    ("PendingSign", "approved"),
];

/// The `pub` fns of yw-engine's wallet that take or return an `Approved` by value (file, fn,
/// reason). Every other fn there that does is `pub(crate)` or private.
const PUB_APPROVAL_FNS: [(&str, &str, &str); 1] = [(
    "yw-engine/src/wallet/app_btc.rs",
    "consumed",
    "the Bitcoin controller `BtcUi`'s signing step (spec/08 §11.1): `Wallet::btc_consumed` calls \
     it, and the pinned helper `impl Harness` of the frozen `tests/btc_app_flow.rs` drives the \
     controller with its own store; yw-app's code cannot hold an `Approved` to give it and names \
     no `consumed`",
)];

/// The identifier tokens of `code` (not starting with a digit) with their offsets.
fn ident_tokens(code: &str) -> Vec<(usize, &str)> {
    let bytes = code.as_bytes();
    let mut tokens = Vec::new();
    let mut at = 0;
    while at < bytes.len() {
        if is_ident(bytes[at]) {
            let start = at;
            while at < bytes.len() && is_ident(bytes[at]) {
                at += 1;
            }
            if !bytes[start].is_ascii_digit() {
                tokens.push((start, &code[start..at]));
            }
        } else {
            at += 1;
        }
    }
    tokens
}

/// Whether the `Approved` at `at` is the variant of one of [`APPROVED_VARIANT_OWNERS`]
/// (`QueueOutcome::Approved`), not the consent token.
fn is_approved_variant(code: &str, at: usize) -> bool {
    code[..at]
        .trim_end()
        .strip_suffix("::")
        .is_some_and(|before| {
            let before = before.trim_end();
            APPROVED_VARIANT_OWNERS
                .iter()
                .any(|owner| ends_with_word(before, owner))
        })
}

/// Whether the path after an `approval` that ends at `after` is its `store` module:
/// `approval::store`, or a `{ … }` group after `approval::` that names `store`.
fn names_the_store_module(code: &str, after: usize) -> bool {
    let Some(rest) = code[after..].trim_start().strip_prefix("::") else {
        return false;
    };
    let rest = rest.trim_start();
    if rest.starts_with('{') {
        let open = code.len() - rest.len();
        return has_word(&code[open..=close_of(code.as_bytes(), open)], "store");
    }
    starts_with_word(rest, "store")
}

/// The keywords that, right before a variant owner's name, make that name something of yw-app's
/// own (2026-11-23, S4 E4 review): `use yw_core::approval as QueueOutcome;` or `mod
/// InteractionStatus { … }` would let `QueueOutcome::Approved` name the consent token.
const OWNER_RENAMES: [&str; 7] = ["as", "mod", "type", "enum", "struct", "union", "trait"];

/// The identifier right before offset `at` in `code` (after blanks), if any.
fn word_before(code: &str, at: usize) -> &str {
    let before = code[..at].trim_end();
    let start = before
        .rfind(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .map_or(0, |n| n + 1);
    &before[start..]
}

/// The names in `code` (comments and strings blanked) that would give it the approval
/// capability, with their offsets: the type `Approved` (not a variant,
/// [`is_approved_variant`]), `ApprovalStore`, `consume`, a path to `approval::store`, a
/// `consumed`/`*_consumed` fn, the consent steps `steps`, the approval carriers `carriers`
/// (the `KeyJob`/`KeyOutcome` variants and the other yw-engine types and aliases that carry an
/// `Approved`, [`approval_carriers`]), the [`TEST_ENTRIES`], and (2026-11-23, S4 E4 review) a
/// variant owner made yw-app's own ([`OWNER_RENAMES`]).
fn capability_names(
    code: &str,
    steps: &BTreeSet<String>,
    carriers: &BTreeSet<String>,
) -> Vec<(usize, String)> {
    let mut found = Vec::new();
    for (at, token) in ident_tokens(code) {
        let hit = match token {
            "Approved" => (!is_approved_variant(code, at)).then(|| token.to_owned()),
            "ApprovalStore" | "consume" => Some(token.to_owned()),
            "approval" => {
                names_the_store_module(code, at + token.len()).then(|| "approval::store".to_owned())
            }
            owner if APPROVED_VARIANT_OWNERS.contains(&owner) => {
                let keyword = word_before(code, at);
                OWNER_RENAMES
                    .contains(&keyword)
                    .then(|| format!("{keyword} {owner}"))
            }
            _ => (token == "consumed"
                || token.ends_with("_consumed")
                || steps.contains(token)
                || carriers.contains(token)
                || TEST_ENTRIES.contains(&token))
            .then(|| token.to_owned()),
        };
        if let Some(name) = hit {
            found.push((at, name));
        }
    }
    found
}

/// The 1-based line of offset `at` in `code` ([`code_only`] keeps every newline).
fn line_at(code: &str, at: usize) -> usize {
    code[..at].matches('\n').count() + 1
}

/// The chunks of the `{ … }` or `( … )` body that opens at `open`, split at its own commas.
fn body_items(code: &str, open: usize) -> Vec<&str> {
    let bytes = code.as_bytes();
    let mut items = Vec::new();
    let mut depth = 0_i32;
    let mut start = open + 1;
    for (at, &byte) in bytes.iter().enumerate().skip(open) {
        match byte {
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' | b'}' => {
                depth -= 1;
                if depth == 0 {
                    items.push(&code[start..at]);
                    break;
                }
            }
            b',' if depth == 1 => {
                items.push(&code[start..at]);
                start = at + 1;
            }
            _ => {}
        }
    }
    items
        .into_iter()
        .map(without_attributes)
        .filter(|item| !item.is_empty())
        .collect()
}

/// `item` trimmed, without its leading `#[…]` attributes.
fn without_attributes(item: &str) -> &str {
    let mut rest = item.trim();
    while rest.starts_with("#[") {
        let end = paren_like_end(rest.as_bytes());
        rest = rest[end..].trim_start();
    }
    rest
}

/// The offset after the `]` that closes the `[` of a leading `#[`.
fn paren_like_end(bytes: &[u8]) -> usize {
    let mut depth = 0_usize;
    for (at, &byte) in bytes.iter().enumerate() {
        match byte {
            b'[' => depth += 1,
            b']' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return at + 1;
                }
            }
            _ => {}
        }
    }
    bytes.len()
}

/// The leading identifier of `text`.
fn leading_ident(text: &str) -> String {
    text.chars()
        .take_while(|&c| c.is_ascii_alphanumeric() || c == '_')
        .collect()
}

/// The approval types themselves: the consent token and the store that makes it.
const APPROVAL_TYPES: [&str; 2] = ["Approved", "ApprovalStore"];

/// The job enums whose own variants [`approval_carriers`] lists (and yw-app's code does not
/// name) instead of the enum: yw-app's shell moves their values between the wallet and the key
/// worker, so the enums themselves stay nameable.
const JOB_ENUMS: [&str; 2] = ["KeyJob", "KeyOutcome"];

/// The approval words of `extra` with [`APPROVAL_TYPES`] (`with_store`) or `Approved` only.
fn approval_words(extra: &BTreeSet<String>, with_store: bool) -> BTreeSet<String> {
    let mut words = extra.clone();
    for word in APPROVAL_TYPES {
        if with_store || word == "Approved" {
            words.insert(word.to_owned());
        }
    }
    words
}

/// What a type definition is.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum TypeKind {
    Struct,
    Enum,
    Alias,
}

/// One type definition of scanned code ([`type_defs`]): a `struct` or `enum` with a body (its
/// fields or variants, [`body_items`]) or a `type` alias with a right-hand side (one item).
struct TypeDef<'a> {
    name: String,
    kind: TypeKind,
    items: Vec<&'a str>,
}

/// Every type definition of `src` ([`TypeDef`]); a unit struct, an alias without a right-hand
/// side (a trait's associated type) and `r#type` are left out.
fn type_defs(src: &Src) -> Vec<TypeDef<'_>> {
    let code = &src.code;
    let bytes = code.as_bytes();
    let mut defs = Vec::new();
    for (keyword, kind) in [
        ("struct ", TypeKind::Struct),
        ("enum ", TypeKind::Enum),
        ("type ", TypeKind::Alias),
    ] {
        for (at, _) in code.match_indices(keyword) {
            if at > 0 && (is_ident(bytes[at - 1]) || bytes[at - 1] == b'#') {
                continue;
            }
            let name = leading_ident(code[at + keyword.len()..].trim_start());
            if name.is_empty() {
                continue;
            }
            let items = if kind == TypeKind::Alias {
                let Some(eq) = code[at..].find(['=', ';', '{']).map(|n| at + n) else {
                    continue;
                };
                if bytes[eq] != b'=' {
                    continue;
                }
                let end = code[eq..].find(';').map_or(code.len(), |n| eq + n);
                vec![code[eq + 1..end].trim()]
            } else {
                let Some(open) = code[at..].find(['{', '(', ';']).map(|n| at + n) else {
                    continue;
                };
                if bytes[open] == b';' {
                    continue;
                }
                body_items(code, open)
            };
            defs.push(TypeDef { name, kind, items });
        }
    }
    defs
}

/// Whether `item` of a `kind` definition names one of `words` as a type: an enum item's first
/// token is its variant's own name, and `Approved` after `QueueOutcome::` or
/// `InteractionStatus::` is a variant ([`is_approved_variant`]).
fn item_names(item: &str, kind: TypeKind, words: &BTreeSet<String>) -> bool {
    ident_tokens(item)
        .into_iter()
        .enumerate()
        .any(|(index, (at, token))| {
            !(kind == TypeKind::Enum && index == 0)
                && words.contains(token)
                && !(token == "Approved" && is_approved_variant(item, at))
        })
}

/// The name of `item` of a `kind` definition: a field's or a variant's name (a tuple field's
/// leading type), or `type` for an alias's right-hand side.
fn item_name(item: &str, kind: TypeKind) -> String {
    if kind == TypeKind::Alias {
        return "type".to_owned();
    }
    leading_ident(
        item.strip_prefix("pub(crate)")
            .or_else(|| item.strip_prefix("pub(super)"))
            .or_else(|| item.strip_prefix("pub"))
            .unwrap_or(item)
            .trim_start(),
    )
}

/// The type aliases of `files` that stand for an approval type ([`APPROVAL_TYPES`]), directly
/// or through another such alias (2026-11-23, S4 E4 review): `pub type T = Box<Approved>;`
/// would hide the type from [`takes_approval_by_value`] and [`approval_holders`], which take
/// these names too. The signer aliases (`SolSigner`, `BtcSigner`, …, `dyn FnMut` steps that
/// take an `Approved`) are among them.
fn approval_aliases(files: &[&Src]) -> BTreeSet<String> {
    let defs: Vec<TypeDef<'_>> = files.iter().flat_map(|src| type_defs(src)).collect();
    let mut aliases = BTreeSet::new();
    loop {
        let words = approval_words(&aliases, true);
        let grown: BTreeSet<String> = defs
            .iter()
            .filter(|def| {
                def.kind == TypeKind::Alias
                    && def
                        .items
                        .iter()
                        .any(|item| item_names(item, def.kind, &words))
            })
            .map(|def| def.name.clone())
            .collect();
        if grown.len() == aliases.len() {
            return aliases;
        }
        aliases = grown;
    }
}

/// What yw-engine's code outside the wallet carries an `Approved` (or the `ApprovalStore`) in
/// ([`approval_carriers`]).
#[derive(Default, Debug)]
struct Carriers {
    /// The [`JOB_ENUMS`] variants that hold one themselves or in a struct or alias that does
    /// (`SignEvm`, `CardUnused`, …): yw-app's code names none.
    variants: BTreeSet<String>,
    /// Every other type or alias that holds one, directly or through another such type, with
    /// the items (fields, variants; `type` for an alias) that do: `ZecKeyJob` (`Sign`,
    /// `SignCard`), the signer aliases, …. yw-app's code names none of these types.
    types: BTreeMap<String, BTreeSet<String>>,
    /// The [`JOB_ENUMS`] variants that hold one only inside such an enum, with that enum
    /// (`Zec`, `ZecKeyJob`): taking the `Approved` out (or putting one in) names the enum's
    /// variant, so the enum is barred and the variant may stay nameable.
    nested: BTreeSet<(String, String)>,
}

impl Carriers {
    /// The names yw-app's code must not use: the variants and the types.
    fn barred(&self) -> BTreeSet<String> {
        let mut barred = self.variants.clone();
        barred.extend(self.types.keys().cloned());
        barred
    }
}

/// The approval carriers of `files` (2026-11-23, S4 E4 review; before, only the variants of
/// `events.rs`'s enums that named `Approved` themselves, which missed `KeyJob::Zec`'s
/// `ZecKeyJob::Sign`/`SignCard`): every type and alias that holds an approval type
/// ([`APPROVAL_TYPES`]) or another carrier, to a fixed point that does not pass through the
/// [`JOB_ENUMS`] (yw-app's code names those; it names none of their carrying variants instead).
fn approval_carriers(files: &[&Src]) -> Carriers {
    let defs: Vec<TypeDef<'_>> = files.iter().flat_map(|src| type_defs(src)).collect();
    let mut words = approval_words(&BTreeSet::new(), true);
    loop {
        let before = words.len();
        for def in &defs {
            if !JOB_ENUMS.contains(&def.name.as_str())
                && def
                    .items
                    .iter()
                    .any(|item| item_names(item, def.kind, &words))
            {
                words.insert(def.name.clone());
            }
        }
        if words.len() == before {
            break;
        }
    }
    let enums: BTreeSet<String> = defs
        .iter()
        .filter(|def| def.kind == TypeKind::Enum && words.contains(&def.name))
        .map(|def| def.name.clone())
        .filter(|name| !JOB_ENUMS.contains(&name.as_str()))
        .collect();
    let direct: BTreeSet<String> = words.difference(&enums).cloned().collect();
    let mut carriers = Carriers::default();
    for def in &defs {
        for item in def
            .items
            .iter()
            .filter(|item| item_names(item, def.kind, &words))
        {
            let name = item_name(item, def.kind);
            if !JOB_ENUMS.contains(&def.name.as_str()) {
                carriers
                    .types
                    .entry(def.name.clone())
                    .or_default()
                    .insert(name);
            } else if item_names(item, def.kind, &direct) {
                carriers.variants.insert(name);
            } else {
                for (_, token) in ident_tokens(item).into_iter().skip(1) {
                    if enums.contains(token) {
                        carriers.nested.insert((name.clone(), token.to_owned()));
                    }
                }
            }
        }
    }
    carriers
}

/// The return type of the fn signature `sig` (after its parameters' `->`), or nothing.
fn return_type(sig: &str) -> &str {
    let bytes = sig.as_bytes();
    let mut depth = 0_i32;
    for (at, &byte) in bytes.iter().enumerate() {
        match byte {
            b'(' | b'[' => depth += 1,
            b')' | b']' => depth -= 1,
            b'-' if depth == 0 && bytes.get(at + 1) == Some(&b'>') => return &sig[at + 2..],
            _ => {}
        }
    }
    ""
}

/// Whether the fn signature `sig` takes or returns an `Approved` (or one of `words`, its
/// aliases, 2026-11-23 S4 E4 review) by value (`Approved`, `Box<Approved>`,
/// `Option<Box<Approved>>`, …), not only a reference to one.
fn takes_approval_by_value(sig: &str, words: &BTreeSet<String>) -> bool {
    let words = approval_words(words, false);
    ident_tokens(sig).into_iter().any(|(at, token)| {
        if !words.contains(token) {
            return false;
        }
        let mut before: String = sig[..at].split_whitespace().collect();
        // The path to the type (`yw_core::approval::`) and a lifetime are not the borrow.
        while let Some(stripped) = before.strip_suffix("::") {
            let keep = stripped.trim_end_matches(|c: char| c.is_ascii_alphanumeric() || c == '_');
            before = keep.to_owned();
        }
        let before = before.trim_end_matches("mut");
        let before =
            before.trim_end_matches(|c: char| c.is_ascii_alphanumeric() || c == '_' || c == '\'');
        !before.ends_with('&')
    })
}

/// One fn of yw-engine's wallet: its file, name, signature (from `fn`), whether it is `pub` and
/// whether it is an `impl Wallet` fn.
struct WalletFnHead {
    file: String,
    name: String,
    sig: String,
    public: bool,
    of_wallet: bool,
}

/// Every fn of yw-engine's wallet (`yw-engine/src/wallet/`, production code) with its head.
fn wallet_fn_heads(files: &[Src]) -> Vec<WalletFnHead> {
    fn_heads(files, |file| file.starts_with("yw-engine/src/wallet/"))
}

/// Every fn with a body of the files of `files` that `keep` keeps, with its head (2026-11-23,
/// S4 E4 review: also yw-engine outside its wallet, [`assert_engine_side`]).
fn fn_heads(files: &[Src], keep: impl Fn(&str) -> bool) -> Vec<WalletFnHead> {
    let mut found = Vec::new();
    for src in files.iter().filter(|src| keep(&src.file)) {
        let impls: Vec<(usize, usize)> = src
            .blocks
            .iter()
            .filter(|block| {
                without_attributes(&normalized(head(&src.code, block.open))) == "impl Wallet"
            })
            .map(|block| (block.open, block.close))
            .collect();
        for block in &src.blocks {
            let block_head = head(&src.code, block.open);
            let Some((at, _)) = block_head
                .match_indices("fn ")
                .find(|&(at, _)| at == 0 || !is_ident(block_head.as_bytes()[at - 1]))
            else {
                continue;
            };
            let sig = &block_head[at..];
            found.push(WalletFnHead {
                file: src.file.clone(),
                name: leading_ident(sig["fn ".len()..].trim_start()),
                sig: normalized(sig),
                public: block_head[..at]
                    .split_whitespace()
                    .any(|word| word == "pub"),
                of_wallet: impls
                    .iter()
                    .any(|&(open, close)| open < block.open && block.close < close),
            });
        }
    }
    found
}

/// The fields of yw-engine's wallet types that hold an `Approved` or an `ApprovalStore`: (type,
/// field, whether the field is `pub`), for brace structs and tuple structs, and for enums
/// (a variant is `pub` with a `pub enum`).
///
/// 2026-11-23 (S4 E4 review): also a field of an alias of either (`words`,
/// [`approval_aliases`]), and an enum's variant name is not read as a type.
fn approval_holders(files: &[Src], words: &BTreeSet<String>) -> Vec<(String, String, bool)> {
    let words = approval_words(words, true);
    let mut found = Vec::new();
    for src in files
        .iter()
        .filter(|src| src.file.starts_with("yw-engine/src/wallet/"))
    {
        let code = &src.code;
        for keyword in ["struct ", "enum "] {
            for (at, _) in code.match_indices(keyword) {
                if at > 0 && is_ident(code.as_bytes()[at - 1]) {
                    continue;
                }
                let name = leading_ident(code[at + keyword.len()..].trim_start());
                let Some(open) = code[at..].find(['{', '(', ';']).map(|n| at + n) else {
                    continue;
                };
                if code.as_bytes()[open] == b';' {
                    continue;
                }
                let line_start = code[..at].rfind(['\n', ';', '}', '{']).map_or(0, |n| n + 1);
                let enum_public = code[line_start..at]
                    .split_whitespace()
                    .any(|word| word == "pub");
                let kind = if keyword == "enum " {
                    TypeKind::Enum
                } else {
                    TypeKind::Struct
                };
                for item in body_items(code, open) {
                    if item_names(item, kind, &words) {
                        let public = if keyword == "enum " {
                            enum_public
                        } else {
                            item.strip_prefix("pub")
                                .is_some_and(|rest| rest.starts_with(char::is_whitespace))
                        };
                        found.push((name.clone(), item_name(item, kind), public));
                    }
                }
            }
        }
    }
    found
}

/// S7 `approval_capability_is_engine_only` (2026-11-23, spec/15 §11.4 S4d E4; plan §4.4 S7,
/// D-22, critique A-15 and A-20; S4d preflight row E4; [03] §11.5, AGENTS.md §6 "Single use"):
/// since E1 the approval flow, the store and every consent step are yw-engine's, and yw-app's
/// code (its `src` without test files and `#[cfg(test)]` items, [`production_code`]) holds no
/// way to the approval capability. It names no:
///
/// - type `Approved` (`QueueOutcome::Approved` and `InteractionStatus::Approved` are variants),
///   `ApprovalStore`, `consume` (in any call form) or path to `yw_core::approval::store`;
/// - consent step: an `impl Wallet` fn that takes an `Approved` (found in the engine, so a new
///   one is covered), [`CONSENT_STEPS`], or any `consumed`/`*_consumed` fn;
/// - approval carrier ([`approval_carriers`], found in yw-engine outside its wallet): a
///   `KeyJob`/`KeyOutcome` variant that carries an `Approved` (`SignEvm`, `CardUnused`, …), or
///   any other type or alias that carries one, directly or nested (`ZecKeyJob`, whose `Sign` and
///   `SignCard` hold one inside `KeyJob::Zec`; the signer aliases), so the shell cannot take one
///   out of a worker's event or a queued job, or put one in a job, by name;
/// - yw-engine test entry ([`TEST_ENTRIES`]);
/// - variant owner made yw-app's own ([`OWNER_RENAMES`]: `use … as QueueOutcome`).
///
/// In yw-engine's wallet every fn that takes or returns an `Approved` (or an alias of one,
/// [`approval_aliases`]) by value, the consent steps among them, is `pub(crate)` or private (but
/// [`PUB_APPROVAL_FNS`]), and every field that holds an `Approved` or the `ApprovalStore` is not
/// `pub` ([`APPROVAL_HOLDERS`]); outside the wallet no `pub` fn returns an `Approved` or a
/// carrier by value. The wallet holds exactly the one `consume` of
/// [`the_only_consume_is_wallet_code`]. The check finds what it looks for (over 50 yw-app files,
/// the named takers, holders and carriers, the variant owners, A-20) and its readers fail on
/// made-up code (`approval_capability_names_on_made_up_code`,
/// `approval_takers_holders_and_carriers_on_made_up_code`, `approval_carriers_on_made_up_code`).
///
/// 2026-11-23 (S4 E4 review): before, the carriers were read from `events.rs` alone, as the
/// variants that named `Approved` themselves (13); `KeyJob::Zec(Box<ZecKeyJob>)` names no
/// `Approved`, so yw-app's code could pop a `KeyJob::Zec` from the key queue and take the
/// `Approved` out of `ZecKeyJob::Sign` unseen (a mutation probe in `app_effects.rs` passed).
/// Now every yw-engine type outside the wallet is read, to a fixed point ([`Carriers`]), aliases
/// are resolved, and a renamed variant owner is refused.
#[test]
fn approval_capability_is_engine_only() {
    let files = production_code();
    let engine: Vec<&Src> = files
        .iter()
        .filter(|src| src.file.starts_with("yw-engine/"))
        .collect();
    let aliases = approval_aliases(&engine);
    let heads = wallet_fn_heads(&files);
    let takers: BTreeSet<String> = heads
        .iter()
        .filter(|head| head.of_wallet && takes_approval_by_value(&head.sig, &aliases))
        .map(|head| head.name.clone())
        .collect();
    for name in NAMED_APPROVAL_TAKERS {
        assert!(takers.contains(name), "{name} takes an Approved");
    }
    let mut steps = takers.clone();
    for name in CONSENT_STEPS {
        assert_eq!(
            heads
                .iter()
                .filter(|head| head.of_wallet && head.name == name)
                .count(),
            1,
            "one impl Wallet fn {name}"
        );
        steps.insert(name.to_owned());
    }
    assert_engine_side(&files, &heads, &steps, &aliases);
    let outside: Vec<&Src> = engine
        .iter()
        .copied()
        .filter(|src| !src.file.starts_with("yw-engine/src/wallet/"))
        .collect();
    let carriers = approval_carriers(&outside);
    assert_carriers_found(&carriers, &aliases);
    let mut barred = carriers.barred();
    barred.extend(aliases.iter().cloned());
    let mut leaks = Vec::new();
    for head in fn_heads(&files, |file| {
        file.starts_with("yw-engine/") && !file.starts_with("yw-engine/src/wallet/")
    }) {
        if head.public && takes_approval_by_value(return_type(&head.sig), &barred) {
            leaks.push(format!("{}:{}", head.file, head.name));
        }
    }
    assert!(
        leaks.is_empty(),
        "pub fns outside the wallet that return an Approved or a carrier: {leaks:?}"
    );
    let app: Vec<&Src> = files
        .iter()
        .filter(|src| src.file.starts_with("yw-app/"))
        .collect();
    assert!(app.len() > 50, "{} yw-app files scanned", app.len());
    let mut found = Vec::new();
    for src in app {
        for (at, name) in capability_names(&src.code, &steps, &barred) {
            found.push(format!("{}:{} {name}", src.file, line_at(&src.code, at)));
        }
    }
    assert!(
        found.is_empty(),
        "yw-app code names the approval capability:\n{}",
        found.join("\n")
    );
}

/// The carriers [`approval_carriers`] must find (A-20; 2026-11-23, S4 E4 review): the
/// `KeyJob`/`KeyOutcome` variants that hold an `Approved` (13: the twelve `Sign*` jobs and
/// `CardUnused`), `ZecKeyJob` with exactly its `Sign` and `SignCard` inside `KeyJob::Zec` (15
/// carrying variants in all), and the signer aliases among `aliases`.
fn assert_carriers_found(carriers: &Carriers, aliases: &BTreeSet<String>) {
    assert!(
        carriers.variants.contains("SignEvm")
            && carriers.variants.contains("CardUnused")
            && carriers.variants.len() >= 13,
        "the variants that carry an Approved: {carriers:?}"
    );
    let zec: BTreeSet<String> = ["Sign", "SignCard"].map(str::to_owned).into();
    assert_eq!(
        carriers.types.get("ZecKeyJob"),
        Some(&zec),
        "ZecKeyJob carries an Approved: {carriers:?}"
    );
    assert!(
        carriers.variants.len() + zec.len() >= 15,
        "15 carrying variants: {carriers:?}"
    );
    assert!(
        carriers
            .nested
            .contains(&("Zec".to_owned(), "ZecKeyJob".to_owned())),
        "KeyJob::Zec carries ZecKeyJob: {carriers:?}"
    );
    for alias in ["SolSigner", "BtcSigner", "ZecSigner"] {
        assert!(
            aliases.contains(alias) && carriers.types.contains_key(alias),
            "{alias} takes an Approved: {aliases:?}"
        );
    }
}

/// The engine half of [`approval_capability_is_engine_only`]: the consent steps `steps` and
/// every wallet fn that takes or returns an `Approved` (or one of its `aliases`) by value are
/// not `pub` (but [`PUB_APPROVAL_FNS`]); the holders are found and not `pub`; the variant owners
/// have the variant; the wallet holds one `consume`, in `consume_and_sign`.
fn assert_engine_side(
    files: &[Src],
    heads: &[WalletFnHead],
    steps: &BTreeSet<String>,
    aliases: &BTreeSet<String>,
) {
    assert!(heads.len() > 900, "{} wallet fns", heads.len());
    let mut public = Vec::new();
    for head in heads {
        let consent = head.of_wallet && steps.contains(&head.name);
        if head.public && (consent || takes_approval_by_value(&head.sig, aliases)) {
            public.push((head.file.as_str(), head.name.as_str()));
        }
    }
    let allowed: Vec<(&str, &str)> = PUB_APPROVAL_FNS
        .iter()
        .map(|&(file, name, _)| (file, name))
        .collect();
    assert_eq!(public, allowed, "pub wallet fns that take an Approved");
    let holders = approval_holders(files, aliases);
    for (ty, field) in APPROVAL_HOLDERS {
        assert!(
            holders.iter().any(|(t, f, _)| t == ty && f == field),
            "{ty}.{field} holds an Approved or the store: {holders:?}"
        );
    }
    let open: Vec<_> = holders.iter().filter(|(_, _, public)| *public).collect();
    assert!(open.is_empty(), "pub approval holders: {open:?}");
    for owner in APPROVED_VARIANT_OWNERS {
        let found = files
            .iter()
            .filter(|src| src.file.starts_with("yw-engine/"))
            .flat_map(|src| enum_variants(src, owner))
            .any(|variant| variant == "Approved");
        assert!(
            found,
            "{owner} is a yw-engine enum with the variant Approved"
        );
    }
    let mut consumes = Vec::new();
    for src in files
        .iter()
        .filter(|src| src.file.starts_with("yw-engine/src/wallet/"))
    {
        for (at, token) in ident_tokens(&src.code) {
            if token == "consume" {
                let func = fn_at(&src.code, &src.blocks, at).unwrap_or_default();
                consumes.push(format!("{}:{func}", src.file));
            }
        }
    }
    assert_eq!(
        consumes,
        ["yw-engine/src/wallet/app_approval.rs:consume_and_sign"],
        "the wallet's one consume"
    );
}

/// The variants of `enum <name>` in `src`.
fn enum_variants(src: &Src, name: &str) -> Vec<String> {
    let mut variants = Vec::new();
    for block in &src.blocks {
        let block_head = normalized(head(&src.code, block.open));
        let words: Vec<&str> = block_head.split_whitespace().collect();
        if words.windows(2).any(|pair| pair == ["enum", name]) {
            variants.extend(
                body_items(&src.code, block.open)
                    .into_iter()
                    .map(leading_ident),
            );
        }
    }
    variants
}

#[test]
fn approval_capability_names_on_made_up_code() {
    let steps: BTreeSet<String> = ["card_begin", "dispatch_evm_sign", "push_sign_waiter"]
        .into_iter()
        .map(str::to_owned)
        .collect();
    let carriers: BTreeSet<String> = ["SignEvm", "CardUnused", "ZecKeyJob"]
        .into_iter()
        .map(str::to_owned)
        .collect();
    for (code, name) in [
        ("fn f(a: yw_core::approval::Approved) {}", "Approved"),
        ("let held: Option<Box<Approved>> = None;", "Approved"),
        ("use yw_core::approval::{ApprovalId, Approved};", "Approved"),
        ("use yw_core::approval::Approved as Token;", "Approved"),
        ("let x = some::alias::Approved;", "Approved"),
        ("let mut store = ApprovalStore::new();", "ApprovalStore"),
        ("let a = store.consume(id, digest, now);", "consume"),
        ("let a = <_>::consume(&mut s, id, d, n);", "consume"),
        ("ids.map(Store::consume)", "consume"),
        ("use yw_core::approval::store;", "approval::store"),
        (
            "use yw_core::approval::{ApprovalId, store::X};",
            "approval::store",
        ),
        ("self.wallet.card_begin(a, kind, None);", "card_begin"),
        (
            "Wallet::dispatch_evm_sign(w, t, a, i, f)",
            "dispatch_evm_sign",
        ),
        ("self.wallet.btc.consumed(ctx, a, &item);", "consumed"),
        ("self.wallet.sol_consumed(a, c, 0);", "sol_consumed"),
        (
            "let t = w.push_sign_waiter(SignWaiter::App);",
            "push_sign_waiter",
        ),
        ("KeyJob::SignEvm { approved, .. } => {}", "SignEvm"),
        (
            "if let KeyOutcome::CardUnused(a, _) = outcome {}",
            "CardUnused",
        ),
        ("use yw_engine::testkit::WalletTestExt;", "testkit"),
        ("let p: StoreProbe<'_> = w.evm_store_mut();", "StoreProbe"),
        // 2026-11-23 (S4 E4 review): the nested carrier and the renamed variant owners.
        (
            "if let Some((_, KeyJob::Zec(job))) = queue.pop() { \
             if let yw_engine::workers::journal::zec::ZecKeyJob::Sign { approved, .. } = *job {} }",
            "ZecKeyJob",
        ),
        (
            "use yw_engine::workers::journal::zec::ZecKeyJob::*;",
            "ZecKeyJob",
        ),
        ("use yw_core::approval as QueueOutcome;", "as QueueOutcome"),
        (
            "use yw_core::approval::{self as InteractionStatus};",
            "as InteractionStatus",
        ),
        (
            "mod QueueOutcome { pub use yw_core::approval::*; }",
            "mod QueueOutcome",
        ),
    ] {
        let found = capability_names(&code_only(code), &steps, &carriers);
        assert!(
            found.iter().any(|(_, found)| found == name),
            "{code}: {found:?}"
        );
    }
    for code in [
        "QueueOutcome::Approved => {}",
        "yw_engine::approval::QueueOutcome::Approved",
        "InteractionStatus :: Approved",
        "let consumed_at_ms = 0; let consumer = 1; let consumes = 2;",
        "struct ApprovedX; struct UnApproved; let approval_store = 0;",
        "use yw_engine::approval::{QueueOutcome, QueueSource};",
        "let s = \"Approved consume card_begin testkit\"; // ApprovalStore",
        "self.wallet.card_begins(); self.wallet.on_cmd(cmd);",
        "if let Some((_, KeyJob::Zec(job))) = queue.pop() { queue.push(KeyJob::Lock); }",
        "use yw_engine::approval::QueueOutcome as Outcome; match o { Outcome::Rejected => {} }",
    ] {
        let found = capability_names(&code_only(code), &steps, &carriers);
        assert!(found.is_empty(), "{code}: {found:?}");
    }
}

/// The set of `names`.
fn set_of(names: &[&str]) -> BTreeSet<String> {
    names.iter().map(|name| (*name).to_owned()).collect()
}

#[test]
fn approval_takers_holders_and_carriers_on_made_up_code() {
    let none = BTreeSet::new();
    for sig in [
        "fn f(&mut self, approved: Approved)",
        "fn f(a: yw_core::approval::Approved, b: u8)",
        "fn f(a: Box<Approved>)",
        "fn f() -> Result<(), Box<Approved>>",
        "fn f(a: &u8) -> Option<yw_core::approval::Approved>",
    ] {
        assert!(takes_approval_by_value(sig, &none), "{sig}");
    }
    for sig in [
        "fn f(a: &Approved)",
        "fn f(a: &yw_core::approval::Approved) -> u8",
        "fn f<'a>(a: &'a Approved)",
        "fn f(a: &mut Approved)",
        "fn f(o: QueueOutcome, a: ApprovedX)",
        "fn f(a: Held)",
    ] {
        assert!(!takes_approval_by_value(sig, &none), "{sig}");
    }
    // 2026-11-23 (S4 E4 review): an alias of the type is the type.
    let held = set_of(&["Held"]);
    assert!(takes_approval_by_value("fn f(a: Held)", &held));
    assert!(takes_approval_by_value("pub fn f() -> Option<Held>", &held));
    assert!(!takes_approval_by_value("fn f(a: &Held)", &held));
    assert_eq!(return_type("fn f(a: Held) -> u8"), " u8");
    assert_eq!(return_type("fn f(g: impl Fn(u8) -> Held)"), "");
    let src = Src::new(
        "yw-engine/src/wallet/made_up.rs".to_owned(),
        code_only(
            "pub struct A { pub approved: Box<Approved>, id: u64 }
pub struct B(pub(crate) ApprovalStore);
enum C { Held(Approved), Empty }
pub enum D { Sign { approved: Box<Approved> } }
struct E;
pub struct F { pub(crate) store: ApprovalStore, pub shown: u64 }
pub type Held = Box<yw_core::approval::Approved>;
pub type Again<'a> = Option<Held>;
pub enum Status { Approved, Rejected }
pub struct G { pub kept: Again<'static>, pub status: Status }",
        ),
    );
    let aliases = approval_aliases(&[&src]);
    assert_eq!(aliases, set_of(&["Again", "Held"]));
    assert_eq!(
        approval_holders(std::slice::from_ref(&src), &aliases),
        [
            ("A".to_owned(), "approved".to_owned(), true),
            ("B".to_owned(), "ApprovalStore".to_owned(), false),
            ("F".to_owned(), "store".to_owned(), false),
            ("G".to_owned(), "kept".to_owned(), true),
            ("C".to_owned(), "Held".to_owned(), false),
            ("D".to_owned(), "Sign".to_owned(), true),
        ]
    );
}

/// [`approval_carriers`] on made-up code (2026-11-23, S4 E4 review): a nested enum, a struct
/// and an alias that carry an `Approved`, to a fixed point that stops at the job enums.
#[test]
fn approval_carriers_on_made_up_code() {
    let events = Src::new(
        "yw-engine/src/events.rs".to_owned(),
        code_only(
            "pub enum KeyJob { Lock, SignEvm { ticket: u64, approved: Box<Approved> }, \
             #[doc(hidden)] Gone(Box<Approved>, u8), Load { a: Result<(), u8> }, \
             Zec(Box<crate::workers::journal::zec::NestJob>), Wrapped(Wrap), Aliased(Token) }
pub enum KeyOutcome { Done, Back(Box<NestJob>, u8) }
pub struct KeyQueue { jobs: Vec<KeyJob> }
pub struct Wrap { pub approved: Token }",
        ),
    );
    let nest = Src::new(
        "yw-engine/src/workers/journal_zec.rs".to_owned(),
        code_only(
            "pub enum NestJob { Public { n: u8 }, Sign { approved: Box<Approved> }, \
             SignCard(Box<Token>, u8) }
pub type Token = Approved;
pub type Signer<'a> = dyn FnMut(&Vault, Approved) -> u8 + 'a;
pub enum QueueOutcome { Approved, Rejected }
pub struct Plain { pub n: u8 }",
        ),
    );
    let carriers = approval_carriers(&[&events, &nest]);
    assert_eq!(
        carriers.variants,
        set_of(&["Aliased", "Gone", "SignEvm", "Wrapped"])
    );
    assert_eq!(
        carriers.types.keys().cloned().collect::<BTreeSet<_>>(),
        set_of(&["NestJob", "Signer", "Token", "Wrap"])
    );
    assert_eq!(
        carriers.types.get("NestJob"),
        Some(&set_of(&["Sign", "SignCard"]))
    );
    assert_eq!(
        carriers.nested,
        [("Back", "NestJob"), ("Zec", "NestJob")]
            .into_iter()
            .map(|(variant, ty)| (variant.to_owned(), ty.to_owned()))
            .collect::<BTreeSet<_>>()
    );
    let barred = carriers.barred();
    for name in [
        "KeyJob",
        "KeyOutcome",
        "KeyQueue",
        "Zec",
        "QueueOutcome",
        "Plain",
    ] {
        assert!(!barred.contains(name), "{name} is barred: {barred:?}");
    }
}

/// The secret form's actions split at `on_secret_action` (2026-11-22, S4c W12, preflight critic
/// C12; plan §3.6, §7.3): the shell's `apply_form_action` keeps only the window's own arms
/// (repaint, paste, copy) and hands each of the five wallet actions to the wallet's half
/// `on_secret_action` (in [`WALLET_FNS`], so [`wallet_fns_name_no_shell`] keeps it free of the
/// shell), which is called from nowhere else in production code: no other path turns a form
/// action into wallet work. It finds both fns (A-20).
///
/// 2026-11-22 (S4c W12 review): the doc said "no wallet write is left in the shell's half for
/// W15 to find"; that was not so. The copy arm's `copy_secret` still calls `drop_clip_notice`
/// (it writes the wallet's `banners`) and `refresh`, through `DerefMut`. They are now the named
/// exceptions of [`SECRET_FORM_SHELL_WALLET_CALLS`]: the shell half's own fns (`paste`,
/// `copy_secret`) call no other `App` fn and write no wallet field, and W15 (the non-test
/// `DerefMut` goes) must resolve the two. The check also pins what the review found unpinned:
/// the shell half starts by dropping another serial's action (`secret_session_is`; the stale
/// `Cancel` of `secret_sessions_follow_their_window_results` is dropped by `on_secret_action`
/// too, so that test passes without it, and a stale `Redraw`, `Paste` or `Copy` would act on
/// whatever secret window is open), and `on_submit`/`on_cancel`, which take the submission and
/// the purpose, have no production caller but `on_secret_action` (plan §7.3 item 3).
#[test]
fn the_secret_form_action_splits_at_on_secret_action() {
    let files = production_code();
    let app = &app_and_wallet(&files);
    let shell = fn_bodies(app, "apply_form_action");
    assert_eq!(shell.len(), 1, "one apply_form_action");
    let wallet = fn_bodies(app, "on_secret_action");
    assert_eq!(wallet.len(), 1, "one on_secret_action");
    assert!(
        WALLET_FNS.contains(&("W12", "on_secret_action")),
        "on_secret_action is wallet code"
    );
    let shell_calls = app_calls(shell[0]);
    for wallet_step in [
        "on_submit",
        "on_cancel",
        "close_secret",
        "refresh",
        "key",
        "yk_hold_complete",
        "mn_hold_complete",
    ] {
        assert!(
            !shell_calls.contains(wallet_step),
            "apply_form_action calls {wallet_step} itself"
        );
        assert!(
            app_calls(wallet[0]).contains(wallet_step),
            "on_secret_action no longer calls {wallet_step}"
        );
    }
    let fields = self_fields(shell[0]);
    for field in ["info", "yk_words", "secret_session", "settings"] {
        assert!(
            !fields.contains(field),
            "apply_form_action names self.{field}"
        );
    }
    let shell_text = normalized(shell[0]);
    for action in [
        "Submit(submission)",
        "Cancel",
        "TimedOut",
        "Close",
        "HoldComplete",
    ] {
        assert_eq!(
            shell_text
                .matches(&format!(
                    "self.on_secret_action(serial, SecretAction::{action})"
                ))
                .count(),
            1,
            "apply_form_action hands {action} to on_secret_action"
        );
    }
    // 2026-11-22 (S4c W12 review): the shell half drops another serial's action first.
    let opening = shell_text
        .split_once('{')
        .map(|(_, rest)| rest.trim_start())
        .unwrap_or_default();
    assert!(
        opening.starts_with("if !self.secret_session_is(serial) { return; }"),
        "apply_form_action no longer starts by dropping another serial's action"
    );
    assert_secret_form_shell_reach(app, &shell_calls);
    let callers_of = |wanted: &str| {
        files
            .iter()
            .flat_map(|src| {
                fn_blocks(src)
                    .into_iter()
                    .map(move |(name, body)| (src, name, body))
            })
            .filter(|(_, _, body)| app_calls(body).contains(wanted))
            .map(|(src, name, _)| format!("{}:{name}", src.file))
            .collect::<Vec<_>>()
    };
    assert_eq!(
        callers_of("on_secret_action"),
        ["yw-app/src/app.rs:apply_form_action"]
    );
    // 2026-11-22 (S4c W12 review): the submission and the purpose enter only through it.
    // 2026-11-23 (S4d E0b): `on_secret_action` is in the wallet half `app/wallet.rs`.
    for purpose_step in ["on_submit", "on_cancel"] {
        assert_eq!(
            callers_of(purpose_step),
            ["yw-engine/src/wallet/mod.rs:on_secret_action"],
            "{purpose_step} has a production caller other than on_secret_action"
        );
    }
}

/// The shell half of the secret form's actions (`apply_form_action`, whose `App` calls are
/// `shell_calls`) calls only the guard, its own arms and the wallet half, and its own arms
/// (`paste`, `copy_secret`) call no `App` fn but their [`SECRET_FORM_SHELL_WALLET_CALLS`] and
/// write no wallet field (2026-11-22, S4c W12 review).
fn assert_secret_form_shell_reach(app: &Src, shell_calls: &BTreeSet<String>) {
    assert_eq!(
        *shell_calls,
        [
            "copy_secret",
            "on_secret_action",
            "paste",
            "secret_session_is"
        ]
        .into_iter()
        .map(str::to_owned)
        .collect::<BTreeSet<_>>(),
        "apply_form_action's calls"
    );
    let wallet_state = wallet_fields(app);
    for own in ["paste", "copy_secret"] {
        let bodies = fn_bodies(app, own);
        assert_eq!(bodies.len(), 1, "one {own}");
        let allowed: BTreeSet<String> = SECRET_FORM_SHELL_WALLET_CALLS
            .iter()
            .filter(|&&(from, _, _)| from == own)
            .map(|&(_, call, _)| call.to_owned())
            .collect();
        assert_eq!(
            app_calls(bodies[0]),
            allowed,
            "{own} calls an App fn that is not its named exception"
        );
        let writes = wallet_writes(bodies[0], &wallet_state);
        assert!(writes.is_empty(), "{own} writes wallet state: {writes:?}");
    }
    for (_, call, reason) in SECRET_FORM_SHELL_WALLET_CALLS {
        assert!(!reason.is_empty(), "{call}: no reason");
    }
}

/// The wallet calls left in the shell's half of the secret form's actions, each with its reason
/// (2026-11-22, S4c W12 review, preflight critic C12): `(shell fn, App fn it calls, why)`.
/// [`the_secret_form_action_splits_at_on_secret_action`] allows nothing else. W15, which removes
/// the non-test `DerefMut`, must resolve them (make `drop_clip_notice` wallet code, as `refresh`
/// already is, and call both through the wallet, or carry the notice drop in an answer).
/// 2026-11-22 (S4c W15): resolved the first way — `drop_clip_notice` is `impl Wallet` (row W15
/// of [`WALLET_FNS`]) and `copy_secret` calls both on the wallet (`self.wallet.`), as
/// [`SHELL_WALLET_CALLS`] lists; they stay here as the shell half's only `App`-level calls.
const SECRET_FORM_SHELL_WALLET_CALLS: [(&str, &str, &str); 2] = [
    (
        "copy_secret",
        "drop_clip_notice",
        "the clip-clear notice (spec/04 §4.8): a new copy replaced one whose clear was still \
         being retried and noticed, so T-CLIP-NOT-CLEARED leaves the wallet's `banners`; the \
         shell knows it where the clipboard answered. Wallet code since W15 (2026-11-22), \
         called on the wallet",
    ),
    ("copy_secret", "refresh", "the repaint of that band"),
];

/// The shell's fns of the `rpc.json` import and the `App` fns each may call (2026-11-22, S4c
/// W13, critique B-5): `(shell fn, its App calls)`. The press handler finds the file
/// (`rpc_json_path`, a free fn) and hands each press on; the read and the delete do the file
/// work (`read_plan`, `delete_file`) and hand the result to the wallet's half. The networks a
/// plan is built for (`url_networks`) are read from the wallet.
const RPC_IMPORT_SHELL_CALLS: [(&str, &[&str]); 3] = [
    (
        "on_rpc_import",
        &[
            "begin_rpc_import",
            "delete_rpc_json",
            "finish_rpc_import",
            "rpc_import_cancel",
            "rpc_json_delete_asked",
        ],
    ),
    ("begin_rpc_import", &["on_rpc_json_read", "url_networks"]),
    ("delete_rpc_json", &["on_rpc_json_deleted"]),
];

/// The wallet's halves of the `rpc.json` import (2026-11-22, S4c W13, critique B-5), all W13
/// lines of [`WALLET_FNS`].
const RPC_IMPORT_WALLET_FNS: [&str; 6] = [
    "on_rpc_json_read",
    "finish_rpc_import",
    "rpc_import_cancel",
    "rpc_json_delete_asked",
    "on_rpc_json_deleted",
    "push_rejected",
];

/// The `rpc.json` import splits at typed wallet entries (2026-11-22, S4c W13, critique B-5; plan
/// §7, owner decision O-13 keeps the file Windows-only in the shell): the shell's fns of
/// `app_rpc_import.rs` ([`RPC_IMPORT_SHELL_CALLS`]: the press handler and the read and delete
/// of the file) write no wallet field and call no `App` fn but their listed ones; the wallet's
/// halves ([`RPC_IMPORT_WALLET_FNS`], in [`WALLET_FNS`] so free of the shell) touch no file:
/// they call none of the file fns (`rpc_json_path`, `read_plan`, `plan_from_bytes`,
/// `delete_file`) and name no `std::fs` or path. The parsed plan enters the wallet only through
/// `on_rpc_json_read`, called by `begin_rpc_import` alone (the delete's result only through
/// `on_rpc_json_deleted`, called by `delete_rpc_json` alone), and no yw-engine `Effect` or `Cmd`
/// source names the plan's types: a plan holds RPC URLs and an endpoint token, so it never
/// travels in a `Cmd` or an `Effect` (§7.1). Before W13, the press handler's arms and
/// `begin_rpc_import`/`delete_rpc_json` wrote the import state, the band and the confirmation
/// themselves. It finds every fn and source it names (A-20). Since the W13 review
/// (2026-11-22) also: no wallet half calls one of the shell's three fns, those are called only
/// from the press path (`on_family` → `on_rpc_import` → the read or the delete; since S4c W15,
/// 2026-11-22, the shell's `on_command` → `on_rpc_import`, critique B-5), and
/// `finish_rpc_import` keeps B-5's order (apply → `save_apikeys` → `save_settings` →
/// `fill_template_gaps` → `queue_rpc_tests`), which the lifecycle scenario pins only in part.
#[test]
fn the_rpc_import_plan_enters_the_wallet_typed() {
    let files = production_code();
    let app = &app_and_wallet(&files);
    let import = src_of(&files, "yw-app/src/app_rpc_import.rs");
    // 2026-11-23 (S4d E0b): the wallet's halves are in `app_rpc_plan.rs` (were `app_rpc_import.rs`'s
    // `impl Wallet` blocks), which also holds the plan and its checks.
    let plan = src_of(&files, "yw-engine/src/wallet/app_rpc_plan.rs");
    assert!(
        !import.code.contains("impl Wallet {"),
        "app_rpc_import.rs holds no wallet code"
    );
    let wallet_state = wallet_fields(app);
    assert!(
        wallet_state.contains("rpc_import"),
        "the import state is the wallet's"
    );
    for (shell_fn, calls) in RPC_IMPORT_SHELL_CALLS {
        let bodies = fn_bodies(import, shell_fn);
        assert_eq!(bodies.len(), 1, "one {shell_fn}");
        assert!(
            !WALLET_FNS.iter().any(|&(_, name)| name == shell_fn),
            "{shell_fn} is the shell's"
        );
        let expected: BTreeSet<String> = calls.iter().map(|&call| call.to_owned()).collect();
        assert_eq!(app_calls(bodies[0]), expected, "{shell_fn}'s App calls");
        let writes = wallet_writes(bodies[0], &wallet_state);
        assert!(
            writes.is_empty(),
            "{shell_fn} writes wallet state: {writes:?}"
        );
    }
    for wallet_fn in RPC_IMPORT_WALLET_FNS {
        assert!(
            WALLET_FNS.contains(&("W13", wallet_fn)),
            "{wallet_fn} is W13 wallet code"
        );
        let bodies = fn_bodies(plan, wallet_fn);
        assert_eq!(bodies.len(), 1, "one {wallet_fn}");
        let text = normalized(bodies[0]);
        for file_step in [
            "rpc_json_path(",
            "read_plan(",
            "plan_from_bytes(",
            "delete_file(",
            "std::fs",
            "Path",
        ] {
            assert!(!text.contains(file_step), "{wallet_fn} names {file_step}");
        }
        // 2026-11-22 (S4c W13 review): nor through the shell's fns, which do the file work
        // (a call of `on_rpc_import(…DeleteConfirm)` from a wallet half passed before).
        let calls = app_calls(bodies[0]);
        for (shell_fn, _) in RPC_IMPORT_SHELL_CALLS {
            assert!(!calls.contains(shell_fn), "{wallet_fn} calls {shell_fn}");
        }
    }
    finish_rpc_import_keeps_its_order(plan);
    let callers_of = |wanted: &str| {
        files
            .iter()
            .flat_map(|src| {
                fn_blocks(src)
                    .into_iter()
                    .map(move |(name, body)| (src, name, body))
            })
            .filter(|(_, _, body)| app_calls(body).contains(wanted))
            .map(|(src, name, _)| format!("{}:{name}", src.file))
            .collect::<Vec<_>>()
    };
    assert_eq!(
        callers_of("on_rpc_json_read"),
        ["yw-app/src/app_rpc_import.rs:begin_rpc_import"]
    );
    assert_eq!(
        callers_of("on_rpc_json_deleted"),
        ["yw-app/src/app_rpc_import.rs:delete_rpc_json"]
    );
    // The shell's fns are reached from the press path only (2026-11-22, S4c W13 review): the
    // family router, then the press handler. No wallet fn reaches the file work through them,
    // directly or through a helper. 2026-11-22 (S4c W15, critique B-5): the shell's press entry
    // `on_command` runs it right after the press reached the wallet; before, the wallet's family
    // router `on_family`.
    assert_eq!(
        callers_of("on_rpc_import"),
        ["yw-app/src/app.rs:on_command"]
    );
    for shell_step in ["begin_rpc_import", "delete_rpc_json"] {
        assert_eq!(
            callers_of(shell_step),
            ["yw-app/src/app_rpc_import.rs:on_rpc_import"],
            "{shell_step}'s callers"
        );
    }
    let carriers: Vec<&Src> = files
        .iter()
        .filter(|src| {
            src.file == "yw-engine/src/effect.rs" || src.file.starts_with("yw-engine/src/cmd/")
        })
        .collect();
    for file in ["yw-engine/src/effect.rs", "yw-engine/src/cmd/mod.rs"] {
        assert!(
            carriers.iter().any(|src| src.file == file),
            "{file} scanned"
        );
    }
    for src in carriers {
        for name in ["ImportPlan", "ImportEntry", "RpcImportPlan", "HttpsUrl"] {
            assert!(!src.code.contains(name), "{} names {name}", src.file);
        }
    }
}

/// The confirmation's order (2026-11-22, S4c W13 review; critique B-5: "in today's order"),
/// part of [`the_rpc_import_plan_enters_the_wallet_typed`]: apply, save the keys, save the
/// settings, fill the template's gaps, queue the tests. The lifecycle scenario
/// `rpc_import_on_temp_data` does not see the settings save move past the gap filling, so the
/// order is read from the source.
fn finish_rpc_import_keeps_its_order(import: &Src) {
    let finish = fn_bodies(import, "finish_rpc_import");
    assert_eq!(finish.len(), 1, "one finish_rpc_import");
    let finish = normalized(finish[0]);
    let steps = [
        "apply_plan(",
        "self.save_apikeys(",
        "self.save_settings(",
        "self.fill_template_gaps(",
        "self.queue_rpc_tests(",
    ];
    for pair in steps.windows(2) {
        let last = finish
            .rfind(pair[0])
            .expect("finish_rpc_import calls the step");
        let next = finish
            .find(pair[1])
            .expect("finish_rpc_import calls the step");
        assert!(
            last < next,
            "finish_rpc_import: {} after {}",
            pair[0],
            pair[1]
        );
    }
}

/// The scanners of [`wallet_fns_name_no_shell`] on made-up code: they can fail.
#[test]
fn shell_reach_on_made_up_code() {
    let shell: BTreeSet<String> = ["main", "controls"]
        .into_iter()
        .map(str::to_owned)
        .collect();
    let shell_fns: BTreeSet<String> = ["drain"].into_iter().map(str::to_owned).collect();
    let none = BTreeSet::new();
    let nowhere = Src::new("yw-app/src/y.rs".to_owned(), String::new());
    assert_eq!(
        shell_reach(
            "{ let t = self.form.text(f); self.wallet.controls.text(1); self.drain(); \
             let w = yw_win::ui::x(); self.refresh(); if self.main.is_some() {} }",
            &nowhere,
            &shell,
            &shell_fns,
            &none,
        ),
        [
            "names self.controls",
            "names self.main",
            "names yw_win",
            "calls App::drain"
        ]
    );
    assert!(
        shell_reach(
            "{ self.form.set(a, b); self.refresh(); self.main_hidden(); }",
            &nowhere,
            &shell,
            &shell_fns,
            &none
        )
        .is_empty()
    );
    let one = |body: &str| -> BTreeMap<String, Vec<(String, String, bool)>> {
        [(
            "f".to_owned(),
            vec![("x.rs".to_owned(), body.to_owned(), true)],
        )]
        .into_iter()
        .collect()
    };
    assert_eq!(
        shell_namers(&one("{ self.main.as_ref(); }"), &shell),
        ["f".to_owned()].into_iter().collect::<BTreeSet<_>>()
    );
    assert!(shell_namers(&one("{ self.main_hidden(); self.form.x(); }"), &shell).is_empty());
    // Two levels (2026-11-21, S4 W3 review): `notice` calls a helper that calls a shell fn; the
    // fixed point finds the helper, so `notice`'s call of it is a reach. `refresh` stays wallet.
    let fns: BTreeMap<String, Vec<(String, String, bool)>> = [
        ("render_main", "{ self.controls.clear(); }"),
        ("probe", "{ self.render_main(); }"),
        ("deeper", "{ self.wallet.probe(); }"),
        ("notice", "{ self.banner(); self.deeper(); }"),
        ("refresh", "{ self.emit(Effect::Render); }"),
    ]
    .into_iter()
    .map(|(name, body)| {
        (
            name.to_owned(),
            vec![("x.rs".to_owned(), body.to_owned(), true)],
        )
    })
    .collect();
    let closed = shell_closure(&fns, shell_namers(&fns, &shell));
    assert_eq!(
        closed,
        ["deeper", "notice", "probe", "render_main"]
            .into_iter()
            .map(str::to_owned)
            .collect::<BTreeSet<_>>()
    );
    assert_eq!(
        shell_reach(
            "{ self.banner(); self.deeper(); }",
            &nowhere,
            &shell,
            &closed,
            &none
        ),
        ["calls App::deeper"]
    );
    assert!(shell_reach("{ self.refresh(); }", &nowhere, &shell, &closed, &none).is_empty());
}

/// [`app_calls`] in [`shell_reach`] and [`shell_closure`] on made-up code (2026-11-21, S4 W7
/// review): `Self::`, `App::` (also after a path) and a closure's `app.` (through `app.wallet.`
/// too) are calls of an `App` fn, in a wallet fn and in the fixed point; another type's path or
/// another receiver is not. Before, only `self.<fn>(` was followed.
#[test]
fn app_calls_on_made_up_code() {
    let shell: BTreeSet<String> = ["main", "controls"]
        .into_iter()
        .map(str::to_owned)
        .collect();
    let shell_fns: BTreeSet<String> = ["drain"].into_iter().map(str::to_owned).collect();
    let none = BTreeSet::new();
    let nowhere = Src::new("yw-app/src/y.rs".to_owned(), String::new());
    for body in [
        "{ Self::drain(self); }",
        "{ crate::app::App::drain(self); }",
        "{ self.after(|app| app.drain()); }",
        "{ self.after(|app| app.wallet.drain()); }",
        // 2026-11-22 (S4 W9 review): a closure's parameter typed as an `App`, any name.
        "{ let _ = |x: &mut Self| x.drain(); }",
        "{ self.after(|mut me: &mut App| me.wallet.drain()); }",
        "{ let f = |a: &'a crate::app::App| a.drain(); }",
    ] {
        assert_eq!(
            shell_reach(body, &nowhere, &shell, &shell_fns, &none),
            ["calls App::drain"],
            "{body}"
        );
    }
    assert!(
        shell_reach(
            "{ Other::drain(self); self.app.drain(); my_app.drain(); MyApp::drain(); \
             let f = Self::drain; let g = |x: &mut Other| x.drain(); \
             let h = |y: &Selfish, z: &mut AppState| { y.drain(); z.drain() }; }",
            &nowhere,
            &shell,
            &shell_fns,
            &none
        )
        .is_empty()
    );
    let fns: BTreeMap<String, Vec<(String, String, bool)>> = [
        ("render_main", "{ self.controls.clear(); }"),
        ("by_path", "{ Self::render_main(self); }"),
        ("by_app", "{ let x = App::by_path(self); }"),
        (
            "by_closure",
            "{ self.later(Box::new(|app| app.by_app())); }",
        ),
        ("plain", "{ Other::render_main(); self.app.by_app(); }"),
    ]
    .into_iter()
    .map(|(name, body)| {
        (
            name.to_owned(),
            vec![("x.rs".to_owned(), body.to_owned(), true)],
        )
    })
    .collect();
    assert_eq!(
        shell_closure(&fns, shell_namers(&fns, &shell)),
        ["by_app", "by_closure", "by_path", "render_main"]
            .into_iter()
            .map(str::to_owned)
            .collect::<BTreeSet<_>>()
    );
}

/// The free-fn scanners of [`wallet_fns_name_no_shell`] on made-up code (2026-11-21, S4 W6
/// review): they can fail.
#[test]
fn free_fn_reach_on_made_up_code() {
    let shell: BTreeSet<String> = ["main"].into_iter().map(str::to_owned).collect();
    // `stamp` names `yw_win`, `label` and the inline module's `deep` call it, `plain` does not,
    // and `method` is no free fn. A wallet fn in `y.rs`, which imports `stamp`, reaches the shell
    // by a bare `stamp(` and by `x::label(`; a method call, a type's path, another module's path,
    // a bare call of a fn it does not import, a definition and a longer name do not.
    let x = Src::new(
        "yw-app/src/x.rs".to_owned(),
        "fn stamp(s: u64) -> u64 { yw_win::time::now(s) }\n\
         pub(crate) fn label(s: u64) -> u64 { stamp(s) }\n\
         fn plain() {}\n\
         mod inner { fn deep() { super::label(1); } }\n\
         impl App { fn method(&self) { stamp(1); } }\n"
            .to_owned(),
    );
    let y = Src::new(
        "yw-app/src/y.rs".to_owned(),
        "use crate::x::stamp;\n".to_owned(),
    );
    let files = [x, y];
    let free = free_fns(&files);
    assert_eq!(
        free.keys().map(String::as_str).collect::<Vec<_>>(),
        ["deep", "label", "plain", "stamp"]
    );
    let shell_free = shell_free_fns(&files, &free);
    let no_fns = BTreeSet::new();
    assert_eq!(
        shell_free
            .iter()
            .map(|(_, name)| name.as_str())
            .collect::<Vec<_>>(),
        ["deep", "label", "stamp"]
    );
    assert_eq!(
        shell_reach(
            "{ let a = stamp(at); let b = crate::x::label (at); }",
            &files[1],
            &shell,
            &no_fns,
            &shell_free
        ),
        ["calls label", "calls stamp"]
    );
    assert!(
        shell_reach(
            "{ self.stamp(1); a.label(2); Clock::stamp(3); yw_engine::text::label(4); \
             label(5); restamp(6); fn label() {} plain(); }",
            &files[1],
            &shell,
            &no_fns,
            &shell_free
        )
        .is_empty()
    );
}

// ---- The lock's composition (2026-11-21, S4 W3a; critique B-1, A-2, preflight critic C11) ------

/// `the_lock_composition_drains_only_for_suspend` (2026-11-21, S4 W3a, spec/04 §5.3): the shell's
/// `App::lock` is exactly the wallet's first half, the drain for `Suspend` (which applies
/// `Effect::AwaitKeyLock`, the wait for the key worker, before the second half), then the second
/// half; the first half emits `AwaitKeyLock` only for `Suspend` and as its last step; the
/// wallet's own lock (`lock_wallet`, a `WalletLock` with no `Suspend`) composes the halves with
/// no drain; and only the shell's entries (`on_system`, `lock_shortcut`, `shutdown`) call `lock`,
/// through any receiver, so no wallet fn can lock for `Suspend` and send `KeyJob::Load` before
/// the wait (the P10b regression `1fb17c1` fixed), while `lock_wallet` has exactly its five
/// wallet callers (2026-11-21, S4 W3a review), and the halves `lock_steps`/`lock_after_wait`
/// have exactly the two compositions as callers (2026-11-22, S4c W14c review). Finds every fn
/// it checks (A-20).
#[test]
fn the_lock_composition_drains_only_for_suspend() {
    let files: Vec<Src> = production_code()
        .into_iter()
        .filter(|src| in_app_or_wallet(&src.file))
        .collect();
    let app = &app_and_wallet(&files);
    let one = |name: &str| -> String {
        let bodies = fn_bodies(app, name);
        assert_eq!(bodies.len(), 1, "one fn {name} in app.rs");
        bodies[0].split_whitespace().collect()
    };
    // 2026-11-22 (S4c W15): the halves are named on the wallet (non-test builds have no
    // `DerefMut`); before, `self.lock_steps(` and `self.lock_after_wait(`.
    assert_eq!(
        one("lock"),
        "fnlock(&mutself,reason:LockReason){letvault_present=self.wallet.lock_steps(reason);\
         ifreason==LockReason::Suspend{self.drain();}self.wallet.lock_after_wait(vault_present);}"
    );
    assert_eq!(
        one("lock_wallet"),
        "fnlock_wallet(&mutself,reason:WalletLock){letvault_present=\
         self.lock_steps(reason.into());self.lock_after_wait(vault_present);}"
    );
    let steps = one("lock_steps");
    assert_eq!(
        steps.matches("AwaitKeyLock").count(),
        1,
        "one wait: {steps}"
    );
    assert!(
        steps.ends_with(
            "ifreason==LockReason::Suspend{self.emit(Effect::AwaitKeyLock{before,ms:1_500});}\
             vault_present}"
        ),
        "the wait is the first half's last effect, for Suspend only: {steps}"
    );
    let after = one("lock_after_wait");
    assert!(!after.contains("emit("), "the second half emits nothing");
    assert!(after.ends_with("self.key(KeyJob::Load);}"), "{after}");
    // Who calls the composition: the shell's entries only. 2026-11-21 (S4 W3a review): any
    // receiver (`app.lock(..)`, `self.app.lock(..)`, not only `self.`) and any argument; before,
    // only `self.lock(`. A call with no argument (`BtcUi::lock()`, the Bitcoin controller's; a
    // mutex's) is another fn.
    let callers_of = |call: &str| -> Vec<String> {
        let mut callers: Vec<String> = files
            .iter()
            .flat_map(|src| {
                fn_blocks(src)
                    .into_iter()
                    .filter(|(_, body)| calls_with_an_argument(&normalized(body), call))
                    .map(|(name, _)| name)
            })
            .collect();
        callers.sort_unstable();
        callers
    };
    // 2026-11-22 (S4c W3b, critic C11): no longer `shutdown`, whose wallet half
    // `shutdown_steps` locks with `lock_wallet(WalletLock::Shutdown)`.
    assert_eq!(callers_of(".lock("), ["lock_shortcut", "on_system"]);
    // The wallet's own lock: exactly these callers (2026-11-21, S4 W3a review: before, at least
    // five), so a new caller, or one that replaces a current one, is a reviewed change here. The
    // dispatcher's `core.lock_wallet()` (no argument) is another fn. 2026-11-22 (S4c W3b): and
    // `shutdown_steps`.
    assert_eq!(
        callers_of(".lock_wallet("),
        [
            "idle_tick",
            "key_result",
            "on_cancel",
            "on_core",
            "reset_execute",
            "shutdown_steps"
        ]
    );
    // The halves themselves: only the two compositions above call them (2026-11-22, S4c W14c
    // review). Since W14c-2 `lock_steps` is an `impl Wallet` fn that still takes a
    // `LockReason`, `Suspend` included, so a wallet fn calling the halves directly would emit
    // `AwaitKeyLock` with no drain and send `KeyJob::Load` before the wait (the P10b regression);
    // before, only the callers of `.lock(` and `.lock_wallet(` were pinned.
    assert_eq!(callers_of(".lock_steps("), ["lock", "lock_wallet"]);
    assert_eq!(callers_of(".lock_after_wait("), ["lock", "lock_wallet"]);
    the_shutdown_composition_runs_from_the_shell(&files);
}

/// The shutdown's composition (2026-11-22, S4c W3b; preflight critic C11, owner's second batch
/// item 1: `shutdown` is split like the lock; spec/04 §1.5), part of
/// [`the_lock_composition_drains_only_for_suspend`]: `App::shutdown` calls the wallet's three
/// halves in order (`shutdown_begin`, `shutdown_steps`, `shutdown_after_wait`) with the shell's
/// pipe stop before the second, its drain and 5 s wait between the second and the third, and the
/// window and the workers after it; the halves are W3b wallet fns (so
/// [`wallet_fns_name_no_shell`] keeps them free of the shell); only the shell's entries
/// `on_system` and `on_command` call `shutdown`, `on_command` right after the `종료` press, whose
/// wallet arm (`on_core`'s `CorePress::Exit`) does nothing. Before W3b, `on_core` called
/// `shutdown`, the shell's composition, from wallet code. Finds every fn it checks (A-20).
/// 2026-11-22 (S4c W3b review): it also pins the order of the statements inside each half (the
/// lock count read before the wallet's lock above all); before, only the composition's order.
fn the_shutdown_composition_runs_from_the_shell(files: &[Src]) {
    let app = &app_and_wallet(files);
    let flat = |name: &str| -> String {
        let bodies = fn_bodies(app, name);
        assert_eq!(bodies.len(), 1, "one fn {name} in app.rs");
        bodies[0].split_whitespace().collect()
    };
    // Each step of `name`, whitespace-free, after the one before it.
    let in_order = |name: &str, order: &[&str]| {
        let body = flat(name);
        let mut at = 0;
        for step in order {
            let found = body[at..].find(step);
            assert!(found.is_some(), "{name} lost or reordered {step}: {body}");
            at += found.unwrap_or_default() + step.len();
        }
    };
    // 2026-11-22 (S4c W15): the halves are named on the wallet (`self.wallet.`; non-test builds
    // have no `DerefMut`).
    in_order(
        "shutdown",
        &[
            "if!self.wallet.shutdown_begin(){return;}",
            "pipe.stop();",
            "letbefore=self.wallet.shutdown_steps();self.drain();",
            "self.lock_signal.wait_beyond(before,Duration::from_secs(5));\
             self.wallet.shutdown_after_wait();self.save_window_state();",
            "yw_win::ui::quit(0);",
        ],
    );
    // The halves keep the order the one fn had before W3b (2026-11-22, S4c W3b review): the
    // mode before the queue's items finish; the dispatcher's stop, then `WalletConnect`, then the
    // key worker's lock count read before the lock (read after it, a fast worker's signal can
    // land first and every shutdown waits the full 5 s), the lock, the count returned; the key
    // worker's stop, then the RPC worker's, then the AI explanation's. 2026-11-22 (S4d F21, owner
    // decision, spec/15 §18 21): the waiting grant writes come before the mode (`flush_grant_writes`
    // writes only while unlocked); before, the mode came right after the guard.
    in_order(
        "shutdown_begin",
        &[
            "ifself.mode==AppMode::ShuttingDown{returnfalse;}",
            "self.flush_grant_writes();self.set_mode(AppMode::ShuttingDown);",
            "self.evm.queue.shutdown()",
            "self.approval_finished(",
            "true}",
        ],
    );
    in_order(
        "shutdown_steps",
        &[
            "ifletSome(browser)=self.browser.as_mut(){browser.stop();}",
            "self.wc_shutdown();",
            "letbefore=self.lock_signal.count();",
            "self.lock_wallet(WalletLock::Shutdown);",
            "before}",
        ],
    );
    in_order(
        "shutdown_after_wait",
        &[
            "self.key_queue.push(self.lock_epoch,KeyJob::Shutdown);",
            "ifletSome(tx)=self.rpc_tx.take(){let_=tx.send(RpcJob::Shutdown);}",
            "self.llm_shutdown();",
        ],
    );
    for half in ["shutdown_begin", "shutdown_steps", "shutdown_after_wait"] {
        assert!(WALLET_FNS.contains(&("W3b", half)), "{half} is wallet code");
        let body = flat(half);
        assert!(!body.contains("drain("), "{half} drains");
    }
    assert!(flat("shutdown_steps").contains("self.lock_wallet(WalletLock::Shutdown);"));
    let mut callers: Vec<String> = files
        .iter()
        .flat_map(|src| {
            fn_blocks(src)
                .into_iter()
                .filter(|(_, body)| normalized(body).contains(".shutdown()"))
                .map(|(name, _)| name)
        })
        .collect();
    callers.sort_unstable();
    // `BtcUi`/queue `shutdown()` calls are other fns' (`evm.queue.shutdown()` in
    // `shutdown_begin`); the composition's callers are the shell's entries.
    callers.retain(|name| name != "shutdown_begin");
    assert_eq!(callers, ["on_command", "on_system"]);
    assert!(
        flat("on_command").contains("Press::Core(CorePress::Exit)=>self.shutdown(),"),
        "on_command runs the shutdown after the 종료 press"
    );
    assert!(
        flat("on_core").contains("CorePress::Exit=>{}"),
        "the wallet's 종료 arm does nothing more"
    );
}

/// Whether `body` calls `call` (a `.name(` text) with an argument, through any receiver.
fn calls_with_an_argument(body: &str, call: &str) -> bool {
    body.split(call)
        .skip(1)
        .any(|rest| !rest.trim_start().starts_with(')'))
}

// ---- The main-window mirror (2026-11-21, S4 W3; critique B-10, preflight critic C7) ------------

/// The fns of `src` whose body holds `pattern`, with their bodies (the mirror check).
fn fns_naming<'a>(src: &'a Src, pattern: &str) -> Vec<(String, &'a str)> {
    fn_blocks(src)
        .into_iter()
        .filter(|(_, body)| body.contains(pattern))
        .collect()
}

/// B-10 `the_main_hidden_mirror_changes_where_the_window_does` (2026-11-21, S4 W3): the wallet's
/// `main_hidden` is a mirror (`Cmd::MainHidden`), and the shell sends it at every place the
/// main window's hidden-or-minimized state can change, so the periodic reads pause exactly as
/// when they read the window (before W3, `App::main_hidden` read it at each call):
/// - only the shell's `main_hidden_now` reads the window's state, and its body is exactly
///   `self.main.as_ref().is_some_and(Window::is_hidden_or_minimized)` (2026-11-21, S4 W3 review);
/// - `App::main` is set only in `create_main_window` and taken only in `shutdown`, and each then
///   syncs the mirror; the window is shown only in `show_main_window`, whose callers are
///   `show_main` (which syncs right after) and the executor's `raise_main`; `App::drain`
///   brings the mirror up to date after every effect it applied (`main_hidden_answer`: a
///   `RaiseMain`, or a secret or approval window's close that asks for the main window's
///   foreground, which can show a hidden one); every main window message syncs first
///   (`on_main_msg`: a minimize or restore by the user is a `WM_SIZE`);
/// - the four polling readers read the wallet's `main_hidden()`, an `impl Wallet` fn that
///   returns the field, which only the `Cmd::MainHidden` arm writes.
///
/// Headless (no window is never hidden), the mirror follows `Cmd::MainHidden` and the sync puts
/// it back to the window's value. A hidden window's case is the winui lifecycle golden
/// `polling_while_hidden`. Debug builds check the mirror against `main_hidden_now` at the end
/// of every drain (`assert_main_hidden_in_step`): that finds a missed sync, not a wrong read
/// (both sides use the same read), hence the exact body above. 2026-11-21 (S4 W3 review): a
/// visible, a minimized and a hidden real main window, with a due balance tick each, are checked
/// only by the on-request windowed `ui::tour_forms` (`main_hidden_follows_the_window`), not by
/// the gate; before, this note said `ui::tour_forms` checked the shown window, which it did not.
#[test]
fn the_main_hidden_mirror_changes_where_the_window_does() {
    let files: Vec<Src> = production_code()
        .into_iter()
        .filter(|src| in_app_or_wallet(&src.file))
        .collect();
    let app = &app_and_wallet(&files);
    let named = |src: &Src, pattern: &str| -> Vec<String> {
        fns_naming(src, pattern)
            .into_iter()
            .map(|(name, _)| name)
            .collect()
    };
    let mut readers = Vec::new();
    for src in &files {
        readers.extend(named(src, "is_hidden_or_minimized"));
    }
    assert_eq!(readers, ["main_hidden_now"], "who reads the window's state");
    let flat = |body: &str| body.split_whitespace().collect::<String>();
    let body_of = |name: &str| -> String {
        let bodies = fn_bodies(app, name);
        assert_eq!(bodies.len(), 1, "one fn {name}");
        flat(bodies[0])
    };
    // The live read, exactly (2026-11-21, S4 W3 review): a window that exists and is hidden or
    // minimized, the read `App::main_hidden` made before W3. The drain-end debug check compares
    // the mirror with this same read, so it cannot find a wrong read; the windowed
    // `ui::tour_forms` (`main_hidden_follows_the_window`) checks it on a real window.
    assert_eq!(
        body_of("main_hidden_now"),
        "fnmain_hidden_now(&self)->bool{self.main.as_ref().is_some_and(Window::is_hidden_or_minimized)}"
    );
    // The window comes and goes; each time the mirror follows in the same fn.
    assert_eq!(named(app, "state.main = "), ["create_main_window"]);
    assert!(
        body_of("create_main_window")
            .ends_with("state.main=Some(window);state.sync_main_hidden();Ok(())}")
    );
    assert_eq!(named(app, ".main.take()"), ["shutdown"]);
    let shutdown = body_of("shutdown");
    assert!(
        shutdown.ends_with("yw_win::ui::quit(0);self.sync_main_hidden();}"),
        "{shutdown}"
    );
    for src in &files {
        if src.file != "yw-app/src/app.rs" {
            for pattern in [".main = ", "main.take()", "main.replace("] {
                assert!(named(src, pattern).is_empty(), "{}: {pattern}", src.file);
            }
        }
    }
    // Shown: only `show_main_window` shows it; its callers sync or answer.
    let mut shows = Vec::new();
    for src in &files {
        for pattern in ["main.show()", "main.show_maximized()"] {
            shows.extend(named(src, pattern));
        }
    }
    shows.dedup();
    assert_eq!(shows, ["show_main_window"]);
    let mut callers = Vec::new();
    for src in &files {
        callers.extend(named(src, "self.show_main_window()"));
    }
    callers.sort_unstable();
    assert_eq!(callers, ["raise_main", "show_main"]);
    assert!(
        body_of("show_main")
            .starts_with("fnshow_main(&mutself){self.show_main_window();self.sync_main_hidden();")
    );
    // Every applied effect (`RaiseMain`, a close that asks for the main window's foreground, …)
    // is followed by the mirror's answer in the drain, before the effect's own answer.
    let effects = src_of(&files, "yw-app/src/app_effects.rs");
    let drain = flat(fn_bodies(effects, "drain")[0]);
    // 2026-11-22 (S4c W15): the answers go to `Wallet::on_cmd`, named on the wallet.
    let mirror = concat!(
        "ifletSome(hidden)=self.main_hidden_answer(){self.wallet.on_cmd(hidden);}",
        "ifletSome(answer)=answer{self.wallet.on_cmd(answer);}"
    );
    assert!(drain.contains(mirror), "{drain}");
    // Every main window message syncs first.
    assert!(body_of("on_main_msg").starts_with(
        "fnon_main_msg(&mutself,window:&Window,msg:&Msg)->Reply{self.sync_main_hidden();"
    ));
    assert!(body_of("sync_main_hidden").contains("self.dispatch(cmd);"));
    // The wallet's side: the readers, the accessor and its one writer.
    let mut users = Vec::new();
    for src in &files {
        users.extend(named(src, "self.main_hidden()"));
    }
    users.sort_unstable();
    assert_eq!(
        users,
        [
            "evm_balance_tick",
            "hc_tick",
            "received_tick",
            "sol_balance_tick"
        ]
    );
    let accessor = impl_fns(&files, "Wallet");
    let accessor = accessor.get("main_hidden").expect("Wallet::main_hidden");
    assert_eq!(accessor.len(), 1);
    assert!(flat(&accessor[0].1).ends_with("{self.main_hidden}"));
    let mut writers = Vec::new();
    for src in &files {
        writers.extend(named(src, "self.main_hidden ="));
    }
    assert_eq!(writers, ["on_cmd"]);
    assert!(
        body_of("on_cmd").contains("Cmd::MainHidden(hidden)=>self.main_hidden=hidden,"),
        "the Cmd's arm"
    );
}

/// The mirror headless (2026-11-21, S4 W3, critique B-10): with no main window the shell's
/// answer is "not hidden"; `Cmd::MainHidden` sets the wallet's mirror, which the polling reads
/// see, and the shell's sync puts it back to the window's value in an entry of its own.
#[test]
fn the_main_hidden_mirror_follows_its_cmd_and_the_sync() {
    use yw_engine::cmd::Cmd;
    let (mut app, dir) = super::unlocked_app("main-hidden-mirror", false);
    assert!(app.main.is_none() && !app.main_hidden());
    assert!(
        app.main_hidden_answer().is_none(),
        "no window: nothing to send"
    );
    app.sync_main_hidden();
    assert!(!app.main_hidden());
    app.on_cmd(Cmd::MainHidden(true));
    assert!(app.main_hidden(), "the Cmd sets the mirror");
    assert!(
        matches!(app.main_hidden_answer(), Some(Cmd::MainHidden(false))),
        "the window (none) is not hidden"
    );
    app.sync_main_hidden();
    assert!(!app.main_hidden(), "the sync follows the window");
    assert_eq!(app.queued_effects(), 0);
    drop(app);
    let _ = std::fs::remove_dir_all(dir);
}

// 2026-11-23 (spec/15 §11.4 S4d E1, preflight critic C10): source check S11
// `moving_files_name_no_shell` (2026-11-22, S4d E0c; E0b review, E0c review, S4d E0b), its
// made-up-code tests and its word lists are gone: the files it scanned are yw-engine's now, and
// yw-engine depends on no yw-app or yw-win item and its `clippy.toml` bans the file, process,
// network, wall-clock and environment calls, so the compiler and clippy refuse what it found.

/// Source check `the_probe_is_installed_only_by_tests` (2026-11-23, S4d E0b, preflight O-4): the
/// wallet code's probe notes (`yw_engine::probe`) reach a sink only in tests. The only install of
/// a sink in yw-app's and yw-engine's sources, test files included, is the yw-app test seam
/// `app/secret_seam.rs` (a `cfg(test)` module) besides the definition in `probe.rs`, and the
/// notes are the two the secret characterization logs. Finds what it checks (A-20).
#[test]
fn the_probe_is_installed_only_by_tests() {
    let crates = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    let mut installs = Vec::new();
    let mut notes = Vec::new();
    let mut scanned = 0_usize;
    for krate in ["yw-app", "yw-engine"] {
        let root = crates.join(krate);
        let mut stack = vec![root.join("src"), root.join("tests")];
        while let Some(dir) = stack.pop() {
            let Ok(entries) = std::fs::read_dir(&dir) else {
                continue;
            };
            for entry in entries {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    stack.push(path);
                } else if path.extension().is_some_and(|ext| ext == "rs") {
                    scanned += 1;
                    let rel = path
                        .strip_prefix(&crates)
                        .unwrap()
                        .to_string_lossy()
                        .replace('\\', "/");
                    let code = code_only(&std::fs::read_to_string(&path).unwrap());
                    for (at, _) in code.match_indices("install(") {
                        let before = code[..at].trim_end();
                        if before.ends_with("probe::")
                            || before.ends_with("fn") && rel.ends_with("probe.rs")
                        {
                            installs.push(rel.clone());
                        }
                    }
                    notes.extend(code.match_indices("probe::note(").map(|_| rel.clone()));
                }
            }
        }
    }
    assert!(scanned > 100, "scanned {scanned} files");
    installs.sort_unstable();
    assert_eq!(
        installs,
        ["yw-app/src/app/secret_seam.rs", "yw-engine/src/probe.rs"],
        "who installs a probe sink"
    );
    notes.sort_unstable();
    assert_eq!(
        notes,
        [
            "yw-engine/src/wallet/app_approval.rs",
            "yw-engine/src/wallet/mod.rs"
        ],
        "who notes a probe"
    );
    let seam =
        std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("src/app.rs")).unwrap();
    assert!(
        seam.contains("#[cfg(test)]\npub(crate) mod secret_seam;"),
        "the seam module is cfg(test)"
    );
}

/// The form of a kept facade entry's re-export (2026-11-23, S4 E3b review; critic C16): the
/// entries a frozen integration test names are `#[doc(hidden)] pub` (that test sees the non-test
/// library), the entries only frozen unit tests name are `#[cfg(test)] pub(crate)`.
const DOC_HIDDEN: &str = "#[doc(hidden)] pub";
/// See [`DOC_HIDDEN`].
const TEST_ONLY: &str = "#[cfg(test)] pub(crate)";

/// The facade entries kept for the bodies of the tests frozen at F-A (2026-11-23, S4d E3b,
/// preflight §2 E3b, critic C16), with the form of their re-export: `yw-app/src/lib.rs`
/// re-exports these yw-engine modules ...
const KEPT_LIB_FACADE: [(&str, &str); 9] = [
    ("btc", DOC_HIDDEN),
    ("errors", DOC_HIDDEN),
    ("events", DOC_HIDDEN),
    ("flow", TEST_ONLY),
    ("meta", DOC_HIDDEN),
    ("network", TEST_ONLY),
    ("sol", TEST_ONLY),
    ("workers", DOC_HIDDEN),
    ("yubikey", TEST_ONLY),
];
/// ... and `yw-app/src/ui/mod.rs` these.
const KEPT_UI_FACADE: [(&str, &str); 2] = [("approval", DOC_HIDDEN), ("approval_view", DOC_HIDDEN)];

/// The other `pub`/`pub(…)` re-exports of yw-engine items in yw-app `src` (2026-11-23, S4 E3b
/// review), as `file|form use path` with the whitespace collapsed; any other is refused, so no
/// facade entry comes back elsewhere. The S4d E1 test-path shims of the frozen tests (preflight
/// O-1, spec/15 §18 28; they go when the S4 freeze ends): `app.rs` `TestState` and `AppMode`,
/// `Purpose`, `Wallet`, the chain-sites test holder's glob, and the `lib.rs` modules
/// `app_browser`, `app_btc`, `app_card`, `app_evm`, `app_sol_dapp`. And the store's own API
/// names of the reset (2026-11-17, S2: defined in `wallet_files`, named `crate::store::…` by the
/// store's callers; items, not a moved module).
const OTHER_ENGINE_REEXPORTS: [&str; 10] = [
    "src/app.rs|#[cfg(test)] pub(crate) use yw_engine::wallet::{AppMode, Purpose, Wallet}",
    "src/app.rs|#[doc(hidden)] pub use yw_engine::wallet::TestState",
    "src/app_chain_sites.rs|pub(crate) use yw_engine::wallet::app_chain_sites::*",
    "src/lib.rs|pub use yw_engine::wallet::app_btc::{ ADDRESS_MODE_BUSY, BtcAction, \
     BtcAddSource, NOT_SENT, REMOVE_BUSY_APPROVAL, REMOVE_BUSY_IN_FLIGHT, }",
    "src/lib.rs|pub(crate) use yw_engine::wallet::app_browser::{ BrowserUi, GrantWrite, \
     SignWaiter, SiteRows, SiteSigner, }",
    "src/lib.rs|pub(crate) use yw_engine::wallet::app_card::{ CardJobKind, T_CARD_SITE_GONE, \
     T_CARD_SITE_REVOKED, T_CARD_TOUCH, approval_touches, touch_text, }",
    "src/lib.rs|pub(crate) use yw_engine::wallet::app_evm::QueuedItem",
    "src/lib.rs|pub(crate) use yw_engine::wallet::app_sol_dapp::SolBroadcast",
    "src/store.rs|pub use yw_engine::wallet_files::file_name",
    "src/store/reset.rs|pub use yw_engine::wallet_files::{FOLDER_PREFIX, README_NAME, \
     ResetError, ResetReport}",
];

/// The files the tests frozen at F-A are in now where that is not their F-A file, relative to
/// the crate (`frozen-tests.txt` keeps the F-A path and never changes): the eight A-4 tests of
/// `app_chain_sites.rs` are in its `#[path]` child `app/tests/chain_sites.rs` since S4 W0
/// (2026-11-21).
const FROZEN_MOVED: [(&str, &str); 1] =
    [("src/app_chain_sites.rs", "src/app/tests/chain_sites.rs")];

/// The (file relative to the crate, fn name) of every yw-app test frozen at F-A, at its file of
/// now (2026-11-23, S4 E3b review: a pair, not a leaf name alone, so a fn of another file with a
/// frozen test's name, e.g. one of the `print` recorders, is no frozen test).
fn frozen_app_tests() -> BTreeSet<(String, String)> {
    include_str!("s4_flow/frozen-tests.txt")
        .lines()
        .filter_map(|line| {
            let mut parts = line.split_whitespace();
            let file = parts.next()?.strip_prefix("yw-app/")?;
            let name = parts.next()?;
            let file = FROZEN_MOVED
                .iter()
                .find(|&&(then, _)| then == file)
                .map_or(file, |&(_, now)| now);
            Some((file.to_owned(), name.to_owned()))
        })
        .collect()
}

/// Whether `code` holds `name` as a whole identifier (a frozen test's file names it: in its
/// `fn`, or in the table of a test-generating macro such as the flow goldens').
fn names_word(code: &str, name: &str) -> bool {
    let bytes = code.as_bytes();
    code.match_indices(name).any(|(at, _)| {
        let end = at + name.len();
        (at == 0 || !is_ident(bytes[at - 1])) && bytes.get(end).is_none_or(|&b| !is_ident(b))
    })
}

/// Every file of `frozen_app_tests` names each of its frozen tests, so a stale `FROZEN_MOVED`
/// (a frozen test moved again) fails here instead of allowing nothing.
fn assert_frozen_files_name_their_tests(
    frozen: &BTreeSet<(String, String)>,
    read: &dyn Fn(&str) -> String,
) {
    let files: BTreeSet<&str> = frozen.iter().map(|(file, _)| file.as_str()).collect();
    for file in files {
        let code = read(file);
        let missing: Vec<&str> = frozen
            .iter()
            .filter(|(now, name)| now == file && !names_word(&code, name))
            .map(|(_, name)| name.as_str())
            .collect();
        assert!(
            missing.is_empty(),
            "frozen tests not in {file}: {missing:?}"
        );
    }
}

fn is_kept(list: &[(&str, &str)], name: &str) -> bool {
    list.iter().any(|&(kept, _)| kept == name)
}

/// The identifier that starts at `at` in `code` (empty when none does).
fn ident_at(code: &str, at: usize) -> &str {
    let end = code[at..]
        .bytes()
        .position(|byte| !is_ident(byte))
        .map_or(code.len(), |n| at + n);
    &code[at..end]
}

/// The offsets where the entries of the `{ … }` group whose `{` is at `open` of `code` start
/// (its own entries; a `,` of a nested group splits nothing here).
fn group_entries(code: &str, open: usize) -> Vec<usize> {
    let bytes = code.as_bytes();
    let close = close_of(bytes, open);
    let mut depth = 0_usize;
    let mut entry = open + 1;
    let mut leads = Vec::new();
    for (n, &byte) in bytes.iter().enumerate().take(close + 1).skip(open + 1) {
        match byte {
            b'{' => depth += 1,
            b',' | b'}' if depth == 0 => {
                let text = &code[entry..n];
                if !text.trim().is_empty() {
                    leads.push(entry + (text.len() - text.trim_start().len()));
                }
                entry = n + 1;
            }
            b'}' => depth -= 1,
            _ => {}
        }
    }
    leads
}

/// The kept facade entries a path names whose first segment (or `{ … }` group) starts at `at` of
/// `code`: `errors::…`, `ui::approval::…`, `{errors::…, ui::{approval::…}}`, `ui::{approval::…,
/// qr}` (2026-11-23, S4 E3b review: before, a group right after `ui::` was not read).
fn kept_entries_at(code: &str, at: usize) -> Vec<String> {
    if code[at..].starts_with('{') {
        return group_entries(code, at)
            .into_iter()
            .flat_map(|lead| kept_entries_at(code, lead))
            .collect();
    }
    let first = ident_at(code, at);
    if is_kept(&KEPT_LIB_FACADE, first) {
        return vec![first.to_owned()];
    }
    let after = at + first.len();
    if first != "ui" || !code[after..].starts_with("::") {
        return Vec::new();
    }
    let rest = after + 2;
    let seconds = if code[rest..].starts_with('{') {
        group_entries(code, rest)
    } else {
        vec![rest]
    };
    seconds
        .into_iter()
        .map(|lead| ident_at(code, lead))
        .filter(|second| is_kept(&KEPT_UI_FACADE, second))
        .map(|second| format!("ui::{second}"))
        .collect()
}

/// The offsets of every use of a kept facade entry in `code`, with the entry: a path that starts
/// at one of `roots` (`crate::` and, for the binary `main.rs`, `yw_app::` in yw-app `src`;
/// `yw_app::` in `tests/`) or at `super::` (relative paths; no yw-app module has a child of one
/// of these names), whole or inside `{ … }` groups at any depth.
fn facade_uses(code: &str, roots: &[&str]) -> Vec<(usize, String)> {
    let bytes = code.as_bytes();
    let mut found = Vec::new();
    for &start in roots.iter().chain(&["super::"]) {
        for (at, _) in code.match_indices(start) {
            if (at > 0 && is_ident(bytes[at - 1])) || code[..at].ends_with("::") {
                continue;
            }
            let mut rest = at + start.len();
            while code[rest..].starts_with("super::") {
                rest += "super::".len();
            }
            found.extend(
                kept_entries_at(code, rest)
                    .into_iter()
                    .map(|entry| (at, entry)),
            );
        }
    }
    found
}

/// The names of the fns whose bodies hold offset `at` of `code`.
fn fns_around(code: &str, at: usize) -> Vec<&str> {
    let bytes = code.as_bytes();
    let mut names = Vec::new();
    for (start, _) in code.match_indices("fn ") {
        if start > at || (start > 0 && is_ident(bytes[start - 1])) {
            continue;
        }
        let rest = &code[start + 3..];
        let name_at = start + 3 + (rest.len() - rest.trim_start().len());
        let name = ident_at(code, name_at);
        let open = code[name_at..].find(['{', ';']).map(|n| name_at + n);
        if let Some(open) = open.filter(|&open| bytes[open] == b'{' && open < at)
            && at <= close_of(bytes, open)
            && !name.is_empty()
        {
            names.push(name);
        }
    }
    names
}

/// The outer attributes and the visibility of the item whose `use` keyword is at `at` of `code`,
/// separated by one space (`#[doc(hidden)] pub`; empty for a private `use` with no attribute).
/// An inner attribute (`#![…]`) ends the search.
fn item_form(code: &str, at: usize) -> String {
    let mut head = code[..at].trim_end();
    let mut vis = "";
    for word in ["pub(crate)", "pub(super)", "pub(self)", "pub"] {
        if let Some(rest) = head.strip_suffix(word)
            && rest.bytes().next_back().is_none_or(|byte| !is_ident(byte))
        {
            vis = word;
            head = rest.trim_end();
            break;
        }
    }
    let mut parts = vec![vis.to_owned()];
    while head.ends_with(']') {
        let bytes = head.as_bytes();
        let mut depth = 0_usize;
        let mut open = None;
        for (n, &byte) in bytes.iter().enumerate().rev() {
            match byte {
                b']' => depth += 1,
                b'[' => {
                    depth = depth.saturating_sub(1);
                    if depth == 0 {
                        open = Some(n);
                        break;
                    }
                }
                _ => {}
            }
        }
        let Some(open) = open.filter(|&open| head[..open].ends_with('#')) else {
            break;
        };
        let attr: String = head[open - 1..]
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect();
        parts.insert(0, attr);
        head = head[..open - 1].trim_end();
    }
    parts.retain(|part| !part.is_empty());
    parts.join(" ")
}

/// The names the `use yw_engine::…;` statements at depth 0 of `code` bind, each with its item's
/// form (`item_form`), sorted.
fn engine_reexports(code: &str) -> Vec<(String, String)> {
    let blocks = blocks_of(code.as_bytes());
    let mut names = Vec::new();
    for (at, _) in code.match_indices("use yw_engine::") {
        if blocks
            .iter()
            .any(|block| block.open < at && at < block.close)
        {
            continue;
        }
        let form = item_form(code, at);
        let end = code[at..].find(';').map_or(code.len(), |n| at + n);
        let path = &code[at + "use yw_engine::".len()..end];
        let entries: Vec<&str> = match path.find('{') {
            Some(open) => path[open + 1..path.rfind('}').unwrap_or(path.len())]
                .split(',')
                .collect(),
            None => vec![path],
        };
        for entry in entries.iter().map(|entry| entry.trim()) {
            if entry.is_empty() {
                continue;
            }
            let bound = match entry.rsplit_once(" as ") {
                Some((_, alias)) => alias,
                None => entry.rsplit("::").next().unwrap_or(entry),
            };
            names.push((bound.trim().to_owned(), form.clone()));
        }
    }
    names.sort();
    names
}

/// Every `pub`/`pub(…)` `use yw_engine::…;` of `code` (in a block too, unless `depth0` is
/// false: then only those inside a block), as `file|form use path` with the whitespace
/// collapsed.
fn pub_engine_uses(rel: &str, code: &str, depth0: bool) -> Vec<String> {
    let blocks = blocks_of(code.as_bytes());
    let mut found = Vec::new();
    for (at, _) in code.match_indices("use yw_engine::") {
        let nested = blocks
            .iter()
            .any(|block| block.open < at && at < block.close);
        let form = item_form(code, at);
        if !(depth0 || nested) || !form.split(' ').any(|word| word.starts_with("pub")) {
            continue;
        }
        let end = code[at..].find(';').map_or(code.len(), |n| at + n);
        let text: Vec<&str> = code[at..end].split_whitespace().collect();
        found.push(format!("{rel}|{form} {}", text.join(" ")));
    }
    found
}

/// Source check `the_kept_facade_is_named_only_by_frozen_tests` (2026-11-23, S4d E3b, preflight
/// §2 E3b "optional source check", critic C16): the S2 facade is gone but for the entries that
/// the bodies of the tests frozen at F-A name (`s4_flow/frozen-tests.txt`, never changed), and no
/// other code names them. Every `crate::`/`yw_app::`/`super::` path in yw-app `src` and every
/// `yw_app::`/`super::` path in yw-app `tests/` that starts with a kept entry (whole or in
/// `{ … }` groups) lies in the body of a frozen test of that file, and every kept entry has such
/// a user (an unused one goes). `lib.rs` and `ui/mod.rs` re-export exactly the kept entries from
/// yw-engine, each in its form (`#[doc(hidden)] pub` or `#[cfg(test)] pub(crate)`), and
/// `browser/mod.rs` nothing; yw-app `src` has no other public yw-engine re-export than
/// `OTHER_ENGINE_REEXPORTS`. Finds what it checks (A-20). 2026-11-23 (S4 E3b review): the
/// groups after `ui::`, the forms, the other re-exports and the (file, fn) pairs were added.
#[test]
fn the_kept_facade_is_named_only_by_frozen_tests() {
    let frozen = frozen_app_tests();
    assert!(frozen.len() > 50, "frozen yw-app tests: {}", frozen.len());
    let app = Path::new(env!("CARGO_MANIFEST_DIR"));
    let read = |rel: &str| code_only(&std::fs::read_to_string(app.join(rel)).unwrap());
    assert_frozen_files_name_their_tests(&frozen, &read);
    let mut scanned = 0_usize;
    let mut used: BTreeMap<String, usize> = BTreeMap::new();
    let mut stray = Vec::new();
    let mut reexports = Vec::new();
    let src: &[&str] = &["crate::", "yw_app::"];
    for (dir, roots) in [("src", src), ("tests", &["yw_app::"])] {
        let mut stack = vec![app.join(dir)];
        while let Some(path) = stack.pop() {
            if path.is_dir() {
                stack.extend(std::fs::read_dir(&path).unwrap().map(|e| e.unwrap().path()));
                continue;
            }
            if path.extension().is_none_or(|ext| ext != "rs") {
                continue;
            }
            let rel = path
                .strip_prefix(app)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            let code = code_only(&std::fs::read_to_string(&path).unwrap());
            let facade = rel == "src/lib.rs" || rel == "src/ui/mod.rs";
            if dir == "src" {
                reexports.extend(pub_engine_uses(&rel, &code, !facade));
            }
            if facade {
                continue;
            }
            scanned += 1;
            for (at, entry) in facade_uses(&code, roots) {
                if fns_around(&code, at)
                    .iter()
                    .any(|&name| frozen.contains(&(rel.clone(), name.to_owned())))
                {
                    *used.entry(entry).or_default() += 1;
                } else {
                    let line = code[..at].matches('\n').count() + 1;
                    stray.push(format!("{rel}:{line} {entry}"));
                }
            }
        }
    }
    assert!(scanned > 100, "scanned {scanned} files");
    assert!(
        stray.is_empty(),
        "facade paths outside frozen test bodies: {stray:#?}"
    );
    let kept: BTreeSet<String> = KEPT_LIB_FACADE
        .iter()
        .map(|&(name, _)| name.to_owned())
        .chain(
            KEPT_UI_FACADE
                .iter()
                .map(|&(name, _)| format!("ui::{name}")),
        )
        .collect();
    assert_eq!(
        used.keys().cloned().collect::<BTreeSet<_>>(),
        kept,
        "every kept entry has a frozen user: {used:?}"
    );
    let forms = |list: &[(&str, &str)]| -> Vec<(String, String)> {
        list.iter()
            .map(|&(name, form)| (name.to_owned(), form.to_owned()))
            .collect()
    };
    assert_eq!(
        engine_reexports(&read("src/lib.rs")),
        forms(&KEPT_LIB_FACADE),
        "lib.rs re-exports and their forms"
    );
    assert_eq!(
        engine_reexports(&read("src/ui/mod.rs")),
        forms(&KEPT_UI_FACADE),
        "ui/mod.rs re-exports and their forms"
    );
    assert!(
        !read("src/browser/mod.rs").contains("use "),
        "browser/mod.rs re-exports nothing"
    );
    reexports.sort();
    let mut listed: Vec<String> = OTHER_ENGINE_REEXPORTS
        .iter()
        .map(|line| line.split_whitespace().collect::<Vec<_>>().join(" "))
        .collect();
    listed.sort();
    assert_eq!(
        reexports, listed,
        "the public yw-engine re-exports of yw-app src beside the kept facade"
    );
}

/// The facade check's readers on made-up code (they can fail).
#[test]
fn facade_uses_on_made_up_code() {
    let code = "use crate::{errors::ErrorCode, ui::approval::QueueSource, store};\n\
                fn frozen() { let x = crate::network::NetworkId::Solana; }\n\
                fn other() { super::super::events::KeyJob::Lock; crate::ui::qr::x(); }\n\
                mod m { pub(crate) use yw_engine::sol; }\n\
                use yw_engine::{btc, errors as e};\n\
                use yw_engine::approval::view as approval_view;\n";
    let uses = facade_uses(code, &["crate::"]);
    let entries: Vec<&str> = uses.iter().map(|(_, entry)| entry.as_str()).collect();
    assert_eq!(entries, ["errors", "ui::approval", "network", "events"]);
    assert!(fns_around(code, uses[0].0).is_empty());
    assert_eq!(fns_around(code, uses[2].0), ["frozen"]);
    assert_eq!(fns_around(code, uses[3].0), ["other"]);
    assert_eq!(
        engine_reexports(code),
        [("approval_view", ""), ("btc", ""), ("e", "")].map(|(n, f)| (n.to_owned(), f.to_owned())),
        "depth 0 only, aliases bound"
    );
    let tests = "fn t() { yw_app::ui::approval_view::x(); yw_app::ui::approval_input::y(); }";
    let found: Vec<String> = facade_uses(tests, &["yw_app::"])
        .into_iter()
        .map(|u| u.1)
        .collect();
    assert_eq!(found, ["ui::approval_view"]);
    // 2026-11-23 (S4 E3b review): groups after `ui::` and groups in groups.
    let groups = "use crate::ui::{approval::QueueOutcome, qr};\n\
                  use crate::{ui::{approval_view::Block}, store::{a, b}};\n\
                  use crate::ui::{self, approval_input::x, approval_view};\n\
                  use crate::{store::{ui, errors_x}, sol};\n\
                  fn f() { super::{errors::E, ui::{qr, approval::{Q, R}}}; }\n\
                  use yw_app::ui::{approval::QueueOutcome};\n\
                  use yw_app::{ui::{approval_view::Block}};\n";
    let found: Vec<String> = facade_uses(groups, &["crate::", "yw_app::"])
        .into_iter()
        .map(|u| u.1)
        .collect();
    assert_eq!(
        found,
        [
            "ui::approval",
            "ui::approval_view",
            "ui::approval_view",
            "sol",
            "ui::approval",
            "ui::approval_view",
            "errors",
            "ui::approval",
        ]
    );
    // The forms of the re-exports (2026-11-23, S4 E3b review).
    let forms = "#![forbid(unsafe_code)]\n// note\n#[doc(hidden)]\npub use yw_engine::{btc, meta};\n\
                 #[cfg(test)]\npub(crate) use yw_engine::flow;\nuse yw_engine::sol;\n\
                 pub use yw_engine::network;\nmod m {\n    pub(crate) use yw_engine::zec::X;\n}\n";
    assert_eq!(
        engine_reexports(&code_only(forms)),
        [
            ("btc", DOC_HIDDEN),
            ("flow", TEST_ONLY),
            ("meta", DOC_HIDDEN),
            ("network", "pub"),
            ("sol", ""),
        ]
        .map(|(n, f)| (n.to_owned(), f.to_owned()))
    );
    assert_eq!(
        pub_engine_uses("x.rs", &code_only(forms), false),
        ["x.rs|pub(crate) use yw_engine::zec::X"]
    );
    assert_eq!(
        pub_engine_uses("x.rs", &code_only(forms), true).len(),
        4,
        "btc/meta, flow, network, zec; not the private sol"
    );
    // A frozen test's name alone is no frozen test: the pair names its file of now.
    let frozen = frozen_app_tests();
    let pair = |file: &str, name: &str| (file.to_owned(), name.to_owned());
    assert!(frozen.contains(&pair(
        "src/app/tests/chain_sites.rs",
        "signatures_and_hashes_answer_only_while_the_grant_holds"
    )));
    assert!(frozen.contains(&pair("src/app_approval_flow_tests.rs", "print")));
    assert!(!frozen.contains(&pair("src/app/tests/s3_census.rs", "print")));
    assert!(!frozen.contains(&pair(
        "src/app_chain_sites.rs",
        "signatures_and_hashes_answer_only_while_the_grant_holds"
    )));
}
