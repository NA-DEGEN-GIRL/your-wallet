//! spec/14 (2026-11-14): every user-visible text of the app is in a catalogue with its English
//! form, fixed in `spec/14-language.md` §5 (the error-code texts in spec/04 §7, D31). These tests
//! read those files and require every catalogue to match them exactly in both languages (no entry
//! missing, none extra), and check the catalogue invariants (placeholders, no Hangul in English,
//! valid display text). `print_spec14_tables` (`--ignored --exact --nocapture`) prints the spec/14
//! tables from the code. `scripts/i18n-scan.mjs` checks that the catalogue registries
//! (`yw_core::lang::catalogues`, `yw_app::catalogues::catalogues`) list every `texts!` block.

use core::fmt::Write as _;

use yw_app::errors::ErrorCode;
use yw_core::approval::{MAX_DISPLAY_VALUE_BYTES, is_valid_display_text};
use yw_core::lang::{Entry, Lang, has_hangul, placeholders};

const SPEC: &str = include_str!("../../../spec/14-language.md");
const SPEC04: &str = include_str!("../../../spec/04-app-ui.md");

/// The error-code catalogue: its canonical table is spec/04 §7 (D31), not spec/14.
const ERRORS: &str = "yw_app::errors::text";

/// Every catalogue of both crates with its entries.
fn registered() -> Vec<(&'static str, Vec<Entry>)> {
    yw_core::lang::catalogues()
        .into_iter()
        .chain(yw_app::catalogues::catalogues())
        .map(|(name, entries)| (name, entries.to_vec()))
        .collect()
}

/// Every catalogue spec/14 lists, by the name its table carries: the registered ones except the
/// error codes, and the fixed display texts that are not in a `texts!` block.
fn catalogues() -> Vec<(&'static str, Vec<Entry>)> {
    let extra = vec![
        entry(
            "APP_ORIGIN",
            yw_core::approval::APP_ORIGIN.ko,
            yw_core::approval::APP_ORIGIN.en,
            0,
        ),
        entry(
            "BTC_MAINNET",
            yw_core::btc::BtcNetwork::Mainnet.banner_in(Lang::Ko),
            yw_core::btc::BtcNetwork::Mainnet.banner_in(Lang::En),
            0,
        ),
        entry(
            "BTC_TESTNET4",
            yw_core::btc::BtcNetwork::Testnet4.banner_in(Lang::Ko),
            yw_core::btc::BtcNetwork::Testnet4.banner_in(Lang::En),
            0,
        ),
    ];
    let mut all: Vec<_> = registered()
        .into_iter()
        .filter(|(name, _)| *name != ERRORS)
        .collect();
    all.push(("display-fixed", extra));
    all
}

const fn entry(name: &'static str, ko: &'static str, en: &'static str, args: usize) -> Entry {
    Entry { name, ko, en, args }
}

/// The rule table rows: id, level word, Korean, English (spec/03 §10 + spec/14 §3).
fn rule_rows() -> Vec<[String; 4]> {
    yw_core::evm::risk::ALL_RULES
        .iter()
        .map(|rule| {
            let level = match yw_core::evm::risk::level_of(*rule) {
                Some(yw_core::approval::RiskLevel::Info) => "정보",
                Some(yw_core::approval::RiskLevel::Caution) => "주의",
                Some(yw_core::approval::RiskLevel::High) => "고위험",
                Some(yw_core::approval::RiskLevel::Blocked) => "차단",
                None => "?",
            };
            [
                rule.label(),
                level.to_owned(),
                yw_core::evm::risk::base_text(*rule, Lang::Ko)
                    .unwrap_or("")
                    .to_owned(),
                yw_core::evm::risk::base_text(*rule, Lang::En)
                    .unwrap_or("")
                    .to_owned(),
            ]
        })
        .collect()
}

/// `\` → `\\`, CR → `\r`, LF → `\n`, `|` → `\|` (a table cell on one line).
fn escape(text: &str) -> String {
    text.replace('\\', "\\\\")
        .replace('\r', "\\r")
        .replace('\n', "\\n")
        .replace('|', "\\|")
}

fn unescape(cell: &str) -> String {
    let mut out = String::new();
    let mut chars = cell.chars();
    while let Some(character) = chars.next() {
        if character == '\\' {
            match chars.next() {
                Some('n') => out.push('\n'),
                Some('r') => out.push('\r'),
                Some(other) => out.push(other),
                None => out.push('\\'),
            }
        } else {
            out.push(character);
        }
    }
    out
}

/// The cells of a `| a | b | c |` row (escaped pipes stay inside a cell).
fn cells(line: &str) -> Vec<String> {
    let inner = line.trim().trim_start_matches('|');
    let inner = inner.strip_suffix('|').unwrap_or(inner);
    let mut out = Vec::new();
    let mut current = String::new();
    let mut escaped = false;
    for character in inner.chars() {
        if escaped {
            current.push('\\');
            current.push(character);
            escaped = false;
        } else if character == '\\' {
            escaped = true;
        } else if character == '|' {
            out.push(unescape(cell_text(&current)));
            current.clear();
        } else {
            current.push(character);
        }
    }
    out.push(unescape(cell_text(&current)));
    out
}

/// A cell without the one separator space on each side (edge spaces of the text are kept).
fn cell_text(raw: &str) -> &str {
    let raw = raw.strip_prefix(' ').unwrap_or(raw);
    raw.strip_suffix(' ').unwrap_or(raw)
}

/// The data rows of the table after `<!-- catalogue: name -->` (header and rule lines skipped).
fn table(name: &str) -> Vec<Vec<String>> {
    let marker = format!("<!-- catalogue: {name} -->");
    let Some(start) = SPEC.find(&marker) else {
        return Vec::new();
    };
    SPEC.get(start + marker.len()..)
        .unwrap_or("")
        .lines()
        .skip_while(|line| !line.starts_with('|'))
        .take_while(|line| line.starts_with('|'))
        .skip(2)
        .map(cells)
        .collect()
}

#[test]
fn spec14_lists_every_catalogue_exactly() {
    let mut problems = Vec::new();
    for (name, entries) in catalogues() {
        let rows = table(name);
        if rows.is_empty() {
            problems.push(format!("{name}: no table in spec/14"));
            continue;
        }
        for entry in &entries {
            match rows
                .iter()
                .find(|row| row.first().map(String::as_str) == Some(entry.name))
            {
                Some(row) => {
                    if row.get(1).map(String::as_str) != Some(entry.ko) {
                        problems.push(format!("{name}::{}: Korean differs", entry.name));
                    }
                    if row.get(2).map(String::as_str) != Some(entry.en) {
                        problems.push(format!("{name}::{}: English differs", entry.name));
                    }
                }
                None => problems.push(format!("{name}::{}: not in spec/14", entry.name)),
            }
        }
        for row in &rows {
            let listed = row.first().map_or("", String::as_str);
            if !entries.iter().any(|entry| entry.name == listed) {
                problems.push(format!("{name}::{listed}: in spec/14 but not in the code"));
            }
        }
    }
    let rules = table("yw_core::evm::risk (rules)");
    let expected = rule_rows();
    if rules.len() != expected.len() {
        problems.push(format!(
            "rules: spec/14 has {} rows, the code {}",
            rules.len(),
            expected.len()
        ));
    }
    for row in &expected {
        if !rules
            .iter()
            .any(|listed| listed.as_slice() == row.as_slice())
        {
            problems.push(format!("rule {} differs from spec/14", row[0]));
        }
    }
    assert!(problems.is_empty(), "{}", problems.join("\n"));
}

#[test]
fn every_catalogue_keeps_its_invariants() {
    let mut problems = Vec::new();
    let mut check = |name: &str, entry: &Entry| {
        let ko = placeholders(entry.ko);
        let en = placeholders(entry.en);
        let used = |index: usize| ko.contains(&index) || en.contains(&index);
        if ko.iter().chain(&en).any(|index| *index >= entry.args) || !(0..entry.args).all(used) {
            problems.push(format!("{name}::{}: placeholders", entry.name));
        }
        if has_hangul(entry.en) {
            problems.push(format!("{name}::{}: Hangul in English", entry.name));
        }
        // Fragments may start or end with a space or LF (they are joined into a value); every
        // character must still pass the display rules. CRLF is a line break of a text written
        // to a file for Notepad (the reset folder's README).
        for text in [entry.ko, entry.en] {
            let text = text.replace("\r\n", "\n");
            if !is_valid_display_text(&format!("a{text}a"), MAX_DISPLAY_VALUE_BYTES, false) {
                problems.push(format!("{name}::{}: not valid display text", entry.name));
            }
        }
    };
    for (name, entries) in catalogues()
        .into_iter()
        .chain(registered().into_iter().filter(|(name, _)| *name == ERRORS))
    {
        for entry in &entries {
            check(name, entry);
        }
    }
    for row in rule_rows() {
        if has_hangul(&row[3]) || row[3].is_empty() {
            problems.push(format!("rule {}: English missing or Korean", row[0]));
        }
    }
    assert!(problems.is_empty(), "{}", problems.join("\n"));
}

/// A spec/04 table row's cells as written (`\|` is a pipe inside a cell; nothing else is
/// unescaped, so paths keep their backslashes).
fn raw_cells(line: &str) -> Vec<String> {
    let inner = line.trim().trim_start_matches('|');
    let inner = inner.strip_suffix('|').unwrap_or(inner);
    let mut out = Vec::new();
    let mut current = String::new();
    let mut previous = ' ';
    for character in inner.chars() {
        if character == '|' && previous != '\\' {
            out.push(current.trim().replace("\\|", "|"));
            current.clear();
        } else {
            current.push(character);
        }
        previous = character;
    }
    out.push(current.trim().replace("\\|", "|"));
    out
}

/// Every `{…}` placeholder as `{}` (the spec names them, the code numbers them).
fn placeholders_blank(text: &str) -> String {
    let mut out = String::new();
    let mut inside = false;
    for character in text.chars() {
        match character {
            '{' => {
                inside = true;
                out.push_str("{}");
            }
            '}' if inside => inside = false,
            _ if inside => {}
            _ => out.push(character),
        }
    }
    out
}

/// spec/04 §7 (2026-11-14): the 문구 and English columns of every error code hold the code's
/// fixed sentences (the spec may add the parenthesised value the code appends).
#[test]
fn spec04_lists_every_error_text_in_both_languages() {
    let section = SPEC04
        .split("## 7. ")
        .nth(1)
        .and_then(|rest| rest.split("\n## ").next())
        .unwrap_or("");
    let mut problems = Vec::new();
    for code in ErrorCode::ALL {
        let prefix = format!("| {} |", code.code());
        let Some(row) = section.lines().find(|line| line.starts_with(&prefix)) else {
            problems.push(format!("{}: no row in spec/04 §7", code.code()));
            continue;
        };
        let cells = raw_cells(row);
        for (column, lang) in [(2, Lang::Ko), (3, Lang::En)] {
            let listed = cells
                .get(column)
                .map_or_else(String::new, |cell| placeholders_blank(cell));
            if !listed.contains(&placeholders_blank(code.message_in(lang))) {
                problems.push(format!(
                    "{} {}: differs from spec/04 §7",
                    code.code(),
                    lang.tag()
                ));
            }
        }
    }
    assert!(problems.is_empty(), "{}", problems.join("\n"));
}

#[test]
fn every_field_key_has_a_label_in_both_languages() {
    for key in 0..=u16::MAX {
        let key = yw_core::approval::FieldKey(key);
        if key.flags().is_some() {
            let text = yw_app::ui::approval::field_label_text(key);
            assert!(
                text.is_some_and(|text| !text.en.is_empty() && !has_hangul(text.en)),
                "{key:?}"
            );
        }
    }
}

#[test]
#[ignore = "prints the spec/14 tables from the code"]
#[expect(clippy::print_stdout, reason = "spec table recording")]
fn print_spec14_tables() {
    let mut out = String::new();
    out.push_str("<!-- catalogue: yw_core::evm::risk (rules) -->\n\n");
    out.push_str("| ID | 등급 | 한국어 | English |\n|---|---|---|---|\n");
    for row in rule_rows() {
        let _ = writeln!(
            out,
            "| {} | {} | {} | {} |",
            row[0],
            row[1],
            escape(&row[2]),
            escape(&row[3])
        );
    }
    for (name, entries) in catalogues() {
        let _ = write!(
            out,
            "\n<!-- catalogue: {name} -->\n\n| 이름 | 한국어 | English |\n|---|---|---|\n"
        );
        for entry in entries {
            let _ = writeln!(
                out,
                "| {} | {} | {} |",
                entry.name,
                escape(entry.ko),
                escape(entry.en)
            );
        }
    }
    println!("{out}");
}
