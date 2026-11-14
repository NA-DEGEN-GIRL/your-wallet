//! spec/14 (2026-11-14): the English texts of the approval displays, the approval window, the risk
//! rules and the secret windows are fixed in `spec/14-language.md`. These tests read that file and
//! require every listed catalogue to match it exactly in both languages (no entry missing, none
//! extra), and check the catalogue invariants (placeholders, no Hangul in English, valid display
//! text). `print_spec14_tables` (`--ignored --exact --nocapture`) prints the tables from the code.

use core::fmt::Write as _;

use yw_core::approval::{MAX_DISPLAY_VALUE_BYTES, is_valid_display_text};
use yw_core::lang::{Entry, Lang, has_hangul, placeholders};

const SPEC: &str = include_str!("../../../spec/14-language.md");

/// Every catalogue spec/14 lists, by the name its table carries.
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
    vec![
        (
            "yw_app::ui::approval::labels",
            yw_app::ui::approval::labels::ALL.to_vec(),
        ),
        (
            "yw_app::ui::approval_text",
            yw_app::ui::approval_text::ALL.to_vec(),
        ),
        (
            "yw_app::walletconnect::text",
            yw_app::walletconnect::text::ALL.to_vec(),
        ),
        (
            "yw_app::flow::evm::prepare",
            yw_app::flow::evm::prepare::ALL.to_vec(),
        ),
        (
            "yw_app::ui::secret_text",
            yw_app::ui::secret_text::ALL.to_vec(),
        ),
        ("display-fixed", extra),
        (
            "yw_core::evm::risk::text",
            yw_core::evm::risk::text::ALL.to_vec(),
        ),
        ("yw_core::evm::text", yw_core::evm::text::ALL.to_vec()),
        (
            "yw_core::evm::display::text",
            yw_core::evm::display::text::ALL.to_vec(),
        ),
        (
            "yw_core::evm::display::time",
            yw_core::evm::display::time::ALL.to_vec(),
        ),
        (
            "yw_core::journal::evm::text",
            yw_core::journal::evm::text::ALL.to_vec(),
        ),
        (
            "yw_core::approval::message_text",
            yw_core::approval::message_text::ALL.to_vec(),
        ),
        ("yw_core::sol::text", yw_core::sol::text::ALL.to_vec()),
        (
            "yw_core::sol::dapp::text",
            yw_core::sol::dapp::text::ALL.to_vec(),
        ),
        ("yw_core::btc::text", yw_core::btc::text::ALL.to_vec()),
        ("yw_core::zec::text", yw_core::zec::text::ALL.to_vec()),
        (
            "yw_core::hypercore::text",
            yw_core::hypercore::text::ALL.to_vec(),
        ),
        ("yw_core::slip10::text", yw_core::slip10::text::ALL.to_vec()),
    ]
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

/// `\` → `\\`, LF → `\n`, `|` → `\|` (a table cell on one line).
fn escape(text: &str) -> String {
    text.replace('\\', "\\\\")
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
        // character must still pass the display rules.
        for text in [entry.ko, entry.en] {
            if !is_valid_display_text(&format!("a{text}a"), MAX_DISPLAY_VALUE_BYTES, false) {
                problems.push(format!("{name}::{}: not valid display text", entry.name));
            }
        }
    };
    for (name, entries) in catalogues() {
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
