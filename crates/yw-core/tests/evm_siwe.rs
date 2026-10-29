//! `personal_sign` and SIWE (spec/03 §9, EVM-V12, spec/09 X-9, X-10, X-20).

use yw_core::approval::{
    ApprovalDraft, ApprovalId, ApprovalKind, ApprovalOrigin, FieldKey, RiskLevel,
    build_personal_request,
};
use yw_core::bip32::path::AccountIndex;
use yw_core::evm::address::parse_address;
use yw_core::evm::chain::sepolia;
use yw_core::evm::eip191::{decode_personal_message, parse_personal_param, personal_preimage};
use yw_core::evm::siwe::{SiweParse, parse_date_time, parse_siwe};
use yw_core::policy::BrowserOrigin;
use yw_core::vault::EvmKeySource;

const BASE: &str = "app.example wants you to sign in with your Ethereum account:\n0x9858EfFD232B4033E47d90003D41EC34EcaEda94\n\nSign in to Example.\n\nURI: https://app.example/login\nVersion: 1\nChain ID: 11155111\nNonce: 32891756\nIssued At: 2026-10-25T23:59:00Z";
const ACC1: &str = "0x9858EfFD232B4033E47d90003D41EC34EcaEda94";

type Fallible<T> = Result<T, Box<dyn std::error::Error>>;

fn now_ms() -> u64 {
    parse_date_time("2026-10-26T00:00:00Z")
        .and_then(|seconds| u64::try_from(seconds).ok())
        .map_or(0, |seconds| seconds * 1_000)
}

fn try_request(message: &str, origin: &str) -> Fallible<ApprovalDraft> {
    Ok(build_personal_request(
        ApprovalId([2; 16]),
        ApprovalOrigin::Site(BrowserOrigin::parse(origin).ok_or("origin")?),
        EvmKeySource::Derived(AccountIndex::ZERO),
        parse_address(ACC1)?,
        ApprovalKind::EvmPersonalSign,
        &sepolia(),
        &decode_personal_message(message.as_bytes().to_vec()),
        now_ms(),
    )?)
}

fn labels(draft: &ApprovalDraft) -> Vec<String> {
    draft
        .display
        .warnings
        .iter()
        .map(|w| w.rule.label())
        .collect()
}

#[test]
fn base_message_passes_and_reassembles() {
    let SiweParse::Message(message) = parse_siwe(BASE) else {
        unreachable!("base message must parse");
    };
    assert_eq!(message.to_text(), BASE);
    assert_eq!(message.domain_host, "app.example");
    assert_eq!(message.chain_id, 11_155_111);
    assert_eq!(message.statement.as_deref(), Some("Sign in to Example."));
    let draft = try_request(BASE, "https://app.example").unwrap();
    assert_eq!(labels(&draft), ["S09"]);
    assert_eq!(draft.display.risk, RiskLevel::Info);
    assert_eq!(draft.display.title, "[Sepolia 테스트넷] 로그인 요청 (SIWE)");
    assert!(
        draft
            .display
            .fields
            .iter()
            .any(|f| f.key == FieldKey::SIWE_FIELD
                && f.sub_label == "도메인"
                && f.value == "app.example")
    );
    // One trailing LF is allowed and reassembled.
    let trailing = format!("{BASE}\n");
    let SiweParse::Message(message) = parse_siwe(&trailing) else {
        unreachable!("trailing LF");
    };
    assert_eq!(message.to_text(), trailing);
    assert_eq!(
        labels(&try_request(&trailing, "https://app.example").unwrap()),
        ["S09"]
    );
}

#[test]
fn x9_siwe_violations() {
    let checksum_error = BASE.replace(
        "0x9858EfFD232B4033E47d90003D41EC34EcaEda94",
        "0x9858EfFD232B4033E47d90003D41EC34EcaEda9A",
    );
    let cases: Vec<(String, &str, RiskLevel)> = vec![
        (
            BASE.replace("app.example wants", "evil.example wants"),
            "S01",
            RiskLevel::Blocked,
        ),
        (
            BASE.replace("app.example wants", "http://app.example wants"),
            "S02",
            RiskLevel::Blocked,
        ),
        (
            BASE.replace("app.example wants", "user@app.example wants"),
            "S02",
            RiskLevel::Blocked,
        ),
        (
            BASE.replace(ACC1, "0x6Fac4D18c912343BF86fa7049364Dd4E424Ab9C0"),
            "S03",
            RiskLevel::Blocked,
        ),
        (checksum_error, "S03", RiskLevel::Blocked),
        (
            format!("{BASE}\nExpiration Time: 2020-01-01T00:00:00Z"),
            "S04",
            RiskLevel::Blocked,
        ),
        (
            BASE.replace("app.example wants", "app.example:8443 wants"),
            "S05",
            RiskLevel::Caution,
        ),
        (
            BASE.replace("Chain ID: 11155111", "Chain ID: 1"),
            "S06",
            RiskLevel::Caution,
        ),
        (
            format!("{BASE}\nNot Before: 2099-01-01T00:00:00Z"),
            "S07",
            RiskLevel::Caution,
        ),
        (
            BASE.replace("Nonce: 32891756", "Nonce: 3289175"),
            "S08",
            RiskLevel::High,
        ),
        (
            BASE.replace("Version: 1\n", "Version: 1\r\n"),
            "S08",
            RiskLevel::High,
        ),
    ];
    for (message, rule, level) in cases {
        let draft = try_request(&message, "https://app.example").unwrap();
        let labels = labels(&draft);
        assert!(labels.contains(&rule.to_owned()), "{rule}: {labels:?}");
        assert!(!labels.contains(&"S09".to_owned()), "{rule}");
        assert_eq!(draft.display.risk, level, "{rule}");
    }
    // Port equal to the effective port is fine; an explicit https port 443 in SIWE matches.
    let same_port = BASE.replace("app.example wants", "app.example:443 wants");
    assert_eq!(
        labels(&try_request(&same_port, "https://app.example").unwrap()),
        ["S09"]
    );
    // An http SIWE from an allowed localhost origin matches its scheme.
    let local = BASE.replace("app.example wants", "http://localhost:5173 wants");
    assert_eq!(
        labels(&try_request(&local, "http://localhost:5173").unwrap()),
        ["S09"]
    );
}

#[test]
fn siwe_optional_fields_round_trip() {
    let full = format!(
        "https://{BASE}\nExpiration Time: 2099-01-01T00:00:00.123+09:00\nNot Before: 2026-10-25T00:00:00z\nRequest ID: abc-1\nResources:\n- https://app.example/a\n- ipfs://bafy"
    );
    let SiweParse::Message(message) = parse_siwe(&full) else {
        unreachable!("full message must parse");
    };
    assert_eq!(message.to_text(), full);
    assert_eq!(message.resources.len(), 2);
    assert_eq!(message.request_id.as_deref(), Some("abc-1"));
    assert_eq!(
        labels(&try_request(&full, "https://app.example").unwrap()),
        ["S09"]
    );
    // ERC-4361: without a statement the address is followed by three LFs.
    let no_statement = BASE.replace("Sign in to Example.\n", "");
    let SiweParse::Message(message) = parse_siwe(&no_statement) else {
        unreachable!("no statement");
    };
    assert_eq!(message.statement, None);
    assert_eq!(message.to_text(), no_statement);
    for broken in [
        BASE.replace("Version: 1", "Version: 2"),
        BASE.replace("URI: https://app.example/login", "URI: not a uri"),
        BASE.replace(
            "Issued At: 2026-10-25T23:59:00Z",
            "Issued At: 2026-02-30T00:00:00Z",
        ),
        format!("{BASE}\n\n"),
        format!("ftp://{BASE}"),
    ] {
        assert_eq!(parse_siwe(&broken), SiweParse::MarkerOnly, "{broken:?}");
    }
    assert_eq!(parse_siwe("hello"), SiweParse::NotSiwe);
    assert_eq!(parse_date_time("1970-01-01T00:00:00Z"), Some(0));
    assert_eq!(parse_date_time("1970-01-01T09:00:00+09:00"), Some(0));
    assert_eq!(parse_date_time("1970-01-01 00:00:00Z"), None);
}

#[test]
fn x10_x20_personal_messages() {
    assert_eq!(
        parse_personal_param("0xff00fe").unwrap(),
        vec![0xff, 0x00, 0xfe]
    );
    let hex = build_personal_request(
        ApprovalId([3; 16]),
        ApprovalOrigin::Site(BrowserOrigin::parse("https://app.example").unwrap()),
        EvmKeySource::Derived(AccountIndex::ZERO),
        parse_address(ACC1).unwrap(),
        ApprovalKind::EvmPersonalSign,
        &sepolia(),
        &decode_personal_message(parse_personal_param("0xff00fe").unwrap()),
        now_ms(),
    )
    .unwrap();
    assert_eq!(labels(&hex), ["P01"]);
    assert_eq!(hex.display.risk, RiskLevel::High);
    assert!(
        hex.display
            .fields
            .iter()
            .any(|f| f.key == FieldKey::MESSAGE_HEX && f.value == "0xff00fe")
    );
    assert_eq!(
        hex.payload,
        yw_core::approval::SigningPayload::EvmPersonal(personal_preimage(&[0xff, 0x00, 0xfe]))
    );

    let bidi = format!("pay {} now", char::from_u32(0x202e).unwrap());
    let draft = try_request(&bidi, "https://app.example").unwrap();
    assert_eq!(labels(&draft), ["P02"]);
    assert!(
        draft
            .display
            .fields
            .iter()
            .any(|f| f.key == FieldKey::MESSAGE_TEXT && f.value == "pay [U+202E] now")
    );
    for code in [0x200b_u32, 0xfeff] {
        let text = format!("a{}b", char::from_u32(code).unwrap());
        let draft = try_request(&text, "https://app.example").unwrap();
        assert_eq!(labels(&draft), ["P02"], "{code:x}");
        assert!(draft.display.validate().is_ok());
    }
    let plain = try_request("Some data", "https://app.example").unwrap();
    assert_eq!(labels(&plain), ["P03"]);
    // Surrounding whitespace is escaped rather than dropped; the empty message is labelled.
    let padded = try_request(" hi\n", "https://app.example").unwrap();
    assert!(
        padded
            .display
            .fields
            .iter()
            .any(|f| f.key == FieldKey::MESSAGE_TEXT && f.value == "[U+0020]hi[U+000A]")
    );
    let empty = try_request("", "https://app.example").unwrap();
    assert!(
        empty
            .display
            .fields
            .iter()
            .any(|f| f.key == FieldKey::MESSAGE_TEXT && f.value == "(빈 메시지)")
    );
}

#[test]
fn x20_siwe_statement_with_bidi_is_not_siwe_but_escaped() {
    let statement = format!("Sign in{}", char::from_u32(0x202e).unwrap());
    let message = BASE.replace("Sign in to Example.", &statement);
    let draft = try_request(&message, "https://app.example").unwrap();
    let labels = labels(&draft);
    assert!(
        labels.contains(&"S08".to_owned()) && labels.contains(&"P02".to_owned()),
        "{labels:?}"
    );
    assert!(
        draft
            .display
            .fields
            .iter()
            .any(|f| f.key == FieldKey::MESSAGE_TEXT && f.value.contains("Sign in[U+202E]"))
    );
}

fn message_text(draft: &ApprovalDraft) -> Option<&str> {
    draft
        .display
        .fields
        .iter()
        .find(|f| f.key == FieldKey::MESSAGE_TEXT)
        .map(|f| f.value.as_str())
}

/// C4: a SIWE first line whose grammar fails still gets the domain checks — otherwise breaking
/// one field (here a 7-character nonce) would skip S01.
#[test]
fn c4_marker_only_still_checks_the_domain() {
    let broken = BASE.replace("Nonce: 32891756", "Nonce: 3289175");
    for (message, rules, level) in [
        (
            broken.replace("app.example wants", "evil.example wants"),
            vec!["S01", "S08"],
            RiskLevel::Blocked,
        ),
        (
            broken.replace("app.example wants", "http://app.example wants"),
            vec!["S02", "S08"],
            RiskLevel::Blocked,
        ),
        (
            broken.replace("app.example wants", "user@app.example wants"),
            vec!["S02", "S08"],
            RiskLevel::Blocked,
        ),
        (
            broken.replace("app.example wants", "app.example:8443 wants"),
            vec!["S08", "S05"],
            RiskLevel::High,
        ),
        // Unreadable authority: text before the marker, another scheme, nothing at all.
        (
            broken.replace("app.example wants", "Please visit app.example wants"),
            vec!["S01", "S08"],
            RiskLevel::Blocked,
        ),
        (
            broken.replace("app.example wants", "ftp://app.example wants"),
            vec!["S01", "S08"],
            RiskLevel::Blocked,
        ),
        (
            broken.replace("app.example wants", "wants"),
            vec!["S01", "S08"],
            RiskLevel::Blocked,
        ),
        // The matching domain with a broken body stays high risk (S08) only.
        (broken.clone(), vec!["S08"], RiskLevel::High),
    ] {
        let draft = try_request(&message, "https://app.example").unwrap();
        assert_eq!(labels(&draft), rules, "{message:?}");
        assert_eq!(draft.display.risk, level, "{message:?}");
    }
    let unreadable = try_request(
        &broken.replace("app.example wants", "Please visit app.example wants"),
        "https://app.example",
    )
    .unwrap();
    assert!(
        unreadable.display.warnings[0]
            .text
            .ends_with("SIWE 형식의 첫 줄에서 도메인을 읽을 수 없습니다")
    );
}

/// Review: leading blank lines or spaces do not hide the SIWE marker. The message is marker-only
/// (S08, the strict grammar still fails) and its domain is still checked (S01 blocks).
#[test]
fn leading_whitespace_keeps_the_siwe_domain_check() {
    let evil = BASE.replace("app.example wants", "evil.example wants");
    for prefix in ["\n", "\n\n", "  ", " \t\r\n \n", "\r\n"] {
        let hidden = format!("{prefix}{evil}");
        assert_eq!(parse_siwe(&hidden), SiweParse::MarkerOnly, "{prefix:?}");
        let draft = try_request(&hidden, "https://app.example").unwrap();
        assert_eq!(labels(&draft), ["S01", "S08"], "{prefix:?}");
        assert_eq!(draft.display.risk, RiskLevel::Blocked, "{prefix:?}");
        let padded = format!("{prefix}{BASE}");
        let draft = try_request(&padded, "https://app.example").unwrap();
        assert_eq!(labels(&draft), ["S08"], "{prefix:?}");
        assert_eq!(draft.display.risk, RiskLevel::High, "{prefix:?}");
    }
    // A marker that is not on the first non-blank line is not SIWE (plain message).
    assert_eq!(parse_siwe(&format!("hello\n{evil}")), SiweParse::NotSiwe);
}

/// C5: exactly 32 bytes (a hash) or C0 controls other than TAB/LF/CR → hex, high risk (P04).
#[test]
fn c5_binary_looking_messages_are_hex_and_high() {
    for (message, cause) in [
        (
            "0123456789abcdef0123456789abcdef".to_owned(),
            "정확히 32바이트입니다 — 해시에 서명하는 것일 수 있습니다",
        ),
        (
            "Sign in\u{1}\u{8}\u{8}\u{8} to Example".to_owned(),
            "TAB·줄바꿈 외의 제어 문자가 있습니다",
        ),
        (
            "bell\u{7f}".to_owned(),
            "TAB·줄바꿈 외의 제어 문자가 있습니다",
        ),
    ] {
        let draft = try_request(&message, "https://app.example").unwrap();
        assert_eq!(labels(&draft), ["P04"], "{message:?}");
        assert!(draft.display.warnings[0].text.ends_with(cause));
        assert_eq!(draft.display.risk, RiskLevel::High);
        assert!(message_text(&draft).is_none());
        assert!(
            draft
                .display
                .fields
                .iter()
                .any(|f| f.key == FieldKey::MESSAGE_HEX
                    && f.value == format!("0x{}", yw_core::hex::encode(message.as_bytes())))
        );
    }
    // A SIWE-looking message with a control character keeps the domain checks.
    let hidden = format!("{BASE}\u{1}").replace("app.example wants", "evil.example wants");
    let draft = try_request(&hidden, "https://app.example").unwrap();
    assert_eq!(labels(&draft), ["S01", "P04", "S08"]);
    assert_eq!(draft.display.risk, RiskLevel::Blocked);
    // TAB, LF and CR alone stay text.
    let ok = try_request("a\tb\r\nc", "https://app.example").unwrap();
    assert!(message_text(&ok).is_some());
}

/// C13: line breaks are visible inside the message value, so a line cannot pass for a row.
#[test]
fn c13_message_line_breaks_are_marked() {
    let draft = try_request(
        "Sign in\n받는 주소: 0x2222222222222222222222222222222222222222",
        "https://app.example",
    )
    .unwrap();
    assert_eq!(
        message_text(&draft),
        Some("Sign in[U+000A]\n받는 주소: 0x2222222222222222222222222222222222222222")
    );
    assert_eq!(labels(&draft), ["P03"]);
    // Every line break of a SIWE message is marked too; the parsed fields are unaffected.
    let siwe = try_request(BASE, "https://app.example").unwrap();
    let text = message_text(&siwe).unwrap();
    assert_eq!(text.matches('\n').count(), BASE.matches('\n').count());
    assert_eq!(
        text.matches("[U+000A]\n").count(),
        BASE.matches('\n').count()
    );
    assert_eq!(labels(&siwe), ["S09"]);
}

/// C14: look-alike spaces and overlay marks in a message are escaped and flagged (P02).
#[test]
fn c14_look_alike_characters_in_messages() {
    for (character, escaped) in [
        ('\u{00A0}', "[U+00A0]"),
        ('\u{2007}', "[U+2007]"),
        ('\u{3000}', "[U+3000]"),
        ('\u{0336}', "[U+0336]"),
        ('\u{2800}', "[U+2800]"),
        ('\u{FFFC}', "[U+FFFC]"),
    ] {
        let draft =
            try_request(&format!("pay 1{character}000 now"), "https://app.example").unwrap();
        assert_eq!(labels(&draft), ["P02"], "{escaped}");
        assert_eq!(
            message_text(&draft),
            Some(format!("pay 1{escaped}000 now").as_str())
        );
        assert!(draft.display.validate().is_ok());
    }
}
