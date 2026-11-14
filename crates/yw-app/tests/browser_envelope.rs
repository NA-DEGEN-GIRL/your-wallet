//! spec/05 §10.2 R-E1 (request/cancel goldens → structures, unknown keys, widths, literals,
//! cancel sequencing; ported from `archive/spec-v2.4:crates/native-host/src/wire.rs:1118-1143,
//! 1195-1255`), R-E2 (response/event encoders against the goldens, oversize result → -32603),
//! R-E3 (optional `context.compatMode`, spec/05 §2.12) and R-P1 (app side of the pipe hello).

mod common;

use common::browser::{GOLDEN_ID, golden_request, json};
use yw_app::browser::envelope::{
    BrowserEvent, CancelEnvelope, CompatMode, Correlation, EnvelopeError, HelloReject, Id16, Id32,
    Inbound, encode_event, encode_hello_ack, encode_hello_reject, encode_response, parse_hello,
    parse_inbound,
};
use yw_app::ui::approval_view::compat_mode_badge;
use yw_core::policy::{ProviderError, Route};
use yw_json::{Limits, Number, Object, Value};

const CANCEL_GOLDEN: &str = include_str!("../../../extension/native-host/v1-cancel.golden.json");
const RESULT_GOLDEN: &str =
    include_str!("../../../extension/native-host/v1-response-result.golden.json");
const EVENT_GOLDEN: &str = include_str!("../../../extension/native-host/v1-event.golden.json");
const UNAVAILABLE_GOLDEN: &str =
    include_str!("../../../extension/native-host/v1-unavailable-response.golden.json");
const HELLO_GOLDEN: &str = include_str!("../../../extension/native-host/pipe-hello.golden.json");
const HELLO_ACK_GOLDEN: &str =
    include_str!("../../../extension/native-host/pipe-hello-ack.golden.json");

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn value(text: &str) -> TestResult<Value> {
    Ok(yw_json::parse(text.as_bytes(), &Limits::RESPONSE)?)
}

fn with(base: &Value, key: &str, replacement: Option<Value>) -> TestResult<Vec<u8>> {
    let object = base.as_object().ok_or("not an object")?;
    let mut pairs: Vec<(String, Value)> = Vec::new();
    for (name, item) in object.iter() {
        if name == key {
            if let Some(replacement) = &replacement {
                pairs.push((name.to_owned(), replacement.clone()));
            }
        } else {
            pairs.push((name.to_owned(), item.clone()));
        }
    }
    if object.get(key).is_none()
        && let Some(extra) = replacement
    {
        pairs.push((key.to_owned(), extra));
    }
    let object = Object::from_pairs(pairs).ok_or("duplicate key")?;
    Ok(yw_json::to_vec(&Value::Object(object)))
}

fn with_context(key: &str, replacement: Option<Value>) -> TestResult<Vec<u8>> {
    let golden = golden_request();
    let context = golden
        .as_object()
        .and_then(|object| object.get("context"))
        .ok_or("no context")?
        .clone();
    let changed = yw_json::parse(&with(&context, key, replacement)?, &Limits::REQUEST)?;
    with(&golden, "context", Some(changed))
}

fn golden_correlation() -> Correlation {
    Correlation {
        session_id: Id32([0xbb; 32]),
        sequence: 1,
        activation_nonce: Id32({
            let mut bytes = [0; 32];
            bytes[31] = 0x0c;
            bytes
        }),
        request_id: Id16([0x01; 16]),
    }
}

#[test]
fn r_e1_golden_request_maps_to_the_exact_structure() -> TestResult {
    let frame = yw_json::to_vec(&golden_request());
    let Ok(Inbound::Request(request)) = parse_inbound(&frame, GOLDEN_ID, false) else {
        return Err("golden request did not parse".into());
    };
    assert_eq!(request.correlation, golden_correlation());
    assert_eq!(request.deadline_unix_ms, 1_700_000_120_000);
    assert_eq!(request.profile_install_id, Id32([0xaa; 32]));
    assert_eq!(request.method, "eth_chainId");
    assert_eq!(request.params, Value::Array(Vec::new()));
    assert_eq!(request.route, Route::Permission);
    assert_eq!(request.context.tab_id, 17);
    assert_eq!(request.context.document_id, "document-17");
    assert_eq!(request.context.origin.as_str(), "https://dapp.example");
    let mut channel = [0; 32];
    channel[31] = 0x0d;
    assert_eq!(request.context.channel_nonce, Id32(channel));
    // The golden (default mode) has no compatMode.
    assert_eq!(request.context.compat_mode, None);
    Ok(())
}

#[test]
fn r_e3_optional_compat_mode_context_is_strict() -> TestResult {
    // spec/05 §2.12, §6.1: optional `context.compatMode` ∈ {"metamask", "rabby"}; version 1 is
    // unchanged (absent = default mode).
    for (wire, expected) in [
        ("\"metamask\"", CompatMode::MetaMask),
        ("\"rabby\"", CompatMode::Rabby),
    ] {
        let frame = with_context("compatMode", Some(json(wire)))?;
        let Ok(Inbound::Request(request)) = parse_inbound(&frame, GOLDEN_ID, false) else {
            return Err(format!("compatMode {wire} did not parse").into());
        };
        assert_eq!(request.context.compat_mode, Some(expected));
        // Everything else is the golden context.
        assert_eq!(request.context.origin.as_str(), "https://dapp.example");
        assert_eq!(request.context.tab_id, 17);
    }
    let invalid = EnvelopeError::Invalid(golden_correlation());
    for wire in [
        "\"off\"",
        "\"MetaMask\"",
        "\"RABBY\"",
        "\"\"",
        "\"metamask \"",
        "null",
        "1",
        "true",
        "[\"metamask\"]",
        "{}",
    ] {
        let frame = with_context("compatMode", Some(json(wire)))?;
        assert_eq!(
            parse_inbound(&frame, GOLDEN_ID, false),
            Err(invalid),
            "compatMode {wire}"
        );
    }
    // The optional key does not open the context to other keys.
    let frame = with_context("compatMode", Some(json("\"metamask\"")))?;
    let parsed = yw_json::parse(&frame, &Limits::REQUEST)?;
    let context = parsed
        .as_object()
        .and_then(|object| object.get("context"))
        .ok_or("no context")?
        .clone();
    let extra = yw_json::parse(&with(&context, "extra", Some(json("1")))?, &Limits::REQUEST)?;
    assert_eq!(
        parse_inbound(&with(&parsed, "context", Some(extra))?, GOLDEN_ID, false),
        Err(invalid)
    );
    let missing = yw_json::parse(&with(&context, "tabId", None)?, &Limits::REQUEST)?;
    assert_eq!(
        parse_inbound(&with(&parsed, "context", Some(missing))?, GOLDEN_ID, false),
        Err(invalid)
    );
    // Wire values, labels and the window badge.
    for mode in [CompatMode::MetaMask, CompatMode::Rabby] {
        assert_eq!(CompatMode::parse(mode.as_str()), Some(mode));
    }
    assert_eq!(CompatMode::parse("off"), None);
    assert_eq!(
        compat_mode_badge(yw_core::lang::Lang::Ko, CompatMode::MetaMask),
        "호환 모드: MetaMask"
    );
    assert_eq!(
        compat_mode_badge(yw_core::lang::Lang::Ko, CompatMode::Rabby),
        "호환 모드: Rabby"
    );
    Ok(())
}

#[test]
fn r_e1_unknown_keys_widths_literals_fail_per_request() -> TestResult {
    let golden = golden_request();
    let invalid = EnvelopeError::Invalid(golden_correlation());
    for frame in [
        with(&golden, "extra", Some(Value::Bool(true)))?,
        with(&golden, "role", Some(json("\"broker\"")))?,
        with(&golden, "namespace", Some(json("\"other\"")))?,
        with(&golden, "version", Some(json("2")))?,
        with(&golden, "kind", Some(json("\"other\"")))?,
        with(&golden, "route", Some(json("\"admin\"")))?,
        with(&golden, "deadlineUnixMs", Some(json("9007199254740992")))?,
        with(&golden, "deadlineUnixMs", Some(json("0")))?,
        with(&golden, "profileInstallId", Some(json("\"aa\"")))?,
        with(
            &golden,
            "profileInstallId",
            Some(json(&format!("\"{}\"", "0".repeat(64)))),
        )?,
        with(&golden, "method", Some(json("\"\"")))?,
        with(
            &golden,
            "method",
            Some(json(&format!("\"{}\"", "a".repeat(97)))),
        )?,
        with(&golden, "params", Some(json("\"x\"")))?,
        with(&golden, "context", None)?,
        with_context(
            "extensionId",
            Some(json("\"ponmlkjihgfedcbaponmlkjihgfedcba\"")),
        )?,
        with_context("browserFamily", Some(json("\"firefox\"")))?,
        with_context("frameId", Some(json("1")))?,
        with_context("tabId", Some(json("-1")))?,
        with_context("documentId", Some(json("\"doc id\"")))?,
        with_context("topOrigin", Some(json("\"https://Dapp.example\"")))?,
        with_context("topOrigin", Some(json("\"http://example.com\"")))?,
        with_context("frameOrigin", Some(json("\"https://other.example\"")))?,
        with_context("documentLifecycle", Some(json("\"prerender\"")))?,
        with_context("channelNonce", Some(json("\"0d\"")))?,
        with_context("extra", Some(json("1")))?,
    ] {
        assert_eq!(parse_inbound(&frame, GOLDEN_ID, false), Err(invalid));
    }
    // Uncorrelated: not JSON, bad correlation fields.
    for frame in [
        b"{".to_vec(),
        b"[]".to_vec(),
        with(&golden, "sessionId", Some(json("\"aa\"")))?,
        with(&golden, "sequence", Some(json("0")))?,
        with(&golden, "sequence", Some(json("1.5")))?,
        with(&golden, "requestId", Some(json("\"01\"")))?,
        with(&golden, "activationNonce", None)?,
    ] {
        assert_eq!(
            parse_inbound(&frame, GOLDEN_ID, false),
            Err(EnvelopeError::Uncorrelated)
        );
    }
    // `.0` integers are envelope integers (spec/05 §6.1).
    let dot_zero = with(&golden, "deadlineUnixMs", Some(json("1700000120000.0")))?;
    assert!(matches!(
        parse_inbound(&dot_zero, GOLDEN_ID, false),
        Ok(Inbound::Request(_))
    ));
    Ok(())
}

#[test]
fn r_e1_localhost_toggle_and_pinned_id() -> TestResult {
    let http = with_context("topOrigin", Some(json("\"http://localhost:5173\"")))?;
    let frame = {
        let parsed = yw_json::parse(&http, &Limits::REQUEST).unwrap();
        let context = parsed.as_object().unwrap().get("context").unwrap().clone();
        let context = yw_json::parse(
            &with(
                &context,
                "frameOrigin",
                Some(json("\"http://localhost:5173\"")),
            )?,
            &Limits::REQUEST,
        )
        .unwrap();
        with(&parsed, "context", Some(context))?
    };
    assert_eq!(
        parse_inbound(&frame, GOLDEN_ID, false),
        Err(EnvelopeError::LocalhostDisabled(golden_correlation()))
    );
    assert!(matches!(
        parse_inbound(&frame, GOLDEN_ID, true),
        Ok(Inbound::Request(_))
    ));
    let golden = yw_json::to_vec(&golden_request());
    assert_eq!(
        parse_inbound(&golden, "nnpjlobjgbanccjddghlpaafpohfkeph", false),
        Err(EnvelopeError::Invalid(golden_correlation()))
    );
    Ok(())
}

#[test]
fn r_e1_cancel_golden_and_sequencing() -> TestResult {
    let Ok(Inbound::Cancel(cancel)) = parse_inbound(CANCEL_GOLDEN.as_bytes(), GOLDEN_ID, false)
    else {
        return Err("cancel golden did not parse".into());
    };
    let correlation = golden_correlation();
    assert_eq!(
        cancel,
        CancelEnvelope {
            session_id: correlation.session_id,
            sequence: 2,
            activation_nonce: correlation.activation_nonce,
            request_id: correlation.request_id,
            request_sequence: 1,
            reason: "deadline".to_owned(),
        }
    );
    let golden = value(CANCEL_GOLDEN)?;
    for frame in [
        with(&golden, "requestSequence", Some(json("2")))?,
        with(&golden, "requestSequence", Some(json("0")))?,
        with(&golden, "reason", Some(json("\"bad reason\"")))?,
        with(
            &golden,
            "reason",
            Some(json(&format!("\"{}\"", "a".repeat(129)))),
        )?,
        with(&golden, "extra", Some(json("1")))?,
        with(&golden, "role", Some(json("\"native-host\"")))?,
    ] {
        assert_eq!(
            parse_inbound(&frame, GOLDEN_ID, false),
            Err(EnvelopeError::Uncorrelated)
        );
    }
    Ok(())
}

#[test]
fn r_e2_encoders_match_the_goldens() -> TestResult {
    let correlation = golden_correlation();
    let result = encode_response(&correlation, 1, Ok(&Value::String("0xaa36a7".to_owned())));
    assert_eq!(
        value(std::str::from_utf8(&result).unwrap())?,
        value(RESULT_GOLDEN)?
    );
    let unavailable = encode_response(&correlation, 1, Err(&ProviderError::Unavailable));
    assert_eq!(
        value(std::str::from_utf8(&unavailable).unwrap())?,
        value(UNAVAILABLE_GOLDEN)?
    );
    let event = encode_event(
        &correlation.session_id,
        2,
        &correlation.activation_nonce,
        &BrowserEvent::ChainChanged(1),
    );
    assert_eq!(
        value(std::str::from_utf8(&event).unwrap())?,
        value(EVENT_GOLDEN)?
    );
    // Key order is the golden order.
    assert!(std::str::from_utf8(&result)
        .unwrap()
        .starts_with(r#"{"namespace":"your-wallet","version":1,"role":"native-host","kind":"response","sessionId":""#));
    let accounts = encode_event(
        &correlation.session_id,
        3,
        &correlation.activation_nonce,
        &BrowserEvent::AccountsChanged(vec![[0xab; 20]]),
    );
    assert!(std::str::from_utf8(&accounts).unwrap().ends_with(
        r#""event":"accountsChanged","payload":["0xabababababababababababababababababababab"]}"#
    ));
    Ok(())
}

#[test]
fn r_e2_oversize_or_overdeep_results_become_response_too_large() -> TestResult {
    let correlation = golden_correlation();
    let too_large = Value::String("a".repeat(1_048_576));
    let encoded = encode_response(&correlation, 7, Ok(&too_large));
    let parsed = value(std::str::from_utf8(&encoded).unwrap())?;
    let error = parsed.as_object().unwrap().get("error").unwrap();
    assert_eq!(
        yw_json::to_vec(error),
        br#"{"code":-32603,"message":"Response too large."}"#
    );
    assert_eq!(
        parsed
            .as_object()
            .unwrap()
            .get("sequence")
            .and_then(Value::as_number)
            .and_then(Number::as_u64),
        Some(7)
    );
    // 31 nested arrays fit inside the response root (depth 32); 32 do not.
    let nest = |depth: usize| {
        let mut item = Value::Null;
        for _ in 0..depth {
            item = Value::Array(vec![item]);
        }
        item
    };
    let fits = encode_response(&correlation, 1, Ok(&nest(31)));
    assert!(
        !std::str::from_utf8(&fits)
            .unwrap()
            .contains("Response too large")
    );
    let deep = encode_response(&correlation, 1, Ok(&nest(32)));
    assert!(
        std::str::from_utf8(&deep)
            .unwrap()
            .contains("Response too large")
    );
    // Upstream errors keep their sanitized data.
    let upstream = ProviderError::upstream(Some(3), Some("execution reverted"), Some("0xDEAD"));
    let encoded = encode_response(&correlation, 2, Err(&upstream));
    assert!(
        std::str::from_utf8(&encoded)
            .unwrap()
            .ends_with(r#""error":{"code":3,"message":"execution reverted","data":"0xdead"}}"#)
    );
    Ok(())
}

#[test]
fn r_p1_hello_app_side() -> TestResult {
    let origin = format!("chrome-extension://{GOLDEN_ID}/");
    let hello = parse_hello(HELLO_GOLDEN.as_bytes(), &origin).unwrap();
    assert_eq!(hello.host_version, "0.3.0");
    assert_eq!(hello.pid, 1234);
    assert_eq!(
        parse_hello(
            HELLO_GOLDEN.as_bytes(),
            "chrome-extension://nnpjlobjgbanccjddghlpaafpohfkeph/"
        ),
        Err(HelloReject::Origin)
    );
    let golden = value(HELLO_GOLDEN)?;
    for frame in [
        with(&golden, "protocol", Some(json("2")))?,
        with(&golden, "extra", Some(json("1")))?,
        with(&golden, "pid", Some(json("0")))?,
        with(
            &golden,
            "hostVersion",
            Some(json(&format!("\"{}\"", "1".repeat(33)))),
        )?,
        with(&golden, "kind", Some(json("\"hello-ack\"")))?,
        b"not json".to_vec(),
    ] {
        assert_eq!(parse_hello(&frame, &origin), Err(HelloReject::Protocol));
    }
    let ack = encode_hello_ack("0.3.0");
    assert_eq!(
        value(std::str::from_utf8(&ack).unwrap())?,
        value(HELLO_ACK_GOLDEN)?
    );
    assert_eq!(
        encode_hello_reject(HelloReject::Origin),
        br#"{"kind":"hello-reject","reason":"origin"}"#
    );
    assert_eq!(
        encode_hello_reject(HelloReject::Protocol),
        br#"{"kind":"hello-reject","reason":"protocol"}"#
    );
    Ok(())
}
