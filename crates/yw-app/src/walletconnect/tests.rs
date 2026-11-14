#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_precision_loss,
    clippy::cast_possible_wrap,
    clippy::too_many_lines
)]

use std::sync::{Arc, Mutex};

use qrcodegen::{QrCode, QrCodeEcc};
use yw_core::walletconnect::{
    Envelope, X25519Secret, derive_sym_key, open_envelope, seal_envelope, topic_of,
};
use yw_json::Value;

use super::qr_decode::{Gray, decode, decode_bgra_text, dib_to_bgra};

const URI: &str = "wc:9e5b70f5ddde5d6f3f5a7b9b4a0a3c2d1e0f9a8b7c6d5e4f3a2b1c0d9e8f7a6b@2?expiryTimestamp=1762430000&relay-protocol=irn&symKey=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef&methods=wc_sessionPropose,wc_sessionAuthenticate";

// ----- QR rendering for the decoder tests --------------------------------------------------

struct Scene {
    width: usize,
    height: usize,
    /// Module size in pixels.
    module: f64,
    /// Rotation in degrees.
    angle: f64,
    /// Code centre.
    center: (f64, f64),
    dark: u8,
    light: u8,
    background: u8,
}

fn matrix(qr: &QrCode) -> (usize, Vec<bool>) {
    let size = qr.size();
    let mut out = Vec::new();
    for y in 0..size {
        for x in 0..size {
            out.push(qr.get_module(x, y));
        }
    }
    (size as usize, out)
}

/// Renders the matrix with a 4-module quiet zone, rotated and scaled, 3×3 supersampled, on a
/// "screenshot" background with a few dark UI boxes away from the code.
fn render(size: usize, modules: &[bool], scene: &Scene) -> Vec<u8> {
    let total = size as f64 + 8.0;
    let (sin, cos) = scene.angle.to_radians().sin_cos();
    let mut pixels = Vec::with_capacity(scene.width * scene.height * 4);
    let mut seed = 0x1234_5678_u32;
    let mut boxes = Vec::new();
    for _ in 0..6 {
        seed = seed.wrapping_mul(1_103_515_245).wrapping_add(12_345);
        let x = (seed >> 8) as usize % scene.width;
        seed = seed.wrapping_mul(1_103_515_245).wrapping_add(12_345);
        let y = (seed >> 8) as usize % scene.height;
        boxes.push((x, y));
    }
    let half = total * scene.module / 2.0;
    for py in 0..scene.height {
        for px in 0..scene.width {
            let mut sum = 0.0;
            let mut inside_any = false;
            for sy in 0..3 {
                for sx in 0..3 {
                    let fx = px as f64 + (f64::from(sx) + 0.5) / 3.0 - scene.center.0;
                    let fy = py as f64 + (f64::from(sy) + 0.5) / 3.0 - scene.center.1;
                    // Inverse rotation into the code frame.
                    let rx = fx * cos + fy * sin;
                    let ry = -fx * sin + fy * cos;
                    let mx = (rx + half) / scene.module - 4.0;
                    let my = (ry + half) / scene.module - 4.0;
                    let inside_quiet = (rx + half) >= 0.0
                        && (ry + half) >= 0.0
                        && (rx + half) < total * scene.module
                        && (ry + half) < total * scene.module;
                    inside_any |= inside_quiet;
                    let value = if !inside_quiet {
                        let near_box = boxes
                            .iter()
                            .any(|(bx, by)| px.abs_diff(*bx) < 18 && py.abs_diff(*by) < 10);
                        if near_box {
                            40.0
                        } else {
                            f64::from(scene.background)
                        }
                    } else if mx >= 0.0
                        && my >= 0.0
                        && (mx as usize) < size
                        && (my as usize) < size
                        && modules[my as usize * size + mx as usize]
                    {
                        f64::from(scene.dark)
                    } else {
                        f64::from(scene.light)
                    };
                    sum += value;
                }
            }
            let _ = inside_any;
            let value = (sum / 9.0).round().clamp(0.0, 255.0) as u8;
            pixels.extend_from_slice(&[value, value, value, 255]);
        }
    }
    pixels
}

fn scene(width: usize, height: usize, module: f64, angle: f64) -> Scene {
    Scene {
        width,
        height,
        module,
        angle,
        center: (width as f64 / 2.0, height as f64 / 2.0),
        dark: 20,
        light: 250,
        background: 230,
    }
}

fn decode_scene(qr: &QrCode, scene: &Scene) -> Option<String> {
    let (size, modules) = matrix(qr);
    let pixels = render(size, &modules, scene);
    decode_bgra_text(scene.width, scene.height, &pixels)
}

/// Codes made by the app's own encoder (`qrcodegen`), several versions and levels, upright.
#[test]
fn qr_decodes_generated_codes() {
    let long = format!("{URI}&relay-data=");
    for (text, ecc) in [
        (URI, QrCodeEcc::Medium),
        (URI, QrCodeEcc::Low),
        (URI, QrCodeEcc::High),
        (long.as_str(), QrCodeEcc::Quartile),
        ("HELLO WORLD 123", QrCodeEcc::Medium),
        ("31415926535897932384626433", QrCodeEcc::Low),
    ] {
        let qr = QrCode::encode_text(text, ecc).unwrap();
        let module = 4.0;
        let side = ((f64::from(qr.size()) + 8.0) * module) as usize + 40;
        let found = decode_scene(&qr, &scene(side, side, module, 0.0));
        assert_eq!(
            found.as_deref(),
            Some(text),
            "version {}",
            qr.version().value()
        );
    }
}

/// Screenshot-like samples: rotated and non-integer scaled codes inside a larger image with UI
/// boxes, a 90° turn, a light-on-dark code, and a high-version code.
#[test]
fn qr_decodes_rotated_scaled_and_inverted_screenshots() {
    let qr = QrCode::encode_text(URI, QrCodeEcc::Medium).unwrap();
    for (module, angle) in [
        (3.3, 17.0),
        (2.6, -8.0),
        (5.1, 90.0),
        (3.0, 180.0),
        (4.4, 33.0),
    ] {
        let found = decode_scene(&qr, &scene(900, 700, module, angle));
        assert_eq!(
            found.as_deref(),
            Some(URI),
            "module {module}, angle {angle}"
        );
    }
    let mut dark_mode = scene(700, 600, 3.5, 5.0);
    dark_mode.dark = 245;
    dark_mode.light = 25;
    dark_mode.background = 30;
    assert_eq!(decode_scene(&qr, &dark_mode).as_deref(), Some(URI));
    let big = "x".repeat(700);
    let qr = QrCode::encode_text(&big, QrCodeEcc::Medium).unwrap();
    assert!(qr.version().value() >= 15);
    let found = decode_scene(&qr, &scene(1_000, 1_000, 6.0, 4.0));
    assert_eq!(found.as_deref(), Some(big.as_str()));
}

/// Reed–Solomon corrects damaged modules (a smudge over part of the data area).
#[test]
fn qr_corrects_damaged_modules() {
    let qr = QrCode::encode_text(URI, QrCodeEcc::Medium).unwrap();
    let (size, mut modules) = matrix(&qr);
    for y in 22..26 {
        for x in 20..26 {
            modules[y * size + x] = !modules[y * size + x];
        }
    }
    let scene = scene(500, 500, 4.0, 0.0);
    let pixels = render(size, &modules, &scene);
    assert_eq!(
        decode_bgra_text(scene.width, scene.height, &pixels).as_deref(),
        Some(URI)
    );
    // No code at all.
    let blank = Gray::new(64, 64, vec![255; 64 * 64]).unwrap();
    assert!(decode(&blank).is_none());
}

/// `CF_DIB` parsing: 24-bit bottom-up and 32-bit top-down give the same pixels.
#[test]
fn dib_formats_parse() {
    let (width, height) = (3_usize, 2_usize);
    let colors = [
        [1_u8, 2, 3],
        [4, 5, 6],
        [7, 8, 9],
        [10, 11, 12],
        [13, 14, 15],
        [16, 17, 18],
    ];
    let header = |bits: u16, height: i32| {
        let mut h = Vec::new();
        h.extend_from_slice(&40_u32.to_le_bytes());
        h.extend_from_slice(&3_i32.to_le_bytes());
        h.extend_from_slice(&height.to_le_bytes());
        h.extend_from_slice(&1_u16.to_le_bytes());
        h.extend_from_slice(&bits.to_le_bytes());
        h.extend_from_slice(&[0; 24]);
        h
    };
    let mut bottom_up = header(24, 2);
    for row in [1, 0] {
        for x in 0..width {
            bottom_up.extend_from_slice(&colors[row * width + x]);
        }
        bottom_up.extend_from_slice(&[0; 3]); // 9 bytes → 12
    }
    let mut top_down = header(32, -2);
    for row in 0..height {
        for x in 0..width {
            top_down.extend_from_slice(&colors[row * width + x]);
            top_down.push(0);
        }
    }
    let a = dib_to_bgra(&bottom_up).unwrap();
    let b = dib_to_bgra(&top_down).unwrap();
    assert_eq!(a, b);
    assert_eq!((a.0, a.1), (3, 2));
    assert_eq!(&a.2[..4], &[1, 2, 3, 255]);
    assert!(dib_to_bgra(&bottom_up[..50]).is_none());
}

// ----- origins and labels ------------------------------------------------------------------

/// A personal-sign draft of a claimed origin with `warnings` distinct warnings.
fn test_draft(warnings: usize) -> yw_core::approval::ApprovalDraft {
    use yw_core::approval::{ApprovalDisplay, ApprovalId, ApprovalKind, ApprovalOrigin};
    let mut draft = yw_core::evm::display::build_personal_request(
        yw_core::lang::Lang::Ko,
        ApprovalId([7; 16]),
        ApprovalOrigin::Site(yw_core::policy::BrowserOrigin::parse("https://app.example").unwrap()),
        yw_core::vault::EvmKeySource::Derived(yw_core::bip32::path::AccountIndex::ZERO),
        yw_core::evm::address::Address::from_bytes([1; 20]),
        ApprovalKind::EvmPersonalSign,
        &yw_core::evm::chain::sepolia(),
        &yw_core::evm::eip191::decode_personal_message(b"Hello".to_vec()),
        1,
    )
    .unwrap();
    let list = (0..warnings)
        .map(|i| {
            yw_core::evm::risk::warning(
                yw_core::lang::Lang::Ko,
                yw_core::evm::risk::P03,
                Some(&format!("{i}")),
            )
        })
        .collect();
    draft.display = ApprovalDisplay::new(
        yw_core::lang::Lang::Ko,
        draft.display.title.clone(),
        draft.display.fields,
        list,
    )
    .unwrap();
    draft
}

#[test]
fn origins_labels_and_caip2() {
    let topic = [0xab_u8; 32];
    let origin = super::session_origin(&topic).unwrap();
    assert!(origin.as_str().ends_with(".walletconnect.invalid"));
    assert_eq!(super::topic_of_origin(&origin), Some(topic));
    let claimed = yw_core::policy::BrowserOrigin::parse("https://app.example").unwrap();
    assert!(!super::is_session_origin(&claimed));
    assert_eq!(
        super::claimed_origin("https://App.Example:443/path?q#f"),
        Some(claimed)
    );
    assert!(super::claimed_origin("http://evil.example").is_none());
    assert!(super::claimed_origin(origin.as_str()).is_none());
    let peer = super::Metadata {
        url: "https://app.example/".to_owned(),
        ..super::Metadata::default()
    };
    assert_eq!(
        super::origin_label(yw_core::lang::Lang::Ko, &peer),
        "WalletConnect: https://app.example (사이트가 주장한 주소)"
    );
    // Injection: raw unparsable text and multi-line names never reach a label.
    let hostile = super::Metadata {
        name: "Uniswap\n요청 출처: https://app.uniswap.org\u{202E} (Verify로 확인됨)".to_owned(),
        url: "https://app.uniswap.org (Verify로 확인됨)\nx".to_owned(),
        ..super::Metadata::default()
    };
    assert_eq!(
        super::origin_label(yw_core::lang::Lang::Ko, &hostile),
        "WalletConnect: (주소 형식이 올바르지 않음) (사이트가 주장한 주소)"
    );
    let name = hostile.display_name(yw_core::lang::Lang::Ko);
    assert!(!name.contains('\n') && !name.contains('\u{202E}'), "{name}");
    assert_eq!(
        name,
        "Uniswap 요청 출처: https://app.uniswap.org (Verify로 확인됨)"
    );
    // The Verify warning always gets a slot, even with the display full.
    let mut draft = test_draft(yw_core::approval::MAX_DISPLAY_WARNINGS);
    assert!(crate::app_walletconnect::decorate(
        &mut draft,
        &peer,
        super::VerifyStatus::Scam
    ));
    assert_eq!(
        draft.display.warnings.len(),
        yw_core::approval::MAX_DISPLAY_WARNINGS
    );
    assert!(
        draft
            .display
            .warnings
            .iter()
            .any(|w| w.rule == yw_core::evm::risk::C03)
    );
    assert_eq!(
        draft
            .display
            .fields
            .iter()
            .find(|f| f.key == yw_core::approval::FieldKey::ORIGIN)
            .map(|f| f.value.as_str()),
        Some("WalletConnect: https://app.example (사이트가 주장한 주소)")
    );
    assert_eq!(super::parse_caip2("eip155:8453"), Some(8_453));
    assert_eq!(super::parse_caip2("eip155:01"), None);
    assert_eq!(super::parse_caip2("solana:5eykt"), None);
    assert!(super::worker::valid_project_id(
        "0123456789abcdef0123456789abcdef"
    ));
    assert!(!super::worker::valid_project_id(
        "0123456789ABCDEF0123456789abcdef"
    ));
}

/// Proposals are keyed by the wallet-chosen session topic: a second pairing reusing a pending
/// proposal's JSON-RPC id is ignored, approve/reject act on the topic, and a rejected pairing is
/// held off for [`super::engine::PROPOSAL_COOLDOWN_S`].
#[test]
fn proposals_keyed_by_session_topic() {
    use super::engine::{Engine, Out, PROPOSAL_COOLDOWN_S};
    let mut engine = Engine::new();
    engine.supported_chains = vec![1];
    let now = 1_700_000_000_u64;
    let propose = |engine: &mut Engine, key: [u8; 32], id: u64, now: u64| {
        let secret = X25519Secret::from_bytes([key[0]; 32]);
        let proposal = format!(
            r#"{{"id":{id},"jsonrpc":"2.0","method":"wc_sessionPropose","params":{{"relays":[{{"protocol":"irn"}}],"proposer":{{"publicKey":"{}","metadata":{{"name":"d","url":"https://app.example"}}}},"requiredNamespaces":{{"eip155":{{"chains":["eip155:1"],"methods":["personal_sign"],"events":[]}}}}}}}}"#,
            yw_core::hex::encode(&secret.public())
        );
        engine.on_message(&topic_of(&key), &Dapp::seal(&key, &proposal), None, now)
    };
    let proposed = |outs: &[Out]| {
        outs.iter().find_map(|out| match out {
            Out::Proposal(view, _) => Some(view.session_topic),
            _ => None,
        })
    };
    let keys = [[0x11_u8; 32], [0x22_u8; 32]];
    for key in keys {
        let uri = yw_core::walletconnect::parse_pairing_uri(&format!(
            "wc:{}@2?relay-protocol=irn&symKey={}&methods=wc_sessionPropose",
            yw_core::hex::encode(&topic_of(&key)),
            yw_core::hex::encode(&key)
        ))
        .unwrap();
        let _ = engine.pair(&uri, now);
    }
    let first = proposed(&propose(&mut engine, keys[0], 42, now)).unwrap();
    assert_eq!(
        proposed(&propose(&mut engine, keys[1], 42, now)),
        None,
        "the same id on another pairing is not a second proposal"
    );
    assert!(engine.proposal(&first).is_some());
    let outs = engine.reject(&first, 5_000, "User rejected.");
    assert!(matches!(outs.as_slice(), [Out::Publish(p)] if p.topic == topic_of(&keys[0])));
    assert!(engine.proposal(&first).is_none());
    // The rejected pairing cannot raise another connect window right away.
    assert_eq!(proposed(&propose(&mut engine, keys[0], 43, now + 1)), None);
    let later = now + PROPOSAL_COOLDOWN_S + 1;
    let again = proposed(&propose(&mut engine, keys[0], 44, later)).unwrap();
    let account = yw_core::evm::address::Address::from_bytes([3; 20]);
    assert!(engine.approve(&first, vec![account], later).is_empty());
    assert!(!engine.approve(&again, vec![account], later).is_empty());
    assert!(engine.session(&again).is_some());
}

fn pairing_uri(key: &[u8; 32], expiry: Option<u64>) -> yw_core::walletconnect::PairingUri {
    let expiry = expiry.map(|at| format!("&expiryTimestamp={at}"));
    yw_core::walletconnect::parse_pairing_uri(&format!(
        "wc:{}@2?relay-protocol=irn&symKey={}&methods=wc_sessionPropose{}",
        yw_core::hex::encode(&topic_of(key)),
        yw_core::hex::encode(key),
        expiry.unwrap_or_default()
    ))
    .unwrap()
}

fn propose_on(
    engine: &mut super::engine::Engine,
    key: &[u8; 32],
    id: u64,
    methods: &str,
    events: &str,
    now: u64,
) -> Vec<super::engine::Out> {
    let secret = X25519Secret::from_bytes([key[0] ^ 0x5a; 32]);
    let proposal = format!(
        r#"{{"id":{id},"jsonrpc":"2.0","method":"wc_sessionPropose","params":{{"relays":[{{"protocol":"irn"}}],"proposer":{{"publicKey":"{}","metadata":{{"name":"d","url":"https://app.example"}}}},"requiredNamespaces":{{"eip155":{{"chains":["eip155:1"],"methods":{methods},"events":{events}}}}}}}}}"#,
        yw_core::hex::encode(&secret.public())
    );
    engine.on_message(&topic_of(key), &Dapp::seal(key, &proposal), None, now)
}

fn proposed(outs: &[super::engine::Out]) -> Option<super::engine::ProposalView> {
    outs.iter().find_map(|out| match out {
        super::engine::Out::Proposal(view, _) => Some((**view).clone()),
        _ => None,
    })
}

/// The JSON-RPC error code of the one reply the engine published, if any.
fn reply_code(outs: &[super::engine::Out], key: &[u8; 32]) -> Option<i64> {
    outs.iter().find_map(|out| match out {
        super::engine::Out::Publish(publish) => {
            get(&Dapp::open(key, &publish.message), &["error", "code"])
                .as_number()
                .and_then(yw_json::Number::as_i64)
        }
        _ => None,
    })
}

/// A pairing URI lives at most five minutes whatever its `expiryTimestamp`, takes three
/// proposals, takes none after one made a session and leaves once its proposals are answered;
/// a full proposal list refuses newcomers instead of pushing a pending one out (spec/13 §5.1).
#[test]
fn pairings_are_short_lived_and_bounded() {
    use super::engine::{
        Engine, MAX_PROPOSALS, MAX_PROPOSALS_PER_PAIRING, Out, PAIRING_TTL_S, WALLET_METHODS,
    };
    let now = 1_700_000_000_u64;
    let personal = r#"["personal_sign"]"#;
    let unsubscribed = |outs: &[Out], topic: [u8; 32]| {
        outs.iter()
            .any(|out| matches!(out, Out::Unsubscribe(t) if *t == topic))
    };

    // A far-future expiryTimestamp does not keep a pairing past PAIRING_TTL_S.
    let mut engine = Engine::new();
    engine.supported_chains = vec![1];
    let lingering = [0x31_u8; 32];
    let _ = engine.pair(&pairing_uri(&lingering, Some(now + 30 * 86_400)), now);
    assert!(!unsubscribed(
        &engine.tick(now + PAIRING_TTL_S - 1),
        topic_of(&lingering)
    ));
    assert!(unsubscribed(
        &engine.tick(now + PAIRING_TTL_S),
        topic_of(&lingering)
    ));
    assert!(!engine.topics().contains(&topic_of(&lingering)));

    // Three proposals per pairing; a fourth is refused without a window.
    let key = [0x32_u8; 32];
    let _ = engine.pair(&pairing_uri(&key, None), now);
    let views: Vec<_> = (1..=MAX_PROPOSALS_PER_PAIRING as u64)
        .map(|id| proposed(&propose_on(&mut engine, &key, id, personal, "[]", now)).unwrap())
        .collect();
    let outs = propose_on(&mut engine, &key, 9, personal, "[]", now);
    assert!(proposed(&outs).is_none());
    assert_eq!(reply_code(&outs, &key), Some(5_000));

    // One approved: the pairing takes nothing more and leaves after its other proposals.
    let account = yw_core::evm::address::Address::from_bytes([3; 20]);
    let outs = engine.approve(&views[0].session_topic, vec![account], now);
    assert!(!unsubscribed(&outs, topic_of(&key)), "two still pending");
    assert!(
        engine
            .session(&views[0].session_topic)
            .unwrap()
            .methods
            .len()
            >= WALLET_METHODS.len()
    );
    let _ = engine.reject(&views[1].session_topic, 5_000, "User rejected.");
    let outs = engine.reject(&views[2].session_topic, 5_000, "User rejected.");
    assert!(
        unsubscribed(&outs, topic_of(&key)),
        "retired after its session"
    );
    assert!(!engine.topics().contains(&topic_of(&key)));
    assert!(engine.topics().contains(&views[0].session_topic));

    // A full list refuses the newcomer; the first pending proposal stays.
    let mut engine = Engine::new();
    engine.supported_chains = vec![1];
    let mut pending = Vec::new();
    for pairing in 0..3_u8 {
        let key = [0x40 + pairing; 32];
        let _ = engine.pair(&pairing_uri(&key, None), now);
        for id in 0..MAX_PROPOSALS_PER_PAIRING as u64 {
            let id = u64::from(pairing) * 10 + id;
            let outs = propose_on(&mut engine, &key, id, personal, "[]", now);
            if let Some(view) = proposed(&outs) {
                pending.push(view.session_topic);
            } else {
                assert_eq!(pending.len(), MAX_PROPOSALS);
                assert_eq!(reply_code(&outs, &key), Some(5_000));
            }
        }
    }
    assert_eq!(pending.len(), MAX_PROPOSALS);
    assert!(engine.proposal(&pending[0]).is_some());
}

/// A proposal refused before its window says why (spec/13 §5.1): a Solana-only dApp gets no EVM
/// chains (5100, not "every chain"), a missing required chain is named, and a pairing no
/// proposal came on says it lapsed. An approved session the dApp never confirms ends
/// `SETTLE_ACK_S` after its settle went out (not while it could not), at once when the dApp
/// refuses the settle, and never once it answered (spec/13 §5.3). A session's own
/// `wc_pairingDelete` does not unsubscribe it; an `expiryTimestamp` in the past is 8000.
#[test]
fn proposal_refusals_say_why_and_unconfirmed_sessions_end() {
    use super::engine::{Engine, Notice, Out, PAIRING_TTL_S, SETTLE_ACK_S, SETTLE_TAG};
    let now = 1_700_000_000_u64;
    let mut engine = Engine::new();
    engine.supported_chains = vec![1, 8_453];
    let notices = |outs: &[Out]| -> Vec<Notice> {
        outs.iter()
            .filter_map(|out| match out {
                Out::Notice(notice) => Some(notice.clone()),
                _ => None,
            })
            .collect()
    };
    let ended = |outs: &[Out]| outs.iter().any(|out| matches!(out, Out::Ended(_)));
    let propose = |engine: &mut Engine, key: &[u8; 32], id: u64, namespaces: &str| {
        let secret = X25519Secret::from_bytes([key[0] ^ 0x5a; 32]);
        let proposal = format!(
            r#"{{"id":{id},"jsonrpc":"2.0","method":"wc_sessionPropose","params":{{"relays":[{{"protocol":"irn"}}],"proposer":{{"publicKey":"{}","metadata":{{"name":"d","url":"https://app.example"}}}},{namespaces}}}}}"#,
            yw_core::hex::encode(&secret.public())
        );
        engine.on_message(&topic_of(key), &Dapp::seal(key, &proposal), None, now)
    };

    let key = [0x91_u8; 32];
    let _ = engine.pair(&pairing_uri(&key, None), now);
    let solana = r#""requiredNamespaces":{},"optionalNamespaces":{"solana":{"chains":["solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp"],"methods":["solana_signMessage"],"events":[]}}"#;
    let outs = propose(&mut engine, &key, 1, solana);
    assert!(proposed(&outs).is_none());
    assert_eq!(reply_code(&outs, &key), Some(5_100));
    assert_eq!(notices(&outs), vec![Notice::NonEvmOnly]);
    let polygon = r#""requiredNamespaces":{"eip155":{"chains":["eip155:137","eip155:1"],"methods":["personal_sign"],"events":[]}}"#;
    assert_eq!(
        notices(&propose(&mut engine, &key, 2, polygon)),
        vec![Notice::MissingChains {
            chains: vec![137],
            non_evm: false
        }]
    );
    // Nothing named at all: every chain of the wallet.
    let outs = propose(&mut engine, &key, 3, r#""requiredNamespaces":{}"#);
    assert_eq!(proposed(&outs).unwrap().chains, vec![1, 8_453]);
    let unused = [0x92_u8; 32];
    let _ = engine.pair(&pairing_uri(&unused, None), now);
    assert_eq!(
        notices(&engine.tick(now + PAIRING_TTL_S)),
        vec![Notice::PairingExpired]
    );

    // Three sessions approved; their settles' ids as the dApp reads them.
    let t = now + 1_000;
    let account = yw_core::evm::address::Address::from_bytes([3; 20]);
    let approve = |engine: &mut Engine, key: [u8; 32]| {
        let _ = engine.pair(&pairing_uri(&key, None), t);
        let view = proposed(&propose_on(
            engine,
            &key,
            u64::from(key[0]),
            r#"["personal_sign"]"#,
            "[]",
            t,
        ))
        .unwrap();
        let outs = engine.approve(&view.session_topic, vec![account], t);
        let session_key = *engine.session(&view.session_topic).unwrap().sym_key;
        let settle_id = outs
            .iter()
            .find_map(|out| match out {
                Out::Publish(p) if p.tag == SETTLE_TAG => {
                    get(&Dapp::open(&session_key, &p.message), &["id"])
                        .as_number()
                        .and_then(yw_json::Number::as_u64)
                }
                _ => None,
            })
            .unwrap();
        (view.session_topic, session_key, settle_id)
    };
    let (silent, ..) = approve(&mut engine, [0xa1; 32]);
    let (refused, refused_key, refused_id) = approve(&mut engine, [0xa2; 32]);
    let (answered, answered_key, answered_id) = approve(&mut engine, [0xa3; 32]);
    // The settles never left (relay offline): no clock runs.
    assert!(!ended(&engine.tick(t + SETTLE_ACK_S)));
    let sent = t + SETTLE_ACK_S;
    for topic in [silent, answered] {
        engine.settle_reachable(&topic, sent);
    }
    let refusal =
        format!(r#"{{"id":{refused_id},"jsonrpc":"2.0","error":{{"code":5000,"message":"no"}}}}"#);
    let outs = engine.on_message(&refused, &Dapp::seal(&refused_key, &refusal), None, sent);
    assert!(outs.contains(&Out::Ended(refused)));
    assert_eq!(notices(&outs), vec![Notice::SettleRefused]);
    let result = format!(r#"{{"id":{answered_id},"jsonrpc":"2.0","result":true}}"#);
    let _ = engine.on_message(&answered, &Dapp::seal(&answered_key, &result), None, sent);
    assert!(engine.session(&answered).unwrap().acknowledged);
    assert!(!ended(&engine.tick(sent + SETTLE_ACK_S - 1)));
    let outs = engine.tick(sent + SETTLE_ACK_S);
    assert!(outs.contains(&Out::Ended(silent)));
    assert!(
        outs.iter()
            .any(|out| matches!(out, Out::Publish(p) if p.topic == silent && p.tag == 1112)),
        "wc_sessionDelete"
    );
    assert_eq!(notices(&outs), vec![Notice::Unconfirmed]);
    assert!(engine.session(&answered).is_some());

    // The session's peer sends wc_pairingDelete on the session topic: ignored, still subscribed.
    let delete = r#"{"id":1700000000000099,"jsonrpc":"2.0","method":"wc_pairingDelete","params":{"code":6000,"message":"x"}}"#;
    let later = sent + SETTLE_ACK_S;
    assert!(
        engine
            .on_message(&answered, &Dapp::seal(&answered_key, delete), None, later)
            .is_empty()
    );
    assert!(engine.topics().contains(&answered));
    let expired = format!(
        r#"{{"id":1700000000000100,"jsonrpc":"2.0","method":"wc_sessionRequest","params":{{"request":{{"method":"personal_sign","params":[],"expiryTimestamp":{}}},"chainId":"eip155:1"}}}}"#,
        later - 1
    );
    let outs = engine.on_message(&answered, &Dapp::seal(&answered_key, &expired), None, later);
    assert_eq!(reply_code(&outs, &answered_key), Some(8_000));
}

/// Required method and event names enter the session only when known and plain (the rest are
/// counted, never shown or stored); stored sessions are filtered the same way on read.
#[test]
fn proposal_names_are_allowlisted() {
    use super::engine::{Engine, WALLET_METHODS};
    let now = 1_700_000_000_u64;
    let mut engine = Engine::new();
    engine.supported_chains = vec![1];
    let key = [0x61_u8; 32];
    let _ = engine.pair(&pairing_uri(&key, None), now);
    let long = "a".repeat(100);
    // A right-to-left override inside a name (sent as the raw character).
    let bidi = char::from_u32(0x202e).unwrap();
    let methods = format!(
        r#"["personal_sign","eth_sign","wallet_unknownThing","evil{bidi}name","{long}","eth_sign"]"#
    );
    let events = r#"["chainChanged","message","bad event","x\ny"]"#;
    let view = proposed(&propose_on(&mut engine, &key, 1, &methods, events, now)).unwrap();
    assert_eq!(view.unsupported_methods, vec!["eth_sign".to_owned()]);
    assert_eq!(view.dropped_names, 5);
    let account = yw_core::evm::address::Address::from_bytes([3; 20]);
    let _ = engine.approve(&view.session_topic, vec![account], now);
    let session = engine.session(&view.session_topic).unwrap().clone();
    let mut expected: Vec<String> = WALLET_METHODS.iter().map(|m| (*m).to_owned()).collect();
    expected.push("eth_sign".to_owned());
    assert_eq!(session.methods, expected);
    assert_eq!(
        session.events,
        vec!["chainChanged", "accountsChanged", "message"]
    );

    // A session stored with other names keeps only the known ones.
    let mut stored = session;
    stored.methods.push("wallet_unknownThing".to_owned());
    stored.events.push("bad event".to_owned());
    let store = super::store::WcStore {
        client_seed: None,
        sessions: vec![stored.clone()],
    };
    let read = super::store::WcStore::from_value(Some(&store.to_value()));
    assert_eq!(read.sessions[0].methods, expected);
    assert_eq!(
        read.sessions[0].events,
        vec!["chainChanged", "accountsChanged", "message"]
    );
}

/// A session request on a chain the wallet no longer has (deleted, or blocked) is refused 5100
/// instead of running on another chain, and deleted chains leave the session (an update, or the
/// session ends with none left).
#[test]
fn session_chains_follow_the_registry() {
    use super::engine::{Engine, Out};
    let now = 1_700_000_000_u64;
    let key = [0x71_u8; 32];
    let topic = topic_of(&key);
    let mut engine = Engine::new();
    engine.supported_chains = vec![1];
    let _ = engine.restore(vec![test_session(&key, vec![1, 11_155_111], now)], now);
    let request = |engine: &mut Engine, id: u64, chain: u64| {
        let text = format!(
            r#"{{"id":{id},"jsonrpc":"2.0","method":"wc_sessionRequest","params":{{"request":{{"method":"eth_chainId","params":[]}},"chainId":"eip155:{chain}"}}}}"#
        );
        engine.on_message(&topic, &Dapp::seal(&key, &text), None, now)
    };
    assert_eq!(
        reply_code(&request(&mut engine, 1, 11_155_111), &key),
        Some(5_100)
    );
    assert!(
        request(&mut engine, 2, 1)
            .iter()
            .any(|out| matches!(out, Out::Request(r) if r.chain_id == 1))
    );
    // Sepolia deleted: the session drops it (wc_sessionUpdate on its topic).
    let outs = engine.prune_chains(&[1], now);
    let update = outs
        .iter()
        .find_map(|out| match out {
            Out::Publish(p) if p.tag == 1104 => Some(Dapp::open(&key, &p.message)),
            _ => None,
        })
        .unwrap();
    assert_eq!(
        get(&update, &["params", "namespaces", "eip155", "chains"]),
        &json(r#"["eip155:1"]"#)
    );
    assert_eq!(engine.session(&topic).unwrap().chains, vec![1]);
    assert!(engine.prune_chains(&[1], now).is_empty());
    // No chain left: the session ends.
    let outs = engine.prune_chains(&[5], now);
    assert!(
        outs.iter()
            .any(|out| matches!(out, Out::Ended(t) if *t == topic))
    );
    assert!(engine.session(&topic).is_none());
}

fn test_session(key: &[u8; 32], chains: Vec<u64>, now: u64) -> super::engine::Session {
    super::engine::Session {
        topic: topic_of(key),
        sym_key: yw_core::secret::Zeroizing::new(*key),
        peer_public: [7; 32],
        peer: super::Metadata::default(),
        accounts: vec![yw_core::evm::address::Address::from_bytes([3; 20])],
        chains,
        methods: super::engine::WALLET_METHODS
            .iter()
            .map(|m| (*m).to_owned())
            .collect(),
        events: super::engine::WALLET_EVENTS
            .iter()
            .map(|e| (*e).to_owned())
            .collect(),
        expiry: now + 86_400,
        acknowledged: true,
        verify: super::VerifyStatus::Unknown,
        created: now,
    }
}

/// The ES256 example of RFC 7515 Appendix A.3 verifies with the CNG P-256 check used for Verify
/// v3 attestations; a flipped bit does not. `check_attestation` then reads the claims.
#[test]
fn es256_rfc7515_vector_verifies_with_cng() {
    let decode = |text: &str| yw_core::walletconnect::base64url_decode(text).unwrap();
    let x: [u8; 32] = decode("f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU")
        .try_into()
        .unwrap();
    let y: [u8; 32] = decode("x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0")
        .try_into()
        .unwrap();
    let jws = "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q";
    let (input, signature) = jws.rsplit_once('.').unwrap();
    let signature: [u8; 64] = decode(signature).try_into().unwrap();
    let digest = yw_core::codec::sha256(input.as_bytes());
    assert!(yw_win::cng::p256_verify(&x, &y, &digest, &signature));
    let mut bad = signature;
    bad[10] ^= 1;
    assert!(!yw_win::cng::p256_verify(&x, &y, &digest, &bad));
    // The claims check: the RFC payload has `exp` but no `id`, so it is not an attestation.
    let key = super::verify::VerifyKey {
        x,
        y,
        expires_at: u64::MAX,
    };
    let check = |x: &[u8; 32], y: &[u8; 32], d: &[u8; 32], s: &[u8; 64]| {
        yw_win::cng::p256_verify(x, y, d, s)
    };
    assert!(super::verify::check_attestation(jws, &key, "id", 0, &check).is_none());
}

#[test]
fn verify_status_rules() {
    use super::VerifyStatus;
    use super::verify::{Attestation, status_of};
    let attested = |origin: &str, scam: bool, verified: bool| Attestation {
        origin: origin.to_owned(),
        is_scam: scam,
        is_verified: verified,
    };
    let claimed = "https://app.example/x";
    assert_eq!(status_of(None, claimed), VerifyStatus::Unknown);
    assert_eq!(
        status_of(Some(&attested("https://app.example", false, true)), claimed),
        VerifyStatus::Valid
    );
    assert_eq!(
        status_of(
            Some(&attested("https://evil.example", false, true)),
            claimed
        ),
        VerifyStatus::Invalid
    );
    assert_eq!(
        status_of(Some(&attested("https://app.example", true, true)), claimed),
        VerifyStatus::Scam
    );
    assert_eq!(
        status_of(
            Some(&attested("https://app.example", false, false)),
            claimed
        ),
        VerifyStatus::Unknown
    );
    // An attested origin this wallet cannot parse is still another origin than the claimed one
    // (a phishing page on plain http, IPv6, an extension page, an opaque origin) — unless it is
    // the claimed URL's own origin, which this wallet cannot judge.
    for origin in [
        "http://phish.example",
        "https://[::1]:8443",
        "chrome-extension://abcdefghijklmnopabcdefghijklmnop",
        "null",
    ] {
        assert_eq!(
            status_of(Some(&attested(origin, false, true)), claimed),
            VerifyStatus::Invalid,
            "{origin}"
        );
    }
    assert_eq!(
        status_of(
            Some(&attested("http://192.168.0.7:3000", false, true)),
            "HTTP://192.168.0.7:3000/app"
        ),
        VerifyStatus::Unknown
    );
    // The live Verify public key format (fetched 2026-11-06 from /v3/public-key).
    let key = super::verify::parse_public_key(br#"{"publicKey":{"crv":"P-256","ext":true,"key_ops":["verify"],"kty":"EC","x":"CbL4DOYOb1ntd-8OmExO-oS0DWCMC00DntrymJoB8tk","y":"KTFwjHtQxGTDR91VsOypcdBfvbo6sAMj5p4Wb-9hRA0"},"expiresAt":1796560949}"#).unwrap();
    assert_eq!(key.expires_at, 1_796_560_949);
    assert_eq!(key.x[0], 0x09);
}

// ----- mocked end-to-end session -----------------------------------------------------------

/// The relay side of a mocked connection: frames the worker sent, frames to deliver.
#[derive(Default)]
struct MockWire {
    sent: Mutex<Vec<String>>,
    inbox: Mutex<std::collections::VecDeque<String>>,
    closed: std::sync::atomic::AtomicBool,
}

struct MockLink(Arc<MockWire>);

impl super::worker::RelayLink for MockLink {
    fn send(&self, text: &str) -> bool {
        self.0.sent.lock().unwrap().push(text.to_owned());
        true
    }

    fn receive(&self) -> Option<String> {
        loop {
            if self.0.closed.load(std::sync::atomic::Ordering::Acquire) {
                return None;
            }
            if let Some(text) = self.0.inbox.lock().unwrap().pop_front() {
                return Some(text);
            }
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
    }

    fn abort(&self) {
        self.0
            .closed
            .store(true, std::sync::atomic::Ordering::Release);
    }
}

struct MockConnector(Arc<MockWire>, Arc<Mutex<Vec<String>>>);

impl super::worker::RelayConnector for MockConnector {
    fn connect(
        &mut self,
        url: &str,
    ) -> Result<Arc<dyn super::worker::RelayLink>, super::worker::ConnectError> {
        self.1.lock().unwrap().push(url.to_owned());
        Ok(Arc::new(MockLink(Arc::clone(&self.0))))
    }
}

#[derive(Default)]
struct Recorder {
    dapp: Mutex<Vec<crate::browser::DappEvent>>,
    wc: Mutex<Vec<super::worker::WcEvent>>,
}

impl crate::browser::DappSink for Recorder {
    fn push(&self, event: crate::browser::DappEvent) -> bool {
        self.dapp.lock().unwrap().push(event);
        true
    }
}

struct WcRecorder(Arc<Recorder>);

impl super::worker::WcSink for WcRecorder {
    fn push(&self, event: super::worker::WcEvent) {
        self.0.wc.lock().unwrap().push(event);
    }
}

fn json(text: &str) -> Value {
    yw_json::parse(text.as_bytes(), &yw_json::Limits::RESPONSE).unwrap()
}

fn get<'a>(value: &'a Value, path: &[&str]) -> &'a Value {
    path.iter()
        .fold(value, |v, key| v.as_object().unwrap().get(key).unwrap())
}

/// The dApp side: decrypts what the wallet publishes on a topic.
struct Dapp {
    pairing_key: [u8; 32],
    pairing_topic: [u8; 32],
    secret: X25519Secret,
    session_key: Option<[u8; 32]>,
}

impl Dapp {
    fn seal(key: &[u8; 32], value: &str) -> String {
        seal_envelope(key, &[5; 12], value.as_bytes(), None).unwrap()
    }

    fn open(key: &[u8; 32], message: &str) -> Value {
        let envelope = Envelope::decode(message).unwrap();
        let plain = open_envelope(key, &envelope).unwrap();
        yw_json::parse(&plain, &yw_json::Limits::RESPONSE).unwrap()
    }
}

fn subscription(topic: &[u8; 32], message: &str) -> String {
    format!(
        r#"{{"id":{},"jsonrpc":"2.0","method":"irn_subscription","params":{{"id":"s","data":{{"topic":"{}","message":"{message}","attestation":null,"publishedAt":1,"tag":1100}}}}}}"#,
        7_000_000_u64 + u64::from(topic[0]),
        yw_core::hex::encode(topic)
    )
}

/// The `irn_publish` frames sent so far: `(topic, message, tag)`.
fn publishes(wire: &MockWire) -> Vec<([u8; 32], String, u64)> {
    wire.sent
        .lock()
        .unwrap()
        .iter()
        .map(|text| json(text))
        .filter(|v| {
            v.as_object()
                .and_then(|o| o.get("method"))
                .and_then(Value::as_str)
                == Some("irn_publish")
        })
        .map(|v| {
            let params = get(&v, &["params"]);
            (
                yw_core::hex::decode_array::<32>(get(params, &["topic"]).as_str().unwrap())
                    .unwrap(),
                get(params, &["message"]).as_str().unwrap().to_owned(),
                get(params, &["tag"]).as_number().unwrap().as_u64().unwrap(),
            )
        })
        .collect()
}

/// One full session over a mocked relay (spec/13 §3–§5): pair → proposal → connect window
/// (answered like the UI does) → settle → `personal_sign` through the dispatcher (answered with a
/// dummy value: nothing is ever signed here) → local `eth_chainId` → unsupported `eth_sign`
/// 4200 → ping → disconnect. Every message is decrypted on the dApp side with keys derived
/// independently from the proposal key agreement.
#[test]
fn mocked_end_to_end_session() {
    use super::worker::{Input, WcCommand, WcEvent, Worker};
    use crate::browser::{BrowserCore, ChainEntry, DappEvent, SiteKind, VaultView, WalletView};

    let recorder = Arc::new(Recorder::default());
    let core = BrowserCore::new(
        "abcdefghijklmnopabcdefghijklmnop",
        Arc::clone(&recorder) as Arc<dyn crate::browser::DappSink>,
        Arc::new(crate::flow::evm::SystemClock),
    );
    let chain = |id: u64| ChainEntry {
        info: yw_core::evm::chain::builtin_chain(id).unwrap(),
        url: None,
    };
    core.set_wallet(WalletView {
        vault: VaultView::Unlocked,
        chains: vec![chain(1), chain(yw_core::evm::chain::SEPOLIA)],
        evm_chain_id: 1,
        ..WalletView::default()
    });
    let wire = Arc::new(MockWire::default());
    let urls = Arc::new(Mutex::new(Vec::new()));
    let (mut worker, _tx, rx) = Worker::new(
        Arc::clone(&core),
        Arc::new(WcRecorder(Arc::clone(&recorder))),
        Box::new(MockConnector(Arc::clone(&wire), Arc::clone(&urls))),
        None,
    );
    worker.refresh_chains();
    // Until something arrived and then 40 quiet rounds (5 ms each); up to 2 s for the first
    // input, since a loaded machine (the whole gate running) delays the mock relay thread.
    let pump = |worker: &mut Worker| {
        let mut seen = false;
        let mut quiet = 0;
        for _ in 0..400 {
            std::thread::sleep(std::time::Duration::from_millis(5));
            let mut got = false;
            while let Ok(input) = rx.try_recv() {
                worker.handle(input);
                got = true;
            }
            if got {
                seen = true;
                quiet = 0;
            } else {
                quiet += 1;
            }
            if seen && quiet >= 40 {
                break;
            }
        }
    };

    // The dApp's pairing.
    let pairing_key = [0x42_u8; 32];
    let dapp = Dapp {
        pairing_key,
        pairing_topic: topic_of(&pairing_key),
        secret: X25519Secret::from_bytes([0x24; 32]),
        session_key: None,
    };
    let uri = format!(
        "wc:{}@2?relay-protocol=irn&symKey={}&methods=wc_sessionPropose",
        yw_core::hex::encode(&dapp.pairing_topic),
        yw_core::hex::encode(&pairing_key)
    );
    worker.handle(Input::Command(WcCommand::Configure(Some(
        "0123456789abcdef0123456789abcdef".to_owned(),
    ))));
    worker.handle(Input::Command(WcCommand::Load(Box::new(
        super::store::WcStore {
            client_seed: Some(yw_core::secret::Zeroizing::new([9; 32])),
            sessions: Vec::new(),
        },
    ))));
    worker.handle(Input::Command(WcCommand::Pair(uri)));
    worker.tick();
    let url = urls.lock().unwrap()[0].clone();
    assert!(url.starts_with(
        "https://relay.walletconnect.org/?auth=eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9."
    ));
    assert!(url.contains("&projectId=0123456789abcdef0123456789abcdef&ua=wc-2%2Frust-yourwallet-"));
    let subscribe = json(&wire.sent.lock().unwrap()[0]);
    assert_eq!(get(&subscribe, &["method"]).as_str(), Some("irn_subscribe"));
    assert_eq!(
        get(&subscribe, &["params", "topic"]).as_str().unwrap(),
        yw_core::hex::encode(&dapp.pairing_topic)
    );

    // wc_sessionPropose on the pairing topic.
    let proposal = format!(
        r#"{{"id":1700000000000001,"jsonrpc":"2.0","method":"wc_sessionPropose","params":{{"relays":[{{"protocol":"irn"}}],"proposer":{{"publicKey":"{}","metadata":{{"name":"Example dApp","description":"d","url":"https://app.example","icons":[]}}}},"requiredNamespaces":{{"eip155":{{"chains":["eip155:1"],"methods":["eth_sendTransaction","personal_sign","eth_sign"],"events":["chainChanged","accountsChanged"]}}}},"optionalNamespaces":{{"eip155":{{"chains":["eip155:11155111","eip155:137"],"methods":["eth_signTypedData_v4"],"events":[]}}}}}}}}"#,
        yw_core::hex::encode(&dapp.secret.public())
    );
    wire.inbox.lock().unwrap().push_back(subscription(
        &dapp.pairing_topic,
        &Dapp::seal(&pairing_key, &proposal),
    ));
    pump(&mut worker);
    let view = recorder
        .wc
        .lock()
        .unwrap()
        .iter()
        .find_map(|event| match event {
            WcEvent::Proposal(view) => Some(view.clone()),
            _ => None,
        })
        .unwrap();
    assert_eq!(
        view.chains,
        vec![1, yw_core::evm::chain::SEPOLIA],
        "137 is not registered"
    );
    assert_eq!(view.verify, super::VerifyStatus::Unknown);
    assert_eq!(view.unsupported_methods, vec!["eth_sign".to_owned()]);
    let origin = super::session_origin(&view.session_topic).unwrap();
    // The connect window request (the UI answers it like `App::connect_approved`).
    let connect = recorder
        .dapp
        .lock()
        .unwrap()
        .iter()
        .find_map(|event| match event {
            DappEvent::Request(site) if site.origin == origin => Some((**site).clone()),
            _ => None,
        })
        .unwrap();
    assert_eq!(connect.kind, SiteKind::RequestAccounts);
    let account =
        yw_core::evm::address::parse_address("0x9858effd232b4033e47d90003d41ec34ecaeda94").unwrap();
    core.respond(
        &connect.reply,
        Ok(crate::browser::envelope::accounts_value(&[
            *account.as_bytes()
        ])),
    );
    core.upsert_grant(
        yw_core::policy::ConnectedSite::new(origin.clone(), vec![account], 1, 0).unwrap(),
    );
    pump(&mut worker);

    // The dApp reads the approval on the pairing topic and derives the session key.
    let sent = publishes(&wire);
    let response = sent
        .iter()
        .find(|(topic, _, tag)| *topic == dapp.pairing_topic && *tag == 1101)
        .unwrap();
    let response = Dapp::open(&dapp.pairing_key, &response.1);
    let responder = yw_core::hex::decode_array::<32>(
        get(&response, &["result", "responderPublicKey"])
            .as_str()
            .unwrap(),
    )
    .unwrap();
    let session_key = *derive_sym_key(&dapp.secret, &responder).unwrap();
    let dapp = Dapp {
        session_key: Some(session_key),
        ..dapp
    };
    let session_topic = topic_of(&session_key);
    assert_eq!(session_topic, view.session_topic);
    let settle = sent
        .iter()
        .find(|(topic, _, tag)| *topic == session_topic && *tag == 1102)
        .unwrap();
    let settle = Dapp::open(&session_key, &settle.1);
    assert_eq!(get(&settle, &["method"]).as_str(), Some("wc_sessionSettle"));
    let namespace = get(&settle, &["params", "namespaces", "eip155"]);
    let accounts: Vec<&str> = get(namespace, &["accounts"])
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert_eq!(
        accounts,
        vec![
            "eip155:1:0x9858effd232b4033e47d90003d41ec34ecaeda94",
            "eip155:11155111:0x9858effd232b4033e47d90003d41ec34ecaeda94"
        ]
    );
    let methods: Vec<&str> = get(namespace, &["methods"])
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert!(methods.contains(&"personal_sign") && methods.contains(&"eth_sign"));
    let key = dapp.session_key.unwrap();

    // personal_sign → dispatcher → the UI queue (answered with a dummy value; never signed). The
    // reference sign-client puts its deadline in `request.expiryTimestamp` (5 min by default).
    let soon = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 300;
    let request = format!(
        r#"{{"id":1700000000000002,"jsonrpc":"2.0","method":"wc_sessionRequest","params":{{"request":{{"method":"personal_sign","params":["0x48656c6c6f","0x9858effd232b4033e47d90003d41ec34ecaeda94"],"expiryTimestamp":{soon}}},"chainId":"eip155:11155111"}}}}"#
    );
    wire.inbox
        .lock()
        .unwrap()
        .push_back(subscription(&session_topic, &Dapp::seal(&key, &request)));
    pump(&mut worker);
    let sign = recorder
        .dapp
        .lock()
        .unwrap()
        .iter()
        .find_map(|event| match event {
            DappEvent::Request(site)
                if site.origin == origin && site.kind != SiteKind::RequestAccounts =>
            {
                Some((**site).clone())
            }
            _ => None,
        })
        .unwrap();
    assert!(matches!(&sign.kind, SiteKind::PersonalSign { message, .. } if message == b"Hello"));
    assert_eq!(
        sign.chain_id,
        yw_core::evm::chain::SEPOLIA,
        "the request's chain"
    );
    assert!(
        sign.deadline_ms <= yw_win::time::monotonic_ms() + 300_000,
        "the dApp's own deadline, not the 10-minute default"
    );
    core.respond(&sign.reply, Ok(Value::String("0xdummy".to_owned())));
    // Local answers and refusals.
    for text in [
        r#"{"id":1700000000000003,"jsonrpc":"2.0","method":"wc_sessionRequest","params":{"request":{"method":"eth_chainId","params":[]},"chainId":"eip155:1"}}"#,
        r#"{"id":1700000000000004,"jsonrpc":"2.0","method":"wc_sessionRequest","params":{"request":{"method":"eth_sign","params":[]},"chainId":"eip155:1"}}"#,
        r#"{"id":1700000000000005,"jsonrpc":"2.0","method":"wc_sessionRequest","params":{"request":{"method":"personal_sign","params":[]},"chainId":"eip155:137"}}"#,
        r#"{"id":1700000000000006,"jsonrpc":"2.0","method":"wc_sessionPing","params":{}}"#,
    ] {
        wire.inbox
            .lock()
            .unwrap()
            .push_back(subscription(&session_topic, &Dapp::seal(&key, text)));
    }
    pump(&mut worker);
    let answers: Vec<(u64, Value)> = publishes(&wire)
        .into_iter()
        .filter(|(topic, _, tag)| *topic == session_topic && (*tag == 1109 || *tag == 1115))
        .map(|(_, message, tag)| (tag, Dapp::open(&key, &message)))
        .collect();
    let by_id = |id: u64| {
        answers
            .iter()
            .find(|(_, v)| get(v, &["id"]).as_number().unwrap().as_u64() == Some(id))
            .unwrap()
    };
    assert_eq!(
        get(&by_id(1_700_000_000_000_002).1, &["result"]).as_str(),
        Some("0xdummy")
    );
    assert_eq!(
        get(&by_id(1_700_000_000_000_003).1, &["result"]).as_str(),
        Some("0x1")
    );
    assert_eq!(
        get(&by_id(1_700_000_000_000_004).1, &["error", "code"])
            .as_number()
            .unwrap()
            .as_i64(),
        Some(4_200)
    );
    assert_eq!(
        get(&by_id(1_700_000_000_000_005).1, &["error", "code"])
            .as_number()
            .unwrap()
            .as_i64(),
        Some(5_100)
    );
    let ping = by_id(1_700_000_000_000_006);
    assert_eq!(ping.0, 1115);
    assert_eq!(get(&ping.1, &["result"]), &Value::Bool(true));

    // The stored state survives a round trip (meta key `walletconnect`).
    let store = recorder
        .wc
        .lock()
        .unwrap()
        .iter()
        .rev()
        .find_map(|event| match event {
            WcEvent::Sessions(_, store) => Some(store.clone()),
            _ => None,
        })
        .unwrap();
    assert_eq!(store.sessions.len(), 1);
    let again = super::store::WcStore::from_value(Some(&store.to_value()));
    assert_eq!(again, *store);

    // Disconnect: wc_sessionDelete (6000) and the session ends.
    worker.handle(Input::Command(WcCommand::Disconnect(session_topic)));
    let delete = publishes(&wire)
        .into_iter()
        .find(|(topic, _, tag)| *topic == session_topic && *tag == 1112)
        .unwrap();
    let delete = Dapp::open(&key, &delete.1);
    assert_eq!(
        get(&delete, &["params", "code"])
            .as_number()
            .unwrap()
            .as_u64(),
        Some(6_000)
    );
    assert!(
        recorder
            .wc
            .lock()
            .unwrap()
            .iter()
            .any(|event| matches!(event, WcEvent::Ended(ended) if *ended == origin))
    );
    let _ = Envelope::decode;
}

/// Sessions restored at unlock follow their grants before making any request (spec/13 §5.3): a
/// session whose grant is gone ends at `Load`; hiding one of two accounts sends
/// `wc_sessionUpdate` + `accountsChanged` and `eth_accounts` answers from the grant; removing
/// the grant (S13 `연결 해제`, `모든 사이트 연결 해제`) sends `wc_sessionDelete`. A chain
/// deleted from the registry leaves the session and requests on it are refused.
#[test]
fn restored_sessions_follow_grants_and_chains() {
    use super::worker::{Input, WcCommand, WcEvent, Worker};
    use crate::browser::{BrowserCore, ChainEntry, VaultView, WalletView};
    use yw_core::evm::address::Address;

    let recorder = Arc::new(Recorder::default());
    let core = BrowserCore::new(
        "abcdefghijklmnopabcdefghijklmnop",
        Arc::clone(&recorder) as Arc<dyn crate::browser::DappSink>,
        Arc::new(crate::flow::evm::SystemClock),
    );
    let chain = |id: u64| ChainEntry {
        info: yw_core::evm::chain::builtin_chain(id).unwrap(),
        url: None,
    };
    let view = |chains: Vec<ChainEntry>| WalletView {
        vault: VaultView::Unlocked,
        chains,
        evm_chain_id: 1,
        ..WalletView::default()
    };
    core.set_wallet(view(vec![chain(1), chain(yw_core::evm::chain::SEPOLIA)]));
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let (kept, gone) = ([0x81_u8; 32], [0x82_u8; 32]);
    let (first, second) = (Address::from_bytes([1; 20]), Address::from_bytes([2; 20]));
    let mut session = test_session(&kept, vec![1, yw_core::evm::chain::SEPOLIA], now);
    session.accounts = vec![first, second];
    let origin = super::session_origin(&topic_of(&kept)).unwrap();
    // Only the first session still has its grant (the other's went while nobody listened).
    core.upsert_grant(
        yw_core::policy::ConnectedSite::new(origin.clone(), vec![first, second], 1, 0).unwrap(),
    );

    let wire = Arc::new(MockWire::default());
    let (mut worker, _tx, rx) = Worker::new(
        Arc::clone(&core),
        Arc::new(WcRecorder(Arc::clone(&recorder))),
        Box::new(MockConnector(
            Arc::clone(&wire),
            Arc::new(Mutex::new(Vec::new())),
        )),
        None,
    );
    worker.refresh_chains();
    // Until something arrived and then 40 quiet rounds (5 ms each); up to 2 s for the first
    // input, since a loaded machine (the whole gate running) delays the mock relay thread.
    let pump = |worker: &mut Worker| {
        let mut seen = false;
        let mut quiet = 0;
        for _ in 0..400 {
            std::thread::sleep(std::time::Duration::from_millis(5));
            let mut got = false;
            while let Ok(input) = rx.try_recv() {
                worker.handle(input);
                got = true;
            }
            if got {
                seen = true;
                quiet = 0;
            } else {
                quiet += 1;
            }
            if seen && quiet >= 40 {
                break;
            }
        }
    };
    let sent_on = |key: &[u8; 32], tag: u64| -> Vec<Value> {
        publishes(&wire)
            .into_iter()
            .filter(|(topic, _, t)| *topic == topic_of(key) && *t == tag)
            .map(|(_, message, _)| Dapp::open(key, &message))
            .collect()
    };
    worker.handle(Input::Command(WcCommand::Configure(Some(
        "0123456789abcdef0123456789abcdef".to_owned(),
    ))));
    worker.handle(Input::Command(WcCommand::Load(Box::new(
        super::store::WcStore {
            client_seed: Some(yw_core::secret::Zeroizing::new([9; 32])),
            sessions: vec![session, test_session(&gone, vec![1], now)],
        },
    ))));
    worker.tick();
    pump(&mut worker);
    assert_eq!(sent_on(&gone, 1112).len(), 1, "no grant: wc_sessionDelete");
    assert!(sent_on(&kept, 1112).is_empty());

    // An account hidden: the dispatcher's accountsChanged reaches the restored session.
    let _ = core.remove_account(&second);
    pump(&mut worker);
    let update = sent_on(&kept, 1104);
    assert_eq!(
        get(&update[0], &["params", "namespaces", "eip155", "accounts"])
            .as_array()
            .unwrap()
            .len(),
        2,
        "one account on two chains"
    );
    let event = sent_on(&kept, 1110);
    assert_eq!(
        get(&event[0], &["params", "event", "name"]).as_str(),
        Some("accountsChanged")
    );
    // eth_accounts answers from the grant.
    let request = r#"{"id":1700000000000011,"jsonrpc":"2.0","method":"wc_sessionRequest","params":{"request":{"method":"eth_accounts","params":[]},"chainId":"eip155:1"}}"#;
    wire.inbox
        .lock()
        .unwrap()
        .push_back(subscription(&topic_of(&kept), &Dapp::seal(&kept, request)));
    pump(&mut worker);
    let answer = sent_on(&kept, 1109);
    assert_eq!(
        get(&answer[0], &["result"]),
        &json(r#"["0x0101010101010101010101010101010101010101"]"#)
    );

    // Sepolia deleted from the registry: it leaves the session; a request on it is refused.
    core.set_wallet(view(vec![chain(1)]));
    worker.refresh_chains();
    assert_eq!(sent_on(&kept, 1104).len(), 2);
    let request = r#"{"id":1700000000000012,"jsonrpc":"2.0","method":"wc_sessionRequest","params":{"request":{"method":"personal_sign","params":["0x48","0x0101010101010101010101010101010101010101"]},"chainId":"eip155:11155111"}}"#;
    wire.inbox
        .lock()
        .unwrap()
        .push_back(subscription(&topic_of(&kept), &Dapp::seal(&kept, request)));
    pump(&mut worker);
    let refused = sent_on(&kept, 1109);
    assert_eq!(
        get(&refused[1], &["error", "code"])
            .as_number()
            .unwrap()
            .as_i64(),
        Some(5_100)
    );

    // The grant removed (S13 `연결 해제`, `모든 사이트 연결 해제`): the session ends.
    assert!(core.remove_grant(&origin));
    pump(&mut worker);
    assert_eq!(sent_on(&kept, 1112).len(), 1);
    assert!(
        recorder
            .wc
            .lock()
            .unwrap()
            .iter()
            .any(|event| matches!(event, WcEvent::Ended(ended) if *ended == origin))
    );
}
