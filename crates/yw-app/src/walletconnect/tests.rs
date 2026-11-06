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
                        let near_box = boxes.iter().any(|(bx, by)| {
                            px.abs_diff(*bx) < 18 && py.abs_diff(*by) < 10
                        });
                        if near_box { 40.0 } else { f64::from(scene.background) }
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
        assert_eq!(found.as_deref(), Some(text), "version {}", qr.version().value());
    }
}

/// Screenshot-like samples: rotated and non-integer scaled codes inside a larger image with UI
/// boxes, a 90° turn, a light-on-dark code, and a high-version code.
#[test]
fn qr_decodes_rotated_scaled_and_inverted_screenshots() {
    let qr = QrCode::encode_text(URI, QrCodeEcc::Medium).unwrap();
    for (module, angle) in [(3.3, 17.0), (2.6, -8.0), (5.1, 90.0), (3.0, 180.0), (4.4, 33.0)] {
        let found = decode_scene(&qr, &scene(900, 700, module, angle));
        assert_eq!(found.as_deref(), Some(URI), "module {module}, angle {angle}");
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
    let colors = [[1_u8, 2, 3], [4, 5, 6], [7, 8, 9], [10, 11, 12], [13, 14, 15], [16, 17, 18]];
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
        super::origin_label(&peer, super::VerifyStatus::Unknown),
        "WalletConnect: https://app.example (사이트가 주장한 주소 — 확인되지 않음)"
    );
    assert_eq!(super::parse_caip2("eip155:8453"), Some(8_453));
    assert_eq!(super::parse_caip2("eip155:01"), None);
    assert_eq!(super::parse_caip2("solana:5eykt"), None);
    assert!(super::worker::valid_project_id("0123456789abcdef0123456789abcdef"));
    assert!(!super::worker::valid_project_id("0123456789ABCDEF0123456789abcdef"));
}

/// The ES256 example of RFC 7515 Appendix A.3 verifies with the CNG P-256 check used for Verify
/// v3 attestations; a flipped bit does not. `check_attestation` then reads the claims.
#[test]
fn es256_rfc7515_vector_verifies_with_cng() {
    let decode = |text: &str| yw_core::walletconnect::base64url_decode(text).unwrap();
    let x: [u8; 32] = decode("f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU").try_into().unwrap();
    let y: [u8; 32] = decode("x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0").try_into().unwrap();
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
        status_of(Some(&attested("https://evil.example", false, true)), claimed),
        VerifyStatus::Invalid
    );
    assert_eq!(
        status_of(Some(&attested("https://app.example", true, true)), claimed),
        VerifyStatus::Scam
    );
    assert_eq!(
        status_of(Some(&attested("https://app.example", false, false)), claimed),
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
        self.0.closed.store(true, std::sync::atomic::Ordering::Release);
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
                yw_core::hex::decode_array::<32>(get(params, &["topic"]).as_str().unwrap()).unwrap(),
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
    use crate::browser::{BrowserCore, ChainEntry, DappEvent, SiteKind, VaultView, WalletView};
    use super::worker::{Input, WcCommand, WcEvent, Worker};

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
    let pump = |worker: &mut Worker| {
        for _ in 0..50 {
            std::thread::sleep(std::time::Duration::from_millis(5));
            while let Ok(input) = rx.try_recv() {
                worker.handle(input);
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
    worker.handle(Input::Command(WcCommand::Load(Box::new(super::store::WcStore {
        client_seed: Some(yw_core::secret::Zeroizing::new([9; 32])),
        sessions: Vec::new(),
    }))));
    worker.handle(Input::Command(WcCommand::Pair(uri)));
    worker.tick();
    let url = urls.lock().unwrap()[0].clone();
    assert!(url.starts_with("https://relay.walletconnect.org/?auth=eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9."));
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
    assert_eq!(view.chains, vec![1, yw_core::evm::chain::SEPOLIA], "137 is not registered");
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
    let account = yw_core::evm::address::parse_address("0x9858effd232b4033e47d90003d41ec34ecaeda94").unwrap();
    core.respond(
        &connect.reply,
        Ok(crate::browser::envelope::accounts_value(&[*account.as_bytes()])),
    );
    core.upsert_grant(yw_core::policy::ConnectedSite::new(origin.clone(), vec![account], 1, 0).unwrap());
    pump(&mut worker);

    // The dApp reads the approval on the pairing topic and derives the session key.
    let sent = publishes(&wire);
    let response = sent.iter().find(|(topic, _, tag)| *topic == dapp.pairing_topic && *tag == 1101).unwrap();
    let response = Dapp::open(&dapp.pairing_key, &response.1);
    let responder = yw_core::hex::decode_array::<32>(
        get(&response, &["result", "responderPublicKey"]).as_str().unwrap(),
    )
    .unwrap();
    let session_key = *derive_sym_key(&dapp.secret, &responder).unwrap();
    let dapp = Dapp {
        session_key: Some(session_key),
        ..dapp
    };
    let session_topic = topic_of(&session_key);
    assert_eq!(session_topic, view.session_topic);
    let settle = sent.iter().find(|(topic, _, tag)| *topic == session_topic && *tag == 1102).unwrap();
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
    let methods: Vec<&str> = get(namespace, &["methods"]).as_array().unwrap().iter().map(|v| v.as_str().unwrap()).collect();
    assert!(methods.contains(&"personal_sign") && methods.contains(&"eth_sign"));
    let key = dapp.session_key.unwrap();

    // personal_sign → dispatcher → the UI queue (answered with a dummy value; never signed).
    let request = r#"{"id":1700000000000002,"jsonrpc":"2.0","method":"wc_sessionRequest","params":{"request":{"method":"personal_sign","params":["0x48656c6c6f","0x9858effd232b4033e47d90003d41ec34ecaeda94"]},"chainId":"eip155:11155111"}}"#;
    wire.inbox.lock().unwrap().push_back(subscription(&session_topic, &Dapp::seal(&key, request)));
    pump(&mut worker);
    let sign = recorder
        .dapp
        .lock()
        .unwrap()
        .iter()
        .find_map(|event| match event {
            DappEvent::Request(site) if site.origin == origin && site.kind != SiteKind::RequestAccounts => {
                Some((**site).clone())
            }
            _ => None,
        })
        .unwrap();
    assert!(matches!(&sign.kind, SiteKind::PersonalSign { message, .. } if message == b"Hello"));
    assert_eq!(sign.chain_id, yw_core::evm::chain::SEPOLIA, "the request's chain");
    core.respond(&sign.reply, Ok(Value::String("0xdummy".to_owned())));
    // Local answers and refusals.
    for text in [
        r#"{"id":1700000000000003,"jsonrpc":"2.0","method":"wc_sessionRequest","params":{"request":{"method":"eth_chainId","params":[]},"chainId":"eip155:1"}}"#,
        r#"{"id":1700000000000004,"jsonrpc":"2.0","method":"wc_sessionRequest","params":{"request":{"method":"eth_sign","params":[]},"chainId":"eip155:1"}}"#,
        r#"{"id":1700000000000005,"jsonrpc":"2.0","method":"wc_sessionRequest","params":{"request":{"method":"personal_sign","params":[]},"chainId":"eip155:137"}}"#,
        r#"{"id":1700000000000006,"jsonrpc":"2.0","method":"wc_sessionPing","params":{}}"#,
    ] {
        wire.inbox.lock().unwrap().push_back(subscription(&session_topic, &Dapp::seal(&key, text)));
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
    assert_eq!(get(&by_id(1_700_000_000_000_002).1, &["result"]).as_str(), Some("0xdummy"));
    assert_eq!(get(&by_id(1_700_000_000_000_003).1, &["result"]).as_str(), Some("0x1"));
    assert_eq!(
        get(&by_id(1_700_000_000_000_004).1, &["error", "code"]).as_number().unwrap().as_i64(),
        Some(4_200)
    );
    assert_eq!(
        get(&by_id(1_700_000_000_000_005).1, &["error", "code"]).as_number().unwrap().as_i64(),
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
    assert_eq!(get(&delete, &["params", "code"]).as_number().unwrap().as_u64(), Some(6_000));
    assert!(recorder
        .wc
        .lock()
        .unwrap()
        .iter()
        .any(|event| matches!(event, WcEvent::Ended(ended) if *ended == origin)));
    let _ = Envelope::decode;
}
