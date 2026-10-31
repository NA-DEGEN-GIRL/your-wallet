//! Solana message signing: RFC 8032 vectors through the message signer, transaction and
//! off-chain detection, the SIWS text layout of `createSignInMessageText` with its parser and
//! checks, and the approval display levels.
#![expect(
    clippy::indexing_slicing,
    reason = "test fixtures index buffers of known length"
)]

use super::{
    OffchainMessage, SiwsContext, SiwsMessage, SolMessageError, SolMessageRequest,
    build_sol_message_request, chain_matches, check_siws, domain_matches, looks_like_transaction,
    looks_like_versioned_message, parse_offchain, sign_with_seed, signable,
};
use crate::approval::{ApprovalId, ApprovalKind, FieldKey, RiskLevel};
use crate::bip32::path::AccountIndex;
use crate::evm::risk::{M01, M02, M04, M05, W01, W02, W03, W04, W05, W06, W07, W08};
use crate::policy::BrowserOrigin;
use crate::slip10::SolKeySource;
use crate::sol::SolCluster;

const NOW_MS: u64 = 1_793_404_800_000; // 2026-10-31T00:00:00Z

fn decode32(hex: &str) -> [u8; 32] {
    crate::hex::decode_array::<32>(hex).unwrap()
}

#[test]
fn rfc8032_vectors() {
    for (secret, public, message, signature) in [
        (
            "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
            "",
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
        ),
        (
            "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
            "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
            "72",
            "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
        ),
    ] {
        let message = crate::hex::decode(message).unwrap();
        let signed = sign_with_seed(&decode32(secret), &decode32(public), &message).unwrap();
        assert_eq!(crate::hex::encode(&signed), signature);
    }
    let wrong = decode32("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c");
    assert_eq!(
        sign_with_seed(
            &decode32("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"),
            &wrong,
            b"x"
        ),
        Err(SolMessageError::KeyMismatch)
    );
}

fn legacy_message() -> Vec<u8> {
    let mut out = vec![1, 0, 1, 2];
    out.extend_from_slice(&[0x11; 32]);
    out.extend_from_slice(&[0x22; 32]);
    out.extend_from_slice(&[0x33; 32]);
    out.extend_from_slice(&[1, 1, 1, 0, 4, 2, 0, 0, 0]);
    out
}

#[test]
fn transactions_are_detected() {
    let legacy = legacy_message();
    assert!(looks_like_transaction(&legacy));
    let mut v0 = vec![0x80];
    v0.extend_from_slice(&legacy);
    v0.push(0);
    assert!(looks_like_transaction(&v0));
    let mut signed = vec![1];
    signed.extend_from_slice(&[0x44; 64]);
    signed.extend_from_slice(&legacy);
    assert!(looks_like_transaction(&signed));
    let mut bad_index = legacy.clone();
    let index = bad_index.len() - 7;
    bad_index[index] = 9;
    assert!(!looks_like_transaction(&bad_index));
    // A parsable message prefix with trailing bytes is still a transaction (M01).
    let mut trailing = legacy.clone();
    trailing.push(0);
    assert!(looks_like_transaction(&trailing));
    assert!(!signable(&trailing));
    let mut signed_trailing = signed.clone();
    signed_trailing.extend_from_slice(b"tail");
    assert!(looks_like_transaction(&signed_trailing));
    let mut v0_trailing = v0.clone();
    v0_trailing.extend_from_slice(&[7; 40]);
    assert!(looks_like_transaction(&v0_trailing));
    assert!(!looks_like_transaction(b"Sign in to example.com"));
    assert!(!looks_like_transaction(b""));
    assert!(!signable(&signed));
    assert!(signable(b"hello"));
    assert!(!signable(&vec![b'a'; 65_537]));
}

#[test]
fn future_message_versions_are_blocked() {
    let legacy = legacy_message();
    // Every version prefix 0x81..=0xfe (and a broken v0 = 0x80) is blocked when not UTF-8 text.
    for prefix in 0x80_u8..=0xfe {
        let mut future = vec![prefix];
        future.extend_from_slice(&legacy);
        future.extend_from_slice(&[0xfe, 0x00]);
        assert!(looks_like_versioned_message(&future), "{prefix:#04x}");
        assert!(looks_like_transaction(&future), "{prefix:#04x}");
        assert!(!signable(&future), "{prefix:#04x}");
        let draft = build_sol_message_request(&request(future, false), NOW_MS).unwrap();
        assert_eq!(draft.display.risk, RiskLevel::Blocked, "{prefix:#04x}");
        assert!(rules(&draft.display.warnings).contains(&M01));
    }
    for short in [&[0x81_u8][..], &[0xc0], &[0xfe, 0x01, 0x02]] {
        assert!(looks_like_transaction(short));
        assert!(!signable(short));
    }
    // Valid UTF-8 text starting with a multibyte character stays signable.
    let korean = "가나다 소유 증명".as_bytes();
    assert!(korean[0] >= 0x80);
    assert!(!looks_like_versioned_message(korean));
    assert!(signable(korean));
    let plain = build_sol_message_request(&request(korean.to_vec(), false), NOW_MS).unwrap();
    assert_eq!(plain.display.risk, RiskLevel::Info);
    // The same lead byte followed by non-UTF-8 bytes is blocked.
    let mut broken = korean.to_vec();
    broken.push(0xff);
    assert!(!signable(&broken));
    // 0xff is the off-chain domain's first byte, not a version prefix.
    assert!(!looks_like_versioned_message(&[0xff, 0xfe, 0x00]));
    let mut sdk = super::OFFCHAIN_DOMAIN.to_vec();
    sdk.extend_from_slice(&[0, 0, 5, 0]);
    sdk.extend_from_slice(b"hello");
    assert!(!looks_like_versioned_message(&sdk));
    assert!(signable(&sdk));
    assert!(signable(&[0x01, 0x02, 0x03]));
    assert!(signable(b""));
}

#[test]
fn offchain_layouts() {
    let mut sdk = super::OFFCHAIN_DOMAIN.to_vec();
    sdk.extend_from_slice(&[0, 0, 5, 0]);
    sdk.extend_from_slice(b"hello");
    assert_eq!(
        parse_offchain(&sdk),
        Some(OffchainMessage {
            format: 0,
            signers: Vec::new(),
            message: b"hello".to_vec()
        })
    );
    let mut proposal = super::OFFCHAIN_DOMAIN.to_vec();
    proposal.push(0);
    proposal.extend_from_slice(&[0x55; 32]);
    proposal.extend_from_slice(&[1, 1]);
    proposal.extend_from_slice(&[0x66; 32]);
    proposal.extend_from_slice(&[2, 0]);
    proposal.extend_from_slice(b"hi");
    let parsed = parse_offchain(&proposal).unwrap();
    assert_eq!(parsed.signers, vec![[0x66; 32]]);
    assert_eq!(parsed.message, b"hi");
    let mut broken = sdk.clone();
    broken.push(b'!');
    assert_eq!(parse_offchain(&broken), None);
    let mut version1 = super::OFFCHAIN_DOMAIN.to_vec();
    version1.extend_from_slice(&[1, 0, 1, 0, b'a']);
    assert_eq!(parse_offchain(&version1), None);
    assert!(!signable(&broken));
    assert!(signable(&sdk));
}

fn full() -> SiwsMessage {
    SiwsMessage {
        domain: "app.example".to_owned(),
        address: "4Nd1mBQtrMJVYVfKf2PJy9NZUZdTAsp7D4xWLs4gDB4T".to_owned(),
        statement: Some("Sign in to the app".to_owned()),
        uri: Some("https://app.example/login".to_owned()),
        version: Some("1".to_owned()),
        chain_id: Some("mainnet".to_owned()),
        nonce: Some("oBbLoEldZs".to_owned()),
        issued_at: Some("2026-10-30T23:58:00Z".to_owned()),
        expiration_time: Some("2026-10-31T00:10:00Z".to_owned()),
        not_before: Some("2026-10-30T23:50:00Z".to_owned()),
        request_id: Some("req-1".to_owned()),
        resources: Some(vec![
            "ipfs://bafy".to_owned(),
            "https://app.example/a".to_owned(),
        ]),
    }
}

#[test]
fn siws_text_layout_round_trips() {
    let message = full();
    let text = message.to_text();
    assert_eq!(
        text,
        "app.example wants you to sign in with your Solana account:\n\
         4Nd1mBQtrMJVYVfKf2PJy9NZUZdTAsp7D4xWLs4gDB4T\n\n\
         Sign in to the app\n\n\
         URI: https://app.example/login\n\
         Version: 1\n\
         Chain ID: mainnet\n\
         Nonce: oBbLoEldZs\n\
         Issued At: 2026-10-30T23:58:00Z\n\
         Expiration Time: 2026-10-31T00:10:00Z\n\
         Not Before: 2026-10-30T23:50:00Z\n\
         Request ID: req-1\n\
         Resources:\n\
         - ipfs://bafy\n\
         - https://app.example/a"
    );
    assert_eq!(SiwsMessage::parse(&text), Some(message.clone()));
    assert_eq!(SiwsMessage::parse(&format!("{text}\n\n")), Some(message));
    let minimal = SiwsMessage {
        domain: "app.example".to_owned(),
        address: "A".to_owned(),
        ..SiwsMessage::default()
    };
    assert_eq!(
        minimal.to_text(),
        "app.example wants you to sign in with your Solana account:\nA"
    );
    assert_eq!(
        SiwsMessage::parse(&minimal.to_text()),
        Some(minimal.clone())
    );
    let no_statement = SiwsMessage {
        nonce: Some("12345678".to_owned()),
        ..minimal
    };
    assert_eq!(
        no_statement.to_text(),
        "app.example wants you to sign in with your Solana account:\nA\n\nNonce: 12345678"
    );
    assert_eq!(
        SiwsMessage::parse(&no_statement.to_text()),
        Some(no_statement)
    );
    // Fields out of order or unknown lines do not parse.
    assert_eq!(
        SiwsMessage::parse(
            "a.example wants you to sign in with your Solana account:\nA\n\nNonce: 1\nURI: x"
        ),
        None
    );
    assert_eq!(
        SiwsMessage::parse("a.example wants you to sign in with your Ethereum account:\nA"),
        None
    );
}

fn rules(warnings: &[crate::approval::Warning]) -> Vec<crate::approval::RuleId> {
    warnings.iter().map(|warning| warning.rule).collect()
}

#[test]
fn siws_checks() {
    let origin = BrowserOrigin::parse("https://app.example").unwrap();
    let message = full();
    let context = SiwsContext {
        origin: &origin,
        account: &message.address,
        cluster: SolCluster::Mainnet,
        now_unix_ms: NOW_MS,
    };
    assert_eq!(rules(&check_siws(&message, &context)), vec![W08]);
    let mut other = message.clone();
    other.domain = "evil.example".to_owned();
    other.address = "B".to_owned();
    other.chain_id = Some("devnet".to_owned());
    other.version = Some("2".to_owned());
    other.expiration_time = Some("2026-10-30T00:00:00Z".to_owned());
    other.not_before = Some("2026-11-30T00:00:00Z".to_owned());
    other.issued_at = Some("2026-10-30T00:00:00Z".to_owned());
    let found = rules(&check_siws(&other, &context));
    for rule in [W01, W02, W03, W04, W05, W06, W07] {
        assert!(found.contains(&rule), "{rule:?}");
    }
    other.issued_at = Some("yesterday".to_owned());
    assert!(rules(&check_siws(&other, &context)).contains(&W07));
    assert!(domain_matches("app.example", &origin));
    assert!(domain_matches("app.example:443", &origin));
    assert!(!domain_matches("app.example:8443", &origin));
    assert!(!domain_matches("https://app.example", &origin));
    assert!(!domain_matches("user@app.example", &origin));
    let local = BrowserOrigin::parse("http://localhost:5173").unwrap();
    assert!(domain_matches("localhost:5173", &local));
    // A site on a non-default port must name its port: a bare host matches no port but the default.
    assert!(!domain_matches("localhost", &local));
    assert!(!domain_matches("localhost:80", &local));
    let custom = BrowserOrigin::parse("https://app.example:8443").unwrap();
    assert!(domain_matches("app.example:8443", &custom));
    assert!(!domain_matches("app.example", &custom));
    assert!(!domain_matches("app.example:443", &custom));
    let local_default = BrowserOrigin::parse("http://localhost").unwrap();
    assert!(domain_matches("localhost", &local_default));
    assert!(domain_matches("localhost:80", &local_default));
    assert!(chain_matches("solana:mainnet", SolCluster::Mainnet));
    assert!(chain_matches("devnet", SolCluster::Devnet));
    assert!(!chain_matches("devnet", SolCluster::Mainnet));
}

fn request(message: Vec<u8>, sign_in: bool) -> SolMessageRequest {
    SolMessageRequest {
        id: ApprovalId([3; 16]),
        origin: BrowserOrigin::parse("https://app.example").unwrap(),
        cluster: SolCluster::Mainnet,
        source: SolKeySource::Standard(AccountIndex::new(0).unwrap()),
        public: decode32("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"),
        label: "계정 1".to_owned(),
        message,
        sign_in,
    }
}

#[test]
fn approval_levels() {
    let plain =
        build_sol_message_request(&request(b"Prove you own it".to_vec(), false), NOW_MS).unwrap();
    assert_eq!(plain.kind, ApprovalKind::SolMessage);
    assert_eq!(plain.display.risk, RiskLevel::Info);
    assert_eq!(rules(&plain.display.warnings), vec![M04]);
    assert!(plain.display.title.contains("소유 증명"));
    let account = &plain.display.fields[2].value;
    assert!(account.ends_with("FVen3X669xLzsi6N2V91DoiyzHzg1uAgqiT8jZ9nS96Z"));
    let binary =
        build_sol_message_request(&request(vec![0xff, 0xfe, 0x00], false), NOW_MS).unwrap();
    assert_eq!(binary.display.risk, RiskLevel::High);
    assert!(
        binary
            .display
            .fields
            .iter()
            .any(|field| field.key == FieldKey::MESSAGE_HEX)
    );
    let tx = build_sol_message_request(&request(legacy_message(), false), NOW_MS).unwrap();
    assert_eq!(tx.display.risk, RiskLevel::Blocked);
    assert!(rules(&tx.display.warnings).contains(&M01));
    let mut sdk = super::OFFCHAIN_DOMAIN.to_vec();
    sdk.extend_from_slice(&[0, 0, 5, 0]);
    sdk.extend_from_slice(b"hello");
    let offchain = build_sol_message_request(&request(sdk.clone(), false), NOW_MS).unwrap();
    assert!(rules(&offchain.display.warnings).contains(&M05));
    assert_eq!(offchain.display.risk, RiskLevel::Info);
    sdk.push(0);
    let broken = build_sol_message_request(&request(sdk, false), NOW_MS).unwrap();
    assert!(rules(&broken.display.warnings).contains(&M02));
    assert_eq!(broken.display.risk, RiskLevel::Blocked);
    let siws = SiwsMessage {
        domain: "app.example".to_owned(),
        address: "FVen3X669xLzsi6N2V91DoiyzHzg1uAgqiT8jZ9nS96Z".to_owned(),
        chain_id: Some("mainnet".to_owned()),
        ..SiwsMessage::default()
    };
    let sign_in =
        build_sol_message_request(&request(siws.to_text().into_bytes(), true), NOW_MS).unwrap();
    assert_eq!(sign_in.kind, ApprovalKind::SolSignIn);
    assert!(rules(&sign_in.display.warnings).contains(&W08));
    assert!(sign_in.display.title.contains("SIWS"));
    let phishing = SiwsMessage {
        domain: "evil.example".to_owned(),
        ..siws
    };
    let blocked =
        build_sol_message_request(&request(phishing.to_text().into_bytes(), false), NOW_MS)
            .unwrap();
    assert_eq!(blocked.display.risk, RiskLevel::Blocked);
    assert!(rules(&blocked.display.warnings).contains(&W01));
}
