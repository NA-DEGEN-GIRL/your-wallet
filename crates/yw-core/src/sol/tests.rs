//! Solana tests that need crate-internal items or key values (spec/09 §2.1): the solana-sdk
//! `test_sdk_serialize` vector through the generic encoder, the `T_SOL` golden, the strict parser
//! rejections (SOL-N2), signing with an unlocked test vault (deadline, one-shot approval,
//! post-sign verification), the intent transcript and approval digest, and the journal records.

use ed25519_dalek::{Signer as _, SigningKey};
use sha2::{Digest, Sha256};

use super::address::{COMPUTE_BUDGET_PROGRAM, SYSTEM_PROGRAM, SolAddress, SolCluster, grouped};
use super::broadcast::err;
use super::display::{
    L01, L02, L03, L06, L07, L08, SimSummary, SolBlock, SolPreviewFacts,
    build_sol_transfer_request, intent_flags, transfer_title,
};
use super::fee::{FeeError, max_fee};
use super::intent::{SolTransferIntent, flags};
use super::message::{
    CompiledIx, SolParseError, assemble_transaction, encode_legacy_message, encode_message,
    parse_identical, parse_message, parse_transaction,
};
use super::recipient::{AccountClass, KnownAddress, KnownKind, check_recipient};
use super::sign::{SolSignError, finish_signed, sign_transfer};
use super::template::{SolAsset, SolTransferCore, T_SOL_MESSAGE_LEN, T_SOL_TX_LEN};
use crate::approval::{
    AccountRef, ApprovalError, ApprovalKind, ApprovalStore, ChainRef, FieldKey, RiskLevel, Signer,
    SigningPayload, approval_digest,
};
use crate::bip32::path::AccountIndex;
use crate::codec::base58::{base58_decode_64, base58_encode};
use crate::hex;
use crate::journal::sol::{
    SOL_JOURNAL_HEADER_LEN, SOL_JOURNAL_MAX_RECORDS, SolEntries, SolRecord, SolRecordError,
    SolTransition, SolTxState, activity_row, apply, has_intent, has_room, make_room, pending_for,
    push_record, take_terminal,
};
use crate::journal::{Entry, EntryKind, JournalError, JournalPlain};
use crate::slip10::SolKeySource;
use crate::vault::tests::unlocked_with;

const ABOUT: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
/// RFC 8032 secret seed of `m/44'/501'/0'/0'` for the `abandon`×11 `about` mnemonic.
const STANDARD0_SECRET: &str = "37df573b3ac4ad5b522e064e25b63ea16bcbe79d449e81a0268d1047948bb445";
const FROM: &str = "HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqk";
const TO: &str = "Hh8QwFUA6MtVu1qAoq12ucvFHNwCcVTV7hpWjeY1Hztb";

fn addr(text: &str) -> SolAddress {
    SolAddress::parse(text).unwrap()
}

fn secret() -> [u8; 32] {
    hex::decode(STANDARD0_SECRET).unwrap().try_into().unwrap()
}

/// The spec/07 §17.3 `T_SOL` golden core (`cu_limit` 450, `cu_price` 1,000, 1,000,000 lamports).
fn golden_core() -> SolTransferCore {
    SolTransferCore {
        from: addr(FROM),
        to: addr(TO),
        asset: SolAsset::Sol,
        amount: 1_000_000,
        cu_limit: 450,
        cu_price_micro: 1_000,
    }
}

const BLOCKHASH: [u8; 32] = [7; 32];

fn golden_message() -> Vec<u8> {
    hex::decode(concat!(
        "01000204",
        "f036276246a75b9de3349ed42b15e232f6518fc20f5fcd4f1d64e81f9bd258f7",
        "f8029acf5cbcbdd5ac46ec147f3b78a3df6e5022ef0411db2bab650d329a4cd4",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0306466fe5211732ffecadba72c39be7bc8ce5bbc5f7126b2c439b3a40000000",
        "0707070707070707070707070707070707070707070707070707070707070707",
        "03",
        "03000502c2010000",
        "03000903e803000000000000",
        "020200010c0200000040420f0000000000",
    ))
    .unwrap()
}

#[test]
fn solana_sdk_test_sdk_serialize_vector() {
    let key = SigningKey::from_bytes(
        &hex::decode("ff6524187c17a71584cc9b05b93a794b9ce374c1d7268e16080ee5ef775d05da")
            .unwrap()
            .try_into()
            .unwrap(),
    );
    let payer = key.verifying_key().to_bytes();
    let to = [
        1, 1, 1, 4, 5, 6, 7, 8, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 8, 7, 6, 5, 4, 1,
        1, 1,
    ];
    let program = [
        2, 2, 2, 4, 5, 6, 7, 8, 9, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 9, 8, 7, 6, 5, 4, 2,
        2, 2,
    ];
    let message = encode_legacy_message(
        [1, 0, 1],
        &[payer, to, program],
        &[0; 32],
        &[CompiledIx {
            program: 2,
            accounts: vec![0, 1],
            data: vec![1, 2, 3],
        }],
    );
    let signature = key.sign(&message).to_bytes();
    let tx = assemble_transaction(&signature, &message);
    let expected = hex::decode(concat!(
        "01788aa2b93bd1f19d479d4a830457361c26b4de52403e3d3e162e11cbbb883e2b0b26eb11ef52f08b82d9e3d609f28ddf5e1db86e3e",
        "2057893f8b64dd148904050100010324649efc21a161b93e5963c3faf9bbbdab76f15af80e44dbe73e9d058e1bd27501010104050607",
        "0809090909090909090909090909090909080706050401010102020204050607080901010101010101010101010101010908070605",
        "040202020000000000000000000000000000000000000000000000000000000000000000010202000103010203",
    ))
    .unwrap();
    assert_eq!(tx.len(), 206);
    assert_eq!(tx, expected);
}

#[test]
fn t_sol_golden() {
    let message = encode_message(&golden_core(), &BLOCKHASH);
    assert_eq!(message.len(), T_SOL_MESSAGE_LEN);
    assert_eq!(message, golden_message());
    assert_eq!(
        hex::encode(&Sha256::digest(&message)),
        "09337675ae070066af49c172b5367e9007f506407d5be1bd73b846972d1edcd4"
    );
    let key = SigningKey::from_bytes(&secret());
    assert_eq!(base58_encode(&key.verifying_key().to_bytes()), FROM);
    let signature = key.sign(&message).to_bytes();
    assert_eq!(
        base58_encode(&signature),
        "5DpEKELbVjwDHeTJzKG8EoYQdahDegeR6onWnyBqhTBiz4b1k1YMEKutLioNjVgc1Z1wTZuFLDLW2Y6vU4cu2k2u"
    );
    let tx = assemble_transaction(&signature, &message);
    assert_eq!(tx.len(), T_SOL_TX_LEN);
    assert_eq!(
        hex::encode(&Sha256::digest(&tx)),
        "7ecb80478f954ea1a3625bf0ee1776ff0991c3f8e6ceb33c6f7b198f3929f788"
    );
    assert_eq!(max_fee(450, 1_000), Ok(5_001));
    assert_eq!(
        base58_encode(&BLOCKHASH),
        "US517G5965aydkZ46HS38QLi7UQiSojurfbQfKCELFx"
    );
    let (core, blockhash, parsed_signature) = parse_transaction(&tx, SolCluster::Devnet).unwrap();
    assert_eq!(
        (core, blockhash, parsed_signature),
        (golden_core(), BLOCKHASH, signature)
    );
    assert_eq!(
        parse_identical(&message, SolCluster::Mainnet).unwrap().0,
        golden_core()
    );
}

fn rebuild(header: [u8; 3], keys: &[[u8; 32]], instructions: &[CompiledIx]) -> Vec<u8> {
    encode_legacy_message(header, keys, &BLOCKHASH, instructions)
}

type Parts = ([u8; 32], [u8; 32], [u8; 32], [u8; 32], Vec<CompiledIx>);

fn golden_parts() -> Parts {
    let core = golden_core();
    (
        core.from.to_bytes(),
        core.to.to_bytes(),
        SYSTEM_PROGRAM.to_bytes(),
        COMPUTE_BUDGET_PROGRAM.to_bytes(),
        vec![
            CompiledIx {
                program: 3,
                accounts: vec![],
                data: super::template::set_compute_unit_limit_data(450),
            },
            CompiledIx {
                program: 3,
                accounts: vec![],
                data: super::template::set_compute_unit_price_data(1_000),
            },
            CompiledIx {
                program: 2,
                accounts: vec![0, 1],
                data: super::template::system_transfer_data(1_000_000),
            },
        ],
    )
}

/// SOL-N2: messages outside the template.
#[test]
fn parser_rejects_everything_outside_the_template() {
    let (from, to, system, budget, ixs) = golden_parts();
    let keys = [from, to, system, budget];
    let parse = |msg: &[u8]| parse_message(msg, SolCluster::Mainnet);
    assert!(parse(&rebuild([1, 0, 2], &keys, &ixs)).is_ok());
    // Instruction added / removed / reordered.
    let mut more = ixs.clone();
    more.push(ixs[2].clone());
    assert_eq!(
        parse(&rebuild([1, 0, 2], &keys, &more)),
        Err(SolParseError::UnknownTemplate)
    );
    assert_eq!(
        parse(&rebuild([1, 0, 2], &keys, &ixs[..2])),
        Err(SolParseError::UnknownTemplate)
    );
    let swapped = vec![ixs[1].clone(), ixs[0].clone(), ixs[2].clone()];
    assert_eq!(
        parse(&rebuild([1, 0, 2], &keys, &swapped)),
        Err(SolParseError::BadData)
    );
    let transfer_first = vec![ixs[2].clone(), ixs[0].clone(), ixs[1].clone()];
    assert_eq!(
        parse(&rebuild([1, 0, 2], &keys, &transfer_first)),
        Err(SolParseError::UnexpectedProgram)
    );
    // ComputeBudget twice (limit twice).
    let twice = vec![ixs[0].clone(), ixs[0].clone(), ixs[2].clone()];
    assert_eq!(
        parse(&rebuild([1, 0, 2], &keys, &twice)),
        Err(SolParseError::BadData)
    );
    // Program id changed.
    let other_program = [from, to, system, [9; 32]];
    assert_eq!(
        parse(&rebuild([1, 0, 2], &other_program, &ixs)),
        Err(SolParseError::UnexpectedProgram)
    );
    // Header values changed.
    for header in [[1, 0, 1], [2, 0, 2], [1, 1, 2], [1, 0, 3], [1, 0, 6]] {
        assert_eq!(
            parse(&rebuild(header, &keys, &ixs)),
            Err(SolParseError::UnknownTemplate),
            "{header:?}"
        );
    }
    // Duplicate key.
    let dup = [from, from, system, budget];
    assert_eq!(
        parse(&rebuild([1, 0, 2], &dup, &ixs)),
        Err(SolParseError::DuplicateKey)
    );
    // Group order (programs swapped, indices adjusted).
    let swapped_keys = [from, to, budget, system];
    let adjusted: Vec<CompiledIx> = ixs
        .iter()
        .map(|ix| CompiledIx {
            program: if ix.program == 3 { 2 } else { 3 },
            ..ix.clone()
        })
        .collect();
    assert_eq!(
        parse(&rebuild([1, 0, 2], &swapped_keys, &adjusted)),
        Err(SolParseError::BadGroupOrder)
    );
    // Versioned prefixes.
    for prefix in [0x80_u8, 0x81] {
        let mut versioned = vec![prefix];
        versioned.extend_from_slice(&golden_message());
        assert_eq!(parse(&versioned), Err(SolParseError::Versioned));
    }
    // Trailing bytes.
    let mut trailing = golden_message();
    trailing.push(0);
    assert_eq!(parse(&trailing), Err(SolParseError::TrailingBytes));
}

/// SOL-N2: values, transfer accounts and signature counts outside the template.
#[test]
fn parser_rejects_bad_values_accounts_and_signatures() {
    let (from, to, system, budget, ixs) = golden_parts();
    let keys = [from, to, system, budget];
    let parse = |msg: &[u8]| parse_message(msg, SolCluster::Mainnet);
    // Amount 0, cu_limit 0 and 1,400,001.
    let mut zero = golden_core();
    zero.amount = 0;
    assert_eq!(
        parse(&encode_message(&zero, &BLOCKHASH)),
        Err(SolParseError::ZeroAmount)
    );
    for limit in [0, 1_400_001] {
        let mut core = golden_core();
        core.cu_limit = limit;
        assert_eq!(
            parse(&encode_message(&core, &BLOCKHASH)),
            Err(SolParseError::BadComputeLimit)
        );
    }
    let mut max = golden_core();
    max.cu_limit = 1_400_000;
    assert!(parse(&encode_message(&max, &BLOCKHASH)).is_ok());
    // Wrong accounts of the transfer.
    let mut bad_accounts = ixs;
    bad_accounts[2].accounts = vec![1, 0];
    assert_eq!(
        parse(&rebuild([1, 0, 2], &keys, &bad_accounts)),
        Err(SolParseError::BadAccounts)
    );
    bad_accounts[2].accounts = vec![0, 4];
    assert_eq!(
        parse(&rebuild([1, 0, 2], &keys, &bad_accounts)),
        Err(SolParseError::BadIndex)
    );
    // Signature counts 0 and 2, truncations.
    let tx = assemble_transaction(&[1; 64], &golden_message());
    for count in [0_u8, 2] {
        let mut bad = tx.clone();
        bad[0] = count;
        assert_eq!(
            parse_transaction(&bad, SolCluster::Mainnet),
            Err(SolParseError::BadSignatureCount)
        );
    }
    for len in 0..tx.len() {
        assert!(
            parse_transaction(&tx[..len], SolCluster::Mainnet).is_err(),
            "{len}"
        );
    }
    assert_eq!(
        parse_transaction(&vec![1; 1_233], SolCluster::Mainnet),
        Err(SolParseError::TooLarge)
    );
}

/// SOL-N2: every single-bit flip of the 202-byte message is rejected or parses to something else
/// than the approved (core, blockhash), so the identity check refuses it.
#[test]
fn every_bit_flip_is_rejected_or_differs() {
    let message = golden_message();
    let mut rejected = 0;
    for index in 0..message.len() {
        for bit in 0..8 {
            let mut flipped = message.clone();
            flipped[index] ^= 1 << bit;
            match parse_message(&flipped, SolCluster::Mainnet) {
                Err(_) => rejected += 1,
                Ok((core, blockhash)) => {
                    assert!(
                        core != golden_core() || blockhash != BLOCKHASH,
                        "{index}:{bit}"
                    );
                }
            }
        }
    }
    assert!(rejected > 0);
}

fn intent(core: SolTransferCore, source: SolKeySource, flags: u8) -> SolTransferIntent {
    SolTransferIntent {
        id: [0x42; 16],
        cluster: SolCluster::Devnet,
        source,
        core,
        max_fee_lamports: max_fee(core.cu_limit, core.cu_price_micro).unwrap(),
        fee_cap_lamports: 100_000,
        flags,
        created_at_ms: 1_790_000_000_000,
    }
}

fn facts(intent: &SolTransferIntent) -> SolPreviewFacts {
    SolPreviewFacts {
        account_label: "계정 1".to_owned(),
        recipient: check_recipient(&intent.core.to.to_base58(), &intent.core.from, &[]).unwrap(),
        recipient_account: AccountClass::SystemWallet,
        balance: 10_000_000,
        rent0: 890_880,
        rpc_fee: Some(intent.max_fee_lamports),
        simulation: SimSummary::Ok { units: 450 },
        blocks: Vec::new(),
    }
}

fn approved_for(intent: &SolTransferIntent) -> (ApprovalStore, crate::approval::Approved) {
    let draft =
        build_sol_transfer_request(intent, &intent.cluster.genesis(), &facts(intent)).unwrap();
    let mut store = ApprovalStore::new();
    let request = store.issue(draft, 1_000, intent.created_at_ms).unwrap();
    let approved = store.consume(request.id, request.digest, 2_000).unwrap();
    (store, approved)
}

#[test]
fn sign_transfer_reproduces_the_golden_and_checks_everything() {
    let vault = unlocked_with(ABOUT);
    let standard0 = SolKeySource::Standard(AccountIndex::ZERO);
    let intent = intent(golden_core(), standard0, flags::FIRST_TIME);
    let (mut store, approved) = approved_for(&intent);
    let signed = sign_transfer(&vault, approved, 2_000, BLOCKHASH, 22_000).unwrap();
    assert_eq!(
        base58_encode(&signed.signature),
        "5DpEKELbVjwDHeTJzKG8EoYQdahDegeR6onWnyBqhTBiz4b1k1YMEKutLioNjVgc1Z1wTZuFLDLW2Y6vU4cu2k2u"
    );
    assert_eq!(
        hex::encode(&Sha256::digest(&signed.tx)),
        "7ecb80478f954ea1a3625bf0ee1776ff0991c3f8e6ceb33c6f7b198f3929f788"
    );
    assert_eq!(
        hex::encode(&signed.message_sha256),
        "09337675ae070066af49c172b5367e9007f506407d5be1bd73b846972d1edcd4"
    );
    // ④ the same approval cannot be used twice.
    let request_id = crate::approval::ApprovalId(intent.id);
    assert!(matches!(
        store.consume(request_id, [0; 32], 3_000),
        Err(ApprovalError::NotPending(_))
    ));
    // ④ more than 20 s after consume: refused before any key use.
    let (_, late) = approved_for(&intent);
    assert_eq!(
        sign_transfer(&vault, late, 2_000, BLOCKHASH, 22_001),
        Err(SolSignError::DeadlineExceeded)
    );
    // A key source that does not derive `from`.
    let wrong_source = intent_with_source(SolKeySource::Standard(AccountIndex::new(1).unwrap()));
    let (_, approved) = approved_for(&wrong_source);
    assert_eq!(
        sign_transfer(&vault, approved, 0, BLOCKHASH, 0),
        Err(SolSignError::KeyMismatch)
    );
    // An approval of another kind.
    let evm = crate::approval::Approved::for_test(
        ChainRef::Solana {
            cluster: SolCluster::Devnet,
            genesis: SolCluster::Devnet.genesis(),
        },
        AccountRef::Sol(addr(FROM).to_bytes()),
        Signer::FromPayload,
        ApprovalKind::EvmPersonalSign,
        SigningPayload::EvmPersonal(vec![1]),
    );
    assert_eq!(
        sign_transfer(&vault, evm, 0, BLOCKHASH, 0),
        Err(SolSignError::KindMismatch)
    );
    let cross_cluster = crate::approval::Approved::for_test(
        ChainRef::Solana {
            cluster: SolCluster::Mainnet,
            genesis: SolCluster::Mainnet.genesis(),
        },
        AccountRef::Sol(addr(FROM).to_bytes()),
        Signer::FromPayload,
        ApprovalKind::SolTransfer,
        SigningPayload::SolTransfer(intent),
    );
    assert_eq!(
        sign_transfer(&vault, cross_cluster, 0, BLOCKHASH, 0),
        Err(SolSignError::KindMismatch)
    );
    // A template-invalid core is refused by the parse step (nothing signed).
    let mut zero = golden_core();
    zero.amount = 0;
    let zero_intent = intent_with_core(zero);
    let raw = crate::approval::Approved::for_test(
        ChainRef::Solana {
            cluster: SolCluster::Devnet,
            genesis: SolCluster::Devnet.genesis(),
        },
        AccountRef::Sol(addr(FROM).to_bytes()),
        Signer::FromPayload,
        ApprovalKind::SolTransfer,
        SigningPayload::SolTransfer(zero_intent),
    );
    assert_eq!(
        sign_transfer(&vault, raw, 0, BLOCKHASH, 0),
        Err(SolSignError::Parse(SolParseError::ZeroAmount))
    );
    // Locked vault.
    let mut locked = unlocked_with(ABOUT);
    locked.lock();
    let (_, approved) = approved_for(&intent);
    assert!(matches!(
        sign_transfer(&locked, approved, 0, BLOCKHASH, 0),
        Err(SolSignError::Vault(_))
    ));
}

fn intent_with_source(source: SolKeySource) -> SolTransferIntent {
    intent(golden_core(), source, 0)
}

fn intent_with_core(core: SolTransferCore) -> SolTransferIntent {
    intent(core, SolKeySource::Standard(AccountIndex::ZERO), 0)
}

#[test]
fn post_sign_verification_failure_is_reported() {
    let message = golden_message();
    let key = SigningKey::from_bytes(&secret());
    let mut signature = key.sign(&message).to_bytes();
    let from = addr(FROM).to_bytes();
    assert!(finish_signed(&from, &message, signature, SolCluster::Devnet).is_ok());
    signature[5] ^= 0x10;
    assert_eq!(
        finish_signed(&from, &message, signature, SolCluster::Devnet),
        Err(SolSignError::PostSignVerification)
    );
}

#[test]
fn approval_request_fields_flags_and_digest() {
    let core = golden_core();
    let all = flags::SEND_MAX
        | flags::OFF_CURVE
        | flags::FIRST_TIME
        | flags::LOOKALIKE
        | flags::NON_STANDARD_PATH;
    let lookalike_facts_intent = intent(core, SolKeySource::Bip44Root, all);
    let mut f = facts(&lookalike_facts_intent);
    f.recipient.lookalikes.push(KnownAddress {
        address: addr("7WktogJEd2wQ9eH2oWusmcoFTgeYi6rS632UviTBJ2jm"),
        label: "친구\u{202E}".to_owned(),
        kind: KnownKind::Book { verified: false },
    });
    let draft =
        build_sol_transfer_request(&lookalike_facts_intent, &SolCluster::Devnet.genesis(), &f)
            .unwrap();
    assert_eq!(
        draft.display.title,
        "[Solana devnet (테스트)] SOL 전송: 0.001000000 SOL"
    );
    let keys: Vec<u16> = draft
        .display
        .fields
        .iter()
        .map(|field| field.key.0)
        .collect();
    assert_eq!(
        keys,
        [
            0x0001, 0x0002, 0x0003, 0x0501, 0x0502, 0x0504, 0x0505, 0x0506, 0x0507, 0x0508, 0x0509
        ]
    );
    for field in &draft.display.fields {
        assert!(FieldKey(field.key.0).flags().is_some());
        assert!(!field.volatile);
        assert_eq!(field.critical, (0x0001..=0x0505).contains(&field.key.0));
    }
    let rules: Vec<_> = draft.display.warnings.iter().map(|w| w.rule).collect();
    assert_eq!(rules, [L02, L03, L06, L07, L08]);
    assert_eq!(draft.display.risk, RiskLevel::High);
    assert!(draft.display.ack_required);
    assert!(draft.display.warnings[1].text.contains("[U+202E]"));
    assert_eq!(
        draft.simulation,
        crate::approval::SimulationBinding::NotApplicable
    );
    assert_eq!(draft.signer, Signer::FromPayload);
    // Caution/info only: no acknowledgement.
    let mild = intent(
        core,
        SolKeySource::Standard(AccountIndex::ZERO),
        flags::FIRST_TIME,
    );
    let draft =
        build_sol_transfer_request(&mild, &SolCluster::Devnet.genesis(), &facts(&mild)).unwrap();
    assert_eq!(draft.display.risk, RiskLevel::Caution);
    assert!(!draft.display.ack_required);
    // A block reason makes it L01/Blocked; the store refuses consumption.
    let mut blocked_facts = facts(&mild);
    blocked_facts
        .blocks
        .push(SolBlock::Fee(FeeError::FeeFormulaChanged));
    let draft =
        build_sol_transfer_request(&mild, &SolCluster::Devnet.genesis(), &blocked_facts).unwrap();
    assert_eq!(draft.display.warnings[0].rule, L01);
    assert_eq!(draft.display.risk, RiskLevel::Blocked);
    let mut store = ApprovalStore::new();
    let request = store.issue(draft, 0, 0).unwrap();
    assert_eq!(
        store.consume(request.id, request.digest, 10),
        Err(ApprovalError::Blocked)
    );
}

#[test]
fn approval_digest_binds_every_intent_field() {
    let core = golden_core();
    // The digest binds every intent byte: one flipped bit anywhere changes it.
    let base = intent(core, SolKeySource::Standard(AccountIndex::ZERO), 0);
    let draft =
        build_sol_transfer_request(&base, &SolCluster::Devnet.genesis(), &facts(&base)).unwrap();
    let digest = approval_digest(&draft, 120_000).unwrap();
    let transcript = base.transcript();
    assert!(transcript.starts_with(&[0, 0, 0, 31]));
    assert_eq!(&transcript[4..35], b"your-wallet/sol/transfer-intent");
    let variants = [
        SolTransferIntent {
            id: [0x43; 16],
            ..base
        },
        SolTransferIntent {
            cluster: SolCluster::Mainnet,
            ..base
        },
        SolTransferIntent {
            source: SolKeySource::Bip44Account(AccountIndex::ZERO),
            ..base
        },
        SolTransferIntent {
            max_fee_lamports: base.max_fee_lamports ^ 1,
            ..base
        },
        SolTransferIntent {
            fee_cap_lamports: base.fee_cap_lamports ^ 1,
            ..base
        },
        SolTransferIntent { flags: 1, ..base },
        SolTransferIntent {
            created_at_ms: base.created_at_ms ^ 1,
            ..base
        },
        SolTransferIntent {
            core: SolTransferCore {
                amount: core.amount ^ 1,
                ..core
            },
            ..base
        },
        SolTransferIntent {
            core: SolTransferCore {
                cu_limit: core.cu_limit ^ 1,
                ..core
            },
            ..base
        },
        SolTransferIntent {
            core: SolTransferCore {
                cu_price_micro: core.cu_price_micro ^ 1,
                ..core
            },
            ..base
        },
        SolTransferIntent {
            core: SolTransferCore {
                to: addr(FROM),
                from: addr(TO),
                ..core
            },
            ..base
        },
    ];
    for variant in variants {
        assert_ne!(variant.intent_hash(), base.intent_hash());
        let mut changed = draft.clone();
        changed.payload = SigningPayload::SolTransfer(variant);
        assert_ne!(approval_digest(&changed, 120_000).unwrap(), digest);
    }
    let mut other_genesis = draft.clone();
    other_genesis.chain = ChainRef::Solana {
        cluster: SolCluster::Devnet,
        genesis: [1; 32],
    };
    assert_ne!(approval_digest(&other_genesis, 120_000).unwrap(), digest);
    let mut other_account = draft.clone();
    other_account.account = AccountRef::Sol([3; 32]);
    assert_ne!(approval_digest(&other_account, 120_000).unwrap(), digest);
    assert_ne!(approval_digest(&draft, 120_001).unwrap(), digest);
    // Kind/payload/account consistency is enforced at issue.
    let mut mismatched = draft.clone();
    mismatched.account = AccountRef::Sol([3; 32]);
    assert_eq!(
        ApprovalStore::new().issue(mismatched, 0, 0).unwrap_err(),
        ApprovalError::PayloadMismatch
    );
    let mut simulated = draft;
    simulated.simulation = crate::approval::SimulationBinding::None {
        reason: crate::approval::SimNoneReason::Skipped,
    };
    assert_eq!(
        ApprovalStore::new().issue(simulated, 0, 0).unwrap_err(),
        ApprovalError::SimulationBindingMismatch
    );
}

#[test]
fn flags_follow_what_is_shown() {
    let from = addr(FROM);
    let check =
        check_recipient("5N3f1tj9v1vc5TUZ8S7mCAnVmjVKrfnzXWhxLaxyZAgt", &from, &[]).unwrap();
    let value = intent_flags(
        true,
        &check,
        AccountClass::ProgramOwned,
        SimSummary::Ok { units: 601 },
        600,
        SolKeySource::RawSeed,
    );
    assert_eq!(
        value,
        flags::SEND_MAX
            | flags::OFF_CURVE
            | flags::FIRST_TIME
            | flags::PROGRAM_OWNED
            | flags::SIM_WARNING
            | flags::NON_STANDARD_PATH
    );
    let known = [KnownAddress {
        address: addr(TO),
        label: "계정 2".to_owned(),
        kind: KnownKind::Own { index: 1 },
    }];
    let own = check_recipient(TO, &from, &known).unwrap();
    assert_eq!(
        intent_flags(
            false,
            &own,
            AccountClass::SystemWallet,
            SimSummary::Ok { units: 450 },
            600,
            SolKeySource::Standard(AccountIndex::ZERO)
        ),
        0
    );
    assert_eq!(
        intent_flags(
            false,
            &own,
            AccountClass::SystemWallet,
            SimSummary::Failed {
                err: err::INSUFFICIENT_FUNDS_FOR_FEE,
                units: None
            },
            600,
            SolKeySource::Standard(AccountIndex::ZERO)
        ),
        flags::SIM_WARNING
    );
    assert_eq!(
        intent_flags(
            false,
            &own,
            AccountClass::SystemWallet,
            SimSummary::NoResult,
            600,
            SolKeySource::Standard(AccountIndex::ZERO)
        ),
        0
    );
}

// ---------------------------------------------------------------- journal (spec/07 §14.1)

fn signed_record(core: SolTransferCore, signed_at_ms: u64) -> SolRecord {
    let vault = unlocked_with(ABOUT);
    let intent = intent_with_core(core);
    let (_, approved) = approved_for(&intent);
    let signed = sign_transfer(&vault, approved, 0, BLOCKHASH, 0).unwrap();
    SolRecord::new_pending(&intent, &signed, signed_at_ms, 1_234)
}

fn sol_entry(record: &SolRecord) -> Entry {
    Entry {
        kind: EntryKind::Sol,
        body: record.encode().unwrap(),
    }
}

#[test]
fn journal_record_round_trip_and_rejections() {
    let record = signed_record(golden_core(), 1_790_000_000_000);
    let body = record.encode().unwrap();
    assert_eq!(body.len(), SOL_JOURNAL_HEADER_LEN + T_SOL_TX_LEN);
    assert_eq!(body.len(), 356);
    assert_eq!(SolRecord::decode(&body), Ok(record.clone()));
    // Container round trip with kind 0x02 framing.
    let plain = JournalPlain {
        entries: vec![sol_entry(&record)],
    };
    let bytes = plain.encode().unwrap();
    assert_eq!(bytes[16], 0x02);
    assert_eq!(&bytes[17..21], &356_u32.to_be_bytes());
    let decoded = JournalPlain::decode(&bytes).unwrap();
    assert_eq!(
        SolEntries::from_plain(&decoded).records(),
        vec![record.clone()]
    );
    assert_eq!(record.tx_id().len(), 88);
    assert_eq!(
        base58_decode_64(&record.tx_id()).unwrap(),
        record.signature()
    );
    // Body errors.
    let reject = |mutate: &dyn Fn(&mut Vec<u8>), expected: SolRecordError| {
        let mut bad = body.clone();
        mutate(&mut bad);
        assert_eq!(SolRecord::decode(&bad), Err(expected));
    };
    reject(&|b| b[0] = 0x01, SolRecordError::Header);
    reject(&|b| b[1] = 2, SolRecordError::Header);
    reject(&|b| b[2] = 5, SolRecordError::Value);
    reject(&|b| b[2] = 0, SolRecordError::Value);
    reject(&|b| b[3] = 3, SolRecordError::Value);
    reject(&|b| b[4] = 6, SolRecordError::Source);
    reject(&|b| b[12] = 1, SolRecordError::Source);
    reject(&|b| b.push(0), SolRecordError::Length);
    reject(&|b| b.truncate(b.len() - 1), SolRecordError::Length);
    reject(&|b| b[88] = b[88].wrapping_add(1), SolRecordError::Length);
    reject(&|b| b[84] = 1, SolRecordError::Terminal);
    reject(&|b| b[86] = 1, SolRecordError::Terminal);
    reject(
        &|b| b[89] = 2,
        SolRecordError::Tx(SolParseError::BadSignatureCount),
    );
    reject(&|b| b[100] ^= 1, SolRecordError::Signature);
    reject(
        &|b| {
            let last = b.len() - 1;
            b[last] ^= 1;
        },
        SolRecordError::Signature,
    );
    reject(
        &|b| b[89 + 65] = 0x80,
        SolRecordError::Tx(SolParseError::Versioned),
    );
    // A damaged body stays in the journal verbatim; other entries still decode.
    let mut damaged = body.clone();
    damaged[100] ^= 1;
    let mixed = JournalPlain {
        entries: vec![
            Entry {
                kind: EntryKind::Sol,
                body: damaged.clone(),
            },
            sol_entry(&record),
        ],
    };
    let view = SolEntries::from_plain(&mixed);
    assert_eq!(view.corrupt, 1);
    assert_eq!(view.records.len(), 1);
    assert_eq!(
        JournalPlain::decode(&mixed.encode().unwrap())
            .unwrap()
            .entries[0]
            .body,
        damaged
    );
}

#[test]
fn journal_transitions_activity_and_room() {
    let pending = signed_record(golden_core(), 1_000);
    let mut plain = JournalPlain::default();
    assert!(has_room(&plain));
    push_record(&mut plain, &pending).unwrap();
    assert!(has_intent(&plain, &pending.intent_hash));
    assert!(!has_intent(&plain, &[0; 32]));
    let records = SolEntries::from_plain(&plain).records();
    assert!(pending_for(&records, SolCluster::Devnet, &addr(FROM)).is_some());
    assert!(pending_for(&records, SolCluster::Mainnet, &addr(FROM)).is_none());
    assert!(pending_for(&records, SolCluster::Devnet, &addr(TO)).is_none());
    // Landed / FailedOnChain / Expired mapping.
    let signature = pending.signature();
    for (transition, state, status) in [
        (
            SolTransition::Landed {
                signature,
                slot: 77,
            },
            SolTxState::Landed,
            "succeeded",
        ),
        (
            SolTransition::FailedOnChain {
                signature,
                slot: 78,
                err: err::SYSTEM_INSTRUCTION,
            },
            SolTxState::FailedOnChain,
            "failed",
        ),
        (
            SolTransition::Expired { signature },
            SolTxState::Expired,
            "expired",
        ),
    ] {
        let mut copy = plain.clone();
        assert!(apply(&mut copy, &transition));
        assert!(!apply(&mut copy, &transition), "only Pending moves");
        let record = SolEntries::from_plain(&copy).records().remove(0);
        assert_eq!(record.state, state);
        let row = activity_row(&record, 9_999).unwrap();
        assert_eq!(row.status, status);
        assert_eq!(row.account, FROM);
        assert_eq!(row.counterparty, TO);
        assert_eq!(row.asset, "native");
        assert_eq!(row.amount, "1000000");
        assert_eq!(row.tx_id, pending.tx_id());
        assert_eq!(
            row.title,
            transfer_title(SolCluster::Devnet, &golden_core())
        );
        assert_eq!(row.time_unix_ms, 9_999);
        let rows = take_terminal(&mut copy, 9_999);
        assert_eq!(rows, vec![row]);
        assert!(copy.entries.is_empty());
    }
    assert!(activity_row(&pending, 0).is_none());
    // 64-record cap: terminal records make room oldest first; Pending ones never move.
    let mut full = JournalPlain::default();
    let mut terminal = pending.clone();
    terminal.state = SolTxState::Landed;
    for index in 0..SOL_JOURNAL_MAX_RECORDS {
        let mut record = terminal.clone();
        record.signed_at_ms = u64::try_from(index).unwrap();
        full.entries.push(sol_entry(&record));
    }
    assert!(!has_room(&full));
    assert_eq!(push_record(&mut full, &pending), Err(JournalError::Full));
    let rows = make_room(&mut full, 5).unwrap();
    assert_eq!(rows.len(), 1);
    assert!(has_room(&full));
    let mut all_pending = JournalPlain::default();
    for _ in 0..SOL_JOURNAL_MAX_RECORDS {
        all_pending.entries.push(sol_entry(&pending));
    }
    let before = all_pending.clone();
    assert_eq!(make_room(&mut all_pending, 5), Err(JournalError::Full));
    assert_eq!(all_pending, before);
    // EVM entries are never removed for SOL room, and count toward the global bound.
    let mut crowded = JournalPlain::default();
    for _ in 0..256 {
        crowded.entries.push(Entry {
            kind: EntryKind::Evm,
            body: vec![1],
        });
    }
    assert!(!has_room(&crowded));
    assert_eq!(make_room(&mut crowded, 0), Err(JournalError::Full));
    assert_eq!(crowded.entries.len(), 256);
}

#[test]
fn grouped_display_is_the_full_address() {
    let text = grouped(&addr(FROM));
    assert_eq!(text.replace(' ', ""), FROM);
    assert!(!text.contains('…'));
}
