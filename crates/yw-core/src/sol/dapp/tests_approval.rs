//! dApp transaction approvals (spec/07 §20.4–§20.7, spec/09 SOL-N11–N13 and N18 core parts):
//! the X rules from minimal fixtures, the payload digest and `check_draft`, the display fields
//! (flags, the 32-transaction bound, whole addresses, escaping, per-transaction lookup errors),
//! the fee range and its RPC check, the simulation diff, and the sign-only signer with standard,
//! imported, added-mnemonic and card keys, including the cross-kind refusals.
#![expect(
    clippy::indexing_slicing,
    reason = "test fixtures index buffers of known length"
)]

use ed25519_dalek::{Signer as _, SigningKey};

use super::alt::{LookupTable, ResolvedKeys};
use super::decode::ATA_MISMATCH;
use super::diff::{AccountSnapshot, AuthorityKind, Change, SOL_DAPP_MAX_WATCH, changes, watch_set};
use super::display::{SolTxFacts, SolTxItemFacts, SolTxRequest, build_sol_tx_request};
use super::parse::{
    LookupRef, MessageHeader, SolTxMessage, SolTxVersion, encode_message_any, parse_wire_tx,
};
use super::sign::{SolTxCardError, SolTxSignError, from_message_error, sign_txs, sign_txs_card};
use super::{
    AltError, SolCommitment, SolSendOptions, SolTxItem, SolTxMode, SolTxPayload, SolTxPayloadError,
};
use crate::approval::{
    AccountRef, ApprovalDraft, ApprovalError, ApprovalId, ApprovalKind, ApprovalOrigin,
    ApprovalStore, Approved, ChainRef, FieldKey, RiskLevel, RuleId, Signer, SigningPayload,
    SimulationBinding,
};
use crate::bip32::path::AccountIndex;
use crate::evm::risk::{
    X01, X02, X03, X04, X05, X06, X07, X08, X09, X10, X11, X12, X13, X14, X15, X16, X17, X18, X19,
    X20, is_simulation_status, level_of,
};
use crate::policy::BrowserOrigin;
use crate::slip10::SolKeySource;
use crate::sol::address::{
    ATA_PROGRAM, BPF_LOADER_UPGRADEABLE, COMPUTE_BUDGET_PROGRAM, ED25519_PRECOMPILE,
    MEMO_PROGRAM_V2, SYSTEM_PROGRAM, SYSVAR_CLOCK, SYSVAR_RECENT_BLOCKHASHES, SYSVAR_RENT,
    SolAddress, SolCluster, TOKEN_2022_PROGRAM, TOKEN_PROGRAM, grouped,
};
use crate::sol::display::SimSummary;
use crate::sol::message::CompiledIx;
use crate::sol::msgsign::SolMessageError;
use crate::sol::recipient::{KnownAddress, KnownKind};
use crate::sol::shortvec;
use crate::sol::template::{
    set_compute_unit_limit_data, set_compute_unit_price_data, spl_entries, system_transfer_data,
};
use crate::sol::token::MintView;
use crate::vault::tests::unlocked_with;

/// `abandon`×11 `about`, standard account 0 (spec/07 §17.1). The literal stays in `sol/tests.rs`,
/// a path the privacy scan accepts for test vectors.
pub(super) use crate::sol::tests::ABOUT;
const FROM: &str = "HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqk";
pub(super) const CLUSTER: SolCluster = SolCluster::Devnet;

pub(super) fn wallet() -> SolAddress {
    SolAddress::parse(FROM).unwrap()
}

pub(super) fn key(byte: u8) -> SolAddress {
    SolAddress::from_bytes([byte; 32])
}

/// A co-signer of the site (fee payer or partial signer).
pub(super) fn site_key() -> SigningKey {
    SigningKey::from_bytes(&[0x42; 32])
}

pub(super) fn site_address() -> SolAddress {
    SolAddress::from_bytes(site_key().verifying_key().to_bytes())
}

pub(super) fn ix(program: u8, accounts: &[u8], data: &[u8]) -> CompiledIx {
    CompiledIx {
        program,
        accounts: accounts.to_vec(),
        data: data.to_vec(),
    }
}

fn message(
    version: SolTxVersion,
    header: [u8; 3],
    keys: &[SolAddress],
    instructions: Vec<CompiledIx>,
    lookups: Vec<LookupRef>,
) -> Vec<u8> {
    encode_message_any(&SolTxMessage {
        version,
        header: MessageHeader {
            required: header[0],
            readonly_signed: header[1],
            readonly_unsigned: header[2],
        },
        static_keys: keys.to_vec(),
        blockhash: [7; 32],
        instructions,
        lookups,
    })
}

pub(super) fn legacy(
    header: [u8; 3],
    keys: &[SolAddress],
    instructions: Vec<CompiledIx>,
) -> Vec<u8> {
    message(SolTxVersion::Legacy, header, keys, instructions, Vec::new())
}

/// The wire form with every slot zero, then `signers` filled by their keys.
pub(super) fn wire(message: &[u8], signers: &[(usize, &SigningKey)]) -> Vec<u8> {
    let required = usize::from(if message[0] & 0x80 == 0 {
        message[0]
    } else {
        message[1]
    });
    let mut slots = vec![[0_u8; 64]; required];
    for (slot, signer) in signers {
        slots[*slot] = signer.sign(message).to_bytes();
    }
    let mut out = shortvec::encode(u16::try_from(required).unwrap());
    for slot in &slots {
        out.extend_from_slice(slot);
    }
    out.extend_from_slice(message);
    out
}

/// Wallet pays and sends 1,000 lamports to `0x22…`.
pub(super) fn transfer_message() -> Vec<u8> {
    legacy(
        [1, 0, 1],
        &[wallet(), key(0x22), SYSTEM_PROGRAM],
        vec![ix(2, &[0, 1], &system_transfer_data(1_000))],
    )
}

fn snapshot(owner: SolAddress, lamports: u64, data: Vec<u8>) -> AccountSnapshot {
    AccountSnapshot {
        owner,
        lamports,
        data,
    }
}

/// A 165-byte token account.
fn token_account(
    mint: SolAddress,
    owner: SolAddress,
    amount: u64,
    delegate: Option<SolAddress>,
    close_authority: Option<SolAddress>,
) -> Vec<u8> {
    let mut data = Vec::with_capacity(165);
    data.extend_from_slice(mint.as_bytes());
    data.extend_from_slice(owner.as_bytes());
    data.extend_from_slice(&amount.to_le_bytes());
    match delegate {
        Some(delegate) => {
            data.extend_from_slice(&1_u32.to_le_bytes());
            data.extend_from_slice(delegate.as_bytes());
        }
        None => data.extend_from_slice(&[0; 36]),
    }
    data.push(1);
    data.extend_from_slice(&[0; 12]);
    data.extend_from_slice(&0_u64.to_le_bytes());
    match close_authority {
        Some(authority) => {
            data.extend_from_slice(&1_u32.to_le_bytes());
            data.extend_from_slice(authority.as_bytes());
        }
        None => data.extend_from_slice(&[0; 36]),
    }
    assert_eq!(data.len(), 165);
    data
}

/// Simulation succeeded and the wallet paid 1,000 lamports and the 5,000 fee.
fn ok_facts() -> SolTxItemFacts {
    SolTxItemFacts {
        tables: Ok((0, Vec::new())),
        pre: vec![(
            wallet(),
            Some(snapshot(SYSTEM_PROGRAM, 1_000_000_000, Vec::new())),
        )],
        post: Some(vec![(
            wallet(),
            Some(snapshot(SYSTEM_PROGRAM, 999_994_000, Vec::new())),
        )]),
        sim: SimSummary::Ok { units: 150 },
        sim_replaced_blockhash: false,
        rpc_fee: Some(5_000),
        blockhash_valid: Some(true),
    }
}

fn facts(items: Vec<SolTxItemFacts>) -> SolTxFacts {
    SolTxFacts {
        items,
        mints: Vec::new(),
        unread_mints: Vec::new(),
        known: Vec::new(),
        fee_cap: 100_000,
    }
}

fn request(txs: Vec<Vec<u8>>, mode: SolTxMode) -> SolTxRequest {
    SolTxRequest {
        id: ApprovalId([5; 16]),
        origin: BrowserOrigin::parse("https://dapp.example").unwrap(),
        cluster: CLUSTER,
        source: SolKeySource::Standard(AccountIndex::ZERO),
        public: wallet().to_bytes(),
        label: "계정 1".to_owned(),
        mode,
        options: SolSendOptions::default(),
        txs,
    }
}

/// One sign-only transaction with default facts.
fn draft_of(tx: Vec<u8>, item: SolTxItemFacts) -> ApprovalDraft {
    build_sol_tx_request(&request(vec![tx], SolTxMode::SignOnly), &facts(vec![item])).unwrap()
}

fn rules(draft: &ApprovalDraft) -> Vec<RuleId> {
    draft.display.warnings.iter().map(|w| w.rule).collect()
}

fn text_of(draft: &ApprovalDraft, rule: RuleId) -> String {
    draft
        .display
        .warnings
        .iter()
        .find(|warning| warning.rule == rule)
        .map(|warning| warning.text.clone())
        .unwrap_or_default()
}

fn field(draft: &ApprovalDraft, key: FieldKey) -> String {
    draft
        .display
        .fields
        .iter()
        .find(|field| field.key == key)
        .map(|field| field.value.clone())
        .unwrap_or_default()
}

fn payload(draft: &ApprovalDraft) -> &SolTxPayload {
    match &draft.payload {
        SigningPayload::SolTx(payload) => payload,
        other => unreachable!("not a SolTx payload: {other:?}"),
    }
}

fn issue_and_consume(draft: ApprovalDraft) -> Result<Approved, ApprovalError> {
    let mut store = ApprovalStore::new();
    let request = store.issue(draft, 1_000, 1_790_000_000_000)?;
    store.consume(request.id, request.digest, 2_000)
}

// ----- rules ---------------------------------------------------------------------------------

#[test]
fn rule_table_levels() {
    use RiskLevel::{Blocked, Caution, High, Info};
    for (rule, level) in [
        (X01, Blocked),
        (X02, High),
        (X03, High),
        (X04, High),
        (X05, High),
        (X06, High),
        (X07, High),
        (X08, High),
        (X09, High),
        (X10, Caution),
        (X11, Caution),
        (X12, Caution),
        (X13, Info),
        (X14, High),
        (X15, High),
        (X16, High),
        (X17, High),
        (X18, Caution),
        (X19, Caution),
        (X20, High),
    ] {
        assert_eq!(level_of(rule), Some(level), "{rule:?}");
        assert_eq!(rule.family(), b'X');
    }
    assert!(is_simulation_status(X09) && !is_simulation_status(X02));
}

#[test]
fn plain_transfer_is_a_caution_sign_only_request() {
    let draft = draft_of(wire(&transfer_message(), &[]), ok_facts());
    assert_eq!(draft.kind, ApprovalKind::SolTransaction);
    assert_eq!(draft.simulation, SimulationBinding::NotApplicable);
    assert_eq!(draft.signer, Signer::FromPayload);
    assert_eq!(rules(&draft), vec![X11]);
    assert_eq!(draft.display.risk, RiskLevel::Caution);
    assert_eq!(
        draft.display.title,
        "[Solana devnet (테스트)] 사이트 거래 서명"
    );
    assert!(field(&draft, FieldKey::SOL_TX_SUMMARY).starts_with("서명만"));
    assert!(field(&draft, FieldKey::SOL_TX_CHANGES).contains(
        "내 지갑 SOL -0.000006000 SOL (1,000,000,000 → 999,994,000 lamports, 수수료 포함)"
    ));
    assert!(field(&draft, FieldKey::SOL_TX_INSTRUCTIONS).contains("System: SOL 보내기 (Transfer)"));
    assert!(field(&draft, FieldKey::SOL_TX_FEE).contains("수수료 지불: 내 지갑"));
    assert!(field(&draft, FieldKey::SOL_TX_VALIDITY).starts_with("블록해시 유효 확인됨"));
    assert!(field(&draft, FieldKey::SOL_TX_LOOKUPS).contains("legacy"));
    // A plain transfer is consumable.
    assert!(issue_and_consume(draft).is_ok());
}

/// A wallet-paid transaction with one instruction of `program` over `accounts` (indices into
/// `[wallet, 0x22…, program, extra…]`).
fn one_ix(program: SolAddress, extra: &[SolAddress], accounts: &[u8], data: &[u8]) -> Vec<u8> {
    let mut keys = vec![wallet(), key(0x22)];
    keys.extend_from_slice(extra);
    keys.push(program);
    let program_index = u8::try_from(keys.len() - 1).unwrap();
    let readonly = u8::try_from(1 + extra.len()).unwrap();
    wire(
        &legacy(
            [1, 0, readonly],
            &keys,
            vec![ix(program_index, accounts, data)],
        ),
        &[],
    )
}

#[test]
fn unknown_programs_are_high_and_approvable() {
    let program = key(0x77);
    let draft = draft_of(one_ix(program, &[], &[1], &[9, 9]), ok_facts());
    assert_eq!(rules(&draft), vec![X02, X11]);
    assert_eq!(draft.display.risk, RiskLevel::High);
    assert!(text_of(&draft, X02).contains(&program.to_base58()));
    let instructions = field(&draft, FieldKey::SOL_TX_INSTRUCTIONS);
    assert!(instructions.contains("알 수 없는 프로그램: 해석하지 않음"));
    assert!(instructions.contains("데이터 2바이트\n0x0909"));
    assert!(issue_and_consume(draft).is_ok());
    // The wallet passed to it adds X03.
    let draft = draft_of(one_ix(program, &[], &[0, 1], &[]), ok_facts());
    assert_eq!(rules(&draft), vec![X02, X03, X11]);
    // A known but undecoded program shows its name, still X02.
    let stake = crate::sol::address::STAKE_PROGRAM;
    let draft = draft_of(one_ix(stake, &[], &[1], &[2, 0, 0, 0]), ok_facts());
    assert!(text_of(&draft, X02).contains("Stake 프로그램"));
    // A decoded precompile is not X02; its signature is part of the fee (5,000 + 5,000).
    let mut data = vec![1, 0];
    data.extend_from_slice(&[0; 14]);
    let item = SolTxItemFacts {
        rpc_fee: Some(10_000),
        ..ok_facts()
    };
    let draft = draft_of(one_ix(ED25519_PRECOMPILE, &[], &[], &data), item);
    assert_eq!(rules(&draft), vec![X11]);
}

#[test]
fn ata_mismatch_and_token_2022_extensions_are_x02() {
    let mint = key(0x55);
    let ata = crate::sol::pda::associated_token_address(&wallet(), &TOKEN_PROGRAM, &mint)
        .unwrap()
        .0;
    // keys: wallet, wrong ATA (0x22), mint, system, token, ATA program.
    let keys = [
        wallet(),
        key(0x22),
        mint,
        SYSTEM_PROGRAM,
        TOKEN_PROGRAM,
        ATA_PROGRAM,
    ];
    let bad = wire(
        &legacy([1, 0, 4], &keys, vec![ix(5, &[0, 1, 0, 2, 3, 4], &[1])]),
        &[],
    );
    let draft = draft_of(bad, ok_facts());
    assert!(text_of(&draft, X02).contains(ATA_MISMATCH));
    assert_ne!(draft.display.risk, RiskLevel::Blocked);
    let keys = [
        wallet(),
        ata,
        mint,
        SYSTEM_PROGRAM,
        TOKEN_PROGRAM,
        ATA_PROGRAM,
    ];
    let good = wire(
        &legacy([1, 0, 4], &keys, vec![ix(5, &[0, 1, 0, 2, 3, 4], &[1])]),
        &[],
    );
    let draft = draft_of(good, ok_facts());
    assert_eq!(rules(&draft), vec![X11]);
    assert!(field(&draft, FieldKey::SOL_TX_INSTRUCTIONS).contains("CreateIdempotent"));
    // Token-2022 extension 26 over our wallet: X02 with its cause and X03.
    let draft = draft_of(
        one_ix(TOKEN_2022_PROGRAM, &[], &[1, 0], &[26, 1]),
        ok_facts(),
    );
    assert!(text_of(&draft, X02).contains("Token-2022 확장 명령 26"));
    assert!(rules(&draft).contains(&X03));
}

#[test]
fn wallet_permission_rules() {
    // Approve of our token account (0x22 owned by the wallet in the pre-state).
    let mint = key(0x55);
    let mut owned = ok_facts();
    owned.pre.push((
        key(0x22),
        Some(snapshot(
            TOKEN_PROGRAM,
            2_039_280,
            token_account(mint, wallet(), 50, None, None),
        )),
    ));
    let mut approve = vec![4];
    approve.extend_from_slice(&7_u64.to_le_bytes());
    let delegate = key(0x33);
    let draft = draft_of(
        one_ix(TOKEN_PROGRAM, &[delegate], &[1, 2, 0], &approve),
        owned.clone(),
    );
    assert!(rules(&draft).contains(&X04));
    let instructions = field(&draft, FieldKey::SOL_TX_INSTRUCTIONS);
    assert!(instructions.contains("[내 토큰 계정]"), "{instructions}");
    assert!(
        instructions.contains("위임 한도 7 (원시 단위)"),
        "{instructions}"
    );
    // SetAuthority by the wallet.
    let mut set = vec![6, 2, 1];
    set.extend_from_slice(delegate.as_bytes());
    let draft = draft_of(one_ix(TOKEN_PROGRAM, &[], &[1, 0], &set), owned.clone());
    assert!(text_of(&draft, X05).contains("토큰 계정 소유자(AccountOwner)"));
    // Assign of the wallet account.
    let mut assign = 1_u32.to_le_bytes().to_vec();
    assign.extend_from_slice(key(0x77).as_bytes());
    let draft = draft_of(one_ix(SYSTEM_PROGRAM, &[], &[0], &assign), ok_facts());
    assert!(rules(&draft).contains(&X06));
    // CloseAccount of our token account to someone else (X07), to the wallet (no X07).
    let draft = draft_of(
        one_ix(TOKEN_PROGRAM, &[delegate], &[1, 2, 0], &[9]),
        owned.clone(),
    );
    assert!(rules(&draft).contains(&X07));
    let to_wallet = draft_of(one_ix(TOKEN_PROGRAM, &[], &[1, 0, 0], &[9]), owned);
    assert!(!rules(&to_wallet).contains(&X07));
}

/// `AdvanceNonceAccount` first: nonce `0x44…` (writable), recent blockhashes, the wallet.
pub(super) fn nonce_message(extra: Vec<CompiledIx>) -> Vec<u8> {
    let mut instructions = vec![ix(3, &[1, 2, 0], &[4, 0, 0, 0])];
    instructions.extend(extra);
    legacy(
        [1, 0, 2],
        &[
            wallet(),
            key(0x44),
            SYSVAR_RECENT_BLOCKHASHES,
            SYSTEM_PROGRAM,
        ],
        instructions,
    )
}

#[test]
fn durable_nonce_simulation_fee_and_runtime_rules() {
    let mut item = ok_facts();
    item.blockhash_valid = None;
    let draft = draft_of(wire(&nonce_message(Vec::new()), &[]), item);
    assert!(rules(&draft).contains(&X08));
    assert!(field(&draft, FieldKey::SOL_TX_VALIDITY).starts_with("durable nonce — 만료 없음"));
    // Failed and absent simulations.
    for sim in [
        SimSummary::Failed {
            err: crate::sol::broadcast::err::SYSTEM_INSTRUCTION,
            units: None,
        },
        SimSummary::NoResult,
    ] {
        let item = SolTxItemFacts {
            sim,
            post: None,
            ..ok_facts()
        };
        let draft = draft_of(wire(&transfer_message(), &[]), item);
        assert!(rules(&draft).contains(&X09));
        assert_eq!(
            draft.display.warnings[0].rule, X09,
            "simulation status first"
        );
        assert!(field(&draft, FieldKey::SOL_TX_CHANGES).contains("시뮬레이션 결과가 없어"));
    }
    // Replaced blockhash.
    let item = SolTxItemFacts {
        sim_replaced_blockhash: true,
        ..ok_facts()
    };
    assert!(rules(&draft_of(wire(&transfer_message(), &[]), item)).contains(&X19));
    // Fee over the cap: only when the wallet pays.
    let item = SolTxItemFacts {
        rpc_fee: Some(200_000),
        ..ok_facts()
    };
    let draft = draft_of(wire(&transfer_message(), &[]), item.clone());
    assert!(text_of(&draft, X14).contains("200,000 lamports > 상한 100,000 lamports"));
    // 200,000 is not the 5,000 the message costs either.
    assert!(text_of(&draft, X20).contains("RPC 200,000 lamports · 계산값 5,000 lamports"));
    let foreign = legacy(
        [2, 0, 1],
        &[site_address(), wallet(), SYSTEM_PROGRAM],
        vec![ix(2, &[1, 0], &system_transfer_data(1))],
    );
    let draft = draft_of(wire(&foreign, &[]), item);
    assert!(!rules(&draft).contains(&X14) && !rules(&draft).contains(&X20));
    assert!(rules(&draft).contains(&X13));
    assert!(field(&draft, FieldKey::SOL_TX_FEE).contains("수수료 지불: 다른 계정"));
    // Without an RPC fee only the computed fee is shown.
    let item = SolTxItemFacts {
        rpc_fee: None,
        ..ok_facts()
    };
    let draft = draft_of(wire(&transfer_message(), &[]), item);
    assert!(field(&draft, FieldKey::SOL_TX_FEE).starts_with(
        "RPC가 답하지 않음 (getFeeForMessage)
계산값 5,000 lamports"
    ));
    assert!(!rules(&draft).contains(&X20));
    // Duplicate ComputeBudget.
    let keys = [wallet(), key(0x22), COMPUTE_BUDGET_PROGRAM];
    let cb = set_compute_unit_limit_data(1_000);
    let duplicate = legacy([1, 0, 2], &keys, vec![ix(2, &[], &cb), ix(2, &[], &cb)]);
    assert!(rules(&draft_of(wire(&duplicate, &[]), ok_facts())).contains(&X18));
}

#[test]
fn fee_is_computed_from_the_message_and_checks_the_rpc() {
    let keys = [wallet(), key(0x22), COMPUTE_BUDGET_PROGRAM, SYSTEM_PROGRAM];
    let price = |micro| ix(2, &[], &set_compute_unit_price_data(micro));
    let limit = |units| ix(2, &[], &set_compute_unit_limit_data(units));
    let transfer = || ix(3, &[0, 1], &system_transfer_data(1_000));
    let with_rpc = |rpc_fee| SolTxItemFacts {
        rpc_fee,
        ..ok_facts()
    };
    // An RPC that answers only the base fee of an expensive transaction (or under-reports on
    // purpose) no longer hides X14: the computed fee is the floor, and the mismatch is X20.
    let expensive = wire(
        &legacy(
            [1, 0, 2],
            &keys,
            vec![limit(200_000), price(1_000_000_000), transfer()],
        ),
        &[],
    );
    let draft = draft_of(expensive.clone(), with_rpc(Some(5_000)));
    assert!(text_of(&draft, X14).contains("200,005,000 lamports > 상한 100,000 lamports"));
    assert!(text_of(&draft, X20).contains("RPC 5,000 lamports · 계산값 200,005,000 lamports"));
    assert_eq!(draft.display.risk, RiskLevel::High);
    let fee = field(&draft, FieldKey::SOL_TX_FEE);
    assert!(
        fee.starts_with(
            "5,000 lamports (RPC getFeeForMessage)\n계산값 200,005,000 lamports (거래 바이트로 계산)\n수수료 지불: 내 지갑"
        ),
        "{fee}"
    );
    // The exact RPC value, or none: X14 only.
    for rpc in [Some(200_005_000), None] {
        let found = rules(&draft_of(expensive.clone(), with_rpc(rpc)));
        assert!(found.contains(&X14) && !found.contains(&X20), "{rpc:?}");
    }
    // An honest priority-fee transfer without a limit: two builtins × 3,000 CU at 1,000,000
    // micro-lamports = 6,000, so 11,000 in all — no false X14 (the old estimate said 205,000).
    let honest = wire(
        &legacy([1, 0, 2], &keys, vec![price(1_000_000), transfer()]),
        &[],
    );
    for rpc in [Some(11_000), None] {
        assert_eq!(
            rules(&draft_of(honest.clone(), with_rpc(rpc))),
            vec![X11],
            "{rpc:?}"
        );
    }
    // Above the computed maximum is X20 as well.
    let draft = draft_of(honest, with_rpc(Some(11_001)));
    assert_eq!(rules(&draft), vec![X20, X11]);
    assert!(text_of(&draft, X20).contains("RPC 11,001 lamports · 계산값 11,000 lamports"));
    // Without a limit a migrating builtin (Stake) is bracketed: 3,000 or 200,000 CU.
    let stake = wire(
        &legacy(
            [1, 0, 2],
            &[
                wallet(),
                key(0x22),
                COMPUTE_BUDGET_PROGRAM,
                crate::sol::address::STAKE_PROGRAM,
            ],
            vec![price(1_000_000), ix(3, &[1], &[2, 0, 0, 0])],
        ),
        &[],
    );
    let draft = draft_of(stake.clone(), with_rpc(Some(100_000)));
    assert!(!rules(&draft).contains(&X20) && !rules(&draft).contains(&X14));
    assert!(
        field(&draft, FieldKey::SOL_TX_FEE)
            .contains("계산값 11,000–208,000 lamports (CU 한도가 없어 범위로 계산)")
    );
    let draft = draft_of(stake, with_rpc(Some(10_999)));
    assert!(text_of(&draft, X20).contains("RPC 10,999 lamports · 계산값 11,000–208,000 lamports"));
    // The wallet does not pay: neither X14 nor X20, whatever the RPC says.
    let foreign = wire(
        &legacy(
            [2, 0, 2],
            &[
                site_address(),
                wallet(),
                COMPUTE_BUDGET_PROGRAM,
                SYSTEM_PROGRAM,
            ],
            vec![
                limit(200_000),
                price(1_000_000_000),
                ix(3, &[1, 0], &system_transfer_data(1)),
            ],
        ),
        &[],
    );
    let draft = draft_of(foreign, with_rpc(Some(5_000)));
    let found = rules(&draft);
    assert!(found.contains(&X13) && !found.contains(&X14) && !found.contains(&X20));
    assert!(field(&draft, FieldKey::SOL_TX_FEE).contains("계산값 200,010,000 lamports"));
}

#[test]
fn site_signatures_and_foreign_fee_payer() {
    // The site pays and signed first; we are slot 1.
    let message = legacy(
        [2, 0, 1],
        &[site_address(), wallet(), SYSTEM_PROGRAM],
        vec![ix(2, &[1, 0], &system_transfer_data(1))],
    );
    let signed = wire(&message, &[(0, &site_key())]);
    let draft = draft_of(signed.clone(), ok_facts());
    assert_eq!(rules(&draft), vec![X11, X13]);
    assert_eq!(payload(&draft).items[0].signer_slot, 1);
    let signers = field(&draft, FieldKey::SOL_TX_SIGNERS);
    assert!(signers.contains("서명자 1 · 수수료 지불"));
    assert!(signers.contains("사이트가 넣은 서명 (확인됨)"));
    assert!(signers.contains("지갑이 서명합니다"));
    // The site pays the fee: the wallet's SOL change does not include it.
    let changes = field(&draft, FieldKey::SOL_TX_CHANGES);
    assert!(changes.contains("내 지갑 SOL "), "{changes}");
    assert!(!changes.contains("수수료 포함"), "{changes}");
    // The wallet only signs read-only (an authority): not in the pre-state, so its watched
    // balance is no change rather than a gain from 0.
    let readonly = legacy(
        [2, 1, 1],
        &[site_address(), wallet(), SYSTEM_PROGRAM],
        vec![ix(2, &[0, 0], &system_transfer_data(1))],
    );
    let mut item = ok_facts();
    item.pre = vec![(
        site_address(),
        Some(snapshot(SYSTEM_PROGRAM, 1_000_000_000, Vec::new())),
    )];
    let draft = draft_of(wire(&readonly, &[(0, &site_key())]), item);
    assert_eq!(
        field(&draft, FieldKey::SOL_TX_CHANGES),
        "지켜본 계정(내 지갑·내 토큰 계정·새 계정)에 변화 없음"
    );
    // A broken site signature is X01: shown, never approvable.
    let mut broken = signed;
    broken[5] ^= 1;
    let draft = draft_of(broken, ok_facts());
    assert_eq!(draft.display.risk, RiskLevel::Blocked);
    assert!(text_of(&draft, X01).contains("사이트가 넣은 서명이 맞지 않습니다"));
    assert_eq!(
        issue_and_consume(draft).unwrap_err(),
        ApprovalError::Blocked
    );
}

#[test]
fn runtime_demotion_is_the_runtime_rule() {
    // Writable keys: a non-sysvar whose base58 starts with "Sysvar", the Clock sysvar, the
    // Token program (not invoked) and a program `0x77…` that instruction 0 calls.
    let vanity = SolAddress::parse("SysvarRent111111111111111111111111111111112").unwrap();
    assert!(vanity.to_base58().starts_with("Sysvar") && vanity != SYSVAR_RENT);
    let program = key(0x77);
    let demoted = |extra: &[SolAddress]| {
        let mut keys = vec![wallet(), vanity, SYSVAR_CLOCK, TOKEN_PROGRAM, program];
        keys.extend_from_slice(extra);
        let tx = wire(&legacy([1, 0, 0], &keys, vec![ix(4, &[0], &[])]), &[]);
        let writable = field(&draft_of(tx, ok_facts()), FieldKey::SOL_TX_WRITABLE);
        let lines: Vec<&str> = writable.lines().collect();
        keys.iter()
            .filter(|address| {
                let at = lines
                    .iter()
                    .position(|line| *line == grouped(address))
                    .unwrap();
                lines.get(at + 2) == Some(&"(런타임에서 읽기 전용)")
            })
            .copied()
            .collect::<Vec<_>>()
    };
    assert_eq!(demoted(&[]), vec![SYSVAR_CLOCK, program]);
    // With the BPF Upgradeable Loader among the keys a called program stays writable; the
    // loader itself is a reserved key.
    assert_eq!(
        demoted(&[BPF_LOADER_UPGRADEABLE]),
        vec![SYSVAR_CLOCK, BPF_LOADER_UPGRADEABLE]
    );
}

/// A v0 transaction with one table `0xa1…` loading writable index 0 (`0x30…`) and read-only
/// index 1 (`0x31…`).
pub(super) fn v0_tx() -> Vec<u8> {
    let message = message(
        SolTxVersion::V0,
        [1, 0, 1],
        &[wallet(), MEMO_PROGRAM_V2],
        vec![ix(1, &[0, 2, 3], b"gm")],
        vec![LookupRef {
            table: key(0xa1),
            writable: vec![0],
            readonly: vec![1],
        }],
    );
    wire(&message, &[])
}

fn table(deactivation_slot: u64) -> LookupTable {
    LookupTable {
        deactivation_slot,
        last_extended_slot: 5,
        last_extended_start: 0,
        authority: None,
        addresses: vec![key(0x30), key(0x31)],
    }
}

#[test]
fn lookup_tables_resolve_or_block_one_transaction() {
    let item = SolTxItemFacts {
        tables: Ok((10, vec![(key(0xa1), table(u64::MAX))])),
        ..ok_facts()
    };
    let draft = draft_of(v0_tx(), item);
    assert_eq!(rules(&draft), vec![X10, X11]);
    assert_eq!(
        payload(&draft).items[0].loaded,
        Some(ResolvedKeys {
            writable: vec![key(0x30)],
            readonly: vec![key(0x31)],
        })
    );
    let lookups = field(&draft, FieldKey::SOL_TX_LOOKUPS);
    assert!(lookups.contains(&format!("테이블 1\n{}", grouped(&key(0xa1)))));
    assert!(lookups.contains(&format!(
        "쓰기 · 인덱스 0\n{}\n[쓰기] [테이블 1]",
        grouped(&key(0x30))
    )));
    assert!(field(&draft, FieldKey::SOL_TX_WRITABLE).contains(&grouped(&key(0x30))));
    // A deactivated table resolves with a cause line.
    let item = SolTxItemFacts {
        tables: Ok((10, vec![(key(0xa1), table(9))])),
        ..ok_facts()
    };
    let draft = draft_of(v0_tx(), item);
    assert!(text_of(&draft, X10).contains("비활성화된 테이블"));
    // In a batch, a missing table blocks the request but the window still opens; the other
    // transaction keeps its own data.
    let request = request(
        vec![wire(&transfer_message(), &[]), v0_tx()],
        SolTxMode::SignOnly,
    );
    let missing = SolTxItemFacts {
        tables: Err(AltError::Missing(key(0xa1))),
        ..ok_facts()
    };
    let draft = build_sol_tx_request(&request, &facts(vec![ok_facts(), missing])).unwrap();
    assert_eq!(draft.display.risk, RiskLevel::Blocked);
    assert!(
        text_of(&draft, X01)
            .starts_with("Solana 거래에 서명할 수 없습니다\n거래 2: 조회 테이블이 없습니다")
    );
    assert_eq!(payload(&draft).items[1].loaded, None);
    assert_eq!(
        payload(&draft).items[0].loaded,
        Some(ResolvedKeys::default())
    );
    assert!(draft.display.title.ends_with("사이트 거래 2건 서명"));
    assert_eq!(
        issue_and_consume(draft).unwrap_err(),
        ApprovalError::Blocked
    );
}

#[test]
fn mints_lookalikes_and_simulated_authority_changes() {
    let mint = key(0x55);
    let mut item = ok_facts();
    item.pre.push((
        key(0x22),
        Some(snapshot(
            TOKEN_2022_PROGRAM,
            2_039_280,
            token_account(mint, wallet(), 50, None, None),
        )),
    ));
    // The simulation sets a delegate on our token account.
    let mut post = item.post.clone().unwrap();
    post.push((
        key(0x22),
        Some(snapshot(
            TOKEN_2022_PROGRAM,
            2_039_280,
            token_account(mint, wallet(), 50, Some(key(0x33)), None),
        )),
    ));
    item.post = Some(post);
    let mut all = facts(vec![item]);
    all.mints = vec![(
        mint,
        MintView {
            decimals: 6,
            extensions: vec![1, 12, 14],
        },
    )];
    // A known address one byte away from `0x22…` (same leading base58 characters).
    let mut near = [0x22; 32];
    near[31] = 0x23;
    all.known = vec![KnownAddress {
        address: SolAddress::from_bytes(near),
        label: "친구".to_owned(),
        kind: KnownKind::Book { verified: false },
    }];
    let tx = wire(&transfer_message(), &[]);
    let draft = build_sol_tx_request(&request(vec![tx], SolTxMode::SignOnly), &all).unwrap();
    let found = rules(&draft);
    for rule in [X12, X15, X16, X17] {
        assert!(found.contains(&rule), "{rule:?} missing in {found:?}");
    }
    let changes = field(&draft, FieldKey::SOL_TX_CHANGES);
    assert!(
        changes.starts_with("권한 변화: 토큰 계정 위임자"),
        "{changes}"
    );
    assert!(changes.contains(&format!("이후\n{}", grouped(&key(0x33)))));
    let writable = field(&draft, FieldKey::SOL_TX_WRITABLE);
    assert!(
        writable.contains("[내 토큰 계정] [비슷한 주소 주의]"),
        "{writable}"
    );
}

#[test]
fn an_unread_token_2022_mint_is_treated_as_having_every_extension() {
    // The wallet's Token-2022 account holds a mint the app could not read (over 16 KiB or not
    // parsing): X17 and X12 as if it had a permanent delegate, a hook and a fee.
    let mint = key(0x56);
    let mut item = ok_facts();
    item.pre.push((
        key(0x22),
        Some(snapshot(
            TOKEN_2022_PROGRAM,
            2_039_280,
            token_account(mint, wallet(), 50, None, None),
        )),
    ));
    let tx = wire(&transfer_message(), &[]);
    let draft = draft_of(tx.clone(), item.clone());
    assert!(!rules(&draft).contains(&X17), "{:?}", rules(&draft));
    let mut all = facts(vec![item]);
    all.unread_mints = vec![mint];
    let draft = build_sol_tx_request(&request(vec![tx], SolTxMode::SignOnly), &all).unwrap();
    let found = rules(&draft);
    for rule in [X12, X17] {
        assert!(found.contains(&rule), "{rule:?} missing in {found:?}");
        assert!(
            text_of(&draft, rule).contains(&format!(
                "mint {} · 확장을 읽지 못했습니다",
                mint.to_base58()
            )),
            "{}",
            text_of(&draft, rule)
        );
    }
    assert_eq!(draft.display.risk, RiskLevel::High);
}

#[test]
fn rules_are_one_warning_each_in_a_batch() {
    let program = key(0x77);
    let txs: Vec<Vec<u8>> = (0..5).map(|_| one_ix(program, &[], &[0], &[1])).collect();
    let request = request(txs, SolTxMode::SignOnly);
    let draft = build_sol_tx_request(&request, &facts(vec![ok_facts(); 5])).unwrap();
    assert_eq!(rules(&draft), vec![X02, X03, X11]);
    let x02 = text_of(&draft, X02);
    assert_eq!(x02.lines().count(), 1 + 5, "{x02}");
    assert!(x02.contains("거래 5 명령 1: 프로그램"));
    assert!(draft.display.warnings.len() <= 19);
}

// ----- payload, digest, check_draft ------------------------------------------------------------

type Mutation = Box<dyn Fn(&mut SolTxPayload)>;

#[test]
fn every_payload_field_changes_the_digest() {
    let base = SolTxPayload {
        source: SolKeySource::Standard(AccountIndex::ZERO),
        public: wallet().to_bytes(),
        mode: SolTxMode::SignOnly,
        options: SolSendOptions::default(),
        items: vec![SolTxItem {
            wire: v0_tx(),
            signer_slot: 0,
            loaded: Some(ResolvedKeys {
                writable: vec![key(0x30)],
                readonly: vec![key(0x31)],
            }),
        }],
    };
    let digest = base.digest_bytes();
    let mutations: Vec<Mutation> = vec![
        Box::new(|p| p.source = SolKeySource::Standard(AccountIndex::new(1).unwrap())),
        Box::new(|p| p.source = SolKeySource::Imported),
        Box::new(|p| {
            p.source = SolKeySource::Mnemonic(
                crate::vault::RecordId::from_bytes([9; 16]),
                AccountIndex::ZERO,
            );
        }),
        Box::new(|p| p.public = [1; 32]),
        Box::new(|p| p.mode = SolTxMode::SignAndSend),
        Box::new(|p| p.options.skip_preflight = true),
        Box::new(|p| p.options.preflight_commitment = Some(SolCommitment::Confirmed)),
        Box::new(|p| p.options.min_context_slot = Some(0)),
        Box::new(|p| p.items.push(p.items[0].clone())),
        Box::new(|p| *p.items[0].wire.last_mut().unwrap() ^= 1),
        Box::new(|p| p.items[0].signer_slot = 1),
        Box::new(|p| p.items[0].loaded = None),
        Box::new(|p| p.items[0].loaded.as_mut().unwrap().writable[0] = key(0x32)),
        Box::new(|p| p.items[0].loaded.as_mut().unwrap().readonly[0] = key(0x32)),
        Box::new(|p| {
            let loaded = p.items[0].loaded.as_mut().unwrap();
            core::mem::swap(&mut loaded.writable, &mut loaded.readonly);
        }),
    ];
    for (index, mutate) in mutations.iter().enumerate() {
        let mut changed = base.clone();
        mutate(&mut changed);
        assert_ne!(changed.digest_bytes(), digest, "mutation {index}");
    }
    // Two mnemonic record ids differ; the intent hash binds the approval id.
    let mnemonic = |id: u8| SolTxPayload {
        source: SolKeySource::Mnemonic(
            crate::vault::RecordId::from_bytes([id; 16]),
            AccountIndex::ZERO,
        ),
        ..base.clone()
    };
    assert_ne!(mnemonic(1).digest_bytes(), mnemonic(2).digest_bytes());
    assert_ne!(base.intent_hash(&[1; 16]), base.intent_hash(&[2; 16]));
    assert_eq!(base.intent_hash(&[1; 16]), base.intent_hash(&[1; 16]));
}

fn issue(draft: ApprovalDraft) -> Result<(), ApprovalError> {
    ApprovalStore::new().issue(draft, 0, 0).map(|_| ())
}

#[test]
#[expect(clippy::too_many_lines, reason = "one refusal per check_draft rule")]
fn check_draft_rules() {
    let good = draft_of(wire(&transfer_message(), &[]), ok_facts());
    assert_eq!(issue(good.clone()), Ok(()));
    let mismatch = Err(ApprovalError::PayloadMismatch);
    let with = |mutate: &dyn Fn(&mut ApprovalDraft)| {
        let mut draft = good.clone();
        mutate(&mut draft);
        issue(draft)
    };
    let with_payload = |mutate: &dyn Fn(&mut SolTxPayload)| {
        with(&|draft| {
            if let SigningPayload::SolTx(payload) = &mut draft.payload {
                mutate(payload);
            }
        })
    };
    assert_eq!(with(&|d| d.origin = ApprovalOrigin::App), mismatch);
    assert_eq!(with(&|d| d.account = AccountRef::Sol([9; 32])), mismatch);
    assert_eq!(
        with(&|d| {
            d.chain = ChainRef::Solana {
                cluster: SolCluster::Devnet,
                genesis: SolCluster::Mainnet.genesis(),
            };
        }),
        mismatch
    );
    assert_eq!(
        with(&|d| d.signer = Signer::Evm(crate::vault::EvmKeySource::Derived(AccountIndex::ZERO))),
        mismatch
    );
    assert_eq!(
        with(&|d| {
            d.simulation = SimulationBinding::None {
                reason: crate::approval::SimNoneReason::Transport,
            };
        }),
        Err(ApprovalError::SimulationBindingMismatch)
    );
    // Not a signer: the payload key is only the recipient.
    assert_eq!(
        with(&|d| {
            d.account = AccountRef::Sol(key(0x22).to_bytes());
            if let SigningPayload::SolTx(payload) = &mut d.payload {
                payload.public = key(0x22).to_bytes();
            }
        }),
        mismatch
    );
    assert_eq!(with_payload(&|p| p.items[0].signer_slot = 1), mismatch);
    assert_eq!(with_payload(&|p| p.items.clear()), mismatch);
    assert_eq!(
        with_payload(&|p| p.items = vec![p.items[0].clone(); 33]),
        mismatch
    );
    assert_eq!(
        with_payload(&|p| p.items = vec![p.items[0].clone(); 32]),
        Ok(())
    );
    assert_eq!(
        with_payload(&|p| p.source = SolKeySource::RawSeed),
        mismatch
    );
    // A legacy transaction must carry `Some(empty)`; counts must match the lookups.
    assert_eq!(with_payload(&|p| p.items[0].loaded = None), mismatch);
    assert_eq!(
        with_payload(&|p| {
            p.items[0].loaded = Some(ResolvedKeys {
                writable: vec![key(1)],
                readonly: Vec::new(),
            });
        }),
        mismatch
    );
    assert_eq!(with_payload(&|p| p.items[0].wire.truncate(10)), mismatch);
    // Sends: one transaction, fully signed by the others, no durable nonce.
    assert_eq!(with_payload(&|p| p.mode = SolTxMode::SignAndSend), Ok(()));
    assert_eq!(
        with_payload(&|p| {
            p.mode = SolTxMode::SignAndSend;
            p.items.push(p.items[0].clone());
        }),
        mismatch
    );
    let two_signers = legacy(
        [2, 0, 1],
        &[site_address(), wallet(), SYSTEM_PROGRAM],
        vec![ix(2, &[1, 0], &system_transfer_data(1))],
    );
    let unsigned = SolTxItem {
        wire: wire(&two_signers, &[]),
        signer_slot: 1,
        loaded: Some(ResolvedKeys::default()),
    };
    let signed = SolTxItem {
        wire: wire(&two_signers, &[(0, &site_key())]),
        ..unsigned.clone()
    };
    let nonce = SolTxItem {
        wire: wire(&nonce_message(Vec::new()), &[]),
        signer_slot: 0,
        loaded: Some(ResolvedKeys::default()),
    };
    for (item, expected) in [
        (unsigned.clone(), mismatch),
        (signed, Ok(())),
        (nonce.clone(), mismatch),
    ] {
        let send = with_payload(&|p| {
            p.mode = SolTxMode::SignAndSend;
            p.items = vec![item.clone()];
        });
        assert_eq!(send, expected);
        let sign_only = with_payload(&|p| p.items = vec![item.clone()]);
        assert_eq!(sign_only, Ok(()));
    }
    assert_eq!(
        SolTxPayload {
            mode: SolTxMode::SignAndSend,
            items: vec![unsigned],
            ..payload(&good).clone()
        }
        .validate(),
        Err(SolTxPayloadError::MissingSignature)
    );
    assert_eq!(
        SolTxPayload {
            mode: SolTxMode::SignAndSend,
            items: vec![nonce],
            ..payload(&good).clone()
        }
        .validate(),
        Err(SolTxPayloadError::DurableNonce)
    );
    // The kinds stay apart: a SolTx payload under the transfer or message kind, a message
    // payload under the transaction kind.
    assert_eq!(with(&|d| d.kind = ApprovalKind::SolTransfer), mismatch);
    assert_eq!(with(&|d| d.kind = ApprovalKind::SolMessage), mismatch);
    assert_eq!(
        with(&|d| {
            d.payload = SigningPayload::SolMessage(Box::new(crate::approval::SolMessagePayload {
                source: SolKeySource::Standard(AccountIndex::ZERO),
                public: wallet().to_bytes(),
                message: b"hi".to_vec(),
            }));
        }),
        mismatch
    );
}

// ----- display -------------------------------------------------------------------------------

#[test]
fn display_keys_bounds_whole_addresses_and_escaping() {
    for (raw, flags) in [
        (0x0510, (true, false)),
        (0x0511, (true, false)),
        (0x0512, (true, false)),
        (0x0513, (true, false)),
        (0x0514, (true, false)),
        (0x0515, (true, false)),
        (0x0516, (true, false)),
        (0x0517, (false, false)),
        (0x0518, (false, false)),
        (0x0519, (true, false)),
        (0x051A, (false, false)),
        (0x0540, (false, false)),
    ] {
        assert_eq!(FieldKey(raw).flags(), Some(flags), "{raw:#06x}");
    }
    // 32 transactions: 3 + 1 + 32 × 10 fields, one approval.
    let txs = vec![wire(&transfer_message(), &[]); 32];
    let draft = build_sol_tx_request(
        &request(txs, SolTxMode::SignOnly),
        &facts(vec![ok_facts(); 32]),
    )
    .unwrap();
    assert_eq!(draft.display.fields.len(), 324);
    assert!(draft.display.fields.len() <= 325);
    assert!(draft.display.title.len() <= crate::approval::MAX_TITLE_BYTES);
    assert_eq!(
        draft
            .display
            .fields
            .iter()
            .filter(|field| field.sub_label == "거래 32/32")
            .count(),
        10
    );
    assert!(issue(draft).is_ok());
    // 33 transactions are refused by the builder.
    let txs = vec![wire(&transfer_message(), &[]); 33];
    assert!(
        build_sol_tx_request(
            &request(txs, SolTxMode::SignOnly),
            &facts(vec![ok_facts(); 33])
        )
        .is_err()
    );
    // Every address of the transaction is drawn whole on a line of its own.
    let draft = draft_of(wire(&transfer_message(), &[]), ok_facts());
    for address in [wallet(), key(0x22)] {
        let whole = grouped(&address);
        let mut seen = false;
        for field in &draft.display.fields {
            for line in field.value.lines() {
                assert!(
                    !line.contains(&address.to_base58()),
                    "ungrouped address in {:?}: {line}",
                    field.key
                );
                seen |= line == whole;
            }
        }
        assert!(seen, "{whole} not drawn");
    }
    // Untrusted memo text is escaped (bidi, line feed).
    let memo = "hello\u{202E}\nworld";
    let tx = wire(
        &legacy(
            [1, 0, 1],
            &[wallet(), MEMO_PROGRAM_V2],
            vec![ix(1, &[0], memo.as_bytes())],
        ),
        &[],
    );
    let draft = draft_of(tx, ok_facts());
    let instructions = field(&draft, FieldKey::SOL_TX_INSTRUCTIONS);
    assert!(
        instructions.contains("메모: hello[U+202E][U+000A]world"),
        "{instructions}"
    );
    // The raw message and its SHA-256 are the exact message bytes.
    let message = transfer_message();
    let draft = draft_of(wire(&message, &[]), ok_facts());
    assert_eq!(
        field(&draft, FieldKey::SOL_TX_AUDIT),
        crate::hex::encode(&<sha2::Sha256 as sha2::Digest>::digest(&message))
    );
    assert!(field(&draft, FieldKey::SOL_TX_RAW).starts_with("0x0100"));
}

#[test]
fn send_requests_show_their_options() {
    let two_signers = legacy(
        [2, 0, 1],
        &[site_address(), wallet(), SYSTEM_PROGRAM],
        vec![ix(2, &[1, 0], &system_transfer_data(1))],
    );
    let mut send = request(
        vec![wire(&two_signers, &[(0, &site_key())])],
        SolTxMode::SignAndSend,
    );
    send.options = SolSendOptions {
        skip_preflight: true,
        preflight_commitment: Some(SolCommitment::Processed),
        min_context_slot: Some(1_234),
    };
    let draft = build_sol_tx_request(&send, &facts(vec![ok_facts()])).unwrap();
    assert_eq!(
        draft.display.title,
        "[Solana devnet (테스트)] 사이트 거래 서명 후 전송"
    );
    assert!(!rules(&draft).contains(&X11));
    let options = field(&draft, FieldKey::SOL_TX_SEND_OPTIONS);
    assert!(options.contains("생략 (skipPreflight)"));
    assert!(options.contains("minContextSlot: 1,234 (첫 전송만)"));
    assert_eq!(payload(&draft).options, send.options);
    assert_eq!(draft.display.fields.len(), 3 + 2 + 10);
    assert!(issue(draft).is_ok());
    // A send of an unsigned co-signer or a nonce transaction is X01 (and `check_draft` refuses
    // the payload as well); two transactions are not a send.
    send.txs = vec![wire(&two_signers, &[])];
    let draft = build_sol_tx_request(&send, &facts(vec![ok_facts()])).unwrap();
    assert!(text_of(&draft, X01).contains("전송하려면 다른 서명이 모두 있어야 합니다"));
    send.txs = vec![wire(&nonce_message(Vec::new()), &[])];
    let draft = build_sol_tx_request(&send, &facts(vec![ok_facts()])).unwrap();
    assert!(text_of(&draft, X01).contains("durable nonce 거래는 지갑이 전송하지 않습니다"));
    send.txs = vec![wire(&transfer_message(), &[]); 2];
    assert!(build_sol_tx_request(&send, &facts(vec![ok_facts(); 2])).is_err());
    // Bytes that do not parse, or a key that does not sign, are refused (the app checked first).
    let mut plain = request(vec![vec![1, 2, 3]], SolTxMode::SignOnly);
    assert!(build_sol_tx_request(&plain, &facts(vec![ok_facts()])).is_err());
    plain.txs = vec![wire(&transfer_message(), &[])];
    plain.public = key(0x22).to_bytes();
    assert!(build_sol_tx_request(&plain, &facts(vec![ok_facts()])).is_err());
    // A recovery-scan source is X01 (and refused by `check_draft`).
    let mut scan = request(vec![wire(&transfer_message(), &[])], SolTxMode::SignOnly);
    scan.source = SolKeySource::RawSeed;
    let draft = build_sol_tx_request(&scan, &facts(vec![ok_facts()])).unwrap();
    assert!(rules(&draft).contains(&X01));
    assert_eq!(issue(draft), Err(ApprovalError::PayloadMismatch));
}

// ----- diff --------------------------------------------------------------------------------------

#[test]
fn watch_set_is_a_bounded_subset_of_the_transaction_keys() {
    let mint = key(0x55);
    let token = |owner: SolAddress, delegate: Option<SolAddress>| {
        Some(snapshot(
            TOKEN_PROGRAM,
            1,
            token_account(mint, owner, 1, delegate, None),
        ))
    };
    let pre = vec![
        (key(0x10), token(wallet(), None)),
        (key(0x11), token(key(0x99), Some(wallet()))),
        (key(0x12), token(key(0x99), None)),
        (key(0x13), None),
        (key(0x14), Some(snapshot(SYSTEM_PROGRAM, 1, Vec::new()))),
        (key(0x15), None),
    ];
    let keys = [
        wallet(),
        key(0x10),
        key(0x11),
        key(0x12),
        key(0x13),
        key(0x14),
    ];
    let writable = [
        key(0x10),
        key(0x11),
        key(0x12),
        key(0x13),
        key(0x14),
        key(0x15),
    ];
    assert_eq!(
        watch_set(&wallet(), &keys, &writable, &pre),
        vec![wallet(), key(0x10), key(0x11), key(0x13)]
    );
    // Capped at the number of keys and at 64.
    assert_eq!(watch_set(&wallet(), &keys[..2], &writable, &pre).len(), 2);
    let many: Vec<SolAddress> = (0..100_u8)
        .map(|byte| key(byte.wrapping_add(100)))
        .collect();
    let missing: Vec<(SolAddress, Option<AccountSnapshot>)> =
        many.iter().map(|address| (*address, None)).collect();
    assert_eq!(
        watch_set(&wallet(), &many, &many, &missing).len(),
        SOL_DAPP_MAX_WATCH
    );
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one pre/post pair per kind of change"
)]
fn changes_between_pre_and_post_state() {
    let usdc = spl_entries(CLUSTER).next().unwrap();
    let other_mint = key(0x56);
    let token = |program: SolAddress, mint, owner, amount, delegate| {
        Some(snapshot(
            program,
            2_039_280,
            token_account(mint, owner, amount, delegate, None),
        ))
    };
    let pre = vec![
        (wallet(), Some(snapshot(SYSTEM_PROGRAM, 10_000, Vec::new()))),
        (
            key(0x10),
            token(TOKEN_PROGRAM, usdc.mint, wallet(), 1_500_000, None),
        ),
        (
            key(0x11),
            token(TOKEN_2022_PROGRAM, other_mint, wallet(), 5, None),
        ),
        (
            key(0x12),
            token(TOKEN_PROGRAM, usdc.mint, wallet(), 1, None),
        ),
        (key(0x13), None),
    ];
    let post = vec![
        (wallet(), Some(snapshot(SYSTEM_PROGRAM, 4_000, Vec::new()))),
        (
            key(0x10),
            token(TOKEN_PROGRAM, usdc.mint, wallet(), 500_000, None),
        ),
        (
            key(0x11),
            token(
                TOKEN_2022_PROGRAM,
                other_mint,
                key(0x99),
                5,
                Some(key(0x98)),
            ),
        ),
        (key(0x12), None),
        (
            key(0x13),
            token(TOKEN_PROGRAM, usdc.mint, wallet(), 0, None),
        ),
    ];
    let mints = [(
        other_mint,
        MintView {
            decimals: 2,
            extensions: Vec::new(),
        },
    )];
    let found = changes(&wallet(), CLUSTER, &pre, &post, &mints);
    assert_eq!(
        found,
        vec![
            Change::Authority {
                account: key(0x11),
                what: AuthorityKind::Owner,
                before: Some(wallet()),
                after: Some(key(0x99)),
            },
            Change::Authority {
                account: key(0x11),
                what: AuthorityKind::Delegate,
                before: None,
                after: Some(key(0x98)),
            },
            Change::Sol {
                pre: 10_000,
                post: 4_000
            },
            Change::Token {
                account: key(0x10),
                mint: usdc.mint,
                program2022: false,
                pre: 1_500_000,
                post: 500_000,
                decimals: Some((usdc.decimals, true)),
            },
            Change::Closed { account: key(0x12) },
            Change::Created {
                account: key(0x13),
                mint: Some(usdc.mint),
            },
        ]
    );
    // The wallet's owner program changing is an authority change too.
    let assigned = vec![(wallet(), Some(snapshot(key(0x77), 10_000, Vec::new())))];
    assert_eq!(
        changes(&wallet(), CLUSTER, &pre[..1], &assigned, &[]),
        vec![Change::Authority {
            account: wallet(),
            what: AuthorityKind::WalletOwnerProgram,
            before: Some(SYSTEM_PROGRAM),
            after: Some(key(0x77)),
        }]
    );
    // An account not listed in the pre-state is never "created".
    let unlisted = vec![(
        key(0x40),
        token(TOKEN_PROGRAM, usdc.mint, wallet(), 1, None),
    )];
    assert!(changes(&wallet(), CLUSTER, &pre, &unlisted, &[]).is_empty());
    // A wallet that signs read-only is watched but not in the pre-state: no made-up SOL gain
    // (its balance against 0) and no owner-program change.
    assert!(changes(&wallet(), CLUSTER, &pre[1..], &post[..1], &[]).is_empty());
    assert!(changes(&wallet(), CLUSTER, &pre[1..], &assigned, &[]).is_empty());
    // A wallet the pre-state lists as missing (no account yet) changes from 0.
    assert_eq!(
        changes(&wallet(), CLUSTER, &[(wallet(), None)], &post[..1], &[]),
        vec![Change::Sol {
            pre: 0,
            post: 4_000
        }]
    );
}

// ----- signing ---------------------------------------------------------------------------------

pub(super) fn approval(payload: SolTxPayload, kind: ApprovalKind) -> Approved {
    Approved::for_test(
        ChainRef::Solana {
            cluster: CLUSTER,
            genesis: CLUSTER.genesis(),
        },
        AccountRef::Sol(payload.public),
        Signer::FromPayload,
        kind,
        SigningPayload::SolTx(Box::new(payload)),
    )
}

fn sign_only(public: SolAddress, source: SolKeySource, txs: &[Vec<u8>]) -> SolTxPayload {
    SolTxPayload {
        source,
        public: public.to_bytes(),
        mode: SolTxMode::SignOnly,
        options: SolSendOptions::default(),
        items: txs
            .iter()
            .map(|tx| SolTxItem {
                wire: tx.clone(),
                signer_slot: parse_wire_tx(tx)
                    .unwrap()
                    .message
                    .signer_slot(public.as_bytes())
                    .unwrap(),
                loaded: Some(ResolvedKeys::default()),
            })
            .collect(),
    }
}

/// Only our slot changed, it verifies, and the message bytes are the approved ones.
pub(super) fn assert_only_our_slot(before: &[u8], after: &[u8], public: &SolAddress) {
    let old = parse_wire_tx(before).unwrap();
    let new = parse_wire_tx(after).unwrap();
    assert_eq!(old.message_bytes, new.message_bytes);
    assert_eq!(before.len(), after.len());
    let slot = usize::from(new.message.signer_slot(public.as_bytes()).unwrap());
    for (index, (a, b)) in old.signatures.iter().zip(&new.signatures).enumerate() {
        if index == slot {
            assert!(crate::sol::keys::verify_strict(
                public.as_bytes(),
                &new.message_bytes,
                b
            ));
        } else {
            assert_eq!(a, b, "slot {index} changed");
        }
    }
}

#[test]
fn sign_only_with_a_standard_key() {
    let vault = unlocked_with(ABOUT);
    let standard = SolKeySource::Standard(AccountIndex::ZERO);
    // Our fee-paying transfer, a site-paid one with its signature kept, and one whose site slot
    // is still empty: one approval, three signatures, same order.
    let site_paid = legacy(
        [2, 0, 1],
        &[site_address(), wallet(), SYSTEM_PROGRAM],
        vec![ix(2, &[1, 0], &system_transfer_data(1))],
    );
    let txs = vec![
        wire(&transfer_message(), &[]),
        wire(&site_paid, &[(0, &site_key())]),
        wire(&site_paid, &[]),
    ];
    let signed = sign_txs(
        &vault,
        approval(
            sign_only(wallet(), standard, &txs),
            ApprovalKind::SolTransaction,
        ),
    )
    .unwrap();
    assert_eq!(signed.len(), 3);
    for (before, after) in txs.iter().zip(&signed) {
        assert_only_our_slot(before, after, &wallet());
    }
    // The reference key signs the same bytes (RFC 8032 is deterministic).
    let reference = SigningKey::from_bytes(
        &crate::hex::decode_array::<32>(
            "37df573b3ac4ad5b522e064e25b63ea16bcbe79d449e81a0268d1047948bb445",
        )
        .unwrap(),
    );
    assert_eq!(
        &signed[0][1..65],
        reference.sign(&transfer_message()).to_bytes().as_slice()
    );
    // A bad site signature is refused before key use.
    let mut broken = txs[1].clone();
    broken[5] ^= 1;
    assert_eq!(
        sign_txs(
            &vault,
            approval(
                sign_only(wallet(), standard, &[broken]),
                ApprovalKind::SolTransaction
            )
        ),
        Err(SolTxSignError::ForeignSignature)
    );
    // Another account's key never signs for this public key (E4: `KeyMismatch`).
    let second = SolKeySource::Standard(AccountIndex::new(1).unwrap());
    assert_eq!(
        sign_txs(
            &vault,
            approval(
                sign_only(wallet(), second, &txs[..1]),
                ApprovalKind::SolTransaction
            )
        ),
        Err(SolTxSignError::KeyMismatch)
    );
    // A recovery-scan source is a policy refusal; a send payload is not this signer's.
    assert_eq!(
        sign_txs(
            &vault,
            approval(
                sign_only(wallet(), SolKeySource::RawSeed, &txs[..1]),
                ApprovalKind::SolTransaction
            )
        ),
        Err(SolTxSignError::PolicyMismatch)
    );
    let mut send = sign_only(wallet(), standard, &txs[..1]);
    send.mode = SolTxMode::SignAndSend;
    assert_eq!(
        sign_txs(&vault, approval(send, ApprovalKind::SolTransaction)),
        Err(SolTxSignError::KindMismatch)
    );
    // The hardware key has no seed in the vault.
    let hw = SolKeySource::Hardware(AccountIndex::ZERO);
    assert_eq!(
        sign_txs(
            &vault,
            approval(
                sign_only(wallet(), hw, &txs[..1]),
                ApprovalKind::SolTransaction
            )
        ),
        Err(SolTxSignError::Vault(
            crate::error::VaultError::RecordNotFound
        ))
    );
}

#[test]
fn sign_only_through_the_approval_store() {
    let vault = unlocked_with(ABOUT);
    let draft = draft_of(wire(&transfer_message(), &[]), ok_facts());
    let approved = issue_and_consume(draft).unwrap();
    let signed = sign_txs(&vault, approved).unwrap();
    assert_only_our_slot(&wire(&transfer_message(), &[]), &signed[0], &wallet());
}

#[test]
fn imported_and_added_mnemonic_keys() {
    use crate::vault::tests::{HARDHAT, HARDHAT_SOL_0, unlocked_with_added};
    let vault = crate::sol::tests::imported_vault();
    let txs = vec![wire(&transfer_message(), &[])];
    let signed = sign_txs(
        &vault,
        approval(
            sign_only(wallet(), SolKeySource::Imported, &txs),
            ApprovalKind::SolTransaction,
        ),
    )
    .unwrap();
    assert_only_our_slot(&txs[0], &signed[0], &wallet());
    let (vault, second) = unlocked_with_added(ABOUT, HARDHAT);
    let added = SolAddress::parse(HARDHAT_SOL_0).unwrap();
    let tx = wire(
        &legacy(
            [1, 0, 1],
            &[added, key(0x22), SYSTEM_PROGRAM],
            vec![ix(2, &[0, 1], &system_transfer_data(1))],
        ),
        &[],
    );
    let source = SolKeySource::Mnemonic(second, AccountIndex::ZERO);
    let signed = sign_txs(
        &vault,
        approval(
            sign_only(added, source, std::slice::from_ref(&tx)),
            ApprovalKind::SolTransaction,
        ),
    )
    .unwrap();
    assert_only_our_slot(&tx, &signed[0], &added);
}

#[test]
fn card_signs_each_transaction_once() {
    use crate::yubikey::CardError;
    use crate::yubikey::apdu::ApduMode;
    use crate::yubikey::sign::sign_sol;
    let (mut card, _vault, card_key) = crate::sol::tests::sol_card();
    card.log.clear();
    let hw = SolKeySource::Hardware(AccountIndex::ZERO);
    let txs = vec![wire(&transfer_message(), &[]); 3];
    let mut asked = 0_usize;
    let signed = {
        let mut signer = |message: &[u8]| {
            asked += 1;
            sign_sol(&mut card, ApduMode::Short, &card_key, b"123456", message)
        };
        sign_txs_card(
            approval(sign_only(wallet(), hw, &txs), ApprovalKind::SolTransaction),
            &mut signer,
        )
        .unwrap()
    };
    assert_eq!(asked, 3);
    assert!(!card.saw_write());
    for (before, after) in txs.iter().zip(&signed) {
        assert_only_our_slot(before, after, &wallet());
    }
    // Refusals before the card is asked.
    let mut never = |_: &[u8]| -> Result<[u8; 64], CardError> { unreachable!("not asked") };
    let software = SolKeySource::Standard(AccountIndex::ZERO);
    assert_eq!(
        sign_txs_card(
            approval(
                sign_only(wallet(), software, &txs),
                ApprovalKind::SolTransaction
            ),
            &mut never
        ),
        Err(SolTxCardError::Sign(SolTxSignError::KindMismatch))
    );
    // A card answer that does not verify is refused.
    let mut garbage = |_: &[u8]| -> Result<[u8; 64], CardError> { Ok([7; 64]) };
    assert_eq!(
        sign_txs_card(
            approval(sign_only(wallet(), hw, &txs), ApprovalKind::SolTransaction),
            &mut garbage
        ),
        Err(SolTxCardError::Sign(SolTxSignError::PostSignVerification))
    );
    let mut failing = |_: &[u8]| -> Result<[u8; 64], CardError> { Err(CardError::Internal) };
    assert_eq!(
        sign_txs_card(
            approval(sign_only(wallet(), hw, &txs), ApprovalKind::SolTransaction),
            &mut failing
        ),
        Err(SolTxCardError::Card(CardError::Internal))
    );
}

#[test]
fn kinds_never_cross_and_the_message_error_map() {
    let vault = unlocked_with(ABOUT);
    let standard = SolKeySource::Standard(AccountIndex::ZERO);
    let txs = vec![wire(&transfer_message(), &[])];
    // A transaction approval is not a message approval, and the other way round.
    let as_message = approval(
        sign_only(wallet(), standard, &txs),
        ApprovalKind::SolTransaction,
    );
    assert_eq!(
        crate::sol::msgsign::sign_message(&vault, as_message),
        Err(SolMessageError::KindMismatch)
    );
    for kind in [
        ApprovalKind::SolMessage,
        ApprovalKind::SolSignIn,
        ApprovalKind::SolTransfer,
    ] {
        assert_eq!(
            sign_txs(&vault, approval(sign_only(wallet(), standard, &txs), kind)),
            Err(SolTxSignError::KindMismatch)
        );
    }
    let message = Approved::for_test(
        ChainRef::Solana {
            cluster: CLUSTER,
            genesis: CLUSTER.genesis(),
        },
        AccountRef::Sol(wallet().to_bytes()),
        Signer::FromPayload,
        ApprovalKind::SolTransaction,
        SigningPayload::SolMessage(Box::new(crate::approval::SolMessagePayload {
            source: standard,
            public: wallet().to_bytes(),
            message: b"hi".to_vec(),
        })),
    );
    assert_eq!(sign_txs(&vault, message), Err(SolTxSignError::KindMismatch));
    // Wrong genesis and wrong account.
    let wrong_chain = Approved::for_test(
        ChainRef::Solana {
            cluster: CLUSTER,
            genesis: SolCluster::Mainnet.genesis(),
        },
        AccountRef::Sol(wallet().to_bytes()),
        Signer::FromPayload,
        ApprovalKind::SolTransaction,
        SigningPayload::SolTx(Box::new(sign_only(wallet(), standard, &txs))),
    );
    assert_eq!(
        sign_txs(&vault, wrong_chain),
        Err(SolTxSignError::KindMismatch)
    );
    let wrong_account = Approved::for_test(
        ChainRef::Solana {
            cluster: CLUSTER,
            genesis: CLUSTER.genesis(),
        },
        AccountRef::Sol(key(0x22).to_bytes()),
        Signer::FromPayload,
        ApprovalKind::SolTransaction,
        SigningPayload::SolTx(Box::new(sign_only(wallet(), standard, &txs))),
    );
    assert_eq!(
        sign_txs(&vault, wrong_account),
        Err(SolTxSignError::KindMismatch)
    );
    // E4: the message signer's errors in this signer's terms.
    assert_eq!(
        from_message_error(SolMessageError::KeyMismatch),
        SolTxSignError::KeyMismatch
    );
    assert_eq!(
        from_message_error(SolMessageError::Signing),
        SolTxSignError::PostSignVerification
    );
    assert_eq!(
        from_message_error(SolMessageError::KindMismatch),
        SolTxSignError::KindMismatch
    );
    assert_eq!(
        from_message_error(SolMessageError::Refused),
        SolTxSignError::KindMismatch
    );
}

#[test]
fn every_accepted_draft_is_m01_blocked_as_a_message() {
    for tx in [
        wire(&transfer_message(), &[]),
        v0_tx(),
        wire(&nonce_message(Vec::new()), &[]),
    ] {
        let parsed = parse_wire_tx(&tx).unwrap();
        assert!(crate::sol::msgsign::looks_like_transaction(&tx));
        assert!(crate::sol::msgsign::looks_like_transaction(
            &parsed.message_bytes
        ));
    }
}
