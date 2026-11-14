//! Bitcoin screen contents (M8; spec/04 §2.6–§2.8, §2.11, §2.16, §3.3; spec/08 §2, §3.2, §3.4,
//! §4.7, §7.3, §7.6, §8.2–§8.3, §9, §11.3, §12.1–§12.2): the S10 Bitcoin tab, the BTC send form
//! and its result, the fee-bump form, S12 receive and the S15 Bitcoin section. Every text is a
//! fixed sentence or built by yw-core / the controller ([`crate::app_btc`]); no server string is
//! shown. Addresses are shown in full in 4-character groups, the first and last 6 characters
//! bold (spec/04 §3.3); activity addresses have no copy or select buttons.

use yw_core::bip32::path::BtcChain;
use yw_core::btc::meta::FreezeReason;
use yw_core::btc::policy::texts;
use yw_core::btc::{BtcMeta, BtcNetwork, FeeRate, Sats, Txid, encode_address};
use yw_core::lang::{Lang, Text};

use crate::apikeys::KeyName;
use crate::app::{App, AppMode};
use crate::app_book::{BookTarget, PromptPlace};
use crate::app_btc::{
    BtcCtx, BtcFeeChoice, BtcFeeForm, BtcFlowStage, BtcGate, BtcUi, DISCOVERY_INCOMPLETE,
    PENDING_INCOMING, PENDING_INCOMING_UNREAD, confirmations_text, record_status,
};
use crate::btc::work::FeeQuote;
use crate::errors::ErrorCode;
use crate::meta::BookChain;
use crate::settings::BtcIndexer;
use crate::ui::badge::Badge;
use crate::ui::main_window::{Ctl, Item, Tone};

pub mod text;

pub use text::T_BTC_ESPLORA_NOTE;

/// The muted line under the balance with the received history's unconfirmed deposits
/// (2026-11-13; spec/04 §2.6, spec/08 §4.7-2). Shared with the Zcash card.
#[must_use]
pub fn pending_incoming_line(lang: Lang, amount: &str) -> String {
    text::PENDING_LINE.fill(lang, [amount])
}

/// The refresh's "미확정 입금 있음" banner (spec/08 §4.7-2, 2026-11-13): shown while the refresh
/// saw unconfirmed incoming funds (`flagged`, on the addresses `at`) unless the received history
/// is on and its last read (`covered`: the receive indices it answered completely) covered
/// every one of them — then the list has the deposit as a row (with the amount line) or as
/// counted dust. With the history off the banner points to the switch; on, it says the list has
/// not found it all. Before the 2026-11-13 review the list also had to have a pending row (any,
/// on any address), so a dust-only deposit kept the banner up while it sat in the mempool.
#[must_use]
pub fn pending_banner(
    flagged: bool,
    at: &[(BtcChain, u32)],
    history_on: bool,
    covered: Option<&[u32]>,
) -> Option<Text> {
    if !flagged {
        return None;
    }
    if !history_on {
        return Some(PENDING_INCOMING);
    }
    let covered = covered.is_some_and(|covered| {
        !at.is_empty()
            && at
                .iter()
                .all(|(chain, index)| *chain == BtcChain::Receive && covered.contains(index))
    });
    (!covered).then_some(PENDING_INCOMING_UNREAD)
}

/// Command ids of the Bitcoin screens (9000–9899; the whole map is `ui::command_ids`).
pub mod ids {
    /// Tab `Bitcoin`.
    pub const TAB_BTC: u16 = 9_000;
    /// Settings section `Bitcoin` (also `Bitcoin 설정` on the disabled tab).
    pub const SECTION_BTC: u16 = 9_001;
    /// 새로고침.
    pub const REFRESH: u16 = 9_002;
    /// 보내기.
    pub const SEND_OPEN: u16 = 9_003;
    /// 받기.
    pub const RECEIVE_OPEN: u16 = 9_004;
    /// 수수료 올리기 (the current bump target).
    pub const BUMP_OPEN: u16 = 9_005;
    /// Discovery [다시 시도].
    pub const DISCOVER_RETRY: u16 = 9_006;
    /// 더 찾기.
    pub const DISCOVER_MORE: u16 = 9_007;
    /// Discovery 취소.
    pub const DISCOVER_CANCEL: u16 = 9_008;
    /// [설정을 {`BtcMeta` 값}으로 되돌리기].
    pub const MISMATCH_KEEP_META: u16 = 9_009;
    /// [{settings 값}으로 바꾸기].
    pub const MISMATCH_USE_SETTINGS: u16 = 9_010;
    /// [블록 높이 기록 초기화] (shown while blocked by a tip regression).
    pub const RESET_TIP: u16 = 9_011;
    /// Send: recipient edit.
    pub const SEND_TO_EDIT: u16 = 9_020;
    /// Send: amount edit.
    pub const SEND_AMOUNT_EDIT: u16 = 9_021;
    /// Send: unit `BTC`.
    pub const UNIT_BTC: u16 = 9_022;
    /// Send: unit `sats`.
    pub const UNIT_SATS: u16 = 9_023;
    /// Send: `보내기 최대`.
    pub const SEND_MAX: u16 = 9_024;
    /// Send fee `빠름`.
    pub const FEE_FAST: u16 = 9_025;
    /// Send fee `보통`.
    pub const FEE_NORMAL: u16 = 9_026;
    /// Send fee `느림`.
    pub const FEE_SLOW: u16 = 9_027;
    /// Send fee `직접 입력`.
    pub const FEE_MANUAL: u16 = 9_028;
    /// Send: manual sat/vB edit.
    pub const FEE_MANUAL_EDIT: u16 = 9_029;
    /// Send: typed fee (sats) edit, shown only when the cap needs it.
    pub const TYPED_FEE_EDIT: u16 = 9_030;
    /// Send `검토`.
    pub const SEND_REVIEW: u16 = 9_031;
    /// Send `취소`.
    pub const SEND_CANCEL: u16 = 9_032;
    /// Send: `주소 전체를 직접 확인했습니다` (W-ADDR-3).
    pub const SEND_ADDR_ACK: u16 = 9_033;
    /// Result `해시 복사`.
    pub const RESULT_COPY: u16 = 9_040;
    /// Result [다시 시도] (pre-check communication failure).
    pub const RESULT_RETRY: u16 = 9_041;
    /// Result `보내기 화면으로` (pre-check rejection; inputs kept).
    pub const RESULT_TO_SEND: u16 = 9_042;
    /// Bump fee `빠름`.
    pub const BUMP_FEE_FAST: u16 = 9_050;
    /// Bump fee `보통`.
    pub const BUMP_FEE_NORMAL: u16 = 9_051;
    /// Bump fee `느림`.
    pub const BUMP_FEE_SLOW: u16 = 9_052;
    /// Bump fee `직접 입력`.
    pub const BUMP_FEE_MANUAL: u16 = 9_053;
    /// Bump: manual sat/vB edit.
    pub const BUMP_MANUAL_EDIT: u16 = 9_054;
    /// Bump: typed fee (sats) edit.
    pub const BUMP_TYPED_EDIT: u16 = 9_055;
    /// Bump `검토`.
    pub const BUMP_REVIEW: u16 = 9_056;
    /// Bump `취소`.
    pub const BUMP_CANCEL: u16 = 9_057;
    /// Receive `주소 복사`.
    pub const COPY_ADDRESS: u16 = 9_060;
    /// Receive `새 주소`.
    pub const NEW_ADDRESS: u16 = 9_061;
    /// Settings `Bitcoin 사용` check (켜기 / 끄기).
    pub const ENABLE: u16 = 9_100;
    /// Settings network `mainnet`.
    pub const SET_MAINNET: u16 = 9_101;
    /// Settings network `testnet4`.
    pub const SET_TESTNET4: u16 = 9_102;
    /// Settings indexer `Esplora`.
    pub const IDX_ESPLORA: u16 = 9_103;
    /// Settings indexer `bb-rpc`.
    pub const IDX_BB_RPC: u16 = 9_104;
    /// Settings indexer `bb-rest`.
    pub const IDX_BB_REST: u16 = 9_105;
    /// Esplora URL mainnet: edit.
    pub const ESPLORA_MAINNET_EDIT: u16 = 9_110;
    /// Esplora URL mainnet: `저장`.
    pub const ESPLORA_MAINNET_SAVE: u16 = 9_111;
    /// Esplora URL mainnet: `기본값으로`.
    pub const ESPLORA_MAINNET_DEFAULT: u16 = 9_112;
    /// Esplora URL mainnet: `테스트`.
    pub const ESPLORA_MAINNET_TEST: u16 = 9_113;
    /// Esplora URL testnet4: edit.
    pub const ESPLORA_TESTNET4_EDIT: u16 = 9_120;
    /// Esplora URL testnet4: `저장`.
    pub const ESPLORA_TESTNET4_SAVE: u16 = 9_121;
    /// Esplora URL testnet4: `기본값으로`.
    pub const ESPLORA_TESTNET4_DEFAULT: u16 = 9_122;
    /// Esplora URL testnet4: `테스트`.
    pub const ESPLORA_TESTNET4_TEST: u16 = 9_123;
    /// UTXO rows (`동결` / `해제`, one id per row).
    pub const UTXO_BASE: u16 = 9_200;
    /// UTXO rows shown (and id span).
    pub const UTXO_SPAN: u16 = 300;
    /// Activity rows ([`ACTIVITY_STRIDE`] ids per row: 해시 복사, 수수료 올리기, 같은 바이트 다시
    /// 전송, 포기, Esplora로 전송, 전송 계속 / 다시 시도, 취소).
    pub const ACTIVITY_BASE: u16 = 9_500;
    /// Ids per activity row.
    pub const ACTIVITY_STRIDE: u16 = 8;
    /// Activity id span (`BTC_MAX_ACTIVITY_ROWS` × stride).
    pub const ACTIVITY_SPAN: u16 = 400;
    /// Activity offset: 해시 복사.
    pub const ACT_COPY: u16 = 0;
    /// Activity offset: 수수료 올리기.
    pub const ACT_BUMP: u16 = 1;
    /// Activity offset: 같은 바이트 다시 전송.
    pub const ACT_REBROADCAST: u16 = 2;
    /// Activity offset: 포기.
    pub const ACT_ABANDON: u16 = 3;
    /// Activity offset: Esplora로 전송.
    pub const ACT_ESPLORA: u16 = 4;
    /// Activity offset: 전송 계속 / 다시 시도.
    pub const ACT_CONTINUE: u16 = 5;
    /// Activity offset: 취소 (a `Signed` record).
    pub const ACT_CANCEL: u16 = 6;
    /// Activity offset: 이 주소 저장 (address book).
    pub const ACT_SAVE: u16 = 7;
    /// `계정 추가` (opens the address-type chooser).
    pub const ACCOUNT_ADD: u16 = 9_012;
    /// The chooser's `취소`.
    pub const ACCOUNT_ADD_CANCEL: u16 = 9_013;
    /// The chooser's four address types, in `ScriptType::CHOICES` order (9,014–9,017).
    pub const ACCOUNT_ADD_TYPE: u16 = 9_014;
    /// The chooser's key source `BTC 표준 경로 (권장, 기본값)`.
    pub const ACCOUNT_SOURCE_STANDARD: u16 = 9_018;
    /// The chooser's key source `EVM 계정과 같은 키`.
    pub const ACCOUNT_SOURCE_EVM: u16 = 9_019;
    /// The selected account card's `주소 복사` (2026-11-11): the address that card shows
    /// (`App::btc_card_address`), not the receive screen's.
    pub const CARD_COPY: u16 = 9_034;
    /// Address mode of the selected HD account: `고정 주소 하나만 사용`.
    pub const ADDRESS_MODE_SINGLE: u16 = 9_062;
    /// Address mode of the selected HD account: `받을 때마다 새 주소`.
    pub const ADDRESS_MODE_HD: u16 = 9_063;
    /// The chooser's EVM account radios: `EVM_ACCOUNT_BASE + row` (rows of meta `evm_accounts`).
    pub const EVM_ACCOUNT_BASE: u16 = 9_064;
    /// EVM account rows shown in the chooser (and id span, 9,064–9,095).
    pub const EVM_ACCOUNT_SPAN: u16 = 32;
    /// Account rows: `ACCOUNT_BASE + row` selects that account.
    pub const ACCOUNT_BASE: u16 = 9_130;
    /// Most account rows with a button (1 + `MAX_BTC_ACCOUNTS`).
    pub const ACCOUNT_SPAN: u16 = 65;

    const _: () = assert!(ACT_SAVE < ACTIVITY_STRIDE);
    const _: () = assert!(NEW_ADDRESS < ADDRESS_MODE_SINGLE);
    const _: () = assert!(EVM_ACCOUNT_BASE + EVM_ACCOUNT_SPAN <= ENABLE);
    const _: () = assert!(ACCOUNT_ADD_TYPE + 4 <= ESPLORA_MAINNET_EDIT);
    const _: () = assert!(ESPLORA_TESTNET4_TEST < ACCOUNT_BASE);
    const _: () = assert!(ACCOUNT_BASE + ACCOUNT_SPAN <= UTXO_BASE);
    const _: () = assert!(UTXO_BASE + UTXO_SPAN <= ACTIVITY_BASE);
    const _: () = assert!(ACTIVITY_BASE + ACTIVITY_SPAN <= 10_000);

    /// Every fixed id (tests check uniqueness and the range).
    pub const FIXED: [u16; 64] = [
        CARD_COPY,
        ACCOUNT_SOURCE_STANDARD,
        ACCOUNT_SOURCE_EVM,
        ADDRESS_MODE_SINGLE,
        ADDRESS_MODE_HD,
        TAB_BTC,
        SECTION_BTC,
        REFRESH,
        SEND_OPEN,
        RECEIVE_OPEN,
        BUMP_OPEN,
        DISCOVER_RETRY,
        DISCOVER_MORE,
        DISCOVER_CANCEL,
        MISMATCH_KEEP_META,
        MISMATCH_USE_SETTINGS,
        RESET_TIP,
        ACCOUNT_ADD,
        ACCOUNT_ADD_CANCEL,
        ACCOUNT_ADD_TYPE,
        ACCOUNT_ADD_TYPE + 1,
        ACCOUNT_ADD_TYPE + 2,
        ACCOUNT_ADD_TYPE + 3,
        SEND_TO_EDIT,
        SEND_AMOUNT_EDIT,
        UNIT_BTC,
        UNIT_SATS,
        SEND_MAX,
        FEE_FAST,
        FEE_NORMAL,
        FEE_SLOW,
        FEE_MANUAL,
        FEE_MANUAL_EDIT,
        TYPED_FEE_EDIT,
        SEND_REVIEW,
        SEND_CANCEL,
        SEND_ADDR_ACK,
        RESULT_COPY,
        RESULT_RETRY,
        RESULT_TO_SEND,
        BUMP_FEE_FAST,
        BUMP_FEE_NORMAL,
        BUMP_FEE_SLOW,
        BUMP_FEE_MANUAL,
        BUMP_MANUAL_EDIT,
        BUMP_TYPED_EDIT,
        BUMP_REVIEW,
        BUMP_CANCEL,
        COPY_ADDRESS,
        NEW_ADDRESS,
        ENABLE,
        SET_MAINNET,
        SET_TESTNET4,
        IDX_ESPLORA,
        IDX_BB_RPC,
        IDX_BB_REST,
        ESPLORA_MAINNET_EDIT,
        ESPLORA_MAINNET_SAVE,
        ESPLORA_MAINNET_DEFAULT,
        ESPLORA_MAINNET_TEST,
        ESPLORA_TESTNET4_EDIT,
        ESPLORA_TESTNET4_SAVE,
        ESPLORA_TESTNET4_DEFAULT,
        ESPLORA_TESTNET4_TEST,
    ];
}

/// The fee choices in radio order.
const FEE_CHOICES: [BtcFeeChoice; 4] = [
    BtcFeeChoice::Fast,
    BtcFeeChoice::Normal,
    BtcFeeChoice::Slow,
    BtcFeeChoice::Manual,
];

/// The whole address in 4-character groups separated by one space (spec/04 §3.3; drawing only,
/// the copied text never has spaces).
#[must_use]
pub fn grouped(address: &str) -> String {
    let mut out = String::with_capacity(address.len().saturating_add(address.len() / 4));
    for (index, character) in address.chars().enumerate() {
        if index != 0 && index % 4 == 0 {
            out.push(' ');
        }
        out.push(character);
    }
    out
}

/// The fee radio ids of the send form (`bump = false`) or the fee-bump form, in
/// [`FEE_CHOICES`] order.
#[must_use]
pub const fn fee_ids(bump: bool) -> [u16; 4] {
    if bump {
        [
            ids::BUMP_FEE_FAST,
            ids::BUMP_FEE_NORMAL,
            ids::BUMP_FEE_SLOW,
            ids::BUMP_FEE_MANUAL,
        ]
    } else {
        [
            ids::FEE_FAST,
            ids::FEE_NORMAL,
            ids::FEE_SLOW,
            ids::FEE_MANUAL,
        ]
    }
}

/// The fee choice of a radio id, with whether it belongs to the fee-bump form.
#[must_use]
pub fn fee_choice_of(id: u16) -> Option<(BtcFeeChoice, bool)> {
    for bump in [false, true] {
        if let Some(position) = fee_ids(bump).iter().position(|known| *known == id) {
            return FEE_CHOICES.get(position).map(|choice| (*choice, bump));
        }
    }
    None
}

/// `(edit, 저장, 기본값으로, 테스트)` ids of a network's Esplora URL row.
#[must_use]
pub const fn esplora_ids(net: BtcNetwork) -> (u16, u16, u16, u16) {
    match net {
        BtcNetwork::Mainnet => (
            ids::ESPLORA_MAINNET_EDIT,
            ids::ESPLORA_MAINNET_SAVE,
            ids::ESPLORA_MAINNET_DEFAULT,
            ids::ESPLORA_MAINNET_TEST,
        ),
        BtcNetwork::Testnet4 => (
            ids::ESPLORA_TESTNET4_EDIT,
            ids::ESPLORA_TESTNET4_SAVE,
            ids::ESPLORA_TESTNET4_DEFAULT,
            ids::ESPLORA_TESTNET4_TEST,
        ),
    }
}

/// The settings name with its Korean particle (`mainnet으로`, `testnet4로`; English: the name).
fn with_particle(lang: Lang, net: BtcNetwork) -> String {
    match net {
        BtcNetwork::Mainnet => text::WITH_EURO.fill(lang, [net.settings_name()]),
        BtcNetwork::Testnet4 => text::WITH_RO.fill(lang, [net.settings_name()]),
    }
}

/// The two mismatch buttons in `lang` (spec/08 §2): [설정을 {`BtcMeta` 값}으로 되돌리기] /
/// [{settings 값}으로 바꾸기].
#[must_use]
pub fn mismatch_labels(lang: Lang, meta: BtcNetwork, settings: BtcNetwork) -> (String, String) {
    (
        text::MISMATCH_KEEP.fill(lang, [&with_particle(lang, meta)]),
        text::MISMATCH_USE.fill(lang, [&with_particle(lang, settings)]),
    )
}

/// The network banner tone (spec/08 §2: mainnet red, testnet4 orange).
#[must_use]
pub const fn network_tone(net: BtcNetwork) -> Tone {
    match net {
        BtcNetwork::Mainnet => Tone::BtcMainnet,
        BtcNetwork::Testnet4 => Tone::BtcTestnet4,
    }
}

/// The network banner (spec/08 §2). Testnet4 shows only `BITCOIN TESTNET4 — 가치 없음` (it already
/// says the coins have no value; a second generic testnet band under it was noise).
fn network_banners(lang: Lang, net: BtcNetwork, items: &mut Vec<Item>) {
    items.push(Item::Banner(
        net.banner_in(lang).to_owned(),
        network_tone(net),
    ));
}

/// `YYYY-MM-DD HH:MM` in local time (spec/04 §2.6); UTC with a suffix if the conversion fails.
fn local_time(unix_ms: u64) -> String {
    let wall = yw_win::time::local_wall_ms(unix_ms);
    let text = crate::logging::format_utc(wall.unwrap_or(unix_ms));
    let short = text.get(..16).unwrap_or(&text).replace('T', " ");
    if wall.is_some() {
        short
    } else {
        format!("{short} UTC")
    }
}

/// The rate a fee choice would use with `quote` (the floor when the estimate is below it, like
/// `choose_fee_rate`); `None` for no estimate, no preview or `직접 입력`.
fn quoted_rate(choice: BtcFeeChoice, quote: Option<&FeeQuote>) -> Option<FeeRate> {
    let quote = quote?;
    let slot = match choice {
        BtcFeeChoice::Fast => 0,
        BtcFeeChoice::Normal => 1,
        BtcFeeChoice::Slow => 2,
        BtcFeeChoice::Manual => return None,
    };
    quote
        .rates
        .get(slot)
        .copied()
        .flatten()
        .map(|rate| rate.max(quote.floor))
}

/// A send-form fee radio (2026-11-10): "빠름 · 약 20분 · 12 sat/vB" — the usual wait of 2·6·24
/// blocks — with "· 추정 없음" when the node gave none, the name and wait alone before the preview.
fn fee_choice_label(lang: Lang, choice: BtcFeeChoice, quote: Option<&FeeQuote>) -> String {
    let wait = match choice {
        BtcFeeChoice::Fast => text::WAIT_FAST,
        BtcFeeChoice::Normal => text::WAIT_NORMAL,
        BtcFeeChoice::Slow => text::WAIT_SLOW,
        BtcFeeChoice::Manual => return choice.label(lang).to_owned(),
    }
    .get(lang);
    let label = choice.label(lang);
    match (quote, quoted_rate(choice, quote)) {
        (Some(_), Some(rate)) => format!("{label} · {wait} · {rate}"),
        (Some(_), None) => format!("{label} · {wait} · {}", text::NO_ESTIMATE.get(lang)),
        (None, _) => format!("{label} · {wait}"),
    }
}

/// The plain name of a recipient's address type before its technical name (2026-11-10:
/// "네이티브 세그윗 (P2WPKH)"; the approval window keeps `ScriptKind::type_label`).
const fn kind_text(lang: Lang, kind: &yw_core::btc::ScriptKind) -> &'static str {
    match kind {
        yw_core::btc::ScriptKind::P2pkh(_) => text::KIND_P2PKH,
        yw_core::btc::ScriptKind::P2sh(_) => text::KIND_P2SH,
        yw_core::btc::ScriptKind::P2wpkh(_) => text::KIND_P2WPKH,
        yw_core::btc::ScriptKind::P2wsh(_) => text::KIND_P2WSH,
        yw_core::btc::ScriptKind::P2tr(_) => text::KIND_P2TR,
    }
    .get(lang)
}

/// `X sat/vB` of a recorded fee and vsize (rounded up like spec/08 §8.3 `rate_kvb`).
fn record_rate(fee: Sats, vsize: u32) -> String {
    let kvb = fee
        .get()
        .saturating_mul(1_000)
        .div_ceil(u64::from(vsize.max(1)));
    FeeRate::from_sat_per_kvb(kvb).to_string()
}

/// The selected account's name (`네이티브 세그윗 계정 0`), `Bitcoin 계정` before BTC has one.
fn active_label(ctx: &BtcCtx<'_>) -> String {
    ctx.btc_meta().map_or_else(
        || text::ACCOUNT_FALLBACK.get(ctx.lang).to_owned(),
        |meta| crate::app_btc::account_label(ctx.lang, meta.account()),
    )
}

/// The selected account's node and type line: `m/86'/0'/0' · 탭루트 (bc1p…)`, or for an
/// imported key `가져온 키 · 레거시 (1…)`.
fn active_detail(ctx: &BtcCtx<'_>) -> String {
    let net = ctx.net();
    ctx.btc_meta().map_or_else(String::new, |meta| {
        format!(
            "{} · {}",
            meta.account().node_text_in(ctx.lang, net),
            crate::app_btc::account_type_text(ctx.lang, meta.account(), net)
        )
    })
}

fn flow_stage_text(lang: Lang, stage: BtcFlowStage) -> Option<&'static str> {
    match stage {
        BtcFlowStage::Prechecking => Some(text::STAGE_PRECHECK.get(lang)),
        BtcFlowStage::Applying => Some(text::STAGE_APPLYING.get(lang)),
        BtcFlowStage::Sending => Some(text::STAGE_SENDING.get(lang)),
        BtcFlowStage::Waiting | BtcFlowStage::Done => None,
    }
}

impl App {
    fn btc_tip(&self, ctx: &BtcCtx<'_>) -> u32 {
        self.btc
            .tip
            .or_else(|| ctx.btc_meta().map(BtcMeta::max_tip_seen))
            .unwrap_or(0)
    }

    fn btc_unlocked(&self) -> bool {
        matches!(self.mode, AppMode::Unlocked { .. })
    }

    /// The gate reason of the tab (disabled is handled by the caller).
    fn btc_gate_items(lang: Lang, gate: BtcGate, items: &mut Vec<Item>) {
        match gate {
            // NoAccount: the account card says it, next to `개인키 가져오기`.
            BtcGate::Disabled | BtcGate::NoAccount => {}
            BtcGate::Locked | BtcGate::NoMeta | BtcGate::JournalLoading => {
                items.push(Item::Muted(gate.text(lang)));
            }
            BtcGate::JournalClosed => items.push(Item::Banner(gate.text(lang), Tone::Blocked)),
            BtcGate::Mismatch { meta, settings } => {
                items.push(Item::Banner(gate.text(lang), Tone::Danger));
                Self::btc_mismatch_row(lang, meta, settings, items);
            }
            BtcGate::NoEndpoint => {
                items.push(Item::Banner(gate.text(lang), Tone::Danger));
                // That network's row with its field open (2026-11-10).
                items.push(Item::Row(vec![Ctl::button(
                    crate::ui::screens::ids::BTC_RPC_OPEN,
                    text::RPC_SETUP.get(lang),
                )]));
            }
        }
    }

    fn btc_mismatch_row(lang: Lang, meta: BtcNetwork, settings: BtcNetwork, items: &mut Vec<Item>) {
        let (keep, change) = mismatch_labels(lang, meta, settings);
        items.push(Item::Row(vec![
            Ctl::button(ids::MISMATCH_KEEP_META, &keep),
            Ctl::button(ids::MISMATCH_USE_SETTINGS, &change),
        ]));
    }

    /// The S10 status line of the Bitcoin tab (network id and indexer name only, spec/04 §1.9).
    fn btc_status_line(&self, ctx: &BtcCtx<'_>) -> String {
        let net = ctx.net();
        let lang = ctx.lang;
        let rpc = if ctx.core_url(net).is_none() {
            text::STATUS_NO_RPC.get(lang).to_owned()
        } else if self.btc.blocked.is_some() {
            text::STATUS_BLOCKED.get(lang).to_owned()
        } else if let Some(tip) = self.btc.tip {
            text::STATUS_CONNECTED.fill(lang, [&tip.to_string()])
        } else {
            text::STATUS_UNCHECKED.get(lang).to_owned()
        };
        let indexer = crate::btc::indexer_display(ctx.settings.indexer);
        let checked = if self.btc.indexer_verified {
            text::STATUS_GENESIS_OK
        } else {
            text::STATUS_UNCHECKED
        };
        text::STATUS_LINE.fill(
            lang,
            [
                &crate::btc::network_id(net).to_string(),
                &rpc,
                indexer,
                checked.get(lang),
            ],
        )
    }

    fn btc_discovery_items(&self, ctx: &BtcCtx<'_>, items: &mut Vec<Item>) {
        let discovery = &self.btc.discovery;
        let lang = ctx.lang;
        if discovery.running {
            let doing = if discovery.more {
                text::DISCOVERY_MORE
            } else {
                text::DISCOVERY_RUNNING
            };
            items.push(Item::Muted(
                text::DISCOVERY_PROGRESS
                    .fill(lang, [doing.get(lang), &discovery.checked.to_string()]),
            ));
            items.push(Item::Row(vec![Ctl::button(
                ids::DISCOVER_CANCEL,
                text::CANCEL.get(lang),
            )]));
            return;
        }
        let incomplete = ctx.btc_meta().is_some_and(|meta| !meta.discovery_done());
        if discovery.error.is_some() || incomplete {
            let text = discovery
                .error
                .clone()
                .unwrap_or_else(|| DISCOVERY_INCOMPLETE.get(lang).to_owned());
            items.push(Item::Banner(text, Tone::Warn));
            items.push(Item::Row(vec![
                Ctl::button(ids::DISCOVER_RETRY, text::RETRY.get(lang)).enabled(ctx.gate().is_ok()),
            ]));
        }
    }

    /// `새로고침` and, for an HD account after discovery, `더 찾기`.
    /// The network card's `더 찾기` (`새로고침` is on the account card since 2026-11-11, like
    /// the other tabs).
    fn btc_discover_row(&self, ctx: &BtcCtx<'_>, usable: bool, items: &mut Vec<Item>) {
        let discovery_done = ctx.btc_meta().is_some_and(BtcMeta::discovery_done);
        let single = ctx.btc_meta().is_some_and(BtcMeta::is_single);
        if discovery_done && !single && !self.btc.discovery.running {
            items.push(Item::Row(vec![
                Ctl::button(ids::DISCOVER_MORE, text::FIND_MORE.get(ctx.lang)).enabled(usable),
            ]));
        }
    }

    /// The account list (name, address type with prefix, balance; the selected one marked;
    /// imported keys with the "[가져온 키]" badge), `계정 추가` with its address-type chooser
    /// (wallets with recovery words), and the imported-key actions (`개인키 보기`·`삭제` of the
    /// selected imported account, `개인키 가져오기`).
    fn btc_account_items(&self, ctx: &BtcCtx<'_>, items: &mut Vec<Item>) {
        let net = ctx.net();
        let lang = ctx.lang;
        items.push(Item::Subtitle(text::ACCOUNTS_TITLE.get(lang).to_owned()));
        let usable = ctx.gate().is_ok() && !self.btc.slot;
        let rows = self.btc.account_rows(ctx);
        if rows.is_empty() {
            let none_at_all = ctx
                .meta
                .is_none_or(|meta| meta.btc_accounts.accounts.is_empty());
            items.push(Item::Muted(if none_at_all {
                crate::ui::screens_keys::no_accounts_text(
                    self.settings.language,
                    yw_core::keyimport::ImportChain::Btc,
                )
            } else {
                BtcGate::NoAccount.text(lang)
            }));
        }
        // A drop-down like the network's (2026-11-11): the selected account on its button, the
        // accounts under it while open (each keeps the id its radio had).
        let mut entries = Vec::new();
        for (index, row) in rows.iter().take(usize::from(ids::ACCOUNT_SPAN)).enumerate() {
            let id = ids::ACCOUNT_BASE.saturating_add(u16::try_from(index).unwrap_or(0));
            let hardware = matches!(row.id, yw_core::btc::BtcAccountId::Hardware { .. });
            let badge = match (row.imported, row.evm_shared) {
                _ if hardware => " · YubiKey".to_owned(),
                (true, _) => format!(" · {}", text::BADGE_IMPORTED.get(lang)),
                (false, Some(evm_index)) => format!(
                    " · {}",
                    text::BADGE_EVM_KEY.fill(lang, [&evm_index.to_string()])
                ),
                (false, None) => String::new(),
            };
            // HD rows name their mnemonic with several (spec/02 §8.6).
            let name = match row.id {
                yw_core::btc::BtcAccountId::Hd {
                    mnemonic,
                    script_type,
                    account,
                } => {
                    let name = yw_core::btc::text::ACCOUNT_HD
                        .fill(lang, [script_type.name_in(lang), &account.to_string()]);
                    self.mnemonic_tag(mnemonic.map(|id| *id.as_bytes()))
                        .map_or_else(|| name.clone(), |tag| format!("{name} · {tag}"))
                }
                _ => row.name.clone(),
            };
            entries.push(crate::ui::screens_links::PickerEntry {
                id,
                label: format!(
                    "{name}{badge} · {} · {}",
                    row.kind,
                    BtcUi::amount_text(row.available)
                ),
                selected: row.selected,
                enabled: usable || row.selected,
            });
        }
        if !entries.is_empty() {
            self.push_account_picker(items, crate::ui::screens_links::ids::PICKER_BTC, &entries);
        }
        if let Some(message) = &self.btc.account_message {
            items.push(Item::Banner(message.clone(), Tone::Warn));
        }
        Self::btc_address_mode_items(ctx, usable, items);
        if !ctx.has_mnemonic {
            // A key-only wallet has no recovery words to derive accounts from.
            self.btc_imported_items(ctx, items);
            return;
        }
        if self.btc.add_account_open {
            items.push(Item::Help(text::ADD_ACCOUNT_HELP.get(lang).to_owned()));
            self.btc_add_source_items(ctx, usable, items);
            for (offset, script_type) in yw_core::btc::ScriptType::CHOICES.iter().enumerate() {
                let id = ids::ACCOUNT_ADD_TYPE.saturating_add(u16::try_from(offset).unwrap_or(0));
                items.push(Item::Row(vec![
                    Ctl::button(id, &script_type.label_in(lang, net)).enabled(usable),
                ]));
            }
            items.push(Item::Row(vec![Ctl::button(
                ids::ACCOUNT_ADD_CANCEL,
                text::CANCEL.get(lang),
            )]));
        } else {
            items.push(Item::Row(vec![
                Ctl::button(ids::ACCOUNT_ADD, text::ADD_ACCOUNT.get(lang)).enabled(usable),
            ]));
        }
        items.push(Item::Help(text::ACCOUNTS_HELP.get(lang).to_owned()));
        self.btc_imported_items(ctx, items);
    }

    /// The selected HD account's address mode (spec/08 §3.5): `고정 주소 하나만 사용` (default) /
    /// `받을 때마다 새 주소` with the one-line trade-off. One-key accounts have one address only.
    fn btc_address_mode_items(ctx: &BtcCtx<'_>, usable: bool, items: &mut Vec<Item>) {
        let Some(meta) = ctx.btc_meta().filter(|meta| meta.account().is_hd()) else {
            return;
        };
        let fixed = meta.fixed_address();
        let lang = ctx.lang;
        items.push(Item::Text(text::ADDRESS_MODE.fill(
            lang,
            [&crate::app_btc::account_label(lang, meta.account())],
        )));
        items.push(Item::Row(vec![
            Ctl::radio(
                ids::ADDRESS_MODE_SINGLE,
                crate::app_btc::T_BTC_MODE_SINGLE.get(lang),
                fixed,
                true,
            )
            .enabled(usable),
        ]));
        items.push(Item::Row(vec![
            Ctl::radio(
                ids::ADDRESS_MODE_HD,
                crate::app_btc::T_BTC_MODE_HD.get(lang),
                !fixed,
                false,
            )
            .enabled(usable),
        ]));
        items.push(Item::Help(
            crate::app_btc::T_BTC_MODE_HELP.get(lang).to_owned(),
        ));
    }

    /// The add-account key source (spec/08 §3.5): the standard BTC path (default) or the key of
    /// an EVM account (warning and the EVM account radios; adding asks for confirmation).
    fn btc_add_source_items(&self, ctx: &BtcCtx<'_>, usable: bool, items: &mut Vec<Item>) {
        let evm = self.btc.add_source == crate::app_btc::BtcAddSource::EvmShared;
        let lang = ctx.lang;
        if self.several_mnemonics() {
            // Which recovery phrase the standard-path account comes from (spec/02 §8.6).
            items.push(Item::Text(text::MNEMONIC.get(lang).to_owned()));
            for (row, info) in self.mn.infos.iter().enumerate() {
                let chosen = if info.primary {
                    self.btc.add_mnemonic.is_none()
                } else {
                    self.btc.add_mnemonic == Some(info.id)
                };
                let id = crate::ui::screens_mnemonics::ids::BTC_PICK_BASE
                    .saturating_add(u16::try_from(row).unwrap_or(0));
                items.push(Item::Row(vec![
                    Ctl::radio(id, &self.mnemonic_label(info.id), chosen, row == 0).enabled(usable),
                ]));
            }
            if self.btc.add_mnemonic.is_some() {
                items.push(Item::Help(text::ADDED_MNEMONIC_HELP.get(lang).to_owned()));
                return;
            }
        }
        items.push(Item::Text(text::KEY_SOURCE.get(lang).to_owned()));
        items.push(Item::Row(vec![
            Ctl::radio(
                ids::ACCOUNT_SOURCE_STANDARD,
                crate::app_btc::T_BTC_SOURCE_STANDARD.get(lang),
                !evm,
                true,
            )
            .enabled(usable),
        ]));
        items.push(Item::Help(
            crate::app_btc::T_BTC_SOURCE_STANDARD_HELP
                .get(lang)
                .to_owned(),
        ));
        items.push(Item::Row(vec![
            Ctl::radio(
                ids::ACCOUNT_SOURCE_EVM,
                crate::app_btc::T_BTC_SOURCE_EVM.get(lang),
                evm,
                false,
            )
            .enabled(usable),
        ]));
        if !evm {
            return;
        }
        items.push(Item::Banner(
            crate::app_btc::T_BTC_EVM_SHARED.get(lang).to_owned(),
            Tone::Warn,
        ));
        let accounts = ctx.evm_accounts();
        if accounts.is_empty() {
            items.push(Item::Muted(text::NO_EVM_ACCOUNTS.get(lang).to_owned()));
        }
        for (row, (index, label, address)) in accounts
            .iter()
            .take(usize::from(ids::EVM_ACCOUNT_SPAN))
            .enumerate()
        {
            let id = ids::EVM_ACCOUNT_BASE.saturating_add(u16::try_from(row).unwrap_or(0));
            let text = format!(
                "{label} · {} · m/44'/60'/0'/0/{index}",
                crate::app_btc::short_address(address)
            );
            items.push(Item::Row(vec![
                Ctl::radio(id, &text, self.btc.add_evm_index == *index, row == 0).enabled(usable),
            ]));
        }
        items.push(Item::Help(text::EVM_PICK_HELP.get(lang).to_owned()));
    }

    fn btc_balance_items(&self, ctx: &BtcCtx<'_>, items: &mut Vec<Item>) {
        let lang = ctx.lang;
        items.push(Item::Subtitle(active_label(ctx)));
        items.push(Item::Help(active_detail(ctx)));
        // U7, as on the EVM and Solana tabs: the account's phrase waits for its backup quiz;
        // a YubiKey on its factory PINs likewise (spec/10 §9.3).
        self.mn_signing_banner(self.btc_backup_gate(), items);
        self.card_pin_banner(self.btc_selected_card_gate(), items);
        if let Some(balance) = self.btc.balance(ctx) {
            items.push(Item::Display(BtcUi::amount_text(balance.available)));
            // One status line, like the other tabs (the UTXO explanation is the UTXO card's,
            // 2026-11-11).
            items.push(Item::Help(text::AVAILABLE_NOTE.get(lang).to_owned()));
            if balance.frozen.get() > 0 {
                items.push(Item::Muted(
                    text::FROZEN.fill(lang, [&BtcUi::amount_text(balance.frozen)]),
                ));
            }
            if balance.pending.get() > 0 {
                items.push(Item::Muted(
                    text::PENDING_BALANCE.fill(lang, [&BtcUi::amount_text(balance.pending)]),
                ));
            }
        } else {
            items.push(Item::Display(text::BALANCE_DASH.get(lang).to_owned()));
            items.push(Item::Help(text::BALANCE_UNKNOWN.get(lang).to_owned()));
        }
        // 2026-11-13: the received history's unconfirmed deposits as an amount (display only,
        // never in the balance above); the refresh's yes/no banner stays while that list does
        // not account for every address the refresh flagged.
        let list = self.received_list(crate::received::RecvChain::Btc);
        let pending_sum = list.and_then(crate::app_received::RecvList::pending_sum);
        if let Some(sats) = pending_sum {
            items.push(Item::Muted(pending_incoming_line(
                lang,
                &BtcUi::amount_text(Sats::new(sats).unwrap_or(Sats::ZERO)),
            )));
        }
        if let Some(text) = pending_banner(
            self.btc.pending_incoming,
            &self.btc.pending_incoming_at,
            self.settings.received_history,
            list.map(|list| list.covered.as_slice()),
        ) {
            items.push(Item::Banner(text.get(lang).to_owned(), Tone::Warn));
        }
        if self.btc.verify_failures > 0 {
            items.push(Item::Banner(
                text::VERIFY_FAILURES.fill(lang, [&self.btc.verify_failures.to_string()]),
                Tone::Warn,
            ));
        }
        if self.btc.skipped_addresses > 0 {
            items.push(Item::Banner(
                text::SKIPPED_ADDRESSES.fill(lang, [&self.btc.skipped_addresses.to_string()]),
                Tone::Warn,
            ));
        }
        if !self.btc.hint_mismatch.is_empty() {
            items.push(Item::Banner(
                text::HINT_MISMATCH.fill(lang, [&self.btc.hint_mismatch.len().to_string()]),
                Tone::Warn,
            ));
        }
        if self.btc.auto_frozen > 0 {
            items.push(Item::Banner(
                text::AUTO_FROZEN.fill(lang, [&self.btc.auto_frozen.to_string()]),
                Tone::Info,
            ));
        }
    }

    fn btc_utxo_items(&self, ctx: &BtcCtx<'_>, items: &mut Vec<Item>) {
        let lang = ctx.lang;
        items.push(Item::Subtitle(text::UTXO_TITLE.get(lang).to_owned()));
        items.push(Item::Help(text::UTXO_HELP.get(lang).to_owned()));
        let utxos = self.btc.utxos(ctx);
        if utxos.is_empty() {
            items.push(Item::Help(text::NO_UTXOS.get(lang).to_owned()));
        }
        let can_freeze = self.btc_unlocked() && ctx.mismatch().is_none();
        for (row, utxo) in utxos.iter().take(usize::from(ids::UTXO_SPAN)).enumerate() {
            let mut line = format!(
                "{} · {}",
                BtcUi::amount_text(utxo.value),
                confirmations_text(lang, utxo.confirmations)
            );
            let mut mark = |text: Text| {
                line.push_str(" · ");
                line.push_str(text.get(lang));
            };
            match utxo.frozen {
                Some(FreezeReason::User) => mark(text::UTXO_FROZEN),
                Some(FreezeReason::Auto) => mark(text::UTXO_AUTO_FROZEN),
                None => {}
            }
            if utxo.in_flight {
                mark(text::UTXO_IN_FLIGHT);
            }
            if utxo.own {
                mark(text::UTXO_OWN);
            }
            if utxo.hint_mismatch {
                mark(text::UTXO_HINT);
            }
            if utxo.indexer_only {
                mark(crate::app_btc::INDEXER_ONLY);
            }
            items.push(Item::Text(line));
            items.push(Item::Mono(utxo.outpoint.to_string()));
            let id = ids::UTXO_BASE.saturating_add(u16::try_from(row).unwrap_or(0));
            let label = if utxo.frozen.is_some() {
                text::UNFREEZE
            } else {
                text::FREEZE
            }
            .get(lang);
            items.push(Item::Row(vec![
                Ctl::button(id, label).enabled(can_freeze && !utxo.in_flight),
            ]));
        }
        let hidden = utxos.len().saturating_sub(usize::from(ids::UTXO_SPAN));
        if hidden > 0 {
            items.push(Item::Muted(
                text::UTXO_HIDDEN.fill(lang, [&hidden.to_string(), &ids::UTXO_SPAN.to_string()]),
            ));
        }
    }

    #[expect(clippy::too_many_lines, reason = "one block per activity button")]
    fn btc_activity_items(&self, ctx: &BtcCtx<'_>, items: &mut Vec<Item>) {
        let lang = ctx.lang;
        items.push(Item::Badged(
            Badge::bitcoin(ctx.net()),
            Box::new(Item::Subtitle(text::ACTIVITY_TITLE.get(lang).to_owned())),
        ));
        let mut prompt_drawn = false;
        let rows = self.btc.activity_rows(ctx);
        if rows.is_empty() {
            items.push(Item::Help(text::NO_ACTIVITY.get(lang).to_owned()));
        }
        let usable = ctx.gate().is_ok();
        let unlocked = self.btc_unlocked();
        // Display-only names of the recipients (2026-11-10, like EVM's U11): an address-book
        // entry or one of the wallet's own accounts; earlier recipients are not named.
        let known = if rows.iter().any(|row| !row.counterparty.is_empty()) {
            crate::app_btc::known_addresses_on(ctx, ctx.net())
        } else {
            Vec::new()
        };
        for (index, row) in rows.iter().enumerate() {
            let base = ids::ACTIVITY_BASE.saturating_add(
                u16::try_from(index)
                    .unwrap_or(0)
                    .saturating_mul(ids::ACTIVITY_STRIDE),
            );
            // The status at the end of the first line (2026-11-12: a line of its own before).
            items.push(Item::Text(format!(
                "{} · {} · {} · {}",
                local_time(row.time_unix_ms),
                active_label(ctx),
                row.title,
                row.status
            )));
            let lower = row.counterparty.to_ascii_lowercase();
            let name = known
                .iter()
                .filter(|entry| entry.address == lower)
                .find_map(|entry| match &entry.source {
                    crate::app_btc::BtcKnownSource::Book { label, .. } => {
                        Some(format!(" {}", text::TO_BOOK.fill(lang, [label])))
                    }
                    crate::app_btc::BtcKnownSource::Own { account } => {
                        Some(format!(" {}", text::TO_OWN.fill(lang, [account])))
                    }
                    crate::app_btc::BtcKnownSource::Sent => None,
                })
                .unwrap_or_default();
            if let Some(amount) = row.amount {
                items.push(Item::Muted(
                    text::ROW_AMOUNT_TO.fill(lang, [&BtcUi::amount_text(amount), &name]),
                ));
            } else if !row.counterparty.is_empty() {
                items.push(Item::Muted(text::ROW_TO.fill(lang, [&name])));
            }
            // 2026-11-11: the recipient whole (ends emphasized) and the txid on lines of their
            // own; a click copies either (the wallet's own signed journal — the received
            // history's senders never are), the explorer and address-book actions are icons at
            // the right end of their line.
            if !row.counterparty.is_empty() {
                let save = self.offer_save(BookChain::Btc, &row.counterparty).then(|| {
                    crate::ui::screens_links::save_icon(
                        self.settings.language,
                        base.saturating_add(ids::ACT_SAVE),
                    )
                });
                crate::ui::screens_links::push_address_line(
                    items,
                    self.settings.language,
                    crate::ui::screens_links::ids::row_id(
                        crate::ui::screens_links::ids::BTC_TO_BASE,
                        crate::ui::screens_links::ids::BTC_TO_SPAN,
                        index,
                    ),
                    &row.counterparty,
                    crate::ui::theme::AddressKind::Bitcoin,
                    save.into_iter().collect(),
                );
            }
            crate::ui::screens_links::push_hash_line(
                items,
                self.settings.language,
                Some(base.saturating_add(ids::ACT_COPY)),
                &row.txid,
                self.explorer_tx_icons(
                    crate::network::NetworkId::Bitcoin(self.settings.bitcoin.network),
                    &row.txid,
                    crate::ui::screens_explorer::ids::activity_ids(
                        crate::ui::screens_explorer::ids::BTC_ACTIVITY_BASE,
                        crate::ui::screens_explorer::ids::BTC_ACTIVITY_SPAN,
                        index,
                    ),
                ),
            );
            let flow = Txid::from_display_hex(&row.txid)
                .ok()
                .and_then(|txid| self.btc.flow(&txid));
            if let Some(stage) = flow.and_then(|flow| flow_stage_text(lang, flow.stage)) {
                items.push(Item::Muted(stage.to_owned()));
            }
            if let Some(note) = &row.note {
                let waiting = flow.is_some_and(|flow| flow.stage == BtcFlowStage::Waiting);
                items.push(Item::Banner(
                    note.clone(),
                    if waiting { Tone::Warn } else { Tone::Info },
                ));
            }
            let mut buttons = Vec::new();
            if row.can_bump {
                buttons.push(
                    Ctl::button(base.saturating_add(ids::ACT_BUMP), text::BUMP_FEE.get(lang))
                        .enabled(usable),
                );
            }
            if row.can_rebroadcast {
                buttons.push(
                    Ctl::button(
                        base.saturating_add(ids::ACT_REBROADCAST),
                        text::REBROADCAST.get(lang),
                    )
                    .enabled(usable),
                );
            }
            if row.can_abandon {
                buttons.push(
                    Ctl::button(
                        base.saturating_add(ids::ACT_ABANDON),
                        text::ABANDON.get(lang),
                    )
                    .enabled(unlocked),
                );
            }
            if row.can_esplora {
                buttons.push(
                    Ctl::button(
                        base.saturating_add(ids::ACT_ESPLORA),
                        text::ESPLORA_SEND.get(lang),
                    )
                    .enabled(usable),
                );
            }
            if row.can_continue {
                let retry = flow.is_some_and(|flow| flow.retry_precheck);
                buttons.push(
                    Ctl::button(
                        base.saturating_add(ids::ACT_CONTINUE),
                        if retry {
                            text::RETRY
                        } else {
                            text::CONTINUE_SEND
                        }
                        .get(lang),
                    )
                    .enabled(usable),
                );
                buttons.push(
                    Ctl::button(base.saturating_add(ids::ACT_CANCEL), text::CANCEL.get(lang))
                        .enabled(unlocked),
                );
            }
            if !buttons.is_empty() {
                items.push(Item::Row(buttons));
            }
            if !prompt_drawn && !row.counterparty.is_empty() {
                prompt_drawn = self.prompt_items(
                    PromptPlace::Activity,
                    BookChain::Btc,
                    &row.counterparty,
                    items,
                );
            }
            items.push(Item::Gap(4));
        }
    }

    /// The tab while Bitcoin is off (`설정 → Bitcoin`; a key-only wallet without a Bitcoin key
    /// may import one now).
    fn btc_disabled_items(&self, ctx: &BtcCtx<'_>, items: &mut Vec<Item>) {
        let lang = ctx.lang;
        items.push(Item::CardStart(Some("Bitcoin".to_owned())));
        items.push(Item::Text(BtcGate::Disabled.text(lang)));
        items.push(Item::Help(
            if ctx.has_mnemonic {
                text::DISABLED_HELP_MNEMONIC
            } else {
                text::DISABLED_HELP_KEYS
            }
            .get(lang)
            .to_owned(),
        ));
        items.push(Item::Row(vec![Ctl::primary(
            ids::SECTION_BTC,
            text::BTC_SETTINGS.get(lang),
        )]));
        items.push(Item::CardEnd);
        if !ctx.has_mnemonic
            && ctx
                .meta
                .is_some_and(|meta| meta.btc_accounts.accounts.is_empty())
        {
            // A key-only wallet without a Bitcoin key: it can be imported now (the account
            // waits for Bitcoin to be turned on).
            self.no_accounts_card(yw_core::keyimport::ImportChain::Btc, items);
        }
    }

    /// The S10 Bitcoin tab.
    pub fn btc_main_screen(&self, items: &mut Vec<Item>) {
        let ctx = self.btc_ctx();
        let net = ctx.net();
        let lang = ctx.lang;
        if !ctx.settings.enabled {
            self.btc_disabled_items(&ctx, items);
            return;
        }
        items.push(Item::CardStart(None));
        // The network as a small tag on a `네트워크` line like the other tabs (2026-11-11; the
        // send, receive and result screens keep the full band of spec/08 §2).
        items.push(Item::LabeledRow(
            text::NETWORK.get(lang).to_owned(),
            Vec::new(),
        ));
        items.push(Item::Pill(
            net.banner_in(lang).to_owned(),
            network_tone(net),
        ));
        let gate = ctx.gate();
        if let Err(reason) = gate {
            Self::btc_gate_items(lang, reason, items);
        }
        let mismatch = matches!(gate, Err(BtcGate::Mismatch { .. }));
        if ctx.journal_damaged() {
            items.push(Item::Banner(
                text::JOURNAL_DAMAGED.get(lang).to_owned(),
                Tone::Blocked,
            ));
        }
        if let Some(text) = self.btc.blocked.as_ref().filter(|_| !mismatch) {
            items.push(Item::Banner(text.clone(), Tone::Blocked));
            if self.btc.tip_regressed {
                items.push(Item::Help(text::TIP_REGRESSED_HELP.get(lang).to_owned()));
                items.push(Item::Row(vec![
                    Ctl::button(ids::RESET_TIP, text::RESET_TIP.get(lang))
                        .enabled(self.btc_unlocked()),
                ]));
            }
        }
        if let Some(lag) = self.btc.lag_warning {
            items.push(Item::Banner(
                crate::btc::chain::lag_warning_text(lang, lag),
                Tone::Warn,
            ));
        }
        if let Some(text) = &self.btc.status_error {
            items.push(Item::Banner(text.clone(), Tone::Danger));
        }
        items.push(Item::Help(self.btc_status_line(&ctx)));
        let signed = self.btc.signed_records(&ctx).len();
        if signed > 0 {
            items.push(Item::Banner(
                text::SIGNED_PENDING.fill(lang, [&signed.to_string()]),
                Tone::Warn,
            ));
        }
        self.btc_discovery_items(&ctx, items);
        let usable = gate.is_ok();
        self.btc_discover_row(&ctx, usable, items);
        items.push(Item::CardEnd);
        // `YubiKey` accounts (spec/10 §13) are listed even before BIP84 account 0 exists.
        let has_hardware = ctx
            .accounts()
            .iter()
            .any(|meta| meta.account().is_hardware());
        let show_accounts = (ctx.primary_meta().is_some() || !ctx.has_mnemonic || has_hardware)
            && ctx.mismatch().is_none();
        if ctx.btc_meta().is_none() && !ctx.has_mnemonic {
            // A key-only wallet without a Bitcoin key yet: only the account card.
            if show_accounts {
                items.push(Item::CardStart(None));
                self.btc_account_items(&ctx, items);
                items.push(Item::CardEnd);
            }
            return;
        }
        // Same order as the EVM and Solana tabs (spec/04 §2.6): the selected account's balance
        // with `보내기`·`받기` first, then the account list.
        self.btc_selected_card(&ctx, usable, items);
        // The account card: a mnemonic wallet once BIP84 account 0 exists, a key-only wallet
        // always (its imported keys are its accounts).
        if show_accounts {
            items.push(Item::CardStart(None));
            self.btc_account_items(&ctx, items);
            items.push(Item::CardEnd);
        }
        items.push(Item::CardStart(None));
        self.btc_utxo_items(&ctx, items);
        items.push(Item::CardEnd);
        items.push(Item::CardStart(None));
        self.btc_activity_items(&ctx, items);
        self.received_items(crate::received::RecvChain::Btc, items);
        items.push(Item::CardEnd);
    }

    /// The selected account card, in one layout with the other tabs (2026-11-11): name, path
    /// and type, balance, status, the address with `주소 복사`, then 보내기 · 받기 · 새로고침.
    fn btc_selected_card(&self, ctx: &BtcCtx<'_>, usable: bool, items: &mut Vec<Item>) {
        let lang = ctx.lang;
        items.push(Item::CardStart(None));
        self.btc_balance_items(ctx, items);
        if let Some(address) = self.btc_card_address() {
            items.push(crate::ui::screens::own_address_row(
                self.settings.language,
                &address,
                crate::ui::theme::AddressKind::Bitcoin,
                ids::CARD_COPY,
                true,
                self.explorer_address_icon(
                    crate::network::NetworkId::Bitcoin(self.settings.bitcoin.network),
                    &address,
                    crate::ui::screens_explorer::ids::CARD_BTC,
                ),
            ));
        } else if usable && ctx.btc_meta().is_some() {
            // HD mode with every issued address used: `받기` issues the next one.
            items.push(Item::Help(text::RECEIVE_HINT.get(lang).to_owned()));
        }
        let send_block = self.btc.send_block(ctx);
        let mut actions = vec![
            Ctl::primary(ids::SEND_OPEN, text::SEND.get(lang)).enabled(send_block.is_none()),
            Ctl::primary(ids::RECEIVE_OPEN, text::RECEIVE.get(lang)).enabled(self.btc_unlocked()),
        ];
        if BtcUi::bump_target(ctx).is_some() {
            actions.push(
                Ctl::button(ids::BUMP_OPEN, text::BUMP_FEE.get(lang))
                    .enabled(usable && !self.btc.slot && !ctx.journal_damaged()),
            );
        }
        actions.push(
            Ctl::link(ids::REFRESH, text::REFRESH.get(lang))
                .tip(crate::ui::screens::T_REFRESH_TIP.get(self.settings.language))
                .enabled(usable && !self.btc.refresh.busy && !self.btc.discovery.running),
        );
        items.push(Item::Row(actions));
        if self.btc.refresh.busy {
            items.push(Item::Help(text::REFRESHING.get(lang).to_owned()));
        }
        if let Some(reason) = send_block {
            items.push(Item::Help(text::SEND_BLOCKED.fill(lang, [&reason])));
        }
        items.push(Item::CardEnd);
    }

    /// The send form's fee estimate before `검토` (spec/08 §8, 2026-11-10): with a valid recipient
    /// and a typed amount, the chosen rate × the local vsize of one input of the account's type
    /// and two outputs (recipient, change) — `estimate_weight_with`, no call. Display only: `검토`
    /// plans with the node's fresh estimate and floor, and the approval shows the real fee.
    fn btc_fee_estimate_items(
        &self,
        fee: &BtcFeeForm,
        quote: Option<&FeeQuote>,
        items: &mut Vec<Item>,
    ) {
        let form = &self.btc.send;
        let (Some(recipient), Some(_)) = (form.recipient, form.amount) else {
            return;
        };
        if form.send_max || form.recipient_error.is_some() || form.amount_error.is_some() {
            return;
        }
        let rate = match fee.choice {
            BtcFeeChoice::Manual => fee.manual,
            choice => quoted_rate(choice, quote),
        };
        let ctx = self.btc_ctx();
        let lang = ctx.lang;
        let (Some(rate), Some(meta)) = (rate, ctx.btc_meta()) else {
            return;
        };
        let account = meta.account();
        let Some(weight) = yw_core::btc::tx::estimate_weight_with(
            account.input_weight(),
            1,
            &[
                yw_core::btc::script::spk_len(&recipient),
                account.script_type().spk_len(),
            ],
        ) else {
            return;
        };
        let vsize = weight.div_ceil(4);
        let Some(estimate) = yw_core::btc::fee::fee_for(rate, vsize) else {
            return;
        };
        // A label-value row and one muted line (2026-11-12, was a three-sentence paragraph).
        items.push(Item::Field(
            text::EXPECTED_FEE.get(lang).to_owned(),
            text::FEE_ABOUT.fill(
                lang,
                [
                    &yw_core::btc::amount::format_sats_grouped(estimate.get()),
                    &yw_core::btc::amount::format_btc(estimate),
                ],
            ),
        ));
        items.push(Item::Help(text::FEE_ESTIMATE_HELP.get(lang).to_owned()));
        if rate.sat_per_kvb() > yw_core::btc::BTC_FEE_RATE_CAP
            || estimate.get() > yw_core::btc::BTC_FEE_ABS_CAP
        {
            items.push(Item::Banner(
                text::FEE_OVER_CAP.get(lang).to_owned(),
                Tone::Warn,
            ));
        }
    }

    /// The fee radios, manual rate, floor note and typed-fee override of a form. The send form's
    /// radios carry the node's preview (2026-11-10, `BtcUi::fee_quote`): "빠름 · 약 20분 · 12
    /// sat/vB" (the floor when the estimate is below it), "· 추정 없음", or a loading line.
    fn btc_fee_items(&self, fee: &BtcFeeForm, bump: bool, items: &mut Vec<Item>) {
        let radio_ids = fee_ids(bump);
        let lang = self.settings.language;
        let net = self.btc_ctx().net();
        let quote = if bump {
            None
        } else {
            self.btc.fee_quote_of(net).copied()
        };
        let loading = !bump && quote.is_none() && self.btc.fee_quote_job.is_some();
        let radios = FEE_CHOICES
            .iter()
            .zip(radio_ids)
            .enumerate()
            .map(|(index, (choice, id))| {
                let label = if bump {
                    choice.label(lang).to_owned()
                } else {
                    fee_choice_label(lang, *choice, quote.as_ref())
                };
                Ctl::radio(id, &label, fee.choice == *choice, index == 0)
            })
            .collect();
        items.push(Item::LabeledRow(text::FEE.get(lang).to_owned(), radios));
        if loading {
            items.push(Item::Help(text::FEE_LOADING.get(lang).to_owned()));
        }
        // The send form's radios say the wait and the rate themselves: the note only when one
        // of them has no estimate (2026-11-12). The bump form's radios are bare.
        let missing = FEE_CHOICES.iter().any(|choice| {
            *choice != BtcFeeChoice::Manual && quoted_rate(*choice, quote.as_ref()).is_none()
        });
        if bump || (missing && !loading) {
            items.push(Item::Help(text::FEE_CHOICE_HELP.get(lang).to_owned()));
        }
        if fee.choice == BtcFeeChoice::Manual {
            let id = if bump {
                ids::BUMP_MANUAL_EDIT
            } else {
                ids::FEE_MANUAL_EDIT
            };
            items.push(Item::LabeledRow(
                text::FEE_RATE_LABEL.get(lang).to_owned(),
                vec![Ctl::edit(id, &fee.manual_text, 160, false, 12)],
            ));
        }
        // The preview's floor fills the line before `검토` (2026-11-10).
        let floor = quote.map(|quote| quote.floor).or(self.btc.floor);
        // On the send form only where the floor matters (2026-11-12): `직접 입력`, or a chosen
        // estimate below it (`FEE_CHOICES` starts with the three estimates in `rates` order).
        let floored = quote.is_some_and(|quote| {
            FEE_CHOICES.iter().zip(quote.rates).any(|(choice, rate)| {
                *choice == fee.choice && rate.is_some_and(|rate| rate < quote.floor)
            })
        });
        if bump || fee.choice == BtcFeeChoice::Manual || floored {
            items.push(Item::Help(match floor {
                Some(floor) => text::FLOOR_NOTE.fill(lang, [&floor.to_string()]),
                None => text::FLOOR_UNKNOWN.get(lang).to_owned(),
            }));
        }
        if !bump {
            self.btc_fee_estimate_items(fee, quote.as_ref(), items);
        }
        if let Some(error) = &fee.error {
            items.push(Item::Banner(error.clone(), Tone::Danger));
        }
        if let Some(planned) = fee.needs_typed {
            items.push(Item::Banner(
                text::TYPED_FEE_BANNER.fill(lang, [&BtcUi::amount_text(planned)]),
                Tone::Warn,
            ));
            let id = if bump {
                ids::BUMP_TYPED_EDIT
            } else {
                ids::TYPED_FEE_EDIT
            };
            items.push(Item::LabeledRow(
                text::TYPED_FEE_LABEL.get(lang).to_owned(),
                vec![Ctl::edit(id, &fee.typed_text, 200, false, 20)],
            ));
        }
    }

    /// S11 for Bitcoin (spec/08 §7–§8, spec/04 §2.7).
    #[expect(clippy::too_many_lines, reason = "the Bitcoin S11 fields in order")]
    pub fn btc_send_screen(&self, items: &mut Vec<Item>) {
        let ctx = self.btc_ctx();
        let net = ctx.net();
        let lang = ctx.lang;
        items.push(crate::ui::screens::back_main(self.settings.language));
        items.push(Item::Badged(
            Badge::bitcoin(net),
            Box::new(Item::Title(
                text::SEND_TITLE.fill(lang, [net.display_name_in(lang)]),
            )),
        ));
        network_banners(lang, net, items);
        let form = &self.btc.send;
        // Why the form cannot send at all is said first; what `검토` ended with is said next
        // to the button (below).
        let block = self.btc.send_block(&ctx);
        if let Some(reason) = &block {
            items.push(Item::Banner(reason.clone(), Tone::Warn));
        }
        if ctx.journal_damaged() {
            items.push(Item::Banner(
                text::JOURNAL_DAMAGED.get(lang).to_owned(),
                Tone::Blocked,
            ));
        }
        items.push(Item::CardStart(Some(
            text::FROM_ACCOUNT.get(lang).to_owned(),
        )));
        items.push(Item::Text(active_label(&ctx)));
        items.push(Item::Help(active_detail(&ctx)));
        if let Some(balance) = self.btc.balance(&ctx) {
            items.push(Item::Help(
                text::AVAILABLE_VERIFIED.fill(lang, [&BtcUi::amount_text(balance.available)]),
            ));
        }
        self.mn_signing_banner(self.btc_backup_gate(), items);
        self.card_pin_banner(self.btc_selected_card_gate(), items);
        items.push(Item::CardEnd);
        items.push(Item::CardStart(Some(
            text::RECIPIENT_CARD.get(lang).to_owned(),
        )));
        let target = BookTarget::Btc(net);
        self.favorite_chip_items(target, items);
        items.push(Item::LabeledRow(
            text::RECIPIENT_ADDRESS.get(lang).to_owned(),
            vec![
                Ctl::edit(ids::SEND_TO_EDIT, &form.to_text, 430, false, 128),
                Ctl::button(
                    crate::ui::screens_book::ids::BTC_PICK,
                    text::PICK_FROM_BOOK.get(lang),
                ),
            ],
        ));
        // The format hint only until the address is valid (2026-11-12); the reminder to check
        // all of it then sits under the grouped address.
        if form.recipient.is_none() || form.recipient_error.is_some() {
            items.push(Item::Help(text::ADDRESS_HINT.get(lang).to_owned()));
        }
        self.btc_picker_items(target, items);
        if let Some(error) = &form.recipient_error {
            items.push(Item::Banner(error.clone(), Tone::Danger));
        } else if let Some(kind) = form.recipient {
            items.push(Item::Help(
                text::ADDRESS_KIND.fill(lang, [kind_text(lang, &kind)]),
            ));
            let address = encode_address(&kind, net);
            items.push(Item::Mono(grouped(&address)));
            items.push(Item::Help(text::CHECK_WHOLE.get(lang).to_owned()));
            let entry = self
                .meta
                .as_ref()
                .and_then(|meta| meta.contact(BookChain::Btc, &address));
            if let Some(entry) = &entry {
                let verified = if entry.verified {
                    format!(" {}", text::VERIFIED.get(lang))
                } else {
                    String::new()
                };
                items.push(Item::Banner(
                    text::BOOK_ENTRY.fill(lang, [&entry.label, &verified]),
                    Tone::Info,
                ));
            }
            if let Some(note) = &form.look_alike {
                items.push(Item::Banner(note.clone(), Tone::HighRisk));
                items.push(Item::Row(vec![Ctl::check(
                    ids::SEND_ADDR_ACK,
                    text::ADDR_ACK.get(lang),
                    form.ack,
                )]));
                if entry.as_ref().is_some_and(|entry| !entry.verified) {
                    items.push(Item::Help(
                        crate::app_book::text::BOOK_VERIFY_HINT
                            .get(self.settings.language)
                            .to_owned(),
                    ));
                }
            }
            self.recipient_save_items(target, items);
        }
        items.push(Item::CardEnd);
        items.push(Item::CardStart(Some(
            text::AMOUNT_CARD.get(lang).to_owned(),
        )));
        // What `최대` can send, next to the amount (2026-11-12; only in the sender card before).
        items.push(Item::Help(self.btc.balance(&ctx).map_or_else(
            || text::AVAILABLE_UNREAD.get(lang).to_owned(),
            |balance| text::AVAILABLE.fill(lang, [&BtcUi::amount_text(balance.available)]),
        )));
        items.push(Item::LabeledRow(
            text::AMOUNT.get(lang).to_owned(),
            vec![
                Ctl::edit(ids::SEND_AMOUNT_EDIT, &form.amount_text, 220, false, 32)
                    .enabled(!form.send_max),
                // Right after the field like every chain's `최대` (2026-11-12), then the unit.
                Ctl::tab(ids::SEND_MAX, text::MAX.get(lang), form.send_max),
                Ctl::radio(
                    ids::UNIT_BTC,
                    "BTC",
                    form.unit == crate::app_btc::BtcAmountUnit::Btc,
                    true,
                ),
                Ctl::radio(
                    ids::UNIT_SATS,
                    "sats",
                    form.unit == crate::app_btc::BtcAmountUnit::Sats,
                    false,
                ),
            ],
        ));
        if let Some(error) = &form.amount_error {
            items.push(Item::Banner(error.clone(), Tone::Danger));
        } else if let Some(amount) = form.amount {
            items.push(Item::Help(BtcUi::amount_text(amount)));
        }
        if form.send_max {
            items.push(Item::Help(text::MAX_HELP.get(lang).to_owned()));
        }
        // Only until the amount is valid (2026-11-12).
        if !form.send_max && form.amount.is_none() {
            items.push(Item::Help(text::AMOUNT_HINT.get(lang).to_owned()));
        }
        items.push(Item::Rule);
        self.btc_fee_items(&form.fee, false, items);
        // `검토`'s progress, a plan the node refused (funds, dust, no fee estimate, tip ahead),
        // an expired approval or a signature that failed: next to the button, where the user
        // pressed it (the top of the form is below the fold by then).
        if let Some(info) = form
            .info
            .as_ref()
            .filter(|info| block.as_ref() != Some(*info))
        {
            items.push(Item::Banner(
                info.clone(),
                if info.as_str() == crate::app_btc::BTC_PREPARING.get(lang) {
                    Tone::Info
                } else {
                    Tone::Warn
                },
            ));
        }
        items.push(Item::CardEnd);
        self.journal_send_items(crate::app_sidecar::SendChain::Btc, items);
        let blocker = self.btc_review_blocker();
        items.push(Item::Row(vec![
            Ctl::primary(ids::SEND_REVIEW, text::REVIEW.get(lang)).enabled(blocker.is_none()),
            Ctl::button(ids::SEND_CANCEL, text::CANCEL.get(lang)),
        ]));
        // What `검토` waits for, or that it sends nothing yet (2026-11-12).
        items.push(Item::Help(
            crate::app_sol::ReviewBlocker::line(self.settings.language, blocker).to_owned(),
        ));
    }

    /// Whether the send form's `검토` is enabled: the controller's checks, an account whose
    /// phrase has passed its backup quiz (U7; the band above says why), and after a journal reset
    /// the check above the button.
    #[must_use]
    pub fn btc_can_review(&self) -> bool {
        self.btc_review_blocker().is_none()
    }

    /// Why the send form's `검토` is off, `None` when it is on (2026-11-12: the line under the
    /// button).
    #[must_use]
    pub fn btc_review_blocker(&self) -> Option<crate::app_sol::ReviewBlocker> {
        let held = self.mn_send_blocked(self.btc_backup_gate())
            // spec/10 §9.3: the YubiKey is still on its factory PINs (the band says so).
            || self.btc_selected_card_gate().is_some()
            || self
                .journal_hold(crate::app_sidecar::SendChain::Btc)
                .is_some();
        if held {
            return Some(crate::app_sol::ReviewBlocker::Held);
        }
        self.btc.review_blocker(&self.btc_ctx())
    }

    /// Whether the fee-bump form's `검토` is enabled.
    #[must_use]
    pub fn btc_can_review_bump(&self) -> bool {
        let ctx = self.btc_ctx();
        let form = &self.btc.bump;
        ctx.gate().is_ok()
            && !ctx.journal_damaged()
            && !self.btc.slot
            && form.preparing.is_none()
            && form.fee.error.is_none()
            && (form.fee.choice != BtcFeeChoice::Manual || form.fee.manual.is_some())
            && BtcUi::bump_target(&ctx).is_some()
    }

    /// The fee-bump form (spec/08 §9).
    pub fn btc_bump_screen(&self, items: &mut Vec<Item>) {
        let ctx = self.btc_ctx();
        let net = ctx.net();
        let lang = ctx.lang;
        items.push(crate::ui::screens::back_main(self.settings.language));
        items.push(Item::Title(
            text::BUMP_TITLE.fill(lang, [net.display_name_in(lang)]),
        ));
        network_banners(lang, net, items);
        let form = &self.btc.bump;
        if let Some(info) = &form.info {
            items.push(Item::Banner(info.clone(), Tone::Warn));
        }
        if ctx.journal_damaged() {
            items.push(Item::Banner(
                text::JOURNAL_DAMAGED.get(lang).to_owned(),
                Tone::Danger,
            ));
        }
        let target = form
            .target
            .and_then(|txid| ctx.record(&txid))
            .or_else(|| BtcUi::bump_target(&ctx));
        if let Some(record) = target {
            items.push(Item::Text(text::REPLACED_TX.get(lang).to_owned()));
            items.push(Item::Mono(record.txid.to_display_hex()));
            items.push(Item::Muted(
                text::STATUS.fill(lang, [&record_status(lang, &record, self.btc_tip(&ctx))]),
            ));
            items.push(Item::Muted(text::CURRENT_FEE.fill(
                lang,
                [
                    &BtcUi::amount_text(record.fee),
                    &record_rate(record.fee, record.vsize),
                ],
            )));
            if let Some(amount) = record.recipient_amount() {
                let note = if record.send_max {
                    format!(" {}", text::BUMP_SEND_MAX_NOTE.get(lang))
                } else {
                    String::new()
                };
                items.push(Item::Muted(
                    text::BUMP_AMOUNT.fill(lang, [&BtcUi::amount_text(amount), &note]),
                ));
            }
            if let Some(address) = record.recipient_address() {
                items.push(Item::Mono(grouped(&address)));
            }
        } else {
            items.push(Item::Muted(texts::NOT_BUMPABLE.get(lang).to_owned()));
        }
        items.push(Item::Muted(text::BUMP_HELP.get(lang).to_owned()));
        self.btc_fee_items(&form.fee, true, items);
        items.push(Item::Row(vec![
            Ctl::primary(ids::BUMP_REVIEW, text::REVIEW.get(lang))
                .enabled(self.btc_can_review_bump()),
            Ctl::button(ids::BUMP_CANCEL, text::CANCEL.get(lang)),
        ]));
    }

    /// The S11 result for Bitcoin: the local txid, status and the post-sign flow.
    #[expect(
        clippy::too_many_lines,
        reason = "the result rows and buttons in order"
    )]
    pub fn btc_send_result_screen(&self, items: &mut Vec<Item>) {
        let ctx = self.btc_ctx();
        let net = ctx.net();
        let lang = ctx.lang;
        let record = self.btc.result.and_then(|txid| ctx.record(&txid));
        let bump = record
            .as_ref()
            .is_some_and(|record| record.replaces.is_some());
        items.push(Item::Title(
            if bump {
                text::RESULT_BUMP
            } else {
                text::RESULT_SEND
            }
            .get(lang)
            .to_owned(),
        ));
        network_banners(lang, net, items);
        let Some(txid) = self.btc.result else {
            items.push(Item::Muted(text::NO_RESULT.get(lang).to_owned()));
            items.push(Item::Row(vec![Ctl::button(
                crate::ui::screens::ids::BACK_MAIN,
                text::BACK_MAIN.get(lang),
            )]));
            return;
        };
        items.push(Item::Banner(
            text::SIGNED_BANNER.get(lang).to_owned(),
            Tone::Success,
        ));
        items.push(Item::Mono(txid.to_display_hex()));
        let status = record.as_ref().map_or_else(
            || text::FINISHED_SEE_ACTIVITY.get(lang).to_owned(),
            |record| record_status(lang, record, self.btc_tip(&ctx)),
        );
        items.push(Item::Badged(
            Badge::bitcoin(net),
            Box::new(Item::Muted(
                text::RESULT_STATUS.fill(lang, [&status, net.display_name_in(lang)]),
            )),
        ));
        let flow = self.btc.flow(&txid);
        if let Some(stage) = flow.and_then(|flow| flow_stage_text(lang, flow.stage)) {
            items.push(Item::Muted(stage.to_owned()));
        }
        if let Some(note) = flow.and_then(|flow| flow.note.clone()) {
            let waiting = flow.is_some_and(|flow| flow.stage == BtcFlowStage::Waiting);
            items.push(Item::Banner(
                note,
                if waiting { Tone::Warn } else { Tone::Info },
            ));
        }
        let mut row = vec![Ctl::button(ids::RESULT_COPY, text::COPY_HASH.get(lang))];
        // 2026-11-11: the txid on the network's explorer (also before the broadcast is known:
        // the page then says it does not know the transaction yet).
        row.extend(self.explorer_tx_buttons(
            crate::network::NetworkId::Bitcoin(self.settings.bitcoin.network),
            &txid.to_display_hex(),
            Some((
                crate::ui::screens_explorer::ids::RESULT_BTC_OPEN,
                crate::ui::screens_explorer::ids::RESULT_BTC_COPY,
            )),
        ));
        let signed = record
            .as_ref()
            .is_some_and(|record| record.state == yw_core::journal::btc::BtcTxState::Signed);
        if signed
            && flow.is_some_and(|flow| flow.retry_precheck && flow.stage == BtcFlowStage::Waiting)
        {
            row.push(
                Ctl::button(ids::RESULT_RETRY, text::RETRY.get(lang)).enabled(ctx.gate().is_ok()),
            );
        }
        let rejected = record
            .as_ref()
            .filter(|record| record.state == yw_core::journal::btc::BtcTxState::Rejected);
        if let Some(rejected) = rejected
            && !bump
        {
            items.push(Item::Muted(
                if rejected.disclosed {
                    yw_core::btc::policy::texts::REJECTED_DISCLOSED
                } else {
                    text::NOT_SENT_KEPT
                }
                .get(lang)
                .to_owned(),
            ));
            row.push(Ctl::button(
                ids::RESULT_TO_SEND,
                text::TO_SEND_SCREEN.get(lang),
            ));
        }
        row.insert(
            0,
            Ctl::primary(
                crate::ui::screens::ids::BACK_MAIN,
                text::BACK_MAIN.get(lang),
            ),
        );
        items.push(Item::Row(row));
        if !bump {
            self.result_save_items(BookTarget::Btc(net), items);
        }
    }

    /// S12 for Bitcoin (spec/08 §3.2): the address appears only after `receive_next` is stored.
    pub fn btc_receive_screen(&self, items: &mut Vec<Item>) {
        let ctx = self.btc_ctx();
        let net = self
            .btc
            .receive
            .as_ref()
            .map_or_else(|| ctx.net(), |view| view.network);
        let lang = ctx.lang;
        items.push(crate::ui::screens::back_main(self.settings.language));
        items.push(Item::Badged(
            Badge::bitcoin(net),
            Box::new(Item::Title(
                text::RECEIVE_TITLE.fill(lang, [net.display_name_in(lang)]),
            )),
        ));
        network_banners(lang, net, items);
        if let Some(message) = &self.btc.receive_message {
            items.push(Item::Banner(message.clone(), Tone::Danger));
        }
        // An HD account of the primary phrase or an EVM key's use is the primary phrase's key.
        self.mn_receive_banner(self.btc_backup_gate(), items);
        let Some(view) = &self.btc.receive else {
            if self.btc.receive_message.is_none() {
                items.push(Item::Muted(text::PREPARING_ADDRESS.get(lang).to_owned()));
            }
            return;
        };
        items.push(Item::CardStart(Some(if view.single_key {
            view.account.clone()
        } else if view.fixed {
            text::FIXED_ADDRESS.fill(lang, [&view.account])
        } else {
            text::RECEIVE_INDEX.fill(lang, [&view.account, &view.index.to_string()])
        })));
        items.push(Item::Text(text::ADDRESS_FORMAT.fill(lang, [&view.kind])));
        if view.fixed && !view.single_key {
            // An HD account in fixed-address mode (spec/08 §3.5): said before the QR.
            items.push(Item::Banner(
                crate::app_btc::T_BTC_FIXED_RECEIVE.get(lang).to_owned(),
                Tone::Info,
            ));
        }
        // The address on its copy line with `새 주소` beside it, then the QR (2026-11-12, all
        // chains); the account's note follows the QR.
        let mut actions = Vec::new();
        if !view.fixed {
            actions.push(
                Ctl::button(ids::NEW_ADDRESS, text::NEW_ADDRESS.get(lang))
                    .compact()
                    .enabled(ctx.gate().is_ok()),
            );
        }
        items.push(crate::ui::screens::receive_address_row(
            self.settings.language,
            &grouped(&view.address),
            ids::COPY_ADDRESS,
            actions,
        ));
        items.push(Item::Qr(view.qr.clone()));
        items.push(Item::Help(view.note.clone()));
        items.push(Item::Help(view.path.clone()));
        items.push(Item::CardEnd);
    }

    /// S15 Bitcoin section (spec/04 §2.11, spec/08 §2).
    #[expect(clippy::too_many_lines, reason = "the S15 Bitcoin rows in order")]
    pub fn btc_settings_section(&self, items: &mut Vec<Item>) {
        let ctx = self.btc_ctx();
        let settings = ctx.settings;
        let net = ctx.net();
        let lang = ctx.lang;
        if let Some(message) = &self.btc.settings_message {
            items.push(Item::Banner(message.clone(), Tone::Danger));
        }
        items.push(Item::CardStart(Some(
            text::SETTINGS_CARD.get(lang).to_owned(),
        )));
        items.push(Item::Row(vec![Ctl::check(
            ids::ENABLE,
            text::ENABLE.get(lang),
            settings.enabled,
        )]));
        items.push(Item::LabeledRow(
            text::NETWORK.get(lang).to_owned(),
            vec![
                Ctl::radio(
                    ids::SET_MAINNET,
                    "mainnet",
                    net == BtcNetwork::Mainnet,
                    true,
                ),
                Ctl::radio(
                    ids::SET_TESTNET4,
                    text::TESTNET4_RADIO.get(lang),
                    net == BtcNetwork::Testnet4,
                    false,
                ),
            ],
        ));
        if settings.enabled {
            items.push(Item::Banner(
                net.banner_in(lang).to_owned(),
                network_tone(net),
            ));
            if let Some((meta, current)) = ctx.mismatch() {
                items.push(Item::Banner(
                    texts::NETWORK_MISMATCH.get(lang).to_owned(),
                    Tone::Danger,
                ));
                Self::btc_mismatch_row(lang, meta, current, items);
            }
        }
        items.push(Item::Help(text::ENABLE_HELP.get(lang).to_owned()));
        for known in BtcNetwork::ALL {
            let network = crate::btc::network_id(known);
            let state = if self.apikeys.has(KeyName::Rpc(network)) {
                text::RPC_SET.get(lang).to_owned()
            } else {
                text::RPC_NONE.fill(lang, [ErrorCode::Key005.code()])
            };
            items.push(Item::Help(
                text::RPC_LINE.fill(lang, [&network.to_string(), &state]),
            ));
        }
        items.push(Item::Row(vec![Ctl::button(
            crate::ui::screens::ids::GO_NETWORK,
            text::GO_NETWORK.get(lang),
        )]));
        items.push(Item::CardEnd);
        items.push(Item::CardStart(Some(
            text::INDEXER_CARD.get(lang).to_owned(),
        )));
        let indexer = settings.indexer;
        items.push(Item::LabeledRow(
            text::INDEXER.get(lang).to_owned(),
            vec![
                Ctl::radio(
                    ids::IDX_ESPLORA,
                    "Esplora",
                    indexer == BtcIndexer::Esplora,
                    true,
                ),
                Ctl::radio(
                    ids::IDX_BB_RPC,
                    "Blockbook JSON-RPC (bb-rpc)",
                    indexer == BtcIndexer::BbRpc,
                    false,
                ),
                Ctl::radio(
                    ids::IDX_BB_REST,
                    "Blockbook REST (bb-rest)",
                    indexer == BtcIndexer::BbRest,
                    false,
                ),
            ],
        ));
        items.push(Item::Help(T_BTC_ESPLORA_NOTE.get(lang).to_owned()));
        items.push(Item::Help(text::INDEXER_HELP.get(lang).to_owned()));
        items.push(Item::CardEnd);
        items.push(Item::CardStart(Some("Esplora URL".to_owned())));
        for known in BtcNetwork::ALL {
            let (edit, save, default, test) = esplora_ids(known);
            let value = ctx.esplora_text(known);
            items.push(Item::Subtitle(format!(
                "Esplora URL — {}",
                known.settings_name()
            )));
            items.push(Item::Mono(value.to_owned()));
            items.push(Item::Row(vec![Ctl::edit(edit, value, 420, false, 256)]));
            items.push(Item::Row(vec![
                Ctl::button(save, text::SAVE.get(lang)),
                Ctl::button(default, text::DEFAULT.get(lang)),
                Ctl::button(test, text::TEST.get(lang)),
            ]));
            if let Some((_, message, state)) = self
                .btc
                .esplora_tests
                .iter()
                .find(|(tested, ..)| *tested == known)
            {
                items.push(Item::Banner(message.clone(), state.tone()));
            }
        }
        items.push(Item::Help(text::ESPLORA_TEST_HELP.get(lang).to_owned()));
        items.push(Item::CardEnd);
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use yw_core::btc::{BtcMeta, BtcNetwork, Sats};
    use yw_win::http::HttpsUrl;

    use super::{
        T_BTC_ESPLORA_NOTE, fee_choice_of, fee_ids, grouped, ids, mismatch_labels, network_tone,
    };
    use crate::apikeys::ApiKeys;
    use crate::app::{App, AppMode, Paths, Screen, SettingsSection};
    use crate::app_btc::{BTC_IMPORT_NOTE, BTC_MAX_ACTIVITY_ROWS, BtcFeeChoice};
    use crate::app_sol::ReviewBlocker;
    use crate::errors::ErrorCode;
    use crate::events::JournalView;
    use crate::meta::{Meta, Tab};
    use crate::network::{BtcNet, NetworkId};
    use crate::settings::Settings;
    use crate::ui::main_window::{Ctl, Item, Tone};
    use crate::ui::theme::address_spans;
    use yw_core::lang::Lang;

    /// A compressed account public key (the `meta.rs` test value; never derived from here).
    const TESTNET_ACCOUNT: &str =
        "03b88e0fbe3f646337ed93bc0c0f3b843fcf7d2589e5ec884754e6402027a890b4";

    fn app(enabled: bool, settings_net: BtcNet, meta_net: Option<BtcNetwork>, url: bool) -> App {
        let mut settings = Settings::default();
        settings.bitcoin.enabled = enabled;
        settings.bitcoin.network = settings_net;
        let mut apikeys = ApiKeys::default();
        if url {
            apikeys.set_rpc(
                NetworkId::Bitcoin(settings_net),
                &HttpsUrl::parse("https://btc.example.test/").unwrap(),
            );
        }
        let dir = std::env::temp_dir().join(format!("yw-app-btc-screens-{}", std::process::id()));
        let mut app = App::new(
            Paths {
                data: dir.clone(),
                logs: dir.join("logs"),
            },
            true,
            settings,
            apikeys,
        );
        app.mode = AppMode::Unlocked {
            alt_passphrase: false,
        };
        let mut meta = Meta::default();
        meta.prefs.tab = Tab::Btc;
        meta.btc = meta_net.map(|net| {
            let account = yw_core::bip32::AccountXpub {
                pubkey: yw_core::hex::decode_array::<33>(TESTNET_ACCOUNT).unwrap(),
                chain_code: [7; 32],
            };
            Box::new(BtcMeta::new(net, account))
        });
        app.meta = Some(meta);
        app.evm.journal = Some(JournalView {
            room: true,
            sol_room: true,
            btc_room: true,
            ..JournalView::default()
        });
        app.screen = Screen::Main;
        app
    }

    fn controls(items: &[Item]) -> Vec<Ctl> {
        items
            .iter()
            .flat_map(|item| match item {
                Item::Row(ctls) | Item::LabeledRow(_, ctls) | Item::Menu(ctls) => ctls.clone(),
                Item::CopyLine { value, actions } => {
                    let mut all = vec![value.clone()];
                    all.extend(actions.iter().cloned());
                    all
                }
                _ => Vec::new(),
            })
            .collect()
    }

    fn has_text(items: &[Item], wanted: &str) -> bool {
        items.iter().any(|item| match item {
            Item::Title(text)
            | Item::Text(text)
            | Item::Muted(text)
            | Item::Mono(text)
            | Item::Help(text)
            | Item::Subtitle(text)
            | Item::Display(text)
            | Item::Banner(text, _)
            | Item::Pill(text, _) => text.contains(wanted),
            _ => false,
        })
    }

    fn control(items: &[Item], id: u16) -> Option<Ctl> {
        controls(items).into_iter().find(|ctl| ctl.id == id)
    }

    #[test]
    fn btc_ids_are_unique_in_their_own_range() {
        let mut seen = BTreeSet::new();
        for id in ids::FIXED {
            assert!((9_000..ids::UTXO_BASE).contains(&id), "{id}");
            assert!(seen.insert(id), "duplicate {id}");
        }
        let utxo_end = ids::UTXO_BASE + ids::UTXO_SPAN;
        assert!(utxo_end <= ids::ACTIVITY_BASE);
        let rows = u16::try_from(BTC_MAX_ACTIVITY_ROWS).unwrap();
        assert!(rows * ids::ACTIVITY_STRIDE <= ids::ACTIVITY_SPAN);
        // The other modules are checked against these ranges in `ui::command_ids`.
        // Fee radios map back to their form.
        for bump in [false, true] {
            let choices: Vec<_> = fee_ids(bump)
                .into_iter()
                .map(|id| fee_choice_of(id).unwrap())
                .collect();
            assert_eq!(
                choices,
                [
                    (BtcFeeChoice::Fast, bump),
                    (BtcFeeChoice::Normal, bump),
                    (BtcFeeChoice::Slow, bump),
                    (BtcFeeChoice::Manual, bump),
                ]
            );
        }
        assert_eq!(fee_choice_of(ids::SEND_REVIEW), None);
    }

    #[test]
    fn btc_address_is_drawn_whole_with_four_after_the_prefix_and_the_last_four() {
        let address = "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu";
        let text = grouped(address);
        assert_eq!(text, "bc1q cr8t e4kr 609g cawu tmrz a0j4 xv80 jy8z 306f yu");
        for line in [address, text.as_str()] {
            let spans = address_spans(line).unwrap();
            let joined: String = spans.iter().map(|(piece, _)| piece.as_str()).collect();
            assert_eq!(joined, address);
            let strong: Vec<&str> = spans
                .iter()
                .filter(|(_, strong)| *strong)
                .map(|(piece, _)| piece.as_str())
                .collect();
            assert_eq!(strong, ["cr8t", "6fyu"]);
        }
        assert!(address_spans("bc1q cr8t e4kr 609g cawu tmrz a0j4 xv80 jy8z 306f yv").is_none());
    }

    #[test]
    fn mismatch_shows_both_buttons_and_nothing_else_calls() {
        let mut app = app(true, BtcNet::Mainnet, Some(BtcNetwork::Testnet4), true);
        let items = app.items();
        assert!(has_text(
            &items,
            "BTC 네트워크 설정이 지갑 데이터와 다릅니다"
        ));
        assert_eq!(
            control(&items, ids::MISMATCH_KEEP_META).map(|ctl| ctl.text),
            Some("설정을 testnet4로 되돌리기".to_owned())
        );
        assert_eq!(
            control(&items, ids::MISMATCH_USE_SETTINGS).map(|ctl| ctl.text),
            Some("mainnet으로 바꾸기".to_owned())
        );
        assert_eq!(
            mismatch_labels(Lang::Ko, BtcNetwork::Mainnet, BtcNetwork::Testnet4),
            (
                "설정을 mainnet으로 되돌리기".to_owned(),
                "testnet4로 바꾸기".to_owned()
            )
        );
        // The tab row has Bitcoin selected; sending and refreshing are off.
        assert_eq!(
            control(&items, ids::TAB_BTC).and_then(|ctl| ctl.checked),
            Some(true)
        );
        assert_eq!(
            control(&items, ids::SEND_OPEN).map(|ctl| ctl.enabled),
            Some(false)
        );
        assert_eq!(
            control(&items, ids::REFRESH).map(|ctl| ctl.enabled),
            Some(false)
        );
        // The network card's tag (2026-11-11: no longer a full-width band on S10).
        assert!(items.iter().any(|item| matches!(
            item,
            Item::Pill(text, Tone::BtcMainnet) if text == "BITCOIN MAINNET"
        )));
        // The settings section shows the same pair.
        app.screen = Screen::Settings(SettingsSection::Bitcoin);
        let items = app.items();
        assert!(control(&items, ids::MISMATCH_KEEP_META).is_some());
        assert!(control(&items, ids::MISMATCH_USE_SETTINGS).is_some());
    }

    /// spec/04 §2.6 Bitcoin: the account card lists each account with its type and prefix, and
    /// `계정 추가` opens the four plain-Korean choices with the network's prefixes, native segwit
    /// first and recommended.
    #[test]
    fn account_card_and_type_chooser() {
        for (net, settings_net, labels) in [
            (
                BtcNetwork::Mainnet,
                BtcNet::Mainnet,
                [
                    "네이티브 세그윗 (bc1q…, 권장)",
                    "탭루트 (bc1p…)",
                    "호환 세그윗 (3…)",
                    "레거시 (1…)",
                ],
            ),
            (
                BtcNetwork::Testnet4,
                BtcNet::Testnet4,
                [
                    "네이티브 세그윗 (tb1q…, 권장)",
                    "탭루트 (tb1p…)",
                    "호환 세그윗 (2…)",
                    "레거시 (m·n…)",
                ],
            ),
        ] {
            let mut app = app(true, settings_net, Some(net), true);
            // The account drop-down (2026-11-11): its button names the selected account; open,
            // the list has one entry per account (the radio ids of before), the selected marked.
            let items = app.items();
            let picker = control(&items, crate::ui::screens_links::ids::PICKER_BTC)
                .expect("account drop-down");
            assert!(
                picker
                    .text
                    .starts_with("네이티브 세그윗 계정 0 · 네이티브 세그윗 (")
            );
            assert!(control(&items, ids::ACCOUNT_BASE).is_none());
            assert!(app.on_links_command(crate::ui::screens_links::ids::PICKER_BTC));
            let items = app.items();
            let row = control(&items, ids::ACCOUNT_BASE).expect("account row");
            assert!(
                row.text
                    .starts_with("네이티브 세그윗 계정 0 · 네이티브 세그윗 (")
            );
            assert_eq!(row.checked, Some(true));
            assert!(app.on_links_command(crate::ui::screens_links::ids::PICKER_BTC));
            let items = app.items();
            assert!(control(&items, ids::ACCOUNT_ADD).is_some_and(|ctl| ctl.text == "계정 추가"));
            assert!(has_text(&items, "네이티브 세그윗 계정 0"));
            app.btc.add_account_open = true;
            let items = app.items();
            for (offset, label) in labels.iter().enumerate() {
                let id = ids::ACCOUNT_ADD_TYPE + u16::try_from(offset).unwrap();
                assert_eq!(
                    control(&items, id).map(|ctl| ctl.text),
                    Some((*label).to_owned())
                );
            }
            assert!(control(&items, ids::ACCOUNT_ADD_CANCEL).is_some());
            assert!(control(&items, ids::ACCOUNT_ADD).is_none());
            // Key source: the standard path is checked by default (spec/08 §3.5 (a)); the EVM
            // key needs the explicit choice and shows the warning and the EVM accounts.
            let standard = control(&items, ids::ACCOUNT_SOURCE_STANDARD).expect("standard");
            assert_eq!(standard.text, "BTC 표준 경로 (권장, 기본값)");
            assert_eq!(standard.checked, Some(true));
            let evm = control(&items, ids::ACCOUNT_SOURCE_EVM).expect("evm source");
            assert_eq!(evm.text, "EVM 계정과 같은 키");
            assert_eq!(evm.checked, Some(false));
            assert!(control(&items, ids::EVM_ACCOUNT_BASE).is_none());
            assert!(!has_text(&items, crate::app_btc::T_BTC_EVM_SHARED.ko));
            app.btc.add_source = crate::app_btc::BtcAddSource::EvmShared;
            let items = app.items();
            assert_eq!(
                control(&items, ids::ACCOUNT_SOURCE_EVM).and_then(|ctl| ctl.checked),
                Some(true)
            );
            assert!(has_text(&items, crate::app_btc::T_BTC_EVM_SHARED.ko));
            let first = control(&items, ids::EVM_ACCOUNT_BASE).expect("EVM account 0");
            assert!(first.text.ends_with("m/44'/60'/0'/0/0"), "{}", first.text);
            assert_eq!(first.checked, Some(true));
            app.btc.add_source = crate::app_btc::BtcAddSource::Standard;
        }
    }

    /// spec/08 §3.5: the selected HD account's address mode (fixed by default, the one-line
    /// trade-off) and the receive screen of each mode: fixed shows `…/0/0`, the explanation and
    /// no `새 주소`; HD shows the index and `새 주소`.
    #[test]
    fn address_mode_radios_and_receive_screen() {
        let mut app = app(true, BtcNet::Testnet4, Some(BtcNetwork::Testnet4), true);
        let items = app.items();
        let single = control(&items, ids::ADDRESS_MODE_SINGLE).expect("fixed radio");
        assert_eq!(single.text, "고정 주소 하나만 사용 (UniSat·Xverse 방식)");
        assert_eq!(single.checked, Some(true));
        let hd = control(&items, ids::ADDRESS_MODE_HD).expect("hd radio");
        assert_eq!(hd.text, "받을 때마다 새 주소 (HD, 프라이버시↑)");
        assert_eq!(hd.checked, Some(false));
        assert!(has_text(&items, crate::app_btc::T_BTC_MODE_HELP.ko));
        let meta = app.btc_ctx().btc_meta().cloned().unwrap();
        app.btc.receive = crate::app_btc::BtcUi::receive_view(Lang::Ko, &meta, 0);
        app.screen = Screen::BtcReceive;
        let items = app.items();
        assert!(has_text(&items, crate::app_btc::T_BTC_FIXED_RECEIVE.ko));
        assert!(has_text(&items, "m/84'/1'/0'/0/0"));
        assert!(control(&items, ids::NEW_ADDRESS).is_none());
        assert!(control(&items, ids::COPY_ADDRESS).is_some());
        // HD mode.
        let mut hd_meta = meta;
        hd_meta.set_single_address(false).unwrap();
        if let Some(document) = app.meta.as_mut() {
            document.btc = Some(Box::new(hd_meta.clone()));
        }
        app.btc.receive = crate::app_btc::BtcUi::receive_view(Lang::Ko, &hd_meta, 3);
        let items = app.items();
        assert!(!has_text(&items, crate::app_btc::T_BTC_FIXED_RECEIVE.ko));
        assert!(has_text(&items, "m/84'/1'/0'/0/3"));
        assert!(control(&items, ids::NEW_ADDRESS).is_some());
        // The address is one copy line before the QR (2026-11-12), whole (§3.3), with
        // `새 주소` on that line.
        let address = app.btc.receive.as_ref().unwrap().address.clone();
        assert_eq!(
            control(&items, ids::COPY_ADDRESS).and_then(|line| line.value_text()),
            Some(address)
        );
        let line = items
            .iter()
            .position(|item| matches!(item, Item::CopyLine { actions, .. } if actions.len() == 1));
        assert!(line.is_some() && line < items.iter().position(|item| matches!(item, Item::Qr(_))));
        app.screen = Screen::Main;
        let items = app.items();
        assert_eq!(
            control(&items, ids::ADDRESS_MODE_HD).and_then(|ctl| ctl.checked),
            Some(true)
        );
    }

    /// Same order as the other tabs: the selected account's `보내기`·`받기` come before the
    /// account list; `개인키 가져오기` opens its address-type chooser on demand.
    #[test]
    fn selected_account_first_and_import_chooser_on_demand() {
        use crate::ui::screens_keys::ids as key_ids;
        let mut app = app(true, BtcNet::Testnet4, Some(BtcNetwork::Testnet4), true);
        let items = app.items();
        let order: Vec<u16> = controls(&items).iter().map(|ctl| ctl.id).collect();
        let position = |id: u16| order.iter().position(|each| *each == id).unwrap();
        assert!(position(ids::SEND_OPEN) < position(crate::ui::screens_links::ids::PICKER_BTC));
        assert!(position(ids::RECEIVE_OPEN) < position(ids::ACCOUNT_ADD));
        // Closed: one line and the button, no radios.
        assert!(order.contains(&key_ids::BTC_IMPORT));
        assert!(!order.contains(&key_ids::BTC_IMPORT_NEXT));
        assert!(!order.contains(&key_ids::SCRIPT_BASE));
        assert!(has_text(&items, "누르면 주소 형식을 고릅니다"));
        assert!(app.on_keys_command(key_ids::BTC_IMPORT));
        let items = app.items();
        let open: Vec<Ctl> = controls(&items);
        assert!(open.iter().any(|ctl| ctl.id == key_ids::BTC_IMPORT_NEXT));
        assert!(open.iter().any(|ctl| ctl.id == key_ids::BTC_IMPORT_CANCEL));
        assert!(!open.iter().any(|ctl| ctl.id == key_ids::BTC_IMPORT));
        assert!(
            open.iter()
                .any(|ctl| ctl.text == "네이티브 세그윗 (bc1q…, P2WPKH)"
                    && ctl.checked == Some(true))
        );
        assert!(app.on_keys_command(key_ids::BTC_IMPORT_CANCEL));
        assert!(control(&app.items(), key_ids::BTC_IMPORT).is_some());
        // One Bitcoin network tag, not a second generic testnet band.
        assert_eq!(
            items
                .iter()
                .filter(|item| matches!(
                    item,
                    Item::Banner(_, Tone::BtcTestnet4 | Tone::Testnet)
                        | Item::Pill(_, Tone::BtcTestnet4 | Tone::Testnet)
                ))
                .count(),
            1
        );
    }

    #[test]
    fn gate_texts_of_the_tab() {
        // Disabled: the fixed text and a way to the settings section, no banner.
        let app_off = app(false, BtcNet::Testnet4, None, false);
        let items = app_off.items();
        assert!(has_text(&items, "Bitcoin이 꺼져 있습니다"));
        assert!(control(&items, ids::SECTION_BTC).is_some());
        assert!(control(&items, ids::SEND_OPEN).is_none());
        assert!(!has_text(&items, "BITCOIN TESTNET4"));
        // No endpoint: E-KEY-005 and `RPC 설정하기` (that network's row).
        let app_no_url = app(true, BtcNet::Testnet4, Some(BtcNetwork::Testnet4), false);
        let items = app_no_url.items();
        assert!(has_text(
            &items,
            &ErrorCode::Key005.text_in(yw_core::lang::Lang::Ko)
        ));
        assert!(control(&items, crate::ui::screens::ids::BTC_RPC_OPEN).is_some());
        assert!(items.iter().any(|item| matches!(
            item,
            Item::Pill(text, Tone::BtcTestnet4) if text == "BITCOIN TESTNET4 — 가치 없음"
        )));
        assert!(!items.iter().any(|item| matches!(
            item,
            Item::Banner(_, Tone::Testnet) | Item::Pill(_, Tone::Testnet)
        )));
        // Usable but discovery not done: "주소 검색 미완료" + [다시 시도]; sending blocked.
        let ready = app(true, BtcNet::Testnet4, Some(BtcNetwork::Testnet4), true);
        let items = ready.items();
        assert!(has_text(&items, "주소 검색 미완료"));
        assert_eq!(
            control(&items, ids::DISCOVER_RETRY).map(|ctl| ctl.enabled),
            Some(true)
        );
        assert_eq!(
            control(&items, ids::SEND_OPEN).map(|ctl| ctl.enabled),
            Some(false)
        );
        assert!(has_text(&items, "보내기: 주소 검색 미완료"));
        assert_eq!(
            control(&items, ids::RECEIVE_OPEN).map(|ctl| ctl.enabled),
            Some(true)
        );
        assert!(has_text(&items, "Core RPC (bitcoin:testnet4): 확인 전"));
        assert_eq!(network_tone(BtcNetwork::Mainnet), Tone::BtcMainnet);
    }

    #[test]
    fn send_form_shows_the_typed_fee_field_only_when_needed() {
        let mut app = app(true, BtcNet::Testnet4, Some(BtcNetwork::Testnet4), true);
        app.screen = Screen::BtcSend;
        let items = app.items();
        for id in [
            ids::SEND_TO_EDIT,
            ids::SEND_AMOUNT_EDIT,
            ids::UNIT_BTC,
            ids::UNIT_SATS,
            ids::SEND_MAX,
            ids::FEE_FAST,
            ids::FEE_NORMAL,
            ids::FEE_SLOW,
            ids::FEE_MANUAL,
            ids::SEND_REVIEW,
            ids::SEND_CANCEL,
        ] {
            assert!(control(&items, id).is_some(), "{id}");
        }
        assert_eq!(
            control(&items, ids::FEE_NORMAL).and_then(|ctl| ctl.checked),
            Some(true)
        );
        assert!(control(&items, ids::TYPED_FEE_EDIT).is_none());
        assert!(control(&items, ids::FEE_MANUAL_EDIT).is_none());
        assert_eq!(
            control(&items, ids::SEND_REVIEW).map(|ctl| ctl.enabled),
            Some(false)
        );
        // The line under it says why: the address search has not run (the band at the top).
        assert_eq!(app.btc_review_blocker(), Some(ReviewBlocker::Held));
        assert!(has_text(
            &items,
            ReviewBlocker::Held.text_in(yw_core::lang::Lang::Ko)
        ));
        app.btc.send.fee.choice = BtcFeeChoice::Manual;
        app.btc.send.fee.needs_typed = Sats::new(600_000);
        let items = app.items();
        assert!(control(&items, ids::FEE_MANUAL_EDIT).is_some());
        assert!(control(&items, ids::TYPED_FEE_EDIT).is_some());
        assert!(has_text(&items, "수수료(sats)를 정확히 입력해 상한 해제"));
        // The fee-bump form has its own ids.
        app.screen = Screen::BtcBump;
        let items = app.items();
        assert!(control(&items, ids::BUMP_FEE_NORMAL).is_some());
        assert!(control(&items, ids::FEE_NORMAL).is_none());
        assert_eq!(
            control(&items, ids::BUMP_REVIEW).map(|ctl| ctl.enabled),
            Some(false)
        );
    }

    #[test]
    fn settings_section_import_note_and_url_list() {
        let mut app = app(false, BtcNet::Mainnet, None, true);
        app.screen = Screen::Settings(SettingsSection::Bitcoin);
        let items = app.items();
        for id in [
            ids::ENABLE,
            ids::SET_MAINNET,
            ids::SET_TESTNET4,
            ids::IDX_ESPLORA,
            ids::IDX_BB_RPC,
            ids::IDX_BB_REST,
            ids::ESPLORA_MAINNET_EDIT,
            ids::ESPLORA_MAINNET_SAVE,
            ids::ESPLORA_MAINNET_DEFAULT,
            ids::ESPLORA_MAINNET_TEST,
            ids::ESPLORA_TESTNET4_EDIT,
            ids::ESPLORA_TESTNET4_SAVE,
            ids::ESPLORA_TESTNET4_DEFAULT,
            ids::ESPLORA_TESTNET4_TEST,
        ] {
            assert!(control(&items, id).is_some(), "{id}");
        }
        assert_eq!(
            control(&items, ids::ENABLE).and_then(|ctl| ctl.checked),
            Some(false)
        );
        assert!(has_text(&items, T_BTC_ESPLORA_NOTE.ko));
        assert!(has_text(&items, "https://mempool.space/testnet4/api"));
        assert_eq!(
            control(&items, ids::ESPLORA_MAINNET_EDIT).map(|ctl| ctl.text),
            Some("https://mempool.space/api".to_owned())
        );
        assert!(has_text(&items, "Core RPC 주소 bitcoin:mainnet: 설정됨"));
        assert!(has_text(
            &items,
            "Core RPC 주소 bitcoin:testnet4: 없음 — E-KEY-005"
        ));
        // The selected settings tab is drawn selected (Ctl::tab).
        assert_eq!(
            control(&items, ids::SECTION_BTC).and_then(|ctl| ctl.checked),
            Some(true)
        );
        app.screen = Screen::ImportIntro;
        assert!(has_text(&app.items(), BTC_IMPORT_NOTE.ko));
        app.screen = Screen::Settings(SettingsSection::Network);
        let items = app.items();
        assert!(!has_text(&items, "M8"));
        assert!(has_text(&items, "(bitcoin:testnet4)"));
    }

    /// Every text of an item and its controls (labels, values, tooltips are not drawn here).
    fn all_texts(items: &[Item]) -> Vec<String> {
        let mut out: Vec<String> = items
            .iter()
            .filter_map(|item| match item {
                Item::Title(text)
                | Item::Text(text)
                | Item::Muted(text)
                | Item::Help(text)
                | Item::Subtitle(text)
                | Item::Display(text)
                | Item::Banner(text, _)
                | Item::Pill(text, _)
                | Item::LabeledRow(text, _) => Some(text.clone()),
                Item::Field(label, value) => Some(format!("{label} {value}")),
                Item::CardStart(Some(title)) => Some(title.clone()),
                _ => None,
            })
            .collect();
        out.extend(controls(items).into_iter().map(|ctl| ctl.text));
        out
    }

    /// spec/14 (Step 3): the Bitcoin screens built in English show none of the Bitcoin
    /// catalogues' Korean texts, and every Bitcoin control (ids 9000–9899) has a Hangul-free label.
    #[test]
    fn english_bitcoin_screens_have_no_korean_btc_text() {
        use yw_core::lang::has_hangul;
        let korean: Vec<&str> = super::text::ALL
            .iter()
            .chain(crate::app_btc::text::ALL)
            .chain(crate::btc::text::ALL)
            .map(|entry| entry.ko)
            .filter(|ko| has_hangul(ko) && ko.chars().count() >= 4 && !ko.contains("{0}"))
            .collect();
        let check = |items: &[Item], screen: &str| {
            for text in all_texts(items) {
                for ko in &korean {
                    assert!(!text.contains(ko), "{screen}: {text}");
                }
            }
            for ctl in controls(items) {
                if (9_000..9_900).contains(&ctl.id) {
                    assert!(!has_hangul(&ctl.text), "{screen}: {}", ctl.text);
                }
            }
        };
        // Disabled tab, mismatch, the normal tab and its forms, receive, settings.
        let mut off = app(false, BtcNet::Mainnet, None, true);
        off.settings.language = Lang::En;
        check(&off.items(), "disabled");
        let mut mismatch = app(true, BtcNet::Mainnet, Some(BtcNetwork::Testnet4), true);
        mismatch.settings.language = Lang::En;
        let items = mismatch.items();
        check(&items, "mismatch");
        assert_eq!(
            control(&items, ids::MISMATCH_KEEP_META).map(|ctl| ctl.text),
            Some("Set the setting back to testnet4".to_owned())
        );
        let mut app = app(true, BtcNet::Testnet4, Some(BtcNetwork::Testnet4), true);
        app.settings.language = Lang::En;
        app.btc.add_account_open = true;
        app.btc.verify_failures = 1;
        app.btc.auto_frozen = 2;
        let items = app.items();
        check(&items, "tab");
        assert!(items.iter().any(|item| matches!(
            item,
            Item::Pill(text, Tone::BtcTestnet4) if text == "BITCOIN TESTNET4 — NO VALUE"
        )));
        for screen in [
            Screen::BtcSend,
            Screen::BtcBump,
            Screen::BtcSendResult,
            Screen::Settings(SettingsSection::Bitcoin),
        ] {
            let name = format!("{screen:?}");
            app.screen = screen;
            check(&app.items(), &name);
        }
        let meta = app.btc_ctx().btc_meta().cloned().unwrap();
        app.btc.receive = crate::app_btc::BtcUi::receive_view(Lang::En, &meta, 0);
        app.screen = Screen::BtcReceive;
        let items = app.items();
        check(&items, "receive");
        let view = app.btc.receive.as_ref().unwrap();
        assert!(!has_hangul(&view.note) && !has_hangul(&view.kind) && !has_hangul(&view.account));
    }

    /// spec/14: every confirmation overlay, the fee radios, statuses and the W-ADDR-3 ends in
    /// English are Hangul-free; the Korean ones keep their text.
    #[test]
    fn english_bitcoin_confirmations_and_statuses() {
        use crate::app_btc::BtcConfirm;
        use yw_core::lang::has_hangul;
        let txid = yw_core::btc::Txid::from_bytes([1; 32]);
        for confirm in [
            BtcConfirm::NetworkChange {
                to: BtcNetwork::Mainnet,
            },
            BtcConfirm::IndexerOptIn {
                indexer: crate::settings::BtcIndexer::BbRpc,
            },
            BtcConfirm::GapWarning { unused: 20 },
            BtcConfirm::Abandon { txid },
            BtcConfirm::CancelSigned {
                txid,
                disclosed: false,
            },
            BtcConfirm::CancelSigned {
                txid,
                disclosed: true,
            },
            BtcConfirm::EsploraBroadcast { txid },
            BtcConfirm::ResetTip,
            BtcConfirm::AddEvmShared {
                script_type: yw_core::btc::ScriptType::P2tr,
                evm_index: 3,
            },
        ] {
            let (title, body, yes) = confirm.texts(Lang::En);
            assert!(
                !has_hangul(title) && !has_hangul(&body) && !has_hangul(yes),
                "{body}"
            );
            assert!(!has_hangul(confirm.no_label(Lang::En)));
            let (_, korean, _) = confirm.texts(Lang::Ko);
            assert!(has_hangul(&korean));
        }
        for choice in super::FEE_CHOICES {
            assert!(!has_hangul(choice.label(Lang::En)));
        }
        for confirmations in [0, 1, 6] {
            assert!(!has_hangul(&crate::app_btc::confirmations_text(
                Lang::En,
                confirmations
            )));
        }
        assert_eq!(
            crate::app_btc::ends_text(Lang::En, (4, 4)),
            "first 4 and last 4 characters"
        );
        assert_eq!(crate::app_btc::ends_text(Lang::Ko, (0, 5)), "끝 5자");
    }

    /// spec/14: the screen catalogue keeps the catalogue invariants.
    #[test]
    fn bitcoin_screen_catalogues_are_well_formed() {
        use yw_core::lang::{has_hangul, placeholders};
        for entry in super::text::ALL
            .iter()
            .chain(crate::app_btc::text::ALL)
            .chain(crate::btc::text::ALL)
            .chain(crate::received::btc::text::ALL)
            .chain(crate::workers::journal::btc::text::ALL)
        {
            let expected: Vec<usize> = (0..entry.args).collect();
            for template in [entry.ko, entry.en] {
                let mut found = placeholders(template);
                found.sort_unstable();
                found.dedup();
                assert_eq!(found, expected, "{}", entry.name);
            }
            assert!(!has_hangul(entry.en), "{}", entry.name);
        }
    }
}
