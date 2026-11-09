//! Bitcoin screen contents (M8; spec/04 §2.6–§2.8, §2.11, §2.16, §3.3; spec/08 §2, §3.2, §3.4,
//! §4.7, §7.3, §7.6, §8.2–§8.3, §9, §11.3, §12.1–§12.2): the S10 Bitcoin tab, the BTC send form
//! and its result, the fee-bump form, S12 receive and the S15 Bitcoin section. Every text is a
//! fixed sentence or built by yw-core / the controller ([`crate::app_btc`]); no server string is
//! shown. Addresses are shown in full in 4-character groups, the first and last 6 characters
//! bold (spec/04 §3.3); activity addresses have no copy or select buttons.

use yw_core::btc::meta::FreezeReason;
use yw_core::btc::policy::texts;
use yw_core::btc::{BtcMeta, BtcNetwork, FeeRate, Sats, Txid, encode_address};

use crate::apikeys::KeyName;
use crate::app::{App, AppMode};
use crate::app_book::{BookTarget, PromptPlace};
use crate::app_btc::{
    BtcCtx, BtcFeeChoice, BtcFeeForm, BtcFlowStage, BtcGate, BtcUi, DISCOVERY_INCOMPLETE,
    PENDING_INCOMING, confirmations_text, record_status,
};
use crate::errors::ErrorCode;
use crate::meta::BookChain;
use crate::settings::BtcIndexer;
use crate::ui::badge::Badge;
use crate::ui::main_window::{Ctl, Item, Tone};

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
    pub const FIXED: [u16; 63] = [
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

/// T-BTC-ESPLORA-NOTE (spec/04 §2.16).
pub const T_BTC_ESPLORA_NOTE: &str = "인덱서(Esplora 서버)는 조회하는 주소와 이 PC의 IP를 봅니다. 기본값은 mempool.space이며 자체 Esplora 서버로 바꿀 수 있습니다. mempool.space에 연결되지 않으면 아래 Esplora URL을 https://blockstream.info/api (testnet4는 https://blockstream.info/testnet4/api)로 바꾸고 테스트하세요. Esplora URL은 평문으로 저장되므로 토큰·API 키가 들어 있는 URL은 넣지 마세요.";
/// The testnet band of S10/S11 (spec/04 §2.6).
/// The testnet badge of S12 (spec/04 §2.8).
/// Journal damage of the BTC entries (spec/08 §12.4, E-VLT-006).
const JOURNAL_DAMAGED: &str =
    "거래 저널의 Bitcoin 기록이 손상되어 Bitcoin 보내기를 멈췄습니다. (E-VLT-006)";
/// Help under the account list (spec/04 §2.6 Bitcoin).
const ACCOUNTS_HELP: &str = "계정마다 주소 형식이 정해집니다. 새 계정은 같은 복구 단어에서 만들어지며 다른 지갑에서도 같은 형식(BIP44·49·84·86)을 고르면 복구됩니다.";
/// Help of the add-account chooser.
const ADD_ACCOUNT_HELP: &str = "주소 형식을 고르세요. 잘 모르면 네이티브 세그윗을 고르세요(수수료가 낮고 대부분의 거래소·지갑이 지원). 탭루트는 수수료가 가장 낮지만 일부 거래소는 보내기를 지원하지 않습니다. 레거시·호환 세그윗은 오래된 서비스와 호환용입니다.";

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

/// The settings name with its Korean particle (`mainnet으로`, `testnet4로`).
fn with_particle(net: BtcNetwork) -> String {
    match net {
        BtcNetwork::Mainnet => format!("{}으로", net.settings_name()),
        BtcNetwork::Testnet4 => format!("{}로", net.settings_name()),
    }
}

/// The two mismatch buttons (spec/08 §2): [설정을 {`BtcMeta` 값}으로 되돌리기] /
/// [{settings 값}으로 바꾸기].
#[must_use]
pub fn mismatch_labels(meta: BtcNetwork, settings: BtcNetwork) -> (String, String) {
    (
        format!("설정을 {} 되돌리기", with_particle(meta)),
        format!("{} 바꾸기", with_particle(settings)),
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
fn network_banners(net: BtcNetwork, items: &mut Vec<Item>) {
    items.push(Item::Banner(net.banner().to_owned(), network_tone(net)));
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
        || "Bitcoin 계정".to_owned(),
        |meta| crate::app_btc::account_label(meta.account()),
    )
}

/// The selected account's node and type line: `m/86'/0'/0' · 탭루트 (bc1p…)`, or for an
/// imported key `가져온 키 · 레거시 (1…)`.
fn active_detail(ctx: &BtcCtx<'_>) -> String {
    let net = ctx.net();
    ctx.btc_meta().map_or_else(String::new, |meta| {
        format!(
            "{} · {}",
            meta.account().node_text(net),
            crate::app_btc::account_type_text(meta.account(), net)
        )
    })
}

fn flow_stage_text(stage: BtcFlowStage) -> Option<&'static str> {
    match stage {
        BtcFlowStage::Prechecking => Some("노드 사전 검사(testmempoolaccept) 중…"),
        BtcFlowStage::Applying => Some("저널에 기록하는 중…"),
        BtcFlowStage::Sending => Some("전송 중…"),
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
    fn btc_gate_items(gate: BtcGate, items: &mut Vec<Item>) {
        match gate {
            // NoAccount: the account card says it, next to `개인키 가져오기`.
            BtcGate::Disabled | BtcGate::NoAccount => {}
            BtcGate::Locked | BtcGate::NoMeta | BtcGate::JournalLoading => {
                items.push(Item::Muted(gate.text()));
            }
            BtcGate::Mismatch { meta, settings } => {
                items.push(Item::Banner(gate.text(), Tone::Danger));
                Self::btc_mismatch_row(meta, settings, items);
            }
            BtcGate::NoEndpoint => {
                items.push(Item::Banner(gate.text(), Tone::Danger));
                items.push(Item::Row(vec![Ctl::button(
                    crate::ui::screens::ids::SECTION_NETWORK,
                    "RPC 설정하기",
                )]));
            }
        }
    }

    fn btc_mismatch_row(meta: BtcNetwork, settings: BtcNetwork, items: &mut Vec<Item>) {
        let (keep, change) = mismatch_labels(meta, settings);
        items.push(Item::Row(vec![
            Ctl::button(ids::MISMATCH_KEEP_META, &keep),
            Ctl::button(ids::MISMATCH_USE_SETTINGS, &change),
        ]));
    }

    /// The S10 status line of the Bitcoin tab (network id and indexer name only, spec/04 §1.9).
    fn btc_status_line(&self, ctx: &BtcCtx<'_>) -> String {
        let net = ctx.net();
        let rpc = if ctx.core_url(net).is_none() {
            "엔드포인트 없음 (E-KEY-005)".to_owned()
        } else if self.btc.blocked.is_some() {
            "차단됨".to_owned()
        } else if let Some(tip) = self.btc.tip {
            format!("연결됨 · 블록 높이 {tip} (서버 기준)")
        } else {
            "확인 전".to_owned()
        };
        let indexer = crate::btc::indexer_display(ctx.settings.indexer);
        let checked = if self.btc.indexer_verified {
            "genesis 확인됨"
        } else {
            "확인 전"
        };
        format!(
            "Core RPC ({}): {rpc}   ·   인덱서: {indexer} ({checked})",
            crate::btc::network_id(net)
        )
    }

    fn btc_discovery_items(&self, ctx: &BtcCtx<'_>, items: &mut Vec<Item>) {
        let discovery = &self.btc.discovery;
        if discovery.running {
            items.push(Item::Muted(format!(
                "{} 검사한 주소 {}개",
                if discovery.more {
                    "주소를 더 찾는 중…"
                } else {
                    "주소를 찾는 중…"
                },
                discovery.checked
            )));
            items.push(Item::Row(vec![Ctl::button(ids::DISCOVER_CANCEL, "취소")]));
            return;
        }
        let incomplete = ctx.btc_meta().is_some_and(|meta| !meta.discovery_done());
        if discovery.error.is_some() || incomplete {
            let text = discovery
                .error
                .clone()
                .unwrap_or_else(|| DISCOVERY_INCOMPLETE.to_owned());
            items.push(Item::Banner(text, Tone::Warn));
            items.push(Item::Row(vec![
                Ctl::button(ids::DISCOVER_RETRY, "다시 시도").enabled(ctx.gate().is_ok()),
            ]));
        }
    }

    /// `새로고침` and, for an HD account after discovery, `더 찾기`.
    fn btc_refresh_row(&self, ctx: &BtcCtx<'_>, usable: bool, items: &mut Vec<Item>) {
        let discovery_done = ctx.btc_meta().is_some_and(BtcMeta::discovery_done);
        let single = ctx.btc_meta().is_some_and(BtcMeta::is_single);
        let mut row = vec![
            Ctl::button(ids::REFRESH, "새로고침")
                .enabled(usable && !self.btc.refresh.busy && !self.btc.discovery.running),
        ];
        if discovery_done && !single && !self.btc.discovery.running {
            row.push(Ctl::button(ids::DISCOVER_MORE, "더 찾기").enabled(usable));
        }
        items.push(Item::Row(row));
        if self.btc.refresh.busy {
            items.push(Item::Help("새로고침 중…".to_owned()));
        }
    }

    /// The account list (name, address type with prefix, balance; the selected one marked;
    /// imported keys with the "[가져온 키]" badge), `계정 추가` with its address-type chooser
    /// (wallets with recovery words), and the imported-key actions (`개인키 보기`·`삭제` of the
    /// selected imported account, `개인키 가져오기`).
    fn btc_account_items(&self, ctx: &BtcCtx<'_>, items: &mut Vec<Item>) {
        let net = ctx.net();
        items.push(Item::Subtitle("Bitcoin 계정".to_owned()));
        let usable = ctx.gate().is_ok() && !self.btc.slot;
        let rows = self.btc.account_rows(ctx);
        if rows.is_empty() {
            let none_at_all = ctx
                .meta
                .is_none_or(|meta| meta.btc_accounts.accounts.is_empty());
            items.push(Item::Muted(if none_at_all {
                crate::ui::screens_keys::no_accounts_text(yw_core::keyimport::ImportChain::Btc)
            } else {
                BtcGate::NoAccount.text()
            }));
        }
        for (index, row) in rows.iter().take(usize::from(ids::ACCOUNT_SPAN)).enumerate() {
            let id = ids::ACCOUNT_BASE.saturating_add(u16::try_from(index).unwrap_or(0));
            let hardware = matches!(row.id, yw_core::btc::BtcAccountId::Hardware { .. });
            let badge = match (row.imported, row.evm_shared) {
                _ if hardware => "[YubiKey] ".to_owned(),
                (true, _) => "[가져온 키] ".to_owned(),
                (false, Some(evm_index)) => format!("[EVM 계정 {evm_index} 키] "),
                (false, None) => String::new(),
            };
            // HD rows name their mnemonic with several (spec/02 §8.6).
            let name = match row.id {
                yw_core::btc::BtcAccountId::Hd {
                    mnemonic,
                    script_type,
                    account,
                } => self.mnemonic_tagged(
                    &format!("{} 계정 {account}", script_type.name()),
                    mnemonic.map(|id| *id.as_bytes()),
                ),
                _ => row.name.clone(),
            };
            let label = format!(
                "{badge}{name} · {} · {}",
                row.kind,
                BtcUi::amount_text(row.available)
            );
            items.push(Item::Row(vec![
                Ctl::radio(id, &label, row.selected, index == 0).enabled(usable || row.selected),
            ]));
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
            items.push(Item::Help(ADD_ACCOUNT_HELP.to_owned()));
            self.btc_add_source_items(ctx, usable, items);
            for (offset, script_type) in yw_core::btc::ScriptType::CHOICES.iter().enumerate() {
                let id = ids::ACCOUNT_ADD_TYPE.saturating_add(u16::try_from(offset).unwrap_or(0));
                items.push(Item::Row(vec![
                    Ctl::button(id, &script_type.label(net)).enabled(usable),
                ]));
            }
            items.push(Item::Row(vec![Ctl::button(
                ids::ACCOUNT_ADD_CANCEL,
                "취소",
            )]));
        } else {
            items.push(Item::Row(vec![
                Ctl::button(ids::ACCOUNT_ADD, "계정 추가").enabled(usable),
            ]));
        }
        items.push(Item::Help(ACCOUNTS_HELP.to_owned()));
        self.btc_imported_items(ctx, items);
    }

    /// The selected HD account's address mode (spec/08 §3.5): `고정 주소 하나만 사용` (default) /
    /// `받을 때마다 새 주소` with the one-line trade-off. One-key accounts have one address only.
    fn btc_address_mode_items(ctx: &BtcCtx<'_>, usable: bool, items: &mut Vec<Item>) {
        let Some(meta) = ctx.btc_meta().filter(|meta| meta.account().is_hd()) else {
            return;
        };
        let fixed = meta.fixed_address();
        items.push(Item::Text(format!(
            "주소 방식 — {}",
            crate::app_btc::account_label(meta.account())
        )));
        items.push(Item::Row(vec![
            Ctl::radio(
                ids::ADDRESS_MODE_SINGLE,
                crate::app_btc::T_BTC_MODE_SINGLE,
                fixed,
                true,
            )
            .enabled(usable),
        ]));
        items.push(Item::Row(vec![
            Ctl::radio(
                ids::ADDRESS_MODE_HD,
                crate::app_btc::T_BTC_MODE_HD,
                !fixed,
                false,
            )
            .enabled(usable),
        ]));
        items.push(Item::Help(crate::app_btc::T_BTC_MODE_HELP.to_owned()));
    }

    /// The add-account key source (spec/08 §3.5): the standard BTC path (default) or the key of
    /// an EVM account (warning and the EVM account radios; adding asks for confirmation).
    fn btc_add_source_items(&self, ctx: &BtcCtx<'_>, usable: bool, items: &mut Vec<Item>) {
        let evm = self.btc.add_source == crate::app_btc::BtcAddSource::EvmShared;
        if self.several_mnemonics() {
            // Which recovery phrase the standard-path account comes from (spec/02 §8.6).
            items.push(Item::Text("복구 단어".to_owned()));
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
                items.push(Item::Help(
                    "추가한 복구 단어의 표준 경로 m/{44·49·84·86}'/{코인}'/{계정}'에서 만듭니다(계정 0부터)."
                        .to_owned(),
                ));
                return;
            }
        }
        items.push(Item::Text("키 출처".to_owned()));
        items.push(Item::Row(vec![
            Ctl::radio(
                ids::ACCOUNT_SOURCE_STANDARD,
                crate::app_btc::T_BTC_SOURCE_STANDARD,
                !evm,
                true,
            )
            .enabled(usable),
        ]));
        items.push(Item::Help(
            crate::app_btc::T_BTC_SOURCE_STANDARD_HELP.to_owned(),
        ));
        items.push(Item::Row(vec![
            Ctl::radio(
                ids::ACCOUNT_SOURCE_EVM,
                crate::app_btc::T_BTC_SOURCE_EVM,
                evm,
                false,
            )
            .enabled(usable),
        ]));
        if !evm {
            return;
        }
        items.push(Item::Banner(
            crate::app_btc::T_BTC_EVM_SHARED.to_owned(),
            Tone::Warn,
        ));
        let accounts = ctx.evm_accounts();
        if accounts.is_empty() {
            items.push(Item::Muted("EVM 계정이 없습니다".to_owned()));
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
        items.push(Item::Help(
            "주소 형식을 누르면 확인 창이 열립니다. 그 EVM 계정의 키로 주소 하나를 만듭니다."
                .to_owned(),
        ));
    }

    fn btc_balance_items(&self, ctx: &BtcCtx<'_>, items: &mut Vec<Item>) {
        items.push(Item::Subtitle(active_label(ctx)));
        items.push(Item::Help(active_detail(ctx)));
        // U7, as on the EVM and Solana tabs: the account's phrase waits for its backup quiz.
        self.mn_signing_banner(self.btc_backup_gate(), items);
        if let Some(balance) = self.btc.balance(ctx) {
            items.push(Item::Display(BtcUi::amount_text(balance.available)));
            items.push(Item::Help("사용 가능 (확인 1 이상, 서버 기준)".to_owned()));
            if balance.frozen.get() > 0 {
                items.push(Item::Muted(format!(
                    "동결 {}",
                    BtcUi::amount_text(balance.frozen)
                )));
            }
            if balance.pending.get() > 0 {
                items.push(Item::Muted(format!(
                    "확인 대기 {} (아직 쓸 수 없음)",
                    BtcUi::amount_text(balance.pending)
                )));
            }
            items.push(Item::Help(
                    "잔액은 이전 거래로 검증한 UTXO 가운데 확인 수 1 이상(서버 기준)인 것의 합입니다. 진행 중 거래가 쓰는 UTXO는 빠집니다."
                        .to_owned(),
                ));
        } else {
            items.push(Item::Display("잔액 —".to_owned()));
            items.push(Item::Help("잔액 알 수 없음".to_owned()));
        }
        if self.btc.pending_incoming {
            items.push(Item::Banner(PENDING_INCOMING.to_owned(), Tone::Warn));
        }
        if self.btc.verify_failures > 0 {
            items.push(Item::Banner(
                format!("검증 실패 UTXO {}개", self.btc.verify_failures),
                Tone::Warn,
            ));
        }
        if self.btc.skipped_addresses > 0 {
            items.push(Item::Banner(
                format!(
                    "UTXO가 너무 많아 목록을 받지 못한 주소 {}개 — 그 주소의 UTXO는 지난번에 확인한 그대로 두며 이미 쓰였을 수 있습니다",
                    self.btc.skipped_addresses
                ),
                Tone::Warn,
            ));
        }
        if !self.btc.hint_mismatch.is_empty() {
            items.push(Item::Banner(
                format!(
                    "서버 응답 불일치 UTXO {}개 (검증한 값을 씁니다)",
                    self.btc.hint_mismatch.len()
                ),
                Tone::Warn,
            ));
        }
        if self.btc.auto_frozen > 0 {
            items.push(Item::Banner(
                format!(
                    "작은 입금 자동 동결(먼지 공격 방지) {}개",
                    self.btc.auto_frozen
                ),
                Tone::Info,
            ));
        }
    }

    fn btc_utxo_items(&self, ctx: &BtcCtx<'_>, items: &mut Vec<Item>) {
        items.push(Item::Subtitle("UTXO (검증됨)".to_owned()));
        items.push(Item::Help(
            "UTXO는 받은 돈 한 건 한 건입니다. 작은 입금은 먼지 공격을 막으려고 자동으로 동결합니다."
                .to_owned(),
        ));
        let utxos = self.btc.utxos(ctx);
        if utxos.is_empty() {
            items.push(Item::Help("검증된 UTXO가 없습니다.".to_owned()));
        }
        let can_freeze = self.btc_unlocked() && ctx.mismatch().is_none();
        for (row, utxo) in utxos.iter().take(usize::from(ids::UTXO_SPAN)).enumerate() {
            let mut line = format!(
                "{} · {}",
                BtcUi::amount_text(utxo.value),
                confirmations_text(utxo.confirmations)
            );
            match utxo.frozen {
                Some(FreezeReason::User) => line.push_str(" · 동결"),
                Some(FreezeReason::Auto) => {
                    line.push_str(" · 자동 동결(작은 입금, 먼지 공격 방지)");
                }
                None => {}
            }
            if utxo.in_flight {
                line.push_str(" · 진행 중 거래가 사용");
            }
            if utxo.own {
                line.push_str(" · 내 잔돈");
            }
            if utxo.hint_mismatch {
                line.push_str(" · 서버 응답 불일치");
            }
            if utxo.indexer_only {
                line.push_str(" · ");
                line.push_str(crate::app_btc::INDEXER_ONLY);
            }
            items.push(Item::Text(line));
            items.push(Item::Mono(utxo.outpoint.to_string()));
            let id = ids::UTXO_BASE.saturating_add(u16::try_from(row).unwrap_or(0));
            let label = if utxo.frozen.is_some() {
                "해제"
            } else {
                "동결"
            };
            items.push(Item::Row(vec![
                Ctl::button(id, label).enabled(can_freeze && !utxo.in_flight),
            ]));
        }
        let hidden = utxos.len().saturating_sub(usize::from(ids::UTXO_SPAN));
        if hidden > 0 {
            items.push(Item::Muted(format!(
                "UTXO {hidden}개는 목록에 표시하지 않았습니다(표시 상한 {}개).",
                ids::UTXO_SPAN
            )));
        }
    }

    #[expect(clippy::too_many_lines, reason = "one block per activity button")]
    fn btc_activity_items(&self, ctx: &BtcCtx<'_>, items: &mut Vec<Item>) {
        items.push(Item::Badged(
            Badge::bitcoin(ctx.net()),
            Box::new(Item::Subtitle("활동 (이 지갑이 보낸 거래)".to_owned())),
        ));
        let mut prompt_drawn = false;
        let rows = self.btc.activity_rows(ctx);
        if rows.is_empty() {
            items.push(Item::Help(format!(
                "아직 보낸 거래가 없습니다. {}",
                crate::ui::screens::T_ACTIVITY_RECEIVED
            )));
        }
        let usable = ctx.gate().is_ok();
        let unlocked = self.btc_unlocked();
        for (index, row) in rows.iter().enumerate() {
            let base = ids::ACTIVITY_BASE.saturating_add(
                u16::try_from(index)
                    .unwrap_or(0)
                    .saturating_mul(ids::ACTIVITY_STRIDE),
            );
            items.push(Item::Text(format!(
                "{} · {} · {}",
                local_time(row.time_unix_ms),
                active_label(ctx),
                row.title
            )));
            items.push(Item::Muted(format!("상태: {}", row.status)));
            if let Some(amount) = row.amount {
                items.push(Item::Muted(format!(
                    "받는 금액 {} · 받는 주소:",
                    BtcUi::amount_text(amount)
                )));
            } else if !row.counterparty.is_empty() {
                items.push(Item::Muted("받는 주소:".to_owned()));
            }
            if !row.counterparty.is_empty() {
                items.push(Item::Mono(grouped(&row.counterparty)));
            }
            items.push(Item::Mono(row.txid.clone()));
            let flow = Txid::from_display_hex(&row.txid)
                .ok()
                .and_then(|txid| self.btc.flow(&txid));
            if let Some(text) = flow.and_then(|flow| flow_stage_text(flow.stage)) {
                items.push(Item::Muted(text.to_owned()));
            }
            if let Some(note) = &row.note {
                let waiting = flow.is_some_and(|flow| flow.stage == BtcFlowStage::Waiting);
                items.push(Item::Banner(
                    note.clone(),
                    if waiting { Tone::Warn } else { Tone::Info },
                ));
            }
            let mut buttons = vec![Ctl::button(base, "해시 복사")];
            if row.can_bump {
                buttons.push(
                    Ctl::button(base.saturating_add(ids::ACT_BUMP), "수수료 올리기")
                        .enabled(usable),
                );
            }
            if row.can_rebroadcast {
                buttons.push(
                    Ctl::button(
                        base.saturating_add(ids::ACT_REBROADCAST),
                        "같은 바이트 다시 전송",
                    )
                    .enabled(usable),
                );
            }
            if row.can_abandon {
                buttons.push(
                    Ctl::button(base.saturating_add(ids::ACT_ABANDON), "포기").enabled(unlocked),
                );
            }
            if row.can_esplora {
                buttons.push(
                    Ctl::button(base.saturating_add(ids::ACT_ESPLORA), "Esplora로 전송")
                        .enabled(usable),
                );
            }
            if row.can_continue {
                let retry = flow.is_some_and(|flow| flow.retry_precheck);
                buttons.push(
                    Ctl::button(
                        base.saturating_add(ids::ACT_CONTINUE),
                        if retry {
                            "다시 시도"
                        } else {
                            "전송 계속"
                        },
                    )
                    .enabled(usable),
                );
                buttons.push(
                    Ctl::button(base.saturating_add(ids::ACT_CANCEL), "취소").enabled(unlocked),
                );
            }
            if self.offer_save(BookChain::Btc, &row.counterparty) {
                buttons.push(Ctl::link(
                    base.saturating_add(ids::ACT_SAVE),
                    "이 주소 저장",
                ));
            }
            items.push(Item::Row(buttons));
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
        items.push(Item::CardStart(Some("Bitcoin".to_owned())));
        items.push(Item::Text(BtcGate::Disabled.text()));
        items.push(Item::Help(if ctx.has_mnemonic {
                "설정 → Bitcoin에서 켜면 네이티브 세그윗(bc1q…) 계정 0의 주소를 찾아 잔액을 보여줍니다. 다른 주소 형식(탭루트·호환 세그윗·레거시)은 켠 뒤 [계정 추가]로 더하고, 다른 지갑의 WIF 개인키는 [개인키 가져오기]로 더합니다. 먼저 네트워크(RPC)에 bitcoin 주소가 있어야 합니다."
                    .to_owned()
            } else {
                "설정 → Bitcoin에서 켜면 가져온 Bitcoin 개인키의 잔액을 보여주고 받기·보내기를 할 수 있습니다. 먼저 네트워크(RPC)에 bitcoin 주소가 있어야 합니다."
                    .to_owned()
            }));
        items.push(Item::Row(vec![Ctl::primary(
            ids::SECTION_BTC,
            "Bitcoin 설정",
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
        if !ctx.settings.enabled {
            self.btc_disabled_items(&ctx, items);
            return;
        }
        items.push(Item::CardStart(None));
        network_banners(net, items);
        let gate = ctx.gate();
        if let Err(reason) = gate {
            Self::btc_gate_items(reason, items);
        }
        let mismatch = matches!(gate, Err(BtcGate::Mismatch { .. }));
        if ctx.journal_damaged() {
            items.push(Item::Banner(JOURNAL_DAMAGED.to_owned(), Tone::Blocked));
        }
        if let Some(text) = self.btc.blocked.as_ref().filter(|_| !mismatch) {
            items.push(Item::Banner(text.clone(), Tone::Blocked));
            if self.btc.tip_regressed {
                items.push(Item::Help(
                    "노드 블록 높이가 이 지갑이 전에 본 높이보다 6블록 넘게 낮습니다. 노드(RPC)를 바꿨거나 이전 노드가 잘못된 높이를 알려 준 경우에만 기록을 초기화하세요."
                        .to_owned(),
                ));
                items.push(Item::Row(vec![
                    Ctl::button(ids::RESET_TIP, "블록 높이 기록 초기화")
                        .enabled(self.btc_unlocked()),
                ]));
            }
        }
        if let Some(lag) = self.btc.lag_warning {
            items.push(Item::Banner(
                crate::btc::chain::lag_warning_text(lag),
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
                format!(
                    "서명했지만 보내지 않은 Bitcoin 거래가 {signed}건 있습니다. 아래 활동에서 [전송 계속] 또는 [취소]를 고르세요."
                ),
                Tone::Warn,
            ));
        }
        self.btc_discovery_items(&ctx, items);
        let usable = gate.is_ok();
        self.btc_refresh_row(&ctx, usable, items);
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
        {
            items.push(Item::CardStart(None));
            self.btc_balance_items(&ctx, items);
            let send_block = self.btc.send_block(&ctx);
            let mut actions = vec![
                Ctl::primary(ids::SEND_OPEN, "보내기").enabled(send_block.is_none()),
                Ctl::primary(ids::RECEIVE_OPEN, "받기").enabled(self.btc_unlocked()),
            ];
            if BtcUi::bump_target(&ctx).is_some() {
                actions.push(
                    Ctl::button(ids::BUMP_OPEN, "수수료 올리기")
                        .enabled(usable && !self.btc.slot && !ctx.journal_damaged()),
                );
            }
            items.push(Item::Row(actions));
            if let Some(reason) = send_block {
                items.push(Item::Help(format!("보내기: {reason}")));
            }
            items.push(Item::CardEnd);
        }
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
        items.push(Item::CardEnd);
    }

    /// The fee radios, manual rate, floor note and typed-fee override of a form.
    fn btc_fee_items(&self, fee: &BtcFeeForm, bump: bool, items: &mut Vec<Item>) {
        let radio_ids = fee_ids(bump);
        let radios = FEE_CHOICES
            .iter()
            .zip(radio_ids)
            .enumerate()
            .map(|(index, (choice, id))| {
                Ctl::radio(id, choice.label(), fee.choice == *choice, index == 0)
            })
            .collect();
        items.push(Item::LabeledRow("수수료".to_owned(), radios));
        items.push(Item::Help(
            "빠름·보통·느림 = 노드 추정(2·6·24블록). 추정이 없으면(testnet4에서 흔함) 직접 입력만 됩니다."
                .to_owned(),
        ));
        if fee.choice == BtcFeeChoice::Manual {
            let id = if bump {
                ids::BUMP_MANUAL_EDIT
            } else {
                ids::FEE_MANUAL_EDIT
            };
            items.push(Item::LabeledRow(
                "수수료율 (sat/vB)".to_owned(),
                vec![Ctl::edit(id, &fee.manual_text, 160, false, 12)],
            ));
        }
        items.push(Item::Help(match self.btc.floor {
            Some(floor) => format!(
                "수수료 하한 {floor} (노드 기준): 추정이 하한보다 낮으면 하한을 적용합니다(하한 적용). 직접 입력은 하한 이상이어야 합니다."
            ),
            None => "수수료 하한(1 sat/vB와 노드 최소값 중 큰 값)은 검토할 때 노드에서 확인합니다."
                .to_owned(),
        }));
        if let Some(error) = &fee.error {
            items.push(Item::Banner(error.clone(), Tone::Danger));
        }
        if let Some(planned) = fee.needs_typed {
            items.push(Item::Banner(
                format!(
                    "수수료(sats)를 정확히 입력해 상한 해제 — 계획 수수료 {}",
                    BtcUi::amount_text(planned)
                ),
                Tone::Warn,
            ));
            let id = if bump {
                ids::BUMP_TYPED_EDIT
            } else {
                ids::TYPED_FEE_EDIT
            };
            items.push(Item::LabeledRow(
                "수수료(sats)".to_owned(),
                vec![Ctl::edit(id, &fee.typed_text, 200, false, 20)],
            ));
        }
    }

    /// S11 for Bitcoin (spec/08 §7–§8, spec/04 §2.7).
    #[expect(clippy::too_many_lines, reason = "the Bitcoin S11 fields in order")]
    pub fn btc_send_screen(&self, items: &mut Vec<Item>) {
        let ctx = self.btc_ctx();
        let net = ctx.net();
        items.push(crate::ui::screens::back_main());
        items.push(Item::Badged(
            Badge::bitcoin(net),
            Box::new(Item::Title(format!("보내기 — {}", net.display_name()))),
        ));
        network_banners(net, items);
        let form = &self.btc.send;
        // Why the form cannot send at all is said first; what `검토` ended with is said next
        // to the button (below).
        let block = self.btc.send_block(&ctx);
        if let Some(reason) = &block {
            items.push(Item::Banner(reason.clone(), Tone::Warn));
        }
        if ctx.journal_damaged() {
            items.push(Item::Banner(JOURNAL_DAMAGED.to_owned(), Tone::Blocked));
        }
        items.push(Item::CardStart(Some("보내는 계정".to_owned())));
        items.push(Item::Text(active_label(&ctx)));
        items.push(Item::Help(active_detail(&ctx)));
        if let Some(balance) = self.btc.balance(&ctx) {
            items.push(Item::Help(format!(
                "사용 가능 {} (검증됨, 확인 1 이상 서버 기준)",
                BtcUi::amount_text(balance.available)
            )));
        }
        self.mn_signing_banner(self.btc_backup_gate(), items);
        items.push(Item::CardEnd);
        items.push(Item::CardStart(Some("받는 사람".to_owned())));
        let target = BookTarget::Btc(net);
        self.favorite_chip_items(target, items);
        items.push(Item::LabeledRow(
            "받는 주소".to_owned(),
            vec![
                Ctl::edit(ids::SEND_TO_EDIT, &form.to_text, 430, false, 128),
                Ctl::button(crate::ui::screens_book::ids::BTC_PICK, "주소록에서 선택"),
            ],
        ));
        items.push(Item::Help(
            "bc1…·tb1… 등 Bitcoin 주소입니다. 붙여넣은 뒤 굵게 표시된 앞 6자·뒤 6자와 가운데까지 전체를 확인하세요."
                .to_owned(),
        ));
        self.btc_picker_items(target, items);
        if let Some(error) = &form.recipient_error {
            items.push(Item::Banner(error.clone(), Tone::Danger));
        } else if let Some(kind) = form.recipient {
            items.push(Item::Help(format!("주소 종류: {}", kind.type_label())));
            let address = encode_address(&kind, net);
            items.push(Item::Mono(grouped(&address)));
            let entry = self
                .meta
                .as_ref()
                .and_then(|meta| meta.contact(BookChain::Btc, &address));
            if let Some(entry) = &entry {
                items.push(Item::Banner(
                    format!(
                        "주소록: {}{}",
                        entry.label,
                        if entry.verified { " ✓ 확인됨" } else { "" }
                    ),
                    Tone::Info,
                ));
            }
            if let Some(note) = &form.look_alike {
                items.push(Item::Banner(note.clone(), Tone::HighRisk));
                items.push(Item::Row(vec![Ctl::check(
                    ids::SEND_ADDR_ACK,
                    "주소 전체를 직접 확인했습니다",
                    form.ack,
                )]));
                if entry.as_ref().is_some_and(|entry| !entry.verified) {
                    items.push(Item::Help(crate::app_book::T_BOOK_VERIFY_HINT.to_owned()));
                }
            }
            self.recipient_save_items(target, items);
        }
        items.push(Item::CardEnd);
        items.push(Item::CardStart(Some("금액과 수수료".to_owned())));
        items.push(Item::LabeledRow(
            "금액".to_owned(),
            vec![
                Ctl::edit(ids::SEND_AMOUNT_EDIT, &form.amount_text, 220, false, 32)
                    .enabled(!form.send_max),
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
                Ctl::check(ids::SEND_MAX, "보내기 최대", form.send_max),
            ],
        ));
        if let Some(error) = &form.amount_error {
            items.push(Item::Banner(error.clone(), Tone::Danger));
        } else if let Some(amount) = form.amount {
            items.push(Item::Help(BtcUi::amount_text(amount)));
        }
        if form.send_max {
            items.push(Item::Help(
                "보내기 최대: 동결되지 않은 확인된 UTXO(최대 100개)의 합에서 수수료를 뺀 금액을 보냅니다(승인 창에서 확인)."
                    .to_owned(),
            ));
        }
        items.push(Item::Help(
            "BTC는 소수 8자리까지(예 0.0012), sats는 정수(예 120000)로 입력합니다. 천 단위 구분자·지수 표기는 받지 않습니다."
                .to_owned(),
        ));
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
                if info.as_str() == crate::app_btc::BTC_PREPARING {
                    Tone::Info
                } else {
                    Tone::Warn
                },
            ));
        }
        items.push(Item::CardEnd);
        items.push(Item::Row(vec![
            Ctl::primary(ids::SEND_REVIEW, "검토").enabled(self.btc_can_review()),
            Ctl::button(ids::SEND_CANCEL, "취소"),
        ]));
    }

    /// Whether the send form's `검토` is enabled: the controller's checks, and an account whose
    /// phrase has passed its backup quiz (U7; the band above says why).
    #[must_use]
    pub fn btc_can_review(&self) -> bool {
        self.btc.can_review(&self.btc_ctx()) && !self.mn_send_blocked(self.btc_backup_gate())
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
        items.push(crate::ui::screens::back_main());
        items.push(Item::Title(format!(
            "수수료 올리기 — {}",
            net.display_name()
        )));
        network_banners(net, items);
        let form = &self.btc.bump;
        if let Some(info) = &form.info {
            items.push(Item::Banner(info.clone(), Tone::Warn));
        }
        if ctx.journal_damaged() {
            items.push(Item::Banner(JOURNAL_DAMAGED.to_owned(), Tone::Danger));
        }
        let target = form
            .target
            .and_then(|txid| ctx.record(&txid))
            .or_else(|| BtcUi::bump_target(&ctx));
        if let Some(record) = target {
            items.push(Item::Text("교체 대상 거래".to_owned()));
            items.push(Item::Mono(record.txid.to_display_hex()));
            items.push(Item::Muted(format!(
                "상태: {}",
                record_status(&record, self.btc_tip(&ctx))
            )));
            items.push(Item::Muted(format!(
                "현재 수수료 {} · {}",
                BtcUi::amount_text(record.fee),
                record_rate(record.fee, record.vsize)
            )));
            if let Some(amount) = record.recipient_amount() {
                items.push(Item::Muted(format!(
                    "받는 금액 {}{} · 받는 주소:",
                    BtcUi::amount_text(amount),
                    if record.send_max {
                        " (보내기 최대: 수수료가 오른 만큼 받는 금액이 줄어듭니다)"
                    } else {
                        ""
                    }
                )));
            }
            if let Some(address) = record.recipient_address() {
                items.push(Item::Mono(grouped(&address)));
            }
        } else {
            items.push(Item::Muted(texts::NOT_BUMPABLE.to_owned()));
        }
        items.push(Item::Muted(
            "새 수수료는 이전 수수료 + 노드 최소 증분 이상이고 수수료율이 더 높아야 합니다. 받는 주소·금액은 그대로이고(보내기 최대 거래는 받는 금액이 줄어듭니다) 매번 새로 승인합니다."
                .to_owned(),
        ));
        self.btc_fee_items(&form.fee, true, items);
        items.push(Item::Row(vec![
            Ctl::primary(ids::BUMP_REVIEW, "검토").enabled(self.btc_can_review_bump()),
            Ctl::button(ids::BUMP_CANCEL, "취소"),
        ]));
    }

    /// The S11 result for Bitcoin: the local txid, status and the post-sign flow.
    pub fn btc_send_result_screen(&self, items: &mut Vec<Item>) {
        let ctx = self.btc_ctx();
        let net = ctx.net();
        let record = self.btc.result.and_then(|txid| ctx.record(&txid));
        let bump = record
            .as_ref()
            .is_some_and(|record| record.replaces.is_some());
        items.push(Item::Title(
            if bump {
                "수수료 올리기 결과"
            } else {
                "보내기 결과"
            }
            .to_owned(),
        ));
        network_banners(net, items);
        let Some(txid) = self.btc.result else {
            items.push(Item::Muted("표시할 결과가 없습니다.".to_owned()));
            items.push(Item::Row(vec![Ctl::button(
                crate::ui::screens::ids::BACK_MAIN,
                "메인으로",
            )]));
            return;
        };
        items.push(Item::Banner(
            "서명하고 저널에 기록했습니다. 아래 해시는 이 지갑이 계산한 값입니다.".to_owned(),
            Tone::Success,
        ));
        items.push(Item::Mono(txid.to_display_hex()));
        let status = record.as_ref().map_or_else(
            || "종결 (활동 참고)".to_owned(),
            |record| record_status(record, self.btc_tip(&ctx)),
        );
        items.push(Item::Badged(
            Badge::bitcoin(net),
            Box::new(Item::Muted(format!(
                "상태: {status} ({})",
                net.display_name()
            ))),
        ));
        let flow = self.btc.flow(&txid);
        if let Some(text) = flow.and_then(|flow| flow_stage_text(flow.stage)) {
            items.push(Item::Muted(text.to_owned()));
        }
        if let Some(note) = flow.and_then(|flow| flow.note.clone()) {
            let waiting = flow.is_some_and(|flow| flow.stage == BtcFlowStage::Waiting);
            items.push(Item::Banner(
                note,
                if waiting { Tone::Warn } else { Tone::Info },
            ));
        }
        let mut row = vec![Ctl::button(ids::RESULT_COPY, "해시 복사")];
        let signed = record
            .as_ref()
            .is_some_and(|record| record.state == yw_core::journal::btc::BtcTxState::Signed);
        if signed
            && flow.is_some_and(|flow| flow.retry_precheck && flow.stage == BtcFlowStage::Waiting)
        {
            row.push(Ctl::button(ids::RESULT_RETRY, "다시 시도").enabled(ctx.gate().is_ok()));
        }
        let rejected = record
            .as_ref()
            .filter(|record| record.state == yw_core::journal::btc::BtcTxState::Rejected);
        if let Some(rejected) = rejected
            && !bump
        {
            items.push(Item::Muted(if rejected.disclosed {
                yw_core::btc::policy::texts::REJECTED_DISCLOSED.to_owned()
            } else {
                "전송하지 않았습니다. 입력은 보내기 화면에 남아 있으니 수수료를 바꿔 다시 검토하세요."
                    .to_owned()
            }));
            row.push(Ctl::button(ids::RESULT_TO_SEND, "보내기 화면으로"));
        }
        row.insert(
            0,
            Ctl::primary(crate::ui::screens::ids::BACK_MAIN, "메인으로"),
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
        items.push(crate::ui::screens::back_main());
        items.push(Item::Badged(
            Badge::bitcoin(net),
            Box::new(Item::Title(format!("받기 — {}", net.display_name()))),
        ));
        network_banners(net, items);
        if let Some(message) = &self.btc.receive_message {
            items.push(Item::Banner(message.clone(), Tone::Danger));
        }
        // An HD account of the primary phrase or an EVM key's use is the primary phrase's key.
        self.mn_receive_banner(self.btc_backup_gate(), items);
        let Some(view) = &self.btc.receive else {
            if self.btc.receive_message.is_none() {
                items.push(Item::Muted("주소를 준비하는 중…".to_owned()));
            }
            return;
        };
        items.push(Item::CardStart(Some(if view.single_key {
            view.account.clone()
        } else if view.fixed {
            format!("{} · 고정 주소", view.account)
        } else {
            format!("{} · 받기 주소 {}번", view.account, view.index)
        })));
        items.push(Item::Text(format!("주소 형식: {}", view.kind)));
        if view.fixed && !view.single_key {
            // An HD account in fixed-address mode (spec/08 §3.5): said before the QR.
            items.push(Item::Banner(
                crate::app_btc::T_BTC_FIXED_RECEIVE.to_owned(),
                Tone::Info,
            ));
        }
        // Address and `주소 복사` before the QR (2026-11-08, all chains).
        items.push(Item::Mono(grouped(&view.address)));
        let mut row = vec![Ctl::primary(ids::COPY_ADDRESS, "주소 복사")];
        if !view.fixed {
            row.push(Ctl::button(ids::NEW_ADDRESS, "새 주소").enabled(ctx.gate().is_ok()));
        }
        items.push(Item::Row(row));
        items.push(Item::Help(view.note.clone()));
        items.push(Item::Qr(view.qr.clone()));
        items.push(Item::Help(view.path.clone()));
        items.push(Item::CardEnd);
    }

    /// S15 Bitcoin section (spec/04 §2.11, spec/08 §2).
    #[expect(clippy::too_many_lines, reason = "the S15 Bitcoin rows in order")]
    pub fn btc_settings_section(&self, items: &mut Vec<Item>) {
        let ctx = self.btc_ctx();
        let settings = ctx.settings;
        let net = ctx.net();
        if let Some(message) = &self.btc.settings_message {
            items.push(Item::Banner(message.clone(), Tone::Danger));
        }
        items.push(Item::CardStart(Some("Bitcoin 사용과 네트워크".to_owned())));
        items.push(Item::Row(vec![Ctl::check(
            ids::ENABLE,
            "Bitcoin 사용",
            settings.enabled,
        )]));
        items.push(Item::LabeledRow(
            "네트워크".to_owned(),
            vec![
                Ctl::radio(
                    ids::SET_MAINNET,
                    "mainnet",
                    net == BtcNetwork::Mainnet,
                    true,
                ),
                Ctl::radio(
                    ids::SET_TESTNET4,
                    "testnet4 (테스트, 가치 없음)",
                    net == BtcNetwork::Testnet4,
                    false,
                ),
            ],
        ));
        if settings.enabled {
            items.push(Item::Banner(net.banner().to_owned(), network_tone(net)));
            if let Some((meta, current)) = ctx.mismatch() {
                items.push(Item::Banner(
                    texts::NETWORK_MISMATCH.to_owned(),
                    Tone::Danger,
                ));
                Self::btc_mismatch_row(meta, current, items);
            }
        }
        items.push(Item::Help(
            "켤 때 고른 네트워크의 BIP84 주소를 찾습니다. 켠 뒤 네트워크를 바꾸면(진행 중 거래가 없을 때만) 주소 인덱스·UTXO 캐시·동결·보낸 주소 기록을 새로 시작하고 다시 찾습니다. 끄면 데이터는 남습니다."
                .to_owned(),
        ));
        for known in BtcNetwork::ALL {
            let network = crate::btc::network_id(known);
            let state = if self.apikeys.has(KeyName::Rpc(network)) {
                "설정됨".to_owned()
            } else {
                format!("없음 — {}", ErrorCode::Key005.code())
            };
            items.push(Item::Help(format!("Core 엔드포인트 {network}: {state}")));
        }
        items.push(Item::Row(vec![Ctl::button(
            crate::ui::screens::ids::GO_NETWORK,
            "네트워크(RPC) 설정으로",
        )]));
        items.push(Item::CardEnd);
        items.push(Item::CardStart(Some("주소 조회 서버(인덱서)".to_owned())));
        let indexer = settings.indexer;
        items.push(Item::LabeledRow(
            "인덱서".to_owned(),
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
        items.push(Item::Help(T_BTC_ESPLORA_NOTE.to_owned()));
        items.push(Item::Help(
            "Esplora: 무료·키 없음(기본 mempool.space). bb-rpc: Core URL의 bb_* (QuickNode BTC Blockbook 유료 애드온). bb-rest: Core URL의 /api/v2/ (알케미 UTXO API)."
                .to_owned(),
        ));
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
                Ctl::button(save, "저장"),
                Ctl::button(default, "기본값으로"),
                Ctl::button(test, "테스트"),
            ]));
            if let Some((_, message, ok)) = self
                .btc
                .esplora_tests
                .iter()
                .find(|(tested, ..)| *tested == known)
            {
                items.push(Item::Banner(
                    message.clone(),
                    if *ok { Tone::Success } else { Tone::Danger },
                ));
            }
        }
        items.push(Item::Help(
            "`테스트`는 입력 칸의 값(비어 있으면 저장된 값)으로 GET /block-height/0을 한 번 보냅니다. 주소를 보내지 않으므로 잠긴 상태에서도 됩니다. `저장`은 테스트를 요구하지 않으며 쓰기 전에 연결 검사가 다시 확인합니다."
                .to_owned(),
        ));
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
    use crate::errors::ErrorCode;
    use crate::events::JournalView;
    use crate::meta::{Meta, Tab};
    use crate::network::{BtcNet, NetworkId};
    use crate::settings::Settings;
    use crate::ui::main_window::{Ctl, Item, Tone};
    use crate::ui::theme::{address_segments, btc_address_segments};

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
                Item::Row(ctls) | Item::LabeledRow(_, ctls) => ctls.clone(),
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
            | Item::Banner(text, _) => text.contains(wanted),
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
    fn btc_grouped_address_bolds_first_and_last_six_characters() {
        let address = "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu";
        let text = grouped(address);
        assert_eq!(text, "bc1q cr8t e4kr 609g cawu tmrz a0j4 xv80 jy8z 306f yu");
        let segments = btc_address_segments(&text).unwrap();
        let joined: String = segments.iter().map(|(piece, _)| *piece).collect();
        assert_eq!(joined, text);
        let bold: String = segments
            .iter()
            .filter(|(_, bold)| *bold)
            .map(|(piece, _)| *piece)
            .collect();
        assert_eq!(bold, "bc1qcr306fyu");
        assert_eq!(segments.first(), Some(&("bc1q", true)));
        assert!(segments.contains(&("cr", true)));
        assert!(segments.contains(&("8t", false)));
        assert_eq!(segments.last(), Some(&("yu", true)));
        // Testnet4 and base58 addresses take the same rule.
        let testnet = grouped("tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx");
        assert!(btc_address_segments(&testnet).is_some());
        let legacy = grouped("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2");
        let bold: String = btc_address_segments(&legacy)
            .unwrap()
            .iter()
            .filter(|(_, bold)| *bold)
            .map(|(piece, _)| *piece)
            .collect();
        assert_eq!(bold, "1BvBMSJaNVN2");
        // Ungrouped, altered or non-address text keeps its weight; Solana keeps its own rule.
        for text in [
            address,
            "bc1q cr8t e4kr 609g cawu tmrz a0j4 xv80 jy8z 306f yv",
            "bc1 qcr8 te4k r609 gcaw utmr za0j 4xv8 0jy8 z306 fyu",
            "bitc oin: bc1q",
            "0x98 58Ef FD23",
            "",
        ] {
            assert!(btc_address_segments(text).is_none(), "{text}");
        }
        let sol = "HAgk 14Jp MQLg t6rV gv7c BQFJ WFto 5Dqx i472 uT3D Kpqk";
        assert!(btc_address_segments(sol).is_none());
        assert!(address_segments(sol).is_some());
        assert!(address_segments(&text).is_some());
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
            mismatch_labels(BtcNetwork::Mainnet, BtcNetwork::Testnet4),
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
        assert!(items.iter().any(|item| matches!(
            item,
            Item::Banner(text, Tone::BtcMainnet) if text == "BITCOIN MAINNET"
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
            let items = app.items();
            let row = control(&items, ids::ACCOUNT_BASE).expect("account row");
            assert!(
                row.text
                    .starts_with("네이티브 세그윗 계정 0 · 네이티브 세그윗 (")
            );
            assert_eq!(row.checked, Some(true));
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
            assert!(!has_text(&items, crate::app_btc::T_BTC_EVM_SHARED));
            app.btc.add_source = crate::app_btc::BtcAddSource::EvmShared;
            let items = app.items();
            assert_eq!(
                control(&items, ids::ACCOUNT_SOURCE_EVM).and_then(|ctl| ctl.checked),
                Some(true)
            );
            assert!(has_text(&items, crate::app_btc::T_BTC_EVM_SHARED));
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
        assert!(has_text(&items, crate::app_btc::T_BTC_MODE_HELP));
        let meta = app.btc_ctx().btc_meta().cloned().unwrap();
        app.btc.receive = crate::app_btc::BtcUi::receive_view(&meta, 0);
        app.screen = Screen::BtcReceive;
        let items = app.items();
        assert!(has_text(&items, crate::app_btc::T_BTC_FIXED_RECEIVE));
        assert!(has_text(&items, "m/84'/1'/0'/0/0"));
        assert!(control(&items, ids::NEW_ADDRESS).is_none());
        assert!(control(&items, ids::COPY_ADDRESS).is_some());
        // HD mode.
        let mut hd_meta = meta;
        hd_meta.set_single_address(false).unwrap();
        if let Some(document) = app.meta.as_mut() {
            document.btc = Some(Box::new(hd_meta.clone()));
        }
        app.btc.receive = crate::app_btc::BtcUi::receive_view(&hd_meta, 3);
        let items = app.items();
        assert!(!has_text(&items, crate::app_btc::T_BTC_FIXED_RECEIVE));
        assert!(has_text(&items, "m/84'/1'/0'/0/3"));
        assert!(control(&items, ids::NEW_ADDRESS).is_some());
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
        assert!(position(ids::SEND_OPEN) < position(ids::ACCOUNT_BASE));
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
        // One Bitcoin banner, not a second generic testnet band.
        assert_eq!(
            items
                .iter()
                .filter(|item| matches!(item, Item::Banner(_, Tone::BtcTestnet4 | Tone::Testnet)))
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
        // No endpoint: E-KEY-005 and `RPC 설정하기`.
        let app_no_url = app(true, BtcNet::Testnet4, Some(BtcNetwork::Testnet4), false);
        let items = app_no_url.items();
        assert!(has_text(&items, &ErrorCode::Key005.text()));
        assert!(control(&items, crate::ui::screens::ids::SECTION_NETWORK).is_some());
        assert!(items.iter().any(|item| matches!(
            item,
            Item::Banner(text, Tone::BtcTestnet4) if text == "BITCOIN TESTNET4 — 가치 없음"
        )));
        assert!(
            !items
                .iter()
                .any(|item| matches!(item, Item::Banner(_, Tone::Testnet)))
        );
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
        assert!(has_text(&items, T_BTC_ESPLORA_NOTE));
        assert!(has_text(&items, "https://mempool.space/testnet4/api"));
        assert_eq!(
            control(&items, ids::ESPLORA_MAINNET_EDIT).map(|ctl| ctl.text),
            Some("https://mempool.space/api".to_owned())
        );
        assert!(has_text(&items, "Core 엔드포인트 bitcoin:mainnet: 설정됨"));
        assert!(has_text(
            &items,
            "Core 엔드포인트 bitcoin:testnet4: 없음 — E-KEY-005"
        ));
        // The selected settings tab is drawn selected (Ctl::tab).
        assert_eq!(
            control(&items, ids::SECTION_BTC).and_then(|ctl| ctl.checked),
            Some(true)
        );
        app.screen = Screen::ImportIntro;
        assert!(has_text(&app.items(), BTC_IMPORT_NOTE));
        app.screen = Screen::Settings(SettingsSection::Network);
        let items = app.items();
        assert!(!has_text(&items, "M8"));
        assert!(has_text(&items, "(bitcoin:testnet4)"));
    }
}
