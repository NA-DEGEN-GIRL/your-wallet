//! The S10 Zcash tab (spec/12 §11, spec/04 §2.6): enable / network, account and key source,
//! balance, receive (transparent address, QR, the Zashi note), send (t-address, TEX or the
//! transparent receiver of a UA; amount or `보내기 최대`; review, with what it ended with next
//! to `검토`), activity (this wallet's journal records with `해시 복사`, and the address UTXOs).
//! One page, no extra screens.

use yw_core::journal::zec::ZecTxState;
use yw_core::lang::Lang;
use yw_core::zec::{ZecKeySource, ZecNetwork, format_zec, format_zec_and_zats};

use crate::app::{App, AppMode};
use crate::settings::ZecIndexer;
use crate::ui::badge::Badge;
use crate::ui::main_window::{Ctl, Item};
use crate::ui::screens_accounts::AccountItem;
use crate::zec::rpc::ZecRpcError;
use yw_engine::screen::AccountSource;
use yw_engine::screen::Tone;

/// Fixed texts of the S10 Zcash tab (spec/12 §11, spec/04 §2.6; English spec/14 §5).
pub mod text {
    yw_core::texts! {
        OWN_CHANGE(1) = "확인 대기 {0} (내 거래의 잔돈, 아직 쓸 수 없음)"
            / "Awaiting confirmation {0} (change of your own transaction, not spendable yet)";
        UNCLASSIFIED(1) = "미확정 출력 {0} (0 확인 — 입금인지 확인하지 않았습니다, 아직 쓸 수 없음)"
            / "Unconfirmed outputs {0} (0 confirmations — not checked as a deposit, not spendable yet)";
        /// T-ZEC-RECEIVE.
        RECEIVE_NOTE = "일반(transparent) 주소입니다 — Zashi 등 비공개 주소로 받으려면 그 지갑에서 받으세요."
            / "This is a transparent address — to receive on a shielded address (Zashi etc.), receive in that wallet.";
        /// T-ZEC-EVM-SHARED: the linkage warning of the EVM-key source.
        EVM_SHARED = "EVM 계정과 같은 키를 쓰면 EVM 주소와 이 Zcash 주소가 같은 공개키라 누구나 두 주소를 한 사람의 것으로 묶을 수 있습니다. 같은 복구 단어를 다른 Zcash 지갑에 넣어도 이 주소는 나오지 않습니다(표준 경로가 아님). 정말 필요할 때만 쓰세요."
            / "With the same key as an EVM account, the EVM address and this Zcash address share one public key, so anyone can link both addresses to one person. Putting the same recovery phrase into another Zcash wallet does not give this address (not the standard path). Use it only when you really need to.";
        REVEAL_KEY = "개인키 보기" / "Show private key";
        DELETE = "삭제" / "Delete";
        IMPORT_HELP = "다른 지갑(zcashd 등)의 Zcash 일반 주소 개인키(압축 WIF 또는 16진수)를 가져와 이 네트워크의 계정으로 쓸 수 있습니다. 가져온 키는 복구 단어로 복구되지 않습니다."
            / "You can import a Zcash transparent address private key (compressed WIF or hex) from another wallet (zcashd etc.) and use it as this network's account. An imported key is not restored by the recovery phrase.";
        IMPORT_KEY = "개인키 가져오기" / "Import private key";
        DISABLED_TITLE = "Zcash (일반 주소 전용)" / "Zcash (transparent addresses only)";
        DISABLED_TEXT = "Zcash 일반(transparent) 주소로 받고 보냅니다. 비공개(shielded) 전송은 지원하지 않습니다."
            / "Receives and sends with a Zcash transparent address. Shielded transfers are not supported.";
        DISABLED_HELP = "켜면 복구 단어에서 m/44'/133'/0'/0/0 (testnet m/44'/1'/0'/0/0) 주소 하나를 씁니다. 먼저 설정 → 네트워크(RPC)에서 그 네트워크의 Zcash RPC 주소(zcash:mainnet·zcash:testnet)를 넣으세요."
            / "When on, one address m/44'/133'/0'/0/0 (testnet m/44'/1'/0'/0/0) of the recovery phrase is used. First enter that network's Zcash RPC address (zcash:mainnet·zcash:testnet) in Settings → Networks (RPC).";
        ENABLE_MAINNET = "Zcash mainnet 켜기" / "Turn on Zcash mainnet";
        ENABLE_TESTNET = "Zcash testnet 켜기 (테스트)" / "Turn on Zcash testnet (test)";
        RPC_SETUP = "RPC 설정하기" / "Set up RPC";
        JOURNAL_DAMAGED = "거래 저널의 Zcash 기록이 손상되어 Zcash 보내기를 멈췄습니다. (E-VLT-006)"
            / "The Zcash records of the transaction journal are damaged, so Zcash sending is stopped. (E-VLT-006)";
        NETWORK = "네트워크" / "Network";
        TESTNET_CHIP = "Zcash testnet (테스트)" / "Zcash testnet (test)";
        RPC_NONE = "RPC 주소 없음 (E-KEY-005) — 설정 → 네트워크(RPC)에서 Zcash RPC 주소를 넣으세요"
            / "No RPC address (E-KEY-005) — enter the Zcash RPC address in Settings → Networks (RPC)";
        UPGRADE_UNKNOWN = "알 수 없음" / "unknown";
        RPC_CONNECTED(2) = "연결됨 (genesis 확인) · 블록 {0} · 업그레이드 {1}"
            / "Connected (genesis verified) · block {0} · upgrade {1}";
        RPC_CHECKING = "확인 중…" / "Checking…";
        RPC_UNCHECKED = "확인 전" / "Not checked yet";
        UTXO_SOURCE = "UTXO 원천" / "UTXO source";
        INDEXER_NODE = "노드 getaddressutxos" / "Node getaddressutxos";
        DISABLE = "Zcash 끄기" / "Turn off Zcash";
        ACCOUNT_TITLE(1) = "Zcash 계정 · {0}" / "Zcash account · {0}";
        ACCOUNT_LOADING = "Zcash 계정 키를 불러오는 중… (복구 단어가 없는 지갑은 YubiKey Zcash 슬롯만 쓸 수 있습니다)"
            / "Loading the Zcash account key… (a wallet without a recovery phrase can only use a YubiKey Zcash slot)";
        KEY_SOURCE_LINE(2) = "키 출처: {0} · {1}" / "Key source: {0} · {1}";
        BALANCE_DASH = "잔액 —" / "Balance —";
        CONFIRMED_BALANCE_NOTE(1) = "확인된 잔액 {0} (서버 기준, 진행 중 거래의 입력 제외)"
            / "Confirmed balance {0} (per the server, inputs of transactions in progress excluded)";
        REFRESH = "새로고침" / "Refresh";
        /// The account card (2026-11-15: the shared card `내 Zcash 계정` whose drop-down lists
        /// the key sources; before, a card `키 출처` with the radios `키 출처 바꾸기`, `이 키 출처
        /// 사용`, `YubiKey Zcash 주소 {0} 사용`, `{0} 표준 경로 사용` and `[가져온 키] {0}` rows
        /// with `이 키 사용`).
        MY_ACCOUNTS = "내 Zcash 계정" / "My Zcash accounts";
        /// The drop-down item of the wallet's own recovery words.
        SOURCE_STANDARD = "Zcash 표준 경로 (권장, 기본값)" / "Zcash standard path (recommended, default)";
        /// The drop-down item of an EVM account's key (its source says which account).
        EVM_PATH = "EVM 경로 (비표준)" / "EVM path (non-standard)";
        /// The drop-down item of a `YubiKey` Zcash key whose path is not known: {0} its number.
        CARD_KEY(1) = "카드 키 {0} (경로 모름)" / "Card key {0} (path unknown)";
        CONFIRM_EVM = "정말 EVM 키 사용" / "Really use the EVM key";
        CANCEL = "취소" / "Cancel";
        RECEIVE = "받기" / "Receive";
        COPY_ADDRESS = "주소 복사" / "Copy address";
        QR_HIDE = "QR 숨기기" / "Hide QR";
        QR_SHOW = "QR 보기" / "Show QR";
        SEND = "보내기" / "Send";
        RECIPIENT_HELP = "받는 주소: t1…/t3… (testnet tm…/t2…), TEX(tex1…) 또는 일반 수신자가 있는 통합 주소(u1…). 비공개 주소(zs…)는 받지 않습니다."
            / "Recipient: t1…/t3… (testnet tm…/t2…), TEX (tex1…) or a unified address with a transparent receiver (u1…). Shielded addresses (zs…) are not accepted.";
        RECIPIENT = "받는 주소" / "Recipient";
        ADDRESS_ACK = "주소 전체를 직접 확인했습니다" / "I checked the whole address myself";
        CONFIRMED_UNREAD = "확인된 잔액: 아직 읽지 못했습니다" / "Confirmed balance: not read yet";
        CONFIRMED_BALANCE(1) = "확인된 잔액 {0}" / "Confirmed balance {0}";
        AMOUNT = "금액 (ZEC)" / "Amount (ZEC)";
        MAX = "최대" / "Max";
        MAX_NOTE(1) = "최대: 확인된 출력(최대 {0}개)의 합에서 수수료를 뺀 금액을 보냅니다(승인 창에서 확인)."
            / "Max: sends the sum of the confirmed outputs (up to {0}) minus the fee (confirmed in the approval window).";
        FEE_NOTE = "수수료는 ZIP 317 기본값(입력·출력 수에 따라 0.0001 ZEC부터)입니다. 승인 창에서 받는 주소·금액·수수료·만료 높이를 확인하세요."
            / "The fee is the ZIP 317 conventional fee (from 0.0001 ZEC, by the number of inputs·outputs). Check the recipient·amount·fee·expiry height in the approval window.";
        SENT(1) = "보냈습니다. txid {0} — 아래 활동에서 확인 상태를 봅니다."
            / "Sent. txid {0} — see the confirmation status in the activity below.";
        REVIEW = "검토" / "Review";
        COPY_HASH = "해시 복사" / "Copy hash";
        ACTIVITY = "활동" / "Activity";
        NO_ACTIVITY(1) = "이 지갑에서 보낸 Zcash 거래가 없습니다. {0}"
            / "No Zcash transactions sent from this wallet. {0}";
        CONFIRMED_AT(1) = "확인됨 (블록 {0})" / "Confirmed (block {0})";
        ROW(3) = "{0} · 보냄 {1} ZEC · {2}" / "{0} · sent {1} ZEC · {2}";
        EXPIRY_HEIGHT(1) = "만료 높이 {0}" / "Expiry height {0}";
        TO_OWN(1) = "받는 주소 → 내 계정: {0}" / "Recipient → my account: {0}";
        TO_NONE = "받는 주소 -" / "Recipient -";
        FEE(1) = "수수료 {0} ZEC" / "Fee {0} ZEC";
        UTXOS = "받은 출력 (UTXO, 서버 기준)" / "Received outputs (UTXO, per the server)";
        UTXO_ERROR(1) = "출력 목록을 불러오지 못했습니다: {0}" / "Could not load the output list: {0}";
        NO_UTXOS = "이 주소에 사용 가능한 출력이 없습니다." / "No spendable outputs on this address.";
        IGNORED(3) = "아주 작은 출력(먼지, {0} zats 이하)이나 한도({1}개)를 넘는 작은 출력 {2}개는 잔액과 보내기에서 제외했습니다."
            / "{2} tiny outputs (dust, {0} zats or less) or small outputs over the limit ({1}) were left out of the balance and sending.";
        UNCONFIRMED = "미확정 (0 확인)" / "Unconfirmed (0 confirmations)";
        BLOCK(1) = "블록 {0}" / "Block {0}";
    }
}

/// The muted line of our own unconfirmed change in `lang` (2026-11-13; spec/12 §11).
#[must_use]
pub fn own_change_line(lang: Lang, amount: &str) -> String {
    text::OWN_CHANGE.fill(lang, [amount])
}

/// The muted line of unconfirmed outputs no read has classified as a deposit in `lang`
/// (2026-11-13 review; spec/12 §11): the received history is off or has not read them, or found
/// them to be a send by this key from elsewhere or unreadable.
#[must_use]
pub fn unclassified_line(lang: Lang, amount: &str) -> String {
    text::UNCLASSIFIED.fill(lang, [amount])
}

/// Command ids of the Zcash tab (8,000–8,099; the map and its checks are `ui::command_ids`).
pub mod ids {
    /// Tab `Zcash`.
    pub const TAB_ZEC: u16 = 8_000;
    /// Enable on mainnet.
    pub const ENABLE_MAINNET: u16 = 8_001;
    /// Enable on testnet.
    pub const ENABLE_TESTNET: u16 = 8_002;
    /// Turn off.
    pub const DISABLE: u16 = 8_003;
    /// 새로고침.
    pub const REFRESH: u16 = 8_004;
    /// 주소 복사.
    pub const COPY_ADDRESS: u16 = 8_005;
    /// QR 보기 / 숨기기.
    pub const QR_TOGGLE: u16 = 8_006;
    /// Recipient edit.
    pub const SEND_TO_EDIT: u16 = 8_007;
    /// Amount edit.
    pub const SEND_AMOUNT_EDIT: u16 = 8_008;
    /// 최대 (check box).
    pub const SEND_MAX: u16 = 8_009;
    /// 검토.
    pub const SEND_REVIEW: u16 = 8_010;
    /// The drop-down item of the standard path: picking it applies it (2026-11-15; its radio
    /// before, applied by `이 키 출처 사용`).
    pub const SOURCE_STANDARD: u16 = 8_011;
    /// `정말 EVM 키 사용` of the EVM-key confirmation (2026-11-15: shown for that step only;
    /// before, also the radios' `이 키 출처 사용`).
    pub const SOURCE_APPLY: u16 = 8_012;
    /// Key source: cancel the EVM-key confirmation.
    pub const SOURCE_CANCEL: u16 = 8_013;
    /// The drop-down item of the account's source when no other item is it (a path, an EVM
    /// account, a card key or an imported key not listed now): picking it changes nothing.
    pub const SOURCE_CURRENT: u16 = 8_019;
    /// UTXO source: node.
    pub const INDEXER_NODE: u16 = 8_014;
    /// UTXO source: Blockbook.
    pub const INDEXER_BB: u16 = 8_015;
    /// W-ADDR-3 `주소 전체를 직접 확인했습니다`.
    pub const SEND_ADDR_ACK: u16 = 8_016;
    /// `해시 복사` of the 보내기 card's result line (the txid the node accepted).
    pub const RESULT_COPY: u16 = 8_017;
    /// The account card's `주소 복사` (2026-11-11; the 받기 card keeps [`COPY_ADDRESS`]).
    pub const CARD_COPY: u16 = 8_018;
    /// `해시 복사` of the activity rows (newest first, one id per row).
    pub const ACTIVITY_COPY_BASE: u16 = 8_100;
    /// Activity copy span (every record the journal can hold).
    pub const ACTIVITY_COPY_SPAN: u16 = 80;
    /// Drop-down items of the EVM accounts' keys (position in the EVM account list; their radios
    /// before 2026-11-15).
    pub const SOURCE_EVM_BASE: u16 = 8_020;
    /// EVM item span.
    pub const SOURCE_EVM_SPAN: u16 = crate::app_zec::ZEC_SOURCE_EVM_ROWS;
    /// Drop-down items of the `YubiKey` Zcash keys (position in the slot list; buttons before
    /// 2026-11-15).
    pub const HW_BASE: u16 = 8_040;
    /// `YubiKey` item span.
    pub const HW_SPAN: u16 = crate::app_zec::ZEC_HW_ROWS;
    /// `개인키 가져오기` (spec/12 §2.3).
    pub const IMPORT: u16 = 8_050;
    /// `개인키 보기` of the account's imported key.
    pub const REVEAL: u16 = 8_051;
    /// `삭제` of the account's imported key.
    pub const REMOVE: u16 = 8_052;
    /// Drop-down items of the imported keys of the network (position in the list; their
    /// `이 키 사용` before 2026-11-15).
    pub const IMPORTED_BASE: u16 = 8_060;
    /// Imported-key item span (15 keys per chain).
    pub const IMPORTED_SPAN: u16 = 16;

    const _: () = assert!(CARD_COPY < SOURCE_CURRENT);
    const _: () = assert!(SOURCE_CURRENT < SOURCE_EVM_BASE);
    const _: () = assert!(SOURCE_EVM_BASE + SOURCE_EVM_SPAN <= HW_BASE);
    const _: () = assert!(HW_BASE + HW_SPAN <= IMPORT);
    const _: () = assert!(IMPORTED_BASE + IMPORTED_SPAN <= ACTIVITY_COPY_BASE);
    const _: () = assert!(ACTIVITY_COPY_BASE + ACTIVITY_COPY_SPAN <= 8_200);

    /// Every fixed id.
    pub const FIXED: [u16; 23] = [
        CARD_COPY,
        SOURCE_CURRENT,
        TAB_ZEC,
        ENABLE_MAINNET,
        ENABLE_TESTNET,
        DISABLE,
        REFRESH,
        COPY_ADDRESS,
        QR_TOGGLE,
        SEND_TO_EDIT,
        SEND_AMOUNT_EDIT,
        SEND_MAX,
        SEND_REVIEW,
        SOURCE_STANDARD,
        SOURCE_APPLY,
        SOURCE_CANCEL,
        INDEXER_NODE,
        INDEXER_BB,
        SEND_ADDR_ACK,
        RESULT_COPY,
        IMPORT,
        REVEAL,
        REMOVE,
    ];

    /// The press control `id` stands for (2026-11-18, S3 C7: `ui::cmd_table`). `None` when `id`
    /// is not one of this module's presses (the two edits are fields). Each row range is claimed
    /// whole, as the ids reached the handler before.
    #[must_use]
    pub fn press_of(id: u16) -> Option<yw_engine::cmd::ZecPress> {
        use yw_engine::cmd::{Row, ZecPress};
        let within = |base: u16, span: u16| super::offset(id, base, span).map(Row);
        Some(match id {
            TAB_ZEC => ZecPress::TabZec,
            ENABLE_MAINNET => ZecPress::EnableMainnet,
            ENABLE_TESTNET => ZecPress::EnableTestnet,
            DISABLE => ZecPress::Disable,
            REFRESH => ZecPress::Refresh,
            COPY_ADDRESS => ZecPress::CopyAddress,
            CARD_COPY => ZecPress::CardCopy,
            QR_TOGGLE => ZecPress::QrToggle,
            SEND_MAX => ZecPress::SendMax,
            SEND_REVIEW => ZecPress::SendReview,
            SOURCE_STANDARD => ZecPress::SourceStandard,
            SOURCE_APPLY => ZecPress::SourceApply,
            SOURCE_CANCEL => ZecPress::SourceCancel,
            SOURCE_CURRENT => ZecPress::SourceCurrent,
            INDEXER_NODE => ZecPress::IndexerNode,
            INDEXER_BB => ZecPress::IndexerBb,
            SEND_ADDR_ACK => ZecPress::SendAddrAck,
            RESULT_COPY => ZecPress::ResultCopy,
            IMPORT => ZecPress::Import,
            REVEAL => ZecPress::Reveal,
            REMOVE => ZecPress::Remove,
            _ => within(ACTIVITY_COPY_BASE, ACTIVITY_COPY_SPAN)
                .map(ZecPress::ActivityCopy)
                .or_else(|| within(IMPORTED_BASE, IMPORTED_SPAN).map(ZecPress::Imported))
                .or_else(|| within(SOURCE_EVM_BASE, SOURCE_EVM_SPAN).map(ZecPress::SourceEvm))
                .or_else(|| within(HW_BASE, HW_SPAN).map(ZecPress::Hw))?,
        })
    }

    /// The control id of `press` (the inverse of [`press_of`]).
    #[must_use]
    pub const fn id_of(press: yw_engine::cmd::ZecPress) -> u16 {
        use yw_engine::cmd::{Row, ZecPress};
        match press {
            ZecPress::TabZec => TAB_ZEC,
            ZecPress::EnableMainnet => ENABLE_MAINNET,
            ZecPress::EnableTestnet => ENABLE_TESTNET,
            ZecPress::Disable => DISABLE,
            ZecPress::Refresh => REFRESH,
            ZecPress::CopyAddress => COPY_ADDRESS,
            ZecPress::CardCopy => CARD_COPY,
            ZecPress::QrToggle => QR_TOGGLE,
            ZecPress::SendMax => SEND_MAX,
            ZecPress::SendReview => SEND_REVIEW,
            ZecPress::SourceStandard => SOURCE_STANDARD,
            ZecPress::SourceApply => SOURCE_APPLY,
            ZecPress::SourceCancel => SOURCE_CANCEL,
            ZecPress::SourceCurrent => SOURCE_CURRENT,
            ZecPress::IndexerNode => INDEXER_NODE,
            ZecPress::IndexerBb => INDEXER_BB,
            ZecPress::SendAddrAck => SEND_ADDR_ACK,
            ZecPress::ResultCopy => RESULT_COPY,
            ZecPress::Import => IMPORT,
            ZecPress::Reveal => REVEAL,
            ZecPress::Remove => REMOVE,
            ZecPress::ActivityCopy(Row(row)) => ACTIVITY_COPY_BASE.wrapping_add(row),
            ZecPress::Imported(Row(row)) => IMPORTED_BASE.wrapping_add(row),
            ZecPress::SourceEvm(Row(row)) => SOURCE_EVM_BASE.wrapping_add(row),
            ZecPress::Hw(Row(row)) => HW_BASE.wrapping_add(row),
        }
    }
}

fn offset(id: u16, base: u16, span: u16) -> Option<u16> {
    id.checked_sub(base).filter(|offset| *offset < span)
}

/// `YYYY-MM-DD HH:MM` in local time (UTC with a suffix if the conversion fails).
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

fn grouped(address: &str) -> String {
    let mut out = String::with_capacity(address.len() + address.len() / 4);
    for (position, character) in address.chars().enumerate() {
        if position > 0 && position % 4 == 0 {
            out.push(' ');
        }
        out.push(character);
    }
    out
}

impl App {
    /// The label and source of the drop-down item of `source` on the current network (`address`
    /// names an imported key, whose item is its whole address).
    fn zec_item_of(&self, source: ZecKeySource, address: &str) -> (String, AccountSource) {
        let lang = self.settings.language;
        match source {
            ZecKeySource::Derived {
                account: 0,
                index: 0,
            } => (
                text::SOURCE_STANDARD.get(lang).to_owned(),
                AccountSource::Words(None),
            ),
            ZecKeySource::Derived { .. } => (source.label_in(lang), AccountSource::Words(None)),
            ZecKeySource::Mnemonic {
                mnemonic,
                account,
                index,
            } => (
                ZecKeySource::Derived { account, index }.label_in(lang),
                AccountSource::Words(Some(*mnemonic.as_bytes())),
            ),
            ZecKeySource::EvmShared { evm_index } => (
                text::EVM_PATH.get(lang).to_owned(),
                AccountSource::EvmKey(evm_index),
            ),
            ZecKeySource::Hardware { index } => (
                if yw_core::yubikey::plan::is_unknown_index(index) {
                    text::CARD_KEY.fill(
                        lang,
                        [&index
                            .saturating_sub(yw_core::yubikey::plan::UNKNOWN_PATH_FIRST)
                            .saturating_add(1)
                            .to_string()],
                    )
                } else {
                    ZecKeySource::Derived { account: 0, index }.label_in(lang)
                },
                AccountSource::Card(Some(yw_core::yubikey::plan::KeyRole::Zec {
                    network: self.zec_network(),
                    index,
                })),
            ),
            ZecKeySource::Imported => (address.to_owned(), AccountSource::Imported),
        }
    }

    /// The drop-down items of `내 Zcash 계정` (2026-11-15, spec/12 §11): the key sources of the
    /// network, read `label · source` — the wallet's recovery words' standard path
    /// (`Zcash 표준 경로 (권장, 기본값)`), each added set of recovery words' standard path, each
    /// visible EVM account's key (`EVM 경로 (비표준) · EVM 계정 {i} 키`), each `YubiKey` Zcash
    /// key (`Zcash 표준 경로 · YubiKey: {cards}`) and each imported key (its whole address
    /// `· 가져온 키`). The account's source is the selected item; when none of them is it (a
    /// non-standard path, a hidden EVM account, a card key no record holds …) it is one more
    /// item ([`ids::SOURCE_CURRENT`]). A wallet without recovery words lists its cards' and
    /// imported keys only.
    #[must_use]
    pub fn zec_source_items(&self) -> Vec<AccountItem> {
        let unlocked = matches!(self.mode, AppMode::Unlocked { .. });
        let uses = |source, pubkey| self.zec_source_in_use(source, pubkey);
        let mut out = Vec::new();
        let mut push = |id: u16, source: ZecKeySource, address: &str, selected: bool| {
            let (label, source) = self.zec_item_of(source, address);
            out.push(AccountItem {
                id,
                label,
                source,
                selected,
                enabled: unlocked,
            });
        };
        let at =
            |base: u16, position: usize| base.saturating_add(u16::try_from(position).unwrap_or(0));
        if !self.key_only() {
            push(
                ids::SOURCE_STANDARD,
                ZecKeySource::DEFAULT,
                "",
                uses(ZecKeySource::DEFAULT, None),
            );
            for (row, info) in self
                .mn
                .infos
                .iter()
                .enumerate()
                .take(usize::from(crate::ui::screens_mnemonics::ids::ROW_SPAN))
                .filter(|(_, info)| !info.primary)
            {
                let source = ZecKeySource::Mnemonic {
                    mnemonic: info.id,
                    account: 0,
                    index: 0,
                };
                push(
                    at(crate::ui::screens_mnemonics::ids::ZEC_PICK_BASE, row),
                    source,
                    "",
                    uses(source, None),
                );
            }
            for (position, evm_index) in self.zec_evm_indices().into_iter().enumerate() {
                let source = ZecKeySource::EvmShared { evm_index };
                push(
                    at(ids::SOURCE_EVM_BASE, position),
                    source,
                    "",
                    uses(source, None),
                );
            }
        }
        for (position, index) in self.zec_hw_slots().into_iter().enumerate() {
            let source = ZecKeySource::Hardware { index };
            push(at(ids::HW_BASE, position), source, "", uses(source, None));
        }
        for (position, (_, info)) in self.zec_imported_keys().iter().enumerate() {
            push(
                at(ids::IMPORTED_BASE, position),
                ZecKeySource::Imported,
                &info.address,
                uses(ZecKeySource::Imported, Some(info.pubkey)),
            );
        }
        if let Some(account) = self.zec_account()
            && !out.iter().any(|item| item.selected)
        {
            let (label, source) = self.zec_item_of(account.source, &account.address());
            out.push(AccountItem {
                id: ids::SOURCE_CURRENT,
                label,
                source,
                selected: true,
                enabled: unlocked,
            });
        }
        out
    }

    /// The account's source as the line under the balance card's title says it: its drop-down
    /// item (`Zcash 표준 경로 · YubiKey: 백업`), an imported key's `가져온 키` alone (its address
    /// is the card's copy line).
    fn zec_source_name(&self, source: ZecKeySource) -> String {
        if source == ZecKeySource::Imported {
            return self.zec_source_label(source);
        }
        let accounts = self.zec_source_items();
        accounts
            .iter()
            .zip(self.account_item_labels(&accounts))
            .find(|(account, _)| account.selected)
            .map_or_else(|| self.zec_source_label(source), |(_, label)| label)
    }

    /// The account card `내 Zcash 계정` (2026-11-15, the shared card of `ui::screens_accounts`
    /// like the other tabs): the shared help, the drop-down of the key sources
    /// ([`App::zec_source_items`]; picking one applies it, disabled with `SOURCE_BUSY` while a
    /// transaction is unfinished), an imported key's `개인키 보기`·`삭제` with its backup note,
    /// the EVM key's linkage warning and its `정말 EVM 키 사용`·`취소` step, then
    /// `개인키 가져오기` (spec/12 §2.3), the recovery-words link and the import hint. Zcash has
    /// one account per network: no `이름 바꾸기`, no `숨기기`, no `계정 추가` (a deliberate
    /// exception, spec/04 §2.6).
    ///
    /// Before 2026-11-15 a card `키 출처` with the radios `Zcash 표준 경로` / `EVM 계정 {i}과
    /// 같은 키` and `이 키 출처 사용`, a button per `YubiKey` Zcash key, a row of the added
    /// recovery words' paths and `[가져온 키] {address}` rows with `이 키 사용`.
    fn zec_account_card(&self, items: &mut Vec<Item>) {
        use crate::ui::screens_accounts::{AccountCard, SelectedLine};
        let lang = self.settings.language;
        let unlocked = matches!(self.mode, AppMode::Unlocked { .. });
        let free = self.zec_all_terminal();
        let imported = self.zec_selected_imported().is_some();
        let selected = imported.then(|| {
            SelectedLine::Buttons(vec![
                Ctl::button(ids::REVEAL, text::REVEAL_KEY.get(lang))
                    .compact()
                    .enabled(unlocked),
                Ctl::danger(ids::REMOVE, text::DELETE.get(lang))
                    .compact()
                    .enabled(unlocked && self.can_remove_imported()),
            ])
        });
        let mut details = Vec::new();
        if imported {
            details.push(Item::Help(
                if self.key_only() {
                    yw_engine::secret::text::KEY_ONLY_BACKUP
                } else {
                    yw_engine::secret::text::IMPORTED_KEY_BACKUP
                }
                .get(lang)
                .to_owned(),
            ));
        }
        // T-ZEC-EVM-SHARED: while the EVM key waits for its confirmation and while the account
        // is on it.
        let on_evm = self
            .zec_account()
            .is_some_and(|account| matches!(account.source, ZecKeySource::EvmShared { .. }));
        if self.zec.confirm_shared || on_evm {
            details.push(Item::Banner(
                text::EVM_SHARED.get(lang).to_owned(),
                Tone::Warn,
            ));
        }
        if self.zec.confirm_shared {
            details.push(Item::Row(vec![
                Ctl::button(ids::SOURCE_APPLY, text::CONFIRM_EVM.get(lang))
                    .enabled(unlocked && free),
                Ctl::link(ids::SOURCE_CANCEL, text::CANCEL.get(lang)),
            ]));
        }
        let mut actions = vec![
            Ctl::button(ids::IMPORT, text::IMPORT_KEY.get(lang))
                .compact()
                .enabled(self.can_import(yw_core::keyimport::ImportChain::Zec)),
        ];
        if !self.key_only() {
            actions.push(self.mnemonics_link());
        }
        self.push_account_card(
            items,
            AccountCard {
                title: text::MY_ACCOUNTS.get(lang).to_owned(),
                picker: crate::ui::screens_links::ids::PICKER_ZEC,
                accounts: self.zec_source_items(),
                empty: Some(crate::ui::screens_keys::no_accounts_text(
                    lang,
                    yw_core::keyimport::ImportChain::Zec,
                )),
                locked: (!free).then(|| crate::app_zec::text::SOURCE_BUSY.get(lang).to_owned()),
                selected,
                details,
                hidden: None,
                actions,
                footer: vec![Item::Help(text::IMPORT_HELP.get(lang).to_owned())],
            },
        );
    }

    fn zec_disabled_items(&self, items: &mut Vec<Item>) {
        let lang = self.settings.language;
        items.push(Item::CardStart(Some(
            text::DISABLED_TITLE.get(lang).to_owned(),
        )));
        items.push(Item::Text(text::DISABLED_TEXT.get(lang).to_owned()));
        items.push(Item::Help(text::DISABLED_HELP.get(lang).to_owned()));
        let unlocked = matches!(self.mode, AppMode::Unlocked { .. });
        let mut row = vec![
            Ctl::primary(ids::ENABLE_MAINNET, text::ENABLE_MAINNET.get(lang)).enabled(unlocked),
            Ctl::button(ids::ENABLE_TESTNET, text::ENABLE_TESTNET.get(lang)).enabled(unlocked),
        ];
        if ZecNetwork::ALL.into_iter().all(|network| {
            self.apikeys
                .rpc_url(crate::network::NetworkId::Zcash(network))
                .is_none()
        }) {
            row.push(Ctl::link(
                crate::ui::screens::ids::ZEC_RPC_OPEN,
                text::RPC_SETUP.get(lang),
            ));
        }
        items.push(Item::Row(row));
        items.push(Item::CardEnd);
    }
}

impl App {
    /// The S10 Zcash tab body.
    #[expect(clippy::too_many_lines, reason = "the Zcash tab sections in order")]
    pub fn zec_main_screen(&self, items: &mut Vec<Item>) {
        if !self.settings.zcash.enabled {
            self.zec_disabled_items(items);
            return;
        }
        let lang = self.settings.language;
        let network = self.zec_network();
        if self.zec_journal_damaged() {
            items.push(Item::Banner(
                text::JOURNAL_DAMAGED.get(lang).to_owned(),
                Tone::Blocked,
            ));
        }
        let has_endpoint = self
            .apikeys
            .rpc_url(crate::network::NetworkId::Zcash(network))
            .is_some();
        // A missing URL is already the network card's status line with `RPC 설정하기`; the same
        // E-KEY-005 is not repeated as a red band above it (review 2026-11-07 F6). Nor is what
        // the 보내기 card already says next to `검토`.
        if let Some(error) = self.zec.error.as_ref().filter(|error| {
            (has_endpoint || **error != crate::errors::ErrorCode::Key005.text_in(lang))
                && self.zec.send_error.as_ref() != Some(*error)
        }) {
            items.push(Item::Banner(error.clone(), Tone::Danger));
        }
        if let Some(info) = &self.zec.info {
            items.push(Item::Banner(info.clone(), Tone::Info));
        }
        let snapshot = self
            .zec
            .snapshot
            .as_ref()
            .filter(|(net, _)| *net == network)
            .map(|(_, snapshot)| snapshot);
        // Network and endpoint.
        items.push(Item::CardStart(None));
        items.push(Item::LabeledRow(
            text::NETWORK.get(lang).to_owned(),
            vec![
                Ctl::tab(
                    ids::ENABLE_MAINNET,
                    "Zcash mainnet",
                    network == ZecNetwork::Mainnet,
                )
                .badge(Badge::zcash(ZecNetwork::Mainnet))
                .enabled(!self.zec.busy),
                Ctl::tab(
                    ids::ENABLE_TESTNET,
                    text::TESTNET_CHIP.get(lang),
                    network == ZecNetwork::Testnet,
                )
                .badge(Badge::zcash(ZecNetwork::Testnet))
                .enabled(!self.zec.busy),
            ],
        ));
        // The network tag after the chips, as on the other tabs (2026-11-11: a small tag, no
        // longer a full-width band).
        items.push(Item::Pill(
            network.banner_in(lang).to_owned(),
            match network {
                ZecNetwork::Mainnet => Tone::BtcMainnet,
                ZecNetwork::Testnet => Tone::Testnet,
            },
        ));
        let rpc = match (has_endpoint, snapshot) {
            (false, _) => text::RPC_NONE.get(lang).to_owned(),
            (true, Some(snapshot)) => {
                let upgrade = yw_core::zec::upgrade::known(snapshot.chain.consensus.next_branch)
                    .map_or(text::UPGRADE_UNKNOWN.get(lang), |upgrade| upgrade.name);
                text::RPC_CONNECTED.fill(lang, [&snapshot.chain.tip.to_string(), upgrade])
            }
            (true, None) if self.zec.refreshing => text::RPC_CHECKING.get(lang).to_owned(),
            (true, None) => text::RPC_UNCHECKED.get(lang).to_owned(),
        };
        items.push(Item::Help(format!(
            "RPC ({}): {rpc}",
            network.endpoint_id()
        )));
        let indexer = self.settings.zcash.indexer;
        items.push(Item::LabeledRow(
            text::UTXO_SOURCE.get(lang).to_owned(),
            vec![
                Ctl::tab(
                    ids::INDEXER_NODE,
                    text::INDEXER_NODE.get(lang),
                    indexer == ZecIndexer::Node,
                ),
                Ctl::tab(
                    ids::INDEXER_BB,
                    "Blockbook (/api/v2)",
                    indexer == ZecIndexer::BbRest,
                ),
            ],
        ));
        // `새로고침` (or `RPC 설정하기`) is the account card's, as on the other tabs (2026-11-11).
        items.push(Item::Row(vec![
            Ctl::link(ids::DISABLE, text::DISABLE.get(lang)).enabled(!self.zec.busy),
        ]));
        items.push(Item::CardEnd);

        // Account and balance: the other tabs' layout (2026-11-11) — name, key source and
        // path, balance, status, the address with `주소 복사`, `새로고침`. The account card under
        // it (2026-11-15) picks the key source, as Bitcoin's picks the account.
        let account = self.zec_account();
        let hw_state = self.zec_hw_state();
        let address_ok = matches!(
            hw_state,
            crate::app_zec::ZecHwState::NotHardware | crate::app_zec::ZecHwState::Present
        );
        items.push(Item::CardStart(None));
        items.push(Item::Badged(
            Badge::zcash(network),
            Box::new(Item::Subtitle(
                text::ACCOUNT_TITLE.fill(lang, [network.display_name()]),
            )),
        ));
        // The confirmed balance, shown again next to the send amount (2026-11-12).
        let mut spendable = None;
        match account {
            None => items.push(Item::Text(text::ACCOUNT_LOADING.get(lang).to_owned())),
            Some(account) => {
                // The source as the drop-down names it (2026-11-15: `YubiKey: {cards}` for a
                // card key; the core name `YubiKey (주소 0)` before), then the path.
                items.push(Item::Help(text::KEY_SOURCE_LINE.fill(
                    lang,
                    [
                        &self.zec_source_name(account.source),
                        &account.source.path_text_in(lang, network),
                    ],
                )));
                // 2026-11-13: the unconfirmed outputs are split into deposits ("미확정 입금"),
                // our own change ("확인 대기") and, review of the same day, outputs nothing has
                // classified ("미확정 출력"); before, one "· 미확인 …" suffix mixed them. None
                // is ever part of the confirmed balance or spendable.
                let (confirmed, others, own_change) =
                    snapshot.map_or((None, Vec::new(), 0), |snapshot| {
                        let records = self.zec_records();
                        let reserved: Vec<_> = records
                            .iter()
                            .filter(|record| record.reserves_inputs())
                            .flat_map(yw_core::journal::zec::ZecRecord::inputs)
                            .collect();
                        let own_txids: Vec<String> = records
                            .iter()
                            .map(|record| record.txid_hex().to_ascii_lowercase())
                            .collect();
                        let confirmed = snapshot
                            .utxos
                            .iter()
                            .filter(|utxo| {
                                utxo.height.is_some() && !reserved.contains(&utxo.outpoint)
                            })
                            .map(|utxo| utxo.value)
                            .fold(0_u64, u64::saturating_add);
                        let (others, own) =
                            crate::app_received::zec_unconfirmed(snapshot, &own_txids);
                        (Some(confirmed), others, own)
                    });
                // Only the received history's list (its read classified the inputs) says
                // "미확정 입금"; the snapshot's other unconfirmed outputs the list does not know
                // get the neutral line, dust left out (it is hidden in the list too). Before
                // the 2026-11-13 review the snapshot sum was "미확정 입금" whenever the list had
                // no pending row, dust and our change from a send made elsewhere included.
                let list = self
                    .received_list(crate::received::RecvChain::Zec)
                    .filter(|list| list.loaded && list.unsupported.is_none());
                let incoming = list
                    .and_then(crate::app_received::RecvList::pending_sum)
                    .unwrap_or(0);
                let unclassified = others
                    .iter()
                    .filter(|(txid, zats)| {
                        *zats >= crate::received::DUST_ZEC_ZATS
                            && !list.is_some_and(|list| list.knows(txid))
                    })
                    .map(|(_, zats)| *zats)
                    .fold(0_u64, u64::saturating_add);
                spendable = confirmed;
                // The other tabs' words when there is no balance yet (2026-11-11).
                items.push(Item::Display(confirmed.map_or_else(
                    || text::BALANCE_DASH.get(lang).to_owned(),
                    |zats| format!("{} ZEC", format_zec(zats)),
                )));
                items.push(Item::Help(match confirmed {
                    Some(zats) => {
                        text::CONFIRMED_BALANCE_NOTE.fill(lang, [&format_zec_and_zats(zats)])
                    }
                    None if !has_endpoint => crate::ui::screens::no_endpoint_text(
                        lang,
                        &self.network_name(crate::network::NetworkId::Zcash(network)),
                    ),
                    None if self.zec.error.is_some() && !self.zec.refreshing => {
                        crate::ui::screens::T_BALANCE_FAILED.get(lang).to_owned()
                    }
                    None => crate::ui::screens::T_BALANCE_LOADING.get(lang).to_owned(),
                }));
                if incoming > 0 {
                    items.push(Item::Muted(crate::ui::screens_btc::pending_incoming_line(
                        lang,
                        &format_zec_and_zats(incoming),
                    )));
                }
                if unclassified > 0 {
                    items.push(Item::Muted(unclassified_line(
                        lang,
                        &format_zec_and_zats(unclassified),
                    )));
                }
                if own_change > 0 {
                    items.push(Item::Muted(own_change_line(
                        lang,
                        &format_zec_and_zats(own_change),
                    )));
                }
                // Not while a hardware account's key is missing or unchecked (like 받기).
                if address_ok {
                    let address = account.address();
                    items.push(crate::ui::screens::own_address_row(
                        self.settings.language,
                        &address,
                        crate::ui::theme::AddressKind::Zcash,
                        ids::CARD_COPY,
                        !self.passphrase_unverified(),
                        self.explorer_address_icon(
                            crate::network::NetworkId::Zcash(network),
                            &address,
                            crate::ui::screens_explorer::ids::CARD_ZEC,
                        ),
                    ));
                }
            }
        }
        items.push(Item::Row(vec![if has_endpoint {
            Ctl::link(ids::REFRESH, text::REFRESH.get(lang))
                .tip(crate::ui::screens::T_REFRESH_TIP.get(lang))
                .enabled(!self.zec.refreshing)
        } else {
            // Nothing to refresh without an address: this network's row (EVM·Solana alike).
            Ctl::button(
                crate::ui::screens::ids::ZEC_RPC_OPEN,
                text::RPC_SETUP.get(lang),
            )
        }]));
        items.push(Item::CardEnd);
        // The account card `내 Zcash 계정` (2026-11-15: a card `키 출처` before).
        self.zec_account_card(items);
        let unlocked = matches!(self.mode, AppMode::Unlocked { .. });

        // Receive (hidden while a hardware account's key is missing or not yet checked).
        if hw_state == crate::app_zec::ZecHwState::Missing {
            items.push(Item::Banner(
                crate::app_zec::text::HW_MISSING.get(lang).to_owned(),
                Tone::Danger,
            ));
        }
        if let Some(account) = account.filter(|_| address_ok) {
            let address = account.address();
            items.push(Item::CardStart(Some(text::RECEIVE.get(lang).to_owned())));
            items.push(Item::Mono(grouped(&address)));
            items.push(Item::Banner(
                text::RECEIVE_NOTE.get(lang).to_owned(),
                Tone::Info,
            ));
            self.mn_receive_banner(
                self.mn_backup_gate(
                    account.source.mnemonic(),
                    matches!(
                        account.source,
                        ZecKeySource::Derived { .. } | ZecKeySource::EvmShared { .. }
                    ),
                ),
                items,
            );
            let receive_ok = !self.passphrase_unverified();
            items.push(Item::Row(vec![
                Ctl::button(ids::COPY_ADDRESS, text::COPY_ADDRESS.get(lang)).enabled(receive_ok),
                Ctl::button(
                    ids::QR_TOGGLE,
                    if self.zec.show_qr {
                        text::QR_HIDE
                    } else {
                        text::QR_SHOW
                    }
                    .get(lang),
                )
                .enabled(receive_ok),
            ]));
            if self.zec.show_qr && receive_ok {
                items.push(Item::Qr(format!("zcash:{address}")));
            }
            items.push(Item::CardEnd);
        }

        // Send.
        items.push(Item::CardStart(Some(text::SEND.get(lang).to_owned())));
        // U7: an account whose phrase has not passed its backup quiz cannot sign; said before
        // the form, with `검토` off, instead of after the approval (E-VLT-009).
        let backup_gate = self.zec_backup_gate();
        self.mn_signing_banner(backup_gate, items);
        self.card_pin_banner(self.zec_card_gate(), items);
        items.push(Item::Help(text::RECIPIENT_HELP.get(lang).to_owned()));
        items.push(Item::LabeledRow(
            text::RECIPIENT.get(lang).to_owned(),
            vec![Ctl::edit(
                ids::SEND_TO_EDIT,
                &self.zec.to_text,
                460,
                false,
                1_000,
            )],
        ));
        if let Some(note) = &self.zec.look_alike {
            items.push(Item::Banner(note.clone(), Tone::HighRisk));
            items.push(Item::Row(vec![Ctl::check(
                ids::SEND_ADDR_ACK,
                text::ADDRESS_ACK.get(lang),
                self.zec.ack,
            )]));
        }
        items.push(Item::Help(spendable.map_or_else(
            || text::CONFIRMED_UNREAD.get(lang).to_owned(),
            |zats| text::CONFIRMED_BALANCE.fill(lang, [&format_zec_and_zats(zats)]),
        )));
        items.push(Item::LabeledRow(
            text::AMOUNT.get(lang).to_owned(),
            vec![
                Ctl::edit(ids::SEND_AMOUNT_EDIT, &self.zec.amount_text, 200, false, 24)
                    .enabled(!self.zec.send_max),
                // Like every chain's `최대` (2026-11-12): pressed while on.
                Ctl::tab(ids::SEND_MAX, text::MAX.get(lang), self.zec.send_max),
            ],
        ));
        if self.zec.send_max {
            items.push(Item::Help(
                text::MAX_NOTE.fill(lang, [&yw_core::zec::ZEC_MAX_INPUTS.to_string()]),
            ));
        }
        items.push(Item::Help(text::FEE_NOTE.get(lang).to_owned()));
        let can_send = unlocked
            && account.is_some()
            && !self.zec.busy
            && !self.zec.refreshing
            && !self.zec_journal_damaged()
            && !self.mn_send_blocked(backup_gate)
            // spec/10 §9.3: the YubiKey is still on its factory PINs (the band says so).
            && self.zec_card_gate().is_none()
            && self
                .journal_hold(crate::app_sidecar::SendChain::Zec)
                .is_none()
            && (self.zec.look_alike.is_none() || self.zec.ack);
        // What `검토`, the approval, signing and sending ended with, next to the button (the
        // tab's own band is several cards above it).
        if let Some(error) = &self.zec.send_error {
            items.push(Item::Banner(error.clone(), Tone::Danger));
        }
        if let Some(info) = &self.zec.send_info {
            items.push(Item::Banner(info.clone(), Tone::Info));
        }
        if let Some(txid) = &self.zec.sent {
            items.push(Item::Banner(
                text::SENT.fill(lang, [&yw_core::zec::tx::txid_display(txid)]),
                Tone::Success,
            ));
        }
        self.journal_send_items(crate::app_sidecar::SendChain::Zec, items);
        let mut row =
            vec![Ctl::primary(ids::SEND_REVIEW, text::REVIEW.get(lang)).enabled(can_send)];
        if let Some(txid) = &self.zec.sent {
            row.push(Ctl::button(ids::RESULT_COPY, text::COPY_HASH.get(lang)));
            // 2026-11-11: the accepted txid on the network's explorer.
            row.extend(self.explorer_tx_buttons(
                crate::network::NetworkId::Zcash(network),
                &yw_core::zec::tx::txid_display(txid),
                Some((
                    crate::ui::screens_explorer::ids::RESULT_ZEC_OPEN,
                    crate::ui::screens_explorer::ids::RESULT_ZEC_COPY,
                )),
            ));
        }
        items.push(Item::Row(row));
        items.push(Item::CardEnd);

        // Activity.
        items.push(Item::CardStart(Some(text::ACTIVITY.get(lang).to_owned())));
        let records = self.zec_records();
        if records.is_empty() {
            items.push(Item::Help(
                text::NO_ACTIVITY.fill(lang, [crate::ui::screens::T_ACTIVITY_RECEIVED.get(lang)]),
            ));
        }
        // The rows of the other chains' order (2026-11-10): time and amount, status (the expiry
        // height only while it may still confirm), the recipient with its display-only name on
        // its own `Mono` line, the fee in ZEC, then the txid.
        let own = self
            .zec_account()
            .map(|account| (account.address(), self.zec_source_label(account.source)));
        for (row, record) in records.iter().rev().enumerate() {
            let state = match record.state {
                ZecTxState::Confirmed => {
                    text::CONFIRMED_AT.fill(lang, [&record.mined_height.to_string()])
                }
                other => other.label_in(lang).to_owned(),
            };
            // The status at the end of the first line (2026-11-12: a line of its own before).
            items.push(Item::Text(text::ROW.fill(
                lang,
                [
                    &local_time(record.signed_at_ms),
                    &format_zec(record.amount),
                    &state,
                ],
            )));
            if !record.state.is_terminal() {
                items.push(Item::Help(
                    text::EXPIRY_HEIGHT.fill(lang, [&record.expiry_height().to_string()]),
                ));
            }
            match record.recipient().map(|dest| dest.encode(network)) {
                Some(to) => {
                    let line = own
                        .as_ref()
                        .filter(|(address, _)| *address == to)
                        .map_or_else(
                            || text::RECIPIENT.get(lang).to_owned(),
                            |(_, label)| text::TO_OWN.fill(lang, [label]),
                        );
                    items.push(Item::Help(line));
                    // 2026-11-11: whole, ends emphasized; a click copies it (the wallet's own
                    // signed journal — the received history's senders never are).
                    crate::ui::screens_links::push_address_line(
                        items,
                        self.settings.language,
                        crate::ui::screens_links::ids::row_id(
                            crate::ui::screens_links::ids::ZEC_TO_BASE,
                            crate::ui::screens_links::ids::ZEC_TO_SPAN,
                            row,
                        ),
                        &to,
                        crate::ui::theme::AddressKind::Zcash,
                        Vec::new(),
                    );
                }
                None => items.push(Item::Help(text::TO_NONE.get(lang).to_owned())),
            }
            items.push(Item::Help(text::FEE.fill(lang, [&format_zec(record.fee)])));
            let txid = record.txid_hex();
            // A click copies the txid; `탐색기에서 열기` ↗ · `탐색기 링크 복사` 🔗 at the right
            // end (ids of `ui::screens_explorer`).
            crate::ui::screens_links::push_hash_line(
                items,
                self.settings.language,
                crate::ui::screens_links::ids::row_id(
                    ids::ACTIVITY_COPY_BASE,
                    ids::ACTIVITY_COPY_SPAN,
                    row,
                ),
                &txid,
                self.explorer_tx_icons(
                    crate::network::NetworkId::Zcash(network),
                    &txid,
                    crate::ui::screens_explorer::ids::activity_ids(
                        crate::ui::screens_explorer::ids::ZEC_ACTIVITY_BASE,
                        crate::ui::screens_explorer::ids::ZEC_ACTIVITY_SPAN,
                        row,
                    ),
                ),
            );
        }
        if let Some(snapshot) = snapshot {
            items.push(Item::Subtitle(text::UTXOS.get(lang).to_owned()));
            if snapshot.utxo_error == Some(ZecRpcError::TooMany) {
                items.push(Item::Help(ZecRpcError::TooMany.text_in(lang)));
            } else if let Some(error) = snapshot.utxo_error {
                items.push(Item::Help(
                    text::UTXO_ERROR.fill(lang, [&error.text_in(lang)]),
                ));
            } else if snapshot.utxos.is_empty() {
                items.push(Item::Help(text::NO_UTXOS.get(lang).to_owned()));
            }
            if snapshot.ignored_utxos > 0 {
                items.push(Item::Help(text::IGNORED.fill(
                    lang,
                    [
                        &yw_core::zec::ZEC_MIN_UTXO.to_string(),
                        &yw_core::zec::ZEC_MAX_UTXOS.to_string(),
                        &snapshot.ignored_utxos.to_string(),
                    ],
                )));
            }
            for utxo in snapshot.utxos.iter().take(50) {
                let height = utxo.height.map_or_else(
                    || text::UNCONFIRMED.get(lang).to_owned(),
                    |height| text::BLOCK.fill(lang, [&height.to_string()]),
                );
                items.push(Item::Field(
                    format!("{} ZEC", format_zec(utxo.value)),
                    format!(
                        "{height} · {}:{}",
                        yw_core::zec::tx::txid_display(&utxo.outpoint.txid),
                        utxo.outpoint.index
                    ),
                ));
            }
        }
        self.received_items(crate::received::RecvChain::Zec, items);
        items.push(Item::CardEnd);
    }
}
