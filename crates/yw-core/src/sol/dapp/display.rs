//! The approval request of dApp Solana transactions (spec/07 §20.6): the payload, the display
//! fields `0x0510`–`0x051A` and `0x0540`, and the `X01`–`X19` warnings. The builder parses every
//! transaction itself (never a structure from the app), resolves its lookups from the RPC tables,
//! decodes every instruction and checks the site's signatures; RPC facts (tables, pre-state,
//! simulation, mints, fee) are shown as references and bound only through the display digest.
//! Every address is drawn whole on its own line (`grouped`), its notes on the line after it.
#![deny(clippy::indexing_slicing)]

use sha2::{Digest, Sha256};

use super::alt::{self, AltError, KeyRole, LookupTable, ResolvedKeys, full_keys};
use super::decode::{AtaIx, AuthorityType, CbIx, DecodedIx, SystemIx, TokenIx, decode_message};
use super::diff::{AccountSnapshot, AuthorityKind, Change, changes, mint_decimals};
use super::parse::{SolTxVersion, SolWireTx, encode_message_any, parse_wire_tx};
use super::{SolSendOptions, SolTxItem, SolTxMode, SolTxPayload};
use crate::approval::message::{hex_lines, inline_value};
use crate::approval::{
    AccountRef, ApprovalDisplay, ApprovalDraft, ApprovalId, ApprovalKind, ApprovalOrigin, ChainRef,
    DisplayError, DisplayField, FieldKey, MAX_TITLE_BYTES, RuleId, Signer, SigningPayload,
    SimulationBinding, Warning,
};
use crate::evm::risk::{
    self, X01, X02, X03, X04, X05, X06, X07, X08, X09, X10, X11, X12, X13, X14, X15, X16, X17, X18,
    X19,
};
use crate::policy::BrowserOrigin;
use crate::slip10::SolKeySource;
use crate::sol::address::{
    BPF_LOADER_UPGRADEABLE, SolAddress, SolCluster, grouped, is_reserved_key, program_name,
};
use crate::sol::broadcast::err;
use crate::sol::display::SimSummary;
use crate::sol::fee::dapp_fee_estimate;
use crate::sol::recipient::{KnownAddress, KnownKind, is_lookalike};
use crate::sol::rent::{format_amount, format_raw};
use crate::sol::template::spl_entry;
use crate::sol::token::MintView;

/// More account keys than this may fail at runtime (X18).
const RUNTIME_ACCOUNT_LIMIT: usize = 128;
/// Mint TLV extension types the rules read (spec/07 §20.6).
const EXT_TRANSFER_FEE_CONFIG: u16 = 1;
const EXT_PERMANENT_DELEGATE: u16 = 12;
const EXT_TRANSFER_HOOK: u16 = 14;

/// What the RPC said about one transaction (references, spec/07 §20.7).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SolTxItemFacts {
    /// The lookup tables at `slot` (`getMultipleAccounts`), or why they could not be read. A
    /// message without lookups ignores it.
    pub tables: Result<(u64, Vec<(SolAddress, LookupTable)>), AltError>,
    /// Pre-state of the writable accounts (`dataSlice 0/166`; `None`: the account is missing).
    pub pre: Vec<(SolAddress, Option<AccountSnapshot>)>,
    /// Simulated post-state of the watched accounts (`None`: no simulation result).
    pub post: Option<Vec<(SolAddress, Option<AccountSnapshot>)>>,
    /// The simulation verdict.
    pub sim: SimSummary,
    /// The simulation replaced the blockhash (X19).
    pub sim_replaced_blockhash: bool,
    /// `getFeeForMessage` (`None`: the local estimate is shown).
    pub rpc_fee: Option<u64>,
    /// `isBlockhashValid(processed)` (`None`: not asked, e.g. a durable nonce).
    pub blockhash_valid: Option<bool>,
}

/// What the app gathered for the whole request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SolTxFacts {
    /// One entry per transaction, in request order.
    pub items: Vec<SolTxItemFacts>,
    /// Mints read for the request (Token-2022 extensions, decimals).
    pub mints: Vec<(SolAddress, MintView)>,
    /// Address book, own accounts and sent history (exact notes and X16).
    pub known: Vec<KnownAddress>,
    /// The user's fee cap in lamports (X14 when the wallet pays more).
    pub fee_cap: u64,
}

/// The request as the dApp sent it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SolTxRequest {
    /// Approval id.
    pub id: ApprovalId,
    /// Requesting site.
    pub origin: BrowserOrigin,
    /// The wallet's cluster (the pinned genesis is bound).
    pub cluster: SolCluster,
    /// Key source.
    pub source: SolKeySource,
    /// Public key.
    pub public: [u8; 32],
    /// The account label (user text, escaped here).
    pub label: String,
    /// Sign only or sign and send.
    pub mode: SolTxMode,
    /// Send options (default for sign-only).
    pub options: SolSendOptions,
    /// The wire transactions.
    pub txs: Vec<Vec<u8>>,
}

/// One warning per rule with every cause merged (spec/07 §20.6).
#[derive(Default)]
struct Causes(Vec<(RuleId, Vec<String>)>);

impl Causes {
    fn add(&mut self, rule: RuleId, cause: Option<String>) {
        if !self.0.iter().any(|(known, _)| *known == rule) {
            self.0.push((rule, Vec::new()));
        }
        if let Some(cause) = cause
            && let Some((_, list)) = self.0.iter_mut().find(|(known, _)| *known == rule)
            && !list.contains(&cause)
        {
            list.push(cause);
        }
    }

    fn into_warnings(self) -> Vec<Warning> {
        self.0
            .into_iter()
            .map(|(rule, causes)| {
                let joined = causes.join("\n");
                risk::warning(rule, (!joined.is_empty()).then_some(joined.as_str()))
            })
            .collect()
    }
}

/// `거래 k: ` / `거래 k 명령 i: ` (only the instruction part for a single transaction).
fn at(index: usize, count: usize, instruction: Option<usize>) -> String {
    match (count > 1, instruction) {
        (true, Some(ix)) => format!(
            "거래 {} 명령 {}: ",
            index.saturating_add(1),
            ix.saturating_add(1)
        ),
        (true, None) => format!("거래 {}: ", index.saturating_add(1)),
        (false, Some(ix)) => format!("명령 {}: ", ix.saturating_add(1)),
        (false, None) => String::new(),
    }
}

/// `+1.000000000 SOL` / `-…` of a change.
fn delta(pre: u64, post: u64, decimals: u8) -> String {
    if post >= pre {
        format!("+{}", format_amount(post.saturating_sub(pre), decimals))
    } else {
        format!("-{}", format_amount(pre.saturating_sub(post), decimals))
    }
}

/// What one transaction's builder knows besides the bytes.
struct Tx<'a> {
    wallet: SolAddress,
    cluster: SolCluster,
    known: &'a [KnownAddress],
    keys: Vec<(SolAddress, KeyRole)>,
    programs: Vec<SolAddress>,
    tables: Vec<SolAddress>,
    /// Pre-state token accounts the wallet owns, with their mint.
    own_tokens: Vec<(SolAddress, SolAddress)>,
    pre: &'a [(SolAddress, Option<AccountSnapshot>)],
    mints: &'a [(SolAddress, MintView)],
}

impl Tx<'_> {
    fn exact(&self, address: &SolAddress) -> Option<&KnownAddress> {
        self.known.iter().find(|known| known.address == *address)
    }

    fn lookalike(&self, address: &SolAddress) -> Option<&KnownAddress> {
        if *address == self.wallet || self.exact(address).is_some() {
            return None;
        }
        self.known
            .iter()
            .find(|known| is_lookalike(address, &known.address))
    }

    fn own_token_mint(&self, address: &SolAddress) -> Option<&SolAddress> {
        self.own_tokens
            .iter()
            .find(|(account, _)| account == address)
            .map(|(_, mint)| mint)
    }

    fn is_ours(&self, address: &SolAddress) -> bool {
        *address == self.wallet || self.own_token_mint(address).is_some()
    }

    /// The mint of a pre-state token account.
    fn mint_of(&self, account: &SolAddress) -> Option<SolAddress> {
        self.pre
            .iter()
            .find(|(address, _)| address == account)
            .and_then(|(_, snapshot)| snapshot.as_ref())
            .and_then(AccountSnapshot::token)
            .map(|view| view.mint)
    }

    /// Whether the runtime loads a writable key read-only (Agave `is_writable`, spec/07 §20.6):
    /// an exact reserved key, or a key called as a program while the BPF Upgradeable Loader is
    /// not among the keys.
    fn demoted(&self, address: &SolAddress) -> bool {
        is_reserved_key(address)
            || (self.programs.contains(address)
                && !self
                    .keys
                    .iter()
                    .any(|(key, _)| *key == BPF_LOADER_UPGRADEABLE))
    }

    fn symbol(&self, mint: &SolAddress) -> Option<&'static str> {
        spl_entry(self.cluster, mint).map(|entry| entry.symbol)
    }

    /// The notes of an address: role in the message, the wallet, our token account, known
    /// names, lookalike.
    fn tags(&self, address: &SolAddress) -> String {
        let mut tags: Vec<String> = Vec::new();
        if let Some((_, role)) = self.keys.iter().find(|(key, _)| key == address) {
            if role.signer {
                tags.push("[서명]".to_owned());
            }
            if role.writable {
                tags.push("[쓰기]".to_owned());
            }
            if let Some(table) = role.table
                && let Some(index) = self.tables.iter().position(|known| *known == table)
            {
                tags.push(format!("[테이블 {}]", index.saturating_add(1)));
            }
        }
        if let Some(name) = program_name(address) {
            tags.push(format!("[{name} 프로그램]"));
        }
        if *address == self.wallet {
            tags.push("[내 지갑]".to_owned());
        }
        if let Some(mint) = self.own_token_mint(address) {
            tags.push(match self.symbol(mint) {
                Some(symbol) => format!("[내 토큰 계정 · {symbol}]"),
                None => "[내 토큰 계정]".to_owned(),
            });
        }
        if let Some(known) = self.exact(address) {
            let name = inline_value(&known.label);
            match known.kind {
                KnownKind::Book { verified: true } => tags.push(format!("[주소록: {name} ✓]")),
                KnownKind::Book { verified: false } => tags.push(format!("[주소록: {name}]")),
                KnownKind::Own { .. }
                | KnownKind::OwnImported
                | KnownKind::OwnHardware
                | KnownKind::OwnMnemonic => tags.push(format!("[내 계정: {name}]")),
                KnownKind::Sent => tags.push("[보낸 적 있는 주소]".to_owned()),
                KnownKind::History => {}
            }
        }
        if self.lookalike(address).is_some() {
            tags.push("[비슷한 주소 주의]".to_owned());
        }
        tags.join(" ")
    }

    /// `label` (when not empty), the grouped address, then its notes.
    fn address(&self, out: &mut Vec<String>, label: &str, address: &SolAddress) {
        if !label.is_empty() {
            out.push(label.to_owned());
        }
        out.push(grouped(address));
        let tags = self.tags(address);
        if !tags.is_empty() {
            out.push(tags);
        }
    }

    /// A token amount: allowlist symbol and decimals, the instruction's decimals, the RPC mint's
    /// decimals ("RPC 참고"), or raw units.
    fn amount(&self, mint: Option<&SolAddress>, raw: u64, decimals: Option<u8>) -> String {
        if let Some(entry) = mint.and_then(|mint| spl_entry(self.cluster, mint)) {
            return format!(
                "{} {} ({} 원시 단위)",
                format_amount(raw, entry.decimals),
                entry.symbol,
                format_raw(raw)
            );
        }
        if let Some(decimals) = decimals {
            return format!(
                "{} 토큰 ({} 원시 단위, decimals {decimals})",
                format_amount(raw, decimals),
                format_raw(raw)
            );
        }
        match mint.and_then(|mint| mint_decimals(self.cluster, mint, self.mints)) {
            Some((decimals, _)) => format!(
                "{} 토큰 ({} 원시 단위, decimals {decimals} RPC 참고)",
                format_amount(raw, decimals),
                format_raw(raw)
            ),
            None => format!("{} (원시 단위)", format_raw(raw)),
        }
    }
}

fn lamports_line(lamports: u64) -> String {
    format!(
        "{} SOL ({} lamports)",
        format_amount(lamports, 9),
        format_raw(lamports)
    )
}

fn seed_line(seed: &str) -> String {
    format!("seed: {}", inline_value(seed))
}

fn option_line(out: &mut Vec<String>, tx: &Tx<'_>, label: &str, address: Option<&SolAddress>) {
    match address {
        Some(address) => tx.address(out, label, address),
        None => out.push(format!("{label} 없음")),
    }
}

/// The title and lines of a System instruction.
#[expect(
    clippy::too_many_lines,
    reason = "one arm per System tag, in tag order like the spec/07 §20.4 list"
)]
fn system_lines(tx: &Tx<'_>, ix: &SystemIx, out: &mut Vec<String>) -> &'static str {
    match ix {
        SystemIx::CreateAccount {
            from,
            to,
            lamports,
            space,
            owner,
        } => {
            tx.address(out, "자금 계정", from);
            tx.address(out, "새 계정", to);
            out.push(lamports_line(*lamports));
            out.push(format!("크기 {}바이트", format_raw(*space)));
            tx.address(out, "소유 프로그램", owner);
            "계정 만들기 (CreateAccount)"
        }
        SystemIx::Assign { account, owner } => {
            tx.address(out, "계정", account);
            tx.address(out, "새 소유 프로그램", owner);
            "소유 프로그램 바꾸기 (Assign)"
        }
        SystemIx::Transfer { from, to, lamports } => {
            tx.address(out, "보내는 계정", from);
            tx.address(out, "받는 계정", to);
            out.push(lamports_line(*lamports));
            "SOL 보내기 (Transfer)"
        }
        SystemIx::CreateAccountWithSeed {
            from,
            to,
            base,
            seed,
            lamports,
            space,
            owner,
        } => {
            tx.address(out, "자금 계정", from);
            tx.address(out, "새 계정", to);
            tx.address(out, "기준 계정", base);
            out.push(seed_line(seed));
            out.push(lamports_line(*lamports));
            out.push(format!("크기 {}바이트", format_raw(*space)));
            tx.address(out, "소유 프로그램", owner);
            "seed로 계정 만들기 (CreateAccountWithSeed)"
        }
        SystemIx::AdvanceNonce {
            nonce,
            authority,
            extra,
        } => {
            tx.address(out, "nonce 계정", nonce);
            tx.address(out, "nonce 권한", authority);
            if !extra.is_empty() {
                out.push(format!(
                    "뒤에 붙은 바이트(런타임이 무시): {}",
                    crate::hex::encode(extra)
                ));
            }
            "durable nonce 진행 (AdvanceNonceAccount)"
        }
        SystemIx::WithdrawNonce {
            nonce,
            to,
            authority,
            lamports,
        } => {
            tx.address(out, "nonce 계정", nonce);
            tx.address(out, "받는 계정", to);
            tx.address(out, "nonce 권한", authority);
            out.push(lamports_line(*lamports));
            "nonce 계정에서 꺼내기 (WithdrawNonceAccount)"
        }
        SystemIx::InitializeNonce { nonce, authority } => {
            tx.address(out, "nonce 계정", nonce);
            tx.address(out, "nonce 권한", authority);
            "nonce 계정 초기화 (InitializeNonceAccount)"
        }
        SystemIx::AuthorizeNonce {
            nonce,
            authority,
            new_authority,
        } => {
            tx.address(out, "nonce 계정", nonce);
            tx.address(out, "현재 권한", authority);
            tx.address(out, "새 권한", new_authority);
            "nonce 권한 바꾸기 (AuthorizeNonceAccount)"
        }
        SystemIx::Allocate { account, space } => {
            tx.address(out, "계정", account);
            out.push(format!("크기 {}바이트", format_raw(*space)));
            "공간 할당 (Allocate)"
        }
        SystemIx::AllocateWithSeed {
            account,
            base,
            seed,
            space,
            owner,
        } => {
            tx.address(out, "계정", account);
            tx.address(out, "기준 계정", base);
            out.push(seed_line(seed));
            out.push(format!("크기 {}바이트", format_raw(*space)));
            tx.address(out, "소유 프로그램", owner);
            "seed 계정 공간 할당 (AllocateWithSeed)"
        }
        SystemIx::AssignWithSeed {
            account,
            base,
            seed,
            owner,
        } => {
            tx.address(out, "계정", account);
            tx.address(out, "기준 계정", base);
            out.push(seed_line(seed));
            tx.address(out, "새 소유 프로그램", owner);
            "seed 계정 소유 프로그램 바꾸기 (AssignWithSeed)"
        }
        SystemIx::TransferWithSeed {
            from,
            base,
            to,
            lamports,
            seed,
            owner,
        } => {
            tx.address(out, "보내는 계정", from);
            tx.address(out, "기준 계정", base);
            tx.address(out, "받는 계정", to);
            out.push(lamports_line(*lamports));
            out.push(seed_line(seed));
            tx.address(out, "소유 프로그램", owner);
            "seed 계정에서 SOL 보내기 (TransferWithSeed)"
        }
        SystemIx::UpgradeNonce { nonce } => {
            tx.address(out, "nonce 계정", nonce);
            "nonce 계정 갱신 (UpgradeNonceAccount)"
        }
    }
}

const fn authority_type_text(kind: AuthorityType) -> &'static str {
    match kind {
        AuthorityType::MintTokens => "발행 권한(MintTokens)",
        AuthorityType::FreezeAccount => "동결 권한(FreezeAccount)",
        AuthorityType::AccountOwner => "토큰 계정 소유자(AccountOwner)",
        AuthorityType::CloseAccount => "닫기 권한(CloseAccount)",
    }
}

/// The title and lines of a Token or Token-2022 instruction.
#[expect(
    clippy::too_many_lines,
    reason = "one arm per Token tag, in tag order like the spec/07 §20.4 list"
)]
fn token_lines(tx: &Tx<'_>, ix: &TokenIx, out: &mut Vec<String>) -> String {
    let title = match ix {
        TokenIx::InitializeMint {
            mint,
            decimals,
            mint_authority,
            freeze_authority,
        }
        | TokenIx::InitializeMint2 {
            mint,
            decimals,
            mint_authority,
            freeze_authority,
        } => {
            tx.address(out, "mint", mint);
            out.push(format!("decimals {decimals}"));
            tx.address(out, "발행 권한", mint_authority);
            option_line(out, tx, "동결 권한", freeze_authority.as_ref());
            "mint 초기화 (InitializeMint)"
        }
        TokenIx::InitializeAccount {
            account,
            mint,
            owner,
        }
        | TokenIx::InitializeAccount2 {
            account,
            mint,
            owner,
        }
        | TokenIx::InitializeAccount3 {
            account,
            mint,
            owner,
        } => {
            tx.address(out, "토큰 계정", account);
            tx.address(out, "mint", mint);
            tx.address(out, "소유자", owner);
            "토큰 계정 초기화 (InitializeAccount)"
        }
        TokenIx::InitializeMultisig { multisig, m }
        | TokenIx::InitializeMultisig2 { multisig, m } => {
            tx.address(out, "멀티시그 계정", multisig);
            out.push(format!("필요 서명 {m}개"));
            "멀티시그 초기화 (InitializeMultisig)"
        }
        TokenIx::Transfer {
            source,
            destination,
            authority,
            amount,
        } => {
            tx.address(out, "보내는 토큰 계정", source);
            tx.address(out, "받는 토큰 계정", destination);
            tx.address(out, "소유자·위임자", authority);
            out.push(tx.amount(tx.mint_of(source).as_ref(), *amount, None));
            "토큰 보내기 (Transfer)"
        }
        TokenIx::Approve {
            source,
            delegate,
            owner,
            amount,
        } => {
            tx.address(out, "토큰 계정", source);
            tx.address(out, "위임받는 주소", delegate);
            tx.address(out, "소유자", owner);
            out.push(format!(
                "위임 한도 {}",
                tx.amount(tx.mint_of(source).as_ref(), *amount, None)
            ));
            "토큰 사용 권한 위임 (Approve)"
        }
        TokenIx::Revoke { source, owner } => {
            tx.address(out, "토큰 계정", source);
            tx.address(out, "소유자", owner);
            "위임 해제 (Revoke)"
        }
        TokenIx::SetAuthority {
            account,
            current,
            kind,
            new,
        } => {
            tx.address(out, "mint·토큰 계정", account);
            out.push(format!("바뀌는 권한: {}", authority_type_text(*kind)));
            tx.address(out, "현재 권한", current);
            option_line(out, tx, "새 권한", new.as_ref());
            "권한 변경 (SetAuthority)"
        }
        TokenIx::MintTo {
            mint,
            destination,
            authority,
            amount,
        } => {
            tx.address(out, "mint", mint);
            tx.address(out, "받는 토큰 계정", destination);
            tx.address(out, "발행 권한", authority);
            out.push(tx.amount(Some(mint), *amount, None));
            "토큰 발행 (MintTo)"
        }
        TokenIx::Burn {
            account,
            mint,
            authority,
            amount,
        } => {
            tx.address(out, "토큰 계정", account);
            tx.address(out, "mint", mint);
            tx.address(out, "소유자·위임자", authority);
            out.push(tx.amount(Some(mint), *amount, None));
            "토큰 소각 (Burn)"
        }
        TokenIx::CloseAccount {
            account,
            destination,
            authority,
        } => {
            tx.address(out, "닫는 토큰 계정", account);
            tx.address(out, "남은 SOL을 받는 주소", destination);
            tx.address(out, "소유자·닫기 권한", authority);
            "토큰 계정 닫기 (CloseAccount)"
        }
        TokenIx::FreezeAccount {
            account,
            mint,
            authority,
        } => {
            tx.address(out, "토큰 계정", account);
            tx.address(out, "mint", mint);
            tx.address(out, "동결 권한", authority);
            "토큰 계정 동결 (FreezeAccount)"
        }
        TokenIx::ThawAccount {
            account,
            mint,
            authority,
        } => {
            tx.address(out, "토큰 계정", account);
            tx.address(out, "mint", mint);
            tx.address(out, "동결 권한", authority);
            "토큰 계정 동결 해제 (ThawAccount)"
        }
        TokenIx::TransferChecked {
            source,
            mint,
            destination,
            authority,
            amount,
            decimals,
        } => {
            tx.address(out, "보내는 토큰 계정", source);
            tx.address(out, "mint", mint);
            tx.address(out, "받는 토큰 계정", destination);
            tx.address(out, "소유자·위임자", authority);
            out.push(tx.amount(Some(mint), *amount, Some(*decimals)));
            "토큰 보내기 (TransferChecked)"
        }
        TokenIx::ApproveChecked {
            source,
            mint,
            delegate,
            owner,
            amount,
            decimals,
        } => {
            tx.address(out, "토큰 계정", source);
            tx.address(out, "mint", mint);
            tx.address(out, "위임받는 주소", delegate);
            tx.address(out, "소유자", owner);
            out.push(format!(
                "위임 한도 {}",
                tx.amount(Some(mint), *amount, Some(*decimals))
            ));
            "토큰 사용 권한 위임 (ApproveChecked)"
        }
        TokenIx::MintToChecked {
            mint,
            destination,
            authority,
            amount,
            decimals,
        } => {
            tx.address(out, "mint", mint);
            tx.address(out, "받는 토큰 계정", destination);
            tx.address(out, "발행 권한", authority);
            out.push(tx.amount(Some(mint), *amount, Some(*decimals)));
            "토큰 발행 (MintToChecked)"
        }
        TokenIx::BurnChecked {
            account,
            mint,
            authority,
            amount,
            decimals,
        } => {
            tx.address(out, "토큰 계정", account);
            tx.address(out, "mint", mint);
            tx.address(out, "소유자·위임자", authority);
            out.push(tx.amount(Some(mint), *amount, Some(*decimals)));
            "토큰 소각 (BurnChecked)"
        }
        TokenIx::SyncNative { account } => {
            tx.address(out, "wrapped SOL 토큰 계정", account);
            "wrapped SOL 잔액 맞추기 (SyncNative)"
        }
        TokenIx::GetAccountDataSize { mint, extensions } => {
            tx.address(out, "mint", mint);
            if !extensions.is_empty() {
                let list: Vec<String> = extensions.iter().map(u16::to_string).collect();
                out.push(format!("확장 유형: {}", list.join(", ")));
            }
            "계정 크기 조회 (GetAccountDataSize)"
        }
        TokenIx::InitializeImmutableOwner { account } => {
            tx.address(out, "토큰 계정", account);
            "소유자 고정 (InitializeImmutableOwner)"
        }
        TokenIx::AmountToUiAmount { mint, amount } => {
            tx.address(out, "mint", mint);
            out.push(format!("{} 원시 단위", format_raw(*amount)));
            "금액 표기 변환 (AmountToUiAmount)"
        }
        TokenIx::UiAmountToAmount { mint, ui_amount } => {
            tx.address(out, "mint", mint);
            out.push(format!("금액 표기: {}", inline_value(ui_amount)));
            "금액 표기 변환 (UiAmountToAmount)"
        }
        TokenIx::Extension { tag } => {
            return format!("Token-2022 확장 명령 {tag} (해석하지 않음)");
        }
    };
    title.to_owned()
}

/// The title and lines of an ATA instruction.
fn ata_lines(tx: &Tx<'_>, ix: &AtaIx, out: &mut Vec<String>) -> &'static str {
    match ix {
        AtaIx::Create {
            payer,
            ata,
            wallet,
            mint,
            token_program,
            idempotent,
        } => {
            tx.address(out, "rent를 내는 계정", payer);
            tx.address(out, "토큰 계정(ATA, 유도값 확인됨)", ata);
            tx.address(out, "소유 지갑", wallet);
            tx.address(out, "mint", mint);
            tx.address(out, "토큰 프로그램", token_program);
            if *idempotent {
                "토큰 계정 만들기, 있으면 그대로 (CreateIdempotent)"
            } else {
                "토큰 계정 만들기 (Create)"
            }
        }
        AtaIx::RecoverNested {
            nested,
            nested_mint,
            destination,
            owner_ata,
            owner_mint,
            wallet,
            token_program,
        } => {
            tx.address(out, "중첩된 토큰 계정", nested);
            tx.address(out, "중첩 mint", nested_mint);
            tx.address(out, "받는 토큰 계정", destination);
            tx.address(out, "소유 토큰 계정", owner_ata);
            tx.address(out, "소유 mint", owner_mint);
            tx.address(out, "지갑", wallet);
            tx.address(out, "토큰 프로그램", token_program);
            "중첩 토큰 계정 회수 (RecoverNested)"
        }
    }
}

fn compute_budget_text(ix: CbIx) -> (&'static str, u64) {
    match ix {
        CbIx::RequestHeapFrame(bytes) => {
            ("힙 크기 요청 (RequestHeapFrame), 바이트", u64::from(bytes))
        }
        CbIx::SetComputeUnitLimit(units) => ("CU 한도 (SetComputeUnitLimit)", u64::from(units)),
        CbIx::SetComputeUnitPrice(micro) => {
            ("CU 가격 (SetComputeUnitPrice), micro-lamports/CU", micro)
        }
        CbIx::SetLoadedAccountsDataSizeLimit(bytes) => (
            "읽는 계정 데이터 한도 (SetLoadedAccountsDataSizeLimit), 바이트",
            u64::from(bytes),
        ),
    }
}

/// The instruction list (`0x0512`): per instruction its program, what it does, every account it
/// names and, when not interpreted, its accounts and data as they are.
fn instructions_text(tx: &Tx<'_>, wire: &SolWireTx, decoded: &[DecodedIx]) -> String {
    let message = &wire.message;
    let mut out: Vec<String> = Vec::new();
    for (index, ix) in decoded.iter().enumerate() {
        let Some((program, indices, data)) = message.instruction(index) else {
            continue;
        };
        let name = program_name(program).unwrap_or("알 수 없는 프로그램");
        let mut lines: Vec<String> = Vec::new();
        let title: String = match ix {
            DecodedIx::System(system) => system_lines(tx, system, &mut lines).to_owned(),
            DecodedIx::Token { ix: token, .. } => token_lines(tx, token, &mut lines),
            DecodedIx::Ata(ata) => ata_lines(tx, ata, &mut lines).to_owned(),
            DecodedIx::ComputeBudget(cb) => {
                let (text, value) = compute_budget_text(*cb);
                format!("{text}: {}", format_raw(value))
            }
            DecodedIx::Memo(memo) => {
                match core::str::from_utf8(memo) {
                    Ok(text) => lines.push(format!("메모: {}", inline_value(text))),
                    Err(_) => lines.push(format!("메모(hex):\n{}", hex_lines(memo))),
                }
                "메모".to_owned()
            }
            DecodedIx::Precompile { count } => format!("서명 검증 {count}건 (계정 사용 없음)"),
            DecodedIx::Unknown { reason } => match reason {
                Some(reason) => format!("해석하지 않음 — {reason}"),
                None => "해석하지 않음".to_owned(),
            },
        };
        out.push(format!("{}. {name}: {title}", index.saturating_add(1)));
        if ix.is_opaque() || program_name(program).is_none() {
            tx.address(&mut out, "프로그램", program);
        }
        out.extend(lines);
        if ix.is_opaque() {
            for (position, account) in indices.iter().enumerate() {
                let label = format!("계정 {}", position.saturating_add(1));
                match tx.keys.get(usize::from(*account)) {
                    Some((address, _)) => tx.address(&mut out, &label, address),
                    None => out.push(format!(
                        "{label}: 조회 테이블 인덱스 {account} (해석 못 함)"
                    )),
                }
            }
            out.push(format!("데이터 {}바이트", data.len()));
            if !data.is_empty() {
                out.push(hex_lines(data));
            }
        }
    }
    if out.is_empty() {
        "명령 없음".to_owned()
    } else {
        out.join("\n")
    }
}

/// The signer slots (`0x0511`): who signs, who pays the fee, and the state of each slot.
fn signers_text(tx: &Tx<'_>, wire: &SolWireTx, ours: u8, send: bool) -> String {
    let message = &wire.message;
    let mut out: Vec<String> = Vec::new();
    for (index, signature) in wire.signatures.iter().enumerate() {
        let Some(key) = message.static_keys.get(index) else {
            continue;
        };
        let label = if index == 0 {
            format!("서명자 {} · 수수료 지불", index.saturating_add(1))
        } else {
            format!("서명자 {}", index.saturating_add(1))
        };
        tx.address(&mut out, &label, key);
        let state = if index == usize::from(ours) {
            "지갑이 서명합니다"
        } else if signature.iter().all(|byte| *byte == 0) {
            if send {
                "서명 없음 — 지갑이 전송할 수 없습니다"
            } else {
                "서명 없음 (사이트가 나중에 채움)"
            }
        } else if crate::sol::keys::verify_strict(key.as_bytes(), &wire.message_bytes, signature) {
            "사이트가 넣은 서명 (확인됨)"
        } else {
            "사이트가 넣은 서명이 맞지 않습니다"
        };
        out.push(state.to_owned());
    }
    out.join("\n")
}

/// The writable accounts (`0x0513`), with the runtime's read-only demotion noted.
fn writable_text(tx: &Tx<'_>, loaded: Option<&ResolvedKeys>, has_lookups: bool) -> String {
    let mut out: Vec<String> = Vec::new();
    for (address, role) in &tx.keys {
        if role.writable {
            tx.address(&mut out, "", address);
            if tx.demoted(address) {
                out.push("(런타임에서 읽기 전용)".to_owned());
            }
        }
    }
    if has_lookups && loaded.is_none() {
        out.push(
            "조회 테이블을 해석하지 못해 테이블에서 오는 쓰기 가능한 주소를 알 수 없습니다"
                .to_owned(),
        );
    }
    if out.is_empty() {
        "없음".to_owned()
    } else {
        out.join("\n")
    }
}

/// The lookups (`0x0514`): each table and the addresses it gave (RPC values).
fn lookups_text(
    tx: &Tx<'_>,
    wire: &SolWireTx,
    loaded: Option<&ResolvedKeys>,
    tables: &[(SolAddress, LookupTable)],
    error: Option<&AltError>,
) -> String {
    let message = &wire.message;
    if message.lookups.is_empty() {
        return match message.version {
            SolTxVersion::Legacy => "조회 테이블 없음 (legacy 거래)".to_owned(),
            SolTxVersion::V0 => "조회 테이블 없음".to_owned(),
        };
    }
    let mut out: Vec<String> = Vec::new();
    let (mut writable, mut readonly) = (0_usize, 0_usize);
    for lookup in &message.lookups {
        let number = tx
            .tables
            .iter()
            .position(|table| *table == lookup.table)
            .map_or(0, |index| index.saturating_add(1));
        tx.address(&mut out, &format!("테이블 {number}"), &lookup.table);
        if tables
            .iter()
            .any(|(address, table)| *address == lookup.table && table.is_deactivated())
        {
            out.push("비활성화된 테이블".to_owned());
        }
        let Some(loaded) = loaded else {
            continue;
        };
        for (kind, indices, list, at) in [
            ("쓰기", &lookup.writable, &loaded.writable, &mut writable),
            ("읽기", &lookup.readonly, &loaded.readonly, &mut readonly),
        ] {
            for index in indices {
                if let Some(address) = list.get(*at) {
                    tx.address(&mut out, &format!("{kind} · 인덱스 {index}"), address);
                }
                *at = at.saturating_add(1);
            }
        }
    }
    if let Some(error) = error {
        out.push(format!("해석하지 못함: {error}"));
    }
    out.join("\n")
}

/// The changes (`0x0515`), authority changes first. The SOL change includes the fee only when
/// the wallet pays it (`wallet_pays`, slot 0; spec/07 §20.7).
fn changes_text(tx: &Tx<'_>, list: Option<&[Change]>, wallet_pays: bool) -> String {
    let Some(list) = list else {
        return "시뮬레이션 결과가 없어 변화를 확인할 수 없습니다".to_owned();
    };
    if list.is_empty() {
        return "지켜본 계정(내 지갑·내 토큰 계정·새 계정)에 변화 없음".to_owned();
    }
    let mut out: Vec<String> = Vec::new();
    for change in list {
        match change {
            Change::Sol { pre, post } => out.push(format!(
                "내 지갑 SOL {} SOL ({} → {} lamports{})",
                delta(*pre, *post, 9),
                format_raw(*pre),
                format_raw(*post),
                if wallet_pays {
                    ", 수수료 포함"
                } else {
                    ""
                }
            )),
            Change::Token {
                account,
                mint,
                program2022,
                pre,
                post,
                decimals,
            } => {
                let unit = match decimals {
                    Some((decimals, true)) => format!(
                        "{} {}",
                        delta(*pre, *post, *decimals),
                        tx.symbol(mint).unwrap_or("토큰")
                    ),
                    Some((decimals, false)) => format!(
                        "{} 토큰 (decimals {decimals} RPC 참고)",
                        delta(*pre, *post, *decimals)
                    ),
                    None => format!("{} (원시 단위)", delta(*pre, *post, 0)),
                };
                let program = if *program2022 { " (Token-2022)" } else { "" };
                out.push(format!("내 토큰{program} {unit}"));
                tx.address(&mut out, "토큰 계정", account);
                tx.address(&mut out, "mint", mint);
            }
            Change::Authority {
                account,
                what,
                before,
                after,
            } => {
                out.push(
                    match what {
                        AuthorityKind::Owner => "권한 변화: 토큰 계정 소유자",
                        AuthorityKind::Delegate => "권한 변화: 토큰 계정 위임자",
                        AuthorityKind::CloseAuthority => "권한 변화: 토큰 계정 닫기 권한",
                        AuthorityKind::WalletOwnerProgram => "권한 변화: 내 지갑의 소유 프로그램",
                    }
                    .to_owned(),
                );
                tx.address(&mut out, "계정", account);
                option_line(&mut out, tx, "이전", before.as_ref());
                option_line(&mut out, tx, "이후", after.as_ref());
            }
            Change::Closed { account } => tx.address(&mut out, "닫힘", account),
            Change::Created { account, mint } => {
                tx.address(&mut out, "새로 만들어짐", account);
                if let Some(mint) = mint {
                    tx.address(&mut out, "토큰 계정 · mint", mint);
                }
            }
        }
    }
    out.join("\n")
}

fn sim_text(sim: SimSummary, replaced: bool) -> String {
    let mut text = match sim {
        SimSummary::Ok { units } => format!("성공 (CU {})", format_raw(units)),
        SimSummary::Failed { err: code, .. } => format!("실패: {}", err::text(code)),
        SimSummary::NoResult => "결과 없음".to_owned(),
    };
    if replaced {
        text.push_str("\n블록해시를 바꿔 시뮬레이션함(replaceRecentBlockhash) — 참고용");
    }
    text
}

fn fee_text(tx: &Tx<'_>, fee: u128, from_rpc: bool, payer: &SolAddress, cap: u64) -> String {
    let mut out = vec![format!(
        "{} lamports ({})",
        format_raw(u64::try_from(fee).unwrap_or(u64::MAX)),
        if from_rpc {
            "RPC getFeeForMessage"
        } else {
            "계산값 — RPC가 답하지 않음"
        }
    )];
    if *payer == tx.wallet {
        out.push("수수료 지불: 내 지갑".to_owned());
        out.push(format!("사용자 상한 {} lamports", format_raw(cap)));
    } else {
        tx.address(&mut out, "수수료 지불: 다른 계정", payer);
    }
    out.join("\n")
}

/// The per-transaction rules from the decoded instructions (X02–X07).
fn instruction_rules(
    tx: &Tx<'_>,
    wire: &SolWireTx,
    decoded: &[DecodedIx],
    prefix: &dyn Fn(Option<usize>) -> String,
    causes: &mut Causes,
) {
    for (index, ix) in decoded.iter().enumerate() {
        let Some((program, indices, _)) = wire.message.instruction(index) else {
            continue;
        };
        let at = prefix(Some(index));
        if ix.is_opaque() {
            let what = match (ix, program_name(program)) {
                (
                    DecodedIx::Token {
                        ix: TokenIx::Extension { tag },
                        ..
                    },
                    _,
                ) => format!("Token-2022 확장 명령 {tag}"),
                (
                    DecodedIx::Unknown {
                        reason: Some(reason),
                    },
                    Some(name),
                ) => {
                    format!("{name} — {reason}")
                }
                (
                    DecodedIx::Unknown {
                        reason: Some(reason),
                    },
                    None,
                ) => {
                    format!("{} — {reason}", program.to_base58())
                }
                (_, Some(name)) => format!("{name} 프로그램 {}", program.to_base58()),
                (_, None) => format!("프로그램 {}", program.to_base58()),
            };
            causes.add(X02, Some(format!("{at}{what}")));
            let touches_ours = indices.iter().any(|account| {
                tx.keys
                    .get(usize::from(*account))
                    .is_some_and(|(address, _)| tx.is_ours(address))
            });
            if touches_ours {
                causes.add(X03, Some(format!("{at}{what}")));
            }
        }
        match ix {
            DecodedIx::Token {
                ix:
                    TokenIx::Approve { source, owner, .. }
                    | TokenIx::ApproveChecked { source, owner, .. },
                ..
            } if *owner == tx.wallet || tx.is_ours(source) => {
                causes.add(X04, Some(format!("{at}토큰 사용 권한 위임")));
            }
            DecodedIx::Token {
                ix:
                    TokenIx::SetAuthority {
                        account,
                        current,
                        kind,
                        ..
                    },
                ..
            } if *current == tx.wallet || tx.is_ours(account) => {
                causes.add(X05, Some(format!("{at}{}", authority_type_text(*kind))));
            }
            DecodedIx::System(
                SystemIx::Assign { account, .. }
                | SystemIx::Allocate { account, .. }
                | SystemIx::AssignWithSeed { account, .. }
                | SystemIx::AllocateWithSeed { account, .. },
            ) if *account == tx.wallet => {
                causes.add(
                    X06,
                    (!at.is_empty()).then(|| at.trim_end_matches(": ").to_owned()),
                );
            }
            DecodedIx::Token {
                ix:
                    TokenIx::CloseAccount {
                        account,
                        destination,
                        authority,
                    },
                ..
            } if (tx.is_ours(account) || *authority == tx.wallet) && *destination != tx.wallet => {
                causes.add(
                    X07,
                    Some(format!(
                        "{at}남은 SOL을 받는 주소 {}",
                        destination.to_base58()
                    )),
                );
            }
            _ => {}
        }
    }
}

/// The mints a transaction touches: named by token instructions or held by its pre-state token
/// accounts.
fn touched_mints(tx: &Tx<'_>, decoded: &[DecodedIx]) -> Vec<SolAddress> {
    let mut out: Vec<SolAddress> = Vec::new();
    let mut add = |mint: SolAddress| {
        if !out.contains(&mint) {
            out.push(mint);
        }
    };
    for ix in decoded {
        let mint = ix.named_mint().or_else(|| match ix {
            DecodedIx::Token {
                ix: TokenIx::Transfer { source, .. } | TokenIx::Approve { source, .. },
                ..
            } => tx.mint_of(source),
            _ => None,
        });
        if let Some(mint) = mint {
            add(mint);
        }
    }
    for (_, snapshot) in tx.pre {
        if let Some(view) = snapshot.as_ref().and_then(AccountSnapshot::token) {
            add(view.mint);
        }
    }
    out
}

/// One transaction's payload item, fields and warnings.
struct Built {
    item: SolTxItem,
    fields: Vec<DisplayField>,
}

#[expect(
    clippy::too_many_lines,
    reason = "the spec/07 §20.6 rules and fields of one transaction in order"
)]
fn build_item(
    request: &SolTxRequest,
    facts: &SolTxFacts,
    item_facts: &SolTxItemFacts,
    index: usize,
    causes: &mut Causes,
) -> Result<Built, DisplayError> {
    let count = request.txs.len();
    let bytes = request.txs.get(index).ok_or(DisplayError::InvalidText)?;
    let wire = parse_wire_tx(bytes).map_err(|_| DisplayError::InvalidText)?;
    let message = &wire.message;
    if encode_message_any(message) != wire.message_bytes {
        return Err(DisplayError::InvalidText);
    }
    let slot = message
        .signer_slot(&request.public)
        .map_err(|_| DisplayError::InvalidText)?;
    let send = request.mode == SolTxMode::SignAndSend;
    let prefix = |instruction: Option<usize>| at(index, count, instruction);
    let wallet = SolAddress::from_bytes(request.public);
    // Lookups: resolved from the RPC tables, or X01 for this transaction only.
    let empty: Vec<(SolAddress, LookupTable)> = Vec::new();
    let (loaded, tables, alt_error) = if message.lookups.is_empty() {
        (Some(ResolvedKeys::default()), empty.as_slice(), None)
    } else {
        causes.add(X10, None);
        match &item_facts.tables {
            Ok((current, tables)) => match alt::resolve(message, tables, *current) {
                Ok(keys) => (Some(keys), tables.as_slice(), None),
                Err(error) => (None, tables.as_slice(), Some(error)),
            },
            Err(error) => (None, empty.as_slice(), Some(*error)),
        }
    };
    if let Some(error) = alt_error {
        causes.add(X01, Some(format!("{}{error}", prefix(None))));
    }
    let table_order = alt::lookup_tables(message);
    for (address, table) in tables {
        if table.is_deactivated() && table_order.contains(address) {
            causes.add(
                X10,
                Some(format!(
                    "{}비활성화된 테이블 {}",
                    prefix(None),
                    address.to_base58()
                )),
            );
        }
    }
    let keys = full_keys(message, loaded.as_ref());
    let own_tokens: Vec<(SolAddress, SolAddress)> = item_facts
        .pre
        .iter()
        .filter_map(|(address, snapshot)| {
            let view = snapshot.as_ref()?.token()?;
            (view.owner == wallet).then_some((*address, view.mint))
        })
        .collect();
    let tx = Tx {
        wallet,
        cluster: request.cluster,
        known: &facts.known,
        keys,
        programs: message.program_ids(),
        tables: table_order,
        own_tokens,
        pre: &item_facts.pre,
        mints: &facts.mints,
    };
    let decoded = decode_message(message, &tx.keys);
    // Signatures: every non-zero site signature must verify; a send needs all of them.
    if !wire.foreign_signatures_ok(slot, false) {
        causes.add(
            X01,
            Some(format!(
                "{}사이트가 넣은 서명이 맞지 않습니다",
                prefix(None)
            )),
        );
    }
    let foreign_signed = wire
        .signatures
        .iter()
        .enumerate()
        .any(|(index, signature)| index != usize::from(slot) && signature.iter().any(|b| *b != 0));
    if send && !wire.foreign_signatures_ok(slot, true) {
        causes.add(
            X01,
            Some(format!(
                "{}전송하려면 다른 서명이 모두 있어야 합니다",
                prefix(None)
            )),
        );
    }
    let nonce = message.durable_nonce().is_some();
    if nonce {
        causes.add(
            X08,
            (count > 1).then(|| prefix(None).trim_end_matches(": ").to_owned()),
        );
        if send {
            causes.add(
                X01,
                Some(format!(
                    "{}durable nonce 거래는 지갑이 전송하지 않습니다",
                    prefix(None)
                )),
            );
        }
    }
    if slot != 0 || foreign_signed {
        let mut parts = Vec::new();
        if slot != 0 {
            parts.push("수수료는 다른 계정이 냅니다");
        }
        if foreign_signed {
            parts.push("사이트가 넣은 서명이 있습니다");
        }
        causes.add(X13, Some(format!("{}{}", prefix(None), parts.join(" · "))));
    }
    instruction_rules(&tx, &wire, &decoded, &prefix, causes);
    // Mint extensions (Token-2022 TLV).
    for mint in touched_mints(&tx, &decoded) {
        let Some((_, view)) = facts.mints.iter().find(|(address, _)| *address == mint) else {
            continue;
        };
        if view.extensions.contains(&EXT_TRANSFER_FEE_CONFIG) {
            causes.add(
                X12,
                Some(format!("{}mint {}", prefix(None), mint.to_base58())),
            );
        }
        if view.extensions.contains(&EXT_PERMANENT_DELEGATE)
            || view.extensions.contains(&EXT_TRANSFER_HOOK)
        {
            causes.add(
                X17,
                Some(format!("{}mint {}", prefix(None), mint.to_base58())),
            );
        }
    }
    // Simulation.
    if matches!(
        item_facts.sim,
        SimSummary::Failed { .. } | SimSummary::NoResult
    ) {
        causes.add(
            X09,
            Some(format!(
                "{}{}",
                prefix(None),
                sim_text(item_facts.sim, false)
            )),
        );
    }
    if item_facts.sim_replaced_blockhash {
        causes.add(
            X19,
            (count > 1).then(|| prefix(None).trim_end_matches(": ").to_owned()),
        );
    }
    let diff = item_facts.post.as_ref().map(|post| {
        changes(
            &wallet,
            request.cluster,
            &item_facts.pre,
            post,
            &facts.mints,
        )
    });
    if diff
        .as_ref()
        .is_some_and(|list| list.iter().any(Change::is_authority))
    {
        causes.add(
            X15,
            (count > 1).then(|| prefix(None).trim_end_matches(": ").to_owned()),
        );
    }
    // Lookalikes among every key.
    for (address, _) in &tx.keys {
        if let Some(known) = tx.lookalike(address) {
            causes.add(
                X16,
                Some(format!(
                    "{}{} ↔ {} ({})",
                    prefix(None),
                    address.to_base58(),
                    known.address.to_base58(),
                    inline_value(&known.label)
                )),
            );
        }
    }
    if message.account_count() > RUNTIME_ACCOUNT_LIMIT || message.duplicate_compute_budget() {
        causes.add(
            X18,
            (count > 1).then(|| prefix(None).trim_end_matches(": ").to_owned()),
        );
    }
    // Fee.
    let (fee, from_rpc) = item_facts.rpc_fee.map_or_else(
        || (dapp_fee_estimate(message), false),
        |fee| (u128::from(fee), true),
    );
    let payer = message.fee_payer().ok_or(DisplayError::InvalidText)?;
    if slot == 0 && fee > u128::from(facts.fee_cap) {
        causes.add(
            X14,
            Some(format!(
                "{}{} lamports > 상한 {} lamports",
                prefix(None),
                format_raw(u64::try_from(fee).unwrap_or(u64::MAX)),
                format_raw(facts.fee_cap)
            )),
        );
    }
    // Fields in the window's order: changes, fee, instructions, writable, signers, tables,
    // simulation, validity, audit, raw.
    let sub = if count > 1 {
        format!("거래 {}/{count}", index.saturating_add(1))
    } else {
        String::new()
    };
    let validity = if nonce {
        "durable nonce — 만료 없음\n서명한 거래는 언제든 제출될 수 있습니다".to_owned()
    } else {
        let checked = if item_facts.blockhash_valid == Some(true) {
            "블록해시 유효 확인됨 (RPC, processed)"
        } else {
            "블록해시 확인 안 됨 — 만료되었거나 RPC보다 새것"
        };
        format!(
            "{checked}\n블록해시는 약 150블록 뒤 만료됩니다 — 늦게 승인하면 거래가 실패할 수 있습니다"
        )
    };
    let fields = vec![
        DisplayField::new(
            FieldKey::SOL_TX_CHANGES,
            sub.clone(),
            changes_text(&tx, diff.as_deref(), slot == 0),
        )?,
        DisplayField::new(
            FieldKey::SOL_TX_FEE,
            sub.clone(),
            fee_text(&tx, fee, from_rpc, &payer, facts.fee_cap),
        )?,
        DisplayField::new(
            FieldKey::SOL_TX_INSTRUCTIONS,
            sub.clone(),
            instructions_text(&tx, &wire, &decoded),
        )?,
        DisplayField::new(
            FieldKey::SOL_TX_WRITABLE,
            sub.clone(),
            writable_text(&tx, loaded.as_ref(), !message.lookups.is_empty()),
        )?,
        DisplayField::new(
            FieldKey::SOL_TX_SIGNERS,
            sub.clone(),
            signers_text(&tx, &wire, slot, send),
        )?,
        DisplayField::new(
            FieldKey::SOL_TX_LOOKUPS,
            sub.clone(),
            lookups_text(&tx, &wire, loaded.as_ref(), tables, alt_error.as_ref()),
        )?,
        DisplayField::new(
            FieldKey::SOL_TX_SIMULATION,
            sub.clone(),
            sim_text(item_facts.sim, item_facts.sim_replaced_blockhash),
        )?,
        DisplayField::new(FieldKey::SOL_TX_VALIDITY, sub.clone(), validity)?,
        DisplayField::new(
            FieldKey::SOL_TX_AUDIT,
            sub.clone(),
            crate::hex::encode(&Sha256::digest(&wire.message_bytes)),
        )?,
        DisplayField::new(FieldKey::SOL_TX_RAW, sub, hex_lines(&wire.message_bytes))?,
    ];
    Ok(Built {
        item: SolTxItem {
            wire: bytes.clone(),
            signer_slot: slot,
            loaded,
        },
        fields,
    })
}

fn title(cluster: SolCluster, mode: SolTxMode, count: usize) -> String {
    let action = match (mode, count) {
        (SolTxMode::SignAndSend, _) => "사이트 거래 서명 후 전송".to_owned(),
        (SolTxMode::SignOnly, 1) => "사이트 거래 서명".to_owned(),
        (SolTxMode::SignOnly, count) => format!("사이트 거래 {count}건 서명"),
    };
    let full = format!("[{}] {action}", cluster.display_name());
    if full.len() <= MAX_TITLE_BYTES {
        full
    } else {
        format!("[{}] 사이트 거래 서명", cluster.display_name())
    }
}

fn send_options_text(options: &SolSendOptions) -> String {
    let preflight = if options.skip_preflight {
        "preflight 검사: 생략 (skipPreflight)".to_owned()
    } else {
        format!(
            "preflight 검사: 함 (commitment {})",
            options
                .preflight_commitment
                .map_or("confirmed", super::SolCommitment::as_str)
        )
    };
    let min = options.min_context_slot.map_or_else(
        || "minContextSlot: 없음".to_owned(),
        |slot| format!("minContextSlot: {} (첫 전송만)", format_raw(slot)),
    );
    format!("{preflight}\n{min}\n재전송: 만료될 때까지 지갑이 직접 (maxRetries 0)")
}

/// Builds the approval draft of a dApp transaction request (spec/07 §20.6).
///
/// # Errors
///
/// [`DisplayError`]: a transaction that does not parse, whose key is not a signer, or whose
/// facts are missing (the app validated all of this first: defensive), or a display bound.
pub fn build_sol_tx_request(
    request: &SolTxRequest,
    facts: &SolTxFacts,
) -> Result<ApprovalDraft, DisplayError> {
    let count = request.txs.len();
    if count == 0
        || count > super::SOL_TX_MAX_BATCH
        || facts.items.len() != count
        || (request.mode == SolTxMode::SignAndSend && count != 1)
    {
        return Err(DisplayError::InvalidText);
    }
    let address = SolAddress::from_bytes(request.public);
    let mut fields = vec![
        DisplayField::new(FieldKey::ORIGIN, "", request.origin.as_str())?,
        DisplayField::new(
            FieldKey::NETWORK,
            "",
            format!(
                "{}\ngenesis 확인됨: {}",
                request.cluster.display_name(),
                crate::codec::base58::base58_encode(&request.cluster.genesis())
            ),
        )?,
        DisplayField::new(
            FieldKey::ACCOUNT,
            "",
            format!(
                "{}\n{}\n{}",
                inline_value(&request.label),
                request.source.path_text(),
                grouped(&address)
            ),
        )?,
        DisplayField::new(
            FieldKey::SOL_TX_SUMMARY,
            "",
            match request.mode {
                SolTxMode::SignOnly => format!(
                    "서명만 — 서명한 거래를 사이트에 돌려줍니다 (지갑은 전송하지 않음)\n거래 {count}건"
                ),
                SolTxMode::SignAndSend => {
                    "서명 후 전송 — 지갑이 서명하고 바로 전송합니다\n거래 1건".to_owned()
                }
            },
        )?,
    ];
    if request.mode == SolTxMode::SignAndSend {
        fields.push(DisplayField::new(
            FieldKey::SOL_TX_SEND_OPTIONS,
            "",
            send_options_text(&request.options),
        )?);
    }
    let mut causes = Causes::default();
    if request.source.needs_move_rule() {
        causes.add(
            X01,
            Some("복구 스캔 계정으로는 사이트 거래에 서명하지 않습니다".to_owned()),
        );
    }
    if request.mode == SolTxMode::SignOnly {
        causes.add(X11, None);
    }
    let mut items = Vec::with_capacity(count);
    for (index, item_facts) in facts.items.iter().enumerate() {
        let built = build_item(request, facts, item_facts, index, &mut causes)?;
        items.push(built.item);
        fields.extend(built.fields);
    }
    let display = ApprovalDisplay::new(
        title(request.cluster, request.mode, count),
        fields,
        causes.into_warnings(),
    )?;
    let options = match request.mode {
        SolTxMode::SignOnly => SolSendOptions::default(),
        SolTxMode::SignAndSend => request.options,
    };
    Ok(ApprovalDraft {
        id: request.id,
        origin: ApprovalOrigin::Site(request.origin.clone()),
        chain: ChainRef::Solana {
            cluster: request.cluster,
            genesis: request.cluster.genesis(),
        },
        account: AccountRef::Sol(request.public),
        signer: Signer::FromPayload,
        kind: ApprovalKind::SolTransaction,
        payload: SigningPayload::SolTx(Box::new(SolTxPayload {
            source: request.source,
            public: request.public,
            mode: request.mode,
            options,
            items,
        })),
        display,
        simulation: SimulationBinding::NotApplicable,
    })
}
