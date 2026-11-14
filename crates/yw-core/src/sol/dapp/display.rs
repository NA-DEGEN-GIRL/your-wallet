//! The approval request of dApp Solana transactions (spec/07 §20.6): the payload, the display
//! fields `0x0510`–`0x051A` and `0x0540`, and the `X01`–`X20` warnings. The builder parses every
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
use super::text as t;
use super::{SolSendOptions, SolTxItem, SolTxMode, SolTxPayload};
use crate::approval::message::{hex_lines, inline_value};
use crate::approval::{
    AccountRef, ApprovalDisplay, ApprovalDraft, ApprovalId, ApprovalKind, ApprovalOrigin, ChainRef,
    DisplayError, DisplayField, FieldKey, MAX_TITLE_BYTES, RuleId, Signer, SigningPayload,
    SimulationBinding, Warning,
};
use crate::evm::risk::{
    self, X01, X02, X03, X04, X05, X06, X07, X08, X09, X10, X11, X12, X13, X14, X15, X16, X17, X18,
    X19, X20,
};
use crate::lang::{Lang, Text};
use crate::policy::BrowserOrigin;
use crate::slip10::SolKeySource;
use crate::sol::address::{
    BPF_LOADER_UPGRADEABLE, SolAddress, SolCluster, grouped, is_reserved_key, program_name,
};
use crate::sol::broadcast::err;
use crate::sol::display::SimSummary;
use crate::sol::fee::{DappFeeBounds, dapp_fee_bounds};
use crate::sol::recipient::{KnownAddress, KnownKind, is_lookalike};
use crate::sol::rent::{format_amount, format_raw};
use crate::sol::template::spl_entry;
use crate::sol::text as sol_text;
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
    /// `getFeeForMessage` (`None`: only the fee computed from the message is shown). Checked
    /// against that range (X20), never trusted below its maximum (X14).
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
    /// Token-2022 accounts named as mints whose data was not read (over the 16 KiB bound) or
    /// does not parse: X17 and X12 as if they had every extension (spec/07 §20.7 ④).
    pub unread_mints: Vec<SolAddress>,
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

    fn into_warnings(self, lang: Lang) -> Vec<Warning> {
        self.0
            .into_iter()
            .map(|(rule, causes)| {
                let joined = causes.join("\n");
                risk::warning(lang, rule, (!joined.is_empty()).then_some(joined.as_str()))
            })
            .collect()
    }
}

/// `거래 k: ` / `거래 k 명령 i: ` (only the instruction part for a single transaction).
fn at(lang: Lang, index: usize, count: usize, instruction: Option<usize>) -> String {
    let tx = index.saturating_add(1).to_string();
    let head = match (count > 1, instruction) {
        (true, Some(ix)) => t::AT_TX_IX.fill(lang, [&tx, &ix.saturating_add(1).to_string()]),
        (true, None) => t::AT_TX.fill(lang, [&tx]),
        (false, Some(ix)) => t::AT_IX.fill(lang, [&ix.saturating_add(1).to_string()]),
        (false, None) => return String::new(),
    };
    format!("{head}: ")
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
    lang: Lang,
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
    /// A fixed text in the request's language.
    fn tr(&self, text: Text) -> &'static str {
        text.get(self.lang)
    }

    fn tags(&self, address: &SolAddress) -> String {
        let lang = self.lang;
        let mut tags: Vec<String> = Vec::new();
        if let Some((_, role)) = self.keys.iter().find(|(key, _)| key == address) {
            if role.signer {
                tags.push(self.tr(t::TAG_SIGNER).to_owned());
            }
            if role.writable {
                tags.push(self.tr(t::TAG_WRITABLE).to_owned());
            }
            if let Some(table) = role.table
                && let Some(index) = self.tables.iter().position(|known| *known == table)
            {
                tags.push(t::TAG_TABLE.fill(lang, [&index.saturating_add(1).to_string()]));
            }
        }
        if let Some(name) = program_name(address) {
            tags.push(t::TAG_PROGRAM.fill(lang, [name]));
        }
        if *address == self.wallet {
            tags.push(self.tr(t::TAG_MY_WALLET).to_owned());
        }
        if let Some(mint) = self.own_token_mint(address) {
            tags.push(match self.symbol(mint) {
                Some(symbol) => t::TAG_MY_TOKEN_SYMBOL.fill(lang, [symbol]),
                None => self.tr(t::TAG_MY_TOKEN).to_owned(),
            });
        }
        if let Some(known) = self.exact(address) {
            let name = inline_value(lang, &known.label);
            match known.kind {
                KnownKind::Book { verified: true } => {
                    tags.push(t::TAG_BOOK_VERIFIED.fill(lang, [&name]));
                }
                KnownKind::Book { verified: false } => tags.push(t::TAG_BOOK.fill(lang, [&name])),
                KnownKind::Own { .. }
                | KnownKind::OwnImported
                | KnownKind::OwnHardware
                | KnownKind::OwnMnemonic => tags.push(t::TAG_MY_ACCOUNT.fill(lang, [&name])),
                KnownKind::Sent => tags.push(self.tr(t::TAG_SENT).to_owned()),
                KnownKind::History => {}
            }
        }
        if self.lookalike(address).is_some() {
            tags.push(self.tr(t::TAG_LOOKALIKE).to_owned());
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
        let lang = self.lang;
        if let Some(entry) = mint.and_then(|mint| spl_entry(self.cluster, mint)) {
            return t::AMOUNT_LISTED.fill(
                lang,
                [
                    &format_amount(raw, entry.decimals),
                    entry.symbol,
                    &format_raw(raw),
                ],
            );
        }
        if let Some(decimals) = decimals {
            return t::AMOUNT_DECIMALS.fill(
                lang,
                [
                    &format_amount(raw, decimals),
                    &format_raw(raw),
                    &decimals.to_string(),
                ],
            );
        }
        match mint.and_then(|mint| mint_decimals(self.cluster, mint, self.mints)) {
            Some((decimals, _)) => t::AMOUNT_RPC_DECIMALS.fill(
                lang,
                [
                    &format_amount(raw, decimals),
                    &format_raw(raw),
                    &decimals.to_string(),
                ],
            ),
            None => t::AMOUNT_RAW.fill(lang, [&format_raw(raw)]),
        }
    }

    /// `address` under the fixed label `label`.
    fn labeled(&self, out: &mut Vec<String>, label: Text, address: &SolAddress) {
        self.address(out, self.tr(label), address);
    }

    /// `크기 N바이트`.
    fn size_line(&self, space: u64) -> String {
        t::SIZE_BYTES.fill(self.lang, [&format_raw(space)])
    }
}

fn lamports_line(lamports: u64) -> String {
    format!(
        "{} SOL ({} lamports)",
        format_amount(lamports, 9),
        format_raw(lamports)
    )
}

fn seed_line(lang: Lang, seed: &str) -> String {
    format!("seed: {}", inline_value(lang, seed))
}

fn option_line(out: &mut Vec<String>, tx: &Tx<'_>, label: Text, address: Option<&SolAddress>) {
    match address {
        Some(address) => tx.labeled(out, label, address),
        None => out.push(t::OPTION_NONE.fill(tx.lang, [tx.tr(label)])),
    }
}

/// The title and lines of a System instruction.
#[expect(
    clippy::too_many_lines,
    reason = "one arm per System tag, in tag order like the spec/07 §20.4 list"
)]
fn system_lines(tx: &Tx<'_>, ix: &SystemIx, out: &mut Vec<String>) -> Text {
    match ix {
        SystemIx::CreateAccount {
            from,
            to,
            lamports,
            space,
            owner,
        } => {
            tx.labeled(out, t::L_FUNDING, from);
            tx.labeled(out, t::L_NEW_ACCOUNT, to);
            out.push(lamports_line(*lamports));
            out.push(tx.size_line(*space));
            tx.labeled(out, t::L_OWNER_PROGRAM, owner);
            t::T_CREATE_ACCOUNT
        }
        SystemIx::Assign { account, owner } => {
            tx.labeled(out, t::L_ACCOUNT, account);
            tx.labeled(out, t::L_NEW_OWNER_PROGRAM, owner);
            t::T_ASSIGN
        }
        SystemIx::Transfer { from, to, lamports } => {
            tx.labeled(out, t::L_FROM, from);
            tx.labeled(out, t::L_TO, to);
            out.push(lamports_line(*lamports));
            t::T_SOL_TRANSFER
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
            tx.labeled(out, t::L_FUNDING, from);
            tx.labeled(out, t::L_NEW_ACCOUNT, to);
            tx.labeled(out, t::L_BASE, base);
            out.push(seed_line(tx.lang, seed));
            out.push(lamports_line(*lamports));
            out.push(tx.size_line(*space));
            tx.labeled(out, t::L_OWNER_PROGRAM, owner);
            t::T_CREATE_WITH_SEED
        }
        SystemIx::AdvanceNonce {
            nonce,
            authority,
            extra,
        } => {
            tx.labeled(out, t::L_NONCE, nonce);
            tx.labeled(out, t::L_NONCE_AUTHORITY, authority);
            if !extra.is_empty() {
                out.push(t::TRAILING_BYTES.fill(tx.lang, [&crate::hex::encode(extra)]));
            }
            t::T_ADVANCE_NONCE
        }
        SystemIx::WithdrawNonce {
            nonce,
            to,
            authority,
            lamports,
        } => {
            tx.labeled(out, t::L_NONCE, nonce);
            tx.labeled(out, t::L_TO, to);
            tx.labeled(out, t::L_NONCE_AUTHORITY, authority);
            out.push(lamports_line(*lamports));
            t::T_WITHDRAW_NONCE
        }
        SystemIx::InitializeNonce { nonce, authority } => {
            tx.labeled(out, t::L_NONCE, nonce);
            tx.labeled(out, t::L_NONCE_AUTHORITY, authority);
            t::T_INIT_NONCE
        }
        SystemIx::AuthorizeNonce {
            nonce,
            authority,
            new_authority,
        } => {
            tx.labeled(out, t::L_NONCE, nonce);
            tx.labeled(out, t::L_CURRENT_AUTHORITY, authority);
            tx.labeled(out, t::L_NEW_AUTHORITY, new_authority);
            t::T_AUTHORIZE_NONCE
        }
        SystemIx::Allocate { account, space } => {
            tx.labeled(out, t::L_ACCOUNT, account);
            out.push(tx.size_line(*space));
            t::T_ALLOCATE
        }
        SystemIx::AllocateWithSeed {
            account,
            base,
            seed,
            space,
            owner,
        } => {
            tx.labeled(out, t::L_ACCOUNT, account);
            tx.labeled(out, t::L_BASE, base);
            out.push(seed_line(tx.lang, seed));
            out.push(tx.size_line(*space));
            tx.labeled(out, t::L_OWNER_PROGRAM, owner);
            t::T_ALLOCATE_WITH_SEED
        }
        SystemIx::AssignWithSeed {
            account,
            base,
            seed,
            owner,
        } => {
            tx.labeled(out, t::L_ACCOUNT, account);
            tx.labeled(out, t::L_BASE, base);
            out.push(seed_line(tx.lang, seed));
            tx.labeled(out, t::L_NEW_OWNER_PROGRAM, owner);
            t::T_ASSIGN_WITH_SEED
        }
        SystemIx::TransferWithSeed {
            from,
            base,
            to,
            lamports,
            seed,
            owner,
        } => {
            tx.labeled(out, t::L_FROM, from);
            tx.labeled(out, t::L_BASE, base);
            tx.labeled(out, t::L_TO, to);
            out.push(lamports_line(*lamports));
            out.push(seed_line(tx.lang, seed));
            tx.labeled(out, t::L_OWNER_PROGRAM, owner);
            t::T_TRANSFER_WITH_SEED
        }
        SystemIx::UpgradeNonce { nonce } => {
            tx.labeled(out, t::L_NONCE, nonce);
            t::T_UPGRADE_NONCE
        }
    }
}

const fn authority_type_text(lang: Lang, kind: AuthorityType) -> &'static str {
    match kind {
        AuthorityType::MintTokens => t::AUTH_MINT_TOKENS,
        AuthorityType::FreezeAccount => t::AUTH_FREEZE,
        AuthorityType::AccountOwner => t::AUTH_ACCOUNT_OWNER,
        AuthorityType::CloseAccount => t::AUTH_CLOSE,
    }
    .get(lang)
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
            tx.labeled(out, t::L_MINT_AUTHORITY, mint_authority);
            option_line(out, tx, t::L_FREEZE_AUTHORITY, freeze_authority.as_ref());
            t::T_INIT_MINT
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
            tx.labeled(out, t::L_TOKEN_ACCOUNT, account);
            tx.address(out, "mint", mint);
            tx.labeled(out, t::L_OWNER, owner);
            t::T_INIT_ACCOUNT
        }
        TokenIx::InitializeMultisig { multisig, m }
        | TokenIx::InitializeMultisig2 { multisig, m } => {
            tx.labeled(out, t::L_MULTISIG, multisig);
            out.push(t::REQUIRED_SIGNATURES.fill(tx.lang, [&m.to_string()]));
            t::T_INIT_MULTISIG
        }
        TokenIx::Transfer {
            source,
            destination,
            authority,
            amount,
        } => {
            tx.labeled(out, t::L_FROM_TOKEN, source);
            tx.labeled(out, t::L_TO_TOKEN, destination);
            tx.labeled(out, t::L_OWNER_DELEGATE, authority);
            out.push(tx.amount(tx.mint_of(source).as_ref(), *amount, None));
            t::T_TOKEN_TRANSFER
        }
        TokenIx::Approve {
            source,
            delegate,
            owner,
            amount,
        } => {
            tx.labeled(out, t::L_TOKEN_ACCOUNT, source);
            tx.labeled(out, t::L_DELEGATE, delegate);
            tx.labeled(out, t::L_OWNER, owner);
            let limit = tx.amount(tx.mint_of(source).as_ref(), *amount, None);
            out.push(t::DELEGATE_LIMIT.fill(tx.lang, [&limit]));
            t::T_APPROVE
        }
        TokenIx::Revoke { source, owner } => {
            tx.labeled(out, t::L_TOKEN_ACCOUNT, source);
            tx.labeled(out, t::L_OWNER, owner);
            t::T_REVOKE
        }
        TokenIx::SetAuthority {
            account,
            current,
            kind,
            new,
        } => {
            tx.labeled(out, t::L_MINT_OR_TOKEN, account);
            out.push(t::CHANGED_AUTHORITY.fill(tx.lang, [authority_type_text(tx.lang, *kind)]));
            tx.labeled(out, t::L_CURRENT_AUTHORITY, current);
            option_line(out, tx, t::L_NEW_AUTHORITY, new.as_ref());
            t::T_SET_AUTHORITY
        }
        TokenIx::MintTo {
            mint,
            destination,
            authority,
            amount,
        } => {
            tx.address(out, "mint", mint);
            tx.labeled(out, t::L_TO_TOKEN, destination);
            tx.labeled(out, t::L_MINT_AUTHORITY, authority);
            out.push(tx.amount(Some(mint), *amount, None));
            t::T_MINT_TO
        }
        TokenIx::Burn {
            account,
            mint,
            authority,
            amount,
        } => {
            tx.labeled(out, t::L_TOKEN_ACCOUNT, account);
            tx.address(out, "mint", mint);
            tx.labeled(out, t::L_OWNER_DELEGATE, authority);
            out.push(tx.amount(Some(mint), *amount, None));
            t::T_BURN
        }
        TokenIx::CloseAccount {
            account,
            destination,
            authority,
        } => {
            tx.labeled(out, t::L_CLOSING, account);
            tx.labeled(out, t::L_REST_TO, destination);
            tx.labeled(out, t::L_OWNER_CLOSE, authority);
            t::T_CLOSE
        }
        TokenIx::FreezeAccount {
            account,
            mint,
            authority,
        } => {
            tx.labeled(out, t::L_TOKEN_ACCOUNT, account);
            tx.address(out, "mint", mint);
            tx.labeled(out, t::L_FREEZE_AUTHORITY, authority);
            t::T_FREEZE
        }
        TokenIx::ThawAccount {
            account,
            mint,
            authority,
        } => {
            tx.labeled(out, t::L_TOKEN_ACCOUNT, account);
            tx.address(out, "mint", mint);
            tx.labeled(out, t::L_FREEZE_AUTHORITY, authority);
            t::T_THAW
        }
        TokenIx::TransferChecked {
            source,
            mint,
            destination,
            authority,
            amount,
            decimals,
        } => {
            tx.labeled(out, t::L_FROM_TOKEN, source);
            tx.address(out, "mint", mint);
            tx.labeled(out, t::L_TO_TOKEN, destination);
            tx.labeled(out, t::L_OWNER_DELEGATE, authority);
            out.push(tx.amount(Some(mint), *amount, Some(*decimals)));
            t::T_TRANSFER_CHECKED
        }
        TokenIx::ApproveChecked {
            source,
            mint,
            delegate,
            owner,
            amount,
            decimals,
        } => {
            tx.labeled(out, t::L_TOKEN_ACCOUNT, source);
            tx.address(out, "mint", mint);
            tx.labeled(out, t::L_DELEGATE, delegate);
            tx.labeled(out, t::L_OWNER, owner);
            let limit = tx.amount(Some(mint), *amount, Some(*decimals));
            out.push(t::DELEGATE_LIMIT.fill(tx.lang, [&limit]));
            t::T_APPROVE_CHECKED
        }
        TokenIx::MintToChecked {
            mint,
            destination,
            authority,
            amount,
            decimals,
        } => {
            tx.address(out, "mint", mint);
            tx.labeled(out, t::L_TO_TOKEN, destination);
            tx.labeled(out, t::L_MINT_AUTHORITY, authority);
            out.push(tx.amount(Some(mint), *amount, Some(*decimals)));
            t::T_MINT_TO_CHECKED
        }
        TokenIx::BurnChecked {
            account,
            mint,
            authority,
            amount,
            decimals,
        } => {
            tx.labeled(out, t::L_TOKEN_ACCOUNT, account);
            tx.address(out, "mint", mint);
            tx.labeled(out, t::L_OWNER_DELEGATE, authority);
            out.push(tx.amount(Some(mint), *amount, Some(*decimals)));
            t::T_BURN_CHECKED
        }
        TokenIx::SyncNative { account } => {
            tx.labeled(out, t::L_WSOL, account);
            t::T_SYNC_NATIVE
        }
        TokenIx::GetAccountDataSize { mint, extensions } => {
            tx.address(out, "mint", mint);
            if !extensions.is_empty() {
                let list: Vec<String> = extensions.iter().map(u16::to_string).collect();
                out.push(t::EXTENSION_TYPES.fill(tx.lang, [&list.join(", ")]));
            }
            t::T_GET_SIZE
        }
        TokenIx::InitializeImmutableOwner { account } => {
            tx.labeled(out, t::L_TOKEN_ACCOUNT, account);
            t::T_IMMUTABLE_OWNER
        }
        TokenIx::AmountToUiAmount { mint, amount } => {
            tx.address(out, "mint", mint);
            out.push(t::RAW_UNITS.fill(tx.lang, [&format_raw(*amount)]));
            t::T_AMOUNT_TO_UI
        }
        TokenIx::UiAmountToAmount { mint, ui_amount } => {
            tx.address(out, "mint", mint);
            out.push(t::UI_AMOUNT.fill(tx.lang, [&inline_value(tx.lang, ui_amount)]));
            t::T_UI_TO_AMOUNT
        }
        TokenIx::Extension { tag } => {
            return t::T_EXTENSION.fill(tx.lang, [&tag.to_string()]);
        }
    };
    tx.tr(title).to_owned()
}

/// The title and lines of an ATA instruction.
fn ata_lines(tx: &Tx<'_>, ix: &AtaIx, out: &mut Vec<String>) -> Text {
    match ix {
        AtaIx::Create {
            payer,
            ata,
            wallet,
            mint,
            token_program,
            idempotent,
        } => {
            tx.labeled(out, t::L_RENT_PAYER, payer);
            tx.labeled(out, t::L_ATA_DERIVED, ata);
            tx.labeled(out, t::L_OWNER_WALLET, wallet);
            tx.address(out, "mint", mint);
            tx.labeled(out, t::L_TOKEN_PROGRAM, token_program);
            if *idempotent {
                t::T_ATA_IDEMPOTENT
            } else {
                t::T_ATA_CREATE
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
            tx.labeled(out, t::L_NESTED, nested);
            tx.labeled(out, t::L_NESTED_MINT, nested_mint);
            tx.labeled(out, t::L_TO_TOKEN, destination);
            tx.labeled(out, t::L_OWNER_TOKEN, owner_ata);
            tx.labeled(out, t::L_OWNER_MINT, owner_mint);
            tx.labeled(out, t::L_WALLET, wallet);
            tx.labeled(out, t::L_TOKEN_PROGRAM, token_program);
            t::T_RECOVER_NESTED
        }
    }
}

fn compute_budget_text(ix: CbIx) -> (Text, u64) {
    match ix {
        CbIx::RequestHeapFrame(bytes) => (t::CB_HEAP, u64::from(bytes)),
        CbIx::SetComputeUnitLimit(units) => (t::CB_CU_LIMIT, u64::from(units)),
        CbIx::SetComputeUnitPrice(micro) => (t::CB_CU_PRICE, micro),
        CbIx::SetLoadedAccountsDataSizeLimit(bytes) => (t::CB_DATA_LIMIT, u64::from(bytes)),
    }
}

/// The instruction list (`0x0512`): per instruction its program, what it does, every account it
/// names and, when not interpreted, its accounts and data as they are.
fn instructions_text(tx: &Tx<'_>, wire: &SolWireTx, decoded: &[DecodedIx]) -> String {
    let lang = tx.lang;
    let message = &wire.message;
    let mut out: Vec<String> = Vec::new();
    for (index, ix) in decoded.iter().enumerate() {
        let Some((program, indices, data)) = message.instruction(index) else {
            continue;
        };
        let name = program_name(program).unwrap_or(tx.tr(t::UNKNOWN_PROGRAM));
        let mut lines: Vec<String> = Vec::new();
        let title: String = match ix {
            DecodedIx::System(system) => tx.tr(system_lines(tx, system, &mut lines)).to_owned(),
            DecodedIx::Token { ix: token, .. } => token_lines(tx, token, &mut lines),
            DecodedIx::Ata(ata) => tx.tr(ata_lines(tx, ata, &mut lines)).to_owned(),
            DecodedIx::ComputeBudget(cb) => {
                let (text, value) = compute_budget_text(*cb);
                format!("{}: {}", tx.tr(text), format_raw(value))
            }
            DecodedIx::Memo(memo) => {
                match core::str::from_utf8(memo) {
                    Ok(text) => lines.push(t::MEMO_TEXT.fill(lang, [&inline_value(lang, text)])),
                    Err(_) => lines.push(t::MEMO_HEX.fill(lang, [&hex_lines(memo)])),
                }
                tx.tr(t::T_MEMO).to_owned()
            }
            DecodedIx::Precompile { count } => t::T_PRECOMPILE.fill(lang, [&count.to_string()]),
            DecodedIx::Unknown { reason } => match reason {
                Some(reason) => t::T_UNKNOWN_REASON.fill(lang, [reason.get(lang)]),
                None => tx.tr(t::T_UNKNOWN).to_owned(),
            },
        };
        out.push(format!("{}. {name}: {title}", index.saturating_add(1)));
        if ix.is_opaque() || program_name(program).is_none() {
            tx.labeled(&mut out, t::L_PROGRAM, program);
        }
        out.extend(lines);
        if ix.is_opaque() {
            for (position, account) in indices.iter().enumerate() {
                let label = t::L_ACCOUNT_N.fill(lang, [&position.saturating_add(1).to_string()]);
                match tx.keys.get(usize::from(*account)) {
                    Some((address, _)) => tx.address(&mut out, &label, address),
                    None => {
                        out.push(t::ACCOUNT_UNRESOLVED.fill(lang, [&label, &account.to_string()]));
                    }
                }
            }
            out.push(t::DATA_BYTES.fill(lang, [&data.len().to_string()]));
            if !data.is_empty() {
                out.push(hex_lines(data));
            }
        }
    }
    if out.is_empty() {
        tx.tr(t::NO_INSTRUCTIONS).to_owned()
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
        let number = index.saturating_add(1).to_string();
        let label = if index == 0 {
            t::SIGNER_FEE_PAYER.fill(tx.lang, [&number])
        } else {
            t::SIGNER_N.fill(tx.lang, [&number])
        };
        tx.address(&mut out, &label, key);
        let state = if index == usize::from(ours) {
            t::SLOT_WALLET
        } else if signature.iter().all(|byte| *byte == 0) {
            if send {
                t::SLOT_MISSING_SEND
            } else {
                t::SLOT_MISSING
            }
        } else if crate::sol::keys::verify_strict(key.as_bytes(), &wire.message_bytes, signature) {
            t::SLOT_SITE_OK
        } else {
            t::SITE_SIGNATURE_BAD
        };
        out.push(tx.tr(state).to_owned());
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
                out.push(tx.tr(t::DEMOTED).to_owned());
            }
        }
    }
    if has_lookups && loaded.is_none() {
        out.push(tx.tr(t::WRITABLE_UNKNOWN).to_owned());
    }
    if out.is_empty() {
        tx.tr(t::NONE).to_owned()
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
            SolTxVersion::Legacy => tx.tr(t::NO_TABLES_LEGACY),
            SolTxVersion::V0 => tx.tr(t::NO_TABLES),
        }
        .to_owned();
    }
    let mut out: Vec<String> = Vec::new();
    let (mut writable, mut readonly) = (0_usize, 0_usize);
    for lookup in &message.lookups {
        let number = tx
            .tables
            .iter()
            .position(|table| *table == lookup.table)
            .map_or(0, |index| index.saturating_add(1));
        let label = t::TABLE_N.fill(tx.lang, [&number.to_string()]);
        tx.address(&mut out, &label, &lookup.table);
        if tables
            .iter()
            .any(|(address, table)| *address == lookup.table && table.is_deactivated())
        {
            out.push(tx.tr(t::TABLE_DEACTIVATED).to_owned());
        }
        let Some(loaded) = loaded else {
            continue;
        };
        for (kind, indices, list, at) in [
            (
                t::KIND_WRITE,
                &lookup.writable,
                &loaded.writable,
                &mut writable,
            ),
            (
                t::KIND_READ,
                &lookup.readonly,
                &loaded.readonly,
                &mut readonly,
            ),
        ] {
            for index in indices {
                if let Some(address) = list.get(*at) {
                    let label = t::LOOKUP_ENTRY.fill(tx.lang, [tx.tr(kind), &index.to_string()]);
                    tx.address(&mut out, &label, address);
                }
                *at = at.saturating_add(1);
            }
        }
    }
    if let Some(error) = error {
        out.push(t::UNRESOLVED_ERROR.fill(tx.lang, [&error.text_in(tx.lang)]));
    }
    out.join("\n")
}

/// The changes (`0x0515`), authority changes first. The SOL change includes the fee only when
/// the wallet pays it (`wallet_pays`, slot 0; spec/07 §20.7).
fn changes_text(tx: &Tx<'_>, list: Option<&[Change]>, wallet_pays: bool) -> String {
    let lang = tx.lang;
    let Some(list) = list else {
        return tx.tr(t::CHANGES_NO_SIM).to_owned();
    };
    if list.is_empty() {
        return tx.tr(t::CHANGES_NONE).to_owned();
    }
    let mut out: Vec<String> = Vec::new();
    for change in list {
        match change {
            Change::Sol { pre, post } => out.push(t::CHANGE_SOL.fill(
                lang,
                [
                    &delta(*pre, *post, 9),
                    &format_raw(*pre),
                    &format_raw(*post),
                    if wallet_pays {
                        tx.tr(t::FEE_INCLUDED)
                    } else {
                        ""
                    },
                ],
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
                        tx.symbol(mint).unwrap_or(tx.tr(t::TOKEN_FALLBACK))
                    ),
                    Some((decimals, false)) => t::CHANGE_TOKEN_RPC.fill(
                        lang,
                        [&delta(*pre, *post, *decimals), &decimals.to_string()],
                    ),
                    None => t::AMOUNT_RAW.fill(lang, [&delta(*pre, *post, 0)]),
                };
                let program = if *program2022 { " (Token-2022)" } else { "" };
                out.push(t::CHANGE_TOKEN.fill(lang, [program, &unit]));
                tx.labeled(&mut out, t::L_TOKEN_ACCOUNT, account);
                tx.address(&mut out, "mint", mint);
            }
            Change::Authority {
                account,
                what,
                before,
                after,
            } => {
                let text = match what {
                    AuthorityKind::Owner => t::AUTH_CHANGE_OWNER,
                    AuthorityKind::Delegate => t::AUTH_CHANGE_DELEGATE,
                    AuthorityKind::CloseAuthority => t::AUTH_CHANGE_CLOSE,
                    AuthorityKind::WalletOwnerProgram => t::AUTH_CHANGE_WALLET,
                };
                out.push(tx.tr(text).to_owned());
                tx.labeled(&mut out, t::L_ACCOUNT, account);
                option_line(&mut out, tx, t::L_BEFORE, before.as_ref());
                option_line(&mut out, tx, t::L_AFTER, after.as_ref());
            }
            Change::Closed { account } => tx.labeled(&mut out, t::L_CLOSED, account),
            Change::Created { account, mint } => {
                tx.labeled(&mut out, t::L_CREATED, account);
                if let Some(mint) = mint {
                    tx.labeled(&mut out, t::L_TOKEN_MINT, mint);
                }
            }
        }
    }
    out.join("\n")
}

fn sim_text(lang: Lang, sim: SimSummary, replaced: bool) -> String {
    let mut text = match sim {
        SimSummary::Ok { units } => t::SIM_OK.fill(lang, [&format_raw(units)]),
        SimSummary::Failed { err: code, .. } => {
            sol_text::SIM_FAILED.fill(lang, [err::text_in(code, lang)])
        }
        SimSummary::NoResult => t::SIM_NO_RESULT.get(lang).to_owned(),
    };
    if replaced {
        text.push('\n');
        text.push_str(t::SIM_REPLACED.get(lang));
    }
    text
}

/// `low` or `low–high` lamports (u128 shown saturated at `u64::MAX`).
fn fee_range_text(bounds: DappFeeBounds) -> String {
    let lamports = |fee: u128| format_raw(u64::try_from(fee).unwrap_or(u64::MAX));
    if bounds.low == bounds.high {
        format!("{} lamports", lamports(bounds.low))
    } else {
        format!(
            "{}–{} lamports",
            lamports(bounds.low),
            lamports(bounds.high)
        )
    }
}

/// The RPC value and the range computed from the message (spec/07 §20.4): both are shown, the
/// RPC value never replaces the computed one.
fn fee_text(
    tx: &Tx<'_>,
    rpc: Option<u64>,
    bounds: DappFeeBounds,
    payer: &SolAddress,
    cap: u64,
) -> String {
    let mut out = vec![match rpc {
        Some(fee) => format!("{} lamports (RPC getFeeForMessage)", format_raw(fee)),
        None => tx.tr(t::FEE_RPC_NONE).to_owned(),
    }];
    let computed = if bounds.rejected {
        t::FEE_REJECTED
    } else if bounds.low == bounds.high {
        t::FEE_EXACT
    } else {
        t::FEE_RANGE
    };
    out.push(computed.fill(tx.lang, [&fee_range_text(bounds)]));
    if *payer == tx.wallet {
        out.push(tx.tr(t::FEE_PAYER_ME).to_owned());
        out.push(t::FEE_CAP.fill(tx.lang, [&format_raw(cap)]));
    } else {
        tx.labeled(&mut out, t::FEE_PAYER_OTHER, payer);
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
                ) => t::X_EXTENSION.fill(tx.lang, [&tag.to_string()]),
                (
                    DecodedIx::Unknown {
                        reason: Some(reason),
                    },
                    Some(name),
                ) => {
                    format!("{name} — {}", tx.tr(*reason))
                }
                (
                    DecodedIx::Unknown {
                        reason: Some(reason),
                    },
                    None,
                ) => {
                    format!("{} — {}", program.to_base58(), tx.tr(*reason))
                }
                (_, Some(name)) => t::X_PROGRAM_NAMED.fill(tx.lang, [name, &program.to_base58()]),
                (_, None) => t::X_PROGRAM.fill(tx.lang, [&program.to_base58()]),
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
                causes.add(X04, Some(format!("{at}{}", tx.tr(t::X04_CAUSE))));
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
                causes.add(
                    X05,
                    Some(format!("{at}{}", authority_type_text(tx.lang, *kind))),
                );
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
                        "{at}{}",
                        t::X07_CAUSE.fill(tx.lang, [&destination.to_base58()])
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
    lang: Lang,
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
    let prefix = |instruction: Option<usize>| at(lang, index, count, instruction);
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
        causes.add(
            X01,
            Some(format!("{}{}", prefix(None), error.text_in(lang))),
        );
    }
    let table_order = alt::lookup_tables(message);
    for (address, table) in tables {
        if table.is_deactivated() && table_order.contains(address) {
            causes.add(
                X10,
                Some(format!(
                    "{}{}",
                    prefix(None),
                    t::X10_DEACTIVATED.fill(lang, [&address.to_base58()])
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
        lang,
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
                "{}{}",
                prefix(None),
                t::SITE_SIGNATURE_BAD.get(lang)
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
            Some(format!("{}{}", prefix(None), t::X01_NEED_ALL.get(lang))),
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
                Some(format!("{}{}", prefix(None), t::X01_NONCE_SEND.get(lang))),
            );
        }
    }
    if slot != 0 || foreign_signed {
        let mut parts = Vec::new();
        if slot != 0 {
            parts.push(t::X13_OTHER_PAYER.get(lang));
        }
        if foreign_signed {
            parts.push(t::X13_SITE_SIGNED.get(lang));
        }
        causes.add(X13, Some(format!("{}{}", prefix(None), parts.join(" · "))));
    }
    instruction_rules(&tx, &wire, &decoded, &prefix, causes);
    // Mint extensions (Token-2022 TLV).
    for mint in touched_mints(&tx, &decoded) {
        if facts.unread_mints.contains(&mint) {
            let text = format!(
                "{}{}",
                prefix(None),
                t::X12_UNREAD.fill(lang, [&mint.to_base58()])
            );
            causes.add(X12, Some(text.clone()));
            causes.add(X17, Some(text));
            continue;
        }
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
                sim_text(lang, item_facts.sim, false)
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
                    inline_value(lang, &known.label)
                )),
            );
        }
    }
    let bounds = dapp_fee_bounds(message);
    if message.account_count() > RUNTIME_ACCOUNT_LIMIT || bounds.rejected {
        causes.add(
            X18,
            (count > 1).then(|| prefix(None).trim_end_matches(": ").to_owned()),
        );
    }
    // Fee: the range computed from the message is exact with a limit; the RPC value is a
    // reference that may raise the fee checked against the cap but never lower it below the
    // computed maximum. 2026-11-13: before, an RPC value replaced the computed one, so an RPC
    // that under-reported the fee hid X14; then (same day) the computed minimum was the floor,
    // so inside a bracket (no limit, a Stake·Config·ALT·… instruction) an RPC answering the
    // minimum, or no answer, still hid up to 197,000 CU × price per such instruction. Both
    // rules only when the wallet pays.
    let payer = message.fee_payer().ok_or(DisplayError::InvalidText)?;
    if slot == 0 {
        let fee = item_facts.rpc_fee.map_or(0, u128::from).max(bounds.high);
        if fee > u128::from(facts.fee_cap) {
            let template = if bounds.low < bounds.high && fee == bounds.high {
                t::X14_CAUSE_MAX
            } else {
                t::X14_CAUSE
            };
            let text = template.fill(
                lang,
                [
                    &format_raw(u64::try_from(fee).unwrap_or(u64::MAX)),
                    &format_raw(facts.fee_cap),
                ],
            );
            causes.add(X14, Some(format!("{}{text}", prefix(None))));
        }
        if let Some(rpc) = item_facts.rpc_fee
            && !bounds.contains(u128::from(rpc))
        {
            causes.add(
                X20,
                Some(format!(
                    "{}{}",
                    prefix(None),
                    t::X20_CAUSE.fill(lang, [&format_raw(rpc), &fee_range_text(bounds)])
                )),
            );
        }
    }
    // Fields in the window's order: changes, fee, instructions, writable, signers, tables,
    // simulation, validity, audit, raw.
    let sub = if count > 1 {
        t::SUB_TX.fill(
            lang,
            [&index.saturating_add(1).to_string(), &count.to_string()],
        )
    } else {
        String::new()
    };
    let validity = if nonce {
        t::VALIDITY_NONCE.get(lang).to_owned()
    } else {
        let checked = if item_facts.blockhash_valid == Some(true) {
            t::BLOCKHASH_OK
        } else {
            t::BLOCKHASH_UNCHECKED
        };
        t::VALIDITY.fill(lang, [checked.get(lang)])
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
            fee_text(&tx, item_facts.rpc_fee, bounds, &payer, facts.fee_cap),
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
            sim_text(lang, item_facts.sim, item_facts.sim_replaced_blockhash),
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

fn title(lang: Lang, cluster: SolCluster, mode: SolTxMode, count: usize) -> String {
    let action = match (mode, count) {
        (SolTxMode::SignAndSend, _) => t::TITLE_SIGN_SEND.get(lang).to_owned(),
        (SolTxMode::SignOnly, 1) => t::TITLE_SIGN.get(lang).to_owned(),
        (SolTxMode::SignOnly, count) => t::TITLE_SIGN_N.fill(lang, [&count.to_string()]),
    };
    let network = cluster.display_name_in(lang);
    let full = format!("[{network}] {action}");
    if full.len() <= MAX_TITLE_BYTES {
        full
    } else {
        format!("[{network}] {}", t::TITLE_SIGN.get(lang))
    }
}

fn send_options_text(lang: Lang, options: &SolSendOptions) -> String {
    let preflight = if options.skip_preflight {
        t::PREFLIGHT_SKIP.get(lang).to_owned()
    } else {
        t::PREFLIGHT.fill(
            lang,
            [options
                .preflight_commitment
                .map_or("confirmed", super::SolCommitment::as_str)],
        )
    };
    let min = options.min_context_slot.map_or_else(
        || t::MIN_SLOT_NONE.get(lang).to_owned(),
        |slot| t::MIN_SLOT.fill(lang, [&format_raw(slot)]),
    );
    format!("{preflight}\n{min}\n{}", t::RESEND.get(lang))
}

/// Builds the approval draft of a dApp transaction request (spec/07 §20.6) with every fixed text
/// in `lang`.
///
/// # Errors
///
/// [`DisplayError`]: a transaction that does not parse, whose key is not a signer, or whose
/// facts are missing (the app validated all of this first: defensive), or a display bound.
pub fn build_sol_tx_request(
    lang: Lang,
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
            sol_text::NETWORK_GENESIS.fill(
                lang,
                [
                    request.cluster.display_name_in(lang),
                    &crate::codec::base58::base58_encode(&request.cluster.genesis()),
                ],
            ),
        )?,
        DisplayField::new(
            FieldKey::ACCOUNT,
            "",
            format!(
                "{}\n{}\n{}",
                inline_value(lang, &request.label),
                request.source.path_text_in(lang),
                grouped(&address)
            ),
        )?,
        DisplayField::new(
            FieldKey::SOL_TX_SUMMARY,
            "",
            match request.mode {
                SolTxMode::SignOnly => t::SUMMARY_SIGN_ONLY.fill(lang, [&count.to_string()]),
                SolTxMode::SignAndSend => t::SUMMARY_SEND.get(lang).to_owned(),
            },
        )?,
    ];
    if request.mode == SolTxMode::SignAndSend {
        fields.push(DisplayField::new(
            FieldKey::SOL_TX_SEND_OPTIONS,
            "",
            send_options_text(lang, &request.options),
        )?);
    }
    let mut causes = Causes::default();
    if request.source.needs_move_rule() {
        causes.add(X01, Some(t::X01_SCAN.get(lang).to_owned()));
    }
    if request.mode == SolTxMode::SignOnly {
        causes.add(X11, None);
    }
    let mut items = Vec::with_capacity(count);
    for (index, item_facts) in facts.items.iter().enumerate() {
        let built = build_item(lang, request, facts, item_facts, index, &mut causes)?;
        items.push(built.item);
        fields.extend(built.fields);
    }
    let display = ApprovalDisplay::new(
        lang,
        title(lang, request.cluster, request.mode, count),
        fields,
        causes.into_warnings(lang),
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
