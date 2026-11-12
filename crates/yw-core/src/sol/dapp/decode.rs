//! Instruction decoders for dApp transactions (spec/07 §20.4): System, Token and Token-2022,
//! Associated Token Account, `ComputeBudget`, Memo and the signature precompiles. A decoder only
//! accepts the exact data length and at least the accounts the program reads; anything else is
//! `Unknown` with a reason and is shown raw, never guessed.
#![deny(clippy::indexing_slicing)]

use super::alt::KeyRole;
use super::parse::SolTxMessage;
use crate::sol::address::{
    ATA_PROGRAM, COMPUTE_BUDGET_PROGRAM, ED25519_PRECOMPILE, MEMO_PROGRAM_V1, MEMO_PROGRAM_V2,
    SECP256K1_PRECOMPILE, SECP256R1_PRECOMPILE, SYSTEM_PROGRAM, SolAddress, TOKEN_2022_PROGRAM,
    TOKEN_PROGRAM,
};
use crate::sol::pda::{MAX_SEED_LEN, associated_token_address};

/// `Unknown` reason: the data length, tag or account count does not fit the program.
pub const MALFORMED: &str = "형식이 맞지 않음";
/// `Unknown` reason: an ATA instruction whose token account is not the derived address.
pub const ATA_MISMATCH: &str = "ATA 주소가 유도값과 다릅니다";
/// `Unknown` reason: an account comes from a lookup table that could not be resolved.
pub const UNRESOLVED: &str = "조회 테이블을 해석하지 못함";

/// A decoded instruction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DecodedIx {
    /// System program.
    System(SystemIx),
    /// Token or Token-2022.
    Token {
        /// The Token-2022 program.
        program2022: bool,
        /// The instruction.
        ix: TokenIx,
    },
    /// Associated Token Account program (addresses checked against their derivation).
    Ata(AtaIx),
    /// `ComputeBudget` program.
    ComputeBudget(CbIx),
    /// Memo v1 or v2: the raw memo bytes (text or hex is the display's choice).
    Memo(Vec<u8>),
    /// Ed25519, Secp256k1 or Secp256r1 precompile: the signatures it verifies.
    Precompile {
        /// `data[0]`.
        count: u8,
    },
    /// Not decoded: shown raw with X02. `None` for a program the wallet does not interpret.
    Unknown {
        /// Why a known program's instruction was not decoded.
        reason: Option<&'static str>,
    },
}

impl DecodedIx {
    /// Whether the wallet cannot say what the instruction does (X02): every `Unknown` and every
    /// Token-2022 extension instruction.
    #[must_use]
    pub const fn is_opaque(&self) -> bool {
        matches!(
            self,
            Self::Unknown { .. }
                | Self::Token {
                    ix: TokenIx::Extension { .. },
                    ..
                }
        )
    }

    /// The mint a token or ATA instruction names among its accounts (the mints the app reads
    /// for the Token-2022 extension rules, spec/07 §20.6). `Transfer` and `Approve` name none:
    /// their mint is the pre-state of the source account.
    #[must_use]
    pub const fn named_mint(&self) -> Option<SolAddress> {
        match self {
            Self::Token { ix, .. } => ix.named_mint(),
            Self::Ata(AtaIx::Create { mint, .. }) => Some(*mint),
            _ => None,
        }
    }
}

/// System program instructions (u32 LE tag, bincode layout).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SystemIx {
    /// 0.
    CreateAccount {
        /// Funding account.
        from: SolAddress,
        /// New account.
        to: SolAddress,
        /// Lamports moved.
        lamports: u64,
        /// Data size.
        space: u64,
        /// Owner program of the new account.
        owner: SolAddress,
    },
    /// 1.
    Assign {
        /// Account whose owner program changes.
        account: SolAddress,
        /// New owner program.
        owner: SolAddress,
    },
    /// 2.
    Transfer {
        /// Source.
        from: SolAddress,
        /// Destination.
        to: SolAddress,
        /// Lamports.
        lamports: u64,
    },
    /// 3.
    CreateAccountWithSeed {
        /// Funding account.
        from: SolAddress,
        /// New account.
        to: SolAddress,
        /// Base of the derivation.
        base: SolAddress,
        /// Seed text.
        seed: String,
        /// Lamports moved.
        lamports: u64,
        /// Data size.
        space: u64,
        /// Owner program of the new account.
        owner: SolAddress,
    },
    /// 4 (the first four data bytes; the runtime ignores any after them).
    AdvanceNonce {
        /// Nonce account.
        nonce: SolAddress,
        /// Nonce authority.
        authority: SolAddress,
        /// Bytes after the tag (shown as hex).
        extra: Vec<u8>,
    },
    /// 5.
    WithdrawNonce {
        /// Nonce account.
        nonce: SolAddress,
        /// Destination.
        to: SolAddress,
        /// Nonce authority.
        authority: SolAddress,
        /// Lamports.
        lamports: u64,
    },
    /// 6.
    InitializeNonce {
        /// Nonce account.
        nonce: SolAddress,
        /// Authority set.
        authority: SolAddress,
    },
    /// 7.
    AuthorizeNonce {
        /// Nonce account.
        nonce: SolAddress,
        /// Current authority.
        authority: SolAddress,
        /// New authority.
        new_authority: SolAddress,
    },
    /// 8.
    Allocate {
        /// Account.
        account: SolAddress,
        /// Data size.
        space: u64,
    },
    /// 9.
    AllocateWithSeed {
        /// Account.
        account: SolAddress,
        /// Base of the derivation.
        base: SolAddress,
        /// Seed text.
        seed: String,
        /// Data size.
        space: u64,
        /// Owner program.
        owner: SolAddress,
    },
    /// 10.
    AssignWithSeed {
        /// Account.
        account: SolAddress,
        /// Base of the derivation.
        base: SolAddress,
        /// Seed text.
        seed: String,
        /// New owner program.
        owner: SolAddress,
    },
    /// 11.
    TransferWithSeed {
        /// Source (derived from `base`).
        from: SolAddress,
        /// Base of the derivation (signs).
        base: SolAddress,
        /// Destination.
        to: SolAddress,
        /// Lamports.
        lamports: u64,
        /// Seed text.
        seed: String,
        /// Owner program of the source derivation.
        owner: SolAddress,
    },
    /// 12.
    UpgradeNonce {
        /// Nonce account.
        nonce: SolAddress,
    },
}

/// `SetAuthority` authority types the wallet decodes (classic Token's set).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthorityType {
    /// 0.
    MintTokens,
    /// 1.
    FreezeAccount,
    /// 2: who owns a token account.
    AccountOwner,
    /// 3: who may close a token account.
    CloseAccount,
}

/// Token and Token-2022 instructions (u8 tag; spec/07 §20.4 lists them).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TokenIx {
    /// 0.
    InitializeMint {
        /// Mint.
        mint: SolAddress,
        /// Decimals.
        decimals: u8,
        /// Mint authority.
        mint_authority: SolAddress,
        /// Freeze authority.
        freeze_authority: Option<SolAddress>,
    },
    /// 1.
    InitializeAccount {
        /// Token account.
        account: SolAddress,
        /// Mint.
        mint: SolAddress,
        /// Owner (an account).
        owner: SolAddress,
    },
    /// 2.
    InitializeMultisig {
        /// Multisig account.
        multisig: SolAddress,
        /// Signatures required.
        m: u8,
    },
    /// 3.
    Transfer {
        /// Source token account.
        source: SolAddress,
        /// Destination token account.
        destination: SolAddress,
        /// Owner or delegate.
        authority: SolAddress,
        /// Raw amount.
        amount: u64,
    },
    /// 4.
    Approve {
        /// Token account.
        source: SolAddress,
        /// Delegate.
        delegate: SolAddress,
        /// Owner.
        owner: SolAddress,
        /// Raw amount.
        amount: u64,
    },
    /// 5.
    Revoke {
        /// Token account.
        source: SolAddress,
        /// Owner.
        owner: SolAddress,
    },
    /// 6.
    SetAuthority {
        /// Mint or token account.
        account: SolAddress,
        /// Current authority.
        current: SolAddress,
        /// Which authority.
        kind: AuthorityType,
        /// New authority (`None` removes it).
        new: Option<SolAddress>,
    },
    /// 7.
    MintTo {
        /// Mint.
        mint: SolAddress,
        /// Destination token account.
        destination: SolAddress,
        /// Mint authority.
        authority: SolAddress,
        /// Raw amount.
        amount: u64,
    },
    /// 8.
    Burn {
        /// Token account.
        account: SolAddress,
        /// Mint.
        mint: SolAddress,
        /// Owner or delegate.
        authority: SolAddress,
        /// Raw amount.
        amount: u64,
    },
    /// 9.
    CloseAccount {
        /// Token account.
        account: SolAddress,
        /// Receives the lamports.
        destination: SolAddress,
        /// Owner or close authority.
        authority: SolAddress,
    },
    /// 10.
    FreezeAccount {
        /// Token account.
        account: SolAddress,
        /// Mint.
        mint: SolAddress,
        /// Freeze authority.
        authority: SolAddress,
    },
    /// 11.
    ThawAccount {
        /// Token account.
        account: SolAddress,
        /// Mint.
        mint: SolAddress,
        /// Freeze authority.
        authority: SolAddress,
    },
    /// 12.
    TransferChecked {
        /// Source token account.
        source: SolAddress,
        /// Mint.
        mint: SolAddress,
        /// Destination token account.
        destination: SolAddress,
        /// Owner or delegate.
        authority: SolAddress,
        /// Raw amount.
        amount: u64,
        /// Decimals the signer expects.
        decimals: u8,
    },
    /// 13.
    ApproveChecked {
        /// Token account.
        source: SolAddress,
        /// Mint.
        mint: SolAddress,
        /// Delegate.
        delegate: SolAddress,
        /// Owner.
        owner: SolAddress,
        /// Raw amount.
        amount: u64,
        /// Decimals.
        decimals: u8,
    },
    /// 14.
    MintToChecked {
        /// Mint.
        mint: SolAddress,
        /// Destination token account.
        destination: SolAddress,
        /// Mint authority.
        authority: SolAddress,
        /// Raw amount.
        amount: u64,
        /// Decimals.
        decimals: u8,
    },
    /// 15.
    BurnChecked {
        /// Token account.
        account: SolAddress,
        /// Mint.
        mint: SolAddress,
        /// Owner or delegate.
        authority: SolAddress,
        /// Raw amount.
        amount: u64,
        /// Decimals.
        decimals: u8,
    },
    /// 16.
    InitializeAccount2 {
        /// Token account.
        account: SolAddress,
        /// Mint.
        mint: SolAddress,
        /// Owner (from data).
        owner: SolAddress,
    },
    /// 17.
    SyncNative {
        /// Wrapped-SOL token account.
        account: SolAddress,
    },
    /// 18.
    InitializeAccount3 {
        /// Token account.
        account: SolAddress,
        /// Mint.
        mint: SolAddress,
        /// Owner (from data).
        owner: SolAddress,
    },
    /// 19.
    InitializeMultisig2 {
        /// Multisig account.
        multisig: SolAddress,
        /// Signatures required.
        m: u8,
    },
    /// 20.
    InitializeMint2 {
        /// Mint.
        mint: SolAddress,
        /// Decimals.
        decimals: u8,
        /// Mint authority.
        mint_authority: SolAddress,
        /// Freeze authority.
        freeze_authority: Option<SolAddress>,
    },
    /// 21 (Token-2022 may list extension types).
    GetAccountDataSize {
        /// Mint.
        mint: SolAddress,
        /// Extension types (Token-2022 only).
        extensions: Vec<u16>,
    },
    /// 22.
    InitializeImmutableOwner {
        /// Token account.
        account: SolAddress,
    },
    /// 23.
    AmountToUiAmount {
        /// Mint.
        mint: SolAddress,
        /// Raw amount.
        amount: u64,
    },
    /// 24.
    UiAmountToAmount {
        /// Mint.
        mint: SolAddress,
        /// Amount text.
        ui_amount: String,
    },
    /// Token-2022 tag 25 or above: an extension instruction, not decoded (X02).
    Extension {
        /// The tag.
        tag: u8,
    },
}

impl TokenIx {
    /// The instruction tag.
    #[must_use]
    pub const fn tag(&self) -> u8 {
        match self {
            Self::InitializeMint { .. } => 0,
            Self::InitializeAccount { .. } => 1,
            Self::InitializeMultisig { .. } => 2,
            Self::Transfer { .. } => 3,
            Self::Approve { .. } => 4,
            Self::Revoke { .. } => 5,
            Self::SetAuthority { .. } => 6,
            Self::MintTo { .. } => 7,
            Self::Burn { .. } => 8,
            Self::CloseAccount { .. } => 9,
            Self::FreezeAccount { .. } => 10,
            Self::ThawAccount { .. } => 11,
            Self::TransferChecked { .. } => 12,
            Self::ApproveChecked { .. } => 13,
            Self::MintToChecked { .. } => 14,
            Self::BurnChecked { .. } => 15,
            Self::InitializeAccount2 { .. } => 16,
            Self::SyncNative { .. } => 17,
            Self::InitializeAccount3 { .. } => 18,
            Self::InitializeMultisig2 { .. } => 19,
            Self::InitializeMint2 { .. } => 20,
            Self::GetAccountDataSize { .. } => 21,
            Self::InitializeImmutableOwner { .. } => 22,
            Self::AmountToUiAmount { .. } => 23,
            Self::UiAmountToAmount { .. } => 24,
            Self::Extension { tag } => *tag,
        }
    }

    /// The mint account the instruction names ([`DecodedIx::named_mint`]).
    #[must_use]
    pub const fn named_mint(&self) -> Option<SolAddress> {
        match self {
            Self::InitializeMint { mint, .. }
            | Self::InitializeMint2 { mint, .. }
            | Self::InitializeAccount { mint, .. }
            | Self::InitializeAccount2 { mint, .. }
            | Self::InitializeAccount3 { mint, .. }
            | Self::MintTo { mint, .. }
            | Self::Burn { mint, .. }
            | Self::FreezeAccount { mint, .. }
            | Self::ThawAccount { mint, .. }
            | Self::TransferChecked { mint, .. }
            | Self::ApproveChecked { mint, .. }
            | Self::MintToChecked { mint, .. }
            | Self::BurnChecked { mint, .. } => Some(*mint),
            _ => None,
        }
    }
}

/// Associated Token Account instructions (every address matches its derivation).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AtaIx {
    /// Data empty or `[0]` (`Create`), `[1]` (`CreateIdempotent`).
    Create {
        /// Pays the rent.
        payer: SolAddress,
        /// The associated token account.
        ata: SolAddress,
        /// Its owner.
        wallet: SolAddress,
        /// Mint.
        mint: SolAddress,
        /// Token or Token-2022.
        token_program: SolAddress,
        /// `CreateIdempotent`.
        idempotent: bool,
    },
    /// `[2]`: moves tokens out of an ATA owned by another ATA of the same wallet.
    RecoverNested {
        /// `ATA(owner_ata, nested_mint)`.
        nested: SolAddress,
        /// Mint of the nested account.
        nested_mint: SolAddress,
        /// `ATA(wallet, nested_mint)`.
        destination: SolAddress,
        /// `ATA(wallet, owner_mint)`.
        owner_ata: SolAddress,
        /// Mint of the owner ATA.
        owner_mint: SolAddress,
        /// The wallet (signs).
        wallet: SolAddress,
        /// Token or Token-2022.
        token_program: SolAddress,
    },
}

/// `ComputeBudget` instructions (u8 tag).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CbIx {
    /// 1: heap bytes.
    RequestHeapFrame(u32),
    /// 2: compute-unit limit.
    SetComputeUnitLimit(u32),
    /// 3: micro-lamports per compute unit.
    SetComputeUnitPrice(u64),
    /// 4: loaded account data limit (bytes).
    SetLoadedAccountsDataSizeLimit(u32),
}

/// A little-endian cursor over instruction data.
struct Data<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Data<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, at: 0 }
    }

    fn take(&mut self, len: usize) -> Option<&'a [u8]> {
        let end = self.at.checked_add(len)?;
        let slice = self.bytes.get(self.at..end)?;
        self.at = end;
        Some(slice)
    }

    fn array<const N: usize>(&mut self) -> Option<[u8; N]> {
        self.take(N)?.try_into().ok()
    }

    fn u8(&mut self) -> Option<u8> {
        self.array::<1>().map(|[byte]| byte)
    }

    fn u32(&mut self) -> Option<u32> {
        self.array::<4>().map(u32::from_le_bytes)
    }

    fn u64(&mut self) -> Option<u64> {
        self.array::<8>().map(u64::from_le_bytes)
    }

    fn key(&mut self) -> Option<SolAddress> {
        self.array::<32>().map(SolAddress::from_bytes)
    }

    /// bincode `String` (u64 LE length + UTF-8) of at most 32 bytes, as a PDA seed.
    fn seed(&mut self) -> Option<String> {
        let len = usize::try_from(self.u64()?).ok()?;
        if len > MAX_SEED_LEN {
            return None;
        }
        String::from_utf8(self.take(len)?.to_vec()).ok()
    }

    /// Token `COption<Pubkey>` in instruction data: `0` or `1 ‖ 32 bytes`. As the last field, `0`
    /// may also be followed by exactly 32 zero bytes: @solana/spl-token writes the option at a
    /// fixed width, and the programs ignore what follows a `0` (spec/07 §20.4).
    fn option_key(&mut self) -> Result<Option<SolAddress>, ()> {
        match self.u8().ok_or(())? {
            0 => {
                let rest = self.bytes.get(self.at..).unwrap_or(&[]);
                if rest.len() == 32 && rest.iter().all(|&byte| byte == 0) {
                    self.at = self.bytes.len();
                }
                Ok(None)
            }
            1 => self.key().map(Some).ok_or(()),
            _ => Err(()),
        }
    }

    fn rest(&mut self) -> &'a [u8] {
        let rest = self.bytes.get(self.at..).unwrap_or(&[]);
        self.at = self.bytes.len();
        rest
    }

    /// `value` when every byte was read.
    fn end<T>(&self, value: T) -> Option<T> {
        (self.at == self.bytes.len()).then_some(value)
    }
}

/// The first `N` accounts (more are allowed: multisig signers, optional sysvars).
fn first<const N: usize>(accounts: &[SolAddress]) -> Option<[SolAddress; N]> {
    accounts.get(..N)?.try_into().ok()
}

/// Decodes one instruction of `program` with its accounts (resolved, in instruction order) and
/// data.
#[must_use]
pub fn decode(program: &SolAddress, accounts: &[SolAddress], data: &[u8]) -> DecodedIx {
    let malformed = DecodedIx::Unknown {
        reason: Some(MALFORMED),
    };
    if *program == SYSTEM_PROGRAM {
        system(accounts, data).map_or(malformed, DecodedIx::System)
    } else if *program == TOKEN_PROGRAM || *program == TOKEN_2022_PROGRAM {
        let program2022 = *program == TOKEN_2022_PROGRAM;
        token(program2022, accounts, data)
            .map_or(malformed, |ix| DecodedIx::Token { program2022, ix })
    } else if *program == ATA_PROGRAM {
        ata(accounts, data)
    } else if *program == COMPUTE_BUDGET_PROGRAM {
        compute_budget(data).map_or(malformed, DecodedIx::ComputeBudget)
    } else if *program == MEMO_PROGRAM_V1 || *program == MEMO_PROGRAM_V2 {
        DecodedIx::Memo(data.to_vec())
    } else if [
        ED25519_PRECOMPILE,
        SECP256K1_PRECOMPILE,
        SECP256R1_PRECOMPILE,
    ]
    .contains(program)
    {
        precompile(program, data).map_or(malformed, |count| DecodedIx::Precompile { count })
    } else {
        DecodedIx::Unknown { reason: None }
    }
}

/// Decodes every instruction of `message` against `keys` (`alt::full_keys`). An instruction
/// that names an account the keys do not cover (lookups unresolved) is `Unknown(UNRESOLVED)`.
#[must_use]
pub fn decode_message(message: &SolTxMessage, keys: &[(SolAddress, KeyRole)]) -> Vec<DecodedIx> {
    (0..message.instruction_count())
        .filter_map(|index| message.instruction(index))
        .map(|(program, indices, data)| {
            let accounts: Option<Vec<SolAddress>> = indices
                .iter()
                .map(|index| keys.get(usize::from(*index)).map(|(key, _)| *key))
                .collect();
            accounts.map_or(
                DecodedIx::Unknown {
                    reason: Some(UNRESOLVED),
                },
                |accounts| decode(program, &accounts, data),
            )
        })
        .collect()
}

#[expect(
    clippy::too_many_lines,
    reason = "one arm per System tag, in tag order like the spec/07 §20.4 list"
)]
fn system(accounts: &[SolAddress], data: &[u8]) -> Option<SystemIx> {
    let mut d = Data::new(data);
    let ix = match d.u32()? {
        0 => {
            let [from, to] = first(accounts)?;
            SystemIx::CreateAccount {
                from,
                to,
                lamports: d.u64()?,
                space: d.u64()?,
                owner: d.key()?,
            }
        }
        1 => {
            let [account] = first(accounts)?;
            SystemIx::Assign {
                account,
                owner: d.key()?,
            }
        }
        2 => {
            let [from, to] = first(accounts)?;
            SystemIx::Transfer {
                from,
                to,
                lamports: d.u64()?,
            }
        }
        3 => {
            let [from, to] = first(accounts)?;
            SystemIx::CreateAccountWithSeed {
                from,
                to,
                base: d.key()?,
                seed: d.seed()?,
                lamports: d.u64()?,
                space: d.u64()?,
                owner: d.key()?,
            }
        }
        4 => {
            // Accounts: nonce, RecentBlockhashes sysvar, authority. Bytes after the tag are
            // ignored by the runtime, so they are kept for display instead of refused.
            let [nonce, _, authority] = first(accounts)?;
            SystemIx::AdvanceNonce {
                nonce,
                authority,
                extra: d.rest().to_vec(),
            }
        }
        5 => {
            // Accounts: nonce, to, RecentBlockhashes, Rent, authority.
            let [nonce, to, _, _, authority] = first(accounts)?;
            SystemIx::WithdrawNonce {
                nonce,
                to,
                authority,
                lamports: d.u64()?,
            }
        }
        6 => {
            // Accounts: nonce, RecentBlockhashes, Rent.
            let [nonce, _, _] = first(accounts)?;
            SystemIx::InitializeNonce {
                nonce,
                authority: d.key()?,
            }
        }
        7 => {
            let [nonce, authority] = first(accounts)?;
            SystemIx::AuthorizeNonce {
                nonce,
                authority,
                new_authority: d.key()?,
            }
        }
        8 => {
            let [account] = first(accounts)?;
            SystemIx::Allocate {
                account,
                space: d.u64()?,
            }
        }
        9 => {
            let [account, _] = first(accounts)?;
            SystemIx::AllocateWithSeed {
                account,
                base: d.key()?,
                seed: d.seed()?,
                space: d.u64()?,
                owner: d.key()?,
            }
        }
        10 => {
            let [account, _] = first(accounts)?;
            SystemIx::AssignWithSeed {
                account,
                base: d.key()?,
                seed: d.seed()?,
                owner: d.key()?,
            }
        }
        11 => {
            let [from, base, to] = first(accounts)?;
            SystemIx::TransferWithSeed {
                from,
                base,
                to,
                lamports: d.u64()?,
                seed: d.seed()?,
                owner: d.key()?,
            }
        }
        12 => {
            let [nonce] = first(accounts)?;
            SystemIx::UpgradeNonce { nonce }
        }
        _ => return None,
    };
    d.end(ix)
}

#[expect(
    clippy::too_many_lines,
    reason = "one arm per Token tag, in tag order like the spec/07 §20.4 list"
)]
fn token(program2022: bool, accounts: &[SolAddress], data: &[u8]) -> Option<TokenIx> {
    let mut d = Data::new(data);
    let ix = match d.u8()? {
        0 => {
            let [mint, _] = first(accounts)?;
            TokenIx::InitializeMint {
                mint,
                decimals: d.u8()?,
                mint_authority: d.key()?,
                freeze_authority: d.option_key().ok()?,
            }
        }
        1 => {
            let [account, mint, owner, _] = first(accounts)?;
            TokenIx::InitializeAccount {
                account,
                mint,
                owner,
            }
        }
        2 => {
            let [multisig, _, _] = first(accounts)?;
            TokenIx::InitializeMultisig {
                multisig,
                m: d.u8()?,
            }
        }
        3 => {
            let [source, destination, authority] = first(accounts)?;
            TokenIx::Transfer {
                source,
                destination,
                authority,
                amount: d.u64()?,
            }
        }
        4 => {
            let [source, delegate, owner] = first(accounts)?;
            TokenIx::Approve {
                source,
                delegate,
                owner,
                amount: d.u64()?,
            }
        }
        5 => {
            let [source, owner] = first(accounts)?;
            TokenIx::Revoke { source, owner }
        }
        6 => {
            let [account, current] = first(accounts)?;
            let kind = match d.u8()? {
                0 => AuthorityType::MintTokens,
                1 => AuthorityType::FreezeAccount,
                2 => AuthorityType::AccountOwner,
                3 => AuthorityType::CloseAccount,
                _ => return None,
            };
            TokenIx::SetAuthority {
                account,
                current,
                kind,
                new: d.option_key().ok()?,
            }
        }
        7 => {
            let [mint, destination, authority] = first(accounts)?;
            TokenIx::MintTo {
                mint,
                destination,
                authority,
                amount: d.u64()?,
            }
        }
        8 => {
            let [account, mint, authority] = first(accounts)?;
            TokenIx::Burn {
                account,
                mint,
                authority,
                amount: d.u64()?,
            }
        }
        9 => {
            let [account, destination, authority] = first(accounts)?;
            TokenIx::CloseAccount {
                account,
                destination,
                authority,
            }
        }
        10 => {
            let [account, mint, authority] = first(accounts)?;
            TokenIx::FreezeAccount {
                account,
                mint,
                authority,
            }
        }
        11 => {
            let [account, mint, authority] = first(accounts)?;
            TokenIx::ThawAccount {
                account,
                mint,
                authority,
            }
        }
        12 => {
            let [source, mint, destination, authority] = first(accounts)?;
            TokenIx::TransferChecked {
                source,
                mint,
                destination,
                authority,
                amount: d.u64()?,
                decimals: d.u8()?,
            }
        }
        13 => {
            let [source, mint, delegate, owner] = first(accounts)?;
            TokenIx::ApproveChecked {
                source,
                mint,
                delegate,
                owner,
                amount: d.u64()?,
                decimals: d.u8()?,
            }
        }
        14 => {
            let [mint, destination, authority] = first(accounts)?;
            TokenIx::MintToChecked {
                mint,
                destination,
                authority,
                amount: d.u64()?,
                decimals: d.u8()?,
            }
        }
        15 => {
            let [account, mint, authority] = first(accounts)?;
            TokenIx::BurnChecked {
                account,
                mint,
                authority,
                amount: d.u64()?,
                decimals: d.u8()?,
            }
        }
        16 => {
            let [account, mint, _] = first(accounts)?;
            TokenIx::InitializeAccount2 {
                account,
                mint,
                owner: d.key()?,
            }
        }
        17 => {
            let [account] = first(accounts)?;
            TokenIx::SyncNative { account }
        }
        18 => {
            let [account, mint] = first(accounts)?;
            TokenIx::InitializeAccount3 {
                account,
                mint,
                owner: d.key()?,
            }
        }
        19 => {
            let [multisig, _] = first(accounts)?;
            TokenIx::InitializeMultisig2 {
                multisig,
                m: d.u8()?,
            }
        }
        20 => {
            let [mint] = first(accounts)?;
            TokenIx::InitializeMint2 {
                mint,
                decimals: d.u8()?,
                mint_authority: d.key()?,
                freeze_authority: d.option_key().ok()?,
            }
        }
        21 => {
            // Classic Token takes no data; Token-2022 may list u16 LE extension types.
            let [mint] = first(accounts)?;
            let rest = d.rest();
            if (!program2022 && !rest.is_empty()) || !rest.len().is_multiple_of(2) {
                return None;
            }
            TokenIx::GetAccountDataSize {
                mint,
                extensions: rest
                    .chunks_exact(2)
                    .filter_map(|pair| <[u8; 2]>::try_from(pair).ok())
                    .map(u16::from_le_bytes)
                    .collect(),
            }
        }
        22 => {
            let [account] = first(accounts)?;
            TokenIx::InitializeImmutableOwner { account }
        }
        23 => {
            let [mint] = first(accounts)?;
            TokenIx::AmountToUiAmount {
                mint,
                amount: d.u64()?,
            }
        }
        24 => {
            let [mint] = first(accounts)?;
            TokenIx::UiAmountToAmount {
                mint,
                ui_amount: String::from_utf8(d.rest().to_vec()).ok()?,
            }
        }
        tag if program2022 => {
            // Extensions (transfer fee, confidential transfer, CPI guard, …): raw, X02.
            d.rest();
            TokenIx::Extension { tag }
        }
        _ => return None,
    };
    d.end(ix)
}

fn derived(
    wallet: &SolAddress,
    token_program: &SolAddress,
    mint: &SolAddress,
) -> Option<SolAddress> {
    associated_token_address(wallet, token_program, mint)
        .ok()
        .map(|(address, _)| address)
}

/// ATA instructions: only with Token or Token-2022 and the System program in place, and only
/// when every associated address equals its local derivation (else `ATA_MISMATCH`, raw + X02).
fn ata(accounts: &[SolAddress], data: &[u8]) -> DecodedIx {
    let malformed = DecodedIx::Unknown {
        reason: Some(MALFORMED),
    };
    let mismatch = DecodedIx::Unknown {
        reason: Some(ATA_MISMATCH),
    };
    let token_ok =
        |program: &SolAddress| *program == TOKEN_PROGRAM || *program == TOKEN_2022_PROGRAM;
    match data {
        [] | [0 | 1] => {
            let Some([payer, ata, wallet, mint, system, token_program]) = first(accounts) else {
                return malformed;
            };
            if system != SYSTEM_PROGRAM || !token_ok(&token_program) {
                return malformed;
            }
            if derived(&wallet, &token_program, &mint) != Some(ata) {
                return mismatch;
            }
            DecodedIx::Ata(AtaIx::Create {
                payer,
                ata,
                wallet,
                mint,
                token_program,
                idempotent: data == [1],
            })
        }
        [2] => {
            let Some(
                [
                    nested,
                    nested_mint,
                    destination,
                    owner_ata,
                    owner_mint,
                    wallet,
                    token_program,
                ],
            ) = first(accounts)
            else {
                return malformed;
            };
            if !token_ok(&token_program) {
                return malformed;
            }
            if derived(&owner_ata, &token_program, &nested_mint) != Some(nested)
                || derived(&wallet, &token_program, &nested_mint) != Some(destination)
                || derived(&wallet, &token_program, &owner_mint) != Some(owner_ata)
            {
                return mismatch;
            }
            DecodedIx::Ata(AtaIx::RecoverNested {
                nested,
                nested_mint,
                destination,
                owner_ata,
                owner_mint,
                wallet,
                token_program,
            })
        }
        _ => malformed,
    }
}

fn compute_budget(data: &[u8]) -> Option<CbIx> {
    let mut d = Data::new(data);
    let ix = match d.u8()? {
        1 => CbIx::RequestHeapFrame(d.u32()?),
        2 => CbIx::SetComputeUnitLimit(d.u32()?),
        3 => CbIx::SetComputeUnitPrice(d.u64()?),
        4 => CbIx::SetLoadedAccountsDataSizeLimit(d.u32()?),
        _ => return None,
    };
    d.end(ix)
}

/// The signature count of a precompile instruction whose data holds the whole offsets table
/// (Ed25519 and Secp256r1: `2 + 14n` bytes; Secp256k1: `1 + 11n`).
fn precompile(program: &SolAddress, data: &[u8]) -> Option<u8> {
    let count = *data.first()?;
    let (start, entry) = if *program == SECP256K1_PRECOMPILE {
        (1_usize, 11_usize)
    } else {
        (2, 14)
    };
    let table = start.checked_add(entry.checked_mul(usize::from(count))?)?;
    (data.len() >= table).then_some(count)
}
