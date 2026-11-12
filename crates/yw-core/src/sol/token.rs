//! SPL account data (spec/07 §15.4, v1.1): the raw classic-Token mint (82 bytes) and token
//! account (165 bytes) layouts as returned by `getAccountInfo` (`base64`, no `jsonParsed`), and
//! their classification against the pinned allowlist. RPC data is a reference only: it can block
//! a send (fail-closed) but never changes the mint, decimals, program or accounts of the message,
//! which come from the allowlist and the local ATA derivation.
#![deny(clippy::indexing_slicing)]

use super::address::{SolAddress, TOKEN_2022_PROGRAM, TOKEN_PROGRAM};
use super::template::{MINT_LEN, SplAllowEntry, TOKEN_ACCOUNT_LEN};

/// A parsed mint account.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MintData {
    /// Total supply (raw units).
    pub supply: u64,
    /// Decimals as stored on chain (compared with the pinned value, never used).
    pub decimals: u8,
    /// `is_initialized`.
    pub initialized: bool,
}

/// Token account state byte.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TokenState {
    /// 0.
    Uninitialized,
    /// 1.
    Initialized,
    /// 2: transfers in and out fail.
    Frozen,
}

/// A parsed token account.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TokenAccountData {
    /// Mint.
    pub mint: SolAddress,
    /// Wallet that owns the tokens.
    pub owner: SolAddress,
    /// Raw amount.
    pub amount: u64,
    /// State.
    pub state: TokenState,
    /// `is_native` is set (a wrapped-SOL account).
    pub native: bool,
}

fn array<const N: usize>(data: &[u8], at: usize) -> Option<[u8; N]> {
    data.get(at..at.checked_add(N)?)?.try_into().ok()
}

fn le_u64(data: &[u8], at: usize) -> Option<u64> {
    array::<8>(data, at).map(u64::from_le_bytes)
}

/// `COption` tag (u32 LE) at `at`: `Some(false)` none, `Some(true)` some, `None` invalid.
fn option_tag(data: &[u8], at: usize) -> Option<bool> {
    match array::<4>(data, at).map(u32::from_le_bytes)? {
        0 => Some(false),
        1 => Some(true),
        _ => None,
    }
}

/// Parses a mint: exactly 82 bytes, `COption` tags 0/1, `is_initialized` 0/1.
#[must_use]
pub fn parse_mint(data: &[u8]) -> Option<MintData> {
    if data.len() != MINT_LEN {
        return None;
    }
    option_tag(data, 0)?; // mint_authority
    let supply = le_u64(data, 36)?;
    let decimals = *data.get(44)?;
    let initialized = match *data.get(45)? {
        0 => false,
        1 => true,
        _ => return None,
    };
    option_tag(data, 46)?; // freeze_authority
    Some(MintData {
        supply,
        decimals,
        initialized,
    })
}

/// Parses a token account: exactly 165 bytes, `COption` tags 0/1, state 0–2.
#[must_use]
pub fn parse_token_account(data: &[u8]) -> Option<TokenAccountData> {
    if data.len() != TOKEN_ACCOUNT_LEN {
        return None;
    }
    let mint = SolAddress::from_bytes(array::<32>(data, 0)?);
    let owner = SolAddress::from_bytes(array::<32>(data, 32)?);
    let amount = le_u64(data, 64)?;
    option_tag(data, 72)?; // delegate
    let state = match *data.get(108)? {
        0 => TokenState::Uninitialized,
        1 => TokenState::Initialized,
        2 => TokenState::Frozen,
        _ => return None,
    };
    let native = option_tag(data, 109)?;
    option_tag(data, 129)?; // close_authority
    Some(TokenAccountData {
        mint,
        owner,
        amount,
        state,
        native,
    })
}

/// Why a mint account does not match its allowlist entry (an `RpcAnomaly` block).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MintMismatch {
    /// `getAccountInfo(mint)` returned `null`.
    Missing,
    /// Owner is not the pinned token program.
    Owner,
    /// Not an 82-byte mint layout.
    Layout,
    /// On-chain decimals differ from the pinned value (the pinned value is still what is used).
    Decimals,
    /// Not initialized.
    Uninitialized,
}

/// Cross-checks a mint account with its entry (spec/07 §15.4): owner = token program, 82 bytes,
/// `data[44] == pinned decimals`, `data[45] == 1`.
///
/// # Errors
///
/// [`MintMismatch`].
pub fn check_mint(
    entry: &SplAllowEntry,
    account: Option<(&SolAddress, &[u8])>,
) -> Result<MintData, MintMismatch> {
    let (program, data) = account.ok_or(MintMismatch::Missing)?;
    if *program != entry.token_program {
        return Err(MintMismatch::Owner);
    }
    let mint = parse_mint(data).ok_or(MintMismatch::Layout)?;
    if mint.decimals != entry.decimals {
        return Err(MintMismatch::Decimals);
    }
    if !mint.initialized {
        return Err(MintMismatch::Uninitialized);
    }
    Ok(mint)
}

/// What the derived ATA of `(wallet, entry)` holds according to RPC.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TokenHolding {
    /// `getAccountInfo` = `null`: no token account (balance 0; receiving creates it).
    Missing,
    /// A normal account of this mint and wallet.
    Active(u64),
    /// Frozen by the mint's freeze authority: transfers fail.
    Frozen(u64),
    /// Something else lives at the ATA address (other program, layout, mint, owner, native,
    /// uninitialized): never shown as a balance and never sent from or to.
    Invalid,
}

impl TokenHolding {
    /// The raw balance to show (`Missing` = 0; `Invalid` = none).
    #[must_use]
    pub const fn balance(self) -> Option<u64> {
        match self {
            Self::Missing => Some(0),
            Self::Active(amount) | Self::Frozen(amount) => Some(amount),
            Self::Invalid => None,
        }
    }
}

/// Classifies `getAccountInfo(ATA(wallet, entry))`: `account` = `(owner program, data)`, `None`
/// for a missing account. Only the classic layout of the pinned program, the pinned mint and
/// `wallet` as owner count; decimals are never read from it.
#[must_use]
pub fn classify_holding(
    entry: &SplAllowEntry,
    wallet: &SolAddress,
    account: Option<(&SolAddress, &[u8])>,
) -> TokenHolding {
    let Some((program, data)) = account else {
        return TokenHolding::Missing;
    };
    if *program != entry.token_program {
        return TokenHolding::Invalid;
    }
    let Some(parsed) = parse_token_account(data) else {
        return TokenHolding::Invalid;
    };
    if parsed.mint != entry.mint || parsed.owner != *wallet || parsed.native {
        return TokenHolding::Invalid;
    }
    match parsed.state {
        TokenState::Initialized => TokenHolding::Active(parsed.amount),
        TokenState::Frozen => TokenHolding::Frozen(parsed.amount),
        TokenState::Uninitialized => TokenHolding::Invalid,
    }
}

// ----- any token account or mint (dApp transactions, spec/07 §20.7) -----------------------

/// Size of a Token multisig account: Token-2022 pads an extended account that would have this
/// length, so an account of exactly this size is always a multisig.
const MULTISIG_LEN: usize = 355;
/// Token-2022 account-type byte after the 165-byte base (`1` mint, `2` account).
const ACCOUNT_TYPE_AT: usize = TOKEN_ACCOUNT_LEN;
/// Most Token-2022 mint extensions read.
const MAX_MINT_EXTENSIONS: usize = 64;

/// A token account of Token or Token-2022 (the 165-byte base; extensions are not read). Used
/// only to show RPC pre-state and simulation changes, never to build a message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TokenAccountView {
    /// Mint.
    pub mint: SolAddress,
    /// Wallet that owns the tokens.
    pub owner: SolAddress,
    /// Raw amount (the public balance only; Token-2022 confidential balances are not visible).
    pub amount: u64,
    /// Delegate allowed to move `delegated_amount`.
    pub delegate: Option<SolAddress>,
    /// Amount the delegate may move.
    pub delegated_amount: u64,
    /// State byte: 0 uninitialized, 1 initialized, 2 frozen.
    pub state: u8,
    /// Rent-exempt reserve of a wrapped-SOL account.
    pub is_native: Option<u64>,
    /// Who may close the account (the owner when `None`).
    pub close_authority: Option<SolAddress>,
}

/// `COption<Pubkey>` (u32 LE tag + 32 bytes) at `at`; `Err` for an invalid tag.
fn option_key(data: &[u8], at: usize) -> Result<Option<SolAddress>, ()> {
    if option_tag(data, at).ok_or(())? {
        let key = array::<32>(data, at.checked_add(4).ok_or(())?).ok_or(())?;
        Ok(Some(SolAddress::from_bytes(key)))
    } else {
        Ok(None)
    }
}

/// Parses a token account owned by `owner_program`: Token needs exactly 165 bytes; Token-2022
/// takes 165 bytes, or at least 166 with account type `2` at byte 165 (a 355-byte account is a
/// multisig). `COption` tags must be 0/1 and the state 0–2.
#[must_use]
pub fn parse_token_account_any(
    owner_program: &SolAddress,
    data: &[u8],
) -> Option<TokenAccountView> {
    let base_only = data.len() == TOKEN_ACCOUNT_LEN;
    let ok = if *owner_program == TOKEN_PROGRAM {
        base_only
    } else if *owner_program == TOKEN_2022_PROGRAM {
        base_only || (data.len() != MULTISIG_LEN && data.get(ACCOUNT_TYPE_AT) == Some(&2))
    } else {
        false
    };
    if !ok {
        return None;
    }
    let state = *data.get(108)?;
    if state > 2 {
        return None;
    }
    let is_native = if option_tag(data, 109)? {
        Some(le_u64(data, 113)?)
    } else {
        None
    };
    Some(TokenAccountView {
        mint: SolAddress::from_bytes(array::<32>(data, 0)?),
        owner: SolAddress::from_bytes(array::<32>(data, 32)?),
        amount: le_u64(data, 64)?,
        delegate: option_key(data, 72).ok()?,
        delegated_amount: le_u64(data, 121)?,
        state,
        is_native,
        close_authority: option_key(data, 129).ok()?,
    })
}

/// A mint of Token or Token-2022: decimals and the Token-2022 extension types (TLV order).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MintView {
    /// Decimals as stored on chain (display only).
    pub decimals: u8,
    /// Token-2022 extension types (`12` permanent delegate, `14` transfer hook, `1` transfer fee
    /// config, …); empty for Token and base-only mints.
    pub extensions: Vec<u16>,
}

/// Parses a mint owned by `owner_program`: Token needs exactly 82 bytes; Token-2022 takes 82
/// bytes, or more than 165 with zero padding after the base, account type `1` at byte 165 and
/// TLV entries from byte 166 (u16 LE type, u16 LE length, inside the data, at most 64; type 0
/// or fewer than two bytes left ends the list).
#[must_use]
pub fn parse_mint_any(owner_program: &SolAddress, data: &[u8]) -> Option<MintView> {
    let base = parse_mint(data.get(..MINT_LEN)?)?;
    if data.len() == MINT_LEN {
        return (*owner_program == TOKEN_PROGRAM || *owner_program == TOKEN_2022_PROGRAM).then(
            || MintView {
                decimals: base.decimals,
                extensions: Vec::new(),
            },
        );
    }
    if *owner_program != TOKEN_2022_PROGRAM
        || data.len() <= ACCOUNT_TYPE_AT
        || data.len() == MULTISIG_LEN
        || data.get(ACCOUNT_TYPE_AT) != Some(&1)
        || data
            .get(MINT_LEN..ACCOUNT_TYPE_AT)?
            .iter()
            .any(|byte| *byte != 0)
    {
        return None;
    }
    let mut extensions = Vec::new();
    let mut at = ACCOUNT_TYPE_AT.checked_add(1)?;
    // Fewer than two bytes left cannot hold a type: the end (Token-2022 `get_extension_types`).
    while let Some(kind) = array::<2>(data, at).map(u16::from_le_bytes) {
        if kind == 0 {
            break;
        }
        let length = usize::from(u16::from_le_bytes(array::<2>(data, at.checked_add(2)?)?));
        let end = at.checked_add(4)?.checked_add(length)?;
        if end > data.len() || extensions.len() == MAX_MINT_EXTENSIONS {
            return None;
        }
        extensions.push(kind);
        at = end;
    }
    Some(MintView {
        decimals: base.decimals,
        extensions,
    })
}

#[cfg(test)]
#[expect(clippy::indexing_slicing, reason = "fixed-size test buffers")]
pub(crate) mod tests {
    use super::{
        MintMismatch, MintView, TokenHolding, TokenState, check_mint, classify_holding, parse_mint,
        parse_mint_any, parse_token_account, parse_token_account_any,
    };
    use crate::sol::address::{SYSTEM_PROGRAM, SolAddress, TOKEN_2022_PROGRAM, TOKEN_PROGRAM};
    use crate::sol::template::SPL_ALLOWLIST;

    /// A classic mint body (82 bytes).
    pub(crate) fn mint_bytes(decimals: u8, initialized: u8) -> Vec<u8> {
        let mut data = vec![0_u8; 82];
        data[0] = 1; // mint_authority Some
        data[36..44].copy_from_slice(&1_000_000_000_u64.to_le_bytes());
        data[44] = decimals;
        data[45] = initialized;
        data
    }

    /// A classic token account body (165 bytes).
    pub(crate) fn token_bytes(
        mint: &SolAddress,
        owner: &SolAddress,
        amount: u64,
        state: u8,
    ) -> Vec<u8> {
        let mut data = vec![0_u8; 165];
        data[0..32].copy_from_slice(mint.as_bytes());
        data[32..64].copy_from_slice(owner.as_bytes());
        data[64..72].copy_from_slice(&amount.to_le_bytes());
        data[108] = state;
        data
    }

    #[test]
    fn layouts_are_strict() {
        let mint = parse_mint(&mint_bytes(6, 1)).unwrap();
        assert_eq!(
            (mint.decimals, mint.initialized, mint.supply),
            (6, true, 1_000_000_000)
        );
        assert!(parse_mint(&mint_bytes(6, 2)).is_none());
        let mut bad_tag = mint_bytes(6, 1);
        bad_tag[0] = 2;
        assert!(parse_mint(&bad_tag).is_none());
        let mut long = mint_bytes(6, 1);
        long.push(0);
        assert!(parse_mint(&long).is_none());
        assert!(parse_mint(&[]).is_none());

        let entry = &SPL_ALLOWLIST[0];
        let wallet = SolAddress::from_bytes([7; 32]);
        let account = parse_token_account(&token_bytes(&entry.mint, &wallet, 42, 1)).unwrap();
        assert_eq!(
            (
                account.mint,
                account.owner,
                account.amount,
                account.state,
                account.native
            ),
            (entry.mint, wallet, 42, TokenState::Initialized, false)
        );
        assert!(parse_token_account(&token_bytes(&entry.mint, &wallet, 42, 3)).is_none());
        let mut bad_delegate = token_bytes(&entry.mint, &wallet, 42, 1);
        bad_delegate[72] = 9;
        assert!(parse_token_account(&bad_delegate).is_none());
        assert!(parse_token_account(&token_bytes(&entry.mint, &wallet, 42, 1)[..164]).is_none());
    }

    /// Decimals pinning: an RPC that reports other decimals blocks (fail-closed) and never
    /// changes the pinned value.
    #[test]
    fn mint_cross_check() {
        let entry = &SPL_ALLOWLIST[0];
        let six = mint_bytes(6, 1);
        assert_eq!(
            check_mint(entry, Some((&TOKEN_PROGRAM, &six)))
                .unwrap()
                .decimals,
            6
        );
        let nine = mint_bytes(9, 1);
        assert_eq!(
            check_mint(entry, Some((&TOKEN_PROGRAM, &nine))),
            Err(MintMismatch::Decimals)
        );
        assert_eq!(entry.decimals, 6);
        assert_eq!(
            check_mint(entry, Some((&SYSTEM_PROGRAM, &six))),
            Err(MintMismatch::Owner)
        );
        assert_eq!(check_mint(entry, None), Err(MintMismatch::Missing));
        assert_eq!(
            check_mint(entry, Some((&TOKEN_PROGRAM, &six[..81]))),
            Err(MintMismatch::Layout)
        );
        let uninitialized = mint_bytes(6, 0);
        assert_eq!(
            check_mint(entry, Some((&TOKEN_PROGRAM, &uninitialized))),
            Err(MintMismatch::Uninitialized)
        );
    }

    #[test]
    fn holdings() {
        let entry = &SPL_ALLOWLIST[0];
        let wallet = SolAddress::from_bytes([7; 32]);
        let other = SolAddress::from_bytes([8; 32]);
        let classify = |program: &SolAddress, data: &[u8]| {
            classify_holding(entry, &wallet, Some((program, data)))
        };
        assert_eq!(
            classify_holding(entry, &wallet, None),
            TokenHolding::Missing
        );
        assert_eq!(
            classify(&TOKEN_PROGRAM, &token_bytes(&entry.mint, &wallet, 5, 1)),
            TokenHolding::Active(5)
        );
        assert_eq!(
            classify(&TOKEN_PROGRAM, &token_bytes(&entry.mint, &wallet, 5, 2)),
            TokenHolding::Frozen(5)
        );
        for invalid in [
            classify(&SYSTEM_PROGRAM, &token_bytes(&entry.mint, &wallet, 5, 1)),
            classify(&TOKEN_PROGRAM, &token_bytes(&other, &wallet, 5, 1)),
            classify(&TOKEN_PROGRAM, &token_bytes(&entry.mint, &other, 5, 1)),
            classify(&TOKEN_PROGRAM, &token_bytes(&entry.mint, &wallet, 5, 0)),
            classify(&TOKEN_PROGRAM, &[0; 82]),
        ] {
            assert_eq!(invalid, TokenHolding::Invalid);
        }
        let mut native = token_bytes(&entry.mint, &wallet, 5, 1);
        native[109] = 1;
        assert_eq!(classify(&TOKEN_PROGRAM, &native), TokenHolding::Invalid);
        assert_eq!(TokenHolding::Missing.balance(), Some(0));
        assert_eq!(TokenHolding::Invalid.balance(), None);
    }

    /// Token and Token-2022 accounts: the full base with delegate, native reserve and close
    /// authority; Token-2022 extended (or `dataSlice` 0/166) accounts need account type 2.
    #[test]
    fn any_token_account() {
        let mint = SolAddress::from_bytes([3; 32]);
        let wallet = SolAddress::from_bytes([7; 32]);
        let mut data = token_bytes(&mint, &wallet, 42, 1);
        data[72] = 1;
        data[76..108].copy_from_slice(&[9; 32]);
        data[109] = 1;
        data[113..121].copy_from_slice(&2_039_280_u64.to_le_bytes());
        data[121..129].copy_from_slice(&40_u64.to_le_bytes());
        data[129] = 1;
        data[133..165].copy_from_slice(&[5; 32]);
        let view = parse_token_account_any(&TOKEN_PROGRAM, &data).unwrap();
        assert_eq!(
            (view.mint, view.owner, view.amount, view.state),
            (mint, wallet, 42, 1)
        );
        assert_eq!(view.delegate, Some(SolAddress::from_bytes([9; 32])));
        assert_eq!(view.delegated_amount, 40);
        assert_eq!(view.is_native, Some(2_039_280));
        assert_eq!(view.close_authority, Some(SolAddress::from_bytes([5; 32])));
        assert_eq!(
            parse_token_account_any(&TOKEN_2022_PROGRAM, &data),
            Some(view)
        );
        let plain =
            parse_token_account_any(&TOKEN_PROGRAM, &token_bytes(&mint, &wallet, 1, 2)).unwrap();
        assert_eq!(
            (plain.delegate, plain.is_native, plain.close_authority),
            (None, None, None)
        );

        let mut extended = data.clone();
        extended.push(2);
        assert_eq!(
            parse_token_account_any(&TOKEN_2022_PROGRAM, &extended),
            Some(view)
        );
        extended.extend_from_slice(&[0; 40]);
        assert!(parse_token_account_any(&TOKEN_2022_PROGRAM, &extended).is_some());
        // Classic Token has no extensions; type 1 is a mint; a 355-byte account is a multisig.
        assert!(parse_token_account_any(&TOKEN_PROGRAM, &extended).is_none());
        extended[165] = 1;
        assert!(parse_token_account_any(&TOKEN_2022_PROGRAM, &extended).is_none());
        let mut multisig = data.clone();
        multisig.push(2);
        multisig.resize(355, 0);
        assert!(parse_token_account_any(&TOKEN_2022_PROGRAM, &multisig).is_none());
        assert!(parse_token_account_any(&SYSTEM_PROGRAM, &data).is_none());
        assert!(parse_token_account_any(&TOKEN_PROGRAM, &data[..164]).is_none());
        for (at, value) in [(72, 2), (108, 3), (109, 2), (129, 7)] {
            let mut bad = data.clone();
            bad[at] = value;
            assert!(
                parse_token_account_any(&TOKEN_PROGRAM, &bad).is_none(),
                "{at}"
            );
        }
    }

    /// A Token-2022 mint with `types` as TLV entries of `length` bytes each.
    fn mint_2022(types: &[u16], length: u16) -> Vec<u8> {
        let mut data = mint_bytes(9, 1);
        data.resize(165, 0);
        data.push(1);
        for kind in types {
            data.extend_from_slice(&kind.to_le_bytes());
            data.extend_from_slice(&length.to_le_bytes());
            data.extend(std::iter::repeat_n(0xab, usize::from(length)));
        }
        data
    }

    #[test]
    fn any_mint() {
        let base = mint_bytes(6, 1);
        for program in [TOKEN_PROGRAM, TOKEN_2022_PROGRAM] {
            assert_eq!(
                parse_mint_any(&program, &base),
                Some(MintView {
                    decimals: 6,
                    extensions: Vec::new()
                })
            );
        }
        assert!(parse_mint_any(&SYSTEM_PROGRAM, &base).is_none());
        let extended = mint_2022(&[1, 12, 14], 3);
        assert_eq!(
            parse_mint_any(&TOKEN_2022_PROGRAM, &extended),
            Some(MintView {
                decimals: 9,
                extensions: vec![1, 12, 14]
            })
        );
        assert!(parse_mint_any(&TOKEN_PROGRAM, &extended).is_none());
        // Type 0 and a lone trailing byte end the list; an empty list is a valid extended mint.
        let mut padded = mint_2022(&[12], 32);
        padded.extend_from_slice(&[0; 8]);
        assert_eq!(
            parse_mint_any(&TOKEN_2022_PROGRAM, &padded)
                .unwrap()
                .extensions,
            [12]
        );
        let mut odd = mint_2022(&[14], 0);
        odd.push(0xff);
        assert_eq!(
            parse_mint_any(&TOKEN_2022_PROGRAM, &odd)
                .unwrap()
                .extensions,
            [14]
        );
        assert_eq!(
            parse_mint_any(&TOKEN_2022_PROGRAM, &mint_2022(&[], 0))
                .unwrap()
                .extensions,
            Vec::<u16>::new()
        );
        // A value past the end, a type cut in half, nonzero padding, account type 2, the
        // in-between lengths and a 65th entry are all refused.
        let mut long = mint_2022(&[1], 4);
        long.truncate(long.len() - 1);
        assert!(parse_mint_any(&TOKEN_2022_PROGRAM, &long).is_none());
        let mut cut = mint_2022(&[1], 0);
        cut.extend_from_slice(&[0x0c, 0x00, 0x01]);
        assert!(parse_mint_any(&TOKEN_2022_PROGRAM, &cut).is_none());
        let mut dirty = mint_2022(&[1], 0);
        dirty[100] = 1;
        assert!(parse_mint_any(&TOKEN_2022_PROGRAM, &dirty).is_none());
        let mut account = mint_2022(&[1], 0);
        account[165] = 2;
        assert!(parse_mint_any(&TOKEN_2022_PROGRAM, &account).is_none());
        for length in [83, 165] {
            let mut data = mint_bytes(6, 1);
            data.resize(length, 0);
            assert!(
                parse_mint_any(&TOKEN_2022_PROGRAM, &data).is_none(),
                "{length}"
            );
        }
        let many: Vec<u16> = (1..=64).collect();
        assert_eq!(
            parse_mint_any(&TOKEN_2022_PROGRAM, &mint_2022(&many, 0))
                .unwrap()
                .extensions
                .len(),
            64
        );
        let too_many: Vec<u16> = (1..=65).collect();
        assert!(parse_mint_any(&TOKEN_2022_PROGRAM, &mint_2022(&too_many, 0)).is_none());
        assert!(parse_mint_any(&TOKEN_2022_PROGRAM, &mint_bytes(6, 2)).is_none());
    }
}
