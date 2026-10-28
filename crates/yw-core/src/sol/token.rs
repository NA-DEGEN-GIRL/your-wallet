//! SPL account data (spec/07 §15.4, v1.1): the raw classic-Token mint (82 bytes) and token
//! account (165 bytes) layouts as returned by `getAccountInfo` (`base64`, no `jsonParsed`), and
//! their classification against the pinned allowlist. RPC data is a reference only: it can block
//! a send (fail-closed) but never changes the mint, decimals, program or accounts of the message,
//! which come from the allowlist and the local ATA derivation.
#![deny(clippy::indexing_slicing)]

use super::address::SolAddress;
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

#[cfg(test)]
#[expect(clippy::indexing_slicing, reason = "fixed-size test buffers")]
pub(crate) mod tests {
    use super::{
        MintMismatch, TokenHolding, TokenState, check_mint, classify_holding, parse_mint,
        parse_token_account,
    };
    use crate::sol::address::{SYSTEM_PROGRAM, SolAddress, TOKEN_PROGRAM};
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
}
