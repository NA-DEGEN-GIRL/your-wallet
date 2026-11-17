//! meta `token_view` (spec/02 §5.3, spec/04 §2.6): which rows the S10 token cards hide.
//!
//! Display only. Hiding a token changes which rows the EVM and Solana token cards (and the EVM
//! send form's asset radios) show first; it never changes which tokens the wallet knows, fetches
//! balances for, or how approvals recognise them (registry trust, E19 lookalike checks, risk
//! rules read the registry and meta `tokens`, never this). Activity rows of hidden tokens stay.
//!
//! JSON: `{ "hidden": { NetworkId: [token id…] }, "hide_zero": bool }`, an optional top-level key
//! written only when not the default. Token ids are canonical: `eip155:*` the lowercase `0x`
//! contract, `solana:*` the base58 mint. An invalid value falls back to the default (like
//! `prefs`) instead of rejecting the document: it is a view preference, not wallet state.

use yw_json::Value;

use crate::meta::{is_evm_addr, is_sol_addr};
use crate::network::NetworkId;
use crate::text::{json_object, json_object_owned, json_str};

/// The optional top-level meta key.
pub const TOKEN_VIEW_KEY: &str = "token_view";
/// Hidden ids per network (registry tokens + up to 100 user tokens, with room for stale ids of
/// deleted tokens or of a registry that changed).
pub const MAX_HIDDEN_PER_NETWORK: usize = 200;
/// Hidden ids over all networks.
pub const MAX_HIDDEN_TOTAL: usize = 2_000;

/// meta `token_view`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TokenView {
    /// Hidden token ids per network (`NetworkId` string), in the order they were hidden. No
    /// empty lists, no duplicates.
    pub hidden: Vec<(String, Vec<String>)>,
    /// EVM token card: also hide rows whose balance is known to be zero (`잔액 0인 토큰 숨기기`).
    pub hide_zero: bool,
}

/// Where a token row goes on a card.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RowPlace {
    /// A normal row.
    Shown,
    /// Hidden by the user: listed (dimmed, `다시 보이기`) under `숨긴 토큰 n개 보기`.
    Hidden,
    /// Not hidden, but the balance is known to be zero and `잔액 0인 토큰 숨기기` is on.
    ZeroHidden,
}

/// The place of one row: an explicit hide wins; a zero balance hides only when it is known
/// (`balance_zero == Some(true)`) and the toggle is on, so an unread balance never hides a row.
#[must_use]
pub const fn place(hidden: bool, balance_zero: Option<bool>, hide_zero: bool) -> RowPlace {
    if hidden {
        RowPlace::Hidden
    } else if hide_zero && matches!(balance_zero, Some(true)) {
        RowPlace::ZeroHidden
    } else {
        RowPlace::Shown
    }
}

/// The canonical token id is valid for the network (EVM lowercase contract, Solana mint).
fn valid_id(network: NetworkId, id: &str) -> bool {
    match network {
        NetworkId::Eip155(_) => is_evm_addr(id),
        NetworkId::Solana(_) => is_sol_addr(id),
        NetworkId::Bitcoin(_) | NetworkId::Zcash(_) => false,
    }
}

impl TokenView {
    /// Nothing hidden and the zero toggle off (the key is then not written).
    #[must_use]
    pub fn is_default(&self) -> bool {
        self.hidden.is_empty() && !self.hide_zero
    }

    /// The hidden ids of a network.
    #[must_use]
    pub fn hidden_of(&self, network: &str) -> &[String] {
        self.hidden
            .iter()
            .find(|(key, _)| key == network)
            .map_or(&[], |(_, ids)| ids.as_slice())
    }

    /// Whether `token` (canonical id) is hidden on `network`.
    #[must_use]
    pub fn is_hidden(&self, network: &str, token: &str) -> bool {
        self.hidden_of(network).iter().any(|id| id == token)
    }

    /// Hides or shows `token` on `network`; `false` (nothing changed) when hiding would exceed
    /// the bounds or the id is not canonical for the network.
    pub fn set_hidden(&mut self, network: &str, token: &str, hidden: bool) -> bool {
        if !hidden {
            for (key, ids) in &mut self.hidden {
                if key == network {
                    ids.retain(|id| id != token);
                }
            }
            self.hidden.retain(|(_, ids)| !ids.is_empty());
            return true;
        }
        if self.is_hidden(network, token) {
            return true;
        }
        let total: usize = self.hidden.iter().map(|(_, ids)| ids.len()).sum();
        let valid = NetworkId::parse(network).is_some_and(|parsed| valid_id(parsed, token));
        if !valid
            || self.hidden_of(network).len() >= MAX_HIDDEN_PER_NETWORK
            || total >= MAX_HIDDEN_TOTAL
        {
            return false;
        }
        match self.hidden.iter_mut().find(|(key, _)| key == network) {
            Some((_, ids)) => ids.push(token.to_owned()),
            None => self
                .hidden
                .push((network.to_owned(), vec![token.to_owned()])),
        }
        true
    }

    /// Parses the JSON value (`None`: any violation; the caller falls back to the default).
    #[must_use]
    pub fn from_json(value: &Value) -> Option<Self> {
        let object = value.as_object()?;
        if object.len() != 2 {
            return None;
        }
        let hide_zero = object.get("hide_zero")?.as_bool()?;
        let mut hidden = Vec::new();
        let mut total = 0_usize;
        for (key, ids) in object.get("hidden")?.as_object()?.iter() {
            let network = NetworkId::parse(key)?;
            let ids = ids.as_array()?;
            if ids.is_empty() || ids.len() > MAX_HIDDEN_PER_NETWORK {
                return None;
            }
            let mut list: Vec<String> = Vec::with_capacity(ids.len());
            for id in ids {
                let id = id.as_str()?;
                if !valid_id(network, id) || list.iter().any(|known| known == id) {
                    return None;
                }
                list.push(id.to_owned());
            }
            total = total.checked_add(list.len())?;
            hidden.push((key.to_owned(), list));
        }
        (total <= MAX_HIDDEN_TOTAL).then_some(Self { hidden, hide_zero })
    }

    /// The JSON value (`hidden` first, then `hide_zero`).
    #[must_use]
    pub fn to_json(&self) -> Value {
        let hidden = json_object_owned(
            self.hidden
                .iter()
                .map(|(key, ids)| {
                    (
                        key.clone(),
                        Value::Array(ids.iter().map(|id| json_str(id)).collect()),
                    )
                })
                .collect(),
        )
        .unwrap_or_else(|| json_object(Vec::new()));
        json_object(vec![
            ("hidden", hidden),
            ("hide_zero", Value::Bool(self.hide_zero)),
        ])
    }
}

#[cfg(test)]
mod tests {
    use super::{MAX_HIDDEN_PER_NETWORK, RowPlace, TokenView, place};

    const USDC: &str = "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48";
    const MINT: &str = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";

    #[test]
    fn hide_unhide_and_bounds() {
        let mut view = TokenView::default();
        assert!(view.is_default());
        assert!(view.set_hidden("eip155:1", USDC, true));
        assert!(
            view.set_hidden("eip155:1", USDC, true),
            "hiding twice is a no-op"
        );
        assert_eq!(view.hidden_of("eip155:1"), [USDC.to_owned()]);
        assert!(view.is_hidden("eip155:1", USDC));
        assert!(!view.is_hidden("eip155:11155111", USDC), "per network");
        assert!(view.set_hidden("solana:mainnet", MINT, true));
        assert!(!view.is_default());
        // Non-canonical ids and Bitcoin networks are refused.
        assert!(!view.set_hidden("eip155:1", &USDC.to_uppercase(), true));
        assert!(!view.set_hidden("eip155:1", MINT, true));
        assert!(!view.set_hidden("solana:mainnet", USDC, true));
        assert!(!view.set_hidden("bitcoin:mainnet", USDC, true));
        assert!(!view.set_hidden("eip155:x", USDC, true));
        assert!(view.set_hidden("eip155:1", USDC, false));
        assert!(view.set_hidden("solana:mainnet", MINT, false));
        assert!(view.is_default(), "empty lists are dropped");
        // The per-network bound.
        for n in 0..MAX_HIDDEN_PER_NETWORK {
            assert!(view.set_hidden("eip155:5", &format!("0x{n:040x}"), true));
        }
        assert!(!view.set_hidden("eip155:5", USDC, true));
        assert!(view.set_hidden("eip155:6", USDC, true));
    }

    #[test]
    fn row_places() {
        assert_eq!(place(false, None, true), RowPlace::Shown, "unknown balance");
        assert_eq!(
            place(false, Some(true), false),
            RowPlace::Shown,
            "toggle off"
        );
        assert_eq!(place(false, Some(true), true), RowPlace::ZeroHidden);
        assert_eq!(place(false, Some(false), true), RowPlace::Shown);
        assert_eq!(place(true, Some(false), false), RowPlace::Hidden);
        assert_eq!(
            place(true, Some(true), true),
            RowPlace::Hidden,
            "explicit wins"
        );
    }

    #[test]
    fn json_round_trip_and_validation() {
        let mut view = TokenView {
            hide_zero: true,
            ..TokenView::default()
        };
        view.set_hidden("eip155:1", USDC, true);
        view.set_hidden("solana:mainnet", MINT, true);
        let value = view.to_json();
        assert_eq!(TokenView::from_json(&value), Some(view));
        let text = |json: &str| {
            let limits = yw_json::Limits {
                max_bytes: 4_096,
                max_depth: 8,
                max_nodes: 1_000,
                max_items: 1_000,
            };
            yw_json::parse(json.as_bytes(), &limits)
                .ok()
                .and_then(|value| TokenView::from_json(&value))
        };
        assert!(text(r#"{"hidden":{},"hide_zero":false}"#).is_some());
        for bad in [
            r#"{"hidden":{}}"#.to_owned(),
            r#"{"hidden":{},"hide_zero":false,"x":1}"#.to_owned(),
            r#"{"hidden":{"eip155:1":[]},"hide_zero":false}"#.to_owned(),
            format!(r#"{{"hidden":{{"eip155:1":["{USDC}","{USDC}"]}},"hide_zero":false}}"#),
            format!(r#"{{"hidden":{{"bitcoin:mainnet":["{USDC}"]}},"hide_zero":false}}"#),
            format!(r#"{{"hidden":{{"solana:mainnet":["{USDC}"]}},"hide_zero":false}}"#),
            format!(r#"{{"hidden":{{"eip155:1":["{MINT}"]}},"hide_zero":false}}"#),
            r#"{"hidden":{"eip155:1":[1]},"hide_zero":false}"#.to_owned(),
            r#"{"hidden":[],"hide_zero":false}"#.to_owned(),
            r#"{"hidden":{},"hide_zero":0}"#.to_owned(),
        ] {
            assert!(text(&bad).is_none(), "{bad}");
        }
    }
}
