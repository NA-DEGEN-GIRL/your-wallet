//! Meta `zcash` (spec/12 §12.3, optional top-level key): the Zcash account of each network —
//! key source and cached compressed public key (public information; meta is encrypted). Absent
//! in files of earlier versions, which keep it unread (as an unknown key) when they write.

use yw_core::zec::{ZecAccount, ZecKeySource, ZecNetwork};
use yw_json::{Number, Object, Value};

/// The optional top-level meta key.
pub const ZCASH_KEY: &str = "zcash";

/// The accounts (at most one per network).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ZcashMeta {
    /// Mainnet account.
    pub mainnet: Option<ZecAccount>,
    /// Testnet account.
    pub testnet: Option<ZecAccount>,
}

fn account_json(account: &ZecAccount) -> Value {
    let (a, b) = account.source.params();
    Value::Object(
        Object::from_pairs(vec![
            (
                "source".to_owned(),
                Value::Number(Number::from_u64(u64::from(account.source.code()))),
            ),
            (
                "a".to_owned(),
                Value::Number(Number::from_u64(u64::from(a))),
            ),
            (
                "b".to_owned(),
                Value::Number(Number::from_u64(u64::from(b))),
            ),
            (
                "pubkey".to_owned(),
                Value::String(yw_core::hex::encode(&account.pubkey)),
            ),
        ])
        .unwrap_or_default(),
    )
}

fn account_from(network: ZecNetwork, value: &Value) -> Option<ZecAccount> {
    let object = value.as_object()?;
    if object.len() != 4 {
        return None;
    }
    let number = |key: &str| -> Option<u32> {
        object
            .get(key)?
            .as_number()?
            .as_u64()
            .and_then(|value| u32::try_from(value).ok())
    };
    let code = u8::try_from(number("source")?).ok()?;
    let source = ZecKeySource::from_parts(code, number("a")?, number("b")?)?;
    let pubkey = yw_core::hex::decode_array::<33>(object.get("pubkey")?.as_str()?).ok()?;
    if !matches!(pubkey.first(), Some(0x02 | 0x03)) {
        return None;
    }
    Some(ZecAccount {
        network,
        source,
        pubkey,
    })
}

impl ZcashMeta {
    /// The account of `network`.
    #[must_use]
    pub const fn get(&self, network: ZecNetwork) -> Option<&ZecAccount> {
        match network {
            ZecNetwork::Mainnet => self.mainnet.as_ref(),
            ZecNetwork::Testnet => self.testnet.as_ref(),
        }
    }

    /// Replaces the account of its network.
    pub fn set(&mut self, account: ZecAccount) {
        match account.network {
            ZecNetwork::Mainnet => self.mainnet = Some(account),
            ZecNetwork::Testnet => self.testnet = Some(account),
        }
    }

    /// Nothing stored (the key is then not written).
    #[must_use]
    pub const fn is_default(&self) -> bool {
        self.mainnet.is_none() && self.testnet.is_none()
    }

    /// The JSON value.
    #[must_use]
    pub fn to_json(&self) -> Value {
        let mut pairs = Vec::new();
        for network in ZecNetwork::ALL {
            if let Some(account) = self.get(network) {
                pairs.push((network.name().to_owned(), account_json(account)));
            }
        }
        Value::Object(Object::from_pairs(pairs).unwrap_or_default())
    }

    /// Parses the key (`None` value = absent). An invalid entry drops that network's account
    /// (it is derived again from the vault), never the whole meta.
    #[must_use]
    pub fn from_json(value: Option<&Value>) -> Self {
        let mut out = Self::default();
        let Some(object) = value.and_then(Value::as_object) else {
            return out;
        };
        for network in ZecNetwork::ALL {
            if let Some(account) = object
                .get(network.name())
                .and_then(|entry| account_from(network, entry))
            {
                out.set(account);
            }
        }
        out
    }
}
