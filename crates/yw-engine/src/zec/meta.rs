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

fn mnemonic_account_from(network: ZecNetwork, value: &Value) -> Option<ZecAccount> {
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
    let text = object.get("mnemonic")?.as_str()?;
    if text.bytes().any(|byte| byte.is_ascii_uppercase()) {
        return None;
    }
    let id = yw_core::hex::decode_array::<16>(text).ok()?;
    let source = ZecKeySource::from_mnemonic_parts(id, number("a")?, number("b")?)?;
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

    /// Forgets the account of `network` (it is made again with the default key).
    pub const fn clear(&mut self, network: ZecNetwork) {
        match network {
            ZecNetwork::Mainnet => self.mainnet = None,
            ZecNetwork::Testnet => self.testnet = None,
        }
    }

    /// Nothing stored in the `zcash` key (it is then not written): no account, or only accounts
    /// on an added mnemonic's key (those go to `mnemonic_accounts.zec`).
    #[must_use]
    pub fn is_default(&self) -> bool {
        ZecNetwork::ALL.iter().all(|network| {
            self.get(*network)
                .is_none_or(|account| account.source.mnemonic().is_some())
        })
    }

    /// The `zcash` value: every account except those on an added mnemonic's key (earlier builds
    /// would drop such an entry and make the network's account again; spec/02 §8.6).
    #[must_use]
    pub fn to_json(&self) -> Value {
        let mut pairs = Vec::new();
        for network in ZecNetwork::ALL {
            if let Some(account) = self.get(network)
                && account.source.mnemonic().is_none()
            {
                pairs.push((network.name().to_owned(), account_json(account)));
            }
        }
        Value::Object(Object::from_pairs(pairs).unwrap_or_default())
    }

    /// `mnemonic_accounts.zec` (`None` without such an account): `{network: {"mnemonic": Hex16,
    /// "a": account, "b": index, "pubkey": hex66}}`.
    #[must_use]
    pub fn mnemonic_accounts_json(&self) -> Option<Value> {
        let mut pairs = Vec::new();
        for network in ZecNetwork::ALL {
            let Some(account) = self.get(network) else {
                continue;
            };
            let Some(id) = account.source.mnemonic() else {
                continue;
            };
            let (a, b) = account.source.params();
            let number = |value: u32| Value::Number(Number::from_u64(u64::from(value)));
            pairs.push((
                network.name().to_owned(),
                Value::Object(
                    Object::from_pairs(vec![
                        (
                            "mnemonic".to_owned(),
                            Value::String(yw_core::hex::encode(id.as_bytes())),
                        ),
                        ("a".to_owned(), number(a)),
                        ("b".to_owned(), number(b)),
                        (
                            "pubkey".to_owned(),
                            Value::String(yw_core::hex::encode(&account.pubkey)),
                        ),
                    ])
                    .unwrap_or_default(),
                ),
            ));
        }
        (!pairs.is_empty()).then(|| Value::Object(Object::from_pairs(pairs).unwrap_or_default()))
    }

    /// Reads `mnemonic_accounts.zec` over the `zcash` accounts (strict: `false` for an invalid
    /// value). Such an entry wins over the network's `zcash` entry (an earlier build may have made
    /// that one again meanwhile).
    #[must_use]
    pub fn read_mnemonic_accounts(&mut self, value: &Value) -> bool {
        let Some(object) = value.as_object() else {
            return false;
        };
        if object
            .keys()
            .any(|key| !ZecNetwork::ALL.iter().any(|network| network.name() == key))
        {
            return false;
        }
        for network in ZecNetwork::ALL {
            let Some(entry) = object.get(network.name()) else {
                continue;
            };
            let Some(account) = mnemonic_account_from(network, entry) else {
                return false;
            };
            self.set(account);
        }
        true
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
