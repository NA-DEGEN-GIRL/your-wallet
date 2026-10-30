//! meta `connected_sites` ↔ [`ConnectedSite`] (spec/02 §5.3 JSON form, spec/05 §4.1 meaning).
//! The meta module keeps the section as validated JSON values; these helpers convert both ways.

use yw_core::btc::{BtcNetwork, BtcPubKey, ScriptType};
use yw_core::evm::address::{Address, parse_address};
use yw_core::policy::{
    BrowserOrigin, BtcGrant, BtcGrantAddress, BtcPurpose, ConnectedSite, SolGrant,
};
use yw_json::Value;

use crate::text::{json_object, json_str, json_u64};

/// Parses one meta entry (`None` when it is not a usable grant: an origin outside spec/05 §4.7
/// or accounts that do not parse; meta validation already checked the shape).
#[must_use]
pub fn site_from_value(value: &Value) -> Option<ConnectedSite> {
    let object = value.as_object()?;
    let origin = BrowserOrigin::parse(object.get("origin")?.as_str()?)?;
    let accounts = object
        .get("accounts")?
        .as_array()?
        .iter()
        .map(|account| parse_address(account.as_str()?).ok())
        .collect::<Option<Vec<Address>>>()?;
    let number = |key: &str| {
        object
            .get(key)
            .and_then(Value::as_number)
            .and_then(yw_json::Number::as_u64)
    };
    ConnectedSite::new(
        origin,
        accounts,
        number("chain_id")?,
        number("granted_at_unix_ms")?,
    )
}

/// The meta JSON form.
#[must_use]
pub fn site_to_value(site: &ConnectedSite) -> Value {
    json_object(vec![
        ("origin", json_str(site.origin.as_str())),
        (
            "accounts",
            Value::Array(
                site.accounts
                    .iter()
                    .map(|account| json_str(&account.to_lower_hex()))
                    .collect(),
            ),
        ),
        ("chain_id", json_u64(site.chain_id)),
        ("granted_at_unix_ms", json_u64(site.granted_at_unix_ms)),
    ])
}

/// All usable grants of a meta section (unusable entries are skipped; at most one per origin).
#[must_use]
pub fn sites_from_values(values: &[Value]) -> Vec<ConnectedSite> {
    let mut out: Vec<ConnectedSite> = Vec::new();
    for site in values.iter().filter_map(site_from_value) {
        if !out.iter().any(|other| other.origin == site.origin) {
            out.push(site);
        }
    }
    out
}

/// The meta section of `sites`.
#[must_use]
pub fn sites_to_values(sites: &[ConnectedSite]) -> Vec<Value> {
    sites.iter().map(site_to_value).collect()
}

#[cfg(test)]
mod tests {
    use super::{site_from_value, site_to_value, sites_from_values};
    use yw_core::evm::address::Address;
    use yw_core::policy::{BrowserOrigin, ConnectedSite};

    #[test]
    fn round_trip_and_duplicates() {
        let site = ConnectedSite::new(
            BrowserOrigin::parse("https://app.example").unwrap(),
            vec![Address::from_bytes([0xab; 20])],
            11_155_111,
            1_700_000_000_000,
        )
        .unwrap();
        let value = site_to_value(&site);
        assert_eq!(
            String::from_utf8(yw_json::to_vec(&value)).unwrap(),
            r#"{"origin":"https://app.example","accounts":["0xabababababababababababababababababababab"],"chain_id":11155111,"granted_at_unix_ms":1700000000000}"#
        );
        assert_eq!(site_from_value(&value), Some(site.clone()));
        assert_eq!(sites_from_values(&[value.clone(), value]).len(), 1);
    }
}

/// meta `sol_sites` entry → [`SolGrant`] (`None` when unusable).
#[must_use]
pub fn sol_site_from_value(value: &Value) -> Option<SolGrant> {
    let object = value.as_object()?;
    Some(SolGrant {
        origin: BrowserOrigin::parse(object.get("origin")?.as_str()?)?,
        public: yw_core::codec::base58::base58_decode_32(object.get("public_key")?.as_str()?)
            .ok()?,
        granted_at_unix_ms: object.get("granted_at_unix_ms")?.as_number()?.as_u64()?,
    })
}

/// The meta JSON form of a Solana grant.
#[must_use]
pub fn sol_site_to_value(site: &SolGrant) -> Value {
    json_object(vec![
        ("origin", json_str(site.origin.as_str())),
        (
            "public_key",
            json_str(&yw_core::codec::base58::base58_encode(&site.public)),
        ),
        ("granted_at_unix_ms", json_u64(site.granted_at_unix_ms)),
    ])
}

/// meta `btc_sites` entry → [`BtcGrant`] (`None` when unusable).
#[must_use]
pub fn btc_site_from_value(value: &Value) -> Option<BtcGrant> {
    let object = value.as_object()?;
    let network = u8::try_from(object.get("network")?.as_number()?.as_u64()?).ok()?;
    let addresses = object
        .get("addresses")?
        .as_array()?
        .iter()
        .map(|entry| {
            let entry = entry.as_object()?;
            Some(BtcGrantAddress {
                purpose: BtcPurpose::parse(entry.get("purpose")?.as_str()?)?,
                address: entry.get("address")?.as_str()?.to_owned(),
                pubkey: BtcPubKey::parse(
                    &yw_core::hex::decode(entry.get("public_key")?.as_str()?).ok()?,
                )
                .ok()?,
                script_type: ScriptType::parse_json_name(entry.get("script_type")?.as_str()?)?,
            })
        })
        .collect::<Option<Vec<_>>>()?;
    BtcGrant::new(
        BrowserOrigin::parse(object.get("origin")?.as_str()?)?,
        BtcNetwork::from_id(network)?,
        addresses,
        object.get("granted_at_unix_ms")?.as_number()?.as_u64()?,
    )
}

/// The meta JSON form of a Bitcoin grant.
#[must_use]
pub fn btc_site_to_value(site: &BtcGrant) -> Value {
    json_object(vec![
        ("origin", json_str(site.origin.as_str())),
        ("network", json_u64(u64::from(site.network.id()))),
        (
            "addresses",
            Value::Array(
                site.addresses
                    .iter()
                    .map(|entry| {
                        json_object(vec![
                            ("purpose", json_str(entry.purpose.as_str())),
                            ("address", json_str(&entry.address)),
                            (
                                "public_key",
                                json_str(&yw_core::hex::encode(entry.pubkey.as_bytes())),
                            ),
                            ("script_type", json_str(entry.script_type.json_name())),
                        ])
                    })
                    .collect(),
            ),
        ),
        ("granted_at_unix_ms", json_u64(site.granted_at_unix_ms)),
    ])
}

/// Usable Solana grants (one per origin).
#[must_use]
pub fn sol_sites_from_values(values: &[Value]) -> Vec<SolGrant> {
    let mut out: Vec<SolGrant> = Vec::new();
    for site in values.iter().filter_map(sol_site_from_value) {
        if !out.iter().any(|other| other.origin == site.origin) {
            out.push(site);
        }
    }
    out
}

/// Usable Bitcoin grants (one per origin).
#[must_use]
pub fn btc_sites_from_values(values: &[Value]) -> Vec<BtcGrant> {
    let mut out: Vec<BtcGrant> = Vec::new();
    for site in values.iter().filter_map(btc_site_from_value) {
        if !out.iter().any(|other| other.origin == site.origin) {
            out.push(site);
        }
    }
    out
}

#[cfg(test)]
mod chain_tests {
    use super::{btc_site_from_value, btc_site_to_value, sol_site_from_value, sol_site_to_value};
    use yw_core::btc::{BtcNetwork, BtcPubKey, ScriptType};
    use yw_core::policy::{BrowserOrigin, BtcGrant, BtcGrantAddress, BtcPurpose, SolGrant};

    #[test]
    fn chain_grants_round_trip() {
        let origin = BrowserOrigin::parse("https://app.example").unwrap();
        let sol = SolGrant {
            origin: origin.clone(),
            public: [7; 32],
            granted_at_unix_ms: 5,
        };
        assert_eq!(sol_site_from_value(&sol_site_to_value(&sol)), Some(sol));
        let btc = BtcGrant::new(
            origin,
            BtcNetwork::Testnet4,
            vec![BtcGrantAddress {
                purpose: BtcPurpose::Ordinals,
                address: "tb1p".to_owned(),
                pubkey: BtcPubKey::Compressed(
                    yw_core::hex::decode_array::<33>(
                        "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
                    )
                    .unwrap(),
                ),
                script_type: ScriptType::P2tr,
            }],
            9,
        )
        .unwrap();
        assert_eq!(btc_site_from_value(&btc_site_to_value(&btc)), Some(btc));
    }
}
