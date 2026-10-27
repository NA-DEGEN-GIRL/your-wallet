//! meta `connected_sites` ↔ [`ConnectedSite`] (spec/02 §5.3 JSON form, spec/05 §4.1 meaning).
//! The meta module keeps the section as validated JSON values; these helpers convert both ways.

use yw_core::evm::address::{Address, parse_address};
use yw_core::policy::{BrowserOrigin, ConnectedSite};
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
