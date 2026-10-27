//! R-J1 (spec/05 §10.2): every case of the shared `v1-limits.golden.json` (spec/05 §10.3), built
//! by `shape`/`n` exactly as the extension's S2 test does, against `Limits::REQUEST`/`RESPONSE`.
//! Duplicate keys, trailing data and the integer accessor cases of R-J1 are covered verbatim by
//! `tests/strict.rs` (`rejects_non_canonical_input`, `integer_accessors_are_exact`).

use yw_json::{Limits, Value, parse};

const GOLDEN: &str = include_str!("../../../extension/native-host/v1-limits.golden.json");

fn field<'a>(value: &'a Value, key: &str) -> Option<&'a Value> {
    value.as_object()?.get(key)
}

fn integer(value: &Value, key: &str) -> Option<u64> {
    field(value, key)?.as_number()?.as_u64()
}

fn profile(name: &str) -> Option<Limits> {
    match name {
        "request" => Some(Limits::REQUEST),
        "response" => Some(Limits::RESPONSE),
        _ => None,
    }
}

/// The document for one golden case (spec/05 §10.3 table).
fn build(shape: &str, n: usize) -> Option<Vec<u8>> {
    let text = match shape {
        // {"v": X}: n = 1 → null, n ≥ 2 → n − 1 nested arrays; depth n.
        "depth" => {
            let inner = if n == 1 {
                "null".to_owned()
            } else {
                let nested = n.checked_sub(1)?;
                format!("{}{}", "[".repeat(nested), "]".repeat(nested))
            };
            format!("{{\"v\":{inner}}}")
        }
        // {"v":[0,…]} with n elements: items n + 1, nodes n + 3.
        "array" => format!("{{\"v\":[{}]}}", vec!["0"; n].join(",")),
        // Flat root {"k0":0,…}: items n, nodes 2n + 1.
        "object" => {
            let members: Vec<String> = (0..n).map(|index| format!("\"k{index}\":0")).collect();
            format!("{{{}}}", members.join(","))
        }
        // {"v":"a"×(n−8)}: exactly n bytes.
        "bytes" => format!("{{\"v\":\"{}\"}}", "a".repeat(n.checked_sub(8)?)),
        _ => return None,
    };
    Some(text.into_bytes())
}

#[test]
fn r_j1_golden_limits_match_the_profiles() {
    let golden = parse(GOLDEN.as_bytes(), &Limits::REQUEST).unwrap();
    let limits = field(&golden, "limits").unwrap();
    for name in ["request", "response"] {
        let expected = field(limits, name).unwrap();
        let actual = profile(name).unwrap();
        assert_eq!(
            integer(expected, "maxBytes"),
            u64::try_from(actual.max_bytes).ok()
        );
        assert_eq!(
            integer(expected, "maxDepth"),
            Some(u64::from(actual.max_depth))
        );
        assert_eq!(
            integer(expected, "maxNodes"),
            Some(u64::from(actual.max_nodes))
        );
        assert_eq!(
            integer(expected, "maxItems"),
            Some(u64::from(actual.max_items))
        );
    }
}

#[test]
fn r_j1_every_golden_case() {
    let golden = parse(GOLDEN.as_bytes(), &Limits::REQUEST).unwrap();
    let cases = field(&golden, "cases").and_then(Value::as_array).unwrap();
    assert_eq!(cases.len(), 14);
    for case in cases {
        let name = field(case, "profile").and_then(Value::as_str).unwrap();
        let shape = field(case, "shape").and_then(Value::as_str).unwrap();
        let n = usize::try_from(integer(case, "n").unwrap()).unwrap();
        let ok = field(case, "ok").and_then(Value::as_bool).unwrap();
        let bytes = build(shape, n).unwrap();
        if shape == "bytes" {
            assert_eq!(bytes.len(), n);
        }
        let result = parse(&bytes, &profile(name).unwrap());
        assert_eq!(result.is_ok(), ok, "{name} {shape} {n}: {:?}", result.err());
    }
}
