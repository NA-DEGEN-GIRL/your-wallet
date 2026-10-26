//! Strict parser and writer behaviour (spec/01 §2.3, spec/05 §2.9). The shared limits golden
//! (`v1-limits.golden.json`, spec/05 R-J1) is added with the browser milestone.

use yw_json::{Limits, Number, Object, ParseError, Value, parse, to_vec};

const SMALL: Limits = Limits {
    max_bytes: 64,
    max_depth: 2,
    max_nodes: 6,
    max_items: 3,
};

fn ok(text: &str) -> Result<Value, ParseError> {
    parse(text.as_bytes(), &Limits::REQUEST)
}

fn err(text: &[u8]) -> Option<ParseError> {
    parse(text, &Limits::REQUEST).err()
}

#[test]
fn accepts_rfc8259_documents_and_round_trips() {
    let text = r#" { "a" : [1, -0.5e+3, true, false, null, "x\"\\\/\b\f\n\r\t\u00e9\ud83d\ude00"], "b": {} , "c": [] } "#;
    let value = ok(text).unwrap();
    let written = to_vec(&value);
    assert_eq!(
        String::from_utf8(written.clone()).unwrap(),
        "{\"a\":[1,-0.5e+3,true,false,null,\"x\\\"\\\\/\\b\\f\\n\\r\\t\u{e9}\u{1f600}\"],\"b\":{},\"c\":[]}"
    );
    assert_eq!(parse(&written, &Limits::REQUEST).unwrap(), value);
    let object = value.as_object().unwrap();
    assert_eq!(object.keys().collect::<Vec<_>>(), ["a", "b", "c"]);
    assert_eq!(object.len(), 3);
    assert!(object.get("b").unwrap().as_object().unwrap().is_empty());
    assert!(ok("null").unwrap().is_null());
    assert_eq!(ok("\"\\u0001\"").unwrap().as_str(), Some("\u{1}"));
    assert_eq!(to_vec(&ok("\"\\u001f\"").unwrap()), b"\"\\u001f\"");
}

#[test]
fn rejects_non_canonical_input() {
    assert_eq!(
        err(b"\xef\xbb\xbf{}"),
        Some(ParseError::Syntax { offset: 0 })
    );
    assert_eq!(err(b""), Some(ParseError::Syntax { offset: 0 }));
    assert_eq!(err(b"\"a\x01\""), Some(ParseError::Syntax { offset: 2 }));
    assert_eq!(err(b"01"), Some(ParseError::TrailingData { offset: 1 }));
    assert_eq!(err(b"+1"), Some(ParseError::Syntax { offset: 0 }));
    assert_eq!(err(b"NaN"), Some(ParseError::Syntax { offset: 0 }));
    assert_eq!(err(b"Infinity"), Some(ParseError::Syntax { offset: 0 }));
    assert_eq!(err(b"-Infinity"), Some(ParseError::Syntax { offset: 1 }));
    assert_eq!(err(b"1."), Some(ParseError::Syntax { offset: 2 }));
    assert_eq!(err(b"1e"), Some(ParseError::Syntax { offset: 2 }));
    assert_eq!(err(b"[1,]"), Some(ParseError::Syntax { offset: 3 }));
    assert_eq!(err(b"{\"a\":1,}"), Some(ParseError::Syntax { offset: 7 }));
    assert_eq!(err(b"{} x"), Some(ParseError::TrailingData { offset: 3 }));
    assert_eq!(
        err(b"{\"a\":1,\"a\":2}"),
        Some(ParseError::DuplicateKey { offset: 7 })
    );
    assert_eq!(
        err(b"\"\\ud800\""),
        Some(ParseError::LoneSurrogate { offset: 1 })
    );
    assert_eq!(
        err(b"\"\\udc00\""),
        Some(ParseError::LoneSurrogate { offset: 1 })
    );
    assert_eq!(
        err(b"\"\\ud800\\u0041\""),
        Some(ParseError::LoneSurrogate { offset: 1 })
    );
    assert_eq!(err(b"\"\\x\""), Some(ParseError::Syntax { offset: 2 }));
    assert_eq!(err(b"\"\xff\""), Some(ParseError::InvalidUtf8));
    assert_eq!(err(b"tru"), Some(ParseError::Syntax { offset: 0 }));
    assert_eq!(err(b"[1 2]"), Some(ParseError::Syntax { offset: 3 }));
    assert_eq!(err(b"{1:2}"), Some(ParseError::Syntax { offset: 1 }));
}

#[test]
fn limits_follow_the_shared_counting_rules() {
    // depth: root container = 1.
    assert!(parse(b"[[1]]", &SMALL).is_ok());
    assert_eq!(parse(b"[[[1]]]", &SMALL), Err(ParseError::TooDeep));
    // nodes: values + keys. {"a":1,"b":2} = 1 + 2 keys + 2 values = 5.
    assert!(parse(b"{\"a\":1,\"b\":2}", &SMALL).is_ok());
    assert_eq!(
        parse(b"{\"a\":\"x\",\"b\":\"y\",\"c\":\"z\"}", &SMALL),
        Err(ParseError::TooManyNodes)
    );
    // items: elements + members.
    assert!(parse(b"[1,2,3]", &SMALL).is_ok());
    assert_eq!(parse(b"[1,2,3,4]", &SMALL), Err(ParseError::TooManyItems));
    // bytes.
    assert_eq!(parse(&[b' '; 65], &SMALL), Err(ParseError::TooLarge));
    assert_eq!(
        parse(
            b"{\"a\":1}",
            &Limits {
                max_nodes: 2,
                ..SMALL
            }
        ),
        Err(ParseError::TooManyNodes)
    );
}

#[test]
fn integer_accessors_are_exact() {
    let number = |text: &str| Number::from_literal(text).unwrap();
    assert_eq!(number("1.0").as_u64_allow_dot_zero(), Some(1));
    assert_eq!(number("1.0").as_u64(), None);
    for text in ["1e0", "1.00", "-1"] {
        assert_eq!(number(text).as_u64(), None, "{text}");
        assert_eq!(number(text).as_u64_allow_dot_zero(), None, "{text}");
    }
    assert_eq!(number("18446744073709551615").as_u64(), Some(u64::MAX));
    assert_eq!(number("18446744073709551616").as_u64(), None);
    assert_eq!(number("18446744073709551616").as_u64_allow_dot_zero(), None);
    assert_eq!(number("-42").as_i64(), Some(-42));
    assert_eq!(number("-4.2").as_i64(), None);
    assert!(number("12").is_integer());
    assert!(!number("1e2").is_integer());
    assert!(number("-0").is_negative_zero());
    assert!(number("-0.000e7").is_negative_zero());
    assert!(!number("-0.1").is_negative_zero());
    assert!(!number("0").is_negative_zero());
    assert_eq!(number("0.00012000").as_str(), "0.00012000");
    assert_eq!(
        Number::from_literal("01"),
        Err(ParseError::Syntax { offset: 1 })
    );
    assert_eq!(
        Number::from_literal(" 1"),
        Err(ParseError::Syntax { offset: 0 })
    );
}

#[test]
fn error_display_has_no_input_content() {
    let error = err(b"{\"secret-value\":1,\"secret-value\":2}").unwrap();
    assert!(!error.to_string().contains("secret"));
}

#[test]
fn built_objects_keep_order_and_reject_duplicate_keys() {
    let object = Object::from_pairs(vec![
        ("b".to_owned(), Value::Number(Number::from_u64(1))),
        ("a".to_owned(), Value::Bool(true)),
    ])
    .expect("unique keys");
    assert_eq!(to_vec(&Value::Object(object)), br#"{"b":1,"a":true}"#);
    assert!(
        Object::from_pairs(vec![
            ("a".to_owned(), Value::Null),
            ("a".to_owned(), Value::Null),
        ])
        .is_none()
    );
    assert_eq!(Number::from_u64(u64::MAX).as_u64(), Some(u64::MAX));
}
