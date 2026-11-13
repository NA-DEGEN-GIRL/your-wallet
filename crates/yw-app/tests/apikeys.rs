//! ST-2 (`apikeys.dpapi` plaintext, spec/04 §6.3), the pure parts of ST-4 (`template_url`,
//! `mask_url`, the `generate_urls` overwrite rule, spec/04 §2.11.1) and V-DPAPI at the
//! application level (spec/09 §4.1).
//! Names, tokens and keys are fake; URLs are assembled at run time.

use yw_app::apikeys::{
    APIKEYS_ENTROPY, APIKEYS_MAX_ACTIVE, APIKEYS_MAX_ENTRIES, ApiKeys, KeyName, TemplateCred,
    TemplateEntry, is_registered, mask_url, template_entry, template_url,
};
use yw_app::network::{BtcNet, NetworkId, SolCluster};
use yw_app::settings::{EvmChainDef, MAX_CUSTOM_EVM_CHAINS, RpcTemplate, Settings};
use yw_core::evm::chain::SimulationSupport;
use yw_core::secret::Zeroizing;
use yw_win::http::HttpsUrl;

const NAME: &str = "fake-node";
const TOKEN: &str = "FakeToken_0123456789abcdef";
const KEY: &str = "FakeAlchemyKey_0123456789";

fn entry(name: &str, value: &str) -> Vec<u8> {
    let mut out = vec![u8::try_from(name.len()).unwrap_or(u8::MAX)];
    out.extend_from_slice(name.as_bytes());
    out.extend_from_slice(&u16::try_from(value.len()).unwrap_or(u16::MAX).to_be_bytes());
    out.extend_from_slice(value.as_bytes());
    out
}

fn plaintext(entries: &[(String, String)]) -> Vec<u8> {
    let mut out = b"YWAPIK01".to_vec();
    out.push(u8::try_from(entries.len()).unwrap_or(u8::MAX));
    for (name, value) in entries {
        out.extend(entry(name, value));
    }
    out
}

fn all_registered(_: NetworkId) -> bool {
    true
}

fn long_url(tag: usize) -> String {
    let head = format!("https://h{tag}.example/");
    format!("{head}{}", "a".repeat(2_048 - head.len()))
}

fn full_set() -> Vec<(String, String)> {
    let mut entries = vec![
        ("tpl:quicknode".to_owned(), format!("{NAME}:{TOKEN}")),
        ("tpl:alchemy".to_owned(), KEY.to_owned()),
        ("llm".to_owned(), "local-model-key".to_owned()),
    ];
    let mut networks = vec![
        "eip155:1".to_owned(),
        "eip155:11155111".to_owned(),
        "eip155:999".to_owned(),
    ];
    networks.extend((0..32).map(|i| format!("eip155:{}", 10_000 + i)));
    networks.extend(
        [
            "solana:mainnet",
            "solana:devnet",
            "bitcoin:mainnet",
            "bitcoin:testnet4",
        ]
        .map(str::to_owned),
    );
    for (index, network) in networks.into_iter().enumerate() {
        entries.push((format!("rpc:{network}"), long_url(index)));
    }
    entries
}

#[test]
fn forty_two_entries_round_trip() {
    let entries = full_set();
    assert_eq!(entries.len(), 42);
    let bytes = plaintext(&entries);
    assert!(bytes.len() < 131_072);
    let decoded = ApiKeys::decode(&bytes, &all_registered).unwrap();
    assert!(decoded.orphans.is_empty());
    assert_eq!(decoded.keys.encode().as_slice(), bytes.as_slice());
    let endpoints = decoded.keys.endpoints();
    assert_eq!(endpoints.len(), 39);
    assert!(endpoints.iter().all(|(_, url)| url.expose().len() == 2_048));
    assert!(decoded.keys.has(KeyName::TplQuickNode));
}

/// Settings with the most user EVM chains a user can register (spec/04 §2.17).
fn settings_with_all_user_chains() -> Settings {
    let evm_chains = (100_000_u64..)
        .zip(0..MAX_CUSTOM_EVM_CHAINS)
        .map(|(chain_id, index)| EvmChainDef {
            chain_id,
            name: format!("Chain {index}"),
            symbol: "ETH".to_owned(),
            decimals: 18,
            quicknode_subdomain: None,
            alchemy_label: None,
            explorer: None,
            simulation: SimulationSupport::Auto,
            genesis_hash: [0x11; 32],
        })
        .collect();
    Settings {
        evm_chains,
        ..Settings::default()
    }
}

#[test]
fn every_entry_a_user_can_store_is_read_back() {
    // 2026-11-13: the bound was 48, below this full set (49), so the file written for it was
    // rejected as a whole (E-KEY-001) at the next start.
    let settings = settings_with_all_user_chains();
    let registered = |network: NetworkId| is_registered(&settings, network);
    let mut networks: Vec<NetworkId> = settings
        .registered_evm()
        .into_iter()
        .map(NetworkId::Eip155)
        .collect();
    networks.extend([
        NetworkId::Solana(SolCluster::Mainnet),
        NetworkId::Solana(SolCluster::Devnet),
        NetworkId::Bitcoin(BtcNet::Mainnet),
        NetworkId::Bitcoin(BtcNet::Testnet4),
        NetworkId::Zcash(yw_core::zec::ZecNetwork::Mainnet),
        NetworkId::Zcash(yw_core::zec::ZecNetwork::Testnet),
    ]);
    let mut keys = ApiKeys::default();
    keys.set_quicknode(NAME, TOKEN);
    keys.set_alchemy(KEY);
    keys.set_llm("local-model-key", Some("llm.example:8443"));
    for (index, network) in networks.iter().enumerate() {
        keys.set_rpc(*network, &HttpsUrl::parse(&long_url(index)).unwrap());
    }
    assert_eq!(keys.names().len(), APIKEYS_MAX_ACTIVE);
    assert_eq!(APIKEYS_MAX_ACTIVE, 49);
    let bytes = keys.encode();
    assert_eq!(usize::from(bytes[8]), APIKEYS_MAX_ACTIVE);
    assert!(bytes.len() < 131_072);
    let decoded = ApiKeys::decode(&bytes, &registered).unwrap();
    assert!(decoded.orphans.is_empty());
    assert_eq!(decoded.keys.names().len(), APIKEYS_MAX_ACTIVE);
    assert_eq!(decoded.keys.endpoints().len(), networks.len());
    assert_eq!(decoded.keys.llm_host(), Some("llm.example:8443"));
    assert_eq!(decoded.keys.encode().as_slice(), bytes.as_slice());

    // The rest of the bound keeps dormant entries (an orphan and a newer version's names) next to
    // the full set; past it the last dormant ones are left out, never an active one.
    let mut grown = bytes.to_vec();
    let dormant = APIKEYS_MAX_ENTRIES - APIKEYS_MAX_ACTIVE;
    grown[8] = u8::try_from(APIKEYS_MAX_ENTRIES).unwrap();
    grown.extend(entry("rpc:eip155:84532", &long_url(90)));
    for index in 1..dormant {
        grown.extend(entry(&format!("tpl:future{index}"), KEY));
    }
    assert!(grown.len() < 131_072);
    let mut kept = ApiKeys::decode(&grown, &registered).unwrap().keys;
    assert_eq!(kept.dormant_names().len(), dormant);
    assert_eq!(kept.encode().as_slice(), grown.as_slice());
    let mut over = grown.clone();
    over[8] = u8::try_from(APIKEYS_MAX_ENTRIES + 1).unwrap();
    over.extend(entry("tpl:future99", KEY));
    assert!(ApiKeys::decode(&over, &registered).is_err());
    kept.remove(KeyName::Llm);
    kept.set_llm("local-model-key", Some("llm.example:8443"));
    kept.set_rpc(
        NetworkId::Eip155(100_000),
        &HttpsUrl::parse("https://replaced.example/").unwrap(),
    );
    let rewritten = kept.encode();
    assert_eq!(usize::from(rewritten[8]), APIKEYS_MAX_ENTRIES);
    let again = ApiKeys::decode(&rewritten, &registered).unwrap().keys;
    assert_eq!(again.names().len(), APIKEYS_MAX_ACTIVE);
    assert_eq!(again.dormant_names().len(), dormant);
}

#[test]
fn format_errors_reject_everything() {
    let good = full_set();
    let mut cases: Vec<Vec<u8>> = Vec::new();
    // 2026-11-13: the bound is 56 (48 before).
    let mut count_57 = plaintext(&good[..1]);
    count_57[8] = 57;
    cases.push(count_57);
    cases.push(plaintext(&[
        ("llm".to_owned(), "a".to_owned()),
        ("llm".to_owned(), "b".to_owned()),
    ]));
    cases.push(plaintext(&[("rpc:eip155:01".to_owned(), long_url(1))]));
    cases.push(plaintext(&[(
        format!("rpc:eip155:{}", "1".repeat(22)),
        long_url(1),
    )]));
    // Names outside `[a-z0-9:._-]` and malformed names of a known family are damage, not a newer
    // version's entry.
    cases.push(plaintext(&[("TPL:infura".to_owned(), KEY.to_owned())]));
    cases.push(plaintext(&[("tpl infura".to_owned(), KEY.to_owned())]));
    cases.push(plaintext(&[("rpc:eip155:abc".to_owned(), long_url(1))]));
    cases.push(plaintext(&[("rpc:".to_owned(), long_url(1))]));
    cases.push(plaintext(&[
        ("tpl:infura".to_owned(), KEY.to_owned()),
        ("tpl:infura".to_owned(), KEY.to_owned()),
    ]));
    cases.push(plaintext(&[(
        "rpc:eip155:84532".to_owned(),
        "http://h.example/".to_owned(),
    )]));
    cases.push(plaintext(&[(
        "tpl:quicknode".to_owned(),
        format!("{NAME}{TOKEN}"),
    )]));
    cases.push(plaintext(&[(
        "tpl:quicknode".to_owned(),
        format!("Fake-Node:{TOKEN}"),
    )]));
    cases.push(plaintext(&[(
        "tpl:quicknode".to_owned(),
        format!("{NAME}:{}", &TOKEN[..15]),
    )]));
    cases.push(plaintext(&[(
        "rpc:eip155:1".to_owned(),
        "http://h.example/".to_owned(),
    )]));
    let mut trailing = plaintext(&good[..2]);
    trailing.push(0);
    cases.push(trailing);
    cases.push(b"YWAPIK02\x00".to_vec());
    for (index, case) in cases.iter().enumerate() {
        assert!(
            ApiKeys::decode(case, &all_registered).is_err(),
            "case {index}"
        );
    }
    assert!(ApiKeys::decode(b"YWAPIK01\x00", &all_registered).is_ok());
}

#[test]
fn unregistered_rpc_entries_are_orphans_kept_on_save() {
    let settings = Settings::default();
    let registered = |network: NetworkId| yw_app::apikeys::is_registered(&settings, network);
    let bytes = plaintext(&[
        ("rpc:eip155:10".to_owned(), long_url(1)),
        ("rpc:eip155:11155111".to_owned(), long_url(2)),
    ]);
    let decoded = ApiKeys::decode(&bytes, &registered).unwrap();
    assert_eq!(decoded.orphans, [KeyName::Rpc(NetworkId::Eip155(10))]);
    // Not an endpoint while unregistered, but written back (spec/04 §6.6).
    assert_eq!(
        decoded.keys.names(),
        [KeyName::Rpc(NetworkId::Eip155(11_155_111))]
    );
    assert_eq!(decoded.keys.endpoints().len(), 1);
    assert_eq!(decoded.keys.dormant_names(), ["rpc:eip155:10"]);
    let saved = decoded.keys.encode();
    let again = ApiKeys::decode(&saved, &all_registered).unwrap();
    assert_eq!(
        again.keys.names(),
        [
            KeyName::Rpc(NetworkId::Eip155(11_155_111)),
            KeyName::Rpc(NetworkId::Eip155(10))
        ]
    );
    assert_eq!(
        again.keys.rpc_url(NetworkId::Eip155(10)).unwrap().expose(),
        long_url(1)
    );
    // Setting the network again replaces the dormant entry; removing it removes it.
    let mut keys = ApiKeys::decode(&bytes, &registered).unwrap().keys;
    let fresh = HttpsUrl::parse("https://fresh.example/rpc").unwrap();
    keys.set_rpc(NetworkId::Eip155(10), &fresh);
    assert!(keys.dormant_names().is_empty());
    let replaced = ApiKeys::decode(&keys.encode(), &all_registered).unwrap();
    assert_eq!(
        replaced
            .keys
            .rpc_url(NetworkId::Eip155(10))
            .unwrap()
            .expose(),
        fresh.expose()
    );
    let mut keys = ApiKeys::decode(&bytes, &registered).unwrap().keys;
    assert!(keys.remove(KeyName::Rpc(NetworkId::Eip155(10))));
    assert!(keys.dormant_names().is_empty());
    let mut keys = ApiKeys::decode(&bytes, &registered).unwrap().keys;
    assert_eq!(keys.prune_dormant(), 1);
    assert_eq!(
        ApiKeys::decode(&keys.encode(), &all_registered)
            .unwrap()
            .keys
            .names(),
        [KeyName::Rpc(NetworkId::Eip155(11_155_111))]
    );
}

#[test]
fn unknown_entry_names_are_kept_verbatim() {
    // A newer version's entries: opaque values (not UTF-8 here), never used, written back.
    let mut entries = full_set();
    entries.truncate(10);
    let mut bytes = plaintext(&entries);
    let opaque: [u8; 4] = [0xff, 0x00, 0x80, 0x7f];
    bytes[8] += 2;
    bytes.extend(entry("tpl:infura", KEY));
    bytes.push(u8::try_from("rpc:solana:testnet".len()).unwrap());
    bytes.extend_from_slice(b"rpc:solana:testnet");
    bytes.extend_from_slice(&4_u16.to_be_bytes());
    bytes.extend_from_slice(&opaque);
    let decoded = ApiKeys::decode(&bytes, &all_registered).unwrap();
    assert!(decoded.orphans.is_empty());
    assert_eq!(
        decoded.keys.dormant_names(),
        ["tpl:infura", "rpc:solana:testnet"]
    );
    assert_eq!(decoded.keys.names().len(), 10);
    assert_eq!(decoded.keys.encode().as_slice(), bytes.as_slice());
    // Dormant entries give way to the 56-entry bound; the active entries always fit.
    let mut keys = ApiKeys::decode(&bytes, &all_registered).unwrap().keys;
    for index in 0..46_u64 {
        keys.set_rpc(
            NetworkId::Eip155(20_000 + index),
            &HttpsUrl::parse(&format!("https://h{index}.example/")).unwrap(),
        );
    }
    let capped = keys.encode();
    assert_eq!(usize::from(capped[8]), APIKEYS_MAX_ENTRIES);
    let again = ApiKeys::decode(&capped, &all_registered).unwrap();
    assert_eq!(again.keys.names().len(), APIKEYS_MAX_ENTRIES);
    assert!(again.keys.dormant_names().is_empty());
}

#[test]
fn pasted_quicknode_urls_give_name_and_token() {
    use yw_app::apikeys::{QuickNodeField, parse_quicknode_url, quicknode_credentials};
    let host = ".quiknode.pro/";
    let mainnet = format!("https://{NAME}{host}{TOKEN}/");
    let sepolia = format!("  https://Fake-Node.ethereum-sepolia{host}{TOKEN}/  ");
    let hyperevm = format!("https://{NAME}.hype-mainnet{host}{TOKEN}/nanoreth");
    let wss = format!("wss://{NAME}.btc-testnet4{host}{TOKEN}/");
    for url in [&mainnet, &sepolia, &hyperevm, &wss] {
        let (name, token) = parse_quicknode_url(url).unwrap();
        assert_eq!(name, NAME, "{url}");
        assert_eq!(token.as_str(), TOKEN, "{url}");
    }
    for bad in [
        format!("http://{NAME}{host}{TOKEN}/"),
        format!("https://{NAME}.a.b{host}{TOKEN}/"),
        format!("https://{NAME}.quiknode.pro:8443/{TOKEN}/"),
        format!("https://{NAME}{host}short/"),
        format!("https://{NAME}.g.alchemy.com/v2/{KEY}"),
        format!("https://{NAME}{host}"),
        NAME.to_owned(),
    ] {
        assert!(parse_quicknode_url(&bad).is_none(), "{bad}");
    }
    // Either field may hold the whole URL.
    for (name_field, token_field) in [
        (mainnet.as_str(), ""),
        ("", hyperevm.as_str()),
        (sepolia.as_str(), TOKEN),
        ("FAKE-NODE", mainnet.as_str()),
        (mainnet.as_str(), mainnet.as_str()),
        (" Fake-Node ", TOKEN),
    ] {
        let (name, token) = quicknode_credentials(name_field, token_field).unwrap();
        assert_eq!((name.as_str(), token.as_str()), (NAME, TOKEN));
    }
    assert_eq!(
        quicknode_credentials(&mainnet, "OtherToken_0123456789abcdef"),
        Err(QuickNodeField::Token)
    );
    assert_eq!(
        quicknode_credentials("other-node", &mainnet),
        Err(QuickNodeField::Name)
    );
    assert_eq!(
        quicknode_credentials("fake_node", TOKEN),
        Err(QuickNodeField::Name)
    );
    assert_eq!(
        quicknode_credentials(NAME, &TOKEN[..15]),
        Err(QuickNodeField::Token)
    );
    assert_eq!(QuickNodeField::Token.label(), "토큰");
}

#[test]
fn dpapi_round_trip_of_the_plaintext() {
    let bytes = plaintext(&full_set());
    let blob = yw_win::dpapi::protect(&bytes, APIKEYS_ENTROPY).unwrap();
    let plain = yw_win::dpapi::unprotect(&blob, APIKEYS_ENTROPY).unwrap();
    assert_eq!(plain.as_slice(), bytes.as_slice());
    assert!(yw_win::dpapi::unprotect(&blob, b"other").is_err());
    let mut tampered = blob;
    let last = tampered.len() - 1;
    tampered[last] ^= 0x80;
    assert!(yw_win::dpapi::unprotect(&tampered, APIKEYS_ENTROPY).is_err());
}

fn quicknode() -> TemplateCred {
    TemplateCred::QuickNode {
        name: NAME.to_owned(),
        token: Zeroizing::new(TOKEN.to_owned()),
    }
}

fn alchemy() -> TemplateCred {
    TemplateCred::Alchemy {
        key: Zeroizing::new(KEY.to_owned()),
    }
}

fn url_for(template: RpcTemplate, cred: &TemplateCred, network: NetworkId) -> Option<HttpsUrl> {
    let settings = Settings::default();
    template_url(
        template,
        cred,
        template_entry(template, network, &settings).as_ref(),
    )
}

#[test]
fn template_urls_follow_the_tables() {
    let qn = quicknode();
    let al = alchemy();
    let host = ".quiknode.pro/";
    assert_eq!(
        url_for(RpcTemplate::QuickNode, &qn, NetworkId::Eip155(1))
            .unwrap()
            .expose(),
        format!("https://{NAME}{host}{TOKEN}/")
    );
    assert_eq!(
        url_for(RpcTemplate::QuickNode, &qn, NetworkId::Eip155(11_155_111))
            .unwrap()
            .expose(),
        format!("https://{NAME}.ethereum-sepolia{host}{TOKEN}/")
    );
    assert_eq!(
        url_for(RpcTemplate::QuickNode, &qn, NetworkId::Eip155(999))
            .unwrap()
            .expose(),
        format!("https://{NAME}.hype-mainnet{host}{TOKEN}/nanoreth")
    );
    assert_eq!(
        url_for(
            RpcTemplate::QuickNode,
            &qn,
            NetworkId::Bitcoin(BtcNet::Testnet4)
        )
        .unwrap()
        .expose(),
        format!("https://{NAME}.btc-testnet4{host}{TOKEN}/")
    );
    let alchemy_path = ".g.alchemy.com/v2/";
    assert_eq!(
        url_for(
            RpcTemplate::Alchemy,
            &al,
            NetworkId::Solana(SolCluster::Devnet)
        )
        .unwrap()
        .expose(),
        format!("https://solana-devnet{alchemy_path}{KEY}")
    );
    assert_eq!(
        url_for(RpcTemplate::Alchemy, &al, NetworkId::Eip155(11_155_111))
            .unwrap()
            .expose(),
        format!("https://eth-sepolia{alchemy_path}{KEY}")
    );
    // The L2/L1 built-ins of 2026-11-06 (spec/03 §1.1: QuickNode and Alchemy docs examples).
    for (chain_id, subdomain, label) in [
        (42_161, "arbitrum-mainnet", "arb-mainnet"),
        (8_453, "base-mainnet", "base-mainnet"),
        (56, "bsc", "bnb-mainnet"),
        (4_663, "robinhood-mainnet", "robinhood-mainnet"),
    ] {
        assert_eq!(
            url_for(RpcTemplate::QuickNode, &qn, NetworkId::Eip155(chain_id))
                .unwrap()
                .expose(),
            format!("https://{NAME}.{subdomain}{host}{TOKEN}/"),
            "{chain_id}"
        );
        assert_eq!(
            url_for(RpcTemplate::Alchemy, &al, NetworkId::Eip155(chain_id))
                .unwrap()
                .expose(),
            format!("https://{label}{alchemy_path}{KEY}"),
            "{chain_id}"
        );
    }
    assert!(url_for(RpcTemplate::QuickNode, &qn, NetworkId::Eip155(84_532)).is_none());
    assert!(url_for(RpcTemplate::Manual, &qn, NetworkId::Eip155(1)).is_none());
    assert!(url_for(RpcTemplate::Alchemy, &qn, NetworkId::Eip155(1)).is_none());
    assert_eq!(
        template_entry(
            RpcTemplate::QuickNode,
            NetworkId::Eip155(1),
            &Settings::default()
        ),
        Some(TemplateEntry::QuickNode {
            subdomain: None,
            path: None
        })
    );
}

#[test]
fn masked_urls_hide_every_secret_part() {
    for (template, cred, network) in [
        (
            RpcTemplate::QuickNode,
            quicknode(),
            NetworkId::Eip155(11_155_111),
        ),
        (
            RpcTemplate::Alchemy,
            alchemy(),
            NetworkId::Solana(SolCluster::Devnet),
        ),
    ] {
        let url = url_for(template, &cred, network).unwrap();
        let masked = mask_url(&url);
        for secret in [NAME, TOKEN, KEY, "ethereum-sepolia", "solana-devnet"] {
            assert!(!masked.contains(secret), "{masked}");
        }
        assert!(masked.starts_with("https://\u{25CF}"));
    }
    let quick = url_for(RpcTemplate::QuickNode, &quicknode(), NetworkId::Eip155(1)).unwrap();
    assert_eq!(
        mask_url(&quick),
        "https://\u{25CF}\u{25CF}\u{25CF}\u{25CF}.quiknode.pro/\u{25CF}\u{25CF}\u{25CF}\u{25CF}"
    );
    let other = HttpsUrl::parse("https://rpc.example.org/secret/path").unwrap();
    assert_eq!(
        mask_url(&other),
        "https://\u{25CF}\u{25CF}\u{25CF}\u{25CF}/\u{25CF}\u{25CF}\u{25CF}\u{25CF}"
    );
}

#[test]
fn generation_keeps_existing_urls_unless_overwrite_is_checked() {
    let settings = Settings::default();
    let qn = quicknode();
    let mainnet = NetworkId::Eip155(1);
    let sepolia = NetworkId::Eip155(11_155_111);
    let hyperevm = NetworkId::Eip155(999);
    let manual = HttpsUrl::parse("https://manual.example/rpc").unwrap();
    let mut keys = ApiKeys::default();
    keys.set_rpc(sepolia, &manual);
    let before = keys.encode();
    let targets = [mainnet, sepolia, hyperevm];

    let written = keys.generate_urls(RpcTemplate::QuickNode, &qn, &settings, &targets, false);
    assert_eq!(written, vec![mainnet, hyperevm]);
    assert_eq!(keys.rpc_url(sepolia).unwrap().expose(), manual.expose());
    assert_ne!(keys.encode().as_slice(), before.as_slice());

    let unchanged = keys.encode();
    assert!(
        keys.generate_urls(RpcTemplate::QuickNode, &qn, &settings, &targets, false)
            .is_empty()
    );
    assert_eq!(keys.encode().as_slice(), unchanged.as_slice());

    let written = keys.generate_urls(RpcTemplate::QuickNode, &qn, &settings, &targets, true);
    assert_eq!(written, vec![mainnet, sepolia, hyperevm]);
    assert_eq!(
        keys.rpc_url(sepolia).unwrap().expose(),
        url_for(RpcTemplate::QuickNode, &qn, sepolia)
            .unwrap()
            .expose()
    );

    let mut empty = ApiKeys::default();
    assert!(
        empty
            .generate_urls(RpcTemplate::Manual, &qn, &settings, &targets, true)
            .is_empty()
    );
    assert!(empty.endpoints().is_empty());
}

/// spec/06 §2.1: the LLM key is stored with the endpoint `host[:port]` it was entered for
/// (`llm:host`), survives a round trip, and goes away with the key.
#[test]
fn llm_key_is_bound_to_its_endpoint_host() {
    let mut keys = ApiKeys::default();
    keys.set_llm("local-model-key", Some("api.example.org"));
    assert_eq!(keys.llm_key(), Some("local-model-key"));
    assert_eq!(keys.llm_host(), Some("api.example.org"));
    let again = ApiKeys::decode(&keys.encode(), &all_registered)
        .unwrap()
        .keys;
    assert_eq!(again.llm_key(), Some("local-model-key"));
    assert_eq!(again.llm_host(), Some("api.example.org"));
    assert!(again.names().contains(&KeyName::LlmHost));
    // A bound key is never re-bound by the legacy rule.
    let mut bound = again;
    assert!(!bound.bind_llm_host("other.example.org"));
    assert_eq!(bound.llm_host(), Some("api.example.org"));
    // Entering the key again binds it to the new host; without a host it is stored unbound.
    bound.set_llm("second-key", Some("127.0.0.1:11434"));
    assert_eq!(bound.llm_host(), Some("127.0.0.1:11434"));
    bound.set_llm("third-key", None);
    assert_eq!(bound.llm_host(), None);
    assert!(!bound.has(KeyName::LlmHost));
    // Deleting the key deletes its binding.
    bound.set_llm("fourth-key", Some("api.example.org"));
    assert!(bound.remove(KeyName::Llm));
    assert!(!bound.has(KeyName::LlmHost));
    assert_eq!(bound.llm_host(), None);
    // A malformed host value is a format error like any other known entry.
    let bad = plaintext(&[
        ("llm".to_owned(), "k".to_owned()),
        ("llm:host".to_owned(), "API.example.org/path".to_owned()),
    ]);
    assert!(ApiKeys::decode(&bad, &all_registered).is_err());
}

/// spec/06 §2.1 compatibility: a key written by an older version has no `llm:host`; it decodes
/// unbound and the legacy rule binds it once.
#[test]
fn legacy_llm_key_without_a_host_binds_once() {
    let old = plaintext(&[("llm".to_owned(), "legacy-key".to_owned())]);
    let mut keys = ApiKeys::decode(&old, &all_registered).unwrap().keys;
    assert_eq!(keys.llm_key(), Some("legacy-key"));
    assert_eq!(keys.llm_host(), None);
    assert!(keys.bind_llm_host("api.example.org"));
    assert_eq!(keys.llm_host(), Some("api.example.org"));
    assert!(!keys.bind_llm_host("other.example.org"));
    let saved = ApiKeys::decode(&keys.encode(), &all_registered)
        .unwrap()
        .keys;
    assert_eq!(saved.llm_host(), Some("api.example.org"));
    // No key: nothing to bind.
    assert!(!ApiKeys::default().bind_llm_host("api.example.org"));
}
