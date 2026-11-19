//! `yw_engine::services` (spec/15 §11.2, §11.4 S4 P2): the one-shot LLM factory handed to
//! `ExplainService::start` calls the reusable `Services::llm` exactly when it is called (never
//! when it is made), and `Debug` names the parts present and the platform word only. No socket,
//! no session: the factories here make nothing.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use yw_engine::services::Services;
use yw_platform::http::EndpointUrl;

fn endpoint() -> Option<EndpointUrl> {
    yw_engine::explain::config::parse_endpoint("http://127.0.0.1:9/v1/chat/completions")
        .map(|endpoint| endpoint.url)
}

#[test]
fn the_one_shot_llm_factory_calls_the_services_factory_only_when_run() {
    let calls = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&calls);
    let services = Services {
        llm: Arc::new(move |_endpoint| {
            counted.fetch_add(1, Ordering::SeqCst);
            None
        }),
        walletconnect: None,
        ua_platform: "test",
    };
    let url = endpoint().unwrap();
    let factory = services.llm_factory();
    assert_eq!(calls.load(Ordering::SeqCst), 0, "making it calls nothing");
    assert!(factory(&url).is_none());
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    let again = services.llm_factory();
    assert!(again(&url).is_none());
    assert!((services.llm)(&url).is_none());
    assert_eq!(calls.load(Ordering::SeqCst), 3);
}

#[test]
fn services_debug_names_parts_and_the_platform_word_only() {
    let services = Services {
        llm: Arc::new(|_endpoint| None),
        walletconnect: None,
        ua_platform: "test",
    };
    assert_eq!(
        format!("{services:?}"),
        r#"Services { walletconnect: false, ua_platform: "test", .. }"#
    );
}
