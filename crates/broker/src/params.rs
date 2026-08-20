use serde_json::{Map, Value};
use wallet_model::{Address20, BrowserOrigin, Hash32, U256};

use crate::{BrokerError, MAX_PUBLIC_MESSAGE_BYTES, ProviderMethod};

const PUBLIC_ENVELOPE_OVERHEAD: usize = 256;
const MAX_JSON_DEPTH: usize = 32;
const MAX_JSON_NODES: usize = 16_384;
const MAX_JSON_OBJECT_MEMBERS: usize = 128;
const MAX_JSON_ARRAY_ITEMS: usize = 4_096;
const MAX_JSON_STRING_BYTES: usize = 524_288;
const MAX_AGGREGATE_STRING_BYTES: usize = 786_432;
const MAX_CALL_DATA_BYTES: usize = 131_072;
const MAX_PERSONAL_MESSAGE_BYTES: usize = 65_536;
const MAX_TYPED_DATA_BYTES: usize = 131_072;
const MAX_ACCESS_LIST_ENTRIES: usize = 256;
const MAX_ACCESS_LIST_STORAGE_KEYS: usize = 256;
const MAX_LOG_ADDRESSES: usize = 32;
const MAX_LOG_TOPIC_ALTERNATIVES: usize = 32;
const MAX_LOG_BLOCK_RANGE: u64 = 10_000;
const MAX_FEE_HISTORY_BLOCKS: u64 = 1_024;
const MAX_FEE_HISTORY_PERCENTILES: usize = 100;
const MAX_URL_BYTES: usize = 2_048;
const MAX_URLS_PER_FIELD: usize = 8;

/// Validates one public provider request using canonical bytes computed locally.
pub(crate) fn validate(method: &str, params: &Value) -> Result<ProviderMethod, BrokerError> {
    let provider_method = ProviderMethod::parse(method).ok_or(BrokerError::UnsupportedMethod)?;
    validate_json_limits(params)?;

    let canonical = serde_json::to_vec(&(method, params)).map_err(|_| BrokerError::Malformed)?;
    let accounted_size = canonical
        .len()
        .checked_add(PUBLIC_ENVELOPE_OVERHEAD)
        .ok_or(BrokerError::LimitExceeded)?;
    if accounted_size > MAX_PUBLIC_MESSAGE_BYTES {
        return Err(BrokerError::LimitExceeded);
    }

    validate_schema(provider_method, params)?;
    Ok(provider_method)
}

#[derive(Default)]
struct JsonBudget {
    nodes: usize,
    string_bytes: usize,
}

fn validate_json_limits(value: &Value) -> Result<(), BrokerError> {
    visit_json(value, 0, &mut JsonBudget::default())
}

fn visit_json(value: &Value, depth: usize, budget: &mut JsonBudget) -> Result<(), BrokerError> {
    if depth > MAX_JSON_DEPTH {
        return Err(BrokerError::LimitExceeded);
    }
    budget.nodes = budget
        .nodes
        .checked_add(1)
        .ok_or(BrokerError::LimitExceeded)?;
    if budget.nodes > MAX_JSON_NODES {
        return Err(BrokerError::LimitExceeded);
    }

    match value {
        Value::String(text) => add_string_budget(text, budget),
        Value::Array(values) => {
            if values.len() > MAX_JSON_ARRAY_ITEMS {
                return Err(BrokerError::LimitExceeded);
            }
            for item in values {
                visit_json(item, depth.saturating_add(1), budget)?;
            }
            Ok(())
        }
        Value::Object(values) => {
            if values.len() > MAX_JSON_OBJECT_MEMBERS {
                return Err(BrokerError::LimitExceeded);
            }
            for (key, item) in values {
                add_string_budget(key, budget)?;
                visit_json(item, depth.saturating_add(1), budget)?;
            }
            Ok(())
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => Ok(()),
    }
}

fn add_string_budget(text: &str, budget: &mut JsonBudget) -> Result<(), BrokerError> {
    if text.len() > MAX_JSON_STRING_BYTES || text.chars().any(char::is_control) {
        return Err(BrokerError::LimitExceeded);
    }
    budget.string_bytes = budget
        .string_bytes
        .checked_add(text.len())
        .ok_or(BrokerError::LimitExceeded)?;
    if budget.string_bytes > MAX_AGGREGATE_STRING_BYTES {
        return Err(BrokerError::LimitExceeded);
    }
    Ok(())
}

fn validate_schema(method: ProviderMethod, params: &Value) -> Result<(), BrokerError> {
    match method {
        ProviderMethod::RequestAccounts
        | ProviderMethod::Accounts
        | ProviderMethod::ChainId
        | ProviderMethod::NetVersion
        | ProviderMethod::BlockNumber
        | ProviderMethod::GasPrice
        | ProviderMethod::MaxPriorityFeePerGas
        | ProviderMethod::GetPermissions => expect_empty(params),
        ProviderMethod::GetBalance
        | ProviderMethod::GetCode
        | ProviderMethod::GetTransactionCount => validate_address_and_block(params),
        ProviderMethod::GetStorageAt => validate_storage_at(params),
        ProviderMethod::Call | ProviderMethod::EstimateGas => validate_call(params),
        ProviderMethod::FeeHistory => validate_fee_history(params),
        ProviderMethod::GetBlockByHash => validate_block_by_hash(params),
        ProviderMethod::GetBlockByNumber => validate_block_by_number(params),
        ProviderMethod::GetTransactionByHash | ProviderMethod::GetTransactionReceipt => {
            validate_single_hash(params)
        }
        ProviderMethod::GetLogs => validate_logs(params),
        ProviderMethod::SendTransaction => validate_send_transaction(params),
        ProviderMethod::PersonalSign => validate_personal_sign(params),
        ProviderMethod::SignTypedDataV4 => validate_typed_data(params),
        ProviderMethod::AddEthereumChain => validate_add_chain(params),
        ProviderMethod::SwitchEthereumChain => validate_switch_chain(params),
        ProviderMethod::WatchAsset => validate_watch_asset(params),
        ProviderMethod::GetCapabilities => validate_get_capabilities(params),
        ProviderMethod::RequestPermissions => validate_permissions(params),
    }
}

fn params_array(params: &Value) -> Result<&[Value], BrokerError> {
    params
        .as_array()
        .map(Vec::as_slice)
        .ok_or(BrokerError::Malformed)
}

fn exact_params(params: &Value, expected: usize) -> Result<&[Value], BrokerError> {
    let values = params_array(params)?;
    if values.len() != expected {
        return Err(BrokerError::Malformed);
    }
    Ok(values)
}

fn expect_empty(params: &Value) -> Result<(), BrokerError> {
    exact_params(params, 0).map(|_| ())
}

fn object(value: &Value) -> Result<&Map<String, Value>, BrokerError> {
    value.as_object().ok_or(BrokerError::Malformed)
}

fn require_exact_keys(
    object: &Map<String, Value>,
    required: &[&str],
    optional: &[&str],
) -> Result<(), BrokerError> {
    let expected_max = required
        .len()
        .checked_add(optional.len())
        .ok_or(BrokerError::LimitExceeded)?;
    if object.len() < required.len()
        || object.len() > expected_max
        || required.iter().any(|key| !object.contains_key(*key))
        || object
            .keys()
            .any(|key| !required.contains(&key.as_str()) && !optional.contains(&key.as_str()))
    {
        return Err(BrokerError::Malformed);
    }
    Ok(())
}

fn string(value: &Value, maximum: usize) -> Result<&str, BrokerError> {
    let text = value.as_str().ok_or(BrokerError::Malformed)?;
    if text.len() > maximum || text.chars().any(char::is_control) {
        return Err(BrokerError::LimitExceeded);
    }
    Ok(text)
}

fn address(value: &Value) -> Result<Address20, BrokerError> {
    Address20::from_fixed_hex(string(value, 42)?).map_err(|_| BrokerError::Malformed)
}

fn hash(value: &Value) -> Result<Hash32, BrokerError> {
    Hash32::from_fixed_hex(string(value, 66)?).map_err(|_| BrokerError::Malformed)
}

fn quantity(value: &Value) -> Result<U256, BrokerError> {
    U256::from_canonical_quantity(string(value, 66)?).map_err(|_| BrokerError::Malformed)
}

fn quantity_u64(value: &Value) -> Result<u64, BrokerError> {
    let parsed = quantity(value)?;
    let bytes = parsed.as_be_bytes();
    if bytes[..24].iter().any(|byte| *byte != 0) {
        return Err(BrokerError::LimitExceeded);
    }
    let tail: [u8; 8] = bytes[24..].try_into().map_err(|_| BrokerError::Malformed)?;
    Ok(u64::from_be_bytes(tail))
}

fn hex_data(value: &Value, maximum_bytes: usize) -> Result<(), BrokerError> {
    let maximum_chars = maximum_bytes
        .checked_mul(2)
        .and_then(|size| size.checked_add(2))
        .ok_or(BrokerError::LimitExceeded)?;
    let text = string(value, maximum_chars)?;
    let Some(digits) = text.strip_prefix("0x") else {
        return Err(BrokerError::Malformed);
    };
    if digits.len() % 2 != 0
        || !digits
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(BrokerError::Malformed);
    }
    Ok(())
}

fn validate_block_reference(value: &Value) -> Result<(), BrokerError> {
    let text = string(value, 66)?;
    if matches!(
        text,
        "latest" | "earliest" | "pending" | "safe" | "finalized"
    ) {
        return Ok(());
    }
    quantity(value).map(|_| ())
}

fn validate_address_and_block(params: &Value) -> Result<(), BrokerError> {
    let values = exact_params(params, 2)?;
    address(&values[0])?;
    validate_block_reference(&values[1])
}

fn validate_storage_at(params: &Value) -> Result<(), BrokerError> {
    let values = exact_params(params, 3)?;
    address(&values[0])?;
    quantity(&values[1])?;
    validate_block_reference(&values[2])
}

fn validate_call(params: &Value) -> Result<(), BrokerError> {
    let values = params_array(params)?;
    if !(1..=2).contains(&values.len()) {
        return Err(BrokerError::Malformed);
    }
    validate_transaction_object(&values[0], false)?;
    if let Some(block) = values.get(1) {
        validate_block_reference(block)?;
    }
    Ok(())
}

fn validate_fee_history(params: &Value) -> Result<(), BrokerError> {
    let values = exact_params(params, 3)?;
    let block_count = quantity_u64(&values[0])?;
    if block_count == 0 || block_count > MAX_FEE_HISTORY_BLOCKS {
        return Err(BrokerError::LimitExceeded);
    }
    validate_block_reference(&values[1])?;
    let percentiles = values[2].as_array().ok_or(BrokerError::Malformed)?;
    if percentiles.len() > MAX_FEE_HISTORY_PERCENTILES {
        return Err(BrokerError::LimitExceeded);
    }
    let mut previous = None;
    for value in percentiles {
        let percentile = value.as_f64().ok_or(BrokerError::Malformed)?;
        if !(0.0..=100.0).contains(&percentile) || previous.is_some_and(|last| percentile <= last) {
            return Err(BrokerError::Malformed);
        }
        previous = Some(percentile);
    }
    Ok(())
}

fn validate_block_by_hash(params: &Value) -> Result<(), BrokerError> {
    let values = exact_params(params, 2)?;
    hash(&values[0])?;
    values[1].as_bool().ok_or(BrokerError::Malformed)?;
    Ok(())
}

fn validate_block_by_number(params: &Value) -> Result<(), BrokerError> {
    let values = exact_params(params, 2)?;
    validate_block_reference(&values[0])?;
    values[1].as_bool().ok_or(BrokerError::Malformed)?;
    Ok(())
}

fn validate_single_hash(params: &Value) -> Result<(), BrokerError> {
    let values = exact_params(params, 1)?;
    hash(&values[0]).map(|_| ())
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum LogBlockReference {
    Number(u64),
    Tag(String),
}

fn log_block_reference(value: &Value) -> Result<LogBlockReference, BrokerError> {
    let text = string(value, 66)?;
    if matches!(
        text,
        "latest" | "earliest" | "pending" | "safe" | "finalized"
    ) {
        return Ok(LogBlockReference::Tag(text.to_owned()));
    }
    Ok(LogBlockReference::Number(quantity_u64(value)?))
}

fn validate_logs(params: &Value) -> Result<(), BrokerError> {
    let values = exact_params(params, 1)?;
    let filter = object(&values[0])?;
    require_exact_keys(
        filter,
        &[],
        &["fromBlock", "toBlock", "blockHash", "address", "topics"],
    )?;

    let has_range = filter.contains_key("fromBlock") || filter.contains_key("toBlock");
    if filter.contains_key("blockHash") && has_range {
        return Err(BrokerError::Malformed);
    }
    if let Some(block_hash) = filter.get("blockHash") {
        hash(block_hash)?;
    } else {
        validate_log_range(filter.get("fromBlock"), filter.get("toBlock"))?;
    }
    if let Some(address_filter) = filter.get("address") {
        validate_log_addresses(address_filter)?;
    }
    if let Some(topics) = filter.get("topics") {
        validate_log_topics(topics)?;
    }
    Ok(())
}

fn validate_log_range(from: Option<&Value>, to: Option<&Value>) -> Result<(), BrokerError> {
    match (from, to) {
        (None, None) => Ok(()),
        (Some(left), Some(right)) => {
            let left = log_block_reference(left)?;
            let right = log_block_reference(right)?;
            match (left, right) {
                (LogBlockReference::Number(start), LogBlockReference::Number(end))
                    if end >= start && end.saturating_sub(start) <= MAX_LOG_BLOCK_RANGE =>
                {
                    Ok(())
                }
                (LogBlockReference::Tag(start), LogBlockReference::Tag(end)) if start == end => {
                    Ok(())
                }
                _ => Err(BrokerError::LimitExceeded),
            }
        }
        (Some(value), None) | (None, Some(value)) => {
            log_block_reference(value)?;
            Err(BrokerError::LimitExceeded)
        }
    }
}

fn validate_log_addresses(value: &Value) -> Result<(), BrokerError> {
    if value.is_string() {
        return address(value).map(|_| ());
    }
    let addresses = value.as_array().ok_or(BrokerError::Malformed)?;
    if addresses.is_empty() || addresses.len() > MAX_LOG_ADDRESSES {
        return Err(BrokerError::LimitExceeded);
    }
    for item in addresses {
        address(item)?;
    }
    Ok(())
}

fn validate_log_topics(value: &Value) -> Result<(), BrokerError> {
    let topics = value.as_array().ok_or(BrokerError::Malformed)?;
    if topics.len() > 4 {
        return Err(BrokerError::LimitExceeded);
    }
    for topic in topics {
        if topic.is_null() {
            continue;
        }
        if topic.is_string() {
            hash(topic)?;
            continue;
        }
        let alternatives = topic.as_array().ok_or(BrokerError::Malformed)?;
        if alternatives.is_empty() || alternatives.len() > MAX_LOG_TOPIC_ALTERNATIVES {
            return Err(BrokerError::LimitExceeded);
        }
        for alternative in alternatives {
            hash(alternative)?;
        }
    }
    Ok(())
}

fn validate_send_transaction(params: &Value) -> Result<(), BrokerError> {
    let values = exact_params(params, 1)?;
    validate_transaction_object(&values[0], true)
}

fn validate_transaction_object(value: &Value, require_from: bool) -> Result<(), BrokerError> {
    let transaction = object(value)?;
    let required = if require_from {
        &["from", "to"][..]
    } else {
        &["to"][..]
    };
    require_exact_keys(
        transaction,
        required,
        &[
            "from",
            "gas",
            "gasPrice",
            "maxFeePerGas",
            "maxPriorityFeePerGas",
            "value",
            "data",
            "input",
            "nonce",
            "type",
            "chainId",
            "accessList",
        ],
    )?;

    if let Some(from) = transaction.get("from") {
        address(from)?;
    }
    address(transaction.get("to").ok_or(BrokerError::Malformed)?)?;
    for field in [
        "gas",
        "gasPrice",
        "maxFeePerGas",
        "maxPriorityFeePerGas",
        "value",
        "nonce",
        "chainId",
    ] {
        if let Some(item) = transaction.get(field) {
            quantity(item)?;
        }
    }
    if transaction.contains_key("data") && transaction.contains_key("input") {
        return Err(BrokerError::Malformed);
    }
    for field in ["data", "input"] {
        if let Some(item) = transaction.get(field) {
            hex_data(item, MAX_CALL_DATA_BYTES)?;
        }
    }

    let has_legacy_fee = transaction.contains_key("gasPrice");
    let has_dynamic_fee = transaction.contains_key("maxFeePerGas")
        || transaction.contains_key("maxPriorityFeePerGas");
    if has_legacy_fee && has_dynamic_fee
        || transaction.contains_key("maxPriorityFeePerGas")
            && !transaction.contains_key("maxFeePerGas")
    {
        return Err(BrokerError::Malformed);
    }

    if let Some(transaction_type) = transaction.get("type") {
        let value = quantity_u64(transaction_type)?;
        if value > 2
            || value < 2 && has_dynamic_fee
            || value == 2 && has_legacy_fee
            || value == 0 && transaction.contains_key("accessList")
        {
            return Err(BrokerError::Malformed);
        }
    }
    if let Some(access_list) = transaction.get("accessList") {
        validate_access_list(access_list)?;
    }
    Ok(())
}

fn validate_access_list(value: &Value) -> Result<(), BrokerError> {
    let entries = value.as_array().ok_or(BrokerError::Malformed)?;
    if entries.len() > MAX_ACCESS_LIST_ENTRIES {
        return Err(BrokerError::LimitExceeded);
    }
    for entry in entries {
        let entry = object(entry)?;
        require_exact_keys(entry, &["address", "storageKeys"], &[])?;
        address(entry.get("address").ok_or(BrokerError::Malformed)?)?;
        let keys = entry
            .get("storageKeys")
            .and_then(Value::as_array)
            .ok_or(BrokerError::Malformed)?;
        if keys.len() > MAX_ACCESS_LIST_STORAGE_KEYS {
            return Err(BrokerError::LimitExceeded);
        }
        for key in keys {
            hash(key)?;
        }
    }
    Ok(())
}

fn validate_personal_sign(params: &Value) -> Result<(), BrokerError> {
    let values = exact_params(params, 2)?;
    hex_data(&values[0], MAX_PERSONAL_MESSAGE_BYTES)?;
    address(&values[1]).map(|_| ())
}

fn validate_typed_data(params: &Value) -> Result<(), BrokerError> {
    let values = exact_params(params, 2)?;
    address(&values[0])?;
    let source = string(&values[1], MAX_TYPED_DATA_BYTES)?;
    let parsed: Value = serde_json::from_str(source).map_err(|_| BrokerError::Malformed)?;
    validate_json_limits(&parsed)?;
    let root = object(&parsed)?;
    require_exact_keys(root, &["types", "primaryType", "domain", "message"], &[])?;
    object(root.get("types").ok_or(BrokerError::Malformed)?)?;
    string(root.get("primaryType").ok_or(BrokerError::Malformed)?, 128)?;
    object(root.get("domain").ok_or(BrokerError::Malformed)?)?;
    object(root.get("message").ok_or(BrokerError::Malformed)?)?;
    Ok(())
}

fn validate_add_chain(params: &Value) -> Result<(), BrokerError> {
    let values = exact_params(params, 1)?;
    let chain = object(&values[0])?;
    require_exact_keys(
        chain,
        &["chainId", "chainName", "nativeCurrency", "rpcUrls"],
        &["blockExplorerUrls", "iconUrls"],
    )?;
    quantity(chain.get("chainId").ok_or(BrokerError::Malformed)?)?;
    nonempty_text(chain.get("chainName").ok_or(BrokerError::Malformed)?, 128)?;
    validate_native_currency(chain.get("nativeCurrency").ok_or(BrokerError::Malformed)?)?;
    validate_url_array(chain.get("rpcUrls").ok_or(BrokerError::Malformed)?, true)?;
    for optional_urls in ["blockExplorerUrls", "iconUrls"] {
        if let Some(urls) = chain.get(optional_urls) {
            validate_url_array(urls, false)?;
        }
    }
    Ok(())
}

fn validate_native_currency(value: &Value) -> Result<(), BrokerError> {
    let currency = object(value)?;
    require_exact_keys(currency, &["name", "symbol", "decimals"], &[])?;
    nonempty_text(currency.get("name").ok_or(BrokerError::Malformed)?, 64)?;
    let symbol = nonempty_text(currency.get("symbol").ok_or(BrokerError::Malformed)?, 16)?;
    if !symbol
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    {
        return Err(BrokerError::Malformed);
    }
    let decimals = currency
        .get("decimals")
        .and_then(Value::as_u64)
        .ok_or(BrokerError::Malformed)?;
    if decimals > 36 {
        return Err(BrokerError::LimitExceeded);
    }
    Ok(())
}

fn validate_url_array(value: &Value, require_nonempty: bool) -> Result<(), BrokerError> {
    let urls = value.as_array().ok_or(BrokerError::Malformed)?;
    if urls.len() > MAX_URLS_PER_FIELD || require_nonempty && urls.is_empty() {
        return Err(BrokerError::LimitExceeded);
    }
    for url in urls {
        validate_https_url(url)?;
    }
    Ok(())
}

fn validate_https_url(value: &Value) -> Result<(), BrokerError> {
    let text = string(value, MAX_URL_BYTES)?;
    let Some(remainder) = text.strip_prefix("https://") else {
        return Err(BrokerError::Malformed);
    };
    if remainder.is_empty()
        || remainder.contains(['@', '?', '#', '\\'])
        || !remainder.is_ascii()
        || remainder.bytes().any(|byte| byte.is_ascii_whitespace())
    {
        return Err(BrokerError::Malformed);
    }
    let authority = remainder.split('/').next().ok_or(BrokerError::Malformed)?;
    let serialized_origin = format!("https://{authority}");
    BrowserOrigin::new(serialized_origin).map_err(|_| BrokerError::Malformed)?;
    Ok(())
}

fn validate_switch_chain(params: &Value) -> Result<(), BrokerError> {
    let values = exact_params(params, 1)?;
    let chain = object(&values[0])?;
    require_exact_keys(chain, &["chainId"], &[])?;
    quantity(chain.get("chainId").ok_or(BrokerError::Malformed)?)?;
    Ok(())
}

fn validate_watch_asset(params: &Value) -> Result<(), BrokerError> {
    let values = exact_params(params, 1)?;
    let request = object(&values[0])?;
    require_exact_keys(request, &["type", "options"], &[])?;
    if string(request.get("type").ok_or(BrokerError::Malformed)?, 8)? != "ERC20" {
        return Err(BrokerError::Malformed);
    }
    let options = object(request.get("options").ok_or(BrokerError::Malformed)?)?;
    require_exact_keys(options, &["address", "symbol", "decimals"], &[])?;
    address(options.get("address").ok_or(BrokerError::Malformed)?)?;
    let symbol = nonempty_text(options.get("symbol").ok_or(BrokerError::Malformed)?, 16)?;
    if !symbol.bytes().all(|byte| byte.is_ascii_alphanumeric()) {
        return Err(BrokerError::Malformed);
    }
    let decimals = options
        .get("decimals")
        .and_then(Value::as_u64)
        .ok_or(BrokerError::Malformed)?;
    if decimals > 36 {
        return Err(BrokerError::LimitExceeded);
    }
    Ok(())
}

fn validate_get_capabilities(params: &Value) -> Result<(), BrokerError> {
    let values = params_array(params)?;
    match values {
        [] => Ok(()),
        [account] => address(account).map(|_| ()),
        _ => Err(BrokerError::Malformed),
    }
}

fn validate_permissions(params: &Value) -> Result<(), BrokerError> {
    let values = exact_params(params, 1)?;
    let permissions = object(&values[0])?;
    require_exact_keys(permissions, &["eth_accounts"], &[])?;
    let accounts = object(
        permissions
            .get("eth_accounts")
            .ok_or(BrokerError::Malformed)?,
    )?;
    require_exact_keys(accounts, &[], &[])
}

fn nonempty_text(value: &Value, maximum: usize) -> Result<&str, BrokerError> {
    let text = string(value, maximum)?;
    if text.is_empty() {
        return Err(BrokerError::Malformed);
    }
    Ok(text)
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::{MAX_CALL_DATA_BYTES, validate};
    use crate::{BrokerError, ProviderMethod};

    #[test]
    fn exact_method_schemas_reject_extra_or_ambiguous_fields() {
        assert_eq!(
            validate("eth_accounts", &json!(["surprise"])),
            Err(BrokerError::Malformed)
        );
        assert_eq!(
            validate(
                "eth_sendTransaction",
                &json!([{
                    "from": "0x1111111111111111111111111111111111111111",
                    "to": "0x2222222222222222222222222222222222222222",
                    "gasPrice": "0x1",
                    "maxFeePerGas": "0x2"
                }])
            ),
            Err(BrokerError::Malformed)
        );
        assert_eq!(
            validate(
                "wallet_switchEthereumChain",
                &json!([{"chainId": "0x1", "ignored": true}])
            ),
            Err(BrokerError::Malformed)
        );
    }

    #[test]
    fn canonical_hex_types_are_enforced() {
        for params in [
            json!(["0x111111111111111111111111111111111111111A", "latest"]),
            json!(["0x1111111111111111111111111111111111111111", "0x00"]),
            json!(["0x1111", "latest"]),
        ] {
            assert_eq!(
                validate("eth_getBalance", &params),
                Err(BrokerError::Malformed)
            );
        }
        assert_eq!(
            validate(
                "eth_getBalance",
                &json!(["0x1111111111111111111111111111111111111111", "0x0"])
            ),
            Ok(ProviderMethod::GetBalance)
        );
    }

    #[test]
    fn log_ranges_and_topic_fanout_are_bounded() {
        assert_eq!(
            validate(
                "eth_getLogs",
                &json!([{"fromBlock": "0x0", "toBlock": "0x2711"}])
            ),
            Err(BrokerError::LimitExceeded)
        );
        let alternatives = vec![
            Value::String(
                "0x1111111111111111111111111111111111111111111111111111111111111111".to_owned(),
            );
            33
        ];
        assert_eq!(
            validate("eth_getLogs", &json!([{"topics": [alternatives]}])),
            Err(BrokerError::LimitExceeded)
        );
    }

    #[test]
    fn canonical_accounting_ignores_a_claimed_length() {
        let oversized_data = format!("0x{}", "aa".repeat(MAX_CALL_DATA_BYTES + 1));
        assert_eq!(
            validate(
                "eth_call",
                &json!([{
                    "to": "0x2222222222222222222222222222222222222222",
                    "data": oversized_data
                }])
            ),
            Err(BrokerError::LimitExceeded)
        );
    }

    #[test]
    fn aggregate_depth_and_container_fanout_fail_before_schema_dispatch() {
        let mut deeply_nested = Value::Null;
        for _ in 0..=33 {
            deeply_nested = Value::Array(vec![deeply_nested]);
        }
        assert_eq!(
            validate("eth_accounts", &deeply_nested),
            Err(BrokerError::LimitExceeded)
        );

        let excessive_fanout = Value::Array(vec![Value::Null; 4_097]);
        assert_eq!(
            validate("eth_accounts", &excessive_fanout),
            Err(BrokerError::LimitExceeded)
        );
    }

    #[test]
    fn typed_data_must_be_bounded_strict_json() {
        assert_eq!(
            validate(
                "eth_signTypedData_v4",
                &json!([
                    "0x1111111111111111111111111111111111111111",
                    "{\"domain\":{},\"message\":{},\"primaryType\":\"Mail\",\"types\":{}}"
                ])
            ),
            Ok(ProviderMethod::SignTypedDataV4)
        );
        assert_eq!(
            validate(
                "eth_signTypedData_v4",
                &json!([
                    "0x1111111111111111111111111111111111111111",
                    "{\"domain\":{},\"message\":{},\"primaryType\":\"Mail\",\"types\":{},\"extra\":1}"
                ])
            ),
            Err(BrokerError::Malformed)
        );
    }

    #[test]
    fn only_https_metadata_urls_without_credentials_are_accepted() {
        let base = json!([{
            "chainId": "0x539",
            "chainName": "Private Canary",
            "nativeCurrency": {"name": "Ether", "symbol": "ETH", "decimals": 18},
            "rpcUrls": ["https://rpc.example.test/path"]
        }]);
        assert_eq!(
            validate("wallet_addEthereumChain", &base),
            Ok(ProviderMethod::AddEthereumChain)
        );
        let credentialed = json!([{
            "chainId": "0x539",
            "chainName": "Private Canary",
            "nativeCurrency": {"name": "Ether", "symbol": "ETH", "decimals": 18},
            "rpcUrls": ["https://user@rpc.example.test"]
        }]);
        assert_eq!(
            validate("wallet_addEthereumChain", &credentialed),
            Err(BrokerError::Malformed)
        );
    }
}
