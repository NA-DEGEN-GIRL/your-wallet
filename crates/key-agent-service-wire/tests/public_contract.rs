//! Public contract and stable version-1 vectors.

use key_agent_service_wire::{
    COMMAND_REQUEST_BYTES, COMMAND_RESPONSE_BYTES, EpochNonce, OPEN_EPOCH_ACK_BYTES,
    OPEN_EPOCH_REQUEST_BYTES, OpenEpochAck, OpenEpochRequest, ProtocolVersion, ServiceCommand,
    ServiceCommandRequest, ServiceRequest, ServiceRequestId, ServiceResponse, ServiceStatus,
    ServiceStatusResponse, WireError, decode_request, decode_response, encode_request,
    encode_response,
};

fn decode_hex(source: &str) -> Result<Vec<u8>, &'static str> {
    if !source.len().is_multiple_of(2) {
        return Err("hex vector length was odd");
    }
    let mut bytes = Vec::with_capacity(source.len() / 2);
    for pair in source.as_bytes().chunks_exact(2) {
        let high = hex_nibble(pair[0])?;
        let low = hex_nibble(pair[1])?;
        bytes.push((high << 4) | low);
    }
    Ok(bytes)
}

const fn hex_nibble(value: u8) -> Result<u8, &'static str> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        b'A'..=b'F' => Ok(value - b'A' + 10),
        _ => Err("hex vector contained a non-hex byte"),
    }
}

fn epoch() -> Result<EpochNonce, WireError> {
    EpochNonce::new([0xA5; 32])
}

fn request_id() -> Result<ServiceRequestId, WireError> {
    ServiceRequestId::new([0x5A; 16])
}

#[test]
fn public_api_round_trips_the_complete_v1_set() -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(ProtocolVersion::try_from(1)?, ProtocolVersion::V1);
    assert_eq!(ProtocolVersion::V1.wire_code(), 1);

    let open = ServiceRequest::OpenEpoch(OpenEpochRequest::new());
    let ack = ServiceResponse::OpenEpoch(OpenEpochAck::new(epoch()?));
    let command = ServiceRequest::Command(ServiceCommandRequest::new(
        epoch()?,
        request_id()?,
        ServiceCommand::Status,
    ));
    let status = ServiceResponse::Status(ServiceStatusResponse::new(
        epoch()?,
        request_id()?,
        ServiceStatus::Unavailable,
    ));

    let open_bytes = encode_request(&open);
    let ack_bytes = encode_response(&ack);
    let command_bytes = encode_request(&command);
    let status_bytes = encode_response(&status);

    assert_eq!(open_bytes.len(), OPEN_EPOCH_REQUEST_BYTES);
    assert_eq!(ack_bytes.len(), OPEN_EPOCH_ACK_BYTES);
    assert_eq!(command_bytes.len(), COMMAND_REQUEST_BYTES);
    assert_eq!(status_bytes.len(), COMMAND_RESPONSE_BYTES);
    assert_eq!(decode_request(&open_bytes)?, open);
    assert_eq!(decode_response(&ack_bytes)?, ack);
    assert_eq!(decode_request(&command_bytes)?, command);
    assert_eq!(decode_response(&status_bytes)?, status);
    Ok(())
}

#[test]
fn stable_golden_vectors_decode_and_reencode_exactly() -> Result<(), Box<dyn std::error::Error>> {
    // These vectors are populated from the independently reviewed v1 layout.
    let vectors = [
        (true, "59574b415356303100010001000000004408a573"),
        (
            false,
            "59574b41535630310001000200000000a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5991279df",
        ),
        (
            true,
            "59574b41535630310001000300000000a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a55a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a0001000049b6c377",
        ),
        (
            false,
            "59574b41535630310001000400000000a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a55a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a000100002384c7b3",
        ),
    ];

    for (is_request, vector) in vectors {
        let bytes = decode_hex(vector)?;
        if is_request {
            let decoded = decode_request(&bytes)?;
            assert_eq!(encode_request(&decoded), bytes);
        } else {
            let decoded = decode_response(&bytes)?;
            assert_eq!(encode_response(&decoded), bytes);
        }
    }
    Ok(())
}

#[test]
fn public_errors_are_category_only_and_payload_debug_is_redacted()
-> Result<(), Box<dyn std::error::Error>> {
    let epoch = epoch()?;
    let request_id = request_id()?;
    assert_eq!(format!("{epoch:?}"), "EpochNonce([REDACTED])");
    assert_eq!(format!("{request_id:?}"), "ServiceRequestId([REDACTED])");
    assert_eq!(
        ProtocolVersion::try_from(2),
        Err(WireError::UnsupportedVersion)
    );
    let command = ServiceCommandRequest::new(epoch, request_id, ServiceCommand::Status);
    let status = ServiceStatusResponse::new(epoch, request_id, ServiceStatus::Unavailable);
    for debug_value in [
        format!("{:?}", OpenEpochAck::new(epoch)),
        format!("{command:?}"),
        format!("{status:?}"),
        format!("{:?}", ServiceRequest::Command(command)),
        format!("{:?}", ServiceResponse::OpenEpoch(OpenEpochAck::new(epoch))),
        format!("{:?}", ServiceResponse::Status(status)),
    ] {
        assert!(debug_value.contains("[REDACTED]"));
        assert!(!debug_value.contains("165, 165"));
        assert!(!debug_value.contains("90, 90"));
    }

    let categories = [
        (WireError::Truncated, "service wire frame was truncated"),
        (
            WireError::TrailingData,
            "service wire frame had trailing data",
        ),
        (WireError::InvalidMagic, "service wire magic was invalid"),
        (
            WireError::UnsupportedVersion,
            "service wire version was unsupported",
        ),
        (WireError::UnknownKind, "service wire kind was unknown"),
        (
            WireError::NonZeroReserved,
            "service wire reserved field was nonzero",
        ),
        (WireError::InvalidValue, "service wire value was invalid"),
        (
            WireError::Integrity,
            "service wire framing integrity check failed",
        ),
        (
            WireError::BindingMismatch,
            "service wire response binding did not match",
        ),
    ];
    for (error, expected) in categories {
        assert_eq!(error.to_string(), expected);
    }
    Ok(())
}

#[test]
fn public_response_correlation_rejects_every_mismatch() -> Result<(), Box<dyn std::error::Error>> {
    let request = ServiceCommandRequest::new(epoch()?, request_id()?, ServiceCommand::Status);
    let response = ServiceStatusResponse::new(epoch()?, request_id()?, ServiceStatus::Unavailable);
    response.ensure_correlates_with(&request)?;

    let request_outer = ServiceRequest::Command(request);
    let response_outer = ServiceResponse::Status(response);
    response_outer.ensure_correlates_with(&request_outer)?;

    let wrong_epoch = ServiceResponse::Status(ServiceStatusResponse::new(
        EpochNonce::new([0xA6; 32])?,
        request_id()?,
        ServiceStatus::Unavailable,
    ));
    assert_eq!(
        wrong_epoch.ensure_correlates_with(&request_outer),
        Err(WireError::BindingMismatch)
    );

    let wrong_request_id = ServiceResponse::Status(ServiceStatusResponse::new(
        epoch()?,
        ServiceRequestId::new([0x5B; 16])?,
        ServiceStatus::Unavailable,
    ));
    assert_eq!(
        wrong_request_id.ensure_correlates_with(&request_outer),
        Err(WireError::BindingMismatch)
    );

    let open_request = ServiceRequest::OpenEpoch(OpenEpochRequest::new());
    let open_response = ServiceResponse::OpenEpoch(OpenEpochAck::new(epoch()?));
    open_response.ensure_correlates_with(&open_request)?;
    assert_eq!(
        open_response.ensure_correlates_with(&request_outer),
        Err(WireError::BindingMismatch)
    );
    assert_eq!(
        response_outer.ensure_correlates_with(&open_request),
        Err(WireError::BindingMismatch)
    );
    Ok(())
}
