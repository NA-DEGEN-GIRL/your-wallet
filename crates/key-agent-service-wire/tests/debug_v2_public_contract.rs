//! Public contract and stable debug-only version-2 vectors.

#![cfg(feature = "debug-feasibility-v2")]

use key_agent_service_wire::{
    EpochNonce, ServiceRequestId, WireError,
    debug_v2::{
        self, DESKTOP_COMMAND_REQUEST_BYTES, DESKTOP_COMMAND_RESPONSE_BYTES, DesktopCommand,
        DesktopCommandRequest, DesktopCommandResponse, DesktopResult, HELPER_READY_ACK_BYTES,
        HELPER_READY_REQUEST_BYTES, HelperReadyAck, HelperReadyRequest, OPEN_EPOCH_ACK_BYTES,
        OPEN_EPOCH_REQUEST_BYTES, OpenEpochAck, OpenEpochRequest, ProtocolVersion, ServiceRequest,
        ServiceResponse,
    },
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
fn public_api_round_trips_the_complete_v2_set() -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(debug_v2::PROTOCOL_MAGIC, *b"YWKASV02");
    assert_eq!(ProtocolVersion::try_from(2)?, ProtocolVersion::V2);
    assert_eq!(ProtocolVersion::V2.wire_code(), 2);

    let requests = [
        ServiceRequest::OpenEpoch(OpenEpochRequest::new()),
        ServiceRequest::DesktopCommand(DesktopCommandRequest::new(
            epoch()?,
            request_id()?,
            DesktopCommand::Status,
        )),
        ServiceRequest::DesktopCommand(DesktopCommandRequest::new(
            epoch()?,
            request_id()?,
            DesktopCommand::LaunchApprovalRpcProbe,
        )),
        ServiceRequest::DesktopCommand(DesktopCommandRequest::new(
            epoch()?,
            request_id()?,
            DesktopCommand::LaunchSecretInputRpcProbe,
        )),
        ServiceRequest::HelperReady(HelperReadyRequest::new(epoch()?, request_id()?)),
    ];
    for request in requests {
        let encoded = debug_v2::encode_request(&request);
        let expected_length = match request {
            ServiceRequest::OpenEpoch(_) => OPEN_EPOCH_REQUEST_BYTES,
            ServiceRequest::DesktopCommand(_) => DESKTOP_COMMAND_REQUEST_BYTES,
            ServiceRequest::HelperReady(_) => HELPER_READY_REQUEST_BYTES,
        };
        assert_eq!(encoded.len(), expected_length);
        assert_eq!(debug_v2::decode_request(&encoded)?, request);
    }

    let responses = [
        ServiceResponse::OpenEpoch(OpenEpochAck::new(epoch()?)),
        ServiceResponse::DesktopCommand(DesktopCommandResponse::new(
            epoch()?,
            request_id()?,
            DesktopResult::Unavailable,
        )),
        ServiceResponse::DesktopCommand(DesktopCommandResponse::new(
            epoch()?,
            request_id()?,
            DesktopResult::ApprovalRpcProbeCompleted,
        )),
        ServiceResponse::DesktopCommand(DesktopCommandResponse::new(
            epoch()?,
            request_id()?,
            DesktopResult::SecretInputRpcProbeCompleted,
        )),
        ServiceResponse::HelperReady(HelperReadyAck::new(epoch()?, request_id()?)),
    ];
    for response in responses {
        let encoded = debug_v2::encode_response(&response);
        let expected_length = match response {
            ServiceResponse::OpenEpoch(_) => OPEN_EPOCH_ACK_BYTES,
            ServiceResponse::DesktopCommand(_) => DESKTOP_COMMAND_RESPONSE_BYTES,
            ServiceResponse::HelperReady(_) => HELPER_READY_ACK_BYTES,
        };
        assert_eq!(encoded.len(), expected_length);
        assert_eq!(debug_v2::decode_response(&encoded)?, response);
    }
    Ok(())
}

#[test]
fn stable_golden_vectors_decode_and_reencode_exactly() -> Result<(), Box<dyn std::error::Error>> {
    let vectors = [
        (true, "59574b41535630320002000100000000e5a2dc02"),
        (
            false,
            "59574b41535630320002000200000000a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a537c622bc",
        ),
        (
            true,
            "59574b41535630320002000300000000a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a55a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a0001000049f27d8e",
        ),
        (
            true,
            "59574b41535630320002000300000000a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a55a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a00020000a3dcbdfd",
        ),
        (
            true,
            "59574b41535630320002000300000000a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a55a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a00030000069d2f83",
        ),
        (
            false,
            "59574b41535630320002000400000000a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a55a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a0001000023c0794a",
        ),
        (
            false,
            "59574b41535630320002000400000000a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a55a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a00020000c9eeb939",
        ),
        (
            false,
            "59574b41535630320002000400000000a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a55a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a000300006caf2b47",
        ),
        (
            true,
            "59574b41535630320002000500000000a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a55a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5af9831890",
        ),
        (
            false,
            "59574b41535630320002000600000000a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a55a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5aa7797bdf",
        ),
    ];

    for (is_request, vector) in vectors {
        let bytes = decode_hex(vector)?;
        if is_request {
            let decoded = debug_v2::decode_request(&bytes)?;
            assert_eq!(debug_v2::encode_request(&decoded), bytes);
        } else {
            let decoded = debug_v2::decode_response(&bytes)?;
            assert_eq!(debug_v2::encode_response(&decoded), bytes);
        }
    }
    Ok(())
}

#[test]
fn feature_does_not_change_the_immutable_v1_version_contract() {
    assert_eq!(key_agent_service_wire::PROTOCOL_MAGIC, *b"YWKASV01");
    assert_eq!(
        key_agent_service_wire::ProtocolVersion::try_from(2),
        Err(WireError::UnsupportedVersion)
    );
}

#[test]
fn v1_and_v2_frames_are_never_cross_decoded() {
    let v1 =
        key_agent_service_wire::encode_request(&key_agent_service_wire::ServiceRequest::OpenEpoch(
            key_agent_service_wire::OpenEpochRequest::new(),
        ));
    let v2 = debug_v2::encode_request(&ServiceRequest::OpenEpoch(OpenEpochRequest::new()));

    assert_eq!(debug_v2::decode_request(&v1), Err(WireError::InvalidMagic));
    assert_eq!(
        key_agent_service_wire::decode_request(&v2),
        Err(WireError::InvalidMagic)
    );
}
