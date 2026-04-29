#![no_main]

use libfuzzer_sys::fuzz_target;
use locket_agent::{
    RequestEnvelope, ResponseEnvelope, decode_request_frame, decode_response_frame, encode_frame,
};

const MAX_FRAME_SIZE: usize = 16 * 1024;

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_FRAME_SIZE + 4 {
        return;
    }

    if let Ok((request, consumed)) = decode_request_frame(data, MAX_FRAME_SIZE) {
        assert!(consumed <= data.len());
        let frame = encode_frame(&request, MAX_FRAME_SIZE).expect("valid request should encode");
        let (roundtrip, roundtrip_consumed) =
            decode_request_frame(&frame, MAX_FRAME_SIZE).expect("encoded request should decode");
        assert_eq!(roundtrip, request);
        assert_eq!(roundtrip_consumed, frame.len());
    }

    if let Ok((response, consumed)) = decode_response_frame(data, MAX_FRAME_SIZE) {
        assert!(consumed <= data.len());
        let frame = encode_frame(&response, MAX_FRAME_SIZE).expect("valid response should encode");
        let (roundtrip, roundtrip_consumed) =
            decode_response_frame(&frame, MAX_FRAME_SIZE).expect("encoded response should decode");
        assert_eq!(roundtrip, response);
        assert_eq!(roundtrip_consumed, frame.len());
    }

    let _ = serde_json::from_slice::<RequestEnvelope>(data);
    let _ = serde_json::from_slice::<ResponseEnvelope>(data);
});
