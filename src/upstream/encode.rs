use super::client::NativeChatRequest;
use crate::protobuf::ProtobufEncoder;

const CHAT_REQUEST_TYPE_CASCADE: u64 = 5;
const CHAT_MESSAGE_SOURCE_USER: u64 = 1;
const CHAT_DEFAULT_MAX_INPUT_TOKENS: u64 = 128_000;
const CHAT_DEFAULT_MAX_OUTPUT_TOKENS: u64 = 32_000;
const CHAT_DEFAULT_TEMPERATURE: f64 = 0.2;
const CHAT_DEFAULT_TOP_P: f64 = 0.95;
const CHAT_DEFAULT_TOP_K: u64 = 50;

pub(super) fn encode_get_chat_message_request(
    metadata: &[u8],
    request: NativeChatRequest<'_>,
    cascade_id: &str,
    prompt_id: &str,
) -> Vec<u8> {
    let mut encoder = ProtobufEncoder::new();
    encoder.write_bytes(1, metadata);
    encoder.write_message(3, &encode_chat_message_prompt(request.prompt));
    encoder.write_varint(7, CHAT_REQUEST_TYPE_CASCADE);
    encoder.write_message(8, &encode_completion_configuration());
    encoder.write_string(16, cascade_id);
    encoder.write_string(17, prompt_id);
    encoder.write_string(21, request.model_uid);
    encoder.to_bytes()
}

fn encode_chat_message_prompt(prompt: &str) -> ProtobufEncoder {
    let mut encoder = ProtobufEncoder::new();
    encoder.write_varint(2, CHAT_MESSAGE_SOURCE_USER);
    encoder.write_string(3, prompt);
    encoder.write_varint(4, crate::util::estimate_tokens(prompt));
    encoder.write_varint(5, 1);
    encoder
}

fn encode_completion_configuration() -> ProtobufEncoder {
    let mut encoder = ProtobufEncoder::new();
    encoder.write_varint(1, 1);
    encoder.write_varint(2, CHAT_DEFAULT_MAX_INPUT_TOKENS);
    encoder.write_varint(3, CHAT_DEFAULT_MAX_OUTPUT_TOKENS);
    encoder.write_fixed64_f64(5, CHAT_DEFAULT_TEMPERATURE);
    encoder.write_fixed64_f64(6, CHAT_DEFAULT_TOP_P);
    encoder.write_varint(7, CHAT_DEFAULT_TOP_K);
    encoder.write_fixed64_f64(8, 1.0);
    encoder.write_fixed64_f64(11, 1.0);
    encoder
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protobuf::{field_bytes, field_string, field_varint, iter_fields};

    #[test]
    fn encodes_get_chat_message_request_shape() {
        let request = encode_get_chat_message_request(
            b"metadata",
            NativeChatRequest {
                model_uid: "swe-check",
                prompt: "review this diff",
            },
            "cascade-id",
            "prompt-id",
        );
        let fields = iter_fields(&request);

        assert_eq!(field_bytes(&fields[0]), Some(b"metadata".as_slice()));
        assert!(fields.iter().any(|field| field.number == 3));
        assert!(fields.iter().any(|field| {
            field.number == 7 && field_varint(field) == Some(CHAT_REQUEST_TYPE_CASCADE)
        }));
        assert!(fields.iter().any(|field| field.number == 8));
        assert!(fields.iter().any(|field| {
            field.number == 16 && field_string(field).as_deref() == Some("cascade-id")
        }));
        assert!(fields.iter().any(|field| {
            field.number == 17 && field_string(field).as_deref() == Some("prompt-id")
        }));
        assert!(fields.iter().any(|field| {
            field.number == 21 && field_string(field).as_deref() == Some("swe-check")
        }));
        assert!(!fields.iter().any(|field| field.number == 22));
    }
}
