use super::client::NativeError;
use crate::protobuf::{gzip_compress, gzip_decompress};
use serde_json::{Value, json};

const CONNECT_GZIP_FLAG: u8 = 0x01;
const CONNECT_END_STREAM_FLAG: u8 = 0x02;

pub(super) fn post(client: &ureq::Agent, url: &str, body: Vec<u8>) -> Result<Vec<u8>, NativeError> {
    send_post(
        client,
        url,
        body,
        &[
            ("Content-Type", "application/proto"),
            ("Connect-Protocol-Version", "1"),
            ("User-Agent", "connect-go/1.18.1 (go1.25.5)"),
            ("Accept-Encoding", "gzip"),
        ],
    )
}

pub(super) fn post_connect_stream(
    client: &ureq::Agent,
    url: &str,
    body: Vec<u8>,
) -> Result<Vec<Vec<u8>>, NativeError> {
    let framed = frame_connect_stream(&body)?;
    let bytes = send_post(
        client,
        url,
        framed,
        &[
            ("Content-Type", "application/connect+proto"),
            ("Connect-Protocol-Version", "1"),
            ("Connect-Content-Encoding", "gzip"),
            ("Connect-Accept-Encoding", "gzip"),
            ("User-Agent", "connect-go/1.18.1 (go1.25.5)"),
            ("Accept-Encoding", "gzip"),
        ],
    )?;
    parse_connect_stream_response(&bytes)
}

fn send_post(
    client: &ureq::Agent,
    url: &str,
    body: Vec<u8>,
    headers: &[(&str, &str)],
) -> Result<Vec<u8>, NativeError> {
    let mut request = client.post(url);
    for (name, value) in headers {
        request = request.header(*name, *value);
    }
    let mut response = request
        .send(body)
        .map_err(|err| NativeError::Network(err.to_string()))?;
    let status = response.status();
    let encoding = response
        .headers()
        .get("content-encoding")
        .and_then(|value| value.to_str().ok())
        .map(str::to_ascii_lowercase);
    let bytes = response
        .body_mut()
        .read_to_vec()
        .map_err(|err| NativeError::Network(err.to_string()))?;
    if !status.is_success() {
        return Err(NativeError::Http {
            status: status.as_u16(),
            body: String::from_utf8_lossy(&bytes).into_owned(),
        });
    }
    if encoding.is_some_and(|value| value.contains("gzip")) || bytes.starts_with(&[0x1f, 0x8b]) {
        return gzip_decompress(&bytes).map_err(|err| NativeError::Network(err.to_string()));
    }
    Ok(bytes)
}

fn frame_connect_stream(body: &[u8]) -> Result<Vec<u8>, NativeError> {
    let payload = gzip_compress(body).map_err(|err| NativeError::Network(err.to_string()))?;
    let length = u32::try_from(payload.len())
        .map_err(|_| NativeError::Connect("request frame too large".to_string()))?;
    let mut out = Vec::with_capacity(5 + payload.len());
    out.push(CONNECT_GZIP_FLAG);
    out.extend(length.to_be_bytes());
    out.extend(payload);
    Ok(out)
}

fn parse_connect_stream_response(data: &[u8]) -> Result<Vec<Vec<u8>>, NativeError> {
    let mut frames = Vec::new();
    let mut offset = 0_usize;
    while offset + 5 <= data.len() {
        let flags = data[offset];
        let length = u32::from_be_bytes(
            data[offset + 1..offset + 5]
                .try_into()
                .map_err(|_| NativeError::Decode("Connect frame length"))?,
        ) as usize;
        let start = offset + 5;
        let end = start
            .checked_add(length)
            .ok_or(NativeError::Decode("Connect frame length"))?;
        if end > data.len() {
            return Err(NativeError::Decode("Connect frame payload"));
        }
        let mut payload = data[start..end].to_vec();
        if flags & CONNECT_GZIP_FLAG != 0 {
            payload = gzip_decompress(&payload)
                .map_err(|err| NativeError::Connect(format!("gzip decode failed: {err}")))?;
        }
        if flags & CONNECT_END_STREAM_FLAG != 0 {
            if let Some(message) = connect_error_message(&payload) {
                return Err(NativeError::Connect(message));
            }
        } else {
            frames.push(payload);
        }
        offset = end;
    }
    if offset != data.len() {
        return Err(NativeError::Decode("Connect stream trailing bytes"));
    }
    Ok(frames)
}

fn connect_error_message(payload: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(payload).ok()?.trim();
    if text.is_empty() || text == "{}" {
        return None;
    }
    let Ok(value) = serde_json::from_str::<Value>(text) else {
        return Some(text.to_string());
    };
    let Some(error) = value.get("error") else {
        return (value != json!({})).then(|| text.to_string());
    };
    let code = error.get("code").and_then(Value::as_str).unwrap_or("error");
    let message = error
        .get("message")
        .and_then(Value::as_str)
        .unwrap_or("unknown Connect error");
    Some(format!("{code}: {message}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connect_stream_frame_round_trips_gzip_payload() {
        let body = b"\x0a\x02ok";
        let frame = frame_connect_stream(body).unwrap();
        let frames = parse_connect_stream_response(&frame).unwrap();

        assert_eq!(frames, vec![body.to_vec()]);
    }

    #[test]
    fn connect_stream_eos_error_is_reported() {
        let payload = br#"{"error":{"code":"failed_precondition","message":"quota exhausted"}}"#;
        let mut frame = Vec::new();
        frame.push(CONNECT_END_STREAM_FLAG);
        frame.extend((payload.len() as u32).to_be_bytes());
        frame.extend(payload);

        let error = parse_connect_stream_response(&frame).unwrap_err();

        assert!(error.to_string().contains("failed_precondition"));
        assert!(error.to_string().contains("quota exhausted"));
    }
}
