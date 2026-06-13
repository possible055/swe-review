use crate::protobuf::{
    ProtobufEncoder, field_bytes, field_fixed64_f64, field_string, field_varint, gzip_compress,
    gzip_decompress, iter_fields,
};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE;
use reqwest::header::{CONTENT_ENCODING, HeaderMap, HeaderName, HeaderValue};
use serde::Serialize;
use serde_json::{Value, json};
use std::env;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use thiserror::Error;
use uuid::Uuid;

pub const DEFAULT_API_BASE: &str =
    "https://server.self-serve.windsurf.com/exa.api_server_pb.ApiServerService";
pub const DEFAULT_API_SERVER_URL: &str = "https://server.codeium.com";
pub const QUICK_REVIEW_DISPLAY_OPTION: u64 = 4;
const AUTH_BASE: &str = "https://server.self-serve.windsurf.com/exa.auth_pb.AuthService";
const API_SERVER_SERVICE: &str = "exa.api_server_pb.ApiServerService";
const AUTH_SERVICE: &str = "exa.auth_pb.AuthService";
const SEAT_MANAGEMENT_SERVICE: &str = "exa.seat_management_pb.SeatManagementService";
const WS_APP: &str = "windsurf";
const DEFAULT_WS_APP_VER: &str = "0.2.0";
const DEFAULT_WS_LS_VER: &str = "1.110.1";
const DEFAULT_CLOUD_VERSION: &str = "2.0.0";
const CONNECT_GZIP_FLAG: u8 = 0x01;
const CONNECT_END_STREAM_FLAG: u8 = 0x02;
const CHAT_REQUEST_TYPE_CASCADE: u64 = 5;
const CHAT_MESSAGE_SOURCE_USER: u64 = 1;
const CHAT_DEFAULT_MAX_INPUT_TOKENS: u64 = 128_000;
const CHAT_DEFAULT_MAX_OUTPUT_TOKENS: u64 = 32_000;
const CHAT_DEFAULT_TEMPERATURE: f64 = 0.2;
const CHAT_DEFAULT_TOP_P: f64 = 0.95;
const CHAT_DEFAULT_TOP_K: u64 = 50;

#[derive(Debug, Clone)]
pub struct NativeClientOptions {
    pub api_key: Option<String>,
    pub endpoint: NativeClientEndpoint,
    pub timeout_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeClientEndpoint {
    Lifeguard,
    QuickReview,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct LifeguardMode {
    pub name: String,
    pub enabled: bool,
    pub model_id: u64,
    pub model_display_name: String,
    pub agent_version: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct NativeModelConfig {
    pub model_uid: String,
    pub label: String,
    pub description: Option<String>,
    pub display_option: Option<u64>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct NativeTeamSettings {
    pub allowed_model_uids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct CheckBugsReport {
    pub bugs: Vec<ReviewBug>,
    pub bug_check_id: Option<String>,
    pub method_used: Option<String>,
    pub model_used: Option<String>,
    pub playgrounds: Option<String>,
    pub model_id: Option<u64>,
    pub agent_version: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct ReviewBug {
    pub id: String,
    pub file: String,
    pub start: i32,
    pub end: i32,
    pub title: String,
    pub description: String,
    pub severity: String,
    pub resolution: String,
    pub confidence: Option<f64>,
    pub categories: Vec<String>,
    pub fix: Option<ReviewFix>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ReviewFix {
    pub old_str: String,
    pub new_str: String,
}

#[derive(Debug, Clone)]
pub struct CheckBugsRequest<'a> {
    pub diff: &'a str,
    pub repo_name: &'a str,
    pub commit_hash: &'a str,
    pub author_name: &'a str,
    pub commit_message: &'a str,
    pub user_rules: &'a [String],
    pub method: &'a str,
    pub symbol_context: &'a str,
    pub check_type: &'a str,
    pub base_ref: &'a str,
    pub git_root: &'a str,
}

#[derive(Debug, Clone)]
pub struct NativeChatRequest<'a> {
    pub model_uid: &'a str,
    pub prompt: &'a str,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct NativeChatResponse {
    pub text: String,
    pub session_id: String,
    pub cascade_id: String,
    pub prompt_id: String,
}

#[derive(Debug, Error)]
pub enum NativeError {
    #[error(
        "Windsurf API key not found. Provide --api-key, set WINDSURF_API_KEY, add WINDSURF_API_KEY to swe-tools/config.json, or run `swe-review extract-key --save`."
    )]
    ApiKeyMissing,
    #[error("{0}")]
    ApiKey(String),
    #[error("HTTP request failed: {0}")]
    Network(String),
    #[error("Server returned HTTP {status}: {body}")]
    Http { status: u16, body: String },
    #[error("Connect stream failed: {0}")]
    Connect(String),
    #[error("Failed to extract JWT from GetUserJwt response")]
    JwtMissing,
    #[error("Lifeguard mode '{0}' is not available for this account or team")]
    ModeUnavailable(String),
    #[error("Malformed protobuf response: {0}")]
    Decode(&'static str),
    #[error(
        "The server rejected Quick Review chat streaming for the configured Windsurf session token. Re-running `swe-review extract-key --save` will save the same local session token unless Windsurf has refreshed it. Try a discovered model value, omit --model, or provide a standard Windsurf API key via --api-key, WINDSURF_API_KEY, or swe-tools/config.json."
    )]
    SessionTokenNotAllowed,
}

pub struct NativeClient {
    api_key: String,
    api_base: String,
    auth_base: String,
    seat_management_base: String,
    timeout_ms: u64,
    client: reqwest::Client,
    jwt: Option<String>,
}

impl NativeClient {
    pub fn new(options: NativeClientOptions) -> Result<Self, NativeError> {
        let api_key = options
            .api_key
            .filter(|key| !key.trim().is_empty())
            .ok_or(NativeError::ApiKeyMissing)?;
        let (api_base, auth_base, seat_management_base) = endpoint_urls(options.endpoint);
        let client = reqwest::Client::builder()
            .build()
            .map_err(|err| NativeError::Network(err.to_string()))?;

        Ok(Self {
            api_key,
            api_base,
            auth_base,
            seat_management_base,
            timeout_ms: options.timeout_ms,
            client,
            jwt: None,
        })
    }

    pub async fn get_lifeguard_mode(&mut self, method: &str) -> Result<LifeguardMode, NativeError> {
        let metadata = self.metadata().await?;
        let mut request = ProtobufEncoder::new();
        request.write_bytes(1, &metadata);
        let response = self
            .post(
                &format!("{}/GetLifeguardConfig", self.api_base),
                request.to_bytes(),
            )
            .await?;
        let modes = parse_lifeguard_modes(&response)?;
        modes
            .into_iter()
            .find(|mode| mode.name == method && mode.enabled)
            .ok_or_else(|| NativeError::ModeUnavailable(method.to_string()))
    }

    pub async fn check_bugs(
        &mut self,
        request: CheckBugsRequest<'_>,
    ) -> Result<CheckBugsReport, NativeError> {
        let metadata = self.metadata().await?;
        let body = encode_check_bugs_request(&metadata, request);
        let response = self
            .post(&format!("{}/CheckBugs", self.api_base), body)
            .await?;
        parse_check_bugs_response(&response)
    }

    pub async fn get_cli_model_configs(&mut self) -> Result<Vec<NativeModelConfig>, NativeError> {
        let metadata = self.metadata().await?;
        let mut request = ProtobufEncoder::new();
        request.write_bytes(1, &metadata);
        let response = self
            .post(
                &format!("{}/GetCliModelConfigs", self.api_base),
                request.to_bytes(),
            )
            .await?;
        Ok(parse_cli_model_configs(&response))
    }

    pub async fn get_cli_team_settings(&mut self) -> Result<NativeTeamSettings, NativeError> {
        let metadata = self.metadata().await?;
        let mut request = ProtobufEncoder::new();
        request.write_bytes(1, &metadata);
        let response = self
            .post(
                &format!("{}/GetCliTeamSettings", self.seat_management_base),
                request.to_bytes(),
            )
            .await?;
        Ok(parse_cli_team_settings(&response))
    }

    pub async fn get_chat_message(
        &mut self,
        request: NativeChatRequest<'_>,
    ) -> Result<NativeChatResponse, NativeError> {
        let session_id = Uuid::new_v4().to_string();
        let cascade_id = Uuid::new_v4().to_string();
        let prompt_id = Uuid::new_v4().to_string();
        let trigger_id = Uuid::new_v4().to_string();
        let metadata = self.cloud_metadata(&session_id, &trigger_id).await?;
        let body = encode_get_chat_message_request(&metadata, request, &cascade_id, &prompt_id);
        let frames = self
            .post_connect_stream(&format!("{}/GetChatMessage", self.api_base), body)
            .await?;
        let text = parse_get_chat_message_frames(&frames);
        if text.trim().is_empty() {
            return Err(NativeError::Decode("GetChatMessageResponse.delta_text"));
        }
        Ok(NativeChatResponse {
            text,
            session_id,
            cascade_id,
            prompt_id,
        })
    }

    async fn metadata(&mut self) -> Result<Vec<u8>, NativeError> {
        let jwt = self.jwt().await?;
        let mut metadata = ProtobufEncoder::new();
        metadata.write_string(1, WS_APP);
        metadata.write_string(2, DEFAULT_WS_APP_VER);
        metadata.write_string(3, &self.api_key);
        metadata.write_string(4, "zh-cn");
        metadata.write_string(7, DEFAULT_WS_LS_VER);
        metadata.write_string(12, WS_APP);
        metadata.write_string(21, &jwt);
        metadata.write_bytes(30, b"\x00\x01");
        Ok(metadata.to_bytes())
    }

    async fn cloud_metadata(
        &mut self,
        session_id: &str,
        trigger_id: &str,
    ) -> Result<Vec<u8>, NativeError> {
        let jwt = self.jwt().await?;
        let mut metadata = ProtobufEncoder::new();
        metadata.write_string(1, WS_APP);
        metadata.write_string(2, DEFAULT_CLOUD_VERSION);
        metadata.write_string(3, &self.api_key);
        metadata.write_string(4, "en");
        metadata.write_string(5, os_name());
        metadata.write_string(7, DEFAULT_CLOUD_VERSION);
        metadata.write_varint(9, now_millis());
        metadata.write_string(10, session_id);
        metadata.write_string(12, WS_APP);
        metadata.write_message(16, &timestamp_message());
        metadata.write_string(21, &jwt);
        metadata.write_string(25, trigger_id);
        metadata.write_string(26, "Unset");
        metadata.write_string(28, WS_APP);
        Ok(metadata.to_bytes())
    }

    async fn jwt(&mut self) -> Result<String, NativeError> {
        if let Some(jwt) = &self.jwt
            && jwt_expires_at(jwt) > now_seconds() + 60.0
        {
            return Ok(jwt.clone());
        }

        let mut metadata = ProtobufEncoder::new();
        metadata.write_string(1, WS_APP);
        metadata.write_string(2, DEFAULT_WS_APP_VER);
        metadata.write_string(3, &self.api_key);
        metadata.write_string(4, "zh-cn");
        metadata.write_string(7, DEFAULT_WS_LS_VER);
        metadata.write_string(12, WS_APP);
        metadata.write_bytes(30, b"\x00\x01");

        let mut outer = ProtobufEncoder::new();
        outer.write_message(1, &metadata);
        let response = self
            .post(&format!("{}/GetUserJwt", self.auth_base), outer.to_bytes())
            .await?;
        let jwt = crate::protobuf::extract_strings(&response)
            .into_iter()
            .find(|value| value.starts_with("eyJ") && value.contains('.'))
            .ok_or(NativeError::JwtMissing)?;
        self.jwt = Some(jwt.clone());
        Ok(jwt)
    }

    async fn post(&self, url: &str, body: Vec<u8>) -> Result<Vec<u8>, NativeError> {
        let headers = header_map(&[
            ("Content-Type", "application/proto".to_string()),
            ("Connect-Protocol-Version", "1".to_string()),
            ("User-Agent", "connect-go/1.18.1 (go1.25.5)".to_string()),
            ("Accept-Encoding", "gzip".to_string()),
        ]);
        send_post(&self.client, url, body, headers, self.timeout_ms).await
    }

    async fn post_connect_stream(
        &self,
        url: &str,
        body: Vec<u8>,
    ) -> Result<Vec<Vec<u8>>, NativeError> {
        let headers = header_map(&[
            ("Content-Type", "application/connect+proto".to_string()),
            ("Connect-Protocol-Version", "1".to_string()),
            ("Connect-Content-Encoding", "gzip".to_string()),
            ("Connect-Accept-Encoding", "gzip".to_string()),
            ("User-Agent", "connect-go/1.18.1 (go1.25.5)".to_string()),
            ("Accept-Encoding", "gzip".to_string()),
        ]);
        let framed = frame_connect_stream(&body)?;
        let bytes = send_post(&self.client, url, framed, headers, self.timeout_ms).await?;
        parse_connect_stream_response(&bytes)
    }
}

async fn send_post(
    client: &reqwest::Client,
    url: &str,
    body: Vec<u8>,
    headers: HeaderMap,
    timeout_ms: u64,
) -> Result<Vec<u8>, NativeError> {
    let response = client
        .post(url)
        .headers(headers)
        .body(body)
        .timeout(Duration::from_millis(timeout_ms))
        .send()
        .await
        .map_err(|err| NativeError::Network(err.to_string()))?;
    let status = response.status();
    let encoding = response
        .headers()
        .get(CONTENT_ENCODING)
        .and_then(|value| value.to_str().ok())
        .map(str::to_ascii_lowercase);
    let bytes = response
        .bytes()
        .await
        .map_err(|err| NativeError::Network(err.to_string()))?
        .to_vec();
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

fn header_map(headers: &[(&str, String)]) -> HeaderMap {
    let mut map = HeaderMap::new();
    for (name, value) in headers {
        if let (Ok(name), Ok(value)) = (
            HeaderName::from_bytes(name.as_bytes()),
            HeaderValue::from_str(value),
        ) {
            map.insert(name, value);
        }
    }
    map
}

fn encode_check_bugs_request(metadata: &[u8], request: CheckBugsRequest<'_>) -> Vec<u8> {
    let mut encoder = ProtobufEncoder::new();
    encoder.write_bytes(1, metadata);
    encoder.write_string(2, request.diff);
    encoder.write_string(3, request.repo_name);
    encoder.write_string(4, request.commit_hash);
    encoder.write_string(5, request.author_name);
    encoder.write_string(7, request.commit_message);
    for rule in request.user_rules {
        encoder.write_string(9, rule);
    }
    encoder.write_string(10, request.method);
    encoder.write_string(11, request.symbol_context);
    encoder.write_string(12, request.check_type);
    encoder.write_string(13, request.base_ref);
    encoder.write_string(14, request.git_root);
    encoder.to_bytes()
}

fn encode_get_chat_message_request(
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
    encoder.write_varint(4, estimate_tokens(prompt));
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

fn estimate_tokens(prompt: &str) -> u64 {
    (prompt.chars().count() as u64 / 4).max(1)
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

fn parse_get_chat_message_frames(frames: &[Vec<u8>]) -> String {
    let mut text = String::new();
    for frame in frames {
        for field in iter_fields(frame) {
            if field.number == 3
                && let Some(delta) = field_string(&field)
            {
                text.push_str(&delta);
            }
        }
    }
    text
}

fn parse_lifeguard_modes(data: &[u8]) -> Result<Vec<LifeguardMode>, NativeError> {
    let config = iter_fields(data)
        .into_iter()
        .find(|field| field.number == 1)
        .and_then(|field| field_bytes(&field).map(ToOwned::to_owned))
        .ok_or(NativeError::Decode("GetLifeguardConfigResponse.config"))?;
    let mut modes = Vec::new();
    for entry in iter_fields(&config)
        .into_iter()
        .filter(|field| field.number == 1)
        .filter_map(|field| field_bytes(&field).map(ToOwned::to_owned))
    {
        if let Some(mode) = parse_lifeguard_mode_entry(&entry) {
            modes.push(mode);
        }
    }
    Ok(modes)
}

fn parse_lifeguard_mode_entry(data: &[u8]) -> Option<LifeguardMode> {
    let mut name = String::new();
    let mut value = Vec::new();
    for field in iter_fields(data) {
        match field.number {
            1 => name = field_string(&field)?,
            2 => value = field_bytes(&field)?.to_vec(),
            _ => {}
        }
    }
    if name.is_empty() {
        return None;
    }

    let mut mode = LifeguardMode {
        name,
        enabled: false,
        model_id: 0,
        model_display_name: String::new(),
        agent_version: String::new(),
    };
    for field in iter_fields(&value) {
        match field.number {
            1 => mode.enabled = field_varint(&field).unwrap_or(0) != 0,
            2 => mode.model_id = field_varint(&field).unwrap_or(0),
            3 => mode.model_display_name = field_string(&field).unwrap_or_default(),
            4 => mode.agent_version = field_string(&field).unwrap_or_default(),
            _ => {}
        }
    }
    Some(mode)
}

fn parse_check_bugs_response(data: &[u8]) -> Result<CheckBugsReport, NativeError> {
    let mut report = CheckBugsReport {
        bugs: Vec::new(),
        bug_check_id: None,
        method_used: None,
        model_used: None,
        playgrounds: None,
        model_id: None,
        agent_version: None,
    };

    for field in iter_fields(data) {
        match field.number {
            1 => {
                if let Some(bytes) = field_bytes(&field) {
                    report.bugs.push(parse_bug(bytes));
                }
            }
            2 => report.bug_check_id = field_string(&field),
            3 => report.method_used = field_string(&field),
            4 => report.model_used = field_string(&field),
            5 => report.playgrounds = field_string(&field),
            6 => report.model_id = field_varint(&field),
            7 => report.agent_version = field_string(&field),
            _ => {}
        }
    }

    Ok(report)
}

pub fn parse_cli_model_configs(data: &[u8]) -> Vec<NativeModelConfig> {
    iter_fields(data)
        .into_iter()
        .filter(|field| field.number == 1)
        .filter_map(|field| field_bytes(&field).and_then(parse_native_model_config))
        .collect()
}

fn parse_native_model_config(data: &[u8]) -> Option<NativeModelConfig> {
    let mut config = NativeModelConfig {
        model_uid: String::new(),
        label: String::new(),
        description: None,
        display_option: None,
    };

    for field in iter_fields(data) {
        match field.number {
            1 => config.label = field_string(&field).unwrap_or_default(),
            22 => config.model_uid = field_string(&field).unwrap_or_default(),
            23 => {
                if let Some(bytes) = field_bytes(&field) {
                    config.display_option = parse_model_info_display_option(bytes);
                }
            }
            27 => config.description = field_string(&field),
            _ => {}
        }
    }

    if config.model_uid.is_empty() {
        None
    } else {
        if config.label.is_empty() {
            config.label = config.model_uid.clone();
        }
        Some(config)
    }
}

fn parse_model_info_display_option(data: &[u8]) -> Option<u64> {
    iter_fields(data)
        .into_iter()
        .find(|field| field.number == 22)
        .and_then(|field| field_varint(&field))
}

pub fn parse_cli_team_settings(data: &[u8]) -> NativeTeamSettings {
    NativeTeamSettings {
        allowed_model_uids: iter_fields(data)
            .into_iter()
            .filter(|field| field.number == 7)
            .filter_map(|field| field_string(&field))
            .collect(),
    }
}

fn parse_bug(data: &[u8]) -> ReviewBug {
    let mut bug = ReviewBug {
        id: String::new(),
        file: String::new(),
        start: 0,
        end: 0,
        title: String::new(),
        description: String::new(),
        severity: String::new(),
        resolution: String::new(),
        confidence: None,
        categories: Vec::new(),
        fix: None,
    };
    for field in iter_fields(data) {
        match field.number {
            1 => bug.id = field_string(&field).unwrap_or_default(),
            2 => bug.file = field_string(&field).unwrap_or_default(),
            3 => bug.start = field_varint(&field).unwrap_or(0) as i32,
            4 => bug.end = field_varint(&field).unwrap_or(0) as i32,
            5 => bug.title = field_string(&field).unwrap_or_default(),
            6 => bug.description = field_string(&field).unwrap_or_default(),
            7 => bug.severity = field_string(&field).unwrap_or_default(),
            8 => bug.resolution = field_string(&field).unwrap_or_default(),
            9 => bug.confidence = field_fixed64_f64(&field),
            10 => {
                if let Some(category) = field_string(&field) {
                    bug.categories.push(category);
                }
            }
            11 => bug.fix = field_bytes(&field).map(parse_fix),
            _ => {}
        }
    }
    bug
}

fn parse_fix(data: &[u8]) -> ReviewFix {
    let mut fix = ReviewFix {
        old_str: String::new(),
        new_str: String::new(),
    };
    for field in iter_fields(data) {
        match field.number {
            1 => fix.old_str = field_string(&field).unwrap_or_default(),
            2 => fix.new_str = field_string(&field).unwrap_or_default(),
            _ => {}
        }
    }
    fix
}

fn service_url(base_url: &str, service: &str) -> String {
    format!("{}/{}", base_url.trim_end_matches('/'), service)
}

fn endpoint_urls(endpoint: NativeClientEndpoint) -> (String, String, String) {
    match endpoint {
        NativeClientEndpoint::Lifeguard => (
            DEFAULT_API_BASE.to_string(),
            AUTH_BASE.to_string(),
            service_url(DEFAULT_API_SERVER_URL, SEAT_MANAGEMENT_SERVICE),
        ),
        NativeClientEndpoint::QuickReview => (
            service_url(DEFAULT_API_SERVER_URL, API_SERVER_SERVICE),
            service_url(DEFAULT_API_SERVER_URL, AUTH_SERVICE),
            service_url(DEFAULT_API_SERVER_URL, SEAT_MANAGEMENT_SERVICE),
        ),
    }
}

fn now_seconds() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs_f64())
        .unwrap_or(0.0)
}

fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}

fn timestamp_message() -> ProtobufEncoder {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let mut timestamp = ProtobufEncoder::new();
    timestamp.write_varint(1, duration.as_secs());
    if duration.subsec_nanos() > 0 {
        timestamp.write_varint(2, u64::from(duration.subsec_nanos()));
    }
    timestamp
}

fn os_name() -> &'static str {
    if cfg!(target_os = "windows") {
        "windows"
    } else if cfg!(target_os = "macos") {
        "darwin"
    } else if cfg!(target_os = "linux") {
        "linux"
    } else {
        env::consts::OS
    }
}

fn jwt_expires_at(jwt: &str) -> f64 {
    let parts = jwt.split('.').collect::<Vec<_>>();
    if parts.len() < 2 {
        return 0.0;
    }
    let mut payload = parts[1].to_string();
    payload.push_str(&"=".repeat((4 - payload.len() % 4) % 4));
    let Ok(decoded) = URL_SAFE.decode(payload) else {
        return 0.0;
    };
    let Ok(value) = serde_json::from_slice::<Value>(&decoded) else {
        return 0.0;
    };
    value.get("exp").and_then(Value::as_f64).unwrap_or(0.0)
}

pub fn format_bugs_markdown(report: &CheckBugsReport) -> String {
    if report.bugs.is_empty() {
        return "No issues found.".to_string();
    }

    let mut lines = Vec::new();
    lines.push(format!("Found {} issue(s).", report.bugs.len()));
    for (index, bug) in report.bugs.iter().enumerate() {
        let title = if bug.title.is_empty() {
            "Untitled issue"
        } else {
            &bug.title
        };
        lines.push(String::new());
        lines.push(format!("{}. {} ({})", index + 1, title, bug.severity));
        if !bug.file.is_empty() {
            lines.push(format!("   File: {}:{}-{}", bug.file, bug.start, bug.end));
        }
        if !bug.description.is_empty() {
            lines.push(format!("   Problem: {}", bug.description));
        }
        if !bug.resolution.is_empty() {
            lines.push(format!("   Fix: {}", bug.resolution));
        }
        if let Some(fix) = &bug.fix
            && (!fix.old_str.is_empty() || !fix.new_str.is_empty())
        {
            lines.push("   Suggested patch:".to_string());
            lines.push(format!("   - old: {}", fix.old_str));
            lines.push(format!("   - new: {}", fix.new_str));
        }
    }
    lines.join("\n")
}

pub fn check_bugs_request_preview(request: &CheckBugsRequest<'_>) -> Value {
    json!({
        "repo_name": request.repo_name,
        "commit_hash": request.commit_hash,
        "author_name": request.author_name,
        "method": request.method,
        "check_type": request.check_type,
        "base_ref": request.base_ref,
        "git_root": request.git_root,
        "diff_bytes": request.diff.len(),
        "user_rules": request.user_rules.len(),
        "symbol_context_bytes": request.symbol_context.len(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lifeguard_client_uses_fixed_official_endpoints() {
        let client = NativeClient::new(NativeClientOptions {
            api_key: Some("test-key".to_string()),
            endpoint: NativeClientEndpoint::Lifeguard,
            timeout_ms: 1000,
        })
        .unwrap();

        assert_eq!(client.api_base, DEFAULT_API_BASE);
        assert_eq!(client.auth_base, AUTH_BASE);
        assert_eq!(
            client.seat_management_base,
            "https://server.codeium.com/exa.seat_management_pb.SeatManagementService"
        );
    }

    #[test]
    fn quick_review_client_uses_fixed_official_endpoints() {
        let client = NativeClient::new(NativeClientOptions {
            api_key: Some("test-key".to_string()),
            endpoint: NativeClientEndpoint::QuickReview,
            timeout_ms: 1000,
        })
        .unwrap();

        assert_eq!(
            client.api_base,
            "https://server.codeium.com/exa.api_server_pb.ApiServerService"
        );
        assert_eq!(
            client.auth_base,
            "https://server.codeium.com/exa.auth_pb.AuthService"
        );
        assert_eq!(
            client.seat_management_base,
            "https://server.codeium.com/exa.seat_management_pb.SeatManagementService"
        );
    }

    #[test]
    fn parses_lifeguard_config_modes() {
        let mut mode = ProtobufEncoder::new();
        mode.write_varint(1, 1);
        mode.write_varint(2, 410);
        mode.write_string(3, "cognition-lifeguard");
        mode.write_string(4, "v2");

        let mut entry = ProtobufEncoder::new();
        entry.write_string(1, "agent");
        entry.write_message(2, &mode);

        let mut config = ProtobufEncoder::new();
        config.write_message(1, &entry);

        let mut response = ProtobufEncoder::new();
        response.write_message(1, &config);

        assert_eq!(
            parse_lifeguard_modes(&response.to_bytes()).unwrap(),
            vec![LifeguardMode {
                name: "agent".to_string(),
                enabled: true,
                model_id: 410,
                model_display_name: "cognition-lifeguard".to_string(),
                agent_version: "v2".to_string(),
            }]
        );
    }

    #[test]
    fn parses_check_bugs_response_with_bug() {
        let mut fix = ProtobufEncoder::new();
        fix.write_string(1, "old");
        fix.write_string(2, "new");

        let mut bug = ProtobufEncoder::new();
        bug.write_string(1, "bug-1");
        bug.write_string(2, "src/lib.rs");
        bug.write_varint(3, 10);
        bug.write_varint(4, 12);
        bug.write_string(5, "Bad change");
        bug.write_string(6, "It breaks behavior.");
        bug.write_string(7, "high");
        bug.write_string(8, "Use the existing helper.");
        bug.write_string(10, "correctness");
        bug.write_message(11, &fix);

        let mut response = ProtobufEncoder::new();
        response.write_message(1, &bug);
        response.write_string(3, "agent");
        response.write_varint(6, 410);
        response.write_string(7, "v2");

        let report = parse_check_bugs_response(&response.to_bytes()).unwrap();
        assert_eq!(report.method_used.as_deref(), Some("agent"));
        assert_eq!(report.model_id, Some(410));
        assert_eq!(report.bugs[0].title, "Bad change");
        assert_eq!(report.bugs[0].fix.as_ref().unwrap().new_str, "new");
    }

    #[test]
    fn formats_no_bug_report() {
        let report = CheckBugsReport {
            bugs: Vec::new(),
            bug_check_id: None,
            method_used: Some("agent".to_string()),
            model_used: None,
            playgrounds: None,
            model_id: Some(410),
            agent_version: Some("v2".to_string()),
        };
        assert_eq!(format_bugs_markdown(&report), "No issues found.");
    }

    #[test]
    fn parses_quick_review_model_configs() {
        let mut model_info = ProtobufEncoder::new();
        model_info.write_varint(22, QUICK_REVIEW_DISPLAY_OPTION);

        let mut config = ProtobufEncoder::new();
        config.write_string(1, "SWE-check");
        config.write_string(22, "swe-check");
        config.write_message(23, &model_info);
        config.write_string(27, "Fast review model");

        let mut response = ProtobufEncoder::new();
        response.write_message(1, &config);

        assert_eq!(
            parse_cli_model_configs(&response.to_bytes()),
            vec![NativeModelConfig {
                model_uid: "swe-check".to_string(),
                label: "SWE-check".to_string(),
                description: Some("Fast review model".to_string()),
                display_option: Some(QUICK_REVIEW_DISPLAY_OPTION),
            }]
        );
    }

    #[test]
    fn parses_optional_local_model_config_cache() {
        let Some(path) = env::var_os("SWE_REVIEW_TEST_MODEL_CONFIG_CACHE") else {
            return;
        };
        let data = std::fs::read(path).unwrap();
        let models = parse_cli_model_configs(&data);

        assert!(models.iter().any(|model| {
            model.model_uid == "swe-check"
                && model.label == "SWE-check"
                && model.display_option == Some(QUICK_REVIEW_DISPLAY_OPTION)
        }));
    }

    #[test]
    fn parses_allowed_model_uids() {
        let mut response = ProtobufEncoder::new();
        response.write_string(7, "swe-check");
        response.write_string(7, "gpt-5-5-review");

        assert_eq!(
            parse_cli_team_settings(&response.to_bytes()),
            NativeTeamSettings {
                allowed_model_uids: vec!["swe-check".to_string(), "gpt-5-5-review".to_string()],
            }
        );
    }

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

    #[test]
    fn parses_get_chat_message_visible_text() {
        let mut first = ProtobufEncoder::new();
        first.write_string(3, "Looks ");
        first.write_string(9, "hidden reasoning");
        let mut second = ProtobufEncoder::new();
        second.write_string(3, "good.");

        assert_eq!(
            parse_get_chat_message_frames(&[first.to_bytes(), second.to_bytes()]),
            "Looks good."
        );
    }
}
