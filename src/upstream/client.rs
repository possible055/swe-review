use super::encode::encode_get_chat_message_request;
use super::parse::{
    jwt_expires_at, parse_cli_model_configs, parse_cli_team_settings, parse_get_chat_message_frames,
};
use super::transport::{post, post_connect_stream};
use crate::protobuf::ProtobufEncoder;
use serde::Serialize;
use std::env;
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;
use uuid::Uuid;

pub const DEFAULT_API_SERVER_URL: &str = "https://server.codeium.com";
pub const QUICK_REVIEW_DISPLAY_OPTION: u64 = 4;

const API_SERVER_SERVICE: &str = "exa.api_server_pb.ApiServerService";
const AUTH_SERVICE: &str = "exa.auth_pb.AuthService";
const SEAT_MANAGEMENT_SERVICE: &str = "exa.seat_management_pb.SeatManagementService";
const WS_APP: &str = "windsurf";
const DEFAULT_WS_APP_VER: &str = "0.2.0";
const DEFAULT_WS_LS_VER: &str = "1.110.1";
const DEFAULT_CLOUD_VERSION: &str = "2.0.0";

#[derive(Debug, Clone)]
pub struct NativeClientOptions {
    pub api_key: Option<String>,
    pub timeout_ms: u64,
    pub identity: NativeClientIdentity,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeClientIdentity {
    windsurf_extension_version: String,
    windsurf_ls_version: String,
    cloud_version: String,
}

impl Default for NativeClientIdentity {
    fn default() -> Self {
        Self {
            windsurf_extension_version: DEFAULT_WS_APP_VER.to_string(),
            windsurf_ls_version: DEFAULT_WS_LS_VER.to_string(),
            cloud_version: DEFAULT_CLOUD_VERSION.to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct NativeModelConfig {
    pub model_uid: String,
    pub label: String,
    pub description: Option<String>,
    pub display_option: Option<u64>,
}

#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
pub struct NativeTeamSettings {
    pub allowed_model_uids: Vec<String>,
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
    identity: NativeClientIdentity,
}

impl NativeClient {
    pub fn new(options: NativeClientOptions) -> Result<Self, NativeError> {
        let api_key = options
            .api_key
            .filter(|key| !key.trim().is_empty())
            .ok_or(NativeError::ApiKeyMissing)?;
        let client = reqwest::Client::builder()
            .build()
            .map_err(|err| NativeError::Network(err.to_string()))?;

        Ok(Self {
            api_key,
            api_base: service_url(DEFAULT_API_SERVER_URL, API_SERVER_SERVICE),
            auth_base: service_url(DEFAULT_API_SERVER_URL, AUTH_SERVICE),
            seat_management_base: service_url(DEFAULT_API_SERVER_URL, SEAT_MANAGEMENT_SERVICE),
            timeout_ms: options.timeout_ms,
            client,
            jwt: None,
            identity: options.identity,
        })
    }

    pub async fn get_cli_model_configs(&mut self) -> Result<Vec<NativeModelConfig>, NativeError> {
        let metadata = self.jwt_metadata().await?;
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
        let metadata = self.jwt_metadata().await?;
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

    async fn jwt_metadata(&mut self) -> Result<Vec<u8>, NativeError> {
        let jwt = self.jwt().await?;
        let mut metadata = ProtobufEncoder::new();
        metadata.write_string(1, WS_APP);
        metadata.write_string(2, &self.identity.windsurf_extension_version);
        metadata.write_string(3, &self.api_key);
        metadata.write_string(4, "zh-cn");
        metadata.write_string(7, &self.identity.windsurf_ls_version);
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
        metadata.write_string(2, &self.identity.cloud_version);
        metadata.write_string(3, &self.api_key);
        metadata.write_string(4, "en");
        metadata.write_string(5, os_name());
        metadata.write_string(7, &self.identity.cloud_version);
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
        metadata.write_string(2, &self.identity.windsurf_extension_version);
        metadata.write_string(3, &self.api_key);
        metadata.write_string(4, "zh-cn");
        metadata.write_string(7, &self.identity.windsurf_ls_version);
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
        post(&self.client, url, body, self.timeout_ms).await
    }

    async fn post_connect_stream(
        &self,
        url: &str,
        body: Vec<u8>,
    ) -> Result<Vec<Vec<u8>>, NativeError> {
        post_connect_stream(&self.client, url, body, self.timeout_ms).await
    }
}

fn service_url(base_url: &str, service: &str) -> String {
    format!("{}/{}", base_url.trim_end_matches('/'), service)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_uses_fixed_official_endpoints() {
        let client = NativeClient::new(NativeClientOptions {
            api_key: Some("test-key".to_string()),
            timeout_ms: 1000,
            identity: NativeClientIdentity::default(),
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
}
