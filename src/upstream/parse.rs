use super::client::{NativeModelConfig, NativeTeamSettings};
use crate::protobuf::{field_bytes, field_string, field_varint, iter_fields};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE;
use serde_json::Value;

pub(super) fn parse_get_chat_message_frames(frames: &[Vec<u8>]) -> String {
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

pub(super) fn jwt_expires_at(jwt: &str) -> f64 {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protobuf::ProtobufEncoder;
    use crate::upstream::QUICK_REVIEW_DISPLAY_OPTION;
    use std::env;

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
