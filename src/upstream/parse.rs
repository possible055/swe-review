use super::client::{
    CheckBugsReport, LifeguardMode, NativeError, NativeModelConfig, NativeTeamSettings, ReviewBug,
    ReviewFix,
};
use crate::protobuf::{field_bytes, field_fixed64_f64, field_string, field_varint, iter_fields};
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

pub(super) fn parse_lifeguard_modes(data: &[u8]) -> Result<Vec<LifeguardMode>, NativeError> {
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

pub(super) fn parse_check_bugs_response(data: &[u8]) -> Result<CheckBugsReport, NativeError> {
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
