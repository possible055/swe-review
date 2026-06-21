use super::{ExtractKeyResult, auth_db::windows_wsl_roaming_dirs, non_empty};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

fn devin_credentials_path_candidates() -> Vec<PathBuf> {
    let mut candidates = Vec::new();

    if cfg!(windows) {
        if let Some(appdata) = env::var_os("APPDATA") {
            candidates.push(
                PathBuf::from(appdata)
                    .join("devin")
                    .join("credentials.toml"),
            );
        }
        return candidates;
    }

    if let Some(home) = env::var_os("HOME") {
        candidates.push(
            PathBuf::from(home)
                .join(".config")
                .join("devin")
                .join("credentials.toml"),
        );
    }

    for roaming in windows_wsl_roaming_dirs() {
        candidates.push(roaming.join("devin").join("credentials.toml"));
    }

    candidates
}

pub(super) fn extract_key_from_devin_credentials_candidates() -> ExtractKeyResult {
    let candidates = devin_credentials_path_candidates();
    let mut attempted = Vec::new();
    let mut first_error = None;

    for path in candidates {
        if !path.exists() {
            attempted.push(path.to_string_lossy().into_owned());
            continue;
        }

        let result = extract_key_from_devin_credentials_path(&path);
        if result.api_key.is_some() {
            return result;
        }
        if first_error.is_none() {
            first_error = result.error.clone();
        }
        attempted.push(path.to_string_lossy().into_owned());
    }

    if let Some(error) = first_error {
        return ExtractKeyResult::error_with_hint(
            error,
            format!("Checked Devin credentials: {}", attempted.join(", ")),
            attempted.first().cloned().unwrap_or_default(),
        );
    }

    let fallback = attempted.first().cloned().unwrap_or_default();
    ExtractKeyResult::error_with_hint(
        "Devin credentials.toml not found",
        format!("Checked Devin credentials: {}", attempted.join(", ")),
        fallback,
    )
}

fn extract_key_from_devin_credentials_path(path: &Path) -> ExtractKeyResult {
    let text = match fs::read_to_string(path) {
        Ok(text) => text,
        Err(error) => {
            return ExtractKeyResult::error(
                format!("Failed to read Devin credentials: {error}"),
                path.to_string_lossy(),
            );
        }
    };

    let api_key = match parse_devin_credentials_api_key(&text) {
        Ok(Some(api_key)) => api_key,
        Ok(None) => {
            return ExtractKeyResult::error(
                "windsurf_api_key field not found in Devin credentials",
                path.to_string_lossy(),
            );
        }
        Err(error) => {
            return ExtractKeyResult::error(
                format!("Failed to parse Devin credentials: {error}"),
                path.to_string_lossy(),
            );
        }
    };

    ExtractKeyResult::success(api_key, path, "Source credentials")
}

pub(super) fn parse_devin_credentials_api_key(
    text: &str,
) -> Result<Option<String>, toml::de::Error> {
    let data: toml::Value = toml::from_str(text)?;
    Ok(data
        .get("windsurf_api_key")
        .and_then(|value| value.as_str())
        .and_then(|value| non_empty(Some(value.to_string()))))
}
