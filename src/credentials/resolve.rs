use super::{
    ApiKeySource, ExtractKeyResult, ResolveApiKeyError, ResolvedApiKey, config, extract_key,
    non_empty, resolved,
};
use std::env;
use std::path::PathBuf;

pub fn resolve_api_key(explicit: Option<String>) -> Result<ResolvedApiKey, ResolveApiKeyError> {
    resolve_api_key_with_extractor(explicit, || extract_key(None))
}

pub(super) fn resolve_api_key_with_extractor(
    explicit: Option<String>,
    extract: impl FnOnce() -> ExtractKeyResult,
) -> Result<ResolvedApiKey, ResolveApiKeyError> {
    if let Some(value) = non_empty(explicit) {
        return Ok(resolved(value, ApiKeySource::Explicit));
    }

    if let Some(value) = env::var("WINDSURF_API_KEY")
        .ok()
        .and_then(|value| non_empty(Some(value)))
    {
        return Ok(resolved(value, ApiKeySource::Env("WINDSURF_API_KEY")));
    }

    match config::swe_tools_config_api_key() {
        Ok(Some((value, path))) => return Ok(resolved(value, ApiKeySource::Config(path))),
        Ok(None) => {}
        Err(error) => {
            eprintln!(
                "Warning: failed to read swe-tools config; falling back to credential extraction: {error}"
            );
        }
    }

    let result = extract();
    match result.api_key {
        Some(value) => {
            let path = PathBuf::from(result.db_path);
            Ok(resolved(value, ApiKeySource::AuthDb(path)))
        }
        None => Err(ResolveApiKeyError::ExtractKey {
            error: result
                .error
                .unwrap_or_else(|| "apiKey field is empty".to_string()),
            hint: result.hint,
        }),
    }
}
