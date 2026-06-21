mod auth_db;
mod config;
mod devin;
mod resolve;

pub use config::write_swe_tools_config_api_key;
pub use resolve::resolve_api_key;

use std::fmt;
use std::io;
use std::path::{Path, PathBuf};
use thiserror::Error;

pub const CONFIG_KEY: &str = "WINDSURF_API_KEY";
const WINDSURF_AUTH_STATUS_KEY: &str = "windsurfAuthStatus";
const WINDSURF_API_KEY_FIELD: &str = "apiKey";
const SESSION_TOKEN_PREFIX: &str = "devin-session-token$";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedApiKey {
    pub value: String,
    pub source: ApiKeySource,
    pub is_session_token: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApiKeySource {
    Explicit,
    Env(&'static str),
    Config(PathBuf),
    AuthDb(PathBuf),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtractKeyResult {
    pub api_key: Option<String>,
    pub error: Option<String>,
    pub hint: Option<String>,
    pub db_path: String,
    pub source_label: &'static str,
    pub key_type: Option<String>,
}

impl ExtractKeyResult {
    fn success(api_key: String, path: &Path, source_label: &'static str) -> Self {
        Self {
            key_type: Some(classify_api_key(&api_key).to_string()),
            api_key: Some(api_key),
            error: None,
            hint: None,
            db_path: path.to_string_lossy().into_owned(),
            source_label,
        }
    }

    fn error(message: impl Into<String>, db_path: impl Into<String>) -> Self {
        Self {
            api_key: None,
            error: Some(message.into()),
            hint: None,
            db_path: db_path.into(),
            source_label: "Source",
            key_type: None,
        }
    }

    fn error_with_hint(
        message: impl Into<String>,
        hint: impl Into<String>,
        db_path: impl Into<String>,
    ) -> Self {
        Self {
            api_key: None,
            error: Some(message.into()),
            hint: Some(hint.into()),
            db_path: db_path.into(),
            source_label: "Source",
            key_type: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolveApiKeyError {
    #[allow(dead_code)]
    Config(String),
    ExtractKey {
        error: String,
        hint: Option<String>,
    },
}

impl fmt::Display for ResolveApiKeyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let prefix = "Windsurf API key not found. Provide --api-key, set WINDSURF_API_KEY, add WINDSURF_API_KEY to swe-tools/config.json, or run `swe-review extract-key --save`.";
        match self {
            Self::Config(error) => write!(formatter, "{prefix} Config read failed: {error}"),
            Self::ExtractKey { error, hint } => {
                write!(formatter, "{prefix} extract-key failed: {error}")?;
                if let Some(hint) = hint {
                    write!(formatter, " Hint: {hint}")?;
                }
                Ok(())
            }
        }
    }
}

impl std::error::Error for ResolveApiKeyError {}

#[derive(Debug, Error)]
pub enum CredentialsError {
    #[error("swe-tools config path could not be determined")]
    ConfigPathMissing,
    #[error("failed to read {path}: {source}")]
    Read { path: PathBuf, source: io::Error },
    #[error("failed to write {path}: {source}")]
    Write { path: PathBuf, source: io::Error },
    #[error("failed to parse {path}: {source}")]
    Json {
        path: PathBuf,
        source: serde_json::Error,
    },
}

pub fn classify_api_key(value: &str) -> &'static str {
    if value.starts_with("sk-") {
        return "standard";
    }
    if let Some((_, jwt)) = value.split_once('$')
        && jwt.starts_with("eyJ")
        && jwt.contains('.')
    {
        return if value.starts_with(SESSION_TOKEN_PREFIX) {
            "session-token"
        } else {
            "embedded-jwt"
        };
    }
    "unknown"
}

pub fn mask_api_key(key: &str) -> String {
    if key.len() <= 16 {
        "*".repeat(key.len())
    } else {
        format!("{}...{}", &key[..10], &key[key.len() - 6..])
    }
}

pub fn extract_key(db_path: Option<&Path>) -> ExtractKeyResult {
    if let Some(path) = db_path {
        return auth_db::extract_key_from_path(path);
    }

    let credentials = devin::extract_key_from_devin_credentials_candidates();
    if credentials.api_key.is_some() {
        return credentials;
    }

    let candidates = match auth_db::auth_db_path_candidates() {
        Ok(paths) => paths,
        Err(err) => {
            return ExtractKeyResult::error(format!("Cannot determine database path: {err}"), "");
        }
    };
    auth_db::extract_key_from_candidates(&candidates)
}

#[allow(dead_code)]
pub fn get_config_path() -> Option<PathBuf> {
    config::get_config_path()
}

fn resolved(value: String, source: ApiKeySource) -> ResolvedApiKey {
    ResolvedApiKey {
        is_session_token: value.starts_with(SESSION_TOKEN_PREFIX),
        value,
        source,
    }
}

fn non_empty(value: Option<String>) -> Option<String> {
    value
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

impl fmt::Display for ApiKeySource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Explicit => formatter.write_str("--api-key"),
            Self::Env(name) => formatter.write_str(name),
            Self::Config(path) => write!(formatter, "{}", path.display()),
            Self::AuthDb(path) => write!(formatter, "{}", path.display()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::{Connection, params};
    use serde_json::{Value, json};
    use std::env;
    use std::fs;
    use std::path::Path;
    use std::sync::{Mutex, MutexGuard};

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    struct EnvGuard {
        _lock: MutexGuard<'static, ()>,
        values: Vec<(&'static str, Option<std::ffi::OsString>)>,
    }

    impl EnvGuard {
        fn new(names: &[&'static str]) -> Self {
            let lock = ENV_LOCK.lock().unwrap();
            let values = names
                .iter()
                .map(|name| (*name, env::var_os(name)))
                .collect();
            Self {
                _lock: lock,
                values,
            }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            for (name, value) in &self.values {
                if let Some(value) = value {
                    unsafe { env::set_var(name, value) };
                } else {
                    unsafe { env::remove_var(name) };
                }
            }
        }
    }

    fn clear_key_env() -> EnvGuard {
        let guard = EnvGuard::new(&[
            "WINDSURF_API_KEY",
            "SWE_REVIEW_API_KEY",
            "XDG_CONFIG_HOME",
            "HOME",
            "APPDATA",
        ]);
        unsafe { env::remove_var("WINDSURF_API_KEY") };
        unsafe { env::remove_var("SWE_REVIEW_API_KEY") };
        unsafe { env::remove_var("XDG_CONFIG_HOME") };
        unsafe { env::remove_var("HOME") };
        unsafe { env::remove_var("APPDATA") };
        guard
    }

    #[test]
    fn explicit_api_key_wins_over_env_and_config() {
        let _guard = clear_key_env();
        let temp = tempfile::tempdir().unwrap();
        let config_home = temp.path().join("xdg");
        let config_path = config_home.join("swe-tools").join("config.json");
        fs::create_dir_all(config_path.parent().unwrap()).unwrap();
        fs::write(&config_path, r#"{"WINDSURF_API_KEY":"config-key"}"#).unwrap();
        unsafe { env::set_var("WINDSURF_API_KEY", "env-key") };
        unsafe { env::set_var("XDG_CONFIG_HOME", &config_home) };

        let resolved = resolve_api_key(Some("explicit-key".to_string())).unwrap();

        assert_eq!(resolved.value, "explicit-key");
        assert_eq!(resolved.source, ApiKeySource::Explicit);
    }

    #[test]
    fn windsurf_env_wins_over_config() {
        let _guard = clear_key_env();
        let temp = tempfile::tempdir().unwrap();
        let config_home = temp.path().join("xdg");
        let config_path = config_home.join("swe-tools").join("config.json");
        fs::create_dir_all(config_path.parent().unwrap()).unwrap();
        fs::write(&config_path, r#"{"WINDSURF_API_KEY":"config-key"}"#).unwrap();
        unsafe { env::set_var("WINDSURF_API_KEY", "env-key") };
        unsafe { env::set_var("XDG_CONFIG_HOME", &config_home) };

        let resolved = resolve_api_key(None).unwrap();

        assert_eq!(resolved.value, "env-key");
        assert_eq!(resolved.source, ApiKeySource::Env("WINDSURF_API_KEY"));
    }

    #[test]
    fn swe_tools_config_is_used_when_env_is_missing() {
        let _guard = clear_key_env();
        let temp = tempfile::tempdir().unwrap();
        let config_path = temp
            .path()
            .join(".config")
            .join("swe-tools")
            .join("config.json");
        fs::create_dir_all(config_path.parent().unwrap()).unwrap();
        fs::write(&config_path, r#"{"WINDSURF_API_KEY":"config-key"}"#).unwrap();
        unsafe { env::set_var("HOME", temp.path()) };

        let resolved = resolve_api_key(None).unwrap();

        assert_eq!(resolved.value, "config-key");
        assert_eq!(resolved.source, ApiKeySource::Config(config_path));
    }

    #[test]
    fn extract_key_is_used_when_explicit_env_and_config_are_missing() {
        let _guard = clear_key_env();
        let db_path = PathBuf::from("/tmp/state.vscdb");

        let resolved = resolve::resolve_api_key_with_extractor(None, || ExtractKeyResult {
            api_key: Some("sk-ws-01-discovered".to_string()),
            error: None,
            hint: None,
            db_path: db_path.to_string_lossy().into_owned(),
            source_label: "Source DB",
            key_type: Some("standard".to_string()),
        })
        .unwrap();

        assert_eq!(resolved.value, "sk-ws-01-discovered");
        assert_eq!(resolved.source, ApiKeySource::AuthDb(db_path));
    }

    #[test]
    fn invalid_config_warns_and_falls_back_to_extraction() {
        let _guard = clear_key_env();
        let temp = tempfile::tempdir().unwrap();
        let config_path = temp
            .path()
            .join(".config")
            .join("swe-tools")
            .join("config.json");
        let db_path = temp.path().join("state.vscdb");
        fs::create_dir_all(config_path.parent().unwrap()).unwrap();
        fs::write(&config_path, "{not-json").unwrap();
        unsafe { env::set_var("HOME", temp.path()) };

        let resolved = resolve::resolve_api_key_with_extractor(None, || ExtractKeyResult {
            api_key: Some("sk-ws-01-fallback".to_string()),
            error: None,
            hint: None,
            db_path: db_path.to_string_lossy().into_owned(),
            source_label: "Source DB",
            key_type: Some("standard".to_string()),
        })
        .unwrap();

        assert_eq!(resolved.value, "sk-ws-01-fallback");
        assert_eq!(resolved.source, ApiKeySource::AuthDb(db_path));
    }

    #[test]
    fn extract_key_failure_is_reported_when_key_sources_are_missing() {
        let _guard = clear_key_env();

        let error = resolve::resolve_api_key_with_extractor(None, || {
            ExtractKeyResult::error_with_hint(
                "Auth database not found: /tmp/state.vscdb",
                "Ensure Windsurf or Devin is installed and logged in.",
                "/tmp/state.vscdb",
            )
        })
        .unwrap_err();

        let message = error.to_string();
        assert!(message.contains("swe-review extract-key --save"));
        assert!(message.contains("Auth database not found"));
        assert!(message.contains("Ensure Windsurf or Devin is installed and logged in."));
    }

    #[test]
    fn swegrep_config_is_not_used() {
        let _guard = clear_key_env();
        let temp = tempfile::tempdir().unwrap();
        let config_path = temp
            .path()
            .join(".config")
            .join("swegrep")
            .join("config.json");
        fs::create_dir_all(config_path.parent().unwrap()).unwrap();
        fs::write(&config_path, r#"{"WINDSURF_API_KEY":"legacy-key"}"#).unwrap();
        unsafe { env::set_var("HOME", temp.path()) };

        let result = resolve::resolve_api_key_with_extractor(None, || {
            ExtractKeyResult::error("Auth database not found", "")
        });

        assert!(matches!(result, Err(ResolveApiKeyError::ExtractKey { .. })));
    }

    #[test]
    fn swe_review_api_key_is_not_accepted() {
        let _guard = clear_key_env();
        unsafe { env::set_var("SWE_REVIEW_API_KEY", "legacy-key") };

        let result = resolve::resolve_api_key_with_extractor(None, || {
            ExtractKeyResult::error("Auth database not found", "")
        });

        assert!(matches!(result, Err(ResolveApiKeyError::ExtractKey { .. })));
    }

    #[test]
    fn linux_config_path_prefers_xdg_config_home() {
        let path = config::swe_tools_config_path_for(
            config::ConfigPlatform::Unix,
            None::<PathBuf>,
            Some(PathBuf::from("/tmp/xdg")),
            Some(PathBuf::from("/home/alice")),
        )
        .unwrap();

        assert_eq!(path, PathBuf::from("/tmp/xdg/swe-tools/config.json"));
    }

    #[test]
    fn linux_config_path_falls_back_to_home_config() {
        let path = config::swe_tools_config_path_for(
            config::ConfigPlatform::Unix,
            None::<PathBuf>,
            None::<PathBuf>,
            Some(PathBuf::from("/home/alice")),
        )
        .unwrap();

        assert_eq!(
            path,
            PathBuf::from("/home/alice/.config/swe-tools/config.json")
        );
    }

    #[test]
    fn windows_config_path_uses_appdata() {
        let path = config::swe_tools_config_path_for(
            config::ConfigPlatform::Windows,
            Some(PathBuf::from(r"C:\Users\Alice\AppData\Roaming")),
            None::<PathBuf>,
            Some(PathBuf::from("/home/alice")),
        )
        .unwrap();

        assert_eq!(
            path,
            PathBuf::from(r"C:\Users\Alice\AppData\Roaming")
                .join("swe-tools")
                .join("config.json")
        );
    }

    #[test]
    fn session_token_prefix_is_preserved_and_marked() {
        let raw = "devin-session-token$jwt";
        let resolved = resolved(raw.to_string(), ApiKeySource::Explicit);

        assert_eq!(resolved.value, raw);
        assert!(resolved.is_session_token);
    }

    #[test]
    fn auth_db_candidates_prefer_devin_next() {
        let base = PathBuf::from(r"C:\Users\Alice\AppData\Roaming");
        let mut candidates = Vec::new();

        auth_db::push_auth_db_path_candidates(&mut candidates, &base);

        assert_eq!(
            candidates,
            vec![
                base.join("Devin - Next")
                    .join("User")
                    .join("globalStorage")
                    .join("state.vscdb"),
                base.join("devin")
                    .join("User")
                    .join("globalStorage")
                    .join("state.vscdb"),
                base.join("Windsurf")
                    .join("User")
                    .join("globalStorage")
                    .join("state.vscdb"),
            ]
        );
    }

    fn write_auth_db(db_path: &Path, value: Value) {
        let conn = Connection::open(db_path).unwrap();
        conn.execute(
            "CREATE TABLE ItemTable (key TEXT PRIMARY KEY, value TEXT)",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO ItemTable (key, value) VALUES (?1, ?2)",
            params![WINDSURF_AUTH_STATUS_KEY, value.to_string()],
        )
        .unwrap();
    }

    fn write_empty_auth_db(db_path: &Path) {
        let conn = Connection::open(db_path).unwrap();
        conn.execute(
            "CREATE TABLE ItemTable (key TEXT PRIMARY KEY, value TEXT)",
            [],
        )
        .unwrap();
    }

    #[test]
    fn extract_key_reads_windsurf_auth_status() {
        let temp = tempfile::tempdir().unwrap();
        let db_path = temp.path().join("state.vscdb");
        write_auth_db(&db_path, json!({ "apiKey": "sk-ws-01-testkey123456" }));

        let result = extract_key(Some(&db_path));

        assert_eq!(result.api_key.as_deref(), Some("sk-ws-01-testkey123456"));
        assert_eq!(result.db_path, db_path.to_string_lossy());
        assert_eq!(result.key_type.as_deref(), Some("standard"));
    }

    #[test]
    fn devin_credentials_toml_parser_handles_escapes_and_comments() {
        let text = r#"
            api_server_url = "https://server.codeium.com"
            windsurf_api_key = "sk-ws-01-escaped\u002Dkey" # generated by Devin
        "#;

        assert_eq!(
            devin::parse_devin_credentials_api_key(text)
                .unwrap()
                .as_deref(),
            Some("sk-ws-01-escaped-key")
        );
    }

    #[test]
    fn extract_key_reports_missing_record() {
        let temp = tempfile::tempdir().unwrap();
        let db_path = temp.path().join("state.vscdb");
        write_empty_auth_db(&db_path);

        let result = extract_key(Some(&db_path));

        assert!(
            result
                .error
                .as_deref()
                .unwrap()
                .contains("windsurfAuthStatus record not found")
        );
    }

    #[test]
    fn extract_key_from_candidates_tries_next_database() {
        let temp = tempfile::tempdir().unwrap();
        let windsurf_db_path = temp.path().join("Windsurf").join("state.vscdb");
        let devin_db_path = temp.path().join("devin").join("state.vscdb");
        fs::create_dir_all(windsurf_db_path.parent().unwrap()).unwrap();
        fs::create_dir_all(devin_db_path.parent().unwrap()).unwrap();
        write_empty_auth_db(&windsurf_db_path);
        write_auth_db(
            &devin_db_path,
            json!({ "apiKey": "devin-session-token$eyJhbGciOiJIUzI1NiJ9.payload.signature" }),
        );

        let result =
            auth_db::extract_key_from_candidates(&[windsurf_db_path, devin_db_path.clone()]);

        assert_eq!(
            result.api_key.as_deref(),
            Some("devin-session-token$eyJhbGciOiJIUzI1NiJ9.payload.signature")
        );
        assert_eq!(result.db_path, devin_db_path.to_string_lossy());
        assert_eq!(result.key_type.as_deref(), Some("session-token"));
    }

    #[test]
    fn extract_key_prefers_devin_credentials_over_auth_database() {
        let _guard = clear_key_env();
        let temp = tempfile::tempdir().unwrap();
        let credentials_path = temp
            .path()
            .join(".config")
            .join("devin")
            .join("credentials.toml");
        let windsurf_db_path = temp
            .path()
            .join(".config")
            .join("Windsurf")
            .join("User")
            .join("globalStorage")
            .join("state.vscdb");
        fs::create_dir_all(credentials_path.parent().unwrap()).unwrap();
        fs::create_dir_all(windsurf_db_path.parent().unwrap()).unwrap();
        fs::write(
            &credentials_path,
            "windsurf_api_key = \"devin-session-token$credentials\"\n",
        )
        .unwrap();
        write_auth_db(
            &windsurf_db_path,
            json!({ "apiKey": "devin-session-token$windsurf-db" }),
        );
        unsafe { env::set_var("HOME", temp.path()) };

        let result = extract_key(None);

        assert_eq!(
            result.api_key.as_deref(),
            Some("devin-session-token$credentials")
        );
        assert_eq!(result.db_path, credentials_path.to_string_lossy());
        assert_eq!(result.source_label, "Source credentials");
    }
}
