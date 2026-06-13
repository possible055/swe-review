use rusqlite::{Connection, OpenFlags, OptionalExtension};
use serde_json::{Value, json};
use std::env;
use std::fmt;
use std::fs;
use std::io;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
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
    Config(String),
    ExtractKey { error: String, hint: Option<String> },
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

pub fn resolve_api_key(explicit: Option<String>) -> Result<ResolvedApiKey, ResolveApiKeyError> {
    resolve_api_key_with_extractor(explicit, || extract_key(None))
}

fn resolve_api_key_with_extractor(
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

    match swe_tools_config_api_key() {
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

pub fn write_swe_tools_config_api_key(api_key: &str) -> Result<PathBuf, CredentialsError> {
    let path = get_config_path().ok_or(CredentialsError::ConfigPathMissing)?;
    write_swe_tools_config_api_key_to(&path, api_key)?;
    Ok(path)
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
        return extract_key_from_path(path);
    }

    let credentials = extract_key_from_devin_credentials_candidates();
    if credentials.api_key.is_some() {
        return credentials;
    }

    let candidates = match auth_db_path_candidates() {
        Ok(paths) => paths,
        Err(err) => {
            return ExtractKeyResult::error(format!("Cannot determine database path: {err}"), "");
        }
    };
    extract_key_from_candidates(&candidates)
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

fn swe_tools_config_api_key() -> Result<Option<(String, PathBuf)>, CredentialsError> {
    let Some(path) = get_config_path() else {
        return Ok(None);
    };
    let text = match fs::read_to_string(&path) {
        Ok(text) => text,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(source) => {
            return Err(CredentialsError::Read {
                path: path.clone(),
                source,
            });
        }
    };
    let value: Value = serde_json::from_str(&text).map_err(|source| CredentialsError::Json {
        path: path.clone(),
        source,
    })?;
    Ok(value
        .get(CONFIG_KEY)
        .and_then(|value| value.as_str())
        .and_then(|value| non_empty(Some(value.to_string())))
        .map(|value| (value, path)))
}

fn write_swe_tools_config_api_key_to(path: &Path, api_key: &str) -> Result<(), CredentialsError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|source| CredentialsError::Write {
            path: parent.to_path_buf(),
            source,
        })?;
    }
    let text = serde_json::to_string_pretty(&json!({ "WINDSURF_API_KEY": api_key }))
        .expect("static JSON object serializes");
    fs::write(path, format!("{text}\n")).map_err(|source| CredentialsError::Write {
        path: path.to_path_buf(),
        source,
    })?;
    #[cfg(unix)]
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).map_err(|source| {
        CredentialsError::Write {
            path: path.to_path_buf(),
            source,
        }
    })?;
    Ok(())
}

pub fn get_config_path() -> Option<PathBuf> {
    swe_tools_config_path_for(
        ConfigPlatform::current(),
        env::var_os("APPDATA"),
        env::var_os("XDG_CONFIG_HOME"),
        env::var_os("HOME"),
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConfigPlatform {
    Windows,
    Unix,
}

impl ConfigPlatform {
    fn current() -> Self {
        if cfg!(windows) {
            Self::Windows
        } else {
            Self::Unix
        }
    }
}

fn swe_tools_config_path_for(
    platform: ConfigPlatform,
    appdata: Option<impl Into<PathBuf>>,
    xdg_config_home: Option<impl Into<PathBuf>>,
    home: Option<impl Into<PathBuf>>,
) -> Option<PathBuf> {
    match platform {
        ConfigPlatform::Windows => appdata
            .map(Into::into)
            .filter(|path: &PathBuf| !path.as_os_str().is_empty())
            .map(|path| path.join("swe-tools").join("config.json")),
        ConfigPlatform::Unix => xdg_config_home
            .map(Into::into)
            .filter(|path: &PathBuf| !path.as_os_str().is_empty())
            .or_else(|| {
                home.map(Into::into)
                    .filter(|path: &PathBuf| !path.as_os_str().is_empty())
                    .map(|path: PathBuf| path.join(".config"))
            })
            .map(|path| path.join("swe-tools").join("config.json")),
    }
}

fn auth_db_path(base: &Path, app_name: &str) -> PathBuf {
    base.join(app_name)
        .join("User")
        .join("globalStorage")
        .join("state.vscdb")
}

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

    let c_users = Path::new("/mnt/c/Users");
    if c_users.exists()
        && let Ok(users) = fs::read_dir(c_users)
    {
        for entry in users.flatten() {
            let user_dir = entry.path();
            if !user_dir.is_dir() {
                continue;
            }
            let Some(name) = user_dir.file_name().and_then(|name| name.to_str()) else {
                continue;
            };
            if name.starts_with('.') {
                continue;
            }
            candidates.push(
                user_dir
                    .join("AppData")
                    .join("Roaming")
                    .join("devin")
                    .join("credentials.toml"),
            );
        }
    }

    candidates
}

fn extract_key_from_devin_credentials_candidates() -> ExtractKeyResult {
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

fn parse_devin_credentials_api_key(text: &str) -> Result<Option<String>, toml::de::Error> {
    let data: toml::Value = toml::from_str(text)?;
    Ok(data
        .get("windsurf_api_key")
        .and_then(|value| value.as_str())
        .and_then(|value| non_empty(Some(value.to_string()))))
}

fn auth_db_path_candidates() -> Result<Vec<PathBuf>, String> {
    let home = env::var_os("HOME").map(PathBuf::from);

    if cfg!(target_os = "macos") {
        let home = home.ok_or("Cannot determine HOME path")?;
        let app_support = home.join("Library").join("Application Support");
        return Ok(vec![
            auth_db_path(&app_support, "Windsurf"),
            auth_db_path(&app_support, "devin"),
        ]);
    }

    if cfg!(target_os = "windows") {
        let appdata = env::var_os("APPDATA").ok_or("Cannot determine APPDATA path")?;
        let appdata = PathBuf::from(appdata);
        return Ok(vec![
            auth_db_path(&appdata, "Windsurf"),
            auth_db_path(&appdata, "devin"),
        ]);
    }

    let mut candidates = Vec::new();
    let c_users = Path::new("/mnt/c/Users");
    if c_users.exists()
        && let Ok(users) = fs::read_dir(c_users)
    {
        for entry in users.flatten() {
            let user_dir = entry.path();
            if !user_dir.is_dir() {
                continue;
            }
            let Some(name) = user_dir.file_name().and_then(|name| name.to_str()) else {
                continue;
            };
            if name.starts_with('.') {
                continue;
            }
            let roaming = user_dir.join("AppData").join("Roaming");
            candidates.push(auth_db_path(&roaming, "Windsurf"));
            candidates.push(auth_db_path(&roaming, "devin"));
        }
    }

    let config_dir = env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| home.map(|path| path.join(".config")))
        .ok_or("Cannot determine HOME path")?;
    candidates.push(auth_db_path(&config_dir, "Windsurf"));
    candidates.push(auth_db_path(&config_dir, "devin"));
    Ok(candidates)
}

fn extract_key_from_candidates(candidates: &[PathBuf]) -> ExtractKeyResult {
    let mut attempted = Vec::new();
    let mut first_error = None;
    for path in candidates {
        if !path.exists() {
            attempted.push(path.to_string_lossy().into_owned());
            continue;
        }
        let result = extract_key_from_path(path);
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
            format!("Checked auth databases: {}", attempted.join(", ")),
            attempted.first().cloned().unwrap_or_default(),
        );
    }

    let fallback = candidates.first().cloned().unwrap_or_default();
    ExtractKeyResult::error_with_hint(
        format!("Auth database not found: {}", fallback.display()),
        format!("Checked auth databases: {}", attempted.join(", ")),
        fallback.to_string_lossy(),
    )
}

fn extract_key_from_path(path: &Path) -> ExtractKeyResult {
    if !path.exists() {
        return ExtractKeyResult::error_with_hint(
            format!("Auth database not found: {}", path.display()),
            "Ensure Windsurf or Devin is installed and logged in.",
            path.to_string_lossy(),
        );
    }

    let conn = match Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY) {
        Ok(conn) => conn,
        Err(_) => match Connection::open(path) {
            Ok(conn) => conn,
            Err(err) => {
                return ExtractKeyResult::error(
                    format!("Failed to open database: {err}"),
                    path.to_string_lossy(),
                );
            }
        },
    };

    extract_key_from_connection(&conn, path)
        .unwrap_or_else(|err| ExtractKeyResult::error(err, path.to_string_lossy()))
}

fn extract_key_from_connection(conn: &Connection, path: &Path) -> Result<ExtractKeyResult, String> {
    let value: Option<String> = conn
        .query_row(
            "SELECT value FROM ItemTable WHERE key = ?",
            [WINDSURF_AUTH_STATUS_KEY],
            |row| row.get(0),
        )
        .optional()
        .map_err(|err| format!("Extraction failed: {err}"))?;

    let Some(value) = value else {
        return Ok(ExtractKeyResult::error_with_hint(
            "windsurfAuthStatus record not found",
            "Ensure Windsurf is logged in.",
            path.to_string_lossy(),
        ));
    };

    let data: Value = serde_json::from_str(&value)
        .map_err(|_| "windsurfAuthStatus data parse failed".to_string())?;
    let Some(api_key_value) = data.get(WINDSURF_API_KEY_FIELD) else {
        return Ok(ExtractKeyResult::error(
            "apiKey field is empty",
            path.to_string_lossy(),
        ));
    };
    let Some(api_key) = api_key_value.as_str() else {
        return Ok(ExtractKeyResult::error(
            "apiKey field is not a string",
            path.to_string_lossy(),
        ));
    };
    if api_key.is_empty() {
        return Ok(ExtractKeyResult::error(
            "apiKey field is empty",
            path.to_string_lossy(),
        ));
    }

    Ok(ExtractKeyResult::success(
        api_key.to_string(),
        path,
        "Source DB",
    ))
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
    use rusqlite::params;
    use serde_json::json;
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

        let resolved = resolve_api_key_with_extractor(None, || ExtractKeyResult {
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

        let resolved = resolve_api_key_with_extractor(None, || ExtractKeyResult {
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

        let error = resolve_api_key_with_extractor(None, || {
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

        let result = resolve_api_key_with_extractor(None, || {
            ExtractKeyResult::error("Auth database not found", "")
        });

        assert!(matches!(result, Err(ResolveApiKeyError::ExtractKey { .. })));
    }

    #[test]
    fn swe_review_api_key_is_not_accepted() {
        let _guard = clear_key_env();
        unsafe { env::set_var("SWE_REVIEW_API_KEY", "legacy-key") };

        let result = resolve_api_key_with_extractor(None, || {
            ExtractKeyResult::error("Auth database not found", "")
        });

        assert!(matches!(result, Err(ResolveApiKeyError::ExtractKey { .. })));
    }

    #[test]
    fn linux_config_path_prefers_xdg_config_home() {
        let path = swe_tools_config_path_for(
            ConfigPlatform::Unix,
            None::<PathBuf>,
            Some(PathBuf::from("/tmp/xdg")),
            Some(PathBuf::from("/home/alice")),
        )
        .unwrap();

        assert_eq!(path, PathBuf::from("/tmp/xdg/swe-tools/config.json"));
    }

    #[test]
    fn linux_config_path_falls_back_to_home_config() {
        let path = swe_tools_config_path_for(
            ConfigPlatform::Unix,
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
        let path = swe_tools_config_path_for(
            ConfigPlatform::Windows,
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
            parse_devin_credentials_api_key(text).unwrap().as_deref(),
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

        let result = extract_key_from_candidates(&[windsurf_db_path, devin_db_path.clone()]);

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
