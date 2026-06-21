use super::{CONFIG_KEY, CredentialsError, non_empty};
use serde_json::{Value, json};
use std::env;
use std::fs;
use std::io;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

pub fn write_swe_tools_config_api_key(api_key: &str) -> Result<PathBuf, CredentialsError> {
    let path = get_config_path().ok_or(CredentialsError::ConfigPathMissing)?;
    write_swe_tools_config_api_key_to(&path, api_key)?;
    Ok(path)
}

pub(super) fn swe_tools_config_api_key() -> Result<Option<(String, PathBuf)>, CredentialsError> {
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
    let text = serde_json::to_string_pretty(&json!({ CONFIG_KEY: api_key })).map_err(|source| {
        CredentialsError::Json {
            path: path.to_path_buf(),
            source,
        }
    })?;
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
pub(super) enum ConfigPlatform {
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

pub(super) fn swe_tools_config_path_for(
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
