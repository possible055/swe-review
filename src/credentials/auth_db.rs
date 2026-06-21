use super::{ExtractKeyResult, WINDSURF_API_KEY_FIELD, WINDSURF_AUTH_STATUS_KEY};
use rusqlite::{Connection, OpenFlags, OptionalExtension};
use serde_json::Value;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

const AUTH_DB_APP_NAMES: &[&str] = &["Devin - Next", "devin", "Windsurf"];

fn auth_db_path(base: &Path, app_name: &str) -> PathBuf {
    base.join(app_name)
        .join("User")
        .join("globalStorage")
        .join("state.vscdb")
}

pub(super) fn push_auth_db_path_candidates(candidates: &mut Vec<PathBuf>, base: &Path) {
    for app_name in AUTH_DB_APP_NAMES {
        candidates.push(auth_db_path(base, app_name));
    }
}

pub(super) fn windows_wsl_roaming_dirs() -> Vec<PathBuf> {
    let c_users = Path::new("/mnt/c/Users");
    if !c_users.exists() {
        return Vec::new();
    }
    let Ok(users) = fs::read_dir(c_users) else {
        return Vec::new();
    };
    let mut dirs = Vec::new();
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
        dirs.push(user_dir.join("AppData").join("Roaming"));
    }
    dirs
}

pub(super) fn auth_db_path_candidates() -> Result<Vec<PathBuf>, String> {
    let home = env::var_os("HOME").map(PathBuf::from);

    if cfg!(target_os = "macos") {
        let home = home.ok_or("Cannot determine HOME path")?;
        let app_support = home.join("Library").join("Application Support");
        let mut candidates = Vec::new();
        push_auth_db_path_candidates(&mut candidates, &app_support);
        return Ok(candidates);
    }

    if cfg!(target_os = "windows") {
        let appdata = env::var_os("APPDATA").ok_or("Cannot determine APPDATA path")?;
        let appdata = PathBuf::from(appdata);
        let mut candidates = Vec::new();
        push_auth_db_path_candidates(&mut candidates, &appdata);
        return Ok(candidates);
    }

    let mut candidates = Vec::new();
    for roaming in windows_wsl_roaming_dirs() {
        push_auth_db_path_candidates(&mut candidates, &roaming);
    }

    let config_dir = env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| home.map(|path| path.join(".config")))
        .ok_or("Cannot determine HOME path")?;
    push_auth_db_path_candidates(&mut candidates, &config_dir);
    Ok(candidates)
}

pub(super) fn extract_key_from_candidates(candidates: &[PathBuf]) -> ExtractKeyResult {
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

pub(super) fn extract_key_from_path(path: &Path) -> ExtractKeyResult {
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
