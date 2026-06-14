use assert_cmd::Command;
use rusqlite::{Connection, params};
use serde_json::json;
use std::fs;
use tempfile::TempDir;

fn write_auth_db(path: &std::path::Path, key: &str) {
    let conn = Connection::open(path).unwrap();
    conn.execute(
        "CREATE TABLE ItemTable (key TEXT PRIMARY KEY, value TEXT)",
        [],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO ItemTable (key, value) VALUES (?1, ?2)",
        params!["windsurfAuthStatus", json!({ "apiKey": key }).to_string()],
    )
    .unwrap();
}

#[test]
fn review_command_is_removed() {
    let output = Command::cargo_bin("swe-review")
        .unwrap()
        .args(["review", "--help"])
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("review"));
}

#[test]
fn quick_review_help_is_native_only() {
    let output = Command::cargo_bin("swe-review")
        .unwrap()
        .args(["quick-review", "--help"])
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("--model"));
    assert!(stdout.contains("--api-key"));
    assert!(stdout.contains("--max-total-diff-bytes"));
    assert!(!stdout.contains("SWE_REVIEW_API_KEY"));
    assert!(!stdout.contains("swegrep"));
    assert!(!stdout.contains("Devin CLI credentials"));
}

#[test]
fn quick_review_rejects_conflicting_diff_sources() {
    let tmp = TempDir::new().unwrap();
    let output = Command::cargo_bin("swe-review")
        .unwrap()
        .args(["quick-review", "--path"])
        .arg(tmp.path())
        .args(["--staged", "--diff-file", "changes.diff"])
        .output()
        .unwrap();

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("mutually exclusive"));
}

#[test]
fn extract_key_show_prints_full_key_and_source() {
    let tmp = TempDir::new().unwrap();
    let db_path = tmp.path().join("state.vscdb");
    write_auth_db(&db_path, "sk-ws-01-mock");

    let output = Command::cargo_bin("swe-review")
        .unwrap()
        .args(["extract-key", "--show", "--db-path"])
        .arg(&db_path)
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stdout.contains("Windsurf API Key: sk-ws-01-mock"));
    assert!(stdout.contains("export WINDSURF_API_KEY=\"sk-ws-01-mock\""));
    assert!(stderr.contains("Key type: standard"));
    assert!(stderr.contains("Source DB:"));
}

#[test]
fn extract_key_save_writes_swe_tools_config_and_masks_stdout() {
    let tmp = TempDir::new().unwrap();
    let xdg = TempDir::new().unwrap();
    let db_path = tmp.path().join("state.vscdb");
    write_auth_db(&db_path, "devin-session-token$integration");

    let output = Command::cargo_bin("swe-review")
        .unwrap()
        .args(["extract-key", "--save", "--db-path"])
        .arg(&db_path)
        .env("XDG_CONFIG_HOME", xdg.path())
        .env_remove("APPDATA")
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stdout.contains("Windsurf API Key: devin-sess...ration"));
    assert!(stderr.contains("Saved Windsurf API key"));
    assert!(stderr.contains("Key type: unknown"));

    let config_path = xdg.path().join("swe-tools/config.json");
    let config = fs::read_to_string(config_path).unwrap();
    assert!(config.contains(r#""WINDSURF_API_KEY": "devin-session-token$integration""#));
}

#[test]
fn extract_key_save_prefers_devin_credentials_toml() {
    let home = TempDir::new().unwrap();
    let xdg = TempDir::new().unwrap();
    let credentials_path = home.path().join(".config/devin/credentials.toml");
    let windsurf_db_path = home
        .path()
        .join(".config/Windsurf/User/globalStorage/state.vscdb");
    fs::create_dir_all(credentials_path.parent().unwrap()).unwrap();
    fs::create_dir_all(windsurf_db_path.parent().unwrap()).unwrap();
    fs::write(
        &credentials_path,
        "windsurf_api_key = \"devin-session-token$credentials\"\n",
    )
    .unwrap();
    write_auth_db(&windsurf_db_path, "devin-session-token$windsurf-db");

    let output = Command::cargo_bin("swe-review")
        .unwrap()
        .args(["extract-key", "--save"])
        .env("HOME", home.path())
        .env("XDG_CONFIG_HOME", xdg.path())
        .env_remove("APPDATA")
        .output()
        .unwrap();

    assert!(output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("Source credentials:"));

    let config_path = xdg.path().join("swe-tools/config.json");
    let config = fs::read_to_string(config_path).unwrap();
    assert!(config.contains(r#""WINDSURF_API_KEY": "devin-session-token$credentials""#));
}

#[test]
fn auth_command_is_removed() {
    let output = Command::cargo_bin("swe-review")
        .unwrap()
        .args(["auth", "--help"])
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("auth"));
}

#[test]
fn cli_help_omits_legacy_credential_sources() {
    for args in [
        &["extract-key", "--help"][..],
        &["quick-review", "--help"][..],
    ] {
        let output = Command::cargo_bin("swe-review")
            .unwrap()
            .args(args)
            .output()
            .unwrap();

        assert!(output.status.success());
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(!stdout.contains("SWE_REVIEW_API_KEY"));
        assert!(!stdout.contains("swegrep"));
        assert!(!stdout.contains("auth extract-key"));
        assert!(!stdout.contains("import-devin"));
    }
}

#[test]
fn top_level_help_omits_review_command() {
    let output = Command::cargo_bin("swe-review")
        .unwrap()
        .args(["--help"])
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("quick-review"));
    assert!(!stdout.contains("review [OPTIONS]"));
}
