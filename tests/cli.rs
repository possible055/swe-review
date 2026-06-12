use assert_cmd::Command;
use tempfile::TempDir;

#[test]
fn review_requires_path() {
    let output = Command::cargo_bin("swe-review")
        .unwrap()
        .args(["review"])
        .output()
        .unwrap();

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("--path"));
}

#[test]
fn review_rejects_conflicting_diff_sources() {
    let tmp = TempDir::new().unwrap();
    let output = Command::cargo_bin("swe-review")
        .unwrap()
        .args(["review", "--path"])
        .arg(tmp.path())
        .args(["--staged", "--base", "main"])
        .output()
        .unwrap();

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("mutually exclusive"));
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
fn quick_review_defaults_to_native_without_devin_binary_lookup() {
    use std::fs;

    let tmp = TempDir::new().unwrap();
    let diff_file = tmp.path().join("change.diff");
    fs::write(
        &diff_file,
        "--- a/a.txt\n+++ b/a.txt\n@@ -1,1 +1,1 @@\n-old\n+new\n",
    )
    .unwrap();

    let output = Command::cargo_bin("swe-review")
        .unwrap()
        .args(["quick-review", "--path"])
        .arg(tmp.path())
        .args(["--diff-file"])
        .arg(&diff_file)
        .env_remove("SWE_REVIEW_API_KEY")
        .env_remove("WINDSURF_API_KEY")
        .output()
        .unwrap();

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("API key not found"));
}
