use serde::Serialize;
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiffSource {
    WorkingTree,
    Staged,
    Unstaged,
    Base(String),
    #[allow(dead_code)]
    DiffFile(PathBuf),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ReviewFile {
    pub path: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SkippedFile {
    pub path: String,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FileSnapshot {
    path: String,
    before: String,
    after: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ReviewDiff {
    pub text: String,
    pub files: Vec<ReviewFile>,
    pub skipped_files: Vec<SkippedFile>,
    pub line_count: usize,
}

pub const DEFAULT_MAX_TOTAL_DIFF_BYTES: usize = 512_000;
pub const DEFAULT_MAX_TOTAL_DIFF_LINES: usize = 12_000;
pub const DEFAULT_MAX_ESTIMATED_TOKENS: u64 = 120_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DiffBudget {
    pub max_total_diff_bytes: usize,
    pub max_total_diff_lines: usize,
}

impl Default for DiffBudget {
    fn default() -> Self {
        Self {
            max_total_diff_bytes: DEFAULT_MAX_TOTAL_DIFF_BYTES,
            max_total_diff_lines: DEFAULT_MAX_TOTAL_DIFF_LINES,
        }
    }
}

#[derive(Debug, Error)]
pub enum DiffError {
    #[error("Project path does not exist: {0}")]
    ProjectPathMissing(String),
    #[error("Git command failed: {0}")]
    Git(String),
    #[error("Could not read {path}: {message}")]
    ReadFile { path: String, message: String },
    #[error("Diff file is not valid UTF-8: {0}")]
    DiffFileUtf8(String),
    #[error("Diff budget exceeded for {metric}: actual {actual}, limit {limit}")]
    DiffBudgetExceeded {
        metric: &'static str,
        actual: u64,
        limit: u64,
    },
}

const EXCLUDE_PATHS: &[&str] = &[
    ":(exclude)*.min.js",
    ":(exclude)*.min.css",
    ":(exclude)*.bundle.js",
    ":(exclude)*.bundle.css",
    ":(exclude)*.map",
    ":(exclude)*.generated.*",
    ":(exclude)*.png",
    ":(exclude)*.jpg",
    ":(exclude)*.jpeg",
    ":(exclude)*.gif",
    ":(exclude)*.ico",
    ":(exclude)*.webp",
    ":(exclude)*.svg",
    ":(exclude)*.pdf",
    ":(exclude)*.zip",
    ":(exclude)*.tar",
    ":(exclude)*.gz",
    ":(exclude)node_modules/*",
    ":(exclude)vendor/*",
    ":(exclude)dist/*",
    ":(exclude)build/*",
    ":(exclude)out/*",
    ":(exclude)target/*",
    ":(exclude).next/*",
    ":(exclude).nuxt/*",
    ":(exclude)coverage/*",
    ":(exclude)__pycache__/*",
    ":(exclude).pytest_cache/*",
    ":(exclude).tox/*",
    ":(exclude).venv/*",
    ":(exclude)venv/*",
];

pub fn build_quick_review_diff(
    project_path: &Path,
    source: &DiffSource,
    max_file_bytes: u64,
    budget: DiffBudget,
) -> Result<ReviewDiff, DiffError> {
    if let DiffSource::DiffFile(path) = source {
        let bytes = fs::read(path).map_err(|err| DiffError::ReadFile {
            path: path.display().to_string(),
            message: err.to_string(),
        })?;
        let text = String::from_utf8(bytes)
            .map_err(|_| DiffError::DiffFileUtf8(path.display().to_string()))?;
        let line_count = count_lines(&text);
        enforce_budget(&text, line_count, budget)?;
        return Ok(ReviewDiff {
            line_count,
            text,
            files: Vec::new(),
            skipped_files: Vec::new(),
        });
    }

    let root = git_root(project_path)?;
    let paths = changed_paths(&root, source)?;
    let mut snapshots = Vec::new();
    let mut files = Vec::new();
    let mut skipped_files = Vec::new();

    for path in paths {
        match snapshot_file(&root, &path, source, max_file_bytes) {
            Ok(Some(snapshot)) => {
                files.push(ReviewFile {
                    path: snapshot.path.clone(),
                });
                snapshots.push(snapshot);
            }
            Ok(None) => {}
            Err(reason) => skipped_files.push(SkippedFile { path, reason }),
        }
    }

    let text = format_full_file_diff(&snapshots);
    let line_count = count_lines(&text);
    enforce_budget(&text, line_count, budget)?;
    Ok(ReviewDiff {
        line_count,
        text,
        files,
        skipped_files,
    })
}

fn git_root(path: &Path) -> Result<PathBuf, DiffError> {
    if !path.exists() {
        return Err(DiffError::ProjectPathMissing(path.display().to_string()));
    }
    let output = Command::new("git")
        .args(["-C"])
        .arg(path)
        .args(["rev-parse", "--show-toplevel"])
        .output()
        .map_err(|err| DiffError::Git(err.to_string()))?;
    if !output.status.success() {
        return Err(DiffError::Git(stderr_text(&output.stderr)));
    }
    let text = String::from_utf8_lossy(&output.stdout);
    Ok(PathBuf::from(text.trim()))
}

fn changed_paths(root: &Path, source: &DiffSource) -> Result<Vec<String>, DiffError> {
    let mut paths = BTreeSet::new();
    match source {
        DiffSource::WorkingTree => {
            paths.extend(git_paths(
                root,
                &["diff", "--name-only", "-z", "HEAD", "--"],
                true,
            )?);
            paths.extend(git_paths(
                root,
                &["ls-files", "--others", "--exclude-standard", "-z"],
                true,
            )?);
        }
        DiffSource::Staged => {
            paths.extend(git_paths(
                root,
                &["diff", "--cached", "--name-only", "-z", "--"],
                true,
            )?);
        }
        DiffSource::Unstaged => {
            paths.extend(git_paths(root, &["diff", "--name-only", "-z", "--"], true)?);
            paths.extend(git_paths(
                root,
                &["ls-files", "--others", "--exclude-standard", "-z"],
                true,
            )?);
        }
        DiffSource::Base(base) => {
            let args = ["diff", "--name-only", "-z", base.as_str(), "--"];
            paths.extend(git_paths(root, &args, true)?);
        }
        DiffSource::DiffFile(_) => {}
    }
    Ok(paths.into_iter().collect())
}

fn git_paths(root: &Path, args: &[&str], add_excludes: bool) -> Result<Vec<String>, DiffError> {
    let output = git_output(root, args, add_excludes)?;
    if !output.status.success() {
        return Err(DiffError::Git(stderr_text(&output.stderr)));
    }
    Ok(output
        .stdout
        .split(|byte| *byte == 0)
        .filter(|part| !part.is_empty())
        .map(|part| String::from_utf8_lossy(part).into_owned())
        .collect())
}

fn git_output(root: &Path, args: &[&str], add_excludes: bool) -> Result<Output, DiffError> {
    let mut command = Command::new("git");
    command.current_dir(root).args(args);
    if add_excludes {
        command.arg(".");
        command.args(EXCLUDE_PATHS);
    }
    command
        .output()
        .map_err(|err| DiffError::Git(err.to_string()))
}

fn snapshot_file(
    root: &Path,
    path: &str,
    source: &DiffSource,
    max_file_bytes: u64,
) -> Result<Option<FileSnapshot>, String> {
    let before = match source {
        DiffSource::WorkingTree | DiffSource::Staged => {
            git_blob(root, &format!("HEAD:{path}"), max_file_bytes)?.unwrap_or_default()
        }
        DiffSource::Unstaged => git_blob(root, &format!(":{path}"), max_file_bytes)?
            .or_else(|| {
                git_blob(root, &format!("HEAD:{path}"), max_file_bytes)
                    .ok()
                    .flatten()
            })
            .unwrap_or_default(),
        DiffSource::Base(base) => {
            git_blob(root, &format!("{base}:{path}"), max_file_bytes)?.unwrap_or_default()
        }
        DiffSource::DiffFile(_) => String::new(),
    };

    let after = match source {
        DiffSource::Staged => {
            git_blob(root, &format!(":{path}"), max_file_bytes)?.unwrap_or_default()
        }
        DiffSource::WorkingTree | DiffSource::Unstaged | DiffSource::Base(_) => {
            worktree_file(root, path, max_file_bytes)?
        }
        DiffSource::DiffFile(_) => String::new(),
    };

    if before == after {
        return Ok(None);
    }
    Ok(Some(FileSnapshot {
        path: path.to_string(),
        before,
        after,
    }))
}

fn git_blob(root: &Path, rev_path: &str, max_file_bytes: u64) -> Result<Option<String>, String> {
    let output = Command::new("git")
        .current_dir(root)
        .args(["show", rev_path])
        .output()
        .map_err(|err| err.to_string())?;
    if !output.status.success() {
        return Ok(None);
    }
    bytes_to_text(output.stdout, max_file_bytes)
}

fn worktree_file(root: &Path, path: &str, max_file_bytes: u64) -> Result<String, String> {
    let full_path = root.join(path);
    if !full_path.exists() {
        return Ok(String::new());
    }
    let metadata = fs::metadata(&full_path).map_err(|err| err.to_string())?;
    if !metadata.is_file() {
        return Err("not a regular file".to_string());
    }
    if metadata.len() > max_file_bytes {
        return Err(format!("larger than {max_file_bytes} bytes"));
    }
    let bytes = fs::read(&full_path).map_err(|err| err.to_string())?;
    Ok(bytes_to_text(bytes, max_file_bytes)?.unwrap_or_default())
}

fn bytes_to_text(bytes: Vec<u8>, max_file_bytes: u64) -> Result<Option<String>, String> {
    if bytes.len() as u64 > max_file_bytes {
        return Err(format!("larger than {max_file_bytes} bytes"));
    }
    if bytes.contains(&0) {
        return Err("binary file".to_string());
    }
    String::from_utf8(bytes)
        .map(Some)
        .map_err(|_| "not valid UTF-8".to_string())
}

fn format_full_file_diff(files: &[FileSnapshot]) -> String {
    let mut lines = Vec::new();
    for file in files {
        lines.push(format!("--- a/{}", file.path));
        lines.push(format!("+++ b/{}", file.path));
        let before = split_like_unified_diff(&file.before);
        let after = split_like_unified_diff(&file.after);
        lines.push(format!("@@ -1,{} +1,{} @@", before.len(), after.len()));
        lines.extend(before.into_iter().map(|line| format!("-{line}")));
        lines.extend(after.into_iter().map(|line| format!("+{line}")));
    }
    lines.join("\n")
}

fn split_like_unified_diff(text: &str) -> Vec<&str> {
    text.split('\n').collect()
}

fn count_lines(text: &str) -> usize {
    text.lines().count()
}

fn enforce_budget(text: &str, line_count: usize, budget: DiffBudget) -> Result<(), DiffError> {
    if text.len() > budget.max_total_diff_bytes {
        return Err(DiffError::DiffBudgetExceeded {
            metric: "bytes",
            actual: text.len() as u64,
            limit: budget.max_total_diff_bytes as u64,
        });
    }
    if line_count > budget.max_total_diff_lines {
        return Err(DiffError::DiffBudgetExceeded {
            metric: "lines",
            actual: line_count as u64,
            limit: budget.max_total_diff_lines as u64,
        });
    }
    Ok(())
}

fn stderr_text(stderr: &[u8]) -> String {
    let text = String::from_utf8_lossy(stderr).trim().to_string();
    if text.is_empty() {
        "unknown git error".to_string()
    } else {
        text
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn full_file_diff_uses_full_file_hunks() {
        let files = vec![FileSnapshot {
            path: "src/lib.rs".to_string(),
            before: "old\nvalue".to_string(),
            after: "new\nvalue".to_string(),
        }];

        assert_eq!(
            format_full_file_diff(&files),
            "--- a/src/lib.rs\n+++ b/src/lib.rs\n@@ -1,2 +1,2 @@\n-old\n-value\n+new\n+value"
        );
    }

    #[test]
    fn diff_file_respects_total_budget() {
        let tmp = TempDir::new().unwrap();
        let diff_file = tmp.path().join("change.diff");
        fs::write(
            &diff_file,
            "--- a/Cargo.lock\n+++ b/Cargo.lock\n@@ -1,1 +1,1 @@\n-old\n+new\n",
        )
        .unwrap();

        let error = build_quick_review_diff(
            tmp.path(),
            &DiffSource::DiffFile(diff_file),
            1_000_000,
            DiffBudget {
                max_total_diff_bytes: 10,
                max_total_diff_lines: 100,
            },
        )
        .unwrap_err();

        assert!(matches!(
            error,
            DiffError::DiffBudgetExceeded {
                metric: "bytes",
                ..
            }
        ));
    }

    #[test]
    fn lockfiles_are_not_excluded_from_changed_paths() {
        assert!(
            !EXCLUDE_PATHS
                .iter()
                .any(|path| path.to_ascii_lowercase().contains("lock"))
        );
    }
}
