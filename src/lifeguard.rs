use crate::credentials::resolve_api_key;
use crate::diff::{
    DiffBudget, DiffSource, ReviewDiff, SkippedFile, build_review_diff, git_context,
};
use crate::lifeguard_rules::{RulesError, read_user_rules};
use crate::upstream::{
    CheckBugsReport, CheckBugsRequest, LifeguardMode, NativeClient, NativeClientEndpoint,
    NativeClientOptions, NativeError, format_bugs_markdown,
};
use serde::Serialize;
use std::path::PathBuf;
use thiserror::Error;

const DEFAULT_MAX_FILE_BYTES: u64 = 1_000_000;

#[derive(Debug, Clone)]
pub struct ReviewOptions {
    pub project_path: PathBuf,
    pub source: DiffSource,
    pub api_key: Option<String>,
    pub method: String,
    pub max_file_bytes: u64,
    pub max_total_diff_bytes: usize,
    pub max_total_diff_lines: usize,
    pub max_estimated_tokens: u64,
    pub timeout_ms: u64,
}

impl ReviewOptions {
    pub fn new(project_path: impl Into<PathBuf>) -> Self {
        Self {
            project_path: project_path.into(),
            source: DiffSource::WorkingTree,
            api_key: None,
            method: "agent".to_string(),
            max_file_bytes: DEFAULT_MAX_FILE_BYTES,
            max_total_diff_bytes: DiffBudget::default().max_total_diff_bytes,
            max_total_diff_lines: DiffBudget::default().max_total_diff_lines,
            max_estimated_tokens: DiffBudget::default().max_estimated_tokens,
            timeout_ms: 120_000,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ReviewReport {
    pub review: String,
    pub mode: LifeguardMode,
    pub check: CheckBugsReport,
    pub diff_files: Vec<String>,
    pub skipped_files: Vec<SkippedFile>,
    pub diff_line_count: usize,
    pub rules_count: usize,
}

#[derive(Debug, Error)]
pub enum ReviewError {
    #[error(transparent)]
    Diff(#[from] crate::diff::DiffError),
    #[error(transparent)]
    Native(#[from] NativeError),
    #[error(transparent)]
    Rules(#[from] RulesError),
    #[error("No reviewable changes found")]
    NoChanges,
}

pub async fn run_review(
    options: ReviewOptions,
    on_progress: Option<&(dyn Fn(&str) + Sync)>,
) -> Result<ReviewReport, ReviewError> {
    let git = git_context(&options.project_path)?;
    progress(on_progress, "Collecting diff");
    let diff = build_review_diff(
        &options.project_path,
        &options.source,
        options.max_file_bytes,
        options.diff_budget(),
    )?;
    if diff.text.trim().is_empty() {
        return Err(ReviewError::NoChanges);
    }
    progress(
        on_progress,
        &format!(
            "Prepared {} file(s), {} diff line(s)",
            diff.files.len(),
            diff.line_count
        ),
    );

    let ReviewDiff {
        text,
        files,
        skipped_files,
        line_count,
    } = diff;
    let file_paths = files.into_iter().map(|file| file.path).collect::<Vec<_>>();
    let user_rules = read_user_rules(&git.root, options.method == "agent")?;
    progress(
        on_progress,
        &format!("Loaded {} Lifeguard rule(s)", user_rules.len()),
    );

    let api_key = resolve_api_key(options.api_key).map_err(|error| {
        NativeError::ApiKey(format!("Unable to resolve Windsurf API key: {error}"))
    })?;
    let mut client = NativeClient::new(NativeClientOptions {
        api_key: Some(api_key.value),
        endpoint: NativeClientEndpoint::Lifeguard,
        timeout_ms: options.timeout_ms,
    })?;
    progress(on_progress, "Checking Lifeguard config");
    let mode = client.get_lifeguard_mode(&options.method).await?;
    progress(
        on_progress,
        &format!(
            "Using Lifeguard method: {} ({}, {})",
            mode.name, mode.model_display_name, mode.agent_version
        ),
    );
    let check_type = check_type(&options.source);
    let base_ref = match &options.source {
        DiffSource::Base(base) => base.as_str(),
        _ => "",
    };
    let git_root = git.root.to_string_lossy().to_string();
    let request = CheckBugsRequest {
        diff: &text,
        repo_name: &git.repo_name,
        commit_hash: &git.commit_hash,
        author_name: &git.author_name,
        commit_message: &git.commit_message,
        user_rules: &user_rules,
        method: &options.method,
        symbol_context: "",
        check_type,
        base_ref,
        git_root: &git_root,
    };
    progress(on_progress, "Sending CheckBugs request");
    let check = client.check_bugs(request).await?;
    let review = format_bugs_markdown(&check);

    Ok(ReviewReport {
        review,
        mode,
        check,
        diff_files: file_paths,
        skipped_files,
        diff_line_count: line_count,
        rules_count: user_rules.len(),
    })
}

impl ReviewOptions {
    fn diff_budget(&self) -> DiffBudget {
        DiffBudget {
            max_total_diff_bytes: self.max_total_diff_bytes,
            max_total_diff_lines: self.max_total_diff_lines,
            max_estimated_tokens: self.max_estimated_tokens,
        }
    }
}

fn check_type(source: &DiffSource) -> &'static str {
    match source {
        DiffSource::Base(_) => "compareWithRef",
        _ => "currentChanges",
    }
}

fn progress(on_progress: Option<&(dyn Fn(&str) + Sync)>, message: &str) {
    if let Some(on_progress) = on_progress {
        on_progress(message);
    }
}
