use crate::diff::{DiffBudget, DiffSource, ReviewDiff, SkippedFile, build_quick_review_diff};
use crate::upstream::{
    NativeChatRequest, NativeClient, NativeClientEndpoint, NativeClientOptions, NativeError,
    NativeModelConfig, QUICK_REVIEW_DISPLAY_OPTION,
};
use serde::Serialize;
use std::collections::HashSet;
use std::env;
use std::path::PathBuf;
use thiserror::Error;

const QUICK_REVIEW_DIFF_URI: &str = "diff://workspace/changes";
const DEFAULT_NATIVE_QUICK_REVIEW_MODEL: &str = "swe-check";
const QUICK_REVIEW_PROMPT: &str = "Review these changes in detail. Look for:\n- Bugs, logic errors, and incorrect behavior\n- Security vulnerabilities or unsafe patterns\n- Performance issues and unnecessary complexity\n- Missing error handling or edge cases\n- Code style issues and violations of project conventions\n\nBe thorough and specific. For each issue found, explain the problem, its impact, and suggest a concrete fix. If the changes look correct, confirm that with a brief explanation of why.";

#[derive(Debug, Clone)]
pub struct QuickReviewOptions {
    pub project_path: PathBuf,
    pub source: DiffSource,
    pub model: Option<String>,
    pub api_key: Option<String>,
    pub max_file_bytes: u64,
    pub max_total_diff_bytes: usize,
    pub max_total_diff_lines: usize,
    pub max_estimated_tokens: u64,
    pub timeout_ms: u64,
}

impl QuickReviewOptions {
    pub fn new(project_path: impl Into<PathBuf>) -> Self {
        Self {
            project_path: project_path.into(),
            source: DiffSource::WorkingTree,
            model: None,
            api_key: None,
            max_file_bytes: 1_000_000,
            max_total_diff_bytes: DiffBudget::default().max_total_diff_bytes,
            max_total_diff_lines: DiffBudget::default().max_total_diff_lines,
            max_estimated_tokens: DiffBudget::default().max_estimated_tokens,
            timeout_ms: 120_000,
        }
    }

    fn diff_budget(&self) -> DiffBudget {
        DiffBudget {
            max_total_diff_bytes: self.max_total_diff_bytes,
            max_total_diff_lines: self.max_total_diff_lines,
            max_estimated_tokens: self.max_estimated_tokens,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct QuickReviewReport {
    pub review: String,
    pub model: QuickReviewModel,
    pub session_id: String,
    pub diff_files: Vec<String>,
    pub skipped_files: Vec<SkippedFile>,
    pub diff_line_count: usize,
    pub restore_error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct QuickReviewModel {
    pub value: String,
    pub name: String,
    pub description: Option<String>,
}

#[derive(Debug, Error)]
pub enum QuickReviewError {
    #[error(transparent)]
    Diff(#[from] crate::diff::DiffError),
    #[error("No reviewable changes found")]
    NoChanges,
    #[error(
        "Quick Review model was not found. Available model options: {0}. Use --model <value> to override."
    )]
    ModelUnavailable(String),
    #[error(transparent)]
    Native(#[from] NativeError),
    #[error("Failed to start async runtime: {0}")]
    Runtime(String),
}

pub fn run_quick_review(
    options: QuickReviewOptions,
    on_progress: Option<&(dyn Fn(&str) + Sync)>,
) -> Result<QuickReviewReport, QuickReviewError> {
    progress(on_progress, "Collecting Quick Review diff");
    let diff = build_quick_review_diff(
        &options.project_path,
        &options.source,
        options.max_file_bytes,
        options.diff_budget(),
    )?;
    if diff.text.trim().is_empty() {
        return Err(QuickReviewError::NoChanges);
    }
    progress(
        on_progress,
        &format!(
            "Prepared {} file(s), {} diff line(s)",
            diff.files.len(),
            diff.line_count
        ),
    );

    run_quick_review_native(options, diff, on_progress)
}

fn run_quick_review_native(
    options: QuickReviewOptions,
    diff: ReviewDiff,
    on_progress: Option<&(dyn Fn(&str) + Sync)>,
) -> Result<QuickReviewReport, QuickReviewError> {
    progress(
        on_progress,
        "Discovering Quick Review models via native API",
    );
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|error| QuickReviewError::Runtime(error.to_string()))?;
    let ReviewDiff {
        text,
        files,
        skipped_files,
        line_count,
    } = diff;
    let file_paths = files.into_iter().map(|file| file.path).collect::<Vec<_>>();
    let review_prompt = native_quick_review_prompt(&text);

    let (model, response) = runtime.block_on(async {
        let mut client = NativeClient::new(NativeClientOptions {
            api_key: quick_review_api_key(options.api_key),
            endpoint: NativeClientEndpoint::QuickReview,
            timeout_ms: options.timeout_ms,
        })?;
        let models = client.get_cli_model_configs().await?;
        let team_settings = client.get_cli_team_settings().await?;
        let candidates =
            quick_review_models_from_native(&models, &team_settings.allowed_model_uids);
        let model =
            select_quick_review_model_from_candidates(&candidates, options.model.as_deref())?;
        progress(on_progress, "Sending Quick Review prompt via native API");
        let response = client
            .get_chat_message(NativeChatRequest {
                model_uid: &model.value,
                prompt: &review_prompt,
            })
            .await?;
        Ok::<_, QuickReviewError>((model, response))
    })?;

    Ok(QuickReviewReport {
        review: response.text,
        model,
        session_id: response.session_id,
        diff_files: file_paths,
        skipped_files,
        diff_line_count: line_count,
        restore_error: None,
    })
}

fn quick_review_models_from_native(
    models: &[NativeModelConfig],
    allowed_model_uids: &[String],
) -> Vec<QuickReviewModel> {
    let allowed = allowed_model_uids.iter().collect::<HashSet<_>>();
    models
        .iter()
        .filter(|model| model.display_option == Some(QUICK_REVIEW_DISPLAY_OPTION))
        .filter(|model| allowed.is_empty() || allowed.contains(&model.model_uid))
        .map(|model| QuickReviewModel {
            value: model.model_uid.clone(),
            name: model.label.clone(),
            description: model.description.clone(),
        })
        .collect()
}

fn select_quick_review_model_from_candidates(
    models: &[QuickReviewModel],
    explicit_model: Option<&str>,
) -> Result<QuickReviewModel, QuickReviewError> {
    if let Some(explicit_model) = explicit_model {
        return Ok(models
            .iter()
            .find(|model| model.value == explicit_model || model.name == explicit_model)
            .cloned()
            .unwrap_or_else(|| QuickReviewModel {
                value: explicit_model.to_string(),
                name: explicit_model.to_string(),
                description: None,
            }));
    }

    models
        .iter()
        .find(|model| is_swe_check_model(model))
        .cloned()
        .or_else(|| {
            models.is_empty().then(|| QuickReviewModel {
                value: DEFAULT_NATIVE_QUICK_REVIEW_MODEL.to_string(),
                name: "SWE-check".to_string(),
                description: Some(
                    "Default free Quick Review model used when the native catalog is empty."
                        .to_string(),
                ),
            })
        })
        .ok_or_else(|| QuickReviewError::ModelUnavailable(describe_quick_review_models(models)))
}

fn describe_quick_review_models(models: &[QuickReviewModel]) -> String {
    if models.is_empty() {
        return "none".to_string();
    }
    models
        .iter()
        .map(|model| {
            if model.name == model.value {
                model.name.clone()
            } else {
                format!("{} ({})", model.name, model.value)
            }
        })
        .collect::<Vec<_>>()
        .join(", ")
}

fn is_swe_check_model(model: &QuickReviewModel) -> bool {
    let haystack = format!(
        "{} {} {}",
        model.name,
        model.value,
        model.description.as_deref().unwrap_or("")
    )
    .to_ascii_lowercase();
    haystack.contains("swe-check")
        || haystack.contains("swe check")
        || haystack.contains("swecheck")
}

fn quick_review_api_key(explicit: Option<String>) -> Option<String> {
    explicit
        .or_else(|| env::var("SWE_REVIEW_API_KEY").ok())
        .or_else(|| env::var("WINDSURF_API_KEY").ok())
        .filter(|key| !key.trim().is_empty())
}

fn native_quick_review_prompt(diff: &str) -> String {
    format!(
        "{QUICK_REVIEW_PROMPT}\n\n<resource uri=\"{QUICK_REVIEW_DIFF_URI}\" mimeType=\"text/x-diff\">\n{diff}\n</resource>"
    )
}

fn progress(on_progress: Option<&(dyn Fn(&str) + Sync)>, message: &str) {
    if let Some(on_progress) = on_progress {
        on_progress(message);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filters_native_quick_review_models_by_display_option_and_team_settings() {
        let models = vec![
            NativeModelConfig {
                model_uid: "swe-check".to_string(),
                label: "SWE-check".to_string(),
                description: None,
                display_option: Some(QUICK_REVIEW_DISPLAY_OPTION),
            },
            NativeModelConfig {
                model_uid: "adaptive".to_string(),
                label: "Adaptive".to_string(),
                description: None,
                display_option: None,
            },
            NativeModelConfig {
                model_uid: "opus-4-7-review".to_string(),
                label: "Opus 4.7 Review".to_string(),
                description: None,
                display_option: Some(QUICK_REVIEW_DISPLAY_OPTION),
            },
        ];
        let allowed = vec!["swe-check".to_string()];

        let candidates = quick_review_models_from_native(&models, &allowed);

        assert_eq!(
            candidates,
            vec![QuickReviewModel {
                value: "swe-check".to_string(),
                name: "SWE-check".to_string(),
                description: None,
            }]
        );
    }

    #[test]
    fn selects_swe_check_from_native_candidates() {
        let candidates = vec![
            QuickReviewModel {
                value: "gpt-5-5-review".to_string(),
                name: "GPT 5.5 Review".to_string(),
                description: None,
            },
            QuickReviewModel {
                value: "swe-check".to_string(),
                name: "SWE-check".to_string(),
                description: None,
            },
        ];

        let selected = select_quick_review_model_from_candidates(&candidates, None).unwrap();

        assert_eq!(selected.value, "swe-check");
    }

    #[test]
    fn explicit_model_value_wins_even_when_not_listed() {
        let selected =
            select_quick_review_model_from_candidates(&[], Some("manual-model")).unwrap();

        assert_eq!(selected.value, "manual-model");
        assert_eq!(selected.name, "manual-model");
    }

    #[test]
    fn native_candidates_fall_back_to_swe_check_when_catalog_is_empty() {
        let selected = select_quick_review_model_from_candidates(&[], None).unwrap();

        assert_eq!(selected.value, "swe-check");
        assert_eq!(selected.name, "SWE-check");
    }

    #[test]
    fn native_prompt_embeds_diff_resource_marker() {
        let prompt = native_quick_review_prompt("--- a/src/lib.rs\n+++ b/src/lib.rs");

        assert!(prompt.contains(QUICK_REVIEW_PROMPT));
        assert!(prompt.contains("uri=\"diff://workspace/changes\""));
        assert!(prompt.contains("mimeType=\"text/x-diff\""));
        assert!(prompt.contains("--- a/src/lib.rs"));
    }
}
