use crate::credentials::resolve_api_key;
use crate::diff::{ReviewDiff, SkippedFile, build_quick_review_diff};
use crate::review_options::ReviewOptions;
use crate::upstream::{
    NativeChatRequest, NativeClient, NativeClientIdentity, NativeClientOptions, NativeError,
    NativeModelConfig, NativeTeamSettings, QUICK_REVIEW_DISPLAY_OPTION,
};
use crate::util::progress;
use serde::Serialize;
use std::collections::HashSet;
use std::path::PathBuf;
use thiserror::Error;

const QUICK_REVIEW_DIFF_URI: &str = "diff://workspace/changes";
const DEFAULT_QUICK_REVIEW_MODEL: &str = "swe-check";
const DEFAULT_QUICK_REVIEW_MODEL_NAME: &str = "SWE-check";
const OPUS_REVIEW_MODEL: &str = "opus-4-7-review";
const OPUS_REVIEW_MODEL_NAME: &str = "Opus 4.7 Review";
const GPT_REVIEW_MODEL: &str = "gpt-5-5-review";
const GPT_REVIEW_MODEL_NAME: &str = "GPT 5.5 Review";
const QUICK_REVIEW_PROMPT: &str = "Review these changes in detail. Look for:\n- Bugs, logic errors, and incorrect behavior\n- Security vulnerabilities or unsafe patterns\n- Performance issues and unnecessary complexity\n- Missing error handling or edge cases\n- Code style issues and violations of project conventions\n\nBe thorough and specific. For each issue found, explain the problem, its impact, and suggest a concrete fix. If the changes look correct, confirm that with a brief explanation of why.";

#[derive(Debug, Clone)]
pub struct QuickReviewOptions {
    pub review: ReviewOptions,
    pub model: Option<String>,
}

impl QuickReviewOptions {
    pub fn new(project_path: impl Into<PathBuf>) -> Self {
        Self {
            review: ReviewOptions::new(project_path),
            model: None,
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
    #[error(transparent)]
    Native(#[from] NativeError),
}

pub fn run_quick_review(
    options: QuickReviewOptions,
    on_progress: Option<&(dyn Fn(&str) + Sync)>,
) -> Result<QuickReviewReport, QuickReviewError> {
    progress(on_progress, "Collecting Quick Review diff");
    let diff = build_quick_review_diff(
        &options.review.project_path,
        &options.review.source,
        options.review.max_file_bytes,
        options.review.diff_budget(),
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
    let ReviewDiff {
        text,
        files,
        skipped_files,
        line_count,
    } = diff;
    let file_paths = files.into_iter().map(|file| file.path).collect::<Vec<_>>();
    let review_prompt = native_quick_review_prompt(&text);
    enforce_prompt_token_budget(&review_prompt, options.review.max_estimated_tokens)?;

    let api_key = resolve_api_key(options.review.api_key.clone()).map_err(|error| {
        NativeError::ApiKey(format!("Unable to resolve Windsurf API key: {error}"))
    })?;
    let is_session_token = api_key.is_session_token;

    let mut client = NativeClient::new(NativeClientOptions {
        api_key: Some(api_key.value),
        timeout_ms: options.review.timeout_ms,
        identity: NativeClientIdentity::default(),
    })?;
    let (models, team_settings) = discover_quick_review_catalog(&mut client, on_progress);
    let native_candidates =
        quick_review_models_from_native(&models, &team_settings.allowed_model_uids);
    progress(
        on_progress,
        &format!(
            "Quick Review catalog has {} eligible model(s)",
            native_candidates.len()
        ),
    );
    let candidates = if native_candidates.is_empty() {
        let fallback = fallback_quick_review_models();
        progress(
            on_progress,
            &format!(
                "Using {} known Quick Review model option(s)",
                fallback.len()
            ),
        );
        fallback
    } else {
        native_candidates
    };
    let model = select_quick_review_model_from_candidates(
        &candidates,
        options.model.as_deref(),
        !models.is_empty(),
    );
    progress(on_progress, "Sending Quick Review prompt via native API");
    let response = client
        .get_chat_message(NativeChatRequest {
            model_uid: &model.value,
            prompt: &review_prompt,
        })
        .map_err(|err| {
            if is_session_token && err.to_string().contains("permission_denied") {
                QuickReviewError::Native(NativeError::SessionTokenNotAllowed)
            } else {
                err.into()
            }
        })?;

    Ok(QuickReviewReport {
        review: response.text,
        model,
        session_id: response.session_id,
        diff_files: file_paths,
        skipped_files,
        diff_line_count: line_count,
    })
}

fn enforce_prompt_token_budget(prompt: &str, limit: u64) -> Result<(), QuickReviewError> {
    if let Some(tokens) = crate::util::exceeds_token_limit(prompt, limit) {
        return Err(crate::diff::DiffError::DiffBudgetExceeded {
            metric: "tokens",
            actual: tokens,
            limit,
        }
        .into());
    }
    Ok(())
}

fn discover_quick_review_catalog(
    client: &mut NativeClient,
    on_progress: Option<&(dyn Fn(&str) + Sync)>,
) -> (Vec<NativeModelConfig>, NativeTeamSettings) {
    let models = match client.get_cli_model_configs() {
        Ok(models) => {
            progress(
                on_progress,
                &format!(
                    "Quick Review model catalog discovered {} model(s)",
                    models.len()
                ),
            );
            models
        }
        Err(error) => {
            progress(
                on_progress,
                &format!("Quick Review model catalog unavailable; using swe-check ({error})"),
            );
            return (Vec::new(), NativeTeamSettings::default());
        }
    };
    let team_settings = match client.get_cli_team_settings() {
        Ok(settings) => {
            progress(
                on_progress,
                &format!(
                    "Quick Review team settings allow {} model(s)",
                    settings.allowed_model_uids.len()
                ),
            );
            settings
        }
        Err(error) => {
            progress(
                on_progress,
                &format!(
                    "Quick Review team settings unavailable; using unfiltered catalog ({error})"
                ),
            );
            NativeTeamSettings::default()
        }
    };
    (models, team_settings)
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
    catalog_available: bool,
) -> QuickReviewModel {
    let selected_model = explicit_model.unwrap_or(DEFAULT_QUICK_REVIEW_MODEL);
    if let Some(model) = models
        .iter()
        .find(|model| model.value == selected_model || model.name == selected_model)
        .cloned()
    {
        return model;
    }
    if explicit_model.is_none()
        && catalog_available
        && let Some(model) = models.first()
    {
        return model.clone();
    }
    quick_review_model_from_input(selected_model)
}

fn fallback_quick_review_models() -> Vec<QuickReviewModel> {
    vec![
        known_quick_review_model(DEFAULT_QUICK_REVIEW_MODEL).expect("default model is known"),
        known_quick_review_model(OPUS_REVIEW_MODEL).expect("opus review model is known"),
        known_quick_review_model(GPT_REVIEW_MODEL).expect("gpt review model is known"),
    ]
}

fn quick_review_model_from_input(model: &str) -> QuickReviewModel {
    let value = canonical_quick_review_model_value(model);
    if let Some(model) = known_quick_review_model(&value) {
        return model;
    }
    QuickReviewModel {
        value,
        name: model.to_string(),
        description: None,
    }
}

fn known_quick_review_model(value: &str) -> Option<QuickReviewModel> {
    let name = match value {
        DEFAULT_QUICK_REVIEW_MODEL => DEFAULT_QUICK_REVIEW_MODEL_NAME,
        OPUS_REVIEW_MODEL => OPUS_REVIEW_MODEL_NAME,
        GPT_REVIEW_MODEL => GPT_REVIEW_MODEL_NAME,
        _ => return None,
    };
    Some(QuickReviewModel {
        value: value.to_string(),
        name: name.to_string(),
        description: None,
    })
}

fn canonical_quick_review_model_value(model: &str) -> String {
    let normalized = model
        .chars()
        .filter(|character| !matches!(character, '-' | ' ' | '.' | '_'))
        .collect::<String>()
        .to_ascii_lowercase();
    match normalized.as_str() {
        "swecheck" => DEFAULT_QUICK_REVIEW_MODEL.to_string(),
        "opus47" | "opus47review" => OPUS_REVIEW_MODEL.to_string(),
        "gpt55" | "gpt55review" => GPT_REVIEW_MODEL.to_string(),
        _ => model.to_string(),
    }
}

fn native_quick_review_prompt(diff: &str) -> String {
    format!(
        "{QUICK_REVIEW_PROMPT}\n\n<resource uri=\"{QUICK_REVIEW_DIFF_URI}\" mimeType=\"text/x-diff\">\n{diff}\n</resource>"
    )
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
    fn defaults_to_swe_check_even_when_it_is_not_first() {
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

        let selected = select_quick_review_model_from_candidates(&candidates, None, true);

        assert_eq!(selected.value, "swe-check");
        assert_eq!(selected.name, "SWE-check");
    }

    #[test]
    fn defaults_to_first_catalog_model_when_swe_check_is_unavailable() {
        let candidates = vec![QuickReviewModel {
            value: "gpt-5-5-review".to_string(),
            name: "GPT 5.5 Review".to_string(),
            description: None,
        }];

        let selected = select_quick_review_model_from_candidates(&candidates, None, true);

        assert_eq!(selected.value, "gpt-5-5-review");
        assert_eq!(selected.name, "GPT 5.5 Review");
    }

    #[test]
    fn defaults_to_swe_check_when_catalog_is_empty() {
        let selected = select_quick_review_model_from_candidates(&[], None, false);

        assert_eq!(selected.value, "swe-check");
        assert_eq!(selected.name, "SWE-check");
    }

    #[test]
    fn known_fallback_models_are_quick_review_models() {
        let candidates = fallback_quick_review_models();

        assert_eq!(
            candidates
                .iter()
                .map(|model| model.value.as_str())
                .collect::<Vec<_>>(),
            vec!["swe-check", "opus-4-7-review", "gpt-5-5-review"]
        );
    }

    #[test]
    fn explicit_model_value_wins_even_when_not_listed() {
        let selected = select_quick_review_model_from_candidates(&[], Some("manual-model"), false);

        assert_eq!(selected.value, "manual-model");
        assert_eq!(selected.name, "manual-model");
        assert_eq!(selected.description, None);
    }

    #[test]
    fn explicit_swe_check_display_name_uses_known_model_uid() {
        let selected = select_quick_review_model_from_candidates(&[], Some("SWE-check"), false);

        assert_eq!(selected.value, "swe-check");
        assert_eq!(selected.name, "SWE-check");
    }

    #[test]
    fn explicit_paid_review_display_names_use_known_model_uids() {
        let opus = select_quick_review_model_from_candidates(&[], Some("Opus 4.7 Review"), false);
        let gpt = select_quick_review_model_from_candidates(&[], Some("GPT 5.5 Review"), false);

        assert_eq!(opus.value, "opus-4-7-review");
        assert_eq!(opus.name, "Opus 4.7 Review");
        assert_eq!(gpt.value, "gpt-5-5-review");
        assert_eq!(gpt.name, "GPT 5.5 Review");
    }

    #[test]
    fn native_prompt_embeds_diff_resource_marker() {
        let prompt = native_quick_review_prompt("--- a/src/lib.rs\n+++ b/src/lib.rs");

        assert!(prompt.contains(QUICK_REVIEW_PROMPT));
        assert!(prompt.contains("uri=\"diff://workspace/changes\""));
        assert!(prompt.contains("mimeType=\"text/x-diff\""));
        assert!(prompt.contains("--- a/src/lib.rs"));
    }

    #[test]
    fn prompt_token_budget_counts_full_prompt_wrapper() {
        let prompt = native_quick_review_prompt("small diff");

        enforce_prompt_token_budget(&prompt, 1).unwrap_err();
    }
}
