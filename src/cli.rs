use crate::credentials::{extract_key, mask_api_key, write_swe_tools_config_api_key};
use crate::diff::DiffSource;
use crate::quick_review::{QuickReviewOptions, run_quick_review};
use crate::review_options::ReviewOptions;
use clap::{Args, Parser, Subcommand};
use std::env;
use std::io::Write;
use std::path::{Path, PathBuf};

const MAX_FILE_BYTES_ENV: &str = "SWE_REVIEW_MAX_FILE_BYTES";
const MAX_TOTAL_DIFF_BYTES_ENV: &str = "SWE_REVIEW_MAX_TOTAL_DIFF_BYTES";
const MAX_TOTAL_DIFF_LINES_ENV: &str = "SWE_REVIEW_MAX_TOTAL_DIFF_LINES";
const MAX_ESTIMATED_TOKENS_ENV: &str = "SWE_REVIEW_MAX_ESTIMATED_TOKENS";
const TIMEOUT_MS_ENV: &str = "SWE_REVIEW_TIMEOUT_MS";

#[derive(Debug, Parser)]
#[command(name = "swe-review", version)]
#[command(about = "Run Quick Review over local changes")]
#[command(disable_help_subcommand = true)]
#[command(args_conflicts_with_subcommands = true)]
#[command(subcommand_negates_reqs = true)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    #[command(flatten)]
    review: QuickReviewArgs,
}

#[derive(Debug, Subcommand)]
enum Commands {
    #[command(about = "Extract Windsurf API key from local database")]
    ExtractKey(ExtractKeyArgs),
}

#[derive(Debug, Args)]
struct QuickReviewArgs {
    #[command(flatten)]
    review: ReviewArgs,

    #[arg(
        long,
        help = "Quick Review model to use: swe-check, opus-4-7-review, or gpt-5-5-review. Defaults to swe-check."
    )]
    model: Option<String>,
}

#[derive(Debug, Args)]
struct ReviewArgs {
    #[arg(long, help = "Absolute or relative path to the Git project root.")]
    path: Option<PathBuf>,

    #[arg(
        long,
        help = "Windsurf API key. Defaults to WINDSURF_API_KEY or swe-tools/config.json."
    )]
    api_key: Option<String>,

    #[arg(long, help = "Review only staged changes.")]
    staged: bool,

    #[arg(long, help = "Review only unstaged and untracked changes.")]
    unstaged: bool,

    #[arg(
        long,
        value_name = "REF",
        help = "Compare working tree changes against a Git ref."
    )]
    base: Option<String>,

    #[arg(long, help = "Print a JSON report instead of Markdown.")]
    json: bool,
}

#[derive(Debug, Args)]
struct ExtractKeyArgs {
    #[arg(long, help = "Path to Windsurf state.vscdb. Default is auto-detect.")]
    db_path: Option<PathBuf>,

    #[arg(long, help = "Save extracted key to swe-tools config.")]
    save: bool,

    #[arg(long, help = "Print the full key instead of a masked key.")]
    show: bool,
}

pub fn run() -> i32 {
    let cli = Cli::parse();
    match cli.command {
        Some(Commands::ExtractKey(args)) => run_extract_key(args),
        None => run_quick_review_command(cli.review),
    }
}

fn run_extract_key(args: ExtractKeyArgs) -> i32 {
    let result = extract_key(args.db_path.as_deref());
    if let Some(error) = result.error {
        eprintln!("Error: {error}");
        if let Some(hint) = result.hint {
            eprintln!("Hint: {hint}");
        }
        return 1;
    }

    let Some(key) = result.api_key else {
        eprintln!("Error: apiKey field is empty");
        return 1;
    };

    if args.save {
        match write_swe_tools_config_api_key(&key) {
            Ok(config_path) => eprintln!("Saved Windsurf API key to {}", config_path.display()),
            Err(error) => {
                eprintln!("Error: {error}");
                return 1;
            }
        }
    }

    println!(
        "Windsurf API Key: {}",
        if args.show {
            key.clone()
        } else {
            mask_api_key(&key)
        }
    );
    if let Some(key_type) = result.key_type {
        eprintln!("Key type: {key_type}");
    }
    eprintln!("{}: {}", result.source_label, result.db_path);

    if args.show {
        println!("\nRun the following command to set the env var:");
        println!("  export WINDSURF_API_KEY=\"{key}\"");
    }

    0
}

fn run_quick_review_command(args: QuickReviewArgs) -> i32 {
    let Some(path) = args.review.path.as_deref() else {
        eprintln!("Error: --path is required");
        return 2;
    };
    let source = match diff_source_from_args(&args.review) {
        Ok(source) => source,
        Err(message) => {
            eprintln!("Error: {message}");
            return 2;
        }
    };
    let mut options = QuickReviewOptions::new(absolute_path(path));
    if let Err(message) = apply_review_options(&mut options.review, source, &args.review) {
        eprintln!("Error: {message}");
        return 2;
    }
    options.model = args.model;

    let progress = |message: &str| {
        eprintln!("[swe-review] {message}");
        let _ = std::io::stderr().flush();
    };

    match run_quick_review(options, Some(&progress)) {
        Ok(report) if args.review.json => match serde_json::to_string_pretty(&report) {
            Ok(text) => {
                println!("{text}");
                0
            }
            Err(error) => {
                eprintln!("Unexpected error: {error}");
                1
            }
        },
        Ok(report) => {
            if !report.skipped_files.is_empty() {
                eprintln!(
                    "[swe-review] Skipped {} file(s):",
                    report.skipped_files.len()
                );
                for skipped in &report.skipped_files {
                    eprintln!("[swe-review]   {}: {}", skipped.path, skipped.reason);
                }
            }
            println!("{}", report.review);
            0
        }
        Err(error) => {
            eprintln!("Quick Review failed: {error}");
            1
        }
    }
}

fn diff_source_from_args(args: &ReviewArgs) -> Result<DiffSource, String> {
    diff_source(args.staged, args.unstaged, args.base.as_deref())
}

fn diff_source(staged: bool, unstaged: bool, base: Option<&str>) -> Result<DiffSource, String> {
    let selected = staged as usize + unstaged as usize + usize::from(base.is_some());
    if selected > 1 {
        return Err("--staged, --unstaged, and --base are mutually exclusive".to_string());
    }
    if staged {
        return Ok(DiffSource::Staged);
    }
    if unstaged {
        return Ok(DiffSource::Unstaged);
    }
    if let Some(base) = base {
        return Ok(DiffSource::Base(base.to_string()));
    }
    Ok(DiffSource::WorkingTree)
}

fn apply_review_options(
    options: &mut ReviewOptions,
    source: DiffSource,
    args: &ReviewArgs,
) -> Result<(), String> {
    options.source = source;
    options.api_key = args.api_key.clone();
    options.max_file_bytes = env_value(MAX_FILE_BYTES_ENV, options.max_file_bytes)?;
    options.max_total_diff_bytes =
        env_value(MAX_TOTAL_DIFF_BYTES_ENV, options.max_total_diff_bytes)?;
    options.max_total_diff_lines =
        env_value(MAX_TOTAL_DIFF_LINES_ENV, options.max_total_diff_lines)?;
    options.max_estimated_tokens =
        env_value(MAX_ESTIMATED_TOKENS_ENV, options.max_estimated_tokens)?;
    options.timeout_ms = env_value(TIMEOUT_MS_ENV, options.timeout_ms)?;
    Ok(())
}

fn env_value<T>(name: &str, default: T) -> Result<T, String>
where
    T: std::str::FromStr,
{
    match env::var(name) {
        Ok(value) => value
            .parse()
            .map_err(|_| format!("{name} must be an integer")),
        Err(env::VarError::NotPresent) => Ok(default),
        Err(env::VarError::NotUnicode(_)) => Err(format!("{name} must be valid Unicode")),
    }
}

fn absolute_path(path: &Path) -> PathBuf {
    let candidate = if path.is_absolute() {
        path.to_path_buf()
    } else {
        env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("."))
            .join(path)
    };
    candidate.canonicalize().unwrap_or(candidate)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args() -> ReviewArgs {
        ReviewArgs {
            path: Some(PathBuf::from(".")),
            api_key: None,
            staged: false,
            unstaged: false,
            base: None,
            json: false,
        }
    }

    #[test]
    fn diff_source_defaults_to_working_tree() {
        assert!(matches!(
            diff_source_from_args(&args()).unwrap(),
            DiffSource::WorkingTree
        ));
    }

    #[test]
    fn diff_source_rejects_multiple_sources() {
        let mut args = args();
        args.staged = true;
        args.base = Some("main".to_string());
        assert!(diff_source_from_args(&args).is_err());
    }
}
