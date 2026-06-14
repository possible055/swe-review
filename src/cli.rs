use crate::credentials::{extract_key, mask_api_key, write_swe_tools_config_api_key};
use crate::diff::DiffSource;
use crate::quick_review::{QuickReviewOptions, run_quick_review};
use crate::review_options::ReviewOptions;
use clap::{Args, Parser, Subcommand};
use std::env;
use std::io::Write;
use std::path::{Path, PathBuf};

#[derive(Debug, Parser)]
#[command(name = "swe-review", version)]
#[command(disable_help_subcommand = true)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    #[command(about = "Extract Windsurf API key from local database")]
    ExtractKey(ExtractKeyArgs),
    #[command(about = "Run Quick Review over local changes")]
    QuickReview(QuickReviewArgs),
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
    path: PathBuf,

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
        help = "Review working tree changes against a base ref."
    )]
    base: Option<String>,

    #[arg(
        long,
        value_name = "FILE",
        help = "Read an existing unified diff file."
    )]
    diff_file: Option<PathBuf>,

    #[arg(
        long,
        default_value_t = 1_000_000,
        help = "Skip changed files larger than this many bytes."
    )]
    max_file_bytes: u64,

    #[arg(
        long,
        default_value_t = 512_000,
        help = "Fail when the prepared diff exceeds this many bytes."
    )]
    max_total_diff_bytes: usize,

    #[arg(
        long,
        default_value_t = 12_000,
        help = "Fail when the prepared diff exceeds this many lines."
    )]
    max_total_diff_lines: usize,

    #[arg(
        long,
        default_value_t = 100_000,
        help = "Fail when the prepared diff estimate exceeds this many tokens."
    )]
    max_estimated_tokens: u64,

    #[arg(
        long,
        default_value_t = 120_000,
        help = "HTTP request timeout in milliseconds."
    )]
    timeout_ms: u64,

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
        Commands::ExtractKey(args) => run_extract_key(args),
        Commands::QuickReview(args) => run_quick_review_command(args),
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
    let source = match diff_source_from_args(&args.review) {
        Ok(source) => source,
        Err(message) => {
            eprintln!("Error: {message}");
            return 2;
        }
    };
    let mut options = QuickReviewOptions::new(absolute_path(&args.review.path));
    apply_review_options(&mut options.review, source, &args.review);
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
    diff_source(
        args.staged,
        args.unstaged,
        args.base.as_deref(),
        args.diff_file.as_deref(),
    )
}

fn diff_source(
    staged: bool,
    unstaged: bool,
    base: Option<&str>,
    diff_file: Option<&Path>,
) -> Result<DiffSource, String> {
    let selected = staged as usize
        + unstaged as usize
        + usize::from(base.is_some())
        + usize::from(diff_file.is_some());
    if selected > 1 {
        return Err(
            "--staged, --unstaged, --base, and --diff-file are mutually exclusive".to_string(),
        );
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
    if let Some(diff_file) = diff_file {
        return Ok(DiffSource::DiffFile(diff_file.to_path_buf()));
    }
    Ok(DiffSource::WorkingTree)
}

fn apply_review_options(options: &mut ReviewOptions, source: DiffSource, args: &ReviewArgs) {
    options.source = source;
    options.api_key = args.api_key.clone();
    options.max_file_bytes = args.max_file_bytes;
    options.max_total_diff_bytes = args.max_total_diff_bytes;
    options.max_total_diff_lines = args.max_total_diff_lines;
    options.max_estimated_tokens = args.max_estimated_tokens;
    options.timeout_ms = args.timeout_ms;
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
            path: PathBuf::from("."),
            api_key: None,
            staged: false,
            unstaged: false,
            base: None,
            diff_file: None,
            max_file_bytes: 100,
            max_total_diff_bytes: 512_000,
            max_total_diff_lines: 12_000,
            max_estimated_tokens: 100_000,
            timeout_ms: 1000,
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
