use crate::diff::DiffSource;
use crate::lifeguard::{ReviewOptions, run_review};
use crate::quick_review::{QuickReviewOptions, run_quick_review};
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
    #[command(about = "Run a Lifeguard review over local changes")]
    Review(ReviewArgs),
    #[command(about = "Run Quick Review over local changes")]
    QuickReview(QuickReviewArgs),
}

#[derive(Debug, Args)]
struct ReviewArgs {
    #[arg(long, help = "Absolute or relative path to the Git project root.")]
    path: PathBuf,

    #[arg(
        long,
        help = "Windsurf or Devin API key. Defaults to SWE_REVIEW_API_KEY or WINDSURF_API_KEY."
    )]
    api_key: Option<String>,

    #[arg(
        long,
        default_value = "agent",
        value_parser = ["agent", "smart", "fast"],
        help = "Lifeguard method to run."
    )]
    method: String,

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
struct QuickReviewArgs {
    #[arg(long, help = "Absolute or relative path to the Git project root.")]
    path: PathBuf,

    #[arg(
        long,
        help = "Model config value to use. Defaults to discovered SWE-check, or the free swe-check model when the native catalog is empty."
    )]
    model: Option<String>,

    #[arg(
        long,
        help = "Devin/Windsurf API key. Defaults to SWE_REVIEW_API_KEY or WINDSURF_API_KEY when set."
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

pub fn run() -> i32 {
    let cli = Cli::parse();
    match cli.command {
        Commands::Review(args) => run_review_command(args),
        Commands::QuickReview(args) => run_quick_review_command(args),
    }
}

fn run_review_command(args: ReviewArgs) -> i32 {
    let source = match review_source(&args) {
        Ok(source) => source,
        Err(message) => {
            eprintln!("Error: {message}");
            return 2;
        }
    };
    let mut options = ReviewOptions::new(absolute_path(&args.path));
    options.source = source;
    options.api_key = args.api_key.or_else(|| env::var("SWE_REVIEW_API_KEY").ok());
    options.method = args.method;
    options.max_file_bytes = args.max_file_bytes;
    options.max_total_diff_bytes = args.max_total_diff_bytes;
    options.max_total_diff_lines = args.max_total_diff_lines;
    options.max_estimated_tokens = args.max_estimated_tokens;
    options.timeout_ms = args.timeout_ms;

    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("Unexpected error: {error}");
            return 1;
        }
    };
    let progress = |message: &str| {
        eprintln!("[swe-review] {message}");
        let _ = std::io::stderr().flush();
    };

    match runtime.block_on(async { run_review(options, Some(&progress)).await }) {
        Ok(report) if args.json => match serde_json::to_string_pretty(&report) {
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
            eprintln!("Review failed: {error}");
            1
        }
    }
}

fn run_quick_review_command(args: QuickReviewArgs) -> i32 {
    let source = match diff_source(
        args.staged,
        args.unstaged,
        args.base.as_deref(),
        args.diff_file.as_deref(),
    ) {
        Ok(source) => source,
        Err(message) => {
            eprintln!("Error: {message}");
            return 2;
        }
    };
    let mut options = QuickReviewOptions::new(absolute_path(&args.path));
    options.source = source;
    options.model = args.model;
    options.api_key = args.api_key;
    options.max_file_bytes = args.max_file_bytes;
    options.max_total_diff_bytes = args.max_total_diff_bytes;
    options.max_total_diff_lines = args.max_total_diff_lines;
    options.max_estimated_tokens = args.max_estimated_tokens;
    options.timeout_ms = args.timeout_ms;

    let progress = |message: &str| {
        eprintln!("[swe-review] {message}");
        let _ = std::io::stderr().flush();
    };

    match run_quick_review(options, Some(&progress)) {
        Ok(report) if args.json => match serde_json::to_string_pretty(&report) {
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
            if let Some(error) = &report.restore_error {
                eprintln!("[swe-review] Quick Review: failed to restore model: {error}");
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

fn review_source(args: &ReviewArgs) -> Result<DiffSource, String> {
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
            method: "agent".to_string(),
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
    fn review_source_defaults_to_working_tree() {
        assert!(matches!(
            review_source(&args()).unwrap(),
            DiffSource::WorkingTree
        ));
    }

    #[test]
    fn review_source_rejects_multiple_sources() {
        let mut args = args();
        args.staged = true;
        args.base = Some("main".to_string());
        assert!(review_source(&args).is_err());
    }
}
