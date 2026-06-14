use crate::diff::{DEFAULT_MAX_ESTIMATED_TOKENS, DiffBudget, DiffSource};
use std::path::PathBuf;

const DEFAULT_MAX_FILE_BYTES: u64 = 1_000_000;

#[derive(Debug, Clone)]
pub struct ReviewOptions {
    pub project_path: PathBuf,
    pub source: DiffSource,
    pub api_key: Option<String>,
    pub max_file_bytes: u64,
    pub max_total_diff_bytes: usize,
    pub max_total_diff_lines: usize,
    pub max_estimated_tokens: u64,
    pub timeout_ms: u64,
}

impl ReviewOptions {
    pub fn new(project_path: impl Into<PathBuf>) -> Self {
        let budget = DiffBudget::default();
        Self {
            project_path: project_path.into(),
            source: DiffSource::WorkingTree,
            api_key: None,
            max_file_bytes: DEFAULT_MAX_FILE_BYTES,
            max_total_diff_bytes: budget.max_total_diff_bytes,
            max_total_diff_lines: budget.max_total_diff_lines,
            max_estimated_tokens: DEFAULT_MAX_ESTIMATED_TOKENS,
            timeout_ms: 120_000,
        }
    }

    pub fn diff_budget(&self) -> DiffBudget {
        DiffBudget {
            max_total_diff_bytes: self.max_total_diff_bytes,
            max_total_diff_lines: self.max_total_diff_lines,
        }
    }
}
