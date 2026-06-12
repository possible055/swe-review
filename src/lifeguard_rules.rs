use serde::Deserialize;
use std::fs;
use std::path::{Path, PathBuf};
use thiserror::Error;

const RULES_FILE_NAME: &str = "lifeguard.yaml";

const AGENT_RULES: &[&str] = &[
    "Flag any unimplemented code sections, newly added TODO comments, placeholder implementations, or comments indicating incomplete work (e.g., \"implement later\", \"add logic here\", \"stub\").",
    "Flag messy code that duplicates existing abstractions instead of reusing them, or that should have refactored related code for consistency.",
    "Flag brittle coupling between components - code should use well-defined interfaces rather than reaching into implementation details.",
    "Flag inline imports or require statements that appear in the middle of files rather than at the top with other imports.",
];

#[derive(Debug, Error)]
pub enum RulesError {
    #[error("Could not read {path}: {message}")]
    Read { path: String, message: String },
    #[error("Could not parse {path}: {message}")]
    Parse { path: String, message: String },
}

#[derive(Debug, Deserialize)]
struct LifeguardYaml {
    #[serde(default)]
    rules: Vec<Rule>,
    #[serde(default)]
    memories: Vec<Memory>,
}

#[derive(Debug, Deserialize)]
struct Rule {
    name: String,
    description: String,
}

#[derive(Debug, Deserialize)]
struct Memory {
    title: String,
    description: String,
    #[serde(default)]
    comment: String,
    #[serde(default)]
    file: Option<String>,
    #[serde(default)]
    line: Option<u64>,
}

pub fn read_user_rules(
    repo_root: &Path,
    include_agent_rules: bool,
) -> Result<Vec<String>, RulesError> {
    let mut rules = match rules_file(repo_root) {
        Some(path) => read_rules_file(&path)?,
        None => Vec::new(),
    };
    if include_agent_rules {
        rules.extend(AGENT_RULES.iter().map(|rule| (*rule).to_string()));
    }
    Ok(rules)
}

fn rules_file(repo_root: &Path) -> Option<PathBuf> {
    [
        repo_root.join(".devin").join(RULES_FILE_NAME),
        repo_root.join(".windsurf").join(RULES_FILE_NAME),
    ]
    .into_iter()
    .find(|path| path.is_file())
}

fn read_rules_file(path: &Path) -> Result<Vec<String>, RulesError> {
    let text = fs::read_to_string(path).map_err(|err| RulesError::Read {
        path: path.display().to_string(),
        message: err.to_string(),
    })?;
    let parsed = serde_yaml::from_str::<LifeguardYaml>(&text).map_err(|err| RulesError::Parse {
        path: path.display().to_string(),
        message: err.to_string(),
    })?;
    let mut out = Vec::new();
    out.extend(
        parsed
            .rules
            .into_iter()
            .map(|rule| format!("{}: {}", rule.name, rule.description)),
    );
    out.extend(parsed.memories.into_iter().map(format_memory));
    Ok(out)
}

fn format_memory(memory: Memory) -> String {
    let mut file = String::new();
    if let Some(path) = memory.file
        && !path.is_empty()
    {
        file = format!(
            " (File: {}{})",
            path,
            memory
                .line
                .map(|line| format!(":{line}"))
                .unwrap_or_default()
        );
    }
    format!(
        "IGNORE: \"{}\" - {}. User comment: {}{}",
        memory.title, memory.description, memory.comment, file
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn reads_rules_and_memories() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().join(".devin");
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join(RULES_FILE_NAME),
            r#"
rules:
  - name: Prefer helpers
    description: Reuse existing helpers.
memories:
  - title: Legacy false positive
    description: This pattern is allowed
    comment: Keep it
    file: src/lib.rs
    line: 42
"#,
        )
        .unwrap();

        let rules = read_user_rules(tmp.path(), false).unwrap();
        assert_eq!(rules[0], "Prefer helpers: Reuse existing helpers.");
        assert_eq!(
            rules[1],
            "IGNORE: \"Legacy false positive\" - This pattern is allowed. User comment: Keep it (File: src/lib.rs:42)"
        );
    }

    #[test]
    fn appends_agent_rules_when_enabled() {
        let tmp = TempDir::new().unwrap();
        let rules = read_user_rules(tmp.path(), true).unwrap();
        assert_eq!(rules.len(), AGENT_RULES.len());
    }
}
