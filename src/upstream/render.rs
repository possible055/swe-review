use super::client::CheckBugsReport;

pub fn format_bugs_markdown(report: &CheckBugsReport) -> String {
    if report.bugs.is_empty() {
        return "No issues found.".to_string();
    }

    let mut lines = Vec::new();
    lines.push(format!("Found {} issue(s).", report.bugs.len()));
    for (index, bug) in report.bugs.iter().enumerate() {
        let title = if bug.title.is_empty() {
            "Untitled issue"
        } else {
            &bug.title
        };
        lines.push(String::new());
        lines.push(format!("{}. {} ({})", index + 1, title, bug.severity));
        if !bug.file.is_empty() {
            lines.push(format!("   File: {}:{}-{}", bug.file, bug.start, bug.end));
        }
        if !bug.description.is_empty() {
            lines.push(format!("   Problem: {}", bug.description));
        }
        if !bug.resolution.is_empty() {
            lines.push(format!("   Fix: {}", bug.resolution));
        }
        if let Some(fix) = &bug.fix
            && (!fix.old_str.is_empty() || !fix.new_str.is_empty())
        {
            lines.push("   Suggested patch:".to_string());
            lines.push(format!("   - old: {}", fix.old_str));
            lines.push(format!("   - new: {}", fix.new_str));
        }
    }
    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_no_bug_report() {
        let report = CheckBugsReport {
            bugs: Vec::new(),
            bug_check_id: None,
            method_used: Some("agent".to_string()),
            model_used: None,
            playgrounds: None,
            model_id: Some(410),
            agent_version: Some("v2".to_string()),
        };
        assert_eq!(format_bugs_markdown(&report), "No issues found.");
    }
}
