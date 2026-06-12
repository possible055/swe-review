---
name: swe-review
description: Run Devin/Windsurf Lifeguard or Quick Review over local Git changes.
metadata:
  short-description: Local Devin/Windsurf review
---

# SWE Review

Use this skill when the user asks for an independent review of local code
changes using Devin/Windsurf Lifeguard or Quick Review.

## Binary

The packaged executable is located next to this skill file:

- Linux: `./bin/swe-review`
- Windows: `.\bin\swe-review.exe`

## Command

Run a review from the target repository root:

```sh
./bin/swe-review review --path <repo-path>
./bin/swe-review quick-review --path <repo-path>
```

Useful options:

- `--staged`: review staged changes only.
- `--unstaged`: review unstaged and untracked changes only.
- `--base <ref>`: review the working tree against a base ref.
- `--diff-file <file>`: review an existing unified diff file.
- `--method <agent|smart|fast>`: choose the Lifeguard method.
- `--transport <native|acp>`: choose direct Quick Review HTTP API or Devin ACP fallback.
- `--devin-bin <path>`: choose the standalone Devin CLI for `--transport acp`.
- `--model <value>`: override Quick Review model selection; native defaults to `swe-check` when the review catalog is empty.
- `--api-key <key>`: authenticate Lifeguard or Quick Review without relying on stored CLI credentials.
- `--json`: return a structured JSON report.
