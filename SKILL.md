---
name: swe-review
description: Run Devin/Windsurf Quick Review over local Git changes.
metadata:
  short-description: Local Devin review
---

# SWE Review

Use this skill when the user asks for an independent Quick Review of local code
changes using Devin/Windsurf.

## Binary

The packaged executable is located next to this skill file:

- Linux: `./bin/swe-review`
- Windows: `.\bin\swe-review.exe`

## Command

Run a review from the target repository root:

```sh
./bin/swe-review --path <repo-path>
```

Useful options:

- `--staged`: review staged changes only.
- `--unstaged`: review unstaged and untracked changes only.
- `--base <ref>`: review the working tree against a base ref.
- `--model <value>`: override Quick Review model selection; by default Quick Review uses the first discovered review model.
- `--api-key <key>`: authenticate Quick Review without relying on `WINDSURF_API_KEY` or `swe-tools/config.json`.
- `--json`: return a structured JSON report.

Large diff limits and HTTP timeout are controlled by environment variables:

- `SWE_REVIEW_MAX_FILE_BYTES`
- `SWE_REVIEW_MAX_TOTAL_DIFF_BYTES`
- `SWE_REVIEW_MAX_TOTAL_DIFF_LINES`
- `SWE_REVIEW_MAX_ESTIMATED_TOKENS`
- `SWE_REVIEW_TIMEOUT_MS`

To extract local Devin credentials or local Windsurf/Devin database credentials
into `swe-tools/config.json`:

```sh
./bin/swe-review extract-key --save
```

Useful extract-key options:

- `--show`: print the full key instead of a masked key.
- `--db-path <path>`: read a specific `state.vscdb`.
