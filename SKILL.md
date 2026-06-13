---
name: swe-review
description: Run Devin/Windsurf Lifeguard or Quick Review over local Git changes.
metadata:
  short-description: Local Devin review
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
- `--model <value>`: override Quick Review model selection; by default Quick Review uses the first discovered review model.
- `--api-key <key>`: authenticate Lifeguard or Quick Review without relying on `WINDSURF_API_KEY` or `swe-tools/config.json`.
- `--json`: return a structured JSON report.

To extract local Devin credentials or local Windsurf/Devin database credentials
into `swe-tools/config.json`:

```sh
./bin/swe-review extract-key --save
```

Useful extract-key options:

- `--show`: print the full key instead of a masked key.
- `--db-path <path>`: read a specific `state.vscdb`.
