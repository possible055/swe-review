# swe-review

`swe-review` reviews local Git changes with Devin/Windsurf Quick Review.
Use it before committing, opening a pull request, or handing work to another
agent.

It reads your local diff and prints review feedback. It does not modify your
files.

## Commands

| Command | Use when you want | Output |
| --- | --- | --- |
| no subcommand | Broader review feedback | Free-form review text |
| `extract-key` | Save or inspect local credentials | Masked or full key output |

## Setup

Build the CLI:

```bash
cargo build --release
```

If you already use Devin or Windsurf locally, save a usable key once:

```bash
swe-review extract-key --save
```

You can also provide a key directly:

```bash
export WINDSURF_API_KEY="..."
swe-review --path . --api-key "$WINDSURF_API_KEY"
```

## Basic Usage

Review current working tree changes:

```bash
swe-review --path .
```

Review staged changes only:

```bash
swe-review --path . --staged
```

Review changes against a base branch:

```bash
swe-review --path . --base main
```

Print JSON:

```bash
swe-review --path . --json
```

## Review Options

Choose a Quick Review model:

```bash
swe-review --path . --model swe-check
```

Choose one diff source at a time:

```bash
swe-review --path . --staged
swe-review --path . --unstaged
swe-review --path . --base main
```

If no diff source is selected, `swe-review` reviews the current working tree.

## Large Diffs

Large diff limits are controlled by environment variables. Defaults are suitable
for normal local reviews.

| Variable | Default | Use |
| --- | ---: | --- |
| `SWE_REVIEW_MAX_FILE_BYTES` | `1000000` | Skip changed files larger than this many bytes |
| `SWE_REVIEW_MAX_TOTAL_DIFF_BYTES` | `512000` | Fail when the prepared diff exceeds this many bytes |
| `SWE_REVIEW_MAX_TOTAL_DIFF_LINES` | `12000` | Fail when the prepared diff exceeds this many lines |
| `SWE_REVIEW_MAX_ESTIMATED_TOKENS` | `120000` | Fail when the prepared prompt exceeds this many tokens |
| `SWE_REVIEW_TIMEOUT_MS` | `120000` | HTTP request timeout in milliseconds |

## Credentials

Credential lookup order:

1. `--api-key`
2. `WINDSURF_API_KEY`
3. Saved key from `swe-review extract-key --save`
4. Local Devin/Windsurf credentials

To inspect the extracted key source without saving:

```bash
swe-review extract-key
```

To print the full key for shell setup:

```bash
swe-review extract-key --show
```
