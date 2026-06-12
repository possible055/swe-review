# swe-review

`swe-review` is a command-line tool for reviewing local Git changes with
Devin/Windsurf review capabilities.

Use it when you want a second pass over code changes before committing,
opening a pull request, or handing work to another agent.

## What It Does

`swe-review` provides two review commands:

| Command | Best for | Output |
| --- | --- | --- |
| `review` | Focused bug finding | Structured findings rendered as Markdown |
| `quick-review` | Broader code review feedback | Free-form review text |

Both commands review local changes from a Git repository. They do not modify
your files.

## Setup

Build the CLI:

```bash
cargo build --release
```

Provide an API key with either a flag:

```bash
swe-review review --path . --api-key "$WINDSURF_API_KEY"
```

or an environment variable:

```bash
export SWE_REVIEW_API_KEY="..."
```

`WINDSURF_API_KEY` is also accepted.

## Basic Usage

Review current working tree changes:

```bash
swe-review review --path .
```

Run a broader Quick Review:

```bash
swe-review quick-review --path .
```

Review staged changes only:

```bash
swe-review review --path . --staged
```

Review changes against a base branch:

```bash
swe-review review --path . --base main
```

Review an existing diff file:

```bash
swe-review review --path . --diff-file changes.diff
```

Print JSON instead of Markdown/text:

```bash
swe-review review --path . --json
```

## Choosing A Review Mode

Use `review` when you want concise bug-oriented findings:

```bash
swe-review review --path . --method agent
```

Available methods are:

- `agent`
- `smart`
- `fast`

Use `quick-review` when you want broader review commentary:

```bash
swe-review quick-review --path .
```

To request a specific Quick Review model:

```bash
swe-review quick-review --path . --model <model-value>
```

## Diff Selection

Choose one diff source at a time:

```bash
swe-review review --path . --staged
swe-review review --path . --unstaged
swe-review review --path . --base main
swe-review review --path . --diff-file changes.diff
```

If no diff source is selected, `swe-review` reviews the current working tree.

## Size Limits

Large diffs can be limited before they are sent for review:

```bash
swe-review review --path . \
  --max-file-bytes 1000000 \
  --max-total-diff-bytes 512000 \
  --max-total-diff-lines 12000 \
  --max-estimated-tokens 100000
```

These limits help keep reviews predictable for large repositories.

## Notes

- Credentials can be supplied by `--api-key`, `SWE_REVIEW_API_KEY`, or
  `WINDSURF_API_KEY`.
