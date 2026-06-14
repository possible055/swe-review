# swe-review

`swe-review` reviews local Git changes with Devin/Windsurf Quick Review.
Use it before committing, opening a pull request, or handing work to another
agent.

It reads your local diff and prints review feedback. It does not modify your
files.

## Commands

| Command | Use when you want | Output |
| --- | --- | --- |
| `quick-review` | Broader review feedback | Free-form review text |
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
swe-review quick-review --path . --api-key "$WINDSURF_API_KEY"
```

## Basic Usage

Review current working tree changes:

```bash
swe-review quick-review --path .
```

Review staged changes only:

```bash
swe-review quick-review --path . --staged
```

Review changes against a base branch:

```bash
swe-review quick-review --path . --base main
```

Review an existing diff file:

```bash
swe-review quick-review --path . --diff-file changes.diff
```

Print JSON:

```bash
swe-review quick-review --path . --json
```

## Review Options

Choose a Quick Review model:

```bash
swe-review quick-review --path . --model swe-check
```

Choose one diff source at a time:

```bash
swe-review quick-review --path . --staged
swe-review quick-review --path . --unstaged
swe-review quick-review --path . --base main
swe-review quick-review --path . --diff-file changes.diff
```

If no diff source is selected, `swe-review` reviews the current working tree.

## Large Diffs

Use limits when reviewing large repositories or generated-heavy changes:

```bash
swe-review quick-review --path . \
  --max-file-bytes 1000000 \
  --max-total-diff-bytes 512000 \
  --max-total-diff-lines 12000 \
  --max-estimated-tokens 100000
```

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
