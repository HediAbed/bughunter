# BugHunter

BugHunter is a command-line tool that scans a project for bugs, security vulnerabilities, SOLID violations, and code-quality problems. Static checks run locally with no network access. AI-assisted review is opt-in and never runs unless you ask for it.

## Features

- Local static analysis with no external requests: long functions, large files, TODO/FIXME markers, and hardcoded secrets
- Syntax-tree parsing for Rust, Python, JavaScript, TypeScript, Go, Java, C, C++, Bash, HCL, YAML, and JSON
- Optional AI review through a `claude-cli` or `openai-compatible` backend
- GitHub pull request review over a SHA-pinned compare range
- JSON or Markdown reports with severity, confidence, and evidence per finding
- Live progress display while AI analysis runs, cancellable with `Ctrl-C`
- Coverage reporting that tells you which files were never inspected
- Exit codes designed for CI gating

## Install

Prebuilt archives for `x86_64-unknown-linux-gnu` are on the [releases page](https://github.com/HediAbed/bughunter/releases). Each ships a CycloneDX SBOM and `SHA256SUMS`; verify the checksum before unpacking. Build from source on other platforms.

From source, with Rust 1.88 or newer:

```sh
git clone https://github.com/HediAbed/bughunter.git
cd bughunter
cargo install --path . --locked
```

## Quick start

```sh
bughunter analyze --project .
```

That is the default mode: local static checks only, report on stdout as JSON.

## Analysis modes

| Mode | Flag | Network | What runs |
|---|---|---|---|
| Static (default) | none, or `--static-only` | none | Regex and syntax-tree checks |
| Static + AI | `--with-ai` | yes | Static checks, then AI review |
| AI only | `--ai-only` | yes | AI review, static checks skipped |
| Pull request | `--pr <N>` | yes | AI review scoped to the PR's changed lines |

```sh
bughunter analyze --project .                                  # static, fastest
bughunter analyze --project . --with-ai --output report.json   # both
bughunter analyze --project . --ai-only --format md            # AI only, Markdown

export GH_TOKEN=<token>                                        # or GITHUB_TOKEN
bughunter analyze --project . --pr 123                         # review a PR
```

`--ai-only` skips the local checks entirely, so it reports only what the model finds. Use `--with-ai` when you want both layers in one report.

`--pr` reads a token from `GH_TOKEN` or `GITHUB_TOKEN` and needs one for private repositories. Set `GITHUB_API_URL` to target GitHub Enterprise.

## Commands

```sh
bughunter analyze     # scan a project
bughunter doctor      # check the configured backend's local prerequisites, no network calls
bughunter init        # write a default .bughunter.toml
bughunter version     # print version information
```

## Getting help

```sh
bughunter --help              # top-level help, env vars, examples
bughunter help analyze        # every analyze flag with defaults
bughunter analyze -h          # short summary
```

`bughunter help analyze` is the authoritative flag reference; this README covers the common cases.

## Options

| Flag | Purpose |
|---|---|
| `--project <PATH>` | Project root (default `.`) |
| `--format <json\|md>` | Report format (default `json`) |
| `--output <FILE>` | Write the report to a file instead of stdout |
| `--categories <LIST>` | Limit to `bug`, `quality`, `solid`, `vulnerability` |
| `--min-confidence <LEVEL>` | Drop findings below `high`, `medium`, or `low` (default `low`) |
| `--fail-severity <LEVEL>` | Severity that triggers exit 1 (default `high`) |
| `--no-fail` | Always exit 0, even when findings meet the threshold |
| `--allow-partial` | Exit normally even when AI coverage was incomplete |
| `--no-progress` | Disable the interactive progress display |
| `--config <FILE>` | Use a specific `.bughunter.toml` |
| `--repo <OWNER/REPO>` | Repository for `--pr`; defaults to the git origin |
| `--verbose` | Debug logging on stderr |

## Configuration

AI modes need a backend. The default `claude-cli` backend uses your installed, authenticated `claude` executable and needs no further setup. Configure the `openai-compatible` backend through the environment:

```sh
export BUGHUNTER_BACKEND=openai-compatible
export BUGHUNTER_API_URL=https://your-provider/v1
export BUGHUNTER_API_TOKEN=<token>
export BUGHUNTER_MODEL=<model-id>
```

| Variable | Purpose |
|---|---|
| `BUGHUNTER_BACKEND` | `claude-cli` or `openai-compatible` |
| `BUGHUNTER_CLAUDE_CLI_BINARY` | Executable path for the CLI backend |
| `BUGHUNTER_MODEL` | Model identifier |
| `BUGHUNTER_API_TOKEN` | Bearer token for the HTTP backend |
| `BUGHUNTER_API_URL` | HTTP backend base URL |
| `BUGHUNTER_LOG_LEVEL` | `trace`, `debug`, `info`, `warn`, or `error` |

API tokens are accepted only from the environment, never from a config file. Settings also load from `.bughunter.toml` in the project and `$HOME/.bughunter/config.toml`; CLI flags override both.

Run `bughunter doctor --project .` to confirm a backend is usable before a long scan.

## Reports and coverage

A report carries every finding with its severity, confidence, rule, file, line range, and evidence, plus a `scan` object describing coverage. When AI analysis cannot inspect everything, the report marks itself `partial` and names the files it skipped, and the run exits 5 unless you pass `--allow-partial`.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Completed below the fail threshold |
| 1 | Findings met the fail threshold |
| 2 | Configuration error |
| 3 | Backend error |
| 4 | Project or engine error |
| 5 | Partial analysis coverage |
| 130 | Cancelled |

## Continuous integration

```sh
bughunter analyze --project . --format json --output report.json --fail-severity high
```

Static mode makes no network calls, so it needs no credentials. The interactive display turns itself off automatically when `CI` is set or when the terminal is not interactive.

## Security

Report vulnerabilities through a [private GitHub security advisory](https://github.com/HediAbed/bughunter/security/advisories/new) rather than a public issue.

Static modes make no network requests. `--with-ai`, `--ai-only`, and `--pr` send repository data to the configured backend, so review your provider's data policies before scanning private code. Credentials are read from the environment, redacted from logs, and never written to reports.

## Contributing

Issues and pull requests are welcome. Run `make check` before submitting; it gates on formatting, Clippy with warnings denied, and the full test suite.

## License

BugHunter is available under the [MIT License](LICENSE).
