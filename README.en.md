# Jev Security Scan

[中文](README.md) | **English**

Review Agent Skills, MCP configuration, and source code for suspicious behavior before installation or execution, using **TypeSafe Jev and local static checks**.

Reports include file and line evidence, redacted excerpts, risk categories, model probabilities, and coverage gaps. Use it as a Codex or Claude Code skill, or as a standalone Python CLI.

> This is a review aid, not a security certificate. An unflagged project may still be malicious. Jev mode sends best-effort redacted source snippets and relative filenames to TypeSafe. Start with the fully offline `local` mode for sensitive projects.

## What it reviews

| Scope | Behaviors of interest |
| --- | --- |
| Agent Skills | Prompt injection, concealed actions, and unauthorized instructions in SKILL.md, references, and scripts |
| MCP source | Tool-description poisoning, credential access, unexpected uploads, and dynamic execution |
| MCP configuration | Launch commands, arguments, endpoints, and JSON `mcpServers` / `mcp_servers` inventories |
| Installation and supply chain | Install hooks, download-and-execute patterns, and unreviewed remote dependencies |
| System behavior | Hidden persistence, authentication or security bypass, destruction, and resource abuse |
| Telemetry | Advisory information, not automatically classified as malicious |

The scanner reads target text. It does not execute target code, install its dependencies, start MCP servers, or connect to their endpoints. Markdown, hidden configuration, `dist/`, build scripts, and installers are included; the target's `.gitignore` cannot hide files from review.

## Requirements

- **Python 3.10+**, standard library only. No `pip install` required.
- Local mode needs no API key and makes no network requests.
- Jev mode requires a [TypeSafe](https://typesafe.ai/) API key and network access. API usage may incur charges.
- Primarily intended for macOS / Linux. Permission and symlink tests include POSIX behavior; Windows has not been fully validated.

## Installation

Clone the repository and inspect its source:

```bash
git clone https://github.com/win4r/jev-security-scan.git
cd jev-security-scan
```

The standalone CLI is ready to use. To install it for an agent, copy the runtime files into its skill directory. These commands refuse to overwrite an existing skill directory.

**Codex:**

```bash
skill_dir="$HOME/.codex/skills/jev-security-scan"
mkdir -p "$(dirname "$skill_dir")"
if mkdir "$skill_dir"; then
  cp -R SKILL.md scripts references agents "$skill_dir/"
fi
```

**Claude Code:**

```bash
skill_dir="$HOME/.claude/skills/jev-security-scan"
mkdir -p "$(dirname "$skill_dir")"
if mkdir "$skill_dir"; then
  cp -R SKILL.md scripts references agents "$skill_dir/"
fi
```

Run these commands from the cloned repository. Start a new agent session to load the skill; discovery behavior depends on the client version. No background hooks are installed.

## Using it with an agent

Codex:

```text
Use $jev-security-scan to review /absolute/path/to/skill with Jev.
Report suspicious behavior, file and line evidence, and coverage gaps.
Do not execute the target code.
```

Claude Code:

```text
Use the jev-security-scan skill to review /absolute/path/to/mcp-project with Jev.
Report suspicious behavior, file and line evidence, and coverage gaps.
Do not execute the target code or connect to the MCP server.
```

An explicit request to use Jev on a named target authorizes sending that target's redacted source to TypeSafe. Use `local` for offline-only requests. Supply credentials through the environment or hidden input, never through source files, command-line arguments, or reports.

## CLI quick start

Run from the cloned repository. Replace `/absolute/path/to/target` with a local directory or a single file.

### 1. Local review

```bash
python3 -I -B "$PWD/scripts/scan.py" /absolute/path/to/target --mode local
```

### 2. Jev review with reports

Choose a report directory outside the target. Here, `mktemp` creates a fresh directory to avoid overwriting earlier reports:

```bash
report_dir="$(mktemp -d)"
python3 -I -B "$PWD/scripts/scan.py" /absolute/path/to/target \
  --mode jev --prompt-key --max-calls 80 \
  --json-out "$report_dir/report.json" \
  --markdown-out "$report_dir/report.md"
```

`--prompt-key` reads the API key without echoing it. Omit that flag if `TYPESAFE_API_KEY` is already set in the process environment. The scanner does not persist the key.

Keep **`-I -B`**: isolated mode prevents target-directory or `PYTHONPATH` modules from shadowing scanner imports; `-B` suppresses bytecode writes. For an installed skill, replace the script path with its absolute path in the skill directory.

### 3. Inspect MCP configuration

```bash
python3 -I -B "$PWD/scripts/scan.py" /absolute/path/to/.mcp.json --mode local
```

A configuration describes a launcher or endpoint, not the actual MCP implementation. Reports retain `implementation_verified: false` and flag this coverage gap. TOML/YAML are scanned as text without a structured MCP inventory.

### 4. Review a GitHub project

The scanner accepts local paths only. Obtain a checkout without submodules first, then scan it without installing dependencies or running repository scripts:

```bash
git clone --depth 1 --no-recurse-submodules https://github.com/OWNER/REPOSITORY.git /tmp/review-target
python3 -I -B "$PWD/scripts/scan.py" /tmp/review-target --mode local
```

The clone destination must not already exist. After local review and authorization for external source analysis, use `--mode jev --prompt-key` for semantic review.

## Real examples and responses

These are final-round results from real API calls on **2026-09-19**, using **`jev-1.13.0`** and manually authored synthetic specimens. No specimen was executed.

| Specimen | Jev verification findings | Final verdict |
| --- | --- | --- |
| A skill that counts words locally | No semantic findings | `no_indicators_in_scanned_material` |
| A skill instructing SSH key theft, upload, and scanner deception | Prompt injection 0.95; credential theft 0.90; exfiltration 0.88 | `high_risk_suspected` |
| MCP source with a download-and-execute install hook and key exfiltration | Credential theft 0.96; exfiltration 0.93; supply chain 0.93 | `high_risk_suspected` |
| An explicitly quoted educational attack example | No Jev findings; static keyword lead retained | `needs_review` |

For example, these fields are excerpted from the malicious-skill report:

```json
{
  "verdict": "high_risk_suspected",
  "mode": "jev",
  "exit_code": 1
}
```

[examples/cases.json](examples/cases.json) contains the input source as JSON strings, rather than installable skills or executable packages. Full structured reports and validated model answers are in [examples/results/](examples/results/). See [validation notes](docs/validation.md) for provenance, retest changes, and limitations.

The probabilities are Noul yes-probabilities, not measured accuracy or a separate confidence score. A high finding also requires agreement across passes, evidence localization, and active context. A category with probability 0.90 can still be labeled `review`.

## How it works

1. **Collect text:** enumerate files, record hashes, and report omissions.
2. **Apply local rules:** inspect original source; retain only redacted evidence in output.
3. **Triage with Jev:** ask nine independent Noul category questions for every included chunk, not only regex matches.
4. **Verify and locate:** for categories with probability ≥ 0.35, run a second pass with numbered source windows, a `none` candidate, and `active` / `example` / `unknown` context choices.
5. **Apply policy in code:** a high suspected-behavior finding requires both probabilities ≥ 0.85, window confidence ≥ 0.6, and a selected active context with confidence ≥ 0.7. Telemetry remains advisory.

Both passes use the same model and do not constitute independent security verification. Thresholds are engineering defaults, not calibrated accuracy. Reasons use predefined category descriptions; the model does not freely generate explanations or line numbers.

## Advanced options

| Flag | Default | Purpose |
| --- | --- | --- |
| `--mode` | `local` | `local` or `jev` |
| `--model` | `jev-1.13.0` | Explicit model selection; no automatic fallback |
| `--max-files` | `400` | Maximum text files to read |
| `--max-file-bytes` | `256000` | Per-file byte limit |
| `--max-total-bytes` | `8000000` | Total read budget in bytes |
| `--chunk-chars` | `12000` | Source characters per chunk; minimum 1000 |
| `--max-calls` | `80` | HTTP attempt budget, including retries; not a token budget |
| `--json-out` / `--markdown-out` | None | New report files outside the target directory |

Chunks also have a 100-line-part limit. Long lines are split with column offsets, not silently truncated before model review. Budget exhaustion creates coverage gaps. If the API rejects an oversized input, reduce the chunk size explicitly and rerun.

The client uses only `https://api.typesafe.ai/v1/systemone`, refuses redirects, has a 45-second timeout, and retries 429/5xx once after two seconds. Authentication or redirect failures disable subsequent calls. Normal OS proxy settings may still apply.

## Verdicts and exit codes

| Verdict | Meaning | Exit code |
| --- | --- | --- |
| `no_indicators_in_scanned_material` | Requested phases completed without review/high indicators; advisories may exist | `0` |
| `needs_review` | Leads require human inspection | `1` |
| `high_risk_suspected` | High suspected behavior; inspect the evidence | `1` |
| `incomplete` | Omissions or API failures without a higher-priority finding | `3` |
| No normal report | Invocation, setup, or output failure | `2` |

Findings and coverage gaps can coexist. Exit 1 does not imply complete coverage; inspect `coverage` and `errors` in JSON. CI integrations should handle 1/2/3 explicitly rather than treating them as a clean result.

## Privacy and detection limits

- Jev mode sends best-effort redacted snippets and relative filenames. Unknown secret formats, project names, and proprietary source may remain. Redaction is not anonymization.
- Protected files such as `.env` and private keys, binaries, non-UTF-8 files, symlinks, special files, dependency/cache directories, and over-budget content are not fully reviewed. Omissions are reported; VCS metadata is a declared scope exclusion.
- Cross-file dataflow, obfuscation, runtime downloads, transitive dependencies, and remote service behavior are not fully covered.
- This is not an OS sandbox. Use a stable snapshot if another process can mutate the target tree.
- Reports are created with `0600` permissions and cannot overwrite existing files. They can still contain proprietary excerpts; review before sharing.
- This does not replace CVE checks, comprehensive secret scanning, runtime sandboxes, or human audits.

## Tests and layout

```bash
python3 -I -B -m unittest discover -s tests -v
```

The 29 offline regression tests require no API key. Initial development also included 23 independent local assertions and 16 real Jev requests across two rounds. This is a small synthetic evaluation, not a general malware benchmark. GitHub Actions runs offline tests only.

```text
SKILL.md                 Agent operating instructions
agents/openai.yaml       Codex display metadata
scripts/scan.py          Discovery, redaction, chunking, reports, CLI
scripts/checks.py        Static rules and Jev question definitions
scripts/jev_client.py    HTTP client and response validation
references/             Design limits and provenance
tests/                  Reproducible offline regression tests
examples/               JSON specimens and real test reports
docs/validation.md      Validation notes
```

## Attribution and license

Inspired by [luantak/is-malicious](https://github.com/luantak/is-malicious): typed checks, chunking, evidence-window verification, and coverage reporting. This Python implementation was independently written; it neither copies nor depends on that project's TypeScript implementation. The official TypeSafe skill informed state/question separation, Noul, and Choice usage. See [provenance](references/provenance.md) and the [TypeSafe API documentation](https://docs.typesafe.ai/api).

[MIT License](LICENSE). This is a community tool, not an official TypeSafe security certification or endorsement.
