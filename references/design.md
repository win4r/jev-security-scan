# Design and operating limits

## Pipeline

Enumerate local files without executing target code. Exclude VCS metadata and declared dependency/cache directories; do not obey target-controlled gitignore. Include Markdown, hidden agent configuration, dist, build scripts, extensionless UTF-8 files and lockfiles within budgets. Refuse symlinks, special files, unreadable/changing files, binary/non-UTF-8 contents and protected secret files; list omissions. This is not an OS sandbox: use a stable snapshot if another process can actively mutate the tree.

Record original SHA-256, redacted hash, bytes and line counts. Redact likely secret assignments, known token formats, bearer strings, credential URLs and private-key blocks before model calls/reports. Preserve line count. Omit .env, credentials and private-key files except sample/template variants. Unknown formats, project names and proprietary source can remain.

For valid JSON, parse string-token boundaries and mask protected values (including all MCP env/header string values) without rebuilding line layout. For local static analysis, inspect original source but retain only redacted evidence: a variable named secret_command must not hide an execution pattern. Use Python -I -B to isolate imports from target files and suppress bytecode writes.

Local patterns produce inspection leads, not malware verdicts. Jev mode sends every included text chunk, not just regex hits. Each request asks independent Noul questions for credential theft, unexpected upload, remote execution, agent prompt injection, persistence, security bypass, destructive/resource abuse, supply-chain behavior and telemetry.

For categories with first-pass probability >= 0.35, a second pass uses the same chunk plus overlapping numbered windows, a none candidate, and context choices active/example/unknown. Every offered candidate has its source in state. No generated explanation or line number is trusted.

Both probabilities >= 0.85, selected-window confidence >= 0.6 and active-context confidence >= 0.7 produce high **suspected behavior**; telemetry stays advisory. Lower or unlocalized signals remain review items. Strong first-pass signals are retained when the second pass disagrees. Thresholds are engineering defaults, not calibration. Static clues remain independent; repeated findings may need human grouping. Cross-file dataflow, obfuscation and behavior split across chunks can be missed. Complete coverage means completion of implemented phases, not semantic completeness.

## Budgets and API behavior

Defaults: 400 text files; 256,000 bytes/file; 8,000,000 total bytes; 12,000 source characters or 100 line parts/chunk; 80 HTTP attempts including retries. Long lines are split with column offsets, not truncated. Displayed evidence can be shortened; source sent for that chunk is not. An API token-limit rejection is reported as a failure; reduce chunk size explicitly and re-run.

The client fixes the official endpoint, blocks redirects, uses a 45-second timeout, and retries HTTP 429/5xx once after two seconds. Authentication/redirect failures disable further calls. Validate response shape, candidate membership and finite probability ranges. No target installer, package download, MCP connection, custom API endpoint or third-party telemetry is used. Normal OS proxy settings may still apply to Python's HTTP stack.

The request budget does not bound tokens. Reports include returned usage; failed requests may have unknown billing. No automatic model fallback or key persistence.

## Reports and exit status

JSON includes hashes, redaction counts, omissions, static/model findings, MCP metadata, validated model answers, usage and failures. Triage input is identified by a state hash; reports do not include all source, but findings contain redacted evidence. Check original SHA-256 if files change after review. Output files use 0600 permissions and refuse overwrite. Reports may still contain proprietary excerpts.

- 0: no review/high indicators in completed requested phases; advisories possible.
- 1: review/high indicators. Still inspect coverage and failures.
- 2: invocation/setup/output error preventing a normal report.
- 3: incomplete coverage without a higher-priority finding.

Local mode never claims Jev ran. MCP JSON mcpServers/mcp_servers launchers are inventoried, never started. Their implementation stays unverified even if related local files exist: the scanner cannot prove which runtime artifact resolves. TOML/YAML are scanned as text without this JSON inventory.

## Agent compatibility

Portable folder: SKILL.md, Python scripts, references. Codex loads it under ~/.codex/skills/jev-security-scan. Claude Code can use the same contents under ~/.claude/skills/jev-security-scan. Do not add a hook that silently sends every cloned repository to an external service. Run for a scoped review or an already-authorized installation review.

This is not a CVE database, comprehensive secret scanner, antivirus, sandbox or formal audit. Unflagged code is not certified safe.
