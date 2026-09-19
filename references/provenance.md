# Sources and design provenance

Reviewed 2026-09-19.

- Reference: [luantak/is-malicious](https://github.com/luantak/is-malicious), commit b6052465eb47cf85f347596385954aa06532718a, package 0.1.0, MIT. Read README, manifest/license, discovery, Jev questions, escalation, report paths, skill and wrapper. No dependencies installed or reference code executed. This was bounded source inspection, not a complete security audit.
- Borrowed ideas: typed checks in one Jev request, source chunking, second-pass evidence windows, telemetry advisories, coverage and usage reporting. This Python scanner is independently written; it does not import the reference package or copy its TypeScript implementation.
- Skill/MCP additions: instruction/tool-description poisoning; Markdown and hidden config inclusion; no gitignore-controlled omission or automatic dist/build exclusion; secret-file omissions and best-effort redaction; candidate/state alignment; raw Noul probability without invented confidence; explicit local-only mode; redirect refusal; no target execution.
- [TypeSafe HTTP API](https://docs.typesafe.ai/api): endpoint and typed request/response contract.
- [TypeSafe Noul](https://docs.typesafe.ai/primitives/noul): yes-probability with no separate confidence.
- [TypeSafe guardrail cookbook](https://docs.typesafe.ai/cookbooks/llm_guardrails): independent hazard judgments feeding policy in code. It does not establish this scanner's adversarial robustness.
- The installed official typesafe-ai skill guided state/question separation, atomic judgments, no-match choices and uncertainty handling.
