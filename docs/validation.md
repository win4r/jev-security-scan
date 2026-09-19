# Validation / 验证说明

## Scope / 范围

Version: **0.1.0**. Original evaluation date: **2026-09-19**.

验证分为可复现的离线回归、开发阶段独立断言、四组自制样本的真实 Jev 调用。它们不能证明通用检测准确率，也不是第三方机构认证。

Validation comprises reproducible offline regressions, independent local assertions during development, and real Jev calls on four manually authored specimens. It does not establish general detection accuracy or third-party certification.

## Offline regressions

Run from the repository root:

```bash
python3 -I -B -m unittest discover -s tests -v
```

The 29 tests cover discovery and inclusion, refusal to execute target code, import isolation, symlinks and FIFOs, protected-file omissions, JSON and plain-text redaction, escaped quotes, Unicode and CR line accounting, full chunk coverage, budgets, incomplete results, MCP inventory, evidence candidates, malformed model responses, redirects, output overwrite refusal, and terminal/Markdown display escaping.

Tests use temporary synthetic files and a fake client. No API key is required. They never run the attack specimens. Some tests create POSIX filesystem objects, which is why the CI matrix targets Linux and macOS.

29 项测试使用临时合成文件与模拟客户端，不消耗 Jev API。它们验证程序行为与已复现的问题，不能替代实际目标的人工审计。

## Independent local checks

During initial development, a separate agent authored and executed local forward tests. It found credential-redaction and line-accounting defects; these were fixed before publication. The final run passed **23 assertions**. The repository's 29 regression tests include coverage of the reproduced defects.

The 23-assertion run is a historical development result, not an additional test suite shipped in this repository or an independent institutional security audit. Its scope excluded external API calls, real credentials, and target-code execution.

开发阶段的独立验证最终通过 23 项断言；这是历史开发记录，本仓库提供的是 29 项回归套件，不能将两者相加称为独立安全基准。

## Live Jev evaluation

Model: `jev-1.13.0`. Official endpoint: `https://api.typesafe.ai/v1/systemone`.

| Round | HTTP attempts | Input tokens | Output tokens |
| --- | ---: | ---: | ---: |
| Initial rubric | 8 | 23,546 | 2,745 |
| Revised rubric | 8 | 20,228 | 1,703 |
| Total | 16 | 43,774 | 4,448 |

All 16 requests succeeded. Counts are observed usage for these specimens, not a pricing estimate or performance promise. No real private key or production repository was sent. No target code was executed.

The initial rubric sometimes expanded credential theft into unsupported persistence, security-bypass, or destruction categories. Definitions were narrowed to concrete mechanisms and exclusions, then the same specimens were retested. That improves results on these examples but creates a tuning bias; there is no held-out dataset or adversarial benchmark.

初版曾出现类别泛化，收紧具体行为定义后对同一组样本复测。该结果有样本调参偏差，不能用于声称“100% 准确”或“消除了误报”。两次模型判断也不是独立证据。

### Published evidence

- [Input specimens](../examples/cases.json): exact original source contents, stored as inert JSON strings. Treat them as untrusted data. Do not execute or install their contents.
- [Final-round summary](../examples/results/live-summary.json): final verdicts, model findings, call counts, and usage.
- [Benign skill report](../examples/results/benign-skill.json).
- [Malicious skill report](../examples/results/malicious-skill.json).
- [Malicious MCP source report](../examples/results/malicious-mcp.json).
- [Quoted educational example report](../examples/results/quoted-example.json).

Only the final round's reports are published here. Original local absolute `target` paths were replaced with `synthetic-fixtures/<case>` before publication. Other report fields, including timestamps, source hashes, findings, validated model answers, and usage, are preserved. These are scanner reports containing validated API answers, not unmodified HTTP transcripts. The initial round's totals above are historical aggregates.

公开报告将 `target` 中的机器绝对路径替换为合成目标标签，其他字段保留；报告含经过客户端校验的回答，不是原始 HTTP 抓包。API Key 不包含在报告或仓库中。

### Interpretation

The benign specimen produced no indicators. The malicious Skill and MCP specimens produced high suspected-behavior findings. The educational quotation produced no Jev findings, while a static prompt-override rule retained `needs_review`.

A displayed Noul value is a yes-probability, not observed accuracy. High findings additionally require two-pass agreement, a valid evidence choice, and active context. These checks can reduce some false positives but cannot establish intent or completeness.

## Reproduction boundaries

Offline tests are directly reproducible using the command above. Live responses may change even with the same model identifier. To review a specimen again, materialize only the selected JSON case's text in a disposable directory, use the scanner in `jev` mode with your own key, and do not run the specimen's installers or entry points. Live evaluation is deliberately excluded from GitHub Actions.

Private source review requires authorization for TypeSafe transfer. Credential redaction is best effort. For behavioral limits, read [design.md](../references/design.md).
