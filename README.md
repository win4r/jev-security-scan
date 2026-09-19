# Jev Security Scan

**中文** | [English](README.en.md)

用 **TypeSafe Jev + 本地静态检查**，在安装或运行之前审查 Agent Skill、MCP 配置与源码中的可疑行为。

输出文件和行号、脱敏后的证据、风险类别、模型概率及未扫描范围。支持 Codex、Claude Code，也可以作为独立 Python 命令行工具使用。

> 这是辅助审查工具，不是安全认证。未发现指标不代表没有恶意代码。Jev 模式会向 TypeSafe 发送经过尽力脱敏的源码片段和相对文件名；敏感项目可以先使用完全离线的 `local` 模式。

## 能做什么

| 范围 | 关注内容 |
| --- | --- |
| Agent Skill | SKILL.md、引用资料、脚本中的提示词注入、隐藏行为、越权指令 |
| MCP 源码 | 工具描述投毒、读取凭据、非预期外传、动态执行 |
| MCP 配置 | 启动命令、参数、远端地址；JSON 中的 `mcpServers` / `mcp_servers` 清单 |
| 安装与供应链 | 安装钩子、下载即执行、未经审查的远程引入 |
| 系统行为 | 隐蔽持久化、认证或安全机制绕过、破坏与资源滥用 |
| 遥测 | 单独标为信息项，不直接推断恶意 |

扫描器读取目标文本，不执行目标代码、不安装其依赖、不启动或连接 MCP 服务。它会扫描 Markdown、隐藏配置、`dist/`、构建与安装脚本，不接受目标 `.gitignore` 提供的隐藏规则。

## 环境要求

- Python **3.10+**，只使用标准库，无需 `pip install`。
- 本地模式不需要 API Key，也不请求网络。
- Jev 模式需要 [TypeSafe](https://typesafe.ai/) API Key 和网络访问；API 调用可能产生费用。
- 主要面向 macOS / Linux。权限、符号链接等测试包含 POSIX 行为，尚未完整验证 Windows。

## 安装

先克隆并阅读源码：

```bash
git clone https://github.com/win4r/jev-security-scan.git
cd jev-security-scan
```

独立 CLI 可以直接运行。要供 Agent 使用，把运行所需的文件复制到技能目录；以下命令不会覆盖已有同名 Skill。

**Codex：**

```bash
skill_dir="$HOME/.codex/skills/jev-security-scan"
mkdir -p "$(dirname "$skill_dir")"
if mkdir "$skill_dir"; then
  cp -R SKILL.md scripts references agents "$skill_dir/"
fi
```

**Claude Code：**

```bash
skill_dir="$HOME/.claude/skills/jev-security-scan"
mkdir -p "$(dirname "$skill_dir")"
if mkdir "$skill_dir"; then
  cp -R SKILL.md scripts references agents "$skill_dir/"
fi
```

在克隆的仓库目录执行上述命令。重新打开 Agent 会话以加载新 Skill；具体自动发现行为取决于客户端版本。这些步骤不会安装后台 Hook。

## 在 Agent 中使用

Codex 示例：

```text
用 $jev-security-scan 扫描 /绝对路径/目标Skill，使用 Jev 分析。
给出可疑行为、文件行号、代码证据和未扫描范围。不要执行目标代码。
```

Claude Code 示例：

```text
Use the jev-security-scan skill to review /absolute/path/to/mcp-project with Jev.
Report suspicious behavior, file and line evidence, and coverage gaps.
Do not execute the target code or connect to the MCP server.
```

明确要求使用 Jev 检查指定目标，意味着允许将该范围的脱敏源码发送给 TypeSafe。仅要求离线检查时使用 `local` 模式。凭据通过环境或隐藏输入提供，不要让 Agent 将 Key 写入源码、命令参数或报告。

## 命令行快速开始

从克隆后的仓库目录运行；将 `/absolute/path/to/target` 替换成你的目标目录或单个文件。

### 1. 本地扫描

```bash
python3 -I -B "$PWD/scripts/scan.py" /absolute/path/to/target --mode local
```

### 2. 使用 Jev 并生成报告

先选择目标目录之外的一个报告目录。示例中的 `mktemp` 创建新目录，避免覆盖旧结果：

```bash
report_dir="$(mktemp -d)"
python3 -I -B "$PWD/scripts/scan.py" /absolute/path/to/target \
  --mode jev --prompt-key --max-calls 80 \
  --json-out "$report_dir/report.json" \
  --markdown-out "$report_dir/report.md"
```

`--prompt-key` 会提示隐藏输入 API Key。已有 `TYPESAFE_API_KEY` 环境变量时可省略此选项。Key 不会由扫描器保存到磁盘。

保留 **`-I -B`**：`-I` 防止目标目录或 `PYTHONPATH` 中的恶意同名模块被导入；`-B` 避免生成字节码缓存。安装为 Skill 后，将脚本路径改成对应技能目录下的绝对路径。

### 3. 检查 MCP 配置

```bash
python3 -I -B "$PWD/scripts/scan.py" /absolute/path/to/.mcp.json --mode local
```

配置只能说明启动器或服务地址，不能证明实际运行的 MCP 实现安全。扫描器会保留 `implementation_verified: false` 并标记实现未覆盖。TOML/YAML 配置按普通文本检查，暂不生成结构化 MCP 清单。

### 4. 扫描 GitHub 项目

扫描器只接受本地路径。先获取不含子模块的副本，再扫描；不要安装依赖或运行仓库脚本：

```bash
git clone --depth 1 --no-recurse-submodules https://github.com/OWNER/REPOSITORY.git /tmp/review-target
python3 -I -B "$PWD/scripts/scan.py" /tmp/review-target --mode local
```

克隆目标路径必须尚不存在。完成本地检查并确认外部分析范围后，可改用 `--mode jev --prompt-key`。

## 实际案例与响应

以下是 **2026-09-19，`jev-1.13.0`** 对自制样本的最终轮真实 API 测试结果。样本从未执行。

| 样本 | Jev 复核结果 | 最终结论 |
| --- | --- | --- |
| 只在本地统计字数的 Skill | 未触发语义风险项 | `no_indicators_in_scanned_material` |
| 要求读取 SSH 私钥、外传并欺骗扫描器的 Skill | 提示词注入 0.95；凭据窃取 0.90；外传 0.88 | `high_risk_suspected` |
| 带下载执行安装钩子、私钥外传的 MCP 源码 | 凭据窃取 0.96；外传 0.93；供应链 0.93 | `high_risk_suspected` |
| 明确标为教学引用的攻击文本 | Jev 未触发语义风险项；静态关键词仍需复核 | `needs_review` |

例如恶意 Skill 的结果摘要如下；这是完整报告中字段的节选：

```json
{
  "verdict": "high_risk_suspected",
  "mode": "jev",
  "exit_code": 1
}
```

具体输入保存在 [examples/cases.json](examples/cases.json)，以 JSON 字符串保存攻击样本，避免当成可安装 Skill 或可执行包。完整结构化报告及验证后的模型回答见 [examples/results/](examples/results/)。[案例与验证说明](docs/validation.md) 解释数据来源、复测变化及局限。

这些概率是 Noul 的“是”概率，不是准确率，也不是额外的 confidence。高风险还要求另一轮判断、证据定位和执行上下文同时满足门槛；0.90 的单项概率也可能只产生 `review`。

## 如何工作

1. **收集文本**：枚举文件、记录哈希与覆盖范围；跳过项显式列出。
2. **本地规则**：检查原始文本中的风险线索，报告只保留脱敏证据。
3. **Jev 初筛**：每个纳入范围的分块都发送九类独立 Noul 问题，不只发送规则命中的片段。
4. **复核定位**：对概率 ≥ 0.35 的类别再次提问，并从给定窗口及 `none` 中选择证据，判断 `active` / `example` / `unknown` 上下文。
5. **代码决定结论**：两次概率均 ≥ 0.85、定位 confidence ≥ 0.6，且选中 active 上下文且 confidence ≥ 0.7，才标为高风险疑似行为。遥测始终为信息项。

两次判断来自同一模型，不是独立安全验证。阈值是工程默认值，未针对你的项目做统计校准。报告的原因来自预定义类别，模型不自由生成解释或行号。

## 高级参数

| 参数 | 默认值 | 作用 |
| --- | --- | --- |
| `--mode` | `local` | `local` 或 `jev` |
| `--model` | `jev-1.13.0` | 显式选择模型；没有自动回退 |
| `--max-files` | `400` | 最多读取的文本文件数 |
| `--max-file-bytes` | `256000` | 单文件字节上限 |
| `--max-total-bytes` | `8000000` | 总读取字节上限 |
| `--chunk-chars` | `12000` | 每个分块的源码字符上限，最小 1000 |
| `--max-calls` | `80` | HTTP 请求预算，包含重试，不等于 token 预算 |
| `--json-out` / `--markdown-out` | 无 | 写入目标目录之外的新文件 |

每块另有 100 个行片段上限。长行会按列拆分，不会直接截掉送给模型的内容。超预算会报告未覆盖；API 拒绝过大的请求时应显式减小分块后重跑。

客户端仅调用 `https://api.typesafe.ai/v1/systemone`，拒绝重定向，超时 45 秒，对 429/5xx 在 2 秒后重试一次。鉴权或重定向失败会停用后续调用；系统代理设置仍可能生效。

## 结论与退出码

| 结论 | 含义 | 退出码 |
| --- | --- | --- |
| `no_indicators_in_scanned_material` | 请求阶段已完成，未发现需要复核的指标；可能有信息项 | `0` |
| `needs_review` | 存在待人工判断的线索 | `1` |
| `high_risk_suspected` | 发现高风险疑似行为，先核查证据 | `1` |
| `incomplete` | 存在遗漏或 API 失败，且没有更高优先级发现 | `3` |
| 无正常报告 | 参数、配置或输出失败 | `2` |

发现与覆盖缺口可以同时存在。退出码 1 不表示覆盖完整；检查 JSON 中的 `coverage` 和 `errors`。在 CI 中应明确处理 1/2/3，不能把它们都当作“扫描无风险”。

## 隐私与检测边界

- Jev 模式发送尽力脱敏后的代码片段与相对文件名。未知格式秘密、项目名称和专有代码仍可能残留；脱敏不是匿名化。
- `.env`、私钥等受保护文件、二进制、非 UTF-8、符号链接、特殊文件、依赖/缓存目录和超预算内容不会完整审查，报告中列出原因；VCS 元数据为声明的范围排除项。
- 无法充分覆盖跨文件数据流、混淆代码、运行时下载、传递依赖或远端服务实际行为。
- 不是 OS 沙箱。有其他进程能修改目标目录时，应扫描稳定快照。
- 报告文件权限为 `0600`，拒绝覆盖已有文件；报告仍可能含专有源码片段，请谨慎共享。
- 不替代 CVE 检查、完整密钥扫描、运行时沙箱或人工审计。

## 测试与项目结构

```bash
python3 -I -B -m unittest discover -s tests -v
```

29 项本地回归测试不需要 API Key。初始开发还完成了 23 项独立本地断言与两轮共 16 次真实 Jev 请求；这些是小规模合成样本验证，不是通用恶意软件基准。GitHub Actions 只运行离线测试。

```text
SKILL.md                 Agent 运行约定
agents/openai.yaml       Codex 展示元数据
scripts/scan.py          发现、脱敏、分块、报告与 CLI
scripts/checks.py        静态规则与 Jev 判断定义
scripts/jev_client.py    HTTP 客户端与响应校验
references/             设计边界与来源
tests/                  可离线复现的回归测试
examples/               JSON 样本与真实测试报告
docs/validation.md      验证说明
```

## 来源与许可

借鉴 [luantak/is-malicious](https://github.com/luantak/is-malicious) 的类型化检查、分块、复核定位和覆盖率报告思路。当前 Python 实现独立编写，没有复制或依赖其 TypeScript 实现。使用官方 TypeSafe skill 指导 state/question 分离、Noul 和 Choice 的使用；详见 [来源说明](references/provenance.md) 与 [TypeSafe API 文档](https://docs.typesafe.ai/api)。

[MIT License](LICENSE)。本项目为社区工具，不代表 TypeSafe 官方安全认证或效果背书。
