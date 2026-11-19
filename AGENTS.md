# AGENTS.md — 工程纪律与证据完整性契约

本文档规定 Harness Reliability Lab 的离线核验命令、单向依赖边界、冻结资产只读纪律、模拟优先测试准则及 16 项负向脱敏红线。配套文档见 [五幕交互专著](site/index.html)、[仓库导览与速查表](README.md)、[控制面与协议规范](docs/architecture-and-protocol.md) 与 [实证评估报告](docs/empirical-evaluation.md)。

## 1. 命令优先的零密钥离线核验（零外部 API 调用 / 零 `.env`）

所有检查均在仓库根目录下使用锁定依赖与 `--no-env-file` 执行：

```bash
uv sync --frozen --group dev
uv run --frozen --no-env-file ruff check --config pyproject.toml .
uv run --frozen --no-env-file harness-lab doctor
uv run --frozen --no-env-file pytest -c pyproject.toml
uv run --frozen --no-env-file python -m evals.verify_all --export-ledger
uv run --frozen --no-env-file python -m evals.verify_all --ci
```

- `--export-ledger`：面向本地完整 `artifacts/` 目录执行深审（SHA-256 树哈希对账、`324` 次 `replication-v2` 独立重评分与协议/门禁复核、后训练与 `M1–M6` 扩展不变量核验、递归脱敏扫描），并原子导出 `evals/evidence_ledger.json`（`<= 150 KB`）、`site/ledger-data.js` 及五份静态配套阅读页。
- `--ci`：面向干净克隆环境的免产物核验，不依赖 `artifacts/` 目录与任何 `.env` 凭证。

## 2. 运行时与评测层的单向导入边界

- **运行时核心层（`src/harness_lab/*`）**：仅包含 `contracts`、`mcp_port`、`models`、`runtime`、`storage`、`timing`、`tool_server`、`trace` 与 `cli` 九个模块，严禁反向导入 `evals`、`tests`、历史 `app` 或 `scripts`。
- **评测与审计层（`evals/*`、`tests/*`）**：仅可调用 `harness_lab` 公开接口，依赖方向严格限定为 `evals / tests → harness_lab`。
- **标准包安装纪律**：统一由 `pyproject.toml` 与 `uv.lock` 标准安装；严禁篡改 `sys.path`、注入 `PYTHONPATH` 或绕过 `python -I -m harness_lab doctor` 隔离自检。
- **顶层评测模块冻结**：顶层 15 个 `evals/*.py` 文件已由 `specs/replication-v1.json` 与 `specs/replication-v2.json` 锁定 SHA-256 摘要；新增评测或核验工具一律置于独立子包（`evals/<subpkg>/__init__.py` + `__main__.py`）。

## 3. 冻结资产与主实验证据的只读纪律

- **零字节冻结范围**：`src/harness_lab/*`、顶层 15 个 `evals/*.py`、`evals/replication_v2/*`、`pyproject.toml`、`uv.lock`、`specs/*` 及 `tasks/frozen/*` 保持零字节变更（相对 `specs/replication-v2.json` 零差异）。
- **主复现数据集（`replication-v2`）**：`artifacts/replication-v2-2026-11-17/`（`324/324` 次运行、`54/54` 个配对区组、`0` 次 `model_failed`、双模型版本失效组 `P1 → P2` 由 `0/18` 升至 `18/18`、控制组 Model A `36/36 → 36/36`、Model B `36/36 → 35/36`）及其同级 `-audit/` 目录严格只读。
- **有效失败原样保留**：`acc-15-r2-B-P2` 为合法 HTTP 200 响应下的单引号 Python 字典语法退化，原样保留 `0` 分，严禁挑样重跑，严禁在运行时添加 `ast.literal_eval()` 等事后宽松 JSON 解析器。
- **扩展实验产物保护**：`acc15-probe-v2-2026-11-18`、`diagnostics-v2-2026-11-18`、`post-training-v2-2026-11-18`、`nextgen-v1-m2a-m3-pareto`、`nextgen-v1-m2b-m4-context-virtual`、`nextgen-v1-m5-security-shield` 及历史 `protected-before.json` 清单保持逐字节完好；任何重审均须校验前后指纹并写入全新独立目录。
- **指标语义分离**：严格区分 `correct_disposition` 与 `goal_completed`。仅当任务判定准则明确要求停止或拒绝时，安全停止或拒绝才属合规处置；未完成的可执行写任务绝不计入 `goal_completed`。

## 4. 离线模拟优先测试准则

- 任何运行时、协议、恢复、安全或审计变更，均须先在零外部 API 调用下通过确定性离线测试（`ScriptedController`、`httpx.MockTransport`、stdio/热池 MCP 子进程、`?mode=ro` 只读 SQLite 夹具）。
- 离线命令从不自动加载 `.env`。经显式授权的在线实验仅可读取 `--model-env` 指定文件，严格遵守单次尝试停机规则，并记录 `perf_counter` 单调时钟耗时与真实词元用量。
- 模拟时钟与注入式进程崩溃仅用于离线基准与单元测试，绝不混作在线模型实验结论。

## 5. 16 项负向脱敏硬红线

版本库跟踪文件、`evals/evidence_ledger.json`、后训练导出语料、扩展实验摘要及 `site/*` 静态站资产必须同时满足以下 16 项负向红线：

1. 严禁跟踪 `.env`、`.env.*`（`.env.example` 除外）或任何真实 API 密钥与 `Bearer ` 令牌字符串。
2. 严禁在公开产物中输出模型服务商环境变量名（`LAB_MODEL_API_KEY`、`LAB_MODEL_BASE_URL`、`LAB_MODEL_NAME`、`LAB_MODEL_TOKEN_LIMIT_FIELD`、`api_key`）。
3. 严禁在公开或跟踪产物中泄漏本地盘符根路径、用户主目录或系统临时目录路径。
4. 严禁提交原始 `.sqlite` 沙箱数据库、`private-server.json` 或未脱敏的 `trace.jsonl` 轨迹文件。
5. 严禁在公开或训练载荷中暴露宿主线缆安全信封模式（`envelope`、`$defs`、`Envelope`）。
6. 严禁暴露内部槽位或幂等令牌标识（`run_id`、`principal`、`operation_id`、`idempotency_key`、`run-<hex>`、`:write-0`、`dev-user`）。
7. 严禁暴露宿主内部重试计数或阶段标记（`attempt`、`attempts`、`stage`、`initial_read`、`refresh_read`）。
8. 严禁暴露私有故障注入配置（`fault`、`fault_plan`、`state_patch`、`delay_s`、`state_change`、`pre_commit_delay`、`commit_response_delay`、`malformed_result`、`protocol_error`）。
9. 严禁暴露服务端私有文件系统键名（`db_path`、`server_path`、`private-server.json`、`environment.sqlite`）。
10. 严禁暴露评测私有判定准则字段（`oracle`、`completable`、`write_allowed`、`final_state`、`expected_params`、`handoff_reason`、`required_facts`）。
11. 严禁持久化或导出服务端不透明上下文与明文思维链字段（`encrypted_content`、`reasoning_content`、`reasoning`）。
12. 严禁在字符串字段内嵌套未脱敏的 JSON 或 Python 字典字面量；审计扫描器对嵌套字面量执行递归解析。
13. 严禁在监督微调导出中对 `system`、`user` 或 `tool` 消息设置 `loss_mask=1`；仅合规 `assistant` 决策轮允许纳入监督损失。
14. 严禁导出上下文前缀不一致的偏好对，或将外部 API 传输异常充当负向内容样本。
15. 严禁在导出的公开工具 JSON Schema 中遗漏 `additionalProperties: false` 或泄漏额外底层参数。
16. 严禁绕过 `SecurityViolationError`（`assert_nextgen_artifact_safe` 与 `evals.verify_all`）写出公开账本或静态站数据。
