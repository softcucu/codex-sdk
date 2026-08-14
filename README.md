# codex-goal-controller

Codex 的 Python 控制封装，基于官方 `openai-codex` SDK 和本地 app-server JSON-RPC 协议。

它主要解决两个问题：

- 使用 Codex 的持久化 Goal（等价于 `/goal`），遇到 HTTP 429、服务过载、响应流断开或非主动暂停后，自动执行 `/goal resume` 的协议等价操作。
- 支持 `quiet`、`human`、`debug` 三种输出模式，默认 `human`。

项目要求 Python 3.10 或更高版本。官方资料：[Codex Python SDK](https://learn.chatgpt.com/docs/codex-sdk#python-library)、[Using Goals in Codex](https://developers.openai.com/cookbook/examples/codex/using_goals_in_codex)、[app-server API](https://learn.chatgpt.com/docs/app-server#api-overview)。

## 安装

```bash
git clone git@github.com:softcucu/codex-sdk.git
cd codex-sdk
python3.11 -m venv .venv
.venv/bin/pip install -e .
```

官方 SDK 会安装与其版本匹配的 Codex runtime，并复用现有 Codex 登录状态。也可以通过 `codex_bin=` 指定本机 Codex 可执行文件。

## 最简用法

```python
from codex_controller import CodexController


with CodexController(cwd="/path/to/repository") as codex:
    result = codex.goal(
        "让全部测试通过，并且不改变公开 API；以完整测试套件结果作为完成证据"
    )

print(result.completed)
print(result.goal.status)
print(result.final_response)
print(result.resume_count)
print(result.thread_id)
```

Goal 是 thread 级持久状态。`result.thread_id` 应保存下来，进程重启后可继续：

```python
from codex_controller import CodexController


with CodexController(
    cwd="/path/to/repository",
    thread_id="019c...",
) as codex:
    result = codex.resume_goal()
```

普通的单轮 Codex 调用使用 `run()`：

```python
with CodexController(cwd="/path/to/repository") as codex:
    result = codex.run("解释这个项目的架构")
    print(result.final_response)
```

## 三种输出模式

### 1. 不打印：`quiet`

不会向输出流写任何 Codex 事件。结果仍由 Python 返回，适合服务端、批处理和自行接日志系统。

```python
with CodexController(cwd=".", output_mode="quiet") as codex:
    result = codex.goal("修复测试并验证")
```

### 2. 适合人看：`human`（默认）

流式显示回复、命令、文件变更、计划、错误、Goal 恢复和完成状态，风格接近 Codex CLI。

```python
with CodexController(cwd=".") as codex:
    result = codex.goal("完成迁移并让测试通过")
```

典型输出：

```text
codex  thread 019c...
goal   完成迁移并让测试通过
• Run pytest -q
  └ exit 1 · 3.2s
↻      Codex usage/rate limit stopped the Goal; resuming in 5.0s
↻      resumed Goal (attempt 1)
• Run pytest -q
  └ exit 0 · 4.1s
goal   complete (18432 tokens, 1 resumes)
```

### 3. 尽可能详细：`debug`

每行输出一个 JSON 对象，包括 UTC 时间、严格递增序号、来源、原始 app-server 事件名和完整结构化 payload；封装自己的重试、重连和异常事件也会记录。

```python
with CodexController(cwd=".", output_mode="debug") as codex:
    result = codex.goal("定位并修复 flaky test")
```

也可以传入文件或自定义 `TextIO`：

```python
with open("codex-debug.jsonl", "w", encoding="utf-8") as log:
    with CodexController(cwd=".", output_mode="debug", output=log) as codex:
        result = codex.goal("定位并修复 flaky test")
```

`debug` 会记录 Codex 事件内容，可能包含提示词、命令输出和文件内容，请按敏感日志处理。

## 自动 Goal resume

默认策略是持续恢复，直到 Goal：

- `complete`：完成，返回 `GoalResult(completed=True)`；
- `blocked`：确实需要用户输入，停止并返回当前结果；
- `budgetLimited`：达到 Goal token budget，停止并返回当前结果；
- 用户按 `Ctrl+C`：暂停 Goal 并抛出 `KeyboardInterrupt`；
- 达到你配置的恢复次数或总时长：抛出 `GoalResumeExhaustedError`，异常的 `partial_result` 中保留阶段性结果。

以下情况会自动恢复：

- Goal 状态是 `usageLimited` 或非主动的 `paused`；
- HTTP 408、409、425、429、500、502、503、504；
- server overload、retry limit、响应流/连接中断；
- app-server transport 关闭。此时封装会重启 runtime、重新加载同一 thread，再恢复已持久化的 Goal。

重试采用带抖动的指数退避，默认从 5 秒开始，最大 300 秒。可以限制：

```python
from codex_controller import CodexController, GoalResumeExhaustedError, ResumePolicy


policy = ResumePolicy(
    max_attempts=20,
    max_elapsed_seconds=6 * 60 * 60,
    initial_delay_seconds=10,
    max_delay_seconds=600,
    multiplier=2,
    jitter_ratio=0.2,
)

try:
    with CodexController(cwd=".", resume_policy=policy) as codex:
        result = codex.goal("完成长期任务", token_budget=500_000)
except GoalResumeExhaustedError as exc:
    partial = exc.partial_result
    print(partial.goal.status if partial else "unknown")
```

如果 429 是长期额度耗尽而不是短暂限流，默认无限恢复会一直等待；生产环境建议设置 `max_attempts` 或 `max_elapsed_seconds`。

## 线程和 Goal 控制 API

```python
from codex_controller import CodexController, Sandbox


codex = CodexController(cwd=".")
try:
    thread_id = codex.start_thread(
        sandbox=Sandbox.workspace_write,
        model="gpt-5.6-terra",
    )

    codex.run("先分析失败原因")
    result = codex.goal("修复失败并用测试验证", token_budget=100_000)

    state = codex.get_goal()  # /goal
    paused = codex.pause_goal()  # /goal pause
    resumed = codex.resume_goal()  # /goal resume
    cleared = codex.clear_goal()  # /goal clear
finally:
    codex.close()
```

主要返回类型：

- `RunResult`：普通 turn 的状态、最终回复、items、usage 和 error。
- `GoalState`：objective、status、token budget/usage、耗时。
- `GoalResult`：最终 Goal 状态、恢复次数、最后回复、合并后的 items/usage/error。

## 命令行入口

安装后也可直接运行：

```bash
codex-goal -C /path/to/repo goal "让全部测试通过，以 pytest 结果为完成证据"
codex-goal -C /path/to/repo --output-mode debug goal "定位性能回退"
codex-goal -C /path/to/repo --output-mode quiet --thread-id 019c... resume-goal
```

查看完整参数：

```bash
codex-goal --help
```

## 开发和测试

```bash
python3.11 -m venv .venv
.venv/bin/pip install -e '.[dev]'
.venv/bin/pytest
```

单元测试不调用模型，不消耗 API 配额；它使用结构化假事件验证 429、transport 重连、恢复次数限制和三种日志模式。

## 兼容性说明

当前版本针对官方 `openai-codex 0.144.x`。Goal RPC 已经是 app-server 的正式结构化方法，但该 SDK 版本尚未把 Goal 控制暴露到高层 `Thread` API，因此本项目把相关兼容访问隔离在 `_backend.py` 中，并将依赖限制在 `<0.145`。升级官方 SDK 时应先运行测试并检查该适配层；这样不会把私有兼容细节扩散到业务代码。
