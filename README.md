# codex-goal-controller

Codex 的 Python 控制封装，基于官方 `openai-codex` SDK 和本地 app-server JSON-RPC 协议。

它主要解决两个问题：

- 使用 Codex 的持久化 Goal（等价于 `/goal`），遇到 HTTP 429、服务过载、响应流断开或非主动暂停后，自动执行 `/goal resume` 的协议等价操作。
- 支持 `quiet`、`human`、`debug` 三种输出模式，默认 `human`。
- 每个普通 turn 或 Goal 都能独立指定模型，并支持多个独立 Codex thread 并发执行。

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
        "让全部测试通过，并且不改变公开 API；以完整测试套件结果作为完成证据",
        model="your-codex-model",
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
    result = codex.run("解释这个项目的架构", model="your-fast-model")
    print(result.final_response)
```

## 每次任务指定模型

普通 turn 的 `model=` 只覆盖这次任务，并按照 Codex 协议成为该 thread 后续 turns 的设置：

```python
with CodexController(cwd=".") as codex:
    analysis = codex.run("分析失败原因", model="model-for-analysis")
    implementation = codex.run("实现修复", model="model-for-coding")
```

新建或重新加载 thread 时，Goal 会把模型直接传给 `thread/start` 或 `thread/resume`；
对于已经加载的 thread，则会在激活 Goal 前更新 thread settings。因此 Goal 自动产生的
首轮、后续 continuation，以及 429 后的自动 resume 都使用指定模型：

```python
with CodexController(cwd=".") as codex:
    result = codex.goal(
        "修复全部失败并运行测试验证",
        model="model-for-coding",
    )
```

恢复已有 Goal 时也可切换模型：

```python
with CodexController(cwd=".", thread_id="019c...") as codex:
    result = codex.resume_goal(model="another-model")
```

模型名称会原样交给 Codex runtime 校验；封装不会维护一份容易过期的模型白名单。
返回结果中的 `result.model` 表示本次请求的模型覆盖值；如果 Codex runtime 因服务能力发生模型 reroute，应以 debug 事件中的 `model/rerouted` 为准。

## 多线程并发调用

`CodexThreadPool` 基于 Python `ThreadPoolExecutor`。每个任务使用独立的 `CodexController`、app-server 连接和 Codex thread，因此不会共享当前 turn 或 Goal 状态：

```python
from codex_controller import CodexThreadPool


with CodexThreadPool(max_workers=3, output_mode="human") as pool:
    futures = [
        pool.submit_goal(
            "修复项目 A 的测试",
            cwd="/work/project-a",
            model="model-a",
        ),
        pool.submit_goal(
            "审计项目 B 并输出报告",
            cwd="/work/project-b",
            model="model-b",
        ),
        pool.submit_run(
            "解释项目 C 的架构",
            cwd="/work/project-c",
            model="model-c",
        ),
    ]

    results = [future.result() for future in futures]
```

也可以用任务对象批量提交，返回顺序与输入一致：

```python
from codex_controller import CodexThreadPool, GoalTask


tasks = [
    GoalTask("完成任务 A", model="model-a", cwd="/work/a"),
    GoalTask("完成任务 B", model="model-b", cwd="/work/b"),
]

with CodexThreadPool(max_workers=2) as pool:
    results = pool.map_goals(tasks)
```

已有 Goal 也能并发恢复：

```python
future = pool.submit_resume_goal("thread-id", model="selected-model", cwd="/work/a")
```

并发输出策略：

- `quiet` 不输出；
- `human` 和 `debug` 为每个任务单独缓冲，任务结束时原子写出，避免多线程日志交叉；
- 超过 1 MiB 的任务日志自动滚动到临时文件，避免长期 Goal 一直占用内存；
- `debug` 记录包含 `context.pool_task_id`，可以区分并发任务。

同一个 `CodexController` 表示一个当前 thread，内部会串行化操作。需要并行时应使用 `CodexThreadPool`。如果多个任务会修改同一代码仓库，请给它们使用不同 Git worktree 或确保写入范围互不重叠，否则并发文件修改本身仍可能冲突。

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

SDK 在瞬态错误后需要同时收到 turn 结束和 Goal 状态通知，才会结束当前逻辑事件流。
如果 429 后 Goal 状态已经持久化为 `usageLimited`，但对应状态通知丢失或无法解析，
控制器会主动读取持久化状态并释放事件流；如果失败 turn 后 Goal 异常地继续保持
`active` 且 30 秒没有新事件，控制器会结束这个僵死 operation，再交给上述自动恢复流程。
这个检查只在已经观察到瞬态错误或失败 turn 后启用，不会限制正常的长时间工具调用。

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
codex-goal -C /path/to/repo --model your-codex-model goal "完成迁移并验证"
codex-goal -C /path/to/repo --output-mode debug goal "定位性能回退"
codex-goal -C /path/to/repo --output-mode quiet --thread-id 019c... resume-goal
```

查看完整参数：

```bash
codex-goal --help
```

### 根目录 `main.py`

仓库根目录提供了一个参数式入口，默认启动支持自动恢复的 Goal。基本格式如下；
`--prompt` 和 `--prompt-file` 必须且只能指定一个：

```text
.venv/bin/python main.py [OPTIONS] (--prompt TEXT | --prompt-file PATH)
```

启动 Goal：

```bash
.venv/bin/python main.py \
  --project-path /path/to/repo \
  --model your-codex-model \
  --retry-count 3 \
  --prompt "让全部测试通过，以 pytest 结果为完成证据"
```

执行一个不自动恢复的普通 turn：

```bash
.venv/bin/python main.py \
  --project-path /path/to/repo \
  --task-type run \
  --prompt "解释项目架构"
```

提示词较长时，可以用 `--prompt-file` 从 UTF-8 文本文件读取；它与 `--prompt` 二选一：

```bash
.venv/bin/python main.py \
  --project-path /path/to/repo \
  --model your-codex-model \
  --retry-count 3 \
  --prompt-file /path/to/prompt.md
```

继续已有 thread：

```bash
.venv/bin/python main.py \
  --project-path /path/to/repo \
  --thread-id 019c... \
  --prompt "基于已有上下文完成后续修改并验证"
```

可设置参数：

| 参数 | 含义 |
| --- | --- |
| `-h`, `--help` | 打印帮助并退出。 |
| `-C PATH`, `--project-path PATH`, `--cwd PATH` | Codex 项目目录，必须是已经存在的目录；默认是当前目录。相对路径会转换为绝对路径。 |
| `-m MODEL`, `--model MODEL` | 本次 turn 或 Goal 使用的模型；不传时使用本机 Codex 配置的默认模型。 |
| `-r N`, `--retry-count N`, `--max-resumes N` | Goal 首次执行后最多自动恢复 `N` 次。`0` 表示不自动恢复；不传表示不限制次数。只影响 `goal`。 |
| `-p TEXT`, `--prompt TEXT` | 普通 turn 的提示词，或 Goal 的 objective；与 `--prompt-file` 二选一。 |
| `--prompt-file PATH` | 从 UTF-8 文本文件读取完整提示词；文件必须存在且可读，与 `--prompt` 二选一。 |
| `--task-type {goal,run}` | `goal` 启动可自动恢复的 Goal；`run` 只执行一个普通 turn。默认是 `goal`。 |
| `--token-budget N` | Goal 的正整数 token budget；只对 `--task-type goal` 生效。不传时不设置 Goal token budget。 |
| `--max-elapsed-seconds SECONDS` | Goal 执行及自动恢复允许使用的最大总时长，必须大于 `0`；不传表示不限制总时长。只影响 `goal`。 |
| `--initial-delay SECONDS` | Goal 第一次自动恢复前的基础等待时间，必须大于等于 `0`，默认 `5` 秒。后续等待使用指数退避并带少量随机抖动。 |
| `--max-delay SECONDS` | Goal 单次自动恢复等待时间的上限，必须大于等于 `0`，默认 `300` 秒。 |
| `--output-mode {quiet,human,debug}` | 输出模式：`quiet` 不打印事件，`human` 输出适合阅读的流式活动，`debug` 输出完整 JSONL 事件。默认是 `human`。 |
| `--thread-id ID` | 恢复指定的已有 Codex thread 及其上下文，再执行本次 `run` 或启动一个新 Goal；不传时创建新 thread。它不会调用 `resume_goal()`，因此 `--task-type goal` 会用本次 objective 替换该 thread 上原有的 Goal。 |
| `--codex-bin PATH` | 使用指定的 Codex 可执行文件；不传时使用 `openai-codex` SDK 自带或自动解析的 runtime。 |

`main.py` 对新建和恢复的 thread 都固定使用 `Sandbox.workspace_write` 和
`ApprovalMode.deny_all`：Codex 可以修改项目工作区和沙箱默认临时目录，但所有需要扩大
权限的请求都会被拒绝，不会自动提权。

退出码：任务完成返回 `0`，任务未完成返回 `2`，运行异常返回 `1`，用户按
`Ctrl+C` 中断返回 `130`。

查看当前版本的完整参数：

```bash
.venv/bin/python main.py --help
```

## 开发和测试

```bash
python3.11 -m venv .venv
.venv/bin/pip install -e '.[dev]'
.venv/bin/pytest
```

单元测试不调用模型，不消耗 API 配额；它使用结构化假事件验证按任务选择模型、真正的多线程并发、429、transport 重连、恢复次数限制和三种日志模式。

## 兼容性说明

当前版本针对官方 `openai-codex 0.144.x`。Goal RPC 已经是 app-server 的正式结构化方法，但该 SDK 版本尚未把 Goal 控制暴露到高层 `Thread` API，因此本项目把相关兼容访问隔离在 `_backend.py` 中，并将依赖限制在 `<0.145`。升级官方 SDK 时应先运行测试并检查该适配层；这样不会把私有兼容细节扩散到业务代码。
