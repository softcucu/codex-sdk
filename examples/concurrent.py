from codex_controller import CodexThreadPool, GoalTask


tasks = [
    GoalTask(
        "修复单元测试，以完整测试结果作为证据",
        model="model-for-coding",
        cwd="/path/to/project-a",
    ),
    GoalTask(
        "完成代码审计并输出报告",
        model="model-for-review",
        cwd="/path/to/project-b",
    ),
]

with CodexThreadPool(max_workers=2) as pool:
    results = pool.map_goals(tasks)

for result in results:
    print(result.thread_id, result.model, result.goal.status)

