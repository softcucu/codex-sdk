from codex_controller import CodexController


with CodexController(cwd=".") as codex:
    result = codex.goal(
        "让全部测试通过并保持公开 API 不变；以完整测试套件输出作为完成证据"
    )

print(f"thread={result.thread_id}")
print(f"status={result.goal.status}")
print(f"resumes={result.resume_count}")

