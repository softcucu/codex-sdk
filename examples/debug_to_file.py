from codex_controller import CodexController, ResumePolicy


policy = ResumePolicy(max_attempts=20, max_elapsed_seconds=6 * 60 * 60)

with open("codex-debug.jsonl", "w", encoding="utf-8") as log:
    with CodexController(
        cwd=".",
        output_mode="debug",
        output=log,
        resume_policy=policy,
    ) as codex:
        result = codex.goal("定位并修复 flaky test，以重复测试结果作为证据")

print(result.goal.status, result.resume_count)

