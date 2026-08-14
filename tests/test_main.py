from __future__ import annotations

import importlib.util
from pathlib import Path
from types import SimpleNamespace


_MAIN_PATH = Path(__file__).parents[1] / "main.py"
_MAIN_SPEC = importlib.util.spec_from_file_location("project_main", _MAIN_PATH)
assert _MAIN_SPEC is not None and _MAIN_SPEC.loader is not None
main_module = importlib.util.module_from_spec(_MAIN_SPEC)
_MAIN_SPEC.loader.exec_module(main_module)


class FakeController:
    init_kwargs = None
    thread_call = None
    call = None
    closed = False

    def __init__(self, **kwargs):
        type(self).init_kwargs = kwargs
        type(self).thread_call = None
        type(self).call = None
        type(self).closed = False

    def start_thread(self, **kwargs):
        type(self).thread_call = ("start", kwargs)

    def resume_thread(self, thread_id, **kwargs):
        type(self).thread_call = ("resume", thread_id, kwargs)

    def close(self):
        type(self).closed = True

    def goal(self, prompt, **kwargs):
        type(self).call = ("goal", prompt, kwargs)
        return SimpleNamespace(completed=True)

    def run(self, prompt, **kwargs):
        type(self).call = ("run", prompt, kwargs)
        return SimpleNamespace(completed=True)


def test_main_forwards_goal_arguments(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(main_module, "CodexController", FakeController)

    exit_code = main_module.main(
        [
            "--project-path",
            str(tmp_path),
            "--model",
            "test-model",
            "--retry-count",
            "4",
            "--token-budget",
            "1000",
            "--prompt",
            "fix all tests",
        ]
    )

    assert exit_code == 0
    assert FakeController.init_kwargs["cwd"] == str(tmp_path.resolve())
    assert FakeController.init_kwargs["resume_policy"].max_attempts == 4
    assert FakeController.thread_call == (
        "start",
        {
            "sandbox": main_module.Sandbox.workspace_write,
            "approval_mode": main_module.ApprovalMode.deny_all,
            "model": "test-model",
        },
    )
    assert FakeController.call == (
        "goal",
        "fix all tests",
        {"model": "test-model", "token_budget": 1000},
    )
    assert FakeController.closed is True


def test_main_can_run_an_ordinary_turn(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(main_module, "CodexController", FakeController)

    exit_code = main_module.main(
        [
            "--project-path",
            str(tmp_path),
            "--task-type",
            "run",
            "--prompt",
            "explain the architecture",
        ]
    )

    assert exit_code == 0
    assert FakeController.call == (
        "run",
        "explain the architecture",
        {"model": None},
    )


def test_main_reads_prompt_from_utf8_file(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(main_module, "CodexController", FakeController)
    prompt_file = tmp_path / "prompt.md"
    prompt_file.write_text("修复测试\n并验证结果\n", encoding="utf-8")

    exit_code = main_module.main(
        [
            "--project-path",
            str(tmp_path),
            "--prompt-file",
            str(prompt_file),
        ]
    )

    assert exit_code == 0
    assert FakeController.call == (
        "goal",
        "修复测试\n并验证结果\n",
        {"model": None, "token_budget": None},
    )


def test_main_resumes_thread_with_restricted_permissions(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(main_module, "CodexController", FakeController)

    exit_code = main_module.main(
        [
            "--project-path",
            str(tmp_path),
            "--thread-id",
            "thread-123",
            "--model",
            "resume-model",
            "--prompt",
            "continue",
        ]
    )

    assert exit_code == 0
    assert FakeController.thread_call == (
        "resume",
        "thread-123",
        {
            "sandbox": main_module.Sandbox.workspace_write,
            "approval_mode": main_module.ApprovalMode.deny_all,
            "model": "resume-model",
        },
    )
