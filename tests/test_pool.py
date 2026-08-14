from __future__ import annotations

import io
import threading
from types import SimpleNamespace
from typing import Any

from codex_controller import CodexThreadPool, GoalTask, RunTask


class ConcurrentFakeController:
    barrier = threading.Barrier(2)
    lock = threading.Lock()
    calls: list[tuple[str, str | None, int]] = []

    def __init__(self, **kwargs: Any) -> None:
        self.output = kwargs["output"]
        self.thread_id = kwargs.get("thread_id")

    def goal(self, objective: str, *, model: str | None = None, **kwargs: Any) -> Any:
        worker = threading.get_ident()
        with self.lock:
            self.calls.append((objective, model, worker))
        self.output.write(f"goal {objective} model={model}\n")
        self.barrier.wait(timeout=2)
        return SimpleNamespace(objective=objective, model=model)

    def run(self, prompt: str, *, model: str | None = None, **kwargs: Any) -> Any:
        return SimpleNamespace(prompt=prompt, model=model)

    def resume_goal(self, *, model: str | None = None) -> Any:
        return SimpleNamespace(thread_id=self.thread_id, model=model)

    def start_thread(self, **options: Any) -> str:
        self.thread_id = "new-thread"
        return self.thread_id

    def resume_thread(self, thread_id: str, **options: Any) -> str:
        self.thread_id = thread_id
        return thread_id

    def close(self) -> None:
        pass


def test_pool_runs_goals_concurrently_with_per_task_models() -> None:
    ConcurrentFakeController.barrier = threading.Barrier(2)
    ConcurrentFakeController.calls = []
    output = io.StringIO()
    with CodexThreadPool(
        max_workers=2,
        output=output,
        _controller_factory=ConcurrentFakeController,
    ) as pool:
        first = pool.submit_goal("first", model="model-a")
        second = pool.submit_goal("second", model="model-b")
        results = [first.result(timeout=3), second.result(timeout=3)]

    assert [(result.objective, result.model) for result in results] == [
        ("first", "model-a"),
        ("second", "model-b"),
    ]
    assert len({worker for _, _, worker in ConcurrentFakeController.calls}) == 2
    assert {(objective, model) for objective, model, _ in ConcurrentFakeController.calls} == {
        ("first", "model-a"),
        ("second", "model-b"),
    }
    rendered = output.getvalue()
    assert "=== Codex task 1 (goal) ===" in rendered
    assert "=== Codex task 2 (goal) ===" in rendered


def test_pool_batch_helpers_preserve_input_order_and_models() -> None:
    with CodexThreadPool(
        max_workers=1,
        output_mode="quiet",
        _controller_factory=ConcurrentFakeController,
    ) as pool:
        runs = pool.map_runs(
            [RunTask("one", model="m1"), RunTask("two", model="m2")]
        )

    assert [(result.prompt, result.model) for result in runs] == [
        ("one", "m1"),
        ("two", "m2"),
    ]


def test_pool_can_resume_existing_goal_with_selected_model() -> None:
    with CodexThreadPool(
        max_workers=1,
        output_mode="quiet",
        _controller_factory=ConcurrentFakeController,
    ) as pool:
        result = pool.submit_resume_goal(
            "existing-thread", model="resume-model"
        ).result(timeout=2)

    assert result.thread_id == "existing-thread"
    assert result.model == "resume-model"


def test_goal_task_batch_type_is_supported() -> None:
    ConcurrentFakeController.barrier = threading.Barrier(2)
    with CodexThreadPool(
        max_workers=2,
        output_mode="quiet",
        _controller_factory=ConcurrentFakeController,
    ) as pool:
        results = pool.map_goals(
            [GoalTask("a", model="ma"), GoalTask("b", model="mb")]
        )

    assert [(result.objective, result.model) for result in results] == [
        ("a", "ma"),
        ("b", "mb"),
    ]
